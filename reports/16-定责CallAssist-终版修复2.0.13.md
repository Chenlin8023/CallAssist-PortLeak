# 16 定责：CallAssist（来电助手）powerdxpc 轮询泄漏 → 2.0.13 终版修复

> 归档日期：2026-10-26 · 关联：15（栈回溯修正与 2.0.12）
> 状态：**全案定责完成；2.0.13 带针对性回收修复，已构建待真机验证**

---

## 一、一句话结论

2.0.12 修正路径过滤后，栈回溯首次给出真实归因：**`CallAssist.dylib+1a9cfc`（来电助手
插件）以每秒约 2 次的频率轮询 IOKit 电池/电源接口，每次创建一条
`com.apple.iokit.powerdxpc` XPC 连接且从不释放**——其增速（+~580/5min）与
IOKit/powerdxpc 连接增速（+~610/5min）吻合 96%，其余所有来源合计不足 5%。
这就是"iPhone 每天自动注销"的元凶。2.0.13 按「接管-宽限-回收」模式对泄漏连接做
针对性回收，来电助手可以继续用。

## 二、定责数据（guard.log 01:25–01:40，SB pid 7655）

| 时间 | IOKit 累计 | CallAssist+1a9cfc | 其余来源 |
|---|---|---|---|
| 01:30 | 1005 | 955 | all-system 318 + 零头 |
| 01:35 | 1609（+604） | 1528（+573） | all-system 357 |
| 01:40 | 2219（+610） | 2110（+582） | all-system 396 |

- 两条曲线斜率差 <5%，一一对应；
- 次要源 `all-system(nosb)` +~78/5min ≈ 0.26/s（SystemConfiguration 网络轮询形态，
  单独触顶需 5 天以上，暂不处理）；
- 其它现形插件均为个位数：MilkyWayReborn(21)、AppData(8)、BioProtect(3~11，属正常
  使用非泄漏)、libcrane(1)、CallAssist 另两个调用点(2)。

## 三、2.0.13 修复设计（与 CF 通知同款「接管-宽限-回收」）

1. **接管**：xpc 创建钩子内，栈回溯确认「插件驱动」且服务名 =
   `com.apple.iokit.powerdxpc` 时，`xpc_retain` 一份并登记（512 槽，复用指针去重）；
   SB 自身与纯系统路径的连接一律不碰；
2. **回收**：既有的 5 秒定时器里，把超过宽限期（默认 10s，`XPCGraceSeconds` 可配）
   的登记连接 `xpc_connection_cancel`（异步拆除，mach 端口随之释放）+ `xpc_release`；
   轮询型调用点 10 秒后早已弃用，回收安全；
3. xpc_retain / xpc_release / xpc_connection_cancel 全部 dlsym 取址，不给 dylib
   增加依赖（保持原生 roothide 形态）；任一缺失则自动降级为仅观测；
4. `EnableXPCReclaim=false` 可整体关闭（config.plist）；
5. stat 行新增 `xpcA=`（接管数）/ `xpcF=`（回收数）。

| 项 | 值 |
|---|---|
| 包 | `release/com.local.bioprotectleakguard_2.0.13_iphoneos-arm64e.deb` |
| 包 md5 | `fd57a20375527562fd5205b23d883314` |
| 设备端 dylib 应有 md5 | `b389fe794486df6f93bb9dfbd8b0d35e` |

## 四、真机验证（装 2.0.13 → respring → 正常用机半天）

1. boot 块应出现「xpc 回收: 就绪（宽限 10s …）」；
2. stat 行判读：
   - **`xpcA` 与 `xpcF` 同步增长、差值稳定在个位数~几十**（宽限期内的新连接）→
     回收机制工作正常；
   - **`ports=` 亮屏期也只微涨**（残余 ≈ 0.26/s 的次要源，锁屏归平）→ 主泄漏已消除；
   - 24 小时不注销 → **全案终结**；
3. 来电助手功能照常使用（来电归属地等信息不受影响；若个别功能异常，config.plist
   把 `EnableXPCReclaim` 改 false 关闭回收，并改走「卸载/更新 CallAssist」路线）。

## 五、备选与治本

- **治本**：卸载或更新 CallAssist（其作者修复轮询泄漏后，我们的回收自动无事可做）；
- **兼容**：2.0.13 的回收按「服务名+插件驱动」判定，不锁定 CallAssist 的版本偏移，
  其它插件将来出现同类轮询泄漏也会被自动兜住。

## 六、全案总结（给未来的自己）

- 用户主诉"BioProtect 导致注销"——四轮逆向+真机数据证明 BioProtect 无关；
  真因是 CallAssist 的 IOKit 轮询。**归因靠的是逐层收窄的观测链**：
  端口类型分解（tR/tS 同涨=连接泄漏）→ 创建口计数（xpc≈tR）→ 直方图点名
  （IOKit/powerdxpc）→ 栈回溯定责（CallAssist+1a9cfc）→ 针对性回收。
- 中间踩的三个坑都已沉淀为红线：观测表必须可淘汰、roothide 路径判定必须前缀、
  dispatch_source_t 必须全局持有。
