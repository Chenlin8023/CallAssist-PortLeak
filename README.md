# CallAssist PortLeak — SpringBoard 端口泄漏侦查/止血工具

> **v2.1.0** · 原生 roothide 包（`iphoneos-arm64e`）
>
> 旧名 BioProtect Leak Guard 已停用：真正的泄漏源是 CallAssist，包名同步改为
> `com.local.callassistportleak`（附带 `Conflicts`/`Replaces` 旧包，可直接升级覆盖）。
>
> 解决「iPhone 每天自动注销」：SpringBoard 的 Mach 端口被某插件持续泄漏、耗尽额度后触发系统保护性注销。
> 本工具**逐层观测归因**，最终定责 **CallAssist（电话助手/来电助手）以约 2 次/秒轮询 IOKit 电池接口、
> XPC 连接从不释放（占泄漏 96%）**，并以「接管-宽限-回收」机制针对性止血——**来电助手可继续正常使用**。

---

## 一、问题与定责链路

用户主诉"BioProtect 导致每天注销"。四轮逆向 + 真机数据证明 **BioProtect 无关**，真正的元凶是
CallAssist 的 IOKit 轮询泄漏。整条归因链值得留档：

| 步骤 | 方法 | 结论 |
|---|---|---|
| 1 | 端口类型分解 | `tR/tS` 同涨 → 连接类泄漏 |
| 2 | 创建口计数 | `xpc ≈ tR` → XPC 连接泄漏 |
| 3 | 服务名直方图 | `com.apple.iokit.powerdxpc` 占 94% |
| 4 | 栈回溯定责 | `CallAssist.dylib+1a9cfc`，2 次/秒轮询 IOKit 电池/电源接口，每次新建连接且从不释放 |
| 5 | 数据吻合 | CallAssist 增速 +~580/5min 与 IOKit 连接增速 +~610/5min 吻合 **96%**，其余来源合计 <5% |

案卷全记录见 [`reports/`](reports/)（04→16 共 13 篇，含三次误归因的修正过程与红线总结）。

## 二、工具做了什么

加载于 SpringBoard（另覆盖 Preferences / camera / InCallService / Spotlight），三层能力：

1. **观测**：每 5 分钟输出 stat 行（端口总数、fd 使用量、分类型计数、Top 调用点、
   `xpcA=` 接管数 / `xpcF=` 回收数），归因数据可复现；
2. **既有止血**：CFUserNotification 应答端口宽限后取消、摘除泄漏 RunLoop 源、
   fd 超水位时经 `F_GETPATH` 复核后关闭泄漏 fd；
3. **XPC 接管-宽限-回收（本案核心）**：
   - `xpc_connection_create*` 钩子内，栈回溯确认「插件驱动」且服务名 = `com.apple.iokit.powerdxpc`
     时 `xpc_retain` 一份并登记（512 槽，指针去重）；**SpringBoard 自身与纯系统路径的连接一律不碰**；
   - 5 秒清扫定时器里，把超过宽限期（默认 10s）的登记连接 `xpc_connection_cancel`（异步拆除，
     mach 端口随之释放）+ `xpc_release`——轮询型调用点 10 秒后早已弃用，回收安全；
   - `xpc_retain / xpc_release / xpc_connection_cancel` 全部 `dlsym` 取址，不新增链接依赖，
     任一缺失自动降级为仅观测模式。

## 三、安装

- **适用环境**：roothide 越狱（Bootstrap）；本包为**原生 roothide 形态**（`iphoneos-arm64e`），
  **直接安装，不要过 RootHide 转换器**（转换器会破坏 arm64e 的 PAC 认证，这正是 2.0.6 之前
  进安全模式的原因）。
- 安装包：`com.local.callassistportleak_2.1.0_iphoneos-arm64e.deb`
  （越狱源 <https://chenlin8023.github.io/> 直接安装，或见 Releases）
- 校验：deb MD5 = `fd57a20375527562fd5205b23d883314`；安装后 postinst 会打印设备端 dylib 的
  md5，应等于 `b389fe794486df6f93bb9dfbd8b0d35e`（即未被转换器动过）。
- 装完 **respring（注销）一次**生效。

## 四、配置（可选）

配置文件按以下顺序探测（存在即用）：`<rootfs>/Library/BioProtectLeakGuard/config.plist`、
`<home>/Library/BioProtectLeakGuard/config.plist`、`<rootfs|home>/Library/Preferences/BioProtectLeakGuard.plist`。

| 键 | 默认 | 说明 |
|---|---|---|
| `EnableXPCReclaim` | `true` | XPC 接管-宽限-回收总开关 |
| `XPCGraceSeconds` | `10` | 回收宽限期（秒，≥5） |
| `EnableAutoRespring` | 按 `gCfgRespring` | 端口触顶后自动注销兜底 |
| `PortThreshold` | 见源码（≥2000 生效） | 端口触顶阈值 |
| `DebugVerbose` | `false` | 详细日志 |

## 五、验证（装 2.1.0 → respring → 正常用机半天）

1. boot 块应出现「xpc 回收: 就绪（宽限 10s …）」；
2. stat 行判读：`xpcA` 与 `xpcF` 同步增长、差值稳定在个位数~几十 → 回收正常；
   `ports=` 亮屏期只微涨（残余 ≈0.26/s 的次要源，锁屏归平）→ 主泄漏已消除；
3. **24 小时不自动注销 → 全案终结**；
4. 来电助手功能照常；若个别功能异常，把 `EnableXPCReclaim` 改 `false` 关闭回收。

## 六、备选与治本

- **治本**：卸载或更新 CallAssist——其作者修复轮询泄漏后，本模块的回收会自动无事可做；
- **通用性**：回收按「服务名 + 插件驱动」判定，不锁定 CallAssist 的版本偏移，
  其它插件将来出现同类轮询泄漏也会被自动兜住。

## 七、从源码构建

```bash
# WSL2 (Ubuntu-22.04) + theos（含 arm64e 攻坚补丁，详见 build.sh 内注释）
wsl -d Ubuntu-22.04 -- bash /mnt/<路径>/CallAssist-PortLeak/build.sh
```

- `build.sh` 内置 **arm64e CFString isa 认证补丁**（clang19 编译的 `__cfstring` isa 无 PAC 认证
  会导致 `objc_msgSend` SIGBUS 进安全模式，2.0.7 修复，详见 [reports/10](reports/)）与
  执行位/签名全套断言；
- `verify.sh` 用于安装后校验；
- 依赖：theos、roothide 版 substrate stub（仓库内 `libsubstrate_roothide.tbd`）。

## 八、目录结构

```
CallAssist-PortLeak/
├── BioProtectLeakGuard.xm     # 全部逻辑（约 1600 行，注释很细）
├── Makefile                   # theos 构建（原生 roothide：THEOS_PACKAGE_INSTALL_PREFIX 为空）
├── control                    # deb 包信息
├── BioProtectLeakGuard.plist  # 注入过滤器（SpringBoard 等 5 个进程）
├── build.sh / verify.sh       # 构建（含 isa 认证补丁与断言）/ 安装后校验
├── libsubstrate_roothide.tbd  # roothide substrate stub
├── layout/DEBIAN/postinst     # 安装脚本（打印 dylib md5）
└── reports/                   # 13 篇案卷报告（04→16，完整归因与攻坚记录）
```

## 九、许可与致谢

- 本项目以 **[MIT License](LICENSE)** 发布；
- BioProtect、CallAssistant（CallAssist）均为 **Limneos** 的产品；本项目是对其进行**独立观测与诊断**
  的工具，**未分发、未修改**上述产品的任何代码或二进制；泄漏定责基于栈回溯的客观观测数据；
- 修复思路（接管-宽限-回收）与全部代码为本项目原创。
