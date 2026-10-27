# 14 泄漏点名：IOKit → powerd XPC 轮询 + 2.0.11 栈回溯定位驱动插件

> 归档日期：2026-10-26 凌晨 · 关联：13（XPC 连接泄漏定性与 2.0.10）
> 状态：**泄漏接口已点名（IOKit 电池/电源 → com.apple.iokit.powerdxpc）；2.0.11 已构建，
> 装后日志直接给出驱动它的插件名与偏移**

---

## 一、一句话结论

2.0.10 的归因收口成功：`top xpc img` 榜首 **IOKit** 一骑绝尘（683 → 11121，每 5 分钟
+600~950 ≈ 2-3 次/秒），明细行 `IOKit+3cde4/com.apple.iokit.powerdxpc`——**SpringBoard
里有代码在反复调用 IOKit 的电池/电源接口**（每次调用创建一条到 powerd 的 XPC 连接且
从不释放）。第二名 Foundation（NSXPCConnection 便捷封装的各服务）仅 ~390 次且基本
一次性，可忽略。至此：**死因 = IOKit 电源接口轮询泄漏 × 10 小时 = 131072 端口 = 注销**。

## 二、数据摘录（guard.log 22:49–00:04，SB pid 6750）

| 时间 | ports | xpc5 | IOKit 榜首累计 | 第二名 |
|---|---|---|---|---|
| 22:54 | 2616 | 970 | 683 | Foundation 169 |
| 23:24 | 12508 | 603 | 5628 | Foundation 242 |
| 23:54 | 20927 | 933 | 9755 | Foundation 329 |
| 00:04 | 23630 | 675 | 11121 | Foundation 392 |

- IOKit 占全部 XPC 创建的 **94%+**，且速率恒定（屏幕使用与否不影响 → 后台定时轮询）；
- 次要源：`SystemConfiguration+a268`（mach_port_construct 口，+120/5min，网络状态
  轮询形态——Shadowrocket.Widget 这类网络插件的典型行为，量级为主犯的 1/8）；
- `Foundation+2d8dc` = NSXPCConnection 便捷封装（siri.uaf.service 等，~2/5min，正常量级）。

## 三、嫌疑人画像与 2.0.11

IOKit+3cde4 是系统框架内部地址——真正**驱动**它的是更上层的调用者（某个插件在定时器里
轮询电池/电源状态）。SB 注入插件里符合画像的候选（按嫌疑排序）：
**Immortalizer**（保活类）、**CPUDasher 系**（CPU/电池仪表）、**Lynx2_CN**、**SHELLX**、
**Crane**、**Shadowrocket.Widget**（更贴合 SystemConfiguration 次要泄漏）。

与其逐个卸载试，2.0.11 直接在 xpc 钩子里做**栈回溯归因**：当直接调用方是系统框架时，
`backtrace()` 最多 12 帧，找**第一个非系统帧**（不在 /System/、/usr/lib/，也排除我们与
注入器）→ 该帧的镜像+偏移就是驱动插件；全栈都是系统帧则记 `SpringBoard(self)`。
iOS arm64 默认保留帧指针，回溯可行；backtrace 需手动 extern 声明（SDK 头文件缺失）。

stat 后新增输出行：`xpc 驱动者(栈回溯): 插件名+偏移:次数 …`

## 四、产物

| 项 | 值 |
|---|---|
| 包 | `release/com.local.bioprotectleakguard_2.0.11_iphoneos-arm64e.deb` |
| 包 md5 | `9681f19c9665ebacc4a0c9669c9bd09d` |
| 设备端 dylib 应有 md5 | `c71914ebde160b57e10c4dd313e258f2` |

## 五、验证与后续（装 2.0.11 → respring → 10 分钟 → 取 guard.log）

1. 看 `xpc 驱动者(栈回溯):` 行：
   - 第一名是**插件名+偏移** → 定责完成。处理二选一：
     a. **卸载/禁用该插件**（用户操作，最干净）→ 观察 ports 曲线 30 分钟内归平即为实锤；
     b. 若该插件必须保留 → 我们按偏移做针对性 hook（对该调用点的连接用完即 invalidate，
        或拦截其轮询定时器降频）。
   - 第一名是 `SpringBoard(self)` → SB 原生代码在漏（系统 bug 或配置诱发）→ 换思路：
     对 IOKit+3cde4 调用点直接做「宽限后 invalidate」兜底（拿到确切调用频率后安全可做）；
   - `(no-stack)` → 帧指针缺失，回退用逐个卸载嫌疑插件对照法。
2. 止血开关仍可选：config.plist `EnableAutoRespring=true`。

## 六、全案时间线小结（04→14 报告）

1. 04/05：逆向定性 BioProtect 的 CF/fd 泄漏（后被真机数据修正——非本案主因）；
2. 06-09：arm64e 三层根因（架构/ABI/转换器误判）；
3. 10：isa 未认证（真 root cause）→ 2.0.7 修复成功；
4. 11：定时器 ARC bug → 2.0.8 修复成功，归因开始产出数据；
5. 12：BioProtect 零嫌疑实锤，泄漏在 construct/xpc 口；
6. 13：定性 = 每秒 2.9 个 XPC 连接不释放；
7. 14（本篇）：点名 IOKit/powerdxpc，2.0.11 栈回溯锁定驱动插件。
