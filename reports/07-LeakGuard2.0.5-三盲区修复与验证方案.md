# 07 BioProtectLeakGuard 2.0.5：装上却看不到日志的三个盲区与补救

> 归档日期：2026-10-23（同日第二阶段） · 关联：06（阶段收尾）、05（4.6 逆向）
> 状态：**2.0.5 已构建并双重复核（build.sh 断言 + LIEF），待设备验证**

---

## 一、背景与输入

06 收工时的悬案：2.0.4（substrate 直连形态，与设备上确认可加载的 VolMan 同形）交付后，
用户反馈 `com.local.bioprotectleakguard.plist` 仍未出现，且**无法区分「没装」与「装了没加载」**。
本轮接手目标：不再依赖猜，把「装上却看不到日志」的每一种可能都堵上，让下一次设备验证一次到位。

## 二、症结分析（静态审查 + 二进制复核的结论）

对 2.0.4 源码（`bioprotect-fix/BioProtectLeakGuard.xm`）与 deb 产物逐层审查，发现三个盲区：

### 盲区 ①（关键）：影子日志在 dyld init 阶段做同步 XPC

2.0.4 的日志链路：`bplg_log → bplg_vlog → bplg_prefs_shadow →
CFPreferencesSetAppValue + CFPreferencesAppSynchronize`。

而 `%ctor` 里**第一条 boot 日志就会走到这里**——此时是 dyld init 阶段（SpringBoard 的 `main`
尚未执行）。对 cfprefsd 做同步 XPC：

- 轻则**静默失败**（值留在进程缓存、cfprefsd 从未收到）→ 恰好复现「dylib 已加载、
  diaglog 却始终不出现」的现象，与用户报告完全兼容；
- 重则卡启动（无实证，但理论存在）。

这条「%ctor 阶段写 CFPreferences」的路径**从未在本设备验证过**（VolMan 全程只用 plist 文件
读写），是 2.0.4 唯一没被设备证据背书的设计点。

### 盲区 ②：文件日志落点全部指向用户找不到的位置

- home 派生路径在 roothide 下被 libroot 重定向到 `.jbroot-*/var/mobile/...` 内部；
- `/tmp/bioprotectleakguard.log` 与 config 路径数组是**写死的绝对路径字面量**（LIEF 实测
  2.0.4 dylib 内 `/var/mobile` ×5、`/var/jb` ×3、`/tmp/...` ×1）——**RootHide 转换器会改写**，
  改写后落点不可预测。
- 结果：即使 dylib 加载且文件日志在写，用户在 Filza 里也找不到。

### 盲区 ③：没有「安装证据」

postinst 只建目录、放 config，不落任何可辨识标记。「plist 没出现」无法区分：
- 用户还没装 2.0.4（06 收工时的可能性 A，至今未排除）；
- 装了但 dylib 未加载（可能性 B）；
- 装了、dylib 加载了、但影子通道静默失败（本轮新识别的可能性 C，即盲区 ①）。

## 三、2.0.5 修复内容

| # | 修改 | 目的 |
|---|---|---|
| 1 | 影子日志延迟启用：新增 `gShadowReady` 门闩，`%ctor` 阶段一律跳过 CFPreferences；GCD 定时器首个 tick（约 +5s，`main` 已跑、cfprefsd 就绪）调 `bplg_shadow_boot()` 启用并补写横幅 | 堵死盲区 ①：启动期 XPC 风险清零 |
| 2 | 影子通道自验证：`bplg_shadow_boot` 用 `CFPreferencesCopyAppValue` 回读 diaglog，结果写进文件日志与 stat 行（`shadow=ok/fail/wait`） | 把「cfprefsd 收没收到」变成可观测 |
| 3 | 新增 `/rootfs` 真实根直写落点：`bplg_rootfs_home()` 运行时拼 `/rootfs` + home 相对后缀 → 日志直写真实根 `/var/mobile/Library/BioProtectLeakGuard/guard.log`，不依赖 cfprefsd、不被 libroot 重定向 | 堵死盲区 ②：Filza 从根直接可见（依据：转换器把 postinst 路径改写为 `/rootfs/...` 前缀，证明 libroot 对该前缀放行到真实根） |
| 4 | dylib 内**彻底清除写死绝对路径**：config 路径数组改运行时拼接；`/tmp` 落点拆成前缀+文件名两个字面量 | 转换器无从改写（LIEF 复核 `/var/mobile` ×0） |
| 5 | postinst 落**安装标记** `BioProtectLeakGuard.installed`（Preferences 目录等多处，含版本+时间戳） | 堵死盲区 ③：「装没装」一查便知 |
| 6 | `build.sh` 新增断言：dylib 内出现 `/var/mobile` 字面量即构建失败 | 防回归 |

不变的部分：substrate 直连形态（`#include <substrate.h>` + 直调 `MSHookFunction`，导入
`_MSHookFunction`、依赖 `@rpath/CydiaSubstrate.framework/CydiaSubstrate`，与 VolMan 完全同形）；
CF 泄漏接管、fd 水位回收、F_GETPATH 复核、dladdr 调用方判定逻辑全部原样保留。

## 四、产物

| 项 | 值 |
|---|---|
| deb | `release/com.local.bioprotectleakguard_2.0.5_iphoneos-arm64.deb`（12,168 B，md5 `347a56f88a4630e2e548a0daa8e10080`） |
| dylib | 72,032 B，755，arm64 单切片，md5 `dd39a0aaa4c3ee4dc5506a94fcab883e` |
| LIEF 复核 | substrate 依赖 ✓ / `_MSHookFunction` 导入 ✓ / `CFPreferences*` 三符号导入 ✓ / 版本串 2.0.5 ✓ / `/var/mobile` ×0 ✓（2.0.4 为 ×5） |
| postinst | 含 installed 标记写入 + 三步验证指引 ✓ |
| 源码 | `bioprotect-fix/`（镜像已与 `codetest/bioprotect-fix` 字节级同步） |

注：dylib 内残留的 `/var/jb/` ×2 是 LC_RPATH（链接器生成，2.0.4 与 VolMan 同样存在），
转换器会正确处理，非源码字面量。

## 五、设备验证步骤（傻瓜级，按顺序看三跳）

1. **RootHide 转换器**把 2.0.5 deb 转换后，用 Sileo/Filza 安装，**respring**。
2. **第一跳（装没装）**：Filza 打开 `/var/mobile/Library/Preferences/`，找
   `BioProtectLeakGuard.installed`，内容应有 `2.0.5 installed at <时间>`。
   没有 → 包没装上（或装了旧版），到此为止，先解决安装。
3. **第二跳（加载没）**：同一目录找 `com.local.bioprotectleakguard.plist`，打开看 `diaglog` 键
   （等 5 分钟再看）。出现 `[boot]`、`影子通道启用`、`stat ports=...` 行 → **dylib 已加载**。
   - `stat` 行里 `shadow=ok` → 影子通道正常；
   - `shadow=fail` → cfprefsd 链路异常，但**文件日志仍在写**，看第三跳。
4. **第三跳（修复效果）**：看 `guard.log`（优先 `/var/mobile/Library/BioProtectLeakGuard/guard.log`
   真实根直写）或 diaglog 里的 `stat` 曲线：
   - `ports=` 从单调上升变为平台/回落、`cf_free` 增长 → CF 端口回收生效；
   - `fd_close` 增长 → fd 回收生效；`fd_close` 恒为 0 而 `fd_skip` 增长 → F_GETPATH 复核
     没过，把 stat 行发回分析；
   - `ports=` 仍线性涨且 `cf_adopt` 很少 → 泄漏源不止 CFUserNotification，按 06 §四 排查其它插件。

## 六、判读表（现象 → 结论 → 下一步）

| 现象 | 结论 | 下一步 |
|---|---|---|
| installed 标记都没有 | 包没装上 | 检查转换/安装流程，与代码无关 |
| 有 installed、无 diaglog、无 guard.log | dylib 未加载（substrate 形态理论被挑战） | 收集：Sileo 显示版本、DynamicLibraries 下文件大小（≈72,032 B）、是否 respring、包内 `.roothidepatch` 标记 |
| 无 diaglog、但 guard.log 在写（含 `shadow=fail`） | dylib 已加载，cfprefsd 链路异常 | 影子通道弃用即可，文件日志已够用；回传 stat 曲线 |
| diaglog 正常、`shadow=ok` | 全链路健康 | 只看 `ports=`/`fd=` 曲线评估修复效果 |

## 七、本轮新经验（已并入 MEMORY.md）

1. **roothide 的 `/rootfs` 前缀是运行时逃逸口**：libroot 对该前缀放行到真实根文件系统
   （由转换器改写行为反证）。「tweak 想直写真实根」可用运行时拼接 `/rootfs` + 路径后缀实现，
   且前缀与后缀拆成两个字面量后，转换器按完整路径匹配便无从改写。
2. **%ctor（dyld init）阶段不要做同步 XPC**：CFPreferences 写入挪到首个 GCD tick（+5s），
   `main` 已跑、cfprefsd 就绪，失败率与死锁风险都归零。
3. **「装上没反应」要设计成三态可判**：安装标记（postinst）→ 加载证据（影子/文件日志）→
   修复效果（stat 曲线），每层独立可观测，才不会陷入「一个现象多种解释」的悬案。
