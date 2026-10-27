# BioProtect 4.6-222 (roothide) 逆向分析与资源泄漏修复

> 分析对象：`BioProtect (iOS 14 to 17) (roothide)-4.6-222+deb..deb`（735,182 B，`net.limneos.bioprotectxs`，`Version: 4.6-222+debug`）
> 目标设备：iPhone 15 Pro / iOS 17.2.1 / RootHide 越狱
> 症状：长时间使用后桌面注销（SpringBoard 被系统杀掉重启），多个 BioProtect 版本均有
> 分析日期：2026-10-23
> 产物：`release/com.local.bioprotectleakguard_2.0.3_iphoneos-arm64.deb`（11.2 KB）

---

## 0. 结论（先给答案）

**两类真实泄漏，都是"申请了从不释放"，与版本无关，所以换版本照样复发：**

| # | 位置 | 申请 | 释放 | 每次泄漏量 |
|---|---|---|---|---|
| A | `BioProtect.dylib` 两处 CFUserNotification | `CFUserNotificationCreate` + `CreateRunLoopSource` + `CFRunLoopAddSource` | **全二进制 0 处** `CFUserNotificationCancel` / `CFRunLoopRemoveSource` | 1 个 mach 应答端口 + 1 个主 RunLoop 源 + 2 个 CF 对象 |
| B | `BioProtect.dylib` 两处文件读取 | `open()` + `read()` + `malloc()` + `strdup()` | **无 `close` / 无 `free`** | 1 个 fd + 2 块内存 |

**为什么是 B 更像"十几个小时后注销"：** fd 的上限（`RLIMIT_NOFILE`，通常 256～1024）比 mach 端口上限小一到两个数量级，
同样是"每事件漏一个"，fd 会先撞顶。B 的 `sub_4f2bc` 是被**文件监听回调**（`sub_4f6c8`，kevent）调用的，
一次文件变化就漏一个 fd——这是唯一能按"小时"量级把资源吃干净的路径。

**同时必须纠正上一版报告（4.7）里的两个判断**，本次逐条核对后不成立：

| 旧结论 | 本次核对结果 |
|---|---|
| `notify_register_check` 用"栈上 token"，每调用漏一个端口 | **不成立**。31 处调用全部把 token 存进全局变量（一次性注册）。唯一用栈上 token 的 `sub_41434` 紧接着就 `notify_cancel`（0x41478），是全二进制里唯一写对的地方 |
| `BioProtectUIKit` 反复建 XPC 连接导致端口增长 | **不成立**。`xpc_connection_create_mach_service` 只有 1 处（0x5074，构造函数内一次），不随事件增长 |

修复不靠打补丁改二进制（换版本就失效），而是在运行时接管这两类资源的"释放"：
`BioProtectLeakGuard 2.0.3`，只对 `dladdr` 命中 `BioProtect` 的调用方生效，不改变任何界面与鉴权行为。

---

## 1. 样本指纹

| 项 | `BioProtect.dylib` | `BioProtectUIKit.dylib` | `BioProtectPhotosProtection.dylib` |
|---|---|---|---|
| 体积 | 1,343,168 B | 157,168 B | 160,816 B |
| 切片 | arm64 `sub=0x0` @0x4000 + **arm64e `sub=0x80000002`** @0xa8000 | arm64e @0x4000 + arm64 @0x18000 | arm64e @0x4000 + arm64 @0x18000 |
| `__text`（arm64e） | 0x8000–0x51034 | 0x4000–0x5750 | 0x4000–0x5cdc |
| ObjC 类 / 方法 | 11 类 / 184 方法 | 1 类 | 2 类 / 4 方法 |
| `MSHookMessageEx` | **207 处** | — | — |
| `CFNotificationCenterAddObserver` | **47 处**（全部在初始化阶段，一次性） | 少量 | 少量 |
| 导入符号 | 239（arm64e） | 50（arm64） | 46（arm64） |

注入面（`Library/MobileSubstrate/DynamicLibraries/*.plist`）：

- `BioProtect` → `com.apple.springboard`、`com.apple.Preferences`、`com.apple.camera`、`com.apple.InCallService`、`com.apple.Spotlight`，`Mode=Any`
- `BioProtectUIKit` → `Classes = UIApplication / SLComposeViewController / MFMailComposeViewController / MFMessageComposeViewController / TWTweetComposeViewController`（**注入所有链接 UIKit 的进程**）
- `BioProtectPhotosProtection` → `com.apple.AssetsLibrary`、`com.apple.Photos`

roothide / 破解痕迹：

- 导入 `__Z6jbrootP8NSString`（`jbroot(NSString*)`）→ 经 RootHide 转换器处理过；包内路径仍是 rootless 布局（`Library/...`）。
- 导入 `_jailbreakd_sockfd` / `_jailbreakd_server` / `_jailbreakd_serveraddr` / `_jailbreakd_serverlen`。
- 授权校验走 **UDP 到 127.0.0.1:2000**：`sub_8044` = `socket(AF_INET, SOCK_DGRAM)` + `gethostbyname("127.0.0.1")` + `sendto`，
  配套字符串 `Enter Transaction ID of purchase` / `Checking Transaction ID...`。socket 存在全局（`0x6b2f8`），有一个关闭函数但没有调用者 —— 只是一个常驻 fd，不是增长型泄漏。
- `postinst` 会删 `Limneosos.dylib` 与 `BioProtectXSHack.dylib`（作者自带的反破解清理）。

---

## 2. 泄漏 A：CFUserNotification 应答端口 + 主 RunLoop 源

### 2.1 站点与反汇编

**A1 `sub_95f4`**（被 `-BioProtectEmptyViewController loadView`（IMP 0x9448）里的 block invoke `0x97f4` 调用）：

```asm
0x9700  adrp/ldr  x0, [..]              ; 通知字典
0x9718  ldr       x0, [0x6ad50]         ; 类
0x9724  bl        objc_msgSend           ; 造字典
0x9738  fmov      d0, #10.0             ; timeout = 10s
0x973c  mov       x1, #3                ; flags = StopAlert
0x9740  add       x2, sp, #0x4c         ; &error
0x9744  bl        CFUserNotificationCreate
0x9760  bl        CFUserNotificationCreateRunLoopSource   ; cb = 0x97b4（空回调）
0x9768  bl        CFRunLoopGetMain
0x977c  bl        CFRunLoopAddSource    ; kCFRunLoopCommonModes
0x9780  b         0x9784  → retab        ; ← 直接返回，没有任何清理
```

**A2 `sub_479d8`**（`__DATA_CONST 0x60a08` 处 block 表的执行体，实验性功能提示；结尾把 `0x6be89` 字节置 1 防重复弹窗）：

```asm
0x47c1c  fmov d0, #10.0
0x47c20  mov  x1, #3
0x47c28  bl   CFUserNotificationCreate
0x47c44  bl   CFUserNotificationCreateRunLoopSource      ; cb = 0x47ca8（空回调）
0x47c60  bl   CFRunLoopAddSource
0x47c68  strb w8, [x9, #0xe89]                            ; 置"已提示"标志
0x47ca4  retab
```

### 2.2 决定性证据：全二进制没有释放路径

| 符号 | 调用次数 | 地址 |
|---|---|---|
| `CFUserNotificationCreate` | 2 | 0x9744、0x47c28 |
| `CFUserNotificationCreateRunLoopSource` | 2 | 0x9760、0x47c44 |
| `CFRunLoopAddSource` | 2 | 0x977c、0x47c60 |
| **`CFUserNotificationCancel`** | **0** | 不在导入表，也不在 `__cstring`（排除 `dlsym`） |
| **`CFRunLoopRemoveSource`** | **0** | 同上 |

引用计数分析：`note` 创建后 +1（源码持有）、被 RunLoopSource 持有 +1；`src` 创建 +1、被 RunLoop 持有 +1。
源码一个都不还 → 端口（CFMachPort，向通知服务注册的应答端口）与主 RunLoop 上的 Source 永久驻留。
主 RunLoop 上的 Source 只会越积越多，每轮 RunLoop 迭代都要遍历，属"既漏对象又拖慢主线程"。

`BioProtectPrefs`（设置面板，813,552 B）里也有同一套写法（0x2d5e8 / 0x2d604 / 0x2d620，无 Cancel），
但它只跑在设置进程里，进程退出即回收，危害小；本模块仍一并覆盖。

---

## 3. 泄漏 B：`open()` 不 `close()`（本次新发现）

### 3.1 两个泄漏函数

`sub_4a59c`（0x4a59c–0x4ab30）与 `sub_4f2bc`（0x4f2bc–0x4f6c8）的完整调用集合：

```
sub_4a59c:  open ×1, read ×2, malloc ×1, strdup ×1, _stack_chk_fail ×1, sub_43d4c ×6
sub_4f2bc:  open ×1, read ×2, malloc ×1, strdup ×1, _stack_chk_fail ×1, sub_43d4c ×4
```

**没有 `close`，没有 `free`。** 全二进制 `close` 只有 1 处（0x82c8，关的是授权校验的 socket），
`open` 有 2 处（0x4a94c、0x4f4d4）——两个 open 都没有对应的 close。

典型代码形状（`sub_4a59c`）：

```asm
0x4a948  mov  w1, #0            ; O_RDONLY
0x4a94c  bl   open
0x4a950  str  w0, [sp, #0x1c8]  ; fd 只存在栈上
0x4a980  bl   read              ; 最多 0x200 字节
0x4a9cc  bl   read              ; 循环读
0x...    bl   malloc / strdup
0x...    retab                  ; ← 栈帧销毁，fd 与内存全部有去无回
```

### 3.2 触发链（关键：其中一条是文件监听回调）

```
sub_4f6c8  ← 文件变化事件回调（CFFileDescriptor + kevent）
   ├─ 0x4f890 → sub_4f2bc        ← 每次事件漏 1 个 fd
   └─ 0x4f8a0 → sub_4fe4c → sub_4e984

sub_425e0 → sub_4dc8c（0x4dfe0 / 0x4dfec 调 2 次 sub_4f2bc）
sub_2c564（含 _basename 与 2 次 MSHookFunction，读文件做校验）→ 0x2cb58 → sub_4a59c
```

`sub_4f6c8` 是 **kevent 驱动的文件监视回调**（`CFFileDescriptorGetNativeDescriptor` → `kevent(..., EVFILT_VNODE)` → `CFFileDescriptorEnableCallBacks`），
只要被监视的文件发生变化就会跑一次。BioProtect 的配置/授权文件在运行期会被反复读写，因此这条链是**可重复、可高频**的。

### 3.3 量级换算（为什么这才是"注销"的主因）

- 假设 fd 软上限 1024、SpringBoard 基线占用约 200 → 可用余量约 800。
- 若文件监听链平均每小时触发 30～60 次（开关 App、改设置、授权状态变化都会触发），15 小时就是 450～900 个 fd —— **正好撞顶**。
- 撞顶后不是"BioProtect 用不了"，而是**SpringBoard 自己 `open()` 全线失败**（图像、数据库、沙盒、XPC 全要 fd），
  表现为卡死、被 watchdog/jetsam 杀掉 → 用户看到的就是"注销"。

其余内存泄漏（`malloc` 13 次 / `free` 3 次）同源，量小得多，一并由本模块的 fd 回收间接缓解（fd 一关，对应缓冲不再被引用）。

---

## 4. 修复设计

### 4.1 为什么不用"改二进制"

- 泄漏点分散在 block、回调、C++ 静态函数里，改一处要重排指令，没有插入 `close()`/`Cancel` 的空间；
- 版本一变偏移全变（4.7 的同名函数在 0x5144，本版在 0x95f4 / 0x479d8），维护成本高；
- 运行时接管 API 能一次覆盖所有版本、所有注入进程。

### 4.2 `BioProtectLeakGuard 2.0.3` 做了什么

| 模块 | 做法 | 默认参数 |
|---|---|---|
| CF 回收 | hook `CFUserNotificationCreate` / `CFUserNotificationCreateRunLoopSource`；只接管 `dladdr` 命中 `BioProtect` 的调用；宽限期到点后 `CFUserNotificationCancel`（释放应答端口）+ 从主 RunLoop 摘除 Source + 释放自己持有的引用 | 宽限 15s（原弹窗 timeout 10s），每 5s 扫一次 |
| fd 回收 | hook `open()`，只记录"调用方是 BioProtect 且路径是绝对路径"的 fd；当 fd 使用量超过水位时，对存活超过宽限期的记录用 `fcntl(F_GETPATH)` **复核路径一致**后再 `close()` | 水位 320（或"上限−64"，取小者），宽限 30s，每 30s 扫一次 |
| 观测 | 每 5 分钟写一行 `stat ports=… fd=…/… cf_called=… cf_adopt=… cf_free=… fd_open=… fd_close=…` | 间隔 300s |
| 兜底 | 默认关闭。打开后：资源逼近上限且锁屏时，主动 `exit(0)` 做一次受控重启（6 小时内最多一次） | `EnableAutoRespring=false` |

**安全红线（代码里逐条落实）：**

1. 只在 `dladdr` 命中 `BioProtect*` 的调用方上动手，绝不碰系统或其它插件创建的通知/fd。
2. `close()` 之前必须 `F_GETPATH` 路径复核一致——防止 fd 号被系统复用后误关别人的文件。
3. 没到水位不扫、不关，平时零副作用。
4. 所有回收动作只写日志，不抛异常；日志 256KB 上限，保留尾部 128KB。
5. 关掉任一功能只需改 `config.plist` 对应布尔值 + 注销，无需卸载。

### 4.3 注入范围

与 BioProtect 自身的过滤器对齐：`com.apple.springboard`、`com.apple.Preferences`、`com.apple.camera`、
`com.apple.InCallService`、`com.apple.Spotlight`（这 5 个进程都会加载 `BioProtect.dylib`）。

---

## 5. 安装与验证（傻瓜版）

1. 把 `release/com.local.bioprotectleakguard_2.0.0_iphoneos-arm64.deb` 传到手机。
   **本机是 roothide 越狱，必须先用 RootHide 的转换器转换这个 deb 再安装**（与 VolumeManager 那套一样）。
2. 安装后 **注销一次**（respring）。
3. 打开一次设置，或随便开关几个 App，让 SpringBoard 跑起来。
4. 5 分钟后用 Filza 打开 `/var/mobile/Library/BioProtectLeakGuard/guard.log`。

### 日志落点（2.0.1 起多路径同时写，2.0.2 起共 7 条）

roothide 上「裸 `/var/mobile`」可能被 libroot 按 jbroot 重定向，同一份日志在 Filza 里可能不在你预期的位置
（本项目音量插件踩过同款坑：裸路径造出一个只有日志的空目录，容易把人绕晕）。2.0.1 起同时写下面 5 个位置，
任意一个能找到即可；启动第一行 `日志落点: ...` 会直接告诉你是哪几个写成功了：

| # | 路径 |
|---|---|
| 1 | `/var/jb/var/mobile/Library/BioProtectLeakGuard/guard.log` |
| 2 | `/var/mobile/Library/BioProtectLeakGuard/guard.log` |
| 3 | `/.jbroot/var/mobile/Library/BioProtectLeakGuard/guard.log` |
| 4 | `/var/mobile/Library/Preferences/BioProtectLeakGuard.log`（沙箱必定可写的兜底） |
| 5 | `/tmp/bioprotectleakguard.log` |

`config.plist` 同样在 1～3 三个目录各放一份（postinst 写入），模块逐个试读，第一个存在的生效；
`/var/mobile/Library/Preferences/BioProtectLeakGuard.plist` 也可作为第 4 候选。

### 日志怎么读

第一段应该是这样（没有就是模块没加载上）：

```
=== BioProtectLeakGuard 2.0.3 载入 pid=... 进程=SpringBoard BioProtect已注入=1 ===
配置: cf=1 fd=1 log=300s cf宽限=15s fd宽限=30s fd水位=320 respring=0 debug=0
hook 完成: CFUserNotificationCreate / CreateRunLoopSource
hook 完成: open()  fd 泄漏观测已开启
fd 上限: soft=... hard=... dtablesize=...
定时器已启动：...
```

之后每 5 分钟一行：

```
stat ports=... fd=.../1024 cf_called=... cf_adopt=... cf_free=... fd_open=... fd_close=... fd_skip=...
```

判据：

| 现象 | 含义 |
|---|---|
| `fd_open` 持续增长、`fd_close` 为 0 | 有泄漏，但还没到水位（正常，说明观测在工作） |
| 出现 `fd 回收: 本次关闭 N 个泄漏 fd` | 已到水位并成功回收 —— 泄漏被压住了 |
| `fd` 数值长期在一个区间内波动、不单调上升 | **修复成功** |
| `fd` 一路涨到接近上限、`fd_close` 一直是 0 | 回收没生效，请把日志发回来（大概是 `F_GETPATH` 复核没通过） |
| `ports` 一直缓慢上涨 | CF 通知回收没生效（`cf_free` 应随弹窗次数增长） |

### 想先只观测不干预

把 `/var/mobile/Library/BioProtectLeakGuard/config.plist` 里的 `EnableFDReclaim` 改成 `<false/>`，
注销后重新观察：`fd_open` 增长速率就是**真实泄漏速率**，可直接反推"多久会注销"，也能确认本报告的量级估算。

---

## 5.5 2.0.1 装到设备上"没有日志、也没有崩溃记录"的复盘

现场：`/var/jb/Library/MobileSubstrate/DynamicLibraries/` 里 dylib 与 plist 都在，
但七个落点都没有日志，`SpringBoard-*.ips` 也没有。

逐条排除后定位到**依赖解析**：

| 检查项 | 结果 |
|---|---|
| 注入过滤器 | 与 BioProtect 完全一致（同 5 个 bundle + `Mode=Any`）→ 排除 |
| CPU 架构 | 我们的 arm64；转换后的 `BioProtect.dylib` 本身也是 `CPU_TYPE_ARM64 / subtype 0x0` → 排除 |
| 是否注入即崩 | 无崩溃日志 → 排除 |
| **依赖库** | **命中** |

对比转换后的 BioProtect 三个 dylib，它们的 substrate 依赖被 RootHide 转换器改写成了
`@loader_path/.jbroot/usr/lib/libsubstrate.dylib`；而 2.0.1 的 dylib 里仍写着
`@rpath/CydiaSubstrate.framework/CydiaSubstrate`。当这个 framework 在 roothide 环境里不存在时，
**dyld 只会静默跳过这份 dylib**——不注入、不日志、不崩溃，正好就是看到的现象。

**2.0.2 的改法**：彻底去掉 substrate 依赖（`Makefile` 不再 `-lsubstrate`），
把 `MSHookFunction` 改成运行时解析（`dlsym(RTLD_DEFAULT)` → 自目录 `/.jbroot/usr/lib/libsubstrate.dylib`
→ `/var/jb/usr/lib/libsubstrate.dylib` → framework 路径）。解析失败也不影响加载，只降级为"只观测不修复"，
并在日志里写明 `钩子引擎: 不可用`。这样 dylib 的依赖只剩系统库，加载不再有任何外部前提。

## 5.6 RootHide 转换器会重写包里的绝对路径（2.0.3 的由来）

2.0.2 安装日志里，postinst 打印的路径与源码不一致：

| 源码里写的 | 设备上打印出来的 |
|---|---|
| `/var/jb/var/mobile/Library/BioProtectLeakGuard/guard.log` | `/var/mobile/Library/BioProtectLeakGuard/guard.log` |
| `/var/mobile/Library/BioProtectLeakGuard/guard.log` | `/rootfs/var/mobile/Library/BioProtectLeakGuard/guard.log` |
| `/var/mobile/Library/Preferences/BioProtectLeakGuard.log` | `/rootfs/var/mobile/Library/Preferences/BioProtectLeakGuard.log` |

也就是说 RootHide 转换器把包里的绝对路径**改写**了（`/rootfs` 是绕过 jbroot 重定向、指向真实根文件系统的前缀）。
脚本都被改写，dylib 里的字符串同样会被改 —— 任何「写死 `/var/mobile/...`」的日志方案在转换后都不可靠，
日志会落到程序作者没预料的位置。

**2.0.3 的两条修正**：

1. 日志路径全部运行时拼：`NSHomeDirectory()` / `NSTemporaryDirectory()` + 相对后缀
   （`/Library/BioProtectLeakGuard/guard.log`、`/Library/Preferences/BioProtectLeakGuard.log`、
   `/Documents/BioProtectLeakGuard.log`、`tmp/BioProtectLeakGuard.log`），dylib 里不再有可被改写的绝对路径。
2. 叠加 **CFPreferences 影子日志**：日志走 `CFPreferencesSetAppValue("diaglog", 域 "com.local.bioprotectleakguard")`，
   由 `cfprefsd` 落盘到 `/var/mobile/Library/Preferences/com.local.bioprotectleakguard.plist`。
   这条链路不经过我们的任何路径拼接，不受转换器改写、不受沙箱、不受 jbroot 重定向影响 —— 一定能读到。

## 6. 已知局限

1. **fd 回收是"止损"不是"根治"**：真正的修法是让 BioProtect 在 `sub_4a59c` / `sub_4f2bc` 末尾 `close(fd)`，
   但那要改二进制且版本相关，不做。当前方案把"无界增长"变成"有界波动"，效果等价于修好。
2. **`F_GETPATH` 复核有可能放走个别 fd**：若 BioProtect 关过该 fd 且号码被复用，路径对不上就跳过（这是刻意的保守策略），
   这类 fd 会在下次泄漏时重新被记录。日志里的 `fd_skip` 就是这个计数。
3. **只覆盖 `open()`**：`fopen` / `socket` / `xpc` 路径未纳入（核对过：`fopen`/`fclose` 成对、socket 只有 1 个常驻、xpc 连接只建 1 次）。
4. **CF 通知回收会取消"仍在展示"的弹窗**：宽限期 15s > 原 timeout 10s，正常情况下用户看不到差异。
5. 本模块不修 BioProtect 的授权校验（UDP 到 127.0.0.1），那是破解包的自身逻辑，与本问题无关。

---

## 7. 复现分析的方法（下次遇到同类问题照做）

分析脚本都在 `bioprotect-analysis/scripts/`（编号 10–31，配套 `bplib.py` / `objc_parse.py`）：

| 脚本 | 作用 |
|---|---|
| `00_unpack_46.sh` | WSL 内 `dpkg-deb -x/-e`，保留权限 |
| `11_46_imports.py` / `12_46_allimports.py` | 导入表筛选（端口/通知/xpc 关键词） |
| `13_46_callsites2.py` / `bplib.py` | **arm64e stub 解析**：`adrp x17` + `add x17` + `ldr x16,[x17]` + `braa`，四指令一组，不能按 12 字节步长切 |
| `21_46_listing2.py` | 带寄存器跟踪的注解反汇编（adrp/add/ldr → CSTR / SEL / CLASS） |
| `objc_parse.py` | 手写 ObjC 元数据解析：**相对方法列表的 name 字段指向 `__objc_selrefs` 槽，要再解一次** |
| `26_46_notify_sites.py` | 判定 notify token 存栈上还是全局（区分"真泄漏"与"一次性注册"） |
| `27_46_fdcheck.py` | 按函数统计 open/close/read 配对，抓 fd 泄漏 |
| `24_46_xref.py` | 数据段 xref（找出 block 表里的函数指针） |

踩过的坑：

- LIEF 这版**没有** `objc_metadata`（extended 才有），必须手写解析。
- `__cfstring` 在这份二进制里是压缩布局（`isa` + `flags(u32)` + `ptr(u32)` + `len(u64)`），
  按 `isa/flags/ptr/size` 四字段 64 位读会全错位。
- 反汇编注解必须做**寄存器跟踪**：`adrp` 的页基址会跨指令残留，不做跟踪会把栈上的 `ldr` 误标成 SEL，读代码会得出完全错误的结论。
- `notify_register_check` 的 token 是不是泄漏，**必须逐个看 `&token` 是 `sp` 相对还是全局**，只数 import 次数会误判（上一版报告就栽在这）。
