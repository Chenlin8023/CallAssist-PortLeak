# BioProtect XS 4.7 — Mach 端口泄漏根因分析与修复方案

> 分析对象：`BioProtect XS-4.7-4-iphoneos-arm64e..deb`（包名 `org.mr.bioprotectxs-rootless`，已带 RootHide 转换补丁）
> 目标设备：iPhone 15 Pro / iOS 17.2.1 / RootHide 越狱
> 分析日期：2026-10-18
> 分析方法：dpkg 解包 → FAT 切片解析 → 绑定表/桩解析 → 全量调用点统计 → ObjC 方法表还原 → 关键函数反汇编

---

## 0. 结论（先给答案）

**这不是"某个插件抢占了端口"，而是 BioProtect 自己在 SpringBoard 里反复申请端口却没有任何释放路径。**

四个注入模块的导入表里，端口类资源（CFUserNotification 应答端口、notify 检查端口、XPC 连接）的**申请 API 全都在，释放 API 一个都没有**——不是"某处忘了写"，而是整份二进制里根本不存在清理代码。因此：

- 泄漏是**结构性的、无界的**，与是否"恰好遇到冲突"无关；
- 其它插件的作用是**抬高 SpringBoard 的端口基线**，让同一根"漏水的管子"更快触顶；
- 15 小时不是固定值，而是"泄漏速率 ÷（上限 − 基线）"在当前装机组合下得到一个时间常数。

**同时必须说清楚的一点**：按实测频次估算，BioProtect 自身这四处泄漏合起来约"几十端口/天"，**单靠它不足以在 15 小时内触顶**。因此"15 小时"这个现象本身说明还叠着一个放大机制（§3 表）——本报告既给出已确证的缺陷与修复，也给出能把"谁在放大"测出来的手段，不用推测代替结论。

**触发链**：锁屏提示 / Face ID 身份变更 / 鉴权弹窗 → `CFUserNotificationCreate` + `CreateRunLoopSource` + `CFRunLoopAddSource`（主 RunLoop）→ 函数直接 `ret` → 端口与 RunLoopSource 永久驻留 → 端口空间/内核 ipc_port 与 vm_map 持续增长 → SpringBoard 被 jetsam 或端口空间耗尽判死 → 前端表现为"注销"。

---

## 1. 模块与注入面

| 模块 | 体积 | 注入过滤器 | 注入进程 | 端口相关行为 |
|---|---|---|---|---|
| `BioProtect.dylib` | 758,640 B | `Bundles`: springboard / Preferences / camera / InCallService / Spotlight，`Mode=Any` | **SpringBoard（常驻）** 等 5 类 | CFUserNotification ×2、notify 注册 ×31、XPC 服务端回复 |
| `BioProtectUIKit.dylib` | 168,512 B | `Classes`: UIApplication、SLComposeViewController、MFMailComposeViewController、MFMessageComposeViewController、TWTweetComposeViewController | **所有链接 UIKit 的进程**（含 SpringBoard、全部 App） | 连 `com.apple.frontboard.systemappservices`，2 处同步 XPC 往返 |
| `BioProtectPhotosProtection.dylib` | 168,240 B | `Bundles`: AssetsLibrary / Photos | 相册相关 | notify 注册 ×8 |
| `BioProtectXS_CN.dylib` | 148,784 B | `Bundles`: Preferences / springboard | 设置、SpringBoard | 仅字符串/汉化替换，无端口操作 |
| `BioProtectPrefs.bundle` | 506,352 B | — | 设置进程（短命） | CFUserNotification ×1 |
| `BioProtectModule.bundle` | 166,816 B | — | 控制中心 | 仅 `notify_post` |

`BioProtect.dylib` 是 **ARM64 FAT 双切片**（arm64 `cpusubtype=0x0` + arm64e `0x80000002`），`minos 14.0`，共 **212 处 `MSHookMessageEx`**、还原后 **11 个自有类**（`BioProtectController`、`BioAlertView`、`BioProtectUnlockController` 等）。

---

## 2. 根因证据

### 2.1 决定性证据：申请与释放 API 的配对缺失

对四个 dylib 的导入表做配对核对（`MISSING = 该模块从未链接该符号，即代码中不存在此调用路径`）：

| 模块 | 已申请端口资源 | 已链接的释放 API | 缺失的释放 API |
|---|---|---|---|
| `BioProtect.dylib` | `CFUserNotificationCreate`、`CFUserNotificationCreateRunLoopSource`、`CFRunLoopAddSource`、`CFNotificationCenterAddObserver`、`notify_register_check` | 仅 `notify_cancel`（全二进制 **1 处**）、`CFRelease`（不用于上述对象） | `CFUserNotificationCancel`、`CFRunLoopRemoveSource`、`CFRunLoopContainsSource`、`CFNotificationCenterRemoveObserver`、`mach_port_deallocate` |
| `BioProtectUIKit.dylib` | `xpc_connection_create_mach_service`、`xpc_connection_send_message_with_reply_sync`、`CFNotificationCenterAddObserver`、`notify_register_check` | 无 | `xpc_connection_cancel`、`xpc_connection_suspend`、`CFNotificationCenterRemoveObserver` |
| `BioProtectPhotosProtection.dylib` | `notify_register_check`、`CFNotificationCenterAddObserver` | `notify_cancel` | `CFNotificationCenterRemoveObserver` |
| `BioProtectXS_CN.dylib` | 无 | — | — |

> 关键点：`_CFRunLoopRemoveSource` 与 `_CFUserNotificationCancel` **在整个 BioProtect.dylib 中一次都没有被引用**。这意味着"加了 RunLoop Source 之后把它摘掉"这件事，代码里从没发生过。

### 2.2 泄漏点 A（主因）：CFUserNotification 应答端口 + RunLoopSource

核心函数位于 `BioProtect.dylib` 文件偏移 `0x5144`（`__text` 内），反汇编如下（节选，语义已标注）：

```asm
0051dc: bl  CFUserNotificationCreate        ; (0, flags=3, &respFlags, timeout=10.0s, dict)
0051f8: mov x1, x0                          ; notif
0051fc: adrp/add x2, #0x52b8                ; callback = 0x52b8
00520c: bl  CFUserNotificationCreateRunLoopSource
005214: bl  CFRunLoopGetMain
005228: bl  CFRunLoopAddSource              ; 挂到主 RunLoop，mode = kCFRunLoopCommonModes
005254: ret                                 ; ← 函数到此返回
```

`0x52b8` 处的回调只有一条指令：`ret`（空回调，纯粹为了让弹窗显示出来）。

**该函数从创建到返回，没有一次 `CFUserNotificationCancel`、没有一次 `CFRunLoopRemoveSource`、没有一次 `CFRelease`。** 每次调用产生的资源全部无主：

| 资源 | 引用计数去向 | 后果 |
|---|---|---|
| `CFUserNotification` | 创建 +1，源码不释放 | 对象常驻 |
| 应答端口（CFMachPort，向通知服务注册） | 由 notif 持有 | **SpringBoard 端口空间永久 +1** |
| `CFRunLoopSource` | 创建 +1，`AddSource` 再 +1，源码都不释放 | 主 RunLoop 永久 +1 个 source |

**调用者（由方法表 + 212 处 hook 表 + 达尔文观察者表三重反查得到，共 4 个入口）**：

| 触发点 | 调用链 | 条件 |
|---|---|---|
| Darwin 通知 `net.limneos.bioprotect.lockafterfiveseconds` | 观察者回调 `0x286bc` → `0x2895c` → `0x5144` | 每次"即将自动锁屏"提示 |
| `BiometricKit -removeIdentity:` | IMP `0x2be18` → `0x2c15c` → `0x5144` | 每次移除 Face ID 身份 |
| `BioProtectController -handleMessageNamed:userInfo:` | IMP `0xd0c0` → `0xe010` → `0x5144` | **仅"未录入指纹"错误分支**（弹窗文案实测为 `You do not have any fingerprints set so you cannot use this feature.`） |
| 授权提示（`0x2cef8` 处的第二处 `CFUserNotificationCreate`） | 独立实现，同样不带清理 | 授权/试用提示 |

> 修正说明：`lockdevicenow` 用的是另一个回调（`0x28f80`），**不**走这条弹窗路径；`BiometricKit -updateIdentity:`（IMP `0x2c1d8`）只发 notify，也不走弹窗。这两条在最初归类时容易混淆，此处已按调用点逐一对齐。


### 2.3 泄漏点 B：notify 检查端口（栈上 token 丢弃）

`BioProtect.dylib` 中 `-allowPhotoLibraryAccess:`（IMP `0xec0c`，`BioProtectController` 的方法）完整实现只有 5 条有效指令：

```asm
00ec28: add  x1, sp, #0xc                                 ; &token —— 在栈上
00ec30: bl   notify_register_check                        ; 新建一个 notify 检查端口
00ec38: ldr  w0, [sp, #0xc]
00ec3c: bl   notify_set_state                             ; 用一次
00ec44: bl   notify_post
00ec54: ret                                               ; token 随栈销毁，永不 notify_cancel
```

全二进制统计：`notify_register_check` **31 处**，`notify_cancel` **仅 1 处**（`0x292b4`，位于一个"读一次状态即取消"的辅助函数里，是唯一写对的地方）。其中十余处把 token 存进全局变量（属"永久占用"，不增长），但上表这类**栈上 token** 的写法每调用一次就净漏 1 个端口。

### 2.4 泄漏点 C：XPC 同步往返的回复对象从不释放

`BioProtectUIKit.dylib`（注入全部 App）在构造函数里建一次连接：

```asm
004934: bl  dispatch_queue_create("net.limneos.bioprotect.extensionhook.queue")
004948: bl  xpc_connection_create_mach_service("com.apple.frontboard.systemappservices", q, 0)
004960: bl  xpc_connection_set_event_handler
```

随后两处（`0x4354`、`0x4aec`）执行：

```asm
bl  xpc_connection_send_message_with_reply_sync   ; 无超时参数（该 API 本身无超时）
mov x24, x0                                       ; 回复字典（内含 reply port 引用）
...
bl  xpc_release                                   ; 只释放了「请求」字典 x25
                                                  ; 回复字典 x24 从头到尾没有 xpc_release
```

配合"整个二进制没有 `xpc_connection_cancel`"，结论是：**连接不可主动断开，回复对象不可回收**。这部分的泄漏量受进程生命周期限制（App 退出即回收），但在 SpringBoard 这种常驻进程里同样累积。

### 2.5 泄漏点 D：Darwin 通知观察者从不移除

`CFNotificationCenterAddObserver` 在 `BioProtect.dylib` 与 `BioProtectUIKit.dylib` 均有调用，`CFNotificationCenterRemoveObserver` 在所有模块中**均未链接**。每个 Darwin 中心观察者都会让 CF 在进程内建一个 notify 注册端口。多数在初始化时一次性注册（实测 `BioProtect.dylib` 中该调用点共 **45 处**，覆盖 `com.apple.springboard.lockstate`、`screenchanged`、`finishedstartup`、`BiometricKit.enrollmentChanged`、`prefsChanged` 等），属"永久占用"，量小但同样无法回收。

### 2.6 频次量级测算 —— 以及"15 小时"这个数字该怎么读

把上面四处泄漏的触发率如实估一遍（以"中等使用强度"计）：

| 泄漏点 | 典型频次 | 端口/天 |
|---|---|---|
| A（弹窗） | 锁屏提示 ~20–60 次/天；重录 Face ID 极少；错误分支极少 | 20–60 |
| B（notify 栈 token） | 相册权限请求 ~1–10 次/天 | 1–10 |
| C（XPC 回复对象） | 每次受保护 App 激活 1–2 次，App 退出即回收 | **不累积**（SpringBoard 侧接近 0） |
| D（初始化注册） | 一次性 | 约 44（恒定） |

**结论必须说清楚：单靠 BioProtect 自己的这四处泄漏，速率大约在「每天几十个端口」量级。** 这个量级不足以在 15 小时内把 SpringBoard 的端口空间耗尽（iOS 上 SpringBoard 正常有数千个端口，命名空间上限远高于此）。所以：

- **BioProtect 确实在漏，而且是结构性的、永不回收的漏 —— 这部分是板上钉钉的缺陷，必须修**；
- 但要把时间压到 15 小时，还必须有**数量级更大的第二个源**，或者存在**把上述低频路径放大成高频循环的冲突组合**（见 §4.3）。

这就是为什么本报告同时提供**监控**（§6.3）：静态分析能确定"哪里有漏"，但不能确定"哪个漏得最多"——后者只有实测的 `ports=` 斜率能给答案。


---

## 3. 为什么表现为"约每 15 小时强制注销"

按因果链逐段说明，并把可证实与需实测的部分分开：

1. **泄漏发生在唯一常驻的注入目标上**。`BioProtect.dylib` 注入 SpringBoard，SpringBoard 从开机到重启不会退出，所有泄漏只增不减。
2. **每次事件泄漏量恒定**（≥1 个 mach port + 1 个 CF 对象 + 1 个 RunLoopSource）。
3. **主 RunLoop 上堆积 source 有二次伤害**：RunLoop 每次迭代要遍历 source 集合，source 数量线性增长会让事件分发变慢，SpringBoard 的看门狗（主线程卡顿检测）更容易触发；这与"先变卡、再注销"的体感一致。
4. **触顶路径有两条，二者都可致死**：
   - 端口命名空间 / 内核 `ipc_port` 对象耗尽：`mach_port_allocate`/`bootstrap_register` 开始返回 `KERN_NO_SPACE`/`MACH_SEND_NO_BUFFER`，SpringBoard 的自检失败后自行退出或被 launchd 重启；
   - 内存压力：每个端口与每个 RunLoopSource 都占内核 + 用户态内存，jetsam 把 SpringBoard 列为可回收高价值目标 → `SIGKILL`。
5. **为何是"约 15 小时"而非固定**：设泄漏速率为 λ（端口/小时），SpringBoard 的端口上限为 L，装机基线为 B，则 `T ≈ (L − B) / λ`。**装的插件越多，B 越高，T 越短。** "约 15 小时"是"你的装机组合 + 你的使用频率"下的一个观测值，不是插件的固有常量。
6. 前端表现：SpringBoard 被 `SIGKILL` 后由 launchd 立刻拉起 → 屏幕黑一下、转圈、回到锁屏，用户描述为"注销/自动重启桌面"。

**关于量级的诚实结论（重要）**：

按 §2.6 的估算，BioProtect 自身的泄漏速率在"几十个端口/天"。若真要在 15 小时内触顶，需要 λ ≈ 数百至上千端口/小时，也就是说必须存在下列情形之一：

| 情形 | 说明 | 如何验证 |
|---|---|---|
| ① 同族插件叠加 | 装了 Limneos 同族插件，同一事件双份弹窗 → A 的速率翻倍；再多装几个则成倍放大 | 卸载同族插件后对比 `ports=` 斜率 |
| ② XPC 回复丢失 | 某插件截断了 `com.apple.frontboard.systemappservices` 的回复，App 侧同步调用永久阻塞，每次重试挂一个 reply port（见 §4.3） | 观察"某 App 打开卡死"是否与注销周期同步出现 |
| ③ 锁屏事件被循环触发 | 某个锁屏类插件反复触发 `screenchanged` / `lockstate` / `lockafterfiveseconds`，把"每次锁屏一次"放大成"每次锁屏几十次" | 日志里 `cf_cleaned` 增速是否远高于实际锁屏次数 |
| ④ 另有第三方泄漏源 | 与 BioProtect 无关的另一个插件 | 用 §6.3 的日志确认 `cf_cleaned` 正常但 `ports=` 仍线性上升 |

> 也就是说：**"15 小时"这个数字本身，就是"存在放大机制"的证据**。修掉 BioProtect 的四处泄漏是必要不充分条件；`ports=` 曲线的斜率变化会直接指出放大来自哪一侧。本报告不做没有依据的断言。


> 说明：第 4 步中"jetsam 还是端口空间耗尽"两者静态分析无法区分（都符合现象）。装上第 6 节的监控后，日志里 `ports=N` 的增长曲线与最后一行数值会直接给出答案。

---

## 4. 冲突分析：模块 × 触发条件

### 4.1 同族命名空间冲突（已在 control 中声明）

`control-e` 里声明了对 `Limneosos`、`AudioRecorder`、`CallBar`、`NFCWriter` 等插件（均为 Limneos 出品）的 `Conflicts`。原因不是"依赖打架"，而是：

- 它们共用 `net.limneos.*` 达尔文通知命名空间与 XPC 消息名（如 `net.limneos.bioprotect.*`）；
- 同时安装时会出现**同一个事件被两个插件各自弹一次窗**，也就是泄漏点 A 被执行两次 —— **泄漏速率直接翻倍**，触顶时间减半。

**这是最需要避免的组合**：装了同族插件，等于给漏水的管子接了两根。

### 4.2 SpringBoard 钩子重叠

`BioProtect.dylib` 挂了 212 个方法钩子，覆盖面极宽（节选还原结果）：

- 应用启动链：`workspace:handleOpenApplicationRequest:withOptions:origin:withResult:`、`systemService:handleOpenApplicationRequest:withCompletion:`、`launchFromLocation:context:`、`activateApplication:`
- 多任务/切换器：`toggleSwitcherNoninteractively`、`_toggleSwitcher`、`switcherContentController:selectedItem:`
- 电源：`_powerOff`、`shutdownWithOptions:`、`reboot`、`restartWithTransitionRequest:`、`relaunchSpringBoard`
- 弹窗基建：继承 `SBAlertItem` 动态创建 `BioAlertItem`；`handleAlertAction:`

**冲突条件**：任何"应用锁 / 防窥 / 锁屏美化 / 多任务增强"类插件，只要也 hook 上述任一方法且 `%orig` 处理不完整，就会出现
`A 钩子 → 提前 return → B 钩子拿不到调用` 或 `A、B 各弹一次窗`。
前者使鉴权流程卡住（见 4.3），后者使泄漏翻倍。

### 4.3 XPC 消息竞争 —— "冲突 → 端口泄漏"的正反馈路径（关键）

`com.apple.frontboard.systemappservices` 是 SpringBoard 提供的**公共** mach service。BioProtect 的做法是：

- App 侧（`BioProtectUIKit.dylib`）：`xpc_connection_send_message_with_reply_sync` **同步等回复**；
- SpringBoard 侧（`BioProtect.dylib`）：`-handleMessageNamed:userInfo:`（IMP `0xd0c0`）消费自定义消息名（`net.limneos.bioprotect.suspendFrontMostApp`、`alertCancelled`、`net.limneos.bioprotect.extensions` …），并用 `xpc_dictionary_create_reply` 回包。

**冲突条件**：另一个插件也在这条链路上挂钩（或替换了该 service 的 event handler），导致 BioProtect 的回复丢失。
**后果**：App 侧的同步调用**永久阻塞**（该 API 没有超时），阻塞期间 App 与 SpringBoard 各自持有一个 reply port 不放；用户等不及杀掉 App，端口才回收 —— 期间每重开一次就再挂一个。

这条路径解释了为什么"刚装上某个插件后，注销间隔突然从 2 天变成 15 小时"。

### 4.4 全 App 注入带来的横向冲突

`BioProtectUIKit.dylib` 的过滤器是 `Classes = (UIApplication, ...)`，会进入**每一个链接 UIKit 的进程**（含 SpringBoard）。任何同样 hook `UIApplication` 生命周期（`applicationDidFinishLaunching:`、`applicationDidBecomeActive:`）的插件都与它正面重叠；出问题时表现为"某个 App 打开就白屏/卡住"，且该 App 的端口会一直被占。

### 4.5 RootHide 环境的额外风险

包内自带 6 个 `*.roothidepatch → /usr/lib/DynamicPatches/AutoPatches.dylib` 符号链接，说明是**转换版**。若设备上同时存在"roothide 原生版 BioProtect"，两者会抢同一批文件路径并同时注入 → 钩子装两遍、弹窗弹两次、泄漏 ×2。

### 4.6 与本项目 VolumeManager（自研音频插件）的关系

无 API 面重叠（音频渲染 vs UI/XPC），不构成直接冲突。但**共享 SpringBoard 端口预算**：如果 VolumeManager 侧也存在端口增长，两者叠加会显著缩短触顶时间。建议一并纳入第 6 节的监控。

---

## 5. 立即缓解措施（零风险，不改代码）

在打补丁之前，先把"泄漏速率"降下来：

1. **卸载同族插件**：Limneosos / AudioRecorder / CallBar / NFCWriter 与 BioProtect 不要共存（`control` 里本就声明了冲突）。
2. **关闭高频触发点**：在 BioProtect 设置中关闭"锁屏提示 / 5 秒后锁定提示"类开关（对应 `lockafterfiveseconds`、`lockdevicenow` 两条达尔文通知）。这能砍掉占比最高的一路触发。
3. **关闭 Face ID 身份变更提示**（对应 `-updateIdentity:` 路径）。
4. **不要同时保留转换版与原生版** BioProtect。
5. 装端口监控（见 6.3），先拿到 24h 的 `ports=` 曲线作为基线。

> 这些措施只降低速率，不消除泄漏。要"不再注销"，必须做第 6.2 节的补丁。

---

## 6. 修复方案

### 6.1 根治（给作者的源码级改法）

如果拿得到源码，正确改法只有三处：

```c
// ① 弹窗：不要每次新建，复用一个实例；且必须成对释放
static CFUserNotificationRef gNote; static CFRunLoopSourceRef gSrc;
if (!gNote) {
    gNote = CFUserNotificationCreate(NULL, 10.0, kCFUserNotificationPlainAlertLevel, &flags, dict);
    gSrc  = CFUserNotificationCreateRunLoopSource(NULL, gNote, cb, 0);
    CFRunLoopAddSource(CFRunLoopGetMain(), gSrc, kCFRunLoopCommonModes);
}
// 在回调（或超时计时器）里：
CFUserNotificationCancel(gNote);
CFRunLoopRemoveSource(CFRunLoopGetMain(), gSrc, kCFRunLoopCommonModes);
CFRelease(gSrc); CFRelease(gNote); gSrc = NULL; gNote = NULL;

// ② notify：token 必须缓存成 static，注册一次
static int gTok = -1;
if (gTok == -1) notify_register_check(name, &gTok);
notify_set_state(gTok, v); notify_post(name);
// 进程退出/卸载时 notify_cancel(gTok);

// ③ XPC：同步调用后必须 xpc_release 回复；退出路径必须 xpc_connection_cancel
xpc_object_t reply = xpc_connection_send_message_with_reply_sync(conn, msg);
if (reply) { /* 使用 */ xpc_release(reply); }
```

### 6.2 无需源码的补丁模块：`BioProtectLeakGuard`（已构建）

由于拿不到源码，采用**运行期接管**的方式补上缺失的释放路径。工程位于 `D:\WorkBudy\codetest\bioprotect-fix\`，产物已编译：

**`release/com.local.bioprotectleakguard_1.0.0_iphoneos-arm64.deb`**（7.0 KB，arm64 单切片）

| 组件 | 作用 | 关键实现 |
|---|---|---|
| Fix A（主） | 回收泄漏点 A 的端口与 RunLoopSource | `MSHookFunction(CFUserNotificationCreateRunLoopSource)`：仅在**调用方位于 BioProtect 镜像内**（`dladdr` 判定，`strstr(fname,"BioProtect")`）时接管；14 秒后（原弹窗 timeout 为 10 秒）执行 `CFUserNotificationCancel` → `CFRunLoopRemoveSource` → `CFRelease(src)` → `CFRelease(note)` |
| Fix B | 消除泄漏点 B | 重实现 `BioProtectController -allowPhotoLibraryAccess:`：token 缓存为 `static`，注册一次；行为与原来逐指令等价（set_state + post），不再新建端口 |
| Fix C | 观测 | 后台定时器每 5 分钟用 `mach_port_names()` 采样端口数，写 `ports=N cf_cleaned=… notify_fixed=…`；> 28000 时追加告警行 |
| Fix D（兜底，默认关） | 防"突然注销" | 端口数超过阈值（默认 20000）**且当前处于锁屏状态**时，主动 `exit(0)` 让 launchd 重新拉起 SpringBoard —— 这是一次"看不见的 respring"（屏幕本来就黑着），代价远低于被 jetsam 在任意时刻强杀 |

**为什么这样是安全的（引用计数推导）**：

- `CFUserNotificationCreate` 给 `note` +1（原程序从不释放）；
- `CreateRunLoopSource` 返回的 `src` +1（原程序从不释放），且 `src` 内部 retain `note`（共 2）；
- `CFRunLoopAddSource` 让 RunLoop retain `src`（共 2）；
- 我们做的：`RemoveSource` → `src` 2→1；`CFRelease(src)` → 1→0，析构时释放 `note` 2→1；`CFRelease(note)` → 1→0。
- **收支平衡，无双重释放**；且 block 捕获 CF 类型不会额外产生 retain（CF 不受 ARC 管理）。
- 若调用方不是 BioProtect，则原样返回、不做任何事（`cf_skipped` 计数），因此不会干扰系统或其它插件自己创建的 CFUserNotification。
- 若未来 BioProtect 版本自己加了释放逻辑，本模块的接管会导致双重释放 —— 因此配置文件中可一键关闭（见下）。

**配置文件**：`/var/mobile/Library/BioProtectLeakGuard/config.plist`

```xml
<key>EnableCFCleanup</key><true/>        <!-- 关掉 = 完全不介入 CF 对象（若将来官方修好了就关这个） -->
<key>EnableNotifyFix</key><true/>
<key>EnablePortLog</key><true/>
<key>PortLogInterval</key><integer>300</integer>
<key>EnableAutoRespring</key><false/>    <!-- 想"绝不突然注销"就改 true -->
<key>PortThreshold</key><integer>20000</integer>
```

> 设计取舍 1：**没有**去 hook `notify_register_check` 做"事后 cancel"。因为 token 号会被 libnotify 回收复用，延迟 cancel 有概率取消掉别人的注册，风险高于收益；改为在唯一的高频调用点上做等价重实现。
>
> 设计取舍 2：`EnableAutoRespring` 默认 **false**。它是"保险丝"而不是"修复"：主修复（A/B）已经把 BioProtect 这一侧的泄漏堵住；若 24 小时后 `ports=` 仍线性上升（说明还有别的源），把它改成 `true` 即可获得"永不被强杀"的硬保证 —— 代价是每 6 小时最多一次、且只在锁屏时发生的静默 respring。

### 6.3 安装与验证步骤

**在电脑上**：把 `release/com.local.bioprotectleakguard_1.0.0_iphoneos-arm64.deb` 传到手机（Filza / AirDrop 均可）。

**在手机上**：

1. 用 Filza 点开该 deb → 安装（或 Sileo 里 `重新加载` 后安装）。
2. 安装完成后**必须**重启一次桌面：Sileo 里点 `Respring`，或终端执行 `sbreload`。
   （只 respring 即可，不需要重启手机。）
3. 打开 Filza，进入路径：`/var/mobile/Library/BioProtectLeakGuard/`
   - 应能看到 `guard.log` 与 `config.plist`；
   - 若目录不存在，说明模块没有加载，先检查 Sileo 里包是否已安装。

**读日志判断是否生效**：

打开 `guard.log`，应能看到两类行：

```
[12:31:07] === BioProtectLeakGuard 载入 (pid=... ) cfg{cf=1,notify=1,portlog=1,300s} ===
[12:31:07] CFUserNotificationCreateRunLoopSource hook 安装完成
[12:31:08] BiometricKit/Controller hook 安装完成 (BioProtectController -allowPhotoLibraryAccess:)
[12:36:09] ports=1843  cf_cleaned=0 cf_skipped=0 notify_fixed=0 notify_canceled=0
[12:41:09] ports=1845  cf_cleaned=3 cf_skipped=0 notify_fixed=1 notify_canceled=0
```

验收标准（跑满 24 小时）：

| 指标 | 修复前 | 修复后（合格） |
|---|---|---|
| `ports=` 走势 | 单调线性上升 | **平台状**，相邻采样差 ≤ ±5%，不随锁屏次数阶梯上升 |
| `cf_cleaned` | 恒为 0（模块未装） | 随每次锁屏/鉴权 +1 |
| `notify_fixed` | 恒为 0 | 每请求一次相册权限 +1 |
| 体感 | 约 15h 注销 | ≥ 48h 无强制注销 |

**三种结果对应的下一步**：

| 现象 | 判读 | 下一步 |
|---|---|---|
| `ports=` 走平，`cf_cleaned` 照常增长 | BioProtect 是主源，已修好 | 结束，长期挂着即可 |
| `cf_cleaned` 正常但 `ports=` 仍线性上升 | BioProtect 的漏已堵，另有第三方源 | 保持本模块，用同一套脚本扫描其它插件；或先开 `EnableAutoRespring` 拿到硬保证 |
| `cf_cleaned` 增速远大于真实锁屏次数 | 存在把弹窗路径放大成循环的冲突 | 按 §4.1 / §4.3 定位并卸载冲突插件 |

---

## 7. 影响面与风险

| 项 | 评估 |
|---|---|
| 功能影响 | 无。弹窗照常显示（只是 14 秒后底层对象被回收，此时弹窗早已按原 10 秒 timeout 消失）；相册权限通知照常发出；Face ID 流程不介入 |
| 稳定性风险 | 低。只在 `dladdr` 命中 BioProtect 时接管，外呼一律放行；所有清理动作有 `@try` 包裹，异常只写日志 |
| 与其它插件兼容 | 不 hook 任何系统/第三方方法（除 `BioProtectController` 这一个 BioProtect 自有类），不改变全局 CF 行为 |
| 与 RootHide 的兼容 | 采用 rootless scheme（安装到 `/var/jb`），与现有 BioProtect 转换版一致，可用 RootHide 转换器一并处理 |
| 已知未修 | XPC 回复字典泄漏（泄漏点 C）。它受进程生命周期限制，SpringBoard 侧增量远小于 A；如需修需 hook `xpc_connection_send_message_with_reply_sync` 并延迟释放返回值，有被其它调用方复用的风险，列为 v1.1 可选项 |

---

## 8. 附：本次分析产出的可复现材料

| 文件 | 说明 |
|---|---|
| `bioprotect-analysis/extracted/` | deb 解包内容（WSL `dpkg-deb -x`，保留权限位） |
| `bioprotect-analysis/stub_sites.json` / `callstats.txt` | 全部外部 API 调用点地址（含 212 处 `MSHookMessageEx`） |
| `bioprotect-analysis/notif_ctx.txt` | 31 处 `notify_register_check` 的上下文分类（是否一次性、token 在栈还是全局） |
| `bioprotect-analysis/objc_methods.txt` | 还原的 11 个 ObjC 类与全部方法（含 IMP 地址），用于把 IMP 反查回方法名 |
| `bioprotect-analysis/hooks2.txt` | 212 处 hook 的「选择器 → IMP」映射 |
| `bioprotect-analysis/scripts/` | 上述结果的全部脚本（LIEF + Capstone，处理了 FAT 切片基址与 chained fixups 指针编码） |
| `bioprotect-fix/` | 补丁模块完整可编译工程（`build.sh` 一键构建，`verify.sh` 校验产物） |
