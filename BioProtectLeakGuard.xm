// ============================================================================
//  BioProtectLeakGuard 2.0.4
//  ---------------------------------------------------------------------------
//  针对 BioProtect 4.6-222 (roothide) 逆向结论编写的资源泄漏修复模块。
//
//  逆向证据（bioprotect-analysis/dumps_46/BioProtect_v2.txt）：
//
//    泄漏 A —— mach port（CFUserNotification 应答端口）
//      A1  BioProtect.dylib  sub_95f4  （位于 -BioProtectEmptyViewController loadView）
//      A2  BioProtect.dylib  sub_479d8 （hook 表里的 block，实验性功能提示）
//      两处都是：CFUserNotificationCreate → CFUserNotificationCreateRunLoopSource
//      → CFRunLoopAddSource(主 RunLoop) 之后直接返回。
//      全二进制 CFUserNotificationCancel / CFRunLoopRemoveSource 各 0 次引用。
//      每次调用 = 1 个 CFMachPort + 1 个 RunLoopSource + 2 个 CF 对象永久驻留。
//
//    泄漏 B —— 文件描述符（本次新发现，且是唯一会随事件高频增长的泄漏）
//      B1  BioProtect.dylib  sub_4a59c   : open + read×2 + malloc + strdup，无 close/free
//      B2  BioProtect.dylib  sub_4f2bc   : 同上
//      触发链：sub_4f6c8（文件监听回调，kevent）→ sub_4f2bc → 泄漏
//              0x4f890 每次文件变化事件走一次；另有 sub_4dc8c 调 2 次。
//      每次调用 = 1 个 fd + 1 块内存永久泄漏。fd 上限（RLIMIT_NOFILE）比端口上限
//      小一到两个数量级，这类泄漏比端口泄漏更快触顶，是「跑十几个小时后桌面注销」
//      最合理的解释。
//
//    不成立的怀疑（已逐条核对，见报告）：
//      · notify_register_check 共 31 处，但 token 全部存在全局变量里（一次性注册），
//        不是 4.7 报告里说的「栈上 token」，不构成增长型泄漏。
//      · BioProtectUIKit 只建 1 个 XPC 连接（构造函数内一次），不随事件增长。
//
//  修复策略（不改任何可见行为）：
//    1) CF 通知：接管 BioProtect 创建的 CFUserNotification，超时（默认 15s）后
//       Cancel（释放应答端口）+ 从主 RunLoop 摘除 Source + 释放我们自己持有的引用。
//    2) fd：只记录「调用方确实是 BioProtect 代码」的 open()，在 fd 使用量超过水位
//       （默认 320）且该 fd 已存活超过宽限期（默认 30s）时，用 F_GETPATH 复核
//       路径一致后才 close，避免误关别人复用的 fd。
//    3) 监控：定时把 ports / fd 使用量 / 回收计数写进 guard.log，便于验证。
//    4) 兜底（默认关）：逼近上限且锁屏时做一次受控重启，避免被随机强杀。
//
//  设计红线：
//    · 只在 dladdr 命中 "BioProtect" 的调用方上动手，绝不碰系统或其它插件。
//    · 任何异常只写日志，不抛异常、不 abort。
//    · 只有 BPLG_DEBUG 打开时才输出逐次日志，平时只写汇总，日志量可控。
//
//  2.0.4 修正（关键）：恢复链接 substrate，改回直接调用 MSHookFunction。
//  崩溃日志 usedImages 证明本设备（RootHide + Orion + ElleKit）只加载「导入
//  MSHookFunction/MSHookMessageEx 并链接 substrate」的 tweak——BioProtect 三个
//  dylib、VolManAudioQueue、以及 SpringBoard 里全部 40+ 个插件都如此，
//  唯独 2.0.1–2.0.3 的「零 substrate 依赖」dylib 因从不引用 MSHook* 符号
//  而没有 substrate 依赖，被加载器完全无视（日志全空的真正原因）。
//  2.0.4 直接调用 MSHookFunction，链接器据此生成 substrate 依赖，经转换后的
//  @loader_path/.jbroot 的 rpath 在设备上解析（与 VolMan 已验证形态一致）。
//
//  2.0.5 修正（三个诊断盲区，装上却看不到日志的补救）：
//    ① 影子日志（CFPreferences）从 %ctor 挪到首个定时器 tick（约 +5s）：
//      dyld init 阶段（main 之前）对 cfprefsd 做同步 XPC 有静默失败甚至
//      卡启动的风险——「dylib 已加载、diaglog 却始终不出现」很可能正是
//      这一步在启动早期静默失败；
//    ② 新增 /rootfs 前缀直写落点：roothide 的 libroot 对 /rootfs 放行
//      （真实根文件系统），运行时拼接、不写字面量完整路径 → 日志直接落
//      在真实根的 /var/mobile/Library/... 下，Filza 从根可见，不依赖
//      cfprefsd、也不被 libroot 重定向；
//    ③ dylib 内彻底清除写死的绝对路径（config 路径也改运行时拼接），
//      RootHide 转换器无从改写；影子通道写入后回读自验证（stat 行带
//      shadow=ok/fail/wait）。
//
//  2.0.7 修正（arm64e 第四层根因：CFString isa 未认证）：
//    clang19（L1ghtmann）给 arm64e 编 CFSTR 时 isa 重定位是普通 UNSIGNED，
//    不是 ARM64_RELOC_AUTHENTICATED_POINTER → ld64 产出的 chained fixups 里
//    __cfstring 的 isa 全是「普通 bind（无 PAC）」，而 Xcode 编的原版全是
//    「auth bind（diversity=0x6AE1, addrDiv=1, key=2）」。arm64e 系统进程里
//    objc_msgSend 碰到常量字符串接收者时对未签名 isa 做认证 → SIGBUS（即
//    Spotlight-2026-10-24 崩溃栈：LeakGuard+0x1940 → objc_msgSend）。
//    构建脚本在链接后把 isa 条目补丁成 auth bind 再重签（build.sh）。
//    另新增 ctor 纯 POSIX 面包屑（crumb.log）：再出问题时可判别
//    「dylib 没被加载」vs「加载后死在哪一步」。
//
//  2.0.8 修正（真机验证暴露的新 bug：定时器从未运行）：
//    2.0.7 真机日志证明 dylib 在 SB/Spotlight/设置里全部加载成功、ctor 全跑完，
//    但「影子通道自验证」（首个 tick 必写）与 stat 行一条都没出现 → 5 秒定时器
//    从未触发。原因：dispatch_source_t 是 bplg_start_timers 的局部变量，函数
//    返回即被 ARC 释放，定时器随之销毁 → CF 回收/fd 回收/统计/影子全部没跑过，
//    SpringBoard 照旧在 10.7 小时后 PORT_SPACE 131072 被 jetsam 杀掉。
//    修复：source/queue 存入文件级全局，生命周期与进程相同。
//    同时新增端口归因：hook mach_port_allocate，统计总分配数与 BioProtect 调用方
//    的分配数及 Top 调用点（镜像内偏移），stat 行输出 —— 若端口仍上涨，
//    下一份日志直接点名泄漏函数。
//
//  2.0.9（真机 2.0.8 数据驱动的归因升级）：
//    实测 ports 每分钟 +300（约 5.3/秒），但 paBP=0 且 pa 增速仅为 ports 的 1/3
//    → 泄漏既不是 BioProtect 直接 mach_port_allocate（04/05 报告的 CF 假设排除：
//    cf_called 全程 0），也有 2/3 来自 mach_port_allocate 之外的机制
//    （mach_port_construct / xpc 连接 / 内核注入的 send-once 权）。
//    本版新增三层归因：
//    ① 端口类型分解：mach_port_names 顺带返回的 types 做 send/receive/send-once/
//      dead/port-set 占比（tS/tR/tO/tD/tP）——send-once 涨 = 未应答 RPC 泛滥；
//      receive 涨 = 进程内自建（construct/allocate）；send 涨 = 持有外发连接不释放；
//    ② hook mach_port_construct 与 mach_port_allocate_full（xpc/GCD 通道的创建口），
//      统计总量与 Top 调用点（镜像+偏移）；
//    ③ hook xpc_connection_create / xpc_connection_create_mach_service（dlsym 取址），
//      按「调用方镜像/服务名」做 Top 直方图 —— 谁在反复建 XPC 连接一眼可见。
//    钩子内仍只做计数与查表，不做任何 IO。
//
//  2.0.10（真机 2.0.9 数据驱动的收口）：
//    实测泄漏 = 每秒 ~2.9 个 XPC 连接创建后从未释放（xpc 增速 ≈ tR ≈ tS
//    ≈ +875/5min，2.9/s × 10.7h ≈ 11 万端口 = 131072 触顶），tO≈0 排除未应答 RPC，
//    top construct 全部来自 libxpc 内部。但 top xpc 直方图 10 槽被开机键占满
//    且不淘汰 → 热点调用者（真正每秒 3 次的那个）进不了表。本版：
//    ① 直方图 32 槽 + 淘汰计数最小项，键带调用点偏移（镜像+偏移/服务名）；
//    ② 新增按调用镜像聚合的总量表（24 槽）——不受服务名种类稀释；
//    ③ stat 行加 xpc5=（本周期创建数），rate 一眼可见；
//    ④ 补 hook xpc_connection_create_from_endpoint。
//
//  2.0.13（终版修复；2.0.12 定责 CallAssist.dylib+1a9cfc 以 ~2 次/秒轮询 IOKit 电池
//  接口、每次创建 powerdxpc 连接从不释放，占总泄漏 96%）：对「插件驱动」的
//  com.apple.iokit.powerdxpc 连接做接管-宽限-回收（xpc_retain 登记，超宽限期
//  xpc_connection_cancel + 释放），CallAssist 可继续使用而端口不再泄漏。
//  EnableXPCReclaim=false 可关（config.plist）。
// ============================================================================

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <notify.h>
#import <dlfcn.h>
#import <pthread.h>
#import <substrate.h>
#import <sys/fcntl.h>
#import <sys/stat.h>
#import <sys/sysctl.h>
#import <sys/resource.h>
#import <limits.h>
#import <unistd.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <stdarg.h>
#import <time.h>
#import <dispatch/dispatch.h>

// iOS SDK 的 execinfo.h 不声明 backtrace（符号在 libSystem 里存在），手动声明
extern "C" int backtrace(void **, int);

#define BPLG_VERSION   "2.0.13"
#define BPLG_MAXLOG    (256 * 1024)
#define BPLG_KEEPLOG   (128 * 1024)

// ---------------------------------------------------------------------------
//  落盘路径（2.0.3 起不再写死绝对路径）
//  ---------------------------------------------------------------------------
//  RootHide 的转换器会把包里的绝对路径字面量改写掉（实测它把 postinst 里的
//  /var/jb/var/mobile 改成 /var/mobile、把 /var/mobile/Library 改成
//  /rootfs/var/mobile/Library）。dylib 里的字符串同样会被改，
//  所以这里改成运行时用 NSHomeDirectory()/NSTemporaryDirectory() 拼出来，
//  不受转换器影响；再叠一层 CFPreferences 影子日志（cfprefsd 落盘，完全不经过
//  我们的路径拼接，也不受沙箱与重定向影响）。
// ---------------------------------------------------------------------------
#define BPLG_LOG_NAME   "guard.log"
#define BPLG_PREF_DOMAIN "com.local.bioprotectleakguard"

// ---------------------------------------------------------------------------
//  2.0.7 面包屑：纯 POSIX（getenv/open/write/close），必须先于一切 ObjC/CF。
//  万一再进安全模式，凭 crumb.log 判断 dylib 是否加载、走到了哪一步。
//  路径拆两个字面量拼接，防 RootHide 转换器按完整路径匹配改写。
// ---------------------------------------------------------------------------
static void bplg_crumb(const char *tag) {
    const char *home = getenv("CFFIXED_USER_HOME");
    if (!home || !*home) home = getenv("HOME");
    if (!home || !*home) home = "/tmp";
    char path[512];
    snprintf(path, sizeof(path), "%s/Library/" "BioProtectLeakGuard/crumb.log", home);
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        snprintf(path, sizeof(path), "/tmp/" "BPLG-crumb.log");
        fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd < 0) return;
    }
    char line[192];
    int n = snprintf(line, sizeof(line), "[%s] v%s pid=%d\n", tag, BPLG_VERSION, getpid());
    if (n > 0) write(fd, line, (size_t)n);
    close(fd);
}

static char kBPLGLogs[8][512];      // 运行时填充
static int  gLogCount = 0;
static char gSinkNote[768];         // 启动时记下哪些落点真正写成功了

// /rootfs 前缀：roothide 的 libroot 对该前缀放行（真实根文件系统）。
// 前缀与 home 后缀运行时拼接 → dylib 里不留完整绝对路径字面量，
// RootHide 转换器便无从改写（2.0.5）。
static NSString *bplg_rootfs_home(void) {
    NSString *home = NSHomeDirectory();
    if (home.length <= 1) return nil;
    return [@"/rootfs" stringByAppendingPathComponent:[home substringFromIndex:1]];
}

static void bplg_build_sinks(void) {
    gLogCount = 0;
    NSString *home = NSHomeDirectory();
    NSString *tmp  = NSTemporaryDirectory();
    NSString *rf   = bplg_rootfs_home();

    NSString *cands[8];
    int n = 0;
    if (rf) {
        // 真实根直写：不经 libroot 重定向、不经 cfprefsd，Filza 从根目录直接可见
        cands[n++] = [rf stringByAppendingPathComponent:@"Library/BioProtectLeakGuard/guard.log"];
        cands[n++] = [rf stringByAppendingPathComponent:@"Library/Preferences/BioProtectLeakGuard.log"];
    }
    if (home) {
        cands[n++] = [home stringByAppendingPathComponent:@"/Library/BioProtectLeakGuard/guard.log"];
        cands[n++] = [home stringByAppendingPathComponent:@"/Library/Preferences/BioProtectLeakGuard.log"];
        cands[n++] = [home stringByAppendingPathComponent:@"/Documents/BioProtectLeakGuard.log"];
    }
    if (tmp) cands[n++] = [tmp stringByAppendingPathComponent:@"BioProtectLeakGuard.log"];
    cands[n++] = [@"/tmp" stringByAppendingPathComponent:@"bioprotectleakguard.log"];

    for (int i = 0; i < n && i < 8; i++) {
        const char *p = cands[i].fileSystemRepresentation;
        if (!p) continue;
        strncpy(kBPLGLogs[gLogCount], p, sizeof(kBPLGLogs[0]) - 1);
        kBPLGLogs[gLogCount][sizeof(kBPLGLogs[0]) - 1] = 0;
        gLogCount++;
    }
}

static char kBPLGCfgs[4][512];      // 运行时填充（真实根 + home 派生，无写死路径）
static int  gCfgCount = 0;

static void bplg_build_cfg_paths(void) {
    gCfgCount = 0;
    NSString *home = NSHomeDirectory();
    NSString *rf   = bplg_rootfs_home();
    NSString *cands[4];
    int n = 0;
    if (rf)   cands[n++] = [rf   stringByAppendingPathComponent:@"Library/BioProtectLeakGuard/config.plist"];
    if (home) cands[n++] = [home stringByAppendingPathComponent:@"/Library/BioProtectLeakGuard/config.plist"];
    if (rf)   cands[n++] = [rf   stringByAppendingPathComponent:@"Library/Preferences/BioProtectLeakGuard.plist"];
    if (home) cands[n++] = [home stringByAppendingPathComponent:@"/Library/Preferences/BioProtectLeakGuard.plist"];
    for (int i = 0; i < n && i < 4; i++) {
        const char *p = cands[i].fileSystemRepresentation;
        if (!p) continue;
        strncpy(kBPLGCfgs[gCfgCount], p, sizeof(kBPLGCfgs[0]) - 1);
        kBPLGCfgs[gCfgCount][sizeof(kBPLGCfgs[0]) - 1] = 0;
        gCfgCount++;
    }
}


// ---------------------------------------------------------------------------
//  运行参数（可被 config.plist 覆盖）
// ---------------------------------------------------------------------------
static int      gCfgCF          = 1;    // 接管 CFUserNotification
static int      gCfgFD          = 1;    // fd 回收
static int      gCfgLog         = 1;    // 周期日志
static int      gCfgRespring    = 0;    // 兜底受控重启
static long     gCfgInterval    = 300;  // 日志间隔（秒）
static long     gCfgCFGrace     = 15;   // CF 通知宽限（秒）
static long     gCfgFDGrace     = 30;   // fd 宽限（秒）
static long     gCfgFDHighWater = 320;  // fd 水位（达到后开始回收）
static long     gCfgPortLimit   = 20000;
static int      gCfgDebug       = 0;

static pthread_mutex_t gLock = PTHREAD_MUTEX_INITIALIZER;

static volatile unsigned long gCFCreateCalls = 0;
static volatile unsigned long gCFAdopted     = 0;
static volatile unsigned long gCFReclaimed   = 0;
static volatile unsigned long gFDOpened      = 0;
static volatile unsigned long gFDClosed      = 0;
static volatile unsigned long gFDSkipped     = 0;

// ===========================================================================
//  日志
// ===========================================================================
// 逐级建目录（父目录可能都不存在）
static void bplg_mkdir_p(const char *path) {
    char tmp[512];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(tmp)) return;
    memcpy(tmp, path, len + 1);
    for (char *q = tmp + 1; *q; q++) {
        if (*q == '/') {
            *q = 0;
            mkdir(tmp, 0755);
            *q = '/';
        }
    }
    mkdir(tmp, 0755);
}

static void bplg_dirname_of(const char *path) {
    char buf[512];
    strncpy(buf, path, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    char *slash = strrchr(buf, '/');
    if (!slash || slash == buf) return;
    *slash = 0;
    bplg_mkdir_p(buf);
}

static void bplg_ensure_dirs(void) {
    for (int i = 0; i < gLogCount; i++) bplg_dirname_of(kBPLGLogs[i]);
    for (int i = 0; i < gCfgCount; i++) bplg_dirname_of(kBPLGCfgs[i]);
}

// ---------------------------------------------------------------------------
//  CFPreferences 影子日志
//  完全不走文件路径：由 cfprefsd 落到 /var/mobile/Library/Preferences/ 下，
//  用 Filza 打开 com.local.bioprotectleakguard.plist 就能看到最近的日志。
//  转换器改不到它，沙箱也拦不住。
// ---------------------------------------------------------------------------
static char   gShadowBuf[6144];
static size_t gShadowUsed = 0;
static volatile int gShadowReady = 0;   // 0 = %ctor/dyld init 阶段（不碰 cfprefsd）
static volatile int gShadowOk    = 0;   // 首次写入后回读自验证的结果

static void bplg_prefs_shadow(const char *line) {
    if (!gShadowReady) return;   // 2.0.5：init 阶段不做同步 XPC，等进程跑起来再写
    size_t len = strlen(line);
    if (len == 0 || len > sizeof(gShadowBuf)) return;

    if (gShadowUsed + len > sizeof(gShadowBuf) - 1) {
        // 丢掉前一半，保留后半
        size_t half = gShadowUsed / 2;
        memmove(gShadowBuf, gShadowBuf + half, gShadowUsed - half);
        gShadowUsed -= half;
        gShadowBuf[gShadowUsed] = 0;
    }
    memcpy(gShadowBuf + gShadowUsed, line, len);
    gShadowUsed += len;
    gShadowBuf[gShadowUsed] = 0;

    CFStringRef v = CFStringCreateWithCString(NULL, gShadowBuf, kCFStringEncodingUTF8);
    if (!v) return;
    CFPreferencesSetAppValue(CFSTR("diaglog"), v, CFSTR(BPLG_PREF_DOMAIN));
    CFPreferencesAppSynchronize(CFSTR(BPLG_PREF_DOMAIN));
    CFRelease(v);
}

// 首个定时器 tick（进程已运行 ~5 秒、main 已起）时启用影子通道并自验证。
// 2.0.5 修正：此前 %ctor（dyld init、main 之前）就同步调 CFPreferences →
// 与 cfprefsd 的 XPC 在启动早期有静默失败甚至卡启动的风险，这可能正是
// 「dylib 已加载、diaglog 却始终不出现」的原因。
static void bplg_log(const char *fmt, ...);   // 前置声明（定义在 bplg_vlog 之后）

static void bplg_shadow_boot(void) {
    char boot[512];
    int n = snprintf(boot, sizeof(boot),
                     "=== BioProtectLeakGuard %s pid=%d 进程=%s 影子通道启用 ===\n",
                     BPLG_VERSION, getpid(),
                     NSProcessInfo.processInfo.processName.UTF8String ?: "?");
    if (n <= 0) return;
    gShadowReady = 1;
    bplg_prefs_shadow(boot);

    CFTypeRef v = CFPreferencesCopyAppValue(CFSTR("diaglog"), CFSTR(BPLG_PREF_DOMAIN));
    gShadowOk = (v != NULL);
    if (v) CFRelease(v);
    bplg_log("影子通道自验证: %s",
             gShadowOk ? "ok（cfprefsd 已收到并可回读）" : "fail（回读为空，看文件日志）");
}

static void bplg_vlog(const char *fmt, va_list ap) {
    char body[1024];
    vsnprintf(body, sizeof(body), fmt, ap);

    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    char line[1200];
    int n = snprintf(line, sizeof(line), "[%02d:%02d:%02d] %s\n",
                     tmv.tm_hour, tmv.tm_min, tmv.tm_sec, body);
    if (n <= 0) return;

    for (int i = 0; i < gLogCount; i++) {
        FILE *f = fopen(kBPLGLogs[i], "a");
        if (!f) continue;
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        if (sz > BPLG_MAXLOG) {
            // 保留尾部，不整份清空（历史教训：清空会让人误判"日志坏了"）
            char *keep = (char *)malloc(BPLG_KEEPLOG);
            if (keep) {
                fseek(f, sz - BPLG_KEEPLOG, SEEK_SET);
                size_t got = fread(keep, 1, BPLG_KEEPLOG, f);
                fclose(f);
                f = fopen(kBPLGLogs[i], "w");
                if (f) {
                    const char *mark = "[日志超过 256KB，已丢弃较早内容，保留最近 128KB]\n";
                    fwrite(mark, 1, strlen(mark), f);
                    fwrite(keep, 1, got, f);
                }
                free(keep);
                if (!f) continue;
            }
        }
        fwrite(line, 1, (size_t)n, f);
        fclose(f);
    }

    bplg_prefs_shadow(line);
}

static void bplg_log(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    bplg_vlog(fmt, ap);
    va_end(ap);
}

#define BPLG_DBG(...) do { if (gCfgDebug) bplg_log(__VA_ARGS__); } while (0)
#define BPLG_SWEEPLOG(...) bplg_log(__VA_ARGS__)

// ===========================================================================
//  钩子引擎：substrate 直连（2.0.4 关键修正）
//  ---------------------------------------------------------------------------
//  2.0.1–2.0.3 的「运行时 dlsym、零 substrate 依赖」路线是错误方向：
//  崩溃日志 usedImages 显示，本设备（RootHide + Orion + ElleKit）上所有能注入
//  的 tweak（BioProtect 三个 dylib、VolManAudioQueue 等 40+ 个）都导入
//  MSHookFunction/MSHookMessageEx 并链接 substrate（转换后为
//  @loader_path/.jbroot/usr/lib/libsubstrate.dylib 或
//  @rpath/CydiaSubstrate.framework/CydiaSubstrate），唯独我们的 dylib 因为
//  从不引用 MSHook* 符号而没有 substrate 依赖 → 加载器根本不加载它。
//  2.0.4 恢复直接调用 MSHookFunction：链接器据此生成 substrate 依赖，
//  经转换后的 @loader_path/.jbroot rpath 在设备上解析（VolMan 同款形态
//  已被 usedImages 验证可加载）。
// ===========================================================================

// ===========================================================================
//  调用方判定：只有 BioProtect 自己的代码才接管
//  用按返回地址直接映射的小表缓存 dladdr 结果，避免 hot path 上反复解析符号
// ===========================================================================
#define BP_CACHE_SLOTS 512
static struct { void *ra; int isBP; } gCallerCache[BP_CACHE_SLOTS];

static int bplg_caller_is_bioprotect(void *ra) {
    if (!ra) return 0;
    unsigned slot = (unsigned)(((uintptr_t)ra >> 2) & (BP_CACHE_SLOTS - 1));
    if (gCallerCache[slot].ra == ra) return gCallerCache[slot].isBP;

    Dl_info info;
    int isbp = 0;
    if (dladdr(ra, &info) && info.dli_fname) {
        const char *base = strrchr(info.dli_fname, '/');
        base = base ? base + 1 : info.dli_fname;
        // 本模块自己叫 BioProtectLeakGuard.dylib，也以 BioProtect 开头，必须排除，
        // 否则会把自己的 fd 当成泄漏源
        if (strstr(base, "LeakGuard") == NULL &&
            strncmp(base, "BioProtect", 10) == 0) isbp = 1;
    }
    gCallerCache[slot].ra = ra;
    gCallerCache[slot].isBP = isbp;
    return isbp;
}

// ===========================================================================
//  泄漏 A：CFUserNotification 应答端口 + RunLoopSource
// ===========================================================================
#define BPLG_CF_MAX 256

typedef struct {
    CFUserNotificationRef note;
    CFRunLoopSourceRef    src;
    double                born;
    int                   used;
} bplg_cf_rec;

static bplg_cf_rec gCFRecs[BPLG_CF_MAX];

typedef CFUserNotificationRef (*bplg_create_t)(CFAllocatorRef, CFTimeInterval,
                                               CFOptionFlags, SInt32 *, CFDictionaryRef);
typedef CFRunLoopSourceRef (*bplg_rls_t)(CFAllocatorRef, CFUserNotificationRef,
                                        CFUserNotificationCallBack, CFIndex);

static bplg_create_t gOrigCreate = NULL;
static bplg_rls_t    gOrigRLS    = NULL;

static double bplg_now(void) {
    return (double)CFAbsoluteTimeGetCurrent();
}

static bplg_cf_rec *bplg_cf_slot_for(CFUserNotificationRef note, int create, int *is_new) {
    bplg_cf_rec *free_slot = NULL;
    if (is_new) *is_new = 0;
    for (int i = 0; i < BPLG_CF_MAX; i++) {
        if (gCFRecs[i].used && gCFRecs[i].note == note) return &gCFRecs[i];
        if (!gCFRecs[i].used && !free_slot) free_slot = &gCFRecs[i];
    }
    if (create && free_slot) {
        free_slot->used = 1;
        free_slot->note = note;
        free_slot->src = NULL;
        free_slot->born = bplg_now();
        if (is_new) *is_new = 1;
    }
    return create ? free_slot : NULL;
}

static CFUserNotificationRef bplg_hook_create(CFAllocatorRef alloc, CFTimeInterval timeout,
                                             CFOptionFlags flags, SInt32 *err,
                                             CFDictionaryRef dict) {
    CFUserNotificationRef note = gOrigCreate ? gOrigCreate(alloc, timeout, flags, err, dict) : NULL;
    if (!note) return note;
    __sync_fetch_and_add(&gCFCreateCalls, 1);

    if (gCfgCF && bplg_caller_is_bioprotect(__builtin_return_address(0))) {
        int fresh = 0;
        pthread_mutex_lock(&gLock);
        bplg_cf_rec *r = bplg_cf_slot_for(note, 1, &fresh);
        if (r && fresh) {
            CFRetain(note);            // 我们自己的引用，回收时只释放这一份
            __sync_fetch_and_add(&gCFAdopted, 1);
        }
        pthread_mutex_unlock(&gLock);
    }
    return note;
}

static CFRunLoopSourceRef bplg_hook_rls(CFAllocatorRef alloc, CFUserNotificationRef note,
                                        CFUserNotificationCallBack cb, CFIndex order) {
    CFRunLoopSourceRef src = gOrigRLS ? gOrigRLS(alloc, note, cb, order) : NULL;
    if (!src || !note) return src;

    if (gCfgCF) {
        int adopted = 0;
        pthread_mutex_lock(&gLock);
        bplg_cf_rec *r = bplg_cf_slot_for(note, 0, NULL);
        if (r && !r->src) {
            CFRetain(src);             // 我们自己的引用
            r->src = src;
            r->born = bplg_now();
            adopted = 1;
        }
        pthread_mutex_unlock(&gLock);
        if (adopted) BPLG_DBG("CF 已接管: note=%p src=%p", note, src);
    }
    return src;
}

// 每 5 秒扫一次：超过宽限期的通知立刻回收
static void bplg_cf_sweep(void) {
    if (!gCfgCF) return;
    double now = bplg_now();
    CFRunLoopRef rl = CFRunLoopGetMain();

    for (int i = 0; i < BPLG_CF_MAX; i++) {
        if (!gCFRecs[i].used) continue;
        if (now - gCFRecs[i].born < (double)gCfgCFGrace) continue;

        CFUserNotificationRef note = gCFRecs[i].note;
        CFRunLoopSourceRef    src  = gCFRecs[i].src;

        pthread_mutex_lock(&gLock);
        gCFRecs[i].used = 0;
        gCFRecs[i].note = NULL;
        gCFRecs[i].src = NULL;
        pthread_mutex_unlock(&gLock);

        if (note) {
            CFUserNotificationCancel(note);                 // 关键：释放应答 mach port
            if (src) {
                CFRunLoopRemoveSource(rl, src, kCFRunLoopCommonModes);
                CFRunLoopRemoveSource(rl, src, kCFRunLoopDefaultMode);
                CFRelease(src);                             // 释放我们的引用
            }
            CFRelease(note);                                // 释放我们的引用
            __sync_fetch_and_add(&gCFReclaimed, 1);
        }
    }
}

// ===========================================================================
//  泄漏 B：open() 未 close 的文件描述符
// ===========================================================================
#define BPLG_FD_MAX 2048

typedef struct {
    int    fd;
    double born;
    char   path[160];
    int    used;
} bplg_fd_rec;

static bplg_fd_rec gFDRecs[BPLG_FD_MAX];

typedef int (*bplg_open_t)(const char *, int, ...);
static bplg_open_t gOrigOpen = NULL;

static void bplg_fd_record(int fd, const char *path) {
    if (fd < 0 || !path) return;
    if (path[0] != '/') return;   // 相对路径无法用 F_GETPATH 复核，不记录

    pthread_mutex_lock(&gLock);
    bplg_fd_rec *slot = NULL;
    for (int i = 0; i < BPLG_FD_MAX; i++) {
        if (gFDRecs[i].used && gFDRecs[i].fd == fd) { slot = &gFDRecs[i]; break; }
        if (!gFDRecs[i].used && !slot) slot = &gFDRecs[i];
    }
    if (slot) {
        slot->used = 1;
        slot->fd = fd;
        slot->born = bplg_now();
        strncpy(slot->path, path, sizeof(slot->path) - 1);
        slot->path[sizeof(slot->path) - 1] = 0;
        __sync_fetch_and_add(&gFDOpened, 1);
    }
    pthread_mutex_unlock(&gLock);
}

static int bplg_hook_open(const char *path, int oflag, ...) {
    int ret;
    if (oflag & O_CREAT) {
        va_list ap;
        va_start(ap, oflag);
        mode_t mode = (mode_t)va_arg(ap, int);
        va_end(ap);
        ret = gOrigOpen(path, oflag, mode);
    } else {
        ret = gOrigOpen(path, oflag);
    }

    if (ret >= 0 && gCfgFD && path) {
        void *ra = __builtin_return_address(0);
        if (bplg_caller_is_bioprotect(ra)) bplg_fd_record(ret, path);
    }
    return ret;
}

static int bplg_fd_used(int limit) {
    int n = 0;
    for (int i = 0; i < limit; i++) {
        if (fcntl(i, F_GETFD) != -1) n++;
    }
    return n;
}

// fd 水位回收：只关「BioProtect 直呼 open 且至今没关、路径复核一致」的 fd
static void bplg_fd_sweep(void) {
    if (!gCfgFD) return;

    int limit = getdtablesize();
    if (limit <= 0) limit = 1024;
    if (limit > 8192) limit = 8192;

    int used = bplg_fd_used(limit);

    // 触发水位：配置值，或「上限 - 64」（RLIMIT 很小时靠这条兜底，避免上限先被撞到）
    long trigger = gCfgFDHighWater;
    if (limit - 64 < trigger) trigger = limit - 64;
    if (trigger < 32) trigger = 32;
    if (used < trigger) return;               // 没到水位不动手，平时零副作用

    double now = bplg_now();
    int closed = 0;
    for (int i = 0; i < BPLG_FD_MAX; i++) {
        if (!gFDRecs[i].used) continue;
        if (now - gFDRecs[i].born < (double)gCfgFDGrace) continue;

        int fd = gFDRecs[i].fd;
        char cur[PATH_MAX] = {0};
        int verified = 0;
        if (fcntl(fd, F_GETPATH, cur) == 0) {
            // 只有路径仍与记录一致才敢关：防止 fd 号被系统复用后误关别人的文件
            verified = (strcmp(cur, gFDRecs[i].path) == 0);
        }

        pthread_mutex_lock(&gLock);
        gFDRecs[i].used = 0;
        pthread_mutex_unlock(&gLock);

        if (verified) {
            close(fd);
            closed++;
            __sync_fetch_and_add(&gFDClosed, 1);
        } else {
            __sync_fetch_and_add(&gFDSkipped, 1);
        }
    }
    if (closed > 0) {
        BPLG_SWEEPLOG("fd 回收: 本次关闭 %d 个泄漏 fd（回收前使用 %d/%d）", closed, used, limit);
    }
}

// ===========================================================================
//  观测（2.0.8）：mach_port_allocate 端口归因
//  统计全进程端口分配总数 + BioProtect 调用方的分配数与 Top 调用点偏移。
//  stat 行输出：pa=总数 paBP=BioProtect数 bp_sites=镜像:偏移:次数 …
//  若端口曲线仍上涨，据此直接定位到 BioProtect.dylib 里的具体调用点。
//  注意：本钩子路径只做计数与查表（dladdr 结果有 ra 缓存），绝不做日志/IO。
// ===========================================================================
#define BPLG_PA_SITES 8
static unsigned long gPATotal = 0;      // 进程内 mach_port_allocate 成功总数
static unsigned long gPABP   = 0;       // 其中调用方在 BioProtect 镜像内的次数
static struct { void *ra; unsigned long n; } gMPASites[BPLG_PA_SITES];
static pthread_mutex_t gMPALock = PTHREAD_MUTEX_INITIALIZER;

typedef kern_return_t (*bplg_mpa_t)(mach_port_name_t, mach_port_right_t, mach_port_name_t *);
static bplg_mpa_t gOrigMPA = NULL;

static kern_return_t bplg_hook_mpa(mach_port_name_t task, mach_port_right_t right,
                                   mach_port_name_t *name) {
    kern_return_t kr = gOrigMPA ? gOrigMPA(task, right, name) : KERN_FAILURE;
    if (kr != KERN_SUCCESS) return kr;
    __sync_fetch_and_add(&gPATotal, 1);

    void *ra = __builtin_return_address(0);
    if (!bplg_caller_is_bioprotect(ra)) return kr;
    __sync_fetch_and_add(&gPABP, 1);

    pthread_mutex_lock(&gMPALock);
    int k, hit = 0;
    for (k = 0; k < BPLG_PA_SITES; k++) {
        if (gMPASites[k].ra == ra) { gMPASites[k].n++; hit = 1; break; }
        if (gMPASites[k].ra == NULL) { gMPASites[k].ra = ra; gMPASites[k].n = 1; hit = 1; break; }
    }
    (void)hit;   // 表满（>8 个调用点）时只计总数，不再记新点，足够定位
    pthread_mutex_unlock(&gMPALock);
    return kr;
}

// stat 行用：把 Top 调用点渲染成 "偏移:次数" 列表（镜像名固定为 BP*）
static void bplg_pa_sites_string(char *out, size_t cap) {
    size_t off = 0;
    out[0] = 0;
    pthread_mutex_lock(&gMPALock);
    for (int k = 0; k < BPLG_PA_SITES && gMPASites[k].ra && off + 32 < cap; k++) {
        Dl_info info;
        unsigned long rel = 0;
        const char *img = "?";
        if (dladdr(gMPASites[k].ra, &info) && info.dli_fbase) {
            const char *b = strrchr(info.dli_fname ? info.dli_fname : "", '/');
            b = b ? b + 1 : (info.dli_fname ? info.dli_fname : "?");
            img = b;
            rel = (unsigned long)((char *)gMPASites[k].ra - (char *)info.dli_fbase);
        }
        off += (size_t)snprintf(out + off, cap - off, "%s+%lx:%lu ", img, rel, gMPASites[k].n);
    }
    pthread_mutex_unlock(&gMPALock);
}

// ===========================================================================
//  观测（2.0.9）：其余端口创建口归因
//  mach_port_construct / mach_port_allocate_full（xpc、GCD 通道走这里）
//  与 xpc_connection_create / _create_mach_service（服务名直接可见）。
//  xpc 两个函数用 dlsym 取址（不给 dylib 增加 libxpc 依赖，保持原生 roothide 形态）。
// ===========================================================================
static unsigned long gPCTotal  = 0;   // mach_port_construct 成功总数
static unsigned long gPAFTotal = 0;   // mach_port_allocate_full 成功总数
static unsigned long gXPCTotal = 0;   // xpc_connection_create* 总数

#define BPLG_CS_SLOTS 8
static struct { void *ra; unsigned long n; } gCSTop[BPLG_CS_SLOTS];
static pthread_mutex_t gCSLock = PTHREAD_MUTEX_INITIALIZER;

static void bplg_cs_note(void *ra) {
    pthread_mutex_lock(&gCSLock);
    for (int k = 0; k < BPLG_CS_SLOTS; k++) {
        if (gCSTop[k].ra == ra) { gCSTop[k].n++; break; }
        if (gCSTop[k].ra == NULL) { gCSTop[k].ra = ra; gCSTop[k].n = 1; break; }
    }
    pthread_mutex_unlock(&gCSLock);
}

// 渲染 construct/allocate_full 的 Top 调用点："镜像+偏移:次数 …"
static void bplg_cs_sites_string(char *out, size_t cap) {
    size_t off = 0;
    out[0] = 0;
    pthread_mutex_lock(&gCSLock);
    for (int k = 0; k < BPLG_CS_SLOTS && gCSTop[k].ra && off + 40 < cap; k++) {
        Dl_info info;
        unsigned long rel = 0;
        const char *img = "?";
        if (dladdr(gCSTop[k].ra, &info) && info.dli_fbase) {
            const char *b = strrchr(info.dli_fname ? info.dli_fname : "", '/');
            img = b ? b + 1 : (info.dli_fname ? info.dli_fname : "?");
            rel = (unsigned long)((char *)gCSTop[k].ra - (char *)info.dli_fbase);
        }
        off += (size_t)snprintf(out + off, cap - off, "%s+%lx:%lu ", img, rel, gCSTop[k].n);
    }
    pthread_mutex_unlock(&gCSLock);
}

// 参数类型刻意用 void*/uint64_t 透传（SDK 头里 mach_port_options_t / xpc 对象不必引入）
typedef kern_return_t (*bplg_mpc_t)(mach_port_name_t, const void *, uint64_t, mach_port_name_t *);
static bplg_mpc_t gOrigMPC = NULL;
typedef kern_return_t (*bplg_mpaf_t)(mach_port_name_t, mach_port_right_t, mach_port_name_t,
                                     const void *, mach_port_name_t *);
static bplg_mpaf_t gOrigMPAF = NULL;

static kern_return_t bplg_hook_mpc(mach_port_name_t task, const void *options,
                                   uint64_t context, mach_port_name_t *name) {
    kern_return_t kr = gOrigMPC ? gOrigMPC(task, options, context, name) : KERN_FAILURE;
    if (kr != KERN_SUCCESS) return kr;
    __sync_fetch_and_add(&gPCTotal, 1);
    bplg_cs_note(__builtin_return_address(0));
    return kr;
}

static kern_return_t bplg_hook_mpaf(mach_port_name_t task, mach_port_right_t right,
                                    mach_port_name_t proto, const void *info,
                                    mach_port_name_t *name) {
    kern_return_t kr = gOrigMPAF ? gOrigMPAF(task, right, proto, info, name) : KERN_FAILURE;
    if (kr != KERN_SUCCESS) return kr;
    __sync_fetch_and_add(&gPAFTotal, 1);
    bplg_cs_note(__builtin_return_address(0));
    return kr;
}

// xpc_connection_create / _mach_service / _from_endpoint：
//   ① 明细表：键 = 调用镜像+偏移/服务名，32 槽，满则淘汰计数最小项（2.0.9 的
//     10 槽不淘汰版被开机键占满，真正的热点进不了表——已修）；
//   ② 聚合表：按调用镜像累计（24 槽），不受服务名种类稀释。
#define BPLG_XPC_SLOTS 32
static struct { char key[104]; unsigned long n; } gXPCTop[BPLG_XPC_SLOTS];
#define BPLG_XPC_IMGS 24
static struct { char img[40]; unsigned long n; } gXPCImg[BPLG_XPC_IMGS];
static pthread_mutex_t gXPCLock = PTHREAD_MUTEX_INITIALIZER;

typedef void *(*bplg_xpc_create_t)(const char *, void *);
typedef void *(*bplg_xpc_create_ms_t)(const char *, void *, unsigned long);
typedef void *(*bplg_xpc_create_ep_t)(void *, void *);
static bplg_xpc_create_t    gOrigXPC    = NULL;
static bplg_xpc_create_ms_t gOrigXPCMS  = NULL;
static bplg_xpc_create_ep_t gOrigXPCEP  = NULL;

// 2.0.11 驱动者归因：top xpc 的榜首调用方是系统框架（IOKit/SystemConfiguration 等）
// 时，真正驱动轮询的是更上层——在钩子里回溯调用栈，找第一个「非系统帧」，
// 那一帧所在的镜像（TweakInject 下的插件）就是驱动者。iOS 的 arm64 默认保留
// 帧指针，backtrace() 可用；找不到非系统帧则记 SpringBoard(self)。
#define BPLG_DRV_SLOTS 12
static struct { char key[104]; unsigned long n; } gDrvTop[BPLG_DRV_SLOTS];
static pthread_mutex_t gDrvLock = PTHREAD_MUTEX_INITIALIZER;

static int bplg_is_system_path(const char *p) {
    if (!p) return 1;
    // 必须按前缀判断：roothide 插件路径 ".jbroot-*/usr/lib/TweakInject/x.dylib"
    // 里含有 "/usr/lib/" 子串，用 strstr 会把插件帧误判成系统帧
    // （2.0.11 的 SpringBoard(self) 误归因即由此而来）
    return (strncmp(p, "/System/", 8) == 0 ||
            strncmp(p, "/usr/lib/", 9) == 0 ||
            strncmp(p, "/Developer/", 11) == 0);
}

static void bplg_drv_note(const char *key) {
    pthread_mutex_lock(&gDrvLock);
    int slot = -1, minSlot = 0;
    for (int k = 0; k < BPLG_DRV_SLOTS; k++) {
        if (gDrvTop[k].n && strcmp(gDrvTop[k].key, key) == 0) { slot = k; break; }
        if (gDrvTop[k].n == 0 && slot < 0) slot = k;
        if (gDrvTop[k].n < gDrvTop[minSlot].n) minSlot = k;
    }
    if (slot < 0) slot = minSlot;
    strncpy(gDrvTop[slot].key, key, sizeof(gDrvTop[slot].key) - 1);
    gDrvTop[slot].key[sizeof(gDrvTop[slot].key) - 1] = 0;
    gDrvTop[slot].n++;
    pthread_mutex_unlock(&gDrvLock);
}

// 只在「xpc 的直接调用方是系统框架」时调用（插件直连的创建 top xpc 已可见）。
// 返回 1 = 找到插件驱动者（imgOut 填其镜像名）；0 = 全系统帧（已记 SBself/all-system）。
static int bplg_xpc_driver_walk(void *ra, char *imgOut, size_t imgCap) {
    imgOut[0] = 0;
    void *frames[12];
    int n = backtrace(frames, 12);
    if (n <= 1) { bplg_drv_note("(no-stack)"); return 0; }
    for (int i = 1; i < n; i++) {
        Dl_info fi;
        if (!dladdr(frames[i], &fi) || !fi.dli_fname) continue;
        if (bplg_is_system_path(fi.dli_fname)) continue;
        if (strstr(fi.dli_fname, "LeakGuard") || strstr(fi.dli_fname, "ubstrate") ||
            strstr(fi.dli_fname, "lleKit") || strstr(fi.dli_fname, "llekit") ||
            strstr(fi.dli_fname, "injector")) continue;   // 跳过我们自己与注入器
        const char *b = strrchr(fi.dli_fname, '/');
        b = b ? b + 1 : fi.dli_fname;
        unsigned long rel = fi.dli_fbase ? (unsigned long)((char *)frames[i] - (char *)fi.dli_fbase) : 0;
        char key[104];
        snprintf(key, sizeof(key), "%s+%lx", b, rel);
        bplg_drv_note(key);
        snprintf(imgOut, imgCap, "%s", b);
        return 1;
    }
    // 全栈都是系统帧：若其中有 SpringBoard 二进制的帧，记下偏移便于比对
    for (int i = 1; i < n; i++) {
        Dl_info fi;
        if (!dladdr(frames[i], &fi) || !fi.dli_fname) continue;
        if (strstr(fi.dli_fname, "SpringBoard.app") == NULL || !fi.dli_fbase) continue;
        char key[104];
        snprintf(key, sizeof(key), "SBself+%lx",
                 (unsigned long)((char *)frames[i] - (char *)fi.dli_fbase));
        bplg_drv_note(key);
        return 0;
    }
    bplg_drv_note("all-system(nosb)");
    return 0;
}

static int      gCfgXPC         = 1;    // 2.0.13：回收插件驱动的 powerdxpc 泄漏连接
static long     gCfgXPCGrace    = 10;   // 宽限（秒）

// ===========================================================================
//  泄漏 C（2.0.13 终版修复）：插件驱动的 powerdxpc 连接泄漏
//  定责（2.0.12 真机）：CallAssist.dylib+1a9cfc 以 ~2 次/秒轮询 IOKit 电池接口，
//  每次创建一条 com.apple.iokit.powerdxpc 连接且从不释放（增速与总泄漏 96% 吻合）。
//  修复：与 CF 通知同款「接管-宽限-回收」——插件驱动创建的 powerdxpc 连接，
//  钩子里 xpc_retain 一份并登记；定时器把超过宽限期仍未消亡的连接
//  xpc_connection_cancel + 释放（轮询型调用点 10 秒后早已弃用，回收安全）。
//  仅限：①服务名=com.apple.iokit.powerdxpc ②栈回溯找到插件驱动者。
//  SB 自身/纯系统路径的连接不碰。EnableXPCReclaim=false 可关。
// ===========================================================================
#define BPLG_XPCREC_MAX 512
static struct { void *conn; double born; int used; } gXPCRecs[BPLG_XPCREC_MAX];
static pthread_mutex_t gXPCRecLock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long gXPCAdopted = 0, gXPCFreed = 0;

typedef void *(*bplg_xpc_retain_t)(void *);
typedef void  (*bplg_xpc_release_t)(void *);
typedef void  (*bplg_xpc_cancel_t)(void *);
static bplg_xpc_retain_t  bplg_xpc_retain_fn  = NULL;
static bplg_xpc_release_t bplg_xpc_release_fn = NULL;
static bplg_xpc_cancel_t  bplg_xpc_cancel_fn  = NULL;

static void bplg_xpc_adopt(const char *name, void *conn, const char *drvimg) {
    if (!gCfgXPC || !conn || !name || !drvimg[0]) return;
    if (strcmp(name, "com.apple.iokit.powerdxpc") != 0) return;   // 只接管定责服务
    if (!bplg_xpc_retain_fn || !bplg_xpc_release_fn) return;
    bplg_xpc_retain_fn(conn);   // 我们自己的引用，回收时只释放这一份

    pthread_mutex_lock(&gXPCRecLock);
    int slot = -1;
    for (int i = 0; i < BPLG_XPCREC_MAX; i++) {
        if (gXPCRecs[i].used && gXPCRecs[i].conn == conn) { slot = i; break; }
        if (!gXPCRecs[i].used && slot < 0) slot = i;
    }
    if (slot >= 0) {
        gXPCRecs[slot].used = 1;
        gXPCRecs[slot].conn = conn;
        gXPCRecs[slot].born = bplg_now();
    }
    pthread_mutex_unlock(&gXPCRecLock);
    if (slot >= 0) __sync_fetch_and_add(&gXPCAdopted, 1);
}

static void bplg_xpc_sweep(void) {
    if (!gCfgXPC || !bplg_xpc_release_fn) return;
    double now = bplg_now();
    for (int i = 0; i < BPLG_XPCREC_MAX; i++) {
        void *conn = NULL;
        pthread_mutex_lock(&gXPCRecLock);
        if (gXPCRecs[i].used && (now - gXPCRecs[i].born) >= (double)gCfgXPCGrace) {
            conn = gXPCRecs[i].conn;
            gXPCRecs[i].used = 0;
            gXPCRecs[i].conn = NULL;
        }
        pthread_mutex_unlock(&gXPCRecLock);
        if (!conn) continue;
        if (bplg_xpc_cancel_fn) bplg_xpc_cancel_fn(conn);   // 异步拆除，端口随之释放
        bplg_xpc_release_fn(conn);                          // 释放我们的引用
        __sync_fetch_and_add(&gXPCFreed, 1);
    }
}

static void bplg_drv_string(char *out, size_t cap) {
    size_t off = 0;
    out[0] = 0;
    pthread_mutex_lock(&gDrvLock);
    for (int k = 0; k < BPLG_DRV_SLOTS && off + 40 < cap; k++) {
        if (gDrvTop[k].n == 0) continue;
        off += (size_t)snprintf(out + off, cap - off, "%s:%lu ", gDrvTop[k].key, gDrvTop[k].n);
    }
    pthread_mutex_unlock(&gDrvLock);
}

static void bplg_xpc_note(const char *name, void *ra) {
    Dl_info info;
    const char *img = "?";
    unsigned long rel = 0;
    if (dladdr(ra, &info) && info.dli_fname) {
        const char *b = strrchr(info.dli_fname, '/');
        img = b ? b + 1 : info.dli_fname;
        if (info.dli_fbase) rel = (unsigned long)((char *)ra - (char *)info.dli_fbase);
    }
    char key[104];
    snprintf(key, sizeof(key), "%.28s+%lx/%.40s", img, rel,
             (name && name[0]) ? name : "(anon)");
    pthread_mutex_lock(&gXPCLock);
    int slot = -1, minSlot = 0;
    for (int k = 0; k < BPLG_XPC_SLOTS; k++) {
        if (gXPCTop[k].n && strcmp(gXPCTop[k].key, key) == 0) { slot = k; break; }
        if (gXPCTop[k].n == 0 && slot < 0) slot = k;
        if (gXPCTop[k].n < gXPCTop[minSlot].n) minSlot = k;
    }
    if (slot < 0) slot = minSlot;   // 满 32 槽：顶掉计数最小的
    strncpy(gXPCTop[slot].key, key, sizeof(gXPCTop[slot].key) - 1);
    gXPCTop[slot].key[sizeof(gXPCTop[slot].key) - 1] = 0;
    gXPCTop[slot].n++;

    int islot = -1, imin = 0;
    for (int k = 0; k < BPLG_XPC_IMGS; k++) {
        if (gXPCImg[k].n && strncmp(gXPCImg[k].img, img, sizeof(gXPCImg[k].img) - 1) == 0) { islot = k; break; }
        if (gXPCImg[k].n == 0 && islot < 0) islot = k;
        if (gXPCImg[k].n < gXPCImg[imin].n) imin = k;
    }
    if (islot < 0) islot = imin;
    strncpy(gXPCImg[islot].img, img, sizeof(gXPCImg[islot].img) - 1);
    gXPCImg[islot].img[sizeof(gXPCImg[islot].img) - 1] = 0;
    gXPCImg[islot].n++;
    pthread_mutex_unlock(&gXPCLock);
}

static void *bplg_hook_xpc_create(const char *name, void *targetq) {
    void *c = gOrigXPC ? gOrigXPC(name, targetq) : NULL;
    if (c) {
        __sync_fetch_and_add(&gXPCTotal, 1);
        void *ra = __builtin_return_address(0);
        bplg_xpc_note(name, ra);
        Dl_info di;
        if (dladdr(ra, &di) && bplg_is_system_path(di.dli_fname)) {
            char drv[64];
            if (bplg_xpc_driver_walk(ra, drv, sizeof(drv)))
                bplg_xpc_adopt(name, c, drv);   // 插件驱动 → 接管候选
        }
    }
    return c;
}

static void *bplg_hook_xpc_create_ms(const char *name, void *targetq, unsigned long flags) {
    void *c = gOrigXPCMS ? gOrigXPCMS(name, targetq, flags) : NULL;
    if (c) {
        __sync_fetch_and_add(&gXPCTotal, 1);
        void *ra = __builtin_return_address(0);
        bplg_xpc_note(name, ra);
        Dl_info di;
        if (dladdr(ra, &di) && bplg_is_system_path(di.dli_fname)) {
            char drv[64];
            if (bplg_xpc_driver_walk(ra, drv, sizeof(drv)))
                bplg_xpc_adopt(name, c, drv);
        }
    }
    return c;
}

static void *bplg_hook_xpc_create_ep(void *ep, void *targetq) {
    void *c = gOrigXPCEP ? gOrigXPCEP(ep, targetq) : NULL;
    if (c) {
        __sync_fetch_and_add(&gXPCTotal, 1);
        bplg_xpc_note("(endpoint)", __builtin_return_address(0));
    }
    return c;
}

static void bplg_xpc_top_string(char *out, size_t cap) {
    size_t off = 0;
    out[0] = 0;
    pthread_mutex_lock(&gXPCLock);
    // 简单选择排序输出 Top（32 项排序开销可忽略）
    int idx[BPLG_XPC_SLOTS];
    for (int k = 0; k < BPLG_XPC_SLOTS; k++) idx[k] = k;
    for (int a = 0; a < BPLG_XPC_SLOTS - 1; a++)
        for (int b = a + 1; b < BPLG_XPC_SLOTS; b++)
            if (gXPCTop[idx[b]].n > gXPCTop[idx[a]].n) { int t = idx[a]; idx[a] = idx[b]; idx[b] = t; }
    for (int k = 0; k < BPLG_XPC_SLOTS && off + 48 < cap; k++) {
        if (gXPCTop[idx[k]].n == 0) break;
        off += (size_t)snprintf(out + off, cap - off, "%s:%lu ",
                                gXPCTop[idx[k]].key, gXPCTop[idx[k]].n);
    }
    pthread_mutex_unlock(&gXPCLock);
}

static void bplg_xpc_img_string(char *out, size_t cap) {
    size_t off = 0;
    out[0] = 0;
    pthread_mutex_lock(&gXPCLock);
    int idx[BPLG_XPC_IMGS];
    for (int k = 0; k < BPLG_XPC_IMGS; k++) idx[k] = k;
    for (int a = 0; a < BPLG_XPC_IMGS - 1; a++)
        for (int b = a + 1; b < BPLG_XPC_IMGS; b++)
            if (gXPCImg[idx[b]].n > gXPCImg[idx[a]].n) { int t = idx[a]; idx[a] = idx[b]; idx[b] = t; }
    for (int k = 0; k < BPLG_XPC_IMGS && off + 32 < cap; k++) {
        if (gXPCImg[idx[k]].n == 0) break;
        off += (size_t)snprintf(out + off, cap - off, "%s:%lu ",
                                gXPCImg[idx[k]].img, gXPCImg[idx[k]].n);
    }
    pthread_mutex_unlock(&gXPCLock);
}

// ===========================================================================
//  观测：mach port 数量 + 类型分解（2.0.9）
//  mach_port_names 顺带返回每个名字的类型位，分类后即可判断泄漏机制：
//    send-once 涨 = 未应答 RPC（reply port）泛滥；
//    receive  涨 = 进程内自建端口（mach_port_allocate / construct）没销毁；
//    send     涨 = 持有指向外部的 send 权不放（连接对象泄漏的典型形态）。
// ===========================================================================
static unsigned long gPtSend = 0, gPtRecv = 0, gPtOnce = 0, gPtDead = 0, gPtSet = 0;

static mach_msg_type_number_t bplg_port_count(void) {
    mach_port_name_array_t names = NULL;
    mach_msg_type_number_t ncnt = 0;
    mach_port_type_array_t types = NULL;
    mach_msg_type_number_t tcnt = 0;
    gPtSend = gPtRecv = gPtOnce = gPtDead = gPtSet = 0;
    kern_return_t kr = mach_port_names(mach_task_self(), &names, &ncnt, &types, &tcnt);
    if (kr == KERN_SUCCESS && types) {
        for (mach_msg_type_number_t i = 0; i < tcnt; i++) {
            mach_port_type_t t = types[i];
            if (t & MACH_PORT_TYPE_SEND_ONCE)      gPtOnce++;
            else if (t & MACH_PORT_TYPE_RECEIVE)   gPtRecv++;
            else if (t & MACH_PORT_TYPE_SEND)      gPtSend++;
            else if (t & MACH_PORT_TYPE_DEAD_NAME) gPtDead++;
            else if (t & MACH_PORT_TYPE_PORT_SET)  gPtSet++;
        }
    }
    if (names && ncnt) {
        vm_deallocate(mach_task_self(), (vm_address_t)names,
                      (vm_size_t)(ncnt * sizeof(mach_port_name_t)));
    }
    if (types && tcnt) {
        vm_deallocate(mach_task_self(), (vm_address_t)types,
                      (vm_size_t)(tcnt * sizeof(mach_port_type_t)));
    }
    return (kr == KERN_SUCCESS) ? ncnt : 0;
}

static int bplg_is_locked(void) {
    static int tok = -1;
    if (tok == -1) {
        int t = -1;
        if (notify_register_check("com.apple.springboard.lockstate", &t) == NOTIFY_STATUS_OK) tok = t;
    }
    if (tok == -1) return 0;
    uint64_t st = 0;
    if (notify_get_state(tok, &st) != NOTIFY_STATUS_OK) return 0;
    return st != 0;
}

// ===========================================================================
//  配置
// ===========================================================================
static void bplg_load_config(void) {
    NSDictionary *d = nil;
    for (int i = 0; i < gCfgCount; i++) {
        NSString *p = [NSString stringWithUTF8String:kBPLGCfgs[i]];
        d = [NSDictionary dictionaryWithContentsOfFile:p];
        if ([d isKindOfClass:[NSDictionary class]]) break;
        d = nil;
    }
    if (!d) return;
    id v;
    if ((v = d[@"EnableCFCleanup"]))      gCfgCF = [v boolValue];
    if ((v = d[@"EnableFDReclaim"]))      gCfgFD = [v boolValue];
    if ((v = d[@"EnableLog"]))            gCfgLog = [v boolValue];
    if ((v = d[@"LogInterval"]))          { long x = [v longValue]; if (x >= 30) gCfgInterval = x; }
    if ((v = d[@"CFGraceSeconds"]))       { long x = [v longValue]; if (x >= 5) gCfgCFGrace = x; }
    if ((v = d[@"FDGraceSeconds"]))       { long x = [v longValue]; if (x >= 5) gCfgFDGrace = x; }
    if ((v = d[@"FDHighWater"]))          { long x = [v longValue]; if (x >= 100) gCfgFDHighWater = x; }
    if ((v = d[@"EnableAutoRespring"]))   gCfgRespring = [v boolValue];
    if ((v = d[@"PortThreshold"]))        { long x = [v longValue]; if (x >= 2000) gCfgPortLimit = x; }
    if ((v = d[@"EnableXPCReclaim"]))    gCfgXPC = [v boolValue];
    if ((v = d[@"XPCGraceSeconds"]))     { long x = [v longValue]; if (x >= 5) gCfgXPCGrace = x; }
    if ((v = d[@"DebugVerbose"]))         gCfgDebug = [v boolValue];
}

// ===========================================================================
//  定时任务：CF 回收 / fd 回收 / 周期日志 / 兜底
// ===========================================================================
static void bplg_start_timers(void) {
    // 2.0.8 关键修正：source 与 queue 必须放全局。
    // 局部变量在函数返回时被 ARC 释放，定时器随之销毁 —— 2.0.7 真机日志证明
    // 那样写 5 秒 tick 一次都不会触发（无影子自验证行、无 stat 行），
    // CF/fd 清扫与统计全部没跑，端口照旧涨满。
    static dispatch_source_t t = NULL;
    static dispatch_queue_t q = NULL;
    if (t) return;   // 已启动，防重入
    q = dispatch_queue_create("bioprotectleakguard.timer", NULL);
    t = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
    if (!t) {
        bplg_log("!! 定时器创建失败：清扫与统计将不会运行");
        return;
    }
    dispatch_source_set_timer(t, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC),
                              5 * NSEC_PER_SEC, 2 * NSEC_PER_SEC);

    __block long tick = 0;
    __block double lastRespring = 0;
    dispatch_source_set_event_handler(t, ^{
        @autoreleasepool {
            tick++;
            if (tick == 1) bplg_shadow_boot();   // 进程已运行 ~5s，cfprefsd 就绪
            bplg_cf_sweep();
            bplg_xpc_sweep();   // 2.0.13：回收插件驱动的 powerdxpc 泄漏连接
            if ((tick % 6) == 0) bplg_fd_sweep();     // 每 30s

            long logEvery = gCfgInterval / 5;
            if (logEvery < 1) logEvery = 1;
            if (gCfgLog && (tick % logEvery) == 0) {
                int limit = getdtablesize();
                if (limit <= 0) limit = 1024;
                if (limit > 8192) limit = 8192;
                mach_msg_type_number_t ports = bplg_port_count();
                int used = bplg_fd_used(limit);
                char paSites[320];
                bplg_pa_sites_string(paSites, sizeof(paSites));
                static unsigned long sLastXPC = 0;
                unsigned long xpc5 = (gXPCTotal >= sLastXPC) ? (gXPCTotal - sLastXPC) : 0;
                sLastXPC = gXPCTotal;
                bplg_log("stat ports=%u fd=%d/%d shadow=%s cf_called=%lu cf_adopt=%lu cf_free=%lu fd_open=%lu fd_close=%lu fd_skip=%lu pa=%lu paBP=%lu pc=%lu mpaf=%lu xpc=%lu xpc5=%lu xpcA=%lu xpcF=%lu tS=%lu tR=%lu tO=%lu tD=%lu tP=%lu lock=%d",
                         ports, used, limit,
                         gShadowOk ? "ok" : (gShadowReady ? "fail" : "wait"),
                         gCFCreateCalls, gCFAdopted, gCFReclaimed,
                         gFDOpened, gFDClosed, gFDSkipped,
                         gPATotal, gPABP, gPCTotal, gPAFTotal, gXPCTotal, xpc5, gXPCAdopted, gXPCFreed,
                         gPtSend, gPtRecv, gPtOnce, gPtDead, gPtSet, bplg_is_locked());
                if (paSites[0])
                    bplg_log("top bp_alloc: %s", paSites);
                char cs[320];
                bplg_cs_sites_string(cs, sizeof(cs));
                if (cs[0])
                    bplg_log("top construct/alloc_full: %s", cs);
                char xi[384];
                bplg_xpc_img_string(xi, sizeof(xi));
                if (xi[0])
                    bplg_log("top xpc img: %s", xi);
                char xt[640];
                bplg_xpc_top_string(xt, sizeof(xt));
                if (xt[0])
                    bplg_log("top xpc: %s", xt);
                char drv[384];
                bplg_drv_string(drv, sizeof(drv));
                if (drv[0])
                    bplg_log("xpc 驱动者(栈回溯): %s", drv);

                if (gCfgRespring) {
                    double now = bplg_now();
                    if ((ports > (mach_msg_type_number_t)gCfgPortLimit || used > (limit * 4 / 5)) &&
                        (now - lastRespring) > 6 * 3600 && bplg_is_locked()) {
                        lastRespring = now;
                        bplg_log("!! 资源逼近上限(ports=%u fd=%d/%d)，锁屏中执行一次受控桌面重启",
                                 ports, used, limit);
                        sleep(1);
                        exit(0);
                    }
                }
            }
        }
    });
    dispatch_resume(t);
}

// ===========================================================================
//  入口
// ===========================================================================
static int bplg_bp_image_loaded(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "BioProtect") && strstr(name, ".dylib")) return 1;
    }
    return 0;
}

%ctor {
    @autoreleasepool {
        static int inited = 0;
        if (inited) return;
        inited = 1;

        // 第一件事就是落盘一行（纯 C，不依赖任何框架），
        // 只要 dylib 被 dlopen 过，这一行就一定能看到
        bplg_crumb("ctor");
        bplg_build_sinks();
        bplg_build_cfg_paths();
        bplg_ensure_dirs();
        bplg_log("[boot] v%s pid=%d 已进入构造函数", BPLG_VERSION, getpid());

        bplg_log("钩子引擎: substrate 直连（MSHookFunction 已链接）");
        NSLog(@"[BioProtectLeakGuard] v%s pid=%d hook=substrate直连", BPLG_VERSION, getpid());

        bplg_load_config();

        // 探明哪些落点真的可写，写进日志与 NSLog，省得靠猜
        gSinkNote[0] = 0;
        for (int i = 0; i < gLogCount; i++) {
            FILE *probe = fopen(kBPLGLogs[i], "a");
            if (!probe) continue;
            fclose(probe);
            size_t used = strlen(gSinkNote);
            snprintf(gSinkNote + used, sizeof(gSinkNote) - used, "%s%s",
                     used ? " | " : "", kBPLGLogs[i]);
        }

        bplg_log("=== BioProtectLeakGuard %s 载入 pid=%d 进程=%s BioProtect已注入=%d ===",
                 BPLG_VERSION, getpid(),
                 NSProcessInfo.processInfo.processName.UTF8String ?: "?",
                 bplg_bp_image_loaded());
        bplg_log("日志落点: %s", gSinkNote[0] ? gSinkNote : "(文件全部不可写)");
        bplg_log("影子日志: 域 %s 的 diaglog 键（加载 5 秒后启用，避开启动期 XPC）", BPLG_PREF_DOMAIN);
        NSLog(@"[BioProtectLeakGuard] v%s pid=%d sink=%s", BPLG_VERSION, getpid(), gSinkNote);

        bplg_log("配置: cf=%d fd=%d log=%lds cf宽限=%lds fd宽限=%lds fd水位=%ld respring=%d debug=%d",
                 gCfgCF, gCfgFD, gCfgInterval, gCfgCFGrace, gCfgFDGrace,
                 gCfgFDHighWater, gCfgRespring, gCfgDebug);

        if (gCfgCF) {
            MSHookFunction((void *)CFUserNotificationCreate, (void *)bplg_hook_create, (void **)&gOrigCreate);
            MSHookFunction((void *)CFUserNotificationCreateRunLoopSource, (void *)bplg_hook_rls, (void **)&gOrigRLS);
            bplg_log("hook 完成: CFUserNotificationCreate / CreateRunLoopSource（substrate 直连）");
        }

        if (gCfgFD) {
            MSHookFunction((void *)open, (void *)bplg_hook_open, (void **)&gOrigOpen);
            bplg_log("hook 完成: open()  fd 泄漏观测已开启（substrate 直连）");
        }

        // 2.0.8：端口归因观测（不受 config 开关限制——统计本身无副作用，
        // 而「端口还在涨但不知道谁分配的」正是上一轮卡住的地方）
        MSHookFunction((void *)mach_port_allocate, (void *)bplg_hook_mpa, (void **)&gOrigMPA);
        bplg_log("hook 完成: mach_port_allocate  端口归因观测已开启（substrate 直连）");

        // 2.0.9：其余端口创建口（xpc/GCD 通道走 mach_port_construct）
        MSHookFunction((void *)mach_port_construct, (void *)bplg_hook_mpc, (void **)&gOrigMPC);
        MSHookFunction((void *)mach_port_allocate_full, (void *)bplg_hook_mpaf, (void **)&gOrigMPAF);
        bplg_log("hook 完成: mach_port_construct / mach_port_allocate_full（substrate 直连）");

        // xpc 三个入口用 dlsym 取址（不给 dylib 增加 libxpc 依赖，保持原生 roothide 形态）
        gOrigXPC = (bplg_xpc_create_t)dlsym(RTLD_DEFAULT, "xpc_connection_create");
        if (gOrigXPC)
            MSHookFunction((void *)gOrigXPC, (void *)bplg_hook_xpc_create, (void **)&gOrigXPC);
        gOrigXPCMS = (bplg_xpc_create_ms_t)dlsym(RTLD_DEFAULT, "xpc_connection_create_mach_service");
        if (gOrigXPCMS)
            MSHookFunction((void *)gOrigXPCMS, (void *)bplg_hook_xpc_create_ms, (void **)&gOrigXPCMS);
        gOrigXPCEP = (bplg_xpc_create_ep_t)dlsym(RTLD_DEFAULT, "xpc_connection_create_from_endpoint");
        if (gOrigXPCEP)
            MSHookFunction((void *)gOrigXPCEP, (void *)bplg_hook_xpc_create_ep, (void **)&gOrigXPCEP);
        bplg_log("hook 完成: xpc_connection_create%s%s%s（dlsym 取址）",
                 gOrigXPC ? "" : " 缺失",
                 gOrigXPCMS ? "" : "(_mach_service 缺失)",
                 gOrigXPCEP ? "" : "(_from_endpoint 缺失)");

        // 2.0.13：powerdxpc 泄漏连接回收（CallAssist 定责）所需的三个函数
        bplg_xpc_retain_fn  = (bplg_xpc_retain_t)dlsym(RTLD_DEFAULT, "xpc_retain");
        bplg_xpc_release_fn = (bplg_xpc_release_t)dlsym(RTLD_DEFAULT, "xpc_release");
        bplg_xpc_cancel_fn  = (bplg_xpc_cancel_t)dlsym(RTLD_DEFAULT, "xpc_connection_cancel");
        bplg_log("xpc 回收: %s（宽限 %lds，目标=插件驱动的 powerdxpc 连接）",
                 (bplg_xpc_retain_fn && bplg_xpc_release_fn) ? "就绪" : "函数缺失，仅观测",
                 gCfgXPCGrace);

        bplg_crumb("hooks");

        struct rlimit rl;
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
            bplg_log("fd 上限: soft=%llu hard=%llu dtablesize=%d",
                     (unsigned long long)rl.rlim_cur, (unsigned long long)rl.rlim_max,
                     getdtablesize());
        }

        bplg_start_timers();
        bplg_log("定时器已启动：CF 回收每 5s，fd 回收每 30s，日志每 %lds", gCfgInterval);
        bplg_crumb("ready");
    }
}
