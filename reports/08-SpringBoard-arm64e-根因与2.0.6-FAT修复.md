# 08 SpringBoard arm64e 根因 + 2.0.6 FAT 双切片修复

> 归档日期：2026-10-24 · 关联：07（2.0.5 三盲区）、06（阶段收尾）
> 状态：**2.0.6 最终版已构建（clang 19 + ld64 956，真 arm64e），待设备验证**

## 最终根因（一句话）

SpringBoard 是 arm64e 进程，只吃 arm64e 切片。这条链路有三层坑，全踩平才算修好：
1. **架构**：arm64 单切片被 dyld 静默拒载 → 需 arm64e 切片；
2. **chained fixups 格式**：clang 11/13 + ld64-609 产的 arm64e 是 ptr_format=1（普通）而非 12（arm64e auth）
   → 数据指针无 PAC 重定位 → 崩；需 clang 19 + ld64 956；
3. **ldid 重签不重算 auth PAC**：clang 19 产物本身 auth 有效，但 RootHide 转换器改写 `/var/jb` rpath 字节后
   重签（CodeDirectory 变了、auth PAC 没跟着重算）→ auth 失效 → dyld 拒载 → 进安全模式无日志。
   → 解法：去掉 `/var/jb` rpath（只留 `@loader_path/.jbroot`），转换器无需改写、无需重签，auth 保持。

---

## 一、一句话结论

LeakGuard 2.0.5（及之前所有版本）**从未进入 SpringBoard 的真正原因不是过滤器、不是依赖、不是签名，
而是架构不匹配：SpringBoard 是 arm64e 进程，只加载 arm64e 切片的 tweak；我们的 dylib 是 arm64 单切片，
被 dyld 静默拒载。** 2.0.6 产出 FAT（arm64 + arm64e `0x80000002`）双切片，arm64 App 用 arm64 切片、
SpringBoard 用 arm64e 切片。

## 二、证据链

1. **2.0.5 加 `com.apple.UIKit` 过滤器后**：Filza/Sileo（第三方 App，**arm64 进程**）被注入，
   `guard.log` 出现 boot 行；但 **SpringBoard 始终 0 次**（用户两次拷回的日志均只有 Filza/Sileo）。
2. **架构核查（LIEF/FAT 头）**：
   - `BioProtect.dylib`（原版，能注入 SB）：**FAT `arm64 + arm64e(0x80000002)`**；
   - `BioProtectLeakGuard.dylib`（2.0.5）：**thin `arm64(0x0)` 单切片**；
   - 崩溃日志：`procName=SpringBoard, modelCode=iPhone16, cpuType=ARM-64` → SpringBoard 是 arm64e 系统进程。
3. **修正一个旧结论**：VolumeManager 净化模块「进不了设置 App」此前归因于「roothide 白名单对系统 App 的
   硬限制」——**真正原因很可能同样是 arm64e**（设置 App 是 arm64e 系统 App，净化模块是 arm64 单切片）。
   而 VolManAudioQueue（arm64）注入的全是第三方 App、从不进 SpringBoard，与之一致。

## 三、工具链限制与对策

- WSL Theos 工具链 clang 11.1.0 用 `-target arm64e-apple-ios15.0` 编译，object 的 cpusubtype 是
  **`0x2`（旧 arm64e ABI，iOS 12 beta 废弃形态）**；链接时 ld 报「incompatible arm64e ABI compiler」，
  且链接后的 arm64e 切片**不含 PAC 指令**（实为 arm64 代码）。
- **首版对策（已证伪）**：把最终 FAT 里 arm64e 切片 cpusubtype 从 `0x2` 改为 `0x80000002` + ldid 重签。
  结果：**用户实机加载即崩、进安全模式且退出无效**。根因：ld 链接时因「incompatible arm64e ABI」把 PAC
  剥离了，得到的只是「无 PAC 的 arm64 代码 + arm64e 标签」，在 arm64e 系统进程里运行时 PAC 校验失败。
- **最终对策（有效）**：在**编译阶段**（ld 链接之前）用 wrapper 编译器把 arm64e object 的 cpusubtype
  从 `0x2` patch 成 `0x80000002`，ld 据此按新 ABI 链接、**保留 PAC**（pacibsp/retab），产出真正的
  arm64e（`0x80000002` + 带 PAC）。实现：`build.sh` 生成 wrapper `clang/clang++`，编译后检查输出 .o，
  若是 arm64e(0x2) 就 patch；`make package TARGET_CC/TARGET_CXX/TARGET_LD=$WRAP/...` 强制 theos 走 wrapper
  （PATH 劫持无效，theos 会把 clang 解析成绝对路径）。链接必须用 clang++ 驱动（否则丢 libc++ 报
  `___gxx_personality_v0` 未定义）。

## 四、2.0.6 修改

| 项 | 内容 |
|---|---|
| Makefile | `ARCHS = arm64 arm64e` |
| build.sh | 新增「解包 → Python patch arm64e cpusubtype → ldid 重签 → dpkg-deb --build 重打包」；断言改为 FAT + arm64e 切片 cpusubtype==0x80000002；版本串 2.0.6 |
| 源码 | 逻辑零改动（仅版本号 2.0.6）；substrate 直连、CF/fd 钩子、运行时路径、影子日志全部保留 |
| 注意 | dpkg-deb --build 重打包后压缩格式变为 **zst**（原 make package 是 lzma）；Windows 解析需 zstandard |

## 五、产物（最终版）

- `release/com.local.bioprotectleakguard_2.0.6_iphoneos-arm64.deb`（14,266 B，md5 `d53c5ef7cbbc348c3f014c886d1818de`）
- dylib FAT：slice0 `arm64(0x0)` + slice1 `arm64e(0x80000002)`，755
- **最终版关键断言全过**：arm64e 切片 cpusubtype==0x80000002 ✓、**chained fixups ptr_format==12（arm64e auth）✓**、
  **rpath 只有 `@loader_path/.jbroot`（无 `/var/jb`）✓**、`@rpath/CydiaSubstrate.framework/CydiaSubstrate` 依赖 ✓、
  `_MSHookFunction` 导入 ✓、版本串 2.0.6 ✓、`/var/mobile` 字面量 0 ✓。
- 工具链：clang 19（L1ghtmann v19.0.0）+ ld64 956 + ldid(Procursus)，构建于 Ubuntu 24.04。
- 关键改动：theos rootless scheme 的 `vendor/mod/rootless/instance/rules.mk` 里 v1 行（`-rpath $(THEOS_PACKAGE_INSTALL_PREFIX)/...` = `/var/jb`）
  已注释掉（备份 `.bak`），只保留 v2 的 `@loader_path/.jbroot`。这是「让转换器不改 dylib」的核心。
- 构建踩坑记录：clang 19 默认隐式模块 → Makefile 加 `-fno-modules`（OBJCCFLAGS）；tc19 libc++ 的
  `__config_site` 在 host 三元组目录 → 复制到 `include/c++/v1/`；MSHookFunction 链接需显式
  `FRAMEWORKS += CydiaSubstrate` + `LDFLAGS += -F$(THEOS)/vendor/lib/iphone/rootless`。

## 六、用户验证步骤（傻瓜级）

1. RootHide 转换 → 装 2.0.6 → **respring**（必须真正注销，不是重开 Filza）。
2. 等 5 分钟，取 `/var/mobile/Library/BioProtectLeakGuard/guard.log`（真实根）或
   `/var/mobile/Library/Preferences/BioProtectLeakGuard.log`。
3. **判据**：
   - 出现 `进程=SpringBoard` 的 boot 行 → **arm64e 方案成功**，读 `stat ports=…` 曲线；
   - SpringBoard 崩溃/进安全模式 → arm64e patch 在这台机不稳，回退 2.0.5 并走工具链升级路线；
   - 仍只有 Filza/Sileo、无 SpringBoard → 架构之外还有别的关卡，把日志发回继续查。

## 七、经验沉淀（已并入 MEMORY.md）

1. **arm64e 设备（A12+，尤其系统进程）只吃 arm64e 切片**；给 SpringBoard 类的系统进程做 tweak，
   dylib 必须含 arm64e（`0x80000002`）切片，否则 dyld 静默拒载（无日志、无崩溃、无任何痕迹）。
2. **WSL clang 11 产 arm64e 是旧 ABI `0x2`，且 ld 链接后剥离 PAC**——patch cpusubtype 到 `0x80000002`
   + ldid 重签是可行捷径（arm64 代码与 arm64e 进程共存是 PAC 设计目标）。
3. **「装上了但某个进程没反应」优先查架构匹配**，其次才是过滤器/依赖/签名/路径。
