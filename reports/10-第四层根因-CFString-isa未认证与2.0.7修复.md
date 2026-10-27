# 10 第四层根因实锤：CFString isa 未认证 + 2.0.7 修复

> 归档日期：2026-10-25 · 关联：08（arm64e 根因与 FAT）、09（arm64e 攻坚记录）
> 状态：**根因已定位并在二进制层修复，2.0.7 已构建，待真机验证**

---

## 一、本轮结论（一句话）

前三层修完仍进安全模式的"第四层"是：**clang19 工具链给 arm64e 编 CFSTR 常量时，isa
重定位是普通 UNSIGNED 而非 ARM64_RELOC_AUTHENTICATED_POINTER，导致 chained fixups 里
`__cfstring` 的 27 个 isa 全是「无 PAC 的普通 bind」**；arm64e 系统进程里 objc_msgSend
碰到常量字符串接收者就对未签名 isa 做指针认证 → SIGBUS → 安全模式。构建期把这 27 条
补丁成与原版逐位同形的「auth bind」后重签，即 2.0.7。

## 二、证据链（本轮如何实锤）

### 1. 新证据：四份 .ips（项目根目录，2026-10-25 分析）

| 文件 | 进程 | 结论 |
|---|---|---|
| `Spotlight-2026-10-24-013017..ips` | **Spotlight（arm64e 系统进程）** | **决定性**：BioProtectLeakGuard.dylib 以 arm64e 切片加载成功（`/usr/lib/TweakInject/`），崩溃栈 = dyld initializer（我们的 %ctor）→ LeakGuard+0x1414 → +0x1940 → **objc_msgSend → SIGBUS**（UNKNOWN_0x105 @ 0xdac11950）。即：dylib 能被加载，是**我们自己的代码在 ctor 里调 ObjC 时崩** |
| `irisin-2026-10-23-212111..ips` | irisin | 与本模块无关：栈顶是 `ScreenshotShell.dylib`（用户另装的插件）PAC 失败 |
| `Debs-2026-10-23-222825/222831..ips` | Debs（arm64e 企业签 App） | 与本模块无关：LimneosCrack.dylib（img10，arm64e）抛 ObjC 消息转发异常 → abort ×2 |

注意 Spotlight 崩溃的 dylib UUID `fccfed7a…` ≠ 最终原生包 arm64e 切片 UUID `53536dfd…`
——它是更早的 clang11 patch-object 版（15,300B，ptr_format=1）。但它证明了崩溃**签名**：
ctor → objc_msgSend → 坏指针。clang19 版(ptr_format=12)与原生版在设备上"仍安全模式"，
症状一致，指向同一类机制。

### 2. 静态对比：逐条解码 chained fixups（scripts/50、51）

与设备验证可加载的 BioProtect 4.6-222 原版（Xcode 编译）arm64e 切片逐项对比：

| 条目类别 | 我们 2.0.6 | 原版（可用） | 判定 |
|---|---|---|---|
| `__auth_got` 函数指针 | 70 × auth bind（key=0, addrDiv=1, div=0） | 110 × 同构 | ✓ 一致 |
| `__got` C 符号 | 9 × plain bind | 28+1 × plain bind | ✓ 一致 |
| `__objc_selrefs` | 14 × plain rebase | 807 × plain rebase | ✓ 一致 |
| `__objc_classrefs` | 3 × plain bind | 53 × plain bind | ✓ 一致 |
| `__cfstring` 的 `.ptr` | 27 × plain rebase | 416 × plain rebase | ✓ 一致 |
| **`__cfstring` 的 isa** | **27 × plain bind（无 PAC）** | **416 × auth bind** | **✗ 唯一实质差异** |

原版 isa 签名参数（三个 BioProtect dylib 交叉验证完全一致）：**auth bind，diversity=0x6AE1，
addrDiv=1，key=2**（0x6AE1 即 objc4 的 ISA 签名常量）。

### 3. 工具链验证（WSL 最小样例）

`clang -target arm64e-apple-ios15.0 -c t.c`（t.c 只含一行 CFSTR）后 `otool -r`：
isa 槽的重定位是 `ARM64_RELOC_UNSIGNED`，**没有** `ARM64_RELOC_AUTHENTICATED_POINTER`。
→ 差异源头在 clang19（L1ghtmann Linux 工具链）的 CFString 代码生成，不是 ld64。
所以修复只能在链接后做二进制补丁（或换 Apple clang，本环境没有）。

### 4. 对旧结论的修正

- 报告 09 的"第四层未知"三假设（转换器仍触发 / 代码 arm64e 兼容 / 加载器）全部不对，
  真凶是 isa 未认证——它从 clang19 版（14,270B）起就在，与转换器无关。
- **"ldid 重签破坏 PAC"（第三层）存疑**：fixups 数据从未被破坏过（本轮 llvm-otool 全面
  解析正常）；当年对比的"转换前后崩溃差异"更可能是 isa 问题一直存在 + arm64/arm64e
  进程差异造成的误判。ldid 重签本身无害（2.0.7 补丁后也要重签）。
- Spotlight 崩溃日志证明 **roothide 的注入路径是 `/usr/lib/TweakInject/`**（libinjector.dylib
  → dlopen → initializer），arm64e 原生包可以被系统进程加载——加载层没有额外障碍。

## 三、2.0.7 修复实现

`bioprotect-fix/build.sh`（2026-10-25 重写）在 `make package` 之后追加四步：

1. `dpkg-deb -R` 解包；
2. **isa 补丁**（内嵌 Python）：只动 arm64e 切片（cpusubtype=0x80000002）的
   `__DATA_CONST/__cfstring`，按 32 字节结构步长定位每个 isa 槽，把
   `plain bind24` 改写为 `auth bind24`：保留 ordinal（bits 0-23）与 next（51-61），
   写入 diversity=0x6AE1（32-47）、addrDiv=1（48）、key=2（49-51）、bind=1、auth=1。
   arm64 切片（format 6，无认证概念）不动；
3. `ldid -S` 重签（CodeDirectory 重算）；
4. `dpkg-deb -b -Zxz` 重打包，随后全套断言。

**断言（在 2.0.6 基础上新增两条）**：
- arm64e 切片 chained fixups：`pointer_format==12` **且 每个带链段 `page_count>=1`**
  （页链为空 = 指针全不绑定，2.0.6 只查了 format 没查页数——本轮一度误判的教训）；
- `__cfstring` 全部 isa：`auth==1 且 (div,addrDiv,key)==(0x6AE1,1,2)`，plain=0。

**运行时新增（BioProtectLeakGuard.xm）**：`bplg_crumb()` 纯 POSIX 面包屑
（getenv/open/write/close，先于一切 ObjC/CF），%ctor 三段落盘
`~/Library/BioProtectLeakGuard/crumb.log`：`[ctor]`（进入）→ `[hooks]`（MSHook 挂完）
→ `[ready]`（定时器启动）。再出问题时能判别「没加载 / 加载后死在哪一步」。
postinst 新增：安装时打印设备上 dylib 的 md5 与 ls（与构建 md5 对不上 = 被转换器重写）。

## 四、产物

| 项 | 值 |
|---|---|
| 包 | `release/com.local.bioprotectleakguard_2.0.7_iphoneos-arm64e.deb`（14,840 B） |
| 包 md5 | `e375f646fa7ef0007310d739a2b8370b` |
| dylib | FAT 170,144 B，md5 `4c0bea31784ecf8fcd1c37f6fe30d9b2`，sha256 `1f79e5af…76a6` |
| 断言 | 全过：cpusubtype 0x80000002 ✓ ptr_format=12 ✓ 页链≥1 ✓ **isa auth=27 plain=0** ✓ MSHookFunction ✓ 依赖 `.jbroot` substrate ✓ rpath 空 ✓ 无写死路径 ✓ 755 ✓ |

Windows 侧独立复核 + WSL llvm-otool 双切片解析均正常。

## 五、真机验证步骤（下一步）

1. 卸载旧版（若装过 2.0.6）→ 安装 `…2.0.7_iphoneos-arm64e.deb`（**不要**过 RootHide
   转换器；若 Sileo 强制转换，postinst 打印的 md5 会 ≠ `4c0bea31…`，一查便知）；
2. respring；
3. 判读（三态）：
   - **不进安全模式** + Filza 看 `/var/mobile/Library/BioProtectLeakGuard/crumb.log`
     出现 `[ctor]/[hooks]/[ready]` → **修复成功**，后续看 guard.log 的 ports/fd 曲线验证泄漏修复效果；
   - **进安全模式** 但 crumb.log 有 `[ctor]` → dylib 已加载、死在 ObjC 阶段 → 抓
     SpringBoard 最新 .ips（这次一定有崩溃栈）回来定位；
   - **进安全模式** 且 crumb.log 没有 → 死在更早（加载/依赖层）→ 比对设备端 dylib md5。
4. 若一切正常，观察 12+ 小时：桌面不再自动注销 = 初步胜利；guard.log 的 `fd_close`、
   `cf_free` 增长 = 回收机制生效。

## 六、本轮新增可复用结论

1. **arm64e 判定标准再补两条**：除 `cpusubtype==0x80000002` + `ptr_format==12` 外，
   还须查 **starts 表 page_count≥1** 和 **__cfstring isa 全 auth bind**。任何一条不满足
   都是"看似 arm64e 实则必崩"。
2. **L1ghtmann clang19（Linux 工具链）不会给 CFSTR isa 发认证重定位**，用它在 arm64e
   上发 tweak 必须链接后补丁 isa（配方已固化在 build.sh）。
3. **dyld_chained_starts_in_segment 结构含 segment_offset(u64) 字段**（size,page_size,
   ptr_format 之后、max_valid_pointer 之前）——漏掉它会把 page_count 解析成 0，
   本轮差点据此做出一次错误"修复"（先入为主 + 自写解析器的双重教训：
   **自写解析结果必须用 llvm-otool 等权威工具交叉验证**）。
4. chained fixups 条目就在数据段槽位里（starts 表只标记哪些页有链）；
   format 12 下 8 字节一条、next 以 8 字节为步进单位。
5. 崩溃日志里 `usedImages` 的 `"arch": "arm64e"` + 进程路径可判断目标进程是 arm64e
   （企业签 App 也可能是 arm64e，如 Debs）。
6. 本机 roothide 实际注入目录：`/usr/lib/TweakInject/`（libinjector.dylib 负责注入）。
