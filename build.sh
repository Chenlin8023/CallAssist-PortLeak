#!/bin/bash
# BioProtectLeakGuard 构建脚本（在 WSL 里跑）
#   用法： wsl -d Ubuntu-22.04 -- bash /mnt/d/WorkBudy/Bioprotect/bioprotect-fix/build.sh
#
# 2.0.7（isa 认证补丁，沿用）：clang19（L1ghtmann）给 arm64e 编 CFSTR 时 isa 重定位是
#   普通 UNSIGNED（不是 ARM64_RELOC_AUTHENTICATED_POINTER，已用最小样例实测），
#   ld64 956 据此在 chained fixups 里把 __cfstring 的 isa 全写成
#   「普通 bind（无 PAC）」；Xcode 编的原版（BioProtect 三个 dylib 一致）
#   全是「auth bind：diversity=0x6AE1, addrDiv=1, key=2」。
#   arm64e 系统进程里 objc_msgSend 遇到常量字符串接收者，对未签名 isa
#   做指针认证 → SIGBUS（Spotlight-2026-10-24-013017 崩溃栈实锤：
#   LeakGuard+0x1414 → +0x1940 → objc_msgSend）。
#   修复：make package 之后，把 arm64e 切片 __cfstring 的 isa 条目逐个
#   补丁成 auth bind（保留 ordinal 与 next，签名参数逐位对齐原版），
#   ldid 重签，dpkg-deb 重打包，再跑全套断言。
# 2.0.8（运行时修复，构建流程不变）：修定时器 ARC 生命周期 bug（局部
#   dispatch_source_t 函数返回即释放 → 清扫/统计从未运行，端口照旧涨满）。
# 2.0.9（归因升级，构建流程不变）：端口类型分解 + construct/xpc 归因钩子
#   （真机数据：泄漏非 BioProtect 直接分配，pa 仅占增速 1/3）。
# 2.0.13（归因收口，构建流程不变）：xpc 直方图 32 槽淘汰制 + 按镜像聚合 + 偏移键
#   + xpc5 增量 + from_endpoint 钩子（2.0.9 的 10 槽直方图被开机键占满漏掉热点）。
#
#  历史根因链（勿重走）：
#   1) SpringBoard 是 arm64e 进程，只加载 arm64e 切片（arm64 单切片被 dyld 静默拒载）；
#   2) clang 11/13 的 arm64e 是旧 ABI（0x2），patch 也产不出 ptr_format=12 → 换 clang 19；
#   3) 转换器改写 + 重签曾被视为破坏 PAC —— 复核后真凶其实是本层的 isa 未认证，
#      它从 clang19 版（14,270B）到原生版（14,200B）一直都在；
#   4) isa 未认证（本层）。
set -u
export THEOS="$HOME/theos"
export PATH="$THEOS/bin:$PATH"

SRC=/mnt/d/WorkBudy/Bioprotect/bioprotect-fix
DST="$HOME/bplg"
OUT=/mnt/d/WorkBudy/Bioprotect/release
TC19="$HOME/tc19/linux/iphone/bin"   # clang 19 + ld64 956 + ldid(Procursus)

die() { echo "!! $*"; exit 1; }
[ -x "$TC19/clang" ] || die "clang 19 工具链不存在（$TC19/clang）"

rm -rf "$DST"; mkdir -p "$DST"
cp -r "$SRC"/. "$DST"/
find "$DST" -type f -exec sed -i 's/\r$//' {} \; 2>/dev/null
chmod 644 "$DST"/BioProtectLeakGuard.xm "$DST"/Makefile "$DST"/control "$DST"/BioProtectLeakGuard.plist
chmod 755 "$DST"/layout/DEBIAN/postinst
mkdir -p "$DST/layout/Library/MobileSubstrate/DynamicLibraries"

cd "$DST" || die "无法进入 $DST"
echo "=== 清理旧产物 ==="
make clean >/dev/null 2>&1
rm -rf packages .theos

echo "=== 编译（clang 19 + ld64 956，arm64 + arm64e）==="
if ! make package FINALPACKAGE=1 \
    TARGET_CC="$TC19/clang" TARGET_CXX="$TC19/clang++" TARGET_LD="$TC19/clang++" \
    TARGET_CODESIGN="$TC19/ldid" 2>&1 | tail -40; then
    die "编译失败"
fi

DEB=$(ls -1t packages/*.deb 2>/dev/null | head -1)
[ -n "$DEB" ] || die "没有生成 deb"
dpkg-deb -f "$DEB" >/dev/null || die "control 解析失败"
dpkg-deb -f "$DEB" Version Architecture

echo
echo "=== isa 认证补丁（arm64e 切片 __cfstring → auth bind）==="
rm -rf "$DST/repack"; mkdir -p "$DST/repack"
dpkg-deb -R "$DEB" "$DST/repack" || die "dpkg-deb -R 失败"
DYLIB="$DST/repack/Library/MobileSubstrate/DynamicLibraries/BioProtectLeakGuard.dylib"
[ -f "$DYLIB" ] || die "解包后找不到 dylib"

python3 - "$DYLIB" <<'PYEOF' || die "isa 补丁失败"
import struct, sys

p = sys.argv[1]
d = bytearray(open(p, 'rb').read())
assert struct.unpack_from('>I', d, 0)[0] == 0xcafebabe, 'not FAT'
nfat = struct.unpack_from('>I', d, 4)[0]
patched = skipped = 0
for i in range(nfat):
    ct, sub, off, sz, al = struct.unpack_from('>IIIII', d, 8 + i * 20)
    if ct != 0x0100000c or sub != 0x80000002:
        continue  # 只动 arm64e 切片（arm64 格式 6 无认证概念）
    ncmds = struct.unpack_from('<I', d, off + 16)[0]
    q = off + 32
    for k in range(ncmds):
        cmd, csz = struct.unpack_from('<II', d, q)
        if cmd == 0x19:  # LC_SEGMENT_64
            seg = bytes(d[q+8:q+24]).rstrip(b'\0').decode()
            if seg == '__DATA_CONST':
                nsects = struct.unpack_from('<I', d, q + 64)[0]
                so = q + 72
                for j in range(nsects):
                    b = so + j * 80
                    sn = bytes(d[b:b+16]).rstrip(b'\0').decode()
                    if sn != '__cfstring':
                        continue
                    fsize = struct.unpack_from('<Q', d, b + 40)[0]
                    foff = struct.unpack_from('<I', d, b + 48)[0]
                    for s in range(fsize // 32):
                        eo = off + foff + s * 32
                        raw = struct.unpack_from('<Q', d, eo)[0]
                        bind = (raw >> 62) & 1
                        auth = (raw >> 63) & 1
                        if not bind:
                            print('  warn: isa slot %d 非 bind 条目 raw=%#x，跳过' % (s, raw))
                            skipped += 1
                            continue
                        if auth:
                            skipped += 1  # 已认证，不动
                            continue
                        ordinal = raw & 0xFFFFFF
                        nxt = (raw >> 51) & 0x7FF
                        # auth bind24: ordinal[0:24] | diversity=0x6AE1[32:48) | addrDiv=1[48] | key=2[49:51) | next[51:62) | bind=1 | auth=1
                        newv = ((ordinal & 0xFFFFFF)
                                | (0x6AE1 << 32) | (1 << 48) | (2 << 49)
                                | (nxt << 51) | (1 << 62) | (1 << 63))
                        struct.pack_into('<Q', d, eo, newv)
                        patched += 1
        q += csz
open(p, 'wb').write(bytes(d))
print('  isa 补丁：改写 %d 条，跳过 %d 条' % (patched, skipped))
assert patched > 0, '没有可补丁的 isa 条目（构建异常）'
PYEOF

echo "=== 重签（ldid）==="
"$TC19/ldid" -S "$DYLIB" || die "ldid 重签失败"

echo "=== 重打包 deb ===="
rm -f "$DST/packages/patched.deb"
dpkg-deb -b -Zxz "$DST/repack" "$DST/packages/patched.deb" || die "dpkg-deb -b 失败"
DEB="$DST/packages/patched.deb"

echo
echo "=== 包内文件与权限 ==="
rm -rf "$DST/chk"; mkdir -p "$DST/chk"
dpkg-deb -x "$DEB" "$DST/chk"
find "$DST/chk" -name "*.dylib" -o -name "*.plist" | while read -r f; do
    printf '%s %s\n' "$(stat -c '%A' "$f")" "${f#$DST/chk}"
done

DYLIB=$(find "$DST/chk" -name "BioProtectLeakGuard.dylib" | head -1)
[ -n "$DYLIB" ] || die "包里没有主 dylib"
[ -x "$DYLIB" ] || die "主 dylib 没有执行位（ElleKit 会静默跳过加载）"
ARCHS=$("$TC19/lipo" -archs "$DYLIB" 2>/dev/null)
echo "架构: $ARCHS"
echo "$ARCHS" | grep -q "arm64 " || die "缺 arm64 切片"
echo "$ARCHS" | grep -q "arm64e" || die "缺 arm64e 切片"
grep -q "2.0.13" "$DYLIB" || die "dylib 内没有版本串 2.0.13"

# ---------------------------------------------------------------------------
# 二进制终审：arm64e 切片四要素（cpusubtype / ptr_format=12 / 页链非空 / isa 全认证）
# ---------------------------------------------------------------------------
python3 - "$DYLIB" <<'PYEOF' || die "arm64e 切片终审未通过"
import struct, sys

raw = open(sys.argv[1], 'rb').read()
nfat = struct.unpack_from('>I', raw, 4)[0]
for i in range(nfat):
    ct, sub, off, sz = struct.unpack_from('>IIII', raw, 8 + i * 20)
    if ct == 0x0100000c and sub == 0x80000002:
        break
else:
    sys.exit('找不到 arm64e 切片')
s = raw[off:off+sz]
print('arm64e 切片 cpusubtype = 0x%08x' % struct.unpack_from('<I', s, 8)[0])
assert struct.unpack_from('<I', s, 8)[0] == 0x80000002

ncmds = struct.unpack_from('<I', s, 16)[0]
fxo = cfo = cfsz = None
rpaths = []
q = 32
for _ in range(ncmds):
    cmd, csz = struct.unpack_from('<II', s, q)
    if cmd == 0x19:
        seg = s[q+8:q+24].rstrip(b'\0').decode()
        if seg == '__DATA_CONST':
            nsects = struct.unpack_from('<I', s, q + 64)[0]
            so = q + 72
            for j in range(nsects):
                b = so + j * 80
                if s[b:b+16].rstrip(b'\0') == b'__cfstring':
                    cfsz = struct.unpack_from('<Q', s, b + 40)[0]
                    cfo = struct.unpack_from('<I', s, b + 48)[0]
    elif cmd == 0x80000034:  # LC_DYLD_CHAINED_FIXUPS
        fxo, fxs = struct.unpack_from('<II', s, q + 8)
    elif cmd == 0x1c:  # LC_RPATH
        no = struct.unpack_from('<I', s, q + 8)[0]
        rpaths.append(s[q+8+no:q+csz].split(b'\0')[0])
    q += csz
assert not rpaths, 'rpath 非空: %r' % rpaths

fx = s[fxo:fxo+fxs]
ver, s_off, s_size, i_off, i_size, y_off, y_size, i_fmt = struct.unpack_from('<8I', fx, 0)
seg_count = struct.unpack_from('<I', fx, s_off)[0]
segoffs = struct.unpack_from('<%dI' % seg_count, fx, s_off + 4)
chains = 0
for k, so in enumerate(segoffs):
    if so == 0:
        continue
    b = s_off + so
    sz_, psz, pfmt, segoff, maxvp, pc = struct.unpack_from('<IHHQIH', fx, b)
    if pfmt != 12:
        sys.exit('seg[%d] pointer_format=%d（须 12=arm64e auth）' % (k, pfmt))
    if pc < 1:
        sys.exit('seg[%d] page_count=%d（页链为空 = 指针全不绑定）' % (k, pc))
    chains += 1
print('chained fixups: ptr_format=12 ✓  带链段数=%d（每段 page_count≥1 ✓）' % chains)

assert cfo is not None, '没有 __cfstring 节'
bad = plain = auth = 0
for t in range(cfsz // 32):
    rawv = struct.unpack_from('<Q', s, cfo + t * 32)[0]
    if not ((rawv >> 62) & 1):
        bad += 1
        continue
    if (rawv >> 63) & 1:
        auth += 1
        div = (rawv >> 32) & 0xFFFF
        adv = (rawv >> 48) & 1
        key = (rawv >> 49) & 3
        if (div, adv, key) != (0x6AE1, 1, 2):
            bad += 1
            print('  isa[%d] 参数异常 div=%#x adv=%d key=%d' % (t, div, adv, key))
    else:
        plain += 1
print('__cfstring isa: auth=%d plain=%d 异常=%d（须 plain=0 且 bad=0）' % (auth, plain, bad))
assert plain == 0 and bad == 0, 'isa 未全部认证'
PYEOF

# 2.0.4 关键断言：必须导入 MSHookFunction。
grep -q "MSHookFunction" "$DYLIB" || die "dylib 未导入 MSHookFunction —— 加载器不会注入，必须链接 substrate"

# 原生 roothide 关键断言：依赖 @loader_path/.jbroot/usr/lib/libsubstrate.dylib、rpath 空、
# Architecture = iphoneos-arm64e（与 BioProtect 原版同形，不经过转换器）。
grep -q "libsubstrate.dylib" "$DYLIB" || die "dylib 依赖不是 @loader_path/.jbroot/usr/lib/libsubstrate.dylib（原生 roothide 形态）"
grep -q "CydiaSubstrate" "$DYLIB" && die "dylib 仍依赖 @rpath/CydiaSubstrate（rootless 形态，会被转换器改写破坏 PAC）"
[ "$(dpkg-deb -f "$DEB" Architecture)" = "iphoneos-arm64e" ] || die "Architecture 不是 iphoneos-arm64e: $(dpkg-deb -f "$DEB" Architecture)"

# 2.0.5 关键断言：dylib 内不得出现写死的绝对路径。
if grep -q "/var/mobile" "$DYLIB"; then
    echo "!! dylib 内检测到写死路径 /var/mobile："
    strings -a "$DYLIB" | grep "/var/mobile" | head -5
    die "必须改为运行时拼接 —— 转换器会改写字面量路径"
fi

mkdir -p "$OUT"
cp -f "$DEB" "$OUT/com.local.bioprotectleakguard_2.0.13_iphoneos-arm64e.deb"
echo "=== 已复制到 $OUT ==="
md5sum "$OUT/com.local.bioprotectleakguard_2.0.13_iphoneos-arm64e.deb"
md5sum "$DYLIB"
ls -la "$OUT"/*.deb | tail -6
