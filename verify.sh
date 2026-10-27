#!/bin/bash
# 产物校验：解包 → 权限 / 架构 / 关键字符串
set -u
export THEOS="$HOME/theos"
DEB=/mnt/d/WorkBudy/codetest/release/com.local.bioprotectleakguard_2.0.5_iphoneos-arm64.deb
CHK=/mnt/d/WorkBudy/codetest/bioprotect-fix/chk
D="$CHK/var/jb/Library/MobileSubstrate/DynamicLibraries/BioProtectLeakGuard.dylib"

rm -rf "$CHK"; mkdir -p "$CHK"
dpkg-deb -x "$DEB" "$CHK" || exit 1

echo "=== 文件 ==="
find "$CHK" -type f -printf '%M %10s %p\n'
echo "=== md5 ==="
md5sum "$D"
echo "=== 架构 ==="
"$THEOS/toolchain/linux/iphone/bin/lipo" -archs "$D"
echo "=== 关键字符串 ==="
strings -a "$D" | grep -E 'BioProtectLeakGuard 2|LeakGuard|回收|stat ports|CFUserNotification|F_GETPATH' | sort -u | head -20
echo "=== 导入 ==="
"$THEOS/toolchain/linux/iphone/bin/llvm-nm" -u "$D" 2>/dev/null | grep -E 'CFUserNotification|RunLoop|MSHook|_open|_close|mach_port|notify' | sort -u
