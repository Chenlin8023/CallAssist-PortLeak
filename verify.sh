#!/bin/bash
# 产物校验：解包 → 权限 / 架构 / 关键字符串
#   用法: bash verify.sh [deb路径]   缺省校验 release/ 里的 2.1.0 包
set -u
export THEOS="$HOME/theos"
DEB="${1:-/mnt/d/WorkBudy/iOS-Tweaks/release/com.local.callassistleakguard_2.1.0_iphoneos-arm64e.deb}"
CHK="$HOME/bplg_verify"
[ -f "$DEB" ] || { echo "!! 找不到 $DEB"; exit 1; }

rm -rf "$CHK"; mkdir -p "$CHK"
dpkg-deb -x "$DEB" "$CHK" || exit 1
D=$(find "$CHK" -name "CallAssistLeakGuard.dylib" | head -1)
[ -n "$D" ] || { echo "!! 包里没有 CallAssistLeakGuard.dylib"; find "$CHK" -type f; exit 1; }

echo "=== 文件 ==="
find "$CHK" -type f -printf '%M %10s %p\n'
echo "=== md5 ==="
md5sum "$D"
echo "=== 架构 ==="
"$THEOS/toolchain/linux/iphone/bin/lipo" -archs "$D" 2>/dev/null || lipo -archs "$D" 2>/dev/null
echo "=== 关键字符串 ==="
strings -a "$D" | grep -E 'CallAssistLeakGuard [0-9]|LeakGuard|回收|stat ports|powerdxpc|F_GETPATH' | sort -u | head -20
echo "=== 导入 ==="
"$THEOS/toolchain/linux/iphone/bin/llvm-nm" -u "$D" 2>/dev/null | grep -E 'CFUserNotification|RunLoop|MSHook|_open|_close|mach_port|notify' | sort -u
echo "=== 原生 roothide 断言 ==="
grep -q "libsubstrate.dylib" "$D" && echo "substrate 依赖: @loader_path/.jbroot 形态 ✓" || echo "!! 缺 roothide substrate 依赖"
grep -q "CydiaSubstrate" "$D" && echo "!! 仍是 rootless CydiaSubstrate 形态" || echo "无 rootless 残留 ✓"
