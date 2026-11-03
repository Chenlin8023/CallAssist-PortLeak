ARCHS = arm64 arm64e
TARGET = iphone:clang:16.5:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

# 原生 roothide 包：安装前缀为空（layout 不带 /var/jb），与 BioProtect 4.6-roothide 原版同形。
# RootHide 环境下直接安装，不经过转换器 → arm64e 的 PAC 认证不被破坏。
THEOS_PACKAGE_INSTALL_PREFIX =

TWEAK_NAME = CallAssistLeakGuard

CallAssistLeakGuard_FILES = CallAssistLeakGuard.xm
CallAssistLeakGuard_FRAMEWORKS = Foundation CoreFoundation
# 链接 roothide 版 substrate stub：install-name = @loader_path/.jbroot/usr/lib/libsubstrate.dylib
# （不用 @rpath/CydiaSubstrate，那是 rootless 形态，转换器会改写）
CallAssistLeakGuard_LDFLAGS = -L$(THEOS_PROJECT_DIR) -lsubstrate_roothide
CallAssistLeakGuard_CFLAGS = -fobjc-arc -Wall -Wno-unused-function -Wno-unused-variable
CallAssistLeakGuard_OBJCCFLAGS = -fno-modules

include $(THEOS_MAKE_PATH)/tweak.mk
