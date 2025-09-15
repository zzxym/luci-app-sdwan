
#
# Copyright (C) 2024 OpenWrt.org
#

PKG_NAME:=sdwan
PKG_VERSION:=25.9.10

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk

# 定义ARCH到APP_ARCH的映射
ifeq ($(ARCH),mipsel)	APP_ARCH:=mipsel
endif
ifeq ($(ARCH),mips)	APP_ARCH:=mips
endif
ifeq ($(ARCH),arm)	APP_ARCH:=arm
endif
ifeq ($(BOARD),kirkwood)	APP_ARCH:=arm
endif
ifeq ($(ARCH),armv7)	APP_ARCH:=armv7
endif
ifeq ($(ARCH),aarch64)	APP_ARCH:=aarch64
endif
ifeq ($(ARCH),arm64)	APP_ARCH:=aarch64
endif
ifeq ($(ARCH),armv8)	APP_ARCH:=aarch64
endif
ifeq ($(ARCH),x86_64)	APP_ARCH:=x86_64
endif

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

# 确保PKG_BUILD_DIR存在
$(PKG_BUILD_DIR):
	mkdir -p $@

define Package/sdwan
	SECTION:=net
	CATEGORY:=Network
	TITLE:=A simple, decentralized mesh VPN with WireGuard support.
	DEPENDS:=@(x86_64||arm||aarch64||mipsel||mips) +kmod-tun
	URL:=https://github.com/zzxym/sdwan
endef

define Package/sdwan/description
  A simple, decentralized mesh VPN with WireGuard support.
endef

define Build/Prepare
	# 使用本仓库zip目录下的zip文件
	# 检查多个可能的zip文件路径
	# 1. 首先检查标准feeds路径
	if [ -d "$(TOPDIR)/feeds/packages_ci/sdwan/zip/" ]; then
		ZIP_PATH="$(TOPDIR)/feeds/packages_ci/sdwan/zip/"
	elif [ -d "$(CURDIR)/../../zip/" ]; then
		# 2. 检查项目根目录下的zip目录
		ZIP_PATH="$(CURDIR)/../../zip/"
	elif [ -d "$(TOPDIR)/../zip/" ]; then
		# 3. 检查SDK目录上层的zip目录
		ZIP_PATH="$(TOPDIR)/../zip/"
	else
		echo "错误：找不到zip文件目录，请确保在正确的构建环境中" >&2
		exit 1
	fi
	
	# 尝试多种文件名格式
	ZIP_FOUND:=0
	# 格式1: sdwan-linux-ARCH-VERSION.zip
	if [ -f "$${ZIP_PATH}$(PKG_NAME)-linux-$(APP_ARCH)-$(PKG_VERSION).zip" ]; then
		cp -f "$${ZIP_PATH}$(PKG_NAME)-linux-$(APP_ARCH)-$(PKG_VERSION).zip" $(PKG_NAME)-$(PKG_VERSION).zip
		ZIP_FOUND:=1
	fi
	# 格式2: sdwan-linux-ARCH-vVERSION.zip
	if [ $${ZIP_FOUND} -eq 0 ] && [ -f "$${ZIP_PATH}$(PKG_NAME)-linux-$(APP_ARCH)-v$(PKG_VERSION).zip" ]; then
		cp -f "$${ZIP_PATH}$(PKG_NAME)-linux-$(APP_ARCH)-v$(PKG_VERSION).zip" $(PKG_NAME)-$(PKG_VERSION).zip
		ZIP_FOUND:=1
	fi
	# 格式3: sdwan-ARCH.zip (简化格式)
	if [ $${ZIP_FOUND} -eq 0 ] && [ -f "$${ZIP_PATH}$(PKG_NAME)-$(APP_ARCH).zip" ]; then
		cp -f "$${ZIP_PATH}$(PKG_NAME)-$(APP_ARCH).zip" $(PKG_NAME)-$(PKG_VERSION).zip
		ZIP_FOUND:=1
	fi
	
	# 如果没有找到zip文件，报错
	if [ $${ZIP_FOUND} -eq 0 ]; then
		echo "错误：找不到zip文件。已尝试以下路径和格式：" >&2
		echo "  1. $${ZIP_PATH}$(PKG_NAME)-linux-$(APP_ARCH)-$(PKG_VERSION).zip" >&2
		echo "  2. $${ZIP_PATH}$(PKG_NAME)-linux-$(APP_ARCH)-v$(PKG_VERSION).zip" >&2
		echo "  3. $${ZIP_PATH}$(PKG_NAME)-$(APP_ARCH).zip" >&2
		exit 1
	fi
	
	# 解压文件
	unzip -j $(PKG_NAME)-$(PKG_VERSION).zip -d $(PKG_BUILD_DIR)
endef

define Build/Compile
	# 这个包是预编译的二进制包，不需要额外编译步骤
endef

define Package/sdwan/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sdwan-core $(1)/usr/bin/sdwan-core
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sdwan-cli $(1)/usr/bin/sdwan-cli
	# 只在非mips架构上安装web组件
	[ "$(APP_ARCH)" != "mips" ] && [ "$(APP_ARCH)" != "mipsel" ] && $(INSTALL_BIN) $(PKG_BUILD_DIR)/sdwan-web-embed $(1)/usr/bin/sdwan-web || true
endef

# 确保使用正确的构建包宏
$(eval $(call BuildPackage,sdwan))
