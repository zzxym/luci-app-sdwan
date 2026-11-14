include $(TOPDIR)/rules.mk
-include $(dir $(lastword $(MAKEFILE_LIST)))../version.mk

PKG_NAME:=sdwan
PKG_VERSION:=$(or $(SDWAN_VERSION),2.6.4)

# Self-hosted release channel; override with SDWAN_RELEASE_BASE_URL when building.
RELEASE_BASE_URL:=$(or $(SDWAN_RELEASE_BASE_URL),https://github.com/zzxym/sdwan)
# Release tag / asset suffix; override with SDWAN_RELEASE_TAG.
RELEASE_TAG:=$(or $(SDWAN_RELEASE_TAG),sdwan-v$(PKG_VERSION))
# Resolve the download base at make level. Shell variables in Build/Prepare get
# expanded twice by OpenWrt, which eats the leading character of $RELEASE_BASE_URL.
ifneq (,$(filter https://github.com/%,$(RELEASE_BASE_URL)))
RELEASE_DOWNLOAD_BASE:=$(RELEASE_BASE_URL)/releases/download
else
RELEASE_DOWNLOAD_BASE:=$(RELEASE_BASE_URL)
endif

ifeq ($(ARCH),mipsel)
	APP_ARCH:=mipsel
endif
ifeq ($(ARCH),mips)
	APP_ARCH:=mips
endif
ifeq ($(ARCH),arm)
	APP_ARCH:=arm
endif
ifeq ($(BOARD),kirkwood)
	APP_ARCH:=arm
endif
ifeq ($(ARCH),armv7)
	APP_ARCH:=armv7
endif
ifeq ($(ARCH),aarch64)
	APP_ARCH:=aarch64
endif
ifeq ($(ARCH),arm64)
	APP_ARCH:=aarch64
endif
ifeq ($(ARCH),armv8)
	APP_ARCH:=aarch64
endif
ifeq ($(ARCH),x86_64)
	APP_ARCH:=x86_64
endif

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

RSTRIP:=:

define Package/$(PKG_NAME)
	SECTION:=net
	CATEGORY:=Network
	TITLE:=A simple, decentralized mesh VPN with WireGuard support.
	DEPENDS:=@(x86_64||arm||aarch64||mipsel||mips) +kmod-tun
	URL:=https://github.com/zzxym/luci-app-sdwan
	MENU:=1
endef

define Package/$(PKG_NAME)/description
  A simple, decentralized mesh VPN with WireGuard support.
endef

define Package/$(PKG_NAME)/config
	config SDWAN_INCLUDE_WEBCONSOLE
		bool "Include Web Console (sdwan-web)"
		depends on PACKAGE_$(PKG_NAME)
		depends on !(mips || mipsel)
		default y
		help
		  Install the sdwan-web web console.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	if [ ! -f $(PKG_BUILD_DIR)/sdwan-core ]; then \
		wget "$(RELEASE_DOWNLOAD_BASE)/$(RELEASE_TAG)/sdwan-linux-$(APP_ARCH)-$(RELEASE_TAG).zip" -O $(PKG_BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION).zip || exit 1; \
		unzip -o -j $(PKG_BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION).zip -d $(PKG_BUILD_DIR) || exit 1; \
		rm -f $(PKG_BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION).zip; \
	fi
endef

define Build/Compile
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_BUILD_DIR)/sdwan-core $(1)/usr/bin/sdwan-core
	chmod 0755 $(1)/usr/bin/sdwan-core
	$(CP) $(PKG_BUILD_DIR)/sdwan-cli $(1)/usr/bin/sdwan-cli
	chmod 0755 $(1)/usr/bin/sdwan-cli
ifdef CONFIG_SDWAN_INCLUDE_WEBCONSOLE
	$(CP) $(PKG_BUILD_DIR)/sdwan-web-embed $(1)/usr/bin/sdwan-web
	chmod 0755 $(1)/usr/bin/sdwan-web
endif
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
