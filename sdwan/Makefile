include $(TOPDIR)/rules.mk

PKG_NAME:=sdwan
PKG_VERSION:=25.9.10

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

define Package/$(PKG_NAME)
	SECTION:=net
	CATEGORY:=Network
	TITLE:=A simple, decentralized mesh VPN with WireGuard support.
	DEPENDS:=@(x86_64||arm||aarch64||mipsel||mips) +kmod-tun
	URL:=https://github.com/zzxym/sdwan
endef
define Package/$(PKG_NAME)/description
  A simple, decentralized mesh VPN with WireGuard support.
endef

define Build/Prepare
	[ ! -f $(PKG_BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION).zip ] && wget https://github.com/zzxym/sdwan/releases/download/v$(PKG_VERSION)/$(PKG_NAME)-linux-$(APP_ARCH)-v$(PKG_VERSION).zip -O $(PKG_NAME)-$(PKG_VERSION).zip
	unzip -j $(PKG_NAME)-$(PKG_VERSION).zip -d $(PKG_BUILD_DIR)
endef

define Build/Compile
endef

define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sdwan-core $(1)/usr/bin/sdwan-core
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sdwan-cli $(1)/usr/bin/sdwan-cli
	[ "$(APP_ARCH)" != "mips" ] && [ "$(APP_ARCH)" != "mipsel" ] && $(INSTALL_BIN) $(PKG_BUILD_DIR)/sdwan-web-embed $(1)/usr/bin/sdwan-web || true
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
