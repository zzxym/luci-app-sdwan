#
# Copyright (C) 2008-2014 The LuCI Team <luci@lists.subsignal.org>
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk
-include $(dir $(lastword $(MAKEFILE_LIST)))../version.mk

PKG_VERSION:=$(or $(SDWAN_VERSION),2.6.4)
PKG_RELEASE:=1

LUCI_TITLE:=LuCI support for SDWAN
# 不强制依赖核心包：sdwan 与 sdwan-noweb 都会安装 /usr/bin/sdwan-core，二者互斥，
# 强制依赖会让安装顺序受限。本包的 init.d 在缺少核心程序时会自动在线下载，
# 因此先装本包再装核心包、先装核心包再装本包都可以。
LUCI_DEPENDS:=+kmod-tun +luci-compat
LUCI_PKGARCH:=all

PKG_NAME:=luci-app-sdwan

define Package/$(PKG_NAME)/conffiles
/etc/config/sdwan
/etc/sdwan/
endef

define Package/$(PKG_NAME)/prerm
#!/bin/sh
if [ -f /etc/config/sdwan ] ; then
  echo "备份luci配置文件/etc/config/sdwan到/tmp/sdwan_backup"
  echo "不重启设备之前再次安装luci-app-sdwan 配置不丢失,无需重新配置"
  cp -rf /etc/config/sdwan /tmp/sdwan_backup
fi

if ls /etc/sdwan/* >/dev/null 2>&1; then
  echo "备份sdwan配置目录/etc/sdwan到/tmp/sdwan_config_backup"
  echo "不重启设备之前再次安装luci-app-sdwan 配置不丢失,无需重新配置"
  cp -rf /etc/sdwan /tmp/sdwan_config_backup
fi

endef

define Package/$(PKG_NAME)/postinst
#!/bin/sh
chmod +x /etc/init.d/sdwan
if [ -f /tmp/sdwan_backup ] ; then
  echo "发现luci备份配置文件/tmp/sdwan_backup，开始恢复到/etc/config/sdwan"
  rm -rf /etc/config/sdwan
  mv -f /tmp/sdwan_backup /etc/config/sdwan
  echo "请前往 VPN - SDWAN 界面进行重启插件"
fi
if [ -d /tmp/sdwan_config_backup ] ; then
  echo "发现sdwan备份配置目录/tmp/sdwan_config_backup，开始恢复到/etc/sdwan"
  rm -rf /etc/sdwan
  mv -f /tmp/sdwan_config_backup /etc/sdwan
  echo "请前往 VPN - SDWAN 界面进行重启插件"
fi
# 恢复的配置可能开启了自建 Web 控制台，但当前安装的核心包不一定带 Web 控制台
# （sdwan-noweb 不包含 sdwan-web）。此时关闭该开关，避免启动时触发不必要的在线下载。
# 注意：Makefile 中 shell 的命令替换必须写成 $$(...) ，否则会被 make 提前展开。
webbin="$$(uci -q get sdwan.@sdwan[0].webbin)"
[ -z "$$webbin" ] && webbin="/usr/bin/sdwan-web"
if [ "$$(uci -q get sdwan.@sdwan[0].web_enabled)" = "1" ] && [ ! -f "$$webbin" ] && [ ! -f /tmp/sdwan-web-embed ] ; then
  echo "未找到$${webbin}，已关闭自建 Web 控制台（安装 sdwan 包或从上传程序页面上传 sdwan-web-embed 后可重新开启）"
  uci -q set sdwan.@sdwan[0].web_enabled='0'
  uci commit sdwan
fi
exit 0
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
