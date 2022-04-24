# Copyright (C) 2022 yaott

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-bypass2ray
PKG_VERSION:=1.1
PKG_RELEASE:=3

PKG_CONFIG_DEPENDS:= \
	CONFIG_PACKAGE_$(PKG_NAME)_Transparent_Proxy

LUCI_TITLE:=LuCI support for ByPass2Ray
LUCI_PKGARCH:=all
LUCI_DEPENDS:=+coreutils +coreutils-base64 +coreutils-nohup +curl \
	+ip-full +libuci-lua +lua +luci-compat +luci-lib-jsonc +resolveip +sudo +tcping

define Package/$(PKG_NAME)/config
menu "Configuration"

config PACKAGE_$(PKG_NAME)_Transparent_Proxy
	bool "Transparent Proxy"
	select PACKAGE_dnsmasq-full
	select PACKAGE_ipset
	select PACKAGE_iptables
	select PACKAGE_iptables-legacy
	select PACKAGE_iptables-mod-iprange
	select PACKAGE_iptables-mod-socket
	select PACKAGE_iptables-mod-tproxy
	select PACKAGE_kmod-ipt-nat
	default y

endmenu
endef

define Package/$(PKG_NAME)/conffiles
/etc/config/bypass2ray
endef

define Package/$(PKG_NAME)/postinst
#!/bin/sh
chmod 0755 "$${IPKG_INSTROOT}/etc/init.d/bypass2ray" >/dev/null 2>&1
chmod 0755 "$${IPKG_INSTROOT}/usr/share/bypass2ray/app.sh" >/dev/null 2>&1
exit 0
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
