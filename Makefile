# Copyright (C) 2022 yaott

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-bypass2ray
PKG_VERSION:=1.0
PKG_RELEASE:=2

PKG_CONFIG_DEPENDS:= \
	CONFIG_PACKAGE_$(PKG_NAME)_Transparent_Proxy

LUCI_TITLE:=LuCI support for ByPass2Ray
LUCI_PKGARCH:=all
LUCI_DEPENDS:=+coreutils +coreutils-base64 +coreutils-nohup +curl \
	+ip-full +libuci-lua +lua +luci-compat +luci-lib-jsonc +resolveip \
	+dnsmasq-full +ipset +iptables +iptables-legacy +iptables-mod-iprange \
	+iptables-mod-socket +iptables-mod-tproxy +kmod-ipt-nat +sudo

define Package/$(PKG_NAME)/conffiles
/etc/config/bypass2ray
endef

define Package/$(PKG_NAME)/postinst
#!/bin/sh
chmod 0755 "$${IPKG_INSTROOT}/etc/init.d/bypass2ray" >/dev/null 2>&1
chmod 0755 "$${IPKG_INSTROOT}/usr/share/bypass2ray/*" >/dev/null 2>&1
exit 0
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
