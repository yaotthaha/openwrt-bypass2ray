include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-bypass2ray
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

LUCI_TITLE:=LuCI support for bypass2ray
LUCI_DEPENDS:=
LUCI_PKGARCH:=all

define Package/$(PKG_NAME)/conffiles
/etc/config/bypass2ray
endef

include $(TOPDIR)/feeds/luci/luci.mk

define Package/$(PKG_NAME)/postinst
chmod 0755 "$${IPKG_INSTROOT}/etc/init.d/bypass2ray" >/dev/null 2>&1
chmod 0755 "$${IPKG_INSTROOT}/usr/share/bypass2ray/*" >/dev/null 2>&1
exit 0
endef