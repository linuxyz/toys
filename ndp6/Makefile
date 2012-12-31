# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=neighbor6
PKG_VERSION:=2012-12-30
PKG_RELEASE=$(PKG_SOURCE_VERSION)

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=git://github.com/linuxyz/neighbor6.git
PKG_SOURCE_PROTO:=git
#PKG_SOURCE_VERSION:=

PKG_MAINTAINER:=Yi Zhao <zzlinux AT hotmail DOT com>

PKG_BUILD_DIR:=$(BUILD_DIR)/neighbor6

include $(INCLUDE_DIR)/package.mk

CONFIGURE_ARGS += \
	--with-linux-headers="$(LINUX_DIR)" \

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp ./src/* $(PKG_BUILD_DIR)
endef

define Package/neighbor6/compile
	$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" 
endef

define Package/neighbor6
  SECTION:=ipv6
  CATEGORY:=IPv6
  TITLE:=IPv6 neighborhood helper (RA, Route and NDP-Proxy register)
  DEPENDS:=+kmod-ipv6
endef

define Package/neighbor6/description
 neighbor5 is a lightweight router advertisement daemon. 
 It makes the router as a IPv6 router by discovery the LAN IPv6 addresses, 
 register the NDP proxy and route data into routers. 
 This is useful to avoid NAT in chained IPv6-routers.

endef

define Package/neighbor6/install
$(INSTALL_DIR) $(1)/usr/sbin/
$(INSTALL_BIN) $(PKG_BUILD_DIR)/neighbor6 $(1)/usr/sbin/
$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
$(INSTALL_DATA) ./files/neighbor6.hotplug $(1)/etc/hotplug.d/iface/30-neighbor6
$(INSTALL_DIR) $(1)/etc/init.d
$(INSTALL_BIN) ./files/neighbor6.init $(1)/etc/init.d/neighbor6
endef

$(eval $(call BuildPackage,neighbor6))

