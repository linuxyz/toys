# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
#include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=tunet
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/tunet

include $(INCLUDE_DIR)/package.mk

define Package/tunet
  SECTION:=net
  CATEGORY:=Base system
  TITLE:=Tsinghua University Network Login Client
endef

define Package/tunet/description
 Manage the login account of Tsinghua University network access
 form any PC.
endef

CONFIGURE_ARGS += \
	--with-linux-headers="$(LINUX_DIR)" \

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp ./src/* $(PKG_BUILD_DIR)
endef

define Package/tunet/compile
	$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" 
endef

define Package/tunet/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tunet $(1)/usr/bin/
endef

$(eval $(call BuildPackage,tunet))
