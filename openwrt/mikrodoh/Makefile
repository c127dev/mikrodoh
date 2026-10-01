# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Johan Alvarado

include $(TOPDIR)/rules.mk

PKG_NAME:=mikrodoh
PKG_VERSION:=2026.09.23
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/c127dev/mikrodoh.git
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_MIRROR_HASH:=skip

PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Johan Alvarado <contact@c127.dev>

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

CMAKE_OPTIONS += -DMIKRODOH_SMALL=ON

define Package/mikrodoh
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=IP Addresses and Names
  TITLE:=Lightweight DNS-over-HTTPS proxy
  URL:=https://github.com/c127dev/mikrodoh
  DEPENDS:=+libcurl +libstdcpp +LIBCURL_NGHTTP2:libnghttp2
endef

define Package/mikrodoh/description
  DNS over UDP/TCP to DNS-over-HTTPS proxy with caching, failover,
  rate limiting and a seccomp sandbox. libcurl needs HTTP/2
  (LIBCURL_NGHTTP2) to multiplex queries on one connection.
endef

define Package/mikrodoh/conffiles
/etc/config/mikrodoh
endef

define Package/mikrodoh/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/mikrodoh $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/mikrodoh.init $(1)/etc/init.d/mikrodoh
	$(INSTALL_CONF) ./files/mikrodoh.config $(1)/etc/config/mikrodoh
endef

$(eval $(call BuildPackage,mikrodoh))
