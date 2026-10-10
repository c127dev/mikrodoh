# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Johan Alvarado

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI support for MikroDoH
LUCI_DEPENDS:=+luci-base +mikrodoh
LUCI_PKGARCH:=all

PKG_VERSION:=2026.10.09
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=Johan Alvarado <contact@c127.dev>

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
