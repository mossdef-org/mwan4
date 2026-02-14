# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 MOSSDeF, Stan Grishin (stangri@melmac.ca).
# Based on original mwan3 by Florian Eckert <fe@dev.tdt.de>

include $(TOPDIR)/rules.mk

PKG_NAME:=mwan4
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=AGPL-3.0-or-later
PKG_MAINTAINER:=Stan Grishin <stangri@melmac.ca>

include $(INCLUDE_DIR)/package.mk

define Package/mwan4
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=Multiwan with nftables support
  URL:=https://github.com/mossdef-org/mwan4/
  PKGARCH:=all
  CONFLICTS:=mwan3
  DEPENDS:= \
    +ip-full \
    +jshn \
    +jsonfilter \
    +resolveip \
    +!BUSYBOX_DEFAULT_AWK:gawk \
    +!BUSYBOX_DEFAULT_GREP:grep \
    +!BUSYBOX_DEFAULT_SED:sed \
    +!BUSYBOX_DEFAULT_PING:iputils-ping \
    +kmod-nft-core \
    +kmod-nft-nat \
    +nftables-json \
    +rpcd-mod-ucode
  SUGGESTS:= \
    iputils-arping \
    httping \
    nping
endef

define Package/mwan4/description
  Multiwan hotplug script with connection tracking support using nftables.
  Supports loadbalancing/failover for up to 254 WAN interfaces with
  firewall4/nftables integration.
endef

define Package/mwan4/conffiles
/etc/config/mwan4
/etc/mwan4.user
endef

define Build/Configure
endef

define Build/Compile
	$(TARGET_CC) $(CFLAGS) $(LDFLAGS) $(FPIC) \
		-shared \
		-o $(PKG_BUILD_DIR)/libwrap_mwan4_sockopt.so.1.0 \
		-DCONFIG_IPV6 \
		$(PKG_BUILD_DIR)/sockopt_wrap.c \
		-ldl
endef

define Package/mwan4/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/mwan4 \
		$(1)/etc/config/

	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_DATA) ./files/etc/hotplug.d/iface/15-mwan4 \
		$(1)/etc/hotplug.d/iface/
	$(INSTALL_DATA) ./files/etc/hotplug.d/iface/16-mwan4-user \
		$(1)/etc/hotplug.d/iface/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/mwan4 \
		$(1)/etc/init.d/
	$(SED) "s|^\(readonly PKG_VERSION\).*|\1='$(PKG_VERSION)-r$(PKG_RELEASE)'|" $(1)/etc/init.d/mwan4

	$(INSTALL_DIR) $(1)/lib/mwan4
	$(INSTALL_DATA) ./files/lib/mwan4/common.sh \
		$(1)/lib/mwan4/
	$(INSTALL_DATA) ./files/lib/mwan4/mwan4.sh \
		$(1)/lib/mwan4/

	$(INSTALL_DIR) $(1)/usr/share/rpcd/ucode/
	$(INSTALL_BIN) ./files/usr/share/rpcd/ucode/mwan4 \
		$(1)/usr/share/rpcd/ucode/

	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/usr/sbin/mwan4 \
		$(1)/usr/sbin/
	$(INSTALL_BIN) ./files/usr/sbin/mwan4rtmon \
		$(1)/usr/sbin/
	$(INSTALL_BIN) ./files/usr/sbin/mwan4track \
		$(1)/usr/sbin/

	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_BIN) ./files/etc/mwan4.user \
		$(1)/etc/

	$(CP) $(PKG_BUILD_DIR)/libwrap_mwan4_sockopt.so.1.0 $(1)/lib/mwan4/

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/90-mwan4 \
		$(1)/etc/uci-defaults/
	$(INSTALL_BIN) ./files/etc/uci-defaults/91-mwan4-nft \
		$(1)/etc/uci-defaults/
	$(INSTALL_BIN) ./files/etc/uci-defaults/92-mwan4-rename \
		$(1)/etc/uci-defaults/
endef

define Package/mwan4/postinst
#!/bin/sh
# check if we are on real system
if [ -z "$${IPKG_INSTROOT}" ]; then
	echo -n "Installing rc.d symlink for mwan4... "
	/etc/init.d/mwan4 enable && echo "OK" || echo "FAIL"
	/etc/init.d/rpcd restart >/dev/null 2>&1
fi
exit 0
endef

define Package/mwan4/prerm
#!/bin/sh
# check if we are on real system
if [ -z "$${IPKG_INSTROOT}" ]; then
	echo -n "Stopping mwan4 service... "
	/etc/init.d/mwan4 stop >/dev/null 2>&1 && echo "OK" || echo "FAIL"
	echo -n "Removing rc.d symlink for mwan4... "
	/etc/init.d/mwan4 disable && echo "OK" || echo "FAIL"
fi
exit 0
endef

define Package/mwan4/postrm
#!/bin/sh
# check if we are on real system
if [ -z "$${IPKG_INSTROOT}" ]; then
	fw4 -q reload || true
	/etc/init.d/rpcd restart >/dev/null 2>&1
fi
exit 0
endef

$(eval $(call BuildPackage,mwan4))
