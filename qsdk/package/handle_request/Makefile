include $(TOPDIR)/rules.mk

PKG_NAME:=handle_request
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk


define Package/$(PKG_NAME)
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=Json Handler - a demonstration package
	DEPENDS:=+libc +libjson-c
endef

define Package/$(PKG_NAME)/description
	A simple Json Handler application as a demonstration.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef


define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_CPPFLAGS) \
		-I$(STAGING_DIR)/usr/include/json-c \
		-o $(PKG_BUILD_DIR)/json_handle.cgi \
		$(PKG_BUILD_DIR)/handle_request.c \
		-L$(STAGING_DIR)/usr/lib -ljson-c
endef


define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/www/cgi-bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/json_handle.cgi $(1)/www/cgi-bin/
endef


$(eval $(call BuildPackage,$(PKG_NAME)))
