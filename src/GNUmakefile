# non-recursive prologue
sp := $(sp).x
dirstack_$(sp) := $(d)
d := $(abspath $(lastword $(MAKEFILE_LIST))/..)

ifeq ($(origin GUARD_$(d)), undefined)
GUARD_$(d) := 1


#
# E N V I R O N M E N T  C O N F I G U R A T I O N
#
include $(d)/../GNUmakefile


#
# C O M P I L A T I O N  F L A G S
#
CPPFLAGS_$(d) = $(ALL_CPPFLAGS) -DHAVE_CONFIG_H -DCOMPAT53_PREFIX=luaossl
CFLAGS_$(d) = $(ALL_CFLAGS)
SOFLAGS_$(d) = $(ALL_SOFLAGS)
LDFLAGS_$(d) = $(ALL_LDFLAGS)
LIBS_$(d) = $(ALL_LIBS)

#
# C O M P I L A T I O N  R U L E S
#
OBJS_$(d) = openssl.o

$(d)/config.h: $(abspath $(d)/..)/config.h
	$(CP) $< $@

define BUILD_$(d)

$$(d)/$(1)/openssl.so: $$(addprefix $$(d)/$(1)/, $$(OBJS_$(d)))
	$$(CC) -o $$@ $$^ $$(SOFLAGS_$$(abspath $$(@D)/..)) $$(LDFLAGS_$$(abspath $$(@D)/..)) $$(LIBS_$$(abspath $$(@D)/..))

$$(d)/$(1)/%.o: $$(d)/%.c $$(d)/config.h
	$$(MKDIR) -p $$(@D)
	$$(CC) $$(CFLAGS_$$(<D)) $$(ALL_LUA$(subst .,,$(1))_CPPFLAGS) $$(CPPFLAGS_$$(<D)) -c -o $$@ $$<

ifneq ($(1), 5.3)
$$(d)/$(1)/compat53.o: $$(d)/../vendor/compat53/c-api/compat-5.3.c $$(d)/../vendor/compat53/c-api/compat-5.3.h $$(d)/config.h
	$$(MKDIR) -p $$(@D)
	$$(CC) $$(CFLAGS_$(d)) $$(ALL_LUA$(subst .,,$(1))_CPPFLAGS) $$(CPPFLAGS_$(d)) -c -o $$@ $$<

$$(d)/$(1)/%.o: $$(d)/../vendor/compat53/c-api/compat-5.3.h

$$(d)/$(1)/openssl.so: $$(d)/$(1)/compat53.o
endif

.SECONDARY: liblua$(1)-openssl openssl$(1) openssl

liblua$(1)-openssl openssl$(1) openssl: $$(d)/$(1)/openssl.so

endef # BUILD_$(d)

$(eval $(call BUILD_$(d),5.1))
$(eval $(call BUILD_$(d),5.2))
$(eval $(call BUILD_$(d),5.3))

ifneq "$(filter $(abspath $(d)/..)/%, $(abspath $(firstword $(MAKEFILE_LIST))))" ""
.SECONDARY: all all5.1 all5.2 all5.3

all5.1: liblua5.1-openssl
all5.2: liblua5.2-openssl
all5.3: liblua5.3-openssl
all: $(foreach API,$(strip $(LUA_APIS)),all$(API))

endif


#
# I N S T A L L  &  U N I N S T A L L  R U L E S
#
define INSTALL_$(d)

MODS$(1)_$(d) = \
	$$(DESTDIR)$(2)/_openssl.so \
	$$(DESTDIR)$(3)/openssl.lua \
	$$(DESTDIR)$(3)/openssl/auxlib.lua \
	$$(DESTDIR)$(3)/openssl/bignum.lua \
	$$(DESTDIR)$(3)/openssl/ocsp/basic.lua \
	$$(DESTDIR)$(3)/openssl/ocsp/response.lua \
	$$(DESTDIR)$(3)/openssl/pkey.lua \
	$$(DESTDIR)$(3)/openssl/pubkey.lua \
	$$(DESTDIR)$(3)/openssl/x509.lua \
	$$(DESTDIR)$(3)/openssl/x509/name.lua \
	$$(DESTDIR)$(3)/openssl/x509/altname.lua \
	$$(DESTDIR)$(3)/openssl/x509/chain.lua \
	$$(DESTDIR)$(3)/openssl/x509/crl.lua \
	$$(DESTDIR)$(3)/openssl/x509/csr.lua \
	$$(DESTDIR)$(3)/openssl/x509/extension.lua \
	$$(DESTDIR)$(3)/openssl/x509/store.lua \
	$$(DESTDIR)$(3)/openssl/x509/verify_param.lua \
	$$(DESTDIR)$(3)/openssl/pkcs12.lua \
	$$(DESTDIR)$(3)/openssl/ssl/context.lua \
	$$(DESTDIR)$(3)/openssl/ssl.lua \
	$$(DESTDIR)$(3)/openssl/digest.lua \
	$$(DESTDIR)$(3)/openssl/hmac.lua \
	$$(DESTDIR)$(3)/openssl/cipher.lua \
	$$(DESTDIR)$(3)/openssl/rand.lua \
	$$(DESTDIR)$(3)/openssl/des.lua

.SECONDARY: liblua$(1)-openssl-install openssl$(1)-install

liblua$(1)-openssl-install openssl$(1)-install: $$(MODS$(1)_$$(d))

$$(DESTDIR)$(2)/_openssl.so: $$(d)/$(1)/openssl.so
	$$(MKDIR) -p $$(@D)
	$$(CP) -p $$< $$@

$$(DESTDIR)$(3)/%.lua: $$(d)/%.lua
	$$(LUAC$(subst .,,$(1))) -p $$<
	$$(MKDIR) -p $$(@D)
	$$(CP) -p $$< $$@

$$(DESTDIR)$(3)/openssl/%.lua: $$(d)/openssl.%.lua
	$$(LUAC$(subst .,,$(1))) -p $$<
	$$(MKDIR) -p $$(@D)
	$$(CP) -p $$< $$@

$$(DESTDIR)$(3)/openssl/ocsp/%.lua: $$(d)/openssl.ocsp.%.lua
	$$(LUAC$(subst .,,$(1))) -p $$<
	$$(MKDIR) -p $$(@D)
	$$(CP) -p $$< $$@

$$(DESTDIR)$(3)/openssl/x509/%.lua: $$(d)/openssl.x509.%.lua
	$$(LUAC$(subst .,,$(1))) -p $$<
	$$(MKDIR) -p $$(@D)
	$$(CP) -p $$< $$@

$$(DESTDIR)$(3)/openssl/ssl/%.lua: $$(d)/openssl.ssl.%.lua
	$$(LUAC$(subst .,,$(1))) -p $$<
	$$(MKDIR) -p $$(@D)
	$$(CP) -p $$< $$@

liblua$(1)-openssl-install openssl$(1)-install: $$(MODS$(1)_$$(d))

.PHONY: liblua$(1)-openssl-uninstall openssl$(1)-uninstall

liblua$(1)-openssl-uninstall openssl$(1)-uninstall:
	$$(RM) -f $$(MODS$(1)_$(d))
	-$$(RMDIR) $$(DESTDIR)$(3)/openssl/ocsp
	-$$(RMDIR) $$(DESTDIR)$(3)/openssl/x509
	-$$(RMDIR) $$(DESTDIR)$(3)/openssl/ssl
	-$$(RMDIR) $$(DESTDIR)$(3)/openssl

endef # INSTALL_$(d)

$(eval $(call INSTALL_$(d),5.1,$$(lua51cpath),$$(lua51path)))
$(eval $(call INSTALL_$(d),5.2,$$(lua52cpath),$$(lua52path)))
$(eval $(call INSTALL_$(d),5.3,$$(lua53cpath),$$(lua53path)))

ifneq "$(filter $(abspath $(d)/..)/%, $(abspath $(firstword $(MAKEFILE_LIST))))" ""

.SECONDARY: install5.1 install5.2 install5.3 install

install5.1: liblua5.1-openssl-install
install5.2: liblua5.2-openssl-install
install5.3: liblua5.3-openssl-install
install: $(foreach API,$(strip $(LUA_APIS)),install$(API))

.PHONY: uninstall5.1 uninstall5.2 uninstall5.3 uninstall

uninstall5.1: liblua5.1-openssl-uninstall
uninstall5.2: liblua5.2-openssl-uninstall
uninstall5.3: liblua5.3-openssl-uninstall
uninstall: $(foreach API,$(strip $(LUA_APIS)),uninstall$(API))

endif


#
# C L E A N  R U L E S
#
.PHONY: $(d)/clean $(d)/clean~ clean clean~

$(d)/clean:
	$(RM) -fr $(@D)/config.h $(@D)/*.dSYM $(@D)/5.1 $(@D)/5.2 $(@D)/5.3

$(d)/clean~: $(d)/clean
	$(RM) -f $(@D)/*~

clean: $(d)/clean

clean~: $(d)/clean~


#
# H E L P  R U L E S
#
.PHONY: $(d)/help help

$(d)/help:
	@echo
	@echo "src/ targets:"
	@echo ""
	@echo "         all - build all API targets"
	@echo "      all5.1 - build 5.1/openssl.so"
	@echo "      all5.2 - build 5.2/openssl.so"
	@echo "      all5.3 - build 5.3/openssl.so"
	@echo "     install - install all API targets"
	@echo "  install5.1 - install openssl Lua 5.1 modules"
	@echo "  install5.2 - install openssl Lua 5.2 modules"
	@echo "  install5.3 - install openssl Lua 5.3 modules"
	@echo "   uninstall - uninstall all API targets"
	@echo "uninstall5.1 - uninstall openssl Lua 5.1 modules"
	@echo "uninstall5.2 - uninstall openssl Lua 5.2 modules"
	@echo "uninstall5.3 - uninstall openssl Lua 5.3 modules"
	@echo "       clean - rm binary targets, object files, debugging symbols, etc"
	@echo "      clean~ - clean + rm *~"
	@echo "        help - echo this help message"
	@echo ""
	@echo "Some important Make variables:"
	@echo ""
	@echo '  LUA_APIS - default Lua APIs to target ($(LUA_APIS))'
	@echo "    prefix - path to install root ($(value prefix))"
	@echo ' lua51path - install path for Lua 5.1 modules ($(value lua51path))'
	@echo 'lua51cpath - install path for Lua 5.1 C modules ($(value lua51cpath))'
	@echo ' lua52path - install path for Lua 5.2 modules ($(value lua52path))'
	@echo 'lua52cpath - install path for Lua 5.2 C modules ($(value lua52cpath))'
	@echo ' lua53path - install path for Lua 5.3 modules ($(value lua53path))'
	@echo 'lua53cpath - install path for Lua 5.3 C modules ($(value lua53cpath))'
	@echo ""
	@echo 'LUA51_CPPFLAGS - cpp flags for Lua 5.1 headers ($(LUA51_CPPFLAGS))'
	@echo 'LUA52_CPPFLAGS - cpp flags for Lua 5.2 headers ($(LUA52_CPPFLAGS))'
	@echo 'LUA53_CPPFLAGS - cpp flags for Lua 5.3 headers ($(LUA53_CPPFLAGS))'
	@echo ""
	@echo "(NOTE: all the common GNU-style paths are supported, including"
	@echo "prefix, bindir, libdir, datadir, includedir, and DESTDIR.)"
	@echo ""
	@echo "Report bugs to <william@25thandClement.com>"

help: $(d)/help


endif # include guard

# non-recursive epilogue
d := $(dirstack_$(sp))
sp := $(basename $(sp))
