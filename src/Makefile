CWD     = $(shell pwd)

ROOT    = $(CWD)/..
DLDIR   = $(ROOT)/download
SRCDIR  = $(CWD)

OSSLSRC   = $(SRCDIR)/openssl
CLSRC     = $(SRCDIR)/cryptlib
CLIENTSRC = $(SRCDIR)/cmpclient
SERVERSRC = $(SRCDIR)/cmpserver

OPENSSL_VERSION = 0.9.8g
# as >331 is not released yet...
# CRYPTLIB_VERSION = 332
CRYPTLIB_VERSION = SNAP-20070922

LIBOSSL       = $(OSSLSRC)/libssl.a
OPENSSLCFGOPT = -g no-asm no-idea no-fips no-rc5 no-mdc2 no-camellia -fomit-frame-pointer -fno-strict-aliasing

LIBCRYPTO = $(OSSLSRC)/libcrypto.a

all: openssl cryptlib cmpclient cmpserver

world: openssl_src cryptlib_src
.PHONY: world

$(DLDIR)/openssl-$(OPENSSL_VERSION).tar.gz:
	wget --directory-prefix=$(DLDIR) http://www.openssl.org/source/openssl-$(OPENSSL_VERSION).tar.gz

$(DLDIR)/cl$(CRYPTLIB_VERSION).zip:
	wget --directory-prefix=$(DLDIR) ftp://ftp.franken.de/pub/crypt/cryptlib/cl$(CRYPTLIB_VERSION).zip

openssl_src: $(DLDIR)/openssl-$(OPENSSL_VERSION).tar.gz
	tar xvfz $(DLDIR)/openssl-$(OPENSSL_VERSION).tar.gz -C $(SRCDIR)
	-rm $(OSSLSRC)
	ln -s --force openssl-$(OPENSSL_VERSION) $(OSSLSRC)

$(CLSRC)/unzip-stamp: $(DLDIR)/cl$(CRYPTLIB_VERSION).zip
	-mkdir $(SRCDIR)/cryptlib-$(CRYPTLIB_VERSION)
	unzip -a $(DLDIR)/cl$(CRYPTLIB_VERSION).zip -d $(SRCDIR)/cryptlib-$(CRYPTLIB_VERSION)
	-rm $(CLSRC)
	ln -s --force cryptlib-$(CRYPTLIB_VERSION) $(CLSRC)
	touch $(CLSRC)/unzip-stamp

.PHONY: openssl_src cryptlib_src

# this is forced to be sure it is rebuilt if any file in it was changed
$(OSSLSRC)/Makefile: FORCE
	cd $(OSSLSRC) && \
	./config --prefix=$(ROOT) $(OPENSSLCFGOPT) && \
	make depend && \
	make update

openssl: $(OSSLSRC)/Makefile FORCE
	cd $(OSSLSRC) && \
	make

cryptlib: $(CLSRC)/libcl.a

$(CLSRC)/libcl.a: $(CLSRC)/unzip-stamp
	cd $(CLSRC) && \
	make

$(CLIENTSRC)/cmpclient: $(LIBOSSL)
	cd $(CLIENTSRC) && \
	make && \
	make install

cmpclient: $(CLIENTSRC)/cmpclient

$(SERVERSRC)/cmpserver-cl: $(LIBCRYPTO)
	cd $(SERVERSRC) && \
	make && \
	make install

cmpserver: $(SERVERSRC)/cmpserver-cl

FORCE:

update: $(OSSLSRC)/Makefile all

.PHONY: openssl cryptlib cmpclient cmpserver update all
