CWD     = $(shell pwd)

ROOT    = $(CWD)/..
DLDIR   = $(ROOT)/download
SRCDIR  = $(CWD)

OSSLSRC   = $(SRCDIR)/openssl
CLSRC     = $(SRCDIR)/cryptlib
CLIENTSRC = $(SRCDIR)/cmpclient
SERVERSRC = $(SRCDIR)/cmpserver

OPENSSL_VERSION = 1.0.0
# as >331 is not released yet...
# CRYPTLIB_VERSION = 332
CRYPTLIB_VERSION = 333

LIBOSSL       = $(OSSLSRC)/libssl.a
OPENSSLCFGOPT = -g no-asm no-idea no-fips no-rc5 no-mdc2 no-camellia -fomit-frame-pointer -fno-strict-aliasing

LIBCRYPTO = $(CLSRC)/libcrypto.a

all: openssl_patch_$(OPENSSL_VERSION) openssl cmpclient cryptlib cmpserver 

.PHONY: all

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

.PHONY: openssl_src

# this is forced to be sure it is rebuilt if any file in it was changed
$(OSSLSRC)/config-stamp: FORCE
	# force the objects to be updated
	touch $(OSSLSRC)/crypto/objects/objects.txt
	cd $(OSSLSRC) && \
	./config --prefix=$(ROOT) $(OPENSSLCFGOPT) && \
	make update
	touch $(OSSLSRC)/config-stamp

openssl: $(OSSLSRC)/config-stamp FORCE
	cd $(OSSLSRC) && \
	make

.PHONY: openssl

cryptlib: $(CLSRC)/libcl.a

.PHONY: cryptlib

$(CLSRC)/libcl.a: $(CLSRC)/unzip-stamp
	cd $(CLSRC) && \
	make

$(CLIENTSRC)/cmpclient: openssl
	cd $(CLIENTSRC) && \
	make && \
	make install

cmpclient: $(CLIENTSRC)/cmpclient

.PHONY: cmpclient

$(SERVERSRC)/cmpserver-cl: cryptlib
	cd $(SERVERSRC) && \
	make && \
	make install

cmpserver: $(SERVERSRC)/cmpserver-cl

.PHONY: cmpserver

update: $(OSSLSRC)/Makefile all

.PHONY: update

openssl_patch_1.0.0:
	echo TODO: generate patch for openssl-1.0.0

openssl_patch_0.9.8g:
	-mkdir patches
	cd $(SRCDIR) && \
	svn diff -r 26:BASE openssl-0.9.8g-cmp > patches/openssl-0.9.8.g_cmp.diff

.PHONY: openssl_patch_0.9.8.g

openssl_patch_0.9.8n:
	-mkdir patches
	cd $(SRCDIR) && \
	svn diff -r 51:BASE openssl-0.9.8n-cmp > patches/openssl-0.9.8.n_cmp.diff

.PHONY: openssl_patch_0.9.8.n

FORCE:

