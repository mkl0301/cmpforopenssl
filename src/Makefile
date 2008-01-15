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

LIBCRYPTO = $(CLSRC)/libcrypto.a

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

cryptlib: $(CLSRC)/libcl.a

$(CLSRC)/libcl.a: $(CLSRC)/unzip-stamp
	cd $(CLSRC) && \
	make

$(CLIENTSRC)/cmpclient: openssl
	cd $(CLIENTSRC) && \
	make && \
	make install

cmpclient: $(CLIENTSRC)/cmpclient

$(SERVERSRC)/cmpserver-cl: cryptlib
	cd $(SERVERSRC) && \
	make && \
	make install

cmpserver: $(SERVERSRC)/cmpserver-cl

FORCE:

update: $(OSSLSRC)/Makefile all

.PHONY: openssl cryptlib cmpclient cmpserver update all
