CWD     = $(shell pwd)

ROOT    = $(CWD)/..
DLDIR   = $(ROOT)/download
SRCDIR  = $(CWD)
LIB_DIR = $(ROOT)/lib

OSSLSRC   = $(SRCDIR)/openssl
CLSRC     = $(SRCDIR)/cryptlib
CLIENTSRC = $(SRCDIR)/cmpclient
SERVERSRC = $(SRCDIR)/cmpserver
CURLSRC   = $(SRCDIR)/curl

OPENSSL_VERSION = 1.0.0
CRYPTLIB_VERSION = 333
CURL_VERSION = 7.21.0

CURL_TARBALL = $(DLDIR)/curl-$(CURL_VERSION).tar.bz2

LIBOSSL       = $(OSSLSRC)/libssl.a
OPENSSLCFGOPT = -g no-asm no-idea no-fips no-rc5 no-mdc2 no-camellia -fomit-frame-pointer -fno-strict-aliasing

#TODO do we have to set LIBDIR or CCFLAGS...?
CURLCFGOPT = --prefix=$(ROOT) \
						 --disable-ftp --disable-file --disable-ldap --disable-ldaps --disable-rtsp --disable-proxy \
						 --disable-dict --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smtp \
						 --disable-shared --disable-manual --without-ca-bundle --without-ca-path \
						 --disable-threaded-resover --disable-sspi --disable-crypto-auth --disable-cookies \
						 --disable-soname-bump --without-ssl --without-zlib --without-gnutls --without-polarssl \
						 --without-nss --without-libssh2 --without-librtmp

LIBCRYPTO = $(CLSRC)/libcrypto.a

all: openssl_patch_$(OPENSSL_VERSION) openssl cmpclient cryptlib cmpserver curl

.PHONY: all

world: openssl_src cryptlib_src curl_src

.PHONY: world

################################################################################
# OpenSSL
################################################################################

openssl: $(OSSLSRC)/config-stamp FORCE
	cd $(OSSLSRC) && \
	make

.PHONY: openssl

# this is forced to be sure it is rebuilt if any file in it was changed
$(OSSLSRC)/config-stamp: FORCE
	# force the objects to be updated
	touch $(OSSLSRC)/crypto/objects/objects.txt
	cd $(OSSLSRC) && \
	./config --prefix=$(ROOT) $(OPENSSLCFGOPT) && \
	make update
	touch $(OSSLSRC)/config-stamp

openssl_src: $(DLDIR)/openssl-$(OPENSSL_VERSION).tar.gz
	tar xvfz $(DLDIR)/openssl-$(OPENSSL_VERSION).tar.gz -C $(SRCDIR)
	-rm $(OSSLSRC)
	ln -s --force openssl-$(OPENSSL_VERSION) $(OSSLSRC)

.PHONY: openssl_src

$(DLDIR)/openssl-$(OPENSSL_VERSION).tar.gz:
	wget --directory-prefix=$(DLDIR) http://www.openssl.org/source/openssl-$(OPENSSL_VERSION).tar.gz

#TODO: is the following needed at all?
update: $(OSSLSRC)/Makefile all

.PHONY: update

################################################################################
# CMPServer
################################################################################

cmpserver: $(SERVERSRC)/cmpserver-cl

.PHONY: cmpserver

################################################################################
# CMPClient
################################################################################

cmpclient: $(CLIENTSRC)/cmpclient

.PHONY: cmpclient

$(CLIENTSRC)/cmpclient: openssl
	cd $(CLIENTSRC) && \
	make && \
	make install

################################################################################
# Cryptlib
################################################################################

cryptlib: $(CLSRC)/libcl.a

.PHONY: cryptlib

$(CLSRC)/libcl.a: $(CLSRC)/unzip-stamp
	cd $(CLSRC) && \
	make

$(SERVERSRC)/cmpserver-cl: cryptlib
	cd $(SERVERSRC) && \
	make && \
	make install

$(DLDIR)/cl$(CRYPTLIB_VERSION).zip:
	wget --directory-prefix=$(DLDIR) ftp://ftp.franken.de/pub/crypt/cryptlib/cl$(CRYPTLIB_VERSION).zip

$(CLSRC)/unzip-stamp: $(DLDIR)/cl$(CRYPTLIB_VERSION).zip
	-mkdir $(SRCDIR)/cryptlib-$(CRYPTLIB_VERSION)
	unzip -a $(DLDIR)/cl$(CRYPTLIB_VERSION).zip -d $(SRCDIR)/cryptlib-$(CRYPTLIB_VERSION)
	-rm $(CLSRC)
	ln -s --force cryptlib-$(CRYPTLIB_VERSION) $(CLSRC)
	touch $(CLSRC)/unzip-stamp

################################################################################
# OpenSSL patches
################################################################################

openssl_patch_1.0.0:
	echo TODO: generate patch for openssl-1.0.0

openssl_patch_0.9.8g:
	-mkdir -p patches
	cd $(SRCDIR) && \
	svn diff -r 26:BASE openssl-0.9.8g-cmp > patches/openssl-0.9.8.g_cmp.diff

.PHONY: openssl_patch_0.9.8.g

openssl_patch_0.9.8n:
	-mkdir -p patches
	cd $(SRCDIR) && \
	svn diff -r 51:BASE openssl-0.9.8n-cmp > patches/openssl-0.9.8.n_cmp.diff

.PHONY: openssl_patch_0.9.8.n

################################################################################
# CURL
################################################################################

curl: $(LIB_DIR)/libcurl.a

.PHONY: curl

$(CURLSRC)/unzip-stamp: $(CURL_TARBALL)
	cd $(SRCDIR) && \
	tar xvfj $(CURL_TARBALL)
	ln -s --force curl-$(CURL_VERSION) $(CURLSRC)
	touch $(CURLSRC)/unzip-stamp

#TODO set configure options (installdir...)
$(LIB_DIR)/libcurl.a: $(CURLSRC)/unzip-stamp
	cd $(CURLSRC) && \
	./configure $(CURLCFGOPT) && \
	make && \
	cd $(CURLSRC)/lib && \
	make install && \
	cd $(CURLSRC)/include && \
	make install


FORCE:

