CWD     = $(shell pwd)

ROOT    = $(CWD)/..
DLDIR   = $(ROOT)/download
SRCDIR  = $(CWD)
BIN_DIR = $(ROOT)/bin
LIB_DIR = $(ROOT)/lib

OSSLSRC   = $(SRCDIR)/openssl
CLSRC     = $(SRCDIR)/cryptlib
CLIENTSRC = $(SRCDIR)/cmpclient
SERVERSRC = $(SRCDIR)/cmpserver
CURLSRC   = $(SRCDIR)/curl
LIGHTTPDSRC    = $(SRCDIR)/lighttpd
LIGHTTPDMODSRC = $(SRCDIR)/lighttpd-cmpserver
LIGHTTPDPATCH  = $(LIGHTTPDMODSRC)/lighttpd-build.patch

OPENSSL_VERSION = 1.0.0d
CRYPTLIB_VERSION = 340
CURL_VERSION = 7.21.6
LIGHTTPD_VERSION = 1.4.28

CURL_TARBALL = $(DLDIR)/curl-$(CURL_VERSION).tar.bz2
LIGHTTPD_TARBALL = $(DLDIR)/lighttpd-$(LIGHTTPD_VERSION).tar.bz2

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

LIGHTTPDCFGOPT = --prefix=$(ROOT) \
				 --without-mysql --without-ldap --without-attr --without-valgrind \
				 --without-openssl --without-kerberos5 --without-zlib \
				 --without-bzip2 --without-fam --without-webdav-props --without-webdav-locks \
				 --without-gdbm --without-memcache --without-lua


LIBCRYPTO = $(CLSRC)/libcrypto.a

all: openssl_patch_$(OPENSSL_VERSION) openssl cmpclient cryptlib cmpserver curl lighttpd

.PHONY: all

world: openssl_src cryptlib_src curl_src lighttpd_src

.PHONY: world

################################################################################
# OpenSSL
################################################################################

openssl: $(OSSLSRC)/config-stamp FORCE
	cd $(OSSLSRC) && \
	make

.PHONY: openssl

openssl-noconfig:
	cd $(OSSLSRC) && \
	make

.PHONY: openssl-noconfig

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
	ln -s -f openssl-$(OPENSSL_VERSION) $(OSSLSRC)

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
	ln -s -f cryptlib-$(CRYPTLIB_VERSION) $(CLSRC)
	touch $(CLSRC)/unzip-stamp

################################################################################
# OpenSSL patches
################################################################################

openssl_patch_1.0.0d:
	cd $(SRCDIR) && \
	svn diff -r 178:BASE openssl-1.0.0d-cmp > patches/openssl-1.0.0d_cmp.diff

.PHONY: openssl_patch_1.0.0d

################################################################################
# CURL
################################################################################

curl: $(LIB_DIR)/libcurl.a

.PHONY: curl

$(CURLSRC)/unzip-stamp: $(CURL_TARBALL)
	cd $(SRCDIR) && \
	tar xvfj $(CURL_TARBALL)
	ln -s -f curl-$(CURL_VERSION) $(CURLSRC)
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


################################################################################
# LIGHTTPD
################################################################################

lighttpd: $(BIN_DIR)/lighttpd

.PHONY: lighttpd

$(LIGHTTPDSRC)/unzip-stamp: $(LIGHTTPD_TARBALL)
	cd $(SRCDIR)
	rm -rf lighttpd-$(LIGHTTPD_VERSION) 
	tar xvfj $(LIGHTTPD_TARBALL)
	ln -sf lighttpd-$(LIGHTTPD_VERSION) $(LIGHTTPDSRC)
	patch -d $(LIGHTTPDSRC) -p1 < $(LIGHTTPDPATCH)
	ln -sf $(LIGHTTPDMODSRC)/{*.c,*.h} $(LIGHTTPDSRC)/src
	touch $(LIGHTTPDSRC)/unzip_stamp

$(BIN_DIR)/lighttpd: $(LIGHTTPDSRC)/unzip-stamp
	cd $(LIGHTTPDSRC) && ./configure $(LIGHTTPDCFGOPT)
	make -C $(LIGHTTPDSRC) all install

FORCE:

