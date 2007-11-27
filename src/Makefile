CWD     = $(shell pwd)

ROOT    = $(CWD)/..

OSSLSRC = $(CWD)/openssl
CLSRC   = $(CWD)/cryptlib

CLIENTSRC = $(CWD)/cmpclient
SERVERSRC = $(CWD)/cmpserver

LIBOSSL       = $(OSSLSRC)/libssl.a
OPENSSLCFGOPT = -g no-asm no-idea no-fips no-rc5 no-mdc2 no-camellia -fomit-frame-pointer -fno-strict-aliasing

LIBCRYPTO = $(OSSLSRC)/libcrypto.a

all: openssl cryptlib cmpclient cmpserver

$(OSSLSRC)/Makefile: 
	cd $(OSSLSRC) && \
	./config --prefix=$(ROOT) $(OPENSSLCFGOPT) && \
	make depend

$(LIBOSSL): $(OSSLSRC)/Makefile
	cd $(OSSLSRC) && \
	make

$(LIBCRYPTO): $(OSSLSRC)/Makefile
	cd $(OSSLSRC) && \
	make

openssl: $(LIBOSSL) $(LIBCRYPTO)

cryptlib: $(CLSRC)/libcl.a

$(CLSRC)/libcl.a:
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

.PHONY: openssl cryptlib cmpclient cmpserver
