#
# OpenSSL/cmp/Makefile
#

DIR=	cmp
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG) -Wall -DCMP_DEBUG

GENERAL=Makefile README
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= cmp_asn.c cmp_lib.c cmp_msg.c cmp_vfy.c cmp_http.c cmp_ses.c cmp_ctx.c cmp_err.c
LIBOBJ= cmp_asn.o cmp_lib.o cmp_msg.o cmp_vfy.o cmp_http.o cmp_ses.o cmp_ctx.o cmp_err.o

SRC= $(LIBSRC)

EXHEADER= cmp.h
HEADER=	$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

cmp_asn.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cmp_asn.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cmp_asn.o: ../../include/openssl/cmp.h ../../include/openssl/conf.h
cmp_asn.o: ../../include/openssl/crmf.h ../../include/openssl/crypto.h
cmp_asn.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cmp_asn.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cmp_asn.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cmp_asn.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cmp_asn.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cmp_asn.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
cmp_asn.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cmp_asn.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cmp_asn.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cmp_asn.o: ../../include/openssl/x509v3.h cmp_asn.c
cmp_ctx.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cmp_ctx.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cmp_ctx.o: ../../include/openssl/cmp.h ../../include/openssl/conf.h
cmp_ctx.o: ../../include/openssl/crmf.h ../../include/openssl/crypto.h
cmp_ctx.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cmp_ctx.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cmp_ctx.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cmp_ctx.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cmp_ctx.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cmp_ctx.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cmp_ctx.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cmp_ctx.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
cmp_ctx.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cmp_ctx.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cmp_ctx.o: cmp_ctx.c
cmp_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
cmp_err.o: ../../include/openssl/buffer.h ../../include/openssl/cmp.h
cmp_err.o: ../../include/openssl/conf.h ../../include/openssl/crmf.h
cmp_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cmp_err.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cmp_err.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
cmp_err.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cmp_err.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cmp_err.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cmp_err.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
cmp_err.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cmp_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cmp_err.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cmp_err.o: ../../include/openssl/x509v3.h cmp_err.c
cmp_http.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cmp_http.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cmp_http.o: ../../include/openssl/cmp.h ../../include/openssl/conf.h
cmp_http.o: ../../include/openssl/crmf.h ../../include/openssl/crypto.h
cmp_http.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cmp_http.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cmp_http.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cmp_http.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cmp_http.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cmp_http.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cmp_http.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cmp_http.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
cmp_http.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cmp_http.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cmp_http.o: cmp_http.c
cmp_lib.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cmp_lib.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cmp_lib.o: ../../include/openssl/cmp.h ../../include/openssl/conf.h
cmp_lib.o: ../../include/openssl/crmf.h ../../include/openssl/crypto.h
cmp_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cmp_lib.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cmp_lib.o: ../../include/openssl/engine.h ../../include/openssl/err.h
cmp_lib.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cmp_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cmp_lib.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cmp_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
cmp_lib.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
cmp_lib.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
cmp_lib.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cmp_lib.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cmp_lib.o: cmp_lib.c
cmp_msg.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cmp_msg.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cmp_msg.o: ../../include/openssl/cmp.h ../../include/openssl/conf.h
cmp_msg.o: ../../include/openssl/crmf.h ../../include/openssl/crypto.h
cmp_msg.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cmp_msg.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cmp_msg.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cmp_msg.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cmp_msg.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cmp_msg.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cmp_msg.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cmp_msg.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
cmp_msg.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cmp_msg.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cmp_msg.o: cmp_msg.c
cmp_ses.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
cmp_ses.o: ../../include/openssl/buffer.h ../../include/openssl/cmp.h
cmp_ses.o: ../../include/openssl/conf.h ../../include/openssl/crmf.h
cmp_ses.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cmp_ses.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cmp_ses.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
cmp_ses.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cmp_ses.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cmp_ses.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cmp_ses.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
cmp_ses.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cmp_ses.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cmp_ses.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cmp_ses.o: ../../include/openssl/x509v3.h cmp_ses.c
cmp_vfy.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cmp_vfy.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cmp_vfy.o: ../../include/openssl/cmp.h ../../include/openssl/conf.h
cmp_vfy.o: ../../include/openssl/crmf.h ../../include/openssl/crypto.h
cmp_vfy.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cmp_vfy.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cmp_vfy.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cmp_vfy.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cmp_vfy.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cmp_vfy.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cmp_vfy.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cmp_vfy.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
cmp_vfy.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cmp_vfy.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cmp_vfy.o: cmp_vfy.c
