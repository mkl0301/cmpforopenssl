#
# OpenSSL/crmf/Makefile
#

DIR=	crmf
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile README
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= crmf_asn.c crmf_lib.c crmf_pbm.c crmf_msg.c crmf_atav.c
LIBOBJ= crmf_asn.o crmf_lib.o crmf_pbm.o crmf_msg.o crmf_atav.o

SRC= $(LIBSRC)

EXHEADER= crmf.h
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

crmf_asn.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
crmf_asn.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
crmf_asn.o: ../../include/openssl/conf.h ../../include/openssl/crmf.h
crmf_asn.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
crmf_asn.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
crmf_asn.o: ../../include/openssl/ecdsa.h ../../include/openssl/evp.h
crmf_asn.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
crmf_asn.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
crmf_asn.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
crmf_asn.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
crmf_asn.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
crmf_asn.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
crmf_asn.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
crmf_asn.o: crmf_asn.c
crmf_atav.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
crmf_atav.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
crmf_atav.o: ../../include/openssl/conf.h ../../include/openssl/crmf.h
crmf_atav.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
crmf_atav.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
crmf_atav.o: ../../include/openssl/ecdsa.h ../../include/openssl/evp.h
crmf_atav.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
crmf_atav.o: ../../include/openssl/objects.h
crmf_atav.o: ../../include/openssl/opensslconf.h
crmf_atav.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
crmf_atav.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
crmf_atav.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
crmf_atav.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
crmf_atav.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
crmf_atav.o: crmf_atav.c
crmf_lib.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
crmf_lib.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
crmf_lib.o: ../../include/openssl/conf.h ../../include/openssl/crmf.h
crmf_lib.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
crmf_lib.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
crmf_lib.o: ../../include/openssl/ecdsa.h ../../include/openssl/evp.h
crmf_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
crmf_lib.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
crmf_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
crmf_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
crmf_lib.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
crmf_lib.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
crmf_lib.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
crmf_lib.o: crmf_lib.c
crmf_msg.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
crmf_msg.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
crmf_msg.o: ../../include/openssl/conf.h ../../include/openssl/crmf.h
crmf_msg.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
crmf_msg.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
crmf_msg.o: ../../include/openssl/ecdsa.h ../../include/openssl/evp.h
crmf_msg.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
crmf_msg.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
crmf_msg.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
crmf_msg.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
crmf_msg.o: ../../include/openssl/sha.h ../../include/openssl/stack.h
crmf_msg.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
crmf_msg.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
crmf_msg.o: crmf_msg.c
crmf_pbm.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
crmf_pbm.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
crmf_pbm.o: ../../include/openssl/conf.h ../../include/openssl/crmf.h
crmf_pbm.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
crmf_pbm.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
crmf_pbm.o: ../../include/openssl/ecdsa.h ../../include/openssl/evp.h
crmf_pbm.o: ../../include/openssl/hmac.h ../../include/openssl/lhash.h
crmf_pbm.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
crmf_pbm.o: ../../include/openssl/opensslconf.h
crmf_pbm.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
crmf_pbm.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
crmf_pbm.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
crmf_pbm.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
crmf_pbm.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
crmf_pbm.o: ../../include/openssl/x509v3.h crmf_pbm.c
