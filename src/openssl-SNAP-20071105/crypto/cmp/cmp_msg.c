/* crypto/cmp/cmp_msg.c
 *
 * Functions for creating CMP (RFC 4210) messages for OpenSSL
 *
 * Written by Martin Peylo <martin.peylo@nsn.com>
 */

/*
 * The following license applies to this file:
 *
 * Copyright (c) 2007, Nokia Siemens Networks (NSN)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of NSN nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY NSN ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL NSN BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * The following licenses apply to OpenSSL:
 *
 * OpenSSL License
 * ---------------
 *
 * ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 * ====================================================================
 *
 * Original SSLeay License
 * -----------------------
 *
 * Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crmf.h>
#include <openssl/cmp.h>
#include <openssl/x509.h>
#include <openssl/safestack.h>

#include <string.h>

#if 0
/* ############################################################################ */
/* Lie and say we'd be CL */
/* XXX this is just for testing and should be removed */
/* ############################################################################ */
void pretend_to_be_cl(CMP_PKIMESSAGE *msg) {
	/* for saying we'd be CL */
	ASN1_STRING *emptySetStr=NULL;
	unsigned char *emptySetDer=NULL;
	CMP_INFOTYPEANDVALUE *itavLie=NULL;
	ASN1_OBJECT *clNid;

	emptySetStr = ASN1_STRING_new();
	emptySetDer = OPENSSL_malloc(3);
	emptySetDer[0] = 0x31;
	emptySetDer[1] = 0x0;
	emptySetDer[2] = 0x0;
	ASN1_STRING_set0( emptySetStr, emptySetDer, 2);
	clNid = OBJ_txt2obj("1.3.6.1.4.1.3029.3.1.1",1);
	itavLie = CMP_INFOTYPEANDVALUE_new();
	CMP_INFOTYPEANDVALUE_set0(itavLie, clNid, V_ASN1_SET, emptySetStr);
	CMP_PKIMESSAGE_add0_infotypeandvalue(msg, itavLie);

	return;
}
#endif



#if 0
/* ############################################################################ */
/* ############################################################################ */
unsigned char *StrToHexStr(unsigned char *str, int length)
{
	unsigned char *newstr;
	unsigned char *cpold;
	unsigned char *cpnew;

	newstr = (unsigned char *)malloc((size_t)(length*2+1));
	/* XXX I know this is not freed... */
	cpold = str;
	cpnew = newstr;

	while(length--) {
		sprintf((char *)cpnew, "%02X", *cpold++);
		cpnew+=2;
	}
	*(cpnew) = '\0';
	return(newstr);
}
#endif


/* ############################################################################ */
/* ############################################################################ */
CMP_PKIMESSAGE * CMP_ir_new( CMP_CTX *ctx) {
	CMP_PKIMESSAGE  *msg=NULL;
	CRMF_CERTREQMSG *certReq0=NULL;

	/* check if all necessary options are set */
	if (!ctx) goto err;
	if (!ctx->caCert) goto err;
	if (!ctx->referenceValue) goto err;
	if (!ctx->secretValue) goto err;
	if (!ctx->pkey) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;

	if( !CMP_PKIHEADER_set1( msg->header, ctx)) goto err;

	if (ctx->implicitConfirm)
		if (! CMP_PKIMESSAGE_set_implicitConfirm(msg)) goto err;

	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_IR);

	/* XXX certReq 0 is not freed on error, but that's because it will become part of ir and is freed there */
	if( !(certReq0 = CRMF_cr_new(0L, ctx->pkey, NULL))) goto err;

	msg->body->value.ir = sk_CRMF_CERTREQMSG_new_null();
	sk_CRMF_CERTREQMSG_push( msg->body->value.ir, certReq0);

	/* XXX what about setting the optional 2nd certreqmsg? */

	/* TODO catch errors */
	msg->protection = CMP_protection_new( msg, NULL, NULL, ctx->secretValue);

	/* XXX - should this be done somewhere else? */
	CMP_CTX_set1_protectionAlgor( ctx, msg->header->protectionAlg);

	return msg;
err:
printf( "ERROR: in CMP_ir_new, FILE: %s, LINE: %d\n", __FILE__, __LINE__);
	if (msg) CMP_PKIMESSAGE_free(msg);
	return NULL;
}

/* ############################################################################ */
/* ############################################################################ */
CMP_PKIMESSAGE * CMP_kur_new( CMP_CTX *ctx) {
	CMP_PKIMESSAGE *msg=NULL;
	CRMF_CERTREQMSG *certReq0=NULL;

	/* for oldCertId in "controls" of the CRMF cr message*/
	GENERAL_NAME *gName;
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;
	long serial;
	ASN1_INTEGER *serialASN=NULL;

	/* for setting the id-aa-signingCertificate for CL */
	unsigned int hashLen;
	unsigned char hash[EVP_MAX_MD_SIZE];
	ESS_ESSCERTID *essCertId=NULL;
	ESS_SIGNINGCERTIFICATE *signingCert;
	unsigned char *itavValueDer=NULL;
	size_t itavValueDerLen;
	ASN1_STRING * itavValueStr=NULL;
	CMP_INFOTYPEANDVALUE *itav=NULL;
	unsigned char *itavValueDerSet=NULL;

	/* check if all necessary options are set */
	if (!ctx) goto err;
	if (!ctx->caCert) goto err;
	if (!ctx->clCert) goto err;
	if (!ctx->pkey) goto err;
	if (!ctx->newPkey) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;

	/* get the subject_key_id from the certificate to set it later as senderKID */
	/* XXX this is actually not required by the RFC but CL does like that */
	if( ctx->compatibility == CMP_COMPAT_CRYPTLIB) {
		int subjKeyIDLoc;
		if( (subjKeyIDLoc = X509_get_ext_by_NID( (X509*) ctx->clCert, NID_subject_key_identifier, -1)) != -1) {
			/* found a subject key ID */
			ASN1_OCTET_STRING *subjKeyIDStr = NULL;
			X509_EXTENSION *ex = NULL;
			const unsigned char *subjKeyIDStrDer = NULL;

			ex=sk_X509_EXTENSION_value( ctx->clCert->cert_info->extensions, subjKeyIDLoc);

			subjKeyIDStrDer = (const unsigned char *) ex->value->data;
			subjKeyIDStr = d2i_ASN1_OCTET_STRING( NULL, &subjKeyIDStrDer, ex->value->length);

			CMP_CTX_set1_referenceValue( ctx, subjKeyIDStr->data, subjKeyIDStr->length);

			/* clean up */
			ASN1_OCTET_STRING_free(subjKeyIDStr);
		}
	}

	if( !CMP_PKIHEADER_set1(msg->header, ctx)) goto err;

	if (ctx->implicitConfirm)
		if (! CMP_PKIMESSAGE_set_implicitConfirm( msg)) goto err;

	/* XXX certReq 0 is not freed on error, but that's because it will become part of kur and is freed there */
	/* XXX setting the sender in a KUR message is not really required by the RFC */
	if( !(certReq0 = CRMF_cr_new(0L, ctx->newPkey, X509_get_subject_name( (X509*) ctx->clCert)))) goto err;

	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_KUR);
	msg->body->value.kur = sk_CRMF_CERTREQMSG_new_null();

	/* identify our cert */

	/* this is like it is described in the RFC:
	 * set oldCertId in "controls" of the CRMF cr message
	 * CL does not like this to be set */
	if( ctx->compatibility != CMP_COMPAT_CRYPTLIB) {
		gName = GENERAL_NAME_new();
		/* 1 GET issuer X509_NAME from certificate */
		/* 2 transform to GENERAL_NAME */
		X509_NAME_set( &gName->d.directoryName, X509_get_issuer_name( ctx->clCert));
		gName->type = GEN_DIRNAME;
		/* 3 set it with the following commands */
		serialASN   = X509_get_serialNumber(ctx->clCert);
		serial      = ASN1_INTEGER_get(serialASN);
		atav        = CRMF_ATAV_OldCertId_new( gName, serialASN);
		CRMF_CERTREQMSG_push0_control( certReq0, atav);
	}

	/* this is like CL likes it:
	 * set id-aa-signingCertificate "generalInfo" of the CMP header */
	if( ctx->compatibility == CMP_COMPAT_CRYPTLIB) {
		if (!X509_digest(ctx->clCert, EVP_sha1(), hash, &hashLen)) goto err;
		essCertId = ESS_ESSCERTID_new();
		if (!ASN1_OCTET_STRING_set(essCertId->certHash, hash, hashLen)) goto err;

		signingCert = ESS_SIGNINGCERTIFICATE_new();
		if( !signingCert->certs) {
			/* XXX free... */
			if( !(signingCert->certs = sk_ESS_ESSCERTID_new_null())) goto err;
		}
		if(!sk_ESS_ESSCERTID_push(signingCert->certs, essCertId)) goto err;
		itavValueDerLen = i2d_ESS_SIGNINGCERTIFICATE( signingCert, &itavValueDer);

		/* this is just wrong but CL does it:
		 * prepend an ASN.1 set to the id-aa-signingCertificate sequence */
		itavValueDerSet    = OPENSSL_malloc( itavValueDerLen+2);
		itavValueDerSet[0] = 0x31;
		itavValueDerSet[1] = itavValueDer[1]+2;
		memcpy( itavValueDerSet+2, itavValueDer, itavValueDerLen);

		itavValueStr = ASN1_STRING_new();
#if 0
		ASN1_STRING_set0( itavValueStr, itavValueDer, itavValueDerLen);
#endif
		ASN1_STRING_set0( itavValueStr, itavValueDerSet, itavValueDerLen+2);

		itav = CMP_INFOTYPEANDVALUE_new();
#if 0
		CMP_INFOTYPEANDVALUE_set0(itav, OBJ_nid2obj(NID_id_smime_aa_signingCertificate), V_ASN1_SEQUENCE, itavValueStr);
#endif
		CMP_INFOTYPEANDVALUE_set0(itav, OBJ_nid2obj( NID_id_smime_aa_signingCertificate), V_ASN1_SET, itavValueStr);
		CMP_PKIHEADER_generalInfo_item_push0( msg->header, itav);
	}

	sk_CRMF_CERTREQMSG_push( msg->body->value.kur, certReq0);

	/* XXX what about setting the optional 2nd certreqmsg? */

	/* TODO catch errors */
	msg->protection = CMP_protection_new( msg, NULL, (EVP_PKEY*) ctx->pkey, NULL);

	/* XXX - should this be done somewhere else? */
	CMP_CTX_set1_protectionAlgor( ctx, msg->header->protectionAlg);

	return msg;
err:
printf( "ERROR: in CMP_kur_new, FILE: %s, LINE: %d\n", __FILE__, __LINE__);
	if (msg) CMP_PKIMESSAGE_free(msg);
	return NULL;
}


/* ############################################################################ */
/* ############################################################################ */
CMP_PKIMESSAGE * CMP_certConf_new( CMP_CTX *ctx) {

	CMP_PKIMESSAGE *msg=NULL;
	CMP_CERTSTATUS *certStatus=NULL;

	/* check if all necessary options are set */
	if (!ctx) goto err;
	if (!ctx->caCert) goto err;
	if (!ctx->newClCert) goto err;
	if ( (!ctx->pkey) || ((!ctx->referenceValue) && (!ctx->secretValue)) ) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;

	if( !CMP_PKIHEADER_set1(msg->header, ctx)) goto err;

	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_CERTCONF);

	/* TODO - there could be more than one certconf */
	if( !(certStatus = CMP_CERTSTATUS_new())) goto err;

	/* set the # of the certReq */
	ASN1_INTEGER_set(certStatus->certReqId,0L);

	/*
        -- the hash of the certificate, using the same hash algorithm
        -- as is used to create and verify the certificate signature
	*/
	/* TODO: iterate through all the certificates in order to handle all */

/* XXX the former value should be freed */
	CMP_CERTSTATUS_set_certHash( certStatus, ctx->newClCert);

	/* TODO: set optional PKIStatusInfo */

	msg->body->value.certConf = sk_CMP_CERTSTATUS_new_null();
	if(!sk_CMP_CERTSTATUS_push( msg->body->value.certConf, certStatus)) goto err;

	/* TODO catch errors */
	msg->protection = CMP_protection_new( msg, NULL, ctx->pkey, ctx->secretValue);

	return msg;
err:
printf( "ERROR: in CMP_certConf_new, FILE: %s, LINE: %d\n", __FILE__, __LINE__);
	if (msg) CMP_PKIMESSAGE_free(msg);
	return NULL;
}


/* ############################################################################ */
/* ############################################################################ */
CMP_PKIMESSAGE *CMP_genm_new( CMP_CTX *ctx) {
	CMP_PKIMESSAGE *msg=NULL;
	CMP_INFOTYPEANDVALUE *itav=NULL;

	/* check if all necessary options are set */
	if (!ctx) goto err;

	/* XXX not setting senderNonce test for PKI INFO */
	ctx->setSenderNonce  = 0;
	/* XXX not setting transactionID test for PKI INFO */
	ctx->setTransactionID  = 1;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;

	if( !CMP_PKIHEADER_set1(msg->header, ctx)) goto err;

	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_GENM);

	/* create an empty message body */
	if( CMP_PKIMESSAGE_genm_item_push0( msg, NULL)) {
		printf( "INFO: created message body\n");
	}
#if 0
	itav = CMP_INFOTYPEANDVALUE_new();
	if( CMP_INFOTYPEANDVALUE_set0( itav, OBJ_txt2obj("1.3.6.1.5.5.7.4.4",1), V_ASN1_UNDEF, NULL)) {
		printf( "INFO: setting itav\n");
	} /* Preferred Symmetric Algorithm */
	if( CMP_PKIMESSAGE_genm_item_push0( msg, itav)) {
		printf( "INFO: pushing itav\n");
	}
#endif
#if 0
	itav = CMP_INFOTYPEANDVALUE_new();
	if( CMP_INFOTYPEANDVALUE_set0( itav, OBJ_txt2obj("1.3.6.1.5.5.7.4.6",1), V_ASN1_UNDEF, NULL)) {
		printf( "INFO: setting itav\n");
	} /* CRL */
	if( CMP_PKIMESSAGE_genm_item_push0( msg, itav)) {
		printf( "INFO: pushing itav\n");
	}
#endif
#if 0
	itav = CMP_INFOTYPEANDVALUE_new();
	if( CMP_INFOTYPEANDVALUE_set0( itav, OBJ_txt2obj("1.3.6.1.4.1.3029.3.1.2",1), V_ASN1_UNDEF, NULL)) {
		printf( "INFO: setting itav\n");
	} /* PKIBoot request */
	if( CMP_PKIMESSAGE_genm_item_push0( msg, itav)) {
		printf( "INFO: pushing itav\n");
	}
#endif
#if 0
	itav = CMP_INFOTYPEANDVALUE_new_by_def_noVal( CMP_ITAV_CRYPTLIB_PKIBOOT);
	if( CMP_PKIMESSAGE_genm_item_push0( msg, itav)) {
		printf( "INFO: pushing itav\n");
	}
#endif

	/* TODO catch errors */
	msg->protection = CMP_protection_new( msg, NULL, NULL, ctx->secretValue);
	return msg;
err:
printf( "ERROR: in CMP_genm_new, FILE: %s, LINE: %d\n", __FILE__, __LINE__);
	if (msg) CMP_PKIMESSAGE_free(msg);
	return NULL;
}

/* ############################################################################ */
/* XXX this is untested and work in progress */
/* The sanity of this kind of message is not without controversy */
	/* CKUANN looks like:
	 * ckuann message:
	 *
	 * Field        Value                        Comment
	 * --------------------------------------------------------------
	 * sender       CA name CA name
	 * body         ckuann(CAKeyUpdAnnContent)
	 * oldWithNew   present                  see Appendix E.3 above
	 * newWithOld   present                  see Appendix E.3 above
	 * newWithNew   present                  see Appendix E.3 above
	 * extraCerts   optionally present       can be used to "publish"
	 * 					 certificates (e.g.,
	 * 					 certificates signed using
	 * 					 the new private key)
	 */
/* ############################################################################ */
CMP_PKIMESSAGE *CMP_ckuann_new( const X509 *oldCaCert, const EVP_PKEY *oldPkey, const X509 *newCaCert, const EVP_PKEY *newPkey) {
	CMP_PKIMESSAGE *msg=NULL;
	X509_NAME *oldCaName=NULL;
	X509_NAME *newCaName=NULL;
	X509 *newWithNew=NULL;
	X509 *newWithOld=NULL;
	X509 *oldWithNew=NULL;

#if 0
	if (!ctx) goto err;
#endif

	/* get and compare the subject Names of the certificates */
	if (!(oldCaName = X509_get_subject_name( (X509*) oldCaCert))) goto err;
	if (!(newCaName = X509_get_subject_name( (X509*) newCaCert))) goto err;
	/* the subjects of old and new CaCerts have to be equal */
	if (! X509_NAME_cmp( oldCaName, newCaName)) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;

	CMP_PKIHEADER_set_version(msg->header, CMP_VERSION);
	if( !CMP_PKIHEADER_set1_sender( msg->header, X509_get_subject_name( (X509*) oldCaCert))) goto err;

	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_CKUANN);
	msg->body->value.ckuann = CMP_CAKEYUPDANNCONTENT_new();

	/* as I understand the newWithNew is the same as the newCaCert */
	newWithNew = X509_dup( (X509*) newCaCert);
	msg->body->value.ckuann->newWithNew = newWithNew;

	/* create the newWithOld and oldWithNew certificates */
	newWithOld = X509_dup( (X509*) newCaCert);
	/* XXX Do I have to check what digest to use? */
	X509_sign( newWithOld, (EVP_PKEY*) oldPkey, EVP_sha1());
	msg->body->value.ckuann->newWithOld = newWithOld;

	oldWithNew = X509_dup( (X509*) oldCaCert);
	/* XXX Do I have to check what digest to use? */
	X509_sign( oldWithNew, (EVP_PKEY*) newPkey, EVP_sha1());
	msg->body->value.ckuann->oldWithNew = oldWithNew;

	return msg;
err:
printf( "ERROR: in CMP_ckuann_new, FILE: %s, LINE: %d\n", __FILE__, __LINE__);
	if (msg) CMP_PKIMESSAGE_free(msg);
	return NULL;
}
