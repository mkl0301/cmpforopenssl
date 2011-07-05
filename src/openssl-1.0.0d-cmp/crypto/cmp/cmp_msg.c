/* crypto/cmp/cmp_msg.c
 * Functions for creating CMP (RFC 4210) messages for OpenSSL
 */
/* ====================================================================
 * Originally written by Martin Peylo for the OpenSSL project.
 * <martin dot peylo at nsn dot com>
 */
/* ====================================================================
 * Copyright (c) 2007-2010 The OpenSSL Project.  All rights reserved.
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
 */
/* ====================================================================
 * Copyright 2007-2010 Nokia Siemens Networks Oy. ALL RIGHTS RESERVED.
 * CMP support in OpenSSL originally developed by 
 * Nokia Siemens Networks for contribution to the OpenSSL project.
 */

/* =========================== CHANGE LOG =============================
 * 2007 - Martin Peylo - Initial Creation
 * 2008 - Sami Lehtonen - added CMP_cr_new()
 *                      - bugfix in CMP_certConf_new(): pkey or ref/secret pair is enough
 * 06/2010 - Miikka Viljanen - Report errors with OpenSSL error codes instead
 *                             of printf statements.
 * 06/10/2010 - Martin Peylo - fixed potential NPD in CMP_ir_new(), CMP_cr_new() and 
 *                             CMP_kur_new() and CMP_certConf_new() in case of failing 
 *                             OPENSSL_malloc() and potential MLKS in error cases
 */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crmf.h>
#include <openssl/cmp.h>
#include <openssl/x509.h>
#include <openssl/safestack.h>
#include <openssl/err.h>

#include <string.h>

static int add_altname_extensions(X509_EXTENSIONS **extensions, STACK_OF(GENERAL_NAME) *altnames) {
	X509_EXTENSION *ext = NULL;
	unsigned char *der = NULL;
	int derlen = 0;
	ASN1_OCTET_STRING *str = ASN1_OCTET_STRING_new();

	ASN1_seq_pack_GENERAL_NAME(altnames, i2d_GENERAL_NAME, &der, &derlen);

	ASN1_STRING_set(str, der, derlen);
	X509_EXTENSION_create_by_NID(&ext, NID_subject_alt_name, 0, str);

	ASN1_OCTET_STRING_free(str);
	OPENSSL_free(der);

	X509v3_add_ext(extensions, ext, 0);

	return 1;
}

/* ############################################################################ */
/* ############################################################################ */
CMP_PKIMESSAGE * CMP_ir_new( CMP_CTX *ctx) {
	CMP_PKIMESSAGE  *msg=NULL;
	CRMF_CERTREQMSG *certReq0=NULL;
	X509_EXTENSIONS *extensions = NULL;
	X509_NAME *subject=NULL;

	/* check if all necessary options are set */
	if (!ctx) goto err;
#if 0
	if (!ctx->caCert) goto err;
#endif
	if (!ctx->referenceValue) goto err;
	if (!ctx->secretValue) goto err;
	if (!ctx->pkey) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;

	if( !CMP_PKIHEADER_set1( msg->header, ctx)) goto err;

	if (ctx->implicitConfirm)
		if (! CMP_PKIMESSAGE_set_implicitConfirm(msg)) goto err;

	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_IR);

	if (ctx->clCert)
		subject = X509_get_subject_name(ctx->clCert);
	else if (ctx->extCert)
		subject = X509_get_subject_name(ctx->extCert);
	else
		subject = ctx->subjectName;

	/* subject name is required for insta compatibility! */
	if (ctx->compatibility == CMP_COMPAT_INSTA_3_3 && subject == NULL) {
		/* XXX should this raise an error, or should we just use a default? */
		subject = X509_NAME_new();
		if (!X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (unsigned char*) "My Common Name", -1, -1, 0))
			goto err;
#if 0
		CMPerr(CMP_F_CMP_IR_NEW, CMP_R_SUBJECT_NAME_NOT_SET);
		ERR_add_error_data(1, "subject name is required in insta compatibility mode");
		goto err;
#endif
	}

	if (sk_GENERAL_NAME_num(ctx->subjectAltNames) > 0)
		add_altname_extensions(&extensions, ctx->subjectAltNames);

	/* XXX certReq 0 is not freed on error, but that's because it will become part of ir and is freed there */
	if( !(certReq0 = CRMF_cr_new(0L, ctx->pkey, subject, ctx->compatibility, ctx->popoMethod, extensions))) goto err;

	if (extensions) sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);

	if( !(msg->body->value.ir = sk_CRMF_CERTREQMSG_new_null())) goto err;
	sk_CRMF_CERTREQMSG_push( msg->body->value.ir, certReq0);

	/* if we have external cert, try to initialize with that. */
	if (ctx->extCert) {
		if( !msg->extraCerts && !(msg->extraCerts = sk_X509_new_null())) goto err;
		sk_X509_push(msg->extraCerts, ctx->extCert);
	}

	/* add any extraCerts that are set in the context */
	if (sk_X509_num(ctx->extraCerts) > 0) {
		int i;
		if( !msg->extraCerts && !(msg->extraCerts = sk_X509_new_null())) goto err;
		for (i = 0; i < sk_X509_num(ctx->extraCerts); i++)
			sk_X509_push(msg->extraCerts, X509_dup(sk_X509_value(ctx->extraCerts, i)));
	}

	/* XXX what about setting the optional 2nd certreqmsg? */

	if( !(msg->protection = CMP_protection_new( msg, NULL, (EVP_PKEY *) ctx->pkey, ctx->secretValue))) goto err;

	/* XXX - should this be done somewhere else? */
	CMP_CTX_set1_protectionAlgor( ctx, msg->header->protectionAlg);

	return msg;

err:
	CMPerr(CMP_F_CMP_IR_NEW, CMP_R_CMPERROR);
	if (msg) CMP_PKIMESSAGE_free(msg);
	if (certReq0) CRMF_CERTREQMSG_free(certReq0);
	return NULL;
}

/* ############################################################################ */
/* ############################################################################ */
CMP_PKIMESSAGE * CMP_rr_new( CMP_CTX *ctx) {
	CMP_PKIMESSAGE  *msg=NULL;
	CRMF_CERTTEMPLATE *certTpl=NULL;
	X509_NAME *subject=NULL;

	/* check if all necessary options are set */
	if (!ctx) goto err;
#if 0
	if (!ctx->caCert) goto err;
#endif
	if (!ctx->clCert) goto err;
	if (!ctx->pkey) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;
	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_RR);

	{
		int subjKeyIDLoc;
		if( (subjKeyIDLoc = X509_get_ext_by_NID( (X509*) ctx->clCert, 
												 NID_subject_key_identifier, -1)) != -1) {
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

	if( !CMP_PKIHEADER_set1( msg->header, ctx)) goto err;

	if (ctx->implicitConfirm)
		if (! CMP_PKIMESSAGE_set_implicitConfirm(msg)) goto err;

	certTpl = CRMF_CERTTEMPLATE_new();
	/* Set the subject from the previous certificate */
	subject = X509_get_subject_name(ctx->clCert);
	X509_NAME_set(&certTpl->subject, subject);
	X509_PUBKEY_set(&certTpl->publicKey, (EVP_PKEY*) ctx->pkey);
	certTpl->serialNumber = ASN1_INTEGER_dup(ctx->clCert->cert_info->serialNumber);
	X509_NAME_set(&certTpl->issuer, ctx->clCert->cert_info->issuer);

	CMP_REVDETAILS *rd = CMP_REVDETAILS_new();
	rd->certDetails = certTpl;

	if( !(msg->body->value.rr = sk_CMP_REVDETAILS_new_null())) goto err;
	sk_CMP_REVDETAILS_push( msg->body->value.rr, rd);

	msg->protection = CMP_protection_new( msg, NULL, (EVP_PKEY*) ctx->pkey, ctx->secretValue);
	if (!msg->protection) goto err;

	CMP_CTX_set1_protectionAlgor( ctx, msg->header->protectionAlg);

	return msg;

err:
	CMPerr(CMP_F_CMP_RR_NEW, CMP_R_CMPERROR);
	if (msg) CMP_PKIMESSAGE_free(msg);
	if (certTpl) CRMF_CERTTEMPLATE_free(certTpl);
	return NULL;
}


/* ############################################################################ */
/* ############################################################################ */
CMP_PKIMESSAGE * CMP_cr_new( CMP_CTX *ctx) {
	CMP_PKIMESSAGE  *msg=NULL;
	CRMF_CERTREQMSG *certReq0=NULL;

	X509_NAME *subject=NULL; /* needed for COMPAT_INSTA */

	/* check if all necessary options are set */
	if (!ctx) goto err;
#if 0
	if (!ctx->caCert) goto err;
#endif
	if (!ctx->clCert) goto err;
	if (!ctx->pkey) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;

	if( !CMP_PKIHEADER_set1( msg->header, ctx)) goto err;

	if (ctx->implicitConfirm)
		if (! CMP_PKIMESSAGE_set_implicitConfirm(msg)) goto err;

	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_CR);

	/* Set the subject from the previous certificate */
	subject = X509_get_subject_name(ctx->clCert);

	/* XXX certReq 0 is not freed on error, but that's because it will become part of ir and is freed there */
	if( !(certReq0 = CRMF_cr_new(0L, ctx->pkey, subject, ctx->compatibility, ctx->popoMethod, NULL))) goto err;

	if( !(msg->body->value.cr = sk_CRMF_CERTREQMSG_new_null())) goto err;
	sk_CRMF_CERTREQMSG_push( msg->body->value.cr, certReq0);

	if (sk_X509_num(ctx->extraCerts) > 0) {
		int i;
		if( !msg->extraCerts && !(msg->extraCerts = sk_X509_new_null())) goto err;
		for (i = 0; i < sk_X509_num(ctx->extraCerts); i++)
			sk_X509_push(msg->extraCerts, X509_dup(sk_X509_value(ctx->extraCerts, i)));
	}

	/* XXX what about setting the optional 2nd certreqmsg? */

	msg->protection = CMP_protection_new( msg, NULL, (EVP_PKEY*) ctx->pkey, NULL);
	if (!msg->protection) goto err;

	/* XXX - should this be done somewhere else? */
	CMP_CTX_set1_protectionAlgor( ctx, msg->header->protectionAlg);

	return msg;

err:
	CMPerr(CMP_F_CMP_CR_NEW, CMP_R_CMPERROR);
	if (msg) CMP_PKIMESSAGE_free(msg);
	if (certReq0) CRMF_CERTREQMSG_free(certReq0);
	return NULL;
}


/* ############################################################################ */
/* ############################################################################ */
CMP_PKIMESSAGE * CMP_kur_new( CMP_CTX *ctx) {
	CMP_PKIMESSAGE *msg=NULL;
	CRMF_CERTREQMSG *certReq0=NULL;

	/* check if all necessary options are set */
	if (!ctx) goto err;
	if (!ctx->caCert) goto err;
	if (!ctx->clCert) goto err;
	if (!ctx->pkey) goto err;
	if (!ctx->newPkey) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;

	/* get the subject_key_id from the certificate to set it later as senderKID */
	/* XXX this is actually not required by the RFC but CL does like that */
	/*     Insta also seems to have problems when this is not set! */
	if( ctx->compatibility == CMP_COMPAT_CRYPTLIB || ctx->compatibility == CMP_COMPAT_INSTA_3_3) {
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
	if( !(certReq0 = CRMF_cr_new(0L, ctx->newPkey, X509_get_subject_name( (X509*) ctx->clCert), ctx->compatibility, ctx->popoMethod, NULL))) goto err;

	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_KUR);
	if( !(msg->body->value.kur = sk_CRMF_CERTREQMSG_new_null())) goto err;

	/* identify our cert */

	/* this is like it is described in the RFC:
	 * set oldCertId in "controls" of the CRMF cr message
	 * CL does not like this to be set */
	if( ctx->compatibility != CMP_COMPAT_CRYPTLIB) {
		CRMF_CERTREQMSG_set1_control_oldCertId( certReq0, ctx->clCert);
	}

	/* this is like CL likes it:
	 * set id-aa-signingCertificate "generalInfo" of the CMP header */
	if( ctx->compatibility == CMP_COMPAT_CRYPTLIB) {
		unsigned int hashLen;
		unsigned char hash[EVP_MAX_MD_SIZE];
		ESS_CERT_ID *essCertId = NULL;
		ESS_SIGNING_CERT *signingCert = NULL;
		CMP_INFOTYPEANDVALUE *itav = NULL;
		STACK_OF(ESS_SIGNING_CERT) *set = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x1000000fL 
		if (!X509_digest(ctx->clCert, EVP_sha1(), hash, &hashLen)) goto err;
		essCertId = ESS_CERT_ID_new();
		if (!ASN1_OCTET_STRING_set(essCertId->hash, hash, hashLen)) goto err;

		signingCert = ESS_SIGNING_CERT_new();
		if( !signingCert->cert_ids) {
			/* XXX free... */
			if( !(signingCert->cert_ids = sk_ESS_CERT_ID_new_null())) goto err;
		}
		if(!sk_ESS_CERT_ID_push(signingCert->cert_ids, essCertId)) goto err;

		if (!(set = sk_ESS_SIGNING_CERT_new_null())) goto err;
		sk_ESS_SIGNING_CERT_push(set, signingCert);
		itav = CMP_INFOTYPEANDVALUE_new();
		itav->infoType = OBJ_nid2obj( NID_id_smime_aa_signingCertificate);
		itav->infoValue.signingCertificate = set;
		CMP_PKIHEADER_generalInfo_item_push0( msg->header, itav);
#else
		unsigned char *itavValueDer=NULL;
		size_t itavValueDerLen;
		ASN1_STRING * itavValueStr=NULL;
		unsigned char *itavValueDerSet=NULL;

        if (!X509_digest(ctx->clCert, EVP_sha1(), hash, &hashLen)) goto err;
		essCertId = ESS_CERT_ID_new();
		if (!ASN1_OCTET_STRING_set(essCertId->certHash, hash, hashLen)) goto err;

		signingCert = ESS_SIGNING_CERT_new();
		if( !signingCert->certs) {
			/* XXX free... */
			if( !(signingCert->certs = sk_ESS_CERT_ID_new_null())) goto err;
		}
		if(!sk_ESS_CERT_ID_push(signingCert->certs, essCertId)) goto err;
		itavValueDerLen = i2d_ESS_SIGNING_CERT( signingCert, &itavValueDer);

		/* this is just wrong but CL does it:
		 * prepend an ASN.1 set to the id-aa-signingCertificate sequence */
		if( !(itavValueDerSet = OPENSSL_malloc( itavValueDerLen+2))) goto err;
		itavValueDerSet[0] = 0x31;
		itavValueDerSet[1] = itavValueDer[1]+2;
		memcpy( itavValueDerSet+2, itavValueDer, itavValueDerLen);

		itavValueStr = ASN1_STRING_new();
#if 0
		ASN1_STRING_set( itavValueStr, itavValueDer, itavValueDerLen);
#endif
		ASN1_STRING_set( itavValueStr, itavValueDerSet, itavValueDerLen+2);

		itav = CMP_INFOTYPEANDVALUE_new();
#if 0
		CMP_INFOTYPEANDVALUE_set0(itav, OBJ_nid2obj(NID_id_smime_aa_signingCertificate), V_ASN1_SEQUENCE, itavValueStr);
#endif
		/* CMP_INFOTYPEANDVALUE_set0(itav, OBJ_nid2obj( NID_id_smime_aa_signingCertificate), V_ASN1_SET, itavValueStr); */
		itav->infoType = OBJ_nid2obj( NID_id_smime_aa_signingCertificate);
		itav->infoValue.signingCertificate = set;
		CMP_PKIHEADER_generalInfo_item_push0( msg->header, itav);
#endif

	}

	sk_CRMF_CERTREQMSG_push( msg->body->value.kur, certReq0);

	
	if (sk_X509_num(ctx->extraCerts) > 0) {
		int i;
		if( !msg->extraCerts && !(msg->extraCerts = sk_X509_new_null())) goto err;
		for (i = 0; i < sk_X509_num(ctx->extraCerts); i++)
			sk_X509_push(msg->extraCerts, X509_dup(sk_X509_value(ctx->extraCerts, i)));
	}

	/* XXX what about setting the optional 2nd certreqmsg? */

	msg->protection = CMP_protection_new( msg, NULL, (EVP_PKEY*) ctx->pkey, NULL);
	if (!msg->protection) goto err;

	/* XXX - should this be done somewhere else? */
	CMP_CTX_set1_protectionAlgor( ctx, msg->header->protectionAlg);

	return msg;

err:
	CMPerr(CMP_F_CMP_KUR_NEW, CMP_R_CMPERROR);
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
	/* if (!ctx->caCert) goto err; */
	if (!ctx->newClCert) goto err;
	if ( (!ctx->pkey) && ((!ctx->referenceValue) && (!ctx->secretValue)) ) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;

	if( !CMP_PKIHEADER_set1(msg->header, ctx)) goto err;

	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_CERTCONF);

	/* TODO - there could be more than one certconf */
	/* TODO - do I have to free this in error case? */
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

	if( !(msg->body->value.certConf = sk_CMP_CERTSTATUS_new_null())) goto err;
	if( !sk_CMP_CERTSTATUS_push( msg->body->value.certConf, certStatus)) goto err;

	if( !(msg->protection = CMP_protection_new( msg, NULL, ctx->pkey, ctx->secretValue))) goto err;

	return msg;

err:
	CMPerr(CMP_F_CMP_CERTCONF_NEW, CMP_R_CMPERROR);
	if (msg) CMP_PKIMESSAGE_free(msg);
	return NULL;
}


/* ############################################################################ */
/* ############################################################################ */
CMP_PKIMESSAGE *CMP_genm_new( CMP_CTX *ctx) {
	CMP_PKIMESSAGE *msg=NULL;
#if 1
	CMP_INFOTYPEANDVALUE *itav=NULL;
#endif

	/* check if all necessary options are set */
	if (!ctx) goto err;

	/* XXX not setting senderNonce test for PKI INFO */
	ctx->setSenderNonce  = 0;
	/* XXX not setting transactionID test for PKI INFO */
	ctx->setTransactionID  = 1;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;

	if( !CMP_PKIHEADER_set1(msg->header, ctx)) goto err;

	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_GENM);

	itav = CMP_INFOTYPEANDVALUE_new();
	itav->infoType = OBJ_nid2obj(NID_id_it_preferredSymmAlg);
	itav->infoValue.ptr = NULL;
	CMP_PKIMESSAGE_genm_item_push0( msg, itav);

#if 0
	/* create an empty message body */
	if( CMP_PKIMESSAGE_genm_item_push0( msg, NULL)) {
		CMP_printf("INFO: created message body\n");
	}
#endif
#if 0
	itav = CMP_INFOTYPEANDVALUE_new();
	if( CMP_INFOTYPEANDVALUE_set0( itav, OBJ_txt2obj("1.3.6.1.5.5.7.4.4",1), V_ASN1_UNDEF, NULL)) {
		CMP_printf( "INFO: setting itav\n");
	} /* Preferred Symmetric Algorithm */
	if( CMP_PKIMESSAGE_genm_item_push0( msg, itav)) {
		CMP_printf( "INFO: pushing itav\n");
	}
#endif
#if 0
	itav = CMP_INFOTYPEANDVALUE_new();
	if( CMP_INFOTYPEANDVALUE_set0( itav, OBJ_txt2obj("1.3.6.1.5.5.7.4.6",1), V_ASN1_UNDEF, NULL)) {
		CMP_printf( "INFO: setting itav\n");
	} /* CRL */
	if( CMP_PKIMESSAGE_genm_item_push0( msg, itav)) {
		CMP_printf( "INFO: pushing itav\n");
	}
#endif
#if 0
	itav = CMP_INFOTYPEANDVALUE_new();
	if( CMP_INFOTYPEANDVALUE_set0( itav, OBJ_txt2obj("1.3.6.1.4.1.3029.3.1.2",1), V_ASN1_UNDEF, NULL)) {
		CMP_printf( "INFO: setting itav\n");
	} /* PKIBoot request */
	if( CMP_PKIMESSAGE_genm_item_push0( msg, itav)) {
		CMP_printf( "INFO: pushing itav\n");
	}
#endif
#if 0
	itav = CMP_INFOTYPEANDVALUE_new_by_def_noVal( CMP_ITAV_CRYPTLIB_PKIBOOT);
	if( CMP_PKIMESSAGE_genm_item_push0( msg, itav)) {
		CMP_printf( "INFO: pushing itav\n");
	}
#endif

	if (!(msg->protection = CMP_protection_new( msg, NULL, NULL, ctx->secretValue))) goto err;

	return msg;

err:
	CMPerr(CMP_F_CMP_GENM_NEW, CMP_R_CMPERROR);
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
	CMPerr(CMP_F_CMP_CKUANN_NEW, CMP_R_CMPERROR);

	if (msg) CMP_PKIMESSAGE_free(msg);
	return NULL;
}
