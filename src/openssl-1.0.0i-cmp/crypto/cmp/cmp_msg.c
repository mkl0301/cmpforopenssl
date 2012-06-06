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

/* ############################################################################ 
 * Takes a stack of GENERAL_NAMEs and adds them to the given extension stack.
 * ############################################################################ */
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

/* ############################################################################ 
 * Returns the trust chain for a given certificate up to and including
 * the trust anchor
 * ############################################################################ */
STACK_OF(X509) *CMP_build_cert_chain(X509_STORE *store, X509 *cert, int includeRoot) {
	X509_STORE_CTX *csc;
	STACK_OF(X509) *chain, *certs = NULL;
	X509 *last_cert = cert;
	int i;
	X509_STORE_set_flags(store, 0);

	if( !(csc = X509_STORE_CTX_new()))
		return NULL;
	if( !(chain = sk_X509_new_null())) {
		X509_STORE_CTX_free(csc);
		return NULL;
	}

	if(!X509_STORE_CTX_init(csc,store,cert,NULL))
		goto err;

	sk_X509_push(chain, X509_dup(cert));
	while ((certs = X509_STORE_get1_certs(csc, X509_get_issuer_name(last_cert))) != NULL) {
		X509 *issuer = NULL;
		for (i = 0; i < sk_X509_num(certs); i++) {
			X509 *current_cert = sk_X509_value(certs, i);
			EVP_PKEY *pubkey = X509_get_pubkey(current_cert);
			if (X509_verify(last_cert, pubkey)) {
				EVP_PKEY_free(pubkey);
				issuer = current_cert;
				break;
			}
			EVP_PKEY_free(pubkey);
		}
		sk_X509_pop_free(certs, X509_free);
		if (issuer == last_cert) {
			if (includeRoot)
				sk_X509_push(chain, X509_dup(last_cert));
			break;
		}
		if (issuer == NULL) break;
		last_cert = issuer;
		sk_X509_push(chain, X509_dup(last_cert));
	}
	X509_STORE_CTX_free(csc);

	return chain;
err:
	X509_STORE_CTX_free(csc);
	sk_X509_free(chain);
	return NULL;
}

/* ############################################################################ *
 * Creates a new polling request PKIMessage for the given request ID
 * ############################################################################ */
CMP_PKIMESSAGE * CMP_pollReq_new( CMP_CTX *ctx, int reqId) {
	CMP_PKIMESSAGE *msg = NULL;
	CMP_POLLREQ    *preq = NULL;
	if (!ctx) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;

	if( !CMP_PKIHEADER_set1( msg->header, ctx)) goto err;

	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_POLLREQ);

	preq = CMP_POLLREQ_new();
	/* TODO support multiple cert request ids to poll */
	ASN1_INTEGER_set(preq->certReqId, reqId);
	if (!(msg->body->value.pollReq = sk_CMP_POLLREQ_new_null()))
		goto err;

	sk_CMP_POLLREQ_push(msg->body->value.pollReq, preq);

	if( !(msg->protection = CMP_protection_new( msg, NULL, (EVP_PKEY *) ctx->pkey, ctx->secretValue))) 
		goto err;

	/* TODO: make a generic function to create msg protection and set this, do
	 * this for all message types */
	CMP_CTX_set1_protectionAlgor( ctx, msg->header->protectionAlg);
	return msg;

err:
	return NULL;
}

/* ############################################################################ *
 * Create a new Initial Request PKIMessage
 * ############################################################################ */
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
	/* for authentication we need either a reference value/secret or external identity certificate and private key */
	if (!((ctx->referenceValue && ctx->secretValue) || (ctx->pkey && ctx->clCert))) goto err;
	if (!ctx->newPkey) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;

	/* E.7: get the subject_key_id from the external identity certificate to set it later as senderKID */
	/* this actually seems to be explicity required not to be done by RFC 4210 (E.7, end of page 81)
	 * HOWEVER, it seems as if the RFC is wrong here and it confuses the different
	 * use cases of the senderKID field (referenceNUM vs. Key Identifier) */
	/* TODO: make this generic and bring it close together with CMP_protection_new() */
	if(ctx->clCert)
	{
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

	if( !CMP_PKIHEADER_set1( msg->header, ctx)) goto err;

	if (ctx->implicitConfirm)
		if (! CMP_PKIMESSAGE_set_implicitConfirm(msg)) goto err;

	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_IR);

	if (ctx->subjectName)
		subject = ctx->subjectName;
	else if (ctx->clCert) /* E.7 */
		subject = X509_get_subject_name(ctx->clCert);
	else
		subject = NULL;

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
	if( !(certReq0 = CRMF_cr_new(0L, ctx->newPkey, subject, ctx->compatibility, ctx->popoMethod, extensions))) goto err;

	if (extensions) sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);

	if( !(msg->body->value.ir = sk_CRMF_CERTREQMSG_new_null())) goto err;
	sk_CRMF_CERTREQMSG_push( msg->body->value.ir, certReq0);

	/* TODO: combine the following two blocks for adding extraCerts */
	/* E.7: if we have external identity cert add to extraCerts */
	if (ctx->clCert) {
		if( !msg->extraCerts && !(msg->extraCerts = sk_X509_new_null())) goto err;

		/* if we have untrusted store, try to add all the intermediate certs and our own */
		if (ctx->untrusted_store) {
			STACK_OF(X509) *chain = CMP_build_cert_chain(ctx->untrusted_store, ctx->clCert, 0);
			int i;
			for(i = 0; i < sk_X509_num(chain); i++)
				sk_X509_push(msg->extraCerts, sk_X509_value(chain, i));
			sk_X509_free(chain);
		}
		else if (sk_X509_num(msg->extraCerts) == 0)
			/* Make sure that at least our own cert gets sent */
			sk_X509_push(msg->extraCerts, X509_dup(ctx->clCert));
	}

	/* add any extraCertsOut that are set in the context */
	if (sk_X509_num(ctx->extraCertsOut) > 0) {
		int i;
		if( !msg->extraCerts && !(msg->extraCerts = sk_X509_new_null())) goto err;
		for (i = 0; i < sk_X509_num(ctx->extraCertsOut); i++)
			sk_X509_push(msg->extraCerts, X509_dup(sk_X509_value(ctx->extraCertsOut, i)));
	}

	/* XXX what about setting the optional 2nd certreqmsg? */

	if( !(msg->protection = CMP_protection_new( msg, NULL, (EVP_PKEY *) ctx->pkey, ctx->secretValue))) goto err;

	/* TODO: make a generic function to create msg protection and set this, do
	 * this for all message types */
	CMP_CTX_set1_protectionAlgor( ctx, msg->header->protectionAlg);

	return msg;

err:
	CMPerr(CMP_F_CMP_IR_NEW, CMP_R_CMPERROR);
	if (msg) CMP_PKIMESSAGE_free(msg);
	if (certReq0) CRMF_CERTREQMSG_free(certReq0);
	return NULL;
}

/* ############################################################################ *
 * Creates a new Revocation Request PKIMessage
 * ############################################################################ */
CMP_PKIMESSAGE * CMP_rr_new( CMP_CTX *ctx) {
	CMP_PKIMESSAGE  *msg=NULL;
	CRMF_CERTTEMPLATE *certTpl=NULL;
	X509_NAME *subject=NULL;
	CMP_REVDETAILS *rd=NULL;

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

	rd = CMP_REVDETAILS_new();
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


/* ############################################################################ *
 * Creates a new Certificate Request PKIMessage
 * ############################################################################ */
CMP_PKIMESSAGE * CMP_cr_new( CMP_CTX *ctx) {
	CMP_PKIMESSAGE  *msg=NULL;
	CRMF_CERTREQMSG *certReq0=NULL;

	X509_NAME *subject=NULL; /* needed for COMPAT_INSTA */
	int subjKeyIDLoc;

	/* check if all necessary options are set */
	if (!ctx) goto err;
	if (!ctx->caCert) goto err;
	if (!ctx->clCert) goto err;
	if (!ctx->pkey) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;

	/* TODO this is pasted around at least 3 times, refactor it... */
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

  /* TODO XXX: we should make sure to add an extra certs if we sign with a * certifcate */
	if (sk_X509_num(ctx->extraCertsOut) > 0) {
		int i;
		if( !msg->extraCerts && !(msg->extraCerts = sk_X509_new_null())) goto err;
		for (i = 0; i < sk_X509_num(ctx->extraCertsOut); i++)
			sk_X509_push(msg->extraCerts, X509_dup(sk_X509_value(ctx->extraCertsOut, i)));
	}

	if (ctx->untrusted_store) {
		/* attempt to get the trust chain for our certificate and send it along */
		STACK_OF(X509) *chain = CMP_build_cert_chain(ctx->untrusted_store, ctx->clCert, 0);
		int i;
		if( !msg->extraCerts && !(msg->extraCerts = sk_X509_new_null())) goto err;
		for(i = 0; i < sk_X509_num(chain); i++)
			sk_X509_push(msg->extraCerts, sk_X509_value(chain, i));
		sk_X509_free(chain);
	}

	if (sk_X509_num(msg->extraCerts) == 0)
		/* Make sure that at least our own cert gets sent */
		sk_X509_push(msg->extraCerts, X509_dup(ctx->clCert));

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


/* ############################################################################ *
 * Creates a new Key Update Request PKIMessage
 * TODO: KUR can actually also be done with MSG_MAC_ALG, check D.6, 2 *
 * ############################################################################ */
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
	/* this is not needed in case protection is done with MSG_MAC_ALG (what is not
	 * implemented so far) */
	if( ctx->clCert ) {
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

	
  /* TODO XXX: we should make sure to add an extra certs if we sign with a * certifcate */
	if (sk_X509_num(ctx->extraCertsOut) > 0) {
		int i;
		if( !msg->extraCerts && !(msg->extraCerts = sk_X509_new_null())) goto err;
		for (i = 0; i < sk_X509_num(ctx->extraCertsOut); i++)
			sk_X509_push(msg->extraCerts, X509_dup(sk_X509_value(ctx->extraCertsOut, i)));
	}

	if (ctx->untrusted_store) {
		/* attempt to get the trust chain for our certificate and send it along */
		STACK_OF(X509) *chain = CMP_build_cert_chain(ctx->untrusted_store, ctx->clCert, 0);
		int i;
		if( !msg->extraCerts && !(msg->extraCerts = sk_X509_new_null())) goto err;
		for(i = 0; i < sk_X509_num(chain); i++)
			sk_X509_push(msg->extraCerts, sk_X509_value(chain, i));
		sk_X509_free(chain);
	}

	if (sk_X509_num(msg->extraCerts) == 0)
		/* Make sure that at least our own cert gets sent */
		sk_X509_push(msg->extraCerts, X509_dup(ctx->clCert));

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


/* ############################################################################ *
 * Creates a new Certificate Confirmation PKIMessage
 * ############################################################################ */
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


/* ############################################################################ *
 * Creates a new General Message with the given nid as type and the given value
 * ############################################################################ */
CMP_PKIMESSAGE *CMP_genm_new( CMP_CTX *ctx, int nid, char *value) {
	CMP_PKIMESSAGE *msg=NULL;
	CMP_INFOTYPEANDVALUE *itav=NULL;

	/* check if all necessary options are set */
	if (!ctx) goto err;

#if 0
	/* XXX What were these for and are they still useful??? */

	/* XXX not setting senderNonce test for PKI INFO */
	ctx->setSenderNonce  = 1;
	/* XXX not setting transactionID test for PKI INFO */
	ctx->setTransactionID  = 1;
#endif

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;

	if( !CMP_PKIHEADER_set1(msg->header, ctx)) goto err;

	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_GENM);

	itav = CMP_INFOTYPEANDVALUE_new();
	itav->infoType = OBJ_nid2obj(nid);
	itav->infoValue.ptr = value;
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