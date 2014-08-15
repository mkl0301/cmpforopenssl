/* vim: set noet ts=4 sts=4 sw=4: */
/* crypto/cmp/cmp_msg.c
 * Functions for creating CMP (RFC 4210) messages for OpenSSL
 */
/* ====================================================================
 * Originally written by Martin Peylo for the OpenSSL project.
 * <martin dot peylo at nsn dot com>
 * 2010-2014 Miikka Viljanen <mviljane@users.sourceforge.net>
 */
/* ====================================================================
 * Copyright (c) 2007-2010 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *	  software must display the following acknowledgment:
 *	  "This product includes software developed by the OpenSSL Project
 *	  for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *	  endorse or promote products derived from this software without
 *	  prior written permission. For written permission, please contact
 *	  openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *	  nor may "OpenSSL" appear in their names without prior written
 *	  permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *	  acknowledgment:
 *	  "This product includes software developed by the OpenSSL Project
 *	  for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.	IN NO EVENT SHALL THE OpenSSL PROJECT OR
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
 * Copyright 2007-2014 Nokia Oy. ALL RIGHTS RESERVED.
 * CMP support in OpenSSL originally developed by 
 * Nokia for contribution to the OpenSSL project.
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
 * this is used to setting subject alternate names to a certTemplate
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
static int add_altname_extensions(X509_EXTENSIONS **extensions, STACK_OF(GENERAL_NAME) *altnames, int critical)
	{
	X509_EXTENSION *ext = NULL;
	unsigned char *der = NULL;
	int derlen = 0;
	ASN1_OCTET_STRING *str = NULL;;

	if(!extensions) goto err;
	if(!altnames) goto err;

	if(!(str = ASN1_OCTET_STRING_new())) goto err;

	if(!(ASN1_seq_pack_GENERAL_NAME(altnames, i2d_GENERAL_NAME, &der, &derlen))) goto err;

	if(!ASN1_STRING_set(str, der, derlen)) goto err;
	if(!X509_EXTENSION_create_by_NID(&ext, NID_subject_alt_name, critical, str)) goto err;

	ASN1_OCTET_STRING_free(str);
	OPENSSL_free(der);

	if(!X509v3_add_ext(extensions, ext, 0)) goto err;

	X509_EXTENSION_free(ext);

	return 1;
err:
	if (ext) X509_EXTENSION_free(ext);
	return 0;
	}

static int add_policy_extensions(X509_EXTENSIONS **extensions, CERTIFICATEPOLICIES *policies)
	{
	X509_EXTENSION *ext = NULL;
	unsigned char *der = NULL;
	int derlen = 0;
	ASN1_OCTET_STRING *str = NULL;

	if(!extensions || !policies) goto err;

	if(!(str = ASN1_OCTET_STRING_new())) goto err;

	derlen = i2d_CERTIFICATEPOLICIES(policies, &der);
	if(!ASN1_STRING_set(str, der, derlen)) goto err;
	if(!X509_EXTENSION_create_by_NID(&ext, NID_certificate_policies, 1, str)) goto err;

	ASN1_OCTET_STRING_free(str);
	OPENSSL_free(der);

	if(!X509v3_add_ext(extensions, ext, 0)) goto err;

	X509_EXTENSION_free(ext);

	return 1;
err:
	if (ext) X509_EXTENSION_free(ext);
	return 0;
	}

/* ############################################################################
 * Adds the certificates to the extraCerts fields in the given message.  For
 * this it tries to build the certificate chain of our client cert (ctx->clCert)
 * by using certificates in ctx->untrusted_store. If no untrusted store is set, 
 * it will at least place the client certificate into extraCerts.
 * Additionally all the certificates explicitly specified to be sent out
 * (i.e. ctx->extraCertsOut) are added to the stack.
 *
 * Note: it will NOT put the trust anchor in the extraCerts - unless it would be
 * in the untrusted store.
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
static int add_extraCerts(CMP_CTX *ctx, CMP_PKIMESSAGE *msg)
	{
	int i;

	if (!ctx) goto err;
	if (!msg) goto err;
	if (!msg->extraCerts && !(msg->extraCerts = sk_X509_new_null())) goto err;

	/* add any additional certificates from ctx->extraCertsOut */
	for (i = 0; i < sk_X509_num(ctx->extraCertsOut); i++)
		sk_X509_push(msg->extraCerts, X509_dup(sk_X509_value(ctx->extraCertsOut, i)));

	if (ctx->clCert)
		{
		/* if we have untrusted store, try to add all the intermediate certs and our own */
		if (ctx->untrusted_store)
			{
			STACK_OF(X509) *chain = CMP_build_cert_chain(ctx->untrusted_store, ctx->clCert);
			int i;
			for(i = 0; i < sk_X509_num(chain); i++)
				{
				X509 *cert = sk_X509_value(chain, i);
				sk_X509_push(msg->extraCerts, cert);
				}
			sk_X509_free(chain); /* only frees the stack, not the content */
			} else {
			/* Make sure that at least our own cert gets sent */
			sk_X509_push(msg->extraCerts, X509_dup(ctx->clCert));
			}
		}

	return 1;

err:
	return 0;
	}

/* ############################################################################ *
 * Creates a new polling request PKIMessage for the given request ID
 * returns a pointer to the PKIMessage on success, NULL on error
 * ############################################################################ */
CMP_PKIMESSAGE * CMP_pollReq_new( CMP_CTX *ctx, int reqId)
	{
	CMP_PKIMESSAGE *msg = NULL;
	CMP_POLLREQ    *preq = NULL;
	if (!ctx) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;
	if( !CMP_PKIHEADER_init( ctx, msg->header)) goto err;
	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_POLLREQ);

	if(!(preq = CMP_POLLREQ_new())) goto err;
	/* TODO support multiple cert request ids to poll */
	ASN1_INTEGER_set(preq->certReqId, reqId);
	if (!(msg->body->value.pollReq = sk_CMP_POLLREQ_new_null()))
		goto err;

	sk_CMP_POLLREQ_push(msg->body->value.pollReq, preq);

	if(!CMP_PKIMESSAGE_protect(ctx, msg)) goto err;

	return msg;
err:
	CMPerr(CMP_F_CMP_POLLREQ_NEW, CMP_R_ERROR_CREATING_POLLREQ);
	if (msg) CMP_PKIMESSAGE_free(msg);
	return NULL;
	}

/* ############################################################################ *
 * Create a new Initial Request PKIMessage based on the settings in given ctx
 * returns a pointer to the PKIMessage on success, NULL on error
 * ############################################################################ */
CMP_PKIMESSAGE * CMP_ir_new( CMP_CTX *ctx)
	{
	CMP_PKIMESSAGE	*msg=NULL;
	CRMF_CERTREQMSG *certReq0=NULL;
	X509_EXTENSIONS *extensions = NULL;
	X509_NAME *subject=NULL;

	if (!ctx) goto err;

	/* for authentication we need either a reference value/secret or external identity certificate (E.7) and private key */
	if (!((ctx->referenceValue && ctx->secretValue) || (ctx->pkey && ctx->clCert))) goto err;

	/* new key pair for new Certificate must be set */
	if (!ctx->newPkey) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;
	if (!CMP_PKIHEADER_init( ctx, msg->header)) goto err;

	/* Add Insta CA profile ID */
	if (ctx->profileID != 0) {
		CMP_INFOTYPEANDVALUE *itav = CMP_INFOTYPEANDVALUE_new();
		itav->infoType = OBJ_txt2obj("1.3.6.1.4.1.36878.3.3.1.1", 1);
		itav->infoValue.other = ASN1_TYPE_new();
		itav->infoValue.other->type = V_ASN1_INTEGER;
		itav->infoValue.other->value.integer = ASN1_INTEGER_new();
		ASN1_INTEGER_set(itav->infoValue.other->value.integer, ctx->profileID);
		CMP_PKIHEADER_generalInfo_item_push0(msg->header, itav);
	}

	if (ctx->implicitConfirm)
		if (! CMP_PKIMESSAGE_set_implicitConfirm(msg)) goto err;
	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_IR);

	if (ctx->subjectName)
		subject = ctx->subjectName;
	else if (ctx->clCert && sk_GENERAL_NAME_num(ctx->subjectAltNames) <= 0)
		/* get subject name from existing certificate (E.7) */
		subject = X509_get_subject_name(ctx->clCert);
	else
		subject = NULL;

	if (sk_GENERAL_NAME_num(ctx->subjectAltNames) > 0)
		/* According to RFC5280, subjectAltName MUST be critical if subject is null */
		add_altname_extensions(&extensions, ctx->subjectAltNames, ctx->setSubjectAltNameCritical || subject == NULL);

	if (ctx->policies)
		add_policy_extensions(&extensions, ctx->policies);

	if (!(msg->body->value.ir = sk_CRMF_CERTREQMSG_new_null())) goto err;
	if (!(certReq0 = CRMF_cr_new(0L, ctx->newPkey, subject, extensions))) goto err;
	sk_CRMF_CERTREQMSG_push( msg->body->value.ir, certReq0);
	/* TODO: here also the optional 2nd certreqmsg could be pushed to the stack */

    /* sets the id-regCtrl-regToken to regInfo (not described in RFC, but EJBCA
	 * in CA mode might insist on that) */
	if (ctx->regToken)
		if (!CRMF_CERTREQMSG_set1_regInfo_regToken(certReq0, ctx->regToken)) goto err;

	CRMF_CERTREQMSG_calc_and_set_popo( certReq0, ctx->newPkey, ctx->popoMethod);

	add_extraCerts(ctx, msg);
	if (!CMP_PKIMESSAGE_protect(ctx, msg)) goto err;

	/* cleanup */
	if (extensions) sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
	
	return msg;

err:
	CMPerr(CMP_F_CMP_IR_NEW, CMP_R_ERROR_CREATING_IR);
	if (extensions) sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
	if (msg) CMP_PKIMESSAGE_free(msg);
	return NULL;
	}

/* ############################################################################ *
 * Creates a new Revocation Request PKIMessage based on the settings in ctx
 * returns a pointer to the PKIMessage on success, NULL on error
 * ############################################################################ */
CMP_PKIMESSAGE * CMP_rr_new( CMP_CTX *ctx)
	{
	CMP_PKIMESSAGE	*msg=NULL;
	CRMF_CERTTEMPLATE *certTpl=NULL;
	X509_NAME *subject=NULL;
	CMP_REVDETAILS *rd=NULL;

	if (!ctx) goto err;
	if (!ctx->clCert) goto err;
	if (!ctx->pkey) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;
	if (!CMP_PKIHEADER_init( ctx, msg->header)) goto err;
	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_RR);

	if (!(msg->body->value.rr = sk_CMP_REVDETAILS_new_null())) goto err;
	if (!(rd = CMP_REVDETAILS_new())) goto err;
	sk_CMP_REVDETAILS_push( msg->body->value.rr, rd);

	if (!(certTpl = CRMF_CERTTEMPLATE_new())) goto err;
	rd->certDetails = certTpl;

	/* Set the subject from the previous certificate */
	if (!(subject = X509_get_subject_name(ctx->clCert))) goto err;
	X509_NAME_set(&certTpl->subject, subject);
	X509_PUBKEY_set(&certTpl->publicKey, ctx->pkey);
	if (!(certTpl->serialNumber = ASN1_INTEGER_dup(ctx->clCert->cert_info->serialNumber))) goto err;
	X509_NAME_set(&certTpl->issuer, ctx->clCert->cert_info->issuer);

	/* TODO: the Revocation Passphrase according to section 5.3.19.9 could be set here if set in ctx */

	if(!CMP_PKIMESSAGE_protect(ctx, msg)) goto err;

	return msg;

err:
	CMPerr(CMP_F_CMP_RR_NEW, CMP_R_ERROR_CREATING_RR);
	if (msg) CMP_PKIMESSAGE_free(msg);

	return NULL;
	}

/* ############################################################################ *
 * Creates a new Certificate Request PKIMessage based on the settings in ctx
 * returns a pointer to the PKIMessage on success, NULL on error
 * ############################################################################ */
CMP_PKIMESSAGE * CMP_cr_new( CMP_CTX *ctx)
	{
	CMP_PKIMESSAGE	*msg=NULL;
	CRMF_CERTREQMSG *certReq0=NULL;
	X509_NAME *subject=NULL;

	if (!ctx) goto err;
	/* for authentication we need either a reference value/secret for MSG_MAC_ALG 
	 * or existing certificate and private key for MSG_SIG_ALG */
	if (!((ctx->referenceValue && ctx->secretValue) || (ctx->pkey && ctx->clCert))) goto err;
	if (!ctx->pkey) goto err;

	if (ctx->subjectName)
		subject = ctx->subjectName;
	else if (ctx->clCert) /* get subject name from existing certificate */
		subject = X509_get_subject_name(ctx->clCert);
	else
		goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;
	if (!CMP_PKIHEADER_init( ctx, msg->header)) goto err;
	if (ctx->implicitConfirm)
		if (! CMP_PKIMESSAGE_set_implicitConfirm(msg)) goto err;
	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_CR);

	if (!(msg->body->value.cr = sk_CRMF_CERTREQMSG_new_null())) goto err;
	if (!(certReq0 = CRMF_cr_new(0L, ctx->pkey, subject, NULL))) goto err;
	sk_CRMF_CERTREQMSG_push( msg->body->value.cr, certReq0);
	/* TODO: here also the optional 2nd certreqmsg could be pushed to the stack */

	CRMF_CERTREQMSG_calc_and_set_popo( certReq0, ctx->pkey, ctx->popoMethod);

	add_extraCerts(ctx, msg);
	if (!CMP_PKIMESSAGE_protect(ctx, msg)) goto err;

	return msg;

err:
	CMPerr(CMP_F_CMP_CR_NEW, CMP_R_ERROR_CREATING_CR);
	if (msg) CMP_PKIMESSAGE_free(msg);
	return NULL;
	}

/* ############################################################################ *
 * Creates a new Key Update Request PKIMessage based on the settings in ctx
 * returns a pointer to the PKIMessage on success, NULL on error
 * TODO: the differentiation between certificate used to sign the CMP messages
 * and the certificate to update should be improved - so far only the clCert
 * could be updated
 * ############################################################################ */
CMP_PKIMESSAGE * CMP_kur_new( CMP_CTX *ctx)
	{
	CMP_PKIMESSAGE *msg=NULL;
	CRMF_CERTREQMSG *certReq0=NULL;
	X509_EXTENSIONS *extensions = NULL;
	X509_NAME *subject=NULL;

	if (!ctx) goto err;
	/* for authentication we need either a reference value/secret for MSG_MAC_ALG 
	 * or existing certificate and private key for MSG_SIG_ALG */
	if (!((ctx->referenceValue && ctx->secretValue) || (ctx->pkey && ctx->clCert))) goto err;
	if (!ctx->newPkey) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;
	if (!CMP_PKIHEADER_init( ctx, msg->header)) goto err;
	if (ctx->implicitConfirm)
		if (! CMP_PKIMESSAGE_set_implicitConfirm( msg)) goto err;
	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_KUR);

	if (ctx->subjectName)
		subject = ctx->subjectName;
	else
		subject = X509_get_subject_name( (X509*) ctx->clCert); /* TODO: from certificate to be renewed */

	if (sk_GENERAL_NAME_num(ctx->subjectAltNames) > 0)
		/* According to RFC5280, subjectAltName MUST be critical if subject is null */
		add_altname_extensions(&extensions, ctx->subjectAltNames, ctx->setSubjectAltNameCritical || subject == NULL);

	if (ctx->policies)
		add_policy_extensions(&extensions, ctx->policies);

	if (!(msg->body->value.kur = sk_CRMF_CERTREQMSG_new_null())) goto err;
	if (!(certReq0 = CRMF_cr_new(0L, ctx->newPkey, subject, extensions))) goto err;
	sk_CRMF_CERTREQMSG_push( msg->body->value.kur, certReq0);
	/* TODO: here also the optional 2nd certreqmsg could be pushed to the stack */

	/* setting OldCertId according to D.6:
	   7.  regCtrl OldCertId SHOULD be used */

	if (ctx->oldClCert)
		CRMF_CERTREQMSG_set1_control_oldCertId( certReq0, ctx->oldClCert);
	else
		CRMF_CERTREQMSG_set1_control_oldCertId( certReq0, ctx->clCert);


	CRMF_CERTREQMSG_calc_and_set_popo( certReq0, ctx->newPkey, ctx->popoMethod);

	add_extraCerts(ctx, msg);
	if (!CMP_PKIMESSAGE_protect(ctx, msg)) goto err;

	if (extensions) sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);

	return msg;

err:
	CMPerr(CMP_F_CMP_KUR_NEW, CMP_R_ERROR_CREATING_KUR);
	if (msg) CMP_PKIMESSAGE_free(msg);
	if (extensions) sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
	return NULL;
	}

/* ############################################################################ *
 * Creates a new Certificate Confirmation PKIMessage
 * returns a pointer to the PKIMessage on success, NULL on error
 * TODO: handle both possible certificates when signing and encrypting
 * certificates have been requested/received
 * ############################################################################ */
CMP_PKIMESSAGE * CMP_certConf_new( CMP_CTX *ctx)
	{
	CMP_PKIMESSAGE *msg=NULL;
	CMP_CERTSTATUS *certStatus=NULL;

	if (!ctx) goto err;
	/* for authentication we need either a reference value/secret for MSG_MAC_ALG 
	 * or existing certificate and private key for MSG_SIG_ALG */
	if (!((ctx->referenceValue && ctx->secretValue) || (ctx->pkey && ctx->clCert))) goto err;
	if (!ctx->newClCert) goto err; /* in this case we wouldn't have received a certificate */

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;
	if (!CMP_PKIHEADER_init( ctx, msg->header)) goto err;
	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_CERTCONF);
	if (!(msg->body->value.certConf = sk_CMP_CERTSTATUS_new_null())) goto err;

	if (!(certStatus = CMP_CERTSTATUS_new())) goto err;
	if (!sk_CMP_CERTSTATUS_push( msg->body->value.certConf, certStatus)) goto err;
	/* set the # of the certReq */
	ASN1_INTEGER_set(certStatus->certReqId,0L);
	/* -- the hash of the certificate, using the same hash algorithm
	 * -- as is used to create and verify the certificate signature */
	CMP_CERTSTATUS_set_certHash( certStatus, ctx->newClCert);

	/* execute the callback function set in ctx which can be used to examine a
	 * certificate and reject it */
	if (ctx->certConf_cb && ctx->newClCert && ctx->certConf_cb(ctx->lastPKIStatus, ctx->newClCert) == 0)
		{
		certStatus->statusInfo = CMP_PKISTATUSINFO_new();
		ASN1_INTEGER_set(certStatus->statusInfo->status, CMP_PKISTATUS_rejection);
		CMP_printf(ctx, "INFO: rejecting certificate.");
		}

	if (!CMP_PKIMESSAGE_protect(ctx, msg)) goto err;

	return msg;

err:
	CMPerr(CMP_F_CMP_CERTCONF_NEW, CMP_R_ERROR_CREATING_CERTCONF);
	if (msg) CMP_PKIMESSAGE_free(msg);

	return NULL;
	}

/* ############################################################################ *
 * Creates a new General Message with an empty itav stack
 * returns a pointer to the PKIMessage on success, NULL on error
 * ############################################################################ */
CMP_PKIMESSAGE *CMP_genm_new( CMP_CTX *ctx)
	{
	CMP_PKIMESSAGE *msg=NULL;

	if (!ctx) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;
	if (!CMP_PKIHEADER_init( ctx, msg->header)) goto err;
	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_GENM);
	if (!(msg->body->value.genm = sk_CMP_INFOTYPEANDVALUE_new_null())) goto err; /* initialize with empty stack */

	if (!CMP_PKIMESSAGE_protect(ctx, msg)) goto err;

	return msg;

err:
	CMPerr(CMP_F_CMP_GENM_NEW, CMP_R_ERROR_CREATING_GENM);
	if (msg) CMP_PKIMESSAGE_free(msg);
	return NULL;
	}

