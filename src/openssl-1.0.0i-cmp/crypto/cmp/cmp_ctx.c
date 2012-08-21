/* vim: set noet ts=4 sts=4 sw=4: */
/* crypto/cmp/cmp_ctx.c
 * CMP (RFC 4210) context functions for OpenSSL
 */
/* ====================================================================
 * Originally written by Martin Peylo for the OpenSSL project.
 * <martin dot peylo at nsn dot com>
 * 2010-2012 Miikka Viljanen <mviljane@users.sourceforge.net>
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
 * Copyright 2007-2010 Nokia Siemens Networks Oy. ALL RIGHTS RESERVED.
 * CMP support in OpenSSL originally developed by 
 * Nokia Siemens Networks for contribution to the OpenSSL project.
 */

/* =========================== CHANGE LOG =============================
 * 2007 - Martin Peylo - Initial Creation
 */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <string.h>
#include <dirent.h>

/* NAMING
 * The 0 version uses the supplied structure pointer directly in the parent and
 * it will be freed up when the parent is freed. In the above example crl would
 * be freed but rev would not.
 *
 * The 1 function uses a copy of the supplied structure pointer (or in some
 * cases increases its link count) in the parent and so both (x and obj above)
 * should be freed up.
 */

ASN1_SEQUENCE(CMP_CTX) = {
	ASN1_OPT(CMP_CTX, referenceValue, ASN1_OCTET_STRING),
	ASN1_OPT(CMP_CTX, secretValue, ASN1_OCTET_STRING),
	ASN1_OPT(CMP_CTX, regToken, ASN1_UTF8STRING),
	ASN1_OPT(CMP_CTX, srvCert, X509),
	ASN1_OPT(CMP_CTX, clCert, X509),
	ASN1_OPT(CMP_CTX, subjectName, X509_NAME),
	ASN1_OPT(CMP_CTX, recipient, X509_NAME),
	ASN1_SEQUENCE_OF_OPT(CMP_CTX, subjectAltNames, GENERAL_NAME),
	ASN1_SEQUENCE_OF_OPT(CMP_CTX, caPubs, X509),
	ASN1_SEQUENCE_OF_OPT(CMP_CTX, extraCertsOut, X509),
	ASN1_SEQUENCE_OF_OPT(CMP_CTX, extraCertsIn, X509),
	/* EVP_PKEY *pkey */
	ASN1_OPT(CMP_CTX, newClCert, X509),
	/* EVP_PKEY *newPkey */
	ASN1_OPT(CMP_CTX, transactionID, ASN1_OCTET_STRING),
	ASN1_OPT(CMP_CTX, recipNonce, ASN1_OCTET_STRING),
	ASN1_OPT(CMP_CTX, validatedSrvCert, X509),
#if 0
	/* this is actually CMP_PKIFREETEXT which is STACK_OF(ANS1_UTF8STRING) */
	ASN1_SEQUENCE_OPT(CMP_CTX, freeText, STACK_OF(UTF8STRING));
#endif
	/* the following are not ASN1 types and present in the declaration in cmp.h
	 * char *serverName
	 * int serverPort
	 * int transport
	 * int implicitConfirm
	 * int setSenderNonce
	 * int setTransactionID
	 * int popoMethod
	 * int timeOut
	 */
} ASN1_SEQUENCE_END(CMP_CTX)
IMPLEMENT_ASN1_FUNCTIONS(CMP_CTX)

/* ############################################################################ *
 * Returns a duplicate of the given stack of X509 certificates.
 * ############################################################################ */
static STACK_OF(X509)* X509_stack_dup(const STACK_OF(X509)* stack)
{
	STACK_OF(X509) *newsk = NULL;
	int i;

	if (!stack) goto err;
	if (!(newsk = sk_X509_new_null())) goto err;

	for (i = 0; i < sk_X509_num(stack); i++)
		sk_X509_push(newsk, X509_dup(sk_X509_value(stack, i)));

	return newsk;
err:
	return 0;
}

/* ############################################################################ *
 * Creates a copy of the given EVP_PKEY.
 * ############################################################################ */
static EVP_PKEY *pkey_dup(const EVP_PKEY *pkey)
{
	EVP_PKEY *pkeyDup = EVP_PKEY_new();
	if (!pkeyDup) goto err;
	
	switch (pkey->type) {
#ifndef OPENSSL_NO_RSA
		case EVP_PKEY_RSA:
			EVP_PKEY_set1_RSA(pkeyDup, pkey->pkey.rsa);
			break;
#endif
#ifndef OPENSSL_NO_DSA
		case EVP_PKEY_DSA: 
			EVP_PKEY_set1_DSA(pkeyDup, pkey->pkey.dsa);
			break;
#endif
#ifndef OPENSSL_NO_DH
		case EVP_PKEY_DH:
			EVP_PKEY_set1_DH(pkeyDup, pkey->pkey.dh);
			break;
#endif
#ifndef OPENSSL_NO_EC
		case EVP_PKEY_EC:
			EVP_PKEY_set1_EC_KEY(pkeyDup, pkey->pkey.ec);
			break;
#endif
		default: 
			CMPerr(CMP_F_PKEY_DUP, CMP_R_UNSUPPORTED_KEY_TYPE);
			goto err;
	}
	return pkeyDup;

err:
	if (pkeyDup) EVP_PKEY_free(pkeyDup);
	return NULL;
}

;
/* ############################################################################ *
 * Set certificate store containing root CA certs.
 * ############################################################################ */
int CMP_CTX_set0_trustedStore( CMP_CTX *ctx, X509_STORE *store) {
	if (!store) return 0;
	if (ctx->trusted_store)
		X509_STORE_free(ctx->trusted_store);
	ctx->trusted_store = store;
	return 1;
}

#if 0
int CMP_CTX_set1_trustedStore( CMP_CTX *ctx, X509_STORE *store) {
	X509_STORE *dup = NULL;
	if (!store) return 0;
	if (!(dup = X509_STORE_dup(store))) return 0;
	return CMP_CTX_trustedStore_set0(ctx, dup);
}
#endif

/* ############################################################################ *
 * Set certificate store containing intermediate certificates (for building
 * our own cert chain to send in extraCerts).
 * ############################################################################ */
int CMP_CTX_set0_untrustedStore( CMP_CTX *ctx, X509_STORE *store) {
	if (!store) return 0;
	if (ctx->untrusted_store)
		X509_STORE_free(ctx->untrusted_store);
	ctx->untrusted_store = store;
	return 1;
}

#if 0
int CMP_CTX_set1_untrustedStore( CMP_CTX *ctx, X509_STORE *store) {
	X509_STORE *dup = NULL;
	if (!store) return 0;
	if (!(dup = X509_STORE_dup(store))) return 0;
	return CMP_CTX_untrustedStore_set0(ctx, dup);
}
#endif

/* ################################################################ *
 * Allocates and initializes a CMP_CTX context structure with some 
 * default values.
 * ################################################################ */
int CMP_CTX_init( CMP_CTX *ctx) {
	if (!ctx) {
		CMPerr(CMP_F_CMP_CTX_INIT, CMP_R_INVALID_CONTEXT);
		goto err;
	}

	/* all other elements are initialized through ASN1 macros */
	ctx->pkey			 = NULL;
	ctx->newPkey		 = NULL;
	ctx->serverName		 = NULL;
	/* serverPath has to be an empty sting if not set since it is not mandatory */
	/* this will be freed by CMP_CTX_delete() */
	ctx->serverPath		 = OPENSSL_malloc(1);
	ctx->serverPath[0]	 = 0;
	ctx->serverPort		 = 0;
	ctx->proxyName		 = NULL;
	ctx->proxyPort		 = 0;
	ctx->transport		 = CMP_TRANSPORT_HTTP;
	ctx->implicitConfirm = 0;
	ctx->setSenderNonce  = 1;
	ctx->setTransactionID= 1;
	ctx->popoMethod		 = CRMF_POPO_SIGNATURE;
	ctx->timeOut		 = 2*60;
	ctx->validatePath	 = 0;

	ctx->error_cb = NULL;
	ctx->debug_cb = (cmp_logfn_t) puts;
	ctx->certConf_cb = NULL;

	ctx->trusted_store	 = X509_STORE_new();
	ctx->untrusted_store = X509_STORE_new();

	ctx->maxPollCount = 3;

	ctx->lastStatus = -1;
	ctx->failInfoCode = 0;

	ctx->permitTAInExtraCertsForIR = 1;
	ctx->validatedSrvCert = NULL;

#if 0
	/* These are initialized already by the call to CMP_CTX_new() */
	ctx->referenceValue  = NULL;
	ctx->secretValue	 = NULL;
	ctx->srvCert		 = NULL;
	ctx->clCert			 = NULL;
	ctx->newClCert		 = NULL;
	ctx->transactionID	 = NULL;
	ctx->recipNonce		 = NULL;
	ctx->subjectName	 = NULL;
	ctx->recipient		 = NULL;
	ctx->subjectAltNames = NULL;
	ctx->caPubs			 = NULL;
	ctx->extraCertsOut	 = NULL;
	ctx->extraCertsIn	 = NULL;
#endif

	/* initialize OpenSSL */
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();

	return 1;

err:
	return 0;
}

/* ################################################################ */
/* frees CMP_CTX variables allocated in CMP_CTX_init and calls CMP_CTX_free */
/* ################################################################ */
void CMP_CTX_delete(CMP_CTX *ctx) {
	if (!ctx) return;
	if (ctx->serverPath) OPENSSL_free(ctx->serverPath);
	if (ctx->serverName) OPENSSL_free(ctx->serverName);
	if (ctx->proxyName) OPENSSL_free(ctx->proxyName);
	CMP_CTX_free(ctx);
}


/* ################################################################ */
/* creates and initializes a CMP_CTX structure */
/* ################################################################ */
CMP_CTX *CMP_CTX_create(void) {
	CMP_CTX *ctx=NULL;

	if( !(ctx = CMP_CTX_new())) goto err;
	if( !(CMP_CTX_init(ctx))) goto err;

	return ctx;
err:
	CMPerr(CMP_F_CMP_CTX_CREATE, CMP_R_UNABLE_TO_CREATE_CONTEXT);
	if (ctx) CMP_CTX_free(ctx);
	return NULL;
}

unsigned long CMP_CTX_get_failInfoCode( CMP_CTX *ctx)
{
	if (!ctx) goto err;
	return ctx->failInfoCode;
err:
	return 0;
}

/* ################################################################ *
 * Set callback function for checking if the cert is ok or should
 * it be rejected.
 * ################################################################ */
int CMP_CTX_set_certConf_callback( CMP_CTX *ctx, cmp_certConfFn_t cb)
{
	if (!ctx || !cb) goto err;
	ctx->certConf_cb = cb;
err:
	return 0;
}

/* ################################################################ *
 * Set a callback function which will receive debug messages.
 * ################################################################ */
int CMP_CTX_set_error_callback( CMP_CTX *ctx, cmp_logfn_t cb)
{
	if (!ctx || !cb) goto err;
	ctx->error_cb = cb;
err:
	return 0;
}

/* ################################################################ *
 * Set a callback function which will receive error messages.
 * ################################################################ */
int CMP_CTX_set_debug_callback( CMP_CTX *ctx, cmp_logfn_t cb)
{
	if (!ctx || !cb) goto err;
	ctx->debug_cb = cb;
err:
	return 0;
}

/* ################################################################ *
 * Set the reference value to be used for identification (i.e. the 
 * username) when using PBMAC.
 * ################################################################ */
int CMP_CTX_set1_referenceValue( CMP_CTX *ctx, const unsigned char *ref, size_t len) {
	if (!ctx || !ref) {
		CMPerr(CMP_F_CMP_CTX_SET1_REFERENCEVALUE, CMP_R_INVALID_PARAMETERS);
		goto err;
	}

	if (!ctx->referenceValue)
		ctx->referenceValue = ASN1_OCTET_STRING_new();

	return (ASN1_OCTET_STRING_set(ctx->referenceValue, ref, len));
err:
	return 0;
}

/* ################################################################ *
 * Set the password to be used for protecting messages with PBMAC
 * ################################################################ */
int CMP_CTX_set1_secretValue( CMP_CTX *ctx, const unsigned char *sec, const size_t len) {
	if (!ctx) goto err;
	if (!sec) goto err;

	if (!ctx->secretValue)
		ctx->secretValue = ASN1_OCTET_STRING_new();

	return (ASN1_OCTET_STRING_set(ctx->secretValue, sec, len));
err:
	CMPerr(CMP_F_CMP_CTX_SET1_SECRETVALUE, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Set the registration token value (the password for EJBCA for example)
 * ################################################################ */
int CMP_CTX_set1_regToken( CMP_CTX *ctx, const char *regtoken, const size_t len) {
	if (!ctx) goto err;
	if (!regtoken) goto err;

	if (!ctx->regToken)
		ctx->regToken = ASN1_UTF8STRING_new();

	return (ASN1_STRING_set(ctx->regToken, regtoken, len));
err:
	CMPerr(CMP_F_CMP_CTX_SET1_REGTOKEN, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Returns the stack of certificates received in a response message.
 * The stack is duplicated so the caller must handle freeing it!
 * ################################################################ */
STACK_OF(X509)* CMP_CTX_extraCertsIn_get1( CMP_CTX *ctx) {
	if (!ctx) goto err;
	if (!ctx->extraCertsIn) return 0;
	return X509_stack_dup(ctx->extraCertsIn);
err:
	CMPerr(CMP_F_CMP_CTX_EXTRACERTSIN_GET1, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Pops and returns one certificate from the received extraCerts field
 * ################################################################ */
X509 *CMP_CTX_extraCertsIn_pop( CMP_CTX *ctx)
{
	if (!ctx) goto err;
	if (!ctx->extraCertsIn) return NULL;
	return sk_X509_pop(ctx->extraCertsIn);
err:
	CMPerr(CMP_F_CMP_CTX_EXTRACERTSIN_POP, CMP_R_NULL_ARGUMENT);
	return NULL;
}

/* ################################################################ *
 * Returns the number of extraCerts received in a response.
 * ################################################################ */
int CMP_CTX_extraCertsIn_num( CMP_CTX *ctx)
{
	if (!ctx) goto err;
	if (!ctx->extraCertsIn) return 0;
	return sk_X509_num(ctx->extraCertsIn);
err:
	CMPerr(CMP_F_CMP_CTX_EXTRACERTSIN_NUM, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Copies the given stack of inbound X509 certificates to the 
 * CMP_CTX structure so that they may be retrieved later.
 * ################################################################ */
int CMP_CTX_set1_extraCertsIn( CMP_CTX *ctx, const STACK_OF(X509) *extraCertsIn) {
	if (!ctx) goto err;
	if (!extraCertsIn) goto err;

/* if there are already inbound extraCerts on the stack deleten them */
	if (ctx->extraCertsIn) {
		sk_X509_pop_free(ctx->extraCertsIn, X509_free);
		ctx->extraCertsIn = NULL;
	}

	if (!(ctx->extraCertsIn = X509_stack_dup(extraCertsIn))) goto err;

	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_EXTRACERTSIN, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Duplicate and push the given X509 certificate to the stack of 
 * outbound certificates to send in the extraCerts field.
 * ################################################################ */
int CMP_CTX_extraCertsOut_push1( CMP_CTX *ctx, const X509 *val)
{
	if (!ctx) goto err;
	if (!ctx->extraCertsOut && !(ctx->extraCertsOut = sk_X509_new_null())) return 0;
	return sk_X509_push(ctx->extraCertsOut, X509_dup((X509*)val));
err:
	CMPerr(CMP_F_CMP_CTX_EXTRACERTS_PUSH1, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ############################################################################ *
 * load all the intermediate certificates from the given stack into untrusted_store
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_CTX_loadUntrustedStack(CMP_CTX *ctx, STACK_OF(X509) *stack)
{
	int i;
	EVP_PKEY *pubkey;
	X509 *cert;
	
	if (!stack) goto err;
	if (!ctx->untrusted_store && !( ctx->untrusted_store = X509_STORE_new() ))
		goto err;

	for (i = 0; i < sk_X509_num(stack); i++) {
		if(!(cert = sk_X509_value(stack, i))) goto err;
		if(!(pubkey = X509_get_pubkey(cert))) continue;

		/* don't add self-signed certs here */
		if (!X509_verify(cert, pubkey))
			X509_STORE_add_cert(ctx->untrusted_store, cert);  /* don't fail as adding existing certificate to store would cause error */
	}

	return 1;
err:
	return 0;
}

/* ################################################################ *
 * Return the number of certificates we have in the outbound 
 * extraCerts stack.
 * ################################################################ */
int CMP_CTX_extraCertsOut_num( CMP_CTX *ctx)
{
	if (!ctx) goto err;
	if (!ctx->extraCertsOut) return 0;
	return sk_X509_num(ctx->extraCertsOut);
err:
	CMPerr(CMP_F_CMP_CTX_EXTRACERTS_NUM, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Duplicate and set the given stack as the new stack of X509 
 * certificates to send out in the extraCerts field.
 * ################################################################ */
int CMP_CTX_set1_extraCertsOut( CMP_CTX *ctx, const STACK_OF(X509) *extraCertsOut) {
	if (!ctx) goto err;
	if (!extraCertsOut) goto err;

	if (ctx->extraCertsOut) {
		sk_X509_pop_free(ctx->extraCertsOut, X509_free);
		ctx->extraCertsOut = NULL;
	}

	if (!(ctx->extraCertsOut = X509_stack_dup(extraCertsOut))) goto err;

	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_EXTRACERTS, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Returns a duplicate of the stack received X509 certificates that
 * were received in the caPubs field of the last response message.
 * ################################################################ */
STACK_OF(X509)* CMP_CTX_caPubs_get1( CMP_CTX *ctx) {
	if (!ctx) goto err;
	if (!ctx->caPubs) return 0;
	return X509_stack_dup(ctx->caPubs);
err:
	CMPerr(CMP_F_CMP_CTX_CAPUBS_GET1, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Pop one certificate out of the list of certificates received in
 * the caPubs field.
 * ################################################################ */
X509 *CMP_CTX_caPubs_pop( CMP_CTX *ctx) {
	if (!ctx) goto err;
	if (!ctx->caPubs) return NULL;
	return sk_X509_pop(ctx->caPubs);
err:
	CMPerr(CMP_F_CMP_CTX_CAPUBS_POP, CMP_R_NULL_ARGUMENT);
	return NULL;
}

/* ################################################################ *
 * Return the number of certificates received in the caPubs field
 * of the last response message.
 * ################################################################ */
int CMP_CTX_caPubs_num( CMP_CTX *ctx) {
	if (!ctx) goto err;
	if (!ctx->caPubs) return 0;
	return sk_X509_num(ctx->caPubs);
err:
	CMPerr(CMP_F_CMP_CTX_CAPUBS_NUM, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Duplciate and copy the given stack of certificates to the given 
 * CMP_CTX structure so that they may be retrieved later.
 * ################################################################ */
int CMP_CTX_set1_caPubs( CMP_CTX *ctx, const STACK_OF(X509) *caPubs) {
	if (!ctx) goto err;
	if (!caPubs) goto err;

	if (ctx->caPubs) {
		sk_X509_pop_free(ctx->caPubs, X509_free);
		ctx->caPubs = NULL;
	}

	if (!(ctx->caPubs = X509_stack_dup(caPubs))) goto err;

	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_CAPUBS, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Sets the CA certificate that is to be used for verifying response
 * messages. Pointer is not consumed.
 * ################################################################ */
int CMP_CTX_set1_srvCert( CMP_CTX *ctx, const X509 *cert) {
	if (!ctx) goto err;
	if (!cert) goto err;

	if (ctx->srvCert) {
		X509_free(ctx->srvCert);
		ctx->srvCert = NULL;
	}

	if (!(ctx->srvCert = X509_dup( (X509*)cert))) goto err;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_SRVCERT, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Set the X509 name of the recipient. Set in the PKIHeader.
 * ################################################################ */
int CMP_CTX_set1_recipient( CMP_CTX *ctx, const X509_NAME *name) {
	if (!ctx) goto err;
	if (!name) goto err;

	if (ctx->recipient) {
		X509_NAME_free(ctx->recipient);
		ctx->recipient = NULL;
	}

	if (!(ctx->recipient = X509_NAME_dup( (X509_NAME*)name))) goto err;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_RECIPIENT, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Set the subject name that will be placed in the certificate 
 * request. This will be the subject name on the received certificate.
 * ################################################################ */
int CMP_CTX_set1_subjectName( CMP_CTX *ctx, const X509_NAME *name) {
	if (!ctx) goto err;
	if (!name) goto err;

	if (ctx->subjectName) {
		X509_NAME_free(ctx->subjectName);
		ctx->subjectName = NULL;
	}

	if (!(ctx->subjectName = X509_NAME_dup( (X509_NAME*)name))) goto err;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_SUBJECTNAME, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Push a GENERAL_NAME structure that will be added to the CRMF
 * request's extensions field to request subject alternative names.
 * ################################################################ */
int CMP_CTX_subjectAltName_push1( CMP_CTX *ctx, const GENERAL_NAME *name) {
	if (!ctx) goto err;
	if (!name) goto err;

	if (!ctx->subjectAltNames && !(ctx->subjectAltNames = sk_GENERAL_NAME_new_null()))
		goto err;

	if (!sk_GENERAL_NAME_push(ctx->subjectAltNames, GENERAL_NAME_dup( (GENERAL_NAME*)name))) goto err;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SUBJECTALTNAME_PUSH1, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Set our own client certificate, used for example in KUR and when
 * doing the IR with existing certificate.
 * ################################################################ */
int CMP_CTX_set1_clCert( CMP_CTX *ctx, const X509 *cert) {
	if (!ctx) goto err;
	if (!cert) goto err;

	if (ctx->clCert) {
		X509_free(ctx->clCert);
		ctx->clCert = NULL;
	}

	if (!(ctx->clCert = X509_dup( (X509*)cert))) goto err;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_CLCERT, CMP_R_NULL_ARGUMENT);
	return 0;
}


/* ################################################################ *
 * ################################################################ */
int CMP_CTX_set1_newClCert( CMP_CTX *ctx, const X509 *cert) {
	if (!ctx) goto err;
	if (!cert) goto err;

	if (ctx->newClCert) {
		X509_free(ctx->newClCert);
		ctx->newClCert = NULL;
	}

	if (!(ctx->newClCert = X509_dup( (X509*)cert))) goto err;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_NEWCLCERT, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Set the client's private key. This creates a duplicate of the key
 * so the given pointer is not used directly.
 * ################################################################ */
int CMP_CTX_set1_pkey( CMP_CTX *ctx, const EVP_PKEY *pkey) {
	EVP_PKEY *pkeyDup = NULL;
	if (!ctx) goto err;
	if (!pkey) goto err;

	pkeyDup = pkey_dup(pkey);;
	return CMP_CTX_set0_pkey(ctx, pkeyDup);

err:
	if (pkeyDup) EVP_PKEY_free(pkeyDup);
	CMPerr(CMP_F_CMP_CTX_SET1_PKEY, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Set the client's current private key. NOTE: this version uses
 * the given pointer directly!
 * ################################################################ */
int CMP_CTX_set0_pkey( CMP_CTX *ctx, const EVP_PKEY *pkey) {
	if (!ctx) goto err;
	if (!pkey) goto err;

	if (ctx->pkey) {
		EVP_PKEY_free(ctx->pkey);
		ctx->pkey = NULL;
	}

	ctx->pkey = (EVP_PKEY*) pkey;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET0_PKEY, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Set new private key. Used for example when doing Key Update.
 * The key is duplicated so the original pointer is not directly used.
 * ################################################################ */
int CMP_CTX_set1_newPkey( CMP_CTX *ctx, const EVP_PKEY *pkey) {
	EVP_PKEY *pkeyDup = NULL;
	if (!ctx) goto err;
	if (!pkey) goto err;

	pkeyDup = pkey_dup(pkey);
	return CMP_CTX_set0_newPkey(ctx, pkeyDup);

err:
	if (pkeyDup) EVP_PKEY_free(pkeyDup);
	CMPerr(CMP_F_CMP_CTX_SET1_NEWPKEY, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Set new private key. Used for example when doing Key Update.
 * NOTE: uses the pointer directly!
 * ################################################################ */
int CMP_CTX_set0_newPkey( CMP_CTX *ctx, const EVP_PKEY *pkey) {
	if (!ctx) goto err;
	if (!pkey) goto err;

	if (ctx->newPkey) {
		EVP_PKEY_free(ctx->newPkey);
		ctx->newPkey = NULL;
	}

	ctx->newPkey = (EVP_PKEY*) pkey;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET0_NEWPKEY, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * 
 * ################################################################ */
int CMP_CTX_set1_transactionID( CMP_CTX *ctx, const ASN1_OCTET_STRING *id) {
	if (!ctx) goto err;
	if (!id) goto err;

	if (ctx->transactionID) {
		ASN1_OCTET_STRING_free(ctx->transactionID);
		ctx->transactionID = NULL;
	}

	if (!(ctx->transactionID = ASN1_OCTET_STRING_dup((ASN1_OCTET_STRING *)id)))
		return 0;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_TRANSACTIONID, CMP_R_NULL_ARGUMENT);
	return 0;
}


/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set1_recipNonce( CMP_CTX *ctx, const ASN1_OCTET_STRING *nonce) {
	if (!ctx) goto err;
	if (!nonce) goto err;

	if (ctx->recipNonce) {
		ASN1_OCTET_STRING_free(ctx->recipNonce);
		ctx->recipNonce = NULL;
	}

	if (!(ctx->recipNonce = ASN1_OCTET_STRING_dup((ASN1_OCTET_STRING *)nonce))) 
		return 0;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_RECIPNONCE, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Set the hostname of the proxy server to use for all connections
 * ################################################################ */
int CMP_CTX_set1_proxyName( CMP_CTX *ctx, const char *name) {
	if (!ctx) goto err;
	if (!name) goto err;

	if (ctx->proxyName) {
		OPENSSL_free( ctx->proxyName);
		ctx->proxyName = NULL;
	}

	ctx->proxyName = OPENSSL_malloc( strlen(name)+1);
	strcpy( ctx->proxyName, name);

	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_PROXYNAME, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Set the hostname of the CA server
 * ################################################################ */
int CMP_CTX_set1_serverName( CMP_CTX *ctx, const char *name) {
	if (!ctx) goto err;
	if (!name) goto err;

	if (ctx->serverName) {
		OPENSSL_free( ctx->serverName);
		ctx->serverName = NULL;
	}

	ctx->serverName = OPENSSL_malloc( strlen(name)+1);
	strcpy( ctx->serverName, name);

	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_SERVERNAME, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set1_popoMethod( CMP_CTX *ctx, int method) {
	if (!ctx) goto err;

	ctx->popoMethod = method;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_POPOMETHOD, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set1_timeOut( CMP_CTX *ctx, int time) {
	if (!ctx) goto err;

	ctx->timeOut = time;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_TIMEOUT, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set1_proxyPort( CMP_CTX *ctx, int port) {
	if (!ctx) goto err;

	ctx->proxyPort = port;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_PROXYPORT, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set1_serverPort( CMP_CTX *ctx, int port) {
	if (!ctx) goto err;

	ctx->serverPort = port;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_SERVERPORT, CMP_R_NULL_ARGUMENT);
	return 0;
}

/* ################################################################ *
 * Sets the HTTP path to be used on the server (normally "pkix/")
 * ################################################################ */
int CMP_CTX_set1_serverPath( CMP_CTX *ctx, const char *path) {
	if (!ctx) goto err;

	if (ctx->serverPath) {
		/* clear the old value */
		OPENSSL_free( ctx->serverPath);
		ctx->serverPath = 0;
	}

	if (!path) {
		/* clear the serverPath */
		ctx->serverPath = OPENSSL_malloc(1);
		ctx->serverPath[0] = 0;
		return 1;
	}

	ctx->serverPath = OPENSSL_malloc( strlen(path)+1);
	strcpy( ctx->serverPath, path);

	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_SERVERPATH, CMP_R_NULL_ARGUMENT);
	return 0;
}


/* ################################################################ *
 * Set the failinfo error code bits in CMP_CTX based on the given
 * CMP_PKIFAILUREINFO structure
 * ################################################################ */
int CMP_CTX_set_failInfoCode(CMP_CTX *ctx, CMP_PKIFAILUREINFO *failInfo) {
	int i;

	if (!ctx || !failInfo) return 0;

	ctx->failInfoCode = 0;
	for ( i=0; i <= CMP_PKIFAILUREINFO_MAX; i++)
		if( ASN1_BIT_STRING_get_bit(failInfo, i))
			ctx->failInfoCode |= 1 << i;

	return 1;
}

unsigned long CMP_CTX_failInfoCode_get(CMP_CTX *ctx) {
	if (!ctx) return 0;
	return ctx->failInfoCode;
}

#if 0
/* ################################################################ */
/* pushes a given 0-terminated character string to ctx->freeText */
/* this is inteded for human consumption */
/* ################################################################ */
int CMP_CTX_push_freeText( CMP_CTX *ctx, const char *text) {
	ASN1_UTF8STRING *utf8string=NULL;

	if (!ctx) goto err;
	if (!text) goto err;

	if (!ctx->freeText)
		if( !(ctx->freeText = sk_ASN1_UTF8STRING_new())) goto err;

	if( !(utf8string = ASN1_UTF8STRING_new())) goto err;
	ASN1_UTF8STRING_set(utf8string, text, strlen(text));
	if( !(sk_ASN1_UTF8STRING_push(ctx->freeText, utf8string) goto err;
	return 1;
err:
	CMP_printf( "ERROR in FILE: %s, LINE: %d\n", __FILE__, __LINE__);
	if (utf8string) ASN1_UTF8STRING_free(utf8string);
	return 0;
}
#endif

/* ################################################################ */
/* sets a BOOLEAN option of the context to the "val" arg */
/* ################################################################ */
int CMP_CTX_set_option( CMP_CTX *ctx, const int opt, const int val) {
	if (!ctx) goto err;

	switch (opt) {
		case CMP_CTX_OPT_IMPLICITCONFIRM:
			ctx->implicitConfirm = val;
			break;
		case CMP_CTX_OPT_POPMETHOD:
			ctx->popoMethod = val;
			break;
		case CMP_CTX_OPT_VALIDATEPATH:
			ctx->validatePath = val;
			break;
		case CMP_CTX_OPT_MAXPOLLCOUNT:
			ctx->maxPollCount = val;
			break;
		default:
			goto err;
	}

	return 1;
err:
	return 0;
}

/* ################################################################ *
 * Function used for printing debug messages.
 * ################################################################ */
void CMP_printf(const CMP_CTX *ctx, const char *fmt, ...)
{
	if (!ctx || !ctx->debug_cb) return;

	va_list arg_ptr;
	va_start(arg_ptr, fmt);

	char buf[1024];
	vsnprintf(buf, sizeof(buf), fmt, arg_ptr);
	ctx->debug_cb(buf);

	// else vfprintf(stdout, fmt, arg_ptr);
	va_end(arg_ptr);
}

#ifdef HAVE_CURL
long CMP_get_http_code(const CMPBIO *bio) {
	long code = 0;
	curl_easy_getinfo((CMPBIO*)bio, CURLINFO_RESPONSE_CODE, &code);
	return code;
}
#endif

/* ############################################################################ *
 * This callback is used to print out the OpenSSL error queue via'
 * ERR_print_errors_cb() to the ctx->error_cb() function set by the user
 * ############################################################################ */
int CMP_CTX_error_callback(const char *str, size_t len, void *u) {
	CMP_CTX *ctx = (CMP_CTX*) u;
	if (ctx && ctx->error_cb) 
		ctx->error_cb(str);
	return 1;
}

