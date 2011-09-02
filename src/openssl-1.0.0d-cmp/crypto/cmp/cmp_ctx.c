/* crypto/cmp/cmp_ctx.c
 * CMP (RFC 4210) context functions for OpenSSL
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
 * 06/2010 - Miikka Viljanen - Report errors with OpenSSL error codes instead
 *                             of printf statements.
 */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/cmp.h>
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
	ASN1_OPT(CMP_CTX, caCert, X509),
	ASN1_OPT(CMP_CTX, clCert, X509),
	ASN1_OPT(CMP_CTX, subjectName, X509_NAME),
	ASN1_OPT(CMP_CTX, recipient, X509_NAME),
	ASN1_SEQUENCE_OF_OPT(CMP_CTX, subjectAltNames, GENERAL_NAME),
	ASN1_SEQUENCE_OF_OPT(CMP_CTX, caPubs, X509),
	ASN1_SEQUENCE_OF_OPT(CMP_CTX, extraCertsOut, X509),
	ASN1_SEQUENCE_OF_OPT(CMP_CTX, extraCertsIn, X509),
	ASN1_SEQUENCE_OF_OPT(CMP_CTX, caCertsIn, X509),
	/* EVP_PKEY *pkey */
	ASN1_OPT(CMP_CTX, newClCert, X509),
	/* EVP_PKEY *newPkey */
	ASN1_OPT(CMP_CTX, transactionID, ASN1_OCTET_STRING),
	ASN1_OPT(CMP_CTX, recipNonce, ASN1_OCTET_STRING),
	ASN1_OPT(CMP_CTX, protectionAlgor, X509_ALGOR),
#if 0
	/* this is actually CMP_PKIFREETEXT which is STACK_OF(ANS1_UTF8STRING) */
	ASN1_SEQUENCE_OPT(CMP_CTX, freeText, STACK_OF(UTF8STRING));
#endif
	/* the following are not ASN1 types and present in the declaration in cmp.h
	 * int compatibilitiy
	 * char *serverName
	 * int serverPort
	 * int transport
	 * int implicitConfirm
	* XXX not setting senderNonce test for PKI INFO
	 * int setSenderNonce
	* XXX not setting transactionID test for PKI INFO
	 * int setTransactionID
	 * int popoMethod
	 * int timeOut
	 */
} ASN1_SEQUENCE_END(CMP_CTX)
IMPLEMENT_ASN1_FUNCTIONS(CMP_CTX)

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

static EVP_PKEY *pkey_dup(const EVP_PKEY *pkey)
{
	EVP_PKEY *pkeyDup = EVP_PKEY_new();
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
	EVP_PKEY_free(pkeyDup);
	CMPerr(CMP_F_PKEY_DUP, CMP_R_CMPERROR);
	return NULL;
}

;

/* ############################################################################ *
 * Creates an X509_STORE structure for looking up certs within a directory,
 * using the 'hash'.0 naming format.
 * ############################################################################ */
static X509_STORE *create_cert_store(char *dir) {
    X509_STORE *cert_ctx=NULL;
    X509_LOOKUP *lookup=NULL;

    cert_ctx=X509_STORE_new();
    if (cert_ctx == NULL) goto err;

    X509_STORE_set_verify_cb(cert_ctx, CMP_cert_callback);

	/* TODO what happens if we have two certificates with the same subject name? (i.e. same hash) */
    lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
    if (lookup == NULL) goto err;

    // XXX PEM or DER format?
    // X509_LOOKUP_add_dir(lookup, ctx.trusted_dir, X509_FILETYPE_PEM);
    X509_LOOKUP_add_dir(lookup, dir, X509_FILETYPE_ASN1);

    return cert_ctx;

err:
    return NULL;
}

int CMP_CTX_set_untrustedPath( CMP_CTX *ctx, char *dir) 
{
	ctx->untrusted_store = create_cert_store(dir);
	if (ctx->untrusted_store)
		return 1;
	return 0;
}


int CMP_CTX_set_trustedPath( CMP_CTX *ctx, char *dir) {
	ctx->trusted_store = create_cert_store(dir);
	if (ctx->trusted_store)
		return 1;
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_init( CMP_CTX *ctx) {
	if (!ctx) {
		CMPerr(CMP_F_CMP_CTX_INIT, CMP_R_INVALID_CONTEXT);
		goto err;
	}

	/* all other elements are initialized through ASN1 macros */
	ctx->pkey            = NULL;
	ctx->newPkey         = NULL;
	ctx->compatibility   = CMP_COMPAT_RFC;
	ctx->serverName      = NULL;
	/* serverPath has to be an empty sting if not set since it is not mandatory */
	/* this will be freed by CMP_CTX_delete() */
	ctx->serverPath      = OPENSSL_malloc(1);
	ctx->serverPath[0]   = 0;
	ctx->serverPort      = 0;
	ctx->transport       = CMP_TRANSPORT_HTTP;
	ctx->implicitConfirm = 0;
	/* XXX not setting senderNonce test for PKI INFO */
	ctx->setSenderNonce  = 1;
	/* XXX not setting transactionID test for PKI INFO */
	ctx->setTransactionID  = 1;
	ctx->popoMethod = CMP_POPO_SIGNATURE;
	ctx->timeOut         = 2*60;
	/* ctx->popoMethod = CMP_POPO_ENCRCERT; */
	ctx->validatePath    = 0;

	ctx->error_cb = (cmp_logfn_t) puts;
	ctx->debug_cb = (cmp_logfn_t) puts;

	ctx->trusted_store   = NULL;
	ctx->untrusted_store = NULL;

	ctx->maxPollCount = 3;

#if 0
	ctx->referenceValue = NULL;
	ctx->secretValue = NULL;
	ctx->caCert = NULL;
	ctx->clCert = NULL;
	ctx->newClCert = NULL;
	ctx->transactionID = NULL;
	ctx->recipNonce = NULL;
	ctx->protectionAlgor = NULL;
#endif

	/* initialize OpenSSL */
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();

	return 1;

err:
	CMPerr(CMP_F_CMP_CTX_INIT, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* frees CMP_CTX variables allocated in CMP_CTX_init and calls CMP_CTX_free */
/* ################################################################ */
void CMP_CTX_delete(CMP_CTX *ctx) {
	if (!ctx) return;
	OPENSSL_free(ctx->serverPath);
	if (ctx->serverName) OPENSSL_free(ctx->serverName);
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
	CMPerr(CMP_F_CMP_CTX_CREATE, CMP_R_CMPERROR);
	if (ctx) CMP_CTX_free(ctx);
	return NULL;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set_error_callback( CMP_CTX *ctx, cmp_logfn_t cb)
{
	if (!ctx || !cb) goto err;
	ctx->error_cb = cb;
err:
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set_debug_callback( CMP_CTX *ctx, cmp_logfn_t cb)
{
	if (!ctx || !cb) goto err;
	ctx->debug_cb = cb;
err:
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set1_referenceValue( CMP_CTX *ctx, const unsigned char *ref, size_t len) {
	if (!ctx) goto err;
	if (!ref) goto err;

	if (!ctx->referenceValue)
		ctx->referenceValue = ASN1_OCTET_STRING_new();

	return (ASN1_OCTET_STRING_set(ctx->referenceValue, ref, len));
err:
	CMPerr(CMP_F_CMP_CTX_SET1_REFERENCEVALUE, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set1_secretValue( CMP_CTX *ctx, const unsigned char *sec, const size_t len) {
	if (!ctx) goto err;
	if (!sec) goto err;

	if (!ctx->secretValue)
		ctx->secretValue = ASN1_OCTET_STRING_new();

	return (ASN1_OCTET_STRING_set(ctx->secretValue, sec, len));
err:
	CMPerr(CMP_F_CMP_CTX_SET1_SECRETVALUE, CMP_R_CMPERROR);
	return 0;
}

int CMP_CTX_caCertsIn_set1( CMP_CTX *ctx, const STACK_OF(X509) *caPubs, const STACK_OF(X509) *extraCerts)
{
	int i;
	if (!ctx) goto err;

	if (ctx->caCertsIn) 
		sk_X509_pop_free(ctx->caCertsIn, X509_free);

	if (!(ctx->caCertsIn = sk_X509_new_null())) 
		goto err;

	if (caPubs)
		for (i = 0; i > sk_X509_num(caPubs); i++)
			sk_X509_push(ctx->caCertsIn, X509_dup( sk_X509_value(caPubs,i)));
	if (extraCerts)
		for (i = 0; i > sk_X509_num(extraCerts); i++)
			sk_X509_push(ctx->caCertsIn, X509_dup( sk_X509_value(extraCerts,i)));

	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_CACERTS_ADD, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
X509 *CMP_CTX_caCertsIn_pop( CMP_CTX *ctx)
{
	if (!ctx) goto err;
	if (!ctx->caCertsIn) return NULL;
	return sk_X509_pop(ctx->caCertsIn);
err:
	CMPerr(CMP_F_CMP_CTX_CAcaCerts_POP, CMP_R_CMPERROR);
	return NULL;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_caCertsIn_num( CMP_CTX *ctx)
{
	if (!ctx) goto err;
	if (!ctx->caCertsIn) return 0;
	return sk_X509_num(ctx->caCertsIn);
  err:
	CMPerr(CMP_F_CMP_CTX_CACERTSIN_NUM, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_caCertsIn_get1( CMP_CTX *ctx)
{
	if (!ctx) goto err;
	if (!ctx->caCertsIn) return 0;
	return X509_stack_dup(ctx->caCertsIn);
  err:
	CMPerr(CMP_F_CMP_CTX_CACERTSIN_GET1, CMP_R_CMPERROR);
	return 0;
}


/* ################################################################ */
/* ################################################################ */
X509 *CMP_CTX_extraCertsIn_pop( CMP_CTX *ctx)
{
	if (!ctx) goto err;
	if (!ctx->extraCertsIn) return NULL;
	return sk_X509_pop(ctx->extraCertsIn);
err:
	CMPerr(CMP_F_CMP_CTX_EXTRACERTSIN_POP, CMP_R_CMPERROR);
	return NULL;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_extraCertsIn_num( CMP_CTX *ctx)
{
	if (!ctx) goto err;
	if (!ctx->extraCertsIn) return 0;
	return sk_X509_num(ctx->extraCertsIn);
  err:
	CMPerr(CMP_F_CMP_CTX_EXTRACERTSIN_NUM, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
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
	CMPerr(CMP_F_CMP_CTX_SET1_CAEXTRACERTS, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_extraCertsOut_push1( CMP_CTX *ctx, const X509 *val)
{
	if (!ctx) goto err;
	if (!ctx->extraCertsOut && !(ctx->extraCertsOut = sk_X509_new_null())) return 0;
	return sk_X509_push(ctx->extraCertsOut, X509_dup((X509*)val));
err:
	CMPerr(CMP_F_CMP_CTX_EXTRACERTS_PUSH1, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_extraCertsOut_num( CMP_CTX *ctx)
{
	if (!ctx) goto err;
	if (!ctx->extraCertsOut) return 0;
	return sk_X509_num(ctx->extraCertsOut);
  err:
	CMPerr(CMP_F_CMP_CTX_EXTRACERTS_NUM, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
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
	CMPerr(CMP_F_CMP_CTX_SET1_EXTRACERTS, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
X509 *CMP_CTX_caPubs_pop( CMP_CTX *ctx) {
	if (!ctx) goto err;
	if (!ctx->caPubs) return NULL;
	return sk_X509_pop(ctx->caPubs);
err:
	CMPerr(CMP_F_CMP_CTX_CAPUBS_POP, CMP_R_CMPERROR);
	return NULL;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_caPubs_num( CMP_CTX *ctx) {
	if (!ctx) goto err;
	if (!ctx->caPubs) return 0;
	return sk_X509_num(ctx->caPubs);
err:
	CMPerr(CMP_F_CMP_CTX_CAPUBS_NUM, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
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
	CMPerr(CMP_F_CMP_CTX_SET1_CAPUBS, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set1_caCert( CMP_CTX *ctx, const X509 *cert) {
	if (!ctx) goto err;
	if (!cert) goto err;

	if (ctx->caCert) {
		X509_free(ctx->caCert);
		ctx->caCert = NULL;
	}

	if (!(ctx->caCert = X509_dup( (X509*)cert))) goto err;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_CACERT, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
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
	CMPerr(CMP_F_CMP_CTX_SET1_RECIPIENT, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
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
	CMPerr(CMP_F_CMP_CTX_SET1_SUBJECTNAME, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_subjectAltName_push1( CMP_CTX *ctx, const GENERAL_NAME *name) {
	if (!ctx) goto err;
	if (!name) goto err;

	if (!ctx->subjectAltNames && !(ctx->subjectAltNames = sk_GENERAL_NAME_new_null()))
		goto err;

	if (!sk_GENERAL_NAME_push(ctx->subjectAltNames, GENERAL_NAME_dup( (GENERAL_NAME*)name))) goto err;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SUBJECTALTNAME_PUSH1, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
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
	CMPerr(CMP_F_CMP_CTX_SET1_CLCERT, CMP_R_CMPERROR);
	return 0;
}


/* ################################################################ */
/* ################################################################ */
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
	CMPerr(CMP_F_CMP_CTX_SET1_NEWCLCERT, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set1_pkey( CMP_CTX *ctx, const EVP_PKEY *pkey) {
	EVP_PKEY *pkeyDup = NULL;
	if (!ctx) goto err;
	if (!pkey) goto err;

	pkeyDup = pkey_dup(pkey);;
	return CMP_CTX_set0_pkey(ctx, pkeyDup);

err:
	if (pkeyDup) EVP_PKEY_free(pkeyDup);
	CMPerr(CMP_F_CMP_CTX_SET1_PKEY, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
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
	CMPerr(CMP_F_CMP_CTX_SET0_PKEY, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set1_newPkey( CMP_CTX *ctx, const EVP_PKEY *pkey) {
	EVP_PKEY *pkeyDup = NULL;
	if (!ctx) goto err;
	if (!pkey) goto err;

	pkeyDup = pkey_dup(pkey);
	return CMP_CTX_set0_newPkey(ctx, pkeyDup);

err:
	if (pkeyDup) EVP_PKEY_free(pkeyDup);
	CMPerr(CMP_F_CMP_CTX_SET1_NEWPKEY, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
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
	CMPerr(CMP_F_CMP_CTX_SET0_NEWPKEY, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set1_transactionID( CMP_CTX *ctx, const ASN1_OCTET_STRING *id) {
	if (!ctx) goto err;
	if (!id) goto err;

	if (ctx->transactionID) {
		ASN1_OCTET_STRING_free(ctx->transactionID);
		ctx->transactionID = NULL;
	}

	if (!(ctx->transactionID = ASN1_OCTET_STRING_dup((ASN1_OCTET_STRING *)id))) goto err;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_TRANSACTIONID, CMP_R_CMPERROR);
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

	if (!(ctx->recipNonce = ASN1_OCTET_STRING_dup((ASN1_OCTET_STRING *)nonce))) goto err;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_RECIPNONCE, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set1_protectionAlgor( CMP_CTX *ctx, const X509_ALGOR *algor) {
	if (!ctx) goto err;
	if (!algor) goto err;

	if (ctx->protectionAlgor) {
		X509_ALGOR_free(ctx->protectionAlgor);
		ctx->protectionAlgor = NULL;
	}

	if (!(ctx->protectionAlgor = X509_ALGOR_dup( (X509_ALGOR*)algor))) goto err;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_PROTECTIONALGOR, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set_compatibility( CMP_CTX *ctx, const int mode) {
	if (!ctx) goto err;

	ctx->compatibility = mode;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET_COMPATIBILITY, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
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
	CMPerr(CMP_F_CMP_CTX_SET1_SERVERNAME, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set1_popoMethod( CMP_CTX *ctx, int method) {
	if (!ctx) goto err;

	ctx->popoMethod = method;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_POPOMETHOD, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set1_timeOut( CMP_CTX *ctx, int time) {
	if (!ctx) goto err;

	ctx->timeOut = time;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_TIMEOUT, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set1_serverPort( CMP_CTX *ctx, int port) {
	if (!ctx) goto err;

	ctx->serverPort = port;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_SERVERPORT, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
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
	CMPerr(CMP_F_CMP_CTX_SET1_SERVERPATH, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set_protectionAlgor( CMP_CTX *ctx, const int algID) {
	int nid;

	if (!ctx) goto err;

	switch (algID) {
		case CMP_ALG_PBMAC:
			nid = NID_id_PasswordBasedMAC;
			break;
		case CMP_ALG_SIG: {
			/* first try to set algorithm based on the algorithm 
			 * used in the certificate, if we already have one */
			if (ctx->clCert && (ctx->protectionAlgor = ctx->clCert->sig_alg) != NULL)
				return 1;

			if (!ctx->pkey) goto err;
#ifndef OPENSSL_NO_DSA
			if (EVP_PKEY_type(ctx->pkey->type) == EVP_PKEY_DSA) {
				nid = NID_dsaWithSHA1;
				break;
			}
#endif
#ifndef OPENSSL_NO_RSA
			if (EVP_PKEY_type(ctx->pkey->type) == EVP_PKEY_RSA) {
				nid = NID_sha1WithRSAEncryption;
				break;
			}
#endif
			goto err;
			break;
		}
		default:
			goto err;
	}

	if (ctx->protectionAlgor) {
		X509_ALGOR_free(ctx->protectionAlgor);
		ctx->protectionAlgor = NULL;
	}

	if (!(ctx->protectionAlgor = CMP_get_protectionAlgor_by_nid(nid))) goto err;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET_PROTECTIONALGOR, CMP_R_CMPERROR);
	return 0;
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
/* sets a BOOLEAN option to of the context to the "val" arg */
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
		case CMP_CTX_OPT_COMBINECACERTS:
			ctx->combineCACerts = val;
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


