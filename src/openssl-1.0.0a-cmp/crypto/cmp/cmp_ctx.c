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
	ASN1_SEQUENCE_OF_OPT(CMP_CTX, caPubs, X509),
	ASN1_SEQUENCE_OF_OPT(CMP_CTX, extraCerts, X509),
	ASN1_SEQUENCE_OF_OPT(CMP_CTX, caExtraCerts, X509),
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
	 */
} ASN1_SEQUENCE_END(CMP_CTX)
IMPLEMENT_ASN1_FUNCTIONS(CMP_CTX)

/* TODO find out what's wrong with/how to use sk_X509_dup()
 * so that this function could be removed... */
static STACK_OF(X509)* X509_stack_dup(const STACK_OF(X509)* stack)
{
	STACK_OF(X509) *newsk = NULL;
	int i;

	if (!stack) goto err;
	if (!(newsk = sk_X509_new_null())) goto err;

	for (i = 0; i < sk_X509_num(stack); i++)
		/* XXX does the X509_dup() call cause memory leakage? */
		sk_X509_push(newsk, X509_dup(sk_X509_value(stack, i)));

	return newsk;
err:
	return 0;
}

;
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
	/* XXX TODO this should be freed somewhere */
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
	/* ctx->popoMethod = CMP_POPO_ENCRCERT; */

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

	return 1;

err:
	CMPerr(CMP_F_CMP_CTX_INIT, CMP_R_CMPERROR);
	return 0;
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

/* ################################################################ */
/* ################################################################ */
X509 *CMP_CTX_caExtraCerts_pop( CMP_CTX *ctx)
{
	if (!ctx) goto err;
	if (!ctx->caExtraCerts) return NULL;
	return sk_X509_pop(ctx->caExtraCerts);
err:
	CMPerr(CMP_F_CMP_CTX_CAEXTRACERTS_POP, CMP_R_CMPERROR);
	return NULL;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_caExtraCerts_num( CMP_CTX *ctx)
{
	if (!ctx) goto err;
	if (!ctx->caExtraCerts) return 0;
	return sk_X509_num(ctx->caExtraCerts);
  err:
	CMPerr(CMP_F_CMP_CTX_CAEXTRACERTS_NUM, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set1_caExtraCerts( CMP_CTX *ctx, const STACK_OF(X509) *caExtraCerts) {
	if (!ctx) goto err;
	if (!caExtraCerts) goto err;

	if (ctx->caExtraCerts) {
		sk_X509_pop_free(ctx->caExtraCerts, X509_free);
		ctx->caExtraCerts = NULL;
	}

	if (!(ctx->caExtraCerts = X509_stack_dup(caExtraCerts))) goto err;

	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_CAEXTRACERTS, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_extraCerts_push( CMP_CTX *ctx, const X509 *val)
{
	if (!ctx) goto err;
	if (!ctx->extraCerts && !(ctx->extraCerts = sk_X509_new_null())) return 0;
	return sk_X509_push(ctx->extraCerts, val);
err:
	CMPerr(CMP_F_CMP_CTX_EXTRACERTS_POP, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_extraCerts_num( CMP_CTX *ctx)
{
	if (!ctx) goto err;
	if (!ctx->extraCerts) return 0;
	return sk_X509_num(ctx->extraCerts);
  err:
	CMPerr(CMP_F_CMP_CTX_EXTRACERTS_NUM, CMP_R_CMPERROR);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set1_extraCerts( CMP_CTX *ctx, const STACK_OF(X509) *extraCerts) {
	if (!ctx) goto err;
	if (!extraCerts) goto err;

	if (ctx->extraCerts) {
		sk_X509_pop_free(ctx->extraCerts, X509_free);
		ctx->extraCerts = NULL;
	}

	if (!(ctx->extraCerts = X509_stack_dup(extraCerts))) goto err;

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

	/* XXX why doesn't this work? */
	/* if (!(ctx->caPubs = sk_X509_dup( (X509*)caPubs))) goto err; */
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
int CMP_CTX_set1_subjectName( CMP_CTX *ctx, const X509_NAME *name) {
	if (!ctx) goto err;
	if (!name) goto err;

	if (ctx->subjectName) {
		X509_NAME_free(ctx->subjectName);
		ctx->clCert = NULL;
	}

	if (!(ctx->subjectName = X509_NAME_dup( (X509_NAME*)name))) goto err;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET1_SUBJECTNAME, CMP_R_CMPERROR);
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
int CMP_CTX_set1_extCert( CMP_CTX *ctx, const X509 *cert) {
	if (!ctx) goto err;

	if (!cert) {
		ctx->extCert = NULL;
		return 1;
	}

	if (ctx->clCert) {
		X509_free(ctx->extCert);
		ctx->extCert = NULL;
	}

	if (!(ctx->extCert = X509_dup( (X509*)cert))) goto err;
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
int CMP_CTX_set0_pkey( CMP_CTX *ctx, const EVP_PKEY *pkey) {
	if (!ctx) goto err;
	if (!pkey) goto err;

	if (ctx->pkey) {
		EVP_PKEY_free(ctx->pkey);
		ctx->pkey = NULL;
	}

// XXX SETTING CTX->PKEY SHOULD NOT CONSUME THE POINTER
#if 0
/* XXX this is NOT sufficient to copy everything! */
	ctx->pkey = EVP_PKEY_new();

	return (EVP_PKEY_copy_parameters( ctx->pkey, pkey));
#endif
	ctx->pkey = (EVP_PKEY*) pkey;
	return 1;
err:
	CMPerr(CMP_F_CMP_CTX_SET0_PKEY, CMP_R_CMPERROR);
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

// XXX SETTING CTX->NEWPKEY SHOULD NOT CONSUME THE POINTER
#if 0
	ctx->newPkey = EVP_PKEY_new();

	return (EVP_PKEY_copy_parameters( ctx->newPkey, pkey));
#endif
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
		case CMP_ALG_SIG:
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
		default:
			goto err;
	}

	return 1;
err:
	return 0;
}
