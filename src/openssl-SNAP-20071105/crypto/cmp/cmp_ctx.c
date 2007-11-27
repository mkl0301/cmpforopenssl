/* crypto/cmp/cmp_ctx.c
 *
 * CMP (RFC 4210) context functions for OpenSSL
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
#include <openssl/cmp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
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
	/* EVP_PKEY *pkey */
	ASN1_OPT(CMP_CTX, newClCert, X509),
	/* EVP_PKEY *newPkey */
	ASN1_OPT(CMP_CTX, transactionID, ASN1_OCTET_STRING),
	ASN1_OPT(CMP_CTX, recipNonce, ASN1_OCTET_STRING),
	ASN1_OPT(CMP_CTX, protectionAlgor, X509_ALGOR),
#if 0
	ASN1_OPT(CMP_CTX, lastMsgSent, CMP_PKIMESSAGE),
	ASN1_OPT(CMP_CTX, lastMsgRecvd, CMP_PKIMESSAGE),
#endif
#if 0
	/* this is actually CMP_PKIFREETEXT which is STACK_OF(ANS1_UTF8STRING) */
	ASN1_SEQUENCE_OPT(CMP_CTX, freeText, STACK_OF(UTF8STRING));
#endif
	/* the following are not ASN1 types:
	 * int compatibilitiy
	 * char *serverName
	 * int serverPort
	 * int transport
	 * int implicitConfirm
	* XXX not setting senderNonce test for PKI INFO
	 * int setSenderNonce
	* XXX not setting transactionID test for PKI INFO
	 * int setTransactionID
	 */
} ASN1_SEQUENCE_END(CMP_CTX)
IMPLEMENT_ASN1_FUNCTIONS(CMP_CTX)

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_init( CMP_CTX *ctx) {
	if (!ctx) goto err;

	/* all other elements are initialized through ASN1 macros */
	ctx->pkey            = NULL;
	ctx->newPkey         = NULL;
	ctx->compatibility   = CMP_COMPAT_RFC;
	ctx->serverName      = NULL;
	ctx->serverPort      = 0;
	ctx->transport       = CMP_TRANSPORT_HTTP;
	ctx->implicitConfirm = 0;
	/* XXX not setting senderNonce test for PKI INFO */
	ctx->setSenderNonce  = 1;
	/* XXX not setting transactionID test for PKI INFO */
	ctx->setTransactionID  = 1;

#if 0
	ctx->referenceValue = NULL;
	ctx->secretValue = NULL;
	ctx->caCert = NULL;
	ctx->clCert = NULL;
	ctx->newClCert = NULL;
	ctx->transactionID = NULL;
	ctx->recipNonce = NULL;
	ctx->protectionAlgor = NULL;
	ctx->lastMsgSent = NULL;
	ctx->lastMsgRecvd = NULL;
#endif

	return 1;
err:
printf( "ERROR in CMP_CTX_init, FILE: %s, LINE: %d\n", __FILE__, __LINE__);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
CMP_CTX *CMP_CTX_create() {
	CMP_CTX *ctx=NULL;

	if( !(ctx = CMP_CTX_new())) goto err;
#if 0
	ctx = OPENSSL_malloc(sizeof(CMP_CTX));
#endif
	if( !(CMP_CTX_init(ctx))) goto err;

	return ctx;
err:
printf( "ERROR in CMP_CTX_create, FILE: %s, LINE: %d\n", __FILE__, __LINE__);
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
printf( "ERROR in FILE: %s, LINE: %d\n", __FILE__, __LINE__);
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
printf( "ERROR in FILE: %s, LINE: %d\n", __FILE__, __LINE__);
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
printf( "ERROR in FILE: %s, LINE: %d\n", __FILE__, __LINE__);
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
printf( "ERROR in FILE: %s, LINE: %d\n", __FILE__, __LINE__);
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
printf( "ERROR in FILE: %s, LINE: %d\n", __FILE__, __LINE__);
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

#warning SETTING CTX->PKEY SHOULD NOT CONSUME THE POINTER
#if 0
/* XXX this is NOT sufficient to copy everything! */
	ctx->pkey = EVP_PKEY_new();

	return (EVP_PKEY_copy_parameters( ctx->pkey, pkey));
#endif
	ctx->pkey = (EVP_PKEY*) pkey;
	return 1;
err:
printf( "ERROR in FILE: %s, LINE: %d\n", __FILE__, __LINE__);
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

#warning SETTING CTX->NEWPKEY SHOULD NOT CONSUME THE POINTER
#if 0
	ctx->newPkey = EVP_PKEY_new();

	return (EVP_PKEY_copy_parameters( ctx->newPkey, pkey));
#endif
	ctx->newPkey = (EVP_PKEY*) pkey;
	return 1;
err:
printf( "ERROR in FILE: %s, LINE: %d\n", __FILE__, __LINE__);
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

	if (!(ctx->transactionID = ASN1_OCTET_STRING_dup(id))) goto err;
	return 1;
err:
printf( "ERROR in FILE: %s, LINE: %d\n", __FILE__, __LINE__);
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

	if (!(ctx->recipNonce = ASN1_OCTET_STRING_dup(nonce))) goto err;
	return 1;
err:
printf( "ERROR in FILE: %s, LINE: %d\n", __FILE__, __LINE__);
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
printf( "ERROR in FILE: %s, LINE: %d\n", __FILE__, __LINE__);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set_compatibility( CMP_CTX *ctx, const int mode) {
	if (!ctx) goto err;

	ctx->compatibility = mode;
	return 1;
err:
printf( "ERROR in FILE: %s, LINE: %d\n", __FILE__, __LINE__);
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
printf( "ERROR in FILE: %s, LINE: %d\n", __FILE__, __LINE__);
	return 0;
}

/* ################################################################ */
/* ################################################################ */
int CMP_CTX_set1_serverPort( CMP_CTX *ctx, int port) {
	if (!ctx) goto err;

	ctx->serverPort = port;
	return 1;
err:
printf( "ERROR in FILE: %s, LINE: %d\n", __FILE__, __LINE__);
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
printf( "ERROR in FILE: %s, LINE: %d\n", __FILE__, __LINE__);
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
printf( "ERROR in FILE: %s, LINE: %d\n", __FILE__, __LINE__);
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
		default:
			goto err;
	}

	return 1;
err:
	return 0;
}
