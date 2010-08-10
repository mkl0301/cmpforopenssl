/* crypto/cmp/cmp_vfy.c
 * Functions to verify CMP (RFC 4210) messages for OpenSSL
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
#include <openssl/crmf.h>
#include <openssl/cmp.h>
#include <openssl/err.h>

/* ############################################################################ *
 * validate a protected message (sha1+RSA/DSA or any other algorithm supported by OpenSSL)
 * ############################################################################ */
static int CMP_verify_signature( CMP_PKIMESSAGE *msg, X509_ALGOR *algor, EVP_PKEY *senderPkey) {
	EVP_MD_CTX *ctx=NULL;
	CMP_PROTECTEDPART protPart;
	int ret;

	size_t protPartDerLen;
	unsigned char *protPartDer=NULL;

	protPart.header = msg->header;
	protPart.body   = msg->body;
	protPartDerLen  = i2d_CMP_PROTECTEDPART(&protPart, &protPartDer);

	ctx=EVP_MD_CTX_create();
	EVP_VerifyInit_ex(ctx, EVP_get_digestbynid(OBJ_obj2nid(algor->algorithm)), NULL);
	EVP_VerifyUpdate(ctx, protPartDer, protPartDerLen);
	ret = EVP_VerifyFinal(ctx, msg->protection->data, msg->protection->length, senderPkey);

	/* cleanup */
	EVP_MD_CTX_destroy(ctx);
	return ret;
}

/* ############################################################################ */
/* Validate the protection of a PKIMessage
 * returns 1 when valid
 * returns 0 when invalid, not existent or on error
 */
/* ############################################################################ */
int CMP_protection_verify(CMP_PKIMESSAGE *msg, 
			    X509_ALGOR *_algor,
			    EVP_PKEY *senderPkey,
			    const ASN1_OCTET_STRING *secret) {
	ASN1_BIT_STRING *protection=NULL;
	X509_ALGOR *algor=NULL;
	ASN1_OBJECT *algorOID=NULL;
	int valid = 0;

	int usedAlgorNid;

	if (!msg->protection) goto err;
	if (!msg->header->protectionAlg) goto err;
	if (!(algor = X509_ALGOR_dup(msg->header->protectionAlg))) goto err;

	X509_ALGOR_get0( &algorOID, NULL, NULL, algor);
	usedAlgorNid = OBJ_obj2nid(algorOID);
	if (usedAlgorNid == NID_id_PasswordBasedMAC) {
		/* need to have params for PBMAC, so check that we have them */
		if (!algor->parameter || 
				ASN1_TYPE_get(algor->parameter) == V_ASN1_UNDEF ||
				ASN1_TYPE_get(algor->parameter) == V_ASN1_NULL) {
			/* if parameter is not given in PKIMessage, then try to use parameter from arguments */
			if (!_algor || algor->algorithm->nid != _algor->algorithm->nid || 
					ASN1_TYPE_get(_algor->parameter) == V_ASN1_UNDEF || 
					ASN1_TYPE_get(_algor->parameter) == V_ASN1_NULL) {
				CMPerr(CMP_F_CMP_PROTECTION_VERIFY, CMP_R_FAILED_TO_DETERMINE_PROTECTION_ALGORITHM);
				goto err;
			}
			ASN1_TYPE_set1(algor->parameter, _algor->parameter->type, _algor->parameter->value.ptr);
		}
	}

	CMP_printf("INFO: Verifying protection, algorithm %s\n", OBJ_nid2sn(OBJ_obj2nid(msg->header->protectionAlg->algorithm)));

	if (usedAlgorNid == NID_id_PasswordBasedMAC)  {
		/* password based Mac */ 
		if (!(protection = CMP_protection_new( msg, algor, NULL, secret)))
			goto err; /* failed to generate protection string! */
		if (!M_ASN1_BIT_STRING_cmp( protection, msg->protection))
			/* protection is valid */
			valid = 1;
		else
			/* strings are not equal */
			valid = 0;
	}
	else
		valid = CMP_verify_signature(msg, algor, senderPkey);

	X509_ALGOR_free(algor);

	return valid;

err:
	if (algor) X509_ALGOR_free(algor);
	CMPerr(CMP_F_CMP_PROTECTION_VERIFY, CMP_R_CMPERROR);
	return 0;
}
