/* crypto/cmp/cmp_lib.c
 * CMP (RFC 4210) library functions for OpenSSL
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
 */


 /* NAMING
  * The 0 version uses the supplied structure pointer directly in the parent and
  * it will be freed up when the parent is freed. In the above example crl would
  * be freed but rev would not.
  *
  * The 1 function uses a copy of the supplied structure pointer (or in some
  * cases increases its link count) in the parent and so both (x and obj above)
  * should be freed up.
 */

/* ############################################################################ *
 * In this file are the functions which set the individual items inside         *
 * the CMP structures                                                          *
 * ############################################################################ */


#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crmf.h>
#include <openssl/cmp.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/safestack.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
/* for bio_err */
#include <openssl/err.h>

#include <time.h>


#if 0
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
		sprintf((char*)cpnew, "%02X", (unsigned char)(*cpold++));
		cpnew+=2;
	}
	*(cpnew) = '\0';
	return(newstr);
}
#endif

/* ############################################################################ */
/* ############################################################################ */
int CMP_PKIHEADER_set_version(CMP_PKIHEADER *hdr, int version) {
	if( !hdr) return 0;

	ASN1_INTEGER_set(hdr->pvno, version);

	return 1;
}

/* ############################################################################ */
/* ############################################################################ */
int CMP_PKIHEADER_set0_recipient(CMP_PKIHEADER *hdr, const X509_NAME *nm)
{
	GENERAL_NAME *gen=NULL;
	if( !hdr) return 0;

	gen = GENERAL_NAME_new();
	if( !gen) return 0;

	/* if nm is not set an empty dirname will be set */
	if (nm == NULL) {
		if(gen->d.directoryName) X509_NAME_free(gen->d.directoryName);
		gen->d.directoryName = X509_NAME_new();
	} else {
		if (!X509_NAME_set(&gen->d.directoryName, (X509_NAME*) nm))
		{
			GENERAL_NAME_free(gen);
			return 0;
		}
	}
	gen->type = GEN_DIRNAME;
	if (hdr->recipient)
		GENERAL_NAME_free(hdr->recipient);
	hdr->recipient = gen;
	return 1;
}

/* ############################################################################ */
int CMP_PKIHEADER_set1_recipient(CMP_PKIHEADER *hdr, const X509_NAME *nm)
{
	X509_NAME *nmDup=NULL;
	int ret;

	if( !hdr) return 0;

	if(nm)
		nmDup = X509_NAME_dup( (X509_NAME*) nm);

	if( !(ret = CMP_PKIHEADER_set0_recipient( hdr, nm)))
		if( nmDup)
			X509_NAME_free(nmDup);

	return ret;
}

/* ############################################################################ */
int CMP_PKIHEADER_set0_sender(CMP_PKIHEADER *hdr, const X509_NAME *nm)
{
	GENERAL_NAME *gen=NULL;
	if( !hdr) return 0;

	gen = GENERAL_NAME_new();
	if( !gen) return 0;

	/* if nm is not set an empty dirname will be set */
	if (nm == NULL) {
		if(gen->d.directoryName) X509_NAME_free(gen->d.directoryName);
		gen->d.directoryName = X509_NAME_new();
	} else {
		if (!X509_NAME_set(&gen->d.directoryName, (X509_NAME*) nm))
		{
			GENERAL_NAME_free(gen);
			return 0;
		}
	}
	gen->type = GEN_DIRNAME;
	if (hdr->sender)
		GENERAL_NAME_free(hdr->sender);
	hdr->sender = gen;
	return 1;
}

/* ############################################################################ */
int CMP_PKIHEADER_set1_sender(CMP_PKIHEADER *hdr, const X509_NAME *nm)
{
	X509_NAME *nmDup=NULL;
	int ret;

	if( !hdr) return 0;

	if(nm)
		nmDup = X509_NAME_dup( (X509_NAME*) nm);

	if( !(ret = CMP_PKIHEADER_set0_sender( hdr, nm)))
		if( nmDup)
			X509_NAME_free(nmDup);

	return ret;
}

#if 0
/* ############################################################################ */
int CMP_PKIHEADER_set_protectionAlg_dsa(CMP_PKIHEADER *hdr) {
	if (!hdr->protectionAlg)
		if (!(hdr->protectionAlg = X509_ALGOR_new())) goto err;
	X509_ALGOR_set0( hdr->protectionAlg, OBJ_nid2obj(NID_dsaWithSHA1), V_ASN1_NULL, NULL);
	return 1;
err:
	return 0;
}

/* ############################################################################ */
int CMP_PKIHEADER_set_protectionAlg_rsa(CMP_PKIHEADER *hdr) {
	if (!hdr->protectionAlg)
		if (!(hdr->protectionAlg = X509_ALGOR_new())) goto err;
	X509_ALGOR_set0( hdr->protectionAlg, OBJ_nid2obj(NID_sha1WithRSAEncryption), V_ASN1_NULL, NULL);
	return 1;
err:
	return 0;
}
#endif

/* ############################################################################ */
X509_ALGOR *CMP_get_protectionAlgor_by_nid(int nid) {
	X509_ALGOR *alg=NULL;

	switch(nid) {
		case NID_id_PasswordBasedMAC:
			return CMP_get_protectionAlgor_pbmac();
			break;
		case NID_sha1WithRSAEncryption:
		case NID_dsaWithSHA1:
		default:
			if( !(alg = X509_ALGOR_new())) goto err;
			if( !(X509_ALGOR_set0( alg, OBJ_nid2obj(nid), V_ASN1_NULL, NULL))) goto err;
			break;
	}
	return alg;
err:
	if (alg) X509_ALGOR_free(alg);
	return NULL;
}

#if 0
/* ############################################################################ */
int CMP_PKIHEADER_set_protectionAlg_pbmac(CMP_PKIHEADER *hdr) {
	CRMF_PBMPARAMETER *pbm=NULL;
	unsigned char *pbmDer=NULL;
	int pbmDerLen;
	ASN1_STRING *pbmStr=NULL;

	/* CRMF_pbm_new allocates and initializes */
	if (!(pbm = CRMF_pbm_new())) goto err;

	if (!hdr->protectionAlg)
		if (!(hdr->protectionAlg = X509_ALGOR_new())) goto err;

	if (!(pbmStr = ASN1_STRING_new())) goto err;
	pbmDerLen = i2d_CRMF_PBMPARAMETER( pbm, &pbmDer);
	ASN1_STRING_set( pbmStr, pbmDer, pbmDerLen);
	X509_ALGOR_set0( hdr->protectionAlg, OBJ_nid2obj(NID_id_PasswordBasedMAC), V_ASN1_SEQUENCE, pbmStr);
	CRMF_PBMPARAMETER_free( pbm);

	return 1;
err:
	/* XXX hdr->protoectionAlg is not freed on error*/
	if (pbm) CRMF_PBMPARAMETER_free( pbm);
	if (pbmStr) ASN1_STRING_free( pbmStr);
	return 0;
}
#endif

/* ############################################################################ */
X509_ALGOR *CMP_get_protectionAlgor_pbmac() {
	X509_ALGOR *alg=NULL;
	CRMF_PBMPARAMETER *pbm=NULL;
	unsigned char *pbmDer=NULL;
	int pbmDerLen;
	ASN1_STRING *pbmStr=NULL;

	if (!(alg = X509_ALGOR_new())) goto err;
	if (!(pbm = CRMF_pbm_new())) goto err;
	if (!(pbmStr = ASN1_STRING_new())) goto err;

	pbmDerLen = i2d_CRMF_PBMPARAMETER( pbm, &pbmDer);

	ASN1_STRING_set( pbmStr, pbmDer, pbmDerLen);
	pbmDer = NULL;
	X509_ALGOR_set0( alg, OBJ_nid2obj(NID_id_PasswordBasedMAC), V_ASN1_SEQUENCE, pbmStr);
	pbmStr = NULL;

	CRMF_PBMPARAMETER_free( pbm);
	return alg;
err:
	if (alg) X509_ALGOR_free(alg);
	if (pbm) CRMF_PBMPARAMETER_free( pbm);
	if (pbmStr) ASN1_STRING_free( pbmStr);
	if (pbmDer) OPENSSL_free( pbmDer);
	return NULL;
}

/* ############################################################################ */
	/*
   It is RECOMMENDED that the clients fill the transactionID field with
   128 bits of (pseudo-) random data for the start of a transaction to
   reduce the probability of having the transactionID in use at the
   server.
   */
int CMP_PKIHEADER_set1_transactionID(CMP_PKIHEADER *hdr, const ASN1_OCTET_STRING *transactionID) {
#define TRANSACTIONID_LENGTH 16
	unsigned char *transactionIDuchar=NULL;

	if( !hdr) goto err;

	if (hdr->transactionID == NULL) {
		hdr->transactionID = ASN1_OCTET_STRING_new();
	}

	/* generate a new value if none was given */
	if (transactionID == NULL) {
		transactionIDuchar = (unsigned char*)OPENSSL_malloc(TRANSACTIONID_LENGTH);
		RAND_pseudo_bytes(transactionIDuchar, TRANSACTIONID_LENGTH);
		if (!(ASN1_OCTET_STRING_set(hdr->transactionID, transactionIDuchar, TRANSACTIONID_LENGTH))) goto err;
	} else {
		if (!(hdr->transactionID = ASN1_OCTET_STRING_dup((ASN1_OCTET_STRING *)transactionID))) goto err;
	}

	if(transactionIDuchar)
		OPENSSL_free(transactionIDuchar);
	return 1;
err:
	if(transactionIDuchar)
		OPENSSL_free(transactionIDuchar);
	return 0;
}

/* ############################################################################ */
	/*
   senderNonce          present
     -- 128 (pseudo-)random bits
   The senderNonce and recipNonce fields protect the PKIMessage against
   replay attacks.  The senderNonce will typically be 128 bits of
   (pseudo-) random data generated by the sender, whereas the recipNonce
   is copied from the senderNonce of the previous message in the
   transaction.
     */

int CMP_PKIHEADER_new_senderNonce(CMP_PKIHEADER *hdr) {
#define SENDERNONCE_LENGTH 16
	unsigned char senderNonce[SENDERNONCE_LENGTH];
	RAND_pseudo_bytes(senderNonce, SENDERNONCE_LENGTH);

	if( !hdr) goto err;

	if (hdr->senderNonce == NULL) {
		hdr->senderNonce = ASN1_OCTET_STRING_new();
	}

	if (!(ASN1_OCTET_STRING_set(hdr->senderNonce, senderNonce, SENDERNONCE_LENGTH))) goto err;

	return 1;
err:
	return 0;
}


/* ############################################################################ */
/*
         -- nonces used to provide replay protection, senderNonce
         -- is inserted by the creator of this message; recipNonce
         -- is a nonce previously inserted in a related message by
         -- the intended recipient of this message
 */
int CMP_PKIHEADER_set1_recipNonce(CMP_PKIHEADER *hdr, const ASN1_OCTET_STRING *recipNonce) {
	if( !hdr) goto err;
	if( !recipNonce) goto err;

	if (hdr->recipNonce != NULL)
		ASN1_OCTET_STRING_free(hdr->recipNonce);

	if (!(hdr->recipNonce = ASN1_OCTET_STRING_dup((ASN1_OCTET_STRING *)recipNonce))) goto err;

	return 1;
err:
	return 0;
}


/* ############################################################################ */
/*
   senderKID            referenceNum
     -- the reference number which the CA has previously issued
     -- to the end entity (together with the MACing key)
     */
int CMP_PKIHEADER_set1_senderKID(CMP_PKIHEADER *hdr, const ASN1_OCTET_STRING *senderKID) {
	if (!hdr) goto err;
	if (!senderKID) goto err;

	if (hdr->senderKID)
		 ASN1_OCTET_STRING_free(hdr->senderKID);

	if (!(hdr->senderKID = ASN1_OCTET_STRING_dup((ASN1_OCTET_STRING *)senderKID))) goto err;

	return 1;
err:
	return 0;
}

/* ############################################################################
 * set the messageTime to the current system time
 *
 * The messageTime field contains the time at which the sender created
 * the message.  This may be useful to allow end entities to
 * correct/check their local time for consistency with the time on a
 * central system.
 * ############################################################################ */
int CMP_PKIHEADER_set_messageTime(CMP_PKIHEADER *hdr) {
	if (!hdr) goto err;

	if (!hdr->messageTime)
		 hdr->messageTime = ASN1_GENERALIZEDTIME_new();

	if (! ASN1_GENERALIZEDTIME_set( hdr->messageTime, time(NULL))) goto err;
	return 1;
err:
	return 0;
}

/* ############################################################################ */
/* ############################################################################ */
int CMP_PKIHEADER_set1_protectionAlgor(CMP_PKIHEADER *hdr, const X509_ALGOR *alg) {
	if (!hdr) goto err;
	if (!alg) goto err;

	if (hdr->protectionAlg)
		X509_ALGOR_free(hdr->protectionAlg);

	if (!(hdr->protectionAlg = X509_ALGOR_dup((X509_ALGOR*)alg))) goto err;

	return 1;
err:
	return 0;
}

#if 0
/* ############################################################################ */
/* push an ASN1_UTF8STRING to hdr->freeText and consume the given pointer */
/* ############################################################################ */
int CMP_PKIHEADER_push0_freeText( CMP_PKIHEADER *hdr, ASN1_UTF8STRING *text) {
	if (!hdr) goto err;
	if (!text) goto err;

	if (!hdr->freeText)
		hdr->freeText = sk_ASN1_UTF8STRING_new_null();

	if (!(sk_ASN1_UTF8STRING_push(hdr->freeText, text))) goto err;

	return 1;
err:
	return 0;
}

/* ############################################################################ */
/* push an ASN1_UTF8STRING to hdr->freeText and don't consume the given pointer */
/* ############################################################################ */
int CMP_PKIHEADER_push1_freeText( CMP_PKIHEADER *hdr, ASN1_UTF8STRING *text) {
	ASN1_UTF8STRING *textDup=NULL;

	if (!hdr) goto err;
	if (!text) goto err;

	/* XXX there is no function ASN1_UTF8STRING_dup()? */
	if( !(textDup = ASN1_UTF8STRING_new())) goto err;
	if( !ASN1_UTF8STRING_set( textDup, text->data, text->length)) goto err;

	return CMP_PKIHEADER_push0_freeText( hdr, textDup);
err:
	if (textDup) ASN1_UTF8STRING_free(textDup);
	return 0;
}

/* ############################################################################ */
/* set an ASN1_UTF8STRING stack to hdr->freeText and consume the given pointer */
/* ############################################################################ */
int CMP_PKIHEADER_set1_freeText( CMP_PKIHEADER *hdr, STACK_OF(ASN1_UTF8STRING) *text) {
	STACK_OF(ASN1_UTF8STRING) *textDup;

	if (!hdr) goto err;
	if (!text) goto err;

	if (!hdr->freeText)
		sk_ASN1_UTF8STRING_free(hdr->freeText);

	hdr->freeText = text;

	return 1;
err:
	return 0;
}

/* ############################################################################ */
/* set an ASN1_UTF8STRING stack to hdr->freeText and don't consume the given pointer */
/* ############################################################################ */
int CMP_PKIHEADER_set0_freeText( CMP_PKIHEADER *hdr, STACK_OF(ASN1_UTF8STRING) *text) {
	STACK_OF(ASN1_UTF8STRING) *textDup;

	if (!hdr) goto err;
	if (!text) goto err;

	if (!textDup = sk_ASN1_UTF8STRING_dup(text)) goto err;
	return CMP_PKIHEADER_set0_freeText( hdr, textDup);
err:
	return 0;
}
#endif


/* ############################################################################ */
/* if referenceValue is given, it will be set as senderKID
 */
int CMP_PKIHEADER_set1(CMP_PKIHEADER *hdr, CMP_CTX *ctx) {
	/* check existence of mandatory arguments */
	if( !hdr) goto err;
	if( !ctx) goto err;

	/* set the CMP version */
	CMP_PKIHEADER_set_version( hdr, CMP_VERSION);

	/* in case there is no OLD client cert, the subject name is not set */
	if( ctx->clCert) {
		if( !CMP_PKIHEADER_set1_sender( hdr, X509_get_subject_name( (X509*) ctx->clCert))) goto err;
	} else {
		if( !CMP_PKIHEADER_set1_sender( hdr, NULL)) goto err;
	}

	if( ctx->caCert) {
		if( !CMP_PKIHEADER_set1_recipient( hdr, X509_get_subject_name( (X509*) ctx->caCert))) goto err;
	} else {
		if( !CMP_PKIHEADER_set1_recipient( hdr, NULL)) goto err;
	}

	/* INSTA replies with a very strange message when the time is set */
	if( (ctx->compatibility != CMP_COMPAT_INSTA) && (ctx->compatibility != CMP_COMPAT_INSTA_3_3) ) {
		if( !CMP_PKIHEADER_set_messageTime(hdr)) goto err;
	}

	if( ctx->protectionAlgor) {
		if( !CMP_PKIHEADER_set1_protectionAlgor( hdr, ctx->protectionAlgor)) goto err;
	}

	if( ctx->referenceValue) {
		if( !CMP_PKIHEADER_set1_senderKID(hdr, ctx->referenceValue)) goto err;
	}

	/* XXX not setting transactionID test for PKI INFO */
	if( ctx->setTransactionID == 1) {
		if( ctx->transactionID) {
			if( !CMP_PKIHEADER_set1_transactionID(hdr, ctx->transactionID)) goto err;
		} else {
			/* create new transaction ID */
			if( !CMP_PKIHEADER_set1_transactionID(hdr, NULL)) goto err;
			/* XXX this is not nice, it should be done somehow through the function */
			CMP_CTX_set1_transactionID( ctx, hdr->transactionID);
		}
	}

	/* XXX not setting senderNonce test for PKI INFO */
	if( ctx->setSenderNonce == 1) {
		if( !CMP_PKIHEADER_new_senderNonce(hdr)) goto err;
	}
	if( ctx->recipNonce)
		if( !CMP_PKIHEADER_set1_recipNonce(hdr, ctx->recipNonce)) goto err;

#if 0
	/*
         freeText        [7] PKIFreeText             OPTIONAL,
         -- this may be used to indicate context-specific instructions
         -- (this field is intended for human consumption)
	 */

	if( ctx->freeText)
		if( !CMP_PKIHEADER_push1_freeText(hdr, ctx->freeText)) goto err;
#endif

	return 1;
err:
	return 0;
}


/* ############################################################################ */
/*
   In the above protectionAlg, the salt value is appended to the shared
   secret input.  The OWF is then applied iterationCount times, where
   the salted secret is the input to the first iteration and, for each
   successive iteration, the input is set to be the output of the
   previous iteration.  The output of the final iteration (called
   "BASEKEY" for ease of reference, with a size of "H") is what is used
   to form the symmetric key.  If the MAC algorithm requires a K-bit key
   and K <= H, then the most significant K bits of BASEKEY are used.  If
   K > H, then all of BASEKEY is used for the most significant H bits of
   the key, OWF("1" || BASEKEY) is used for the next most significant H
   bits of the key, OWF("2" || BASEKEY) is used for the next most
   significant H bits of the key, and so on, until all K bits have been
   derived.  [Here "N" is the ASCII byte encoding the number N and "||"
   represents concatenation.]

   Note: it is RECOMMENDED that the fields of PBMParameter remain
   constant throughout the messages of a single transaction (e.g.,
   ir/ip/certConf/pkiConf) in order to reduce the overhead associated
   with PasswordBasedMAC computation).
   */

ASN1_BIT_STRING *CMP_protection_new(CMP_PKIMESSAGE *pkimessage,
				    X509_ALGOR *_algor,
				    const EVP_PKEY *pkey,
				    const ASN1_OCTET_STRING *secret) {
	ASN1_BIT_STRING *prot=NULL;
	CMP_PROTECTEDPART protPart;
	ASN1_STRING *pbmStr=NULL;
	X509_ALGOR *algor=NULL;
	ASN1_OBJECT *algorOID=NULL;

	CRMF_PBMPARAMETER *pbm=NULL;

	size_t protPartDerLen;
	unsigned int macLen;
	size_t maxMacLen;
	unsigned char *protPartDer=NULL;
	unsigned char *mac=NULL;
	const unsigned char *pbmStrUchar=NULL;

	int pptype;
	void *ppval;

	int usedAlgorNid;

	EVP_MD_CTX *ctx=NULL;

	protPart.header = pkimessage->header;
	protPart.body   = pkimessage->body;
	protPartDerLen  = i2d_CMP_PROTECTEDPART(&protPart, &protPartDer);

	if (_algor) {
		/* algorithm is given with the arguments */
		algor = _algor;
	} else {
		/* algorithm is taken from the message */
		algor = pkimessage->header->protectionAlg;
	}

	X509_ALGOR_get0( &algorOID, &pptype, &ppval, algor);
	usedAlgorNid = OBJ_obj2nid(algorOID);

	/* XXX this should be more general - it should be verified that the right key is there (DSA or RSA) */
	switch (usedAlgorNid) {
		case NID_sha1WithRSAEncryption:
		case NID_dsaWithSHA1:

			maxMacLen = EVP_PKEY_size( (EVP_PKEY*) pkey);
			mac = OPENSSL_malloc(maxMacLen);

			ctx=EVP_MD_CTX_create();
			/* XXX do I have to do that here or somewhere else? */
			OpenSSL_add_all_digests();

			if (!(EVP_SignInit_ex(ctx, EVP_get_digestbynid(usedAlgorNid), NULL))) goto err;
			if (!(EVP_SignUpdate(ctx, protPartDer, protPartDerLen))) goto err;
			if (!(EVP_SignFinal(ctx, mac, &macLen, (EVP_PKEY*) pkey))) goto err;
			break;
		case NID_id_PasswordBasedMAC:
			/* there is no pmb set in this message */
			if (!ppval) return NULL;

			pbmStr = (ASN1_STRING *)ppval;
			pbmStrUchar = (unsigned char *)pbmStr->data;
			pbm = d2i_CRMF_PBMPARAMETER( NULL, &pbmStrUchar, pbmStr->length);

			if(!(CRMF_passwordBasedMac_new(pbm, protPartDer, protPartDerLen, secret->data, secret->length, &mac, &macLen))) goto err;
			break;
		default:
printf("FILE: %s, LINE %d, why did I hit default?\n", __FILE__, __LINE__);
			break;
	}

	if(!(prot = ASN1_BIT_STRING_new())) goto err;
	ASN1_BIT_STRING_set(prot, mac, macLen);

	/* Actually this should not be needed but OpenSSL defaults all bitstrings to be a NamedBitList */
	prot->flags &= ~0x07;
	prot->flags |= ASN1_STRING_FLAG_BITS_LEFT;

	/* cleanup */
	// XXX why does this produce an segfault?
	// EVP_MD_CTX_destroy(ctx);
	return prot;
err:
	if(prot) ASN1_BIT_STRING_free(prot);
	return NULL;
}


/* ############################################################################ */
	/*
        -- the hash of the certificate, using the same hash algorithm
        -- as is used to create and verify the certificate signature
	*/
int CMP_CERTSTATUS_set_certHash( CMP_CERTSTATUS *certStatus, const X509 *cert) {
	ASN1_OCTET_STRING *certHash=NULL;
	unsigned int hashLen;
	unsigned char hash[EVP_MAX_MD_SIZE];

	if (!certStatus) goto err;
	if (!cert) goto err;

	/* this works but TODO: does this comply with the RFC?
	        -- the hash of the certificate, using the same hash algorithm
		-- as is used to create and verify the certificate signature
		*/

	/* XXX Do I have to check what algorithm to use? */
	if (!X509_digest(cert, EVP_sha1(), hash, &hashLen)) goto err;
certHash=ASN1_OCTET_STRING_new();
	if (!ASN1_OCTET_STRING_set(certHash, hash, hashLen)) goto err;

	if (certStatus->certHash)
		ASN1_OCTET_STRING_free(certStatus->certHash);
	certStatus->certHash = certHash;

	return 1;
err:
printf("Error in file: %s, line: %d\n", __FILE__, __LINE__);
	if( certHash) ASN1_OCTET_STRING_free(certHash);
	return 0;
}


/* ############################################################################ */
/* sets implicitConfirm in the generalInfo field of the header
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIMESSAGE_set_implicitConfirm(CMP_PKIMESSAGE *msg) {
	CMP_INFOTYPEANDVALUE *itav=NULL;

	if (!msg) goto err;

	itav = CMP_INFOTYPEANDVALUE_new();
	if (! CMP_INFOTYPEANDVALUE_set0( itav, OBJ_nid2obj(NID_id_it_implicitConfirm), V_ASN1_NULL, NULL)) goto err;
	if (! CMP_PKIHEADER_generalInfo_item_push0( msg->header, itav)) goto err;
	return 1;
err:
	if (itav) CMP_INFOTYPEANDVALUE_free(itav);
	return 0;
}

/* ############################################################################
 * checks if implicitConfirm in the generalInfo field of the header is set
 * returns 1 if it is set, 0 if not
 * ############################################################################ */
int CMP_PKIMESSAGE_check_implicitConfirm(CMP_PKIMESSAGE *msg) {
	int itavCount;
	int i;
	ASN1_OBJECT *obj=NULL;
	CMP_INFOTYPEANDVALUE *itav=NULL;


	if (!msg) return 0;

	itavCount = sk_CMP_INFOTYPEANDVALUE_num(msg->header->generalInfo);

	for( i=0; i < itavCount; i++) {
		itav = sk_CMP_INFOTYPEANDVALUE_value(msg->header->generalInfo,i);
		CMP_INFOTYPEANDVALUE_get0( &obj, NULL, NULL, itav);
		if (OBJ_obj2nid(obj) == NID_id_it_implicitConfirm)
			return 1;
	}

	/* not found */
	return 0;
}


/* ############################################################################ */
/* is that really "push0" - what does "push" do? */
/* TODO: check */
/* ############################################################################ */
int CMP_PKIHEADER_generalInfo_item_push0(CMP_PKIHEADER *hdr, const CMP_INFOTYPEANDVALUE *itav) {
	if( !hdr)
		return 0;
#if 0
	/* this is allowed and will just make sure the stack is created */
	if( !itav)
		return 0;
#endif

	if( !CMP_ITAV_stack_item_push0(&hdr->generalInfo, itav))
		goto err;
	return 1;
err:
	return 0;
}

/* ############################################################################ */
/* is that really "push0" - what does "push" do? */
/* TODO: check */
/* ############################################################################ */
int CMP_PKIMESSAGE_genm_item_push0(CMP_PKIMESSAGE *msg, const CMP_INFOTYPEANDVALUE *itav) {
	if( !msg)
		return 0;
#if 0
	/* this is allowed and will just make sure the stack is created */
	if( !itav)
		return 0;
#endif

	if( !CMP_ITAV_stack_item_push0( &msg->body->value.genm, itav))
		goto err;
	return 1;
err:
	return 0;
}

/* ############################################################################ */
/* TODO: is that really "push0" - what does "push" do? */
/* @itav: a pointer to the infoTypeAndValue item to push on the stack. */
/*        If NULL it will be only made sure the stack exists */
/* ############################################################################ */
int CMP_ITAV_stack_item_push0(STACK_OF(CMP_INFOTYPEANDVALUE) **itav_sk_p, const CMP_INFOTYPEANDVALUE *itav) {
	int created = 0;

	if( !itav_sk_p)
		return 0;
#if 0
	/* this is allowed and will just make sure the stack is created */
	if( !itav)
		return 0;
#endif

	if( !*itav_sk_p) {
		/* not yet created */
		if (!(*itav_sk_p = sk_CMP_INFOTYPEANDVALUE_new_null()))
			goto err;
		created= 1;
	}
	if( itav) {
		if( !sk_CMP_INFOTYPEANDVALUE_push(*itav_sk_p, itav)) goto err;
	}
	return 1;
err:
	if( created) {
		sk_CMP_INFOTYPEANDVALUE_free(*itav_sk_p);
		*itav_sk_p = NULL;
	}
	return 0;
}

/* ############################################################################ */
/* returns the PKIStatus of the given PKIStatusInfo */
/* returns -1 on error */
/* ############################################################################ */
long CMP_PKISTATUSINFO_PKIstatus_get( CMP_PKISTATUSINFO *statusInfo) {
	if (!statusInfo) return -1;
	return ASN1_INTEGER_get(statusInfo->status);
}

/* ############################################################################ */
/* returns the PKIStatus of the given ErrorMessage */
/* returns -1 on error */
/* ############################################################################ */
long CMP_ERRORMSGCONTENT_PKIStatus_get( CMP_ERRORMSGCONTENT *error) {
	if (!error) return -1;
	return CMP_PKISTATUSINFO_PKIstatus_get(error->pKIStatusInfo);
}

/* ############################################################################ */
/* prints the PKIStatus of the given PKIStatusInfo */
/* returns 1 on success */
/* returns 0 on error */
/* ############################################################################ */
int CMP_PKISTATUSINFO_PKIstatus_print( CMP_PKISTATUSINFO *statusInfo) {
	long PKIstatus;

	if (!statusInfo) return 0;

	PKIstatus = CMP_PKISTATUSINFO_PKIstatus_get(statusInfo);
	switch (PKIstatus) {
		case CMP_PKISTATUS_accepted:
			printf("PKIStatus: accepted\n");
			break;
		case CMP_PKISTATUS_grantedWithMods:
			printf("PKIStatus: granded with mods\n");
			break;
		case CMP_PKISTATUS_rejection:
			printf("PKIStatus: rejection\n");
			break;
		case CMP_PKISTATUS_waiting:
			printf("PKIStatus: waiting\n");
			break;
		case CMP_PKISTATUS_revocationWarning:
			printf("PKIStatus: revocation warning\n");
			break;
		case CMP_PKISTATUS_revocationNotification:
			printf("PKIStatus: revocation notification\n");
			break;
		case CMP_PKISTATUS_keyUpdateWarning:
			printf("PKIStatus: key update warning\n");
			break;
		case -1:
		default:
printf("ERROR: parsing PKIStatus\n");
			/* return 0; */
			break;
	}
	return 1;
}

/* ############################################################################ */
/* prints the PKIStatus of the givven error message to stdout */
/* returns 1 on success */
/* returns 0 on error */
/* ############################################################################ */
int CMP_ERRORMSGCONTENT_PKIStatus_print( CMP_ERRORMSGCONTENT *error) {
	if (!error) return 0;
	return CMP_PKISTATUSINFO_PKIstatus_print(error->pKIStatusInfo);
}

/* ############################################################################ */
/* returns the PKIStatus of the given Certresponse */
/* returns -1 on error */
/* ############################################################################ */
long CMP_CERTRESPONSE_PKIStatus_get( CMP_CERTRESPONSE *resp) {
	if (!resp) return -1;
	return CMP_PKISTATUSINFO_PKIstatus_get(resp->status);
}

/* ############################################################################ */
/* prints the PKIFailureInfo to stdout */
/* returns 1 on success */
/* returns 0 on error */
/* ############################################################################ */
int CMP_PKISTATUSINFO_PKIFailureInfo_print( CMP_PKISTATUSINFO *statusInfo) {
	int i;

	if (!statusInfo) return 0;
	for ( i=0; i <= CMP_PKIFAILUREINFO_MAX; i++) {
		if( ASN1_BIT_STRING_get_bit(statusInfo->failInfo, i)) {
			switch (i) {
				case CMP_PKIFAILUREINFO_badAlg:
					printf("PKIFailureInfo: badAlg\n");
					break;
				case CMP_PKIFAILUREINFO_badMessageCheck:
					printf("PKIFailureInfo: badMessageCheck\n");
					break;
				case CMP_PKIFAILUREINFO_badRequest:
					printf("PKIFailureInfo: badRequest\n");
					break;
				case CMP_PKIFAILUREINFO_badTime:
					printf("PKIFailureInfo: badTime\n");
					break;
				case CMP_PKIFAILUREINFO_badCertId:
					printf("PKIFailureInfo: badCertId\n");
					break;
				case CMP_PKIFAILUREINFO_badDataFormat:
					printf("PKIFailureInfo: badDataFormat\n");
					break;
				case CMP_PKIFAILUREINFO_wrongAuthority:
					printf("PKIFailureInfo: wrongAuthority\n");
					break;
				case CMP_PKIFAILUREINFO_incorrectData:
					printf("PKIFailureInfo: incorrectData\n");
					break;
				case CMP_PKIFAILUREINFO_missingTimeStamp:
					printf("PKIFailureInfo: missingTimeStamp\n");
					break;
				case CMP_PKIFAILUREINFO_badPOP:
					printf("PKIFailureInfo: badPOP\n");
					break;
				case CMP_PKIFAILUREINFO_certRevoked:
					printf("PKIFailureInfo: certRevoked\n");
					break;
				case CMP_PKIFAILUREINFO_certConfirmed:
					printf("PKIFailureInfo: certConfirmed\n");
					break;
				case CMP_PKIFAILUREINFO_wrongIntegrity:
					printf("PKIFailureInfo: wrongIntegrity\n");
					break;
				case CMP_PKIFAILUREINFO_badRecipientNonce:
					printf("PKIFailureInfo: badRecipientNonce\n");
					break;
				case CMP_PKIFAILUREINFO_timeNotAvailable:
					printf("PKIFailureInfo: timeNotAvailable\n");
					break;
				case CMP_PKIFAILUREINFO_unacceptedPolicy:
					printf("PKIFailureInfo: unacceptedPolicy\n");
					break;
				case CMP_PKIFAILUREINFO_unacceptedExtension:
					printf("PKIFailureInfo: unacceptedExtension\n");
					break;
				case CMP_PKIFAILUREINFO_addInfoNotAvailable:
					printf("PKIFailureInfo: addInfoNotAvailable\n");
					break;
				case CMP_PKIFAILUREINFO_badSenderNonce:
					printf("PKIFailureInfo: badSenderNonce\n");
					break;
				case CMP_PKIFAILUREINFO_badCertTemplate:
					printf("PKIFailureInfo: badCertTemplate\n");
					break;
				case CMP_PKIFAILUREINFO_signerNotTrusted:
					printf("PKIFailureInfo: signerNotTrusted\n");
					break;
				case CMP_PKIFAILUREINFO_transactionIdInUse:
					printf("PKIFailureInfo: transactionIdInUse\n");
					break;
				case CMP_PKIFAILUREINFO_unsupportedVersion:
					printf("PKIFailureInfo: unsupportedVersion\n");
					break;
				case CMP_PKIFAILUREINFO_notAuthorized:
					printf("PKIFailureInfo: notAuthorized\n");
					break;
				case CMP_PKIFAILUREINFO_systemUnavail:
					printf("PKIFailureInfo: systemUnavail\n");
					break;
				case CMP_PKIFAILUREINFO_systemFailure:
					printf("PKIFailureInfo: systemFailure\n");
					break;
				case CMP_PKIFAILUREINFO_duplicateCertReq:
					printf("PKIFailureInfo: duplicateCertReq\n");
					break;
			}
		}
	}
	return 1;
}

/* ############################################################################ */
/* returns the PKIFailureInfo # of the given ErrorMessage */
/* returns 1 on success */
/* returns 0 on error */
/* ############################################################################ */
int CMP_ERRORMSGCONTENT_PKIFailureInfo_print( CMP_ERRORMSGCONTENT *error) {
	if (!error) return 0;
	return CMP_PKISTATUSINFO_PKIFailureInfo_print(error->pKIStatusInfo);
}

/* ############################################################################ */
/* returns the PKIStatus of the given certReqId inside a CertRepMessage */
/* returns -1 on error */
/* ############################################################################ */
long CMP_CERTREPMESSAGE_PKIStatus_get( CMP_CERTREPMESSAGE *certRep, long certReqId) {
	CMP_CERTRESPONSE *certResponse=NULL;
	if (!certRep) return -1;

	if ( (certResponse = CMP_CERTREPMESSAGE_certResponse_get0( certRep, certReqId)) ) {
		return (CMP_CERTRESPONSE_PKIStatus_get(certResponse));
	}

	/* did not find a CertResponse with the right certRep */
	return -1;
}


/* ############################################################################ */
/* returns 1 if a given bit is set in a PKIFailureInfo */
/*              0 if            not set */
/*             -1 on error */
/* PKIFailureInfo ::= ASN1_BIT_STRING */
/* ############################################################################ */
int CMP_PKIFAILUREINFO_check( ASN1_BIT_STRING *failInfo, int codeBit) {
	if (!failInfo) return -1;
	if ( (codeBit < 0) || (codeBit > CMP_PKIFAILUREINFO_MAX)) return -1;

	return ASN1_BIT_STRING_get_bit( failInfo, codeBit);
}


/* ############################################################################ */
/* returns a pointer to the CertResponse with the given certReqId inside a CertRepMessage */
/* returns NULL on error or if no CertResponse available */
/* ############################################################################ */
CMP_CERTRESPONSE *CMP_CERTREPMESSAGE_certResponse_get0( CMP_CERTREPMESSAGE *certRep, long certReqId) {
	CMP_CERTRESPONSE *certResponse=NULL;
	int certRespCount;
	int i;

	if( !certRep) return NULL;

	certRespCount = sk_CMP_CERTRESPONSE_num( certRep->response);

	for( i=0; i < certRespCount; i++) {
		/* is it the right certReqId */
		if( certReqId == ASN1_INTEGER_get(sk_CMP_CERTRESPONSE_value(certRep->response,i)->certReqId) ) {
			certResponse = sk_CMP_CERTRESPONSE_value(certRep->response,i);
			break;
		}
	}

	return certResponse;
}



/* ############################################################################ */
/* returns a pointer to the Certificate with the given certReqId inside a CertRepMessage */
/* returns NULL on error or if no Certificate available */
/* ############################################################################ */
X509 *CMP_CERTREPMESSAGE_cert_get0( CMP_CERTREPMESSAGE *certRep, long certReqId) {
	X509 *cert=NULL;
	CMP_CERTRESPONSE *certResponse=NULL;

	if( !certRep) return NULL;

	if ( (certResponse = CMP_CERTREPMESSAGE_certResponse_get0( certRep, certReqId)) ) {
		cert = certResponse->certifiedKeyPair->certOrEncCert->value.certificate;
	}

	return cert;
}

/* ############################################################################ */
/* returns a pointer to a copy of the Certificate with the given certReqId inside a CertRepMessage */
/* returns NULL on error or if no Certificate available */
/* ############################################################################ */
X509 *CMP_CERTREPMESSAGE_cert_get1( CMP_CERTREPMESSAGE *certRep, long certReqId) {
	X509 *cert=NULL;
	X509 *certCopy=NULL;

	if( !certRep) return NULL;

	if( (cert = CMP_CERTREPMESSAGE_cert_get0(certRep, certReqId)))
		certCopy = X509_dup(cert);
	return certCopy;
}

/* ############################################################################ */
/* returns 1 on success */
/* returns 0 on error */
/* ############################################################################ */
int CMP_PKIMESSAGE_set_bodytype( CMP_PKIMESSAGE *msg, int type) {
	if( !msg) return 0;

	msg->body->type = type;

	return 1;
}

/* ############################################################################ */
/* returns the body type of the given CMP message */
/* returns -1 on error */
/* ############################################################################ */
int CMP_PKIMESSAGE_get_bodytype( CMP_PKIMESSAGE *msg) {
	if( !msg) return -1;

	return msg->body->type;
}

/* ############################################################################ */
/* returns 1 on success */
/* returns 0 on error */
/* TODO: work in progress */
/* ############################################################################ */
int CMP_PKIMESSAGE_parse_error_msg( CMP_PKIMESSAGE *msg) {
	if( !msg) return 0;
	if( CMP_PKIMESSAGE_get_bodytype(msg) != V_CMP_PKIBODY_ERROR) return 0;

	CMP_ERRORMSGCONTENT_PKIStatus_print(msg->body->value.error);

	/* PKIFailureInfo is optional */
	CMP_ERRORMSGCONTENT_PKIFailureInfo_print(msg->body->value.error);

	return 1;
}

