/* vim: set noet ts=4 sts=4 sw=4: */
/* crypto/cmp/cmp_lib.c
 * CMP (RFC 4210) library functions for OpenSSL
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
 * Copyright 2007-2012 Nokia Siemens Networks Oy. ALL RIGHTS RESERVED.
 * CMP support in OpenSSL originally developed by 
 * Nokia Siemens Networks for contribution to the OpenSSL project.
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
 * In this file are the functions which set the individual items inside			*
 * the CMP structures															*
 * ############################################################################ */


#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crmf.h>
#include <openssl/cmp.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/safestack.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
/* for bio_err */
#include <openssl/err.h>

#include <time.h>
#include <string.h>

/* ############################################################################ *
 * Sets the protocol version number in PKIHeader.
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIHEADER_set_version(CMP_PKIHEADER *hdr, int version) {
	if( !hdr) goto err;

	if(! ASN1_INTEGER_set(hdr->pvno, version)) goto err;

	return 1;
err:
	return 0;
}

/* ############################################################################ *
 * Set the recipient name of PKIHeader.
 * when nm is NULL, recipient is set to an empty string
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIHEADER_set1_recipient(CMP_PKIHEADER *hdr, const X509_NAME *nm)
{
	GENERAL_NAME *gen=NULL;
	if( !hdr) goto err;

	gen = GENERAL_NAME_new();
	if( !gen) goto err;

	gen->type = GEN_DIRNAME;

	/* if nm is not set an empty dirname will be set */
	if (nm == NULL) {
		gen->d.directoryName = X509_NAME_new();
	} else {
		if (!X509_NAME_set(&gen->d.directoryName, (X509_NAME*) nm))
		{
			GENERAL_NAME_free(gen);
			goto err;
		}
	}

	if (hdr->recipient)
		GENERAL_NAME_free(hdr->recipient);
	hdr->recipient = gen;

	return 1;
err:
	return 0;
}

/* ############################################################################ *
 * Set the sender name in PKIHeader.
 * when nm is NULL, sender is set to an empty string
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIHEADER_set1_sender(CMP_PKIHEADER *hdr, const X509_NAME *nm)
{
	GENERAL_NAME *gen=NULL;
	if( !hdr) goto err;

	gen = GENERAL_NAME_new();
	if( !gen) goto err;

	gen->type = GEN_DIRNAME;

	/* if nm is not set an empty dirname will be set */
	if (nm == NULL) {
		gen->d.directoryName = X509_NAME_new();
	} else {
		if (!X509_NAME_set(&gen->d.directoryName, (X509_NAME*) nm))
		{
			GENERAL_NAME_free(gen);
			goto err;
		}
	}
	if (hdr->sender)
		GENERAL_NAME_free(hdr->sender);
	hdr->sender = gen;

	return 1;
err:
	return 0;
}

/* ############################################################################ *
 * (re-)set given transaction ID in CMP header
 * if given *transactionID is NULL, a random one is created with 128 bit
 * according to section 5.1.1:
 *
 * It is RECOMMENDED that the clients fill the transactionID field with
 * 128 bits of (pseudo-) random data for the start of a transaction to
 * reduce the probability of having the transactionID in use at the
 * server.
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIHEADER_set1_transactionID(CMP_PKIHEADER *hdr, const ASN1_OCTET_STRING *transactionID) {
#define TRANSACTIONID_LENGTH 16
	unsigned char *transactionIDuchar=NULL;

	if(!hdr) goto err;

	if(transactionID) {
		if (!(hdr->transactionID = ASN1_OCTET_STRING_dup((ASN1_OCTET_STRING *)transactionID))) goto err;
	} else {
		/* generate a random value if none was given */
		if(!(transactionIDuchar = (unsigned char*)OPENSSL_malloc(TRANSACTIONID_LENGTH))) goto err;
		RAND_pseudo_bytes(transactionIDuchar, TRANSACTIONID_LENGTH);

		if(hdr->transactionID == NULL) {
			hdr->transactionID = ASN1_OCTET_STRING_new();
		}
		if(!(ASN1_OCTET_STRING_set(hdr->transactionID, transactionIDuchar, TRANSACTIONID_LENGTH))) goto err;

		OPENSSL_free(transactionIDuchar);
	}

	return 1;
err:
	if(transactionIDuchar)
		OPENSSL_free(transactionIDuchar);
	return 0;
}

/* ############################################################################ *
 * (re-)set random senderNonce to given header
 * as in 5.1.1:
 *
 * senderNonce			present
 *	   -- 128 (pseudo-)random bits
 * The senderNonce and recipNonce fields protect the PKIMessage against
 * replay attacks.	The senderNonce will typically be 128 bits of
 * (pseudo-) random data generated by the sender, whereas the recipNonce
 * is copied from the senderNonce of the previous message in the
 * transaction.
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIHEADER_new_senderNonce(CMP_PKIHEADER *hdr) {
#define SENDERNONCE_LENGTH 16
	unsigned char senderNonce[SENDERNONCE_LENGTH];

	if( !hdr) goto err;

	RAND_pseudo_bytes(senderNonce, SENDERNONCE_LENGTH);

	if (hdr->senderNonce == NULL) {
		hdr->senderNonce = ASN1_OCTET_STRING_new();
	}

	if (!(ASN1_OCTET_STRING_set(hdr->senderNonce, senderNonce, SENDERNONCE_LENGTH))) goto err;

	return 1;
err:
	return 0;
}

/* ############################################################################ *
 * (re-)sets given recipient nonce to given header
 * as per 5.1.1 used to mirror the nonce back to the other side
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIHEADER_set1_recipNonce(CMP_PKIHEADER *hdr, const ASN1_OCTET_STRING *recipNonce) {
	if (!hdr) goto err;
	if (!recipNonce) goto err;

	if (hdr->recipNonce)
		ASN1_OCTET_STRING_free(hdr->recipNonce);

	if (!(hdr->recipNonce = ASN1_OCTET_STRING_dup((ASN1_OCTET_STRING *)recipNonce))) goto err;

	return 1;
err:
	return 0;
}

/* ############################################################################ * 
 * (re-)set given senderKID to given header
 *
 * senderKID			referenceNum
 *	 -- the reference number which the CA has previously issued
 *	 -- to the end entity (together with the MACing key)
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
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
 * (re-)set the messageTime to the current system time
 *
 * as in 5.1.1:
 *
 * The messageTime field contains the time at which the sender created
 * the message.  This may be useful to allow end entities to
 * correct/check their local time for consistency with the time on a
 * central system.
 *
 * returns 1 on success, 0 on error
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

/* ############################################################################ *
 * push given ASN1_UTF8STRING to hdr->freeText and consume the given pointer
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIHEADER_push0_freeText( CMP_PKIHEADER *hdr, ASN1_UTF8STRING *text) {
	if (!hdr) goto err;
	if (!text) goto err;

	if (!hdr->freeText)
		if (!(hdr->freeText = sk_ASN1_UTF8STRING_new_null())) goto err;

	if (!(sk_ASN1_UTF8STRING_push(hdr->freeText, text))) goto err;

	return 1;
err:
	return 0;
}

/* ############################################################################ *
 * push an ASN1_UTF8STRING to hdr->freeText and don't consume the given pointer
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIHEADER_push1_freeText( CMP_PKIHEADER *hdr, ASN1_UTF8STRING *text) {
	ASN1_UTF8STRING *textDup=NULL;

	if (!hdr) goto err;
	if (!text) goto err;

	if( !(textDup = ASN1_UTF8STRING_new())) goto err;
	if( !ASN1_STRING_set( textDup, text->data, text->length)) goto err;

	return CMP_PKIHEADER_push0_freeText( hdr, textDup);
err:
	if (textDup) ASN1_UTF8STRING_free(textDup);
	return 0;
}

/* ############################################################################ *
 * Initialize the given PkiHeader structure with values set in the CMP_CTX structure.
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIHEADER_set1(CMP_PKIHEADER *hdr, CMP_CTX *ctx) {
	/* check existence of mandatory arguments */
	if( !hdr) goto err;
	if( !ctx) goto err;

	/* set the CMP version */
	CMP_PKIHEADER_set_version( hdr, CMP_VERSION);

	/* in case there is no OLD client cert the sender name is not set (e.g. for IR) */
	if( ctx->clCert) {
		if( !CMP_PKIHEADER_set1_sender( hdr, X509_get_subject_name( (X509*) ctx->clCert))) goto err;
	} else {
		if( !CMP_PKIHEADER_set1_sender( hdr, NULL)) goto err;
	}

	/* set recipient name either from known server certificate or recipient name in ctx, leave empty if not set in ctx */
	if( ctx->srvCert) {
		if( !CMP_PKIHEADER_set1_recipient( hdr, X509_get_subject_name( (X509*) ctx->srvCert))) goto err;
	} else if( ctx->recipient) {
		if( !CMP_PKIHEADER_set1_recipient( hdr, ctx->recipient)) goto err;
	} else {
		if( !CMP_PKIHEADER_set1_recipient( hdr, NULL)) goto err;
	}

	/* set current time as message time */
	if( !CMP_PKIHEADER_set_messageTime(hdr)) goto err;

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
		 freeText		 [7] PKIFreeText			 OPTIONAL,
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


/* ############################################################################ * 
 * also used for verification from cmp_vfy
 *
 * calculate PBM protection for given PKImessage utilizing the given secret and the
 * pbm-parameters set inside the message header's protectionAlg
 *
 * returns pointer to ASN1_BIT_STRING containing protection on success, NULL on
 * error
 * ############################################################################ */
ASN1_BIT_STRING *CMP_calc_protection_pbmac(CMP_PKIMESSAGE *pkimessage, const ASN1_OCTET_STRING *secret) {
	ASN1_BIT_STRING *prot=NULL;
	CMP_PROTECTEDPART protPart;
	ASN1_STRING *pbmStr=NULL;
	ASN1_OBJECT *algorOID=NULL;

	CRMF_PBMPARAMETER *pbm=NULL;

	size_t protPartDerLen;
	unsigned int macLen;
	unsigned char *protPartDer=NULL;
	unsigned char *mac=NULL;
	const unsigned char *pbmStrUchar=NULL;

	void *ppval=NULL;
	int pptype=0;

	if (!secret) {
		CMPerr(CMP_F_CMP_CALC_PROTECTION_PBMAC, CMP_R_NO_SECRET_VALUE_GIVEN_FOR_PBMAC);
		goto err;
	}

	protPart.header = pkimessage->header;
	protPart.body	= pkimessage->body;
	protPartDerLen	= i2d_CMP_PROTECTEDPART(&protPart, &protPartDer);

	X509_ALGOR_get0( &algorOID, &pptype, &ppval, pkimessage->header->protectionAlg);

	if (NID_id_PasswordBasedMAC == OBJ_obj2nid(algorOID)) {
		/* there is no pmb set in this message */
		if (!ppval) goto err;

		pbmStr = (ASN1_STRING *)ppval;
		pbmStrUchar = (unsigned char *)pbmStr->data;
		pbm = d2i_CRMF_PBMPARAMETER( NULL, &pbmStrUchar, pbmStr->length);

		if(!(CRMF_passwordBasedMac_new(pbm, protPartDer, protPartDerLen, secret->data, secret->length, &mac, &macLen))) goto err;
	} else {
		CMPerr(CMP_F_CMP_CALC_PROTECTION_PBMAC, CMP_R_WRONG_ALGORITHM_OID);
		goto err;
	}

	if(!(prot = ASN1_BIT_STRING_new())) goto err;
	ASN1_BIT_STRING_set(prot, mac, macLen);

	/* Actually this should not be needed but OpenSSL defaults all bitstrings to be a NamedBitList */
	prot->flags &= ~0x07;
	prot->flags |= ASN1_STRING_FLAG_BITS_LEFT;

	/* cleanup */
	if (mac) OPENSSL_free(mac);
	return prot;

err:
	if (mac) OPENSSL_free(mac);

	CMPerr(CMP_F_CMP_CALC_PROTECTION_PBMAC, CMP_R_ERROR_CALCULATING_PROTECTION);
	if(prot) ASN1_BIT_STRING_free(prot);
	return NULL;
}

/* ############################################################################ * 
 * only used internally
 *
 * calculate signature protection for given PKImessage utilizing the given secret key 
 * and the algorithm parameters set inside the message header's protectionAlg
 *
 * returns pointer to ASN1_BIT_STRING containing protection on success, NULL on
 * error
 * ############################################################################ */
ASN1_BIT_STRING *CMP_calc_protection_sig(CMP_PKIMESSAGE *pkimessage, EVP_PKEY *pkey) {
	ASN1_BIT_STRING *prot=NULL;
	CMP_PROTECTEDPART protPart;
	ASN1_OBJECT *algorOID=NULL;

	size_t protPartDerLen;
	unsigned int macLen;
	size_t maxMacLen;
	unsigned char *protPartDer=NULL;
	unsigned char *mac=NULL;

	void *ppval=NULL;
	int pptype=0;

	EVP_MD_CTX	 *evp_ctx=NULL;
	const EVP_MD *md=NULL;

	if (!pkey) { /* EVP_SignFinal() will check that pkey type is correct for the algorithm */
		CMPerr(CMP_F_CMP_CALC_PROTECTION_SIG, CMP_R_INVALID_KEY);
		ERR_add_error_data(1, "pkey was NULL although it is supposed to be used for generating protection");
		goto err;
	}

	/* construct data to be signed */
	protPart.header = pkimessage->header;
	protPart.body	= pkimessage->body;
	protPartDerLen	= i2d_CMP_PROTECTEDPART(&protPart, &protPartDer);

	X509_ALGOR_get0( &algorOID, &pptype, &ppval, pkimessage->header->protectionAlg);

	if ((md = EVP_get_digestbynid(OBJ_obj2nid(algorOID)))) {

		maxMacLen = EVP_PKEY_size(pkey);
		mac = OPENSSL_malloc(maxMacLen);

		/* calculate signature */
		evp_ctx = EVP_MD_CTX_create();
		if (!(EVP_SignInit_ex(evp_ctx, md, NULL))) goto err;
		if (!(EVP_SignUpdate(evp_ctx, protPartDer, protPartDerLen))) goto err;
		if (!(EVP_SignFinal(evp_ctx, mac, &macLen, pkey))) goto err;
	} else {
		CMPerr(CMP_F_CMP_CALC_PROTECTION_SIG, CMP_R_UNKNOWN_ALGORITHM_ID);
		goto err;
	}

	if(!(prot = ASN1_BIT_STRING_new())) goto err;
	ASN1_BIT_STRING_set(prot, mac, macLen);

	/* Actually this should not be needed but OpenSSL defaults all bitstrings to be a NamedBitList */
	prot->flags &= ~0x07;
	prot->flags |= ASN1_STRING_FLAG_BITS_LEFT;

	/* cleanup */
	if (evp_ctx) EVP_MD_CTX_destroy(evp_ctx);
	if (mac) OPENSSL_free(mac);
	return prot;

err:
	if (evp_ctx) EVP_MD_CTX_destroy(evp_ctx);
	if (mac) OPENSSL_free(mac);

	CMPerr(CMP_F_CMP_CALC_PROTECTION_SIG, CMP_R_ERROR_CALCULATING_PROTECTION);
	if(prot) ASN1_BIT_STRING_free(prot);
	return NULL;
}

/* ############################################################################ *
 * internal function
 * Create an X509_ALGOR structure for PasswordBasedMAC protection
 * returns pointer to X509_ALGOR on success, NULL on error
 * TODO: this could take options to configure the pbmac
 * ############################################################################ */
X509_ALGOR *CMP_create_pbmac_algor(void) {
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
	OPENSSL_free( pbmDer);
	pbmDer = NULL; /* to avoid double free in case there would be a "goto err" inserted behind this point later in development */

	X509_ALGOR_set0( alg, OBJ_nid2obj(NID_id_PasswordBasedMAC), V_ASN1_SEQUENCE, pbmStr);
	pbmStr = NULL; /* pbmStr is not freed explicityly because the pointer was consumed by X509_ALGOR_set0() */

	CRMF_PBMPARAMETER_free( pbm);
	return alg;
err:
	if (alg) X509_ALGOR_free(alg);
	if (pbm) CRMF_PBMPARAMETER_free( pbm);
	if (pbmDer) OPENSSL_free( pbmDer);
	return NULL;
}

/* ############################################################################ *
 * determines which kind of protection should be created based on the ctx
 * sets this into the protectionAlg field in the message header
 * calculates the protection and sets it in the protections filed
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIMESSAGE_protect(CMP_CTX *ctx, CMP_PKIMESSAGE *msg) {
	if(!ctx) goto err;
	if(!msg) goto err;

	/* use PasswordBasedMac according to 5.1.3.1 if secretValue is given */
	if (ctx->secretValue) {
		if(!(msg->header->protectionAlg = CMP_create_pbmac_algor())) goto err;
		CMP_PKIHEADER_set1_senderKID(msg->header, ctx->referenceValue);
		if(!(msg->protection = CMP_calc_protection_pbmac( msg, ctx->secretValue))) 
			goto err;
	} else {
		/* use MSG_SIG_ALG according to 5.1.3.3 if client Certificate and private key is given */
		if (ctx->clCert && ctx->pkey) {
			ASN1_OCTET_STRING *subjKeyIDStr = NULL;
			int algNID = 0;
			
#if 0
			if (!ctx->clCert->sig_alg) goto err;
			if (!(msg->header->protectionAlg = X509_ALGOR_dup(ctx->clCert->sig_alg))) goto err;
#else
			/* TODO SHA1 is hardcoded here */
			if (msg->header->protectionAlg)
				X509_ALGOR_free(msg->header->protectionAlg);
			msg->header->protectionAlg = X509_ALGOR_new();
			
			switch (EVP_PKEY_type(ctx->pkey->type)) {
				case EVP_PKEY_DSA: 
					algNID = NID_dsaWithSHA1;
					break;
				case EVP_PKEY_RSA:
					algNID = NID_sha1WithRSAEncryption;
					break;
				default:
					CMPerr(CMP_F_CMP_PKIMESSAGE_PROTECT, CMP_R_UNSUPPORTED_KEY_TYPE);
					goto err;
			}
			X509_ALGOR_set0(msg->header->protectionAlg, OBJ_nid2obj(algNID), V_ASN1_NULL, NULL);
#endif

			subjKeyIDStr = CMP_get_subject_key_id(ctx->clCert);
			if (subjKeyIDStr) {
				CMP_PKIHEADER_set1_senderKID(msg->header, subjKeyIDStr);
				ASN1_OCTET_STRING_free(subjKeyIDStr);
			}
			
			if (!(msg->protection = CMP_calc_protection_sig( msg, ctx->pkey))) 
				goto err;
		} else {
			CMPerr(CMP_F_CMP_PKIMESSAGE_PROTECT, CMP_R_MISSING_KEY_INPUT_FOR_CREATING_PROTECTION);
			goto err;
		}
	}

	return 1;
err:
	CMPerr(CMP_F_CMP_PKIMESSAGE_PROTECT, CMP_R_ERROR_PROTECTING_MESSAGE);
	return 0;
}

/* ############################################################################ * 
		-- the hash of the certificate, using the same hash algorithm
		-- as is used to create and verify the certificate signature
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_CERTSTATUS_set_certHash( CMP_CERTSTATUS *certStatus, const X509 *cert) {
	ASN1_OCTET_STRING *certHash=NULL;
	unsigned int hashLen;
	unsigned char hash[EVP_MAX_MD_SIZE];
	int sigAlgID;
	const EVP_MD *md = NULL;

	if (!certStatus) goto err;
	if (!cert) goto err;

	sigAlgID = OBJ_obj2nid(cert->sig_alg->algorithm);

	/* select algorithm based on the one used in the cert signature */
	if ((md = EVP_get_digestbynid(sigAlgID))) {
		if (!X509_digest(cert, md, hash, &hashLen)) goto err;
		if (!(certHash=ASN1_OCTET_STRING_new())) goto err;
		if (!ASN1_OCTET_STRING_set(certHash, hash, hashLen)) goto err;

		if (certStatus->certHash)
			ASN1_OCTET_STRING_free(certStatus->certHash);
		certStatus->certHash = certHash;
	}
	else {
		CMPerr(CMP_F_CMP_CERTSTATUS_SET_CERTHASH, CMP_R_UNSUPPORTED_ALGORITHM);
		goto err;
	}

	return 1;
err:
	CMPerr(CMP_F_CMP_CERTSTATUS_SET_CERTHASH, CMP_R_ERROR_SETTING_CERTHASH);
	if( certHash) ASN1_OCTET_STRING_free(certHash);
	return 0;
}

/* ############################################################################ *
 * sets implicitConfirm in the generalInfo field of the PKIMessage header
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIMESSAGE_set_implicitConfirm(CMP_PKIMESSAGE *msg) {
	CMP_INFOTYPEANDVALUE *itav=NULL;

	if (!msg) goto err;

	if (!(itav = CMP_INFOTYPEANDVALUE_new())) goto err;
	itav->infoType = OBJ_nid2obj(NID_id_it_implicitConfirm);
	itav->infoValue.implicitConfirm = ASN1_NULL_new();
	if (!CMP_PKIHEADER_generalInfo_item_push0( msg->header, itav)) goto err;
	return 1;
err:
	if (itav) CMP_INFOTYPEANDVALUE_free(itav);
	return 0;
}

/* ############################################################################
 * checks if implicitConfirm in the generalInfo field of the header is set
 *
 * returns 1 if it is set, 0 if not
 * ############################################################################ */
int CMP_PKIMESSAGE_check_implicitConfirm(CMP_PKIMESSAGE *msg) {
	int itavCount;
	int i;
	CMP_INFOTYPEANDVALUE *itav=NULL;

	if (!msg) return 0;

	itavCount = sk_CMP_INFOTYPEANDVALUE_num(msg->header->generalInfo);

	for( i=0; i < itavCount; i++) {
		itav = sk_CMP_INFOTYPEANDVALUE_value(msg->header->generalInfo,i);
		if (OBJ_obj2nid(itav->infoType) == NID_id_it_implicitConfirm)
			return 1;
	}

	/* not found */
	return 0;
}

/* ############################################################################ * 
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIHEADER_generalInfo_item_push0(CMP_PKIHEADER *hdr, const CMP_INFOTYPEANDVALUE *itav) {
	if( !hdr)
		return 0;

	if( !CMP_ITAV_stack_item_push0(&hdr->generalInfo, itav))
		goto err;
	return 1;
err:
	return 0;
}

/* ############################################################################ * 
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIMESSAGE_genm_item_push0(CMP_PKIMESSAGE *msg, const CMP_INFOTYPEANDVALUE *itav) {
	if (!msg)
		return 0;

	if (!CMP_ITAV_stack_item_push0( &msg->body->value.genm, itav))
		goto err;
	return 1;
err:
	return 0;
}

/* ############################################################################ * 
 * @itav: a pointer to the infoTypeAndValue item to push on the stack.
 *		  If NULL it will be only made sure the stack exists
 *
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_ITAV_stack_item_push0(STACK_OF(CMP_INFOTYPEANDVALUE) **itav_sk_p, const CMP_INFOTYPEANDVALUE *itav) {
	int created = 0;

	if (!itav_sk_p)
		return 0;

	if (!*itav_sk_p) {
		/* not yet created */
		if (!(*itav_sk_p = sk_CMP_INFOTYPEANDVALUE_new_null()))
			goto err;
		created = 1;
	}
	if (itav) {
		if (!sk_CMP_INFOTYPEANDVALUE_push(*itav_sk_p, itav)) goto err;
	}
	return 1;
err:
	if (created) {
		sk_CMP_INFOTYPEANDVALUE_pop_free(*itav_sk_p, CMP_INFOTYPEANDVALUE_free);
		*itav_sk_p = NULL;
	}
	return 0;
}

/* ############################################################################ * 
 * returns the PKIStatus of the given PKIStatusInfo
 * returns -1 on error
 * ############################################################################ */
long CMP_PKISTATUSINFO_PKIstatus_get( CMP_PKISTATUSINFO *statusInfo) {
	if (!statusInfo) return -1;
	return ASN1_INTEGER_get(statusInfo->status);
}

/* ############################################################################ * 
 * returns the PKIStatus of the given ErrorMessage
 * returns -1 on error
 * ############################################################################ */
long CMP_ERRORMSGCONTENT_PKIStatus_get( CMP_ERRORMSGCONTENT *error) {
	if (!error) return -1;
	return CMP_PKISTATUSINFO_PKIstatus_get(error->pKIStatusInfo);
}

/* ############################################################################ * 
 * returns the PKIStatus of the given PKIStatusInfo
 * or NULL on error
 * ############################################################################ */
char *CMP_PKISTATUSINFO_PKIstatus_get_string( CMP_PKISTATUSINFO *statusInfo) {
	long PKIstatus;

	if (!statusInfo) return 0;

	PKIstatus = CMP_PKISTATUSINFO_PKIstatus_get(statusInfo);
	switch (PKIstatus) {
		case CMP_PKISTATUS_accepted:
			return "PKIStatus: accepted";
		case CMP_PKISTATUS_grantedWithMods:
			return "PKIStatus: granded with mods";
		case CMP_PKISTATUS_rejection:
			return "PKIStatus: rejection";
		case CMP_PKISTATUS_waiting:
			return "PKIStatus: waiting";
		case CMP_PKISTATUS_revocationWarning:
			return "PKIStatus: revocation warning";
		case CMP_PKISTATUS_revocationNotification:
			return "PKIStatus: revocation notification";
		case CMP_PKISTATUS_keyUpdateWarning:
			return "PKIStatus: key update warning";
		case -1:
		default:
			CMPerr(CMP_F_CMP_PKISTATUSINFO_PKISTATUS_GET_STRING, CMP_R_ERROR_PARSING_PKISTATUS);
			return 0;
	}
	return 0;
}

/* ############################################################################ * 
 * returns the PKIStatus info of the given error message
 * returns 0 on error
 * ############################################################################ */
char *CMP_ERRORMSGCONTENT_PKIStatus_get_string( CMP_ERRORMSGCONTENT *error) {
	if (!error) return 0;
	return CMP_PKISTATUSINFO_PKIstatus_get_string(error->pKIStatusInfo);
}

/* ############################################################################ * 
 * returns the PKIStatus of the given Certresponse
 * returns -1 on error
 * ############################################################################ */
long CMP_CERTRESPONSE_PKIStatus_get( CMP_CERTRESPONSE *resp) {
	if (!resp) return -1;
	return CMP_PKISTATUSINFO_PKIstatus_get(resp->status);
}

/* ############################################################################ * 
 * ############################################################################ */
STACK_OF(ASN1_UTF8STRING)* CMP_CERTRESPONSE_PKIStatusString_get0( CMP_CERTRESPONSE *resp) {
	if (!resp) return NULL;
	return resp->status->statusString;
}

/* ############################################################################ * 
 * returns the PKIFailureInfo
 * returns 0 on error
 * ############################################################################ */
char *CMP_PKISTATUSINFO_PKIFailureInfo_get_string( CMP_PKISTATUSINFO *statusInfo) {
	int i;

	if (!statusInfo) return 0;
	for (i=0; i <= CMP_PKIFAILUREINFO_MAX; i++) {
		if (ASN1_BIT_STRING_get_bit(statusInfo->failInfo, i)) {
			switch (i) {
				case CMP_PKIFAILUREINFO_badAlg:
					return "PKIFailureInfo: badAlg";
				case CMP_PKIFAILUREINFO_badMessageCheck:
					return "PKIFailureInfo: badMessageCheck";
				case CMP_PKIFAILUREINFO_badRequest:
					return "PKIFailureInfo: badRequest";
				case CMP_PKIFAILUREINFO_badTime:
					return "PKIFailureInfo: badTime";
				case CMP_PKIFAILUREINFO_badCertId:
					return "PKIFailureInfo: badCertId";
				case CMP_PKIFAILUREINFO_badDataFormat:
					return "PKIFailureInfo: badDataFormat";
				case CMP_PKIFAILUREINFO_wrongAuthority:
					return "PKIFailureInfo: wrongAuthority";
				case CMP_PKIFAILUREINFO_incorrectData:
					return "PKIFailureInfo: incorrectData";
				case CMP_PKIFAILUREINFO_missingTimeStamp:
					return "PKIFailureInfo: missingTimeStamp";
				case CMP_PKIFAILUREINFO_badPOP:
					return "PKIFailureInfo: badPOP";
				case CMP_PKIFAILUREINFO_certRevoked:
					return "PKIFailureInfo: certRevoked";
				case CMP_PKIFAILUREINFO_certConfirmed:
					return "PKIFailureInfo: certConfirmed";
				case CMP_PKIFAILUREINFO_wrongIntegrity:
					return "PKIFailureInfo: wrongIntegrity";
				case CMP_PKIFAILUREINFO_badRecipientNonce:
					return "PKIFailureInfo: badRecipientNonce";
				case CMP_PKIFAILUREINFO_timeNotAvailable:
					return "PKIFailureInfo: timeNotAvailable";
				case CMP_PKIFAILUREINFO_unacceptedPolicy:
					return "PKIFailureInfo: unacceptedPolicy";
				case CMP_PKIFAILUREINFO_unacceptedExtension:
					return "PKIFailureInfo: unacceptedExtension";
				case CMP_PKIFAILUREINFO_addInfoNotAvailable:
					return "PKIFailureInfo: addInfoNotAvailable";
				case CMP_PKIFAILUREINFO_badSenderNonce:
					return "PKIFailureInfo: badSenderNonce";
				case CMP_PKIFAILUREINFO_badCertTemplate:
					return "PKIFailureInfo: badCertTemplate";
				case CMP_PKIFAILUREINFO_signerNotTrusted:
					return "PKIFailureInfo: signerNotTrusted";
				case CMP_PKIFAILUREINFO_transactionIdInUse:
					return "PKIFailureInfo: transactionIdInUse";
				case CMP_PKIFAILUREINFO_unsupportedVersion:
					return "PKIFailureInfo: unsupportedVersion";
				case CMP_PKIFAILUREINFO_notAuthorized:
					return "PKIFailureInfo: notAuthorized";
				case CMP_PKIFAILUREINFO_systemUnavail:
					return "PKIFailureInfo: systemUnavail";
				case CMP_PKIFAILUREINFO_systemFailure:
					return "PKIFailureInfo: systemFailure";
				case CMP_PKIFAILUREINFO_duplicateCertReq:
					return "PKIFailureInfo: duplicateCertReq";
			}
		}
	}
	return 0;
}

/* ############################################################################ * 
 * returns the PKIFailureInfo # of the given ErrorMessage
 * returns 1 on success
 * returns 0 on error
 * ############################################################################ */
char *CMP_ERRORMSGCONTENT_PKIFailureInfo_get_string( CMP_ERRORMSGCONTENT *error) {
	if (!error) return 0;
	return CMP_PKISTATUSINFO_PKIFailureInfo_get_string(error->pKIStatusInfo);
}

/* ############################################################################ *
 * returns the PKIStatus of the given certReqId inside a Rev
 * returns -1 on error
 * ############################################################################ */
long CMP_REVREPCONTENT_PKIStatus_get( CMP_REVREPCONTENT *revRep, long reqId) {
	CMP_PKISTATUSINFO *status=NULL;
	if (!revRep) return -1;

	if ( (status = sk_CMP_PKISTATUSINFO_value( revRep->status, reqId)) ) {
		return CMP_PKISTATUSINFO_PKIstatus_get(status);
	}

	/* did not find a CertResponse with the right certRep */
	return -1;
}

/* ############################################################################ *
 * returns the PKIStatus of the given certReqId inside a CertRepMessage
 * returns -1 on error
 * ############################################################################ */
long CMP_CERTREPMESSAGE_PKIStatus_get( CMP_CERTREPMESSAGE *certRep, long certReqId) {
	CMP_CERTRESPONSE *certResponse=NULL;
	if (!certRep) return -1;

	if ( (certResponse = CMP_CERTREPMESSAGE_certResponse_get0( certRep, certReqId)) ) {
		return (CMP_CERTRESPONSE_PKIStatus_get(certResponse));
	}

	/* did not find a CertResponse with the right certRep */
	return -1;
}

/* ############################################################################ * 
 * returns pointer to PKIFailureInfo of given certRep message
 * returns NULL on error or if no matching failInfo was found
 * ############################################################################ */
CMP_PKIFAILUREINFO *CMP_CERTREPMESSAGE_PKIFailureInfo_get0(CMP_CERTREPMESSAGE *certRep, long certReqId) {
	CMP_CERTRESPONSE *certResponse=NULL;
	if (!certRep) return NULL;

	if ( (certResponse = CMP_CERTREPMESSAGE_certResponse_get0( certRep, certReqId)) ) {

		if (certResponse->status)
			return certResponse->status->failInfo;
	}

	/* did not find a CertResponse with the right certRep */
	return NULL;
}

/* ############################################################################ * 
 * returns pointer to PKIFailureInfoString character array of given certRep message
 * returns NULL on error or if no matching failInfo was found
 * ############################################################################ */
char *CMP_CERTREPMESSAGE_PKIFailureInfoString_get0(CMP_CERTREPMESSAGE *certRep, long certReqId) {
	CMP_CERTRESPONSE *certResponse=NULL;
	if (!certRep) return NULL;

	if ( (certResponse = CMP_CERTREPMESSAGE_certResponse_get0( certRep, certReqId)) ) {

		if (certResponse->status)
			return CMP_PKISTATUSINFO_PKIFailureInfo_get_string(certResponse->status);
	}

	/* did not find a CertResponse with the right certRep */
	return NULL;
}

/* ############################################################################ *
 * returns the status string of the given certReqId inside a CertRepMessage
 * returns NULL on error
 * ############################################################################ */
STACK_OF(ASN1_UTF8STRING)* CMP_CERTREPMESSAGE_PKIStatusString_get0( CMP_CERTREPMESSAGE *certRep, long certReqId) {
	CMP_CERTRESPONSE *certResponse=NULL;
	if (!certRep) return NULL;

	if ( (certResponse = CMP_CERTREPMESSAGE_certResponse_get0( certRep, certReqId)) ) {
		return (CMP_CERTRESPONSE_PKIStatusString_get0(certResponse));
	}

	/* did not find a CertResponse with the right certRep */
	return NULL;
}

/* ############################################################################ *
 * returns 1 if a given bit is set in a PKIFailureInfo
 *				0 if			not set
 *			   -1 on error
 * PKIFailureInfo ::= ASN1_BIT_STRING
 * ############################################################################ */
int CMP_PKIFAILUREINFO_check( ASN1_BIT_STRING *failInfo, int codeBit) {
	if (!failInfo) return -1;
	if ( (codeBit < 0) || (codeBit > CMP_PKIFAILUREINFO_MAX)) return -1;

	return ASN1_BIT_STRING_get_bit( failInfo, codeBit);
}


/* ############################################################################ *
 * returns a pointer to the CertResponse with the given certReqId inside a CertRepMessage
 * returns NULL on error or if no CertResponse available
 * ############################################################################ */
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

/* ############################################################################ *
 * returns a pointer to the Certificate with the given certReqId inside a CertRepMessage
 * returns NULL on error or if no Certificate available
 * ############################################################################ */
X509 *CMP_CERTREPMESSAGE_cert_get0( CMP_CERTREPMESSAGE *certRep, long certReqId) {
	X509 *cert=NULL;
	CMP_CERTRESPONSE *certResponse=NULL;

	if( !certRep) return NULL;

	if ( (certResponse = CMP_CERTREPMESSAGE_certResponse_get0( certRep, certReqId)) ) {
		cert = certResponse->certifiedKeyPair->certOrEncCert->value.certificate;
	}

	return cert;
}

/* ############################################################################ *
 * returns a pointer to a copy of the Certificate with the given certReqId inside a CertRepMessage
 * returns NULL on error or if no Certificate available
 * ############################################################################ */
X509 *CMP_CERTREPMESSAGE_cert_get1( CMP_CERTREPMESSAGE *certRep, long certReqId) {
	X509 *cert=NULL;
	X509 *certCopy=NULL;

	if( !certRep) return NULL;

	if( (cert = CMP_CERTREPMESSAGE_cert_get0(certRep, certReqId)))
		certCopy = X509_dup(cert);
	return certCopy;
}

/* ############################################################################# *
 * Decrypts the certificate with the given certReqId inside a CertRepMessage and
 * returns a pointer to the decrypted certificate
 * returns NULL on error or if no Certificate available
 * ############################################################################# */
X509 *CMP_CERTREPMESSAGE_encCert_get1( CMP_CERTREPMESSAGE *certRep, long certReqId, EVP_PKEY *pkey) {
	CRMF_ENCRYPTEDVALUE *encCert   = NULL;
	X509				*cert	   = NULL; /* decrypted certificate					  */
	EVP_CIPHER_CTX		*ctx	   = NULL; /* context for symmetric encryption		  */
	unsigned char		*ek		   = NULL; /* decrypted symmetric encryption key	  */
	const EVP_CIPHER	*cipher    = NULL; /* used cipher							  */
	unsigned char		*iv		   = NULL; /* initial vector for symmetric encryption */
	unsigned char		*outbuf    = NULL; /* decryption output buffer				  */
	const unsigned char *p		   = NULL; /* needed for decoding ASN1				  */
	int					 symmAlg;  /* NIDs for key and symmetric algorithm	  */
	int					 n, outlen = 0;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L 
	EVP_PKEY_CTX		*pkctx	   = NULL;	 /* private key context */
#endif

	CMP_CERTRESPONSE *certResponse = NULL;
	if ( !(certResponse = CMP_CERTREPMESSAGE_certResponse_get0( certRep, certReqId)) )
		goto err;

	encCert = certResponse->certifiedKeyPair->certOrEncCert->value.encryptedCert;

	/* keyAlg  = OBJ_obj2nid(encCert->keyAlg->algorithm); */
	symmAlg = OBJ_obj2nid(encCert->symmAlg->algorithm);

	/* first the symmetric key needs to be decrypted */

#if OPENSSL_VERSION_NUMBER >= 0x10000000L 
	if ((pkctx = EVP_PKEY_CTX_new(pkey, NULL)) && EVP_PKEY_decrypt_init(pkctx)) {
		ASN1_BIT_STRING *encKey = encCert->encSymmKey;

		size_t eksize = 0;
		if (EVP_PKEY_decrypt(pkctx, NULL, &eksize, encKey->data, encKey->length) <= 0
				|| !(ek = OPENSSL_malloc(eksize))
				|| EVP_PKEY_decrypt(pkctx, ek, &eksize, encKey->data, encKey->length) <= 0) {

			CMPerr(CMP_F_CMP_CERTREPMESSAGE_ENCCERT_GET1, CMP_R_ERROR_DECRYPTING_SYMMETRIC_KEY);
			goto err;
		}
		EVP_PKEY_CTX_free(pkctx);
	}
	else {
		CMPerr(CMP_F_CMP_CERTREPMESSAGE_ENCCERT_GET1, CMP_R_ERROR_DECRYPTING_KEY);
		goto err;
	}
#else
	ASN1_BIT_STRING *encKey = encCert->encSymmKey;
	ek = OPENSSL_malloc(encKey->length);
	if (EVP_PKEY_decrypt(ek, encKey->data, encKey->length, pkey) == -1) {
		CMPerr(CMP_F_CMP_CERTREPMESSAGE_ENCCERT_GET1, CMP_R_ERROR_DECRYPTING_KEY);
		goto err;
	}
#endif

	/* select cipher based on algorithm given in message */
	if (!(cipher = EVP_get_cipherbynid(symmAlg))) {
		CMPerr(CMP_F_CMP_CERTREPMESSAGE_ENCCERT_GET1, CMP_R_UNKNOWN_CIPHER);
		goto err;
	}
	if (!(iv = OPENSSL_malloc(cipher->iv_len))) goto err;
	ASN1_TYPE_get_octetstring(encCert->symmAlg->parameter, iv, cipher->iv_len);

	/* d2i_X509 changes the given pointer, so use p for decoding the message and keep the 
	 * original pointer in outbuf so that the memory can be freed later */
	if (!(p = outbuf = OPENSSL_malloc(encCert->encValue->length + cipher->block_size - 1))) goto err;
	ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	if (!EVP_DecryptInit(ctx, cipher, ek, iv)
		|| !EVP_DecryptUpdate(ctx, outbuf, &outlen, encCert->encValue->data, encCert->encValue->length)
		|| !EVP_DecryptFinal(ctx, outbuf+outlen, &n)) {
		CMPerr(CMP_F_CMP_CERTREPMESSAGE_ENCCERT_GET1, CMP_R_ERROR_DECRYPTING_CERTIFICATE);
		goto err;
	}
	outlen += n;

	if (!(cert = d2i_X509(NULL, &p, outlen))) {
		CMPerr(CMP_F_CMP_CERTREPMESSAGE_ENCCERT_GET1, CMP_R_ERROR_DECODING_CERTIFICATE);
		goto err;
	}

	OPENSSL_free(outbuf);
	EVP_CIPHER_CTX_free(ctx);
	OPENSSL_free(ek);
	OPENSSL_free(iv);
	return cert;

err:
	CMPerr(CMP_F_CMP_CERTREPMESSAGE_ENCCERT_GET1, CMP_R_ERROR_DECRYPTING_ENCCERT);
	if (outbuf) OPENSSL_free(outbuf);
	if (ctx) EVP_CIPHER_CTX_free(ctx);
	if (ek) OPENSSL_free(ek);
	if (iv) OPENSSL_free(iv);
	return NULL;
}

/* ############################################################################ *
 * returns the type of the certificate contained in the certificate response
 * returns -1 on errror
 * ############################################################################ */
int CMP_CERTREPMESSAGE_certType_get( CMP_CERTREPMESSAGE *certRep, long certReqId) {
	CMP_CERTRESPONSE *certResponse=NULL;

	if( !certRep) return -1;
	if( !(certResponse = CMP_CERTREPMESSAGE_certResponse_get0( certRep, certReqId)) )
		return -1;

	return certResponse->certifiedKeyPair->certOrEncCert->type;
}

/* ############################################################################ *
 * returns 1 on success
 * returns 0 on error
 * ############################################################################ */
int CMP_PKIMESSAGE_set_bodytype( CMP_PKIMESSAGE *msg, int type) {
	if( !msg) return 0;

	msg->body->type = type;

	return 1;
}

/* ############################################################################ *
 * returns the body type of the given CMP message
 * returns -1 on error
 * ############################################################################ */
int CMP_PKIMESSAGE_get_bodytype( CMP_PKIMESSAGE *msg) {
	if( !msg) return -1;

	return msg->body->type;
}

/* ############################################################################ *
 * return error message string or NULL on error
 * ############################################################################ */
char *CMP_PKIMESSAGE_parse_error_msg( CMP_PKIMESSAGE *msg, char *errormsg, int bufsize) {
	char *status, *failureinfo;

	if( !msg) return 0;
	if( CMP_PKIMESSAGE_get_bodytype(msg) != V_CMP_PKIBODY_ERROR) return 0;

	status = CMP_ERRORMSGCONTENT_PKIStatus_get_string(msg->body->value.error);
	if (!status) {
		BIO_snprintf(errormsg, bufsize, "failed to parse error message");
		return errormsg;
	}

	/* PKIFailureInfo is optional */
	failureinfo = CMP_ERRORMSGCONTENT_PKIFailureInfo_get_string(msg->body->value.error);

	if (failureinfo)
		BIO_snprintf(errormsg, bufsize, "Status: %s, Failureinfo: %s", status, failureinfo);
	else
		BIO_snprintf(errormsg, bufsize, "Status: %s", status);

	return errormsg;
}

/* ############################################################################ *
 * Retrieve the returned certificate from the given certrepmessage.
 * returns NULL if not found
 * TODO: what if there are more than one?
 * ############################################################################ */
X509 *CMP_CERTREPMESSAGE_get_certificate(CMP_CTX *ctx, CMP_CERTREPMESSAGE *certrep) {
	X509 *newClCert = NULL;
	int repNum = 0;

	/* Get the certReqId of the first certresponse. Need to do it this way instead
	 * of just using certReqId==0, because in error cases Insta replies with a certReqId
	 * of -1... */
	if (sk_CMP_CERTRESPONSE_num(certrep->response) > 0)
		repNum = ASN1_INTEGER_get(sk_CMP_CERTRESPONSE_value(certrep->response, 0)->certReqId);
	
	CMP_CTX_set_failInfoCode(ctx, CMP_CERTREPMESSAGE_PKIFailureInfo_get0(certrep, repNum));

	ctx->lastStatus = CMP_CERTREPMESSAGE_PKIStatus_get( certrep, repNum);
	switch (ctx->lastStatus) {

		case CMP_PKISTATUS_waiting:
			goto err;
			break;

		case CMP_PKISTATUS_grantedWithMods:
			CMP_printf( ctx, "WARNING: got \"grantedWithMods\"");

		case CMP_PKISTATUS_accepted:
			/* if we received a certificate then place it to ctx->newClCert and return,
			 * if the cert is encrypted then we first decrypt it. */
			switch (CMP_CERTREPMESSAGE_certType_get(certrep, repNum)) {
				case CMP_CERTORENCCERT_CERTIFICATE:
					if( !(newClCert = CMP_CERTREPMESSAGE_cert_get1(certrep,repNum))) {
						CMPerr(CMP_F_CERTREP_GET_CERTIFICATE, CMP_R_CERTIFICATE_NOT_FOUND);
						goto err;
					}
					break;
				case CMP_CERTORENCCERT_ENCRYPTEDCERT:
					if( !(newClCert = CMP_CERTREPMESSAGE_encCert_get1(certrep,repNum,ctx->newPkey))) {
						CMPerr(CMP_F_CERTREP_GET_CERTIFICATE, CMP_R_CERTIFICATE_NOT_FOUND);
						goto err;
					}					
					break;
				default:
					CMPerr(CMP_F_CERTREP_GET_CERTIFICATE, CMP_R_UNKNOWN_CERTTYPE);
					goto err;
			}
			break;

		case CMP_PKISTATUS_rejection: {
			char *statusString = NULL;
			int statusLen = 0;
			ASN1_UTF8STRING *status = NULL;
			STACK_OF(ASN1_UTF8STRING) *strstack = CMP_CERTREPMESSAGE_PKIStatusString_get0(certrep, repNum);

			CMPerr(CMP_F_CERTREP_GET_CERTIFICATE, CMP_R_REQUEST_REJECTED_BY_CA);

			statusString = CMP_CERTREPMESSAGE_PKIFailureInfoString_get0(certrep, repNum);
			if (!statusString) goto err;
			statusString = OPENSSL_strdup(statusString);
			if (!statusString) goto err;
			statusLen = strlen(statusString);

			statusString = OPENSSL_realloc(statusString, statusLen+20);
			strcat(statusString, ", statusString: \"");
			statusLen = strlen(statusString);

			while ((status = sk_ASN1_UTF8STRING_pop(strstack))) {
				statusLen += strlen((char*)status->data)+2;
				statusString = OPENSSL_realloc(statusString, statusLen);
				if (!statusString) goto err;
				strcat(statusString, (char*)status->data);
			}

			strcat(statusString, "\"");
			ERR_add_error_data(1, statusString);

			goto err;
			break;
		}

		case CMP_PKISTATUS_revocationWarning:
		case CMP_PKISTATUS_revocationNotification:
		case CMP_PKISTATUS_keyUpdateWarning:
			CMPerr(CMP_F_CERTREP_GET_CERTIFICATE, CMP_R_NO_CERTIFICATE_RECEIVED);
			goto err;
			break;

		default: {
			STACK_OF(ASN1_UTF8STRING) *strstack = CMP_CERTREPMESSAGE_PKIStatusString_get0(certrep, 0);
			ASN1_UTF8STRING *status = NULL;

			CMPerr(CMP_F_CERTREP_GET_CERTIFICATE, CMP_R_UNKNOWN_PKISTATUS);
			while ((status = sk_ASN1_UTF8STRING_pop(strstack)))
				ERR_add_error_data(3, "statusString=\"", status->data, "\"");

			CMP_printf( ctx, "ERROR: unknown pkistatus %ld", CMP_CERTREPMESSAGE_PKIStatus_get( certrep, repNum));
			goto err;
			break;
		}
	}

	return newClCert;
err:
	return NULL;
}

/* ################################################################ *
 * Builds up the certificate chain of cert as high up as possible using
 * the given X509_STORE.
 * 
 * NOTE: This creates duplicates of the stack AND of each certificate,
 * so when the stack is no longer needed it should be freed with
 * sk_X509_pop_free()
 * ################################################################ */
STACK_OF(X509) *CMP_build_cert_chain(X509_STORE *store, X509 *cert) {
	STACK_OF(X509) *chain = NULL, *chainDup = NULL;
	X509_STORE_CTX *csc = NULL;
	int i=0;

	if (!store || !cert) goto err;

	csc = X509_STORE_CTX_new();
	if (!csc) goto err;

	chainDup = sk_X509_new_null();
	if (!chainDup) goto err;

	X509_STORE_set_flags(store, 0);
	if(!X509_STORE_CTX_init(csc,store,cert,NULL))
		goto err;

	X509_verify_cert(csc);

	chain = X509_STORE_CTX_get_chain(csc);
	for (i = 0; i < sk_X509_num(chain); i++) {
		X509 *certDup = X509_dup( sk_X509_value(chain, i) );
		sk_X509_push(chainDup, certDup);
	}
	X509_STORE_CTX_free(csc);

	return chainDup;

err:
	if (csc) X509_STORE_CTX_free(csc);
	if (chainDup) sk_X509_free(chainDup);
	return NULL;
}

