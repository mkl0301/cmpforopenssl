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
 * the CMP structures                                                           *
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
 * ############################################################################ */
int CMP_PKIHEADER_set_version(CMP_PKIHEADER *hdr, int version) {
	if( !hdr) return 0;

	ASN1_INTEGER_set(hdr->pvno, version);

	return 1;
}

/* ############################################################################ *
 * Set the recipient name of PKIHeader. The pointer nm is used directly!
 * ############################################################################ */
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

/* ############################################################################ *
 * Set the recipient name of PKIHeader. The contents of nm is copied.
 * ############################################################################ */
int CMP_PKIHEADER_set1_recipient(CMP_PKIHEADER *hdr, const X509_NAME *nm)
{
	X509_NAME *nmDup=NULL;

	if( !hdr) return 0;

	if(nm && !(nmDup = X509_NAME_dup( (X509_NAME*) nm)))
		return 0;

	return CMP_PKIHEADER_set0_recipient( hdr, nmDup);
}

/* ############################################################################ *
 * Set the sender name in PKIHeader.
 * ############################################################################ */
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

/* ############################################################################ *
 * Set the sender name in PKIHeader. The contents of nm is duplicated.
 * ############################################################################ */
int CMP_PKIHEADER_set1_sender(CMP_PKIHEADER *hdr, const X509_NAME *nm)
{
	X509_NAME *nmDup=NULL;

	if( !hdr) return 0;

	if(nm)
		nmDup = X509_NAME_dup( (X509_NAME*) nm);

	return CMP_PKIHEADER_set0_sender( hdr, nmDup);
}


/* ############################################################################ *
 * Create an X509_ALGOR structure for PasswordBasedMAC protection
 * ############################################################################ */
X509_ALGOR *CMP_get_protectionAlg_pbmac(void) {
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
/* push an ASN1_UTF8STRING to hdr->freeText and consume the given pointer       */
/* ############################################################################ */
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

/* ############################################################################ */
/* push an ASN1_UTF8STRING to hdr->freeText and don't consume the given pointer */
/* ############################################################################ */
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

#if 0
/* ############################################################################ */
/* set an ASN1_UTF8STRING stack to hdr->freeText and consume the given pointer */
/* ############################################################################ */
int CMP_PKIHEADER_set0_freeText( CMP_PKIHEADER *hdr, STACK_OF(ASN1_UTF8STRING) *text) {
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
int CMP_PKIHEADER_set1_freeText( CMP_PKIHEADER *hdr, STACK_OF(ASN1_UTF8STRING) *text) {
	STACK_OF(ASN1_UTF8STRING) *textDup;

	if (!hdr) goto err;
	if (!text) goto err;

	if (!textDup = sk_ASN1_UTF8STRING_dup(text)) goto err;
	return CMP_PKIHEADER_set0_freeText( hdr, textDup);
err:
	return 0;
}
#endif


/* ############################################################################ *
 * Initialize the given PkiHeader structure with values set in the CMP_CTX structure.
 * if referenceValue is given in ctx, it will be set as senderKID
 * ############################################################################ */
int CMP_PKIHEADER_set1(CMP_PKIHEADER *hdr, CMP_CTX *ctx) {
	/* check existence of mandatory arguments */
	if( !hdr) goto err;
	if( !ctx) goto err;

	/* set the CMP version */
	CMP_PKIHEADER_set_version( hdr, CMP_VERSION);

	/* in case there is no OLD client cert and no subject name is set in ctx,
	 * the subject name is not set */
  /* TODO: can we set our subject name differently than through clCert? */
	if( ctx->clCert) {
		if( !CMP_PKIHEADER_set1_sender( hdr, X509_get_subject_name( (X509*) ctx->clCert))) goto err;
	} else {
		if( !CMP_PKIHEADER_set1_sender( hdr, NULL)) goto err;
	}

	if( ctx->srvCert) {
		if( !CMP_PKIHEADER_set1_recipient( hdr, X509_get_subject_name( (X509*) ctx->srvCert))) goto err;
	} else if( ctx->recipient) {
		if( !CMP_PKIHEADER_set1_recipient( hdr, ctx->recipient)) goto err;
	}else {
		if( !CMP_PKIHEADER_set1_recipient( hdr, NULL)) goto err;
	}

	if( !CMP_PKIHEADER_set_messageTime(hdr)) goto err;

  /* the protectionAlg is set when creating the message protection in
   * CMP_PKIMESSAGE_protect() */

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

	int pptype=0;
	void *ppval=NULL;

	int usedAlgorNid;

	EVP_MD_CTX   *ctx=NULL;
	const EVP_MD *md=NULL;

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

	if (usedAlgorNid == NID_id_PasswordBasedMAC) {
		/* there is no pmb set in this message */
		if (!ppval) goto err;
		if (!secret) {
			CMPerr(CMP_F_CMP_PROTECTION_NEW, CMP_R_NO_SECRET_VALUE_GIVEN_FOR_PBMAC);
			goto err;
		}

		pbmStr = (ASN1_STRING *)ppval;
		pbmStrUchar = (unsigned char *)pbmStr->data;
		pbm = d2i_CRMF_PBMPARAMETER( NULL, &pbmStrUchar, pbmStr->length);

		if(!(CRMF_passwordBasedMac_new(pbm, protPartDer, protPartDerLen, secret->data, secret->length, &mac, &macLen))) goto err;
	}
	else if ((md = EVP_get_digestbynid(usedAlgorNid)) != NULL) {
		// printf("INFO: protecting with pkey, algorithm %s\n", OBJ_nid2sn(usedAlgorNid));
		if (!pkey) { /* EVP_SignFinal() will check that pkey type is correct for the algorithm */
			CMPerr(CMP_F_CMP_PROTECTION_NEW, CMP_R_INVALID_KEY);
			ERR_add_error_data(1, "pkey was NULL although it is supposed to be used for generating protection");
			goto err;
		}

		maxMacLen = EVP_PKEY_size( (EVP_PKEY*) pkey);
		mac = OPENSSL_malloc(maxMacLen);

		ctx = EVP_MD_CTX_create();
		if (!(EVP_SignInit_ex(ctx, md, NULL))) goto err;
		if (!(EVP_SignUpdate(ctx, protPartDer, protPartDerLen))) goto err;
		if (!(EVP_SignFinal(ctx, mac, &macLen, (EVP_PKEY*) pkey))) goto err;
	}
	else {
		CMPerr(CMP_F_CMP_PROTECTION_NEW, CMP_R_UNKNOWN_ALGORITHM_ID);
		goto err;
	}

	if(!(prot = ASN1_BIT_STRING_new())) goto err;
	ASN1_BIT_STRING_set(prot, mac, macLen);

	/* Actually this should not be needed but OpenSSL defaults all bitstrings to be a NamedBitList */
	prot->flags &= ~0x07;
	prot->flags |= ASN1_STRING_FLAG_BITS_LEFT;

	/* cleanup */
	if (ctx) EVP_MD_CTX_destroy(ctx);
	if (mac) OPENSSL_free(mac);
	return prot;

err:
	if (ctx) EVP_MD_CTX_destroy(ctx);
	if (mac) OPENSSL_free(mac);

	CMPerr(CMP_F_CMP_PROTECTION_NEW, CMP_R_ERROR_CALCULATING_PROTECTION);
	if(prot) ASN1_BIT_STRING_free(prot);
	return NULL;
}

/* ############################################################################ *
 * determines which kind of protection should be created based on the ctx
 * sets this into the protectionAlg field in the message header
 * calculates the protection and sets it in the protections filed
 * ############################################################################ */
int CMP_PKIMESSAGE_protect(CMP_CTX *ctx, CMP_PKIMESSAGE *msg) {
  if(!ctx) goto err;
  if(!msg) goto err;

  /* use PasswordBasedMac according to 5.1.3.1 if secretValue is given */
	if (ctx->secretValue) {
		if (!(msg->header->protectionAlg = CMP_get_protectionAlg_pbmac())) goto err;
	} else
  /* use MSG_SIG_ALG according to 5.1.3.3 if client Certificate is given */
  if (ctx->clCert){
    if(!ctx->clCert->sig_alg) goto err;
    if(!(msg->header->protectionAlg = X509_ALGOR_dup(ctx->clCert->sig_alg))) goto err;
	} else {
    CMPerr(CMP_F_CMP_PKIMESSAGE_PROTECT, CMP_R_MISSING_KEY_INPUT_FOR_CREATING_PROTECTION);
    goto err;
  }

	if( !(msg->protection = CMP_protection_new( msg, NULL, (EVP_PKEY *) ctx->pkey, ctx->secretValue))) 
		goto err;
  
  return 1;
err:
  CMPerr(CMP_F_CMP_PKIMESSAGE_PROTECT, CMP_R_ERROR_PROTECTING_MESSAGE);
  return 0;
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
	int sigAlgID;
	const EVP_MD *md = NULL;

	if (!certStatus) goto err;
	if (!cert) goto err;

	sigAlgID = OBJ_obj2nid(cert->sig_alg->algorithm);
	// printf("INFO: certificate signature algorithm used: \"%s\"\n", OBJ_nid2sn(sigAlgID));

	/* select algorithm based on the one used in the cert signature */
	if ((md = EVP_get_digestbynid(sigAlgID))) {
		if (!X509_digest(cert, md, hash, &hashLen)) goto err;
		certHash=ASN1_OCTET_STRING_new();
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


/* ############################################################################ */
/* sets implicitConfirm in the generalInfo field of the header
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CMP_PKIMESSAGE_set_implicitConfirm(CMP_PKIMESSAGE *msg) {
	CMP_INFOTYPEANDVALUE *itav=NULL;

	if (!msg) goto err;

	itav = CMP_INFOTYPEANDVALUE_new();
	itav->infoType = OBJ_nid2obj(NID_id_it_implicitConfirm);
	itav->infoValue.implicitConfirm = ASN1_NULL_new();
	// if (! CMP_INFOTYPEANDVALUE_set0( itav, OBJ_nid2obj(NID_id_it_implicitConfirm), V_ASN1_NULL, NULL)) goto err;
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


/* ############################################################################ */
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
		sk_CMP_INFOTYPEANDVALUE_pop_free(*itav_sk_p, CMP_INFOTYPEANDVALUE_free);
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
/* returns the PKIStatus of the given PKIStatusInfo */
/* or NULL on error */
/* ############################################################################ */
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

/* ############################################################################ */
/* returns the PKIStatus info of the given error message */
/* returns 0 on error */
/* ############################################################################ */
char *CMP_ERRORMSGCONTENT_PKIStatus_get_string( CMP_ERRORMSGCONTENT *error) {
	if (!error) return 0;
	return CMP_PKISTATUSINFO_PKIstatus_get_string(error->pKIStatusInfo);
}

/* ############################################################################ */
/* returns the PKIStatus of the given Certresponse */
/* returns -1 on error */
/* ############################################################################ */
long CMP_CERTRESPONSE_PKIStatus_get( CMP_CERTRESPONSE *resp) {
	if (!resp) return -1;
	return CMP_PKISTATUSINFO_PKIstatus_get(resp->status);
}

STACK_OF(ASN1_UTF8STRING)* CMP_CERTRESPONSE_PKIStatusString_get0( CMP_CERTRESPONSE *resp) {
	if (!resp) return NULL;
	return resp->status->statusString;
}

/* ############################################################################ */
/* returns the PKIFailureInfo */
/* returns 0 on error */
/* ############################################################################ */
char *CMP_PKISTATUSINFO_PKIFailureInfo_get_string( CMP_PKISTATUSINFO *statusInfo) {
	int i;

	if (!statusInfo) return 0;
	for ( i=0; i <= CMP_PKIFAILUREINFO_MAX; i++) {
		if( ASN1_BIT_STRING_get_bit(statusInfo->failInfo, i)) {
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

/* ############################################################################ */
/* returns the PKIFailureInfo # of the given ErrorMessage */
/* returns 1 on success */
/* returns 0 on error */
/* ############################################################################ */
char *CMP_ERRORMSGCONTENT_PKIFailureInfo_get_string( CMP_ERRORMSGCONTENT *error) {
	if (!error) return 0;
	return CMP_PKISTATUSINFO_PKIFailureInfo_get_string(error->pKIStatusInfo);
}

/* ############################################################################ */
/* returns the PKIStatus of the given certReqId inside a Rev */
/* returns -1 on error */
/* ############################################################################ */
long CMP_REVREPCONTENT_PKIStatus_get( CMP_REVREPCONTENT *revRep, long reqId) {
	CMP_PKISTATUSINFO *status=NULL;
	if (!revRep) return -1;

	if ( (status = sk_CMP_PKISTATUSINFO_value( revRep->status, reqId)) ) {
		return CMP_PKISTATUSINFO_PKIstatus_get(status);
	}

	/* did not find a CertResponse with the right certRep */
	return -1;
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

/* ############################################################################ */
/* returns the status string of the given certReqId inside a CertRepMessage */
/* returns NULL on error */
/* ############################################################################ */
STACK_OF(ASN1_UTF8STRING)* CMP_CERTREPMESSAGE_PKIStatusString_get0( CMP_CERTREPMESSAGE *certRep, long certReqId) {
	CMP_CERTRESPONSE *certResponse=NULL;
	if (!certRep) return NULL;

	if ( (certResponse = CMP_CERTREPMESSAGE_certResponse_get0( certRep, certReqId)) ) {
		return (CMP_CERTRESPONSE_PKIStatusString_get0(certResponse));
	}

	/* did not find a CertResponse with the right certRep */
	return NULL;
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

/* ############################################################################# */
/* Decrypts the certificate with the given certReqId inside a CertRepMessage and */
/* returns a pointer to the decrypted certificate                                */
/* returns NULL on error or if no Certificate available                          */
/* ############################################################################# */
X509 *CMP_CERTREPMESSAGE_encCert_get1( CMP_CERTREPMESSAGE *certRep, long certReqId, EVP_PKEY *pkey) {
	CRMF_ENCRYPTEDVALUE *encCert   = NULL;
	X509                *cert      = NULL; /* decrypted certificate                   */
	EVP_CIPHER_CTX      *ctx       = NULL; /* context for symmetric encryption        */
	unsigned char       *ek        = NULL; /* decrypted symmetric encryption key      */
	const EVP_CIPHER    *cipher    = NULL; /* used cipher                             */
	unsigned char       *iv        = NULL; /* initial vector for symmetric encryption */
	unsigned char       *outbuf    = NULL; /* decryption output buffer                */
	const unsigned char *p         = NULL; /* needed for decoding ASN1                */
	int                  symmAlg;  /* NIDs for key and symmetric algorithm    */
	int                  n, outlen = 0;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L 
	EVP_PKEY_CTX        *pkctx     = NULL;   /* private key context */
#endif

	// printf("INFO: Received encrypted certificate, attempting to decrypt... \n");

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

/* ############################################################################ */
/* returns the type of the certificate contained in the certificate response    */
/* returns -1 on errror                                                         */
/* ############################################################################ */
int CMP_CERTREPMESSAGE_certType_get( CMP_CERTREPMESSAGE *certRep, long certReqId) {
	CMP_CERTRESPONSE *certResponse=NULL;

	if( !certRep) return -1;
	if( !(certResponse = CMP_CERTREPMESSAGE_certResponse_get0( certRep, certReqId)) )
		return -1;

	return certResponse->certifiedKeyPair->certOrEncCert->type;
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
/* return error message string or NULL on error */
/* ############################################################################ */
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
 * ############################################################################ */
X509 *CMP_CERTREPMESSAGE_get_certificate(CMP_CTX *ctx, CMP_CERTREPMESSAGE *certrep) {
	X509 *newClCert = NULL;
	
	CMP_CTX_set_failInfoCode(ctx, CMP_CERTREPMESSAGE_PKIFailureInfo_get0(certrep, 0));

	ctx->lastStatus = CMP_CERTREPMESSAGE_PKIStatus_get( certrep, 0);
	switch (ctx->lastStatus) {

		case CMP_PKISTATUS_waiting:
			goto err;
			break;

		case CMP_PKISTATUS_grantedWithMods:
			CMP_printf( ctx, "WARNING: got \"grantedWithMods\"");

		case CMP_PKISTATUS_accepted:
			/* if we received a certificate then place it to ctx->newClCert and return,
			 * if the cert is encrypted then we first decrypt it. */
			switch (CMP_CERTREPMESSAGE_certType_get(certrep, 0)) {
				case CMP_CERTORENCCERT_CERTIFICATE:
					if( !(newClCert = CMP_CERTREPMESSAGE_cert_get1(certrep,0))) {
						CMPerr(CMP_F_CERTREP_GET_CERTIFICATE, CMP_R_CERTIFICATE_NOT_FOUND);
						goto err;
					}					
					break;
				case CMP_CERTORENCCERT_ENCRYPTEDCERT:
					if( !(newClCert = CMP_CERTREPMESSAGE_encCert_get1(certrep,0,ctx->newPkey))) {
						CMPerr(CMP_F_CERTREP_GET_CERTIFICATE, CMP_R_CERTIFICATE_NOT_FOUND);
						goto err;
					}					
					break;
			}
			break;

		case CMP_PKISTATUS_rejection: {
			char *statusString = NULL;
			int statusLen = 0;
			ASN1_UTF8STRING *status = NULL;
			STACK_OF(ASN1_UTF8STRING) *strstack = CMP_CERTREPMESSAGE_PKIStatusString_get0(certrep, 0);

			CMPerr(CMP_F_CERTREP_GET_CERTIFICATE, CMP_R_REQUEST_REJECTED_BY_CA);

			statusString = CMP_CERTREPMESSAGE_PKIFailureInfoString_get0(certrep, 0);
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

			CMP_printf( ctx, "ERROR: unknown pkistatus %ld", CMP_CERTREPMESSAGE_PKIStatus_get( certrep, 0));
			goto err;
			break;
		}
	}


	return newClCert;
err:
	return NULL;
}


