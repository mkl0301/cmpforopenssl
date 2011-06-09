/* crypto/crmf/crmf_lib.c
 * CRMF (RFC 4211) library functions for OpenSSL
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
 * the CRMF structures                                                          *
 * ############################################################################ */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* ############################################################################ */
/* ############################################################################ */
int CRMF_CERTREQMSG_push0_control( CRMF_CERTREQMSG *certReqMsg, CRMF_ATTRIBUTETYPEANDVALUE *control) {
	int newControls = 0;

	if( !certReqMsg) return 0;
	if( !control) return 0;

	if( !(certReqMsg->certReq->controls)) {
		/* OPTIONAL, not initialized yet */
		if( !(certReqMsg->certReq->controls = sk_CRMF_ATTRIBUTETYPEANDVALUE_new_null())) 
			return 0;
		newControls = 1;
	}
	if( !sk_CRMF_ATTRIBUTETYPEANDVALUE_push( certReqMsg->certReq->controls, control)) goto err;
	return 1;
err:
	CRMFerr(CRMF_F_CRMF_CERTREQMSG_PUSH0_CONTROL, CRMF_R_CRMFERROR);

	if( newControls) {
		sk_CRMF_ATTRIBUTETYPEANDVALUE_pop_free(certReqMsg->certReq->controls, CRMF_ATTRIBUTETYPEANDVALUE_free);
		certReqMsg->certReq->controls = NULL;
	}
	return 0;
}

/* ############################################################################ */
/* ############################################################################ */
int CRMF_CERTREQMSG_push0_regInfo( CRMF_CERTREQMSG *certReqMsg, CRMF_ATTRIBUTETYPEANDVALUE *regInfo) {
	int newRegInfo = 0;

	if( !certReqMsg) return 0;
	if( !regInfo) return 0;

	if( !(certReqMsg->regInfo)) {
		/* OPTIONAL, not initialized yet */
		if( !(certReqMsg->regInfo = sk_CRMF_ATTRIBUTETYPEANDVALUE_new_null())) 
			return 0;
		newRegInfo = 1;
	}
	if( !sk_CRMF_ATTRIBUTETYPEANDVALUE_push( certReqMsg->regInfo, regInfo)) goto err;
	return 1;
err:
	CRMFerr(CRMF_F_CRMF_CERTREQMSG_PUSH0_REGINFO, CRMF_R_CRMFERROR);

	if( newRegInfo) {
		sk_CRMF_ATTRIBUTETYPEANDVALUE_pop_free(certReqMsg->regInfo, CRMF_ATTRIBUTETYPEANDVALUE_free);
		certReqMsg->regInfo = NULL;
	}
	return 0;
}

/* ############################################################################ */
/* ############################################################################ */
int CRMF_CERTREQMSG_push1_control( CRMF_CERTREQMSG *certReqMsg, CRMF_ATTRIBUTETYPEANDVALUE *control) {
	CRMF_ATTRIBUTETYPEANDVALUE * controlDup=NULL;

	if( !certReqMsg) return 0;
	if( !control) return 0;

	controlDup = CRMF_ATTRIBUTETYPEANDVALUE_dup( control);

	if( !CRMF_CERTREQMSG_push0_control( certReqMsg, controlDup)) goto err;
	controlDup = NULL;

	return 1;
err:
	if( controlDup) CRMF_ATTRIBUTETYPEANDVALUE_free( controlDup);
	return 0;
}

/* ############################################################################ */
/* ############################################################################ */
int CRMF_CERTREQMSG_set1_control_oldCertId( CRMF_CERTREQMSG *certReqMsg, X509 *oldCert) { 
	CRMF_ATTRIBUTETYPEANDVALUE *atav   = NULL;
	CRMF_CERTID                *certId = NULL;
	GENERAL_NAME               *gName  = NULL;

	if ( !certReqMsg) goto err;
	if ( !oldCert) goto err;

	if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())
			|| !(certId = CRMF_CERTID_new())
			|| !(gName = GENERAL_NAME_new()))
		goto err;

	/* note: X509_NAME_set does not consume the pointer so this is ok */
	X509_NAME_set( &gName->d.directoryName, X509_get_issuer_name( oldCert));
	gName->type = GEN_DIRNAME;
	certId->issuer = gName;
	certId->serialNumber = ASN1_INTEGER_dup(X509_get_serialNumber(oldCert));

	atav->type = OBJ_nid2obj(NID_id_regCtrl_oldCertID);
	atav->value.oldCertId = certId;

	if (!CRMF_CERTREQMSG_push0_control( certReqMsg, atav)) goto err;

	return 1;
err:
	if (gName) GENERAL_NAME_free(gName);
	if (certId) CRMF_CERTID_free(certId);
	if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free( atav);
	return 0;
}


/* ############################################################################ */
/* ############################################################################ */
int CRMF_CERTREQMSG_set1_control_regToken( CRMF_CERTREQMSG *msg, ASN1_UTF8STRING *tok) {
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;
	ASN1_UTF8STRING *tokDup=NULL;

	if (!msg) return 0;
	if (!tok) return 0;

	if (!(tokDup = ASN1_STRING_dup( tok))) goto err;
	
	if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())) goto err;

	atav->type = OBJ_nid2obj(NID_id_regCtrl_regToken);
	atav->value.regToken = tokDup;
	tokDup = NULL;

	if( !CRMF_CERTREQMSG_push0_control( msg, atav)) goto err;
	atav = NULL;
	
	return 1;
err:
	if (tokDup) ASN1_UTF8STRING_free( tokDup);
	if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free( atav);
	return 0;
}

/* ############################################################################ */
/* ############################################################################ */
int CRMF_CERTREQMSG_set1_control_authenticator( CRMF_CERTREQMSG *msg, ASN1_UTF8STRING *auth) {
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;
	ASN1_UTF8STRING *authDup=NULL;

	if (!msg) return 0;
	if (!auth) return 0;

	if (!(authDup = ASN1_STRING_dup( auth))) goto err;
	
	if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())) goto err;

	atav->type = OBJ_nid2obj(NID_id_regCtrl_authenticator);
	atav->value.regToken = authDup;
	authDup = NULL;
	if( !CRMF_CERTREQMSG_push0_control( msg, atav)) goto err;
	atav = NULL;
	
	return 1;
err:
	if (authDup) ASN1_UTF8STRING_free( authDup);
	if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free( atav);
	return 0;
}

/* ############################################################################ */
/* ############################################################################ */
int CRMF_CERTREQMSG_set1_control_pkiPublicationInfo( CRMF_CERTREQMSG *msg, CRMF_PKIPUBLICATIONINFO *pubinfo) {
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;
	CRMF_PKIPUBLICATIONINFO *pubinfoDup=NULL;

	if (!msg) return 0;
	if (!pubinfo) return 0;

	if (!(pubinfoDup = CRMF_PKIPUBLICATIONINFO_dup( pubinfo))) goto err;
	
	if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())) goto err;

	atav->type = OBJ_nid2obj(NID_id_regCtrl_pkiPublicationInfo);
	atav->value.pkiPublicationInfo = pubinfoDup;
	pubinfoDup = NULL;
	if( !CRMF_CERTREQMSG_push0_control( msg, atav)) goto err;
	atav = NULL;
	
	return 1;
err:
	if (pubinfoDup) CRMF_PKIPUBLICATIONINFO_free( pubinfoDup);
	if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free( atav);
	return 0;
}

/* ############################################################################ */
/* ############################################################################ */
int CRMF_CERTREQMSG_set1_control_pkiArchiveOptions( CRMF_CERTREQMSG *msg, CRMF_PKIARCHIVEOPTIONS *archopts) {
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;
	CRMF_PKIARCHIVEOPTIONS *archoptsDup=NULL;

	if (!msg) return 0;
	if (!archopts) return 0;

	if (!(archoptsDup = CRMF_PKIARCHIVEOPTIONS_dup( archopts))) goto err;
	
	if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())) goto err;

	atav->type = OBJ_nid2obj(NID_id_regCtrl_pkiArchiveOptions);
	atav->value.pkiArchiveOptions = archoptsDup;
	archoptsDup = NULL;
	if( !CRMF_CERTREQMSG_push0_control( msg, atav)) goto err;
	atav = NULL;
	
	return 1;
err:
	if (archoptsDup) CRMF_PKIARCHIVEOPTIONS_free( archoptsDup);
	if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free( atav);
	return 0;
}

/* ############################################################################ */
/* ############################################################################ */
static IMPLEMENT_ASN1_DUP_FUNCTION(X509_PUBKEY);
int CRMF_CERTREQMSG_set1_control_protocolEncrKey( CRMF_CERTREQMSG *msg, X509_PUBKEY *pubkey) {	
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;
	X509_PUBKEY *pubkeyDup=NULL;

	if (!msg) return 0;
	if (!pubkey) return 0;

	if (!(pubkeyDup = X509_PUBKEY_dup(pubkey))) goto err;

	if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())) goto err;

	atav->type = OBJ_nid2obj(NID_id_regCtrl_protocolEncrKey);
	atav->value.protocolEncrKey = pubkeyDup;
	if( !CRMF_CERTREQMSG_push0_control( msg, atav)) goto err;
	atav = NULL;
	
	return 1;
err:
	if (pubkeyDup) X509_PUBKEY_free(pubkeyDup);
	if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free( atav);
	return 0;
}

	
/* ############################################################################ */

/* REGINFO */
/* ############################################################################ */
/* ############################################################################ */
int CRMF_CERTREQMSG_set1_regInfo_utf8Pairs( CRMF_CERTREQMSG *msg, ASN1_UTF8STRING *utf8pairs) {
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;
	ASN1_UTF8STRING *utf8pairsDup=NULL;

	if (!msg) return 0;
	if (!utf8pairs) return 0;

	if (!(utf8pairsDup = ASN1_STRING_dup( utf8pairs))) goto err;
	
	if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())) goto err;

	atav->type = OBJ_nid2obj(NID_id_regInfo_utf8Pairs);
	atav->value.utf8pairs = utf8pairsDup;
	utf8pairsDup = NULL;

	if( !CRMF_CERTREQMSG_push0_regInfo( msg, atav)) goto err;
	atav = NULL;
	
	return 1;
err:
	if (utf8pairsDup) ASN1_UTF8STRING_free( utf8pairsDup);
	if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free( atav);
	return 0;
}

/* ############################################################################ */
/* ############################################################################ */
int CRMF_CERTREQMSG_set1_regInfo_regToken( CRMF_CERTREQMSG *msg, ASN1_UTF8STRING *tok) {
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;
	ASN1_UTF8STRING *tokDup=NULL;

	if (!msg) return 0;
	if (!tok) return 0;

	if (!(tokDup = ASN1_STRING_dup( tok))) goto err;
	
	if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())) goto err;

	atav->type = OBJ_nid2obj(NID_id_regCtrl_regToken);
	atav->value.regToken = tokDup;
	tokDup = NULL;

	if( !CRMF_CERTREQMSG_push0_regInfo( msg, atav)) goto err;
	atav = NULL;
	
	return 1;
err:
	if (tokDup) ASN1_UTF8STRING_free( tokDup);
	if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free( atav);
	return 0;
}

/* ############################################################################ */
/* ############################################################################ */
int CRMF_CERTREQMSG_set1_regInfo_certReq( CRMF_CERTREQMSG *msg, CRMF_CERTREQUEST *certReq) {
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;
	CRMF_CERTREQUEST *certReqDup=NULL;

	if (!msg) return 0;
	if (!certReq) return 0;

	if (!(certReqDup = CRMF_CERTREQUEST_dup( certReq))) goto err;
	
	if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())) goto err;

	atav->type = OBJ_nid2obj(NID_id_regInfo_certReq);
	atav->value.certReq = (struct CRMF_CERTREQUEST*) certReqDup;
	certReqDup = NULL;

	if( !CRMF_CERTREQMSG_push0_regInfo( msg, atav)) goto err;
	atav = NULL;
	
	return 1;
err:
	if (certReqDup) CRMF_CERTREQUEST_free( certReqDup);
	if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free( atav);
	return 0;
}


/* ############################################################################ */

/* CERTTEMPLATE */
/* ############################################################################ */
/* CertRequest syntax:
 * version MUST be 2 if supplied.  It SHOULD be omitted. */
/* ############################################################################ */
int CRMF_CERTREQMSG_set_version2( CRMF_CERTREQMSG *certReqMsg) {
	if (! certReqMsg) return 0;

	if (! certReqMsg->certReq->certTemplate->version)
		/* OPTIONAL, not initialized yet */
		certReqMsg->certReq->certTemplate->version = ASN1_INTEGER_new();
	ASN1_INTEGER_set( certReqMsg->certReq->certTemplate->version, 2L);
	return 1;
}

/* ############################################################################ */
/* returns 1 on success, 0 on error */
/* sets notBefore and/or notAfter in certTemplate of the given certreqmsg - if they are not given as 0 */
/* ############################################################################ */
int CRMF_CERTREQMSG_set_validity( CRMF_CERTREQMSG *certReqMsg, time_t notBefore, time_t notAfter) {
	CRMF_OPTIONALVALIDITY *validity=NULL;
	ASN1_TIME *notBeforeAsn=NULL;
	ASN1_TIME *notAfterAsn=NULL;

	if (! certReqMsg) return 0;

	if (notBefore) {
		if( !(notBeforeAsn = ASN1_TIME_set(NULL, notBefore))) goto err;
	}
	if (notAfter) {
		if( !(notAfterAsn = ASN1_TIME_set(NULL, notAfter))) goto err;
	}
	if (!(validity = CRMF_OPTIONALVALIDITY_new())) goto err;

	validity->notBefore = notBeforeAsn;
	validity->notAfter  = notAfterAsn;

	certReqMsg->certReq->certTemplate->validity = validity;

	return 1;
err:
    CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET_VALIDITY, CRMF_R_CRMFERROR);

	if (validity) CRMF_OPTIONALVALIDITY_free(validity);
	if (notBeforeAsn) ASN1_TIME_free(notBeforeAsn);
	if (notAfterAsn) ASN1_TIME_free(notAfterAsn);
	return 0;
}

/* ############################################################################ */
/* set the certReqId */
/*
      certReqId contains an integer value that is used by the
      certificate requestor to associate a specific certificate request
      with a certificate response.
*/
/* ############################################################################ */
int CRMF_CERTREQMSG_set_certReqId( CRMF_CERTREQMSG *certReqMsg, const long certReqId) {
	if (! certReqMsg) return 0;

	return ASN1_INTEGER_set(certReqMsg->certReq->certReqId, certReqId);
}

/* ############################################################################ */
/* set the public Key */
/* ############################################################################ */
int CRMF_CERTREQMSG_set1_publicKey( CRMF_CERTREQMSG *certReqMsg, const EVP_PKEY *pkey) {
	if (! certReqMsg) goto err;
	if (! pkey) goto err;

	/* this function is *not* consuming the pointer */
	return X509_PUBKEY_set(&(certReqMsg->certReq->certTemplate->publicKey), (EVP_PKEY*) pkey);

err:
	CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET1_PUBLICKEY, CRMF_R_CRMFERROR);
	return 0;
}

/* ############################################################################ */
/* set the subject in the cert Template */
/* ############################################################################ */
int CRMF_CERTREQMSG_set1_subject( CRMF_CERTREQMSG *certReqMsg, const X509_NAME *subject) {
	if (! certReqMsg) return 0;
	if (! subject) return 0;

	/* this function is *not* consuming the pointer */
	return X509_NAME_set(&(certReqMsg->certReq->certTemplate->subject), (X509_NAME*) subject);
}

/* ############################################################################ */
/* returns 1 on success, 0 on error */
/* push an extension to the extension stack */
/* ############################################################################ */
int CRMF_CERTREQMSG_push0_extension( CRMF_CERTREQMSG *certReqMsg, X509_EXTENSION *ext) {
	int createdStack = 0;

	if (! certReqMsg) goto err;
	if (! ext) goto err;

	if (! certReqMsg->certReq->certTemplate->extensions) {
		if( !(certReqMsg->certReq->certTemplate->extensions = sk_X509_EXTENSION_new_null())) 
			goto err;
		createdStack = 1;
	}

	if( !sk_X509_EXTENSION_push(certReqMsg->certReq->certTemplate->extensions, ext)) goto err;
	return 1;
err:
	CRMFerr(CRMF_F_CRMF_CERTREQMSG_PUSH0_EXTENSION, CRMF_R_CRMFERROR);

	if (createdStack) {
		sk_X509_EXTENSION_pop_free( certReqMsg->certReq->certTemplate->extensions, X509_EXTENSION_free);
		certReqMsg->certReq->certTemplate->extensions = NULL;
	}
	return 0;
}

/* ############################################################################ */
/* TODO check */
/*
   1.  The certificate subject has not yet established an authenticated
       identity with a CA/RA, but has a password and identity string
       from the CA/RA.  In this case, the POPOSigningKeyInput structure
       would be filled out using the publicKeyMAC choice for authInfo,
       and the password and identity would be used to compute the
       publicKeyMAC value.  The public key for the certificate being
       requested would be placed in both the POPOSigningKeyInput and the
       Certificate Template structures.  The signature field is computed
       over the DER-encoded POPOSigningKeyInput structure.
       */
/*
      poposkInput contains the data to be signed, when present.  This
      field MUST be present when the certificate template does not
      contain both the public key value and a subject name value.

      algorithmIdentifier identifiers the signature algorithm and an
      associated parameters used to produce the POP value.

      signature contains the POP value produce.  If poposkInput is
      present, the signature is computed over the DER-encoded value of
      poposkInput.  If poposkInput is absent, the signature is computed
      over the DER-encoded value of certReq.
      */
/* ############################################################################ */
/* XXX There should be identified what algorithm SHOULD be used.
 * going with sha1withRSA for now
 */
CRMF_POPOSIGNINGKEY * CRMF_poposigningkey_new( CRMF_CERTREQUEST *certReq, const EVP_PKEY *pkey) {
	CRMF_POPOSIGNINGKEY *poposig=NULL;
	size_t certReqSize, maxSignatureSize;
	unsigned int sigLen;
	unsigned char *certReqDer=NULL;
	unsigned char *signature=NULL;

	EVP_MD_CTX *ctx=NULL;

	/* TODO: what about PoposkInput? */
	if( !(poposig = CRMF_POPOSIGNINGKEY_new())) goto err;
	/* get DER representation */
	certReqSize = i2d_CRMF_CERTREQUEST( certReq, &certReqDer);

	maxSignatureSize = EVP_PKEY_size( (EVP_PKEY*) pkey);
	signature = OPENSSL_malloc(maxSignatureSize);

	ctx=EVP_MD_CTX_create();
	if (!(EVP_SignInit_ex(ctx, EVP_sha1(),NULL))) goto err;
	if (!(EVP_SignUpdate(ctx, certReqDer, certReqSize))) goto err;
	if (!(EVP_SignFinal(ctx, signature, &sigLen, (EVP_PKEY*) pkey))) goto err;

	/* set the signature value */
	if (!(ASN1_BIT_STRING_set( poposig->signature, signature, sigLen))) goto err;

	/* Actually this should not be needed but OpenSSL defaults all bitstrings to be a NamedBitList */
	poposig->signature->flags &= ~0x07;
	poposig->signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;

	/* set the type of the algorithm */
	if (EVP_PKEY_type(pkey->type) == EVP_PKEY_DSA)
		X509_ALGOR_set0(poposig->algorithmIdentifier, OBJ_nid2obj(NID_dsaWithSHA1), V_ASN1_NULL, NULL);
	else /* assume RSA */
		X509_ALGOR_set0(poposig->algorithmIdentifier, OBJ_nid2obj(NID_sha1WithRSAEncryption), V_ASN1_NULL, NULL);

	/* cleanup */
	OPENSSL_free(certReqDer);
	EVP_MD_CTX_destroy(ctx);
	OPENSSL_free(signature);
	return poposig;
err:
	if( poposig) CRMF_POPOSIGNINGKEY_free( poposig);
	if( certReqDer) OPENSSL_free(certReqDer);
	if( ctx) EVP_MD_CTX_destroy(ctx);
	if( signature) OPENSSL_free(signature);
	return NULL;
}

/* ############################################################################ */
/* calculate and set the proof of possession */
/* ############################################################################ */
int CRMF_CERTREQMSG_calc_and_set_popo( CRMF_CERTREQMSG *certReqMsg, const EVP_PKEY *pkey, int popoMethod) {
	CRMF_PROOFOFPOSSESION *newPopo=NULL;

	if (! certReqMsg) return 0;
	if (! pkey) return 0;

	if( !(newPopo = CRMF_PROOFOFPOSSESION_new())) goto err;
	CRMF_printf("INFO: using popoMethod %d\n", popoMethod);

	switch (popoMethod) {
		case CMP_POPO_SIGNATURE:
			newPopo->value.signature = CRMF_poposigningkey_new( certReqMsg->certReq, pkey);
			if( !(newPopo->value.signature)) goto err;
			newPopo->type = CRMF_PROOFOFPOSESSION_SIGNATURE;
			break;

		case CMP_POPO_ENCRCERT:
			newPopo->type = CRMF_PROOFOFPOSESSION_KEYENCIPHERMENT;
			newPopo->value.keyEncipherment = CRMF_POPOPRIVKEY_new();

			newPopo->value.keyEncipherment->type = CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE;
			
			newPopo->value.keyEncipherment->value.subsequentMessage = ASN1_INTEGER_new();
			ASN1_INTEGER_set(newPopo->value.keyEncipherment->value.subsequentMessage, CRMF_SUBSEQUENTMESSAGE_ENCRCERT);
			break;

		default: goto err;
	}

	if(certReqMsg->popo) 
		/* OPTIONAL, initialized before */
		CRMF_PROOFOFPOSSESION_free(certReqMsg->popo);
	certReqMsg->popo = newPopo;

	CMP_printf("INFO: popo set\n");

	return 1;
err:
	if( newPopo) CRMF_PROOFOFPOSSESION_free( newPopo);
	return 0;
}

