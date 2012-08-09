/* crypto/crmf/crmf_lib.c
 * CRMF (RFC 4211) library functions for OpenSSL
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
 * In this file are the functions which set the individual items inside         *
 * the CRMF structures                                                          *
 * ############################################################################ */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* ############################################################################ *
 * Pushes the given control attribute into the controls stack of a CertRequest
 * (section 6)
 * ############################################################################ */
int CRMF_CERTREQMSG_push0_control( CRMF_CERTREQMSG *certReqMsg, CRMF_ATTRIBUTETYPEANDVALUE *control) {
	int newControls = 0;

	if( !certReqMsg) return 0;
	if( !control) return 0;

	if( !(certReqMsg->certReq->controls)) {
		/* as it is OPTIONAL it might not yet be initialized */
		if( !(certReqMsg->certReq->controls = sk_CRMF_ATTRIBUTETYPEANDVALUE_new_null())) goto err;
		newControls = 1; /* for potential cleanup in error case */
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

/* ############################################################################ *
 * sets the id-regCtrl-regToken Control (section 6.1)
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_control_regToken( CRMF_CERTREQMSG *msg, ASN1_UTF8STRING *tok) {
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;

	if (!msg) goto err;
	if (!tok) goto err;
	
	if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())) goto err;

	atav->type = OBJ_nid2obj(NID_id_regCtrl_regToken);
	if (!(atav->value.regToken = ASN1_STRING_dup( tok))) goto err;

	if( !CRMF_CERTREQMSG_push0_control( msg, atav)) goto err;
	atav = NULL;
	
	return 1;
err:
	if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free( atav);
	return 0;
}

/* ############################################################################ *
 * sets the id-regCtrl-authenticator Control (section 6.2)
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_control_authenticator( CRMF_CERTREQMSG *msg, ASN1_UTF8STRING *auth) {
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;

	if (!msg) goto err;
	if (!auth) goto err;
	
	if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())) goto err;

	atav->type = OBJ_nid2obj(NID_id_regCtrl_authenticator);
	if (!(atav->value.regToken = ASN1_STRING_dup( auth))) goto err;
	if( !CRMF_CERTREQMSG_push0_control( msg, atav)) goto err;
	atav = NULL;
	
	return 1;
err:
	if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free( atav);
	return 0;
}

/* ############################################################################ *
 * sets the id-regCtrl-pkiPublicationInfo Control (section 6.3)
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_control_pkiPublicationInfo( CRMF_CERTREQMSG *msg, CRMF_PKIPUBLICATIONINFO *pubinfo) {
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;

	if (!msg) goto err;
	if (!pubinfo) goto err;

	
	if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())) goto err;

	atav->type = OBJ_nid2obj(NID_id_regCtrl_pkiPublicationInfo);
	if (!(atav->value.pkiPublicationInfo = CRMF_PKIPUBLICATIONINFO_dup( pubinfo))) goto err;
	if( !CRMF_CERTREQMSG_push0_control( msg, atav)) goto err;
	atav = NULL;
	
	return 1;
err:
	if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free( atav);
	return 0;
}

/* ############################################################################
 * sets the id-regCtrl-pkiArchiveOptions Control (section 6.4)
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_control_pkiArchiveOptions( CRMF_CERTREQMSG *msg, CRMF_PKIARCHIVEOPTIONS *archopts) {
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;

	if (!msg) goto err;
	if (!archopts) goto err;
	
	if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())) goto err;

	atav->type = OBJ_nid2obj(NID_id_regCtrl_pkiArchiveOptions);
	if (!(atav->value.pkiArchiveOptions = CRMF_PKIARCHIVEOPTIONS_dup( archopts))) goto err;
	if( !CRMF_CERTREQMSG_push0_control( msg, atav)) goto err;
	atav = NULL;
	
	return 1;
err:
	if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free( atav);
	return 0;
}

/* ############################################################################ *
 * sets the id-regCtrl-oldCertID Control (section 6.5)
 * ############################################################################ */
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

	/* X509_NAME_set does not consume the pointer so this is ok */
	X509_NAME_set( &gName->d.directoryName, X509_get_issuer_name( oldCert));
	gName->type = GEN_DIRNAME;
	certId->issuer = gName;
	if (!(certId->serialNumber = ASN1_INTEGER_dup(X509_get_serialNumber(oldCert)))) goto err;

	atav->type = OBJ_nid2obj(NID_id_regCtrl_oldCertID);
	atav->value.oldCertId = certId;

	if (!CRMF_CERTREQMSG_push0_control( certReqMsg, atav)) goto err;

	return 1;
err:
	if (gName) GENERAL_NAME_free(gName);
	if (certId) {
    certId->issuer = NULL;
    CRMF_CERTID_free(certId);
  }
	if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free( atav);
	return 0;
}

/* ############################################################################ *
 * For some reason X509_PUBKEY_dup() does not appear to be implemented by 
 * OpenSSL's X509 code, so we implement it here. It's only needed in the following
 * function so it can be declared static. *
 * TODO: check whether that should go elsewhere *
 * ############################################################################ */
static IMPLEMENT_ASN1_DUP_FUNCTION(X509_PUBKEY);

/* ############################################################################ *
 * sets the id-regCtrl-protocolEncrKey Control (section 6.6)
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_control_protocolEncrKey( CRMF_CERTREQMSG *msg, X509_PUBKEY *pubkey) {	
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;

	if (!msg) goto err;
	if (!pubkey) goto err;

	if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())) goto err;

	atav->type = OBJ_nid2obj(NID_id_regCtrl_protocolEncrKey);
	if (!(atav->value.protocolEncrKey = X509_PUBKEY_dup(pubkey))) goto err;
	if( !CRMF_CERTREQMSG_push0_control( msg, atav)) goto err;
	atav = NULL;
	
	return 1;
err:
	if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free( atav);
	return 0;
}

/* ############################################################################ *
 * Pushes the attribute given in regInfo in to the CertReqMsg->regInfo stack.
 * (section 7)
 * ############################################################################ */
int CRMF_CERTREQMSG_push0_regInfo( CRMF_CERTREQMSG *certReqMsg, CRMF_ATTRIBUTETYPEANDVALUE *regInfo) {
	int newRegInfo = 0;

	if( !certReqMsg) return 0;
	if( !regInfo) return 0;

	if( !(certReqMsg->regInfo)) {
		/* as it is OPTIONAL it might not yet be initialized */
		if( !(certReqMsg->regInfo = sk_CRMF_ATTRIBUTETYPEANDVALUE_new_null())) goto err;
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
	
/* ############################################################################ *
 * sets the id-regInfo-utf8Pairs to regInfo (section 7.1)
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_regInfo_utf8Pairs( CRMF_CERTREQMSG *msg, ASN1_UTF8STRING *utf8pairs) {
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;

	if (!msg) goto err;
	if (!utf8pairs) goto err;

	
	if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())) goto err;

	atav->type = OBJ_nid2obj(NID_id_regInfo_utf8Pairs);
	if (!(atav->value.utf8pairs = ASN1_STRING_dup( utf8pairs))) goto err;

	if( !CRMF_CERTREQMSG_push0_regInfo( msg, atav)) goto err;
	atav = NULL;
	
	return 1;
err:
	if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free( atav);
	return 0;
}

/* ############################################################################ *
 * sets the id-regCtrl-regToken to regInfo (not described in RFC)
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_regInfo_regToken( CRMF_CERTREQMSG *msg, ASN1_UTF8STRING *tok) {
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;

	if (!msg) return 0;
	if (!tok) return 0;

	
	if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())) goto err;

	atav->type = OBJ_nid2obj(NID_id_regCtrl_regToken);
	if (!(atav->value.regToken = ASN1_STRING_dup( tok))) goto err;

	if( !CRMF_CERTREQMSG_push0_regInfo( msg, atav)) goto err;
	atav = NULL;
	
	return 1;
err:
	if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free( atav);
	return 0;
}

/* ############################################################################ *
 * sets the id-regInfo-certReq to regInfo (section 7.2)
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_regInfo_certReq( CRMF_CERTREQMSG *msg, CRMF_CERTREQUEST *certReq) {
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;

	if (!msg) goto err;
	if (!certReq) goto err;

	if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())) goto err;

	atav->type = OBJ_nid2obj(NID_id_regInfo_certReq);
	if (!(atav->value.certReq = CRMF_CERTREQUEST_dup( certReq))) goto err;

	if( !CRMF_CERTREQMSG_push0_regInfo( msg, atav)) goto err;
	atav = NULL;
	
	return 1;
err:
	if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free( atav);
	return 0;
}


/* ############################################################################ *
 * sets version 2 in cert Template
 * version MUST be 2 if supplied.  It SHOULD be omitted.
 * ############################################################################ */
int CRMF_CERTREQMSG_set_version2( CRMF_CERTREQMSG *certReqMsg) {
	if (! certReqMsg) return 0;

	if (! certReqMsg->certReq->certTemplate->version)
		/* as it is OPTIONAL it might not yet be initialized */
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

	if (validity) {
    CRMF_OPTIONALVALIDITY_free(validity);
    notBeforeAsn = NULL;
    notAfterAsn = NULL;
  }
	if (notBeforeAsn) ASN1_TIME_free(notBeforeAsn);
	if (notAfterAsn) ASN1_TIME_free(notAfterAsn);
	return 0;
}

/* ############################################################################ *
 * set the certReqId according to section 5
 * returns 0 on error, 1 on success
 *
 *    certReqId contains an integer value that is used by the
 *    certificate requestor to associate a specific certificate request
 *    with a certificate response.
 * ############################################################################ */
int CRMF_CERTREQMSG_set_certReqId( CRMF_CERTREQMSG *certReqMsg, const long certReqId) {
	if (! certReqMsg) goto err;
	if (! certReqMsg->certReq) goto err;

	return ASN1_INTEGER_set(certReqMsg->certReq->certReqId, certReqId);
err:
	return 0;
}

/* ############################################################################ *
 * set the public Key to the certTemplate according to chapgter 5 *
 * returns 0 on error, 1 on success
 *    publicKey contains the public key for which the certificate is
 *    being created.  This field MUST be filled in if the requestor
 *    generates its own key.  The field is omitted if the key is
 *    generated by the RA/CA.
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_publicKey( CRMF_CERTREQMSG *certReqMsg, const EVP_PKEY *pkey) {
	if (! certReqMsg) goto err;
	if (! pkey) goto err;

	/* this function is not consuming the pointer */
	return X509_PUBKEY_set(&(certReqMsg->certReq->certTemplate->publicKey), (EVP_PKEY*) pkey);
err:
	CRMFerr(CRMF_F_CRMF_CERTREQMSG_SET1_PUBLICKEY, CRMF_R_CRMFERROR);
	return 0;
}

/* ############################################################################ *
 * Set the subject name in the given certificate template according to section 5
 * returns 1 on success, 0 on error
 *    subject is filled in with the suggested name for the requestor.
 *    This would normally be filled in by a name that has been
 *    previously issued to the requestor by the CA.
 * ############################################################################ */
int CRMF_CERTREQMSG_set1_subject( CRMF_CERTREQMSG *certReqMsg, const X509_NAME *subject) {
	if (! certReqMsg) goto err;
	if (! subject) goto err;

	/* this function is *not* consuming the pointer */
	return X509_NAME_set(&(certReqMsg->certReq->certTemplate->subject), (X509_NAME*) subject);
err:
	return 0;
}

/* ############################################################################ *
 * push an extension to the extension stack
 * returns 1 on success, 0 on error
 *    extensions contains extensions that the requestor wants to have
 *    placed in the certificate.  These extensions would generally deal
 *    with things such as setting the key usage to keyEncipherment.
 * ############################################################################ */
int CRMF_CERTREQMSG_push0_extension( CRMF_CERTREQMSG *certReqMsg, X509_EXTENSION *ext) {
	int createdStack = 0;

	if (! certReqMsg) goto err;
	if (! ext) goto err;

	if (! certReqMsg->certReq->certTemplate->extensions) {
		if( !(certReqMsg->certReq->certTemplate->extensions = sk_X509_EXTENSION_new_null())) goto err;
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

/* ############################################################################ *
 * Create proof-of-posession information by signing the certrequest with our 
 * private key according to section 4.1. Algorithm is chosen based on key type.
 *
 * returns a pointer to the created CRMF_POPOSIGNINGKEY on success, NULL on
 * error
 *
 * TODO:
 * This function does not work for cases where the subject name is not in the 
 * Certificate Template structure as it doesn't create poposkInput.
 * Compare section 4, 3rd case to look at:
 *
   3.  The certificate subject places its name in the Certificate
       Template structure along with the public key.  In this case the
       poposkInput field is omitted from the POPOSigningKey structure.
       The signature field is computed over the DER-encoded certificate
       template structure.
 *
 * TODO: only RSA/DSA are supported so far
 *
 * as default, for RSA/DSA SHA-1 is used for generating the input
 * ############################################################################ */
CRMF_POPOSIGNINGKEY * CRMF_poposigningkey_new( CRMF_CERTREQUEST *certReq, const EVP_PKEY *pkey) {
	CRMF_POPOSIGNINGKEY *poposig=NULL;
	size_t certReqSize, maxSignatureSize;
	unsigned int sigLen;
	unsigned char *certReqDer=NULL;
	unsigned char *signature=NULL;
	const EVP_MD *alg=NULL;

	EVP_MD_CTX *ctx=NULL;

	/* NOTE: PoposkInput is not handled here. */
	if( !(poposig = CRMF_POPOSIGNINGKEY_new())) goto err;
	/* get DER representation */
	certReqSize = i2d_CRMF_CERTREQUEST( certReq, &certReqDer);

	maxSignatureSize = EVP_PKEY_size( (EVP_PKEY*) pkey);
	signature = OPENSSL_malloc(maxSignatureSize);

	/* set the type of the algorithm */
  switch (EVP_PKEY_type(pkey->type)){
#ifndef OPENSSL_NO_DSA
  case EVP_PKEY_DSA:
		X509_ALGOR_set0(poposig->algorithmIdentifier, OBJ_nid2obj(NID_dsaWithSHA1), V_ASN1_NULL, NULL);
		alg = EVP_dss1();
    break;
#endif
#ifndef OPENSSL_NO_RSA
  case EVP_PKEY_RSA:
		X509_ALGOR_set0(poposig->algorithmIdentifier, OBJ_nid2obj(NID_sha1WithRSAEncryption), V_ASN1_NULL, NULL);
		alg = EVP_sha1();
    break;
#endif
  default:
  /* TODO: error msg - unsupported key */
    goto err;
  }

	ctx=EVP_MD_CTX_create();
	if (!(EVP_SignInit_ex(ctx, alg, NULL))) goto err;
	if (!(EVP_SignUpdate(ctx, certReqDer, certReqSize))) goto err;
	if (!(EVP_SignFinal(ctx, signature, &sigLen, (EVP_PKEY*) pkey))) goto err;

	/* set the signature value */
	if (!(ASN1_BIT_STRING_set( poposig->signature, signature, sigLen))) goto err;

	/* cleanup */
	OPENSSL_free(certReqDer);
	EVP_MD_CTX_destroy(ctx);
	OPENSSL_free(signature);
	return poposig;
err:
  /* TODO: error msg */
	if( poposig) CRMF_POPOSIGNINGKEY_free( poposig);
	if( certReqDer) OPENSSL_free(certReqDer);
	if( ctx) EVP_MD_CTX_destroy(ctx);
	if( signature) OPENSSL_free(signature);
	return NULL;
}

/* ############################################################################ *
 * calculate and set the proof of possession based on the popoMethod (define in cmp.h)
 * the following types are supported so far:
 *   CMP_POPO_SIGNATURE: according to section 4.1
 *   CMP_POPO_ENCRCERT:  according to section 4.2 with the indirect method.
 * returns 1 on success, 0 on error
 * ############################################################################ */
int CRMF_CERTREQMSG_calc_and_set_popo( CRMF_CERTREQMSG *certReqMsg, const EVP_PKEY *pkey, int popoMethod) {
	CRMF_PROOFOFPOSSESION *newPopo=NULL;

	if (! certReqMsg) goto err;
	if (! pkey) goto err;

	if( !(newPopo = CRMF_PROOFOFPOSSESION_new())) goto err;

	switch (popoMethod) {
		case CMP_POPO_SIGNATURE:
			if( !(newPopo->value.signature = CRMF_poposigningkey_new( certReqMsg->certReq, pkey))) goto err;
			newPopo->type = CRMF_PROOFOFPOSESSION_SIGNATURE;
			break;

		case CMP_POPO_ENCRCERT:
			newPopo->type = CRMF_PROOFOFPOSESSION_KEYENCIPHERMENT;
			newPopo->value.keyEncipherment = CRMF_POPOPRIVKEY_new();

			newPopo->value.keyEncipherment->type = CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE;
			
			newPopo->value.keyEncipherment->value.subsequentMessage = ASN1_INTEGER_new();
			ASN1_INTEGER_set(newPopo->value.keyEncipherment->value.subsequentMessage, CRMF_SUBSEQUENTMESSAGE_ENCRCERT);
			break;

		default: 
      goto err;
	}

	if(certReqMsg->popo) 
		/* OPTIONAL but initialized before */
		CRMF_PROOFOFPOSSESION_free(certReqMsg->popo);
	certReqMsg->popo = newPopo;

	CMP_printf("INFO: proof-of-posession set\n");

	return 1;
err:
  /* TODO: error msg */
	if( newPopo) CRMF_PROOFOFPOSSESION_free( newPopo);
	return 0;
}

