/* crypto/crmf/crmf_lib.c
 * 
 * CRMF (RFC 4211) header file for OpenSSL
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
#include <openssl/crmf.h>
#include <openssl/evp.h>

/* ############################################################################ */
/* TODO: check */
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
printf("FILE %s, LINE %d :Success setting control\n", __FILE__, __LINE__);
	return 1;
err:
	if( newControls) {
		sk_CRMF_ATTRIBUTETYPEANDVALUE_free(certReqMsg->certReq->controls);
		certReqMsg->certReq->controls = NULL;
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
/* TODO: check */
/* ############################################################################ */
int CRMF_CERTREQMSG_set1_control_regToken( CRMF_CERTREQMSG *msg, ASN1_UTF8STRING *tok) {
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;
	ASN1_UTF8STRING *tokDup=NULL;

	if (!msg) return 0;
	if (!tok) return 0;

	/* XXX is there no ASN1_UTF8STRING_dup() function? */
	if (!(tokDup = ASN1_STRING_dup( tok))) goto err;
	
	if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())) goto err;

	if( !CRMF_ATTRIBUTETYPEANDVALUE_set0_nid_utf8string( atav, NID_id_regCtrl_regToken, tokDup)) goto err;
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
/* TODO: check */
/* ############################################################################ */
int CRMF_CERTREQMSG_set1_control_authenticator( CRMF_CERTREQMSG *msg, ASN1_UTF8STRING *auth) {
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;
	ASN1_UTF8STRING *authDup=NULL;

	if (!msg) return 0;
	if (!auth) return 0;

	/* XXX is there no ASN1_UTF8STRING_dup() function? */
	if (!(authDup = ASN1_STRING_dup( auth))) goto err;
	
	if (!(atav = CRMF_ATTRIBUTETYPEANDVALUE_new())) goto err;

	if( !CRMF_ATTRIBUTETYPEANDVALUE_set0_nid_utf8string( atav, NID_id_regCtrl_authenticator, authDup)) goto err;
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
/* TODO: implement */
#if 0
int CRMF_CERTREQMSG_set1_control_pkiPublicationInfo( CRMF_CERTREQMSG *msg, ASN1_UTF8STRING *auth) {
#endif
/* ############################################################################ */

/* ############################################################################ */
/* TODO: implement */
#if 0
int CRMF_CERTREQMSG_set1_control_pkiArchiveOptions( CRMF_CERTREQMSG *msg, ASN1_UTF8STRING *auth) {
#endif
/* ############################################################################ */

/* ############################################################################ */
/* TODO: implement */
#if 0
int CRMF_CERTREQMSG_set1_control_oldCertID( CRMF_CERTREQMSG *msg, ASN1_UTF8STRING *auth) {
#endif
/* ############################################################################ */

/* ############################################################################ */
/* TODO: implement */
#if 0
int CRMF_CERTREQMSG_set1_control_protocolEncrKey( CRMF_CERTREQMSG *msg, ASN1_UTF8STRING *auth) {
#endif
/* ############################################################################ */

/* REGINFO */
/* ############################################################################ */
/* TODO: implement */
#if 0
int CRMF_CERTREQMSG_set1_regInfo_utf8Pairs( CRMF_CERTREQMSG *msg, ASN1_UTF8STRING *auth) {
#endif
/* ############################################################################ */
/* ############################################################################ */
/* TODO: implement */
#if 0
int CRMF_CERTREQMSG_set1_regInfo_certReq( CRMF_CERTREQMSG *msg, ASN1_UTF8STRING *auth) {
#endif
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
printf("ERROR in FILE %s, LINE %d\n", __FILE__, __LINE__);
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
printf("ERROR in FILE %s, LINE %d\n", __FILE__, __LINE__);
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
printf("ERROR in FILE %s, LINE %d\n", __FILE__, __LINE__);
	if (createdStack) {
		sk_X509_EXTENSION_free( certReqMsg->certReq->certTemplate->extensions);
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
	/* TODO - Do I free that? */
	certReqSize = i2d_CRMF_CERTREQUEST( certReq, &certReqDer);

	maxSignatureSize = EVP_PKEY_size( (EVP_PKEY*) pkey);
	signature = OPENSSL_malloc(maxSignatureSize);

	/* TODO do I have to free this? */
	ctx=EVP_MD_CTX_create();
	if (!(EVP_SignInit_ex(ctx, EVP_sha1(),NULL))) goto err;
	if (!(EVP_SignUpdate(ctx, certReqDer, certReqSize))) goto err;
	if (!(EVP_SignFinal(ctx, signature, &sigLen, (EVP_PKEY*) pkey))) goto err;

	/* set the signature value */
	if (!(ASN1_BIT_STRING_set( poposig->signature, signature, sigLen))) goto err;

	/* set the type of the algorithm */
	/* TODO: this should be set according to the used key */
	X509_ALGOR_set0(poposig->algorithmIdentifier, OBJ_nid2obj(NID_sha1WithRSAEncryption), V_ASN1_NULL, NULL);

	/* cleanup */
#if 0
	/* XXX do I have to do that? */
printf("file: %s line: %d\n", __FILE__, __LINE__);
	OPENSSL_free(certReqDer);
#endif
	EVP_MD_CTX_destroy(ctx);
	OPENSSL_free(signature);
	return poposig;
err:
	if( poposig) CRMF_POPOSIGNINGKEY_free( poposig);
#if 0
	/* XXX do I have to do that? */
printf("file: %s line: %d\n", __FILE__, __LINE__);
	OPENSSL_free(certReqDer);
#endif
	if( signature) OPENSSL_free(signature);
	return NULL;
}

/* ############################################################################ */
/* calculate and set the proof of possession */
/* ############################################################################ */
int CRMF_CERTREQMSG_calc_and_set_popo( CRMF_CERTREQMSG *certReqMsg, const EVP_PKEY *pkey) {
	CRMF_PROOFOFPOSSESION *newPopo=NULL;

	if (! certReqMsg) return 0;
	if (! pkey) return 0;

	if( !(newPopo = CRMF_PROOFOFPOSSESION_new())) goto err;

	newPopo->value.signature = CRMF_poposigningkey_new( certReqMsg->certReq, pkey);
	if( !(newPopo->value.signature)) goto err;
	newPopo->type = CRMF_PROOFOFPOSESSION_SIGNATURE;

	if(certReqMsg->popo) 
		/* OPTIONAL, initialized before */
		CRMF_PROOFOFPOSSESION_free(certReqMsg->popo);
	certReqMsg->popo = newPopo;

	return 1;
err:
	if( newPopo) CRMF_PROOFOFPOSSESION_free( newPopo);
	return 0;
}

/* ############################################################################ */
/* TODO check */
/* XXX this is a test */
/* ############################################################################ */
CRMF_ATTRIBUTETYPEANDVALUE * CRMF_ATAV_OldCertId_new( GENERAL_NAME *issuer, ASN1_INTEGER *serialNumber) {
	CRMF_ATTRIBUTETYPEANDVALUE *atav=NULL;
	CRMF_CERTID *certId=NULL;
	unsigned char *certIdDer=NULL;
	int certIdDerLen;
	ASN1_STRING *certIdStr=NULL;

	/* XXX catch errors */
	atav = CRMF_ATTRIBUTETYPEANDVALUE_new();

	certId = CRMF_CERTID_new();
	certId->issuer = GENERAL_NAME_dup(issuer);
	certId->serialNumber = ASN1_INTEGER_dup(serialNumber);
	
	certIdDerLen = i2d_CRMF_CERTID( certId, &certIdDer);

	if (!(certIdStr = ASN1_STRING_new())) goto err;
	ASN1_STRING_set0( certIdStr, certIdDer, certIdDerLen);
	certIdDer = NULL;

	CRMF_CERTID_free( certId);

	CRMF_ATTRIBUTETYPEANDVALUE_set0( atav, OBJ_nid2obj(NID_id_regCtrl_oldCertID), V_ASN1_SEQUENCE, certIdStr);
	certIdStr = NULL;
printf("FIle %s, Line %d\n", __FILE__, __LINE__);

	return atav;
err:
printf("GOT ERROR IN %s, %d\n", __FILE__, __LINE__);
	if (certIdDer) OPENSSL_free(certIdDer);
	if (atav) CRMF_ATTRIBUTETYPEANDVALUE_free(atav);
	if (certIdStr) ASN1_STRING_free(certIdStr);
	return NULL;
}
