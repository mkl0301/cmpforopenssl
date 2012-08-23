/* vim: set noet ts=4 sts=4 sw=4: */
/* cmp.h
 * CMP (RFC 4210) header file for OpenSSL
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
 * Copyright 2007-2010 Nokia Siemens Networks Oy. ALL RIGHTS RESERVED.
 * CMP support in OpenSSL originally developed by 
 * Nokia Siemens Networks for contribution to the OpenSSL project.
 */

/* =========================== CHANGE LOG =============================
 * 2007 - Martin Peylo - Initial Creation
 * 2008 - Sami Lehtonen - added CMP_cr_new() and CMP_doCertificateRequestSeq()
 *						  declarations
 * 2010 - Miikka viljanen - Added error code list
 */

#ifndef HEADER_CMP_H
#define HEADER_CMP_H

#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/safestack.h>

#ifdef HAVE_CURL
#include <curl/curl.h>
#endif


#include <openssl/crmf.h>

#ifdef	__cplusplus
extern "C" {
#endif


/*
	 RevAnnContent ::= SEQUENCE {
		 status				 PKIStatus,
		 certId				 CertId,
		 willBeRevokedAt	 GeneralizedTime,
		 badSinceDate		 GeneralizedTime,
		 crlDetails			 Extensions  OPTIONAL
		 -- extra CRL details (e.g., crl number, reason, location, etc.)
	 }
	 */
typedef struct cmp_revanncontent_st
{
	ASN1_INTEGER			 *status;
	CRMF_CERTID				 *certId;
	ASN1_GENERALIZEDTIME	 *willBeRevokedAt;
	ASN1_GENERALIZEDTIME	 *badSinceDate;
	X509_EXTENSIONS			 *crlDetails;
} CMP_REVANNCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_REVANNCONTENT)


/*
	 Challenge ::= SEQUENCE {
		 owf				 AlgorithmIdentifier  OPTIONAL,

		 -- MUST be present in the first Challenge; MAY be omitted in
		 -- any subsequent Challenge in POPODecKeyChallContent (if
		 -- omitted, then the owf used in the immediately preceding
		 -- Challenge is to be used).

		 witness			 OCTET STRING,
		 -- the result of applying the one-way function (owf) to a
		 -- randomly-generated INTEGER, A.	[Note that a different
		 -- INTEGER MUST be used for each Challenge.]
		 challenge			 OCTET STRING
		 -- the encryption (under the public key for which the cert.
		 -- request is being made) of Rand, where Rand is specified as
		 --   Rand ::= SEQUENCE {
		 --		 int	  INTEGER,
		 --		  - the randomly-generated INTEGER A (above)
		 --		 sender   GeneralName
		 --		  - the sender's name (as included in PKIHeader)
		 --   }
	 }
	 */
typedef struct cmp_challenge_st
{
	X509_ALGOR		  *owf;
	ASN1_OCTET_STRING *whitness;
	ASN1_OCTET_STRING *challenge;
} CMP_CHALLENGE;
DECLARE_ASN1_FUNCTIONS(CMP_CHALLENGE)
DECLARE_STACK_OF(CMP_CHALLENGE)
/* TODO:
	 POPODecKeyChallContent ::= SEQUENCE OF Challenge
	 -- One Challenge per encryption key certification request (in the
	 -- same order as these requests appear in CertReqMessages).
	 */

/* the rfc allows substituting that with "Certificate"... */
	/*
	  CMPCertificate ::= CHOICE {
		 x509v3PKCert		 Certificate
	  }
	  */
#define CMP_CMPCERTIFICATE_X509V3PKCERT   0
typedef struct cmp_cmpcertificate_st
{
	int type;
	union{
		X509 *x509v3PKCert;
	} value;
} CMP_CMPCERTIFICATE;
DECLARE_ASN1_FUNCTIONS(CMP_CMPCERTIFICATE)
DECLARE_STACK_OF(CMP_CMPCERTIFICATE)


	/*
	 CAKeyUpdAnnContent ::= SEQUENCE {
		 oldWithNew   CMPCertificate, -- old pub signed with new priv
		 newWithOld   CMPCertificate, -- new pub signed with old priv
		 newWithNew   CMPCertificate  -- new pub signed with new priv
	 }
	 */
typedef struct cmp_cakeyupdanncontent_st
{
#if 0
/* the rfc allows substituting CMPCertificate with "Certificate"... */
	CMP_CMPCERTIFICATE *oldWithNew;
	CMP_CMPCERTIFICATE *newWithOld;
	CMP_CMPCERTIFICATE *newWithNew;
#endif
	X509 *oldWithNew;
	X509 *newWithOld;
	X509 *newWithNew;
} CMP_CAKEYUPDANNCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_CAKEYUPDANNCONTENT)

/* declared here as it will be used in CMP_PKIMESSAGE (nested) and infotype and
 * value*/
typedef STACK_OF(CMP_PKIMESSAGE) CMP_PKIMESSAGES;
DECLARE_ASN1_FUNCTIONS(CMP_PKIMESSAGES)

/* ESS_SIGNING_CERT comes from ts.h, but for some reason ESS_SIGNING_CERT_it isn't declared there */
DECLARE_ASN1_ITEM(ESS_SIGNING_CERT)
DECLARE_STACK_OF(ESS_SIGNING_CERT)

typedef struct cmp_infotypeandvalue_st
{
	ASN1_OBJECT *infoType;
	union {
		char *ptr;

		/* NID_id_it_caProtEncCert - CA Protocol Encryption Certificate  */
		X509 *caProtEncCert;
		/* NID_id_it_signKeyPairTypes - Signing Key Pair Types	*/
		STACK_OF(X509_ALGOR) *signKeyPairTypes;
		/* NID_id_it_encKeyPairTypes - Encryption/Key Agreement Key Pair Types	*/
		STACK_OF(X509_ALGOR) *encKeyPairTypes;
		/* NID_id_it_preferredSymmAlg - Preferred Symmetric Algorithm  */
		X509_ALGOR *preferredSymmAlg;
		/* NID_id_it_caKeyUpdateInfo - Updated CA Key Pair	*/
		CMP_CAKEYUPDANNCONTENT *caKeyUpdateInfo;
		/* NID_id_it_currentCRL - CRL  */
		X509_CRL *currentCRL;
		/* NID_id_it_unsupportedOIDs - Unsupported Object Identifiers  */
		STACK_OF(ASN1_OBJECT) *unsupportedOIDs;
		/* NID_id_it_keyPairParamReq - Key Pair Parameters Request	*/
		ASN1_OBJECT *keyPairParamReq;
		/* NID_id_it_keyPairParamRep - Key Pair Parameters Response  */
		X509_ALGOR *keyPairParamRep;
		/* NID_id_it_revPassphrase - Revocation Passphrase	*/
		CRMF_ENCRYPTEDVALUE *revPassphrase;

		/* NID_id_it_implicitConfirm - ImplicitConfirm	*/
		ASN1_NULL *implicitConfirm;
		/* NID_id_it_confirmWaitTime - ConfirmWaitTime	*/
		ASN1_GENERALIZEDTIME *confirmWaitTime;

		/* NID_id_it_origPKIMessage - origPKIMessage  */
		CMP_PKIMESSAGES *origPKIMessage;

	STACK_OF(ASN1_UTF8STRING) *suppLangTagsValue;

#if 0
	/* this is what CL likes for KUR - not in the RFC */
		/* NID_id_smime_aa_signingCertificate */
		STACK_OF(ESS_SIGNING_CERT) *signingCertificate; 
#endif 

		ASN1_TYPE *other;
	} infoValue;
} CMP_INFOTYPEANDVALUE;
DECLARE_ASN1_FUNCTIONS(CMP_INFOTYPEANDVALUE)
DECLARE_STACK_OF(CMP_INFOTYPEANDVALUE)

	/*
	 PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
		 -- text encoded as UTF-8 String [RFC3629] (note: each
		 -- UTF8String MAY include an [RFC3066] language tag
		 -- to indicate the language of the contained text
		 -- see [RFC2482] for details)
	 */

#if 0
DECLARE_STACK_OF(ASN1_UTF8STRING)
typedef STACK_OF(ASN1_UTF8STRING) CMP_PKIFREETEXT;
DECLARE_ASN1_FUNCTIONS(CMP_PKIFREETEXT)
#endif


/*
	 PKIFailureInfo ::= BIT STRING {
	 -- since we can fail in more than one way!
	 -- More codes may be added in the future if/when required.
		 badAlg				 (0),
		 -- unrecognized or unsupported Algorithm Identifier
		 badMessageCheck	 (1),
		 -- integrity check failed (e.g., signature did not verify)
		 badRequest			 (2),
		 -- transaction not permitted or supported
		 badTime			 (3),
		 -- messageTime was not sufficiently close to the system time,
		 -- as defined by local policy
		 badCertId			 (4),
		 -- no certificate could be found matching the provided criteria
		 badDataFormat		 (5),
		 -- the data submitted has the wrong format
		 wrongAuthority		 (6),
		 -- the authority indicated in the request is different from the
		 -- one creating the response token
		 incorrectData		 (7),
		 -- the requester's data is incorrect (for notary services)
		 missingTimeStamp	 (8),
		 -- when the timestamp is missing but should be there
		 -- (by policy)
		 badPOP				 (9),
		 -- the proof-of-possession failed
		 certRevoked		 (10),
			-- the certificate has already been revoked
		 certConfirmed		 (11),
			-- the certificate has already been confirmed
		 wrongIntegrity		 (12),
			-- invalid integrity, password based instead of signature or
			-- vice versa
		 badRecipientNonce	 (13),
			-- invalid recipient nonce, either missing or wrong value
		 timeNotAvailable	 (14),
			-- the TSA's time source is not available
		 unacceptedPolicy	 (15),
			-- the requested TSA policy is not supported by the TSA.
		 unacceptedExtension (16),
			-- the requested extension is not supported by the TSA.
		 addInfoNotAvailable (17),
			-- the additional information requested could not be
			-- understood or is not available
		 badSenderNonce		 (18),
			-- invalid sender nonce, either missing or wrong size
		 badCertTemplate	 (19),
			-- invalid cert. template or missing mandatory information
		 signerNotTrusted	 (20),
			-- signer of the message unknown or not trusted
		 transactionIdInUse  (21),
			-- the transaction identifier is already in use
		 unsupportedVersion  (22),
			-- the version of the message is not supported
		 notAuthorized		 (23),
			-- the sender was not authorized to make the preceding
			-- request or perform the preceding action
		 systemUnavail		 (24),
		 -- the request cannot be handled due to system unavailability
		 systemFailure		 (25),
		 -- the request cannot be handled due to system failure
		 duplicateCertReq	 (26)
		 -- certificate cannot be issued because a duplicate
		 -- certificate already exists
	 }
	 */
#define CMP_PKIFAILUREINFO_badAlg		 0
#define CMP_PKIFAILUREINFO_badMessageCheck	 1
#define CMP_PKIFAILUREINFO_badRequest		 2
#define CMP_PKIFAILUREINFO_badTime		 3
#define CMP_PKIFAILUREINFO_badCertId		 4
#define CMP_PKIFAILUREINFO_badDataFormat	 5
#define CMP_PKIFAILUREINFO_wrongAuthority	 6
#define CMP_PKIFAILUREINFO_incorrectData	 7
#define CMP_PKIFAILUREINFO_missingTimeStamp	 8
#define CMP_PKIFAILUREINFO_badPOP		 9
#define CMP_PKIFAILUREINFO_certRevoked		10
#define CMP_PKIFAILUREINFO_certConfirmed	11
#define CMP_PKIFAILUREINFO_wrongIntegrity	12
#define CMP_PKIFAILUREINFO_badRecipientNonce	13
#define CMP_PKIFAILUREINFO_timeNotAvailable	14
#define CMP_PKIFAILUREINFO_unacceptedPolicy	15
#define CMP_PKIFAILUREINFO_unacceptedExtension	16
#define CMP_PKIFAILUREINFO_addInfoNotAvailable	17
#define CMP_PKIFAILUREINFO_badSenderNonce	18
#define CMP_PKIFAILUREINFO_badCertTemplate	19
#define CMP_PKIFAILUREINFO_signerNotTrusted	20
#define CMP_PKIFAILUREINFO_transactionIdInUse	21
#define CMP_PKIFAILUREINFO_unsupportedVersion	22
#define CMP_PKIFAILUREINFO_notAuthorized	23
#define CMP_PKIFAILUREINFO_systemUnavail	24
#define CMP_PKIFAILUREINFO_systemFailure	25
#define CMP_PKIFAILUREINFO_duplicateCertReq	26
#define CMP_PKIFAILUREINFO_MAX					26
typedef ASN1_BIT_STRING CMP_PKIFAILUREINFO;

#define CMP_CTX_FAILINFO_badAlg				 (1 << 0)
#define CMP_CTX_FAILINFO_badMessageCheck	 (1 << 1)
#define CMP_CTX_FAILINFO_badRequest			 (1 << 2)
#define CMP_CTX_FAILINFO_badTime			 (1 << 3)
#define CMP_CTX_FAILINFO_badCertId			 (1 << 4)
#define CMP_CTX_FAILINFO_badDataFormat		 (1 << 5)
#define CMP_CTX_FAILINFO_wrongAuthority		 (1 << 6)
#define CMP_CTX_FAILINFO_incorrectData		 (1 << 7)
#define CMP_CTX_FAILINFO_missingTimeStamp	 (1 << 8)
#define CMP_CTX_FAILINFO_badPOP				 (1 << 9)
#define CMP_CTX_FAILINFO_certRevoked		 (1 << 10)
#define CMP_CTX_FAILINFO_certConfirmed		 (1 << 11)
#define CMP_CTX_FAILINFO_wrongIntegrity		 (1 << 12)
#define CMP_CTX_FAILINFO_badRecipientNonce	 (1 << 13)
#define CMP_CTX_FAILINFO_timeNotAvailable	 (1 << 14)
#define CMP_CTX_FAILINFO_unacceptedPolicy	 (1 << 15)
#define CMP_CTX_FAILINFO_unacceptedExtension (1 << 16)
#define CMP_CTX_FAILINFO_addInfoNotAvailable (1 << 17)
#define CMP_CTX_FAILINFO_badSenderNonce		 (1 << 18)
#define CMP_CTX_FAILINFO_badCertTemplate	 (1 << 19)
#define CMP_CTX_FAILINFO_signerNotTrusted	 (1 << 20)
#define CMP_CTX_FAILINFO_transactionIdInUse  (1 << 21)
#define CMP_CTX_FAILINFO_unsupportedVersion  (1 << 22)
#define CMP_CTX_FAILINFO_notAuthorized		 (1 << 23)
#define CMP_CTX_FAILINFO_systemUnavail		 (1 << 24)
#define CMP_CTX_FAILINFO_systemFailure		 (1 << 25)
#define CMP_CTX_FAILINFO_duplicateCertReq	 (1 << 26)

/*
	 PKIStatus ::= INTEGER {
		 accepted				 (0),
		 -- you got exactly what you asked for
		 grantedWithMods		(1),
		 -- you got something like what you asked for; the
		 -- requester is responsible for ascertaining the differences
		 rejection				(2),
		 -- you don't get it, more information elsewhere in the message
		 waiting				(3),
		 -- the request body part has not yet been processed; expect to
		 -- hear more later (note: proper handling of this status
		 -- response MAY use the polling req/rep PKIMessages specified
		 -- in Section 5.3.22; alternatively, polling in the underlying
		 -- transport layer MAY have some utility in this regard)
		 revocationWarning		(4),
		 -- this message contains a warning that a revocation is
		 -- imminent
		 revocationNotification (5),
		 -- notification that a revocation has occurred
		 keyUpdateWarning		(6)
		 -- update already done for the oldCertId specified in
		 -- CertReqMsg
	 }
	 */
#define CMP_PKISTATUS_accepted			0
#define CMP_PKISTATUS_grantedWithMods		1
#define CMP_PKISTATUS_rejection			2
#define CMP_PKISTATUS_waiting			3
#define CMP_PKISTATUS_revocationWarning		4
#define CMP_PKISTATUS_revocationNotification	5
#define CMP_PKISTATUS_keyUpdateWarning		6

typedef ASN1_INTEGER CMP_PKISTATUS;
DECLARE_ASN1_FUNCTIONS(CMP_PKISTATUS)



/*
	 CertOrEncCert ::= CHOICE {
		 certificate	 [0] CMPCertificate,
		 encryptedCert	 [1] EncryptedValue
	 }
	 */
#define CMP_CERTORENCCERT_CERTIFICATE	0
#define CMP_CERTORENCCERT_ENCRYPTEDCERT 1
typedef struct cmp_certorenccert_st
{
	int type;
	union{
		//CMP_CMPCERTIFICATE  *certificate;
		X509  *certificate;
		CRMF_ENCRYPTEDVALUE *encryptedCert;
	} value;
} CMP_CERTORENCCERT;
DECLARE_ASN1_FUNCTIONS(CMP_CERTORENCCERT)
/*
	 CertifiedKeyPair ::= SEQUENCE {
		 certOrEncCert		 CertOrEncCert,
		 privateKey		 [0] EncryptedValue		 OPTIONAL,
		 -- see [CRMF] for comment on encoding
		 publicationInfo [1] PKIPublicationInfo  OPTIONAL
	 }
	 */
typedef struct cmp_certifiedkeypair_st
{
	CMP_CERTORENCCERT		*certOrEncCert;
	CRMF_ENCRYPTEDVALUE		*privateKey;
	CRMF_PKIPUBLICATIONINFO *failInfo;
} CMP_CERTIFIEDKEYPAIR;
DECLARE_ASN1_FUNCTIONS(CMP_CERTIFIEDKEYPAIR)




/*
	 PKIStatusInfo ::= SEQUENCE {
		 status		   PKIStatus,
		 statusString  PKIFreeText	   OPTIONAL,
		 failInfo	   PKIFailureInfo  OPTIONAL
	 }
	 */

typedef struct cmp_pkistatusinfo_st
{
	CMP_PKISTATUS	   *status;
#if 0
	CMP_PKIFREETEXT    *statusString;
#endif
	STACK_OF(ASN1_UTF8STRING)	 *statusString;
	CMP_PKIFAILUREINFO *failInfo;
} CMP_PKISTATUSINFO;
DECLARE_ASN1_FUNCTIONS(CMP_PKISTATUSINFO)
DECLARE_STACK_OF(CMP_PKISTATUSINFO)

/*
	 RevReqContent ::= SEQUENCE OF RevDetails

	 RevDetails ::= SEQUENCE {
		 certDetails		 CertTemplate,
		 -- allows requester to specify as much as they can about
		 -- the cert. for which revocation is requested
		 -- (e.g., for cases in which serialNumber is not available)
		 crlEntryDetails	 Extensions		  OPTIONAL
		 -- requested crlEntryExtensions
	 }
*/

typedef struct cmp_revdetails_st
{
	CRMF_CERTTEMPLATE		 *certDetails;
	X509_EXTENSIONS			 *crlEntryDetails;
} CMP_REVDETAILS;
DECLARE_ASN1_FUNCTIONS(CMP_REVDETAILS)
DECLARE_STACK_OF(CMP_REVDETAILS)


/*
	 RevRepContent ::= SEQUENCE {
		 status		  SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
		 -- in same order as was sent in RevReqContent
		 revCerts [0] SEQUENCE SIZE (1..MAX) OF CertId
											 OPTIONAL,
		 -- IDs for which revocation was requested
		 -- (same order as status)
		 crls	  [1] SEQUENCE SIZE (1..MAX) OF CertificateList
											 OPTIONAL
		 -- the resulting CRLs (there may be more than one)
	 }
	 */

typedef struct cmp_revrep_st
{
	STACK_OF(CMP_PKISTATUSINFO) *status;
	STACK_OF(CRMF_CERTID)		*certId;
	STACK_OF(X509)				*crls;
} CMP_REVREPCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_REVREPCONTENT)


/*
	 KeyRecRepContent ::= SEQUENCE {
		 status					 PKIStatusInfo,
		 newSigCert			 [0] CMPCertificate OPTIONAL,
		 caCerts			 [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate OPTIONAL,
		 keyPairHist		 [2] SEQUENCE SIZE (1..MAX) OF CertifiedKeyPair OPTIONAL
	 }
*/
typedef struct cmp_keyrecrepcontent_st
{
	CMP_PKISTATUSINFO		*status;
	/* CMP_CMPCERTIFICATE is effectively X509 so it is used directly */
	X509					*newSigCert;
	/* CMP_CMPCERTIFICATE is effectively X509 so it is used directly */
	STACK_OF(X509)			*caCerts;
	STACK_OF(CMP_CERTIFIEDKEYPAIR) *keyPairHist;
} CMP_KEYRECREPCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_KEYRECREPCONTENT)


/*
	 ErrorMsgContent ::= SEQUENCE {
		 pKIStatusInfo			PKIStatusInfo,
		 errorCode				INTEGER			  OPTIONAL,
		 -- implementation-specific error codes
		 errorDetails			PKIFreeText		  OPTIONAL
		 -- implementation-specific error details
	 }
	 */
typedef struct cmp_errormsgcontent_st
{
	CMP_PKISTATUSINFO *pKIStatusInfo;
	ASN1_INTEGER	  *errorCode;
	STACK_OF(ASN1_UTF8STRING)	*errorDetails;
#if 0
	CMP_PKIFREETEXT   *errorDetails;
#endif
} CMP_ERRORMSGCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_ERRORMSGCONTENT)


/*
	 CertConfirmContent ::= SEQUENCE OF CertStatus

	 CertStatus ::= SEQUENCE {
		certHash	OCTET STRING,
		-- the hash of the certificate, using the same hash algorithm
		-- as is used to create and verify the certificate signature
		certReqId	INTEGER,
		-- to match this confirmation with the corresponding req/rep
		statusInfo	PKIStatusInfo OPTIONAL
	 }
	 */
typedef struct cmp_certstatus_st
{
	ASN1_OCTET_STRING	*certHash;
	ASN1_INTEGER		*certReqId;
	CMP_PKISTATUSINFO	*statusInfo;
} CMP_CERTSTATUS;
DECLARE_STACK_OF(CMP_CERTSTATUS)
DECLARE_ASN1_SET_OF(CMP_CERTSTATUS)
DECLARE_ASN1_FUNCTIONS(CMP_CERTSTATUS)

typedef STACK_OF(CMP_CERTSTATUS) CMP_CERTCONFIRMCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_CERTCONFIRMCONTENT)

/*
	 CertResponse ::= SEQUENCE {
		 certReqId			 INTEGER,
		 -- to match this response with corresponding request (a value
		 -- of -1 is to be used if certReqId is not specified in the
		 -- corresponding request)
		 status				 PKIStatusInfo,
		 certifiedKeyPair	 CertifiedKeyPair	 OPTIONAL,
		 rspInfo			 OCTET STRING		 OPTIONAL
		 -- analogous to the id-regInfo-utf8Pairs string defined
		 -- for regInfo in CertReqMsg [CRMF]
	 }
*/
typedef struct cmp_certresponse_st
{
	ASN1_INTEGER		 *certReqId;
	CMP_PKISTATUSINFO	 *status;
	CMP_CERTIFIEDKEYPAIR *certifiedKeyPair;
	ASN1_OCTET_STRING	 *rspInfo;
} CMP_CERTRESPONSE;
DECLARE_ASN1_FUNCTIONS(CMP_CERTRESPONSE)
DECLARE_STACK_OF(CMP_CERTRESPONSE)

/*
	 CertRepMessage ::= SEQUENCE {
		 caPubs		  [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
						  OPTIONAL,
		 response		  SEQUENCE OF CertResponse
	 }
*/
typedef struct cmp_certrepmessage_st
{
	// STACK_OF(CMP_CMPCERTIFICATE) *caPubs;
	STACK_OF(X509) *caPubs;
	STACK_OF(CMP_CERTRESPONSE)	 *response;
} CMP_CERTREPMESSAGE;
DECLARE_ASN1_FUNCTIONS(CMP_CERTREPMESSAGE)

/* the following is from RFC 2986 - PKCS #10

Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
	type	ATTRIBUTE.&id({IOSet}),
	values	SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
}

CertificationRequestInfo ::= SEQUENCE {
	version		  INTEGER { v1(0) } (v1,...),
	subject		  Name,
	subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
	attributes	  [0] Attributes{{ CRIAttributes }}
}

CertificationRequest ::= SEQUENCE {
	certificationRequestInfo CertificationRequestInfo,
	signatureAlgorithm		 AlgorithmIdentifier{{ SignatureAlgorithms }},
	signature				 BIT STRING
}
*/

typedef struct pkcs10_attribute_st
{
	ASN1_OBJECT			*id;
	STACK_OF(ASN1_TYPE) *values;
} PKCS10_ATTRIBUTE;
DECLARE_ASN1_FUNCTIONS(PKCS10_ATTRIBUTE)
DECLARE_STACK_OF(PKCS10_ATTRIBUTE)

typedef struct pkcs10_certificationrequestinfo_st
{
	ASN1_INTEGER			   *version;
	X509_NAME				   *subject;
	X509_PUBKEY				   *subjectPKInfo;
	STACK_OF(PKCS10_ATTRIBUTE) attributes;
} PKCS10_CERTIFICATIONREQUESTINFO;
DECLARE_ASN1_FUNCTIONS(PKCS10_CERTIFICATIONREQUESTINFO)

typedef struct pkcs10_certificationrequest_st
{
	PKCS10_CERTIFICATIONREQUESTINFO *certificationRequestInfo;
	X509_ALGOR						*signatureAlgorithm;
	ASN1_BIT_STRING					*signature;
} PKCS10_CERTIFICATIONREQUEST;
DECLARE_ASN1_FUNCTIONS(PKCS10_CERTIFICATIONREQUEST)

/*
	 PKIBody ::= CHOICE {		-- message-specific body elements
		 ir		  [0]  CertReqMessages,		   --Initialization Request
		 ip		  [1]  CertRepMessage,		   --Initialization Response
		 cr		  [2]  CertReqMessages,		   --Certification Request
		 cp		  [3]  CertRepMessage,		   --Certification Response
		 p10cr	  [4]  CertificationRequest,   --imported from [PKCS10]
		 popdecc  [5]  POPODecKeyChallContent, --pop Challenge
		 popdecr  [6]  POPODecKeyRespContent,  --pop Response
		 kur	  [7]  CertReqMessages,		   --Key Update Request
		 kup	  [8]  CertRepMessage,		   --Key Update Response
		 krr	  [9]  CertReqMessages,		   --Key Recovery Request
		 krp	  [10] KeyRecRepContent,	   --Key Recovery Response
		 rr		  [11] RevReqContent,		   --Revocation Request
		 rp		  [12] RevRepContent,		   --Revocation Response
		 ccr	  [13] CertReqMessages,		   --Cross-Cert. Request
		 ccp	  [14] CertRepMessage,		   --Cross-Cert. Response
		 ckuann   [15] CAKeyUpdAnnContent,	   --CA Key Update Ann.
		 cann	  [16] CertAnnContent,		   --Certificate Ann.
		 rann	  [17] RevAnnContent,		   --Revocation Ann.
		 crlann   [18] CRLAnnContent,		   --CRL Announcement
		 pkiconf  [19] PKIConfirmContent,	   --Confirmation
		 nested   [20] NestedMessageContent,   --Nested Message
		 genm	  [21] GenMsgContent,		   --General Message
		 genp	  [22] GenRepContent,		   --General Response
		 error	  [23] ErrorMsgContent,		   --Error Message
		 certConf [24] CertConfirmContent,	   --Certificate confirm
		 pollReq  [25] PollReqContent,		   --Polling request
		 pollRep  [26] PollRepContent		   --Polling response
*/

/*

	 PKIProtection ::= BIT STRING

	 PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage

	  PKIMessage ::= SEQUENCE {
		 header			  PKIHeader,
		 body			  PKIBody,
		 protection   [0] PKIProtection OPTIONAL,
		 extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
						  OPTIONAL
	 }

*/

/*
	 PKIHeader ::= SEQUENCE {
		 pvno				 INTEGER	 { cmp1999(1), cmp2000(2) },
		 sender				 GeneralName,
		 -- identifies the sender
		 recipient			 GeneralName,
		 -- identifies the intended recipient
		 messageTime	 [0] GeneralizedTime		 OPTIONAL,
		 -- time of production of this message (used when sender
		 -- believes that the transport will be "suitable"; i.e.,
		 -- that the time will still be meaningful upon receipt)
		 protectionAlg	 [1] AlgorithmIdentifier	 OPTIONAL,
		 -- algorithm used for calculation of protection bits
		 senderKID		 [2] KeyIdentifier			 OPTIONAL,
		 recipKID		 [3] KeyIdentifier			 OPTIONAL,
		 -- to identify specific keys used for protection
		 transactionID	 [4] OCTET STRING			 OPTIONAL,
		 -- identifies the transaction; i.e., this will be the same in
		 -- corresponding request, response, certConf, and PKIConf
		 -- messages
		 senderNonce	 [5] OCTET STRING			 OPTIONAL,
		 recipNonce		 [6] OCTET STRING			 OPTIONAL,
		 -- nonces used to provide replay protection, senderNonce
		 -- is inserted by the creator of this message; recipNonce
		 -- is a nonce previously inserted in a related message by
		 -- the intended recipient of this message
		 freeText		 [7] PKIFreeText			 OPTIONAL,
		 -- this may be used to indicate context-specific instructions
		 -- (this field is intended for human consumption)
		 generalInfo	 [8] SEQUENCE SIZE (1..MAX) OF
								InfoTypeAndValue	 OPTIONAL
		 -- this may be used to convey context-specific information
		 -- (this field not primarily intended for human consumption)
	 }
*/

typedef struct cmp_pollreq_st {
	ASN1_INTEGER *certReqId;
} CMP_POLLREQ;
DECLARE_ASN1_FUNCTIONS(CMP_POLLREQ)
DECLARE_STACK_OF(CMP_POLLREQ)

typedef struct cmp_pollrep_st {
	ASN1_INTEGER *certReqId;
	ASN1_INTEGER *checkAfter;
	STACK_OF(ASN1_UTF8STRING) *reason;
} CMP_POLLREP;
DECLARE_ASN1_FUNCTIONS(CMP_POLLREP)
DECLARE_STACK_OF(CMP_POLLREP)

typedef struct cmp_pkiheader_st
{
	ASN1_INTEGER				  *pvno;
	GENERAL_NAME				  *sender;
	GENERAL_NAME				  *recipient;
	ASN1_GENERALIZEDTIME		  *messageTime;    /* 0 */
	X509_ALGOR					  *protectionAlg;  /* 1 */
	ASN1_OCTET_STRING			  *senderKID;	   /* 2 */
	ASN1_OCTET_STRING			  *recipKID;	   /* 3 */
	ASN1_OCTET_STRING			  *transactionID;  /* 4 */
	ASN1_OCTET_STRING			  *senderNonce;    /* 5 */
	ASN1_OCTET_STRING			  *recipNonce;	   /* 6 */
	STACK_OF(ASN1_UTF8STRING)	  *freeText;	   /* 7 */
	STACK_OF(CMP_INFOTYPEANDVALUE) *generalInfo;	/* 8 */
} CMP_PKIHEADER;
DECLARE_ASN1_FUNCTIONS(CMP_PKIHEADER)

	/*
	 InfoTypeAndValue ::= SEQUENCE {
		 infoType				OBJECT IDENTIFIER,
		 infoValue				ANY DEFINED BY infoType  OPTIONAL
	 }
	 */


#define V_CMP_PKIBODY_IR	0
#define V_CMP_PKIBODY_IP	1
#define V_CMP_PKIBODY_CR	2
#define V_CMP_PKIBODY_CP	3
#define V_CMP_PKIBODY_P10CR	4
#define V_CMP_PKIBODY_POPDECC	5
#define V_CMP_PKIBODY_POPDECR	6
#define V_CMP_PKIBODY_KUR	7
#define V_CMP_PKIBODY_KUP	8
#define V_CMP_PKIBODY_KRR	9
#define V_CMP_PKIBODY_KRP	10
#define V_CMP_PKIBODY_RR	11
#define V_CMP_PKIBODY_RP	12
#define V_CMP_PKIBODY_CCR	13
#define V_CMP_PKIBODY_CCP	14
#define V_CMP_PKIBODY_CKUANN	15
#define V_CMP_PKIBODY_CANN	16
#define V_CMP_PKIBODY_RANN	17
#define V_CMP_PKIBODY_CRLANN	18
#define V_CMP_PKIBODY_PKICONF	19
#define V_CMP_PKIBODY_NESTED	20
#define V_CMP_PKIBODY_GENM	21
#define V_CMP_PKIBODY_GENP	22
#define V_CMP_PKIBODY_ERROR	23
#define V_CMP_PKIBODY_CERTCONF	24
#define V_CMP_PKIBODY_POLLREQ	25
#define V_CMP_PKIBODY_POLLREP	26

typedef STACK_OF(CMP_CHALLENGE) CMP_POPODECKEYCHALLCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_POPODECKEYCHALLCONTENT)

typedef STACK_OF(ASN1_INTEGER) CMP_POPODECKEYRESPCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_POPODECKEYRESPCONTENT)

typedef STACK_OF(CMP_REVDETAILS) CMP_REVREQCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_REVREQCONTENT)

typedef STACK_OF(X509_CRL) CMP_CRLANNCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_CRLANNCONTENT)

typedef STACK_OF(CMP_INFOTYPEANDVALUE) CMP_GENMSGCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_GENMSGCONTENT)

typedef STACK_OF(CMP_INFOTYPEANDVALUE) CMP_GENREPCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_GENREPCONTENT)

typedef STACK_OF(CMP_POLLREQ) CMP_POLLREQCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_POLLREQCONTENT)

typedef STACK_OF(CMP_POLLREP) CMP_POLLREPCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_POLLREPCONTENT)

typedef struct cmp_pkibody_st
{
	int type;
	union{
		CRMF_CERTREQMESSAGES   *ir;   /* 0 */
		CMP_CERTREPMESSAGE			*ip;   /* 1 */
		CRMF_CERTREQMESSAGES   *cr;   /* 2 */
		CMP_CERTREPMESSAGE			*cp;   /* 3 */
		/* p10cr	[4]  CertificationRequest,	 --imported from [PKCS10] */
		PKCS10_CERTIFICATIONREQUEST *p10cr;   /* 4 */
		/* popdecc	[5]  POPODecKeyChallContent, --pop Challenge */
	/* POPODecKeyChallContent ::= SEQUENCE OF Challenge */
		CMP_POPODECKEYCHALLCONTENT *popdecc; /* 5 */
	/* popdecr	[6]  POPODecKeyRespContent,  --pop Response */
	/* POPODecKeyRespContent ::= SEQUENCE OF INTEGER */
		CMP_POPODECKEYRESPCONTENT  *popdecr; /* 6 */
		CRMF_CERTREQMESSAGES   *kur;   /* 7 */
		CMP_CERTREPMESSAGE			*kup;	/* 8 */
		CRMF_CERTREQMESSAGES   *krr;   /* 9 */

	/* krp		[10] KeyRecRepContent,		 --Key Recovery Response */
		CMP_KEYRECREPCONTENT		*krp;	/* 10 */
		/* rr		[11] RevReqContent,			 --Revocation Request */
		CMP_REVREQCONTENT	 *rr; /* 11 */
		/* rp		[12] RevRepContent,			 --Revocation Response */
		CMP_REVREPCONTENT	*rp; /* 12 */
		/* ccr		[13] CertReqMessages,		 --Cross-Cert. Request */
		CRMF_CERTREQMESSAGES   *ccr; /* 13 */
		/* ccp		[14] CertRepMessage,		 --Cross-Cert. Response */
		CMP_CERTREPMESSAGE			*ccp; /* 14 */
		/* ckuann	[15] CAKeyUpdAnnContent,	 --CA Key Update Ann. */
		CMP_CAKEYUPDANNCONTENT	 *ckuann; /* 15 */
	/* cann		[16] CertAnnContent,		 --Certificate Ann. */
	/* CMP_CMPCERTIFICATE is effectively X509 so it is used directly */
		X509					   *cann; /* 16 */
		/* rann		[17] RevAnnContent,			 --Revocation Ann. */
		CMP_REVANNCONTENT		   *rann; /* 17 */
		/* crlann	[18] CRLAnnContent,			 --CRL Announcement */
		/* CRLAnnContent ::= SEQUENCE OF CertificateList */
		CMP_CRLANNCONTENT		  *crlann;
		/* pkiconf	[19] PKIConfirmContent,		 --Confirmation */
	/* CMP_PKICONFIRMCONTENT would be only a typedfef of ASN1_NULL */
	/* CMP_CONFIRMCONTENT *pkiconf; */
		/* this should ASN1_NULL according to the RFC but there might be a struct in it */
		ASN1_TYPE						*pkiconf; /* 19 */
		/* nested	[20] NestedMessageContent,	 --Nested Message */
		/* NestedMessageContent ::= PKIMessages */
		CMP_PKIMESSAGES				   *nested; /* 20 */
		/* genm		[21] GenMsgContent,			 --General Message */
		/* GenMsgContent ::= SEQUENCE OF InfoTypeAndValue */
		CMP_GENMSGCONTENT *genm; /* 21 */
		/* genp		[22] GenRepContent,			 --General Response */
	/* GenRepContent ::= SEQUENCE OF InfoTypeAndValue */
		CMP_GENREPCONTENT *genp; /* 22 */
		/* error	[23] ErrorMsgContent,		 --Error Message */
		CMP_ERRORMSGCONTENT			   *error;	  /* 23 */
		/* certConf [24] CertConfirmContent,	 --Certificate confirm */
		CMP_CERTCONFIRMCONTENT		   *certConf; /* 24 */
		/* pollReq	[25] PollReqContent,		 --Polling request */
		CMP_POLLREQCONTENT			*pollReq;
		/* pollRep	[26] PollRepContent			 --Polling response */
		CMP_POLLREPCONTENT			 *pollRep;
	} value;
} CMP_PKIBODY;
DECLARE_ASN1_FUNCTIONS(CMP_PKIBODY)

typedef struct cmp_pkimessage_st
{
	CMP_PKIHEADER				 *header;
	CMP_PKIBODY					 *body;
	ASN1_BIT_STRING				 *protection; /* 0 */
	/* CMP_CMPCERTIFICATE is effectively X509 so it is used directly */
	STACK_OF(X509) *extraCerts; /* 1 */
} CMP_PKIMESSAGE;
DECLARE_ASN1_FUNCTIONS(CMP_PKIMESSAGE)
DECLARE_STACK_OF(CMP_PKIMESSAGE) /* PKIMessages */

/*
	 ProtectedPart ::= SEQUENCE {
		 header    PKIHeader,
		 body	   PKIBody
	 }
	 */
typedef struct cmp_protectedpart_st
{
	CMP_PKIHEADER				 *header;
	CMP_PKIBODY					 *body;
} CMP_PROTECTEDPART;
DECLARE_ASN1_FUNCTIONS(CMP_PROTECTEDPART)


/*
Appendix F.  Compilable ASN.1 Definitions

	 PKIXCMP {iso(1) identified-organization(3)
		   dod(6) internet(1) security(5) mechanisms(5) pkix(7)
		   id-mod(0) id-mod-cmp2000(16)}

	 DEFINITIONS EXPLICIT TAGS ::=

	 BEGIN

	 -- EXPORTS ALL --

	 IMPORTS

		 Certificate, CertificateList, Extensions, AlgorithmIdentifier,
		 UTF8String -- if required; otherwise, comment out
				FROM PKIX1Explicit88 {iso(1) identified-organization(3)
				dod(6) internet(1) security(5) mechanisms(5) pkix(7)
				id-mod(0) id-pkix1-explicit-88(1)}

		 GeneralName, KeyIdentifier
				FROM PKIX1Implicit88 {iso(1) identified-organization(3)
				dod(6) internet(1) security(5) mechanisms(5) pkix(7)
				id-mod(0) id-pkix1-implicit-88(2)}

		 CertTemplate, PKIPublicationInfo, EncryptedValue, CertId,
		 CertReqMessages
				FROM PKIXCRMF-2005 {iso(1) identified-organization(3)
				dod(6) internet(1) security(5) mechanisms(5) pkix(7)
				id-mod(0) id-mod-crmf2005(36)}

		 -- see also the behavioral clarifications to CRMF codified in
		 -- Appendix C of this specification

		 CertificationRequest
				FROM PKCS-10 {iso(1) member-body(2)
							  us(840) rsadsi(113549)
							  pkcs(1) pkcs-10(10) modules(1) pkcs-10(1)}

		 -- (specified in RFC 2986 with 1993 ASN.1 syntax and IMPLICIT
		 -- tags).	Alternatively, implementers may directly include
		 -- the [PKCS10] syntax in this module




Adams, et al.				Standards Track					   [Page 83]

RFC 4210						  CMP					  September 2005


		 ;

   -- the rest of the module contains locally-defined OIDs and
   -- constructs

   -- This syntax, while bits-on-the-wire compatible with the
   -- standard X.509 definition of "Certificate", allows the
   -- possibility of future certificate types (such as X.509
   -- attribute certificates, WAP WTLS certificates, or other kinds
   -- of certificates) within this certificate management protocol,
   -- should a need ever arise to support such generality.	Those
   -- implementations that do not foresee a need to ever support
   -- other certificate types MAY, if they wish, comment out the
   -- above structure and "un-comment" the following one prior to
   -- compiling this ASN.1 module.	(Note that interoperability
   -- with implementations that dont do this will be unaffected by
   -- this change.)

   -- CMPCertificate ::= Certificate





Adams, et al.				Standards Track					   [Page 84]

RFC 4210						  CMP					  September 2005






Adams, et al.				Standards Track					   [Page 85]

RFC 4210						  CMP					  September 2005


		 genp	  [22] GenRepContent,		   --General Response
		 error	  [23] ErrorMsgContent,		   --Error Message
		 certConf [24] CertConfirmContent,	   --Certificate confirm
		 pollReq  [25] PollReqContent,		   --Polling request
		 pollRep  [26] PollRepContent		   --Polling response
	 }


	 id-PasswordBasedMac OBJECT IDENTIFIER ::= {1 2 840 113533 7 66 13}
	 PBMParameter ::= SEQUENCE {
		 salt				 OCTET STRING,
		 -- note:  implementations MAY wish to limit acceptable sizes
		 -- of this string to values appropriate for their environment
		 -- in order to reduce the risk of denial-of-service attacks
		 owf				 AlgorithmIdentifier,
		 -- AlgId for a One-Way Function (SHA-1 recommended)
		 iterationCount		 INTEGER,
		 -- number of times the OWF is applied
		 -- note:  implementations MAY wish to limit acceptable sizes
		 -- of this integer to values appropriate for their environment
		 -- in order to reduce the risk of denial-of-service attacks
		 mac				 AlgorithmIdentifier
		 -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
	 }	 -- or HMAC [RFC2104, RFC2202])

	 id-DHBasedMac OBJECT IDENTIFIER ::= {1 2 840 113533 7 66 30}
	 DHBMParameter ::= SEQUENCE {
		 owf				 AlgorithmIdentifier,
		 -- AlgId for a One-Way Function (SHA-1 recommended)
		 mac				 AlgorithmIdentifier
		 -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
	 }	 -- or HMAC [RFC2104, RFC2202])






	 OOBCert ::= CMPCertificate

	 OOBCertHash ::= SEQUENCE {
		 hashAlg	 [0] AlgorithmIdentifier	 OPTIONAL,
		 certId		 [1] CertId					 OPTIONAL,
		 hashVal		 BIT STRING



Adams, et al.				Standards Track					   [Page 88]

RFC 4210						  CMP					  September 2005


		 -- hashVal is calculated over the DER encoding of the
		 -- self-signed certificate with the identifier certID.
	 }






	 RevRepContent ::= SEQUENCE {
		 status		  SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
		 -- in same order as was sent in RevReqContent
		 revCerts [0] SEQUENCE SIZE (1..MAX) OF CertId
											 OPTIONAL,
		 -- IDs for which revocation was requested
		 -- (same order as status)
		 crls	  [1] SEQUENCE SIZE (1..MAX) OF CertificateList
											 OPTIONAL



Adams, et al.				Standards Track					   [Page 90]

RFC 4210						  CMP					  September 2005


		 -- the resulting CRLs (there may be more than one)
	 }






	 PKIConfirmContent ::= NULL

	 -- Example InfoTypeAndValue contents include, but are not limited
	 -- to, the following (un-comment in this ASN.1 module and use as
	 -- appropriate for a given environment):
	 --
	 --   id-it-caProtEncCert	 OBJECT IDENTIFIER ::= {id-it 1}
	 --		 CAProtEncCertValue		 ::= CMPCertificate
	 --   id-it-signKeyPairTypes OBJECT IDENTIFIER ::= {id-it 2}
	 --		 SignKeyPairTypesValue	 ::= SEQUENCE OF AlgorithmIdentifier
	 --   id-it-encKeyPairTypes  OBJECT IDENTIFIER ::= {id-it 3}



Adams, et al.				Standards Track					   [Page 91]

RFC 4210						  CMP					  September 2005


	 --		 EncKeyPairTypesValue	 ::= SEQUENCE OF AlgorithmIdentifier
	 --   id-it-preferredSymmAlg OBJECT IDENTIFIER ::= {id-it 4}
	 --		 PreferredSymmAlgValue	 ::= AlgorithmIdentifier
	 --   id-it-caKeyUpdateInfo  OBJECT IDENTIFIER ::= {id-it 5}
	 --		 CAKeyUpdateInfoValue	 ::= CAKeyUpdAnnContent
	 --   id-it-currentCRL		 OBJECT IDENTIFIER ::= {id-it 6}
	 --		 CurrentCRLValue		 ::= CertificateList
	 --   id-it-unsupportedOIDs  OBJECT IDENTIFIER ::= {id-it 7}
	 --		 UnsupportedOIDsValue	 ::= SEQUENCE OF OBJECT IDENTIFIER
	 --   id-it-keyPairParamReq  OBJECT IDENTIFIER ::= {id-it 10}
	 --		 KeyPairParamReqValue	 ::= OBJECT IDENTIFIER
	 --   id-it-keyPairParamRep  OBJECT IDENTIFIER ::= {id-it 11}
	 --		 KeyPairParamRepValue	 ::= AlgorithmIdentifer
	 --   id-it-revPassphrase	 OBJECT IDENTIFIER ::= {id-it 12}
	 --		 RevPassphraseValue		 ::= EncryptedValue
	 --   id-it-implicitConfirm  OBJECT IDENTIFIER ::= {id-it 13}
	 --		 ImplicitConfirmValue	 ::= NULL
	 --   id-it-confirmWaitTime  OBJECT IDENTIFIER ::= {id-it 14}
	 --		 ConfirmWaitTimeValue	 ::= GeneralizedTime
	 --   id-it-origPKIMessage	 OBJECT IDENTIFIER ::= {id-it 15}
	 --		 OrigPKIMessageValue	 ::= PKIMessages
	 --   id-it-suppLangTags	 OBJECT IDENTIFIER ::= {id-it 16}
	 --		 SuppLangTagsValue		 ::= SEQUENCE OF UTF8String
	 --
	 -- where
	 --
	 --   id-pkix OBJECT IDENTIFIER ::= {
	 --		 iso(1) identified-organization(3)
	 --		 dod(6) internet(1) security(5) mechanisms(5) pkix(7)}
	 -- and
	 --   id-it   OBJECT IDENTIFIER ::= {id-pkix 4}
	 --
	 --
	 -- This construct MAY also be used to define new PKIX Certificate
	 -- Management Protocol request and response messages, or general-
	 -- purpose (e.g., announcement) messages for future needs or for
	 -- specific environments.


	 -- May be sent by EE, RA, or CA (depending on message content).
	 -- The OPTIONAL infoValue parameter of InfoTypeAndValue will
	 -- typically be omitted for some of the examples given above.
	 -- The receiver is free to ignore any contained OBJ. IDs that it
	 -- does not recognize. If sent from EE to CA, the empty set
	 -- indicates that the CA may send
	 -- any/all information that it wishes.




Adams, et al.				Standards Track					   [Page 92]

RFC 4210						  CMP					  September 2005



	 PollReqContent ::= SEQUENCE OF SEQUENCE {
		 certReqId				INTEGER
	 }

	 PollRepContent ::= SEQUENCE OF SEQUENCE {
		 certReqId				INTEGER,
		 checkAfter				INTEGER,  -- time in seconds
		 reason					PKIFreeText OPTIONAL
	 }


	 END -- of CMP module
*/

typedef void (*cmp_logfn_t)(const char *msg);
typedef int (*cmp_certConfFn_t)(int status, const X509 *cert);


/* CMP_CTX definitions */
/* this structure is used to store the context for CMP sessions */
/* partly in ASN.1 syntax in order to ease storing it in the future */
typedef struct cmp_ctx_st
{
	/* "reference and secret" as described in
	 * 4.2.1.2.  End Entity Message Origin Authentication
	 * this is used for IR Sequence
	 */
	ASN1_OCTET_STRING	 *referenceValue;
	ASN1_OCTET_STRING	 *secretValue;
	ASN1_UTF8STRING		 *regToken;
	/* CA certificate used to identify the CA */
	X509				 *srvCert;
	/* current client certificate used to identify and sign */
	X509				 *clCert;
	/* subject name to be used in the cert template. note: if clcert is set,
	 * subject name is read from there and this is ignored */
	X509_NAME			 *subjectName;
	/* X509_NAME to set in PKIHEADER->recipient */ 
	X509_NAME			 *recipient;
	/* names to be added to the cert template as the subjectAltName extension */
	STACK_OF(GENERAL_NAME) *subjectAltNames;
	/* Stack of CA certificates sent by the CA in a IP message */ 
	STACK_OF(X509)		 *caPubs;
	/* stack of extraCerts to be included when sending a PKI message */
	STACK_OF(X509)		 *extraCertsOut;
	/* stack of extraCerts received from remote */ 
	STACK_OF(X509)		 *extraCertsIn;
	/* EVP_PKEY holding the *current* keys */
	/* Note: this is not an ASN.1 type */
	EVP_PKEY			 *pkey;
	/* *new* CLIENT certificate received from the CA */
	/* XXX this should be a stack since there could be more than one */
	X509				 *newClCert;
	/* EVP_PKEY holding the *new* keys */
	/* Note: this is not an ASN.1 type */
	EVP_PKEY			 *newPkey;
	/* the current transaction ID */
	ASN1_OCTET_STRING	 *transactionID;
	/* last nonce received */
	ASN1_OCTET_STRING	 *recipNonce;
	char	  *serverName;
	int	   serverPort;
	char	  *serverPath;
	char	  *proxyName;
	int	   proxyPort;
#define CMP_TRANSPORT_HTTP	1
#define CMP_TRANSPORT_TCP	2
	int	   transport;
#if 0
	/* this is actually CMP_PKIFREETEXT which is STACK_OF(ANS1_UTF8STRING) */
	STACK_OF(ASN1_UTF8STRING)	   *freeText;
#endif
	int	implicitConfirm;
	/* XXX not setting transactionID test for PKI INFO */
	int	setTransactionID;
	/* XXX not setting senderNonce test for PKI INFO */
	int	setSenderNonce;
	/* if this is enabled, we will try to verify the entire CA certificate until
	 * the trust anchor, and if this fails we reject the message */
	int validatePath;

	/* Proof-of-posession mechanism used. Defaults to signature (POPOsignkingKey) */ 
	int	popoMethod;
	/* maximum time in secods to wait for an http transfer to complete
	 * XXX note: only usable with libcurl! */
	int	timeOut;

	/* maximum number of times we attempt to poll the server for a response 
	 * if a 'waiting' PKIStatus is received*/
	int maxPollCount;

	int lastStatus;

	unsigned long failInfoCode;

	/* log callback functions for error and debug messages */
	cmp_logfn_t error_cb, debug_cb;

	/* callback for letting the user check the received certificate and 
	 * reject if necessary */
	cmp_certConfFn_t certConf_cb;

	/* */
	X509_STORE *trusted_store;
	X509_STORE *untrusted_store;

	/* include root certs from extracerts when validating? */
	int permitTAInExtraCertsForIR;
	X509 *validatedSrvCert;
} CMP_CTX;

DECLARE_ASN1_FUNCTIONS(CMP_CTX)



/* DECLARATIONS */

/* cmp_msg.c */
CMP_PKIMESSAGE *CMP_ir_new( CMP_CTX *ctx);
CMP_PKIMESSAGE *CMP_cr_new( CMP_CTX *ctx);
CMP_PKIMESSAGE *CMP_rr_new( CMP_CTX *ctx);
CMP_PKIMESSAGE *CMP_certConf_new( CMP_CTX *ctx);
CMP_PKIMESSAGE *CMP_kur_new( CMP_CTX *ctx);
CMP_PKIMESSAGE *CMP_genm_new( CMP_CTX *ctx, int nid, char *value);
#if 0
CMP_PKIMESSAGE *CMP_ckuann_new( CMP_CTX *ctx);
#endif
CMP_PKIMESSAGE *CMP_ckuann_new( const X509 *oldCaCert, const EVP_PKEY *oldPkey, const X509 *newCaCert, const EVP_PKEY *newPkey);
CMP_PKIMESSAGE *CMP_pollReq_new( CMP_CTX *ctx, int reqId);
ASN1_OCTET_STRING *CMP_get_subject_key_id(const X509 *cert);

/* cmp_lib.c */

long CMP_REVREPCONTENT_PKIStatus_get(CMP_REVREPCONTENT *revRep, long reqId);
int CMP_PKIHEADER_set_version(CMP_PKIHEADER *hdr, int version);
int CMP_PKIHEADER_set1_recipient(CMP_PKIHEADER *hdr, const X509_NAME *nm);
int CMP_PKIHEADER_set1_sender(CMP_PKIHEADER *hdr, const X509_NAME *nm);
int CMP_PKIHEADER_set1_transactionID(CMP_PKIHEADER *hdr, const ASN1_OCTET_STRING *transactionID);
int CMP_PKIHEADER_set1_recipNonce(CMP_PKIHEADER *hdr, const ASN1_OCTET_STRING *recipNonce);
int CMP_PKIHEADER_set1_senderKID(CMP_PKIHEADER *hdr, const ASN1_OCTET_STRING *senderKID);
int CMP_PKIHEADER_set_messageTime(CMP_PKIHEADER *hdr);
int CMP_PKIMESSAGE_set_implicitConfirm(CMP_PKIMESSAGE *msg);
int CMP_PKIMESSAGE_check_implicitConfirm(CMP_PKIMESSAGE *msg);

int CMP_PKIHEADER_push0_freeText( CMP_PKIHEADER *hdr, ASN1_UTF8STRING *text);
int CMP_PKIHEADER_push1_freeText( CMP_PKIHEADER *hdr, ASN1_UTF8STRING *text);

int CMP_PKIHEADER_set1(CMP_PKIHEADER *hdr, CMP_CTX *ctx);

ASN1_BIT_STRING *CMP_calc_protection_pbmac(CMP_PKIMESSAGE *pkimessage, const ASN1_OCTET_STRING *secret);

int CMP_PKIMESSAGE_protect(CMP_CTX *ctx, CMP_PKIMESSAGE *msg);

int CMP_CERTSTATUS_set_certHash( CMP_CERTSTATUS *certStatus, const X509 *cert);

int CMP_PKIHEADER_generalInfo_item_push0(CMP_PKIHEADER *hdr, const CMP_INFOTYPEANDVALUE *itav);
int CMP_PKIMESSAGE_genm_item_push0(CMP_PKIMESSAGE *msg, const CMP_INFOTYPEANDVALUE *itav);
int CMP_ITAV_stack_item_push0(STACK_OF(CMP_INFOTYPEANDVALUE) **itav_sk_p, const CMP_INFOTYPEANDVALUE *itav);

long CMP_PKISTATUSINFO_PKIstatus_get( CMP_PKISTATUSINFO *statusInfo);

char *CMP_PKISTATUSINFO_PKIFailureInfo_get_string( CMP_PKISTATUSINFO *statusInfo);
char *CMP_ERRORMSGCONTENT_PKIFailureInfo_get_string( CMP_ERRORMSGCONTENT *error);

long CMP_CERTRESPONSE_PKIStatus_get( CMP_CERTRESPONSE *resp);
long CMP_CERTREPMESSAGE_PKIStatus_get( CMP_CERTREPMESSAGE *certRep, long certReqId);

char *CMP_CERTREPMESSAGE_PKIFailureInfoString_get0(CMP_CERTREPMESSAGE *certRep, long certReqId);
STACK_OF(ASN1_UTF8STRING)* CMP_CERTREPMESSAGE_PKIStatusString_get0( CMP_CERTREPMESSAGE *certRep, long certReqId);
CMP_PKIFAILUREINFO *CMP_CERTREPMESSAGE_PKIFailureInfo_get0(CMP_CERTREPMESSAGE *certRep, long certReqId);
X509 *CMP_CERTREPMESSAGE_get_certificate(CMP_CTX *ctx, CMP_CERTREPMESSAGE *certrep);

int CMP_PKIFAILUREINFO_check( ASN1_BIT_STRING *failInfo, int codeBit);

CMP_CERTRESPONSE *CMP_CERTREPMESSAGE_certResponse_get0( CMP_CERTREPMESSAGE *certRep, long certReqId);
X509 *CMP_CERTREPMESSAGE_cert_get0( CMP_CERTREPMESSAGE *certRep, long certReqId);
X509 *CMP_CERTREPMESSAGE_cert_get1( CMP_CERTREPMESSAGE *certRep, long certReqId);

X509 *CMP_CERTREPMESSAGE_encCert_get1( CMP_CERTREPMESSAGE *certRep, long certReqId, EVP_PKEY *pkey);
int CMP_CERTREPMESSAGE_certType_get( CMP_CERTREPMESSAGE *certRep, long certReqId);

int CMP_PKIMESSAGE_set_bodytype( CMP_PKIMESSAGE *msg, int type);
int CMP_PKIMESSAGE_get_bodytype( CMP_PKIMESSAGE *msg);

char *CMP_PKIMESSAGE_parse_error_msg( CMP_PKIMESSAGE *msg, char *errormsg, int bufsize);

STACK_OF(X509) *CMP_build_cert_chain(X509_STORE *store, X509 *cert);

/* cmp_vfy.c */
int CMP_validate_msg(CMP_CTX *ctx, CMP_PKIMESSAGE *msg);

#ifdef HAVE_CURL
typedef CURL CMPBIO;
#else
typedef BIO CMPBIO;
#endif

/* from cmp_http.c */
int CMP_PKIMESSAGE_http_perform(CMPBIO *cbio, const CMP_CTX *ctx, 
								const CMP_PKIMESSAGE *msg,
								CMP_PKIMESSAGE **out);
int CMP_new_http_bio_ex(CMPBIO **cbio, const char* serverName, const int port, const char *srcip);
int CMP_new_http_bio(CMPBIO **cbio, const char* serverName, const int port);
int CMP_delete_http_bio( CMPBIO *cbio);

/* from cmp_ses.c */
X509 *CMP_doInitialRequestSeq( CMPBIO *cbio, CMP_CTX *ctx);
X509 *CMP_doCertificateRequestSeq( CMPBIO *cbio, CMP_CTX *ctx);
int CMP_doRevocationRequestSeq( CMPBIO *cbio, CMP_CTX *ctx);
X509 *CMP_doKeyUpdateRequestSeq( CMPBIO *cbio, CMP_CTX *ctx);
int CMP_doPKIInfoReqSeq( CMPBIO *cbio, CMP_CTX *ctx);
char *CMP_doGeneralMessageSeq( CMPBIO *cbio, CMP_CTX *ctx, int nid, char *value);
CMP_CAKEYUPDANNCONTENT *CMP_doCAKeyUpdateReq( CMPBIO *cbio, CMP_CTX *ctx);
X509_CRL *CMP_doCurrentCRLReq( CMPBIO *cbio, CMP_CTX *ctx);

/* from cmp_ctx.c */
int CMP_CTX_init( CMP_CTX *ctx);
int CMP_CTX_set0_trustedStore( CMP_CTX *ctx, X509_STORE *store);
int CMP_CTX_set0_untrustedStore( CMP_CTX *ctx, X509_STORE *store);
void CMP_CTX_delete(CMP_CTX *ctx);
CMP_CTX *CMP_CTX_create(void);
int CMP_CTX_set_error_callback( CMP_CTX *ctx, cmp_logfn_t cb);
int CMP_CTX_set_debug_callback( CMP_CTX *ctx, cmp_logfn_t cb);
int CMP_CTX_set_certConf_callback( CMP_CTX *ctx, cmp_certConfFn_t cb);
int CMP_CTX_set1_referenceValue( CMP_CTX *ctx, const unsigned char *ref, size_t len);
int CMP_CTX_set1_secretValue( CMP_CTX *ctx, const unsigned char *sec, const size_t len);
int CMP_CTX_set1_regToken( CMP_CTX *ctx, const char *regtoken, const size_t len);
/* for backwards compatibility, TODO: remove asap */
#define CMP_CTX_set1_caCert CMP_CTX_set1_srvCert
int CMP_CTX_set1_srvCert( CMP_CTX *ctx, const X509 *cert);
int CMP_CTX_set1_clCert( CMP_CTX *ctx, const X509 *cert);
int CMP_CTX_set1_subjectName( CMP_CTX *ctx, const X509_NAME *name);
int CMP_CTX_set1_recipient( CMP_CTX *ctx, const X509_NAME *name);
int CMP_CTX_subjectAltName_push1( CMP_CTX *ctx, const GENERAL_NAME *name);
int CMP_CTX_set1_sender( CMP_CTX *ctx, const X509_NAME *name);
X509_NAME* CMP_CTX_sender_get( CMP_CTX *ctx);
STACK_OF(X509)* CMP_CTX_caPubs_get1( CMP_CTX *ctx);
X509 *CMP_CTX_caPubs_pop( CMP_CTX *ctx);
int CMP_CTX_caPubs_num( CMP_CTX *ctx);
int CMP_CTX_set1_caPubs( CMP_CTX *ctx, const STACK_OF(X509) *caPubs);

int CMP_CTX_set1_extraCertsOut( CMP_CTX *ctx, const STACK_OF(X509) *extraCertsOut);
int CMP_CTX_extraCertsOut_push1( CMP_CTX *ctx, const X509 *val);
int CMP_CTX_extraCertsOut_num( CMP_CTX *ctx);
STACK_OF(X509)* CMP_CTX_extraCertsIn_get1( CMP_CTX *ctx);
int CMP_CTX_set1_extraCertsIn( CMP_CTX *ctx, const STACK_OF(X509) *extraCertsIn);
X509 *CMP_CTX_extraCertsIn_pop( CMP_CTX *ctx);
int CMP_CTX_extraCertsIn_num( CMP_CTX *ctx);
int CMP_CTX_loadUntrustedStack(CMP_CTX *ctx, STACK_OF(X509) *stack);

int CMP_CTX_set1_newClCert( CMP_CTX *ctx, const X509 *cert);
int CMP_CTX_set0_pkey( CMP_CTX *ctx, const EVP_PKEY *pkey);
int CMP_CTX_set1_pkey( CMP_CTX *ctx, const EVP_PKEY *pkey);
int CMP_CTX_set0_newPkey( CMP_CTX *ctx, const EVP_PKEY *pkey);
int CMP_CTX_set1_newPkey( CMP_CTX *ctx, const EVP_PKEY *pkey);
int CMP_CTX_set1_transactionID( CMP_CTX *ctx, const ASN1_OCTET_STRING *id);
int CMP_CTX_set1_senderNonce( CMP_CTX *ctx, const ASN1_OCTET_STRING *nonce);
int CMP_CTX_set1_recipNonce( CMP_CTX *ctx, const ASN1_OCTET_STRING *nonce);
int CMP_CTX_set1_serverName( CMP_CTX *ctx, const char *name);
int CMP_CTX_set1_serverPort( CMP_CTX *ctx, int port);
int CMP_CTX_set1_proxyName( CMP_CTX *ctx, const char *name);
int CMP_CTX_set1_proxyPort( CMP_CTX *ctx, int port);
int CMP_CTX_set1_timeOut( CMP_CTX *ctx, int time);
int CMP_CTX_set1_popoMethod( CMP_CTX *ctx, int method);
int CMP_CTX_set1_serverPath( CMP_CTX *ctx, const char *path);
int CMP_CTX_set_failInfoCode(CMP_CTX *ctx, CMP_PKIFAILUREINFO *failInfo);
unsigned long CMP_CTX_failInfoCode_get(CMP_CTX *ctx);
#define CMP_CTX_OPT_UNSET			0
#define CMP_CTX_OPT_SET				1
#define CMP_CTX_OPT_IMPLICITCONFIRM 1
#define CMP_CTX_OPT_POPMETHOD		2
#define CMP_CTX_OPT_VALIDATEPATH	3
#define CMP_CTX_OPT_MAXPOLLCOUNT	4
#define CMP_CTX_PERMIT_TA_IN_EXTRACERTS_FOR_IR 5
int CMP_CTX_set_option( CMP_CTX *ctx, const int opt, const int val);
#if 0
int CMP_CTX_push_freeText( CMP_CTX *ctx, const char *text);
#endif

int CMP_CTX_error_callback(const char *str, size_t len, void *u);

#ifdef HAVE_CURL
long CMP_get_http_code(const CMPBIO *bio);
#endif

/* BIO definitions */
#define d2i_CMP_PKIMESSAGE_bio(bp,p) ASN1_d2i_bio_of(CMP_PKIMESSAGE,CMP_PKIMESSAGE_new,d2i_CMP_PKIMESSAGE,bp,p)
#define i2d_CMP_PKIMESSAGE_bio(bp,o) ASN1_i2d_bio_of(CMP_PKIMESSAGE,i2d_CMP_PKIMESSAGE,bp,o)
#define d2i_CMP_PROTECTEDPART_bio(bp,p) ASN1_d2i_bio_of(CMP_PROTECTEDPART,CMP_PROTECTEDPART_new,d2i_CMP_PROTECTEDPART,bp,p)
#define i2d_CMP_PROTECTEDPART_bio(bp,o) ASN1_i2d_bio_of(CMP_PROTECTEDPART,i2d_CMP_PROTECTEDPART,bp,o)

#define CMP_VERSION 2L

#ifndef CMP_printf
	#ifdef CMP_DEBUG
		void CMP_printf(const CMP_CTX *ctx, const char *fmt, ...);
	#else
		#define CMP_printf(...) //
	#endif
#endif

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_CMP_strings(void);

/* Error codes for the CMP functions. */

/* Function codes. */
#define CMP_F_CERTREP_GET_CERTIFICATE			 162
#define CMP_F_CMP_CALC_PROTECTION_PBMAC			 170
#define CMP_F_CMP_CALC_PROTECTION_SIG			 171
#define CMP_F_CMP_CERTCONF_NEW				 100
#define CMP_F_CMP_CERTREPMESSAGE_ENCCERT_GET1		 101
#define CMP_F_CMP_CERTSTATUS_SET_CERTHASH		 102
#define CMP_F_CMP_CKUANN_NEW				 103
#define CMP_F_CMP_CR_NEW				 104
#define CMP_F_CMP_CTX_CAPUBS_GET1			 105
#define CMP_F_CMP_CTX_CAPUBS_NUM			 106
#define CMP_F_CMP_CTX_CAPUBS_POP			 107
#define CMP_F_CMP_CTX_CREATE				 108
#define CMP_F_CMP_CTX_EXTRACERTSIN_GET1			 109
#define CMP_F_CMP_CTX_EXTRACERTSIN_NUM			 110
#define CMP_F_CMP_CTX_EXTRACERTSIN_POP			 111
#define CMP_F_CMP_CTX_EXTRACERTS_NUM			 112
#define CMP_F_CMP_CTX_EXTRACERTS_PUSH1			 113
#define CMP_F_CMP_CTX_INIT				 114
#define CMP_F_CMP_CTX_SET0_NEWPKEY			 115
#define CMP_F_CMP_CTX_SET0_PKEY				 116
#define CMP_F_CMP_CTX_SET1_CACERT			 117
#define CMP_F_CMP_CTX_SET1_CAEXTRACERTS			 118
#define CMP_F_CMP_CTX_SET1_CAPUBS			 119
#define CMP_F_CMP_CTX_SET1_CLCERT			 120
#define CMP_F_CMP_CTX_SET1_EXTRACERTS			 121
#define CMP_F_CMP_CTX_SET1_EXTRACERTSIN			 172
#define CMP_F_CMP_CTX_SET1_NEWCLCERT			 122
#define CMP_F_CMP_CTX_SET1_NEWPKEY			 123
#define CMP_F_CMP_CTX_SET1_PKEY				 124
#define CMP_F_CMP_CTX_SET1_POPOMETHOD			 125
#define CMP_F_CMP_CTX_SET1_PROTECTIONALG		 126
#define CMP_F_CMP_CTX_SET1_PROXYNAME			 127
#define CMP_F_CMP_CTX_SET1_PROXYPORT			 128
#define CMP_F_CMP_CTX_SET1_RECIPIENT			 129
#define CMP_F_CMP_CTX_SET1_RECIPNONCE			 130
#define CMP_F_CMP_CTX_SET1_REFERENCEVALUE		 131
#define CMP_F_CMP_CTX_SET1_REGTOKEN			 163
#define CMP_F_CMP_CTX_SET1_SECRETVALUE			 132
#define CMP_F_CMP_CTX_SET1_SENDER			 133
#define CMP_F_CMP_CTX_SET1_SERVERNAME			 134
#define CMP_F_CMP_CTX_SET1_SERVERPATH			 135
#define CMP_F_CMP_CTX_SET1_SERVERPORT			 136
#define CMP_F_CMP_CTX_SET1_SRVCERT			 173
#define CMP_F_CMP_CTX_SET1_SUBJECTNAME			 137
#define CMP_F_CMP_CTX_SET1_TIMEOUT			 138
#define CMP_F_CMP_CTX_SET1_TRANSACTIONID		 139
#define CMP_F_CMP_CTX_SET_PROTECTIONALG			 141
#define CMP_F_CMP_CTX_SUBJECTALTNAME_PUSH1		 142
#define CMP_F_CMP_DOCERTIFICATEREQUESTSEQ		 143
#define CMP_F_CMP_DOGENERALMESSAGESEQ			 166
#define CMP_F_CMP_DOINITIALREQUESTSEQ			 144
#define CMP_F_CMP_DOKEYUPDATEREQUESTSEQ			 145
#define CMP_F_CMP_DOPKIINFOREQSEQ			 146
#define CMP_F_CMP_DOREVOCATIONREQUESTSEQ		 147
#define CMP_F_CMP_GENM_NEW				 148
#define CMP_F_CMP_IR_NEW				 149
#define CMP_F_CMP_KUR_NEW				 150
#define CMP_F_CMP_NEW_HTTP_BIO_EX			 151
#define CMP_F_CMP_PKIMESSAGE_HTTP_BIO_RECV		 152
#define CMP_F_CMP_PKIMESSAGE_HTTP_BIO_SEND		 153
#define CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM		 154
#define CMP_F_CMP_PKIMESSAGE_PROTECT			 165
#define CMP_F_CMP_PKISTATUSINFO_PKISTATUS_GET_STRING	 155
#define CMP_F_CMP_PROTECTION_NEW			 156
#define CMP_F_CMP_PROTECTION_VERIFY			 157
#define CMP_F_CMP_PROTECT_MSG				 164
#define CMP_F_CMP_RR_NEW				 158
#define CMP_F_CMP_VALIDATE_CERT_PATH			 159
#define CMP_F_CMP_VALIDATE_MSG				 168
#define CMP_F_CMP_VERIFY_SIGNATURE			 169
#define CMP_F_PKEY_DUP					 160
#define CMP_F_POLLFORRESPONSE				 167
#define CMP_F_TRY_POLLING				 161

/* Reason codes. */
#define CMP_R_ALGORITHM_NOT_SUPPORTED			 156
#define CMP_R_CERTIFICATE_NOT_FOUND			 100
#define CMP_R_COULD_NOT_VALIDATE_CERTIFICATE_PATH	 101
#define CMP_R_CP_NOT_RECEIVED				 102
#define CMP_R_CURL_ERROR				 103
#define CMP_R_DEPRECATED_FUNCTION			 104
#define CMP_R_ERROR_CALCULATING_PROTECTION		 105
#define CMP_R_ERROR_CREATING_CERTCONF			 106
#define CMP_R_ERROR_CREATING_CKUANN			 107
#define CMP_R_ERROR_CREATING_CR				 108
#define CMP_R_ERROR_CREATING_GENM			 109
#define CMP_R_ERROR_CREATING_IR				 110
#define CMP_R_ERROR_CREATING_KUR			 111
#define CMP_R_ERROR_CREATING_RR				 112
#define CMP_R_ERROR_DECODING_CERTIFICATE		 113
#define CMP_R_ERROR_DECRYPTING_CERTIFICATE		 114
#define CMP_R_ERROR_DECRYPTING_ENCCERT			 115
#define CMP_R_ERROR_DECRYPTING_KEY			 116
#define CMP_R_ERROR_DECRYPTING_SYMMETRIC_KEY		 117
#define CMP_R_ERROR_PARSING_PKISTATUS			 118
#define CMP_R_ERROR_PROTECTING_MESSAGE			 152
#define CMP_R_ERROR_SETTING_CERTHASH			 119
#define CMP_R_ERROR_SETTING_PROTECTION_ALGORITHM	 120
#define CMP_R_ERROR_VALIDATING_PROTECTION		 121
#define CMP_R_ERROR_VERIFYING_PROTECTION		 122
#define CMP_R_FAILED_TO_DECODE_PKIMESSAGE		 148
#define CMP_R_FAILED_TO_DETERMINE_PROTECTION_ALGORITHM	 123
#define CMP_R_GENP_NOT_RECEIVED				 124
#define CMP_R_INVALID_ARGS				 125
#define CMP_R_INVALID_CONTENT_TYPE			 147
#define CMP_R_INVALID_CONTEXT				 126
#define CMP_R_INVALID_KEY				 127
#define CMP_R_INVALID_PARAMETERS			 128
#define CMP_R_IP_NOT_RECEIVED				 129
#define CMP_R_KUP_NOT_RECEIVED				 130
#define CMP_R_MISSING_KEY_INPUT_FOR_CREATING_PROTECTION	 153
#define CMP_R_MISSING_SERVER_CERTIFICATE		 151
#define CMP_R_NO_CERTIFICATE_RECEIVED			 131
#define CMP_R_NO_SECRET_VALUE_GIVEN_FOR_PBMAC		 132
#define CMP_R_NO_TRUSTED_CERTIFICATES_SET		 133
#define CMP_R_NO_VALID_SRVCERT_FOUND			 159
#define CMP_R_NULL_ARGUMENT				 134
#define CMP_R_PKIBODY_ERROR				 135
#define CMP_R_PKICONF_NOT_RECEIVED			 136
#define CMP_R_POLLING_FAILED				 150
#define CMP_R_POLLREP_NOT_RECEIVED			 154
#define CMP_R_RECEIVED_INVALID_RESPONSE_TO_POLLREQ	 137
#define CMP_R_REQUEST_REJECTED_BY_CA			 138
#define CMP_R_RP_NOT_RECEIVED				 139
#define CMP_R_SERVER_NOT_REACHABLE			 149
#define CMP_R_SUBJECT_NAME_NOT_SET			 140
#define CMP_R_UNABLE_TO_CREATE_CONTEXT			 141
#define CMP_R_UNKNOWN_ALGORITHM_ID			 142
#define CMP_R_UNKNOWN_CERTTYPE				 158
#define CMP_R_UNKNOWN_CIPHER				 143
#define CMP_R_UNKNOWN_PKISTATUS				 144
#define CMP_R_UNSUPPORTED_ALGORITHM			 145
#define CMP_R_UNSUPPORTED_KEY_TYPE			 146
#define CMP_R_UNSUPPORTED_PROTECTION_ALG_DHBASEDMAC	 155
#define CMP_R_WRONG_ALGORITHM_OID			 157

#ifdef  __cplusplus
}
#endif
#endif
