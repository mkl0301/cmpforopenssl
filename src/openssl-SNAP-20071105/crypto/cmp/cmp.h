/* cmp.h
 *
 * CMP (RFC 4210) header file for OpenSSL
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

#ifndef HEADER_CMP_H
#define HEADER_CMP_H

#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/crmf.h>
#include <openssl/safestack.h>


#ifdef  __cplusplus
extern "C" {
#endif


/*
     RevAnnContent ::= SEQUENCE {
         status              PKIStatus,
         certId              CertId,
         willBeRevokedAt     GeneralizedTime,
         badSinceDate        GeneralizedTime,
         crlDetails          Extensions  OPTIONAL
         -- extra CRL details (e.g., crl number, reason, location, etc.)
     }
     */
typedef struct cmp_revanncontent_st
{
	ASN1_INTEGER             *status;
	CRMF_CERTID              *certId;
	ASN1_GENERALIZEDTIME     *willBeRevokedAt;
	ASN1_GENERALIZEDTIME     *badSinceDate;
	STACK_OF(X509_EXTENSION) *crlDetails;
} CMP_REVANNCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_REVANNCONTENT)


/*
     Challenge ::= SEQUENCE {
         owf                 AlgorithmIdentifier  OPTIONAL,

         -- MUST be present in the first Challenge; MAY be omitted in
         -- any subsequent Challenge in POPODecKeyChallContent (if
         -- omitted, then the owf used in the immediately preceding
         -- Challenge is to be used).

         witness             OCTET STRING,
         -- the result of applying the one-way function (owf) to a
         -- randomly-generated INTEGER, A.  [Note that a different
         -- INTEGER MUST be used for each Challenge.]
         challenge           OCTET STRING
         -- the encryption (under the public key for which the cert.
         -- request is being made) of Rand, where Rand is specified as
         --   Rand ::= SEQUENCE {
         --      int      INTEGER,
         --       - the randomly-generated INTEGER A (above)
         --      sender   GeneralName
         --       - the sender's name (as included in PKIHeader)
         --   }
     }
     */
typedef struct cmp_challenge_st
{
	X509_ALGOR        *owf;
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

/* XXX USING THAT DOES NOT WORK FOR SOME REASON */
/* the rfc allows substituting that with "Certificate"... */
	/*
      CMPCertificate ::= CHOICE {
         x509v3PKCert        Certificate
      }
      */
#define CMP_CMPCERTIFICATE_X509V3PKCERT   0
typedef struct cmp_cmpcertificate_st
{
	int type;
	union{
		/* XXX is this the right type? */
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

	/*
     InfoTypeAndValue ::= SEQUENCE {
         infoType               OBJECT IDENTIFIER,
         infoValue              ANY DEFINED BY infoType  OPTIONAL
     }
     */

typedef struct cmp_infotypeandvalue_st
{
	ASN1_OBJECT *infoType;
	/* XXX is this right? */
	ASN1_TYPE   *infoValue;
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

	 /* XXX is this right? */
#if 0
DECLARE_STACK_OF(ASN1_UTF8STRING)
typedef STACK_OF(ASN1_UTF8STRING) CMP_PKIFREETEXT;
DECLARE_ASN1_FUNCTIONS(CMP_PKIFREETEXT)
#endif


/*
     PKIFailureInfo ::= BIT STRING {
     -- since we can fail in more than one way!
     -- More codes may be added in the future if/when required.
         badAlg              (0),
         -- unrecognized or unsupported Algorithm Identifier
         badMessageCheck     (1),
         -- integrity check failed (e.g., signature did not verify)
         badRequest          (2),
         -- transaction not permitted or supported
         badTime             (3),
         -- messageTime was not sufficiently close to the system time,
         -- as defined by local policy
         badCertId           (4),
         -- no certificate could be found matching the provided criteria
         badDataFormat       (5),
         -- the data submitted has the wrong format
         wrongAuthority      (6),
         -- the authority indicated in the request is different from the
         -- one creating the response token
         incorrectData       (7),
         -- the requester's data is incorrect (for notary services)
         missingTimeStamp    (8),
         -- when the timestamp is missing but should be there
         -- (by policy)
         badPOP              (9),
         -- the proof-of-possession failed
         certRevoked         (10),
            -- the certificate has already been revoked
         certConfirmed       (11),
            -- the certificate has already been confirmed
         wrongIntegrity      (12),
            -- invalid integrity, password based instead of signature or
            -- vice versa
         badRecipientNonce   (13),
            -- invalid recipient nonce, either missing or wrong value
         timeNotAvailable    (14),
            -- the TSA's time source is not available
         unacceptedPolicy    (15),
            -- the requested TSA policy is not supported by the TSA.
         unacceptedExtension (16),
            -- the requested extension is not supported by the TSA.
         addInfoNotAvailable (17),
            -- the additional information requested could not be
            -- understood or is not available
         badSenderNonce      (18),
            -- invalid sender nonce, either missing or wrong size
         badCertTemplate     (19),
            -- invalid cert. template or missing mandatory information
         signerNotTrusted    (20),
            -- signer of the message unknown or not trusted
         transactionIdInUse  (21),
            -- the transaction identifier is already in use
         unsupportedVersion  (22),
            -- the version of the message is not supported
         notAuthorized       (23),
            -- the sender was not authorized to make the preceding
            -- request or perform the preceding action
         systemUnavail       (24),
         -- the request cannot be handled due to system unavailability
         systemFailure       (25),
         -- the request cannot be handled due to system failure
         duplicateCertReq    (26)
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
#define CMP_PKIFAILUREINFO_MAX                  26
     /* XXX this should be done right */
typedef ASN1_BIT_STRING CMP_PKIFAILUREINFO;

/*
     PKIStatus ::= INTEGER {
         accepted                (0),
         -- you got exactly what you asked for
         grantedWithMods        (1),
         -- you got something like what you asked for; the
         -- requester is responsible for ascertaining the differences
         rejection              (2),
         -- you don't get it, more information elsewhere in the message
         waiting                (3),
         -- the request body part has not yet been processed; expect to
         -- hear more later (note: proper handling of this status
         -- response MAY use the polling req/rep PKIMessages specified
         -- in Section 5.3.22; alternatively, polling in the underlying
         -- transport layer MAY have some utility in this regard)
         revocationWarning      (4),
         -- this message contains a warning that a revocation is
         -- imminent
         revocationNotification (5),
         -- notification that a revocation has occurred
         keyUpdateWarning       (6)
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
     /* XXX this should be done right */
typedef ASN1_INTEGER CMP_PKISTATUS;



/*
     CertOrEncCert ::= CHOICE {
         certificate     [0] CMPCertificate,
         encryptedCert   [1] EncryptedValue
     }
     */
#define CMP_CERTORENCCERT_CERTIFICATE   0
#define CMP_CERTORENCCERT_ENCRYPTEDCERT 1
typedef struct cmp_certorenccert_st
{
	int type;
	union{
		/* XXX is this the right type? */
		//CMP_CMPCERTIFICATE  *certificate;
		X509  *certificate;
		CRMF_ENCRYPTEDVALUE *encryptedCert;
	} value;
} CMP_CERTORENCCERT;
DECLARE_ASN1_FUNCTIONS(CMP_CERTORENCCERT)
/*
     CertifiedKeyPair ::= SEQUENCE {
         certOrEncCert       CertOrEncCert,
         privateKey      [0] EncryptedValue      OPTIONAL,
         -- see [CRMF] for comment on encoding
         publicationInfo [1] PKIPublicationInfo  OPTIONAL
     }
     */
typedef struct cmp_certifiedkeypair_st
{
	CMP_CERTORENCCERT       *certOrEncCert;
	CRMF_ENCRYPTEDVALUE     *privateKey;
	CRMF_PKIPUBLICATIONINFO *failInfo;
} CMP_CERTIFIEDKEYPAIR;
DECLARE_ASN1_FUNCTIONS(CMP_CERTIFIEDKEYPAIR)




/*
     PKIStatusInfo ::= SEQUENCE {
         status        PKIStatus,
         statusString  PKIFreeText     OPTIONAL,
         failInfo      PKIFailureInfo  OPTIONAL
     }
     */

typedef struct cmp_pkistatusinfo_st
{
/* XXX XXX this should actually be
	CMP_PKISTATUS      *status;
	*/
	ASN1_INTEGER       *status;
#if 0
	CMP_PKIFREETEXT    *statusString;
#endif
	STACK_OF(ASN1_UTF8STRING)    *statusString;
/* XXX XXX this should actually be
	CMP_PKIFAILUREINFO *failInfo;
	*/
	ASN1_BIT_STRING    *failInfo;
} CMP_PKISTATUSINFO;
DECLARE_ASN1_FUNCTIONS(CMP_PKISTATUSINFO)

/*
     XXX RevReqContent ::= SEQUENCE OF RevDetails

     RevDetails ::= SEQUENCE {
         certDetails         CertTemplate,
         -- allows requester to specify as much as they can about
         -- the cert. for which revocation is requested
         -- (e.g., for cases in which serialNumber is not available)
         crlEntryDetails     Extensions       OPTIONAL
         -- requested crlEntryExtensions
     }
*/

typedef struct cmp_revdetails_st
{
	CRMF_CERTTEMPLATE        *certDetails;
	STACK_OF(X509_EXTENSION) *crlEntryDetails;
} CMP_REVDETAILS;
DECLARE_ASN1_FUNCTIONS(CMP_REVDETAILS)

/*
     KeyRecRepContent ::= SEQUENCE {
         status                  PKIStatusInfo,
         newSigCert          [0] CMPCertificate OPTIONAL,
         caCerts             [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate OPTIONAL,
         keyPairHist         [2] SEQUENCE SIZE (1..MAX) OF CertifiedKeyPair OPTIONAL
     }
*/
typedef struct cmp_keyrecrepcontent_st
{
	CMP_PKISTATUSINFO       *status;
	/* XXX CMPcertificate ::= Certificate */
	X509                    *newSigCert;
	/* XXX CMPcertificate ::= Certificate */
	STACK_OF(X509)          *caCerts;
	STACK_OF(CMP_CERTIFIEDKEYPAIR) *keyPairHist;
} CMP_KEYRECREPCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_KEYRECREPCONTENT)


/*
     ErrorMsgContent ::= SEQUENCE {
         pKIStatusInfo          PKIStatusInfo,
         errorCode              INTEGER           OPTIONAL,
         -- implementation-specific error codes
         errorDetails           PKIFreeText       OPTIONAL
         -- implementation-specific error details
     }
     */
typedef struct cmp_errormsgcontent_st
{
	CMP_PKISTATUSINFO *pKIStatusInfo;
	ASN1_INTEGER	  *errorCode;
	STACK_OF(ASN1_UTF8STRING)   *errorDetails;
#if 0
	CMP_PKIFREETEXT   *errorDetails;
#endif
} CMP_ERRORMSGCONTENT;
DECLARE_ASN1_FUNCTIONS(CMP_ERRORMSGCONTENT)


/*
     CertConfirmContent ::= SEQUENCE OF CertStatus

     CertStatus ::= SEQUENCE {
        certHash    OCTET STRING,
        -- the hash of the certificate, using the same hash algorithm
        -- as is used to create and verify the certificate signature
        certReqId   INTEGER,
        -- to match this confirmation with the corresponding req/rep
        statusInfo  PKIStatusInfo OPTIONAL
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

/* XXX this is not used */
/* typedef STACK_OF(CMP_CERTSTATUS) CMP_CERTCONFIRMCONTENT; */
/* DECLARE_ASN1_FUNCTIONS(CMP_CERTCONFIRMCONTENT) */


/*
     CertResponse ::= SEQUENCE {
         certReqId           INTEGER,
         -- to match this response with corresponding request (a value
         -- of -1 is to be used if certReqId is not specified in the
         -- corresponding request)
         status              PKIStatusInfo,
         certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
         rspInfo             OCTET STRING        OPTIONAL
         -- analogous to the id-regInfo-utf8Pairs string defined
         -- for regInfo in CertReqMsg [CRMF]
     }
*/
typedef struct cmp_certresponse_st
{
	ASN1_INTEGER         *certReqId;
	CMP_PKISTATUSINFO    *status;
	CMP_CERTIFIEDKEYPAIR *certifiedKeyPair;
	ASN1_OCTET_STRING    *rspInfo;
} CMP_CERTRESPONSE;
DECLARE_ASN1_FUNCTIONS(CMP_CERTRESPONSE)
DECLARE_STACK_OF(CMP_CERTRESPONSE)

/*
     CertRepMessage ::= SEQUENCE {
         caPubs       [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
                          OPTIONAL,
         response         SEQUENCE OF CertResponse
     }
*/
typedef struct cmp_certrepmessage_st
{
	//CMP_CMPCERTIFICATE *caPubs;
	/* XXX is this STACK_OF - stuff right? */
	STACK_OF(X509) *caPubs;
	STACK_OF(CMP_CERTRESPONSE)   *response;
} CMP_CERTREPMESSAGE;
DECLARE_ASN1_FUNCTIONS(CMP_CERTREPMESSAGE)


/*
TODO: A LOT
     PKIBody ::= CHOICE {       -- message-specific body elements
         ir       [0]  CertReqMessages,        --Initialization Request
         ip       [1]  CertRepMessage,         --Initialization Response
         cr       [2]  CertReqMessages,        --Certification Request
         cp       [3]  CertRepMessage,         --Certification Response
         p10cr    [4]  CertificationRequest,   --imported from [PKCS10]
         popdecc  [5]  POPODecKeyChallContent, --pop Challenge
         popdecr  [6]  POPODecKeyRespContent,  --pop Response
         kur      [7]  CertReqMessages,        --Key Update Request
         kup      [8]  CertRepMessage,         --Key Update Response
         krr      [9]  CertReqMessages,        --Key Recovery Request
         krp      [10] KeyRecRepContent,       --Key Recovery Response
         rr       [11] RevReqContent,          --Revocation Request
         rp       [12] RevRepContent,          --Revocation Response
         ccr      [13] CertReqMessages,        --Cross-Cert. Request
         ccp      [14] CertRepMessage,         --Cross-Cert. Response
         ckuann   [15] CAKeyUpdAnnContent,     --CA Key Update Ann.
         cann     [16] CertAnnContent,         --Certificate Ann.
         rann     [17] RevAnnContent,          --Revocation Ann.
         crlann   [18] CRLAnnContent,          --CRL Announcement
         pkiconf  [19] PKIConfirmContent,      --Confirmation
         nested   [20] NestedMessageContent,   --Nested Message
         genm     [21] GenMsgContent,          --General Message
         genp     [22] GenRepContent,          --General Response
         error    [23] ErrorMsgContent,        --Error Message
         certConf [24] CertConfirmContent,     --Certificate confirm
         pollReq  [25] PollReqContent,         --Polling request
         pollRep  [26] PollRepContent          --Polling response
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

typedef struct cmp_pkibody_st
{
	int type;
	union{
		STACK_OF(CRMF_CERTREQMSG)   *ir;   /* 0 */
		CMP_CERTREPMESSAGE          *ip;   /* 1 */
		STACK_OF(CRMF_CERTREQMSG)   *cr;   /* 2 */
		CMP_CERTREPMESSAGE          *cp;   /* 3 */
        /* p10cr    [4]  CertificationRequest,   --imported from [PKCS10] */
/* TODO */
ASN1_INTEGER *p10cr; /* 4 */
        /* popdecc  [5]  POPODecKeyChallContent, --pop Challenge */
	/* POPODecKeyChallContent ::= SEQUENCE OF Challenge */
		STACK_OF(CMP_CHALLENGE) *popdecc; /* 5 */
	/* popdecr  [6]  POPODecKeyRespContent,  --pop Response */
	/* POPODecKeyRespContent ::= SEQUENCE OF INTEGER */
		STACK_OF(ASN1_INTEGER)    *popdecr; /* 6 */
		STACK_OF(CRMF_CERTREQMSG)   *kur;   /* 7 */
		CMP_CERTREPMESSAGE          *kup;   /* 8 */
		STACK_OF(CRMF_CERTREQMSG)   *krr;   /* 9 */

	/* krp      [10] KeyRecRepContent,       --Key Recovery Response */
		CMP_KEYRECREPCONTENT        *krp;   /* 10 */
        /* rr       [11] RevReqContent,          --Revocation Request */
		STACK_OF(CMP_REVDETAILS)    *rr; /* 11 */
        /* rp       [12] RevRepContent,          --Revocation Response */
		STACK_OF(CRMF_CERTREQMSG)   *rp; /* 12 */
        /* ccr      [13] CertReqMessages,        --Cross-Cert. Request */
		STACK_OF(CRMF_CERTREQMSG)   *crr; /* 13 */
        /* ccp      [14] CertRepMessage,         --Cross-Cert. Response */
		CMP_CERTREPMESSAGE          *ccp; /* 14 */
        /* ckuann   [15] CAKeyUpdAnnContent,     --CA Key Update Ann. */
		CMP_CAKEYUPDANNCONTENT   *ckuann; /* 15 */
	/* cann     [16] CertAnnContent,         --Certificate Ann. */
	/* TODO: CertAnnContent ::= CMPCertificate */
	/* XXX CMPcertificate ::= Certificate */
		X509                       *cann; /* 16 */
        /* rann     [17] RevAnnContent,          --Revocation Ann. */
		CMP_REVANNCONTENT          *rann; /* 17 */
        /* crlann   [18] CRLAnnContent,          --CRL Announcement */
        /* CRLAnnContent ::= SEQUENCE OF CertificateList */
	/* XXX what is CertificateList? */
/* TODO */
ASN1_INTEGER *crlann; /* 18 */
        /* pkiconf  [19] PKIConfirmContent,      --Confirmation */
	/* CMP_PKICONFIRMCONTENT would be only a typedfef of ASN1_NULL */
	/* CMP_CONFIRMCONTENT *pkiconf; */
	/* XXX it should be the following according to the RFC but there might be a struct in it */
#if 0
	ASN1_NULL *pkiconf; /* 19 */
#endif
		ASN1_TYPE                       *pkiconf; /* 19 */
        /* nested   [20] NestedMessageContent,   --Nested Message */
        /* NestedMessageContent ::= PKIMessages */
		STACK_OF(CMP_PKIMESSAGE)        *nested; /* 20 */
        /* genm     [21] GenMsgContent,          --General Message */
        /* GenMsgContent ::= SEQUENCE OF InfoTypeAndValue */
		STACK_OF(CMP_INFOTYPEANDVALUE) *genm; /* 21 */
        /* genp     [22] GenRepContent,          --General Response */
	/* GenRepContent ::= SEQUENCE OF InfoTypeAndValue */
		STACK_OF(CMP_INFOTYPEANDVALUE) *genp; /* 22 */
        /* error    [23] ErrorMsgContent,        --Error Message */
		CMP_ERRORMSGCONTENT            *error;    /* 23 */
        /* certConf [24] CertConfirmContent,     --Certificate confirm */
	 	/* CMP_CERTCONFIRMCONTENT      *certConf; / * 24 */
	 	STACK_OF(CMP_CERTSTATUS)       *certConf; /* 24 */
	/* pollReq  [25] PollReqContent,         --Polling request */
/* TODO */
ASN1_INTEGER *pollReq; /* 25 */
        /* pollRep  [26] PollRepContent          --Polling response */
/* TODO */
ASN1_INTEGER *pollRep; /* 26 */
	} value;
} CMP_PKIBODY;
DECLARE_ASN1_FUNCTIONS(CMP_PKIBODY)


/*
     PKIHeader ::= SEQUENCE {
         pvno                INTEGER     { cmp1999(1), cmp2000(2) },
         sender              GeneralName,
         -- identifies the sender
         recipient           GeneralName,
         -- identifies the intended recipient
         messageTime     [0] GeneralizedTime         OPTIONAL,
         -- time of production of this message (used when sender
         -- believes that the transport will be "suitable"; i.e.,
         -- that the time will still be meaningful upon receipt)
         protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
         -- algorithm used for calculation of protection bits
         senderKID       [2] KeyIdentifier           OPTIONAL,
         recipKID        [3] KeyIdentifier           OPTIONAL,
         -- to identify specific keys used for protection
         transactionID   [4] OCTET STRING            OPTIONAL,
         -- identifies the transaction; i.e., this will be the same in
         -- corresponding request, response, certConf, and PKIConf
         -- messages
         senderNonce     [5] OCTET STRING            OPTIONAL,
         recipNonce      [6] OCTET STRING            OPTIONAL,
         -- nonces used to provide replay protection, senderNonce
         -- is inserted by the creator of this message; recipNonce
         -- is a nonce previously inserted in a related message by
         -- the intended recipient of this message
         freeText        [7] PKIFreeText             OPTIONAL,
         -- this may be used to indicate context-specific instructions
         -- (this field is intended for human consumption)
         generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
                                InfoTypeAndValue     OPTIONAL
         -- this may be used to convey context-specific information
         -- (this field not primarily intended for human consumption)
     }
*/

#if 0
XXX this does not work
typedef ASN1_OCTET_STRING XXX_KEYIDENTIFIER;
DECLARE_ASN1_FUNCTIONS(XXX_KEYIDENTIFIER)
#endif

typedef struct cmp_pkiheader_st
{
	ASN1_INTEGER                  *pvno;
	GENERAL_NAME                  *sender;
	GENERAL_NAME                  *recipient;
	ASN1_GENERALIZEDTIME          *messageTime;    /* 0 */
	/* TODO The following actually should be: */
	X509_ALGOR                    *protectionAlg;  /* 1 */
	ASN1_OCTET_STRING             *senderKID;      /* 2 */
	ASN1_OCTET_STRING             *recipKID;       /* 3 */
	ASN1_OCTET_STRING             *transactionID;  /* 4 */
	ASN1_OCTET_STRING             *senderNonce;    /* 5 */
	ASN1_OCTET_STRING             *recipNonce;     /* 6 */
	/* XXX is this right? */
#if 0
	CMP_PKIFREETEXT               *freeText;       /* 7 */
#endif
	STACK_OF(ASN1_UTF8STRING)               *freeText;       /* 7 */
	STACK_OF(CMP_INFOTYPEANDVALUE) *generalInfo;    /* 8 */
} CMP_PKIHEADER;
DECLARE_ASN1_FUNCTIONS(CMP_PKIHEADER)

/*
     ProtectedPart ::= SEQUENCE {
         header    PKIHeader,
         body      PKIBody
     }
     */
typedef struct cmp_protectedpart_st
{
	CMP_PKIHEADER                *header;
	CMP_PKIBODY                  *body;
} CMP_PROTECTEDPART;
DECLARE_ASN1_FUNCTIONS(CMP_PROTECTEDPART)


/*

     PKIProtection ::= BIT STRING

     PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage

      PKIMessage ::= SEQUENCE {
         header           PKIHeader,
         body             PKIBody,
         protection   [0] PKIProtection OPTIONAL,
         extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
                          OPTIONAL
     }

*/

#if 0
XXX this does not work
typedef ASN1_BIT_STRING CMP_PKIPROTECTION;
DECLARE_ASN1_FUNCTIONS(CMP_PKIPROTECTION)
#endif

typedef struct cmp_pkimessage_st
{
	CMP_PKIHEADER                *header;
	CMP_PKIBODY                  *body;
	ASN1_BIT_STRING              *protection; /* 0 */
	//STACK_OF(CMP_CMPCERTIFICATE) *extraCerts; /* 1 */
	STACK_OF(X509) *extraCerts; /* 1 */
} CMP_PKIMESSAGE;
DECLARE_ASN1_FUNCTIONS(CMP_PKIMESSAGE)
DECLARE_STACK_OF(CMP_PKIMESSAGE) /* PKIMessages */

/* XXX is there more to do for that? */
typedef STACK_OF(CMP_PKIMESSAGE) CMP_PKIMESSAGES;




#if 0
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
         -- tags).  Alternatively, implementers may directly include
         -- the [PKCS10] syntax in this module




Adams, et al.               Standards Track                    [Page 83]

RFC 4210                          CMP                     September 2005


         ;

   -- the rest of the module contains locally-defined OIDs and
   -- constructs

   -- This syntax, while bits-on-the-wire compatible with the
   -- standard X.509 definition of "Certificate", allows the
   -- possibility of future certificate types (such as X.509
   -- attribute certificates, WAP WTLS certificates, or other kinds
   -- of certificates) within this certificate management protocol,
   -- should a need ever arise to support such generality.  Those
   -- implementations that do not foresee a need to ever support
   -- other certificate types MAY, if they wish, comment out the
   -- above structure and "un-comment" the following one prior to
   -- compiling this ASN.1 module.  (Note that interoperability
   -- with implementations that dont do this will be unaffected by
   -- this change.)

   -- CMPCertificate ::= Certificate





Adams, et al.               Standards Track                    [Page 84]

RFC 4210                          CMP                     September 2005






Adams, et al.               Standards Track                    [Page 85]

RFC 4210                          CMP                     September 2005


         genp     [22] GenRepContent,          --General Response
         error    [23] ErrorMsgContent,        --Error Message
         certConf [24] CertConfirmContent,     --Certificate confirm
         pollReq  [25] PollReqContent,         --Polling request
         pollRep  [26] PollRepContent          --Polling response
     }


     id-PasswordBasedMac OBJECT IDENTIFIER ::= {1 2 840 113533 7 66 13}
     PBMParameter ::= SEQUENCE {
         salt                OCTET STRING,
         -- note:  implementations MAY wish to limit acceptable sizes
         -- of this string to values appropriate for their environment
         -- in order to reduce the risk of denial-of-service attacks
         owf                 AlgorithmIdentifier,
         -- AlgId for a One-Way Function (SHA-1 recommended)
         iterationCount      INTEGER,
         -- number of times the OWF is applied
         -- note:  implementations MAY wish to limit acceptable sizes
         -- of this integer to values appropriate for their environment
         -- in order to reduce the risk of denial-of-service attacks
         mac                 AlgorithmIdentifier
         -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
     }   -- or HMAC [RFC2104, RFC2202])

     id-DHBasedMac OBJECT IDENTIFIER ::= {1 2 840 113533 7 66 30}
     DHBMParameter ::= SEQUENCE {
         owf                 AlgorithmIdentifier,
         -- AlgId for a One-Way Function (SHA-1 recommended)
         mac                 AlgorithmIdentifier
         -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
     }   -- or HMAC [RFC2104, RFC2202])






     OOBCert ::= CMPCertificate

     OOBCertHash ::= SEQUENCE {
         hashAlg     [0] AlgorithmIdentifier     OPTIONAL,
         certId      [1] CertId                  OPTIONAL,
         hashVal         BIT STRING



Adams, et al.               Standards Track                    [Page 88]

RFC 4210                          CMP                     September 2005


         -- hashVal is calculated over the DER encoding of the
         -- self-signed certificate with the identifier certID.
     }






     RevRepContent ::= SEQUENCE {
         status       SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
         -- in same order as was sent in RevReqContent
         revCerts [0] SEQUENCE SIZE (1..MAX) OF CertId
                                             OPTIONAL,
         -- IDs for which revocation was requested
         -- (same order as status)
         crls     [1] SEQUENCE SIZE (1..MAX) OF CertificateList
                                             OPTIONAL



Adams, et al.               Standards Track                    [Page 90]

RFC 4210                          CMP                     September 2005


         -- the resulting CRLs (there may be more than one)
     }






     PKIConfirmContent ::= NULL

     -- Example InfoTypeAndValue contents include, but are not limited
     -- to, the following (un-comment in this ASN.1 module and use as
     -- appropriate for a given environment):
     --
     --   id-it-caProtEncCert    OBJECT IDENTIFIER ::= {id-it 1}
     --      CAProtEncCertValue      ::= CMPCertificate
     --   id-it-signKeyPairTypes OBJECT IDENTIFIER ::= {id-it 2}
     --      SignKeyPairTypesValue   ::= SEQUENCE OF AlgorithmIdentifier
     --   id-it-encKeyPairTypes  OBJECT IDENTIFIER ::= {id-it 3}



Adams, et al.               Standards Track                    [Page 91]

RFC 4210                          CMP                     September 2005


     --      EncKeyPairTypesValue    ::= SEQUENCE OF AlgorithmIdentifier
     --   id-it-preferredSymmAlg OBJECT IDENTIFIER ::= {id-it 4}
     --      PreferredSymmAlgValue   ::= AlgorithmIdentifier
     --   id-it-caKeyUpdateInfo  OBJECT IDENTIFIER ::= {id-it 5}
     --      CAKeyUpdateInfoValue    ::= CAKeyUpdAnnContent
     --   id-it-currentCRL       OBJECT IDENTIFIER ::= {id-it 6}
     --      CurrentCRLValue         ::= CertificateList
     --   id-it-unsupportedOIDs  OBJECT IDENTIFIER ::= {id-it 7}
     --      UnsupportedOIDsValue    ::= SEQUENCE OF OBJECT IDENTIFIER
     --   id-it-keyPairParamReq  OBJECT IDENTIFIER ::= {id-it 10}
     --      KeyPairParamReqValue    ::= OBJECT IDENTIFIER
     --   id-it-keyPairParamRep  OBJECT IDENTIFIER ::= {id-it 11}
     --      KeyPairParamRepValue    ::= AlgorithmIdentifer
     --   id-it-revPassphrase    OBJECT IDENTIFIER ::= {id-it 12}
     --      RevPassphraseValue      ::= EncryptedValue
     --   id-it-implicitConfirm  OBJECT IDENTIFIER ::= {id-it 13}
     --      ImplicitConfirmValue    ::= NULL
     --   id-it-confirmWaitTime  OBJECT IDENTIFIER ::= {id-it 14}
     --      ConfirmWaitTimeValue    ::= GeneralizedTime
     --   id-it-origPKIMessage   OBJECT IDENTIFIER ::= {id-it 15}
     --      OrigPKIMessageValue     ::= PKIMessages
     --   id-it-suppLangTags     OBJECT IDENTIFIER ::= {id-it 16}
     --      SuppLangTagsValue       ::= SEQUENCE OF UTF8String
     --
     -- where
     --
     --   id-pkix OBJECT IDENTIFIER ::= {
     --      iso(1) identified-organization(3)
     --      dod(6) internet(1) security(5) mechanisms(5) pkix(7)}
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




Adams, et al.               Standards Track                    [Page 92]

RFC 4210                          CMP                     September 2005



     PollReqContent ::= SEQUENCE OF SEQUENCE {
         certReqId              INTEGER
     }

     PollRepContent ::= SEQUENCE OF SEQUENCE {
         certReqId              INTEGER,
         checkAfter             INTEGER,  -- time in seconds
         reason                 PKIFreeText OPTIONAL
     }


     END -- of CMP module
#endif /* 0 */

     /* XXX HELPERS - where should they actually be? */
#if 0
	id-aa-signingCertificate OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9) smime(16) id-aa(2) 12 }

	SigningCertificate ::=  SEQUENCE {
		certs        SEQUENCE OF ESSCertID,
		policies     SEQUENCE OF PolicyInformation OPTIONAL
	}

	ESSCertID ::=  SEQUENCE {
		certHash                 Hash,
		issuerSerial             IssuerSerial OPTIONAL
	}
	Hash ::= OCTET STRING -- SHA1 hash of entire certificate

	IssuerSerial ::= SEQUENCE {
		issuer                   GeneralNames,
		serialNumber             CertificateSerialNumber
	}
#endif
typedef struct ess_issuerserial_st
{
	GENERAL_NAMES *issuer;
	ASN1_INTEGER  *serialNumber;
} ESS_ISSUERSERIAL;
DECLARE_ASN1_FUNCTIONS(ESS_ISSUERSERIAL)

typedef struct ess_esscertid_st
{
	ASN1_OCTET_STRING *certHash;
	ESS_ISSUERSERIAL  *issuerSerial;
} ESS_ESSCERTID;
DECLARE_ASN1_FUNCTIONS(ESS_ESSCERTID)
DECLARE_STACK_OF(ESS_ESSCERTID)
/* XXX DO I NEED THAT? */
DECLARE_ASN1_SET_OF(ESS_ESSCERTID)

typedef struct ess_signingcertificate_st
{
	STACK_OF(ESS_ESSCERTID) *certs;
	STACK_OF(POLICYINFO)    *policies;
} ESS_SIGNINGCERTIFICATE;
DECLARE_ASN1_FUNCTIONS(ESS_SIGNINGCERTIFICATE)

/* CMP_CTX definitions */
/* XXX TODO work in progress */
/* this structure is used to store the context for CMP sessions */
/* partly in ASN.1 syntax in order to ease storing it in the future */
typedef struct cmp_ctx_st
{
	/* "reference and secret" as described in
	 * 4.2.1.2.  End Entity Message Origin Authentication
	 * this is used for IR Sequence
	 */
	ASN1_OCTET_STRING    *referenceValue;
	ASN1_OCTET_STRING    *secretValue;
	/* CA certificate used to identify the CA */
	X509                 *caCert;
	/* *current* CLIENT certificate used to identify the Client */
	/* XXX this should be a stack since there could be more than one */
	X509                 *clCert;
	/* EVP_PKEY holding the *current* keys */
	/* XXX this is not an ASN.1 type */
	EVP_PKEY             *pkey;
	/* *new* CLIENT certificate received from the CA */
	/* XXX this should be a stack since there could be more than one */
	X509                 *newClCert;
	/* EVP_PKEY holding the *new* keys */
	/* XXX this is not an ASN.1 type */
	EVP_PKEY             *newPkey;
	/* the current transaction ID */
	ASN1_OCTET_STRING    *transactionID;
	/* last nonce received */
	ASN1_OCTET_STRING    *recipNonce;
	/* Algorithm used for protection */
	X509_ALGOR           *protectionAlgor;
	/* compatibility mode */
#define CMP_COMPAT_RFC		1
#define CMP_COMPAT_CRYPTLIB	2
	int	   compatibility;
	char      *serverName;
	int       serverPort;
#define CMP_TRANSPORT_HTTP	1
#define CMP_TRANSPORT_TCP	2
	int	   transport;
#if 0
	CMP_PKIMESSAGE       *lastMsgSent;
	CMP_PKIMESSAGE       *lastMsgRecvd;
#endif
#if 0
	/* this is actually CMP_PKIFREETEXT which is STACK_OF(ANS1_UTF8STRING) */
	STACK_OF(ASN1_UTF8STRING)      *freeText;
#endif
	int	implicitConfirm;
	/* XXX not setting transactionID test for PKI INFO */
	int	setTransactionID;
	/* XXX not setting senderNonce test for PKI INFO */
	int	setSenderNonce;
} CMP_CTX;
DECLARE_ASN1_FUNCTIONS(CMP_CTX)



/* DECLARATIONS */

/* cmp_msg.c */
CMP_PKIMESSAGE *CMP_ir_new( CMP_CTX *ctx);
CMP_PKIMESSAGE *CMP_certConf_new( CMP_CTX *ctx);
CMP_PKIMESSAGE *CMP_kur_new( CMP_CTX *ctx);
CMP_PKIMESSAGE *CMP_genm_new( CMP_CTX *ctx);
#if 0
CMP_PKIMESSAGE *CMP_ckuann_new( CMP_CTX *ctx);
#endif
CMP_PKIMESSAGE *CMP_ckuann_new( const X509 *oldCaCert, const EVP_PKEY *oldPkey, const X509 *newCaCert, const EVP_PKEY *newPkey);

/* cmp_lib.c */

int CMP_PKIHEADER_set_version(CMP_PKIHEADER *hdr, int version);
int CMP_PKIHEADER_set0_recipient(CMP_PKIHEADER *hdr, const X509_NAME *nm);
int CMP_PKIHEADER_set1_recipient(CMP_PKIHEADER *hdr, const X509_NAME *nm);
int CMP_PKIHEADER_set0_sender(CMP_PKIHEADER *hdr, const X509_NAME *nm);
int CMP_PKIHEADER_set1_sender(CMP_PKIHEADER *hdr, const X509_NAME *nm);
#if 0
int CMP_PKIHEADER_set_protectionAlg_dsa(CMP_PKIHEADER *hdr);
int CMP_PKIHEADER_set_protectionAlg_rsa(CMP_PKIHEADER *hdr);
#endif
int CMP_PKIHEADER_set1_transactionID(CMP_PKIHEADER *hdr, const ASN1_OCTET_STRING *transactionID);
int CMP_PKIHEADER_set1_recipNonce(CMP_PKIHEADER *hdr, const ASN1_OCTET_STRING *recipNonce);
int CMP_PKIHEADER_set1_senderKID(CMP_PKIHEADER *hdr, const ASN1_OCTET_STRING *senderKID);
int CMP_PKIHEADER_set1_protectionAlgor(CMP_PKIHEADER *hdr, const X509_ALGOR *alg);
X509_ALGOR *CMP_get_protectionAlgor_by_nid(int nid);
X509_ALGOR *CMP_get_protectionAlgor_pbmac();
int CMP_PKIHEADER_set_messageTime(CMP_PKIHEADER *hdr);
int CMP_PKIMESSAGE_set_implicitConfirm(CMP_PKIMESSAGE *msg);
int CMP_PKIMESSAGE_check_implicitConfirm(CMP_PKIMESSAGE *msg);
#if 0
int CMP_PKIHEADER_push0_freeText( CMP_PKIHEADER *hdr, ASN1_UTF8STRING *text);
int CMP_PKIHEADER_push1_freeText( CMP_PKIHEADER *hdr, ASN1_UTF8STRING *text);
int CMP_PKIHEADER_set0_freeText( CMP_PKIHEADER *hdr, STACK_OF(ASN1_UTF8STRING) *text);
int CMP_PKIHEADER_set1_freeText( CMP_PKIHEADER *hdr, STACK_OF(ASN1_UTF8STRING) *text);
#endif

int CMP_PKIHEADER_set1(CMP_PKIHEADER *hdr, CMP_CTX *ctx);

ASN1_BIT_STRING *CMP_protection_new(CMP_PKIMESSAGE *pkimessage,
				    X509_ALGOR *_algor,
				    const EVP_PKEY *pkey,
				    const ASN1_OCTET_STRING *secret);

int CMP_CERTSTATUS_set_certHash( CMP_CERTSTATUS *certStatus, const X509 *cert);

int CMP_PKIHEADER_generalInfo_item_push0(CMP_PKIHEADER *hdr, const CMP_INFOTYPEANDVALUE *itav);
int CMP_PKIMESSAGE_genm_item_push0(CMP_PKIMESSAGE *msg, const CMP_INFOTYPEANDVALUE *itav);
int CMP_ITAV_stack_item_push0(STACK_OF(CMP_INFOTYPEANDVALUE) **itav_sk_p, const CMP_INFOTYPEANDVALUE *itav);

long CMP_PKISTATUSINFO_PKIstatus_get( CMP_PKISTATUSINFO *statusInfo);
long CMP_ERRORMSGCONTENT_PKIStatus_get( CMP_ERRORMSGCONTENT *error);
int CMP_PKISTATUSINFO_PKIStatus_print( CMP_PKISTATUSINFO *statusInfo);
int CMP_ERRORMSGCONTENT_PKIStatus_print( CMP_ERRORMSGCONTENT *error);

int CMP_PKISTATUSINFO_PKIFailureInfo_print( CMP_PKISTATUSINFO *statusInfo);
int CMP_ERRORMSGCONTENT_PKIFailureInfo_print( CMP_ERRORMSGCONTENT *error);

long CMP_CERTRESPONSE_PKIStatus_get( CMP_CERTRESPONSE *resp);
long CMP_CERTREPMESSAGE_PKIStatus_get( CMP_CERTREPMESSAGE *certRep, long certReqId);

int CMP_PKIFAILUREINFO_check( ASN1_BIT_STRING *failInfo, int codeBit);

CMP_CERTRESPONSE *CMP_CERTREPMESSAGE_certResponse_get0( CMP_CERTREPMESSAGE *certRep, long certReqId);
X509 *CMP_CERTREPMESSAGE_cert_get0( CMP_CERTREPMESSAGE *certRep, long certReqId);
X509 *CMP_CERTREPMESSAGE_cert_get1( CMP_CERTREPMESSAGE *certRep, long certReqId);

int CMP_PKIMESSAGE_set_bodytype( CMP_PKIMESSAGE *msg, int type);
int CMP_PKIMESSAGE_get_bodytype( CMP_PKIMESSAGE *msg);

int CMP_PKIMESSAGE_parse_error_msg( CMP_PKIMESSAGE *msg);

/* cmp_vfy.c */
int CMP_protection_verify(CMP_PKIMESSAGE *msg,
			    X509_ALGOR *algor,
			    EVP_PKEY *pkey,
			    const ASN1_OCTET_STRING *secret);

/* cmp_itav.c */
/* CA Protocol Encryption Certificate */
#define CMP_ITAV_CA_PROT_ENC_CERT	1
/* Signing Key Pair Types */
#define CMP_ITAV_SIGN_KEY_PAIR_TYPES	2
/* Encryption/Key Agreement Key Pair Types */
#define CMP_ITAV_ENC_KEY_PAIR_TYPES	3
/* Preferred Symmetric Algorithm */
#define CMP_ITAV_PREFERRED_SYMM_ALG	4
/* Updated CA Key Pair */
#define CMP_ITAV_CA_KEY_UPDATE_INFO	5
/* CRL */
#define CMP_ITAV_CURRENT_CRL		6
/* Unsupported Object Identifiers */
#define CMP_ITAV_UNSUPPORTED_OIDS	7
/* Key Pair Parameters */
#define CMP_ITAV_KEY_PAIR_PARAM_REQ	10
#define CMP_ITAV_KEY_PAIR_PARAM_REP	11
/* Revocation Passphrase */
#define CMP_ITAV_REV_PASSPHRASE		12
/* ImplicitConfirm */
#define CMP_ITAV_IMPLICIT_CONFIRM	13
/* ConfirmWaitTime */
#define CMP_ITAV_CONFIRM_WAIT_TIME	14
/* OrigPKIMessage */
#define CMP_ITAV_ORIG_PKI_MESSAGE	15
/* Supported Language Tags */
#define CMP_ITAV_SUPP_LANG_TAGS		16
/* Defines used by Cryptlib */
/* 1.3.6.1.4.1.3029.3.1.1 */
#define CMP_ITAV_CRYPTLIB		101
/* 1.3.6.1.4.1.3029.3.1.2 */
#define CMP_ITAV_CRYPTLIB_PKIBOOT	102
CMP_INFOTYPEANDVALUE *CMP_INFOTYPEANDVALUE_new_by_def_noVal(int def);

int CMP_INFOTYPEANDVALUE_set0(CMP_INFOTYPEANDVALUE *itav, ASN1_OBJECT *aobj, int ptype, void *pval);
void CMP_INFOTYPEANDVALUE_get0(ASN1_OBJECT **paobj, int *pptype, void **ppval, CMP_INFOTYPEANDVALUE *itav);

/* from cmp_http.c */
int CMP_new_bio(BIO **cbio, const char* serverName, const int port);
int CMP_CTX_set1_serverPort( CMP_CTX *ctx, int port);
int CMP_PKIMESSAGE_bio_send(BIO *cbio, const char* serverName, const int serverPort, const CMP_PKIMESSAGE *msg);
int CMP_PKIMESSAGE_bio_recv(BIO *cbio, CMP_PKIMESSAGE **ip);

/* from cmp_ses.c */
X509 *CMP_doInitialRequestSeq( BIO *cbio, CMP_CTX *ctx);
X509 *CMP_doKeyUpdateRequestSeq( BIO *cbio, CMP_CTX *ctx);
int CMP_doPKIInfoReqSeq( BIO *cbio, CMP_CTX *ctx);

/* from cmp_ctx.c */
int CMP_CTX_init( CMP_CTX *ctx);
CMP_CTX *CMP_CTX_create();
int CMP_CTX_set1_referenceValue( CMP_CTX *ctx, const unsigned char *ref, size_t len);
int CMP_CTX_set1_secretValue( CMP_CTX *ctx, const unsigned char *sec, const size_t len);
int CMP_CTX_set1_caCert( CMP_CTX *ctx, const X509 *cert);
int CMP_CTX_set1_clCert( CMP_CTX *ctx, const X509 *cert);
int CMP_CTX_set1_newClCert( CMP_CTX *ctx, const X509 *cert);
int CMP_CTX_set0_pkey( CMP_CTX *ctx, const EVP_PKEY *pkey);
int CMP_CTX_set0_newPkey( CMP_CTX *ctx, const EVP_PKEY *pkey);
int CMP_CTX_set1_transactionID( CMP_CTX *ctx, const ASN1_OCTET_STRING *id);
int CMP_CTX_set1_senderNonce( CMP_CTX *ctx, const ASN1_OCTET_STRING *nonce);
int CMP_CTX_set1_recipNonce( CMP_CTX *ctx, const ASN1_OCTET_STRING *nonce);
int CMP_CTX_set1_protectionAlgor( CMP_CTX *ctx, const X509_ALGOR *algor);
int CMP_CTX_set_compatibility( CMP_CTX *ctx, const int mode);
int CMP_CTX_set1_serverName( CMP_CTX *ctx, const char *name);
#define CMP_ALG_PBMAC 1
#define CMP_ALG_SIG   2
int CMP_CTX_set_protectionAlgor( CMP_CTX *ctx, const int algId);
#define CMP_CTX_OPT_UNSET           0
#define CMP_CTX_OPT_SET             1
#define CMP_CTX_OPT_IMPLICITCONFIRM 1
int CMP_CTX_set_option( CMP_CTX *ctx, const int opt, const int val);
#if 0
int CMP_CTX_push_freeText( CMP_CTX *ctx, const char *text);
#endif

/* BIO definitions */
#define d2i_CMP_PKIMESSAGE_bio(bp,p) ASN1_d2i_bio_of(CMP_PKIMESSAGE,CMP_PKIMESSAGE_new,d2i_CMP_PKIMESSAGE,bp,p)
#define i2d_CMP_PKIMESSAGE_bio(bp,o) ASN1_i2d_bio_of(CMP_PKIMESSAGE,i2d_CMP_PKIMESSAGE,bp,o)
#define d2i_CMP_PROTECTEDPART_bio(bp,p) ASN1_d2i_bio_of(CMP_PROTECTEDPART,CMP_PROTECTEDPART_new,d2i_CMP_PROTECTEDPART,bp,p)
#define i2d_CMP_PROTECTEDPART_bio(bp,o) ASN1_i2d_bio_of(CMP_PROTECTEDPART,i2d_CMP_PROTECTEDPART,bp,o)

#define CMP_VERSION 2L

#ifdef  __cplusplus
}
#endif
#endif
