/* crypto/crmf/crmf.h
 * Header file for CRMF (RFC 4211) for OpenSSL
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
 */

#ifndef HEADER_CRMF_H
#define HEADER_CRMF_H

#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/safestack.h>

#ifdef  __cplusplus
extern "C" {
#endif

// make sure this is defined only once if both cmp.h and crmf.h are included
#ifndef HEADER_CMP_H
#if OPENSSL_VERSION_NUMBER < 0x10000000L 
typedef STACK_OF(X509_EXTENSION) X509_EXTENSIONS;
#endif
#endif

/*
Attributes ::= SET OF Attribute
=> X509_ATTRIBUTE

PrivateKeyInfo ::= SEQUENCE {
   version                   INTEGER,
   privateKeyAlgorithm       AlgorithmIdentifier,
   privateKey                OCTET STRING,
   attributes                [0] IMPLICIT Attributes OPTIONAL
}
*/

typedef struct crmf_privatekeyinfo_st
{
	ASN1_INTEGER             *version;
	X509_ALGOR               *AlgorithmIdentifier;
	ASN1_OCTET_STRING        *privateKey;
	STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
} CRMF_PRIVATEKEYINFO;
DECLARE_ASN1_FUNCTIONS(CRMF_PRIVATEKEYINFO)

/*
EncKeyWithID ::= SEQUENCE {
  privateKey           PrivateKeyInfo,
  identifier CHOICE {
    string             UTF8String,
    generalName        GeneralName
  } OPTIONAL
}
*/
typedef struct crmf_enckeywithid_identifier_st
{
	int type;
	union   {
		ASN1_UTF8STRING *string;
		GENERAL_NAME    *generalName;
	} value;
} CRMF_ENCKEYWITHID_IDENTIFIER;
DECLARE_ASN1_FUNCTIONS(CRMF_ENCKEYWITHID_IDENTIFIER)

typedef struct crmf_enckeywithid_st
{
	CRMF_PRIVATEKEYINFO          *privateKey;
	/* TODO is this really done right? */
	/* look at asn1/x_attrib.c */
	CRMF_ENCKEYWITHID_IDENTIFIER *identifier; /* [0] */

} CRMF_ENCKEYWITHID;
DECLARE_ASN1_FUNCTIONS(CRMF_ENCKEYWITHID)

/*
CertId ::= SEQUENCE {
 issuer           GeneralName,
 serialNumber     INTEGER }
 */

typedef struct crmf_certid_st
{
	GENERAL_NAME *issuer;
	ASN1_INTEGER *serialNumber;
} CRMF_CERTID;
DECLARE_ASN1_FUNCTIONS(CRMF_CERTID)
DECLARE_STACK_OF(CRMF_CERTID)

/*
EncryptedValue ::= SEQUENCE {
 intendedAlg   [0] AlgorithmIdentifier  OPTIONAL,
 -- the intended algorithm for which the value will be used
 symmAlg       [1] AlgorithmIdentifier  OPTIONAL,
 -- the symmetric algorithm used to encrypt the value
 encSymmKey    [2] BIT STRING           OPTIONAL,
 -- the (encrypted) symmetric key used to encrypt the value
 keyAlg        [3] AlgorithmIdentifier  OPTIONAL,
 -- algorithm used to encrypt the symmetric key
 valueHint     [4] OCTET STRING         OPTIONAL,
 -- a brief description or identifier of the encValue content
 -- (may be meaningful only to the sending entity, and used only
 -- if EncryptedValue might be re-examined by the sending entity
 -- in the future)
 encValue       BIT STRING }
 -- the encrypted value itself
*/

typedef struct crmf_encrypetedvalue_st
{
	X509_ALGOR               *intendedAlg; /* 0 */
	X509_ALGOR               *symmAlg; /* 1 */
	ASN1_BIT_STRING          *encSymmKey; /* 2 */
	X509_ALGOR               *keyAlg; /* 3 */
	ASN1_OCTET_STRING        *valueHint; /* 4 */
	ASN1_BIT_STRING          *encValue;
} CRMF_ENCRYPTEDVALUE;
DECLARE_ASN1_FUNCTIONS(CRMF_ENCRYPTEDVALUE)

/*
TODO
   -- Cryptographic Message Syntax
   EnvelopedData
   FROM CryptographicMessageSyntax2004 { iso(1) member-body(2)
   us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16)
   modules(0) cms-2004(24) };  -- found in [CMS]

[CMS] Housley, R., "Cryptographic Message Syntax (CMS)", RFC 3852, July 2004.

*/
typedef struct cms_envelopeddata_st
{
	/* TODO
	 * There is actually much more
	 * I hope I'll not need that 
	 */
	ASN1_INTEGER *version;

} CMS_ENVELOPEDDATA;
DECLARE_ASN1_FUNCTIONS(CMS_ENVELOPEDDATA)


/*
EncryptedKey ::= CHOICE {
 encryptedValue        EncryptedValue,   -- Deprecated
 envelopedData     [0] EnvelopedData }
 */
typedef struct crmf_encryptedkey_st
{
	int type;
	union   {
		CRMF_ENCRYPTEDVALUE *encryptedValue; /* Deprecated */
		/* TODO - why is this 0? */
		CMS_ENVELOPEDDATA *envelopedData; /* XXX this is not really implemented so far */ /* 0 */
	} value;
} CRMF_ENCRYPTEDKEY;
DECLARE_ASN1_FUNCTIONS(CRMF_ENCRYPTEDKEY)

/*
PKIArchiveOptions ::= CHOICE {
 encryptedPrivKey     [0] EncryptedKey,
 -- the actual value of the private key
 keyGenParameters     [1] KeyGenParameters,
 -- parameters that allow the private key to be re-generated
 archiveRemGenPrivKey [2] BOOLEAN }
 -- set to TRUE if sender wishes receiver to archive the private
 -- key of a key pair that the receiver generates in response to
 -- this request; set to FALSE if no archival is desired.
*/
typedef struct crmf_pkiarchiveoptions_st
{
	int type;
	union   {
		CRMF_ENCRYPTEDKEY *encryptedPrivKey; /* 0 */
		ASN1_OCTET_STRING *keyGenParameters; /* KeyGenParameters ::= OCTET STRING */ /* 1 */
		ASN1_BOOLEAN      *archiveRemGenPrivKey; /* 2 */
	} value;
} CRMF_PKIARCHIVEOPTIONS;
DECLARE_ASN1_FUNCTIONS(CRMF_PKIARCHIVEOPTIONS)
CRMF_PKIARCHIVEOPTIONS *CRMF_PKIARCHIVEOPTIONS_dup( CRMF_PKIARCHIVEOPTIONS *pkiPubInfo);

/*
SinglePubInfo ::= SEQUENCE {
 pubMethod    INTEGER {
     dontCare    (0),
     x500        (1),
     web         (2),
     ldap        (3) },
 pubLocation  GeneralName OPTIONAL }
 */

typedef struct crmf_singlepubinfo_st
{
	ASN1_INTEGER *pubMethod; /* XXX what to do with the defined values? */
	GENERAL_NAME *pubLocation;
} CRMF_SINGLEPUBINFO;
DECLARE_ASN1_FUNCTIONS(CRMF_SINGLEPUBINFO)


/*
PKIPublicationInfo ::= SEQUENCE {
action     INTEGER {
             dontPublish (0),
             pleasePublish (1) },
pubInfos  SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }
  -- pubInfos MUST NOT be present if action is "dontPublish"
  -- (if action is "pleasePublish" and pubInfos is omitted,
  -- "dontCare" is assumed)
*/

typedef struct crmf_pkipublicationinfo_st
{
	ASN1_INTEGER *action; /* XXX what to do with the defined values? */
	CRMF_SINGLEPUBINFO *pubinfos; /* XXX what to do with the SEQUENCE SIZE... ? */
} CRMF_PKIPUBLICATIONINFO;
DECLARE_ASN1_FUNCTIONS(CRMF_PKIPUBLICATIONINFO)
CRMF_PKIPUBLICATIONINFO *CRMF_PKIPUBLICATIONINFO_dup( CRMF_PKIPUBLICATIONINFO *pkiPubInfo);

/*
TODO
PKMACValue ::= SEQUENCE {
algId  AlgorithmIdentifier,
-- algorithm value shall be PasswordBasedMac {1 2 840 113533 7 66 13}
-- parameter value is PBMParameter
value  BIT STRING }
*/
typedef struct crmf_pkmacvalue_st
{
	X509_ALGOR      *algId;
	ASN1_BIT_STRING *value;
} CRMF_PKMACVALUE;
DECLARE_ASN1_FUNCTIONS(CRMF_PKMACVALUE)


/*
SubsequentMessage ::= INTEGER {
 encrCert (0),
 -- requests that resulting certificate be encrypted for the
 -- end entity (following which, POP will be proven in a
 -- confirmation message)
 challengeResp (1) }
 -- requests that CA engage in challenge-response exchange with
 -- end entity in order to prove private key possession

POPOPrivKey ::= CHOICE {
 thisMessage       [0] BIT STRING,         -- Deprecated
 -- possession is proven in this message (which contains the private
 -- key itself (encrypted for the CA))
 subsequentMessage [1] SubsequentMessage,
 -- possession will be proven in a subsequent message
 dhMAC             [2] BIT STRING,         -- Deprecated
 agreeMAC          [3] PKMACValue,
 encryptedKey      [4] EnvelopedData }
*/
#define CRMF_POPOPRIVKEY_THISMESSAGE       0
#define CRMF_POPOPRIVKEY_SUBSEQUENTMESSAGE 1
#define CRMF_POPOPRIVKEY_DHMAC             2
#define CRMF_POPOPRIVKEY_AGREEMAC          3
#define CRMF_POPOPRIVKEY_ENCRYPTEDKEY      4

#define CRMF_SUBSEQUENTMESSAGE_ENCRCERT      0
#define CRMF_SUBSEQUENTMESSAGE_CHALLENGERESP 1

typedef struct crmf_popoprivkey_st
{
	int type;
	union   {
		ASN1_BIT_STRING   *thisMessage; /* Deprecated */ /* 0 */
		ASN1_INTEGER      *subsequentMessage; /* XXX what to do with the SEQUENCE SIZE... ? */ /* 1 */
		ASN1_BIT_STRING   *dhMAC; /* 2 */
		CRMF_PKMACVALUE   *agreeMAC; /* 3 */
		CMS_ENVELOPEDDATA *encryptedKey; /* 4 */
	} value;
} CRMF_POPOPRIVKEY;
DECLARE_ASN1_FUNCTIONS(CRMF_POPOPRIVKEY)

/*
PBMParameter ::= SEQUENCE {
   salt                OCTET STRING,
   owf                 AlgorithmIdentifier,
   -- AlgId for a One-Way Function (SHA-1 recommended)
   iterationCount      INTEGER,
   -- number of times the OWF is applied
   mac                 AlgorithmIdentifier
   -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
}   -- or HMAC [HMAC, RFC2202])
*/
typedef struct crmf_pbmparameter_st
{
	ASN1_OCTET_STRING *salt;
	X509_ALGOR        *owf;
	ASN1_INTEGER      *iterationCount;
	X509_ALGOR        *mac;
} CRMF_PBMPARAMETER;
DECLARE_ASN1_FUNCTIONS(CRMF_PBMPARAMETER)

/*
POPOSigningKeyInput ::= SEQUENCE {
 authInfo            CHOICE {
     sender              [0] GeneralName,
     -- used only if an authenticated identity has been
     -- established for the sender (e.g., a DN from a
     -- previously-issued and currently-valid certificate)
     publicKeyMAC        PKMACValue },
     -- used if no authenticated GeneralName currently exists for
     -- the sender; publicKeyMAC contains a password-based MAC
     -- on the DER-encoded value of publicKey
 publicKey           SubjectPublicKeyInfo }  -- from CertTemplate
*/
typedef struct crmf_poposigningkeyinput_authinfo_st
{
	int type;
	union   {
		GENERAL_NAME    *sender; /* 0 */
		CRMF_PKMACVALUE *publicKeyMAC; /* XXX imp/exp? */ /* 1 */
	} value;
} CRMF_POPOSIGNINGKEYINPUT_AUTHINFO;
DECLARE_ASN1_FUNCTIONS(CRMF_POPOSIGNINGKEYINPUT_AUTHINFO)

typedef struct crmf_poposigningkeyinput_st
{
	CRMF_POPOSIGNINGKEYINPUT_AUTHINFO *authinfo;
	X509_PUBKEY *publicKey;
} CRMF_POPOSIGNINGKEYINPUT;
DECLARE_ASN1_FUNCTIONS(CRMF_POPOSIGNINGKEYINPUT)

/*
POPOSigningKey ::= SEQUENCE {
 poposkInput           [0] POPOSigningKeyInput OPTIONAL,
 algorithmIdentifier   AlgorithmIdentifier,
 signature             BIT STRING }
 */

typedef struct crmf_poposigningkey_st
{
	CRMF_POPOSIGNINGKEYINPUT *poposkInput;
	X509_ALGOR               *algorithmIdentifier;
	ASN1_BIT_STRING          *signature;
} CRMF_POPOSIGNINGKEY;
DECLARE_ASN1_FUNCTIONS(CRMF_POPOSIGNINGKEY)

/*
ProofOfPossession ::= CHOICE {
 raVerified        [0] NULL,
 -- used if the RA has already verified that the requester is in
 -- possession of the private key
 signature         [1] POPOSigningKey,
 keyEncipherment   [2] POPOPrivKey,
 keyAgreement      [3] POPOPrivKey }
 */
#define CRMF_PROOFOFPOSESSION_RAVERIFIED      0
#define CRMF_PROOFOFPOSESSION_SIGNATURE       1
#define CRMF_PROOFOFPOSESSION_KEYENCIPHERMENT 2
#define CRMF_PROOFOFPOSESSION_KEYAGREEMENT    3
typedef struct crmf_proofofpossesion_st
{
	int type;
	union   {
		ASN1_NULL           *raVerified; /* 0 */
		CRMF_POPOSIGNINGKEY *signature;  /* 1 */
		CRMF_POPOPRIVKEY    *keyEncipherment; /* 2 */
		CRMF_POPOPRIVKEY    *keyAgreement; /* 3 */
	} value;
} CRMF_PROOFOFPOSSESION;
DECLARE_ASN1_FUNCTIONS(CRMF_PROOFOFPOSSESION)

/* XXX looks like x509.h also just uses ASN1_TIME */
/*
OptionalValidity ::= SEQUENCE {
 notBefore  [0] Time OPTIONAL,
 notAfter   [1] Time OPTIONAL } -- at least one MUST be present
 */
typedef struct crmf_optionalvalidity_st
{
	ASN1_TIME *notBefore; /* 0 */
	ASN1_TIME *notAfter;  /* 1 */
} CRMF_OPTIONALVALIDITY;
DECLARE_ASN1_FUNCTIONS(CRMF_OPTIONALVALIDITY)

/*
CertTemplate ::= SEQUENCE {
 version      [0] Version               OPTIONAL,
 serialNumber [1] INTEGER               OPTIONAL,
 signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
 issuer       [3] Name                  OPTIONAL,
 validity     [4] OptionalValidity      OPTIONAL,
 subject      [5] Name                  OPTIONAL,
 publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
 issuerUID    [7] UniqueIdentifier      OPTIONAL,
 subjectUID   [8] UniqueIdentifier      OPTIONAL,
 extensions   [9] Extensions            OPTIONAL }
 */

typedef struct crmf_certtemplate_st
{
	ASN1_INTEGER *version;       /* 0 */
	/* serialNumber MUST be omitted.  This field is assigned by the CA
	 * during certificate creation. */
	ASN1_INTEGER *serialNumber;  /* 1 */
	/* signingAlg MUST be omitted.  This field is assigned by the CA
	 * during certificate creation. */
	X509_ALGOR   *signingAlg;    /* 2 */
	X509_NAME    *issuer;        /* 3 */
	CRMF_OPTIONALVALIDITY *validity; /* 4 */
	X509_NAME    *subject;       /* 5 */
	X509_PUBKEY  *publicKey;     /* 6 */
	/* According to rfc 3280:
	   UniqueIdentifier  ::=  BIT STRING
	   */
	/* issuerUID is deprecated in version 2 */
	ASN1_BIT_STRING *issuerUID;  /* 7 */
	/* subjectUID is deprecated in version 2 */
	ASN1_BIT_STRING *subjectUID; /* 8 */
	STACK_OF(X509_EXTENSION)  *extensions; /* 9 */
	// X509_EXTENSIONS  *extensions; /* 9 */

} CRMF_CERTTEMPLATE;
DECLARE_ASN1_FUNCTIONS(CRMF_CERTTEMPLATE)

/*
CertRequest ::= SEQUENCE {
 certReqId     INTEGER,          -- ID for matching request and reply
 certTemplate  CertTemplate,  -- Selected fields of cert to be issued
 controls      Controls OPTIONAL }   -- Attributes affecting issuance
 */
typedef struct crmf_certrequest_st
{
	ASN1_INTEGER      *certReqId;
	CRMF_CERTTEMPLATE *certTemplate;
	/* XXX is this done right? */
	STACK_OF(CRMF_ATTRIBUTETYPEANDVALUE) *controls;
} CRMF_CERTREQUEST;
DECLARE_ASN1_FUNCTIONS(CRMF_CERTREQUEST)
CRMF_CERTREQUEST *CRMF_CERTREQUEST_dup( CRMF_CERTREQUEST *atav);

typedef struct crmf_attributetypeandvalue_st
{
	ASN1_OBJECT *type;
	union {
		/* NID_id_regCtrl_regToken */ 
		ASN1_UTF8STRING *regToken;

		/* NID_id_regCtrl_authenticator */ 
		ASN1_UTF8STRING *authenticator;

		/* NID_id_regCtrl_pkiPublicationInfo */
		CRMF_PKIPUBLICATIONINFO *pkiPublicationInfo;

		/* NID_id_regCtrl_pkiArchiveOptions */ 
		CRMF_PKIARCHIVEOPTIONS *pkiArchiveOptions;

		/* NID_id_regCtrl_oldCertID */
		CRMF_CERTID     *oldCertId;

		/* NID_id_regCtrl_protocolEncrKey */
		X509_PUBKEY     *protocolEncrKey;

		/* NID_id_regInfo_utf8Pairs */ 
		ASN1_UTF8STRING *utf8pairs;

		/* NID_id_regInfo_certReq */ 
		CRMF_CERTREQUEST *certReq;

		ASN1_TYPE *other;
	} value;
} CRMF_ATTRIBUTETYPEANDVALUE;
DECLARE_ASN1_FUNCTIONS(CRMF_ATTRIBUTETYPEANDVALUE)
DECLARE_STACK_OF(CRMF_ATTRIBUTETYPEANDVALUE)
CRMF_ATTRIBUTETYPEANDVALUE *CRMF_ATTRIBUTETYPEANDVALUE_dup( CRMF_ATTRIBUTETYPEANDVALUE *atav);

/*
CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg

CertReqMsg ::= SEQUENCE {
 certReq   CertRequest,
 popo       ProofOfPossession  OPTIONAL,
 -- content depends upon key type
 regInfo   SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue OPTIONAL }
 */
typedef struct crmf_certreqmsg_st
{
	CRMF_CERTREQUEST           *certReq;
	CRMF_PROOFOFPOSSESION      *popo;    /* 0 */
	STACK_OF(CRMF_ATTRIBUTETYPEANDVALUE) *regInfo; /* 1 */
} CRMF_CERTREQMSG;
DECLARE_ASN1_FUNCTIONS(CRMF_CERTREQMSG)

#if 0
typedef STACK_OF(CRMF_CERTREQMSG) CRMF_CERTREQMESSAGES;
DECLARE_ASN1_FUNCTIONS(CRMF_CERTREQMESSAGES);
#endif 
DECLARE_STACK_OF(CRMF_CERTREQMSG) /* CertReqMessages */
DECLARE_ASN1_SET_OF(CRMF_CERTREQMSG) /* CertReqMessages */


/* DECLARATIONS */
/* crmf_msg.c */
CRMF_CERTREQMSG * CRMF_cr_new( const long certReqId, const EVP_PKEY *pkey, const X509_NAME *subject, const int compatibility, int popoMethod, X509_EXTENSIONS *extensions);

/* crmf_pbm.c */
CRMF_PBMPARAMETER * CRMF_pbm_new(void);
int CRMF_passwordBasedMac_new( const CRMF_PBMPARAMETER *pbm,
                           const unsigned char* msg, size_t msgLen,
                           const unsigned char* secret, size_t secretLen,
                           unsigned char** mac, unsigned int* macLen);


/* crmf_lib.c */
int CRMF_CERTREQMSG_push0_control( CRMF_CERTREQMSG *certReqMsg, CRMF_ATTRIBUTETYPEANDVALUE *control);
int CRMF_CERTREQMSG_push1_control( CRMF_CERTREQMSG *certReqMsg, CRMF_ATTRIBUTETYPEANDVALUE *control);
int CRMF_CERTREQMSG_set1_control_regToken( CRMF_CERTREQMSG *msg, ASN1_UTF8STRING *tok);
int CRMF_CERTREQMSG_set1_control_authenticator( CRMF_CERTREQMSG *msg, ASN1_UTF8STRING *auth);
int CRMF_CERTREQMSG_push0_regInfo( CRMF_CERTREQMSG *certReqMsg, CRMF_ATTRIBUTETYPEANDVALUE *regInfo);
int CRMF_CERTREQMSG_set1_regInfo_regToken( CRMF_CERTREQMSG *msg, ASN1_UTF8STRING *tok);

int CRMF_CERTREQMSG_set_version2( CRMF_CERTREQMSG *certReqMsg);
int CRMF_CERTREQMSG_set_validity( CRMF_CERTREQMSG *certReqMsg, time_t notBefore, time_t notAfter);
int CRMF_CERTREQMSG_set_certReqId( CRMF_CERTREQMSG *certReqMsg, const long certReqId);
int CRMF_CERTREQMSG_set1_publicKey( CRMF_CERTREQMSG *certReqMsg, const EVP_PKEY *pkey);
int CRMF_CERTREQMSG_set1_subject( CRMF_CERTREQMSG *certReqMsg, const X509_NAME *subject);
int CRMF_CERTREQMSG_push0_extension( CRMF_CERTREQMSG *certReqMsg, X509_EXTENSION *ext);

int CRMF_CERTREQMSG_calc_and_set_popo( CRMF_CERTREQMSG *certReqMsg, const EVP_PKEY *pkey, int popoMethod);

CRMF_POPOSIGNINGKEY * CRMF_poposigningkey_new( CRMF_CERTREQUEST *certReq, const EVP_PKEY *pkey);

int CRMF_CERTREQMSG_set1_control_oldCertId( CRMF_CERTREQMSG *certReqMsg, X509 *oldCert);

/* crmf_atav.c */
void CRMF_ATTRIBUTETYPEANDVALUE_get0(ASN1_OBJECT **paobj, int *pptype, void **ppval, CRMF_ATTRIBUTETYPEANDVALUE *atav);
int CRMF_ATTRIBUTETYPEANDVALUE_set0(CRMF_ATTRIBUTETYPEANDVALUE *atav, ASN1_OBJECT *aobj, int ptype, void *pval);
int CRMF_ATTRIBUTETYPEANDVALUE_set0_nid_utf8string( CRMF_ATTRIBUTETYPEANDVALUE *atav, int nid, ASN1_UTF8STRING *utf8str);

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_CRMF_strings(void);

/* Error codes for the CRMF functions. */

/* Function codes. */
#define CRMF_F_CRMF_CERTREQMSG_PUSH0_CONTROL		 100
#define CRMF_F_CRMF_CERTREQMSG_PUSH0_EXTENSION		 101
#define CRMF_F_CRMF_CERTREQMSG_PUSH0_REGINFO		 102
#define CRMF_F_CRMF_CERTREQMSG_SET1_PUBLICKEY		 103
#define CRMF_F_CRMF_CERTREQMSG_SET_VALIDITY		 104
#define CRMF_F_CRMF_CR_NEW				 105
#define CRMF_F_CRMF_PASSWORDBASEDMAC_NEW		 106

/* Reason codes. */
#define CRMF_R_CRMFERROR				 100
#define CRMF_R_ERROR_SETTING_PUBLIC_KEY			 101
#define CRMF_R_UNSUPPORTED_ALGORITHM			 102

#ifdef  __cplusplus
}
#endif
#endif
