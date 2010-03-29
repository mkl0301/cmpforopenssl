/* cmp_asn.c
 *
 * OpenSSL ASN.1 definitions for CMP (RFC 4210)
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

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crmf.h>
#include <openssl/cmp.h>

ASN1_SEQUENCE(CMP_REVANNCONTENT) = {
	ASN1_SIMPLE(CMP_REVANNCONTENT, status, ASN1_INTEGER),
	ASN1_SIMPLE(CMP_REVANNCONTENT, certId, CRMF_CERTID),
	ASN1_SIMPLE(CMP_REVANNCONTENT, willBeRevokedAt, ASN1_GENERALIZEDTIME),
	ASN1_SIMPLE(CMP_REVANNCONTENT, badSinceDate, ASN1_GENERALIZEDTIME),
	ASN1_EXP_SEQUENCE_OF_OPT(CMP_REVANNCONTENT, crlDetails, X509_EXTENSION,0)
} ASN1_SEQUENCE_END(CMP_REVANNCONTENT)
IMPLEMENT_ASN1_FUNCTIONS(CMP_REVANNCONTENT)


ASN1_SEQUENCE(CMP_CHALLENGE) = {
	/* XXX EXP ...? */
	ASN1_OPT(CMP_CHALLENGE, owf, X509_ALGOR),
	ASN1_SIMPLE(CMP_CHALLENGE, whitness, ASN1_OCTET_STRING),
	ASN1_SIMPLE(CMP_CHALLENGE, challenge, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(CMP_CHALLENGE)
IMPLEMENT_ASN1_FUNCTIONS(CMP_CHALLENGE)


ASN1_SEQUENCE(CMP_CAKEYUPDANNCONTENT) = {
#if 0
/* the rfc allows substituting CMPCertificate with "Certificate"... */
	ASN1_SIMPLE(CMP_CAKEYUPDANNCONTENT, oldWithNew, CMP_CMPCERTIFICATE),
	ASN1_SIMPLE(CMP_CAKEYUPDANNCONTENT, newWithOld, CMP_CMPCERTIFICATE),
	ASN1_SIMPLE(CMP_CAKEYUPDANNCONTENT, newWithNew, CMP_CMPCERTIFICATE)
#endif
	ASN1_SIMPLE(CMP_CAKEYUPDANNCONTENT, oldWithNew, X509),
	ASN1_SIMPLE(CMP_CAKEYUPDANNCONTENT, newWithOld, X509),
	ASN1_SIMPLE(CMP_CAKEYUPDANNCONTENT, newWithNew, X509)
} ASN1_SEQUENCE_END(CMP_CAKEYUPDANNCONTENT)
IMPLEMENT_ASN1_FUNCTIONS(CMP_CAKEYUPDANNCONTENT)


ASN1_SEQUENCE(CMP_ERRORMSGCONTENT) = {
	ASN1_SIMPLE(CMP_ERRORMSGCONTENT, pKIStatusInfo, CMP_PKISTATUSINFO),
	ASN1_OPT(CMP_ERRORMSGCONTENT, errorCode, ASN1_INTEGER),
#if 0
	ASN1_OPT(CMP_ERRORMSGCONTENT, errorDetails, CMP_PKIFREETEXT)
#endif
	ASN1_SEQUENCE_OF_OPT(CMP_ERRORMSGCONTENT, errorDetails, ASN1_UTF8STRING)
} ASN1_SEQUENCE_END(CMP_ERRORMSGCONTENT)
IMPLEMENT_ASN1_FUNCTIONS(CMP_ERRORMSGCONTENT)

#if 0
/* XXX USING THAT DOES NOT WORK FOR SOME REASON */
/* the rfc allows substituting that with "Certificate"... */
ASN1_CHOICE(CMP_CMPCERTIFICATE) = {
	ASN1_EXP(CMP_CMPCERTIFICATE, value.x509v3PKCert, X509, 0)
} ASN1_CHOICE_END(CMP_CMPCERTIFICATE)
IMPLEMENT_ASN1_FUNCTIONS(CMP_CMPCERTIFICATE)
#endif

ASN1_SEQUENCE(CMP_INFOTYPEANDVALUE) = {
	ASN1_SIMPLE(CMP_INFOTYPEANDVALUE, infoType, ASN1_OBJECT),
	ASN1_OPT(CMP_INFOTYPEANDVALUE, infoValue, ASN1_ANY)
} ASN1_SEQUENCE_END(CMP_INFOTYPEANDVALUE)
IMPLEMENT_ASN1_FUNCTIONS(CMP_INFOTYPEANDVALUE)


ASN1_CHOICE(CMP_CERTORENCCERT) = {
#if 0
	ASN1_EXP(CMP_CERTORENCCERT, value.certificate, CMP_CMPCERTIFICATE, 0),
#endif
	ASN1_EXP(CMP_CERTORENCCERT, value.certificate, X509, 0),
	ASN1_EXP(CMP_CERTORENCCERT, value.encryptedCert, CRMF_ENCRYPTEDVALUE, 1),
} ASN1_CHOICE_END(CMP_CERTORENCCERT)
IMPLEMENT_ASN1_FUNCTIONS(CMP_CERTORENCCERT)


ASN1_SEQUENCE(CMP_CERTIFIEDKEYPAIR) = {
	ASN1_SIMPLE(CMP_CERTIFIEDKEYPAIR, certOrEncCert, CMP_CERTORENCCERT),
	ASN1_EXP_OPT(CMP_CERTIFIEDKEYPAIR, privateKey, CRMF_ENCRYPTEDVALUE,0),
	ASN1_EXP_OPT(CMP_CERTIFIEDKEYPAIR, failInfo, CRMF_PKIPUBLICATIONINFO,1)
} ASN1_SEQUENCE_END(CMP_CERTIFIEDKEYPAIR)
IMPLEMENT_ASN1_FUNCTIONS(CMP_CERTIFIEDKEYPAIR)


ASN1_SEQUENCE(CMP_REVDETAILS) = {
	ASN1_SIMPLE(CMP_REVDETAILS, certDetails, CRMF_CERTTEMPLATE),
	ASN1_OPT(CMP_REVDETAILS, crlEntryDetails, X509_EXTENSION)
} ASN1_SEQUENCE_END(CMP_REVDETAILS)
IMPLEMENT_ASN1_FUNCTIONS(CMP_REVDETAILS)


ASN1_SEQUENCE(CMP_KEYRECREPCONTENT) = {
	ASN1_SIMPLE(CMP_KEYRECREPCONTENT, status, CMP_PKISTATUSINFO),
	/* XXX CMPcertificate ::= Certificate */
	ASN1_EXP_OPT(CMP_KEYRECREPCONTENT, newSigCert, X509, 0),
	/* XXX CMPcertificate ::= Certificate */
	ASN1_EXP_SEQUENCE_OF_OPT(CMP_KEYRECREPCONTENT, caCerts, X509, 1),
	ASN1_EXP_SEQUENCE_OF_OPT(CMP_KEYRECREPCONTENT, keyPairHist, X509, 2)
} ASN1_SEQUENCE_END(CMP_KEYRECREPCONTENT)
IMPLEMENT_ASN1_FUNCTIONS(CMP_KEYRECREPCONTENT)


ASN1_SEQUENCE(CMP_PKISTATUSINFO) = {
/* XXX this should actually be */
#if 0
	ASN1_SIMPLE(CMP_PKISTATUSINFO, status, CMP_PKISTATUS),
#endif
	ASN1_SIMPLE(CMP_PKISTATUSINFO, status, ASN1_INTEGER),
#if 0
	ASN1_OPT(CMP_PKISTATUSINFO, statusString, CMP_PKIFREETEXT),
#endif
	ASN1_SEQUENCE_OF_OPT(CMP_PKISTATUSINFO, statusString, ASN1_UTF8STRING),
/* XXX this should actually be */
#if 0
	ASN1_OPT(CMP_PKISTATUSINFO, failInfo, CMP_PKIFAILUREINFO)
#endif
	ASN1_OPT(CMP_PKISTATUSINFO, failInfo, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(CMP_PKISTATUSINFO)
IMPLEMENT_ASN1_FUNCTIONS(CMP_PKISTATUSINFO)


ASN1_SEQUENCE(CMP_CERTSTATUS) = {
	ASN1_SIMPLE(CMP_CERTSTATUS, certHash, ASN1_OCTET_STRING),
	ASN1_SIMPLE(CMP_CERTSTATUS, certReqId, ASN1_INTEGER),
	ASN1_EXP_OPT(CMP_CERTSTATUS, statusInfo, CMP_PKISTATUSINFO,0)
} ASN1_SEQUENCE_END(CMP_CERTSTATUS)
IMPLEMENT_ASN1_FUNCTIONS(CMP_CERTSTATUS)


#if 0
/* XXX is this OK? what is "0" for? */
ASN1_ITEM_TEMPLATE(CMP_CERTCONFIRMCONTENT) =
/* XXX is EXPTAG ok? */
	ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_EXPTAG, 0, CMP_CERTCONFIRMCONTENT, CMP_CERTSTATUS)
ASN1_ITEM_TEMPLATE_END(CMP_CERTCONFIRMCONTENT)
IMPLEMENT_ASN1_FUNCTIONS(CMP_CERTCONFIRMCONTENT)
#endif


ASN1_SEQUENCE(CMP_CERTRESPONSE) = {
	ASN1_SIMPLE(CMP_CERTRESPONSE, certReqId, ASN1_INTEGER),
	ASN1_SIMPLE(CMP_CERTRESPONSE, status, CMP_PKISTATUSINFO),
	ASN1_OPT(CMP_CERTRESPONSE, certifiedKeyPair, CMP_CERTIFIEDKEYPAIR),
	ASN1_OPT(CMP_CERTRESPONSE, rspInfo, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(CMP_CERTRESPONSE)
IMPLEMENT_ASN1_FUNCTIONS(CMP_CERTRESPONSE)


ASN1_SEQUENCE(CMP_CERTREPMESSAGE) = {
	//ASN1_EXP_SEQUENCE_OF_OPT(CMP_CERTREPMESSAGE, caPubs, CMP_CMPCERTIFICATE,1),
	ASN1_EXP_SEQUENCE_OF_OPT(CMP_CERTREPMESSAGE, caPubs, X509,1),
	ASN1_SEQUENCE_OF(CMP_CERTREPMESSAGE, response, CMP_CERTRESPONSE)
} ASN1_SEQUENCE_END(CMP_CERTREPMESSAGE)
IMPLEMENT_ASN1_FUNCTIONS(CMP_CERTREPMESSAGE)


/* XXX EXP_OPT or not OPT? */
ASN1_CHOICE(CMP_PKIBODY) = {
	ASN1_EXP_SEQUENCE_OF(CMP_PKIBODY, value.ir, CRMF_CERTREQMSG, 0),
	ASN1_EXP(CMP_PKIBODY, value.ip, CMP_CERTREPMESSAGE, 1),
	ASN1_EXP_SEQUENCE_OF(CMP_PKIBODY, value.cr, CRMF_CERTREQMSG, 2),
	ASN1_EXP(CMP_PKIBODY, value.cp, CMP_CERTREPMESSAGE, 3),
/* TODO */
ASN1_EXP(CMP_PKIBODY, value.p10cr, ASN1_INTEGER, 4),
	ASN1_EXP_SEQUENCE_OF(CMP_PKIBODY, value.popdecc, CMP_CHALLENGE, 5),
	ASN1_EXP_SEQUENCE_OF(CMP_PKIBODY, value.popdecr, ASN1_INTEGER, 6),
	ASN1_EXP_SEQUENCE_OF(CMP_PKIBODY, value.kur, CRMF_CERTREQMSG, 7),
	ASN1_EXP(CMP_PKIBODY, value.kup, CMP_CERTREPMESSAGE, 8),
	ASN1_EXP_SEQUENCE_OF(CMP_PKIBODY, value.krr, CRMF_CERTREQMSG, 9),
	ASN1_EXP(CMP_PKIBODY, value.krp, CMP_KEYRECREPCONTENT, 10),
	ASN1_EXP_SEQUENCE_OF(CMP_PKIBODY, value.rr, CMP_REVDETAILS, 11),
	ASN1_EXP_SEQUENCE_OF(CMP_PKIBODY, value.rp, CRMF_CERTREQMSG, 12),
	ASN1_EXP_SEQUENCE_OF(CMP_PKIBODY, value.crr, CRMF_CERTREQMSG, 13),
	ASN1_EXP(CMP_PKIBODY, value.ccp, CMP_CERTREPMESSAGE, 14),
	ASN1_EXP(CMP_PKIBODY, value.ckuann, CMP_CAKEYUPDANNCONTENT, 15),
	ASN1_EXP(CMP_PKIBODY, value.cann, X509, 16),
	ASN1_EXP(CMP_PKIBODY, value.rann, CMP_REVANNCONTENT, 17),
/* TODO */
ASN1_EXP(CMP_PKIBODY, value.crlann, ASN1_INTEGER, 18),
#if 0
	/* CMP_PKICONFIRMCONTENT would be only a typedfef of ASN1_NULL */
	/* ASN1_EXP(CMP_PKIBODY, value.pkiconf, CMP_PKICONFIRMCONTENT, 19), */
	/* XXX it should be the following according to the RFC but CL puts it in a struct */
	ASN1_EXP(CMP_PKIBODY, value.pkiconf, ASN1_NULL, 19),
#endif
	ASN1_EXP(CMP_PKIBODY, value.pkiconf, ASN1_ANY, 19),
	ASN1_EXP_SEQUENCE_OF(CMP_PKIBODY, value.nested, CMP_PKIMESSAGE, 20),
	ASN1_EXP_SEQUENCE_OF(CMP_PKIBODY, value.genm, CMP_INFOTYPEANDVALUE, 21),
	ASN1_EXP_SEQUENCE_OF(CMP_PKIBODY, value.genp, CMP_INFOTYPEANDVALUE, 22),
	ASN1_EXP(CMP_PKIBODY, value.error, CMP_ERRORMSGCONTENT, 23),
	/* XXX this should actually be: */
#if 0
	ASN1_EXP(CMP_PKIBODY, value.certConf, CMP_CERTCONFIRMCONTENT, 24)
#endif
	ASN1_EXP_SEQUENCE_OF(CMP_PKIBODY, value.certConf, CMP_CERTSTATUS, 24),
/* TODO */
ASN1_EXP(CMP_PKIBODY, value.pollReq, ASN1_INTEGER, 25),
/* TODO */
ASN1_EXP(CMP_PKIBODY, value.pollRep, ASN1_INTEGER, 26)
} ASN1_CHOICE_END(CMP_PKIBODY)
IMPLEMENT_ASN1_FUNCTIONS(CMP_PKIBODY)

#if 0
XXX this does not work
/* XXX this comes from just a typedef */
IMPLEMENT_ASN1_FUNCTIONS(XXX_KEYIDENTIFIER)
#endif

#if 0
ASN1_ITEM_TEMPLATE(CMP_PKIFREETEXT) =
	ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, PKIFreeText, ASN1_UTF8STRING)
	ASN1_ITEM_TEMPLATE_END(CMP_PKIFREETEXT)

IMPLEMENT_ASN1_FUNCTIONS(CMP_PKIFREETEXT)
#endif


ASN1_SEQUENCE(CMP_PKIHEADER) = {
	ASN1_SIMPLE(CMP_PKIHEADER, pvno, ASN1_INTEGER),
	ASN1_SIMPLE(CMP_PKIHEADER, sender, GENERAL_NAME),
	ASN1_SIMPLE(CMP_PKIHEADER, recipient, GENERAL_NAME),
	ASN1_EXP_OPT(CMP_PKIHEADER, messageTime, ASN1_GENERALIZEDTIME,0),
	ASN1_EXP_OPT(CMP_PKIHEADER, protectionAlg, X509_ALGOR,1),
	ASN1_EXP_OPT(CMP_PKIHEADER, senderKID, ASN1_OCTET_STRING,2),
	ASN1_EXP_OPT(CMP_PKIHEADER, recipKID, ASN1_OCTET_STRING,3),
	ASN1_EXP_OPT(CMP_PKIHEADER, transactionID, ASN1_OCTET_STRING,4),
	ASN1_EXP_OPT(CMP_PKIHEADER, senderNonce, ASN1_OCTET_STRING,5),
	ASN1_EXP_OPT(CMP_PKIHEADER, recipNonce, ASN1_OCTET_STRING,6),
#if 0
	ASN1_EXP_OPT(CMP_PKIHEADER, freeText, CMP_PKIFREETEXT,7),
#endif
	ASN1_EXP_SEQUENCE_OF_OPT(CMP_PKIHEADER, freeText, ASN1_UTF8STRING,7),
	ASN1_EXP_SEQUENCE_OF_OPT(CMP_PKIHEADER, generalInfo, CMP_INFOTYPEANDVALUE,8)
} ASN1_SEQUENCE_END(CMP_PKIHEADER)
IMPLEMENT_ASN1_FUNCTIONS(CMP_PKIHEADER)

ASN1_SEQUENCE(CMP_PROTECTEDPART) = {
	ASN1_SIMPLE(CMP_PKIMESSAGE, header, CMP_PKIHEADER),
	ASN1_SIMPLE(CMP_PKIMESSAGE, body, CMP_PKIBODY)
} ASN1_SEQUENCE_END(CMP_PROTECTEDPART)
IMPLEMENT_ASN1_FUNCTIONS(CMP_PROTECTEDPART);

#if 0
XXX this does not work
/* XXX this comes from just a typedef */
IMPLEMENT_ASN1_FUNCTIONS(CMP_PKIPROTECTION)
#endif


ASN1_SEQUENCE(CMP_PKIMESSAGE) = {
	ASN1_SIMPLE(CMP_PKIMESSAGE, header, CMP_PKIHEADER),
	ASN1_SIMPLE(CMP_PKIMESSAGE, body, CMP_PKIBODY),
	/* IMP OR EXP? */
	ASN1_EXP_OPT(CMP_PKIMESSAGE, protection, ASN1_BIT_STRING,0),
	//ASN1_EXP_SEQUENCE_OF_OPT(CMP_PKIMESSAGE, extraCerts, CMP_CMPCERTIFICATE,1)
	ASN1_EXP_SEQUENCE_OF_OPT(CMP_PKIMESSAGE, extraCerts, X509,1)
} ASN1_SEQUENCE_END(CMP_PKIMESSAGE)
IMPLEMENT_ASN1_FUNCTIONS(CMP_PKIMESSAGE)


/* XXX is this OK? what is "0" for? */
ASN1_ITEM_TEMPLATE(CMP_PKIMESSAGES) =
/* XXX is EXPTAG ok? */
ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_EXPTAG, 0, CMP_PKIMESSAGES, CMP_PKIMESSAGE)
ASN1_ITEM_TEMPLATE_END(CMP_PKIMESSAGES)



/* XXX HELPERS - where should they actually be? */
/* In question - all were declared IMPLICIT */
ASN1_SEQUENCE(ESS_ISSUERSERIAL) = {
	ASN1_SEQUENCE_OF(ESS_ISSUERSERIAL, issuer, GENERAL_NAME),
	ASN1_SIMPLE(ESS_ISSUERSERIAL, serialNumber, ASN1_INTEGER)
} ASN1_SEQUENCE_END(ESS_ISSUERSERIAL)
IMPLEMENT_ASN1_FUNCTIONS(ESS_ISSUERSERIAL)

ASN1_SEQUENCE(ESS_ESSCERTID) = {
	ASN1_SIMPLE(ESS_ESSCERTID, certHash, ASN1_OCTET_STRING),
	ASN1_OPT(ESS_ESSCERTID, issuerSerial, ESS_ISSUERSERIAL)
} ASN1_SEQUENCE_END(ESS_ESSCERTID)
IMPLEMENT_ASN1_FUNCTIONS(ESS_ESSCERTID)

ASN1_SEQUENCE(ESS_SIGNINGCERTIFICATE) = {
	ASN1_SEQUENCE_OF(ESS_SIGNINGCERTIFICATE, certs, ESS_ESSCERTID),
	ASN1_SEQUENCE_OF_OPT(ESS_SIGNINGCERTIFICATE, policies, POLICYINFO)
} ASN1_SEQUENCE_END(ESS_SIGNINGCERTIFICATE)
IMPLEMENT_ASN1_FUNCTIONS(ESS_SIGNINGCERTIFICATE)
