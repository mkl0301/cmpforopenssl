/* crypto/cmp/cmp_err.c */
/* ====================================================================
 * Copyright (c) 1999-2011 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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

/* NOTE: this file was auto generated by the mkerr.pl script: any changes
 * made to it will be overwritten when the script next updates this file,
 * only reason strings will be preserved.
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/cmp.h>

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

#define ERR_FUNC(func) ERR_PACK(ERR_LIB_CMP,func,0)
#define ERR_REASON(reason) ERR_PACK(ERR_LIB_CMP,0,reason)

static ERR_STRING_DATA CMP_str_functs[]=
	{
{ERR_FUNC(CMP_F_CERTREP_GET_CERTIFICATE),	"CERTREP_GET_CERTIFICATE"},
{ERR_FUNC(CMP_F_CMP_CALC_PROTECTION_PBMAC),	"CMP_calc_protection_pbmac"},
{ERR_FUNC(CMP_F_CMP_CALC_PROTECTION_SIG),	"CMP_CALC_PROTECTION_SIG"},
{ERR_FUNC(CMP_F_CMP_CERTCONF_NEW),	"CMP_certConf_new"},
{ERR_FUNC(CMP_F_CMP_CERTREPMESSAGE_ENCCERT_GET1),	"CMP_CERTREPMESSAGE_encCert_get1"},
{ERR_FUNC(CMP_F_CMP_CERTREPMESSAGE_PKIFAILUREINFOSTRING_GET0),	"CMP_CERTREPMESSAGE_PKIFailureInfoString_get0"},
{ERR_FUNC(CMP_F_CMP_CERTREPMESSAGE_PKIFAILUREINFO_GET0),	"CMP_CERTREPMESSAGE_PKIFailureInfo_get0"},
{ERR_FUNC(CMP_F_CMP_CERTREPMESSAGE_PKISTATUSSTRING_GET0),	"CMP_CERTREPMESSAGE_PKIStatusString_get0"},
{ERR_FUNC(CMP_F_CMP_CERTREPMESSAGE_PKISTATUS_GET),	"CMP_CERTREPMESSAGE_PKIStatus_get"},
{ERR_FUNC(CMP_F_CMP_CERTSTATUS_SET_CERTHASH),	"CMP_CERTSTATUS_set_certHash"},
{ERR_FUNC(CMP_F_CMP_CKUANN_NEW),	"CMP_ckuann_new"},
{ERR_FUNC(CMP_F_CMP_CR_NEW),	"CMP_cr_new"},
{ERR_FUNC(CMP_F_CMP_CTX_CAPUBS_GET1),	"CMP_CTX_caPubs_get1"},
{ERR_FUNC(CMP_F_CMP_CTX_CAPUBS_NUM),	"CMP_CTX_caPubs_num"},
{ERR_FUNC(CMP_F_CMP_CTX_CAPUBS_POP),	"CMP_CTX_caPubs_pop"},
{ERR_FUNC(CMP_F_CMP_CTX_CREATE),	"CMP_CTX_create"},
{ERR_FUNC(CMP_F_CMP_CTX_EXTRACERTSIN_GET1),	"CMP_CTX_extraCertsIn_get1"},
{ERR_FUNC(CMP_F_CMP_CTX_EXTRACERTSIN_NUM),	"CMP_CTX_extraCertsIn_num"},
{ERR_FUNC(CMP_F_CMP_CTX_EXTRACERTSIN_POP),	"CMP_CTX_extraCertsIn_pop"},
{ERR_FUNC(CMP_F_CMP_CTX_EXTRACERTS_NUM),	"CMP_CTX_EXTRACERTS_NUM"},
{ERR_FUNC(CMP_F_CMP_CTX_EXTRACERTS_PUSH1),	"CMP_CTX_EXTRACERTS_PUSH1"},
{ERR_FUNC(CMP_F_CMP_CTX_INIT),	"CMP_CTX_init"},
{ERR_FUNC(CMP_F_CMP_CTX_SET0_NEWPKEY),	"CMP_CTX_set0_newPkey"},
{ERR_FUNC(CMP_F_CMP_CTX_SET0_PKEY),	"CMP_CTX_set0_pkey"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_CACERT),	"CMP_CTX_set1_caCert"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_CAEXTRACERTS),	"CMP_CTX_SET1_CAEXTRACERTS"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_CAPUBS),	"CMP_CTX_set1_caPubs"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_CLCERT),	"CMP_CTX_set1_clCert"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_EXTRACERTS),	"CMP_CTX_SET1_EXTRACERTS"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_EXTRACERTSIN),	"CMP_CTX_set1_extraCertsIn"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_NEWCLCERT),	"CMP_CTX_set1_newClCert"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_NEWPKEY),	"CMP_CTX_set1_newPkey"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_PKEY),	"CMP_CTX_set1_pkey"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_POPOMETHOD),	"CMP_CTX_set1_popoMethod"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_PROTECTIONALG),	"CMP_CTX_set1_protectionAlg"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_PROXYNAME),	"CMP_CTX_set1_proxyName"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_PROXYPORT),	"CMP_CTX_set1_proxyPort"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_RECIPIENT),	"CMP_CTX_set1_recipient"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_RECIPNONCE),	"CMP_CTX_set1_recipNonce"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_REFERENCEVALUE),	"CMP_CTX_set1_referenceValue"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_REGTOKEN),	"CMP_CTX_set1_regToken"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_SECRETVALUE),	"CMP_CTX_set1_secretValue"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_SENDER),	"CMP_CTX_set1_sender"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_SERVERNAME),	"CMP_CTX_set1_serverName"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_SERVERPATH),	"CMP_CTX_set1_serverPath"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_SERVERPORT),	"CMP_CTX_set1_serverPort"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_SRVCERT),	"CMP_CTX_set1_srvCert"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_SUBJECTNAME),	"CMP_CTX_set1_subjectName"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_TIMEOUT),	"CMP_CTX_set1_timeOut"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_TRANSACTIONID),	"CMP_CTX_set1_transactionID"},
{ERR_FUNC(CMP_F_CMP_CTX_SET_PROTECTIONALG),	"CMP_CTX_set_protectionAlg"},
{ERR_FUNC(CMP_F_CMP_CTX_SUBJECTALTNAME_PUSH1),	"CMP_CTX_subjectAltName_push1"},
{ERR_FUNC(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ),	"CMP_doCertificateRequestSeq"},
{ERR_FUNC(CMP_F_CMP_DOGENERALMESSAGESEQ),	"CMP_doGeneralMessageSeq"},
{ERR_FUNC(CMP_F_CMP_DOINITIALREQUESTSEQ),	"CMP_doInitialRequestSeq"},
{ERR_FUNC(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ),	"CMP_doKeyUpdateRequestSeq"},
{ERR_FUNC(CMP_F_CMP_DOPKIINFOREQSEQ),	"CMP_doPKIInfoReqSeq"},
{ERR_FUNC(CMP_F_CMP_DOREVOCATIONREQUESTSEQ),	"CMP_doRevocationRequestSeq"},
{ERR_FUNC(CMP_F_CMP_GENM_NEW),	"CMP_genm_new"},
{ERR_FUNC(CMP_F_CMP_IR_NEW),	"CMP_ir_new"},
{ERR_FUNC(CMP_F_CMP_KUR_NEW),	"CMP_kur_new"},
{ERR_FUNC(CMP_F_CMP_NEW_HTTP_BIO_EX),	"CMP_new_http_bio_ex"},
{ERR_FUNC(CMP_F_CMP_PKIMESSAGE_HTTP_BIO_RECV),	"CMP_PKIMESSAGE_HTTP_BIO_RECV"},
{ERR_FUNC(CMP_F_CMP_PKIMESSAGE_HTTP_BIO_SEND),	"CMP_PKIMESSAGE_HTTP_BIO_SEND"},
{ERR_FUNC(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM),	"CMP_PKIMESSAGE_http_perform"},
{ERR_FUNC(CMP_F_CMP_PKIMESSAGE_PARSE_ERROR_MSG),	"CMP_PKIMESSAGE_parse_error_msg"},
{ERR_FUNC(CMP_F_CMP_PKIMESSAGE_PROTECT),	"CMP_PKIMESSAGE_protect"},
{ERR_FUNC(CMP_F_CMP_PKISTATUSINFO_PKISTATUS_GET_STRING),	"CMP_PKISTATUSINFO_PKIStatus_get_string"},
{ERR_FUNC(CMP_F_CMP_POLLREQ_NEW),	"CMP_pollReq_new"},
{ERR_FUNC(CMP_F_CMP_PROTECTION_NEW),	"CMP_protection_new"},
{ERR_FUNC(CMP_F_CMP_PROTECTION_VERIFY),	"CMP_protection_verify"},
{ERR_FUNC(CMP_F_CMP_PROTECT_MSG),	"CMP_PROTECT_MSG"},
{ERR_FUNC(CMP_F_CMP_REVREPCONTENT_PKISTATUS_GET),	"CMP_REVREPCONTENT_PKIStatus_get"},
{ERR_FUNC(CMP_F_CMP_RR_NEW),	"CMP_rr_new"},
{ERR_FUNC(CMP_F_CMP_VALIDATE_CERT_PATH),	"CMP_validate_cert_path"},
{ERR_FUNC(CMP_F_CMP_VALIDATE_MSG),	"CMP_validate_msg"},
{ERR_FUNC(CMP_F_CMP_VERIFY_SIGNATURE),	"CMP_VERIFY_SIGNATURE"},
{ERR_FUNC(CMP_F_PKEY_DUP),	"PKEY_DUP"},
{ERR_FUNC(CMP_F_POLLFORRESPONSE),	"POLLFORRESPONSE"},
{ERR_FUNC(CMP_F_TRY_POLLING),	"TRY_POLLING"},
{0,NULL}
	};

static ERR_STRING_DATA CMP_str_reasons[]=
	{
{ERR_REASON(CMP_R_ALGORITHM_NOT_SUPPORTED),"algorithm not supported"},
{ERR_REASON(CMP_R_CERTIFICATE_NOT_FOUND) ,"certificate not found"},
{ERR_REASON(CMP_R_COULD_NOT_VALIDATE_CERTIFICATE_PATH),"could not validate certificate path"},
{ERR_REASON(CMP_R_CP_NOT_RECEIVED)       ,"cp not received"},
{ERR_REASON(CMP_R_CURL_ERROR)            ,"curl error"},
{ERR_REASON(CMP_R_DEPRECATED_FUNCTION)   ,"deprecated function"},
{ERR_REASON(CMP_R_ERROR_CALCULATING_PROTECTION),"error calculating protection"},
{ERR_REASON(CMP_R_ERROR_CREATING_CERTCONF),"error creating certconf"},
{ERR_REASON(CMP_R_ERROR_CREATING_CKUANN) ,"error creating ckuann"},
{ERR_REASON(CMP_R_ERROR_CREATING_CR)     ,"error creating cr"},
{ERR_REASON(CMP_R_ERROR_CREATING_GENM)   ,"error creating genm"},
{ERR_REASON(CMP_R_ERROR_CREATING_IR)     ,"error creating ir"},
{ERR_REASON(CMP_R_ERROR_CREATING_KUR)    ,"error creating kur"},
{ERR_REASON(CMP_R_ERROR_CREATING_POLLREQ),"error creating pollreq"},
{ERR_REASON(CMP_R_ERROR_CREATING_RR)     ,"error creating rr"},
{ERR_REASON(CMP_R_ERROR_DECODING_CERTIFICATE),"error decoding certificate"},
{ERR_REASON(CMP_R_ERROR_DECRYPTING_CERTIFICATE),"error decrypting certificate"},
{ERR_REASON(CMP_R_ERROR_DECRYPTING_ENCCERT),"error decrypting enccert"},
{ERR_REASON(CMP_R_ERROR_DECRYPTING_KEY)  ,"error decrypting key"},
{ERR_REASON(CMP_R_ERROR_DECRYPTING_SYMMETRIC_KEY),"error decrypting symmetric key"},
{ERR_REASON(CMP_R_ERROR_NONCES_DO_NOT_MATCH),"error nonces do not match"},
{ERR_REASON(CMP_R_ERROR_PARSING_ERROR_MESSAGE),"error parsing error message"},
{ERR_REASON(CMP_R_ERROR_PARSING_PKISTATUS),"error parsing pkistatus"},
{ERR_REASON(CMP_R_ERROR_PROTECTING_MESSAGE),"error protecting message"},
{ERR_REASON(CMP_R_ERROR_REQID_NOT_FOUND) ,"error reqid not found"},
{ERR_REASON(CMP_R_ERROR_SETTING_CERTHASH),"error setting certhash"},
{ERR_REASON(CMP_R_ERROR_SETTING_PROTECTION_ALGORITHM),"error setting protection algorithm"},
{ERR_REASON(CMP_R_ERROR_VALIDATING_PROTECTION),"error validating protection"},
{ERR_REASON(CMP_R_ERROR_VERIFYING_PROTECTION),"error verifying protection"},
{ERR_REASON(CMP_R_FAILED_TO_DECODE_PKIMESSAGE),"failed to decode pkimessage"},
{ERR_REASON(CMP_R_FAILED_TO_DETERMINE_PROTECTION_ALGORITHM),"failed to determine protection algorithm"},
{ERR_REASON(CMP_R_GENP_NOT_RECEIVED)     ,"genp not received"},
{ERR_REASON(CMP_R_INVALID_ARGS)          ,"invalid args"},
{ERR_REASON(CMP_R_INVALID_CONTENT_TYPE)  ,"invalid content type"},
{ERR_REASON(CMP_R_INVALID_CONTEXT)       ,"invalid context"},
{ERR_REASON(CMP_R_INVALID_KEY)           ,"invalid key"},
{ERR_REASON(CMP_R_INVALID_PARAMETERS)    ,"invalid parameters"},
{ERR_REASON(CMP_R_IP_NOT_RECEIVED)       ,"ip not received"},
{ERR_REASON(CMP_R_KUP_NOT_RECEIVED)      ,"kup not received"},
{ERR_REASON(CMP_R_MISSING_KEY_INPUT_FOR_CREATING_PROTECTION),"missing key input for creating protection"},
{ERR_REASON(CMP_R_MISSING_SERVER_CERTIFICATE),"missing server certificate"},
{ERR_REASON(CMP_R_NO_CERTIFICATE_RECEIVED),"no certificate received"},
{ERR_REASON(CMP_R_NO_SECRET_VALUE_GIVEN_FOR_PBMAC),"no secret value given for pbmac"},
{ERR_REASON(CMP_R_NO_TRUSTED_CERTIFICATES_SET),"no trusted certificates set"},
{ERR_REASON(CMP_R_NO_VALID_SRVCERT_FOUND),"no valid srvcert found"},
{ERR_REASON(CMP_R_NULL_ARGUMENT)         ,"null argument"},
{ERR_REASON(CMP_R_PKIBODY_ERROR)         ,"pkibody error"},
{ERR_REASON(CMP_R_PKICONF_NOT_RECEIVED)  ,"pkiconf not received"},
{ERR_REASON(CMP_R_POLLING_FAILED)        ,"polling failed"},
{ERR_REASON(CMP_R_POLLREP_NOT_RECEIVED)  ,"pollrep not received"},
{ERR_REASON(CMP_R_RECEIVED_INVALID_RESPONSE_TO_POLLREQ),"received invalid response to pollreq"},
{ERR_REASON(CMP_R_REQUEST_REJECTED_BY_CA),"request rejected by ca"},
{ERR_REASON(CMP_R_RP_NOT_RECEIVED)       ,"rp not received"},
{ERR_REASON(CMP_R_SERVER_NOT_REACHABLE)  ,"server not reachable"},
{ERR_REASON(CMP_R_SUBJECT_NAME_NOT_SET)  ,"subject name not set"},
{ERR_REASON(CMP_R_UNABLE_TO_CREATE_CONTEXT),"unable to create context"},
{ERR_REASON(CMP_R_UNEXPECTED_PKISTATUS)  ,"unexpected pkistatus"},
{ERR_REASON(CMP_R_UNKNOWN_ALGORITHM_ID)  ,"unknown algorithm id"},
{ERR_REASON(CMP_R_UNKNOWN_CERTTYPE)      ,"unknown certtype"},
{ERR_REASON(CMP_R_UNKNOWN_CIPHER)        ,"unknown cipher"},
{ERR_REASON(CMP_R_UNKNOWN_PKISTATUS)     ,"unknown pkistatus"},
{ERR_REASON(CMP_R_UNSUPPORTED_ALGORITHM) ,"unsupported algorithm"},
{ERR_REASON(CMP_R_UNSUPPORTED_CIPHER)    ,"unsupported cipher"},
{ERR_REASON(CMP_R_UNSUPPORTED_KEY_TYPE)  ,"unsupported key type"},
{ERR_REASON(CMP_R_UNSUPPORTED_PROTECTION_ALG_DHBASEDMAC),"unsupported protection alg dhbasedmac"},
{ERR_REASON(CMP_R_WRONG_ALGORITHM_OID)   ,"wrong algorithm oid"},
{0,NULL}
	};

#endif

void ERR_load_CMP_strings(void)
	{
#ifndef OPENSSL_NO_ERR

	if (ERR_func_error_string(CMP_str_functs[0].error) == NULL)
		{
		ERR_load_strings(0,CMP_str_functs);
		ERR_load_strings(0,CMP_str_reasons);
		}
#endif
	}
