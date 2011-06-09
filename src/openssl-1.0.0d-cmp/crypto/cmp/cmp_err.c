/* crypto/cmp/cmp_err.c */
/* ====================================================================
 * Copyright (c) 1999-2010 The OpenSSL Project.  All rights reserved.
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
{ERR_FUNC(CMP_F_CMP_CERTCONF_NEW),	"CMP_certConf_new"},
{ERR_FUNC(CMP_F_CMP_CERTREPMESSAGE_ENCCERT_GET1),	"CMP_CERTREPMESSAGE_encCert_get1"},
{ERR_FUNC(CMP_F_CMP_CERTSTATUS_SET_CERTHASH),	"CMP_CERTSTATUS_set_certHash"},
{ERR_FUNC(CMP_F_CMP_CKUANN_NEW),	"CMP_ckuann_new"},
{ERR_FUNC(CMP_F_CMP_CR_NEW),	"CMP_cr_new"},
{ERR_FUNC(CMP_F_CMP_CTX_CAEXTRACERTS_NUM),	"CMP_CTX_caExtraCerts_num"},
{ERR_FUNC(CMP_F_CMP_CTX_CAEXTRACERTS_POP),	"CMP_CTX_caExtraCerts_pop"},
{ERR_FUNC(CMP_F_CMP_CTX_CAPUBS_NUM),	"CMP_CTX_caPubs_num"},
{ERR_FUNC(CMP_F_CMP_CTX_CAPUBS_POP),	"CMP_CTX_caPubs_pop"},
{ERR_FUNC(CMP_F_CMP_CTX_CREATE),	"CMP_CTX_create"},
{ERR_FUNC(CMP_F_CMP_CTX_EXTRACERTS_NUM),	"CMP_CTX_extraCerts_num"},
{ERR_FUNC(CMP_F_CMP_CTX_EXTRACERTS_PUSH1),	"CMP_CTX_extraCerts_push1"},
{ERR_FUNC(CMP_F_CMP_CTX_INIT),	"CMP_CTX_init"},
{ERR_FUNC(CMP_F_CMP_CTX_SET0_NEWPKEY),	"CMP_CTX_set0_newPkey"},
{ERR_FUNC(CMP_F_CMP_CTX_SET0_PKEY),	"CMP_CTX_set0_pkey"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_CACERT),	"CMP_CTX_set1_caCert"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_CAEXTRACERTS),	"CMP_CTX_set1_caExtraCerts"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_CAPUBS),	"CMP_CTX_set1_caPubs"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_CLCERT),	"CMP_CTX_set1_clCert"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_EXTRACERTS),	"CMP_CTX_set1_extraCerts"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_NEWCLCERT),	"CMP_CTX_set1_newClCert"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_NEWPKEY),	"CMP_CTX_set1_newPkey"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_PKEY),	"CMP_CTX_set1_pkey"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_PROTECTIONALGOR),	"CMP_CTX_set1_protectionAlgor"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_RECIPNONCE),	"CMP_CTX_set1_recipNonce"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_REFERENCEVALUE),	"CMP_CTX_set1_referenceValue"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_SECRETVALUE),	"CMP_CTX_set1_secretValue"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_SERVERNAME),	"CMP_CTX_set1_serverName"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_SERVERPATH),	"CMP_CTX_set1_serverPath"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_SERVERPORT),	"CMP_CTX_set1_serverPort"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_SUBJECTNAME),	"CMP_CTX_set1_subjectName"},
{ERR_FUNC(CMP_F_CMP_CTX_SET1_TRANSACTIONID),	"CMP_CTX_set1_transactionID"},
{ERR_FUNC(CMP_F_CMP_CTX_SET_COMPATIBILITY),	"CMP_CTX_set_compatibility"},
{ERR_FUNC(CMP_F_CMP_CTX_SET_PROTECTIONALGOR),	"CMP_CTX_set_protectionAlgor"},
{ERR_FUNC(CMP_F_CMP_CTX_SUBJECTALTNAME_PUSH1),	"CMP_CTX_subjectAltName_push1"},
{ERR_FUNC(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ),	"CMP_doCertificateRequestSeq"},
{ERR_FUNC(CMP_F_CMP_DOINITIALREQUESTSEQ),	"CMP_doInitialRequestSeq"},
{ERR_FUNC(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ),	"CMP_doKeyUpdateRequestSeq"},
{ERR_FUNC(CMP_F_CMP_DOPKIINFOREQSEQ),	"CMP_doPKIInfoReqSeq"},
{ERR_FUNC(CMP_F_CMP_GENM_NEW),	"CMP_genm_new"},
{ERR_FUNC(CMP_F_CMP_INFOTYPEANDVALUE_NEW_BY_DEF_NOVAL),	"CMP_INFOTYPEANDVALUE_new_by_def_noVal"},
{ERR_FUNC(CMP_F_CMP_IR_NEW),	"CMP_ir_new"},
{ERR_FUNC(CMP_F_CMP_KUR_NEW),	"CMP_kur_new"},
{ERR_FUNC(CMP_F_CMP_PKISTATUSINFO_PKISTATUS_GET_STRING),	"CMP_PKISTATUSINFO_PKIStatus_get_string"},
{ERR_FUNC(CMP_F_CMP_PROTECTION_NEW),	"CMP_protection_new"},
{ERR_FUNC(CMP_F_CMP_PROTECTION_VERIFY),	"CMP_protection_verify"},
{ERR_FUNC(CMP_F_PKEY_DUP),	"PKEY_DUP"},
{0,NULL}
	};

static ERR_STRING_DATA CMP_str_reasons[]=
	{
{ERR_REASON(CMP_R_CERTIFICATE_NOT_FOUND) ,"certificate not found"},
{ERR_REASON(CMP_R_CMPERROR)              ,"cmperror"},
{ERR_REASON(CMP_R_ERROR_DECODING_CERTIFICATE),"error decoding certificate"},
{ERR_REASON(CMP_R_ERROR_DECRYPTING_CERTIFICATE),"error decrypting certificate"},
{ERR_REASON(CMP_R_ERROR_DECRYPTING_KEY)  ,"error decrypting key"},
{ERR_REASON(CMP_R_ERROR_DECRYPTING_SYMMETRIC_KEY),"error decrypting symmetric key"},
{ERR_REASON(CMP_R_ERROR_PARSING_PKISTATUS),"error parsing pkistatus"},
{ERR_REASON(CMP_R_ERROR_RECEIVING_MESSAGE),"error receiving message"},
{ERR_REASON(CMP_R_ERROR_VALIDATING_PROTECTION),"error validating protection"},
{ERR_REASON(CMP_R_FAILED_TO_DETERMINE_PROTECTION_ALGORITHM),"failed to determine protection algorithm"},
{ERR_REASON(CMP_R_INVALID_CONTEXT)       ,"invalid context"},
{ERR_REASON(CMP_R_INVALID_KEY)           ,"invalid key"},
{ERR_REASON(CMP_R_NO_CERTIFICATE_RECEIVED),"no certificate received"},
{ERR_REASON(CMP_R_PKIBODY_ERROR)         ,"pkibody error"},
{ERR_REASON(CMP_R_SUBJECT_NAME_NOT_SET)  ,"subject name not set"},
{ERR_REASON(CMP_R_UNKNOWN_ALGORITHM_ID)  ,"unknown algorithm id"},
{ERR_REASON(CMP_R_UNKNOWN_CIPHER)        ,"unknown cipher"},
{ERR_REASON(CMP_R_UNKNOWN_PKISTATUS)     ,"unknown pkistatus"},
{ERR_REASON(CMP_R_UNSUPPORTED_ALGORITHM) ,"unsupported algorithm"},
{ERR_REASON(CMP_R_UNSUPPORTED_KEY_TYPE)  ,"unsupported key type"},
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
