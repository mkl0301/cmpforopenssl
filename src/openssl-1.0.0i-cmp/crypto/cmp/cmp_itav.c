/* crypto/cmp/cmp_itav.c */

/* Adjusted by Martin Peylo <martin.peylo@nsn.com> */

/* this file is derived from x_algor.c,
 * written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2000.
 */

/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
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
 */

#include <stddef.h>
#include <openssl/cmp.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>

#if 0
int CMP_INFOTYPEANDVALUE_set0(CMP_INFOTYPEANDVALUE *itav, ASN1_OBJECT *aobj, int ptype, void *pval) {
	if (!itav)
		return 0;
	if (ptype != V_ASN1_UNDEF) {
		if (itav->infoValue == NULL)
			itav->infoValue = ASN1_TYPE_new();
		if (itav->infoValue == NULL)
			return 0;
	}
	if (itav) {
		if (itav->infoType)
			ASN1_OBJECT_free(itav->infoType);
		itav->infoType = aobj;
	}
	if (ptype == 0)
		return 1;	
	if (ptype == V_ASN1_UNDEF) {
		if (itav->infoValue) {
			ASN1_TYPE_free(itav->infoValue);
			itav->infoValue = NULL;
		}
	} else
		ASN1_TYPE_set(itav->infoValue, ptype, pval);
	return 1;
}

/* ################################################################ *
 * 
 * ################################################################ */
void CMP_INFOTYPEANDVALUE_get0(ASN1_OBJECT **paobj, int *pptype, void **ppval, CMP_INFOTYPEANDVALUE *itav) {
	if (paobj)
		*paobj = itav->infoType;
	if (pptype) {
		if (itav->infoValue == NULL) {
			*pptype = V_ASN1_UNDEF;
			return;
		} else
			*pptype = itav->infoValue->type;
		if (ppval)
			*ppval = itav->infoValue->value.ptr;
	}
}

CMP_INFOTYPEANDVALUE *CMP_INFOTYPEANDVALUE_new_by_def_noVal(int def) {
	CMP_INFOTYPEANDVALUE *itav=NULL;
	ASN1_OBJECT *obj=NULL;

	switch (def) {
		/* CA Protocol Encryption Certificate */
		case CMP_ITAV_CA_PROT_ENC_CERT:
			obj = OBJ_nid2obj(NID_id_it_caProtEncCert);
			break;
		/* Signing Key Pair Types */
		case CMP_ITAV_SIGN_KEY_PAIR_TYPES:
			obj = OBJ_nid2obj(NID_id_it_signKeyPairTypes);
			break;
		/* Encryption/Key Agreement Key Pair Types */
		case CMP_ITAV_ENC_KEY_PAIR_TYPES:
			obj = OBJ_nid2obj(NID_id_it_encKeyPairTypes);
			break;
		/* Preferred Symmetric Algorithm */
		case CMP_ITAV_PREFERRED_SYMM_ALG:
			obj = OBJ_nid2obj(NID_id_it_preferredSymmAlg);
			break;
		/* Updated CA Key Pair */
		case CMP_ITAV_CA_KEY_UPDATE_INFO:
			obj = OBJ_nid2obj(NID_id_it_caKeyUpdateInfo);
			break;
		/* CRL */
		case CMP_ITAV_CURRENT_CRL:
			obj = OBJ_nid2obj(NID_id_it_currentCRL);
			break;
		/* Unsupported Object Identifiers */
		case CMP_ITAV_UNSUPPORTED_OIDS:
			obj = OBJ_nid2obj(NID_id_it_unsupportedOIDs);
			break;
		/* Key Pair Parameters Request */
		case CMP_ITAV_KEY_PAIR_PARAM_REQ:
			obj = OBJ_nid2obj(NID_id_it_keyPairParamReq);
			break;
		/* Key Pair Parameters Response */
		case CMP_ITAV_KEY_PAIR_PARAM_REP:
			obj = OBJ_nid2obj(NID_id_it_keyPairParamRep);
			break;
		/* Revocation Passphrase */
		case CMP_ITAV_REV_PASSPHRASE:
			obj = OBJ_nid2obj(NID_id_it_revPassphrase);
			break;
		/* ImplicitConfirm */
		case CMP_ITAV_IMPLICIT_CONFIRM:
			obj = OBJ_nid2obj(NID_id_it_implicitConfirm);
			break;
		/* ConfirmWaitTime */
		case CMP_ITAV_CONFIRM_WAIT_TIME:
			obj = OBJ_nid2obj(NID_id_it_confirmWaitTime);
			break;
		/* origPKIMessage */
		case CMP_ITAV_ORIG_PKI_MESSAGE:
			obj = OBJ_nid2obj(NID_id_it_origPKIMessage);
			break;
		/* Supported Language Tags */ /* TODO: put in obj.h */
		case CMP_ITAV_SUPP_LANG_TAGS:
			obj = OBJ_txt2obj("id-it.16",0);
			break;
	/* Defines used by Cryptlib */
		/* 1.3.6.1.4.1.3029.3.1.1 */ /* TODO: put in obj.h */
		case CMP_ITAV_CRYPTLIB:
			obj = OBJ_txt2obj("1.3.6.1.4.1.3029.3.1.1",1);
			break;
		/* 1.3.6.1.4.1.3029.3.1.2 */ /* TODO: put in obj.h */
		case CMP_ITAV_CRYPTLIB_PKIBOOT:
			obj = OBJ_txt2obj("1.3.6.1.4.1.3029.3.1.2",1);
			break;
		default:
			goto err;
			break;
	}

	if (!(itav = CMP_INFOTYPEANDVALUE_new())) goto err;
	if (!CMP_INFOTYPEANDVALUE_set0( itav, obj, V_ASN1_UNDEF, NULL)) goto err;
	return itav;
err:

	if (itav) CMP_INFOTYPEANDVALUE_free(itav);
	return NULL;
}
#endif
