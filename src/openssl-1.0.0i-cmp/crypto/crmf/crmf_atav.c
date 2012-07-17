/* crypto/crmf/crmf_itav.c */

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
#include <openssl/crmf.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#if 0
/* ############################################################################ */
/* ############################################################################ */
int CRMF_ATTRIBUTETYPEANDVALUE_set0(CRMF_ATTRIBUTETYPEANDVALUE *atav, ASN1_OBJECT *aobj, int ptype, void *pval)
	{
	if (!atav)
		return 0;
	if (ptype != V_ASN1_UNDEF) {
		if (atav->value == NULL)
			atav->value = ASN1_TYPE_new();
		if (atav->value == NULL)
			return 0;
	}
	if (atav) {
		if (atav->type)
			ASN1_OBJECT_free(atav->type);
		atav->type = aobj;
	}
	if (ptype == 0)
		return 1;	
	if (ptype == V_ASN1_UNDEF) {
		if (atav->value) {
			ASN1_TYPE_free(atav->value);
			atav->value = NULL;
		}
	}
	else
		ASN1_TYPE_set(atav->value, ptype, pval);
	return 1;
}


/* ############################################################################ */
/* ############################################################################ */
void CRMF_ATTRIBUTETYPEANDVALUE_get0(ASN1_OBJECT **paobj, int *pptype, void **ppval, CRMF_ATTRIBUTETYPEANDVALUE *atav) {
	if (paobj)
		*paobj = atav->type;
	if (pptype) {
		if (atav->value == NULL) {
			*pptype = V_ASN1_UNDEF;
			return;
		} else
			*pptype = atav->value->type;
		if (ppval)
			*ppval = atav->value->value.ptr;
		}
}

/* ############################################################################ */
/* ############################################################################ */
int CRMF_ATTRIBUTETYPEANDVALUE_set0_nid_utf8string( CRMF_ATTRIBUTETYPEANDVALUE *atav, int nid, ASN1_UTF8STRING *utf8str) {
	unsigned char *utf8strDer=NULL;
	int utf8strDerLen;
	ASN1_STRING *utf8strStr=NULL;

	if (!atav) goto err;
	if (!utf8str) goto err;

	utf8strDerLen = i2d_ASN1_UTF8STRING( utf8str, &utf8strDer);
	if (!(utf8strStr = ASN1_STRING_new())) goto err;
	ASN1_STRING_set( utf8strStr, utf8strDer, utf8strDerLen);
	utf8strDer = NULL;

	if( !CRMF_ATTRIBUTETYPEANDVALUE_set0( atav, OBJ_nid2obj(nid), V_ASN1_UTF8STRING, utf8strStr)) goto err;
	utf8strStr = NULL;

	return 1;
err:	
	if (utf8strStr) ASN1_STRING_free( utf8strStr);
	if (utf8strDer) OPENSSL_free( utf8strDer);
	return 0;
}
#endif
