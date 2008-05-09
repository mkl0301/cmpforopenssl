/* crypto/crmf/crmf_msg.c
 *
 * Functions for creating CRMF (RFC 4211) messages for OpenSSL
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

/* ############################################################################ */
/* In this file are the functions which build and evaluate the CRMF messages    */
/* ############################################################################ */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crmf.h>
#include <openssl/evp.h>
#include <openssl/cmp.h> /* for the CMP_COMPAT_* flags */


/* ############################################################################ */
/* XXX is the naming of this function sane? Is it too connected to CMP? */
/* TODO there are some optional settings which are not cared for right now */
CRMF_CERTREQMSG * CRMF_cr_new( const long certReqId, const EVP_PKEY *pkey, const X509_NAME *subject, const int compatibility) {
	CRMF_CERTREQMSG *certReqMsg;

	if( !(certReqMsg = CRMF_CERTREQMSG_new())) goto err;

	/* This SHOULD be omitted - INSTA requires this */
	/* it answers with a "timeNotAvailable" Error if this is not present */
	if( (compatibility == CMP_COMPAT_INSTA) || (compatibility == CMP_COMPAT_INSTA_3_3)) {
		/* version MUST be 2 if supplied.  It SHOULD be omitted. */
		CRMF_CERTREQMSG_set_version2( certReqMsg);
	}

#if 0
	/* serialNumber MUST be ommited - INSTA does it but it does *NOT require* it */
	/* XXX just for figuring out how they calculate the protection */
	if( (compatibility == CMP_COMPAT_INSTA) || (compatibility == CMP_COMPAT_INSTA_3_3)) {
		certReqMsg->certReq->certTemplate->serialNumber = ASN1_INTEGER_new();
		ASN1_INTEGER_set( certReqMsg->certReq->certTemplate->serialNumber, 0L);
#warning serialNumber for INSTA is hardcoded
	}

	/* signingAlg MUST be ommited - INSTA does it but it does *NOT require* it */
	/* XXX just for figuring out how they calculate the protection */
	if( (compatibility == CMP_COMPAT_INSTA) || (compatibility == CMP_COMPAT_INSTA_3_3)) {
		certReqMsg->certReq->certTemplate->signingAlg = X509_ALGOR_new();
		X509_ALGOR_set0( certReqMsg->certReq->certTemplate->signingAlg, OBJ_nid2obj(NID_sha1WithRSAEncryption), V_ASN1_NULL, NULL);
#warning signingAlg for INSTA is hardcoded
	}
#endif

	CRMF_CERTREQMSG_set_certReqId( certReqMsg, certReqId);
	if (!CRMF_CERTREQMSG_set1_publicKey( certReqMsg, pkey))
		printf("ERROR: setting public key, FILE %s, LINE %d\n", __FILE__, __LINE__);

#if 0
	/* CL supports this (for client certificates) for up to 3 years in the future for both dates
	 * in case the notBefore date is in the past it will be set to the current date without any comment */
	int CRMF_CERTREQMSG_set_validity( CRMF_CERTREQMSG *certReqMsg, time_t notBefore, time_t notAfter);
#endif
	CRMF_CERTREQMSG_set1_subject( certReqMsg, subject);
#if 0
	/* this could be done here */
	int CRMF_CERTREQMSG_push0_extension( CRMF_CERTREQMSG *certReqMsg, X509_EXTENSION *ext);
#endif
	CRMF_CERTREQMSG_calc_and_set_popo( certReqMsg, pkey);

	return certReqMsg;
err:
	if( certReqMsg)
		CRMF_CERTREQMSG_free( certReqMsg);
	return NULL;
}

