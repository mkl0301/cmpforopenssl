/* crypto/cmp/cmp_ses.c
 * 
 * Functions to do CMP (RFC 4210) message sequences for OpenSSL
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

#include <openssl/cmp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>


/* ############################################################################ */
/* ############################################################################ */
X509 *CMP_doInitialRequestSeq( BIO *cbio, CMP_CTX *ctx) {
	CMP_PKIMESSAGE *ir=NULL;
	CMP_PKIMESSAGE *ip=NULL;
	CMP_PKIMESSAGE *certConf=NULL;
	CMP_PKIMESSAGE *PKIconf=NULL;

	/* check if all necessary options are set */
	if (!cbio) goto err;
	if (!ctx) goto err;
	if (!ctx->caCert) goto err;
	if (!ctx->referenceValue) goto err;
	if (!ctx->secretValue) goto err;
	if (!ctx->pkey) goto err;

	/* this can not have been set here */
	if (ctx->clCert) goto err;

	/* set the protection Algor which will be used during the whole session */
	if ( !CMP_CTX_set_protectionAlgor( ctx, CMP_ALG_PBMAC)) goto err;

	/* create Initialization Request - ir */
	if (! (ir = CMP_ir_new(ctx))) goto err;

	printf("INFO: Sending Initialization Request\n");
	if (! CMP_PKIMESSAGE_http_bio_send(cbio, ctx->serverName, ctx->serverPort, ctx->serverPath, ctx->compatibility, ir))
		goto err;

	/* receive Initialization Response - ip */
	printf("INFO: Attempting to receive IP\n");
	if (! CMP_PKIMESSAGE_http_bio_recv(cbio, &ip, ctx->compatibility))
		goto err;

	if (CMP_protection_verify( ip, ctx->protectionAlgor, NULL, ctx->secretValue))
		printf( "SUCCESS: validating protection of incoming message\n");
	else {
		printf( "ERROR: validating protection of incoming message\n");
		goto err;
	}

	/* make sure the received messagetype indicates an IP message */
	switch (CMP_PKIMESSAGE_get_bodytype(ip)) {
		case V_CMP_PKIBODY_IP:
			/* this is the expected outcome at SUCCESS: */
			break;
		case V_CMP_PKIBODY_ERROR:
			printf( "ERROR: received an ERROR: %d Message\n", CMP_PKIMESSAGE_get_bodytype( ip));
			CMP_PKIMESSAGE_parse_error_msg( ip);
			goto err;
			break;
		default:
			printf( "ERROR: received neither an IP nor an ERROR: but %d Message\n", CMP_PKIMESSAGE_get_bodytype( ip));
			goto err;
			break;
	}

	/* make sure the PKIStatus for the *first* CERTrepmessage indicates a certificate was granted */
	/* TODO - there could be two CERTrepmessages */
	switch (CMP_CERTREPMESSAGE_PKIStatus_get( ip->body->value.ip, 0)) {
		case CMP_PKISTATUS_grantedWithMods:
			printf( "WARNING: got \"grantedWithMods\"\n");
		case CMP_PKISTATUS_accepted:
			if( !(ctx->newClCert = CMP_CERTREPMESSAGE_cert_get1(ip->body->value.ip,0))) {
				printf( "ERROR: could not find the certificate with certReqId=0\nFILE %s, LINE %d\n", __FILE__, __LINE__);
				goto err;
			}
			break;
		case CMP_PKISTATUS_rejection:
		case CMP_PKISTATUS_waiting:
		case CMP_PKISTATUS_revocationWarning:
		case CMP_PKISTATUS_revocationNotification:
		case CMP_PKISTATUS_keyUpdateWarning:
			printf( "ERROR: didn't get a certificate\n");
			goto err;
			break;
		default:
			printf( "ERROR: got an unknown PKIStatus\n");
			goto err;
			break;
	}

	/* check if implicit confirm is set in generalInfo */
	/* TODO should I check if that was requested?
	 * What happens if this is set here while it was not requested?
	 */
	if (CMP_PKIMESSAGE_check_implicitConfirm(ip)) goto cleanup;

	/* create Certificate Confirmation - certConf */
	if (! (certConf = CMP_certConf_new(ctx))) goto err;

	printf("INFO: Sending Certificate Confirm\n");
	if (! CMP_PKIMESSAGE_http_bio_send(cbio, ctx->serverName, ctx->serverPort, ctx->serverPath, ctx->compatibility, certConf))
		goto err;

	/* receive PKIconf - PKIconf */
	printf("INFO: Attempting to receive PKIconf\n");
	if (! CMP_PKIMESSAGE_http_bio_recv(cbio, &PKIconf, ctx->compatibility))
		goto err;

	if (CMP_protection_verify( PKIconf, ctx->protectionAlgor, NULL, ctx->secretValue))
		printf( "SUCCESS: validating protection of incoming message\n");
	else {
		printf( "ERROR: validating protection of incoming message\n");
		goto err;
	}

	/* make sure the received messagetype indicates an PKIconf message */
	switch (CMP_PKIMESSAGE_get_bodytype(PKIconf)) {
		case V_CMP_PKIBODY_PKICONF:
			break;
		case V_CMP_PKIBODY_ERROR:
			printf( "ERROR: received an ERROR: %d Message\n", CMP_PKIMESSAGE_get_bodytype( PKIconf));
			CMP_PKIMESSAGE_parse_error_msg( PKIconf);
			goto err;
			break;
		default:
			printf( "ERROR: received neither an PKIconf nor an ERROR: but a %d Message\n", CMP_PKIMESSAGE_get_bodytype( PKIconf));
			goto err;
			break;
	}

cleanup:
	/* clean up */
	CMP_PKIMESSAGE_free(ir);
	CMP_PKIMESSAGE_free(ip);
	/* those are not set in case of implicitConfirm */
	if (certConf) CMP_PKIMESSAGE_free(certConf);
	if (PKIconf) CMP_PKIMESSAGE_free(PKIconf);
	return ctx->newClCert;
err:
printf( "ERROR: in CMP_doInitialRequestSeq, FILE: %s, LINE: %d\n", __FILE__, __LINE__);
	if (ir) CMP_PKIMESSAGE_free(ir);
	if (ip) CMP_PKIMESSAGE_free(ip);
	if (certConf) CMP_PKIMESSAGE_free(certConf);
	if (PKIconf) CMP_PKIMESSAGE_free(PKIconf);
	return NULL;
}


/* ############################################################################ */
/* ############################################################################ */
X509 *CMP_doKeyUpdateRequestSeq( BIO *cbio, CMP_CTX *ctx) {
	CMP_PKIMESSAGE *kur=NULL;
	CMP_PKIMESSAGE *kup=NULL;
	CMP_PKIMESSAGE *certConf=NULL;
	CMP_PKIMESSAGE *PKIconf=NULL;

	/* check if all necessary options are set */
	if (!cbio) goto err;
	if (!ctx) goto err;
	if (!ctx->serverName) goto err;
	if (!ctx->pkey) goto err;
	if (!ctx->newPkey) goto err;
	if (!ctx->clCert) goto err;
	if (!ctx->caCert) goto err;

	/* set the protection Algor which will be used during the whole session */
	CMP_CTX_set_protectionAlgor( ctx, CMP_ALG_SIG);

	/* create Key Update Request - kur */
	if (! (kur = CMP_kur_new(ctx))) goto err;

	printf("INFO: Sending Key Update Request\n");
	if (! CMP_PKIMESSAGE_http_bio_send(cbio, ctx->serverName, ctx->serverPort, ctx->serverPath, ctx->compatibility, kur))
		goto err;

	/* receive Key Update Response - kup */
	printf("INFO: Attempting to receive KUP\n");
	if (! CMP_PKIMESSAGE_http_bio_recv(cbio, &kup, ctx->compatibility))
		goto err;

	switch (CMP_PKIMESSAGE_get_bodytype( kup)) {
		case V_CMP_PKIBODY_KUP: 
			break;
		case V_CMP_PKIBODY_ERROR:
			printf( "ERROR: received an ERROR: %d Message\n", CMP_PKIMESSAGE_get_bodytype( kup));
			CMP_PKIMESSAGE_parse_error_msg( kup);
			goto err;
			break;
		case -1:
			printf( "ERROR: received NO message, FILE: %s, LINE: %d\n", __FILE__, __LINE__);
			exit(0);
		default:		
			printf( "ERROR: received not KUP message, but %d, FILE: %s, LINE: %d\n", CMP_PKIMESSAGE_get_bodytype( kup),__FILE__, __LINE__);
			break;
	}
	if (CMP_protection_verify( kup, ctx->protectionAlgor, X509_get_pubkey( (X509*) ctx->caCert), NULL)) {
		printf( "SUCCESS: validating protection of incoming message\n");
	} else {
		printf( "ERROR: validating protection of incoming message\n");
		goto err;
	}

	switch (CMP_CERTREPMESSAGE_PKIStatus_get( kup->body->value.kup, 0)) {
		case CMP_PKISTATUS_grantedWithMods:
			printf( "WARNING: got \"grantedWithMods\"");
		case CMP_PKISTATUS_accepted:
			if( !(ctx->newClCert = CMP_CERTREPMESSAGE_cert_get1(kup->body->value.kup,0))) {
				printf( "ERROR: could not find the certificate with certReqId=0\nFILE %s, LINE %d\n", __FILE__, __LINE__);
				goto err;
			}
			break;
		case CMP_PKISTATUS_rejection:
		case CMP_PKISTATUS_waiting:
		case CMP_PKISTATUS_revocationWarning:
		case CMP_PKISTATUS_revocationNotification:
		case CMP_PKISTATUS_keyUpdateWarning:
			printf( "ERROR: didn't get a certificate");
			goto err;
			break;
		default:
			printf( "ERROR: got an unknown PKIStatus");
			goto err;
			break;
	}

	/* check if implicit confirm is set in generalInfo */
	/* TODO should I check if that was requested?
	 * What happens if this is set here while it was not requested?
	 */
	if (CMP_PKIMESSAGE_check_implicitConfirm(kup)) goto cleanup;

	/* crate Certificate Confirmation - certConf */
	if (! (certConf = CMP_certConf_new(ctx))) goto err;

	printf("INFO: Sending Certificate Confirm\n");
	if (! CMP_PKIMESSAGE_http_bio_send(cbio, ctx->serverName, ctx->serverPort, ctx->serverPath, ctx->compatibility, certConf))
		goto err;

	/* receive PKI confirmation - PKIconf */
	printf("INFO: Attempting to receive PKIconf\n");
	if (! CMP_PKIMESSAGE_http_bio_recv(cbio, &PKIconf, ctx->compatibility))
		goto err;

	if (CMP_protection_verify( PKIconf, ctx->protectionAlgor, X509_get_pubkey( (X509*) ctx->caCert), NULL)) {
		printf( "SUCCESS: validating protection of incoming message\n");
	} else {
		printf( "ERROR: validating protection of incoming message\n");
		goto err;
	}

	/* make sure the received messagetype indicates an PKIconf message */
	switch (CMP_PKIMESSAGE_get_bodytype(PKIconf)) {
		case V_CMP_PKIBODY_PKICONF:
			break;
		case V_CMP_PKIBODY_ERROR:
			printf( "ERROR: received an ERROR: %d Message\n", CMP_PKIMESSAGE_get_bodytype( PKIconf));
			CMP_PKIMESSAGE_parse_error_msg( PKIconf);
			goto err;
			break;
		default:
			printf( "ERROR: received neither an PKIconf nor an ERROR: but a %d Message\n", CMP_PKIMESSAGE_get_bodytype( PKIconf));
			goto err;
			break;
	}

cleanup:
	/* clean up */
	CMP_PKIMESSAGE_free(kur);
	CMP_PKIMESSAGE_free(kup);
	/* those are not set in case of implicitConfirm */
	if (certConf) CMP_PKIMESSAGE_free(certConf);
	if (PKIconf) CMP_PKIMESSAGE_free(PKIconf);
	return ctx->newClCert;
err:
printf( "ERROR: in CMP_doInitialRequestSeq, FILE: %s, LINE: %d\n", __FILE__, __LINE__);
	if (kur) CMP_PKIMESSAGE_free(kur);
	if (kup) CMP_PKIMESSAGE_free(kup);
	if (certConf) CMP_PKIMESSAGE_free(certConf);
	if (PKIconf) CMP_PKIMESSAGE_free(PKIconf);
	return NULL;
}

/* ############################################################################ */
/* ############################################################################ */
int CMP_doPKIInfoReqSeq( BIO *cbio, CMP_CTX *ctx) {
	CMP_PKIMESSAGE *genm=NULL;
	CMP_PKIMESSAGE *genp=NULL;

	/* check if all necessary options are set */
	if (!cbio) goto err;
	if (!ctx) goto err;
	if (!ctx->caCert) goto err;
	if (!ctx->referenceValue) goto err;
	if (!ctx->secretValue) goto err;

	/* set the protection Algor which will be used during the whole session */
	CMP_CTX_set_protectionAlgor( ctx, CMP_ALG_PBMAC);

	/* crate GenMsgContent - genm*/
	if (! (genm = CMP_genm_new(ctx))) goto err;

	printf("INFO: Sending General Message\n");
	if (! CMP_PKIMESSAGE_http_bio_send(cbio, ctx->serverName, ctx->serverPort, ctx->serverPath, ctx->compatibility, genm))
		goto err;

	/* receive GenRepContent - genp */
	printf("INFO: Attempting to receive General Response\n");
	if (! CMP_PKIMESSAGE_http_bio_recv(cbio, &genp, ctx->compatibility))
		goto err;

	if (CMP_protection_verify( genp, ctx->protectionAlgor, NULL, ctx->secretValue))
		printf( "SUCCESS: validating protection of incoming message\n");
	else {
		printf( "ERROR: validating protection of incoming message\n");
		goto err;
	}

	/* make sure the received messagetype indicates an IP message */
	switch (CMP_PKIMESSAGE_get_bodytype(genp)) {
		case V_CMP_PKIBODY_GENP:
			/* this is the expected outcome at SUCCESS: */
			break;
		case V_CMP_PKIBODY_ERROR:
			printf( "ERROR: received an ERROR: %d Message\n", CMP_PKIMESSAGE_get_bodytype( genp));
			CMP_PKIMESSAGE_parse_error_msg( genp);
			goto err;
			break;
		default:
			printf( "ERROR: received neither an GENP nor an ERROR: but %d Message\n", CMP_PKIMESSAGE_get_bodytype( genp));
			goto err;
			break;
	}
	return 1;
err:
printf( "ERROR: in CMP_doPKIInfoReqSeq, FILE: %s, LINE: %d\n", __FILE__, __LINE__);
	if (genm) CMP_PKIMESSAGE_free(genm);
	if (genp) CMP_PKIMESSAGE_free(genp);
	return 0;
}
