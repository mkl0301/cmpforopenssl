/* vim: set noet ts=4 sts=4 sw=4: */
 /* crypto/cmp/cmp_ses.c
 * Functions to do CMP (RFC 4210) message sequences for OpenSSL
 */
/* ====================================================================
 * Originally written by Martin Peylo for the OpenSSL project.
 * <martin dot peylo at nsn dot com>
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
 * 2008 - Sami Lehtonen - added CMP_doCertificateRequestSeq()
 * 06/2010 - Miikka Viljanen - Report errors with OpenSSL error codes instead
 *                             of printf statements.
 */

#include <string.h>

#include <openssl/cmp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* ############################################################################ */
/* Prints error data of the given CMP_PKIMESSAGE into a buffer specified by out */
/* and returns pointer to the buffer.                                           */
/* ############################################################################ */
static char *PKIError_data(CMP_PKIMESSAGE *msg, char *out, int outsize) {
	char tempbuf[256];
	switch (CMP_PKIMESSAGE_get_bodytype(msg)) {
		case V_CMP_PKIBODY_ERROR:
			BIO_snprintf(out, outsize, "message=%d, error=\"%s\"",
					CMP_PKIMESSAGE_get_bodytype( msg),
					CMP_PKIMESSAGE_parse_error_msg( msg, tempbuf, sizeof(tempbuf)));
			break;
		case -1:
			BIO_snprintf(out, outsize, "received NO message");
			break;
		default:
			BIO_snprintf(out, outsize, "received neither IP nor ERROR, but message=%d", CMP_PKIMESSAGE_get_bodytype( msg));
			break;
	}
	return out;
}


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
	if (!ctx->referenceValue) goto err;
	if (!ctx->secretValue && (!ctx->extCert || !ctx->caCert)) goto err;
	if (!ctx->pkey) goto err;

	/* this can not have been set here */
	if (ctx->clCert) goto err;

	/* set the protection Algor which will be used during the whole session */
	/* if extCert is set, try to use that for authentication (appendix E.7) instead of PBMAC */
	if (ctx->extCert) {
		if (!CMP_CTX_set_protectionAlgor( ctx, CMP_ALG_SIG)) goto err;
	}
	else if (!CMP_CTX_set_protectionAlgor( ctx, CMP_ALG_PBMAC)) goto err;

	/* create Initialization Request - ir */
	if (! (ir = CMP_ir_new(ctx))) goto err;

	CMP_printf("INFO: Sending Initialization Request\n");
	if (! CMP_PKIMESSAGE_http_bio_send(cbio, ctx->serverName, ctx->serverPort, ctx->serverPath, ctx->compatibility, ir)) {
		CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_ERROR_RECEIVING_MESSAGE);
		goto err;
	}

	/* receive Initialization Response - ip */
	CMP_printf("INFO: Attempting to receive IP\n");
	if (! CMP_PKIMESSAGE_http_bio_recv(cbio, &ip, ctx->compatibility)) {
		CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_ERROR_RECEIVING_MESSAGE);
		goto err;
	}

	if (CMP_protection_verify( ip, ctx->protectionAlgor, X509_get_pubkey( (X509*) ctx->caCert), ctx->secretValue))
		CMP_printf( "SUCCESS: validating protection of incoming message\n");
	else {
		CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
	}

	/* make sure the received messagetype indicates an IP message */
	if (CMP_PKIMESSAGE_get_bodytype(ip) != V_CMP_PKIBODY_IP) {
		ASN1_UTF8STRING *ftstr = NULL;
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data(ip, errmsg, sizeof(errmsg)));
		while ((ftstr = sk_ASN1_UTF8STRING_pop(ip->header->freeText)))
			ERR_add_error_data(3, "freeText=\"", ftstr->data, "\"");
		goto err;
	}

	/* make sure the PKIStatus for the *first* CERTrepmessage indicates a certificate was granted */
	/* TODO - there could be two CERTrepmessages */
	switch (CMP_CERTREPMESSAGE_PKIStatus_get( ip->body->value.ip, 0)) {
		case CMP_PKISTATUS_grantedWithMods:
			CMP_printf( "WARNING: got \"grantedWithMods\"\n");
		case CMP_PKISTATUS_accepted:
			switch (CMP_CERTREPMESSAGE_certType_get(ip->body->value.ip, 0)) {
				case CMP_CERTORENCCERT_CERTIFICATE:
					if( !(ctx->newClCert = CMP_CERTREPMESSAGE_cert_get1(ip->body->value.ip,0))) {
						CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_CERTIFICATE_NOT_FOUND);
						goto err;
					}					
					break;
				case CMP_CERTORENCCERT_ENCRYPTEDCERT:
					if( !(ctx->newClCert = CMP_CERTREPMESSAGE_encCert_get1(ip->body->value.ip,0,ctx->pkey))) {
						CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_CERTIFICATE_NOT_FOUND);
						goto err;
					}					
					break;
			}
			break;
		case CMP_PKISTATUS_rejection:
		case CMP_PKISTATUS_waiting:
		case CMP_PKISTATUS_revocationWarning:
		case CMP_PKISTATUS_revocationNotification:
		case CMP_PKISTATUS_keyUpdateWarning:
			CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_NO_CERTIFICATE_RECEIVED);
			goto err;
			break;
		default: {
			STACK_OF(ASN1_UTF8STRING) *strstack = CMP_CERTREPMESSAGE_PKIStatusString_get0(ip->body->value.ip, 0);
			ASN1_UTF8STRING *status = NULL;

			CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_UNKNOWN_PKISTATUS);
			while ((status = sk_ASN1_UTF8STRING_pop(strstack)))
				ERR_add_error_data(3, "statusString=\"", status->data, "\"");

			CMP_printf("ERROR: unknown pkistatus %ld\n", CMP_CERTREPMESSAGE_PKIStatus_get( ip->body->value.ip, 0));
			goto err;
			break;
		}
	}

	/* if the CA returned certificates in the caPubs field, copy them
	 * to the context so that they can be retrieved if necessary */
	if (ip->body->value.ip->caPubs)
		CMP_CTX_set1_caPubs(ctx, ip->body->value.ip->caPubs);

	/* copy any received extraCerts to context->caExtraCerts so
	 * they can also be retrieved */
	if (ip->extraCerts)
		CMP_CTX_set1_caExtraCerts(ctx, ip->extraCerts);

	/* check if implicit confirm is set in generalInfo */
	if (CMP_PKIMESSAGE_check_implicitConfirm(ip)) goto cleanup;

	/* create Certificate Confirmation - certConf */
	if (! (certConf = CMP_certConf_new(ctx))) goto err;

	CMP_printf("INFO: Sending Certificate Confirm\n");
	if (! CMP_PKIMESSAGE_http_bio_send(cbio, ctx->serverName, ctx->serverPort, ctx->serverPath, ctx->compatibility, certConf))
		goto err;

	/* receive PKIconf - PKIconf */
	CMP_printf("INFO: Attempting to receive PKIconf\n");
	if (! CMP_PKIMESSAGE_http_bio_recv(cbio, &PKIconf, ctx->compatibility))
		goto err;

	if (CMP_protection_verify( PKIconf, ctx->protectionAlgor, NULL, ctx->secretValue))
		CMP_printf( "SUCCESS: validating protection of incoming message\n");
	else {
		CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
	}

	/* make sure the received messagetype indicates an PKIconf message */
	if (CMP_PKIMESSAGE_get_bodytype(PKIconf) != V_CMP_PKIBODY_PKICONF) {
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data(PKIconf, errmsg, sizeof(errmsg)));
		goto err;
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
	CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_CMPERROR);

	if (ir) CMP_PKIMESSAGE_free(ir);
	if (ip) CMP_PKIMESSAGE_free(ip);
	if (certConf) CMP_PKIMESSAGE_free(certConf);
	if (PKIconf) CMP_PKIMESSAGE_free(PKIconf);
	return NULL;
}
/* ############################################################################ */
/* ############################################################################ */
X509 *CMP_doCertificateRequestSeq( BIO *cbio, CMP_CTX *ctx) {
	CMP_PKIMESSAGE *cr=NULL;
	CMP_PKIMESSAGE *cp=NULL;
	CMP_PKIMESSAGE *certConf=NULL;
	CMP_PKIMESSAGE *PKIconf=NULL;

	/* check if all necessary options are set */
	if (!cbio) goto err;
	if (!ctx) goto err;
	if (!ctx->serverName) goto err;
	if (!ctx->pkey) goto err;
	if (!ctx->clCert) goto err;
	if (!ctx->caCert) goto err;

	/* set the protection Algor which will be used during the whole session */
	CMP_CTX_set_protectionAlgor( ctx, CMP_ALG_SIG);

	/* create Certificate Request - cr */
	if (! (cr = CMP_cr_new(ctx))) goto err;

	CMP_printf("INFO: Sending Certificate Request\n");
	if (! CMP_PKIMESSAGE_http_bio_send(cbio, ctx->serverName, ctx->serverPort, ctx->serverPath, ctx->compatibility, cr))
		goto err;

	/* receive Certificate Response - cp */
	CMP_printf("INFO: Attempting to receive CP\n");
	if (! CMP_PKIMESSAGE_http_bio_recv(cbio, &cp, ctx->compatibility))
		goto err;

	if (CMP_PKIMESSAGE_get_bodytype( cp) != V_CMP_PKIBODY_CP) {
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data(cp, errmsg, sizeof(errmsg)));
		goto err;
	}


	if (CMP_protection_verify( cp, ctx->protectionAlgor, X509_get_pubkey( (X509*) ctx->caCert), NULL)) {
		CMP_printf( "SUCCESS: validating protection of incoming message\n");
	} else {
		CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
	}

	switch (CMP_CERTREPMESSAGE_PKIStatus_get( cp->body->value.cp, 0)) {
		case CMP_PKISTATUS_grantedWithMods:
			CMP_printf( "WARNING: got \"grantedWithMods\"");
		case CMP_PKISTATUS_accepted:
			if( !(ctx->newClCert = CMP_CERTREPMESSAGE_cert_get1(cp->body->value.cp,0))) {
				// old: "ERROR: could not find the certificate with certReqId=0"
				CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_CERTIFICATE_NOT_FOUND);
				goto err;
			}
			break;
		case CMP_PKISTATUS_rejection:
		case CMP_PKISTATUS_waiting:
		case CMP_PKISTATUS_revocationWarning:
		case CMP_PKISTATUS_revocationNotification:
		case CMP_PKISTATUS_keyUpdateWarning:
			CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_NO_CERTIFICATE_RECEIVED);
			goto err;
			break;
		default:
			CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_UNKNOWN_PKISTATUS);
			goto err;
			break;
	}

	/* if the CA returned certificates in the caPubs field, copy them
	 * to the context so that they can be retrieved if necessary */
	if (cp->body->value.cp->caPubs)
		CMP_CTX_set1_caPubs(ctx, cp->body->value.cp->caPubs);

	/* copy any received extraCerts to context->caExtraCerts so
	 * they can also be retrieved */
	if (cp->extraCerts)
		CMP_CTX_set1_caExtraCerts(ctx, cp->extraCerts);

	/* check if implicit confirm is set in generalInfo */
	if (CMP_PKIMESSAGE_check_implicitConfirm(cp)) goto cleanup;

	/* crate Certificate Confirmation - certConf */
	if (! (certConf = CMP_certConf_new(ctx))) goto err;

	CMP_printf("INFO: Sending Certificate Confirm\n");
	if (! CMP_PKIMESSAGE_http_bio_send(cbio, ctx->serverName, ctx->serverPort, ctx->serverPath, ctx->compatibility, certConf))
		goto err;

	/* receive PKI confirmation - PKIconf */
	CMP_printf("INFO: Attempting to receive PKIconf\n");
	if (! CMP_PKIMESSAGE_http_bio_recv(cbio, &PKIconf, ctx->compatibility))
		goto err;

	if (CMP_protection_verify( PKIconf, ctx->protectionAlgor, X509_get_pubkey( (X509*) ctx->caCert), NULL)) {
		CMP_printf( "SUCCESS: validating protection of incoming message\n");
	} else {
		/* old: "ERROR: validating protection of incoming message\n" */
		CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
	}

	/* make sure the received messagetype indicates an PKIconf message */
	if (CMP_PKIMESSAGE_get_bodytype(PKIconf) != V_CMP_PKIBODY_PKICONF) {
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data(PKIconf, errmsg, sizeof(errmsg)));
		goto err;
	}

cleanup:
	/* clean up */
	CMP_PKIMESSAGE_free(cr);
	CMP_PKIMESSAGE_free(cp);
	/* those are not set in case of implicitConfirm */
	if (certConf) CMP_PKIMESSAGE_free(certConf);
	if (PKIconf) CMP_PKIMESSAGE_free(PKIconf);
	return ctx->newClCert;

err:
	CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_CMPERROR);

	if (cr) CMP_PKIMESSAGE_free(cr);
	if (cp) CMP_PKIMESSAGE_free(cp);
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

	CMP_printf("INFO: Sending Key Update Request\n");
	if (! CMP_PKIMESSAGE_http_bio_send(cbio, ctx->serverName, ctx->serverPort, ctx->serverPath, ctx->compatibility, kur))
		goto err;

	/* receive Key Update Response - kup */
	CMP_printf("INFO: Attempting to receive KUP\n");
	if (! CMP_PKIMESSAGE_http_bio_recv(cbio, &kup, ctx->compatibility))
		goto err;

	if (CMP_PKIMESSAGE_get_bodytype( kup) != V_CMP_PKIBODY_KUP) {
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data(kup, errmsg, sizeof(errmsg)));
		goto err;
	}

	if (CMP_protection_verify( kup, ctx->protectionAlgor, X509_get_pubkey( (X509*) ctx->caCert), NULL)) {
		CMP_printf( "SUCCESS: validating protection of incoming message\n");
	} else {
		CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
	}

	switch (CMP_CERTREPMESSAGE_PKIStatus_get( kup->body->value.kup, 0)) {
		case CMP_PKISTATUS_grantedWithMods:
			CMP_printf( "WARNING: got \"grantedWithMods\"");
		case CMP_PKISTATUS_accepted:
			if( !(ctx->newClCert = CMP_CERTREPMESSAGE_cert_get1(kup->body->value.kup,0))) {
				CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_CERTIFICATE_NOT_FOUND);
				goto err;
			}
			break;
		case CMP_PKISTATUS_rejection:
		case CMP_PKISTATUS_waiting:
		case CMP_PKISTATUS_revocationWarning:
		case CMP_PKISTATUS_revocationNotification:
		case CMP_PKISTATUS_keyUpdateWarning:
			CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_NO_CERTIFICATE_RECEIVED);
			goto err;
			break;
		default:
			CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_UNKNOWN_PKISTATUS);
			goto err;
			break;
	}

	/* if the CA returned certificates in the caPubs field, copy them
	 * to the context so that they can be retrieved if necessary */
	if (kup->body->value.kup->caPubs)
		CMP_CTX_set1_caPubs(ctx, kup->body->value.kup->caPubs);

	/* copy any received extraCerts to context->caExtraCerts so
	 * they can also be retrieved */
	if (kup->extraCerts)
		CMP_CTX_set1_caExtraCerts(ctx, kup->extraCerts);

	/* check if implicit confirm is set in generalInfo */
	if (CMP_PKIMESSAGE_check_implicitConfirm(kup)) goto cleanup;

	/* crate Certificate Confirmation - certConf */
	if (! (certConf = CMP_certConf_new(ctx))) goto err;

	CMP_printf("INFO: Sending Certificate Confirm\n");
	if (! CMP_PKIMESSAGE_http_bio_send(cbio, ctx->serverName, ctx->serverPort, ctx->serverPath, ctx->compatibility, certConf))
		goto err;

	/* receive PKI confirmation - PKIconf */
	CMP_printf("INFO: Attempting to receive PKIconf\n");
	if (! CMP_PKIMESSAGE_http_bio_recv(cbio, &PKIconf, ctx->compatibility))
		goto err;

	if (CMP_protection_verify( PKIconf, ctx->protectionAlgor, X509_get_pubkey( (X509*) ctx->caCert), NULL)) {
		CMP_printf( "SUCCESS: validating protection of incoming message\n");
	} else {
		CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
	}

	/* make sure the received messagetype indicates an PKIconf message */
	if (CMP_PKIMESSAGE_get_bodytype(PKIconf) != V_CMP_PKIBODY_PKICONF) {
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data(PKIconf, errmsg, sizeof(errmsg)));
		goto err;
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
	CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_CMPERROR);

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

	CMP_printf("INFO: Sending General Message\n");
	if (! CMP_PKIMESSAGE_http_bio_send(cbio, ctx->serverName, ctx->serverPort, ctx->serverPath, ctx->compatibility, genm))
		goto err;

	/* receive GenRepContent - genp */
	CMP_printf("INFO: Attempting to receive General Response\n");
	if (! CMP_PKIMESSAGE_http_bio_recv(cbio, &genp, ctx->compatibility))
		goto err;

	if (CMP_protection_verify( genp, ctx->protectionAlgor, NULL, ctx->secretValue))
		CMP_printf( "SUCCESS: validating protection of incoming message\n");
	else {
		CMPerr(CMP_F_CMP_DOPKIINFOREQSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
	}

	/* make sure the received messagetype indicates an IP message */
	if (CMP_PKIMESSAGE_get_bodytype(genp) != V_CMP_PKIBODY_GENP) {
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOPKIINFOREQSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data(genp, errmsg, sizeof(errmsg)));
		goto err;
	}

	return 1;
err:
	CMPerr(CMP_F_CMP_DOPKIINFOREQSEQ, CMP_R_CMPERROR);

	if (genm) CMP_PKIMESSAGE_free(genm);
	if (genp) CMP_PKIMESSAGE_free(genp);
	return 0;
}

