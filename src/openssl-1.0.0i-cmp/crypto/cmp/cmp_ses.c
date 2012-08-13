/* vim: set noet ts=4 sts=4 sw=4: */
 /* crypto/cmp/cmp_ses.c
 * Functions to do CMP (RFC 4210) message sequences for OpenSSL
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

#include <unistd.h>


int CMP_error_callback(const char *str, size_t len, void *u) {
	CMP_CTX *ctx = (CMP_CTX*) u;
	if (ctx && ctx->error_cb) 
		ctx->error_cb(str);
	return 1;
}

#ifndef HAVE_CURL

/* show some warning here? */

#else

// {{{ char V_CMP_TABLE[] 

static char *V_CMP_TABLE[] = {
  "IR",
  "IP",
  "CR",
  "CP",
  "P10CR",
  "POPDECC",
  "POPDECR",
  "KUR",
  "KUP",
  "KRR",
  "KRP",
  "RR",
  "RP",
  "CCR",
  "CCP",
  "CKUANN",
  "CANN",
  "RANN",
  "CRLANN",
  "PKICONF",
  "NESTED",
  "GENM",
  "GENP",
  "ERROR",
  "CERTCONF",
  "POLLREQ",
  "POLLREP",
};

//      }}}
#define MSG_TYPE_STR(type)  \
  (((unsigned int) (type) < sizeof(V_CMP_TABLE)/sizeof(V_CMP_TABLE[0])) \
   ? V_CMP_TABLE[(unsigned int)(type)] : "unknown")

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
			BIO_snprintf(out, outsize, "received unexpected message of type '%s'", MSG_TYPE_STR(CMP_PKIMESSAGE_get_bodytype( msg)));
			break;
	}
	return out;
}

ASN1_OCTET_STRING *CMP_get_subject_key_id(const X509 *cert);

static X509 *find_cert_by_keyID(STACK_OF(X509) *certs, ASN1_OCTET_STRING *keyid) {
	if (!certs || !keyid) return NULL;
	int n = sk_X509_num(certs);
	while (n --> 0) {
		X509 *cert = sk_X509_value(certs, n);
		ASN1_OCTET_STRING *cert_keyid = CMP_get_subject_key_id(cert);

		if (!ASN1_OCTET_STRING_cmp(cert_keyid, keyid))
			return cert;
	}
	return NULL;
}

static X509 *find_cert_by_name(STACK_OF(X509) *certs, X509_NAME *name) {
	if (!certs || !name) return NULL;
	int n = sk_X509_num(certs);
	while (n --> 0) {
		X509 *cert = sk_X509_value(certs, n);
		X509_NAME *cert_name = X509_get_subject_name(cert);
		if (!X509_NAME_cmp(cert_name, name))
			return cert;
	}
	return NULL;
}

static void add_error_data(const char *txt) {
    ERR_STATE *es;
	int i, len, newlen;
    char *err;
    
    es=ERR_get_state();

	i=es->top;
	if (i == 0)
		i=ERR_NUM_ERRORS-1;
    err=es->err_data[i];

    if (err == NULL) {
        ERR_add_error_data(1, txt);
        return;
    }

    len = strlen(es->err_data[i]);
    newlen = len + 1 + strlen(txt);

    if (newlen > 80) {
        err=OPENSSL_realloc(err, newlen+1);
        if (err == NULL)
            return;
    }

    BUF_strlcat(err, ":", (size_t)newlen+1);        
    BUF_strlcat(err, txt, (size_t)newlen+1);        
}

/* ############################################################################ *
 * ############################################################################ */

static X509 *certrep_get_certificate(CMP_CTX *ctx, CMP_CERTREPMESSAGE *certrep, EVP_PKEY *pkey) {
	X509 *newClCert = NULL;
	
	CMP_CTX_set_failInfoCode(ctx, CMP_CERTREPMESSAGE_PKIFailureInfo_get0(certrep, 0));

	ctx->lastStatus = CMP_CERTREPMESSAGE_PKIStatus_get( certrep, 0);
	switch (ctx->lastStatus) {

		case CMP_PKISTATUS_waiting:
			goto err;
			break;

		case CMP_PKISTATUS_grantedWithMods:
			CMP_printf( ctx, "WARNING: got \"grantedWithMods\"");

		case CMP_PKISTATUS_accepted:
			/* if we received a certificate then place it to ctx->newClCert and return,
			 * if the cert is encrypted then we first decrypt it. */
			switch (CMP_CERTREPMESSAGE_certType_get(certrep, 0)) {
				case CMP_CERTORENCCERT_CERTIFICATE:
					if( !(newClCert = CMP_CERTREPMESSAGE_cert_get1(certrep,0))) {
						CMPerr(CMP_F_CERTREP_GET_CERTIFICATE, CMP_R_CERTIFICATE_NOT_FOUND);
						goto err;
					}					
					break;
				case CMP_CERTORENCCERT_ENCRYPTEDCERT:
					if( !(newClCert = CMP_CERTREPMESSAGE_encCert_get1(certrep,0,pkey))) {
						CMPerr(CMP_F_CERTREP_GET_CERTIFICATE, CMP_R_CERTIFICATE_NOT_FOUND);
						goto err;
					}					
					break;
			}
			break;

		case CMP_PKISTATUS_rejection: {
			/* XXX Should a certconf message be sent even in case of rejection? */
			char *statusString = NULL;
			int statusLen = 0;
			ASN1_UTF8STRING *status = NULL;
			STACK_OF(ASN1_UTF8STRING) *strstack = CMP_CERTREPMESSAGE_PKIStatusString_get0(certrep, 0);

			CMPerr(CMP_F_CERTREP_GET_CERTIFICATE, CMP_R_REQUEST_REJECTED_BY_CA);

			statusString = CMP_CERTREPMESSAGE_PKIFailureInfoString_get0(certrep, 0);
			if (!statusString) goto err;
			statusString = OPENSSL_strdup(statusString);
			if (!statusString) goto err;
			statusLen = strlen(statusString);

			statusString = OPENSSL_realloc(statusString, statusLen+20);
			strcat(statusString, ", statusString: \"");
			statusLen = strlen(statusString);

			while ((status = sk_ASN1_UTF8STRING_pop(strstack))) {
				statusLen += strlen((char*)status->data)+2;
				statusString = OPENSSL_realloc(statusString, statusLen);
				if (!statusString) goto err;
				strcat(statusString, (char*)status->data);
			}

			strcat(statusString, "\"");
			add_error_data(statusString);

			goto err;
			break;
		}

		case CMP_PKISTATUS_revocationWarning:
		case CMP_PKISTATUS_revocationNotification:
		case CMP_PKISTATUS_keyUpdateWarning:
			CMPerr(CMP_F_CERTREP_GET_CERTIFICATE, CMP_R_NO_CERTIFICATE_RECEIVED);
			goto err;
			break;

		default: {
			STACK_OF(ASN1_UTF8STRING) *strstack = CMP_CERTREPMESSAGE_PKIStatusString_get0(certrep, 0);
			ASN1_UTF8STRING *status = NULL;

			CMPerr(CMP_F_CERTREP_GET_CERTIFICATE, CMP_R_UNKNOWN_PKISTATUS);
			/* XXX ERR_add_error_data overwrites the previous error data, fix this! */
			while ((status = sk_ASN1_UTF8STRING_pop(strstack)))
				ERR_add_error_data(3, "statusString=\"", status->data, "\"");

			CMP_printf( ctx, "ERROR: unknown pkistatus %ld", CMP_CERTREPMESSAGE_PKIStatus_get( certrep, 0));
			goto err;
			break;
		}
	}


	return newClCert;
err:
	return NULL;
}


static int try_polling(CMP_CTX *ctx, CMPBIO *cbio, CMP_CERTREPMESSAGE *certrep, CMP_PKIMESSAGE **msg) {
	int i;
	CMP_printf(ctx, "INFO: Received 'waiting' PKIStatus, attempting to poll server for response.");
	for (i = 0; i < ctx->maxPollCount; i++) {
		CMP_PKIMESSAGE *preq = CMP_pollReq_new(ctx, 0);
		CMP_PKIMESSAGE *prep = NULL;
		CMP_POLLREP *pollRep = NULL;

		if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, preq, &prep))) {
			if (ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_NULL_ARGUMENT
				&& ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_SERVER_NOT_REACHABLE)
				CMPerr(CMP_F_TRY_POLLING, CMP_R_IP_NOT_RECEIVED);
			else
				add_error_data("unable to send ir");
			goto err;
		}

		/* TODO handle multiple pollreqs */
		if ( CMP_PKIMESSAGE_get_bodytype(prep) == V_CMP_PKIBODY_IP) {
			CMP_PKIMESSAGE_free(preq);
			if (CMP_CERTREPMESSAGE_PKIStatus_get( certrep, 0) != CMP_PKISTATUS_waiting) {
				*msg = prep;
				return 1;
			}
		} else if ( CMP_PKIMESSAGE_get_bodytype(prep) == V_CMP_PKIBODY_POLLREP) {
			int checkAfter;
			pollRep = sk_CMP_POLLREP_value(prep->body->value.pollRep, 0);
			checkAfter = ASN1_INTEGER_get(pollRep->checkAfter);
			CMP_printf(ctx, "INFO: Waiting %ld seconds before sending pollReq...\n", checkAfter);
			sleep(checkAfter);
		} else {
			CMP_PKIMESSAGE_free(preq);
			CMP_PKIMESSAGE_free(prep);
			CMPerr(CMP_F_TRY_POLLING, CMP_R_RECEIVED_INVALID_RESPONSE_TO_POLLREQ);
			goto err;
		}

		CMP_PKIMESSAGE_free(preq);
		CMP_PKIMESSAGE_free(prep);
	}

err:
	return 0;
}

/* This function loads all the intermediate certificates from extraCerts into
 * the untrusted_store, and if the option is set it also loads any self-signed
 * certs to trusted_store */
static int load_extraCerts(CMP_CTX *ctx, STACK_OF(X509) *stack)
{
	int i;

	if (!stack) goto err;

	for (i = 0; i < sk_X509_num(stack); i++) {
		X509 *cert = sk_X509_value(stack, i);
		EVP_PKEY *pubkey = X509_get_pubkey(cert);

		/* check if cert is self-signed */
		if (X509_verify(cert, pubkey)) {
			if (/*3GPP_OPTION &&*/ ctx->trusted_store)
				X509_STORE_add_cert(ctx->trusted_store, X509_dup(cert));
		}
		else {
			if (ctx->untrusted_store)
				X509_STORE_add_cert(ctx->untrusted_store, X509_dup(cert));
		}
	}

	return 1;

err:
	return 0;
}



/* ############################################################################ *
 * ############################################################################ */
X509 *CMP_doInitialRequestSeq( CMPBIO *cbio, CMP_CTX *ctx) {
	CMP_PKIMESSAGE *ir=NULL;
	CMP_PKIMESSAGE *ip=NULL;
	CMP_PKIMESSAGE *certConf=NULL;
	CMP_PKIMESSAGE *PKIconf=NULL;
	X509 *srvCert = NULL;

	/* check if all necessary options are set */
	if (!cbio || !ctx || !ctx->newPkey ||
		 /* for authentication we need either reference/secret or external 
		  * identity certificate and private key */
		 (!(ctx->referenceValue && ctx->secretValue) && !(ctx->pkey && ctx->clCert)) ) {
		CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_INVALID_ARGS);
		goto err;
	}


	/* set the protection Algor which will be used during the whole session */
	/* E.7: if clCert is set, use that for signing instead of PBMAC */
	if (! ctx->clCert)
		CMP_CTX_set_protectionAlgor( ctx, CMP_ALG_PBMAC);
	else 
		if (!CMP_CTX_set_protectionAlgor( ctx, CMP_ALG_SIG)) goto err;

	/* create Initialization Request - ir */
	if (! (ir = CMP_ir_new(ctx))) goto err;

	CMP_printf(ctx, "INFO: Sending Initialization Request");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, ir, &ip))) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_NULL_ARGUMENT
            && ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_SERVER_NOT_REACHABLE)
            CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_IP_NOT_RECEIVED);
        else
            add_error_data("unable to send ir");
		goto err;
	}

	CMP_CTX_set1_sender(ctx, ip->header->sender->d.directoryName);

	/* TODO: standard when cert protection: use trusted_store + certs from extra
	 * certs to validate sender Cert */
#if 0
	/* either ctx->caCert or trusted_store are acceptable */
	if (ip->header->sender->d.directoryName combined with optional ip->header->senderKID is in trusted_store) {
		/* TODO: what if there is no senderKID but two certificates with the
		 * same name? */
		srvCert = identified trust anchor;
		--> no need to verify chain
	} else {
		/* TODO: what if there is no senderKID but two certificates with the
		 * same name? */
		srvCert = find_cert_by_name(ip->extraCerts, ip->header->sender->d.directoryName), check optional senderKID;

		if(verify srvCert chain to trusted store, using extraCerts as intermediate is OK) {
			SUCCESS
		} else {
			if(3GPP-E.7-profile-option) {
				if(srvCert is self-signed) {
					if( not validate issued certificate included in IP with srvCert as Trust Anchor) { /* This is the 3GPP requirement for accepting a self-singed trust anchor from extaCerts */
						FAIL
					}
				}	
				if(srvCert is not self-signed) {
					while (potialTrustAnchor = search(extraCerts for self-signed Certs)) {
						if( validate issued certificate included in IP with potentialTrustAnchor as Trust Anchor and extraCerts as intermediate certs) { /* This is the 3GPP requirement for accepting a self-singed trust anchor from extaCerts */
							if( not validate srvCert with potentialTurustAnchor as Trust Anchor and extraCerts as intermediate certs) {
								FAIL;
							}
						} else NEXT;
					}
					if (not SUCCESS before) FAIL;
				}	
			} else FAIL;
		}
	}
	if (!srvCert) {
		FAIL /* as sender cert is not known - do we need to send errMsg? */
	}
	if( validate CMP Message Protection with srvCert) {
		SUCCESS
	} else FAIL;
#endif

	/* load the provided extraCerts to help with cert path validation */
	load_extraCerts(ctx, ip->extraCerts);
	/* TODO: load caPubs too? */

	/* if initializing with existing cert, first we'll see if the sender
	 * certificate can be found and validated using our root CA certificates */
	if (ctx->trusted_store && !srvCert) {
		srvCert = find_cert_by_keyID(ip->extraCerts, ip->header->senderKID);
		if (!srvCert)
			/* TODO what if we have two certs with the same name on stack? */
			srvCert = find_cert_by_name(ip->extraCerts, ip->header->sender->d.directoryName);

		if (srvCert && CMP_validate_cert_path(ctx, srvCert) == 0) {
			/* if there is a srvCert provided, try to use that for verifying 
			 * the message signature. otherwise fail here. */
			if (!ctx->caCert) {
				CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_COULD_NOT_VALIDATE_CERTIFICATE_PATH);
				goto err;
			}
		}
	}
	/* either not using existing cert or couldn't find the CA cert in extracerts. */
	if (!srvCert) srvCert = ctx->caCert;

	if (ctx->validatePath && srvCert) {
		CMP_printf(ctx, "INFO: validating CA certificate path");
		if( CMP_validate_cert_path(ctx, srvCert) == 0) {
			CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_COULD_NOT_VALIDATE_CERTIFICATE_PATH);
			goto err;
		}
	}

	if (CMP_protection_verify( ip, ctx->protectionAlgor, X509_get_pubkey( (X509*) srvCert), ctx->secretValue))
		CMP_printf( ctx, "SUCCESS: validating protection of incoming message");
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

	if (CMP_CERTREPMESSAGE_PKIStatus_get( ip->body->value.ip, 0) == CMP_PKISTATUS_waiting)
		if (!try_polling(ctx, cbio, ip->body->value.ip, &ip)) {
            CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_IP_NOT_RECEIVED);
			ERR_add_error_data(1, "received 'waiting' pkistatus but polling failed");
			goto err;
		}

	ctx->newClCert = certrep_get_certificate(ctx, ip->body->value.ip, ctx->newPkey);
	if (ctx->newClCert == NULL) goto err;

	/* if the CA returned certificates in the caPubs field, copy them
	 * to the context so that they can be retrieved if necessary */
	if (ip->body->value.ip->caPubs)
		CMP_CTX_set1_caPubs(ctx, ip->body->value.ip->caPubs);

	/* copy any received extraCerts to ctx->etraCertsIn so they can be retrieved */
	if (ip->extraCerts)
		CMP_CTX_set1_extraCertsIn(ctx, ip->extraCerts);

	/* check if implicit confirm is set in generalInfo */
	if (CMP_PKIMESSAGE_check_implicitConfirm(ip)) goto cleanup;

	/* create Certificate Confirmation - certConf */
	if (! (certConf = CMP_certConf_new(ctx))) goto err;

	CMP_printf( ctx, "INFO: Sending Certificate Confirm");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, certConf, &PKIconf))) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_NULL_ARGUMENT
            && ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_SERVER_NOT_REACHABLE)
            CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_PKICONF_NOT_RECEIVED);
        else
            add_error_data("unable to send certConf");
		goto err;
	}

	if (CMP_protection_verify( PKIconf, ctx->protectionAlgor, X509_get_pubkey( (X509*) srvCert), ctx->secretValue))
		CMP_printf(  ctx, "SUCCESS: validating protection of incoming message");
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
	if (ir) CMP_PKIMESSAGE_free(ir);
	if (ip) CMP_PKIMESSAGE_free(ip);
	if (certConf) CMP_PKIMESSAGE_free(certConf);
	if (PKIconf) CMP_PKIMESSAGE_free(PKIconf);

	/* print out openssl and cmp errors to error_cb if it's set */
	if (ctx&&ctx->error_cb) ERR_print_errors_cb(CMP_error_callback, (void*) ctx);

	return NULL;
}

int CMP_doRevocationRequestSeq( CMPBIO *cbio, CMP_CTX *ctx) {
	CMP_PKIMESSAGE *rr=NULL;
	CMP_PKIMESSAGE *rp=NULL;
	// X509 *caCert=NULL;

	if (!cbio || !ctx || !ctx->serverName || !ctx->pkey ||
		!ctx->clCert || !ctx->caCert) {
		CMPerr(CMP_F_CMP_DOREVOCATIONREQUESTSEQ, CMP_R_INVALID_ARGS);
		goto err;
	}

	CMP_CTX_set_protectionAlgor( ctx, CMP_ALG_SIG);
	// CMP_CTX_set_protectionAlgor( ctx, CMP_ALG_PBMAC);

	if (! (rr = CMP_rr_new(ctx))) goto err;

	CMP_printf( ctx, "INFO: Sending Revocation Request");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, rr, &rp))) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_NULL_ARGUMENT
            && ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_SERVER_NOT_REACHABLE)
            CMPerr(CMP_F_CMP_DOREVOCATIONREQUESTSEQ, CMP_R_RP_NOT_RECEIVED);
        else
            add_error_data("unable to send rr");
		goto err;
	}

	CMP_CTX_set1_sender(ctx, rp->header->sender->d.directoryName);

	if (CMP_PKIMESSAGE_get_bodytype( rp) != V_CMP_PKIBODY_RP) {
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOREVOCATIONREQUESTSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data(rp, errmsg, sizeof(errmsg)));
		goto err;
	}


	if (CMP_protection_verify( rp, ctx->protectionAlgor, X509_get_pubkey( (X509*) ctx->caCert), ctx->secretValue)) {
		CMP_printf(  ctx, "SUCCESS: validating protection of incoming message");
	} else {
		CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
	}

	switch (CMP_REVREPCONTENT_PKIStatus_get( rp->body->value.rp, 0)) 
	{
		case CMP_PKISTATUS_grantedWithMods:
			CMP_printf(  ctx, "WARNING: got \"grantedWithMods\"");
		case CMP_PKISTATUS_accepted:
			CMP_printf(  ctx, "INFO: revocation accepted");
			break;
		case CMP_PKISTATUS_rejection:
			goto err;
			break;
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

	return 1;

err:
	if (ctx&&ctx->error_cb) ERR_print_errors_cb(CMP_error_callback, (void*) ctx);
	return 0;
}


/* ############################################################################ */
/* ############################################################################ */
X509 *CMP_doCertificateRequestSeq( CMPBIO *cbio, CMP_CTX *ctx) {
	CMP_PKIMESSAGE *cr=NULL;
	CMP_PKIMESSAGE *cp=NULL;
	CMP_PKIMESSAGE *certConf=NULL;
	CMP_PKIMESSAGE *PKIconf=NULL;
	X509 *caCert=NULL;

	/* check if all necessary options are set */
	if (!cbio || !ctx || !ctx->serverName
		|| !ctx->pkey || !ctx->clCert ||
		(!ctx->caCert && !ctx->trusted_store)) {
		CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_INVALID_ARGS);
		goto err;
	}

	/* set the protection Algor which will be used during the whole session */
	CMP_CTX_set_protectionAlgor( ctx, CMP_ALG_SIG);

	/* create Certificate Request - cr */
	if (! (cr = CMP_cr_new(ctx))) goto err;

	CMP_printf( ctx, "INFO: Sending Certificate Request");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, cr, &cp))) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_NULL_ARGUMENT
            && ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_SERVER_NOT_REACHABLE)
            CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_CP_NOT_RECEIVED);
        else
            add_error_data("unable to send cr");
		goto err;
	}

	CMP_CTX_set1_sender(ctx, cp->header->sender->d.directoryName);

	if (CMP_PKIMESSAGE_get_bodytype( cp) != V_CMP_PKIBODY_CP) {
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data(cp, errmsg, sizeof(errmsg)));
		goto err;
	}

	/* if  initializing with existing cert, first we'll see if the CA (sender) cert
	 * can be found and validated using our root CA certificates */
	if (ctx->trusted_store) {
		caCert = find_cert_by_name(cp->extraCerts, cp->header->sender->d.directoryName);
		if (caCert && CMP_validate_cert_path(ctx, caCert) == 0) {
			/* if there is a caCert provided, try to use that for verifying 
			 * the message signature. otherwise fail here. */
			if (!ctx->caCert) {
				CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_COULD_NOT_VALIDATE_CERTIFICATE_PATH);
				goto err;
			}
		}
	}
	/* either not using existing cert or couldn't find the CA cert in extracerts. */
	if (!caCert) caCert = ctx->caCert;

	if (ctx->validatePath && caCert) {
		CMP_printf(ctx, "INFO: validating CA certificate path");
		if( CMP_validate_cert_path(ctx, caCert) == 0) {
			CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_COULD_NOT_VALIDATE_CERTIFICATE_PATH);
			goto err;
		}
	}

	if (CMP_protection_verify( cp, ctx->protectionAlgor, X509_get_pubkey( (X509*) caCert), NULL)) {
		CMP_printf(  ctx, "SUCCESS: validating protection of incoming message");
	} else {
		CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
	}

	if (CMP_CERTREPMESSAGE_PKIStatus_get( cp->body->value.cp, 0) == CMP_PKISTATUS_waiting)
		if (!try_polling(ctx, cbio, cp->body->value.cp, &cp)) {
            CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_CP_NOT_RECEIVED);
			ERR_add_error_data(1, "received 'waiting' pkistatus but polling failed");
			goto err;
		}

	ctx->newClCert = certrep_get_certificate(ctx, cp->body->value.cp, ctx->newPkey);
	if (ctx->newClCert == NULL) goto err;


#if 0 /* those can only come in an IR --> 5.3.2 */
	/* if the CA returned certificates in the caPubs field, copy them
	 * to the context so that they can be retrieved if necessary */
	if (cp->body->value.cp->caPubs)
		CMP_CTX_set1_caPubs(ctx, cp->body->value.cp->caPubs);
#endif /* 0 */

	/* copy any received extraCerts to ctx->etraCertsIn so they can be retrieved */
	if (cp->extraCerts)
		CMP_CTX_set1_extraCertsIn(ctx, cp->extraCerts);

	/* check if implicit confirm is set in generalInfo */
	if (CMP_PKIMESSAGE_check_implicitConfirm(cp)) goto cleanup;

	/* crate Certificate Confirmation - certConf */
	if (! (certConf = CMP_certConf_new(ctx))) goto err;

	CMP_printf( ctx, "INFO: Sending Certificate Confirm");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, certConf, &PKIconf))) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_NULL_ARGUMENT
            && ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_SERVER_NOT_REACHABLE)
            CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_PKICONF_NOT_RECEIVED);
        else
            add_error_data("unable to send certConf");
		goto err;
	}

	if (CMP_protection_verify( PKIconf, ctx->protectionAlgor, X509_get_pubkey( (X509*) caCert), NULL)) {
		CMP_printf( ctx,  "SUCCESS: validating protection of incoming message");
	} else {
		/* old: "ERROR: validating protection of incoming message" */
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
	if (cr) CMP_PKIMESSAGE_free(cr);
	if (cp) CMP_PKIMESSAGE_free(cp);
	if (certConf) CMP_PKIMESSAGE_free(certConf);
	if (PKIconf) CMP_PKIMESSAGE_free(PKIconf);

	/* print out openssl and cmp errors to error_cb if it's set */
	if (ctx&&ctx->error_cb) ERR_print_errors_cb(CMP_error_callback, (void*) ctx);

	return NULL;
}


/* ############################################################################ */
/* ############################################################################ */
X509 *CMP_doKeyUpdateRequestSeq( CMPBIO *cbio, CMP_CTX *ctx) {
	CMP_PKIMESSAGE *kur=NULL;
	CMP_PKIMESSAGE *kup=NULL;
	CMP_PKIMESSAGE *certConf=NULL;
	CMP_PKIMESSAGE *PKIconf=NULL;
	X509 *caCert = NULL;

	/* check if all necessary options are set */
	if (!cbio || !ctx || !ctx->serverName
		|| !ctx->pkey || !ctx->newPkey || !ctx->clCert
		|| (!ctx->caCert && !ctx->trusted_store)) {
		CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_INVALID_ARGS);
		goto err;
	}

	/* set the protection Algor which will be used during the whole session */
	CMP_CTX_set_protectionAlgor( ctx, CMP_ALG_SIG);

	/* create Key Update Request - kur */
	if (! (kur = CMP_kur_new(ctx))) goto err;

	CMP_printf( ctx, "INFO: Sending Key Update Request");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, kur, &kup))) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_NULL_ARGUMENT
            && ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_SERVER_NOT_REACHABLE)
            CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_KUP_NOT_RECEIVED);
        else
            add_error_data("unable to send kur");
		goto err;
	}

	CMP_CTX_set1_sender(ctx, kup->header->sender->d.directoryName);

	/* see if the CA (sender) cert can be found and validated using our root CA certificates */
	if (ctx->trusted_store) {
		caCert = find_cert_by_name(kup->extraCerts, kup->header->sender->d.directoryName);
		if (caCert && CMP_validate_cert_path(ctx, caCert) == 0) {
			/* if there is a caCert provided, try to use that for verifying 
			 * the message signature. otherwise fail here. */
			if (!ctx->caCert) {
				CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_COULD_NOT_VALIDATE_CERTIFICATE_PATH);
				goto err;
			}
		}
	}
	/* either not using existing cert or couldn't find the CA cert in extracerts. */
	if (!caCert) caCert = ctx->caCert;

	if (ctx->validatePath && caCert) {
		CMP_printf(ctx, "INFO: validating CA certificate path");
		if( CMP_validate_cert_path(ctx, caCert) == 0) {
			CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_COULD_NOT_VALIDATE_CERTIFICATE_PATH);
			goto err;
		}
	}

	if (CMP_protection_verify( kup, ctx->protectionAlgor, X509_get_pubkey( (X509*) caCert), NULL)) {
		CMP_printf( ctx,  "SUCCESS: validating protection of incoming message");
	} else {
		CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
	}

	if (CMP_PKIMESSAGE_get_bodytype( kup) != V_CMP_PKIBODY_KUP) {
		ASN1_UTF8STRING *ftstr = NULL;
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data(kup, errmsg, sizeof(errmsg)));
		while ((ftstr = sk_ASN1_UTF8STRING_pop(kup->header->freeText)))
			ERR_add_error_data(3, "freeText=\"", ftstr->data, "\"");
		goto err;
	}

	if (CMP_CERTREPMESSAGE_PKIStatus_get( kup->body->value.kup, 0) == CMP_PKISTATUS_waiting)
		if (!try_polling(ctx, cbio, kup->body->value.kup, &kup)) {
            CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_KUP_NOT_RECEIVED);
			ERR_add_error_data(1, "received 'waiting' pkistatus but polling failed");
			goto err;
		}

	ctx->newClCert = certrep_get_certificate(ctx, kup->body->value.kup, ctx->newPkey);
	if (ctx->newClCert == NULL) goto err;


#if 0 /* those can only come in an IR --> 5.3.2 */
	/* if the CA returned certificates in the caPubs field, copy them
	 * to the context so that they can be retrieved if necessary */
	if (kup->body->value.kup->caPubs)
		CMP_CTX_set1_caPubs(ctx, kup->body->value.kup->caPubs);
#endif /* 0 */

	/* copy any received extraCerts to ctx->etraCertsIn so they can be retrieved */
	if (kup->extraCerts)
		CMP_CTX_set1_extraCertsIn(ctx, kup->extraCerts);

	/* check if implicit confirm is set in generalInfo */
	if (CMP_PKIMESSAGE_check_implicitConfirm(kup)) goto cleanup;

	/* crate Certificate Confirmation - certConf */
	if (! (certConf = CMP_certConf_new(ctx))) goto err;

	CMP_printf( ctx, "INFO: Sending Certificate Confirm");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, certConf, &PKIconf))) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_NULL_ARGUMENT
            && ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_SERVER_NOT_REACHABLE)
            CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_PKICONF_NOT_RECEIVED);
        else
            add_error_data("unable to send certConf");
		goto err;
	}

	if (CMP_protection_verify( PKIconf, ctx->protectionAlgor, X509_get_pubkey( (X509*) caCert), NULL)) {
		CMP_printf( ctx,  "SUCCESS: validating protection of incoming message");
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
	if (kur) CMP_PKIMESSAGE_free(kur);
	if (kup) CMP_PKIMESSAGE_free(kup);
	if (certConf) CMP_PKIMESSAGE_free(certConf);
	if (PKIconf) CMP_PKIMESSAGE_free(PKIconf);

	/* print out openssl and cmp errors to error_cb if it's set */
	if (ctx&&ctx->error_cb) ERR_print_errors_cb(CMP_error_callback, (void*) ctx);

	return NULL;
}

CMP_CAKEYUPDANNCONTENT *CMP_doCAKeyUpdateReq( CMPBIO *cbio, CMP_CTX *ctx)
{
#if 0
	itav = sk_CMP_INFOTYPEANDVALUE_value( genp->body->value.genp, 0);
	cku = itav->infoValue.caKeyUpdateInfo;

	CMP_printf( ctx, "INFO: Attempting to verify received ckuann certificates.");
	// printf("%08x\n", cku->newWithNew->cert_info->key);
	// printf("%08x\n", cku->newWithNew->cert_info->key->public_key);
	
	/*
	EVP_PKEY *newpk = cku->newWithNew->cert_info->key->pkey;
	EVP_PKEY *oldpk = cku->oldWithNew->cert_info->key->pkey;
	printf("oldWithNew: %d\n", X509_verify(cku->oldWithNew, newpk));
	printf("newWithold: %d\n", X509_verify(cku->newWithOld, oldpk));
	*/
#endif

	return (CMP_CAKEYUPDANNCONTENT*) CMP_doGeneralMessageSeq( cbio, ctx, NID_id_it_caKeyUpdateInfo, NULL);
}

X509_CRL *CMP_doCurrentCRLReq( CMPBIO *cbio, CMP_CTX *ctx)
{
	return (X509_CRL*) CMP_doGeneralMessageSeq( cbio, ctx, NID_id_it_currentCRL, NULL);
}

/* ############################################################################ */
/* ############################################################################ */
char *CMP_doGeneralMessageSeq( CMPBIO *cbio, CMP_CTX *ctx, int nid, char *value)
{
	CMP_PKIMESSAGE *genm=NULL;
	CMP_PKIMESSAGE *genp=NULL;
	CMP_INFOTYPEANDVALUE *itav=NULL;

	/* check if all necessary options are set */
	if (!cbio || !ctx || !ctx->caCert || !ctx->referenceValue || !ctx->secretValue) {
		CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_INVALID_ARGS);
	 	goto err;
	}

	/* set the protection Algor which will be used during the whole session */
	CMP_CTX_set_protectionAlgor( ctx, CMP_ALG_PBMAC);

	/* crate GenMsgContent - genm*/
	// if (! (genm = CMP_genm_new(ctx, NID_id_it_caKeyUpdateInfo))) goto err;
	if (! (genm = CMP_genm_new(ctx, nid, value))) goto err;

	CMP_printf( ctx, "INFO: Sending General Message");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, genm, &genp))) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_NULL_ARGUMENT
            && ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_SERVER_NOT_REACHABLE)
            CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_GENP_NOT_RECEIVED);
        else
            add_error_data("unable to send genm");
		goto err;
	}

	CMP_CTX_set1_sender(ctx, genp->header->sender->d.directoryName);

	if (CMP_protection_verify( genp, ctx->protectionAlgor, NULL, ctx->secretValue))
		CMP_printf( ctx,  "SUCCESS: validating protection of incoming message");
	else {
		CMPerr(CMP_F_CMP_DOPKIINFOREQSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
	}

	/* make sure the received messagetype indicates an GENP message */
	if (CMP_PKIMESSAGE_get_bodytype(genp) != V_CMP_PKIBODY_GENP) {
		STACK_OF(ASN1_UTF8STRING) *strstack = CMP_CERTREPMESSAGE_PKIStatusString_get0(genp->body->value.ip, 0);
		ASN1_UTF8STRING *status = NULL;

		char errmsg[256];
		CMPerr(CMP_F_CMP_DOPKIINFOREQSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data(genp, errmsg, sizeof(errmsg)));


		CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_UNKNOWN_PKISTATUS);
		while ((status = sk_ASN1_UTF8STRING_pop(strstack)))
			ERR_add_error_data(3, "statusString=\"", status->data, "\"");
		goto err;
	}

	itav = sk_CMP_INFOTYPEANDVALUE_value( genp->body->value.genp, 0);
	if (!itav) goto err;

	return itav->infoValue.ptr;
err:

	if (genm) CMP_PKIMESSAGE_free(genm);
	if (genp) CMP_PKIMESSAGE_free(genp);

	/* print out openssl and cmp errors to error_cb if it's set */
	if (ctx&&ctx->error_cb) ERR_print_errors_cb(CMP_error_callback, (void*) ctx);

	return NULL;
}


/* ############################################################################ */
/* ############################################################################ */
int CMP_doPKIInfoReqSeq( CMPBIO *cbio, CMP_CTX *ctx) {
	CMP_PKIMESSAGE *genm=NULL;
	CMP_PKIMESSAGE *genp=NULL;

	/* check if all necessary options are set */
	if (!cbio || !ctx || !ctx->caCert || !ctx->referenceValue || !ctx->secretValue) {
		CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_INVALID_ARGS);
		goto err;
	}

	/* set the protection Algor which will be used during the whole session */
	CMP_CTX_set_protectionAlgor( ctx, CMP_ALG_PBMAC);

	/* crate GenMsgContent - genm*/
	if (! (genm = CMP_genm_new(ctx, 0, NULL))) goto err;

	CMP_printf( ctx, "INFO: Sending General Message");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, genm, &genp))) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_NULL_ARGUMENT
            && ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_SERVER_NOT_REACHABLE)
            CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_GENP_NOT_RECEIVED);
        else
            add_error_data("unable to send genm");
		goto err;
	}

	if (CMP_protection_verify( genp, ctx->protectionAlgor, NULL, ctx->secretValue))
		CMP_printf( ctx,  "SUCCESS: validating protection of incoming message");
	else {
		CMPerr(CMP_F_CMP_DOPKIINFOREQSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
	}

	/* make sure the received messagetype indicates an GENP message */
	if (CMP_PKIMESSAGE_get_bodytype(genp) != V_CMP_PKIBODY_GENP) {
		STACK_OF(ASN1_UTF8STRING) *strstack = CMP_CERTREPMESSAGE_PKIStatusString_get0(genp->body->value.ip, 0);
		ASN1_UTF8STRING *status = NULL;

		char errmsg[256];
		CMPerr(CMP_F_CMP_DOPKIINFOREQSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data(genp, errmsg, sizeof(errmsg)));


		CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_UNKNOWN_PKISTATUS);
		while ((status = sk_ASN1_UTF8STRING_pop(strstack)))
			ERR_add_error_data(3, "statusString=\"", status->data, "\"");
		goto err;
	}

	return 1;

err:
	if (genm) CMP_PKIMESSAGE_free(genm);
	if (genp) CMP_PKIMESSAGE_free(genp);

	/* print out openssl and cmp errors to error_cb if it's set */
	if (ctx&&ctx->error_cb) ERR_print_errors_cb(CMP_error_callback, (void*) ctx);

	return 0;
}

#endif

