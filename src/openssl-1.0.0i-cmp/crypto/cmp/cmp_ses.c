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
 * Copyright 2007-2012 Nokia Siemens Networks Oy. ALL RIGHTS RESERVED.
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


/* ############################################################################ *
 * This callback is used to print out the OpenSSL error queue via'
 * ERR_print_errors_cb() to the ctx->error_cb() function set by the user
 * ############################################################################ */
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

/* ############################################################################ *
 * table used to translate PKIMessage body type number into a printable string
 * ############################################################################ */
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

/* ############################################################################ *
 * Adds text to the extra error data field of the last error in openssl's error
 * queue. ERR_add_error_data() simply overwrites the previous contents of the error
 * data, while this function can be used to add a string to the end of it.
 * ############################################################################ */
void CMP_add_error_data(const char *txt) {
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
 * When a 'waiting' PKIStatus has been received, this function is used to attempt
 * to poll for a response message. The maximum number of times to attempt polling
 * is set in ctx->maxPollCount, and between polling it waits the number of seconds
 * specified in pollrep->checkAfter.
 *
 * TODO: need to be able to set a maximum waiting time
 * ############################################################################ */
static int pollForResponse(CMP_CTX *ctx, CMPBIO *cbio, CMP_CERTREPMESSAGE *certrep, CMP_PKIMESSAGE **msg) {
	int i;
	CMP_printf(ctx, "INFO: Received 'waiting' PKIStatus, attempting to poll server for response.");
	for (i = 0; i < ctx->maxPollCount; i++) {
		CMP_PKIMESSAGE *preq = CMP_pollReq_new(ctx, 0);
		CMP_PKIMESSAGE *prep = NULL;
		CMP_POLLREP *pollRep = NULL;

		if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, preq, &prep))) {
			if (ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_NULL_ARGUMENT
				&& ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_SERVER_NOT_REACHABLE)
				CMPerr(CMP_F_POLLFORRESPONSE, CMP_R_POLLREP_NOT_RECEIVED);
			else
				CMP_add_error_data("unable to send ir");
			goto err;
		}

		/* TODO handle multiple pollreqs */
		if ( CMP_PKIMESSAGE_get_bodytype(prep) == V_CMP_PKIBODY_POLLREP) {
			int checkAfter;
			pollRep = sk_CMP_POLLREP_value(prep->body->value.pollRep, 0);
			checkAfter = ASN1_INTEGER_get(pollRep->checkAfter);
			CMP_printf(ctx, "INFO: Waiting %ld seconds before sending pollReq...\n", checkAfter);
			sleep(checkAfter);
		}
		else if (CMP_CERTREPMESSAGE_PKIStatus_get( certrep, 0) != CMP_PKISTATUS_waiting) {
			*msg = prep;
			return 1; /* final success */
		}

		CMP_PKIMESSAGE_free(preq);
		CMP_PKIMESSAGE_free(prep);
	}

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

	/* check if all necessary options are set */
	if (!cbio || !ctx || !ctx->newPkey ||
		 /* for authentication we need either reference/secret or external 
		  * identity certificate and private key */
		 (!(ctx->referenceValue && ctx->secretValue) && !(ctx->pkey && ctx->clCert)) ) {
		CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_INVALID_ARGS);
		goto err;
	}

	/* create Initialization Request - ir */
	if (! (ir = CMP_ir_new(ctx))) goto err;

	CMP_printf(ctx, "INFO: Sending Initialization Request");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, ir, &ip))) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_NULL_ARGUMENT
            && ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_SERVER_NOT_REACHABLE)
            CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_IP_NOT_RECEIVED);
        else
            CMP_add_error_data("unable to send ir");
		goto err;
	}

	/* TODO: standard when cert protection: use trusted_store + certs from extra
	 * certs to validate sender Cert */
#if 0
	/* either ctx->srvCert or trusted_store are acceptable */
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

	
	if (CMP_validate_msg(ctx, ip)) {
		CMP_printf( ctx, "SUCCESS: validating protection of incoming message");
	} else {
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
		if (!pollForResponse(ctx, cbio, ip->body->value.ip, &ip)) {
            CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_IP_NOT_RECEIVED);
			ERR_add_error_data(1, "received 'waiting' pkistatus but polling failed");
			goto err;
		}

	ctx->newClCert = CMP_CERTREPMESSAGE_get_certificate(ctx, ip->body->value.ip);
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
            CMP_add_error_data("unable to send certConf");
		goto err;
	}

	if (CMP_validate_msg(ctx, PKIconf)) {
		CMP_printf(  ctx, "SUCCESS: validating protection of incoming message");
	} else {
		CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
	}

	/* make sure the received messagetype indicates an PKIconf message */
	if (CMP_PKIMESSAGE_get_bodytype(PKIconf) != V_CMP_PKIBODY_PKICONF) {
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data( PKIconf, errmsg, sizeof(errmsg)));
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

/* ############################################################################ *
 * ############################################################################ */
int CMP_doRevocationRequestSeq( CMPBIO *cbio, CMP_CTX *ctx) {
	CMP_PKIMESSAGE *rr=NULL;
	CMP_PKIMESSAGE *rp=NULL;
	// X509 *srvCert=NULL;

	if (!cbio || !ctx || !ctx->serverName || !ctx->pkey ||
		!ctx->clCert || !ctx->srvCert) {
		CMPerr(CMP_F_CMP_DOREVOCATIONREQUESTSEQ, CMP_R_INVALID_ARGS);
		goto err;
	}

	if (! (rr = CMP_rr_new(ctx))) goto err;

	CMP_printf( ctx, "INFO: Sending Revocation Request");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, rr, &rp))) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_NULL_ARGUMENT
            && ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_SERVER_NOT_REACHABLE)
            CMPerr(CMP_F_CMP_DOREVOCATIONREQUESTSEQ, CMP_R_RP_NOT_RECEIVED);
        else
            CMP_add_error_data("unable to send rr");
		goto err;
	}

	if (CMP_PKIMESSAGE_get_bodytype( rp) != V_CMP_PKIBODY_RP) {
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOREVOCATIONREQUESTSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data( rp, errmsg, sizeof(errmsg)));
		goto err;
	}


	if (CMP_validate_msg(ctx, rp)) {
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

	/* check if all necessary options are set */
	if (!cbio || !ctx || !ctx->serverName
		|| !ctx->pkey || !ctx->clCert ||
		(!ctx->srvCert && !ctx->trusted_store)) {
		CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_INVALID_ARGS);
		goto err;
	}

	/* create Certificate Request - cr */
	if (! (cr = CMP_cr_new(ctx))) goto err;

	CMP_printf( ctx, "INFO: Sending Certificate Request");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, cr, &cp))) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_NULL_ARGUMENT
            && ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_SERVER_NOT_REACHABLE)
            CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_CP_NOT_RECEIVED);
        else
            CMP_add_error_data("unable to send cr");
		goto err;
	}

	if (CMP_validate_msg(ctx, cp)) {
		CMP_printf(  ctx, "SUCCESS: validating protection of incoming message");
	} else {
		CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
	}

	if (CMP_PKIMESSAGE_get_bodytype( cp) != V_CMP_PKIBODY_CP) {
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data( cp, errmsg, sizeof(errmsg)));
		goto err;
	}


	if (CMP_CERTREPMESSAGE_PKIStatus_get( cp->body->value.cp, 0) == CMP_PKISTATUS_waiting)
		if (!pollForResponse(ctx, cbio, cp->body->value.cp, &cp)) {
            CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_CP_NOT_RECEIVED);
			ERR_add_error_data(1, "received 'waiting' pkistatus but polling failed");
			goto err;
		}

	ctx->newClCert = CMP_CERTREPMESSAGE_get_certificate(ctx, cp->body->value.cp);
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
            CMP_add_error_data("unable to send certConf");
		goto err;
	}

	if (CMP_validate_msg(ctx, PKIconf)) {
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
		ERR_add_error_data(1, PKIError_data( PKIconf, errmsg, sizeof(errmsg)));
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

	/* check if all necessary options are set */
	if (!cbio || !ctx || !ctx->serverName
		|| !ctx->pkey || !ctx->newPkey || !ctx->clCert
		|| (!ctx->srvCert && !ctx->trusted_store)) {
		CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_INVALID_ARGS);
		goto err;
	}

	/* create Key Update Request - kur */
	if (! (kur = CMP_kur_new(ctx))) goto err;

	CMP_printf( ctx, "INFO: Sending Key Update Request");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, kur, &kup))) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_NULL_ARGUMENT
            && ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_SERVER_NOT_REACHABLE)
            CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_KUP_NOT_RECEIVED);
        else
            CMP_add_error_data("unable to send kur");
		goto err;
	}

	if (CMP_validate_msg(ctx, kup)) {
		CMP_printf( ctx,  "SUCCESS: validating protection of incoming message");
	} else {
		CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
	}

	if (CMP_PKIMESSAGE_get_bodytype( kup) != V_CMP_PKIBODY_KUP) {
		ASN1_UTF8STRING *ftstr = NULL;
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data( kup, errmsg, sizeof(errmsg)));
		while ((ftstr = sk_ASN1_UTF8STRING_pop(kup->header->freeText)))
			ERR_add_error_data(3, "freeText=\"", ftstr->data, "\"");
		goto err;
	}

	if (CMP_CERTREPMESSAGE_PKIStatus_get( kup->body->value.kup, 0) == CMP_PKISTATUS_waiting)
		if (!pollForResponse(ctx, cbio, kup->body->value.kup, &kup)) {
            CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_KUP_NOT_RECEIVED);
			ERR_add_error_data(1, "received 'waiting' pkistatus but polling failed");
			goto err;
		}

	ctx->newClCert = CMP_CERTREPMESSAGE_get_certificate(ctx, kup->body->value.kup);
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
            CMP_add_error_data("unable to send certConf");
		goto err;
	}

	if (CMP_validate_msg(ctx, PKIconf)) {
		CMP_printf( ctx,  "SUCCESS: validating protection of incoming message");
	} else {
		CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
	}

	/* make sure the received messagetype indicates an PKIconf message */
	if (CMP_PKIMESSAGE_get_bodytype(PKIconf) != V_CMP_PKIBODY_PKICONF) {
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data( PKIconf, errmsg, sizeof(errmsg)));
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

/* ############################################################################ *
 * ############################################################################ */
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

/* ############################################################################ *
 * ############################################################################ */
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
	if (!cbio || !ctx || !ctx->srvCert || !ctx->referenceValue || !ctx->secretValue) {
		CMPerr(CMP_F_CMP_DOGENERALMESSAGESEQ, CMP_R_INVALID_ARGS);
	 	goto err;
	}

	/* crate GenMsgContent - genm*/
	// if (! (genm = CMP_genm_new(ctx, NID_id_it_caKeyUpdateInfo))) goto err;
	if (! (genm = CMP_genm_new(ctx, nid, value))) goto err;

	CMP_printf( ctx, "INFO: Sending General Message");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, genm, &genp))) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_NULL_ARGUMENT
            && ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_SERVER_NOT_REACHABLE)
            CMPerr(CMP_F_CMP_DOGENERALMESSAGESEQ, CMP_R_GENP_NOT_RECEIVED);
        else
            CMP_add_error_data("unable to send genm");
		goto err;
	}

	if (CMP_validate_msg(ctx, genp)) {
		CMP_printf( ctx,  "SUCCESS: validating protection of incoming message");
	} else {
		CMPerr(CMP_F_CMP_DOGENERALMESSAGESEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
	}

	/* make sure the received messagetype indicates an GENP message */
	if (CMP_PKIMESSAGE_get_bodytype(genp) != V_CMP_PKIBODY_GENP) {
		STACK_OF(ASN1_UTF8STRING) *strstack = CMP_CERTREPMESSAGE_PKIStatusString_get0(genp->body->value.ip, 0);
		ASN1_UTF8STRING *status = NULL;

		char errmsg[256];
		CMPerr(CMP_F_CMP_DOGENERALMESSAGESEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data( genp, errmsg, sizeof(errmsg)));


		CMPerr(CMP_F_CMP_DOGENERALMESSAGESEQ, CMP_R_UNKNOWN_PKISTATUS);
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
	if (!cbio || !ctx || !ctx->srvCert || !ctx->referenceValue || !ctx->secretValue) {
		CMPerr(CMP_F_CMP_DOPKIINFOREQSEQ, CMP_R_INVALID_ARGS);
		goto err;
	}

	/* crate GenMsgContent - genm*/
	if (! (genm = CMP_genm_new(ctx, 0, NULL))) goto err;

	CMP_printf( ctx, "INFO: Sending General Message");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, genm, &genp))) {
        if (ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_NULL_ARGUMENT
            && ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_SERVER_NOT_REACHABLE)
            CMPerr(CMP_F_CMP_DOPKIINFOREQSEQ, CMP_R_GENP_NOT_RECEIVED);
        else
            CMP_add_error_data("unable to send genm");
		goto err;
	}

	if (CMP_validate_msg(ctx, genp)) {
		CMP_printf( ctx,  "SUCCESS: validating protection of incoming message");
	} else {
		CMPerr(CMP_F_CMP_DOPKIINFOREQSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
	}

	/* make sure the received messagetype indicates an GENP message */
	if (CMP_PKIMESSAGE_get_bodytype(genp) != V_CMP_PKIBODY_GENP) {
		STACK_OF(ASN1_UTF8STRING) *strstack = CMP_CERTREPMESSAGE_PKIStatusString_get0(genp->body->value.ip, 0);
		ASN1_UTF8STRING *status = NULL;

		char errmsg[256];
		CMPerr(CMP_F_CMP_DOPKIINFOREQSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data( genp, errmsg, sizeof(errmsg)));


		CMPerr(CMP_F_CMP_DOPKIINFOREQSEQ, CMP_R_UNKNOWN_PKISTATUS);
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

