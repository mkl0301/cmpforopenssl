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
 *		notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *		notice, this list of conditions and the following disclaimer in
 *		the documentation and/or other materials provided with the
 *		distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *		software must display the following acknowledgment:
 *		"This product includes software developed by the OpenSSL Project
 *		for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *		endorse or promote products derived from this software without
 *		prior written permission. For written permission, please contact
 *		openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *		nor may "OpenSSL" appear in their names without prior written
 *		permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *		acknowledgment:
 *		"This product includes software developed by the OpenSSL Project
 *		for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.	IN NO EVENT SHALL THE OpenSSL PROJECT OR
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
/* =========================== ACKNOWLEDGEMENTS =======================
 * 2008 - Sami Lehtonen - added CMP_doCertificateRequestSeq()
 */

#include <string.h>

#include <openssl/cmp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <unistd.h>


#ifndef HAVE_CURL

/* show some warning here? */

#else

/* TODO this is here to fool the openssl perl script that checks errors codes strictly */
static void func() { }
/* adds connection error information to OpenSSL error queue */
#define ADD_HTTP_ERROR_INFO(cmp_f_func, errcode, msg)\
		if (ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_NULL_ARGUMENT\
			&& ERR_GET_REASON(ERR_peek_last_error()) != CMP_R_SERVER_NOT_REACHABLE)\
			CMPerr(cmp_f_func, errcode);\
		else\
			add_error_data("unable to send "msg);

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

#define MSG_TYPE_STR(type)	\
	(((unsigned int) (type) < sizeof(V_CMP_TABLE)/sizeof(V_CMP_TABLE[0])) \
	 ? V_CMP_TABLE[(unsigned int)(type)] : "unknown")

/* ############################################################################ * 
 * internal function
 *
 * Prints error data of the given CMP_PKIMESSAGE into a buffer specified by out
 * and returns pointer to the buffer.
 * ############################################################################ */
static char *PKIError_data(CMP_PKIMESSAGE *msg, char *out, int outsize)
	{
	char tempbuf[256];
	switch (CMP_PKIMESSAGE_get_bodytype(msg))
		{
		case V_CMP_PKIBODY_ERROR:
			BIO_snprintf(out, outsize, "bodytype=%d, error=\"%s\"",
				V_CMP_PKIBODY_ERROR,
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
 * internal function
 *
 * Adds text to the extra error data field of the last error in openssl's error
 * queue. ERR_add_error_data() simply overwrites the previous contents of the error
 * data, while this function can be used to add a string to the end of it.
 * ############################################################################ */
static void add_error_data(const char *txt)
	{
	const char *current_error=NULL;
	ERR_peek_error_line_data(NULL, NULL, &current_error, NULL);
	ERR_add_error_data(3, current_error, ":", txt);
	}

/* ############################################################################ *
 * internal function
 *
 * When a 'waiting' PKIStatus has been received, this function is used to attempt
 * to poll for a response message. 
 *
 * A maxPollTime timeout can be set in the context.  The function will continue
 * to poll until the timeout is reached and then poll a last time even when that
 * is before the "checkAfter" sent by the server.  If ctx->maxPollTime is 0, the
 * timeout is disabled.
 *
 * returns 1 on success, returns received PKIMESSAGE in *msg argument
 * returns 0 on error or when timeout is reached without a received messsage
 *
 * TODO handle multiple pollreqs for multiple certificates
 * ############################################################################ */
static int pollForResponse(CMP_CTX *ctx, CMPBIO *cbio, CMP_CERTREPMESSAGE *certrep, CMP_PKIMESSAGE **msg)
	{
	int maxTimeLeft = ctx->maxPollTime;
	CMP_PKIMESSAGE *preq = NULL;
	CMP_PKIMESSAGE *prep = NULL;
	CMP_POLLREP *pollRep = NULL;

	CMP_printf(ctx, "INFO: Received 'waiting' PKIStatus, attempting to poll server for response.");
	for (;;)
		{
		if(!(preq = CMP_pollReq_new(ctx, 0))) goto err; /* TODO: this only handles one certificate request so far */

		/* immediately send the first pollReq */
		if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, preq, &prep)))
			{
			/* set message to error stack */
			ADD_HTTP_ERROR_INFO(CMP_F_POLLFORRESPONSE, CMP_R_POLLREP_NOT_RECEIVED, "pollReq");
			goto err;
			}

		/* handle potential pollRep */
		if (CMP_PKIMESSAGE_get_bodytype(prep) == V_CMP_PKIBODY_POLLREP)
			{
			int checkAfter;
			if(!(pollRep = sk_CMP_POLLREP_value(prep->body->value.pollRep, 0))) goto err; /* TODO: this only handles one certificate request so far */
			checkAfter = ASN1_INTEGER_get(pollRep->checkAfter);
			/* TODO: print OPTIONAL reason (PKIFreeText) from message */
			CMP_printf(ctx, "INFO: Waiting %ld seconds before sending pollReq...\n", checkAfter);

			if (ctx->maxPollTime != 0)
				{        /* timout is set in context */
				if (maxTimeLeft == 0) goto err; /* timeout reached */
				if (maxTimeLeft > checkAfter)
					{
					maxTimeLeft -= checkAfter;
					}
				else
					{
					checkAfter = maxTimeLeft; /* poll a last time just when the set timeout will be reached */
					maxTimeLeft = 0;
					}
				}

			CMP_PKIMESSAGE_free(prep);
			CMP_PKIMESSAGE_free(preq);
			sleep(checkAfter);
			}
		else break; /* final success */
		}

	CMP_PKIMESSAGE_free(preq);
	*msg = prep;

	return 1; 
err:
	CMP_PKIMESSAGE_free(preq);
	CMP_PKIMESSAGE_free(prep);
	return 0;
	}


/* ############################################################################ *
 * send certConf for IR, CR or KUR sequences
 * returns 1 on success, 0 on error
 * ############################################################################ */
static int sendCertConf( CMPBIO *cbio, CMP_CTX *ctx)
	{
	CMP_PKIMESSAGE *certConf=NULL;
	CMP_PKIMESSAGE *PKIconf=NULL;

	/* crate Certificate Confirmation - certConf */
	if (!(certConf = CMP_certConf_new(ctx))) goto err;

	CMP_printf( ctx, "INFO: Sending Certificate Confirm");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, certConf, &PKIconf)))
		{
		ADD_HTTP_ERROR_INFO(CMP_F_SENDCERTCONF, CMP_R_PKICONF_NOT_RECEIVED, "certConf");
		goto err;
		}

	/* make sure the received messagetype indicates an PKIconf message */
	if (CMP_PKIMESSAGE_get_bodytype(PKIconf) != V_CMP_PKIBODY_PKICONF)
		{
		char errmsg[256];
		CMPerr(CMP_F_SENDCERTCONF, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data( PKIconf, errmsg, sizeof(errmsg)));
		goto err;
		}

	/* validate message protection */
	if (CMP_validate_msg(ctx, PKIconf))
		{
		CMP_printf( ctx,"SUCCESS: validating protection of incoming message");
		}
	else
		{
		CMPerr(CMP_F_SENDCERTCONF, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
		}

	/* compare received nonce with the one sent in certConf */
	if (PKIconf->header->recipNonce)
		{
		if(ASN1_OCTET_STRING_cmp(certConf->header->senderNonce, PKIconf->header->recipNonce))
			{
			CMPerr(CMP_F_SENDCERTCONF, CMP_R_ERROR_NONCES_DO_NOT_MATCH);
			goto err;
			}
		} /* it's not clear from the RFC whether recipNonce MUST be set or not */

	CMP_PKIMESSAGE_free(certConf);
	CMP_PKIMESSAGE_free(PKIconf);
	return 1;
err:
	if (certConf) CMP_PKIMESSAGE_free(certConf);
	if (PKIconf) CMP_PKIMESSAGE_free(PKIconf);
	return 0;
	}

/* ############################################################################ *
 * internal function
 *
 * saves error information from PKIStatus field of a certrepmessage into the ctx
 * TODO: in case we would get multiple certreps, this function would need to be 
 *       extended to save the status from each one
 * ############################################################################ */
static void save_certrep_statusInfo(CMP_CTX *ctx, CMP_CERTREPMESSAGE *certrep)
	{
	CMP_CERTRESPONSE *resp=NULL;
	int i = 0;

	if (sk_CMP_CERTRESPONSE_num(certrep->response) > 0 &&
		(resp = sk_CMP_CERTRESPONSE_value(certrep->response, 0)))
		{
		if (resp->status)
			CMP_CTX_set_failInfoCode(ctx, resp->status->failInfo);
		ctx->lastPKIStatus = CMP_PKISTATUSINFO_PKIstatus_get(resp->status);

		if (!ctx->lastStatusString)
			ctx->lastStatusString = sk_ASN1_UTF8STRING_new_null();

		if (ctx->lastStatusString)
			{
			for (i = 0; i < sk_ASN1_UTF8STRING_num(resp->status->statusString); i++)
				{
				ASN1_UTF8STRING *str = sk_ASN1_UTF8STRING_value(resp->status->statusString, i);
				sk_ASN1_UTF8STRING_push(ctx->lastStatusString, ASN1_STRING_dup(str));
				}
			}
		}
	}

/* ############################################################################ *
 * do the full sequence for IR, including IR, IP, certConf, PKIconf and
 * potential polling
 *
 * All options need to be set in the context.
 *
 * TODO: another function to request two certificates at once should be created
 *
 * returns pointer to received certificate, NULL if none was received
 * ############################################################################ */
X509 *CMP_doInitialRequestSeq( CMPBIO *cbio, CMP_CTX *ctx)
	{
	CMP_PKIMESSAGE *ir=NULL;
	CMP_PKIMESSAGE *ip=NULL;

	/* check if all necessary options are set */
	if (!cbio || !ctx || !ctx->newPkey ||
		/* for authentication we need either reference/secret or external 
		 * identity certificate and private key, the server name/cert might not be
		 * known here yet especiallaly in case of E.7 */
			(!(ctx->referenceValue && ctx->secretValue) &&  /* MSG_MAC_ALG */
			!(ctx->pkey && ctx->clCert)) )
		{ /* MSG_SIG_ALG for E.7 */
		CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_INVALID_ARGS);
		goto err;
		}

	/* create Initialization Request - ir */
	if (!(ir = CMP_ir_new(ctx))) goto err;

	CMP_printf(ctx, "INFO: Sending Initialization Request");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, ir, &ip)))
		{
		ADD_HTTP_ERROR_INFO(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_IP_NOT_RECEIVED, "ir");
		goto err;
		}
	
	/* catch if the received messagetype does not indicate an IP message (e.g. error)*/
	if (CMP_PKIMESSAGE_get_bodytype(ip) != V_CMP_PKIBODY_IP)
		{
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data(ip, errmsg, sizeof(errmsg)));
		goto err;
		}

	save_certrep_statusInfo(ctx, ip->body->value.ip);

	/* validate message protection */
	if (CMP_validate_msg(ctx, ip))
		{
		CMP_printf( ctx, "SUCCESS: validating protection of incoming message");
		} else {
		CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
		}

	/* compare received nonce with the one sent in IR */
	if (ip->header->recipNonce)
		{
		if(ASN1_OCTET_STRING_cmp(ir->header->senderNonce, ip->header->recipNonce))
			{
			/* senderNonce != recipNonce (sic although there is no "!" in the if) */
			CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_ERROR_NONCES_DO_NOT_MATCH);
			goto err;
			}
		} /* it's not clear from the RFC whether recipNonce MUST be set or not */
	CMP_CTX_set1_recipNonce(ctx, ip->header->senderNonce); /* store for setting in the next msg */

	/* make sure the PKIStatus for the *first* CERTrepmessage indicates a certificate was granted */
	/* TODO handle second CERTrepmessages if two would have sent */
	if (CMP_CERTREPMESSAGE_PKIStatus_get( ip->body->value.ip, 0) == CMP_PKISTATUS_waiting)
		if (!pollForResponse(ctx, cbio, ip->body->value.ip, &ip))
			{
			CMPerr(CMP_F_CMP_DOINITIALREQUESTSEQ, CMP_R_IP_NOT_RECEIVED);
			ERR_add_error_data(1, "received 'waiting' pkistatus but polling failed");
			goto err;
			}

	if (!(ctx->newClCert = CMP_CERTREPMESSAGE_get_certificate(ctx, ip->body->value.ip))) goto err;

	/* if the CA returned certificates in the caPubs field, copy them
	 * to the context so that they can be retrieved if necessary 
	 *
	 * section 5.3.2:
	 * Note that if the PKI
	 * Message Protection is "shared secret information" (see Section
	 * 5.1.3), then any certificate transported in the caPubs field may be
	 * directly trusted as a root CA certificate by the initiator. */

	if (ip->body->value.ip->caPubs)
		CMP_CTX_set1_caPubs(ctx, ip->body->value.ip->caPubs);

	/* copy any received extraCerts to ctx->extraCertsIn so they can be retrieved */
	if (ip->extraCerts)
		CMP_CTX_set1_extraCertsIn(ctx, ip->extraCerts);

	/* check if implicit confirm is set in generalInfo and send certConf if not */
	if (!CMP_PKIMESSAGE_check_implicitConfirm(ip)) 
		if (!sendCertConf(cbio, ctx)) goto err;

	CMP_PKIMESSAGE_free(ir);
	CMP_PKIMESSAGE_free(ip);
	return ctx->newClCert;

err:
	if (ir) CMP_PKIMESSAGE_free(ir);
	if (ip) CMP_PKIMESSAGE_free(ip);

	/* print out openssl and cmp errors to error_cb if it's set */
	if (ctx&&ctx->error_cb) ERR_print_errors_cb(CMP_CTX_error_callback, (void*) ctx);
	return NULL;
	}

/* ############################################################################ *
 * do the full sequence for RR, including RR, RP and potential polling
 *
 * All options need to be set in the context.
 *
 * TODO: this function can only revoke one certifcate so far, should be possible
 * for several according to 5.3.9
 * TODO: this actually revokes the current clCertificate - it might be desired
 * to revoke another certificate the EE posesses.
 *
 * The RFC is vague in which PKIStatus should be returned by the server, so we
 * take "accepted, grantedWithMods, revocationWaring, revocationNotification"
 * as information that the certifcate was revoked, "rejection" as information
 * that the revocation was rejected and don't expect "waiting, keyUpdateWarning"
 * (which are handled as error)
 *
 * returns according to PKIStatus received, 0 on error
 *          accepted               (1)
 *          grantedWithMods        (2)
 *          rejection              (3) (this is not an error!)
 *          revocationWarning      (5)
 *          revocationNotification (6)
 * ############################################################################ */
int CMP_doRevocationRequestSeq( CMPBIO *cbio, CMP_CTX *ctx)
	{
	CMP_PKIMESSAGE *rr=NULL;
	CMP_PKIMESSAGE *rp=NULL;
	int pkiStatus = 0;

	if (!cbio || !ctx || !ctx->serverName || !ctx->pkey ||
		!ctx->clCert || !(ctx->srvCert || ctx->trusted_store))
		{
		CMPerr(CMP_F_CMP_DOREVOCATIONREQUESTSEQ, CMP_R_INVALID_ARGS);
		goto err;
		}

	if (! (rr = CMP_rr_new(ctx))) goto err;

	CMP_printf( ctx, "INFO: Sending Revocation Request");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, rr, &rp)))
		{
		ADD_HTTP_ERROR_INFO(CMP_F_CMP_DOREVOCATIONREQUESTSEQ, CMP_R_RP_NOT_RECEIVED, "rr");
		goto err;
		}

	/* make sure the received messagetype indicates an RP message */
	if (CMP_PKIMESSAGE_get_bodytype( rp) != V_CMP_PKIBODY_RP)
		{
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOREVOCATIONREQUESTSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data( rp, errmsg, sizeof(errmsg)));
		goto err;
		}

	/* validate message protection */
	if (CMP_validate_msg(ctx, rp))
		{
		CMP_printf(  ctx, "SUCCESS: validating protection of incoming message");
		}
	else
		{
		CMPerr(CMP_F_CMP_DOREVOCATIONREQUESTSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
		}

	/* compare received nonce with the one sent in RR */
	if (rp->header->recipNonce)
		{
		if(ASN1_OCTET_STRING_cmp(rr->header->senderNonce, rp->header->recipNonce))
			{
			/* senderNonce != recipNonce (sic although there is no "!" in the if) */
			CMPerr(CMP_F_CMP_DOREVOCATIONREQUESTSEQ, CMP_R_ERROR_NONCES_DO_NOT_MATCH);
			goto err;
			}
		} /* it's not clear from the RFC whether recipNonce MUST be set or not */
	

	/* evaluate PKIStatus field */
	switch (pkiStatus = CMP_REVREPCONTENT_PKIStatus_get( rp->body->value.rp, 0)) 
		{
		case CMP_PKISTATUS_accepted:
			CMP_printf( ctx, "INFO: revocation accepted (PKIStatus=accepted)");
			break;
		case CMP_PKISTATUS_grantedWithMods:
			CMP_printf( ctx, "INFO: revocation accepted (PKIStatus=grantedWithMods)");
			break;
		case CMP_PKISTATUS_rejection:
			CMP_printf( ctx, "INFO: revocation rejected (PKIStatus=rejection)");
			break;
		case CMP_PKISTATUS_revocationWarning:
			CMP_printf( ctx, "INFO: revocation accepted (PKIStatus=revocationWarning)");
			break;
		case CMP_PKISTATUS_revocationNotification:
			CMP_printf( ctx, "INFO: revocation accepted (PKIStatus=revocationNotification)");
			break;
		case CMP_PKISTATUS_waiting:
		case CMP_PKISTATUS_keyUpdateWarning:
			CMPerr(CMP_F_CMP_DOREVOCATIONREQUESTSEQ, CMP_R_UNEXPECTED_PKISTATUS);
			goto err;
		default:
			CMPerr(CMP_F_CMP_DOREVOCATIONREQUESTSEQ, CMP_R_UNKNOWN_PKISTATUS);
			goto err;
		}

	CMP_PKIMESSAGE_free(rr);
	CMP_PKIMESSAGE_free(rp);
	return (pkiStatus+1);
err:
	if (ctx&&ctx->error_cb) ERR_print_errors_cb(CMP_CTX_error_callback, (void*) ctx);
	if (rr) CMP_PKIMESSAGE_free(rr);
	if (rp) CMP_PKIMESSAGE_free(rp);
	return 0;
	}


/* ############################################################################ *
 * do the full sequence for CR, including CR, CP, certConf, PKIconf and
 * potential polling
 *
 * All options need to be set in the context.
 *
 * TODO: another function to request two certificates at once should be created
 *
 * returns pointer to received certificate, NULL if non was received
 * ############################################################################ */
X509 *CMP_doCertificateRequestSeq( CMPBIO *cbio, CMP_CTX *ctx)
	{
	CMP_PKIMESSAGE *cr=NULL;
	CMP_PKIMESSAGE *cp=NULL;

	/* check if all necessary options are set */
	if (!cbio || !ctx ||  !ctx->pkey ||
			(!(ctx->referenceValue && ctx->secretValue) && /* MSG_MAC_ALG */
			!(ctx->pkey && ctx->clCert && (ctx->srvCert || ctx->trusted_store))) /* MSG_SIG_ALG */
		)
		{
		CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_INVALID_ARGS);
		goto err;
		}

	/* create Certificate Request - cr */
	if (! (cr = CMP_cr_new(ctx))) goto err;

	CMP_printf( ctx, "INFO: Sending Certificate Request");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, cr, &cp)))
		{
		ADD_HTTP_ERROR_INFO(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_CP_NOT_RECEIVED, "cr");
		goto err;
		}

	/* make sure the received messagetype indicates an CP message */
	if (CMP_PKIMESSAGE_get_bodytype( cp) != V_CMP_PKIBODY_CP)
		{
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data( cp, errmsg, sizeof(errmsg)));
		goto err;
		}

	save_certrep_statusInfo(ctx, cp->body->value.cp);

	/* validate message protection */
	if (CMP_validate_msg(ctx, cp))
		{
		CMP_printf(  ctx, "SUCCESS: validating protection of incoming message");
		} else {
		CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
		}

	/* compare received nonce with the one sent in CR */
	if (cp->header->recipNonce)
		{
		if(ASN1_OCTET_STRING_cmp(cr->header->senderNonce, cp->header->recipNonce))
			{
			/* senderNonce != recipNonce (sic although there is no "!" in the if) */
			CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_ERROR_NONCES_DO_NOT_MATCH);
			goto err;
			}
		} /* it's not clear from the RFC whether recipNonce MUST be set or not */
	CMP_CTX_set1_recipNonce(ctx, cp->header->senderNonce); /* store for setting in the next msg */

	/* evaluate PKIStatus field */
	if (CMP_CERTREPMESSAGE_PKIStatus_get( cp->body->value.cp, 0) == CMP_PKISTATUS_waiting)
		if (!pollForResponse(ctx, cbio, cp->body->value.cp, &cp))
			{
			CMPerr(CMP_F_CMP_DOCERTIFICATEREQUESTSEQ, CMP_R_CP_NOT_RECEIVED);
			ERR_add_error_data(1, "received 'waiting' pkistatus but polling failed");
			goto err;
			}

	if (!(ctx->newClCert = CMP_CERTREPMESSAGE_get_certificate(ctx, cp->body->value.cp))) goto err;

	/* copy any received extraCerts to ctx->etraCertsIn so they can be retrieved */
	if (cp->extraCerts)
		CMP_CTX_set1_extraCertsIn(ctx, cp->extraCerts);

	/* check if implicit confirm is set in generalInfo and send certConf if not */
	if (!CMP_PKIMESSAGE_check_implicitConfirm(cp)) 
		if (!sendCertConf(cbio, ctx)) goto err;

	CMP_PKIMESSAGE_free(cr);
	CMP_PKIMESSAGE_free(cp);
	return ctx->newClCert;

err:
	if (cr) CMP_PKIMESSAGE_free(cr);
	if (cp) CMP_PKIMESSAGE_free(cp);

	/* print out openssl and cmp errors to error_cb if it's set */
	if (ctx&&ctx->error_cb) ERR_print_errors_cb(CMP_CTX_error_callback, (void*) ctx);
	return NULL;
	}

/* ############################################################################ *
 * do the full sequence for KUR, including KUR, KUP, certConf, PKIconf and
 * potential polling
 *
 * All options need to be set in the context.
 *
 * NB: the ctx->newKey can be set *by the user* as the same as the current key 
 * as per section 5.3.5:
 * An update is a replacement
 * certificate containing either a new subject public key or the current
 * subject public key (although the latter practice may not be
 * appropriate for some environments).
 *
 * TODO: another function to request two certificates at once should be created
 *
 * returns pointer to received certificate, NULL if non was received
 * ############################################################################ */
X509 *CMP_doKeyUpdateRequestSeq( CMPBIO *cbio, CMP_CTX *ctx)
	{
	CMP_PKIMESSAGE *kur=NULL;
	CMP_PKIMESSAGE *kup=NULL;

	/* check if all necessary options are set */
	if (!cbio || !ctx ||  !ctx->newPkey ||
			(!(ctx->referenceValue && ctx->secretValue) && /* MSG_MAC_ALG */
			!(ctx->pkey && ctx->clCert && (ctx->srvCert || ctx->trusted_store)))) /* MSG_SIG_ALG */
		{
		CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_INVALID_ARGS);
		goto err;
		}

	/* create Key Update Request - kur */
	if (! (kur = CMP_kur_new(ctx))) goto err;

	CMP_printf( ctx, "INFO: Sending Key Update Request");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, kur, &kup)))
		{
		ADD_HTTP_ERROR_INFO(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_KUP_NOT_RECEIVED, "kur");
		goto err;
		}

	/* make sure the received messagetype indicates an KUP message */
	if (CMP_PKIMESSAGE_get_bodytype( kup) != V_CMP_PKIBODY_KUP)
		{
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data( kup, errmsg, sizeof(errmsg)));
		goto err;
		}

	save_certrep_statusInfo(ctx, kup->body->value.kup);

	/* validate message protection */
	if (CMP_validate_msg(ctx, kup))
		{
		CMP_printf( ctx,	"SUCCESS: validating protection of incoming message");
		} else {
		CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
		}

	/* compare received nonce with the one sent in KUR */
	if (kup->header->recipNonce)
		{
		if(ASN1_OCTET_STRING_cmp(kur->header->senderNonce, kup->header->recipNonce))
			{
			/* senderNonce != recipNonce (sic although there is no "!" in the if) */
			CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_ERROR_NONCES_DO_NOT_MATCH);
			goto err;
			}
		} /* it's not clear from the RFC whether recipNonce MUST be set or not */
	CMP_CTX_set1_recipNonce(ctx, kup->header->senderNonce); /* store for setting in the next msg */

	/* evaluate PKIStatus field */
	if (CMP_CERTREPMESSAGE_PKIStatus_get( kup->body->value.kup, 0) == CMP_PKISTATUS_waiting)
		{
		if (!pollForResponse(ctx, cbio, kup->body->value.kup, &kup)) {
			CMPerr(CMP_F_CMP_DOKEYUPDATEREQUESTSEQ, CMP_R_KUP_NOT_RECEIVED);
			ERR_add_error_data(1, "received 'waiting' pkistatus but polling failed");
			goto err;
			}
		}

	if (!(ctx->newClCert = CMP_CERTREPMESSAGE_get_certificate(ctx, kup->body->value.kup))) goto err;

	/* copy received capubs to the context */
	if (kup->body->value.kup->caPubs)
		CMP_CTX_set1_caPubs(ctx, kup->body->value.kup->caPubs);

	/* copy any received extraCerts to ctx->etraCertsIn so they can be retrieved */
	if (kup->extraCerts)
		CMP_CTX_set1_extraCertsIn(ctx, kup->extraCerts);

	/* check if implicit confirm is set in generalInfo and send certConf if not */
	if (!CMP_PKIMESSAGE_check_implicitConfirm(kup)) 
		if (!sendCertConf(cbio, ctx)) goto err;

	CMP_PKIMESSAGE_free(kur);
	CMP_PKIMESSAGE_free(kup);
	return ctx->newClCert;

err:
	if (kur) CMP_PKIMESSAGE_free(kur);
	if (kup) CMP_PKIMESSAGE_free(kup);

	/* print out openssl and cmp errors to error_cb if it's set */
	if (ctx&&ctx->error_cb) ERR_print_errors_cb(CMP_CTX_error_callback, (void*) ctx);
	return NULL;
	}

/* ############################################################################ *
 * Sends a general message to the server to request information specified in the
 * InfoType and Value (itav) given in the nid (section 5.3.19 and E.5).
 *
 * all obtions besides the single ITAV and it's value to be sent need to be set
 * in the context.
 *
 * TODO: this could take multiple nids to have several ITAVs in the Genm
 *
 * returns pointer to stack of ITAVs received in the answer or NULL on error
 * ############################################################################ */
STACK_OF(CMP_INFOTYPEANDVALUE) *CMP_doGeneralMessageSeq( CMPBIO *cbio, CMP_CTX *ctx, int nid, char *value)
	{
	CMP_PKIMESSAGE *genm=NULL;
	CMP_PKIMESSAGE *genp=NULL;
	CMP_INFOTYPEANDVALUE *itav=NULL;
	STACK_OF(CMP_INFOTYPEANDVALUE) *rcvdItavs=NULL;

	/* check if all necessary options are set */
	if (!cbio || !ctx ||
			(!(ctx->referenceValue && ctx->secretValue) && /* MSG_MAC_ALG */
			!(ctx->pkey && ctx->clCert && (ctx->srvCert || ctx->trusted_store)))) /* MSG_SIG_ALG */
		{
		CMPerr(CMP_F_CMP_DOGENERALMESSAGESEQ, CMP_R_INVALID_ARGS);
		goto err;
		}

	/* crate GenMsgContent - genm*/
	if (! (genm = CMP_genm_new(ctx))) goto err;

	/* set itav - TODO: let this function take a STACK of ITAV as arguments */
	itav = CMP_INFOTYPEANDVALUE_new();
	itav->infoType = OBJ_nid2obj(nid);
	itav->infoValue.ptr = value;
	CMP_PKIMESSAGE_genm_item_push0( genm, itav);

	CMP_printf( ctx, "INFO: Sending General Message");
	if (! (CMP_PKIMESSAGE_http_perform(cbio, ctx, genm, &genp)))
		{
		ADD_HTTP_ERROR_INFO(CMP_F_CMP_DOGENERALMESSAGESEQ, CMP_R_GENP_NOT_RECEIVED, "genm");
		goto err;
		}

	/* make sure the received messagetype indicates an GENP message */
	if (CMP_PKIMESSAGE_get_bodytype(genp) != V_CMP_PKIBODY_GENP)
		{
		char errmsg[256];
		CMPerr(CMP_F_CMP_DOGENERALMESSAGESEQ, CMP_R_PKIBODY_ERROR);
		ERR_add_error_data(1, PKIError_data( genp, errmsg, sizeof(errmsg)));
		goto err;
		}

	/* validate message protection */
	if (CMP_validate_msg(ctx, genp))
		{
		CMP_printf( ctx, "SUCCESS: validating protection of incoming message");
		} else {
		CMPerr(CMP_F_CMP_DOGENERALMESSAGESEQ, CMP_R_ERROR_VALIDATING_PROTECTION);
		goto err;
		}

	/* compare received nonce with the one sent in genm */
	if (genp->header->recipNonce)
		{
		if(ASN1_OCTET_STRING_cmp(genm->header->senderNonce, genp->header->recipNonce))
			{
			CMPerr(CMP_F_CMP_DOGENERALMESSAGESEQ, CMP_R_ERROR_NONCES_DO_NOT_MATCH);
			goto err;
			}
		} /* it's not clear from the RFC whether recipNonce MUST be set or not */
	
	/* the received stack of itavs shouldn't be freed with the message */
	rcvdItavs = genp->body->value.genp;
	genp->body->value.genp = NULL;

	CMP_PKIMESSAGE_free(genm);
	CMP_PKIMESSAGE_free(genp);

	return rcvdItavs;

err:
	if (genm) CMP_PKIMESSAGE_free(genm);
	if (genp) CMP_PKIMESSAGE_free(genp);

	/* print out openssl and cmp errors to error_cb if it's set */
	if (ctx&&ctx->error_cb) ERR_print_errors_cb(CMP_CTX_error_callback, (void*) ctx);
	return NULL;
	}

#endif

