
  /***********************************************************************/
  /* Copyright 2010-2011 Nokia Siemens Networks Oy. ALL RIGHTS RESERVED. */
  /* Written by Miikka Viljanen <mviljane@users.sourceforge.net>         */
  /***********************************************************************/

#include "mod_cmpsrv.h"

/* TODO: these functions will be moved to the CMP library.
 * they are here only for testing purposes.*/

/* ############################################################################ */
/* ############################################################################ */
CMP_PKIMESSAGE * CMP_ip_new( CMP_CTX *ctx, X509 *cert)
{
	UNUSED(ctx);

	CMP_PKIMESSAGE *msg=NULL;

	// if (!ctx) goto err;
	if (!ctx->referenceValue) goto err;
	if (!ctx->secretValue) goto err;
	// if (!ctx->pkey) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;

	CMP_PKIHEADER_set1(msg->header, ctx);
	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_IP);

	CMP_PKIHEADER_set1_sender( msg->header, X509_get_subject_name( (X509*)ctx->caCert));


#if 0
	/* set implicitconfirm */
	msg->header->generalInfo = sk_CMP_INFOTYPEANDVALUE_new_null();
	CMP_INFOTYPEANDVALUE *itav = CMP_INFOTYPEANDVALUE_new();
	itav->infoType = OBJ_nid2obj(NID_id_it_implicitConfirm);
	sk_CMP_INFOTYPEANDVALUE_push(msg->header->generalInfo, itav);
#endif

	/* Generate X509 certificate */
	/*
		 int			X509_set_version(X509 *x,long version);
		 int			X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial);
		 ASN1_INTEGER *	X509_get_serialNumber(X509 *x);
		 int			X509_set_issuer_name(X509 *x, X509_NAME *name);
		 X509_NAME *	X509_get_issuer_name(X509 *a);
		 int			X509_set_subject_name(X509 *x, X509_NAME *name);
		 X509_NAME *	X509_get_subject_name(X509 *a);
		 int			X509_set_notBefore(X509 *x, const ASN1_TIME *tm);
		 int			X509_set_notAfter(X509 *x, const ASN1_TIME *tm);
		 int			X509_set_pubkey(X509 *x, EVP_PKEY *pkey);
		 EVP_PKEY *	X509_get_pubkey(X509 *x);
		 ASN1_BIT_STRING * X509_get0_pubkey_bitstr(const X509 *x);
		 int		X509_certificate_type(X509 *x,EVP_PKEY *pubkey optional );
		 */

	// CRMF_CERTREQMSG *reqmsg = sk_CRMF_CERTREQMSG_value( msg->body->value.ir, 0);
	// CMP_PKIHEADER_set1_recipient( msg->header, reqmsg->certReq->certTemplate->subject);

	CMP_CERTREPMESSAGE *resp = CMP_CERTREPMESSAGE_new();

	CMP_CERTRESPONSE *cr = CMP_CERTRESPONSE_new();
	ASN1_INTEGER_set(cr->certReqId, 0);
	ASN1_INTEGER_set(cr->status->status, CMP_PKISTATUS_accepted);

	cr->certifiedKeyPair = CMP_CERTIFIEDKEYPAIR_new();
	cr->certifiedKeyPair->certOrEncCert->type = CMP_CERTORENCCERT_CERTIFICATE;
	cr->certifiedKeyPair->certOrEncCert->value.certificate = cert;

	resp->response = sk_CMP_CERTRESPONSE_new_null();
	sk_CMP_CERTRESPONSE_push(resp->response, cr);
	
	resp->caPubs = sk_X509_new_null();
	//todo send cacert

	msg->body->value.ip = resp;

	return msg;

err:
	return NULL;
}


CMP_PKIMESSAGE * CMP_kup_new( CMP_CTX *ctx, X509 *cert)
{
	UNUSED(ctx);

	CMP_PKIMESSAGE *msg=NULL;

	// if (!ctx) goto err;
	if (!ctx->referenceValue) goto err;
	if (!ctx->secretValue) goto err;
	// if (!ctx->pkey) goto err;

	if (!(msg = CMP_PKIMESSAGE_new())) goto err;

	CMP_PKIHEADER_set1(msg->header, ctx);
	CMP_PKIMESSAGE_set_bodytype( msg, V_CMP_PKIBODY_KUP);

	CMP_PKIHEADER_set1_sender( msg->header, X509_get_subject_name( (X509*)ctx->caCert));


#if 0
	/* set implicitconfirm */
	msg->header->generalInfo = sk_CMP_INFOTYPEANDVALUE_new_null();
	CMP_INFOTYPEANDVALUE *itav = CMP_INFOTYPEANDVALUE_new();
	itav->infoType = OBJ_nid2obj(NID_id_it_implicitConfirm);
	sk_CMP_INFOTYPEANDVALUE_push(msg->header->generalInfo, itav);
#endif

	/* Generate X509 certificate */
	/*
		 int			X509_set_version(X509 *x,long version);
		 int			X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial);
		 ASN1_INTEGER *	X509_get_serialNumber(X509 *x);
		 int			X509_set_issuer_name(X509 *x, X509_NAME *name);
		 X509_NAME *	X509_get_issuer_name(X509 *a);
		 int			X509_set_subject_name(X509 *x, X509_NAME *name);
		 X509_NAME *	X509_get_subject_name(X509 *a);
		 int			X509_set_notBefore(X509 *x, const ASN1_TIME *tm);
		 int			X509_set_notAfter(X509 *x, const ASN1_TIME *tm);
		 int			X509_set_pubkey(X509 *x, EVP_PKEY *pkey);
		 EVP_PKEY *	X509_get_pubkey(X509 *x);
		 ASN1_BIT_STRING * X509_get0_pubkey_bitstr(const X509 *x);
		 int		X509_certificate_type(X509 *x,EVP_PKEY *pubkey optional );
		 */

	// CRMF_CERTREQMSG *reqmsg = sk_CRMF_CERTREQMSG_value( msg->body->value.ir, 0);
	// CMP_PKIHEADER_set1_recipient( msg->header, reqmsg->certReq->certTemplate->subject);

	CMP_CERTREPMESSAGE *resp = CMP_CERTREPMESSAGE_new();

	CMP_CERTRESPONSE *cr = CMP_CERTRESPONSE_new();
	ASN1_INTEGER_set(cr->certReqId, 0);
	ASN1_INTEGER_set(cr->status->status, CMP_PKISTATUS_accepted);

	cr->certifiedKeyPair = CMP_CERTIFIEDKEYPAIR_new();
	cr->certifiedKeyPair->certOrEncCert->type = CMP_CERTORENCCERT_CERTIFICATE;
	cr->certifiedKeyPair->certOrEncCert->value.certificate = cert;

	resp->response = sk_CMP_CERTRESPONSE_new_null();
	sk_CMP_CERTRESPONSE_push(resp->response, cr);
	
	// resp->caPubs = sk_X509_new_null();

	msg->body->value.kup = resp;

	return msg;

err:
	return NULL;
}
