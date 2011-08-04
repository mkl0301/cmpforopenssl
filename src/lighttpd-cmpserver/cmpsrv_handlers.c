
  /***********************************************************************/
  /* Copyright 2010-2011 Nokia Siemens Networks Oy. ALL RIGHTS RESERVED. */
  /* Written by Miikka Viljanen <mviljane@users.sourceforge.net>         */
  /***********************************************************************/

#include "mod_cmpsrv.h"

#define CMPHANDLER_ARGS server *srv, cmpsrv_ctx *srv_ctx, CMP_PKIMESSAGE *msg, CMP_PKIMESSAGE **out
#define CMPHANDLER_FUNC(fn) static int fn(CMPHANDLER_ARGS)

typedef int (*cmp_messageHandler_t)(CMPHANDLER_ARGS);
#define V_CMP_PKIBODY_LAST (V_CMP_PKIBODY_POLLREP+1)
cmp_messageHandler_t msg_handlers[V_CMP_PKIBODY_LAST];

static STACK_OF(X509)* X509_stack_dup(const STACK_OF(X509)* stack)
{
    STACK_OF(X509) *newsk = NULL;
    int i;

    if (!stack) goto err;
    if (!(newsk = sk_X509_new_null())) goto err;

    for (i = 0; i < sk_X509_num(stack); i++)
        sk_X509_push(newsk, X509_dup(sk_X509_value(stack, i)));

    return newsk;
err:
    return 0;
}


CMPHANDLER_FUNC(handlemsg_ir)
{
  CMP_CTX *ctx = srv_ctx->cmp_ctx;

  int numCertRequests = sk_CRMF_CERTREQMSG_num(msg->body->value.ir);
  dbgmsg("sd", "number of cert requests:", numCertRequests);

  /* TODO handle multiple CERTREQMSGS? */
  // CRMF_CERTREQMSG *crm = sk_CRMF_CERTREQMSG_pop(msg->body->value.ir);
  // int reqId = ASN1_INTEGER_get(crm->certReq->certReqId);

  // TODO verify proof-of-posession

  CRMF_CERTREQMSG *reqmsg = sk_CRMF_CERTREQMSG_value( msg->body->value.ir, 0);
  CRMF_CERTREQUEST *req = reqmsg->certReq;
  CRMF_CERTTEMPLATE *tpl = req->certTemplate;

  X509 *cert = cert_create(srv_ctx, tpl);
  CRMF_CERTTEMPLATE_free(tpl);

  *out = CMP_ip_new(ctx, cert);
  (*out)->extraCerts = X509_stack_dup(srv_ctx->extraCerts);
  sk_X509_push((*out)->body->value.ip->caPubs, HELP_read_der_cert("/home/mv/cmp/certs/rootCA.der"));

  // char filename[1024];
  // EVP_PKEY *p = X509_PUBKEY_get(cert->cert_info->key);
  // dbgmsg("d", p);
  // int keyid = EVP_PKEY_base_id(p);
  // sprintf(filename, "%s/%d.der", srv_ctx->certPath, keyid);
  // dbgmsg("ss", "saving cert to", filename);
  int r = cert_save(srv_ctx, cert);
  dbgmsg("sd", "cert_save:", r);

  // dbgmsg("s", "done");
  return 0;
}

CMPHANDLER_FUNC(handlemsg_rr)
{
  UNUSED(srv);
  UNUSED(srv_ctx);
  UNUSED(msg);

  CMP_CTX *ctx = srv_ctx->cmp_ctx;

  CMP_PKIMESSAGE *resp = CMP_PKIMESSAGE_new();
  CMP_PKIMESSAGE_set_bodytype( resp, V_CMP_PKIBODY_RP);
  CMP_PKIHEADER_set1(resp->header, ctx);

  CMP_REVREP *rp = CMP_REVREP_new();
  rp->status = sk_CMP_PKISTATUSINFO_new_null();
  CMP_PKISTATUSINFO *s = CMP_PKISTATUSINFO_new();
  // s->status = ASN1_INTEGER_new();
  ASN1_INTEGER_set(s->status, 0);
  // rp->status = s;
  sk_CMP_PKISTATUSINFO_push(rp->status, s);

  resp->body->value.rp = rp;

  dbgmsg("s", "rr done");
  *out = resp;

  return 0;
}

CMPHANDLER_FUNC(handlemsg_kur)
{
  UNUSED(srv);
  UNUSED(srv_ctx);
  UNUSED(msg);
  UNUSED(out);

  CMP_CTX *ctx = srv_ctx->cmp_ctx;

  CRMF_CERTREQMSG *reqmsg = sk_CRMF_CERTREQMSG_value( msg->body->value.kur, 0);
  CRMF_CERTREQUEST *req = reqmsg->certReq;
  CRMF_CERTTEMPLATE *tpl = req->certTemplate;

  int n = sk_CRMF_ATTRIBUTETYPEANDVALUE_num(req->controls);
  int oldserial = 0;
  for (int i = 0; i < n; i++) {
    CRMF_ATTRIBUTETYPEANDVALUE *atav = sk_CRMF_ATTRIBUTETYPEANDVALUE_value(req->controls,i);
    if (OBJ_obj2nid(atav->type) == NID_id_regCtrl_oldCertID) {
      CRMF_CERTID *cid = atav->value.oldCertId;
      oldserial = ASN1_INTEGER_get(cid->serialNumber);
    }
  }

  dbgprintf("removing %x", oldserial);
  int rc=cert_remove(srv_ctx, oldserial);
  if (rc != 0) dbgprintf("success");
  else dbgprintf("failure (%d)", rc);

  X509 *cert = cert_create(srv_ctx, tpl);
  CRMF_CERTTEMPLATE_free(tpl);

  *out = CMP_kup_new(ctx, cert);
  (*out)->extraCerts = X509_stack_dup(srv_ctx->extraCerts);

  int r = cert_save(srv_ctx, cert);
  dbgmsg("sd", "cert_save:", r);

  return 0;
}

CMPHANDLER_FUNC(handlemsg_certConf)
{
  UNUSED(srv);
  UNUSED(msg);

  CMP_CTX *ctx = srv_ctx->cmp_ctx;
  CMP_PKIMESSAGE *resp = CMP_PKIMESSAGE_new();
  CMP_PKIHEADER_set1(resp->header, ctx);
  CMP_PKIMESSAGE_set_bodytype(resp, V_CMP_PKIBODY_PKICONF);
  ASN1_TYPE *t = ASN1_TYPE_new();
  ASN1_TYPE_set(t, V_ASN1_NULL, NULL);
  resp->body->value.pkiconf = t;

  *out = resp;
  return 0;
}

CMPHANDLER_FUNC(handlemsg_genm)
{
  UNUSED(msg);

  CMP_CTX *ctx = srv_ctx->cmp_ctx;
  CMP_PKIMESSAGE *resp=NULL;
  CMP_INFOTYPEANDVALUE *itav=NULL;

  resp = CMP_PKIMESSAGE_new();
  CMP_PKIHEADER_set1(resp->header, ctx);
  CMP_PKIMESSAGE_set_bodytype(resp, V_CMP_PKIBODY_GENP);

  itav = CMP_INFOTYPEANDVALUE_new();
  itav->infoType = OBJ_nid2obj(NID_id_it_caKeyUpdateInfo);

  CMP_CAKEYUPDANNCONTENT *ckuann = CMP_CAKEYUPDANNCONTENT_new();
  // X509 *cert = X509_new();
  // X509_set_version(cert, 2);
  // ASN1_INTEGER_set(cert->cert_info->serialNumber, 0);
  // ASN1_TIME_set(cert->cert_info->validity->notBefore, time(0));
  // ASN1_TIME_set(cert->cert_info->validity->notAfter, time(0)+60*60*24*365);
  char certfn[1024];
  sprintf(certfn, "%s/ca_cert_oldwithnew.der", srv_ctx->certPath);
  ckuann->oldWithNew = HELP_read_der_cert(certfn);

  sprintf(certfn, "%s/ca_cert_newwithold.der", srv_ctx->certPath);
  ckuann->newWithOld = HELP_read_der_cert(certfn);

  sprintf(certfn, "%s/ca_cert_newwithnew.der", srv_ctx->certPath);
  ckuann->newWithNew = HELP_read_der_cert(certfn);

  itav->infoValue.ptr = (void*) ckuann;

  CMP_ITAV_stack_item_push0( &resp->body->value.genm, itav);
  dbgmsg("s", "itsa done");

  *out = resp;
  return 0;
}

void init_handler_table(void)
{
  for (int i = 0; i < V_CMP_PKIBODY_LAST; i++)
    msg_handlers[i] = NULL;

  msg_handlers[V_CMP_PKIBODY_IR]       = handlemsg_ir;
  msg_handlers[V_CMP_PKIBODY_RR]       = handlemsg_rr;
  msg_handlers[V_CMP_PKIBODY_KUR]      = handlemsg_kur;
  msg_handlers[V_CMP_PKIBODY_CERTCONF] = handlemsg_certConf;
  msg_handlers[V_CMP_PKIBODY_GENM]     = handlemsg_genm;
}


// {{{ char V_CMP_TABLE[] 

char *V_CMP_TABLE[] = {
  "V_CMP_PKIBODY_IR",
  "V_CMP_PKIBODY_IP",
  "V_CMP_PKIBODY_CR",
  "V_CMP_PKIBODY_CP",
  "V_CMP_PKIBODY_P10CR",
  "V_CMP_PKIBODY_POPDECC",
  "V_CMP_PKIBODY_POPDECR",
  "V_CMP_PKIBODY_KUR",
  "V_CMP_PKIBODY_KUP",
  "V_CMP_PKIBODY_KRR",
  "V_CMP_PKIBODY_KRP",
  "V_CMP_PKIBODY_RR",
  "V_CMP_PKIBODY_RP",
  "V_CMP_PKIBODY_CCR",
  "V_CMP_PKIBODY_CCP",
  "V_CMP_PKIBODY_CKUANN",
  "V_CMP_PKIBODY_CANN",
  "V_CMP_PKIBODY_RANN",
  "V_CMP_PKIBODY_CRLANN",
  "V_CMP_PKIBODY_PKICONF",
  "V_CMP_PKIBODY_NESTED",
  "V_CMP_PKIBODY_GENM",
  "V_CMP_PKIBODY_GENP",
  "V_CMP_PKIBODY_ERROR",
  "V_CMP_PKIBODY_CERTCONF",
  "V_CMP_PKIBODY_POLLREQ",
  "V_CMP_PKIBODY_POLLREP",
};

//      }}}
#define MSG_TYPE_STR(type)  \
  (((unsigned int) (type) < sizeof(V_CMP_TABLE)/sizeof(V_CMP_TABLE[0])) \
   ? V_CMP_TABLE[(unsigned int)(type)] : "unknown")

EVP_PKEY *clkey = NULL;
int handleMessage(server *srv, connection *con, cmpsrv_ctx *ctx, CMP_PKIMESSAGE *msg, CMP_PKIMESSAGE **out)
{
  UNUSED(con);

  CMP_PKIMESSAGE *resp = 0;
  int result = 0;
  // EVP_PKEY *clkey = NULL;

  int bodyType = CMP_PKIMESSAGE_get_bodytype(msg);
  // CMP_CTX_set_protectionAlgor( ctx->cmp_ctx, CMP_ALG_SIG);
  ctx->cmp_ctx->protectionAlgor = X509_ALGOR_dup(msg->header->protectionAlg);

  if (ctx->cmp_ctx->transactionID != NULL)
    ASN1_OCTET_STRING_free(ctx->transactionID);
  ctx->cmp_ctx->transactionID = ASN1_STRING_dup(msg->header->transactionID);

  if (bodyType == V_CMP_PKIBODY_KUR) {
    // CMP_CTX_set_protectionAlgor( ctx->cmp_ctx, CMP_ALG_SIG);

    // get private key for verifying protection
    CRMF_CERTREQMSG *reqmsg = sk_CRMF_CERTREQMSG_value( msg->body->value.kur, 0);
    CRMF_CERTREQUEST *req = reqmsg->certReq;

    int n = sk_CRMF_ATTRIBUTETYPEANDVALUE_num(req->controls);
    int oldserial = 0;
    for (int i = 0; i < n; i++) {
      CRMF_ATTRIBUTETYPEANDVALUE *atav = sk_CRMF_ATTRIBUTETYPEANDVALUE_value(req->controls,i);
      if (OBJ_obj2nid(atav->type) == NID_id_regCtrl_oldCertID) {
        CRMF_CERTID *cid = atav->value.oldCertId;
        oldserial = ASN1_INTEGER_get(cid->serialNumber);
      }
    }

    X509 *c = cert_find_by_serial(ctx, oldserial);
    if (c != NULL)
      clkey = c->cert_info->key->pkey;
  }

  if (!CMP_protection_verify(msg, msg->header->protectionAlg, clkey,
                             ctx->cmp_ctx->secretValue)) {
    dbgmsg("s", "ERROR: protection not valid!");
    /* TODO send back error message */
    log_cmperrors(srv);
    // return 0;
  }
  else dbgmsg("s", "protection validated successfully");

  if (msg_handlers[bodyType] != 0) {
    if (msg_handlers[bodyType](srv, ctx, msg, &resp) == 0) {
      dbgmsg("ss", "successfully handled message: ", MSG_TYPE_STR(bodyType));
      ASN1_UTF8STRING *idstr = ASN1_UTF8STRING_new();
      const char *szidstr = "Using mod_cmpsrv test CMP responder.";
      ASN1_STRING_set(idstr, szidstr, strlen(szidstr));
      CMP_PKIHEADER_push0_freeText(resp->header, idstr);

      resp->header->recipient = GENERAL_NAME_dup(msg->header->sender);

      resp->protection = CMP_protection_new(resp, NULL, ctx->cmp_ctx->pkey, ctx->cmp_ctx->secretValue);
    }
    else
      dbgmsg("ss", "error handling message: ", MSG_TYPE_STR(bodyType));
  }
  else
    dbgmsg("s", "ERROR: unsupported message: ", MSG_TYPE_STR(bodyType));

  *out = resp;

  return result;
}

