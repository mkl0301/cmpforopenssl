
  /***********************************************************************/
  /* Copyright 2010-2011 Nokia Siemens Networks Oy. ALL RIGHTS RESERVED. */
  /* Written by Miikka Viljanen <mviljane@users.sourceforge.net>         */
  /***********************************************************************/

#include "mod_cmpsrv.h"

#ifdef DEBUG
static int ossl_error_cb(const char *str, size_t len, void *u)
{
  UNUSED(len);
  server *srv = (server*) u;
  dbgmsg("s", str);
  return 0;
}
void log_cmperrors(server *srv) { ERR_print_errors_cb(ossl_error_cb, (void*) srv); }
#else
void log_cmperrors(server *srv) { return; }
#endif

#define CMP_CONTENT_TYPE "application/pkixcmp"

/* init the plugin data */
INIT_FUNC(mod_cmpsrv_init) {
  plugin_data *p;

  p = calloc(1, sizeof(*p));

  p->userID = buffer_init();
  p->secretKey = buffer_init();
  p->certPath = buffer_init();
  p->caCert = buffer_init();
  p->caKey = buffer_init();
  p->extraCertPath = buffer_init();
  p->rootCertPath = buffer_init();

  return p;
}

/* detroy the plugin data */
FREE_FUNC(mod_cmpsrv_free) {
  plugin_data *p = p_d;

  UNUSED(srv);

  if (!p) return HANDLER_GO_ON;

  if (p->config_storage) {
    size_t i;

    for (i = 0; i < srv->config_context->used; i++) {
      plugin_config *s = p->config_storage[i];

      if (!s) continue;

      free(s);
    }

    free(p->config_storage);
  }

  buffer_free(p->userID);
  buffer_free(p->secretKey);
  buffer_free(p->certPath);
  buffer_free(p->caCert);
  buffer_free(p->caKey);
  array_free(p->extraCertPath);
  array_free(p->rootCertPath);

  free(p);

  return HANDLER_GO_ON;
}

/* handle plugin config and check values */

SETDEFAULTS_FUNC(mod_cmpsrv_set_defaults) {
  plugin_data *p = p_d;
  size_t i = 0;

  config_values_t cv[] = {
    { "cmpsrv.userID",       NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_SERVER }, /* 0 */
    { "cmpsrv.secretKey",    NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_SERVER }, /* 1 */
    { "cmpsrv.certPath",     NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_SERVER }, /* 2 */
    { "cmpsrv.caCert",       NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_SERVER }, /* 3 */
    { "cmpsrv.caKey",        NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_SERVER }, /* 4 */
    { "cmpsrv.extraCertPath", NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_SERVER }, /* 5 */
    { "cmpsrv.rootCertPath",  NULL, T_CONFIG_STRING, T_CONFIG_SCOPE_SERVER }, /* 6 */
    { NULL,                  NULL, T_CONFIG_UNSET, T_CONFIG_SCOPE_UNSET }
  };

  if (!p) return HANDLER_ERROR;

  p->config_storage = calloc(1, srv->config_context->used * sizeof(specific_config *));

  for (i = 0; i < srv->config_context->used; i++) {
    plugin_config *s;

    s = calloc(1, sizeof(plugin_config));
    // s->match    = array_init();

    cv[0].destination = p->userID;
    cv[1].destination = p->secretKey;
    cv[2].destination = p->certPath;
    cv[3].destination = p->caCert;
    cv[4].destination = p->caKey;
    cv[5].destination = p->extraCertPath;
    cv[6].destination = p->rootCertPath;

    p->config_storage[i] = s;

    if (0 != config_insert_values_global(srv, ((data_config *)srv->config_context->data[i])->value, cv)) {
      return HANDLER_ERROR;
    }
  }

  return HANDLER_GO_ON;
}

#if 0
static int mod_cmpsrv_patch_connection(server *srv, connection *con, plugin_data *p) {
  UNUSED(p);
  size_t i;

  for (i = 1; i < srv->config_context->used; i++) {
    data_config *dc = (data_config *)srv->config_context->data[i];
    if (!config_check_cond(srv, con, dc)) continue;
  }

  return 0;
}
#endif

static buffer *get_content(chunkqueue *cq) 
{
  if (cq->first && cq->first->mem && cq->first->mem->used > 0)
    return cq->first->mem;
  return 0;
}

static CMP_PKIMESSAGE *decodeMessage(buffer *msg)
{
  const unsigned char *derMsg = (unsigned char *) msg->ptr;
  size_t derLen = msg->used-1;
  return d2i_CMP_PKIMESSAGE(NULL, &derMsg, derLen);
}

static void sendResponse(server *srv, connection *con, CMP_PKIMESSAGE *msg)
{
  unsigned char *derBuf = 0;
  size_t derLen = 0;

  dbgmsg("s", "attempting to encode message");
  derLen = i2d_CMP_PKIMESSAGE( msg, &derBuf);
  dbgmsg("sd", "message encoded, sending... len=", derLen);

  response_header_overwrite(srv, con, CONST_STR_LEN("Content-Type"), CONST_STR_LEN(CMP_CONTENT_TYPE));
  http_chunk_append_mem(srv, con, (const char*)derBuf, derLen+1);

  dbgmsg("s", "response sent");
  free(derBuf);
}

URIHANDLER_FUNC(mod_cmpsrv_uri_handler) {
  plugin_data *p = p_d;
  // int s_len;
  buffer *msg;

  UNUSED(srv);

  if (con->mode != DIRECT) return HANDLER_GO_ON;

  if (con->uri.path->used == 0) return HANDLER_GO_ON;

  // mod_cmpsrv_patch_connection(srv, con, p);

  // s_len = con->uri.path->used - 1;

  dbgmsg("s", "mod_cmpsrv_uri_handler called");

  if (0 == con->request.http_content_type ||
      0 != strncmp(con->request.http_content_type, CMP_CONTENT_TYPE, sizeof(CMP_CONTENT_TYPE)-1)) {
    dbgmsg("s", "invalid content type");
    return HANDLER_GO_ON;
  }


  /* TODO: handle multiple chunks correctly */
  if (chunkqueue_length(con->request_content_queue) != (off_t)con->request.content_length) {
    dbgmsg("s", "invalid chunkqueue_length");
    return HANDLER_GO_ON;
  }

  msg = get_content(con->request_content_queue);
  if (!msg) {
    dbgmsg("s", "error getting message content");
    return HANDLER_GO_ON;
  }

  if (msg->used != (off_t)con->request.content_length+1) {
    dbgmsg("sd", "too many chunks", msg->used);
    return HANDLER_GO_ON;
  }

  dbgmsg("s", "decoding DER message ...");

  CMP_PKIMESSAGE *pkiMsg = decodeMessage(msg);
  if (!pkiMsg) {
    dbgmsg("s", "ERROR decoding message");
    log_cmperrors(srv);
    return HANDLER_GO_ON;
  }

  /* handle the received PKI message */
  CMP_PKIMESSAGE *resp = NULL;
  cmpsrv_ctx *ctx = cmpsrv_ctx_new(p);
  if (!ctx) {
    dbgmsg("s", "ERROR: failed to create CMP context");
    log_cmperrors(srv);
    return HANDLER_FINISHED;
  }

  handleMessage(srv, con, ctx, pkiMsg, &resp);

  if (resp != NULL) {
    dbgmsg("s", "sending response");
    sendResponse(srv, con, resp);
    CMP_PKIMESSAGE_free(resp); //XXX crashes if freeing a genp
    // result = 1;
  }

  log_cmperrors(srv);

  // con->http_status = 200;
  // con->mode = DIRECT;
  con->file_finished = 1;

  return HANDLER_FINISHED;
}

/* this function is called at dlopen() time and inits the callbacks */

int mod_cmpsrv_plugin_init(plugin *p) {
  p->version          = LIGHTTPD_VERSION_ID;
  p->name             = buffer_init_string("cmpsrv");
  p->init             = mod_cmpsrv_init;
  p->handle_uri_clean = mod_cmpsrv_uri_handler;
  p->set_defaults     = mod_cmpsrv_set_defaults;
  p->cleanup          = mod_cmpsrv_free;
  p->data             = NULL;

  init_handler_table();

  return 0;
}
