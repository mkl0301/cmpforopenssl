
  /***********************************************************************/
  /* Copyright 2010-2011 Nokia Siemens Networks Oy. ALL RIGHTS RESERVED. */
  /* Written by Miikka Viljanen <mviljane@users.sourceforge.net>         */
  /***********************************************************************/

#ifndef __MOD_CMPSRV_H__
#define __MOD_CMPSRV_H__

#include "base.h"
#include "log.h"
#include "buffer.h"
#include "http_chunk.h"
#include "response.h"

#include "plugin.h"

#include "sqlite3.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/rand.h>

#define DEBUG 1
void log_cmperrors(server *srv);

#ifdef DEBUG
// #define dbgmsg(fmt, ...) log_error_write(srv, __FILE__, __LINE__, "s"fmt, "CMPDBG: ", __VA_ARGS__)
#define dbgmsg(fmt, ...) log_error_write(srv, __FILE__, __LINE__, fmt, __VA_ARGS__)
#else
#define dbgmsg //
#endif

/* plugin config for all request/connections */

typedef struct {
  buffer *b;
} plugin_config;

typedef struct {
  PLUGIN_DATA;

  buffer *userID;
  buffer *secretKey;
  buffer *certPath;
  buffer *caCert;
  buffer *caKey;
  array *extraCerts;

  plugin_config **config_storage;

  plugin_config conf;
} plugin_data;

typedef struct {
  char *certPath;
  EVP_PKEY *caKey;
  CMP_CTX *cmp_ctx;
  plugin_data *p_d;
  ASN1_OCTET_STRING *transactionID;
  STACK_OF(X509) *extraCerts;
} cmpsrv_ctx;

/* cmpsrv_ctx.c */
cmpsrv_ctx *cmpsrv_ctx_new(plugin_data *p);
void cmpsrv_ctx_delete(cmpsrv_ctx *ctx);

/* cmpsrv_misc.c */
X509 *HELP_read_der_cert( const char *file);
EVP_PKEY *HELP_readPrivKey(const char * filename, const char *password);
int HELP_write_der_cert( X509 *cert, const char *filename);
void dbgprintf(const char *fmt, ...);
EVP_PKEY *HELP_generateRSAKey();

/* cmpsrv_handlers.c */
void init_handler_table(void);
int handleMessage(server *srv, connection *con, cmpsrv_ctx *ctx, CMP_PKIMESSAGE *msg, CMP_PKIMESSAGE **out);

/* cmpsrv_msg.c */
CMP_PKIMESSAGE * CMP_ip_new( CMP_CTX *ctx, X509 *cert);
CMP_PKIMESSAGE * CMP_kup_new( CMP_CTX *ctx, X509 *cert);
CMP_PKIMESSAGE * CMP_pollRep_new( CMP_CTX *ctx);

/* cmpsrv_certstore.c */
X509 *cert_create(cmpsrv_ctx *ctx, CRMF_CERTTEMPLATE *tpl);
int cert_save(cmpsrv_ctx *ctx, X509 *cert);
int cert_remove(cmpsrv_ctx *ctx, int serialNo);
X509 *cert_find_by_serial(cmpsrv_ctx *ctx, int serialNo);
X509 *cert_find_by_name(cmpsrv_ctx *ctx, X509_NAME *name);
sqlite3 *open_db(cmpsrv_ctx *ctx);

#endif
