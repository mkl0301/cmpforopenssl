
  /***********************************************************************/
  /* Copyright 2010-2011 Nokia Siemens Networks Oy. ALL RIGHTS RESERVED. */
  /* Written by Miikka Viljanen <mviljane@users.sourceforge.net>         */
  /***********************************************************************/

#include "mod_cmpsrv.h"

static size_t str2hex(char *str, unsigned char *out, size_t outlen)
{
  size_t len = strlen(str), j = 0;
  if (len > outlen*2) return 0;
  for (size_t i = 0; i < len; i += 2, j++) {
    char *junk, byte[3] = {str[i], str[i+1], 0};
    out[j] = strtoul(byte, &junk, 16);
  }
  return j;
}


void cmpsrv_ctx_delete(cmpsrv_ctx *ctx)
{
  CMP_CTX_delete(ctx->cmp_ctx);
  EVP_PKEY_free(ctx->caKey);
  free(ctx->certPath);
  free(ctx);
}

cmpsrv_ctx *cmpsrv_ctx_new(plugin_data *p)
{
  cmpsrv_ctx *ctx = calloc(1, sizeof(cmpsrv_ctx));
  ctx->certPath = strdup(p->certPath->ptr);

  CMP_CTX *cmp_ctx = CMP_CTX_create();
  unsigned char referenceVal[32], secretVal[32];
  size_t refLen, secLen;

  refLen = str2hex(p->userID->ptr, referenceVal, sizeof(referenceVal));
  secLen = str2hex(p->secretKey->ptr, secretVal, sizeof(secretVal));

  // CMP_CTX_set1_serverName( cmp_ctx, opt_serverName);
  // CMP_CTX_set1_serverPath( cmp_ctx, opt_serverPath);
  // CMP_CTX_set1_serverPort( cmp_ctx, opt_serverPort);
  CMP_CTX_set1_referenceValue( cmp_ctx, referenceVal, refLen);
  CMP_CTX_set1_secretValue( cmp_ctx, secretVal, secLen);
  // CMP_CTX_set0_pkey( cmp_ctx, initialPkey);
  // CMP_CTX_set1_caCert( cmp_ctx, caCert);
  // CMP_CTX_set_compatibility( cmp_ctx, opt_compatibility);

  X509 *caCert = HELP_read_der_cert(p->caCert->ptr);
  if (!caCert) goto err;
  CMP_CTX_set1_caCert( cmp_ctx, caCert);
  X509_free(caCert);

  EVP_PKEY *caKey = HELP_readPrivKey(p->caKey->ptr, "");
  if (!caKey) goto err;
  ctx->caKey = caKey;
  cmp_ctx->pkey = caKey;

  CMP_CTX_set_protectionAlgor( cmp_ctx, CMP_ALG_PBMAC);

  ctx->cmp_ctx = cmp_ctx;
  ctx->p_d = p;

  return ctx;

err:
  cmpsrv_ctx_delete( ctx);
  return NULL;
}

