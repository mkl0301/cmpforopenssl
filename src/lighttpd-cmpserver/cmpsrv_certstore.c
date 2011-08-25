
  /***********************************************************************/
  /* Copyright 2010-2011 Nokia Siemens Networks Oy. ALL RIGHTS RESERVED. */
  /* Written by Miikka Viljanen <mviljane@users.sourceforge.net>         */
  /***********************************************************************/

#include "mod_cmpsrv.h"

#include "sqlite3.h"


static IMPLEMENT_ASN1_DUP_FUNCTION(X509_PUBKEY)

X509 *cert_create(cmpsrv_ctx *ctx, CRMF_CERTTEMPLATE *tpl)
{
  UNUSED(ctx);
  UNUSED(tpl);
  X509 *cert = X509_new();

  X509_set_version(cert, 2);
  unsigned int serial = 0;
  RAND_bytes((unsigned char*)&serial, sizeof(unsigned int));
  ASN1_INTEGER_set(cert->cert_info->serialNumber, abs(serial));
  ASN1_TIME_set(cert->cert_info->validity->notBefore, time(0));
  ASN1_TIME_set(cert->cert_info->validity->notAfter, time(0)+60*60*24*365*10);
  X509_set_subject_name(cert, tpl->subject);
  X509_set_issuer_name(cert, X509_get_subject_name(ctx->cmp_ctx->caCert));
  cert->cert_info->key = X509_PUBKEY_dup(tpl->publicKey);
  // X509_set_pubkey(cert, tpl->publicKey->pkey);

  X509_ALGOR_set0(cert->sig_alg, OBJ_nid2obj(NID_sha1WithRSAEncryption), V_ASN1_NULL, NULL);
  const EVP_MD *md = EVP_get_digestbynid(NID_sha1WithRSAEncryption);
  X509_sign(cert, ctx->caKey, md);

  return cert;
}

static int get_name_digest(X509_NAME *name, char **digest, unsigned int *len)
{
  if (!digest || !len)
    return 0;

  const EVP_MD *type = EVP_get_digestbynid(NID_sha1WithRSAEncryption);
  unsigned int mdlen=128;
  unsigned char *md=calloc(1,mdlen);
  X509_NAME_digest(name, type, md, &mdlen);

  char *nameDigest = calloc(1, (mdlen+1)*2);
  for (unsigned int i=0, j=0; j < mdlen; i+=2,j++)
    sprintf(&nameDigest [i], "%02X", md[j]);
  free(md);

  *digest = nameDigest;
  *len = mdlen;
  return 1;
}

sqlite3 *open_db(cmpsrv_ctx *ctx)
{
  sqlite3 *db = NULL;
  char dbfile[1024];
  sprintf(dbfile, "%s/certs.db", ctx->certPath);
  int rc = sqlite3_open(dbfile, &db);
  if (rc != SQLITE_OK) return NULL;
  return db;
}

X509 *cert_find_by_name(cmpsrv_ctx *ctx, X509_NAME *name)
{
  UNUSED(ctx);
  UNUSED(name);
  //TODO implement ?

  // char *nameDigest;
  // unsigned int mdlen;
  // get_name_digest(X509_get_subject_name(cert), &nameDigest, &mdlen);
  return NULL;
}

X509 *cert_find_by_serial(cmpsrv_ctx *ctx, int serialNo)
{
  X509 *cert = NULL;
  sqlite3 *db = open_db(ctx);
  if (!db) return NULL;

  const char *select_sql = "select cert from certs where serial = ?";
  sqlite3_stmt *q;
  int rc;

  rc = sqlite3_prepare(db, select_sql, -1, &q, NULL);
  if (rc != SQLITE_OK) return NULL; //TODO report error

  rc = sqlite3_bind_int(q, 1, serialNo);
  if (rc != SQLITE_OK) return NULL; //TODO report error

  while (1) {
    int s = sqlite3_step(q);
    if (s == SQLITE_ROW) {
      const unsigned char *derCert = sqlite3_column_blob(q, 0);
      const unsigned char *p = derCert;
      int len = sqlite3_column_bytes(q, 0);
      cert = d2i_X509(NULL, &p, len);
      dbgprintf("cert = %08x", cert);
    }
    else if (s == SQLITE_DONE)
      break;
    else  {
      //TODO report error
    }
  }

  sqlite3_close(db);
  return cert;
}

int cert_remove(cmpsrv_ctx *ctx, int serialNo)
{
  const char *sql = "delete from certs where serial = ?";
  sqlite3 *db = open_db(ctx);
  sqlite3_stmt *q;
  int rc;

  rc = sqlite3_prepare(db, sql, -1, &q, NULL);
  if (rc != SQLITE_OK) return rc;

  rc = sqlite3_bind_int(q, 1, serialNo);
  if (rc != SQLITE_OK) return rc;

  rc = sqlite3_step(q);
  if (rc != SQLITE_OK) return rc;

  return SQLITE_OK;
}

int cert_save(cmpsrv_ctx *ctx, X509 *cert)
{
  UNUSED(cert);
  int rc = -1;

  char *nameDigest;
  unsigned int mdlen;
  get_name_digest(X509_get_subject_name(cert), &nameDigest, &mdlen);

  unsigned char *derCert = NULL;
  int derLen = i2d_X509(cert, &derCert);

  sqlite3 *db = open_db(ctx);
  if (!db) goto err;

  sqlite3_stmt *q;
  const char *insert_sql = "insert into certs values (?, ?, ?)";

  rc = sqlite3_prepare(db, insert_sql, -1, &q, NULL);
  if (rc != SQLITE_OK) goto err;

  rc = sqlite3_bind_int(q, 1, ASN1_INTEGER_get(cert->cert_info->serialNumber));
  if (rc != SQLITE_OK) goto err;

  rc = sqlite3_bind_text(q, 2, nameDigest, mdlen*2, NULL);
  if (rc != SQLITE_OK) goto err;

  rc = sqlite3_bind_blob(q, 3, derCert, derLen, NULL);
  if (rc != SQLITE_OK) goto err;

  rc = sqlite3_step(q);
  if (rc != SQLITE_OK) goto err;

  rc = sqlite3_finalize(q);
  if (rc != SQLITE_OK) goto err;

  sqlite3_close(db);

  free(nameDigest);
  return 0;

err:
  if (db) sqlite3_close(db);
  free(nameDigest);
  return rc;
}

