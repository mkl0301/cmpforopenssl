
  /***********************************************************************/
  /* Copyright 2010-2011 Nokia Siemens Networks Oy. ALL RIGHTS RESERVED. */
  /* Written by Miikka Viljanen <mviljane@users.sourceforge.net>         */
  /***********************************************************************/

#include "mod_cmpsrv.h"

void dbgprintf(const char *fmt, ...) {
  va_list arg_ptr;
  va_start(arg_ptr, fmt);
  FILE *f = fopen("/tmp/cmpsrv.log", "a");
  if (f) {
    vfprintf(f, fmt, arg_ptr);
    fprintf(f, "\n");
    fclose(f);
  }
  va_end(arg_ptr);
}

EVP_PKEY *HELP_readPrivKey(const char * filename, const char *password)
{
  FILE *fp;
  EVP_PKEY *pkey;

  if(!filename) return NULL; /* mandatory parameter */

  printf("INFO: Reading Public Key from File %s\n", filename);
  printf("INFO: the passphrase is \"%s\"...\n", password);
  if( !(fp = fopen(filename, "r"))) {
    printf("ERROR: could not open file \"%s\" for reading.\n", filename);
    return NULL;
  }
  /* XXX this is NOT encrypted */
  pkey = PEM_read_PrivateKey(fp, NULL, NULL, (char*) password);
  if( pkey)
    fclose(fp);

  return pkey;
}


X509 *HELP_read_der_cert( const char *file)
{
  X509 *x;
  BIO  *bio;

  printf("INFO: Reading Certificate from File %s\n", file);
  if ((bio=BIO_new(BIO_s_file())) != NULL)
    if (!BIO_read_filename(bio,file)) {
      printf("ERROR: could not open file \"%s\" for reading.\n", file);
      return NULL;
    }

  x=d2i_X509_bio(bio,NULL);

  BIO_free(bio);
  return x;
}

int HELP_write_der_cert( X509 *cert, const char *filename)
{
  BIO  *bio;

  if(!cert) return 0;     /* mandatory parameter */
  if(!filename) return 0; /* mandatory parameter */

  printf("INFO: Saving Certificate to File %s\n", filename);

  if ((bio=BIO_new(BIO_s_file())) == NULL)
    return 0;

  if (!BIO_write_filename(bio,(char *)filename)) {
    printf("ERROR: could not open file \"%s\" for writing.\n", filename);
    return 0;
  }

  if (!i2d_X509_bio(bio, cert))
    return 0;

  BIO_free(bio);
  return 1;
}

