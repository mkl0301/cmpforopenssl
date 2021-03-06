/* cmpclient_help.c
 *
 * Helper functions for cmpclient.c - A simple CMP client utilizing OpenSSL
 *
 * Written by Martin Peylo <martin.peylo@nsn.com>
 *
 * OpenSSL can be obtained from:
 * http://www.openssl.org/
 */

/*
 * The following license applies to this file:
 *
 * Copyright (c) 2007, Nokia Siemens Networks (NSN)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of NSN nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY NSN ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL NSN BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * The following licenses apply to OpenSSL:
 *
 * OpenSSL License
 * ---------------
 *
 * ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
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
 * ====================================================================
 *
 * Original SSLeay License
 * -----------------------
 *
 * Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <cmpclient_help.h>

#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

extern int opt_pem;

/* ############################################################################ *
 * Creates an X509_STORE structure for looking up certs within a directory,
 * using the 'hash'.0 naming format.
 * ############################################################################ */
X509_STORE *HELP_create_cert_store(char *dir) {
    X509_STORE *cert_ctx=NULL;
    X509_LOOKUP *lookup=NULL;

    cert_ctx=X509_STORE_new();
    if (cert_ctx == NULL) goto err;

    // X509_STORE_set_verify_cb(cert_ctx, CMP_cert_callback);

	/* TODO what happens if we have two certificates with the same subject name? (i.e. same hash) */
    lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
    if (lookup == NULL) goto err;

    if (opt_pem)
		X509_LOOKUP_add_dir(lookup, dir, X509_FILETYPE_PEM);
	else
		X509_LOOKUP_add_dir(lookup, dir, X509_FILETYPE_ASN1);

    return cert_ctx;

err:
    return NULL;
}



/* ############################################################################ */
/* convert hex string to string, return length */
/* str has to be freed afterwards
 * if *str already contains a pointer that address will be freed */
/* XXX this is just a hack... */
/* returns 0 on error */
size_t HELP_hex2str( char *hex, unsigned char **str) {
	size_t hexLen, ret;
	unsigned char* strPtr;

	hexLen = strlen(hex);
	ret = hexLen/2;
  /* ensure that we're not leaking */
  if(*str) free(*str);
	if(! (*str = malloc(hexLen/2))) goto err;
	strPtr = *str;

	while(hexLen) {
		if( (*hex >= '0') && (*hex <= '9'))
			*strPtr = ((*hex++)-'0')<<4;
		else if ( (*hex >= 'a') && (*hex <= 'f'))
			*strPtr = (((*hex++)-'a')+10)<<4;
		else if ( (*hex >= 'A') && (*hex <= 'F'))
			*strPtr = (((*hex++)-'A')+10)<<4;

		if( (*hex >= '0') && (*hex <= '9'))
			*strPtr += ((*hex++)-'0');
		else if ( (*hex >= 'a') && (*hex <= 'f'))
			*strPtr += (((*hex++)-'a')+10);
		else if ( (*hex >= 'A') && (*hex <= 'F'))
			*strPtr += (((*hex++)-'A')+10);
		strPtr++;
		hexLen -= 2;
	}

	return ret;

err:
  /* TODO: this can be handled better... */
  return 0;
}

/* ############################################################################ */
/* returns 0 on error */
/* ############################################################################ */
X509 *HELP_read_der_cert( const char *filename) {
	X509 *cert;
	BIO  *bio;

  if(!filename) return 0; /* mandatory parameter */

printf("INFO: Reading DER Certificate from File %s\n", filename);
	if ((bio=BIO_new(BIO_s_file())) != NULL)
		IFSTAT(BIO_new)

	if (!BIO_read_filename(bio,filename)) {
		printf("ERROR: could not open file \"%s\" for reading.\n", filename);
		return NULL;
	}

	cert = d2i_X509_bio(bio,NULL);

	BIO_free(bio);
	return cert;
}

/* ############################################################################ */
/* returns 0 on error */
/* ############################################################################ */
X509 *HELP_read_pem_cert( const char *filename) {
	X509 *cert;
	BIO  *bio;

	if(!filename) return 0; /* mandatory parameter */

	printf("INFO: Reading PEM Certificate from File %s\n", filename);
	if ((bio=BIO_new(BIO_s_file())) != NULL)
		IFSTAT(BIO_new)

	if (!BIO_read_filename(bio,filename)) {
		printf("ERROR: could not open file \"%s\" for reading.\n", filename);
		return NULL;
	}

	cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);

	BIO_free(bio);
	return cert;
}

/* ############################################################################ */
/* First attempts to read certificate in DER format, then in PEM format. */
/* return 0 if both fail */
/* ############################################################################ */
X509 *HELP_read_cert( const char *filename) {
	X509 *cert = HELP_read_der_cert(filename);
	if (!cert) {
		printf("INFO: Unable to read certificate in DER format, trying PEM...\n");
		cert = HELP_read_pem_cert(filename);
	}
	return cert;
}

/* ############################################################################ */
/* returns 0 on error */
/* ############################################################################ */
int HELP_write_der_cert( X509 *cert, const char *filename) {
	BIO  *bio;

  if(!cert) return 0;     /* mandatory parameter */
  if(!filename) return 0; /* mandatory parameter */

printf("INFO: Saving Certificate to File %s\n", filename);

	if ((bio=BIO_new(BIO_s_file())) != NULL)
		IFSTAT(BIO_new)

	if (!BIO_write_filename(bio,(char *)filename)) {
		printf("ERROR: could not open file \"%s\" for writing.\n", filename);
		return 0;
	}

	if (i2d_X509_bio(bio, cert))
		IFSTAT(write X509)

	BIO_free(bio);
	return 1;
}

int HELP_write_cert( X509 *cert, const char *filename) {
	BIO  *bio;

	if(!cert) return 0;     /* mandatory parameter */
	if(!filename) return 0; /* mandatory parameter */

	printf("INFO: Saving %s format Certificate to File %s\n", 
		   opt_pem ? "PEM" : "DER", filename);

	if ((bio=BIO_new(BIO_s_file())) != NULL)
		IFSTAT(BIO_new)

	if (!BIO_write_filename(bio,(char *)filename)) {
		printf("ERROR: could not open file \"%s\" for writing.\n", filename);
		return 0;
	}

	if (opt_pem) {
		if (PEM_write_bio_X509(bio, cert))
			IFSTAT(write X509)
	}
	else {
		if (i2d_X509_bio(bio, cert))
			IFSTAT(write X509)
	}

	BIO_free(bio);
	return 1;
}

static int dsa_cb(int p, int n, BN_GENCB *arg) {
	return 1;
}

DSA *generateDSA(const int length) {
	BN_GENCB cb;
	int counter;
	unsigned long h;
	DSA *key = NULL;
	// BIO *bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

	BN_GENCB_set(&cb, dsa_cb, NULL);
	if( !(key = DSA_new()))
		return NULL;
	DSA_generate_parameters_ex(key, length, NULL, 0, &counter, &h, &cb);
	DSA_generate_key(key);

	return key;
}

/* ############################################################################ */
/* returns NULL on error */
/* ############################################################################ */
EVP_PKEY *HELP_generateDSAKey() {
	DSA *DSAkey=NULL;
	EVP_PKEY *pkey=NULL;

	/* generate RSA key */
	if(! (DSAkey = generateDSA(1024))) return NULL;
	if( (pkey = EVP_PKEY_new()) )
		EVP_PKEY_set1_DSA(pkey, DSAkey);

	DSA_free(DSAkey);
	ERR_load_crypto_strings();
	ERR_print_errors_fp(stderr);

	return pkey;
}

/* ############################################################################ */
/* returns NULL on error */
/* ############################################################################ */
RSA *generateRSA(const int length) {
	RSA *RSAkey=NULL;
	BIGNUM *bn;

	if( !(bn = BN_new()))
		return NULL;
	BN_set_word(bn, RSA_F4);

	if( !(RSAkey = RSA_new()))
		return NULL;

	printf("INFO: Generating (%d bit) RSA key\n",length);
	if(!RSA_generate_key_ex(RSAkey,length,bn,NULL))
	{
		printf("ERROR: generating key.\n");
		RSA_free(RSAkey);
		return NULL;
	}

	return RSAkey;
}

/* ############################################################################ */
/* returns NULL on error */
/* ############################################################################ */
EVP_PKEY *HELP_generateRSAKey() {
	RSA *RSAkey=NULL;
	EVP_PKEY *pkey=NULL;

	/* generate RSA key */
  if(! (RSAkey = generateRSA(1024))) return NULL;
  if( (pkey = EVP_PKEY_new()) )
      EVP_PKEY_set1_RSA(pkey, RSAkey);

	RSA_free(RSAkey);

	return pkey;
}

/* ############################################################################ */
/* returns 0 on error */
/* ############################################################################ */
int HELP_savePrivKey(EVP_PKEY *pkey, const char * filename, const char *password) {
	FILE *fp;

  if(!pkey) return 0;     /* mandatory parameter */
  if(!filename) return 0; /* mandatory parameter */

printf("INFO: Writing Private Key to File %s\n", filename);
printf("INFO: the passphrase is \"%s\"\n", password);
	if( !(fp = fopen(filename, "w"))) {
		printf("ERROR: could not open file \"%s\" for writing.\n", filename);
		return 0;
	}
	PEM_write_PrivateKey(fp, pkey, NULL, (unsigned char*)password, 0, 0, 0);
printf("INFO: private Key written\n");
	fclose(fp);

	return 1;
}

/* ############################################################################ */
/* returns 0 on error */
/* ############################################################################ */
int HELP_saveRSAPublicKey(EVP_PKEY *pkey, const char * filename) {
	FILE *fp;

  if(!pkey) return 0;     /* mandatory parameter */
  if(!filename) return 0; /* mandatory parameter */

printf("INFO: Writing Public Key to File %s\n", filename);
	if( !(fp = fopen(filename, "w"))) {
		printf("ERROR: could not open file \"%s\" for writing.\n", filename);
		return 0;
	}
	PEM_write_RSAPublicKey(fp, pkey->pkey.rsa);
printf("INFO: public Key written\n");
	fclose(fp);

	return 1;
}

/* ############################################################################ */
/* returns NULL on error */
/* ############################################################################ */
EVP_PKEY *HELP_readPrivKey(const char * filename, const char *password) {
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
	pkey = PEM_read_PrivateKey(fp, NULL, NULL, (char*)password);
	if( pkey)
		IFSTAT( Reading PKEY)
	fclose(fp);

	return pkey;
}

#if 0
X509_NAME* HELP_create_X509_NAME(char *string)
{
	X509_NAME* subject = X509_NAME_new();
	if (subject == NULL) goto err;
	
	char* result = strtok(string, ",");

	while (result != NULL) {
		char* content = strchr(result, '=');

		if (content != NULL) {
			*content++ = 0;
			if(!X509_NAME_add_entry_by_txt(subject, result, MBSTRING_ASC, (unsigned char*)content, -1, -1, 0))
				printf("ERROR unable to add entry by txt to X509 subject name\n");
		}
		result = strtok(NULL, ",");
	}

	return subject;
err:
	return NULL;
}
#endif

/*
 * subject is expected to be in the format type0=value0,type1=value1,type2=...
 * where characters may be escaped by \
 * Note: taken from openssl/apps/apps.c and adapted slightly to use commas instead
 *       of forward slashes as separator
 */
X509_NAME* HELP_create_X509_NAME(char *subject)
{
	size_t buflen = strlen(subject)+1; /* to copy the types and values into. due to escaping, the copy can only become shorter */
	char *buf = OPENSSL_malloc(buflen);
	size_t max_ne = buflen / 2 + 1; /* maximum number of name elements */
	char **ne_types = OPENSSL_malloc(max_ne * sizeof (char *));
	char **ne_values = OPENSSL_malloc(max_ne * sizeof (char *));
	int *mval = OPENSSL_malloc (max_ne * sizeof (int));

	char *sp = subject, *bp = buf;
	int i, ne_num = 0;

	X509_NAME *n = NULL;
	int nid;

	if (!buf || !ne_types || !ne_values)
	{
		fprintf(stderr, "malloc error\n");
		goto error;
	}	

#if 0
	if (*subject != '/')
	{
		fprintf(stderr, "Subject does not start with '/'.\n");
		goto error;
	}
	sp++; /* skip leading / */
#endif

	/* no multivalued RDN by default */
	mval[ne_num] = 0;

	while (*sp)
	{
		/* collect type */
		ne_types[ne_num] = bp;
		while (*sp)
		{
			if (*sp == '\\') /* is there anything to escape in the type...? */
			{
				if (*++sp)
					*bp++ = *sp++;
				else	
				{
					fprintf(stderr, "escape character at end of string\n");
					goto error;
				}
			}	
			else if (*sp == '=')
			{
				sp++;
				*bp++ = '\0';
				break;
			}
			else
				*bp++ = *sp++;
		}
		if (!*sp)
		{
			fprintf(stderr, "end of string encountered while processing type of subject name element #%d\n", ne_num);
			goto error;
		}
		ne_values[ne_num] = bp;
		while (*sp)
		{
			if (*sp == '\\')
			{
				if (*++sp)
					*bp++ = *sp++;
				else
				{
					fprintf(stderr, "escape character at end of string\n");
					goto error;
				}
			}
			else if (*sp == ',')
			{
				sp++;
				/* no multivalued RDN by default */
				mval[ne_num+1] = 0;
				/* skip whitspace after separator */
				while (*sp == ' ' || *sp == '\t') sp++;
				break;
			}
			/* XXX multivalued RDN's not supported for now */
#if 0
			else if (*sp == '+' /*&& multirdn*/)
			{
				/* a not escaped + signals a mutlivalued RDN */
				sp++;
				mval[ne_num+1] = -1;
				break;
			}
#endif
			else
				*bp++ = *sp++;
		}
		*bp++ = '\0';
		ne_num++;
	}	

	if (!(n = X509_NAME_new()))
		goto error;

	for (i = 0; i < ne_num; i++)
	{
		if ((nid=OBJ_txt2nid(ne_types[i])) == NID_undef)
		{
			fprintf(stderr, "Subject Attribute %s has no known NID, skipped\n", ne_types[i]);
			continue;
		}

		if (!*ne_values[i])
		{
			fprintf(stderr, "No value provided for Subject Attribute %s, skipped\n", ne_types[i]);
			continue;
		}

		if (!X509_NAME_add_entry_by_NID(n, nid, MBSTRING_ASC, (unsigned char*)ne_values[i], -1,-1,mval[i]))
			goto error;
	}

	OPENSSL_free(ne_values);
	OPENSSL_free(ne_types);
	OPENSSL_free(buf);
	return n;

error:
	X509_NAME_free(n);
	if (ne_values)
		OPENSSL_free(ne_values);
	if (ne_types)
		OPENSSL_free(ne_types);
	if (buf)
		OPENSSL_free(buf);
	return NULL;
}
