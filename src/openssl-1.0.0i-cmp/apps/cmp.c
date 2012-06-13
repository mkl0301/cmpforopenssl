/* apps/cmp.c
 */
/* ====================================================================
 * Originally written by Miikka Viljanen
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
 * Copyright 2012 Nokia Siemens Networks Oy. ALL RIGHTS RESERVED.
 * CMP support in OpenSSL originally developed by 
 * Nokia Siemens Networks for contribution to the OpenSSL project.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"


#include <openssl/cmp.h>
#include <openssl/crmf.h>

#define CONFIG_FILE "openssl.cnf"
#undef PROG
#define PROG	cmp_main

static const char *cmp_usage[]={
    "usage: cmp args",
    "",
    "  -server arg - address of the cmp server",
    " .....",
    ""
};

static CONF *conf=NULL;
static CONF *extconf=NULL;
static BIO *bio_c_out=NULL;

int MAIN(int argc, char **argv)
    {
    char *configfile=NULL;
    long errorline=-1;
    char *tofree=NULL;
    int badops=0;
    int ret=1;
    
    apps_startup();
    ERR_load_crypto_strings();
    bio_c_out=BIO_new_fp(stdout,BIO_NOCLOSE);

    if (configfile == NULL) configfile = getenv("OPENSSL_CONF");
	if (configfile == NULL) configfile = getenv("SSLEAY_CONF");
	if (configfile == NULL)
		{
		const char *s=X509_get_default_cert_area();
		size_t len;

		len = strlen(s)+sizeof(CONFIG_FILE)+1;
		tofree=OPENSSL_malloc(len);
		BUF_strlcpy(tofree,s,len);
		BUF_strlcat(tofree,"/"CONFIG_FILE,len);
		configfile=tofree;
		}

	BIO_printf(bio_err,"Using configuration from %s\n",configfile);
	conf = NCONF_new(NULL);
	if (NCONF_load(conf,configfile,&errorline) <= 0)
		{
		if (errorline <= 0)
			BIO_printf(bio_err,"error loading the config file '%s'\n",
				configfile);
		else
			BIO_printf(bio_err,"error on line %ld of config file '%s'\n"
				,errorline,configfile);
		goto err;
		}
	if(tofree)
		{
		OPENSSL_free(tofree);
		tofree = NULL;
		}
    
    badops=1;
    if (badops)
        {
        int i;
        for (i=0; i < sizeof(cmp_usage)/sizeof(cmp_usage[0]); i++)
            BIO_printf(bio_err, "%s\n", cmp_usage[i]);
        }

    BIO_printf(bio_c_out,"not implemented yet\n");


    ret=0;
    
err:
    if(tofree)
        OPENSSL_free(tofree);

    OPENSSL_EXIT(ret);
    }
