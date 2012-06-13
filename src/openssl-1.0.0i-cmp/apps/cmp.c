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

typedef enum { OPT_BOOL, OPT_NUM, OPT_TXT } opttype_t;
typedef struct 
    {
    const char *name;
    const char *help;
    opttype_t type;
    union {
        char **txt;
        int *num;
        } v;
    } opt_t;

static char *opt_server=NULL;
static char *opt_cmd=NULL;
static char *opt_user=NULL;
static char *opt_pass=NULL;

static opt_t cmp_opts[]={
    { "server", "The 'ADDRESS:PORT/PATH' for the CMP server.", OPT_TXT, {&opt_server} },
    { "cmd", "CMP command to execute: ir/kur/cr/rr/ckuann/...", OPT_TXT, {&opt_cmd} },
    { "user", "Username for doing the IR with a pre-shared key.", OPT_TXT, {&opt_user} },
    { "pass", "Password for doing the IR with a pre-shared key.", OPT_TXT, {&opt_pass} },

#if 0
    { "cert", "Client's current certificate.", OPT_TXT, {&} },
    { "key", "Key for the client's current certificate.", OPT_TXT, {&} },
    { "keypass", "Password for the key.", OPT_TXT, {&} },

    { "cert", "Client's current certificate.", OPT_TXT, {&} },
    { "newkey", "", OPT_TXT, {&} },
    { "newkeypass", "", OPT_TXT, {&} },

    { "certout", "Where to save the new certificate", OPT_TXT, {&} },
    

    { "CApath", "A directory of trusted certificates.", OPT_TXT, {&} },
    { "CAfile", "A file of trusted certificates.", OPT_TXT, {&} },

    { "validate_chain", ".", OPT_TXT, {&} },
#endif
};

void show_help(void)
    {
    const int ALIGN_COL=8;
    opt_t *o=cmp_opts;
    int i=0,j=0;
    
    BIO_puts(bio_err, "\nusage: cmp args\n");
    for (i=0; i < sizeof(cmp_opts)/sizeof(cmp_opts[0]); i++,o++) {
        BIO_printf(bio_err, "  -%s", o->name);
        for (j=ALIGN_COL-strlen(o->name); j > 0; j--)
            BIO_puts(bio_err, " ");
        BIO_printf(bio_err, "- %s\n", o->help);
        }
    }


static CONF *conf=NULL;
/* static CONF *extconf=NULL; */
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

    while (--argc > 0 && ++argv)
        {
        opt_t *opt=cmp_opts;
        char *arg=*argv;
        int found=0,i;

        if (*arg++ != '-' || *arg == 0) {
            badops=1;
            break;
        }
        
        for (i=0; i < sizeof(cmp_opts)/sizeof(cmp_opts[0]); i++,opt++) {
            if (!strcmp(arg, opt->name))
                {
                if (argc <= 1 && opt->type != OPT_BOOL) {
                    BIO_printf(bio_err, "missing argument for '-%s'\n", opt->name);
                    badops=1;
                    goto bad_ops;
                    }
                switch(opt->type)
                    {
                    case OPT_BOOL:
                        *opt->v.num = 1;
                        break;
                    case OPT_NUM:
                        *opt->v.num = atoi(*++argv);
                        argc--;
                        break;
                    case OPT_TXT:
                        *opt->v.txt = *++argv;
                        argc--;
                        break;
                    default:
                        badops=1;
                        break;
                    }
                found=1;
                }
            if (!found) {
                BIO_printf(bio_err, "unknown argument: '%s'\n", *argv);
                badops=1;
                goto bad_ops;
                }
            }
        }

bad_ops:
    if (badops)
        show_help();


    ret=0;
    
err:
    if(tofree)
        OPENSSL_free(tofree);

    OPENSSL_EXIT(ret);
    }
