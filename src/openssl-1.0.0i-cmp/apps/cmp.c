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

typedef enum { CMP_IR,
               CMP_KUR,
               CMP_CR,
               CMP_RR,
               CMP_CKUANN,
    } cmp_cmd_t;

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
static char *server_address=NULL;
static int   server_port=0;
static char *opt_path="/";

static char *opt_cmd=NULL;
static int cmp_cmd=-1;
static char *opt_user=NULL;
static char *opt_pass=NULL;

static char *opt_cert=NULL;
static char *opt_key=NULL;
static char *opt_keypass=NULL;

static char *opt_certout=NULL;
static char *opt_newkey=NULL;
static char *opt_newkeypass=NULL;

static char *opt_svcert=NULL;
static char *opt_trusted=NULL;
static char *opt_untrusted=NULL;
static char *opt_engine=NULL;
static int   opt_validate_path=0;

static char *opt_extcerts=NULL;
static char *opt_subject=NULL;
static char *opt_recipient=NULL;

static char *opt_save_capubs=NULL;
static char *opt_save_extracerts=NULL;

static opt_t cmp_opts[]={
    { "server", "The 'ADDRESS:PORT' for the CMP server", OPT_TXT, {&opt_server} },
    { "path", "Path location inside the server", OPT_TXT, {&opt_path} },
    { "cmd", "CMP command to execute: ir/kur/cr/rr/ckuann/...", OPT_TXT, {&opt_cmd} },
    { "user", "Username for doing the IR with a pre-shared key", OPT_TXT, {&opt_user} },
    { "pass", "Password for doing the IR with a pre-shared key", OPT_TXT, {&opt_pass} },

    { "cert", "Client's current certificate", OPT_TXT, {&opt_cert} },
    { "key", "Key for the client's current certificate", OPT_TXT, {&opt_key} },
    { "keypass", "Password for the key", OPT_TXT, {&opt_keypass} },

    { "certout", "Where to save the new certificate", OPT_TXT, {&opt_certout} },
    { "newkey", "Key file to use for the new certificate", OPT_TXT, {&opt_newkey} },
    { "newkeypass", "Password for the new keyfile", OPT_TXT, {&opt_newkeypass} },

    { "svcert", "Certificate of the CMP server", OPT_TXT, {&opt_svcert} },
    /* { "CApath", "A directory of trusted certificates", OPT_TXT, {&} }, */
    { "trusted", "A file of trusted certificates", OPT_TXT, {&opt_trusted} },
    { "untrusted", "A file of untrusted certificates", OPT_TXT, {&opt_untrusted} },

    /* { "format", "Use PEM or DER format", OPT_TXT, {&} }, */
    { "engine", "OpenSSL engine to use", OPT_TXT, {&opt_engine} },

    /* XXX should this be on by default? */
    { "validate_path", "Validate the trust path of the CA certificate", OPT_TXT, {.num=&opt_validate_path} },
    { "extcerts", "List of certificate files to include in outgoing messages", OPT_TXT, {&opt_extcerts} },
    { "subject", "X509 subject name to be used in the requested certificate template", OPT_TXT, {&opt_subject} },
    { "recipient", "X509 name of the recipient", OPT_TXT, {&opt_recipient} },
    
    { "save_extracerts", "Directory where to save extra certificates received", OPT_TXT, {&opt_save_extracerts} },
    { "save_capubs", "Directory where to save received CA certificates (from IR)", OPT_TXT, {&opt_save_capubs} },
};

void show_help(void)
    {
    const int ALIGN_COL=15;
    opt_t *o=cmp_opts;
    int i=0,j=0;
    
    BIO_puts(bio_err, "\nusage: cmp args\n");
    for (i=0; i < sizeof(cmp_opts)/sizeof(cmp_opts[0]); i++,o++) {
        
        BIO_printf(bio_err, " -%s", o->name);
        for (j=ALIGN_COL-strlen(o->name); j > 0; j--)
            BIO_puts(bio_err, " ");
        BIO_printf(bio_err, " -%s\n", o->help);
        }
    BIO_puts(bio_err, "\n");
    }

int check_options(void)
    {
    if (opt_server) {
        char *p = strchr(opt_server, ':');
        size_t addrlen=0;
        if (p == NULL) {
            BIO_puts(bio_err, "error: missing server port\n");
            goto err;
            }
        addrlen = (size_t)p - (size_t)opt_server;
        server_address = OPENSSL_malloc(addrlen+1);
        strncpy(server_address, opt_server, addrlen);
        server_address[addrlen]=0;
        server_port = atoi(++p);
    }
    else {
        BIO_puts(bio_err, "error: missing server address\n");
        goto err;
        }

    if (opt_cmd) {
        if (!strcmp(opt_cmd, "ir")) cmp_cmd = CMP_IR;
        else if (!strcmp(opt_cmd, "kur")) cmp_cmd = CMP_KUR;
        else if (!strcmp(opt_cmd, "cr")) cmp_cmd = CMP_CR;
        else if (!strcmp(opt_cmd, "rr")) cmp_cmd = CMP_RR;
        else if (!strcmp(opt_cmd, "rr")) cmp_cmd = CMP_CKUANN;
        else {
            BIO_printf(bio_err, "error: unknown cmp command '%s'\n", opt_cmd);
            goto err;
            }
    }
    else {
        BIO_puts(bio_err, "error: no cmp command to execute\n");
        goto err;
    }

    
    
    return 1;
    err:
    return 0;
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

    if (argc <= 1) {
        badops=1;
        goto bad_ops;
    }
    
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
        int found,i;

        if (*arg++ != '-' || *arg == 0) {
            badops=1;
            break;
        }

        found=0;
        for (i=0; i < sizeof(cmp_opts)/sizeof(cmp_opts[0]); i++,opt++) {
            if (opt->name && !strcmp(arg, opt->name))
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
            }
        
        if (!found) {
            BIO_printf(bio_err, "unknown argument: '%s'\n", *argv);
            badops=1;
            goto bad_ops;
            }
        }

    if (!badops)
        badops = check_options();

bad_ops:
    if (badops)
        show_help();


    ret=0;
    
err:
    if(tofree)
        OPENSSL_free(tofree);

    OPENSSL_EXIT(ret);
    }
