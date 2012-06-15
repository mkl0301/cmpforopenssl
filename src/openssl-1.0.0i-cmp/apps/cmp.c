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

static char *opt_cmd_s=NULL;
static int   opt_cmd=-1;
static char *opt_user=NULL;
static char *opt_pass=NULL;

static char *opt_cert=NULL;
static char *opt_key=NULL;
static char *opt_keypass=NULL;

static char *opt_certout=NULL;
static char *opt_newkey=NULL;
static char *opt_newkeypass=NULL;

static char *opt_cacert=NULL;
static char *opt_trusted=NULL;
static char *opt_untrusted=NULL;
static char *opt_keyfmt_s=NULL;
static char *opt_certfmt_s=NULL;
static int   opt_keyfmt=FORMAT_PEM;
static int   opt_certfmt=FORMAT_PEM;
static char *opt_engine=NULL;
static int   opt_validate_path=0;

static char *opt_extcerts=NULL;
static char *opt_subject=NULL;
static char *opt_recipient=NULL;

static char *opt_cacertsout=NULL;
static char *opt_extracertsout=NULL;

static opt_t cmp_opts[]={
    { "server", "The 'ADDRESS:PORT' for the CMP server", OPT_TXT, {&opt_server} },
    { "path", "Path location inside the server", OPT_TXT, {&opt_path} },
    { "cmd", "CMP command to execute: ir/kur/cr/rr/ckuann/...", OPT_TXT, {&opt_cmd_s} },
    { "user", "Username for doing the IR with a pre-shared key", OPT_TXT, {&opt_user} },
    { "pass", "Password for doing the IR with a pre-shared key", OPT_TXT, {&opt_pass} },

    { "cert", "Client's current certificate", OPT_TXT, {&opt_cert} },
    { "key", "Key for the client's current certificate", OPT_TXT, {&opt_key} },
    { "keypass", "Password for the key", OPT_TXT, {&opt_keypass} },

    { "certout", "Where to save the new certificate", OPT_TXT, {&opt_certout} },
    { "newkey", "Key file to use for the new certificate", OPT_TXT, {&opt_newkey} },
    { "newkeypass", "Password for the new keyfile", OPT_TXT, {&opt_newkeypass} },

    { "cacert", "Certificate of the CMP server", OPT_TXT, {&opt_cacert} },
    /* { "CApath", "A directory of trusted certificates", OPT_TXT, {&} }, */
    { "trusted", "A file of trusted certificates", OPT_TXT, {&opt_trusted} },
    { "untrusted", "A file of untrusted certificates", OPT_TXT, {&opt_untrusted} },

    { "keyfmt", "Format to use for key files. Default PEM.", OPT_TXT, {&opt_keyfmt_s} },
    { "certfmt", "Format to use for certificate files. Default PEM.", OPT_TXT, {&opt_certfmt_s} },
    { "engine", "OpenSSL engine to use", OPT_TXT, {&opt_engine} },

    /* XXX should this be on by default? */
    { "validate_path", "Validate the trust path of the CA certificate", OPT_TXT, {.num=&opt_validate_path} },
    { "extcerts", "List of certificate files to include in outgoing messages", OPT_TXT, {&opt_extcerts} },
    { "subject", "X509 subject name to be used in the requested certificate template", OPT_TXT, {&opt_subject} },
    { "recipient", "X509 name of the recipient", OPT_TXT, {&opt_recipient} },
    
    { "extracertsout", "Directory where to save extra certificates received", OPT_TXT, {&opt_extracertsout} },
    { "cacertsout", "Directory where to save received CA certificates (from IR)", OPT_TXT, {&opt_cacertsout} },
};

static void show_help(void)
    {
    const int ALIGN_COL=15;
    opt_t *o=cmp_opts;
    int i=0,j=0;
    
    BIO_puts(bio_err, "\nusage: cmp args\n");
    for (i=0; i < sizeof(cmp_opts)/sizeof(cmp_opts[0]); i++,o++)
        {
        BIO_printf(bio_err, " -%s", o->name);
        for (j=ALIGN_COL-strlen(o->name); j > 0; j--)
            BIO_puts(bio_err, " ");
        BIO_printf(bio_err, " -%s\n", o->help);
        }
    BIO_puts(bio_err, "\n");
    }

static int check_options(void)
    {
    if (opt_server)
        {
        char *p=strchr(opt_server, ':');
        size_t addrlen=0;
        if (p == NULL)
            {
            BIO_puts(bio_err, "error: missing server port\n");
            goto err;
            }
        addrlen=(size_t)p - (size_t)opt_server;
        server_address=OPENSSL_malloc(addrlen+1);
        strncpy(server_address, opt_server, addrlen);
        server_address[addrlen]=0;
        server_port=atoi(++p);
    }
    else
        {
        BIO_puts(bio_err, "error: missing server address\n");
        goto err;
        }

    if (opt_cmd_s)
        {
        if (!strcmp(opt_cmd_s, "ir")) opt_cmd = CMP_IR;
        else if (!strcmp(opt_cmd_s, "kur")) opt_cmd = CMP_KUR;
        else if (!strcmp(opt_cmd_s, "cr")) opt_cmd = CMP_CR;
        else if (!strcmp(opt_cmd_s, "rr")) opt_cmd = CMP_RR;
        else if (!strcmp(opt_cmd_s, "rr")) opt_cmd = CMP_CKUANN;
        else
            {
            BIO_printf(bio_err, "error: unknown cmp command '%s'\n", opt_cmd_s);
            goto err;
            }
    }
    else
        {
        BIO_puts(bio_err, "error: no cmp command to execute\n");
        goto err;
        }

    switch (opt_cmd)
        {
        case CMP_IR:
            if (!(opt_user && opt_pass) && !(opt_cert && opt_key))
                {
                BIO_puts(bio_err, "error: missing user/pass or existing certificate and key for ir\n");
                goto err;
                }

            if (opt_cert && !(opt_cacert || opt_trusted))
                {
                BIO_puts(bio_err, "error: using client certificate but no server certificate or trusted store set\n");
                goto err;
                }
            break;
        case CMP_KUR:
        case CMP_CR:
        case CMP_RR:
            if (!(opt_cert && opt_key))
                {
                BIO_puts(bio_err, "error: missing certificate and key\n");
                goto err;
                }

            if (!opt_cacert && !opt_trusted)
                {
                BIO_puts(bio_err, "error: no server certificate or trusted store set\n");
                goto err;
                }
            break;
        case CMP_CKUANN:
            /* TODO */
            break;
        }

    if (opt_cmd == CMP_IR || opt_cmd == CMP_KUR)
        {
        if (!opt_newkey)
            {
            BIO_puts(bio_err, "error: missing new key file\n");
            goto err;
            }
        if (!opt_certout)
            {
            BIO_puts(bio_err, "error: certout not given, nowhere save certificate\n");
            goto err;
            }
        }

    if (opt_validate_path && !opt_trusted)
        {
        BIO_puts(bio_err, "error: trust path validation enabled but no trust store is set\n");
        goto err;
        }

    if (opt_keyfmt_s)
        opt_keyfmt=str2fmt(opt_keyfmt_s);

    if (opt_certfmt_s)
        opt_certfmt=str2fmt(opt_certfmt_s);

    return 1;

    err:
    return 0;
    }

static X509_STORE *create_cert_store(char *file) {
    X509_STORE *cert_ctx=NULL;
    X509_LOOKUP *lookup=NULL;

    cert_ctx=X509_STORE_new();
    if (cert_ctx == NULL) goto err;

    lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
    if (lookup == NULL) goto err;

    X509_LOOKUP_load_file(lookup, file,
        opt_certfmt==FORMAT_ASN1 ? X509_FILETYPE_ASN1 : X509_FILETYPE_PEM);

    return cert_ctx;

err:
    return NULL;
    }

static int setup_ctx(CMP_CTX *ctx)
    {
    EVP_PKEY *pkey=NULL;
    EVP_PKEY *newPkey=NULL;
    X509 *clcert=NULL;
    X509 *cacert=NULL;

    CMP_CTX_set1_serverName(ctx, server_address);
    CMP_CTX_set1_serverPath(ctx, opt_path);
    CMP_CTX_set1_serverPort(ctx, server_port);
    
    if (opt_user && opt_pass)
        {
        CMP_CTX_set1_referenceValue(ctx, (unsigned char*)opt_user, strlen(opt_user));
        CMP_CTX_set1_secretValue(ctx, (unsigned char*)opt_pass, strlen(opt_pass));
        }
    
    if (opt_key &&
        !(pkey=load_key(bio_err, opt_key, opt_keyfmt, 0, opt_keypass, NULL, "key")))
        {
        BIO_printf(bio_err, "error: unable to load private key '%s'\n", opt_key);
        goto err;
        }
    CMP_CTX_set0_pkey(ctx, pkey);

    if (opt_newkey &&
        !(newPkey=load_key(bio_err, opt_newkey, opt_keyfmt, 0, opt_newkeypass, NULL, "newkey")))
        {
        BIO_printf(bio_err, "error: unable to load private key '%s'\n", opt_key);
        goto err;
        }
    CMP_CTX_set0_newPkey(ctx, newPkey);

    if (opt_cert &&
        !(clcert=load_cert(bio_err, opt_cert, opt_certfmt, NULL, NULL, "clcert")))
        {
        BIO_printf(bio_err, "error: unable to load client certificate '%s'\n", opt_key);
        goto err;
        }
    CMP_CTX_set1_clCert(ctx, clcert);

    if (opt_cacert &&
        !(cacert=load_cert(bio_err, opt_cacert, opt_certfmt, NULL, NULL, "cacert")))
        {
        BIO_printf(bio_err, "error: unable to load server certificate '%s'\n", opt_key);
        goto err;
        }
    CMP_CTX_set1_caCert(ctx, cacert);

    if (opt_trusted && !CMP_CTX_set0_trustedStore(ctx, create_cert_store(opt_trusted)))
        {
        BIO_printf(bio_err, "error: unable to load trusted store '%s'\n", opt_key);
        goto err;
        }

    if (opt_untrusted && !CMP_CTX_set0_untrustedStore(ctx, create_cert_store(opt_untrusted)))
        {
        BIO_printf(bio_err, "error: unable to load untrusted store '%s'\n", opt_key);
        goto err;
        }

    if (opt_subject)
        {
        X509_NAME *n=parse_name(opt_subject, MBSTRING_ASC, 0);
        if (n == NULL)
            {
            BIO_printf(bio_err, "error: unable to parse subject name '%s'\n", opt_subject);
            goto err;
            }
        CMP_CTX_set1_subjectName(ctx, n);
        }

    if (opt_recipient)
        {
        X509_NAME *n=parse_name(opt_recipient, MBSTRING_ASC, 0);
        if (n == NULL)
            {
            BIO_printf(bio_err, "error: unable to parse recipient name '%s'\n", opt_recipient);
            goto err;
            }
        CMP_CTX_set1_recipient(ctx, n);
        }

    /* TODO add extcerts !! */
    
    if (opt_validate_path)
        CMP_CTX_set_option(ctx, CMP_CTX_OPT_VALIDATEPATH, 1);

    CMP_CTX_set1_timeOut(ctx, 5*60);

    return 1;

    err:
    return 0;
    }

static CONF *conf=NULL;
/* static CONF *extconf=NULL; */
static BIO *bio_c_out=NULL;


int MAIN(int argc, char **argv)
    {
    /*
    char *configfile=NULL;
    long errorline=-1;
    char *tofree=NULL;
    */
    int badops=0;
    int ret=1;
    CMP_CTX *cmp_ctx;
    CMPBIO *cmp_bio;
    X509 *newcert=NULL;

    if (argc <= 1)
        {
        badops=1;
        goto bad_ops;
        }
    
    apps_startup();
    ERR_load_crypto_strings();
    bio_c_out=BIO_new_fp(stdout,BIO_NOCLOSE);

    /* TODO load up default values from config for trusted store location etc */
    /*
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
    */

    while (--argc > 0 && ++argv)
        {
        opt_t *opt=cmp_opts;
        char *arg=*argv;
        int found,i;

        if (*arg++ != '-' || *arg == 0)
            {
            badops=1;
            break;
            }

        found=0;
        for (i=0; i < sizeof(cmp_opts)/sizeof(cmp_opts[0]); i++,opt++)
            {
            if (opt->name && !strcmp(arg, opt->name))
                {
                if (argc <= 1 && opt->type != OPT_BOOL)
                    {
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
        
        if (!found)
            {
            BIO_printf(bio_err, "unknown argument: '%s'\n", *argv);
            badops=1;
            goto bad_ops;
            }
        }

    if (!badops)
        badops = check_options() == 0;

bad_ops:
    if (badops)
        {
        show_help();
        goto err;
        }

    if (!(cmp_ctx = CMP_CTX_create()) || !setup_ctx(cmp_ctx))
        {
        BIO_puts(bio_err, "error creating new cmp context\n");
        goto err;
        }

    if (!CMP_new_http_bio(&cmp_bio, server_address, server_port))
        {
        BIO_puts(bio_err, "error: setting up connection context\n");
        goto err;
        }

    curl_easy_setopt(cmp_bio, CURLOPT_PROXY, 0);

    switch (opt_cmd)
        {
        case CMP_IR:
            newcert = CMP_doInitialRequestSeq(cmp_bio, cmp_ctx);
            if (!newcert)
                goto err;
            break;
        case CMP_KUR:
            newcert = CMP_doKeyUpdateRequestSeq(cmp_bio, cmp_ctx);
            if (!newcert)
                goto err;
            break;
        case CMP_CR:
            newcert = CMP_doCertificateRequestSeq(cmp_bio, cmp_ctx);
            if (!newcert)
                goto err;
            break;
        case CMP_RR:
            CMP_doRevocationRequestSeq(cmp_bio, cmp_ctx);
            break;
        default: break;
        }

    if (newcert && opt_certout)
        {
        BIO *b = NULL;
        BIO_printf(bio_c_out, "saving certificate to '%s'...\n", opt_certout);
        b=BIO_new(BIO_s_file());
        if (b == NULL || !BIO_write_filename(b, opt_certout))
            {
            BIO_printf(bio_err, "error: unable to open file '%s' for writing\n", opt_certout);
            goto err;
            }
        if (opt_certfmt == FORMAT_ASN1)
            ret = i2d_X509_bio(b, newcert) == 0;
        else
            ret = PEM_write_bio_X509(b, newcert)==0;

        if (ret) goto err;
        }
    
    ret=0;
err:
    /*
    if(tofree)
        OPENSSL_free(tofree);
    */

    OPENSSL_EXIT(ret);
    }
