/* vim: set cinoptions={1s: */
/* apps/cmp.c
 */
/* ====================================================================
 * Written by Miikka Viljanen, based on cmpclient by Martin Peylo
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
 */
/* ====================================================================
 * Copyright 2012 Nokia Siemens Networks Oy. ALL RIGHTS RESERVED.
 * CMP support in OpenSSL originally developed by 
 * Nokia Siemens Networks for contribution to the OpenSSL project.
 */

/* ============================== TODO List ============================== 
 * TODO: actually send the genm for requesting the CKUANN message
 */

#include <openssl/opensslconf.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"

#define CONFIG_FILE "openssl.cnf"
#define CMP_SECTION "cmp"
#undef PROG
#define PROG	cmp_main

#if !defined(HAVE_CURL) || defined(OPENSSL_NO_CMP) || defined(OPENSSL_NO_CMP_CLIENT)

/* can't use the client without cmp and curl... */
int MAIN(int argc, char **argv)
    {
    BIO_puts(bio_err, "error: openssl was compiled without libcurl or with cmp support disabled\n");
    OPENSSL_EXIT(0);
    }

#else

#include <openssl/cmp.h>
#include <openssl/crmf.h>
#include <openssl/pem.h>

static CONF *conf=NULL; /* OpenSSL config file context structure */
static BIO *bio_c_out=NULL; /* OpenSSL BIO for printing to STDOUT */ 

/* the type of cmp command we want to send */
typedef enum { CMP_IR,
               CMP_KUR,
               CMP_CR,
               CMP_RR,
               CMP_CKUANN,
    } cmp_cmd_t;

/* type of a cmdline option.
 * - OPT_BOOL does not take an additional argument and just
 *   toggles something on or off
 * - OPT_NUM takes a number argument and sets that to a variable
 * - OPT_TXT copies the argument text to a buffer
 * */
typedef enum { OPT_BOOL, OPT_NUM, OPT_TXT } opttype_t;
typedef struct 
    {
    const char *name;
    const char *help;
    opttype_t type;
    union {
        char **txt;
        long *num;
        } v;
    } opt_t;

static char *opt_server=NULL;
static char *server_address=NULL;
static long  server_port=0;
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

static char *opt_srvcert=NULL;
static char *opt_trusted=NULL;
static char *opt_untrusted=NULL;
static char *opt_keyfmt_s="PEM";
static char *opt_certfmt_s="PEM";
static int   opt_keyfmt=FORMAT_PEM;
static int   opt_certfmt=FORMAT_PEM;

static char *opt_extcerts=NULL;
static char *opt_subject=NULL;
static char *opt_recipient=NULL;

static char *opt_cacertsout=NULL;
static char *opt_extracertsout=NULL;

/* Table of commandline options.
 * NOTE: this table is also used to parse options from
 *       openssl's config file (openssl.cnf) !*/
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

    { "srvcert", "Certificate of the CMP server", OPT_TXT, {&opt_srvcert} },
    { "trusted", "A file of trusted certificates", OPT_TXT, {&opt_trusted} },
    { "untrusted", "A file of untrusted certificates", OPT_TXT, {&opt_untrusted} },

    { "keyfmt", "Format to use for key files. Default PEM.", OPT_TXT, {&opt_keyfmt_s} },
    { "certfmt", "Format to use for certificate files. Default PEM.", OPT_TXT, {&opt_certfmt_s} },

    { "extcerts", "List of certificate files to include in outgoing messages", OPT_TXT, {&opt_extcerts} },
    { "subject", "X509 subject name to be used in the requested certificate template", OPT_TXT, {&opt_subject} },
    { "recipient", "X509 name of the recipient", OPT_TXT, {&opt_recipient} },
    
    { "extracertsout", "File where to save extra certificates received", OPT_TXT, {&opt_extracertsout} },
    { "cacertsout", "File where to save received CA certificates (from IR)", OPT_TXT, {&opt_cacertsout} },
};

/* ########################################################################## *
 * print out the help text for each commandline option
 * ########################################################################## */
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

/* ########################################################################## *
 * use the commandline option table to read values from the [ cmp ] section of 
 * openssl.cnf.  Defaults are taken from the config file, they can be 
 * overwritten on the command line
 * ########################################################################## */
static void read_config(CONF *conf)
    {
    opt_t *opt=cmp_opts;
    int i=0;

    for (i=0; i < sizeof(cmp_opts)/sizeof(cmp_opts[0]); i++,opt++)
        {
        switch(opt->type)
            {
            case OPT_BOOL:
            case OPT_NUM:
                NCONF_get_number_e(conf, CMP_SECTION, opt->name, opt->v.num);
                break;
            case OPT_TXT:
                *opt->v.txt = NCONF_get_string(conf, CMP_SECTION, opt->name);
                break;
            default:
                break;
            }
        }

    ERR_clear_error();
    }

/* ########################################################################## *
 * verify that all the necessary options have been set
 * prints reason for error to bio_err
 * returns 1 on success, 0 on error
 * ########################################################################## */
static int check_options(void)
    {
    if (opt_server)
        {
        char *p=strrchr(opt_server, ':');
        size_t addrlen=0;
        if (p == NULL)
            {
            BIO_puts(bio_err, "error: missing server port\n");
            goto err;
            }
        addrlen=(size_t)p - (size_t)opt_server;
        server_address=OPENSSL_malloc(addrlen+1);
        if (server_address == NULL)
            {
            BIO_puts(bio_err, "error: out of memory\n");
            goto err;
            }
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
        else if (!strcmp(opt_cmd_s, "ckuann")) opt_cmd = CMP_CKUANN;
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

            if (opt_cert && !(opt_srvcert || opt_trusted))
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

            if (!opt_srvcert && !opt_trusted)
                {
                BIO_puts(bio_err, "error: no server certificate or trusted store set\n");
                goto err;
                }
            break;
        case CMP_CKUANN:
            /* TODO: sending the empty GENM to request the CKUANN */
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

    if (opt_keyfmt_s)
        opt_keyfmt=str2fmt(opt_keyfmt_s);

    if (opt_certfmt_s)
        opt_certfmt=str2fmt(opt_certfmt_s);

    return 1;

    err:
    return 0;
    }

/* ########################################################################## *
 * create cert store structure with certificates read from givenfile
 * returns pointer to created X509_STORE on success, NULL on error
 * ########################################################################## */
static X509_STORE *create_cert_store(char *file)
    {
    X509_STORE *cert_ctx=NULL;
    X509_LOOKUP *lookup=NULL;

    cert_ctx=X509_STORE_new();
    if (cert_ctx == NULL) goto err;

    lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
    if (lookup == NULL) goto err;

    X509_LOOKUP_load_file(lookup, file,
        opt_certfmt==FORMAT_ASN1 ? X509_FILETYPE_ASN1 : X509_FILETYPE_PEM);

    return cert_ctx;

err:
    return NULL;
    }

/* ########################################################################## *
 * set up the CMP_CTX structure based on options from config file/CLI
 * prints reason for error to bio_err
 * returns 1 on success, 0 on error
 * ########################################################################## */
static int setup_ctx(CMP_CTX *ctx)
    {
    EVP_PKEY *pkey=NULL;
    EVP_PKEY *newPkey=NULL;
    X509 *clcert=NULL;
    X509 *srvcert=NULL;

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
    if (pkey) CMP_CTX_set0_pkey(ctx, pkey);

    if (opt_newkey &&
        !(newPkey=load_key(bio_err, opt_newkey, opt_keyfmt, 0, opt_newkeypass, NULL, "newkey")))
        {
        BIO_printf(bio_err, "error: unable to load private key '%s'\n", opt_newkey);
        goto err;
        }
    if (newPkey) CMP_CTX_set0_newPkey(ctx, newPkey);

    if (opt_cert &&
        !(clcert=load_cert(bio_err, opt_cert, opt_certfmt, NULL, NULL, "clcert")))
        {
        BIO_printf(bio_err, "error: unable to load client certificate '%s'\n", opt_cert);
        goto err;
        }
    if (clcert) CMP_CTX_set1_clCert(ctx, clcert);

    if (opt_srvcert &&
        !(srvcert=load_cert(bio_err, opt_srvcert, opt_certfmt, NULL, NULL, "cacert")))
        {
        BIO_printf(bio_err, "error: unable to load server certificate '%s'\n", opt_srvcert);
        goto err;
        }
    if (srvcert) CMP_CTX_set1_caCert(ctx, srvcert);

    if (opt_trusted && !CMP_CTX_set0_trustedStore(ctx, create_cert_store(opt_trusted)))
        {
        BIO_printf(bio_err, "error: unable to load trusted store '%s'\n", opt_trusted);
        goto err;
        }

    if (opt_untrusted && !CMP_CTX_set0_untrustedStore(ctx, create_cert_store(opt_untrusted)))
        {
        BIO_printf(bio_err, "error: unable to load untrusted store '%s'\n", opt_untrusted);
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

    CMP_CTX_set_HttpTimeOut(ctx, 5*60);

    return 1;

    err:
    return 0;
    }


/* ########################################################################## *
 * write out the given certificate to the output specified by bio.
 * depending on options use either PEM or DER format
 * returns 1 on success, 0 on error
 * ########################################################################## */
static int write_cert(BIO *bio, X509 *cert)
    {
        if ( (opt_certfmt == FORMAT_PEM && PEM_write_bio_X509(bio, cert))
             || (opt_certfmt == FORMAT_ASN1 && i2d_X509_bio(bio, cert)) )
            return 1;
        return 0;
    }

/* ########################################################################## *
 * writes out the received CA certs to the given file
 * returns number of written certificates on success, 0 on error
 * ########################################################################## */
static int save_capubs(CMP_CTX *cmp_ctx, char *destFile)
    {
    X509 *cert = NULL;
    BIO *bio=NULL;
    int n = 0;

    if (!destFile || (bio=BIO_new(BIO_s_file())) == NULL ||
            !BIO_append_filename(bio,(char *)destFile))
        goto err;

    BIO_printf(bio_c_out, "Received %d CA certificates, saving to %s\n", CMP_CTX_caPubs_num(cmp_ctx), destFile);
    while ( (cert=CMP_CTX_caPubs_pop(cmp_ctx)) != NULL)
        {
        if (write_cert(bio, cert))
            n++;
        else
            BIO_printf(bio_err,"ERROR writing certificate to %s!\n", destFile);
        }
    return n;

err:
    BIO_printf(bio_err, "ERROR: could not open '%s' for writing\n", destFile);
    return 0;
    }

/* ########################################################################## *
 * writes out the received extraCerts to the given file
 * returns number of written certificates on success, 0 on error
 * ########################################################################## */
static int save_extracerts(CMP_CTX *cmp_ctx, char *destFile)
    {
    X509 *cert = NULL;
    BIO *bio=NULL;
    int n = 0;

    if (!destFile || (bio=BIO_new(BIO_s_file())) == NULL ||
            !BIO_append_filename(bio,(char *)destFile))
        goto err;

    BIO_printf(bio_c_out, "Received %d extra certificates, saving to %s\n", CMP_CTX_extraCertsIn_num(cmp_ctx), destFile);
    while ( (cert=CMP_CTX_extraCertsIn_pop(cmp_ctx)) != NULL)
        {
        if (write_cert(bio, cert))
            n++;
        else
            BIO_printf(bio_err,"ERROR writing certificate to %s!\n", destFile);
        }
    return n;

err:
    BIO_printf(bio_err, "ERROR: could not open '%s' for writing\n", destFile);
    return 0;
    }


/* ########################################################################## *
 * ########################################################################## */
int MAIN(int argc, char **argv)
    {
    char *configfile=NULL;
    long errorline=-1;
    char *tofree=NULL; /* used as getenv returns a direct pointer to the environment setting */
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

    if (!strcmp(argv[1], "-help"))
        {
        show_help();
        goto err;
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

	/* read default values for options from openssl.cnf */
    if (configfile)
        {
        BIO_printf(bio_err,"Using configuration from %s\n",configfile);
        conf = NCONF_new(NULL);
        if (NCONF_load(conf,configfile,&errorline) <= 0)
            {
            if (errorline <= 0)
                BIO_printf(bio_err,"error loading the config file '%s'\n",
                        configfile);
            else
                BIO_printf(bio_err,"error on line %ld of config file '%s'\n",
                        errorline,configfile);
            goto err;
            }

        read_config(conf);
        }

    if(tofree)
        {
        OPENSSL_free(tofree);
        tofree = NULL;
        }

	/* parse commandline options */
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

	/* set up the connection context but don't connect yet */
    if (!CMP_new_http_bio(&cmp_bio, server_address, server_port))
        {
        BIO_puts(bio_err, "error: setting up connection context\n");
        goto err;
        }

	/* everything is ready, now connect and preform the command! */
    switch (opt_cmd)
        {
        case CMP_IR:
            newcert = CMP_doInitialRequestSeq(cmp_bio, cmp_ctx);
            if (!newcert)
                goto err;
            if (opt_cacertsout && CMP_CTX_caPubs_num(cmp_ctx) > 0)
                save_capubs(cmp_ctx, opt_cacertsout);
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
        case CMP_CKUANN:
            /* TODO: sending the empty GENM to request the CKUANN */
            break;
        default: break;
        }

    if (opt_extracertsout && CMP_CTX_extraCertsIn_num(cmp_ctx) > 0)
        save_extracerts(cmp_ctx, opt_extracertsout);

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
    if (ret != 0)
        ERR_print_errors_fp(stderr);
    if(tofree)
        OPENSSL_free(tofree);

    OPENSSL_EXIT(ret);
    }

#endif

