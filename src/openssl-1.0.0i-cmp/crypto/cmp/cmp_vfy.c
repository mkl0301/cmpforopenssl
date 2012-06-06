/* vim: set noet ts=4 sts=4 sw=4: */
/* crypto/cmp/cmp_vfy.c
 * Functions to verify CMP (RFC 4210) messages for OpenSSL
 */
/* ====================================================================
 * Originally written by Martin Peylo for the OpenSSL project.
 * <martin dot peylo at nsn dot com>
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
 * Copyright 2007-2010 Nokia Siemens Networks Oy. ALL RIGHTS RESERVED.
 * CMP support in OpenSSL originally developed by 
 * Nokia Siemens Networks for contribution to the OpenSSL project.
 */

/* =========================== CHANGE LOG =============================
 * 2007 - Martin Peylo - Initial Creation
 * 06/2010 - Miikka Viljanen - Report errors with OpenSSL error codes instead
 *                             of printf statements.
 */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/crmf.h>
#include <openssl/cmp.h>
#include <openssl/err.h>

int CMP_error_callback(const char *str, size_t len, void *u);

/* ############################################################################ *
 * validate a protected message (sha1+RSA/DSA or any other algorithm supported by OpenSSL)
 * ############################################################################ */
static int CMP_verify_signature( CMP_PKIMESSAGE *msg, X509_ALGOR *algor, EVP_PKEY *senderPkey) {
    EVP_MD_CTX *ctx=NULL;
    CMP_PROTECTEDPART protPart;
    int ret;

    size_t protPartDerLen;
    unsigned char *protPartDer=NULL;

    if (!msg || !algor || !senderPkey) return 0;

    protPart.header = msg->header;
    protPart.body   = msg->body;
    protPartDerLen  = i2d_CMP_PROTECTEDPART(&protPart, &protPartDer);

    ctx=EVP_MD_CTX_create();
    EVP_VerifyInit_ex(ctx, EVP_get_digestbynid(OBJ_obj2nid(algor->algorithm)), NULL);
    EVP_VerifyUpdate(ctx, protPartDer, protPartDerLen);
    ret = EVP_VerifyFinal(ctx, msg->protection->data, msg->protection->length, senderPkey);

    /* cleanup */
    EVP_MD_CTX_destroy(ctx);
    return ret;
}

/* ############################################################################ */
/* Validate the protection of a PKIMessage
 * returns 1 when valid
 * returns 0 when invalid, not existent or on error
 */
/* ############################################################################ */
int CMP_protection_verify(CMP_PKIMESSAGE *msg, 
			    X509_ALGOR *_algor,
			    EVP_PKEY *senderPkey,
			    const ASN1_OCTET_STRING *secret)
{
    ASN1_BIT_STRING *protection=NULL;
    X509_ALGOR *algor=NULL;
    ASN1_OBJECT *algorOID=NULL;
    int valid = 0;

    int usedAlgorNid;

    if (!msg->protection) goto err;
    if (!msg->header->protectionAlg) goto err;
    if (!(algor = X509_ALGOR_dup(msg->header->protectionAlg))) goto err;

    X509_ALGOR_get0( &algorOID, NULL, NULL, algor);
    usedAlgorNid = OBJ_obj2nid(algorOID);
    if (usedAlgorNid == NID_id_PasswordBasedMAC) {
        /* need to have params for PBMAC, so check that we have them */
        /* TODO: simplify this logic / check if it's even necessary*/
        if (!algor->parameter || 
            ASN1_TYPE_get(algor->parameter) == V_ASN1_UNDEF ||
            ASN1_TYPE_get(algor->parameter) == V_ASN1_NULL) {
            /* if parameter is not given in PKIMessage, then try to use parameter from arguments */
            if (!_algor || algor->algorithm->nid != _algor->algorithm->nid || 
                ASN1_TYPE_get(_algor->parameter) == V_ASN1_UNDEF || 
                ASN1_TYPE_get(_algor->parameter) == V_ASN1_NULL) {
                CMPerr(CMP_F_CMP_PROTECTION_VERIFY, CMP_R_FAILED_TO_DETERMINE_PROTECTION_ALGORITHM);
                goto err;
            }
            if (!algor->parameter)
                algor->parameter = ASN1_TYPE_new();
            ASN1_TYPE_set(algor->parameter, _algor->parameter->type, _algor->parameter->value.ptr);
        }
    }

    // printf("INFO: Verifying protection, algorithm %s\n", OBJ_nid2sn(OBJ_obj2nid(msg->header->protectionAlg->algorithm)));

    if (usedAlgorNid == NID_id_PasswordBasedMAC)  {
        /* password based Mac */ 
        if (!(protection = CMP_protection_new( msg, algor, NULL, secret)))
            goto err; /* failed to generate protection string! */
        if (!M_ASN1_BIT_STRING_cmp( protection, msg->protection))
            /* protection is valid */
            valid = 1;
        else
            /* strings are not equal */
            valid = 0;
    }
    else {
        valid = CMP_verify_signature(msg, algor, senderPkey);
    }

    X509_ALGOR_free(algor);

    return valid;

err:
    if (algor) X509_ALGOR_free(algor);
    CMPerr(CMP_F_CMP_PROTECTION_VERIFY, CMP_R_CMPERROR);
    return 0;
}

/* ############################################################################ *
 * Structure to hold the X509_STORE_CTX and a pointer to CMP_CTX so that we can
 * provide extra data to the cert validation callback
 * ############################################################################ */
typedef struct {
    X509_STORE_CTX cert_ctx;
    CMP_CTX *cmp_ctx;
} X509_STORE_CTX_ext;

/* ############################################################################ *
 * Attempt to validate certificate path. returns 1 if the path was
 * validated successfully and 0 if not.
 * ############################################################################ */
int CMP_validate_cert_path(CMP_CTX *cmp_ctx, STACK_OF(X509) *tchain, STACK_OF(X509) *uchain, X509 *cert)
{
    int i=0,ret=0;
    X509_STORE *ctx;
    X509_STORE_CTX *csc;
    X509_STORE_CTX_ext cscex;

    if (cmp_ctx == NULL || cert == NULL) goto end;

    if (!cmp_ctx->trusted_store && !tchain) {
        CMPerr(CMP_F_CMP_VALIDATE_CERT_PATH, CMP_R_NO_TRUSTED_CERTIFICATES_SET);
        goto end;
    }

    if (!cmp_ctx->trusted_store)
        cmp_ctx->trusted_store = ctx = X509_STORE_new();
    else
        ctx = cmp_ctx->trusted_store;
    if (!ctx) goto end;

    csc = X509_STORE_CTX_new();
    if (csc == NULL)
    {
	if (cmp_ctx&&cmp_ctx->error_cb) ERR_print_errors_cb(CMP_error_callback, (void*) cmp_ctx);
        goto end;
    }

    /* TODO include the certs in ctx->untrusted_store in the validation process.
     * right now we only use the certs provided in uchain (which come from the extracerts field) */

    X509_STORE_set_flags(ctx, 0);
    if(!X509_STORE_CTX_init(csc, ctx, cert, uchain))
    {
	if (cmp_ctx&&cmp_ctx->error_cb) ERR_print_errors_cb(CMP_error_callback, (void*) cmp_ctx);
        goto end;
    }

    /* add whatever stuff we have in tcain to the trusted store.
     * it we set tchain using X509_STORE_CTX_trusted_stack the
     * trusted_store will be ignored, so we do it this way... */
    for (i=0; i < sk_X509_num(tchain); i++) {
        X509_OBJECT *o = (X509_OBJECT*) malloc(sizeof(X509_OBJECT));
        if (o) {
            o->type = 1;
            o->data.x509 = X509_dup(sk_X509_value(tchain, i));
            sk_X509_OBJECT_push(cmp_ctx->trusted_store->objs, o);
        }
    }

    /* if(tchain) X509_STORE_CTX_trusted_stack(csc, tchain); */

    /* TODO handle CRLs? */
    /* if (crls) X509_STORE_CTX_set0_crls(csc, crls); */

    cscex.cert_ctx = *csc;
    cscex.cmp_ctx = cmp_ctx;
    i=X509_verify_cert((X509_STORE_CTX*) &cscex);

    X509_STORE_CTX_free(csc);

    ret=0;
end:
    if (i > 0)
    {
        fprintf(stdout,"OK\n");
        ret=1;
    }
    else
	if (cmp_ctx&&cmp_ctx->error_cb) ERR_print_errors_cb(CMP_error_callback, (void*) cmp_ctx);

    return(ret);
}

#if 0
static void nodes_print(BIO *out, const char *name,
    STACK_OF(X509_POLICY_NODE) *nodes)
    {
    X509_POLICY_NODE *node;
    int i;
    BIO_printf(out, "%s Policies:", name);
    if (nodes)
        {
        BIO_puts(out, "\n");
        for (i = 0; i < sk_X509_POLICY_NODE_num(nodes); i++)
            {
            node = sk_X509_POLICY_NODE_value(nodes, i);
            X509_POLICY_NODE_print(out, node, 2);
            }
        }
    else
        BIO_puts(out, " <empty>\n");
    }


static void policies_print(BIO *out, X509_STORE_CTX *ctx)
    {
    X509_POLICY_TREE *tree;
    int explicit_policy;
    int free_out = 0;
    if (out == NULL)
        {
        out = BIO_new_fp(stderr, BIO_NOCLOSE);
        free_out = 1;
        }
    tree = X509_STORE_CTX_get0_policy_tree(ctx);
    explicit_policy = X509_STORE_CTX_get_explicit_policy(ctx);

    BIO_printf(out, "Require explicit Policy: %s\n", explicit_policy ? "True" : "False");

    nodes_print(out, "Authority", X509_policy_tree_get0_policies(tree));
    nodes_print(out, "User", X509_policy_tree_get0_user_policies(tree));
    if (free_out)
        BIO_free(out);
    }
#endif

/* ############################################################################ *
 * This is called for every valid certificate. Here we could add additional checks,
 * for policies for example.
 * ############################################################################ */
int CMP_cert_callback(int ok, X509_STORE_CTX *ctx)
{
    X509_STORE_CTX_ext *ctxext = (X509_STORE_CTX_ext*) ctx;
    int cert_error = X509_STORE_CTX_get_error(ctx);
    X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);

    /* XXX should we check policies here? */

    if (!ok)
    {
        char cert_name[512] = {0};
        if (current_cert)
        {
            BIO *bio = BIO_new(BIO_s_mem());
            X509_NAME_print(bio, X509_get_subject_name(current_cert), XN_FLAG_ONELINE);
            BIO_read(bio, cert_name, sizeof(cert_name));
            BIO_free(bio);
        }

        CMP_printf(ctxext->cmp_ctx, "Certificate '%s': %serror %d at %d depth lookup:%s\n",
                   cert_name,
                   X509_STORE_CTX_get0_parent_ctx(ctx) ? "[CRL path]" : "",
                   cert_error,
                   X509_STORE_CTX_get_error_depth(ctx),
                   X509_verify_cert_error_string(cert_error));
        switch(cert_error)
        {
            case X509_V_ERR_NO_EXPLICIT_POLICY:
                // policies_print(NULL, ctx);
            case X509_V_ERR_CERT_HAS_EXPIRED:

                /* since we are just checking the certificates, it is
                 * ok if they are self signed. But we should still warn
                 * the user.
                 */

            case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
                /* Continue after extension errors too */
            case X509_V_ERR_INVALID_CA:
            case X509_V_ERR_INVALID_NON_CA:
            case X509_V_ERR_PATH_LENGTH_EXCEEDED:
            case X509_V_ERR_INVALID_PURPOSE:
            case X509_V_ERR_CRL_HAS_EXPIRED:
            case X509_V_ERR_CRL_NOT_YET_VALID:
            case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
                ok = 1;

        }

        CMP_printf(ctxext->cmp_ctx, "cert_error = %d\n", cert_error);

        return ok;

    }
#if 0
    if (cert_error == X509_V_OK && ok == 2)
        policies_print(NULL, ctx);
#endif

    return(ok);
}
