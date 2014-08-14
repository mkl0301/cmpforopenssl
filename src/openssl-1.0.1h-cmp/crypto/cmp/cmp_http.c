/* vim: set noet ts=4 sts=4 sw=4: */
/* crypto/cmp/cmp_http.c
 * HTTP functions for CMP (RFC 4210) for OpenSSL
 */
/* ====================================================================
 * Originally written by Martin Peylo for the OpenSSL project.
 * <martin dot peylo at nsn dot com>
 * 2010-2013 Miikka Viljanen <mviljane@users.sourceforge.net>
 * 
 * HTTP code taken from crypto/ocsp/ocsp_ht.c, written by 
 * Dr Stephen N Henson (steve@openssl.org)
 */
/* ====================================================================
 * Copyright (c) 2007-2010 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *	  software must display the following acknowledgment:
 *	  "This product includes software developed by the OpenSSL Project
 *	  for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *	  endorse or promote products derived from this software without
 *	  prior written permission. For written permission, please contact
 *	  openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *	  nor may "OpenSSL" appear in their names without prior written
 *	  permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *	  acknowledgment:
 *	  "This product includes software developed by the OpenSSL Project
 *	  for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.	IN NO EVENT SHALL THE OpenSSL PROJECT OR
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
 * Copyright 2007-2014 Nokia Oy. ALL RIGHTS RESERVED.
 * CMP support in OpenSSL originally developed by 
 * Nokia for contribution to the OpenSSL project.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "e_os.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/cmp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/ssl.h>

#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef OPENSSL_SYS_SUNOS
#define strtoul (unsigned long)strtol
#endif /* OPENSSL_SYS_SUNOS */


#ifndef HAVE_CURL /* NO curl support, so we use HTTP code from OCSP */

typedef BIO CMPBIO;

/* This code for HTTP was adapted from crypto/ocsp/ocsp_ht.c, OpenSSL version
 * 1.0.1e, originally written by Dr Stephen N Henson (steve@openssl.org) for
 * the OpenSSL project 2006.
 */

/* Stateful CMP request code, supporting non-blocking I/O */

/* Opaque CMP request status structure */

typedef struct cmp_req_ctx_st CMP_REQ_CTX;
struct cmp_req_ctx_st {
	int state;		/* Current I/O state */
	unsigned char *iobuf;	/* Line buffer */
	int iobuflen;		/* Line buffer length */
	BIO *io;		/* BIO to perform I/O with */
	BIO *mem;		/* Memory BIO response is built into */
	unsigned long asn1_len;	/* ASN1 length of response */
	};

#define CMP_MAX_REQUEST_LENGTH	(100 * 1024)
#define CMP_MAX_LINE_LEN	4096;

/* CMP states */

/* If set no reading should be performed */
#define OHS_NOREAD		0x1000
/* Error condition */
#define OHS_ERROR		(0 | OHS_NOREAD)
/* First line being read */
#define OHS_FIRSTLINE		1
/* MIME headers being read */
#define OHS_HEADERS		2
/* CMP initial header (tag + length) being read */
#define OHS_ASN1_HEADER		3
/* CMP content octets being read */
#define OHS_ASN1_CONTENT	4
/* Request being sent */
#define OHS_ASN1_WRITE		(6 | OHS_NOREAD)
/* Request being flushed */
#define OHS_ASN1_FLUSH		(7 | OHS_NOREAD)
/* Completed */
#define OHS_DONE		(8 | OHS_NOREAD)

/* from apps.h */
#ifndef openssl_fdset
#ifdef OPENSSL_SYSNAME_WIN32
#  define openssl_fdset(a,b) FD_SET((unsigned int)a, b)
#else
#  define openssl_fdset(a,b) FD_SET(a, b)
#endif
#endif


static int parse_http_line1(char *line);

void CMP_REQ_CTX_free(CMP_REQ_CTX *rctx)
	{
	if (rctx->mem)
		BIO_free(rctx->mem);
	if (rctx->iobuf)
		OPENSSL_free(rctx->iobuf);
	OPENSSL_free(rctx);
	}

int CMP_REQ_CTX_set1_req(CMP_REQ_CTX *rctx, CMP_PKIMESSAGE *req)
	{
	static const char req_hdr[] =
	"Content-Type: application/pkixcmp\r\n"
	"Cache-control: no-cache\r\n"
	"Content-Length: %d\r\n\r\n";
        if (BIO_printf(rctx->mem, req_hdr, i2d_CMP_PKIMESSAGE(req, NULL)) <= 0)
		return 0;
        if (i2d_CMP_PKIMESSAGE_bio(rctx->mem, req) <= 0)
		return 0;
	rctx->state = OHS_ASN1_WRITE;
	rctx->asn1_len = BIO_get_mem_data(rctx->mem, NULL);
	return 1;
	}

int CMP_REQ_CTX_add1_header(CMP_REQ_CTX *rctx,
		const char *name, const char *value)
	{
	if (!name)
		return 0;
	if (BIO_puts(rctx->mem, name) <= 0)
		return 0;
	if (value)
		{
		if (BIO_write(rctx->mem, ": ", 2) != 2)
			return 0;
		if (BIO_puts(rctx->mem, value) <= 0)
			return 0;
		}
	if (BIO_write(rctx->mem, "\r\n", 2) != 2)
		return 0;
	return 1;
	}

CMP_REQ_CTX *CMP_sendreq_new(BIO *io, char *path, CMP_PKIMESSAGE *req,
								int maxline)
	{
	static const char post_hdr[] = "POST %s HTTP/1.0\r\n";

	CMP_REQ_CTX *rctx;
	rctx = OPENSSL_malloc(sizeof(CMP_REQ_CTX));
	rctx->state = OHS_ERROR;
	rctx->mem = BIO_new(BIO_s_mem());
	rctx->io = io;
	rctx->asn1_len = 0;
	if (maxline > 0)
		rctx->iobuflen = maxline;
	else
		rctx->iobuflen = CMP_MAX_LINE_LEN;
	rctx->iobuf = OPENSSL_malloc(rctx->iobuflen);
	if (!rctx->iobuf)
		return 0;
	if (!path)
		path = "/";

        if (BIO_printf(rctx->mem, post_hdr, path) <= 0)
		return 0;

	if (req && !CMP_REQ_CTX_set1_req(rctx, req))
		return 0;

	return rctx;
	}

/* Parse the HTTP response. This will look like this:
 * "HTTP/1.0 200 OK". We need to obtain the numeric code and
 * (optional) informational message.
 */

static int parse_http_line1(char *line)
	{
	int retcode;
	char *p, *q, *r;
	/* Skip to first white space (passed protocol info) */

	for(p = line; *p && !isspace((unsigned char)*p); p++)
		continue;
	if(!*p)
		{
		CMPerr(CMP_F_PARSE_HTTP_LINE1,
					CMP_R_SERVER_RESPONSE_PARSE_ERROR);
		return 0;
		}

	/* Skip past white space to start of response code */
	while(*p && isspace((unsigned char)*p))
		p++;

	if(!*p)
		{
		CMPerr(CMP_F_PARSE_HTTP_LINE1,
					CMP_R_SERVER_RESPONSE_PARSE_ERROR);
		return 0;
		}

	/* Find end of response code: first whitespace after start of code */
	for(q = p; *q && !isspace((unsigned char)*q); q++)
		continue;

	if(!*q)
		{
		CMPerr(CMP_F_PARSE_HTTP_LINE1,
					CMP_R_SERVER_RESPONSE_PARSE_ERROR);
		return 0;
		}

	/* Set end of response code and start of message */ 
	*q++ = 0;

	/* Attempt to parse numeric code */
	retcode = strtoul(p, &r, 10);

	if(*r)
		return 0;

	/* Skip over any leading white space in message */
	while(*q && isspace((unsigned char)*q))
		q++;

	if(*q)
		{
		/* Finally zap any trailing white space in message (include
		 * CRLF) */

		/* We know q has a non white space character so this is OK */
		for(r = q + strlen(q) - 1; isspace((unsigned char)*r); r--)
			*r = 0;
		}
	if(retcode != 200)
		{
		CMPerr(CMP_F_PARSE_HTTP_LINE1, CMP_R_SERVER_RESPONSE_ERROR);
		if(!*q)
			ERR_add_error_data(2, "Code=", p);
		else
			ERR_add_error_data(4, "Code=", p, ",Reason=", q);
		return 0;
		}


	return 1;

	}

int CMP_sendreq_nbio(CMP_PKIMESSAGE **presp, CMP_REQ_CTX *rctx)
	{
	int i, n;
	const unsigned char *p;
	next_io:
	if (!(rctx->state & OHS_NOREAD))
		{
		n = BIO_read(rctx->io, rctx->iobuf, rctx->iobuflen);

		if (n <= 0)
			{
			if (BIO_should_retry(rctx->io))
				return -1;
			return 0;
			}

		/* Write data to memory BIO */

		if (BIO_write(rctx->mem, rctx->iobuf, n) != n)
			return 0;
		}

	switch(rctx->state)
		{

		case OHS_ASN1_WRITE:
		n = BIO_get_mem_data(rctx->mem, &p);

		i = BIO_write(rctx->io,
			p + (n - rctx->asn1_len), rctx->asn1_len);

		if (i <= 0)
			{
			if (BIO_should_retry(rctx->io))
				return -1;
			rctx->state = OHS_ERROR;
			return 0;
			}

		rctx->asn1_len -= i;

		if (rctx->asn1_len > 0)
			goto next_io;

		rctx->state = OHS_ASN1_FLUSH;

		(void)BIO_reset(rctx->mem);

		case OHS_ASN1_FLUSH:

		i = BIO_flush(rctx->io);

		if (i > 0)
			{
			rctx->state = OHS_FIRSTLINE;
			goto next_io;
			}

		if (BIO_should_retry(rctx->io))
			return -1;

		rctx->state = OHS_ERROR;
		return 0;

		case OHS_ERROR:
		return 0;

		case OHS_FIRSTLINE:
		case OHS_HEADERS:

		/* Attempt to read a line in */

		next_line:
		/* Due to &%^*$" memory BIO behaviour with BIO_gets we
		 * have to check there's a complete line in there before
		 * calling BIO_gets or we'll just get a partial read.
		 */
		n = BIO_get_mem_data(rctx->mem, &p);
		if ((n <= 0) || !memchr(p, '\n', n))
			{
			if (n >= rctx->iobuflen)
				{
				rctx->state = OHS_ERROR;
				return 0;
				}
			goto next_io;
			}
		n = BIO_gets(rctx->mem, (char *)rctx->iobuf, rctx->iobuflen);

		if (n <= 0)
			{
			if (BIO_should_retry(rctx->mem))
				goto next_io;
			rctx->state = OHS_ERROR;
			return 0;
			}

		/* Don't allow excessive lines */
		if (n == rctx->iobuflen)
			{
			rctx->state = OHS_ERROR;
			return 0;
			}

		/* First line */
		if (rctx->state == OHS_FIRSTLINE)
			{
			if (parse_http_line1((char *)rctx->iobuf))
				{
				rctx->state = OHS_HEADERS;
				goto next_line;
				}
			else
				{
				rctx->state = OHS_ERROR;
				return 0;
				}
			}
		else
			{
			/* Look for blank line: end of headers */
			for (p = rctx->iobuf; *p; p++)
				{
				if ((*p != '\r') && (*p != '\n'))
					break;
				}
			if (*p)
				goto next_line;

			rctx->state = OHS_ASN1_HEADER;

			}
 
		/* Fall thru */


		case OHS_ASN1_HEADER:
		/* Now reading ASN1 header: can read at least 2 bytes which
		 * is enough for ASN1 SEQUENCE header and either length field
		 * or at least the length of the length field.
		 */
		n = BIO_get_mem_data(rctx->mem, &p);
		if (n < 2)
			goto next_io;

		/* Check it is an ASN1 SEQUENCE */
		if (*p++ != (V_ASN1_SEQUENCE|V_ASN1_CONSTRUCTED))
			{
			rctx->state = OHS_ERROR;
			return 0;
			}

		/* Check out length field */
		if (*p & 0x80)
			{
			/* If MSB set on initial length octet we can now
			 * always read 6 octets: make sure we have them.
			 */
			if (n < 6)
				goto next_io;
			n = *p & 0x7F;
			/* Not NDEF or excessive length */
			if (!n || (n > 4))
				{
				rctx->state = OHS_ERROR;
				return 0;
				}
			p++;
			rctx->asn1_len = 0;
			for (i = 0; i < n; i++)
				{
				rctx->asn1_len <<= 8;
				rctx->asn1_len |= *p++;
				}

			if (rctx->asn1_len > CMP_MAX_REQUEST_LENGTH)
				{
				rctx->state = OHS_ERROR;
				return 0;
				}

			rctx->asn1_len += n + 2;
			}
		else
			rctx->asn1_len = *p + 2;

		rctx->state = OHS_ASN1_CONTENT;

		/* Fall thru */
		
		case OHS_ASN1_CONTENT:
		n = BIO_get_mem_data(rctx->mem, &p);
		if (n < (int)rctx->asn1_len)
			goto next_io;


		*presp = d2i_CMP_PKIMESSAGE(NULL, &p, rctx->asn1_len);
		if (*presp)
			{
			rctx->state = OHS_DONE;
			return 1;
			}

		rctx->state = OHS_ERROR;
		return 0;

		break;

		case OHS_DONE:
		return 1;

		}

	return 0;
	}

/* Blocking CMP request handler: now a special case of non-blocking I/O */

CMP_PKIMESSAGE *CMP_sendreq_bio(BIO *b, char *path, CMP_PKIMESSAGE *req)
	{
	CMP_PKIMESSAGE *resp = NULL;
	CMP_REQ_CTX *ctx;
	int rv;

	ctx = CMP_sendreq_new(b, path, req, -1);
	if (!ctx) return NULL;

	do
		{
		rv = CMP_sendreq_nbio(&resp, ctx);
		} while ((rv == -1) && BIO_should_retry(b));

	CMP_REQ_CTX_free(ctx);

	if (rv)
		return resp;

	return NULL;
	}


#else /* HAVE_CURL */

typedef CURL CMPBIO;

/* If libcurl is available, we use this code. */

typedef struct rdata_s
	{
	char *memory;
	size_t size;
	} rdata_t;

/* ############################################################################ *
 * internal function
 *
 * realloc which doesn't fail when trying to reallocate NULL pointers
 *
 * returns pointer to (re-)allocate space or NULL on error
 * ############################################################################ */
static void *myrealloc(void *ptr, size_t size)
	{
	if(ptr)
		return realloc(ptr, size);
	else
		return calloc(1,size);
	}

/* ############################################################################ *
 * internal function
 *
 * used for CURLOPT_WRITEFUNCTION
 *
 * returns size of written data in bytes
 * ############################################################################ */
static size_t write_data(void *ptr, size_t size, size_t nmemb, void *data)
	{
	size_t realsize = size * nmemb;
	struct rdata_s *mem = (struct rdata_s *) data;

	mem->memory = myrealloc(mem->memory, mem->size + realsize + 1);
	if (mem->memory)
		{
		memcpy(&(mem->memory[mem->size]), ptr, realsize);
		mem->size += realsize;
		mem->memory[mem->size] = 0;
		}
	return realsize;
	}

/* ################################################################ *
 * internal function
 *
 * In CMP_CTX we have separate variables for server address and path,
 * but libcurl doesn't have a separate function for just setting the
 * path. This function simply checks the end of the effective url to
 * make sure that the correct path is there, and if it's not set yet
 * it will be added.
 *
 * returns 1 on success, 0 on error
 * ################################################################ */
static int set_http_path(CURL *curl, const CMP_CTX *ctx)
	{
	char *url = NULL;
	int bufsize = 0;

	bufsize = strlen(ctx->serverName) + strlen(ctx->serverPath) + 2;
	url = malloc(bufsize);
	if (!url) return 0;

	BIO_snprintf(url, bufsize, "%s/%s", ctx->serverName, ctx->serverPath);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	free(url);

	return 1;
	}


#endif


/*
static uint32_t gethostiplong(const char *host)
	{
	unsigned char ip[4];

	BIO_get_host_ip(host, ip);

	return htonl( (unsigned long)
			((unsigned long)ip[0]<<24L)|
			((unsigned long)ip[1]<<16L)|
			((unsigned long)ip[2]<< 8L)|
			((unsigned long)ip[3]) );
	}
*/

/* ########################################################################## *
 * internal function
 * Create a new http connection, with a specified source ip/interface
 * returns 1 on success, 0 on error, returns the created bio inside the *bio
 * argument
 * ########################################################################## */
static int CMP_new_http_bio( CMPBIO **bio, const CMP_CTX *ctx)
	{
#ifndef HAVE_CURL
	BIO *cbio = NULL;

	if (!ctx) goto err;
	
	if (!ctx->proxyName || !ctx->proxyPort)
		{
		cbio = BIO_new_connect(ctx->serverName);
		if (!cbio) goto err;
		BIO_set_conn_int_port(cbio, &ctx->serverPort);
		}
	else
		{
		cbio = BIO_new_connect(ctx->proxyName);
		if (!cbio) goto err;
		BIO_set_conn_int_port(cbio, &ctx->proxyPort);
		}

	if (ctx->useTLS)
		{
		OpenSSL_add_ssl_algorithms();
		// SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
		SSL_CTX *ctx = SSL_CTX_new(TLSv1_client_method());
		SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
		BIO *sbio = BIO_new_ssl(ctx, 1);
		cbio = BIO_push(sbio, cbio);
		}

	*bio = cbio;
	return 1;

	err:
	return 0;
#else
	struct curl_slist *slist=NULL;
	CURL *curl;
	
	static int curl_initialized = 0;

	if (!ctx) goto err;

	if (curl_initialized == 0)
		{
		curl_initialized =	1;
		curl_global_init(CURL_GLOBAL_ALL);
		}

	if (!(curl=curl_easy_init())) goto err;

	slist = curl_slist_append(slist, "Content-Type: application/pkixcmp");
	slist = curl_slist_append(slist, "Cache-control: no-cache");
	slist = curl_slist_append(slist, "Expect:"); 
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
	if (ctx->sourceAddress != NULL)
		curl_easy_setopt(curl, CURLOPT_INTERFACE, ctx->sourceAddress);

	curl_easy_setopt(curl, CURLOPT_URL, ctx->serverName);
	curl_easy_setopt(curl, CURLOPT_PORT, ctx->serverPort);

	curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);

	if (ctx->proxyName && ctx->proxyPort)
		{
		curl_easy_setopt(curl, CURLOPT_PROXY, ctx->proxyName);
		curl_easy_setopt(curl, CURLOPT_PROXYPORT, ctx->proxyPort);
		curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
		}
	else
		{
		/* curl will automatically try to get proxy from environment if we don't set this.
		 * if proxy use is enabled, it will be set in CMP_PKIMESSAGE_http_perform. */
		curl_easy_setopt(curl, CURLOPT_PROXY, ""); /* TODO: that needs to be explicitly documented */
		}

	*bio = curl;
	return 1;

	err:
	CMPerr(CMP_F_CMP_NEW_HTTP_BIO, CMP_R_CURL_ERROR);
	return 0;
#endif
	}

static int CMP_delete_http_bio( CMPBIO *cbio)
	{
#ifndef HAVE_CURL
	if (cbio) BIO_free_all(cbio);
#else
	if (cbio) curl_easy_cleanup(cbio);
#endif
	return 1;
	}

/* ################################################################ *
 * Send the given PKIMessage msg and place the response in *out.
 * returns 1 on success, 0 on error
 * on success, returns pointer to received PKIMessage in *out
 * ################################################################ */
#ifndef HAVE_CURL

int CMP_PKIMESSAGE_http_perform(const CMP_CTX *ctx, const CMP_PKIMESSAGE *msg, CMP_PKIMESSAGE **out)
	{
	int rv, fd;
	fd_set confds;
	struct timeval tv;
	char *path=0;
	size_t pos=0, pathlen=0;
	CMPBIO *cbio = 0;

	CMP_new_http_bio(&cbio, ctx);

	if (!cbio || !ctx || !msg || !out)
		{
		CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_NULL_ARGUMENT);
		goto err;
		}

	if (!ctx->serverName || !ctx->serverPath || !ctx->serverPort)
		{
		CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_NULL_ARGUMENT);
		goto err;
		}

	if (ctx->HttpTimeOut != 0)
		BIO_set_nbio(cbio, 1);
	
	rv = BIO_do_connect(cbio);
	if (rv <= 0 && (ctx->HttpTimeOut == -1 || !BIO_should_retry(cbio)))
		{
		/* Error connecting */
		CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_SERVER_NOT_REACHABLE);
		goto err;
		}

	if (BIO_get_fd(cbio, &fd) <= 0)
		{
		/* XXX Can't get fd, is this the right error to return? */
		CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_SERVER_NOT_REACHABLE);
		goto err;
		}

	if (ctx->HttpTimeOut != -1 && rv <= 0)
		{
		FD_ZERO(&confds);
		openssl_fdset(fd, &confds);
		tv.tv_usec = 0;
		tv.tv_sec = ctx->HttpTimeOut;
		rv = select(fd + 1, NULL, (void *)&confds, NULL, &tv);
		if (rv == 0)
			{
			// Timed out
			CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_SERVER_NOT_REACHABLE);
			goto err;
			}
		}

	pathlen = strlen(ctx->serverName) + strlen(ctx->serverPath) + 32;
	path = (char*) OPENSSL_malloc(pathlen);
	if (!path) goto err;

	/* Section 5.1.2 of RFC 1945 states that the absoluteURI form is only allowed when using a proxy */
	if (ctx->proxyName && ctx->proxyPort)
		pos = BIO_snprintf(path, pathlen-1, "http://%s:%d", ctx->serverName, ctx->serverPort);
	
	/* make sure path includes a forward slash */
	if (ctx->serverPath[0] != '/') path[pos++] = '/';

	BIO_snprintf(path+pos, pathlen-pos-1, "%s", ctx->serverPath);

	*out = CMP_sendreq_bio(cbio, path, (CMP_PKIMESSAGE*) msg);

	OPENSSL_free(path);
	// BIO_reset(cbio);
	CMP_delete_http_bio(cbio);
	
	if (!*out) {
		CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_FAILED_TO_DECODE_PKIMESSAGE);
		goto err;
	}
	
	return 1;

	err:
	return 0;
	}

#else  /* HAVE_CURL */

int CMP_PKIMESSAGE_http_perform(const CMP_CTX *ctx, const CMP_PKIMESSAGE *msg, CMP_PKIMESSAGE **out)
	{
	unsigned char *derMsg = NULL, *pder = NULL;
	char *content_type = NULL;
	int derLen = 0;
	CURLcode res;
	rdata_t rdata = {0,0};
	CMPBIO *curl = NULL;

	CMP_new_http_bio(&curl, ctx);

	if (!curl || !ctx || !msg || !out)
		{
		CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_NULL_ARGUMENT);
		goto err;
		}

	if (!ctx->serverName || !ctx->serverPath || !ctx->serverPort)
		{
		CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_NULL_ARGUMENT);
		goto err;
		}

	derLen = i2d_CMP_PKIMESSAGE( (CMP_PKIMESSAGE*) msg, &derMsg);

	set_http_path(curl, ctx);

	/* curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0); */

	/* rdata will contain the data received from the server */
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&rdata);

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (void*) derMsg);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, derLen);

	/* set timeout for the entire HTTP operation */
	if (ctx->HttpTimeOut != 0)
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, ctx->HttpTimeOut);

	res = curl_easy_perform(curl);

	/* free up sent DER message from memory */
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (void*) 0);
	free(derMsg);

	if (res != CURLE_OK)
		{
		char num[64];

		if (res == CURLE_COULDNT_CONNECT
			|| res == CURLE_COULDNT_RESOLVE_PROXY
			|| res == CURLE_COULDNT_RESOLVE_HOST
			|| res == CURLE_SEND_ERROR
			|| res == CURLE_RECV_ERROR
			|| res == CURLE_OPERATION_TIMEDOUT
			|| res == CURLE_INTERFACE_FAILED)
			CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_SERVER_NOT_REACHABLE);
		else if (res != CURLE_OK)
			CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_CURL_ERROR);

		BIO_snprintf(num, sizeof(num)-1, "%d:", res);
		ERR_add_error_data(2, num, curl_easy_strerror(res));
		goto err;
		}
	
	/* verify that Content-type is application/pkixcmp */
	curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type);
	if (content_type == NULL || strcmp(content_type, "application/pkixcmp") != 0)
		{
		CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_INVALID_CONTENT_TYPE);
		goto err;
		}

	pder = (unsigned char*) rdata.memory;
	*out = d2i_CMP_PKIMESSAGE( NULL, (const unsigned char**) &pder, rdata.size);
	if (*out == 0)
		{
		CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_FAILED_TO_DECODE_PKIMESSAGE);
		goto err;
		}

	if (CURLE_OK != curl_easy_getinfo((CMPBIO*)curl, CURLINFO_RESPONSE_CODE, &ctx->lastHTTPCode)) goto err;

	CMP_delete_http_bio(curl);

	free(rdata.memory);
	return 1;

	err:
	if (rdata.memory)
		free(rdata.memory);

	if (curl)
		CMP_delete_http_bio(curl);
	return 0;
	}
#endif	/* HAVE_CURL */


/* ################################################################ *
 * Returns the HTTP response code of the last response we got from
 * the server.
 * returns 0 on error
 * ################################################################ */
long CMP_get_http_response_code(const CMP_CTX *ctx)
	{
	if (!ctx) return 0;
	return ctx->lastHTTPCode;
	}
