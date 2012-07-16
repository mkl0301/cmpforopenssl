/* crypto/cmp/cmp_http.c
 * HTTP functions for CMP (RFC 4210) for OpenSSL
 */
/* ====================================================================
 * Originally written by Martin Peylo for the OpenSSL project.
 * <martin dot peylo at nsn dot com>
 * 2010-2012 Miikka Viljanen <mviljane@users.sourceforge.net>
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
 * 6/10/2010 - Martin Peylo - fixed potential harmful sscanf conversion in CMP_PKIMESSAGE_hhtp_bio_recv()
 * 6/20/2011 - Miikka Viljanen - implemented HTTP transport using libcurl
 */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/cmp.h>

#include <ctype.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>


#ifdef HAVE_CURL

typedef struct rdata_s {
	char *memory;
	size_t size;
} rdata_t;

static void *myrealloc(void *ptr, size_t size)
{
	/* There might be a realloc() out there that doesn't like reallocing
	 *      NULL pointers, so we take care of it here */ 
	if(ptr)
		return realloc(ptr, size);
	else
		return calloc(1,size);
}

static size_t write_data(void *ptr, size_t size, size_t nmemb, void *data)
{
	size_t realsize = size * nmemb;
	struct rdata_s *mem = (struct rdata_s *) data;

	mem->memory = myrealloc(mem->memory, mem->size + realsize + 1);
	if (mem->memory) {
		memcpy(&(mem->memory[mem->size]), ptr, realsize);
		mem->size += realsize;
		mem->memory[mem->size] = 0;
	}
	return realsize;
}

/* ################################################################ *
 * In CMP_CTX we have separate variables for server address and path,
 * but libcurl doesn't have a separate function for just setting the
 * path. This function simply checks the end of the effective url to
 * make sure that the correct path is there, and if it's not set yet
 * it will be added.
 * ################################################################ */
static int set_http_path(CURL *curl, const char *path) {
	char *current_url = NULL, *url = NULL;
	int pathlen = strlen(path), current_len;

	curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &current_url);
	if (!current_url)
		return 0;

	current_len = strlen(current_url);
	if (!strcmp(&current_url[current_len - pathlen], path))
		/* path is already set, let's not do it again... */
		return 1;

	if( !(url = malloc(strlen(current_url) + strlen(path) + 2)))
		return 0;

	sprintf(url, "%s/%s", current_url, path);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	free(url);

	return 1;
}

/* ################################################################ *
 * Create a new http connection, with a specified source ip/interface
 * ################################################################ */
int CMP_new_http_bio_ex( CMPBIO **bio, const char* serverAddress, const int port, const char *srcip) {
	struct curl_slist *slist=NULL;
	CURL *curl;
	
	static int curl_initialized = 0;
	if (curl_initialized == 0) {
		curl_initialized =  1;
		curl_global_init(CURL_GLOBAL_ALL);
	}

	if (!(curl=curl_easy_init())) goto err;

	slist = curl_slist_append(slist, "Content-Type: application/pkixcmp");
	slist = curl_slist_append(slist, "Cache-control: no-cache");
	slist = curl_slist_append(slist, "Expect:"); 
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
	if (srcip != NULL)
		curl_easy_setopt(curl, CURLOPT_INTERFACE, srcip);

	curl_easy_setopt(curl, CURLOPT_URL, serverAddress);
	curl_easy_setopt(curl, CURLOPT_PORT, port);

	curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);

	/* curl will automatically try to get proxy from environment if we don't set this.
	 * if proxy use is enabled, it will be set in CMP_PKIMESSAGE_http_perform. */
	/* XXX what's the correct thing to do, should we take proxy from env or not? */
	curl_easy_setopt(curl, CURLOPT_PROXY, "");

	*bio = curl;
	return 1;

err:
	CMPerr(CMP_F_CMP_NEW_HTTP_BIO_EX, CMP_R_CURL_ERROR);
	return 0;
}

int CMP_new_http_bio( CMPBIO **cbio, const char* serverName, const int port) {
	return CMP_new_http_bio_ex(cbio, serverName, port, NULL);
}

int CMP_delete_http_bio( CMPBIO *cbio) {
	curl_easy_cleanup(cbio);
	return 1;
}

/* ################################################################ *
 * Send the given PKIMessage msg and place the response in *out.
 * ################################################################ */
int CMP_PKIMESSAGE_http_perform(CMPBIO *curl, const CMP_CTX *ctx, 
								const CMP_PKIMESSAGE *msg,
								CMP_PKIMESSAGE **out)
{
	unsigned char *derMsg = NULL, *pder = NULL;
	char *errormsg = NULL;
	char *content_type = NULL;
	int derLen = 0;
	CURLcode res;
	rdata_t rdata = {0,0};

	if (!curl || !ctx || !msg || !out) {
		CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_NULL_ARGUMENT);
		return 0;
	}

	if (!ctx->serverName || !ctx->serverPath || ctx->serverPort == 0) {
		CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_NULL_ARGUMENT);
		return 0;
	}

	derLen = i2d_CMP_PKIMESSAGE( (CMP_PKIMESSAGE*) msg, &derMsg);

	if (ctx->proxyName && ctx->proxyPort) {
		curl_easy_setopt(curl, CURLOPT_PROXY, ctx->proxyName);
		curl_easy_setopt(curl, CURLOPT_PROXYPORT, ctx->proxyPort);
	}

	set_http_path(curl, ctx->serverPath);

	/* curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0); */

	/* rdata will contain the data received from the server */
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&rdata);

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (void*) derMsg);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, derLen);
	if (ctx->timeOut != 0)
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, ctx->timeOut);

	res = curl_easy_perform(curl);

	/* free up sent DER message from memory */
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (void*) 0);
	free(derMsg);

	if (   res == CURLE_COULDNT_CONNECT
		|| res == CURLE_COULDNT_RESOLVE_PROXY
		|| res == CURLE_COULDNT_RESOLVE_HOST
		|| res == CURLE_SEND_ERROR
		|| res == CURLE_RECV_ERROR
		|| res == CURLE_OPERATION_TIMEDOUT
		|| res == CURLE_INTERFACE_FAILED)
    {
        CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_SERVER_NOT_REACHABLE);
        char num[64];
        snprintf(num, sizeof(num)-1, "%d:", res);
        ERR_add_error_data(2, num, curl_easy_strerror(res));
        return 0;
    }
	else if (res != CURLE_OK) {
		CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_CURL_ERROR);
        char num[64];
        snprintf(num, sizeof(num)-1, "%d:", res);
        ERR_add_error_data(2, num, curl_easy_strerror(res));
		return 0;
	}

	/* verify that Content-type is application/pkixcmp */
	curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type);
	if (content_type == NULL || strcmp(content_type, "application/pkixcmp") != 0) {
		CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_INVALID_CONTENT_TYPE);
		free(errormsg);
		free(rdata.memory);
		return 0;
	}

	pder = (unsigned char*) rdata.memory;
    *out = d2i_CMP_PKIMESSAGE( NULL, (const unsigned char**) &pder, rdata.size);
    if (*out == 0) {
		CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_FAILED_TO_DECODE_PKIMESSAGE);
		free(rdata.memory);
		return 0;
	}

	free(rdata.memory);
	return 1;
}

int CMP_PKIMESSAGE_http_bio_send(CMPBIO *cbio, CMP_CTX *ctx,
								 const CMP_PKIMESSAGE *msg) {
	CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_BIO_SEND, CMP_R_DEPRECATED_FUNCTION);
	return 0;
}

int CMP_PKIMESSAGE_http_bio_recv( CMPBIO *cbio, CMP_CTX *ctx,
				  CMP_PKIMESSAGE **ip) {
	CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_BIO_RECV, CMP_R_DEPRECATED_FUNCTION);
	return 0;
}

#endif

