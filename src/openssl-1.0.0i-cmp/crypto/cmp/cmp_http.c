/* vim: set noet ts=4 sts=4 sw=4: */
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
 * Copyright 2007-2012 Nokia Siemens Networks Oy. ALL RIGHTS RESERVED.
 * CMP support in OpenSSL originally developed by 
 * Nokia Siemens Networks for contribution to the OpenSSL project.
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
	if (mem->memory) {
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
 * TODO: check if that can be rewritten to be nicer
 * DEPRECATED: only for legacy TODO remove
 *
 * returns 1 on success, 0 on error
 * ################################################################ */
static int set_http_path(CURL *curl, const char *path) {
	char *current_url = NULL, *url = NULL;
	int pathlen = 0, current_len = 0;

	curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &current_url);
	if (!current_url || !path)
		return 0;

	pathlen = strlen(path);
	current_len = strlen(current_url);
	if (!strcmp(&current_url[current_len - pathlen], path))
		/* path is already set, let's not do it again... */
		return 1;

	url = malloc(strlen(current_url) + strlen(path) + 2);
	if (!url) return 0;

	sprintf(url, "%s/%s", current_url, path);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	free(url);

	return 1;
}

/* ########################################################################## *
 * Create a new http connection, with a specified source ip/interface
 * returns 1 on success, 0 on error, returns the created bio inside the *bio
 * argument
 * TODO: srcip --> ctx
 * TODO: new function with arguments (bio, ctx)
 * TODO: mark existing functions as DEPRECATED and add "TODO: remove to break
 * backwards compatiblity"
 * ########################################################################## */
int CMP_new_http_bio_ex( CMPBIO **bio, const char* serverAddress, const int port, const char *srcip) {
	struct curl_slist *slist=NULL;
	CURL *curl;
	
	static int curl_initialized = 0;
	if (curl_initialized == 0) {
		curl_initialized =	1;
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
	curl_easy_setopt(curl, CURLOPT_PROXY, ""); /* TODO: that needs to be explicitly documented */

	*bio = curl;
	return 1;

err:
	CMPerr(CMP_F_CMP_NEW_HTTP_BIO_EX, CMP_R_CURL_ERROR);
	return 0;
}

/* ################################################################ *
 * DEPRECATED: only for legacy TODO remove
 * ################################################################ */
int CMP_new_http_bio( CMPBIO **cbio, const char* serverName, const int port) {
	return CMP_new_http_bio_ex(cbio, serverName, port, NULL);
}

/* ################################################################ *
 * DEPRECATED: only for legacy TODO remove
 * ################################################################ */
int CMP_delete_http_bio( CMPBIO *cbio) {
	curl_easy_cleanup(cbio);
	return 1;
}

/* ################################################################ *
 * Send the given PKIMessage msg and place the response in *out.
 * returns 1 on success, 0 on error
 * on success, returns pointer to received PKIMessage in *out
 * TODO: add some comments
 * TODO: set 
 * ################################################################ */
int CMP_PKIMESSAGE_http_perform(CMPBIO *curl, const CMP_CTX *ctx, 
								const CMP_PKIMESSAGE *msg,
								CMP_PKIMESSAGE **out)
{
	unsigned char *derMsg = NULL, *pder = NULL;
	char *content_type = NULL;
	int derLen = 0;
	CURLcode res;
	rdata_t rdata = {0,0};

	if (!curl || !ctx || !msg || !out) {
		CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_NULL_ARGUMENT);
		goto err;
	}

	if (!ctx->serverName || !ctx->serverPath || ctx->serverPort == 0) {
		CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_NULL_ARGUMENT);
		goto err;
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

	/* set timeout for the entire HTTP operation */
	if (ctx->HttpTimeOut != 0)
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, ctx->HttpTimeOut);

	res = curl_easy_perform(curl);

	/* free up sent DER message from memory */
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (void*) 0);
	free(derMsg);

	if (res != CURLE_OK) {
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

		snprintf(num, sizeof(num)-1, "%d:", res);
		ERR_add_error_data(2, num, curl_easy_strerror(res));
		goto err;
	}
	
	/* verify that Content-type is application/pkixcmp */
	curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type);
	if (content_type == NULL || strcmp(content_type, "application/pkixcmp") != 0) {
		CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_INVALID_CONTENT_TYPE);
		goto err;
	}

	pder = (unsigned char*) rdata.memory;
	*out = d2i_CMP_PKIMESSAGE( NULL, (const unsigned char**) &pder, rdata.size);
	if (*out == 0) {
		CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_FAILED_TO_DECODE_PKIMESSAGE);
		goto err;
	}

	free(rdata.memory);
	return 1;

err:
	if (rdata.memory)
		free(rdata.memory);
	return 0;
}

/* ################################################################ *
 * Returns the HTTP response code of the last response we got from
 * the server.
 * returns 0 on error
 * ################################################################ */
long CMP_get_http_response_code(const CMPBIO *bio) {
	long code = 0;

	if (!bio) goto err;
	if (CURLE_OK != curl_easy_getinfo((CMPBIO*)bio, CURLINFO_RESPONSE_CODE, &code)) goto err;
	return code;
err:
	return 0;
}

#endif

