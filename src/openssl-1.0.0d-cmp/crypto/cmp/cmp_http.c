/* crypto/cmp/cmp_http.c
 * HTTP functions for CMP (RFC 4210) for OpenSSL
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

static int get_server_port(CURL *curl) {
	char *addr = NULL, *p;
	int i, ret = 0;
	curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &addr);

	addr = strdup(addr);


	/* find port number */
	for (p = addr; *p != 0 && !(*p==':'&&p[1]!='/'); p++)
		;
	p++;
	/* skip path if there is any */
	for (i=0; isdigit(p[i]); i++)
		;
	p[i] = 0;

	if (*p) ret = atoi(p);
	return ret;
}

static char *get_server_addr(CURL *curl) {
	char *addr = NULL, *p, tmp[8];
	int i;
	curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &addr);

	addr = strdup(addr);

	/* skip the http:// part if it's there, 
	 * curl will put it back on its own... */

	for (i = 0; i <= 7; i++)
		tmp[i] = tolower(addr[i]);
	tmp[7] = 0;
	if (!strcmp(tmp, "http://")) 
		addr += 7;

	/* cut off the url starting from port or path,
	 * so we only get the server name */
	for (p = addr; *p != 0; p++)
		if (*p == ':' || *p == '/') {
			*p = 0;
			break;
		}

	return addr;
}

static void set_http_path(CURL *curl, const char *path) {
	char *current_url = NULL, *url = NULL;

	current_url = get_server_addr(curl);
	url = malloc(strlen(current_url) + strlen(path) + 2);
	sprintf(url, "%s/%s", current_url, path);
	curl_easy_setopt(curl, CURLOPT_URL, url);

	// free(current_url);
	free(url);
}

int CMP_new_http_bio_ex( CMPBIO **bio, const char* serverAddress, const int port, const char *srcip) {
	struct curl_slist *slist=NULL;
	CURL *curl;
	char *url;
	
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

	url = malloc(strlen(serverAddress) + 7);
	sprintf(url, "%s:%d", serverAddress, port);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	free(url);

	curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP);
	curl_easy_setopt(curl, CURLOPT_PORT, port);

	/* if proxy is used, it will be set in CMP_PKIMESSAGE_http_perform. */
	curl_easy_setopt(curl, CURLOPT_PROXY, "");

	*bio = curl;
	return 1;

err:
	return 0;
}

int CMP_new_http_bio( CMPBIO **cbio, const char* serverName, const int port) {
	return CMP_new_http_bio_ex(cbio, serverName, port, NULL);
}

int CMP_delete_http_bio( CMPBIO *cbio) {
	curl_easy_cleanup(cbio);
	return 1;
}

int CMP_PKIMESSAGE_http_perform(CMPBIO *curl, const CMP_CTX *ctx, 
								const CMP_PKIMESSAGE *msg,
								CMP_PKIMESSAGE **out)
{
	unsigned char *derMsg = NULL, *pder = NULL;
	char *srv = NULL, *errormsg = NULL;
	int derLen = 0;
	CURLcode res;
	rdata_t rdata = {0,0};

	if (!curl || !ctx || !msg || !out)
		goto err;

	if (!ctx->serverName || !ctx->serverPath || ctx->serverPort == 0)
		goto err;

	derLen = i2d_CMP_PKIMESSAGE( (CMP_PKIMESSAGE*) msg, &derMsg);

	/* check if we are using a proxy. */
	srv = get_server_addr(curl);
	if (strcmp(srv, ctx->serverName) != 0) {
		/* XXX: this is done in this way only because we want to remain
		 * compatible with the old HTTP code. when that is removed, this code
		 * should be moved to the init function*/

		long proxyPort = get_server_port(curl);
		// curl_easy_getinfo(curl, CURLINFO_PRIMARY_PORT, &proxyPort);
		curl_easy_setopt(curl, CURLOPT_PROXY, srv);
		curl_easy_setopt(curl, CURLOPT_PROXYPORT, proxyPort);

		curl_easy_setopt(curl, CURLOPT_PORT, ctx->serverPort);
		curl_easy_setopt(curl, CURLOPT_URL, ctx->serverName);
	}
	// free(srv);

	set_http_path(curl, ctx->serverPath);

	// curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&rdata);

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (void*) derMsg);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, derLen);
	if (ctx->timeOut != 0)
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, ctx->timeOut);

	errormsg = calloc(1, CURL_ERROR_SIZE);
	res = curl_easy_perform(curl);
	if (res == 0) {
		free(errormsg);
		errormsg = 0;
	}
	else goto err;

	pder = (unsigned char*) rdata.memory;
    *out = d2i_CMP_PKIMESSAGE( NULL, (const unsigned char**) &pder, rdata.size);
    if (*out == 0) {
		errormsg = "Failed to decode PKIMESSAGE";
		goto err;
	}

	free(rdata.memory);
    free(derMsg);
	return 1;

err:
	CMPerr(CMP_F_CMP_PKIMESSAGE_HTTP_PERFORM, CMP_R_CURL_ERROR);
	if (errormsg) {
		ERR_add_error_data(3, "Error: \"", errormsg, "\"");
		free(errormsg);
	}
	return 0;
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

#else

static uint32_t gethostiplong(const char *host) {
	unsigned char ip[4];

	BIO_get_host_ip(host, ip);

	return htonl( (unsigned long)
			((unsigned long)ip[0]<<24L)|
			((unsigned long)ip[1]<<16L)|
			((unsigned long)ip[2]<< 8L)|
			((unsigned long)ip[3]) );
}

int CMP_new_http_bio_ex(CMPBIO **bio, const char* serverName, const int port, const char *srcip) {
	struct sockaddr_in svaddr;
	int sockfd;
	BIO *cbio;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		goto err;

	if (srcip != NULL) {
		struct sockaddr_in claddr;

		memset(&claddr, 0, sizeof(claddr));
		claddr.sin_family = AF_INET; 
		claddr.sin_port = htons(0);
		claddr.sin_addr.s_addr = gethostiplong(srcip);

		if (bind(sockfd, (struct sockaddr *) &claddr, sizeof(claddr)) < 0)
			goto err;
	}

	memset(&svaddr, 0, sizeof(svaddr));
	svaddr.sin_family = AF_INET;
	svaddr.sin_port = htons((unsigned short)port);
	svaddr.sin_addr.s_addr = gethostiplong(serverName);

	if (connect(sockfd, (struct sockaddr *) &svaddr, sizeof(svaddr)) < 0)
		goto err;

	if (!(cbio = BIO_new_socket(sockfd, 1)))
		goto err;

	*bio = cbio;
	return 1;

  err:
    if (sockfd >= 0)
        close(sockfd);
	return 0;
}

/* ############################################################################ */
/* returns 1 on success, 0 on failure */
/* @serverName holds a sting like "my.server.com" or "1.2.3.4" */
/* ############################################################################ */
int CMP_new_http_bio(CMPBIO **cbio, const char* serverName, const int port) {
	return CMP_new_http_bio_ex(cbio, serverName, port, NULL);
}

/* ############################################################################ */
int CMP_delete_http_bio( CMPBIO *cbio) {
	BIO_free( cbio);
	return 1;
}

/* ############################################################################ */
static int CMP_PKIMESSAGE_http_bio_send(CMPBIO *cbio, const CMP_CTX *ctx, const CMP_PKIMESSAGE *msg)
{
	int derLen;

	const char *serverName = ctx->serverName,
		  *serverPath = ctx->serverPath;
	const int serverPort = ctx->serverPort;

#ifdef SUPPORT_OLD_INSTA
	const int compatibility = ctx->compatibility;
	unsigned int derLenUint;
	size_t derLenUintSize;
	unsigned char instaHeader[7] ;

	/* for receiving the INSTA continue message... */
	size_t recvLen=0;
	char recvBuf[101];
	int respCode;
#endif

	char http_hdr[] =
		"POST http://%s:%d/%s HTTP/1.1\r\n" /* TODO: check HTTP standard if that's right */
		"Host: %s:%d\r\n"
		"Content-type: application/pkixcmp\r\n"
		"Content-Length: %d\r\n"
		"Connection: Keep-Alive\r\n" /* this is actually HTTP 1.0 but might be necessary for proxies */
		"Cache-Control: no-cache\r\n\r\n";

#ifdef SUPPORT_OLD_INSTA
	char insta_http_hdr[] =
		/* "POST http://%s:%d/%s HTTP/1.1\r\n" */
		"POST /%s HTTP/1.1\r\n" /* XXX INSTA 3.2.1 likes it like this XXX */
		"Host: %s:%d\r\n"
		/* "Content-type: application/pkixcmp\r\n" */
		"Content-type: application/pkixcmp-poll\r\n" /* XXX This is not necessary... but INSTA's client does it XXX */
		"Content-Length: %d\r\n"
		"Connection: Keep-Alive\r\n" /* this is actually HTTP 1.0 but might be necessary for proxies */
		"Cache-Control: no-cache\r\n"
		"Expect: 100-continue\r\n\r\n"; /* XXX don't understand why they do that */
#endif

	if (!cbio)
		return 0;

	derLen = i2d_CMP_PKIMESSAGE( (CMP_PKIMESSAGE*) msg, NULL);

#ifdef SUPPORT_OLD_INSTA /* TODO remove completely one day */
	/* Insta < 3.3 prepends the TCP header to the CMP message (Content-Type: pkixcmp-poll) */
	if (compatibility == CMP_COMPAT_INSTA) {
		/* this will be used for the msg length in TCP style transport */
		derLenUint = (unsigned int) derLen + 3; /* +3 are the following 3 octets */
		/* this will be used for the HTTP Content-Length */
		derLen += 7;
	}
#endif /* SUPPORT_OLD_INSTA */

	/* print HTTP header */
#ifdef SUPPORT_OLD_INSTA /* TODO remove completely one day */
	if( compatibility != CMP_COMPAT_INSTA) {
#endif /* SUPPORT_OLD_INSTA */
		if (BIO_printf(cbio, http_hdr, serverName, serverPort, serverPath, serverName, serverPort, derLen) <= 0)
			return 0;
#ifdef SUPPORT_OLD_INSTA /* TODO remove completely one day */
	} else {
		/* XXX INSTA 3.2.1 likes it like this */
		if (BIO_printf(cbio, insta_http_hdr, serverPath, serverName, serverPort, derLen) <= 0)
			return 0;
		if (BIO_flush(cbio) <= 0)
			return 0;
		while( recvLen < 20) {
// WARNING: this will fail in many cases...
			recvLen = BIO_read(cbio, recvBuf, 100); /* 100 should be enough */
		}
		if( sscanf(recvBuf, "HTTP/1.1 %d Continue", &respCode) < 1) {
			fprintf( stderr, "ERROR: Did not receive HTTP/1.1 Continue message. FILE %s, LINE %d\n", __FILE__, __LINE__);
			return -1;
		}
		if( respCode != 100) {
			fprintf( stderr, "ERROR: \"Response Code\" != 100. FILE %s, LINE %d\n", __FILE__, __LINE__);
			return -1;
		}
	}
#endif /* SUPPORT_OLD_INSTA */

#ifdef SUPPORT_OLD_INSTA /* TODO remove completely one day */
	/* Insta < 3.3 prepends the TCP header to the CMP message (Content-Type: pkixcmp-poll) */
	if (compatibility == CMP_COMPAT_INSTA) {
		derLenUintSize = sizeof(derLenUint);
#ifdef L_ENDIAN
		if(derLenUint >= 4)
			instaHeader[0] = (unsigned char) (derLenUint>>(3*8)) & 0xff;
		else
			instaHeader[0] = 0x0;
		if(derLenUint >= 3)
			instaHeader[1] = (unsigned char) (derLenUint>>(2*8)) & 0xff;
		else
			instaHeader[1] = 0x0;
		if(derLenUint >= 2)
			instaHeader[2] = (unsigned char) (derLenUint>>(1*8)) & 0xff;
		else
			instaHeader[2] = 0x0;
		/* it should be at least one byte... */
		instaHeader[3] = (unsigned char) (derLenUint>>(0*8)) & 0xff;
#elif defined B_ENDIAN
		if(derLenUint >= 4)
			instaHeader[0] = (unsigned char) (derLenUint>>(0*8)) & 0xff;
		else
			instaHeader[0] = 0x0;
		if(derLenUint >= 3)
			instaHeader[1] = (unsigned char) (derLenUint>>(1*8)) & 0xff;
		else
			instaHeader[1] = 0x0;
		if(derLenUint >= 2)
			instaHeader[2] = (unsigned char) (derLenUint>>(2*8)) & 0xff;
		else
			instaHeader[2] = 0x0;
		/* it should be at least one byte... */
		instaHeader[3] = (unsigned char) (derLenUint>>(3*8)) & 0xff;
#else
#error Endianess is not defined
#endif /* endianess */
		instaHeader[4] = 0x0a;
		instaHeader[5] = 0x01;
		instaHeader[6] = 0x0; /* XXX this is only for IR so far XXX */

		if (BIO_write(cbio, instaHeader, 7) != 7)
			return 0;
	}
#endif /* SUPPORT_OLD_INSTA */

	i2d_CMP_PKIMESSAGE_bio(cbio, msg);

	if (BIO_flush(cbio) <= 0)
		return 0;
	return 1;
}

// TODO RECEIVING HTTP MESSGES SHOULD BE IMPROVED!
/* ############################################################################ */
/* for sure this could be done better */
/* ############################################################################ */
int CMP_PKIMESSAGE_http_bio_recv( CMPBIO *cbio,
				  const CMP_CTX *ctx,
				  CMP_PKIMESSAGE **ip) {
#define MAX_RECV_BYTE 10240
	char tmpbuf[1024];
	/* XXX this is not nice */
	char recvMsg[MAX_RECV_BYTE];
	char *recvPtr=NULL;
	int hits=0;
	int chunkedHTTP=0;

	int retID;
	char retSTR[256];
	char *contLenBeg=NULL;
	const unsigned char *derMessage=NULL;

  /* TODO: it must be checked if size_t is good for the format conversions in
   * sscanf() etc - is that unsigned long everywhere? */
	size_t recvLen=0;
	size_t totalMsgLen=0;
	size_t contentLen=0;
	size_t totalRecvdLen=0;
	size_t chunkLen=0;

	recvPtr = recvMsg;
	/* receive at least the http header */
	for(;;) {
		recvLen = BIO_read(cbio, tmpbuf, 1024);
		if(recvLen <= 0) {
			fprintf( stderr, "ERROR: receiving message. FILE %s, LINE %d\n", __FILE__, __LINE__);
			return 0;
		}
		if( (totalRecvdLen+recvLen) > MAX_RECV_BYTE) {
			fprintf( stderr, "ERROR: message received is bigger than %d Bytes. FILE %s, LINE %d\n", MAX_RECV_BYTE, __FILE__, __LINE__);
			return 0;
		}

		totalRecvdLen += recvLen;
		memcpy(recvPtr, tmpbuf, recvLen);
		recvPtr += recvLen;
		/* does it start with HTTP? */
		if( recvLen < 4) continue;
		if( strncmp( recvMsg, "HTTP", 4)) {
			/* it does not start with HTTP */
			fprintf( stderr, "ERROR: message received is not a HTTP message. FILE %s, LINE %d\n", __FILE__, __LINE__);
			return 0;
		}
		/* is the HTTP header complete? */
		if( (derMessage = (unsigned char*) strstr(recvMsg, "\r\n\r\n"))) break;
	}
	/* remember the end of the HTTP header */
	derMessage += 4;

	/* analyze HTTP header */
	/* XXX: yes, I know this is extremely unsafe... */
	hits = sscanf(recvMsg, "HTTP/1.1%d%255s\r\n", &retID, retSTR);
	if( hits != 2) {
		fprintf( stderr, "ERROR: received malformed message. FILE: %s, LINE %d\n", __FILE__, __LINE__);
		return 0;
	}
	if( retID != 200)  {
		fprintf( stderr, "ERROR: message received has ERROR: code %d. FILE: %s, LINE: %d\n", retID, __FILE__, __LINE__);
		return 0;
	}

	/* determine the Content-Length */
	contLenBeg = strstr(recvMsg, "Content-Length:");
	if( contLenBeg)
		hits = sscanf(contLenBeg, "Content-Length:%lu\r\n", (long unsigned int*) &contentLen);
	if( hits != 1) {
		/* is it a chunked HTTP message as INSTA sends them? */
		if( strstr(recvMsg, "Transfer-Encoding: chunked\r\n")) {
			chunkedHTTP = 1;
		} else {
			fprintf( stderr, "ERROR: received malformed HTTP message. Could not determine Content-Length. FILE: %s, LINE %d\n", __FILE__, __LINE__);
			return 0;
		}
	}

	/* determine chunkLen if chunked */
	if( chunkedHTTP) {
		/* TODO: make sure we received the whole header of the chunk */
		/* the first hex shall be the lenght of the chunk */
		hits = sscanf((char *)derMessage, "%lx", (long unsigned int*) &chunkLen); /* the hex could be followed by a ; and other stuff */
		/* jump to the beginning of the DER message inside the chunk */
		derMessage = (unsigned char *) strstr((char*)derMessage, "\r\n")+2;
		/* TODO: handle if there is more than one chunk */
		/* "7" is actually the minimum extra length of the "chunked" footer... */
		totalMsgLen = (derMessage - (unsigned char*) recvMsg) + chunkLen + 7;
		contentLen = chunkLen;
	} else {
		/* determine the HeaderLength */
		totalMsgLen = (derMessage - (unsigned char*) recvMsg) + contentLen;
	}

#ifdef SUPPORT_OLD_INSTA /* TODO remove completely one day */
	/* skip TCP-Style INSTA < 3.3 header */
	if( ctx->compatibility == CMP_COMPAT_INSTA) {
		derMessage += 7;
	}
#endif /* SUPPORT_OLD_INSTA */

CMP_printf(ctx, "totalRecvdLen %lu, totalMsgLen %lu, chunkLen %lu\n", (long unsigned int)totalRecvdLen, (long unsigned int)totalMsgLen, (long unsigned int)chunkLen);
	/* if not already done, receive the rest of the message */
	while( totalRecvdLen < totalMsgLen) {
		/* TODO: make sure we don't receive too much */
		recvLen = BIO_read(cbio, tmpbuf, 1024);
		if(recvLen <= 0) {
			fprintf( stderr, "ERROR: receiving message. FILE %s, LINE %d\n", __FILE__, __LINE__);
			return 0;
		}
		if( (totalRecvdLen+recvLen) > MAX_RECV_BYTE) {
			fprintf( stderr, "ERROR: message received is bigger than %d Bytes. FILE %s, LINE %d\n", MAX_RECV_BYTE, __FILE__, __LINE__);
			return 0;
		}
		totalRecvdLen += recvLen;
		memcpy(recvPtr, tmpbuf, recvLen);
		recvPtr += recvLen;
	}

	/* TODO XXX - make sure we received the whole message */

	CMP_printf(ctx,  "INFO: received contentLen = %lu\n", contentLen);
	/* transform DER message to OPENSSL internal format */
	if( (*ip = d2i_CMP_PKIMESSAGE( NULL, &derMessage, contentLen))) {
		return 1;
	} else {
		fprintf( stderr, "ERROR: decoding DER encoded message. FILE: %s, LINE %d\n", __FILE__, __LINE__);
		return 0;
	}
}

/* ############################################################################ */
int CMP_PKIMESSAGE_http_perform(CMPBIO *cbio, const CMP_CTX *ctx, 
								const CMP_PKIMESSAGE *msg,
								CMP_PKIMESSAGE **out)
{
	if (! CMP_PKIMESSAGE_http_bio_send(cbio, ctx, msg))
		goto err;

	CMP_PKIMESSAGE *resp = NULL;
	if (! CMP_PKIMESSAGE_http_bio_recv(cbio, ctx, &resp))
		goto err;

	*out = resp;
	return 1;
err:
	return 0;
}



#endif

