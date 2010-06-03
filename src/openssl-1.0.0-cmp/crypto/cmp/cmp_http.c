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
 */

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/cmp.h>

/* ############################################################################ */
/* returns 1 on success, 0 on failure */
/* @serverName holds a sting like "my.server.com" or "1.2.3.4" */
/* ############################################################################ */
int CMP_new_http_bio(BIO **cbio, const char* serverName, const int port) {
	*cbio = BIO_new(BIO_s_connect());
	BIO_set_conn_hostname(*cbio, serverName);
	BIO_set_conn_int_port(*cbio, &port);
	/* set nonblocking - XXX should this really be done? */
	/* BIO_setn_nbio(*cbio,1); */
	return BIO_do_connect(*cbio);
}

/* ############################################################################ */
int CMP_PKIMESSAGE_http_bio_send(BIO *cbio,
				 const char *serverName,
				 const int   serverPort,
				 const char *serverPath,
				 const int   compatibility,
				 const CMP_PKIMESSAGE *msg)
{
	int derLen;
	unsigned int derLenUint;
	size_t derLenUintSize;
	unsigned char instaHeader[7] ;

	/* for receiving the INSTA continue message... */
	size_t recvLen=0;
	char recvBuf[101];
	int respCode;

	char http_hdr[] =
		"POST http://%s:%d/%s HTTP/1.1\r\n" /* TODO: check HTTP standard if that's right */
		"Host: %s:%d\r\n"
		"Content-type: application/pkixcmp\r\n"
		"Content-Length: %d\r\n"
		"Connection: Keep-Alive\r\n" /* this is actually HTTP 1.0 but might be necessary for proxies */
		"Cache-Control: no-cache\r\n\r\n";

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

	if (!cbio)
		return 0;

	derLen = i2d_CMP_PKIMESSAGE( (CMP_PKIMESSAGE*) msg, NULL);

	/* Insta < 3.3 prepends the TCP header to the CMP message (Content-Type: pkixcmp-poll) */
	if (compatibility == CMP_COMPAT_INSTA) {
		/* this will be used for the msg length in TCP style transport */
		derLenUint = (unsigned int) derLen + 3; /* +3 are the following 3 octets */
		/* this will be used for the HTTP Content-Length */
		derLen += 7;
	}

	/* print HTTP header */
	if( compatibility != CMP_COMPAT_INSTA) {
		if (BIO_printf(cbio, http_hdr, serverName, serverPort, serverPath, serverName, serverPort, derLen) <= 0)
			return 0;
	} else {
		/* XXX INSTA 3.2.1 likes it like this */
		if (BIO_printf(cbio, insta_http_hdr, serverPath, serverName, serverPort, derLen) <= 0)
			return 0;
		if (BIO_flush(cbio) <= 0)
			return 0;
		while( recvLen < 20) {
// #warning this will fail in many cases...
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

	i2d_CMP_PKIMESSAGE_bio(cbio, msg);

	if (BIO_flush(cbio) <= 0)
		return 0;
	return 1;
}

// #warning RECEIVING HTTP MESSGES SHOULD BE IMPROVED!
/* ############################################################################ */
/* for sure this could be done better */
/* ############################################################################ */
int CMP_PKIMESSAGE_http_bio_recv( BIO *cbio,
				  CMP_PKIMESSAGE **ip,
				  const int compatibility
				  ) {
#define MAX_RECV_BYTE 10240
	char tmpbuf[1024];
	/* XXX this is not nice */
	char recvMsg[MAX_RECV_BYTE];
	char *recvPtr=NULL;
	int hits=0;
	int chunkedHTTP=0;

	int retID;
	char retSTR[10];
	char *contLenBeg=NULL;
	const unsigned char *derMessage=NULL;

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
	hits = sscanf(recvMsg, "HTTP/1.1%d%s\r\n", &retID, retSTR);
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
		hits = sscanf(contLenBeg, "Content-Length:%d\r\n", &contentLen);
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
		hits = sscanf((char *)derMessage, "%x", &chunkLen); /* the hex could be followed by a ; and other stuff */
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

	/* skip TCP-Style INSTA < 3.3 header */
	if( compatibility == CMP_COMPAT_INSTA) {
		derMessage += 7;
	}

printf("totalRecvdLen %d, totalMsgLen %d, chunkLen %d\n", totalRecvdLen, totalMsgLen, chunkLen);
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

	/* transform DER message to OPENSSL internal format */
	if( (*ip = d2i_CMP_PKIMESSAGE( NULL, &derMessage, contentLen))) {
		return 1;
	} else {
		fprintf( stderr, "ERROR: decoding DER encoded message. FILE: %s, LINE %d\n", __FILE__, __LINE__);
		return 0;
	}
}

