/* crypto/cmp/cmp_http.c
 *
 * HTTP functions for CMP (RFC 4210) for OpenSSL
 *
 * Written by Martin Peylo <martin.peylo@nsn.com>
 */

/*
 * The following license applies to this file:
 *
 * Copyright (c) 2007, Nokia Siemens Networks (NSN)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of NSN nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY NSN ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL NSN BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * The following licenses apply to OpenSSL:
 *
 * OpenSSL License
 * ---------------
 *
 * ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
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
 * ====================================================================
 *
 * Original SSLeay License
 * -----------------------
 *
 * Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
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

	char http_hdr[] =
		"POST http://%s:%d/%s HTTP/1.1\r\n"
		/* "POST /%s HTTP/1.1\r\n" */ /* XXX INSTA TEST XXX */
		"Host: %s:%d\r\n"
		"Content-type: application/pkixcmp\r\n"
		/* "Content-type: application/pkixcmp-poll\r\n" */ /* XXX INSTA TEST XXX */
		"Content-Length: %d\r\n"
		"Connection: Keep-Alive\r\n" /* this is actually HTTP 1.0 but might be necessary for proxies */
		"Cache-Control: no-cache\r\n\r\n";

	if (!cbio)
		return 0;

	derLen = i2d_CMP_PKIMESSAGE( (CMP_PKIMESSAGE*) msg, NULL);

	/* Insta prepends a proprietary header before the CMP msg */
	if (compatibility == CMP_COMPAT_INSTA) {
		/* this will be used for the msg length in the proprietary header */
		derLenUint = (unsigned int) derLen + 3; /* +3 are the following 3 octets */
		/* this will be used for the HTTP Content-Length */
		derLen += 7;
	}

	/* print HTTP header */
	BIO_printf(cbio, http_hdr, serverName, serverPort, serverPath, serverName, serverPort, derLen);
	/* BIO_printf(cbio, http_hdr, serverPath, serverName, serverPort, derLen); */ /* XXX INSTA TEST */

	/* Insta prepends a proprietary header before the CMP msg */
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
#error No code for Big endian available so far
#else
#error Endianess is not defined
#endif /* endianess */
		instaHeader[4] = 0x0a;
		instaHeader[5] = 0x01;
		instaHeader[6] = 0x0; /* XXX this is only for IR so far XXX */

		BIO_write(cbio, instaHeader, 7);
	}

	i2d_CMP_PKIMESSAGE_bio(cbio, msg);

	(void) BIO_flush(cbio);
	return 1;
}


#warning RECEIVING HTTP MESSGES SHOULD BE DONE BETTER!
/* ############################################################################ */
/* for sure this could be done better */
/* ############################################################################ */
int CMP_PKIMESSAGE_http_bio_recv( BIO *cbio, CMP_PKIMESSAGE **ip) {
#define MAX_RECV_BYTE 10240
	char tmpbuf[1024];
	/* XXX this is not nice */
	char recvMsg[MAX_RECV_BYTE];
	char *recvPtr=NULL;
	int hits=0;

	int retID;
	char retSTR[10];
	char *contLenBeg=NULL;
	const unsigned char *derMessage=NULL;

	size_t recvLen=0;
	size_t headerLen=0;
	size_t contentLen=0;
	size_t totalLen=0;

	recvPtr = recvMsg;

	/* receive at least the http header */
	for(;;) {
		recvLen = BIO_read(cbio, tmpbuf, 1024);
		if(recvLen <= 0) {
			fprintf( stderr, "ERROR: receiving message. FILE %s, LINE %d\n", __FILE__, __LINE__);
			return 0;
		}
		if( (totalLen+recvLen) > MAX_RECV_BYTE) {
			fprintf( stderr, "ERROR: message received is bigger than %d Bytes. FILE %s, LINE %d\n", MAX_RECV_BYTE, __FILE__, __LINE__);
			return 0;
		}

		totalLen += recvLen;
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
	/* go to the beginning of the der Message */
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
	hits = sscanf(contLenBeg, "Content-Length:%d\r\n", &contentLen);
	if( hits != 1) {
		fprintf( stderr, "ERROR: received malformed HTTP message. Could not determine Content-Length. FILE: %s, LINE %d\n", __FILE__, __LINE__);
		return 0;
	}

	/* determine the HeaderLength */
	headerLen = derMessage - (unsigned char*) recvMsg;
	while( totalLen < (headerLen+contentLen)) {
		recvLen = BIO_read(cbio, tmpbuf, 1024);
		if(recvLen <= 0) {
			fprintf( stderr, "ERROR: receiving message. FILE %s, LINE %d\n", __FILE__, __LINE__);
			return 0;
		}
		if( (totalLen+recvLen) > MAX_RECV_BYTE) {
			fprintf( stderr, "ERROR: message received is bigger than %d Bytes. FILE %s, LINE %d\n", MAX_RECV_BYTE, __FILE__, __LINE__);
			return 0;
		}
		totalLen += recvLen;
		memcpy(recvPtr, tmpbuf, recvLen);
		recvPtr += recvLen;
	}

	/* transform DER message to OPENSSL internal format */
	if( (*ip = d2i_CMP_PKIMESSAGE( NULL, &derMessage, contentLen))) {
		return 1;
	} else {
		fprintf( stderr, "ERROR: decoding DER encoded message. FILE: %s, LINE %d\n", __FILE__, __LINE__);
		return 0;
	}
}

