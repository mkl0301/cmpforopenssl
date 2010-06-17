/* crypto/cmp/cmp_trans.c
 * Transport functions for CMP (RFC 4210) for OpenSSL
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
 * Copyright 2010 Nokia Siemens Networks Oy. ALL RIGHTS RESERVED.
 * CMP support in OpenSSL originally developed by 
 * Nokia Siemens Networks for contribution to the OpenSSL project.
 */

/* =========================== CHANGE LOG =============================
 * 17.6.2010 - Martin Peylo - Initial Creation
 */

#include <openssl/cmp.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/opensslv.h>
#include <curl/curl.h>
#include <stdlib.h>

/* TODO: add error catching for all memory operations */
/* TODO: include CMP_ctx into all functions */

/* XXX is this wise? */
/* ... that way we can (should!) only have one open connection */
static struct curl_slist *slist=NULL;

/* ############################################################################ */
/* this are helper functions for storing what we got with cURL */
/* ############################################################################ */

/* this has to be included into CMP_ctx struct */
struct MemoryStruct {
  char *memory;
  size_t size;
};

struct MemoryStruct myReceivedData;

static void *myrealloc(void *ptr, size_t size)
{
  /* There might be a realloc() out there that doesn't like reallocing
   *      NULL pointers, so we take care of it here */ 
  if(ptr)
    return realloc(ptr, size);
  else
    return malloc(size);
}

static size_t WriteMemoryCallback(void *ptr, size_t size, size_t nmemb, void *data)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)data;

  mem->memory = myrealloc(mem->memory, mem->size + realsize + 1);
  if (mem->memory) {
    memcpy(&(mem->memory[mem->size]), ptr, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
  }
  return realsize;
}


/* ############################################################################ */
/* returns pointer to CURL structure on success, NULL on failure */
/* @serverName holds a sting like "my.server.com" or "1.2.3.4" */
/* ############################################################################ */
CURL* CMP_trans_new_bio(const char* url, const int port) {
  CURL *curl;
  CURLcode res;

  if(!( curl = curl_easy_int())) goto err;

  // TODO: catch (!=0) and throw errors 
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_PORT, (long) port);

  // TODO: add proxy handling
  // curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
  // curl_easy_setopt(curl, CURLOPT_PROXY_PORT, proxy_port); // if not already included in proxy url

  /* XXX if we are using HTTP - what is not a must */
  /* adjust the HTTP header to our needs */
  slist = curl_slist_append(slist, "Content-Type: application/pkixcmp");
  slist = curl_slist_append(slist, "Expect:"); // We're *not* sending "Expect: 100-continue"
  curl_easy_setopt(handle, CURLOPT_HTTPHEADER, slist);

  /* This is for storing what we got with cURL */
  /* send all data to this function  */ 
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&myReceivedData);

  curl_easy_setopt(curl, CURLOPT_USERAGENT, "CMP for " OPENSSL_VERSION_TEXT); // this could be made optional (or removed)

  return curl;
err:
  if(curl) curl_easy_cleanup(curl);
  return NULL;
}


/* ############################################################################ */
/* does not return anything */
/* ############################################################################ */
void CMP_trans_delete_bio(CURL *curl) {
  curl_easy_cleanup(curl);

  curl_slist_free_all(slist); /* free the list again */ 
  slist=NULL;
  return;
}


/* ############################################################################ */
/* returns 1 on success, 0 on failure */
/* ############################################################################ */
int CMP_trans_bio_send(CURL* curl,
				 const int compatibility,
				 const CMP_PKIMESSAGE *msg)
{
	size_t derLen;
  void* derMsg;

	if (!curl) return 0;
	if (!msg) return 0;

  /* transform the CMP message into sendable format */
	derLen = i2d_CMP_PKIMESSAGE( (CMP_PKIMESSAGE*) msg, NULL);
  if(! (derMsg = malloc(derLen)) ) goto err;
  i2d_CMP_PKIMESSAGE( (CMP_PKIMESSAGE*) msg, derMsg);

  /* tell curl what the POST content is */
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, derMsg);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, derLen); // XXX size_t is ok?
  
  // the actual sending
  // TODO: catch (!=0) and throw errors 
  curl_easy_perfom(curl);

  free(derMsg);

  return 1;
err:
  if(slist) curl_slist_free_all(slist);
  if(derMsg) free(derMsg);
  return 0;
}
