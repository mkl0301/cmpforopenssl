/* defines.h
 *
 * Definitions and macros for cmpserver-cl.c
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

#ifndef DEFINES_H
#define DEFINES_H

/* DATABASE */
/* either only the DB name or user:pass@name if needed */
#define MY_DB	"myodbc"

/* SERVER */
#define MY_CA_KEYSET_PASSWORD "password"
#define MY_CA_KEY_LABEL "CA Key Label"

/* CLIENT */
#define MY_CL_PRIVKEY_PASSWORD "verySecure"
#define MY_CL_KEY_LABEL "CL Key Label"

/* COMMON */
#define MY_CERT_BUF_SIZE 10000

/* MACROS */
#define STAT( xxx ) do { \
	if( status != CRYPT_OK ) \
		printf( "ERROR "#xxx"  - in FILE: %s, LINE %d, status=%d\n", __FILE__, __LINE__, status); \
	else \
		printf( "SUCCESS "#xxx"\n"); \
}while(0)

#endif /* DEFINES_H */
