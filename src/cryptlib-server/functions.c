/* functions.c
 * 
 * Functions for cmpserver-cl.c
 *
 * Written by Martin Peylo <martin.peylo@nsn.com>
 *
 * Cryptlib can be obtained from:
 * http://www.cs.auckland.ac.nz/~pgut001/cryptlib/
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
 * The following license applies to cryptlib which is utilized by this file:
 *
 * Copyright 1992-2007 Peter Gutmann. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Redistributions in any form must be accompanied by information on how to
 * obtain complete source code for the cryptlib software and any accompanying
 * software that uses the cryptlib software.  The source code must either be
 * included in the distribution or be available for no more than the cost of
 * distribution, and must be freely redistributable under reasonable
 * conditions.  For an executable file, complete source code means the source
 * code for all modules it contains or uses.  It does not include source code
 * for modules or files that typically accompany the major components of the
 * operating system on which the executable file runs.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT, ARE DISCLAIMED.  IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#include "defines.h"
#include "functions.h"
#include <cryptlib.h>
#include <stdio.h>
#include <stdlib.h>

/* ########################################################################## */
int myExportCertificate (const CRYPT_CERTIFICATE myCertificate,
			 const char* fileName) {
	int status;
	char * certificate;
	int certMaxLength, certLength;
	FILE * myFile;

	/* determine certMaxLength */
	status = cryptExportCert( NULL, 0, &certMaxLength, CRYPT_CERTFORMAT_CERTIFICATE, myCertificate );
	STAT(export Certificate - checking certMaxLength);
	/* Allocate memory for the encoded certificate */
	certificate = malloc( certMaxLength );
	/* Export the encoded certificate from the certificate object */
	status = cryptExportCert( certificate, certMaxLength, &certLength, CRYPT_CERTFORMAT_CERTIFICATE, myCertificate );
	STAT(export Certificate);

	if( ( myFile = fopen( fileName, "w" ) ) == NULL )
		printf( "ERROR writing file\n");
	fwrite( certificate, certLength, 1, myFile );
	fclose( myFile );

	free(certificate);

	return status;
}

/* ########################################################################## */
int myImportCert( CRYPT_CERTIFICATE *myCryptCert_p, char* fileName ) {
	int status;
	int count;
	FILE * myFile_p;
	char buffer[MY_CERT_BUF_SIZE];

	if( ( myFile_p = fopen( fileName, "r" ) ) == NULL )
		printf("ERROR - opening FILE\n");
	count = fread( buffer, 1, MY_CERT_BUF_SIZE, myFile_p );
	fclose( myFile_p );
	if( count == MY_CERT_BUF_SIZE )  /* Certificate too large for buffer */
		printf("ERROR - BUFFER TOO SMALL\n");

	/* Import the certificate */
	status = cryptImportCert( buffer, count, CRYPT_UNUSED, myCryptCert_p );
	STAT(Importing certificate);

	return status;
}


