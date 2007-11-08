/* cmpclient.c
 * 
 * A simple CMP client utilizing OpenSSL
 *
 * Written by Martin Peylo <martin.peylo@nsn.com>
 *
 * OpenSSL can be obtained from:
 * http://www.openssl.org/
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

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/cmp.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>

#include <cmpclient.h>
#include <cmpclient_help.h>

/* ############################################################################ */
/* ############################################################################ */
     
/* set by CLA */
static int verbose_flag;
static int   opt_serverPort=0;
static char* opt_serverName=NULL;
static char* opt_httpProxy=NULL;
static char* opt_httpProxyName=NULL;
int opt_httpProxyPort=0;
static char* opt_caCertFile=NULL;
static char* opt_clCertFile=NULL;
static char* opt_newClCertFile=NULL;
static char* opt_clKeyFile=NULL;
static char* opt_newClKeyFile=NULL;
static char* opt_user=NULL;
static char* opt_password=NULL;
static int opt_hex=0;
static int opt_sequenceSet=0;
static int opt_doIr=0;
static int opt_doKur=0;
static int opt_doInfo=0;

/* calculated from CLA */
static unsigned char *idString=NULL;
static unsigned char *password=NULL;
static size_t idStringLen=0, passwordLen=0;
static X509 *caCert=NULL;


/* ############################################################################ */
/* ############################################################################ */
void printUsage( const char* cmdName) {
	printf("Usage: %s [COMMON OPTIONS] [CMD] [OPTIONS]\n", cmdName);
	printf("Use the \"Certificate Management Protocol\" as client\n");
	printf("\n");
	printf("Written by Martin Peylo <martin.peylo@nsn.com>\n");
	printf("\n");
	printf("The COMMON OPTIONS have to be set for each CMD:\n");
	printf(" --server SERVER    the address of the CMP server\n");
	printf(" --port PORT        the port of the CMP server\n");
	printf(" --cacert           location of the CA's certificate\n");
	printf("\n");
	printf("One of the following can be used as CMD:\n");
	printf(" --ir   do initial certificate request sequence\n");
	printf(" --kur  do key update request sequence\n");
	printf(" --info do PKI Information request sequence\n");
	printf("\n");
	printf("The following OPTIONS have to be set when needed by CMD:\n");
	printf(" --user USER           the user for an IR message\n");
	printf(" --password PASSWORD   the password for an IR message\n");
	printf(" --hex                 user and password are HEX, not ASCII\n");
	printf(" --clcert FILE         location of the client's certificate\n");
	printf("                       this is overwritten at IR\n");
	printf(" --newclcert FILE      location of the client's new certificate\n");
	printf("                       this is overwritten at KUR\n");
	printf(" --key FILE            location of the client's private key\n");
	printf("                       this is overwritten at IR\n");
	printf(" --newkey FILE         location of the client's new private key\n");
	printf("                       this is overwritten at KUR\n");
	printf("\n");
	printf("Other options are:\n");
	printf(" --verbose  ignored so far\n");
	printf(" --brief    ignored so far\n");
	printf(" --help     shows this help\n");
	printf("\n");
	exit(1);
}


/* ############################################################################ */
/* ############################################################################ */
void doIr() {
	EVP_PKEY *initialPkey=NULL;
	BIO *cbio=NULL;
	X509 *initialClCert=NULL;
	CMP_CTX *cmp_ctx=NULL;

	/* generate RSA key */
	initialPkey = HELP_generateRSAKey();
	HELP_savePrivKey(initialPkey, opt_clKeyFile);

	/* XXX this is not freed yet */
	cmp_ctx = CMP_CTX_create();
	CMP_CTX_set1_serverName( cmp_ctx, opt_serverName);
	CMP_CTX_set1_serverPort( cmp_ctx, opt_serverPort);
	CMP_CTX_set1_referenceValue( cmp_ctx, idString, idStringLen);
	CMP_CTX_set1_secretValue( cmp_ctx, password, passwordLen);
	CMP_CTX_set0_pkey( cmp_ctx, initialPkey);
	CMP_CTX_set1_caCert( cmp_ctx, caCert);
	CMP_CTX_set_compatibility( cmp_ctx, CMP_COMPAT_CRYPTLIB);

	/* CL does not support this, it just ignores it.
	 * CMP_CTX_set_option( cmp_ctx, CMP_CTX_OPT_IMPLICITCONFIRM, CMP_CTX_OPT_SET);
	 */

	if (!CMP_new_bio( &cbio, opt_httpProxyName, opt_httpProxyPort)) {
		printf( "ERROR: setting up connection to server");
		exit(1);
	}

	initialClCert = CMP_doInitialRequestSeq( cbio, cmp_ctx);
	BIO_free(cbio);

	if( initialClCert) {
		printf( "SUCCESS: received initial Client Certificate. FILE %s, LINE %d\n", __FILE__, __LINE__);
	} else {
		printf( "ERROR: received no initial Client Certificate. FILE %s, LINE %d\n", __FILE__, __LINE__);
	}
	HELP_write_der_cert(initialClCert, opt_clCertFile);

	return;
}

/* ############################################################################ */
/* ############################################################################ */
void doKur() {
	EVP_PKEY *initialPkey=NULL;
	X509 *initialClCert=NULL;

	EVP_PKEY *updatedPkey=NULL;
	BIO *cbio=NULL;
	X509 *updatedClCert=NULL;

	CMP_CTX *cmp_ctx=NULL;

	initialPkey = HELP_readPrivKey(opt_clKeyFile);
	initialClCert = HELP_read_der_cert(opt_clCertFile);

	/* generate RSA key */
	updatedPkey = HELP_generateRSAKey();
	HELP_savePrivKey( updatedPkey, opt_newClKeyFile);

	/* XXX this is not freed yet */
	cmp_ctx = CMP_CTX_create();
	CMP_CTX_set1_serverName( cmp_ctx, opt_serverName);
	CMP_CTX_set1_serverPort( cmp_ctx, opt_serverPort);
	CMP_CTX_set0_pkey( cmp_ctx, initialPkey);
	CMP_CTX_set0_newPkey( cmp_ctx, updatedPkey);
	CMP_CTX_set1_clCert( cmp_ctx, initialClCert);
	CMP_CTX_set1_caCert( cmp_ctx, caCert);
	CMP_CTX_set_compatibility( cmp_ctx, CMP_COMPAT_CRYPTLIB);

	if (!CMP_new_bio( &cbio, opt_httpProxyName, opt_httpProxyPort)) {
		printf( "ERROR: setting up connection to server");
		exit(1);
	}

	updatedClCert = CMP_doKeyUpdateRequestSeq( cbio, cmp_ctx);
	BIO_free(cbio);

	if( updatedClCert) {
		printf( "SUCCESS: received updated Client Certificate. FILE %s, LINE %d\n", __FILE__, __LINE__);
	} else {
		printf( "ERROR: received no updated Client Certificate. FILE %s, LINE %d\n", __FILE__, __LINE__);
	}
	HELP_write_der_cert( updatedClCert, opt_newClCertFile);

	return;
}

/* ############################################################################ */
/* ############################################################################ */
void doInfo() {
	BIO *cbio=NULL;
	CMP_CTX *cmp_ctx=NULL;
	int res=0;

	/* XXX this is not freed yet */
	cmp_ctx = CMP_CTX_create();
	CMP_CTX_set1_serverName( cmp_ctx, opt_serverName);
	CMP_CTX_set1_serverPort( cmp_ctx, opt_serverPort);
	CMP_CTX_set1_referenceValue( cmp_ctx, idString, idStringLen);
	CMP_CTX_set1_secretValue( cmp_ctx, password, passwordLen);
	CMP_CTX_set1_caCert( cmp_ctx, caCert);
	CMP_CTX_set_compatibility( cmp_ctx, CMP_COMPAT_CRYPTLIB);

	if (!CMP_new_bio( &cbio, opt_httpProxyName, opt_httpProxyPort)) {
		printf( "ERROR: setting up connection to server");
		exit(1);
	}

	res = CMP_doPKIInfoReqSeq( cbio, cmp_ctx);
	BIO_free(cbio);

	if( res) {
		printf( "SUCCESS: Doing PKI Information Request/Response. FILE %s, LINE %d\n", __FILE__, __LINE__);
	} else {
		printf( "ERROR: Doing PKI Information Request/Response. FILE %s, LINE %d\n", __FILE__, __LINE__);
	}

	return;
}

/* ############################################################################ */
/* ############################################################################ */
void parseCLA( int argc, char **argv) {
	/* manage command line options */
	int c;
	/* getopt_long stores the option index here. */
	int option_index = 0;

	static struct option long_options[] =
	{
		{"verbose",  no_argument,          &verbose_flag, 1},
		{"brief",    no_argument,          &verbose_flag, 0},
		{"server",   required_argument,    0, 'a'},
		{"port",     required_argument,    0, 'b'},
		{"ir",       no_argument,          0, 'c'},
		{"kur",      no_argument,          0, 'd'},
		{"info",     no_argument,          0, 'n'},
		{"user",     required_argument,    0, 'e'},
		{"password", required_argument,    0, 'f'},
		{"cacert",   required_argument,    0, 'g'},
		{"clcert",   required_argument,    0, 'h'},
		{"help",     no_argument,          0, 'i'},
		{"key",      required_argument,    0, 'j'},
		{"newkey",   required_argument,    0, 'k'},
		{"newclcert",required_argument,    0, 'l'},
		{"hex",      no_argument,          0, 'm'},
		{0, 0, 0, 0}
	};

	while (1)
	{
		c = getopt_long (argc, argv, "a:b:cde:f:g:h:ij:k:l:mn", long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c)
		{
			case 0:
				/* If this option set a flag, do nothing else now. */
				if (long_options[option_index].flag != 0)
					break;
				printf ("option %s", long_options[option_index].name);
				if (optarg)
					printf (" with arg %s", optarg);
				printf ("\n");
				break;

			case 'a':
				opt_serverName = (char*) malloc(strlen(optarg)+1);
				strcpy(opt_serverName, optarg);
				break;

			case 'b':
				opt_serverPort = atoi(optarg);
				break;

			case 'c':
				if( opt_sequenceSet) {
					fprintf( stderr, "ERROR: only one message sequence can be set at once!\n");
					printUsage( argv[0]);
				}
				opt_sequenceSet = 1;
				opt_doIr = 1;
				break;

			case 'd':
				if( opt_sequenceSet) {
					fprintf( stderr, "ERROR: only one message sequence can be set at once!\n");
					printUsage( argv[0]);
				}
				opt_sequenceSet = 1;
				opt_doKur = 1;
				break;

			case 'n':
				if( opt_sequenceSet) {
					fprintf( stderr, "ERROR: only one message sequence can be set at once!\n");
					printUsage( argv[0]);
				}
				opt_sequenceSet = 1;
				opt_doInfo = 1;
				break;

			case 'e':
				opt_user = (char*) malloc(strlen(optarg)+1);
				strcpy(opt_user, optarg);
				break;
			case 'f':
				opt_password = (char*) malloc(strlen(optarg)+1);
				strcpy(opt_password, optarg);
				break;
			case 'g':
				opt_caCertFile = (char*) malloc(strlen(optarg)+1);
				strcpy(opt_caCertFile, optarg);
				break;
			case 'h':
				opt_clCertFile = (char*) malloc(strlen(optarg)+1);
				strcpy(opt_clCertFile, optarg);
				break;
			case 'i':
				printUsage( argv[0]);
				break;
			case 'j':
				opt_clKeyFile = (char*) malloc(strlen(optarg)+1);
				strcpy(opt_clKeyFile, optarg);
				break;
			case 'k':
				opt_newClKeyFile = (char*) malloc(strlen(optarg)+1);
				strcpy(opt_newClKeyFile, optarg);
				break;
			case 'l':
				opt_newClCertFile = (char*) malloc(strlen(optarg)+1);
				strcpy(opt_newClCertFile, optarg);
				break;
			case 'm':
				opt_hex = 1;
				break;
			case '?':
				/* getopt_long already printed an error message. */
				break;

			default:
				abort ();
		}
	}

	if (optind < argc) {
		printf ("ERROR: the following arguments were not recognized: ");
		while (optind < argc)
			printf ("%s ", argv[optind++]);
		printf("\n\n");
		printUsage( argv[0]);
	}

	if (!(opt_serverName && opt_serverPort && opt_caCertFile)) {
		printf("ERROR: setting server, port and cacert is mandatory for all sequences\n\n");
		printUsage( argv[0]);
	}

	if (!opt_sequenceSet) {
		printf("ERROR: supply a CMD\n");
		printUsage( argv[0]);
	}

	if( opt_doKur) {
		if (!(opt_clCertFile && opt_clKeyFile && opt_newClCertFile && opt_newClKeyFile)) {
			printf("ERROR: setting cacert, clcert, newclcert, key and newkey is mandatory for KUP\n\n");
			printUsage( argv[0]);
		}
	}

	if( opt_doIr) {
		if (!(opt_user && opt_password && opt_clCertFile && opt_clKeyFile)) {
			printf("ERROR: setting user, password, cacert, clcert and key is mandatory for IR\n\n");
			printUsage( argv[0]);
		}
	}

	if( opt_doInfo) {
		if (!(opt_user && opt_password )) {
			printf("ERROR: setting user and password is mandatory for PKIInfo\n\n");
			printUsage( argv[0]);
		}
	}


	return;
}

int getHttpProxy( char **name, int *port) {
	char *proxy=NULL;
	char *colon=NULL;

	if( opt_httpProxy) {
		proxy = opt_httpProxy;
	} else {
		if( getenv("http_proxy")) {
			proxy = strdup(getenv("http_proxy"));
		} else {
			/* no proxy setting found */
			return 0;
		}
	}

	/* convert all colons to space */
	while( (colon = strchr(proxy, ':'))) {
		*colon = ' ';
	}

	/* this will be long enough */
	*name = malloc(strlen(proxy)+1);

	if( (sscanf( proxy, "http //%s %d", *name, port) < 1)) {
		/* maybe it is set without leading http:// */
		if( (sscanf( proxy, "%s %d", *name, port) < 1)) {
			printf("ERROR: Failed to determine proxy from \"%s\"\n", proxy);
			return 0;
		}
	}
	printf("INFO: found proxy setting, Name=%s, Port=%d\n", *name, *port);
	return 1;
}

/* ############################################################################ */
/* ############################################################################ */
int main(int argc, char **argv) {
	char *httpProxyName;
	int httpProxyPort;

	parseCLA(argc, argv);

	if (getHttpProxy( &httpProxyName, &httpProxyPort)) {
		opt_httpProxyName = httpProxyName;
		opt_httpProxyPort = httpProxyPort;
	} else {
		opt_httpProxyName = opt_serverName;
		opt_httpProxyPort = opt_serverPort;
	}

	/* read CA certificate */
	caCert = HELP_read_der_cert(opt_caCertFile);

	if( opt_doIr) {
		if (opt_hex) {
			/* get str representation of hex passwords */
			idStringLen = HELP_hex2str(opt_user, &idString);
			passwordLen = HELP_hex2str(opt_password, &password);
		} else {
			idStringLen = strlen(opt_user);
			idString = (unsigned char*) opt_user;
			passwordLen = strlen(opt_password);
			password = (unsigned char*) opt_password;
		}
		doIr();
	}

	if( opt_doKur) {
		doKur();
	}

	if( opt_doInfo) {
		if (opt_hex) {
			/* get str representation of hex passwords */
			idStringLen = HELP_hex2str(opt_user, &idString);
			passwordLen = HELP_hex2str(opt_password, &password);
		} else {
			idStringLen = strlen(opt_user);
			idString = (unsigned char*) opt_user;
			passwordLen = strlen(opt_password);
			password = (unsigned char*) opt_password;
		}
		doInfo();
	}

	return 0;
}

