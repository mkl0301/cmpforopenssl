/* cmpserver-cl.c
 *
 * A very simple CMP CA using cryptlib
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
#include <stdio.h>
#include <string.h>
#include <cryptlib.h>
#include <time.h>
#include <stdlib.h>

#include <getopt.h>

/* set by CLA */
static int verbose_flag;
static int   opt_serverPort=0;
static char* opt_serverName=NULL;
static char* opt_caCertFile=NULL;
static char* opt_caKeyFile=NULL;

static int opt_actionSet=0;

static int opt_doCreateCert=0;
static int opt_doCreateUser=0;
static int opt_doRunDeamon=0;

static char* opt_commonname=NULL;
static char* opt_country=NULL;
static char* opt_unit=NULL;
static char* opt_organization=NULL;

/* ########################################################################## */
/* ########################################################################## */
void printErrorString( int status, CRYPT_SESSION myCryptSession) {
	int errorCode, errorStringLength;
	char errorString[1024];

	printf("trying to get the Errorstring:\n");
	status = cryptGetAttribute( myCryptSession, CRYPT_ATTRIBUTE_INT_ERRORCODE, &errorCode );

	if( cryptStatusError( status ) )
	{
		printf("Error while trying to get the Errorcode\n");
		/* translateStatus(status); */
	}

	printf("get errorStringLength:\n");
	cryptGetAttributeString( myCryptSession, CRYPT_ATTRIBUTE_INT_ERRORMESSAGE, NULL, &errorStringLength );
	printf("The ErrorStringLength:%d\n", errorStringLength);

	printf("get errorString:\n");
	cryptGetAttributeString( myCryptSession, CRYPT_ATTRIBUTE_INT_ERRORMESSAGE, errorString, &errorStringLength );
	printf("The ErrorString: %s\n", errorString);
}

/* ########################################################################## */
/* ########################################################################## */
unsigned char *StrToHexStr(char *str, int length)
{
	unsigned char *newstr;
	unsigned char *cpold;
	unsigned char *cpnew;

	newstr = (unsigned char *)malloc((size_t)(length*2+1));
	/* XXX I know this is not freed... */
	cpold = (unsigned char*)str;
	cpnew = newstr;

	while(length--) {
		sprintf(cpnew, "%02X", (unsigned char)(*cpold++));
		cpnew+=2;
	}
	*(cpnew) = '\0';
	return(newstr);
}

/* ##########################################################################
 * Once the user information has been entered into the certificate store,
 * you can read back the PKI user ID, ... page 244
 *
 * The CA needs to communicate this information to the user via some out-of-band
 * means, typically through the use of a PIN mailer or via some other direct
 * communication means during the certificate sign-up process. Once this information
 * is communicated, the user can use it to obtain their initial certificate. Any further
 * certificates are typically obtained by signing the request with the initial certificate or
 * with subsequently-obtained certificates.
 * ########################################################################## */
int readUserAndPwd( CRYPT_CERTIFICATE *myPKIUser_p) {
	int status;
	char userID[ CRYPT_MAX_TEXTSIZE + 1 ];
	char issuePW[ CRYPT_MAX_TEXTSIZE + 1 ];
	char revPW[ CRYPT_MAX_TEXTSIZE + 1 ];
	int userIDlength, issuePWlength, revPWlength;

	/* XXX let's try this */
	unsigned char decodedUserID[ 64+8 ];
	unsigned char decodedPW[ 64+8 ];
	unsigned char decodedRevPW[ 64+8 ];
	int decUIDlen, decPWlen, decRPWlen;

	unsigned char *aux1, *aux2, *aux3;

	cryptGetAttributeString( *myPKIUser_p, CRYPT_CERTINFO_PKIUSER_ID, userID, &userIDlength );
	userID[ userIDlength ] = '\0';
	cryptGetAttributeString( *myPKIUser_p, CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD, issuePW, &issuePWlength );
	issuePW[ issuePWlength ] = '\0';
	cryptGetAttributeString( *myPKIUser_p, CRYPT_CERTINFO_PKIUSER_REVPASSWORD, revPW, &revPWlength );
	revPW[ revPWlength ] = '\0';

	if( userIDlength>0) {
		/* if there is a user set */
		/* XXX let's try this */
		decodePKIUserValue( decodedUserID, 64, &decUIDlen, userID,  userIDlength  );
		decodePKIUserValue( decodedPW,     64, &decPWlen,  issuePW, issuePWlength );
		decodePKIUserValue( decodedRevPW,  64, &decRPWlen, revPW,   revPWlength   );

		printf( "User= %s\nPassword= %s\nRevPW= %s\n", userID, issuePW, revPW);
		printf( "DECODED, HEX: User= %s\nPassword= %s\nRevPW= %s\n", aux1=StrToHexStr(decodedUserID, decUIDlen),
			aux2=StrToHexStr(decodedPW, decPWlen), aux3=StrToHexStr(decodedRevPW, decRPWlen));

		free(aux1);
		free(aux2);
		free(aux3);
	}

	return status;
}



/* ########################################################################## */
/* ########################################################################## */
int createCACertificate (const char *caCertFile, const CRYPT_KEYSET *myKeyset_p, CRYPT_CONTEXT *cryptContext_p,
		const char *country,
		const char *organization,
		const char *unit,
		const char *commonname) {
	int status;
	time_t validity;
	char *ctxinfo;
	CRYPT_CERTIFICATE myCertificate;

	/* Create the CA certificate and add the public key */
	status = cryptCreateCert( &myCertificate, CRYPT_UNUSED, CRYPT_CERTTYPE_CERTIFICATE );
	STAT(creating the certificate);
	status = cryptSetAttribute( myCertificate, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, *cryptContext_p );
	STAT(setting the CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO attribute);

	/* Add identification information */
	status = cryptSetAttributeString( myCertificate, CRYPT_CERTINFO_COUNTRYNAME, country, strlen(country) );
	STAT(setting the CRYPT_CERTINFO_COUNTRYNAME attribute);
	status = cryptSetAttributeString( myCertificate, CRYPT_CERTINFO_ORGANIZATIONNAME, organization, strlen(organization) );
	STAT(setting the CRYPT_CERTINFO_ORGANIZATIONNAME attribute);
	status = cryptSetAttributeString( myCertificate, CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, unit, strlen(unit) );
	STAT(setting the CRYPT_CERTINFO_ORGANIZATIONALUNITNAME attribute);
	status = cryptSetAttributeString( myCertificate, CRYPT_CERTINFO_COMMONNAME, commonname, strlen(commonname) );
	STAT(setting the CRYPT_CERTINFO_COMMONNAME attribute);

	/* Make it valid for 5 years */
	validity = time( NULL ) + ( 86400L * 365 * 3 );
	status = cryptSetAttributeString( myCertificate, CRYPT_CERTINFO_VALIDTO, &validity, sizeof( time_t ) );
	STAT(setting the validity);

	/* mark as self-signed CA certificate p 241 */
	status = cryptSetAttribute( myCertificate, CRYPT_CERTINFO_SELFSIGNED, 1 );
	STAT(setting the CRYPT_CERTINFO_SELFSIGNED attribute);
	status = cryptSetAttribute( myCertificate, CRYPT_CERTINFO_CA, 1 );
	STAT(setting the CRYPT_CERTINFO_CA attribute);

	/* sign the root CA certificate */
	status = cryptSignCert( myCertificate, *cryptContext_p);
	STAT(signing the certificate);

	/* store the root CA certificate */
	status = cryptAddPrivateKey( *myKeyset_p, *cryptContext_p, MY_CA_KEYSET_PASSWORD);
	STAT(storing the private key);

	/* enable PKI-Booting this certificate  */
	status = cryptSetAttribute( myCertificate, CRYPT_CERTINFO_TRUSTED_IMPLICIT, 1 );
	STAT(setting Certificat to be trusted);

	status = cryptAddPublicKey( *myKeyset_p, myCertificate);
	STAT(storing the public key);

	/* export the certificate */
	myExportCertificate( myCertificate, caCertFile);

	/* Clean up */
	status = cryptDestroyCert( myCertificate);
	STAT(Destroying the certificate);

	return status;
}


/* ########################################################################## */
/* ########################################################################## */
int prepareCACert (const char *caCertFile,
                   const CRYPT_KEYSET *myCertStore_p,
		   const char *country,
		   const char *organization,
		   const char *unit,
		   const char *commonname) {
	int status;
	CRYPT_CONTEXT myContext;

	/* Create an RSA public/private key context, set a label for it, and generate a key into it */
	status = cryptCreateContext( &myContext, CRYPT_UNUSED, CRYPT_ALGO_RSA );
	STAT(creating Context);
	status = cryptSetAttributeString( myContext, CRYPT_CTXINFO_LABEL, MY_CA_KEY_LABEL, strlen(MY_CA_KEY_LABEL) );
	STAT(setting Attribute CRYPT_CTXINFO_LABEL);
	status = cryptGenerateKey( myContext );
	STAT(generating Key);

	createCACertificate( caCertFile, myCertStore_p, &myContext, country, organization, unit, commonname);

	status = cryptDestroyContext( myContext);
	STAT(destroying context);
	return status;
}

/* ########################################################################## */
/* ########################################################################## */
int createPKIuser (const CRYPT_KEYSET *myCertStore_p,
		   const char* country,
		   const char* organization,
		   const char* unit,
		   const char* commonname) {
	int status;
	CRYPT_CERTIFICATE myPKIUser;

	printf("INFO: Creating PKI User COUNTRY:\"%s\" ORG:\"%s\" UNIT:\"%s\" CN:\"%s\"\n", country, organization, unit, commonname);
	status = cryptCreateCert( &myPKIUser, CRYPT_UNUSED, CRYPT_CERTTYPE_PKIUSER );
	STAT(creating certificate);
	/* Add identification information */
	status = cryptSetAttributeString( myPKIUser, CRYPT_CERTINFO_COUNTRYNAME, country, strlen(country) );
	status = cryptSetAttributeString( myPKIUser, CRYPT_CERTINFO_ORGANIZATIONNAME, organization, strlen(organization) );
	status = cryptSetAttributeString( myPKIUser, CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, unit, strlen(unit) );
	status = cryptSetAttributeString( myPKIUser, CRYPT_CERTINFO_COMMONNAME, commonname, strlen(commonname) );

	/* Add the certificate to the store */
	status = cryptCAAddItem( *myCertStore_p, myPKIUser );
	STAT(storing the PKI User);
	if( status == -44)
		printf("ERROR-INFO: Error -44 MIGHT indicate that the exact same user already exists\n");

	if( status == CRYPT_OK) readUserAndPwd( &myPKIUser);

	/* clean up */
	status = cryptDestroyCert( myPKIUser );
	STAT(destroying certificate);
	return status;
}

/* ########################################################################## */
/* ########################################################################## */
int startCMPServer ( CRYPT_KEYSET *myCertStore_p,
		     CRYPT_KEYSET *myKeyset_p,
		     const char *serverName,
		     const int serverPort
		) {
	int status;
	CRYPT_SESSION myCryptSession;
	CRYPT_CONTEXT myPrivKey;

	printf("INFO: Starting CMP Server, serverName=%s, serverPort=%d\n", serverName, serverPort);

	/* get the private Key from the Keyset */
	status = cryptGetPrivateKey( *myKeyset_p, &myPrivKey, CRYPT_KEYID_NAME, MY_CA_KEY_LABEL, MY_CA_KEYSET_PASSWORD );
	STAT(get the private Key);

	/* Create the session */
	status = cryptCreateSession( &myCryptSession, CRYPT_UNUSED, CRYPT_SESSION_CMP_SERVER );
	STAT(create CMP Server);

	/* Add the CA certificate store and CA server key and activate session */
	status = cryptSetAttribute( myCryptSession, CRYPT_SESSINFO_KEYSET, *myCertStore_p );
	STAT(set attribute for certStore);

	/* Add the private Key */
	status = cryptSetAttribute( myCryptSession, CRYPT_SESSINFO_PRIVATEKEY, myPrivKey);
	STAT(set attribute for private Key);

	/* Address of the CMP Server */
	status = cryptSetAttributeString( myCryptSession, CRYPT_SESSINFO_SERVER_NAME, serverName, strlen(serverName) );
	STAT(set attribute for server Address);
	status = cryptSetAttribute( myCryptSession, CRYPT_SESSINFO_SERVER_PORT, serverPort );
	STAT(set attribute for server Port);

	/* START the CMP Server */
	status = cryptSetAttribute( myCryptSession, CRYPT_SESSINFO_ACTIVE, 1 );
	STAT(set attribute CMP session active);

	/* XXX */
	printErrorString( status, myCryptSession);

	/* clean up */
	status = cryptDestroyContext( myPrivKey);
	STAT(destroy private Key);
	status = cryptDestroySession( myCryptSession);
	STAT(destroy session);
	return status;
}

/* ############################################################################ */
/* ############################################################################ */
void printUsage( const char* cmdName) {
	printf("Usage: %s [ACTION] [OPTIONS]\n", cmdName);
	printf("Use the \"Certificate Management Protocol\" as server\n");
	printf("\n");
	printf("Written by Martin Peylo <martin.peylo@nsn.com>\n");
	printf("\n");
	printf("One of the following can be used as ACTION:\n");
	printf(" --createcert  create CA certificate\n");
	printf(" --createuser  create a new PKI user (initialize EE)\n");
	printf(" --daemon      run as daemon\n");
	printf("\n");
	printf("The following OPTIONS have to be set when needed by ACTION:\n");
	printf(" --server SERVER    the address of the CMP server\n");
	printf(" --port PORT        the port of the CMP server\n");
	printf(" --cacert           location of the CA's certificate\n");
	printf("                    this is overwritten at CREATECERT\n");
	printf(" --country COUNTRY  the \"country\" to set for the CA cert or PKI user\n");
	printf(" --organization ORG the \"organization\" to set for the CA cert or PKI user\n");
	printf(" --unit UNIT        the \"unit\" to set for the CA cert or PKI user\n");
	printf(" --commonname NAME  the \"commonname\" to set for the CA cert or PKI user\n");
	printf(" --key FILE         location of the CA's key storage\n");
	printf("                    this is overwritten at CREATECERT\n");
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
void parseCLA( int argc, char **argv) {
	/* manage command line options */
	int c;
	/* getopt_long stores the option index here. */
	int option_index = 0;

	static struct option long_options[] =
	{
		{"verbose",      no_argument,       &verbose_flag, 1},
		{"brief",        no_argument,       &verbose_flag, 0},
		{"port",         required_argument, 0, 'a'},
		{"createcert",   no_argument,       0, 'b'},
		{"createuser",   no_argument,       0, 'c'},
		{"key",          required_argument, 0, 'd'},
		{"cacert",       required_argument, 0, 'e'},
		{"commonname",   required_argument, 0, 'f'},
		{"country",      required_argument, 0, 'g'},
		{"organization", required_argument, 0, 'h'},
		{"unit",         required_argument, 0, 'i'},
		{"help",         no_argument,       0, 'j'},
		{"daemon",       no_argument,       0, 'k'},
		{"server",       required_argument, 0, 'l'},
		{0, 0, 0, 0}
	};

	while (1)
	{
		c = getopt_long (argc, argv, "a:bcd:e:f:g:h:i:jkl:", long_options, &option_index);

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
				opt_serverPort = atoi(optarg);
				break;
			case 'b':
				if( opt_actionSet) {
					fprintf( stderr, "ERROR: only one action can be set at once!\n");
					printUsage( argv[0]);
				}
				opt_actionSet = 1;
				opt_doCreateCert = 1;
				break;
			case 'c':
				if( opt_actionSet) {
					fprintf( stderr, "ERROR: only one action can be set at once!\n");
					printUsage( argv[0]);
				}
				opt_actionSet = 1;
				opt_doCreateUser= 1;
				break;
			case 'd':
				opt_caKeyFile = (char*) malloc(strlen(optarg)+1);
				strcpy(opt_caKeyFile, optarg);
				break;
			case 'e':
				opt_caCertFile = (char*) malloc(strlen(optarg)+1);
				strcpy(opt_caCertFile, optarg);
				break;
			case 'f':
				if(strlen(optarg)==0) {
					fprintf( stderr, "ERROR: no value for --commonname set\n");
					exit(1);
				}
				opt_commonname = (char*) malloc(strlen(optarg)+1);
				strcpy(opt_commonname, optarg);
				break;
			case 'g':
				if(strlen(optarg)==0) {
					fprintf( stderr, "ERROR: no value for --country set\n");
					exit(1);
				}
				opt_country = (char*) malloc(strlen(optarg)+1);
				strcpy(opt_country, optarg);
				break;
			case 'h':
				if(strlen(optarg)==0) {
					fprintf( stderr, "ERROR: no value for --organization set\n");
					exit(1);
				}
				opt_organization = (char*) malloc(strlen(optarg)+1);
				strcpy(opt_organization, optarg);
				break;
			case 'i':
				if(strlen(optarg)==0) {
					fprintf( stderr, "ERROR: no value for --unit set\n");
					exit(1);
				}
				opt_unit = (char*) malloc(strlen(optarg)+1);
				strcpy(opt_unit, optarg);
				break;
			case 'j':
				printUsage( argv[0]);
				break;
			case 'k':
				if( opt_actionSet) {
					fprintf( stderr, "ERROR: only one action can be set at once!\n");
					printUsage( argv[0]);
				}
				opt_actionSet = 1;
				opt_doRunDeamon = 1;
				break;
			case 'l':
				opt_serverName = (char*) malloc(strlen(optarg)+1);
				strcpy(opt_serverName, optarg);
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

	if (!opt_actionSet) {
		printf("ERROR: supply an ACTION\n");
		printUsage( argv[0]);
	}

	if( opt_doCreateCert) {
		if (!(opt_caCertFile && opt_caKeyFile && opt_commonname && opt_unit && opt_organization && opt_country)) {
			printf("ERROR: setting cacert, key, commonname, unit, organization and country is mandatory for createcert\n\n");
			printUsage( argv[0]);
		}
	}

	if( opt_doCreateUser) {
		if (!(opt_commonname && opt_unit && opt_organization && opt_country)) {
			printf("ERROR: setting commonname, unit, organization and country is mandatory for createuser\n\n");
			printUsage( argv[0]);
		}
	}

	if( opt_doRunDeamon) {
		if (!(opt_caKeyFile && opt_serverName && opt_serverPort)) {
			printf("ERROR: setting key, server and port is mandatory for daemon\n\n");
			printUsage( argv[0]);
		}
	}


	return;
}

/* ########################################################################## */
/* ########################################################################## */
int main (int argc, char **argv) {
	int status;

	parseCLA(argc, argv);

	CRYPT_KEYSET myCertStore;
	CRYPT_KEYSET myKeyset;

/* INITIALIZING CRYPTLIB */
	status = cryptInit();
	STAT(init);
	status = cryptAddRandom( NULL, CRYPT_RANDOM_SLOWPOLL );
	STAT(add random);

/* INITIALIZING CMP SERVER CERTIFICATE */
	if (opt_doCreateCert) {
		status = cryptKeysetOpen( &myKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, opt_caKeyFile, CRYPT_KEYOPT_CREATE );
		STAT(open keyset);
		/* create new CA certificate */
		prepareCACert( opt_caCertFile, &myKeyset, opt_country, opt_organization, opt_unit, opt_commonname);
		status = cryptKeysetClose( myKeyset);
		STAT(close keyset);
	}

/* INITIALIZING PKI USERS */
	if (opt_doCreateUser) {
		status = cryptKeysetOpen( &myCertStore, CRYPT_UNUSED, CRYPT_KEYSET_ODBC_STORE, MY_DB, CRYPT_KEYOPT_CREATE);
		if( status  != CRYPT_OK ) {
			STAT(create and open certstore);
			/* might be already created */
			status = cryptKeysetOpen( &myCertStore, CRYPT_UNUSED, CRYPT_KEYSET_ODBC_STORE, MY_DB, CRYPT_KEYOPT_NONE );
		}
		/* this actually might show the wrong status */
		STAT(open certstore);
		createPKIuser( &myCertStore, opt_country, opt_organization, opt_unit, opt_commonname);

		status = cryptKeysetClose( myCertStore);
		STAT(close certstore);
	}

/* RUNNING CMP SERVER */
	if (opt_doRunDeamon) {
		status = cryptKeysetOpen( &myCertStore, CRYPT_UNUSED, CRYPT_KEYSET_ODBC_STORE, MY_DB, CRYPT_KEYOPT_NONE );
		STAT(open certstore);
		status = cryptKeysetOpen( &myKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, opt_caKeyFile, CRYPT_KEYOPT_READONLY );
		STAT(open keyset);

		while (1) {
			startCMPServer( &myCertStore, &myKeyset, opt_serverName, opt_serverPort);
		}

		status = cryptKeysetClose( myCertStore);
		STAT(close certstore);
		status = cryptKeysetClose( myKeyset);
		STAT(close keyset);
	}

/* SHUTTING DOWN CRYPTLIB */
	status = cryptEnd();
	STAT( shutting down cryptlib);

	return status;
}
