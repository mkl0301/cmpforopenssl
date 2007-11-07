/****************************************************************************
*																			*
*				cryptlib Cert Management Session Test Routines				*
*						Copyright Peter Gutmann 1998-2005					*
*																			*
****************************************************************************/

#include "cryptlib.h"
#include "test/test.h"

#if defined( __MVS__ ) || defined( __VMCMS__ )
  /* Suspend conversion of literals to ASCII. */
  #pragma convlit( suspend )
#endif /* IBM big iron */
#if defined( __ILEC400__ )
  #pragma convert( 0 )
#endif /* IBM medium iron */

#if defined( TEST_SESSION ) || defined( TEST_SESSION_LOOPBACK )

/****************************************************************************
*																			*
*								SCEP Test Data								*
*																			*
****************************************************************************/

/* There are various SCEP test servers available, the following mappings
   can be used to test different ones.  Implementation peculiarities:

	#1 - cryptlib: None.

	#2 - SSH (www.ssh.com/support/testzone/pki.html): Invalid CA certs.

	#3 - OpenSCEP (openscep.othello.ch): Seems to be permanently unavailable.

	#4 - Entrust (freecerts.entrust.com/vpncerts/cep.htm): Only seems to be
			set up to handle Cisco gear.

	#5 - EJBCA: */

#define SCEP_NO		1

typedef struct {
	const char FAR_BSS *name;
	const C_CHR FAR_BSS *url, FAR_BSS *user, FAR_BSS *password, FAR_BSS *caCertUrl;
	} SCEP_INFO;

static const SCEP_INFO FAR_BSS scepInfo[] = {
	{ NULL },	/* Dummy so index == SCEP_NO */
	{ /*1*/ "cryptlib", TEXT( "http://localhost/pkiclient.exe" ), NULL, NULL, NULL },
	{ /*2*/ "SSH", TEXT( "http://pki.ssh.com:8080/scep/pkiclient.exe" ), TEXT( "ssh" ), TEXT( "ssh" ),
			TEXT( "http://pki.ssh.com:8080/scep/pkiclient.exe?operation=GetCACert&message=test-ca1.ssh.com" ) },
	{ /*3*/ "OpenSCEP", TEXT( "http://openscep.othello.ch/pkiclient.exe" ), TEXT( "????" ), TEXT( "????" ), NULL },
	{ /*4*/ "Entrust", TEXT( "http://vpncerts.entrust.com/pkiclient.exe" ), TEXT( "????" ), TEXT( "????" ), NULL },
	{ /*5*/ "EJBCA", TEXT( "http://q-rl-xp:8080/ejbca/publicweb/apply/scep/pkiclient.exe" ),
			TEXT("test2"), TEXT("test2"),
			TEXT( "http://q-rl-xp:8080/ejbca/publicweb/webdist/certdist?cmd=nscacert&issuer=O=Test&+level=1" ) },
	};

/* Cert request data for the cert from the SCEP server.  Note that we have
   to set the CN to the PKI user CN, for CMP ir's we just omit the DN
   entirely and have the server provide it for us but since SCEP uses PKCS
   #10 requests we need to provide a DN, and since we provide it it has to
   match the PKI user DN */

static const CERT_DATA FAR_BSS scepRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Test SCEP PKI user" ) },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, TEXT( "dave@wetas-r-us.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.wetas-r-us.com" ) },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

/* PKI user data to authorise the issuing of the various certs */

static const CERT_DATA FAR_BSS scepPkiUserData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Test SCEP PKI user" ) },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Add a PKI user to the cert store */

static int addPKIUser( const CRYPT_KEYSET cryptCertStore,
					   const CERT_DATA *pkiUserData,
					   const BOOLEAN isSCEP )
	{
	CRYPT_CERTIFICATE cryptPKIUser;
	CRYPT_SESSION cryptSession;
	C_CHR userID[ CRYPT_MAX_TEXTSIZE + 1 ], issuePW[ CRYPT_MAX_TEXTSIZE + 1 ];
	int length, status;

	/* Create the PKI user object and add the user's identification
	   information */
	status = cryptCreateCert( &cryptPKIUser, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_PKIUSER );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	if( !addCertFields( cryptPKIUser, pkiUserData, __LINE__ ) )
		return( FALSE );

	/* Add the user info to the cert store */
	status = cryptCAAddItem( cryptCertStore, cryptPKIUser );
	if( status == CRYPT_ERROR_DUPLICATE )
		{
		C_CHR userCN[ CRYPT_MAX_TEXTSIZE + 1 ];

		/* Get the name of the duplicate user */
		status = cryptGetAttributeString( cryptPKIUser,
										  CRYPT_CERTINFO_COMMONNAME,
										  userCN, &length );
		if( cryptStatusError( status ) )
			return( attrErrorExit( cryptPKIUser, "cryptGetAttribute()",
								   status, __LINE__ ) );
#ifdef UNICODE_STRINGS
		length /= sizeof( wchar_t );
#endif /* UNICODE_STRINGS */
		userCN[ length ] = TEXT( '\0' );

		/* The PKI user info was already present, for SCEP this isn't a
		   problem since we can just re-use the existing info, but for CMP
		   we can only authorise a single cert issue per user so we have
		   to delete the existing user info and try again */
		if( isSCEP )
			{
			/* The PKI user info is already present from a previous run, get
			   the existing info */
			puts( "PKI user information is already present from a previous "
				  "run, reusing existing\n  PKI user data..." );
			cryptDestroyCert( cryptPKIUser );
			status = cryptCAGetItem( cryptCertStore, &cryptPKIUser,
									 CRYPT_CERTTYPE_PKIUSER, CRYPT_KEYID_NAME,
									 userCN );
			}
		else
			{
			puts( "PKI user information is already present from a previous "
				  "run, deleting existing\n  PKI user data..." );
			status = cryptCADeleteItem( cryptCertStore, CRYPT_CERTTYPE_PKIUSER,
										CRYPT_KEYID_NAME, userCN );
			if( cryptStatusError( status ) )
				return( extErrorExit( cryptCertStore, "cryptCADeleteItem()",
									  status, __LINE__ ) );
			status = cryptCAAddItem( cryptCertStore, cryptPKIUser );
			}
		}
	if( cryptStatusError( status ) )
		return( extErrorExit( cryptCertStore, "cryptCAAdd/GetItem()", status,
							  __LINE__ ) );

	/* Display the information for the new user and make sure the error-
	   checking in the user information works.  We have to check both
	   passwords to reduce false positives since it's just a simple integrity
	   check meant to catch typing errors rather than a cryptographically
	   strong check */
	if( !printCertInfo( cryptPKIUser ) )
		return( FALSE );
	status = cryptGetAttributeString( cryptPKIUser,
									  CRYPT_CERTINFO_PKIUSER_ID,
									  userID, &length );
	if( cryptStatusOK( status ) )
		{
#ifdef UNICODE_STRINGS
		length /= sizeof( wchar_t );
#endif /* UNICODE_STRINGS */
		userID[ length ] = '\0';
		status = cryptGetAttributeString( cryptPKIUser,
									CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD,
									issuePW, &length );
		}
	if( cryptStatusOK( status ) )
		{
#ifdef UNICODE_STRINGS
		length /= sizeof( wchar_t );
#endif /* UNICODE_STRINGS */
		issuePW[ length ] = '\0';
		}
	else
		return( attrErrorExit( cryptPKIUser, "cryptGetAttribute()", status,
							   __LINE__ ) );
	cryptCreateSession( &cryptSession, CRYPT_UNUSED, CRYPT_SESSION_CMP );
	if( userID[ 2 ] >= TEXT( 'A' ) && userID[ 2 ] < TEXT( 'Z' ) )
		userID[ 2 ]++;
	else
		userID[ 2 ] = TEXT( 'A' );
	if( issuePW[ 8 ] >= TEXT( 'A' ) && issuePW[ 8 ] < TEXT( 'Z' ) )
		issuePW[ 8 ]++;
	else
		issuePW[ 8 ] = TEXT( 'A' );
	status = cryptSetAttributeString( cryptSession, CRYPT_SESSINFO_USERNAME,
									  userID, paramStrlen( userID ) );
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptSession, CRYPT_SESSINFO_PASSWORD,
										  issuePW, paramStrlen( issuePW ) );
	if( cryptStatusOK( status ) )
		{
		puts( "Integrity check of user ID and password failed to catch "
			  "errors in the data.\n(This check isn't foolproof and is "
			  "intended only to catch typing errors when\nentering the "
			  "data.  Try running the test again to see if the problem "
			  "still\noccurs)." );
		return( FALSE );
		}
	cryptDestroySession( cryptSession );

	/* Clean up */
	cryptDestroyCert( cryptPKIUser );
	return( TRUE );
	}

/* Get information on a PKI user */

int pkiGetUserInfo( C_STR userID, C_STR issuePW, C_STR revPW, C_STR userName )
	{
	CRYPT_KEYSET cryptCertStore;
	CRYPT_CERTIFICATE cryptPKIUser;
	int length, status;

	/* cryptlib implements per-user (rather than shared interop) IDs and
	   passwords so we need to read the user ID and password information
	   before we can perform any operations.  First we get the PkiUser
	   object */
	status = cryptKeysetOpen( &cryptCertStore, CRYPT_UNUSED,
							  CERTSTORE_KEYSET_TYPE, CERTSTORE_KEYSET_NAME,
							  CRYPT_KEYOPT_NONE );
	if( status == CRYPT_ERROR_PARAM3 )
		{
		/* This type of keyset access isn't available, return a special error
		   code to indicate that the test wasn't performed, but that this
		   isn't a reason to abort processing */
		puts( "No certificate store available, aborting CMP test.\n" );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCAGetItem( cryptCertStore, &cryptPKIUser,
							 CRYPT_CERTTYPE_PKIUSER, CRYPT_KEYID_NAME,
							 userName );
	cryptKeysetClose( cryptCertStore );
	if( cryptStatusError( status ) )
		{
		/* Only report error info if it's not a basic presence check */
		if( userID != NULL )
			extErrorExit( cryptCertStore, "cryptCAGetItem()", status, __LINE__ );
		return( FALSE );
		}

	/* If it's a presence check only, we're done */
	if( userID == NULL )
		{
		cryptDestroyCert( cryptPKIUser );
		return( TRUE );
		}

	/* Then we extract the information from the PkiUser object */
	status = cryptGetAttributeString( cryptPKIUser,
									  CRYPT_CERTINFO_PKIUSER_ID,
									  userID, &length );
	if( cryptStatusOK( status ) )
		{
		userID[ length ] = '\0';
		status = cryptGetAttributeString( cryptPKIUser,
									CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD,
									issuePW, &length );
		}
	if( cryptStatusOK( status ) )
		issuePW[ length ] = '\0';
	if( cryptStatusOK( status ) && revPW != NULL )
		{
		status = cryptGetAttributeString( cryptPKIUser,
									CRYPT_CERTINFO_PKIUSER_REVPASSWORD,
									revPW, &length );
		if( cryptStatusOK( status ) )
			revPW[ length ] = '\0';
		}
	cryptDestroyCert( cryptPKIUser );
	if( cryptStatusError( status ) )
		{
		attrErrorExit( cryptPKIUser, "cryptGetAttribute()", status,
					   __LINE__ );
		return( FALSE );
		}

	/* We've got what we need, tell the user what we're doing */
	printf( "Using user name %s, password %s.\n", userID, issuePW );
	return( TRUE );
	}

/* Set up objects and information needed by a server-side PKI session */

int pkiServerInit( CRYPT_CONTEXT *cryptPrivateKey, 
				   CRYPT_KEYSET *cryptCertStore, const C_STR keyFileName,
				   const C_STR keyLabel, const CERT_DATA *pkiUserData,
				   const CERT_DATA *pkiUserCAData, const char *protocolName )
	{
	int status;

	/* Get the cert store to use with the session.  Before we use the store
	   we perform a cleanup action to remove any leftover requests from
	   previous runs */
	status = cryptKeysetOpen( cryptCertStore, CRYPT_UNUSED,
							  CERTSTORE_KEYSET_TYPE, CERTSTORE_KEYSET_NAME,
							  CRYPT_KEYOPT_CREATE );
	if( status == CRYPT_ERROR_PARAM3 )
		{
		/* This type of keyset access isn't available, return a special error
		   code to indicate that the test wasn't performed, but that this
		   isn't a reason to abort processing */
		printf( "SVR: No certificate store available, aborting %s server "
				"test.\n\n", protocolName );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	if( status == CRYPT_ERROR_DUPLICATE )
		status = cryptKeysetOpen( cryptCertStore, CRYPT_UNUSED,
								  CERTSTORE_KEYSET_TYPE, CERTSTORE_KEYSET_NAME,
								  CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: cryptKeysetOpen() failed with error code %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}
	cryptCACertManagement( NULL, CRYPT_CERTACTION_CLEANUP, *cryptCertStore,
						   CRYPT_UNUSED, CRYPT_UNUSED );

	/* Create the EE and CA PKI users */
	puts( "Creating PKI user..." );
	if( !addPKIUser( *cryptCertStore, pkiUserData,
					 !strcmp( protocolName, "SCEP" ) ? TRUE : FALSE ) )
		return( FALSE );
	if( pkiUserCAData != NULL && \
		!addPKIUser( *cryptCertStore, pkiUserCAData,
					 !strcmp( protocolName, "SCEP" ) ? TRUE : FALSE ) )
		return( FALSE );

	/* Get the CA's private key */
	status = getPrivateKey( cryptPrivateKey, keyFileName,
							keyLabel, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: CA private key read failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

/****************************************************************************
*																			*
*								SCEP Routines Test							*
*																			*
****************************************************************************/

/* Get an SCEP CA cert */

static int getScepCACert( const C_STR caCertUrl,
						  CRYPT_CERTIFICATE *cryptCACert )
	{
	CRYPT_KEYSET cryptKeyset;
	int status;

	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_HTTP,
							  caCertUrl, CRYPT_KEYOPT_READONLY );
	if( cryptStatusOK( status ) )
		{
		status = cryptGetPublicKey( cryptKeyset, cryptCACert, CRYPT_KEYID_NAME,
									TEXT( "[None]" ) );
		cryptKeysetClose( cryptKeyset );
		}
	if( cryptStatusError( status ) )
		return( extErrorExit( cryptKeyset, "cryptGetPublicKey()",
							  status, __LINE__ ) );

	return( TRUE );
	}

/* Perform an SCEP test */

static int connectSCEP( const BOOLEAN localSession,
						const BOOLEAN userSuppliesCACert )
	{
	CRYPT_SESSION cryptSession;
	CRYPT_CERTIFICATE cryptRequest, cryptResponse, cryptCACert;
	CRYPT_CONTEXT cryptContext;
#if ( SCEP_NO == 1 )
	C_CHR userID[ 64 ], password[ 64 ];
#endif /* cryptlib SCEP_NO == 1 */
	const C_STR userPtr = scepInfo[ SCEP_NO ].user;
	const C_STR passwordPtr = scepInfo[ SCEP_NO ].password;
	int status;

	printf( "Testing %s SCEP session%s...\n", scepInfo[ SCEP_NO ].name,
			userSuppliesCACert ? "" : " with CA cert read" );

	/* Wait for the server to finish initialising */
	if( localSession && waitMutex() == CRYPT_ERROR_TIMEOUT )
		{
		printf( "Timed out waiting for server to initialise, line %d.\n", 
				__LINE__ );
		return( FALSE );
		}

#if ( SCEP_NO == 1 )
	/* If we're doing a loopback test, make sure that the required user info
	   is present.  If it isn't, the CA auditing will detect a request from
	   a nonexistant user and refuse to issue a certificate */
	if( !pkiGetUserInfo( NULL, NULL, NULL, TEXT( "Test SCEP PKI user" ) ) )
		{
		puts( "CA certificate store doesn't contain the PKI user "
			  "information needed to\nauthenticate certificate issue "
			  "operations, can't perform SCEP test.\n" );
		return( CRYPT_ERROR_NOTAVAIL );
		}
#endif /* cryptlib SCEP_NO == 1 */

	/* Get the issuing CA's cert if required */
	if( userSuppliesCACert )
		{
		if( scepInfo[ SCEP_NO ].caCertUrl != NULL )
			{
			if( !getScepCACert( scepInfo[ SCEP_NO ].caCertUrl, 
								&cryptCACert ) )
				return( FALSE );
			}
		else
			{
			status = importCertFromTemplate( &cryptCACert, 
											 SCEP_CA_FILE_TEMPLATE, SCEP_NO );
			if( cryptStatusError( status ) )
				{
				printf( "Couldn't get SCEP CA certificate, status = %d, "
						"line %d.\n", status, __LINE__ );
				return( FALSE );
				}
			}
		}

	/* cryptlib implements per-user (rather than shared interop) IDs and
	   passwords so we need to read the user ID and password information
	   before we can perform any operations */
#if ( SCEP_NO == 1 )
	status = pkiGetUserInfo( userID, password, NULL,
							 TEXT( "Test SCEP PKI user" ) );
	if( !status || status == CRYPT_ERROR_NOTAVAIL )
		{
		if( userSuppliesCACert )
			cryptDestroyCert( cryptCACert );

		/* If cert store operations aren't available, exit but continue with
		   other tests, otherwise abort the tests */
		return( ( status == CRYPT_ERROR_NOTAVAIL ) ? TRUE : FALSE );
		}
	userPtr = userID;
	passwordPtr = password;
#endif /* cryptlib SCEP_NO == 1 */

	/* Create the SCEP session */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED,
								 CRYPT_SESSION_SCEP );
	if( status == CRYPT_ERROR_PARAM3 )	/* SCEP session access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateSession() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Set up the user and server information */
	status = cryptSetAttributeString( cryptSession,
									  CRYPT_SESSINFO_USERNAME,
									  userPtr, paramStrlen( userPtr ) );
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptSession,
										  CRYPT_SESSINFO_PASSWORD,
										  passwordPtr, paramStrlen( passwordPtr ) );
	if( cryptStatusOK( status ) )
		status = cryptSetAttributeString( cryptSession,
									CRYPT_SESSINFO_SERVER_NAME,
									scepInfo[ SCEP_NO ].url,
									paramStrlen( scepInfo[ SCEP_NO ].url ) );
	if( userSuppliesCACert )
		{
		if( cryptStatusOK( status ) )
			status = cryptSetAttribute( cryptSession,
										CRYPT_SESSINFO_CACERTIFICATE,
										cryptCACert );
		cryptDestroyCert( cryptCACert );
		}
	if( cryptStatusError( status ) )
		{
		printf( "Addition of session information failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Create the (unsigned) PKCS #10 request */
#if ( SCEP_NO == 1 )
	cryptCreateContext( &cryptContext, CRYPT_UNUSED, CRYPT_ALGO_RSA );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL,
							 USER_PRIVKEY_LABEL,
							 paramStrlen( USER_PRIVKEY_LABEL ) );
	status = cryptGenerateKey( cryptContext );
	if( cryptStatusOK( status ) )
#else
	loadRSAContextsEx( CRYPT_UNUSED, NULL, &cryptContext, NULL,
					   USER_PRIVKEY_LABEL );
#endif /* cryptlib SCEP_NO == 1 */
	status = cryptCreateCert( &cryptRequest, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTREQUEST );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptRequest,
							CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusOK( status ) && \
		!addCertFields( cryptRequest, scepRequestData, __LINE__ ) )
		status = CRYPT_ERROR_FAILED;
#if 0
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptRequest, cryptContext );
#endif
	if( cryptStatusError( status ) )
		{
		printf( "Creation of PKCS #10 request failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Set up the private key and request, and activate the session */
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_PRIVATEKEY,
								cryptContext );
	cryptDestroyContext( cryptContext );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_REQUEST,
									cryptRequest );
	cryptDestroyCert( cryptRequest );
	if( cryptStatusError( status ) )
		{
		printf( "cryptSetAttribute() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE, TRUE );
	if( cryptStatusError( status ) )
		{
		printExtError( cryptSession, "Attempt to activate SCEP client "
					   "session", status, __LINE__ );
		cryptDestroySession( cryptSession );
		if( status == CRYPT_ERROR_OPEN || status == CRYPT_ERROR_READ )
			{
			/* These servers are constantly appearing and disappearing so if
			   we get a straight connect error we don't treat it as a serious
			   failure */
			puts( "  (Server could be down, faking it and continuing...)\n" );
			return( CRYPT_ERROR_FAILED );
			}
		return( FALSE );
		}

	/* Print the session security information */
	printFingerprint( cryptSession, FALSE );

	/* Obtain the response information */
	status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_RESPONSE,
								&cryptResponse );
	if( cryptStatusOK( status ) && !userSuppliesCACert )
		status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_RESPONSE,
									&cryptCACert );
	cryptDestroySession( cryptSession );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetAttribute() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
#if ( SCEP_NO != 1 )
	puts( "Returned certificate details are:" );
	printCertInfo( cryptResponse );
	if( !userSuppliesCACert )
		{
		puts( "Returned CA certificate details are:" );
		printCertInfo( cryptCACert );
		}
#endif /* Keep the cryptlib results on one screen */

	/* Clean up */
	cryptDestroyCert( cryptResponse );
	puts( "SCEP client session succeeded.\n" );
	return( TRUE );
	}

int testSessionSCEP( void )
	{
	return( connectSCEP( FALSE, TRUE ) );
	}

int testSessionSCEPCACert( void )
	{
	return( connectSCEP( FALSE, FALSE ) );
	}

int testSessionSCEPServer( void )
	{
	CRYPT_SESSION cryptSession;
	CRYPT_CONTEXT cryptCAKey;
	CRYPT_KEYSET cryptCertStore;
	int status;

	puts( "SVR: Testing SCEP server session ..." );

	/* Perform a test create of a SCEP server session to verify that we can
	   do this test */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED,
								 CRYPT_SESSION_SCEP_SERVER );
	if( status == CRYPT_ERROR_PARAM3 )	/* SCEP session access not available */
		return( CRYPT_ERROR_NOTAVAIL );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: cryptCreateSession() failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	cryptDestroySession( cryptSession );

	/* Set up the server-side objects */
	if( !pkiServerInit( &cryptCAKey, &cryptCertStore, SCEPCA_PRIVKEY_FILE,
						USER_PRIVKEY_LABEL, scepPkiUserData, NULL, "SCEP" ) )
		return( FALSE );

	/* Create the SCEP session and add the CA key and cert store */
	status = cryptCreateSession( &cryptSession, CRYPT_UNUSED,
								 CRYPT_SESSION_SCEP_SERVER );
	if( cryptStatusError( status ) )
		{
		printf( "SVR: cryptCreateSession() failed with error code %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptSession,
							CRYPT_SESSINFO_PRIVATEKEY, cryptCAKey );
	if( cryptStatusOK( status ) )
		status = cryptSetAttribute( cryptSession,
							CRYPT_SESSINFO_KEYSET, cryptCertStore );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptSession, "SVR: cryptSetAttribute()",
							   status, __LINE__ ) );

	/* Tell the client that we're ready to go */
	releaseMutex();

	/* Activate the session */
	status = activatePersistentServerSession( cryptSession, FALSE );
	if( cryptStatusError( status ) )
		{
		cryptKeysetClose( cryptCertStore );
		cryptDestroyContext( cryptCAKey );
		return( extErrorExit( cryptSession, "SVR: Attempt to activate SCEP "
							  "server session", status, __LINE__ ) );
		}

	/* Clean up */
	cryptDestroySession( cryptSession );
	cryptKeysetClose( cryptCertStore );
	cryptDestroyContext( cryptCAKey );

	puts( "SVR: SCEP session succeeded.\n" );
	return( TRUE );
	}

/* Perform a client/server loopback test */

#ifdef WINDOWS_THREADS

unsigned __stdcall scepServerThread( void *dummy )
	{
	acquireMutex();
	testSessionSCEPServer();
	_endthreadex( 0 );
	return( 0 );
	}

int testSessionSCEPClientServer( void )
	{
	HANDLE hThread;
	unsigned threadID;
	int status;

#if ( SCEP_NO != 1 )
	/* Because the code has to handle so many CA-specific peculiarities, we
	   can only perform this test when the CA being used is the cryptlib
	   CA */
	puts( "Error: The local SCEP session test only works with SCEP_NO == 1." );
	return( FALSE );
#endif /* cryptlib CA */

	/* Start the server and wait for it to initialise */
	createMutex();
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, scepServerThread,
										 NULL, 0, &threadID );
	Sleep( 1000 );

	/* Connect to the local server */
	status = connectSCEP( TRUE, TRUE );
	waitForThread( hThread );
	destroyMutex();
	return( status );
	}

int testSessionSCEPCACertClientServer( void )
	{
	HANDLE hThread;
	unsigned threadID;
	int status;

#if ( SCEP_NO != 1 )
	/* Because the code has to handle so many CA-specific peculiarities, we
	   can only perform this test when the CA being used is the cryptlib
	   CA */
	puts( "Error: The local SCEP session test only works with SCEP_NO == 1." );
	return( FALSE );
#endif /* cryptlib CA */

	/* Start the server and wait for it to initialise */
	createMutex();
	hThread = ( HANDLE ) _beginthreadex( NULL, 0, scepServerThread,
										 NULL, 0, &threadID );
	Sleep( 1000 );

	/* Connect to the local server */
	status = connectSCEP( TRUE, FALSE );
	waitForThread( hThread );
	destroyMutex();
	return( status );
	}
#endif /* WINDOWS_THREADS */

#endif /* TEST_SESSION || TEST_SESSION_LOOPBACK */
