/****************************************************************************
*																			*
*					cryptlib Certificate Handling Test Routines				*
*						Copyright Peter Gutmann 1997-2005					*
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

extern BYTE FAR_BSS certBuffer[ BUFFER_SIZE ];

/****************************************************************************
*																			*
*							Certificate Processing Test						*
*																			*
****************************************************************************/

static const CERT_DATA FAR_BSS certRequestData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Smith" ) },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, TEXT( "dave@wetas-r-us.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.wetas-r-us.com" ) },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

static const CERT_DATA FAR_BSS certProcessData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Dave Smith" ) },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, TEXT( "dave@wetas-r-us.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.wetas-r-us.com" ) },

	/* Re-select the subject name after poking around in the altName */
	{ CRYPT_CERTINFO_SUBJECTNAME, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

/* Create a certification request */

static int createCertRequest( void *certRequest,
							  const CRYPT_ALGO_TYPE cryptAlgo,
							  const BOOLEAN useCRMF )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT cryptContext;
	int length, status;

	/* Create a new key */
	cryptCreateContext( &cryptContext, CRYPT_UNUSED, cryptAlgo );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL,
							 TEXT( "Private key" ),
							 paramStrlen( TEXT( "Private key" ) ) );
	status = cryptGenerateKey( cryptContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the certification request */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED, useCRMF ? \
				CRYPT_CERTTYPE_REQUEST_CERT : CRYPT_CERTTYPE_CERTREQUEST );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusError( status ) )
		return( status );
	if( !addCertFields( cryptCert, certRequestData, __LINE__ ) )
		return( -1 );
#ifndef _WIN32_WCE
	if( useCRMF )
		{
		const time_t startTime = time( NULL ) - 1000;
		const time_t endTime = time( NULL ) + 86400;

		/* Since we're using a CRMF request, set some fields that can't
		   be specified in the standard cert request */
		status = cryptSetAttributeString( cryptCert,
					CRYPT_CERTINFO_VALIDFROM, &startTime, sizeof( time_t ) );
		if( cryptStatusOK( status ) )
			status = cryptSetAttributeString( cryptCert,
					CRYPT_CERTINFO_VALIDTO, &endTime, sizeof( time_t ) );
		}
#endif /* _WIN32_WCE */
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, cryptContext );
	if( cryptStatusOK( status ) )
		status = cryptExportCert( certRequest, BUFFER_SIZE, &length,
								  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusOK( status ) )
		status = cryptDestroyCert( cryptCert );
	if( cryptStatusError( status ) )
		return( status );

	/* Clean up */
	cryptDestroyContext( cryptContext );
	return( length );
	}

/* Create a certificate from a cert request */

static int createCertificate( void *certificate, const void *certRequest,
							  const int certReqLength,
							  const CRYPT_CONTEXT caKeyContext )
	{
	CRYPT_CERTIFICATE cryptCert, cryptCertRequest;
	int length, status;

	/* Import and verify the certification request */
	status = cryptImportCert( certRequest, certReqLength, CRYPT_UNUSED,
							  &cryptCertRequest );
	if( cryptStatusOK( status ) )
		status = cryptCheckCert( cryptCertRequest, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the certificate */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_CERTREQUEST, cryptCertRequest );
	if( cryptStatusOK( status ) )
		status = cryptSignCert( cryptCert, caKeyContext );
	if( cryptStatusOK( status ) )
		status = cryptExportCert( certificate, BUFFER_SIZE, &length,
								  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusOK( status ) )
		status = cryptDestroyCert( cryptCert );

	/* Clean up */
	cryptDestroyCert( cryptCertRequest );
	return( ( cryptStatusOK( status ) ) ? length : status );
	}

/* Create a certificate directly, used for algorithms that don't support
   self-signed cert requests */

static int createCertDirect( void *certificate,
							 const CRYPT_ALGO_TYPE cryptAlgo,
							 const CRYPT_CONTEXT caKeyContext )
	{
	CRYPT_CERTIFICATE cryptCert;
	CRYPT_CONTEXT cryptContext;
	int length, status;

	/* Create a new key */
	cryptCreateContext( &cryptContext, CRYPT_UNUSED, cryptAlgo );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL,
							 TEXT( "Private key" ),
							 paramStrlen( TEXT( "Private key" ) ) );
	status = cryptGenerateKey( cryptContext );
	if( cryptStatusError( status ) )
		return( status );

	/* Create the certification */
	status = cryptCreateCert( &cryptCert, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptSetAttribute( cryptCert,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
	if( cryptStatusError( status ) )
		return( status );
	if( !addCertFields( cryptCert, certProcessData, __LINE__ ) )
		return( FALSE );
	status = cryptSignCert( cryptCert, caKeyContext );
	if( cryptStatusOK( status ) )
		status = cryptExportCert( certificate, BUFFER_SIZE, &length,
								  CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
	if( cryptStatusOK( status ) )
		status = cryptDestroyCert( cryptCert );

	/* Clean up */
	cryptDestroyContext( cryptContext );
	return( ( cryptStatusOK( status ) ) ? length : status );
	}

/* Test the full certification process */

static int certProcess( const CRYPT_ALGO_TYPE cryptAlgo,
						const char *algoName,
						const CRYPT_CONTEXT cryptCAKey,
						const BOOLEAN useCRMF )
	{
	CRYPT_CERTIFICATE cryptCert;
	const char *certName = \
			( cryptAlgo == CRYPT_ALGO_RSA ) ? \
				( useCRMF ? "prcrtrsa_c" : "prcrtrsa" ) : \
			( cryptAlgo == CRYPT_ALGO_DSA ) ? "prcrtdsa" : \
			( cryptAlgo == CRYPT_ALGO_DH ) ? "prcrtdh" : \
			( cryptAlgo == CRYPT_ALGO_ELGAMAL ) ? "prcrtelg" : "prcrtxxx";
	int length, status;

	printf( "Testing %s certificate processing%s...\n", algoName,
			useCRMF ? " from CRMF request" : "" );

	/* Some algorithms can't create self-signed cert requests so we have to
	   create the cert directly */
	if( cryptAlgo != CRYPT_ALGO_ELGAMAL && cryptAlgo != CRYPT_ALGO_DH )
		{
		const char *reqName = \
			( cryptAlgo == CRYPT_ALGO_RSA ) ? \
				( useCRMF ? "prreqrsa_c" : "prreqrsa" ) : \
			( cryptAlgo == CRYPT_ALGO_DSA ) ? "prreqdsa" : \
			( cryptAlgo == CRYPT_ALGO_DH ) ? "prreqdh" : \
			( cryptAlgo == CRYPT_ALGO_ELGAMAL ) ? "prreqelg" : "prreqxxx";

		/* Create the certification request */
		status = length = createCertRequest( certBuffer, cryptAlgo, useCRMF );
		if( cryptStatusError( status ) )
			{
			printf( "Certification request creation failed with error code "
					"%d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		debugDump( reqName, certBuffer, length );

		/* Create a certificate from the certification request */
		status = createCertificate( certBuffer, certBuffer, length,
									cryptCAKey );
		}
	else
		status = createCertDirect( certBuffer, cryptAlgo, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate creation failed with error code %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}
	length = status;
	debugDump( certName, certBuffer, length );

	/* Import the certificate and check its validity using the CA key (we use
	   the private key context since it's handy, in practice we should use
	   the public key certificate */
	status = cryptImportCert( certBuffer, length, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusOK( status ) )
		status = cryptCheckCert( cryptCert, cryptCAKey );
	if( cryptStatusError( status ) )
		{
		printf( "Certificate validation failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyCert( cryptCert );
	printf( "%s certificate processing succeeded.\n\n", algoName );
	return( TRUE );
	}

int testCertProcess( void )
	{
	CRYPT_CONTEXT cryptCAKey;
	int status;

	/* Get the CA's private key */
	status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "CA private key read failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Test each PKC algorithm */
	if( !certProcess( CRYPT_ALGO_RSA, "RSA", cryptCAKey, FALSE ) )
		return( FALSE );
	if( !certProcess( CRYPT_ALGO_DSA, "DSA", cryptCAKey, FALSE ) )
		return( FALSE );
	if( !certProcess( CRYPT_ALGO_ELGAMAL, "Elgamal", cryptCAKey, FALSE ) )
		return( FALSE );
	if( !certProcess( CRYPT_ALGO_DH, "Diffie-Hellman", cryptCAKey, FALSE ) )
		return( FALSE );

	/* Run the test again with a CRMF instead of PKCS #10 request */
	if( !certProcess( CRYPT_ALGO_RSA, "RSA", cryptCAKey, TRUE ) )
		return( FALSE );

	/* Clean up */
	cryptDestroyContext( cryptCAKey );
	return( TRUE );
	}

/****************************************************************************
*																			*
*							CA Certificate Management Test					*
*																			*
****************************************************************************/

/* Since opening the cert store for update creates a log entry each time,
   we open it once at the start and then call a series of sub-tests with
   the store open throughout the tests.  This also allows us to keep the
   CA key active througout */

static const CERT_DATA FAR_BSS cert1Data[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Test user 1" ) },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, TEXT( "test1@testusers.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.wetas-r-us.com" ) },

	/* Re-select the subject name after poking around in the altName */
	{ CRYPT_CERTINFO_SUBJECTNAME, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};
static const CERT_DATA FAR_BSS revokableCert1Data[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Revoked cert user 1" ) },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, TEXT( "test2@testusers.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.wetas-r-us.com" ) },

	/* Re-select the subject name after poking around in the altName */
	{ CRYPT_CERTINFO_SUBJECTNAME, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};
static const CERT_DATA FAR_BSS revokableCert2Data[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Revoked cert user 2" ) },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, TEXT( "revoked1@testusers.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.wetas-r-us.com" ) },

	/* Re-select the subject name after poking around in the altName */
	{ CRYPT_CERTINFO_SUBJECTNAME, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};
static const CERT_DATA FAR_BSS expiredCert1Data[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Expired cert user 1" ) },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, TEXT( "revoked2@testusers.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.wetas-r-us.com" ) },

	/* Re-select the subject name after poking around in the altName */
	{ CRYPT_CERTINFO_SUBJECTNAME, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};
static const CERT_DATA FAR_BSS expiredCert2Data[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Expired cert user 2" ) },

	/* Subject altName */
	{ CRYPT_CERTINFO_RFC822NAME, IS_STRING, 0, TEXT( "expired2@testusers.com" ) },
	{ CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, IS_STRING, 0, TEXT( "http://www.wetas-r-us.com" ) },

	/* Re-select the subject name after poking around in the altName */
	{ CRYPT_CERTINFO_SUBJECTNAME, IS_NUMERIC, CRYPT_UNUSED },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};
static const CERT_DATA FAR_BSS certCAData[] = {
	/* Identification information */
	{ CRYPT_CERTINFO_COUNTRYNAME, IS_STRING, 0, TEXT( "NZ" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONNAME, IS_STRING, 0, TEXT( "Dave's Wetaburgers" ) },
	{ CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, IS_STRING, 0, TEXT( "Procurement" ) },
	{ CRYPT_CERTINFO_COMMONNAME, IS_STRING, 0, TEXT( "Test CA user" ) },

	/* CA extensions.  These should be rejected/stripped by the cert
	   management code, since new CAs can only be created by the issuing CA
	   specifying it in the PKI user info */
	{ CRYPT_CERTINFO_KEYUSAGE, IS_NUMERIC,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
	{ CRYPT_CERTINFO_CA, IS_NUMERIC, TRUE },

	{ CRYPT_ATTRIBUTE_NONE, IS_VOID }
	};

/* Add a certification request to the cert store */

static int addCertRequest( const CRYPT_KEYSET cryptCertStore,
						   const CERT_DATA *certReqData,
						   const BOOLEAN isExpired )
	{
	CRYPT_CONTEXT cryptContext;
	CRYPT_CERTIFICATE cryptCertRequest;
	int length, status;

	/* Generate a (short) key for the request */
	cryptCreateContext( &cryptContext, CRYPT_UNUSED, CRYPT_ALGO_RSA );
	cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_LABEL,
							 TEXT( "Private key" ),
							 paramStrlen( TEXT( "Private key" ) ) );
	status = cryptGenerateKey( cryptContext );
	if( cryptStatusError( status ) )
		{
		printf( "Creation of private key for cert failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Create the certification request.  If we're adding an expiry time
	   we have to make it a CRMF request since a standard request can't
	   handle this */
	status = cryptCreateCert( &cryptCertRequest, CRYPT_UNUSED, isExpired ? \
					CRYPT_CERTTYPE_REQUEST_CERT : CRYPT_CERTTYPE_CERTREQUEST );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptCertRequest,
					CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, cryptContext );
#ifndef _WIN32_WCE
	if( cryptStatusOK( status ) && isExpired )
		{
		const time_t theTime = time( NULL ) + 5;

		/* Set the expiry time to a few seconds after the current time to
		   ensure that the cert has expired by the time we need it.  This
		   is a tiny bit risky since it requires that the interval between
		   setting this attribute and the creation of the cert below is
		   less than five seconds, however there's no easy way to guarantee
		   the creation of a pre-expired cert since if we set the time too
		   far back it won't be created */
		status = cryptSetAttributeString( cryptCertRequest,
					CRYPT_CERTINFO_VALIDTO, &theTime, sizeof( time_t ) );
		}
#endif /* _WIN32_WCE */
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCertRequest, "cryptSetAttribute()",
							   status, __LINE__ ) );
	if( !addCertFields( cryptCertRequest, certReqData, __LINE__ ) )
		return( FALSE );
	status = cryptSignCert( cryptCertRequest, cryptContext );
	cryptDestroyContext( cryptContext );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCertRequest, "cryptSignCert()",
							   status, __LINE__ ) );

	/* Export the request, destroy it, and recreate it by importing it again.
	   This is just a pedantic check to make sure that we emulate exactly a
	   real-world scenario of an externally-obtained request */
	status = cryptExportCert( certBuffer, BUFFER_SIZE, &length,
							  CRYPT_CERTFORMAT_CERTIFICATE,
							  cryptCertRequest );
	cryptDestroyCert( cryptCertRequest );
	if( cryptStatusOK( status ) )
		status = cryptImportCert( certBuffer, length, CRYPT_UNUSED,
								  &cryptCertRequest );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't export/re-import cert request, status = %d, "
				"line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	/* Add the request to the cert store */
	status = cryptCAAddItem( cryptCertStore, cryptCertRequest );
	if( cryptStatusError( status ) )
		return( extErrorExit( cryptCertStore, "cryptCAAddItem()", status,
							  __LINE__ ) );

	return( cryptCertRequest );
	}

/* Add a revocation request to the cert store.  This code isn't currently
   used because CMP doesn't allow revocation requests to be signed, so we
   can't create a signed object to add directly but have to come in via
   CMP */

#if 0

static int addRevRequest( const CRYPT_KEYSET cryptCertStore,
						  const CERT_DATA *certReqData )
	{
	CRYPT_CERTIFICATE cryptCert, cryptCertRequest;
	int i, status;

	/* Find the CN of the cert we're revoking and use it to fetch the cert */
	for( i = 0; certReqData[ i ].componentType != CRYPT_ATTRIBUTE_NONE; i++ )
		if( certReqData[ i ].type == CRYPT_CERTINFO_COMMONNAME )
			printf( "Revoking certificate for '%s'.\n",
					( char * ) certReqData[ i ].stringValue );
	status = cryptGetPublicKey( cryptCertStore, &cryptCert, CRYPT_KEYID_NAME,
								certReqData[ i ].stringValue );
	if( cryptStatusError( status ) )
		return( extErrorExit( cryptCertStore, "cryptGetPublicKey()", status,
							  __LINE__ ) );

	/* Create the revocation request */
	status = cryptCreateCert( &cryptCertRequest, CRYPT_UNUSED,
							  CRYPT_CERTTYPE_REQUEST_REVOCATION );
	if( cryptStatusError( status ) )
		{
		printf( "cryptCreateCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptSetAttribute( cryptCertRequest, CRYPT_CERTINFO_CERTIFICATE,
								cryptCert );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCertRequest, "cryptSetAttribute()",
							   status, __LINE__ ) );
	if( !addCertFields( cryptCertRequest, revRequestData, __LINE__ ) )
		return( FALSE );

	/* Add the request to the cert store */
	status = cryptCAAddItem( cryptCertStore, cryptCertRequest );
	if( cryptStatusError( status ) )
		return( extErrorExit( cryptCertStore, "cryptCAAddItem()", status,
							  __LINE__ ) );

	return( cryptCertRequest );
	}
#endif /* 0 */

/* Issue a certificate from a cert request */

static int issueCert( const CRYPT_KEYSET cryptCertStore,
					  const CRYPT_CONTEXT cryptCAKey,
					  const CERT_DATA *certReqData, const BOOLEAN isExpired,
					  const BOOLEAN issueShouldFail )
	{
	CRYPT_CERTIFICATE cryptCertRequest;
	int i, status;

	/* Provide some feedback on what we're doing */
	for( i = 0; certReqData[ i ].componentType != CRYPT_ATTRIBUTE_NONE; i++ )
		if( certReqData[ i ].type == CRYPT_CERTINFO_COMMONNAME )
			printf( "Issuing certificate for '%s'.\n",
					( char * ) certReqData[ i ].stringValue );

	/* Issue the cert via the cert store */
	cryptCertRequest = addCertRequest( cryptCertStore, certReqData, isExpired );
	if( !cryptCertRequest )
		return( FALSE );
	status = cryptCACertManagement( NULL, CRYPT_CERTACTION_ISSUE_CERT,
									cryptCertStore, cryptCAKey,
									cryptCertRequest );
	cryptDestroyCert( cryptCertRequest );
	if( cryptStatusError( status ) )
		{
		if( issueShouldFail )
			/* If this is a check of the request validity-checking system,
			   the issue is supposed to fail */
			return( TRUE );
		if( isExpired && status == CRYPT_ERROR_INVALID )
			{
			puts( "The short-expiry-time certificate has already expired at "
				  "the time of issue.\nThis happened because there was a "
				  "delay of more than 5s between adding the\nrequest and "
				  "issuing the certificate for it.  Try re-running the test "
				  "on a\nless-heavily-loaded system, or increase the expiry "
				  "delay to more than 5s." );
			return( FALSE );
			}
		return( extErrorExit( cryptCertStore, "cryptCACertManagement()",
							  status, __LINE__ ) );
		}

	return( issueShouldFail ? FALSE : TRUE );
	}

/* Issue a CRL.  Although we can't do this directly (see the comment above
   for the revocation request code) we can at least test the ability to
   create an empty CRL (and if the CMP code has been run there will probably
   be a few revocation entries present to fill the CRL) */

static int issueCRL( const CRYPT_KEYSET cryptCertStore,
					 const CRYPT_CONTEXT cryptCAKey )
	{
	CRYPT_CERTIFICATE cryptCRL;
	int noEntries = 0, status;

	/* Issue the CRL via the cert store */
	status = cryptCACertManagement( &cryptCRL, CRYPT_CERTACTION_ISSUE_CRL,
									cryptCertStore, cryptCAKey,
									CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( extErrorExit( cryptCertStore, "cryptCACertManagement()",
							  status, __LINE__ ) );

	/* Print information on the CRL */
	if( cryptStatusOK( cryptSetAttribute( cryptCRL,
										  CRYPT_CERTINFO_CURRENT_CERTIFICATE,
										  CRYPT_CURSOR_FIRST ) ) )
		do
			noEntries++;
		while( cryptSetAttribute( cryptCRL,
								  CRYPT_CERTINFO_CURRENT_CERTIFICATE,
								  CRYPT_CURSOR_NEXT ) == CRYPT_OK );
	printf( "CRL has %d entr%s.\n", noEntries,
			( noEntries == 1 ) ? "y" : "ies" );
	if( !noEntries )
		puts( "  (This is probably because there haven't been any revocation "
			  "entries added\n   via the CMP test yet)." );

	/* Clean up */
	cryptDestroyCert( cryptCRL );
	return( TRUE );
	}

/* Fetch the issued cert that was created from a given cert template */

static CRYPT_CERTIFICATE getCertFromTemplate( const CRYPT_KEYSET cryptCertStore,
											  const CERT_DATA *certReqData )
	{
	CRYPT_CERTIFICATE cryptCert;
	int i, status;

	for( i = 0; certReqData[ i ].componentType != CRYPT_ATTRIBUTE_NONE; i++ )
		if( certReqData[ i ].type == CRYPT_CERTINFO_COMMONNAME )
			break;
	status = cryptGetPublicKey( cryptCertStore, &cryptCert, CRYPT_KEYID_NAME,
							    certReqData[ i ].stringValue );
	return( cryptStatusOK( status ) ? cryptCert : status );
	}

int testCertManagement( void )
	{
	CRYPT_CERTIFICATE cryptCert, cryptCertRequest;
	CRYPT_CONTEXT cryptCAKey;
	CRYPT_KEYSET cryptCertStore;
	time_t certTime;
	int dummy, status;

	puts( "Testing certificate management using cert store..." );

	/* Get the CA's private key */
	status = getPrivateKey( &cryptCAKey, CA_PRIVKEY_FILE,
							CA_PRIVKEY_LABEL, TEST_PRIVKEY_PASSWORD );
	if( cryptStatusError( status ) )
		{
		printf( "CA private key read failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Create the cert store keyset with a check to make sure that this
	   access method exists so we can return an appropriate error message.
	   If the database table already exists, this will return a duplicate
	   data error so we retry the open with no flags to open the existing
	   database keyset for write access */
	status = cryptKeysetOpen( &cryptCertStore, CRYPT_UNUSED,
							  CERTSTORE_KEYSET_TYPE, CERTSTORE_KEYSET_NAME,
							  CRYPT_KEYOPT_CREATE );
	if( cryptStatusOK( status ) )
		puts( "Created new certificate store '" CERTSTORE_KEYSET_NAME_ASCII
			  "'." );
	if( status == CRYPT_ERROR_PARAM3 )
		{
		/* This type of keyset access isn't available, return a special error
		   code to indicate that the test wasn't performed, but that this
		   isn't a reason to abort processing */
		cryptDestroyContext( cryptCAKey );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	if( status == CRYPT_ERROR_DUPLICATE )
		status = cryptKeysetOpen( &cryptCertStore, CRYPT_UNUSED,
								  CERTSTORE_KEYSET_TYPE, CERTSTORE_KEYSET_NAME,
								  CRYPT_KEYOPT_NONE );
	if( cryptStatusError( status ) )
		{
		printf( "cryptKeysetOpen() failed with error code %d, line %d.\n",
				status, __LINE__ );
		if( status == CRYPT_ERROR_OPEN )
			{
			cryptDestroyContext( cryptCAKey );
			return( CRYPT_ERROR_FAILED );
			}
		return( FALSE );
		}

	/* Create a cert request, add it to the store, and destroy it, simulating
	   a delayed cert issue in which the request can't immediately be
	   converted into a cert.  Then read the request back from the store and
	   issue a certificate based on it */
	puts( "Issuing certificate for 'Test user 1'..." );
	cryptCertRequest = addCertRequest( cryptCertStore, cert1Data, FALSE );
	if( !cryptCertRequest )
		return( FALSE );
	cryptDestroyCert( cryptCertRequest );
	status = cryptCAGetItem( cryptCertStore, &cryptCertRequest,
							 CRYPT_CERTTYPE_REQUEST_CERT, CRYPT_KEYID_NAME,
							 TEXT( "Test user 1" ) );
	if( cryptStatusError( status ) )
		return( extErrorExit( cryptCertStore, "cryptCAGetItem()", status,
							  __LINE__ ) );
	status = cryptCACertManagement( &cryptCert, CRYPT_CERTACTION_ISSUE_CERT,
									cryptCertStore, cryptCAKey,
									cryptCertRequest );
	cryptDestroyCert( cryptCertRequest );
	if( cryptStatusError( status ) )
		return( extErrorExit( cryptCertStore, "cryptCACertManagement()",
							  status, __LINE__ ) );
	cryptDestroyCert( cryptCert );

	/* Issue some more certs, this time directly from the request and without
	   bothering to obtain the resulting cert.  The first two have a validity
	   time that expires in a few seconds so that we can use them to test
	   cert expiry processing, we issue these first to ensure that as much
	   time as possible passes due to other operations occurring before we
	   run the expiry.  The second two are for revocation and CRL testing */
	if( !issueCert( cryptCertStore, cryptCAKey, expiredCert1Data, TRUE, FALSE ) )
		return( FALSE );
	if( !issueCert( cryptCertStore, cryptCAKey, expiredCert2Data, TRUE, FALSE ) )
		return( FALSE );
	if( !issueCert( cryptCertStore, cryptCAKey, revokableCert1Data, FALSE, FALSE ) )
		return( FALSE );
	if( !issueCert( cryptCertStore, cryptCAKey, revokableCert2Data, FALSE, FALSE ) )
		return( FALSE );

	/* The following tests are specifically inserted at this point (rather
	   than at some other point in the test run) because they'll add some
	   further delay before the expiry operation */

	/* Try and get a CA cert issued.  This should fail, since new CAs can
	   only be created if the issuing CA specifies it (either directly when
	   it creates the cert manually or via the PKI user info), but never at
	   the request of the user */
	if( !issueCert( cryptCertStore, cryptCAKey, certCAData, FALSE, TRUE ) )
		{
		printf( "Issue of cert from invalid request succeeded when it "
				"should have failed,\nline %d.\n", __LINE__ );
		return( FALSE );
		}

	/* Get a cert and (to-be-)revoked cert from the store and save them to
	   disk for later tests */
	status = cryptCert = getCertFromTemplate( cryptCertStore, cert1Data );
	if( !cryptStatusError( status ) )
		{
		BYTE fileName[ BUFFER_SIZE ];
		FILE *filePtr;
		int length;

		/* First save the CA cert */
		filenameFromTemplate( fileName, OCSP_CA_FILE_TEMPLATE, 1 );
		cryptExportCert( certBuffer, BUFFER_SIZE, &length,
						 CRYPT_CERTFORMAT_CERTIFICATE, cryptCAKey );
		if( ( filePtr = fopen( fileName, "wb" ) ) != NULL )
			{
			fwrite( certBuffer, length, 1, filePtr );
			fclose( filePtr );
			}

		/* Then the EE cert */
		filenameFromTemplate( fileName, OCSP_EEOK_FILE_TEMPLATE, 1 );
		cryptExportCert( certBuffer, BUFFER_SIZE, &length,
						 CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
		if( ( filePtr = fopen( fileName, "wb" ) ) != NULL )
			{
			fwrite( certBuffer, length, 1, filePtr );
			fclose( filePtr );
			}
		cryptDestroyCert( cryptCert );
		}
	if( !cryptStatusError( status ) )
		status = cryptCert = getCertFromTemplate( cryptCertStore,
												  revokableCert1Data );
	if( !cryptStatusError( status ) )
		{
		BYTE fileName[ BUFFER_SIZE ];
		FILE *filePtr;
		int length;

		filenameFromTemplate( fileName, OCSP_EEREV_FILE_TEMPLATE, 1 );
		cryptExportCert( certBuffer, BUFFER_SIZE, &length,
						 CRYPT_CERTFORMAT_CERTIFICATE, cryptCert );
		if( ( filePtr = fopen( fileName, "wb" ) ) != NULL )
			{
			fwrite( certBuffer, length, 1, filePtr );
			fclose( filePtr );
			}
		cryptDestroyCert( cryptCert );
		}
	if( cryptStatusError( status ) )
		puts( "Issued certificates couldn't be fetched from the cert store "
			  "and written to\ndisk, the OCSP server test will abort when it "
			  "fails to find these\ncertificates." );

	/* Issue a CRL.  This will probably be a zero-length CRL unless we've run
	   the CMP tests because we can't directly revoke a cert.  Again, we
	   perform it before the expiry test because it'll add some further
	   delay */
	if( !issueCRL( cryptCertStore, cryptCAKey ) )
		return( FALSE );

	/* Get the most recent of the expired certs and wait for it to expire
	   if necessary */
	status = cryptCert = getCertFromTemplate( cryptCertStore,
											  expiredCert1Data );
	if( !cryptStatusError( status ) )
		status = cryptGetAttributeString( cryptCert, CRYPT_CERTINFO_VALIDTO,
										  &certTime, &dummy );
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't get expiry information for expired cert." );
		return( FALSE );
		}
#ifndef _WIN32_WCE
	if( certTime >= time( NULL ) )
		{
		printf( "Waiting for certificates to expire.." );
		while( certTime >= time( NULL ) )
			{
			delayThread( 1 );
			printf( "." );
			}
		puts( " done." );
		}
#endif /* _WIN32_WCE */
	cryptDestroyCert( cryptCert );

	/* Expire the certs */
	puts( "Expiring certificates..." );
	status = cryptCACertManagement( NULL, CRYPT_CERTACTION_EXPIRE_CERT,
									cryptCertStore, CRYPT_UNUSED,
									CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( extErrorExit( cryptCertStore, "cryptCACertManagement()",
							  status, __LINE__ ) );

	/* Clean up */
	cryptDestroyContext( cryptCAKey );
	cryptKeysetClose( cryptCertStore );
	puts( "Certificate management using cert store succeeded.\n" );
	return( TRUE );
	}
