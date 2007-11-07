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

/****************************************************************************
*																			*
*							Certificate Import Routines Test				*
*																			*
****************************************************************************/

/* Test certificate import code */

static BOOLEAN handleCertError( const CRYPT_CERTIFICATE cryptCert, 
								const int certNo, const int errorCode )
	{
	int errorLocus, status;

	printf( "\n" );
	status = cryptGetAttribute( cryptCert, CRYPT_ATTRIBUTE_ERRORLOCUS, 
								&errorLocus );
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't get error locus for certificate check failure." );
		return( FALSE );
		}

	/* Some old certs use deprecated or now-broken algorithms which will 
	   produce a CRYPT_ERROR_NOTAVAIL if we try and verify the signature, 
	   treat this as a special case */
	if( certNo == 1 && errorCode == CRYPT_ERROR_NOTAVAIL )
		{
		puts( "Warning: The hash/signature algorithm required to verify "
			  "this certificate\n         isn't enabled in this build of "
			  "cryptlib, can't verify the cert\n         signature." );
		return( TRUE );
		}

	/* Make sure that we don't fail just because the cert that we're using 
	   as a test has expired */
	if( errorLocus == CRYPT_CERTINFO_VALIDTO )
		{
		puts( "Warning: Validity check failed because the certificate has "
			  "expired." );
		return( TRUE );
		}

	/* RegTP CA certs are marked as non-CA certs, report the problem and 
	   continue */
	if( certNo == 4 && errorLocus == CRYPT_CERTINFO_CA )
		{
		puts( "Warning: Validity check failed due to RegTP CA certificate "
			  "incorrectly\n         marked as non-CA certificate." );
		return( TRUE );
		}

	/* Cert #26 is a special-case test cert used to check the ability to 
	   detect invalid PKCS #1 padding */
	if( certNo == 26 )
		{
		puts( "Warning: Certificate contains invalid PKCS #1 padding for "
			  "exponent-3 RSA\n         key, the certificate signature is "
			  "invalid." );
		if( errorCode == CRYPT_ERROR_BADDATA )
			{
			puts( "  (This is the correct result for this test)." );
			return( TRUE );
			}

		/* Not detecting this is an error */
		puts( "  (This should have been detected but wasn't)." );
		return( FALSE );
		}

	return( FALSE );
	}

static int certImport( const int certNo, const BOOLEAN isBase64 )
	{
	CRYPT_CERTIFICATE cryptCert;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, value, status;

	printf( "Testing %scertificate #%d import...\n",
			isBase64 ? "base64 " : "", certNo );
	filenameFromTemplate( buffer, isBase64 ? BASE64CERT_FILE_TEMPLATE : \
											 CERT_FILE_TEMPLATE, certNo );
	if( ( filePtr = fopen( buffer, "rb" ) ) == NULL )
		{
		puts( "Couldn't find certificate file for import test." );
		return( FALSE );
		}
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );

	/* Import the certificate */
	status = cryptImportCert( buffer, count, CRYPT_UNUSED,
							  &cryptCert );
#ifdef __UNIX__
	if( status == CRYPT_ERROR_NOTAVAIL || status == CRYPT_ERROR_BADDATA )
		{
		puts( "The certificate import failed, probably because you're "
			  "using an\nolder version of unzip that corrupts "
			  "certain types of files when it\nextracts them.  To fix this, "
			  "you need to re-extract test/*.der without\nusing the -a "
			  "option to convert text files.\n" );
		return( TRUE );		/* Skip this test and continue */
		}
#endif /* __UNIX__ */
	if( status == CRYPT_ERROR_NOSECURE && \
		( certNo == 5 || certNo == 13 || certNo == 14 || certNo == 21 || \
		  certNo == 26 ) )
		{
		/* Some older certs use totally insecure 512-bit keys and can't be
		   processed unless we deliberately allow insecure keys.  
		   Unfortunately this also blocks out the cert that's used to check
		   the ability to handle invalid PKCS #1 padding, since this only
		   uses a 512-bit key, but if necessary it can be tested by lowering 
		   MIN_PKCSIZE when building cryptlib */
		puts( "Warning: Certificate import failed because the certificate "
			  "uses a very short\n         (insecure) key." );
		return( TRUE );
		}
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() for cert #%d failed with error code %d, "
				"line %d.\n", certNo, status, __LINE__ );
		return( FALSE );
		}
	status = cryptGetAttribute( cryptCert, CRYPT_CERTINFO_SELFSIGNED,
								&value );
	if( cryptStatusError( status ) )
		{
		/* Sanity check to make sure that the cert internal state is
		   consistent - this should never happen */
		printf( "Couldn't get cert.self-signed status, status %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}
	if( value )
		{
		printf( "Certificate is self-signed, checking signature... " );
		status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
		if( cryptStatusError( status ) )
			{
			if( !handleCertError( cryptCert, certNo, status ) )
				return( attrErrorExit( cryptCert, "cryptCheckCert()", 
									   status, __LINE__ ) );
			}
		else
			puts( "signature verified." );
		}
	else
		puts( "Certificate is signed, signature key unknown." );

	/* Print information on what we've got */
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Clean up */
	cryptDestroyCert( cryptCert );
	puts( "Certificate import succeeded.\n" );
	return( TRUE );
	}

#if 0	/* Test rig for NISCC cert data */

static void importTestData( void )
	{
	int i;

	for( i = 1; i <= 110000; i++ )
		{
		CRYPT_CERTIFICATE cryptCert;
		FILE *filePtr;
		BYTE buffer[ BUFFER_SIZE ];
		int count, status;

		if( !( i % 100 ) )
			printf( "%06d\r", i );
/*		filenameFromTemplate( buffer, "/tmp/simple_client/%08d", i ); */
/*		filenameFromTemplate( buffer, "/tmp/simple_server/%08d", i ); */
		filenameFromTemplate( buffer, "/tmp/simple_rootca/%08d", i );
		if( ( filePtr = fopen( buffer, "rb" ) ) == NULL )
			break;
		count = fread( buffer, 1, BUFFER_SIZE, filePtr );
		fclose( filePtr );
		status = cryptImportCert( buffer, count, CRYPT_UNUSED,
								  &cryptCert );
		if( cryptStatusOK( status ) )
			cryptDestroyCert( cryptCert );
		}
	}
#endif /* 0 */

int testCertImport( void )
	{
	int i;

	for( i = 1; i <= 26; i++ )
		if( !certImport( i, FALSE ) )
			return( FALSE );
	return( TRUE );
	}

static int certReqImport( const int certNo )
	{
	CRYPT_CERTIFICATE cryptCert;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, complianceValue, status;

	printf( "Testing certificate request #%d import...\n", certNo );
	filenameFromTemplate( buffer, CERTREQ_FILE_TEMPLATE, certNo );
	if( ( filePtr = fopen( buffer, "rb" ) ) == NULL )
		{
		puts( "Couldn't find certificate file for import test." );
		return( FALSE );
		}
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );

	/* Import the certificate request and check that the signature is valid */
	if( certNo == 3 )
		{
		/* Some of the requests are broken and we have to set the compliance
		   level to oblivious to handle them */
		cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
						   &complianceValue );
		cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
						   CRYPT_COMPLIANCELEVEL_OBLIVIOUS );
		}
	status = cryptImportCert( buffer, count, CRYPT_UNUSED,
							  &cryptCert );
	if( certNo == 3 )
		cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
						   complianceValue );
#ifdef __UNIX__
	if( status == CRYPT_ERROR_NOTAVAIL || status == CRYPT_ERROR_BADDATA )
		{
		puts( "The certificate request import failed, probably because "
			  "you're using an\nolder version of unzip that corrupts "
			  "certain types of files when it\nextracts them.  To fix this, "
			  "you need to re-extract test/*.der without\nusing the -a "
			  "option to convert text files.\n" );
		return( TRUE );		/* Skip this test and continue */
		}
#endif /* __UNIX__ */
	if( status == CRYPT_ERROR_NOSECURE && certNo == 1 )
		{
		puts( "Warning: Cert.request import failed because the request "
			  "uses a very short\n         (insecure) key." );
		return( TRUE );
		}
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "Checking signature... " );
	status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status, 
							   __LINE__ ) );
	puts( "signature verified." );

	/* Print information on what we've got */
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Clean up */
	cryptDestroyCert( cryptCert );
	puts( "Certificate request import succeeded.\n" );
	return( TRUE );
	}

int testCertReqImport( void )
	{
	int i;

	for( i = 1; i <= 3; i++ )
		if( !certReqImport( i ) )
			return( FALSE );
	return( TRUE );
	}

#define LARGE_CRL_SIZE	32767	/* Large CRL is too big for std.buffer */

static int crlImport( const int crlNo, BYTE *buffer )
	{
	CRYPT_CERTIFICATE cryptCert;
	FILE *filePtr;
	int count, status;

	filenameFromTemplate( buffer, CRL_FILE_TEMPLATE, crlNo );
	if( ( filePtr = fopen( buffer, "rb" ) ) == NULL )
		{
		printf( "Couldn't find CRL file for CRL #%d import test.\n", crlNo );
		return( FALSE );
		}
	count = fread( buffer, 1, LARGE_CRL_SIZE, filePtr );
	fclose( filePtr );
	printf( "CRL #%d has size %d bytes.\n", crlNo, count );

	/* Import the CRL.  Since CRL's don't include the signing cert, we can't
	   (easily) check the signature on it */
	status = cryptImportCert( buffer, count, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Print information on what we've got and clean up */
	if( !printCertInfo( cryptCert ) )
		return( FALSE );
	cryptDestroyCert( cryptCert );

	return( TRUE );
	}

int testCRLImport( void )
	{
	BYTE *bufPtr;
	int i;

	puts( "Testing CRL import..." );

	/* Since we're working with an unusually large cert object we have to
	   dynamically allocate the buffer for it */
	if( ( bufPtr = malloc( LARGE_CRL_SIZE ) ) == NULL )
		{
		puts( "Out of memory." );
		return( FALSE );
		}
	for( i = 1; i <= 3; i++ )
		if( !crlImport( i, bufPtr ) )
			return( FALSE );

	/* Clean up */
	free( bufPtr );
	puts( "CRL import succeeded.\n" );
	return( TRUE );
	}

static BOOLEAN handleCertChainError( const CRYPT_CERTIFICATE cryptCertChain, 
									 const int certNo, const int errorCode )
	{
	int trustValue = CRYPT_UNUSED, complianceValue = CRYPT_UNUSED;
	int errorLocus, status;

	/* If the chain contains a single non-CA cert, we'll get a parameter 
	   error since we haven't supplied a signing cert */
	if( errorCode == CRYPT_ERROR_PARAM2 )
		{
		cryptSetAttribute( cryptCertChain, CRYPT_CERTINFO_CURRENT_CERTIFICATE,
						   CRYPT_CURSOR_FIRST );
		if( cryptSetAttribute( cryptCertChain,
							   CRYPT_CERTINFO_CURRENT_CERTIFICATE,
							   CRYPT_CURSOR_NEXT ) == CRYPT_ERROR_NOTFOUND )
			{
			/* There's only a single cert present, we can't do much with 
			   it */
			puts( "\nCertificate chain contains only a single standalone "
				  "cert, skipping\nsignature check..." );
			return( TRUE );
			}
		}

	/* If it's not a problem with validity, we can't go any further */
	if( errorCode != CRYPT_ERROR_INVALID )
		return( attrErrorExit( cryptCertChain, "cryptCheckCert()", 
							   errorCode, __LINE__ ) );

	/* Check the nature of the problem */
	status = cryptGetAttribute( cryptCertChain, CRYPT_ATTRIBUTE_ERRORLOCUS,
								&errorLocus );
	if( cryptStatusError( status ) )
		{
		puts( "Couldn't get error locus for certificate check failure." );
		return( FALSE );
		}

	/* Try to work around the error */
	status = errorCode;
	if( errorLocus == CRYPT_CERTINFO_TRUSTED_IMPLICIT || \
		errorLocus == CRYPT_CERTINFO_TRUSTED_USAGE )
		{
		/* The error occured because of a problem with the root cert, try 
		   again with an implicitly-trusted root */
		if( errorLocus == CRYPT_CERTINFO_TRUSTED_IMPLICIT )
			printf( "\nWarning: The certificate chain didn't verify "
					"because it didn't end in a\n         trusted root "
					"certificate.  Checking again using an "
					"implicitly\n         trusted root..." );
		else
			printf( "\nWarning: The certificate chain didn't verify "
					"because the root certificate's\n         key isn't "
					"enabled for this usage.  Checking again using "
					"an\n         implicitly trusted root..." );
		if( cryptStatusError( \
				setRootTrust( cryptCertChain, &trustValue, 1 ) ) )
			{
			printf( "\nAttempt to make chain root implicitly trusted "
					"failed, status = %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		status = cryptCheckCert( cryptCertChain, CRYPT_UNUSED );
		if( status == CRYPT_ERROR_INVALID )
			cryptGetAttribute( cryptCertChain, CRYPT_ATTRIBUTE_ERRORLOCUS,
							   &errorLocus );
		}
	if( errorLocus == CRYPT_CERTINFO_VALIDTO )
		{
		/* One (or more) certs in the chain have expired, try again with the 
		   compliance level wound down to nothing */
		puts( "\nThe certificate chain didn't verify because one or more "
			  "certificates in it\nhave expired.  Trying again in oblivious "
			  "mode..." );
		cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
						   &complianceValue );
		cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
						   CRYPT_COMPLIANCELEVEL_OBLIVIOUS );
		status = cryptCheckCert( cryptCertChain, CRYPT_UNUSED );
		}

	/* If we changed settings, restore their original values */
	if( trustValue != CRYPT_UNUSED )
		setRootTrust( cryptCertChain, NULL, trustValue );
	if( complianceValue != CRYPT_UNUSED )
		cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
						   complianceValue );

	/* Some old certs use deprecated or now-broken algorithms which will 
	   produce a CRYPT_ERROR_NOTAVAIL if we try and verify the signature, 
	   treat this as a special case */
	if( certNo == 2 && status == CRYPT_ERROR_NOTAVAIL )
		{
		puts( "\nWarning: The hash/signature algorithm required to verify "
			  "this certificate\n         isn't enabled in this build of "
			  "cryptlib, can't verify the cert\n         signature." );
		return( TRUE );
		}

	/* If the lowered-limits check still didn't work, it's an error */
	if( cryptStatusError( status ) )
		{
		putchar( '\n' );
		return( attrErrorExit( cryptCertChain, "cryptCheckCert()", status, 
							   __LINE__ ) );
		}

	puts( "signatures verified." );
	return( TRUE );
	}

static int certChainImport( const int certNo, const BOOLEAN isBase64 )
	{
	CRYPT_CERTIFICATE cryptCertChain;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, status;

	printf( "Testing %scert chain #%d import...\n",
			isBase64 ? "base64 " : "", certNo );
	filenameFromTemplate( buffer, isBase64 ? BASE64CERTCHAIN_FILE_TEMPLATE : \
											 CERTCHAIN_FILE_TEMPLATE, certNo );
	if( ( filePtr = fopen( buffer, "rb" ) ) == NULL )
		{
		puts( "Couldn't find certificate chain file for import test." );
		return( FALSE );
		}
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	if( count == BUFFER_SIZE )
		{
		puts( "The certificate buffer size is too small for the certificate "
			  "chain.  To fix\nthis, increase the BUFFER_SIZE value in "
			  "test/testcert.c and recompile the code." );
		return( TRUE );		/* Skip this test and continue */
		}
	printf( "Certificate chain has size %d bytes.\n", count );

	/* Import the certificate chain.  This assumes that the default certs are
	   installed as trusted certs, which is required for cryptCheckCert() */
	status = cryptImportCert( buffer, count, CRYPT_UNUSED,
							  &cryptCertChain );
	if( cryptStatusError( status ) )
		{
		/* If we failed on the RSA e=3 cert, this is a valid result */
		if( certNo == 3 && status == CRYPT_ERROR_BADDATA )
			{
			printf( "Import of certificate with invalid e=3 key failed, "
					"line %d.\n", __LINE__ );
			puts( "  (This is the correct result for this test)." );
			return( TRUE );
			}
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	if( certNo == 3 )
		{
		printf( "Import of certificate with invalid e=3 key succeeded when "
				"it should have\n  failed, line %d.\n", __LINE__ );
		return( FALSE );
		}
	printf( "Checking signatures... " );
	status = cryptCheckCert( cryptCertChain, CRYPT_UNUSED );
	if( cryptStatusError( status ) && \
		!handleCertChainError( cryptCertChain, certNo, status ) )
		return( FALSE );	
	puts( "signatures verified." );

	/* Display info on each cert in the chain */
	if( !printCertChainInfo( cryptCertChain ) )
		return( FALSE );

	/* Clean up */
	cryptDestroyCert( cryptCertChain );
	puts( "Certificate chain import succeeded.\n" );
	return( TRUE );
	}

int testCertChainImport( void )
	{
	int i;

	for( i = 1; i <= 3; i++ )
		if( !certChainImport( i, FALSE ) )
			return( FALSE );
	return( TRUE );
	}

int testOCSPImport( void )
	{
	CRYPT_CERTIFICATE cryptCert, cryptResponderCert;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, status;

	if( ( filePtr = fopen( convertFileName( OCSP_OK_FILE ), "rb" ) ) == NULL )
		{
		puts( "Couldn't find OCSP OK response file for import test." );
		return( FALSE );
		}
	puts( "Testing OCSP OK response import..." );
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	printf( "OCSP OK response has size %d bytes.\n", count );

	/* Import the OCSP OK response.  Because of the choose-your-own-trust-
	   model status of the OCSP RFC we have to supply our own signature
	   check cert to verify the response */
	status = cryptImportCert( buffer, count, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	printf( "Checking signature... " );
	status = importCertFile( &cryptResponderCert, OCSP_CA_FILE );
	if( cryptStatusOK( status ) )
		{
		status = cryptCheckCert( cryptCert, cryptResponderCert );
		cryptDestroyCert( cryptResponderCert );
		}
	if( cryptStatusError( status ) )
		return( attrErrorExit( cryptCert, "cryptCheckCert()", status,
							   __LINE__ ) );
	puts( "signatures verified." );

	/* Print information on what we've got */
	if( !printCertInfo( cryptCert ) )
		return( FALSE );
	cryptDestroyCert( cryptCert );

	/* Now import the OCSP revoked response.  This has a different CA cert
	   than the OK response, to keep things simple we don't bother with a
	   sig check for this one */
	puts( "Testing OCSP revoked response import..." );
	if( ( filePtr = fopen( convertFileName( OCSP_REV_FILE ), "rb" ) ) == NULL )
		{
		puts( "Couldn't find OCSP revoked response file for import test." );
		return( FALSE );
		}
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	printf( "OCSP revoked response has size %d bytes.\n", count );
	status = cryptImportCert( buffer, count, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) )
		{
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Print information on what we've got */
	if( !printCertInfo( cryptCert ) )
		return( FALSE );

	/* Clean up */
	cryptDestroyCert( cryptCert );
	puts( "OCSP import succeeded.\n" );
	return( TRUE );
	}

int testBase64CertImport( void )
	{
	int i;

	/* If this is an EBCDIC system, we can't (easily) import the base64-
	   encoded cert without complex calisthenics to handle the different
	   character sets */
#if 'A' == 0xC1
	puts( "Skipping import of base64-encoded data on EBCDIC system.\n" );
	return( TRUE );
#endif /* EBCDIC system */

	for( i = 1; i <= 1; i++ )
		if( !certImport( i, TRUE ) )
			return( FALSE );
	return( TRUE );
	}

int testBase64CertChainImport( void )
	{
	int i;

	/* If this is an EBCDIC system, we can't (easily) import the base64-
	   encoded cert without complex calisthenics to handle the different
	   character sets */
#if 'A' == 0xC1
	puts( "Skipping import of base64-encoded data on EBCDIC system.\n" );
	return( TRUE );
#endif /* EBCDIC system */

	for( i = 1; i <= 1; i++ )
		if( !certChainImport( i, TRUE ) )
			return( FALSE );
	return( TRUE );
	}

static int miscImport( const char *fileName, const char *description )
	{
	CRYPT_CERTIFICATE cryptCert;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, status;

	if( ( filePtr = fopen( fileName, "rb" ) ) == NULL )
		{
		printf( "Couldn't find file for %s key import test.\n",
				description );
		return( FALSE );
		}
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );

	/* Import the object.  Since this isn't a certificate we can't do much
	   more with it than this - this is only used to test the low-level
	   code and needs to be run inside a debugger, since the call always
	   fails (the data being imported isn't a certificate) */
	status = cryptImportCert( buffer, count, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusError( status ) && status != CRYPT_ERROR_BADDATA )
		{
		printf( "cryptImportCert() for %s key failed with error code %d, "
				"line %d.\n", description, status, __LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyCert( cryptCert );
	return( TRUE );
	}

int testMiscImport( void )
	{
	BYTE buffer[ BUFFER_SIZE ];
	int i;

	puts( "Testing base64-encoded SSH/PGP key import..." );
	for( i = 1; i <= 2; i++ )
		{
		filenameFromTemplate( buffer, SSHKEY_FILE_TEMPLATE, i );
		if( !miscImport( buffer, "SSH" ) )
			return( FALSE );
		}
	for( i = 1; i <= 3; i++ )
		{
		filenameFromTemplate( buffer, PGPKEY_FILE_TEMPLATE, i );
		if( !miscImport( buffer, "PGP" ) )
			return( FALSE );
		}
	puts( "Import succeeded.\n" );
	return( TRUE );
	}

/* Test handling of certs that chain by DN but not by keyID */

int testNonchainCert( void )
	{
	CRYPT_CERTIFICATE cryptLeafCert, cryptCACert;
	int value, status;

	puts( "Testing handling of incorrectly chained certs..." );

	/* Since this test requires the use of attributes that aren't decoded at
	   the default compliance level, we have to raise it a notch to make sure
	   that we get the cert attributes necessary to sort out the mess */
	cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   &value );
	if( value < CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL )
		cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
						   CRYPT_COMPLIANCELEVEL_PKIX_PARTIAL );

	/* Get the EE and incorrectly chained CA certs */
	status = importCertFile( &cryptLeafCert, NOCHAIN_EE_FILE );
	if( cryptStatusOK( status ) )
		status = importCertFile( &cryptCACert, NOCHAIN_CA_FILE );
	if( cryptStatusError( status ) )
		return( FALSE );

	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   value );

	/* Check the EE cert using the apparently-correct but actually incorrect
	   CA cert and make sure that we get the correct error message */
	status = cryptCheckCert( cryptLeafCert, cryptCACert );
	if( status != CRYPT_ERROR_SIGNATURE )
		{
		printf( "Sig.check of incorrectly chained cert returned %d, should "
				"have been %d, line %d.\n", status, CRYPT_ERROR_SIGNATURE, 
				__LINE__ );
		return( FALSE );
		}

	/* Clean up */
	cryptDestroyCert( cryptLeafCert );
	cryptDestroyCert( cryptCACert );

	puts( "Handling of incorrectly chained certs succeeded.\n" );
	return( TRUE );
	}

/* Test cert handling at various levels of compliance */

int testCertComplianceLevel( void )
	{
	CRYPT_CERTIFICATE cryptCert, cryptCaCert;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count, value, status;

	cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   &value );

	/* Test import of a broken cert.  First we try it in normal mode, then
	   again in oblivious mode */
	printf( "Testing cert handling at various compliance levels "
			"(current = %d)...\n", value );
	if( ( filePtr = fopen( convertFileName( BROKEN_CERT_FILE ), "rb" ) ) == NULL )
		{
		puts( "Couldn't certificate for import test." );
		return( FALSE );
		}
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
	if( value < CRYPT_COMPLIANCELEVEL_PKIX_FULL )
		cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
						   CRYPT_COMPLIANCELEVEL_PKIX_FULL );
	status = cryptImportCert( buffer, count, CRYPT_UNUSED,
							  &cryptCert );
	if( cryptStatusOK( status ) )
		{
		/* Import in normal mode should fail */
		cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
						   value );
		printf( "cryptImportCert() of broken cert succeeded when it should "
				"have failed, line %d.\n", __LINE__ );
		return( FALSE );
		}
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   CRYPT_COMPLIANCELEVEL_STANDARD );
	status = cryptImportCert( buffer, count, CRYPT_UNUSED,
							  &cryptCert );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   value );
	if( cryptStatusError( status ) )
		{
		/* Import in reduced-compliance mode should succeed */
		printf( "cryptImportCert() failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}

	/* Print information on what we've got.  This should only print info for
	   the two basic extensions that are handled in oblivious mode  */
	if( !printCertInfo( cryptCert ) )
		return( FALSE );
	cryptDestroyCert( cryptCert );

	/* Test checking of an expired cert using a broken CA cert in oblivious
	   mode (this checks chaining and the signature, but little else) */
	status = importCertFile( &cryptCert, BROKEN_USER_CERT_FILE );
	if( cryptStatusOK( status ) )
		status = importCertFile( &cryptCaCert, BROKEN_CA_CERT_FILE );
	if( cryptStatusError( status ) )
		{
		printf( "Cert import failed with error code %d, line %d.\n",
				status, __LINE__ );
		return( FALSE );
		}
	status = cryptCheckCert( cryptCert, cryptCaCert );
	if( cryptStatusOK( status ) )
		{
		/* Checking in normal mode should fail */
		printf( "cryptCheckCert() of broken cert succeeded when it should "
				"have failed, line %d.\n", __LINE__ );
		return( FALSE );
		}
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   CRYPT_COMPLIANCELEVEL_OBLIVIOUS );
	status = cryptCheckCert( cryptCert, cryptCaCert );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   value );
	if( cryptStatusError( status ) )
		{
		/* Checking in oblivious mode should succeed */
		printf( "cryptCheckCert() of broken cert failed when it should "
				"have succeeded, line %d.\n", __LINE__ );
		return( FALSE );
		}
	cryptDestroyCert( cryptCaCert );
	cryptDestroyCert( cryptCert );

	/* Clean up */
	puts( "Certificate handling at different compliance levels succeeded.\n" );
	return( TRUE );
	}

/* Test path processing using the NIST PKI test suite.  This doesn't run all
   of the tests since some are somewhat redundant (e.g. path length
   constraints ending at cert n in a chain vs.cert n+1 in a chain where
   both are well short of the constraint length), or require complex
   additional processing (e.g. CRL fetches) which it's difficult to
   automate */

typedef struct {
	const int fileMajor, fileMinor;	/* Major and minor number of file */
	const BOOLEAN isValid;			/* Whether path is valid */
	const BOOLEAN policyOptional;	/* Whether explicit policy optional */
	} PATH_TEST_INFO;

static const PATH_TEST_INFO FAR_BSS pathTestInfo[] = {
	/* Signature verification */
	/*  0 */ { 1, 1, TRUE },
	/*  1 */ { 1, 2, FALSE },
	/*  2 */ { 1, 3, FALSE },
	/*  3 */ { 1, 4, TRUE },
	/*  4 */ { 1, 6, FALSE },

	/* Validity periods */
	/*  5 */ { 2, 1, FALSE },
	/*  6 */ { 2, 2, FALSE },
	/* The second cert in test 4.2.3 has a validFrom date of 1950, which
	   cryptlib rejects on import as being not even remotely valid (it can't
	   even be represented in the ANSI/ISO C date format).  Supposedly half-
	   century-old certs are symptomatic of severely broken software, so
	   rejecting this cert is justified */
/*	{ 2, 3, TRUE }, */
	/*  7 */ { 2, 4, TRUE },
	/*  8 */ { 2, 5, FALSE },
	/*  9 */ { 2, 6, FALSE },
	/* 10 */ { 2, 7, FALSE },
	/* 11 */ { 2, 8, TRUE },

	/* Name chaining */
	/* 12 */ { 3, 1, FALSE },
	/* 13 */ { 3, 6, TRUE },
	/* 14 */ { 3, 8, TRUE },
	/* 15 */ { 3, 9, TRUE },

	/* 4 = CRLs */

	/* oldWithNew / newWithOld */
	/* 16 */ { 5, 1, TRUE },
	/* 17 */ { 5, 3, TRUE },

	/* Basic constraints */
	/* 18 */ { 6, 1, FALSE },
	/* 19 */ { 6, 2, FALSE },
	/* 20 */ { 6, 5, FALSE },
	/* 21 */ { 6, 6, FALSE },
	/* 22 */ { 6, 7, TRUE },
	/* The second-to-last cert in the path sets a pathLenConstraint of zero,
	   with the next cert being a CA cert (there's no EE cert present).
	   cryptlib treats this as invalid since it can never lead to a valid
	   path once the EE cert is added */
	/* 23 */ { 6, 8, FALSE /* TRUE */ },
	/* 24 */ { 6, 9, FALSE },
	/* 25 */ { 6, 11, FALSE },
	/* 26 */ { 6, 12, FALSE },
	/* 27 */ { 6, 13, TRUE },
	/* As for 4.6.8 */
	/* 28 */ { 6, 14, FALSE /* TRUE */ },
	/* The following are 4.5.x-style  oldWithNew / newWithOld, but with path
	   constraints */
	/* 29 */ { 6, 15, TRUE },
	/* 30 */ { 6, 16, FALSE },
	/* 31 */ { 6, 17, TRUE },

	/* Key usage */
	/* 32 */ { 7, 1, FALSE },
	/* 33 */ { 7, 2, FALSE },

	/* Policies */
	/* The first cert asserts a policy that differs from that of all other
	   certs in the path.  If no explicit policy is required (by setting
	   CRYPT_OPTION_REQUIREPOLICY to FALSE) it will verify, otherwise it
	   won't */
	/* 34 */ { 8, 3, TRUE, TRUE },	/* Policy optional */
	/* 35 */ { 8, 3, FALSE },
	/* 36 */ { 8, 4, FALSE },
	/* 37 */ { 8, 6, TRUE },
	/* 38 */ { 8, 10, TRUE },
	/* 39 */ { 8, 11, TRUE },
	/* 40 */ { 8, 14, TRUE },
	/* 41 */ { 8, 15, TRUE },
	/* 42 */ { 8, 20, TRUE },

	/* Policy constraints.  For these tests policy handling is dictated by
	   policy constraints so we don't require explicit policies */
	/* 43 */ { 9, 2, TRUE, TRUE },
	/* The NIST test value for this one is wrong.  RFC 3280 section 4.2.1.12
	   says:

		If the requireExplicitPolicy field is present, the value of
		requireExplicitPolicy indicates the number of additional
		certificates that may appear in the path before an explicit policy
		is required for the entire path.  When an explicit policy is
		required, it is necessary for all certificates in the path to
		contain an acceptable policy identifier in the certificate policies
		extension.

	   Test 4.9.3 has requireExplicitPolicy = 4 in a chain of 4 certs, for
	   which the last one has no policy.  NIST claims this shouldn't
	   validate, which is incorrect */
	/* 44 */ { 9, 3, TRUE /* FALSE */, TRUE },
	/* 45 */ { 9, 4, TRUE, TRUE },
	/* 46 */ { 9, 5, FALSE, TRUE },
	/* 47 */ { 9, 6, TRUE, TRUE },
	/* 48 */ { 9, 7, FALSE, TRUE },

	/* 10, 11 = Policy mappings */
	/* 49 */ { 10, 7, FALSE },
	/* 50 */ { 10, 8, FALSE },

	/* Policy inhibitAny */
	/* 51 */ { 12, 1, FALSE },
	/* 52 */ { 12, 2, TRUE },
	/* 53 */ { 12, 3, TRUE },
	/* 54 */ { 12, 4, FALSE },
	/* The NIST test results for 4.12.7 and 4.12.9 are wrong, or more
	   specifically the PKIX spec is wrong, contradicting itself in the body
	   of the spec and the path-processing pseudocode, in that there's no
	   path-kludge exception for policy constraints in the body, but there
	   is one in the pseudocode.  Since these chains contain path-kludge
	   certs, the paths are invalid - they would only be valid if there was
	   a path-kludge exception for inhibitAnyPolicy.  Note that 4.9.7 and
	   4.9.8 have the same conditions for requireExplicitPolicy, but this
	   time the NIST test results go the other way.  So although the PKIX
	   spec is wrong, the NIST test is also wrong in that it applies an
	   inconsistent interpretation of the contradictions in the PKIX spec */
	/* 55 */ { 12, 7, FALSE /* TRUE */ },
	/* 56 */ { 12, 8, FALSE },
	/* 57 */ { 12, 9, FALSE /* TRUE */ },

	/* Name constraints */
	/* 58 */ { 13, 1, TRUE },
	/* 59 */ { 13, 2, FALSE },
	/* 60 */ { 13, 3, FALSE },
	/* 61 */ { 13, 4, TRUE },
	/* 62 */ { 13, 5, TRUE },
	/* 63 */ { 13, 6, TRUE },
	/* 64 */ { 13, 7, FALSE },
	/* 65 */ { 13, 8, FALSE },
	/* 66 */ { 13, 9, FALSE },
	/* 67 */ { 13, 10, FALSE },
	/* 68 */ { 13, 11, TRUE },
	/* 69 */ { 13, 12, FALSE },
	/* 70 */ { 13, 13, FALSE },
	/* 71 */ { 13, 14, TRUE },
	/* 72 */ { 13, 15, FALSE },
	/* 73 */ { 13, 17, FALSE },
	/* 74 */ { 13, 18, TRUE },
	/* 75 */ { 13, 19, TRUE },
	/* 76 */ { 13, 20, FALSE },
	/* 77 */ { 13, 21, TRUE },
	/* 78 */ { 13, 22, FALSE },
	/* 79 */ { 13, 23, TRUE },
	/* 80 */ { 13, 24, FALSE },
	/* 81 */ { 13, 25, TRUE },
	/* 82 */ { 13, 26, FALSE },
	/* 83 */ { 13, 27, TRUE },
	/* 84 */ { 13, 28, FALSE },
	/* 85 */ { 13, 29, FALSE },
	/* 86 */ { 13, 30, TRUE },
	/* 87 */ { 13, 31, FALSE },
	/* 88 */ { 13, 32, TRUE },
	/* 89 */ { 13, 33, FALSE },
	/* 90 */ { 13, 34, TRUE },
	/* 91 */ { 13, 35, FALSE },
	/* 92 */ { 13, 36, TRUE },
	/* 93 */ { 13, 37, FALSE },
	/* The NIST test results for 4.13.38 are wrong.  PKIX section 4.2.1.11
	   says:

		DNS name restrictions are expressed as foo.bar.com.  Any DNS name
		that can be constructed by simply adding to the left hand side of
		the name satisfies the name constraint.  For example,
		www.foo.bar.com would satisfy the constraint but foo1.bar.com would
		not.

	   The permitted subtree is testcertificates.gov and the altName is
	   mytestcertificates.gov, which satisfies the above rule, so the path
	   should be valid and not invalid */
	/* 94 */ { 13, 38, TRUE /* FALSE */ },

	/* 14, 15 = CRLs */

	/* Private cert extensions */
	/* 95 */ { 16, 1, TRUE },
	/* 96 */ { 16, 2, FALSE },
	{ 0, 0 }
	};

static int testPath( const PATH_TEST_INFO *pathInfo )
	{
	CRYPT_CERTIFICATE cryptCertPath;
	char pathName[ 64 ];
	int pathNo, requirePolicy, status;

	/* Convert the composite path info into a single number used for fetching
	   the corresponding data file */
	sprintf( pathName, "4%d%d", pathInfo->fileMajor, pathInfo->fileMinor );
	pathNo = atoi( pathName );

	/* Test the path */
	sprintf( pathName, "4.%d.%d", pathInfo->fileMajor, pathInfo->fileMinor );
	printf( "  Path %s%s...", pathName, pathInfo->policyOptional ? \
			" without explicit policy" : "" );
	status = importCertFromTemplate( &cryptCertPath,
									 PATHTEST_FILE_TEMPLATE, pathNo );
	if( cryptStatusError( status ) )
		{
		printf( "Cert import for test path %s failed, line %d.\n",
				pathName, __LINE__ );
		return( FALSE );
		}
	if( pathInfo->policyOptional )
		{
		/* By default we require policy chaining, for some tests we can turn
		   this off to check non-explict policy processing */
		cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_REQUIREPOLICY,
						   &requirePolicy );
		assert( requirePolicy != FALSE );
		cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_REQUIREPOLICY,
						   FALSE );
		}
	status = cryptCheckCert( cryptCertPath, CRYPT_UNUSED );
	if( pathInfo->policyOptional )
		cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_REQUIREPOLICY,
						   requirePolicy );
	if( pathInfo->isValid )
		{
		if( cryptStatusError( status ) )
			{
			puts( " didn't verify even though it should be valid." );
			return( attrErrorExit( cryptCertPath, "cryptCheckCert()",
								   status, __LINE__ ) );
			}
		}
	else
		if( cryptStatusOK( status ) )
			{
			puts( " verified even though it should have failed." );
			return( FALSE );
			}
	puts( " succeeded." );
	cryptDestroyCert( cryptCertPath );

	return( TRUE );
	}

int testPathProcessing( void )
	{
	CRYPT_CERTIFICATE cryptRootCert;
	int certTrust, complianceLevel, i, status;

	puts( "Testing path processing..." );

	/* Get the root cert and make it implicitly trusted and crank the
	   compliance level up to maximum, since we're going to be testing some
	   pretty obscure extensions */
	status = importCertFromTemplate( &cryptRootCert,
									 PATHTEST_FILE_TEMPLATE, 0 );
	if( cryptStatusOK( status ) )
		status = setRootTrust( cryptRootCert, &certTrust, 1 );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't create trusted root cert for path processing, "
				"line %d.\n", __LINE__ );
		return( FALSE );
		}
	cryptGetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   &complianceLevel );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   CRYPT_COMPLIANCELEVEL_PKIX_FULL );

	/* Process each cert path and make sure that it succeeds or fails as
	   required */
	for( i = 0; pathTestInfo[ i ].fileMajor; i++ )
		if( !testPath( &pathTestInfo[ i ] ) )
			break;
	setRootTrust( cryptRootCert, NULL, certTrust );
	cryptDestroyCert( cryptRootCert );
	cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CERT_COMPLIANCELEVEL,
					   complianceLevel );
	if( pathTestInfo[ i ].fileMajor )
		return( FALSE );

	puts( "Path processing succeeded." );
	return( TRUE );
	}

/* Test handling of invalid PKCS #1 padding in cert signatures.  Note that
   running this test properly requires disabling the padding format check
   in mech_sig.c, since the signatures have such an obviously dodgy format
   that they don't even make it past the padding sanity check */

int testPKCS1Padding( void )
	{
	CRYPT_CERTIFICATE cryptCert;
	int i, status;

	puts( "Testing invalid PKCS #1 padding handling..." );

	for( i = 1; i <= 11; i++ )
		{
		status = importCertFromTemplate( &cryptCert, PADTEST_FILE_TEMPLATE,
										 i );
		if( cryptStatusError( status ) )
			{
			printf( "Couldn't import cert for padding check, status %d, "
					"line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		status = cryptCheckCert( cryptCert, CRYPT_UNUSED );
		if( cryptStatusOK( status ) )
			{
			printf( "Cert with bad padding verified, should have failed, "
					"line %d.\n", __LINE__ );
			return( FALSE );
			}
		cryptDestroyCert( cryptCert );
		}

	puts( "Padding handling succeeded." );
	return( TRUE );
	}

/* Generic test routines used for debugging.  These are only meant to be
   used interactively, and throw exceptions rather than returning status
   values */

void xxxCertImport( const char *fileName )
	{
	CRYPT_CERTIFICATE cryptCert;
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ], *bufPtr = buffer;
	long length, count;
	int status;

	filePtr = fopen( fileName, "rb" );
	assert( filePtr != NULL );
	fseek( filePtr, 0L, SEEK_END );
	length = ftell( filePtr );
	fseek( filePtr, 0L, SEEK_SET );
	if( length > BUFFER_SIZE )
		{
		bufPtr = malloc( length );
		assert( bufPtr != NULL );
		}
	count = fread( bufPtr, 1, length, filePtr );
	assert( count == length );
	fclose( filePtr );
	status = cryptImportCert( bufPtr, count, CRYPT_UNUSED, &cryptCert );
	assert( cryptStatusOK( status ) );
	if( bufPtr != buffer )
		free( bufPtr );
	printCertInfo( cryptCert );
	cryptDestroyCert( cryptCert );
	}

void xxxCertCheck( const C_STR certFileName, const C_STR caFileName )
	{
	CRYPT_CERTIFICATE cryptCert, cryptCaCert;
	int status;

	status = importCertFile( &cryptCert, certFileName );
	assert( cryptStatusOK( status ) );
	status = importCertFile( &cryptCaCert, caFileName );
	assert( cryptStatusOK( status ) );
	status = cryptCheckCert( cryptCert, cryptCaCert );
	if( cryptStatusError( status ) )
		printErrorAttributeInfo( cryptCert );
	assert( cryptStatusOK( status ) );
	cryptDestroyCert( cryptCert );
	cryptDestroyCert( cryptCaCert );
	}
