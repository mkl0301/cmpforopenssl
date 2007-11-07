/****************************************************************************
*																			*
*					  cryptlib Self-test Utility Routines					*
*						Copyright Peter Gutmann 1997-2007					*
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

#ifdef HAS_WIDECHAR
  #include <wchar.h>
#endif /* HAS_WIDECHAR */

/* The keys used with the test code have associated certs that expire at
   some point.  The following value defines the number of days before the
   expiry at which we start printing warnings */

#if defined( _MSC_VER ) && ( _MSC_VER == 1200 ) && !defined( NDEBUG )
  #define EXPIRY_WARN_DAYS		90
#else
  #define EXPIRY_WARN_DAYS		30
#endif /* VC 6 debug/development, give some advance warning */

/****************************************************************************
*																			*
*							Import/Export Functions							*
*																			*
****************************************************************************/

/* Check that a file is accessible.  This is a generic sanity check to make
   sure that access to keyset files is functioning */

int checkFileAccess( void )
	{
	CRYPT_KEYSET cryptKeyset;
	FILE *filePtr;
	int status;

	/* First, check that the file actually exists so that we can return an
	   appropriate error message */
	if( ( filePtr = fopen( convertFileName( CA_PRIVKEY_FILE ),
						   "rb" ) ) == NULL )
		{
		printf( "Couldn't access cryptlib keyset file %s.  Please make "
				"sure\nthat all the cryptlib files have been installed "
				"correctly, and the cryptlib\nself-test is being run from "
				"the correct directory.\n", CA_PRIVKEY_FILE );
		return( FALSE );
		}
	fclose( filePtr );

	/* The file exists and is accessible, now try and open it using the
	   cryptlib file access functions */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  CA_PRIVKEY_FILE, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		{
		/* If file keyset access isn't available, the inability to access
		   the keyset isn't an error */
		if( status == CRYPT_ERROR_NOTAVAIL )
			return( TRUE );

		printf( "Couldn't access cryptlib keyset file %s even though the "
				"file\nexists and is readable.  Please make sure that the "
				"cryptlib self-test is\nbeing run from the correct "
				"directory.\n", CA_PRIVKEY_FILE );
		return( FALSE );
		}
	cryptKeysetClose( cryptKeyset );

	return( TRUE );
	}

/* Import a certificate object */

int importCertFile( CRYPT_CERTIFICATE *cryptCert, const C_STR fileName )
	{
	FILE *filePtr;
	BYTE buffer[ BUFFER_SIZE ];
	int count;

	if( ( filePtr = fopen( convertFileName( fileName ), "rb" ) ) == NULL )
		return( CRYPT_ERROR_OPEN );
	count = fread( buffer, 1, BUFFER_SIZE, filePtr );
	fclose( filePtr );
    if( count == BUFFER_SIZE )	/* Item too large for buffer */
		return( CRYPT_ERROR_OVERFLOW );

	/* Import the certificate */
	return( cryptImportCert( buffer, count, CRYPT_UNUSED, cryptCert ) );
	}

int importCertFromTemplate( CRYPT_CERTIFICATE *cryptCert,
							const C_STR fileTemplate, const int number )
	{
	BYTE filenameBuffer[ FILENAME_BUFFER_SIZE ];
#ifdef UNICODE_STRINGS
	wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];
#endif /* UNICODE_STRINGS */

	filenameFromTemplate( filenameBuffer, fileTemplate, number );
#ifdef UNICODE_STRINGS
	mbstowcs( wcBuffer, filenameBuffer, strlen( filenameBuffer ) + 1 );
	return( importCertFile( cryptCert, wcBuffer ) );
#else
	return( importCertFile( cryptCert, filenameBuffer ) );
#endif /* UNICODE_STRINGS */
	}

/* Read a key from a key file */

int getPublicKey( CRYPT_CONTEXT *cryptContext, const C_STR keysetName,
				  const C_STR keyName )
	{
	CRYPT_KEYSET cryptKeyset;
	int status;

	/* Read the key from the keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  keysetName, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptGetPublicKey( cryptKeyset, cryptContext, CRYPT_KEYID_NAME,
								keyName );
	cryptKeysetClose( cryptKeyset );
	return( status );
	}

int getPrivateKey( CRYPT_CONTEXT *cryptContext, const C_STR keysetName,
				   const C_STR keyName, const C_STR password )
	{
	CRYPT_KEYSET cryptKeyset;
	time_t validFrom, validTo;
	int dummy, status;

	/* Read the key from the keyset */
	status = cryptKeysetOpen( &cryptKeyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
							  keysetName, CRYPT_KEYOPT_READONLY );
	if( cryptStatusError( status ) )
		return( status );
	status = cryptGetPrivateKey( cryptKeyset, cryptContext, CRYPT_KEYID_NAME,
								 keyName, password );
	cryptKeysetClose( cryptKeyset );
	if( cryptStatusError( status ) )
		return( status );

	/* If the key has a cert attached, make sure it's still valid before we
	   hand it back to the self-test functions that will report the problem
	   as being with the self-test rather than with the cert.  We check not
	   just the expiry date but also the expiry interval, to make sure that
	   we don't get false positives on short-validity certs */
	status = cryptGetAttributeString( *cryptContext,
					CRYPT_CERTINFO_VALIDFROM, &validFrom, &dummy );
	if( cryptStatusError( status ) )
		/* There's no cert there, this isn't an error */
		return( CRYPT_OK );
	cryptGetAttributeString( *cryptContext,
					CRYPT_CERTINFO_VALIDTO, &validTo, &dummy );
#ifndef _WIN32_WCE
	if( ( validTo - validFrom > ( 86400 * EXPIRY_WARN_DAYS ) ) && \
		validTo - time( NULL ) <= ( 86400 * EXPIRY_WARN_DAYS ) )
		{
		const time_t currentTime = time( NULL );

		puts( "                         ********************" );
		if( validTo <= currentTime )
			puts( "Warning: This key has expired.  Certificate-related "
				  "operations will fail or\n         result in error "
				  "messages from the test code." );
		else
			if( validTo - currentTime <= 86400 )
				puts( "Warning: This key expires today.  Certificate-"
					  "related operations may fail\n         or result in "
					  "error messages from the test code." );
			else
				printf( "Warning: This key will expire in %ld days.  "
						"Certificate-related operations\n         may fail "
						"or result in error messages from the test code.\n",
						( validTo - currentTime ) / 86400 );
		puts( "                         ********************" );
		printf( "Hit a key..." );
		getchar();
		putchar( '\r' );
		}
#endif /* _WIN32_WCE */
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Key File Access Routines						*
*																			*
****************************************************************************/

/* Key file and password-handling access routines */

const C_STR getKeyfileName( const KEYFILE_TYPE type,
							const BOOLEAN isPrivKey )
	{
	switch( type )
		{
		case KEYFILE_X509:
			return( USER_PRIVKEY_FILE );
		case KEYFILE_PGP:
			return( isPrivKey ? PGP_PRIVKEY_FILE : PGP_PUBKEY_FILE );
		case KEYFILE_OPENPGP:
			return( isPrivKey ? OPENPGP_PRIVKEY_FILE : OPENPGP_PUBKEY_FILE );
		case KEYFILE_OPENPGP_HASH:
			return( isPrivKey ? OPENPGP_PRIVKEY_HASH_FILE : OPENPGP_PUBKEY_HASH_FILE );
		case KEYFILE_OPENPGP_AES:
			return( isPrivKey ? OPENPGP_PRIVKEY_AES_FILE : OPENPGP_PUBKEY_AES_FILE );
		case KEYFILE_OPENPGP_RSA:
			return( isPrivKey ? OPENPGP_PRIVKEY_RSA_FILE : OPENPGP_PUBKEY_RSA_FILE );
		case KEYFILE_OPENPGP_PARTIAL:
			return( OPENPGP_PRIVKEY_PART_FILE );
		case KEYFILE_NAIPGP:
			return( isPrivKey ? NAIPGP_PRIVKEY_FILE : NAIPGP_PUBKEY_FILE );
		}
	assert( 0 );
	return( TEXT( "notfound" ) );
	}

const C_STR getKeyfilePassword( const KEYFILE_TYPE type )
	{
	switch( type )
		{
		case KEYFILE_X509:
			return( TEST_PRIVKEY_PASSWORD );
		case KEYFILE_PGP:
		case KEYFILE_OPENPGP:
		case KEYFILE_OPENPGP_HASH:
		case KEYFILE_OPENPGP_RSA:
			return( TEXT( "test1" ) );
		case KEYFILE_NAIPGP:
			return( TEXT( "test10" ) );
		case KEYFILE_OPENPGP_AES:
			return( TEXT( "testkey" ) );
		case KEYFILE_OPENPGP_PARTIAL:
			return( TEXT( "def" ) );
		}
	assert( 0 );
	return( TEXT( "notfound" ) );
	}

const C_STR getKeyfileUserID( const KEYFILE_TYPE type,
							  const BOOLEAN isPrivKey )
	{
	/* If possible we specify user IDs for keys in the middle of the keyring
	   to make sure that we test the ability to correctly handle multiple
	   keys */
	switch( type )
		{
		case KEYFILE_X509:
			return( USER_PRIVKEY_LABEL );
		case KEYFILE_PGP:
			return( TEXT( "test" ) );
		case KEYFILE_NAIPGP:
			return( isPrivKey ? TEXT( "test" ) : TEXT( "test cryptlib" ) );
		case KEYFILE_OPENPGP:
		case KEYFILE_OPENPGP_HASH:
		case KEYFILE_OPENPGP_RSA:
			return( TEXT( "test1" ) );
		case KEYFILE_OPENPGP_AES:
			return( TEXT( "Max Mustermann" ) );
		}
	assert( 0 );
	return( TEXT( "notfound" ) );
	}

/****************************************************************************
*																			*
*							OS Helper Functions								*
*																			*
****************************************************************************/

#if defined( __BORLANDC__ ) && ( __BORLANDC__ <= 0x310 )

/* BC++ 3.x doesn't have mbstowcs() in the default library, and also defines
   wchar_t as char (!!) so we fake it here */

size_t mbstowcs( char *pwcs, const char *s, size_t n )
	{
	memcpy( pwcs, s, n );
	return( n );
	}
#endif /* BC++ 3.1 or lower */

/* When using multiple threads we need to delay one thread for a small
   amount of time, unfortunately there's no easy way to do this with pthreads
   so we have to provide the following wrapper function that makes an
   (implementation-specific) attempt at it */

#if defined( UNIX_THREADS ) || defined( WINDOWS_THREADS ) || defined( OS2_THREADS )

#if defined( UNIX_THREADS )
  /* This include must be outside the function to avoid weird compiler errors
	 on some systems */
  #include <sys/time.h>
#endif /* UNIX_THREADS */

void delayThread( const int seconds )
	{
#if defined( UNIX_THREADS )
	struct timeval tv = { 0 };

	/* The following should put a thread to sleep for a second on most
	   systems since the select() should be a thread-safe one in the
	   presence of pthreads */
	tv.tv_sec = seconds;
	select( 1, NULL, NULL, NULL, &tv );
#elif defined( WINDOWS_THREADS )
	Sleep( seconds * 1000 );
#endif /* Threading system-specific delay functions */
	}
#endif /* Systems with threading support */

/* Helper functions to make tracking down errors on systems with no console
   a bit less painful.  These just use the debug console as stdout */

#ifdef _WIN32_WCE

void wcPrintf( const char *format, ... )
	{
	wchar_t wcBuffer[ 1024 ];
	char buffer[ 1024 ];
	va_list argPtr;

	va_start( argPtr, format );
	vsprintf( buffer, format, argPtr );
	va_end( argPtr );
	mbstowcs( wcBuffer, buffer, strlen( buffer ) + 1 );
	NKDbgPrintfW( wcBuffer );
	}

void wcPuts( const char *string )
	{
	wcPrintf( "%s\n", string );
	}
#endif /* Console-less environments */

/* Conversion functions used to get Unicode input into generic ASCII
   output */

#ifdef UNICODE_STRINGS

/* Get a filename in an appropriate format for the C runtime library */

const char *convertFileName( const C_STR fileName )
	{
	static char fileNameBuffer[ FILENAME_BUFFER_SIZE ];

	wcstombs( fileNameBuffer, fileName, wcslen( fileName ) + 1 );
	return( fileNameBuffer );
	}

/* Map a filename template to an actual filename, input in Unicode, output in
   ASCII */

void filenameFromTemplate( char *buffer, const wchar_t *fileTemplate,
						   const int count )
	{
	wchar_t wcBuffer[ FILENAME_BUFFER_SIZE ];
	int length;

	length = _snwprintf( wcBuffer, FILENAME_BUFFER_SIZE, fileTemplate,
						 count );
	wcstombs( buffer, wcBuffer, length + 1 );
	}

void filenameParamFromTemplate( wchar_t *buffer,
								const wchar_t *fileTemplate,
								const int count )
	{
	int length;

	length = _snwprintf( buffer, FILENAME_BUFFER_SIZE, fileTemplate,
						 count );
	}
#endif /* UNICODE_STRINGS */

/****************************************************************************
*																			*
*							Thread Support Functions						*
*																			*
****************************************************************************/

#if defined( WINDOWS_THREADS )

static HANDLE hMutex;

void createMutex( void )
	{
	hMutex = CreateMutex( NULL, FALSE, NULL );
	}
void acquireMutex( void )
	{
	if( WaitForSingleObject( hMutex, 30000 ) == WAIT_TIMEOUT )
		{
		puts( "Warning: Couldn't acquire mutex after 30s wait.  Press a "
			  "key to continue." );
		getchar();
		}
	}
int waitMutex( void )
	{
	if( WaitForSingleObject( hMutex, 30000 ) == WAIT_TIMEOUT )
		return( CRYPT_ERROR_TIMEOUT );
	
	/* Since this is merely a synchronisation operation in which a later 
	   thread waits to catch up to an earlier one, we release the mutex again
	   so other threads can get in */
	releaseMutex();
	return( CRYPT_OK );
	}
void releaseMutex( void )
	{
	if( !ReleaseMutex( hMutex ) )
		{
		puts( "Warning: Couldn't release mutex.  Press a key to continue." );
		getchar();
		}
	}
void destroyMutex( void )
	{
	CloseHandle( hMutex );
	}

void waitForThread( const HANDLE hThread )
	{
	if( WaitForSingleObject( hThread, 15000 ) == WAIT_TIMEOUT )
		{
		puts( "Warning: Server thread is still active due to session "
			  "negotiation failure,\n         this will cause an error "
			  "condition when cryptEnd() is called due\n         to "
			  "resources remaining allocated.  Press a key to continue." );
		getchar();
		}
	CloseHandle( hThread );
	}
#elif defined( UNIX_THREADS )

static pthread_mutex_t mutex;

void createMutex( void )
	{
	pthread_mutex_init( &mutex, NULL );
	}
void acquireMutex( void )
	{
	pthread_mutex_lock( &mutex );
	}
int waitMutex( void )
	{
	pthread_mutex_lock( &mutex );
	
	/* Since this is merely a synchronisation operation in which a later 
	   thread waits to catch up to an earlier one, we release the mutex again
	   so other threads can get in */
	releaseMutex();
	return( CRYPT_OK );
	}
void releaseMutex( void )
	{
	pthread_mutex_unlock( &mutex );
	}
void destroyMutex( void )
	{
	pthread_mutex_destroy( &mutex );
	}

void waitForThread( const pthread_t hThread )
	{
	if( pthread_join( hThread, NULL ) < 0 )
		{
		puts( "Warning: Server thread is still active due to session "
			  "negotiation failure,\n         this will cause an error "
			  "condition when cryptEnd() is called due\n         to "
			  "resources remaining allocated.  Press a key to continue." );
		getchar();
		}
	}

#else

void createMutex( void )
	{
	}
void acquireMutex( void )
	{
	}
void releaseMutex( void )
	{
	}
int waitMutex( void )
	{
	return( CRYPT_OK );
	}
void destroyMutex( void )
	{
	}
#endif /* WINDOWS_THREADS */

#if defined( WINDOWS_THREADS ) || defined( UNIX_THREADS )

/* Dispatch multiple client and server threads and wait for them to exit */

int multiThreadDispatch( THREAD_FUNC clientFunction,
						 THREAD_FUNC serverFunction, const int noThreads )
	{
	THREAD_HANDLE hClientThreads[ MAX_NO_THREADS ];
	THREAD_HANDLE hServerThreads[ MAX_NO_THREADS ];
	int sessionID[ MAX_NO_THREADS ];
	int i;

	assert( noThreads <= MAX_NO_THREADS );

	/* Set up the session ID values */	
	for( i = 0; i < MAX_NO_THREADS; i++ )
		sessionID[ i ] = i;

	/* Start the sessions and wait for them initialise.  We have to wait for
	   some time since the multiple private key reads can take awhile */
	for( i = 0; i < noThreads; i++ )
		{
#ifdef WINDOWS_THREADS
		unsigned int threadID;

		hServerThreads[ i ] = ( HANDLE ) \
						_beginthreadex( NULL, 0, serverFunction,
										&sessionID[ i ], 0, &threadID );
#else
		pthread_t threadHandle;

		hServerThreads[ i ] = 0;
		if( pthread_create( &threadHandle, NULL, serverFunction,
							&sessionID[ i ] ) == 0 )
			hServerThreads[ i ] = threadHandle;
#endif /* Windows vs. pthreads */
		}
	delayThread( 3 );

	/* Connect to the local server */
	for( i = 0; i < noThreads; i++ )
		{
#ifdef WINDOWS_THREADS
		unsigned int threadID;

		hClientThreads[ i ] = ( HANDLE ) \
						_beginthreadex( NULL, 0, clientFunction,
										&sessionID[ i ], 0, &threadID );
#else
		pthread_t threadHandle;

		hServerThreads[ i ] = 0;
		if( pthread_create( &threadHandle, NULL, clientFunction,
							&sessionID[ i ] ) == 0 )
			hClientThreads[ i ] = threadHandle;
#endif /* Windows vs. pthreads */
		}
#ifdef WINDOWS_THREADS
	if( WaitForMultipleObjects( noThreads, hServerThreads, TRUE,
								60000 ) == WAIT_TIMEOUT || \
		WaitForMultipleObjects( noThreads, hClientThreads, TRUE,
								60000 ) == WAIT_TIMEOUT )
#else
	/* Posix doesn't have an ability to wait for multiple threads for mostly
	   religious reasons ("That's not how we do things around here") so we
	   just wait for two token threads */
	pthread_join( hServerThreads[ 0 ], NULL );
	pthread_join( hClientThreads[ 0 ], NULL );
#endif /* Windows vs. pthreads */
		{
		puts( "Warning: Server threads are still active due to session "
			  "negotiation failure,\n         this will cause an error "
			  "condition when cryptEnd() is called due\n         to "
			  "resources remaining allocated.  Press a key to continue." );
		getchar();
		}
#ifdef WINDOWS_THREADS
	for( i = 0; i < noThreads; i++ )
		if( hServerThreads[ i ] != 0 )
			CloseHandle( hServerThreads[ i ] );
	for( i = 0; i < noThreads; i++ )
		if( hClientThreads[ i ] != 0 )
			CloseHandle( hClientThreads[ i ] );
#endif /* Windows vs. pthreads */

	return( TRUE );
	}
#endif /* Windows/Unix threads */

/****************************************************************************
*																			*
*							Error-handling Functions						*
*																			*
****************************************************************************/

/* Print extended error attribute information */

void printErrorAttributeInfo( const CRYPT_HANDLE cryptHandle )
	{
	int errorType, errorLocus;
	int status;

	status = cryptGetAttribute( cryptHandle, CRYPT_ATTRIBUTE_ERRORTYPE,
								&errorType );
	cryptGetAttribute( cryptHandle, CRYPT_ATTRIBUTE_ERRORLOCUS, &errorLocus );
	if( cryptStatusOK( status ) && errorType != CRYPT_ERRTYPE_NONE )
		printf( "  Error info attributes report locus %d, type %d.\n",
				errorLocus, errorType );
	}

/* Print extended object error information */

void printExtError( const CRYPT_HANDLE cryptHandle,
					const char *functionName, const int functionStatus,
					const int lineNo )
	{
	char errorMessage[ 512 ];
	int errorCode, errorMessageLength, status, msgStatus;

	printf( "%s failed with error code %d, line %d.\n", functionName,
			functionStatus, lineNo );
	status = cryptGetAttribute( cryptHandle, CRYPT_ATTRIBUTE_INT_ERRORCODE,
								&errorCode );
	msgStatus = cryptGetAttributeString( cryptHandle,
										 CRYPT_ATTRIBUTE_INT_ERRORMESSAGE,
										 errorMessage, &errorMessageLength );
	if( cryptStatusError( status ) )
		{
		printf( "Read of error attributes failed with error code %d, "
				"line %d.\n", status, __LINE__ );
		return;
		}
	if( !errorCode && cryptStatusError( msgStatus ) )
		{
		puts( "  No extended error information available." );
		printErrorAttributeInfo( cryptHandle );
		return;
		}
	if( errorCode )
		printf( "  Extended error code = %d (0x%X).\n", errorCode, 
				errorCode );
	if( cryptStatusOK( msgStatus ) )
		{
		errorMessage[ errorMessageLength ] = '\0';
		printf( "  Error message = %s'%s'.\n",
				( errorMessageLength > ( 80 - 21 ) ) ? "\n  " : "", 
				errorMessage );
		}
	else
		puts( "." );
	printErrorAttributeInfo( cryptHandle );
	}

/* Exit with an error message.  attrErrorExit() prints the locus and type,
   extErrorExit() prints the extended error code and message */

BOOLEAN attrErrorExit( const CRYPT_HANDLE cryptHandle,
					   const char *functionName, const int errorCode,
					   const int lineNumber )
	{
	printf( "%s failed with error code %d, line %d.\n", functionName,
			errorCode, lineNumber );
	printErrorAttributeInfo( cryptHandle );
	return( FALSE );
	}

BOOLEAN extErrorExit( const CRYPT_HANDLE cryptHandle,
					  const char *functionName, const int errorCode,
					  const int lineNumber )
	{
	printExtError( cryptHandle, functionName, errorCode, lineNumber );
	cryptDestroyObject( cryptHandle );
	return( FALSE );
	}

/****************************************************************************
*																			*
*								Misc. Functions								*
*																			*
****************************************************************************/

/* Some algorithms can be disabled to eliminate patent problems or reduce the
   size of the code.  The following functions are used to select generally
   equivalent alternatives if the required algorithm isn't available.  These
   selections make certain assumptions, namely that at least one of the
   algorithms in the fallback chain is always available (which is guaranteed,
   3DES is used internally), and that they have the same general properties
   as the algorithms they're replacing, which is also usually the case,
   with Blowfish being a first-instance substitute for IDEA, RC2, or RC5, and
   then 3DES as the fallback if Blowfish isn't available */

CRYPT_ALGO_TYPE selectCipher( const CRYPT_ALGO_TYPE algorithm )
	{
	if( cryptStatusOK( cryptQueryCapability( algorithm, NULL ) ) )
		return( algorithm );
	if( cryptStatusOK( cryptQueryCapability( CRYPT_ALGO_BLOWFISH, NULL ) ) )
		return( CRYPT_ALGO_BLOWFISH );
	return( CRYPT_ALGO_3DES );
	}

/* Add a collection of fields to a certificate */

int addCertFields( const CRYPT_CERTIFICATE certificate,
				   const CERT_DATA *certData, const int lineNo )
	{
	int i;

	for( i = 0; certData[ i ].type != CRYPT_ATTRIBUTE_NONE; i++ )
		{
		int status;

		switch( certData[ i ].componentType )
			{
			case IS_NUMERIC:
				status = cryptSetAttribute( certificate,
							certData[ i ].type, certData[ i ].numericValue );
				if( cryptStatusError( status ) )
					printf( "cryptSetAttribute() for entry %d, field ID %d,\n"
							"  value %d, failed with error code %d, line %d.\n",
							i + 1, certData[ i ].type, certData[ i ].numericValue,
							status, lineNo );
				break;

			case IS_STRING:
				status = cryptSetAttributeString( certificate,
							certData[ i ].type, certData[ i ].stringValue,
							certData[ i ].numericValue ? \
								certData[ i ].numericValue : \
								paramStrlen( certData[ i ].stringValue ) );
				if( cryptStatusError( status ) )
					{
#if defined( _MSC_VER ) && ( _MSC_VER == 1200 ) && !defined( NDEBUG )
					if( status == CRYPT_ERROR_INVALID && \
						paramStrlen( certData[ i ].stringValue ) == 2 && \
						!memcmp( certData[ i ].stringValue, "NZ", 2 ) )
						{
						/* Warn about BoundsChecker-induced Heisenbugs */
						puts( "                         ********************" );
						puts( "If you're running this under BoundsChecker "
							  "you need to disable it to complete\nthe test "
							  "since it causes errors in the cert "
							  "string-checking code.  The\nfollowing error "
							  "is caused by BoundsChecker, not by the "
							  "self-test failing." );
						puts( "                         ********************" );
						}
#endif /* VC++ 6 */
					printf( "cryptSetAttributeString() for entry %d, field ID %d,\n"
							"  value '%s', failed with error code %d, line %d.\n",
							i + 1, certData[ i ].type,
							( char * ) certData[ i ].stringValue, status,
							lineNo );
					}
				break;

#ifdef HAS_WIDECHAR
			case IS_WCSTRING:
				status = cryptSetAttributeString( certificate,
							certData[ i ].type, certData[ i ].stringValue,
							wcslen( certData[ i ].stringValue ) * sizeof( wchar_t ) );
				if( cryptStatusError( status ) )
					printf( "cryptSetAttributeString() for entry %d, field ID %d,\n"
							"  value '%s', failed with error code %d, line %d.\n",
							i + 1, certData[ i ].type,
							( char * ) certData[ i ].stringValue, status,
							lineNo );
				break;
#endif /* HAS_WIDECHAR */

			case IS_TIME:
				status = cryptSetAttributeString( certificate,
							certData[ i ].type, &certData[ i ].timeValue,
							sizeof( time_t ) );
				if( cryptStatusError( status ) )
					printf( "cryptSetAttributeString() for entry %d, field ID %d,\n"
							"  value 0x%lX, failed with error code %d, line %d.\n",
							i + 1, certData[ i ].type, certData[ i ].timeValue,
							status, lineNo );
				break;

			default:
				assert( FALSE );
				return( FALSE );
			}
		if( cryptStatusError( status ) )
			{
			printErrorAttributeInfo( certificate );
			return( FALSE );
			}
		}

	return( TRUE );
	}

/* Populate a key database with the contents of a directory.  This is a
   rather OS-specific utility function for setting up test databases that
   only works under Win32 (in fact it's not used at all at the moment) */

#if defined( _MSC_VER ) && defined( _WIN32 ) && !defined( _WIN32_WCE ) && 0

void loadCertificates( void )
	{
	WIN32_FIND_DATA findData;
	HANDLE searchHandle;

	searchHandle = FindFirstFile( "d:/tmp/certs/*.der", &findData );
	if( searchHandle == INVALID_HANDLE_VALUE )
		return;
	do
		{
		CRYPT_CERTIFICATE cryptCert;
		int status;

		printf( "Adding cert %s.\n", findData.cFileName );
		status = importCertFile( &cryptCert, findData.cFileName );
		if( cryptStatusOK( status ) )
			{
			cryptDestroyCert( cryptCert );
			}
		}
	while( FindNextFile( searchHandle, &findData ) );
	FindClose( searchHandle );
	}
#endif /* Win32 */

/****************************************************************************
*																			*
*								Debug Functions								*
*																			*
****************************************************************************/

/* Write an object to a file for debugging purposes */

#if defined( _MSC_VER ) && \
	!( defined( _WIN32_WCE ) || defined( __PALMSOURCE__ ) )
  #include <direct.h>
  #include <io.h>
#endif /* VC++ Win16/Win32 */

void debugDump( const char *fileName, const void *data, const int dataLength )
	{
	FILE *filePtr;
#ifdef __UNIX__
	const char *tmpPath = getenv( "TMPDIR" );
	char fileNameBuffer[ FILENAME_BUFFER_SIZE ];
	const int tmpPathLen = ( tmpPath != NULL ) ? strlen( tmpPath ) : 0;
#else
	char fileNameBuffer[ 128 ];
#endif /* __UNIX__ */
	const int length = strlen( fileName );

#if defined( _WIN32_WCE )
	/* Under WinCE we don't want to scribble a ton of data into flash every
	   time we're run, so we don't try and do anything */
	return;
#elif ( defined( _MSC_VER ) && !defined( __PALMSOURCE__ ) )
	if( access( "d:/tmp/", 6 ) == 0 )
		{
		/* There's a data partition available, dump the info there */
		if( access( "d:/tmp/", 6 ) == -1 && mkdir( "d:/tmp" ) == -1 )
			return;
		strcpy( fileNameBuffer, "d:/tmp/" );
		}
	else
		{
		/* There's no separate data partition, everything's dumped into the
		   same partition */
		if( access( "c:/tmp/", 6 ) == -1 && mkdir( "c:/tmp" ) == -1 )
			return;
		strcpy( fileNameBuffer, "c:/tmp/" );
		}
#elif defined( __UNIX__ )
	if( tmpPathLen > 3 && tmpPathLen < 768 )
		{
		strcpy( fileNameBuffer, tmpPath );
		if( fileNameBuffer[ tmpPathLen - 1 ] != '/' )
			strcat( fileNameBuffer + tmpPathLen, "/" );
		}
	else
		strcpy( fileNameBuffer, "/tmp/" );
#else
	fileNameBuffer[ 0 ] = '\0';
#endif /* OS-specific paths */
	strcat( fileNameBuffer, fileName );
	if( length <= 3 || fileName[ length - 4 ] != '.' )
		strcat( fileNameBuffer, ".der" );

#if defined( __VMCMS__ )
	{
	char formatBuffer[ 32 ];

	sprintf( formatBuffer, "wb, recfm=F, lrecl=%d, noseek", dataLength );
	filePtr = fopen( fileNameBuffer, formatBuffer );
	}
	if( filePtr == NULL )
#else
	if( ( filePtr = fopen( fileNameBuffer, "wb" ) ) == NULL )
#endif /* __VMCMS__ */
		return;
	fwrite( data, dataLength, 1, filePtr );
	fclose( filePtr );
	}

/****************************************************************************
*																			*
*								Session Functions							*
*																			*
****************************************************************************/

/* Print information on the peer that we're talking to */

int printConnectInfo( const CRYPT_SESSION cryptSession )
	{
#ifndef UNICODE_STRINGS
	time_t theTime;
#endif /* UNICODE_STRINGS */
	C_CHR serverName[ 128 ];
	int serverNameLength, serverPort, status;

	status = cryptGetAttributeString( cryptSession, CRYPT_SESSINFO_CLIENT_NAME,
									  serverName, &serverNameLength );
	if( cryptStatusError( status ) )
		return( FALSE );
	cryptGetAttribute( cryptSession, CRYPT_SESSINFO_CLIENT_PORT, &serverPort );
#ifdef UNICODE_STRINGS
	serverName[ serverNameLength / sizeof( wchar_t ) ] = TEXT( '\0' );
	printf( "SVR: Connect attempt from %S, port %d", serverName, serverPort );
#else
	serverName[ serverNameLength ] = '\0';
	time( &theTime );
	printf( "SVR: Connect attempt from %s, port %d, on %s", serverName,
			serverPort, ctime( &theTime ) );
#endif /* UNICODE_STRINGS */

	/* Display all the attributes that we've got */
	return( displayAttributes( cryptSession ) );
	}

/* Print security info for the session */

int printSecurityInfo( const CRYPT_SESSION cryptSession,
					   const BOOLEAN isServer,
					   const BOOLEAN showFingerprint )
	{
	int cryptAlgo, keySize, version, status;

	/* Print general security info */
	status = cryptGetAttribute( cryptSession, CRYPT_CTXINFO_ALGO,
								&cryptAlgo );
	if( cryptStatusOK( status ) )
		status = cryptGetAttribute( cryptSession, CRYPT_CTXINFO_KEYSIZE,
									&keySize );
	if( cryptStatusOK( status ) )
		status = cryptGetAttribute( cryptSession, CRYPT_SESSINFO_VERSION,
									&version );
	if( cryptStatusError( status ) )
		{
		printf( "Couldn't get session security parameters, status %d, line "
				"%d.\n", status, __LINE__ );
		return( FALSE );
		}
	printf( "%sSession is protected using algorithm %d with a %d bit key,\n"
			"  protocol version %d.\n", isServer ? "SVR: " : "",
			cryptAlgo, keySize * 8, version );
	if( isServer || !showFingerprint )
		return( TRUE );

	return( printFingerprint( cryptSession, FALSE ) );
	}

int printFingerprint( const CRYPT_SESSION cryptSession,
					  const BOOLEAN isServer )
	{
	BYTE fingerPrint[ CRYPT_MAX_HASHSIZE ];
	int i, length, status;

	/* Print the server key fingerprint */
	status = cryptGetAttributeString( cryptSession,
									  CRYPT_SESSINFO_SERVER_FINGERPRINT,
									  fingerPrint, &length );
	if( cryptStatusError( status ) )
		{
		printf( "cryptGetAttributeString() failed with error code "
				"%d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}
	printf( "%sServer key fingerprint =", isServer ? "SVR: " : "" );
	for( i = 0; i < length; i++ )
		printf( " %02X", fingerPrint[ i ] );
	puts( "." );

	return( TRUE );
	}

/* Set up a client/server to connect locally.  For the client his simply
   tells it where to connect, for the server this binds it to the local
   address so we don't inadvertently open up outside ports (admittedly
   they can't do much except run the hardcoded self-test, but it's better
   not to do this at all) */

BOOLEAN setLocalConnect( const CRYPT_SESSION cryptSession, const int port )
	{
	int status;

	status = cryptSetAttributeString( cryptSession,
									  CRYPT_SESSINFO_SERVER_NAME,
									  TEXT( "localhost" ),
									  paramStrlen( TEXT( "localhost" ) ) );
#ifdef __UNIX__
	/* If we're running under Unix, set the port to a nonprivileged one so
	   we don't have to run as root.  For anything other than very low-
	   numbered ports (e.g. SSH), the way we determine the port is to repeat
	   the first digit, so e.g. TSA on 318 becomes 3318, this seems to be
	   the method most commonly used */
	if( cryptStatusOK( status ) && port < 1024 )
		{
		if( port < 100 )
			status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_SERVER_PORT,
										port + 4000 );
		else
			status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_SERVER_PORT,
										( ( port / 100 ) * 1000 ) + port );
		}
#endif /* __UNIX__ */
	if( cryptStatusError( status ) )
		{
		printf( "cryptSetAttribute/AttributeString() failed with error code "
				"%d, line %d.\n", status, __LINE__ );
		return( FALSE );
		}

	return( TRUE );
	}

/* Run a persistent server session, recycling the connection if the client
   kept the link open */

int activatePersistentServerSession( const CRYPT_SESSION cryptSession,
									 const BOOLEAN showOperationType )
	{
	BOOLEAN connectionActive = FALSE;
	int status;

	do
		{
		/* Activate the connection */
		status = cryptSetAttribute( cryptSession, CRYPT_SESSINFO_ACTIVE,
									TRUE );
		if( status == CRYPT_ERROR_READ && connectionActive )
			{
			/* The other side closed the connection after a previous
			   successful transaction, this isn't an error */
			return( CRYPT_OK );
			}

		/* Print connection info and check whether the connection is still
		   active.  If it is, we recycle the session so that we can process
		   another request */
		printConnectInfo( cryptSession );
		if( cryptStatusOK( status ) && showOperationType )
			{
			char userID[ CRYPT_MAX_TEXTSIZE ];
			int userIDsize, requestType;

			status = cryptGetAttribute( cryptSession,
										CRYPT_SESSINFO_CMP_REQUESTTYPE,
										&requestType );
			if( cryptStatusOK( status ) )
				status = cryptGetAttributeString( cryptSession,
											CRYPT_SESSINFO_USERNAME,
											userID, &userIDsize );
			if( cryptStatusError( status ) )
				printf( "cryptGetAttribute/AttributeString() failed with "
						"error code %d, line %d.\n", status, __LINE__ );
			else
				{
				userID[ userIDsize ] = '\0';
				printf( "SVR: Operation type was %d, user '%s'.\n",
						requestType, userID );
				}
			}
		cryptGetAttribute( cryptSession, CRYPT_SESSINFO_CONNECTIONACTIVE,
						   &connectionActive );
		}
	while( cryptStatusOK( status ) && connectionActive );

	return( status );
	}

/****************************************************************************
*																			*
*							Attribute Dump Routines							*
*																			*
****************************************************************************/

/* Print a list of all attributes present in an object */

int displayAttributes( const CRYPT_HANDLE cryptHandle )
	{
	int status;

	if( cryptStatusError( \
			cryptSetAttribute( cryptHandle, CRYPT_ATTRIBUTE_CURRENT_GROUP,
							   CRYPT_CURSOR_FIRST ) ) )
		return( TRUE );

	puts( "Attributes present (by cryptlib ID) are:" );
	do
		{
		BOOLEAN firstAttr = TRUE;
		int value;

		status = cryptGetAttribute( cryptHandle,
									CRYPT_ATTRIBUTE_CURRENT_GROUP, &value );
		if( cryptStatusError( status ) )
			{
			printf( "\nCurrent attribute group value read failed with "
					"error code %d, line %d.\n", status, __LINE__ );
			return( FALSE );
			}
		printf( "  Attribute group %d, values =", value );
		do
			{
			status = cryptGetAttribute( cryptHandle, CRYPT_ATTRIBUTE_CURRENT,
										&value );
			if( cryptStatusError( status ) )
				{
				printf( "\nCurrent attribute value read failed with error "
						"code %d, line %d.\n", status, __LINE__ );
				return( FALSE );
				}
			if( !firstAttr )
				putchar( ',' );
			printf( " %d", value );
			firstAttr = FALSE;
			}
		while( cryptSetAttribute( cryptHandle, CRYPT_ATTRIBUTE_CURRENT,
								  CRYPT_CURSOR_NEXT ) == CRYPT_OK );
		puts( "." );
		}
	while( cryptSetAttribute( cryptHandle, CRYPT_ATTRIBUTE_CURRENT_GROUP,
							  CRYPT_CURSOR_NEXT ) == CRYPT_OK );

	/* Reset the cursor to the first attribute.  This is useful for things
	   like envelopes and sessions where the cursor points at the first
	   attribute that needs to be handled */
	cryptSetAttribute( cryptHandle, CRYPT_ATTRIBUTE_CURRENT_GROUP,
					   CRYPT_CURSOR_FIRST );
	return( TRUE );
	}

/****************************************************************************
*																			*
*							Certificate Dump Routines						*
*																			*
****************************************************************************/

/* Print a hex string */

static void printHex( const BYTE *value, const int length )
	{
	int i;

	for( i = 0; i < length; i++ )
		{
		if( i )
			printf( " " );
		printf( "%02X", value[ i ] );
		}
	puts( "." );
	}

/* Print a DN */

static void printDN( const CRYPT_CERTIFICATE certificate )
	{
	char buffer[ 1024 + 1 ];
	int length, status;

	status = cryptGetAttributeString( certificate,
						CRYPT_CERTINFO_DN, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  DN string = %s.\n", buffer ); }
	status = cryptGetAttributeString( certificate,
						CRYPT_CERTINFO_COUNTRYNAME, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  C = %s.\n", buffer ); }
	status = cryptGetAttributeString( certificate,
						CRYPT_CERTINFO_STATEORPROVINCENAME, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  S = %s.\n", buffer ); }
	status = cryptGetAttributeString( certificate,
						CRYPT_CERTINFO_LOCALITYNAME, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  L = %s.\n", buffer ); }
	status = cryptGetAttributeString( certificate,
						CRYPT_CERTINFO_ORGANIZATIONNAME, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  O = %s.\n", buffer ); }
	status = cryptGetAttributeString( certificate,
						CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  OU = %s.\n", buffer ); }
	status = cryptGetAttributeString( certificate,
						CRYPT_CERTINFO_COMMONNAME, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  CN = %s.\n", buffer ); }
	}

/* Print an altName */

static void printAltName( const CRYPT_CERTIFICATE certificate )
	{
	char buffer[ 512 ];
	int length, status;

	status = cryptGetAttributeString( certificate,
						CRYPT_CERTINFO_RFC822NAME, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  Email = %s.\n", buffer ); }
	status = cryptGetAttributeString( certificate,
						CRYPT_CERTINFO_DNSNAME, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  DNSName = %s.\n", buffer ); }
	status = cryptGetAttributeString( certificate,
						CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  EDI Nameassigner = %s.\n", buffer ); }
	status = cryptGetAttributeString( certificate,
						CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  EDI Partyname = %s.\n", buffer ); }
	status = cryptGetAttributeString( certificate,
						CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  URL = %s.\n", buffer ); }
	status = cryptGetAttributeString( certificate,
						CRYPT_CERTINFO_IPADDRESS, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  IP = %s.\n", buffer ); }
	status = cryptGetAttributeString( certificate,
						CRYPT_CERTINFO_REGISTEREDID, buffer, &length );
	if( cryptStatusOK( status ) )
		{ buffer[ length ] = '\0'; printf( "  Registered ID = %s.\n", buffer ); }
	status = cryptSetAttribute( certificate, CRYPT_CERTINFO_DIRECTORYNAME,
								CRYPT_UNUSED );
	if( cryptStatusOK( status ) )
		{
		printf( "  altName DN is:\n" );
		printDN( certificate );
		}
	}

/* The following function performs many attribute accesses, rather than using
   huge numbers of status checks we use the following macro to check each
   attribute access */

#define CHK( function ) \
		status = function; \
		if( cryptStatusError( status ) ) \
			return( certInfoErrorExit( #function, status, __LINE__ ) )

static int certInfoErrorExit( const char *functionCall, const int status,
							  const int line )
	{
	printf( "\n%s failed with status %d, line %d.\n", functionCall,
			status, line );
	return( FALSE );
	}

/* Print information on a certificate */

int printCertInfo( const CRYPT_CERTIFICATE certificate )
	{
	CRYPT_CERTTYPE_TYPE certType;
	char buffer[ 1024 ];
	int length, value, status;

	CHK( cryptGetAttribute( certificate, CRYPT_CERTINFO_CERTTYPE, &value ) );
	certType = value;

	/* Display the issuer and subject DN */
	if( certType != CRYPT_CERTTYPE_CERTREQUEST && \
		certType != CRYPT_CERTTYPE_REQUEST_CERT && \
		certType != CRYPT_CERTTYPE_REQUEST_REVOCATION && \
		certType != CRYPT_CERTTYPE_RTCS_REQUEST && \
		certType != CRYPT_CERTTYPE_RTCS_RESPONSE && \
		certType != CRYPT_CERTTYPE_OCSP_REQUEST && \
		certType != CRYPT_CERTTYPE_CMS_ATTRIBUTES && \
		certType != CRYPT_CERTTYPE_PKIUSER )
		{
		puts( "Certificate object issuer name is:" );
		CHK( cryptSetAttribute( certificate, CRYPT_CERTINFO_ISSUERNAME,
								CRYPT_UNUSED ) );
		printDN( certificate );
		if( cryptStatusOK( \
				cryptGetAttribute( certificate,
								   CRYPT_CERTINFO_ISSUERALTNAME, &value ) ) )
			{
			CHK( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT,
									CRYPT_CERTINFO_ISSUERALTNAME ) );
			printAltName( certificate );
			}
		}
	if( certType != CRYPT_CERTTYPE_CRL && \
		certType != CRYPT_CERTTYPE_REQUEST_REVOCATION && \
		certType != CRYPT_CERTTYPE_CMS_ATTRIBUTES && \
		certType != CRYPT_CERTTYPE_RTCS_REQUEST && \
		certType != CRYPT_CERTTYPE_RTCS_RESPONSE && \
		certType != CRYPT_CERTTYPE_OCSP_REQUEST && \
		certType != CRYPT_CERTTYPE_OCSP_RESPONSE )
		{
		puts( "Certificate object subject name is:" );
		CHK( cryptSetAttribute( certificate, CRYPT_CERTINFO_SUBJECTNAME,
								CRYPT_UNUSED ) );
		printDN( certificate );
		if( cryptStatusOK( \
				cryptGetAttribute( certificate,
								   CRYPT_CERTINFO_SUBJECTALTNAME, &value ) ) )
			{
			CHK( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT,
									CRYPT_CERTINFO_SUBJECTALTNAME ) );
			printAltName( certificate );
			}
		}

	/* Display the validity information */
#ifndef _WIN32_WCE
	if( certType == CRYPT_CERTTYPE_CERTCHAIN ||
		certType == CRYPT_CERTTYPE_CERTIFICATE || \
		certType == CRYPT_CERTTYPE_ATTRIBUTE_CERT )
		{
		time_t validFrom, validTo;

		CHK( cryptGetAttributeString( certificate, CRYPT_CERTINFO_VALIDFROM,
									  &validFrom, &length ) );
		CHK( cryptGetAttributeString( certificate, CRYPT_CERTINFO_VALIDTO,
									  &validTo, &length ) );
		strcpy( buffer, ctime( &validFrom ) );
		buffer[ strlen( buffer ) - 1 ] = '\0';	/* Stomp '\n' */
		printf( "Certificate is valid from %s to %s", buffer,
				ctime( &validTo ) );
		}
	if( certType == CRYPT_CERTTYPE_OCSP_RESPONSE )
		{
		char tuBuffer[ 50 ], nuBuffer[ 50 ];
		time_t timeStamp;

		status = cryptGetAttributeString( certificate, CRYPT_CERTINFO_THISUPDATE,
										  &timeStamp, &length );
		if( cryptStatusOK( status ) )
			{
			/* RTCS basic responses only return a minimal valid/not valid
			   status, so failing to find a time isn't an error */
			strcpy( tuBuffer, ctime( &timeStamp ) );
			tuBuffer[ strlen( tuBuffer ) - 1 ] = '\0';		/* Stomp '\n' */
			status = cryptGetAttributeString( certificate,
											  CRYPT_CERTINFO_NEXTUPDATE,
											  &timeStamp, &length );
			if( cryptStatusOK( status ) )
				{
				strcpy( nuBuffer, ctime( &timeStamp ) );
				nuBuffer[ strlen( nuBuffer ) - 1 ] = '\0';	/* Stomp '\n' */
				printf( "OCSP source CRL time %s,\n  next update %s.\n", tuBuffer,
						nuBuffer );
				}
			else
				printf( "OCSP source CRL time %s.\n", tuBuffer );
			}
		}
	if( certType == CRYPT_CERTTYPE_CRL )
		{
		char tuBuffer[ 50 ], nuBuffer[ 50 ];
		time_t timeStamp;

		CHK( cryptGetAttributeString( certificate, CRYPT_CERTINFO_THISUPDATE,
									  &timeStamp, &length ) );
		strcpy( tuBuffer, ctime( &timeStamp ) );
		tuBuffer[ strlen( tuBuffer ) - 1 ] = '\0';		/* Stomp '\n' */
		status = cryptGetAttributeString( certificate, CRYPT_CERTINFO_NEXTUPDATE,
										  &timeStamp, &length );
		if( cryptStatusOK( status ) )
			{
			strcpy( nuBuffer, ctime( &timeStamp ) );
			nuBuffer[ strlen( nuBuffer ) - 1 ] = '\0';	/* Stomp '\n' */
			printf( "CRL time %s,\n  next update %s.\n", tuBuffer, nuBuffer );
			}
		else
			printf( "CRL time %s.\n", tuBuffer );
		}
#endif /* _WIN32_WCE */
	if( certType == CRYPT_CERTTYPE_CRL || \
		certType == CRYPT_CERTTYPE_RTCS_RESPONSE || \
		certType == CRYPT_CERTTYPE_OCSP_RESPONSE )
		{
		int noEntries = 0;

		/* Count and display the entries */
		if( cryptSetAttribute( certificate, CRYPT_CERTINFO_CURRENT_CERTIFICATE,
							   CRYPT_CURSOR_FIRST ) == CRYPT_OK )
			{
			puts( "Revocation/validity list information: " );
			do
				{
				char timeBuffer[ 50 ];
#ifndef _WIN32_WCE
				time_t timeStamp;
#endif /* _WIN32_WCE */
				int revStatus, certStatus;

				noEntries++;

				/* Extract response-specific status information */
				if( certType == CRYPT_CERTTYPE_RTCS_RESPONSE )
					{
					CHK( cryptGetAttribute( certificate,
								CRYPT_CERTINFO_CERTSTATUS, &certStatus ) );
					}
				if( certType == CRYPT_CERTTYPE_OCSP_RESPONSE )
					{
					CHK( cryptGetAttribute( certificate,
								CRYPT_CERTINFO_REVOCATIONSTATUS, &revStatus ) );
					}
#ifndef _WIN32_WCE
				if( certType == CRYPT_CERTTYPE_CRL || \
					( certType == CRYPT_CERTTYPE_OCSP_RESPONSE && \
					  revStatus == CRYPT_OCSPSTATUS_REVOKED ) || \
					( certType == CRYPT_CERTTYPE_RTCS_RESPONSE && \
					  certStatus == CRYPT_CERTSTATUS_NOTVALID ) )
					{
					CHK( cryptGetAttributeString( certificate,
								CRYPT_CERTINFO_REVOCATIONDATE, &timeStamp,
								&length ) );
					strcpy( timeBuffer, ctime( &timeStamp ) );
					timeBuffer[ strlen( timeBuffer ) - 1 ] = '\0';	/* Stomp '\n' */
					}
				else
#endif /* _WIN32_WCE */
					strcpy( timeBuffer, "<None>" );

				/* Make sure we don't print excessive amounts of
				   information */
				if( noEntries >= 20 )
					{
					if( noEntries == 20 )
						puts( "  (Further entries exist, but won't be printed)." );
					continue;
					}

				/* Print details status info */
				switch( certType )
					{
					case CRYPT_CERTTYPE_RTCS_RESPONSE:
						printf( "  Certificate status = %d (%s).\n",
								certStatus,
								( certStatus == CRYPT_CERTSTATUS_VALID ) ? \
									"valid" : \
								( certStatus == CRYPT_CERTSTATUS_NOTVALID ) ? \
									"not valid" : \
								( certStatus == CRYPT_CERTSTATUS_NONAUTHORITATIVE ) ? \
									"only non-authoritative response available" : \
									"unknown" );
						break;

					case CRYPT_CERTTYPE_OCSP_RESPONSE:
						printf( "  Entry %d, rev.status = %d (%s), rev.time "
								"%s.\n", noEntries, revStatus,
								( revStatus == CRYPT_OCSPSTATUS_NOTREVOKED ) ? \
									"not revoked" : \
								( revStatus == CRYPT_OCSPSTATUS_REVOKED ) ? \
									"revoked" : "unknown",
								timeBuffer );
						break;

					case CRYPT_CERTTYPE_CRL:
						printf( "  Entry %d, revocation time %s.\n", noEntries,
								timeBuffer );
						break;

					default:
						assert( 0 );
					}
				}
			while( cryptSetAttribute( certificate,
									  CRYPT_CERTINFO_CURRENT_CERTIFICATE,
									  CRYPT_CURSOR_NEXT ) == CRYPT_OK );
			}
		printf( "Revocation/validity list has %d entr%s.\n", noEntries,
				( noEntries == 1 ) ? "y" : "ies" );
		}

	/* Display the self-signed status and fingerprint */
	if( cryptStatusOK( cryptGetAttribute( certificate,
									CRYPT_CERTINFO_SELFSIGNED, &value ) ) )
		printf( "Certificate object is %sself-signed.\n",
				value ? "" : "not " );
	if( certType == CRYPT_CERTTYPE_CERTIFICATE || \
		certType == CRYPT_CERTTYPE_CERTCHAIN )
		{
		CHK( cryptGetAttributeString( certificate, CRYPT_CERTINFO_FINGERPRINT,
									  buffer, &length ) );
		printf( "Certificate fingerprint = " );
		printHex( buffer, length );
		}

	/* List the attribute types */
	if( !displayAttributes( certificate ) )
		return( FALSE );

	/* Display common attributes */
	if( cryptStatusError( \
			cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT_GROUP,
							   CRYPT_CURSOR_FIRST ) ) )
		{
		puts( "  (No extensions/attributes)." );
		return( TRUE );
		}
	puts( "Some of the common extensions/attributes are:" );
	if( certType == CRYPT_CERTTYPE_CRL )
		{
		time_t theTime;

		CHK( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT_GROUP,
								CRYPT_CURSOR_FIRST ) );
		status = cryptGetAttribute( certificate, CRYPT_CERTINFO_CRLNUMBER,
									&value );
		if( cryptStatusOK( status ) && value )
			printf( "  crlNumber = %d.\n", value );
		status = cryptGetAttribute( certificate, CRYPT_CERTINFO_DELTACRLINDICATOR,
									&value );
		if( cryptStatusOK( status ) && value )
			printf( "  deltaCRLIndicator = %d.\n", value );
		status = cryptGetAttribute( certificate, CRYPT_CERTINFO_CRLREASON,
									&value );
		if( cryptStatusOK( status ) && value )
			printf( "  crlReason = %d.\n", value );
		status = cryptGetAttributeString( certificate,
								CRYPT_CERTINFO_INVALIDITYDATE, &theTime, &length );
#ifndef _WIN32_WCE
		if( cryptStatusOK( status ) )
			printf( "  invalidityDate = %s", ctime( &theTime ) );
#endif /* _WIN32_WCE */
		if( cryptStatusOK( \
				cryptGetAttribute( certificate,
								   CRYPT_CERTINFO_ISSUINGDIST_FULLNAME, &value ) ) )
			{
			CHK( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT,
									CRYPT_CERTINFO_ISSUINGDIST_FULLNAME ) );
			puts( "  issuingDistributionPoint is:" );
			printDN( certificate );
			printAltName( certificate );
			}
		return( TRUE );
		}
#ifndef _WIN32_WCE
	if( certType == CRYPT_CERTTYPE_CMS_ATTRIBUTES )
		{
		time_t signingTime;

		status = cryptGetAttributeString( certificate,
										  CRYPT_CERTINFO_CMS_SIGNINGTIME,
										  &signingTime, &length );
		if( cryptStatusOK( status ) )
			printf( "Signing time %s", ctime( &signingTime ) );
		return( TRUE );
		}
#endif /* _WIN32_WCE */
	if( certType == CRYPT_CERTTYPE_PKIUSER )
		{
		CHK( cryptGetAttributeString( certificate, CRYPT_CERTINFO_PKIUSER_ID,
									  buffer, &length ) );
		buffer[ length ] ='\0';
		printf( "  PKI user ID = %s.\n", buffer );
		CHK( cryptGetAttributeString( certificate,
									  CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD,
									  buffer, &length ) );
		buffer[ length ] ='\0';
		printf( "  PKI user issue password = %s.\n", buffer );
		CHK( cryptGetAttributeString( certificate,
									  CRYPT_CERTINFO_PKIUSER_REVPASSWORD,
									  buffer, &length ) );
		buffer[ length ] ='\0';
		printf( "  PKI user revocation password = %s.\n", buffer );
		return( TRUE );
		}
	status = cryptGetAttribute( certificate,
								CRYPT_CERTINFO_KEYUSAGE, &value );
	if( cryptStatusOK( status ) && value )
		{
		static const struct { int flag; char *name; } usageNames[] = {
			{ CRYPT_KEYUSAGE_DIGITALSIGNATURE, "digSig" },
			{ CRYPT_KEYUSAGE_NONREPUDIATION, "nonRep" },
			{ CRYPT_KEYUSAGE_KEYENCIPHERMENT, "keyEnc" },
			{ CRYPT_KEYUSAGE_DATAENCIPHERMENT, "dataEnc" },
			{ CRYPT_KEYUSAGE_KEYAGREEMENT, "keyAgree" },
			{ CRYPT_KEYUSAGE_KEYCERTSIGN, "certSign" },
			{ CRYPT_KEYUSAGE_CRLSIGN, "crlSign" },
			{ CRYPT_KEYUSAGE_ENCIPHERONLY, "encOnly" },
			{ CRYPT_KEYUSAGE_DECIPHERONLY, "decOnly" },
			{ CRYPT_KEYUSAGE_NONE, NULL }
			};
		BOOLEAN printedUsage = FALSE;
		int i;

		printf( "  keyUsage = %02X (", value );
		for( i = 0; usageNames[ i ].flag != CRYPT_KEYUSAGE_NONE; i++ )
			{
			if( usageNames[ i ].flag & value )
				{
				if( printedUsage )
					printf( ", " );
				printf( usageNames[ i ].name );
				printedUsage = TRUE;
				}
			}
		printf( ").\n" );
		}
	status = cryptGetAttribute( certificate,
								CRYPT_CERTINFO_EXTKEYUSAGE, &value );
	if( cryptStatusOK( status ) && value )
		{
		BOOLEAN firstTime = TRUE;

		printf( "  extKeyUsage types = " );
		CHK( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT_GROUP,
								CRYPT_CERTINFO_EXTKEYUSAGE ) );
		do
			{
			CHK( cryptGetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT,
									&value ) );
			printf( "%s%d", firstTime ? "" : ", ", value );
			firstTime = FALSE;
			}
		while( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT,
								  CRYPT_CURSOR_NEXT ) == CRYPT_OK );
		printf( ".\n" );
		}
	status = cryptGetAttribute( certificate, CRYPT_CERTINFO_CA, &value );
	if( cryptStatusOK( status ) && value )
		printf( "  basicConstraints.cA = %s.\n", value ? "True" : "False" );
	status = cryptGetAttribute( certificate, CRYPT_CERTINFO_PATHLENCONSTRAINT,
								&value );
	if( cryptStatusOK( status ) && value )
		printf( "  basicConstraints.pathLenConstraint = %d.\n", value );
	status = cryptGetAttributeString( certificate,
							CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER, buffer, &length );
	if( cryptStatusOK( status ) )
		{
		printf( "  subjectKeyIdentifier = " );
		printHex( buffer, length );
		}
	status = cryptGetAttributeString( certificate,
							CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER, buffer, &length );
	if( cryptStatusOK( status ) )
		{
		printf( "  authorityKeyIdentifier = " );
		printHex( buffer, length );
		}
	status = cryptGetAttributeString( certificate,
							CRYPT_CERTINFO_CERTPOLICYID, buffer, &length );
	if( cryptStatusOK( status ) )
		{
		buffer[ length ] = '\0';
		printf( "  certificatePolicies.policyInformation.policyIdentifier = "
				"%s.\n", buffer );
		status = cryptGetAttributeString( certificate,
							CRYPT_CERTINFO_CERTPOLICY_CPSURI, buffer, &length );
		if( cryptStatusOK( status ) )
			{
			buffer[ length ] = '\0';
			printf( "  certificatePolicies.policyInformation.cpsURI = "
					"%s.\n", buffer );
			}
		status = cryptGetAttributeString( certificate,
							CRYPT_CERTINFO_CERTPOLICY_ORGANIZATION, buffer, &length );
		if( cryptStatusOK( status ) )
			{
			buffer[ length ] = '\0';
			printf( "  certificatePolicies.policyInformation.organisation = "
					"%s.\n", buffer );
			}
		status = cryptGetAttributeString( certificate,
							CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT, buffer, &length );
		if( cryptStatusOK( status ) )
			{
			buffer[ length ] = '\0';
			printf( "  certificatePolicies.policyInformation.explicitText = "
					"%s.\n", buffer );
			}
		}
	if( cryptStatusOK( \
			cryptGetAttribute( certificate,
							   CRYPT_CERTINFO_CRLDIST_FULLNAME, &value ) ) )
		{
		CHK( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT,
								CRYPT_CERTINFO_CRLDIST_FULLNAME ) );
		puts( "  crlDistributionPoint is/are:" );
		do
			{
			printDN( certificate );
			printAltName( certificate );
			}
		while( cryptSetAttribute( certificate, CRYPT_ATTRIBUTE_CURRENT_INSTANCE,
								  CRYPT_CURSOR_NEXT ) == CRYPT_OK );
		}

	return( TRUE );
	}

int printCertChainInfo( const CRYPT_CERTIFICATE certChain )
	{
	int value, count, status;

	/* Make sure it really is a cert chain */
	CHK( cryptGetAttribute( certChain, CRYPT_CERTINFO_CERTTYPE, &value ) );
	if( value != CRYPT_CERTTYPE_CERTCHAIN )
		{
		printCertInfo( certChain );
		return( TRUE );
		}

	/* Display info on each cert in the chain.  This uses the cursor
	   mechanism to select successive certs in the chain from the leaf up to
	   the root */
	count = 0;
	CHK( cryptSetAttribute( certChain, CRYPT_CERTINFO_CURRENT_CERTIFICATE,
							CRYPT_CURSOR_FIRST ) );
	do
		{
		printf( "Certificate %d\n-------------\n", count++ );
		printCertInfo( certChain );
		printf( "\n" );
		}
	while( cryptSetAttribute( certChain,
			CRYPT_CERTINFO_CURRENT_CERTIFICATE, CRYPT_CURSOR_NEXT ) == CRYPT_OK );

	/* Reset the cursor position in the chain */
	CHK( cryptSetAttribute( certChain, CRYPT_CERTINFO_CURRENT_CERTIFICATE,
							CRYPT_CURSOR_FIRST ) );

	return( TRUE );
	}
