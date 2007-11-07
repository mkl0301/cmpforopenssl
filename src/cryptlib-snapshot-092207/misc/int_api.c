/****************************************************************************
*																			*
*							cryptlib Internal API							*
*						Copyright Peter Gutmann 1992-2007					*
*																			*
****************************************************************************/

/* A generic module that implements a rug under which all problems not
   solved elsewhere are swept */

#include <stdarg.h>
#include <stdio.h>	/* Needed on some systems for macro-mapped *printf()'s */
#if defined( INC_ALL )
  #include "crypt.h"
  #ifdef USE_MD2
	#include "md2.h"
  #endif /* USE_MD2 */
  #ifdef USE_MD5
	#include "md5.h"
  #endif /* USE_MD5 */
  #ifdef USE_RIPEMD160
	#include "ripemd.h"
  #endif /* USE_RIPEMD160 */
  #include "sha.h"
  #ifdef USE_SHA2
	#include "sha2.h"
  #endif /* USE_SHA2 */
  #include "stream.h"
#else
  #include "crypt.h"
  #ifdef USE_MD2
	#include "crypt/md2.h"
  #endif /* USE_MD2 */
  #ifdef USE_MD5
	#include "crypt/md5.h"
  #endif /* USE_MD5 */
  #ifdef USE_RIPEMD160
	#include "crypt/ripemd.h"
  #endif /* USE_RIPEMD160 */
  #include "crypt/sha.h"
  #ifdef USE_SHA2
	#include "crypt/sha2.h"
  #endif /* USE_SHA2 */
  #include "io/stream.h"
#endif /* Compiler-specific includes */

/* Perform the FIPS-140 statistical checks that are feasible on a byte
   string.  The full suite of tests assumes that an infinite source of
   values (and time) is available, the following is a scaled-down version
   used to sanity-check keys and other short random data blocks.  Note that
   this check requires at least 64 bits of data in order to produce useful
   results */

BOOLEAN checkEntropy( const BYTE *data, const int dataLength )
	{
	const int delta = ( dataLength < 16 ) ? 1 : 0;
	int bitCount[ 4 + 8 ] = { 0 }, noOnes, i;

	assert( isReadPtr( data, dataLength ) );
	assert( dataLength >= 8 );

	for( i = 0; i < dataLength; i++ )
		{
		const int value = data[ i ];

		bitCount[ value & 3 ]++;
		bitCount[ ( value >> 2 ) & 3 ]++;
		bitCount[ ( value >> 4 ) & 3 ]++;
		bitCount[ value >> 6 ]++;
		}

	/* Monobit test: Make sure that at least 1/4 of the bits are ones and 1/4
	   are zeroes */
	noOnes = bitCount[ 1 ] + bitCount[ 2 ] + ( 2 * bitCount[ 3 ] );
	if( noOnes < dataLength * 2 || noOnes > dataLength * 6 )
		return( FALSE );

	/* Poker test (almost): Make sure that each bit pair is present at least
	   1/16 of the time.  The FIPS 140 version uses 4-bit values, but the
	   numer of samples available from the keys is far too small for this.

	   This isn't precisely 1/16, for short samples (< 128 bits) we adjust
	   the count by one because of the small sample size, and for odd-length
	   data we're getting four more samples so the actual figure is slightly
	   less than 1/16 */
	if( ( bitCount[ 0 ] + delta < dataLength / 2 ) || \
		( bitCount[ 1 ] + delta < dataLength / 2 ) || \
		( bitCount[ 2 ] + delta < dataLength / 2 ) || \
		( bitCount[ 3 ] + delta < dataLength / 2 ) )
		return( FALSE );

	return( TRUE );
	}

/* Copy a string attribute to external storage, with various range checks
   to follow the cryptlib semantics (these will already have been done by
   the caller, this is just a backup check).  There are two forms for this
   function, one that takes a MESSAGE_DATA parameter containing all of the 
   result parameters in one place and the other that takes distinct result
   parameters, typically because they've been passed down through several
   levels of function call beyond the point where they were in a 
   MESSAGE_DATA.
   
   We also have a second function that's used internally for data-copying */

int attributeCopyParams( void *dest, const int destMaxLength, 
						 int *destLength, const void *source, 
						 const int sourceLength )
	{
	assert( dest == NULL || isWritePtr( dest, destMaxLength ) );
	assert( sourceLength == 0 || isReadPtr( source, sourceLength ) );

	/* Clear return value */
	*destLength = 0;

	if( sourceLength <= 0 )
		return( CRYPT_ERROR_NOTFOUND );
	if( dest != NULL )
		{
		assert( isReadPtr( source, sourceLength ) );

		if( sourceLength > destMaxLength || \
			!isWritePtr( dest, sourceLength ) )
			return( CRYPT_ARGERROR_STR1 );
		memcpy( dest, source, sourceLength );
		}
	*destLength = sourceLength;

	return( CRYPT_OK );
	}

int attributeCopy( MESSAGE_DATA *msgData, const void *attribute,
				   const int attributeLength )
	{
	assert( isWritePtr( msgData, sizeof( MESSAGE_DATA ) ) );
	assert( attributeLength == 0 || \
			isReadPtr( attribute, attributeLength ) );

	return( attributeCopyParams( msgData->data, msgData->length, 
								 &msgData->length, attribute, 
								 attributeLength ) );
	}

int dataCopy( void *dest, const int destMaxLength, int *destLength,
			  const void *source, const int sourceLength )
	{
	assert( isWritePtr( dest, destMaxLength ) );
	assert( isWritePtr( destLength, sizeof( int ) ) );
	assert( isReadPtr( source, sourceLength ) );

	/* Clear return value */
	*destLength = 0;

	if( sourceLength <= 0 )
		return( CRYPT_ERROR_NOTFOUND );
	if( sourceLength > destMaxLength )
		return( CRYPT_ERROR_OVERFLOW );
	memcpy( dest, source, sourceLength );
	*destLength = sourceLength;

	return( CRYPT_OK );
	}

/* Check whether a given algorithm is available */

BOOLEAN algoAvailable( const CRYPT_ALGO_TYPE cryptAlgo )
	{
	CRYPT_QUERY_INFO queryInfo;

	assert( cryptAlgo > CRYPT_ALGO_NONE && cryptAlgo < CRYPT_ALGO_LAST );

	return( cryptStatusOK( krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									IMESSAGE_DEV_QUERYCAPABILITY, &queryInfo,
									cryptAlgo ) ) ? TRUE : FALSE );
	}

/* For a given algorithm pair, check whether the first is stronger than the
   second.  For hashes the order is:

	SHA2 > RIPEMD160 > SHA-1 > all others */

BOOLEAN isStrongerHash( const CRYPT_ALGO_TYPE algorithm1,
						const CRYPT_ALGO_TYPE algorithm2 )
	{
	static const CRYPT_ALGO_TYPE algoPrecedence[] = {
		CRYPT_ALGO_SHA2, CRYPT_ALGO_RIPEMD160, CRYPT_ALGO_SHA,
		CRYPT_ALGO_NONE, CRYPT_ALGO_NONE };
	int algo1index, algo2index;

	assert( algorithm1 >= CRYPT_ALGO_FIRST_HASH && \
			algorithm1 <= CRYPT_ALGO_LAST_HASH );
	assert( algorithm2 >= CRYPT_ALGO_FIRST_HASH && \
			algorithm2 <= CRYPT_ALGO_LAST_HASH );

	/* Find the relative positions on the scale of the two algorithms */
	for( algo1index = 0; 
		 algoPrecedence[ algo1index ] != algorithm1 && \
			algo1index < FAILSAFE_ARRAYSIZE( algoPrecedence, CRYPT_ALGO_TYPE );
		 algo1index++ )
		{
		/* If we've reached an unrated algorithm, it can't be stronger than 
		   the other one */
		if( algoPrecedence[ algo1index ] == CRYPT_ALGO_NONE )
			return( FALSE );
		}
	if( algo1index >= FAILSAFE_ARRAYSIZE( algoPrecedence, CRYPT_ALGO_TYPE ) )
		retIntError_Boolean();
	for( algo2index = 0; 
		 algoPrecedence[ algo2index ] != algorithm2 && \
			algo2index < FAILSAFE_ARRAYSIZE( algoPrecedence, CRYPT_ALGO_TYPE );
		 algo2index++ )
		{
		/* If we've reached an unrated algorithm, it's weaker than the other 
		   one */
		if( algoPrecedence[ algo2index ] == CRYPT_ALGO_NONE )
			return( TRUE );
		}
	if( algo2index >= FAILSAFE_ARRAYSIZE( algoPrecedence, CRYPT_ALGO_TYPE ) )
		retIntError_Boolean();

	/* If the first algorithm has a smaller index than the second, it's a
	   stronger algorithm */
	return( ( algo1index < algo2index ) ? TRUE : FALSE );
	}

/****************************************************************************
*																			*
*							Error-handling Functions						*
*																			*
****************************************************************************/

#ifdef USE_ERRMSGS

/* Exit after recording a detailed error message.  This is used by lower-
   level code to provide more information to the caller than a basic error 
   code */

int retExtFn( const int status, ERROR_INFO *errorInfoPtr, 
			  const char *format, ... )
	{
	va_list argPtr;

	assert( isWritePtr( errorInfoPtr, sizeof( ERROR_INFO ) ) );
	assert( isWritePtr( errorInfoPtr->errorString, MAX_ERRMSG_SIZE ) );
	assert( isReadPtr( format, 4 ) );

	va_start( argPtr, format );
	vsprintf_s( errorInfoPtr->errorString, MAX_ERRMSG_SIZE, format, argPtr ); 
	va_end( argPtr );
	assert( !cryptArgError( status ) );	/* Catch leaks */
	return( cryptArgError( status ) ? CRYPT_ERROR_FAILED : status );
	}

int retExtObjFn( const int status, ERROR_INFO *errorInfoPtr, 
				 const CRYPT_HANDLE extErrorObject, const char *format, ... )
	{
	MESSAGE_DATA msgData;
	va_list argPtr;
	int extErrorStatus;

	assert( isWritePtr( errorInfoPtr, sizeof( ERROR_INFO ) ) );
	assert( isWritePtr( errorInfoPtr->errorString, MAX_ERRMSG_SIZE ) );
	assert( extErrorObject == DEFAULTUSER_OBJECT_HANDLE || \
			isHandleRangeValid( extErrorObject ) );
	assert( isReadPtr( format, 4 ) );

	/* Check whether there's any additional error information available */
	va_start( argPtr, format );
	setMessageData( &msgData, NULL, 0 );
	extErrorStatus = krnlSendMessage( extErrorObject, MESSAGE_GETATTRIBUTE_S,
									  &msgData, 
									  CRYPT_ATTRIBUTE_INT_ERRORMESSAGE );
	if( cryptStatusOK( extErrorStatus ) )
		{
		char extraErrorString[ MAX_ERRMSG_SIZE + 1 + 8 ];

		/* There's additional information present via the additional object, 
		   fetch it and append it to the session-level error message */
		setMessageData( &msgData, extraErrorString, MAX_ERRMSG_SIZE );
		extErrorStatus = krnlSendMessage( extErrorObject, MESSAGE_GETATTRIBUTE_S,
										  &msgData, 
										  CRYPT_ATTRIBUTE_INT_ERRORMESSAGE );
		if( cryptStatusOK( extErrorStatus ) )
			extraErrorString[ msgData.length ] = '\0';
		else
			strlcpy_s( extraErrorString, MAX_ERRMSG_SIZE, 
					   "(None available)" );
		vsprintf_s( errorInfoPtr->errorString, MAX_ERRMSG_SIZE, format, 
					argPtr );
		if( strlen( errorInfoPtr->errorString ) < MAX_ERRMSG_SIZE - 64 )
			{
			strlcat_s( errorInfoPtr->errorString, MAX_ERRMSG_SIZE, 
					   ". Additional information: " );
			strlcat_s( errorInfoPtr->errorString, MAX_ERRMSG_SIZE, 
					   extraErrorString );
			}
		}
	else
		vsprintf_s( errorInfoPtr->errorString, MAX_ERRMSG_SIZE, format, argPtr ); 
	va_end( argPtr );
	assert( !cryptArgError( status ) );	/* Catch leaks */
	return( cryptArgError( status ) ? CRYPT_ERROR_FAILED : status );
	}

int retExtStrFn( const int status, ERROR_INFO *errorInfoPtr, 
				 const char *extErrorString, const char *format, ... )
	{
	char errorString[ MAX_ERRMSG_SIZE + 1 + 8 ];
	va_list argPtr;

	assert( isWritePtr( errorInfoPtr, sizeof( ERROR_INFO ) ) );
	assert( isWritePtr( errorInfoPtr->errorString, MAX_ERRMSG_SIZE ) );
	assert( isReadPtr( extErrorString, 4 ) );
	assert( isReadPtr( format, 4 ) );

	/* This function is typically used when the caller wants to convert 
	   something like "Low-level error string" into "High-level error 
	   string: Low-level error string".  If the low-level error string was
	   generated by a retExt() call then it'll already be in the errorInfo
	   buffer where the high-level error string needs to go.  To get around
	   this we copy the string into a temporary buffer from where it can be
	   appended back onto the string in the errorInfo buffer */
	strlcpy_s( errorString, MAX_ERRMSG_SIZE, extErrorString );

	va_start( argPtr, format );
	vsprintf_s( errorInfoPtr->errorString, MAX_ERRMSG_SIZE, format, argPtr );
	if( strlen( errorInfoPtr->errorString ) < MAX_ERRMSG_SIZE - 64 )
		strlcat_s( errorInfoPtr->errorString, MAX_ERRMSG_SIZE, 
				   errorString );
	va_end( argPtr );
	assert( !cryptArgError( status ) );	/* Catch leaks */
	return( cryptArgError( status ) ? CRYPT_ERROR_FAILED : status );
	}
#endif /* USE_ERRMSGS */

/****************************************************************************
*																			*
*								Time Functions 								*
*																			*
****************************************************************************/

/* Get the system time safely.  The first function implements hard failures,
   converting invalid time values to zero, which yield a warning date of
   1/1/1970 rather than an out-of-bounds or garbage value.  The second
   function implements soft failures, returning an estimate of the
   approximate current date.  The third function is used for operations such
   as signing certs and timestamping and tries to get the time from a
   hardware time source if one is available */

time_t getTime( void )
	{
	const time_t theTime = time( NULL );

	return( ( theTime <= MIN_TIME_VALUE ) ? 0 : theTime );
	}

time_t getApproxTime( void )
	{
	const time_t theTime = time( NULL );

	return( ( theTime <= MIN_TIME_VALUE ) ? CURRENT_TIME_VALUE : theTime );
	}

time_t getReliableTime( const CRYPT_HANDLE cryptHandle )
	{
	CRYPT_DEVICE cryptDevice;
	MESSAGE_DATA msgData;
	time_t theTime;
	int status;

	assert( cryptHandle == SYSTEM_OBJECT_HANDLE || \
			isHandleRangeValid( cryptHandle ) );

	/* Get the dependent device for the object that needs the time */
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETDEPENDENT,
							  &cryptDevice, OBJECT_TYPE_DEVICE );
	if( cryptStatusError( status ) )
		cryptDevice = SYSTEM_OBJECT_HANDLE;

	/* Try and get the time from the device */
	setMessageData( &msgData, &theTime, sizeof( time_t ) );
	status = krnlSendMessage( cryptDevice, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_TIME );
	if( cryptStatusError( status ) && cryptDevice != SYSTEM_OBJECT_HANDLE )
		{
		/* We couldn't get the time from a crypto token, fall back to the
		   system device */
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  IMESSAGE_GETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_TIME );
		}
	if( cryptStatusError( status ) )
		return( 0 );
	return( ( theTime <= MIN_TIME_VALUE ) ? 0 : theTime );
	}

/* Monotonic timer interface that protect against the system clock being 
   changed during a timing operation.  Even without deliberate fiddling
   with the system clock, a timeout during a DST switch can cause something
   like a 5s wait to turn into a 1hr 5s wait, so we have to abstract the
   standard time API into a monotonic time API.  Since these functions are
   purely peripheral to other operations (for example handling timeouts for
   network I/O), they never fail but simply return good-enough results if
   there's a problem (although they assert in debug mode).  This is because 
   we don't want to abort a network session just because we've detected 
   some trivial clock irregularity.

   The way this works is that we record the following information for each
   timing interval:

										endTime
	................+-----------------------+...............
		^			|						|		^
	currentTime		|<--- timeRemaining --->|	currentTime

   When currentTime falls outside the timeRemaining interval, we know that a 
   clock change has occurred and can try and correct it.  Moving forwards
   by an unexpected amount is a bit more tricky because it's hard to define
   "unexpected", so we use an estimation method that detects the typical
   reasons for a clock leap (DST adjust) without yielding false positives */

static void handleTimeOutOfBounds( MONOTIMER_INFO *timerInfo )
	{
	assert( isWritePtr( timerInfo, sizeof( MONOTIMER_INFO ) ) );

	assert( NOTREACHED );

	/* We've run into an overflow condition, this is a bit tricky to handle 
	   because we can't just give up on (say) performing network I/O just 
	   because we can't reliably set a timeout.  The best that we can do is 
	   warn in debug mode and set a zero timeout so that at least one lot of 
	   I/O will still take place */
	timerInfo->totalTimeout = timerInfo->timeRemaining = 0;
	}

static void correctMonoTimer( MONOTIMER_INFO *timerInfo,
							  const time_t currentTime )
	{
	BOOLEAN needsCorrection = FALSE;

	assert( isWritePtr( timerInfo, sizeof( MONOTIMER_INFO ) ) );

	/* If the clock has been rolled back to before the start time, we need 
	   to correct this */
	if( currentTime < timerInfo->endTime - timerInfo->timeRemaining )
		needsCorrection = TRUE;
	else
		{
		/* If we're past the timer end time, check to see whether it's 
		   jumped by a suspicious amount.  If we're more than 30 minutes
		   past the timeout (which will catch things like DST changes)
		   and the initial timeout was less then the change (to avoid a
		   false positive if we've been waiting > 30 minutes for a
		   legitimate timeout), we need to correct this */
		if( currentTime > timerInfo->endTime )
			{
			const time_t delta = currentTime - timerInfo->endTime;

			if( delta > ( 30 * 60 ) && \
				timerInfo->totalTimeout < delta )
				needsCorrection = TRUE;
			}
		}
	if( !needsCorrection )
		return;

	/* The time information has been changed, correct the recorded time
	   information for the new time */
	timerInfo->endTime = currentTime + timerInfo->timeRemaining;
	if( timerInfo->endTime < currentTime + max( timerInfo->timeRemaining,
												timerInfo->totalTimeout ) )
		handleTimeOutOfBounds( timerInfo );
	}

void setMonoTimer( MONOTIMER_INFO *timerInfo, const int duration )
	{
	const time_t currentTime = getApproxTime();

	assert( isWritePtr( timerInfo, sizeof( MONOTIMER_INFO ) ) );
	assert( duration >= 0 && duration < INT_MAX );

	memset( timerInfo, 0, sizeof( MONOTIMER_INFO ) );
	timerInfo->endTime = currentTime + duration;
	timerInfo->timeRemaining = timerInfo->totalTimeout = duration;
	if( duration == 0 )
		return;	/* No-wait I/O, we're done */
	correctMonoTimer( timerInfo, currentTime );
	}

void extendMonoTimer( MONOTIMER_INFO *timerInfo, const int duration )
	{
	const time_t currentTime = getApproxTime();

	assert( isWritePtr( timerInfo, sizeof( MONOTIMER_INFO ) ) );
	assert( duration >= 0 && duration < INT_MAX );

	/* Correct the timer for clock skew if required */
	correctMonoTimer( timerInfo, currentTime );

	/* Extend the monotonic timer's timeout interval to allow for further
	   data to be processed */
	timerInfo->totalTimeout += duration;
	timerInfo->endTime += duration;
	timerInfo->timeRemaining = timerInfo->endTime - currentTime;

	/* Re-correct the timer in case overflow occurred */
	correctMonoTimer( timerInfo, currentTime );
	}

BOOLEAN checkMonoTimerExpired( MONOTIMER_INFO *timerInfo )
	{
	const time_t currentTime = getApproxTime();
	int timeRemaining;

	assert( isWritePtr( timerInfo, sizeof( MONOTIMER_INFO ) ) );

	/* If the timeout has expired, don't try doing anything else */
	if( timerInfo->timeRemaining <= 0 )
		return( TRUE );

	/* Correct the monotonic timer for clock skew if required */
	correctMonoTimer( timerInfo, currentTime );

	/* Check whether the time has expired */
	timeRemaining = timerInfo->endTime - currentTime;
	if( timeRemaining > timerInfo->timeRemaining )
		{
		handleTimeOutOfBounds( timerInfo );
		timeRemaining = 0;
		}
	timerInfo->timeRemaining = timeRemaining;
	return( ( timerInfo->timeRemaining <= 0 ) ? TRUE : FALSE );
	}

BOOLEAN checkMonoTimerExpiryImminent( MONOTIMER_INFO *timerInfo,
									  const int timeLeft )
	{
	const time_t currentTime = getApproxTime();
	int timeRemaining;

	assert( isWritePtr( timerInfo, sizeof( MONOTIMER_INFO ) ) );

	/* If the timeout has expired, don't try doing anything else */
	if( timerInfo->timeRemaining <= 0 )
		return( TRUE );

	/* Correct the monotonic timer for clock skew if required */
	correctMonoTimer( timerInfo, currentTime );

	/* Check whether the time will expire within timeLeft seconds */
	timeRemaining = timerInfo->endTime - currentTime;
	if( timeRemaining > timerInfo->timeRemaining )
		{
		handleTimeOutOfBounds( timerInfo );
		timeRemaining = 0;
		}
	timerInfo->timeRemaining = timeRemaining;
	return( ( timerInfo->timeRemaining < timeLeft ) ? TRUE : FALSE );
	}

/****************************************************************************
*																			*
*							Checksum/Hash Functions							*
*																			*
****************************************************************************/

/* Calculate a 16-bit Fletcher-like checksum of a block of data.  This isn't
   quite a pure Fletcher checksum because we don't bother keeping the
   accumulators at 8 bits, and also don't need to set the initial value to
   nonzero since we'll never see a sequence of zero bytes.  This isn't a big
   deal since all we need is a consistent result.  In addition we don't
   bother with masking to 16 bits during the calculation since it's not
   being used as a true checksum */

int checksumData( const void *data, const int dataLength )
	{
	const BYTE *dataPtr = data;
	int sum1 = 0, sum2 = 0, i;

	assert( isReadPtr( data, dataLength ) );

	/* Error handling: If there's a problem, return a zero checksum */
	if( data == NULL || dataLength <= 0 )
		retIntError();

	for( i = 0; i < dataLength; i++ )
		{
		sum1 += dataPtr[ i ];
		sum2 += sum1;
		}

	return( sum2 & 0xFFFF );
	}

/* Calculate the hash of a block of data.  We use SHA-1 because it's the 
   built-in default, but any algorithm will do since we're only using it
   to transform a variable-length value to a fixed-length one for easy
   comparison purposes */

void hashData( BYTE *hash, const int hashMaxLength, 
			   const void *data, const int dataLength )
	{
	static HASHFUNCTION hashFunction = NULL;
	static int hashSize;
	BYTE hashBuffer[ 20 + 8 ];

	assert( isWritePtr( hash, hashMaxLength ) );
	assert( hashMaxLength >= HASH_DATA_SIZE );
	assert( isReadPtr( data, dataLength ) );

	/* Get the hash algorithm information if necessary */
	if( hashFunction == NULL )
		getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );

	/* Error handling: If there's a problem, return a zero hash.  Note that
	   this can lead to a false-positive match if we've called multiple 
	   times with invalid input, in theory we could full the return buffer 
	   with nonce data to ensure that we never get a false-positive match,
	   but since this is a should-never-occur condition anyway it's not 
	   certain whether forcing a match or forcing a non-match is the 
	   preferred behaviour */
	if( data == NULL || dataLength <= 0 || hashMaxLength > hashSize || \
		hashFunction == NULL )
		{
		memset( hash, 0, hashMaxLength );
		retIntError_Void();
		}

	/* Hash the data and copy as many bytes as the caller has requested to
	   the output (typically they'll require only a subset of the full 
	   amount, since all that we're doing is transforming a variable-length
	   value to a fixed-length value for easy comparison purposes) */
	hashFunction( NULL, hashBuffer, 20, ( BYTE * ) data, dataLength, 
				  HASH_ALL );
	memcpy( hash, hashBuffer, min( hashMaxLength, hashSize ) );
	zeroise( hashBuffer, 20 );
	}

/* Determine the parameters for a particular hash algorithm */

void md2HashBuffer( HASHINFO hashInfo, BYTE *outBuffer, 
					const int outBufMaxLength, const BYTE *inBuffer, 
					const int inLength, const HASH_STATE hashState );
void md5HashBuffer( HASHINFO hashInfo, BYTE *outBuffer, 
					const int outBufMaxLength, const BYTE *inBuffer, 
					const int inLength, const HASH_STATE hashState );
void ripemd160HashBuffer( HASHINFO hashInfo, BYTE *outBuffer, 
						  const int outBufMaxLength, const BYTE *inBuffer, 
						  const int inLength, const HASH_STATE hashState );
void shaHashBuffer( HASHINFO hashInfo, BYTE *outBuffer, 
					const int outBufMaxLength, const BYTE *inBuffer, 
					const int inLength, const HASH_STATE hashState );
void sha2HashBuffer( HASHINFO hashInfo, BYTE *outBuffer, 
					 const int outBufMaxLength, const BYTE *inBuffer, 
					 const int inLength, const HASH_STATE hashState );
void sha2_512HashBuffer( HASHINFO hashInfo, BYTE *outBuffer, 
						 const int outBufMaxLength, const BYTE *inBuffer, 
						 const int inLength, const HASH_STATE hashState );

void getHashParameters( const CRYPT_ALGO_TYPE hashAlgorithm,
						HASHFUNCTION *hashFunction, int *hashSize )
	{
	assert( hashAlgorithm >= CRYPT_ALGO_FIRST_HASH && \
			hashAlgorithm <= CRYPT_ALGO_LAST_HASH );
	assert( isWritePtr( hashFunction, sizeof( HASHFUNCTION ) ) );
	assert( ( hashSize == NULL ) || isWritePtr( hashSize, sizeof( int ) ) );

	switch( hashAlgorithm )
		{
#ifdef USE_MD2
		case CRYPT_ALGO_MD2:
			*hashFunction = md2HashBuffer;
			if( hashSize != NULL )
				*hashSize = MD2_DIGEST_LENGTH;
			return;
#endif /* USE_MD2 */

#ifdef USE_MD5
		case CRYPT_ALGO_MD5:
			*hashFunction = md5HashBuffer;
			if( hashSize != NULL )
				*hashSize = MD5_DIGEST_LENGTH;
			return;
#endif /* USE_MD5 */

#ifdef USE_RIPEMD160
		case CRYPT_ALGO_RIPEMD160:
			*hashFunction = ripemd160HashBuffer;
			if( hashSize != NULL )
				*hashSize = RIPEMD160_DIGEST_LENGTH;
			return;
#endif /* USE_RIPEMD160 */

		case CRYPT_ALGO_SHA:
			*hashFunction = shaHashBuffer;
			if( hashSize != NULL )
				*hashSize = SHA_DIGEST_LENGTH;
			return;

#ifdef USE_SHA2
		case CRYPT_ALGO_SHA2:
			*hashFunction = sha2HashBuffer;
			if( hashSize != NULL )
				*hashSize = SHA256_DIGEST_SIZE;
			return;

  /* SHA2-512 is only available on systems with 64-bit data type support,
     at the moment this is only used internally for some PRFs so we have
	 to handle it via a kludge on SHA2 */
  #ifdef USE_SHA2_512
		case CRYPT_ALGO_SHA2 + 1:
			*hashFunction = sha2_512HashBuffer;
			if( hashSize != NULL )
				*hashSize = SHA512_DIGEST_SIZE;
			return;
  #endif /* USE_SHA2_512 */
#endif /* USE_SHA2 */
		}

	/* Make sure that we always get some sort of hash function rather than
	   just dying.  This code always works because the internal self-test
	   has confirmed the availability and functioning of SHA-1 on startup */
	*hashFunction = shaHashBuffer;
	if( hashSize != NULL )
		*hashSize = SHA_DIGEST_LENGTH;
	retIntError_Void();
	}

/****************************************************************************
*																			*
*								String Functions							*
*																			*
****************************************************************************/

/* Perform various string-processing operations */

int strFindCh( const char *str, const int strLen, const char findCh )
	{
	int i;

	assert( isReadPtr( str, strLen ) );

	for( i = 0; i < strLen; i++ )
		{
		if( str[ i ] == findCh )
			return( i );
		}

	return( -1 );
	}

int strFindStr( const char *str, const int strLen, 
				const char *findStr, const int findStrLen )
	{
	const char findCh = *findStr;
	int i;

	assert( isReadPtr( str, strLen ) );
	assert( isReadPtr( findStr, findStrLen ) );

	for( i = 0; i < strLen - findStrLen; i++ )
		{
		if( str[ i ] == findCh && \
			!strCompare( str + i, findStr, findStrLen ) )
			return( i );
		}

	return( -1 );
	}

int strSkipWhitespace( const char *str, const int strLen )
	{
	int i;

	assert( isReadPtr( str, strLen ) );

	for( i = 0; i < strLen && ( str[ i ] == ' ' || str[ i ] == '\t' ); i++ );
	return( ( i < strLen ) ? i : -1 );
	}

int strSkipNonWhitespace( const char *str, const int strLen )
	{
	int i;

	assert( isReadPtr( str, strLen ) );

	/* This differs slightly from strSkipWhitespace() in that EOL is also 
	   counted as whitespace, so there's never an error condition unless
	   we don't find anything at all */
	for( i = 0; i < strLen && str[ i ] != ' ' && str[ i ] != '\t'; i++ );
	return( i > 0 ? i : -1 );
	}

int strStripWhitespace( char **newStringPtr, const char *string,
						const int stringLen )
	{
	int startPos, endPos;

	assert( isWritePtr( newStringPtr, sizeof( char * ) ) );
	assert( isReadPtr( string, stringLen ) );

	/* Skip leading and trailing whitespace */
	for( startPos = 0;
		 startPos < stringLen && string[ startPos ] <= ' ';
		 startPos++ );
	*newStringPtr = ( char * ) string + startPos;
	for( endPos = stringLen;
		 endPos > startPos && string[ endPos - 1 ] <= ' ';
		 endPos-- );
	return( endPos - startPos );
	}

int strGetNumeric( const char *str, const int strLen, const int minValue,
				   const int maxValue )
	{
	int i, value = 0;

	assert( isReadPtr( str, strLen ) );
	assert( minValue >= 0 && \
			minValue < maxValue && \
			maxValue <= MAX_INTLENGTH );

	/* Safe conversion of the numeric string gets a bit problematic because 
	   atoi() can't really indicate an error except by returning 0, which is 
	   indistinguishable from a zero numeric value.  To handle this, we have
	   to perform the conversion ourselves */
	if( strLen < 1 || strLen > 7 )
		return( CRYPT_ERROR_BADDATA );	/* Must be 'n' ... 'nnnnnnn' */
	for( i = 0; i < strLen; i++ )
		{
		const int ch = str[ i ] - '0';

		if( ch < 0 || ch > 9 )
			return( CRYPT_ERROR_BADDATA );
		value = ( value * 10 ) + ch;
		}
	if( value < 0 || value < minValue || \
		value > MAX_INTLENGTH || value > maxValue )
		return( CRYPT_ERROR_BADDATA );

	return( value );
	}

/* Sanitise a string before passing it back to the user.  This is used to
   clear potential problem characters (for example control characters)
   from strings passed back from untrusted sources.  As well as the length
   of the string that we want to sanitise, we take an additional 
   totalLength parameter that's used to calculate whether we should append 
   a '[...]' to the string to show that there was further output present 
   that was dropped.  Note that only ( string, stringLength ) is valid 
   string data, totalLength may be an arbitrarily large value.
   
   The function returns a pointer to the string to allow it to be used in 
   the form printf( "..%s..", sanitiseString( string, stringLength, 
											  totalLength ) ) */

char *sanitiseString( char *string, const int stringLength, 
					  const int totalLength )
	{
	int i;

	assert( isWritePtr( string, stringLength ) );
	assert( stringLength <= totalLength );

	/* Remove any potentially unsafe characters from the string */
	for( i = 0; i < stringLength; i++ )
		{
		if( !isPrint( string[ i ] ) )
			string[ i ] = '.';
		}

	/* If there was more input than we could fit into the buffer and 
	   there's room for a continuation indicator, add this to the output 
	   string */
	if( ( totalLength > stringLength ) && ( stringLength > 8 ) )
		memcpy( string + stringLength - 5, "[...]", 5 );

	/* Terminate the string to allow it to be used in printf()-style
	   functions */
	string[ stringLength ] = '\0';

	return( string );
	}

/****************************************************************************
*																			*
*						TR 24731 Safe stdlib Extensions						*
*																			*
****************************************************************************/

#ifndef __STDC_LIB_EXT1__

/* Minimal wrappers for the TR 24731 functions to map them to older stdlib 
   equivalents */

int mbstowcs_s( size_t *retval, wchar_t *dst, size_t dstmax, 
				const char *src, size_t len )
	{
	*retval = mbstowcs( dst, src, len );
	return( ( *retval > 0 ) ? 0 : -1 );
	}

int wcstombs_s( size_t *retval, char *dst, size_t dstmax, 
				const wchar_t *src, size_t len )
	{
	*retval = wcstombs( dst, src, len );
	return( ( *retval > 0 ) ? 0 : -1 );
	}
#endif /* !__STDC_LIB_EXT1__ */

/****************************************************************************
*																			*
*						Dynamic Buffer Management Routines					*
*																			*
****************************************************************************/

/* Dynamic buffer management functions.  When reading variable-length
   object data we can usually fit the data into a small fixed-length buffer, 
   but occasionally we have to cope with larger data amounts that require a 
   dynamically-allocated buffer.  The following routines manage this 
   process, dynamically allocating and freeing a larger buffer if required */

static int getDynData( DYNBUF *dynBuf, const CRYPT_HANDLE cryptHandle,
					   const MESSAGE_TYPE message, const int messageParam )
	{
	MESSAGE_DATA msgData;
	void *dataPtr = NULL;
	int status;

	assert( isWritePtr( dynBuf, sizeof( DYNBUF ) ) );
	assert( isHandleRangeValid( cryptHandle ) );
	assert( message == IMESSAGE_GETATTRIBUTE_S || \
			message == IMESSAGE_CRT_EXPORT );

	/* Clear return value.  Note that we don't use the usual memset() to clear 
	   the value since the structure contains the storage for the fixed-size
	   portion of the buffer appended to it, and using memset() to clear that
	   is just unnecessary overhead */
	dynBuf->data = dynBuf->dataBuffer;
	dynBuf->length = 0;

	/* Get the data from the object */
	setMessageData( &msgData, NULL, 0 );
	status = krnlSendMessage( cryptHandle, message, &msgData, messageParam );
	if( cryptStatusError( status ) )
		return( status );
	if( msgData.length > DYNBUF_SIZE )
		{
		/* The data is larger than the built-in buffer size, dynamically
		   allocate a larger buffer */
		if( ( dataPtr = clDynAlloc( "dynCreate", msgData.length ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		msgData.data = dataPtr;
		status = krnlSendMessage( cryptHandle, message, &msgData,
								  messageParam );
		if( cryptStatusError( status ) )
			{
			clFree( "dynCreate", dataPtr );
			return( status );
			}
		dynBuf->data = dataPtr;
		}
	else
		{
		/* The data will fit into the built-in buffer, read it directly into
		   the buffer */
		msgData.data = dynBuf->data;
		status = krnlSendMessage( cryptHandle, message, &msgData,
								  messageParam );
		if( cryptStatusError( status ) )
			return( status );
		}
	dynBuf->length = msgData.length;
	return( CRYPT_OK );
	}

int dynCreate( DYNBUF *dynBuf, const CRYPT_HANDLE cryptHandle,
			   const CRYPT_ATTRIBUTE_TYPE attributeType )
	{
	assert( isWritePtr( dynBuf, sizeof( DYNBUF ) ) );
	assert( isHandleRangeValid( cryptHandle ) );
	assert( isAttribute( attributeType ) || \
			isInternalAttribute( attributeType ) );

	return( getDynData( dynBuf, cryptHandle, IMESSAGE_GETATTRIBUTE_S,
						attributeType ) );
	}

int dynCreateCert( DYNBUF *dynBuf, const CRYPT_HANDLE cryptHandle,
				   const CRYPT_CERTFORMAT_TYPE formatType )
	{
	assert( isWritePtr( dynBuf, sizeof( DYNBUF ) ) );
	assert( isHandleRangeValid( cryptHandle ) );
	assert( formatType == CRYPT_CERTFORMAT_CERTIFICATE );

	return( getDynData( dynBuf, cryptHandle, IMESSAGE_CRT_EXPORT, 
						formatType ) );
	}

void dynDestroy( DYNBUF *dynBuf )
	{
	assert( isWritePtr( dynBuf, sizeof( DYNBUF ) ) );
	assert( isWritePtr( dynBuf->data, dynBuf->length ) );

	zeroise( dynBuf->data, dynBuf->length );
	if( dynBuf->data != dynBuf->dataBuffer )
		clFree( "dynDestroy", dynBuf->data );
	}

/****************************************************************************
*																			*
*							Memory Management Routines						*
*																			*
****************************************************************************/

/* Memory pool management functions.  When allocating many little blocks of
   memory, especially in resource-constrained systems, it's better if we pre-
   allocate a small memory pool ourselves and grab chunks of it as required,
   falling back to dynamically allocating memory later on if we exhaust the
   pool.  The following functions implement the custom memory pool
   management */

typedef struct {
	void *storage;					/* Memory pool */
	int storagePos, storageSize;	/* Current usage and total size of pool */
	} MEMPOOL_INFO;

void initMemPool( void *statePtr, void *memPool, const int memPoolSize )
	{
	MEMPOOL_INFO *state = ( MEMPOOL_INFO * ) statePtr;

	assert( isWritePtr( state, sizeof( MEMPOOL_INFO ) ) );
	assert( isWritePtr( memPool, memPoolSize ) );
	assert( memPoolSize >= 64 );
	assert( sizeof( MEMPOOL_STATE ) >= sizeof( MEMPOOL_INFO ) );

	memset( state, 0, sizeof( MEMPOOL_INFO ) );
	state->storage = memPool;
	state->storageSize = memPoolSize;
	}

void *getMemPool( void *statePtr, const int size )
	{
	MEMPOOL_INFO *state = ( MEMPOOL_INFO * ) statePtr;
	BYTE *allocPtr = state->storage;
	const int allocSize = roundUp( size, sizeof( int ) );

	assert( isWritePtr( state, sizeof( MEMPOOL_INFO ) ) );
	assert( isWritePtr( state->storage, state->storageSize ) );

	/* If we can't satisfy the request from the memory pool, we have to
	   allocate it dynamically */
	if( state->storagePos + allocSize > state->storageSize )
		return( clDynAlloc( "getMemPool", size ) );

	/* We can satisfy the request from the pool */
	allocPtr += state->storagePos;
	state->storagePos += allocSize;
	return( allocPtr );
	}

void freeMemPool( void *statePtr, void *memblock )
	{
	MEMPOOL_INFO *state = ( MEMPOOL_INFO * ) statePtr;

	assert( isWritePtr( state, sizeof( MEMPOOL_INFO ) ) );
	assert( isWritePtr( state->storage, state->storageSize ) );

	/* If the memory block is within the pool, there's nothing to do */
	if( memblock >= state->storage && \
		memblock < ( void * ) ( ( BYTE * ) state->storage + \
										   state->storageSize ) )
		return;

	/* It's outside the pool and therefore dynamically allocated, free it */
	clFree( "freeMemPool", memblock );
	}

/* Debugging malloc() that dumps memory usage diagnostics to stdout */

#ifdef CONFIG_DEBUG_MALLOC

#ifdef __WIN32__
  #include <direct.h>
#endif /* __WIN32__ */

#ifdef __WINCE__

static int wcPrintf( const char *format, ... )
	{
	wchar_t wcBuffer[ 1024 + 8 ];
	char buffer[ 1024 + 8 ];
	va_list argPtr;
	int length;

	va_start( argPtr, format );
	length = vsprintf_s( buffer, 1024, format, argPtr );
	va_end( argPtr );
	mbstowcs( wcBuffer, buffer, length + 1 );
	NKDbgPrintfW( wcBuffer );

	return( length );
	}

#define printf		wcPrintf

#endif /* __WINCE__ */

static int clAllocIndex = 0;

void *clAllocFn( const char *fileName, const char *fnName,
				 const int lineNo, size_t size )
	{
	char buffer[ 512 + 8 ];
	BYTE *memPtr;
	int length;

	/* Strip off the leading path components if we can to reduce the amount
	   of noise in the output */
#if defined( __WIN32__ ) || defined( __UNIX__ )
	if( getcwd( buffer, 512 ) != NULL )
		{
		const int pathLen = strlen( buffer ) + 1;	/* Leading path + '/' */

		assert( pathLen < strlen( fileName ) );
		fileName += pathLen;
		}
#endif /* __WIN32__ || __UNIX__ */

	length = printf( "ALLOC: %s:%s:%d", fileName, fnName, lineNo );
	while( length < 46 )
		{
		putchar( ' ' );
		length++;
		}
	printf( " %4d - %d bytes.\n", clAllocIndex, size );
	if( ( memPtr = malloc( size + sizeof( LONG ) ) ) == NULL )
		return( NULL );
	mputLong( memPtr, clAllocIndex );	/* Implicit memPtr += sizeof( LONG ) */
	clAllocIndex++;
	return( memPtr );
	}

void clFreeFn( const char *fileName, const char *fnName,
			   const int lineNo, void *memblock )
	{
	char buffer[ 512 + 8 ];
	BYTE *memPtr = ( BYTE * ) memblock - sizeof( LONG );
	int index;

	/* Strip off the leading path components if we can to reduce the amount
	   of noise in the output */
#if defined( __WIN32__ ) || defined( __UNIX__ )
	if( getcwd( buffer, 512 ) != NULL )
		{
		const int pathLen = strlen( buffer ) + 1;	/* Leading path + '/' */

		assert( pathLen < strlen( fileName ) );
		fileName += pathLen;
		}
#endif /* __WIN32__ || __UNIX__ */

	index = mgetLong( memPtr );
	memPtr -= sizeof( LONG );		/* mgetLong() changes memPtr */
	length = printf( "FREE : %s:%s:%d", fileName, fnName, lineNo );
	while( length < 46 )
		{
		putchar( ' ' );
		length++;
		}
	printf( " %4d.\n", index );
	free( memPtr );
	}
#endif /* CONFIG_DEBUG_MALLOC */

/****************************************************************************
*																			*
*							Stream Export/Import Routines					*
*																			*
****************************************************************************/

/* Export attribute or certificate data to a stream.  In theory we would
   have to export this via a dynbuf and then write it to the stream, however
   we can save some overhead by writing it directly to the stream's buffer.
   
   Some attributes have a user-defined size (e.g. 
   CRYPT_IATTRIBUTE_RANDOM_NONCE) so we allow the caller to specify an 
   optional length parameter indicating how much of the attribute should be 
   exported */

static int exportAttr( STREAM *stream, const CRYPT_HANDLE cryptHandle,
					   const CRYPT_ATTRIBUTE_TYPE attributeType,
					   const int length )
	{
	MESSAGE_DATA msgData;
	int attrLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );
	assert( cryptHandle == SYSTEM_OBJECT_HANDLE || \
			isHandleRangeValid( cryptHandle ) );
	assert( isAttribute( attributeType ) || \
			isInternalAttribute( attributeType ) );
	assert( ( length == CRYPT_UNUSED ) || \
			( length >= 8 && length <= 16384 ) );

	/* Before we try the export, make sure that everything is OK with the
	   stream */
	if( !sStatusOK( stream ) )
		return( sGetStatus( stream ) );
	if( length != CRYPT_UNUSED )
		{
		/* It's an explicit-length attribute, make sure that there's enough 
		   room left in the stream for it */
		if( sMemDataLeft( stream ) < length )
			return( CRYPT_ERROR_OVERFLOW );
		attrLength = length;
		}
	else
		{
		/* It's an implicit-length attribute whose maximum length is defined 
		   by the stream size */
		attrLength = sMemDataLeft( stream );
		}

	/* Export the attribute directly into the stream buffer */
	setMessageData( &msgData, sMemBufPtr( stream ), attrLength );
	status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, attributeType );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, msgData.length );
	return( status );
	}

int exportAttributeToStream( void *streamPtr, const CRYPT_HANDLE cryptHandle,
							 const CRYPT_ATTRIBUTE_TYPE attributeType )
	{
	assert( isWritePtr( streamPtr, sizeof( STREAM ) ) );
	assert( isHandleRangeValid( cryptHandle ) );
	assert( isAttribute( attributeType ) || \
			isInternalAttribute( attributeType ) );

	return( exportAttr( streamPtr, cryptHandle, attributeType, \
						CRYPT_UNUSED ) );
	}

int exportVarsizeAttributeToStream( void *streamPtr, 
									const CRYPT_HANDLE cryptHandle,
									const CRYPT_ATTRIBUTE_TYPE attributeType,
									const int attributeDataLength )
	{
	assert( isWritePtr( streamPtr, sizeof( STREAM ) ) );
	assert( cryptHandle == SYSTEM_OBJECT_HANDLE );
	assert( attributeType == CRYPT_IATTRIBUTE_RANDOM_NONCE );
	assert( attributeDataLength >= 8 && attributeDataLength <= 1024 );

	return( exportAttr( streamPtr, cryptHandle, attributeType, 
						attributeDataLength ) );
	}

int exportCertToStream( void *streamPtr,
						const CRYPT_CERTIFICATE cryptCertificate,
						const CRYPT_CERTFORMAT_TYPE certFormatType )
	{
	MESSAGE_DATA msgData;
	STREAM *stream = streamPtr;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );
	assert( isHandleRangeValid( cryptCertificate ) );
	assert( certFormatType > CRYPT_CERTFORMAT_NONE && \
			certFormatType < CRYPT_CERTFORMAT_LAST );

	/* Before we try the export, make sure that everything is OK with the
	   stream */
	if( !sStatusOK( stream ) )
		return( sGetStatus( stream ) );
	if( !sIsNullStream( stream ) && \
		sMemDataLeft( stream ) < MIN_CRYPT_OBJECTSIZE )
		return( CRYPT_ERROR_UNDERFLOW );

	/* Export the cert directly into the stream buffer */
	setMessageData( &msgData, sMemBufPtr( stream ), sMemDataLeft( stream ) );
	status = krnlSendMessage( cryptCertificate, IMESSAGE_CRT_EXPORT,
							  &msgData, certFormatType );
	if( cryptStatusOK( status ) )
		status = sSkip( stream, msgData.length );
	return( status );
	}

int importCertFromStream( void *streamPtr,
						  CRYPT_CERTIFICATE *cryptCertificate,
						  const CRYPT_CERTTYPE_TYPE certType, 
						  const int certDataLength )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	STREAM *stream = streamPtr;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( sStatusOK( stream ) );
	assert( isWritePtr( cryptCertificate, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( certDataLength > 0 && certDataLength < INT_MAX );
	assert( certType > CRYPT_CERTTYPE_NONE && \
			certType < CRYPT_CERTTYPE_LAST );

	/* Clear return value */
	*cryptCertificate = CRYPT_ERROR;

	/* Before we try the import, make sure that everything is OK with the
	   stream and parameters */
	if( !sStatusOK( stream ) )
		return( sGetStatus( stream ) );
	if( sMemDataLeft( stream ) < MIN_CRYPT_OBJECTSIZE || \
		certDataLength > sMemDataLeft( stream ) )
		return( CRYPT_ERROR_UNDERFLOW );

	/* Export the cert directly from the stream buffer */
	setMessageCreateObjectIndirectInfo( &createInfo, sMemBufPtr( stream ),
										certDataLength, certType );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		{
		status = sSkip( stream, certDataLength );
		if( cryptStatusOK( status ) )
			*cryptCertificate = createInfo.cryptHandle;
		else
			krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		}
	return( status );
	}

/****************************************************************************
*																			*
*							Safe Text-line Read Functions					*
*																			*
****************************************************************************/

/* Read a line of text data ending in an EOL.  When we read data we're 
   mostly looking for the EOL marker.  If we find more data than will fit in 
   the input buffer, we discard it until we find an EOL.  As a secondary 
   concern, we want to strip leading, trailing, and repeated whitespace.  We 
   handle the former by setting the seen-whitespace flag to true initially, 
   this treats any whitespace at the start of the line as superfluous and 
   strips it.  We also handle continued lines, denoted by a semicolon or 
   occasionally a backslash as the last non-whitespace character.  Stripping 
   of repeated whitespace is also handled by the seenWhitespace flag, 
   stripping of trailing whitespace is handled by walking back through any 
   final whitespace once we see the EOL, and continued lines are handled by
   setting the seenContinuation flag if we see a semicolon or backslash as
   the last non-whitespace character.

   Finally, we also need to handle generic DoS attacks.  If we see more than
   MAX_LINE_LENGTH chars in a line, we bail out */

#define MAX_LINE_LENGTH		4096

static int retTextLineError( STREAM *stream, const int status,
							 const char *format, const int value1, 
							 int value2 )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( format, 4 ) );

	/* Currently only network streams can report extended error information,
	   so if this is a non-network stream we don't try anything further.
	   Note that we can't check for the absence of the error-info structure
	   because that's not present in some builds */
	if( stream->type != STREAM_TYPE_NETWORK )
		return( status );

	/* This extra level of indirection is necessary to turn the opaque 
	   stream pointer back into a STREAM structure for use by the retExt()
	   macro.  Normally this is handled via the STREAM_ERRINFO_VOID
	   macro, but in this case the stream really is being used as an I/O
	   stream (rather than just an errorInfo container) so we can't use
	   this macro here */
	retExt( CRYPT_ERROR_BADDATA, 
			( CRYPT_ERROR_BADDATA, STREAM_ERRINFO, 
			  format, value1, value2 ) );
	}

int readTextLine( READCHARFUNCTION readCharFunction, void *streamPtr, 
				  char *buffer, const int maxSize, BOOLEAN *localError )
	{
	BOOLEAN seenWhitespace, seenContinuation = FALSE;
	int totalChars, bufPos = 0;

	assert( isWritePtr( streamPtr, sizeof( STREAM ) ) );
	assert( maxSize > 16 );
	assert( isWritePtr( buffer, maxSize ) );
	assert( localError == NULL || \
			isWritePtr( localError, sizeof( BOOLEAN ) ) );

	/* Clear return value */
	if( localError != NULL )
		*localError = FALSE;

	/* Set the seen-whitespace flag initially to strip leading whitespace */
	seenWhitespace = TRUE;

	/* Read up to MAX_LINE_LENGTH chars.  Anything longer than this is 
	   probably a DoS */
	for( totalChars = 0; totalChars < MAX_LINE_LENGTH; totalChars++ )
		{
		int ch;

		/* Get the next input character */
		ch = readCharFunction( streamPtr );
		if( cryptStatusError( ch ) )
			return( ch );

		/* If we're over the maximum buffer size, the only character that we 
		   recognise is EOL */
		if( ( bufPos > maxSize - 8 ) && ( ch != '\n' ) )
			{
			/* If we've run off into the weeds (for example we're reading 
			   binary data following the text header), bail out */
			if( !isPrint( ch ) && ch != '\r' )
				{
				if( localError != NULL )
					*localError = TRUE;
				return( retTextLineError( streamPtr, CRYPT_ERROR_BADDATA,
										  "Invalid character 0x%02X at "
										  "position %d", ch, totalChars ) );
				}
			continue;
			}

		/* Process EOL */
		if( ch == '\n' )
			{
			/* Strip trailing whitespace.  At this point it's all been
			   canonicalised so we don't need to check for anything other 
			   than spaces */
			while( bufPos > 0 && buffer[ bufPos - 1 ] == ' ' )
				bufPos--;

			/* If we've seen a continuation marker as the last non-
			   whitespace char, the line continues on the next one */
			if( seenContinuation )
				{
				seenContinuation = FALSE;
				continue;
				}

			/* We're done */
			buffer[ bufPos ] = '\0';
			break;
			}

		/* Ignore any additional decoration that may accompany EOLs */
		if( ch == '\r' )
			continue;

		/* Process whitespace.  We can't use isspace() for this because it
		   includes all sorts of extra control characters */
		if( ch == ' ' || ch == '\t' )
			{
			if( seenWhitespace )
				/* Ignore leading and repeated whitespace */
				continue;
			ch = ' ';	/* Canonicalise whitespace */
			}

		/* Process any remaining chars */
		if( !( isPrint( ch ) ) )
			{
			if( localError != NULL )
				*localError = TRUE;
			return( retTextLineError( streamPtr, CRYPT_ERROR_BADDATA,
									  "Invalid character 0x%02X at "
									  "position %d", ch, totalChars ) );
			}
		buffer[ bufPos++ ] = ch;
		seenWhitespace = ( ch == ' ' ) ? TRUE : FALSE;
		seenContinuation = ( ch == ';' || ch == '\\' || \
						     ( seenContinuation && \
							   seenWhitespace ) ) ? \
						   TRUE : FALSE;
		}
	if( totalChars >= MAX_LINE_LENGTH )
		{
		if( localError != NULL )
			*localError = TRUE;
		return( retTextLineError( streamPtr, CRYPT_ERROR_OVERFLOW,
								  "Text line too long", 0, 0 ) );
		}

	return( bufPos );
	}
