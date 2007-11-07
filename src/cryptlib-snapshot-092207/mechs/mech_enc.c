/****************************************************************************
*																			*
*					cryptlib Encryption Mechanism Routines					*
*					  Copyright Peter Gutmann 1992-2006						*
*																			*
****************************************************************************/

#ifdef INC_ALL
  #include "crypt.h"
  #include "mech_int.h"
  #include "asn1.h"
  #include "pgp.h"
#else
  #include "crypt.h"
  #include "mechs/mech_int.h"
  #include "misc/asn1.h"
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

/* Prototypes for kernel-internal access functions */

int extractKeyData( const CRYPT_CONTEXT iCryptContext, void *keyData, 
					const int keyDataMaxLen );

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

#if defined( USE_PGP ) || defined( USE_PGPKEYS )

/* PGP checksums the PKCS #1 wrapped data (even though this doesn't really
   serve any purpose since any decryption error will corrupt the PKCS #1
   padding), the following routine calculates this checksum and either 
   appends it to the data or checks it against the stored value */

static void pgpGenerateChecksum( BYTE *dataPtr, const int length )
	{
	int checksum = 0, i;

	assert( isWritePtr( dataPtr, length ) );

	for( i = 0; i < length; i++ )
		checksum += *dataPtr++;
	mputWord( dataPtr, checksum );
	}

static BOOLEAN pgpVerifyChecksum( const BYTE *dataPtr, const int length )
	{
	int checksum = 0, storedChecksum, i;

	assert( isReadPtr( dataPtr, length ) );

	for( i = 0; i < length; i++ )
		checksum += *dataPtr++;
	storedChecksum = mgetWord( dataPtr );

	return( storedChecksum == checksum );
	}

/* PGP includes the session key information alongside the encrypted key so
   it's not really possible to import the key into a context in the
   conventional sense.  Instead, the import code has to create the context
   as part of the import process and return it to the caller.  This is ugly,
   but less ugly than doing a raw import and handling the key directly in
   the calling code */

static int pgpExtractKey( CRYPT_CONTEXT *iCryptContext, const BYTE *data,
				   const int dataLength )
	{
	CRYPT_ALGO_TYPE cryptAlgo = CRYPT_ALGO_NONE;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	static const CRYPT_MODE_TYPE mode = CRYPT_MODE_CFB;
	int status;

	assert( isWritePtr( iCryptContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( isReadPtr( data, dataLength ) );
	assert( dataLength >= MIN_KEYSIZE );

	/* Get the session key algorithm.  We delay checking the algorithm ID
	   until after the checksum calculation to reduce the chance of being
	   used as an oracle */
	cryptAlgo = pgpToCryptlibAlgo( data[ 0 ], PGP_ALGOCLASS_CRYPT );

	/* Checksum the session key, skipping the algorithm ID at the start and
	   the checksum at the end.  This is actually superfluous since any
	   decryption error will be caught by corrupted PKCS #1 padding with
	   vastly higher probability than this simple checksum, but we do it
	   anyway because PGP does it too */
	if( !pgpVerifyChecksum( data + 1, dataLength - 3 ) )
		return( CRYPT_ERROR_BADDATA );

	/* Make sure that the algorithm ID is valid.  We only perform the check 
	   at this point because this returns a different error code than the 
	   usual bad-data, we want to be absolutely sure that the problem really 
	   is an unknown algorithm and not the result of scrambled decrypted 
	   data */
	if( cryptAlgo == CRYPT_ALGO_NONE )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Create the context ready to have the key loaded into it */
	setMessageCreateObjectInfo( &createInfo, cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
					 ( void * ) &mode, CRYPT_CTXINFO_MODE );
	*iCryptContext = createInfo.cryptHandle;

	return( CRYPT_OK );
	}
#endif /* USE_PGP || USE_PGPKEYS */

/* Wrap/unwrap data using a public/private-key context */

static int pkcWrapData( MECHANISM_WRAP_INFO *mechanismInfo,
						BYTE *wrappedData, const int wrappedDataLength,
						const BOOLEAN usePgpWrap, const BOOLEAN isDlpAlgo )
	{
	BYTE dataSample[ 16 + 8 ];
	const void *samplePtr = wrappedData + ( wrappedDataLength / 2 );
	int status;

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );
	assert( isWritePtr( wrappedData, wrappedDataLength ) );

	/* Take a sample of the input for comparison with the output */
	memcpy( dataSample, samplePtr, 16 );

	if( isDlpAlgo )
		{
		DLP_PARAMS dlpParams;

		/* For DLP-based PKC's the output length isn't the same as the key
		   size so we adjust the return length as required */
		setDLPParams( &dlpParams, wrappedData, wrappedDataLength, 
					  wrappedData, mechanismInfo->wrappedDataLength );
		if( usePgpWrap )
			dlpParams.formatType = CRYPT_FORMAT_PGP;
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_CTX_ENCRYPT, &dlpParams,
								  sizeof( DLP_PARAMS ) );
		if( cryptStatusOK( status ) )
			mechanismInfo->wrappedDataLength = dlpParams.outLen;
		}
	else
		{
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_CTX_ENCRYPT, wrappedData, 
								  wrappedDataLength );
		if( cryptStatusOK( status ) )
			mechanismInfo->wrappedDataLength = wrappedDataLength;
		}
	if( cryptStatusOK( status ) && !memcmp( dataSample, samplePtr, 16 ) )
		{
		/* The data to wrap is unchanged, there's been a catastrophic 
		   failure of the encryption */
		assert( NOTREACHED );
		status = CRYPT_ERROR_FAILED;
		}
	zeroise( dataSample, 16 );
	if( cryptStatusError( status ) )
		/* There was a problem with the wrapping, clear the output value */
		zeroise( wrappedData, wrappedDataLength );

	return( status );
	}

static int pkcUnwrapData( MECHANISM_WRAP_INFO *mechanismInfo, BYTE *data, 
						  const int dataMaxLength, const int dataInLength, 
						  int *dataOutLength, const BOOLEAN usePgpWrap, 
						  const BOOLEAN isDlpAlgo )
	{
	int status;

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );
	assert( isWritePtr( data, dataMaxLength ) );
	assert( dataInLength <= dataMaxLength );
	assert( isWritePtr( dataOutLength, sizeof( int ) ) );

	if( isDlpAlgo )
		{
		DLP_PARAMS dlpParams;

		setDLPParams( &dlpParams, mechanismInfo->wrappedData,
					  mechanismInfo->wrappedDataLength, data, 
					  dataMaxLength );
		if( usePgpWrap )
			dlpParams.formatType = CRYPT_FORMAT_PGP;
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_CTX_DECRYPT, &dlpParams,
								  sizeof( DLP_PARAMS ) );
		if( cryptStatusOK( status ) )
			{
			*dataOutLength = dlpParams.outLen;
			return( CRYPT_OK );
			}
		}
	else
		{
		status = adjustPKCS1Data( data, dataMaxLength,
								  mechanismInfo->wrappedData,
								  mechanismInfo->wrappedDataLength, 
								  dataInLength );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( mechanismInfo->wrapContext,
									  IMESSAGE_CTX_DECRYPT, data,
									  dataInLength );
		if( cryptStatusOK( status ) )
			{
			*dataOutLength = dataInLength;
			return( CRYPT_OK );
			}
		}

	/* There was a problem with the wrapping, clear the output value */
	zeroise( data, CRYPT_MAX_PKCSIZE );
	return( status );
	}

/****************************************************************************
*																			*
*							PKCS #1 Wrap/Unwrap Mechanisms					*
*																			*
****************************************************************************/

/* Generate/recover a PKCS #1 data block */

static int generatePkcs1DataBlock( BYTE *data, const int dataMaxLen, 
								   const int messageLen )
	{
	MESSAGE_DATA msgData;
	const int padSize = dataMaxLen - ( messageLen + 3 );
	int status;

	assert( isWritePtr( data, dataMaxLen ) );
	assert( messageLen > MIN_KEYSIZE && messageLen < dataMaxLen );
	
	/* Determine PKCS #1 padding parameters and make sure that the key is 
	   long enough to encrypt the payload.  PKCS #1 requires that the 
	   maximum payload size be 11 bytes less than the length (to give a 
	   minimum of 8 bytes of random padding) */
	if( messageLen > dataMaxLen - 11 )
		return( CRYPT_ERROR_OVERFLOW );

	/* Encode the payload using the PKCS #1 format:
	   
		[ 0 ][ 2 ][ nonzero random padding ][ 0 ][ payload ]

	   Note that the random padding is a nice place for a subliminal channel,
	   especially with large public key sizes where you can communicate more
	   information in the padding than in the payload */
	data[ 0 ] = 0;
	data[ 1 ] = 2;
	setMessageData( &msgData, data + 2, padSize );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_RANDOM_NZ );
	if( cryptStatusError( status ) )
		{
		zeroise( data, dataMaxLen );
		return( status );
		}
	data[ 2 + padSize ] = 0;

	return( 2 + padSize + 1 );
	}

static int recoverPkcs1DataBlock( BYTE *data, const int dataLen )
	{
	int ch = 1, i;

	assert( isWritePtr( data, dataLen ) );

	/* Undo the PKCS #1 padding:

		[ 0 ][ 2 ][ random nonzero padding ][ 0 ][ payload ]
	
	   with a minimum of 8 bytes padding.  Note that some implementations 
	   may have bignum code that zero-truncates the result, producing a 
	   CRYPT_ERROR_BADDATA error, it's the responsibility of the lower-level 
	   crypto layer to reformat the data to return a correctly-formatted 
	   result if necessary.

	   In order to avoid being used as a decription timing oracle, we bundle
	   all of the formatting checks into a single location, and make the 
	   code as simple and quick as possible.  At best, an attacker will get
	   only a few clock cycles of timing information, which should be lost 
	   in the general noise */
	if( dataLen < 11 + MIN_KEYSIZE )
		{
		/* PKCS #1 padding requires at least 11 (2 + 8 + 1) bytes of 
		   padding data, if there isn't this much present then what we've 
		   got can't be a valid payload */
		return( CRYPT_ERROR_BADDATA );
		}
	if( data[ 0 ] != 0x00 || data[ 1 ] != 0x02 )
		return( CRYPT_ERROR_BADDATA );
	for( i = 2; i < dataLen - MIN_KEYSIZE && \
				( ch = data[ i ] ) != 0x00; i++ );
	if( ch != 0x00 || i < 11 )
		return( CRYPT_ERROR_BADDATA );

	/* Sanity check to make sure that the padding data looks OK.  We only do 
	   this in debug mode since it's a probabalistic test and we don't want 
	   to bail out due to a false positive in production code */
	assert( checkEntropy( data + 2, i ) );

	/* Make sure that there's enough room left after the PKCS #1 padding to
	   hold at least a minimum-length key */
	if( dataLen - ( i + 1 ) < MIN_KEYSIZE )
		return( CRYPT_ERROR_BADDATA );

	return( i + 1 );
	}

/* Perform PKCS #1 wrapping/unwrapping.  There are several variations of
   this that are handled through common PKCS #1 mechanism functions */

typedef enum { PKCS1_WRAP_NORMAL, PKCS1_WRAP_RAW, PKCS1_WRAP_PGP } PKCS1_WRAP_TYPE;

static int pkcs1Wrap( MECHANISM_WRAP_INFO *mechanismInfo,
					  const PKCS1_WRAP_TYPE type )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	BYTE *wrappedData = mechanismInfo->wrappedData, *dataPtr;
	int payloadSize, length, dataBlockSize, status;
#ifdef USE_PGP
	int pgpAlgoID;
#endif /* USE_PGP */

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );
	assert( type == PKCS1_WRAP_NORMAL || type == PKCS1_WRAP_RAW || \
			type == PKCS1_WRAP_PGP );

	/* Clear the return value */
	if( mechanismInfo->wrappedData != NULL )
		memset( mechanismInfo->wrappedData, 0,
				mechanismInfo->wrappedDataLength );

	/* Get various algorithm parameters */
	status = getPkcAlgoParams( mechanismInfo->wrapContext, &cryptAlgo, 
							   &length );
	if( cryptStatusError( status ) )
		return( status );

	/* If this is just a length check, we're done */
	if( mechanismInfo->wrappedData == NULL )
		{
		/* Determine how long the encrypted value will be.  In the case of
		   Elgamal it's just an estimate since it can change by up to two
		   bytes depending on whether the values have the high bit set or
		   not, which requires zero-padding of the ASN.1-encoded integers.
		   This is rather nasty because it means that we can't tell how 
		   large an encrypted value will be without actually creating it.  
		   The 10-byte length at the start is for the ASN.1 SEQUENCE (= 4) 
		   and 2 * INTEGER (= 2*3) encoding */
		mechanismInfo->wrappedDataLength = \
							( cryptAlgo == CRYPT_ALGO_ELGAMAL ) ? \
							10 + ( 2 * ( length + 1 ) ) : length;
		return( CRYPT_OK );
		}

	/* Get the payload details, either as data passed in by the caller or
	   from the key context */
	if( type == PKCS1_WRAP_RAW )
		payloadSize = mechanismInfo->keyDataLength;
	else
		{
		status = krnlSendMessage( mechanismInfo->keyContext,
								  IMESSAGE_GETATTRIBUTE, &payloadSize,
								  CRYPT_CTXINFO_KEYSIZE );
		if( cryptStatusError( status ) )
			return( status );
		}
#ifdef USE_PGP
	if( type == PKCS1_WRAP_PGP )
		{
		CRYPT_ALGO_TYPE sessionKeyAlgo;

		/* PGP includes an additional algorithm specifier and checksum with
		   the wrapped key so we adjust the length to take this into
		   account */
		status = krnlSendMessage( mechanismInfo->keyContext,
								  IMESSAGE_GETATTRIBUTE, &sessionKeyAlgo,
								  CRYPT_CTXINFO_ALGO );
		if( cryptStatusError( status ) )
			return( status );
		pgpAlgoID = cryptlibToPgpAlgo( sessionKeyAlgo );
		if( pgpAlgoID == PGP_ALGO_NONE )
			return( CRYPT_ERROR_NOTAVAIL );
		payloadSize += 3;	/* 1-byte algo ID + 2-byte checksum */
		}
#endif /* USE_PGP */

	/* Generate the PKCS #1 data block, with room for the payload at the 
	   end */
	status = dataBlockSize = generatePkcs1DataBlock( wrappedData, length, 
													 payloadSize );
	if( cryptStatusError( status ) )
		{
		zeroise( wrappedData, length );
		return( status );
		}

	/* Copy the payload in at the last possible moment, then encrypt it */
	dataPtr = wrappedData + dataBlockSize;
	switch( type )
		{
		case PKCS1_WRAP_NORMAL:
			status = extractKeyData( mechanismInfo->keyContext, dataPtr,
									 mechanismInfo->wrappedDataLength - \
										dataBlockSize );
			break;

		case PKCS1_WRAP_RAW:
			memcpy( dataPtr, mechanismInfo->keyData, payloadSize );
			break;

#ifdef USE_PGP
		case PKCS1_WRAP_PGP:
			*dataPtr++ = pgpAlgoID;
			status = extractKeyData( mechanismInfo->keyContext, dataPtr,
									 mechanismInfo->wrappedDataLength - \
										( dataBlockSize + 1 ) );
			pgpGenerateChecksum( dataPtr, payloadSize - 3 );
			break;
#endif /* USE_PGP */

		default:
			retIntError();
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Wrap the encoded data using the public key */
	return( pkcWrapData( mechanismInfo, wrappedData, length,
						 ( type == PKCS1_WRAP_PGP ) ? TRUE : FALSE,
						 ( cryptAlgo == CRYPT_ALGO_ELGAMAL ) ? TRUE : FALSE ) );
	}

static int pkcs1Unwrap( MECHANISM_WRAP_INFO *mechanismInfo,
						const PKCS1_WRAP_TYPE type )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	MESSAGE_DATA msgData;
	BYTE decryptedData[ CRYPT_MAX_PKCSIZE + 8 ];
	const BYTE *payloadPtr;
	int length, dataBlockSize, status;

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );
	assert( type == PKCS1_WRAP_NORMAL || type == PKCS1_WRAP_RAW || \
			type == PKCS1_WRAP_PGP );

	/* Clear the return value if we're returning raw data */
	if( type == PKCS1_WRAP_RAW )
		memset( mechanismInfo->keyData, 0, mechanismInfo->keyDataLength );

	/* Get various algorithm parameters */
	status = getPkcAlgoParams( mechanismInfo->wrapContext, &cryptAlgo, 
							   &length );
	if( cryptStatusError( status ) )
		return( status );

	/* Decrypt the data */
	status = pkcUnwrapData( mechanismInfo, decryptedData, CRYPT_MAX_PKCSIZE,
							length, &length, 
							( type == PKCS1_WRAP_PGP ) ? TRUE : FALSE,
							( cryptAlgo == CRYPT_ALGO_ELGAMAL ) ? TRUE : FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Recover the PKCS #1 data block, with the payload at the end */
	dataBlockSize = recoverPkcs1DataBlock( decryptedData, length );
	if( cryptStatusError( dataBlockSize ) )
		{
		zeroise( decryptedData, CRYPT_MAX_PKCSIZE );
		return( dataBlockSize );
		}
	payloadPtr = decryptedData + dataBlockSize;
	length -= dataBlockSize;

	/* Return the result to the caller or load it into a context as a key */
	switch( type )
		{
#ifdef USE_PGP
		case PKCS1_WRAP_PGP:
			/* PGP includes extra wrapping around the key, so we have to
			   process that before we can load it */
			status = pgpExtractKey( &mechanismInfo->keyContext, payloadPtr, 
									length );
			if( cryptStatusError( status ) )
				break;
			payloadPtr++;		/* Skip algorithm ID */
			length -= 3;		/* Subtract extra wrapping length */
			if( length < MIN_KEYSIZE )
				return( CRYPT_ERROR_BADDATA );
			/* Fall through */
#endif /* USE_PGP */

		case PKCS1_WRAP_NORMAL:
			/* Load the decrypted keying information into the session key
			   context */
			setMessageData( &msgData, ( void * ) payloadPtr, length );
			status = krnlSendMessage( mechanismInfo->keyContext,
									  IMESSAGE_SETATTRIBUTE_S, &msgData,
									  CRYPT_CTXINFO_KEY );
			if( status == CRYPT_ARGERROR_STR1 || \
				status == CRYPT_ARGERROR_NUM1 )
				/* If there was an error with the key value or size, convert
				   the return value into something more appropriate */
				status = CRYPT_ERROR_BADDATA;
			break;

		case PKCS1_WRAP_RAW:
			/* Return the result to the caller */
			if( length > mechanismInfo->keyDataLength )
				status = CRYPT_ERROR_OVERFLOW;
			else
				{
				memcpy( mechanismInfo->keyData, payloadPtr, length );
				mechanismInfo->keyDataLength = length;
				}
			break;

		default:
			retIntError();
		}
	zeroise( decryptedData, CRYPT_MAX_PKCSIZE );

	return( status );
	}

int exportPKCS1( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	UNUSED( dummy );

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );

	return( pkcs1Wrap( mechanismInfo,
					   ( mechanismInfo->keyContext == CRYPT_UNUSED ) ? \
					   PKCS1_WRAP_RAW : PKCS1_WRAP_NORMAL ) );
	}

int importPKCS1( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	UNUSED( dummy );

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );

	return( pkcs1Unwrap( mechanismInfo,
						 ( mechanismInfo->keyData != NULL ) ? \
						 PKCS1_WRAP_RAW : PKCS1_WRAP_NORMAL ) );
	}

#ifdef USE_PGP

int exportPKCS1PGP( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	UNUSED( dummy );

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );

	return( pkcs1Wrap( mechanismInfo, PKCS1_WRAP_PGP ) );
	}

int importPKCS1PGP( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	UNUSED( dummy );

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );

	return( pkcs1Unwrap( mechanismInfo, PKCS1_WRAP_PGP ) );
	}
#endif /* USE_PGP */

/****************************************************************************
*																			*
*							OAEP Key Wrap/Unwrap Mechanisms					*
*																			*
****************************************************************************/

/* If OAEP is used with SHA2-512 in the PRF, the standard CRYPT_MAX_HASHSIZE
   value isn't sufficient to contain the hash data any more, so we have to
   define a special larger-than-normal maximum hash size to contain it */

#define OAEP_MAX_HASHSIZE	64

/* Get the lHash value used for OAEP.  In theory this should be a hash of a 
   label applied to the OAEP operation, but this is never used so what ends
   up being used is a fixed hash of an empty string.  Since this is 
   constant, we can use a pre-calculated value for each hash algorithm */

typedef struct {
	const CRYPT_ALGO_TYPE hashAlgo;
	const BYTE FAR_BSS *lHash;
	const int lHashSize;
	} LHASH_INFO;

static const LHASH_INFO FAR_BSS lHashInfo[] = {
	{ CRYPT_ALGO_SHA, ( const BYTE * )		/* For pedantic compilers */
	  "\xDA\x39\xA3\xEE\x5E\x6B\x4B\x0D\x32\x55\xBF\xEF\x95\x60\x18\x90"
	  "\xAF\xD8\x07\x09", 20 },
	{ CRYPT_ALGO_SHA2, ( const BYTE * )		/* For pedantic compilers */
	  "\xE3\xB0\xC4\x42\x98\xFC\x1C\x14\x9A\xFB\xF4\xC8\x99\x6F\xB9\x24"
	  "\x27\xAE\x41\xE4\x64\x9B\x93\x4C\xA4\x95\x99\x1B\x78\x52\xB8\x55", 32 },
#ifdef USE_SHA2_512
	  /* SHA2-512 is only available on systems with 64-bit data type support, 
	     at the moment this is only used internally for some PRFs so we have 
		 to identify it via a kludge on the SHA2 algorithm ID */
	{ CRYPT_ALGO_SHA2 + 1, ( const BYTE * )	/* For pedantic compilers */
	  "\xCF\x83\xE1\x35\x7E\xEF\xB8\xBD\xF1\x54\x28\x50\xD6\x6D\x80\x07"
	  "\xD6\x20\xE4\x05\x0B\x57\x15\xDC\x83\xF4\xA9\x21\xD3\x6C\xE9\xCE"
	  "\x47\xD0\xD1\x3C\x5D\x85\xF2\xB0\xFF\x83\x18\xD2\x87\x7E\xEC\x2F"
	  "\x63\xB9\x31\xBD\x47\x41\x7A\x81\xA5\x38\x32\x7A\xF9\x27\xDA\x3E", 64 },
#endif /* USE_SHA2_512 */
	{ CRYPT_ALGO_NONE, NULL, 0 }, { CRYPT_ALGO_NONE, NULL, 0 }
	};

static int getOaepHash( void *lHash, const int lHashMaxLen,
						const CRYPT_ALGO_TYPE hashAlgo )
	{
	int i;

	assert( ( lHash == NULL && lHashMaxLen == 0 ) || \
			isWritePtr( lHash, lHashMaxLen ) );
	assert( hashAlgo >= CRYPT_ALGO_FIRST_HASH && 
			hashAlgo <= CRYPT_ALGO_LAST_HASH );

	for( i = 0; lHashInfo[ i ].hashAlgo != CRYPT_ALGO_NONE && \
				i < FAILSAFE_ARRAYSIZE( lHashInfo, LHASH_INFO ); i++ )
		{
		if( lHashInfo[ i ].hashAlgo == hashAlgo )
			{
			if( lHash != NULL )
				memcpy( lHash, lHashInfo[ i ].lHash, 
						lHashInfo[ i ].lHashSize );
			return( lHashInfo[ i ].lHashSize );
			}
		}
	if( i >= FAILSAFE_ARRAYSIZE( lHashInfo, LHASH_INFO ) )
		retIntError();

	zeroise( lHash, lHashMaxLen );
	return( CRYPT_ERROR_NOTAVAIL );
	}

#define getOaepHashSize( hashAlgo )	getOaepHash( NULL, 0, hashAlgo )

/* OAEP mask generation function (MGF1) */

static int mgf1( void *mask, const int maskLen, 
				 const void *seed, const int seedLen,
				 const CRYPT_ALGO_TYPE hashAlgo )
	{
	HASHFUNCTION hashFunction;
	HASHINFO hashInfo;
	BYTE countBuffer[ 4 + 8 ], maskBuffer[ OAEP_MAX_HASHSIZE + 8 ];
	BYTE *maskOutPtr = mask;
	int hashSize, maskIndex, blockCount = 0, iterationCount = 0;

	assert( isWritePtr( mask, maskLen ) );
	assert( isReadPtr( seed, seedLen ) );
	assert( hashAlgo >= CRYPT_ALGO_FIRST_HASH && 
			hashAlgo <= CRYPT_ALGO_LAST_HASH );

	getHashParameters( hashAlgo, &hashFunction, &hashSize );

	/* Set up the block counter buffer.  This will never have more than the
	   last few bits set (8 bits = 5120 bytes of mask for the smallest hash,
	   SHA-1) so we only change the last byte */
	memset( countBuffer, 0, 4 );

	/* Produce enough blocks of output to fill the mask */
	for( maskIndex = 0; maskIndex < maskLen && \
					    iterationCount++ < FAILSAFE_ITERATIONS_MED; 	
		 maskIndex += hashSize, maskOutPtr += hashSize )
		{
		const int noMaskBytes = ( maskLen - maskIndex > hashSize ) ? \
								hashSize : maskLen - maskIndex;

		/* Calculate hash( seed || counter ) */
		countBuffer[ 3 ] = ( BYTE ) blockCount++;
		hashFunction( hashInfo, NULL, 0, seed, seedLen, HASH_START );
		hashFunction( hashInfo, maskBuffer, hashSize, countBuffer, 4, 
					  HASH_END );
		memcpy( maskOutPtr, maskBuffer, noMaskBytes );
		}
	if( iterationCount >= FAILSAFE_ITERATIONS_MED )
		retIntError();
	zeroise( hashInfo, sizeof( HASHINFO ) );
	zeroise( maskBuffer, OAEP_MAX_HASHSIZE );

	return( CRYPT_OK );
	}

/* Generate/recover an OAEP data block:

							 +----------+---------+-------+
						DB = |  lHash   |    PS   |   M   |
							 +----------+---------+-------+
											|
				  +----------+				V
				  |   seed   |--> MGF ---> xor
				  +----------+				|
						|					|
			   +--+		V					|
			   |00|	   xor <----- MGF <-----|
			   +--+		|					|
				 |		|					|
				 V		V					V
			   +--+----------+----------------------------+
		 EM =  |00|maskedSeed|          maskedDB          |
			   +--+----------+----------------------------+ 
						|					|
						V					V
					   xor <----- MGF <-----|
						|					|
						V					|
				  +----------+				V
				  |   seed   |--> MGF ---> xor
				  +----------+				|
											V
							 +----------+---------+-------+
						DB = |  lHash   |    PS   |   M   |
							 +----------+---------+-------+ */

static int generateOaepDataBlock( BYTE *data, const int dataMaxLen, 
								  const void *message, const int messageLen,
								  const void *seed, const int seedLen,
								  const CRYPT_ALGO_TYPE hashAlgo )
	{
	BYTE dbMask[ CRYPT_MAX_PKCSIZE + 8 ], seedMask[ OAEP_MAX_HASHSIZE + 8 ];
	BYTE *maskedSeed = data + 1, *db = maskedSeed + seedLen;
	int dbLen, i, status;

	assert( isWritePtr( data, dataMaxLen ) );
	assert( isReadPtr( message, messageLen ) );
	assert( isReadPtr( seed, seedLen ) );
	assert( seedLen == getOaepHashSize( hashAlgo ) );
	assert( hashAlgo >= CRYPT_ALGO_FIRST_HASH && 
			hashAlgo <= CRYPT_ALGO_LAST_HASH );

	/* Make sure that the payload fits:

		<------------ dataMaxLen ----------->
		+--+------+-------+----+--+---------+
		|00| seed | lhash | PS |01| message |
		+--+------+-------+----+--+---------+
		  1	 hLen	 hLen	 1	 1	 msgLen

	   Although PS may have a length of zero bytes, we require at least one
	   padding byte.  In general the only case where we can ever run into 
	   problems is if we try and use SHA2-512 with a 1024-bit key */
	if( messageLen > dataMaxLen - ( 1 + seedLen + seedLen + 1 + 1 ) )
		return( CRYPT_ERROR_OVERFLOW );

	/* Calculate the sizes of the various data quantities */
	dbLen = dataMaxLen - ( 1 + seedLen );

	/* db = lHash || zeroes || 0x01 || message */
	memset( db, 0, dbLen );
	status = getOaepHash( db, CRYPT_MAX_PKCSIZE, hashAlgo );
	if( cryptStatusError( status ) )
		return( status );
	db[ dbLen - messageLen - 1 ] = 0x01;
	memcpy( db + dbLen - messageLen, message, messageLen );
	
	/* dbMask = MGF1( seed, dbLen ) */
	status = mgf1( dbMask, dbLen, seed, seedLen, hashAlgo );
	if( cryptStatusError( status ) )
		return( status );

	/* maskedDB = db ^ dbMask */
	for( i = 0; i < dbLen; i++ )
		db[ i ] ^= dbMask[ i ];

	/* seedMask = MGF1( maskedDB, seedLen ) */
	status = mgf1( seedMask, seedLen, db, dbLen, hashAlgo );
	if( cryptStatusError( status ) )
		return( status );

	/* maskedSeed = seed ^ seedMask */
	for( i = 0; i < seedLen; i++ )
		maskedSeed[ i ] = ( ( const BYTE * ) seed )[ i ] ^ seedMask[ i ];

	/* data = 0x00 || maskedSeed || maskedDB */
	data[ 0 ] = 0x00;

	zeroise( dbMask, CRYPT_MAX_PKCSIZE );
	zeroise( seedMask, OAEP_MAX_HASHSIZE );

	return( CRYPT_OK );
	}

static int recoverOaepDataBlock( BYTE *message, const int messageMaxLen, 
								 int *messageLen, void *data, 
								 const int dataLen, 
								 const CRYPT_ALGO_TYPE hashAlgo )
	{
	BYTE dbMask[ CRYPT_MAX_PKCSIZE + 8 ], seedMask[ OAEP_MAX_HASHSIZE + 8 ];
	const int seedLen = getOaepHashSize( hashAlgo );
	BYTE *dataPtr = data, *seed = dataPtr + 1, *db = seed + seedLen;
	int dbLen, length, i, m1status, m2status, status;

	assert( isWritePtr( message, messageMaxLen ) );
	assert( isWritePtr( messageLen, sizeof( int ) ) );
	assert( isReadPtr( data, dataLen ) );
	assert( hashAlgo >= CRYPT_ALGO_FIRST_HASH && 
			hashAlgo <= CRYPT_ALGO_LAST_HASH );

	/* Clear return value */
	memset( message, 0, messageMaxLen );
	*messageLen = 0;

	/* Make sure that the MGF requirements are met.  Note that this check 
	   has already been performed by the caller to avoid this being used as 
	   a timing oracle, this is merely here to make the fact that the check 
	   has been done explicit */
	if( cryptStatusError( seedLen ) )
		return( seedLen );

	/* Calculate the sizes of the various data quantities */
	dbLen = dataLen - ( 1 + seedLen );

	/* seedMask = MGF1( maskedDB, seedLen ) */
	m1status = mgf1( seedMask, seedLen, db, dbLen, hashAlgo );

	/* seed = maskedSeed ^ seedMask */
	for( i = 0; i < seedLen; i++ )
		seed[ i ] ^= seedMask[ i ];

	/* dbMask = MGF1( seed, dbLen ) */
	m2status = mgf1( dbMask, dbLen, seed, seedLen, hashAlgo );

	/* db = maskedDB ^ dbMask */
	for( i = 0; i < dbLen; i++ )
		db[ i ] ^= dbMask[ i ];

	/* Verify that:

		data = 0x00 || [seed] || db 
			 = 0x00 || [seed] || lHash || zeroes || 0x01 || message

	   We have to be careful with the order of the checks, for example we 
	   could check for the leading 0x00 before performing the OAEP 
	   processing but this might allow an attacker to mount a timing attack,
	   see "A chosen ciphertext attack on RSA optimal asymmetric encryption 
	   padding (OAEP)" by James Manger, Proceedings of Crypto'01, LNCS 
	   No.2139, p.230.  To make this as hard as possible, we cluster all of 
	   the format checks as close together as we can to try and produce a 
	   near-constant-time accept/reject decision */
	status = getOaepHash( dbMask, CRYPT_MAX_PKCSIZE, hashAlgo );
	if( cryptStatusError( status ) )
		return( status );	/* See earlier comment about oracle attacks */
	if( cryptStatusError( m1status ) || cryptStatusError( m2status ) )
		return( cryptStatusError( m1status ) ? m1status : m2status );
	if( 1 + seedLen + seedLen + 1 + 1 + MIN_KEYSIZE > dataLen )
		{
		/* Make sure that at least a minimum-length payload fits:

			<------------ dataMaxLen ----------->
			+--+------+-------+----+--+---------+
			|00| seed | lhash | PS |01| message |
			+--+------+-------+----+--+---------+
			  1	 hLen	 hLen	 1	 1	 msgLen
		
		   Again, we perform this check after all formatting operations have
		   completed to try and avoid a timing attack */
		return( CRYPT_ERROR_BADDATA );
		}
	if( dataPtr[ 0 ] != 0x00 || memcmp( db, dbMask, seedLen ) )
		return( CRYPT_ERROR_BADDATA );
	for( i = seedLen; i < dbLen && db[ i ] == 0x00; i++ );
	if( i <= seedLen || i >= dbLen || db[ i++ ] != 0x01 )
		return( CRYPT_ERROR_BADDATA );
	length = dbLen - i;
	if( length < MIN_KEYSIZE )
		return( CRYPT_ERROR_UNDERFLOW );
	if( length > messageMaxLen )
		return( CRYPT_ERROR_OVERFLOW );

	/* Return the recovered message to the caller */
	memcpy( message, db + i, length );
	*messageLen = length;

	zeroise( dbMask, CRYPT_MAX_PKCSIZE );
	zeroise( seedMask, OAEP_MAX_HASHSIZE );

	return( CRYPT_OK );
	}

/* Perform OAEP wrapping/unwrapping */

int exportOAEP( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	MESSAGE_DATA msgData;
	BYTE payload[ CRYPT_MAX_KEYSIZE + 8 ], seed[ OAEP_MAX_HASHSIZE + 8 ];
	const int seedLen = getOaepHashSize( mechanismInfo->auxInfo );
	int payloadSize, length, status;

	UNUSED( dummy );
	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );

	/* Clear the return value */
	if( mechanismInfo->wrappedData != NULL )
		memset( mechanismInfo->wrappedData, 0,
				mechanismInfo->wrappedDataLength );

	/* Make sure that the OAEP auxiliary algorithm requirements are met */
	if( cryptStatusError( seedLen ) )
		return( seedLen );

	/* Get various algorithm parameters */
	status = getPkcAlgoParams( mechanismInfo->wrapContext, &cryptAlgo, 
							   &length );
	if( cryptStatusError( status ) )
		return( status );

	/* If this is just a length check, we're done */
	if( mechanismInfo->wrappedData == NULL )
		{
		/* Determine how long the encrypted value will be.  In the case of
		   Elgamal it's just an estimate since it can change by up to two
		   bytes depending on whether the values have the high bit set or
		   not, which requires zero-padding of the ASN.1-encoded integers.
		   This is rather nasty because it means that we can't tell how 
		   large an encrypted value will be without actually creating it.  
		   The 10-byte length at the start is for the ASN.1 SEQUENCE (= 4) 
		   and 2 * INTEGER (= 2*3) encoding */
		mechanismInfo->wrappedDataLength = \
							( cryptAlgo == CRYPT_ALGO_ELGAMAL ) ? \
							10 + ( 2 * ( length + 1 ) ) : length;
		}

	/* Get the payload details from the key context */
	status = krnlSendMessage( mechanismInfo->keyContext, 
							  IMESSAGE_GETATTRIBUTE, &payloadSize,
							  CRYPT_CTXINFO_KEYSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the OAEP random seed value */
	setMessageData( &msgData, seed, seedLen );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_RANDOM );
	if( cryptStatusError( status ) )
		return( status );

	/* Extract the key data and process it into an OAEP data block */
	status = extractKeyData( mechanismInfo->keyContext, payload, payloadSize );
	if( cryptStatusOK( status ) )
		status = generateOaepDataBlock( mechanismInfo->wrappedData, length, 
										payload, payloadSize, seed, seedLen,
										mechanismInfo->auxInfo );
	zeroise( payload, bitsToBytes( CRYPT_MAX_KEYSIZE ) );
	zeroise( seed, OAEP_MAX_HASHSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Wrap the encoded data using the public key */
	return( pkcWrapData( mechanismInfo, mechanismInfo->wrappedData, length, 
						 FALSE, ( cryptAlgo == CRYPT_ALGO_ELGAMAL ) ? \
								TRUE : FALSE ) );
	}

int importOAEP( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	MESSAGE_DATA msgData;
	BYTE decryptedData[ CRYPT_MAX_PKCSIZE + 8 ];
	BYTE message[ CRYPT_MAX_PKCSIZE + 8 ];
	int length, messageLen, status;

	UNUSED( dummy );
	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );

	/* Get various algorithm parameters */
	status = getPkcAlgoParams( mechanismInfo->wrapContext, &cryptAlgo, 
							   &length );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the MGF requirements are met.  This check isn't 
	   actually needed until the recoverOaepDataBlock() call, but we perform
	   it here before the decrypt to avoid being used as a timing oracle
	   (feeding in a non-usable hash function that causes the processing to 
	   bail out right after the decrypt provides a reasonably precise timer 
	   for the decryption) */
	status = getOaepHashSize( mechanismInfo->auxInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Decrypt the data */
	status = pkcUnwrapData( mechanismInfo, decryptedData, CRYPT_MAX_PKCSIZE,
							length, &length, FALSE,
							( cryptAlgo == CRYPT_ALGO_ELGAMAL ) ? TRUE : FALSE );
	if( cryptStatusError( status ) )
		return( status );

	/* Recover the payload from the OAEP data block */
	status = recoverOaepDataBlock( message, CRYPT_MAX_PKCSIZE, &messageLen, 
								   decryptedData, length, 
								   mechanismInfo->auxInfo );
	zeroise( decryptedData, CRYPT_MAX_PKCSIZE );
	if( cryptStatusError( status ) )
		{
		zeroise( message, CRYPT_MAX_PKCSIZE );
		return( status );
		}

	/* Load the decrypted keying information into the session key context */
	setMessageData( &msgData, message, messageLen );
	status = krnlSendMessage( mechanismInfo->keyContext, 
							  IMESSAGE_SETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_KEY );
	if( status == CRYPT_ARGERROR_STR1 || status == CRYPT_ARGERROR_NUM1 )
		/* If there was an error with the key value or size, convert the 
		   return value into something more appropriate */
		status = CRYPT_ERROR_BADDATA;
	zeroise( message, CRYPT_MAX_PKCSIZE );

	return( status );
	}

#if 0

void testOAEP( void )
	{
	const BYTE seed[] = { 0xaa, 0xfd, 0x12, 0xf6, 0x59, 0xca, 0xe6, 0x34, 
						  0x89, 0xb4, 0x79, 0xe5, 0x07, 0x6d, 0xde, 0xc2,
						  0xf0, 0x6c, 0xb5, 0x8f };
	const BYTE message[] = { 0xd4, 0x36, 0xe9, 0x95, 0x69, 0xfd, 0x32, 0xa7,
							 0xc8, 0xa0, 0x5b, 0xbc, 0x90, 0xd3, 0x2c, 0x49 };
	BYTE buffer[ 1024 ], outMessage[ 128 ];
	const int seedLen = getOaepHashSize( CRYPT_ALGO_SHA );
	int outLen, status;

	memset( buffer, '*', 1024 );

	status = generateOaepDataBlock( buffer, 128, message, 16, seed, seedLen, 
									CRYPT_ALGO_SHA );
	status = recoverOaepDataBlock( outMessage, 128, &outLen, buffer, 128, 
								   CRYPT_ALGO_SHA );
	if( outLen != 16 || memcmp( message, outMessage, outLen ) )
		puts( "Bang." );
	puts( "Done." );
	}
#endif /* 0 */

/****************************************************************************
*																			*
*							CMS Wrap/Unwrap Mechanisms						*
*																			*
****************************************************************************/

/* Perform CMS data wrapping.  Returns an error code or the number of output
   bytes */

#define CMS_KEYBLOCK_HEADERSIZE		4

static int cmsGetPadSize( const CRYPT_CONTEXT iExportContext,
						  const int payloadSize )
	{
	int blockSize, totalSize, status;

	assert( isHandleRangeValid( iExportContext ) );
	assert( payloadSize > MIN_KEYSIZE );

	status = krnlSendMessage( iExportContext, IMESSAGE_GETATTRIBUTE,
							  &blockSize, CRYPT_CTXINFO_IVSIZE );
	if( cryptStatusError( status ) )
		return( status );

	/* Determine the padding size, which is the amount of padding required to
	   bring the total data size up to a multiple of the block size with a
	   minimum size of two blocks */
	totalSize = roundUp( payloadSize, blockSize );
	if( totalSize < blockSize * 2 )
		totalSize = blockSize * 2;
	assert( !( totalSize & ( blockSize - 1 ) ) );

	return( totalSize - payloadSize );
	}

int exportCMS( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	BYTE *keyBlockPtr = ( BYTE * ) mechanismInfo->wrappedData;
	BYTE dataSample[ 16 + 8 ];
	int payloadSize, padSize, status = CRYPT_OK;

	UNUSED( dummy );
	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );

	/* Clear the return value */
	if( mechanismInfo->wrappedData != NULL )
		memset( mechanismInfo->wrappedData, 0,
				mechanismInfo->wrappedDataLength );

	/* Get the payload details, either as data passed in by the caller or
	   from the key context */
	if( mechanismInfo->keyContext == CRYPT_UNUSED )
		payloadSize = mechanismInfo->keyDataLength;
	else
		{
		status = krnlSendMessage( mechanismInfo->keyContext,
								  IMESSAGE_GETATTRIBUTE, &payloadSize,
								  CRYPT_CTXINFO_KEYSIZE );
		if( cryptStatusError( status ) )
			return( status );
		}
	payloadSize += CMS_KEYBLOCK_HEADERSIZE;
	padSize = cmsGetPadSize( mechanismInfo->wrapContext, payloadSize );
	if( cryptStatusError( padSize ) )
		return( padSize );

	/* If this is just a length check, we're done */
	if( mechanismInfo->wrappedData == NULL )
		{
		mechanismInfo->wrappedDataLength = payloadSize + padSize;
		return( CRYPT_OK );
		}

	/* Make sure that the wrapped key data fits in the output */
	if( payloadSize + padSize > mechanismInfo->wrappedDataLength )
		return( CRYPT_ERROR_OVERFLOW );

	/* Pad the payload out with a random nonce if required */
	if( padSize > 0 )
		{
		MESSAGE_DATA msgData;

		setMessageData( &msgData, keyBlockPtr + payloadSize, padSize );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Format the key block:

		[ length ][ check value ][ key ][ padding ]
		
	   then copy the payload in at the last possible moment and perform two 
	   passes of encryption, retaining the IV from the first pass for the 
	   second pass */
	keyBlockPtr[ 0 ] = payloadSize - CMS_KEYBLOCK_HEADERSIZE;
	if( mechanismInfo->keyContext != CRYPT_UNUSED )
		status = extractKeyData( mechanismInfo->keyContext,
								 keyBlockPtr + CMS_KEYBLOCK_HEADERSIZE,
								 mechanismInfo->wrappedDataLength - \
									( CMS_KEYBLOCK_HEADERSIZE + padSize ) );
	else
		memcpy( keyBlockPtr + CMS_KEYBLOCK_HEADERSIZE,
				mechanismInfo->keyData, payloadSize );
	keyBlockPtr[ 1 ] = keyBlockPtr[ CMS_KEYBLOCK_HEADERSIZE ] ^ 0xFF;
	keyBlockPtr[ 2 ] = keyBlockPtr[ CMS_KEYBLOCK_HEADERSIZE + 1 ] ^ 0xFF;
	keyBlockPtr[ 3 ] = keyBlockPtr[ CMS_KEYBLOCK_HEADERSIZE + 2 ] ^ 0xFF;
	memcpy( dataSample, keyBlockPtr, 16 );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_CTX_ENCRYPT,
								  mechanismInfo->wrappedData,
								  payloadSize + padSize );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_CTX_ENCRYPT,
								  mechanismInfo->wrappedData,
								  payloadSize + padSize );
	if( cryptStatusOK( status ) && !memcmp( dataSample, keyBlockPtr, 16 ) )
		{
		/* The data to wrap is unchanged, there's been a catastrophic 
		   failure of the encryption */
		assert( NOTREACHED );
		status = CRYPT_ERROR_FAILED;
		}
	zeroise( dataSample, 16 );
	if( cryptStatusError( status ) )
		{
		zeroise( mechanismInfo->wrappedData,
				 mechanismInfo->wrappedDataLength );
		return( status );
		}
	mechanismInfo->wrappedDataLength = payloadSize + padSize;

	return( CRYPT_OK );
	}

/* Perform CMS data unwrapping */

int importCMS( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	MESSAGE_DATA msgData;
	BYTE buffer[ CRYPT_MAX_KEYSIZE + CRYPT_MAX_IVSIZE + 8 ];
	BYTE ivBuffer[ CRYPT_MAX_IVSIZE + 8 ];
	BYTE *dataEndPtr = buffer + mechanismInfo->wrappedDataLength;
	int blockSize, status;

	UNUSED( dummy );
	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );

	/* Make sure that the data is a multiple of the cipher block size and 
	   contains at least two encrypted blocks */
	status = krnlSendMessage( mechanismInfo->wrapContext,
							  IMESSAGE_GETATTRIBUTE, &blockSize,
							  CRYPT_CTXINFO_IVSIZE );
	if( cryptStatusError( status ) )
		return( status );
	if( mechanismInfo->wrappedDataLength & ( blockSize - 1 ) )
		return( CRYPT_ERROR_BADDATA );
	if( mechanismInfo->wrappedDataLength < 2 * blockSize )
		return( CRYPT_ERROR_UNDERFLOW );
	if( mechanismInfo->wrappedDataLength > CRYPT_MAX_KEYSIZE )
		return( CRYPT_ERROR_OVERFLOW );

	/* Save the current IV for the inner decryption */
	setMessageData( &msgData, ivBuffer, CRYPT_MAX_IVSIZE );
	krnlSendMessage( mechanismInfo->wrapContext, IMESSAGE_GETATTRIBUTE_S,
					 &msgData, CRYPT_CTXINFO_IV );

	/* Using the n-1'th ciphertext block as the new IV, decrypt the n'th block.
	   Then, using the decrypted n'th ciphertext block as the IV, decrypt the
	   remainder of the ciphertext blocks */
	memcpy( buffer, mechanismInfo->wrappedData,
			mechanismInfo->wrappedDataLength );
	setMessageData( &msgData, dataEndPtr - ( 2 * blockSize ), blockSize );
	krnlSendMessage( mechanismInfo->wrapContext, IMESSAGE_SETATTRIBUTE_S, 
					 &msgData, CRYPT_CTXINFO_IV );
	status = krnlSendMessage( mechanismInfo->wrapContext,
							  IMESSAGE_CTX_DECRYPT, dataEndPtr - blockSize,
							  blockSize );
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, dataEndPtr - blockSize, blockSize );
		krnlSendMessage( mechanismInfo->wrapContext,
						 IMESSAGE_SETATTRIBUTE_S, &msgData, CRYPT_CTXINFO_IV );
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_CTX_DECRYPT, buffer,
								  mechanismInfo->wrappedDataLength - blockSize );
		}
	if( cryptStatusError( status ) )
		{
		zeroise( buffer, CRYPT_MAX_KEYSIZE + CRYPT_MAX_IVSIZE );
		return( status );
		}

	/* Using the original IV, decrypt the inner data */
	setMessageData( &msgData, ivBuffer, blockSize );
	krnlSendMessage( mechanismInfo->wrapContext, IMESSAGE_SETATTRIBUTE_S,
					 &msgData, CRYPT_CTXINFO_IV );
	status = krnlSendMessage( mechanismInfo->wrapContext,
							  IMESSAGE_CTX_DECRYPT, buffer,
							  mechanismInfo->wrappedDataLength );
	if( cryptStatusOK( status ) )
		{
		/* Make sure that everything is in order and load the decrypted 
		   keying information into the session key context */
		if( buffer[ 0 ] < MIN_KEYSIZE || \
			buffer[ 0 ] > MAX_WORKING_KEYSIZE || \
			buffer[ 0 ] > mechanismInfo->wrappedDataLength - blockSize )
			status = CRYPT_ERROR_BADDATA;
		if( buffer[ 1 ] != ( buffer[ CMS_KEYBLOCK_HEADERSIZE ] ^ 0xFF ) || \
			buffer[ 2 ] != ( buffer[ CMS_KEYBLOCK_HEADERSIZE + 1 ] ^ 0xFF ) || \
			buffer[ 3 ] != ( buffer[ CMS_KEYBLOCK_HEADERSIZE + 2 ] ^ 0xFF ) )
			status = CRYPT_ERROR_BADDATA;
		}
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, buffer + CMS_KEYBLOCK_HEADERSIZE,
						buffer[ 0 ] );
		status = krnlSendMessage( mechanismInfo->keyContext,
								  IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_KEY );
		if( status == CRYPT_ARGERROR_STR1 || status == CRYPT_ARGERROR_NUM1 )
			/* If there was an error with the key value or size, convert the
			   return value into something more appropriate */
			status = CRYPT_ERROR_BADDATA;
		}
	zeroise( buffer, CRYPT_MAX_KEYSIZE + CRYPT_MAX_IVSIZE );

	return( status );
	}
