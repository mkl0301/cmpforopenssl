/****************************************************************************
*																			*
*						  cryptlib Mechanism Routines						*
*						Copyright Peter Gutmann 1992-2003					*
*																			*
****************************************************************************/

#ifdef INC_ALL
  #include "crypt.h"
  #include "mech_int.h"
  #include "asn1.h"
  #include "misc_rw.h"
  #include "pgp.h"
#else
  #include "crypt.h"
  #include "mechs/mech_int.h"
  #include "misc/asn1.h"
  #include "misc/misc_rw.h"
  #include "misc/pgp.h"
#endif /* Compiler-specific includes */

/* Prototypes for kernel-internal access functions */

int importPrivateKeyData( STREAM *stream, const CRYPT_CONTEXT iCryptContext,
						  const KEYFORMAT_TYPE type );
int exportPrivateKeyData( STREAM *stream, const CRYPT_CONTEXT iCryptContext,
						  const KEYFORMAT_TYPE type );

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

#if defined( USE_PGP ) || defined( USE_PGPKEYS )

/* Decrypt a PGP MPI */

static int pgpReadDecryptMPI( STREAM *stream,
							  const CRYPT_CONTEXT iCryptContext,
							  const int minLength, const int maxLength )
	{
	void *mpiDataPtr = sMemBufPtr( stream ) + UINT16_SIZE;
	const long position = stell( stream ) + UINT16_SIZE;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isHandleRangeValid( iCryptContext ) );
	assert( minLength >= 1 && maxLength <= CRYPT_MAX_PKCSIZE );

	/* Get the MPI length and decrypt the payload data */
	status = readInteger16Ubits( stream, NULL, NULL, minLength, maxLength );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iCryptContext, IMESSAGE_CTX_DECRYPT,
								  mpiDataPtr, 
								  ( int ) stell( stream ) - position );
	return( status );
	}

/* Checksum a PGP MPI */

static int pgpChecksumMPI( STREAM *stream, const int minLength, 
						   const int maxLength )
	{
	const BYTE *mpiPtr = sMemBufPtr( stream );
	const long position = stell( stream );
	int checkSum = 0, i, length, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( minLength >= 1 && maxLength <= CRYPT_MAX_PKCSIZE );

	/* Read the MPI length and make sure that it's in order */
	status = readInteger16Ubits( stream, NULL, NULL, minLength, maxLength );
	if( cryptStatusError( status ) )
		{
		/* There's a problem with the stream, return a dummy value.  This
		   means that the checksum will (almost certainly) fail, but in
		   any case the stream error state will cause it to fail too */
		return( -1 );
		}

	/* Calculate the MPI checksum */
	length = ( int ) stell( stream ) - position;
	for( i = 0; i < length; i++ )
		checkSum += mpiPtr[ i ];
	return( checkSum );
	}

/* The PGP 2.x key wrap encrypts only the MPI payload data rather than the 
   entire private key record, so we have to read and then decrypt each 
   component separately.  This is a horrible way to handle things because we 
   have to repeatedly process the MPI data, first in the PGP keyring code to
   find out how much key is present, then again during decryption to find 
   the MPI payload that needs to be decrypted, and finally again after
   decryption to find the MPI payload that needs to be hashed */

static int pgp2DecryptKey( const void *data, const int dataLength, 
						   const CRYPT_CONTEXT iCryptContext,
						   const BOOLEAN isDlpAlgo )
	{
	STREAM stream;
	int status;

	assert( isReadPtr( data, dataLength ) );
	assert( isHandleRangeValid( iCryptContext ) );

	sMemConnect( &stream, data, dataLength );
	status = pgpReadDecryptMPI( &stream, iCryptContext,			/* d or x */
								bitsToBytes( 155 ), CRYPT_MAX_PKCSIZE );
	if( cryptStatusOK( status ) && !isDlpAlgo )
		{
		status = pgpReadDecryptMPI( &stream, iCryptContext,			/* p */
									MIN_PKCSIZE / 2, CRYPT_MAX_PKCSIZE );
		if( cryptStatusOK( status ) )
			status = pgpReadDecryptMPI( &stream, iCryptContext,		/* q */
										MIN_PKCSIZE / 2, CRYPT_MAX_PKCSIZE );
		if( cryptStatusOK( status ) )
			status = pgpReadDecryptMPI( &stream, iCryptContext,		/* u */
										MIN_PKCSIZE / 2, CRYPT_MAX_PKCSIZE  );
		}
	sMemDisconnect( &stream );

	return( status );
	}
#endif /* USE_PGP || USE_PGPKEYS */

/* Check that the unwrapped data hasn't been corrupted */

static int checkKeyIntegrity( const void *data, const int dataLength,
							  const int blockSize )
	{
	const BYTE *padPtr;
	int length, padSize, i;

	assert( isReadPtr( data, dataLength ) );
	assert( blockSize >= 8 && blockSize <= CRYPT_MAX_IVSIZE );

	/* Get the length of the encapsulated ASN.1 object */
	length = getObjectLength( data, dataLength );
	if( cryptStatusError( length ) )
		return( ( length == CRYPT_ERROR_BADDATA ) ? \
				CRYPT_ERROR_WRONGKEY : length );

	/* Check that the PKCS #5 padding is as expected.  Performing the check 
	   this way is the reverse of the way that it's usually done because we 
	   already know the payload size from the ASN.1 and can use this to 
	   determine the expected padding value and thus check that the end of 
	   the encrypted data hasn't been subject to a bit-flipping attack.  For 
	   example for RSA private keys the end of the data is:

		[ INTEGER u ][ INTEGER keySize ][ padding ]

	   where the keySize is encoded as a 4-byte value and the padding is 1-8 
	   bytes.  In order to flip the low bits of u, there's a 5/8 chance that 
	   either the keySize value (checked in the RSA read code) or padding 
	   will be messed up, both of which will be detected (in addition the 
	   RSA key load checks try and verify u when the key is loaded).  For 
	   DLP keys the end of the data is:

		[ INTEGER x ][ padding ]

	   for which bit flipping is rather harder to detect since 7/8 of the 
	   time the following block won't be affected, however the DLP key load 
	   checks also verify x when the key is loaded.  The padding checking is 
	   effectively free and helps make Klima-Rosa type attacks harder */
	padPtr = ( const BYTE * ) data + length;
	padSize = blockSize - ( length & ( blockSize - 1 ) );
	if( padSize < 1 || padSize > CRYPT_MAX_IVSIZE )
		return( CRYPT_ERROR_BADDATA );
	for( i = 0; i < padSize; i++ )
		if( padPtr[ i ] != padSize )
			return( CRYPT_ERROR_BADDATA );

	return( CRYPT_OK );
	}

#if defined( USE_PGP ) || defined( USE_PGPKEYS )

static int checkPgp2KeyIntegrity( const void *data, const int dataLength, 
								  const BOOLEAN isDlpAlgo )
	{
	STREAM stream;
	int checkSum, packetChecksum, status;

	assert( isReadPtr( data, dataLength ) );

	/* Checksum the MPI payload to make sure that the decrypt went OK */
	sMemConnect( &stream, data, dataLength );
	checkSum = pgpChecksumMPI( &stream, bitsToBytes( 155 ),	/* d or x */
							   CRYPT_MAX_PKCSIZE );
	if( !isDlpAlgo )
		{
		checkSum += pgpChecksumMPI( &stream, MIN_PKCSIZE / 2,	/* p */
									CRYPT_MAX_PKCSIZE );
		checkSum += pgpChecksumMPI( &stream, MIN_PKCSIZE / 2,	/* q */
									 CRYPT_MAX_PKCSIZE );
		checkSum += pgpChecksumMPI( &stream, MIN_PKCSIZE / 2,	/* u */
									 CRYPT_MAX_PKCSIZE );
		}
	status = packetChecksum = readUint16( &stream );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) || checkSum != packetChecksum )
		return( CRYPT_ERROR_WRONGKEY );
	
	return( CRYPT_OK );
	}

static int checkOpenPgpKeyIntegrity( const void *data, const int dataLength )
	{
	HASHFUNCTION hashFunction;
	BYTE hashValue[ CRYPT_MAX_HASHSIZE + 8 ];
	const BYTE *hashValuePtr;
	int hashSize;

	assert( isReadPtr( data, dataLength ) );

	/* Get the hash algorithm info and make sure that there's room for 
	   minimal-length data and the checksum */
	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
	if( dataLength < bitsToBytes( 155 ) + hashSize )
		return( CRYPT_ERROR_BADDATA );
	hashValuePtr = ( const BYTE * ) data + dataLength - hashSize; 

	/* Hash the data and make sure that it matches the stored MDC */
	hashFunction( NULL, hashValue, CRYPT_MAX_HASHSIZE, data, 
				  dataLength - hashSize, HASH_ALL );
	if( memcmp( hashValue, hashValuePtr, hashSize ) )
		return( CRYPT_ERROR_WRONGKEY );

	return( CRYPT_OK );
	}
#endif /* USE_PGP || USE_PGPKEYS */

/****************************************************************************
*																			*
*							Key Wrap/Unwrap Mechanisms						*
*																			*
****************************************************************************/

/* Perform private key wrapping/unwrapping.  There are several variations of
   this that are handled through common private key wrap mechanism
   functions */

typedef enum { PRIVATEKEY_WRAP_NORMAL,
			   PRIVATEKEY_WRAP_OLD } PRIVATEKEY_WRAP_TYPE;

static int privateKeyWrap( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo,
						   const PRIVATEKEY_WRAP_TYPE type )
	{
	const KEYFORMAT_TYPE formatType = ( type == PRIVATEKEY_WRAP_NORMAL ) ? \
								KEYFORMAT_PRIVATE : KEYFORMAT_PRIVATE_OLD;
	STREAM stream;
	int payloadSize, blockSize, padSize, status;

	UNUSED( dummy );

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );
	assert( type == PRIVATEKEY_WRAP_NORMAL || \
			type == PRIVATEKEY_WRAP_OLD );

	/* Clear the return value */
	if( mechanismInfo->wrappedData != NULL )
		memset( mechanismInfo->wrappedData, 0,
				mechanismInfo->wrappedDataLength );

	/* Get the payload details */
	sMemOpen( &stream, NULL, 0 );
	status = exportPrivateKeyData( &stream, mechanismInfo->keyContext,
								   formatType );
	payloadSize = stell( &stream );
	sMemClose( &stream );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_GETATTRIBUTE, &blockSize,
								  CRYPT_CTXINFO_IVSIZE );
	if( cryptStatusError( status ) )
		return( status );
	padSize = roundUp( payloadSize + 1, blockSize ) - payloadSize;
	assert( !( ( payloadSize + padSize ) & ( blockSize - 1 ) ) );

	/* If this is just a length check, we're done */
	if( mechanismInfo->wrappedData == NULL )
		{
		mechanismInfo->wrappedDataLength = payloadSize + padSize;
		return( CRYPT_OK );
		}

	/* Write the private key data, PKCS #5-pad it, and encrypt it */
	sMemOpen( &stream, mechanismInfo->wrappedData,
			  mechanismInfo->wrappedDataLength );
	status = exportPrivateKeyData( &stream, mechanismInfo->keyContext,
								   formatType );
	sMemDisconnect( &stream );
	if( cryptStatusOK( status ) )
		{
		BYTE startSample[ 8 + 8 ], endSample[ 8 + 8 ];
		BYTE *dataPtr = mechanismInfo->wrappedData;
		const void *dataEndPtr = dataPtr + payloadSize + padSize - 8;
		int i;

		/* Sample the first and last 8 bytes of data so that we can check
		   that they really have been encrypted */
		memcpy( startSample, dataPtr, 8 );
		memcpy( endSample, dataEndPtr, 8 );

		/* Add the PKCS #5 padding and encrypt the data */
		for( i = 0; i < padSize; i++ )
			dataPtr[ payloadSize + i ] = padSize;
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_CTX_ENCRYPT,
								  mechanismInfo->wrappedData,
								  payloadSize + padSize );

		/* Make sure that the original data samples differ from the final
		   data */
		if( cryptStatusOK( status ) && \
			( !memcmp( startSample, dataPtr, 8 ) || \
			  !memcmp( endSample, dataEndPtr, 8 ) ) )
			{
			assert( NOTREACHED );
			status = CRYPT_ERROR_FAILED;
			}
		zeroise( startSample, 8 );
		zeroise( endSample, 8 );
		}
	if( cryptStatusError( status ) )
		{
		zeroise( mechanismInfo->wrappedData,
				 mechanismInfo->wrappedDataLength );
		return( status );
		}
	mechanismInfo->wrappedDataLength = payloadSize + padSize;

	return( CRYPT_OK );
	}

static int privateKeyUnwrap( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo,
							 const PRIVATEKEY_WRAP_TYPE type )
	{
	const KEYFORMAT_TYPE formatType = ( type == PRIVATEKEY_WRAP_NORMAL ) ? \
								KEYFORMAT_PRIVATE : KEYFORMAT_PRIVATE_OLD;
	void *buffer;
	int blockSize, status;

	UNUSED( dummy );

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );
	assert( type == PRIVATEKEY_WRAP_NORMAL || \
			type == PRIVATEKEY_WRAP_OLD );

	/* Make sure that the data has a sane length and is a multiple of the
	   cipher block size.  Since we force the use of CBC mode we know that 
	   it has to have this property */
	status = krnlSendMessage( mechanismInfo->wrapContext,
							  IMESSAGE_GETATTRIBUTE, &blockSize,
							  CRYPT_CTXINFO_IVSIZE );
	if( cryptStatusError( status ) )
		return( status );
	if( ( mechanismInfo->wrappedDataLength >= MAX_PRIVATE_KEYSIZE ) || \
		( mechanismInfo->wrappedDataLength & ( blockSize - 1 ) ) )
		return( CRYPT_ERROR_BADDATA );

	/* Copy the encrypted private key data to a temporary buffer, decrypt it,
	   and read it into the context.  If we get a corrupted-data error then
	   it's far more likely to be because we decrypted with the wrong key
	   than because any data was corrupted, so we convert it to a wrong-key
	   error */
	if( ( status = krnlMemalloc( &buffer, \
							mechanismInfo->wrappedDataLength ) ) != CRYPT_OK )
		return( status );
	memcpy( buffer, mechanismInfo->wrappedData,
			mechanismInfo->wrappedDataLength );
	status = krnlSendMessage( mechanismInfo->wrapContext,
							  IMESSAGE_CTX_DECRYPT, buffer,
							  mechanismInfo->wrappedDataLength );
	if( cryptStatusOK( status ) )
		status = checkKeyIntegrity( buffer, 
									mechanismInfo->wrappedDataLength, 
									blockSize );
	if( cryptStatusOK( status ) )
		{
		STREAM stream;

		sMemConnect( &stream, buffer, mechanismInfo->wrappedDataLength );
		status = importPrivateKeyData( &stream, mechanismInfo->keyContext,
									   formatType );
		if( status == CRYPT_ERROR_BADDATA )
			status = CRYPT_ERROR_WRONGKEY;
		sMemDisconnect( &stream );
		}
	zeroise( buffer, mechanismInfo->wrappedDataLength );
	krnlMemfree( &buffer );

	return( status );
	}

int exportPrivateKey( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );

	return( privateKeyWrap( dummy, mechanismInfo, PRIVATEKEY_WRAP_NORMAL ) );
	}

int importPrivateKey( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );

	return( privateKeyUnwrap( dummy, mechanismInfo, PRIVATEKEY_WRAP_NORMAL ) );
	}

int exportPrivateKeyPKCS8( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );

	return( privateKeyWrap( dummy, mechanismInfo, PRIVATEKEY_WRAP_OLD ) );
	}

int importPrivateKeyPKCS8( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );

	return( privateKeyUnwrap( dummy, mechanismInfo, PRIVATEKEY_WRAP_OLD ) );
	}

#ifdef USE_PGPKEYS

/* Perform PGP private key wrapping/unwrapping.  There are several variations
   of this that are handled through common private key wrap mechanism
   functions.  The variations are:

	PGP2: mpi_enc( d ), mpi_enc( p ), mpi_enc( q ), mpi_enc( u ),
		  uint16 checksum
	
	OpenPGP_Old: enc( mpi [...], 
					  uint16 checksum )
	
	OpenPGP: enc( mpi [...], 
				  byte[20] mdc ) */

typedef enum { PRIVATEKEY_WRAP_PGP2, PRIVATEKEY_WRAP_OPENPGP_OLD,
			   PRIVATEKEY_WRAP_OPENPGP } PRIVATEKEY_WRAP_PGP_TYPE;

static int privateKeyUnwrapPGP( void *dummy,
								MECHANISM_WRAP_INFO *mechanismInfo,
								const PRIVATEKEY_WRAP_PGP_TYPE type )
	{
	CRYPT_ALGO_TYPE cryptAlgo;
	STREAM stream;
	void *buffer;
	int status;

	UNUSED( dummy );

	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );
	assert( type == PRIVATEKEY_WRAP_PGP2 || \
			type == PRIVATEKEY_WRAP_OPENPGP || \
			type == PRIVATEKEY_WRAP_OPENPGP_OLD );

	/* Get various algorithm parameters */
	status = krnlSendMessage( mechanismInfo->keyContext,
							  IMESSAGE_GETATTRIBUTE, &cryptAlgo,
							  CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );

	/* Copy the encrypted private key data to a temporary buffer, decrypt it,
	   and read it into the context */
	if( ( status = krnlMemalloc( &buffer, \
						mechanismInfo->wrappedDataLength ) ) != CRYPT_OK )
		return( status );
	memcpy( buffer, mechanismInfo->wrappedData,
			mechanismInfo->wrappedDataLength );
	if( type == PRIVATEKEY_WRAP_PGP2 )
		status = pgp2DecryptKey( buffer, mechanismInfo->wrappedDataLength,
								 mechanismInfo->wrapContext,
								 ( cryptAlgo != CRYPT_ALGO_RSA ) ? \
									TRUE : FALSE );
	else
		status = krnlSendMessage( mechanismInfo->wrapContext,
								  IMESSAGE_CTX_DECRYPT, buffer,
								  mechanismInfo->wrappedDataLength );
	if( cryptStatusOK( status ) )
		{
		if( type == PRIVATEKEY_WRAP_PGP2 || \
			type == PRIVATEKEY_WRAP_OPENPGP_OLD )
			status = checkPgp2KeyIntegrity( buffer, 
											mechanismInfo->wrappedDataLength,
											( cryptAlgo != CRYPT_ALGO_RSA ) ? \
												TRUE : FALSE  );
		else
			status = checkOpenPgpKeyIntegrity( buffer, 
											   mechanismInfo->wrappedDataLength );
		}
	if( cryptStatusOK( status ) )
		{
		sMemConnect( &stream, buffer, mechanismInfo->wrappedDataLength );
		status = importPrivateKeyData( &stream, mechanismInfo->keyContext,
									   KEYFORMAT_PGP );
		if( status == CRYPT_ERROR_BADDATA )
			status = CRYPT_ERROR_WRONGKEY;
		sMemDisconnect( &stream );
		}
	zeroise( buffer, mechanismInfo->wrappedDataLength );
	krnlMemfree( &buffer );

	return( status );
	}

int importPrivateKeyPGP2( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );

	return( privateKeyUnwrapPGP( dummy, mechanismInfo,
								 PRIVATEKEY_WRAP_PGP2 ) );
	}

int importPrivateKeyOpenPGPOld( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );

	return( privateKeyUnwrapPGP( dummy, mechanismInfo,
								 PRIVATEKEY_WRAP_OPENPGP_OLD ) );
	}

int importPrivateKeyOpenPGP( void *dummy, MECHANISM_WRAP_INFO *mechanismInfo )
	{
	assert( isWritePtr( mechanismInfo, sizeof( MECHANISM_WRAP_INFO ) ) );

	return( privateKeyUnwrapPGP( dummy, mechanismInfo,
								 PRIVATEKEY_WRAP_OPENPGP ) );
	}
#endif /* USE_PGPKEYS */
