/****************************************************************************
*																			*
*					cryptlib Internal Mechanism Routines					*
*					  Copyright Peter Gutmann 1992-2006						*
*																			*
****************************************************************************/

#ifdef INC_ALL
  #include "crypt.h"
  #include "mech_int.h"
#else
  #include "crypt.h"
  #include "mechs/mech_int.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*									PKC Routines							*
*																			*
****************************************************************************/

/* The length of the input data for PKCS #1 transformations is usually
   determined by the key size, however sometimes we can be passed data that
   has been zero-padded (for example data coming from an ASN.1 INTEGER in
   which the high bit is a sign bit) making it longer than the key size, or
   that has leading zero byte(s), making it shorter than the key size.  The
   best place to handle this is somewhat uncertain, it's an encoding issue
   so it probably shouldn't be visible to the raw crypto routines, but
   putting it at the mechanism layer removes the algorithm-independence of
   that layer, and putting it at the mid-level sign/key-exchange routine
   layer both removes the algorithm-independence and requires duplication of
   the code for signatures and encryption.  The best place to put it seems to
   be at the mechanism layer, since an encoding issue really shouldn't be
   visible at the crypto layer, and because it would require duplicating the
   handling every time a new PKC implementation is plugged in.

   The intent of the size adjustment is to make the data size match the key
   length.  If it's longer, we try to strip leading zero bytes.  If it's
   shorter, we pad it with zero bytes to match the key size.  The result is
   either the data adjusted to match the key size, or CRYPT_ERROR_BADDATA if
   this isn't possible */

int adjustPKCS1Data( BYTE *outData, const int outDataMaxLen, 
					 const BYTE *inData, const int inLen, const int keySize )
	{
	int length, i;

	assert( isWritePtr( outData, outDataMaxLen ) );
	assert( isReadPtr( inData, inLen ) );
	assert( keySize >= MIN_PKCSIZE && keySize <= CRYPT_MAX_PKCSIZE );
	assert( outData != inData );

	/* Make sure that the result will fit in the output buffer.  This has 
	   already been checked by the kernel mechanism ACL, but we make the 
	   check explicit here */
	if( keySize > outDataMaxLen )
		return( CRYPT_ERROR_OVERFLOW );

	/* Find the start of the data payload.  If it's suspiciously short, 
	   don't try and process it */
	for( i = 0; i < inLen && inData[ i ] == 0; i++ );
	length = inLen - i;
	if( length < MIN_PKCSIZE )
		return( CRYPT_ERROR_BADDATA );

	/* If it's of the correct size, exit */
	if( inLen == keySize )
		{
		memcpy( outData, inData, keySize );
		return( CRYPT_OK );
		}

	/* If it's too long, try and strip leading zero bytes.  If it's still too
	   long, complain */
	while( length > keySize && *inData == 0 )
		{
		length--;
		inData++;
		}
	if( length > keySize )
		return( CRYPT_ERROR_BADDATA );

	/* If it's suspiciously short, don't try and process it */
	if( length < MIN_PKCSIZE - 8 )
		return( CRYPT_ERROR_BADDATA );

	/* We've adjusted the size to account for zero-padding during encoding,
	   now we have to move the data into a fixed-length format to match the
	   key size.  To do this we copy the payload into the output buffer with
	   enough leading-zero bytes to bring the total size up to the key size */
	memset( outData, 0, keySize );
	memcpy( outData + ( keySize - length ), inData, length );

	return( CRYPT_OK );
	}

/* Get PKC algorithm parameters */

int getPkcAlgoParams( const CRYPT_CONTEXT pkcContext,
					  CRYPT_ALGO_TYPE *pkcAlgo, int *pkcKeySize )
	{
	int status;

	assert( isHandleRangeValid( pkcContext ) );
	assert( ( pkcAlgo == NULL ) || \
			isWritePtr( pkcAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );
	assert( isWritePtr( pkcKeySize, sizeof( int ) ) );

	/* Clear return values */
	if( pkcAlgo != NULL )
		*pkcAlgo = CRYPT_ALGO_NONE;
	*pkcKeySize = 0;

	/* Get various PKC algorithm parameters */
	if( pkcAlgo != NULL )
		{
		status = krnlSendMessage( pkcContext, IMESSAGE_GETATTRIBUTE, 
								  pkcAlgo, CRYPT_CTXINFO_ALGO );
		if( cryptStatusError( status ) )
			return( status );
		}
	return( krnlSendMessage( pkcContext, IMESSAGE_GETATTRIBUTE, 
							 pkcKeySize, CRYPT_CTXINFO_KEYSIZE ) );
	}

/****************************************************************************
*																			*
*									Hash Routines							*
*																			*
****************************************************************************/

/* Get hash algorithm parameters */

int getHashAlgoParams( const CRYPT_CONTEXT hashContext,
					   CRYPT_ALGO_TYPE *hashAlgo, int *hashSize )
	{
	int status;

	assert( isHandleRangeValid( hashContext ) );
	assert( isWritePtr( hashAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );
	assert( ( hashSize == NULL ) || \
			isWritePtr( hashSize, sizeof( int ) ) );

	/* Clear return values */
	if( hashSize != NULL )
		*hashSize = 0;
	*hashAlgo = CRYPT_ALGO_NONE;

	/* Get various PKC algorithm parameters */
	if( hashSize != NULL )
		{
		status = krnlSendMessage( hashContext, IMESSAGE_GETATTRIBUTE, 
								  hashSize, CRYPT_CTXINFO_BLOCKSIZE );
		if( cryptStatusError( status ) )
			return( status );
		}
	return( krnlSendMessage( hashContext, IMESSAGE_GETATTRIBUTE, 
							 hashAlgo, CRYPT_CTXINFO_ALGO ) );
	}

