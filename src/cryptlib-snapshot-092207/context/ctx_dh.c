/****************************************************************************
*																			*
*					cryptlib Diffie-Hellman Key Exchange Routines			*
*						Copyright Peter Gutmann 1995-2005					*
*																			*
****************************************************************************/

#define PKC_CONTEXT		/* Indicate that we're working with PKC context */
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
#else
  #include "crypt.h"
  #include "context/context.h"
#endif /* Compiler-specific includes */

/* The DH key exchange process is somewhat complex because there are two
   phases involved for both sides, an "export" and an "import" phase, and
   they have to be performed in the correct order.  The sequence of
   operations is:

	A.load:		set p, g from fixed or external values
				x(A) = rand, x s.t. 0 < x < q-1

	A.export	y(A) = g^x(A) mod p		error if y != 0 at start
				output = y(A)

	B.load		read p, g / set p, g from external values
				x(B) = rand, x s.t. 0 < x < q-1

	B.import	y(A) = input
				z = y(A)^x(B) mod p

	B.export	y(B) = g^x(B) mod p		error if y != 0 at start
				output = y(B)

	A.import	y(B) = input
				z = y(B)^x(A) mod p

   Note that we have to set x when we load p and g because otherwise we'd
   have to set x(A) on export and x(B) on import, which is tricky since the
   DH code doesn't know whether it's working with A or B */

#ifdef USE_DH

/****************************************************************************
*																			*
*								Algorithm Self-test							*
*																			*
****************************************************************************/

/* Test the Diffie-Hellman implementation using a sample key.  Because a lot 
   of the high-level encryption routines don't exist yet, we cheat a bit and 
   set up a dummy encryption context with just enough information for the 
   following code to work */

typedef struct {
	const int pLen; const BYTE p[ 128 ];
	const int qLen; const BYTE q[ 20 ];
	const int gLen; const BYTE g[ 128 ];
	const int xLen; const BYTE x[ 20 ];
	const int yLen; const BYTE y[ 128 ];
	} DLP_KEY;

static const DLP_KEY FAR_BSS dlpTestKey = {
	/* p */
	128,
	{ 0x04, 0x4C, 0xDD, 0x5D, 0xB6, 0xED, 0x23, 0xAE, 
	  0xB2, 0xA7, 0x59, 0xE6, 0xF8, 0x3D, 0xA6, 0x27, 
	  0x85, 0xF2, 0xFE, 0xE2, 0xE8, 0xF3, 0xDA, 0xA3, 
	  0x7B, 0xD6, 0x48, 0xD4, 0x44, 0xCA, 0x6E, 0x10, 
	  0x97, 0x6C, 0x1D, 0x6C, 0x39, 0xA7, 0x0C, 0x88, 
	  0x8E, 0x1F, 0xDD, 0xF7, 0x59, 0x69, 0xDA, 0x36, 
	  0xDD, 0xB8, 0x3E, 0x1A, 0xD2, 0x91, 0x3E, 0x30, 
	  0xB1, 0xB5, 0xC2, 0xBC, 0xA9, 0xA3, 0xA5, 0xDE, 
	  0xC7, 0xCF, 0x51, 0x2C, 0x1B, 0x89, 0xD0, 0x71, 
	  0xE3, 0x71, 0xBB, 0x50, 0x86, 0x26, 0x32, 0x9F, 
	  0xF5, 0x4A, 0x9C, 0xB1, 0x78, 0x7B, 0x47, 0x1F, 
	  0x19, 0xC7, 0x26, 0x22, 0x15, 0x62, 0x71, 0xAB, 
	  0xD7, 0x25, 0xA5, 0xE4, 0x68, 0x71, 0x93, 0x5D, 
	  0x1F, 0x29, 0x01, 0x05, 0x9C, 0x57, 0x3A, 0x09, 
	  0xB0, 0xB8, 0xE4, 0xD2, 0x37, 0x90, 0x36, 0x2F, 
	  0xBF, 0x1E, 0x74, 0xB4, 0x6B, 0xE4, 0x66, 0x07 }, 

	/* q */
	20,
	{ 0xFD, 0xD9, 0xC8, 0x5F, 0x73, 0x62, 0xC9, 0x79, 
	  0xEF, 0xD5, 0x09, 0x07, 0x02, 0xE7, 0xF2, 0x90, 
	  0x97, 0x13, 0x26, 0x1D }, 

	/* g */
	128,
	{ 0x02, 0x4E, 0xDD, 0x0D, 0x7F, 0x4D, 0xB1, 0x42, 
	  0x01, 0x50, 0xE7, 0x9A, 0x65, 0x73, 0x8B, 0x31, 
	  0x24, 0x6B, 0xC6, 0x74, 0xA7, 0x68, 0x26, 0x11, 
	  0x06, 0x3C, 0x96, 0xA9, 0xA6, 0x23, 0x12, 0x79, 
	  0xC4, 0xEE, 0x21, 0x88, 0xDD, 0xE3, 0xF0, 0x37, 
	  0xCE, 0x3E, 0x54, 0x53, 0x57, 0x03, 0x30, 0xE4, 
	  0xD3, 0xAB, 0x39, 0x4E, 0x39, 0xDC, 0xA2, 0x88, 
	  0x82, 0xF6, 0xE8, 0xBA, 0xAC, 0xF5, 0x7D, 0x2F, 
	  0x23, 0x9A, 0x09, 0x94, 0xB2, 0x89, 0xA2, 0xC9, 
	  0x7C, 0xBE, 0x4D, 0x48, 0x0E, 0x59, 0x51, 0xB8, 
	  0x7D, 0x99, 0x88, 0x79, 0xA8, 0x13, 0x0E, 0x12, 
	  0x56, 0x9D, 0x4B, 0x2E, 0xE0, 0xE1, 0x37, 0x78, 
	  0x6F, 0xCC, 0x4D, 0x97, 0xA9, 0x02, 0x0E, 0xD2, 
	  0x43, 0x83, 0xEC, 0x4F, 0xC2, 0x70, 0xEF, 0x16, 
	  0xDE, 0xBF, 0xBA, 0xD1, 0x6C, 0x8A, 0x36, 0xEE, 
	  0x42, 0x41, 0xE9, 0xE7, 0x66, 0xAE, 0x46, 0x3B }, 

	/* x */
	20,
	{ 0xD9, 0x41, 0x29, 0xF7, 0x40, 0x32, 0x09, 0x71, 
	  0xB8, 0xE2, 0xB8, 0xCB, 0x74, 0x46, 0x0B, 0xD4, 
	  0xF2, 0xAB, 0x54, 0xA1 }, 

	/* y */
	128,
	{ 0x01, 0x7E, 0x16, 0x5B, 0x65, 0x51, 0x0A, 0xDA, 
	  0x82, 0x1A, 0xD9, 0xF4, 0x1E, 0x66, 0x6D, 0x7D, 
	  0x23, 0xA6, 0x28, 0x2F, 0xE6, 0xC2, 0x03, 0x8E, 
	  0x8C, 0xAB, 0xC2, 0x08, 0x87, 0xC9, 0xE8, 0x51, 
	  0x0A, 0x37, 0x1E, 0xD4, 0x41, 0x7F, 0xA2, 0xC5, 
	  0x48, 0x26, 0xB7, 0xF6, 0xC2, 0x6F, 0xB2, 0xF8, 
	  0xF9, 0x43, 0x43, 0xF9, 0xDA, 0xAB, 0xA2, 0x59, 
	  0x27, 0xBA, 0xC9, 0x1C, 0x8C, 0xAB, 0xC4, 0x90, 
	  0x27, 0xE1, 0x10, 0x39, 0x6F, 0xD2, 0xCD, 0x7C, 
	  0xD1, 0x0B, 0xFA, 0x28, 0xD2, 0x7A, 0x7B, 0x52, 
	  0x8A, 0xA0, 0x5A, 0x0F, 0x10, 0xF7, 0xBA, 0xFD, 
	  0x33, 0x0C, 0x3C, 0xCE, 0xE5, 0xF2, 0xF6, 0x92, 
	  0xED, 0x04, 0xBF, 0xD3, 0xF8, 0x3D, 0x39, 0xCC, 
	  0xAA, 0xCC, 0x0B, 0xB2, 0x6B, 0xD8, 0xB2, 0x8A, 
	  0x5C, 0xCE, 0xDA, 0xF9, 0xE1, 0xA7, 0x23, 0x50, 
	  0xDC, 0xCE, 0xA4, 0xD5, 0xA5, 0x4F, 0x08, 0x0F }
	};

static BOOLEAN pairwiseConsistencyTest( CONTEXT_INFO *contextInfoPtr,
										const BOOLEAN isGeneratedKey )
	{
	CONTEXT_INFO checkContextInfo;
	PKC_INFO contextData, *pkcInfo = &contextData;
	KEYAGREE_PARAMS keyAgreeParams1, keyAgreeParams2;
	const CAPABILITY_INFO *capabilityInfoPtr;
	int status;

	/* The DH pairwise check is a bit more complex than the one for the
	   other algorithms because there's no matched public/private key pair,
	   so we have to load a second DH key to use for key agreement with
	   the first one */
	staticInitContext( &checkContextInfo, CONTEXT_PKC, getDHCapability(),
					   &contextData, sizeof( PKC_INFO ), NULL );
	if( isGeneratedKey )
		{
		PKC_INFO *sourcePkcInfo = contextInfoPtr->ctxPKC;
		int bnStatus = BN_STATUS;

		/* If it's a generated key with random p and g parameters rather
		   than the fixed test values, we have to make the parameters for
		   the check context match the ones for the generated key */
		CKPTR( BN_copy( &pkcInfo->dlpParam_p, &sourcePkcInfo->dlpParam_p ) );
		CKPTR( BN_copy( &pkcInfo->dlpParam_g, &sourcePkcInfo->dlpParam_g ) );
		CKPTR( BN_copy( &pkcInfo->dlpParam_q, &sourcePkcInfo->dlpParam_q ) );
		CKPTR( BN_copy( &pkcInfo->dlpParam_y, &sourcePkcInfo->dlpParam_y ) );
		if( bnStatusError( bnStatus ) )
			return( getBnStatus( bnStatus ) );
		}
	else
		{
		status = extractBignum( &pkcInfo->dlpParam_p, dlpTestKey.p, 
								dlpTestKey.pLen, DLPPARAM_MIN_P, 
								DLPPARAM_MAX_P, NULL );
		if( cryptStatusOK( status ) )
			status = extractBignum( &pkcInfo->dlpParam_g, dlpTestKey.g, 
									dlpTestKey.gLen, DLPPARAM_MIN_G, 
									DLPPARAM_MAX_G, &pkcInfo->dlpParam_p );
		if( cryptStatusOK( status ) )
			status = extractBignum( &pkcInfo->dlpParam_q, dlpTestKey.q, 
									dlpTestKey.qLen, DLPPARAM_MIN_Q, 
									DLPPARAM_MAX_Q, &pkcInfo->dlpParam_p );
		if( cryptStatusOK( status ) )
			status = extractBignum( &pkcInfo->dlpParam_y, dlpTestKey.y, 
									dlpTestKey.yLen, DLPPARAM_MIN_Y, 
									DLPPARAM_MAX_Y, &pkcInfo->dlpParam_p );
		if( cryptStatusOK( status ) )
			status = extractBignum( &pkcInfo->dlpParam_x, dlpTestKey.x, 
									dlpTestKey.xLen, DLPPARAM_MIN_X, 
									DLPPARAM_MAX_X, &pkcInfo->dlpParam_p );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Perform the pairwise test using the check key */
	capabilityInfoPtr = checkContextInfo.capabilityInfo;
	status = capabilityInfoPtr->initKeyFunction( &checkContextInfo, NULL, 0 );
	if( cryptStatusOK( status ) )
		{
		memset( &keyAgreeParams1, 0, sizeof( KEYAGREE_PARAMS ) );
		status = capabilityInfoPtr->encryptFunction( contextInfoPtr,
					( BYTE * ) &keyAgreeParams1, sizeof( KEYAGREE_PARAMS ) );
		}
	if( cryptStatusOK( status ) )
		{
		memset( &keyAgreeParams2, 0, sizeof( KEYAGREE_PARAMS ) );
		status = capabilityInfoPtr->encryptFunction( &checkContextInfo,
					( BYTE * ) &keyAgreeParams2, sizeof( KEYAGREE_PARAMS ) );
		}
	if( cryptStatusOK( status ) )
		status = capabilityInfoPtr->decryptFunction( contextInfoPtr,
					( BYTE * ) &keyAgreeParams2, sizeof( KEYAGREE_PARAMS ) );
	if( cryptStatusOK( status ) )
		status = capabilityInfoPtr->decryptFunction( &checkContextInfo,
					( BYTE * ) &keyAgreeParams1, sizeof( KEYAGREE_PARAMS ) );
	if( cryptStatusError( status ) || \
		memcmp( keyAgreeParams1.wrappedKey, keyAgreeParams2.wrappedKey, 
				dlpTestKey.pLen ) )
		status = CRYPT_ERROR_FAILED;

	/* Clean up */
	staticDestroyContext( &checkContextInfo );

	return( cryptStatusOK( status ) ? TRUE : FALSE );
	}

static int selfTest( void )
	{
	CONTEXT_INFO contextInfo;
	PKC_INFO contextData, *pkcInfo = &contextData;
	int status;

	/* Initialise the key components */
	staticInitContext( &contextInfo, CONTEXT_PKC, getDHCapability(),
					   &contextData, sizeof( PKC_INFO ), NULL );
	status = extractBignum( &pkcInfo->dlpParam_p, dlpTestKey.p, 
							dlpTestKey.pLen, DLPPARAM_MIN_P, 
							DLPPARAM_MAX_P, NULL );
	if( cryptStatusOK( status ) )
		status = extractBignum( &pkcInfo->dlpParam_g, dlpTestKey.g, 
								dlpTestKey.gLen, DLPPARAM_MIN_G, 
								DLPPARAM_MAX_G, &pkcInfo->dlpParam_p );
	if( cryptStatusOK( status ) )
		status = extractBignum( &pkcInfo->dlpParam_q, dlpTestKey.q, 
								dlpTestKey.qLen, DLPPARAM_MIN_Q, 
								DLPPARAM_MAX_Q, &pkcInfo->dlpParam_p );
	if( cryptStatusOK( status ) )
		status = extractBignum( &pkcInfo->dlpParam_y, dlpTestKey.y, 
								dlpTestKey.yLen, DLPPARAM_MIN_Y, 
								DLPPARAM_MAX_Y, &pkcInfo->dlpParam_p );
	if( cryptStatusOK( status ) )
		status = extractBignum( &pkcInfo->dlpParam_x, dlpTestKey.x, 
								dlpTestKey.xLen, DLPPARAM_MIN_X, 
								DLPPARAM_MAX_X, &pkcInfo->dlpParam_p );
	if( cryptStatusError( status ) )
		{
		staticDestroyContext( &contextInfo );
		retIntError();
		}

	/* Perform the test key exchange on a block of data */
	status = contextInfo.capabilityInfo->initKeyFunction( &contextInfo, NULL, 0 );
	if( cryptStatusOK( status ) && \
		!pairwiseConsistencyTest( &contextInfo, FALSE ) )
		status = CRYPT_ERROR_FAILED;

	/* Clean up */
	staticDestroyContext( &contextInfo );

	return( status );
	}

/****************************************************************************
*																			*
*						Diffie-Hellman Key Exchange Routines				*
*																			*
****************************************************************************/

/* Perform phase 1 of Diffie-Hellman ("export").  We have to append the
   distinguisher 'Fn' to the name since some systems already have 'encrypt'
   and 'decrypt' in their standard headers */

static int encryptFn( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	KEYAGREE_PARAMS *keyAgreeParams = ( KEYAGREE_PARAMS * ) buffer;

	UNUSED( noBytes );

	assert( noBytes == sizeof( KEYAGREE_PARAMS ) );
	assert( !BN_is_zero( &pkcInfo->dlpParam_y ) );

	/* y is generated either at keygen time for static DH or as a side-effect
	   of the implicit generation of the x value for ephemeral DH, so all we
	   have to do is copy it to the output */
	keyAgreeParams->publicValueLen = \
							BN_bn2bin( &pkcInfo->dlpParam_y,
									   keyAgreeParams->publicValue );
	return( CRYPT_OK );

#if 0
	BN_CTX *bnCTX;

	if( ( bnCTX = BN_CTX_new() ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Export y = g^x mod p.  There is no input data since x was set when the
	   DH values were loaded */
	BN_mod_exp_mont( &pkcInfo->dlpParam_y, &pkcInfo->dlpParam_g,
					 &pkcInfo->dlpParam_x, &pkcInfo->dlpParam_p, bnCTX,
					 &pkcInfo->dlpParam_mont_p );
	keyAgreeParams->publicValueLen = \
							BN_bn2bin( &pkcInfo->dlpParam_y,
									   keyAgreeParams->publicValue );
	BN_CTX_free( bnCTX );

	return( ( status == -1 ) ? CRYPT_ERROR_FAILED : status );
#endif /* 0 */
	}

/* Perform phase 2 of Diffie-Hellman ("import") */

static int decryptFn( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	KEYAGREE_PARAMS *keyAgreeParams = ( KEYAGREE_PARAMS * ) buffer;
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	BIGNUM *z = &pkcInfo->tmp1;
	int bnStatus = BN_STATUS, status;

	assert( noBytes == sizeof( KEYAGREE_PARAMS ) );
	assert( keyAgreeParams->publicValue != NULL && \
			keyAgreeParams->publicValueLen >= MIN_PKCSIZE );

	/* The other party's y value will be stored with the key agreement info
	   rather than having been read in when we read the DH public key */
	status = extractBignum( &pkcInfo->dhParam_yPrime,
							keyAgreeParams->publicValue, 
							keyAgreeParams->publicValueLen,
							DLPPARAM_MIN_Y, DLPPARAM_MAX_Y, 
							&pkcInfo->dlpParam_p );
	if( cryptStatusError( status ) )
		return( status );

	/* Export z = y^x mod p.  We need to use separate y and z values because
	   the bignum code can't handle modexp with the first two parameters the
	   same */
	CK( BN_mod_exp_mont( z, &pkcInfo->dhParam_yPrime, &pkcInfo->dlpParam_x,
						 &pkcInfo->dlpParam_p, pkcInfo->bnCTX,
						 &pkcInfo->dlpParam_mont_p ) );
	keyAgreeParams->wrappedKeyLen = BN_bn2bin( z, keyAgreeParams->wrappedKey );

	return( getBnStatus( bnStatus ) );
	}

/****************************************************************************
*																			*
*								Key Management								*
*																			*
****************************************************************************/

/* Load key components into an encryption context */

static int initKey( CONTEXT_INFO *contextInfoPtr, const void *key,
					const int keyLength )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	int status;

#ifndef USE_FIPS140
	/* Load the key component from the external representation into the
	   internal bignums unless we're doing an internal load */
	if( key != NULL )
		{
		const CRYPT_PKCINFO_DLP *dhKey = ( CRYPT_PKCINFO_DLP * ) key;

		contextInfoPtr->flags |= ( dhKey->isPublicKey ) ? \
							CONTEXT_ISPUBLICKEY : CONTEXT_ISPRIVATEKEY;
		status = extractBignum( &pkcInfo->dlpParam_p, dhKey->p, 
								bitsToBytes( dhKey->pLen ),
								DLPPARAM_MIN_P, DLPPARAM_MAX_P, NULL );
		if( cryptStatusOK( status ) )
			status = extractBignum( &pkcInfo->dlpParam_g, dhKey->g, 
									bitsToBytes( dhKey->gLen ),
									DLPPARAM_MIN_G, DLPPARAM_MAX_G,
									&pkcInfo->dlpParam_p );
		if( cryptStatusOK( status ) )
			status = extractBignum( &pkcInfo->dlpParam_q, dhKey->q, 
									bitsToBytes( dhKey->qLen ),
									DLPPARAM_MIN_Q, DLPPARAM_MAX_Q,
									&pkcInfo->dlpParam_p );
		if( cryptStatusOK( status ) )
			status = extractBignum( &pkcInfo->dlpParam_y, dhKey->y, 
									bitsToBytes( dhKey->yLen ),
									DLPPARAM_MIN_Y, DLPPARAM_MAX_Y,
									&pkcInfo->dlpParam_p );
		if( cryptStatusOK( status ) && !dhKey->isPublicKey )
			status = extractBignum( &pkcInfo->dlpParam_x, dhKey->x, 
									bitsToBytes( dhKey->xLen ),
									DLPPARAM_MIN_X, DLPPARAM_MAX_X,
									&pkcInfo->dlpParam_p );
		contextInfoPtr->flags |= CONTEXT_PBO;
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* USE_FIPS140 */

	/* Complete the key checking and setup */
	status = initDLPkey( contextInfoPtr, TRUE );
	if( cryptStatusOK( status ) )
		/* DH keys may follow PKCS #3 rather than X9.42, which means we can't
		   do extended checking using q, so if q is zero we denote it as a
		   PKCS #3 key.  This is only permitted for DH keys, other key types
		   will fail the check if q = 0 */
		status = checkDLPkey( contextInfoPtr,
							  BN_is_zero( &pkcInfo->dlpParam_q ) ? \
								TRUE : FALSE );
	if( cryptStatusOK( status ) )
		status = pkcInfo->calculateKeyIDFunction( contextInfoPtr );
	return( status );
	}

/* Generate a key into an encryption context */

static int generateKey( CONTEXT_INFO *contextInfoPtr, const int keySizeBits )
	{
	int status;

	status = generateDLPkey( contextInfoPtr, keySizeBits, CRYPT_USE_DEFAULT,
							 TRUE );
	if( cryptStatusOK( status ) &&
#ifndef USE_FIPS140
		( contextInfoPtr->flags & CONTEXT_SIDECHANNELPROTECTION ) &&
#endif /* USE_FIPS140 */
		!pairwiseConsistencyTest( contextInfoPtr, TRUE ) )
		{
		assert( NOTREACHED );
		status = CRYPT_ERROR_FAILED;
		}
	if( cryptStatusOK( status ) )
		status = contextInfoPtr->ctxPKC->calculateKeyIDFunction( contextInfoPtr );
	return( status );
	}

/****************************************************************************
*																			*
*						Capability Access Routines							*
*																			*
****************************************************************************/

static const CAPABILITY_INFO FAR_BSS capabilityInfo = {
	CRYPT_ALGO_DH, bitsToBytes( 0 ), "Diffie-Hellman", 14,
	MIN_PKCSIZE, bitsToBytes( 1024 ), CRYPT_MAX_PKCSIZE,
	selfTest, getDefaultInfo, NULL, NULL, initKey, generateKey, encryptFn, decryptFn
	};

const CAPABILITY_INFO *getDHCapability( void )
	{
	return( &capabilityInfo );
	}

#endif /* USE_DH */
