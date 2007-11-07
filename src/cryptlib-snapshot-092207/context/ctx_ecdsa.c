/****************************************************************************
*																			*
*					cryptlib ECDSA Encryption Routines						*
*			Copyright Matthias Bruestle and Peter Gutmann 2006-2007			*
*																			*
****************************************************************************/

#define PKC_CONTEXT		/* Indicate that we're working with PKC context */
#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
/*  #include "ecp.h" */
#else
  #include "crypt.h"
  #include "context/context.h"
/*  #include "context/ecp.h" */
#endif /* Compiler-specific includes */

#ifdef USE_ECC

/****************************************************************************
*																			*
*								Algorithm Self-test							*
*																			*
****************************************************************************/

/* Test the ECDSA implementation using the test vectors from GEC 2: 
   Test Vectors for SEC 1, Working Draft, September, 1999, Version 0.3

   Because a lot of the high-level encryption routines don't exist yet, we
   cheat a bit and set up a dummy encryption context with just enough
   information for the following code to work */

#define ECDSA_TESTVECTOR_SIZE	20

static const FAR_BSS CRYPT_PKCINFO_ECC ecdsaTestKey = {
	0,
	/* p */
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	  0x7F, 0xFF, 0xFF, 0xFF },
	160,
	/* a */
	{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	  0x7F, 0xFF, 0xFF, 0xFC },
	160,
	/* b */
	{ 0x1C, 0x97, 0xBE, 0xFC, 0x54, 0xBD, 0x7A, 0x8B,
	  0x65, 0xAC, 0xF8, 0x9F, 0x81, 0xD4, 0xD4, 0xAD,
	  0xC5, 0x65, 0xFA, 0x45 },
	160,
	/* gx */
	{ 0x4A, 0x96, 0xB5, 0x68, 0x8E, 0xF5, 0x73, 0x28,
	  0x46, 0x64, 0x69, 0x89, 0x68, 0xC3, 0x8B, 0xB9,
	  0x13, 0xCB, 0xFC, 0x82 },
	160,
	/* gy */
	{ 0x23, 0xA6, 0x28, 0x55, 0x31, 0x68, 0x94, 0x7D,
	  0x59, 0xDC, 0xC9, 0x12, 0x04, 0x23, 0x51, 0x37,
	  0x7A, 0xC5, 0xFB, 0x32 },
	160,
	/* gr */
	{ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	  0x00, 0x00, 0x01, 0xF4, 0xC8, 0xF9, 0x27, 0xAE,
	  0xD3, 0xCA, 0x75, 0x22, 0x57 },
	160,
	/* gh */
	{ 0x01 },
	1,
	/* qx */
	{ 0x51, 0xB4, 0x49, 0x6F, 0xEC, 0xC4, 0x06, 0xED,
	  0x0E, 0x75, 0xA2, 0x4A, 0x3C, 0x03, 0x20, 0x62,
	  0x51, 0x41, 0x9D, 0xC0 },
	160,
	/* qy */
	{ 0xC2, 0x8D, 0xCB, 0x4B, 0x73, 0xA5, 0x14, 0xB4,
	  0x68, 0xD7, 0x93, 0x89, 0x4F, 0x38, 0x1C, 0xCC,
	  0x17, 0x56, 0xAA, 0x6C },
	160,
	/* d */
	{ 0xAA, 0x37, 0x4F, 0xFC, 0x3C, 0xE1, 0x44, 0xE6,
	  0xB0, 0x73, 0x30, 0x79, 0x72, 0xCB, 0x6D, 0x57,
	  0xB2, 0xA4, 0xE9, 0x82 },
	160,
	};

/* SHA-1 hash of "abc" */

static const FAR_BSS BYTE shaM[] = {
	0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
	0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C,
	0x9C, 0xD0, 0xD8, 0x9D
	};

/* If we're doing a self-test using the GEC2 values we use the following
   fixed k data rather than a randomly-generated value. */

static const FAR_BSS BYTE kVal[] = {
	0x7B, 0x01, 0x2D, 0xB7, 0x68, 0x1A, 0x3F, 0x28,
	0xB9, 0x18, 0x5C, 0x8B, 0x2A, 0xC5, 0xD5, 0x28,
	0xDE, 0xCD, 0x52, 0xDA, 
	};

/* Signature:
   r=CE2873E5BE449563391FEB47DDCBA2DC16379191
   s=3480EC1371A091A464B31CE47DF0CB8AA2D98B54 */

static BOOLEAN pairwiseConsistencyTest( CONTEXT_INFO *contextInfoPtr )
	{
	return( CRYPT_ERROR_NOTAVAIL );
	}

static int selfTest( void )
	{
	CONTEXT_INFO contextInfo;
	PKC_INFO contextData, *pkcInfo = &contextData;
	int status;

	/* Initialise the key components */
	staticInitContext( &contextInfo, CONTEXT_PKC, getDSACapability(),
					   &contextData, sizeof( PKC_INFO ), NULL );

	pairwiseConsistencyTest( NULL );	/* Keep compiler happy */

	/* Clean up */
	staticDestroyContext( &contextInfo );

	return( CRYPT_ERROR_NOTAVAIL );
	}

/****************************************************************************
*																			*
*							Create/Check a Signature						*
*																			*
****************************************************************************/

/* Since ECDSA signature generation produces two values and the 
   cryptEncrypt() model only provides for passing a byte string in and out 
   (or, more specifically, the internal bignum data can't be exported to the 
   outside world), we need to encode the resulting data into a flat format.  
   This is done by encoding the output as an X9.31 Dss-Sig record, which is
   also used for ECDSA:

	Dss-Sig ::= SEQUENCE {
		r	INTEGER,
		s	INTEGER
		} */

/* Sign a single block of data  */

static int sign( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	BN_CTX *bnCtx = pkcInfo->bnCTX;
	DLP_PARAMS *eccParams = ( DLP_PARAMS * ) buffer;
	BIGNUM *p = &pkcInfo->eccParam_p, *a = &pkcInfo->eccParam_a;
	BIGNUM *b = &pkcInfo->eccParam_b, *gx = &pkcInfo->eccParam_gx;
	BIGNUM *gy = &pkcInfo->eccParam_gy, *d = &pkcInfo->eccParam_d;
	BIGNUM *gr = &pkcInfo->eccParam_r;
	BIGNUM *hash = &pkcInfo->tmp1, *k = &pkcInfo->tmp2, *r = &pkcInfo->tmp3;
	BIGNUM *s = &pkcInfo->tmp4;
	S_ECP_CTX ctx;
	S_POINT kg;
	int bnStatus = BN_STATUS, status;

printf( "sign( noBytes=%d )\n", noBytes ); // eZ

	assert( noBytes == sizeof( DLP_PARAMS ) );
	assert( eccParams->inParam1 != NULL );
	assert( eccParams->inParam2 == NULL && \
			( eccParams->inLen2 == 0 || eccParams->inLen2 == -999 ) );
	assert( eccParams->outParam != NULL && \
			eccParams->outLen >= ( 2 + CRYPT_MAX_ECCSIZE ) * 2 );

printf( "sign( P1 )\n" ); // eZ

	BN_CTX_start( bnCtx );
//	hash = BN_CTX_get( bnCtx );
//	k = BN_CTX_get( bnCtx );
// Can you hide all this in a ecpCtxInit() that initialises a S_ECP_CTX from
// a BN_CTX + pkcInfo?
ctx.t1 = BN_CTX_get( bnCtx );
ctx.t2 = BN_CTX_get( bnCtx );
ctx.t3 = BN_CTX_get( bnCtx );
ctx.t4 = BN_CTX_get( bnCtx );
ctx.p1.x = BN_CTX_get( bnCtx );
ctx.p1.y = BN_CTX_get( bnCtx );
ctx.p2.x = BN_CTX_get( bnCtx );
ctx.p2.y = BN_CTX_get( bnCtx );
ctx.p3.x = BN_CTX_get( bnCtx );
ctx.p3.y = BN_CTX_get( bnCtx );
ctx.pkc = pkcInfo;
// Same here, with ecpPointInit() instead.
kg.x = BN_CTX_get( bnCtx );
kg.y = BN_CTX_get( bnCtx );

printf( "sign( P2 )\n" ); // eZ

//	r = BN_CTX_get( bnCtx );
//	CKPTR( s = BN_CTX_get( bnCtx ) );
//	if( bnStatusError( bnStatus ) )
//		{
//		status = getBnStatus( bnStatus );
//		goto retreat;
//		}

printf( "sign( P3 )\n" ); // eZ

	if( !ecp_init( &ctx, 0 ) )
		{
		BN_CTX_end( bnCtx );
		return( CRYPT_ERROR_FAILED );
		}

printf( "sign( P4 )\n" ); // eZ

	while( TRUE )
		{
		/* Generate the secret random value k.  During the initial self-test
		   the random data pool may not exist yet, and may in fact never 
		   exist in a satisfactory condition if there isn't enough 
		   randomness present in the system to generate cryptographically 
		   strong random numbers.  To bypass this problem, if the caller 
		   passes in a second length parameter of -999, we know that it's an 
		   internal self-test call and use a fixed bit pattern for k that 
		   avoids having to call generateBignum() (this also means we can 
		   use the GEC2 self-test value for k).  This is a somewhat ugly use 
		   of 'magic numbers', but it's safe because this function can only 
		   be called internally, so all we need to trap is accidental use of 
		   the parameter which is normally unused */
		if( eccParams->inLen2 == -999 )
			BN_bin2bn( ( BYTE * ) kVal, ECDSA_TESTVECTOR_SIZE, k );
		else
			{
			/* Generate the random value k from [1...r-1], i.e. a random 
			   value mod r.  Using a random value of the same length as r 
			   would produce a slight bias in k that leaks a small amount of 
			   the private key in each signature.  Because of this we start 
			   with a value which is 32 bits larger than r and then do the 
			   reduction, eliminating the bias */
			status = generateBignum( k, BN_num_bits( gr ) + 32, 0, 0 );
			if( cryptStatusError( status ) )
				break;
			}
printf( "sign( P5 )\n" ); // eZ
		if( contextInfoPtr->flags & CONTEXT_SIDECHANNELPROTECTION )
			{
			/* Use constant-time modexp() to protect the secret random value 
			   from timing channels */
			BN_set_flags( k, BN_FLG_EXP_CONSTTIME );
			}
printf( "sign( P5b )\n" ); // eZ
//printf( " k = %s\n", BN_num_bits( k ) ); // eZ
//printf( " gr = %s\n", BN_num_bits( gr ) ); // eZ
		CK( BN_mod( k, k, gr, 			/* Reduce k to the correct range */
					pkcInfo->bnCTX ) );
		if( bnStatusError( bnStatus ) )
			{
			status = getBnStatus( bnStatus );
			break;
			}

printf( "sign( P5c )\n" ); // eZ
		/* If the result is zero, try again.  Admittedly the chances of this 
		   are infinitesimally small (typically 2^-160 or less), but 
		   someone's bound to complain if we don't check */
		if( BN_is_zero( k ) )
			continue;
printf( "sign( P6 )\n" ); // eZ

		/* Move the data from the buffer into a bignum */
		BN_bin2bn( ( BYTE * ) eccParams->inParam1, eccParams->inLen1, hash );

		/* Compute the point (x1, y1) = kG */
		CKPTR( BN_copy( kg.x, gx ) );
		CKPTR( BN_copy( kg.y, gy ) );
		if( bnStatusError( bnStatus ) )
			{
			status = CRYPT_ERROR_FAILED;
			break;
			}
printf( "sign( P7 )\n" ); // eZ

		/* Convert kG to an integer r using r = p((x1, y1)) mod n = x1 mod n */
		if( !ecp_pt_smul_naf( &ctx, &kg, k ) )
			{
			status = CRYPT_ERROR_FAILED;
			goto retreat;
			}
printf( "sign( P8 )\n" ); // eZ

		/* r = kG.x mod G.r */
		CK( BN_mod( r, kg.x, gr, bnCtx ) );

		/* k = ( k^-1 ) mod n */
		CKPTR( BN_mod_inverse( k, k, gr, bnCtx ) );

		/* s = k^-1 * ( d * r + e ) mod n */
		CK( BN_mod_mul( s, d, r, gr, bnCtx ) );
		CK( BN_mod_add( s, s, hash, gr, bnCtx ) );
		CK( BN_mod_mul( s, s, k, gr, bnCtx ) );
		if( bnStatusError( bnStatus ) )
			{
			status = getBnStatus( bnStatus );
			break;
			}
printf( "sign( P9 )\n" ); // eZ

		/* If either r = 0 or s = 0, try again.  See the earlier comment 
		   about the real necessity of this check */
		if( BN_is_zero( r ) || BN_is_zero( s ) )
			continue;
		}
	BN_CTX_end( bnCtx );
	if( cryptStatusError( status ) )
		return( status );

	/* Encode the result as a DL data block */
	status = pkcInfo->encodeDLValuesFunction( eccParams->outParam, 
											  eccParams->outLen, r, s,
											  eccParams->formatType );
	if( !cryptStatusError( status ) )
		{
		eccParams->outLen = status;
		status = CRYPT_OK;	/* encodeDLValues() returns a byte count */
		}
printf( "sign( P10 )\n" ); // eZ

	return( status );
	}

/* Signature check a single block of data */

static int sigCheck( CONTEXT_INFO *contextInfoPtr, BYTE *buffer, int noBytes )
	{
	PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
	BN_CTX *bnCtx = pkcInfo->bnCTX;
	DLP_PARAMS *eccParams = ( DLP_PARAMS * ) buffer;
	BIGNUM *p = &pkcInfo->eccParam_p, *a = &pkcInfo->eccParam_a;
	BIGNUM *b = &pkcInfo->eccParam_b, *gx = &pkcInfo->eccParam_gx;
	BIGNUM *gy = &pkcInfo->eccParam_gy, *qx = &pkcInfo->eccParam_qx;
	BIGNUM *qy = &pkcInfo->eccParam_qy, *gr = &pkcInfo->eccParam_r;
	BIGNUM *u1 = &pkcInfo->tmp1, *u2 = &pkcInfo->tmp2;
	BIGNUM *r = &pkcInfo->tmp3, *s = &pkcInfo->tmp4;
	S_POINT	u1g, u2q;
	S_ECP_CTX ctx;
	int bnStatus = BN_STATUS, status;

printf( "sigCheck\n" ); // eZ
	assert( noBytes == sizeof( DLP_PARAMS ) );
	assert( dlpParams->inParam1 != NULL );
	assert( dlpParams->inParam2 != NULL );
	assert( dlpParams->outParam == NULL && dlpParams->outLen == 0 );

	BN_CTX_start( bnCtx );
//	u1 = BN_CTX_get( bnCtx );
//	u2 = BN_CTX_get( bnCtx );
// As before.
ctx.t1 = BN_CTX_get( bnCtx );
ctx.t2 = BN_CTX_get( bnCtx );
ctx.t3 = BN_CTX_get( bnCtx );
ctx.t4 = BN_CTX_get( bnCtx );
ctx.p1.x = BN_CTX_get( bnCtx );
ctx.p1.y = BN_CTX_get( bnCtx );
ctx.p2.x = BN_CTX_get( bnCtx );
ctx.p2.y = BN_CTX_get( bnCtx );
ctx.p3.x = BN_CTX_get( bnCtx );
ctx.p3.y = BN_CTX_get( bnCtx );
ctx.pkc=pkcInfo;
u1g.x = BN_CTX_get( bnCtx );
u1g.y = BN_CTX_get( bnCtx );
u2q.x = BN_CTX_get( bnCtx );
u2q.y = BN_CTX_get( bnCtx );
//	r = BN_CTX_get( bnCtx );
//	CKPTR( s = BN_CTX_get( bnCtx ) );
//	if( bnStatusError( bnStatus ) )
//		{
//		status = getBnStatus( bnStatus );
//		goto retreat;
//		}

	if( !ecp_init( &ctx, 0 ) )
		{
		BN_CTX_end( bnCtx );
		return( CRYPT_ERROR_FAILED );
		}

	/* Decode the values from a DL data block and make sure that r and s are
	   valid, i.e. r, s = [1...gr-1] */
	status = pkcInfo->decodeDLValuesFunction( eccParams->inParam2, 
											  eccParams->inLen2, &r, &s,
											  eccParams->formatType );
	if( cryptStatusError( status ) )
		{
		BN_CTX_end( bnCtx );
		return( status );
		}
	if( BN_is_zero( r ) || BN_cmp( r, gr ) >= 0 || \
		BN_cmp( s, gr ) >= 0 || BN_is_zero( s ) )
		{
		BN_CTX_end( bnCtx );
		return( CRYPT_ERROR_BADDATA );
		}

	/* w = ( s^-1 ) mod G.r */
	CKPTR( BN_mod_inverse( u2, s, gr, bnCtx ) );

	/* u1 = ( hash * w ) mod G.r */
	BN_bin2bn( ( BYTE * ) eccParams->inParam1, eccParams->inLen1, u1 );
	CK( BN_mod_mul( u1, u1, u2, gr, bnCtx ) );

	/* u2 = ( r * w ) mod G.r */
	CK( BN_mod_mul( u2, r, u2, gr, bnCtx ) );

	/* u1p = u1 * G */
	CKPTR( BN_copy( u1g.x, gx ) );
	CKPTR( BN_copy( u1g.y, gy ) );
	if( bnStatusError( bnStatus ) )
		{
		BN_CTX_end( bnCtx );
		return( getBnStatus( bnStatus ) );
		}
	if( !ecp_pt_smul_naf( &ctx, &u1g, u1 ) )
		{
		BN_CTX_end( bnCtx );
		return( CRYPT_ERROR_FAILED );
		}

	/* u2Q = u2 * Q */
	CKPTR( BN_copy( u2q.x, qx ) );
	CKPTR( BN_copy( u2q.y, qy ) );
	if( bnStatusError( bnStatus ) )
		{
		BN_CTX_end( bnCtx );
		return( getBnStatus( bnStatus ) );
		}
	if( !ecp_pt_smul_naf( &ctx, &u2q, u2 ) )
		{
		BN_CTX_end( bnCtx );
		return( CRYPT_ERROR_FAILED );
		}

	/* Point (x1, y1) = u1G + u2Q */
	if( !ecp_pt_add( &ctx, &u1g, &u2q ) )
		{
		BN_CTX_end( bnCtx );
		return( CRYPT_ERROR_FAILED );
		}

	/* Convert point (x1, y1) to an integer r':
		r' = p((x1, y1)) mod n
		   = x1 mod n */
	CK( BN_mod( u1, u1g.x, gr, bnCtx ) );
	if( bnStatusError( bnStatus ) )
		{
		BN_CTX_end( bnCtx );
		return( getBnStatus( bnStatus ) );
		}
	BN_CTX_end( bnCtx );

	/* if r == r' signature is good */
	return( BN_cmp( u1, r ) ? CRYPT_ERROR_SIGNATURE : CRYPT_OK );
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
	int status;

#ifndef USE_FIPS140
	/* Load the key component from the external representation into the
	   internal bignums unless we're doing an internal load */
	if( key != NULL )
		{
		PKC_INFO *pkcInfo = contextInfoPtr->ctxPKC;
		const CRYPT_PKCINFO_ECC *eccKey = ( CRYPT_PKCINFO_ECC * ) key;

		contextInfoPtr->flags |= ( eccKey->isPublicKey ) ? \
							CONTEXT_ISPUBLICKEY : CONTEXT_ISPRIVATEKEY;
		status = extractBignum( &pkcInfo->eccParam_p, eccKey->p, 
								bitsToBytes( eccKey->pLen ),
								ECCPARAM_MIN_P, ECCPARAM_MAX_P );
		if( cryptStatusOK( status ) )
			status = extractBignum( &pkcInfo->eccParam_a, eccKey->a, 
									bitsToBytes( eccKey->aLen ),
									ECCPARAM_MIN_A, ECCPARAM_MAX_A );
		if( cryptStatusOK( status ) )
			status = extractBignum( &pkcInfo->eccParam_b, eccKey->b, 
									bitsToBytes( eccKey->bLen ),
									ECCPARAM_MIN_B, ECCPARAM_MAX_B );
		if( cryptStatusOK( status ) )
			status = extractBignum( &pkcInfo->eccParam_gx, eccKey->gx, 
									bitsToBytes( eccKey->gxLen ),
									ECCPARAM_MIN_GX, ECCPARAM_MAX_GX );
		if( cryptStatusOK( status ) )
			status = extractBignum( &pkcInfo->eccParam_gy, eccKey->gy, 
									bitsToBytes( eccKey->gyLen ),
									ECCPARAM_MIN_GY, ECCPARAM_MAX_GY );
		if( cryptStatusOK( status ) )
			status = extractBignum( &pkcInfo->eccParam_r, eccKey->r, 
									bitsToBytes( eccKey->rLen ),
									ECCPARAM_MIN_R, ECCPARAM_MAX_R );
		if( cryptStatusOK( status ) )
			status = extractBignum( &pkcInfo->eccParam_qx, eccKey->qx, 
									bitsToBytes( eccKey->qxLen ),
									ECCPARAM_MIN_QX, ECCPARAM_MAX_QX );
		if( cryptStatusOK( status ) )
			status = extractBignum( &pkcInfo->eccParam_qy, eccKey->qy, 
									bitsToBytes( eccKey->qyLen ),
									ECCPARAM_MIN_QY, ECCPARAM_MAX_QY );
		if( cryptStatusOK( status ) && !eccKey->isPublicKey )
			status = extractBignum( &pkcInfo->eccParam_d, eccKey->d, 
									bitsToBytes( eccKey->dLen ),
									ECCPARAM_MIN_D, ECCPARAM_MAX_D );
		contextInfoPtr->flags |= CONTEXT_PBO;
		if( cryptStatusError( status ) )
			return( status );
		}
#endif /* USE_FIPS140 */

	/* Complete the key checking and setup */
	status = initECCkey( contextInfoPtr );
	if( cryptStatusOK( status ) )
		status = checkECCkey( contextInfoPtr );
	if( cryptStatusOK( status ) )
		status = contextInfoPtr->ctxPKC->calculateKeyIDFunction( contextInfoPtr );
	return( status );
	}

/* Generate a key into an encryption context */

static int generateKey( CONTEXT_INFO *contextInfoPtr, const int keySizeBits )
	{
	int status;

	status = generateECCkey( contextInfoPtr, keySizeBits );
	if( cryptStatusOK( status ) &&
#ifndef USE_FIPS140
		( contextInfoPtr->flags & CONTEXT_SIDECHANNELPROTECTION ) &&
#endif /* USE_FIPS140 */
		!pairwiseConsistencyTest( contextInfoPtr ) )
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
	CRYPT_ALGO_ECDSA, bitsToBytes( 0 ), "ECDSA", 5,
	MIN_PKCSIZE_ECC, bitsToBytes( 256 ), CRYPT_MAX_PKCSIZE_ECC,
	selfTest, getDefaultInfo, NULL, NULL, initKey, generateKey,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, sign, sigCheck
	};

const CAPABILITY_INFO *getECDSACapability( void )
	{
	return( &capabilityInfo );
	}

#endif /* USE_ECC */
