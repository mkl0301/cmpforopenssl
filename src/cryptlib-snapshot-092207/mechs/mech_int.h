/****************************************************************************
*																			*
*						 Internal Mechanism Header File						*
*						Copyright Peter Gutmann 1992-2006					*
*																			*
****************************************************************************/

#ifndef _MECH_INT_DEFINED

#define _MECH_INT_DEFINED

/* Prototypes for functions in mech_int.c */

int getPkcAlgoParams( const CRYPT_CONTEXT pkcContext,
					  CRYPT_ALGO_TYPE *pkcAlgo, int *pkcKeySize );
int getHashAlgoParams( const CRYPT_CONTEXT hashContext,
					   CRYPT_ALGO_TYPE *hashAlgo, int *hashSize );
int adjustPKCS1Data( BYTE *outData, const int outDataMaxLen, 
					 const BYTE *inData, const int inLen, const int keySize );

#endif /* _MECH_INT_DEFINED */
