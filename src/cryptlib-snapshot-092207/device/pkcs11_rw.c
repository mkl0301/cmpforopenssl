/****************************************************************************
*																			*
*					cryptlib PKCS #11 Item Read/Write Routines				*
*						Copyright Peter Gutmann 1998-2007					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "context.h"
  #include "device.h"
  #include "pkcs11_api.h"
  #include "asn1.h"
#else
  #include "crypt.h"
  #include "context/context.h"
  #include "device/device.h"
  #include "device/pkcs11_api.h"
  #include "misc/asn1.h"
#endif /* Compiler-specific includes */

#ifdef USE_PKCS11

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Convert a time_t to a PKCS #11 CK_DATE */

static void convertDate( CK_DATE *date, const time_t theTime )
	{
	STREAM stream;
	BYTE dateBuffer[ 32 + 8 ];

	assert( isWritePtr( date, sizeof( CK_DATE ) ) );

	/* Clear return value */
	memset( date, 0, sizeof( CK_DATE ) );

	/* Convert the time_t value to an ASN.1 time string that we can use to
	   populate the CK_DATE fields, which are stored as ASCII text strings */
	sMemOpen( &stream, dateBuffer, 32 );
	writeGeneralizedTime( &stream, theTime, DEFAULT_TAG );
	sMemDisconnect( &stream );
	memcpy( &date->year, dateBuffer + 2, 4 );
	memcpy( &date->month, dateBuffer + 6, 2 );
	memcpy( &date->day, dateBuffer + 8, 2 );
	}

/* Get the label for an object.  We can't use a dynBuf for this because it's 
   a PKCS #11 attribute rather than a cryptlib attribute */

static int getObjectLabel( PKCS11_INFO *pkcs11Info, 
						   const CK_OBJECT_HANDLE hObject, 
						   char *label, const int maxLabelSize, 
						   int *labelLength )
	{
	CK_ATTRIBUTE keyLabelTemplate = \
		{ CKA_LABEL, NULL_PTR, 0 };
	CK_RV status;
	char labelBuffer[ CRYPT_MAX_TEXTSIZE + 8 ], *labelPtr = labelBuffer;

	assert( isReadPtr( pkcs11Info, sizeof( PKCS11_INFO ) ) );
	assert( isWritePtr( label, maxLabelSize ) );
	assert( isWritePtr( labelLength, sizeof( int ) ) );

	status = C_GetAttributeValue( pkcs11Info->hSession, hObject,
								  &keyLabelTemplate, 1 );
	if( status == CKR_OK )
		{
		if( keyLabelTemplate.ulValueLen > CRYPT_MAX_TEXTSIZE && \
			( labelPtr = clAlloc( "getObjectLabel", \
					( size_t ) ( keyLabelTemplate.ulValueLen ) ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		keyLabelTemplate.pValue = labelPtr;
		status = C_GetAttributeValue( pkcs11Info->hSession, hObject,
									  &keyLabelTemplate, 1 );
		}
	if( status != CKR_OK )
		{
		*labelLength = 0;
		if( label != NULL )
			label[ 0 ] = '\0';
		}
	else
		{
		*labelLength = min( keyLabelTemplate.ulValueLen, maxLabelSize );
		if( label != NULL )
			memcpy( label, labelPtr, *labelLength );
		}
	if( labelPtr != labelBuffer )
		clFree( "getObjectLabel", labelPtr );
	return( pkcs11MapError( pkcs11Info, status, CRYPT_ERROR_FAILED ) );
	}

/* Read a flag for an object.  An absent value is treated as FALSE */

static BOOLEAN readFlag( const PKCS11_INFO *pkcs11Info, 
						 const CK_OBJECT_HANDLE hObject,
						 const CK_ATTRIBUTE_TYPE flagType )
	{
	CK_BBOOL bFlag = FALSE;
	CK_ATTRIBUTE flagTemplate = { flagType, &bFlag, sizeof( CK_BBOOL ) };

	assert( isReadPtr( pkcs11Info, sizeof( PKCS11_INFO ) ) );

	/* Some buggy implementations return CKR_OK but forget to set the
	   data value in the template (!!!) so we have to initialise bFlag
	   to a default of FALSE to handle this */
	return( ( C_GetAttributeValue( pkcs11Info->hSession, hObject,
								   &flagTemplate, 1 ) == CKR_OK && bFlag ) ? \
			TRUE : FALSE );
	}

/* Get the permitted-action flags for an object */

static int getActionFlags( PKCS11_INFO *pkcs11Info,
						   const CK_OBJECT_HANDLE hObject,
						   const KEYMGMT_ITEM_TYPE itemType,
						   const CRYPT_ALGO_TYPE cryptAlgo )
	{
	const BOOLEAN checkSign = ( isSigAlgo( cryptAlgo ) || \
								( cryptAlgo >= CRYPT_ALGO_FIRST_MAC && \
								  cryptAlgo <= CRYPT_ALGO_LAST_MAC ) ) ? \
							  TRUE : FALSE;
	const BOOLEAN checkCrypt = ( isCryptAlgo( cryptAlgo ) || \
								 ( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
								   cryptAlgo < CRYPT_ALGO_LAST_CONVENTIONAL ) ) ? \
							  TRUE : FALSE;
	const BOOLEAN checkWrap = isCryptAlgo( cryptAlgo );
	BOOLEAN cryptAllowed = FALSE, sigAllowed = FALSE;
	int actionFlags = 0;

	assert( isWritePtr( pkcs11Info, sizeof( PKCS11_INFO ) ) );
	assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			itemType == KEYMGMT_ITEM_PRIVATEKEY || \
			itemType == KEYMGMT_ITEM_SECRETKEY );
	assert( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
			cryptAlgo <= CRYPT_ALGO_LAST_MAC ); 

	/* Get the permitted actions for the object.  Some devices report bogus 
	   capabilities (for example encrypt for a MAC object) so we restrict 
	   the actions that we check for to try and weed out false positives.  
	   The kernel won't allow the setting of an invalid action anyway, but 
	   it's better to be safe here.
	   
	   We also have to provide special translation for the sign and sig-
	   check action flags, PKCS #11 treats the MAC operation as a member
	   of the signature family while cryptlib treats it as a member of the
	   hash family so if we get a sign/sigcheck permitted action for a MAC 
	   object we map it to a hash permitted action */
	if( ( checkCrypt && readFlag( pkcs11Info, hObject, CKA_ENCRYPT ) ) || \
		( checkWrap && readFlag( pkcs11Info, hObject, CKA_WRAP ) ) )
		{
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_ENCRYPT, ACTION_PERM_ALL );
		cryptAllowed = TRUE;
		}
	if( ( checkCrypt && itemType != KEYMGMT_ITEM_PUBLICKEY && \
		  readFlag( pkcs11Info, hObject, CKA_DECRYPT ) ) || \
		( checkWrap && itemType == KEYMGMT_ITEM_PRIVATEKEY && \
		  readFlag( pkcs11Info, hObject, CKA_UNWRAP ) ) )
		{
		actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_DECRYPT, ACTION_PERM_ALL );
		cryptAllowed = TRUE;
		}
	if( checkSign && itemType != KEYMGMT_ITEM_PUBLICKEY && \
		readFlag( pkcs11Info, hObject, CKA_SIGN ) )
		{
		if( cryptAlgo >= CRYPT_ALGO_FIRST_MAC && \
			cryptAlgo <= CRYPT_ALGO_LAST_MAC )
			actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_HASH, ACTION_PERM_ALL );
		else
			actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_SIGN, ACTION_PERM_ALL );
		sigAllowed = TRUE;
		}
	if( checkSign && readFlag( pkcs11Info, hObject, CKA_VERIFY ) )
		{
		if( cryptAlgo >= CRYPT_ALGO_FIRST_MAC && \
			cryptAlgo <= CRYPT_ALGO_LAST_MAC )
			actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_HASH, ACTION_PERM_ALL );
		else
			actionFlags |= MK_ACTION_PERM( MESSAGE_CTX_SIGCHECK, ACTION_PERM_ALL );
		sigAllowed = TRUE;
		}
	if( cryptAlgo == CRYPT_ALGO_RSA )
		{
		/* If there are any restrictions on the key usage, we have to make it
		   internal-only because of RSA's signature/encryption duality */
		if( !( cryptAllowed && sigAllowed ) )
			actionFlags = MK_ACTION_PERM_NONE_EXTERNAL( actionFlags );
		}
	else
		if( isDlpAlgo( cryptAlgo ) )
			{
			/* Because of the special-case data formatting requirements for 
			   DLP algorithms, we make the usage internal-only */
			actionFlags = MK_ACTION_PERM_NONE_EXTERNAL( actionFlags );
			}

	return( actionFlags );
	}

/* Get cryptlib algorithm and capability info for a PKCS #11 object */

static int getMechanismInfo( const PKCS11_INFO *pkcs11Info, 
							 const CK_OBJECT_HANDLE hObject,
							 const void *capabilityInfoList, 
							 const BOOLEAN isPKC,
							 const CAPABILITY_INFO **capabilityInfoPtrPtr,
							 CRYPT_ALGO_TYPE *cryptAlgo )
	{
	CK_KEY_TYPE keyType;
	CK_ATTRIBUTE keyTypeTemplate = \
		{ CKA_KEY_TYPE, ( CK_VOID_PTR ) &keyType, sizeof( CK_KEY_TYPE ) };
	CK_RV status;
	const CAPABILITY_INFO *capabilityInfoPtr;
	const PKCS11_MECHANISM_INFO *mechanismInfoPtr;
	int mechanismInfoSize, i;

	assert( isReadPtr( pkcs11Info, sizeof( PKCS11_INFO ) ) );
	assert( capabilityInfoList != NULL );
	assert( isReadPtr( capabilityInfoPtrPtr, sizeof( CAPABILITY_INFO ) ) );
	assert( isWritePtr( cryptAlgo, sizeof( CRYPT_ALGO_TYPE ) ) );

	/* Clear return values */
	*capabilityInfoPtrPtr = NULL;
	*cryptAlgo = CRYPT_ALGO_NONE;

	/* Get the key type (equivalent to the cryptlib algoID) for this 
	   object */
	status = C_GetAttributeValue( pkcs11Info->hSession, hObject, 
								  &keyTypeTemplate, 1 );
	if( status != CKR_OK )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_FAILED );
		}

	/* Hack for PKCS #11's broken HMAC "support", PKCS #11 has no HMAC 
	   object types so if we find a generic secret key object we assume that 
	   it's an HMAC-SHA1 object, the most common type */
	if( keyType == CKK_GENERIC_SECRET )
		{
		*cryptAlgo = CRYPT_ALGO_HMAC_SHA1;
		capabilityInfoPtr = findCapabilityInfo( capabilityInfoList, 
												*cryptAlgo );
		if( capabilityInfoPtr == NULL )
			return( CRYPT_ERROR_NOTAVAIL );
		*capabilityInfoPtrPtr = capabilityInfoPtr;

		return( CRYPT_OK );
		}

	/* Get the equivalent cryptlib algorithm type and use that to get the
	   capability info for the algorithm */
	if( isPKC )
		mechanismInfoPtr = getMechanismInfoPKC( &mechanismInfoSize );
	else
		mechanismInfoPtr = getMechanismInfoConv( &mechanismInfoSize );
	for( i = 0; mechanismInfoPtr[ i ].keyType != keyType && \
				i < mechanismInfoSize; i++ );
	if( i >= mechanismInfoSize )
		{
		assert( NOTREACHED );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	mechanismInfoPtr = &mechanismInfoPtr[ i ];
	*cryptAlgo = mechanismInfoPtr->cryptAlgo;
	capabilityInfoPtr = findCapabilityInfo( capabilityInfoList, *cryptAlgo );
	if( capabilityInfoPtr == NULL )
		return( CRYPT_ERROR_NOTAVAIL );
	*capabilityInfoPtrPtr = capabilityInfoPtr;
	
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 		Find-Item Routines							*
*																			*
****************************************************************************/

/* Find an object based on a given template.  There are two variations of 
   this, one that finds one and only one object, and the other that returns 
   the first object it finds without treating the presence of multiple 
   objects as an error.
   
   The way in which this call works has special significance, there are PKCS
   #11 implementations that don't allow any other calls during the init/find/
   final sequence, so the code is structured to always call them one after 
   the other without any intervening calls.  In addition some drivers are
   confused over whether they're 1.x or 2.x and may or may not implement
   C_FindObjectsFinal().  Because of this we call it if it exists, if it 
   doesn't we assume that the driver can handle cleanup itself (this 
   situation shouldn't occur because we've checked for 1.x drivers earlier, 
   but there are one or two drivers where it does happen) */

static int findDeviceObjects( PKCS11_INFO *pkcs11Info, 
							  CK_OBJECT_HANDLE *hObject,
							  const CK_ATTRIBUTE *objectTemplate,
							  const CK_ULONG templateCount,
							  const BOOLEAN onlyOne )
	{
	CK_OBJECT_HANDLE hObjectArray[ 2 + 8 ];
	CK_ULONG ulObjectCount;
	CK_RV status;

	assert( isWritePtr( pkcs11Info, sizeof( PKCS11_INFO ) ) );
	assert( isWritePtr( hObject, sizeof( CK_OBJECT_HANDLE  ) ) );
	assert( isReadPtr( objectTemplate, \
					   sizeof( CK_ATTRIBUTE ) * templateCount ) );
	assert( templateCount > 0 );

	status = C_FindObjectsInit( pkcs11Info->hSession,
								( CK_ATTRIBUTE_PTR ) objectTemplate,
								templateCount );
	if( status == CKR_OK )
		{
		status = C_FindObjects( pkcs11Info->hSession, hObjectArray, 
								2, &ulObjectCount );
		if( C_FindObjectsFinal != NULL )
			C_FindObjectsFinal( pkcs11Info->hSession );
		}
	if( status != CKR_OK )
		return( pkcs11MapError( pkcs11Info, status, CRYPT_ERROR_NOTFOUND ) );
	if( ulObjectCount <= 0 )
		return( CRYPT_ERROR_NOTFOUND );
	if( ulObjectCount > 1 && onlyOne )
		return( CRYPT_ERROR_DUPLICATE );
	if( hObject != NULL )
		{
		assert( hObjectArray[ 0 ] != CK_OBJECT_NONE );

		*hObject = hObjectArray[ 0 ];
		}

	return( CRYPT_OK );
	}

static int findObject( PKCS11_INFO *pkcs11Info, CK_OBJECT_HANDLE *hObject,
					   const CK_ATTRIBUTE *objectTemplate,
					   const CK_ULONG templateCount )
	{
	return( findDeviceObjects( pkcs11Info, hObject, 
							   objectTemplate, templateCount, TRUE ) );
	}

static int findObjectEx( PKCS11_INFO *pkcs11Info, CK_OBJECT_HANDLE *hObject,
						 const CK_ATTRIBUTE *objectTemplate,
						 const CK_ULONG templateCount )
	{
	return( findDeviceObjects( pkcs11Info, hObject, 
							   objectTemplate, templateCount, FALSE ) );
	}

/* Find a certificate object based on various search criteria:
   
	- Find cert matching a given label - certFromLabel()
	- Find cert matching a given ID - certFromID()
	- Find cert matching the ID of an object hObject - certFromObject()
	- Find cert matching a supplied template - certFromTemplate()
	- Find any X.509 cert - certFromLabel(), no label supplied.

  These are general-purpose functions whose behaviour can be modified through
  the following action codes */

typedef enum {
	FINDCERT_NORMAL,		/* Instantiate standard cert+context */
	FINDCERT_DATAONLY,		/* Instantiate data-only cert */
	FINDCERT_P11OBJECT		/* Return handle to PKCS #11 object */
	} FINDCERT_ACTION;

static int getCertChain( PKCS11_INFO *pkcs11Info, 
						 const CRYPT_DEVICE iCertSource, 
						 const CK_OBJECT_HANDLE hCertificate, 
						 CRYPT_CERTIFICATE *iCryptCert, 
						 const BOOLEAN createContext );

static int findCertFromLabel( PKCS11_INFO *pkcs11Info,
							  const CRYPT_DEVICE iCertSource, 
							  const CK_ATTRIBUTE_TYPE labelType,
							  const char *label, const int labelLength,
							  CRYPT_CERTIFICATE *iCryptCert,
							  const FINDCERT_ACTION findAction )
	{
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_ATTRIBUTE certTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_LABEL, NULL, 0 }
		};
	CK_OBJECT_HANDLE hCertificate;
	int cryptStatus;

	assert( isWritePtr( pkcs11Info, sizeof( PKCS11_INFO ) ) );
	assert( isHandleRangeValid( iCertSource ) );
	assert( ( label == NULL && labelLength == 0 ) || \
			isReadPtr( label, labelLength ) );
	assert( isWritePtr( iCryptCert, sizeof( CRYPT_CERTIFICATE ) ) );

	*iCryptCert = CRYPT_ERROR;

	/* Try and find the cert with the given label.  Usually this is the 
	   CKA_LABEL but it can also be something like a CKA_URL */
	if( label != NULL )
		{
		certTemplate[ 2 ].type = labelType;
		certTemplate[ 2 ].pValue = ( CK_VOID_PTR ) label;
		certTemplate[ 2 ].ulValueLen = labelLength;
		}
	cryptStatus = findObject( pkcs11Info, &hCertificate, certTemplate, 
							  ( label == NULL ) ? 2 : 3 );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	if( findAction == FINDCERT_P11OBJECT )
		{
		*iCryptCert = hCertificate;
		return( CRYPT_OK );
		}

	return( getCertChain( pkcs11Info, iCertSource, hCertificate, iCryptCert, 
						  ( findAction == FINDCERT_NORMAL ) ? TRUE : FALSE ) );
	}

static int findCertFromID( PKCS11_INFO *pkcs11Info,
						   const CRYPT_DEVICE iCertSource, 
						   const void *certID, 
						   const int certIDlength,
						   CRYPT_CERTIFICATE *iCryptCert,
						   const FINDCERT_ACTION findAction )
	{
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_ATTRIBUTE certTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_ID, ( CK_VOID_PTR ) certID, certIDlength }
		};
	CK_OBJECT_HANDLE hCertificate;
	int cryptStatus;

	assert( isWritePtr( pkcs11Info, sizeof( PKCS11_INFO ) ) );
	assert( isHandleRangeValid( iCertSource ) );
	assert( isReadPtr( certID, certIDlength ) );
	assert( isWritePtr( iCryptCert, sizeof( CRYPT_CERTIFICATE ) ) );

	*iCryptCert = CRYPT_ERROR;

	/* Try and find the cert with the given ID */
	cryptStatus = findObject( pkcs11Info, &hCertificate, certTemplate, 3 );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	if( findAction == FINDCERT_P11OBJECT )
		{
		*iCryptCert = hCertificate;
		return( CRYPT_OK );
		}

	return( getCertChain( pkcs11Info, iCertSource, hCertificate, iCryptCert, 
						  ( findAction == FINDCERT_NORMAL ) ? TRUE : FALSE ) );
	}

static int findCertFromObject( PKCS11_INFO *pkcs11Info,
							   const CRYPT_DEVICE iCertSource, 
							   const CK_OBJECT_HANDLE hObject, 
							   CRYPT_CERTIFICATE *iCryptCert,
							   const FINDCERT_ACTION findAction )
	{
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_ATTRIBUTE idTemplate = \
		{ CKA_ID, NULL_PTR, 0 };
	CK_RV status;
	BYTE buffer[ MAX_BUFFER_SIZE + 8 ], *bufPtr = buffer;
	int cryptStatus;

	assert( isWritePtr( pkcs11Info, sizeof( PKCS11_INFO ) ) );
	assert( isHandleRangeValid( iCertSource ) );
	assert( isWritePtr( iCryptCert, sizeof( CRYPT_CERTIFICATE ) ) );

	*iCryptCert = CRYPT_ERROR;

	/* We're looking for a cert whose ID matches the object, read the key ID 
	   from the device.  We can't use a dynBuf for this because it's a PKCS 
	   #11 attribute rather than a cryptlib attribute */
	status = C_GetAttributeValue( pkcs11Info->hSession, hObject, 
								  &idTemplate, 1 );
	if( status == CKR_OK )
		{
		if( idTemplate.ulValueLen > MAX_BUFFER_SIZE && \
			( bufPtr = clAlloc( "findCertFromObject", \
						( size_t ) ( idTemplate.ulValueLen ) ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		idTemplate.pValue = bufPtr;
		status = C_GetAttributeValue( pkcs11Info->hSession, hObject,
									  &idTemplate, 1 );
		}
	if( status != CKR_OK )
		{
		if( bufPtr != buffer )
			clFree( "findCertFromObject", bufPtr );
		return( pkcs11MapError( pkcs11Info, status, CRYPT_ERROR_NOTFOUND ) );
		}

	/* Look for a certificate with the same ID as the key */
	cryptStatus = findCertFromID( pkcs11Info, iCertSource, bufPtr, 
								  idTemplate.ulValueLen, iCryptCert, 
								  findAction );
	if( bufPtr != buffer )
		clFree( "findCertFromObject", bufPtr );
	return( cryptStatus );
	}

static int findCertFromTemplate( PKCS11_INFO *pkcs11Info,
								 const CRYPT_DEVICE iCertSource, 
								 const CK_ATTRIBUTE *findTemplate,
								 const int templateCount,
								 CRYPT_CERTIFICATE *iCryptCert,
								 const FINDCERT_ACTION findAction )
	{
	CK_OBJECT_HANDLE hCertificate;
	int cryptStatus;

	assert( isWritePtr( pkcs11Info, sizeof( PKCS11_INFO ) ) );
	assert( isHandleRangeValid( iCertSource ) );
	assert( isReadPtr( findTemplate, \
					   sizeof( CK_ATTRIBUTE ) * templateCount ) );
	assert( templateCount > 0 );
	assert( isWritePtr( iCryptCert, sizeof( CRYPT_CERTIFICATE ) ) );

	*iCryptCert = CRYPT_ERROR;

	/* Try and find the cert from the given template */
	cryptStatus = findObject( pkcs11Info, &hCertificate, findTemplate, 
							  templateCount );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	if( findAction == FINDCERT_P11OBJECT )
		{
		*iCryptCert = hCertificate;
		return( CRYPT_OK );
		}

	return( getCertChain( pkcs11Info, iCertSource, hCertificate, iCryptCert, 
						  ( findAction == FINDCERT_NORMAL ) ? TRUE : FALSE ) );
	}

/* Find an object from a source object by matching ID's.  This is used to
   find a key matching a cert, a public key matching a private key, or
   other objects with similar relationships */

static int findObjectFromObject( PKCS11_INFO *pkcs11Info,
								 const CK_OBJECT_HANDLE hSourceObject, 
								 const CK_OBJECT_CLASS objectClass,
								 CK_OBJECT_HANDLE *hObject )
	{
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &objectClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_ID, NULL_PTR, 0 }
		};
	CK_ATTRIBUTE idTemplate = \
		{ CKA_ID, NULL_PTR, 0 };
	CK_RV status;
	BYTE buffer[ MAX_BUFFER_SIZE + 8 ], *bufPtr = buffer;
	int cryptStatus;

	assert( isWritePtr( pkcs11Info, sizeof( PKCS11_INFO ) ) );
	assert( isWritePtr( hObject, sizeof( CK_OBJECT_HANDLE ) ) );

	*hObject = CK_OBJECT_NONE;

	/* We're looking for a key whose ID matches that of the source object, 
	   read its cert ID.  We can't use a dynBuf for this because it's a 
	   PKCS #11 attribute rather than a cryptlib attribute */
	status = C_GetAttributeValue( pkcs11Info->hSession, hSourceObject, 
								  &idTemplate, 1 );
	if( status == CKR_OK )
		{
		if( idTemplate.ulValueLen > MAX_BUFFER_SIZE && \
			( bufPtr = clAlloc( "findObjectFromObject", \
						( size_t ) ( idTemplate.ulValueLen ) ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		idTemplate.pValue = bufPtr;
		status = C_GetAttributeValue( pkcs11Info->hSession, hSourceObject,
									  &idTemplate, 1 );
		}
	if( status != CKR_OK )
		{
		if( bufPtr != buffer )
			clFree( "findObjectFromObject", bufPtr );
		return( pkcs11MapError( pkcs11Info, status, CRYPT_ERROR_NOTFOUND ) );
		}

	/* Find the key object with the given ID */
	keyTemplate[ 1 ].pValue = bufPtr;
	keyTemplate[ 1 ].ulValueLen = idTemplate.ulValueLen;
	cryptStatus = findObject( pkcs11Info, hObject, keyTemplate, 2 );
	if( bufPtr != buffer )
		clFree( "findObjectFromObject", bufPtr );
	return( cryptStatus );
	}

/****************************************************************************
*																			*
*						 	Certificate R/W Routines						*
*																			*
****************************************************************************/

/* Instantiate a cert object from a handle */

static int instantiateCert( PKCS11_INFO *pkcs11Info, 
							const CK_OBJECT_HANDLE hCertificate, 
							CRYPT_CERTIFICATE *iCryptCert,
							const BOOLEAN createContext )
	{
	CK_ATTRIBUTE dataTemplate = \
		{ CKA_VALUE, NULL_PTR, 0 };
	CK_RV status;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BYTE buffer[ MAX_BUFFER_SIZE + 8 ], *bufPtr = buffer;
	int cryptStatus;

	assert( isWritePtr( pkcs11Info, sizeof( PKCS11_INFO ) ) );
	assert( isWritePtr( iCryptCert, sizeof( CRYPT_CERTIFICATE ) ) );

	*iCryptCert = CRYPT_ERROR;

	/* Fetch the cert data into local memory.  We can't use a dynBuf for 
	   this because it's a PKCS #11 attribute rather than a cryptlib 
	   attribute */
	status = C_GetAttributeValue( pkcs11Info->hSession, hCertificate,
								  &dataTemplate, 1 );
	if( status == CKR_OK )
		{
		if( dataTemplate.ulValueLen > MAX_BUFFER_SIZE && \
			( bufPtr = clAlloc( "instantiateCert", \
					( size_t ) ( dataTemplate.ulValueLen ) ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		dataTemplate.pValue = bufPtr;
		status = C_GetAttributeValue( pkcs11Info->hSession, hCertificate,
									  &dataTemplate, 1 );
		}
	if( status != CKR_OK )
		{
		if( bufPtr != buffer )
			clFree( "instantiateCert", bufPtr );
		return( pkcs11MapError( pkcs11Info, status, CRYPT_ERROR_NOTFOUND ) );
		}

	/* Import the cert as a cryptlib object */
	setMessageCreateObjectIndirectInfo( &createInfo, bufPtr, 
										dataTemplate.ulValueLen,
										CRYPT_CERTTYPE_CERTIFICATE );
	createInfo.arg1 = createContext ? CRYPT_CERTTYPE_CERTIFICATE : \
									  CRYPT_ICERTTYPE_DATAONLY;
	cryptStatus = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								   IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
								   &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( bufPtr != buffer )
		clFree( "instantiateCert", bufPtr );
	if( cryptStatusOK( cryptStatus ) )
		*iCryptCert = createInfo.cryptHandle;
	return( cryptStatus );
	}

/* Get a cert chain from a device.  This */

static int getCertChain( PKCS11_INFO *pkcs11Info, 
						 const CRYPT_DEVICE iCertSource, 
						 const CK_OBJECT_HANDLE hCertificate, 
						 CRYPT_CERTIFICATE *iCryptCert, 
						 const BOOLEAN createContext )
	{
	CK_ATTRIBUTE idTemplate = \
		{ CKA_ID, NULL_PTR, 0 };
	CK_RV status;
	BYTE keyID[ MAX_BUFFER_SIZE + 8 ];

	assert( isWritePtr( pkcs11Info, sizeof( PKCS11_INFO ) ) );
	assert( isHandleRangeValid( iCertSource ) );
	assert( isWritePtr( iCryptCert, sizeof( CRYPT_CERTIFICATE ) ) );

	/* Find the ID for this cert */
	status = C_GetAttributeValue( pkcs11Info->hSession, hCertificate, 
								  &idTemplate, 1 );
	if( status == CKR_OK && idTemplate.ulValueLen <= MAX_BUFFER_SIZE )
		{
		idTemplate.pValue = keyID;
		status = C_GetAttributeValue( pkcs11Info->hSession, hCertificate,
									  &idTemplate, 1 );
		}
	if( status != CKR_OK || idTemplate.ulValueLen > MAX_BUFFER_SIZE )
		/* We couldn't get the ID to build the chain or it's too large to be
		   usable, we can at least still return the individual cert */
		return( instantiateCert( pkcs11Info, hCertificate, iCryptCert, 
								 createContext ) );

	/* Create the cert chain via an indirect import */
	return( iCryptImportCertIndirect( iCryptCert, iCertSource, 
							CRYPT_IKEYID_KEYID, keyID, idTemplate.ulValueLen, 
							createContext ? KEYMGMT_FLAG_DATAONLY_CERT : 0 ) );
	}

/* Set up certificate information and load it into the device */

#define addTemplateValue( certTemplatePtr, valueType, valuePtr, valueLen ) \
		{ \
		( certTemplatePtr ).type = valueType; \
		( certTemplatePtr ).pValue = valuePtr; \
		( certTemplatePtr ).ulValueLen = valueLen; \
		}

static int updateCertificate( PKCS11_INFO *pkcs11Info, 
							  const CRYPT_HANDLE iCryptHandle,
							  const BOOLEAN isLeafCert )
	{
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_OBJECT_CLASS privkeyClass = CKO_PRIVATE_KEY;
	static const CK_OBJECT_CLASS pubkeyClass = CKO_PUBLIC_KEY;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	static const CK_BBOOL bTrue = TRUE;
	CK_DATE startDate, endDate;
	CK_ATTRIBUTE certTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_ID, NULL_PTR, 0 },
		{ CKA_SUBJECT, NULL_PTR, 0 },
		{ CKA_ISSUER, NULL_PTR, 0 },
		{ CKA_SERIAL_NUMBER, NULL_PTR, 0 },
		{ CKA_VALUE, NULL_PTR, 0 },
		/* Optional fields, filled in if required */
		{ CKA_NONE, NULL_PTR, 0 },	/*  8 */
		{ CKA_NONE, NULL_PTR, 0 },	/*  9 */
		{ CKA_NONE, NULL_PTR, 0 },	/* 10 */
		{ CKA_NONE, NULL_PTR, 0 },	/* 11 */
		};
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &privkeyClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_ID, NULL_PTR, 0 }
		};
	CK_OBJECT_HANDLE hObject;
	CK_RV status;
	MESSAGE_DATA msgData;
	STREAM stream;
	DYNBUF subjectDB, iAndSDB, certDB;
	BYTE keyID[ CRYPT_MAX_HASHSIZE + 8 ];
	BOOLEAN hasURL = FALSE;
	time_t theTime;
	char label[ CRYPT_MAX_TEXTSIZE + 8 ], uri[ MAX_URL_SIZE + 8 ];
	int length, templateCount = 8, cryptStatus;

	assert( isWritePtr( pkcs11Info, sizeof( PKCS11_INFO ) ) );
	assert( isHandleRangeValid( iCryptHandle ) );

	/* Get the keyID from the cert */
	setMessageData( &msgData, keyID, CRYPT_MAX_HASHSIZE );
	cryptStatus = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
								   &msgData, CRYPT_IATTRIBUTE_KEYID );
	if( cryptStatusError( cryptStatus ) )
		return( CRYPT_ARGERROR_NUM1 );
	certTemplate[ 3 ].pValue = msgData.data;
	certTemplate[ 3 ].ulValueLen = msgData.length;

	/* If it's a leaf cert, use the keyID to locate the corresponding public 
	   or private key object.  This is used as a check to ensure that the 
	   certificate corresponds to a key in the device.  In theory this would 
	   allow us to read the label from the key so that we can reuse it for 
	   the cert, but there doesn't seem to be any good reason for this and 
	   it could lead to problems with multiple certs with the same labels so 
	   we don't do it */
	if( isLeafCert )
		{
		keyTemplate[ 1 ].pValue = certTemplate[ 3 ].pValue;
		keyTemplate[ 1 ].ulValueLen = certTemplate[ 3 ].ulValueLen;
		cryptStatus = findObject( pkcs11Info, &hObject, keyTemplate, 2 );
		if( cryptStatusError( cryptStatus ) )
			{
			/* Couldn't find a private key with this ID, try for a public key */
			keyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) &pubkeyClass;
			cryptStatus = findObject( pkcs11Info, &hObject, keyTemplate, 2 );
			}
		if( cryptStatusError( cryptStatus ) )
			return( CRYPT_ARGERROR_NUM1 );
		}

	/* Get the subjectName from the cert */
	cryptStatus = dynCreate( &subjectDB, iCryptHandle, 
							 CRYPT_IATTRIBUTE_SUBJECT );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	certTemplate[ 4 ].pValue = dynData( subjectDB );
	certTemplate[ 4 ].ulValueLen = dynLength( subjectDB );

	/* Get the issuerAndSerialNumber from the cert */
	cryptStatus = dynCreate( &iAndSDB, iCryptHandle, 
							 CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusError( cryptStatus ) )
		{
		dynDestroy( &subjectDB );
		return( cryptStatus );
		}
	sMemConnect( &stream, dynData( iAndSDB ), dynLength( iAndSDB ) );
	readSequence( &stream, NULL );
	certTemplate[ 5 ].pValue = sMemBufPtr( &stream );
	readSequence( &stream, &length );		/* Issuer DN */
	certTemplate[ 5 ].ulValueLen = ( int ) sizeofObject( length );
	sSkip( &stream, length );
	certTemplate[ 6 ].pValue = sMemBufPtr( &stream );
	readGenericHole( &stream, &length, 1, BER_INTEGER );/* Serial number */
	certTemplate[ 6 ].ulValueLen = ( int ) sizeofObject( length );
	assert( sStatusOK( &stream ) );
	sMemDisconnect( &stream );

	/* Get the validFrom and validTo dates.  These aren't currently used for
	   anything, but can be used in the future to handle superceded certs in
	   the same way that it's done for PKCS #15 keysets */
	setMessageData( &msgData, &theTime, sizeof( time_t ) );
	cryptStatus = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
								   &msgData, CRYPT_CERTINFO_VALIDFROM );
	if( cryptStatusOK( cryptStatus ) )
		{
		convertDate( &startDate, theTime );
		setMessageData( &msgData, &theTime, sizeof( time_t ) );
		cryptStatus = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
									   &msgData, CRYPT_CERTINFO_VALIDTO );
		}
	if( cryptStatusOK( cryptStatus ) )
		convertDate( &endDate, theTime );
	else
		{
		dynDestroy( &subjectDB );
		dynDestroy( &iAndSDB );
		return( cryptStatus );
		}

	/* Get the certificate data */
	cryptStatus = dynCreateCert( &certDB, iCryptHandle, 
								 CRYPT_CERTFORMAT_CERTIFICATE );
	if( cryptStatusError( cryptStatus ) )
		{
		dynDestroy( &subjectDB );
		dynDestroy( &iAndSDB );
		return( cryptStatus );
		}
	certTemplate[ 7 ].pValue = dynData( certDB );
	certTemplate[ 7 ].ulValueLen = dynLength( certDB );

	/* Get the cert holder name (label) from the cert if available */
	setMessageData( &msgData, label, CRYPT_MAX_TEXTSIZE  );
	cryptStatus = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
								   &msgData, CRYPT_IATTRIBUTE_HOLDERNAME );
	if( cryptStatusOK( cryptStatus ) )
		{
		/* We've found a holder name, use it as the cert object label */
		addTemplateValue( certTemplate[ templateCount ], 
						  CKA_LABEL, msgData.data, msgData.length );
		templateCount++;
		}

	/* Add the cert dates.  These have to be located between the label and 
	   URI so that we can selectively back out the attributes that don't 
	   work for this driver, see the comments further down for more details */
	addTemplateValue( certTemplate[ templateCount ], 
					  CKA_START_DATE, ( CK_VOID_PTR ) &startDate, sizeof( CK_DATE ) );
	templateCount++;
	addTemplateValue( certTemplate[ templateCount ], 
					  CKA_END_DATE, ( CK_VOID_PTR ) &endDate, sizeof( CK_DATE ) );
	templateCount++;

	/* Get the URI from the cert if available */
	setMessageData( &msgData, uri, MAX_URL_SIZE );
	cryptStatus = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE_S,
								   &msgData, CRYPT_IATTRIBUTE_HOLDERURI );
	if( cryptStatusOK( cryptStatus ) )
		{
		/* We've found a holder URI, use it as the cert object URL */
		addTemplateValue( certTemplate[ templateCount ], 
						  CKA_URL, msgData.data, msgData.length );
		templateCount++;
		hasURL = TRUE;
		}

	/* Reset the status value, which may contain error values due to not 
	   finding various object attributes above */
	cryptStatus = CRYPT_OK;

	/* We've finally got everything available, try and update the device with
	   the certificate data.  In theory we should also set CKA_PRIVATE = FALSE
	   but the Dallas iButton driver doesn't allow this so we have to rely on
	   drivers doing the right thing with the default setting */
	status = C_CreateObject( pkcs11Info->hSession,
							 ( CK_ATTRIBUTE_PTR ) certTemplate, templateCount, 
							 &hObject );
	if( hasURL && ( status == CKR_TEMPLATE_INCONSISTENT || \
					status == CKR_ATTRIBUTE_TYPE_INVALID ) )
		{
		/* Support for the PKCS #11 v2.20 attribute CKA_URL is pretty hit-
		   and-miss, some drivers from ca.2000 support it but others from 
		   ca.2007 still don't, so if we get a CKR_ATTRIBUTE_TYPE_INVALID 
		   return code we try again without the CKA_URL */
		templateCount--;
		status = C_CreateObject( pkcs11Info->hSession,
								 ( CK_ATTRIBUTE_PTR ) certTemplate, 
								 templateCount, &hObject );
		}
	if( status == CKR_TEMPLATE_INCONSISTENT )
		{
		/* Even support for dates is hit-and-miss so if we're still getting
		   CKR_ATTRIBUTE_TYPE_INVALID we try again without the 
		   CKA_START_DATE/CKA_END_DATE */
		templateCount -= 2;
		status = C_CreateObject( pkcs11Info->hSession,
								 ( CK_ATTRIBUTE_PTR ) certTemplate, 
								 templateCount, &hObject );
		}
	if( status != CKR_OK )
		cryptStatus = pkcs11MapError( pkcs11Info, status, 
									  CRYPT_ERROR_FAILED );
	assert( hObject != CK_OBJECT_NONE );

	/* Clean up */
	dynDestroy( &subjectDB );
	dynDestroy( &iAndSDB );
	dynDestroy( &certDB );
	return( cryptStatus );
	}

/* Update a device using the certs in a cert chain */

static int updateCertChain( PKCS11_INFO *pkcs11Info, 
							const CRYPT_CERTIFICATE iCryptCert )
	{
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_ATTRIBUTE certTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_ISSUER, NULL_PTR, 0 },
		{ CKA_SERIAL_NUMBER, NULL_PTR, 0 },
		};
	BOOLEAN isLeafCert = TRUE, seenNonDuplicate = FALSE;
	int value, iterationCount = 0, cryptStatus;

	assert( isWritePtr( pkcs11Info, sizeof( PKCS11_INFO ) ) );
	assert( isHandleRangeValid( iCryptCert ) );

	/* If we've been passed a standalone cert, check whether it's implicitly
	   trusted, which allows to be added without the presence of a 
	   corresponding public/private key in the device */
	cryptStatus = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE, &value, 
								   CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( cryptStatus ) )
		return( ( cryptStatus == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : cryptStatus );
	if( value == CRYPT_CERTTYPE_CERTIFICATE )
		{
		cryptStatus = krnlSendMessage( iCryptCert, IMESSAGE_GETATTRIBUTE,
									   &value, 
									   CRYPT_CERTINFO_TRUSTED_IMPLICIT );
		if( cryptStatusError( cryptStatus ) )
			return( CRYPT_ARGERROR_NUM1 );

		/* If the cert is implicitly trusted we indicate that it's 
		   (effectively) a non-leaf cert so that it can be added even if 
		   there's no corresponding key already in the device */
		if( value )
			isLeafCert = FALSE;
		}

	/* Add each cert in the chain to the device */
	do
		{
		CK_OBJECT_HANDLE hObject;
		STREAM stream;
		DYNBUF iAndSDB;
		int length;

		/* If the cert is already present, don't do anything */
		cryptStatus = dynCreate( &iAndSDB, iCryptCert, 
								 CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
		if( cryptStatusError( cryptStatus ) )
			return( cryptStatus );
		sMemConnect( &stream, dynData( iAndSDB ), dynLength( iAndSDB ) );
		readSequence( &stream, NULL );
		certTemplate[ 2 ].pValue = sMemBufPtr( &stream );
		readSequence( &stream, &length );		/* Issuer DN */
		certTemplate[ 2 ].ulValueLen = ( int ) sizeofObject( length );
		sSkip( &stream, length );
		certTemplate[ 3 ].pValue = sMemBufPtr( &stream );
		readGenericHole( &stream, &length, 1, BER_INTEGER );/* Serial number */
		certTemplate[ 3 ].ulValueLen = ( int ) sizeofObject( length );
		assert( sStatusOK( &stream ) );
		sMemDisconnect( &stream );
		cryptStatus = findObject( pkcs11Info, &hObject, certTemplate, 4 );
		dynDestroy( &iAndSDB );
		if( cryptStatusOK( cryptStatus ) )
			/* The cert is already present, we don't need to add it again */
			continue;

		/* Write the new cert */
		cryptStatus = updateCertificate( pkcs11Info, iCryptCert, isLeafCert );
		if( cryptStatusError( cryptStatus ) )
			return( cryptStatus );
		isLeafCert = FALSE;
		seenNonDuplicate = TRUE;
		}
	while( krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
							MESSAGE_VALUE_CURSORNEXT,
							CRYPT_CERTINFO_CURRENT_CERTIFICATE ) == CRYPT_OK && \
		   iterationCount++ < FAILSAFE_ITERATIONS_MED );
	if( iterationCount >= FAILSAFE_ITERATIONS_MED )
		retIntError();
	
	return( seenNonDuplicate ? CRYPT_OK : CRYPT_ERROR_DUPLICATE );
	}

/****************************************************************************
*																			*
*						 	Read an Item from a Device						*
*																			*
****************************************************************************/

/* Instantiate an object in a device.  This works like the create context
   function but instantiates a cryptlib object using data already contained
   in the device (for example a stored private key or certificate) */

int rsaSetPublicComponents( PKCS11_INFO *pkcs11Info,
							const CRYPT_CONTEXT iCryptContext,
							const CK_OBJECT_HANDLE hRsaKey,
							const BOOLEAN nativeContext );
int dsaSetPublicComponents( PKCS11_INFO *pkcs11Info,
							const CRYPT_CONTEXT iCryptContext,
							const CK_OBJECT_HANDLE hDsaKey );

static int createNativeObject( PKCS11_INFO *pkcs11Info,
							   CRYPT_CONTEXT *iCryptContext,
							   const CK_OBJECT_HANDLE hObject,
							   const KEYMGMT_ITEM_TYPE itemType,
							   const CRYPT_ALGO_TYPE cryptAlgo )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	int actionFlags, cryptStatus;

	assert( isWritePtr( pkcs11Info, sizeof( PKCS11_INFO ) ) );
	assert( isWritePtr( iCryptContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			itemType == KEYMGMT_ITEM_PRIVATEKEY || \
			itemType == KEYMGMT_ITEM_SECRETKEY );
	assert( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
			cryptAlgo <= CRYPT_ALGO_LAST_MAC ); 

	/* Get the permitted-action flags for the object.  If no usage is 
	   allowed we can't do anything with the object so we don't even try and 
	   create it */
	actionFlags = getActionFlags( pkcs11Info, hObject, itemType, cryptAlgo );
	if( actionFlags == 0 )
		return( CRYPT_ERROR_PERMISSION );

	/* We're creating a public-key context, make it a native context instead 
	   of a device one.  This solves a variety of problems including the 
	   fact that some devices (which function purely as key stores coupled 
	   to modexp accelerators) only support private-key operations, that 
	   performing public-key operations natively is much, much faster than 
	   on any device (around 150us for a 1Kbit RSA key on a 1.7GHz CPU, 
	   which doesn't even cover the device communication overhead), and 
	   finally that if we do it ourselves we can defend against a variety 
	   of RSA padding and timing attacks that have come up since the 
	   device firmware was done */
	setMessageCreateObjectInfo( &createInfo, cryptAlgo );
	cryptStatus = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								   IMESSAGE_DEV_CREATEOBJECT, &createInfo, 
								   OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	*iCryptContext = createInfo.cryptHandle;

	/* Send the keying info to the context and set the action flags */
	if( cryptAlgo == CRYPT_ALGO_RSA )
		cryptStatus = rsaSetPublicComponents( pkcs11Info, *iCryptContext, 
											  hObject, TRUE );
	else
		cryptStatus = dsaSetPublicComponents( pkcs11Info, *iCryptContext, 
											  hObject );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlSendMessage( *iCryptContext, IMESSAGE_SETATTRIBUTE, 
									   &actionFlags, 
									   CRYPT_IATTRIBUTE_ACTIONPERMS );
	if( cryptStatusError( cryptStatus ) )
		{
		krnlSendNotifier( *iCryptContext, IMESSAGE_DECREFCOUNT );
		return( cryptStatus );
		}

	return( CRYPT_OK );
	}

static int createDeviceObject( PKCS11_INFO *pkcs11Info,
							   CRYPT_CONTEXT *iCryptContext,
							   const CK_OBJECT_HANDLE hObject,
							   const CRYPT_CERTIFICATE iCryptCert,
							   const CRYPT_USER iOwnerHandle,
							   const CRYPT_DEVICE iDeviceHandle,
							   const CAPABILITY_INFO *capabilityInfoPtr,
							   const KEYMGMT_ITEM_TYPE itemType,
							   const CRYPT_ALGO_TYPE cryptAlgo,
							   const int keySize )
	{
	MESSAGE_DATA msgData;
	char label[ CRYPT_MAX_TEXTSIZE + 8 ];
	int createFlags = CREATEOBJECT_FLAG_DUMMY;
	int actionFlags, labelLength, cryptStatus;

	assert( isWritePtr( pkcs11Info, sizeof( PKCS11_INFO ) ) );
	assert( isWritePtr( iCryptContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( ( iCryptCert == CRYPT_UNUSED ) || \
			isHandleRangeValid( iCryptCert ) );
	assert( iOwnerHandle == DEFAULTUSER_OBJECT_HANDLE || \
			isHandleRangeValid( iOwnerHandle ) );
	assert( isHandleRangeValid( iDeviceHandle ) );
	assert( isReadPtr( capabilityInfoPtr, sizeof( CAPABILITY_INFO ) ) );
	assert( itemType == KEYMGMT_ITEM_PRIVATEKEY || \
			itemType == KEYMGMT_ITEM_SECRETKEY );
	assert( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
			cryptAlgo <= CRYPT_ALGO_LAST_MAC );
	assert( keySize >= MIN_KEYSIZE && keySize <= CRYPT_MAX_PKCSIZE );

	/* Check whether this is a persistent object */
	if( readFlag( pkcs11Info, hObject, CKA_TOKEN ) )
		createFlags |= CREATEOBJECT_FLAG_PERSISTENT;

	/* Get the permitted-action flags for the object */
	actionFlags = getActionFlags( pkcs11Info, hObject, itemType, cryptAlgo );
	if( actionFlags == 0 )
		{
		/* If no usage is allowed, we can't do anything with the object so
		   we don't even try to create it */
		if( iCryptCert != CRYPT_UNUSED )
			krnlSendNotifier( iCryptCert, IMESSAGE_DECREFCOUNT );
		return( CRYPT_ERROR_PERMISSION );
		}

	/* Create a dummy context for the key, remember the device that it's 
	   contained in, and record the handle for the device-internal key */
	cryptStatus = getObjectLabel( pkcs11Info, hObject, label, 
								  CRYPT_MAX_TEXTSIZE, &labelLength );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = createContextFromCapability( iCryptContext, 
							iOwnerHandle, capabilityInfoPtr, createFlags );
	if( cryptStatusError( cryptStatus ) )
		{
		if( iCryptCert != CRYPT_UNUSED )
			krnlSendNotifier( iCryptCert, IMESSAGE_DECREFCOUNT );
		return( cryptStatus );
		}
	cryptStatus = krnlSendMessage( *iCryptContext, IMESSAGE_SETDEPENDENT,
								   ( void * ) &iDeviceHandle, 
								   SETDEP_OPTION_INCREF );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlSendMessage( *iCryptContext, IMESSAGE_SETATTRIBUTE, 
									   ( void * ) &hObject, 
									   CRYPT_IATTRIBUTE_DEVICEOBJECT );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlSendMessage( *iCryptContext, IMESSAGE_SETATTRIBUTE, 
									   &actionFlags, 
									   CRYPT_IATTRIBUTE_ACTIONPERMS );
	if( cryptStatusError( cryptStatus ) )
		{
		krnlSendNotifier( *iCryptContext, IMESSAGE_DECREFCOUNT );
		if( iCryptCert != CRYPT_UNUSED )
			krnlSendNotifier( iCryptCert, IMESSAGE_DECREFCOUNT );
		return( cryptStatus );
		}

	/* Set the object's label and mark it as initialised (i.e. with a key 
	   loaded).  Setting the label requires special care because the label 
	   that we're setting matches that of an existing object, so trying to
	   set it as a standard CRYPT_CTXINFO_LABEL will return a 
	   CRYPT_ERROR_DUPLICATE error when the context code checks for the
	   existence of an existing label.  To handle this, we use the
	   attribute CRYPT_IATTRIBUTE_EXISTINGLABEL to indicate that we're 
	   setting a label that matches an existing object in the device */
	if( labelLength <= 0 )
		{
		/* If there's no label present, use a dummy value */
		strlcpy_s( label, CRYPT_MAX_TEXTSIZE, "Label-less PKCS #11 key" );
		labelLength = strlen( label );
		}
	setMessageData( &msgData, label, min( labelLength, CRYPT_MAX_TEXTSIZE ) );
	cryptStatus = krnlSendMessage( *iCryptContext, IMESSAGE_SETATTRIBUTE_S,
								   &msgData, CRYPT_IATTRIBUTE_EXISTINGLABEL );
	if( cryptStatusOK( cryptStatus ) )
		{
		/* Send the keying info to the context.  For non-PKC contexts we 
		   only need to set the key length to let the user query the key 
		   size, for PKC contexts we also have to set the key components so
		   they can be written into certs.  Unfortunately we can't do this 
		   for DLP private keys since we can't read y from a DLP private key 
		   object (see the comments in the DSA code for more on this), 
		   however the only time this is necessary is when a cert is being 
		   generated for a key that was pre-generated in the device by 
		   someone else, which is typically done in Europe where DSA isn't 
		   used so this shouldn't be a problem */
		if( cryptAlgo == CRYPT_ALGO_RSA )
			cryptStatus = rsaSetPublicComponents( pkcs11Info, *iCryptContext, 
												  hObject, FALSE );
		else
			cryptStatus = krnlSendMessage( *iCryptContext, 
										   IMESSAGE_SETATTRIBUTE, 
										   ( void * ) &keySize, 
										   CRYPT_IATTRIBUTE_KEYSIZE );
		}
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = krnlSendMessage( *iCryptContext, IMESSAGE_SETATTRIBUTE,
									   MESSAGE_VALUE_UNUSED, 
									   CRYPT_IATTRIBUTE_INITIALISED );
	if( cryptStatusOK( cryptStatus ) && ( iCryptCert != CRYPT_UNUSED ) )
		{
		/* If it's a public key and there's a cert present, attach it to the 
		   context.  The cert is an internal object used only by the context 
		   so we tell the kernel to mark it as owned by the context only */
		cryptStatus = krnlSendMessage( *iCryptContext, IMESSAGE_SETDEPENDENT, 
									   ( void * ) &iCryptCert, 
									   SETDEP_OPTION_NOINCREF );
		}
	if( cryptStatusError( cryptStatus ) )
		{
		krnlSendNotifier( *iCryptContext, IMESSAGE_DECREFCOUNT );
		if( iCryptCert != CRYPT_UNUSED )
			krnlSendNotifier( iCryptCert, IMESSAGE_DECREFCOUNT );
		}
	return( cryptStatus );
	}

/* Get an item from a device and instantiate either a native or a device 
   object from it */

static int getItemFunction( DEVICE_INFO *deviceInfo,
							CRYPT_CONTEXT *iCryptContext,
							const KEYMGMT_ITEM_TYPE itemType,
							const CRYPT_KEYID_TYPE keyIDtype,
							const void *keyID, const int keyIDlength,
							void *auxInfo, int *auxInfoLength, 
							const int flags )
	{
	static const CK_OBJECT_CLASS pubkeyClass = CKO_PUBLIC_KEY;
	static const CK_OBJECT_CLASS privkeyClass = CKO_PRIVATE_KEY;
	static const CK_OBJECT_CLASS secKeyClass = CKO_SECRET_KEY;
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	const CAPABILITY_INFO *capabilityInfoPtr;
	CK_ATTRIBUTE iAndSTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_ISSUER, NULL_PTR, 0 },
		{ CKA_SERIAL_NUMBER, NULL_PTR, 0 }
		}, iAndSTemplateAlt[ 4 ];
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, NULL_PTR, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_LABEL, NULL_PTR, 0 }
		};
	CK_ATTRIBUTE keySizeTemplate = { 0, NULL, 0 };
	CK_OBJECT_HANDLE hObject, hCertificate;
	CRYPT_CERTIFICATE iCryptCert;
	CRYPT_ALGO_TYPE cryptAlgo;
	PKCS11_INFO *pkcs11Info = deviceInfo->devicePKCS11;
	BOOLEAN certViaPrivateKey = FALSE, privateKeyViaCert = FALSE;
	BOOLEAN certPresent = FALSE;
	int keySize, cryptStatus;

	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtr( iCryptContext, sizeof( CRYPT_CONTEXT ) ) );
	assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			itemType == KEYMGMT_ITEM_PRIVATEKEY || \
			itemType == KEYMGMT_ITEM_SECRETKEY );
	assert( keyIDtype == CRYPT_KEYID_NAME || \
			keyIDtype == CRYPT_KEYID_URI || \
			keyIDtype == CRYPT_IKEYID_KEYID || \
			keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER );
	assert( isReadPtr( keyID, keyIDlength ) );
	assert( ( auxInfo == NULL && *auxInfoLength == 0 ) || \
			isReadPtr( auxInfo, *auxInfoLength ) );

	/* If we're looking for a secret key it's fairly straightforward, we
	   can only have a label as an ID */
	if( itemType == KEYMGMT_ITEM_SECRETKEY )
		{
		CK_ULONG keySize;
		CK_ATTRIBUTE keySizeTemplate = \
			{ CKA_VALUE_LEN, &keySize, sizeof( CK_ULONG ) };
		int status;

		assert( keyIDtype == CRYPT_KEYID_NAME || \
				keyIDtype == CRYPT_IKEYID_KEYID );

		/* Try and find the object with the given label/ID */
		keyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) &secKeyClass;
		if( keyIDtype == CRYPT_IKEYID_KEYID )
			keyTemplate[ 1 ].type = CKA_ID;
		keyTemplate[ 1 ].pValue = ( CK_VOID_PTR ) keyID;
		keyTemplate[ 1 ].ulValueLen = keyIDlength;
		cryptStatus = findObject( pkcs11Info, &hObject, keyTemplate, 2 );
		if( cryptStatus == CRYPT_ERROR_NOTFOUND )
			{
			/* Some devices use the iD in place of the label, if a search by 
			   label fails we try again with the label as the iD */
			keyTemplate[ 1 ].type = CKA_ID;
			cryptStatus = findObject( pkcs11Info, &hObject, keyTemplate, 2 );
			keyTemplate[ 1 ].type = CKA_LABEL;
			}
		if( cryptStatusError( cryptStatus ) )
			return( cryptStatus );

		/* If it's just an existence check, return now */
		if( flags & KEYMGMT_FLAG_CHECK_ONLY )
			return( CRYPT_OK );

		/* We found something, map the key type to a cryptlib algorithm ID 
		   and find its capabilities */
		cryptStatus = getMechanismInfo( pkcs11Info, hObject, 
										deviceInfo->capabilityInfoList,
										FALSE, &capabilityInfoPtr,
										&cryptAlgo );
		if( cryptStatusError( cryptStatus ) )
			return( cryptStatus );
		status = C_GetAttributeValue( pkcs11Info->hSession, hObject, 
									  &keySizeTemplate, 1 );
		if( status != CKR_OK )
			return( pkcs11MapError( pkcs11Info, status, 
									CRYPT_ERROR_NOTINITED ) );

		/* Create the object as a device object */
		return( createDeviceObject( pkcs11Info, iCryptContext, hObject, 
								    CRYPT_UNUSED, deviceInfo->ownerHandle, 
								    deviceInfo->objectHandle, capabilityInfoPtr,
								    KEYMGMT_ITEM_SECRETKEY, cryptAlgo, 
									keySize ) );
		}

	/* If we're looking for something based on an issuerAndSerialNumber, set 
	   up the search template.  Because Netscape incorrectly uses the raw
	   serial number and other apps copy this, we also set up an alternative 
	   template with the serial number in this alternative form that we fall 
	   back to if a search using the correct form fails */
	if( keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER )
		{
		STREAM stream;
		int length;

		sMemConnect( &stream, keyID, keyIDlength );
		readSequence( &stream, NULL );
		iAndSTemplate[ 2 ].pValue = sMemBufPtr( &stream );
		readSequence( &stream, &length );		/* Issuer DN */
		iAndSTemplate[ 2 ].ulValueLen = ( int ) sizeofObject( length );
		sSkip( &stream, length );
		iAndSTemplate[ 3 ].pValue = sMemBufPtr( &stream );
		readGenericHole( &stream, &length, 1, BER_INTEGER );/* Serial number */
		iAndSTemplate[ 3 ].ulValueLen = ( int ) sizeofObject( length );
		memcpy( iAndSTemplateAlt, iAndSTemplate, sizeof( iAndSTemplate ) );
		iAndSTemplateAlt[ 3 ].pValue = sMemBufPtr( &stream );
		iAndSTemplateAlt[ 3 ].ulValueLen = length;
		assert( sStatusOK( &stream ) );
		sMemDisconnect( &stream );
		}

	/* If we're looking for a public key, try for a cert first.  Some non-
	   crypto-capable devices don't have an explicit CKO_PUBLIC_KEY but only 
	   a CKO_CERTIFICATE and some apps delete the public key since it's
	   redundant, so we try to create a cert object before we try anything 
	   else.  If the keyID type is an ID or label, this won't necessarily 
	   locate the cert since it could be unlabelled or have a different 
	   label/ID, so if this fails we try again by going via the private key 
	   with the given label/ID */
	if( itemType == KEYMGMT_ITEM_PUBLICKEY )
		{
		const FINDCERT_ACTION findAction = \
			( flags & ( KEYMGMT_FLAG_CHECK_ONLY | KEYMGMT_FLAG_LABEL_ONLY ) ) ? \
			FINDCERT_P11OBJECT : FINDCERT_NORMAL;

		if( keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER )
			{
			cryptStatus = findCertFromTemplate( pkcs11Info, deviceInfo->objectHandle, 
												iAndSTemplate, 4, &iCryptCert, 
												findAction );
			if( cryptStatus == CRYPT_ERROR_NOTFOUND )
				cryptStatus = findCertFromTemplate( pkcs11Info, deviceInfo->objectHandle, 
													iAndSTemplateAlt, 4, &iCryptCert, 
													findAction );
			}
		else
			if( keyIDtype == CRYPT_IKEYID_KEYID )
				cryptStatus = findCertFromID( pkcs11Info, deviceInfo->objectHandle, 
											  keyID, keyIDlength, &iCryptCert, 
											  findAction );
			else
				{
				assert( keyIDtype == CRYPT_KEYID_NAME || \
						keyIDtype == CRYPT_KEYID_URI );

				cryptStatus = findCertFromLabel( pkcs11Info, deviceInfo->objectHandle, 
												 ( keyIDtype == CRYPT_KEYID_NAME ) ? \
													CKA_LABEL : CKA_URL,
												 keyID, keyIDlength, &iCryptCert, 
												 findAction );
				if( cryptStatus == CRYPT_ERROR_NOTFOUND )
					{
					/* Some devices use the iD in place of the label, if a 
					   search by label fails we try again with the label as 
					   the iD */
					cryptStatus = findCertFromID( pkcs11Info, deviceInfo->objectHandle, 
												  keyID, keyIDlength, &iCryptCert, 
												  findAction );
					}
				}
		if( cryptStatusOK( cryptStatus ) )
			{
			/* If we're just checking whether an object exists, return now.  
			   If all we want is the key label, copy it back to the caller 
			   and exit */
			if( flags & KEYMGMT_FLAG_CHECK_ONLY )
				return( CRYPT_OK );
			if( flags & KEYMGMT_FLAG_LABEL_ONLY )
				return( getObjectLabel( pkcs11Info, 
										( CK_OBJECT_HANDLE ) iCryptCert, 
										auxInfo, *auxInfoLength, 
										auxInfoLength ) );

			*iCryptContext = iCryptCert;
			return( CRYPT_OK );
			}
		else
			/* If we're looking for a specific match on a certificate (rather 
			   than just a general public key) and we don't find anything, 
			   exit now */
			if( keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER )
				return( cryptStatus );
		}

	/* Either there were no certs found or we're looking for a private key 
	   (or, somewhat unusually, a raw public key).  At this point we can 
	   approach the problem from one of two sides, if we've got an 
	   issuerAndSerialNumber we have to find the matching cert and get the 
	   key from that, otherwise we find the key and get the cert from that */
	if( keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER )
		{
		/* Try and find the cert from the given template */
		cryptStatus = findObject( pkcs11Info, &hCertificate, 
								  iAndSTemplate, 4 );
		if( cryptStatus == CRYPT_ERROR_NOTFOUND )
			cryptStatus = findObject( pkcs11Info, &hCertificate, 
									  iAndSTemplateAlt, 4 );
		if( cryptStatusOK( cryptStatus ) )
			{
			/* We found the cert, use it to find the corresponding private 
			   key */
			cryptStatus = findObjectFromObject( pkcs11Info, hCertificate, 
												CKO_PRIVATE_KEY, &hObject );
			if( cryptStatusError( cryptStatus ) )
				return( cryptStatus );
	
			/* Remember that we've already got a cert to attach to the private
			   key */
			privateKeyViaCert = TRUE;
			}
		else
			/* If we didn't find anything, it may be because whoever set up
			   the token didn't set the iAndS rather than because there's no
			   key there, so we only bail out if we got some unexpected type 
			   of error */
			if( cryptStatus != CRYPT_ERROR_NOTFOUND )
				return( cryptStatus );
		}
	else
		{
		const int keyTemplateCount = ( keyID == NULL ) ? 1 : 2;

		/* Try and find the object with the given label/ID, or the first 
		   object of the given class if no ID is given */
		keyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) \
								  ( ( itemType == KEYMGMT_ITEM_PUBLICKEY ) ? \
								  &pubkeyClass : &privkeyClass );
		if( keyIDtype != CRYPT_KEYID_NONE )
			{
			if( keyIDtype == CRYPT_IKEYID_KEYID )
				keyTemplate[ 1 ].type = CKA_ID;
			keyTemplate[ 1 ].pValue = ( CK_VOID_PTR ) keyID;
			keyTemplate[ 1 ].ulValueLen = keyIDlength;
			}
		cryptStatus = findObject( pkcs11Info, &hObject, keyTemplate, 
								  keyTemplateCount );
		if( cryptStatus == CRYPT_ERROR_NOTFOUND )
			{
			/* Some devices use the iD in place of the label, if a search by 
			   label fails we try again with the label as the iD */
			keyTemplate[ 1 ].type = CKA_ID;
			cryptStatus = findObject( pkcs11Info, &hObject, keyTemplate, 
									  keyTemplateCount );
			keyTemplate[ 1 ].type = CKA_LABEL;
			}
		if( cryptStatus == CRYPT_ERROR_NOTFOUND && \
			itemType == KEYMGMT_ITEM_PUBLICKEY )
			{
			/* Some devices may only contain private key objects with 
			   associated certificates that can't be picked out of the other 
			   cruft that's present without going via the private key, so if 
			   we're looking for a public key and don't find one, we try 
			   again for a private key whose sole function is to point to an 
			   associated cert */
			keyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) &privkeyClass;
			cryptStatus = findObject( pkcs11Info, &hObject, keyTemplate, 
									  keyTemplateCount );
			if( cryptStatusError( cryptStatus ) )
				return( cryptStatus );
		
			/* Remember that although we've got a private key object, we only 
			   need it to find the associated cert and not finding an 
			   associated cert is an error */
			certViaPrivateKey = TRUE;
			}
		}

	/* If we're looking for any kind of private key and we either have an
	   explicit cert.ID but couldn't find a cert for it or we don't have a 
	   proper ID to search on and a generic search found more than one 
	   matching object, chances are we're after a generic decrypt key.  The 
	   former only occurs in misconfigured or limited-memory tokens, the 
	   latter only in rare tokens that store more than one private key, 
	   typically one for signing and one for verification.  
	   
	   If either of these cases occur we try again looking specifically for 
	   a decryption key.  Even this doesn't always work, there's are some
	   >1-key tokens that mark a signing key as a decryption key so we still 
	   get a CRYPT_ERROR_DUPLICATE error.
	   
	   Finally, if we can't find a decryption key either, we look for an
	   unwrapping key.  This may or may not work, depending on whether we 
	   have a decryption key marked as valid for unwrapping but not 
	   decryption, or a key that's genuinely only valid for unwrapping, but
	   at this point we're ready to try anything */
	if( itemType == KEYMGMT_ITEM_PRIVATEKEY && \
		( keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER && \
		  cryptStatus == CRYPT_ERROR_NOTFOUND ) || \
		( cryptStatus == CRYPT_ERROR_DUPLICATE ) )
		{
		static const CK_BBOOL bTrue = TRUE;
		CK_ATTRIBUTE decryptKeyTemplate[] = {
			{ CKA_CLASS, ( CK_VOID_PTR ) &privkeyClass, sizeof( CK_OBJECT_CLASS ) },
			{ CKA_DECRYPT, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) }
			};

		cryptStatus = findObject( pkcs11Info, &hObject, 
								  decryptKeyTemplate, 2 );
		if( cryptStatusError( cryptStatus ) )
			{
			decryptKeyTemplate[ 1 ].type = CKA_UNWRAP;
			cryptStatus = findObject( pkcs11Info, &hObject, 
									  decryptKeyTemplate, 2 );
			}
		}
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );

	/* If we're just checking whether an object exists, return now.  If all 
	   we want is the key label, copy it back to the caller and exit */
	if( flags & KEYMGMT_FLAG_CHECK_ONLY )
		return( CRYPT_OK );
	if( flags & KEYMGMT_FLAG_LABEL_ONLY )
		return( getObjectLabel( pkcs11Info, hObject, auxInfo, *auxInfoLength,
								auxInfoLength ) );

	/* We found something, map the key type to a cryptlib algorithm ID,
	   determine the key size, and find its capabilities */
	cryptStatus = getMechanismInfo( pkcs11Info, hObject, 
									deviceInfo->capabilityInfoList,
									TRUE, &capabilityInfoPtr, &cryptAlgo );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	switch( cryptAlgo )
		{
		case CRYPT_ALGO_RSA:
			keySizeTemplate.type = CKA_MODULUS;
			break;
		case CRYPT_ALGO_DSA:
			keySizeTemplate.type = CKA_PRIME;
			break;
		case CRYPT_ALGO_DH:
			keySizeTemplate.type = CKA_PRIME;
			break;
		default:
			assert( NOTREACHED );
			return( CRYPT_ERROR_NOTAVAIL );
		}
	C_GetAttributeValue( pkcs11Info->hSession, hObject, 
						 &keySizeTemplate, 1 );
	keySize = keySizeTemplate.ulValueLen;

	/* Try and find a certificate which matches the key.  The process is as
	   follows:

		if cert object found in issuerAndSerialNumber search
			-- Implies key == private key
			create native data-only cert object
			attach cert object to key
		else
			if public key read
				if cert
					create native cert (+context) object
				else
					create context object
			else
				create device privkey object, mark as "key loaded"
				if cert
					create native data-only cert object
					attach cert object to key

	   The reason for doing things this way is given in the comments earlier
	   on in this function */
	if( privateKeyViaCert )
		{
		/* We've already got the cert object handle, instantiate a native
		   data-only cert from it */
		cryptStatus = getCertChain( pkcs11Info, deviceInfo->objectHandle, 
									hCertificate, &iCryptCert, FALSE );
		if( cryptStatusError( cryptStatus ) )
			return( cryptStatus );
		certPresent = TRUE;
		}
	else
		{
		cryptStatus = findCertFromObject( pkcs11Info, deviceInfo->objectHandle, 
										  hObject, &iCryptCert, 
										  ( itemType == KEYMGMT_ITEM_PUBLICKEY ) ? \
										  FINDCERT_NORMAL : FINDCERT_DATAONLY );
		if( cryptStatusError( cryptStatus ) )
			{
			/* If we get a CRYPT_ERROR_NOTFOUND this is OK since it means 
			   there's no cert present, however anything else is an error. In 
			   addition if we've got a private key whose only function is to 
			   point to an associated cert then not finding anything is also 
			   an error */
			if( cryptStatus != CRYPT_ERROR_NOTFOUND || certViaPrivateKey )
				return( cryptStatus );
			}
		else
			{
			/* We got the cert, if we're being asked for a public key then
			   we've created a native object to contain it so we return that */
			certPresent = TRUE;
			if( itemType == KEYMGMT_ITEM_PUBLICKEY )
				{
				*iCryptContext = iCryptCert;
				return( CRYPT_OK );
				}
			}
		}

	/* Create the object.  If it's a public-key object we create a native
	   object for the reasons given in createNativeObject(), otherwise we
	   create a device object */
	if( itemType == KEYMGMT_ITEM_PUBLICKEY )
		return( createNativeObject( pkcs11Info, iCryptContext, hObject,
									KEYMGMT_ITEM_PUBLICKEY, cryptAlgo ) );
	return( createDeviceObject( pkcs11Info, iCryptContext, hObject, 
							    certPresent ? iCryptCert : CRYPT_UNUSED, 
							    deviceInfo->ownerHandle, 
							    deviceInfo->objectHandle, capabilityInfoPtr,
							    KEYMGMT_ITEM_PRIVATEKEY, cryptAlgo, 
								keySize ) );
	}

/* Get the sequence of certs in a chain from a device */

static int getFirstItemFunction( DEVICE_INFO *deviceInfo, 
								 CRYPT_CERTIFICATE *iCertificate,
								 int *stateInfo, 
								 const CRYPT_KEYID_TYPE keyIDtype,
								 const void *keyID, const int keyIDlength,
								 const KEYMGMT_ITEM_TYPE itemType, 
								 const int options )
	{
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_ATTRIBUTE certTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_ID, ( CK_VOID_PTR ) keyID, keyIDlength }
		};
	CK_OBJECT_HANDLE hCertificate;
	PKCS11_INFO *pkcs11Info = deviceInfo->devicePKCS11;
	int cryptStatus;

	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtr( iCertificate, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( keyIDtype == CRYPT_IKEYID_KEYID );
	assert( keyIDlength > 4 && isReadPtr( keyID, keyIDlength ) );
	assert( isWritePtr( stateInfo, sizeof( int ) ) );
	assert( itemType == KEYMGMT_ITEM_PUBLICKEY );

	/* Clear return values */
	*iCertificate = CRYPT_ERROR;
	*stateInfo = CRYPT_ERROR;

	/* Try and find the cert with the given ID.  This should work because 
	   we've just read the ID for the indirect-import that lead to the getFirst
	   call */
	cryptStatus = findObject( pkcs11Info, &hCertificate, certTemplate, 3 );
	if( cryptStatusError( cryptStatus ) )
		{
		assert( NOTREACHED );
		return( cryptStatus );
		}

	/* Instantiate the cert from the device */
	cryptStatus = instantiateCert( pkcs11Info, hCertificate, iCertificate, 
								   ( options & KEYMGMT_FLAG_DATAONLY_CERT ) ? \
									TRUE : FALSE );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	*stateInfo = *iCertificate;
	return( CRYPT_OK );
	}

static int getNextItemFunction( DEVICE_INFO *deviceInfo, 
								CRYPT_CERTIFICATE *iCertificate,
								int *stateInfo, const int options )
	{
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_ATTRIBUTE certTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_SUBJECT, NULL, 0 }
		};
	CK_OBJECT_HANDLE hCertificate;
	PKCS11_INFO *pkcs11Info = deviceInfo->devicePKCS11;
	DYNBUF subjectDB;
	int cryptStatus;

	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );
	assert( isWritePtr( iCertificate, sizeof( CRYPT_CERTIFICATE ) ) );
	assert( isWritePtr( stateInfo, sizeof( int ) ) );
	assert( isHandleRangeValid( *stateInfo ) || *stateInfo == CRYPT_ERROR );

	/* Clear return value */
	*iCertificate = CRYPT_ERROR;

	/* If the previous cert was the last one, there's nothing left to fetch */
	if( *stateInfo == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );

	/* Get the issuerName of the previous cert, which is the subjectName of
	   the cert we want */
	cryptStatus = dynCreate( &subjectDB, *stateInfo, 
							 CRYPT_IATTRIBUTE_ISSUER );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	certTemplate[ 2 ].pValue = dynData( subjectDB );
	certTemplate[ 2 ].ulValueLen = dynLength( subjectDB );

	/* Get the cert with the subject's issuer DN */
	cryptStatus = findObject( pkcs11Info, &hCertificate, certTemplate, 3 );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = instantiateCert( pkcs11Info, hCertificate, iCertificate, 
									   ( options & KEYMGMT_FLAG_DATAONLY_CERT ) ? \
										 TRUE : FALSE );
	dynDestroy( &subjectDB );
	if( cryptStatusError( cryptStatus ) )
		{
		*stateInfo = CRYPT_ERROR;
		return( cryptStatus );
		}
	*stateInfo = *iCertificate;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Write an Item to a Device						*
*																			*
****************************************************************************/

/* Update a device with a certificate */

static int setItemFunction( DEVICE_INFO *deviceInfo, 
							const CRYPT_HANDLE iCryptHandle )
	{
	CRYPT_CERTIFICATE iCryptCert;
	PKCS11_INFO *pkcs11Info = deviceInfo->devicePKCS11;
	int value, cryptStatus;

	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );
	assert( isHandleRangeValid( iCryptHandle ) );

	/* If the cert isn't signed, we can't store it in this state */
	cryptStatus = krnlSendMessage( iCryptHandle, IMESSAGE_GETATTRIBUTE,
								   &value, CRYPT_CERTINFO_IMMUTABLE );
	if( cryptStatusError( cryptStatus ) || !value )
		return( CRYPT_ERROR_NOTINITED );

	/* Lock the cert for our exclusive use (in case it's a cert chain, we 
	   also select the first cert in the chain), update the device with the 
	   cert, and unlock it to allow others access */
	krnlSendMessage( iCryptHandle, IMESSAGE_GETDEPENDENT, &iCryptCert, 
					 OBJECT_TYPE_CERTIFICATE );
	cryptStatus = krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE,
								   MESSAGE_VALUE_TRUE, 
								   CRYPT_IATTRIBUTE_LOCKED );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, 
					 MESSAGE_VALUE_CURSORFIRST, 
					 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	cryptStatus = updateCertChain( pkcs11Info, iCryptCert );
	krnlSendMessage( iCryptCert, IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_FALSE, 
					 CRYPT_IATTRIBUTE_LOCKED );

	return( cryptStatus );
	}

/****************************************************************************
*																			*
*						 	Delete an Item from a Device					*
*																			*
****************************************************************************/

/* Delete an object in a device */

static int deleteItemFunction( DEVICE_INFO *deviceInfo,
							   const KEYMGMT_ITEM_TYPE itemType,
							   const CRYPT_KEYID_TYPE keyIDtype,
							   const void *keyID, const int keyIDlength )
	{
	static const CK_OBJECT_CLASS pubkeyClass = CKO_PUBLIC_KEY;
	static const CK_OBJECT_CLASS privkeyClass = CKO_PRIVATE_KEY;
	static const CK_OBJECT_CLASS secKeyClass = CKO_SECRET_KEY;
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_ATTRIBUTE certTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_LABEL, ( CK_VOID_PTR ) keyID, keyIDlength }
		};
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &pubkeyClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_LABEL, ( CK_VOID_PTR ) keyID, keyIDlength }
		};
	CK_OBJECT_HANDLE hPrivkey = CK_OBJECT_NONE, hCertificate = CK_OBJECT_NONE;
	CK_OBJECT_HANDLE hPubkey = CK_OBJECT_NONE, hSecretKey = CK_OBJECT_NONE;
	CK_RV status;
	PKCS11_INFO *pkcs11Info = deviceInfo->devicePKCS11;
	int cryptStatus;

	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );
	assert( itemType == KEYMGMT_ITEM_PUBLICKEY || \
			itemType == KEYMGMT_ITEM_PRIVATEKEY || \
			itemType == KEYMGMT_ITEM_SECRETKEY );
	assert( keyIDtype == CRYPT_KEYID_NAME );
	assert( isReadPtr( keyID, keyIDlength ) );

	/* Find the object to delete based on the label.  Since we can have 
	   multiple related objects (e.g. a key and a cert) with the same label, 
	   a straight search for all objects with a given label could return
	   CRYPT_ERROR_DUPLICATE so we search for the objects by type as well as 
	   label.  In addition even a search for specific objects can return
	   CRYPT_ERROR_DUPLICATE so we use the Ex version of findObject() to make
	   sure we don't get an error if multiple objects exist.  Although
	   cryptlib won't allow more than one object with a given label to be
	   created, other applications might create duplicate labels.  The correct
	   behaviour in these circumstances is uncertain, what we do for now is
	   delete the first object we find that matches the label.
	   
	   First we try for a cert and use that to find associated keys */
	cryptStatus = findObjectEx( pkcs11Info, &hCertificate, certTemplate, 3 );
	if( cryptStatusOK( cryptStatus ) )
		{
		/* We got a cert, if there are associated keys delete them as well */
		cryptStatus = findObjectFromObject( pkcs11Info, hCertificate, 
											CKO_PUBLIC_KEY, &hPubkey );
		if( cryptStatusError( cryptStatus ) )
			hPubkey = CK_OBJECT_NONE;
		cryptStatus = findObjectFromObject( pkcs11Info, hCertificate, 
											CKO_PRIVATE_KEY, &hPrivkey );
		if( cryptStatusError( cryptStatus ) )
			hPrivkey = CK_OBJECT_NONE;
		}
	else
		{
		/* We didn't find a cert with the given label, try for public, 
		   private, and secret keys */
		cryptStatus = findObjectEx( pkcs11Info, &hPubkey, keyTemplate, 2 );
		if( cryptStatusError( cryptStatus ) )
			hPubkey = CK_OBJECT_NONE;
		keyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) &privkeyClass;
		cryptStatus = findObjectEx( pkcs11Info, &hPrivkey, keyTemplate, 2 );
		if( cryptStatusError( cryptStatus ) )
			hPrivkey = CK_OBJECT_NONE;
		keyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) &secKeyClass;
		cryptStatus = findObjectEx( pkcs11Info, &hSecretKey, keyTemplate, 2 );
		if( cryptStatusError( cryptStatus ) )
			hSecretKey = CK_OBJECT_NONE;

		/* There may be an unlabelled cert present, try and find it by 
		   looking for a cert matching the key ID */
		if( hPubkey != CK_OBJECT_NONE || hPrivkey != CK_OBJECT_NONE )
			{
			cryptStatus = findObjectFromObject( pkcs11Info, 
							( hPrivkey != CK_OBJECT_NONE ) ? hPrivkey : hPubkey, 
							CKO_CERTIFICATE, &hCertificate );
			if( cryptStatusError( cryptStatus ) )
				hCertificate = CK_OBJECT_NONE;
			}
		}

	/* If we found a public key with a given label but no private key, try 
	   and find a matching private key by ID, and vice versa */
	if( hPubkey != CK_OBJECT_NONE && hPrivkey == CK_OBJECT_NONE )
		{
		cryptStatus = findObjectFromObject( pkcs11Info, hPubkey, 
											CKO_PRIVATE_KEY, &hPrivkey );
		if( cryptStatusError( cryptStatus ) )
			hPrivkey = CK_OBJECT_NONE;
		}
	if( hPrivkey != CK_OBJECT_NONE && hPubkey == CK_OBJECT_NONE )
		{
		cryptStatus = findObjectFromObject( pkcs11Info, hPrivkey, 
											CKO_PUBLIC_KEY, &hPubkey );
		if( cryptStatusError( cryptStatus ) )
			hPubkey = CK_OBJECT_NONE;
		}
	if( hPrivkey == CK_OBJECT_NONE && hPubkey == CK_OBJECT_NONE && \
		hSecretKey == CK_OBJECT_NONE )
		return( CRYPT_ERROR_NOTFOUND );

	/* Reset the status values, which may contain error values due to not 
	   finding various objects to delete above */
	cryptStatus = CRYPT_OK;
	status = CKR_OK;

	/* Delete the objects */
	if( hCertificate != CK_OBJECT_NONE )
		status = C_DestroyObject( pkcs11Info->hSession, hCertificate );
	if( hPubkey != CK_OBJECT_NONE )
		{
		int status2;

		status2 = C_DestroyObject( pkcs11Info->hSession, hPubkey );
		if( status2 != CKR_OK && status == CKR_OK )
			status = status2;
		}
	if( hPrivkey != CK_OBJECT_NONE )
		{
		int status2;

		status2 = C_DestroyObject( pkcs11Info->hSession, hPrivkey );
		if( status2 != CKR_OK && status == CKR_OK )
			status = status2;
		}
	if( hSecretKey != CK_OBJECT_NONE )
		{
		int status2;

		status2 = C_DestroyObject( pkcs11Info->hSession, hSecretKey );
		if( status2 != CKR_OK && status == CKR_OK )
			status = status2;
		}
	if( status != CKR_OK )
		cryptStatus = pkcs11MapError( pkcs11Info, status, 
									  CRYPT_ERROR_FAILED );
	return( cryptStatus );
	}

/* Set up the function pointers to the read/write methods */

void initPKCS11RW( DEVICE_INFO *deviceInfo )
	{
	assert( isWritePtr( deviceInfo, sizeof( DEVICE_INFO ) ) );

	deviceInfo->getItemFunction = getItemFunction;
	deviceInfo->setItemFunction = setItemFunction;
	deviceInfo->deleteItemFunction = deleteItemFunction;
	deviceInfo->getFirstItemFunction = getFirstItemFunction;
	deviceInfo->getNextItemFunction = getNextItemFunction;
	}
#endif /* USE_PKCS11 */
