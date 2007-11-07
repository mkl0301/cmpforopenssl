/****************************************************************************
*																			*
*						 cryptlib SCEP Session Management					*
*						Copyright Peter Gutmann 1999-2007					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1_ext.h"
  #include "session.h"
  #include "certstore.h"
  #include "scep.h"
#else
  #include "crypt.h"
  #include "misc/asn1.h"
  #include "misc/asn1_ext.h"
  #include "session/session.h"
  #include "session/certstore.h"
  #include "session/scep.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in pnppki.c */

int pnpPkiSession( SESSION_INFO *sessionInfoPtr );

#ifdef USE_SCEP

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Initialise and clean up protocol info */

static void initProtocolInfo( SCEP_PROTOCOL_INFO *protocolInfo )
	{
	assert( isWritePtr( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) ) );

	memset( protocolInfo, 0, sizeof( SCEP_PROTOCOL_INFO ) );
	protocolInfo->iScepCert = CRYPT_ERROR;
	}

static void destroyProtocolInfo( SCEP_PROTOCOL_INFO *protocolInfo )
	{
	assert( isWritePtr( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) ) );

	if( protocolInfo->iScepCert != CRYPT_ERROR )
		krnlSendNotifier( protocolInfo->iScepCert, IMESSAGE_DECREFCOUNT );

	zeroise( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) );
	}

/* Check that the CA's certificate can also sign and encrypt data.  This is
   normally a really bad idea for CA certs but is required by the SCEP 
   protocol */

BOOLEAN checkCACert( const CRYPT_CERTIFICATE iCaCert )
	{
	int status;

	assert( isHandleRangeValid( iCaCert ) );

	krnlSendMessage( iCaCert, IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_CURSORFIRST,
					 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	status = krnlSendMessage( iCaCert, IMESSAGE_CHECK, NULL,
							  MESSAGE_CHECK_PKC_ENCRYPT );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iCaCert, IMESSAGE_CHECK, NULL,
								  MESSAGE_CHECK_PKC_SIGCHECK );
#if 0	/* RA certs aren't necessarily CA certs */
	if( cryptStatusOK( status ) )
		{
		/* Make sure that it really is a CA cert */
		status = krnlSendMessage( iCaCert, IMESSAGE_CHECK, NULL, 
								  MESSAGE_CHECK_CA );
		}
#endif /* 0 */
	return( cryptStatusOK( status ) ? TRUE : FALSE );
	}

/* Generate/check the server certificate fingerprint.  Unfortunately there's
   just enough protocol-specific handling in each of the different 
   fingerprint-handling routines that we can't use a single routine for all
   of them */

int processKeyFingerprint( SESSION_INFO *sessionInfoPtr )
	{
	const ATTRIBUTE_LIST *fingerprintPtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_SERVER_FINGERPRINT );
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Either compare the cert fingerprint to a supplied one or save it for
	   the caller to examine */
	if( fingerprintPtr != NULL )
		{
		/* The caller has supplied a cert fingerprint, compare it to the
		   received cert's fingerprint to make sure that we're talking to
		   the right system */
		setMessageData( &msgData, fingerprintPtr->value, 
						fingerprintPtr->valueLength );
		status = krnlSendMessage( sessionInfoPtr->iAuthInContext, 
								  IMESSAGE_COMPARE, &msgData, 
								  MESSAGE_COMPARE_FINGERPRINT );
		if( cryptStatusError( status ) )
			retExt( CRYPT_ERROR_WRONGKEY,
					( CRYPT_ERROR_WRONGKEY, SESSION_ERRINFO, 
					  "Server certificate doesn't match key fingerprint" ) );
		}
	else
		{
		BYTE certFingerprint[ CRYPT_MAX_HASHSIZE + 8 ];

		/* Remember the cert fingerprint in case the caller wants to check
		   it.  We don't worry if the add fails, it's a minor thing and not
		   worth aborting the handshake for */
		setMessageData( &msgData, certFingerprint, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( sessionInfoPtr->iAuthInContext, 
								  IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_CERTINFO_FINGERPRINT_SHA );
		if( cryptStatusOK( status ) )
			addSessionAttribute( &sessionInfoPtr->attributeList,
								 CRYPT_SESSINFO_SERVER_FINGERPRINT,
								 certFingerprint, msgData.length );
		}

	return( CRYPT_OK );
	}

/* Check that the information supplied in a request matches what's stored for
   a PKI user */

static int checkPkiUserInfo( SESSION_INFO *sessionInfoPtr,
							 SCEP_PROTOCOL_INFO *protocolInfo )
	{
	const ATTRIBUTE_LIST *userNamePtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_USERNAME );
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	MESSAGE_DATA msgData;
	BYTE keyIDbuffer[ 64 + 8 ], *keyIDptr = userNamePtr->value;
	BYTE requestPassword[ CRYPT_MAX_TEXTSIZE + 8 ];
	BYTE userPassword[ CRYPT_MAX_TEXTSIZE + 8 ];
	int requestPasswordSize, userPasswordSize;
	int keyIDsize = userNamePtr->valueLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) ) );

	/* Get the password from the PKCS #10 request */
	setMessageData( &msgData, requestPassword, CRYPT_MAX_TEXTSIZE );
	status = krnlSendMessage( sessionInfoPtr->iCertRequest, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_CERTINFO_CHALLENGEPASSWORD );
	if( cryptStatusError( status ) )
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't get challenge password from PKCS #10 request" ) );
	requestPasswordSize = msgData.length;

	/* If it's a cryptlib encoded user ID, we need to decode it before we can 
	   look up a PKI user with it */
	if( userNamePtr->flags & ATTR_FLAG_ENCODEDVALUE )
		{
		keyIDsize = decodePKIUserValue( keyIDbuffer, 64, userNamePtr->value, 
										userNamePtr->valueLength );
		keyIDptr = keyIDbuffer;
		if( cryptStatusError( keyIDsize ) )
			retIntError();
		}

	/* Get the user info for the request from the cert store */
	setMessageKeymgmtInfo( &getkeyInfo, CRYPT_IKEYID_KEYID, keyIDptr, 
						   keyIDsize, NULL, 0, KEYMGMT_FLAG_NONE );
	status = krnlSendMessage( sessionInfoPtr->cryptKeyset,
							  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
							  KEYMGMT_ITEM_PKIUSER );
	if( cryptStatusError( status ) )
		{
		zeroise( requestPassword, CRYPT_MAX_TEXTSIZE );
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't get PKI user information for requested user" ) );
		}

	/* Get the password from the PKI user object */
	setMessageData( &msgData, userPassword, CRYPT_MAX_TEXTSIZE );
	status = krnlSendMessage( getkeyInfo.cryptHandle, 
							  IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_CERTINFO_PKIUSER_ISSUEPASSWORD );
	if( cryptStatusError( status ) )
		{
		zeroise( requestPassword, CRYPT_MAX_TEXTSIZE );
		krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "Couldn't read PKI user data from PKI user object" ) );
		}
	userPasswordSize = msgData.length;
	updateSessionAttribute( &sessionInfoPtr->attributeList, 
							CRYPT_SESSINFO_PASSWORD, userPassword, 
							userPasswordSize, CRYPT_MAX_TEXTSIZE,
							ATTR_FLAG_ENCODEDVALUE );

	/* Make sure that the password matches the one in the request */
	if( userPasswordSize != requestPasswordSize || \
		memcmp( userPassword, requestPassword, userPasswordSize ) )
		{
		zeroise( requestPassword, CRYPT_MAX_TEXTSIZE );
		zeroise( userPassword, CRYPT_MAX_TEXTSIZE );
		krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "Supplied password in PKCS #10 request doesn't match "
				  "stored PKI user password" ) );
		}
	zeroise( userPassword, CRYPT_MAX_TEXTSIZE );

	/* If the subject only knows their CN, they may send a CN-only subject DN 
	   in the hope that we can fill it in for them.  In addition there may be 
	   other constraints that the CA wants to apply, these are handled by
	   applying the PKI user info to the request */
	status = krnlSendMessage( sessionInfoPtr->iCertRequest,
							  IMESSAGE_SETATTRIBUTE, &getkeyInfo.cryptHandle,
							  CRYPT_IATTRIBUTE_PKIUSERINFO );
	krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		retExt( CRYPT_ERROR_INVALID, 
				( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
				  "User information in PKCS #10 request can't be "
				  "reconciled with stored information for the user" ) );

	return( CRYPT_OK );
	}

/* Deliver an Einladung betreff Kehrseite to the client.  We don't bother
   checking the return value since there's nothing that we can do in the case 
   of an error except close the connection, which we do anyway since this is 
   the last message, and we don't return extended error information since 
   this would overwrite the information for the error that caused us to 
   return an error response */

static int sendErrorResponse( SESSION_INFO *sessionInfoPtr,
							  SCEP_PROTOCOL_INFO *protocolInfo,
							  const int scepStatus )
	{
	CRYPT_CERTIFICATE iCmsAttributes;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) ) );
	assert( cryptStatusError( scepStatus ) );

	/* Sign the error response using the CA key and SCEP attributes */
	status = createScepAttributes( sessionInfoPtr, protocolInfo,  
								   &iCmsAttributes, FALSE, scepStatus );
	if( cryptStatusError( status ) )
		return( status );	/* Return without changing extended error info */
	status = envelopeSign( sessionInfoPtr->receiveBuffer, 0,
						   sessionInfoPtr->receiveBuffer, 
						   &sessionInfoPtr->receiveBufEnd, 
						   sessionInfoPtr->receiveBufSize, 
						   CRYPT_CONTENT_NONE, sessionInfoPtr->privateKey, 
						   iCmsAttributes );
	krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );	/* Return without changing extended error info */
	DEBUG_DUMP( "scep_srespx", sessionInfoPtr->receiveBuffer, 
				sessionInfoPtr->receiveBufEnd );

	/* Return the response to the client, discarding any error indication 
	   from the write */
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_LASTMESSAGE, NULL, TRUE );
	writePkiDatagram( sessionInfoPtr, SCEP_CONTENT_TYPE );
	return( CRYPT_OK );
	}

/* For some bizarre reason integer status values are encoded as strings,
   so we have to convert them to numeric values before we can do anything
   with them */

int getScepStatusValue( const CRYPT_CERTIFICATE iCmsAttributes,
						const CRYPT_ATTRIBUTE_TYPE attributeType, 
						int *value )
	{
	MESSAGE_DATA msgData;
	BYTE buffer[ 128 + 8 ];
	int numericValue, status;

	assert( isHandleRangeValid( iCmsAttributes ) );
	assert( attributeType == CRYPT_CERTINFO_SCEP_MESSAGETYPE || \
			attributeType == CRYPT_CERTINFO_SCEP_PKISTATUS || \
			attributeType == CRYPT_CERTINFO_SCEP_FAILINFO );
	assert( isWritePtr( value, sizeof( int ) ) );

	*value = CRYPT_ERROR;
	setMessageData( &msgData, buffer, 128 );
	status = krnlSendMessage( iCmsAttributes, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, attributeType );
	if( cryptStatusError( status ) )
		return( status );
	numericValue = strGetNumeric( buffer, msgData.length, 0, 20 );
	if( cryptStatusError( numericValue ) )
		return( CRYPT_ERROR_BADDATA );
	*value = numericValue;
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Request Management Functions						*
*																			*
****************************************************************************/

/* Create a self-signed certificate for signing the request and decrypting
   the response */

static int createScepCert( SESSION_INFO *sessionInfoPtr,
						   SCEP_PROTOCOL_INFO *protocolInfo )
	{
	CRYPT_CERTIFICATE iNewCert;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) ) );

	/* Create a certificate, add the cert request and other information 
	   required by SCEP to it, and sign it.  SCEP requires that the 
	   certificate serial number match the user name/transaction ID, the 
	   spec actually says that the transaction ID should be a hash of the 
	   public key, but since it never specifies exactly what is hashed 
	   ("MD5 hash on [sic] public key") this can probably be anything.  We 
	   use the user name, which is required to identify the pkiUser entry 
	   in the CA cert store */
	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_CERTIFICATE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
							  &sessionInfoPtr->iCertRequest,
							  CRYPT_CERTINFO_CERTREQUEST );
	if( cryptStatusOK( status ) )
		{
		const ATTRIBUTE_LIST *userNamePtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_USERNAME );

		/* Set the serial number to the user name/transaction ID,
		   required by SCEP.  This is the only time that we can write a 
		   serial number to a certificate, normally it's set automagically
		   by the cert-management code */
		setMessageData( &msgData, userNamePtr->value,
						userNamePtr->valueLength );
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CERTINFO_SERIALNUMBER );
		}
	if( cryptStatusOK( status ) )
		{
		static const int keyUsage = CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
									CRYPT_KEYUSAGE_KEYENCIPHERMENT;

		/* Set the cert usage to signing (to sign the request) and
		   encryption (to decrypt the response).  We've already checked that 
		   these capabilities are available when the key was added to the 
		   session.
		   
		   We delete the attribute before we try and set it in case there 
		   was already one present in the request */
		krnlSendMessage( createInfo.cryptHandle, IMESSAGE_DELETEATTRIBUTE, 
						 NULL, CRYPT_CERTINFO_KEYUSAGE );
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_SETATTRIBUTE, ( void * ) &keyUsage, 
								  CRYPT_CERTINFO_KEYUSAGE );
		}
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_TRUE,
								  CRYPT_CERTINFO_SELFSIGNED );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_CRT_SIGN, NULL,
								  sessionInfoPtr->privateKey );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't create ephemeral self-signed SCEP "
				  "certificate" ) );
		}

	/* Now that we have a cert, attach it to the private key.  This is 
	   somewhat ugly since it alters the private key by attaching a cert 
	   that (as far as the user is concerned) shouldn't really exist, but
	   we need to do this to allow signing and decryption.  A side-effect
	   is that it constrains the private-key actions to make them internal-
	   only since it now has a cert attached, hopefully the user won't
	   notice this since the key will have a proper CA-issued cert attached 
	   to it shortly.

	   To further complicate things, we can't directly attach the newly-
	   created cert because it already has a public-key context attached to
	   it, which would result in two keys being associated with the single
	   cert.  To resolve this, we create a second copy of the cert as a
	   data-only cert and attach that to the private key */
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_GETATTRIBUTE, 
							  &iNewCert, CRYPT_IATTRIBUTE_CERTCOPY_DATAONLY );
	if( cryptStatusOK( status ) )
		krnlSendMessage( sessionInfoPtr->privateKey, IMESSAGE_SETDEPENDENT, 
						 &iNewCert, SETDEP_OPTION_NOINCREF );
	protocolInfo->iScepCert = createInfo.cryptHandle;
	return( CRYPT_OK );
	}

/* Complete the user-supplied PKCS #10 request by adding SCEP-internal
   attributes and information */

static int createScepCertRequest( SESSION_INFO *sessionInfoPtr )
	{
	const ATTRIBUTE_LIST *attributeListPtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_PASSWORD );
	MESSAGE_DATA msgData;
	int status = CRYPT_ERROR_NOTINITED;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Add the password to the PKCS #10 request as a ChallengePassword
	   attribute and sign the request.  We always send this in its
	   ASCII string form even if it's an encoded value because the
	   ChallengePassword attribute has to be a text string */
	if( attributeListPtr != NULL )
		{
		setMessageData( &msgData, attributeListPtr->value,
						attributeListPtr->valueLength );
		status = krnlSendMessage( sessionInfoPtr->iCertRequest, 
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CERTINFO_CHALLENGEPASSWORD );
		}
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( sessionInfoPtr->iCertRequest,
								  IMESSAGE_CRT_SIGN, NULL,
								  sessionInfoPtr->privateKey );
	if( cryptStatusError( status ) )
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't finalise PKCS #10 cert request" ) );
	return( CRYPT_OK );
	}

/* Create SCEP signing attributes */

int createScepAttributes( SESSION_INFO *sessionInfoPtr,
						  SCEP_PROTOCOL_INFO *protocolInfo,
						  CRYPT_CERTIFICATE *iScepAttributes,
						  const BOOLEAN isInitiator, const int scepStatus )
	{
	const ATTRIBUTE_LIST *userNamePtr = \
				findSessionAttribute( sessionInfoPtr->attributeList,
									  CRYPT_SESSINFO_USERNAME );
	CRYPT_CERTIFICATE iCmsAttributes;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) ) );
	assert( isWritePtr( iScepAttributes, sizeof( CRYPT_CERTIFICATE ) ) );

	/* Clear return value */
	*iScepAttributes = CRYPT_ERROR;

	/* Create the signing attributes needed by SCEP and add the user name/
	   transaction ID and message type */
	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_CMS_ATTRIBUTES );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT, &createInfo,
							  OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	iCmsAttributes = createInfo.cryptHandle;
	setMessageData( &msgData, userNamePtr->value, userNamePtr->valueLength );
	status = krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_SCEP_TRANSACTIONID );
	if( cryptStatusOK( status ) )
		{
		const char *messageType = isInitiator ? MESSAGETYPE_PKCSREQ : \
												MESSAGETYPE_CERTREP;

		setMessageData( &msgData, ( void * ) messageType, 
						strlen( messageType ) );
		status = krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE_S,
								  &msgData, CRYPT_CERTINFO_SCEP_MESSAGETYPE );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Add the message status */
	if( !isInitiator && cryptStatusError( scepStatus ) )
		{
		const char *failInfo = ( scepStatus == CRYPT_ERROR_SIGNATURE ) ? \
				MESSAGEFAILINFO_BADMESSAGECHECK : MESSAGEFAILINFO_BADREQUEST;

		/* SCEP provides an extremely limited set of error codes so there's 
		   not much that we can return in the way of additional failure 
		   info */
		setMessageData( &msgData, ( void * ) failInfo, strlen( failInfo ) );
		krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE_S,
						 &msgData, CRYPT_CERTINFO_SCEP_FAILINFO );
		setMessageData( &msgData, MESSAGESTATUS_FAILURE,
						strlen( MESSAGESTATUS_FAILURE ) );
		}
	else
		setMessageData( &msgData, MESSAGESTATUS_SUCCESS,
						strlen( MESSAGESTATUS_SUCCESS ) );
	status = krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_SCEP_PKISTATUS );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Add the nonce, identified as a sender nonce if we're the initiator and 
	   a recipient nonce if we're the responder */
	if( isInitiator )
		{
		/* If we're the initiator, generate a new nonce */
		setMessageData( &msgData, protocolInfo->nonce, SCEP_NONCE_SIZE );
		krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_GETATTRIBUTE_S,
						 &msgData, CRYPT_IATTRIBUTE_RANDOM_NONCE );
		protocolInfo->nonceSize = SCEP_NONCE_SIZE;
		}
	else
		/* We're the responder, use the initiator's nonce */
		setMessageData( &msgData, protocolInfo->nonce, 
						protocolInfo->nonceSize );
	status = krnlSendMessage( iCmsAttributes, IMESSAGE_SETATTRIBUTE_S,
							  &msgData, isInitiator ? \
								CRYPT_CERTINFO_SCEP_SENDERNONCE : \
								CRYPT_CERTINFO_SCEP_RECIPIENTNONCE );
	if( cryptStatusError( status ) )
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
	else
		*iScepAttributes = iCmsAttributes;
	return( status );
	}

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Exchange data with an SCEP client/server */

static int clientTransact( SESSION_INFO *sessionInfoPtr )
	{
	SCEP_PROTOCOL_INFO protocolInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Get the issuing CA certificate via SCEP's bolted-on HTTP GET facility 
	   if necessary */
	if( sessionInfoPtr->iAuthInContext == CRYPT_ERROR )
		{
		status = createAdditionalScepRequest( sessionInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Create the self-signed cert that we need in order to sign and decrypt 
	   messages */
	initProtocolInfo( &protocolInfo );
	status = createScepCertRequest( sessionInfoPtr );
	if( cryptStatusOK( status ) )
		status = createScepCert( sessionInfoPtr, &protocolInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Get a new cert from the server */
	status = createScepRequest( sessionInfoPtr, &protocolInfo );
	if( cryptStatusOK( status ) )
		{
///////////////////////////////////////////////////////////////////
#if 0
		sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_QUERY,
				"operation=PKIOperation", 22 );
#endif
///////////////////////////////////////////////////////////////////
		status = writePkiDatagram( sessionInfoPtr, SCEP_CONTENT_TYPE );
		}
	if( cryptStatusOK( status ) )
		status = readPkiDatagram( sessionInfoPtr );
	if( cryptStatusOK( status ) )
		status = checkScepResponse( sessionInfoPtr, &protocolInfo );
	krnlSendNotifier( protocolInfo.iScepCert, IMESSAGE_DECREFCOUNT );
	return( status );
	}

static int clientTransactWrapper( SESSION_INFO *sessionInfoPtr )
	{
	int status;

	/* If it's not a plug-and-play PKI session, just pass the call on down
	   to the client transaction function */
	if( !( sessionInfoPtr->sessionSCEP->flags & SCEP_PFLAG_PNPPKI ) )
		return( clientTransact( sessionInfoPtr ) );

	/* We're doing plug-and-play PKI, point the transaction function at the 
	   client-transact function to execute the PnP steps, then reset it back 
	   to the PnP wrapper after we're done */
	sessionInfoPtr->transactFunction = clientTransact;
	status = pnpPkiSession( sessionInfoPtr );
	sessionInfoPtr->transactFunction = clientTransactWrapper;
	return( status );
	}

static int serverTransact( SESSION_INFO *sessionInfoPtr )
	{
	SCEP_PROTOCOL_INFO protocolInfo;
	HTTP_DATA_INFO httpDataInfo;
	HTTP_URI_INFO httpReqInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* SCEP is a weird protocol that started out as a basic IPsec cert-
	   provisioning mechanism for routers but then had a pile of additional
	   functionality bolted onto it via HTTP mechanisms (rather than having
	   the protocol itself handle the extra functionality).  Because of this 
	   we have to handle not only the standard HTTP-as-a-substrate mechanism 
	   used by the other protocols but also HTTP GET requests for additional 
	   information that the original protocol didn't accomodate */
	sessionInfoPtr->receiveBufEnd = 0;
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_HTTPREQTYPES, NULL, 
			STREAM_NFLAG_HTTPGET | STREAM_NFLAG_HTTPPOST );
	initHttpDataInfoEx( &httpDataInfo, sessionInfoPtr->receiveBuffer,
						sessionInfoPtr->receiveBufSize, &httpReqInfo );
	status = sread( &sessionInfoPtr->stream, &httpDataInfo,
					sizeof( HTTP_DATA_INFO ) );
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &sessionInfoPtr->stream, 
						  &sessionInfoPtr->errorInfo );
		return( status );
		}

	/* If it's one of the bolted-on additions to the basic SCEP protocol, 
	   handle it separately */
	if( httpDataInfo.reqType == STREAM_NFLAG_HTTPGET )
		{
		status = processAdditionalScepRequest( sessionInfoPtr, 
											   &httpReqInfo );
		if( cryptStatusError( status ) )
			return( status );

		/* We've processed the bolted-on portion of the exhange, now go back 
		   to handling the main protocol */
		sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_HTTPREQTYPES, NULL, 
				STREAM_NFLAG_HTTPPOST );
		status = readPkiDatagram( sessionInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		{
		int length = httpDataInfo.bytesAvail;

		/* Unfortunately because we can't use readPkiDatagram() because of 
		   the weird dual-purpose HTTP transport used in SCEP, we have to 
		   duplicate portions of readPkiDatagram() here.  See the 
		   readPkiDatagram() function for code comments explaining the 
		   following operations */
		sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_HTTPREQTYPES, NULL, 
				STREAM_NFLAG_HTTPPOST );
		if( length < 4 )
			retExt( CRYPT_ERROR_UNDERFLOW,
					( CRYPT_ERROR_UNDERFLOW, SESSION_ERRINFO, 
					  "Invalid PKI message length %d", length ) );
		length = checkObjectEncoding( sessionInfoPtr->receiveBuffer, length );
		if( cryptStatusError( length ) )
			retExt( length, 
					( length, SESSION_ERRINFO, 
					  "Invalid PKI message encoding" ) );
		sessionInfoPtr->receiveBufEnd = length;
		}

	/* Read the initial message from the client.  We don't write an error
	   response at the initial read stage to prevent scanning/DOS attacks 
	   (vir sapit qui pauca loquitur) */
	initProtocolInfo( &protocolInfo );
	status = checkScepRequest( sessionInfoPtr, &protocolInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Check that the request is permitted and convert it into a 
	   certificate */
	status = checkPkiUserInfo( sessionInfoPtr, &protocolInfo );
	if( cryptStatusOK( status ) )
		{
		MESSAGE_KEYMGMT_INFO setkeyInfo;

		setMessageKeymgmtInfo( &setkeyInfo, CRYPT_KEYID_NONE, NULL, 0, 
							   NULL, 0, KEYMGMT_FLAG_NONE );
		setkeyInfo.cryptHandle = sessionInfoPtr->iCertRequest;
		status = krnlSendMessage( sessionInfoPtr->cryptKeyset,
								  IMESSAGE_KEY_SETKEY, &setkeyInfo, 
								  KEYMGMT_ITEM_REQUEST );
		if( cryptStatusError( status ) )
			strlcpy_s( sessionInfoPtr->errorInfo.errorString, 
					   MAX_ERRMSG_SIZE,
					   "Request couldn't be added to cert store" );
		}
	if( cryptStatusOK( status ) )
		{
		MESSAGE_CERTMGMT_INFO certMgmtInfo;

		setMessageCertMgmtInfo( &certMgmtInfo, sessionInfoPtr->privateKey,
								sessionInfoPtr->iCertRequest );
		status = krnlSendMessage( sessionInfoPtr->cryptKeyset,
								  IMESSAGE_KEY_CERTMGMT, &certMgmtInfo,
								  CRYPT_CERTACTION_ISSUE_CERT );
		if( cryptStatusOK( status ) )
			sessionInfoPtr->iCertResponse = certMgmtInfo.cryptCert;
		else
			strlcpy_s( sessionInfoPtr->errorInfo.errorString, 
					   MAX_ERRMSG_SIZE, 
					   "Couldn't issue certificate for user" );
		}
	if( cryptStatusError( status ) )
		{
		sendErrorResponse( sessionInfoPtr, &protocolInfo, status );
		destroyProtocolInfo( &protocolInfo );
		return( status );
		}

	/* Return the certificate to the client */
	status = createScepResponse( sessionInfoPtr, &protocolInfo );
	if( cryptStatusOK( status ) )
		status = writePkiDatagram( sessionInfoPtr, SCEP_CONTENT_TYPE );
	destroyProtocolInfo( &protocolInfo );
	return( status );
	}

/****************************************************************************
*																			*
*					Control Information Management Functions				*
*																			*
****************************************************************************/

static int setAttributeFunction( SESSION_INFO *sessionInfoPtr,
								 const void *data,
								 const CRYPT_ATTRIBUTE_TYPE type )
	{
	CRYPT_CERTIFICATE cryptCert = *( ( CRYPT_CERTIFICATE * ) data );
	int value, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( type == CRYPT_SESSINFO_REQUEST || \
			type == CRYPT_SESSINFO_CACERTIFICATE );

	/* Make sure that there aren't any conflicts with existing attributes */
	if( !checkAttributesConsistent( sessionInfoPtr, type ) )
		return( CRYPT_ERROR_INITED );

	if( type == CRYPT_SESSINFO_CMP_PRIVKEYSET )
		{
		CRYPT_CERTIFICATE privKeyset = *( ( CRYPT_CERTIFICATE * ) data );

		/* Remember that we're using plug-and-play PKI functionality */
		sessionInfoPtr->sessionSCEP->flags |= SCEP_PFLAG_PNPPKI;

		krnlSendNotifier( privKeyset, IMESSAGE_INCREFCOUNT );
		sessionInfoPtr->privKeyset = privKeyset;
		return( CRYPT_OK );
		}

	/* Make sure that everything is set up ready to go */
	status = krnlSendMessage( cryptCert, IMESSAGE_GETATTRIBUTE, &value, 
							  CRYPT_CERTINFO_IMMUTABLE );
	if( type == CRYPT_SESSINFO_CACERTIFICATE )
		{
		if( cryptStatusError( status ) || !value )
			return( CRYPT_ARGERROR_NUM1 );
		}
	else
		/* The PKCS #10 request has to be unsigned so that we can add the 
		   challengePassword */
		if( cryptStatusError( status ) || value )
			return( CRYPT_ARGERROR_NUM1 );
	if( type == CRYPT_SESSINFO_CACERTIFICATE )
		{
		/* Make sure that the CA cert meets the SCEP protocol requirements */
		if( !checkCACert( cryptCert ) )
			{
			setErrorInfo( sessionInfoPtr, CRYPT_CERTINFO_KEYUSAGE,
						  CRYPT_ERRTYPE_ATTR_VALUE );
			return( CRYPT_ARGERROR_NUM1 );
			}
		}

	/* Add the request and increment its usage count */
	krnlSendNotifier( cryptCert, IMESSAGE_INCREFCOUNT );
	if( type == CRYPT_SESSINFO_CACERTIFICATE )
		{
		sessionInfoPtr->iAuthInContext = cryptCert;
		processKeyFingerprint( sessionInfoPtr );
		}
	else
		sessionInfoPtr->iCertRequest = cryptCert;

	return( CRYPT_OK );
	}

static int checkAttributeFunction( SESSION_INFO *sessionInfoPtr,
								   const CRYPT_HANDLE cryptHandle,
								   const CRYPT_ATTRIBUTE_TYPE type )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	if( type != CRYPT_SESSINFO_PRIVATEKEY )
		return( CRYPT_OK );

	/* Make sure that there aren't any conflicts with existing attributes */
	if( !checkAttributesConsistent( sessionInfoPtr, type ) )
		return( CRYPT_ERROR_INITED );

	/* If it's a client key, make sure that there's no cert attached */
	if( !isServer( sessionInfoPtr ) )
		{
		int value;

		status = krnlSendMessage( cryptHandle, IMESSAGE_GETATTRIBUTE, &value, 
								  CRYPT_CERTINFO_CERTTYPE );
		if( cryptStatusOK( status ) )
			return( CRYPT_ARGERROR_NUM1 );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

int setAccessMethodSCEP( SESSION_INFO *sessionInfoPtr )
	{
	static const PROTOCOL_INFO protocolInfo = {
		/* General session information */
		TRUE,						/* Request-response protocol */
		SESSION_ISHTTPTRANSPORT,	/* Flags */
		80,							/* HTTP port */
		SESSION_NEEDS_USERID |		/* Client attributes */
			SESSION_NEEDS_PASSWORD | \
			SESSION_NEEDS_PRIVATEKEY | \
			SESSION_NEEDS_PRIVKEYSIGN | \
			SESSION_NEEDS_PRIVKEYCRYPT | \
			SESSION_NEEDS_REQUEST,
		SESSION_NEEDS_PRIVATEKEY |	/* Server attributes */
			SESSION_NEEDS_PRIVKEYSIGN | \
			SESSION_NEEDS_PRIVKEYCRYPT | \
			SESSION_NEEDS_PRIVKEYCERT | \
			SESSION_NEEDS_PRIVKEYCACERT | \
			SESSION_NEEDS_CERTSTORE,
		1, 1, 1						/* Version 1 */
		};

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Set the access method pointers */
	sessionInfoPtr->protocolInfo = &protocolInfo;
	if( isServer( sessionInfoPtr ) )
		sessionInfoPtr->transactFunction = serverTransact;
	else
		sessionInfoPtr->transactFunction = clientTransactWrapper;
	sessionInfoPtr->setAttributeFunction = setAttributeFunction;
	sessionInfoPtr->checkAttributeFunction = checkAttributeFunction;

	return( CRYPT_OK );
	}
#endif /* USE_SCEP */
