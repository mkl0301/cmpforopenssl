/****************************************************************************
*																			*
*						 cryptlib SCEP Client Management					*
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

#ifdef USE_SCEP

/****************************************************************************
*																			*
*					Additional Request Management Functions					*
*																			*
****************************************************************************/

/* Process one of the bolted-on additions to the basic SCEP protocol */

int createAdditionalScepRequest( SESSION_INFO *sessionInfoPtr )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	HTTP_DATA_INFO httpDataInfo;
	HTTP_URI_INFO httpReqInfo;
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( sessionInfoPtr->iAuthInContext == CRYPT_ERROR );

	/* Perform an HTTP GET with arguments "operation=GetCACert&message=*" */
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_HTTPREQTYPES, NULL, 
			STREAM_NFLAG_HTTPGET );
	initHttpDataInfoEx( &httpDataInfo, sessionInfoPtr->receiveBuffer,
						sessionInfoPtr->receiveBufSize, &httpReqInfo );
	memcpy( httpReqInfo.attribute, "operation", 9 );
	httpReqInfo.attributeLen = 9;
	memcpy( httpReqInfo.value, "GetCACert", 9 );
	httpReqInfo.valueLen = 9;
	memcpy( httpReqInfo.extraData, "message=*", 9 );
	httpReqInfo.extraDataLen = 9;
	status = sread( &sessionInfoPtr->stream, &httpDataInfo,
					sizeof( HTTP_DATA_INFO ) );
	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_HTTPREQTYPES, NULL, 
			STREAM_NFLAG_HTTPPOST );
	if( cryptStatusError( status ) )
		return( status );
	length = httpDataInfo.bytesAvail;

	/* Since we can't use readPkiDatagram() because of the weird dual-
	   purpose HTTP transport used in SCEP, we have to duplicate portions of 
	   readPkiDatagram() here.  See the readPkiDatagram() function for code 
	   comments explaining the following operations */
	if( length < 4 )
		retExt( CRYPT_ERROR_UNDERFLOW,
				( CRYPT_ERROR_UNDERFLOW, SESSION_ERRINFO, 
				  "Invalid PKI message length %d", length ) );
	length = checkObjectEncoding( sessionInfoPtr->receiveBuffer, length );
	if( cryptStatusError( length ) )
		retExt( length, 
				( length, SESSION_ERRINFO, 
				  "Invalid PKI message encoding" ) );

	/* Import the CA certificate and save it for later use */
	setMessageCreateObjectIndirectInfo( &createInfo,
								sessionInfoPtr->receiveBuffer, length,
								CRYPT_CERTTYPE_CERTIFICATE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		retExt( length, 
				( length, SESSION_ERRINFO, 
				  "Invalid SCEP CA certificate" ) );
	sessionInfoPtr->iAuthInContext = createInfo.cryptHandle;

	/* Process the server's key fingerprint */
	status = processKeyFingerprint( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the CA cert meets the SCEP protocol requirements */
	if( !checkCACert( sessionInfoPtr->iAuthInContext ) )
		retExt( CRYPT_ERROR_INVALID, 
				( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
				  "CA certificate usage restrictions prevent it from being "
				  "used for SCEP" ) );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Client-side Functions							*
*																			*
****************************************************************************/

/* Create an SCEP request message */

int createScepRequest( SESSION_INFO *sessionInfoPtr,
					   SCEP_PROTOCOL_INFO *protocolInfo )
	{
	CRYPT_CERTIFICATE iCmsAttributes;
	MESSAGE_DATA msgData;
	int dataLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) ) );

	/* Extract the request data into the session buffer */
	setMessageData( &msgData, sessionInfoPtr->receiveBuffer,
					sessionInfoPtr->receiveBufSize );
	status = krnlSendMessage( sessionInfoPtr->iCertRequest,
							  IMESSAGE_CRT_EXPORT, &msgData,
							  CRYPT_CERTFORMAT_CERTIFICATE );
	if( cryptStatusError( status ) )
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't get PKCS #10 request data from SCEP request "
				  "object" ) );
	DEBUG_DUMP( "scep_req0", sessionInfoPtr->receiveBuffer, msgData.length );

	/* Phase 1: Encrypt the data using the CA's key */
	status = envelopeWrap( sessionInfoPtr->receiveBuffer, msgData.length,
						   sessionInfoPtr->receiveBuffer, &dataLength, 
						   sessionInfoPtr->receiveBufSize,
						   CRYPT_FORMAT_CMS, CRYPT_CONTENT_NONE, 
						   sessionInfoPtr->iAuthInContext );
	if( cryptStatusError( status ) )
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't encrypt request data with CA key" ) );
	DEBUG_DUMP( "scep_req1", sessionInfoPtr->receiveBuffer, dataLength );

	/* Create the SCEP signing attributes */
	status = createScepAttributes( sessionInfoPtr, protocolInfo,  
								   &iCmsAttributes, TRUE, CRYPT_OK );
	if( cryptStatusError( status ) )
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't create SCEP request signing attributes" ) );

	/* Phase 2: Sign the data using the self-signed cert and SCEP attributes */
	status = envelopeSign( sessionInfoPtr->receiveBuffer, dataLength,
						   sessionInfoPtr->receiveBuffer, 
						   &sessionInfoPtr->receiveBufEnd, 
						   sessionInfoPtr->receiveBufSize, 
						   CRYPT_CONTENT_NONE, sessionInfoPtr->privateKey, 
						   iCmsAttributes );
	krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't sign request data with ephemeral SCEP "
				  "certificate" ) );
	DEBUG_DUMP( "scep_req2", sessionInfoPtr->receiveBuffer, 
				sessionInfoPtr->receiveBufEnd );
	return( CRYPT_OK );
	}

/* Check an SCEP response message */

int checkScepResponse( SESSION_INFO *sessionInfoPtr,
					   SCEP_PROTOCOL_INFO *protocolInfo )
	{
	CRYPT_CERTIFICATE iCmsAttributes;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	BYTE buffer[ CRYPT_MAX_HASHSIZE + 8 ];
	int dataLength, sigResult, value, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) ) );

	/* Phase 1: Sig.check the data using the CA's key */
	DEBUG_DUMP( "scep_resp2", sessionInfoPtr->receiveBuffer, 
				sessionInfoPtr->receiveBufEnd );
	status = envelopeSigCheck( sessionInfoPtr->receiveBuffer, 
							   sessionInfoPtr->receiveBufEnd,
							   sessionInfoPtr->receiveBuffer, &dataLength, 
							   sessionInfoPtr->receiveBufSize, 
							   sessionInfoPtr->iAuthInContext, &sigResult,
							   NULL, &iCmsAttributes );
	if( cryptStatusError( status ) )
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "Invalid CMS signed data in CA response" ) );
	DEBUG_DUMP( "scep_res1", sessionInfoPtr->receiveBuffer, dataLength );
	if( cryptStatusError( sigResult ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		retExt( sigResult, 
				( sigResult, SESSION_ERRINFO, 
				  "Bad signature on CA response data" ) );
		}

	/* Check that the returned nonce matches our initial nonce.  It's now
	   identified as a recipient nonce since it's coming from the 
	   responder */
	setMessageData( &msgData, buffer, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iCmsAttributes, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_SCEP_RECIPIENTNONCE );
	if( cryptStatusError( status ) || \
		msgData.length != protocolInfo->nonceSize || \
		memcmp( buffer, protocolInfo->nonce, protocolInfo->nonceSize ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Returned nonce doesn't match our original nonce" ) );
		}

	/* Check that the operation succeeded */
	status = getScepStatusValue( iCmsAttributes,
								 CRYPT_CERTINFO_SCEP_MESSAGETYPE, &value );
	if( cryptStatusOK( status ) && value != MESSAGETYPE_CERTREP_VALUE )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusOK( status ) )
		status = getScepStatusValue( iCmsAttributes,
									 CRYPT_CERTINFO_SCEP_PKISTATUS, &value );
	if( cryptStatusOK( status ) && value != MESSAGESTATUS_SUCCESS_VALUE )
		{
		ERROR_INFO *errorInfo = &sessionInfoPtr->errorInfo;

		errorInfo->errorCode = value;
		status = getScepStatusValue( iCmsAttributes,
									 CRYPT_CERTINFO_SCEP_FAILINFO, &value );
		if( cryptStatusOK( status ) )
			errorInfo->errorCode = value;
		status = CRYPT_ERROR_FAILED;
		}
	krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "SCEP server reports that certificate issue operation "
				  "failed" ) );

	/* Phase 2: Decrypt the data using our self-signed key */
	status = envelopeUnwrap( sessionInfoPtr->receiveBuffer, dataLength,
							 sessionInfoPtr->receiveBuffer, &dataLength, 
							 sessionInfoPtr->receiveBufSize,
							 sessionInfoPtr->privateKey );
	if( cryptStatusError( status ) )
		retExt( status, 
				( status,  SESSION_ERRINFO, 
				  "Couldn't decrypt CMS enveloped data in CA response" ) );
	DEBUG_DUMP( "scep_res0", sessionInfoPtr->receiveBuffer, dataLength );

	/* Finally, import the returned cert(s) as a PKCS #7 chain */
	setMessageCreateObjectIndirectInfo( &createInfo,
								sessionInfoPtr->receiveBuffer, dataLength,
								CRYPT_CERTTYPE_CERTCHAIN );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "Invalid PKCS #7 certificate chain in CA response" ) );
	sessionInfoPtr->iCertResponse = createInfo.cryptHandle;
	return( CRYPT_OK );
	}
#endif /* USE_SCEP */
