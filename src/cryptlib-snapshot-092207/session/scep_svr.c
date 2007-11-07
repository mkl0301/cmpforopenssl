/****************************************************************************
*																			*
*						 cryptlib SCEP Server Management					*
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

/* Table mapping a query submitted as an HTTP GET to a supplementary SCEP
   operation.  Note that the first letter must be lowercase for the
   case-insensitive quick match */

enum { SCEP_OPERATION_GETCACERT, SCEP_OPERATION_GETCACERTCHAIN };

static const CERTSTORE_READ_INFO certstoreReadInfo[] = {
	{ "getCACert", 9, SCEP_OPERATION_GETCACERT, CERTSTORE_FLAG_NONE },
	{ "getCACertChain", 14, SCEP_OPERATION_GETCACERTCHAIN, CERTSTORE_FLAG_NONE },
	{ NULL, CRYPT_ERROR, CERTSTORE_FLAG_NONE },
	{ NULL, CRYPT_ERROR, CERTSTORE_FLAG_NONE }
	};

/****************************************************************************
*																			*
*					Additional Request Management Functions					*
*																			*
****************************************************************************/

/* Process one of the bolted-on additions to the basic SCEP protocol */

int processAdditionalScepRequest( SESSION_INFO *sessionInfoPtr,
								  const HTTP_URI_INFO *httpReqInfo )
	{
	HTTP_URI_INFO rewrittenHttpReqInfo;
	MESSAGE_DATA msgData;
	char queryErrorText[ CRYPT_MAX_TEXTSIZE + 8 ];
	int operationType, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( httpReqInfo, sizeof( HTTP_URI_INFO ) ) );

	/* If the client has fed us an HTTP GET request, find out what they  
	   want.  SCEP's handling of HTTP requests is a bit different from the 
	   "attribute '=' value" lookup that's normally used for HTTP data 
	   retrieval.  Instead, it uses the format 
	   "'operation =' value '&' extraData", with the search key buried in 
	   the 'extraData' value.  In addition the content of the 'extraData' 
	   value isn't defined outside of "any string which is understood by the 
	   CA".  However since 'value' defines what we want, we can determine 
	   what to return based on this and ignore the 'extraData' portion.

	   In order to fix up the query info into a format that works with 
	   standard HTTP queries, we rewrite the query data from the 
	   "'operation =' value '&' extraData" form into "attribute '=' value" 
	   before we process the query */
	memset( &rewrittenHttpReqInfo, 0, sizeof( HTTP_URI_INFO ) );
	memcpy( rewrittenHttpReqInfo.attribute, httpReqInfo->value, 
			httpReqInfo->valueLen );
	rewrittenHttpReqInfo.attributeLen = httpReqInfo->valueLen;
	if( httpReqInfo->extraDataLen > 0 )
		{
		memcpy( rewrittenHttpReqInfo.value, httpReqInfo->extraData, 
				httpReqInfo->extraDataLen );
		rewrittenHttpReqInfo.valueLen = httpReqInfo->extraDataLen;
		}
	status = processCertQuery( sessionInfoPtr, &rewrittenHttpReqInfo,
							   certstoreReadInfo, 
							   FAILSAFE_ARRAYSIZE( certstoreReadInfo, \
												   CERTSTORE_READ_INFO ),
							   &operationType, NULL, 0, NULL, 
							   queryErrorText, CRYPT_MAX_TEXTSIZE  );
	if( cryptStatusError( status ) )
		{
		sendCertErrorResponse( sessionInfoPtr, status );
		return( status );
		}
	assert( operationType == SCEP_OPERATION_GETCACERT || \
			operationType == SCEP_OPERATION_GETCACERTCHAIN );

	/* Export the CA certificate and send it to the client */
	setMessageData( &msgData, sessionInfoPtr->receiveBuffer,
					sessionInfoPtr->receiveBufSize );
	status = krnlSendMessage( sessionInfoPtr->privateKey,
							  IMESSAGE_CRT_EXPORT, &msgData,
							  ( operationType == SCEP_OPERATION_GETCACERT ) ? \
								CRYPT_CERTFORMAT_CERTIFICATE : \
								CRYPT_CERTFORMAT_CERTCHAIN );
	if( cryptStatusError( status ) )
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't export CA certificate%s for '%s' request", 
				  ( operationType == SCEP_OPERATION_GETCACERT ) ? \
					"" : " chain",
				  ( operationType == SCEP_OPERATION_GETCACERT ) ? \
					"GetCACert" : "GetCACertChain" ) );
	sessionInfoPtr->receiveBufEnd = msgData.length;
	return( writePkiDatagram( sessionInfoPtr, 
							  ( operationType == SCEP_OPERATION_GETCACERT ) ? \
								SCEP_CONTENT_TYPE_GETCACERT : \
								SCEP_CONTENT_TYPE_GETCACERTCHAIN ) );
	}

/****************************************************************************
*																			*
*							Server-side Functions							*
*																			*
****************************************************************************/

/* Check an SCEP request message */

int checkScepRequest( SESSION_INFO *sessionInfoPtr,
					  SCEP_PROTOCOL_INFO *protocolInfo )
	{
	CRYPT_CERTIFICATE iCmsAttributes;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	int dataLength, sigResult, value, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) ) );

	/* Phase 1: Sig.check the self-signed data */
	DEBUG_DUMP( "scep_sreq2", sessionInfoPtr->receiveBuffer, 
				sessionInfoPtr->receiveBufEnd );
	status = envelopeSigCheck( sessionInfoPtr->receiveBuffer, 
							   sessionInfoPtr->receiveBufEnd,
							   sessionInfoPtr->receiveBuffer, &dataLength, 
							   sessionInfoPtr->receiveBufSize, 
							   CRYPT_UNUSED, &sigResult, 
							   &protocolInfo->iScepCert, &iCmsAttributes );
	if( cryptStatusError( status ) )
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "Invalid CMS signed data in client request" ) );
	DEBUG_DUMP( "scep_sreq1", sessionInfoPtr->receiveBuffer, dataLength );
	if( cryptStatusError( sigResult ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		retExt( sigResult, 
				( sigResult, SESSION_ERRINFO, 
				  "Bad signature on client request data" ) );
		}

	/* Make sure that the client cert is valid for signing and decryption.
	   In effect the signing capability has already been checked by the fact
	   that the cert signed the request, but we do an explicit check here
	   just to be thorough */
	status = krnlSendMessage( protocolInfo->iScepCert, IMESSAGE_CHECK, 
							  NULL, MESSAGE_CHECK_PKC_SIGCHECK );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( protocolInfo->iScepCert, IMESSAGE_CHECK, 
								  NULL, MESSAGE_CHECK_PKC_ENCRYPT );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		retExt( CRYPT_ERROR_INVALID, 
				( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
				  "Ephemeral SCEP client certificate isn't valid for "
				  "signing/encryption" ) );
		}

	/* Get the nonce and transaction ID and save it for the reply */
	setMessageData( &msgData, protocolInfo->nonce, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iCmsAttributes, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_SCEP_SENDERNONCE );
	if( cryptStatusOK( status ) )
		{
		protocolInfo->nonceSize = msgData.length;
		setMessageData( &msgData, protocolInfo->transID, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( iCmsAttributes, IMESSAGE_GETATTRIBUTE_S,
								  &msgData,
								  CRYPT_CERTINFO_SCEP_TRANSACTIONID );
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Request is missing a nonce/transaction ID" ) );
		}
	protocolInfo->transIDsize = msgData.length;

	/* We've got a transaction ID (user ID), remember it for later, 
	   remembering also whether it's a cryptlib encoded ID */
	status = updateSessionAttribute( &sessionInfoPtr->attributeList,
						CRYPT_SESSINFO_USERNAME, protocolInfo->transID, 
						protocolInfo->transIDsize, CRYPT_MAX_HASHSIZE,
						( protocolInfo->transIDsize == 17 && \
						  isPKIUserValue( protocolInfo->transID, \
										  protocolInfo->transIDsize ) ) ? \
						ATTR_FLAG_ENCODEDVALUE : ATTR_FLAG_NONE );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Check that we've been sent the correct type of message */
	status = getScepStatusValue( iCmsAttributes,
								 CRYPT_CERTINFO_SCEP_MESSAGETYPE, &value );
	if( cryptStatusOK( status ) && value != MESSAGETYPE_PKCSREQ_VALUE )
		status = CRYPT_ERROR_BADDATA;
	krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		retExt( status, 
				( status, SESSION_ERRINFO, "Incorrect SCEP message type %d",
				  value ) );

	/* Phase 2: Decrypt the data using our CA key */
	status = envelopeUnwrap( sessionInfoPtr->receiveBuffer, dataLength,
							 sessionInfoPtr->receiveBuffer, &dataLength, 
							 sessionInfoPtr->receiveBufSize,
							 sessionInfoPtr->privateKey );
	if( cryptStatusError( status ) )
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "Couldn't decrypt CMS enveloped data in client request" ) );

	/* Finally, import the request as a PKCS #10 request */
	setMessageCreateObjectIndirectInfo( &createInfo,
								sessionInfoPtr->receiveBuffer, dataLength,
								CRYPT_CERTTYPE_CERTREQUEST );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "Invalid PKCS #10 request in client request" ) );
	sessionInfoPtr->iCertRequest = createInfo.cryptHandle;
	return( CRYPT_OK );
	}

/* Create an SCEP response message */

int createScepResponse( SESSION_INFO *sessionInfoPtr,
						SCEP_PROTOCOL_INFO *protocolInfo )
	{
	CRYPT_CERTIFICATE iCmsAttributes;
	MESSAGE_DATA msgData;
	int dataLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) ) );

	/* Extract the response data into the session buffer */
	setMessageData( &msgData, sessionInfoPtr->receiveBuffer,
					sessionInfoPtr->receiveBufSize );
	status = krnlSendMessage( sessionInfoPtr->iCertResponse,
							  IMESSAGE_CRT_EXPORT, &msgData,
							  CRYPT_CERTFORMAT_CERTCHAIN );
	if( cryptStatusError( status ) )
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't get PKCS #7 cert chain from SCEP response "
				  "object" ) );
	DEBUG_DUMP( "scep_sresp0", sessionInfoPtr->receiveBuffer, msgData.length );

	/* Phase 1: Encrypt the data using the client's key */
	status = envelopeWrap( sessionInfoPtr->receiveBuffer, msgData.length,
						   sessionInfoPtr->receiveBuffer, &dataLength, 
						   sessionInfoPtr->receiveBufSize,
						   CRYPT_FORMAT_CMS, CRYPT_CONTENT_NONE, 
						   protocolInfo->iScepCert );
	if( cryptStatusError( status ) )
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't encrypt response data with client key" ) );
	DEBUG_DUMP( "scep_sresp1", sessionInfoPtr->receiveBuffer, dataLength );

	/* Create the SCEP signing attributes */
	status = createScepAttributes( sessionInfoPtr, protocolInfo,  
								   &iCmsAttributes, FALSE, CRYPT_OK );
	if( cryptStatusError( status ) )
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't create SCEP response signing attributes" ) );

	/* Phase 2: Sign the data using the CA key and SCEP attributes */
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
				  "Couldn't sign response data with CA key" ) );
	DEBUG_DUMP( "scep_sresp2", sessionInfoPtr->receiveBuffer, 
				sessionInfoPtr->receiveBufEnd );
	return( CRYPT_OK );
	}
#endif /* USE_SCEP */
