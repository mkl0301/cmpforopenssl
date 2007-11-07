/****************************************************************************
*																			*
*					cryptlib HTTP Certstore Session Management				*
*						Copyright Peter Gutmann 1998-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc_rw.h"
  #include "session.h"
  #include "certstore.h"
#else
  #include "crypt.h"
  #include "misc/misc_rw.h"
  #include "session/session.h"
  #include "session/certstore.h"
#endif /* Compiler-specific includes */

/* SCEP's bolted-on HTTP query mechanism requires that we use the HTTP 
   certstore access routines to return responses to certificate queries,
   so we enable the use of this code if either certstores or SCEP are
   used */

#if defined( USE_CERTSTORE ) || defined( USE_SCEP )

/* Table mapping a query submitted as an HTTP GET to a cryptlib-internal 
   keyset query.  Note that the first letter must be lowercase for the
   case-insensitive quick match */

static const CERTSTORE_READ_INFO certstoreReadInfo[] = {
	{ "certHash", 8, CRYPT_IKEYID_CERTID, CERTSTORE_FLAG_BASE64 },
	{ "name", 4, CRYPT_KEYID_NAME, CERTSTORE_FLAG_NONE },
	{ "uri", 3, CRYPT_KEYID_URI, CERTSTORE_FLAG_NONE },
	{ "email", 5, CRYPT_KEYID_URI, CERTSTORE_FLAG_NONE },
	{ "sHash", 5, CRYPT_IKEYID_ISSUERID, CERTSTORE_FLAG_BASE64 },
	{ "iHash", 5, CRYPT_IKEYID_ISSUERID, CERTSTORE_FLAG_BASE64 },
	{ "iAndSHash", 9, CRYPT_IKEYID_ISSUERANDSERIALNUMBER, CERTSTORE_FLAG_BASE64 },
	{ "sKIDHash", 8, CRYPT_IKEYID_KEYID, CERTSTORE_FLAG_BASE64 },
	{ NULL, CRYPT_KEYID_NONE, CERTSTORE_FLAG_NONE },
	{ NULL, CRYPT_KEYID_NONE, CERTSTORE_FLAG_NONE }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Process a cert query and return the requested certificate */

int processCertQuery( SESSION_INFO *sessionInfoPtr,	
					  const HTTP_URI_INFO *httpReqInfo,
					  const CERTSTORE_READ_INFO *queryReqInfo,
					  const int queryReqInfoSize,
					  int *attributeID, void *attribute, 
					  const int attributeMaxLen, int *attributeLen,
					  char *queryText, const int queryTextMaxLen )
	{
	const CERTSTORE_READ_INFO *queryInfoPtr = NULL;
	const char firstChar = toLower( httpReqInfo->attribute[ 0 ] );
	int length, i;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isReadPtr( httpReqInfo, sizeof( HTTP_URI_INFO ) ) );
	assert( isReadPtr( queryReqInfo, 
					   sizeof( CERTSTORE_READ_INFO ) * queryReqInfoSize ) );
	assert( isWritePtr( attributeID, sizeof( int ) ) );
	assert( ( attribute == NULL && attributeMaxLen == 0 && \
			  attributeLen == NULL ) || \
			( isWritePtr( attribute, attributeMaxLen ) && \
			  isWritePtr( attributeLen, sizeof( int ) ) ) );
	assert( isWritePtr( queryText, queryTextMaxLen ) );

	/* Clear return values */
	*attributeID = CRYPT_ERROR;
	if( attribute != NULL )
		{
		memset( attribute, 0, attributeMaxLen );
		*attributeLen = 0;
		}
	memset( queryText, 0, queryTextMaxLen );

	/* Save a copy of the query value for use in reporting errors */
	length = min( httpReqInfo->valueLen, queryTextMaxLen );
	memcpy( queryText, httpReqInfo->value, length );
	sanitiseString( queryText, length, httpReqInfo->valueLen );

	/* Convert the search attribute type into a cryptlib key ID */
	for( i = 0; queryReqInfo[ i ].attrName != NULL && \
				i < queryReqInfoSize; i++ )
		{
		if( httpReqInfo->attributeLen == queryReqInfo[ i ].attrNameLen && \
			queryReqInfo[ i ].attrName[ 0 ] == firstChar && \
			!strCompare( httpReqInfo->attribute, \
						 queryReqInfo[ i ].attrName, \
						 queryReqInfo[ i ].attrNameLen ) )
			{
			queryInfoPtr = &queryReqInfo[ i ];
			break;
			}
		}
	if( i >= queryReqInfoSize )
		retIntError();
	if( queryInfoPtr == NULL )
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid certificate query attribute '%s'", queryText ) );

	/* We've got a valid attribute, let the caller know which one it is.  If
	   that's all the information that they're after, we're done */
	*attributeID = queryInfoPtr->attrID;
	if( attribute == NULL )
		return( CRYPT_OK );

	/* If the query data wasn't encoded in any way, we're done */
	if( !( queryInfoPtr->flags & CERTSTORE_FLAG_BASE64 ) )
		{
		memcpy( attribute, httpReqInfo->value, httpReqInfo->valueLen );
		*attributeLen = httpReqInfo->valueLen;

		return( CRYPT_OK );
		}

	/* The value was base64-encoded in transit, decode it to get the actual 
	   query data */
	length = base64decode( attribute, attributeMaxLen, httpReqInfo->value, 
						   httpReqInfo->valueLen, CRYPT_CERTFORMAT_NONE );
	if( cryptStatusError( length ) )
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, SESSION_ERRINFO, 
				  "Invalid base64-encoded query value '%s'", queryText ) );
	*attributeLen = length;

	return( CRYPT_OK );
	}

/* Send an HTTP error response to the client (the status value is mapped at 
   the HTTP layer to an appropriate HTTP response).  We don't return a 
   status from this since the caller already has an error status available */

void sendCertErrorResponse( SESSION_INFO *sessionInfoPtr, 
							const int errorStatus )
	{
	HTTP_DATA_INFO httpDataInfo;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( cryptStatusError( errorStatus ) );

	initHttpDataInfo( &httpDataInfo, sessionInfoPtr->receiveBuffer,
					  sessionInfoPtr->receiveBufSize );
	httpDataInfo.reqStatus = errorStatus;
	swrite( &sessionInfoPtr->stream, &httpDataInfo, 
			sizeof( HTTP_DATA_INFO ) );
	}

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Exchange data with an HTTP client */

static int serverTransact( SESSION_INFO *sessionInfoPtr )
	{
	HTTP_DATA_INFO httpDataInfo;
	HTTP_URI_INFO httpReqInfo;
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	MESSAGE_DATA msgData;
	BYTE keyID[ CRYPT_MAX_TEXTSIZE + 8 ];
	char queryErrorText[ CRYPT_MAX_TEXTSIZE + 8 ];
	int keyIDtype, keyIDLen, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	sioctl( &sessionInfoPtr->stream, STREAM_IOCTL_HTTPREQTYPES, NULL, 
			STREAM_NFLAG_HTTPGET );

	/* Read the request data from the client.  We do a direct read rather 
	   than using readPkiDatagram() since we're reading an idempotent HTTP 
	   GET request and not a PKI datagram submitted via an HTTP POST */
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

	/* Convert the cert query into a certstore search key */
	status = processCertQuery( sessionInfoPtr, &httpReqInfo, 
							   certstoreReadInfo,
							   FAILSAFE_ARRAYSIZE( certstoreReadInfo, \
												   CERTSTORE_READ_INFO ),
							   &keyIDtype, keyID, CRYPT_MAX_TEXTSIZE, 
							   &keyIDLen, queryErrorText, 
							   CRYPT_MAX_TEXTSIZE );
	if( cryptStatusError( status ) )
		{
		sendCertErrorResponse( sessionInfoPtr, status );
		return( status );
		}

	/* Try and fetch the requested cert.  Note that this is somewhat 
	   suboptimal since we have to instantiate the cert only to destroy it
	   again immediately afterwards as soon as we've exported the cert data,
	   for a proper high-performance implementation the server would query
	   the cert database directly and send the stored encoded value to the
	   client */
	setMessageKeymgmtInfo( &getkeyInfo, keyIDtype, keyID, keyIDLen, 
						   NULL, 0, KEYMGMT_FLAG_NONE );
	status = krnlSendMessage( sessionInfoPtr->cryptKeyset,
							  IMESSAGE_KEY_GETKEY, &getkeyInfo, 
							  KEYMGMT_ITEM_PUBLICKEY );
	if( cryptStatusError( status ) )
		{
		/* Not finding a cert in response to a request isn't a real error so
		   all we do is return a warning to the caller */
		sendCertErrorResponse( sessionInfoPtr, status );
		retExt( CRYPT_OK, 
				( CRYPT_OK, SESSION_ERRINFO, 
				  "Warning: Couldn't find certificate for '%s'", 
				  queryErrorText ) );
		}

	/* Write the cert to the session buffer */
	setMessageData( &msgData, sessionInfoPtr->receiveBuffer,
					sessionInfoPtr->receiveBufSize );
	status = krnlSendMessage( getkeyInfo.cryptHandle, IMESSAGE_CRT_EXPORT, 
							  &msgData, CRYPT_CERTFORMAT_CERTIFICATE );
	krnlSendNotifier( getkeyInfo.cryptHandle, IMESSAGE_DESTROY );
	if( cryptStatusError( status ) )
		{
		sendCertErrorResponse( sessionInfoPtr, status );
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "Couldn't export requested certificate for '%s'", 
				  queryErrorText ) );
		}
	sessionInfoPtr->receiveBufEnd = msgData.length;

	/* Send the result to the client */
	return( writePkiDatagram( sessionInfoPtr, CERTSTORE_CONTENT_TYPE ) );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

int setAccessMethodCertstore( SESSION_INFO *sessionInfoPtr )
	{
	static const PROTOCOL_INFO protocolInfo = {
		/* General session information */
		TRUE,						/* Request-response protocol */
		SESSION_ISHTTPTRANSPORT,	/* Flags */
		80,							/* HTTP port */
		0,							/* Client flags */
		SESSION_NEEDS_KEYSET,		/* Server flags */
		1, 1, 1						/* Version 1 */
	
		/* Protocol-specific information */
		};

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Set the access method pointers.  The client-side implementation is 
	  just a standard HTTP fetch so there's no explicit certstore client
	  implementation */
	sessionInfoPtr->protocolInfo = &protocolInfo;
	if( isServer( sessionInfoPtr ) )
		sessionInfoPtr->transactFunction = serverTransact;
	else
		return( CRYPT_ERROR_NOTAVAIL );

	return( CRYPT_OK );
	}
#endif /* USE_CERTSTORE || USE_SCEP */
