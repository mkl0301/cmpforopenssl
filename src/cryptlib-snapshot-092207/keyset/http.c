/****************************************************************************
*																			*
*						 cryptlib HTTP Mapping Routines						*
*						Copyright Peter Gutmann 1998-2004					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "asn1.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
  #include "misc/asn1.h"
#endif /* Compiler-specific includes */

#ifdef USE_HTTP

/* The default size of the HTTP read buffer.  This is adjusted dynamically if
   the data being read won't fit (e.g. large CRLs).  The default size is 
   fine for certs */

#define HTTP_BUFFER_SIZE	4096

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Set up key information for a query */

static const char *getKeyName( const CRYPT_KEYID_TYPE keyIDtype )
	{
	switch( keyIDtype )
		{
		case CRYPT_KEYID_NAME:
			return( "name" );

		case CRYPT_KEYID_URI:
			return( "uri" );

		case CRYPT_IKEYID_KEYID:
			return( "sKIDHash" );

		case CRYPT_IKEYID_ISSUERID:
			return( "iAndSHash" );

		case CRYPT_IKEYID_CERTID:
			return( "certHash" );
		}

	assert( NOTREACHED );
	return( NULL );			/* Get rid of compiler warning */
	}

/****************************************************************************
*																			*
*						 		Keyset Access Routines						*
*																			*
****************************************************************************/

/* Retrieve a cert/CRL from an HTTP server, either as a flat URL if the key
   name is "[none]" or as a cert store */

static int getItemFunction( KEYSET_INFO *keysetInfo,
							CRYPT_HANDLE *iCryptHandle,
							const KEYMGMT_ITEM_TYPE itemType,
							const CRYPT_KEYID_TYPE keyIDtype,
							const void *keyID,  const int keyIDlength,
							void *auxInfo, int *auxInfoLength,
							const int flags )
	{
	HTTP_INFO *httpInfo = keysetInfo->keysetHTTP;
	HTTP_DATA_INFO httpDataInfo;
	HTTP_URI_INFO httpReqInfo;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	BOOLEAN hasExplicitKeyID = FALSE;
	int length, status;

	assert( itemType == KEYMGMT_ITEM_PUBLICKEY );
	assert( keyIDtype == CRYPT_KEYID_NAME || keyIDtype == CRYPT_KEYID_URI );
	assert( auxInfo == NULL ); assert( *auxInfoLength == 0 );

	/* Set the keyID as the query portion of the URL if necessary */
	if( keyIDlength != 6 || strCompare( keyID, "[none]", 6 ) )
		{
		/* Make sure that the keyID is of an appropriate size */
		if( keyIDlength > CRYPT_MAX_TEXTSIZE )
			return( CRYPT_ARGERROR_STR1 );

		hasExplicitKeyID = TRUE;
		}

	/* If we haven't allocated a buffer for the data yet, do so now */
	if( keysetInfo->keyData == NULL )
		{
		/* Allocate the initial I/O buffer */
		if( ( keysetInfo->keyData = clAlloc( "getItemFunction", \
											 HTTP_BUFFER_SIZE ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		keysetInfo->keyDataSize = HTTP_BUFFER_SIZE;
		}
	httpInfo->bufPos = 0;

	/* Set up the HTTP request information */
	if( hasExplicitKeyID )
		{
		const char *keyName = getKeyName( keyIDtype );
		const int keyNameLen = strlen( keyName );

		initHttpDataInfoEx( &httpDataInfo, keysetInfo->keyData,
							keysetInfo->keyDataSize, &httpReqInfo );
		memcpy( httpReqInfo.attribute, keyName, keyNameLen );
		httpReqInfo.attributeLen = keyNameLen;
		memcpy( httpReqInfo.value, keyID, keyIDlength );
		httpReqInfo.valueLen = keyIDlength;
		}
	else
		{
		initHttpDataInfo( &httpDataInfo, keysetInfo->keyData,
						  keysetInfo->keyDataSize );
		}

	/* Send the request to the server.  Since we don't know the size of the 
	   data being read in advance we have to tell the stream I/O code to 
	   adjust the read buffer size if necessary */
	httpDataInfo.flags |= HTTP_FLAG_DYNAMICBUFFER;
	status = sread( &httpInfo->stream, &httpDataInfo,
					sizeof( HTTP_DATA_INFO ) );
	if( httpDataInfo.flags & HTTP_FLAG_BUFFERRESIZED )
		{
		/* The read buffer may have been adjusted even though an error code
		   was returned from a later operation, so we process the resized 
		   flag before we check for an error status */
		keysetInfo->keyData = httpDataInfo.buffer;
		keysetInfo->keyDataSize = httpDataInfo.bufSize;
		}
	if( cryptStatusError( status ) )
		{
		sNetGetErrorInfo( &httpInfo->stream, &keysetInfo->errorInfo );

		/* If it's a not-found error, this is non-fatal condition (it just
		   means that the requested cert wasn't found, but doesn't prevent 
		   us from submitting further requests), so we clear the stream 
		   status to allow further queries */
		if( status == CRYPT_ERROR_NOTFOUND )
			sClearError( &httpInfo->stream );
		return( status );
		}

	/* Find out how much data we got and perform a general check that
	   everything is OK.  We rely on this rather than the read byte count
	   since checking the ASN.1, which is the data that will actually be
	   processed, avoids any vagaries of server implementation oddities,
	   which may send extra null bytes or CRLFs or do who knows what else */
	length = getLongObjectLength( keysetInfo->keyData, 
								  httpDataInfo.bytesAvail );
	if( cryptStatusError( length ) )
		return( length );

	/* Create a certificate object from the returned data */
	setMessageCreateObjectIndirectInfo( &createInfo, keysetInfo->keyData,
										length, CRYPT_CERTTYPE_NONE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		*iCryptHandle = createInfo.cryptHandle;
	return( status );
	}

/* Prepare to open a connection to an HTTP server */

static int initFunction( KEYSET_INFO *keysetInfo, const char *name,
						 const int nameLength,
						 const CRYPT_KEYOPT_TYPE options )
	{
	HTTP_INFO *httpInfo = keysetInfo->keysetHTTP;
	NET_CONNECT_INFO connectInfo;
	int status;

	/* Set up the HTTP connection */
	initNetConnectInfo( &connectInfo, keysetInfo->ownerHandle, CRYPT_ERROR, 
						CRYPT_ERROR, NET_OPTION_HOSTNAME );
	connectInfo.name = name;
	connectInfo.nameLength = nameLength;
	connectInfo.port = 80;
	status = sNetConnect( &httpInfo->stream, STREAM_PROTOCOL_HTTP, 
						  &connectInfo, &keysetInfo->errorInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Since this isn't a general-purpose HTTP stream (of the kind used for 
	   the HTTP-as-a-substrate PKI protocols) but is only being used for 
	   HTTP 'GET' operations, we restrict the usage to just this operation */
	sioctl( &httpInfo->stream, STREAM_IOCTL_HTTPREQTYPES, NULL, 
			STREAM_NFLAG_HTTPGET );
	return( CRYPT_OK );
	}

/* Close a previously-opened HTTP connection */

static int shutdownFunction( KEYSET_INFO *keysetInfo )
	{
	HTTP_INFO *httpInfo = keysetInfo->keysetHTTP;

	sNetDisconnect( &httpInfo->stream );
	if( keysetInfo->keyData != NULL )
		{
		zeroise( keysetInfo->keyData, keysetInfo->keyDataSize );
		clFree( "getItemFunction", keysetInfo->keyData );
		keysetInfo->keyData = NULL;
		}

	return( CRYPT_OK );
	}

int setAccessMethodHTTP( KEYSET_INFO *keysetInfo )
	{
	/* Set the access method pointers */
	keysetInfo->initFunction = initFunction;
	keysetInfo->shutdownFunction = shutdownFunction;
	keysetInfo->getItemFunction = getItemFunction;

	return( CRYPT_OK );
	}
#endif /* USE_HTTP */
