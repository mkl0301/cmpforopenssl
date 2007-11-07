/****************************************************************************
*																			*
*						  cryptlib HTTP Write Routines						*
*						Copyright Peter Gutmann 1998-2006					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "http.h"
#else
  #include "crypt.h"
  #include "io/http.h"
#endif /* Compiler-specific includes */

#ifdef USE_HTTP

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Encode a string as per RFC 1866 (although the list of characters that 
   need to be escaped is itself given in RFC 2396).  Characters that are 
   permitted/not permitted are:

	 !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
	x..x.xx....x...xxxxxxxxxxxx.xxxxx

   Because of this it's easier to check for the most likely permitted
   characters (alphanumerics), and then to check for any special-case
   chars */

static void encodeRFC1866( STREAM *headerStream, const char *string, 
						   const int stringLength )
	{
	static const char allowedChars[] = "$-_.!*'(),\"/";	/* RFC 1738 + '/' */
	int index = 0;

	assert( isWritePtr( headerStream, sizeof( STREAM ) ) );
	assert( isReadPtr( string, stringLength ) );

	while( index < stringLength )
		{
		const int ch = string[ index++ ];
		int i;

		if( isAlnum( ch ) )
			{
			sputc( headerStream, ch );
			continue;
			}
		if( ch == ' ' )
			{
			sputc( headerStream, '+' );
			continue;
			}
		for( i = 0; allowedChars[ i ] != '\0' && ch != allowedChars[ i ] && \
					i < FAILSAFE_ARRAYSIZE( allowedChars, char ) + 1; i++ );
		if( i >= FAILSAFE_ARRAYSIZE( allowedChars, char ) + 1 )
			retIntError_Void();
		if( allowedChars[ i ] != '\0' )
			/* It's in the allowed-chars list, output it verbatim */
			sputc( headerStream, ch );
		else
			{
			char escapeString[ 16 ];
			int escapeStringLen;

			/* It's a special char, escape it */
			escapeStringLen = sprintf_s( escapeString, 8, "%%%02X", ch );
			swrite( headerStream, escapeString, escapeStringLen );
			}
		}
	}

/* If we time out when sending HTTP header data this would usually be 
   reported as a CRYPT_ERROR_TIMEOUT by the lower-level network I/O 
   routines, however due to the multiple layers of I/O and special case 
   timeout handling when (for example) a cryptlib transport session is 
   layered over the network I/O layer and the fact that to the caller the
   write of the out-of-band HTTP header data (which can occur as part of a 
   standard HTTP write, but also in a GET or when sending an error
   response) is invisible, we have to perform an explicit check to make 
   sure that we sent everything */

int sendHTTPData( STREAM *stream, void *buffer, const int length,
				  const int flags )
	{
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( buffer, length ) );

	status = stream->bufferedTransportWriteFunction( stream, buffer, length, 
													 flags );
	if( cryptStatusError( status ) )
		{
		/* Network-level error, the lower-level layers have reported the 
		   error details */
		return( status );
		}
	if( status < length )
		{
		/* The write timed out, convert the incomplete HTTP header write to 
		   the appropriate timeout error */
		retExt( CRYPT_ERROR_TIMEOUT, 
				( CRYPT_ERROR_TIMEOUT, STREAM_ERRINFO, 
				  "HTTP write timed out before all data could be written" ) );
		}
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Write Request/Response Header					*
*																			*
****************************************************************************/

/* Write an HTTP request header */

int writeRequestHeader( STREAM *stream, const HTTP_URI_INFO *httpReqInfo,
						const char *contentType, const int contentTypeLen,
						const int contentLength )
	{
	STREAM headerStream;
	char headerBuffer[ HTTP_LINEBUF_SIZE + 8 ];
	const int transportFlag = ( contentLength > 0 ) ? TRANSPORT_FLAG_NONE : \
													  TRANSPORT_FLAG_FLUSH;
	int headerLength;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( ( httpReqInfo == NULL ) || \
			isReadPtr( httpReqInfo, sizeof( HTTP_URI_INFO * ) ) );
	assert( ( contentLength == 0 && contentType == NULL && \
			  contentTypeLen == 0 ) || \
			( contentLength >= 1 && isReadPtr( contentType, \
											   contentTypeLen ) ) );
	assert( ( httpReqInfo == NULL ) || \
			( httpReqInfo->attributeLen == 0 && \
			  httpReqInfo->valueLen == 0 ) || \
			( httpReqInfo->attributeLen > 0 && \
			  httpReqInfo->valueLen > 0 ) );

	sMemOpen( &headerStream, headerBuffer, HTTP_LINEBUF_SIZE );
	if( stream->nFlags & STREAM_NFLAG_HTTPTUNNEL )
		swrite( &headerStream, "CONNECT ", 8 );
	else
		if( contentLength > 0 )
			swrite( &headerStream, "POST ", 5 );
		else
			swrite( &headerStream, "GET ", 4 );
	if( stream->nFlags & ( STREAM_NFLAG_HTTPPROXY | STREAM_NFLAG_HTTPTUNNEL ) )
		{
		/* If we're going through an HTTP proxy/tunnel, send an absolute URL 
		   rather than just the relative location */
		if( stream->nFlags & STREAM_NFLAG_HTTPPROXY )
			swrite( &headerStream, "http://", 7 );
		swrite( &headerStream, stream->host, stream->hostLen );
		if( stream->port != 80 )
			{
			char portString[ 16 + 8 ];
			int portStringLength;

			portStringLength = sprintf_s( portString, 16, ":%d", 
										  stream->port );
			swrite( &headerStream, portString, portStringLength );
			}
		}
	if( !( stream->nFlags & STREAM_NFLAG_HTTPTUNNEL ) )
		{
		if( stream->path != NULL && stream->pathLen > 0 )
			swrite( &headerStream, stream->path, stream->pathLen );
		else
			sputc( &headerStream, '/' );
		}
	if( httpReqInfo != NULL )
		{
		if( httpReqInfo->attributeLen > 0 && httpReqInfo->valueLen > 0 )
			{
			sputc( &headerStream, '?' );
			swrite( &headerStream, httpReqInfo->attribute, 
					httpReqInfo->attributeLen );
			sputc( &headerStream, '=' );
			encodeRFC1866( &headerStream, httpReqInfo->value, 
						   httpReqInfo->valueLen );
			}
		if( httpReqInfo->extraDataLen > 0 )
			{
			sputc( &headerStream, '&' );
			swrite( &headerStream, httpReqInfo->extraData, 
					httpReqInfo->extraDataLen );
			}
		}
	if( isHTTP10( stream ) )
		swrite( &headerStream, " HTTP/1.0\r\n", 11 );
	else
		{
		swrite( &headerStream, " HTTP/1.1\r\nHost: ", 17 );
		swrite( &headerStream, stream->host, stream->hostLen );
		swrite( &headerStream, "\r\n", 2 );
		if( stream->nFlags & STREAM_NFLAG_LASTMSG )
			swrite( &headerStream, "Connection: close\r\n", 19 );
		}
	if( contentLength > 0 )
		{
		char lengthString[ 8 + 8 ];
		int lengthStringLength;

		swrite( &headerStream, "Content-Type: ", 14 );
		swrite( &headerStream, contentType, contentTypeLen );
		swrite( &headerStream, "\r\nContent-Length: ", 18 );
		lengthStringLength = sprintf_s( lengthString, 8, "%d", 
										contentLength );
		swrite( &headerStream, lengthString, lengthStringLength );
		swrite( &headerStream, "\r\nCache-Control: no-cache\r\n", 27 );
		}
	swrite( &headerStream, "\r\n", 2 );
	headerLength = stell( &headerStream );
	assert( sStatusOK( &headerStream ) );
	sMemDisconnect( &headerStream );
	return( sendHTTPData( stream, headerBuffer, headerLength, 
						  transportFlag ) );
	}

/* Write an HTTP response header */

static int writeResponseHeader( STREAM *stream, const char *contentType, 
								const int contentTypeLen, 
								const int contentLength )
	{
	STREAM headerStream;
	char headerBuffer[ HTTP_LINEBUF_SIZE + 8 ], lengthString[ 8 + 8 ];
	int headerLength, lengthStringLength;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( contentType, contentTypeLen ) );
	assert( contentLength > 0 );

	sMemOpen( &headerStream, headerBuffer, HTTP_LINEBUF_SIZE );
	if( isHTTP10( stream ) )
		swrite( &headerStream, "HTTP/1.0 200 OK\r\n", 17 );
	else
		{
		swrite( &headerStream, "HTTP/1.1 200 OK\r\n", 17 );
		if( stream->nFlags & STREAM_NFLAG_LASTMSG )
			swrite( &headerStream, "Connection: close\r\n", 19 );
		}
	swrite( &headerStream, "Content-Type: ", 14 );
	swrite( &headerStream, contentType, contentTypeLen );
	swrite( &headerStream, "\r\nContent-Length: ", 18 );
	lengthStringLength = sprintf_s( lengthString, 8, "%d", 
									contentLength );
	swrite( &headerStream, lengthString, lengthStringLength );
	swrite( &headerStream, "\r\nCache-Control: no-cache\r\n", 27 );
	if( isHTTP10( stream ) )
		swrite( &headerStream, "Pragma: no-cache\r\n", 18 );
	swrite( &headerStream, "\r\n", 2 );
	headerLength = stell( &headerStream );
	assert( sStatusOK( &headerStream ) );
	sMemDisconnect( &headerStream );
	return( sendHTTPData( stream, headerBuffer, headerLength,
						  TRANSPORT_FLAG_NONE ) );
	}

/****************************************************************************
*																			*
*							HTTP Access Functions							*
*																			*
****************************************************************************/

/* Write data to an HTTP stream */

static int writeFunction( STREAM *stream, const void *buffer,
						  const int length )
	{
	HTTP_DATA_INFO *httpDataInfo = ( HTTP_DATA_INFO * ) buffer;
	int status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( buffer, length ) );
	assert( length == sizeof( HTTP_DATA_INFO ) );

	/* Send the out-of-band HTTP header data to the client or server */
	if( stream->nFlags & STREAM_NFLAG_ISSERVER )
		{
		/* If it's an error status response, send the translated error 
		   status and exit */
		if( cryptStatusError( httpDataInfo->reqStatus ) )
			{
			char headerBuffer[ HTTP_LINEBUF_SIZE + 8 ];

			status = sendHTTPError( stream, headerBuffer, HTTP_LINEBUF_SIZE,
						( httpDataInfo->reqStatus == CRYPT_ERROR_NOTFOUND ) ? \
							404 : \
						( httpDataInfo->reqStatus == CRYPT_ERROR_PERMISSION ) ? \
							401 : 400 );
			return( cryptStatusError( status ) ? status : length );
			}

		status = writeResponseHeader( stream, httpDataInfo->contentType,
									  httpDataInfo->contentTypeLen,
									  httpDataInfo->bufSize );
		}
	else
		{
		assert( ( stream->nFlags & STREAM_NFLAG_HTTPTUNNEL ) || \
				httpDataInfo->contentTypeLen > 0 );
		assert( !( ( stream->nFlags & STREAM_NFLAG_HTTPPROXY ) && 
				   ( stream->nFlags & STREAM_NFLAG_HTTPTUNNEL ) ) );
		assert( stream->host != NULL && stream->hostLen > 0 );

		status = writeRequestHeader( stream, httpDataInfo->reqInfo, 
									 httpDataInfo->contentType,
									 httpDataInfo->contentTypeLen,
									 httpDataInfo->bufSize );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Send the payload data to the client/server */
	httpDataInfo->bytesTransferred = status = \
		stream->bufferedTransportWriteFunction( stream, httpDataInfo->buffer, 
												httpDataInfo->bufSize,
												TRANSPORT_FLAG_FLUSH );
	return( cryptStatusError( status ) ? status : length );
	}

void setStreamLayerHTTPwrite( STREAM *stream )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	/* Set the remaining access method pointers */
	stream->writeFunction = writeFunction;
	}
#endif /* USE_HTTP */
