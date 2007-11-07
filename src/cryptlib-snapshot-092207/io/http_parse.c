/****************************************************************************
*																			*
*						cryptlib HTTP Parsing Routines						*
*					  Copyright Peter Gutmann 1998-2007						*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "http.h"
  #include "misc_rw.h"
#else
  #include "crypt.h"
  #include "io/http.h"
  #include "misc/misc_rw.h"
#endif /* Compiler-specific includes */

#ifdef USE_HTTP

/* The various HTTP header types that we can process */

typedef enum { HTTP_HEADER_NONE, HTTP_HEADER_HOST, HTTP_HEADER_CONTENT_LENGTH,
			   HTTP_HEADER_CONTENT_TYPE, HTTP_HEADER_TRANSFER_ENCODING,
			   HTTP_HEADER_CONTENT_ENCODING,
			   HTTP_HEADER_CONTENT_TRANSFER_ENCODING, HTTP_HEADER_TRAILER,
			   HTTP_HEADER_CONNECTION, HTTP_HEADER_WARNING, 
			   HTTP_HEADER_LOCATION, HTTP_HEADER_EXPECT, HTTP_HEADER_LAST
			 } HTTP_HEADER_TYPE;

/* HTTP header parsing information.  Note that the first letter of the
   header string must be uppercase for the case-insensitive quick match */

typedef struct {
	const char FAR_BSS *headerString;/* Header string */
	const int headerStringLen;		/* Length of header string */
	const HTTP_HEADER_TYPE headerType;	/* Type corresponding to header string */
	} HTTP_HEADER_PARSE_INFO;

static const HTTP_HEADER_PARSE_INFO FAR_BSS httpHeaderParseInfo[] = {
	{ "Host:", 5, HTTP_HEADER_HOST },
	{ "Content-Length:", 15, HTTP_HEADER_CONTENT_LENGTH },
	{ "Content-Type:", 13, HTTP_HEADER_CONTENT_TYPE },
	{ "Transfer-Encoding:", 18, HTTP_HEADER_TRANSFER_ENCODING },
	{ "Content-Encoding:", 17, HTTP_HEADER_CONTENT_ENCODING },
	{ "Content-Transfer-Encoding:", 26, HTTP_HEADER_CONTENT_TRANSFER_ENCODING },
	{ "Trailer:", 8, HTTP_HEADER_TRAILER },
	{ "Connection:", 11, HTTP_HEADER_CONNECTION },
	{ "NnCoection:", 11, HTTP_HEADER_CONNECTION },
	{ "Cneonction:", 11, HTTP_HEADER_CONNECTION },
		/* The bizarre spellings are for buggy NetApp NetCache servers,
		   which unfortunately are widespread enough that we need to provide
		   special-case handling for them.  For the second mis-spelling we
		   have to capitalise the first letter for our use since we compare
		   the uppercase form for a quick match */
	{ "Warning:", 8, HTTP_HEADER_WARNING },
	{ "Location:", 9, HTTP_HEADER_LOCATION },
	{ "Expect:", 7, HTTP_HEADER_EXPECT },
	{ NULL, 0, HTTP_HEADER_NONE }
	};

/* HTTP error/warning messages.  The mapped status for 30x redirects is
   somewhat special-case, see the comment in readResponseHeader() for
   details.  This table also contains known non-HTTP codes in the
   expectation that, when used as a general-purpose substrate, it'll be
   pressed into use in all sorts of situations */

typedef struct {
	const int httpStatus;			/* Numeric status value */
	const char FAR_BSS *httpStatusString;	/* String status value */
	const char FAR_BSS *httpErrorString;	/* Text description of status */
	const int status;				/* Equivalent cryptlib status */
	} HTTP_STATUS_INFO;

static const HTTP_STATUS_INFO FAR_BSS httpStatusInfo[] = {
	{ 100, "100", "Continue", OK_SPECIAL },
	{ 101, "101", "Switching Protocols", CRYPT_ERROR_READ },
	{ 110, "110", "Warning: Response is stale", CRYPT_OK },
	{ 111, "111", "Warning: Revalidation failed", CRYPT_OK },
	{ 112, "112", "Warning: Disconnected operation", CRYPT_OK },
	{ 113, "113", "Warning: Heuristic expiration", CRYPT_OK },
	{ 199, "199", "Warning: Miscellaneous warning", CRYPT_OK },
	{ 200, "200", "OK", CRYPT_OK },
	{ 201, "201", "Created", CRYPT_ERROR_READ },
	{ 202, "202", "Accepted", CRYPT_ERROR_READ },
	{ 203, "203", "Non-Authoritative Information", CRYPT_OK },
	{ 204, "204", "No Content", CRYPT_ERROR_READ },
	{ 205, "205", "Reset Content", CRYPT_ERROR_READ },
	{ 206, "206", "Partial Content", CRYPT_ERROR_READ },
	{ 214, "214", "Warning: Transformation applied", CRYPT_OK },
	{ 250, "250", "RTSP: Low on Storage Space", CRYPT_OK },
	{ 299, "299", "Warning: Miscellaneous persistent warning", CRYPT_OK },
	{ 300, "300", "Multiple Choices", CRYPT_ERROR_READ },
	{ 301, "301", "Moved Permanently", OK_SPECIAL },
	{ 302, "302", "Moved Temporarily/Found", OK_SPECIAL },
	{ 303, "303", "See Other", CRYPT_ERROR_READ },
	{ 304, "304", "Not Modified", CRYPT_ERROR_READ },
	{ 305, "305", "Use Proxy", CRYPT_ERROR_READ },
	{ 306, "306", "Unused/obsolete", CRYPT_ERROR_READ },
	{ 307, "307", "Temporary Redirect", OK_SPECIAL },
	{ 400, "400", "Bad Request", CRYPT_ERROR_READ },
	{ 401, "401", "Unauthorized", CRYPT_ERROR_PERMISSION },
	{ 402, "402", "Payment Required", CRYPT_ERROR_READ },
	{ 403, "403", "Forbidden", CRYPT_ERROR_PERMISSION },
	{ 404, "404", "Not Found", CRYPT_ERROR_NOTFOUND },
	{ 405, "405", "Method Not Allowed", CRYPT_ERROR_NOTAVAIL },
	{ 406, "406", "Not Acceptable", CRYPT_ERROR_PERMISSION },
	{ 407, "407", "Proxy Authentication Required", CRYPT_ERROR_PERMISSION },
	{ 408, "408", "Request Time-out", CRYPT_ERROR_READ },
	{ 409, "409", "Conflict", CRYPT_ERROR_READ },
	{ 410, "410", "Gone", CRYPT_ERROR_NOTFOUND },
	{ 411, "411", "Length Required", CRYPT_ERROR_READ },
	{ 412, "412", "Precondition Failed", CRYPT_ERROR_READ },
	{ 413, "413", "Request Entity too Large", CRYPT_ERROR_OVERFLOW },
	{ 414, "414", "Request-URI too Large", CRYPT_ERROR_OVERFLOW },
	{ 415, "415", "Unsupported Media Type", CRYPT_ERROR_READ },
	{ 416, "416", "Requested range not satisfiable", CRYPT_ERROR_READ },
	{ 417, "417", "Expectation Failed", CRYPT_ERROR_READ },
	{ 426, "426", "Upgrade Required", CRYPT_ERROR_READ },
	{ 451, "451", "RTSP: Parameter not Understood", CRYPT_ERROR_BADDATA },
	{ 452, "452", "RTSP: Conference not Found", CRYPT_ERROR_NOTFOUND },
	{ 453, "453", "RTSP: Not enough Bandwidth", CRYPT_ERROR_NOTAVAIL },
	{ 454, "454", "RTSP: Session not Found", CRYPT_ERROR_NOTFOUND },
	{ 455, "455", "RTSP: Method not Valid in this State", CRYPT_ERROR_NOTAVAIL },
	{ 456, "456", "RTSP: Header Field not Valid for Resource", CRYPT_ERROR_NOTAVAIL },
	{ 457, "457", "RTSP: Invalid Range", CRYPT_ERROR_READ },
	{ 458, "458", "RTSP: Parameter is Read-Only", CRYPT_ERROR_PERMISSION },
	{ 459, "459", "RTSP: Aggregate Operation not Allowed", CRYPT_ERROR_PERMISSION },
	{ 460, "460", "RTSP: Only Aggregate Operation Allowed", CRYPT_ERROR_PERMISSION },
	{ 461, "461", "RTSP: Unsupported Transport", CRYPT_ERROR_NOTAVAIL },
	{ 462, "462", "RTSP: Destination Unreachable", CRYPT_ERROR_OPEN },
	{ 500, "500", "Internal Server Error", CRYPT_ERROR_READ },
	{ 501, "501", "Not Implemented", CRYPT_ERROR_NOTAVAIL },
	{ 502, "502", "Bad Gateway", CRYPT_ERROR_READ },
	{ 503, "503", "Service Unavailable", CRYPT_ERROR_NOTAVAIL },
	{ 504, "504", "Gateway Time-out", CRYPT_ERROR_TIMEOUT },
	{ 505, "505", "HTTP Version not supported", CRYPT_ERROR_READ },
	{ 510, "510", "HTTP-Ext: Not Extended", CRYPT_ERROR_READ },
	{ 551, "551", "RTSP: Option not supported", CRYPT_ERROR_READ },
	{ 0, NULL, "Unrecognised HTTP status condition", CRYPT_ERROR_READ },
		{ 0, NULL, "Unrecognised HTTP status condition", CRYPT_ERROR_READ }
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Callback function used by readTextLine() to read characters from a
   stream.  When reading text data over a network we don't know how much
   more data is to come so we have to read a byte at a time looking for an
   EOL.  In addition we can't use the simple optimisation of reading two
   bytes at a time because some servers only send a LF even though the spec
   requires a CRLF.  This is horribly inefficient but is pretty much
   eliminated through the use of opportunistic read-ahead buffering */

static int readCharFunction( void *streamPtr )
	{
	STREAM *stream = streamPtr;
	BYTE ch;
	int status;

	status = stream->bufferedTransportReadFunction( stream, &ch, 1,
													TRANSPORT_FLAG_NONE );
	return( cryptStatusError( status ) ? status : ch );
	}

/* Decode a hex nibble */

static int getNibble( const char srcCh )
	{
	int ch;

	ch = toLower( srcCh );
	if( !isXDigit( ch ) )
		return( CRYPT_ERROR_BADDATA );
	return( ( ch <= '9' ) ? ch - '0' : ch - ( 'a' - 10 ) );
	}

/* Decode an escaped character */

static int getEncodedChar( const char *buffer, const int bufSize )
	{
	int chLo, chHi, ch;

	/* Make sure that there's enough data left to decode the character */
	if( bufSize < 2 )
		return( CRYPT_ERROR_BADDATA );

	/* Recreate the original from the hex value */
	chHi = getNibble( buffer[ 0 ] );
	chLo = getNibble( buffer[ 1 ] );
	if( cryptStatusError( chHi ) || cryptStatusError( chLo ) )
		return( CRYPT_ERROR_BADDATA );
	ch = ( chHi << 4 ) | chLo;

	/* It's a special-case/control character of some kind, report it as an 
	   error.  This gets rid of things like nulls (treated as string 
	   terminators by some functions) and CR/LF line terminators, which can 
	   be embedded into strings to turn a single line of supplied text into 
	   multi-line responses containing user-controlled type : value pairs 
	   (in other words they allow user data to be injected into the control
	   channel) */
	if( !isPrint( ch ) )
		return( CRYPT_ERROR_BADDATA );

	return( ch );
	}

/* Decode a string as per RFC 1866 */

static int decodeRFC1866( char *buffer, const int bufSize )
	{
	int srcIndex = 0, destIndex = 0;

	assert( isWritePtr( buffer, bufSize ) );

	while( srcIndex < bufSize )
		{
		int ch = buffer[ srcIndex++ ];

		/* If it's an escaped character, decode it.  If it's not escaped we 
		   can copy it straight over, the input has already been sanitised 
		   when it was read so there's no need to perform another check 
		   here */
		if( ch == '%' )
			{
			ch = getEncodedChar( buffer + srcIndex, bufSize - srcIndex );
			if( cryptStatusError( ch ) )
				return( ch );
			srcIndex += 2;
			}
		buffer[ destIndex++ ] = ch;
		}

	/* If we've processed an escape sequence (causing the data to change
	   size), tell the caller the new length, otherwise tell them that
	   nothing's changed */
	return( ( destIndex < srcIndex ) ? destIndex : OK_SPECIAL );
	}

/* Convert a hex ASCII string used with chunked encoding into a numeric
   value */

static int getChunkLength( const char *data, const int dataLength )
	{
	int i, chunkLength = 0, length = dataLength;

	assert( isReadPtr( data, dataLength ) );

	/* Chunk size information can have extensions tacked onto it following a
	   ';', strip these before we start */
	for( i = 0; i < length; i++ )
		{
		if( data[ i ] == ';' )
			{
			/* Move back to the end of the string that precedes the ';' */
			while( i > 0 && data[ i - 1 ] == ' ' )
				i--;
			length = i;	/* Adjust length and force loop exit */
			}
		}

	/* The other side shouldn't be sending us more than 64K of data, given
	   that what we're expecting is a short PKI message */
	if( length < 1 || length > 4 )
		return( CRYPT_ERROR_BADDATA );

	/* Walk down the string converting hex characters into their numeric
	   values */
	for( i = 0; i < length; i++ )
		{
		const int ch = getNibble( data[ i ] );

		if( cryptStatusError( ch ) )
			return( CRYPT_ERROR_BADDATA );
		chunkLength = ( chunkLength << 4 ) | ch;
		}
	if( chunkLength < 0 || chunkLength > MAX_INTLENGTH )
		return( CRYPT_ERROR_BADDATA );

	return( chunkLength );
	}

/****************************************************************************
*																			*
*							Error Handling Functions						*
*																			*
****************************************************************************/

/* Exit with extended error information after a readTextLine() call */

int retTextLineError( STREAM *stream, const int status, 
					  const BOOLEAN isTextLineError, const char *format, 
					  const int value )
	{
	/* If the extended error information came up from a lower level than 
	   readCharFunction(), pass it on up to the caller */
	if( !isTextLineError )
		return( status );

	/* Extend the readTextLine()-level error information with higher-level
	   detail.  This allows us to provide a more useful error report 
	   ("Problem with line x") than just the rather low-level view provided 
	   by readTextLine() ("Invalid character 0x8F at position 12").  The
	   argument handling is:

		printf( format, value );
		printf( stream->errorInfo->errorString );

	   so that 'format' has the form 'High-level error %d: ", to which the
	   low-level string is then appended */
	retExtStr( status, 
			   ( status, STREAM_ERRINFO, stream->errorInfo->errorString, 
			     format, value ) );
	}

/* Exit with extended error information relating to header-line parsing */

static int retHeaderError( STREAM *stream, const char *format, 
						   char *strArg, const int strArgLen, 
						   const int lineNo )
	{
	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( format, 4 ) );
	assert( isWritePtr( strArg, strArgLen ) );

	/* Format the error information.  We add two to the line number since 
	   it's zero-based and the header counts as an extra line */
	retExt( CRYPT_ERROR_BADDATA,
			( CRYPT_ERROR_BADDATA, STREAM_ERRINFO, format,
			  sanitiseString( strArg, min( strArgLen, CRYPT_MAX_TEXTSIZE ), 
										   strArgLen ),
			  lineNo + 2 ) );
	}

/* Send an HTTP error message.  This function is somewhat unusually placed
   with the general HTTP parsing functions because it's used by both read 
   and write code but needs access to the HTTP status decoding table, which 
   is part of the parsing code */

int sendHTTPError( STREAM *stream, char *headerBuffer,
				   const int headerBufMaxLen, const int httpStatus )
	{
	STREAM headerStream;
	const char *statusString = "400";
	const char *errorString = "Bad Request";
	int length, i;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( headerBuffer, headerBufMaxLen ) );
	assert( headerBufMaxLen >= 256 );

	/* Find the HTTP error string that corresponds to the HTTP status
	   value */
	for( i = 0; httpStatusInfo[ i ].httpStatus > 0 && \
				httpStatusInfo[ i ].httpStatus != httpStatus && \
				i < FAILSAFE_ARRAYSIZE( httpStatusInfo, HTTP_STATUS_INFO ); 
		 i++ );
	if( i >= FAILSAFE_ARRAYSIZE( httpStatusInfo, HTTP_STATUS_INFO ) )
		retIntError();
	if( httpStatusInfo[ i ].httpStatus > 0 )
		{
		statusString = httpStatusInfo[ i ].httpStatusString;
		errorString = httpStatusInfo[ i ].httpErrorString;
		}

	/* Send the error message to the peer */
	sMemOpen( &headerStream, headerBuffer, headerBufMaxLen );
	swrite( &headerStream, isHTTP10( stream ) ? "HTTP/1.0 " : \
												"HTTP/1.1 ", 9 );
	swrite( &headerStream, statusString, strlen( statusString ) );
	sputc( &headerStream, ' ' );
	swrite( &headerStream, errorString, strlen( errorString ) );
	swrite( &headerStream, "\r\n\r\n", 4 );
	assert( sStatusOK( &headerStream ) );
	length = stell( &headerStream );
	sMemDisconnect( &headerStream );
	return( sendHTTPData( stream, headerBuffer, length,
						  TRANSPORT_FLAG_FLUSH ) );
	}

/****************************************************************************
*																			*
*							URI Parsing Functions							*
*																			*
****************************************************************************/

/* Information needed to parse a URI sub-segment: The character that ends a
   segment and an optional alternative segment-end character, and the
   minimum and maximum permitted segment size.  The alternative segment-end
   character is used for strings like:

	type-info [; more-info]

   where optional additional information may follow the value that we're
   interested in, separated by a delimiter.  The formatting of the parse
   info is one of:

	endChar	altEndChar	Matches
	-------	----------	------------------
		x		\0		....x.... (Case 1)
		x		y		....x....
						....y....
		\0		y		....	  (Case 2)
						....y.... */

typedef struct {
	const char segmentEndChar, altSegmentEndChar;
	const int segmentMinLength, segmentMaxLength;
	} URI_PARSE_INFO;

/* Get the length of a sub-segment of a URI */

static int getUriSegmentLength( const char *data, const int dataLength,
								const URI_PARSE_INFO *uriParseInfo,
								BOOLEAN *altDelimiterFound )
	{
	const int maxLength = min( dataLength, uriParseInfo->segmentMaxLength );
	int i;

	assert( isReadPtr( data, dataLength ) );
	assert( isReadPtr( uriParseInfo, sizeof( URI_PARSE_INFO  ) ) );
	assert( uriParseInfo->segmentMinLength >= 0 && \
			uriParseInfo->segmentMinLength < \
					uriParseInfo->segmentMaxLength && \
			uriParseInfo->segmentMaxLength <= 1024 );
	assert( ( uriParseInfo->altSegmentEndChar == '\0' && \
			  altDelimiterFound == NULL ) || \
			( uriParseInfo->altSegmentEndChar > '\0' && \
			  isWritePtr( altDelimiterFound, sizeof( BOOLEAN ) ) ) );

	/* Clear return value */
	if( altDelimiterFound != NULL )
		*altDelimiterFound = FALSE;

	/* Parse the current query sub-segment */
	for( i = 0; i < maxLength; i++ )
		{
		if( data[ i ] == uriParseInfo->segmentEndChar )
			break;
		if( uriParseInfo->altSegmentEndChar > '\0' && \
			data[ i ] == uriParseInfo->altSegmentEndChar )
			{
			*altDelimiterFound = TRUE;
			break;
			}
		}

	/* If there's an end-char specified (Case 1) and we didn't find it (or 
	   the alternative end-char if there is one), it's an error.  If there's
	   no end-char specified (Case 2), the end of the sub-segment is at the
	   end of the data */
	if( uriParseInfo->segmentEndChar != '\0' && i >= dataLength )
		return( CRYPT_ERROR_BADDATA );

	/* Make sure that we both got enough data and that we didn't run out of
	   data */
	if( i < uriParseInfo->segmentMinLength || \
		i >= uriParseInfo->segmentMaxLength )
		return( CRYPT_ERROR_BADDATA );

	return( i );
	}

/* Parse a URI of the form "* '?' attribute '=' value [ '&' ... ] ' ' ",
   returning the parsed form to the caller (there's always a space at the
   end because it's followed by the HTTP ID string).  This function needs to 
   return two length values since it decodes the URI string according to RFC 
   1866, which means that its length can change.  So as its standard return 
   value it returns the number of chars consumed, but it also returns the 
   new length of the input as a by-reference parameter */

int parseUriInfo( char *data, const int dataInLength, int *dataOutLength, 
				  HTTP_URI_INFO *uriInfo )
	{
	static const URI_PARSE_INFO locationParseInfo = \
			{ '?', '\0', 1, CRYPT_MAX_TEXTSIZE };
	static const URI_PARSE_INFO attributeParseInfo = \
			{ '=', '\0', 3, CRYPT_MAX_TEXTSIZE };
	static const URI_PARSE_INFO valueParseInfo = \
			{ ' ', '&', 3, CRYPT_MAX_TEXTSIZE };
	static const URI_PARSE_INFO extraParseInfo = \
			{ ' ', '\0', 1, CRYPT_MAX_TEXTSIZE };
	BOOLEAN altDelimiterFound;
	const char *bufPtr = data;
	int length = dataInLength, segmentLength, parsedLength, i, status;

	assert( isWritePtr( data, dataInLength ) );
	assert( isWritePtr( dataOutLength, sizeof( int ) ) );
	assert( isWritePtr( uriInfo, sizeof( HTTP_URI_INFO ) ) );

	/* Clear return values */
	memset( uriInfo, 0, sizeof( HTTP_URI_INFO ) );
	*dataOutLength = 0;

	/* Decode the URI text.  Since there can be multiple nested levels of
	   encoding, we keep iteratively decoding in-place until either 
	   decodeRFC1866() cries Uncle or we hit the sanity-check limit */
	for( i = 0; i < FAILSAFE_ITERATIONS_SMALL; i++ )
		{
		status = decodeRFC1866( data, length );
		if( cryptStatusError( status ) )
			{
			if( status == OK_SPECIAL )
				/* There's been no further change in the data, exit */
				break;
			return( CRYPT_ERROR_BADDATA );
			}
		length = status;	/* Record the new length of the decoded data */
		}
	if( i >= FAILSAFE_ITERATIONS_SMALL )
		{
		/* Sanity-check limit exceeded.  This could be either a data error
		   or an internal error, since we can't automatically tell which it 
		   is we report it as a data error */
		return( CRYPT_ERROR_BADDATA );
		}
	*dataOutLength = length;

	/* We need to get at least 'x?xxx=xxx' */
	if( length < 9 )
		return( CRYPT_ERROR_BADDATA );

	/* Parse a URI of the form "* '?' attribute '=' value [ '&' ... ] ' ' ".
	   The URI is followed by the HTTP ID, so we know that it always has to
	   end on a space; running out of input is an error */
	segmentLength = getUriSegmentLength( bufPtr, length,
										 &locationParseInfo, NULL );
	if( cryptStatusError( segmentLength ) )
		return( segmentLength );
	memcpy( uriInfo->location, bufPtr, segmentLength );
	uriInfo->locationLen = segmentLength;
	bufPtr += segmentLength + 1;	/* Skip delimiter */
	length -= segmentLength + 1;
	parsedLength = segmentLength + 1;
	segmentLength = getUriSegmentLength( bufPtr, length,
										 &attributeParseInfo, NULL );
	if( cryptStatusError( segmentLength  ) )
		return( segmentLength  );
	memcpy( uriInfo->attribute, bufPtr, segmentLength );
	uriInfo->attributeLen = segmentLength;
	bufPtr += segmentLength + 1;	/* Skip delimiter */
	length -= segmentLength + 1;
	parsedLength += segmentLength + 1;
	segmentLength = getUriSegmentLength( bufPtr, length, &valueParseInfo,
										 &altDelimiterFound );
	if( cryptStatusError( segmentLength ) )
		return( segmentLength );
	memcpy( uriInfo->value, bufPtr, segmentLength );
	uriInfo->valueLen = segmentLength;
	bufPtr += segmentLength + 1;	/* Skip delimiter */
	length -= segmentLength + 1;
	parsedLength += segmentLength + 1;
	if( altDelimiterFound )
		{
		segmentLength = getUriSegmentLength( bufPtr, length,
											 &extraParseInfo, NULL );
		if( cryptStatusError( segmentLength  ) )
			return( segmentLength  );
		memcpy( uriInfo->extraData, bufPtr, segmentLength );
		uriInfo->extraDataLen = segmentLength;
		parsedLength += segmentLength + 1;
		}

	return( parsedLength );
	}

/* Check an "HTTP 1.x" ID string.  No PKI client should be sending us a 0.9
   ID, so we only allow 1.x */

int checkHTTPID( const char *data, const int dataLength, STREAM *stream )
	{
	assert( isReadPtr( data, dataLength ) );
	assert( isWritePtr( stream, sizeof( STREAM ) ) );

	if( dataLength < 8 || strCompare( data, "HTTP/1.", 7 ) )
		return( CRYPT_ERROR_BADDATA );
	if( data[ 7 ] == '0' )
		stream->nFlags |= STREAM_NFLAG_HTTP10;
	else
		if( data[ 7 ] != '1' )
			return( CRYPT_ERROR_BADDATA );

	return( 8 );
	}

/****************************************************************************
*																			*
*							HTTP Header Processing							*
*																			*
****************************************************************************/

/* Read an HTTP status code.  Some status values are warnings only and
   don't return an error status */

static int readHTTPStatus( const char *data, const int dataLength,
						   int *httpStatus, void *errorInfo )
	{
	const HTTP_STATUS_INFO *httpStatusPtr;
	const BOOLEAN isResponseStatus = ( httpStatus != NULL ) ? TRUE : FALSE;
	char thirdChar;
	int value, remainderLength, offset, i;

	assert( isReadPtr( data, dataLength ) );
	assert( httpStatus == NULL || \
			isWritePtr( httpStatus, sizeof( int ) ) );
	assert( isWritePtr( errorInfo, sizeof( STREAM ) ) );

	/* Clear return value */
	if( httpStatus != NULL )
		*httpStatus = CRYPT_OK;

	/* Check that the numeric value is in order, being exactly three 
	   characters followed by a space */
	if( dataLength < 3 || strSkipNonWhitespace( data, dataLength ) != 3 )
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, STREAM_ERRINFO_VOID, 
				  "Invalid/missing HTTP %sstatus code", 
				  isResponseStatus ? "response " : "" ) );

	/* Process the three-digit numeric status code */
	value = strGetNumeric( data, 3, 1, 999 );
	if( cryptStatusError( value ) )
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, STREAM_ERRINFO_VOID, 
				  "Invalid HTTP %sstatus code", 
				  isResponseStatus ? "response " : "" ) );
	if( httpStatus != NULL )
		*httpStatus = value;

	/* Try and translate the HTTP status code into a cryptlib equivalent.  
	   Most of the HTTP codes don't have any meaning in a cryptlib context, 
	   so they're mapped to a generic CRYPT_ERROR_READ by the HTTP status 
	   decoding table */
	thirdChar = data[ 2 ];
	for( i = 0; httpStatusInfo[ i ].httpStatus != 0 && \
				i < FAILSAFE_ARRAYSIZE( httpStatusInfo, HTTP_STATUS_INFO ); 
		 i++ )
		{
		/* We check the third digit (the one most likely to be different)
		   for a mismatch to avoid a large number of calls to the string-
		   compare function */
		if( httpStatusInfo[ i ].httpStatusString[ 2 ] == thirdChar && \
			!strCompare( data, httpStatusInfo[ i ].httpStatusString, 3 ) )
			break;
		}
	if( i >= FAILSAFE_ARRAYSIZE( httpStatusInfo, HTTP_STATUS_INFO ) )
		retIntError();
	httpStatusPtr = &httpStatusInfo[ i ];

	/* If we're doing a status read from something in a header line rather
	   than an HTTP response (for example a Warning line, which only 
	   requires a status code but no status message), we're done */
	if( !isResponseStatus )
		return( CRYPT_OK );

	/* We're doing a status read from an HTTP response, make sure that 
	   there's status text present alongside the status code */
	remainderLength = dataLength - 3;
	if( remainderLength < 2 || \
		( offset = strSkipWhitespace( data + 3, remainderLength ) ) < 0 || \
		dataLength - offset < 1 )
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, STREAM_ERRINFO_VOID, 
				  "Missing HTTP response status text" ) );

	/* If it's a special-case condition such as a redirect, tell the caller
	   to handle it specially */
	if( httpStatusPtr->status == OK_SPECIAL )
		return( OK_SPECIAL );

	/* If it's an error condition, return extended error info (from the
	   information we have, not from any externally-supplied message) */
	if( httpStatusPtr->status != CRYPT_OK )
		{
		assert( httpStatusPtr->httpStatusString != NULL );
							/* Catch oddball errors in debug version */
		retExt( httpStatusPtr->status,
				( httpStatusPtr->status, STREAM_ERRINFO_VOID, 
				  "HTTP response status: %s", 
				  httpStatusPtr->httpErrorString ) );
		}

	return( CRYPT_OK );
	}

/* Process an HTTP header line looking for anything that we can handle */

static int processHeaderLine( const char *data, const int dataLength,
							  HTTP_HEADER_TYPE *headerType,
							  void *errorInfo, const int errorLineNo )
	{
	const HTTP_HEADER_PARSE_INFO *headerParseInfoPtr = NULL;
	const char firstChar = toUpper( *data );
	int processedLength, dataLeft, i;

	assert( isReadPtr( data, dataLength ) );
	assert( isWritePtr( headerType, sizeof( HTTP_HEADER_TYPE ) ) );
	assert( isWritePtr( errorInfo, sizeof( STREAM ) ) );
	assert( errorLineNo > 0 && errorLineNo < 1000 );

	/* Clear return value */
	*headerType = HTTP_HEADER_NONE;

	/* Look for a header line that we recognise */
	for( i = 0; 
		 httpHeaderParseInfo[ i ].headerString != NULL && \
			i < FAILSAFE_ARRAYSIZE( httpHeaderParseInfo, HTTP_HEADER_PARSE_INFO ); 
		 i++ )
		{
		if( httpHeaderParseInfo[ i ].headerString[ 0 ] == firstChar && \
			dataLength >= httpHeaderParseInfo[ i ].headerStringLen && \
			!strCompare( data, httpHeaderParseInfo[ i ].headerString, \
						 httpHeaderParseInfo[ i ].headerStringLen ) )
			{
			headerParseInfoPtr = &httpHeaderParseInfo[ i ];
			break;
			}
		}
	if( i >= FAILSAFE_ARRAYSIZE( httpHeaderParseInfo, HTTP_HEADER_PARSE_INFO ) )
		retIntError();
	if( headerParseInfoPtr == NULL )
		/* It's nothing that we can handle, exit */
		return( 0 );
	processedLength = headerParseInfoPtr->headerStringLen;
	dataLeft = dataLength - processedLength;

	/* Make sure that there's an attribute value present */
	if( dataLeft > 0 )
		{
		const int extraLength = \
				strSkipWhitespace( data + processedLength, dataLeft );
		if( cryptStatusError( extraLength ) )
			{
			/* There was a problem, make sure that we fail the following 
			   check */
			dataLeft = CRYPT_ERROR;
			}
		else
			if( extraLength > 0 )
				{
				/* We skipped some whitespace before the attribute value, 
				   adjust the consumed/remaining byte counts */
				dataLeft -= extraLength;
				processedLength += extraLength;
				}
		}
	if( dataLeft < 1 )
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, STREAM_ERRINFO_VOID, 
				  "Missing HTTP header value for '%s' token, line %d",
				  headerParseInfoPtr->headerString, errorLineNo ) );

	/* Tell the caller what we found */
	*headerType = headerParseInfoPtr->headerType;
	return( processedLength );
	}

/* Read the first line in an HTTP response header */

int readFirstHeaderLine( STREAM *stream, char *dataBuffer,
						 const int dataMaxLength, int *httpStatus )
	{
	BOOLEAN textDataError;
	int length, processedLength, dataLeft;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( dataBuffer, dataMaxLength ) );
	assert( isWritePtr( httpStatus, sizeof( int ) ) );

	/* Clear return value */
	*httpStatus = CRYPT_OK;

	/* Read the header and check for an HTTP ID */
	length = readTextLine( readCharFunction, stream, dataBuffer,
						   dataMaxLength, &textDataError );
	if( cryptStatusError( length ) || length < 8 )
		return( retTextLineError( stream, length, textDataError, 
								  "Invalid HTTP header line 1: ", 0 ) );
	processedLength = checkHTTPID( dataBuffer, length, stream );
	if( cryptStatusError( processedLength ) )
		retExt( cryptStatusError( processedLength ) ? \
				processedLength : CRYPT_ERROR_BADDATA, 
				( cryptStatusError( processedLength ) ? \
				  processedLength : CRYPT_ERROR_BADDATA, STREAM_ERRINFO, 
				  "Invalid HTTP ID/version" ) );
	dataLeft = length - processedLength;

	/* Skip the whitespace between the HTTP ID and status info */
	if( dataLeft > 0 )
		{
		const int extraLength = \
				strSkipWhitespace( dataBuffer + processedLength, dataLeft );
		if( cryptStatusError( extraLength ) )
			{
			/* There was a problem, make sure that we fail the following 
			   check */
			dataLeft = CRYPT_ERROR;
			}
		else
			if( extraLength > 0 )
				{
				/* We skipped some whitespace before the HTTP status info,
				   adjust the consumed/remaining byte counts */
				dataLeft -= extraLength;
				processedLength += extraLength;
				}
		}
	if( dataLeft < 1 )
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, STREAM_ERRINFO, 
				  "Missing HTTP status code, line 1" ) );

	/* Read the HTTP status info */
	return( readHTTPStatus( dataBuffer + processedLength, dataLeft,
							httpStatus, stream ) );
	}

/* Read the remaining HTTP header lines after the first one */

int readHeaderLines( STREAM *stream, char *lineBuffer,
					 const int lineBufMaxLen,
					 HTTP_HEADER_INFO *headerInfo )
	{
	BOOLEAN seenHost = FALSE, seenLength = FALSE;
	int contentLength = 0, lineCount, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isWritePtr( lineBuffer, lineBufMaxLen ) );
	assert( isWritePtr( headerInfo, sizeof( HTTP_HEADER_INFO ) ) );

	/* Read each line in the header checking for any fields that we need to
	   handle.  We check for a couple of basic problems with the header to
	   avoid malformed-header attacks, for example an attacker could send a
	   request with two 'Content-Length:' headers, one of which covers the
	   entire message body and the other which indicates that there's a
	   second request that begins halfway through the message body.  Some
	   proxies/caches will take the first length, some the second, if the
	   proxy is expected to check/rewrite the request as it passes through
	   then the single/dual-message issue can be used to bypass the checking
	   on the tunnelled second message.  Because of this we only allow a
	   single Host: and Content-Length: header, and disallow a chunked
	   encoding in combination with a content-length (Apache does some
	   really strange things with chunked encodings).  We can't be too
	   finicky with the checking though or we'll end up rejecting non-
	   malicious requests from some of the broken HTTP implementations out
	   there */
	for( lineCount = 0; lineCount < FAILSAFE_ITERATIONS_MED; lineCount++ )
		{
		HTTP_HEADER_TYPE headerType;
		BOOLEAN textDataError;
		char *lineBufPtr;
		int lineLength;

		lineLength = readTextLine( readCharFunction, stream, lineBuffer,
								   lineBufMaxLen, &textDataError );
		if( cryptStatusError( lineLength ) )
			return( retTextLineError( stream, lineLength, textDataError, 
									  "Invalid HTTP header line %d: ", 
									  lineCount + 2 ) );
		if( lineLength <= 0 )
			/* End of input, exit */
			break;
		status = processHeaderLine( lineBuffer, lineLength, &headerType,
									stream, lineCount + 2 );
		if( cryptStatusError( status ) )
			return( status );
		lineBufPtr = lineBuffer + status;
		lineLength -= status;
		if( lineLength <= 0 )	/* Guaranteed by processHeaderLine() */
			retIntError();
		switch( headerType )
			{
			case HTTP_HEADER_HOST:
				/* Make sure that it's a non-duplicate, and remember that
				   we've seen a Host: line, to meet the HTTP 1.1
				   requirements */
				if( seenHost )
					retExt( CRYPT_ERROR_BADDATA,
							( CRYPT_ERROR_BADDATA, STREAM_ERRINFO, 
							  "Duplicate HTTP 'Host:' header, line %d",
							  lineCount + 2 ) );
				seenHost = TRUE;
				break;

			case HTTP_HEADER_CONTENT_LENGTH:
				/* Make sure that it's a non-duplicate and get the content
				   length.  At this point all that we do is perform a
				   general sanity check that the length looks OK, a specific
				   check against the caller-supplied minimum/maximum
				   allowable length is performed later since the content
				   length may also be provided as a chunked encoding length,
				   which we can't check until we've processed all of the
				   header lines */
				if( seenLength )
					retExt( CRYPT_ERROR_BADDATA, 
							( CRYPT_ERROR_BADDATA, STREAM_ERRINFO, 
							  "Duplicate HTTP 'Content-Length:' header, "
							  "line %d", lineCount + 2 ) );
				contentLength = strGetNumeric( lineBufPtr, lineLength, 
											   1, MAX_INTLENGTH );
				if( cryptStatusError( contentLength ) )
					retExt( CRYPT_ERROR_BADDATA, 
							( CRYPT_ERROR_BADDATA, STREAM_ERRINFO, 
							  "Invalid HTTP content length, line %d",
							  lineCount + 2 ) );
				seenLength = TRUE;
				break;

			case HTTP_HEADER_CONTENT_TYPE:
				{
				static const URI_PARSE_INFO typeParseInfo = \
						{ '/', '\0', 2, CRYPT_MAX_TEXTSIZE };
				static const URI_PARSE_INFO subtypeParseInfo = \
						{ '\0', ';', 2, CRYPT_MAX_TEXTSIZE };
				BOOLEAN dummy;
				char *contentType;
				int contentTypeLen, subTypeLen;

				/* Sometimes if there's an error it'll be returned as content
				   at the HTTP level rather than at the tunnelled-over-HTTP
				   protocol level.  The easiest way to check for this would
				   be to make sure that the content-type matches the
				   expected type and report anything else as an error.
				   Unfortunately due to the hit-and-miss handling of content-
				   types by PKI software using HTTP as a substrate it's not
				   safe to do this, so we have to default to allow-all
				   rather than deny-all, treating only straight text as a
				   problem type.

				   To compound the problem there are also apps out there 
				   that send their PKI messages marked as plain text, so 
				   this isn't 100% foolproof.  This is particularly 
				   problematic for web browsers, where so many servers were 
				   misconfigured to return pretty much anything as 
				   text/plain that Microsoft added content-type guessing 
				   code to MSIE to make web pages served from misconfigured 
				   servers work (you can see this by serving a JPEG file as 
				   text/plain, MSIE will display it as a JPEG while Mozilla/
				   Firefox/Opera/etc will display it as text or prompt for a 
				   helper app to handle it).  Since this content-type 
				   guessing is a potential security hole, MS finally made it
				   configurable in Windows XP SP2, but it's still enabled
				   by default even there.

				   In practice however errors-via-HTTP is more common than
				   certs-via-text.  We try and detect the cert-as-plain-text
				   special-case at a later point when we've got the message
				   body available.

				   Since we're now looking at the content-type line (even if
				   we don't really process it in any way), we perform at 
				   least a minimal validity check for * '/' * [ ';*' ] */
				contentTypeLen = getUriSegmentLength( lineBufPtr, lineLength,
													  &typeParseInfo, NULL );
				if( cryptStatusError( contentTypeLen ) )
					{
					/* We need to have at least 'xx/*' present (length is
					   guaranteed by getUriSegmentLength()) */
					return( retHeaderError( stream, 
								"Invalid HTTP content type '%s', line %d",
								lineBufPtr, lineLength, lineCount ) );
					}
				contentType = lineBufPtr;
				lineBufPtr += contentTypeLen + 1;	/* Skip delimiter */
				lineLength -= contentTypeLen + 1;
				subTypeLen = getUriSegmentLength( lineBufPtr, lineLength,
												  &subtypeParseInfo, &dummy );
				if( cryptStatusError( subTypeLen ) )
					{
					/* We need to have at least 'xx/yy' present (length is
					   guaranteed by getUriSegmentLength()) */
					return( retHeaderError( stream, 
								"Invalid HTTP content subtype '%s', line %d",
								lineBufPtr, lineLength, lineCount ) );
					}
				if( contentTypeLen == 4 && \
					!strCompare( contentType, "text", 4 ) )
					headerInfo->flags |= HTTP_FLAG_TEXTMSG;
				break;
				}

			case HTTP_HEADER_TRANSFER_ENCODING:
				if( lineLength < 7 || \
					strCompare( lineBufPtr, "Chunked", 7 ) )
					{
					return( retHeaderError( stream, 
							  "Invalid HTTP transfer encoding method "
							  "'%s', expected 'Chunked', line %d",
							  lineBufPtr, lineLength, lineCount ) );
					}

				/* If it's a chunked encoding, the length is part of the
				   data and must be read later */
				if( seenLength )
					retExt( CRYPT_ERROR_BADDATA,
							( CRYPT_ERROR_BADDATA, STREAM_ERRINFO, 
							  "Duplicate HTTP 'Content-Length:' header, "
							  "line %d", lineCount + 2 ) );
				headerInfo->flags |= HTTP_FLAG_CHUNKED;
				seenLength = TRUE;
				break;

			case HTTP_HEADER_CONTENT_ENCODING:
				/* We can't handle any type of content encoding (e.g. gzip,
				   compress, deflate, mpeg4, interpretive dance) except the
				   no-op identity encoding */
				if( lineLength < 8 || \
					strCompare( lineBufPtr, "Identity", 8 ) )
					{
					headerInfo->httpStatus = 415;	/* Unsupp.media type */
					return( retHeaderError( stream, 
							  "Invalid HTTP content encoding method "
							  "'%s', expected 'Identity', line %d",
							  lineBufPtr, lineLength, lineCount ) );
					}
				break;

			case HTTP_HEADER_CONTENT_TRANSFER_ENCODING:
				/* HTTP uses Transfer-Encoding, not the MIME Content-
				   Transfer-Encoding types such as base64 or quoted-
				   printable.  If any implementations erroneously use a
				   C-T-E, we make sure that it's something that we can
				   handle */
				if( lineLength < 6 || \
					( strCompare( lineBufPtr, "Identity", 8 ) && \
					  strCompare( lineBufPtr, "Binary", 6 ) ) )
					{
					headerInfo->httpStatus = 415;	/* Unsupp.media type */
					return( retHeaderError( stream, 
							  "Invalid HTTP content transfer encoding "
							  "method '%s', expected 'Identity' or "
							  "'Binary', line %d", lineBufPtr, lineLength, 
							  lineCount ) );
					}
				break;

			case HTTP_HEADER_TRAILER:
				/* The body is followed by trailer lines, used with chunked
				   encodings where some header lines can't be produced until
				   the entire body has been generated.  This wasn't added
				   until RFC 2616, since many implementations are based on
				   RFC 2068 and don't produce this header we don't do
				   anything with it.  The trailer can be auto-detected
				   anyway, it's only present to tell the receiver to perform
				   certain actions such as creating an MD5 hash of the data
				   as it arrives */
				headerInfo->flags |= HTTP_FLAG_TRAILER;
				break;

			case HTTP_HEADER_CONNECTION:
				/* If the other side has indicated that it's going to close
				   the connection, remember that the stream is now no longer
				   usable */
				if( lineLength >= 5 && \
					!strCompare( lineBufPtr, "Close", 5 ) )
					sioctl( stream, STREAM_IOCTL_CONNSTATE, NULL, FALSE );
				break;

			case HTTP_HEADER_WARNING:
				/* Read the HTTP status info from the warning.  
				   readHTTPStatus() will process the error status in the
				   warning line, but since we're passing in a NULL pointer 
				   for the status info it'll only report an error in the
				   warning content itself, it won't return the processed
				   warning status as an error */
				status = readHTTPStatus( lineBufPtr, lineLength, NULL, 
										 stream );
				if( cryptStatusError( status ) )
					return( retHeaderError( stream, 
							  "Invalid HTTP warning information '%s', "
							  "line %d", lineBufPtr, lineLength, 
							  lineCount ) );
				break;

			case HTTP_HEADER_LOCATION:
				{
#if defined( __WIN32__ ) && !defined( NDEBUG ) && 1
				URL_INFO urlInfo;
#endif /* Win32 debug build only */

				/* Make sure that we've been given an HTTP URL as the 
				   redirect location.  We need to do this because 
				   sNetParseURL() will accept a wide range of URL types
				   while we only allow "http://*" */
				if( lineLength < 10 || \
					strCompare( lineBufPtr, "http://", 7 ) )
					return( retHeaderError( stream, 
							  "Invalid HTTP redirect location '%s', line %d",
							  lineBufPtr, lineLength, lineCount ) );

				/* Process the redirect location */
#if defined( __WIN32__ ) && !defined( NDEBUG ) && 1
				/* We don't try and parse the URL other than in the Win32 
				   debug build because we don't do redirects yet so there's 
				   no need to expose ourselves to possibly maliciously-
				   created URLs from external sources */
				status = sNetParseURL( &urlInfo, lineBufPtr, lineLength, 
									   URL_TYPE_HTTP );
				if( cryptStatusError( status ) )
					return( retHeaderError( stream, 
							  "Invalid HTTP redirect location '%s', line %d",
							  lineBufPtr, lineLength, lineCount ) );
#endif /* Win32 debug build only */
				break;
				}

			case HTTP_HEADER_EXPECT:
				/* If the other side wants the go-ahead to continue, give it
				   to them.  We do this automatically because we're merely
				   using HTTP as a substrate, the real decision will be made
				   at the higher-level protocol layer */
				if( lineLength >= 12 && \
					!strCompare( lineBufPtr, "100-Continue", 12 ) )
					sendHTTPError( stream, lineBufPtr, lineBufMaxLen, 100 );
				break;

			case HTTP_HEADER_NONE:
				/* It's something that we don't know/care about, skip it */
				break;

			default:
				assert( NOTREACHED );
			}
		}
	if( lineCount >= FAILSAFE_ITERATIONS_MED )
		retExt( CRYPT_ERROR_OVERFLOW,
				( CRYPT_ERROR_OVERFLOW, STREAM_ERRINFO, 
				  "Too many HTTP header lines" ) );

	/* If this is a tunnel being opened via an HTTP proxy, we're done */
	if( !( stream->nFlags & STREAM_NFLAG_ISSERVER ) && \
		( stream->nFlags & STREAM_NFLAG_HTTPTUNNEL ) )
		return( CRYPT_OK );

	/* If it's a chunked encoding for which the length is kludged on before
	   the data as a hex string, decode the length value */
	if( headerInfo->flags & HTTP_FLAG_CHUNKED )
		{
		BOOLEAN textDataError;

		const int lineLength = readTextLine( readCharFunction, stream,
											 lineBuffer, lineBufMaxLen,
											 &textDataError );
		if( cryptStatusError( lineLength ) )
			return( retTextLineError( stream, lineLength, textDataError, 
									  "Invalid HTTP chunked encoding "
									  "header line %d: ", lineCount + 2 ) );
		if( lineLength <= 0 )
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, STREAM_ERRINFO, 
					  "Missing HTTP chunk length, line %d", lineCount + 2 ) );
		status = contentLength = getChunkLength( lineBuffer, lineLength );
		if( cryptStatusError( status ) )
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, STREAM_ERRINFO, 
					  "Invalid length for HTTP chunked encoding, line %d",
					  lineCount + 2 ) );
		}

	/* If this is a no-op read (for example lines following an error or 100
	   Continue response), all that we're interested in is draining the
	   input, so we don't check any further */
	if( headerInfo->flags & HTTP_FLAG_NOOP )
		return( CRYPT_OK );

	/* If we're a server talking HTTP 1.1 and we haven't seen a "Host:"
	   header from the client, return an error */
	if( ( stream->nFlags & STREAM_NFLAG_ISSERVER ) && \
		!isHTTP10( stream ) && !seenHost )
		{
		headerInfo->httpStatus = 400;	/* Bad request */
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, STREAM_ERRINFO, 
				  "Missing HTTP 1.1 'Host:' header" ) );
		}

	/* If it's a GET request there's no length so we can exit now */
	if( headerInfo->flags & HTTP_FLAG_GET )
		{
		if( seenLength )
			retExt( CRYPT_ERROR_BADDATA,
					( CRYPT_ERROR_BADDATA, STREAM_ERRINFO, 
					  "Unexpected %d bytes HTTP body content received in "
					  "idempotent read", contentLength ) );
		return( CRYPT_OK );
		}

	/* Make sure that we've been given a length.  In theory a server could
	   indicate the length implicitly by closing the connection once it's
	   sent the last byte, but this isn't allowed for PKI messages.  The
	   client can't use this option either since that would make it
	   impossible for us to send back the response */
	if( !seenLength )
		{
		headerInfo->httpStatus = 411;	/* Length required */
		retExt( CRYPT_ERROR_BADDATA, 
				( CRYPT_ERROR_BADDATA, STREAM_ERRINFO, 
				  "Missing HTTP length" ) );
		}

	/* Make sure that the length is sensible */
	if( contentLength < headerInfo->minContentLength || \
		contentLength > headerInfo->maxContentLength )
		{
		retExt( ( contentLength < headerInfo->minContentLength ) ? \
				CRYPT_ERROR_UNDERFLOW : CRYPT_ERROR_OVERFLOW,
				( ( contentLength < headerInfo->minContentLength ) ? \
				  CRYPT_ERROR_UNDERFLOW : CRYPT_ERROR_OVERFLOW, STREAM_ERRINFO,
				  "Invalid HTTP content length %d bytes, expected "
				  "%d...%d bytes", contentLength,
				  headerInfo->minContentLength, 
				  headerInfo->maxContentLength ) );
		}
	headerInfo->contentLength = contentLength;

	return( CRYPT_OK );
	}

/* Read the HTTP trailer lines that follow chunked data:

			CRLF
			"0" CRLF
			trailer-lines*
			CRLF */

int readTrailerLines( STREAM *stream, char *lineBuffer, 
					  const int lineBufMaxLen )
	{
	HTTP_HEADER_INFO headerInfo;
	BOOLEAN textDataError;
	int readLength, status;

	assert( isWritePtr( stream, sizeof( STREAM ) ) );
	assert( isReadPtr( lineBuffer, lineBufMaxLen ) );

	/* Read the blank line and chunk length */
	status = readTextLine( readCharFunction, stream, lineBuffer,
						   lineBufMaxLen, &textDataError );
	if( !cryptStatusError( status ) )
		status = readLength = readTextLine( readCharFunction, stream,
											lineBuffer, lineBufMaxLen,
											&textDataError );
	if( cryptStatusError( status ) )
		return( retTextLineError( stream, status, textDataError, 
								  "Invalid HTTP chunked trailer line: ", 
								  0 ) );

	/* Make sure that there are no more chunks to follow */
	status = getChunkLength( lineBuffer, readLength );
	if( status != 0 )
		retExt( CRYPT_ERROR_BADDATA,
				( CRYPT_ERROR_BADDATA, STREAM_ERRINFO, 
				  "Unexpected additional data following HTTP chunked "
				  "data" ) );

	/* Read any remaining trailer lines */
	initHeaderInfo( &headerInfo, 0, 0, HTTP_FLAG_NOOP );
	return( readHeaderLines( stream, lineBuffer, lineBufMaxLen,
							 &headerInfo ) );
	}
#endif /* USE_HTTP */
