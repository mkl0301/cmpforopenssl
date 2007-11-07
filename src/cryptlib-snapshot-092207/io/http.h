/****************************************************************************
*																			*
*						cryptlib HTTP Interface Header						*
*						Copyright Peter Gutmann 1998-2006					*
*																			*
****************************************************************************/

#ifdef USE_HTTP

#if defined( INC_ALL )
  #include "stream.h"
#else
  #include "io/stream.h"
#endif /* Compiler-specific includes */

/* The size of the HTTP text-line buffer when we're using a dedicated buffer
   to read header lines rather than the main stream buffer.  Anything more
   than this is dropped */

#define HTTP_LINEBUF_SIZE	1024

/* A macro to determine whether we're talking HTTP 1.0 or 1.1 */

#define isHTTP10( stream )	( ( stream )->flags & STREAM_NFLAG_HTTP10 )

/* HTTP state information passed around the various read/write functions */

#define HTTP_FLAG_NONE		0x00	/* No HTTP info */
#define HTTP_FLAG_CHUNKED	0x01	/* Message used chunked encoding */
#define HTTP_FLAG_TRAILER	0x02	/* Chunked encoding has trailer */
#define HTTP_FLAG_NOOP		0x04	/* No-op data (e.g. 100 Continue) */
#define HTTP_FLAG_TEXTMSG	0x08	/* HTTP content is plain text, probably
									   an error message */
#define HTTP_FLAG_GET		0x10	/* Operation is HTTP GET */

/* HTTP header parsing information as used by readHeaderLines() */

typedef struct {
	/* Returned status information: The body content-length, the HTTP error
	   status (if there is one), and general flags information.  The flags
	   parameter is used as both an input and an output parameter */
	int contentLength;	/* HTTP body content length */
	int httpStatus;		/* HTTP error status, if an HTTP error occurs */
	int flags;			/* General flags */

	/* Range-checking information: The minimum and maximum allowable
	   content-length value */
	int minContentLength, maxContentLength;
	} HTTP_HEADER_INFO;

#define initHeaderInfo( headerInfo, minLength, maxLength, hdrFlags ) \
		memset( headerInfo, 0, sizeof( HTTP_HEADER_INFO ) ); \
		( headerInfo )->flags = ( hdrFlags ); \
		( headerInfo )->minContentLength = ( minLength ); \
		( headerInfo )->maxContentLength = ( maxLength );

/* Prototypes for functions in http_rd.c */

int sendHTTPError( STREAM *stream, char *headerBuffer,
				   const int headerBufMaxLen, const int httpStatus );

/* Prototypes for functions in http_wr.c */

int writeRequestHeader( STREAM *stream, const HTTP_URI_INFO *httpReqInfo,
						const char *contentType, const int contentTypeLen,
						const int contentLength );
int sendHTTPData( STREAM *stream, void *buffer, const int length,
				  const int flags );
void setStreamLayerHTTPwrite( STREAM *stream );

/* Prototypes for functions in http_parse.c */

int checkHTTPID( const char *data, const int dataLength, STREAM *stream );
int parseUriInfo( char *data, const int dataInLength, int *dataOutLength, 
				  HTTP_URI_INFO *uriInfo );
int readFirstHeaderLine( STREAM *stream, char *dataBuffer,
						 const int dataMaxLength, int *httpStatus );
int readHeaderLines( STREAM *stream, char *lineBuffer,
					 const int lineBufMaxLen,
					 HTTP_HEADER_INFO *headerInfo );
int readTrailerLines( STREAM *stream, char *lineBuffer, 
					  const int lineBufMaxLen );
int retTextLineError( STREAM *stream, const int status, 
					  const BOOLEAN isTextLineError, const char *format, 
					  const int value );

#endif /* USE_HTTP */
