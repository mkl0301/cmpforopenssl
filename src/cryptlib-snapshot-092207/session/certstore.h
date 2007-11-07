/****************************************************************************
*																			*
*					cryptlib Certstore Session Management					*
*					  Copyright Peter Gutmann 1998-2007						*
*																			*
****************************************************************************/

/* The certstore HTTP content type */

#define CERTSTORE_CONTENT_TYPE	"application/pkix-cert"

/* Processing flags for certstore query data.  These are:

	FLAG_BASE64: The attribute is base64-encoded and must be decoded before
		being returned to the caller */

#define CERTSTORE_FLAG_NONE		0x00	/* No special processing */
#define CERTSTORE_FLAG_BASE64	0x01	/* Data must be base64 */

/* A mapping of a query submitted as an HTTP GET to a cryptlib-specific
   attribute ID that can be used for an operation like a keyset query.  Note 
   that the first letter must be lowercase for the case-insensitive quick 
   match */

typedef struct {
	const char *attrName;				/* Attribute name from HTTP GET */
	const int attrNameLen;				/* Attribute name length */
	const int attrID;					/* Attribute ID */
	const int flags;					/* Processing flags */
	} CERTSTORE_READ_INFO;

/* Prototypes for functions in certstore.c */

int processCertQuery( SESSION_INFO *sessionInfoPtr,	
					  const HTTP_URI_INFO *httpReqInfo,
					  const CERTSTORE_READ_INFO *queryReqInfo,
					  const int queryReqInfoSize,
					  int *attributeID, void *attribute, 
					  const int attributeMaxLen, int *attributeLen,
					  char *queryText, const int queryTextMaxLen );
void sendCertErrorResponse( SESSION_INFO *sessionInfoPtr, 
							const int errorStatus );
