/****************************************************************************
*																			*
*							SCEP Definitions Header File					*
*						Copyright Peter Gutmann 1999-2007					*
*																			*
****************************************************************************/

#ifndef _SCEP_DEFINED

#define _SCEP_DEFINED

/* Various SCEP constants */

#define SCEP_NONCE_SIZE			16

/* SCEP protocol-specific flags that augment the general session flags */

#define SCEP_PFLAG_NONE			0x00	/* No protocol-specific flags */
#define SCEP_PFLAG_PNPPKI		0x01	/* Session is PnP PKI-capable */

/* The SCEP message type, status, and failure info.  For some bizarre
   reason these integer values are communicated as text strings */

#define MESSAGETYPE_CERTREP				"3"
#define MESSAGETYPE_PKCSREQ				"19"

#define MESSAGESTATUS_SUCCESS			"0"
#define MESSAGESTATUS_FAILURE			"2"
#define MESSAGESTATUS_PENDING			"3"

#define MESSAGEFAILINFO_BADALG			"0"
#define MESSAGEFAILINFO_BADMESSAGECHECK	"1"
#define MESSAGEFAILINFO_BADREQUEST		"2"
#define MESSAGEFAILINFO_BADTIME			"3"
#define MESSAGEFAILINFO_BADCERTID		"4"

/* Numeric equivalents of the above, to make them easier to work with */

#define MESSAGETYPE_CERTREP_VALUE		3
#define MESSAGETYPE_PKCSREQ_VALUE		19

#define MESSAGESTATUS_SUCCESS_VALUE		0
#define MESSAGESTATUS_FAILURE_VALUE		2
#define MESSAGESTATUS_PENDING_VALUE		3

/* SCEP HTTP content type */

#define SCEP_CONTENT_TYPE				"application/x-pki-message"
#define SCEP_CONTENT_TYPE_GETCACERT		"application/x-x509-ca-cert"
#define SCEP_CONTENT_TYPE_GETCACERTCHAIN "application/x-x509-ca-ra-cert-chain"

/* SCEP protocol state information.  This is passed around various
   subfunctions that handle individual parts of the protocol */

typedef struct {
	/* Identification/state variable information.  SCEP uses a single
	   nonce, but when present in the initiator's message it's identified
	   as a sender nonce and when present in the responder's message
	   it's identified as a recipient nonce.
	
	   In order to accommodate nonstandard implementations, we allow for 
	   nonces that are slightly larger than the required size */
	BYTE transID[ CRYPT_MAX_HASHSIZE + 8 ];	/* Transaction nonce */
	BYTE nonce[ CRYPT_MAX_HASHSIZE + 8 ];	/* Nonce */
	int transIDsize, nonceSize;

	/* When sending/receiving SCEP messages, the user has to sign the
	   request data and decrypt the response data.  Since they don't
	   have a cert at this point, they need to create an ephemeral
	   self-signed cert to handle this task */
	CRYPT_CERTIFICATE iScepCert;
	} SCEP_PROTOCOL_INFO;

/* Prototypes for functions in scep.c */

BOOLEAN checkCACert( const CRYPT_CERTIFICATE iCaCert );
int processKeyFingerprint( SESSION_INFO *sessionInfoPtr );
int createScepAttributes( SESSION_INFO *sessionInfoPtr,
						  SCEP_PROTOCOL_INFO *protocolInfo,
						  CRYPT_CERTIFICATE *iScepAttributes,
						  const BOOLEAN isInitiator, const int scepStatus );
int getScepStatusValue( const CRYPT_CERTIFICATE iCmsAttributes,
						const CRYPT_ATTRIBUTE_TYPE attributeType, 
						int *value );

/* Prototypes for functions in scep_cli.c */

int createScepRequest( SESSION_INFO *sessionInfoPtr,
					   SCEP_PROTOCOL_INFO *protocolInfo );
int checkScepResponse( SESSION_INFO *sessionInfoPtr,
					   SCEP_PROTOCOL_INFO *protocolInfo );
int createAdditionalScepRequest( SESSION_INFO *sessionInfoPtr );

/* Prototypes for functions in scep_svr.c */

int checkScepRequest( SESSION_INFO *sessionInfoPtr,
					  SCEP_PROTOCOL_INFO *protocolInfo );
int createScepResponse( SESSION_INFO *sessionInfoPtr,
						SCEP_PROTOCOL_INFO *protocolInfo );
int processAdditionalScepRequest( SESSION_INFO *sessionInfoPtr,
								  const HTTP_URI_INFO *httpReqInfo );

#endif /* _SCEP_DEFINED */
