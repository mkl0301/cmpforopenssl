/****************************************************************************
*																			*
*							User Routines Header File						*
*						 Copyright Peter Gutmann 1999-2006					*
*																			*
****************************************************************************/

#ifndef _USER_DEFINED

#define _USER_DEFINED

/* Initialisation states for the user object */

typedef enum {
	USER_STATE_NONE,				/* No initialisation state */
	USER_STATE_SOINITED,			/* SSO inited, not usable */
	USER_STATE_USERINITED,			/* User inited, usable */
	USER_STATE_LOCKED,				/* Disabled, not usable */
	USER_STATE_LAST					/* Last possible state */
	} USER_STATE_TYPE;

/* User information flags.  These are:

	FLAG_ZEROISE: Zeroise in progress, further messages (except destroy) are 
			bounced, and all files are deleted on destroy */

#define USER_FLAG_NONE			0x00	/* No flag */
#define USER_FLAG_ZEROISE		0x01	/* Zeroise in progress */

/* User information as stored in the user info file */

typedef struct {
	CRYPT_USER_TYPE type;			/* User type */
	USER_STATE_TYPE state;			/* User state */
	BYTE userName[ CRYPT_MAX_TEXTSIZE + 8 ];
	int userNameLength;				/* User name */
	BYTE userID[ KEYID_SIZE + 8 ], creatorID[ KEYID_SIZE + 8 ];
									/* ID of user and creator of this user */
	int fileRef;					/* User info file reference */
	} USER_FILE_INFO;

/* The structure that stores the information on a user */

typedef struct UI {
	/* Control and status information */
	int flags;						/* User flags */
	USER_FILE_INFO userFileInfo;	/* General user info */

	/* User index information for the default user */
	void *userIndexPtr;

	/* Configuration options for this user.  These are managed through the 
	   user config code, so they're just treated as a dynamically-allocated 
	   blob within the user object */
	void *configOptions;

	/* Certificate trust information for this user, and a flag indicating
	   whether the trust info has changed and potentially needs to be
	   committed to disk.  This requires access to cert-internal details
	   so it's handled externally via the cert code, the user object just
	   sees the info as an opaque blob */
	void *trustInfoPtr;
	BOOLEAN trustInfoChanged;

	/* The user object contains an associated keyset which is used to store
	   user information to disk.  In addition for SOs and CAs it also 
	   contains an associated encryption context, either a private key (for 
	   an SO) or a conventional key (for a CA) */
	CRYPT_KEYSET iKeyset;			/* Keyset */
	CRYPT_CONTEXT iCryptContext;	/* Private/secret key */

	/* Error information */
	CRYPT_ATTRIBUTE_TYPE errorLocus;/* Error locus */
	CRYPT_ERRTYPE_TYPE errorType;	/* Error type */

	/* The object's handle, used when sending messages to the object when
	   only the xxx_INFO is available */
	CRYPT_HANDLE objectHandle;
	} USER_INFO;

/* Prototypes for functions in user.c */

const USER_FILE_INFO *getPrimarySoUserInfo( void );
BOOLEAN isZeroisePassword( const char *password, const int passwordLen );
int zeroiseUsers( USER_INFO *userInfoPtr );
int setUserPassword( USER_INFO *userInfoPtr, const char *password,
					 const int passwordLength );
int initUserIndex( void **userIndexPtrPtr );
void endUserIndex( void *userIndexPtr );

/* Prototypes for functions in user_cfg.c */

int initOptions( void **configOptionsPtr );
void endOptions( void *configOptions );
int setOption( void *configOptions, const CRYPT_ATTRIBUTE_TYPE option,
			   const int value );
int setOptionString( void *configOptions, const CRYPT_ATTRIBUTE_TYPE option,
					 const char *value, const int valueLength );
int getOption( void *configOptions, const CRYPT_ATTRIBUTE_TYPE option );
const char *getOptionString( void *configOptions, 
							 const CRYPT_ATTRIBUTE_TYPE option );
int readConfig( const CRYPT_USER iCryptUser, const char *fileName,
				void *trustInfoPtr );
int prepareConfigData( void *configOptions, const char *fileName,
					   void *trustInfoPtr, void **data, int *length );
int commitConfigData( const CRYPT_USER cryptUser, const char *fileName,
					  const void *data, const int length );

#endif /* _USER_DEFINED */
