/****************************************************************************
*																			*
*							cryptlib User Routines							*
*						Copyright Peter Gutmann 1999-2007					*
*																			*
****************************************************************************/

/* cryptlib's role-based access control mechanisms are present only for
   forwards-compatibility with future cryptlib versions that will include
   role-based access control if there's user demand for it.  The following
   code implements basic user management routines, but the full role-based
   access control functionality isn't present.  Some of the code related to
   this is therefore present only in template form */

#include <stdio.h>		/* For sprintf_s() */
#include "crypt.h"
#ifdef INC_ALL
  #include "trustmgr.h"
  #include "user.h"
#else
  #include "cert/trustmgr.h"
  #include "misc/user.h"
#endif /* Compiler-specific includes */

/* Default user info.  The default user is a special type that has both 
   normal user and SO privileges.  This is because in its usual usage mode 
   where cryptlib is functioning as a single-user system the user doesn't 
   know about the existence of user objects and just wants everything to 
   work the way that they expect.  Because of this, the default user has to 
   be able to perform the full range of available operations, requiring that 
   they appear as both a normal user and an SO.

   For now the default user is marked as an SO user because the kernel checks
   don't allow dual-type objects and some operations require that the user be
   at least an SO user, once a distinction is made between SOs and users this
   will need to be fixed */

static const USER_FILE_INFO FAR_BSS defaultUserInfo = {
#if 0	/* Disabled since ACL checks are messed up by dual-user, 18/5/02 */
	CRYPT_USER_NONE,				/* Special-case SO+normal user */
#else
	CRYPT_USER_SO,					/* Special-case SO user */
#endif /* 0 */
	USER_STATE_USERINITED,			/* Initialised, ready for use */
	"Default cryptlib user", 21,	/* Pre-set user name */
	"<<<<DEFAULT_USER>>>>", "<<<<DEFAULT_USER>>>>",
	CRYPT_UNUSED					/* No corresponding user file */
	};

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Exit after setting extended error information */

static int exitError( USER_INFO *userInfoPtr,
					  const CRYPT_ATTRIBUTE_TYPE errorLocus,
					  const CRYPT_ERRTYPE_TYPE errorType, const int status )
	{
	setErrorInfo( userInfoPtr, errorLocus, errorType );
	return( status );
	}

static int exitErrorInited( USER_INFO *userInfoPtr,
							const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( userInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_PRESENT, 
					   CRYPT_ERROR_INITED ) );
	}

static int exitErrorNotFound( USER_INFO *userInfoPtr,
							  const CRYPT_ATTRIBUTE_TYPE errorLocus )
	{
	return( exitError( userInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_ABSENT, 
					   CRYPT_ERROR_NOTFOUND ) );
	}

/* Process a set-attribute operation that initiates an operation that's 
   performed in two phases.  The reason for the split is that the second 
   phase doesn't require the use of the user object data any more and can be 
   a somewhat lengthy process due to disk accesses or lengthy crypto 
   operations.  Because of this we unlock the user object between the two 
   phases to ensure that the second phase doesn't stall all other operations 
   that require this user object */

static int processTwoPhaseOperation( USER_INFO *userInfoPtr, 
									 const int messageValue, 
									 const int value )
	{
	const CRYPT_USER iCryptUser = userInfoPtr->objectHandle;
	int refCount, selfTestStatus, status;

	assert( isWritePtr( userInfoPtr, sizeof( USER_INFO ) ) );
	assert( messageValue == CRYPT_OPTION_CONFIGCHANGED || \
			messageValue == CRYPT_OPTION_SELFTESTOK );

	if( messageValue == CRYPT_OPTION_CONFIGCHANGED )
		{
		char userFileName[ 16 + 8 ];
		void *data;
		int length;

		/* The config option write is performed in two phases, a first phase
		   that encodes the config data and a second phase that writes the 
		   data to disk */
		if( userInfoPtr->userFileInfo.fileRef == CRYPT_UNUSED )
			strlcpy_s( userFileName, 16, "cryptlib" );
		else
			sprintf_s( userFileName, 16, "u%06x", 
					   userInfoPtr->userFileInfo.fileRef );
		status = prepareConfigData( userInfoPtr->configOptions,
								    userFileName, userInfoPtr->trustInfoPtr,
								    &data, &length );
		if( status != OK_SPECIAL )
			return( status );

		/* If nothing in the config data has changed, we're done */
		if( length <= 0 && !userInfoPtr->trustInfoChanged )
			return( CRYPT_OK );

		/* We've got the config data in a memory buffer, we can unlock the
		   user object to allow external access while we commit the in-memory
		   data to disk */
		krnlSuspendObject( iCryptUser, &refCount );
		status = commitConfigData( iCryptUser, userFileName, data, length );
		clFree( "userMessageFunction", data );
		krnlResumeObject( iCryptUser, refCount );
		if( cryptStatusOK( status ) )
			userInfoPtr->trustInfoChanged = FALSE;

		return( status );
		}

	/* It's a self-test, forward the message to the system object with 
	   the user object unlocked, tell the system object to perform its self-
	   test, and then re-lock the user object and set the self-test result 
	   value.  Since the self-test config setting will be marked as in-use 
	   at this point (to avoid having another thread update it while the
	   user object was unlocked), it can't be written to directly.  In order
	   to update it, we set the CRYPT_OPTION_LAST pseudo-option to the value 
	   to store in the CRYPT_OPTION_SELFTESTOK option.
	   
	   An alternative way to handle this would be implement an advisory-
	   locking mechanism for config options, but this adds a great deal of
	   complexity just to handle this one single case, so until there's a
	   wider need for general-purpose config option locking the current 
	   approach will do */
	krnlSuspendObject( iCryptUser, &refCount );
	selfTestStatus = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
									  IMESSAGE_SETATTRIBUTE, 
									  ( void * ) &value,
									  CRYPT_IATTRIBUTE_SELFTEST );
	status = krnlResumeObject( iCryptUser, refCount );
	if( cryptStatusOK( status ) )
		status = setOption( userInfoPtr->configOptions, CRYPT_OPTION_LAST,
							cryptStatusOK( selfTestStatus ) ? value : 0 );
	return( status );
	}

static int processUserManagement( USER_INFO *userInfoPtr, 
								  void *messageDataPtr, 
								  const int messageValue )
	{
	assert( isWritePtr( userInfoPtr, sizeof( USER_INFO ) ) );
	assert( messageValue > MESSAGE_USERMGMT_NONE && \
			messageValue < MESSAGE_USERMGMT_LAST );

	switch( messageValue )
		{
		case MESSAGE_USERMGMT_ZEROISE:
			userInfoPtr->flags |= USER_FLAG_ZEROISE;
			return( CRYPT_OK );
		}

	retIntError();
	}

/****************************************************************************
*																			*
*						User Attribute Handling Functions					*
*																			*
****************************************************************************/

/* Handle data sent to or read from a user object */

static int processGetAttribute( USER_INFO *userInfoPtr,
								void *messageDataPtr, const int messageValue )
	{
	int *valuePtr = ( int * ) messageDataPtr;
	int status;

	/* Clear return value */
	*valuePtr = CRYPT_ERROR;

	switch( messageValue )
		{
		case CRYPT_USERINFO_CAKEY_CERTSIGN:
		case CRYPT_USERINFO_CAKEY_CRLSIGN:
		case CRYPT_USERINFO_CAKEY_OCSPSIGN:
			{
			CRYPT_CERTIFICATE caCert;

			/* Make sure that the key type that we're after is present in 
			   the object */
			if( userInfoPtr->iCryptContext == CRYPT_UNUSED )
				return( exitErrorNotFound( userInfoPtr, messageValue ) );

			/* Since the CA signing key tied to the user object is meant to 
			   be used only through cryptlib-internal means, we shouldn't 
			   really be returning it to the caller.  We can return the 
			   ssociated CA cert, but this may be an internal-only object 
			   that the caller can't do anything with.  To avoid this 
			   problem, we isolate the cert by returning a copy of the
			   associated certificate object */
			status = krnlSendMessage( userInfoPtr->iCryptContext, 
									  IMESSAGE_GETATTRIBUTE, &caCert,
									  CRYPT_IATTRIBUTE_CERTCOPY );
			if( cryptStatusOK( status ) )
				*valuePtr = caCert;
			return( status );
			}

		case CRYPT_IATTRIBUTE_CTL:
			{
			MESSAGE_CREATEOBJECT_INFO createInfo;

			/* Check whether there are trusted certs present */
			status = enumTrustedCerts( userInfoPtr->trustInfoPtr,
									   CRYPT_UNUSED, CRYPT_UNUSED );
			if( cryptStatusError( status ) )
				return( status );

			/* Create a cert chain meta-object to hold the overall set of
			   certs */
			setMessageCreateObjectInfo( &createInfo,
										CRYPT_CERTTYPE_CERTCHAIN );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  IMESSAGE_DEV_CREATEOBJECT,
									  &createInfo, OBJECT_TYPE_CERTIFICATE );
			if( cryptStatusError( status ) )
				return( status );

			/* Assemble the trusted certs into the cert chain */
			status = enumTrustedCerts( userInfoPtr->trustInfoPtr,
									   createInfo.cryptHandle, CRYPT_UNUSED );
			if( cryptStatusOK( status ) )
				*valuePtr = createInfo.cryptHandle;
			else
				krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
			return( status );
			}
		}

	/* Anything else has to be a config option */
	assert( messageValue > CRYPT_OPTION_FIRST && \
			messageValue < CRYPT_OPTION_LAST );

	/* A numeric-value get can never fail because we always have default 
	   values present */
	*valuePtr = getOption( userInfoPtr->configOptions, messageValue );
	return( CRYPT_OK );
	}

static int processGetAttributeS( USER_INFO *userInfoPtr,
								 void *messageDataPtr, const int messageValue )
	{
	MESSAGE_DATA *msgData = messageDataPtr;
	const char *stringVal;

	/* This can only be a config option */
	assert( messageValue > CRYPT_OPTION_FIRST && \
			messageValue < CRYPT_OPTION_LAST );

	/* Check whether there's a config value of this type present */
	stringVal = getOptionString( userInfoPtr->configOptions, messageValue );
	if( stringVal == NULL )
		{
		/* No value set, clear the return value in case the caller isn't 
		   checking the return code */
		if( msgData->data != NULL )
			*( ( char * ) msgData->data ) = '\0';
		msgData->length = 0;
		return( CRYPT_ERROR_NOTFOUND );
		}

	return( attributeCopy( msgData, stringVal, strlen( stringVal ) ) );
	}

static int processSetAttribute( USER_INFO *userInfoPtr,
								void *messageDataPtr, const int messageValue )
	{
	const int value = *( ( int * ) messageDataPtr );
	int status;

	switch( messageValue )
		{
		case CRYPT_USERINFO_CAKEY_CERTSIGN:
		case CRYPT_USERINFO_CAKEY_CRLSIGN:
		case CRYPT_USERINFO_CAKEY_OCSPSIGN:
			{
			const int requiredKeyUsage = \
				( messageValue == CRYPT_USERINFO_CAKEY_CERTSIGN ) ? \
					CRYPT_KEYUSAGE_KEYCERTSIGN : \
				( messageValue == CRYPT_USERINFO_CAKEY_CRLSIGN ) ? \
					CRYPT_KEYUSAGE_CRLSIGN : \
					( CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
					  CRYPT_KEYUSAGE_NONREPUDIATION );
			int attributeValue;

			/* Make sure that this key type isn't already present in the 
			   object */
			if( userInfoPtr->iCryptContext != CRYPT_UNUSED )
				return( exitErrorInited( userInfoPtr, messageValue ) );

			/* Make sure that we've been given a signing key */
			status = krnlSendMessage( value, IMESSAGE_CHECK, NULL, 
									  MESSAGE_CHECK_PKC_SIGN );
			if( cryptStatusError( status ) )
				return( CRYPT_ARGERROR_NUM1 );

			/* Make sure that the object has an initialised cert of the
			   correct type associated with it */
			status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE,
									  &attributeValue, 
									  CRYPT_CERTINFO_IMMUTABLE );
			if( cryptStatusError( status ) || !attributeValue )
				return( CRYPT_ARGERROR_NUM1 );
			status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE,
									  &attributeValue, 
									  CRYPT_CERTINFO_CERTTYPE );
			if( cryptStatusError( status ) ||
				( attributeValue != CRYPT_CERTTYPE_CERTIFICATE && \
				  attributeValue != CRYPT_CERTTYPE_CERTCHAIN ) )
				return( CRYPT_ARGERROR_NUM1 );

			/* Make sure that the key usage required for this action is
			   permitted.  OCSP is a bit difficult since the key may or may
			   not have an OCSP extended usage (depending on whether the CA
			   bothers to set it or not, even if they do they may delegate
			   the functionality to a short-term generic signing key) and the
			   signing ability may be indicated by either a digital signature
			   flag or a nonrepudiation flag depending on whether the CA
			   considers an OCSP signature to be short or long-term, so we
			   just check for a generic signing ability */
			status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE,
									  &attributeValue, 
									  CRYPT_CERTINFO_KEYUSAGE );
			if( cryptStatusError( status ) || \
				!( attributeValue & requiredKeyUsage ) )
				return( CRYPT_ARGERROR_NUM1 );

			/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
			/* Save key in the keyset at some point */
			/* Also handle get (gets public key) and /*
			/*			   delete (removes key) */
			/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/

			return( status );
			}

		case CRYPT_IATTRIBUTE_INITIALISED:
			/* If it's an initialisation message, there's nothing to do (we
			   get these when creating the default user object, which doesn't
			   require an explicit logon to move it into the high state) */
			assert( userInfoPtr->objectHandle == DEFAULTUSER_OBJECT_HANDLE );
			return( CRYPT_OK );

		case CRYPT_IATTRUBUTE_CERTKEYSET:
			/* If it's a presence check, handle it specially */
			if( value == CRYPT_UNUSED )
				return( enumTrustedCerts( userInfoPtr->trustInfoPtr,
										  CRYPT_UNUSED, CRYPT_UNUSED ) );

			/* Send all trusted certs to the keyset */
			return( enumTrustedCerts( userInfoPtr->trustInfoPtr, 
									  CRYPT_UNUSED, value ) );

		case CRYPT_IATTRIBUTE_CTL:
			/* Add the certs via the trust list */
			status = addTrustEntry( userInfoPtr->trustInfoPtr,
									value, NULL, 0, FALSE );
			if( cryptStatusOK( status ) )
				userInfoPtr->trustInfoChanged = TRUE;
			return( status );

		case CRYPT_IATTRIBUTE_CERT_TRUSTED:
			/* Add the cert to the trust info */
			status = addTrustEntry( userInfoPtr->trustInfoPtr, value,
									NULL, 0, TRUE );
			if( cryptStatusOK( status ) )
				{
				userInfoPtr->trustInfoChanged = TRUE;
				setOption( userInfoPtr->configOptions,
						   CRYPT_OPTION_CONFIGCHANGED, TRUE );
				}
			return( status );

		case CRYPT_IATTRIBUTE_CERT_UNTRUSTED:
			{
			void *entryToDelete;

			/* This is a rather ugly operation since what we're actually
			   doing is removing a cert and not adding it, however we
			   can't do this via an attribute delete because that just
			   deletes a CRYPT_IATTRIBUTE_CERT_TRUSTED as an attribute, 
			   but can't identify which trusted cert to delete.  A similar
			   problem occurs with CRYPT_IATTRIBUTE_CERT_TRUSTEDISSUER
			   below */

			/* Find the entry to delete and remove it */
			if( ( entryToDelete = findTrustEntry( userInfoPtr->trustInfoPtr,
												  value, FALSE ) ) == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			deleteTrustEntry( userInfoPtr->trustInfoPtr, entryToDelete );
			userInfoPtr->trustInfoChanged = TRUE;
			setOption( userInfoPtr->configOptions,
					   CRYPT_OPTION_CONFIGCHANGED, TRUE );
			return( CRYPT_OK );
			}

		case CRYPT_IATTRIBUTE_CERT_CHECKTRUST:
			{
			int certType;

			/* We can't perform this action as a MESSAGE_CHECK because these
			   are sent to the object being checked (the certificate in this
			   case) rather than the user object that it's associated with, 
			   so we have to do it as a pseudo-attribute-set action */
			status = krnlSendMessage( value, IMESSAGE_GETATTRIBUTE, 
									  &certType, CRYPT_CERTINFO_CERTTYPE );
			if( cryptStatusError( status ) || \
				( certType != CRYPT_CERTTYPE_CERTIFICATE && \
				  certType != CRYPT_CERTTYPE_CERTCHAIN ) )
				/* A non-cert can never be implicitly trusted */
				return( FALSE );

			/* Check whether the cert is present in the trusted certs
			   collection */
			return( ( findTrustEntry( userInfoPtr->trustInfoPtr, value,
									  FALSE ) != NULL ) ? \
					CRYPT_OK : CRYPT_ERROR_INVALID );
			}

		case CRYPT_IATTRIBUTE_CERT_TRUSTEDISSUER:
			{
			void *trustedIssuerInfo;
			int trustedCert;

			/* This is a highly nonstandard use of integer parameters that
			   passes in the user cert as its parameter and returns the
			   issuer cert in the same parameter, overwriting the user
			   cert value.  This is the sole message that does this,
			   unfortunately there's no clean way to handle this without
			   implementing a new message type for this purpose.  Since the
			   kernel is stateless it can only look at the parameter value
			   but not detect that it's changed during the call, so it works
			   for now, but it would be nicer to find some way to fix this */
			trustedIssuerInfo = findTrustEntry( userInfoPtr->trustInfoPtr,
												value, TRUE );
			if( trustedIssuerInfo == NULL )
				return( CRYPT_ERROR_NOTFOUND );

			/* Get the issuer cert and return it to the caller */
			trustedCert = getTrustedCert( trustedIssuerInfo );
			if( cryptStatusError( trustedCert ) )
				return( trustedCert );
			assert( trustedCert != value );
			*( ( int * ) messageDataPtr ) = trustedCert;
			return( CRYPT_OK );
			}
		}

	/* Anything else has to be a config option */
	assert( messageValue > CRYPT_OPTION_FIRST && \
			messageValue < CRYPT_OPTION_LAST );

	/* Set the option.  If it's not one of the two special options with 
	   side-effects, we're done */
	status = setOption( userInfoPtr->configOptions, messageValue, value );
	if( messageValue != CRYPT_OPTION_CONFIGCHANGED && \
		messageValue != CRYPT_OPTION_SELFTESTOK )
		return( status );

	/* If there was a problem setting a side-effects option, don't go any 
	   further */
	if( status != OK_SPECIAL )
		return( status );

	/* Complete the processing of the special options */
	return( processTwoPhaseOperation( userInfoPtr, messageValue, value ) );
	}

static int processSetAttributeS( USER_INFO *userInfoPtr,
								 void *messageDataPtr, const int messageValue )
	{
	MESSAGE_DATA *msgData = messageDataPtr;

	switch( messageValue )
		{
		case CRYPT_USERINFO_PASSWORD:
			return( setUserPassword( userInfoPtr, msgData->data,
									 msgData->length ) );
		}

	/* Anything else has to be a config option */
	assert( messageValue > CRYPT_OPTION_FIRST && \
			messageValue < CRYPT_OPTION_LAST );
	return( setOptionString( userInfoPtr->configOptions, messageValue, 
							 msgData->data, msgData->length ) );
	}

static int processDeleteAttribute( USER_INFO *userInfoPtr,
								   const int messageValue )
	{
	switch( messageValue )
		{
		case CRYPT_USERINFO_CAKEY_CERTSIGN:
		case CRYPT_USERINFO_CAKEY_CRLSIGN:
		case CRYPT_USERINFO_CAKEY_OCSPSIGN:
			return( CRYPT_ERROR_NOTFOUND );
		}

	/* Anything else has to be a config option */
	assert( messageValue > CRYPT_OPTION_FIRST && \
			messageValue < CRYPT_OPTION_LAST );

	/* Only string attributes can be deleted (enforced by the kernel), so we 
	   can safely pass all calls through to the set-string function */
	return( setOptionString( userInfoPtr->configOptions, messageValue, 
							 NULL, 0 ) );
	}

/****************************************************************************
*																			*
*							General User Object Functions					*
*																			*
****************************************************************************/

/* Handle a message sent to a user object */

static int userMessageFunction( void *objectInfoPtr,
								const MESSAGE_TYPE message,
								void *messageDataPtr, const int messageValue )
	{
	USER_INFO *userInfoPtr = ( USER_INFO * ) objectInfoPtr;

	/* Process destroy object messages */
	if( message == MESSAGE_DESTROY )
		{
		/* Clean up any user-related crypto objects if necessary */
		if( userInfoPtr->iCryptContext != CRYPT_ERROR )
			krnlSendNotifier( userInfoPtr->iCryptContext,
							  IMESSAGE_DECREFCOUNT );
		if( userInfoPtr->iKeyset != CRYPT_ERROR )
			krnlSendNotifier( userInfoPtr->iKeyset, IMESSAGE_DECREFCOUNT );

		/* If we're doing a zeroise, clear any persistent user data */
		if( userInfoPtr->flags & USER_FLAG_ZEROISE )
			zeroiseUsers( userInfoPtr );

		/* Clean up the trust info and config options */
		endTrustInfo( userInfoPtr->trustInfoPtr );
		endOptions( userInfoPtr->configOptions );
		endUserIndex( userInfoPtr->userIndexPtr );

		return( CRYPT_OK );
		}

	/* If we're doing a zeroise, don't process any further messages except a 
	   destroy */
	if( userInfoPtr->flags & USER_FLAG_ZEROISE )
		return( CRYPT_ERROR_PERMISSION );

	/* Process attribute get/set/delete messages */
	if( isAttributeMessage( message ) )
		{
		if( message == MESSAGE_GETATTRIBUTE )
			return( processGetAttribute( userInfoPtr, messageDataPtr,
										 messageValue ) );
		if( message == MESSAGE_GETATTRIBUTE_S )
			return( processGetAttributeS( userInfoPtr, messageDataPtr,
										  messageValue ) );
		if( message == MESSAGE_SETATTRIBUTE )
			return( processSetAttribute( userInfoPtr, messageDataPtr,
										 messageValue ) );
		if( message == MESSAGE_SETATTRIBUTE_S )
			return( processSetAttributeS( userInfoPtr, messageDataPtr,
										  messageValue ) );
		if( message == MESSAGE_DELETEATTRIBUTE )
			return( processDeleteAttribute( userInfoPtr, messageValue ) );

		assert( NOTREACHED );
		return( CRYPT_ERROR );	/* Get rid of compiler warning */
		}

	/* Process object-specific messages */
	if( message == MESSAGE_USER_USERMGMT )
		return( processUserManagement( userInfoPtr, messageDataPtr,
									   messageValue ) );

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}

/* Open a user object.  This is a low-level function encapsulated by
   createUser() and used to manage error exits */

static int openUser( CRYPT_USER *iCryptUser, const CRYPT_USER cryptOwner,
					 const USER_FILE_INFO *userInfoTemplate,
					 USER_INFO **userInfoPtrPtr )
	{
	USER_INFO *userInfoPtr;
	USER_FILE_INFO *userFileInfo;
	const OBJECT_SUBTYPE subType = \
		( userInfoTemplate->type == CRYPT_USER_SO ) ? SUBTYPE_USER_SO : \
		( userInfoTemplate->type == CRYPT_USER_CA ) ? SUBTYPE_USER_CA : \
		SUBTYPE_USER_NORMAL;
	int status;

	/* The default user is a special type that has both normal user and SO
	   privileges.  This is because in its usual usage mode where cryptlib 
	   is functioning as a single-user system the user doesn't know about 
	   the existence of user objects and just wants everything to work the 
	   way that they expect.  Because of this, the default user has to be 
	   able to perform the full range of available operations, requiring 
	   that they appear as both a normal user and an SO */
#if 0	/* Disabled since ACL checks are messed up by dual-user, 18/5/02 */
	assert( userInfoTemplate->type == CRYPT_USER_NORMAL || \
			userInfoTemplate->type == CRYPT_USER_SO || \
			userInfoTemplate->type == CRYPT_USER_CA || \
			( userInfoTemplate->type == CRYPT_USER_NONE && \
			  userInfoTemplate->userNameLength == \
								defaultUserInfo.userNameLength && \
			  !memcmp( userInfoTemplate->userName, defaultUserInfo.userName,
					   defaultUserInfo.userNameLength ) ) );
#else
	assert( userInfoTemplate->type == CRYPT_USER_NORMAL || \
			userInfoTemplate->type == CRYPT_USER_SO || \
			userInfoTemplate->type == CRYPT_USER_CA );
#endif /* 0 */

	/* Clear return values */
	*iCryptUser = CRYPT_ERROR;
	*userInfoPtrPtr = NULL;

	/* Create the user object */
	status = krnlCreateObject( ( void ** ) &userInfoPtr, sizeof( USER_INFO ),
							   OBJECT_TYPE_USER, subType,
							   CREATEOBJECT_FLAG_NONE, cryptOwner,
							   ACTION_PERM_NONE_ALL, userMessageFunction );
	if( cryptStatusError( status ) )
		return( status );
	*userInfoPtrPtr = userInfoPtr;
	*iCryptUser = userInfoPtr->objectHandle = status;
	userFileInfo = &userInfoPtr->userFileInfo;
	userFileInfo->type = userInfoTemplate->type;
	userFileInfo->state = userInfoTemplate->state;
	userFileInfo->fileRef = userInfoTemplate->fileRef;
	memcpy( userFileInfo->userName, userInfoTemplate->userName,
			userInfoTemplate->userNameLength );
	userFileInfo->userNameLength = userInfoTemplate->userNameLength;
	memcpy( userFileInfo->userID, userInfoTemplate->userID, KEYID_SIZE );
	memcpy( userFileInfo->creatorID, userInfoTemplate->creatorID, KEYID_SIZE );

	/* Set up any internal objects to contain invalid handles */
	userInfoPtr->iKeyset = userInfoPtr->iCryptContext = CRYPT_ERROR;

	/* Initialise the config options and trust info */
	status = initTrustInfo( &userInfoPtr->trustInfoPtr );
	if( cryptStatusOK( status ) )
		status = initOptions( &userInfoPtr->configOptions );
	return( status );
	}

int createUser( MESSAGE_CREATEOBJECT_INFO *createInfo,
				const void *auxDataPtr, const int auxValue )
	{
	CRYPT_USER iCryptUser;
	USER_INFO *userInfoPtr;
	char userFileName[ 16 + 8 ];
	int fileRef, initStatus, status;

	assert( auxDataPtr == NULL );
	assert( auxValue == 0 );

	/* Perform basic error checking */
	if( createInfo->strArgLen1 < MIN_NAME_LENGTH || \
		createInfo->strArgLen1 > CRYPT_MAX_TEXTSIZE )
		return( CRYPT_ARGERROR_STR1 );
	if( createInfo->strArgLen2 < MIN_NAME_LENGTH || \
		createInfo->strArgLen2 > CRYPT_MAX_TEXTSIZE )
		return( CRYPT_ARGERROR_STR2 );

	/* We can't create another user object with the same name as the
	   cryptlib default user (actually we could and nothing bad would happen,
	   but we reserve the use of this name just in case) */
	if( createInfo->strArgLen1 == defaultUserInfo.userNameLength && \
		!strCompare( createInfo->strArg1, defaultUserInfo.userName,
					 defaultUserInfo.userNameLength ) )
		return( CRYPT_ERROR_INITED );

/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
/* Problem: Access to any user info is via the root user object, however */
/* we don't have access to it at this point.  Pass it in as auxDataPtr? */
/* Need to differentiate cryptCreateUser() vs. cryptLogin(), login uses */
/* the default user object as its target?  This is complex, we really */
/* need to target the message at the default user to get access to the user */
/* info index, but then it won't go through cryptdev's create-object- */
/* handling any more */
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
#if 0
	/* Find the user information for the given user */
	status = fileRef = findUserIndexEntry( USERID_NAME, createInfo->strArg1,
										   createInfo->strArgLen1 );
	if( cryptStatusError( status ) )
		{
		/* If we get a special-case OK status, we're in the zeroised state
		   with no user info present, make sure that the user is logging in
		   with the default SO password */
		if( status == OK_SPECIAL )
			status = ( isZeroisePassword( createInfo->strArg2, \
										  createInfo->strArgLen2 ) ) ? \
					 CRYPT_OK : CRYPT_ERROR_WRONGKEY;
		if( cryptStatusError( status ) )
			return( status );
		fileRef = -1;	/* No user file present yet for primary SO */

		/* We're logging in as the primary SO with the SO default password,
		   create the primary SO user object */
		assert( isZeroisePassword( createInfo->strArg2, \
								   createInfo->strArgLen2 ) );
		initStatus = openUser( &iCryptUser, createInfo->cryptOwner,
							   getPrimarySoUserInfo(), &userInfoPtr );
		}
	else
		{
		USER_FILE_INFO userFileInfo;

		/* We're in the non-zeroised state, no user can use the default SO
		   password */
		if( isZeroisePassword( createInfo->strArg2, createInfo->strArgLen2 ) )
			return( CRYPT_ERROR_WRONGKEY );

		/* Read the user info from the user file and perform access
		   verification */
		status = getCheckUserInfo( &userFileInfo, fileRef );
		if( cryptStatusError( status ) )
			return( status );

		/* Pass the call on to the lower-level open function */
		assert( createInfo->strArgLen1 == userFileInfo.userNameLength && \
				!memcmp( createInfo->strArg1, userFileInfo.userName,
						 userFileInfo.userNameLength ) );
		initStatus = openUser( &iCryptUser, createInfo->cryptOwner,
							   &userFileInfo, &userInfoPtr );
		zeroise( &userFileInfo, sizeof( USER_FILE_INFO ) );
		}
#endif
/*!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
{	/* Get rid of compiler warnings */
userInfoPtr = NULL;
initStatus = CRYPT_ERROR_FAILED;
iCryptUser = CRYPT_UNUSED;
fileRef = 0;
}
	if( userInfoPtr == NULL )
		return( initStatus );	/* Create object failed, return immediately */
	if( cryptStatusError( initStatus ) )
		/* The init failed, make sure that the object gets destroyed when we
		   notify the kernel that the setup process is complete */
		krnlSendNotifier( iCryptUser, IMESSAGE_DESTROY );

	/* We've finished setting up the object-type-specific info, tell the
	   kernel that the object is ready for use */
	status = krnlSendMessage( iCryptUser, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );

	/* If the user object has a corresponding user info file, read any
	   stored config options into the object.  We have to do this after
	   it's initialised because the config data, coming from an external
	   (and therefore untrusted) source has to go through the kernel's
	   ACL checking */
	if( fileRef >= 0 )
		{
		sprintf_s( userFileName, 16, "u%06x", fileRef );
		readConfig( iCryptUser, userFileName, userInfoPtr->trustInfoPtr );
		}
	createInfo->cryptHandle = iCryptUser;
	return( CRYPT_OK );
	}

/* Create the default user object */

static int createDefaultUserObject( void )
	{
	CRYPT_USER iUserObject;
	USER_INFO *userInfoPtr;
	int initStatus, status;

	/* Pass the call on to the lower-level open function.  This user is
	   unique and has no owner or type.

	   Normally if an object init fails we tell the kernel to destroy it by 
	   sending it a destroy message, which is processed after the object's 
	   status has been set to normal.  However we don't have the privileges 
	   to do this for the default user object (or the system object) so we 
	   just pass the error code back to the caller, which causes the 
	   cryptlib init to fail.

	   In addition the init can fail in one of two ways, the object isn't
	   even created (deviceInfoPtr == NULL, nothing to clean up), in which 
	   case we bail out immediately, or the object is created but wasn't set 
	   up properly (deviceInfoPtr is allocated, but the object can't be 
	   used), in which case we bail out after we update its status */
	initStatus = openUser( &iUserObject, SYSTEM_OBJECT_HANDLE, &defaultUserInfo,
						   &userInfoPtr );
	if( userInfoPtr == NULL )
		return( initStatus );	/* Create object failed, return immediately */
	assert( iUserObject == DEFAULTUSER_OBJECT_HANDLE );
	if( cryptStatusOK( initStatus ) )
		{
		/* Read the user index.  We make this part of the object init because
		   it's used for access control, unlike the config option read where
		   we can fall back to defaults if there's a problem this one is
		   critical enough that we abort the cryptlib init if it fails */
		initStatus = initUserIndex( &userInfoPtr->userIndexPtr );
		}

	/* We've finished setting up the object-type-specific info, tell the
	   kernel that the object is ready for use */
	status = krnlSendMessage( iUserObject, IMESSAGE_SETATTRIBUTE,
							  MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS );
	if( cryptStatusError( initStatus ) || cryptStatusError( status ) )
		return( cryptStatusError( initStatus ) ? initStatus : status );

	/* Read any stored config options into the object.  We have to do this 
	   after it's initialised because the config data, coming from an 
	   external (and therefore untrusted) source has to go through the 
	   kernel's ACL checking.  Note that even if the read fails we don't do 
	   anything (except throw an exception in the debug build) since we 
	   don't want the whole cryptlib init to fail because of a wrong entry 
	   in a file */
	status = readConfig( iUserObject, "cryptlib", userInfoPtr->trustInfoPtr );
	assert( cryptStatusOK( status ) );

	/* The object has been initialised, move it into the initialised state */
	return( krnlSendMessage( iUserObject, IMESSAGE_SETATTRIBUTE, 
							 MESSAGE_VALUE_UNUSED, 
							 CRYPT_IATTRIBUTE_INITIALISED ) );
	}

/* Generic management function for this class of object */

int userManagementFunction( const MANAGEMENT_ACTION_TYPE action )
	{
	assert( action == MANAGEMENT_ACTION_INIT );

	switch( action )
		{
		case MANAGEMENT_ACTION_INIT:
			return( createDefaultUserObject() );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR );	/* Get rid of compiler warning */
	}
