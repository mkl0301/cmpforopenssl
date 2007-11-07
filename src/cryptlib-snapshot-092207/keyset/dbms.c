/****************************************************************************
*																			*
*						 cryptlib DBMS Back-end Interface					*
*						Copyright Peter Gutmann 1996-2006					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdarg.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "dbms.h"
  #include "rpc.h"
#else
  #include "crypt.h"
  #include "keyset/keyset.h"
  #include "keyset/dbms.h"
  #include "misc/rpc.h"
#endif /* Compiler-specific includes */

#ifdef USE_DBMS

/****************************************************************************
*																			*
*						Network Database Interface Routines					*
*																			*
****************************************************************************/

#ifdef USE_DATABASE_PLUGIN

#ifdef USE_RPCAPI

static void netEncodeError( BYTE *buffer, const int status )
	{
	putMessageType( buffer, COMMAND_RESULT, 0, 1, 0 );
	putMessageLength( buffer + COMMAND_WORDSIZE, COMMAND_WORDSIZE );
	putMessageWord( buffer + COMMAND_WORD1_OFFSET, status );
	}

void netProcessCommand( void *stateInfo, BYTE *buffer )
	{
	DBMS_STATE_INFO *dbmsInfo = ( DBMS_STATE_INFO * ) stateInfo;
	COMMAND_INFO cmd;
	int length, status;

	memset( &cmd, 0, sizeof( COMMAND_INFO ) );

	/* Get the messge information from the header */
	getMessageType( buffer, cmd.type, cmd.flags,
					cmd.noArgs, cmd.noStrArgs );
	length = getMessageLength( buffer + COMMAND_WORDSIZE );
	if( cmd.type == DBX_COMMAND_OPEN )
		{
		NET_CONNECT_INFO connectInfo;
		BYTE *bufPtr = buffer + COMMAND_FIXED_DATA_SIZE + COMMAND_WORDSIZE;
		int nameLen;

		/* Get the length of the server name and null-terminate it */
		nameLen = getMessageWord( bufPtr );
		bufPtr += COMMAND_WORDSIZE;
		bufPtr[ nameLen ] = '\0';

		/* Connect to the plugin */
		initNetConnectInfo( &connectInfo, DEFAULTUSER_OBJECT_HANDLE,
							CRYPT_ERROR, CRYPT_ERROR, NET_OPTION_HOSTNAME );
		connectInfo.name = bufPtr;
		status = sNetConnect( &dbmsInfo->stream, STREAM_PROTOCOL_TCPIP,
							  &connectInfo, dbmsInfo->errorMessage,
							  &dbmsInfo->errorCode );
		if( cryptStatusError( status ) )
			{
			netEncodeError( buffer, status );
			return;
			}
		}

	/* Send the command to the plugin and read back the response */
	status = swrite( &dbmsInfo->stream, buffer,
					 COMMAND_FIXED_DATA_SIZE + COMMAND_WORDSIZE + length );
	if( cryptStatusOK( status ) )
		status = sread( &dbmsInfo->stream, buffer, COMMAND_FIXED_DATA_SIZE );
	if( !cryptStatusError( status ) )
		{
		/* Perform a consistency check on the returned data */
		getMessageType( buffer, cmd.type, cmd.flags,
						cmd.noArgs, cmd.noStrArgs );
		length = getMessageLength( buffer + COMMAND_WORDSIZE );
		if( !dbxCheckCommandInfo( &cmd, length ) || \
			cmd.type != COMMAND_RESULT )
			status = CRYPT_ERROR_BADDATA;
		}
	if( !cryptStatusError( status ) )
		/* Read the rest of the message */
		status = sread( &dbmsInfo->stream, buffer + COMMAND_FIXED_DATA_SIZE,
						length );

	/* If it's a close command, terminate the connection to the plugin.  We
	   don't do any error checking once we get this far since there's not
	   much that we can still do at this point */
	if( cmd.type == DBX_COMMAND_CLOSE )
		sNetDisconnect( &dbmsInfo->stream );
	else
		if( cryptStatusError( status ) )
			netEncodeError( buffer, status );
	}
#else

int initDispatchNet( DBMS_INFO *dbmsInfo )
	{
	return( CRYPT_ERROR );
	}
#endif /* USE_RPCAPI */

#endif /* USE_DATABASE_PLUGIN */

/****************************************************************************
*																			*
*							Database RPC Routines							*
*																			*
****************************************************************************/

/* Dispatch functions for various database types.  ODBC is the native keyset
   for Windows and (if possible) Unix, a cryptlib-native plugin is the
   fallback for Unix, and the rest are only accessible via database network
   plugins */

#ifdef USE_ODBC
  #ifdef USE_RPCAPI
	void odbcProcessCommand( void *stateInfo, BYTE *buffer );
	#define initDispatchODBC( dbmsInfo ) \
			( dbmsInfo->dispatchFunction = odbcProcessCommand ) != NULL
  #else
	int initDispatchODBC( DBMS_INFO *dbmsInfo );
  #endif /* USE_RPCAPI */
#else
  #define initDispatchODBC( dbmsInfo )		CRYPT_ERROR
#endif /* USE_ODBC */
#if defined( USE_DATABASE )
  #ifdef USE_RPCAPI
	void databaseProcessCommand( void *stateInfo, BYTE *buffer );
	#define initDispatchDatabase( dbmsInfo ) \
			( dbmsInfo->dispatchFunction = databaseProcessCommand ) != NULL
  #else
	int initDispatchDatabase( DBMS_INFO *dbmsInfo );
  #endif /* USE_RPCAPI */
#else
  #define initDispatchDatabase( dbmsInfo )	CRYPT_ERROR
#endif /* General database interface */
#ifdef USE_DATABASE_PLUGIN
  #ifdef USE_RPCAPI
	void netProcessCommand( void *stateInfo, BYTE *buffer );
	#define initDispatchNet( dbmsInfo ) \
			( dbmsInfo->dispatchFunction = netProcessCommand ) != NULL
  #else
	int initDispatchNet( DBMS_INFO *dbmsInfo );
  #endif /* USE_RPCAPI */
#else
  #define initDispatchNet( dbmsInfo )		CRYPT_ERROR
#endif /* USE_DATABASE_PLUGIN */

/* Make sure that we can fit the largest possible SQL query into the RPC
   buffer */

#if MAX_SQL_QUERY_SIZE + 256 >= DBX_IO_BUFSIZE
  #error Database RPC buffer size is too small, increase DBX_IO_BUFSIZE and rebuild
#endif /* SQL query size larger than RPC buffer size */

#ifdef USE_RPCAPI

/* Dispatch data to the back-end */

static int dispatchCommand( COMMAND_INFO *cmd, void *stateInfo,
							DISPATCH_FUNCTION dispatchFunction )
	{
	COMMAND_INFO sentCmd = *cmd;
	BYTE buffer[ DBX_IO_BUFSIZE + 8 ], *bufPtr = buffer;
	BYTE header[ COMMAND_FIXED_DATA_SIZE + 8 ];
	const int payloadLength = ( cmd->noArgs * COMMAND_WORDSIZE ) + \
							  ( cmd->noStrArgs * COMMAND_WORDSIZE ) + \
							  cmd->strArgLen[ 0 ] + cmd->strArgLen[ 1 ] + \
							  cmd->strArgLen[ 2 ];
	long resultLength;
	int i;

	assert( payloadLength + 32 < DBX_IO_BUFSIZE );
	assert( dispatchFunction != NULL );

	/* Clear the return value */
	memset( cmd, 0, sizeof( COMMAND_INFO ) );

	/* Write the header and message fields to the buffer */
	putMessageType( bufPtr, sentCmd.type, sentCmd.flags,
					sentCmd.noArgs, sentCmd.noStrArgs );
	putMessageLength( bufPtr + COMMAND_WORDSIZE, payloadLength );
	bufPtr += COMMAND_FIXED_DATA_SIZE;
	for( i = 0; i < sentCmd.noArgs; i++ )
		{
		putMessageWord( bufPtr, sentCmd.arg[ i ] );
		bufPtr += COMMAND_WORDSIZE;
		}
	for( i = 0; i < sentCmd.noStrArgs; i++ )
		{
		const int argLength = sentCmd.strArgLen[ i ];

		putMessageWord( bufPtr, argLength );
		if( argLength > 0 )
			memcpy( bufPtr + COMMAND_WORDSIZE, sentCmd.strArg[ i ],
					argLength );
		bufPtr += COMMAND_WORDSIZE + argLength;
		}

	/* Send the command to the server and read back the server's message
	   header */
	dispatchFunction( stateInfo, buffer );
	memcpy( header, buffer, COMMAND_FIXED_DATA_SIZE );

	/* Process the fixed message header and make sure that it's valid */
	getMessageType( header, cmd->type, cmd->flags,
					cmd->noArgs, cmd->noStrArgs );
	resultLength = getMessageLength( header + COMMAND_WORDSIZE );
	if( !dbxCheckCommandInfo( cmd, resultLength ) || \
		cmd->type != COMMAND_RESULT )
		return( CRYPT_ERROR );
	if( ( cmd->noStrArgs && cmd->strArgLen[ 0 ] ) && \
		( sentCmd.type != DBX_COMMAND_QUERY && \
		  sentCmd.type != DBX_COMMAND_GETERRORINFO ) )
		/* Only these commands can return data */
		return( CRYPT_ERROR );

	/* Read the rest of the server's message */
	bufPtr = buffer + COMMAND_FIXED_DATA_SIZE;
	for( i = 0; i < cmd->noArgs; i++ )
		{
		cmd->arg[ i ] = getMessageWord( bufPtr );
		bufPtr += COMMAND_WORDSIZE;
		}
	for( i = 0; i < cmd->noStrArgs; i++ )
		{
		cmd->strArgLen[ i ] = getMessageWord( bufPtr );
		cmd->strArg[ i ] = bufPtr + COMMAND_WORDSIZE;
		bufPtr += COMMAND_WORDSIZE + cmd->strArgLen[ i ];
		}

	/* The first value returned is the status code, if it's nonzero return
	   it to the caller, otherwise move the other values down */
	if( cryptStatusError( cmd->arg[ 0 ] ) )
		return( cmd->arg[ 0 ] );
	assert( cryptStatusOK( cmd->arg[ 0 ] ) );
	for( i = 1; i < cmd->noArgs; i++ )
		cmd->arg[ i - 1 ] = cmd->arg[ i ];
	cmd->arg[ i ] = 0;
	cmd->noArgs--;

	/* Copy any string arg data back to the caller */
	if( cmd->noStrArgs && cmd->strArgLen[ 0 ] )
		{
		const int maxBufSize = ( sentCmd.type == DBX_COMMAND_QUERY ) ? \
							   MAX_QUERY_RESULT_SIZE : MAX_ERRMSG_SIZE;
		const int argIndex = sentCmd.noStrArgs;

		memcpy( sentCmd.strArg[ argIndex ], cmd->strArg[ 0 ],
				min( cmd->strArgLen[ 0 ], maxBufSize ) );
		cmd->strArg[ 0 ] = sentCmd.strArg[ argIndex ];
		}

	return( CRYPT_OK );
	}

/* Initialise query data prior to sending it to the database back-end */

static int initQueryData( COMMAND_INFO *cmd, const COMMAND_INFO *cmdTemplate,
						  BYTE *encodedDate, DBMS_INFO *dbmsInfo,
						  const char *command, const void *boundData,
						  const int boundDataLength, const time_t boundDate,
						  const int type )
	{
	int argIndex = 1;

	memcpy( cmd, cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd->arg[ 0 ] = type;
	if( command != NULL )
		{
		cmd->strArg[ 0 ] = ( void * ) command;
		cmd->strArgLen[ 0 ] = strlen( command );
		}
	if( boundDate > 0 )
		{
#ifndef SYSTEM_64BIT
		assert( sizeof( time_t ) <= 4 );
#endif /* !SYSTEM_64BIT */

		/* Encode the date as a 64-bit value */
		memset( encodedDate, 0, 8 );
#ifdef SYSTEM_64BIT
		encodedDate[ 3 ] = ( BYTE )( ( boundDate >> 32 ) & 0xFF );
#endif /* SYSTEM_64BIT */
		encodedDate[ 4 ] = ( BYTE )( ( boundDate >> 24 ) & 0xFF );
		encodedDate[ 5 ] = ( BYTE )( ( boundDate >> 16 ) & 0xFF );
		encodedDate[ 6 ] = ( BYTE )( ( boundDate >> 8 ) & 0xFF );
		encodedDate[ 7 ] = ( BYTE )( ( boundDate ) & 0xFF );
		cmd->noStrArgs++;
		cmd->strArg[ argIndex ] = encodedDate;
		cmd->strArgLen[ argIndex++ ] = 8;
		}
	if( boundData != NULL )
		{
		/* Copy the bound data into non-ephemeral storage where it'll be
		   accessible to the back-end */
		memcpy( dbmsInfo->boundData, boundData, boundDataLength );
		cmd->noStrArgs++;
		cmd->strArg[ argIndex ] = dbmsInfo->boundData;
		cmd->strArgLen[ argIndex++ ] = boundDataLength;
		}

	return( argIndex );
	}

/* Database access functions */

static int openDatabase( DBMS_INFO *dbmsInfo, const char *name,
						 const int nameLength, const int options, 
						 int *featureFlags )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ DBX_COMMAND_OPEN, COMMAND_FLAG_NONE, 1, 1 };
	COMMAND_INFO cmd;
	int status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = options;
	cmd.strArg[ 0 ] = ( void * ) name;
	cmd.strArgLen[ 0 ] = nameLength;
	status = DISPATCH_COMMAND_DBX( cmdOpen, cmd, dbmsInfo );
	if( cryptStatusOK( status ) && \
		( cmd.arg[ 0 ] & DBMS_HAS_BINARYBLOBS ) )
		dbmsInfo->flags |= DBMS_FLAG_BINARYBLOBS;
	return( status );
	}

static void closeDatabase( DBMS_INFO *dbmsInfo )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ DBX_COMMAND_CLOSE, COMMAND_FLAG_NONE, 0, 0 };
	COMMAND_INFO cmd;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	DISPATCH_COMMAND_DBX( cmdClose, cmd, dbmsInfo );
	}

static void performErrorQuery( DBMS_INFO *dbmsInfo )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ DBX_COMMAND_GETERRORINFO, COMMAND_FLAG_NONE, 0, 1 };
	COMMAND_INFO cmd;
	int status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );

	/* Clear the return values */
	memset( dbmsInfo->errorMessage, 0, MAX_ERRMSG_SIZE );
	dbmsInfo->errorCode = 0;

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.strArg[ 0 ] = dbmsInfo->errorMessage;
	cmd.strArgLen[ 0 ] = 0;
	status = DISPATCH_COMMAND_DBX( cmdGetErrorInfo, cmd, dbmsInfo );
	if( cryptStatusOK( status ) )
		{
		dbmsInfo->errorCode = cmd.arg[ 0 ];
		dbmsInfo->errorMessage[ cmd.strArgLen[ 0 ] ] = '\0';
		}
	}

static int performUpdate( DBMS_INFO *dbmsInfo, const char *command,
						  const void *boundData, const int boundDataLength,
						  const time_t boundDate,
						  const DBMS_UPDATE_TYPE updateType )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ DBX_COMMAND_UPDATE, COMMAND_FLAG_NONE, 1, 1 };
	COMMAND_INFO cmd;
	BYTE encodedDate[ 8 + 8 ];
	int status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( updateType > DBMS_UPDATE_NONE && \
			updateType < DBMS_UPDATE_LAST );

	/* If we're trying to abort a transaction that was never begun, don't
	   do anything */
	if( updateType == DBMS_UPDATE_ABORT && \
		!( dbmsInfo->flags & DBMS_FLAG_UPDATEACTIVE ) )
		return( CRYPT_OK );

	/* Dispatch the command */
	initQueryData( &cmd, &cmdTemplate, encodedDate, dbmsInfo, command,
				   boundData, boundDataLength, boundDate, updateType );
	status = DISPATCH_COMMAND_DBX( cmdUpdate, cmd, dbmsInfo );
	if( cryptStatusError( status ) )
		performErrorQuery( dbmsInfo );
	else
		{
		/* If we're starting or ending an update, record the update state */
		if( updateType == DBMS_UPDATE_BEGIN )
			dbmsInfo->flags |= DBMS_FLAG_UPDATEACTIVE;
		if( updateType == DBMS_UPDATE_COMMIT || \
			updateType == DBMS_UPDATE_ABORT )
			dbmsInfo->flags &= ~DBMS_FLAG_UPDATEACTIVE;
		}
	return( status );
	}

static int performStaticUpdate( DBMS_INFO *dbmsInfo, const char *command )
	{
	return( performUpdate( dbmsInfo, command, NULL, 0, 0,
						   DBMS_UPDATE_NORMAL ) );
	}

static int performQuery( DBMS_INFO *dbmsInfo, const char *command,
						 char *data, int *dataLength, const char *queryData,
						 const int queryDataLength, const time_t queryDate,
						 const DBMS_CACHEDQUERY_TYPE queryEntry,
						 const DBMS_QUERY_TYPE queryType )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ DBX_COMMAND_QUERY, COMMAND_FLAG_NONE, 2, 1 };
	COMMAND_INFO cmd;
	BYTE encodedDate[ 8 + 8 ];
	int argIndex, status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( ( data == NULL && dataLength == NULL ) || \
			isWritePtr( data, 16 ) );
	assert( ( queryData == NULL && queryDataLength == 0 ) || \
			( queryDataLength > 0 && \
			  isReadPtr( queryData, queryDataLength ) ) );
	assert( queryEntry >= DBMS_CACHEDQUERY_NONE && \
			queryEntry < DBMS_CACHEDQUERY_LAST );
	assert( queryType > DBMS_QUERY_NONE && queryType < DBMS_QUERY_LAST );

	/* Additional state checks: If we're starting a new query or performing
	   a point query there can't already be one active, and if we're
	   continuing or cancelling an existing query there has to be one
	   already active */
	if( ( ( queryType == DBMS_QUERY_START || \
			queryType == DBMS_QUERY_CHECK || \
			queryType == DBMS_QUERY_NORMAL ) && \
		  ( dbmsInfo->flags & DBMS_FLAG_QUERYACTIVE ) ) ||
		( ( queryType == DBMS_QUERY_CONTINUE || \
			queryType == DBMS_QUERY_CANCEL ) && \
		  !( dbmsInfo->flags & DBMS_FLAG_QUERYACTIVE ) ) )
		retIntError();

	/* Clear return value */
	if( data != NULL )
		{
		memset( data, 0, 16 );
		*dataLength = 0;
		}

	/* Dispatch the command */
	argIndex = initQueryData( &cmd, &cmdTemplate, encodedDate, dbmsInfo,
							  command, queryData, queryDataLength,
							  queryDate, queryType );
	cmd.arg[ 1 ] = queryEntry;
	cmd.strArg[ argIndex ] = data;
	cmd.strArgLen[ argIndex ] = 0;
	cmd.noStrArgs = argIndex + 1;
	status = DISPATCH_COMMAND_DBX( cmdQuery, cmd, dbmsInfo );
	if( cryptStatusError( status ) )
		{
		performErrorQuery( dbmsInfo );
		return( status );
		}

	/* Update the state information based on the query that we've just
	   performed */
	if( queryType == DBMS_QUERY_START  )
		dbmsInfo->flags |= DBMS_FLAG_QUERYACTIVE;
	if( queryType == DBMS_QUERY_CANCEL )
		dbmsInfo->flags &= ~DBMS_FLAG_QUERYACTIVE;
	if( dataLength != NULL )
		{
		*dataLength = cmd.strArgLen[ argIndex ];
		if( *dataLength <= 0 || *dataLength > MAX_QUERY_RESULT_SIZE )
			{
			assert( NOTREACHED );
			memset( data, 0, 16 );
			*dataLength = 0;
			return( CRYPT_ERROR_BADDATA );
			}
		}
	return( CRYPT_OK );
	}

static int performStaticQuery( DBMS_INFO *dbmsInfo, const char *command,
							   const DBMS_CACHEDQUERY_TYPE queryEntry,
							   const DBMS_QUERY_TYPE queryType )
	{
	return( performQuery( dbmsInfo, command, NULL, NULL, NULL, 0, 0,
						  queryEntry, queryType ) );
	}
#else

/* Database access functions */

static int openDatabase( DBMS_INFO *dbmsInfo, const char *name,
						 const int nameLen, const int options, 
						 int *featureFlags )
	{
	DBMS_STATE_INFO *dbmsStateInfo = dbmsInfo->stateInfo;
	int status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( isReadPtr( name, 2 ) );
	assert( isWritePtr( featureFlags, sizeof( int ) ) );

	/* Clear return value */
	*featureFlags = DBMS_HAS_NONE;

	status = dbmsInfo->openDatabaseBackend( dbmsStateInfo, name, nameLen,
											options, featureFlags );
	if( cryptStatusError( status ) )
		return( status );

	/* Make long-term information returned as a back-end interface-specific
	   feature flags persistent if necessary */
	if( *featureFlags & DBMS_HAS_BINARYBLOBS )
		dbmsInfo->flags |= DBMS_FLAG_BINARYBLOBS;

	return( status );
	}

static void closeDatabase( DBMS_INFO *dbmsInfo )
	{
	DBMS_STATE_INFO *dbmsStateInfo = dbmsInfo->stateInfo;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );

	dbmsInfo->closeDatabaseBackend( dbmsStateInfo );
	}

static int performUpdate( DBMS_INFO *dbmsInfo, const char *command,
						  const void *boundData, const int boundDataLength,
						  const time_t boundDate,
						  const DBMS_UPDATE_TYPE updateType )
	{
	DBMS_STATE_INFO *dbmsStateInfo = dbmsInfo->stateInfo;
	int status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( updateType > DBMS_UPDATE_NONE && \
			updateType < DBMS_UPDATE_LAST );

	/* If we're trying to abort a transaction that was never begun, don't
	   do anything */
	if( updateType == DBMS_UPDATE_ABORT && \
		!( dbmsInfo->flags & DBMS_FLAG_UPDATEACTIVE ) )
		return( CRYPT_OK );

	/* Process the update */
	status = dbmsInfo->performUpdateBackend( dbmsStateInfo, command,
											 boundData, boundDataLength,
											 boundDate, updateType );
	if( cryptStatusOK( status ) )
		{
		/* If we're starting or ending an update, record the update state */
		if( updateType == DBMS_UPDATE_BEGIN )
			dbmsInfo->flags |= DBMS_FLAG_UPDATEACTIVE;
		if( updateType == DBMS_UPDATE_COMMIT || \
			updateType == DBMS_UPDATE_ABORT )
			dbmsInfo->flags &= ~DBMS_FLAG_UPDATEACTIVE;
		}
	return( status );
	}

static int performStaticUpdate( DBMS_INFO *dbmsInfo, const char *command )
	{
	return( performUpdate( dbmsInfo, command, NULL, 0, 0,
						   DBMS_UPDATE_NORMAL ) );
	}

static int performQuery( DBMS_INFO *dbmsInfo, const char *command,
						 char *data, int *dataLength, const char *queryData,
						 const int queryDataLength, const time_t queryDate,
						 const DBMS_CACHEDQUERY_TYPE queryEntry,
						 const DBMS_QUERY_TYPE queryType )
	{
	DBMS_STATE_INFO *dbmsStateInfo = dbmsInfo->stateInfo;
	int status;

	assert( isWritePtr( dbmsInfo, sizeof( DBMS_INFO ) ) );
	assert( ( data == NULL && dataLength == NULL ) || \
			isWritePtr( data, MAX_QUERY_RESULT_SIZE ) );
	assert( ( queryData == NULL && queryDataLength == 0 ) || \
			( queryDataLength > 0 && \
			  isReadPtr( queryData, queryDataLength ) ) );
	assert( DBMS_CACHEDQUERY_NONE >= 0 && \
			queryEntry < DBMS_CACHEDQUERY_LAST );
	assert( queryType > DBMS_QUERY_NONE && queryType < DBMS_QUERY_LAST );

	/* Additional state checks: If we're starting a new query or performing
	   a point query there can't already be one active, and if we're
	   continuing or cancelling an existing query there has to be one
	   already active */
	assert( ( ( queryType == DBMS_QUERY_START || \
				queryType == DBMS_QUERY_CHECK || \
				queryType == DBMS_QUERY_NORMAL ) && \
			  !( dbmsInfo->flags & DBMS_FLAG_QUERYACTIVE ) ) ||
			( ( queryType == DBMS_QUERY_CONTINUE || \
				queryType == DBMS_QUERY_CANCEL ) && \
			  ( dbmsInfo->flags & DBMS_FLAG_QUERYACTIVE ) ) );

	/* Clear return value */
	if( data != NULL )
		{
		memset( data, 0, 16 );
		*dataLength = 0;
		}

	/* Process the query */
	status = dbmsInfo->performQueryBackend( dbmsStateInfo, command, data,
											dataLength, queryData,
											queryDataLength, queryDate,
											queryEntry, queryType );
	if( cryptStatusError( status ) )
		return( status );

	/* Sanity-check the result data from the back-end */
	if( dataLength != NULL && \
		( *dataLength <= 0 || *dataLength > MAX_QUERY_RESULT_SIZE ) )
		{
		assert( NOTREACHED );
		memset( data, 0, 16 );
		*dataLength = 0;
		return( CRYPT_ERROR_BADDATA );
		}

	/* Update the state information based on the query we've just
	   performed */
	if( queryType == DBMS_QUERY_START  )
		dbmsInfo->flags |= DBMS_FLAG_QUERYACTIVE;
	if( queryType == DBMS_QUERY_CANCEL )
		dbmsInfo->flags &= ~DBMS_FLAG_QUERYACTIVE;
	return( CRYPT_OK );
	}

static int performStaticQuery( DBMS_INFO *dbmsInfo, const char *command,
							   const DBMS_CACHEDQUERY_TYPE queryEntry,
							   const DBMS_QUERY_TYPE queryType )
	{
	return( performQuery( dbmsInfo, command, NULL, NULL, NULL, 0, 0,
						  queryEntry, queryType ) );
	}
#endif /* USE_RPCAPI */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* The escape char used to escape potentially dangerous values in SQL
   strings */

#define	SQL_ESCAPE	'\''

/* Format input parameters into SQL queries suitable for submission to the
   DBMS back-end, with assorted safety checks of the query data to try and
   reduce the chances of SQL injection.  Unfortunately this can get
   arbitrarily complicated (see the list below), however since we're using
   parameterised queries wherever possible the following stripping is really
   just belt-and-suspenders security.

	';	The standard SQL-injection method, used with values like
		'foo; DROP TABLE bar', or '1=1' to return all entries in a table.

	--	Comment delimiter (other values also exist, e.g. MySQL's '#') to
		truncate queries beyond the end of the injected SQL.

	char(0xNN)	Bypass the first level of filtering, e.g. char(0x41)
		produces the banned char '.

   One additional check that we could do is to try and explicitly strip
   SQL keywords from queries, but this is somewhat problematic because
   apart from the usual trickery (e.g. embedding one SQL keyword inside
   another so that stripping SELECT from SELSELECTECT will still leave the
   outer SELECT, requiring recursive stripping, or taking advantage of the
   fact that VARBINARY values are implicitly cast to VARCHARS, so that
   0x42434445 would turn into ABCD, or further escaping the encoding with
   values like 'sel'+'ect') there are also any number of backend-specific 
   custom keywords and ways of escaping keywords that we can't know about 
   and therefore can't easily strip */

static int copyChar( char *buffer, const int bufMaxLen, const int ch,
					 const BOOLEAN escapeQuotes )
	{
	int bufPos = 0;

	/* If it's a control character, skip it */
	if( ( ch & 0x7F ) < ' ' )
		return( 0 );

	/* Escape metacharacters that could be misused in queries.  We catch the 
	   obvious ' and ;, as well as the less obvious %, which could be used 
	   to hide other metacharacters.  Note that none of these characters are 
	   valid in base64, which makes it safe to escape them in the few 
	   instances where they do occur */
	if( ( ch == '\'' && escapeQuotes ) || \
		ch == '\\' || ch == ';' || ch == '%' )
		{
		/* Escape the character */
		buffer[ bufPos++ ] = SQL_ESCAPE;
		if( bufPos >= bufMaxLen )
			return( CRYPT_ERROR );
		}

	/* Bypass various dangerous SQL "enhancements".  For Windows ODBC the 
	   driver will execute anything delimited by '|'s as an expression (an 
	   example being '|shell("cmd /c echo " & chr(124) & " format c:")|').  
	   Because of this we strip gazintas if we're running under Windoze.  
	   In addition generic ODBC uses '{' and '}' as escape delimiters, so we 
	   also strip these */
#if defined( __WINDOWS__ )
	if( ch != '|' && ch != '{' && ch != '}' )
#else
	if( ch != '{' && ch != '}' )
#endif /* Database-specific dangerous escape sequences */
		buffer[ bufPos++ ] = ch;

	/* Make sure that we haven't overflowed the output buffer.  This 
	   overflowing can be done deliberately, for example by using large 
	   numbers of escape chars (which are in turn escaped) to force 
	   truncation of the query beyond the injected SQL if the processing 
	   simply stops at a given point */
	return( ( bufPos >= bufMaxLen ) ? CRYPT_ERROR : bufPos );
	}

static int copyStringArg( char *buffer, const int bufMaxLen, 
						  const char *strPtr )
	{
	int bufPos = 0;

	assert( isWritePtr( buffer, bufMaxLen ) );
	assert( isReadPtr( strPtr, 1 ) );

	/* Make sure that there's room for at least one more character of 
	   input */
	if( bufMaxLen < 1 )
		return( CRYPT_ERROR );

	/* Copy the string to the output buffer with conversion of any special 
	   characters that are used by SQL */
	while( *strPtr != '\0' )
		{
		int status;

		status = copyChar( buffer + bufPos, bufMaxLen - bufPos, *strPtr++, 
						   TRUE );
		if( cryptStatusError( status ) )
			return( status );
		bufPos += status;
		}

	return( bufPos );
	}

void dbmsFormatSQL( char *buffer, const int bufMaxLen, 
					const char *format, ... )
	{
	va_list argPtr;
	char *formatPtr = ( char * ) format;
	int bufPos = 0;

	va_start( argPtr, format );
	while( *formatPtr != '\0' )
		{
		int length;

		if( *formatPtr == '$' )
			{
			/* Copy across the string arg.  Note that we refuse a query if 
			   it overflows rather than trying to truncate it to a safe 
			   length, both because it's better to fail than to try the 
			   query anyway in truncated form, and because this could be 
			   used by an attacker to ensure that the truncation occurs in 
			   the middle of an escape sequence that de-fangs a dangerous 
			   character, thus negating the escaping */
			length = copyStringArg( buffer + bufPos, bufMaxLen - bufPos, 
									va_arg( argPtr, char * ) );
			formatPtr++;
			}
		else
			{
			/* Just copy the char over, with a length check.  We don't 
			   escape single quotes in this case because we use these 
			   ourselves in SQL queries */
			length = copyChar( buffer + bufPos, bufMaxLen - bufPos, 
							   *formatPtr++, FALSE );
			}
		if( cryptStatusError( length ) )
			{
			bufPos = 0;
			break;
			}
		bufPos += length;
		}
	buffer[ bufPos++ ] = '\0';	/* Add der terminador */

	va_end( argPtr );
	}

/* Format input parameters into SQL queries, replacing meta-values with
   actual column names */

int dbmsFormatQuery( char *output, const int outMaxLength, 
					 const char *input, const int inputLength )
	{
	int inPos = 0, outPos = 0, status = CRYPT_OK;

	while( inPos < inputLength )
		{
		int length;

		if( input[ inPos ] == '$' )
			{
			typedef struct {
				char *sourceName, *destName;
				int sourceLength;
				} NAMEMAP_INFO;
			static const NAMEMAP_INFO nameMapTbl[] = {
				{ "C", "C", 1 }, { "SP", "SP", 2 },
				{ "L", "L", 1 }, { "O", "O", 1 },
				{ "OU", "OU", 2 }, { "CN", "CN", 2 },
				{ "email", "email", 5 }, { "uri", "email", 5 },
				{ "date", "validTo", 4 }, { NULL, NULL, 0 },
				{ NULL, NULL, 0 }
				};
			const int fieldPos = inPos + 1;
			const char *fieldName = input + fieldPos;
			int i;

			inPos++;	/* Skip '$' */

			/* Extract the field name and translate it into the table
			   column name */
			while( isAlpha( input[ inPos ] ) && inPos < inputLength )
				inPos++;
			length = inPos - fieldPos;
			if( length <= 0 || length > 5 )
				{
				status = CRYPT_ERROR_BADDATA;
				break;
				}
			for( i = 0; nameMapTbl[ i ].sourceName != NULL && \
						i < FAILSAFE_ARRAYSIZE( nameMapTbl, NAMEMAP_INFO ); 
				 i++ )
				{
				if( length == nameMapTbl[ i ].sourceLength && \
					!strCompare( fieldName, nameMapTbl[ i ].sourceName, \
								 length ) )
					break;
				}
			if( i >= FAILSAFE_ARRAYSIZE( nameMapTbl, NAMEMAP_INFO ) )
				retIntError();
			if( nameMapTbl[ i ].sourceName == NULL )
				{
				status = CRYPT_ERROR_BADDATA;
				break;
				}

			/* Copy the translated name to the output buffer */
			length = copyStringArg( output + outPos, outMaxLength - outPos, 
									nameMapTbl[ i ].destName );
			}
		else
			{
			/* Just copy the char over, with a length check.  We don't 
			   escape single quotes in this case because we use these 
			   ourselves in SQL queries */
			length = copyChar( output + outPos, outMaxLength - outPos, 
							   input[ inPos++ ], FALSE );
			}
		if( cryptStatusError( length ) )
			{
			status = CRYPT_ERROR_OVERFLOW;
			break;
			}
		outPos += length;
		}
	if( cryptStatusError( status ) )
		outPos = 0;
	output[ outPos++ ] = '\0';	/* Add der terminador */

	return( status );
	}

/* Parse a user-supplied database name into individual components, used by
   the database back-end connect functions.  We don't do a syntax check
   (since the exact syntax is database-specific) but merely break the single
   string up into any recognisable components.  The database back-end can
   determine whether the format is valid or not.  The general format that we
   look for is:

	[generic name]
	user:pass
	user@server
	user:pass@server
	user:pass@server/name

   One distinction that we make is that if there's something after an '@'
   and there's no server/name separator present, we treat it as a name
   rather than a server.  In other words @foo results in name=foo, while
   @foo/bar results in server=foo, name=bar.  This is because the most
   common situation that we have to handle is ODBC, which identifies the 
   database by name rather than by server.

   Some database types use a magic ID value to indicate the use of a C-style
   string for an arg instead of taking an actual length arg, if the caller
   supplies one of these magic IDs we return that for the "length" of the
   parsed components rather than using the actual string length */

int dbmsParseName( DBMS_NAME_INFO *nameInfo, const char *name, 
				   const int nameLen, const int lengthMarker )
	{
	int offset, offset2, length;

	memset( nameInfo, 0, sizeof( DBMS_NAME_INFO ) );

	/* Check for a complex database name */
	if( ( offset = strFindCh( name, nameLen, ':' ) ) < 0 && \
		( offset = strFindCh( name, nameLen, '@' ) ) < 0 )
		{
		/* It's a straightforward name, use it directly */
		nameInfo->name = ( char * ) name;
		nameInfo->nameLen = lengthMarker ? lengthMarker : nameLen;
		return( CRYPT_OK );
		}

	/* Extract the user name */
	length = min( offset, CRYPT_MAX_TEXTSIZE );
	if( length <= 0 )
		return( CRYPT_ERROR_OPEN );
	memcpy( nameInfo->userBuffer, name, length );
	nameInfo->userBuffer[ length ] = '\0';
	nameInfo->user = nameInfo->userBuffer;
	nameInfo->userLen = lengthMarker ? lengthMarker : length;

	/* We're either at the server name or password, extract the password
	   if there is one */
	assert( name[ offset ] == ':' || name[ offset ] == '@' );
	if( name[ offset++ ] == ':' )
		{
		offset2 = strFindCh( name + offset, nameLen - offset, '@' );
		if( offset2 < 0 )
			offset2 = nameLen - offset;	/* Password is rest of string */
		length = min( offset2, CRYPT_MAX_TEXTSIZE );
		if( length <= 0 )
			return( CRYPT_ERROR_OPEN );
		memcpy( nameInfo->passwordBuffer, name + offset, length );
		nameInfo->passwordBuffer[ length ] = '\0';
		nameInfo->password = nameInfo->passwordBuffer;
		nameInfo->passwordLen = lengthMarker ? lengthMarker : length;
		offset += offset2 + 1;
		if( offset >= nameLen )
			return( CRYPT_OK );
		}

	/* Separate the server and database name if necessary */
	offset2 = strFindCh( name + offset, nameLen - offset, '/' );
	if( offset2 >= 0 )
		{
		/* There's a distinction between the server name and database name,
		   extract the server name */
		length = min( offset2, CRYPT_MAX_TEXTSIZE );
		if( length <= 0 )
			return( CRYPT_ERROR_OPEN );
		memcpy( nameInfo->serverBuffer, name + offset, length );
		nameInfo->serverBuffer[ length ] = '\0';
		nameInfo->server = nameInfo->serverBuffer;
		nameInfo->serverLen = lengthMarker ? lengthMarker : length;
		offset += offset2 + 1;
		}

	/* Extract the database name if there is one */
	if( offset < nameLen )
		{
		length = nameLen - offset;
		memcpy( nameInfo->nameBuffer, name + offset, length );
		nameInfo->nameBuffer[ length ] = '\0';
		nameInfo->name = nameInfo->nameBuffer;
		nameInfo->nameLen = lengthMarker ? lengthMarker : length;
		}

	return( CRYPT_OK );
	}

/* Initialise and shut down a session with a database back-end */

int initDbxSession( KEYSET_INFO *keysetInfo, const CRYPT_KEYSET_TYPE type )
	{
	DBMS_INFO *dbmsInfo = keysetInfo->keysetDBMS;
	int status = CRYPT_ERROR;

	/* Select the appropriate dispatch function for the keyset type */
	switch( type )
		{
		case CRYPT_KEYSET_ODBC:
		case CRYPT_KEYSET_ODBC_STORE:
			status = initDispatchODBC( dbmsInfo );
			break;
		case CRYPT_KEYSET_DATABASE:
		case CRYPT_KEYSET_DATABASE_STORE:
			status = initDispatchDatabase( dbmsInfo );
			break;
		case CRYPT_KEYSET_PLUGIN:
		case CRYPT_KEYSET_PLUGIN_STORE:
			status = initDispatchNet( dbmsInfo );
			break;
		default:
			assert( NOTREACHED );
		}
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_NUM1 );

	/* Set up the remaining function pointers */
	dbmsInfo->openDatabaseFunction = openDatabase;
	dbmsInfo->closeDatabaseFunction = closeDatabase;
	dbmsInfo->performUpdateFunction = performUpdate;
	dbmsInfo->performStaticUpdateFunction = performStaticUpdate;
	dbmsInfo->performQueryFunction = performQuery;
	dbmsInfo->performStaticQueryFunction = performStaticQuery;

	/* Allocate the database session state information */
	if( ( keysetInfo->keyData = \
			clAlloc( "initDbxSession", sizeof( DBMS_STATE_INFO ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( keysetInfo->keyData, 0, sizeof( DBMS_STATE_INFO ) );
	keysetInfo->keyDataSize = sizeof( DBMS_STATE_INFO );
	dbmsInfo->stateInfo = keysetInfo->keyData;
	if( type == CRYPT_KEYSET_ODBC_STORE || \
		type == CRYPT_KEYSET_DATABASE_STORE || \
		type == CRYPT_KEYSET_PLUGIN_STORE )
		dbmsInfo->flags |= DBMS_FLAG_CERTSTORE | DBMS_FLAG_CERTSTORE_FIELDS;

	return( CRYPT_OK );
	}

int endDbxSession( KEYSET_INFO *keysetInfo )
	{
	/* Free the database session state information if necessary */
	if( keysetInfo->keyData != NULL )
		{
		memset( keysetInfo->keyData, 0, keysetInfo->keyDataSize );
		clFree( "endDbxSession", keysetInfo->keyData );
		keysetInfo->keyData = NULL;
		}

	return( CRYPT_OK );
	}
#endif /* USE_DBMS */
