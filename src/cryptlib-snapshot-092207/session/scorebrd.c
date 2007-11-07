/****************************************************************************
*																			*
*							cryptlib Session Scoreboard						*
*						Copyright Peter Gutmann 1998-2006					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "session.h"
  #include "ssl.h"
#else
  #include "crypt.h"
  #include "session/session.h"
  #include "session/ssl.h"
#endif /* Compiler-specific includes */

#ifdef USE_SSL

/* The maximum size of any data value to be stored in the scoreboard.  
   Currently this is SSL_SECRET_SIZE, 48 bytes */

#define SCOREBOARD_DATA_SIZE	SSL_SECRET_SIZE

/* Scoreboard data and index information */

typedef BYTE SCOREBOARD_DATA[ SCOREBOARD_DATA_SIZE ];
typedef struct {
	/* Identification information: The checksum and hash of the session ID */
	int checkValue;
	BYTE hashValue[ HASH_DATA_SIZE + 4 ];

	/* Misc info */
	time_t timeStamp;		/* Time entry was added to the scoreboard */
	int uniqueID;			/* Unique ID for this entry */
	BOOLEAN fixedEntry;		/* Whether entry was added manually */
	} SCOREBOARD_INDEX;

/* A template used to initialise scoreboard entries */

static const SCOREBOARD_INDEX SCOREBOARD_INDEX_TEMPLATE = \
								{ 0, { 0 }, 0, 0, FALSE };

/* The maximum amount of time that an entry is retained in the scoreboard,
   1 hour */

#define SCOREBOARD_TIMEOUT		3600

/* The action to perform on the scoreboard.  These are:

	ADD: Add the given key and value.

	LOOKUP: Look up the given key and return the associated value.

	PRESENCECHECK: Check whether the given key is present and return its 
		uniqueID value if it is */

typedef enum { 
	SCOREBOARD_ACTION_NONE,		/* No scoreboard action */
	SCOREBOARD_ACTION_PRESENCECHECK,/* Check for an entry presence */
	SCOREBOARD_ACTION_LOOKUP,	/* Look up a scoreboard entry */
	SCOREBOARD_ACTION_ADD,		/* Add a scoreboard entry */
	SCOREBOARD_ACTION_LAST		/* Last possible scoreboard action */
	} SCOREBOARD_ACTION;

/****************************************************************************
*																			*
*						Scoreboard Management Functions						*
*																			*
****************************************************************************/

/* Find an entry, returning its position in the scoreboard.  This function 
   currently uses a straightforward linear search with entries clustered 
   towards the start of the scoreboard.  Although this may seem somewhat 
   suboptimal, since cryptlib isn't a high-performance server the scoreboard 
   will rarely contain more than a handful of entries (if any).  In any case 
   a quick scan through a small number of integers is probably still faster 
   than the complex in-memory database lookup schemes used by many servers, 
   and is also required to handle things like scoreboard LRU management */

static int findEntry( SCOREBOARD_INFO *scoreboardInfo,
					  const void *key, const int keyLength, 
					  const time_t currentTime, int *position )
	{
	SCOREBOARD_INDEX *scoreboardIndex = scoreboardInfo->index;
	SCOREBOARD_DATA *scoreboardData = scoreboardInfo->data;
	BYTE hashValue[ HASH_DATA_SIZE + 8 ];
	BOOLEAN dataHashed = FALSE;
	time_t oldestTime = currentTime;
	const int checkValue = checksumData( key, keyLength );
	int nextFreeEntry = CRYPT_ERROR, lastUsedEntry = 0, oldestEntry = 0;
	int i;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtr( key, keyLength ) && keyLength >= 8 );
	assert( currentTime > MIN_TIME_VALUE );
	assert( isWritePtr( position, sizeof( int ) ) );
	assert( isWritePtr( scoreboardIndex,
						scoreboardInfo->size * sizeof( SCOREBOARD_INDEX ) ) );
	assert( isWritePtr( scoreboardData,
						scoreboardInfo->size * sizeof( SCOREBOARD_DATA ) ) );

	/* Clear return value */
	*position = CRYPT_ERROR;

	for( i = 0; i < scoreboardInfo->lastEntry && \
				i < FAILSAFE_ITERATIONS_MAX; i++ )
		{
		SCOREBOARD_INDEX *scorebordIndexEntry = &scoreboardIndex[ i ];

		/* If this entry has expired, delete it */
		if( scorebordIndexEntry->timeStamp + SCOREBOARD_TIMEOUT < currentTime )
			{
			scoreboardIndex[ i ] = SCOREBOARD_INDEX_TEMPLATE;
			zeroise( scoreboardData[ i ], sizeof( SCOREBOARD_DATA ) );
			}

		/* Check for a free entry and the oldest non-free entry.  We could
		   perform an early-out once we find a free entry, but this would
		   prevent any following expired entries from being deleted */
		if( scorebordIndexEntry->timeStamp <= MIN_TIME_VALUE )
			{
			/* We've found a free entry, remember it for future use if
			   required and continue */
			if( nextFreeEntry == CRYPT_ERROR )
				nextFreeEntry = i;
			continue;
			}
		lastUsedEntry = i;
		if( scorebordIndexEntry->timeStamp < oldestTime )
			{
			/* We've found an older entry than the current oldest entry,
			   remember it */
			oldestTime = scorebordIndexEntry->timeStamp;
			oldestEntry = i;
			}

		/* Perform a quick check using a checksum of the name to weed out
		   most entries */
		if( scorebordIndexEntry->checkValue == checkValue )
			{
			if( !dataHashed )
				{
				hashData( hashValue, HASH_DATA_SIZE, key, keyLength );
				dataHashed = TRUE;
				}
			if( !memcmp( scorebordIndexEntry->hashValue, hashValue, 
						 HASH_DATA_SIZE ) )
				{
				/* Remember the match position.  We can't immediately exit 
				   at this point because we still need to look for the last 
				   used entry and potentually shrink the scoreboard-used 
				   size */
				*position = i;
				}
			}
		}
	if( i >= FAILSAFE_ITERATIONS_MAX )
		retIntError();

	/* If the total number of entries has shrunk due to old entries expiring,
	   reduce the overall scoreboard-used size */
	if( lastUsedEntry + 1 < scoreboardInfo->lastEntry )
		scoreboardInfo->lastEntry = lastUsedEntry + 1;

	/* If we've found a match, we're done */
	if( *position >= 0 )
		return( CRYPT_OK );

	/* The entry wasn't found, return the location where we can add a new 
	   entry */
	if( nextFreeEntry > 0 )
		/* We've freed up an existing position (which will be before any 
		   remaining free entries), add the new entry there */
		*position = nextFreeEntry;
	else
		{
		/* If there are still free positions in the scoreboard, use the next
		   available one */
		if( scoreboardInfo->lastEntry < scoreboardInfo->size )
			*position = scoreboardInfo->lastEntry;
		else
			/* There are no free positions, overwrite the oldest entry */
			*position = oldestEntry;
		}
	return( CRYPT_ERROR );
	}

/* Add an entry to the scoreboard */

static int addEntry( SCOREBOARD_INFO *scoreboardInfo, const int position,
					 const void *key, const int keyLength, 
					 const void *value, const int valueLength,
					 const time_t currentTime )
	{
	SCOREBOARD_INDEX *scoreboardIndex = scoreboardInfo->index;
	SCOREBOARD_INDEX *scorebordIndexEntry = &scoreboardIndex[ position ];
	SCOREBOARD_DATA *scoreboardData = scoreboardInfo->data;
	const int checkValue = checksumData( key, keyLength );

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtr( key, keyLength ) && keyLength >= 8 );
	assert( isReadPtr( value, valueLength ) );
	assert( currentTime > MIN_TIME_VALUE );
	assert( isWritePtr( scoreboardIndex,
						scoreboardInfo->size * sizeof( SCOREBOARD_INDEX ) ) );
	assert( isWritePtr( scoreboardData,
						scoreboardInfo->size * sizeof( SCOREBOARD_DATA ) ) );

	/* Clear the entry (this should already be done, but we make it explicit
	   here just in case) */
	*scorebordIndexEntry = SCOREBOARD_INDEX_TEMPLATE;
	zeroise( scoreboardData[ position ], sizeof( SCOREBOARD_DATA ) );

	/* Copy across the key and value */
	scorebordIndexEntry->checkValue = checkValue;
	hashData( scorebordIndexEntry->hashValue, HASH_DATA_SIZE, 
			  key, keyLength );
	scorebordIndexEntry->timeStamp = currentTime;
	scorebordIndexEntry->uniqueID = scoreboardInfo->uniqueID++;
	memcpy( scoreboardData[ position ], value, valueLength );

	/* If we've used a new entry, update the position-used index */
	if( position >= scoreboardInfo->lastEntry )
		scoreboardInfo->lastEntry = position + 1;

	return( scoreboardIndex[ position ].uniqueID );
	}

/* Umbrella interface for all scoreboard operations */

static int handleScoreboard( SCOREBOARD_INFO *scoreboardInfo,
							 const SCOREBOARD_ACTION action,
							 const void *key, const int keyLength, 
							 void *value, const int valueLength )
	{
	SCOREBOARD_INDEX *scoreboardIndex = scoreboardInfo->index;
	SCOREBOARD_DATA *scoreboardData = scoreboardInfo->data;
	const time_t currentTime = getTime();
	int position, uniqueID = SCOREBOARD_UNIQUEID_NONE, status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtr( key, keyLength ) && keyLength >= 8 );
	assert( ( value == NULL && valueLength == 0 ) || \
			isReadPtr( value, valueLength ) );
	assert( ( action == SCOREBOARD_ACTION_PRESENCECHECK && value == NULL ) || \
			( action == SCOREBOARD_ACTION_LOOKUP && value != NULL ) || \
			( action == SCOREBOARD_ACTION_ADD && value != NULL ) );
	assert( isWritePtr( scoreboardIndex,
						scoreboardInfo->size * sizeof( SCOREBOARD_INDEX ) ) );
	assert( isWritePtr( scoreboardData,
						scoreboardInfo->size * sizeof( SCOREBOARD_DATA ) ) );

	/* If there's something wrong with the time, we can't perform (time-
	   based) scoreboard management */
	if( currentTime <= MIN_TIME_VALUE )
		return( SCOREBOARD_UNIQUEID_NONE );

	status = krnlEnterMutex( MUTEX_SCOREBOARD );
	if( cryptStatusError( status ) )
		return( status );

	/* Try and find this entry in the scoreboard */
	status = findEntry( scoreboardInfo, key, keyLength, currentTime, 
						&position );
	assert( position >= 0 && position < scoreboardInfo->size );
	if( cryptStatusError( status ) )
		{
		/* No match found, if we're adding a new entry, add it at the
		   appropriate location */
		if( action == SCOREBOARD_ACTION_ADD )
			uniqueID = addEntry( scoreboardInfo, position, key, keyLength, 
								 value, valueLength, currentTime );
		}
	else
		{
		SCOREBOARD_INDEX *scorebordIndexEntry = &scoreboardIndex[ position ];
		SCOREBOARD_DATA *scoreboardDataEntry = &scoreboardData[ position ];

		/* If we're trying to add an entry that matches an existing key, 
		   clear the existing entry and don't add the new one.  Attempting
		   to re-add a value using an existing key is a sign that something
		   suspicious is going on, if we simply ignore the add attempt then
		   it'll appear to the caller that we've added the new value when in
		   fact we've retained the old value.  If on the other hand we
		   overwrite the old value with the new one it'll allow an attacker
		   to replace existing scoreboard contents with attacker-controlled
		   ones */
		if( action == SCOREBOARD_ACTION_ADD )
			{
			scoreboardIndex[ position ] = SCOREBOARD_INDEX_TEMPLATE;
			zeroise( scoreboardDataEntry, sizeof( SCOREBOARD_DATA ) );
			uniqueID = SCOREBOARD_UNIQUEID_NONE;
			}
		else
			{
			/* If we're looking for an existing entry return its data and 
			   update the last-access date */
			if( action == SCOREBOARD_ACTION_LOOKUP )
				{
				memcpy( value, scoreboardDataEntry, SCOREBOARD_DATA_SIZE );
				scorebordIndexEntry->timeStamp = currentTime;
				}
			uniqueID = scorebordIndexEntry->uniqueID;
			}
		}

	krnlExitMutex( MUTEX_SCOREBOARD );
	return( uniqueID );
	}

/****************************************************************************
*																			*
*							Scoreboard Access Functions						*
*																			*
****************************************************************************/

/* Add and delete entries to/from the scoreboard.  These are just wrappers
   for the local scoreboard-access function, for use by external code */

int findScoreboardEntry( SCOREBOARD_INFO *scoreboardInfo,
						 const void *key, const int keyLength,
						 void *value, const int maxValueLength,
						 int *valueLength )
	{
	int resumedSessionID;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtr( key, keyLength ) );
	assert( isWritePtr( value, maxValueLength ) );
	assert( isWritePtr( valueLength, sizeof( int ) ) );

	/* Clear return value */
	memset( value, 0, maxValueLength );
	*valueLength = 0;

	resumedSessionID = handleScoreboard( scoreboardInfo, 
								SCOREBOARD_ACTION_LOOKUP,
								key, keyLength, value, maxValueLength );
	if( resumedSessionID != SCOREBOARD_UNIQUEID_NONE )
		*valueLength = SCOREBOARD_DATA_SIZE;
	return( resumedSessionID );
	}

int findScoreboardEntryID( SCOREBOARD_INFO *scoreboardInfo,
						   const void *key, const int keyLength )
	{
	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtr( key, keyLength ) );

	return( handleScoreboard( scoreboardInfo, SCOREBOARD_ACTION_PRESENCECHECK,
							  key, keyLength, NULL, 0 ) );
	}

int addScoreboardEntry( SCOREBOARD_INFO *scoreboardInfo,
						const void *key, const int keyLength, 
						const void *value, const int valueLength )
	{
	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( isReadPtr( key, keyLength ) );
	assert( isReadPtr( value, valueLength ) && \
			valueLength <= SCOREBOARD_DATA_SIZE );

	/* Add the entry to the scoreboard */
	return( handleScoreboard( scoreboardInfo, SCOREBOARD_ACTION_ADD,
							  key, keyLength, ( void * ) value, valueLength ) );
	}

void deleteScoreboardEntry( SCOREBOARD_INFO *scoreboardInfo, 
							const int uniqueID )
	{
	SCOREBOARD_INDEX *scoreboardIndex = scoreboardInfo->index;
	SCOREBOARD_DATA *scoreboardData = scoreboardInfo->data;
	int i, status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( uniqueID > SCOREBOARD_UNIQUEID_NONE );

	status = krnlEnterMutex( MUTEX_SCOREBOARD );
	if( cryptStatusError( status ) )
		return;

	/* Search the scoreboard for the entry with the given ID */
	for( i = 0; i < scoreboardInfo->lastEntry && \
				i < FAILSAFE_ITERATIONS_MAX; i++ )
		{
		SCOREBOARD_INDEX *scorebordIndexEntry = &scoreboardIndex[ i ];

		/* If we've found the entry that we're after, clear it and exit */
		if( scorebordIndexEntry->uniqueID == uniqueID )
			{
			scoreboardIndex[ i ] = SCOREBOARD_INDEX_TEMPLATE;
			zeroise( scoreboardData[ i ], sizeof( SCOREBOARD_DATA ) );
			break;
			}
		}
	if( i >= FAILSAFE_ITERATIONS_MAX )
		retIntError_Void();

	krnlExitMutex( MUTEX_SCOREBOARD );
	}

/****************************************************************************
*																			*
*							Scoreboard Init/Shutdown						*
*																			*
****************************************************************************/

/* Initialise and shut down the scoreboard */

int initScoreboard( SCOREBOARD_INFO *scoreboardInfo, 
					const int scoreboardSize )
	{
	SCOREBOARD_INDEX *scoreboardIndex;
	int i, status;

	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );
	assert( scoreboardSize > 16 && scoreboardSize <= 8192 );

	krnlEnterMutex( MUTEX_SCOREBOARD );

	/* Initialise the scoreboard */
	memset( scoreboardInfo, 0, sizeof( SCOREBOARD_INFO ) );
	scoreboardInfo->uniqueID = SCOREBOARD_UNIQUEID_NONE + 1;
	scoreboardInfo->lastEntry = 0;
	scoreboardInfo->size = scoreboardSize;

	/* Initialise the scoreboard data */
	if( ( scoreboardInfo->index = clAlloc( "initScoreboard", \
				scoreboardSize * sizeof( SCOREBOARD_INDEX ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	status = krnlMemalloc( &scoreboardInfo->data, \
						   scoreboardSize * sizeof( SCOREBOARD_DATA ) );
	if( cryptStatusError( status ) )
		{
		clFree( "initScoreboard", scoreboardInfo->index );
		memset( scoreboardInfo, 0, sizeof( SCOREBOARD_INFO ) );
		return( status );
		}
	scoreboardIndex = scoreboardInfo->index;
	for( i = 0; i < scoreboardSize; i++ )
		scoreboardIndex[ i ] = SCOREBOARD_INDEX_TEMPLATE;
	memset( scoreboardInfo->data, 0, scoreboardSize * \
									 sizeof( SCOREBOARD_DATA ) );

	krnlExitMutex( MUTEX_SCOREBOARD );
	return( CRYPT_OK );
	}

void endScoreboard( SCOREBOARD_INFO *scoreboardInfo )
	{
	assert( isWritePtr( scoreboardInfo, sizeof( SCOREBOARD_INFO ) ) );

	krnlEnterMutex( MUTEX_SCOREBOARD );

	/* Clear and free the scoreboard */
	krnlMemfree( ( void ** ) &scoreboardInfo->data );
	zeroise( scoreboardInfo->index, \
			 scoreboardInfo->size * sizeof( SCOREBOARD_INDEX ) );
	clFree( "endScoreboard", scoreboardInfo->index );
	memset( scoreboardInfo, 0, sizeof( SCOREBOARD_INFO ) );

	krnlExitMutex( MUTEX_SCOREBOARD );
	}
#endif /* USE_SSL */
