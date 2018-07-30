/*
 * Copyright 2005 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * tracker.h -- server performance tracking threshholds
 *
 * classes:
 *
 *	Tracker -- corralls the threshholds for reporting long 
 *		   running/high consuming server commands.
 *
 *	Tracker uses a number to represent levels of usage: 
 *	
 *		0/1 - output for any activity at all
 *		2 - output if excessive activity for up to 10 users
 *		3 - output if excessive activity for up to 100 users
 *		4 - output if excessive activity for up to 1000 users
 *		5 - output if excessive activity for over 1000 users
 *		-1 - output for any countable database activity
 *
 *	Normally Tracker isn't called at all if the level is 0, but if
 *	it is called it will report everything.
 *
 *	This level is coupled with a TrackerType to produce a number
 *	representing excess usage in the units specific to the TrackerType.
 *	e.g. For TT_SERVER_CLOCK the units will be milliseconds.
 *	
 *
 * public methods:
 *
 *	Tracker::Tracker() - set the level
 *	Tracker::Over() - is usage excessive for this type?
 *	Tracker::UsersToLevel() - pick a level appropriate for the 
 *		number of licensed users.
 */

enum TrackerType {

	TT_SERVER_FATAL,		// finished with fatal error
	TT_SERVER_AUTH, 		// authentication error
	TT_SERVER_CLOCK,		// lapse time in ms
	TT_SERVER_CPU,			// CPU (user+system) in ms
	TT_DB_LOCKS,			// times table locked
	TT_DB_ROWS_IN,			// rows read/scanned
	TT_DB_ROWS_OUT,			// rows put/deleted
	TT_DB_PAGE_IN,			// pages read into cache
	TT_DB_PAGE_OUT,			// pages written out of cache
	TT_DB_READ_WAIT,		// max wait for read lock in ms
	TT_DB_WRITE_WAIT,		// max wait for write lock in ms
	TT_DB_PEEK_WAIT,		// max wait for peek lock in ms
	TT_DB_READ_HELD,		// max hold of read lock in ms
	TT_DB_WRITE_HELD,		// max hold of write lock in ms
	TT_DB_PEEK_HELD,		// max hold of peek lock in ms
	TT_DB_WEDGED,			// wedged (failed 3 attempts)
	TT_DB_REORG_CNT,		// number of pages reorged
	TT_DB_SPLIT_CNT,		// number of page splits
	TT_RPC_MSGS,			// msgs in/out
	TT_RPC_MBYTES,			// mbytes in/out
	TT_RPC_ERRORS,			// rpc errors
	TT_RMTDB_ROWS,			// rows in rmt pipe
	TT_RMTDB_TIME,			// time in rmt pipe
	TT_TRIGGER_TIME,		// time in trigger
	PX_SUB_ADDS,			// proxy files cached on submit
	PX_SUB_FAILS,			// proxy files submitted but failed
	PX_FAULTS,			// proxy cache faults
	PX_FAULTS_MB,			// proxy fault megabytes
	PX_FAULTS_OTH,			// proxy faults adopted from others
	PX_FLUSHES,			// proxy flush1 messages processed
	PX_DELIVERIES,			// proxy cache deliveries
	PX_DELIVERIES_MB,		// proxy cache deliveries megabytes
	PX_TOT_FAULTS,			// proxy cache total faults
	PX_TOT_FAULTS_MB,		// proxy fault total megabytes

	TT_LAST
}  ;

const int TRACKER_LEVEL_DBSTAT = -1;

class Tracker {

    public:

    			Tracker( int l ) { level = l; }

	int		Over( TrackerType type, P4INT64 amount );

	static int	UsersToLevel( int users );

    private:

    	int 		level;

} ;

class TrackReportCallback
{
    public:
	    			TrackReportCallback() { }
	virtual			~TrackReportCallback() { }

	virtual int		Level() const = 0;

	virtual void		Report( const char * ) const = 0;
} ;
