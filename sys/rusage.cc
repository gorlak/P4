/*
 * Copyright 2001 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# define NEED_TIME

# include <stdhdrs.h>
# include <strbuf.h>

# include "rusage.h"

/*
 * Rusage -- CPU, etc usage measuring
 *
 * This sucker will need lots of porting.
 */

# if defined( OS_AS400 ) || \
	defined( OS_MVS ) || \
        defined( OS_SCO ) || \
	defined( OS_NT ) || \
	defined( OS_OS2 ) || \
	defined( OS_BEOS ) || \
	defined( MAC_MWPEF ) || \
	defined( OS_VMS ) || \
	defined( OS_ZETA )

/* Use the dumb version */

Rusage::Rusage() : tc( 0 ) { }
Rusage::~Rusage() { }
void Rusage::Start() { }
P4INT64 Rusage::Time() { return 0; }
void Rusage::Message( StrBuf &msg ) { }
void Rusage::GetTrack( int level, RusageTrack *track ) { track->trackable=0; }

# else /* NOT DUMB, USE GETRUSAGE */
	
# include <sys/time.h>
# include <sys/resource.h>

/*
 * Unix UsageContext:  start timeval and rusage
 */

struct UsageContext {

	/* Start and stop usage and wallclocks */
	/* We need to know start usage, too. */

	struct rusage start, stop;
} ;

inline void
ClearTimeval(struct timeval &v)
{
	v.tv_sec = v.tv_usec = 0;
}

/*
 * TcDiff() - compare two timevals and return diff in ms
 */

static P4INT64 TcDiff( struct timeval &tve, struct timeval &tvs ) 
{ 
	return ( tve.tv_sec - tvs.tv_sec ) * 1000 + 
	       ( tve.tv_usec - tvs.tv_usec ) / 1000; 
}

/*
 * Timer::Timer() - start the timer
 */

Rusage::Rusage()
{
	tc = new UsageContext;
	ClearTimeval(tc->start.ru_utime);
	ClearTimeval(tc->start.ru_stime);
	ClearTimeval(tc->stop.ru_utime);
	ClearTimeval(tc->stop.ru_stime);
}

Rusage::~Rusage()
{
	delete tc;
}

/*
 * Rusage::Start() - restart the timer
 */

void
Rusage::Start()
{
	getrusage( RUSAGE_SELF, &tc->start );
}

/*
 * Rusage::Time() - return CPU time in ms
 */

P4INT64
Rusage::Time()
{
	getrusage( RUSAGE_SELF, &tc->stop );

	return TcDiff( tc->stop.ru_utime, tc->start.ru_utime ) + 
	       TcDiff( tc->stop.ru_stime, tc->start.ru_stime );
}

/*
 * Rusage::Message() - format an OS-specific resource usage message
 */

void
Rusage::Message( StrBuf &msg )
{
	getrusage( RUSAGE_SELF, &tc->stop );

	msg 
	    << StrNum( TcDiff( tc->stop.ru_utime, tc->start.ru_utime ) )
	    << "+"
	    << StrNum( TcDiff( tc->stop.ru_stime, tc->start.ru_stime ) )
	    << "us "
	    << StrNum( tc->stop.ru_inblock - tc->start.ru_inblock )
	    << "+"
	    << StrNum( tc->stop.ru_oublock - tc->start.ru_oublock )
	    << "io "
	    << StrNum( tc->stop.ru_msgrcv - tc->start.ru_msgrcv )
	    << "+"
	    << StrNum( tc->stop.ru_msgsnd - tc->start.ru_msgsnd )
	    << "net "
	    << StrNum( tc->stop.ru_maxrss )
	    << "k "
	    << StrNum( tc->stop.ru_majflt - tc->start.ru_majflt )
	    << "pf "
	;
}

void
Rusage::GetTrack( int level, RusageTrack *track )
{
	getrusage( RUSAGE_SELF, &tc->stop );

	track->trackable=1;

	track->utime = TcDiff( tc->stop.ru_utime, tc->start.ru_utime );
	track->stime = TcDiff( tc->stop.ru_stime, tc->start.ru_stime );
	track->io_in = tc->stop.ru_inblock - tc->start.ru_inblock;
	track->io_out = tc->stop.ru_oublock - tc->start.ru_oublock;
	track->net_in = tc->stop.ru_msgrcv - tc->start.ru_msgrcv;
	track->net_out = tc->stop.ru_msgsnd - tc->start.ru_msgsnd;
	track->maxrss = tc->stop.ru_maxrss;
	track->page_faults = tc->stop.ru_majflt - tc->start.ru_majflt;
}

# endif
