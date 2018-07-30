/*
 * Copyright 2001 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# define NEED_TIME

# include <stdhdrs.h>
# include <strbuf.h>
# include <strops.h>

# include "timer.h"

/*
 * This sucker will need lots of porting.
 */

# if defined( OS_AS400 ) || \
	defined( OS_MVS ) || \
        defined( OS_SCO ) || \
	defined( OS_OS2 ) || \
	defined( OS_BEOS ) || \
	defined( MAC_MWPEF ) || \
	defined( OS_VMS ) || \
	defined( OS_ZETA )

# if defined( OS_OS2 ) || \
     defined( OS_VMS )
# define TIMER_T unsigned long
# endif
     
# if defined ( __MWERKS__) && (__MWERKS__ < 0x2400) && !defined( OS_BEOS )
# define TIMER_T unsigned long
# endif

# ifndef TIMER_T
# define TIMER_T long
# endif

# define HAVE_TIMERSET

void
Timer::Set( Timer::timer &t )
{
	time_t clock;
	time( &clock );
	t.sec = clock;
	t.usec = 0;
}

# endif

# ifdef OS_NT

# define HAVE_TIMERSET

# define WIN32_LEAN_AND_MEAN
# include <windows.h>

void
Timer::Set( Timer::timer &t )
{
	unsigned long tgt = GetTickCount();
	t.sec = tgt / 1000;
	t.usec = ( tgt % 1000 ) * 1000;
}

# endif

/* USE GETTIMEOFDAY */

# ifndef HAVE_TIMERSET 
	
# include <sys/time.h>

# if defined(OS_PTX) || defined(OS_MVS) || defined(OS_MPEIX)
extern "C" int gettimeofday( struct timeval *, int );
# endif

void
Timer::Set( Timer::timer &t )
{
	struct timeval tv;
	gettimeofday( &tv, 0 );
	t.sec = tv.tv_sec;
	t.usec = tv.tv_usec;
}

# endif

/*
 * Timer::Start() - restart the timer
 */

void
Timer::Start()
{
	Set( start );
}

/*
 * Timer::Time() - compute start vs stop in ms
 */

int
Timer::Time()
{
	/* Get end usage */

	Set( stop );

# ifdef OS_NT
	/* Duh, GetTickCount() rolls over at 2^32 ms */
	/* If we time something longer than 49 days, */
	/* it will roll over twice and we'll be lost. */

	if( stop.sec < start.sec )
	{
	    stop.sec += 4294967;
	    stop.usec += 296000;
	}
# endif

	return 
	    ( stop.sec - start.sec ) * 1000 + 
	    ( stop.usec - start.usec ) / 1000;
}

const StrPtr &
Timer::Fmt( StrBuf &buf ) const
{
        long long int timeValue;
        char work1[64];

	timeValue =  start.sec;
	timeValue = ( timeValue * 1000000 ) + start.usec;

	buf.Set( StrBuf::Itoa64( timeValue, work1 + sizeof(work1) ) );

	return ( buf );
}

void
Timer::Parse( const StrPtr &v )
{
        long long int timeValue = v.Atoi64();
	long long int temp;

	temp = timeValue / 1000000;
	start.sec = temp;
	start.usec = timeValue - (temp * 1000000);
}

void
Timer::Restart()
{
	start = stop;
}

/*
 * FmtMs() - format milliseconds with varying precision
 */

StrMs::StrMs( int ms )
{
	// put a '1' where the dot will go.
	// e.g. 123456 -> 1231456

	int s = ms / 1000 * 10000 + 1000 + ms % 1000;
	int dot;

	// Chop off digits (and the decimal point) for large numbers

	if( ms >= 100000 ) 	s /= 10000, dot = -1;
	else if( ms >= 10000 )  s /= 100, dot = 2;
	else if( ms >= 1000 )	s /= 10, dot = 1;
	else 				dot = 0;

	buffer = Itoa( s, buf + sizeof( buf ) );
	length = buf + sizeof( buf ) - buffer - 1;
	if( dot >= 0 ) buffer[ dot ] = '.';
}
