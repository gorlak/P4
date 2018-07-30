/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsdate.cc - format today's date in RCS format
 *
 * External routines:
 *
 *	RcsDateNow() - format today's date in RCS format
 *
 * Internal routines:
 *
 *	RcsDate() - format a date in RCS format
 *
 * History:
 *	2-18-97 (seiwald) - translated to C++.
 */

# define NEED_TIME

# include <stdhdrs.h>

# include "rcsdate.h"

/*
 * RcsDate::Set() - format a date in RCS format
 */

void
RcsDate::Set( char *val )
{
	strncpy( buffer, val, RCS_DATE_BUF_SIZE );
	buffer[ RCS_DATE_BUF_SIZE - 1 ] = 0;
}

void
RcsDate::Set( time_t clock )
{
	struct tm *tm = localtime( &clock );

	if( tm->tm_year>=100) {
	    strftime( buffer, RCS_DATE_BUF_SIZE, "%Y.%m.%d.%H.%M.%S", tm );
	    buffer[ RCS_DATE_BUF_SIZE - 1 ] = 0;
        } else {
	    strftime( buffer, RCS_DATE_BUF_SIZE-2, "%y.%m.%d.%H.%M.%S", tm );
	    buffer[ RCS_DATE_BUF_SIZE - 3 ] = 0;
        }
}

/*
 * RcsDate::Now() - format today's date in RCS format
 */

void
RcsDate::Now()
{
	Set( time( (time_t *)0 ) );
}

/*
 * RcsDate::Parse() - turn RCS format date into a UNIX date
 */

static int
RcsDateNum(
	char **s )
{
	int n = 0;

	while( **s && **s != '.' )
	    n = n * 10 + *((*s)++) - '0';

	if( **s == '.' )
	    (*s)++;

	return n;
}

time_t
RcsDate::Parse()
{
	char *b = buffer;
	struct tm tm[1];

	tm->tm_year = RcsDateNum( &b );
	tm->tm_mon  = RcsDateNum( &b ) - 1;
	tm->tm_mday = RcsDateNum( &b );
	tm->tm_hour = RcsDateNum( &b );
	tm->tm_min  = RcsDateNum( &b );
	tm->tm_sec  = RcsDateNum( &b );
	tm->tm_isdst = -1;

	if( tm->tm_year >= 100 )
	    tm->tm_year -= 1900;

	return mktime( tm );
}
