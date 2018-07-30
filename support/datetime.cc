/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# define NEED_TIME
# define NEED_TIME_HP

# include <stdhdrs.h>
# include <charman.h>
 
# include <strbuf.h>
# include <error.h>
# include <errornum.h>
# include <msgsupp.h>

# include <datetime.h>

# define MILLION (1000000)
# define BILLION ((P4INT64) 1000000000L)

/*
 * DateTime - date as stored in license file (string of time(0))
 */

int
DateTimeParse( const char *&c, const char delim )
{
	int r = 0;

	for( ; *c && isAdigit( c ) && *c != delim; ++c )
	    r = r * 10 + *c - '0';

	// skip delim

	if( delim && *c == delim )
	    ++c;

	return r;
}

void
DateTime::Set( const char *date, Error *e )
{
	struct tm tm;
	const char *odate = date;
	wholeDay = 0;
	tval = 0;

	// No date?  Just clear

	if( !date )
	    return;

	// is it something simple like 'now'?

	if( !strcmp( date, "now" ) )
	{
	    tval = Now();
	    return;
	}

	// Just a time in seconds?

	tval = DateTimeParse( date, '/' );

	if( !*date )
	    return;

	// parse date
	// Allows mm/dd/yy or yyyy/mm/dd

	memset( (void *)&tm, 0, sizeof( tm ) );

	// used to be sscanf( "%d/%d/%d" ), but that crashed on HP GCC!
	// This expects yy/mm/dd.

	tm.tm_year = tval;
	tm.tm_mon = DateTimeParse( date, '/' );
	tm.tm_mday = DateTimeParse( date, ' ' );

	// Allow both : and ' ' to separate date/time

	if( *date == ':' )
	    ++date;

	// Compat with old date format (mm/dd/yy).

	if( tm.tm_mday > 31 )
	{
	    int x = tm.tm_year;
	    tm.tm_year = tm.tm_mday;
	    tm.tm_mday = tm.tm_mon;
	    tm.tm_mon = x;
	}

	// Adjust to tm-style times (year-1900, jan=0)

	--tm.tm_mon;

	if( tm.tm_year > 1900 )
	    tm.tm_year -= 1900;

	// Parse time
	// handles hh:mm:ss

	if( !( wholeDay = !*date ) )
	{
	    tm.tm_hour = DateTimeParse( date, ':' );
	    tm.tm_min = DateTimeParse( date, ':' );
	    tm.tm_sec = DateTimeParse( date, 0 );
	}

	// -1 for isdst tells mktime to figure it out

	tm.tm_isdst = -1;

	// And turn it into an int.
	// Return 0 if date no good (if any left, that is).

	int offset = ParseOffset( date, odate, e );
	if( e->Test() )
	    return;

	if( ( tval = mktime( &tm ) ) == (time_t) -1 )
	    e->Set( MsgSupp::InvalidDate ) << odate;

	if( offset )
	    tval -= ( offset - TzOffset( 0 ) );
}


// If 's' points to the start of a buffer formatted by FmtTz(), this routine
// reads the offset portion ([-]HHMM), converts it to the corresponding
// number of seconds, and returns that. If 's' points to a NUL terminator,
// this routine returns 0. If 's' points to anything else, this routine
// sets an error into 'e' and returns 0.
int	
DateTime::ParseOffset( const char *s, const char *odate, Error *e )
{
	int sign = 1;
	int seconds = 0, hours = 0, minutes = 0;

	if( !*s )
	    return 0;

	if( *s == ' ' )
	    s++;

	if( *s == '-' )
	{
	    sign = -1;
	    s++;
	}
	// 4 valid digits, then a space?
	if( isAdigit( &s[0] ) && isAdigit( &s[1] ) &&
	    isAdigit( &s[2] ) && isAdigit( &s[3] ) &&
	    s[4] == ' ' )
	{
	    hours = s[0] - '0';
	    hours = hours * 10 + s[1] - '0';
	    minutes = s[2] - '0';
	    minutes = minutes * 10 + s[3] - '0';
	    seconds = hours * 3600 + minutes * 60;
	    return seconds * sign;
	}

	e->Set( MsgSupp::InvalidDate ) << odate;
	return 0;
}

time_t
DateTime::Now()
{
	return time(0);
}

void
DateTime::FmtElapsed( char *buf,  const DateTime &t2 ) 
{
	int elapsed = t2.tval - tval;
	int hours = elapsed / 3600;
	int minutes = ( elapsed - (hours*3600) ) / 60;
	int seconds = elapsed - (hours*3600) - (minutes*60);

	sprintf( buf, "%02d:%02d:%02d", hours, minutes, seconds );
}

void
DateTime::Fmt( char *buf ) const
{
	struct tm *tm = localtime( &tval );

	// Don't die for a bogus date.

	if( tm )
	{
	    sprintf( buf, "%04d/%02d/%02d %02d:%02d:%02d",
		    tm->tm_year < 1900 ? tm->tm_year + 1900 : tm->tm_year,
		    tm->tm_mon + 1,
		    tm->tm_mday,
		    tm->tm_hour,
		    tm->tm_min,
		    tm->tm_sec );
	}
	else
	{
	    strcpy( buf, "1970/01/01" );
	}
}

void
DateTime::FmtUTC( char *buf ) const
{
	struct tm *tm = gmtime( &tval );

	// Don't die for a bogus date.

	if( tm )
	{
	    sprintf( buf, "%04d/%02d/%02d %02d:%02d:%02d",
		    tm->tm_year < 1900 ? tm->tm_year + 1900 : tm->tm_year,
		    tm->tm_mon + 1,
		    tm->tm_mday,
		    tm->tm_hour,
		    tm->tm_min,
		    tm->tm_sec );
	}
	else
	{
	    strcpy( buf, "1970/01/01" );
	}
}

void
DateTime::FmtDay( char *buf ) const
{
	struct tm *tm = localtime( &tval );

	// Don't die for a bogus date.

	if( tm )
	{
	    sprintf( buf, "%04d/%02d/%02d",
		    tm->tm_year < 1900 ? tm->tm_year + 1900 : tm->tm_year,
		    tm->tm_mon + 1,
		    tm->tm_mday );
	}
	else
	{
	    strcpy( buf, "1970/01/01" );
	}
}

void
DateTime::FmtDayUTC( char *buf ) const
{
	struct tm *tm = gmtime( &tval );

	// Don't die for a bogus date.

	if( tm )
	{
	    sprintf( buf, "%04d/%02d/%02d",
		    tm->tm_year < 1900 ? tm->tm_year + 1900 : tm->tm_year,
		    tm->tm_mon + 1,
		    tm->tm_mday );
	}
	else
	{
	    strcpy( buf, "1970/01/01" );
	}
}

# if defined( OS_FREEBSD22 ) || defined( OS_MACOSX ) || \
     defined( OS_DARWIN ) || defined( OS_VMS62 )
extern char *tzname[2];
# endif

# if defined( OS_AS400 ) || defined( OS_SUNOS )
char *tzname[2] = { "PDT", "PST" };
# endif

# if defined( OS_NT ) || defined( OS_CYGWIN )
# define tzname _tzname
# endif

int
DateTime::TzOffset( int *retdst ) const
{
	int offset = 0;

	// localtime for dst active or not
	// global time for computing offset in minutes

	struct tm *tm = localtime( &tval );

	// Don't die for a bogus date.

	if( !tm )
	    return offset;

	int isdst = tm->tm_isdst;

	tm = gmtime( &tval );

	// Don't die for a bogus date.

	if( !tm )
	    return offset;

	tm->tm_isdst = isdst;

	if( retdst )
	    *retdst = isdst;

	// take gmt time, pretend it's local, and compute the offset

	offset = ( tval - mktime( tm ) );

	return offset;
}

void
DateTime::FmtTz( char *buf ) const
{
	/*
	   adjust for display reasons
	   Note: Do not be tempted to sprintf the hours and
	   minutes seporately, there be dragons.
	   Those dragons are in the land of negative offsets.
	   On FreeBSD the timezone America/St_Johns is GMT-0230.
	   If the negative offset is a multiple of an hour it is
	   ok, but if the offset is not a multiple of an hour
	   then you will get problems displaying the signs.
	   from -1 to -59 minutes you want -0030 for example
	   not +00-30 if you seporate the hours and minutes.
	   Also, if the offset is -90 minutes you want -0130 not -01-30.
	   The number 40 below is ( 100 - 60 ) and the expression
	   is counting on integer division truncating toward zero
	   (i.e. leaving hours) then multiplying by 40 and adding
	   back in changes 90 into 130 or -90 into -130 or
	   270 into 430.  This code is confusing but this is a hard
	   issue and staying in the math realm to solve these problems
	   makes the result code much smaller and forces thought
	   about the issues. -- JAA
	*/

	int isdst = 0;

	int minutesOff = TzOffset( &isdst ) / 60;
	minutesOff += 40 * ( minutesOff / 60 );

	sprintf( buf, "%+05d", minutesOff );

	// if tzname is ascii, we'll display it

	const char *t;

	for( t = tzname[ isdst ]; *t; t++ )
	    if( isAhighchar( t ) || !isprint( *t ) )
		return;

	strcat( buf, " " );
	strcat( buf, tzname[ isdst ] );
}


/*
 * format date to match the diff 'unified date format'
 * pseudo-specification
 *
 */
void
DateTime::FmtUnifiedDiff( char *buf ) const
{
	struct tm *tm = gmtime( &tval );

	// Don't die for a bogus date.

	if( tm )
	{
	    int isdst = tm->tm_isdst;

	    int minutesOff = TzOffset( &isdst ) / 60;
	    minutesOff += 40 * ( minutesOff / 60 );

	    sprintf( buf, "%04d-%02d-%02d %02d:%02d:%02d.000000000 %-.4d",
		    tm->tm_year < 1900 ? tm->tm_year + 1900 : tm->tm_year,
		    tm->tm_mon + 1,
		    tm->tm_mday,
		    tm->tm_hour,
		    tm->tm_min,
		    tm->tm_sec,
		    minutesOff );
	}
	else
	{
	    strcpy( buf, "1970/01/01 00:00:01.000000000 -0000" );
	}

}

/*
 * DateTime::SetGit() - parse a date in Git internal format.
 *
 * From https://git-scm.com/docs/git-commit-tree:
 *
 * Git internal format
 *
 * It is <unix timestamp> <time zone offset>, where <unix timestamp> is
 * the number of seconds since the UNIX epoch. <time zone offset> is a
 * positive or negative offset from UTC. For example CET (which is 2
 * hours ahead UTC) is +0200.
 *
 * Note that the time zone offset is not used to "correct" the timestamp; the
 * timestamp is already in UTC.
 */
void
DateTime::SetGit( const StrPtr &s, Error *e )
{
	tval = 0;

	const char *p = s.Text();
	while( isAdigit( p ) )
	{
	    tval = ( tval * 10 ) + ( *p - '0' );
	    p++;
	}

	if( *p != ' ' )
	{
	    e->Set( MsgSupp::InvalidDate ) << s;
	    return;
	}

	p++;

	if( *p == '-' || *p == '+' )
	    p++;

	// 4 valid digits?
	if( !( isAdigit( &p[0] ) && isAdigit( &p[1] ) &&
	       isAdigit( &p[2] ) && isAdigit( &p[3] ) ) )
	    e->Set( MsgSupp::InvalidDate ) << s;
}

void
DateTime::FmtGit( StrBuf &buf ) const
{
	int isdst = 0;
	int ofst = TzOffset( &isdst );

	int minutesOff = ofst / 60;
	minutesOff += 40 * ( minutesOff / 60 );

	sprintf( buf.Alloc( DateTimeZoneBufSize ),
	        "%ld %+05d", (long)tval, minutesOff );

	buf.SetLength( strlen( buf.Text() ) );
}

/*
 * CentralOffset - what's time_t's offset from midnight 1/1/70 GMT?
 *
 * Perforce time is always seconds since midnight 1/1/70 GMT, but some
 * OS's (notably the mac) use different epocs.  On the mac, it actually
 * depends on the library against which you link.  So this code, due to
 * Mark Lentzner, tries to divine the offset by clever use of gmtime()
 * and mktime().
 *
 * The offset is then fed to Localize() and Centralize(), which can then
 * used to shuffle from perforce to local time_t and vice versa.  Only
 * stat() and utime() seem to need this adjustment, not mktime().
 */

static int centralOffset;
static int centralInit = 0;

static void
CentralOffset()
{
	// Compute offset to centralized time: midnight Jan 1 1970 GMT

	// Find Midnight Jan 2 1970 localtime offset.

	struct tm tm;
	tm.tm_year = 70;
	tm.tm_mon = 0;
	tm.tm_mday = 2;
	tm.tm_hour = 0;
	tm.tm_min = 0;
	tm.tm_sec = 0;
	tm.tm_isdst = 0;

	centralOffset = mktime( &tm );

	// mktime returns localtime; shift to GMT

	// these are split because the C runtime library static
	// structure returned by gmtime above may be changed by mktime

	time_t dayone = 24*60*60;
	struct tm *tml = gmtime( &dayone );
	
	// 0 = GMT
	// + = local epoc is earlier than central
	// - = local epoc is after central (unlikely)

	centralOffset -= mktime( tml );

	// printf("Central Offset %d\n", centralOffset );

	centralInit = 1;
}

time_t
DateTime::Localize( time_t centralTime )
{
	if( !centralInit ) CentralOffset();
	return centralTime - centralOffset;
}

time_t
DateTime::Centralize( time_t localTime )
{
	if( !centralInit ) CentralOffset();
	return localTime + centralOffset;
}

DateTimeHighPrecision &
DateTimeHighPrecision::operator=( const DateTimeHighPrecision &rhs )
{
	if( this != &rhs ) {
	    seconds = rhs.seconds;
	    nanos = rhs.nanos;
	}

	return *this;
}

DateTimeHighPrecision &
DateTimeHighPrecision::operator+=( const DateTimeHighPrecision &rhs )
{
	P4INT64 sum = ToNanos() + rhs.ToNanos();
	seconds = sum / BILLION;
	nanos = sum % BILLION;

	return *this;
}

DateTimeHighPrecision &
DateTimeHighPrecision::operator-=( const DateTimeHighPrecision &rhs )
{
	P4INT64	diff = ToNanos() - rhs.ToNanos();
	seconds = diff / BILLION;
	nanos = diff % BILLION;

	return *this;
}

bool
DateTimeHighPrecision::operator==( const DateTimeHighPrecision &rhs ) const
{
	return seconds == rhs.seconds && nanos == rhs.nanos;
}

bool
DateTimeHighPrecision::operator!=( const DateTimeHighPrecision &rhs ) const
{
	return !(*this == rhs);
}

bool
DateTimeHighPrecision::operator<( const DateTimeHighPrecision &rhs ) const
{
	if( seconds < rhs.seconds )
	    return true;
	else if( seconds > rhs.seconds )
	    return false;
	else
	    return nanos < rhs.nanos;
}

bool
DateTimeHighPrecision::operator<=( const DateTimeHighPrecision &rhs ) const
{
	if( seconds < rhs.seconds )
	    return true;
	else if( seconds > rhs.seconds )
	    return false;
	else
	    return nanos <= rhs.nanos;
}

bool
DateTimeHighPrecision::operator>( const DateTimeHighPrecision &rhs ) const
{
	return !(*this <= rhs );
}

bool
DateTimeHighPrecision::operator>=( const DateTimeHighPrecision &rhs ) const
{
	return !(*this < rhs);
}

P4INT64
DateTimeHighPrecision::ToNanos() const
{
	return seconds * BILLION + nanos;
}

void
DateTimeHighPrecision::Now()
{
# if defined( HAVE_CLOCK_GETTIME )
	struct timespec ts;
	clock_gettime( CLOCK_REALTIME, &ts );
	seconds = ts.tv_sec;
	nanos   = ts.tv_nsec;
# elif defined( HAVE_GETTIMEOFDAY )
	struct timeval tv;
	gettimeofday( &tv, (struct timezone *)0 );
	seconds = tv.tv_sec;
	nanos   = tv.tv_usec * 1000;
# elif defined( HAVE_GETSYSTEMTIME ) && defined( OS_MINGW )
	// MINGW doesn't have _mkgmtime, but does have mktime.

	SYSTEMTIME st;
	struct tm l_tm;

	::GetLocalTime( &st );

	l_tm.tm_sec   = st.wSecond;
	l_tm.tm_min   = st.wMinute;
	l_tm.tm_hour  = st.wHour;
	l_tm.tm_mday  = st.wDay;
	l_tm.tm_mon   = st.wMonth - 1;
	l_tm.tm_year  = st.wYear - 1900;
	l_tm.tm_wday  = 0;
	l_tm.tm_yday  = 0;
	l_tm.tm_isdst = 0;

	seconds = DateTime::Centralize( ::mktime( &l_tm ) );
	nanos   = st.wMilliseconds * 1000000;
# elif defined( HAVE_GETSYSTEMTIME )
	SYSTEMTIME st;
	struct tm u_tm;

	::GetSystemTime( &st );

	u_tm.tm_sec   = st.wSecond;
	u_tm.tm_min   = st.wMinute;
	u_tm.tm_hour  = st.wHour;
	u_tm.tm_mday  = st.wDay;
	u_tm.tm_mon   = st.wMonth - 1;
	u_tm.tm_year  = st.wYear - 1900;
	u_tm.tm_wday  = 0;
	u_tm.tm_yday  = 0;
	u_tm.tm_isdst = 0;

	seconds = DateTime::Centralize( ::_mkgmtime( &u_tm ) );
	nanos   = st.wMilliseconds * 1000000;
# else
	// Not sure there are any systems in this category right now, but
	// just in case we find some systems that can't handle either
	// gettimeofday or clock_gettime:

	seconds = time(0);
	nanos = 0;
# endif
}

time_t
DateTimeHighPrecision::Seconds() const
{
	return seconds;
}

int
DateTimeHighPrecision::Nanos() const
{
	return nanos;
}

// format t2 - *this
void
DateTimeHighPrecision::FmtElapsed(
	StrBuf &buf,
	const DateTimeHighPrecision t2 ) const
{
	P4INT64	delta = t2.ToNanos() - ToNanos();
	int elapsedSeconds = delta / BILLION;
	int elapsedNanos = delta % BILLION;

	buf.Alloc( DTHighPrecisionBufSize );
#if 0
	// isn't this what we want?
	sprintf( buf.Text(), "%d.%dms", elapsedSeconds, elapsedNanos/MILLION );
#else
	// but this is what the previous code does
	if( elapsedSeconds )
	    sprintf( buf.Text(), "%ds", elapsedSeconds );
	else
	    sprintf( buf.Text(), "%dms", elapsedNanos / MILLION );
#endif
	buf.SetLength();
}

// return (t2 - *this) in nanoseconds
P4INT64
DateTimeHighPrecision::ElapsedNanos( const DateTimeHighPrecision &t2 ) const
{
	return t2.ToNanos() - ToNanos();
}

// return < 0, = 0, or > 0 if *this < rhs, *this == rhs, or *this > rhs, respectively
int
DateTimeHighPrecision::Compare( const DateTimeHighPrecision &rhs ) const
{
	if( seconds < rhs.seconds )
	    return -1;
	else if (seconds > rhs.seconds )
	    return 1;
	else
	    return nanos - rhs.nanos;
}

void
DateTimeHighPrecision::Fmt( char *buf ) const
{
	struct tm *tm = localtime( &seconds );

	// Don't die for a bogus date.

	if( tm )
	{
	    sprintf( buf, "%04d/%02d/%02d %02d:%02d:%02d %09d",
		    tm->tm_year < 1900 ? tm->tm_year + 1900 : tm->tm_year,
		    tm->tm_mon + 1,
		    tm->tm_mday,
		    tm->tm_hour,
		    tm->tm_min,
		    tm->tm_sec,
	            nanos);
	}
	else
	{
	    strcpy( buf, "1970/01/01" );
	}
}

