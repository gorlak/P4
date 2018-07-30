/*
 * Copyright 1995, 2009 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <intarray.h>
# include "jnltrack.h"

# include <ctype.h>

JnlTracker::JnlTracker()
    : pids(10)
{
	Clear();
}

void
JnlTracker::Clear()
{
	npids = maxpids = consistentcnt = markcnt[0] = markcnt[1] = 0;
	scanstate = 0;
	sawJTrailer = 0;
}

int
JnlTracker::Marker( long pid, Kind kind )
{
	++markcnt[ kind ];

	for ( int i = 0; i < npids; ++i )
	{
	    if( pids[i] == pid )
	    {
		if( kind == END )
		{
		    // existing end
		    if( i < --npids )
			pids[ i ] = pids[ npids ];
		    goto done;
		}
		// existing middle
		return 0;
	    }
	}

	if( kind == MIDDLE )
	{
	    // new middle
	    pids[ npids++ ] = pid;
	    if( npids > maxpids )
		maxpids = npids;
	    return 0;
	}

	// new end
	// 0 if not consistent, 1 if consistent
 done:
	if( npids )
	{
	    if( maxpids < npids + 1 )
		maxpids = npids + 1;
	    return 0;
	}
	if( !maxpids )
	    maxpids = 1;
	++consistentcnt;
	return 1;
}

void
JnlTracker::ScanJournal( const char *p, int l, const char **xact )
{
	while( l-- )
	{
	    int	c = *p++;

	    switch( scanstate )
	    {
	    case 0:
		// looking for string start at start of line
		// start
		if( c == '@' )
		    scanstate = 1;
		break;
	    case 1:
		// starting string at start of line
		scanstate = 4;
		if( c == 'm' )
		{
		    scankind = MIDDLE;
		    break;
		}
		else if( c == 'e' )
		{
		    scankind = END;
		    break;
		}
		else if( c == 'n' )
		{
		    // starting a journal note
		    scanstate = 9;
		    break;
		}
		// fall through...
	    instring:
		// in a string, need to end it
		scanstate = 2;
		// fall through...
	    case 2:
		// instring
		if( c == '@' )
		    scanstate = 3;
		break;
	    outstring:
		// out of that string
		scanstate = 3;
		// fall through...
	    case 3:
		// outstring
		if( c == '@' )
		    scanstate = 2;
		else if( c == '\n' )
		    scanstate = 0;
		break;
	    case 4:
		if( c == 'x' )
		    scanstate = 5;
		else
		    goto instring;
		break;
	    case 5:
		if( c == '@' )
		    scanstate = 6;
		else
		    scanstate = 2;
		break;
	    case 6:
		if( isdigit( c ) )
		{
		    scanpid = c - '0';
		    scanstate = 7;
		}
		else if( c != ' ' )
		    goto outstring;
		break;
	    case 7:
		if( isdigit( c ) )
		    scanpid = scanpid * 10 + c - '0';
		else
		{
		    if( c == ' ' && Marker( scanpid, scankind ) && xact )
			scanstate = 8;
		    else
			scanstate = 3;
		}
		break;
	    case 8:
		if( c == '\n' )
		{
		    scanstate = 0;
		    *xact = p;
		}
		break;
	    case 9:
		// starting a journal note
		if( c == 'x' )
		    scanstate = 10;
		else
		    goto instring;
		break;
	    case 10:
		if( c == '@' )
		    scanstate = 11;
		else
		    scanstate = 2;
		break;
	    case 11:
		// is this a server restart note
		if( c == ' ' )
		    break;
		if( c == '7' )
		{
		    Restart();	    // yes! server restart note
		    if( xact )
		    {
			scanstate = 8;
			break;
		    }
		}
		else if( c == '3' )
	            sawJTrailer = 1;
		goto outstring;
	    }
	}
}

int
JnlTracker::SawJournalTrailer()
{
	return sawJTrailer;
}

