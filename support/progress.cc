/*
 * Copyright 1995, 2011 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <timer.h>
# include <progress.h>

ProgressReport::ProgressReport()
{
	fieldChanged = CP_NEW;
	units = 0;
	total = -1;
	position = 0;
	lastReportedPosition = 0;
	needfinal = 0;
	tm.Start();
}

ProgressReport::~ProgressReport()
{
	if( needfinal )
	    DoReport( CPP_FAILDONE );
}

void
ProgressReport::Description( const StrPtr &d )
{
	description = d;
	fieldChanged |= CP_DESC;
}

void
ProgressReport::Units( int u )
{
	units = u;
	fieldChanged |= CP_UNITS;
}

void
ProgressReport::Total( long t )
{
	total = t;
	fieldChanged |= CP_TOTAL;
}

void
ProgressReport::Position( long p, int flag )
{
	if( p != position )
	{
	    position = p;
	    fieldChanged |= CP_POS;
	}
	ConsiderReport( flag );
}

void
ProgressReport::Increment( long p, int flag )
{
	if( p != 0 )
	{
	    position += p;
	    fieldChanged |= CP_POS;
	}
	ConsiderReport( flag );
}

void
ProgressReport::ConsiderReport( int flag )
{
	if( flag == CPP_NORMAL )
	{
	    int tim = tm.Time();
	    if( tim < 500 )
		return;
	    tm.Restart();
	}
	DoReport( flag );
}

void
ProgressReport::DoReport( int flag )
{
}
