/*
 * Copyright 2002 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * diffflags.cc - parse diff's -d<flags>
 */

#include <stdhdrs.h>
#include <strbuf.h>
#include <error.h>

#include "diff.h"

void
DiffFlags::Init( const StrPtr *flags )
{
	Init( flags ? flags->Text() : 0 );
}

void 
DiffFlags::Init( const char *flags )
{
	type = Normal;
	sequence = Line;
	grid = Optimal;
	contextCount = 0;
	int someDigit = 0;

	if( !flags )
	    return;

	for( ; *flags; ++flags )
	    switch( *flags )
	{

	// P4MERGE, reserved flag (don't use!)

	case 'a':		break; 

	// mods -b, -w, -l

	case 'l':		sequence = DashL; break;
	case 'b':		sequence = DashB; break;
	case 'w':		sequence = DashW; break;

	// types

	case 'c': case 'C':	type = Context; break;
	case 'h': case 'H':	type = HTML; sequence = Word; break;
	case 'v':		type = HTML; sequence = WClass; break;
	case 'n':		type = Rcs; break;
	case 's':		type = Summary; break;
	case 'u': case 'U':	type = Unified; break;

	// grid

	case 'g': case 'G':	if( grid == Diff3 ) grid = GuardedDiff3;
	                                       else grid = Guarded;
	                        break;

	case 'x': case 'X':	if( grid == Guarded ) grid = GuardedDiff3;
	                                         else grid = Diff3;
	                        break;

	case 't': case 'T':	grid = TwoWay; break;

	// Simple atoi()

	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
		contextCount = contextCount * 10 + *flags - '0';
		someDigit = 1;
		break;
	}
	if( !someDigit )
	    contextCount = -1;
}
