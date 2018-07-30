/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <charman.h>
# include "mapchar.h"

const char *const MapChar::mapCharNames[] = {
	"0",
	"c",
	"/",
	"%",
	"*",
	"."
} ;

int
MapChar::operator -( char oc ) 
{
	return caseMode == -1 ? StrPtr::SCompare( c, oc )
	     : caseMode == 0  ? c - oc
	     : caseMode == 1  ? c == oc ? 0 : tolowerq( c ) - tolowerq( oc )
	                      : StrPtr::SCompare( c, oc );
}

int
MapChar::operator ==( char oc ) 
{
	if( caseMode == -1 )
	    return StrPtr::SEqual( c, oc );

	if( caseMode == 0 || caseMode == 1 )
	{
	    switch( c^oc ) 
	    {
		default: return 0;
		case 0: return 1;
		case 'A'^'a':
		    return caseMode == 0 ? c == oc
		                         : tolowerq( c ) == tolowerq( oc );
	    }
	}

	return StrPtr::SEqual( c, oc );
}
