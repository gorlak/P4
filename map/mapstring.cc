/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

//
// mapstrings.cc - handle initial substring list for maps
//

# include <stdhdrs.h>
# include <error.h>
# include <strbuf.h>
# include <vararray.h>
# include <debug.h>

# include "maphalf.h"
# include "maptable.h"
# include "mapstring.h"

struct MapString {

	int		hasSubDirs;	// Subdirs after wildcard?
	MapHalf		*mapHalf;	// actual mapHalf

} ;



MapStrings::MapStrings()
{
	strs = new VarArray();
}

MapStrings::~MapStrings()
{
	if( !strs )
	    return;

	for( int i = 0; i < strs->Count(); i++ )
		delete (MapString *)strs->Get( i );

	delete strs;
}

void
MapStrings::Add( MapHalf *mapHalf, int hasSubDirs )
{
	MapString *s = new MapString;
	s->mapHalf = mapHalf;
	s->hasSubDirs = hasSubDirs;
	strs->Put( s );
}
        
int
MapStrings::Count()
{
	return strs->Count();
}

void
MapStrings::Get( int n, StrRef &string, int &hasSubDirs )
{
	MapString *s = (MapString *)strs->Get(n);
	string.Set( s->mapHalf->Text(), s->mapHalf->GetFixedLen() );
	hasSubDirs = s->hasSubDirs;
}

void
MapStrings::Dump()
{
	p4debug.printf( "strings for map:\n" );

	for( int i = 0; i < Count(); i++ )
	    p4debug.printf( "\t-> %d: %.*s (%d)\n", i, 
		((MapString *)strs->Get(i))->mapHalf->GetFixedLen(),
		((MapString *)strs->Get(i))->mapHalf->Text(),
		((MapString *)strs->Get(i))->hasSubDirs );
}
