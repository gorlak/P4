/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

//
// mapping.cc - the mapping master
//

# include <stdhdrs.h>
# include <error.h>
# include <strbuf.h>
# include <vararray.h>

# include <debug.h>
# include <tunable.h>

# include <msgdb.h>

# include "maphalf.h"
# include "maptable.h"
# include "mapstring.h"
# include "mapdebug.h"
# include "mapitem.h"

/*
 * mapFlagGrid -- how to combine two mapFlags
 */

MapFlag mapFlagGrid[6][6] = {

		/* Map */	/* Unmap */	/* Remap */	/* Havemap */	/* Changemap */	/* Andmap */
/* Map */	MfMap,		MfUnmap,	MfRemap,	MfHavemap,	MfChangemap,	MfAndmap,
/* Unmap */	MfUnmap,	MfUnmap,	MfUnmap,	MfUnmap,	MfUnmap,	MfUnmap,
/* Remap */	MfRemap,	MfUnmap,	MfRemap,	MfHavemap,	MfChangemap,	MfAndmap,
/* Havemap */	MfHavemap,	MfUnmap,	MfHavemap,	MfHavemap,	MfHavemap,	MfAndmap,
/* Changemap */	MfChangemap,	MfUnmap,	MfChangemap,	MfHavemap,	MfChangemap,	MfAndmap,
/* Andmap */	MfAndmap,	MfUnmap,	MfAndmap,	MfAndmap,	MfChangemap,	MfAndmap,

} ;

class MapJoiner : public Joiner {

    public:

	MapJoiner()
	{
	    badJoin = 0;
	    m0 = new MapTable;
	}

	virtual	void Insert()
	{
	    map->Lhs()->Expand( *this, newLhs, params );
	    map->Rhs()->Expand( *this, newRhs, params );
	    MapFlag mapFlag = mapFlagGrid[ map->Flag() ][ map2->Flag() ];
	    m0->InsertNoDups( newLhs, newRhs, mapFlag );
	}

    public:
	MapTable *m0;

	MapItem *map;
	MapItem *map2;

    protected:
	StrBuf newLhs;
	StrBuf newRhs;
} ;

class MapJoiner2 : public MapJoiner {

    public:
	MapTableT dir1;
	MapTableT dir2;

	MapJoiner2( MapTableT dir1, MapTableT dir2 )
	{
	    this->dir1 = dir1;
	    this->dir2 = dir2;
	}

	virtual	void Insert()
	{
	    map->Ohs( dir1 )->Expand( *this, newLhs, params );
	    map2->Ohs( dir2 )->Expand( *this, newRhs, params2 );
	    MapFlag mapFlag = mapFlagGrid[ map->Flag() ][ map2->Flag() ];
	    m0->InsertNoDups( newLhs, newRhs, mapFlag );
	}
} ;

void
MapTable::JoinOptimizer( MapTableT dir2 )
{
	if( !trees[ dir2 ].tree )
	    MakeTree( dir2 );
}

void
MapTable::Join( 
	MapTable *m1, MapTableT dir1, 
	MapTable *m2, MapTableT dir2,
	MapJoiner *j, const ErrorId *reason )
{
	if( DEBUG_JOIN )
	{
	    m1->Dump( dir1 == LHS ? "lhs" : "rhs" );
	    m2->Dump( dir2 == LHS ? "lhs" : "rhs" );
	}

	if( m1->caseMode == 0 || m1->caseMode == 1 )
	    this->SetCaseSensitivity( m1->caseMode );

	// Give up if we internally produce more than 1,000,000 rows
	// or more than 10000 + the sum of the two mappings.

	// This can happen when joining multiple lines with multiple
	// ...'s on them.

	const int max1 = p4tunable.Get( P4TUNE_MAP_JOINMAX1 );
	const int max2 = p4tunable.Get( P4TUNE_MAP_JOINMAX2 );

	int m = max1 + m1->count + m2->count;
	if( m > max2 ) m = max2;

	if( !m2->trees[ dir2 ].tree )
	{	
	  for(j->map = m1->entry; j->map && count<m; j->map = j->map->Next())
	        for(j->map2 = m2->entry; j->map2; j->map2 = j->map2->Next())
		{
	            j->map->Ths( dir1 )->Join( j->map2->Ths( dir2 ), *j );
		    if( j->badJoin )
		    {
			joinError = 1;
			emptyReason = &MsgDb::TooWild2;
			this->joinError = 1;
			this->emptyReason = &MsgDb::TooWild;
			return;
		    }
		}
	}
	else
	{
	    // Generate a list of possible pairs of maps to join.
	    // These are maps whose non-wild initial substrings match.
	    // We used to just do for()for(), but when joining large
	    // maps that's slow.  So the inner loop is now a tree
	    // search.  

	    MapPairArray pairArray( dir1, dir2 );

	    if( m2->trees[ dir2 ].tree )
	        for( MapItem *i1 = m1->entry; i1 && count < m; i1 = i1->Next() )
	    {
	        // This inserts entries in tree order,
	        // rather than chain order (precedence), so we have to
	        // resort before doing the MapHalf::Join() calls.

	        pairArray.Clear();
	        pairArray.Match( i1, m2->trees[ dir2 ].tree );
	        pairArray.Sort();

	        MapPair *jp;

	        // Walk the list of possible pairs and call MapHalf::Join()
	        // to do the wildcard joining.

	        for( int i = 0; jp = pairArray.Get(i); i++ )
	        {
		    j->map = jp->item1;
		    j->map2 = jp->tree2;
		    jp->h1->Join( jp->h2, *j );
		    delete jp;
	        }
	    }
	}

	// Insert() reverses the order

	this->Reverse();

	// Empty reasons

	if( count >= m )
	{
	    emptyReason = &MsgDb::TooWild;
	    Clear();
	}
	else if( m1->IsEmpty() && m1->emptyReason )
	{
	    emptyReason = m1->emptyReason;
	}
	else if( m2->IsEmpty() && m2->emptyReason )
	{
	    emptyReason = m2->emptyReason;
	}
	else if( !hasMaps && reason )
	{
	    emptyReason = reason;
	}

	if( DEBUG_JOIN )
	    this->Dump( "map joined" );
}

MapTable *
MapTable::Join( 
	MapTableT dir1, 
	MapTable *m2, 
	MapTableT dir2, 
	const ErrorId *reason )
{
	MapJoiner j;
	j.m0->Join( this, dir1, m2, dir2, &j, reason );
	return j.m0;
}

MapTable *
MapTable::Join2( 
	MapTableT dir1, 
	MapTable *m2, 
	MapTableT dir2, 
	const ErrorId *reason )
{
	MapJoiner2 j( dir1, dir2 );
	j.m0->Join( this, dir1, m2, dir2, &j, reason );
	return j.m0;
}

class MapDisambiguate : public MapJoiner {

    public:
	virtual	void Insert()
	{
	    map->Lhs()->Expand( *this, newLhs, params2 );
	    map->Rhs()->Expand( *this, newRhs, params2 );
	    m0->InsertNoDups( newLhs, newRhs, MfUnmap );
	}
} ;

/*
 * MapTable::JoinCheck() - does this maptable include this string?
 *
 * This isn't simply finding if a file is mapped by the table, but
 * rather if a _mapping_ is mapped by the table.  So we have to take
 * the mapping, put it into its own table, join it, and then throw
 * it all away.  Kinda _slow_.
 */

int
MapTable::JoinCheck( MapTableT dir, const StrPtr &lhs )
{
	MapTable c;

	c.Insert( lhs );
	MapTable *j = c.Join( LHS, this, dir );
	int empty = j->IsEmpty(); 
	delete j;

	return !empty;
}

int
MapTable::JoinCheck( MapTableT dir, MapTable *c, MapTableT dir2 )
{
	MapTable *j = c->Join( dir2, this, dir );
	int empty = j->IsEmpty(); 
	delete j;

	return !empty;
}

/*
 * MapTable::Disambiguate() - handle un/ambiguous mappings
 *
 *	Mappings provided by the user (client views, branch views)
 *	can be ambiguous since later mappings can override earlier
 *	ones.  Disambiguate() adds explicit exclusion (-) mappings 
 *	for any ambiguous mappings, so that Join() and Translate()
 *	don't have to worry about them.
 *
 *	For example:
 *
 *		a/... b/...
 *		a/c b/d
 *
 *	becomes
 *
 *		a/... b/...
 *		-a/c -b/c
 *		-a/d -b/d
 *		a/c b/d
 *
 *	Unmaps are handled similarly, but the high precedence unmap
 *	line itself is not added, because everything that can be unmapped
 *	has been done so by joining it against the lower precedence
 *	mapping lines:
 *
 *		a/... b/...
 *		-a/c b/d
 *
 *	becomes
 *
 *		a/... b/...
 *		-a/c -b/c
 *		-a/d -b/d
 */

void
MapTable::Disambiguate()
{
	MapDisambiguate j;

	// From high precendence to low precedence

	for( j.map = this->entry; j.map; j.map = j.map->Next() )
	{
	    // We skip unmap lines, because we only need to
	    // unmap to the extent that the unmap lines match lower
	    // precedence map lines.  We do that below.

	    switch( j.map->Flag() )
	    {
	    case MfUnmap:
		continue;
	    }

	    // Look for higher precedence mappings that match (join)
	    // this mapping, and to the extent that they overlap add 
	    // unmappings.  We do this for both MfMap and MfUnmap.
	    // A higher precedence MfRemap doesn't occlude us, so
	    // we skip those.

	    // From higher precedence back down to this mapping

	    for( j.map2 = this->entry; 
		 j.map2 != j.map;
		 j.map2 = j.map2->Next() )
	    {
		switch( j.map2->Flag() )
		{
		case MfRemap:
		case MfHavemap:
		    break;

		case MfAndmap:
		    j.map2->Lhs()->Join( j.map2->Rhs(), j );
		    j.map2->Rhs()->Join( j.map->Rhs(), j );
		    break;

		default:
		    j.map2->Lhs()->Join( j.map->Lhs(), j );
		    j.map2->Rhs()->Join( j.map->Rhs(), j );
		}
	    }

	    // now the original map entry

	    j.m0->Insert( *j.map->Lhs(), *j.map->Rhs(), j.map->Flag() );
	}

	// Inserted order leaves low precedence at the head of the
	// list.  Reverse to get it back where it belongs.

	j.m0->Reverse();

	// Just zonk our own and copy j.m0's

	Clear();
	Insert( j.m0, 1, 0 );
	delete j.m0;
}

