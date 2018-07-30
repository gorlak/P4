/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

//
// mapping.cc - the mapping master
//

# include <stdhdrs.h>
# include <ctype.h>
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

//
// CHARHASH - see diff sequencer for comments
//
# define CHARHASH( h, c ) ( 293 * (h) + (c) )

MapTable::MapTable()
{
	count = 0;
	entry = 0;
	hasMaps = 0;
	hasOverlays = 0;
	hasHavemaps = 0;
	hasAndmaps = 0;
	emptyReason = 0;
	joinError = 0;
	caseMode = -1;

	trees = new MapTree[2];
}

MapTable::~MapTable()
{
	Clear();
	delete []trees;
}

MapTable &
MapTable::operator=( MapTable &f )
{
        if( this == &f ) 
            return ( *this );

        Clear();
        Insert( &f, 1, 0 );

        return ( *this );
}

void
MapTable::Clear() 
{
        MapItem *map;

        for( map = entry; map; )
        {
            MapItem *next = map->Next();
            delete map;
            map = next;
        }

	count = 0;
	entry = 0;
	hasMaps = 0;
	hasOverlays = 0;
	hasHavemaps = 0;
	hasAndmaps = 0;

	trees[ LHS ].Clear();
	trees[ RHS ].Clear();
}

void
MapTable::SetCaseSensitivity( int mode )
{
	if( mode != 0 && mode != 1 )
	    return;

	caseMode = mode;

	for( MapItem *map = entry; map; map = map->Next() )
	{
	    map->Half( LHS )->SetCaseMode( mode );
	    map->Half( RHS )->SetCaseMode( mode );
	}
}

void
MapTable::Reverse()
{
	if( entry )
	    entry = entry->Reverse();
}

void
MapTable::Insert( MapTable *table, int fwd, int rev )
{
	MapItem *map;

	for( map = table->entry; map; map = map->Next() )
	{
	    if( fwd ) Insert( *map->Lhs(), *map->Rhs(), map->Flag() );
	    if( rev ) Insert( *map->Rhs(), *map->Lhs(), map->Flag() );
	}

	Reverse();
}

void
MapTable::Insert( const StrPtr &lhs, const StrPtr &rhs, MapFlag mapFlag )
{
	entry = new MapItem( entry, lhs, rhs, mapFlag, count++, caseMode );

	// For IsEmpty(), HasOverlays() and HasHavemaps()

	if( mapFlag != MfUnmap )
	    hasMaps = 1;

	if( mapFlag == MfRemap || mapFlag == MfHavemap )
	    hasOverlays = 1;

	if( mapFlag == MfHavemap )
	    hasHavemaps = 1;

	if( mapFlag == MfAndmap )
	    hasAndmaps = 1;

	trees[ LHS ].Clear();
	trees[ RHS ].Clear();
}

void
MapTable::Insert( const StrPtr &lhs, int slot, const StrPtr &rhs,
		  MapFlag mapFlag )
{
	Insert( lhs, rhs, mapFlag );
	entry = entry->Move( slot );
}

void
MapTable::InsertNoDups( 
	const StrPtr &lhs,
	const StrPtr &rhs,
	MapFlag mapFlag )
{
	// Try to suppress duplicate mappings.

	// Would be nice if Insert() took MapHalfs, rather
	// than starting with the StrPtr again.

	MapHalf hLhs( lhs );
	MapHalf hRhs( rhs );

	// We only look back so far, because big maps cost a 
	// lot to generate, as well.

	int max = 8;

	for( MapItem *map = entry; map && max--; map = map->Next() )
	{
	    if( mapFlag == MfRemap   || map->mapFlag == MfRemap ||
	        mapFlag == MfHavemap || map->mapFlag == MfHavemap )
	    {
	        // Remap and havemaps are additive, so we can
	        // only eliminate literal duplicates.

	        if( *map->Lhs() == lhs && *map->Rhs() == rhs )
	            return;
	    }
	    else
	    {
	        // Regular maps have precedence, and so earlier map entries 
	        // mask later additions.  We used to just check for duplicates, 
	        // but MapHalf::Match( MapHalf ) allows us to check for 
	        // superceding maps.  This limits wildcard expansion of maps 
	        // significantly.

		if( map->Lhs()->Match( hLhs ) && map->Rhs()->Match( hRhs ) )
		   return;
	    }
	}

	Insert( lhs, rhs, mapFlag );
}

void
MapTable::Remove( int slotNum )
{
	int slot = count - slotNum - 1;

	// Validate first
	if( slot < 0 || slot > entry->slot )
	    return;

	MapItem *target, *prev = 0;
	target = entry;

	// Reduce the slot number until we hit our target
	while( target->slot > slot )
	{
	    target->slot--;
	    prev = target;
	    target = target->chain;
	}

	// Rewire the chain (if no previous we're replacing the root)
	if( prev )
	    prev->chain = target->chain;
	else
	    entry = target->chain;

	// Free the memory
	delete target;
	count--;

	// Clean the cache
	trees[ LHS ].Clear();
	trees[ RHS ].Clear();
}

void
MapTable::Validate( const StrPtr &lhs, const StrPtr &rhs, Error *e )
{
	MapHalf l, r;

	l = lhs;
	r = rhs;

	l.Validate( &r, e );
}

void
MapTable::ValidHalf( MapTableT dir, Error *e )
{
	MapItem *map;

	for( map = entry; map; map = map->Next() )
	    map->Ths( dir )->Validate( 0, e );
}

int
MapTable::GetHash()
{
	unsigned int h = 0;
	MapItem *map;
	char *c;
	int i;

	for( map = entry; map; map = map->Next() )
	{
	    c = map->Lhs()->Text(); 
	    for( i = 0; i < map->Lhs()->Length(); ++i )
	        h = CHARHASH( h, *c++ );
	    c = map->Rhs()->Text(); 
	    for( i = 0; i < map->Rhs()->Length(); ++i )
	        h = CHARHASH( h, *c++ );
	    h = CHARHASH( h, map->Flag() );
	}

	return h;
}

void
MapTable::Dump( const char *trace, int fmt )
{
	MapItem *map;

	p4debug.printf( "map %s: %d items, joinError %d, emptyReason %d\n", 
		trace, count, joinError,
		(emptyReason == 0 ? 0 : emptyReason->SubCode()) );

	if( fmt == 0 )
	{
	  // dump in precedence order (most significant first)
	    for( map = entry; map; map = map->Next() )
	        p4debug.printf( "\t%c %s -> %s\n", 
			" -+$@&    123456789"[ map->Flag() ],
			map->Lhs()->Text(), 
			map->Rhs()->Text() );
	}
	else
	{
	    // dump in the order of a client view 
	    for( int i = Count() - 1; i >= 0; i--)
	        p4debug.printf( "\t%c %s -> %s\n",
			" -+$@&    123456789"[ GetFlag( Get( i )) ],
			Get( i )->Lhs()->Text( ), 
			Get( i )->Rhs()->Text( ) );
	}
}

void
MapTable::DumpTree( MapTableT dir, const char *trace )
{
	if( !trees[ dir ].tree )
	    MakeTree( dir );
	trees[dir].tree->Dump( dir, trace );
}

int
MapTable::IsSingle() const
{
	// There may be more than one valid mapping: we only look at the
	// highest precendence one, and it must have no widcards.
	// In theory, the check of the rhs is redundant: views are supposed
	// to have matching wildcards.  In theory, there is no difference
	// between theory and practice.  But in practice there is.

	return count >= 1 && !entry->Lhs()->IsWild() && !entry->Rhs()->IsWild();
}

//
// Sort for MakeTree, Strings
//
// Sort produces a MapItem * array, with the MapItem *'s in sorted order.
//
// Put higher precedent maps first -- this helps MapItem::Match().
//

// Needed for MVS.
// See: http://publib.boulder.ibm.com/infocenter/zos/v1r9/index.jsp?topic=/com.ibm.zos.r9.bpxbd00/qsort.htm
//
extern "C"
{
	
static int
sortcmplhs( const void *a1, const void *a2 )
{
	MapItem **e1 = (MapItem **)a1;
	MapItem **e2 = (MapItem **)a2;

	int r = (*e1)->Lhs()->Compare( *(*e2)->Lhs() );

	return r ? r : (*e2)->Slot() - (*e1)->Slot();
}

static int
sortcmprhs( const void *a1, const void *a2 )
{
	MapItem **e1 = (MapItem **)a1;
	MapItem **e2 = (MapItem **)a2;

	int r = (*e1)->Rhs()->Compare( *(*e2)->Rhs() );

	return r ? r : (*e2)->Slot() - (*e1)->Slot();
}


static int
sortcmpstreamslhs( const void *a1, const void *a2 )
{
        int c1, c2;
	MapItem **e1 = (MapItem **)a1;
	MapItem **e2 = (MapItem **)a2;
	char *str1 = (*e1)->Lhs()->Text();
	char *str2 = (*e2)->Lhs()->Text();
	
	int i = 0;
	int j = 0;

	// skip type values on the start of the RHS
	if( ( c1 = str1[ 0 ] ) == '%' || isdigit( c1 ) )
	{
	    while( str1[ i ] && ( c1 = str1[ i ] ) != '/' )
	        i++;
	}
	if( ( c2 = str2[ 0 ] ) == '%' || isdigit( c2 ) )
	{
	    while( str2[ j ] && ( c2 = str2[ j ] ) != '/' )
	        j++;
	}

	for( ; ( c1=str1[ i ] ) && ( c2=str2[ j ] ); i++, j++ )
	{
	    if( c1 == c2 )
	        continue;

	    if( 0 == strcmp( &str1[ i ], "...") )
	        return( -1 );

	    if( 0 == strcmp( &str2[ j ], "...") )
	        return( 1 );

	    if( c1 == '*' )
	        return( -1 );

	    if( c2 == '*' )
	        return( 1 );

	    if( c1 == '/' )
	        return( 1 );

	    if( c2 == '/' )
	        return( -1 );

	    // starting with 2013.1, this becomes non-default behavior.

	    if( p4tunable.Get( P4TUNE_STREAMVIEW_DOTS_LOW ) )
	    {
	    // make '.' lower than anything else
	    if( c1 == '.' )
	        return( 1 );

	    if( c2 == '.' )
	        return( -1 );
	    }

	    return( c1 - c2 );
        }

	return (*e1)->Slot() - (*e2)->Slot();	
}

/*
 * There RHS of a stream type map may have 'type value'
 * cruft on the start of teh map entry that we must skip..
 */
static int
sortcmpstreamsrhs( const void *a1, const void *a2 )
{
        int c1, c2;
	MapItem **e1 = (MapItem **)a1;
	MapItem **e2 = (MapItem **)a2;
	char *str1 = (*e1)->Rhs()->Text();
	char *str2 = (*e2)->Rhs()->Text();
	
	int i = 0;
	int j = 0;

	// skip type values on the start of the RHS
	if( ( c1 = str1[ 0 ] ) == '%' || isdigit( c1 ) )
	{
	    while( ( c1 = str1[ i ] ) != '/' )
	        i++;
	}
	if( ( c2 = str2[ 0 ] ) == '%' || isdigit( c2 ) )
	{
	    while( ( c2 = str2[ j ] ) != '/' )
	        j++;
	}

	for(; ( c1 = str1[ i ] ) && ( c2 = str2[ j ] ); i++, j++ )
	{
  
	    if( c1 == c2 )
	        continue;

	    if( 0 == strcmp( &str1[ i ], "...") )
	        return( -1 );

	    if( 0 == strcmp( &str2[ j ], "...") )
	        return( 1 );

	    if( c1 == '*' )
	        return( -1 );

	    if( c2 == '*' )
	        return( 1 );

	    if( c1 == '/' )
	        return( -1 );

	    if( c2 == '/' )
	        return( 1 );

	    // starting with 2013.1, this becomes non-default behavior.

	    if( p4tunable.Get( P4TUNE_STREAMVIEW_DOTS_LOW ) )
	    {
	    // make '.' lower than anything else
	    if( c1 == '.' )
	        return( 1 );

	    if( c2 == '.' )
	        return( -1 );
	    }

	    return( c1 - c2 );
        }

	return (*e1)->Slot() - (*e2)->Slot();	
}

} //extern "C"

MapItem **
MapTable::Sort( MapTableT direction, int streamFlag )
{
	// Both Strings and MakeTree want this.

	/*
	 * We cache only non-stream sort results.
	 * Stream sort calls happen at most once per MapTable instance
	 * (in the td tests, so probably also in real life).
	 * Incidentally, td measured an average of 1.45 non-stream sort calls
	 * per instance, so not a huge win there either.
	 * No instances received both stream and non-stream sort calls,
	 * but we check just in case the usage changes in the future.
	 */
	if( !streamFlag && trees[ direction ].sort )
	    return trees[ direction ].sort;

	// Create sort tree

	MapItem **vec = new MapItem *[count];
	MapItem **vecp;

	MapItem *map;

	for( vecp = vec, map = entry; map; map = map->Next() )
	    *vecp++ = map;

	// MACHTEN (gcc 2.3.3) belched at dir==LHS?lhs:rhs
	// Thus this 'if'.
	if( streamFlag )
	{
	    if( direction == LHS )
	        qsort( (char *)vec, count, sizeof( *vec ), sortcmpstreamslhs );
	    else
	        qsort( (char *)vec, count, sizeof( *vec ), sortcmpstreamsrhs );
	    return vec;
	}
	else
	{
	    if( direction == LHS )
	        qsort( (char *)vec, count, sizeof( *vec ), sortcmplhs );
	    else
	        qsort( (char *)vec, count, sizeof( *vec ), sortcmprhs );

	    // save it
	    return trees[ direction ].sort = vec;
	}
}

//
// Map tree construction
//

void
MapTable::MakeTree( MapTableT dir )
{
	int depth = 0;

	MapItem **vec = Sort( dir );

	trees[ dir ].tree = MapItem::Tree( vec, vec + Count(), dir, 0, depth );
	trees[ dir ].depth = depth;
}

//
// MapTable::Better - which table is better for matching?
// 

int
MapTable::Better( MapTable &other, MapTableT dir )
{
	// If we couldn't make a better map because of
	// wildcard explosion, this isn't better than the other.

	if( emptyReason == &MsgDb::TooWild )
	    return 0;

	// Compute the search trees, so we can compare depth.

	if( !trees[ dir ].tree )
	    MakeTree( dir );

	if( !other.trees[ dir ].tree )
	    other.MakeTree( dir );

	// shallower depth generally means faster matching

	return trees[ dir ].depth < other.trees[ dir ].depth;
}

//
// MapStrings construction
//

MapStrings *
MapTable::Strings( MapTableT direction )
{
	MapItem **vec = Sort( direction );
	MapStrings *strings = new MapStrings();
	MapHalf *oMapHalf = 0;
	int oHasSubDirs = 0;

	for( int i = 0; i < count; i++ )
	{
	    // If this is an unmapping, we're not going to get any
	    // satisfaction looking for strings.  Just skip it.

	    if( vec[i]->Flag() == MfUnmap )
		continue;

	    // Find out how much of MapHalf is fixed (non wildcard)
	    // and how much of that matches the saved MapHalf.
	    // Note that match <= fixedLen, because we only match
	    // the fixed portion.

	    MapHalf *mapHalf = vec[i]->Ths( direction );

	    if( oMapHalf )
	    {
		int match = oMapHalf->GetCommonLen( mapHalf );

		if( DEBUG_STRINGS )
		    p4debug.printf( "MapStrings: %s match %d fixed %d\n",
			    mapHalf->Text(), match, 
			    mapHalf->GetFixedLen() );

		// If this MapHalf matched the whole fixed part of the 
		// saved MapHalf (GetCommonLen() can match no more), 
		// then this MapHalf's is a substring of the saved,
		// and so won't needs its own string.

		// But: if this MapHalf has subdirectories, we'll have
		// to mark the saved MapHalf's string as having them.

		if( match == oMapHalf->GetFixedLen() )
		{
		    oHasSubDirs |= mapHalf->HasSubDirs( match );
		    continue;
		}

		// Output old string if new is not substring.
		// Then continue with valid part of new

		if( mapHalf->GetFixedLen() > match )
		    strings->Add( oMapHalf, oHasSubDirs );
	    }

	    oMapHalf = mapHalf;
	    oHasSubDirs = mapHalf->HasSubDirs( mapHalf->GetFixedLen() );
	}

	// We've held onto oMapHalf for the possibility that a new
	// mapHalf would be an initial substring.  Now that there are
	// no more mapHalfs, output the oMapHalf.

	if( oMapHalf )
	    strings->Add( oMapHalf, oHasSubDirs );

	if( DEBUG_STRINGS )
	    strings->Dump();

	return strings;
}

//
// MapTable::Check() - see if lhs matches map
//

MapItem *
MapTable::Check(
	MapTableT dir,
	const StrPtr &from )
{
	if( !trees[ dir ].tree )
	    MakeTree( dir );

	return trees[ dir ].tree ? trees[ dir ].tree->Match( dir, from ) : 0;
}

//
// MapTable::Translate() - map an lhs into an rhs
//

MapItem *
MapTable::Translate(
	MapTableT dir,
	const StrPtr &from,
	StrBuf &to )
{
	Error e;
	if( !trees[ dir ].tree )
	    MakeTree( dir );

	MapItem *map = trees[ dir ].tree
	    ? trees[ dir ].tree->Match( dir, from )
	    : 0;

	// Expand into target string.
	// We have to Match2 here, because the last Match2 done in
	// MapItem::Match may not have been the last to succeed.

	if( map )
	{
	    MapParams params;

	    map->Ths( dir )->Match2( from, params );
	    map->Ohs( dir )->Expand( from, to, params );

	    if( DEBUG_TRANS )
		p4debug.printf( "MapTrans: %s (%d) -> %s\n", 
		    from.Text(), map->Slot(), to.Text() );
	}

	return map;
}

//
// MapTable::Explode() - map an lhs into one or more rhs's
//

MapItemArray *
MapTable::Explode( MapTableT dir, const StrPtr &from)
{
	
	MapItemArray *maps = new MapItemArray;
	Error e;

	if( !trees[ dir ].tree )
	    MakeTree( dir );
	
	MapItemArray ands;
	MapItem *map;

	trees[ dir ].tree->Match( dir, from, &ands );

	// Expand into target string.
	// We have to Match2 here, because the last Match2 done in
	// MapItem::Match may not have been the last to succeed.

	int i = 0;
	int nonand = 0;
	StrBuf to;
	while( ( map = ands.Get( i++ ) ) )
	{
	    MapParams params;
	    if( !map->Ths( dir )->Match2( from, params ) ||
		map->Flag() == MfUnmap )
		return maps;

	    if( map->Flag() != MfAndmap && nonand++ )
		continue;

	    to.Clear();
	    map->Ohs( dir )->Expand( from, to, params );

	    if( DEBUG_TRANS )
		p4debug.printf( "MapTrans: %s (%d) -> %s\n", 
		    from.Text(), map->Slot(), to.Text() );

	    maps->Put( map, &to );
	}

	return maps;
}
//
// MapTable::Match() - just match pattern against string
//

int
MapTable::Match(
	MapHalf *l,
	const StrPtr &rhs )
{
	MapParams params;
	return l->Match( rhs, params );
}

//
// MapTable::Match() - just match pattern against string
//

int
MapTable::Match(
	const StrPtr &lhs,
	const StrPtr &rhs )
{
	MapHalf l;
	l = lhs;
	MapParams params;
	return l.Match( rhs, params );
}

//
// MapTable::ValidDepotMap() - return 1 if map is a valid depot map entry
//

int
MapTable::ValidDepotMap( const StrPtr &map )
{
	MapHalf l;
	l = map;

	// Valid depot map has only one wildcard, and it must
	// be a trailing wildcard of the form '/...'

	return l.WildcardCount() == 1 && l.HasEndSlashEllipses();
}

//
// MapTable::Get() - get a MapTable entry
//

MapItem *
MapTable::Get( int n )
{
	MapItem *map;

	for( map = entry; map; map = map->Next() )
	    if( !n-- )
		return map;

	return 0;
}

//
// MapItem accessors
//

int
MapTable::GetSlot( MapItem *m )
{
	return count - m->Slot() - 1;
}

MapFlag
MapTable::GetFlag( MapItem *m )
{
	return m->Flag();
}

MapItem *
MapTable::GetNext( MapItem *m )
{
	return m->Next();
}

const StrPtr *
MapTable::GetStr( MapItem *m, MapTableT dir )
{
	return m->Ths( dir );
}

int
MapTable::Translate( 
	MapItem *m,
	MapTableT dir,
	const StrPtr &from,
	StrBuf &to )
{
	MapParams params;

	if( m->Flag() == MfUnmap )
	    return 0;

	if( !m->Ths( dir )->Match( from, params ) )
	    return 0;

	// Expand into target string.

	m->Ohs( dir )->Expand( from, to, params );

	return 1;
}

/*
 * MapTable::StripMap() - return copy without mapFlag entries.
 */

MapTable *
MapTable::StripMap( MapFlag mapFlag )
{
	MapTable *m0 = new MapTable;
	MapItem *map;

	for( map = entry; map; map = map->Next() )
	    if( map->Flag() != mapFlag )
		m0->Insert( *map->Lhs(), *map->Rhs(), map->Flag() );

	m0->Reverse();

	return m0;
}

/*
 * MapTable::Swap() - return copy with LHS and RHS swapped for each MapItem.
 */

MapTable *
MapTable::Swap( MapTable *table )
{
	MapTable *m0 = new MapTable;
	MapItem *map;

	for( map = entry; map; map = map->Next() )
	    m0->Insert( *map->Rhs(), *map->Lhs(), map->Flag() );

	m0->Reverse();

	return m0;

}

int
MapTable::CountByFlag( MapFlag mapFlag )
{
	int result = 0;
	MapItem *map;

	for( map = entry; map; map = map->Next() )
	    result += ( map->Flag() == mapFlag );

	return result;
}

void
MapTable::InsertByPattern( 
	const StrPtr &lhs, 
	const StrPtr &rhs, 
	MapFlag mapFlag )
{
	char *l = lhs.End();
	char *r = rhs.End();
	char *ls = lhs.Text();
	char *rs = rhs.Text();
	int slashes;

	// Insist on starting after //xxx/

	for( slashes = 0; slashes < 3 && ls < l; ++ls )
	    slashes += *ls == '/';

	for( slashes = 0; slashes < 3 && rs < r; ++rs )
	    slashes += *rs == '/';

	// Find matching ending substring

	slashes = 0;

	while( l > ls && r > rs && StrPtr::SEqual( l[-1], r[-1] ) )
	{
	    --l, --r;
	    slashes += *l == '/';
	}

	// Don't strip off the last mismatching /

	if( l < lhs.End() && *l == '/' )
	    ++l, ++r, --slashes;

	// Don't strip off trailing . if we are adding ...

	if( ( ( l < lhs.End() && l[-1] == '.' ) ||
	      ( r < rhs.End() && r[-1] == '.' ) ) && slashes )
	    ++l, ++r;

	// Replace end with * or ...
	// And put it on the map

	if( slashes && l < lhs.End() - 3 )
	{
	    StrBuf left;
	    left.Append( lhs.Text(), l - lhs.Text() );
	    left.Append( "...", 3 );

	    StrBuf right;
	    right.Append( rhs.Text(), r - rhs.Text() );
	    right.Append( "...", 3 );

	    InsertNoDups( left, right, mapFlag );
	}
	else if( !slashes && l < lhs.End() - 1 )
	{
	    StrBuf left;
	    left.Append( lhs.Text(), l - lhs.Text() );
	    left.Append( "*", 1 );

	    StrBuf right;
	    right.Append( rhs.Text(), r - rhs.Text() );
	    right.Append( "*", 1 );

	    InsertNoDups( left, right, mapFlag );
	}
	else
	    InsertNoDups( lhs, rhs, mapFlag );
}
