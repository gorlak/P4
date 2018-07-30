/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * MapItem -- mapping entries on a chain
 *
 * A MapItem holds two MapHalfs that constitute a single entry in
 * a MapTable.  MapItem also implement fast searching for entries
 * for MapTable::Check() and MapTable::Translate().
 */

# include <stdhdrs.h>
# include <error.h>
# include <strbuf.h>
# include <vararray.h>

# include <debug.h>

# include "maphalf.h"
# include "maptable.h"
# include "mapstring.h"
# include "mapdebug.h"
# include "mapitem.h"

/*
 * MapItem::Reverse - reverse the chain, to swap precedence
 */

MapItem *
MapItem::Reverse()
{
	MapItem *m = this;
	MapItem *entry = 0;
	int top = m ? m->slot : 0;

	while( m )
	{
	    MapItem *n = m->chain;
	    m->chain = entry;
	    m->slot = top - m->slot;
	    entry = m;
	    m = n;
	}

	return entry;
}

/*
 * MapItem::Move - moves an item up the chain
 */

MapItem *
MapItem::Move( int slot )
{
	MapItem *m = this;
	MapItem *entry = m->chain;

	int start = m->slot;

	// This has no error state, but this is bad
	// We can't go below 0 and we can't go back up either
	if( start <= slot )
	    return m;

	if( slot < 0 )
	    slot = 0;


	MapItem *n = m->chain;
	while( n )
	{
	    if( n->slot != slot )
	    {
	        n->slot++;
	        n = n->chain;
	        continue;
	    }
	    
	    n->slot++;
	    m->slot = slot;
	    m->chain = n->chain;
	    n->chain = m;
	    
	    break;
	}

	return entry;
}

/*
 * MapItem::Tree - recursively construct a trinary sort tree
 */

MapItem *
MapItem::Tree( 
	MapItem **start,
	MapItem **end,
	MapTableT dir,
	MapItem *parent,
	int &depth )
{
	/* No empties */

	if( start == end )
	    return 0;

	/*
	 * start li (middle) ri end 
	 *
	 * (middle) is halfway between start and end.
	 * li is first item that is a parent of middle.
	 * ri is last item li is a parent of.
	 *
	 * We return
	 *
	 *	         *li
	 *             /  |  \
	 *            /   |   \
	 *	     /    |    \
	 *          /     |     \
	 * start->li   li+1->ri  ri->end
	 */

	MapItem **li = start;
	MapItem **ri;

	/*
	 * Quick check: the center tree often ends up in the
	 * shape of a linked list (due to identical entries).
	 * This is an optimization for that case.
	 */

	if( start == end - 1 || (*start)->IsParent( end[-1], dir ) )
	{
	    ri = end;

	    int overlap = 0;
	    int depthBelow = 0;
	    int maxSlot = 0;
	    int hasands = 0;
	    int maxSlotNoAnds = -1;
	    int pLength = (*start)->Ths( dir )->GetFixedLen();

	    MapItem *last = 0;
	    MapItem::MapWhole *t;

	    while( --ri > start )
		if( (*ri)->Ths( dir )->GetFixedLen() == pLength )
		    break;

	    if( parent )
		overlap = (*start)->Ths( dir )->GetCommonLen( parent->Ths( dir ) );
	    if( ri < end - 1 )
	    {
		t = (*ri)->Whole( dir );

		t->overlap = overlap;
		t->maxSlot = (*ri)->slot;
		t->right = t->left = NULL;
		t->hasands = 0;
		t->maxSlotNoAnds = (*ri)->Flag() != MfAndmap ? (*ri)->slot : -1;

		t->center = Tree( ri + 1, end, dir, *ri, depthBelow );
		
		if( maxSlot < t->maxSlot )
		    maxSlot = t->maxSlot;

		if( maxSlotNoAnds < t->maxSlotNoAnds )
		    maxSlotNoAnds = t->maxSlotNoAnds;

		if( t->hasands )
		    hasands = 1;

		if( parent && ( (*ri)->mapFlag == MfAndmap || t->hasands ) )
		    parent->Whole( dir )->hasands = 1;

		last = *ri--;
		++depthBelow;
	    }

	    depthBelow += ri - start + 1;

	    while( ri >= start )
	    {
		t = (*ri)->Whole( dir );

		t->overlap = overlap;

		if( maxSlot < (*ri)->slot )
		    maxSlot = (*ri)->slot;
		t->maxSlot = maxSlot;

		if( (*ri)->Flag() != MfAndmap && maxSlotNoAnds < (*ri)->slot )
		    maxSlotNoAnds = (*ri)->slot;
		t->maxSlotNoAnds = maxSlotNoAnds;

		hasands = ( last && last->mapFlag == MfAndmap ) ? 1 : 0;
		t->hasands = hasands;

		t->right = t->left = NULL;
		t->center = last;
		last = *ri--;
	    }

	    if( parent && parent->Whole( dir )->maxSlot < maxSlot )
		parent->Whole( dir )->maxSlot = maxSlot;

	    if( parent && parent->Whole( dir )->maxSlotNoAnds < maxSlotNoAnds )
		parent->Whole( dir )->maxSlotNoAnds = maxSlotNoAnds;

	    if( parent && ( hasands || ( last && last->mapFlag == MfAndmap ) ))
		parent->Whole( dir )->hasands = 1;

	    if( depth < depthBelow )
		depth = depthBelow;

	    return *li;
	}
	else 

	/*
	 * Start in middle.
	 * Move li from start until we find first parent of ri.
	 * Move ri right until we find last child of li.
	 */

	{
	    ri = start + ( end - start ) / 2;

	    while( li < ri && !(*li)->IsParent( *ri, dir ) )
		++li;

	    while( ri < end && (*li)->IsParent( *ri, dir ) )
		++ri;
	}

	/*
	 * Fill in the *li node, which we will return.
	 *
	 * left, right, center computed recursively.
	 */

	MapItem::MapWhole *t = (*li)->Whole( dir );

	int depthBelow = 0;

	t->overlap = 0;
	t->maxSlot = (*li)->slot;
	t->hasands = 0;
	t->maxSlotNoAnds = (*li)->Flag() != MfAndmap ? (*li)->slot : -1;

	t->left =    Tree( start, li, dir, *li, depthBelow );
	t->center =  Tree( li + 1, ri, dir, *li, depthBelow );
	t->right =   Tree( ri, end, dir, *li, depthBelow );

	/*
	 * Current depth is 1 + what's below us, as long as one of
	 * our peers isn't deeper.
	 */

	if( depth < depthBelow + 1 )
	    depth = depthBelow + 1;

	/*
	 * Relationship to parent:
	 * parent's maxSlot includes our maxSlot.
	 * our initial substring overlap with our parent.
	 */

	if( parent )
	{
	    if( parent->Whole( dir )->maxSlot < t->maxSlot )
		parent->Whole( dir )->maxSlot = t->maxSlot;

	    if( parent->Whole( dir )->maxSlotNoAnds < t->maxSlotNoAnds )
		parent->Whole( dir )->maxSlotNoAnds = t->maxSlotNoAnds;

	    t->overlap = t->half.GetCommonLen( parent->Ths( dir ) );

	    if( (*li)->mapFlag == MfAndmap || t->hasands )
		parent->Whole( dir )->hasands = 1;
	}

	return *li;
}

/*
 * MapItem::Match() - find best matching MapItem
 *
 * We have a chain of MapItems, but instead use trinary tree constructed
 * by MapItem::Tree for this direction.
 *
 * This has three separate optimizations:
 *
 *	1. The trinary tree itself (instead of a linear scan).  We use
 *	   a trinary tree because we need to order mappings that are
 *	   neither less than nor greater than others, but including them.
 *	   e.g. //depot/main/... includes //depot/main/p4...  As we
 *	   decend the tree, we use MapHalf::Match1 to compare the initial
 *	   substring.  If it matches, we will use MapHalf::Match2 to
 *	   do the wildcard comparison and then follow the center down.
 *
 *	2. Slot precedence.  Once we've had a match, we only need to Match2
 *	   nodes with better precedence (map->slot > best).  Further, once
 *	   we've had a match, we can give up entirely if the tree below
 *	   has no nodes with higher precedence (best > t->maxSlot).
 *
 *	3. Overlap.  As we decend the tree, many of the strings have
 *	   initial substrings in common.  So we remember the offset of 
 *	   the last matching character in the parent's MapHalf, adjust it 
 *	   down if needed so as not to exceed the operlap with this
 *	   MapHalf, and start the match from there.
 */

MapItem *
MapItem::Match( MapTableT dir, const StrPtr &from, MapItemArray *ands )
{
	int coff = 0;
	int best = -1;
	int bestnotands = -1;
	int ourarray = 0;
	MapItem *map = 0;
	MapItem *tree = this;
	MapParams params;

	if( !ands && (tree->Whole( dir )->hasands || tree->Flag() == MfAndmap))
	{
	    ourarray = 1;
	    ands = new MapItemArray;
	}

	/* Decend */

	while( tree )
	{
	    MapItem::MapWhole *t = tree->Whole( dir );

	    /*
	     * No better precendence below?  Bail. 
	     * Unless we're looking for andmaps
	     */

	    if( best > t->maxSlot &&	    // Have we already got the best?
		!t->hasands &&		    // Are there andmaps down the tree?
		tree->Flag() != MfAndmap && // This is an andmap?
		bestnotands > t->maxSlotNoAnds ) // We prefer a real mapping
		break;

	    /*
	     * Match with prev map greater than overlap?  trim. 
	     */

	    if( coff > t->overlap )
		coff = t->overlap;

	    /*
	     * Match initial substring (by which the tree is ordered). 
	     * Can skip match if same initial substring as previous map.
	     */

	    int r = 0;

	    if( coff < t->half.GetFixedLen() )
		r = t->half.Match1( from, coff );

	    /*
	     * Match?  Higher precedence?  Wildcard match?  Save. 
	     */

	    if( !r &&
		best < tree->slot &&
		t->half.Match2( from, params ) )
	    {
		map = tree, best = map->slot;
		if( ands )
		    ands->Put( tree );
		if( tree->Flag() != MfAndmap )
		    bestnotands = tree->slot;
	    }

	    /*
	     * Not higher precedence? AndMap Array? Wildcard match? Save
	     */

	    if( !r &&
		ands &&
		map != tree &&
		best >= tree->slot &&
		t->half.Match2( from, params ) )
	    {
		ands->Put( tree );
		if( tree->Flag() != MfAndmap )
		    bestnotands = tree->slot;
	    }

	    /*
	     * Follow to appropriate child. 
	     */

	    if( r < 0 ) 	tree = t->left;
	    else if( r > 0 ) 	tree = t->right;
	    else 		tree = t->center;
	}

	/*
	 * If we were dealing with & maps, we need to make sure we either:
	 *   1. return the highest precedence non-andmap mapping
	 *   2. return the highest precedence andmap mapping
	 */

	if( map && ands )
	{
	    MapItem *m0 = 0;
	    int i = 0;
	    while( ( m0 = (MapItem *) ands->Get( i++ ) ) )
		if( m0->Flag() != MfAndmap )
		{
		    if( m0->mapFlag == MfUnmap )
			break; // Take the best & mapping and break

		    map = m0; // Take the best non-& mapping and break
		    break;
		}
		else if( i == 1 )
		    map = m0; // Take the best & mapping; keep going
	}

	if( ourarray )
	    delete ands;

	/* 
	 * Best mapping an unmapping?  That's no mapping.
	 */

	if( !map || map->mapFlag == MfUnmap )
	    return 0;

	return map;
}

/*
 * MapPairArray -- pre-join two maps by using the MapTrees
 */

int 
MapPairArray::Compare( const void *a1, const void *a2 ) const
{
	return ((MapPair *)a1)->CompareSlot( (MapPair *)a2 );
}

void
MapPairArray::Match( MapItem *item1, MapItem *tree2 )
{
	// Do non-wildcard initial substrings match?

	MapItem::MapWhole *t1 = item1->Whole( dir1 );

	do {

	    MapItem::MapWhole *t2 = tree2->Whole( dir2 );

	    int r = t2->half.MatchHead( t1->half );

	    if( DEBUG_JOIN )
		p4debug.printf("cmp %d %s %s\n", r, t1->half.Text(), t2->half.Text() );

	    // On match, add this to list of pairs for MapHalf::Join()

	    if( !r && !t2->half.MatchTail( t1->half ) )
		Put( new MapPair( item1, tree2, &t1->half, &t2->half ) );

	    // Recursively explore other matching possibilities.

	    if( r <= 0 && t2->left )   Match( item1, t2->left );
	    if( r >= 0 && t2->right )  Match( item1, t2->right );

	    if( r != 0 )
		return;

	    // tail iteration down the center

	    tree2 = t2->center;
	} while( tree2 );
}

/*
 * MapItemArray -- Slot ordered list of MapItems
 */

struct MapWrap {
	MapItem *map;
	StrBuf to;
} ;

MapItemArray::~MapItemArray()
{
	for( int i = 0; i < Count(); i++ )
	    delete (MapWrap *) VarArray::Get( i );
}

MapItem *
MapItemArray::Get( int i )
{
	MapWrap *w = (MapWrap *) VarArray::Get( i );
	return w ? w->map : 0;
}

StrPtr *
MapItemArray::GetTranslation( int i )
{
	MapWrap *w = (MapWrap *) VarArray::Get( i );
	return w ? &w->to : 0;
}

MapItem *
MapItemArray::Put( MapItem *item, StrPtr *trans )
{
	// add the item to the end of the list
	MapWrap *wrap = new MapWrap;
	wrap->map = item;
	if( trans )
	    wrap->to = *trans;

	VarArray::Put( wrap );

	int s = Count(); // index of item + 1

	if( s <= 1 )
	    return item; // only the item we've just added: must be sorted!

	// find the index of the first item with a lower slot than item's
	int i = 0;
	while( Get( i )->slot > item->slot )
	    i++;

	// shuffle the pointers along so that item takes its rightful place
	while( s-- > i + 1)
	    Swap( s - 1, s );

	return item;
}

int
MapItemArray::PutTree( MapItem *item, MapTableT dir )
{
	if( !item )
	    return 0;

	Put( item );
	int count = 1;
	count += PutTree( item->Whole( dir )->left, dir );
	count += PutTree( item->Whole( dir )->center, dir );
	count += PutTree( item->Whole( dir )->right, dir );

	return count;
}

void
MapItemArray::Dump( const char *name )
{
	for( int i = 0; i < Count(); i++ )
	    p4debug.printf( "%s %c%s <-> %s (slot %d)\n",
		name,
		" -+$@&    123456789"[Get( i )->mapFlag],
		Get( i )->Lhs()->Text(),
		Get( i )->Rhs()->Text(),
		Get( i )->slot );
}

/*
* MapItem::Dump() - dump tree, rooted at this
 */

void
MapItem::Dump( MapTableT d, const char *name, int l )
{
	static const char tabs[] = "\t\t\t\t\t\t\t\t";
	const char *indent = l > 8 ? tabs : tabs + 8 - l;

	if( !l )
	    p4debug.printf( "MapTree\n" );

	if( Whole( d )->left ) 
	    Whole( d )->left->Dump( d, "<<<", l+1 );

	p4debug.printf("%s%s %c%s <-> %s%s (maxslot %d (%d))\n", indent, name,
	    " -+$@&    123456789"[ mapFlag ], Ths(d)->Text(), Ohs(d)->Text(),
	    Whole( d )->hasands ? " (has &)" : "", Whole( d )->maxSlot, Whole( d )->maxSlotNoAnds);

	if( Whole( d )->center )
	    Whole( d )->center->Dump( d, "===", l+1 );

	if( Whole( d )->right )
	    Whole( d )->right->Dump( d, ">>>", l+1 );
}
