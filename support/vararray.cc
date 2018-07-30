/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include <debug.h>

# include "vararray.h"

# define DEBUG_RECORDS	( p4debug.GetLevel( DT_RECORDS ) >= 4 )
# define DEBUG_EXTEND	( p4debug.GetLevel( DT_RECORDS ) >= 5 )

VarArray::VarArray()
{
	this->maxElems = 0;
	this->numElems = 0;
	this->elems = 0;
}

VarArray::VarArray( int max )
{
	this->maxElems = max;
	this->numElems = 0;
	this->elems = new void *[max];
}

VarArray::~VarArray()
{
	if( DEBUG_RECORDS )
	    p4debug.printf("~VarArray %d/%d\n", numElems, maxElems );

	if( elems )
	    delete []elems;
}

void **
VarArray::New()
{
	// realloc

	if( numElems >= maxElems )
	{
	    // grow geometrically, please
	    int newMax = ( maxElems + 50 ) * 3 / 2;

	    void **newElems = new void *[newMax];

	    if( elems )
	    {
		memcpy( (void *)newElems, (void *)elems, 
			maxElems * sizeof( void * ) );
		delete []elems;
	    }

	    elems = newElems;
	    maxElems = newMax;

	    if( DEBUG_EXTEND )
		p4debug.printf("VarArray extend %d\n", maxElems );
	}

	return &elems[ numElems++ ];
}

void
VarArray::Remove( int i )
{
	if( 0 <= i && i < numElems )
	{
	    for( int j = i + 1; j < numElems; j++ )
	        elems[j-1] = elems[j];
	    numElems--;
	}
}

int
VarArray::WillGrow( int interval )
{
	if( interval > maxElems )
	    return( (interval + 50) * 3 / 2 );

	if( ( numElems + interval ) > maxElems )
	    return( (maxElems + 50) * 3 / 2 );

	return( 0 );
}

void *
VarArray::Replace( int i, void *newValue )
{
	void *old = 0;
	if ( i >= 0 && i < numElems )
	{
	    old = elems[i];
	    elems[i] = newValue;
	}
	return old;
}


/*
 * VVarArray::Diff()
 * VVarArray::Intersect()
 * VVarArray::Merge()
 *
 * Set operations on arrays.
 *
 * End results:
 *
 *		this			that			discarded
 *   ---------------------------------------------------------------------
 *   Diff	rows only in this	rows only in that	rows in both
 *   Intersect	rows in both 		rows only in that	rows not in both
 *   Merge	rows in either 		none			duplicates
 *
 * Intersect() leaves this VVarArray with the intersection, but also
 * leaves 'other' with its excesses (those not found in this).  This
 * done entirely for the convenience of one caller -- ChangeMgr.
 */

enum VVarSetAct {

	Stay,
	Free,
	PutOut,
	Put3rd

} VVarSetActs[3][3][2] = {

/*		on this     	on that    	on both */
/*              for this,that   for that,that   for this,that */
/*              --------------------------------------------- */
/* Diff */  	PutOut, Stay,  	Stay, PutOut,  	Free, Free,
/* Int */   	Free, Stay,     Stay, PutOut, 	PutOut, Free,
/* Merge */ 	Put3rd, Stay,   Stay, Put3rd, 	Free, Put3rd,

} ;

void
VVarArray::Diff( Op op, VarArray &that )
{
	// i1 this
	// i2 that
	// o1 packed out this
	// o2 packet out that

	int i1 = 0, i2 = 0, o1 = 0, o2 = 0;

	// third temp VarArray for merge

	VarArray *third = 0;

	if( op == OpMerge )
	    third = new VarArray( Count() + that.Count() );

	// Compare arrays

	while( i1 < Count() || i2 < that.Count() )
	{
	    // Compare elements, handling eof

	    int l;

	    if( i1 >= Count() ) l = 1;
	    else if( i2 >= that.Count() ) l = -1;
	    else l = Compare( Get( i1 ), that.Get( i2 ) );

	    // Lookup action [op][ on this=0/that=1/both=2 ]

	    VVarSetAct *a = VVarSetActs[ op ][ l < 0 ? 0 : l > 0 ? 1 : 2 ];

	    // What to do with this?

	    switch( a[0] )
	    {
	    case Free:		Destroy( Get( i1++ ) ); break;
	    case PutOut:	Move( i1++, o1++ ); break;
	    case Put3rd: 	third->Put( Get( i1++ ) ); break;
	    }

	    // What to do with that?

	    switch( a[1] )
	    {
	    case Free:		Destroy( that.Get( i2++ ) ); break;
	    case PutOut:	that.Move( i2++, o2++ ); break;
	    case Put3rd: 	third->Put( that.Get( i2++ ) ); break;
	    }
	}

	// Replace this array with the merged third array.
	// This array (as well as that) are now empty (o1=o2=0).

	if( op == OpMerge )
	{
	    delete []elems;
	    elems = third->elems;
	    third->elems = 0;
	    o1 = third->Count();
	    delete third;
	}

	SetCount( o1 );
	that.SetCount( o2 );
}

void
VVarArray::Uniq()
{
	int i, j;

	for( j = 0, i = 0; i < Count(); i++ )
	{
	    if( j && !Compare( Get( i ), Get( j-1 ) ) )
		continue;
	    Move( i, j++ );
	}

	SetCount( j );
}
