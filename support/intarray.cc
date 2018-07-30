/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

// Remove these next two:
# include <debug.h>
# include <strbuf.h>

# include "intarray.h"

// If you know that this IntArray's values are in sorted order, and you want to
// find the slot number of a particular value, this routine binary-searches
// the array for you. Make sure you call SetCount() first to establish the
// limits of the search.
//
// It returns -1 if the value isn't present in this array.
//
// For example, if your array contains: 1,3,5,6,7,8,9,10, then
//  Find(0) => -1, Find(1) => 0, Find(2) => -1, Find(5)=> 2, Find(8) => 5
//
// If you think you need to modify this routine, read DbArray::Search first.
int
IntArray::Find( int v )
{
	int lo = 0;
	int hi = count;

	for(;;)
	{
	    int index = ( lo + hi ) / 2;

	    if( lo == hi )
		return index < count && ints[ index ] == v ? index : -1;

	    if( v <= ints[ index ] )
		hi = index;
	    else if( index != lo )
		lo = index;
	    else
		lo = hi;
	}
}
