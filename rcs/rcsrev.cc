/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsrev.c - RCS revision number mangling
 *
 * Classes defined
 *
 *	RcsRevPlace - a little handle for finding revision insertion points
 *
 * Methods defined:
 *
 * 	RcsArchive::FollowRevision() - compute successor to current rev
 *
 * 	RcsRevPlace::Locate() - find insertion point for a new revision.
 *
 * External routines:
 *
 *	RcsRevCmp() - compare current rev number with desired one.
 *
 * History:
 *	2-18-97 (seiwald) - translated to C++.
 */

# define NEED_TYPES

# include <stdhdrs.h>

# include <error.h>
# include <debug.h>

# include "readfile.h"
# include "rcsdebug.h"
# include "rcsarch.h"
# include "rcsrev.h"
# include <msglbr.h>

static const char *const cmps[] = { 
	"EQUAL", "MISMATCH", "DOWN", "UP", "ATBRANCH", "NUMBRANCH", "OUT", "IN"
};

/*
 * RcsRevCmp() - compare two revs
 *
 * Compares an RCS revision number (c) to another "target" revision
 * number (t).  The comparison is based soley on the text of the two
 * numbers (i.e., does not depend on the topology of a particular RCS
 * revision tree instance). See the comments before the definition of
 * enum RevCmp in rcsrev.h for return values and examples.
 */

RevCmp
RcsRevCmp( 
	const char *t,
	const char *c )
{
	int levels = 0;
	int diff = 0;
	RevCmp r;

	if( DEBUG_REVNUM )
	    p4debug.printf("rev cmp %s %s: ", t, c );

	while( !diff && *t && *c )
	{
	    int t1 = 0, c1 = 0;

	    while( *t >= '0' && *t <= '9' )
		t1 = t1 * 10 + *t++ - '0';
	    if( *t == '.' ) ++t;

	cvshack:
	    while( *c >= '0' && *c <= '9' )
		c1 = c1 * 10 + *c++ - '0';
	    if( *c == '.' ) ++c;

	    /* Special RCS hack for x.y.0.z, use levels mod 2 to catch
	     * just the magic CVS 0 branch case. A 0 rev is OK, 3.0.
	     */

	    if( (!c1 && !(levels%2)) && *c >= '0' && *c <= '9' )
		goto cvshack;

	    diff = t1 - c1;
	    levels++;
	}

	r = REV_CMP_MISMATCH;

	if( !diff )
	{
	    if( !*t && !*c )
		r = REV_CMP_EQUAL;
	    else if( !*c )
		if ( levels % 2 )
		    r = REV_CMP_NUM_BRANCH;
		else
		    r = REV_CMP_AT_BRANCH;
	}
	else if( diff < 0 )
	{
	    if( levels <= 2 )
		r = REV_CMP_DOWN_TRUNK;
	    else if( !( levels % 2 ) )
		r = REV_CMP_IN_BRANCH;
	}
	else if( diff > 0 )
	{
	    if( levels <= 2 )
		r = REV_CMP_UP_TRUNK;
	    else if( !( levels % 2 ) )
		r = REV_CMP_OUT_BRANCH;
	}

	if( DEBUG_REVNUM )
	    p4debug.printf( "%s\n", cmps[r]);

	return r;
}


/*
 * RcsRevFollow() - compute successor to current rev
 *
 * This routine follows one step in the path from the current revision
 * number to the target revision number.  It calls RcsRevCmp() to tell it
 * whether to follow down the trunk or out the branch (both using the
 * 'next' pointer), or to follow a new branch.  In the latter case, it
 * searches the current rev's branch list for the proper branch point.
 *
 * Maybe a few examples will help:
 *
 *	current 1.3 target 1.1 -> next
 *	current 1.3 target 1.2.2.3 -> next 
 *	current 1.3.3.1 target 1.3.3.3 -> next
 *
 *	current 1.2 target 1.2.2.3 -> 1.2.2.1
 *	current 1.3.3.1 target 1.3.3.1.4.3 -> 1.3.3.1.4.1
 */

RcsRev *
RcsArchive::FollowRevision( 
	RcsRev *currentRev, 
	const char *targetRev,
	Error *e )
{
	RcsList *branch;
	RcsRev *nextRev = 0;

	switch( RcsRevCmp( targetRev, currentRev->revName.text ) )
	{
	case REV_CMP_EQUAL:
	    return currentRev;

	case REV_CMP_MISMATCH:
	case REV_CMP_IN_BRANCH:
	case REV_CMP_UP_TRUNK:
	    e->Set( MsgLbr::NoRev ) << targetRev;
	    return 0;

	case REV_CMP_DOWN_TRUNK:
	case REV_CMP_OUT_BRANCH:
	    nextRev = NextRevision( currentRev, e );

	    if( !nextRev )
		return 0;

	    break;

	case REV_CMP_NUM_BRANCH:
	case REV_CMP_AT_BRANCH:
	    for( branch = currentRev->branches; branch; branch = branch->qNext )
	        switch( RcsRevCmp( targetRev, branch->revision.text ) )
	    {
	    case REV_CMP_EQUAL:
	    case REV_CMP_NUM_BRANCH:
	    case REV_CMP_AT_BRANCH:
	    case REV_CMP_OUT_BRANCH:
		nextRev = FindRevision( branch->revision.text, e );
		break;

	    case REV_CMP_MISMATCH:
	    case REV_CMP_UP_TRUNK:
	    case REV_CMP_IN_BRANCH:
	    case REV_CMP_DOWN_TRUNK:	/* I hope not... */
		continue;
	    }

	    if( !nextRev )
	    {
		e->Set( MsgLbr::NoBranch ) << targetRev;
		return 0;
	    }
	    break;
	}

	/* A sanity check for loops */

	switch( RcsRevCmp( nextRev->revName.text, currentRev->revName.text ) )
	{
	case REV_CMP_EQUAL:
	case REV_CMP_MISMATCH:
	case REV_CMP_IN_BRANCH:
	case REV_CMP_UP_TRUNK:
	    e->Set( MsgLbr::Loop ) << nextRev->revName.text;
	    return 0;

	default:
	    return nextRev;
	}
}

/*
 * RcsRevPlace::Locate() - find insertion point for a new revision.
 *
 * Returns (possibly) three points: to the previous rev, the current rev,
 * and the next rev, in terms of RCS lineage as computed by RcsRevCmp().
 * Returns a flag indicating whether the new revision will be on the
 * trunk or the branch, so that checkin knows which way to compute the
 * diffs.
 *
 * Any of prevRev, currRev, and nextRev may be null.  A null prevRev means 
 * currRev will be the head; a null currRev means it will be new; a null 
 * nextRev means the new rev will be at the tip of a branch (or the base of 
 * the trunk).
 */

int
RcsRevPlace::Locate(
	RcsArchive	*archive,
	const char 	*targetRev,
	Error	*e ) 
{
	RcsList *branch;
	RcsRev *rev = 0;

	/* Clear prevRev, nextRev */

	place = RCS_REV_PLACE_TRUNK;
	prevRev = currRev = nextRev = 0;
	thisPtr = &archive->headRev;

	/* start at head revision. */

	if( archive->headRev.text )
	    rev = archive->FindRevision( archive->headRev.text, e );

	if( !rev )
	    return 1;

	/* Follow down the trunk */

	for(;;)
	    switch( RcsRevCmp( targetRev, rev->revName.text ) )
	{
	case REV_CMP_EQUAL:
	    currRev = rev;

	    if( !rev->next.text )
		return 1;

	    if( !( rev = archive->NextRevision( rev, e ) ) )
		return 0;

	    /* fall through */

	case REV_CMP_IN_BRANCH:
	case REV_CMP_UP_TRUNK:
	    nextRev = rev;
	    return 1;

	case REV_CMP_MISMATCH:
	    return 0;

	case REV_CMP_OUT_BRANCH:
	case REV_CMP_DOWN_TRUNK:
	    prevRev = rev;

	    if( !rev->next.text )
		return 1;

	    thisPtr = &rev->next;

	    if( !( rev = archive->NextRevision( rev, e ) ) )
		return 0;
	    
	    continue;

	case REV_CMP_NUM_BRANCH:
	case REV_CMP_AT_BRANCH:
	    prevRev = rev;
	    place = RCS_REV_PLACE_BRANCH;

	    for( branch = rev->branches; branch; branch = branch->qNext )
	        switch( RcsRevCmp( targetRev, branch->revision.text ) )
	    {
	    case REV_CMP_EQUAL:
	    case REV_CMP_NUM_BRANCH:
	    case REV_CMP_AT_BRANCH:
	    case REV_CMP_OUT_BRANCH:
		thisPtr = &branch->revision;

		rev = archive->FindRevision( branch->revision.text, e );

		if( !rev )
		    return 0;

		goto next;

	    case REV_CMP_MISMATCH:
	    case REV_CMP_UP_TRUNK:
	    case REV_CMP_IN_BRANCH:
	    case REV_CMP_DOWN_TRUNK:	/* I hope not... */
		continue;
	    }

	    e->Set( MsgLbr::NoBrRev ) << targetRev;
	    return 0;

	next:;
	}
}

void
RcsRevTest( 
	RcsArchive	*archive,
	const char 	*targetRev,
	Error		*e )
{
	RcsRevPlace	p[1];
	int n;

	n = p->Locate( archive, targetRev, e );

	if( !n )
	    return;

	p4debug.printf( "%s : from %s to %s to %s\n",
		targetRev,
		p->prevRev ? p->prevRev->revName.text : "head",
		p->currRev ? p->currRev->revName.text : "new",
		p->nextRev ? p->nextRev->revName.text : "tail" );
}

