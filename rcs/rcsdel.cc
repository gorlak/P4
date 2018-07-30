/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsdel.cc - delete revision in RcsArchive
 */

# define NEED_FILE
# define NEED_TYPES

# include <stdhdrs.h>

# include <error.h>
# include <debug.h>
# include <strbuf.h>
# include <readfile.h>

# include "rcsdebug.h"
# include "rcsarch.h"
# include "rcsdel.h"
# include "rcsdate.h"
# include "rcsrev.h"
# include <msglbr.h>

/*
 * RcsDelete() - delete revision in RcsArchive
 */

int
RcsDelete(
	RcsArchive *archive,
	const char *oldRev,
	Error *e )
{
	RcsRevPlace place;
	RcsRev *rev;

	/* 
	 * Find oldRev's currRev, prevRev, and nextRev 
	 * Mark currRev's state "deleted" in the generated file.
	 */

	if( !place.Locate( archive, oldRev, e ) )
	    return 0;

	if( !place.currRev )
	{
	    e->Set( MsgLbr::NoRevDel ) << oldRev;
	    return 0;
	}

	place.currRev->state.Save( "deleted", "state" );

	/* 
	 * Follow out the 'next' chain and see if there are any branches
	 * or undeleted revs.  If so, we won't actually drop the rev from
	 * the file.
	 */

	rev = place.nextRev;

	while( rev )
	{
	    if( strcmp( rev->state.text, "deleted" ) || rev->branches )
		break;

	    rev = rev->next.text ? archive->NextRevision( rev, e ) : 0;
	}

	if( e->Test() || rev )
	    return 0;

	/* 
	 * All revs after currRev have been marked as deleted, so we
	 * now mark the in-memory rev as deleted to prevent RcsGenerate
	 * from writing them to the file.
	 */

	rev = place.currRev;

	while( rev )
	{
	    ++rev->deleted;
	    rev = rev->next.text ? archive->NextRevision( rev, e ) : 0;
	}

	/* 
	 * Touch up the prevRev's next or headRev to indicate this
	 * rev is a gonner.  A missing headRev tells RcsGenerate delete
	 * the Rcs file.
	 */

	/* Return 1 if file is to be deleted. */

	if( place.thisPtr )
	{
	    int allDeleted = ( place.thisPtr == &archive->headRev ) ? 1 : 0;

	    if( !allDeleted )
	    {
	        rev = archive->FindRevision( archive->headRev.text, e );

	        while( rev && !allDeleted )
	        {
	            if( !strcmp( rev->revName.text, oldRev ) )
	                allDeleted = 1;

	            if( strcmp( rev->state.text, "deleted" ) || rev->branches ) 
	                break;

	            rev = rev->next.text ? archive->NextRevision( rev, e ) : 0;
	        }
	    }

	    place.thisPtr->Clear();
	    return allDeleted;
	}

	return 0;
}

