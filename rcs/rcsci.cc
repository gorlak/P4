/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsci.c - update RcsArchive with a new revision
 *
 * Classes defined:
 *
 *	RcsCkin - control block for checkin operation
 *
 * Public methods:
 *
 *	RcsCkin::RcsCkin() - create/repalce a head/post-head revision
 *	RcsCkin::~RcsCkin() - free up resources created by RcsCkin()
 *
 * Internal routines:
 *
 *	ReadFileChunk() - open a file and point a chunk at it
 *
 * History:
 *	2-18-97 (seiwald) - translated to C++.
 */

# define NEED_FILE
# define NEED_TYPES

# include <stdhdrs.h>

# include <error.h>
# include <debug.h>
# include <strbuf.h>
# include <readfile.h>
# include <filesys.h>

# include "rcsdebug.h"
# include "rcsarch.h"
# include "rcsci.h"
# include "rcsdiff.h"
# include "rcsdate.h"
# include "rcsrev.h"
# include <msglbr.h>

/*
 * RcsCkinChunk -- a rev chunk, either diff or whole
 */

RcsCkinChunk::RcsCkinChunk()
{
	diffFile = 0;
	diffFileBinary = 0;
}

/*
 * RcsCkinChunk::~RcsCkinChunk() - free up resources 
 *
 * This should only be done after the RcsArchive has been written
 * with RcsGenerate, as the RcsArchive now has chunks pointing to
 * files opened by RcsCkin().
 */

RcsCkinChunk::~RcsCkinChunk()
{
	delete file;
	delete diffFile;
	delete diffFileBinary;
}

/*
 * RcsCkinChunk::Diff() - produce a diff chunk between newFile and revName
 */

void
RcsCkinChunk::Diff( 
	RcsArchive *archive,
	const char *revName,
	FileSys *newFile,
	int flags,
	Error *e )
{
	/* Create temp file name */

	diffFile = FileSys::CreateGlobalTemp( FST_TEXT );

	/* Pipe previous revision through diff and into temp file */

	RcsDiff( archive, revName, newFile, diffFile->Name(), 
		flags|RCS_DIFF_RCSN, e );

	if( e->Test() )
	    return;

	/* Make currRev now a diff chunk */
	/* First we need to create a new FileSys, so when */
	/* we read the file we read it binary. */

	diffFileBinary = FileSys::Create( FST_BINARY );
	diffFileBinary->Set( diffFile->Name() );

	Save( diffFileBinary, e );

	if( e->Test() )
	    return;

	if( !file->Size() && archive->GetChunkCnt() != 0 )
	    e->Set( MsgLbr::Mangled ) << "empty";

	/* Make sure it looks like diff output, and not */
	/* "binary files differ" */

	if( !file->Eof() && 
	     file->Char() != 'a' && 
	     file->Char() != 'd' )
	{
	    char buf[ 128 ];

	    int l = file->Memccpy( buf, '\n', sizeof( buf )-1 );
	    
	    if( l && buf[ l - 1 ] == '\n' ) --l;
	    buf[ l ] = 0;
	    e->Set( MsgLbr::Mangled ) << buf;
	}

	return;
}

/*
 * RcsCkin::RcsCkin() - create a post-head revision/replace the head revision
 *
 * Takes a file containing the new text and the new revision's name
 * and doctors the RcsArchive structure to make that revision the
 * new head.  This currently supports replacing the head, but doesn't
 * allow checkins on branches and it doesn't validate the revision number.
 */

RcsCkin::RcsCkin(
	RcsArchive *archive,
	FileSys *newFile,
	const char *newRev,
	RcsChunk *log,
	const char *author,
	const char *state,
	time_t modTime,
	Error *e )
{
	RcsDate date;
	RcsRevPlace place;

	/*
	 * Use RcsRevPlace to figure out this rev's relationship to 
	 * existing revs.  The 'place' flag says whether its on the trunk
	 * or on a branch.  The three fields prevRev, currRev, and nextRev 
	 * point to the previous, current, and following revisions in terms 
	 * of RCS lineage.  
	 */

	if( !place.Locate( archive, newRev, e ) )
	    goto fail;

	if( DEBUG_CKIN )
	    p4debug.printf( "checkin new %s following %s\n",
		place.currRev ? place.currRev->revName.text : "none",
		place.nextRev ? place.nextRev->revName.text : "none" );

	/*
	 * If there is no current rev entry, create one.
	 */

	if( !place.currRev )
	    place.currRev = archive->AddRevision( newRev, 0, place.prevRev, e );

	if( e->Test() )
	    goto fail;

	/* 
	 * Fill in the new rev with the new stuff: point its chunk
	 * at the new file.
	 */

	if( !*author || !*state )
	{
	    e->Set( MsgLbr::Empty );
	    goto fail;
	}

	if( modTime )
	    date.Set( modTime );
	else
	    date.Now();
	place.currRev->date.Save( date.Text(), "date" );
	place.currRev->author.Save( author, "author" );
	place.currRev->state.Save( state, "state" );
	place.currRev->log = *log;

	/*
	 * Create chunk for nextRev.
	 *
	 * It will be the diff between the newFile and the nextRev.
	 */

	if( place.nextRev )
	{
	    nextChunk.Diff( archive, place.nextRev->revName.text, 
		    newFile, RCS_DIFF_REVERSE, e );
	    place.nextRev->text = nextChunk;
	}

	/* 
	 * Create chunk for current rev.
	 *
	 * If it is a new head, its contents will be the whole file.
	 * If it follows an existing rev, its contents will be a diff.
	 */

	if( !place.prevRev )
	{
	    currChunk.Save( newFile, e );
	    place.currRev->text = currChunk;
	}
	else
	{
	    currChunk.Diff( archive, place.prevRev->revName.text, 
			newFile, RCS_DIFF_NORMAL, e );
	    place.currRev->text = currChunk;
	}


	if( e->Test() )
	    goto fail;

	/* 
	 * Touch up the head/next pointers along the way.
	 */

	if( place.prevRev )
	{
	    place.prevRev->next.Save( place.currRev->revName, "next" );
	}
	else
	{
	    archive->headRev.Save( place.currRev->revName, "head" );
	}

	if( place.nextRev )
	{
	    place.currRev->next.Save( place.nextRev->revName, "next" );
	}

fail:
	if( e->Test() )
	    e->Set( MsgLbr::Checkin ) << newFile->Name() << newRev;
}

