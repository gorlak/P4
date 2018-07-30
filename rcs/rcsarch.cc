/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsarch.cc - RCS in-memory structure creation
 *
 * Classes defined:
 *
 *	RcsArchive - parsed, in memory copy of RCS file
 *	RcsList - string lists for locks, symbols, access, branches
 *	RcsRev - all information about a revision
 *	RcsChunk - a pointer/length back into the RCS file for @ text
 *	RcsText - an allocated string with its strlen().
 *
 * Public methods:
 *
 *	RcsArchive::RcsArchive() - initialize RcsArchive
 *	RcsArchive::~RcsArchive() - free everything allocated to RcsArchive
 *	RcsArchive::AddRevision() - chain a revision onto the archive's list
 *	RcsArchive::FindRevision() - find a revision on the chain
 *	RcsArchive::NextRevision() - conveniently follow the rev's next pointer
 *
 *	RcsList::RcsList() - append new list member onto chain
 *
 * 	RcsText::Save() - copy text into a new buffer
 *
 *	RcsChunk::Save() - save offset/length pointers of @ block
 *
 * Internal routines:
 *
 *	RcsListFree() - free RcsList chain
 *
 * History:
 *	6-10-95 (seiwald) - added lost support for 'branch rev' in ,v header.
 *	12-17-95 (seiwald) - added support for 'expand flag' in ,v header.
 *	2-18-97 (seiwald) - translated to C++.
 */

# define NEED_TYPES

# include <stdhdrs.h>

# include <error.h>
# include <debug.h>
# include <strbuf.h>
# include <readfile.h>

# include "rcsdebug.h"
# include "rcsarch.h"
# include <msglbr.h>

void
RcsText::Save( 
	const char *ntext,
	int nlen,
	const char *trace )
{
	if( text )
	    delete [] text;

	len = nlen;
	text = new char[ nlen + 1 ];

	memcpy( text, ntext, nlen );

	text[ len ] = 0;

	if( DEBUG_CORE )
	    p4debug.printf( ": %s: %s\n", trace, text );
}

void
RcsChunk::Save(
	RcsChunk *src,
	const char *trace )
{
	*this = *src;

	if( DEBUG_CORE )
	    p4debug.printf( ": %s: %lld bytes\n", trace, src->length );
}

void
RcsChunk::Save(
	FileSys *f,
	Error *e )
{
	file = new ReadFile;

	file->Open( f, e );

	if( e->Test() )
	    return;

	offset = 0;
	length = file->Size();
	atWork = RCS_CHUNK_ATSINGLE;
}

RcsList::RcsList( RcsList **headPtr )
{
	if( !*headPtr ) *headPtr = this;
	else (*headPtr)->qTail->qNext = this;
	(*headPtr)->qTail = this;
	this->qNext = 0;
}

static void
RcsListFree( RcsList *list )
{
	while( list )
	{
	    RcsList *l = list;
	    list = list->qNext;
	    delete l;
	}
}

RcsRev *
RcsArchive::AddRevision(
	const char	*revName,
	int		append,
	RcsRev		*prevRev,
	Error		*e )
{
	int revHash = 0;
	const char *r = revName;
	RcsRev *rev = new RcsRev;

	rev->deleted = 0;
	rev->branches = 0;
	rev->revName.Save( revName, strlen( revName ), "revname" );

	while( *r )
	    revHash = ( revHash << 4 ) ^ (*r++) ;

	rev->revHash = revHash;

	if( append )
	    prevRev = revTail;

	if( prevRev )
	{
	    rev->qNext = prevRev->qNext;
	    prevRev->qNext = rev;
	}
	else
	{
	    rev->qNext = revHead;
	    revHead = rev;
	}

	if( prevRev == revTail )
	    revTail = rev;

	return rev;
}

RcsRev *
RcsArchive::FindRevision(
	const char 	*revName,
	Error 		*e ) 
{
	RcsRev *r;
	const char *rs = revName;
	int revHash = 0;

	while( *rs )
	    revHash = ( revHash << 4 ) ^ (*rs++) ;

	/* We make a first pass starting at the lastFoundRev, figuring */
	/* that in-order scans are the most common (and should go fast). */

	for( r = lastFoundRev; r; r = (RcsRev *)r->qNext )
	{
	    if( r->revHash == revHash && !strcmp( r->revName.text, revName ) )
		return lastFoundRev = r;
	}

	for( r = revHead; r; r = (RcsRev *)r->qNext )
	{
	    if( r->revHash == revHash && !strcmp( r->revName.text, revName ) )
		return lastFoundRev = r;
	}

	e->Set( MsgLbr::NoRev ) << revName;

	return 0;
}

RcsRev *
RcsArchive::NextRevision(
	RcsRev	*rev,
	Error		*e ) 
{
	char *nextRev = rev->next.text;

	if( !nextRev )
	{
	    e->Set( MsgLbr::After ) << rev->revName.text;
	    return 0;
	}

	if( !( rev = FindRevision( nextRev, e ) ) )
	{

	    e->Set( MsgLbr::NoRev3 ) << nextRev;
	    return 0;
	}

	return rev;
}

RcsArchive::RcsArchive()
{
	/* Zero things that might not get set */

	accessList = 0;
	symbolList = 0;
	lockList = 0;
	strict = 0;
	revHead = 0;
	revTail = 0;
	lastFoundRev = 0;
	chunkCnt = 0;
}

RcsArchive::~RcsArchive()
{
	RcsRev *revs;

	RcsListFree( accessList );
	RcsListFree( symbolList );
	RcsListFree( lockList );

	/*
	 * The revision logs & text
	 */

	for( revs = revHead; revs; )
	{
	    RcsRev *rev = revs;
	    revs = revs->qNext;

	    RcsListFree( rev->branches );

	    delete rev;
	}
}

