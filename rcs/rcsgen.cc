/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsgen.c - write a new RCS file, given an RcsArchive structure
 *
 * Classes defines:
 *
 *	RcsGenFile - control block for generating a new RCS file
 *
 * Public methods:
 *
 *	RcsGenFile::Generate() - write out an RcsArchive to a stdio file
 *
 * History:
 *	5-13-95 (seiwald) - added lost support for 'branch rev' in ,v header.
 *	12-17-95 (seiwald) - added support for 'expand flag' in ,v header.
 *	2-18-97 (seiwald) - translated to C++.
 */

# define NEED_TYPES

# include <stdhdrs.h>

# include <error.h>
# include <strbuf.h>
# include <filesys.h>

# include "readfile.h"
# include "rcsarch.h"
# include "rcsgen.h"

void
RcsGenFile::GenList( 
	RcsList *strings,
	int dostring,
	int dorev )
{
	int cnt = 0;

	for( ; strings; strings = strings->qNext )
	{
	    if( cnt++ )
		GenLit( " " );

	    if( dostring )
		GenTxt( &strings->string );

	    if( dostring && dorev )
		GenLit( ":" );

	    if( dorev )
		GenTxt( &strings->revision );
	}
}

void
RcsGenFile::GenString(
	const char *string )
{
	int len = strlen( string );

	GenAt();

	while( len )
	{
	    char *e;
	    int l = buf.Length();

	    if( l > len )
		l = len;

	    if( e = (char *)memccpy( buf.Text(), string, '@', l ) )
		l = e - buf.Text();

	    GenBuf( buf.Text(), l );

	    /* If we stopped at a single @, double it */

	    if( l && buf[ l - 1 ] == '@' )
		GenAt();

	    len -= l;
	    string += l;
	}

	GenAt();
	GenSpace();
}

void
RcsGenFile::GenChunk( 
	RcsChunk *chunk,
	int fastformat )
{
	RcsSize len = chunk->length;

	if( !chunk->file )
	{
	    GenAt();
	    GenAt();
	    return;
	}

	if( fastformat )
	{
	    sprintf( buf.Text(), "%%%lld\n", len );
	    GenBuf( buf.Text(), strlen( buf.Text() ) );
	}
	else 
	{
	    GenAt();
	}

	chunk->file->Seek( chunk->offset );

	/* If single @'s are present, we'll need to quote them. */
	/* RCS files have @'s doubled to quote them. */

	if( chunk->atWork == RCS_CHUNK_ATSINGLE )
	{
	    while( len )
	    {
		int l = buf.Length();

		if( l > len )
		    l = len;

		l = chunk->file->Memccpy( buf.Text(), '@', l );

		GenBuf( buf.Text(), l );

		/* If we stopped at a single @, double it */

		if( l && buf[ l - 1 ] == '@' )
		    GenAt();

		len -= l;
	    }
	}
	else
	{
	    while( len )
	    {
		int l = buf.Length();

		if( l > len )
		    l = len;

		l = chunk->file->Memcpy( buf.Text(), l );

		GenBuf( buf.Text(), l );

		len -= l;
	    }
	}
	 
	if( !fastformat )
	    GenAt();
}

void 
RcsGenFile::Generate( 
	FileSys *wf, 
	RcsArchive *ar,
	Error *e,
	int fastformat )
{
	RcsRev *rev;

	this->wf = wf;
	this->e = e;

	/*
	 * From the header
	 */

	GenLit( "head     " );
	if( ar->headRev.text )
	    GenTxt( &ar->headRev );
	GenSemi();
	GenNL();

	if( ar->branchRev.text )
	{
	    GenLit( "branch   " );
	    GenTxt( &ar->branchRev );
	    GenSemi();
	    GenNL();
	}

	GenLit( "access   " );
	GenList( ar->accessList, 1, 0 );
	GenSemi();
	GenNL();

	GenLit( "symbols  " );
	GenList( ar->symbolList, 1, 1 );
	GenSemi();
	GenNL();

	GenLit( "locks    " );
	GenList( ar->lockList, 1, 1 );
	GenSemi();

	if( ar->strict )
	{
	    GenLit( " strict" );
	    GenSemi();
	    GenNL();
	}

	GenLit( "comment  " );
	GenChunk( &ar->comment, fastformat );
	GenSemi();
	GenNL();

	if( ar->expand.file )
	{
	    GenLit( "expand   " );
	    GenChunk( &ar->expand, fastformat );
	    GenSemi();
	    GenNL();
	}

	GenNL();

	/*
	 * The revision logs
	 */

	for( rev = ar->revHead; rev; rev = rev->qNext )
	    if( !rev->deleted )
	{
	    GenNL();
	    GenTxt( &rev->revName );
	    GenNL();

	    GenLit( "date     " );
	    GenTxt( &rev->date );
	    GenSemi();

	    GenLit( "  author " );
	    GenTxt( &rev->author );
	    GenSemi();

	    GenLit( "  state " );
	    GenTxt( &rev->state );
	    GenSemi();
	    GenNL();

	    GenLit( "branches " );
	    GenList( rev->branches, 0, 1 );
	    GenSemi();
	    GenNL();

	    GenLit( "next     " );
	    if( rev->next.text )
		GenTxt( &rev->next );
	    GenSemi();
	    GenNL();
	}

	/*
	 * The midpoint
	 */

	GenNL();
	GenNL();
	GenLit( "desc" );
	GenNL();
	GenChunk( &ar->desc, fastformat );
	GenNL();

	/*
	 * The revision text
	 */

	for( rev = ar->revHead; rev; rev = rev->qNext )
	    if( !rev->deleted )
	{
	    GenNL();
	    GenNL();
	    GenTxt( &rev->revName );
	    GenNL();
	    GenLit( "log" );
	    GenNL();
	    GenChunk( &rev->log, fastformat );
	    GenNL();
	    GenLit( "text" );
	    GenNL();
	    GenChunk( &rev->text, fastformat );
	    GenNL();
	}

	/* What a nightmare */
}
