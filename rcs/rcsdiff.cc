/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsdiff.c - diff a file against a revision in an RcsArchive
 *
 * External routines:
 *
 *	RcsDiff() - make a diff file between a file and generated rev
 *
 * History:
 *	2-18-97 (seiwald) - translated to C++.
 */

# define NEED_TYPES
# define NEED_FILE

# include <stdhdrs.h>
# include <error.h>
# include <debug.h>
# include <strbuf.h>
# include <filesys.h>

# include <diff.h>

# include "readfile.h"
# include "rcsdebug.h"
# include "rcsarch.h"
# include "rcsco.h"
# include "rcsdiff.h"
# include <msglbr.h>

/*
 * RcsDiff() - make a diff file between a file and generated rev
 *
 * Forks off a diff between stdin and the named file.  Pipes to the 
 * diff the name revision of the file in the archive, using CkoutRead() 
 * to generate that revision on the fly.  Leave the result in a
 * file whose name outFile.
 */

void
RcsDiff(
	RcsArchive *archive,
	const char *revName,
	FileSys *fileName,
	const char *outFile,
	int diffType,
	Error *e )
{
	int l;
	RcsCkout *co = 0;
	StrFixed buf( FileSys::BufferSize() );

	/* Check out previous revision into the stream 'co' */

	FileSys *coTmp = FileSys::CreateGlobalTemp( FST_TEXT );

	coTmp->Open( FOM_WRITE, e );

	if( e->Test() )
	{
	    e->Set( MsgLbr::Diff ) << fileName->Name();
	    delete coTmp;
	    return;
	}

	co = new RcsCkout( archive );
	co->Ckout( revName, e );

	/* Write the revision down to diff. */

	while( !e->Test() && ( l = co->Read( buf.Text(), buf.Length() ) ) )
	    coTmp->Write( buf.Text(), l, e );

	/* Polish things off. */

	delete co;
	coTmp->Close( e );

	if( e->Test() )
	{
	    e->Set( MsgLbr::Diff ) << fileName->Name();
	    delete coTmp;
	    return;
	}

	/* Start the diff command */

	Diff *diff = new Diff;

	/* We want this diff to be done asap */

	diff->DiffFast();

	/* Need to pass diff a BINARY FileSys for the archived */
	/* revision, otherwise the compare will bloat */

	FileSys *coTmpBinary = FileSys::Create( FST_BINARY );
	coTmpBinary->Set( coTmp->Name() );
	DiffFlags flags;

	if( diffType & RCS_DIFF_REVERSE )
	    diff->SetInput( fileName, coTmpBinary, flags, e );
	else
	    diff->SetInput( coTmpBinary, fileName, flags, e );

	if( !e->Test() )
	    diff->SetOutput( outFile, e );

	if( e->Test() )
	    /* don't do a thing */;
	else if( diffType & RCS_DIFF_USER )
	    diff->DiffNorm();
	else
	    diff->DiffRcs();

	archive->SetChunkCnt( diff->GetChunkCnt() );

	diff->CloseOutput( e );

	delete diff;
	delete coTmpBinary;
	delete coTmp;

	if( e->Test() )
	    e->Set( MsgLbr::Diff ) << fileName->Name();
}
