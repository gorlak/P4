/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsvfile.c - open & close the RCS ,v file and its temp successor
 *
 * External routines:
 *
 *	RcsVfile::RcsVfile() - open the RCS ,v file and its temp successor
 *	RcsVfile::~RcsVfile() - close the RCS ,v file and discard its temp 
 * 	RcsVfile::Commit() - replace the RCS ,v file with its successor
 *
 * Internal routines:
 *
 *	RcsVmkDir() - recursively make a directory
 *
 * History:
 *	2-18-97 (seiwald) - translated to C++.
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <error.h>
# include <debug.h>
# include <tunable.h>
# include <filesys.h>
# include <pathsys.h>
# include <readfile.h>

# include "rcsdebug.h"
# include "rcsvfile.h"
# include <msglbr.h>

/*
 * RcsVfile::RcsVfile() - open & close the RCS ,v file and its temp successor
 */

RcsVfile::RcsVfile(
	char *fileName, 
	int modes,
	int nocase,
	Error *e )
{
	// Binary because ReadFile takes care of input CRLF.
	// Raw Text because RcsGen takes care of output CRLF
	// (but we want buffering).

	readFd = 0;
	writeFile = 0;
	readCasefullPath = 0;
	originalFilename = NULL;
	this->modes = modes;

	/*
	 * ,v file
	 */

	StrBuf name;
	name << fileName << ",v";

	rcsFile = FileSys::Create( FST_BINARY );
	rcsFile->Set( name );

	if( nocase )
	{
	    if( modes & RCS_VFILE_DELETE )
		originalFilename = new StrBuf( name );
	    rcsFile->LowerCasePath();
	}

	/* 
	 * This is where we used to setup the ,x, RCS like
	 * temporary files.
	 */

	/*
	 * Open files as requested.
	 */

	if( modes & RCS_VFILE_WRITE )
	{
	    /*
	     * On write, create directory path.
	     */

	    rcsFile->MkDir( e );

	    if( e->Test() )
	    {
		e->Set( MsgLbr::MkDir ) << rcsFile->Name();
		return;
	    }

	    // Special RCS type does fsync() on close.

	    const int nofsync = p4tunable.Get( P4TUNE_RCS_NOFSYNC );

	    writeFile = FileSys::CreateTemp( nofsync ? FST_RTEXT : FST_RCS );
	    writeFile->MakeLocalTemp( rcsFile->Name() );

	    // Leave 666 our RCS files.

	    if( modes & RCS_VFILE_NOLOCK )
		writeFile->Perms( FPM_RW );

	    writeFile->Open( FOM_WRITE, e );

	    // Work around a potential race condition that could occure if the
	    // parent directory is removed between us checking and creating
	    // the temp file.

	    if( e->Test() && rcsFile->NeedMkDir() )
	    {
		e->Clear();

		rcsFile->MkDir( e );

		if( e->Test() )
		{
		    e->Set( MsgLbr::MkDir ) << rcsFile->Name();
		    return;
		}

		writeFile->Open( FOM_WRITE, e );
	    }

	    if( e->Test() )
	    {
		e->Set( MsgLbr::Lock ) << rcsFile->Name();
		return;
	    }
	}

	if( modes & RCS_VFILE_READ )
	{
	    // set cache hint
	    rcsFile->SetCacheHint();

	    readFd = new ReadFile;
	    readFd->Open( rcsFile, e );

	    if( e->Test() && nocase && ! ( rcsFile->Stat() & FSF_EXISTS ) )
	    {
		// caseless operation but file not found, try original
		rcsFile->Set( name );
		e->Clear();
		readFd->Open( rcsFile, e );
		rcsFile->LowerCasePath();
		if( !e->Test() )
		{
		    readCasefullPath = 1;
		    originalFilename = new StrBuf( name );
		}
	    }

	    if( e->Test() )
	    {
	        /* if Open() failed its only okay if its an update */
	        /* and the file does not exist, otherwise return error  */

	        if( !( modes & RCS_VFILE_WRITE ) ||
	             ( rcsFile->Stat() & FSF_EXISTS ) ) return;

		e->Clear();		
		delete readFd;
		readFd = 0;
	    }
	}

	if( DEBUG_VFILE )
	{
	    p4debug.printf( "rcsVfile (read) %s", rcsFile->Name() );
	    if( writeFile )
		p4debug.printf( " (write) %s", writeFile->Name() );
	    p4debug.printf( "\n" );
	}
}

/*
 * RcsVfile::~RcsVfile() - close the RCS ,v file and discard its temp 
 */

RcsVfile::~RcsVfile()
{
	delete readFd;
	delete writeFile;

	// writefile was a temp file, and it's gone now, which means we can
	// remove the archive (assuming it's empty). If the rcsFile doesn't
	// exist then we probably deleted the file: try a RmDir to clean up.

	if( ( modes & RCS_VFILE_WRITE ) && !( rcsFile->Stat() & FSF_EXISTS ) )
	    rcsFile->RmDir();

	delete rcsFile;
	delete originalFilename;
}

/*
 * RcsVfile::Commit() - replace the RCS ,v file with its successor
 */

void
RcsVfile::Commit(
	Error *e )
{
	/* Just in case: don't commit if not writing */

	if( DEBUG_VFILE )
	    p4debug.printf( "committing changes to %s\n", rcsFile->Name() );

	if( !( modes & RCS_VFILE_WRITE ) )
	    return;

	/* If writing, we'll try to flush it and check for errors */
	/* before comitting. */

	if( writeFile )
	{
	    writeFile->Close( e );

	    // Destructor will remove writefile.

	    if( e->Test() )
	    {
		e->Set( MsgLbr::Commit ) << rcsFile->Name();
		return;
	    }
	}

	/* Yeech - NT target must not exist in rename() */
	/* Yeech - NT must be writable to remove.  I hate VMS. */
	/* Yeech - NT target must be close to unlink */
	/* True for NT: OS/2 is not tested. */
	/* BEOS needs target file closed to unlink */

	if( readFd )
	    readFd->Close();

	/* If all revs deleted by RcsDelete, don't write new file. */

	if( modes & RCS_VFILE_DELETE )
	{
	    if( originalFilename && ! ( rcsFile->Stat() & FSF_EXISTS ) )
		rcsFile->Set( *originalFilename );

	    rcsFile->Unlink();
	    return;
	}

	/* Attemp to replace ReadFile with its temp successor. */

	writeFile->Rename( rcsFile, e );

	if( e->Test() )
	    e->Set( MsgLbr::Commit ) << rcsFile->Name();
	else if( readCasefullPath )
	{
	    // we wrote a new rcsfile, with a lower cased path, but we
	    // read a casefull file, this means we have an old case full
	    // file laying around...  Remove it...
	    rcsFile->Set( *originalFilename );
	    rcsFile->Unlink();
	}
}
