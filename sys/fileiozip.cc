/*
 * Copyright 1995, 2003 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * fileiozip.cc - FileIOGzip/FileIOGunzip methods
 */

# include <stdhdrs.h>

# include <error.h>
# include <strbuf.h>
# include <gzip.h>

# include "filesys.h"
# include "fileio.h"

FileIOCompress::~FileIOCompress()
{
	Cleanup();
	delete gzip;
	delete gzbuf;
}

void
FileIOCompress::Open( FileOpenMode mode, Error *e )
{
	switch ( GetType() & FST_C_MASK )
	{
	case FST_C_GZIP:
	    compMode = FIOC_GZIP;
	    break;
	case FST_C_GUNZIP:
	    compMode = FIOC_GUNZIP;
	    break;
	default:
	    compMode = FIOC_PASS;
	}

	if( compMode != FIOC_PASS )
	{
	    gzip = new Gzip;
	    gzbuf = new StrFixed( BufferSize() );

	    // Read expects is/ie; write os/oe.

	    gzip->is = gzbuf->Text();
	    gzip->ie = gzbuf->Text();
	    gzip->os = gzbuf->Text();
	    gzip->oe = gzbuf->Text() + gzbuf->Length();
	}

	FileIOBinary::Open( mode, e );

	if( e->Test() )
	{
	    delete gzip;
	    gzip = 0;
	    delete gzbuf;
	    gzbuf = 0;
	}
}

void
FileIOCompress::Write( const char *buf, int len, Error *e )
{
	switch ( compMode )
	{
	case FIOC_PASS:
	    FileIOBinary::Write( buf, len, e );
	    break;

	case FIOC_GZIP:
	    // Write( 0, 0 ) means flush (from Close()).
	    // Don't be fooled by buf, 0.

	    if( buf && !len ) 
		return;

	    gzip->is = buf;
	    gzip->ie = buf + len;

	    // Flush output if full and Compress input
	    // util Compress() indicates input exhausted

	    do if( gzip->OutputFull() )
	       {
		   FileIOBinary::Write( gzbuf->Text(),
			gzip->os - gzbuf->Text(), e );
		   gzip->os = gzbuf->Text();
	       }
	    while( !e->Test() && gzip->Compress( e ) && !gzip->InputEmpty() );
	    break;
	case FIOC_GUNZIP:
	    gzip->is = buf;
	    gzip->ie = buf + len;

	    // Flush output if full and Compress input
	    // util Compress() indicates input exhausted

	    do if( gzip->OutputFull() )
	       {
		   FileIOBinary::Write( gzbuf->Text(),
			gzip->os - gzbuf->Text(), e );
		   gzip->os = gzbuf->Text();
	       }
	    while( !e->Test() && gzip->Uncompress( e ) && !gzip->InputEmpty() );
	    break;
	}
}

int
FileIOCompress::Read( char *buf, int len, Error *e )
{
	int done;

	switch ( compMode )
	{
	case FIOC_PASS:
	    return FileIOBinary::Read( buf, len, e );

	case FIOC_GZIP:
	    gzip->os = buf;
	    gzip->oe = buf + len;

	    do if( gzip->InputEmpty() )
	       {
		   int l = FileIOBinary::Read( gzbuf->Text(), gzbuf->Length(), e );
		   if( !l )
		       e->Set( E_FAILED, "Unexpected end of file" );
		   gzip->is = gzbuf->Text();
		   gzip->ie = gzbuf->Text() + l;
	       }
	    while( !e->Test() && gzip->Uncompress( e ) && !gzip->OutputFull() );

	    return gzip->os - buf;
	case FIOC_GUNZIP:
	    gzip->os = buf;
	    gzip->oe = buf + len;
	    done = 0;

	    do if( gzip->InputEmpty() && !done )
	       {
		   int l = FileIOBinary::Read( gzbuf->Text(), gzbuf->Length(), e );
		   gzip->is = l ? gzbuf->Text() : 0;
		   gzip->ie = gzbuf->Text() + l;
		   done |= !l;
	       }
	    while( !e->Test() && gzip->Compress( e ) && !gzip->OutputFull() );

	    return gzip->os - buf;
	}

	e->Sys( "read", Name() );
	return -1;
}

void
FileIOCompress::Close( Error *e )
{
	// Flush & clear gzip 

	switch( compMode )
	{
	case FIOC_GZIP:

	    if( gzip && mode == FOM_WRITE && GetFd() != -1 )
	    {
		Write( 0, 0, e );
		FileIOBinary::Write( gzbuf->Text(),
				     gzip->os - gzbuf->Text(), e );
	    }
	    break;

	case FIOC_GUNZIP:
	    // Flush & clear gzip 

	    if( gzip && mode == FOM_WRITE && gzip->os - gzbuf->Text() )
		FileIOBinary::Write( gzbuf->Text(),
			gzip->os - gzbuf->Text(), e );
	    break;

	case FIOC_PASS:
	    break;
	}

	delete gzip;
	gzip = 0;
	delete gzbuf;
	gzbuf = 0;

	// Rest of normal close

	FileIOBinary::Close( e );
}

void
FileIOCompress::Seek( offL_t offset, Error *e )
{
	if ( compMode == FIOC_PASS )
	    FileIOBinary::Seek( offset, e );
	// else set error? The FileSys stub method is quiet on this
}
