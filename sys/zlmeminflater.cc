/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# define NEED_FILE
# define NEED_FCNTL
# define NEED_TYPES
# define NEED_MMAP
# define NEED_FLOCK

# include <stdhdrs.h>

# include <strbuf.h>
# include <error.h>
# include <debug.h>
# include <filesys.h>

# include <msgos.h>

# include "zlib.h"

# include "zlinflater.h"

ZLMemInflater::ZLMemInflater( FileSys *f, offL_t, Error *e )
    : ZLibInflater( f, 65536 )
{
	mapped = mapHandleCreated = 0;

	Open( e );
}

ZLMemInflater::~ZLMemInflater()
{
	Close();
}

void
ZLMemInflater::Seek( offL_t pos, Error *e )
{
	z_streamp zls = (z_streamp)zstrm;

	if( zinitDone )
	    inflateEnd( (z_stream *)zstrm );

	zls->zalloc = Z_NULL;
	zls->zfree  = Z_NULL;
	zls->opaque = Z_NULL;
	zls->next_in = maddr + pos;
	P4INT64 bytesAvail = ( size - pos );
	if( bytesAvail > 0xffffffffll )
	    zls->avail_in = (uInt)0xffffffff; // size - pos, rounded down to 32 bits
	else
	    zls->avail_in = (uInt)bytesAvail;
	zret = inflateInit( zls );
	if( zret != Z_OK )
	{
	    e->Set( MsgOs::ZlibInflateInitSeek ) <<
	            f->Name() << StrNum( zret ) << StrNum( pos );
	    return;
	}
	zinitDone = 1;
}

unsigned char
ZLMemInflater::GetChar2( int &eof, Error *e )
{
	eof = 0;

	while( workP >= workEnd )
	{
	    if( zret == Z_STREAM_END )
	    {
	        eof = 1;
	        return '\0';
	    }

	    z_streamp zls = (z_streamp)zstrm;

	    zls->avail_out = workBuf->Length();
	    zls->next_out = (Bytef *)workBuf->Text();

	    zret = inflate( zls, Z_NO_FLUSH );
	    if( zret != Z_OK && zret != Z_STREAM_END )
	    {
	        e->Set( MsgOs::ZlibInflate ) << f->Name() << StrNum( zret );
	        return '\0';
	    }
	    workP = workBuf->Text();
	    int workLen = workBuf->Length() - zls->avail_out;
	    workEnd = workP + workLen;
	}
	return (unsigned char)(*workP++);
}

void
ZLMemInflater::Open( Error *e )
{
	size = f->GetSize();

	int fd = f->GetFd();

# ifdef HAVE_MMAP

	if( fd > 0 
	    && size > 0 )
	{
	    mlen = size;

	    maddr = (unsigned char *)mmap( 
		    (caddr_t)0, 
		    size,
		    PROT_READ,
		    MAP_PRIVATE,
		    fd,
		    (off_t)0 );

	    mapped = maddr != (unsigned char *)-1;
	    return;
	}
# else
# ifdef OS_NT
	mapHandle = CreateFileMapping( (HANDLE)_get_osfhandle(fd), NULL,
	                                   PAGE_READONLY, 0, 0, NULL );
	if( mapHandle != NULL )
	{
	    mapHandleCreated = 1;

	    maddr = (unsigned char *)
	            MapViewOfFile( mapHandle, FILE_MAP_READ, 0, 0, 0 );

	    mapped = maddr != NULL;
	    return;
	}
# endif
# endif
	e->Set( E_FAILED, "No platform support for mmap" );
}

void
ZLMemInflater::Close()
{
# ifdef HAVE_MMAP
	if( mapped && maddr != (unsigned char *)-1 )
	    munmap( (caddr_t)maddr, mlen );
# else
# ifdef OS_NT
	if( mapped )
	    UnmapViewOfFile( maddr );
	if( mapHandleCreated )
	    CloseHandle( mapHandle );
# endif
# endif

	maddr = (unsigned char *)-1;
	mapped = 0;
}
