/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * readfile.cc - RCS file input routines:
 *
 * History:
 *	2-18-97 (seiwald) - translated to C++.
 */

# define NEED_FILE
# define NEED_FCNTL
# define NEED_TYPES
# define NEED_MMAP

# include <stdhdrs.h>
# include <strbuf.h>
# include <error.h>
# include <debug.h>
# include <tunable.h>
# include <filesys.h>

# include "readfile.h"

/*
 * ReadFile standard implementation (using read/write)
 */

ReadFile::ReadFile()
{
	fp = 0;
	mapped = 0;
	maddr = (unsigned char *)-1;
	mlen = 0;
	mptr = mend = 0;
	size = 0;
	offset = 0;
}

ReadFile::~ReadFile()
{
	Close();
}

void
ReadFile::Open( FileSys *f, Error *e )
{
	/* We open.  ReadFile::Close() will close. */

	this->fp = f;

	f->Open( FOM_READ, e );

	if( e->Test() )
	    return;

	// find size

	size = f->GetSize();

# ifdef HAVE_MMAP

	/* Try to mmap. */
	/* On Solaris (at least), you can't mmap a zero length file. */

	int fd = fp->GetFd();

	if( fd > 0 
	    && size > 0
	    && size <= p4tunable.Get( P4TUNE_FILESYS_MAXMAP ) )
	{
	    mlen = offset = size;

	    maddr = (unsigned char *)mmap( 
		    (caddr_t)0, 
		    size,
		    PROT_READ,
		    MAP_PRIVATE,
		    fd,
		    (off_t)0 );

	    mapped = maddr != (unsigned char *)-1;
	}

# endif

	/* Without mmap, we seek/read as needed */

	if( !mapped )
	{
	    offset = 0;	
	    mlen = FileSys::BufferSize();
	    maddr = new unsigned char[ mlen ];
	}

	/* maddr ... mptr ... mend */

	mptr = maddr;
	mend = mptr + offset;
}

void
ReadFile::Close()
{
	if( !mapped && maddr != (unsigned char *)-1 )
	    delete []maddr;

# ifdef HAVE_MMAP
	if( mapped && maddr != (unsigned char *)-1 )
	    munmap( (caddr_t)maddr, mlen );
# endif

	if( fp )
	    fp->Close( e );

	maddr = (unsigned char *)-1;
	mapped = 0;
	fp = 0;
}

int
ReadFile::Read()
{
	// either mmaped, or all read

	if( offset >= size )
	    return 0;

	int n = fp->Read( (char*)maddr, mlen, e );

	if( e->Test() )
	{
	    // say what? file got short?
	    size = offset;
	    n = 0;
	}

	mptr = maddr;
	mend = mptr + n;
	offset += n;

	/* return if more */

	return n;
}

void	
ReadFile::Seek( offL_t o )
{
	offL_t l = offset - o;

	// Either mmapped or in buffer
	// Else actually seek underlying file.

	if( l >= 0 &&  l <= mend - maddr )
	{
	    mptr = mend - l;
	}
	else
	{
	    Error e;

	    fp->Seek( o, &e );
	    mend = mptr = maddr;
	    offset = o;
	}
}

offL_t
ReadFile::Memcmp( ReadFile *other, offL_t length ) 
{
	int l1, l2;

	while( length && ( l1 = InMem() ) && ( l2 = other->InMem() ) )
	{
	    if( l1 > length )
		l1 = length;
	    if( l1 > l2 )
		l1 = l2;

	    if( int x = memcmp( mptr, other->mptr, l1 ) )
		return x;

	    mptr += l1;
	    other->mptr += l1;
	    length -= l1;
	}

	return 0;
}

offL_t
ReadFile::Memcpy( char *buf, offL_t length )
{
	int l;
	offL_t olen = length;

	while( length && ( l = InMem() ) )
	{
	    if( l > length )
		l = length;
		
	    (void)memcpy( buf, mptr, l );

	    buf += l;
	    mptr += l;
	    length -= l;
	}

	return olen - length;
}

offL_t
ReadFile::Memccpy( char *buf, int c, offL_t length )
{
	int l;
	offL_t olen = length;

	while( length && ( l = InMem() ) )
	{
	    if( l > length )
		l = length;
		
	    char *b;

	    if( b = (char *)memccpy( buf, mptr, c, l ) )
		l = b - buf;

	    buf += l;
	    mptr += l;
	    length -= l;

	    if( b )
		break;
	}

	return olen - length;
}

offL_t
ReadFile::Memchr( int c, offL_t length )
{
	// Memchr( c, -1 ) means to Eof()

	if( length == -1 )
	    length = Size() - Tell();

	int l;
	offL_t olen = length;

	while( length && ( l = InMem() ) )
	{
	    if( l > length )
		l = length;
		
	    unsigned char *p;

	    if( p = (unsigned char *)memchr( mptr, c, l ) )
		l = p - mptr;

	    mptr += l;
	    length -= l;

	    if( p )
		break;
	}

	return olen - length;
}

/*
 * ReadFile::Textcpy() - Memcpy w/ line ending translation
 *
 * Textcpy() is written entirely in calls to Memcpy() and Memccpy().
 */

offL_t
ReadFile::Textcpy( char *dst, offL_t dstlen, offL_t srclen, LineType type )
{
	switch( type )
	{
	default:
	case LineTypeRaw:
	    {
		// Just Memcpy the minimum.

		return Memcpy( dst, dstlen < srclen ? dstlen : srclen );
	    }

	case LineTypeCr:
	    {
		// Memcpy the minimum, translating \r to \n

		char *odst = dst;

		if( dstlen > srclen ) dstlen = srclen;

		while( dstlen )
		{
		    offL_t l = Memccpy( dst, '\r', dstlen );
		    if( !l ) break;
		    dst += l, dstlen -= l;
		    if( dst[-1] == '\r' ) dst[-1] = '\n';
		}

		return dst - odst;
	    }

	case LineTypeCrLf:
	case LineTypeLfcrlf:
	    {
		// Memcpy, stopping at each \r and, if it is followed
		// by a \n, translating the \r to \n and dropping the
		// \n from the source.  This can cause dstlen and srclen
		// to move out of step.  If we hit a \r at the exact end
		// of srclen, and a \n follows, srclen reaches -1.
		// LFCRLF reads CRLF.

		char *odst = dst;

		while( dstlen && srclen > 0 )
		{
		    offL_t l;
		    l = Memccpy( dst, '\r', dstlen < srclen ? dstlen : srclen);
		    if( !l ) break;
		    dst += l, dstlen -= l, srclen -= l;

		    if( dst[-1] == '\r' && !Eof() && Char() == '\n' )
			Next(), dst[-1] = '\n', --srclen;
		}

		return dst - odst;
	    }
	}
}
