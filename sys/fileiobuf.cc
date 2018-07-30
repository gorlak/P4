/*
 * Copyright 1995, 2003 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * fileiobuf.cc -- FileIOBuffer methods
 */

# ifdef USE_EBCDIC
# define NEED_EBCDIC
# endif
# include <stdhdrs.h>

# include <error.h>
# include <strbuf.h>

# include "filesys.h"
# include "fileio.h"

# include <msgsupp.h>

void
FileIOBuffer::Open( FileOpenMode mode, Error *e )
{
	// Start w/ binary open

	if( ( GetType() & FST_C_MASK ) == FST_C_GUNZIP )
	{
	    // We can't handle gunzip stuff at the level below...
	    e->Set( MsgSupp::Deflate );
	    return;
	}

	FileIOCompress::Open( mode, e );

	// Clear send/receive buffers

	snd = rcv = 0;
}

void
FileIOBuffer::FlushBuffer( Error *e )
{
#if defined( USE_EBCDIC ) && defined( NO_EBCDIC_FILES )
    	__etoa_l( iobuf.Text(), iobuf.Length() );
#endif
	FileIOCompress::Write( iobuf.Text(), snd, e );
	snd = 0;
}

void
FileIOBuffer::SetBufferSize( size_t l )
{
	// You can only do this before you open the file.

	if( fd == -1 )
	    iobuf.SetBufferSize( l );
}

void
FileIOBuffer::Close( Error *e )
{
	// Flush buffers

	while( snd && !e->Test())
		FlushBuffer( e );

	// finish with binary close

	FileIOCompress::Close( e );
}

void
FileIOBuffer::Write( const char *buf, int len, Error *e )
{
	// Write logic: copy whole lines that end in \n,
	// translate the \n to a \r, and arrange so that
	// a \n is added thereafter.

	// addnl: saw a \r, must add a \n

	int addnl = 0;

	while( len || addnl )
	{
	    // If iobuf is full, flush

	    if( snd == iobuf.Length() )
	    {
		    FlushBuffer( e );

		    if( e->Test() )
			    return;
	    }

	    // If we owe a \n because we just sent a \r,
	    // add it now (that we know we have space).

	    if( addnl )
		addnl = 0, iobuf.Text()[ snd++ ] = '\n';

	    // buffer what we can

	    char *p;
	    int l = iobuf.Length() - snd;

	    if( l > len )
		l = len;

	    switch( lineType )
	    {
	    case LineTypeRaw:
	    case LineTypeLfcrlf:
		// Straight copy.
		// LFCRLF writes LF.
		memcpy( iobuf.Text() + snd, buf, l );
		break;

	    case LineTypeCr:
		// Copy out to the next \n.  If we hit one, translate
		// it to a \r.

		if( p = (char *)memccpy( iobuf.Text() + snd, buf, '\n', l ) )
		{
		    p[-1] = '\r';
		    l = p - iobuf.Text() - snd;
		}
		break;

	    case LineTypeCrLf:
		// Copy out to the next \n.  If we hit one, translate
		// it to a \r and set addnl so as to write the \n on 
		// the next loop (when we're sure to have space). 

		if( p = (char *)memccpy( iobuf.Text() + snd, buf, '\n', l ) )
		{
		    p[-1] = '\r';
		    l = p - iobuf.Text() - snd;
		    addnl = 1;
		}
		break;
	    }

	    snd += l;
	    buf += l;
	    len -= l;
	}
}

void
FileIOBuffer::FillBuffer( Error *e )
{
	rcv = FileIOCompress::Read( iobuf.Text(), iobuf.Length(), e );
#if defined( USE_EBCDIC ) && defined( NO_EBCDIC_FILES )
	if( rcv > 0 )
	    __atoe_l( iobuf.Text(), rcv );
#endif
}

int
FileIOBuffer::Read( char *buf, int len, Error *e )
{
	// Read logic: read whole lines that end in \r, and
	// arrange so that a following \n translates the \r
	// into a \n and the \n is dropped.

	// soaknl: we saw a \r, skip this \n

	int ilen = len;
	int soaknl = 0;

	while( len || soaknl )
	{
	    // Nothing in the buffer?

	    if( !rcv )
	    {
		ptr = iobuf.Text();
		FillBuffer( e );

		if( e->Test() )
		    return -1;

		if( !rcv )
		    break;
	    }

	    // Skipping \n because we saw a \r?

	    if( soaknl )
	    {
		if( *ptr == '\n' )
		    ++ptr, --rcv, buf[-1] = '\n';
		soaknl = 0;
	    }

	    // Trim avail to what's needed
	    // Fill user buffer; stop at \r

	    char *p;
	    int l = rcv < len ? rcv : len ;

	    switch( lineType )
	    {
	    case LineTypeRaw:
		// Straight copy.
		memcpy( buf, ptr, l );
		break;

	    case LineTypeCr:
		// Copy to the next \r.  If we hit one, translate
		// it to \n.

		if( p = (char *)memccpy( buf, ptr, '\r', l ) )
		{
		    l = p - buf;
		    p[-1] = '\n';
		}
		break;

	    case LineTypeCrLf:
		// Copy to next \r.  If we hit one, arrange so that
		// if we see \n the next time through (when we know
		// there'll be data in the buffer), we translate this
		// \r to a \n and drop the subsequent \n.
		// LFCRLF reads CRLF.

		if( p = (char *)memccpy( buf, ptr, '\r', l ) )
		{
		    l = p - buf;
		    soaknl = 1;
		}
		break;

	    case LineTypeLfcrlf:

		if( p = (char *)memccpy( buf, ptr, '\r', l ) )
		{
		    l = p - buf;
		    p[-1] = '\n';
		    soaknl = 1;
		}
		break;

	    }

	    ptr += l;
	    rcv -= l;
	    buf += l;
	    len -= l;
	}

	return ilen - len;
}

void
FileIOBuffer::Seek( offL_t pos, Error *e )
{
	if( mode == FOM_WRITE && snd > 0 )
	    FlushBuffer( e );

	if( !e->Test() )
	    FileIOCompress::Seek( pos, e );

	// Clear send/receive buffers

	snd = rcv = 0;
}

offL_t
FileIOBuffer::Tell()
{
	if( mode == FOM_READ )
	    return tellpos - rcv;
	return tellpos + snd;
}

/*
 * This is an optimized version of FileSys::ReadLine to take advantage
 * of the buffering we have.
 *
 * The macro STRICT_LINEENDING sets up the code to strictly follow
 * the specified FileSys line ending, but that does not match the
 * reality of the prior existing FileSys::ReadLine.  I'm submitting
 * with this macro option in case we decide to use this strict case
 * in the future instead of having to rediscover how to do that. - JAA
 *
 * See the test program readlinetest in the tests directory.
 *
 * Return values...
 * 0 if end of file
 * 1 if complete line read
 * -1 partial line read - size excedded before line ended
 */

int
FileIOBuffer::ReadLine( StrBuf *buf, Error *e )
{
	buf->Clear();
	int size = iobuf.Length();

	// Read logic: read whole lines that end in \r, and
	// arrange so that a following \n translates the \r
	// into a \n and the \n is dropped.

	// soaknl: we saw a \r, skip this \n

	int soaknl = 0;
	int linedone = 0;

	while( ( !linedone && buf->Length() < size ) || soaknl )
	{
	    // Nothing in the buffer?

	    if( !rcv )
	    {
		ptr = iobuf.Text();
		FillBuffer( e );

		if( e->Test() || !rcv )
		{
		    if( linedone || buf->Length() > 0 )
			break;	// this really exits 1
		    return 0;
		}
	    }

	    // Skipping \n because we saw a \r?

	    if( soaknl )
	    {
		if( *ptr == '\n' )
		    ++ptr, --rcv;
		soaknl = 0;
	    }

	    // Trim avail to what's needed
	    // Fill user buffer; stop at \r

	    if( linedone || buf->Length() >= size )
		break;

	    char *p;
	    int l = rcv < size ? rcv : size;

	    switch( lineType )
	    {
	    case LineTypeRaw:
		// Straight copy.
		p = (char *)memchr( ptr, '\n', l );
		if( p )
		{
		    l = p - ptr;
		    buf->Extend( ptr, l );
		    l++;
		    linedone = 1;
		}
		else
		    buf->Extend( ptr, l );
		break;

	    case LineTypeCr:
		// Copy to the next \r.

#ifndef STRICT_LINEENDING
		// or the next \n
		if( p = (char *)memchr( ptr, '\n', l ) )
		{
		    l = p - ptr;
		    if( p = (char *)memchr( ptr, '\r', l ) )
			l = p - ptr;
		    buf->Extend( ptr, l );
		    l++;
		    linedone = 1;
		}
		else
#endif
		if( p = (char *)memchr( ptr, '\r', l ) )
		{
		    l = p - ptr;
		    buf->Extend( ptr, l );
		    l++;
		    linedone = 1;
		}
		else
		    buf->Extend( ptr, l );
		break;

	    case LineTypeCrLf:
#ifdef STRICT_LINEENDING
		// Copy to next \r.  If we hit one, arrange so that
		// if we see \n the next time through (when we know
		// there'll be data in the buffer) drop it.

		if( p = (char *)memchr( ptr, '\r', l ) )
		{
		    l = p - ptr;
		    buf->Extend( ptr, l );
		    l++;
		    soaknl = linedone = 1;
		}
		else
		    buf->Extend( ptr, l );
		break;
#else
		// fall through...
#endif

	    case LineTypeLfcrlf:

		if( p = (char *)memchr( ptr, '\n', l ) )
		{
		    l = p - ptr;
		    if( p > ptr && p[-1] == '\r' )
			buf->Extend( ptr, l-1 );
		    else
			buf->Extend( ptr, l );
		    l++;
		    linedone = 1;
		}
		else if( ptr[l-1] == '\r' )
		{
		    buf->Extend( ptr, l-1 );
		    soaknl = linedone = 1;
		}
		else
		    buf->Extend( ptr, l );
		break;

	    }

	    ptr += l;
	    rcv -= l;
	}

	buf->Terminate();

	return linedone ? 1 : -1;
}
