/*
 * Copyright 1995, 2003 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * fblreader -- implementation of FileSysBufferedLineReader class
 */

# include <stdhdrs.h>

# include <error.h>
# include <strbuf.h>

# include "filesys.h"
# include "fblreader.h"

FileSysBufferedLineReader::FileSysBufferedLineReader( FileSys *f )
{
	this->src = f;
	this->size = this->src->BufferSize();
	this->t = this->lBuf.Alloc( this->size );
	this->pos = 0;
	this->len = 0;
}

FileSysBufferedLineReader::~FileSysBufferedLineReader()
{
	delete src;
	src = 0;
}

int
FileSysBufferedLineReader::ReadLine( StrBuf *buf, Error *e )
{
	char b = 0;
	buf->Clear();
	 
	while( buf->Length() < size && ReadOne( &b, e ) == 1 && b != '\n' )
	    buf->Extend( b );
 
	if( !buf->Length() && !b )
	    return 0;
 
	buf->Terminate();
 
	return b == '\n' ? 1 : -1;
}

int	
FileSysBufferedLineReader::ReadOne( char *buf, Error *e )
{
	// If we have a saved byte in the buffer, return it:
	if( pos < len )
	{
	    *buf = t[ pos++ ];
	    return 1;
	}
	if( ( len = src->Read( t, size, e ) ) <= 0 )
	    return len;

	*buf = t[ 0 ];
	pos = 1;
	return 1;
}
