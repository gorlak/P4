/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# define NEED_SLEEP
# include <stdhdrs.h>

# include <strbuf.h>
# include <error.h>
# include <debug.h>
# include <vararray.h>
# include <strarray.h>
# include <sha1.h>
# include <filesys.h>

# include "objstream.h"
# include "zfilestream.h"
# include "zlinflater.h"


ZFileStream::ZFileStream( 
	FileSys *packFile,
	ZLibInflater *i,
	P4INT64 offset,
	Error *e )
{
	eof = 0;
	f = packFile;
	inflater = i;
	inflater->Seek( offset, e );
}

ZFileStream::~ZFileStream()
{
}

unsigned char
ZFileStream::Next( Error *e )
{
	return inflater->GetChar( eof, e );
}

void
ZFileStream::GetLine( StrBuf *buf, Error *e )
{
	return inflater->GetLine( buf, eof, e );
}
