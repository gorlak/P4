/*
 * Copyright 1995, 2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include <debug.h>
# include <strbuf.h>

# include "splr.h"

// This simple class lets you read through a StrPtr's text, a "line" at a time.

StrPtrLineReader::StrPtrLineReader( const StrPtr *buf )
{
	start = buf->Text();
}

StrPtrLineReader::~StrPtrLineReader()
{
}

int
StrPtrLineReader::GetLine( StrBuf *line )
{
	if( !start || !(*start) )
	    return 0;

	const char *p = start;
	for( ; p && *p; p++ )
	    if( p[0] == '\n' )
	        break;

	line->Set( start, p - start );
	start = (*p) ? p + 1 : 0 ;
	return 1;
}

int
StrPtrLineReader::CountLines()
{
	if( !start || !(*start) )
	    return 0;

	int numLines = 1;

	for( const char *p = start; *p; p++ )
	    if( *p == '\n' && p[1] != '\0' )
	        numLines++;

	return numLines;
}
