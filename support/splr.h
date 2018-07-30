
/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * StrPtrLineReader: utility class for manipulating a string which
 *                   contains multiple "lines", separated by embedded
 *                   linefeed characters. Wins no awards for efficiency,
 *                   but is intended to be used by command line aliasing,
 *                   which is typically used with small string buffers.
 */
class StrPtrLineReader
{

    public:
	                StrPtrLineReader( const StrPtr *buf );
	                ~StrPtrLineReader();

	int		GetLine( StrBuf *line );

	int		CountLines();

    private:

	const char *	start;
} ;
