/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

class ObjStream
{
    public:

	                        ObjStream() { }

	virtual			~ObjStream() { }

	virtual unsigned char	Next( Error *e ) = 0;

	int			AtEof() { return eof; }

    protected:

	int			eof;
} ;

