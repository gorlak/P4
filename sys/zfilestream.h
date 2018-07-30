/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

class ZLibInflater;

/*
 * ZFileStream - a class which can zl inflate some data from a file.
 */

class ZFileStream : public ObjStream
{
    public:

	                        ZFileStream(
	                            FileSys *f,
	                            ZLibInflater *i,
	                            P4INT64 offset,
	                            Error *e );

				~ZFileStream();

	virtual unsigned char	Next( Error *e );
	virtual void		GetLine( StrBuf *buf, Error *e );

    private:

	FileSys			*f;

	ZLibInflater		*inflater;
} ;

