/*
 * Copyright 1995, 2003 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * zipfile.h - a class for zipping and unzipping zip files
 *
 * Classes Defined:
 *
 *	ZipFile
 */

class ZipFile
{
    public:
			ZipFile();
			~ZipFile();

	void		Open( const char *fName, Error *e );
	void		Close();

	void		AppendBytes(
	                    const char *bytes,
	                    p4size_t len,
	                    Error *e );

	void		StartEntry( const char *entry, Error *e );
	void		FinishEntry( Error *e );

	offL_t		GetSize();

    private:

	void		*zf;
	StrBuf		zfName;
} ;

class UnzipFile
{
    public:

	    		UnzipFile();
	virtual		~UnzipFile();

	void		Open( const char *fName, Error *e );
	void		Close();

	int		HasEntry( const char *entry );
	virtual void	OpenEntry( const char *entry, Error *e );
	void		CloseEntry();

	int		ReadBytes( char *bytes, p4size_t len, Error *e );

	offL_t		GetSize();

    protected:

	void		*zf;

    private:

	StrBuf		zfName;
} ;
