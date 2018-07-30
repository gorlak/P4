/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

class Sha1Digester;

class ZLibInflater
{
    public:
	ZLibInflater( FileSys *, int );
	virtual			~ZLibInflater();

	unsigned char		GetChar( int &eof, Error *e )
	    { eof = 0; return ( workP >= workEnd ) ?
			   GetChar2( eof, e ) : (unsigned char)(*workP++); }
	virtual unsigned char	GetChar2( int &eof, Error *e ) = 0;
	virtual void		GetLine( StrBuf *buf, int &eof, Error *e );
	virtual int		Read( unsigned char *, int, int &, Error *e );
	virtual void		Seek( offL_t pos, Error *e ) = 0;
	virtual unsigned char	*GetBaseAddress() { return 0; }
	virtual offL_t          GetMappedSize() { return (offL_t) 0; }

    protected:

	FileSys			*f;

	// A buffer of data we've successfully inflated:

	StrFixed		*workBuf;
	char			*workP;
	char			*workEnd;

	// zlib state data:
	void			*zstrm;
	int			zret;
	int			zinitDone;
} ;

/*
 * ZLInflater: utility class for un-zlib-ing part or all of a file's data.
 */

class ZLInflater : public ZLibInflater
{
    public:
				ZLInflater(
	                            FileSys *f,
	                            offL_t pos,
	                            Error *e );
				~ZLInflater();

	unsigned char		GetChar2( int &eof, Error *e );

	void			Seek( offL_t pos, Error *e );

    private:

	int                     Fill( char *buf, int len, Error *e );

	int			ReadResults( char *buf, int len, Error *e );

	// A buffer for raw file data we read from the file:

	StrFixed		*filbuf;

	// A buffer for file data we've inflated, and are ready to use:
	StrFixed		*unzbuf;
	int			unzAvail;
	char			*unzP;
} ;

/*
 * ZLMemInflater: utility class for un-zlib-ing using a memory-mapped file.
 */

class ZLMemInflater : public ZLibInflater
{
    public:
				ZLMemInflater(
	                            FileSys *f,
	                            offL_t pos,
	                            Error *e );
				~ZLMemInflater();

	unsigned char		GetChar2( int &eof, Error *e );

	void			Seek( offL_t pos, Error *e );

	unsigned char		*GetBaseAddress() { return maddr; }
	offL_t                  GetMappedSize() { return size; }

    private:

	void			Open( Error *e );
	void			Close();

	offL_t			size;

	unsigned char		*maddr;
	offL_t			mlen;
	int			mapped;
	int			mapHandleCreated;

# ifdef OS_NT
	typedef	void *HANDLE;

	HANDLE			mapHandle;
# endif

} ;

class ZLDeflater
{
    public:
				ZLDeflater(const StrPtr *fName);
				~ZLDeflater();

	void			Write( const char *, int, Error * );

	void			Close( Error * );

    private:

	void			Open( Error *e );

	// zlib state data:
	void			*zstrm;
	int			zret;
	int			zinitDone;

	StrFixed		*workBuf;
	int			opened;
	FileSys			*f;
} ;

class ZLFDeflater
{
    public:
				ZLFDeflater( FileSys *f, Sha1Digester *d );
				~ZLFDeflater();

	void			Start( Error *e );
	void			Write( const char *, int, Error * );
	void			Finish( Error *e );

    private:

	// zlib state data:
	void			*zstrm;
	int			zret;
	int			zinitDone;

	StrFixed		*workBuf;
	FileSys			*f;
	Sha1Digester		*digester;
} ;
