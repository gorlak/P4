/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * fblreader.h - FileSysBufferedLineReader class
 *
 * The FileSysBufferedLineReader class wraps a FileSys with a different
 * version of the ReadLine method, which keeps its own buffer, rather than
 * relying on whatever buffering might be occurring in the underlying
 * FileSys object.
 *
 * This means this class is good for calling ReadLine against an underlying
 * class, such as FileIOGunzip, that does a poor job with single-byte reads.
 */

class FileSysBufferedLineReader : public FileSys {

    public:
			FileSysBufferedLineReader( FileSys *);
			~FileSysBufferedLineReader();

	virtual int	ReadLine( StrBuf *buf, Error *e );

	// These are all simple pass-through wrappers for FileSys virtual
	// methods.

	virtual void	Set( const StrPtr &name )
	                { src->Set( name ); }
	virtual void	Set( const StrPtr &name, Error *e )
	                { src->Set( name, e ); }
	virtual void	Open( FileOpenMode mode, Error *e )
	                { src->Open( mode, e ); }
	virtual void	Write( const char *buf, int len, Error *e )
	                { src->Write( buf, len, e ); }
	virtual int	Read( char *buf, int len, Error *e )
	                { return src->Read( buf, len, e ) ; }
	virtual void	Close( Error *e )
	                { src->Close( e ); }
	virtual int	Stat()
	                { return src->Stat(); }
	virtual int	StatModTime()
	                { return src->StatModTime(); }
	virtual void	Truncate( Error *e )
	                { src->Truncate( e ); }
	virtual void	Truncate( offL_t offset, Error *e )
	                { src->Truncate( offset, e ); }
	virtual void	Unlink( Error *e = 0 )
	                { src->Unlink( e ); }
	virtual void	Rename( FileSys *target, Error *e )
	                { src->Rename( target, e ); }
	virtual void	Chmod( FilePerm perms, Error *e )
	                { src->Chmod( perms, e ); }
	virtual void	ChmodTime( Error *e )
	                { src->ChmodTime( e ); }

    private:

	int		ReadOne( char *buf, Error *e );

	FileSys		*src;
	StrBuf		lBuf;
	char		*t;
	int		pos;
	int		len;
	int		size;
} ;
