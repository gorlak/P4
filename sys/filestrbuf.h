/*
 * Copyright 2011 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * FileStrBuf.h - FileSys interface to in-memory data
 *
 * Public classes:
 *
 *	FileStrPtr - FileSys that reads from a StrPtr
 */

class FileStrPtr : public FileSys
{
    public:

		FileStrPtr( StrPtr *s );

	// FileSys methods needed by ReadFile

	int	Read( char *buf, int len, Error *e );
	void	Open( FileOpenMode mode, Error *e );
	void	Seek( offL_t offset, Error *e );
	offL_t  Tell();
	offL_t	GetSize();

	// FileSys stubs

	void	Close( Error *e ) {};
	void	Write( const char *buf, int len, Error *e ) {};
	int	Stat() { return FSF_EXISTS; }
	int	StatModTime() { return 0; }
	void	Truncate( Error *e ) {};
	void	Truncate( offL_t offset, Error *e ) {};
	void	Unlink( Error *e = 0 ) {};
	void	Rename( FileSys *target, Error *e ) {};
	void	Chmod( FilePerm perms, Error *e ) {};
	void	ChmodTime( Error *e ) {};

    private:

	StrPtr	*ptr;
	int	offset;
};
