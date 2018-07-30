/*
 * Copyright 1995, 2001 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * readfile.h - RCS file input routines:
 *
 * Classes defined:
 *
 *	ReadFile - a file opened for reading
 *
 * Public methods:
 *
 *	ReadFile::Open() - open a file
 *	ReadFile::Close() - close the file
 *
 *	ReadFile::Eof() - true if no more input
 * 	ReadFile::Char() - return current input character
 * 	ReadFile::Next() - advance input character
 * 	ReadFile::Get() - combo Eof/Char/Next
 * 	ReadFile::Tell() - what is offset of current characater
 *	ReadFile::Memcpy() - copy into buffer
 *	ReadFile::Memccpy() - copy up to marker char into buffer
 *	ReadFile::Memchr() - scan to marker char
 *	ReadFile::Memcmp() - compare two files (length must be valid!)
 *	ReadFile::Textcpy() - Memcpy w/ line ending translation
 *	ReadFile::Seek() - set file pointer
 *	ReadFile::Size() - get size of file
 *
 * Private methods:
 *
 * 	ReadFile::Read() - read a line
 *
 * Notes:
 *
 *	Open() takes a FileSys, which must remain valid until Close().
 *	Open()/Close() call FileSys::Open()/Close().
 *
 *	Char() is not valid for a character until Eof() has been called
 *	first to make sure you're not at EOF.
 *
 *	Textcpy() consumes the minimum of srclen and dstlen, returning
 *	the actual dstlen.  The actual srclen can be discerned by bracketing
 *	with Offset() calls.
 *
 * History:
 *	2-18-97 (seiwald) - translated to C++.
 *	3-10-08 (seiwald) - combined mmap/FileIo
 */

# ifdef OS_NT
# define ReadFile P4ReadFile	/* ugh - name conflict */
# endif

/*
 * ReadFile - a file opened for reading
 */

class FileSys;

class ReadFile
{
    public:
			ReadFile();
			~ReadFile();

	void		Open( FileSys *f, Error *e );
	void		Close();

	int		Char() { return *mptr; }
	int		Get() { return Eof(), *mptr++; }

	void		Prev() { if( --mptr < maddr ) Seek( Tell() ); }
	void		Next() { ++mptr; }
	offL_t		Size() { return size; }
	offL_t		Tell() { return offset - ( mend - mptr ); }
	int		Eof() { return !InMem(); }

	void		Seek( offL_t p );

	offL_t		Memcmp( ReadFile *other, offL_t length );
	offL_t		Memcpy( char *buf, offL_t length );
	offL_t		Memccpy( char *buf, int c, offL_t length );
	offL_t		Memchr( int c, offL_t length );

	offL_t 		Textcpy( char *dst, offL_t dstlen, 
				offL_t srclen, LineType type );

    private:

	int		Read();
	int		InMem() { return mend-mptr ? mend-mptr : Read(); }

	unsigned char	*mptr;		// current char in memory window
	unsigned char 	*maddr;		// start of memory window
	unsigned char	*mend;		// end of memory window

	offL_t		size;		// length of file
	offL_t		offset;		// file offset of *mend

	int		mapped;		// maddr is mmapped
	size_t		mlen;		// maddr alloc size

	FileSys		*fp;		// underlying file for Read()

	Error		e[1];		// for Read() and Close()

} ;

