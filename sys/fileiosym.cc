/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# define NEED_FILE
# define NEED_STAT

# include <stdhdrs.h>

# ifdef HAVE_SYMLINKS

# include <error.h>
# include <strbuf.h>
# include <debug.h>
# include <tunable.h>
# include <i18napi.h>
# include <charcvt.h>

# include "filesys.h"
# include "pathsys.h"
# include "fileio.h"

# ifdef OS_NT
extern int nt_readlink( StrPtr *name, StrBuf &buf, int dounicode, int lfn );
# define readlink(name,buf,dounicode,lfn) nt_readlink(name,buf,dounicode,lfn)

extern int nt_makelink( StrBuf &target, StrPtr *name, int dounicode, int lfn );
# define symlink(target,name,dounicode,lfn) nt_makelink(target,name,dounicode,lfn)
# endif

FileIOSymlink::~FileIOSymlink()
{
	Cleanup();
}

void
FileIOSymlink::Open( FileOpenMode mode, Error *e )
{
	offset = 0;
	value.Clear();
	this->mode = mode;

	// If reading, soak up the symlink now, to be passed back by Read().
	// Writing is done at close.

	if( mode == FOM_READ )
	{
# ifdef OS_NT
	    // The StrBuf allocation is done in nt_readlink().
	    int l = readlink( Path(), value, DOUNICODE, LFN );
# else
	    int size = p4tunable.Get( P4TUNE_FILESYS_MAXSYMLINK );

	    int l = readlink( Name(), value.Alloc( size ), size );
# endif

	    if( l < 0 )
	    {
		e->Sys( "readlink", Name() );
		return;
	    }

	    value.SetLength( l );

	    // Append newline for prettiness and terminate string.

	    value.Append( "\n" );
	}
}

void
FileIOSymlink::Write( const char *buf, int len, Error *e )
{
	// Just append to internal buffer.

	value.Append( buf, len );
}

int
FileIOSymlink::Read( char *buf, int len, Error *e )
{
	// Just read from internal buffer.
	// Offset tracks how much we have.
	
	int l = value.Length() - offset;

	if( len < l )
	    l = len;

	memcpy( buf, value.Text() + offset, l );

	offset += l;

	return l;
}

void
FileIOSymlink::Close( Error *e )
{
	if( mode == FOM_WRITE && value.Length() )
	{
	    // Strip newline added by Open().

	    char *p;

	    if( p = strchr( value.Text(), '\n' ) )
	    {
		value.SetEnd( p );
		value.Terminate();
	    }

# ifdef OS_NT
	    if( symlink( value, Path(), DOUNICODE, LFN ) < 0 )
# else
	    if( symlink( value.Text(), Name() ) < 0 )
# endif
		e->Sys( "symlink", Name() );
	}

	// Prevent duplicate closes

	value.Clear();
}

void
FileIOSymlink::Truncate( offL_t offset, Error *e )
{
}

void
FileIOSymlink::Truncate( Error *e )
{
}

int
FileIOSymlink::StatModTime()
{
# ifdef OS_NT
	int t = FileIO::StatModTime();
	return t >= 0 ? t : 0;
# else
	struct stat sb;

	if( lstat( Name(), &sb ) < 0 )
	    return 0;

	return (int)sb.st_mtime;
# endif
}

void
FileIOSymlink::Chmod( FilePerm perms, Error *e )
{
}

void
FileIOSymlink::ChmodTime( int modTime, Error *e )
{
}

# endif
