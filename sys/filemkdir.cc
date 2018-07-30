/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# define NEED_ACCESS
# define NEED_ERRNO
# define NEED_STAT

# include <stdhdrs.h>
# include <charman.h>

# include <i18napi.h>
# include <charcvt.h>

# ifdef OS_VMS
# include <unistd.h>
# include <dirent.h>
# endif

# include <error.h>
# include <strbuf.h>
# include <strarray.h>

# include "pathsys.h"
# include "filesys.h"
# include "macfile.h"
# include "fileio.h"
# include "signaler.h"

# ifdef OS_NT
# include "windows.h"
extern int nt_islink( StrPtr *fname, DWORD *dwFlags, int dounicode, int lfn );
extern void nt_free_wname( const wchar_t *wname );
# endif

// We can encounter .DS_Store files on *any* platform
// and we should remove them if we've been directed to
// RmDir().
//
// http://en.wikipedia.org/wiki/.DS_Store
//
StrRef DS_STORE_NAME(".DS_Store");


# ifdef OS_NT
int
DirExists( const wchar_t *wp )
{
	DWORD attrs;

	// Silly MS, can't use wstat because they screen for wild cards
	// without stepping past the LFN escape, "\\?\".
	//
	attrs = GetFileAttributesW (wp);
	if (attrs == INVALID_FILE_ATTRIBUTES)
	    return -1;
	else
	    return 0;
}
# endif

/*
 * filemkdir.cc -- mkdir and rmdir operations
 */

/*
 * FileSys::MkDir() - make directory, recursively if necessary
 */

void
FileSys::MkDir( const StrPtr &path, Error *e )
{
	PathSys *p = PathSys::Create();
	p->SetCharSet( GetCharSetPriv() );

	p->Set( path );

# ifdef OS_NT
	if( !LFN )
	{
	    // This will error on a Windows path longer than 260 chars.
	    FileSys *f = FileSys::Create( FST_TEXT );
	    f->Set( path, e );
	    delete f;
	}
#endif

	// Bail if there is no parent, or the parent is "" (current dir)

	if( ( e && e->Test() ) || !p->ToParent() || !p->Length() )
	{
	    delete p;
	    return;
	}

	// BEOS and VMS:
	// Blinkin' thing's access() returns -1 for all directories,
        // so we use stat() instead.
	// Now we always use stat(), just 'cause it works.

# ifdef OS_NT
	const wchar_t *wp;

	// LFN is supported in UnicodeName
	if( ( DOUNICODE || LFN ) &&
	    ( wp = FileIO::UnicodeName( p, LFN ) ) )
	{
	    if( DirExists( wp ) < 0 )
	    {
		MkDir( *p, e );

		if( !e->Test() )
		{
		    if( _wmkdir( wp ) < 0 && DirExists( wp ) < 0 )
			if( errno != EEXIST )
			    e->Sys( "mkdir", p->Text() );
		}
	    }

	    nt_free_wname( wp );
	    delete p;
	    return;
	}	
	if( nt_islink( p, NULL, DOUNICODE, LFN ) > 0 )
	{
	    delete p;
	    return;
	}
# endif

	// Ensure it is a dir.  On cygwin (at least) we can create
	// a directory with the same apparent name as a file (on
	// cygwin only if that file is a .exe).

	struct stat sb;

	if( stat( p->Text(), &sb ) >= 0 && S_ISDIR( sb.st_mode ) )
	{
	    delete p;
	    return;
	}

	// Recursively make the directory, but not on VMS, where
	// you can just mkdir() the whole path.

# ifndef OS_VMS
	MkDir( *p, e );

	if( e->Test() )
	{
	    delete p;
	    return;
	}
# endif

	// It seems that some versions of the MSVC runtime have a mangled
	// mkdir that succeeds but returns failure on our "foo,d" directories.

# if defined(OS_OS2) || defined(OS_NT)
	if( mkdir( p->Text() ) < 0 && stat( p->Text(), &sb ) < 0 )
	    if( errno != EEXIST )
		e->Sys( "mkdir", p->Text() );
# else
	if( mkdir( p->Text(), PERM_0777 ) < 0 )
	    if( errno != EEXIST )
		e->Sys( "mkdir", p->Text() );
# endif

	delete p;
}

void
FileSys::RmDir( const StrPtr &path, Error *e )
{
	PathSys *p = PathSys::Create();
	p->SetCharSet( GetCharSetPriv() );  

	p->Set( path );

# ifdef OS_NT
	if( !LFN )
	{
	    // This will error on a Windows path longer than 260 chars.
	    FileSys *f = FileSys::Create( FST_TEXT );
	    f->Set( path, e );
	    delete f;
	}
# endif

	// Bail if there is no parent, or the parent is "" (current dir)

	if( (e && e->Test() ) || !p->ToParent() || !p->Length() )
	{
	    delete p;
	    return;
	}

	if( preserveCWD )
	{
	    char cwd[ 2048 ];
	    getcwd( cwd, sizeof( cwd ) );

	    if( !StrPtr::SCompare( p->Text(), cwd ) )
	    {
	        delete p;
	        return;
	    }
	}

	// Remove the directory.
	// Bail on failure.

# ifdef OS_NT
	DWORD attr;
	const wchar_t *wp = NULL;

	if( DOUNICODE || LFN )
	{
	    if( (wp = FileIO::UnicodeName( p, LFN )) != NULL )
		attr = GetFileAttributesW( wp );
	}
	else	
	    attr = GetFileAttributesA( p->Text() );

	// for windows bail if the directory is a 'junction'

	if( attr & FILE_ATTRIBUTE_REPARSE_POINT )
	{
	    nt_free_wname( wp );
	    delete p;
	    return;  
	}

	if( wp )
	{
	    if( _wrmdir( wp ) < 0 )
	    {
		nt_free_wname( wp );
		delete p;
		return; 
	    }
	    nt_free_wname( wp );
	}
	else
# endif
	if( rmdir( p->Text() ) < 0 )
	{
	    // It's possible we may have encountered a .DS_Store file
	    // These are created by the Finder on Mac OS X.
	    //
	    // http://en.wikipedia.org/wiki/.DS_Store
	    //
	    // These can be deleted with no harm.
	  
	    // First make a path for the .DS_Store file
	    //
	    PathSys * dsp = PathSys::Create();
	    dsp->SetCharSet( GetCharSetPriv() );
	    dsp->SetLocal( *p, DS_STORE_NAME );

	    FileSys * fs = FileSys::Create( FST_BINARY );
	    fs->Set( *dsp );

	    delete dsp;
	    
	    // If there doesn't exist a .DS_Store file, rmdir() failed for
	    // "legitimate" reasons. We bail.
	    //
	    if ( !(fs->Stat() & FSF_EXISTS) )
	    {
	        delete fs;
	        delete p;
	        return;
	    }
	    
	    // If the file exists, we need to make sure it is the *only* file
	    // in the directory.
	    //
	    FileSys * dir = FileSys::Create( FST_BINARY );

	    if ( !dir )
	    {
	        delete fs;
	        delete p;
	        return;
	    }
	    dir->Set( *p );
	    
	    StrArray * files = dir->ScanDir( e );
	    
	    if ( files && files->Count() == 1 )
	        fs->Unlink( e );

	    delete fs;
	    delete dir;
	    delete files;

	    // Try again
	    //
	    if( rmdir( p->Text() ) < 0 )
	    {
	        delete p;
	        return;
	    }
	}

	// Hey -- it worked.  Try to get the parent.

	RmDir( *p, e );

	delete p;
}

void
FileSys::PurgeDir( const char *dir, Error *e )
{
	FileSys *f = FileSys::Create( FST_BINARY );
	f->Set( dir );

	if( !( f->Stat() & FSF_EXISTS ) )
	{
	    delete f;
	    return;
	}

	StrArray *a = f->ScanDir( e );

	PathSys *p = PathSys::Create();

	for( int i = 0; !e->Test() && a && i < a->Count(); i++ )
	{
	    p->SetLocal( StrRef( dir ), *a->Get(i) );
	    f->Set( *p );

	    int stat = f->Stat();

	    if( stat & FSF_DIRECTORY )
	        PurgeDir( f->Name(), e );
	    else
	        f->Unlink( e );
	}

	delete p;
	delete a;

	if( !e->Test() )
	{
	    f->Set( dir );
	    rmdir( f->Name() );
	}
	delete f;
}
