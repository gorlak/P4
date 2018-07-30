/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# define NEED_SLEEP

# include <stdhdrs.h>
# include <pid.h>

# if defined(OS_OS2) || defined(OS_NT)
const char *lclTemp = "t%dt%d.tmp";
const char *gblTemp = ".";
# define HAVE_TEMP
# endif

# ifdef OS_VMS
# ifdef VI_WORKS_WITH_DIR
const char *lclTemp = "t%d%d.tmp";
const char *gblTemp = "sys$scratch:";
# else
const char *lclTemp = "t%d%d.tmp";
const char *gblTemp = "";
# define HAVE_TEMP
# endif
# endif

# ifndef HAVE_TEMP
const char *lclTemp = "tmp.%d.%d";
const char *gblTemp = "/tmp";
# endif

# include <error.h>
# include <strbuf.h>
# include <random.h>
# include <debug.h>
# include <tunable.h>

# include "enviro.h"
# include "pathsys.h"
# include "filesys.h"
# include "datetime.h"
# include "msgsupp.h"

/*
 * FileSys::TempName() - create a temp name in target buffer
 */

void
FileSys::TempName( char *buf )
{
	// Format temp file name

	static int count = 0;

# ifdef OS_OS2
	const int maxTemp = 1000;
# else
	const int maxTemp = p4tunable.Get( P4TUNE_FILESYS_MAXTMP );
# endif

	count = ( count + Random::Integer( 1, 100 ) ) % maxTemp;
	 
	sprintf( buf, lclTemp, Pid().GetID(), count );
}

/*
 * FileSys::MakeLocalTemp() - turn file path into a temp file in same dir
 */

void
FileSys::MakeLocalTemp( char *file )
{
	// Make tempname

	char buf[50];

	PathSys *p = PathSys::Create();
	p->SetCharSet( GetCharSetPriv() );

	int cnt = p4tunable.Get( P4TUNE_FILESYS_MAKETMP );

	do
	{
	    TempName( buf );

	    // Append it to path

	    p->Set( file );
	    p->ToParent();
	    p->SetLocal( *p, StrRef( buf ) );

	    Set( *p );
	} while ( ( Stat() & ( FSF_SYMLINK | FSF_EXISTS ) ) && --cnt > 0 );

	delete p;
}

/*
 * FileSys::MakeGlobalTemp() - create a temp file path in temp dir
 */

void
FileSys::MakeGlobalTemp()
{
	const char *tdir;

	// Use $TEMP or $TMP if given.

	Enviro enviro;
	enviro.SetCharSet( GetCharSetPriv() );

	if( 
# ifdef OS_INTERIX
	    !( tdir = enviro.Get( "TMPDIR" ) ) &&
# endif
	    !( tdir = enviro.Get( "TEMP" ) ) && 
	    !( tdir = enviro.Get( "TMP" ) ) )
		tdir = gblTemp;

	// Make tempname
	char buf[50];

	PathSys *p = PathSys::Create();
	p->SetCharSet( GetCharSetPriv() );

	int cnt = 10;

	do
	{
	    TempName( buf );

	    // Append to global temp dir

	    p->Set( tdir );
	    p->SetLocal( *p, StrRef( buf ) );

	    Set( *p );
	} while ( ( Stat() & ( FSF_SYMLINK | FSF_EXISTS ) ) && --cnt > 0 );

	delete p;
}

// This creates a lock file ment to be very temporary
FileSys *
FileSys::CreateLock( FileSys *f, Error *e )
{
	int t;
	StrBuf nameit;
	DateTime nowtime, locktime;

	FileSys *lockFile = Create( (FileSysType)( FST_BINARY|FST_M_EXCL ) );

	lockFile->SetDeleteOnClose();

	nameit.Set( f->Path() );
	nameit.UAppend( ".lck" );

	lockFile->Set( nameit );

	int lcnt = p4tunable.Get( P4TUNE_FILESYS_LOCKTRY );

	while( --lcnt > 0 )
	{
	    if( ( t = lockFile->StatModTime() ) > 0 )
	    {
		// file exists
		locktime.Set( t );
		nowtime.SetNow();
		if( nowtime.Compare( locktime ) > p4tunable.Get( P4TUNE_FILESYS_LOCKDELAY ) )
		{
		    // lock file old
		    lockFile->Unlink( e );
		    if( e->Test() )
		    {
			lockFile->ClearDeleteOnClose();
			delete lockFile;
			return NULL;
		    }
		}
		else
		{
		    // lock file exists, reasonably new, we should wait
		    sleep( 1 );
		}
	    }
	    else
	    {
		// file does not seem to exist, try create
		lockFile->Open( FOM_WRITE, e );

		if( !e->Test() )
		    return lockFile;

		// if open failed, we try agin
		e->Clear();
	    }
	}

	// too many retries, error
	// set error
	e->Set( MsgSupp::TooManyLockTrys ) << nameit;
	lockFile->ClearDeleteOnClose();
	delete lockFile;
	return NULL;
}
