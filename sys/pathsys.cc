/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>
# include <error.h>
# include <errornum.h>
# include <errorlog.h>
# include <msgsupp.h>
# include <strbuf.h>
# include <strops.h>

# include "pathsys.h"
# include "pathunix.h"
# include "pathnt.h"
# include "pathvms.h"
# include "pathmac.h"

enum PathSysOS { 
	PATH_UNIX, 	// /foo/bar/ola
	PATH_VMS, 	// dev:[dir]file
	PATH_NT, 	// d:\foo\bar\ola
	PATH_MAC 	// vol:dir:dir:file
};	

# if defined(OS_OS2) || defined(OS_NT)
# define PATH_LOCAL PATH_NT
# endif

# ifdef OS_VMS
# define PATH_LOCAL PATH_VMS
# endif

# ifdef OS_MAC
# define PATH_LOCAL PATH_MAC
# endif

# ifndef PATH_LOCAL
# define PATH_LOCAL PATH_UNIX
# endif

static const char *const osNames[] = {
	"UNIX",
	"vms",
	"NT",
	"Mac",
	0,
} ;

// prototypes for local functions
PathSys * NewPathSys( PathSysOS flag );

PathSys::~PathSys() {}

void
PathSys::SetCharSet( int ) { }

/*
 * GetPathSysOS()
 */

const char *
PathSys::GetOS()
{
	return osNames[ PATH_LOCAL ];
}

/*
 * PathSys::Create()
 */

PathSys *
PathSys::Create( int flag )
{
	switch( flag )
	{
	case PATH_UNIX:
	    return new PathUNIX;

	case PATH_NT:
	    return new PathNT;

	case PATH_VMS:
	    return new PathVMS;

	case PATH_MAC:
	    return new PathMAC;

	default:
	    {

	    // Server used to exit here. Now it doesn't since this situation
	    // should not bring down the server. Since this function is now
	    // private, only an internal coding error would now bring us here.

	    return 0;
	    }
	}
}

PathSys *
PathSys::Create()
{
	return Create( (int)PATH_LOCAL );
}

PathSys *
PathSys::Create( const StrPtr &os, Error *e )
{
	for( int i = 0; osNames[i]; i++ )
	    if( os == osNames[i] )
		return Create( i );

	e->Set( MsgSupp::BadOS ) << os;

	return 0;
}

void
PathSys::Expand()
{
	// most files will not require expanding, optimize by doing
	// a quick check and bail.

	if( !strchr( this->Text(), '%' ) )
	    return;

	// expand %x character back to '@#*%'

	StrBuf v;
	v.Set( *this );
	const StrPtr *p = &v;

	StrOps::StrToWild( *p, *this );
}
