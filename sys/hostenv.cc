/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * Hostenv.cc - describe user's environment
 */

# define NEED_GETCWD
# define NEED_GETHOSTNAME
# define NEED_GETPWUID

# include <stdhdrs.h>
# include <strbuf.h>
# include "hostenv.h"
# include <i18napi.h>
# include <charcvt.h>
# include <enviro.h>

# ifdef OS_NT
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
# include <ntmangle.h>
# include <wchar.h>
# include <lmcons.h>
# endif

# ifdef OS_VMS
# define CWD_VAR "PATH"
# else
# define CWD_VAR "PWD"
# endif

# if defined( OS_NT ) || defined( OS_OS2 )
# define USER_VAR "USERNAME"
# else
# define USER_VAR "USER"
# endif

int
HostEnv::GetHost( StrBuf &result )
{

	// host - hostname

	result.Clear();
	result.Alloc( 64 );

# ifdef HAVE_GETHOSTNAME
	if( gethostname( result.Text(), result.Length() ) >= 0 )
	{
	    result.SetLength();
	    return 1;
	}
# endif

# ifdef OS_NT 
	unsigned long buflen = result.Length();
 	if( GetComputerName( result.Text(), &buflen ) ) 
	{
	    result.SetLength();
	    return 1;
	}
# endif 

# if defined( OS_NT ) || defined( OS_OS2 )
	char *c;

	if( c = getenv( "COMPUTERNAME" ) )
	{
	    result.Set( c );
	    return 1;
	}
# endif

	return 0;
}

/*
 * GetEnv() - get a value from the environment, using Unicode API or not
 */

# ifdef OS_NT
static void lowerCaseDrive( char *path83 )
{
	// Make sure that the drive letter is lower case.
	if( path83[0] && path83[1] == ':' )
	{
		if( path83[0] >= 'A' && path83[0] <= 'Z' )
			path83[0] = 'a' + ( path83[0] - 'A' );
	}
}
static void
GetCwd( StrBuf *dest, int charset = 0 )
{
	CHAR cwd[_MAX_PATH];
	if( !CharSetApi::isUnicode( (CharSetApi::CharSet)charset ) )
	{
		getcwd( cwd, _MAX_PATH );
		dest->Clear();
		int len = GetLongPathName( cwd, dest->Alloc( _MAX_PATH ), _MAX_PATH );

		if( len > _MAX_PATH )
		{
			dest->Clear();
			len = GetLongPathName( cwd, dest->Alloc( len ), len );
		}

		if( len == 0 )
		{
			dest->Clear();
			dest->Set( cwd );
		}
		else
			dest->SetLength();

		lowerCaseDrive( dest->Text() );
		return;
	}

	WCHAR wcwd[_MAX_PATH];
	if( !_wgetcwd( wcwd, _MAX_PATH ) )
		return;

	WCHAR wlcwd[_MAX_PATH];
	int len = GetLongPathNameW( wcwd, wlcwd, _MAX_PATH );

	WCHAR *wrcwd = wlcwd;

	if( len > _MAX_PATH || len == 0 )
	{
		wrcwd = wcwd;
		len = wcslen( wcwd );
	}

	CharSetCvtUTF168 cvtval;
	const char *retval = cvtval.FastCvt( (const char *)wrcwd, 2 * len );
	if( !retval )
		return;	// should not happen
	dest->Set( retval );
	lowerCaseDrive( dest->Text() );
}
#else
static void
GetCwd( StrBuf *dest, int = 0 )
{
	dest->Clear();
	dest->Alloc( 256 );
	getcwd( dest->Text(), dest->Length() );
	dest->SetLength();
}
#endif

void
HostEnv::GetCwdbyCS( StrBuf &result, int charset )
{
	::GetCwd( &result, charset );
}

int
HostEnv::GetCwd( StrBuf &result, Enviro * enviro )
{
	Enviro *tmpenviro = NULL;

	if( !enviro )
	    enviro = tmpenviro = new Enviro;

	char *c;

	if( c = enviro->Get( CWD_VAR ) )
	{
	    result.Set( c );
	    delete tmpenviro;
	    return 1;
	}

	::GetCwd( &result, enviro->GetCharSet() );

	delete tmpenviro;

	return 1;
}

int
HostEnv::GetUser( StrBuf &result, Enviro * enviro )
{
	// user - user's name

	Enviro * tmpenviro = NULL;

	if( !enviro )
	    enviro = tmpenviro = new Enviro;

	char *c;

	if( c = enviro->Get( USER_VAR ) )
	{
	    result.Set( c );
	    delete tmpenviro;
	    return 1;
	}

# ifdef OS_NT
	if( CharSetApi::isUnicode( (CharSetApi::CharSet)enviro->GetCharSet() ) )
	{
	    WCHAR wuser[UNLEN+1];
	    DWORD wlength = sizeof(wuser) / sizeof(WCHAR);
	    if( GetUserNameW( wuser,  &wlength ) )
	    {
		CharSetCvtUTF168 cvtval;
		const char *retval = 
			cvtval.FastCvt( (const char *)wuser, 2 * wlength - 2 );
		if( retval )
		{
		    result.Set( retval );
		    delete tmpenviro;
		    return 1;
		}
	    }
	}
	else
	{
	    result.Clear();
	    result.Alloc( 128 );
	    DWORD length = result.Length();
	    if( GetUserNameA( result.Text(), &length ) )
	    {
		result.SetLength();
		delete tmpenviro;
		return 1;
	    }
	}
# endif

# ifdef HAVE_GETPWUID
	struct passwd *pwd;
	if( pwd = getpwuid( getuid() ) )
	{
	    result.Set( pwd->pw_name );
	    delete tmpenviro;
	    return 1;
	}
# endif

# ifdef OS_BEOS
	result.Clear();
	result.Alloc( 128 );
	if( getusername( result.Text(), result.Length() ) )
	{
	    result.SetLength();
	    delete tmpenviro;
	    return 1;
	}
# endif /* OS_BEOS */

	delete tmpenviro;

	return 0;
}

int
HostEnv::GetTicketFile( StrBuf &result, Enviro * enviro )
{
	return GetHomeName( StrRef( "p4tickets" ), result, 
	                    enviro, "P4TICKETS" );
}

int
HostEnv::GetTrustFile( StrBuf &result, Enviro * enviro )
{
	return GetHomeName( StrRef( "p4trust" ), result, 
	                    enviro, "P4TRUST" );
}

int
HostEnv::GetAliasesFile( StrBuf &result, Enviro *enviro )
{
	return GetHomeName( StrRef( "p4aliases" ), result,
	                    enviro, "P4ALIASES" );
}

int
HostEnv::GetHomeName( 
	const StrRef &name, 
	StrBuf &result, 
	Enviro *enviro,
	const char *varName )
{

	Enviro * tmpenviro = NULL;

	if( !enviro )
	    tmpenviro = enviro = new Enviro;

	// Set in the environment ?

	const char *setInEnv = enviro->Get( varName );

	if( setInEnv )
	{
	    result.Set( setInEnv );
	    delete tmpenviro;
	    return 1;
	}

	enviro->GetHome( result );

# ifdef OS_NT
# define HAVE_TICKETS

        // On NT, try looking in $USERPROFILE, if no luck stash in the
        // windows directory.

	if( result.Length() )
	{
	    result.Append( "\\" );
	    result.Append( &name );
	    result.Append( ".txt" );
	}

# endif

# ifdef OS_VMS
# define HAVE_TICKETS

	if( result.Length() )
	{
	    result.Append( "/" );
	    result.Append( &name );
	    result.Append( ".txt" );
	}

# endif

# ifndef HAVE_TICKETS

	if( result.Length() )
	{
	    result.Append( "/." );
	    result.Append( &name );
	}

# endif

	delete tmpenviro;

	return( result.Length() ? 1 : 0 );
}

int
HostEnv::GetUid( int &result )
{
# ifdef HAVE_GETPWUID
	struct passwd *pwd;
	if( pwd = getpwuid( getuid() ) )
	{
	    result = pwd->pw_uid;
	    return 1;
	}
# endif

	return 0;
}
