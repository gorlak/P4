/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * ClientEnv.cc - describe user's environment
 */

# include <stdhdrs.h>

# include <strbuf.h>
# include <strdict.h>
# include <strops.h>
# include <error.h>
# include <enviro.h>
# include <ticket.h>
# include <handler.h>
# include <hostenv.h>
# include <i18napi.h>
# include <charcvt.h>
# include <rpc.h>

# include <pathsys.h>

# include "client.h"

# include <ident.h>
extern Ident p4api_ident;

const StrPtr &
Client::GetCharset()
{
	char *c;

	if( charset.Length() )
	{
	    return charset;
	}
	else if( ( c = enviro->Get( "P4CHARSET" ) ) )
	{
	    charset = c;
	}
	else
	{
	    charsetVar.Set( "P4_" );

	    const StrPtr *p = &GetPort();
	    if( strchr( p->Text(), '=' ) )
	    {
		// If the port contains an equals we replace it
		// since environment names can not have an equals
		StrBuf tmp( *p );

		StrOps::Sub( tmp, '=', '@' );
		charsetVar.Append( &tmp );
	    }
	    else
		charsetVar.Append( p );

	    charsetVar.Append( "_CHARSET" );
	    if( ( c = enviro->Get( charsetVar.Text() ) ) )
		charset = c;
	}

	return charset;
}

const StrPtr &
Client::GetClient()
{
	char *c;

	GetClientNoHost();

	// client - client's name

	if( client.Length() )
	    return client;

	// Use host name

	client.Set( GetHost() );

	// Strip .anything from client

	if( c = strchr( client.Text(), '.' ) )
	{
	    client.SetLength( c - client.Text() );
	    client.Terminate();
	}

	return client;
}

const StrPtr &
Client::GetClientNoHost()
{
	char *c;

	// client - client's name

	if( !client.Length() && ( c = enviro->Get( "P4CLIENT" ) ) )
	    client.Set( c );

	return client;
}

const StrPtr &
Client::GetClientPath()
{
	char *c;

	if( clientPath.Length() )
	    return clientPath;
	else if( c = enviro->Get( "P4CLIENTPATH" ) )
	    clientPath = c;
	else if( ServerDVCS() )
	    return GetInitRoot();
	return clientPath;
}

const StrPtr &
Client::GetTempPath()
{
	char *c;

	if( tempPath.Length() )
	    return tempPath;
	else if( c = enviro->Get( "TEMP" ) )
	    tempPath = c;
	else if( c = enviro->Get( "TMP" ) )
	    tempPath = c;
	else {
	    // Unix centric I know.  Windows will have TEMP set.
	    // we no longer support VMS or other platforms
	    tempPath = "/tmp";
	}
	return tempPath;
}

const StrPtr &
Client::GetCwd()
{
	HostEnv h;

	// cwd - current working directory

	if( !cwd.Length() )
	    h.GetCwd( cwd, enviro );

	return cwd;
}

const StrPtr &
Client::GetHost()
{
	char *c;
	StrPtr *s;
	HostEnv h;

	// host - hostname

	if( host.Length() )
	{
	    return host;
	}
	else if( c = enviro->Get( "P4HOST" ) )
	{
	    host.Set( c );
	}
	else if( h.GetHost( host ) )
	{
	    // OK
	}
	else if( s = GetAddress( RAF_NAME ) )
	{
	    host.Set( s );
	}
	else
	{
	    host.Set( "nohost" );
	}

	return host;
}

const StrPtr &
Client::GetLanguage()
{
	char *c;

	if( language.Length() )
	{
	    return language;
	}
	else if( c = enviro->Get( "P4LANGUAGE" ) )
	{
	    language = c;
	}

	return language;
}

const StrPtr &
Client::GetOs()
{
	// os - client's operating system

	if( os.Length() )
	{
	    return os;
	}
	else
	{
	    os.Set( PathSys::GetOS() );
	}

	return os;
}

const StrPtr &
Client::GetPassword()
{
	return GetPassword( 0 );
}

const StrPtr &
Client::GetPassword( const StrPtr *usrName, int forceTFile )
{
	if( !forceTFile && password.Length() && ticketKey == serverID )
	    return password;

	// A 2007.2 server will send the serverID to use as the ticket key.
	// If its not available, check using the old method (use P4PORT).

	const char *c;

	StrBuf u;

	u = usrName ? *usrName : user;
	if( output_charset )
	{
	    // i18n mode - translate user from p4charset to UTF8

	    CharSetCvt *converter = CharSetCvt::FindCvt(
		(CharSetCvt::CharSet)output_charset, CharSetCvt::UTF_8 );
	    if( converter )
	    {
		c = converter->FastCvt( user.Text(), user.Length() );
		if( c )
		    u = c;
		delete converter;
	    }
	}

	// Must downcase the username to find a ticket when connected to
	// a case insensitive server.

	if( protocolNocase )
	    StrOps::Lower( u );

	if( serverID.Length() )
	{
	    Ticket t( &GetTicketFile() );
	    if( ( c = t.GetTicket( serverID, u ) ) != 0 )
	    {
		ticketKey = serverID;
	        password = c;
	    }
	}

	if( !password.Length() )
	{
	    Ticket t( &GetTicketFile() );
	    if( ( c = t.GetTicket( port, u ) ) != 0 )
	    {
		ticketKey = port;
	        password = c;
	    }
	}

	if( !IsIgnorePassword() && ( c = enviro->Get( "P4PASSWD" ) ) )
	{
	    // If server security level is >= 2,  then don't get the
	    // password from the registry.

	    if( protocolSecurity < 2 || !enviro->FromRegistry( "P4PASSWD" ) )
	    {
	        // Store P4PASSWD as a backup (password2) if we already
	        // found a ticket but not if a password was already set.

	        if( password.Length() )
		{
		    if( !password2.Length() )
			password2 = c;
		}
	        else
		{
	            password = c;
		}
	    }
	}

	return password;
}

const StrPtr &
Client::GetPassword2()
{
	// Usually password2 is empty,  unless there is both a ticket
	// and P4PASSWD is set,  in that case we send both crypto'd to
	// the server.

	return password2;
}

const StrPtr &
Client::GetPort()
{
	char *c;

	if( port.Length() )
	{
	    return port;
	}
	else if( c = enviro->Get( "P4PORT" ) )
	{
	    port.Set( c );
	}
	else 
	{
	    port.Set( "perforce:1666" );
	}

	return port;
}

const StrPtr &
Client::GetProg()
{
	// If program name has not been set yet, use p4 api
	// ident as program name.
	if( !programName.Length() )
	    SetProg( p4api_ident.GetIdent() );

	return programName;
}

const StrPtr &
Client::GetUser()
{
	char *c;
	HostEnv h;

	// user - user's name

	if( user.Length() )
	{
	    // OK.
	}
	else if( c = enviro->Get( "P4USER" ) )
	{
	    user.Set( c );
	}
	else if( h.GetUser( user, enviro ) )
	{
	    // OK
	}
	else
	{
	    user.Set( "nouser" );
	}
	
	// Translate spaces in user name to blanks.
	
	while( c = strchr( user.Text(), ' ' ) )
		*c = '_';

	return user;
}

const StrPtr &
Client::GetTicketFile()
{
	char *c;
	HostEnv h;

	// tickefile - where users login tickets are stashed

	if( ticketfile.Length() )
	{
	    // OK.
	}
	else if( c = enviro->Get( "P4TICKETS" ) )
	{
	    ticketfile.Set( c );
	}
	else 
	{
	    h.GetTicketFile( ticketfile, enviro );
	}
	
	return ticketfile;
}

const StrPtr &
Client::GetTrustFile()
{
	char *c;
	HostEnv h;

	// trustfile - where trusted server fingerprints are kept

	if( trustfile.Length() )
	{
	    // OK.
	}
	else if( c = enviro->Get( "P4TRUST" ) )
	{
	    trustfile.Set( c );
	}
	else 
	{
	    h.GetTrustFile( trustfile, enviro );
	}
	
	return trustfile;
}

const StrPtr &
Client::GetLoginSSO()
{
	char *c;

	if( loginSSO.Length() )
	{
	    // OK.
	}
	else if ( c = enviro->Get( "P4LOGINSSO" ) )
	{
	    loginSSO.Set( c );
	}
	else
	{
	    loginSSO.Set( "unset" );
	}

	return loginSSO;
}

const StrPtr &
Client::GetSyncTrigger()
{
	char *c;

	if( syncTrigger.Length() )
	{
	    // OK.
	}
	else if ( c = enviro->Get( "P4ZEROSYNC" ) )
	{
	    syncTrigger.Set( c );
	}
	else
	{
	    syncTrigger.Set( "unset" );
	}

	return syncTrigger;
}

const StrPtr &
Client::GetIgnoreFile()
{
	char *c;

	if( ignorefile.Length() )
	{
	    // OK.
	}
	else if ( c = enviro->Get( "P4IGNORE" ) )
	{
	    ignorefile.Set( c );
	}
	else
	{
	    ignorefile.Set( "unset" );
	}

	return ignorefile;
}

const StrPtr &
Client::GetConfig()
{
	return enviro->GetConfig();
}

const StrArray *
Client::GetConfigs()
{
	return enviro->GetConfigs();
}

const StrPtr &
Client::GetInitRoot()
{
	char *c;

	if( !initRoot.Length() && ( c = enviro->Get( "P4INITROOT" ) ) )
	    initRoot.Set( c );
	
	return initRoot;
}

const StrPtr &
Client::GetVersion()
{
	return programVersion;
}

/*
 * Client::SetCwd() - set cwd and reload P4CONFIG
 */

void
Client::SetCwd( const StrPtr *c )
{
	// Set as all Set()'s do

	cwd.Set( c );
	ownCwd = 0;

	// And now reload P4CONFIG

	enviro->Config( *c );
}

void
Client::SetCwd( const char *c )
{
	// Set as all Set()'s do

	cwd.Set( c );
	ownCwd = 0;

	// And now reload P4CONFIG

	enviro->Config( cwd );
}

/*
 * Client::DefineClient()
 * Client::DefineCharset()
 * Client::DefineHost()
 * Client::DefineLanguage()
 * Client::DefinePassword()
 * Client::DefinePort()
 * Client::DefineUser() -- set in registry
 */

void
Client::DefineCharset( const char *c, Error *e )
{
	enviro->Set( "P4CHARSET", c, e );
	SetCharset( c );
}

void
Client::DefineClient( const char *c, Error *e )
{
	enviro->Set( "P4CLIENT", c, e );
	SetClient( c );
}

void
Client::DefineHost( const char *c, Error *e )
{
	enviro->Set( "P4HOST", c, e );
	SetHost( c );
}

void
Client::DefineIgnoreFile( const char *c, Error *e )
{
	enviro->Set( "P4IGNORE", c, e );
	SetIgnoreFile( c );
}

void
Client::DefineLanguage( const char *c, Error *e )
{
	enviro->Set( "P4LANGUAGE", c, e );
	SetLanguage( c );
}

void
Client::DefinePassword( const char *c, Error *e )
{
	enviro->Set( "P4PASSWD", c, e );
	SetPassword( c );
}

void
Client::DefinePort( const char *c, Error *e )
{
	enviro->Set( "P4PORT", c, e );
	SetPort( c );
}

void
Client::DefineUser( const char *c, Error *e )
{
	enviro->Set( "P4USER", c, e );
	SetUser( c );
}

