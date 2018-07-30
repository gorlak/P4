/*
 * Copyright 1995, 2015 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * serverhelperapi.cc -- a ServerHelper wrapper that a ClientUser.
 *
 * This class is intened for use from derived APIs, and will be exposed in the
 * P4API as serverhelperapi.h
 */

# include "serverhelperapi.h"

# include <rpc.h>

# include <msgclient.h>

# include "client.h"
# include "serverhelper.h"

ServerHelperApi::ServerHelperApi( Error *e )
{
	server = new ServerHelper( e );
}

ServerHelperApi::~ServerHelperApi()
{
	delete server;
}

// Wrappers around the DVCS stuff

int
ServerHelperApi::Exists( ClientUser *ui, Error *e )
{
	return server->Exists( ui, e );
}

int
ServerHelperApi::CopyConfiguration( ServerHelperApi *remote, ClientUser *ui,
    Error *e )
{
	return server->Discover( remote ? &remote->GetPort() : 0, ui, e );
}

int
ServerHelperApi::PrepareToCloneRemote( ServerHelperApi *remoteServer,
    const char *remote, ClientUser *ui, Error *e )
{
	if( remote )
	{
	    StrRef r( remote );
	    return PrepareToCloneRemote( remoteServer, &r, ui, e );
	}
	else
	    return PrepareToCloneRemote( remoteServer, (StrPtr *) 0, ui, e );

}

int
ServerHelperApi::PrepareToCloneRemote( ServerHelperApi *remoteServer,
    const StrPtr *remote, ClientUser *ui, Error *e )
{
	const StrPtr *p4port = remoteServer ? &remoteServer->GetPort() : 0;
	return server->LoadRemote( p4port, remote, ui, e );
}

int
ServerHelperApi::PrepareToCloneFilepath( ServerHelperApi *remote,
    const char *filePath, ClientUser *ui, Error *e )
{
	if( filePath )
	{
	    StrRef f( filePath );
	    return PrepareToCloneFilepath( remote, &f, ui, e );
	}
	else
	    return PrepareToCloneFilepath( remote, (StrPtr *) 0, ui, e );
}

int
ServerHelperApi::PrepareToCloneFilepath( ServerHelperApi *remoteServer,
    const StrPtr *filePath, ClientUser *ui, Error *e )
{
	const StrPtr *p4port = remoteServer ? &remoteServer->GetPort() : 0;
	return server->MakeRemote( p4port, filePath, ui, e );
}

int
ServerHelperApi::InitLocalServer( ClientUser *ui, Error *e )
{
	return server->InitLocalServer( ui, e );
};

int
ServerHelperApi::CloneFromRemote(
	int depth,
	int noArchivesFlag,
	const StrPtr *debugFlag,
	ClientUser *ui,
	Error *e )
{
	return server->FirstFetch( depth, noArchivesFlag, debugFlag, ui, e );
}

int
ServerHelperApi::CloneFromRemote(
	int depth,
	int noArchives,
	const char *debug,
	ClientUser *ui,
	Error *e )
{
	if( debug )
	{
	    StrRef d( debug );
	    return CloneFromRemote( depth, noArchives, &d, ui, e );
	}
	else
	    return CloneFromRemote( depth, noArchives, (StrPtr *) 0, ui, e );
}


// Server API behavior modifiers

void
ServerHelperApi::SetDebug( StrPtr *v )
{
	server->DoDebug( v );
}

void
ServerHelperApi::SetQuiet()
{
	server->SetQuiet();

}
int
ServerHelperApi::GetQuiet()
{
	return server->GetQuiet();
}

void
ServerHelperApi::SetDefaultStream( const StrPtr *s, Error *e )
{
	server->SetDefaultStream( s, e );
}

void
ServerHelperApi::SetApplication( const StrPtr *a )
{
	server->SetApplication( a );
}

void
ServerHelperApi::SetDefaultStream( const char *s, Error *e )
{
	StrRef stream( s );
	server->SetDefaultStream( &stream, e );
}

StrPtr
ServerHelperApi::GetCaseFlag()
{
	return server->GetCaseFlag();
}

void
ServerHelperApi::SetCaseFlag( const StrPtr *c, Error *e )
{
	server->SetCaseFlag( c, e );
}

void
ServerHelperApi::SetCaseFlag( const char *c, Error *e )
{
	StrRef cflag( c );
	server->SetCaseFlag( &cflag, e );
}

int
ServerHelperApi::GetUnicode()
{
	return server->Unicode();
}

void
ServerHelperApi::SetUnicode( int u )
{
	server->SetUnicode( u );
}

// Trivial stuff

int
ServerHelperApi::SetDvcsDir( const char *dir, Error *e )
{
	if( dir )
	{
	    StrRef d( dir );
	    return SetDvcsDir( &d, e );
	}
	else
	    return SetDvcsDir( (StrPtr *) 0, e );
}

void
ServerHelperApi::SetServerExecutable( const char *c )
{
	server->SetServerExecutable( c );
}

int
ServerHelperApi::SetPort( const char *port, Error *e )
{
	if( port )
	{
	    StrRef p( port );
	    return SetPort( &p, e );
	}
	else
	    return SetPort( (StrPtr *) 0, e );
}

void
ServerHelperApi::SetUser( const char *c )
{
	server->SetUser( c );
}

void
ServerHelperApi::SetClient( const char *c )
{
	server->SetClient( c );
}

void
ServerHelperApi::SetPassword( const char *p )
{
	server->SetPassword( p );
}

void
ServerHelperApi::SetProg( const char *c )
{
	server->SetProg( c );
}

void
ServerHelperApi::SetVersion( const char *c )
{
	server->SetVersion( c );
}

void
ServerHelperApi::SetCharset( const char *c )
{
	server->SetCharset( c );
}

int
ServerHelperApi::SetDvcsDir( const StrPtr *c, Error *e )
{
	if( port.Length() )
	{
	    e->Set( MsgClient::RemoteLocalMismatch );
	    return 0;
	}

	if( c )
	    server->SetDvcsDir( c );
	else
	    server->SetDvcsDir( "" );

	return 1;
}

void
ServerHelperApi::SetServerExecutable( const StrPtr *c )
{
	server->SetServerExecutable( c );
}

int
ServerHelperApi::SetPort( const StrPtr *c, Error *e )
{
	if( server->GetDvcsDir().Length() )
	{
	    e->Set( MsgClient::LocalRemoteMismatch );
	    return 0;
	}

	if( c )
	    port.Set( c );
	else
	    port.Clear();

	return 1;
}

void
ServerHelperApi::SetUser( const StrPtr *c )
{
	server->SetUser( c );
}

void
ServerHelperApi::SetClient( const StrPtr *c )
{
	server->SetClient( c );
}

void
ServerHelperApi::SetPassword( const StrPtr *p )
{
	server->SetPassword( p );
}

void
ServerHelperApi::SetProg( const StrPtr *c )
{
	server->SetProg( c );
}

void
ServerHelperApi::SetVersion( const StrPtr *c )
{
	server->SetVersion( c );
}

void
ServerHelperApi::SetCharset( const StrPtr *c )
{
	server->SetCharset( c );
}

const StrPtr &
ServerHelperApi::GetDvcsDir()
{
	return server->GetDvcsDir();
}

const StrPtr &
ServerHelperApi::GetServerExecutable()
{
	return server->GetServerExecutable();
}

const StrPtr &
ServerHelperApi::GetPort()
{
	return port;
}

const StrPtr &
ServerHelperApi::GetUser()
{
	return server->GetUser();
}

const StrPtr &
ServerHelperApi::GetClient()
{
	return server->GetClient();
}

const StrPtr &
ServerHelperApi::GetPassword()
{
	return server->GetPassword();
}

const StrPtr &
ServerHelperApi::GetProg()
{
	return server->GetProg();
}

const StrPtr &
ServerHelperApi::GetVersion()
{
	return server->GetVersion();
}

void
ServerHelperApi::SetProtocol( const char *p, const char *v )
{
	protocol.SetVar( p, v );
}
void
ServerHelperApi::SetProtocolV( const char *p )
{
	protocol.SetVarV( p );
}
void
ServerHelperApi::ClearProtocol()
{
	protocol.Clear();
}

void
ServerHelperApi::SetTrans( int output, int content, int fnames, int dialog )
{
	server->SetTrans( output, content, fnames, dialog );
}

// Helpful client factory

ClientApi *
ServerHelperApi::GetClient( Error *e )
{
	ClientUser cuser;

	if( !port.Length() &&
	    ( !server->GetDvcsDir().Length() || !server->Exists( 0, e ) ) )
	    e->Set( MsgClient::NoDvcsServer );

	if( e->Test() )
	    return 0;

	ClientApi *client = new ClientApi;

	if( port.Length() )
	    client->SetPort( &port );
	else if( server->GetDvcsDir().Length() && server->GetDvcsDir() != "." )
	    client->SetCwd( &server->GetDvcsDir() );

	// Copy the other variables, if they're set
	if( server->GetPassword().Length() )
	    client->SetPassword( &server->GetPassword() );
	if( server->GetUser().Length() )
	    client->SetUser( &server->GetUser() );
	if( server->GetClient().Length() )
	    client->SetClient( &server->GetClient() );
	if( server->GetCharset().Length() )
	    client->SetCharset( &server->GetCharset() );

	int output, content, fnames, dialog;
	if( server->GetTrans( output, content, fnames, dialog ) )
	    client->SetTrans( output, content, fnames, dialog );

	StrRef var, val;
	int i = 0;
	while( protocol.GetVar( i++, var, val ) )
	    client->SetProtocol( var.Text(), val.Text() );
	
	StrPtr prog = server->GetProg();
	StrPtr version = server->GetVersion();
	client->SetProg( &prog );
	client->SetVersion( &version );

	client->Init( e );

	return client;
}
