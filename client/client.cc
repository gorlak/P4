/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include <debug.h>
# include <strbuf.h>
# include <strdict.h>
# include <strtable.h>
# include <error.h>
# include <i18napi.h>
# include <charcvt.h>
# include <transdict.h>
# include <options.h>
# include <handler.h>
# include <rpc.h>
# include <ident.h>
# include <enviro.h>
# include <ignore.h>
# include <filesys.h>

# include <msgclient.h>
# include <msgserver.h>
# include <msgrpc.h>
# include <msgsupp.h>
# include <p4tags.h>
# include <netportparser.h>

# include "clientuser.h"
# include "clientusernull.h"
# include "clientservice.h"
# include "clientmerge.h"
# include "client.h"

void clientTrust( Client *, Error * );

Ident p4api_ident = {
	        IdentMagic "P4API" "/" ID_OS "/" ID_REL "/" ID_PATCH,
		         ID_Y "/" ID_M "/" ID_D
};

Client::Client( Enviro *e ) : Rpc( &service )
{
	// Use the builtin ClientMerger until SetMerger is called.

	fromTransDialog = toTransDialog = NULL;
	translated = this;
	transfname = this;
	errors = 0;
	fatals = 0;
	is_unicode = 0;
	unknownUnicode = 1;
	content_charset = 0;
	output_charset = 0;
	transErr.Clear();
	ignore = new Ignore;
	lowerTag = upperTag = 0;
	authenticated = 0;
	ignoreList = 0;
	pubKeyChecked = 0;
	hostprotoset = 0;
	syncTime = 0;
	ownCwd = 1;
	fstatPartial = 0;
	extraVars = 0;

	protocolXfiles = -1;
	protocolNocase = 0;
	protocolSecurity = 0;
	protocolUnicode = 0;

	if( e )
	{
	    enviro = e;
	    ownEnviro = 0;
	}
	else
	{
	    enviro = new Enviro;
	    ownEnviro = 1;
	}

	/*
	 * If P4CONFIG is set, we'll need to load the environment
	 * from the .p4 file in the directory path.
	 */

	enviro->Config( GetCwd() );

	// Our standard implementation.
	// See msgs/p4tagl.cc for l_client setting.

	service.Dispatcher( clientDispatch );

	service.SetProtocol( P4Tag::v_cmpfile ); // has clientCompareFile #1737
	service.SetProtocol( P4Tag::v_client, P4Tag::l_client );

	buildInfo = p4api_ident.GetIdent();
}

Client::~Client()
{
	CleanupTrans();
	if( ownEnviro )
	    delete enviro;
	delete fstatPartial;
	delete ignore;
	delete extraVars;
}

void
Client::Init( Error *e )
{
	// Set up address and connect.
	errors = 0;

	// re-add host and port in protocol message
	hostprotoset = 0;

	// unicode setup if possible
	if( unknownUnicode )
	    SetupUnicode( e );

	if( GetEVar( P4Tag::v_ipaddr ) && GetEVar( P4Tag::v_svrname ) )
	    SetProtocol( P4Tag::v_ipaddr, GetEVar( P4Tag::v_ipaddr )->Text() );

	if( !e->Test() )
	    service.SetEndpoint( GetPort().Text(), e );

	if( !e->Test() )
	    Connect( e );

	if( !e->Test() )
	{
	    DoHandshake( e );	// no-op if not ssl

	    if( !e->Test() && unknownUnicode )
	    {
		ClientUserNULL cnull( e );
		
		// discover unicode server status

		// if program name has not been set yet, use p4 api
		// ident as program name
		if( !programName.Length() )
		    SetVar( P4Tag::v_prog, p4api_ident.GetIdent() );

		Run( "discover", &cnull );

		// bad command is expected when connecting to
		// servers before 2014.2
		if( e->CheckId( MsgServer::BadCommand ) )
		{
		    e->Clear();
		    errors = 0;
		}

		// on trust errors, ignore them, and ignore the
		// unicode detection result
		if( e->CheckId( MsgRpc::HostKeyMismatch ) ||
		    e->CheckId( MsgRpc::HostKeyUnknown ) )
		{
		    e->Clear();
		    errors = 0;
		}
		else
		{
		if( !e->Test() )
		    LearnUnicode( e );
		}
		if( e->Test() )
		    (void) Final( e );
	    }

	    // don't bother testing for error since caller will handle

	    return;
	}

	e->Set( MsgClient::Connect );
}

void
Client::Run( const char *func, ClientUser *u )
{
	// Run the command async, and then wait.

	RunTag( func, u );

	WaitTag();
}

void
Client::RunTag( const char *func, ClientUser *u )
{
	Error e;

	// for assembla... job067346 - late protocol set
	// we set this late so that an application can SetHost
	// after creating the Client object and init.
	if( !hostprotoset )
	{
	    hostprotoset = 1;
	    if( GetInitRoot().Length() == 0 )
		SetProtocolDynamic( P4Tag::v_host, GetHost() );
	    SetProtocolDynamic( P4Tag::v_port, GetPort() );
	}

	// Warning: WaitTag() calls Dispatch() which may call Invoke().

	// Fill this tag slot
	// Below we garantee it's empty.

	tags[ upperTag ] = u;

	// Cheesy access to RPC vars, a la OutputStat
	// Equally cheesy access to environment

	if( u )
	{
	    u->varList = this;
	    u->enviro = enviro;
	    if( output_charset )
		u->SetOutputCharset( output_charset );
	}

	if( func && *func == 't' && !strcmp( func, "trust" ) )
	{
	    Loopback( &e );

	    clientTrust( this, &e );

	    if( e.Test() && u )
	        u->Message( &e );

	    return;
	}

	if( !pubKeyChecked )
	{
	    CheckKnownHost( &e, GetTrustFile() );
	    if( e.Test() )
	    {
		if( u )
		{
		    e << "p4 trust";
		    u->Message( &e );
		}
		SetError();
		Clear();
		return;
	    }
	    pubKeyChecked = 1;
	}

	if( programName.Length() )
	    SetVar( P4Tag::v_prog, programName );

	// Formulate up function name.
	// Set user/client/os/cwd
	// Invoke client's request.

	StrBuf s;
	s << "user-" << ( func ? func : "help" );

	GetEnv();
	Invoke( s.Text() );

	// Advance upper tag, and ensure the new slot is empty.

	int nextTag = ( upperTag + 1 ) % ClientTags;

	if( nextTag == lowerTag )
	    WaitTag( tags[ lowerTag ] );

	upperTag = nextTag;

	// Until successful dispatch (after init or setting user/passwd) we 
	// process one command at a time, so that they crypto goes through.

	if( !authenticated )
	    WaitTag();
}

void
Client::WaitTag( ClientUser *u )
{
	// While any RunTag() requests are outstanding, Dispatch().
	// Dispatch() returns exactly once for each Invoke().

	while( lowerTag != upperTag )
	{
	    Dispatch();

	    authenticated = 1;

	    // lowerTag is done; signal that
	    // and bump it.  If that was the
	    // tag we were waiting for, bail.

	    ClientUser *ui = tags[ lowerTag ];

	    if( Dropped() && !IoError()->CheckId( MsgRpc::Break ) )
		ui->Message( IoError() );

	    ui->Finished();

	    lowerTag = ( lowerTag + 1 ) % ClientTags;

	    if( u == ui )
		break;
	}
}

int
Client::Final( Error *e )
{
	// Dispatch returns when the other end is waiting for another
	// request.  We tell it to go away with ReleaseFinal.
	// Then we disconnect.

	ReleaseFinal();
	Disconnect();
	
	// Propagate any IO errors

	if( !e->Test() )
	    *e = *IoError();

	// Return non-zero if any errors have been detected.
	// Note that the server still sends some errors back on
	// stdout, which we don't detect.

	return e->Test() || GetErrors();
}

void
Client::GetEnv()
{
	/*
	 * Load up into RPC variables:
	 *
	 *	client - this client's name
	 *	cwd - the current working directory
	 *	host - this client's host name (for host locking)
	 *	language - preferred language for error messages
	 *	os - the name of the OS (for calculating paths)
	 *	user - the user's name
	 */

	const StrPtr &lang = GetLanguage();
	const StrPtr &initroot = GetInitRoot();

	translated->SetVar( P4Tag::v_client, GetClient() );
	transfname->SetVar( P4Tag::v_cwd, GetCwd() );
	if( transErr.Test() && translated != transfname )
	    translated->SetVar( P4Tag::v_cwd, GetCwd() );
	if( initroot.Length() )
	{
	    transfname->SetVar( P4Tag::v_initroot, initroot );
	    if( transErr.Test() && translated != transfname )
	        translated->SetVar( P4Tag::v_initroot, initroot );
	}
	else
	    SetVar( P4Tag::v_host, GetHost() );
	if( lang.Length() ) translated->SetVar( P4Tag::v_language, lang );
	SetVar( P4Tag::v_os, GetOs() );
	translated->SetVar( P4Tag::v_user, GetUser() );

	/*
	 *	unicode - set if all messages are in unicode
	 */

	if( is_unicode )
        {
            SetVar( P4Tag::v_unicode );
            SetVar( P4Tag::v_charset, content_charset );
        }
        else // no charset was defined
        {
            int cs = GuessCharset();
            if (cs != 0)
                SetVar( P4Tag::v_charset, cs );
        }

	SetVar( P4Tag::v_clientCase, StrBuf::CaseUsage() );

	int i = GetUi()->ProgressIndicator();
	if( i )
	    SetVar( P4Tag::v_progress, i );
}

void
Client::Confirm( const StrPtr *confirm )
{
	// pre 99.1 servers need GetEnv(), too, because they
	// reestablished DmCaller context each time. 

	if( protocolServer < 6 )
	    GetEnv();

	CopyVars();

	Invoke( confirm->Text() );
}

void
Client::NewHandler()
{
	if (translated != this)
	{
		((TransDict *)translated)->Clear();
	}
	if (transfname != this && transfname != translated)
	{
		((TransDict *)transfname)->Clear();
	}
}

void
Client::SetArgv( int ac, char * const * av)
{
	if (translated != this)
		translated->SetArgv(ac, av);
	else
		Rpc::SetArgv(ac, av);
}

void
Client::VSetVar( const StrPtr &var, const StrPtr &val )
{
	if (translated != this)
		translated->RemoveVar(var.Text());
	// careful about the order here
	Rpc::VSetVar(var, val);
}

void
Client::SetProg( const char *prog )
{
	programName.Set( prog );
}

void
Client::SetProg( const StrPtr *prog )
{
	programName.Set( prog );
}

void
Client::SetVersion( const char *version )
{
	SetVar( P4Tag::v_version, version );
}

void
Client::SetVersion( const StrPtr *version )
{
	SetVar( P4Tag::v_version, version );
}

StrPtr *
Client::GetProtocol( const StrPtr &var )
{
	// NB: result only valid until next GetProtocol call.

	if( var == P4Tag::v_server2 || var == P4Tag::v_server )
	    protocolBuf.Set( protocolServer );
	else if( var == P4Tag::v_nocase && protocolNocase )
	    protocolBuf.Set( protocolNocase );
	else if( var == P4Tag::v_security )
	    protocolBuf.Set( protocolSecurity );
	else if( var == P4Tag::v_unicode )
	    protocolBuf.Set( protocolUnicode );
	else return 0;

	return &protocolBuf;
}

void
Client::SetupUnicode( Error *e )
{
	const char *charsetVal = GetCharset().Text();

	if( *charsetVal )
	    LateUnicodeSetup( charsetVal, e );
}

void
Client::LearnUnicode( Error *e )
{
	const char *value = "none";

	if( protocolUnicode )
	    value = "auto";

	SetCharset( value );

	if( charsetVar.Length() )
	    enviro->Set( charsetVar.Text(), value, e );

	// ignore any errors trying to save the charset
	e->Clear();
	errors = 0;

	LateUnicodeSetup( value, e );
}

void
Client::LateUnicodeSetup( const char *value, Error *e )
{
	unknownUnicode = 0;

	int cs = CharSetApi::Lookup( value );

	if( cs >= 0 )
	    SetTrans( cs );
	else if( e )
	    e->Set( MsgClient::UnknownCharset ) << value;
}

void
Client::SetEnviroFile( const char *c )
{
	enviro->SetEnviroFile( c );
	enviro->Reload();
}

const StrPtr *
Client::GetEnviroFile()
{
	return enviro->GetEnviroFile();
}

void
Client::FstatPartialAppend( StrDict *part )
{
	if( !fstatPartial )
	    fstatPartial = new StrBufDict;

	StrRef var, val;

	for( int i = 0; part->GetVar( i, var, val ); i++ )
	    fstatPartial->SetVar( var, val );
}

void
Client::FstatPartialClear()
{
	delete fstatPartial;
	fstatPartial = 0;
}

StrPtr *
Client::GetEVar( const char *k )
{
	StrRef key( k );
	return GetEVar( &key );
}

StrPtr *
Client::GetEVar( const StrPtr *k )
{
	if( !extraVars )
	    return NULL;

	return extraVars->GetVar( *k );
}

void
Client::SetEVar( const StrPtr *k, const StrPtr *v )
{
	if( !extraVars )
	    extraVars = new StrBufDict;

	extraVars->SetVar( *k, *v );
}
