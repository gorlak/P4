/*
 * Copyright 1995, 2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * serverhelper.cc - The logic for creating local Perforce Servers
 */

# define NEED_CHDIR
# define NEED_TYPES
# define NEED_STAT
# define NEED_FLOCK

# include <stdhdrs.h>

# include <strbuf.h>
# include <strdict.h>
# include <strtable.h>
# include <strarray.h>
# include <error.h>
# include <rpc.h>
# include <datetime.h>
# include <strops.h>

# include <pathsys.h>
# include <filesys.h>
# include <fdutil.h>

# include <enviro.h>
# include <hostenv.h>
# include <ignore.h>
# include <i18napi.h>
# include <charcvt.h>
# include <charset.h>
# include <handler.h>
# include <runcmd.h>

# include <msgclient.h>
# include <msgsupp.h>
# include <p4tags.h>

# include "client.h"
# include "clientuser.h"

# include "serverhelper.h"


static void LockCheck( Error * );

static int
Translate( CharSetCvt *cvt, int charset, StrPtr *in, StrBuf &out, Error *e )
{
	int translen;
	const char *transbuf;

	cvt->ResetErr();
	transbuf = cvt->FastCvt(in->Text(), in->Length(), &translen);
	if( transbuf )
	{
	    out.Set( transbuf, translen );
	    out.Terminate();
	}

	int err = cvt->LastErr();

	if( err )
	{
	    e->Set( MsgSupp::ConvertFailed ) << in
	        << CharSetApi::Name( ( CharSetCvt::CharSet )charset )
	        << CharSetApi::Name( CharSetCvt::UTF_8 );
	    return 0;
	}

	return 1;
}

/*
 * The ServerHelper class
 */
ServerHelper::ServerHelper( Error *e )
{
	needLogin = 0;
	fetchAllowed = -1;
	quiet = 0;
	state = 0;
	maxCommitChange = 0;
	unicode = -1;
	security = -1;

	slaveUi = 0;

	defaultStreamChanged = 0;
	defaultStream.Set( "//stream/main" );

	config.Set( INIT_CONFIG );
	ignore.Set( INIT_IGNORE );
	serverExe.Set( INIT_P4DEXE );

	charset.Clear();
	hasTrans = 0;
	outputTrans = 0;
	contentTrans = -2;
	fnamesTrans = -2;
	dialogTrans = -2;

	version.Clear();
	prog.Set( "p4api" );
	version << ID_REL "/" << ID_OS << "/" << ID_PATCH;

	// Load P4CONFIG, or set it if it's not already set
	Enviro enviro;
	const char *s;
	if( ( s = enviro.Get( "P4CONFIG" ) ) )
	    config.Set( s );
	else
	    enviro.Set( "P4CONFIG", config.Text(), e );

	HostEnv h;
	h.GetCwd( pwd, &enviro );
}

void
ServerHelper::SetTrans( int output, int content, int fnames, int dialog )
{
	hasTrans = 1;
	outputTrans = output;
	contentTrans = content;
	fnamesTrans = fnames;
	dialogTrans = dialog;
}

int
ServerHelper::GetTrans( int &output, int &content, int &fnames, int &dialog )
{
	if( !hasTrans )
	    return 0;

	output = outputTrans;
	content = contentTrans;
	fnames = fnamesTrans;
	dialog = dialogTrans;
	return 1;
}

/*
 * Checks to see if a DVCS server exists in a specified directory.
 * This step moves us into that directory too!
 */
int
ServerHelper::Exists( ClientUser *ui, Error *e )
{
	Enviro env;
	const char *s;

	Ignore ign;
	StrArray ignArr;
	
	// If dir hasn't been set, then we're working here

	if( !dir.Length() )
	    dir = pwd;
	
	PathSys *curdir = PathSys::Create();
	FileSys *fsys = FileSys::Create( FST_TEXT );

	curdir->SetLocal( pwd, dir );
	fsys->Set( dir );

	// If the directory doesn't exist, create it now

	if( !( fsys->Stat() & FSF_EXISTS ) )
	{
	    curdir->SetLocal( *curdir, StrRef( "file" ) );
	    fsys->MkDir( *curdir, e );
	    if( e->Test() )
	        goto finish;

	    curdir->ToParent();
	}
	
	if( chdir( curdir->Text() ) < 0 )
	    e->Set( MsgClient::ChdirFail ) << curdir;

	if( e->Test() )
	    goto finish;

	
	// Move the working directory to match
	env.Update( "PWD", curdir->Text() );
	env.Config( *curdir );
	dir.Set( curdir );

	// Check to see if we're somewhere under a DVCS environment
	// or if a .p4root directory exists here.

	
	// Get P4CHARSET and P4IGNORE whilst we're here
	if( ( s = env.Get( "P4CHARSET" ) ) )
	    unicode = StrPtr::CCompare( s, "none" );
	if( ( s = env.Get( "P4IGNORE" ) ) )
	    ignore.Set( s );

	// Make sure that if there are multiple P4IGNORE files specified, we
	// write the correct one.
	if( ign.GetIgnoreFiles( ignore, 0, 1, ignArr ) )
	    ignoreFile = *ignArr.Get( 0 );
	else
	{
	    ignore << ";" << INIT_IGNORE;
	    ignoreFile = INIT_IGNORE;
	}

	fsys->Set( INIT_ROOT );
	if( ( s = env.Get( "P4INITROOT" ) ) || ( fsys->Stat() & FSF_EXISTS  ) )
	{
	    if( !quiet && ui )
	    {
	        Error e1;
	        e1.Set( MsgClient::InitRootExists )
	                << ( s ? s : fsys->Path()->Text() );

	        ui->Message( &e1 );
	    }

	    delete curdir;
	    delete fsys;
	    return 1;
	}

	// Common failure/no-server cleanup
finish:
	delete curdir;
	delete fsys;

	if( !e->Test() )
	{
	    LockCheck( e );
	    if( e->Test() )
	        commandError.Set( MsgClient::LockCheckFail );
	}
	
	if( !commandError.Test() && e->Test() )
	    commandError = *e;
	if( commandError.Test() && ui )
	{
	    ui->Message( &commandError );
	    commandError.Clear();
	}

	return 0;
}

/*
 * Helper method for getting the user and client
 */
void
ServerHelper::SetUserClient( const StrPtr *uIn, const StrPtr *cIn )
{
	Client client;

	// Get username

	if( uIn && uIn->Length() )
	{
	    p4user.Set( uIn );
	    p4user.TrimBlanks();
	}

	if( !uIn || !uIn->Length() || !p4user.Length() )
	    p4user = client.GetUser();

	// Get clientname or generate one

	if( cIn && cIn->Length() )
	{
	    p4client.Set( cIn );
	    p4client.TrimBlanks();
	}

	if( !cIn || !cIn->Length() || !p4client.Length() )
	{
	    DateTime dt;

	    dt.SetNow();
	    StrNum dn( dt.Value() );
	    p4client.Set( p4user );
	    p4client.UAppend( "-dvcs-" );
	    p4client.UAppend( &dn );
	}
}

/*
 * Validates that the caseflag passed in is 0 or 1 (with or without the '-C')
 */
void
ServerHelper::SetCaseFlag( const StrPtr *c, Error *e )
{
	int caseVal = -1;
	if( strncmp( "-C", c->Text(), 2 ) )
	    caseVal = c->Atoi();
	else
	    caseVal = StrRef( c->Text() + 2 ).Atoi();

	if( caseVal != 0 && caseVal != 1 && caseVal != 2 )
	{
	    e->Set( MsgClient::InitCaseFlagUnset );
	    return;
	}

	caseFlag.Set( "-C" );
	caseFlag << caseVal;
}

/*
 * Sets the default stream name (validated to be 2 levels deep)
 */
void
ServerHelper::SetDefaultStream( const StrPtr *branch, Error *e )
{
	// Must look like a stream
	// e.g.   //depot/mainline
	// Or just the short stream name
	// e.g.           mainline

	StrRef slash( "/" );
	if( InvalidChars( branch->Text(), branch->Length() ) ||
	    ( branch->Contains( slash ) && TooWide( branch->Text(), 2, 1 ) ) )
	{
	    e->Set( MsgClient::NotValidStreamName ) << branch;
	    return;
	}

	defaultStream.Set( branch );
	defaultStreamChanged = 1;
}

/*
 * Helper method for configuring a Client object to use either the remote
 * or local Perforce Server.
 */
void
ServerHelper::InitClient( Client *client, int useEnv, Error *e )
{
	if( !useEnv )
	{
	    if( !p4port.Length() )
	        p4port = client->GetPort();

	    SetUserClient( &p4user, &p4client );

	    client->SetPort( &p4port );
	    client->SetUser( &p4user );
	    client->SetClient( &p4client );
	}

	client->SetProtocol( P4Tag::v_tag );
	client->SetProtocol( P4Tag::v_enableStreams );

	if( app.Length() )
	    client->SetProtocolV( app.Text() );

	SetupUnicode( client, e );

	client->SetCwd( &dir );

	if( p4passwd.Length() )
	    client->SetPassword( &p4passwd );

	client->SetProg( &prog );
	client->SetVersion( &version );


	client->Init( e );
}

void
ServerHelper::SetupUnicode( Client *client, Error *e )
{
	if( hasTrans )
	    client->SetTrans( outputTrans, contentTrans, fnamesTrans,
	                      dialogTrans );
	else if( charset.Length() )
	{
	    int cs = CharSetApi::Lookup( charset.Text() );
	    if( cs >= 0 )
	        client->SetTrans( cs );
	    else if( e )
	        e->Set( MsgClient::UnknownCharset ) << charset;
	}
}


/*
 * Runs 'p4 info' to discover configuration details from a remote server
 */
int
ServerHelper::Discover( const StrPtr* port, ClientUser *ui, Error *e )
{
	if( port )
	    p4port.Set( port );

	Client client;

	InitClient( &client, 0, e );
	if( e->Test() )
	{
	    // Don't report the connection error, let the caller decide
	    commandError = *e;
	    return 0;
	}

	// Run info command, no crypto required (yet)

	SetCommand( "info", ui );
	client.Run( "info", this );

	state |= DISCOVERED;

	client.Final( e );
	return 1;
}

/*
 * Loads a remote spec into memory from a remote server
 */
int
ServerHelper::LoadRemote( const StrPtr* port, const StrPtr *remote,
    ClientUser *ui, Error *e )
{
	if( ( state & DISCOVERED ) && !FetchAllowed() )
	    commandError.Set( MsgClient::CloneCantFetch ) << p4port;

	if( !( state & DISCOVERED ) && port )
	    p4port.Set( port );

	if( remoteName.Length() )
	    commandError.Set( MsgClient::RemoteAlreadySet ) << remoteName;
	
	if( commandError.Test() )
	{
	    *e = commandError;
	    return 0;
	}

	// Run remote command, crypto required
	// Check remote exists
	
	Client client;
	char *args[2];

	InitClient( &client, 0, e );
	if( e->Test() )
	{
	    // Don't report the connection error, let the caller decide
	    commandError = *e;
	    return 0;
	}

	if( !( state & DISCOVERED ) )
	{
	    // Run info command, no crypto required (yet)

	    SetCommand( "info", ui );
	    client.Run( "info", this );

	    state |= DISCOVERED;

	    if( !FetchAllowed() )
	    {
	        commandError.Set( MsgClient::CloneCantFetch ) << p4port;
	        *e = commandError;
	        client.Final( e );
	        return 0;
	    }
	}

	args[0] = ( char * ) "-E";
	args[1] = remote->Text();
	SetCommand( "remotes", ui );
	client.SetArgv( 2, args );
	client.Run( "remotes", this );

	if( NeedLogin() )
	{
	    commandError.Set( MsgClient::CloneNeedLogin2 ) << p4user << p4port;
	    commandError.Set( MsgClient::CloneNeedLogin1 ) << p4user << p4port;
	    *e = commandError;
	    client.Final( e );
	    return 0;
	}

	// The remoteName is loaded from the returned data
	if( !remoteName.Length() )
	{
	    if( !GotError() )
	    {
	        commandError.Set( MsgClient::CloneNoRemote )
	            << p4port << remote;
	        *e = commandError;
	    }
	    client.Final( e );
	    return 0;
	}

	// Gather the remote spec's mappings and description

	args[0] = ( char * ) "-o";
	args[1] = remote->Text();
	SetCommand( "remote-out", ui );
	client.SetArgv( 2, args );
	client.Run( "remote", this );
	client.Final( e );

	if( GotError() )
	{
	    *e = commandError;
	    return 0;
	}
	
	state |= WITHREMOTE;

	return 1;
}

/*
 * Constructs a new remote spec in memory using the provided filepath
 */
int
ServerHelper::MakeRemote( const StrPtr *port, const StrPtr *filepath,
    ClientUser *ui, Error *e )
{
	if( ( state & DISCOVERED ) && !FetchAllowed() )
	{
	    commandError.Set( MsgClient::CloneCantFetch ) << p4port;
	    *e = commandError;
	}

	if( !( state & DISCOVERED ) && port )
	    p4port.Set( port );

	if( remoteName.Length() )
	    commandError.Set( MsgClient::RemoteAlreadySet ) << remoteName;
	
	if( commandError.Test() )
	    return 0;
	
	Client client;
	char *args[2];

	InitClient( &client, 0, e );
	if( e->Test() )
	{
	    // Don't report the connection error, let the caller decide
	    commandError = *e;
	    return 0;
	}


	if( !( state & DISCOVERED ) )
	{
	    // Run info command, no crypto required (yet)

	    SetCommand( "info", ui );
	    client.Run( "info", this );

	    state |= DISCOVERED;

	    if( !FetchAllowed() )
	    {
	        commandError.Set( MsgClient::CloneCantFetch ) << p4port;
	        *e = commandError;
	        client.Final( e );
	        return 0;
	    }
	}

	// Fakeup a remote map called origin
	// We can only map a filepath if its only wildcards are
	// trailing ellipses.

	StrBuf depotMap;
	int cannotMap = 0;
	int reMap = 0;
	int quoteSpaces = 0;
	const char *s = filepath->Text();
	const char *x = s + strlen( s );
	const char *p = strstr( s, "/..." );
	const char *newPath;

	if( !p || p != ( x - 4 ) )
	    cannotMap = 1;

	if( TooWide( s, 2, 0 ) && cannotMap )
	{
	    if( *s == '/' && *(s+1) == '/'  && strstr( (s+2), "/" ) 
	                    && *(x-1) != '/'  )
	    {
	        reMap = 1;
	        newPath = x;
	        while( *newPath != '/' ) 
	            newPath--;
	    }
	    else
	    {
	        commandError.Set( MsgClient::ClonePathNoMap ) << filepath;
	        *e = commandError;
	        client.Final( e );
	        return 0;
	    }

	}
	else if( TooWide( s, 2, 0 ) )
	{
	    commandError.Set( MsgClient::ClonePathTooWide ) << filepath;
	    *e = commandError;
	    client.Final( e );
	    return 0;
	}

	int invalid = 0;
	if( ( invalid = InvalidChars( s, x - s - 4 ) ) )
	{
	    commandError.Set( invalid > 1 ? MsgClient::ClonePathHasWild
	                                  : MsgClient::ClonePathHasIllegal )
	        << filepath;
	    *e = commandError;
	    client.Final( e );
	    return 0;
	}
	for( p = s; p < (x - 4); p++ )
	    if( *p == ' ' )
	        quoteSpaces = 1;

	args[0] = (char *) "-s";
	SetCommand( "login-s", ui );
	client.SetArgv( 1, args );
	client.Run( "login", this );

	if( NeedLogin() )
	{
	    commandError.Set( MsgClient::CloneNeedLogin2 ) << p4user << p4port;
	    commandError.Set( MsgClient::CloneNeedLogin1 ) << p4user << p4port;
	    *e = commandError;
	    client.Final( e );
	    return 0;
	}

	client.Final( e );

	StrRef slash( "/" );
	StrBuf left;
	if( defaultStreamChanged && !defaultStream.Contains( slash ) )
	    left << "//stream/";
	left << defaultStream;

	if( reMap )
	    depotMap << left << newPath << " " << filepath;
	else if( cannotMap )
	    depotMap << filepath << " " << filepath;
	else if( quoteSpaces )
	    depotMap << left << "/..." << " \"" << filepath << "\"";
	else
	    depotMap << left << "/..." << " " << filepath;

	Dict()->SetVar( StrRef( "depotMap" ), depotMap );
	SetDescription( "auto-generated from clone command" );
	remoteName.Set( "origin" );

	state |= WITHREMOTE;

	return 1;
}

/*
 * Wrapper method around the steps required to fully initialise the DVCS server
 */
int
ServerHelper::InitLocalServer( ClientUser *ui, Error *e )
{
	int ecode = 0;

	SetUserClient( &p4user, &p4client );

	if( state & CREATED_MASK )
	    return 0;

	if( !caseFlag.Length() )
	    e->Set( MsgClient::InitCaseFlagUnset );
	else if( unicode < 0 )
	    e->Set( MsgClient::InitUnicodeUnset );

	if( e->Test() )
	    return 0;

	WriteConfig( e );

	if( !e->Test() )
	    ecode = CreateLocalServer( ui, e );

	if( !ecode && !e->Test() && PostInit( ui ) )
	    WriteIgnore( e );

	if( e->Test() )
	{
	    ui->Message( e );
	    ecode = ecode ? ecode : 1;
	}

	if( commandError.Test() )
	{
	    ecode = ecode ? ecode : 1;
	    if( !e->Test() )
	        *e = commandError;
	}

	if( !ecode )
	    state |= CREATED_SUCCESS;
	else
	    state |= CREATED_FAIL;

	return ecode;
}

/*
 * Write the P4CONFIG file
 */
void
ServerHelper::WriteConfig( Error *e )
{
	FileSys *fsys = FileSys::Create( FST_TEXT );

	fsys->Set( config );

	// Does a P4CONFIG file exist?

	if( ( fsys->Stat() & ( FSF_EXISTS|FSF_EMPTY ) ) == FSF_EXISTS )
	{
	    // Yes. So append to the config file instead.
	    delete fsys;
	    fsys = FileSys::Create( FST_ATEXT );
	    fsys->Set( config );
	}

	// Add values
	fsys->Perms( FPM_RW );
	fsys->Open( FOM_WRITE, e );

	if( e->Test() )
	    goto finish;

	fsys->Write( StrRef( "P4IGNORE=" ), e );
	fsys->Write( ignore, e );

	fsys->Write( StrRef( "\nP4CHARSET=" ), e );
	fsys->Write( StrRef( unicode ? "auto" : "none" ), e );

	fsys->Write( StrRef("\n"
	    "P4INITROOT=$configdir\n"
	    "P4USER=" ), e );
	fsys->Write( p4user, e );

	fsys->Write( StrRef( "\nP4PORT=rsh:" ), e );
# ifndef OS_NT
	fsys->Write( StrRef( "/bin/sh -c \"umask 077 && exec " ), e );
# endif
	fsys->Write( serverExe, e );
	fsys->Write( StrRef( " -i " ), e );

	if( debug.Length() ) { fsys->Write( StrRef( "-v" ), e );
	                       fsys->Write( debug, e ); }
	                else { fsys->Write( StrRef( "-J off" ), e ); }
# ifdef OS_NT
	fsys->Write( StrRef( " -r \"$configdir\\" INIT_ROOT "\"\n" ), e );
# else
	fsys->Write( StrRef( " -r '$configdir/" INIT_ROOT "'\"\n" ), e );
# endif
	fsys->Write( StrRef( "P4CLIENT=" ), e );
	fsys->Write( p4client, e );
	fsys->Write( "\n", 1, e );

	fsys->Close( e );

finish:
	delete fsys;
}

/*
 * Initialise the new local server using the -xn/-xnn flags
 */
int
ServerHelper::CreateLocalServer( ClientUser *ui, Error *e )
{
	FileSys *fsys = FileSys::Create( FST_TEXT );
	FileSys *rootDir = FileSys::Create( FST_TEXT );
	PathSys *curdir = PathSys::Create();

	RunCommandIo rc;
	RunArgv ra;
	StrBuf res;
	Error e1;
	int ecode = 1;
	StrBuf clientName = p4client;

# ifndef OS_NT
	int oldumask = umask( 077 );
# endif

	ra << serverExe;

	// Move to the .p4root directory
	curdir->SetLocal( dir, StrRef( INIT_ROOT ) );
	ra << "-r" << *curdir;

	// Handle unicode

	if( unicode )
	{
	    int out = 0;
	    Client client;
	    if( hasTrans )
	        out = fnamesTrans;
	    else if( charset.Length() )
	        out = CharSetApi::Lookup( charset.Text(), client.GetEnviro() );
	    else
	        out = CharSetApi::Lookup( "auto", client.GetEnviro() );

	    StrBuf user = p4user;
	    CharSetCvt *cvt = CharSetCvt::FindCvt( (CharSetCvt::CharSet)out,
	                                           CharSetCvt::UTF_8);

	    if( cvt )
	    {
	        int err = 0;
	        err += !Translate( cvt, out, &p4user, user, e );
	        err += !Translate( cvt, out, &p4client, clientName, e );

	        delete cvt;
	        if( err )
	            goto finish;
	    }

	    StrBuf euser;
	    StrOps::EncodeNonPrintable( user, euser, 1, 1 );
	    if( user != euser )
	        ra << "-xne";
	    else
	        ra << "-xn";

	    ra << "-u" << euser;
	}
	else
	{
	    ra << "-xnn";
	    ra << "-u" << p4user;
	}

	// Handle case flags
	ra << caseFlag;

	// quiet
	ra << "-q";
	ra << "-Joff";

	curdir->SetLocal( *curdir, StrRef( "file" ) );
	fsys->Set( *curdir );

	fsys->MkDir( e );

	// Make the .p4root directory hidden

	curdir->ToParent();
	rootDir->Set( *curdir );
	rootDir->SetAttribute( FSA_HIDDEN, e );

	fsys->Set( INIT_SERVERID );
	fsys->Perms( FPM_RW );
	fsys->Open( FOM_WRITE, e );

	if( e->Test() )
	    goto finish;

	fsys->Write( clientName, e );
	fsys->Write( "\n", 1, e );
	fsys->Close( e );

	if( e->Test() )
	    goto finish;
	
	ecode = rc.Run( ra, res, e );

	res.TrimBlanks();
	if( res.Length() )
	{
	    e1.Set( E_INFO, "%output%" ) << res;
	    ui->Message( &e1 );
	}

	if( ecode )
	{
	    // server failed to initialize

	    fsys->Set( config );
	    fsys->Unlink( e );

	    fsys->Set( INIT_SERVERID );
	    fsys->Unlink( e );
	    fsys->RmDir( e );

	    e->Set( MsgClient::InitServerFail );
	    goto finish;
	}

	if( e->Test() )
	    goto finish;

finish:

# ifndef OS_NT
	umask( oldumask );
# endif

	delete curdir;
	delete rootDir;
	delete fsys;

	return ecode;
}

/*
 * Do the things we need to do after we initialise the Perforce Server, but
 * before it can be considered "init'ed".
 *
 * This involes:
 * - creating the server spec
 * - initialising any streams (creating the workspace in the progress)
 */
int
ServerHelper::PostInit( ClientUser *ui )
{
	Error e;
	int i, j;
	StrRef var, val;
	Client client;
	char *args[1000];
	inputData.Clear();

	// Create server record

	InitClient( &client, 1, &e );
	if( e.Test() )
	{
	    // Don't report the connection error, let the caller decide
	    commandError = e;
	    return 0;
	}

	inputData << "\nServerID: " << p4client;
	inputData << "\nType: server";
	inputData << "\nServices: local";
	inputData << "\nDescription:\n\tDVCS local personal repo\n";

	args[0] = (char *) "-i";
	SetCommand( "server-in", ui );
	client.SetArgv( 1, args );
	client.Run( "server", this );
	client.Final( &e );

	if( e.Test() || GotError() )
	{
	    ui->Message( e.Test() ? &e : &commandError );
	    return 0;
	}

	// Grab a new client now (we've just changed the server's context)
	
	InitClient( &client, 1, &e );
	if( e.Test() )
	{
	    // Don't report the connection error, let the caller decide
	    commandError = e;
	    return 0;
	}

	// Initialize depot, build mainline streams
	// Use the first map entry to create the first mainline

	int initDone = 0;
	int argsCount;
	StrBuf filePath;

	for( i = 0; Dict()->GetVar( i, var, val ); i++ )
	{
	    GetStreamName( &filePath, val );

	    if( StreamExists( filePath ) )
	        continue;

	    argsCount = 0;

	    if( initDone )
	    {
	        args[argsCount++] = (char *) "-m";
	        args[argsCount++] = (char *) "-c";
	    }
	    else
	    {
	        args[argsCount++] = (char *) "-i";
	        initDone++;
	    }

	    args[argsCount++] = (char *) "-s";
	    args[argsCount++] = (char *) Trim( filePath, val );

	    for( j = (i+1); Dict()->GetVar( j, var, val ); j++ )
	    {
	        if( !filePath.XCompareN( val ) )
	        {
	            args[argsCount++] = (char *) "-s";
	            args[argsCount++] = (char *) Trim( filePath, val );
	        }
	    }

	    args[argsCount++] = filePath.Text();
	    
	    SetCommand( "switch", ui );
	    client.SetArgv( argsCount, args );
	    client.Run( "switch", this );

	    // cleanup allocated trimmed paths

	    for( int x = 0; x < argsCount; ++x )
	    {
	        if( !strcmp( args[ x ], "-s" ) )
	            free( args[ ++x ] );
	    }

	    if( GotError() )
	        break;
	}

	// Handle init with no stream name

	if( !initDone )
	{
	    argsCount = 0;
	    args[argsCount++] = (char *) "-i";
	    if( defaultStreamChanged )
	        args[argsCount++] = (char *) defaultStream.Text();
	    SetCommand( "switch", ui );
	    client.SetArgv( argsCount, args );
	    client.Run( "switch", this );
	}

	client.Final( &e );

	if( GotError() )
	{
	    ui->Message( &commandError );
	    return 0;
	}

	return 1;
}

/*
 * Do the initial fetch (after saving the remore spec)
 */
int
ServerHelper::FirstFetch(
	int depth,
	int noArchivesFlag,
	const StrPtr *debugFlag,
	ClientUser *ui,
	Error *e )
{
	if( !remoteName.Length() )
	{
	    commandError.Set( MsgClient::NoRemoteToSet );
	    return 0;
	}
	
	Client client;
	int i;
	StrRef var, val;
	char *args[1000];
	inputData.Clear();

	if( !remoteName.Length() )
	    return 0;
	
	InitClient( &client, 1, e );

	if( e->Test() )
	{
	    // Don't report the connection error, let the caller decide
	    commandError = *e;
	    return 0;
	}

	inputData.Clear();
	inputData << "\nRemoteID: origin";
	inputData << "\nAddress: " << p4port;
	inputData << "\nOwner: " << p4user;
	inputData << "\nOptions: " << remoteOptions;
	inputData << "\nDescription: ";

	char *ptr = description.Text();

	while( *ptr != '\0' )
	{
	    inputData.Append( ptr, 1 );
	    if( *ptr++ == '\n' && *ptr != '\0' )
	        inputData << "\t";
	}

	inputData << "\nDepotMap:\n";

	for( i = 0; Dict()->GetVar( i, var, val ); i++ )
	    inputData << "\t" << val.Text() << "\n";

	if( ArchiveLimits()->GetCount() )
	{
	    inputData << "\nArchiveLimits:\n";
	    for( i = 0; ArchiveLimits()->GetVar( i, var, val ); i++ )
	        inputData << "\t" << val.Text() << "\n";
	}

	args[0] = ( char * ) "-i";

	SetCommand( "remote-in", ui );
	client.SetArgv( 1, args );
	client.Run( "remote", this );

	if( GotError() )
	{
	    ui->Message( &commandError );
	    *e = commandError;
	    client.Final( e );
	    return 0;
	}

	commandError.Set( MsgClient::CloneStart ) << p4port;
	ui->Message( &commandError );
	commandError.Clear();

	// Issue fetch command
	int argc = 0;

	if( debugFlag )
	{
	    args[argc++] = ( char * ) "-v";
	}

	if( depth )
	{
	    args[argc++] = ( char * ) "-m";
	    args[argc++] = (char *) StrNum( depth ).Text();
	}
	if( noArchivesFlag )
	    args[argc++] = ( char * ) "-A";

	SetCommand( "fetch", ui );
	client.SetArgv( argc, args );
	client.Run( "fetch", this );

	// Get MaxCommitChange.

	args[0] = ( char * ) "maxCommitChange";

	SetCommand( "counter", ui );
	client.SetArgv( 1, args );
	client.Run( "counter", this );

	// Only update LastPush if data was pulled

	if( !MaxChange() )
	{
	    client.Final( e );
	    return 0;
	}

	// Reload origin remote map.

	args[0] = ( char * ) "-o";
	args[1] = ( char * ) "origin";

	SetCommand( "remote-out2", ui );
	client.SetArgv( 2, args );
	client.Run( "remote", this );

	// Alter last push value

	inputData.Clear();

	StrBuf archiveMap( "ArchiveLimits" ),map;
	map.Set( "DepotMap" );
	int mapCount = 0, archiveLimitsCount = 0;

	for( i = 0; Dict()->GetVar( i, var, val ); i++ )
	{
	    // extra vars not in form

	    if( var == "specFormatted" || var == "func" )
		continue;
	    else if( var == "Description" )
	    {
		char *ptr = val.Text();
		inputData << var << ": ";

		while( *ptr != '\0' )
		{
		    inputData.Append( ptr, 1 );
		    if( *ptr++ == '\n' && *ptr != '\0' )
			inputData << "\t";
		}
	    }
	    else if( !map.XCompareN( var ) )
	    {
		if( !mapCount++ )
		    inputData << "DepotMap:\n";
		inputData << "\t" << val << "\n";
	    }
	    else if( !archiveMap.XCompareN( var ) )
	    {
		if( !archiveLimitsCount++ )
		    inputData << "ArchiveLimits:\n";
		inputData << "\t" << val << "\n";
	    }
	    else
	    {
		inputData << var << ":\n\t";
		if( var == "LastPush" )
		    inputData << MaxChange() << "\n";
		else
		    inputData << val << "\n";
	    }
	}

	args[0] = ( char * ) "-i";

	SetCommand( "remote-in", ui );
	client.SetArgv( 1, args );
	client.Run( "remote", this );

	// End commands

	client.Final( e );

	return 1;
}

/*
 * Writes the P4IGNORE file
 */
void
ServerHelper::WriteIgnore( Error *e )
{
	FileSys *fsys;

	fsys = FileSys::Create( FST_TEXT );
	
	fsys->Set( ignoreFile );

	if( ( fsys->Stat() & ( FSF_EXISTS|FSF_EMPTY ) ) == FSF_EXISTS )
	{
	    // Might have been created by a failed clone, check before
	    // appending.

	    // Assume the clone fetch dumped it here... bail...

	    if( remoteName.Length() )
	        goto finish;

	    fsys->Open( FOM_READ, e );

	    if( e->Test() )
	        goto finish;

	    StrBuf line;
	    while( fsys->ReadLine( &line, e  ) )
	    {
	        if( !line.Compare( StrRef( INIT_ROOT ) ) )
	        {
	            fsys->Close( e );
	            goto finish;
	        }
	    }

	    fsys->Close( e );
	    delete fsys;
	    fsys = FileSys::Create( FST_ATEXT );
	    fsys->Set( ignore );
	}

	fsys->Perms( FPM_RW );
	fsys->Open( FOM_WRITE, e );

	if( e->Test() )
	    goto finish;
 
	fsys->Write( config, e );
	fsys->Write( "\n", 1, e );
	fsys->Write( ignore, e );
	fsys->Write( StrRef( "\n.svn\n.git\n.DS_Store\n"
	             INIT_ROOT "\n*.swp\n" ), e );
	fsys->Close( e );

finish:
	delete fsys;
}

/*
 * Is the streamname in our list
 */
int
ServerHelper::StreamExists( StrPtr &filePath )
{
	int i;
	StrRef var, val;

	for( i = 0; mainlines.GetVar( i, var, val ); i++ )
	{
	    if( !filePath.Compare( var ) )
	        return 1;
	}

	mainlines.SetVar( filePath, filePath );
	return 0;
}

/*
 * Gets the first two levels from a path.
 */
void
ServerHelper::GetStreamName( StrBuf *filePath, StrPtr &val )
{
	filePath->Clear();

	StrBuf buf;
	buf << val.Text();

	if( buf.Length() < 5 )
	    return;

	char *p, *s;

	s = buf.Text();
	while( *s == '-' || *s == '"' ) s++;
	p = s + 2;
	p = strchr( p, '/' );

	if( !p || !*p )
	    return;

	p++;
	p = strchr( p, '/' );

	if( !p )
	    return;

	filePath->Append( s, p - s );
}

/*
 * Gets the bit between the streamname and the first space, or the bit
 * between the streamname and the closing quote, if the path is quoted.
 */
const char *
ServerHelper::Trim( StrPtr &filePath, StrPtr &val )
{
	StrBuf sharePath;

	int quoted = 0;
	char *p = val.Text();
	if( *p == '"' )
	{
	    p++;
	    quoted = 1;
	}
	p = p + filePath.Length() + 1;
	char *e = p;

	while( *e )
	{
	    if( !quoted && *e == ' ' )
	        break;
	    if( quoted && *e == '"' )
	        break;
	    ++e;
	}

	sharePath.Append( p, e - p );

	p = (char *) malloc( sharePath.Length() + 1 );
	strcpy( p, sharePath.Text() );
	return p;
}

/*
 * Intercepting client tagged output parser
 */
void
ServerHelper::OutputStat( StrDict *varList )
{
	// Capture data from info and remote

	if( GetCommand() == "info" )
	{
	    StrPtr *s;

	    unicode = varList->GetVar( P4Tag::v_unicode ) != 0;

	    security = varList->GetVar( P4Tag::v_security ) != 0;

	    s = varList->GetVar( P4Tag::v_userName );
	    if( s )
	        userName.Set( s );

	    s = varList->GetVar( P4Tag::v_serverAddress );
	    if( s )
	        serverAddress.Set( s );

	    s = varList->GetVar( P4Tag::v_caseHandling );
	    if( !s || *s == "sensitive" )  caseFlag.Set( "-C0" );
	    else if( *s == "insensitive" ) caseFlag.Set( "-C1" );
	    else if( *s == "hybrid" )      caseFlag.Set( "-C2" );

	    s = varList->GetVar( "allowFetch" );
	    if( !s || s->Atoi() < 2 )
	        fetchAllowed = 0;
	    else
	        fetchAllowed = 1;

	}
	else if( GetCommand() == "remote-out" )
	{
	    int i;
	    int count = 0;
	    int quoted;
	    StrRef var, val;
	    StrBuf lhs, depot, empty, map, archiveMap;
	    map.Set( "DepotMap" );
	    archiveMap.Set( "ArchiveLimits" );
	    empty.Set( "..." );
	    const char *p;

	    for( i = 0; varList->GetVar( i, var, val ); i++ )
	    {
	        depot.Clear();

	        if( !map.XCompareN( var ) )
	        {
	            StrOps::GetDepotName( val.Text(), depot );

	           if( !empty.XCompareN( depot ) )
	           {
	                commandError.Set( MsgClient::CloneRemoteInvalid );
	                break;
	           }

	            if( count++ )
	            {
	                if( depotName != depot )
	                {
	                    StrBuf depots;
	                    for( int j = 0; varList->GetVar(j, var, val); j++ )
	                        if( !map.XCompareN( var ) )
	                            depots << "\n" << val.Text();

	                    commandError.Set( MsgClient::CloneTooManyDepots )
	                        << depots;
	                    break;
	                }
	            }
	            else
	                depotName << depot;

	            // Validate stream(branch) side of map

	            lhs.Clear();

	            p = val.Text();
	            quoted = (*p++ == '"' );

	            while( *p != 0 )
	            {
	                if( ( quoted && *p == '"' ) ||
	                    (!quoted && *p == ' ' )  )
	                    break;
	                ++p;
	            }

	            if( quoted )
	                lhs.Append( val.Text()+1, (p - val.Text()) - 2 );
	            else
	                lhs.Append( val.Text(), p - val.Text() );

	            p = lhs.Text();
	            if( *p == '-' )
	               ++p;

	            if( TooWide( p, 2, 0 ) )
	                commandError.Set( MsgClient::CloneTooWide ) << lhs;

	            remoteMap.SetVar( var, val );
	            continue;
	        }
	        if( !archiveMap.XCompareN( var ) )
	            archiveLimits.SetVar( var, val );

	        if( var ==  "Description" )
	            description << val;
	        if( var ==  "Options" )
	            remoteOptions << val;
	    }
	}
	else if( GetCommand() == "remote-out2" )
	{
	    int i;
	    StrRef var, val;
	    remoteMap.Clear();

	    for( i = 0; varList->GetVar( i, var, val ); i++ )
	        remoteMap.SetVar( var, val );
	}
	else if( GetCommand() == "counter" )
	{
	    StrPtr *s = varList->GetVar( "value" );

	    if( s )
	        maxCommitChange = s->Atoi();
	}
	else if( GetCommand() == "remotes" )
	{
	    remoteName.Set( varList->GetVar( "RemoteID" ) );
	}
	else if( GetCommand() == "fetch" )
	{
	    StrPtr *cc = varList->GetVar( "changeCount" );
	    StrPtr *fc = varList->GetVar( "totalFileCount" );
	    if( cc && fc && !quiet && slaveUi )
	    {
	        commandError.Set( MsgClient::CloneFetchCounts ) << cc << fc;
	        slaveUi->Message( &commandError );
	    }
	}
}

/*
 * Intercepting client text data passthough
 */
void
ServerHelper::OutputText( const char *data, int length )
{
	slaveUi->OutputText( data, length );
}

/*
 * Intercepting client specific command silencing info message passthough
 */
void
ServerHelper::OutputInfo( char level, const char *data )
{
	// quiet where possible

	if( !debug.Length() &&
	    ( GetCommand() == "remote-in" || GetCommand() == "switch" ) )
	    return;

	if( slaveUi )
	    slaveUi->OutputInfo( level, data );
}

/*
 * Intercepting client session validating error message passthough
 */
void
ServerHelper::OutputError( const char *errBuf )
{
	if( ( GetCommand() == "remotes" || GetCommand() == "login-s" )
	    && ( !strncmp( errBuf, "Perforce password", 17 ) || 
	         !strncmp( errBuf, "Your session has expired", 24 ) ) )
	{
	    needLogin++;
	}
	else if( slaveUi )
	{
	    slaveUi->OutputError( errBuf );
	}
}

/*
 * Intercepting client data sender
 */
void
ServerHelper::InputData( StrBuf *buf, Error *e )
{
	if( GetCommand() == "remote-in" ||
	    GetCommand() == "server-in" )
	    buf->Set( inputData );
}

/*
 * Handle overriden progress indicators
 */
int
ServerHelper::ProgressIndicator()
{
	return slaveUi ? slaveUi->ProgressIndicator()
	               : ClientUserProgress::ProgressIndicator();
}

ClientProgress *
ServerHelper::CreateProgress( int t )
{
	return slaveUi ? slaveUi->CreateProgress( t )
	               : ClientUserProgress::CreateProgress( t );
}

/*
 * Checks a path is at least or eactly N levels deep.
 */
int
ServerHelper::TooWide( const char *s, int levels, int exact )
{
	const char *p;
	int invalid = 0;

	if( *s != '/' || *( s + 1 ) != '/' || *( s + 2 ) == '/' )
	    invalid = 1;

	p = s + 1;

	for( int level = 1; !invalid && level <= levels; level++ )
	{
	    if( level == levels )
	    {
	        if( !exact &&
	            ( !( p = strstr( p + 1, "/" ) ) || *( p + 1 ) == '\0' ) )
	            invalid = 1;
	        else if( exact && ( p = strstr( p + 1, "/" ) ) )
	            invalid = 1;
	    }
	    else if( !( p = strstr( p + 1, "/" ) ) || *( p + 1 ) == '/' )
	        invalid = 1;
	}
	return invalid;
}

/*
 * Checks that a path does not include illegal charaters or embedded wildcards
 */
int
ServerHelper::InvalidChars( const char *s, int l )
{
	const char *p;
	for( p = s; p - s < l; p++ )
	    if( ( *p == '@' || *p == '%' || *p == '#' || *p == '*' ) ||
	        ( *p == '.' && *( p + 1 ) == '.' && *( p + 2 ) == '.' ) )
	        return *p == '.' ? 2 : 1;
	return 0;
}


/*
 * Ensure we're not about to init a server of a filesystem that doesn't
 * support locking (we're looking at you NFS!).
 *
 * Called from Exists(): we only need to check if we're going to init a new
 * server and since that method potentially moved the CWD, it makes sense.
 */
static void
LockCheck( Error *e )
{
	FileSys *fsys, *altsys;

	fsys = FileSys::Create( FST_BINARY );

	fsys->Set( "db.check" );
	fsys->Perms( FPM_RW );
	fsys->Open( FOM_WRITE, e );

	if( e->Test() )
	    goto finish;

	altsys = FileSys::Create( FST_BINARY );

	altsys->Set( fsys->Name() );
	altsys->Perms( FPM_RW );
	altsys->Open( FOM_READ, e );

	if( !e->Test() )
	{
	    int ffd, afd;

	    ffd = fsys->GetFd();
	    afd = altsys->GetFd();

// Because Solaris locking is at a process level not a file descriptor
// level, we can't do all the checks we want

	    if( ! (
	            lockFile( ffd, LOCKF_EX_NB ) == 0 &&
# ifndef OS_SOLARIS
	            lockFile( afd, LOCKF_SH_NB ) == -1 &&
# endif
	            lockFile( ffd, LOCKF_UN ) == 0 &&
	            lockFile( afd, LOCKF_SH_NB ) == 0 &&
# ifndef OS_SOLARIS
	            lockFile( ffd, LOCKF_EX_NB ) == -1 &&
# endif
	            lockFile( afd, LOCKF_UN ) == 0 ) )
	        e->Sys( "lockFile", "db.check" );

	    altsys->Close( e );
	}

	fsys->Close( e );

	delete altsys;

finish:
	fsys->Unlink( e );
	
	delete fsys;
}
