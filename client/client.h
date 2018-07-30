/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * Client - the Perforce client, implemented as an RPC service
 *
 * Basic flow:
 *
 *	ClientUser ui;
 *	Client client;
 *
 *	client.SetProtocol( "gui", "1" ); // optional
 *	client.Dispatcher( &dispatchTable ); // optional
 *
 *	// SetPort() must happen _before_ the Init().
 *
 *	client.SetPort( somefunctionof( client.GetPort() ) ); //optional
 *
 *	client.Init( e );
 *
 *	// GetClient() must happen _after_ the Init().
 *
 *	client.SetClient( somefunctionof( client.GetClient() ) ); //optional
 *	client.SetCwd( somefunctionof( client.GetCwd() ) ); //optional
 *	client.SetUser( somefunctionof( client.GetUser() ) ); //optional
 *
 *	while( !client.Dropped() )
 *	{
 *	    client.SetArgv( argc, argv )
 *	    client.Run( func, &ui )
 *	}
 *
 *	return client.Final( e );
 *
 * Public methods:
 *
 *	Client::Init() - establish connection and prepare to run commands.
 *
 *	Client::Run() - run a single command, assuming arguments have
 *		already been set up.
 *
 *	Client::RunTag() - run a single command (potentially) asynchronously.
 *
 *	Client::WaitTag() - wait for a RunTag()/all RunTag()s to complete.
 *
 *	Client::Final() - clean up end of connection, returning error count.
 *
 *	Client::Dispatcher() - just a shortcut to the service dispatcher.
 *
 *	Client::SetProtocol() - just a shortcut to the service SetProtocol.
 *
 *	Client::SetCharset()
 *	Client::SetClient()
 *	Client::SetCwd()
 *	Client::SetHost()
 *	Client::SetLanguage()
 *	Client::SetPassword()
 *	Client::SetPort()
 *	Client::SetUser() - set current directory, client, host, port, or 
 *		user, overridding all defaults.  SetPort() must be called 
 *		before Init() in order to take effect.  The others must be 
 *		set before Run() to take effect.
 *
 *		SetCwd() additionally searches for a new P4CONFIG file.
 *
 *	Client::DefineCharset()
 *	Client::DefineClient()
 *	Client::DefineHost()
 *	Client::DefineLanguage()
 *	Client::DefinePassword()
 *	Client::DefinePort()
 *	Client::DefineUser() - sets client, port, or user in the registry
 *		and (so as to take permanent effect) then calls SetClient(),
 *		etc. to take immediate effect.
 *
 *	Client::GetBuild()
 *	Client::GetCharset()
 *	Client::GetClient()
 *	Client::GetCwd()
 *	Client::GetHost()
 *	Client::GetLanague()
 *	Client::GetOs()
 *	Client::GetPassword()
 *	Client::GetPort()
 *	Client::GetUser() - get current directory, client, OS, port or user,
 *		as determined by defaults or by corresponding set value.
 *		GetClient()/GetHost() are not valid until after Init() 
 *		establishes the connection, because the hostname of the 
 *		local endpoint may serve as the default client name.
 *
 *	Client::GetConfig() - get the filename pointed to by P4CONFIG, as
 *		determined by enviro::Config().
 *
 *	Client::GetEnv() - set the cwd/client/host/os/user variables (using
 *		Rpc::SetVar() call).  These variables are needed by just
 *		about all calls (via Rpc::Invoke()) to the server.
 *
 *	Client::Confirm() - copy all recv vars to send vars, excluding 
 *		'data' and 'func', and Invoke() the named func.
 *
 *	Client::SetError() - bumps an error counter, whose value is 
 *		returned by GetErrors().  Used by OutputError() to
 *		track any errors returned by the server.
 *
 *	Client::GetErrors() - returns error count of times OutputError()
 *		has been called, so that the client's main routine can
 *		exit non-zero if errors occurred.
 *
 *	Client::OutputError() - a gentle way of reporting an error, rather
 *		than having to blurted out by Rpc::Dispatch().
 */

const int ClientTags = 4; // max pending RunTags()

class ClientUser;
class CharSetCvt;
class Ignore;
class Enviro;
class StrBufDict;

enum EnvVarType
{
	VAR_P4USER =	0x0001,   // P4USER
	VAR_P4CLIENT =	0x0002,   // P4CLIENT
	VAR_P4PORT =	0x0004,   // P4PORT
	VAR_P4PASSWD =	0x0008    // P4PASSWD
} ;

class Client : public Rpc {

    public:
	// caller's main interface

			Client( Enviro * = 0 );
			~Client();

	void		SetTrans( int output, int content = -2,
				int fnames = -2, int dialog = -2 );
	int		GuessCharset();
	int		ContentCharset();

	void		Init( Error *e );
	void		Run( const char *func, ClientUser *ui );
	int		Final( Error *e );

	// alternative async Run() interface

	void		RunTag( const char *func, ClientUser *ui );
	void		WaitTag( ClientUser *ui = 0 );

	void		SetArgv(int ac, char * const * av);

    public:
	// for fine tuning caller's use

	void		SetCharset( const StrPtr *c ) { charset.Set( c ); }
	void		SetClient( const StrPtr *c ) { client.Set( c ); }
	void		SetClientPath( const StrPtr *c )
	                { clientPath.Set( c ); }
	void		SetCwd( const StrPtr *c );
	void		SetCwdNoReload( const StrPtr *c ) { cwd.Set( c ); }
	void		SetExecutable( const StrPtr *c ) { exeName.Set( c ); }
	void		SetHost( const StrPtr *c ) { host.Set( c ); }
	void		SetIgnoreFile( const StrPtr *c ) { ignorefile.Set( c ); }
	void		SetLanguage( const StrPtr *c ) { language.Set( c ); }
	void		SetPort( const StrPtr *c ) { port.Set( c ); }
	void		SetProg( const StrPtr *c );
	void		SetVersion( const StrPtr *c );

	void		SetPassword( const StrPtr *c )
	    { password.Set( c ); password2.Set( c ); ticketKey.Clear(); authenticated = 0; }

	void		SetUser( const StrPtr *c ) 
			{ user.Set( c ); authenticated = 0; }

	void		SetTicketFile( const StrPtr *c )
			{ ticketfile.Set( c ); }

	void		SetTrustFile( const StrPtr *c ) { trustfile.Set( c ); }
	void		SetEnviroFile( const StrPtr *c )
	    { if( c ) SetEnviroFile( c->Text() ); }

	void		SetCharset( const char *c ) { charset.Set( c ); }
	void		SetClient( const char *c ) { client.Set( c ); }
	void		SetCwd( const char *c );
	void		SetCwdNoReload( const char *c ) { cwd.Set( c ); }
	void		SetHost( const char *c ) { host.Set( c ); }
	void		SetIgnoreFile( const char *c ) { ignorefile.Set( c ); }
	void		SetLanguage( const char *c ) { language.Set( c ); }
	void		SetPort( const char *c ) { port.Set( c ); }
	void		SetProg( const char *c );
	void		SetVersion( const char *c );
	void		SetExecutable( const char *c ) { exeName.Set( c ); }

	void		SetPassword( const char *c ) 
	    { password.Set( c ); ticketKey.Clear(); authenticated = 0; }

	void		SetUser( const char *c ) 
			{ user.Set( c ); authenticated = 0; }

	void		SetTicketFile( const char *c )
			{ ticketfile.Set( c ); }

	void		SetTrustFile( const char *c ) { trustfile.Set( c ); }

	void		SetEnviroFile( const char *c );

	void		SetInitRoot( const char *c ) { initRoot.Set( c ); }

	void		SetServerID( const char *c )
	                { serverID.Set( c ); }

	void		DefineCharset( const char *c, Error *e );
	void		DefineClient( const char *c, Error *e );
	void		DefineHost( const char *c, Error *e );
	void		DefineIgnoreFile( const char *c, Error *e );
	void		DefineLanguage( const char *c, Error *e );
	void		DefinePassword( const char *c, Error *e );
	void		DefinePort( const char *c, Error *e );
	void		DefineUser( const char *c, Error *e );

	const StrPtr	&GetCharset();
	const StrPtr	&GetClient();
	const StrPtr	&GetClientNoHost();
	const StrPtr	&GetClientPath();
	const StrPtr	&GetCwd();
	const StrPtr	&GetHost();
	const StrPtr	&GetLanguage();
	const StrPtr	&GetOs();
	const StrPtr	&GetPassword();
	const StrPtr	&GetPassword( const StrPtr *user, int forceTFile = 0 );
	const StrPtr	&GetPassword2();
	const StrPtr	&GetPort();
	const StrPtr	&GetUser();
	const StrPtr	&GetTempPath();
	const StrPtr	&GetTicketFile();
	const StrPtr	&GetTrustFile();
	const StrPtr	&GetConfig();
	const StrArray	*GetConfigs();
	const StrPtr	&GetLoginSSO();
	const StrPtr	&GetSyncTrigger();
	const StrPtr	&GetIgnoreFile();
	const StrPtr	&GetInitRoot();
	const StrPtr	&GetBuild() { return buildInfo; }
	const StrPtr	&GetExecutable() { return exeName; }

	void		SetIgnorePassword() 
			{ ignoreList |= VAR_P4PASSWD; }

	int		IsIgnorePassword()
			{ return ( ignoreList & VAR_P4PASSWD ); }

	void		SetProtocol( const char *p, const char *v )
			{ service.SetProtocol( p, v ); }

	void		SetProtocol( const char *p )
			{ service.SetProtocol( p ); }

	void		SetProtocolV( const char *arg )
			{ service.SetProtocolV( arg ); }

	void		Dispatcher( RpcDispatch *d )
			{ service.Dispatcher( d ); }
	
	StrPtr		*GetEVar( const char *k );
	StrPtr		*GetEVar( const StrPtr *k );
	void		SetEVar( const StrPtr *k, const StrPtr *v );

    public:
	// for use by the client service implementation

	void		GetEnv();
	Enviro*		GetEnviro() { return enviro; }
	const StrPtr *	GetEnviroFile();
	Ignore*		GetIgnore() { return ignore; }
	void		Confirm( const StrPtr *confirm );
	ClientUser *	GetUi() { return tags[ lowerTag ]; }
	
	void		FstatPartialAppend( StrDict *part );
	void		FstatPartialClear();

	void		SetError() { errors++; }
	int		GetErrors() { return errors; }
	void		SetFatal() { fatals++; }
	int		GetFatals() { return fatals; }
	
	void		OutputError( Error *e );

	Handlers	handles;

	void		NewHandler();
	CharSetCvt	*fromTransDialog, *toTransDialog;
        StrDict		*translated, *transfname, *fstatPartial;
	int		unknownUnicode;
	int		content_charset; // file content charset
	int		output_charset;  // result output charset
 
	void		VSetVar( const StrPtr &var, const StrPtr &val );

	int		protocolXfiles;	// 'xfiles' protocol
	int		protocolNocase;	// 'nocase' protocol
	int		protocolSecurity;  // server 'security' protocol
	int		protocolUnicode;	// server 'unicode' protocol

        StrPtr *	GetProtocol( const StrPtr &var );

	void		SetSecretKey( StrPtr &s ) { secretKey.Set( s ); }
	void		ClearSecretKey() { secretKey.Clear(); }
	StrPtr *	GetSecretKey() { return( &secretKey ); }
	void		SetPBuf( StrPtr &s ) { pBuf.Set( s ); }
	void		ClearPBuf() { pBuf.Clear(); }
	StrPtr *	GetPBuf() { return( &pBuf ); }

	void		SetTicketKey( const StrPtr *s ) { ticketKey.Set( *s ); }

        int             IsUnicode() { return is_unicode; }

	void		SetSyncTime( int t ) { syncTime = t; }
	int		GetSyncTime()        { return syncTime; }

	int		ServerDVCS() { return protocolServer >= 39; }

    public:
	// Old closure stuff, only used by scc api and to be retired

	void		*GetClosure() { return closure; }
	void		SetClosure( void *v ) { closure = v; }
	void		*closure;

    protected:
	virtual RpcType	GetRpcType()
	{
	    return RPC_CLIENT;
	}

    private:
	ClientUser	*tags[ClientTags];
	int		lowerTag;
	int		upperTag;
	int		authenticated;
	int		pubKeyChecked;

	RpcService	service;
	int		errors;
	int		fatals;
	Error		transErr;	// Last translation error

	StrBuf		charset;	// character set
	StrBuf		client;		// client's name
	StrBuf		clientPath;	// Authorized areas of the filesystem
	StrBuf		tempPath;	// Temp file directory
	StrBuf		cwd;		// current directory
	StrBuf		host;		// client host name
	StrBuf		os;		// client's OS
	StrBuf		programName;	// (optionally) set by SetProg()
	StrBuf		port;		// server address (P4PORT)
	StrBuf		serverID;	// server address (ID from server)
	StrBuf		user;		// user's name
	StrBuf		password;	// user's password
	StrBuf		password2;	// user's password (password is ticket)
	StrBuf		ticketKey;	// key used to look up ticket
	StrBuf		language;	// language for err messages
	StrBuf		ticketfile;	// alternate location for ticketfile
	StrBuf		trustfile;	// trusted finger print file
	StrBuf		secretKey;	// for salting password key
	StrBuf		pBuf;		// for salting password key
	StrBuf		loginSSO;	// single signon binary
	StrBuf		syncTrigger;	// sync trigger binary
	StrBuf		ignorefile;	// ignore filename
	StrBuf		exeName;
	StrBuf		charsetVar;
	StrBuf		initRoot;
	StrRef		buildInfo;

	Enviro		*enviro;	// environment vars
	Ignore		*ignore;	// naughty list
	StrBufDict	*extraVars;
	int      	ignoreList;	// environment vars to ignore
	int		is_unicode;	// talking in unicode mode
	int		hostprotoset;
	int		syncTime;
	int		ownEnviro;
	int		ownCwd;		// did someone else set cwd

	StrNum		protocolBuf;	// for our GetProtocol

	void		CleanupTrans();	// free translators
	void		SetupUnicode( Error * );
	void		LearnUnicode( Error * );
	void		LateUnicodeSetup( const char *, Error * );
} ;
