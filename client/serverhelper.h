/*
 * Copyright 1995, 2015 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# ifdef OS_NT
# define INIT_CONFIG "p4config.txt"
# define INIT_IGNORE "p4ignore.txt"
# define INIT_P4DEXE "p4d.exe"
# else
# define INIT_CONFIG ".p4config"
# define INIT_IGNORE ".p4ignore"
# define INIT_P4DEXE "p4d"
# endif

# define INIT_ROOT ".p4root"
# define INIT_SERVERID ".p4root/server.id"


enum ConfigureState
{
	EXISTS_TRUE		= 0x01,
	EXISTS_FALSE		= 0x02,
	EXISTS_MASK		= 0x03,

	DISCOVERED		= 0x02,
	WITHREMOTE		= 0x04,
	
	CREATED_SUCCESS		= 0x08,
	CREATED_FAIL		= 0x10,
	CREATED_MASK		= 0x18
};

class ServerHelper : public ClientUserProgress
{
    public:
			ServerHelper( Error *e );

	// The condensed calls required to both init and clone
	int		Exists( ClientUser *ui, Error *e );
	int		Discover( const StrPtr *port, ClientUser *ui,
			          Error *e );

	// Only call one of these!
	int		LoadRemote( const StrPtr *port, const StrPtr *remote,
			            ClientUser *ui, Error *e );
	int		MakeRemote( const StrPtr *port, const StrPtr *filePath,
			            ClientUser *ui, Error *e );

	// This creates the local server
	int		InitLocalServer( ClientUser *ui, Error *e );

	// Only call this if you've loaded or made a remote
	int		FirstFetch( int depth,
			            int noArchivesFlag,
			            const StrPtr *debugFlag,
			            ClientUser *ui, Error *e );


	// Helper methods
	void		InitClient( Client *client, int useEnv, Error *e );

	// Accessors for server and client info
	StrPtr		&GetDvcsDir()                 { return dir; }
	void		SetDvcsDir( const char *u )   { dir.Set( u ); }
	void		SetDvcsDir( const StrPtr *u ) { dir.Set( u ); }
	
	StrPtr		&GetUser()                    { return p4user; }
	void		SetUser( const char *u )      { p4user.Set( u ); }
	void		SetUser( const StrPtr *u )    { p4user.Set( u ); }

	StrPtr		&GetClient()                  { return p4client; }
	void		SetClient( const char *c )    { p4client.Set( c ); }
	void		SetClient( const StrPtr *c )  { p4client.Set( c ); }

	void		SetUserClient( const StrPtr *, const StrPtr * );

	StrPtr		&GetProg()                    { return prog; }
	void		SetProg( const char *p )      { prog.Set( p ); }
	void		SetProg( const StrPtr *p )    { prog.Set( p ); }

	StrPtr		&GetVersion()                 { return version; }
	void		SetVersion( const char *v )   { version.Set( v ); }
	void		SetVersion( const StrPtr *v ) { version.Set( v ); }
	
	StrPtr		&GetServerExecutable()        { return serverExe; }
	void		SetServerExecutable( const char *u )
			                              { serverExe.Set( u ); }
	void		SetServerExecutable( const StrPtr *u )
			                              { serverExe.Set( u ); }
	
	int		GetQuiet()                    { return quiet; }
	void		SetQuiet()                    { quiet = 1; }
	void		DoDebug( StrPtr *v )          { debug.Set( v ); }
	
	StrPtr		&GetPassword()                { return p4passwd; }
	void		SetPassword( const char *p )  { p4passwd.Set( p ); }
	void		SetPassword( const StrPtr *p ) { p4passwd.Set( p ); }
	
	void		SetDefaultStream( const StrPtr *s, Error *e );

	void		SetApplication( const StrPtr *a ){ app.Set( a ); }

	void		SetCaseFlag( const StrPtr *c, Error *e );
	StrPtr		GetCaseFlag() { return caseFlag; }

	void		SetUnicode( int u ) { unicode = u; }
	int		Unicode() { return unicode; }
	
	
	StrPtr		&GetCharset()                 { return charset; }
	void		SetCharset( const char *c )   { charset.Set( c ); }
	void		SetCharset( const StrPtr *c ) { charset.Set( c ); }
	void		SetTrans( int output, int content = -2,
			          int fnames = -2, int dialog = -2 );
	int		GetTrans( int &output, int &content, int &fnames,
			          int &dialog );


	// Discovered only data accessors
	StrPtr		UserName()	{ return userName; }
	StrPtr		Server()	{ return serverAddress; }
	int		FetchAllowed()	{ return fetchAllowed; }
	int		Security()	{ return security; }

	// Process status accessors
	int		GotError() { return commandError.Test(); }
	void		ClearError() { commandError.Clear(); }
	Error		*GetError() { return &commandError; }

	// ClientUser callbacks - Must be public
	void		OutputStat( StrDict *varList ); 
	void		OutputError( const char *errBuf );
	void		OutputText( const char *data, int length );
	void		OutputInfo( char level, const char *data );
	void		InputData( StrBuf *strbuf, Error *e );
	int		ProgressIndicator();
	ClientProgress *CreateProgress( int t );

    private:

	// Support methods

	void		WriteConfig( Error *e );
	int		CreateLocalServer( ClientUser *ui, Error *e );
	int		PostInit( ClientUser *ui );
	void		WriteIgnore( Error *e );

	void		GetStreamName( StrBuf *filePath, StrPtr &val );
	int		TooWide( const char *s, int levels, int exact );
	int		InvalidChars( const char *s, int l );
	const char	*Trim( StrPtr &filePath, StrPtr &val );


	// p4 client context
	StrBuf		prog;
	StrBuf		version;
	StrBuf		config;
	StrBuf		ignore;
	StrBuf		ignoreFile;
	StrBuf		p4user;
	StrBuf		p4client;
	StrBuf		p4passwd;
	int		state;
	
	void		SetupUnicode( Client *client, Error *e );
	StrBuf		charset;
	int		hasTrans;
	int		outputTrans;
	int		contentTrans;
	int		fnamesTrans;
	int		dialogTrans;
	StrBuf		app;

	// p4 server context
	StrBuf		pwd;
	StrBuf		dir;
	StrBuf		p4port;
	StrBuf		serverExe;
	StrBuf		defaultStream;
	int		defaultStreamChanged;

	// p4 info (potentially discovered)
	int		unicode;
	int		security;
	StrBuf		caseFlag;;
	StrBuf		serverAddress;
	int		fetchAllowed;

	// Remote accessors
	StrPtr		Description() { return description; }
	void		SetDescription( const char *d ) 
			    { description.Set( d ); }
	StrBufDict	*GetStreams() { return &mainlines; }
	StrBufDict	*Dict() { return &remoteMap; }
	StrBufDict	*ArchiveLimits() { return &archiveLimits; }
	int		NeedLogin(){ return needLogin; }
	
	int		StreamExists( StrPtr &filePath );
	int		MaxChange() { return maxCommitChange; }

	// p4 remote
	StrBuf		remoteName;
	StrBufDict	remoteMap;
	StrBufDict	archiveLimits;
	StrBuf		depotName;
	StrBuf		remoteOptions;
	StrBuf		description;
	StrBuf		inputData;
	StrBuf		userName;
	int		needLogin;

	// p4 counter
	int		maxCommitChange;
	
	// streams
	StrBufDict	mainlines;

	// command tracking
	void		SetCommand( const char *p, ClientUser *ui )
			    { command.Set( p ); slaveUi = ui; }
	StrPtr		&GetCommand() { return command; }

	StrBuf		command;
	ClientUser	*slaveUi;
	Error		commandError;
	StrBuf		debug;
	int		quiet;

} ;
