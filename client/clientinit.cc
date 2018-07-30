/*
 * Copyright 1995, 2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * clientinit() - Perforce client DVCS init
 *
 */

# define NEED_CHDIR
# define NEED_TYPES
# define NEED_STAT
# define NEED_FLOCK

# include <stdhdrs.h>

# include <strbuf.h>
# include <strdict.h>
# include <strtable.h>
# include <error.h>
# include <options.h>
# include <rpc.h>

# include <filesys.h>
# include <handler.h>

# include <msgclient.h>

# include "client.h"
# include "clientuser.h"
# include "serverhelper.h"

static ErrorId cloneHelp = { ErrorOf( 0, 0, E_INFO, 0, 0),
"\n"
"	clone -- Clone a new personal server from a shared server\n"
"\n"
"	p4 [-u user][-d dir][-c client] clone [-m depth -v -p port] -r remote\n"
"	p4 [-u user][-d dir][-c client] clone [-m depth -v -p port] [-f] file\n"
"\n"
"	This command initializes a new Perforce repository in the current\n"
"	directory (or the directory specified by the -d flag).\n"
"\n"
"	In order to run 'p4 clone', you must have up-to-date and matching\n"
"	versions of the 'p4' and 'p4d' executables in your operating system\n"
"	path. You can download these executables from http://www.perforce.com\n"
"\n"
"	Perforce database files will be stored in the directory named\n"
"	\".p4root\". Perforce configuration settings will be stored in\n"
"	P4CONFIG and P4IGNORE files in the top level of your directory.\n"
"	It is not necessary to view or update these files, but you should\n"
"	be aware that they exist.\n"
"\n"
"	The -m flag performs a shallow fetch; only the last number of\n"
"	specified revisions of each file are fetched.\n"
"\n"
"	The -p flag specifies the address of the target server you wish\n"
"	to clone from, overriding the value of $P4PORT in the environment\n"
"	and the default (perforce:1666).\n"
"\n"
"	The -r flag specifies a remote spec installed on the remote server\n"
"	to use as a template for the clone and stream setup. See 'p4 help\n"
"	remote' for more information about how the clone command interprets\n"
"	the remote spec during the setup steps.\n"
"\n"
"	The -f flag specifies a file pattern in the remote server to use as\n"
"	the path to clone; this file specification will also be used to\n"
"	determine the stream setup in the local server.\n"
"\n"
"	The -v flag specifies verbose mode.\n"
"\n"
"	When the clone completes, a default remote spec will be created,\n"
"	called origin. To update your local repository with the latest\n"
"	changes from the target server, run 'p4 fetch'.\n"
"\n"
"	For more information about using Perforce, run 'p4 help' after you\n"
"	have run 'p4 clone', or visit http://www.perforce.com.\n"
};

static ErrorId initHelp = { ErrorOf( 0, 0, E_INFO, 0, 0),
"\n"
"	init -- Initialize a new personal server.\n"
"\n"
"	p4 [-u user][-d dir][-c client] init [-hq][-c stream][-p port]\n"
"	p4 [-u user][-d dir][-c client] init [-hq][-c stream][-Cx -xi -n]\n"
"\n"
"	This command initializes a new Perforce repository in the current\n"
"	directory (or the directory specified by the -d flag).\n"
"\n"
"	In order to run 'p4 init', you must have up-to-date and matching\n"
"	versions of the 'p4' and 'p4d' executables in your operating system\n"
"	path. You can download these executables from http://www.perforce.com\n"
"\n"
"	Perforce database files will be stored in the directory named\n"
"	\".p4root\". Perforce configuration settings will be stored in\n"
"	P4CONFIG and P4IGNORE files in the top level of your directory.\n"
"	It is not necessary to view or update these files, but you should\n"
"	be aware that they exist.\n"
"\n"
"	After initializing your new repository, run 'p4 reconcile' to mark\n"
"	all of your source files to be added to Perforce, then 'p4 submit'\n"
"	to submit them.\n"
"\n"
"	The -c flag configures the installation to create the specified stream\n"
"	as the mainline stream rather than the default '//stream/main'.\n"
"\n"
"	The -p flag specifies the address of a target server you wish to\n"
"	discover the case sensitivity and unicode settings from. This will\n"
"	make your local repository compatible with that server.\n"
"\n"
"	The -q flag suppresses informational messages (including if\n"
"	p4 init has already been run.)\n"
"\n"
"	The -Cx flag sets the case sensitivity of the new Perforce\n"
"	installation. You may specify either -C0 or -C1. The -C0 flag\n"
"	specifies case-sensitive operation; the -C1 flag specifies\n"
"	case-insensitive operation. (See discovery note below).\n"
"\n"
"	The -n flag configures the installation without unicode support.\n"
"	The -xi flag configures the installation with unicode support.\n"
"	Without -n or -xi, the installation will decide on unicode support\n"
"	based on the P4CHARSET enviroment being set.\n"
"\n"
"	Note: If neither -Cx, -xi or -n flags are set, init will try and\n"
"	discover the correct settings from a server already set in your\n"
"	environment.  If init cannot find a server then it will fail\n"
"	initialization.\n"
"\n"
"	For more information about using Perforce, run 'p4 help' after you\n"
"	have run 'p4 init', or visit http://www.perforce.com.\n"
};

static ErrorId initUsage = { ErrorOf( 0, 0, E_FAILED, 0, 0),
	"Usage: p4 [-u user][-d dir][-c client] init [-hq][-c stream][-p port | -Cx -xi -n]\n"
	"\tUse p4 init -h for detailed help."
};

static ErrorId cloneUsage = { ErrorOf( 0, 0, E_FAILED, 0, 0),
	"Usage: p4 [-u user][-d dir][-c client] clone [-p <port>] [-m depth -v][-r <remote> | [-f] filespec]\n"
	"\tUse p4 clone -h for detailed help."
};

static ErrorId initUnicodeMixup = { ErrorOf( 0, 0, E_FAILED, 0, 0),
	"p4 init does not allow '-n' and '-xi' to be used together"
};

static ErrorId initCaseFlagMixup = { ErrorOf( 0, 0, E_FAILED, 0, 0),
	"Specify either -C0 or -C1."
};

static ErrorId initServerFail = { ErrorOf( 0, 0, E_FAILED, 0, 0),
	"\np4d server failed to initialize.  A 2015.1 or later p4d server\n"
	"must be in your path and runable."
};

static ErrorId pasiveDiscoverFail  = { ErrorOf( 0, 0, E_FAILED, 0, 0 ),
	"No available server to discover configuration, needs flags to\n"
	"specify case sensitivity and Unicode settings:\n"
	"p4 init [-C0|-C1]   (case-sensitive or case-insensitive)\n"
	"p4 init [-xi|-n]    (with Unicode support or without it)\n"
	"Note, it is important to initialize with the same case sensitivity\n"
	"and Unicode settings as the server you wish to push/fetch from.\n"
	"For more information, run: 'p4 help init'."
};


static ErrorId discoverSucceeded   = { ErrorOf( 0, 0, E_INFO, 0, 3 ),
    "Matching server configuration from '%port%':\n"
    "%case%, %unicode%"
};

static ErrorId discoverUnknownUser = { ErrorOf( 0, 0, E_WARN, 0, 1 ),
    "warning: your user '%user%' unknown at this server!"
};

static void
SetProgAndVersion( ServerHelper *clone )
{
	StrBuf v;
	v << ID_REL "/" << ID_OS << "/" << ID_PATCH;
	clone->SetVersion( v.Text() );
	clone->SetProg( "p4" );
}

int
clientInitHelp( int doClone, Error *e )
{
	ClientUser cuser;
	e->Set( doClone ? cloneHelp : initHelp );
	cuser.Message( e );
	e->Clear();
	return 0;
}


int clientInitInit( int ac, char **av, Options &preops, Error *e );
int clientInitClone( int ac, char **av, Options &preops, Error *e );

int
clientInit( int ac, char **av, Options &preops, int doClone, Error *e )
{
	if( doClone )
	    return clientInitClone( ac, av, preops, e );
	else
	    return clientInitInit(  ac, av, preops, e );
}


int
clientInitInit( int ac, char **av, Options &preops, Error *e )
{
	Options opts;
	ClientUserProgress cuser;
	StrPtr *sp;
	StrPtr *port = 0;
	int unicode = -1;
	StrPtr *caseflag = 0;
	int ecode = 0;
	Error e1;

	int longOpts[] = { Options::Help, Options::Quiet, 0 };

	opts.ParseLong( ac, av, "hp:c:nqC#x:", longOpts, OPT_NONE, initUsage,
	                e );

	if( e->Test() )
	    return 1;

	if( opts[ 'h' ] )
	    return clientInitHelp( 0, e );

	if( opts['p'] && ( opts['x'] || opts['n'] || opts['C'] ) )
	    e->Set( initUsage );
	
	if( e->Test() )
	    return 1;

	ServerHelper ruser( e );
	if( e->Test() )
	    return 1;
	
	SetProgAndVersion( &ruser );

	// Set the DVCS directory
	if( ( sp = preops['d'] ) )
	    ruser.SetDvcsDir( sp );
	
	// Set the P4CHARSET
	if( ( sp = preops[ 'C' ] ) )
	    ruser.SetCharset( sp );

	if( ( sp = preops['v'] ) )
	    ruser.DoDebug( sp );

	// turn-on quiet mode
	if( opts['q'] )
	    ruser.SetQuiet();

	// Set the port
	if( ( sp = opts['p'] ) || ( sp = preops['p'] ))
	    port = sp;
	
	// Was case sensitivity specified on the commandline?
	if( ( caseflag = opts['C'] ) )
	{
	    // Validate it now (it'll be overriden by the Discover())
	    ruser.SetCaseFlag( caseflag, e );
	    if( e->Test() )
	    {
	        e->Clear();
	        e->Set( initCaseFlagMixup );
	    }
	}
	
	// Set the default stream
	if( !e->Test() && ( sp = opts['c'] ) )
	    ruser.SetDefaultStream( sp, e );

	if( e->Test() )
	    goto finish;

	// Was unicode specified on the commandline?
	if( ( sp = opts[ 'x' ] ) && sp->Text()[0] == 'i' )
	{
	    unicode = 1;
	    if( opts[ 'n' ] )
	    {
	        e->Set( initUnicodeMixup );
	        goto finish;
	    }
	}
	if( opts[ 'n' ] )
	    unicode = 0;

	// Set the username and client
	// If null pointers are passed, the values come from the envrionment
	ruser.SetUserClient( preops['u'], preops['c'] );

	// check if already initialized
	// P4INITROOT and .p4root dir
	if( ruser.Exists( &cuser, &e1 ) || ruser.GotError() )
	{
	    ecode = 1;
	    goto finish;
	}

	// If there're any gaps in our configuration, query the server to
	// fill in the gaps

	if( !( ( opts['x'] || opts['n'] ) && opts['C'] ) )
	    ruser.Discover( port, &cuser, &e1 );

	if( unicode >= 0 )
	    ruser.SetUnicode( unicode );
	if( caseflag )
	    ruser.SetCaseFlag( caseflag, e );

	if( !( ( opts['x'] || opts['n'] ) && opts['C'] ) )
	{
	    if( ruser.GotError() )
	    {
	        if( !opts['p'] )
	        {
	            // passive discovery failed, require options
	            ruser.ClearError();
	            e->Clear();
	            e->Set( pasiveDiscoverFail );
	        }
	        ecode = 1;
	        goto finish;
	    }
	    else if( !e->Test() )
	    {
	        e->Set( discoverSucceeded );
	        *e << ruser.Server();
	        if( ruser.GetCaseFlag() == "-C0" )
	            *e << "case-sensitive (-C0)";
	        else
	            *e << "case-insensitive (-C1)";
	        if( ruser.Unicode() )
	            *e << "unicode (-xi)";
	        else
	            *e << "non-unicode (-n)";
	        cuser.Message( e );
	        e->Clear();

	        if( ruser.UserName() == "*unknown*" )
	        {
	            e->Set( discoverUnknownUser ) << ruser.GetUser();
	            cuser.Message( e );
	            e->Clear();
	        }
	    }
	}
	else
	    ruser.ClearError();
	
	// Error messages flush before printing, but info's do not
	// flush now so that the message order is correct.
	fflush( stderr );

	// Make it happen...
	ecode = ruser.InitLocalServer( &cuser, &e1 );

finish:
	if( e->Test() )
	{
	    cuser.Message( e );
	    ecode = 1;
	    e->Clear();
	}
	else if( ruser.GotError() )
	    cuser.Message( ruser.GetError() );

	return ecode;
}

int
clientInitClone( int ac, char **av, Options &preops, Error *e )
{
	Options opts;
	ClientUserProgress cuser;
	StrPtr *sp;
	StrPtr *port = 0;
	int depth = 0;
	int ecode = 0;
	Error e1;

	int longOpts[] = { Options::Help, Options::Quiet, 0 };

	opts.ParseLong( ac, av, "Ahp:r:f:m#v", longOpts, OPT_OPT, cloneUsage,
	                e );

	if( e->Test() )
	    return 1;

	if( opts[ 'h' ] )
	    return clientInitHelp( 1, e );

	StrPtr *remoteSpec = opts[ 'r' ];
	StrPtr *fileSpec   = opts[ 'f' ];
	StrBuf filePattern;

	if( ( fileSpec || remoteSpec ) && ac )
	{
	    e->Set( cloneUsage );
	    return 1;
	}

	if( !fileSpec && ac )
	{
	    filePattern.Set( av[0] );
	    fileSpec = &filePattern;
	}

	if( (  remoteSpec &&  fileSpec ) ||
	    ( !remoteSpec && !fileSpec ) )
	        e->Set( cloneUsage );
	
	if( e->Test() )
	    return 1;

	ServerHelper ruser( e );
	if( e->Test() )
	    return 1;
	
	SetProgAndVersion( &ruser );

	// Set the DVCS directory
	if( ( sp = preops['d'] ) )
	    ruser.SetDvcsDir( sp );

	// Set the P4PASSWD
	if( ( sp = preops[ 'P' ] ) )
	    ruser.SetPassword( sp );

	// Set the P4CHARSET
	if( ( sp = preops[ 'C' ] ) )
	    ruser.SetCharset( sp );

	// turn-off quiet mode
	if( ( sp = preops['v'] ) )
	    ruser.DoDebug( sp );

	// Set the port
	if( ( sp = opts['p'] ) || ( sp = preops['p'] ) )
	    port = sp;

	// Set the clone depth
	if( ( sp = opts['m'] ) )
	    depth = sp->Atoi();

	// icmanage (-Zapp=icmanage)
	for( int i = 0; sp = preops.GetValue( 'Z', i ); i++ )
	{
	    if( !strncmp( sp->Text(), "app=", 4 ) )
	        ruser.SetApplication( sp );
	}

	// Set the username and client
	// If null pointers are passed, the values come from the envrionment
	ruser.SetUserClient( preops['u'], preops['c'] );

	// check if already initialized
	// P4INITROOT and .p4root dir
	if( ruser.Exists( &cuser, &e1 ) || ruser.GotError() )
	{
	    ecode = 1;
	    goto finish;
	}
	
	// Get the remote, or build our own
	if( remoteSpec )
	    ruser.LoadRemote( port, remoteSpec, &cuser, &e1 );
	if( fileSpec )
	    ruser.MakeRemote( port, fileSpec, &cuser, &e1 );

	if( ruser.GotError() )
	{
	    ecode = 1;
	    goto finish;
	}

	// Make it happen...

	if( !( ecode = ruser.InitLocalServer( &cuser, &e1 ) ) )
	{
	    if( !e->Test() )
	        ruser.FirstFetch( depth, opts[ 'A' ] ? 1 : 0, opts['v'],
	                          &cuser, &e1 );
	}

finish:
	if( e->Test() )
	{
	    cuser.Message( e );
	    ecode = 1;
	    e->Clear();
	}
	else if( ruser.GotError() )
	    cuser.Message( ruser.GetError() );

	return ecode;
}
