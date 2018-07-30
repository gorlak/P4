/*
 * Copyright 1995, 2009 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * This is a client program to tail a server journal using
 * the export command.  Those journal records can go to a file
 * and to a child process or stdout.  Position state is maintained
 * in a file.  Some care is taken to identify when the journal
 * is complete in the sense of no outstanding transactions.
 */

# define NEED_SLEEP
# define NEED_FILE

# include <clientapi.h>
# include <debug.h>
# include <error.h>
# include <errorlog.h>
# include <options.h>
# include <runcmd.h>
# include <i18napi.h>
# include <enviro.h>
# include <signaler.h>

static ErrorId intervalerror = { ErrorOf( 0, 0, E_FATAL, 0, 0 ),
			  "interval must be zero or positive" };

static ErrorId intervalneeded = { ErrorOf( 0, 0, E_FATAL, 0, 0 ),
			  "Restart on error requires a positive interval" };

class ClientUserJournal : public ClientUser {
    public:
	ClientUserJournal() : outfd(-1), journalno(0), sequence(0),
			      errorseen(0), dataseen(0), rotateseen(0),
			      restartOnError(0), rc(NULL), savedjournal(NULL) {}

	~ClientUserJournal() { delete rc; delete savedjournal; }

	void	OutputStat( StrDict * );
	void	OutputError( const char * );

	void	SetStateFile( const StrPtr *, Error * );
	void	UpdateStateFile( Error *, const StrPtr * = NULL );

	void	SetOutputCommand( int ac, char **av );

	void	Output( const StrPtr &, Error *e );
	void	EndCommand();

	int	outfd;
	int	journalno;
	offL_t	sequence;
	int	errorseen;
	int	dataseen;
	int	rotateseen;
	int	restartOnError;
	StrBuf	statefile;
	RunArgs rargs;
	RunCommand *rc;
	FileSys *savedjournal;
};

void
ClientUserJournal::Output( const StrPtr &dat, Error *e )
{
	if( savedjournal )
	    savedjournal->Write( dat.Text(), dat.Length(), e );

	if( rc )
	{
	    if( outfd == -1 )
	    {
		int fds[2];

		rc->RunChild( rargs, RCO_AS_SHELL|RCO_USE_STDOUT, fds, e );
		if( e->Test() )
		{
		    errorseen = 1;
		    return;
		}
		outfd = fds[1];
	    }
	    int w = write( outfd, dat.Text(), dat.Length() );
	    if( w < 0 )
		e->Sys("write", "pipe");
	}
	else
	    printf( "%.*s", static_cast<int>(dat.Length()), dat.Text() );

	dataseen = 1;
}

void
ClientUserJournal::EndCommand()
{
	if( outfd >= 0 )
	{
	    close( outfd );
	    outfd = -1;
	    if( rc->WaitChild() )
		errorseen = 4;
	}
}

void
ClientUserJournal::OutputStat( StrDict *vars )
{
	Error e;
	StrPtr *dat;

	if( errorseen )
	    return;

	StrPtr *pos = vars->GetVar( "pos" );
	if( pos )
	{
	    // journal no should not change, but we'll
	    // take it anyways
	    journalno = pos->Atoi();
	    sequence = 0;
	    const char *cp = pos->Contains( StrRef( "/" ) );
	    if( cp )
		sequence = StrPtr::Atoi64( ++cp );
	}

	dat = vars->GetVar( P4Tag::v_data );
	if( dat && dat->Length() > 0 )
	{
	    StrPtr *complete = vars->GetVar( "complete" );

	    if( complete )
	    {
		int s = complete->Atoi();

		Output( StrRef( dat->Text(), s ), &e );

		if( pos )
		    UpdateStateFile( &e, pos );

		if( s < dat->Length() )
		    Output( StrRef( dat->Text() + s, dat->Length() - s ), &e );
	    }
	    else
		Output( *dat, &e );

	    if( e.Test() )
	    {
		AssertLog.Report( &e );
		errorseen = 2;
		return;
	    }
	}

	dat = vars->GetVar( P4Tag::v_counter );
	if( dat )
	{
	    // skip to next journal
	    journalno = dat->Atoi();
	    sequence = 0;
	    // I believe that we must be at a complete and consistent point
	    // for a journal rotation to occur so this should be safe...
	    UpdateStateFile( &e );
	    rotateseen = 1;
	}
}

void
ClientUserJournal::OutputError( const char *msg )
{
	ClientUser::OutputError( msg );
	errorseen = 1;
}

void
ClientUserJournal::SetStateFile( const StrPtr *fname, Error *e )
{
	statefile.Set( fname );

	FileSys *f = FileSys::Create( FST_TEXT );
	f->Set( statefile );
	f->Open( FOM_READ, e );
	if( !e->Test() )
	{
	    StrBuf buf;

	    f->ReadWhole( &buf, e );
	    f->Close( e );

	    journalno = buf.Atoi();
	    const char *cp;
	    if( cp = buf.Contains( StrRef( "/" ) ) )
		sequence = StrPtr::Atoi64( ++cp );
	}
	e->Clear();
	delete f;
}

void
ClientUserJournal::UpdateStateFile( Error *e, const StrPtr *pos )
{
	if( errorseen || !dataseen || !statefile.Length() )
	    return;

	FileSys *f = FileSys::Create( FST_TEXT );
	f->Set( statefile );
	FileSys *t = FileSys::Create( FST_TEXT );
	t->MakeLocalTemp( f->Name() );
	t->SetDeleteOnClose();
	t->Open( FOM_WRITE, e );
	if( e->Test() )
	    errorseen = 3;
	else
	{
	    StrBuf buf;

	    if( !pos )
	    {
		buf << journalno << "/" << StrNum( sequence ) << "\n";
		pos = &buf;
	    }
	    t->Write( pos->Text(), pos->Length(), e );
	    t->Perms( FPM_RW );
	    t->Close( e );
	    if( !e->Test() )
		t->Rename( f, e );
	}
	delete t;
	delete f;
}

void
ClientUserJournal::SetOutputCommand( int ac, char **av )
{
	// setup command invocations
	rargs.SetArgs( ac, av );
	rc = new RunCommand;
}

void
cntlc( void *v )
{
	ClientUserJournal *ui = (ClientUserJournal *)v;

	ui->errorseen = 1;
	ui->restartOnError = 0;
}

int
jtail( int ac, char **av, Options &preopts, Options &opts,
	const char *progname )
{
	Error e;
	StrPtr *s;
	int ret;
	int interval = 2;
	int keepopen = 0;
	int exitOnRotate = 0;

	// Debugging 

	for( int i = 0; s = preopts.GetValue( 'v', i ); i++ )
	    p4debug.SetLevel( s->Text() );

	ClientUserJournal ui;

	if( opts[ 'k' ] )
	    keepopen = 1;

	if( opts[ 'x' ] ) 
	    exitOnRotate = 1;

	if( opts[ 'R' ] )
	    ui.restartOnError = 1;

	if( opts[ 'o' ] )
	{
	    ui.savedjournal = FileSys::Create( FST_ATEXT );
	    ui.savedjournal->Set( *opts[ 'o' ] );
	    ui.savedjournal->Open( FOM_WRITE, &e );
	    if( e.Test() )
	    {
		delete ui.savedjournal;
		ui.savedjournal = NULL;
		AssertLog.Report( &e );
		return 1;
	    }
	    ui.savedjournal->Perms( FPM_RW );
	}

	const StrPtr *statefile = opts[ 's' ];
	if( statefile )
	    ui.SetStateFile( statefile, &e );

	const StrPtr *jop = opts[ 'j' ];
	if( jop )
	{
	    ui.journalno = jop->Atoi();
	    const char *cp;
	    if( cp = jop->Contains( StrRef( "/" ) ) )
		ui.sequence = StrPtr::Atoi64( ++cp );
	    if( ui.journalno < 0 )
		ui.journalno = 0;
	    if( ui.sequence < 0 )
		ui.sequence = 0;
	}

	if( opts[ 'i' ] )
	    interval = opts[ 'i' ]->Atoi();

	if( interval < 0 )
	{
	    e.Set( intervalerror );
	    AssertLog.Report( &e );
	    return 1;
	}

	if( ui.restartOnError && interval <= 0 )
	{
	    e.Set( intervalneeded );
	    AssertLog.Report( &e );
	    return 1;
	}

	if( ac > 0 )
	    ui.SetOutputCommand( ac, av );

	const StrPtr *tableBlock = opts[ 'T' ];

	const StrPtr *prefixop = opts[ 'J' ];

	Signaler sig;

	sig.OnIntr( cntlc, (void *)&ui );

	do {
	    ClientApi client;

	    Enviro enviro;
	    const char *lc;
	    enviro.Config( client.GetCwd() );
	    if( s = preopts[ 'C' ] )
		lc = s->Text();
	    else
		lc = enviro.Get( "P4CHARSET" );

	    CharSetApi::CharSet cs = CharSetApi::NOCONV;

	    if( lc )
	    {
		cs = CharSetApi::Lookup( lc );

		if( (int)cs == -1 )
		{
		    // bad charset specification
		    printf( "Character set must be one of:\n"
		        "none, auto, utf8, utf8-bom, iso8859-1, shiftjis, eucjp, iso8859-15,\n"
		        "iso8859-5, macosroman, winansi, koi8-r, cp949, cp1251,\n"
		        "utf16, utf16-nobom, utf16le, utf16le-bom, utf16be,\n"
		        "utf16be-bom, utf32, utf32-nobom, utf32le, utf32le-bom, utf32be,\n"
			"utf32be-bom, utf8unchecked, utf8unchecked-bom,\n"
			"cp936, cp950, cp1253, or iso8859-7.\n"
		        "Check P4CHARSET and your '-C' option.\n" );
		    return 1;
		}
		else
		{
		    CharSetApi::CharSet ws = cs;

		    if( ( s = preopts[ 'Q' ] ) ||
		    ( lc = enviro.Get( "P4COMMANDCHARSET" ) ) )
		    {
			if( s )
			    lc = s->Text();
			cs = CharSetApi::Lookup( lc );
			if( (int)cs == -1 )
			{
			    printf( "P4COMMANDCHARSET unknown\n" );
			    return 1;
			}
		    }
		    if( CharSetApi::Granularity( cs ) != 1 )
		    {
			printf( "p4 can not support a wide charset unless\n"
			    "P4COMMANDCHARSET is set to another charset.\n" );
			return 1;
		    }
		    client.SetTrans( cs, ws, cs, cs );
		}
	    }

	    if( s = preopts[ 'u' ] ) client.SetUser( s );
	    if( s = preopts[ 'p' ] ) client.SetPort( s );
	    if( s = preopts[ 'P' ] ) client.SetPassword( s );

	    e.Clear();
	    ui.errorseen = 0;
	    client.Init( &e );

	    if( e.Test() )
	    {
		AssertLog.Report( &e );
		if( ui.restartOnError )
		{
		    e.Clear();
		    fflush( stdout );
		    sleep( interval );
		    delete ui.savedjournal;
		    ui.savedjournal = NULL;
		    continue;
		}
		return 1;
	    }

	    client.SetProg( progname );

	    // if in unicode mode, remove translations to get unchanged
	    // journal records
	    if( cs != CharSetApi::NOCONV )
		client.SetTrans( CharSetApi::UTF_8_UNCHECKED );

	    for( ;; )
	    {
		StrBuf buf;

		buf << ui.journalno << "/" << StrNum( ui.sequence );

		client.SetVar( StrRef::Null(), StrRef( "-r" ) );
		client.SetVar( StrRef::Null(), StrRef( "-j" ) );
		client.SetVar( StrRef::Null(), buf );

		if( prefixop )
		{
		    client.SetVar( StrRef::Null(), StrRef( "-J" ) );
		    client.SetVar( StrRef::Null(), *prefixop );
		}

		if( tableBlock )
		{
		    client.SetVar( StrRef::Null(), StrRef( "-T" ) );
		    client.SetVar( StrRef::Null(), *tableBlock );
		}

		client.Run( "export", &ui );

		if( ui.errorseen || !keepopen || interval == 0
			|| ( exitOnRotate && ui.rotateseen ) )
		    ui.EndCommand();

		if( ui.errorseen || e.Test() || interval == 0 ||
			( exitOnRotate && ui.rotateseen ) )
		{
		    if( ui.restartOnError && interval > 0 )
			sleep( interval );
		    break;
		}

//	    We should only update the state file on complete transactions
//	    This used to happen here, but now only happens in OutputStat

		fflush( stdout );
		sleep( interval );
	    }

	    client.Final( &e );

	    if( e.Test() )
	    {
		ui.EndCommand();
		AssertLog.Report( &e );
	    }

	    ret = ui.errorseen;

	} while( ui.restartOnError && ! ( exitOnRotate && ui.rotateseen ) );

	delete ui.savedjournal;
	ui.savedjournal = 0;

	return ret;
}

#ifdef BUILD_JTAIL

static ErrorId usage = { ErrorOf( 0, 0, 0, 0, 0),
	"p4jtail [ -p port ][ -u user ][ -P password ][ -C charset ]\n"
	"        [ -j token ][ -s statefile ][ -i interval ][ -k -x -R ]\n"
	"        [ -J prefix ][ -T tables excluded ][ -o output ][ command ]\n"
};

int
main( int ac, char **av )
{
	AssertLog.SetTag( "p4jtail" );

	Error e;

	Options opts;

	opts.Parse( --ac, ++av, "xkj:i:J:s:u:p:P:v:o:C:Q:T:R",
		OPT_ANY, usage, &e );

	if( e.Test() )
	{
	    AssertLog.Report( &e );
	    return 1;
	}

	return jtail( ac, av, opts, opts, "p4jtail" );
}

#endif
