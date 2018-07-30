/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 */

/*
 * ErrorLog.cc - report layered errors
 */

# define NEED_SYSLOG
# define NEED_FLOCK
# define NEED_DBGBREAK
# define NEED_CRITSEC

# include <stdhdrs.h>
# include <strbuf.h>
# include <error.h>
# include <errorlog.h>
# include <fdutil.h>
# include <filesys.h>

/*
 * ErrorLog::errorLog - file where errors are written, type punned
 * ErrorLog::errorTag - string attached to reported errors
 */

Error AssertError;
ErrorLog AssertLog;

ErrorLog::ErrorLog( ErrorLog *from )
	: hook(NULL), context(NULL)
{
	errorFsys = 0;
	errorTag = from->errorTag;
	logType = from->logType;

	// clone errorFsys

	if( from->errorFsys && from->logType == type_none )
	{
	    errorFsys = FileSys::Create( FST_ATEXT );
	    errorFsys->Set( from->errorFsys->Name() );
	    errorFsys->Perms( FPM_RW );
	}		

	// We will not inherit the critical section.  We also do not create
	// a new one, as only AssertLog will be using a critical section.
	vp_critsec = 0;
}

ErrorLog::~ErrorLog()
{
	delete errorFsys;
	errorFsys = 0;

# ifdef HAVE_CRITSEC
	if( vp_critsec )
	{
	    CRITICAL_SECTION *critsec;

	    critsec = (CRITICAL_SECTION *)vp_critsec;
	    DeleteCriticalSection( critsec );
	    delete critsec;
	    vp_critsec = 0;
	}
# endif
}

/*
 * Error::SysLog() - OS style System Logger entry point.
 */

void
ErrorLog::SysLog( const Error *e, int tagged, const char *et, const char *buf )
{
	const char *errTag = errorTag;

	if( !errorTag )
	    init();

	if( et )
	    errTag = et;

# ifdef HAVE_SYSLOG
	// Default to LOG_DEBUG to maintain behavior from LogWrite.

	int level = LOG_DEBUG;

	// If severity defined, determine level accordingly.

	if( e )
	{
	    if( e->GetSeverity() != E_FATAL )
		level = LOG_WARNING;
	    else
		level = LOG_ERR;
	}

	/* char * cast for Lynx 4.0 */

	openlog( (char *)errTag, LOG_PID, LOG_DAEMON );
	if( tagged )
	    syslog( level, "%s: %s", e->FmtSeverity(), buf );
	else
	    syslog( LOG_WARNING, "%s", buf );
	closelog();
# endif

# ifdef HAVE_EVENT_LOG
	// Log a warning unless exiting, then log an error.
	// (can exit on E_FAILED, through ::Abort)

	WORD level = EVENTLOG_INFORMATION_TYPE;

	if( e )
	{
	    if( e->GetSeverity() != E_FATAL )
		level = EVENTLOG_WARNING_TYPE;
	    else
		level = EVENTLOG_ERROR_TYPE;
	}

	// Log the event to the Windows Application Event log.
	// We don't configure our event IDs in the registry or have
	// an event message resource.  Windows will preface our entry
	// with a silly warning message.

	HANDLE hEventSource = 
	    RegisterEventSource( NULL, errTag );

	LPTSTR  lpszStrings[1] = { (LPTSTR)buf };

	if( hEventSource != NULL )
	{
	    ReportEvent( 
		    hEventSource,	// handle of event source
		    level,		// event type
		    0,			// event category, (doesn't matter)
		    0,			// event ID
		    NULL,		// current user's SID, (let it default)
		    1,			// strings in lpszStrings
		    0,			// no bytes of raw data
		    (LPCTSTR *)lpszStrings,	// array of strings
		    NULL );		// no raw data

	    DeregisterEventSource(hEventSource);
	}
# endif // HAVE_EVENT_LOG

	return;
}

void
ErrorLog::init()
{
	logType = type_stderr;
	errorTag = "Error";
	errorFsys = 0;
	vp_critsec = 0;
}

void
ErrorLog::EnableCritSec()
{
# ifdef HAVE_CRITSEC
	if( vp_critsec == NULL )
	{
	    CRITICAL_SECTION *critsec;

	    critsec = new CRITICAL_SECTION;
	    InitializeCriticalSection( critsec );
	    vp_critsec = (void *)critsec;
	}
# endif
}

void
ErrorLog::Report( const Error *e, int reportFlags )
{
	if( e->GetSeverity() == E_EMPTY )
	    return;

	int tagged = reportFlags & REPORT_TAGGED;
	int hooked = reportFlags & REPORT_HOOKED;

	if( !errorTag )
	    init();

	StrBuf buf;

	e->Fmt( buf, tagged ? EF_INDENT | EF_NEWLINE : EF_NEWLINE );

# if defined( HAVE_SYSLOG ) || defined( HAVE_EVENT_LOG )
	if ( logType == type_syslog )
	{
	    SysLog( e, tagged, NULL, buf.Text() );
	    return;
	}
# endif
	if( tagged )
	{
	    StrBuf out;

	    out.Set( errorTag );
	    out.Extend( ' ' );
	    out.Append( e->FmtSeverity() );
	    out.Extend( ':' );
	    out.Extend( '\n' );
	    out.Append( &buf );
	    LogWrite( out );
	}
	else
	    LogWrite( buf );

	if( hook && hooked )
	    (*hook)( context, e );
}

void
ErrorLog::LogWrite( const StrPtr &s )
{
# if defined( HAVE_SYSLOG ) || defined( HAVE_EVENT_LOG )
	if ( logType == type_syslog )
	{
	    // Pass e=NULL and tagged=0 to maintain previous bahavior,
	    // see SysLog for details.

	    SysLog( NULL, 0, NULL, s.Text() );
	    return;
	}
# endif

	if( errorFsys )
	{
	    Error tmpe;

# ifdef HAVE_CRITSEC
	    if( vp_critsec )
	    {
		CRITICAL_SECTION *critsec;

		critsec = (CRITICAL_SECTION *)vp_critsec;
		EnterCriticalSection( critsec );
	    }
# endif

	    errorFsys->Open( FOM_WRITE, &tmpe );
	    if( !tmpe.Test() )
	    {
		errorFsys->Write( &s, &tmpe );
		errorFsys->Close( &tmpe );
	    }
	    if( tmpe.Test() )
	    {
		// An error was encountered when
		// attempting to write to the log.

# if defined( HAVE_SYSLOG ) || defined( HAVE_EVENT_LOG )

		// Write to syslog or the event log the original
		// message that was to be written to the log.
		SysLog( NULL, 0, NULL, s.Text() );

		// Write to syslog or the event log the error that was
		// encountered when attempting to write to the log.
		StrBuf buf;
		tmpe.Fmt( &buf );
		SysLog( &tmpe, 1, NULL, buf.Text() );

# endif

# ifndef OS_NT

		// Write to stderr the error that was encountered when
		// attempting to write to the log. stderr should be
		// well-defined on platforms other than Windows.
		ErrorLog tmpeel;
		tmpeel.SetTag( errorTag );
		tmpeel.Report( &tmpe );

# endif
	    }

# ifdef HAVE_CRITSEC
	    if( vp_critsec )
	    {
		CRITICAL_SECTION *critsec;

		critsec = (CRITICAL_SECTION *)vp_critsec;
		LeaveCriticalSection( critsec );
	    }
# endif

	    return;
	}

	// Under a Windows Service, stderr is not valid.  Observation
	// has shown that fileno(stderr) returns -2.  This is not detected
	// as an invalid file descriptor by the Posix checks.  I suppose
	// MS did this intentionally, just not sure why.
	//
	//   Unix logType defaults to type_stderr.
	//   Windows Services must call UnsetLogType().
	//

	if ( logType == type_stdout || logType == type_stderr )
	{
	    FILE *flog=stderr;

	    if( logType == type_stdout )
		flog = stdout;

	    // lock the file exclusive for this append,  some platforms
	    // don't do append correctly (you know who you are!)

	    int fd = fileno( flog );
	    lockFile( fd, LOCKF_EX );

	    fputs( s.Text(), flog );

	    /* Flush even if stderr, for NT's buffered stderr. */

	    fflush( flog );

	    lockFile( fd, LOCKF_UN );
	}
}

/*
 * Error::Abort() - blurt out an error and exit
 */

void
ErrorLog::Abort( const Error *e )
{
	if( !e->Test() )
	    return;

	Report( e );

# ifdef HAVE_DBGBREAK
	if( IsDebuggerPresent() )
	{
	    char msg[128];

	    // Notice p4diag this is a Process abort event.
	    sprintf (msg, "event: Process Abort");
	    OutputDebugString(msg);

	    // Under p4diag, create a strack trace and mini dump.
	    DebugBreak();
	}
# endif // HAVE_DBGBREAK

	exit(-1);
}

/*
 * ErrorLog::SetLog() - redirect Abort() and Report() to named file
 */

void
ErrorLog::SetLog( const char *file )
{
	// Redirect to syslog, stdout or stderr?

	if( !strcmp( file, "syslog" ) )
	{
	    logType = type_syslog;
	    return;
	}
	else if( !strcmp( file, "stdout" ) )
	{
	    logType = type_stdout;
	    return;
	}
	else if( !strcmp( file, "stderr" ) )
	{
	    logType = type_stderr;
	    return;
	}

	FileSys *fs = FileSys::Create( FST_ATEXT );
	Error e;

	fs->Set( file );

	fs->Perms( FPM_RW );

	fs->MkDir( &e );
	if( !e.Test() )
	    fs->Open( FOM_WRITE, &e );

	if( e.Test() )
	    AssertLog.Report( &e );
	else
	    UnsetLogType();

	fs->Close( &e );

	if( errorFsys )
	    delete errorFsys;

	errorFsys = fs;
}

void
ErrorLog::Rename( const char *file, Error *e )
{
	FileSys *fs = FileSys::Create( FST_ATEXT );
	fs->Set( file );

	errorFsys->Rename( fs, e );

	delete fs;
}

offL_t
ErrorLog::Size()
{
	if( !errorFsys )
	    return 0;

	Error e;
	errorFsys->Open( FOM_READ, &e );

	if( e.Test() )
	    return 0;

	offL_t size = errorFsys->GetSize();

	errorFsys->Close( &e );

	return size;
}

const char *
ErrorLog::Name()
{
	if( !errorFsys )
	    return 0;

	return errorFsys->Name();
}
