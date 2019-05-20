/*
 * Copyright 1995, 2003 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * RunCommand() -- Just run a command and capture its output
 */

# define NEED_ERRNO
# define NEED_FILE
# define NEED_FCNTL
# define NEED_POPEN
# define NEED_FORK
# define NEED_SOCKETPAIR
# define NEED_SLEEP

#include <sys/types.h>
#include <signal.h>

# include <stdhdrs.h>

# include <strbuf.h>
# include <strops.h>
# include <error.h>

# include <pathsys.h>
# include <filesys.h>

# include "strarray.h"
# include <runcmd.h>

/*
 * RunCommand::SetArgs() - clear buffer and add (quoted) args 
 * RunCommand::AddArg() - add (quoted) arg to buffer
 */

# ifdef OS_VMS
# define QUOTE ""
# endif
# if defined (OS_OS2) || defined (OS_NT)
# define QUOTE "\""
# endif
# ifndef QUOTE
# define QUOTE "'"
# endif

// max number of cmdline args + 1
# define CMD_ARGSIZE	1024

void
RunArgs::SetArgs( int argc, const char * const *argv )
{
	buf.Clear();

	while( argc-- )
	    AddArg( *argv++ );
}

void
RunArgs::AddArg( const char *arg )
{
	AddArg( StrRef( arg ) );
}

void
RunArgs::AddArg( const StrPtr &arg )
{
	// Space before 2nd+ args

	if( buf.Length() )
	    buf << " ";

	// Quote args with spaces. On AS400 & NT, quote everything unless it
	// starts with a quote already.

# if defined (OS_AS400) || defined (OS_NT)
	if( arg[0] == '"' )
# else
	if( !memchr( arg.Text(), ' ', arg.Length() ) )
# endif
	    buf << arg;
	else
	    buf << QUOTE << arg << QUOTE;
}

void
RunArgs::AddCmd( const char *arg )
{
	const char *p = arg;

#if OS_NT
	// Try to distinguish a command with spaces in it from a 
	// command followed by flags.  We do so by looking for a
	// - or a / introducing the flags.  Everything before is
	// a single command name, which can get quoted by AddArg().

	while( ( p = strchr( p, ' ' ) ) && !strchr( "-+/", p[1] ) )
	    p = p + 1;
#else
	p = strchr( p, ' ' );
#endif

	// p = the first command flag, or nul if none
	// Add arg up to this flag, and then look for next.

	while( p ) 
	{
	    AddArg( StrRef( arg, p - arg ) );
	    p = strchr( arg = p + 1, ' ' );
	}

	AddArg( StrRef( arg ) );
}

int
RunArgs::Argc( char **argv, int nargs )
{
	return StrOps::Words( argbuf, buf.Text(), argv, nargs );
}

/*
 * Argv-based version of RunArgs
 */

RunArgv::RunArgv()
{
    args = new StrArray();
}

RunArgv::~RunArgv()
{
    delete args;
}

void
RunArgv::SetArgs( int argc, const char * const *argv )
{
	while( argc-- )
	    AddArg( *argv++ );
}

void
RunArgv::AddArg( const char *arg )
{
	AddArg( StrRef( arg ) );
}

void
RunArgv::AddArg( const StrPtr &arg )
{
	args->Put()->Set(arg);
}

void
RunArgv::AddCmd( const char *arg )
{
	const char *p = arg;

#if OS_NT
	// Try to distinguish a command with spaces in it from a
	// command followed by flags.  We do so by looking for a
	// - or a / introducing the flags.  Everything before is
	// a single command name, which can get quoted by AddArg().

	while( ( p = strchr( p, ' ' ) ) && !strchr( "-+/", p[1] ) )
	    p = p + 1;
#else
	p = strchr( p, ' ' );
#endif

	// p = the first command flag, or nul if none
	// Add arg up to this flag, and then look for next.

	while( p )
	{
	    AddArg( StrRef( arg, p - arg ) );
	    p = strchr( arg = p + 1, ' ' );
	}

	AddArg( StrRef( arg ) );
}

/**
 * Fill in the output array with a C-style char *[] from our args,
 * suitable for execv().
 */
int
RunArgv::Argc( char **argv, int nargs )
{
	int	count = args->Count();
	if( nargs <= count)
	{
	    // don't scribble past the end of the array
	    // it would be nice to throw an exception here ...
	    count = nargs-1;
	}

	for( int i = 0; i < count; i++ )
	{
	    argv[i] = args->Get(i)->Text();
	}
	argv[count] = NULL;

	return count;
}

/**
 * Copy all the args into the provided buf and NUL-terminate.
 * Quote any args containing spaces (very crude).
 */
char *
RunArgv::Text(
        StrBuf  &buf)
{
        buf.Clear();

	for( int i = 0; i < args->Count(); i++)
	{
            if( i > 0 )
            {
                buf.Append( " " );
            }
	    const StrBuf
			*argbuf = args->Get(i);

	    if( strchr(argbuf->Text(), ' ') )
	    {
                buf.Append( QUOTE );
                buf.Append( argbuf->Text() );
                buf.Append( QUOTE );
	    }
	    else
	    {
                buf.Append( argbuf->Text() );
	    }
	}
        buf.Terminate();

	return buf.Text();
}

/*
 *
 * NT 
 *	RunCommand::Run
 *	RunCommand::RunInWindow
 *	RunCommand::RunChild
 *	RunCommand::WaitChild
 *	RunCommand::PollChild
 *
 */

# ifdef OS_NT 

# define HAVE_RUN
# define HAVE_RUNINWINDOW
# define HAVE_RUNCHILD

# define WIN32_LEAN_AND_MEAN
# include <windows.h>

/*
 * RunProcess - do NT's CreateProcess. The WaitForMultipleObjects dance
 *              is now finished in the caller.  This requires the caller
 *              to process output on the caller created pipe.
 */

enum RunProcessMode { RPM_Normal, RPM_Silent, RPM_Window, RPM_Detach };

PROCESS_INFORMATION *
RunProcess( 
	char *commandText,	// really should be const char *, but CreateProcess wants LPSTR
	RunProcessMode mode,
	HANDLE inputHandle,
	HANDLE outputHandle,
	HANDLE stderrHandle,
	Error *e )
{
	// The proc structure is freed in WaitChild().

	PROCESS_INFORMATION *ProcInfo;
	ProcInfo = (PROCESS_INFORMATION *)malloc(sizeof(PROCESS_INFORMATION));
	memset( (void *)ProcInfo, 0, sizeof( PROCESS_INFORMATION ) );

	// Run the sucker
	// Must inherit handles for stdout to work

	STARTUPINFO StartInfo = {0};

	StartInfo.cb = sizeof( StartInfo );
	StartInfo.lpReserved = NULL;
	StartInfo.lpTitle = NULL;
	StartInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	StartInfo.wShowWindow = SW_SHOW;

	StartInfo.hStdInput = inputHandle;
	StartInfo.hStdOutput = outputHandle;
	StartInfo.hStdError = stderrHandle;

	DWORD creationFlags = NORMAL_PRIORITY_CLASS;

	// Must be true to inherit startinfo handles.

	BOOL inheritHandles = TRUE;

	// New window?  If so, don't inherit handles, as stdout 
	// means nothing and we don't want this long-term process 
	// holding our fds. If the parent process is a service, any 
	// inherited fds may not work in the new window.

	switch( mode )
	{
	case RPM_Silent:
	    StartInfo.wShowWindow = SW_HIDE;
	    break;

	case RPM_Window:
	    inheritHandles = FALSE;
	    creationFlags |= CREATE_NEW_CONSOLE;
	    // Standard handles will not be inherited.
	    StartInfo.dwFlags &= ~STARTF_USESTDHANDLES;
	    break;

	case RPM_Detach:
	    creationFlags |= DETACHED_PROCESS;
	    break;
	}

	if( !CreateProcess( 
		NULL,			// application name
		commandText,		// command line string
		NULL,			// process security attributes
		NULL,			// thread security attributes
		inheritHandles,		// inherit handles
		creationFlags,		// creation flags
		NULL,			// new environment block
		NULL,			// startup directory
		&StartInfo,		// startup info structure
		ProcInfo		// process info, returned
		) )
	{
	    // We collect the error here and process it later.

	    e->Sys( "Execution Failed", commandText );
	    free( ProcInfo );
	    return 0;
	}

	return ProcInfo;
}

RunCommand::RunCommand()
{
	pid = 0;
	abandon = false;
}

RunCommand::~RunCommand()
{
	if( !abandon )
	    WaitChild();
}

int
RunCommand::Run( RunArgs &command, Error *e )
{
	// Run and wait for the subprocess to exit.

	pid = RunProcess(
		    command.Text(),
		    RPM_Normal,
		    GetStdHandle( STD_INPUT_HANDLE ),
		    GetStdHandle( STD_OUTPUT_HANDLE ),
		    GetStdHandle( STD_ERROR_HANDLE ),
		    e );

	if( e->Test() )
	    return -1;

	return WaitChild();
}

int
RunCommand::Run( RunArgv &command, Error *e )
{
	// Run and wait for the subprocess to exit.

	StrBuf  buf;

	pid = RunProcess(
		    command.Text(buf),
		    RPM_Normal,
		    GetStdHandle( STD_INPUT_HANDLE ),
		    GetStdHandle( STD_OUTPUT_HANDLE ),
		    GetStdHandle( STD_ERROR_HANDLE ),
		    e );

	if( e->Test() )
	    return -1;

	return WaitChild();
}

int
RunCommand::RunInWindow( RunArgs &command, Error *e )
{
	// Don't pass stdin, stdout to a standalone window as it
	// should not hold our fds. If process is launched from
	// a service, inherited fds may not have an association with
	// with the user's desktop and wouldn't work as expected.

	// We don't wait for the subprocess to exit, so unless the launch
	// failed we'll assume the command ran ok.

	pid = RunProcess(
		    command.Text(),
		    RPM_Window,
		    NULL,
		    NULL,
		    NULL,
		    e );

	if( e->Test() )
	    return -1;

	return 0;
}

int
RunCommand::RunInWindow( RunArgv &command, Error *e )
{
	// Don't pass stdin, stdout to a standalone window as it
	// should not hold our fds. If process is launched from
	// a service, inherited fds may not have an association with
	// with the user's desktop and wouldn't work as expected.

	// We don't wait for the subprocess to exit, so unless the launch
	// failed we'll assume the command ran ok.

	StrBuf  buf;

	pid = RunProcess(
		    command.Text(buf),
		    RPM_Window,
		    NULL,
		    NULL,
		    NULL,
		    e );

	if( e->Test() )
	    return -1;

	return 0;
}

void
RunCommand::RunChild( RunArgs &cmd, int ops, int fds[2], Error *e )
{
	DoRunChild( cmd.Text(), NULL, ops, fds, e );
}

void
RunCommand::RunChild( RunArgv &cmd, int ops, int fds[2], Error *e )
{
	StrBuf  buf;

	DoRunChild( cmd.Text(buf), NULL, ops, fds, e );
}

// On Windows, char *argv[] is NULL and not used -- we execute cmdText instead
void
RunCommand::DoRunChild( char *cmdText, char *argv[], int ops, int fds[2], Error *e )
{
	/*
	 * Windows doesn't have socketpair(), so use separate pipes.
	 * We use pipe(), rather than CreatePipe(), because we need fds.
	 *
	 * rp = read pipe (from subprocess' stdout)
	 * wp = write pipe (to subprocess' stdin)
	 */

	int rp[2], wp[2];
	HANDLE	outHandle;
	HANDLE	errHandle;
	
	// Return read/write pipe to caller/parent via fds[].
	//
	// Child process will not inherit fds[1], parent's writer.
	// Always create the subprocess' stdin pipe, wp[0].

	if( _pipe( wp, 8192, O_BINARY ) < 0 )
	{
	    e->Sys( "pipe", "" );
	    return;
	}
	fds[1] = wp[1];
	SetHandleInformation( (HANDLE)_get_osfhandle( wp[1] ), 
		HANDLE_FLAG_INHERIT, 0 );

	if( ops & RCO_USE_STDOUT )
	{
	    // Use parent's stdout/stderr for the subprocess' stdout/stderr.

	    fds[0] = -1;
	    outHandle = GetStdHandle( STD_OUTPUT_HANDLE );
	    errHandle = GetStdHandle( STD_ERROR_HANDLE );
	}
	else
	{
	    // Setup a pipe to collect stdout from the subprocess.
	    // Child process will not inherit fds[0], parent's reader.

	    if( _pipe( rp, 8192, O_BINARY ) < 0 )
	    {
		e->Sys( "pipe", "" );
		return;
	    }
	    fds[0] = rp[0];
	    SetHandleInformation( (HANDLE)_get_osfhandle( rp[0] ), 
		HANDLE_FLAG_INHERIT, 0 );

	    outHandle = (HANDLE)_get_osfhandle( rp[1] );
	    errHandle = (HANDLE)_get_osfhandle( rp[1] );
	}

	// The Server can emit logging on stderr, if using p4 rpc
	// protocol avoid redirecting stderr to the protocol stream.

	if( ops & RCO_P4_RPC )
	    errHandle = GetStdHandle( STD_ERROR_HANDLE );

	// Processes run as a shell can't be run as detached processes

	RunProcessMode rpm = ( ops & RCO_AS_SHELL ) ? RPM_Silent : RPM_Detach;

	// Don't wait for the subprocess to exit.
	// Callers can use WaitChild() if they want to see status.

	pid = RunProcess(
			cmdText,
			rpm,
			(HANDLE)_get_osfhandle( wp[0] ),
			outHandle,
			errHandle,
			e );

	// Only the parent will be running this code.
	// Close the subprocess' end of the pipes, wp[0] and rp[1].

	close( wp[0] );
	if( ~ops & RCO_USE_STDOUT )
	    close( rp[1] );

	if( e->Test() )
	{
	    // We close off the parent's pipes since WaitChild()
	    // may never be called when process creation fails.
	    // Leave error set to indicate process creation failed.

	    if( ~ops & RCO_USE_STDOUT )
		{ close( fds[0] ); fds[0] = -1; }
	    close( fds[1] ); fds[1] = -1;
	}
}

int
RunCommand::WaitChild()
{
	// If pid is NULL, there was no subprocess.

	if( !pid )
	    return 0;

	PROCESS_INFORMATION *ProcInfo = (PROCESS_INFORMATION *)pid;

	// Wait for the process.

	DWORD status = -1;

	if( WaitForMultipleObjects( 
		1,				// # of handles
		&ProcInfo->hProcess,		// handle array
		TRUE,				// wait on all
		INFINITE			// wait forever
		) != WAIT_FAILED )
	{
	    GetExitCodeProcess( ProcInfo->hProcess, &status );
	}

	// You have to close these together, ask Bill.
	// Closing these handles, releases the subprocess.

	CloseHandle( ProcInfo->hThread );
	CloseHandle( ProcInfo->hProcess );
	free( ProcInfo );
	pid = 0;

	return status;
}

/*
 * Returns false if the child process is still alive, else returns true.
 * Also returns false if there's an error and we can't tell whether or not
 * the child is still alive.
 * Does *NOT* reap the child; you still need to call WaitChild() for that.
 */
bool
RunCommand::PollChild(unsigned long millisecs) const
{
	// If pid is NULL, there was no subprocess.
	if( !pid )
	    return true;

	PROCESS_INFORMATION *ProcInfo = (PROCESS_INFORMATION *)pid;
	DWORD status = -1;
	bool ret = false;

	if( WaitForMultipleObjects( 
		1,				// # of handles
		&ProcInfo->hProcess,		// handle array
		TRUE,				// wait on all
		millisecs			// wait specified time
		) != WAIT_FAILED )
	{
	    ret = GetExitCodeProcess( ProcInfo->hProcess, &status );
	}

	if( !ret )
	    return false;

	return status != STILL_ACTIVE;
}

void
RunCommand::StopChild()
{
	if( !pid )
	    return;

	TerminateProcess( pid, 1 );
}

# else

bool
RunCommand::PollChild(unsigned long millisecs) const
{
	// If pid is NULL, there was no subprocess.
	if( !pid )
	    return true;

	int r = waitpid( pid, NULL, WNOHANG );

	if( r > 0 )
	    return true;

	msleep( millisecs );

	r = waitpid( pid, NULL, WNOHANG );

	if( r == -1 || r == 0 )
	    return false;

	return true;
}

void
RunCommand::StopChild()
{
	if( !pid )
	    return;

	kill( pid, SIGTERM );
}

# endif

/*
 *
 * MaxOSX 
 *	RunCommand::RunInWindow
 *
 */

# ifdef OS_MACOSX

# define HAVE_RUNINWINDOW

# include <i18napi.h>
# include <macutil.h>

int
RunCommand::RunInWindow( RunArgs &command, Error *e )
{
	if( getenv( "DISPLAY" ) )
	{
	    // xterm variety
	    // to launch in background

	    command << "&";
	    return system( command.Text() );
	}
	else if( WindowServicesAvailable() )
	{
	    RunCommandInNewTerminal( command.Text() );
	}

	return 0;
}

int
RunCommand::RunInWindow( RunArgv &command, Error *e )
{
	StrBuf  buf;

	if( getenv( "DISPLAY" ) )
	{
	    // xterm variety
	    // to launch in background

	    command << "&";
	    return system( command.Text(buf) );
	}
	else if( WindowServicesAvailable() )
	{
	    RunCommandInNewTerminal( command.Text(buf) );
	}

	return 0;
}

# endif

/*
 *
 * UNIX 
 *	RunCommand::RunChild 
 *
 */

# ifdef HAVE_FORK
# ifndef HAVE_RUNCHILD
# define HAVE_RUNCHILD

void
RunCommand::RunChild( RunArgs &cmd, int opts, int fds[2], Error *e )
{
	// Set up for direct execvp.
	// We used to use 'sh -c cmd' for RCO_AS_SHELL, but we removed
	// the shell execution since it exposed a security risk (job020599)

	char *argv[CMD_ARGSIZE];
	int argc;

	argc = cmd.Argc( argv, CMD_ARGSIZE );
	argv[argc] = 0;
	DoRunChild( cmd.Text(), argv, opts, fds, e);
}

/**
 * Almost exact copy of the RunArgs version of RunChild(), but takes a RunArgv
 * rather than a RunArgs.
 */
void
RunCommand::RunChild( RunArgv &cmd, int opts, int fds[2], Error *e )
{
	// Set up for direct execvp.
	// We used to use 'sh -c cmd' for RCO_AS_SHELL, but we removed
	// the shell execution since it exposed a security risk (job020599)

	char *argv[CMD_ARGSIZE];
	int argc;

	argc = cmd.Argc( argv, CMD_ARGSIZE );
	argv[argc] = 0;

	StrBuf  buf;
	DoRunChild( cmd.Text(buf), argv, opts, fds, e );
}

/**
 * Code common to the two flavors of RunChild()
 */
void
RunCommand::DoRunChild( char *cmdText, char *argv[], int opts, int fds[2], Error *e )
{
	// Create an error pipe which allows the subprocess to report
	// to the parent that the exec failed.  The parent reads from
	// this pipe after the fork.  If the exec succeeds the pipe
	// will break allowing the parent to continue.  If the exec fails
	// the subprocess sends errno through the pipe to the parent.

	int errchk[2];
	if( pipe( errchk ) < 0 )
	{
	    e->Sys( "pipe", "" );
	    return;
	}
	fcntl( errchk[1], F_SETFD, 1 );

	/*
	 * rp = read pipe (from subprocess' stdout)
	 * wp = write pipe (to subprocess' stdin)
	 */

	int rp[2], wp[2];

	// if RCO_USE_STDOUT
	// Create wp for subprocess' stdin/parent's stdout, wp[0]/wp[1].

	if( opts & RCO_USE_STDOUT )
	{
	    if( pipe( wp ) < 0 )
	    {
		e->Sys( "pipe", "" );
		return;
	    }
	}
	else
# ifdef HAVE_SOCKETPAIR

	// We use socketpair if SOLO_FD is set, so that a single
	// fd is the read/write to the child.  That's because
	// our NetStdioEndpoint::Accept() just uses fd 0 for I/O.

	if( opts & RCO_SOLO_FD )
	{
	    if( socketpair( AF_UNIX, SOCK_STREAM, 0, rp ) < 0 )
	    {
		e->Sys( "socketpair", "" );
		return;
	    }

	    wp[1] = dup( rp[0] );
	    wp[0] = dup( rp[1] );
	}
	else

# endif
	// default
	// Create rp for parent's stdin/subprocess' stdout, rp[0]/rp[1].
	// Create wp for subprocess' stdin/parent's stdout, wp[0]/wp[1].

	{
	    if( pipe( rp ) < 0 || pipe( wp ) < 0 )
	    {
		e->Sys( "pipe", "" );
		return;
	    }
	}

	// Return parent's read/write descriptors via fds[0]/fds[1].
	// Tell subprocess to close off parent end of pipes, close
	// on exec.  (1 is FD_CLOEXEC)

	if( opts & RCO_USE_STDOUT )
	    rp[0] = rp[1] = -1;
	else
	    fcntl( rp[0], F_SETFD, 1 );
	fcntl( wp[1], F_SETFD, 1 );

	// Assign parent's stdin/stdout fds[0]/fds[1]

	fds[0] = rp[0];
	fds[1] = wp[1];

	// UNIX wizardry, entry level.

	StrBuf buf;

	switch( pid = fork() )
	{
	case -1:
	    e->Sys( "fork", "" );
	    break;

	case 0:
	    // child

	    // Close the parent's side of the error pipe.

	    close( errchk[0] );

	    // Set stdin to wp[0]

	    if( 0 != wp[0] )
		{ close( 0 ); dup( wp[0] ); close( wp[0] ); }

	    // Set stdout to rp[1] and maybe stderr to rp[1]

	    if( !( opts & RCO_USE_STDOUT ) && 1 != rp[1] )
	    {
		close( 1 ); dup( rp[1] );

		// The Server can emit logging on stderr, if using p4 rpc
		// protocol avoid redirecting stderr to the protocol stream.

		if( ~opts & RCO_P4_RPC )
		    { close( 2 ); dup( rp[1] ); }

		close( rp[1] );
	    }

	    execvp( argv[0], argv );

	    // Send errno and the nil.

	    buf = StrNum( errno );
	    write( errchk[1], buf.Text(), buf.Length()+1 );

	    _exit( -1 );
	    break;

	default:
	    // parent

	    // Close the subprocess' side of the error pipe.

	    close( errchk[1] );

	    break;
	}

	// Only the parent will be running this code.

	if( ! e->Test() )
	{
	    // Read the error pipe for a possible exec error.

	    int len;
	    buf.Clear();
	    buf.Alloc(16);

	    if( (len = read( errchk[0], buf.Text(), 8 )) > 0 )
	    {
		errno = buf.Atoi();
		e->Sys( "Execution Failed", cmdText );
	    }

	}

	close( errchk[0] );

	// Close the subprocess' end of the pipes, wp[0] and rp[1].

	close( wp[0] );
	if( ~opts & RCO_USE_STDOUT )
	    close( rp[1] );

	// If in error, close off the parent's end of the pipes.

	if( e->Test() )
	{
	    if( ~opts & RCO_USE_STDOUT )
		{ close( fds[0] ); fds[0] = -1; }
	    close( fds[1] ); fds[1] = -1;
	}
}

int
RunCommand::WaitChild()
{
	// The fork() or execvp() failed, nothing to wait for.

	if( !pid )
	    return 0;

	int status = 0;
	int rtn;

	for( ;; )
	{
	    rtn = waitpid( pid, &status, 0 );

	    // application might be catching signals,  in that case
	    // the waitpid() could get interrupted - make sure we can
	    // restart.

	    if( rtn < 0 && errno == EINTR )
	        continue;

	    break;
	}

	pid = 0;

	return ( rtn < 0 ) ? rtn : WEXITSTATUS(status);
}

# endif
# endif

/*
 *
 * Defaults 
 *	RunCommand::Run
 *	RunCommand::RunInWindow
 *	RunCommand::RunChild
 *	RunCommand::WaitChild
 *
 */

# ifndef HAVE_RUN

RunCommand::RunCommand()
{
# ifdef HAVE_FORK
	pid = 0;
	abandon = false;
# endif
}

RunCommand::~RunCommand()
{
	if( !abandon )
	    WaitChild();
}

int
RunCommand::Run( RunArgs &command, Error *e )
{
	return system( command.Text() );
}

int
RunCommand::Run( RunArgv &command, Error *e )
{
	StrBuf  buf;

	return system( command.Text(buf) );
}

# endif

# ifndef HAVE_RUNINWINDOW

int
RunCommand::RunInWindow( RunArgs &command, Error *e )
{
	// simply append & to run in background.
	// We don't wait (no way to).  So our parent
	// (init?) may reap child status.

	return Run( command << "&", e );
}

int
RunCommand::RunInWindow( RunArgv &command, Error *e )
{
	// simply append & to run in background.
	// We don't wait (no way to).  So our parent
	// (init?) may reap child status.

	return Run( command << "&", e );
}

# endif

# ifndef HAVE_RUNCHILD

void
RunCommand::RunChild( RunArgs &cmd, int opts, int fds[2], Error *e )
{
        e->Set( E_FAILED, "No RunChild() available!\n" );
}

void
RunCommand::RunChild( RunArgv &cmd, int opts, int fds[2], Error *e )
{
        e->Set( E_FAILED, "No RunChild() available!\n" );
}

int
RunCommand::WaitChild()
{
	return 0;
}

# endif

/*
 *
 * RunCommandIo::Run() -- generic version built upon RunChild()
 *
 */

RunCommandIo::RunCommandIo()
{
	fds[0] = fds[1] = -1;
}

RunCommandIo::~RunCommandIo()
{
	if( fds[0] != -1 ) close( fds[0] );
	if( fds[1] != -1 ) close( fds[1] );
}

/*
 * RunCommandIo::Write() - write the the running command's stdin
 */

void
RunCommandIo::Write( const StrPtr &in, Error *e )
{
	// Send stdin

	if( write( fds[1], in.Text(), in.Length() ) < 0 )
	    e->Sys( "write", "command" );
}

/*
 * RunCommandIo::Read() - internal read with error checking
 */

int
RunCommandIo::Read( char *buf, int len, Error *e )
{
	// Close write fd before reading.

	if( fds[1] != -1 )
	{
	    close( fds[1] );
	    fds[1] = -1;
	}

	// Already done?

	if( fds[0] == -1 )
	    return 0;

	int l = read( fds[0], buf, len );

	if( l < 0 )
	{
	    e->Sys( "read", "command" );
	    return -1;
	}
	else if( !l )
	{
	    close( fds[0] );
	    fds[0] = -1;
	}

	return l;
}

/*
 * RunCommandIo::ReadError() - read a little and see if command failed
 *
 * Reads a buffer's worth of commands output and if it hits EOF checks
 * to see if the command exited non-zero.  If so, returns that buffer
 * as error output.  If the command outputs a full buffer's worth, or
 * exits zero, the buffered data is saved for the next Read() call and
 * ReadError() returns zero.
 */

StrPtr *
RunCommandIo::ReadError( Error *e )
{
	errBuf.Clear();
	int len = 4096;

	while( len )
	{
	    int l;

	    if( ( l = Read( errBuf.Alloc( len ), len, e ) ) < 0 )
		return 0;

	    len -= l;

	    errBuf.SetLength( errBuf.Length() - len );

	    if( !l )
		break;
	}

	if( !len || !WaitChild() )
	    return 0;

	StrOps::StripNewline( errBuf );

	return &errBuf;
}

/*
 * RunCommandIo::Read() - read from the running command's stdout
 */

int
RunCommandIo::Read( const StrPtr &out, Error *e )
{
	// If anything buffered from ReadError, return it first.

	if( errBuf.Length() )
	{
	    int l = errBuf.Length() < out.Length() 
		  ? errBuf.Length() : out.Length() - 1;

	    StrRef( errBuf.Text(), l ).StrCpy( out.Text() );

	    // copy up remainder

	    errBuf.Set( StrRef( errBuf.Text() + l, errBuf.Length() - l ) );

	    return l;
	}

	// Read stdout into result buffer
	// Close read fd at end of reading.

	return Read( out.Text(), out.Length(), e );
}

/*
 * RunCommandIo::Run() - run the command, sending stdin, capturing stdout. 
 */

int
RunCommandIo::Run( RunArgs &command, const StrPtr &in, StrBuf &out, Error *e )
{
	// Run command, capturing stdout
	// Stderr goes to process's stderr

	RunChild( command, RCO_AS_SHELL, fds, e );

	return ProcessRunResults( in, out, e );
}

/*
 * RunCommandIo::Run() - RunArgv version of Run().
 */

int
RunCommandIo::Run( RunArgv &command, const StrPtr &in, StrBuf &out, Error *e )
{
	// Run command, capturing stdout
	// Stderr goes to process's stderr

	RunChild( command, RCO_AS_SHELL, fds, e );

	return ProcessRunResults( in, out, e );
}

int
RunCommandIo::ProcessRunResults( const StrPtr &in, StrBuf &out, Error *e )
{
	if( e->Test() )
	    return -1;

	out.Clear();

	// Send stdin

	if( in.Length() )
	    Write( in, e );

	if( e->Test() )
	{
	    e->Fmt( &out );
	    e->Clear();
	}

	// Read stdout into result buffer

	for(;;)
	{
	    const int len = 1024;

	    int l = Read( StrRef( out.Alloc( len ), len ), e );

	    if( e->Test() )
		return -1;

	    if( l >= 0 )
		out.SetLength( out.Length() - len + l );

	    if( l <= 0 )
		break;
	}

	// The above Read closed both parent read and write fds.

	// Collect exit status

	int status = WaitChild();

	if( status && !out.Length() )
	    out << "no error message";

	// Strip any trailing newline

	StrOps::StripNewline( out );

	return status;
}
