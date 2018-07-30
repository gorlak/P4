/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * Threader.cc -- handle multiple users at the same time
 */

# define NEED_SIGNAL
# define NEED_FORK
# define NEED_SLEEP
# define NEED_ERRNO
# define NEED_THREADS
# define NEED_FCNTL

# include <stdhdrs.h>
# include <pid.h>

# include <strbuf.h>
# include <error.h>
# include <errorlog.h>
# include <msgserver.h>
# include <datetime.h>
# include <threading.h>

/*
 * Regarding GetThreadCount:
 *
 * Different threaders maintain their thread counts in different ways. The
 * implementations all try to keep an accurate thread count, but it is
 * possible that the thread count could be inaccurate. Callers of this method
 * should try to use the information primarily for monitoring and diagnosis,
 * and for performance analysis.
 *
 * Currently, GetThreadCount is used for:
 * - server.maxcommands,
 * - thread high-water-mark tracing in the server log
 */

/*
 *
 * Threader - single Threader
 *
 */

Threader::~Threader()
{
}

void
Threader::Launch( Thread *t )
{
	threadCount++;
	t->Run();
	threadCount--;
	delete t;
}

void
Threader::Cancel()
{
	cancelled = 1;
	process->Cancel();
}

void
Threader::Restart()
{
	restarted = 1;
	process->Cancel();
}

void
Threader::Quiesce()
{
	// no special work for single threading
}

void
Threader::Reap()
{
	// no special termination for single threading
}

int
Threader::GetThreadCount()
{
	return threadCount;
}

/*
*
* MultiThreader - threading on NT, using (uh) threads
*
*/

# ifdef OS_NT

# define HAVE_MULTITHREADER

# define WIN32_LEAN_AND_MEAN
# include <windows.h>
# include <process.h>
# include "ntthdlist.h"

static NtThreadList *NT_ThreadList = 0;

unsigned int WINAPI
NtThreadProc( void *param )
{
	Thread *t = (Thread *)param;

	// Since we are running in the same address space as parent
	// process we don't want to call DisService.

	NT_ThreadList->AddThread( t, GetCurrentThreadId() );

	t->Run();

	if( !NT_ThreadList->RemoveThread( t ) )
	{
	    Error e;
	    char msg[128];

	    sprintf( msg, "Can't remove thread entry %d", GetCurrentThreadId() );
	    e.Set( E_FATAL, msg );
	    AssertLog.Report( &e );
	}

	delete t;
	_endthreadex(0);

	return 0;
}

class MultiThreader : public Threader {

    public:

	MultiThreader( ThreadMode tmb )
	{
	    delete NT_ThreadList;
	    NT_ThreadList = new NtThreadList();
	}

	void Launch( Thread *t )
	{
	    unsigned int ThreadId;

	    HANDLE h = (HANDLE)_beginthreadex(
		    NULL,
		    0,
		    NtThreadProc,
		    (void *)t,
		    0,
		    &ThreadId );

	    if( !h )
	    {
		// create thread failed
		Error e;


		e.Sys( "_beginthreadex()", "NtThreadProc" );
		e.Set( E_FATAL, "Can't create process" );
		AssertLog.Report( &e );

		delete t;
		return;
	    }

	    CloseHandle( h );
	}

	// By now threads have been notified to self terminate.
	// We wait 15 seconds for the thread count to go to 0.
	// In practice most threads will terminate immediately.
	// Any hold out threads will have to be suspended in Reap.
	// Windows "net stop" can timeout if we take too long.

	void Quiesce()
	{
	    Error e;
	    DateTime date;
	    StrBuf dt;

	    date.SetNow();
	    date.Fmt( dt.Alloc( DateTimeBufSize ) );

	    e.Set( MsgServer::Quiescing ) 
		<< dt.Text()
		<< Pid().GetProcID()
		<< GetThreadCount();
	    AssertLog.Report( &e );

	    int retries = 0;
	    while( ! NT_ThreadList->Empty() && retries++ < 15 )
		sleep( 1 );
	    if( retries < 15 )
		return;

	    e.Clear();
	    e.Set( MsgServer::QuiesceFailed )
		<< dt.Text()
		<< Pid().GetProcID();
	    AssertLog.Report( &e );
	}

	// Locks have been taken, threads should not proceed further.
	// Continue with the restart if there are no hold out threads,
	// otherwise suspend any hold out threads and shutdown.

	void Reap()
	{
	    if( NT_ThreadList->Empty() )
		return;

	    if( restarted )
	    {
		Error e;
		DateTime date;
		StrBuf dt;

		date.SetNow();
		date.Fmt( dt.Alloc( DateTimeBufSize ) );

		e.Set( MsgServer::ReDowngrade ) 
		    << dt.Text()
		    << Pid().GetProcID();
		AssertLog.Report( &e );

	        restarted = 0;
	        cancelled = 1;
	    }

	    NT_ThreadList->SuspendThreads();
	}

	int GetThreadCount()
	{
	    return NT_ThreadList->GetThreadCount();
	}
} ;

# endif

# ifdef OS_BEOS

# define HAVE_MULTITHREADER

# include <OS.h>

static status_t
BeOSRunBinder( void *param )
{
	Thread *t = (Thread *)param;

	// Since we are running in the same address space as parent
	// process we don't want to call DisService.

	t->Run();
	delete t;

	return B_OK;
}

class MultiThreader : public Threader {

    public:

	MultiThreader( ThreadMode tmb )
	{
	}

	void Launch( Thread *t )
	{
	    thread_id threadID;

	    threadID = spawn_thread(
			BeOSRunBinder, "p4d task",
			B_NORMAL_PRIORITY,
		    	(void *)t);

	    if( threadID < 0 )
	    {
		// Create thread failed;
		t->Run();
		delete t;
		return;
	    }

	    resume_thread(threadID);
	}

	int GetThreadCount() { return -1; } // not implemented on BEOS
} ;

# endif /* OS_BEOS */

/*
 *
 * MultiThreader - multi Threader on God-fearing UNIX
 *
 * Everything is easy in the forking scheme, except termination.
 *
 * Launching is done by forking.  We catch SIGCHILD just to do the
 * requisite wait() calls to reap the child's exit status.
 *
 * Termination is orchestrated by the parent.  If a child's Cancel()
 * is called, it makes itself immune from SIGTERM and then send SIGTERM
 * to its parent.  The parent, on SIGTERM, resends SIGTERM to its process
 * group, killing everyone.  Why doesn't the child just send SIGTERM to
 * the process group?  Not sure yet.
 *
 * Restart is like termination, but it uses SIGHUP, not SIGTERM.
 */

# if defined( SIGCHLD ) && \
    !defined( OS_BEOS ) && \
    !defined( OS_AS400 ) && \
    !defined( OS_VMS )

# define HAVE_MULTITHREADER
# define HAVE_SIGHUP_HANDLER

/* For MVS, which must have different C/C++ linkage */
/* This precludes making them static, alas */

extern "C" void HandleSigChld( int flag );
extern "C" void HandleSigTerm( int flag );
extern "C" void HandleSigHup( int flag );

static int *threadCountPtr = 0;

void
HandleSigChld( int flag )
{
	int status;
	pid_t pid;

# if defined(OS_CYGWIN) || defined(OS_LINUX26)
	// Cygwin (2.95.3) doesn't restore errno on return from interrupt.
	// This leads accept() to return ECHILD rather than EINTR.

	int save_errno = errno;
# endif
	/*
	 * Note: Changed waitpid code below from waiting on all child processes
	 * (-1) to waiting on processes in process group (0). This change protects
	 * the child process p4zk which detaches itself from the parent's process
	 * group. When p4d is restarting we want to kill all child processes but
	 * keep the p4zk process going. (If invoking shutdown, p4zk will notice
	 * when connection to p4d closes and will exit)
	 */
	while( ( pid = waitpid( (pid_t)0, &status, WNOHANG ) ) > 0 )
	{
	    if( threadCountPtr )
	        --(*threadCountPtr);

	    if( WIFSIGNALED( status ) )
	    {
		Error e;
	        if( WTERMSIG( status ) != SIGTERM )
		    e.Set( E_FATAL,
	                   "Process %pid% exited on a signal %signal%!" );
	        else
		    e.Set( E_INFO,
	                   "Process %pid% terminated normally during server shutdown." );
		e << pid << WTERMSIG(status);
		AssertLog.ReportNoHook( &e );
	    }
	}

# if defined(OS_CYGWIN) || defined(OS_LINUX26)
	errno = save_errno;
# endif

	// Reinstate signal handler. Necessary on some SysV boxes (HP/UX at
	// least) and does no harm elsewhere.
	signal( SIGCHLD, HandleSigChld );
}

void
HandleSigTerm( int flag )
{
	// The child just plain exits on sigterm
	// The parent invokes the global stopping logic.

	Threading::Cancel();
}

void
HandleSigHup( int flag )
{
	Threading::Restart();
}

class MultiThreader : public Threader {

    public:

	MultiThreader( ThreadMode tmb )
	{
	    // Daemon?  Parent forks and exits, leaving child to
	    // call the shots.

	    if( IsDaemon( tmb ) )
	    {
		if( tmb == TmbDaemonSafe )
		{
		    // close stdio file operations
		    close(0);
		    close(1);
		    close(2);
		    int fd = open( "/dev/null", O_RDWR );
		    if( fd == 0 )
		    {
			// must be fd 1 and 2
			dup(fd);
			dup(fd);
		    }
		}
		if( fork() > 0 )
		    exit( 0 );
	    }

	    threadCountPtr = &threadCount; // SIGCHLD handler will decrement it

	    // become the leader of our process group
	    // This way we can kill everyone with one stroke.

	    setpgid( 0, getpid() );

	    // We'll catch this once

	    signal( SIGTERM, HandleSigTerm );
	    signal( SIGHUP, HandleSigHup );
	}

	void Launch( Thread *t )
	{
	    // We'll catch this for each child.
	    // BSD reinstalls this after each signal, but others don't.
	    // Some OS's allow you to ignore the signal and will reap
	    // children automatically.  This is good for AIX, because
	    // manual reaping just doesn't seem to work. Note that due to
	    // this, AIX doesn't provide a valid GetThreadCount() value.

# if defined ( OS_AIX41 ) || ( OS_AIX43 ) || ( OS_AIX53 )
	    signal( SIGCHLD, SIG_IGN );
# else
	    signal( SIGCHLD, HandleSigChld );
	    threadCount++;
# endif

# if defined ( OS_LINUX26 )
	    //
	    // Reap any dead children
	    // (works around Linux kernel bug fixed in 2.6.11).
	    //
	    int status;
	    pid_t pid;
	    /*
	     * Note: Changed waitpid code below from waiting on all child processes
	     * (-1) to waiting on processes in process group (0). This change protects
	     * the child process p4zk which detaches itself from the parent's process
	     * group. When p4d is restarting we want to kill all child processes but
	     * keep the p4zk process going. (If invoking shutdown, p4zk will notice
	     * when connection to p4d closes and will exit)
	     */
	    while( ( pid = waitpid( (pid_t)0, &status, WNOHANG ) ) > 0 )
	    {
	        if( WIFSIGNALED( status ) )
	        {
	            Error e;
	            e.Set( E_FATAL,
	                "Process %pid% exited on a signal %signal%!" );
	            e << pid << WTERMSIG(status);
	            AssertLog.Report( &e );
	        }
	        threadCount--;
	    }
# endif

	    switch( fork() )
	    {
	    case -1:
		/*
		 * Fork failed.  We could bail out here, but since we have
		 * the wherewithall to run the request, we'll just go ahead
		 * and do it, hoping that the crisis will abate.
		 */
		{
		    Error e;
		    e.Set( E_FATAL, "fork() failed,  single threading!\n");
		    AssertLog.Report( &e );
		}

		t->Run();
	        threadCount--;
		delete t;
		break;

	    case 0:
		/*
		 * The child.  Note it so that we know to handle Stop() by
		 * sending a signal to our parent.  To be nice, we drop the
		 * listen socket needed by the parent, using Unlisten().
		 * We then run the request, delete the handler, and exit.
		 *
		 * Revert SIGCHLD here, as on OSF it will spoil RunCmd().
		 */

		process->Child();

		signal( SIGTERM, SIG_DFL );
		signal( SIGHUP, SIG_DFL );
		signal( SIGCHLD, SIG_DFL );

		t->Run();
		delete t;
		exit(0);
		break;

	    default:
		/*
		 * The parent.  Delete the handler, which will close the
		 * child connection, and return so that we can go back
		 * to servicing further requests.
		 */

		delete t;
		break;
	    }
	}

# ifdef OS_SUNOS
// sunos requires an argument
# define getpgrp() getpgrp(0)
# endif

# if defined ( OS_AIX41 ) || ( OS_AIX43 ) || ( OS_AIX53 )
// Dumbo getpgrp() returns garbage on AIX41.
# define getpgrp() getpgid(0)
# endif

	void Cancel()
	{
	    if( getpgrp() != getpid() )
	    {
		// The child really has no control over what's going
		// on, so it just sends a SIGTERM to the parent to tell
		// it to shut down.  We want this child to exit nicely, so
		// we block the SIGTERM the parent will send _us_.

		signal( SIGTERM, SIG_IGN );
		kill( getpgrp(), SIGTERM );
	    }
	    else
	    {
		// The parent knows what to do:

		Threader::Cancel();
	    }
	}

	void Restart()
	{
	    if( getpgrp() != getpid() )
	    {
		signal( SIGTERM, SIG_IGN );
		kill( getpgrp(), SIGHUP );
	    }
	    else
	    {
		Threader::Restart();
	    }
	}

	void Quiesce()
	{
	    // Someday we might handle the sub-processes here.
	}

	void Reap()
	{
	    // Kill all child processes.
	    // 1. Block SIGTERM so #2 doesn't get us.
	    // 2. Kill everyone in our process group.
	    // 3. Wait for them to die.

	    signal( SIGTERM, SIG_IGN );

	    kill( 0, SIGTERM );

	    int status;
	    /*
	     * Note: Changed waitpid code below from waiting on all child processes
	     * (-1) to waiting on processes in process group (0). This change protects
	     * the child process p4zk which detaches itself from the parent's process
	     * group. When p4d is restarting we want to kill all child processes but
	     * keep the p4zk process going. (If invoking shutdown, p4zk will notice
	     * when connection to p4d closes and will exit)
	     *
	     * We now signal SIGTERM periodically in order to encourage our
	     * children to die; this avoids a deadlock during shutdown or restart
	     * when the parent has locked db.* but a child is trying to lock one
	     * of them.  The parent was waiting for the child to die, and the child
	     * was waiting for the parent to release the lock.
	     */
	    int pid = 0;
	    int error = 0;

	    do
	    {
		errno = 0;
		pid = waitpid( (pid_t)0, &status, WNOHANG );
		error = errno;
		if( pid == 0 )	// sleep only if no child exited this time around
		{
		    kill( 0, SIGTERM );		// die! die! my darling!
		    msleep( 50 );
		}
	    } while( (pid >= 0) || (error != ECHILD) );
	}

	int GetThreadCount()
	{
# if defined ( OS_AIX41 ) || ( OS_AIX43 ) || ( OS_AIX53 )
	    // Since SIGCHLD doesn't work on AIX, thread count is unavailable.
	    return -1;
# else
	    return threadCount;
# endif
	}

} ;

# endif /* UNIX */

# ifndef HAVE_MULTITHREADER

class MultiThreader : public Threader
{
    public:
	MultiThreader( ThreadMode tmb )
	{
	}
} ;

# endif

# ifdef HAVE_PTHREAD

/*
 * This is a minimal MultiThreader implementation based on posix threads.
 *
 * It is by no means complete and not suitable for use with the perforce
 * server until it handles termination, thread count, etc.
 *
 * Also, the variable qualifier MT_STATIC needs to be worked on.
 * Not all supported platforms can handle that.
 *
 */

class PosixThreader : public Threader {
    public:
	PosixThreader( ThreadMode )
	{
	}

	void Launch( Thread *t )
	{
		pthread_t newthread;

		pthread_create( &newthread, NULL, starter, (void *)t );

		pthread_detach( newthread );
	}

    private:

	static void *starter( void *v )
	{
	    Thread *t = (Thread *)v;

	    t->Run();

	    delete t;

	    return NULL;
	}

};

# else
typedef MultiThreader PosixThreader;
# endif /* HAVE_PTHREAD */

/*
 *
 * Threader -- generic top level threading
 *
 */

Threader *Threading::current = 0;

Threading::Threading( ThreadMode tmb, Process *p )
{
	switch( tmb )
	{
	case TmbSingle:

# ifdef HAVE_SIGHUP_HANDLER
	    signal( SIGHUP, HandleSigHup );
# endif
	    threader = new Threader;
	    break;
	case TmbMulti:
	case TmbDaemon:
	case TmbDaemonSafe:
	    threader = new MultiThreader( tmb );
	    break;
	case TmbThreads:
	    threader = new PosixThreader( tmb );
	    break;
	}

	threader->process = p;
	current = threader;
}

Thread::~Thread() {}

Process::~Process() {}
