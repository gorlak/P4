/*
 * /+\
 * +\	Copyright 1995, 2000 Perforce Software.	 All rights reserved.
 * \+/
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# define NEED_WINDOWSH

# include <stdhdrs.h>

# include <strbuf.h>
# include <error.h>
# include <datetime.h>
# include <filesys.h>
# include <errorlog.h>
# include <threading.h>

# include "ntservice.h"


#define ASSERT(f)

//
// The static global_this pointer is required so that static callbacks can
// access the instances' data. This scheme fails if there is more than one
// instance. This is not a problem for services of the OWN process type.
//

NtService *NtService::global_this = NULL;

// Implementation of NtService class.

//
// Construction:
//
// In order to create an NtService object an entry point must be specified.
// The entry_point is the function where the service begins execution when it
// is started, and it cannot be main because main attaches to the SCM.
// The SCM ( Service Control Manager ) ultimately calls entry_point.
//

NtService::NtService()
{
	global_this = this;

	// We want to allow our service to stop on user request and during
	// a system shutdown.  The system shutdown will not issue a stop
	// request.  We have to allow and process the shutdown request.

	status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	status.dwCurrentState = SERVICE_START_PENDING;
	status.dwControlsAccepted =
		SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN; // no pause
	status.dwWin32ExitCode = 0;
	status.dwServiceSpecificExitCode = 0;

	// Start with a check point of zero, the initial value only matters
	// if we have an error.  WaitHint=0 and CheckPoint=0 is a special
	// indicator to the SCM that we died on startup.  We use an initial
	// of 1000ms as a marker.  Normally we should never see this
	// value since the Perforce service should be using a higher value.
	// The SCM default wait hint seems to be 2000ms.
	// Using the svcinst tool with -d will show you the wait hints.

	status.dwCheckPoint = 0;
	status.dwWaitHint = 1000;

	entry_point = 0;
	statusHandle = 0;
}

NtService::~NtService()
{
	global_this = NULL;
}

/*
 * NtService::Start()
 *
 * The dispatcher must be called with 8 to 10 seconds upon execution.
 * This function begins the process of bringing up the Service.  When the
 * dispatch table is registered with the Service Control Manager, the
 * StaticRun entry point is called.  We set the start_pending status
 * with a hint indicating we expect to take 10 seconds to start.
 * 
 * Since this class only supports a single service per executable, it
 * simply creates a dispatch table with a single entry and starts the
 * dispatcher.
 *
 * StaticRun() calls global_this->run().  This added complexity
 * allows the startup behavior to be determined by the objects class
 * through the virtual run() method.  The global_this works because
 * there is only one NtService per process; however, multiple
 * services per process requires a different approach.
 */

void NtService::Start( int (*entryPt)( DWORD, char ** ), char *svc, Error *e )
{
	SERVICE_TABLE_ENTRY dispatch_table[] =
	{
	    { TEXT(""), (void (__stdcall *)( DWORD, char **) )StaticRun },
	    { NULL, NULL }
	} ;

	entry_point = entryPt;

	// This API essentially does a CreateThread with StaticRun as the
	// entry point.  This thread will wait until the Windows Service
	// enters a stopped state.  Then we return to main / ntService,
	// which returns to the CRT, which then calls doexit.  We want to
	// make sure nt_main is done before this thread continues.  We
	// only set the Service state to stopped at the end of nt_main.

	if( StartServiceCtrlDispatcher( dispatch_table ) )
	    return;

	e->Sys( "StartServiceCtrlDispatcher", svc );
	e->Set( E_FATAL, "Can not start the Perforce Service" );
}

/*
 * NtService::SetStatus()
 *
 * Call this function to inform the service control manager of changes in the
 * status of the service and to report errors. There are various points at which
 * this function must be called. For example the entry_point function should
 * call set_status( running ) as soon as the service has successfully started.
 * If initialization takes more than about 20 seconds set_status( start_pending)
 * should be called by entry_point at regular intervals.
 *
 * The check_point and wait_hint parameters can be used to inform the SCM of
 * progress if initialization takes a particularly long time. The wait_hint is
 * in milliseconds and the check_point is simply incremented as things progress.
 * This holds true for pause_pending and continue_pending states too.
 *
 * The win32_exitcode allows you to report an error from GetLastError() and
 * the specific_code allows you to specify an application specific error.
 */

void NtService::SetStatus( 
	states state,
	DWORD win32_exitcode, 
	DWORD specific_code,
	DWORD wait_hint )
{
	ASSERT( statusHandle );

	switch( state )
	{
	case no_change:
		break;
	case running:
		status.dwCurrentState = SERVICE_RUNNING;
		break;
	case stopped:
		status.dwCurrentState = SERVICE_STOPPED;
		break;
	case paused:
		status.dwCurrentState = SERVICE_PAUSED;
		break;
	case start_pending:
		status.dwCurrentState = SERVICE_START_PENDING;
		break;
	case stop_pending:
		status.dwCurrentState = SERVICE_STOP_PENDING;
		break;
	case pause_pending:
		status.dwCurrentState = SERVICE_PAUSE_PENDING;
		break;
	case continue_pending:
		status.dwCurrentState = SERVICE_CONTINUE_PENDING;
		break;
	default:
		ASSERT(0);
		break;
	}

	if( state != no_change )
	{
		status.dwWin32ExitCode = win32_exitcode;
		status.dwServiceSpecificExitCode = specific_code;

		// The wait hint must always increase in value.  If you
		// use 10000, then send a 5000, the SCM might get upset.
		// 0 wait hint is only ok if the service is not in transition.

		if( status.dwWaitHint < wait_hint || state == stopped )
			status.dwWaitHint = wait_hint;
	}

	if( ! SetServiceStatus( statusHandle, &status ) )
	{
	    StrBuf msg;
	    DWORD err;
	    Error e;

	    err = GetLastError( );

	    e.Sys( "SetServiceStatus", svcName );
	    e.Set( E_FATAL, "Cannot communicate with Service Control Manager" );
	    e.Fmt( msg, EF_PLAIN );
	    AssertLog.SysLog( NULL, 0, "Perforce Service", msg.Text() );
	}

	if( state == running )
	{
		// Set these back to initial values in prep for the stop.
		status.dwCheckPoint = 0;
		status.dwWaitHint = 1000;
	}
	else
	{
		// We manage the check point internally.
		status.dwCheckPoint++;
	}
}

/*
 * NtService::ControlHandler()
 *
 * This static member function is passed a call back to the SCM which invokes
 * it to control the service. It examines the opcode and invokes the
 * appropriate virtual member function through the global this pointer.
 *
 */

void WINAPI 
NtService::ControlHandler( DWORD opcode )
{
	if( ! global_this )
		return;

	switch( opcode )
	{
	// No support for pause/resume or parameter change.

	case SERVICE_CONTROL_PAUSE: break;
	case SERVICE_CONTROL_CONTINUE: break;

	// We accept and process stop and shutdown requests.  A stop
	// request is not issued at system shutdown time, only a shutdown.

#ifdef SERVICE_CONTROL_PRESHUTDOWN
	case SERVICE_CONTROL_PRESHUTDOWN:
#endif
	case SERVICE_CONTROL_SHUTDOWN:
	case SERVICE_CONTROL_STOP: global_this->Stop(); break;

	// We always report the last known status of our service.  Only
	// the check point value is increasing.

	case SERVICE_CONTROL_INTERROGATE: global_this->SetStatus(); break;

	default: ASSERT(0);
	}
}

/*
 * NtService::StaticRun()
 *
 * This static function is passed as a callback to the SCM because member
 * functions can not be used in callbacks. It then uses the global this
 * pointer to invoke the appropriate virtual member function.
 */

void 
NtService::StaticRun( DWORD argc, char **argv )
{
	if( ! global_this )
		return;
	global_this->Run( argc, argv );
}

/*
 * Starts the service by invoking entry_point.
 */

void 
NtService::Run( DWORD argc, char **argv )
{
	StrBuf msg;

	// Store the service name for the shutdown message.

	strcpy(svcName, argv[0]);

	statusHandle = 
		RegisterServiceCtrlHandler( TEXT(svcName), ControlHandler );

	if( statusHandle == NULL )
	{
	    DWORD err;
	    Error e;

	    err = GetLastError( );

	    e.Sys( "RegisterServiceCtrlHandler", svcName );
	    e.Set( E_FATAL, "Can not register the Perforce Service" );
	    e.Fmt( msg, EF_PLAIN );
	    AssertLog.SysLog( NULL, 0, "Perforce Service", msg.Text() );

	    // If the check point and wait hint are both zero, with
	    // a service state of stopped, the SCM knows we failed.

	    SetStatus( stopped, err, err, 0 );

	    return;
	}

	// Let the Service Mangler know we plan on taking 10 seconds.

	SetStatus( start_pending, 0, 0, 10000 );

	// We want this in the Windows Event log, use SysLog directly.
	// Using Syslog bypasses the logfile setting.

	msg = "Starting the Perforce Service ";
	msg << svcName;
	AssertLog.SysLog( NULL, 0, "Perforce Service", msg.Text() );

	// Start the Perforce server

	entry_point( argc, argv );
}


/*
 * Stops the service. It's not enough to simply set the status to
 * stopped and return -- this will only cause the service to hang for
 * 30 seconds since the service main (the entry_point) thread is still
 * running.  So bring down the service main thread by signalling the
 * event and all will be well.
 */

void 
NtService::Stop()
{
	StrBuf msg;

	// We want this in the Windows Event log, use SysLog directly.
	// Using Syslog bypasses the logfile setting.

	msg = "End of the Perforce Service ";
	msg << svcName;
	AssertLog.SysLog( NULL, 0, "Perforce Service", msg.Text() );

	// We signal the main thread to stop.  It eventually returns
	// and program flow goes through the SCM back to us where we
	// unwind our main via a return.  The SCM is expecting to
	// close everything down.  We must not call ExitProcess().

	Threading::Cancel();
}

