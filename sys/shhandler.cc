/*
 * Copyright 1995, 2010 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * shhandler.cc -- Smart Heap error handler.
 */

# if defined(USE_SMARTHEAP) && !defined(OS_NTIA64)

# define NEED_SMARTHEAP
# ifdef OS_NT
# define NEED_DBGBREAK
# endif

# include <stdhdrs.h>
# include <ctype.h>
# include <strbuf.h>
# include <shhandler.h>
# include <debug.h>
# include <tunable.h>

# if defined( OS_NTX86 ) || defined( OS_LINUXX86 )
# define FMT_U "%lu"
# define FMT_X "0x%lx"
# else
# define FMT_U "%llu"
# define FMT_X "0x%llx"
# endif


// Smart Heap error handler.
// Mostly concerned about out of memory conditions.
//
// If SmartHeap is not able to allocate memory from the normal
// heap lists, it will invoke this error handler.  The problem
// is that SmartHeap will then perform a second chance allocation
// from heaps which are meant for other purposes.
//
// In essence this error handler can be invoked when there is no
// real error.  At least we know we are close to no memory left.
//
// This seems to occur mostly when the Perforce Server is doing
// test memory probes while in critical sections of meta data
// handling.
//

# ifndef OS_NT
// The following two functions are used for Linux instrumentation.
int
IsDebuggerPresent()
{
# ifdef MEM_DEBUG
	return 1;
# else
	// This tunable is only for Linux, "sys.memory.debug".
	return p4tunable.Get( P4TUNE_SYS_MEMORY_DEBUG );
# endif
}

void
OutputDebugString(
	const char *msg
	)
{
	// On Linux, Smart Heap output goes to stderr.
	fprintf(stderr, "%s", msg);
	fflush( stderr );
}
# endif // !OS_NT

MEM_BOOL MEM_CALLBACK
SHHandleError(
    MEM_ERROR_INFO *errorInfo
    )
{
	char msg[128];

# ifdef OS_NT
	// On Windows, we catch Smart Heap errors.
	//
	if( IsDebuggerPresent() )
	{
	    // Post the Smart Heap Error address to p4diag.
	    // P4diag will read the structure from process memory
	    // and display pertinent information.
	    //
	    sprintf (msg, "display MEM_ERROR_INFO: 0x%p\n", errorInfo);
	    OutputDebugString(msg);

# ifdef HAVE_DBGBREAK
	    // If under p4diag, this break point will create a stack
	    // trace and optionally a mini dump.
	    DebugBreak();
# endif // HAVE_DBGBREAK
	}
# else
	// On Linux just report the SH errorCode.
	//
	if( IsDebuggerPresent() )
	{
	    sprintf (msg, "display MEM_ERROR_CODE: 0x%x\n", errorInfo->errorCode);
	    OutputDebugString(msg);
	}
# endif // OS_NT

	return (0);
}


SHHandler::SHHandler()
{
	char msg[128];

	// Initial values are only used when an unset is requested.
	// If we know the previous value, we put it back.

	initial_procfree = (MEM_SIZET)0;
	initial_poolfree = (MEM_SIZET)0;
	initial_ceiling = (MEM_SIZET)0;
	initial_procgrowinc = (MEM_SIZET)0;
	initial_poolgrowinc = (MEM_SIZET)0;

	// The default checkpoint value is 1, we start above that.
	cur_ckpt = 1;
	max_ckpt = 1;

# ifdef OS_NT
	// On Linux let Smart Heap format the error message.
	if( MemSetErrorHandler( SHHandleError ) == NULL)
	    OutputDebugString ("note: MemSetErrorHandler(): failed.\n");
# else
	// On Linux we can not do error output in the constructor.
	MemSetErrorHandler( SHHandleError );
# endif

	MemRegisterTask();

	// Smart Heap instrumented memory checks. Three levels possible.
	//
# ifdef SMARTHEAP_CHECKS
# if (SMARTHEAP_CHECKS == 1)
	// O(c)
	dbgMemSetSafetyLevel( MEM_SAFETY_SOME );
# endif
# if (SMARTHEAP_CHECKS == 2)
	// O(n)
	dbgMemSetSafetyLevel( MEM_SAFETY_FULL );
# endif
# if (SMARTHEAP_CHECKS == 3)
	// O(n*n)
	dbgMemSetSafetyLevel( MEM_SAFETY_DEBUG );
# endif
# if (SMARTHEAP_CHECKS == 4)
	// O(n*n) plus the thorough checking
	dbgMemSetSafetyLevel( MEM_SAFETY_DEBUG );

	// Enable thorough checking, this might take a while.
	dbgMemSetCheckFrequency( 1 );
	dbgMemDeferFreeing( 1 );
	dbgMemSetDeferQueueLen( ULONG_MAX-1 );
	dbgMemSetDeferSizeThreshold( (MEM_SIZET)ULONG_MAX-1 );
# endif
# ifdef OS_NT
	// On Windows, Debug Smart Heap output goes to the debug console.
	// Use p4diag to view these messages.
	if( !dbgMemSetDefaultErrorOutput( DBGMEM_OUTPUT_CONSOLE, NULL))
	    OutputDebugString ("note: dbgMemSetDefaultErrorOutput(): failed.\n");
# else // Linux
	// On Linux, Debug Smart Heap output goes to stderr.
	// On Linux we can not do error output in the constructor.
	dbgMemSetDefaultErrorOutput( DBGMEM_OUTPUT_CONSOLE, NULL);
# endif // OS_NT
# endif // SMARTHEAP_CHECKS

# ifdef OS_NT
	InitializeCriticalSection( &section );

	if( IsDebuggerPresent() )
	{
	    MEM_VERSION vers;

	    vers = MemVersion( );
	    sprintf (msg, "control: set sh_version=%d.%d.%d\n",
		MEM_MAJOR_VERSION(vers), MEM_MINOR_VERSION(vers), MEM_UPDATE_VERSION(vers));
	    OutputDebugString( msg );

# ifdef MEM_DEBUG
	    sprintf (msg, "control: set sh_mode=mem_debug\n");
	    OutputDebugString( msg );
# endif
	}
# endif // OS_NT
}

// Set all Smart Heap tunables.
void
SHHandler::Tunables()
{
	unsigned int value;

	// sys.memory.procfree
	// Controls how much free space is in the large heap block.
	//
	value = (MEM_SIZET)p4tunable.Get( P4TUNE_SYS_MEMORY_PROCFREE );
	SetTunable( P4TUNE_SYS_MEMORY_PROCFREE, &value );

	// sys.memory.poolfree
	// Controls how much free space is in a pool.
	//
	value = (MEM_SIZET)p4tunable.Get( P4TUNE_SYS_MEMORY_POOLFREE );
	SetTunable( P4TUNE_SYS_MEMORY_POOLFREE, &value );

	// sys.memory.procgrowinc
	// Limit a process to a specific growth increment.
	//
	value = (MEM_SIZET)p4tunable.Get( P4TUNE_SYS_MEMORY_PROCGROWINC );
	SetTunable( P4TUNE_SYS_MEMORY_PROCGROWINC, &value );

	// sys.memory.poolgrowinc
	// Limit a pool to a specific growth increment.
	//
	value = (MEM_SIZET)p4tunable.Get( P4TUNE_SYS_MEMORY_POOLGROWINC );
	SetTunable( P4TUNE_SYS_MEMORY_POOLGROWINC, &value );

	// sys.memory.subpools
	// Limit the process to a specific number of sub pools.
	//
	value = (MEM_SIZET)p4tunable.Get( P4TUNE_SYS_MEMORY_SUBPOOLS );
	SetTunable( P4TUNE_SYS_MEMORY_SUBPOOLS, &value );

	// sys.memory.limit
	// Limit the process to a specific amount of memory.
	//
	value = (MEM_SIZET)p4tunable.Get( P4TUNE_SYS_MEMORY_LIMIT );
	SetTunable( P4TUNE_SYS_MEMORY_LIMIT, &value );
}

// Internal function for SH setting tunables.
void
SHHandler::SetTunable(
	int index,
	unsigned int *value
	)
{
	MEM_SIZET membytes = 0;
	MEM_SIZET prevbytes = 0;

# ifdef OS_NT
	// A value of 0 is only allowed for poolgrowinc.
	//
	if( *value == 0 && index != P4TUNE_SYS_MEMORY_POOLGROWINC )
	    return;
# else
	// No values of 0 allowed on Linux.
	// Revisit this if we move to SH 11.0 on Linux.
	//
	if( *value == 0 )
	    return;
# endif

	membytes = (MEM_SIZET)*value;

	// Smart Heap requires a process free low limit of 64.
	// Smart Heap also requires a quantization of 64.

	if( index == P4TUNE_SYS_MEMORY_PROCFREE ||
	    index == P4TUNE_CMD_MEMORY_PROCFREE )
	{
	    if( membytes < 64 )
		membytes = 64;

	    // Quantize up to the next multiple of 64.
	    membytes = (membytes+63) - ((membytes+63)%64);
	}

	// Smart Heap will quantize the grow increment.
	// Pool grow increment is allowed to be 0.
	// For now block a 0 process grow increment above.

	if( index == P4TUNE_SYS_MEMORY_PROCGROWINC ||
	    index == P4TUNE_SYS_MEMORY_POOLGROWINC )
	{
	    if( membytes != 0 )
	    {
		// Quantize up to the next multiple of 64.
		membytes = (membytes+63) - ((membytes+63)%64);
	    }
	}

	// Smart Heap limit checks instituted by Perforce.

	if( index == P4TUNE_SYS_MEMORY_POOLFREE ||
	    index == P4TUNE_CMD_MEMORY_POOLFREE )
	{
	    // Arbitrary pool free low limit of 1K.
	    if( membytes < 1 )
		membytes = (MEM_SIZET)1;

	    // Protect from non linear Smart Heap issues.
	    // Cap at 256 Mbytes, 262144.
	    if( membytes > (MEM_SIZET)262144 )
		membytes = (MEM_SIZET)262144;
	}

	if( (index == P4TUNE_SYS_MEMORY_LIMIT ||
	    index == P4TUNE_CMD_MEMORY_LIMIT ) && membytes < 1024 )
	{
	    // Force a minimum memory limit of 1M.
	    // The Server will not start otherwise.
	    membytes = (MEM_SIZET)1024;
	}

	// Let the caller know the final non scaled value.
	*value = (unsigned int)membytes;

# if defined( OS_NTX86 ) || defined( OS_LINUXX86 )
	// Prevent 32bit rounding back to zero.
	if( membytes == 0 && index != P4TUNE_SYS_MEMORY_POOLGROWINC )
	    membytes = (MEM_SIZET)ULONG_MAX;
# endif

# ifdef OS_NT
	// Smart Heap has not confirmed safety of their APIs.
	EnterCriticalSection( &section );
# endif

	switch( index )
	{
	case P4TUNE_SYS_MEMORY_POOLFREE:
	    membytes *= 1024;
	    prevbytes = MemPoolSetFreeBytes( MemDefaultPool, membytes );
	    if( initial_poolfree == 0 )
		initial_poolfree = prevbytes;
	    break;

	case P4TUNE_SYS_MEMORY_PROCFREE:
	    membytes *= 1024;
	    prevbytes = MemProcessSetFreeBytes( membytes );
	    if( initial_procfree == 0 )
		initial_procfree = prevbytes;
	    break;

	case P4TUNE_SYS_MEMORY_POOLGROWINC:
	    membytes *= 1024;
	    prevbytes = MemPoolSetGrowIncrement( MemDefaultPool, membytes);
	    if( initial_poolgrowinc == 0 )
		initial_poolgrowinc = prevbytes;
	    break;

	case P4TUNE_SYS_MEMORY_PROCGROWINC:
	    membytes *= 1024;
	    prevbytes = MemProcessSetGrowIncrement( membytes);
	    if( initial_procgrowinc == 0 )
		initial_procgrowinc = prevbytes;
	    break;

	case P4TUNE_SYS_MEMORY_SUBPOOLS:
# ifdef OS_NT
# ifndef MEM_DEBUG
	    // Smart Heap bug, debug library doesn't have this export.
	    // Check this again in SH 11.3
	    prevbytes = MemPoolSetMaxSubpools( MemDefaultPool, membytes);
# endif
# endif
	    break;

	case P4TUNE_SYS_MEMORY_LIMIT:
	    membytes *= 1024;
	    prevbytes = MemPoolSetCeiling( MemDefaultPool, membytes );
	    if( initial_ceiling == 0 )
		initial_ceiling = prevbytes;
	    break;

	case P4TUNE_CMD_MEMORY_POOLFREE:
	    membytes *= 1024;
	    prevbytes = MemPoolSetFreeBytes( MemDefaultPool, membytes );
	    break;

	case P4TUNE_CMD_MEMORY_PROCFREE:
	    membytes *= 1024;
	    prevbytes = MemProcessSetFreeBytes( membytes );
	    break;

	case P4TUNE_CMD_MEMORY_LIMIT:
	    membytes *= 1024;
	    prevbytes = MemPoolSetCeiling( MemDefaultPool, membytes );
	    break;

	case P4TUNE_CMD_MEMORY_FLUSHPOOL:
	    prevbytes = FlushPool( MemDefaultPool );
	    break;
	}

# ifdef OS_NT
	LeaveCriticalSection( &section );
# endif

	// These traversal functions will take some time.  Do these
	// outside of the critical section since the pool will be
	// locked during the listing.

	switch( index )
	{
	case P4TUNE_CMD_MEMORY_LISTPOOLS:
	    // ListAllPools (tag, detail)
	    ListAllPools( (const char *)"cmd.memory.listpools", *value );
	    break;

	case P4TUNE_CMD_MEMORY_CHKPT:
	    Checkpoint( (const char *)"cmd.memory.chkpt", *value );
	    break;
	}

	// Emit a trace message for p4diag.
	if( IsDebuggerPresent() )
	{
	    const char *name = p4tunable.GetName( index );
	    char fmt[128];
	    char msg[128];

	    switch( index )
	    {
	    case P4TUNE_CMD_MEMORY_FLUSHPOOL:
		sprintf(fmt, "note: sys.memory.flushpool released %s bytes\n",
			FMT_U);
		sprintf(msg, fmt, prevbytes);
		break;

	    case P4TUNE_SYS_MEMORY_SUBPOOLS:
		sprintf (fmt, "tunable: set %%s to %s\n", FMT_U);
		sprintf (msg, fmt, name, membytes);
		break;

	    case P4TUNE_CMD_MEMORY_LISTPOOLS:
	    case P4TUNE_CMD_MEMORY_CHKPT:
	    default:
		sprintf (fmt, "tunable: set %%s from %s to %s\n", FMT_U, FMT_U);
		sprintf (msg, fmt, name, prevbytes, membytes);
		break;
	    }

	    OutputDebugString( msg );
	}
}

// External function for setting SH tunables.
int
SHHandler::SetTunable(
	StrBuf &name,
	StrBuf &value
	)
{
	int idx;
	unsigned int setting;

	if ((idx = p4tunable.GetIndex( name.Text() )) < 0)
	    return (1);

	// Only Smart Heap tunables get through.
	// Otherwise return 1 to allow caller to continue.

	if( idx < P4TUNE_SYS_MEMORY_POOLFREE ||
	    idx > P4TUNE_CMD_MEMORY_CHKPT )
		return (1);

	setting = Config2Membytes( value.Text() );

	SetTunable( idx, &setting );

	// The setting may have been modified in SetTunable().

	if( setting )
	    value.Set( StrNum( (int)setting ) );

	// If setting a cmd.memory tunable, return 0 to ensure it is
	// not permanently stored.

	if( idx >= P4TUNE_CMD_MEMORY_POOLFREE &&
	    idx <= P4TUNE_CMD_MEMORY_CHKPT )
		return (0);

	return (1);
}

void
SHHandler::UnsetTunable( int index )
{
	MEM_SIZET membytes = 0;
	MEM_SIZET prevbytes = 0;

# ifdef OS_NT
	// Smart Heap has not confirmed safety of their APIs.
	EnterCriticalSection( &section );
# endif

	switch( index )
	{
	case P4TUNE_SYS_MEMORY_POOLFREE:
	    if( initial_poolfree != 0 )
	    {
		membytes = initial_poolfree;
		prevbytes = MemPoolSetFreeBytes( MemDefaultPool, membytes );
	    }
	    break;

	case P4TUNE_SYS_MEMORY_PROCFREE:
	    if( initial_procfree != 0 )
	    {
		membytes = initial_procfree;
		prevbytes = MemProcessSetFreeBytes( membytes );
	    }
	    break;

	case P4TUNE_SYS_MEMORY_POOLGROWINC:
	    if( initial_poolgrowinc != 0 )
	    {
		membytes = initial_poolgrowinc;
		prevbytes = MemPoolSetGrowIncrement( MemDefaultPool, membytes);
	    }
	    break;

	case P4TUNE_SYS_MEMORY_PROCGROWINC:
	    if( initial_procgrowinc != 0 )
	    {
		membytes = initial_procgrowinc;
		prevbytes = MemProcessSetGrowIncrement( membytes);
	    }
	    break;

	case P4TUNE_SYS_MEMORY_SUBPOOLS:
	    // Can not unset sub pools.
	    break;

	case P4TUNE_SYS_MEMORY_LIMIT:
	    if( initial_ceiling != 0 )
	    {
		membytes = initial_ceiling;
		prevbytes = MemPoolSetCeiling( MemDefaultPool, membytes );
	    }
	    break;
	}

# ifdef OS_NT
	LeaveCriticalSection( &section );
# endif

	// Emit a trace message for p4diag.
	if( IsDebuggerPresent() && prevbytes != membytes )
	{
	    const char *name = p4tunable.GetName( index );
	    char fmt[128];
	    char msg[128];

	    sprintf (fmt, "tunable: unset %%s to %s\n", FMT_U);
	    sprintf (msg, fmt, name, membytes);
	    OutputDebugString(msg);
	}
}

int
SHHandler::UnsetTunable( const char *name )
{
	int idx;

	if ((idx = p4tunable.GetIndex( name )) < 0)
	    return (1);

	// Only Smart Heap tunables get through.
	// Otherwise return 1 to allow caller to continue.

	if( idx < P4TUNE_SYS_MEMORY_POOLFREE || idx > P4TUNE_CMD_MEMORY_CHKPT )
	    return (1);

	// If setting a cmd.memory tunable, return now as we can not
	// unset these.

	if(idx >= P4TUNE_CMD_MEMORY_POOLFREE && idx <= P4TUNE_CMD_MEMORY_CHKPT)
	    return (0);

	UnsetTunable( idx );

	return (1);
}

void
SHHandler::Close()
{
# ifdef OS_NT
	DeleteCriticalSection( &section );
# endif
}

void
SHHandler::ListEntry (
	const MEM_POOL_ENTRY *entry,
	int show_unused
	)
{
	char fmt[128];
	char frame[128];
	char msg[8192];

	if( !IsDebuggerPresent() )
	    return;

	if( entry->isInUse )
	{
# ifdef MEM_DEBUG
	    DBGMEM_PTR_INFO info;

	    if( !dbgMemPtrInfo (entry->entry, &info) )
	    {
		OutputDebugString ("note: dbgMemPtrInfo(): failed.\n");
		return;
	    }

	    // Information about the memory block.
	    //
	    const char *srcfile = info.createFile;
	    if (srcfile == NULL)
		srcfile = "unknown";

	    //          entry              sz/asz  thrd cp srcfile line
	    // "lentry: 0x0000000001491BD0 24/32   3036 1 'unknown' 0"
	    sprintf (fmt, "lentry: 0x%%p %s/%s %%lu %%d '%%s' %%d\n",
		    FMT_U, FMT_U);
	    sprintf (msg, fmt,
		    entry->entry, entry->size, info.argSize, info.threadID,
		    info.checkpoint, srcfile, info.createLine);
	    OutputDebugString (msg);

	    // Callstack for the memory block.
	    //
	    if( info.callStack[0] != 0 )
	    {
		int i;

		sprintf (msg, "frames: ");

		// MEM_MAXCALLSTACK is from smrtheap.h
		for (i=0; i<MEM_MAXCALLSTACK && info.callStack[i]!=0; i++)
		{
		    sprintf (frame, "0x%p ", info.callStack[i]);
		    strcat (msg, frame);
		}
		strcat (msg, "\n");

		OutputDebugString (msg);
	    }
# else // MEM_DEBUG
	    // Information about the memory block.
	    //
	    sprintf (fmt, "sentry: 0x%%p %s\n", FMT_U);
	    sprintf (msg, fmt, entry->entry, entry->size);
	    OutputDebugString (msg);
# endif // MEM_DEBUG
	}
	else if( show_unused )
	{
	    sprintf (fmt, "uentry: 0x%%p %s\n", FMT_U);
	    sprintf (msg, fmt, entry->entry, entry->size);
	    OutputDebugString (msg);
	}
}

MEM_BOOL
SHHandler::ValidatePool (
	MEM_POOL pool
	)
{
	MEM_POOL_INFO info;
	MEM_POOL_STATUS status;

	status = MemPoolFirst (&info, 0);
	while (status == MEM_POOL_OK)
	{
	    if( pool == info.pool )
	    	return (MEM_BOOL)1;

	    status = MemPoolNext (&info, 0);
	}
    	return (MEM_BOOL)0;
}

void
SHHandler::ListPool (
	MEM_POOL pool,
	const char *tag,
	unsigned int detail
	)
{
	MEM_POOL_ENTRY entry;
	char fmt[1024];
	char msg[1024];
	int show_unused=0;

	if( !IsDebuggerPresent() )
	    return;

	if( pool == (MEM_POOL)1 )
	    pool = MemDefaultPool;

	if( !ValidatePool(pool) )
	{
	    OutputDebugString ("note: ListPool(): Invalid Pool\n");
	    return;
	}

	// Show heap entries currently not in use.
	if( detail >= 3 )
	    show_unused = 1;

	sprintf (fmt, "poolbegin: %s '%%s' %s %s\n", FMT_X, FMT_U, FMT_U);
	sprintf (msg, fmt, pool, tag, MemPoolCount(pool), MemPoolSize(pool));
	OutputDebugString (msg);

	// Show only pool related information.
	if( detail < 2 )
	    goto end;

	OutputDebugString ("control: set log2file=off\n");
	OutputDebugString ("note: See p4diag log file for heap entries.\n");
	OutputDebugString ("control: set log2file=on\n");

	// Tell p4diag to disable the terminal window logging.
	//
	OutputDebugString ("control: set log2term=off\n");

	entry.entry = NULL;
	MemPoolLock (pool);
	while (MemPoolWalk (pool, &entry) == MEM_POOL_OK)
	{
	    ListEntry (&entry, show_unused);
	}
	MemPoolUnlock (pool);

	// Tell p4diag to enable the terminal window logging.
	//
	OutputDebugString ("control: set log2term=on\n");

end:
	sprintf (fmt, "poolend: %s '%%s'\n", FMT_X);
	sprintf (msg, fmt, pool, tag);
	OutputDebugString (msg);
}

void
SHHandler::ListAllPools (
	const char *tag,
	unsigned int detail
	)
{
	MEM_POOL_INFO info;
	MEM_POOL_STATUS status;
	MEM_POOL_ENTRY entry;
	MEM_SIZET size, s;
	char msg[1024];

	if( !IsDebuggerPresent() )
	    return;

	sprintf (msg, "listbegin: '%s' %d\n", tag, detail);
	OutputDebugString (msg);

	status = MemPoolFirst (&info, 0);
	while (status == MEM_POOL_OK)
	{
	    ListPool( info.pool, tag, detail );

	    status = MemPoolNext (&info, 0);
	}

	sprintf (msg, "listend: '%s'\n", tag);
	OutputDebugString (msg);
}

MEM_SIZET
SHHandler::FlushPool( MEM_POOL pool )
{
	MEM_SIZET membytes;

	if( pool == (MEM_POOL)1 )
	    pool = MemDefaultPool;

	membytes = MemPoolShrink( pool );

	if ( membytes == MEM_ERROR_RET )
	{
	    if( IsDebuggerPresent() )
		OutputDebugString("note: MemPoolShrink() failed\n");
	    return (0);
	}

	return (membytes);
}

int
SHHandler::Config2Membytes( const char *value )
{
	int membytes=0;
	const char *ptr;

	// Atoi()

	ptr = value;
	while( *ptr != '\0' && isdigit( *ptr ) )
	    membytes = membytes * 10 + *ptr++ - '0';

	// k = *1024, m = *1048576

	if( *ptr == 'k' || *ptr == 'K' )
	    membytes *= 1024;

	else if( *ptr == 'm' || *ptr == 'M' )
	    membytes *= 1048576;

	return (membytes);
}

int
SHHandler::Checkpoint (
	const char *tag,
	int ckpt
	)
{
# ifdef MEM_DEBUG
	int prev_ckpt;
	int new_ckpt;
	char msg[256];

	if( ckpt == 0 )
	    new_ckpt = ++cur_ckpt;
	else
	    new_ckpt = cur_ckpt = ckpt;

	if( max_ckpt < new_ckpt )
	    max_ckpt = new_ckpt;

	prev_ckpt = dbgMemSetCheckpoint( new_ckpt );

	if( IsDebuggerPresent() )
	{
	    sprintf (msg, "shchkpt: '%s' %u %u\n", tag, prev_ckpt, new_ckpt);
	    OutputDebugString (msg);
	}

	return (new_ckpt);
# else
	return (0);
# endif
}

void
SHHandler::ReportLeakage (
	int ckpt1,
	int ckpt2
	)
{
# ifdef MEM_DEBUG
	MEM_BOOL ret;
	char msg[256];

	if( !IsDebuggerPresent() )
	    return;

	OutputDebugString ("note: ReportLeakage() begin\n");

	ret = dbgMemReportLeakage( MemDefaultPool, ckpt1, ckpt2 );
	if( !ret )
	{
	    OutputDebugString ("note: ReportLeakage() failed.\n");
	}
	else
	{
	    sprintf (msg, "note: ReportLeakage() ckpt1=%u ckpt1=%u\n",
		ckpt1, ckpt2);
	    OutputDebugString (msg);
	}

	OutputDebugString ("note: ReportLeakage() end\n");
# endif
}

void
SHHandler::MemCheckAll ()
{
# ifdef MEM_DEBUG
	char msg[256];

	if( !IsDebuggerPresent() )
	    return;

	OutputDebugString ("note: MemCheckAll() begin\n");

	if( !dbgMemCheckAll() )
	    OutputDebugString ("note: MemCheckAll() failed.\n");

	// After the check, free the deferred memory.  Otherwise
	// it can pile up and potentially exhaust memory.
	//
	dbgMemFreeDeferred();

	OutputDebugString ("note: MemCheckAll() end\n");
# endif
}

# endif // USE_SMARTHEAP && !OS_NTIA64
