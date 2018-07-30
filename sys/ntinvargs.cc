/*
 * Copyright 1995, 2007 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * ntinvargs.cc -- handle C runtime invalid parameters.
 */

# define NEED_DBGBREAK

# include <stdhdrs.h>
# include <ntinvargs.h>


#if defined(OS_NT) && !defined(OS_NTIA64) && !defined(OS_MINGW)

void
_on_invalid_parameter (
	const wchar_t * expression,
	const wchar_t * function,
	const wchar_t * file,
	unsigned int line,
	uintptr_t pReserved
	)
{
	if( IsDebuggerPresent() )
	{
	    char msg[128];

	    // Notice p4diag this is a Posix Invalid Parameter event.
	    sprintf (msg, "event: Posix Invalid Parameter");
	    OutputDebugString(msg);

# ifdef HAVE_DBGBREAK
	    // Under p4diag, create a strack trace and mini dump.
	    DebugBreak();
# endif // HAVE_DBGBREAK
	}
}


NtInvArgs::NtInvArgs()
{
	_set_invalid_parameter_handler(
	    (_invalid_parameter_handler) _on_invalid_parameter);
}

#else

NtInvArgs::NtInvArgs()
{
}

#endif
