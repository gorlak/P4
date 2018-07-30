/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 */

/*
 * Errorsys.cc - Error::Sys and Error::Net, the ifdef mess
 */


# ifdef OS_NT
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
# include <winsock.h>
# include <errno.h>
# endif  /* OS_NT */

# define NEED_ERRNO

# include <stdhdrs.h>

# include <error.h>
# include <errornum.h>
# include <strbuf.h>
# include <msgos.h>
# include <i18napi.h>
# include <charcvt.h>
# include <charset.h>

# if defined(OS_SUNOS) \
	|| defined(OS_AIX41) \
	|| defined(OS_ATT4) \
	|| defined(OS_PTX)

# define NOSTRERROR

extern const char *const sys_errlist[];
extern int sys_nerr;
extern int errno;

# endif

# ifdef OS_NT
extern const char *nt_sock_errlist[];  // for WSABASEERR + 1 to 112, start=0
extern const char *nt_sock_errlist2[];  // for WSABASEERR + 1001 to 1004
# endif /* OS_NT */

/*
 * Error::Sys() - add a system error message into an Error struct
 * Error::Net() - add a network error message into an Error struct
 * Error::StrError() - return a system (or system) error string (for manual handling)
 * Error::StrNetError() - return a network error string (for manual handling)
 */

# ifdef OS_NT

void
Error::Sys( 
	const char *op,
	const char *arg )
{
        StrBuf  buf;

        StrError( buf );
        Set( MsgOs::Sys ) << op << arg << buf;
}

// Set the passed-in buf to the message for the current errno and return a reference to it
// [static]
StrPtr &
Error::StrError(StrBuf &buf)
{
	return StrError( buf, GetLastError() );
}

// [static]
StrPtr &
Error::StrNetError(StrBuf &buf)
{
	return StrError( buf, WSAGetLastError() );
}

// [static]
StrPtr &
Error::StrError(StrBuf &buf, int errnum)
{
	// For when the posix library doesn't SetLastError().
	if (errnum == ERROR_SUCCESS)
	{
	    extern int errno;
	    switch (errno)
	    {
	    case EMFILE:
		errnum = ERROR_TOO_MANY_OPEN_FILES;
		break;
	    }
	}

	if( GlobalCharSet::Get() == CharSetApi::UTF_8 )
	{
	    const DWORD size = 257;
	    WCHAR wbuf[size];

	    int l = FormatMessageW(
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS |
		FORMAT_MESSAGE_MAX_WIDTH_MASK,
		0,
		errnum,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		wbuf,
		size,
		NULL 
		);

	    CharSetCvtUTF168 cvt;

	    buf.Set( cvt.FastCvt((char *)wbuf, l * 2) );
	}
	else
	{
	    char buffer[256];

	    int l = FormatMessageA( 
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS |
		FORMAT_MESSAGE_MAX_WIDTH_MASK,
		0,
		errnum,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		buffer,
		sizeof( buffer ),
		NULL 
		);

	    buffer[l] = 0;

            buf.Set( buffer );
	}

	return buf;
}


void
Error::Net( 
	const char *op,
	const char *arg )
{
	DWORD errnum = WSAGetLastError();
	DWORD e = errnum - WSABASEERR;

	// errnum == 0 means we don't have the actual error
	if( errnum == 0 )
	    Set( MsgOs::NetUn ) << op << arg << 0;
	else if( e >= 1001 && e <= 1004 ) 
	    Set( MsgOs::Net ) << op << arg << nt_sock_errlist2[ e - 1001 ];
	else if( e >= 1 && e <= 112 )
	    Set( MsgOs::Net ) << op << arg << nt_sock_errlist[ e ];
	else 
	    Set( MsgOs::NetUn ) << op << arg << (int)e;
}

int
Error::GetNetError()
{
	return WSAGetLastError();
}

void
Error::SetNetError(int errnum)
{
	WSASetLastError(errnum);
}

bool
Error::IsSysError()
{
	return GetLastError() != 0;
}

bool
Error::IsNetError()
{
	return WSAGetLastError() != 0;
}

bool
Error::IsSysNetError()
{
	return (WSAGetLastError() != 0) || (GetLastError() != 0);
}


# else /* OS_NT */

void
Error::Sys( 
	const char *op,
	const char *arg )
{
# ifdef NOSTRERROR
	if( errno > 0 && errno <= sys_nerr )
	    Set( MsgOs::Sys ) << op << arg << sys_errlist[ errno ];
	else
	    Set( MsgOs::SysUn ) << op << arg << errno;

# else
	Set( MsgOs::Sys ) << op << arg << strerror( errno );
# endif
}

// Set the passed-in buf to the message for the current errno and return a reference to it
// [static]
StrPtr &
Error::StrError(StrBuf &buf)
{
	return StrError( buf, errno );
}

// [static]
StrPtr &
Error::StrNetError(StrBuf &buf)
{
	return StrError( buf, errno );
}

// [static]
StrPtr &
Error::StrError(StrBuf &buf, int errnum)
{
# ifdef NOSTRERROR
	if( errnum > 0 && errnum <= sys_nerr )
	{
	    buf.Set( sys_errlist[ errnum ] );
	}
	else
	{
	    StrNum errnum( errnum );

	    buf.Set( errnum );
	}
# else
	buf.Set( strerror( errnum ) );
# endif

	return buf;
}

// sys, net, sys|net all the same on unix
bool
Error::IsSysError()
{
	return errno != 0;
}

bool
Error::IsNetError()
{
	return errno != 0;
}

bool
Error::IsSysNetError()
{
	return errno != 0;
}

int
Error::GetNetError()
{
	return errno;
}

void
Error::SetNetError(int errnum)
{
	errno = errnum;
}
	
void
Error::Net( 
	const char *op,
	const char *arg )
{
	Sys( op, arg );
}

# endif

void
Error::Net2(
	const char *op,
	const char *arg )
{
    StrBuf  buf;

    StrNetError( buf );
    Set( MsgOs::Sys2 ) << op << arg << buf;
}
