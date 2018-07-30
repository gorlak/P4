/*
 * Copyright 2001 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * NoEcho -- Turn terminal echoing off/on
 *
 * Declaring a NoEcho object turns off terminal echoing (if possible).
 * Deleting it turns it back on.
 */

# ifdef OS_NT
# define NEED_FILE
# define NEED_FCNTL
# endif

# include <stdhdrs.h>
# include <signaler.h>

# include "echoctl.h"

/*
 * NoEcho - turn on/off echoing
 */

// These next few lines will get ported to hell

# ifdef OS_NT
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
typedef DWORD TIO_T;
# define hstdin (HANDLE)_get_osfhandle( fileno( stdin ) )
# define TIO_GET(tio) GetConsoleMode( hstdin, &tio )
# define TIO_SET(tio) SetConsoleMode( hstdin, tio )
# define TIO_NOECHO(tio) tio &= ~ENABLE_ECHO_INPUT
# endif

# if defined( OS_OS2 ) || defined( MAC_MWPEF ) || \
	defined( OS_VMS ) || defined( OS_AS400 ) || \
	defined( OS_MPEIX )
// no ops
typedef int TIO_T;
# define hstdin fileno( stdin )
# define TIO_GET(tio) {}
# define TIO_SET(tio) {}
# define TIO_NOECHO(tio) {}
# endif

// For now, default to termios

# ifndef TIO_SET
# define USE_TERMIOS
# endif

# ifdef USE_TERMIOS
# include <termios.h>
typedef struct termios TIO_T;
# define TIO_GET(tio) tcgetattr( fileno( stdin ), &tio )
# define TIO_SET(tio) tcsetattr( fileno( stdin ), TCSANOW, &tio )
# define TIO_NOECHO(tio) tio.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL)
# endif

# ifdef USE_SGTTY
# include <sgtty.h>
typedef struct sgttyb TIO_T;
# define TIO_GET(tio) ioctl( fileno( stdin ), TIOCGETP, &tio )
# define TIO_SET(tio) ioctl( fileno( stdin ), TIOCSETP, &tio )
# define TIO_NOECHO(tio) tio.sg_flags &= ~(ECHO)
# endif

struct EchoContext 
{
	TIO_T tio;
	TIO_T tio2;

	EchoContext()
	{
	    memset( &tio, '\0', sizeof( tio ) );
	    memset( &tio2, '\0', sizeof( tio2 ) );
	}
} ;

void 
EchoCleanup( NoEcho *noEcho )
{
	delete noEcho;
}

NoEcho::NoEcho()
{
	context = new EchoContext;

	TIO_GET( context->tio );
	context->tio2 = context->tio;
	TIO_NOECHO( context->tio );
	TIO_SET( context->tio );
	signaler.OnIntr( (SignalFunc)EchoCleanup, this );
}

NoEcho::~NoEcho()
{
	TIO_SET( context->tio2 );
	fputc( '\n', stdout );
	signaler.DeleteOnIntr( this );
	delete context;
}
