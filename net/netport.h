// -*- mode: C++; tab-width: 4; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/*
 * Copyright 2011 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 *
 * System- and compiler-dependent definitions for portability.
 */

// network portability definitions moved from nettcp.cc
// I tried to make it uglier, but that wasn't easy

# ifdef OS_NT
# include <winsock2.h>
# include <ws2tcpip.h>
# ifndef OS_MINGW
# include <wspiapi.h> // required for p4v win2k build
# endif
# else
# ifdef OS_BEOS
# include <net/socket.h>
# else
# ifdef OS_LYNX
# define __NO_INCLUDE_WARN__
# endif
# ifdef OS_ZETA
# include <arpa/inet.h>
# endif

extern "C" {    // because PTX doesn't do this for socket.h

# include <sys/socket.h>
# include <netinet/in.h>

}

# endif

#ifdef OS_HPUX
# if !defined(_XOPEN_SOURCE_EXTENDED) && defined(__ia64) && !defined(_LIBC)
# define TYPE_SOCKLEN    int
# endif
# ifndef _INCLUDE_HPUX_SOURCE
  /*
   * _INCLUDE_HPUX_SOURCE is needed for getaddrinfo and friends (netdb.h)
   * unfortunately, this will enable lots of other stuff,
   * so we'll define it and include netdb.h here and then turn it off
   * afterwards.
   */
# define _INCLUDE_HPUX_SOURCE
# include <netdb.h>
# undef _INCLUDE_HPUX_SOURCE
# else // _INCLUDE_HPUX_SOURCE was already defined
# include <netdb.h>
# endif // end of _INCLUDE_HPUX_SOURCE
# else // not HPUX
# include <netdb.h>
# endif // end of !OS_HPUX

# include <unistd.h>
# if defined(OS_FREEBSD) || defined(OS_MACHTEN) || defined(OS_LINUX)
# include <netinet/tcp.h>
# endif
# ifdef OS_OS2
# include <utils.h>
# endif
# ifdef OS_VMS
# include <unixio.h>
# endif
# endif /* OS_NT */

# if defined( AF_UNIX ) && !defined( OS_NT )
# include <sys/time.h>
# endif

# if defined( OS_AIX43 ) || defined( OS_AIX53 )
# include <strings.h>
# endif

# if defined(OS_MACHTEN) || \
	defined(OS_AIX32) || \
	defined(OS_MVS) || \
	defined(OS_SUNOS)
extern "C" int accept(int, struct sockaddr *, int *);  
extern "C" int bind(int, const struct sockaddr *, int); 
extern "C" int connect(int, const struct sockaddr *, int); 
extern "C" int listen(int, int); 
extern "C" int socket(int, int, int); 
extern "C" int getsockname( int, const struct sockaddr *, int * );
extern "C" int getpeername (int, struct sockaddr *, int *);
extern "C" int getsockopt( int, int, int, void *, int * );
extern "C" int setsockopt( int, int, int, void *, int );
# endif

# if !defined(OS_NT) && !defined(OS_OS2) && \
     !defined(OS_NCR) && !defined(OS_NEXT)
//extern "C" unsigned long inet_addr(const char *);
# endif

# if defined(NEED_SOCKET_IO)
# if defined(OS_NT) || defined(OS_BEOS)
# define close( s ) closesocket( s )
# define read( s, b, l ) recv( s, b, l, 0 )
# define write( s, b, l ) send( s, b, l, 0 )
# ifndef INADDR_LOOPBACK
# define INADDR_LOOPBACK 0x7f000001
# endif
# endif
# endif

# if defined(NEED_SOCKET_IO)
# ifdef OS_OS2
# define close( s ) soclose( s )
# define read( s, b, l ) recv( s, b, l, 0 )
# define write( s, b, l ) send( s, b, l, 0 )
# endif
# endif

# ifdef OS_MVS
# define htons(x) (x)    // yeeuck!
# define htonl(x) (x)
# define ntohs(x) (x)
# endif

# ifdef OS_AS400
# define NI_MAXHOST 255  // needed by our call to getnameinfo(), but not 
	                 // defined in any header files. Value is just a 
	                 // guess. Should perhaps be larger/smaller?
	                 // RFCs 2143, 2553 suggest 1025
# endif

// __BITS_SOCKET_H is an attempt to catch > 4.2 linux

# ifdef OS_VMS
# define TYPE_SOCKLEN unsigned 
# endif
# if defined( OS_LINUX42AXP ) || defined( OS_AIX41 ) || defined( OS_AIX43 ) || \
	defined( OS_AIX5IA64 )
# define TYPE_SOCKLEN unsigned long
# endif
# if defined( OS_UNIXWARE ) || defined( OS_SINIX ) || defined( OS_QNXNTO )
# define TYPE_SOCKLEN size_t
# endif
# if defined( __BITS_SOCKET_H  ) || \
	defined( OS_FREEBSD )   || defined( OS_OPENBSD)    || \
        defined( OS_NETBSD )    || defined( OS_LYNX )      || \
	defined( OS_SOLARIS8 )  || defined( OS_SOLARIS10 ) || \
	( defined( OS_MACOSX )  && OS_VER >= 104 )      || \
	defined( OS_DARWIN )    || defined( OS_AIX53 )
# define TYPE_SOCKLEN socklen_t
# endif
# ifdef OS_AIX
  /*
   * I'm guessing that this is needed for all versions of AIX;
   * It would be safer to define __ss_family to ss_family for all
   * except AIX, and use __ss_family in all the source code,
   * but that's really ugly.
   */
# define ss_family __ss_family
# endif
# if defined( OS_LINUX ) && !defined( TYPE_SOCKLEN )
# define TYPE_SOCKLEN unsigned int
# endif
# if defined (OS_MACOSX) && (__GNUC__ == 4)
# define TYPE_SOCKLEN socklen_t
# endif
# ifndef TYPE_SOCKLEN
# define TYPE_SOCKLEN int
# endif

# define DARWIN_MAX 32*1024
