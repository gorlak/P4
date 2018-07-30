// -*- mode: C++; tab-width: 4; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/*
 * netportipv6.h - required network address #defines and #includes for IPv6
 *
 * Copyright 2011 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <sys/types.h>

# ifdef OS_NT
	# define WIN32_LEAN_AND_MEAN

	/*
	 * sdkddkver.h will set _WIN32_WINNT to a default value if we don't,
	 * so set it to our desired (minimum) value (_WIN32_WINNT_VISTA).
	 * sdkddkver.h will set NTDDI_VERSION and WINVER based
	 * on the value of _WIN32_WINNT, so we don't need to set them.
	 * We must use values, not names, because the names are defined
	 * in sdkddkver.h, and we haven't included it yet.
	 * Microsoft should have split sdkddkver.h into two pieces;
	 * one which defines all the names, and one that sets the defaults.
	 * Then we could include the first, set _WIN32_WINNT to _WIN32_WINNT_VISTA,
	 * and then include the second.  They didn't, so we must use
	 * the numerical value here.
	 */
	# if !defined(_WIN32_WINNT) || (_WIN32_WINNT < 0x0600)
	#   undef _WIN32_WINNT
	#   define _WIN32_WINNT     0x0600
	# endif // _WIN32_WINNT
	
	# if defined(_MSC_VER) && (_MSC_VER >= 1500)
	    /*
	     * Get the default values of _WIN32_WINNT_*, NTDDI_*, etc.
	     * This file doesn't exist in MINGW, so we'll use it only in MSVC
	     * (but it exists only in VS 2008 and later).
	     */
	    # include <sdkddkver.h>
	#  endif

	// see http://msdn.microsoft.com/en-us/library/aa383745(v=VS.85).aspx
	    // was NTDDI_WINXPSP3, _WIN32_WINNT_WS03
	    // need VISTA for inet_ntop

	/*
	 * See: http://predef.sourceforge.net/precomp.html#sec32
	 *
	 * VS Year     VS Ver    _MSC_VER
	 * --------    -------   --------
	 *               7.0       1300
	 * 2003          7.1       1310
	 * 2005          8.0       1400
	 * 2008          9.0       1500
	 * 2010         10.0       1600
	 */

	//# if defined(OS_MINGW) || !defined(_MSC_VER) || (_MSC_VER < 1600)
	    // needed to allow building on pre-VS2010,
	    // but we'll always check, just to be sure
	    # ifndef _WIN32_WINNT_VISTA
	        # define _WIN32_WINNT_VISTA    0x0600
	    # endif

	    # ifndef NTDDI_VISTA
	        # define NTDDI_VISTA           0x06000000
	    # endif
	//# endif

	// Now we can use names (eg, _WIN32_WINNT_VISTA) rather than values (eg, 0x600).
	// In MSVC these *should* all have the correct values already,
	// but maybe not in MINGW or VS 2005.
        # if !defined(NTDDI_VERSION) || (NTDDI_VERSION < NTDDI_VISTA)
	#   undef NTDDI_VERSION
	#   define NTDDI_VERSION    NTDDI_VISTA
        # endif // NTDDI_VERSION
        # if !defined(_WIN32_WINNT) || (_WIN32_WINNT < _WIN32_WINNT_VISTA)
	#   undef _WIN32_WINNT
	#   define _WIN32_WINNT     _WIN32_WINNT_VISTA
        # endif // _WIN32_WINNT
        # if !defined(WINVER) || (WINVER < _WIN32_WINNT)
	#   undef WINVER
	#   define WINVER           _WIN32_WINNT
        # endif // WINVER

	# include <winsock2.h>
	# include <ws2tcpip.h>

	# if defined(_MSC_VER) && (_MSC_VER < 1400)
	    // too old!
	    # error This version (_MSC_VER) of MS Visual Studio does not support IPv6.
	# endif

	# if defined(OS_MINGW) || (defined(_MSC_VER) && (_MSC_VER < 1500))
	    // mingw32, or VS 2005 -- Windows XP and Windows Server 2003
	    // add in values not defined here, in hopes the OS supports them
	    // with these values
	    # ifndef AI_V4MAPPED
	        # define AI_V4MAPPED     0x00000800  // On v6 failure, query v4 and convert to V4MAPPED format
	    # endif
	    # ifndef AI_ALL
	        # define AI_ALL          0x00000100  // Query both IP6 and IP4 with AI_V4MAPPED
	    # endif
	    # ifndef AI_ADDRCONFIG
	        # define AI_ADDRCONFIG   0x00000400  // Resolution only if global address configured
	    # endif
	    # ifndef IPV6_V6ONLY
	        # define IPV6_V6ONLY     27 // Treat wildcard bind as AF_INET6-only.
	    # endif
	# endif

	// Windows uses a non-standard type for the sockopt arg
	typedef char    SOCKOPT_T;
	typedef IN_ADDR	in_addr_t;
	//typedef IN6_ADDR	in6_addr_t;
	
	# define IN_ADDR_VAL(x)	(x.s_addr)
# else // !OS_NT
	# include <arpa/inet.h>
	# include <netdb.h>
	# include <netinet/in.h>

	typedef int     SOCKOPT_T;

	/*
	 * NetBSD and a number of others specifically stripped out AI_ALL
	 * and friends, in response to NetBSD PR 18072.
	 *
	 * AI_ALL/et al are unsupported and unused on NetBSD. However,
	 * they are required to be defined by standards, so it is
	 * reasonable to expect them to be defined. Unfortunately, they
	 * aren't even as late as NetBSD 5.1.2 (released on 2012/02/11).
	 *
	 * It is reasonable to redefine them here on those systems where
	 * netdb.h breaks the standards and fails to do so.
	 */

	#ifndef AI_ALL
	# define AI_ALL 0
	#endif
	#ifndef AI_V4MAPPED
	# define AI_V4MAPPED 0
	#endif
	#ifndef AI_ADDRCONFIG
	# define AI_ADDRCONFIG 0
	#endif

	# define IN_ADDR_VAL(x)	(x)
# endif // OS_NT
