// -*- mode: C++; tab-width: 4; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/*
 * NetUtils
 *
 * Copyright 2011 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

	// define this before including netportipv6.h to get the Winsock typedefs
# define INCL_WINSOCK_API_TYPEDEFS 1

# include "netportipv6.h"	// must be included before stdhdrs.h
# include <stdhdrs.h>
# include <error.h>
# include <ctype.h>
# include "strbuf.h"
# include "netport.h"
# include "netipaddr.h"
# include "netutils.h"
# include "netsupport.h"
# include "debug.h"
# include "netdebug.h"

typedef unsigned int p4_uint32_t;    // don't conflict with any other definitions of uint32_t

// this *should* be defined everywhere that supports IPv6, but just in case ...
# ifndef IN6_IS_ADDR_UNSPECIFIED
	# define IN6_IS_ADDR_UNSPECIFIED(a)           \
	    (((const p4_uint32_t *) (a))[0] == 0      \
	     && ((const p4_uint32_t *) (a))[1] == 0   \
	     && ((const p4_uint32_t *) (a))[2] == 0   \
	     && ((const p4_uint32_t *) (a))[3] == 0)
# endif

// see net/netportipv6.h for a description of the _MSC_VER values

/*
 * sigh.  VS 2010 defines inet_ntop() and inet_pton(), but its implementation
 * calls code in ws2_32.dll; that code doesn't exist until Vista or Server 2008.
 * We need to run on XP SP2 and Server 2003 SP1 so we'll just always use our own
 * version.
 */
# if defined(OS_MINGW) || (defined(OS_NT) && defined(_MSC_VER))
  # if defined(_MSC_VER)
    # define DLL_IMPORT   __declspec( dllimport )
    # define DLL_EXPORT   __declspec( dllexport )

    // VS 2005 or VS 2008 (VS 2010 is >= 1600)
    # if (_MSC_VER < 1400)
      // before VS 2005
      # error This version (_MSC_VER) of MS Visual Studio does not support IPv6.
    # endif
    # define INET_NTOP_RET_TYPE PCSTR
    # define INET_NTOP_SRC_TYPE PVOID
    # define INET_PTON_SRC_TYPE PCSTR
  # else
    // OS_MINGW
    # define DLL_IMPORT
    # define DLL_EXPORT

    # define INET_NTOP_RET_TYPE const char *
    # define INET_NTOP_SRC_TYPE const void *
    # define INET_PTON_SRC_TYPE const char *
  # endif
  # define INET_PTON_RET_TYPE   int

  // use the real Windows (ASCII) definitions if possible
  # ifdef LPFN_INET_NTOP
      typedef LPFN_INET_NTOPA pfunc_ntop_t;
  # else
      typedef INET_NTOP_RET_TYPE (WSAAPI * pfunc_ntop_t)(INT, INET_NTOP_SRC_TYPE, PSTR, size_t);
  # endif
  # ifdef LPFN_INET_PTON
      typedef LPFN_INET_PTONA pfunc_pton_t;
  # else
      typedef INET_PTON_RET_TYPE (WSAAPI * pfunc_pton_t)(INT, INET_PTON_SRC_TYPE, PVOID);
  # endif

// mingw32 or Visual Studio

// job063342: the name of the winsock dll
static const TCHAR *WINSOCK_DLL = TEXT("ws2_32.dll");

/*
 * MINGW doesn't currently (v4.5) provide inet_ntop() or inet_pton()
 * This is Windows-only code, so I'm setting the socket error via
 * WSASetLastError(); I *think* that I'm using the correct values.
 */

// our private implementation of inet_ntop
static INET_NTOP_RET_TYPE
p4_inet_ntop_impl(
	int af,
	INET_NTOP_SRC_TYPE src,
	char *hostbuf,    // should be at least NI_MAXHOST bytes
	TYPE_SOCKLEN size)
{
	*hostbuf = '\0';    // initialize to empty string

	if( af == AF_INET )
	{
	    struct sockaddr_in in;
	    ::memset( &in, 0, sizeof(in) );
	    in.sin_family = AF_INET;
	    ::memcpy( &in.sin_addr, src, sizeof(struct in_addr) );
	    int stat = ::getnameinfo( reinterpret_cast<struct sockaddr *>(&in),
	                   sizeof(struct sockaddr_in),
	                   hostbuf, size, NULL, 0, NI_NUMERICHOST );
	    if( stat )
	        ::WSASetLastError( stat );
	    return stat == 0 ? hostbuf : NULL;
	}
	else if( af == AF_INET6 )
	{
	    struct sockaddr_in6 in;
	    ::memset( &in, 0, sizeof(in) );
	    in.sin6_family = AF_INET6;
	    ::memcpy( &in.sin6_addr, src, sizeof(struct in_addr6) );
	    int stat = ::getnameinfo( reinterpret_cast<struct sockaddr *>(&in),
	                   sizeof(struct sockaddr_in6),
	                   hostbuf, size, NULL, 0, NI_NUMERICHOST );
	    if( stat )
	        ::WSASetLastError( stat );
	    return stat == 0 ? hostbuf : NULL;
	}

	// unsupported address family requested
	::WSASetLastError( WSAEAFNOSUPPORT );
	return NULL;
}

/*
 * Wrapper function to call the system inet_ntop() function if it exists,
 * or our private implementation if it doesn't.
 * Windows only.
 */
INET_NTOP_RET_TYPE
p4_inet_ntop(
	int af,
	INET_NTOP_SRC_TYPE src,
	char *hostbuf,    // should be at least NI_MAXHOST bytes
	TYPE_SOCKLEN size)
{
	// assume that the winsock dll doesn't change while we're running
	static pfunc_ntop_t	p_inet_ntop = reinterpret_cast<pfunc_ntop_t>(
				    ::GetProcAddress(::GetModuleHandle(WINSOCK_DLL), "inet_ntop") );

	if( p_inet_ntop )
	    return p_inet_ntop( af, src, hostbuf, size );
	else
	    return p4_inet_ntop_impl( af, src, hostbuf, size );
}

// our private implementation of inet_pton
static INET_PTON_RET_TYPE
p4_inet_pton_impl(
	int af,
	INET_PTON_SRC_TYPE src,
	void *dst)    // must be at least INET6_ADDRSTRLEN bytes
{
	if( (af != AF_INET) && (af != AF_INET6) )
	{
	    // errno = EAFNOSUPPORT;
	    return -1;
	}

	struct addrinfo hints;
	struct addrinfo *res;

	::memset( &hints, 0, sizeof(struct addrinfo) );
	hints.ai_family = af;

	if( ::getaddrinfo(src, NULL, &hints, &res) != 0 )
	{
	    return 0;
	}

	if( res == NULL )
	{
	    // shouldn't happen
	    return 0;
	}

	// return the first address
	// job063342 : just the address part, not the family, port, etc
	const void *addrp = NetUtils::GetInAddr(res->ai_addr);
	const size_t addrlen = NetUtils::GetAddrSize(res->ai_addr);
	::memcpy( dst, addrp, addrlen );

	::freeaddrinfo( res );

	return 1;
}

/*
 * Wrapper function to call the system inet_pton() function if it exists,
 * or our private implementation if it doesn't.
 * Windows only.
 */
INET_PTON_RET_TYPE
p4_inet_pton(
	int af,
	INET_PTON_SRC_TYPE src,
	void *dst)    // must be at least INET6_ADDRSTRLEN bytes
{
	// assume that the winsock dll doesn't change while we're running
	static pfunc_pton_t	p_inet_pton = reinterpret_cast<pfunc_pton_t>(
				    ::GetProcAddress(::GetModuleHandle(WINSOCK_DLL), "inet_pton") );

	if( p_inet_pton )
	    return p_inet_pton( af, src, dst );
	else
	    return p4_inet_pton_impl( af, src, dst );
}
# endif // OS_MINGW || (OS_NT && Visual Studio)

# if defined(OS_MINGW) || defined(OS_NT)
/*
 * IPv4 only!
 * return zero on failure, non-zero on success
 *
 * Accepts 1 to 4 numeric fields, separated by periods.
 * Each field can be decimal, octal (if preceded by "0"),
 * or hex (if preceded by "0x" or "0X");
 * If just one field, it's the host number
 * (and so is right-justified).
 * We don't allow leading or trailing whitespace.
 * We do allow addr to be NULL, in which case we simply
 * return non-zero if cp points to a valid IPv4 address (or fragment).
 *
 * Fills *addr (if non-NULL) in network byte order.
 *
 * If some future version of Visual Studio defines this routine
 * then this will cause a conflict.  At that time we'll ifdef this
 * for the appropriate value of _MSC_VER.
 */
int
inet_aton(
	const char *cp,
	in_addr *addr)
{
	int base = 10;
	bool valid = false;	// have we seen a valid digit string yet?
	p4_uint32_t val = 0;
	int chunk_index = 0;
	p4_uint32_t chunks[4];
	unsigned char ch;

	// max (host) values for each chunk
	static p4_uint32_t limits[4] = {
	    0xFFFFFFFF, // 32 bits (/0)
	    0x00FFFFFF, // 24 bits (/8)
	    0x0000FFFF, // 16 bits (/16)
	    0x000000FF  //  8 bits (/24)
	};

	while( ch = *cp )
	{
	    val = 0;	// re-initialize for each chunk
	    base = 10;	// each field starts as decimal

	    // each chunk may switch the base
	    if( ch == '0')
	    {
	        if( ((ch = *++cp) == 'x') || (ch == 'X') )
	        {
	            base = 16;
	            cp++;
	        }
	        else
	        {
	            base = 8;
	            valid = true;
	        }

	        // I guess they mean just a value of 0
	        if( !*cp )
	            break;
	    }

	    while( ch = *cp )
	    {
	        // compute the value of this chunk
	        if( isdigit(ch) )
	        {
	            if( (base == 8) && (ch == '8' || ch == '9') )
	                return 0;    // illegal digit in an octal number
	            valid = true;
	            val = (val * base) + (ch - '0');
	            cp++;
	        }
	        else if( (base == 16) && isxdigit(ch) )
	        {
	            valid = true;
	            val = (val << 4) + (ch + 10 - (islower(ch) ? 'a' : 'A'));
	            cp++;
	        }
	        else
	        {
	            break;
	        }
	    }

	    if( ch == '.' )
	    {
	        // chunk_index counts the number of dots (max 3)
	        if( (chunk_index > 2) || (val > limits[chunk_index]) )
	            return 0;
	        chunks[chunk_index++] = val;
	        valid = false;
	        cp++;
	    }
	    else if( !ch )
	    {
	        break;
	    }
	    else
	    {
	        // anything else is invalid
	        return 0;
	    }
	}

	// Must have seen at least one valid digit in this chunk to continue;
	// a trailing dot will fail here.
	if( !valid )
	    return 0;

	/*
	 * Now chunks has the value of each chunk (delimited by a following '.')
	 * and val has the last value (not followed by a '.'),
	 * and chunk_index is the index of where the next chunk (if any) should
	 * be written; it counts the number of dots seen.
	 */

	// return failure if any chunk exceed its limit
	for( int i = 0; i < chunk_index; i++ )
	{
	    if( chunks[i] > limits[i] )
	        return 0;
	}
	// and check the last part (which isn't in a chunk)
	if( val > limits[chunk_index] )
	    return 0;

	switch( chunk_index )
	{
	case 0:	// 192 (0.32), so a host number
	    break;
	case 1: // 192.168 (8.24)
	    val |= (chunks[0] << 24);
	    break;
	case 2: // 192.168.1 (8.8.16)
	    val |= (chunks[0] << 24) | (chunks[1] << 16);
	    break;
	case 3: // 192.168.1.2 (8.8.8.8)
	    val |= (chunks[0] << 24) | (chunks[1] << 16) | (chunks[2] << 8);
	    break;
	}

	if( addr )
	    addr->s_addr = htonl(val);

	return 1;
}
# endif // OS_MINGW || OS_NT

/*
 * convenience wrapper for setsockopt
 */
int
NetUtils::setsockopt( const char *module, int sockfd, int level, int optname, const SOCKOPT_T *optval, socklen_t optlen, const char *name )
{
	int retval = ::setsockopt( sockfd, level, optname, (char *)optval, optlen );
	if( retval < 0 )
	{
	    if( DEBUG_CONNECT )
	    {
	        StrBuf errnum;
	        Error::StrNetError( errnum );
	        p4debug.printf( "%s setsockopt(%s, %d) failed, error = %s\n",
	            module, name, *reinterpret_cast<const int *>(optval), errnum.Text() );
	    }
	}

	return retval;
}

/*
 * Get IPv4 or IPv6 sin[6]_addr ptr convenience function.
 * Returns the sockaddr's sin_addr or sin6_addr pointer,
 * depending on the sockaddr's family.
 * Returns NULL if the sockaddr is neither IPv4 nor IPv6.
 */
const void *
NetUtils::GetInAddr(const struct sockaddr *sa)
{
	if( sa->sa_family == AF_INET )
	{
	    return &(reinterpret_cast<const sockaddr_in *>(sa))->sin_addr;
	}
	else if( sa->sa_family == AF_INET6 )
	{
	    return &(reinterpret_cast<const sockaddr_in6 *>(sa))->sin6_addr;
	}
	else
	{
	    return NULL;
	}
}

/**
 * Get IPv4 or IPv6 sockaddr size convenience function.
 * Returns 0 if the sockaddr is neither IPv4 nor IPv6.
 */
size_t
NetUtils::GetAddrSize(const sockaddr *sa)
{
	if( sa->sa_family == AF_INET )
	{
	    return sizeof *(reinterpret_cast<const sockaddr_in *>(sa));
	}
	else if( sa->sa_family == AF_INET6 )
	{
	    return sizeof *(reinterpret_cast<const sockaddr_in6 *>(sa));
	}
	else
	{
	    return 0;
	}
}

/*
 * Get IPv4 or IPv6 sin[6]_port convenience function.
 * Returns the sockaddr's sin_addr or sin6_addr port,
 * depending on the sockaddr's family.
 * Returns -1 if the sockaddr is neither IPv4 nor IPv6.
 */
int
NetUtils::GetInPort(const sockaddr *sa)
{
	int	port;

	if( sa->sa_family == AF_INET )
	{
	    port = (reinterpret_cast<const sockaddr_in *>(sa))->sin_port & 0xFFFF;
	}
	else if( sa->sa_family == AF_INET6 )
	{
	    port = (reinterpret_cast<const sockaddr_in6 *>(sa))->sin6_port & 0xFFFF;
	}
	else
	{
	    return -1;
	}

	return ntohs( port );
}

/*
 * Return true iff this address is unspecified ("0.0.0.0" or "::").
 * [static]
 */
bool
NetUtils::IsAddrUnspecified(const sockaddr *sa)
{
	if( sa->sa_family == AF_INET )
	{
	    const struct in_addr *iap = &(reinterpret_cast<const sockaddr_in *>(sa))->sin_addr;
	    const p4_uint32_t *ap = reinterpret_cast<const p4_uint32_t *>(iap);
	    return *ap == INADDR_ANY;
	}
	else if( sa->sa_family == AF_INET6 )
	{
	    return IN6_IS_ADDR_UNSPECIFIED( &(reinterpret_cast<const sockaddr_in6 *>(sa))->sin6_addr );
	}
	else
	{
	    return true;    // huh? I guess we'll call it unspecified
	}
}

/*
 * Set this address to the appropriate wildcard address.
 * Return true iff it had a valid family.
 * [static]
 */
bool
NetUtils::SetAddrUnspecified(sockaddr *sa)
{
	if( sa->sa_family == AF_INET )
	{
	    struct in_addr *iap = &(reinterpret_cast<sockaddr_in *>(sa))->sin_addr;
	    p4_uint32_t *ap = reinterpret_cast<p4_uint32_t *>(iap);
	    *ap = INADDR_ANY;
	    return true;
	}
	else if( sa->sa_family == AF_INET6 )
	{
	    struct in6_addr	*in6 = &(reinterpret_cast<sockaddr_in6 *>(sa))->sin6_addr;
	    p4_uint32_t		*a = reinterpret_cast<p4_uint32_t *>(in6);
	    a[0] = 0;
	    a[1] = 0;
	    a[2] = 0;
	    a[3] = 0;

	    return true;
	}

	return false;
}

/*
 * Is this an IPv6 sockaddr?
 * [static]
 */
bool
NetUtils::IsAddrIPv6(const sockaddr *sa)
{
	return sa->sa_family == AF_INET6;
}

/*
 * Simple function to test whether or not a string looks like an IP address in
 * dotted notation, or not. The test is just that it contains only numbers and
 * exactly 3 '.' chars - nothing more sophisticated than that.
 * However, an arbitrary port specification (digits) may be appended after a ':'.
 * NB:  Unlike IPv6 addresses, IPv4 addresses may NOT be enclosed in square brackets.
 *
 * If allowPrefix is true then allow a partial address (fewer than 3 periods),
 * but prohibit a port in such a partial address.
 * [static]
 */
bool
NetUtils::IsIpV4Address( const char *str, bool allowPrefix )
{
	int numDots = 0;
	int numColons = 0;

	for( const char *cp = str; *cp; cp++ )
	{
	    if( *cp == ':' )
	    {
	        // no more than one colon allowed in an IPv4 address
	        if( ++numColons > 1 )
	            break;
	    }

	    if( *cp == '.' )
	    {
	        numDots++;
	        continue;
	    }

	    if( !isdigit(*cp & 0xFF) )
	        return false;
	}

	if( numDots > 3 || numColons > 1 )
	    return false;

	if( allowPrefix )
	{
	    return (numDots == 3) || (numColons == 0);
	}

	return (numDots == 3);
}

/*
 * Simple function to test whether or not a string looks like an IPv6 address in
 * hex colon (or IPv4-mapped dotted) notation, or not. The test is just:
 * - it contains only hexadecimal digits and the ':' char,
 *   optionally followed by a zone id ('%' and any alphanumeric chars).
 * - if it contains any periods then it must end in a valid-looking complete
 *   IPv4 embedded address (optionally followed by a scope-id).
 * - and there must be at least 2 colons (not counting the scope-id portion, if any).
 * - allow the address optionally to be enclosed by square brackets, eg: [::1]
 * - nothing more sophisticated than that.
 *
 * - TODO: check that IPv4-mapped addresses start with 80 bits of zero followed by
 *   16 bits of 1, followed by an IPv4 address.
 *
 * Accept an allowPrefix 2nd argument to match IsIpV4Address(), but ignore it;
 * IPv6 addresses and prefixes must always have at least 2 colons,
 * and we don't allow partial mapped IPv4 addresses (that's just plain silly).
 * [static]
 */
bool
NetUtils::IsIpV6Address( const char *str, bool /* allowPrefix */ )
{
	int numColons = 0;
	int numDots = 0;
	bool brackets = (*str == '[');

	if( brackets )
	    str++;

	for( const char *cp = str; *cp; cp++ )
	{
	    switch( *cp )
	    {
	    case '%':
	        while( *++cp )
	        {
	            if( !isalnum(*cp & 0xFF) )
	                return false;
	        }
	        return (numColons >= 2) && (numDots == 0 || numDots == 3);
	        break;
	    case ':':
	        // no colons allowed in mapped-V4 section
	        if( numDots > 0 )
	            return false;
	        numColons++;
	        break;
	    case '.':
	        numDots++;
	        break;
	    case ']':
	        // allow a right bracket only at the end
	        // and only if str began with a left bracket
	        if( !brackets || cp[1] )
	            return false;
	        break;
	    default:
	        if( !isxdigit(*cp & 0xFF) )
	            return false;
	        break;
	    }
	}

	return (numColons >= 2) && (numDots == 0 || numDots == 3);
}

/*
 * Simple function to check whether an IP is loopback, as defined by
 * the IANA as:
 *    IPv4 = 127.0.0.1/8
 *    IPv6 = ::1
 *
 * IPv6 mapped IPv4 loopback addresses that theoretically are valid,
 * but it's unlikely that we'll ever encounter them in the wild.
 */
bool
NetUtils::IsLocalAddress( const char *addr )
{
	static const NetIPAddr localV4(StrRef("127.0.0.1"), 8);
	static const NetIPAddr localV6(StrRef("::1"), 128);
	static const NetIPAddr localMapped(StrRef("::ffff:127.0.0.1"), 104); // 80 + 16 + 8

	// empty string means connect to localhost or bind to all interfaces (including local)
	if( *addr == '\0' )
	    return true;

	const NetIPAddr tgtAddr(StrRef(addr), 0);

	if( tgtAddr.IsTypeV4() )
	    return tgtAddr.Match(localV4);

	if( tgtAddr.IsTypeV6() )
	    return tgtAddr.Match(localV6) || tgtAddr.Match(localMapped);

	return false;
}

// return a printable address
void
NetUtils::GetAddress(
	int family,
	const sockaddr *addr,
	int raf_flags,
	StrBuf &printableAddress)
{
# ifndef OS_NT
	typedef const void *INADDR_PTR_TYPE;
# else
	typedef PVOID INADDR_PTR_TYPE;
# endif

	if( (family != AF_INET) && (family != AF_INET6) )
	{
	    // don't worry about RAF_NAME and RAF_PORT if we don't understand the address family
	    printableAddress.Set( "unknown" );
	    return;
	}

	printableAddress.Clear();
	printableAddress.Alloc( P4_INET6_ADDRSTRLEN );
	printableAddress.SetLength(0);
	printableAddress.Terminate();

	// default to numeric host string; we'll clear this if we get a name
	bool wantNumericHost = true;
	bool isIPv6 = IsAddrIPv6(addr);

	// don't try to DNS-resolve an unspecified address -- it'll just timeout after a few seconds anyway
	if( (raf_flags & RAF_NAME) && !IsAddrUnspecified(addr) )
	{
	    // try to get the (DNS) name of the server; fall back to the numeric form of the hostname.
	    int bufsize = (NI_MAXHOST >= P4_INET6_ADDRSTRLEN) ? NI_MAXHOST : P4_INET6_ADDRSTRLEN ;
	    printableAddress.Alloc( bufsize );

# ifdef NI_NAMEREQD
	    // try the modern way (getnameinfo)

	    /*
	     * For IPv4 do not pass NI_NAMEREQD, so if it can't get the name,
	     * getnameinfo will fill in the numeric form of the hostname.
	     * For IPv6 do pass NI_NAMEREQD, so we can add the "[...]" later
	     * with the numeric address.
	     */
	    const int flags = isIPv6 ? NI_NAMEREQD : 0;
	    if( !::getnameinfo( addr, GetAddrSize(addr), printableAddress.Text(), NI_MAXHOST, NULL, 0, flags ) )
	    {
	        printableAddress.SetLength();
	        wantNumericHost = false;
	    }
# else
	    // no, try it the old-fashioned non-re-entrant way (gethostbyaddr)
	    struct hostent *h = NULL;
	    if( h = ::gethostbyaddr( GetInAddr(addr), GetAddrSize(addr), addr->sa_family ) && h->h_name )
	    {
	        printableAddress << h->h_name;
	        wantNumericHost = false;
	    }
# endif // NI_NAMEREQD
	}

	// either the caller wanted the numeric form, or we tried to get a hostname but failed
	if( wantNumericHost )
	{
	    char *buf = printableAddress.Text();

	    // format IPv6 numeric addresses nicely to make them easier to read (and unambiguous)
	    if( isIPv6 )
	    {
	        printableAddress.Set( "[" );
	        buf++;
	    }

	    // just get the numeric form of the hostname.
	    if( ::inet_ntop( family, (INADDR_PTR_TYPE)GetInAddr(addr), buf, INET6_ADDRSTRLEN ) )
	    {
	        printableAddress.SetLength();
	    }
	    else
	    {
	        // I give up
	        printableAddress.Set( "unknown" );
	    }

	    if( isIPv6 )
	        printableAddress.Append( "]" );
	}

	if( raf_flags & RAF_PORT )
	{
	    // caller also wants the portnum
	    int portnum = GetInPort( addr );
	    StrNum numbuf( portnum );

	    printableAddress.Append( ":" );
	    printableAddress.Append(&numbuf);
	}
}

# ifdef OS_NT
// initialize windows networking
// returns 0 on success, error code on failure
// [static]
int
NetUtils::InitNetwork()
{
	WSADATA wsaData;

	int starterr = WSAStartup(MAKEWORD(2,2), &wsaData);
	if (starterr != 0)
	{
	    int err = WSAGetLastError();
	    return err;
	}

	return 0;
}

// cleanup windows networking
// [static]
void
NetUtils::CleanupNetwork()
{
	WSACleanup();
}
#else
int
NetUtils::InitNetwork()
{
	return 0;
}

void
NetUtils::CleanupNetwork()
{
}
# endif // OS_NT
