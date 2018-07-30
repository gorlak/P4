// -*- mode: C++; tab-width: 4; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/*
 * Copyright 2011 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * netutils - Utility routines for network support
 *
 * Classes Defined:
 *
 *    NetUtils - IP network address utilities
 */

# define do_setsockopt( module, fd, level, optname, optval, optlen )	NetUtils::setsockopt( module, fd, level, optname, optval, optlen, #optname )

// a guess at a good buffer size; big enough for a max IPv6 address plus surrounding "[...]"
#define P4_INET6_ADDRSTRLEN	(INET6_ADDRSTRLEN+2)

class NetUtils
{
public:
    static const bool IPADDR_PREFIX_PROHIBIT = false;
    static const bool IPADDR_PREFIX_ALLOW = true;

    static int
    setsockopt( const char *module, int sockfd, int level, int optname, const SOCKOPT_T *optval, socklen_t optlen, const char *name );

    /*
     * Get IPv4 or IPv6 sin[6]_addr ptr convenience function.
     * Returns the sockaddr's sin_addr or sin6_addr pointer,
     * depending on the sockaddr's family.
     * Returns NULL if the sockaddr is neither IPv4 nor IPv6.
     */
    static const void *
    GetInAddr(const sockaddr *sa);

    /*
     * Get IPv4 or IPv6 sockaddr size convenience function.
     * Returns 0 if the sockaddr is neither IPv4 nor IPv6.
     */
    static size_t
    GetAddrSize(const sockaddr *sa);

    /*
     * Get IPv4 or IPv6 sin[6]_port convenience function.
     * Returns the sockaddr's sin_addr or sin6_addr port,
     * depending on the sockaddr's family.
     * Returns -1 if the sockaddr is neither IPv4 nor IPv6.
     */
    static int
    GetInPort(const sockaddr *sa);

    /*
     * Return true iff this address is unspecified ("0.0.0.0" or "::").
     */
    static bool
    IsAddrUnspecified(const sockaddr *sa);

    // make this address be unspecified
    static bool
    SetAddrUnspecified(sockaddr *sa);

    static bool
    IsAddrIPv6(const sockaddr *sa);

    static bool
    IsIpV4Address(const char *addr, bool allowPrefix);

    // allowPrefix is ignored for IPv6
    static bool
    IsIpV6Address(const char *addr, bool allowPrefix = true);

    static bool
    IsLocalAddress(const char *addr);

    // return a printable address
    static void
    GetAddress(
	    int family,
	    const sockaddr *addr,
	    int raf_flags,
	    StrBuf &printableAddress);

    // currently no-op except on Windows
    static int
    InitNetwork();

    // currently no-op except on Windows
    static void
    CleanupNetwork();
};

# if defined(OS_MINGW) || (defined(OS_NT) && defined(_MSC_VER))

  // ensure that we don't conflict with a global DLL version
  # define inet_ntop p4_inet_ntop
  # define inet_pton p4_inet_pton

    // MINGW doesn't currently (v4.5) provide inet_ntop() or inet_pton()
    const char *
    p4_inet_ntop(
	    int af,
	    const void *src,
	    char *dst,
	    TYPE_SOCKLEN size);

    int
    p4_inet_pton(
	    int af,
	    const char *src,
	    void *dst);
# endif // OS_MINGW || (OS_NT && Visual Studio)

# if defined(OS_MINGW) || defined(OS_NT)
    // Windows doesn't yet provide inet_aton(); this handles only IPv4 addresses.
    int
    inet_aton(
	const char *cp,
	in_addr *addr);
# endif // OS_MINGW || OS_NT
