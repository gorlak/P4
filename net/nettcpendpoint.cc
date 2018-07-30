// -*- mode: C++; tab-width: 4; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/*
 * NetTcpEndPoint
 *
 * Copyright 1995, 1996, 2011 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 * - previously part of nettcp.cc
 */

# define NEED_ERRNO
# define NEED_SIGNAL
# ifdef OS_NT
# define NEED_FILE
# endif
# define NEED_FCNTL
# define NEED_IOCTL
# define NEED_TYPES
# define NEED_SOCKET_IO

# ifdef OS_MPEIX
# define _SOCKET_SOURCE /* for sys/types.h */
# endif

# include "netportipv6.h"	// must be included before stdhdrs.h
# include <stdhdrs.h>

# if defined(OS_LINUX) || defined(OS_MACOSX) || defined(OS_DARWIN)
# include <sys/un.h>
# endif // OS_LINUX || OS_MACOSX
#include <ctype.h>

# include <error.h>
# include <strbuf.h>
# include "netaddrinfo.h"
# include <bitarray.h>
# include <debug.h>
# include <tunable.h>
# include <keepalive.h>
# include <msgrpc.h>
# include "netportparser.h"
# include "netconnect.h"
# include "netutils.h"
# include "nettcpendpoint.h"
# include "nettcptransport.h"
# include "netselect.h"
# include "netport.h"
# include "netdebug.h"
# include "netsupport.h"

static int one = 1;

/*
 * For 2012.1, default hints flags to nothing.
 * For 2012.2, perhaps default them to AI_ADDRCONFIG.
 *
 * AI_ADDRCONFIG suppresses unnecessary AAAA DNS lookups
 * from hosts that have no IPv6 connectivity,
 * thus preventing long IPv6 stalls for such hosts.
 * See RFC 2553 "Basic Socket Interface Extensions for IPv6".
 *
 * However, AI_ADDRCONFIG also prevents "localhost" (*and* "::1")
 * lookups from returning IPv6 addresses if there are no interfaces
 * with routable IPv6 addresses; this prevents IPv6 testing in 2012.1
 * until we provide IPv6 infrastructure internally.
 * In order to support internal testing of IPv6 in 2012.1
 * we don't turn this flag on.
 *
 * In 2012.1 clients must explicitly request an IPv6 connection
 * via one of the IPv6 transport prefixes; presumably they won't
 * do that at all, as IPv6 support is for internal testing only in 2012.1.
 * Therefore, the lack of AI_ADDRCONFIG should not be a problem in 2012.1.
 *
 * In 2012.2 we could consider changing the default and tcp/ssl transports
 * to IPv4+IPv6 and use the system-defined preference (by default, prefer
 * IPv6), rather than using our own prefer-v4 or prefer-v6 transport
 * prefixes.
 * See RFC 3484 "Default Address Selection for Internet Protocol version 6 (IPv6)".
 * At the same time we should turn on AI_ADDRCONFIG to prevent stalls when
 * trying to connect via IPv6 if the host can't use IPv6.  As a convenience,
 * we could consider not adding AI_ADDRCONFIG if the requested hostname is
 * either "localhost" or "::1" (there's no real need to check for the myriad
 * of localhost aliases or of the different ways to write "::1").
 */
static const int kBaseHintsFlags = 0;

/*
 * NetTcp utility routines
 */

void
NetTcpEndPoint::SetupSocket( int fd, int ai_family, AddrType type, Error *e )
{
# if defined(F_SETFD) && !defined(OS_NT)
	// attempt to set close on exec flag, ignore failures
	fcntl(fd, F_SETFD, 1);
# endif

	// Set buffer size.

	// Turn on misc options:
	//    REUSEADDR - allows listens while dead connections exist
	//    REUSEPORT - allows listens while live connections exist (BSD)
	//    KEEPALIVE - detects dead PCs

	// Do these separately: although SO_XXX look like bit flags, they're not.
	// AIX just plain chokes sometimes on these, so we don't check.
	// Well, we now check, but don't report an error unless DT_NET debugging is enabled.

	//
	// Don't set SO_REUSEADDR on Windows since it doesn't do what it's
	// supposed to. Instead of allowing you to reuse a port within the
	// TIME_WAIT period, it allows a process to bind to a port that's
	// actively being used by another process. Yuk. The good news
	// is that SO_REUSEADDR is not required to rebind within the 
	// TIME_WAIT period on Windows.
	// 

	int sz;
	TYPE_SOCKLEN rsz = sizeof( sz );
	const int MinBufSz = p4tunable.Get( P4TUNE_NET_TCPSIZE );

# ifndef OS_NT
	if( !p4tunable.Get( P4TUNE_NET_AUTOTUNE ) ) {
# endif
# ifdef SO_SNDBUF
	// never reduce the buffer size, so don't set it if we can't get the old value
	if( !getsockopt( fd, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<SOCKOPT_T *>(&sz), &rsz ) )
	{
	    if( sz < MinBufSz )
	    {
	        sz = MinBufSz;
	        do_setsockopt( "NetTcpEndPoint", fd, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<SOCKOPT_T *>(&sz), rsz );
	    }
	}
# endif

# ifdef OS_NT
	if( !p4tunable.Get( P4TUNE_NET_AUTOTUNE ) ) {
# endif
# ifdef SO_RCVBUF
	// never reduce the buffer size, so don't set it if we can't get the old value
	if( !getsockopt( fd, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<SOCKOPT_T *>(&sz), &rsz ) )
	{
	    if( sz < MinBufSz )
	    {
	        sz = MinBufSz;
	        do_setsockopt( "NetTcpEndPoint", fd, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<SOCKOPT_T *>(&sz), rsz );
	    }
	}
# endif
	// this is strange, but it balances the braces
# ifdef OS_NT
	} // !autotune
# else
	} // !autotune
# endif

# if defined( SO_REUSEADDR ) && !defined( OS_NT )
	if( (type == AT_LISTEN) || (type == AT_CHECK) )
	{
	    do_setsockopt( "NetTcpEndPoint", fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<SOCKOPT_T *>(&one), rsz );
	}
# endif

# ifdef SO_REUSEPORT
	const int reuseport = p4tunable.Get( P4TUNE_NET_REUSEPORT );
	if( ((type == AT_LISTEN) || (type == AT_CHECK)) && reuseport )
	{
	    do_setsockopt( "NetTcpEndPoint", fd, SOL_SOCKET, SO_REUSEPORT, reinterpret_cast<SOCKOPT_T *>(&one), rsz );
	}
# endif

# if defined(IPV6_V6ONLY) && !defined(OS_MINGW) && (!defined(_MSC_VER) || (_MSC_VER >= 1400))
	/*
	 * We allow the IPV6_V6ONLY sockopt on Windows only when building on VS 2005 or above,
	 * but we support only VS 2008 and later.
	 *
	 * RFC 3493 says that by default IPv6 sockets accept IPv4 connection requests.
	 * However, on Windows Vista and later the default is that they don't accept
	 * IPv4 connections.  Rather than #ifdef the defaults for all the platforms
	 * (and track them when they change their defaults), we don't rely on the default
	 * and always set this option appropriately.
	 *
	 * Note that it makes no sense to try to configure an IPv4 socket either to be
	 * IPV6-only or to be IPV6-and-IPV4, so we set it only on IPv6 sockets.
	 * Most dual-stack implementations seem to allow its use on IPv4 sockets,
	 * but it seems silly, so we don't do it.
	 *
	 * However, only dual-stack implementations provide this call, so we are #ifdef'ed
	 * on IPV6_V6ONLY.
	 */

	// don't try to set IPV6_V6ONLY on a v4 socket
	if( (type == AT_LISTEN) && (ai_family == AF_INET6) )
	{
	    const int val = GetPortParser().MustIPv6();
	    TRANSPORT_PRINTF( DEBUG_CONNECT, "NetTcpEndPoint setsockopt(IPV6_V6ONLY, %d)", val )

	    // this will fail harmlessly on Windows XP (but only if it passes the #ifdef test)
	    do_setsockopt( "NetTcpEndPoint", fd, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const SOCKOPT_T *>(&val), sizeof(val) );
	}
# endif

	MoreSocketSetup( fd, type, e );    // for subclasses to add extra behavior
}

// subclasses can do more setup here, if desired
void
NetTcpEndPoint::MoreSocketSetup( int fd, AddrType type, Error *e )
{
}

int
NetTcpEndPoint::CreateSocket(
	AddrType type,
	const NetAddrInfo &ai,
	int af_target,
	bool useAlternate,
	Error *e )
{
	int fd = -1;

	// iterate through the address list and use the first of the correct address family
	for( const addrinfo *aip = ai.begin(); aip != ai.end(); aip = aip->ai_next )
	{
	    if( useAlternate && (af_target == AF_UNSPEC) && (aip == ai.begin()) )
	    {
	        /*
	         * If we are to use an alternate address then try the first
	         * address that isn't the same family as the first entry.
	         * For RFC 3484 we try addresses in returned order,
	         * but only the first address (if any) of each family.
	         * If useAlternate was true then we must already have
	         * tried the first entry, so skip it now.
	         */
	        af_target = (aip->ai_family == AF_INET) ? AF_INET6 : AF_INET;
	        continue;
	    }

	    // don't discard any responses if no preference was given
	    if( (AF_UNSPEC != af_target) && (aip->ai_family != af_target) )
	        continue;

	    if( DEBUG_CONNECT )
	    {
	        StrBuf	addr;
	        NetUtils::GetAddress( aip->ai_family, aip->ai_addr, RAF_PORT, addr );
	        TRANSPORT_PRINTF( DEBUG_CONNECT, "NetTcpEndPoint try socket(%d, %d, %d, %s)",
	            aip->ai_family, aip->ai_socktype, aip->ai_protocol, addr.Text() );
	    }

	    fd = ::socket(aip->ai_family, aip->ai_socktype, aip->ai_protocol);
	    if( fd == -1 )
	    {
	        // odd ... probably either EACCES or ENFILE
	        e->Net( "socket", "create" );

	        if( DEBUG_CONNECT )
	        {
	            StrBuf errnum;
	            Error::StrNetError( errnum );
	            TRANSPORT_PRINTF( DEBUG_CONNECT, "NetTcpEndPoint socket(%d, %d, %d) failed, error = %s",
	                aip->ai_family, aip->ai_socktype, aip->ai_protocol, errnum.Text() );
	        }
	        //continue;    // uncomment to try all addresses in this family
	    }
	    else
	    {
	        SetupSocket( fd, aip->ai_family, type, e );

		int result;		// the result of the connect or bind
		const char *op4;	// the name of the IPv4 operation ["connect" or "connect (IPv6)"]
		const char *op6;	// the name of the IPv6 operation ["bind" or "bind (IPv6)"]

	        switch( type )
	        {
	        case AT_CONNECT:
	            result = connect( fd, aip->ai_addr, aip->ai_addrlen );
		    op4 = "connect";
		    op6 = "connect (IPv6)";
	            break;
	        case AT_CHECK:
	        case AT_LISTEN:
	            result = bind( fd, aip->ai_addr, aip->ai_addrlen );
		    op4 = "bind";
		    op6 = "bind (IPv6)";
		    break;
		}

		// did the connect/bind fail?
		if( result == -1 )
		{
		    // preserve/restore the listen error across the GetAddress call
		    int err = Error::GetNetError();
		    StrBuf addrBuf;
		    NetUtils::GetAddress( aip->ai_family, aip->ai_addr, RAF_PORT, addrBuf );
		    Error::SetNetError(err);	// restore the "last" error

		    // use different error ids/args for IPv4 and IPv6 so the correct address arg is output
		    if( aip->ai_family == AF_INET6 )
			e->Net2( op6, addrBuf.Text() );
		    else
			e->Net( op4, addrBuf.Text() );
		    NET_CLOSE_SOCKET( fd );
		    return -1;
		}
	    }
	    break;
	}

	return fd;
}

/**
 * return true if we resolved the address, false otherwise
 */
bool
NetTcpEndPoint::GetAddrInfo( AddrType type, NetAddrInfo &ai, Error *e )
{
	StrBuf port = ai.Port();
	StrBuf host = ai.Host();
	StrBuf hostPort = "[";
	hostPort.Append( &host );
	hostPort.Append( "]:" );
	hostPort.Append( &port );

	e->Clear();
	if( port.IsNumeric() )
	{
	    int portAsInt = port.Atoi();
	    if( portAsInt < 0 || portAsInt >= 65536 )
	    {
	        e->Set( MsgRpc::TcpPortInvalid ) << port;
	        return false;
	    }
	}

	NetPortParser &pp = GetPortParser();
	int ai_family = pp.MustIPv4() ? AF_INET : (pp.MustIPv6() ? AF_INET6 : AF_UNSPEC);
	int ai_flags = kBaseHintsFlags | AI_ALL | (pp.WantIPv6() ? 0 : AI_ADDRCONFIG );

	ai.SetHintsFamily( ai_family );

	// set AI_PASSIVE to get IPv4 addresses mapped in IPv6 if host isn't specified
	if( type != AT_CONNECT )
	{
	    ai_flags |= AI_PASSIVE;

	    if( pp.MayIPv4() && pp.MayIPv6() )
	    {
	        ai_flags |= AI_V4MAPPED;
	    }
	}

	if( DEBUG_CONNECT )
	{
	    p4debug.printf( "NetTcpEndPoint::GetAddrInfo(port=%s, family=%d, flags=0x%x)\n",
	        hostPort.Text(), ai_family, ai_flags );
	}

	ai.SetHintsFlags( ai_flags );
	bool result = ai.GetInfo(e);   // resolve the host and service/port names (IPv4 and/or IPv6)
	if( !result )
	{
	    if( ai.GetStatus() == EAI_BADFLAGS )
	    {
	        /*
	         * Apparently our OS doesn't support AI_ALL or AI_V4MAPPED.
	         *     Maybe it's a single-stack server:
	         *         FreeBSD 7.0 or older
	         *         Windows XP or older
	         *         ...
	         * We'll try again without those flags.
	         */
	        ai_flags = kBaseHintsFlags | (pp.WantIPv6() ? 0 : AI_ADDRCONFIG )
	                   | ( (type == AT_CONNECT) ? 0 : AI_PASSIVE );
	        ai.SetHintsFlags( ai_flags );

		TRANSPORT_PRINTF( DEBUG_CONNECT,
			"NetTcpEndPoint::GetAddrInfo(port=%s, family=%d, flags=0x%x) [retry]",
		         hostPort.Text(), ai_family, ai_flags );

	        e->Clear();
	        result = ai.GetInfo(e);
	    }
	}

	if( !result )
	{
	    // job062842 -- allow local operation without a routable address
	    if( (ai.GetStatus() == EAI_NONAME) && (ai_flags & AI_ADDRCONFIG) )
	    {
	        /*
		 * Perhaps we don't have a routable address and are trying
		 * to run locally.  Try again without AI_ADDRCONFIG.
	         */
	        ai_flags &= ~AI_ADDRCONFIG;
	        ai.SetHintsFlags( ai_flags );

		TRANSPORT_PRINTF( DEBUG_CONNECT,
			"NetTcpEndPoint::GetAddrInfo(port=%s, family=%d, flags=0x%x) [retry-2]",
		         hostPort.Text(), ai_family, ai_flags );

	        e->Clear();
	        result = ai.GetInfo(e);
	    }
	}

	return result;
}

int
NetTcpEndPoint::BindOrConnect( AddrType type, struct Error *e )
{
	int fd = -1;

	// first setup an addrinfo from the parsed P4PORT {transport, host, port} tuple
	NetPortParser &pp = GetPortParser();
	StrBuf	host = pp.Host();
	StrBuf	port = pp.Port();

	// ListenCheck is passed "host" or "host:port"
	if( type == AT_CHECK )
	{
	    /*
	     * We're called with AT_CHECK only from ListenCheck(),
	     * which just wants to ensure that we can bind to the
	     * provided address.
	     */

	    // NetPortParser assumes "host:port" or just "port"
	    if( host.Length() == 0 )
	        host.Set( pp.HostPort() );

	    /*
	     * Don't bind to a specific port; we care about the host address
	     * for this check, not the port, and another service might be
	     * running on the licensed port.  We don't want to get an
	     * EADDRINUSE error just because the port is in use.
	     */
	    port.Set( "" );
	}
	else
	{
	    // check that the address specifies a port
	    // only if we're not checking the license
	    if( !pp.IsValid(e) )
		return -1;
	}

	NetAddrInfo ai( host, port );
	if( !GetAddrInfo(type, ai, e) )
	{
	    // give up if we didn't succeed in resolving the address
	    return -1;
	}

	// now create a socket of the appropriate address family

	/*
	 * In 2012.1 we interpret "tcp:" and "ssl:" to mean IPv4
	 * so that we don't break existing licenses and protects tables.
	 *
	 * Note that if the server specifies "tcp6:" or "ssl6:"
	 * then they are explicitly rejecting IPv4.  Because "tcp:" and "ssl:"
	 * means IPv4 then the user must use "tcp46:" or "tcp64:" (or the ssl
	 * equivalents) to specify "either IPv4 or IPv6".  The first of "4"
	 * or "6" is the preferred transport.
	 *
	 * IPv6 will also work for IPv4 connections (transport only until
	 * 2012.2), except for servers on single-stack OSes: Windows XP or
	 * FreeBSD 7.0 or earlier.
	 * Using "tcp64:" or "ssl64:" on those servers won't provide
	 * IPv4-mapped-in-IPv6.
	 */
	bool rfc3484 = pp.MustRfc3484();
	int af_target = rfc3484 ? AF_UNSPEC
	                        : (pp.PreferIPv6() ? AF_INET6 : AF_INET);

	/*
	 * RFC 3484 specifies a precedence for deciding the order of returned
	 * addresses to be used for connect/bind.  If we're following RFC 3484
	 * then we won't also apply our coarse IPv4-first or IPv6-first ordering.
	 * If we aren't following RFC 3484 then we'll still use the intra-family
	 * order provided by getaddrinfo.
	 *
	 * In 2012.1, NetPortParser.MustRfc3484() will always return false,
	 * but in 2013.1 and later it will return the value of "-v net.rfc3484"
	 * if the transport didn't specify an IPv4 or IPv6 preference (via
	 * transport prefix or numeric address).
	 */
	fd = CreateSocket( type, ai, af_target, false, e );
	if( fd == -1 )
	{
	    // didn't get a socket the first time; try again
	    if( rfc3484 )
	    {
	        // try the first address of the other family
	        fd = CreateSocket( type, ai, af_target, true, e );
	    }
	    else
	    {
	        /*
	         * If we tried and failed to get a socket of our preferred family,
	         * try to get a socket of an acceptable alternate family.
	         * The "else" clause handles IPv6-only hosts, as well as
	         * connect attempts to hosts that are reachable only via IPv6,
	         * when the preferred transport is IPv4 (currently IPv4-only is
	         * the default).
	         */
	        if( (af_target == AF_INET6) && pp.MayIPv4() ) // "tcp64:" or "ssl64:"
	            fd = CreateSocket( type, ai, AF_INET, false, e );
	        else if( (af_target == AF_INET) && pp.MayIPv6() ) // "tcp46:" or "ssl46:"
	            fd = CreateSocket( type, ai, AF_INET6, false, e );
	    }
	}

	if( fd == -1 )
	{
	    // failed to get a socket and/or bind/connect
	    return -1;
	}

	// finally, setup the socket options and return it
	e->Clear();    // because the first CreateSocket() might have set an error

	return fd;
}

/*
 * NetTcpEndPoint
 */

NetTcpEndPoint::NetTcpEndPoint( Error *e )
{
	s = -1;
	/*
	 * Initialize as "false" so client side of connection:
	 *   !isFromClient == isToServer
	 * Will be set to true if "listen" is invoked.
	 */
	isAccepted = false;

	int err = NetUtils::InitNetwork();
	if( err )
	{
	    StrNum errnum( err );

	    e->Net( "Network initialization failure", errnum.Text() );
	}
}

NetTcpEndPoint::~NetTcpEndPoint()
{
	Unlisten();
	NetUtils::CleanupNetwork();
}

void
NetTcpEndPoint::Listen( Error *e )
{
	const int backlog = p4tunable.Get( P4TUNE_NET_BACKLOG );
	isAccepted = true;

	if( ( s = BindOrConnect( AT_LISTEN, e ) ) < 0 )
	{
	    e->Set( MsgRpc::TcpListen ) << GetPortParser().HostPort();
	    return;
	}

	// Now listen

	if( listen( s, backlog ) < 0 )
	{
	    e->Net( "listen", GetPortParser().String().Text() );
	    StrBuf listenAddress;
	    GetListenAddress( s, RAF_PORT, listenAddress );
	    NET_CLOSE_SOCKET( s );
	    e->Set( MsgRpc::TcpListen ) << listenAddress;
	}

# ifdef SIGPIPE
	signal( SIGPIPE, SIG_IGN );
# endif

	if( DEBUG_CONNECT )
	{
	    StrBuf listenAddress;
	    GetListenAddress( s, RAF_PORT, listenAddress );
	    TRANSPORT_PRINTF( DEBUG_CONNECT, "NetTcpEndPoint %s listening",
	        listenAddress.Text() );
	}
}

/**
 * Return the first addrinfo pointer of the desired family;
 * return NULL if none.
 */
const addrinfo *
NetTcpEndPoint::GetMatchingAddrInfo(
	const NetAddrInfo &ai,
	int af_target,
	bool useAlternate)
{
	// iterate through the address list and use the first of the correct address family
	for( const addrinfo *aip = ai.begin(); aip != ai.end(); aip = aip->ai_next )
	{
	    if( useAlternate && (af_target == AF_UNSPEC) && (aip == ai.begin()) )
	    {
	        /*
	         * If we are to use an alternate address then try the first
	         * address that isn't the same family as the first entry.
	         * For RFC 3484 we try addresses in returned order,
	         * but only the first address (if any) of each family.
	         * If useAlternate was true then we must already have
	         * tried the first entry, so skip it now.
	         */
	        af_target = (aip->ai_family == AF_INET) ? AF_INET6 : AF_INET;
	        continue;
	    }

	    if( (AF_UNSPEC == af_target) || (aip->ai_family == af_target) )
	        return aip;
	}

	return NULL;
}

/**
 * "requestedPort" is the P4PORT (or the command-line "-p") string.
 * The "this" NetTcpEndPoint object was constructed using the
 * address[:port] in the license file.
 */
int
NetTcpEndPoint::CheaterCheck( const char *requestedPort )
{
	Error e;

	NetPortParser &ppLicensed = GetPortParser();
	StrBuf	ppLicHost = ppLicensed.Host();
	StrBuf	ppLicPort = ppLicensed.Port();

	NetPortParser ppRequested( requestedPort );
	if( !ppRequested.IsValid( &e ) )
	    return 1;

	// no host? then we were created with just a host, not a port
	if( ppLicHost.Length() == 0 )
	{
	    ppLicHost.Set( ppLicensed.Port() );
	    ppLicPort.Set( "" );
	}

	// We already called BindOrConnect() once from ListenCheck() and there
	// wasn't an error then, so there shouldn't be one now.

	NetAddrInfo ai( ppLicHost, ppLicPort );
	// see the comments in BindOrConnect about RFC 3484 compliance
	bool rfc3484 = ppLicensed.MustRfc3484();
	int af_target = rfc3484 ? AF_UNSPEC
	                        : (ppLicensed.PreferIPv6() ? AF_INET6 : AF_INET);
	if( !GetAddrInfo(AT_CHECK, ai, &e) )
	{
	    return 1;
	}

	// get the addrinfo that we would use if we were to listen
	const addrinfo *aip = GetMatchingAddrInfo( ai, af_target, false );
	if( aip == NULL )
	{
	    if( rfc3484 )
	    {
	        // try the first address of the other family
	        // pointless, really, but matches the BindOrConnect logic
	        aip = GetMatchingAddrInfo( ai, AF_UNSPEC, true );
	    }
	    else
	    {
	        if( (af_target == AF_INET6) && ppLicensed.MayIPv4() )
	            aip = GetMatchingAddrInfo( ai, AF_INET, false );
	        else if( (af_target == AF_INET) && ppLicensed.MayIPv6() )
	            aip = GetMatchingAddrInfo( ai, AF_INET6, false );
	    }
	}
	if( aip == NULL )
	{
	    // no acceptable address
	    return 1;
	}

	// Are they trying to start the server on a port other than
	// the licensed one ???

	int myPort = NetUtils::GetInPort( aip->ai_addr );
	if( myPort == -1 )
	{
	    // bad address family -- shouldn't happen
	    return 1;
	}

	// If the license file has an ip address but no port number we
	// must still allow this.

	unsigned short requestedPortNum = ppRequested.PortNum();
	if( (myPort == 0) || (myPort == requestedPortNum) )
	{
	    return 0;
	}

	return 1;
}

/*
 * Check whether a hostname or IP is loopback
 * - return true if any addresses for the host is local
 *	1) p4portstr is a P4PORT string
 *	2) empty strings, and those with a transport of "rsh:" or "jsh:" are local
 *	3) empty host portion is also local
 *	4) numeric strings (IPv4 or IPv6, optionally surrounded with [...])
 *	   are parsed and checked by NetUtils::IsLocalAddress()
 *	5) otherwise we resolve the name to a set of addresses;
 *	   if any of them are local, return true
 * - there is a lot of code here that's duplicated from BindOrConnect()
 *   and CreateSocket(), so I'll look at refactoring this later.
 * [static]
 */
bool
NetTcpEndPoint::IsLocalHost( const char *p4portstr, AddrType type )
{
	// empty host string means localhost
	if( *p4portstr == '\0' )
	    return true;

	NetPortParser	pp(p4portstr);

	// "rsh:" and "jsh:" are always local
	if( pp.MustRSH() || pp.MustJSH() )
	    return true;

	// empty host portion means localhost
	if( pp.Host().Length() == 0 )
	    return true;

	// don't bother trying to resolve a numeric address
	// note: dns names may start with a digit (see RFC 1123)
	char	ch = pp.Host().Text()[0];
	if( ch == ':' )
	    return NetUtils::IsLocalAddress( pp.Host().Text() );
	char	lastch = pp.Host().Text()[pp.Host().Length()-1];
	if( (ch == '[') && (lastch == ']') )
	{
	    if( pp.Host().Text()[1] == ':' )
		return NetUtils::IsLocalAddress( pp.Host().Text() );
	}

	// ok, let's try resolving the name

	NetAddrInfo	ai( pp.Host(), pp.Port() );
	Error		e;
	bool		useAlternate = false;
	int		af_target = AF_UNSPEC;

	int ai_family = pp.MustIPv4() ? AF_INET : (pp.MustIPv6() ? AF_INET6 : AF_UNSPEC);
	int ai_flags = kBaseHintsFlags | AI_ALL | (pp.WantIPv6() ? 0 : AI_ADDRCONFIG );

	ai.SetHintsFamily( ai_family );

	// set AI_PASSIVE to get IPv4 addresses mapped in IPv6 if host isn't specified
	if( type != AT_CONNECT )
	{
	    ai_flags |= AI_PASSIVE;

	    if( pp.MayIPv4() && pp.MayIPv6() )
	    {
	        ai_flags |= AI_V4MAPPED;
	    }
	}

	if( DEBUG_CONNECT )
	{
	    p4debug.printf( "NetTcpEndPoint::IsLocalHost(port=%s, family=%d, flags=0x%x)\n",
	        pp.Host().Text(), ai_family, ai_flags );
	}

	ai.SetHintsFlags( ai_flags );

	// This will init WinSock, if required, and clean it up too.
	NetTcpEndPoint endpoint( &e );

	bool result = ai.GetInfo(&e);   // resolve the host and service/port names (IPv4 and/or IPv6)
	if( !result )
	{
	    if( ai.GetStatus() == EAI_BADFLAGS )
	    {
	        /*
	         * Apparently our OS doesn't support AI_ALL or AI_V4MAPPED.
	         *     Maybe it's a single-stack server:
	         *         FreeBSD 7.0 or older
	         *         Windows XP or older
	         *         ...
	         * We'll try again without those flags.
	         */
	        ai_flags = kBaseHintsFlags | (pp.WantIPv6() ? 0 : AI_ADDRCONFIG )
	                   | ( (type == AT_CONNECT) ? 0 : AI_PASSIVE );
	        ai.SetHintsFlags( ai_flags );

		if( DEBUG_CONNECT )
		{
		    p4debug.printf(
			"NetTcpEndPoint::IsLocalHost(port=%s, family=%d, flags=0x%x) [retry]\n",
		         pp.Host().Text(), ai_family, ai_flags );
		}

	        e.Clear();
	        result = ai.GetInfo(&e);
	    }
	}

	if( !result )
	{
	    // job062842 -- allow local operation without a routable address
	    if( (ai.GetStatus() == EAI_NONAME) && (ai_flags & AI_ADDRCONFIG) )
	    {
	        /*
		 * Perhaps we don't have a routable address and are trying
		 * to run locally.  Try again without AI_ADDRCONFIG.
	         */
	        ai_flags &= ~AI_ADDRCONFIG;
	        ai.SetHintsFlags( ai_flags );

		if( DEBUG_CONNECT )
		{
		    p4debug.printf(
			"NetTcpEndPoint::IsLocalHost(port=%s, family=%d, flags=0x%x) [retry-2]\n",
		         pp.Host().Text(), ai_family, ai_flags );
		}

	        e.Clear();
	        result = ai.GetInfo(&e);
	    }
	}

	if( result )
	{
	    // iterate through the address list and use the first of the correct address family
	    for( const addrinfo *aip = ai.begin(); aip != ai.end(); aip = aip->ai_next )
	    {
		if( useAlternate && (af_target == AF_UNSPEC) && (aip == ai.begin()) )
		{
		    /*
		     * If we are to use an alternate address then try the first
		     * address that isn't the same family as the first entry.
		     * For RFC 3484 we try addresses in returned order,
		     * but only the first address (if any) of each family.
		     * If useAlternate was true then we must already have
		     * tried the first entry, so skip it now.
		     */
		    af_target = (aip->ai_family == AF_INET) ? AF_INET6 : AF_INET;
		    continue;
		}

		// don't discard any responses if no preference was given
		if( (AF_UNSPEC != af_target) && (aip->ai_family != af_target) )
		    continue;

		StrBuf	printableAddress;
		printableAddress.Clear();
		printableAddress.Alloc( P4_INET6_ADDRSTRLEN );
		printableAddress.SetLength(0);
		printableAddress.Terminate();
		const char	*buf = printableAddress.Text();

		NetUtils::GetAddress( aip->ai_family, aip->ai_addr, 0, printableAddress );
		result = NetUtils::IsLocalAddress(buf);
		if( DEBUG_CONNECT )
		{
		    p4debug.printf(
			"NetTcpEndPoint::IsLocalAddress(%s) = %s\n",
			buf, (result ? "true" : "false") );
		}
		if( result )
		    return true;
	    }
	}

	return false;
}

void
NetTcpEndPoint::ListenCheck( Error *e )
{
	int fd = BindOrConnect( AT_CHECK, e );
	if( fd >= 0 )
	{
	    close( fd );
	}
}

void
NetTcpEndPoint::GetListenAddress( int s, int raf_flags, StrBuf &listenAddress )
{
	struct sockaddr_storage addr;
	struct sockaddr *saddrp = reinterpret_cast<struct sockaddr *>(&addr);
	TYPE_SOCKLEN addrlen = sizeof addr;

	if( getsockname( s, saddrp, &addrlen ) < 0 || addrlen > sizeof addr )
	{
	    listenAddress.Set( "unknown" );
	}
	else
	{
	    NetUtils::GetAddress( addr.ss_family, saddrp, raf_flags, listenAddress );
	}
}

StrPtr *
NetTcpEndPoint::GetHost()
{
	ipAddr = GetPortParser().Host();

	return &ipAddr;
}

/*
 * job063713 -- ensure that IPv6 literal addresses are in our
 * standard form, per RFC 3986 : surrounded with brackets
 * - matches the behavior of NetUtils::GetAddress()
 */
StrBuf
NetTcpEndPoint::GetPrintableHost()
{
	StrPtr	host = GetPortParser().Host();

	if( (host[0] != '[') && NetUtils::IsIpV6Address(host.Text()) )
	{
	    StrBuf	tmp = "[";
	    tmp.Append( host.Text() );
	    tmp.Append( "]" );

	    return tmp;
	}

	return host;
}

void
NetTcpEndPoint::Unlisten()
{
	NET_CLOSE_SOCKET( s );
}

NetTransport *
NetTcpEndPoint::Accept( KeepAlive *keep, Error *e )
{
	TYPE_SOCKLEN lpeer;
	struct sockaddr_storage peer;
	int t;
	NetTcpSelector *selector = NULL;

	TRANSPORT_PRINTF( DEBUG_CONNECT, "NetTcpEndpoint accept on %d", s );

	lpeer = sizeof peer;

	if( keep )
		selector = new NetTcpSelector( s );

	// Loop accepting, as it gets interrupted (by SIGCHILD) on
	// some platforms (MachTen, but not FreeBSD).

	for( ;; )
	{
		if( keep )
		{
			if( !keep->IsAlive() )
			{
				e->Set( MsgRpc::Break );
				delete selector;
				return 0;
			}
			int sr, rd = 1, wr = 0;
			if( ( sr = selector->Select( rd, wr, 500 ) ) == 0 )
				continue;
			if( sr == -1 )
			{
				e->Sys( "select", "accept" );
				delete selector;
				return 0;
			}
		}

		if( ( t = accept( s, reinterpret_cast<struct sockaddr *>(&peer), &lpeer ) ) < 0 )
		{
			if( errno != EINTR )
			{
				e->Net( "accept", "socket" );
				e->Set( MsgRpc::TcpAccept );;
				delete selector;
				return 0;
			}
		}
		else break;
	}

# ifdef F_SETFD
	// close on exec
	// so p4web's launched processes don't get our socket
	fcntl( t, F_SETFD, 1 );
# endif

	delete selector;

	NetTcpTransport *transport = new NetTcpTransport( t, true );
	if( transport )
	    transport->SetPortParser(GetPortParser());
	return transport;
}

NetTransport *
NetTcpEndPoint::Connect( Error *e )
{
	int t;

	// Set up addresses
	if( ( t = BindOrConnect( AT_CONNECT, e ) ) < 0 )
	{
	    e->Set( MsgRpc::TcpConnect ) << GetPortParser().HostPort();
	    return 0;
	}

	TRANSPORT_PRINTF( DEBUG_CONNECT, "NetTcpEndpoint connect on %d", t );

# ifdef SIGPIPE
	signal( SIGPIPE, SIG_IGN );
# endif

	NetTcpTransport *transport = new NetTcpTransport( t, false );
	if( transport )
	    transport->SetPortParser(GetPortParser());
	return transport;
}

# if defined(OS_LINUX) || defined(OS_MACOSX) || defined(OS_DARWIN)
// returns -1 or error or a valid socket fd on success
socketfd_t
NetTcpEndPoint::OpenUnixSocket( const StrBuf &sockName, Error &e )
{
	//NET_ENTER();
	struct sockaddr_un sockAddr;
	socketfd_t        sock = -1;
	int count = 1;
	StrBuf buf;

	//TRANSPORT_PRINTF( DEBUG_CONNECT, "OpenUnixSocket socket filename is: \"%s\"",
	//        sockName.Text() );
	// Verify that we have gotten the filename for the socket
	if ( sockName.Length() == 0 )
	{
	    e.Set(MsgRpc::UnixDomainOpen) << "open" << "invalid filename";
	    //NET_DUMP_ERROR( e );
	    return -1;
	}

	sock = socket( PF_UNIX, SOCK_STREAM, 0 );
	if( sock < 0 )
	{
	    StrBuf buf;
	    Error::StrError(buf);
	    e.Set(MsgRpc::UnixDomainOpen) << "socket" << buf;
	    //NET_DUMP_ERROR( e );
	    return -1;
	}

	memset( &sockAddr, 0, sizeof(struct sockaddr_un) );

	sockAddr.sun_family = AF_UNIX;
	memcpy( sockAddr.sun_path,
	            sockName.Text(),
	            sockName.Length() );
	sockAddr.sun_path[ sockName.Length() ] = '\0';

	//TRANSPORT_PRINTF( DEBUG_CONNECT, "OpenUnixSocket socket filename is: \"%s\"",
	//        sockName.Text() );
	while( connect( sock,
	        (struct sockaddr *) &sockAddr,
	        sizeof(struct sockaddr_un) ) != 0 && (count++ < 10))
	{
	    if( errno == ECONNREFUSED || errno == ENOENT )
	    {
	        sleep(1);
	        continue;
	    }
	    Error::StrError(buf);
	    e.Set(MsgRpc::UnixDomainOpen) << "connect" << buf;
	    //NET_DUMP_ERROR( e );
	    return -1;
	}
	if( count >= 10 )
	{
	    Error::StrError(buf);
	    e.Set(MsgRpc::UnixDomainOpen) << "connect" << buf;
	    //NET_DUMP_ERROR( e );
	    return -1;
	}

	return sock;
}
# endif // OS_LINUX || OS_MACOSX || OS_DARWIN

