// -*- mode: C++; tab-width: 4; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 * - previously part of nettcp.h
 */

/*
 * nettcpendpoint.h - TCP driver for NetTransport
 *
 * Classes Defined:
 *
 *    NetTcpEndPoint - a TCP subclass of NetEndPoint
 */

class Error;
class StrBuf;

enum AddrType {
	AT_LISTEN,            // listen on address:port
	AT_CHECK,             // check address
	AT_CONNECT            // connect to address:port
};

# if defined(OS_LINUX) || defined(OS_MACOSX) || defined(OS_DARWIN)
typedef int	socketfd_t;
# endif // OS_LINUX || OS_MACOSX || OS_DARWIN

class NetTcpEndPoint : public NetEndPoint {

    public:
			NetTcpEndPoint( Error *e );
	virtual		~NetTcpEndPoint();

	StrPtr		*GetHost();
	StrBuf		GetPrintableHost();

	virtual StrPtr	*GetListenAddress( int raf_flags )
			{
			    GetListenAddress( s, raf_flags, listenAddress );
			    return &listenAddress;
			}
	static void	GetListenAddress( int s, int raf_flags, StrBuf &l );

	static bool	IsLocalHost(const char *addr, AddrType type = AT_CONNECT);

	const addrinfo *GetMatchingAddrInfo(
			    const NetAddrInfo &ai,
			    int af_target,
			    bool useAlternate);
	bool		IsAccepted()
			{
			    return isAccepted;
			}

	void		Listen( Error *e );
	void		ListenCheck( Error *e );
	int		CheaterCheck( const char *port );
	void		Unlisten();

	bool		GetAddrInfo( AddrType type, NetAddrInfo &ai, Error *e );
	int		BindOrConnect( AddrType type, Error *e );
	int		CreateSocket( AddrType type, const NetAddrInfo &ai, int af_target, bool useAlternate, Error *e );
	void		SetupSocket( int fd, int ai_family, AddrType type, Error *e );

	// subclasses can override this to do more setup on the socket, if desired
	virtual void	MoreSocketSetup( int fd, AddrType type, Error *e );

	NetTransport *	Connect( Error *e );
	NetTransport *	Accept( KeepAlive *, Error *e );

	int		IsSingle() { return 0; }

# if defined(OS_LINUX) || defined(OS_MACOSX) || defined(OS_DARWIN)
	// intended just for cluster support, which is only on linux (and Mac OS X for dev)
	static socketfd_t
	    		OpenUnixSocket( const StrBuf &sockName, Error &e );
# endif // OS_LINUX || OS_MACOSX || OS_DARWIN

    protected:
	int		s;
	StrBuf		listenAddress;
	StrBuf		ipAddr;
	bool		isAccepted;

	virtual int	GetFd() { return s; };
} ;
