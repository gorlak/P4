// -*- mode: C++; tab-width: 4; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/*
 * NetTcpTransport
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
# define NEED_SLEEP
# define NEED_SOCKET_IO

# ifdef OS_MPEIX
# define _SOCKET_SOURCE /* for sys/types.h */
# endif

# include <stdhdrs.h>
# include <ctype.h>

# include <error.h>
# include <strbuf.h>
# include "netaddrinfo.h"
# include <bitarray.h>
# include <debug.h>
# include <tunable.h>
# include <keepalive.h>
# include <msgrpc.h>
# include <timer.h>

# include "netportparser.h"
# include "netconnect.h"
# include "nettcptransport.h"
# include "netselect.h"
# include "netport.h"
# include "netdebug.h"
# include "netutils.h"
# include "netsupport.h"

# ifdef OS_NT
#    ifndef SIO_KEEPALIVE_VALS
        struct tcp_keepalive {
          unsigned long onoff;
          unsigned long keepalivetime;
          unsigned long keepaliveinterval;
        };
#       define SIO_KEEPALIVE_VALS _WSAIOW(IOC_VENDOR,4)
#    else
#        include <mstcpip.h>
#    endif
# endif // OS_NT

# define PEEK_TIMEOUT 200 /* 200 milliseconds */

NetTcpTransport::NetTcpTransport( int t, bool fromClient )
: isAccepted(fromClient)
{
	this->t = t;
	breakCallback = 0;
	lastRead = 0;
	selector = new NetTcpSelector( t );

	/* SendOrReceive() likes non-blocking I/O. */
	/* Without it, it's just synchronous. */

# ifdef OS_NT
	u_long u_one = 1;
	ioctlsocket( t, FIONBIO, &u_one );
# else
	int f = fcntl( t, F_GETFL, 0 );
	fcntl( t, F_SETFL, f | O_NONBLOCK );
# endif

	SetupKeepAlives( t );

	TRANSPORT_PRINTF( DEBUG_CONNECT,
		"NetTcpTransport %s connected to %s",
	        GetAddress( RAF_PORT )->Text(),
	        GetPeerAddress( RAF_PORT )->Text() );
}

NetTcpTransport::~NetTcpTransport()
{
	Close();

	delete selector;
}

# ifdef OS_NT
/*
 * Set the keepalive parameters on Windows
 * - enable/disable keepalives can be set via setsockopt
 * - On Windows Vista and later the keepalive count is fixed at 10
 * - both the idle time and the interval time must be set in the same call
 * - this routine sets only idle and interval, and only if both are positive
 * - quietly return success if the default values (both 0) are used
 * - else complain and return failure if either are negative
 */
bool
NetTcpTransport::SetWin32KeepAlives(
	int		socket,
	const SOCKOPT_T	ka_idlesecs,
	const int	ka_intvlsecs)
{
	// default values -- don't set, don't complain, and return success
	if( (ka_idlesecs == 0) && (ka_intvlsecs == 0) )
	{
	    return true;
	}

	// if either are non-positive, complain and return failure without setting
	if( (ka_idlesecs <= 0) || (ka_intvlsecs <= 0) )
	{
	    TRANSPORT_PRINTF( DEBUG_CONNECT,
		"NetTcpTransport: not setting TCP keepalive idle = %d secs, interval = %d secs"
		" because both must be positive", ka_idlesecs, ka_intvlsecs );
	    return false;
	}

	DWORD	retcnt;
	struct tcp_keepalive
		keepalive_opts;

	int	ka_idle_msecs = ka_idlesecs * 1000;
	int	ka_intvl_msecs = ka_intvlsecs * 1000;

	// count is fixed to 10
	keepalive_opts.onoff = 1;
	keepalive_opts.keepalivetime = ka_idle_msecs;
	keepalive_opts.keepaliveinterval = ka_intvl_msecs;

	TRANSPORT_PRINTF( DEBUG_CONNECT,
	    "NetTcpTransport: setting TCP keepalive idle = %d secs, interval = %d secs",
		ka_idlesecs, ka_intvlsecs );

	int rv = WSAIoctl( socket, SIO_KEEPALIVE_VALS, &keepalive_opts,
		sizeof(keepalive_opts), NULL, 0, &retcnt, NULL, NULL );
	if( rv )	// error
	{
	    StrBuf errnum;
	    Error::StrNetError( errnum );
	    p4debug.printf(
	    	"NetTcpTransport WSAIoctl(idle=%d, interval=%d) failed, error = %s\n",
		keepalive_opts.keepalivetime, keepalive_opts.keepaliveinterval, errnum.Text() );
	}

	return rv == 0;
}
# endif // OS_NT

void
NetTcpTransport::SetupKeepAlives( int t )
{
# ifdef SO_KEEPALIVE
	const SOCKOPT_T one = 1;

	// turn on tcp keepalives unless user disabled it (in which case turn them off)
	int ka_disable = p4tunable.Get( P4TUNE_NET_KEEPALIVE_DISABLE );
	if( ka_disable )
	{
	    const SOCKOPT_T zero = 0;

	    TRANSPORT_PRINT( DEBUG_CONNECT, "NetTcpTransport: disabling TCP keepalives" );

	    do_setsockopt( "NetTcpTransport", t, SOL_SOCKET, SO_KEEPALIVE, &zero, sizeof( zero ) );
	}
	else
	{
	    TRANSPORT_PRINT( DEBUG_CONNECT, "NetTcpTransport: enabling TCP keepalives" );

	    do_setsockopt( "NetTcpTransport", t, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof( one ) );
# ifdef OS_NT
	    const SOCKOPT_T ka_idlesecs = p4tunable.Get( P4TUNE_NET_KEEPALIVE_IDLE );
	    const int ka_intvlsecs = p4tunable.Get( P4TUNE_NET_KEEPALIVE_INTERVAL );
	    SetWin32KeepAlives( t, ka_idlesecs, ka_intvlsecs );
# else // OS_NT

	    // set tcp keepalive count if user requested
	    const SOCKOPT_T ka_keepcount = p4tunable.Get( P4TUNE_NET_KEEPALIVE_COUNT );
	    if( ka_keepcount )
	    {
// some systems (eg, Darwin 10.5.x) support keepalive but not the tuning parameters!
# if defined(SOL_TCP) && defined(TCP_KEEPCNT)
		TRANSPORT_PRINTF( DEBUG_CONNECT,
			"NetTcpTransport: setting TCP keepalive count = %d", ka_keepcount );
		do_setsockopt( "NetTcpTransport", t, SOL_TCP, TCP_KEEPCNT, &ka_keepcount, sizeof( ka_keepcount ) );
# else
		TRANSPORT_PRINT( DEBUG_CONNECT,
			"NetTcpTransport: this system does not support setting TCP keepalive count" );
# endif // TCP_KEEPCNT
	    }

	    // set tcp keepalive idle time (in seconds) if user requested
	    const SOCKOPT_T ka_idlesecs = p4tunable.Get( P4TUNE_NET_KEEPALIVE_IDLE );
	    if( ka_idlesecs )
	    {
# if defined(SOL_TCP) && defined(TCP_KEEPIDLE)
		TRANSPORT_PRINTF( DEBUG_CONNECT,
			"NetTcpTransport: setting TCP keepalive idle secs = %d", ka_idlesecs );
		do_setsockopt( "NetTcpTransport", t, SOL_TCP, TCP_KEEPIDLE, &ka_idlesecs, sizeof( ka_idlesecs ) );
# else
		TRANSPORT_PRINT( DEBUG_CONNECT,
			"NetTcpTransport: this system does not support setting TCP keepalive idle time" );
# endif // TCP_KEEPIDLE
	    }

	    // set tcp keepalive interval time (in seconds) if user requested
	    const int ka_intvlsecs = p4tunable.Get( P4TUNE_NET_KEEPALIVE_INTERVAL );
	    if( ka_intvlsecs )
	    {
# if defined(SOL_TCP) && defined(TCP_KEEPINTVL)
		TRANSPORT_PRINTF( DEBUG_CONNECT,
			"NetTcpTransport: setting TCP keepalive interval secs = %d", ka_intvlsecs );
		do_setsockopt( "NetTcpTransport", t, SOL_TCP, TCP_KEEPINTVL, &ka_intvlsecs, sizeof( ka_intvlsecs ) );
# else
		TRANSPORT_PRINT( DEBUG_CONNECT,
			"NetTcpTransport: this system does not support setting TCP keepalive interval" );
# endif // TCP_KEEPINTVL
	    }
# endif // OS_NT
	}
# else
	TRANSPORT_PRINTF( DEBUG_CONNECT,
		"NetTcpTransport: this system does not support TCP keepalive packets" );
# endif // SO_KEEPALIVE
}

void
NetTcpTransport::GetAddress( int t, int raf_flags, StrBuf &myAddr )
{
	struct sockaddr_storage addr;
	struct sockaddr *saddrp = reinterpret_cast<struct sockaddr *>(&addr);
	TYPE_SOCKLEN addrlen = sizeof addr;

	if( getsockname( t, saddrp, &addrlen ) < 0 || addrlen > sizeof addr )
	{
	    myAddr.Set( "unknown" );
	}
	else
	{
	    NetUtils::GetAddress( addr.ss_family, saddrp, raf_flags, myAddr );
	}
}

void
NetTcpTransport::GetPeerAddress( int t, int raf_flags, StrBuf &peerAddr )
{
	struct sockaddr_storage addr;
	struct sockaddr *saddrp = reinterpret_cast<struct sockaddr *>(&addr);
	TYPE_SOCKLEN addrlen = sizeof addr;

	if( getpeername( t, saddrp, &addrlen ) < 0 || addrlen > sizeof addr )
	{
	    if( addrlen > sizeof addr )
	    {
		DEBUGPRINT( DEBUG_CONNECT,
			"Unable to get peer address since addrlen > sizeof addr.");
	    }
	    else
	    {
		StrBuf buf;
		Error::StrError(buf, errno);
		DEBUGPRINTF( DEBUG_CONNECT,
			"Unable to get peer address: %s", buf.Text());
	    }
	    peerAddr.Set( "unknown" );
	}
	else
	{
	    NetUtils::GetAddress( addr.ss_family, saddrp, raf_flags, peerAddr );
	}
}

int
NetTcpTransport::GetPortNum( int t )
{
	struct sockaddr_storage addr;
	struct sockaddr *saddrp = reinterpret_cast<struct sockaddr *>(&addr);
	TYPE_SOCKLEN addrlen = sizeof addr;

	if( getsockname( t, saddrp, &addrlen ) < 0 || addrlen > sizeof addr )
	{
	    StrBuf buf;
	    Error::StrError(buf, errno);
	    DEBUGPRINTF( DEBUG_CONNECT,
		    "Unable to get sockname: %s", buf.Text());
	    return -1;
	}
	else
	{
	    return NetUtils::GetInPort( saddrp );
	}
}

bool
NetTcpTransport::IsSockIPv6( int t )
{
	struct sockaddr_storage addr;
	struct sockaddr *saddrp = reinterpret_cast<struct sockaddr *>(&addr);
	TYPE_SOCKLEN addrlen = sizeof addr;

	if( getsockname( t, saddrp, &addrlen ) < 0 || addrlen > sizeof addr )
	{
	    StrBuf buf;
	    Error::StrError(buf, errno);
	    DEBUGPRINTF( DEBUG_CONNECT,
		    "Unable to get sockname: %s", buf.Text());
	    return false;
	}
	else
	{
	    return NetUtils::IsAddrIPv6( saddrp );
	}
}

void
NetTcpTransport::Send( const char *buffer, int length, Error *e )
{
	NetIoPtrs io;

	io.sendPtr = (char *)buffer;
	io.sendEnd = (char *)buffer + length;
	io.recvPtr = 0;
	io.recvEnd = 0;

	while( io.sendPtr != io.sendEnd )
	    if( !NetTcpTransport::SendOrReceive( io, e, e ) )
	        return;
}

int
NetTcpTransport::Receive( char *buffer, int length, Error *e )
{
	NetIoPtrs io;

	io.recvPtr = buffer;
	io.recvEnd = buffer + length;
	io.sendPtr = 0;
	io.sendEnd = 0;

	if( NetTcpTransport::SendOrReceive( io, e, e ) )
	    return io.recvPtr - buffer;

	return e->Test() ? -1 : 0;
}

/*
 * NetTcpTransport::SendOrReceive() - send or receive data as ready
 *
 * If data to write and no room to read, block writing.
 * If room to read and no data to write, block reading.
 * If both data to write and room to read, block until one is ready.
 *
 * If neither data to write nor room to read, don't call this!
 *
 * Brain-dead version of NetTcpSelector::Select() indicates both
 * read/write are ready.  To avoid blocking on read, we only do so
 * if not instructed to write.
 *
 * Returns 1 if either data read or written.
 * Returns 0 if neither, meaning EOF or error.
 */

int
NetTcpTransport::SendOrReceive( NetIoPtrs &io, Error *se, Error *re )
{
    	// if data is waiting to be read, don't let a read error stop us
	bool wasReadError = re->Test();	// remember the read error
	int doRead = io.recvPtr != io.recvEnd && (!wasReadError || selector->Peek());
	int doWrite = io.sendPtr != io.sendEnd && !se->Test();

	int dataReady;
	int maxwait = p4tunable.Get( P4TUNE_NET_MAXWAIT );
	int autotune = p4tunable.Get( P4TUNE_NET_AUTOTUNE );
	int doGoAround = 0;
	int retCode = 0;
	Timer waitTime;
	if( t < 0 )
	{
	    // Socket has been closed don't try to use
	    return 0;
	}
	if( maxwait )
	{
	    maxwait *= 1000;
	    waitTime.Start();
	}

	int readable;
	int writable;

	// Flush can call us with nothing to do when the connection
	// gets broken.

	if( !doRead && !doWrite )
	    return 0;

	do
	{
	    readable = doRead;
	    writable = doWrite;

	    // 500 is .5 seconds.

	    int tv = -1;
	    if( ( readable && breakCallback ) || maxwait )
	    {
	        tv = 500;
	        if( breakCallback )
	        {
	            tv = breakCallback->PollMs();
	            if( tv < 1 )
	                tv = 500;
	        }
	        if( tv < 1 ) // in case of overflow, be sane
	            tv = 500;
	    }

	    if( ( dataReady = selector->Select( readable, writable, tv ) ) < 0 )
	    {
	        re->Sys( "select", "socket" );
	        return 0;
	    }

	    if( !dataReady && maxwait && waitTime.Time() >= maxwait )
	    {
	        lastRead = 0;
	        re->Set( MsgRpc::MaxWait ) <<
	            ( doRead ? "receive" : "send" ) << ( maxwait / 1000 );
	        return 0;
	    }

	    // Before checking for data do the callback isalive test.
	    // If the user defined IsAlive() call returns a zero
	    // value then the user wants this request to terminate.

	    if( doRead && breakCallback && !breakCallback->IsAlive() )
	    {
	        lastRead = 0;
	        re->Set( MsgRpc::Break );
	        return 0;
	    }

	    if( !writable && !readable )
	        continue;

	    if( autotune && readable && writable )
	    {
	        doGoAround = 1;
	        writable = 0;
	    }

	    // Write what we can; read what we can

	    if( writable )
	    {
		goAround:
	        int l = write( t, io.sendPtr, io.sendEnd - io.sendPtr );

	        if( l > 0 )
	            TRANSPORT_PRINTF( DEBUG_TRANS, 
	                "NetTcpTransport send %d bytes", l );

	        if( l > 0 )
	        {
	            lastRead = 0;
	            io.sendPtr += l;
	            if( autotune && !readable )
	                return 1;
	            retCode = 1;
	        }

	        if( l < 0 )
	        {
# ifdef OS_NT
	            int	errornum = WSAGetLastError();

	            // don't use switch, values might be the same
                    if( ( errornum == WSAEWOULDBLOCK ) || 
	                ( errornum == WSATRY_AGAIN ) || 
	                ( errornum == WSAEINTR) ) continue;
# else
	            // don't use switch, values might be the same
	            if( ( errno == EWOULDBLOCK ) || 
	                ( errno == EAGAIN ) || 
	                ( errno == EINTR ) ) continue;
# endif // OS_NT

	            se->Net( "write", "socket" );
	            se->Set( MsgRpc::TcpSend );
	        }
	    }

	    if( readable )
	    {
	        int l = read( t, io.recvPtr, io.recvEnd - io.recvPtr );

	        if( l > 0 )
	            TRANSPORT_PRINTF( DEBUG_TRANS, 
	                "NetTcpTransport recv %d bytes", l );

	        if( l > 0 )
	        {
	            /*
	             * probably we'll never be able to read the FIN if there
	             * isn't data waiting already
	             */
	            lastRead = (wasReadError ? selector->Peek() : 1);
	            io.recvPtr += l;
                    if( doGoAround )
	            {
	                readable = 0;
	                doGoAround = 0;
	                goto goAround;
	            }
	            retCode = 1;
	        }

	        if( l < 0 )
	        {
	            if( doGoAround )
	            {
	                readable = 0;
	                doGoAround = 0;
	                goto goAround;
	            }
# ifdef OS_NT
	            int errornum = WSAGetLastError();
	            // don't use switch, values might be the same
	            if( ( errornum == WSAEWOULDBLOCK ) || 
	                ( errornum == WSATRY_AGAIN ) || 
	                ( errornum == WSAEINTR ) ) continue;
# else
		    // don't use switch, values might be the same
		    if( ( errno == EWOULDBLOCK ) || 
	                ( errno == EAGAIN ) || 
	                ( errno == EINTR ) ) continue;
# endif // OS_NT

	            re->Net( "read", "socket" );
	            re->Set( MsgRpc::TcpRecv );
	        }
	    }

	    return retCode;
	} while( !retCode );

	return retCode;
}

int
NetTcpTransport::DuplexReady()
{
		return !p4tunable.Get( P4TUNE_NET_AUTOTUNE );
}

int
NetTcpTransport::GetSendBuffering()
{
	int sz = 4096;

# ifdef SO_SNDBUF
	TYPE_SOCKLEN rsz = sizeof( sz );

	if( getsockopt( t, SOL_SOCKET, SO_SNDBUF, (char *)&sz, &rsz ) < 0 )
	    sz = 4096;
# endif

# ifdef OS_LINUX
	// Linux says one thing but means another, reserving 1/4th
	// the space for internal use.

	sz = sz * 3 / 4;
# endif

# ifdef OS_DARWIN
	// Darwin's window-size adaptive mechanism returns inflated values
	// in getsockopt() from what sysctl reports in send and recv spaces,
	// at least until net.inet.tcp.sockthreshold sockets are open.
	// Our technique of filling the pipe can cause dead-lock in
	// extreme cases, so we manually avoid Darwin's mechanism here for
	// the send buffer.

	if( sz > DARWIN_MAX  )
	    sz = DARWIN_MAX;
# endif

# ifdef SO_SNDLOWAT
	// FreeBSD and Darwin (at least) will block the sending process
	// when writes are smaller than both the low water mark and space
	// available, so don't use that last bit of space.

	int sl;

	if( getsockopt( t, SOL_SOCKET, SO_SNDLOWAT, (char *)&sl, &rsz ) == 0 )
	    sz -= sl;
# endif

	return sz;
}

int
NetTcpTransport::GetRecvBuffering()
{
	int sz = 4096;

# ifdef SO_RCVBUF
	TYPE_SOCKLEN rsz = sizeof( sz );

	if( getsockopt( t, SOL_SOCKET, SO_RCVBUF, (char *)&sz, &rsz ) < 0 )
	    sz =  4096;
# endif

# ifdef OS_LINUX
	sz = sz * 3 / 4;
# endif

	return sz;
}

void
NetTcpTransport::Close( void )
{
	if( t < 0 )
	    return;

	TRANSPORT_PRINTF( DEBUG_CONNECT, "NetTcpTransport %s closing %s",
	        GetAddress( RAF_PORT )->Text(),
	        GetPeerAddress( RAF_PORT )->Text() );

	// Avoid TIME_WAIT on the server by reading the EOF after
	// the last message sent by the client.  Getting the EOF
	// means we've received the TH_FIN packet, which means we
	// don't have to send our own on close().  He who sends
	// a TH_FIN goes into the 2 minute TIME_WAIT imposed by TCP.

	TRANSPORT_PRINTF( DEBUG_CONNECT,
		"NetTcpTransport lastRead=%d", lastRead );

	if( lastRead )
	{
	    int r = 1;
	    int w = 0;
	    char buf[1];

	    if( selector->Select( r, w, -1 ) >= 0 && r )
	        read( t, buf, 1 );
	}

	if( DEBUG_INFO )
	{
		StrBuf b;

		if( GetInfo( &b ) )
			p4debug.printf( "tcp info: %s", b.Text() );
	}

	NET_CLOSE_SOCKET(t);
}

int
NetTcpTransport::IsAlive()
{
	int readable = 1;
	int writeable = 0;

	if( selector->Select( readable, writeable, 0 ) < 0 )
	    return 0;

	// All good if no EOF waiting

	return !readable || selector->Peek();
}

void
NetTcpTransport::ClientMismatch( Error *e )
{
    if ( CheckForHandshake(t) == PeekSSL)
    {
        // this is a non-ssl connection
        // this is a ssl connection and we are a cleartext server
        e->Net( "accept", "socket" );
        e->Set( MsgRpc::TcpPeerSsl );
        NET_CLOSE_SOCKET(t);
    }
}

int
NetTcpTransport::Peek( int fd, char *buffer, int length )
{
		int count = 0;
		int retval = -1;


# ifdef OS_NT
		u_long u_value = 0;
		// Set to blocking on windows for peek
		ioctlsocket( t, FIONBIO, &u_value );
		retval = recv( fd, buffer, length, MSG_PEEK );
		// Set back to non blocking, @#!%$#@ stupid windows....
		u_value = 1;
		ioctlsocket( t, FIONBIO, &u_value );
# else
		retval = recv( fd, buffer, length, MSG_PEEK );
		// lengthened timeout because found out that timed out early with VPN
		while ((retval == -1 ) && (errno == EAGAIN) && (count < PEEK_TIMEOUT))
		{
			// parent process closing socket can make
			// resource temporarily unavailable.
			msleep(1);
			retval = recv( fd, buffer, length, MSG_PEEK );
			count++;
		}
# endif

		if( retval == -1 && count < 10 )
		{
# ifdef OS_NT
		    TRANSPORT_PRINTF( SSLDEBUG_ERROR,
			    "Peek error is: %d", WSAGetLastError());
# else
		    TRANSPORT_PRINTF( SSLDEBUG_ERROR,
			    "Peek error is: %d", errno);
# endif
		}
		return retval;
}

const NetPortParser &
NetTcpTransport::GetPortParser() const
{
    return portParser;
}

void NetTcpTransport::SetPortParser(const NetPortParser &portParser)
{
    this->portParser = portParser;
}

int
NetTcpTransport::GetInfo( StrBuf *b )
{
# ifdef TCP_INFO
		if( !b )
			return 0;
# define TD( x ) *b << #x << " " << tinfo.tcpi_ ## x << "\t";

		struct tcp_info tinfo;
		socklen_t sl = sizeof tinfo;

		if( getsockopt( t, IPPROTO_TCP, TCP_INFO, (void *)&tinfo, &sl ) >= 0 )
		{
# ifdef OS_FREEBSD
		    b->UAppend( "options" );
# else
		    *b << "retransmits " << (int)tinfo.tcpi_retransmits << "\t";
		    *b << "probes " << (int)tinfo.tcpi_probes << "\t";
		    *b << "backoff " << (int)tinfo.tcpi_backoff << "\noptions";
# endif
			if( tinfo.tcpi_options & TCPI_OPT_TIMESTAMPS )
				*b << " timestamps";
			if( tinfo.tcpi_options & TCPI_OPT_SACK )
				*b << " sack";
			if( tinfo.tcpi_options & TCPI_OPT_WSCALE )
				*b << " wscale";
			if( tinfo.tcpi_options & TCPI_OPT_ECN )
				*b << " ecn";
# ifdef TCPI_OPT_ECN_SEEN
			if( tinfo.tcpi_options & TCPI_OPT_ECN_SEEN )
				*b << " ecn_seen";
# endif
# ifdef TCPI_OPT_SYN_DATA
			if( tinfo.tcpi_options & TCPI_OPT_SYN_DATA )
				*b << " syn_data";
# endif
# ifdef TCPI_OPT_TOE
			if( tinfo.tcpi_options & TCPI_OPT_TOE )
				*b << " toe";
# endif
		    *b << "\nsscale " << (int)tinfo.tcpi_snd_wscale << "\t";
		    *b << "rscale " << (int)tinfo.tcpi_rcv_wscale << "\n";

			TD( rto );
# ifdef OS_LINUX
			TD( ato );
# endif
			TD( snd_mss );
		    *b << "rcv_mss " << tinfo.tcpi_rcv_mss << "\n";

# ifdef OS_LINUX
			TD( unacked );
			TD( sacked );
			TD( lost );
			TD( retrans );
		    *b << "fackets " << tinfo.tcpi_fackets << "\n";

			TD( last_data_sent );
# endif
			TD( last_data_recv );
# ifdef OS_LINUX
			TD( last_ack_recv );

			b->Extend( '\n' );

			TD( pmtu );
			TD( rcv_ssthresh );
# endif
			TD( rtt );
			TD( rttvar );
			b->Extend( '\n' );
			TD( snd_ssthresh );
			TD( snd_cwnd );
# ifdef OS_LINUX
			TD( advmss );
			TD( reordering );

			b->Extend( '\n' );

			//			TD( rcv_rtt );
			//		    p4debug.printf( "total retrans %u\n", tinfo.tcpi_total_retrans );
# endif
# ifdef OS_FREEBSD
			TD( rcv_space );
			TD( snd_wnd );
			TD( snd_bwnd );
			TD( snd_nxt );
			TD( rcv_nxt );
			b->Extend( '\n' );
			TD( toe_tid );
			TD( snd_rexmitpack );
			TD( rcv_ooopack );
			TD( snd_zerowin );
			b->Extend( '\n' );
# endif
			return 1;
		}
# endif
		return 0;
}
