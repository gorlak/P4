/*
 * Copyright 1995, 2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include <debug.h>
# include <strbuf.h>
# include <error.h>
# include <pathsys.h>

# include <msgrpc.h>

# include <keepalive.h>
# include "netaddrinfo.h"
# include "netportparser.h"
# include "netconnect.h"
# include "nettcpendpoint.h"
# include "nettcptransport.h"
# include "netdebug.h"

# ifdef USE_SSL
extern "C" {    // OpenSSL
# include "openssl/bio.h"
# include "openssl/ssl.h"
# include "openssl/err.h"
}
# endif //USE_SSL

/*
 * Note: it is ok to include this header file even if
 * we are not configured to use SSL since we will still
 * check for handshake. Need defines in header.
 */
# include "netsslcredentials.h"
# include "netsslendpoint.h"
# include "netsslmacros.h"
# include "netstd.h"

NetEndPoint *
NetEndPoint::Create( const char *addr, Error *e )
{
	NetEndPoint *endPoint;
	NetPortParser ppaddr( addr );    // parse addr

	// Load up protocol.

	if( ppaddr.MustRSH() || ppaddr.MustJSH() )
	{
	    // Explicit rsh:cmd

	    endPoint = new NetStdioEndPoint( ppaddr.MustJSH(), e );
	    endPoint->ppaddr = ppaddr;
	}
	else if( ppaddr.MustSSL() )
	{
	    // Explicit ssl:cmd

# ifdef USE_SSL
	    endPoint = new NetSslEndPoint( e );
# else
	    DEBUGPRINT( SSLDEBUG_ERROR, "Trying to use SSL when not configured." );
	    // we reserve "ssl:", "ssl4:", and "ssl6:" even w/o ssl
	    // TODO: add an error/warning message
	    e->Set( MsgRpc::TcpPeerSsl );
	    return NULL;
# endif
	    endPoint->ppaddr = ppaddr;
	}
	else
	{
	    // Implicit or explicit [transport:][host:][addr]

	    endPoint = new NetTcpEndPoint( e );
	    endPoint->ppaddr = ppaddr;
	}
	return endPoint;
}

void
NetEndPoint::GetExpiration( StrBuf &buf )
{
	buf.Clear();
	return;
}


NetEndPoint::~NetEndPoint()
{
}

NetTransport::~NetTransport()
{
}


/**
 * NetTransport::CheckForHandshake
 *
 * @brief Peek at the first 3 bytes of client data to see if looks like SSL Client Handshake.
 * @invariant Will leave kernel mbufs unchanged.
 *
 * @param fd - file descripter for socket
 * @see (NetSslEndPoint::ClientMismatch, NetTcpEndPoint::ClientMismatch)
 * @return enum result PeekTimeout, or PeekSSL, PeekCleartext
 */
PeekResults
NetTransport::CheckForHandshake( int fd )
{
	char buffer[SSLHDR_SIZE];
	int num = Peek( fd, buffer, SSLHDR_SIZE );
	if( num != SSLHDR_SIZE )
	{
	    DEBUGPRINTF( SSLDEBUG_ERROR, "Peek return %d bytes.", num);
	    // not able to read 3 bytes, connection screwed up
	    return PeekTimeout;
	}
	if( (buffer[0] == SSLPROTOCOL) && (buffer[1] == SSLVERSION_BYTE1)
	    && (buffer[2] == SSLVERSION_BYTE2) )
	{
	    return PeekSSL;
	}
	DEBUGPRINT( SSLDEBUG_ERROR, "Peek signature not SSL.");
	return PeekCleartext;
}

/**
 * NetTransport::ClientMismatch
 *
 * @brief Default implementation for non-network transports
 *
 * @param Error pointer - pass in error to set if there is a problem
 * @return none
 */
void
NetTransport::ClientMismatch( Error *e )
{
    // Do nothing if called on a non-network transport
}

/**
 * NetTransport::CheckForHandshake
 *
 * @brief Default implementation for non-network based transports
 *
 * @param fd - file descriptor for socket
 * @return -1 to indicate failure
 */
int
NetTransport::Peek( int fd, char *buffer, int length )
{
	// Default implementation for non-network based transports
	// should return a value that looks like an error
	return -1;
}

/*
 * NetTransport::SendOrReceive() - implementation for old NetTransports
 *
 * If there is anything to write, do that.
 * Otherwise, if there is room to read, do that.
 *
 * Returns 1 as long as something happens.
 */

int
NetTransport::SendOrReceive( NetIoPtrs &io, Error *se, Error *re )
{
	if( io.sendPtr != io.sendEnd && !se->Test() )
	{
	    Send( io.sendPtr, io.sendEnd - io.sendPtr, se );

	    if( !se->Test() )
	    {
	        io.sendPtr = io.sendEnd;
	        return 1;
	    }
	}

	if( io.recvPtr != io.recvEnd && !re->Test() )
	{
	    int l = Receive( io.recvPtr, io.recvEnd - io.recvPtr, re );

	    if( l > 0 )
	    {
	        io.recvPtr += l;
	        return 1;
	    }
	}

	return 0;
}

/*
 * This is a fall back for old transports which have the above
 * default SendOrReceive
 */

int
NetTransport::DuplexReady()
{
	return 1;
}
