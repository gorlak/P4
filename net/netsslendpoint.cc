/**
 * @file netsslendpoint.cc
 *
 * @brief SSL driver for NetEndPoint
 *	NetSslEndPoint - a TCP with SSL subclass of NetTcpEndPoint
 *
 * Threading: underlying SSL library contains threading
 *
 * @invariants:
 *
 * Copyright (c) 2011 Perforce Software
 * Confidential.  All Rights Reserved.
 * @author Wendy Heffner
 *
 * Creation Date: August 19, 2011
 */

/**
 * NOTE:
 * The following file only defined if USE_SSL true.
 * The setting of this definition is controlled by
 * the Jamrules file.  If the jam build is specified
 * with -sSSL=yes this class will be defined.
 */
# ifdef USE_SSL

# define NEED_ERRNO
# define NEED_SIGNAL
# ifdef OS_NT
# define NEED_FILE
# endif
# define NEED_FCNTL
# define NEED_IOCTL
# define NEED_TYPES

# ifdef OS_MPEIX
# define _SOCKET_SOURCE /* for sys/types.h */
# endif

// Only partial Smart Heap instrumentation.
//
# ifdef MEM_DEBUG
# undef DEFINE_NEW_MACRO
# endif

# include <stdhdrs.h>
# include <error.h>
# include <strbuf.h>
# include "netaddrinfo.h"

extern "C"
{ // OpenSSL

# include "openssl/bio.h"
# include "openssl/ssl.h"
# include "openssl/err.h"

}

# include <error.h>
# include <errorlog.h>
# include <debug.h>
# include <bitarray.h>
# include <tunable.h>
# include <enviro.h>
# include "filesys.h"
# include "pathsys.h"

# include <keepalive.h>
# include "netsupport.h"
# include "netport.h"

# include "netportparser.h"
# include "netconnect.h"
# include "nettcpendpoint.h"
# include "nettcptransport.h"
# include "netsslcredentials.h"
# include "netsslendpoint.h"
# include "netssltransport.h"
# include "netsslmacros.h"
# include "netselect.h"
# include "netdebug.h"
# include <msgrpc.h>

#include <memory>
using namespace std;

////////////////////////////////////////////////////////////////////////////
//  NetSslEndPoint                                                        //
////////////////////////////////////////////////////////////////////////////

void
NetSslEndPoint::Listen( Error *e )
{
	isAccepted = false;
	if ( !serverCredentials )
	{
	    serverCredentials = new NetSslCredentials();
	    serverCredentials->ReadCredentials( e );
	    if( e->Test() ) {
		return;
	    }
	}
	NetTcpEndPoint::Listen(e);
}
/**
 * NetSslEndPoint::ListenCheck
 *
 * @brief Method stubbed out in ssl version of endpoint
 *
 * @param e, Error pointer to hand back any error state
 */
void
NetSslEndPoint::ListenCheck( Error *e )
{
	/*
	 * This operation should never be performed on an
	 * SSL endpoint.  We do not want to allow the
	 * NetTcpEndPoint::ListenCheck to be used
	 * if ssl.
	 */
	e->Set( MsgRpc::SslInvalid ) << GetPortParser().String().Text();
	return;
}


/**
 * NetSslEndPoint::Accept
 *
 * @brief ssl endpoint version of accept, verifies that client request coming in is via ssl
 *
 * @param error structure
 * @return a NetSslTransport
 */
NetTransport *
NetSslEndPoint::Accept( KeepAlive *, Error *e )
{
	NetSslTransport *  sslTransport = NULL;
	TYPE_SOCKLEN       lpeer;
	struct sockaddr_storage
	                   peer;
	int                t;

	TRANSPORT_PRINTF( SSLDEBUG_TRANS, "NetSslEndpoint accept on %d", s );

	lpeer = sizeof peer;

	// Loop accepting, as it gets interrupted (by SIGCHILD) on
	// some platforms (MachTen, but not FreeBSD).

	while( ( t = accept( s, (struct sockaddr *) &peer, &lpeer )) < 0 )
	{
	    if( errno != EINTR )
	    {
		e->Net( "accept", "socket" );
		goto fail;
	    }
	}

# ifdef F_SETFD
	// close on exec
	// so p4web's launched processes don't get our socket
	fcntl( t, F_SETFD, 1 );
# endif

	sslTransport = new NetSslTransport( t, true, *serverCredentials );

	if(sslTransport)
	{
	    sslTransport->SetPortParser(GetPortParser());
	    /*
	     * Lazy initialization: If no SSL context has been created
	     * for the server side of the connection then do it
	     * now.
	     */
	    StrPtr *hostname = GetListenAddress( RAF_NAME );
	    sslTransport->SslServerInit( hostname, e );
	}
	return sslTransport;

fail:
	DEBUGPRINT( SSLDEBUG_ERROR, "NetSslEndpoint::Accept In fail error code." );
	e->Set( MsgRpc::SslAccept ) << GetPortParser().String().Text() << "";
	return 0;
}

/**
 * NetSslEndPoint::Connect
 *
 * @brief performs a ssl endpoint connect and returns
 * a NetSslTransport for the new connection
 *
 * @param Error structure
 * @return NetSslTransport for the new connection
 */
NetTransport *
NetSslEndPoint::Connect( Error *e )
{
	int                t;
	NetSslTransport *  sslTransport = NULL;

	// Set up addresses

	/* Configure socket */
	if( ( t = BindOrConnect( AT_CONNECT, e )) < 0 )
	{
	    TRANSPORT_PRINT( SSLDEBUG_ERROR,
		    "NetSslEndpoint::Connect In fail error code." );
	    return 0;
	}

	TRANSPORT_PRINTF( SSLDEBUG_TRANS,
		"NetSslEndpoint setup connect socket on %d", t );

# ifdef SIGPIPE
	signal( SIGPIPE, SIG_IGN );
# endif

	sslTransport = new NetSslTransport( t, false );
	if(sslTransport)
	{
	    sslTransport->SetPortParser(GetPortParser());
	    /*
	     * Lazy initialization: If no SSL context has been created
	     * for the client side of the connection then do it
	     * now.
	     */
	    sslTransport->SslClientInit( e );
	}
	return sslTransport;

}


void
NetSslEndPoint::GetMyFingerprint( StrBuf &value )
{
	if( serverCredentials && serverCredentials->GetFingerprint() &&
		serverCredentials->GetFingerprint()->Length() )
	    value.Set( serverCredentials->GetFingerprint()->Text() );
	else
	    value.Clear();
}

void
NetSslEndPoint::GetExpiration( StrBuf &buf )
{
	if (serverCredentials)
	    serverCredentials->GetExpiration( buf );
	else
	    buf.Clear();
}

# endif //USE_SSL
