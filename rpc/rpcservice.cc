/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * RpcService.cc - remote procedure services always available
 *
 * Recognizes the following services directly:
 *
 *	compress1	turns link compression on; sends compress2
 *	compress2	turns recv link compression on
 *	echo		echo stuff to stdout, for testing
 *	flush1		sends a 'flush2' back the the sender
 *	flush2		clears awaitingFlush flag
 *	release		clears awaitingRelease flag, send 'release2'
 *	release2	clears awaitingRelease flag
 */

# include <stdhdrs.h>

# include <debug.h>
# include <strbuf.h>
# include <strdict.h>
# include <error.h>

# include <p4tags.h>

# include "rpc.h"
# include "rpcservice.h"

// Dispatch functions available to all callers.

void
RpcServerCompress1( Rpc *rs, Error *e )
{
	rs->GotRecvCompressed( e );
	rs->InvokeOne( P4Tag::p_compress2 );
	rs->GotSendCompressed( e );
}

void
RpcServerCompress2( Rpc *rs, Error *e )
{
	rs->GotRecvCompressed( e );
}

void
RpcServerEcho( Rpc *rs, Error *e )
{
	StrPtr *param = rs->GetVar( P4Tag::v_arg );

	printf( "%s\n", param ? param->Text() : "" );
}

void
RpcServerFlush1( Rpc *rs, Error *e )
{
	rs->CopyVars();
	rs->Invoke( P4Tag::p_flush2 );
}

void
RpcServerFlush2( Rpc *rs, Error *e )
{
	// Let dispatcher know.
	rs->GotFlushed();
}

void
RpcServerProtocol( Rpc *rs, Error *e )
{
	// Just record the partner's server version number, if passed.
	// Upper level really needs protocol handler.

	StrPtr *s;
	
	if( ( s = rs->GetVar( P4Tag::v_server2 ) ) ||
	    ( s = rs->GetVar( P4Tag::v_server ) ) )
		rs->protocolServer = s->Atoi();
}

void
RpcServerRelease( Rpc *rs, Error *e )
{
	// Let dispatcher know.
	rs->GotReleased();
}

const RpcDispatch rpcServices[] = {
	P4Tag::p_compress1,	RpcCallback( RpcServerCompress1 ),
	P4Tag::p_compress2,	RpcCallback( RpcServerCompress2 ),
	P4Tag::p_echo, 		RpcCallback( RpcServerEcho ),
	P4Tag::p_flush1,	RpcCallback( RpcServerFlush1 ), 
	P4Tag::p_flush2,	RpcCallback( RpcServerFlush2 ),
	P4Tag::p_protocol,	RpcCallback( RpcServerProtocol ),
	P4Tag::p_release,	RpcCallback( RpcServerRelease ),
	P4Tag::p_release2,	RpcCallback( RpcServerRelease ),
	0, 0
} ;

