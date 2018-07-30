/*
 * Copyright 2016 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <netportipv6.h>	// must be included before stdhdrs.h
# include <stdhdrs.h>

# include <signaler.h>

# include <debug.h>
# include <tunable.h>
# include <strbuf.h>
# include <strdict.h>
# include <strarray.h>
# include <strtable.h>
# include <error.h>
# include <errorlog.h>
# include <tracker.h>
# include <timer.h>
# include <md5.h>
# include <ticket.h>
# include <vararray.h>

# include <keepalive.h>
# include <rpc.h>
# include <netportparser.h>
# include <netconnect.h>
# include <netbuffer.h>
# include <netmulti.h>

# include <rpcdebug.h>
# include <rpcmulti.h>
# include <rpctrans.h>
# include <msgrpc.h>
# include <p4tags.h>

RpcMulti::RpcMulti()
{
}

RpcMulti::~RpcMulti()
{
}

int
RpcMulti::Add( Rpc *rpc, RpcDispatcher *disp )
{
	for( int i = 0; i < RpcArray.Count(); ++i )
	{
	    if( RpcArray.Get( i ) == (void *)rpc )
		return 0;
	}
	RpcArray.Put( (void *)rpc );
	DispatcherArray.Put( (void *)disp );
	return 1;
}

int
RpcMulti::Remove( Rpc *rpc )
{
	for( int i = 0; i < RpcArray.Count(); ++i )
	{
	    if( RpcArray.Get( i ) == (void *)rpc )
	    {
		RpcArray.Remove( i );
		DispatcherArray.Remove( i );
		return 1;
	    }
	}
	return 0;
}

int
RpcMulti::AnyActive()
{
	Rpc *wrpc;

	for( int i = 0; ( wrpc = (Rpc *)RpcArray.Get( i ) ); ++i )
	{
	    if( wrpc->Active() )
		return 1;
	}
	return 0;
}

int
RpcMulti::Dispatch( Error *e )
{
	int cnt = 0;
	int blocking = 0;
	Rpc *wrpc;

	do
	{
	    MultiRead( blocking, e );
	    if( e->Test() )
		return -1;
	    for( int i = 0; ( wrpc = (Rpc *)RpcArray.Get( i ) ); ++i )
	    {
		while( wrpc->DispatchReady() && !wrpc->suspendDispatch )
		{
		    ++cnt;
		    RpcDispatcher *disp = (RpcDispatcher *)DispatcherArray.Get( i );
		    wrpc->DispatchOne( disp );
		}
	    }
	    blocking = 1;
	} while ( cnt == 0 );
	return cnt;
}

void
RpcMulti::MultiRead( int blocking, Error *e )
{
	Rpc *wrpc;
	NetMulti mux;

	// build masks
	for( int i = 0; ( wrpc = (Rpc *)RpcArray.Get( i ) ); ++i )
	{
	    mux.AddTransport( wrpc->transport, e );
	    if( e->Test() )
		return;
	    wrpc->FlushTransport();
	}
	// select
	mux.Select( blocking, e );
	if( e->Test() )
	    return;
	for( int i = 0; ( wrpc = (Rpc *)RpcArray.Get( i ) ); ++i )
	{
	    if( mux.Readable( wrpc->transport, e ) )
		wrpc->transport->Fill( &wrpc->re, &wrpc->se );
	}
}
