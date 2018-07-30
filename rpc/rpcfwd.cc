/*
 * Copyright 1995, 2006 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include <strbuf.h>
# include <strdict.h>
# include <strtable.h>
# include <strarray.h>
# include <error.h>
# include <ticket.h>
# include <md5.h>
# include <keepalive.h>
# include <debug.h>

# include <rpc.h>
# include <rpcfwd.h>
# include <rpcdebug.h>
# include <rpcdispatch.h>
# include <rpcservice.h>
# include <rpcbuffer.h>

# include <p4tags.h>

/*
 * RpcForward -- connect two RPCs together
 */

/*
 * s2cCompress1() - process compression request from server to client
 * c2sCompress2() - process compression ack from client to server
 *
 * s2cFlush1() - dispatch from client if pipe through client now full
 * c2sFlsuh2() - note pipe through client emptying
 *
 * s2cForward() - forward message wholesale from server to client
 * c2sForward() - forward message wholesale from client to server
 */

void s2cCompress1( Rpc *rpc, Error *e ) { rpc->GetForwarder()->Compress1( e ); }
void c2sCompress2( Rpc *rpc, Error *e ) { rpc->GetForwarder()->Compress2( e ); }
void s2cFlush1( Rpc *rpc, Error *e ) { rpc->GetForwarder()->Flush1( e ); }
void c2sFlush2( Rpc *rpc, Error *e ) { rpc->GetForwarder()->Flush2( e ); }
void s2cForward( Rpc *rpc, Error *e ) { rpc->GetForwarder()->ForwardS2C(); }
void c2sForward( Rpc *rpc, Error *e ) { rpc->GetForwarder()->ForwardC2S(); }
void s2cCrypto( Rpc *rpc, Error *e ) { rpc->GetForwarder()->CryptoS2C( e ); }
void c2sCrypto( Rpc *rpc, Error *e ) { rpc->GetForwarder()->CryptoC2S( e ); }

const RpcDispatch s2cDispatch[] = {
	P4Tag::p_compress1,	RpcCallback( s2cCompress1 ),
	P4Tag::p_flush1,	RpcCallback( s2cFlush1 ),
	P4Tag::p_protocol,	RpcCallback( s2cForward ),
	P4Tag::c_Crypto,	RpcCallback( s2cCrypto ),
	P4Tag::p_funcHandler,	RpcCallback( s2cForward ),
	0, 0
} ;

const RpcDispatch c2sDispatch[] = {
	P4Tag::p_compress2,	RpcCallback( c2sCompress2 ),
	P4Tag::p_flush2,	RpcCallback( c2sFlush2 ),
	P4Tag::p_protocol,	RpcCallback( c2sForward ),
	"crypto",		RpcCallback( c2sCrypto ),
	P4Tag::p_funcHandler,	RpcCallback( c2sForward ),
	0, 0
} ;

/*
 * RpcForward -- connect two RPCs together
 */

RpcForward::RpcForward( Rpc *client, Rpc *server )
{
	this->client = client;
	this->server = server;

	c2sDispatcher = new RpcDispatcher;
	s2cDispatcher = new RpcDispatcher;

	c2sDispatcher->Add( rpcServices );
	s2cDispatcher->Add( rpcServices );
	c2sDispatcher->Add( c2sDispatch );
	s2cDispatcher->Add( s2cDispatch );

	client->SetForwarder( this );
	server->SetForwarder( this );

	duplexCount = 0;
	himarkadjustment = 50;
}

RpcForward::~RpcForward()
{
	delete c2sDispatcher;
	delete s2cDispatcher;
}

void
RpcForward::Dispatch()
{
	// Dispatch until released

	server->Dispatch( Rpc::DfComplete, s2cDispatcher );
}

void
RpcForward::DispatchOne()
{
	// Dispatch once
	server->DispatchOne( s2cDispatcher );
}

void
RpcForward::ClientDispatchOne()
{
	// Dispatch once
	client->DispatchOne( c2sDispatcher );
}

void
RpcForward::ForwardNoInvoke( Rpc *src, Rpc *dst, StrRef &func )
{
	int i;
	StrRef var, val;

	// copy unnamed args, then named vars

	for( i = 0; i < src->GetArgc(); ++i )
	    dst->SetVar( StrRef::Null(), *src->GetArgi(i) );

	for( i = 0; src->GetVar( i, var, val ) && var != P4Tag::v_func; ++i )
	    dst->SetVar( var, val );

	// last is "func"
	func = val;
}

void
RpcForward::Forward( Rpc *src, Rpc *dst )
{
	int i;
	StrRef var, val;

	// copy unnamed args, then named vars

	for( i = 0; i < src->GetArgc(); ++i )
	    dst->SetVar( StrRef::Null(), *src->GetArgi(i) );

	for( i = 0; src->GetVar( i, var, val ) && var != P4Tag::v_func; ++i )
	    dst->SetVar( var, val );

	// last is "func"

	dst->Invoke( val.Text() );
}

void
RpcForward::InvokeDict( StrDict *dict, Rpc *dst )
{
	int i;
	StrRef var, val;

	for( i = 0; dict->GetVar( i, var, val ) && var != P4Tag::v_func; ++i )
	    dst->SetVar( var, val );

	dst->Invoke( val.Text() );
}

void
RpcForward::ForwardExcept( Rpc *src, Rpc *dst, const StrPtr &except )
{
	int i;
	StrRef var, val;

	// copy unnamed args, then named vars

	for( i = 0; i < src->GetArgc(); ++i )
	    dst->SetVar( StrRef::Null(), *src->GetArgi(i) );

	for( i = 0; src->GetVar( i, var, val ) && var != P4Tag::v_func; ++i )
	    if( var != except )
		dst->SetVar( var, val );

	// last is "func"

	dst->Invoke( val.Text() );
}

void
RpcForward::Compress1( Error *e )
{
	server->GotRecvCompressed( e );
	Forward( server, client );
	client->GotSendCompressed( e );
}

void
RpcForward::Compress2( Error *e )
{
	client->GotRecvCompressed( e );
	Forward( client, server );
	server->GotSendCompressed( e );
}

void
RpcForward::Flush1( Error *e )
{
	StrRef himarkVar( P4Tag::v_himark );

	StrPtr *fseq = server->GetVar( P4Tag::v_fseq );
	StrPtr *himark = server->GetVar( himarkVar );

	if( fseq ) duplexCount += fseq->Atoi();

	// nb. Our high mark is gets adjusted to avoid lockstep network delays

	if( himark )
	{
	    // Note:  The himark comes from the server,  so
	    // we adjust it down when calculating if the pipe through
	    // the client is now full.  However this intermediate
	    // process may have a (rsh:) pipe connection rather than
	    // a socket,  in that case its size is limited by 2K
	    // buffers,  adjust himark to compensate.

	    int himark2 = himark->Atoi();

	    if( client->IsSingle() && himark2 > 4096 )
	        himark2 = 4096;

	    if( himark2 > 0 && himarkadjustment < 100 )
	    {
		int newhimark = himarkadjustment * himark2 / 100;

		// no less than 1k (unless zero - zero is fine and handled above)
		if( newhimark < 1024 )
		    newhimark = 1024;

		himark2 = newhimark;
	    }

	    if( client->recvBuffering == 0 )
	        client->recvBuffering = client->GetRecvBuffering();
	    if( client->recvBuffering > 0 && client->recvBuffering < himark2 )
	        himark2 = client->recvBuffering;

	    client->SetVar( himarkVar, StrNum( himark2 ) );

	    ForwardExcept( server, client, himarkVar );

	    KeepAlive *k = client->GetKeepAlive();

	    RpcRecvBuffer *oldbuf = client->recvBuffer;
	    client->recvBuffer = new RpcRecvBuffer;

	    while( duplexCount > himark2 )
	    {
		if( client->Dropped() )
		    if( !k || !k->IsAlive() || client->ReadErrors() )
			break;
		client->DispatchOne( c2sDispatcher );
	    }

	    delete client->recvBuffer;
	    client->recvBuffer = oldbuf;
	}
	else
	    Forward( server, client );
}

void
RpcForward::Flush2( Error *e )
{
	Forward( client, server );

	StrPtr *fseq = client->GetVar( P4Tag::v_fseq );

	if( fseq ) duplexCount -= fseq->Atoi();
}

void
RpcForward::SetCrypto( StrPtr *svr, StrPtr *tfile )
{
	crypto.Set( svr, tfile );
}

void
RpcForward::CryptoC2S( Error * )
{
	crypto.C2S( client, server );

	Forward( client, server );
}

void
RpcForward::CryptoS2C( Error * )
{
	Forward( server, client );

	crypto.S2C( server );
}

/*
 * RpcCrypto -- handle intermediate service authentication
 */

RpcCrypto::RpcCrypto()
    : attackCount( 0 )
{
}

RpcCrypto::~RpcCrypto()
{
}

void
RpcCrypto::Set( StrPtr *svr, StrPtr *tfile )
{
	if( svr )
	    svrname = *svr;

	if( tfile )
	    ticketFile = *tfile;
}

void
RpcCrypto::S2C( Rpc *server )
{
	cryptoToken.Set( server->GetVar( P4Tag::v_token ) );

	StrPtr *addr = server->GetVar( P4Tag::v_serverAddress );

	if( addr )
	{
	    serverID.Set( addr );

	    // lookup ticket from svrname user
	    if( svrname.Length() )
	    {
		Ticket t( &ticketFile );
		const char *c = t.GetTicket( *addr, svrname );

		if( c )
		    ticket.Set( c );
	    }
	}
}

void
RpcCrypto::C2S( Rpc *client, Rpc *server )
{
	// Set intermediate authentication stuff...

	MD5	md5;
	StrPtr *daddr;
	StrPtr *addr;
	int	clevel = 0;

	StrRef	daddrref( P4Tag::v_daddr );
	StrRef	caddrref( P4Tag::v_caddr );

	daddr = client->GetVar( P4Tag::v_ipaddr );

	if( !daddr )
	    daddr = client->GetVar( daddrref );
	else
	    DEBUGPRINTF( DEBUG_SVR_INFO, "client daddr %s", daddr->Text() );

	while( client->GetVar( daddrref, clevel ) )
	    ++clevel;

	addr = client->GetPeerAddress( 0 );

	if( clevel )
	{
	    // nested proxy ( not closest to client )
	    daddr = client->GetVar( daddrref, clevel - 1 );
	    if( addr )
		server->SetVar( caddrref, clevel, *addr );
	}
	else
	{
	    // first level proxy

	    if( client->GetVar( caddrref ) )
	    {
		DEBUGPRINT( DEBUG_SVR_WARN,
			"client sent caddr to forwarder - ATTACK");
		attackCount++;
		md5.Update( caddrref );
		server->SetVar( P4Tag::v_attack, caddrref );
	    }

	    // if there is no client address due to rsh, use the
	    // local address of the connection to the server
	    if( !client->HasAddress() || !addr )
		addr = server->GetAddress( 0 );
	    if( addr )
		server->SetVar( caddrref, *addr );
	}

	if( daddr && ( addr = client->GetAddress( RAF_PORT ) ) )
	{
	    if( *addr != *daddr )
	    {
		attackCount++;
		md5.Update( *addr );
		server->SetVar( P4Tag::v_attack, clevel, *addr );
		DEBUGPRINTF( DEBUG_SVR_WARN,
			"forwarder to unknown %s vs %s - ATTACK",
			addr->Text(), daddr->Text() );
	    }
	    else
		DEBUGPRINTF( DEBUG_SVR_INFO,
			"forwarder to unknown %s vs %s",
			addr->Text(), daddr->Text() );
	}

	if( addr = server->GetPeerAddress( RAF_PORT ) )
	{
	    StrBuf phash;

	    if( svrname.Length() > 0 )
	    {
		md5.Update( svrname );
		server->SetVar( P4Tag::v_svrname, clevel, svrname );
	    }
	    if( ticket.Length() > 0 )
		md5.Update( ticket );
	    md5.Update( cryptoToken );

	    md5.Update( *addr );
	    server->SetVar( daddrref, clevel, *addr );
	    md5.Final( phash );
	    server->SetVar( P4Tag::v_dhash, clevel, phash );
	}
}
