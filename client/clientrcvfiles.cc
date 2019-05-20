/*
 * Copyright 1995, 2001 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include "clientapi.h"

# include <strops.h>
# include <strarray.h>
# include <strtable.h>
# include <mapapi.h>
# include <runcmd.h>
# include <rpc.h>
# include <mangle.h>
# include <i18napi.h>
# include <charcvt.h>
# include <transdict.h>
# include <debug.h>
# include <tunable.h>
# include <ignore.h>
# include <timer.h>
# include <progress.h>
# include <signaler.h>

# include <pathsys.h>
# include <enviro.h>
# include <ticket.h>

# include <msgclient.h>
# include <msgsupp.h>

# include "clientservice.h"
# include "client.h"
# include "clientprog.h"

# ifdef HAS_CPP11
# include <future>
# include <vector>

class ThreadedKeepAlive : public KeepAlive {
    public:
	int		IsAlive() { return !signaler.IsIntr(); }
} ;

class ThreadedTransfer : public ClientTransfer, public ClientUser
{
	public:

	    int     Transfer( ClientApi *client,
	                      ClientUser *ui,
	                      const char *cmd,
	                      StrArray &args,
	                      StrDict &pVars,
	                      int threads,
	                      Error *e );

	    void 	HandleError( Error *err );
	    void 	Message( Error *err );
	    void 	OutputError( const char *errBuf );
	    void	OutputInfo( char level, const char *data );
	    void 	OutputBinary( const char *data, int length );
	    void 	OutputText( const char *data, int length );

	    void	OutputStat( StrDict *varList );
	    int		OutputStatPartial( StrDict * );

	private:

	    int		RunTransfer( ClientApi *client,
	                             ClientUser *ui,
	                             const char *cmd,
	                             StrArray *args,
	                             StrDict *pVars );

	    ClientUser* master;
	    std::mutex mutex;
	    ThreadedKeepAlive keepAlive;
};

int
ThreadedTransfer::RunTransfer( ClientApi *client,
	                       ClientUser *ui,
	                       const char *cmd,
	                       StrArray *args,
	                       StrDict *pVars )
{
	// Various parts of the P4API are not thread-safe.  E.g. a crash was
	// seen in client->GetPassword().
	mutex.lock();

	Error e;
	ClientApi child;
	StrRef var, val;

	for( int j = 0; pVars->GetVar( j++, var, val ); )
	    child.SetProtocol( var.Text(), val.Text() );

	child.SetProtocol( P4Tag::v_api, "99999" );
	child.SetProtocol( P4Tag::v_enableStreams, "" );
	child.SetProtocol( P4Tag::v_enableGraph, "" );
	child.SetProtocol( P4Tag::v_expandAndmaps, "" );

	child.SetPort( &client->GetPort() );
	child.SetUser( &client->GetUser() );
	child.SetClient( &client->GetClient() );

	if( client->GetPassword().Length() )
	    child.SetPassword( &client->GetPassword() );

	child.SetProtocolV( "tag" );
	child.SetProg( client->GetProg().Text() );

	child.Init( &e );
	child.SetVersion( client->GetVersion().Text() );
	child.SetBreak( &keepAlive );

	if( e.Test() )
	{
	    ui->HandleError( &e );
	    return 1;
	}

	char** a = new char*[ args->Count() ];

	for( int j = 0; j < args->Count(); j++ )
	    a[ j ] = args->Get( j )->Text();

	child.SetArgv( args->Count(), a );
	// Unlock here since we're past most of the issues the P4API
	// has with shared data and so we can execute in parallel.
	mutex.unlock();
	child.Run( cmd, ui );

	delete[] a;
	child.Final( &e );

	if( e.Test() )
	{
	    std::lock_guard< std::mutex > lock( mutex );
	    ui->HandleError( &e );
	    return 1;
	}

	// Errors like MsgClient::ClobberFile are only detected like this.
	if( child.GetErrors() )
	    return 1;

	return 0;
}

int
ThreadedTransfer::Transfer( ClientApi *client,
	                    ClientUser *ui,
	                    const char *cmd,
	                    StrArray &args,
	                    StrDict &pVars,
	                    int threads,
	                    Error *e )
{
	master = ui;

	std::vector< std::future< int > > ts;
	ts.reserve( threads + 1 );

	auto fn = [&]( ClientApi *client, ClientUser *ui, const char *cmd,
	               StrArray *args, StrDict *pVars )
	    { return RunTransfer( client, ui, cmd, args, pVars ); };

	const bool sigState = signaler.GetState();
	signaler.Disable();

	for( int i = 0; i < threads; i++ )
	    ts.emplace_back( std::async( std::launch::async, fn,
	                                 client, this, cmd, &args, &pVars ) );

	int es = 0;

	for( int i = 0; i < threads; i++ )
	    try
	    {
	        es += ts[ i ].get();
	    }
	    // Throw away the error since it only shows up on ctrl-c:
	    // "device or resource busy: device or resource busy"
	    catch( const std::exception& e )
	    {}

	if( !sigState )
	    signaler.Enable();

	return es;
}

void
ThreadedTransfer::HandleError( Error *err )
{
	std::lock_guard< std::mutex > lock( mutex );

	master->HandleError( err );
}

void
ThreadedTransfer::Message( Error *err )
{
	std::lock_guard< std::mutex > lock( mutex );

	master->Message( err );
}

void
ThreadedTransfer::OutputError( const char *errBuf )
{
	std::lock_guard< std::mutex > lock( mutex );

	master->OutputError( errBuf );
}

void
ThreadedTransfer::OutputInfo( char level, const char *data )
{
	std::lock_guard< std::mutex > lock( mutex );

	master->OutputInfo( level, data );
}

void
ThreadedTransfer::OutputBinary( const char *data, int length )
{
	std::lock_guard< std::mutex > lock( mutex );

	master->OutputBinary( data, length );
}

void
ThreadedTransfer::OutputText( const char *data, int length )
{
	std::lock_guard< std::mutex > lock( mutex );

	master->OutputText( data, length );
}

void
ThreadedTransfer::OutputStat(StrDict *varList )
{
	std::lock_guard< std::mutex > lock( mutex );

	master->OutputStat( varList );
}

int
ThreadedTransfer::OutputStatPartial( StrDict *varList )
{
	std::lock_guard< std::mutex > lock( mutex );

	return master->OutputStatPartial( varList );
}

# endif // HAS_CPP11

class TransmitChild
{
    public:

	RunArgv args;
	RunCommand cmd;
	int opts;
	int fds[2];
	Error e;
} ;

class P4ExecTranfer : public ClientTransfer
{
    public:
	int Transfer(   ClientApi *client,
			ClientUser *ui,
			const char *cmd,
			StrArray &args,
			StrDict &pVars,
			int threads,
			Error *e )
	{
	    StrBuf exe( client->GetExecutable() );
	    if( !exe.Length() )
	        exe.Set( "p4" );

	    TransmitChild *tc = new TransmitChild[ threads ];

	    for( int i = 0; i < threads; i++ )
	    {
		tc[i].args.AddArg( exe );
		if( ui->IsOutputTaggedWithErrorLevel() )
		    tc[i].args.AddArg( "-s" );
		StrRef var, val;
		for( int j = 0; pVars.GetVar( j++, var, val ); )
		{
		    StrBuf arg("-Z");
		    arg << var;
		    if( val.Text() )
			arg << "=" << val;
		    tc[i].args.AddArg( arg );
		}
		tc[i].args.AddArg( "-p" );
		tc[i].args.AddArg( client->GetPort() );
		tc[i].args.AddArg( "-u" );
		tc[i].args.AddArg( client->GetUser() );
		tc[i].args.AddArg( "-c" );
		tc[i].args.AddArg( client->GetClient() );
		if( client->GetPassword().Length() )
		{
		    tc[i].args.AddArg( "-P" );
		    tc[i].args.AddArg( client->GetPassword() );
		}
		tc[i].args.AddArg( cmd );
		for( int j = 0; j < args.Count(); j++ )
		    tc[i].args.AddArg( *args.Get( j ) );

		//StrBuf x;
		//p4debug.printf("Argv: %s\n", tc[i].args.Text( x ) );

		tc[ i ].opts = (RCO_AS_SHELL|RCO_USE_STDOUT);
		tc[ i ].fds[0] = tc[ i ].fds[1] = -1;

		tc[ i ].cmd.RunChild(
			tc[ i ].args, tc[ i ].opts, tc[ i ].fds, &tc[ i ].e );

		if( tc[ i ].e.Test() )
		{
		    //p4debug.printf("RunChild apparently failed\n");
		    *e = tc[ i ].e;
		    delete []tc;
		    return 1;
		}
	    }

	    int errSet = 0;
	    for( int i = 0; i < threads; i++ )
	    {
		    //p4debug.printf("Waiting for child %d\n", i);
		int status = tc[ i ].cmd.WaitChild();
		if( status )
		    ++errSet;
	    }
	
	    delete []tc;
	    return errSet;
	}

} ;

void
clientReceiveFiles( Client *client, Error *e )
{
	StrPtr *token = client->GetVar( P4Tag::v_token, e );
	StrPtr *threads = client->GetVar( P4Tag::v_peer, e );
	StrPtr *blockCount = client->GetVar( P4Tag::v_blockCount );
	StrPtr *blockSize = client->GetVar( P4Tag::v_scanSize );
	StrPtr *proxyload = client->GetVar( "proxyload" );
	StrPtr *proxyverbose = client->GetVar( "proxyverbose" );
	StrPtr *doPublish = client->GetVar( "doPublish" );
	StrPtr *applicense = client->GetVar( P4Tag::v_app );
	StrPtr *clientSend = client->GetVar( "clientSend" );
	StrPtr *confirm = client->GetVar( P4Tag::v_confirm );

	if( e->Test() )
	{
	    client->OutputError( e );
	    return;
	}
	int nThreads = threads->Atoi();

	int ourTransfer = 0;
	ClientTransfer *transfer;
	if( !( transfer = client->GetUi()->GetTransfer() ) )
	{
	    ourTransfer = 1;

# ifdef HAS_CPP11
	    transfer = new ThreadedTransfer;
# else
	    transfer = new P4ExecTranfer;
# endif
	}

	StrArray args;
	*args.Put() << "-t" << *token;
	if( blockCount )
	    *args.Put() << "-b" << *blockCount;
	if( blockSize )
	    *args.Put() << "-s" << *blockSize;
	if( clientSend )
	    *args.Put() << "-r";
	if( doPublish )
	    *args.Put() << "-p";

	StrBufDict pVars;
	if( proxyload )
	    pVars.SetVar( "proxyload" );
	if( proxyverbose )
	    pVars.SetVar( "proxyverbose" );
	if( applicense )
	    pVars.SetVar( "app", applicense );

	ClientApi cApi( client );

	int errSet = transfer->Transfer( &cApi, client->GetUi(), "transmit",
	                                 args, pVars, nThreads, e );

	if( ourTransfer )
	{
	    delete transfer;
	    transfer = NULL;
	}

	if( e->Test() )
	    errSet++;

	if( errSet )
	    client->SetError();

	if( errSet && confirm )
	    client->Confirm( confirm );

	return;
}

