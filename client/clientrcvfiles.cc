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

# include <pathsys.h>
# include <enviro.h>
# include <ticket.h>

# include <msgclient.h>
# include <msgsupp.h>

# include "clientservice.h"
# include "client.h"
# include "clientprog.h"

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
	    transfer = new P4ExecTranfer;
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
	    delete transfer;

	if( e->Test() )
	    errSet++;

	if( errSet )
	    client->SetError();

	if( errSet && confirm )
	    client->Confirm( confirm );

	return;
}

