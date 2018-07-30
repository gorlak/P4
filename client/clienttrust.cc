#include <clientapi.h>
#include <options.h>
#include <msgsupp.h>
#include <errorlog.h>
#include <rpc.h>
#include <ticket.h>
#include <client.h>
#include <msgrpc.h>
#include <error.h>
#include <errornum.h>

class MsgClientLocal
{
    public:

	static ErrorId trustHelp;
	static ErrorId trustUsage;
	static ErrorId trustNotSSL;
};

ErrorId MsgClientLocal::trustHelp = { ErrorOf( ES_HELP, 0, E_INFO, EV_NONE, 0 ),
"\n"
"	trust -- Establish trust of an SSL connection\n"
"\n"
"	p4 trust [ -l -y -n -d -f -r -i <fingerprint> ]\n"
"\n"
"	Establish trust of an SSL connection.  This client command manages\n"
"	the p4 trust file.  This file contains fingerprints of the keys\n"
"	received on ssl connections.  When an SSL connection is made, this\n"
"	file is examined to determine if the SSL connection has been used\n"
"	before and if the key is the same as a previously seen key for that\n"
"	connection.  Establishing trust with a connection prevents undetected\n"
"	communication interception (man-in-the-middle) attacks.\n"
"\n"
"	Most options are mutually exclusive.  Only the -r and -f options\n"
"	can be combined with the others.\n"
"\n"
"	The -l flag lists existing known fingerprints.\n"
"\n"
"	Without options, this command will make a connection to a server\n"
"	and examine the key if present, if one cannot be found this command\n"
"	will show a fingerprint and ask if this connection should be trusted.\n"
"	If a fingerprint exists and does not match, an error that a possible\n"
"	security problems exists will be displayed.\n"
"\n"
"	The -y flag will cause prompts to be automatically accepted.\n"
"\n"
"	The -n flag will cause prompts to be automatically refused.\n"
"\n"
"	The -d flag will remove an existing trusted fingerprint.\n"
"\n"
"	The -f flag will force the replacement of a mismatched fingerprint.\n"
"\n"
"	The -i flag will allow a specific fingerprint to be installed.\n"
"\n"
"	The -r flag specifies that a replacement fingerprint is to be\n"
"	affected.  Replacement fingerprints can be used in anticipation\n"
"	of a server replacing its key.  If a replacement fingerprint\n"
"	exists for a connection and the primary fingerprint does not match\n"
"	while the replacement fingerprint does, the replacement fingerprint\n"
"	will replace the primary.  This flag can be combined with -l, -i,\n"
"	or -d.\n"
};

ErrorId MsgClientLocal::trustUsage = { ErrorOf( ES_HELP, 1, E_FAILED, EV_NONE, 0 ),
	"p4 [ -p port ] trust [ -y -n -d -l -f -r -i <fingerprint> ]\n"
	"\tOnly one of -y -n -d -l -i is allowed.\n"
	"\tUse p4 trust -h for detailed help.\n"
};

ErrorId MsgClientLocal::trustNotSSL = { ErrorOf( ES_HELP, 2, E_INFO, EV_NONE, 0 ),
	"Only SSL connections require trust"
};

int 
clientTrustHelp( Error *e )
{
	ClientUser cuser;
	e->Set( MsgClientLocal::trustHelp );
	cuser.Message( e );
	e->Clear();
	return 0;
}

inline void
OutputBuffer( Client *c, const StrPtr &b )
{
    c->GetUi()->OutputText( b.Text(), b.Length() );
}

static void
InstallTrust( Client *client, StrPtr *peer, StrPtr &u, StrPtr &k, Error *e )
{
	StrRef r( client->GetTrustFile() );
	Ticket f( &r );
	f.ReplaceTicket( *peer, u, k, e );
}

static void
DeleteTrust( Client *client, StrPtr *peer, StrPtr &u, Error *e )
{
	StrRef r( client->GetTrustFile() );
	Ticket f( &r );
	f.DeleteTicket( *peer, u, e );
}

static void
ReportPeerKey( Client *client, StrPtr *peer, StrPtr *key )
{
	StrBuf buf;

	buf.Set( "The fingerprint of the server of your P4PORT setting\n" );
	buf.Append( peer );
	buf.Append( " is not known.\n" );
	buf.Append( "That fingerprint is " );
	buf.Append( key );
	buf.Append( "\n" );
	OutputBuffer( client, buf );
}

void
clientTrust( Client *client, Error *e )
{
	AssertLog.SetTag( "trust" );

	Options opts;

	int argc = client->GetArgc();
	StrPtr *argv = client->GetArgv();
	int longOpts[] = { Options::InputValue, Options::Delete,
	                   Options::Status, Options::Yes, Options::No,
	                   Options::Force, Options::Replacement, 0 };
	opts.ParseLong( argc, argv, "hyndflri:", longOpts,
	                OPT_NONE, MsgClientLocal::trustUsage, e );

	if( e->Test() )
	    return;

	int yflag = opts[ 'y' ] != 0;
	int nflag = opts[ 'n' ] != 0;
	int fflag = opts[ 'f' ] != 0;
	int dflag = opts[ 'd' ] != 0;
	int lflag = opts[ 'l' ] != 0;
	int rflag = opts[ 'r' ] != 0;
	int hflag = opts[ 'h' ] != 0;
	int flags = yflag + nflag + dflag + lflag + hflag;
	StrPtr *iflag = opts[ 'i' ];
	if( flags > ( iflag ? 0 : 1 ) )	// tricky!
	{
	    e->Set( MsgSupp::TooMany );
	    e->Set( MsgClientLocal::trustUsage );
	    return;
	}

	if( hflag )
	{
	    e->Set( MsgClientLocal::trustHelp );
	    client->GetUi()->Message( e );
	    return;
	}

	StrPtr *peer;
	peer = client->GetPeerAddress( RAF_PORT );

	StrRef port( client->GetPort() );

	StrBuf peername( "'" );
	peername.Append( &port );
	peername.Append( "' (" );
	peername.Append( peer );
	peername.Append( ")" );

	StrBuf fingerprint;
	client->GetPeerFingerprint( fingerprint );

	if( !fingerprint.Length() )
	{
		e->Set( MsgClientLocal::trustNotSSL );
		client->GetUi()->Message( e );
		return;
	}

	StrRef u( rflag ? "++++++" : "**++**" );

	if( lflag )
	{
	    // list operation is different
	    StrRef r( client->GetTrustFile() );
	    Ticket f( &r );
	    StrBuf o;
	    f.ListUser( u, o );
	    OutputBuffer( client, o );
	    return;
	}

	client->CheckKnownHost( e, client->GetTrustFile() );

	int mismatch = e->CheckId( MsgRpc::HostKeyMismatch );
	int unknown = e->CheckId( MsgRpc::HostKeyUnknown );

	if( iflag )
	{
	    if( unknown )
	    {
		ReportPeerKey( client, &peername, &fingerprint );
		e->Clear();
	    }
	    else if( e->Test() )
	    {
		client->GetUi()->Message( e );
		e->Clear();
	    }

	    InstallTrust( client, peer, u, *opts[ 'i' ], e );
	    if( !e->Test() )
	    {
		StrBuf done;
		done.Set( "Added trust for P4PORT " );
		done.Append( &peername );
		done.Append( "\n" );
	        OutputBuffer( client, done );
	    }

	    return;
	}

	if( !e->Test() )
	{
	    if( dflag )
	    {
		DeleteTrust( client, peer, u, e );
		if( !e->Test() )
		{
		    StrBuf done;
		    done.Set( "Removed trust for P4PORT " );
		    done.Append( &peername );
		    done.Append( "\n" );
		    OutputBuffer( client, done );
		}
	    }
	    else
	    {
		StrRef done( "Trust already established.\n");
	        OutputBuffer( client, done );
	    }
	    return;
	}

	// missing or wrong

	if( unknown )
	    ReportPeerKey( client, &peername, &fingerprint );
	else
	    client->GetUi()->Message( e );
	e->Clear();

	if( dflag )
	{
	    // delete it!
	    DeleteTrust( client, peer, u, e );
	    if( !e->Test() )
	    {
		StrBuf done;
		done.Set( "Removed trust for P4PORT " );
		done.Append( &peername );
		done.Append( "\n" );
	        OutputBuffer( client, done );
	    }
	    return;
	}
	if( nflag )
	{
	    client->SetError();
	    return;
	}
	if( !fflag && mismatch )
	{
	    StrRef done( "Can't trust mismatched P4PORT key without the '-f' force option.\n" ); 
	    OutputBuffer( client, done );
	    client->SetError();
	    return;
	}
	if( !yflag )
	{
	    StrBuf res;

	    client->GetUi()->Prompt( StrRef( "Are you sure you want to establish trust (yes/no)? " ),
			    res, 0, e );

	    if( e->Test() || res != "y" && res != "yes" )
	    {
		client->SetError();
		return;
	    }
	}
	InstallTrust( client, peer, u, fingerprint, e );
	if( e->Test() )
	    client->SetError();
	else
	{
	    StrBuf done;
	    done.Set( "Added trust for P4PORT " );
	    done.Append( &peername );
	    done.Append( "\n" );
	    OutputBuffer( client, done );
	}
}
