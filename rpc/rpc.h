/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * Rpc.h - remote procedure service
 *
 * Classes Defined:
 *
 *	Rpc - an actual Rpc association
 *	RpcService - a send/receive remote procedure service endpoint
 *
 * Public Methods:
 *
 *	RpcService::RpcService() - provide IPC address for Connect
 *	RpcService::Dispatcher() - add functions to call on received RPC
 *	RpcService::Listen() - convert RpcService from client to server
 *	RpcService::ListenCheck() - see if we can listen on the given address
 *	RpcService::CheaterCheck() - check if supplied port is the licensed one
 *	RpcService::Unlisten() - cancel Listen() (still a server, tho)
 *	RpcService::SetProtocol() - set a protocol capability
 *	RpcService::IsSingle() - is this protocol single threading?
 *	RpcService::SetBreak() - keepalive callback for user interrupt.
 *	RpcService::GetHost() - manipulate a peer address for MITM crypto
 *
 *	Rpc::Connect() - create an RPC to/from the named peer
 *	Rpc::Disconnect() - tear down RPC
 *	Rpc::GetAddress() - return address of this endpoint
 *	Rpc::GetPeerAddress() - return address of the peer
 *
 *	Rpc::MakeVar() - return StrBuf for variable contents
 *	Rpc::SetVar() - allocate variable and set contents
 *	Rpc::SetVarV() - set variable using var=value syntax
 *	Rpc::SetArgv() - copy char **argv into as variable settings
 *	Rpc::Invoke() - send buffer full of variables to peer
 *	Rpc::Release() - wrapper to call Invoke() with 'release' op
 *	
 *	Rpc::Dispatch() - dispatch uncoming RPC's until 'release' received
 *	RPC::AbortDispatch() - prematurely shut down the dispatcher
 *	Rpc::GetVar() - get a variable from receive buffer
 *	Rpc::CopyVars() - copy all variables from receive to send buffer
 *
 *	Rpc::InvokeDuplex() - Invoke(), but poll for same data sent back
 *	Rpc::InvokeDuplexRev() - Invoke(), but poll for lots of data sent back
 *	Rpc::FlushDuplex() - flush responses to all Invoke() calls
 *
 *	Rpc::Dropped() - connection is no longer serviceable
 *	Rpc::IoError() - pointer to error struct describing dropped connection
 *	Rpc::DispatchReady() - connection is servicable and has a message
 *			immediately avilable for Dispatching.
 *	Rpc::SuspendDispatch() - Block or unblock dispatch of this Rpc
 *		by the RpcMulti class
 *
 *	Rpc::StartCompression() -- initiate full link compression
 *
 * Methods for rpcservice routines:
 *
 *	Rpc::GotFlushed() - note receipt of "flush" sent by InvokeDuplex()
 *	Rpc::GotReleased() - note receipt of "release" sent by Release()
 * 	Rpc::GotRecvCompress() -- turn on recv half compression
 *	Rpc::GotSendCompress() -- turn on send half compression
 *
 * Public structures:
 *
 *	RpcDispatch - a procedure name/function call mapping
 */

# ifdef OS_NT
// On Windows, one of the OpenSSL includes in rpc.cc brings in a
// system header that includes its own <rpc.h>, so we need to
// guard against that here.
# pragma once
# endif

class Rpc;
class RpcRecvBuffer;
class RpcSendBuffer;
class RpcTransport;
class RpcDispatcher;
class NetEndPoint;
class KeepAlive;
class RpcService;
class RpcForward;
class Timer;

typedef void (*RpcCallback)( Rpc *, Error * );

struct RpcDispatch {
	const char	*opName;
	RpcCallback	function;
} ;

enum RPC_OPEN_TYPE { RPC_NOOPEN, RPC_LISTEN, RPC_CONNECT };

/*
 * NOTE: If you add a new RPC type to this list update the
 * matching string array (const char *RpcTypeNames[]) in rpc.cc
 */
enum RpcType {
    RPC_CLIENT = 0,
    RPC_REMOTE,
    RPC_PX,
    RPC_RH,
    RPC_BACKGROUND,
    RPC_PXCLIENT,
    RPC_RPL,
    RPC_BROKER,
    RPC_BROKER_TO_SERVER,
    RPC_RMTAUTH,
    RPC_SANDBOX,
    RPC_X3,
    RPC_UNKNOWN,
    RPC_DMRPC
};

extern "C" const char *RpcTypeNames[];

/*
 * These are defined here as well as in "net/netsupport.h"
 * so that rpc clients don't need to include the net dir,
 * but they need to be in net to avoid a circular dependency.
 * The two sets of definitions must remain in sync!
 * See "net/netsupport.h" for more details.
 */
# define RAF_NAME 0x01	// get symbolic name
# define RAF_PORT 0x02	// append port number

struct RpcTrack {
	int		trackable;
	P4INT64		sendCount;
	P4INT64		sendBytes;
	P4INT64		recvCount;
	P4INT64		recvBytes;
	int		rpc_hi_mark_fwd;
	int		rpc_hi_mark_rev;
	int		sendTime;
	int		recvTime;
} ;

class RpcService {

    public:
			RpcService();
			virtual ~RpcService();

	void		SetEndpoint( const char *addr, Error *e );
	void		Dispatcher( const RpcDispatch *dispatch );
	void		SetProtocol( const char *var, const StrRef &val );
	void		SetProtocolV( const char *arg );
	void		Listen( Error *e );
	void		ListenCheck( Error *e );
	int		CheaterCheck( const char *port );
	void		Unlisten();
	int		IsSingle();
	void		GetHost( StrPtr *peerAddr, StrBuf & hostBuf, Error *e );
	virtual void	GetMyFingerprint(StrBuf &value);
	void		GetExpiration( StrBuf &buf );
	const StrBuf	GetMyQualifiedP4Port( StrBuf &serverSpecAddr, Error &e ) const;
	virtual StrPtr *GetListenAddress( int raf_flags );

	// Set Protocol varieties

	void		SetProtocol( const char *var )
			{ SetProtocol( var, StrRef::Null() ); }
			
	void		SetProtocol( const char *var, const char *val )
			{ SetProtocol( var, StrRef( val ) ); }

	void		SetProtocol( const char *var, int val )
			{ SetProtocol( var, StrNum( val ) ); }

    friend class Rpc;		// needs the following privates
#ifdef USE_ZK
    friend class RpcZksClient;  // needs access to endpoint
#endif /* USE_ZK */

    private:

	RPC_OPEN_TYPE	openFlag;		// inbound or outbound

	RpcDispatcher	*dispatcher;		// incoming function dispatch
	NetEndPoint	*endPoint;		// transport's endpoint
	RpcSendBuffer	*protoSendBuffer;	// proto/values to send
} ;

class Rpc : public StrDict {

    public:
			Rpc( RpcService *s );
	virtual		~Rpc();

	void		Unlisten() { service->Unlisten(); }
	int		IsSingle() { return service->IsSingle(); }

	void		Connect( Error *e );
	void		Disconnect();
	void		DoHandshake( Error *e );
	void		CheckKnownHost( Error *e, const StrRef & trustfile );
	void    	ClientMismatch( Error *e );
	void            GetEncryptionType( StrBuf &value );
	void            GetPeerFingerprint(StrBuf &value);
	void            GetExpiration(StrBuf &value);

	bool		HasAddress();
	virtual StrPtr *GetAddress( int raf_flags );
	virtual StrPtr *GetPeerAddress( int raf_flags = 0 );
	int		GetPortNum();
	bool		IsSockIPv6();
	KeepAlive	*GetKeepAlive();
	void		SetBreak( KeepAlive *breakCallback );
	void		SetProtocolDynamic( const char *var, const StrRef &val );
	void		ClearProtocolDynamic( const char *var );

	// Invoke/Dispatch

	virtual void	Invoke( const char *opName );
	void		InvokeDuplex( const char *opName );
	void		InvokeDuplexPlus( const char *opName, int extra );
	void		InvokeDuplexRev( const char *opName );
	void		InvokeOver( const char *opName );
	void		FlushDuplex();

	void		Release();
	void		ReleaseFinal();

	enum DispatchFlag { DfComplete, DfDuplex, DfFlush, DfOver, DfContain };

	void		Dispatch( DispatchFlag f, RpcDispatcher *d );

	void		Dispatch() { 
			    Dispatch( DfComplete, service->dispatcher ); 
			}

	void		DispatchFlush() { 
			    Dispatch( DfFlush, service->dispatcher ); 
			}

	void		DispatchContain() { 
			    Dispatch( DfContain, service->dispatcher ); 
			}

	void		AbortDispatch() { endDispatch = 1; };

	// Variable setting/getting
	// The V* are virtuals of StrDict

	StrBuf *	MakeVar( const char *var );
	void		VSetVar( const StrPtr &var, const StrPtr &val );
	StrPtr *	VGetVar( const StrPtr &var );
	int		VGetVarX( int x, StrRef &var, StrRef &val );
	void		VClear();
	void		VRemoveVar( const StrPtr &var );

	virtual int	GetArgc();
	virtual StrPtr *GetArgv();
	StrPtr *	GetArgi( int i, Error *e );
	StrPtr *	GetArgi( int i );

	void		CopyVars();

	// fake out message being sent as being just received
	void		Loopback( Error * );

	// Connection is still alive in spite of send errors if we are
	// expecting acks from earlier sends (i.e. duplexing).

	int		Dropped() { 
			    return re.Test() || !duplexFrecv && se.Test(); 
			}
	int		DuplexDispatchReady( int hiMark );
	
	Error *		IoError() { return se.Test() ? &se : &re; }
	bool		ReadErrors() { return re.Test(); }
	int		SendErrors() { return se.Test(); }

	int		Active();
	int		DispatchReady();
	int		SuspendDispatch( int );
	int		PriorityDispatch( int );

	void		StartCompression( Error *e );

	void		SetHiMark( int sndbuf, int rcvbuf );

	int		protocolServer;		// 'server'/'server2' protocol

    public:

	// Not really public, but needed by the rpcservice.cc routines.

	void		GotFlushed();
	void		GotReleased() { endDispatch = 1; }
	void		GotSendCompressed( Error *e );
	void		GotRecvCompressed( Error *e );
	int		InvokeOne( const char *opName );

	void		FlushTransport();
	int		GetRecvBuffering() ;
	Error *		GetDispatchError() { return &le; }


    public:
	// for proxying

	void		SetForwarder( RpcForward *f ) { forward = f; }
	RpcForward *	GetForwarder() { return forward; }

	void		DispatchOne( RpcDispatcher *dispatcher,
			             bool passError = false );
	void		DispatchOne() { DispatchOne( service->dispatcher ); }
	int		DispatchDepth() { return dispatchDepth; }

	int		recvBuffering; // For flush1 handling in rpcfwd,pxclient

    public:
    
    	// for performance tracking

	void		TrackStart();
	int		Trackable( int level );
	void		TrackReport( int level, StrBuf &out );
	void		GetTrack( int level, RpcTrack *track );
	void		ForceGetTrack( RpcTrack *track );

	int		GetHiMarkFwd() { return rpc_hi_mark_fwd; }

	RpcType		RpcTypeIs() { return GetRpcType(); }

	int		GetInfo( StrBuf * );

    protected:

	virtual RpcType	GetRpcType() { return RPC_UNKNOWN; };

    private:

	friend class RpcForward;
	friend class RpcMulti;

	RpcService	*service;
	RpcTransport	*transport;		// send/receive transport
	RpcForward	*forward;		// for proxying

	RpcSendBuffer	*sendBuffer;		// var/values to send
	RpcRecvBuffer	*recvBuffer;		// var/values received 
	StrDict		*protoDynamic;

	int		duplexFsend;		// bytes InvokeDuplex sent
	int		duplexFrecv;		// and data received back...
	int		duplexRsend;		// bytes InvokeDuplexRev sent 
	int		duplexRrecv;		// and data received back...

	int		dispatchDepth;		// count nested calls
	int		endDispatch;		// cause Dispatch() to return
	int		suspendDispatch;
	int		priorityDispatch;	// for file transfers to server

	int		protocolSent;		// protoSendBuffer sent

	Error		se;			// send errors
	Error		re;			// recv errors
	Error		ue;			// dispatch errors
	Error		le;			// last dispatch error

	int		rpc_lo_mark;
	int		rpc_hi_mark_fwd;	// InvokeDuplex()
	int		rpc_hi_mark_rev;	// InvokeDuplexRev()

	P4INT64		sendCount;		// performance tracking
	P4INT64		sendBytes;
	P4INT64		recvCount;
	P4INT64		recvBytes;
	int		sendTime;
	int		recvTime;

	Timer		*timer;
	KeepAlive	*keep;
} ;

enum RpcUtilityType {
	Generate_Uninitialized = 0,
	Generate_Credentials,
	Generate_Fingerprint
};

class RpcUtility
{
public:

    void Generate(RpcUtilityType type, Error *e );
};
