/*
 * Copyright 1995, 2006 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * RpcForward -- connect two RPCs together
 *
 * RpcForward dispatches from the server connection and forwards
 * data to the client connection, turning the line around and 
 * dispatching/forwarding in the opposite direction when indicated
 * by the flow control mechanism.
 *
 * Aside from mindlessly forwarding messages, RpcForward knows how
 * to set up compression (directly handling the compress1/compress2
 * messages) and manage flow control (handling the flush1/flush2
 * messages).
 *
 * Public methods:
 *
 *	RpcForward::Dispatch()
 *		Start forwarding messages between client and server.
 *		It is assumed the command (the first message) has 
 *		already been sent to the server and that it is now 
 *		time to dispatch from the server.
 *
 *	RpcForward::ForwardC2S() - forward message from client to server
 *	RpcForward::ForwardS2C() - forward message from server to client
 *
 * Private methods:
 *
 *	RpcForward::Flush1() - flow control requests from server to client
 *	RpcForward::Flush2() - flow control responses from client to server
 *	RpcForward::Compress1() - turn on compression from server to client
 *	RpcForward::Compress2() - turn on compression from client to server
 */

class RpcDispatcher;

class RpcCrypto {
    public:
	RpcCrypto();
	~RpcCrypto();

	void		S2C( Rpc * );
	void		C2S( Rpc *, Rpc * );

	void		Set( StrPtr *svr, StrPtr *ticketfile );

	int		Attacks() const { return attackCount; }

    private:
	StrBuf		serverID;
	StrBuf		cryptoToken;
	StrBuf		svrname;
	StrBuf		ticket;
	StrBuf		ticketFile;

	int		attackCount;
};

class RpcForward {

    public:
			RpcForward( Rpc *client, Rpc *server );
			~RpcForward();

	void		Dispatch();
	void		DispatchOne();
	void		ClientDispatchOne();

	static void	InvokeDict( StrDict *dict, Rpc *dst );
	void		InvokeDict2S(StrDict *dict)
			{ InvokeDict( dict, server ); }

	void		ForwardC2S() { Forward( client, server ); }
	void		ForwardS2C() { Forward( server, client ); }

	void		SetCrypto( StrPtr *svr, StrPtr *ticketfile );

	// himark reduction percentage (50% is normal and default)
	void		SetHiMarkAdjustment( int a ) { himarkadjustment = a; }

	void		CryptoS2C( Error *e );
	void		CryptoC2S( Error *e );

    public:
	// historically public

	static void     ForwardNoInvoke( Rpc *src, Rpc *dst, StrRef &func );
	static void	Forward( Rpc *src, Rpc *dst );
	static void	ForwardExcept( Rpc *src, Rpc *dst, const StrPtr &exc );

    public:
	// public for access by RpcDispatcher methods

	void		Flush1( Error *e );
	void		Flush2( Error *e );
	void		Compress1( Error *e );
	void		Compress2( Error *e );

	RpcDispatcher	*GetS2CDispatcher() const { return s2cDispatcher; }
	RpcDispatcher	*GetC2SDispatcher() const { return c2sDispatcher; }

    private:

	Rpc		*client;
	Rpc		*server;

	RpcDispatcher	*c2sDispatcher;
	RpcDispatcher	*s2cDispatcher;

	int		duplexCount;

	int		himarkadjustment;

	RpcCrypto	crypto;
};
