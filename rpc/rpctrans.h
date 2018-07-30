/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * rpctrans.h - buffer I/O to transport
 *
 * Description:
 *
 *	This is just a layer on NetBuffer, which provides for buffering
 *	of a raw NetTransport connection.  RpcTransport just does 
 *	encapsulation of sized data blocks, ensuring that the exact 
 *	buffer sent is recreated in the receiver.
 */

class RpcTransport : public NetBuffer {

    public:
			RpcTransport( NetTransport *t ) : NetBuffer( t ) {}

	void		Send( StrPtr *s, Error *re, Error *se );
	int		Receive( StrBuf *s, Error *re, Error *se );

	// For flow control, himark must include the few extra
	// bytes RpcTransport adds to every message.

	int		SendOverhead() { return 5; }

} ;
