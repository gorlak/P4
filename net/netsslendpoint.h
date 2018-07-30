/**
 * @file netssl.h
 *
 * @brief SSL driver for NetEndPoint (connection setup)
 *	NetSslEndPoint - a TCP subclass of NetTcpEndPoint
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

/*
 * These headers are required to be included before
 * including netsslendpoint.h
 *
 * extern "C" {	// OpenSSL
 *
 * # include "openssl/bio.h"
 * # include "openssl/ssl.h"
 * # include "openssl/err.h"
 *
 * }
 *
 * # include "netsupport.h"
 * # include "netport.h"
 * # include "netaddrinfo.h"
 * # include "netportparser.h"
 * # include "netconnect.h"
 * # include "nettcpendpoint.h"
 * # include "nettcptransport.h"
 */

#ifdef USE_SSL
class NetSslEndPoint : public NetTcpEndPoint
{

    public:
	NetSslEndPoint( Error *e )
	    : NetTcpEndPoint(e)
	    {
		serverCredentials = NULL;
	    }

	virtual ~NetSslEndPoint()
	    {
		if ( serverCredentials )
		    delete serverCredentials;
	    }

	void	    Listen( Error *e );
	void            ListenCheck( Error *e );
	NetTransport *  Connect( Error *e );
	NetTransport *  Accept( KeepAlive *, Error *e );
	virtual void    GetMyFingerprint(StrBuf &value);
	virtual void    GetExpiration( StrBuf &buf );

    private:
	/*
	 * serverCredentials only used if this is a server side
	 * NetSslEndpoint, otherwise this is NULL. Client-side
	 * credentials are NetSslTransport data members instead.
	 */
	NetSslCredentials *serverCredentials;
} ;
# endif //USE_SSL
