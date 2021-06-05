/**
 * @file netssltransport.h
 *
 * @brief SSL driver for NetTransport (connection use and close)
 *	NetSslTransport - a TCP subclass of NetTcpTransport
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
 * including netssltransport.h
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
 * # include "nettcptransport.h"
 * # include "netsslcredentials.h"
 */

# ifdef USE_SSL

////////////////////////////////////////////////////////////////////////////
//  Class NetSslTransport                                                 //
////////////////////////////////////////////////////////////////////////////

class NetSslTransport : public NetTcpTransport
{

    public:
	NetSslTransport( int t, bool fromClient );
	NetSslTransport( int t, bool fromClient, NetSslCredentials &cred );
	~NetSslTransport();

	void            ValidateCredentials( Error *e );
	void            ClientMismatch( Error *e );
	void            DoHandshake( Error *e );
	void            Close();
	int             SendOrReceive( NetIoPtrs &io, Error *se, Error *re );
	void
	GetEncryptionType(StrBuf &value)
	    {
		    value.Set(cipherSuite);
	    }
	void    
	GetPeerFingerprint(StrBuf &value);

    private:
	SSL_CTX *	CreateAndInitializeSslContext(const char *conntype);
	void            SslClientInit( Error *e );
	void            SslServerInit( StrPtr *hostname, Error *e );
	void		ValidateRuntimeVsCompiletimeSSLVersion( Error *e );
	void            GetVersionString( StrBuf &sb, unsigned long version );

	// These two endpoint method need access to the Init methods
	friend NetTransport *NetSslEndPoint::Accept( KeepAlive *, Error *e );
	friend NetTransport *NetSslEndPoint::Connect( Error *e );



	static bool     VerifyKeyFile( const char *path );
	bool            SslHandshake( Error *e );

	static unsigned long  sCompileVersion;
	static SSL_CTX *sServerCtx;
	static SSL_CTX *sClientCtx;
	BIO *           bio;
	SSL *           ssl;
	StrBuf          cipherSuite;
	bool            clientNotSsl;
	NetSslCredentials credentials;
} ;

# endif //USE_SSL
