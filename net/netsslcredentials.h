/**
 * @file netsslcredentials.h
 *
 * @brief Wrapper for getting or generating server cert and private key.
 *
 * Threading: underlying SSL library contains threading
 *
 * @invariants:
 *
 * Copyright (c) 2011 Perforce Software
 * Confidential.  All Rights Reserved.
 * @author Wendy Heffner
 *
 * Creation Date: October 31, 2011
 */

/*
 * These headers are required to be included before
 * including netsslcredentials.h
 *
 * extern "C" {	// OpenSSL
 *
 * # include <openssl/pem.h>
 * # include <openssl/conf.h>
 * # include <openssl/x509v3.h>
 * # ifndef OPENSSL_NO_ENGINE
 * # include <openssl/engine.h>
 * # endif
 *
 * }
 *
 */
# ifdef USE_SSL

static void Callback( int code, int arg, void *cb_arg );

class NetSslCredentials
{
public:
		NetSslCredentials( bool isTest = false );
		NetSslCredentials( NetSslCredentials &rhs);
		~NetSslCredentials();
		void ReadCredentials( Error *e );
		void GenerateCredentials( Error *e );
		void ValidateSslDir( Error * e);
		void ValidateCredentialFiles( Error *e );
		void ValidateCertDateRange( Error *e );
		void GetExpiration( StrBuf &buf );
		void HaveCredentials( Error *e );
		NetSslCredentials &operator =( NetSslCredentials &rhs );

		// Getters and Setters
		X509 *GetCertificate() const;
		const StrPtr *GetFingerprint() const;
		EVP_PKEY *GetPrivateKey() const;
		void SetCertificate(X509 *certificate, Error *e);
		void SetOwnCert(bool ownCert);
		void SetOwnKey(bool ownKey);
		void SetCertC(StrBuf &certC);
		void SetCertCN(StrBuf &certCN);
		void SetCertL(StrBuf &certL);
		void SetCertO(StrBuf &certO);
		void SetCertST(StrBuf &certSt);
		void SetSslDir(StrPtr *sslDir);
		void GetFingerprintFromCert( Error *e );

private:
		// Utilities
		void ParseConfig( Error *e );
		void WriteCredentials(  PathSys *keyFile, PathSys *certFile, Error * e );
		void GetCredentialFilepaths( PathSys *keyFile, PathSys *certFile, Error * e );
		void GetFingerprintFile( PathSys *fpFile, Error * e);
		void MakeSslCredentials( Error *e );
		void CompareFileUids( Error *e );
		void CompareDirUid( Error *e );

		EVP_PKEY *privateKey;
		X509 *certificate;
		StrBuf fingerprint;
		StrBuf certC;
		StrBuf certCN;
		StrBuf certST;
		StrBuf certL;
		StrBuf certO;
		int certEX;
		int certSV;
		int certUNITS;
		bool ownKey;
		bool ownCert;
		StrBuf sslDir;
};

# endif // USE_SSL
