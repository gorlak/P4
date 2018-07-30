/**
 * @file netsslcredentials.cc
 *
 * @brief Wrapper for getting or generating server cert and private key.
 *
 * Note: this code is derived from the OpenSSL demo program selfsign.c
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

# ifdef USE_SSL

# define NEED_GETUID
# define NEED_STAT
# define NEED_ERRNO

# include <stdhdrs.h>
# include <strbuf.h>
# include <error.h>
# include <errorlog.h>
# include <enviro.h>
# include <debug.h>
# include <pathsys.h>
# include <filesys.h>
# include <fileio.h>
# include <hostenv.h>
# include <utils.h>

# include <msgrpc.h>

extern "C"
{ // OpenSSL
# include "openssl/err.h"
# include <openssl/x509v3.h>
# include <openssl/ssl.h>
# include <openssl/x509_vfy.h>
}
# include <stdio.h>
# include "netdebug.h"
# include "netsslmacros.h"
# include "netsslcredentials.h"

////////////////////////////////////////////////////////////////////////////
//  NetSslCredentials - Globals and Defines                               //
////////////////////////////////////////////////////////////////////////////
# define SSL_CONFIGFILE        (const char*)"config.txt"
# define SSL_KEYFILE           (const char*)"privatekey.txt"
# define SSL_CERTFILE          (const char*)"certificate.txt"

# define SSL_X509_NUMBITS      2048
# define SSL_X509_VERSION      3
# define SSL_X509_SERIALNUM    01
# define SSL_X509_NOTBEFORE    0
# define SSL_X509_NOTAFTER     ((long) 730 )  // expires in two years
# define SSL_X509_DAY          ((long) 60 * 60 * 24 )
# define SSL_X509_MAX_SECONDS  2147483647 /*((1 << 31) - 1) */
// Fields:
// C = ISO3166 two character country code
// ST = state or province
// L = Locality; generally means city
// O = Organization - Company Name
// OU = Organization Unit - division or unit
// CN = CommonName - entity name e.g. www.example.com
// Example Values:
// C=MY,ST=another state,L=another city,O=my company,OU=certs,
// CN=www.example.com
# define SSL_X509_C      (const char*)"US"
# define SSL_X509_ST     (const char*)"CA"
# define SSL_X509_L      (const char*)"Alameda"
# define SSL_X509_O      (const char*)"Perforce Autogen Cert"

////////////////////////////////////////////////////////////////////////////
// Static Callback Function Implementation                                //
////////////////////////////////////////////////////////////////////////////

static void
Callback( int code, int arg, void *cb_arg )
{
	if ( !SSLDEBUG_FUNCTION )
	    return;

	if( code == 0 )
	    p4debug.printf(".");
	if( code == 1 )
	    p4debug.printf("+");
	if( code == 2 )
	    p4debug.printf("*");
	if( code == 3 )
	    p4debug.printf("\n");
}

////////////////////////////////////////////////////////////////////////////
//  NetSslCredentials - Methods                                           //
////////////////////////////////////////////////////////////////////////////

NetSslCredentials::NetSslCredentials(bool isTest)
  : privateKey( NULL ),
    certificate( NULL ),
    fingerprint(),
    certC( SSL_X509_C ),
    certCN(),
    certST( SSL_X509_ST ),
    certL( SSL_X509_L ),
    certO( SSL_X509_O )
{
	ownCert = false;
	ownKey = false;
	certEX = SSL_X509_NOTAFTER;
	certSV = SSL_X509_NOTBEFORE;
	certUNITS = SSL_X509_DAY;

	if ( !isTest )
	{
	    HostEnv h;
	    Enviro   enviro;
	    char *sslDirStr = NULL;

	    h.GetHost( certCN );

	    const StrPtr *cachedServerName = enviro.GetCachedServerName();
	    if ( cachedServerName )
	    {
		enviro.BeServer( cachedServerName );
	    }

	    sslDirStr = enviro.Get( "P4SSLDIR" );
	    if ( sslDirStr && sslDirStr[0] != '\0' )
	    {
		sslDir = sslDirStr;
	    }
	}
	else
	{
	    sslDir.Set("/tmp/4kssldir");
	    certCN.Set("TestHost");
	}
}

NetSslCredentials::NetSslCredentials( NetSslCredentials &rhs)
  : privateKey (rhs.privateKey),
    certificate(rhs.certificate),
    fingerprint(rhs.fingerprint),
    certC(rhs.certC),
    certCN(rhs.certCN),
    certST(rhs.certST),
    certL(rhs.certL),
    certO(rhs.certO),
    certEX(rhs.certEX),
    ownKey(false),
    ownCert(false),
    sslDir(rhs.sslDir)
{
}

NetSslCredentials::~NetSslCredentials()
{
	if ( privateKey && ownKey )
	    EVP_PKEY_free( privateKey );

	if ( certificate && ownCert )
	    X509_free( certificate );
}

NetSslCredentials &
NetSslCredentials::operator =( NetSslCredentials &rhs )
{
	privateKey = rhs.privateKey;
	certificate = rhs.certificate;
	fingerprint = rhs.fingerprint;
	certC = rhs.certC;
	certCN = rhs.certCN;
	certST = rhs.certST;
	certL = rhs.certL;
	certO = rhs.certO;
	certEX = rhs.certEX;
	ownKey = false;
	ownCert = false;
	sslDir = rhs.sslDir;
	return *this;
}

void
NetSslCredentials::HaveCredentials( Error *e )
{
	if( !privateKey || !certificate || (fingerprint.Length() == 0) )
	    e->Set(MsgRpc::SslNoCredentials);
}

void
NetSslCredentials::ReadCredentials(  Error *e )
{
	FILE *fp = NULL;
	PathSys *keyFile = PathSys::Create();
	PathSys *certFile = PathSys::Create();

	GetCredentialFilepaths( keyFile, certFile, e);

	// Validate that P4SSLDIR exists and is a directory
	ValidateSslDir( e );
	P4CHECKERROR( e, "NetSslCredentials::ReadCredentials ValidateSslDir", fail );
	ValidateCredentialFiles( e );
	P4CHECKERROR( e, "NetSslCredentials::ReadCredentials ValidateCredentialFiles", fail );

	// read in private key
	fp = fopen( keyFile->Text(), "r" );
	if( fp == NULL ) {
	    e->Net( "fopen", strerror(errno) );
	    goto failSetError;
	}
	privateKey = PEM_read_PrivateKey(fp, NULL, 0, NULL );
	SSLNULLHANDLER( privateKey, e, "NetSslCredentials::ReadCredentials PEM_read_PrivateKey", failSetError );
	// verify that RSA key
	if (privateKey->type != EVP_PKEY_RSA)
	{
	    e->Set( MsgRpc::SslKeyNotRSA );
	    goto fail;
	}
	fclose( fp );

	// read in certificate
	fp  = fopen( certFile->Text(), "r" );
	if( fp == NULL ) {
	    e->Net( "fopen", strerror(errno) );
	    goto failSetError;
	}
	certificate = PEM_read_X509(fp, NULL, 0, NULL );
	SSLNULLHANDLER( certificate, e, "NetSslCredentials::ReadCredentials PEM_read_X509", failSetError );

	ValidateCertDateRange( e );
	P4CHECKERROR( e, "NetSslCredentials::ReadCredentials ValidateCertDateRange", fail );

	ownCert = true;
	ownKey = true;

	GetFingerprintFromCert( e );
	if( e->Test() ) {
	    goto fail;
	}

	fclose( fp );
	delete keyFile;
	delete certFile;
	return;

failSetError:
	e->Set( MsgRpc::SslBadKeyFile );
fail:
	if( fp ) {
	    fclose( fp );
	}
	delete keyFile;
	delete certFile;
	return;
}

void
NetSslCredentials::GenerateCredentials( Error *e  )
{
	PathSys *keyFile = PathSys::Create();
	PathSys *certFile = PathSys::Create();

	GetCredentialFilepaths( keyFile, certFile, e);
	P4CHECKERROR( e, "NetSslCredentials::GenerateCredentials GetCredentialsFiles", fail );

	ValidateSslDir( e );
	P4CHECKERROR( e, "NetSslCredentials::GenerateCredentials ValidateSslDir", fail );

	// Validate that serverKey.txt and serverCert.txt do not exist in P4SSLDIR
	if( FileSys::FileExists( keyFile->Text() ) || FileSys::FileExists( certFile->Text() ) )
	{
	    e->Set( MsgRpc::SslDirHasCreds );
	    goto fail;
	}

	ParseConfig( e );
	P4CHECKERROR( e, "NetSslCredentials::GenerateCredentials ParseConfig", fail );

	MakeSslCredentials( e );
	P4CHECKERROR( e, "NetSslCredentials::GenerateCredentials MakeSslCredentials", fail );

	WriteCredentials(  keyFile, certFile, e );
	P4CHECKERROR( e, "NetSslCredentials::GenerateCredentials WriteCredentials", fail );

	ownCert = true;
	ownKey = true;

fail:
	delete keyFile;
	delete certFile;
	return;
}

void
NetSslCredentials::ValidateSslDir( Error * e)
{

	if ( sslDir.Length() == 0 )
	{
	    e->Set( MsgRpc::SslBadDir );
	    return;
	}

	// Validate that P4SSLDIR exists and is a directory
	FileSys *f = FileSys::Create( FST_BINARY );
	f->Set( sslDir );

	if( (f->Stat() & (FSF_EXISTS | FSF_DIRECTORY)) !=
		(FSF_EXISTS | FSF_DIRECTORY) )
	{
	    e->Set( MsgRpc::SslBadDir );
	    goto fail;
	}

	// Validate that P4SSLDIR permission is 700 or 500
	if( (! f->HasOnlyPerm( FPM_RWXO )) && (! f->HasOnlyPerm( FPM_RXO )) )
	{
	    e->Set( MsgRpc::SslBadFsSecurity );
	    goto fail;
	}

	// Validate that dir is owned by same owner as p4d
	CompareDirUid( e );
	P4CHECKERROR( e, "NetSslCredentials::ValidateSslDir CompareDirUid", fail );

fail:
	delete f;
	return;
}


void
NetSslCredentials::ValidateCredentialFiles( Error *e )
{
	FileSys *f = NULL;
	PathSys *keyFile = PathSys::Create();
	PathSys *certFile = PathSys::Create();

	GetCredentialFilepaths( keyFile, certFile, e);
	if( e->Test() )
	    goto fail;

	// Validate that serverKey.txt and serverCert.txt exist in P4SSLDIR
	if( !( FileSys::FileExists( keyFile->Text() ) && FileSys::FileExists( certFile->Text() )))
	{
	    e->Set( MsgRpc::SslBadKeyFile );
	    goto fail;
	}

	// Validate that files are owned by same owner as p4d
	CompareFileUids( e );
	P4CHECKERROR( e, "NetSslCredentials::ValidateCredentialFiles CompareFileUids", fail );

	// Validate that serverKey.txt and serverCert.txt permissions are 600 or 400
	f = FileSys::Create( FST_BINARY );
	f->Set( keyFile->Text() );
	if( (! f->HasOnlyPerm( FPM_RWO )) && (! f->HasOnlyPerm( FPM_ROO )) )
	{
	    e->Set( MsgRpc::SslBadFsSecurity );
	    goto fail;
	}
	f->Set( certFile->Text() );
	if( ! f->HasOnlyPerm( FPM_RWO ) && ! f->HasOnlyPerm( FPM_ROO ) )
	{
	    e->Set( MsgRpc::SslBadFsSecurity );
	    goto fail;
	}

fail:
	if( f )
	    delete f;
	delete keyFile;
	delete certFile;
	return;
}

void
NetSslCredentials::ValidateCertDateRange( Error *e )
{
	time_t *ptime = NULL;
	int i;

	i=X509_cmp_time(X509_get_notBefore(certificate), ptime);
	if (i >= 0)
	    goto fail;

	i=X509_cmp_time(X509_get_notAfter(certificate), ptime);
	if (i <= 0)
	    goto fail;

	return;

fail:
	e->Set( MsgRpc::SslCertBadDates );
}

void
NetSslCredentials::GetExpiration( StrBuf &buf )
{
	Error e;
	if( !certificate ) {
	    buf.Clear();
	    return;
	}

	BUF_MEM *bufMemPtr = NULL;
	int retVal = 0;

	BIO *bio = BIO_new( BIO_s_mem() );
	SSLNULLHANDLER( bio, &e, "NetSslCredentials::GetExpiration BIO_new", fail );

	retVal = ASN1_TIME_print(bio,X509_get_notAfter(certificate));
	SSLHANDLEFAIL( retVal, &e, "NetSslCredentials::GetExpiration BIO_get_mem_ptr",
		MsgRpc::SslFailGetExpire,
		failCleanBIO );

	retVal = BIO_get_mem_ptr( bio, &bufMemPtr );
	SSLHANDLEFAIL( retVal, &e, "NetSslCredentials::GetExpiration BIO_get_mem_ptr",
	    MsgRpc::SslFailGetExpire,
	    failCleanBIO );


	buf.Set( bufMemPtr->data, bufMemPtr->length );
	buf.Terminate();
	BIO_free_all( bio );
	return;

failCleanBIO:
	BIO_free_all( bio );

fail:
	buf.Clear();
	return;
}


void
NetSslCredentials::ParseConfig( Error *e )
{
	StrBuf line, var, value;
	StrRef configFile( SSL_CONFIGFILE );
	SmartPointer <PathSys> p( PathSys::Create() );
	FileSys *f = FileSys::Create( FileSysType( FST_TEXT|FST_L_CRLF ) );

	// Create full pathname to certificate config file
	p->SetLocal( sslDir, configFile );
	f->Set( *p );
	f->Open( FOM_READ, e );

	// If file doesn't exist then keep defaults and just return
	if( e->Test() )
	{
	    DEBUGPRINT( SSLDEBUG_FUNCTION, "NetSslCredentials::ParseConfig - config.txt file not found in P4SSLDIR." );
	    e->Clear();
	    delete f;
	    return;
	}

	while( f->ReadLine( &line, e ) )
	{
	    line.TruncateBlanks();

	    char *equals = strchr( line.Text(), '=' );
	    if( !equals ) continue;

	    var.Set( line.Text(), equals - line.Text() );
	    var.TrimBlanks();

	    if(  var.Text()[0] == '#' )  continue;

	    value.Set( equals + 1 );
	    value.TrimBlanks();

	    DEBUGPRINTF( SSLDEBUG_FUNCTION,
		    "NetSslCredentials::ParseConfig name=%s, value=%s", var.Text(), value.Text() );

	    if ( var == "C")
	    	certC = value;
	    else if ( var == "CN")
	    	certCN = value;
	    else if ( var == "ST")
	    	certST = value;
	    else if ( var == "L")
	    	certL = value;
	    else if ( var == "O")
	    	certO = value;
	    else if ( var == "EX")
	    {
		int expire = StrBuf::Atoi(value.Text());
		if( expire > 0 )
		{
		    certEX = expire;
		}
		else
		{
		    e->Set( MsgRpc::SslCfgExpire ) << value;
	            f->Close( e );
	            delete f;
		    return;
		}
	    }
	    else if ( var == "SV")
	    {
		int start = StrBuf::Atoi(value.Text());
		certSV = start;
	    }
	    else if ( var == "UNITS")
		if( value == "secs" )
		{
		    certUNITS = 1;
		}
		else if ( value == "mins")
		{
		    certUNITS = 60;
		}
		else if ( value == "hours")
		{
		    certUNITS = 3600;
		} else if ( value == "days")
		    ; // do nothing
		else
		{
		    e->Set( MsgRpc::SslCfgUnits ) << value;
	            f->Close( e );
	            delete f;
		    return;
		}
	    else
	    {
		DEBUGPRINTF( SSLDEBUG_ERROR,
			"Certificate configuration file option \"%s\" unknown.", var.Text() );
	    }
	}
	if( (SSL_X509_MAX_SECONDS / certUNITS) < certEX ) {
	    e->Set( MsgRpc::SslCfgExpire ) << value;
	    f->Close( e );
	    delete f;
	    return;
	}

	f->Close( e );
	delete f;
}

void
NetSslCredentials::WriteCredentials(  PathSys *keyFile, PathSys *certFile, Error * e )
{
	FILE *fp = NULL;
	int retVal = 0;
	FileSys *fsKey = FileSys::Create( FST_TEXT );
	FileSys *fsCert = FileSys::Create( FST_TEXT );

	// write out in private key
	fp = fopen( keyFile->Text(), "w" );
	if( fp == NULL ) {
	    e->Net( "fopen", strerror(errno) );
	    goto fail;
	}
	retVal = PEM_write_PrivateKey(fp, privateKey, NULL, NULL, 0, 0, NULL );
	SSLHANDLEFAIL( retVal, e, "NetSslCredentials::WriteCredentials PEM_write_PrivateKey", MsgRpc::SslCertGen, fail );
	fclose( fp );
	fsKey->Set(*keyFile);
	fsKey->Chmod(FPM_RWO, e);

	// read in certificate
	fp  = fopen( certFile->Text(), "w" );
	if( fp == NULL )
	{
	    e->Net( "fopen", strerror(errno) );
	    e->Set( MsgRpc::SslCertGen );
	    goto fail;
	}
	retVal = PEM_write_X509(fp, certificate );
	SSLHANDLEFAIL( retVal, e, "NetSslCredentials::WriteCredentials PEM_write_X509", MsgRpc::SslCertGen, fail );
	fclose( fp );
	fp = NULL;
	fsCert->Set(*certFile);
	fsCert->Chmod(FPM_RWO, e);

fail:
	if( fp )
	    fclose( fp );
	delete fsKey;
	delete fsCert;
	return;
}
void
NetSslCredentials::CompareFileUids( Error *e )
{
# ifdef HAVE_GETUID
	uid_t keyOwner = 0;
	uid_t certOwner = 0;
	uid_t dirOwner = 0;
	uid_t currUsr = geteuid();
	PathSys *keyFile = PathSys::Create();
	PathSys *certFile = PathSys::Create();
	FileSys *f = FileSys::Create( FST_BINARY );

	GetCredentialFilepaths( keyFile, certFile, e);
	P4CHECKERROR( e, "NetSslCredentials::CompareUids GetCredentialsFiles", fail );

	f->Set( keyFile->Text() );
	keyOwner = f->GetOwner();
	if( currUsr != keyOwner )
	{
	    e->Set( MsgRpc::SslCredsBadOwner );
	    goto fail;
	}

	f->Set( certFile->Text() );
	certOwner = f->GetOwner();
	if( currUsr != certOwner )
	{
	    e->Set( MsgRpc::SslCredsBadOwner );
	    goto fail;
	}

	f->Set( sslDir );
	dirOwner = f->GetOwner();
	if( currUsr != dirOwner )
	    e->Set( MsgRpc::SslCredsBadOwner );

fail:
	delete f;
	delete keyFile;
	delete certFile;
	return;

# endif // HAVE_GETUID
}

void
NetSslCredentials::CompareDirUid( Error *e )
{
# ifdef HAVE_GETUID

	uid_t dirOwner = 0;
	uid_t currUsr = geteuid();
	FileSys *f = FileSys::Create( FST_BINARY );

	f->Set( sslDir );
	dirOwner = f->GetOwner();
	if( currUsr != dirOwner )
	    e->Set( MsgRpc::SslCredsBadOwner );
	delete f;

# endif // HAVE_GETUID
}

void
NetSslCredentials::GetCredentialFilepaths( PathSys *keyFile, PathSys *certFile, Error * e )
{
	StrRef certFilename( SSL_CERTFILE );
	StrRef keyFilename( SSL_KEYFILE );

	keyFile->SetLocal(sslDir, keyFilename );
	certFile->SetLocal(sslDir, certFilename );
}


void
NetSslCredentials::MakeSslCredentials( Error *e )
{
	if ( privateKey && certificate )
	{
	    return;
	}

	RSA *      rsa = NULL;
	X509_NAME *name = NULL;
	int        retval;

	if( ( privateKey = EVP_PKEY_new()) == NULL )
	{
	    e->Net( "EVP_PKEY_new", "failed" );
	    e->Set( MsgRpc::SslCertGen );
	    goto fail;
	}

	certificate = X509_new();
	SSLHANDLEFAIL( certificate, e, "X509_new", MsgRpc::SslCertGen, fail );

	rsa = RSA_generate_key( SSL_X509_NUMBITS, RSA_F4, Callback, NULL );
	SSLHANDLEFAIL( rsa, e, "RSA_generate_key", MsgRpc::SslCertGen, fail );
	retval = EVP_PKEY_assign_RSA( privateKey, rsa );
	SSLHANDLEFAIL( retval, e, "EVP_PKEY_assign_RSA", MsgRpc::SslCertGen, fail );

	X509_set_version( certificate, SSL_X509_VERSION );
	ASN1_INTEGER_set( X509_get_serialNumber( certificate ), SSL_X509_SERIALNUM );
	X509_gmtime_adj( X509_get_notBefore( certificate ), certSV * SSL_X509_DAY );
	X509_gmtime_adj( X509_get_notAfter( certificate ), certEX * certUNITS );
	X509_set_pubkey( certificate, privateKey );

	name = X509_get_subject_name( certificate );
	retval =
	    X509_NAME_add_entry_by_txt( name, "C", MBSTRING_ASC, (unsigned char*)certC.Text(),
					-1,
					-1,
					0 );

	SSLHANDLEFAIL( retval, e, "X509_NAME_add_entry_by_txt for \"C\"",
		       MsgRpc::SslCertGen,
		       fail );

	retval = X509_NAME_add_entry_by_txt( name, "ST", MBSTRING_ASC, (unsigned char*)certST.Text(),
					     -1, -1,
					     0 );
	SSLHANDLEFAIL( retval, e, "X509_NAME_add_entry_by_txt for \"ST\"",
		       MsgRpc::SslCertGen,
		       fail );
	retval =
	    X509_NAME_add_entry_by_txt( name, "L", MBSTRING_ASC, (unsigned char*)certL.Text(),
					-1,
					-1,
					0 );

	SSLHANDLEFAIL( retval, e, "X509_NAME_add_entry_by_txt for \"L\"",
		       MsgRpc::SslCertGen,
		       fail );
	retval =
	    X509_NAME_add_entry_by_txt( name, "O", MBSTRING_ASC, (unsigned char*)certO.Text(),
					-1,
					-1,
					0 );

	SSLHANDLEFAIL( retval, e, "X509_NAME_add_entry_by_txt for \"O\"",
		       MsgRpc::SslCertGen,
		       fail );

	DEBUGPRINTF( SSLDEBUG_FUNCTION, "Setting CN to Hostname: %s", certCN.Text())
	    retval =
	    X509_NAME_add_entry_by_txt( name, "CN", MBSTRING_ASC, (unsigned char*)certCN.Text(),
					-1, -1,
					0 );
	SSLHANDLEFAIL( retval, e, "X509_NAME_add_entry_by_txt for \"CN\": ",
		       MsgRpc::SslCertGen,
		       fail );

	/* Its self signed so set the issuer name to be the same as the
	 * subject.
	 */
	X509_set_issuer_name( certificate, name );

	if( !X509_sign( certificate, privateKey, EVP_sha1() ) )
	{
	    e->Net( "EVP_PKEY_new", "failed" );
	    e->Set( MsgRpc::SslCertGen );
	    goto fail;
	}

	return;

fail:

	if (certificate)
	{
	    X509_free( certificate );
	    certificate = NULL;
	}
	if (privateKey)
	{
	    EVP_PKEY_free( privateKey );
	    privateKey = NULL;
	}

}

void
NetSslCredentials::GetFingerprintFromCert( Error *e )
{
	int retval = 1;
	int i = 0;
	unsigned int n = 0;
	BIO *bio = NULL;
	BUF_MEM *bufMemPtr = NULL;
	unsigned char *asn1pubKey = NULL;
	unsigned char md[EVP_MAX_MD_SIZE];
	const EVP_MD *fdig = EVP_sha1();
	unsigned char *ptr = NULL;
	unsigned int len;

	if( !certificate )
	{
	    e->Set( MsgRpc::SslNoCredentials );
	    return;
	}

	bio = BIO_new(BIO_s_mem());
	SSLNULLHANDLER( bio, e, "GetFingerprintFromCert BIO_new", fail );

	len = i2d_X509_PUBKEY( X509_get_X509_PUBKEY( certificate ), NULL );
	if( (len == 0) || (len > 20480) ) // 20KB should be enough for anyone
	{
	    SSLHANDLEFAIL( false, e, "GetFingerprintFromCert cert zero or too big",
		MsgRpc::SslGetPubKey,
		failCleanBIO );
	}

	ptr = asn1pubKey = new unsigned char[len];
	if( !ptr )
	{
	    SSLHANDLEFAIL( false, e, "GetFingerprintFromCert new asn1pubKey",
		MsgRpc::SslGetPubKey,
		failCleanBIO );
	}

	i2d_X509_PUBKEY( X509_get_X509_PUBKEY( certificate ), &ptr );
	if( ptr - asn1pubKey != len )
	{
	    SSLHANDLEFAIL( false, e, "GetFingerprintFromCert OVERRUN",
		MsgRpc::SslGetPubKey,
		failCleanBIO );
	}
	EVP_Digest( asn1pubKey, len, md, &n, fdig, NULL );

	DEBUGPRINTF( SSLDEBUG_FUNCTION, "pubkey len is: %d", len );
	DEBUGPRINTF( SSLDEBUG_FUNCTION, "digest len is: %u", n );

	n--;  // loop through all but last one
	for (i=0; i<(int)n; i++)
	{
	    BIO_printf(bio,"%02X:",md[i]);
	}
	// last one do not add a colon
	BIO_printf(bio,"%02X",md[n]);

	retval = BIO_get_mem_ptr( bio, &bufMemPtr );
	SSLHANDLEFAIL( retval, e, "GetFingerprintFromCert BIO_get_mem_ptr",
		MsgRpc::SslGetPubKey,
		failCleanBIO );

	fingerprint.Set( bufMemPtr->data, bufMemPtr->length );
	fingerprint.Terminate();
	DEBUGPRINTF( SSLDEBUG_FUNCTION, "GetFingerprintFromCert Fingerprint is: %s", fingerprint.Text() );


failCleanBIO:
	BIO_free_all(bio);
	if( asn1pubKey )
	    delete []asn1pubKey;
fail:
	/* nothing to clean up */
	return;
}

X509 *
NetSslCredentials::GetCertificate() const
{
	return certificate;
}

const StrPtr *
NetSslCredentials::GetFingerprint() const
{
	return &fingerprint;
}

EVP_PKEY *
NetSslCredentials::GetPrivateKey() const
{
	return privateKey;
}

void 
NetSslCredentials::SetCertificate( X509 *cert, Error *e )
{
	if( !cert )
	{
	    e->Set( MsgRpc::SslNoCredentials );
	    return;
	}
	this->certificate = cert;
	this->ownCert = false;
	ValidateCertDateRange( e );
	if( e->Test() )
	{
	    this->certificate = NULL;
	    return;
	}
	GetFingerprintFromCert( e );
	if( e->Test() )
	{
	    this->certificate = NULL;
	    this->fingerprint.Clear();
	    return;
	}
}

void 
NetSslCredentials::SetOwnCert( bool ownCert )
{
	this->ownCert = ownCert;
}

void 
NetSslCredentials::SetOwnKey( bool ownKey )
{
	this->ownKey = ownKey;
}

void 
NetSslCredentials::SetCertC( StrBuf &certC )
{
	this->certC = certC;
}

void 
NetSslCredentials::SetCertCN( StrBuf &certCN )
{
	this->certCN = certCN;
}

void 
NetSslCredentials::SetCertL( StrBuf &certL )
{
	this->certL = certL;
}

void 
NetSslCredentials::SetCertO( StrBuf &certO )
{
	this->certO = certO;
}

void NetSslCredentials::SetCertST( StrBuf &certST )
{
	this->certST = certST;
}

void NetSslCredentials::SetSslDir( StrPtr *sslDir )
{
	this->sslDir = *sslDir;
}


# endif // USE_SSL

