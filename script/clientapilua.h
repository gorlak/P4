/*
 * Copyright 2018 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

class ClientApiLua : public ClientApi
{
	public:

	     ClientApiLua( const void* l );
	    ~ClientApiLua();

	    void restrictAPI( const int max );

	    void fRun( const char *func, ClientUser *ui );
	    void fSetVar( const char *var, const char *value );
	    void fSetVersion( const char *v );
	    void fSetUser( const char *u );
	    void fSetPassword( const char *p );
	    void fSetPort( const char *p );
	    void fSetProg( const char *p );
	    void fSetProtocol( const char *p, const char *v );
	    void fSetClient( const char *c );
	    const char* fGetPort();
	    const char* fGetUser();
	    const char* Null() const;
	    int fInit( ErrorLua &e );
	    int fFinal();

	private:

	    const void* l;

	    int apiMax = 0;
} ;
