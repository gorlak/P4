/*
 * Copyright 1995, 2014 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * ClientUserNULL -- version of output that goes nowhere
 */

class ClientUserNULL : public ClientUser {

    public:
	ClientUserNULL( Error *e ) : return_error( e ) {}

	void		OutputTag( const char *tag, 
				const char *data, int length );

	virtual void	HandleError( Error *err );
	virtual void	OutputInfo( char level, const char *data );
	virtual void 	OutputError( const char *errBuf );
	virtual void 	OutputText( const char *data, int length );

    private:
	Error	*return_error;
};
