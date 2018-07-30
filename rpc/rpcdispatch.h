/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

class VarArray ;

class RpcDispatcher {
    public:

			RpcDispatcher( void );
			~RpcDispatcher( void );

	void			Add( const RpcDispatch *dispatch );
	const RpcDispatch 	*Find( const char *func );

    private:

	VarArray	*dispatches;
} ;
