/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include <debug.h>
# include <strbuf.h>
# include <strdict.h>
# include <error.h>
# include <vararray.h>

# include "rpc.h"
# include "rpcdispatch.h"
# include "rpcdebug.h"

RpcDispatcher::RpcDispatcher( void )
{
	dispatches = new VarArray;
}

RpcDispatcher::~RpcDispatcher( void )
{
	delete dispatches;
}

void
RpcDispatcher::Add( const RpcDispatch *dispatch )
{
	dispatches->Put( (void *)dispatch );
}

const RpcDispatch *
RpcDispatcher::Find( const char *func )
{
	for( int i = dispatches->Count(); i--; )
	{
	    const RpcDispatch *disp = (RpcDispatch *)(dispatches->Get(i));

	    // Look up function name in dispatch table.

	    while( disp->opName && strcmp( func, disp->opName ) )
		disp++;

	    if( disp->opName )
		return disp;
	}

	return 0;
}
