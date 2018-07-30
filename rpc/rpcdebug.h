/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * -vrpc=1 show connection
 * -vrpc=2 show calls to invoke and dispatches
 * -vrpc=3 show variable settings in send/receive buffers
 * -vrpc=5 show flow control details 
 */

extern void DumpError( Error &e, const char *func );

// RPC debugging levels
# define DEBUG_CONNECT	( p4debug.GetLevel( DT_RPC ) >= 1 )
# define DEBUG_FUNCTION	( p4debug.GetLevel( DT_RPC ) >= 2 )
# define DEBUG_VARS	( p4debug.GetLevel( DT_RPC ) >= 3 )
# define DEBUG_FLOW	( p4debug.GetLevel( DT_RPC ) >= 5 )
# define DEBUG_LOUD	( p4debug.GetLevel( DT_RPC ) >= 9 )

// Server debugging levels
# define DEBUG_SVR_ERROR	( p4debug.GetLevel( DT_SERVER ) >= 1 )
# define DEBUG_SVR_WARN		( p4debug.GetLevel( DT_SERVER ) >= 2 )
# define DEBUG_SVR_INFO		( p4debug.GetLevel( DT_SERVER ) >= 4 )

# define RPC_DBG_PRINT( level, msg ) \
	do \
	{ \
	    if( level ) \
	    { \
		p4debug.printf( "%s" msg "\n", RpcTypeNames[GetRpcType()] ); \
	    } \
	} while(0);

# define RPC_DBG_PRINTF( level, msg, ... ) \
	do \
	{ \
	    if( level ) \
	    { \
		p4debug.printf( "%s" msg "\n", RpcTypeNames[GetRpcType()], __VA_ARGS__ ); \
	    } \
	} while(0);

