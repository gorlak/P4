/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * -vnet=1 show listen/connect/disconnect 
 * -vnet=2 show tcp or OS info if available 
 * -vnet=4 show details of transport operations
 * -vnet=5 show send/receive buffer contents
 *
 * -vssl=1 show listen/connect/disconnect
 * -vssl=2 show details of libssl & libcrypto function calls
 * -vssl=5 show ssl buffer status
 */

# define DEBUG_CONNECT	( p4debug.GetLevel( DT_NET ) >= 1 )
# define DEBUG_INFO	( p4debug.GetLevel( DT_NET ) >= 2 )
# define DEBUG_TRANS	( p4debug.GetLevel( DT_NET ) >= 4 )
# define DEBUG_BUFFER	( p4debug.GetLevel( DT_NET ) >= 5 )

# define SSLDEBUG_ERROR    ( p4debug.GetLevel( DT_SSL ) >= 1 )
# define SSLDEBUG_CONNECT  ( p4debug.GetLevel( DT_SSL ) >= 1 )
# define SSLDEBUG_FUNCTION ( p4debug.GetLevel( DT_SSL ) >= 2 )
# define SSLDEBUG_TRANS	   ( p4debug.GetLevel( DT_SSL ) >= 4 )
# define SSLDEBUG_BUFFER   ( p4debug.GetLevel( DT_SSL ) >= 5 )

/*
 * TRANSPORT_PRINT* are debug macros for use with both Tcp and Ssl
 * EndPoints and Transports.  The debug messages for are prepended
 * with the type of interface ("from client" or "to server").
 */
# define TRANSPORT_PRINT(level, msg) \
	do \
	{ \
	    if( level ) \
		p4debug.printf( "%s " msg "\n", isAccepted? "-> ": "<- "); \
	} while(0);

# define TRANSPORT_PRINT_VAR(level, msg) \
	do \
	{ \
	    if( level ) \
		p4debug.printf( "%s %s\n", isAccepted? "-> ": "<- ", msg ); \
	} while(0);

# define TRANSPORT_PRINTF( level, msg, ... ) \
	do \
	{ \
	    if( level ) \
		p4debug.printf( "%s " msg "\n", isAccepted? "-> ": "<- ", __VA_ARGS__ ); \
	} while(0);

