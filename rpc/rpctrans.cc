/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * rpctrans.cc - buffer I/O to transport
 */

# include <stdhdrs.h>

# include <debug.h>
# include <strbuf.h>
# include <strops.h>
# include <error.h>

# include <keepalive.h>
# include "netportparser.h"
# include <netconnect.h>
# include <netbuffer.h>

# include "rpctrans.h"
# include "rpcdebug.h"
# include <msgrpc.h>

void
RpcTransport::Send( StrPtr *s, Error *re, Error *se )
{
	// First write the five byte header.
	// The first byte is a checksum to act as a magic number.
	// The next four bytes are the length.

	// This was a check against 0x7fffffff, but gcc on OSF sometimes
	// didn't answer right.

	if( s->Length() >= 0x1fffffff )
	{
	    se->Set( MsgRpc::TooBig );
	    return;
	}

	unsigned char l[ 5 ];

	l[1] = ( s->Length() / 0x1 ) % 0x100;
	l[2] = ( s->Length() / 0x100 ) % 0x100;
	l[3] = ( s->Length() / 0x10000 ) % 0x100;
	l[4] = ( s->Length() / 0x1000000 ) % 0x100;
	l[0] = l[1] ^ l[2] ^ l[3] ^ l[4];

	NetBuffer::Send( (char *)l, 5, re, se );

	if( se->Test() )
	    return;

	// Now just write the data.

	NetBuffer::Send( s->Text(), s->Length(), re, se );
}

int
RpcTransport::Receive( StrBuf *s, Error *re, Error *se )
{
	// Get the five byte length header.

	unsigned char l[5];

	if( !( NetBuffer::Receive( (char *)l, 5, re, se ) ) )
	    return 0;

	if( l[0] != ( l[1] ^ l[2] ^ l[3] ^ l[4] ) )
	{
	    re->Set( MsgRpc::NotP4 );
	    return -1;
	}

	int length = 
		l[1] * 0x1 +
		l[2] * 0x100 +
		l[3] * 0x10000 +
		l[4] * 0x1000000;

	// Lengths < 11 are not enough for a func variable... bzzzz...
	if( length < 11 || length >= 0x1fffffff )
	{
	    re->Set( MsgRpc::NotP4 );
	    return -1;
	}

	// Now allocate the buffer and read the data.

	if( !( NetBuffer::Receive( s->Alloc( length ), length, re, se ) ) )
	{
	    re->Set( MsgRpc::Read );
	    return -1;
	}

	return 1;
}

