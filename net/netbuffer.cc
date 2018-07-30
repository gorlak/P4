/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * netbuffer.cc - buffer I/O to transport
 */

# include <stdhdrs.h>

# include <debug.h>
# include <strbuf.h>
# include <strops.h>
# include <error.h>
# include <tunable.h>

# include <zlib.h>
# include <zutil.h>
# include <msgsupp.h>

# include <keepalive.h>
# include "netportparser.h"
# include "netconnect.h"
# include "netbuffer.h"
# include "netdebug.h"
# include <msgrpc.h>

NetBuffer::NetBuffer( NetTransport *t )
{
	int size = p4tunable.Get( P4TUNE_NET_BUFSIZE );
	int rcvsize = p4tunable.Get( P4TUNE_NET_RCVBUFSIZE );

	recvBuf.BlockAlloc( rcvsize );
	sendBuf.BlockAlloc( size );

	ResetRecv();
	ResetSend();

	zin = 0;
	zout = 0;
	compressing = 0;

	transport = t;
}

NetBuffer::~NetBuffer()
{
	if( zin ) inflateEnd( zin );
	if( zout ) deflateEnd( zout );
	delete zin;
	delete zout;
	delete transport;
}

void
NetBuffer::SetBufferSizes( int recvSize, int sendSize )
{
	// Remember offsets

	int recvDone = RecvDone();
	int recvReady = RecvReady();
	int sendDone = SendDone();
	int sendReady = SendReady();

	// Note we only increase sizes.

	if( recvSize > recvBuf.Length() )
	    recvBuf.BlockAlloc( recvSize - recvBuf.Length() );

	if( sendSize > sendBuf.Length() )
	    sendBuf.BlockAlloc( sendSize - sendBuf.Length() );

	// Now fix up pointers

	ResetRecv();
	ResetSend();

	recvPtr 	+= recvDone;
	ioPtrs.recvPtr 	+= recvDone + recvReady;
	ioPtrs.sendPtr 	+= sendDone;
	ioPtrs.sendEnd 	+= sendDone + sendReady;
}

void
NetBuffer::ResizeBuffer()
{
	// Try packing first, if we succeed don't bother resizing just yet

	if( RecvDone() )
	{
	    PackRecv();
	    return;
	}

	if( !p4tunable.Get( P4TUNE_NET_AUTOTUNE ) )
	    return;

	if( RecvRoom() > p4tunable.Get( P4TUNE_NET_RCVBUFLOWMARK ) )
	    return;

	int growSize  = p4tunable.Get( P4TUNE_NET_RCVBUFSIZE );
	int maxSize   = p4tunable.Get( P4TUNE_NET_RCVBUFMAXSIZE );

	if( ( recvBuf.Length() + growSize ) > maxSize )
	    growSize = maxSize - recvBuf.Length();

	if( growSize < 1 )
	    return;

	// Remember offsets
	int recvDone = RecvDone();
	int recvReady = RecvReady();

	// Increase buffer size
	recvBuf.BlockAlloc( growSize );

	// Fix up pointers
	ResetRecv();
	recvPtr += recvDone;
	ioPtrs.recvPtr  += recvDone + recvReady;

	if( DEBUG_INFO )
	    p4debug.printf( "NetBuffer grow to %d\n", recvBuf.Length() );
}

void
NetBuffer::SendCompression( Error *e )
{
	// Sanity!
	// Don't let it be turned on twice.

	if( zout )
	    return;

	DEBUGPRINT( DEBUG_TRANS, "NetBuffer send compressing" );

	// create z_stream and init

	zout = new z_stream;
	zout->zalloc = (alloc_func)0;
	zout->zfree = (free_func)0;
	zout->opaque = (voidpf)0;

	if( deflateInit2(
		zout,
		Z_DEFAULT_COMPRESSION,
		Z_DEFLATED,
		-MAX_WBITS,		// - to suppress zlib header!
		DEF_MEM_LEVEL, 0 ) 
		!= Z_OK )
	{
	    e->Set( MsgSupp::DeflateInit );
	}
}

void
NetBuffer::RecvCompression( Error *e )
{
	// Sanity!
	// Don't let it be turned on twice.

	if( zin )
	    return;

	DEBUGPRINT( DEBUG_TRANS, "NetBuffer recv compressing"  );

	// create z_stream and init

	zin = new z_stream;
	zin->zalloc = (alloc_func)0;
	zin->zfree = (free_func)0;
	zin->opaque = (voidpf)0;

	if( inflateInit2( zin, -DEF_WBITS ) != Z_OK )
	    e->Set( MsgSupp::InflateInit );
}

int
NetBuffer::Receive( char *buffer, int length, Error *e )
{
	return Receive( buffer, length, e, e );
}

int
NetBuffer::Receive( char *buffer, int length, Error *re, Error *se )
{
	/*
	 * Receive buffering:
	 *	If we can receive without buffering, do so, otherwise...
	 *	If recvBuf is empty, fill it
	 *	Fill user buffer from recvBuf
	 */

	char *buf = buffer;
	int len = length;

	while( len )
	{
	    int l = RecvReady();

	    // Fill user buffer if data ready

	    if( zin && l )
	    {
		// Uncompress into user buffer

		zin->next_out = (unsigned char *)buf;
		zin->avail_out = len;
		zin->next_in = (unsigned char*)recvPtr;
		zin->avail_in = l;

		int err = inflate( zin, Z_NO_FLUSH );

		recvPtr = (char *)zin->next_in;
		buf = (char *)zin->next_out;
		len = zin->avail_out;

		if( err == Z_STREAM_END )
		    break;
		else if( err == Z_OK )
		    continue;

		re->Set( MsgSupp::Inflate );
		return 0;
	    }
	    else if( l )
	    {
		// Copy into user buffer

		if( l > len ) l = len;
		memcpy( buf, recvPtr, l );
		recvPtr += l;
		len -= l;
		buf += l;
		continue;
	    }

	    // Nothing ready in receive buffer: we're going to read.

	    // If we can receive without buffering, do so. Since we set the
	    // ioPtrs to point outside our buffer space, we must be sure to
	    // reset them.

	    if( !zin && len >= recvBuf.Length() )
	    {
		// Must set (and then reset) for special purpose
		// Limit it to recvBuf chunks.
		// OS/2 can't handle large read/write.

		ioPtrs.recvPtr = buf;
		ioPtrs.recvEnd = buf + recvBuf.Length();

		// Flush & read

		if( !transport->SendOrReceive( ioPtrs, se, re ) )
		{
		    ResetRecv();
		    return 0;
		}

		l = ioPtrs.recvPtr - buf;
		len -= l,
		buf += l;

		ResetRecv();
		continue;
	    }

	    // If compressing, we'll need to flush that separately.
	    // If that produces readable data, don't need another read.

	    if( zout )
	    {
		Flush( re, se );
		if( RecvReady() )
		    continue;
	    }

	    // Read into our buffer.

	    ResetRecv();

	    if( !transport->SendOrReceive( ioPtrs, se, re ) )
		return 0;
	}

	if( DEBUG_BUFFER )
	{
	    p4debug.printf( "NetBuffer rcv %d: ", length );
	    StrOps::Dump( StrRef( buffer, length ) );
	}

	return length;
}

void
NetBuffer::Send( const char *buffer, int length, Error *e )
{
	Send( buffer, length, e, e );
}

void
NetBuffer::Send( const char *buffer, int length, Error *re, Error *se )
{
	if( DEBUG_BUFFER )
	{
	    p4debug.printf( "NetBuffer snd %d: ", length );
	    StrOps::Dump( StrRef( buffer, length ) );
	}

	int sendLimit = sendBuf.Length();
	if( sendLimit > p4tunable.Get( P4TUNE_NET_SENDLIMIT ) )
	    sendLimit = p4tunable.Get( P4TUNE_NET_SENDLIMIT );

	/*
	 * Send buffering:
	 *	If sendBuf is full, send it
	 *	If we can send without buffering, do so
	 *	Otherwise, buffer what we can
	 *	loop
	 */

	while( length )
	{
	    // If we can send without buffering, do so. Since we set the ioPtrs
	    // to point outside our buffer space, we must be sure to reset them.

	    if( !SendReady() && length >= sendLimit && !zout )
	    {
		ioPtrs.sendPtr = (char *)buffer;
		ioPtrs.sendEnd = (char *)buffer + length;

		ResizeBuffer();

		if( !transport->SendOrReceive( ioPtrs, se, re ) )
		{
		    ResetSend();
		    return;
		}

		int l = ioPtrs.sendPtr - buffer;
		buffer += l;
		length -= l;

		ResetSend();
		continue;
	    }

	    //  If sendBuf is of sendable size, do it

	    if( SendReady() >= sendLimit )
	    {
		ResizeBuffer();

		if( !transport->SendOrReceive( ioPtrs, se, re ) )
		    return;

		continue;
	    }

	    // Copy what we can into our buffer
	    // If no room and less than whole sendBuf ready, move
	    // it to the beginning of the sendbuf.

	    PackSend();

	    if( zout )
	    {
		// Compress into SendRoom()

		zout->next_in = (unsigned char *)buffer;
		zout->avail_in = length;
		zout->next_out = (unsigned char *)ioPtrs.sendEnd;
		zout->avail_out = SendRoom();

		if( deflate( zout, Z_NO_FLUSH ) != Z_OK )
		{
		    se->Set( MsgSupp::Deflate );
		    return;
		}

		ioPtrs.sendEnd = (char *)zout->next_out;
		buffer = (char *)zout->next_in;
		length = zout->avail_in;
		compressing = 1;
	    }
	    else
	    {
		// buffer into SendRoom()

		int l = SendRoom();
		if( l > length ) l = length;
		memcpy( ioPtrs.sendEnd, buffer, l );
		ioPtrs.sendEnd += l;
		buffer += l;
		length -= l;
	    }
	}
}

int
NetBuffer::Fill( Error *re, Error *se )
{
	DEBUGPRINT( DEBUG_BUFFER, "NetBuffer fill" );

	ResizeBuffer();
	if( !RecvRoom() )
	    return 0;

	if( !transport->SendOrReceive( ioPtrs, se, re ) )
	    return 0;

	return 1;
}

void
NetBuffer::Flush( Error *re, Error *se )
{
	DEBUGPRINT( DEBUG_TRANS, "NetBuffer flush"  );

	while( compressing || SendReady() )
	{
	    // Anything to purge from compressor?

	    PackSend();

	    if( compressing && SendRoom() )
	    {
		// Flush compress into SendRoom()

		zout->next_in = 0;
		zout->avail_in = 0;
		zout->next_out = (unsigned char *)ioPtrs.sendEnd;
		zout->avail_out = SendRoom();

		if( deflate( zout, Z_FULL_FLUSH ) != Z_OK )
		{
		    se->Set( MsgSupp::Deflate );
		    return;
		}

		ioPtrs.sendEnd = (char *)zout->next_out;
		compressing = !SendRoom();
	    }

	    // Flush what we've got or read if available.

	    PackRecv();
	    
	    if( !transport->SendOrReceive( ioPtrs, se, re ) )
		return;
	}
}

int
NetBuffer::IsAlive()
{
	int isAlive = transport->IsAlive(); 

	// Connection has been closed by the client, remove data from
	// the receive buffer while we are at it (client may have
	// been using RunTag() which means there could be a bunch of
	// commands sitting in the buffer to execute).

	if( !isAlive )
	    ResetRecv();

	return( isAlive );
}
