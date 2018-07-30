/*
 * Copyright 1995, 2003 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include <debug.h>
# include <strbuf.h>
# include <error.h>

# include "zlib.h"
# include "zutil.h"
# include "gzip.h"
# include <msgsupp.h>

/*
 * gz_magic -- the gzip magic header, in a simple form.
 */

static const char gz_magic[] = {
	0x1f,
    static_cast<const char>(0x8b), /* C++11 needs explicit cast for char values over 128 */
	Z_DEFLATED,
	0,			/*flags*/
	0,0,0,0,		/*time*/
	0,			/*xflags*/
	0x03 			/*OS_CODE*/
} ;

#define ASCII_FLAG   0x01 /* bit 0 set: file probably ascii text */
#define HEAD_CRC     0x02 /* bit 1 set: header CRC present */
#define EXTRA_FIELD  0x04 /* bit 2 set: extra field present */
#define ORIG_NAME    0x08 /* bit 3 set: original file name present */
#define COMMENT      0x10 /* bit 4 set: file comment present */
#define RESERVED     0xE0 /* bits 5..7: reserved */

Gzip::Gzip()
{
	// this is used for both inflate & deflate

	zstream = new z_stream;
	zstream->zalloc = (alloc_func)0;
	zstream->zfree = (free_func)0;
	zstream->opaque = (voidpf)0;
	isInflate = 0;
	isDeflate = 0;
	ws = we = 0;
	is = ie = 0;
	os = oe = 0;
	state = 0;
	crc = 0;
	hflags = 0;
	hxlen = 0;
}

Gzip::~Gzip()
{
	if( isInflate ) inflateEnd( zstream );
	if( isDeflate ) deflateEnd( zstream );
	delete zstream;
}

enum GzipState { 

	GZ_INIT,

	// Compress() states

	GZC_COMPRESS,
	GZC_FLUSH,
	GZC_FINAL,
	GZC_DONE,

	// Uncompress() states

	GZU_MAGIC,
	GZU_HEADERS,
	GZU_HEADER_EXTRA,
	GZU_HEADER_EXTRA_READ,
	GZU_HEADER_STRING,
	GZU_UNCOMPRESS,
	GZU_DONE

};

int
Gzip::Compress( Error *e )
{
	int err;

	for(;;)
	{
	    /* Handle any buffer copying */

	    if( ws < we )
	    {
		// copy ws->we to os->oe

		int l = we-ws < oe-os ? we-ws : oe-os;
		memcpy( os, ws, l );
		os += l, ws += l;

		// Output full -- return to caller for more room.

		if( os == oe )
		    return 1;
	    }

	    switch( state )
	    {
	    case GZ_INIT:

		// Initialize compressor

		isDeflate = 1;
		crc = crc32(0L, Z_NULL, 0);

		if( deflateInit2(
			zstream,
			Z_DEFAULT_COMPRESSION,
			Z_DEFLATED,
			-MAX_WBITS,		// - to suppress zlib header!
			DEF_MEM_LEVEL, 0 ) 
			!= Z_OK )
		{
		    e->Set( MsgSupp::DeflateInit );
		    return 0;
		}

		// Arrange to copy out gzip header

		ws = (char *)gz_magic;
		we = ws + sizeof( gz_magic );

		state = GZC_COMPRESS;
		continue;

	    case GZC_COMPRESS:

		// Finished?

		if( !is )
		{
		    state = GZC_FLUSH;
		    continue;
		}

		// Now just wrapping deflate()

		zstream->next_in = (Bytef *)is;
		zstream->avail_in = ie - is;
		zstream->next_out = (Bytef *)os;
		zstream->avail_out = oe - os;

		if( deflate( zstream, Z_NO_FLUSH ) != Z_OK )
		{
		    e->Set( MsgSupp::Deflate );
		    return 0;
		}

		// catch up on CRC

		crc = crc32(crc, (Bytef *)is, zstream->next_in - (Bytef *)is );

		is = (char *)zstream->next_in;
		os = (char *)zstream->next_out;
		
		return 1;

	    case GZC_FLUSH:

		// flush deflater
		// even deflate(Z_FINISH) requires defined _in vars

		zstream->next_in = 0;
		zstream->avail_in = 0;
		zstream->next_out = (Bytef *)os;
		zstream->avail_out = oe - os;

		err = deflate( zstream, Z_FINISH );

		os = (char *)zstream->next_out;

		if( err == Z_OK )
		    return 1;

		if( err != Z_STREAM_END )
		{
		    e->Set( MsgSupp::Deflate );
		    return 0;
		}

		if( deflateEnd( zstream ) != Z_OK )
		{
		    e->Set( MsgSupp::DeflateEnd );
		    return 0;
		}

		state = GZC_FINAL;
		continue;

	    case GZC_FINAL:

		// Write crc & and length

		tmpbuf[0] = ( crc >> 0 ) & 0xff;
		tmpbuf[1] = ( crc >> 8 ) & 0xff;
		tmpbuf[2] = ( crc >> 16 ) & 0xff;
		tmpbuf[3] = ( crc >> 24 ) & 0xff;

		tmpbuf[4] = ( zstream->total_in >> 0 ) & 0xff;
		tmpbuf[5] = ( zstream->total_in >> 8 ) & 0xff;
		tmpbuf[6] = ( zstream->total_in >> 16 ) & 0xff;
		tmpbuf[7] = ( zstream->total_in >> 24 ) & 0xff;

		ws = tmpbuf;
		we = ws + 8;
		
		state = GZC_DONE;
		continue;

	    case GZC_DONE:

		return 0;
	    }
	}
}

int
Gzip::Uncompress( Error *e )
{
	int err;
	char *p;

	for(;;)
	{
	    /* Handle any buffer copying */

	    if( ws < we )
	    {
		// copy is->ie to ws->we

		int l = we-ws < ie-is ? we-ws : ie-is;
		memcpy( ws, is, l );
		is += l, ws += l;

		// input empty -- return to caller for more
		// This protects GZU_UNCOMPRESS which assumes EOF
		// on no input.

		if( is == ie )
		    return 1;
	    }

	    switch( state )
	    {
	    case GZ_INIT:

		// Initialize decompressor

		isInflate = 1;
		crc = crc32(0L, Z_NULL, 0);

		if( inflateInit2( zstream, -DEF_WBITS ) != Z_OK )
		{
		    e->Set( MsgSupp::InflateInit );
		    return 0;
		}

		// Fill magic header

		ws = tmpbuf;
		we = tmpbuf + sizeof( gz_magic );

		state = GZU_MAGIC;
		continue;

	    case GZU_MAGIC:

		// And the magic header

		if( memcmp( tmpbuf, gz_magic, 3 ) )
		{
		    e->Set( MsgSupp::MagicHeader );
		    return 0;
		}

		// Just in case this file was written by gzip and not by us.

		hflags = tmpbuf[3];
		state = GZU_HEADERS;
		continue;

	    case GZU_HEADERS:

		/* What headers are left to process? */
		/* Switch them off from flags as done. */

		if( hflags & EXTRA_FIELD )
		{
		    // 2 byte length + length bytes
		    hflags &= ~EXTRA_FIELD;
		    ws = tmpbuf;
		    we = tmpbuf + 2;
		    state = GZU_HEADER_EXTRA;
		    continue;
		}
		else if( hflags & ORIG_NAME )
		{
		    // null terminated string
		    hflags &= ~ORIG_NAME;
		    state = GZU_HEADER_STRING;
		    continue;
		}
		else if( hflags & COMMENT )
		{
		    // null terminated string
		    hflags &= ~COMMENT;
		    state = GZU_HEADER_STRING;
		    continue;
		}
		else if( hflags & HEAD_CRC )
		{
		    // 2 bytes
		    // back to GZU_HEADERS when done
		    hflags &= ~HEAD_CRC;
		    ws = tmpbuf;
		    we = tmpbuf + 2;
		    continue;
		}

		state = GZU_UNCOMPRESS;
		continue;

	    case GZU_HEADER_EXTRA:

		// Taken length and read that many bytes.

		hxlen = 
		    ((unsigned int)tmpbuf[0]) << 0 | 
		    ((unsigned int)tmpbuf[1]) << 8;

		state = GZU_HEADER_EXTRA_READ;
		continue;

	    case GZU_HEADER_EXTRA_READ:

		// Read hxlen bytes, then return to GZU_HEADERS

		if( ie - is < hxlen )
		{
		    hxlen -= ie - is;
		    is = ie;
		    return 1;
		}

		is += hxlen;
		state = GZU_HEADERS;
		continue;

	    case GZU_HEADER_STRING:

		// Look for a null, then return to GZU_HEADERS

		if( !( p = (char *)memchr( is, 0, ie - is ) ) )
		{
		    is = ie;
		    return 1;
		}

		is = p + 1;
		state = GZU_HEADERS;
		continue;

	    case GZU_UNCOMPRESS:

		// now just wrapping inflate()

		zstream->next_in = (Bytef *)is;
		zstream->avail_in = ie - is;
		zstream->next_out = (Bytef *)os;
		zstream->avail_out = oe - os;

	    	err = inflate( zstream, Z_NO_FLUSH );

		// catch up on CRC

		crc = crc32(crc, (Bytef *)os, zstream->next_out - (Bytef *)os );

		is = (char *)zstream->next_in;
		os = (char *)zstream->next_out;

		if( err == Z_OK )
		    return 1;

		if( err != Z_STREAM_END )
		{
		    e->Set( MsgSupp::Inflate );
		    return 0;
		}

		state = GZU_DONE;
		continue;

	    case GZU_DONE:

		return 0;
	    }
	}
}

