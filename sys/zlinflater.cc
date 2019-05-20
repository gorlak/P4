/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include <strbuf.h>
# include <error.h>
# include <debug.h>
# include <vararray.h>
# include <strarray.h>
# include <sha1.h>
# include <filesys.h>

# include <msgos.h>

# include "zlib.h"

# include "zlinflater.h"

ZLibInflater::ZLibInflater( FileSys *f, int bsize )
{
	this->f = f;
	
	workBuf = new StrFixed( bsize );
	workEnd = workP = workBuf->Text();

	zinitDone = 0;
	zstrm = new z_stream;
}

ZLibInflater::~ZLibInflater()
{
	delete workBuf;
	if( zinitDone )
	    inflateEnd( (z_stream *)zstrm );
	delete (z_stream *)zstrm;
}

void
ZLibInflater::GetLine( StrBuf *buf, int &eof, Error *e )
{
	buf->Clear();
	for( ;; )
	{
	    unsigned char p = GetChar( eof, e );
	    if( e->Test() || eof )
	        break;
	    if( p == '\n' )
	    {
	        buf->Terminate();
	        break;
	    }
	    buf->Extend( p );
	}
}

int
ZLibInflater::Read( unsigned char *buf, int cnt, int &eof, Error *e )
{
	unsigned char *bp = buf;

	while( cnt-- > 0 )
	{
	    *bp++ = GetChar( eof, e );
	    if( eof || e->Test() )
		break;
	}

	return bp - buf;
}

ZLInflater::ZLInflater( FileSys *f, offL_t, Error *e )
    : ZLibInflater( f, 4096 )
{
	filbuf = new StrFixed( 4096 );

	unzbuf = new StrFixed( 65536 );
	unzP = unzbuf->Text();
	unzAvail = 0;
}

ZLInflater::~ZLInflater()
{
	delete filbuf;
	delete unzbuf;
}

void
ZLInflater::Seek( offL_t pos, Error *e )
{
	z_streamp zls = (z_streamp)zstrm;

	if( zinitDone )
	    inflateEnd( (z_stream *)zstrm );

	zls->zalloc = Z_NULL;
	zls->zfree  = Z_NULL;
	zls->opaque = Z_NULL;
	zls->avail_in = 0;
	zls->next_in = Z_NULL;
	zret = inflateInit( zls );
	if( zret != Z_OK )
	{
	    e->Set( MsgOs::ZlibInflateInit ) << f->Name() << StrNum( zret );
	    return;
	}
	zinitDone = 1;

	f->Seek( pos, e );
}


unsigned char
ZLInflater::GetChar2( int &eof, Error *e )
{
	eof = 0;

	if( workP >= workEnd )
	{
	    int workLen = Fill( workBuf->Text(), workBuf->Length(), e );
	    if( e->Test() )
	        return '\0';
	    if( !workLen )
	    {
	        eof = 1;
	        return '\0';
	    }
	    workP = workBuf->Text();
	    workEnd = workP + workLen;
	}
	return (unsigned char)(*workP++);
}

int
ZLInflater::ReadResults( char *buf, int len, Error *e )
{
	int result = len < unzAvail ? len : unzAvail;
	memcpy( buf, unzP, result );
	unzAvail -= result;
	if( unzAvail > 0 )
	    unzP += result;
	else
	    unzP = unzbuf->Text();
	return result;
}

int
ZLInflater::Fill( char *buf, int len, Error *e )
{
	if( unzAvail )
	    return ReadResults( buf, len, e );

	if( zret == Z_STREAM_END )
	    return 0;

	z_streamp zls = (z_streamp)zstrm;

	do {
	    if( zls->avail_in == 0 )
	    {
	        zls->next_in = (Bytef *)filbuf->Text();
	        zls->avail_in = f->Read( filbuf->Text(), filbuf->Length(), e );
	        if( e->Test() )
	            return - 1;
	        if( zls->avail_in == 0 )
	        {
	            e->Set( MsgOs::ZlibInflateEOF ) << f->Name();
	            return -1;
	        }
	    }

	    do {
	        zls->avail_out = unzbuf->Length();
		zls->next_out = (Bytef *)unzbuf->Text();

		zret = inflate( zls, Z_NO_FLUSH );
		if( zret != Z_OK && zret != Z_STREAM_END )
	        {
	            e->Set( MsgOs::ZlibInflate ) << f->Name() << StrNum( zret );
	            return -1;
	        }
		unzAvail = unzbuf->Length() - zls->avail_out;
		unzP = unzbuf->Text();
	        return ReadResults( buf, len, e );
	    } while( zls->avail_out == 0 );

	} while( zret != Z_STREAM_END );

	// NOT-REACHED

	return -1;
}

/*************************************************************************/


ZLDeflater::ZLDeflater( const StrPtr *fName )
{
	opened = 0;
	f = FileSys::Create( FST_BINARY );
	f->Set( *fName );
	zstrm = 0;
	zinitDone = 0;
	workBuf = new StrFixed( 65536 );
}

ZLDeflater::~ZLDeflater()
{
	delete workBuf;
	delete f;
	if( zinitDone )
	    deflateEnd( (z_stream *)zstrm );
	delete (z_stream *)zstrm;
}

void
ZLDeflater::Write( const char *buf, int l, Error *e )
{
	if( !opened )
	{
	    Open( e );
	    if( e->Test() )
	        return;
	}

	z_stream *zls = (z_stream *)zstrm;

	zls->avail_in = l;
	zls->next_in = (Bytef *)buf;

	int done = 0;

	while( ! done )
	{
	    zret = deflate( zls, Z_NO_FLUSH );

	    done = zls->avail_in == 0;

	    if( workBuf->Length() == zls->avail_out )
	        break;

	    f->Write( workBuf->Text(), workBuf->Length() - zls->avail_out, e );
	    if( e->Test() )
	        return;

	    zls->avail_out = workBuf->Length();
	    zls->next_out = (Bytef *)workBuf->Text();
	}
}

void
ZLDeflater::Open( Error *e )
{
	opened = 1;

	zstrm = new z_stream;

	z_stream *zls = (z_stream *)zstrm;

	zls->zalloc = Z_NULL;
	zls->zfree = Z_NULL;
	zls->opaque = Z_NULL;
	zret = deflateInit( zls, Z_DEFAULT_COMPRESSION );
	if( zret != Z_OK )
	{
	    e->Set( MsgOs::ZlibDeflateInit ) << f->Name() << StrNum( zret );
	    return;
	}
	zinitDone = 1;

	f->MkDir( e );
	if( e->Test() )
	    return;

	f->Open( FOM_WRITE, e );
	if( e->Test() )
	    return;

	zls->avail_out = workBuf->Length();
	zls->next_out = (Bytef *)workBuf->Text();
}

void	
ZLDeflater::Close( Error *e )
{
	z_stream *zls = (z_stream *)zstrm;

	zls->avail_in = 0;
	zls->next_in = Z_NULL;

	int done = 0;

	while( ! done )
	{
	    zret = deflate( zls, Z_FINISH );

	    done = zls->avail_out != 0;

	    if( workBuf->Length() == zls->avail_out )
	        break;

	    f->Write( workBuf->Text(), workBuf->Length() - zls->avail_out, e );
	    if( e->Test() )
	        return;

	    zls->avail_out = workBuf->Length();
	    zls->next_out = (Bytef *)workBuf->Text();
	}

	deflateEnd( zls );
	zinitDone = 0;
}

/*************************************************************************
 * ZLFDeflater: very similar to ZLDeflater, but uses a caller-provided   *
 *              FileSys object, which we neither open nor close, just    *
 *              write to.                                                *
 *************************************************************************/

ZLFDeflater::ZLFDeflater( FileSys *f, Sha1Digester *digester )
{
	this->f = f;
	this->digester = digester;
	zstrm = 0;
	zinitDone = 0;
	workBuf = new StrFixed( 65536 );
}

ZLFDeflater::~ZLFDeflater()
{
	delete workBuf;
	if( zinitDone )
	    deflateEnd( (z_stream *)zstrm );
	delete (z_stream *)zstrm;
}

void
ZLFDeflater::Write( const char *buf, int l, Error *e )
{
	z_stream *zls = (z_stream *)zstrm;

	zls->avail_in = l;
	zls->next_in = (Bytef *)buf;

	int done = 0;

	while( ! done )
	{
	    zret = deflate( zls, Z_NO_FLUSH );

	    done = zls->avail_in == 0;

	    StrRef block( workBuf->Text(), workBuf->Length() - zls->avail_out );
	    if( !block.Length() )
	        break;

	    if( digester )
	        digester->Update( block );

	    f->Write( block, e );
	    if( e->Test() )
	        return;

	    zls->avail_out = workBuf->Length();
	    zls->next_out = (Bytef *)workBuf->Text();
	}
}

void
ZLFDeflater::Start( Error *e )
{
	zstrm = new z_stream;

	z_stream *zls = (z_stream *)zstrm;

	zls->zalloc = Z_NULL;
	zls->zfree = Z_NULL;
	zls->opaque = Z_NULL;
	zret = deflateInit( zls, Z_DEFAULT_COMPRESSION );
	if( zret != Z_OK )
	{
	    e->Set( MsgOs::ZlibDeflateInit ) << f->Name() << StrNum( zret );
	    return;
	}
	zinitDone = 1;

	zls->avail_out = workBuf->Length();
	zls->next_out = (Bytef *)workBuf->Text();
}

void	
ZLFDeflater::Finish( Error *e )
{
	z_stream *zls = (z_stream *)zstrm;

	zls->avail_in = 0;
	zls->next_in = Z_NULL;

	int done = 0;

	while( ! done )
	{
	    zret = deflate( zls, Z_FINISH );

	    done = zls->avail_out != 0;

	    StrRef block( workBuf->Text(), workBuf->Length() - zls->avail_out );
	    if( !block.Length() )
	        break;

	    if( digester )
	        digester->Update( block );

	    f->Write( block, e );
	    if( e->Test() )
	        return;

	    zls->avail_out = workBuf->Length();
	    zls->next_out = (Bytef *)workBuf->Text();
	}

	deflateEnd( zls );
	zinitDone = 0;
}

