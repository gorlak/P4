/*
 * Copyright 1995, 2003 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * fileiouni.cc -- FileIOUnicode methods
 */

# include <stdhdrs.h>

# include <error.h>
# include <errornum.h>
# include <msgsupp.h>
# include <strbuf.h>
# include <i18napi.h>
# include <charcvt.h>
# include <debug.h>
# include <tunable.h>
# include <msgserver.h>

# include "filesys.h"
# include "fileio.h"

void
FileIOUnicode::FillBuffer( Error *e )
{
	// Fill buffer from file.

	if (trans)
	{
	    int readlen;
	    int cnt;
	    readlen = tbuf.Length() - tsz;
	    cnt = FileIOCompress::Read( tbuf.Text()+tsz, readlen, e );
	    if ( e->Test() )
		return;

	    tsz += cnt;
	    if (tsz)
	    {
		const char *ss;
		char *ts;
		ss = tbuf.Text();
		ts = iobuf.Text();
		trans->ResetErr();
		trans->Cvt(&ss, tbuf.Text()+tsz, &ts, iobuf.Text()+iobuf.Length());
		if (trans->LastErr() == CharSetCvt::NOMAPPING)
		{
		    // set an error
		    e->Set( MsgSupp::NoTrans ) << trans->LineCnt() << Name();
		    return;
		}
		else if (trans->LastErr() == CharSetCvt::PARTIALCHAR)
		{
		    if( cnt < readlen )
		    {
		        /*
		         * End of file and buffer still had room:
		         * Read() has read a smaller number of bytes than
		         * the size of the buffer that was supplied meaning
		         * it reached the end of file. But cvt() reports
		         * that the last character is partial. Since we
		         * have reached the end of file, there are no further
		         * reading to do to complete this partial character
		         * therefore report an error equivalent to the NOMapping
		         * case.
		         */
		        e->Set( MsgSupp::NoTrans ) 
		                << trans->LineCnt() << Name();
		        return;
		    }
		}
		else if (ts == iobuf.Text())
		{
		    // error
		    e->Set( MsgSupp::PartialChar );
		    return;
		}
		rcv = ts-iobuf.Text();
		tsz += tbuf.Text()-ss;
		if (tsz)
		    memmove(tbuf.Text(), ss, tsz);
	    }
	}
	else
	{
	    FileIOBuffer::FillBuffer( e );
	}

}

void
FileIOUnicode::FlushBuffer( Error *e )
{
	if (trans)
	{
	    const char *ss;
	    char *ts;
	    trans->ResetErr();
	    ss = iobuf.Text();
	    ts = tbuf.Text();
	    trans->Cvt(&ss, iobuf.Text()+snd, &ts, tbuf.Text()+iobuf.Length());
	    if (trans->LastErr() == CharSetCvt::NOMAPPING)
	    {
		// set an error
		e->Set( MsgSupp::NoTrans ) << trans->LineCnt() << Name();
		// prevent close from attempting second flush
		snd = 0;
	    }
	    else if (ts == tbuf.Text())
	    {
		// error
		e->Set( MsgSupp::PartialChar );
		// prevent close from attempting second flush
		snd = 0;
	    }
	    else
	    {
		FileIOCompress::Write( tbuf.Text(), ts-tbuf.Text(), e );
		snd += iobuf.Text()-ss;
		if (snd)
		    memmove(iobuf.Text(), ss, snd);
	    }
	}
	else
	{
	    FileIOBuffer::FlushBuffer( e );
	}
}

void
FileIOUnicode::Close( Error *e )
{
	FileIOBuffer::Close( e );

	tsz = 0;
	trans = NULL;
}

void
FileIOUnicode::Translator( CharSetCvt *c )
{
	trans = c;
	if( c )
	{
	    c->ResetCnt();
	    c->IgnoreBOM();
	}
}

FileIOUTF16::FileIOUTF16( LineType lineType )
    : FileIOUnicode( lineType )
{
	SetContentCharSetPriv( (int)CharSetApi::UTF_16_BOM );
}

void
FileIOUTF16::Set( const StrPtr &name )
{
	Set( name, 0 );
}

void
FileIOUTF16::Set( const StrPtr &name, Error *e )
{
	FileIOUnicode::Set( name, e );
	SetContentCharSetPriv( (int)CharSetApi::UTF_16_BOM );
}

void
FileIOUTF16::Open( FileOpenMode mode, Error *e )
{
	CharSetCvt *cvt;

	if( mode == FOM_READ )
	    cvt = new CharSetCvtUTF168;
	else
	    cvt = new CharSetCvtUTF816( -1, 1 );

	FileIOUnicode::Open( mode, e );

	FileIOUnicode::Translator( cvt );
}

void
FileIOUTF16::Close( Error *e )
{
	CharSetCvt *temp = trans;

	FileIOUnicode::Close( e );

	delete temp;
}

void
FileIOUTF16::Translator( CharSetCvt * )
{
}

FileIOUTF8::FileIOUTF8( LineType lineType )
    : FileIOUTF16( lineType )
{
	SetCharSetPriv();
}

void
FileIOUTF8::Set( const StrPtr &name, Error *e )
{
	FileIOUnicode::Set( name, e );

	SetCharSetPriv();
}

void
FileIOUTF8::SetCharSetPriv()
{
	int c = p4tunable.Get( P4TUNE_FILESYS_UTF8BOM );
	int f = (int)CharSetApi::UTF_8_BOM;
# ifdef OS_NT
	if( c == 0 )
	    f = (int)CharSetApi::UTF_8;
# else
	if( c != 1 ) // meaning either 0 or 2
	    f = (int)CharSetApi::UTF_8;
# endif
	SetContentCharSetPriv( f );
}

void
FileIOUTF8::Open( FileOpenMode mode, Error *e )
{
	CharSetCvt *cvt;

	if( mode == FOM_READ )
	    cvt = new CharSetCvtUTF8UTF8( -1, UTF8_VALID_CHECK );
	else
	{
	    int f = 0;
	    if( GetContentCharSetPriv() == (int)CharSetApi::UTF_8_BOM )
		f = UTF8_WRITE_BOM;
	    cvt = new CharSetCvtUTF8UTF8( 1, f );
	}

	FileIOUnicode::Open( mode, e );

	FileIOUnicode::Translator( cvt );
}
