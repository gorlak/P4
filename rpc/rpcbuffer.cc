/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# ifdef USE_EBCDIC
# define NEED_EBCDIC
# endif

# include <stdhdrs.h>

# include <debug.h>
# include <strbuf.h>
# include <strdict.h>
# include <strarray.h>
# include <strops.h>
# include <strtable.h>
# include <error.h>
# include <p4tags.h>
# include <msgrpc.h>

# include "rpcbuffer.h"
# include "rpcdebug.h"

////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
//
// RpcRecvBuffer
//
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

void
RpcRecvBuffer::Parse( Error *e )
{
	// do the work of Clear

	args.Clear();
	syms.Clear();

	// Step through variables

	char *b = ioBuffer.Text();
	char *endB = b + ioBuffer.Length();

	while( b < endB )
	{
	    // variable, length, value

	    StrRef var( b );

	    b += var.Length() + 5;

	    int valLen = 
		(unsigned char)b[-4] * 0x1 + 
		(unsigned char)b[-3] * 0x100 +
		(unsigned char)b[-2] * 0x10000 +
		(unsigned char)b[-1] * 0x1000000;

	    StrRef val( b, valLen );

	    b += valLen + 1;

	    if( valLen < 0 || b > endB || b[-1] != '\0')
	    {
		DEBUGPRINTF( DEBUG_VARS, "Rpc Buffer parse failure %s %d!",
			var.Text(), b - endB );
		e->Set( MsgRpc::NotP4 );
		return;
	    }

# ifdef USE_EBCDIC
	    // Slog to ebcdic

	    __atoe_l( var.Text(), var.Length() );
	    __atoe_l( val.Text(), val.Length() );
# endif

	    // With var name, into symbol table
	    // No variable name, into arg list

	    if( var.Length() )
		syms.SetVar( var, val );
	    else
		args.Put( val );

	    // Tracing 

	    if( DEBUG_LOUD && val.Length() >= 110 )
	    {
		StrBuf tmp;
		StrBuf tmp2;
		// First truncate then encode non printable
		tmp.Set( val.Text(), 40 );
		StrOps::EncodeNonPrintable( tmp, tmp2 );
		tmp.Reset();
		tmp << "<truncated> " << tmp2;
		DEBUGPRINTF( DEBUG_LOUD, "RpcRecvBuffer %s %s", var.Text(),
			tmp.Text() );
	    }
	    else 
		DEBUGPRINTF( DEBUG_VARS, "RpcRecvBuffer %s = %s", var.Text(),
			val.Length() < 110 ? val.Text() : "<big>" );

	}
}

////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
//
// RpcRecvBuffer
//
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

void
RpcSendBuffer::SetVar( const StrPtr &var, const StrPtr &value )
{
	// Format on wire is:
	//
	//  var<00><l1><l2><l3><l4>value<00>
	//
	// That is, var and value are null terminated and value additionally
	// has a length indicator.  Like lengths for StrPtrs, the it
	// does not include the terminating null.
	//

	MakeVar( var )->Extend( value.Text(), value.Length() );
	EndVar();

	// Tracing 

	if( DEBUG_LOUD && value.Length() >= 110 )
	{
	    StrBuf tmp;
	    StrBuf tmp2;
	    // First truncate then encode non printable
	    tmp.Set( value.Text(), 40 );
	    StrOps::EncodeNonPrintable( tmp, tmp2 );
	    tmp.Reset();
	    tmp << "<truncated> " << tmp2;
	    DEBUGPRINTF( DEBUG_LOUD, "RpcSendBuffer %s = %s", var.Text(),
		    tmp.Text() );
	}
	else 
	    DEBUGPRINTF( DEBUG_VARS, "RpcSendBuffer %s = %s", var.Text(),
		    value.Length() < 110 ? value.Text() : "<big>" );
}

void
RpcSendBuffer::SetVar( const char *var, const StrPtr &value )
{
	StrBuf key = var;
	SetVar( key, value );
}

StrBuf *
RpcSendBuffer::MakeVar( const StrPtr &var )
{
	// Tidy up last MakeVar

	if( lastLength )
	    EndVar();

	// Put var name in buffer
	// EBCDIC->ASCII, if necessary

	ioBuffer.UAppend( &var );

# ifdef USE_EBCDIC
	__etoa_l( ioBuffer.End() - var.Length(), var.Length() );
# endif

	// Make room for var's null plus value's len
	// ensure null is null, incase this alloc relocates.

	*ioBuffer.Alloc(5) = 0;

	lastLength = ioBuffer.Length();

	return &ioBuffer;
}

void
RpcSendBuffer::EndVar()
{
	int length = ioBuffer.Length() - lastLength;
	char *lastVar = ioBuffer.Text() + lastLength;

	lastVar[-4] = ( length / 0x1 ) % 0x100;
	lastVar[-3] = ( length / 0x100 ) % 0x100;
	lastVar[-2] = ( length / 0x10000 ) % 0x100;
	lastVar[-1] = ( length / 0x1000000 ) % 0x100;

# ifdef USE_EBCDIC
	// back up and translate value to ascii
	__etoa_l( lastVar, length );
# endif

	ioBuffer.Extend( 0 );	// skip past null

	lastLength = 0;  // signal MakeVar var completed
}

void
RpcSendBuffer::CopyVars( RpcRecvBuffer *from )
{
	// XXX don't want to copy the 'func' or 'data' variables
	// should have a generic way of excluding variables from the copy.

	int i;
	StrRef var, val;

	for( i = 0; from->syms.GetVar( i, var, val ); i++ )
	{
	    if( var == P4Tag::v_data || var == P4Tag::v_func )
		continue;

	    SetVar( var, val );
	}
}
