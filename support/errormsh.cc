/*
 * Copyright 2002 Perforce Software.  All rights reserved.
 */

/*
 * Errormsh.cc - Error::Marshall/UnMarshall
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <strdict.h>
# include <strtable.h>
# include <strops.h>
# include <error.h>
# include <errorpvt.h>
# include <p4tags.h>

/*
 * Error::Marshall0() - pack an Error into a StrBuf
 * Error::UnMarshall0() - unpack an Error from a StrBuf
 *
 * Marshall0() is used for 2001.2 and earlier clients, but uses a simplified
 * version of the format: 2002.1 and later servers pre-format the message, 
 * removing the argument count from the code and escaping any %'s in the 
 * resulting message.  That's because 2002.1 had much richer message format 
 * support.
 *
 * The layout of a marshalled Error is as follows.  All numbers are
 * represented as null-terminated ASCII strings:
 *
 *	<severity> 
 *	<generic code> 
 *	<error count> 
 *
 *	<error 1 code>
 *	<error 1 offset into buffer>
 *	<error 2 code>
 *	<error 2 offset into buffer>
 *	...
 *
 *	<buffer length>
 *
 *	<error 1 message, using %1 %2 etc>
 *	<error 1 arg 1>
 *	<error 1 arg 2>
 *	...
 *
 *	<error 2 message, using %1 %2 etc>
 *	<error 2 arg 1>
 *	<error 2 arg 2>
 *	...
 *	...
 */

/*
 * EscapePercents() - turn % into %% in a StrBuf (starting at an offset)
 */

void
EscapePercents( StrBuf &buf, int offset )
{
	const char *p;

	while( p = strchr( buf.Text() + offset, '%' ) )
	{
	    /* This is slow, but rare. */

	    StrBuf t;
	    t.Set( p );
	    offset = p - buf.Text() + 1;
	    buf.SetLength( offset );
	    buf.Append( &t );
	    ++offset;
	}
}

/*
 * Error::Marshall0() - pack an Error into a StrBuf
 */

void
Error::Marshall0( StrBuf &out ) const
{
	/* Pack severity, generic code, error count */

	StrOps::PackIntA( out, severity );

	if( severity == E_EMPTY )
	    return;

	StrOps::PackIntA( out, genericCode );
	StrOps::PackIntA( out, ep->errorCount );

	/* Build new buffer of error messages/args for marshalling. */
	/* Marshalled messages are expanded, with the id's arg code */
	/* zeroed and and any %'s escaped with %%. */

	int i;
	ErrorId *id;
	StrBuf tmpBuf;

	for( i = 0; id = GetId( i ); i++ )
	{
	    /* Pack code and (new) offset for message */

	    int codeNoArgs = ErrorOf( 
		id->Subsystem(), id->UniqueCode(),
		id->Severity(), id->Generic(),
		0 /* no args */ );

	    int length = tmpBuf.Length();

	    StrOps::PackIntA( out, codeNoArgs );
	    StrOps::PackIntA( out, length );

	    /* Marshall expanded message. */
	    /* If there's a % (rare case), go back and %% escape it */
	    /* A null separates messages */

	    StrOps::Expand2( tmpBuf, StrRef( id->fmt ), *ep->whichDict ); 
	    EscapePercents( tmpBuf, length );
	    tmpBuf.Extend(0);
	}

	/* Finally, pack the rebuilt messages/parms */

	StrOps::PackStringA( out, tmpBuf );
}

/*
 * Error::UnMarshall0() - unpack an Error from a StrBuf
 *
 * This currently uses no private knowledge of the Error class, other
 * than the temp ErrorPrivate::marshall (for the marshalled messages
 * and params).
 *
 * This expands inline the %x variables of old, so that the resulting
 * Error has only messages without parameters.
 *
 * We don't give a hoot about the original per-item codes; we just
 * doctor up new ones using the global severity/generic.
 *
 * Resulting data is local:
 *
 *	whichDict is ErrorPrivate::errorDict
 *	ids[].fmt in ErrorPrivate::fmtbuf 
 */

void
Error::UnMarshall0( const StrPtr &inp )
{
	if( !ep ) ep = new ErrorPrivate;

	Clear();
	ep->Clear();

	/* We use private dictionary and share the fmts */

	ep->fmtSource = ErrorPrivate::isFmtBuf;

	/* Unpack severity, generic code, error count */
	/* Note these locals override Error class' */

	StrRef in = inp;

	int severity = StrOps::UnpackIntA( in );

	if( (ErrorSeverity)severity == E_EMPTY )
	    return;

	int generic = StrOps::UnpackIntA( in );		
	int count = StrOps::UnpackIntA( in );	

	/* Pass 1.  Unpack code, offset for each error */

	int i;
	int offsets[ ErrorMax ];

	for( i = 0; i < count; i++ )
	{
	    (void)StrOps::UnpackIntA( in );
	    offsets[i] = StrOps::UnpackIntA( in );
	}

	/* Unpack marshall format messages and params */

	StrBuf tmpBuf;
	StrOps::UnpackStringA( in, tmpBuf );

	/* Pass 2. Format each message from tmpBuf into ep->marshall */
	/* expanding the %x params so the resulting fmts have no */
	/* parameters. */

	ep->fmtbuf.Clear();

	for( i = 0; i < count; i++ )
	{
	    // Expand message, expanding args.

	    char *p = tmpBuf.Text() + offsets[ i ];
	    char *a = p + strlen( p ) + 1;
	    char *q;

	    // reusing offsets here: now it's into marshall buffer.

	    offsets[i] = ep->fmtbuf.Length();

	    while( a <= tmpBuf.End() && ( q = strchr( p, '%' ) ) )
	    {
		if( q[1] == '%' )
		{
		    // %% -- append %
		    ep->fmtbuf.Append( p, q + 1 - p );
		} 
		else 
		{
		    // %x
		    int l = strlen( a );
		    ep->fmtbuf.Append( p, q - p );
		    ep->fmtbuf.Append( a, l );
		    a += l + 1;
		}

		p = q + 2;
	    }

	    /* Save remainder of fmt after last %. */
	    /* If there's a % (rare case), go back and %% escape it */
	    /* A null separates messages */

	    ep->fmtbuf.Append( p );
	    EscapePercents( ep->fmtbuf, offsets[i] );
	    ep->fmtbuf.Extend(0);
	}

	/* Pass 3.  Set each error message. */

	for( i = 0; i < count; i++ )
	{
	    ErrorId id;

	    id.code = ErrorOf( 0, 0, severity, generic, 0 );
	    id.fmt = ep->fmtbuf.Text() + offsets[i];

	    Set( id );
	}
}

/*
 * Error::Marshall1() - copy an Error out as a StrDict
 *
 * Marshall1() is used by 2002.1 and newer client/servers, to pass
 * formattable Error and message information to the client.  The
 * StrDict is usually an Rpc one.
 *
 * This encodes an Error as a StrDict, like this:
 *
 *	code0 = code for first error
 *	fmt0 = format string for first error
 *
 *	code1 = code for second error
 *	fmt1 = format string for second error
 *
 *	.
 *	.
 *	.
 *
 *	val = var (for each parameter in the fmt strings)
 *
 * Generic, severity, and count are recalculated by UnMarshall1().
 */

void
Error::Marshall1( StrDict &out, int uniquote ) const
{
	int i;
	StrRef r, l;

	/* Copy variables */

	for( i = 0; i < ep->errorCount; i++ )
	{
	    out.SetVar( P4Tag::v_code, i, StrNum( ep->ids[i].code ) );

	    if( uniquote )
		out.SetVar( P4Tag::v_fmt, i, StrRef( ep->ids[i].fmt ) );
	    else
	    {
		StrBuf mtext;
		StrOps::RmUniquote( mtext, StrRef( ep->ids[i].fmt ) );
		out.SetVar( P4Tag::v_fmt, i, mtext );
	    }
	}

	StrRef c( P4Tag::v_code ), f( P4Tag::v_fmt );

	for( i = 0; ep->whichDict->GetVar( i, r, l ); i++ )
	    if( r != P4Tag::v_func && c.XCompareN( r ) && f.XCompareN( r ) )
	        out.SetVar( r, l );
}

/*
 * Error::UnMarshall1() - import an Error in as a StrDict
 *
 * Resulting data is shared:
 *
 *	whichDict is &'in'
 *	ids[].fmt in 'in'
 */

void
Error::UnMarshall1( StrDict &in )
{
	if( !ep ) ep = new ErrorPrivate;

	Clear();
	ep->Clear();

	/* We use external dictionary and share the fmts */

	ep->whichDict = &in;
	ep->fmtSource = ErrorPrivate::isShared;

	/* Set each of ids[] */

	const StrPtr *s, *t;

	while( ( s = in.GetVar( StrRef( P4Tag::v_code ), ep->errorCount ) ) 
	    && ( t = in.GetVar( StrRef( P4Tag::v_fmt ), ep->errorCount ) ) 
	    && ep->errorCount < ErrorMax )
	{
	    ErrorId &id = ep->ids[ ep->errorCount++ ];

	    id.code = s->Atoi();
	    id.fmt = t->Text();

	    /* Most severe error sets severity/generic */

	    if( id.Severity() >= severity )
	    {
		genericCode = id.Generic();
		severity = ErrorSeverity( id.Severity() );
	    }
	}
}

/*
 * Error::Marshall2() - pack an Error into a StrBuf
 *
 * Marshall2() is used by the server to pack an Error into a StrBuf 
 * so that it can be passed wholly through the client and then
 * reconstructed back on the server.  It looks like this (ints as
 * binary):
 *
 *	severity
 *	generic
 *	count
 *
 *	code0
 *	fmt0 (null terminated)
 *
 *	code1
 *	fmt1
 *	
 *	.
 *	.
 *	.
 *
 *	var0 len/string
 *	var1 len/string
 *	.
 *	.
 *	.
 */

void
Error::Marshall2( StrBuf &out ) const
{
	/* Pack severity, generic code, error count */

	StrOps::PackInt( out, severity );

	if( severity == E_EMPTY )
	    return;

	StrOps::PackInt( out, genericCode );
	StrOps::PackInt( out, ep->errorCount );

	/* Stash ep's arg walk offset in the dict */

	if ( ep->walk )
	    ep->whichDict->SetVar( "errorMarshall2WalkOffset", 
	        ep->walk - ep->ids[ep->errorCount-1].fmt );

	/* Build new buffer of error messages/args for marshalling. */
	/* Marshalled messages are expanded, with the id's arg code */
	/* zeroed and and any %'s escaped with %%. */

	int i;
	ErrorId *id;
	StrRef r, l;
	char c0 = 0;	// for null terminating strings

	for( i = 0; id = GetId( i ); i++ )
	{
	    StrOps::PackInt( out, id->code );
	    StrOps::PackString( out, StrRef( id->fmt ) );
	    StrOps::PackChar( out, &c0, 1 );
	}

	for( i = 0; ep->whichDict->GetVar( i, r, l ); i++ )
	{
	    StrOps::PackString( out, r );
	    StrOps::PackString( out, l );
	}

	if ( ep->walk )
	    ep->whichDict->RemoveVar( "errorMarshall2WalkOffset" );
}

/*
 * Error::UnMarshall2() - unpack an Error from StrBuf
 *
 * Resulting data is local/shared:
 *
 *	whichDict is ErrorPrivate::errorDict
 *	ids[].fmt in 'inp'
 */

void
Error::UnMarshall2( const StrPtr &inp )
{
	if( !ep ) ep = new ErrorPrivate;

	Clear();
	ep->Clear();

	/* We use private dictionary and share the fmts */

	ep->fmtSource = ErrorPrivate::isShared;

	/* Unpack severity, generic code, error count */
	/* Note these locals override Error class' */

	StrRef in = inp;

	severity = (ErrorSeverity)StrOps::UnpackInt( in );

	if( (ErrorSeverity)severity == E_EMPTY )
	    return;

	genericCode = StrOps::UnpackInt( in );		
	ep->errorCount = StrOps::UnpackInt( in );	

	if( ep->errorCount > ErrorMax )
	    ep->errorCount = ErrorMax;

	/* Unpack error code/messages. */

	int i;
	StrRef r, l;
	char c0;

	for( i = 0; i < ep->errorCount; i++ )
	{
	    ep->ids[i].code = StrOps::UnpackInt( in );
	    StrOps::UnpackString( in, r );
	    ep->ids[i].fmt = r.Text();
	    StrOps::UnpackChar( in, &c0, 1 );
	}

	/* Unpack variables */

	while( in.Length() )
	{
	    StrOps::UnpackString( in, r );
	    StrOps::UnpackString( in, l );
	    ep->whichDict->SetVar( r, l );
	}

	StrPtr* walkOff = ep->whichDict->GetVar( "errorMarshall2WalkOffset" );
	if ( !walkOff )
	    return;
	
	int wo = walkOff->Atoi();
	if ( wo >= 0 && wo < strlen( ep->ids[ep->errorCount-1].fmt ) )
	    ep->walk = ep->ids[ep->errorCount-1].fmt + wo;

	ep->whichDict->RemoveVar( "errorMarshall2WalkOffset" );
}
