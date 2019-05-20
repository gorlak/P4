/*
 * Copyright 1995, 2002 Perforce Software.  All rights reserved.
 */

/*
 * Error.cc - accumulate and report layered errors
 *
 * This module containts the manipulation of Error, mostly wrappers
 * of methods to the private ErrorPrivate, which are are managed in 
 * erroritms.cc.
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <strdict.h>
# include <strtable.h>
# include <strops.h>
# include <error.h>
# include <errorpvt.h>

const char *
Error::severityText[] = { "empty", "info", "warning", "error", "error" };

/*
 * Error::Error() - cheaply initialize error struct 
 *
 * Note that setting severity = E_EMPTY is all that is needed
 * to indicate no error.  Things get initialized when severity
 * gets upgraded.
 */

Error::~Error()
{
	delete ep;
}

/*
 * Error::=() - copy an Error struct, piece by piece

 * Note that this makes a shallow copy.  Use Snap() if you need a deep copy.
 */

void
Error::operator =( const Error &s )
{
	// Only severity needed if empty

	severity = s.severity;

	if( severity == E_EMPTY )
	    return;

	// Copy underbelly.

	if( !ep )
	    ep = new ErrorPrivate;

	genericCode = s.genericCode;
	if( s.ep )
	    *ep = *s.ep;
}

/*
 * Error::Merge() - Merge one Error struct into another
 */

Error &
Error::Merge( const Error &source )
{
	/* If source error more severe than mine, save severity & generic */

	if( source.severity >= severity )
	{
	    severity = source.severity;
	    genericCode = source.genericCode;
	}

	if( !ep )
	{
	    // just copy the error private from the source
	    ep = new ErrorPrivate;
	    *ep = *source.ep;
	}
	else
	{
	    // need to merge the error privates
	    ep->Merge( source.ep );
	}

	return *this;
}

/*
 * Error::Set() - add an error message into an Error struct
 */

Error &		
Error::Set( const ErrorId &id )
{ 
	/* First access?  Set private. */

	if( !ep )
	    ep = new ErrorPrivate;

	/* First error?  Clear things out */

	if( severity == E_EMPTY )
	    ep->Clear();

	/* If error more severe that previous, save severity & generic */

	ErrorSeverity s = (ErrorSeverity)id.Severity();

	if( s >= severity )
	{
	    severity = s;
	    genericCode = id.Generic();
	}

	/* Now prepare the error message for formatting. */

	ep->Set( id );

	return *this;
}


/*
 * Error::Set() - add an error message into an Error struct with dict
 * Warning: advanced usage only!
 */

Error &
Error::Set( const ErrorId &id, StrDict *errorDict )
{
	/* First access?  Set private. */

	if (!ep)
	    ep = new ErrorPrivate;

	/* First error?  Clear things out */

	if (severity == E_EMPTY)
	    ep->Clear();

	/* If error more severe that previous, save severity & generic */

	ErrorSeverity s = (ErrorSeverity)id.Severity();

	if (s >= severity)
	{
	    severity = s;
	    genericCode = id.Generic();
	}

	/* Now prepare the error message for formatting. */

	ep->Set(id);

	if( errorDict )
	    ep->errorDict.CopyVars( *errorDict );

	return *this;
}

Error &
Error::operator <<( const StrPtr &arg )
{
	ep->SetArg( arg );
	return *this;
}

Error &
Error::operator <<( const char *arg )
{
	ep->SetArg( StrRef( arg ) );
	return *this;
}

Error &
Error::operator <<( const StrPtr *arg )
{
	ep->SetArg( *arg );
	return *this;
}

Error &
Error::operator <<( int arg )
{
	ep->SetArg( StrNum( arg ) );
	return *this;
}

/*
 * Error::Get() - get an individual Error item
 */

ErrorId *
Error::GetId( int i ) const
{
	return !ep || i < 0 || i >= ep->errorCount ? 0 : &ep->ids[i];
}

int
Error::GetErrorCount() const
{
	return ep ? ep->errorCount : 0;
}

void
Error::LimitErrorCount()
{
	if( ep && ep->errorCount > OldErrorMax )
	    ep->errorCount = OldErrorMax;
}

/*
 * Error::CheckIds() - check each individual Error item for a particular code
 */

int Error::CheckIds( const ErrorId &id ) const
{
	for( int i = 0; i < GetErrorCount(); i++ )
	    if( CheckIdi( i, id ) )
		return 1;

	return 0;
}

/*
 * Error::GetDict() - get StrDict of error parameters
 */

StrDict *
Error::GetDict()
{
	return ep ? ep->whichDict : 0;
}

/*
 * Error::Fmt() - format an error message
 *
 * Error messages are already formatted by Set() and <<.
 */

void
Error::Fmt( StrBuf &buf, int opts ) const
{
	Fmt( -1, buf, opts );
}
void
Error::Fmt( int eno, StrBuf &buf, int opts ) const
{
	if( !severity )
	    return;

	if( !IsInfo() ) 
	    buf.Clear();

	StrBuf lfmt;
	StrPtr *l = 0;

	if( !( opts & EF_NOXLATE ) )
	{
	    lfmt.Set( "lfmt" );
	    l = &lfmt;
	}

	for( int i = ep->errorCount; i-- > 0; )
	{
	    if( eno != -1 && eno != (i+1) )
		continue;

	    if( opts & EF_CODE )
	    {
		buf << StrNum( ep->ids[ i ].UniqueCode() );
		buf.Extend( ':' );
	    }

	    if( opts & EF_INDENT ) buf.Append( "\t", 1 );

	    StrPtr *s;
	    StrRef fmt;

	    if( !l || !( s = ep->whichDict->GetVar( *l, i ) ) )
	    {
		fmt.Set( (char *)ep->ids[i].fmt );
		s = &fmt;
	    }

	    StrOps::Expand2( buf, *s, *ep->whichDict ); 

	    // Always insert; sometimes append

	    if( eno == -1 && ( i || opts & EF_NEWLINE ) )
		buf.Append( "\n", 1 );
	}
}

/*
 * Error::Snap() - after UnMarshall1, copy all data into Error
 *
 * Resulting data is local:
 *
 *	whichDict is ErrorPrivate::errorDict
 *	ids[].fmt in ErrorPrivate::marshall
 */

void
Error::Snap()
{
	// ErrorPrivate::operator = handles snapping.
	if (ep)
	    *ep = *ep;
}

const ErrorId *
Error::MapError( const struct ErrorIdMap map[] )
{
	// shortcut if there are no ErrorIds to lookup
	if( !ep ) {
	    return NULL;
	}

	for(int i = 0; map[i].incomingError.UniqueCode() != 0; i++)
	{
	    for( int j=0; j < ep->errorCount; j++)
	    {
		if (map[i].incomingError.code == ep->ids[j].code )
		{
		    return &(map[i].outgoingError);
		}
	    }
	}
	return NULL;
}


/*
 * Errorpvt.cc - private data for Error object
 */

void
ErrorPrivate::operator =( const ErrorPrivate &s )
{
	// Handle self-assign as a way of snapping data.

	int isSelf = this == &s;

	// Simple parts

	walk = 0;
	errorCount = s.errorCount;
	fmtSource = s.fmtSource;

	// Dictionary.
	// It's a little faster to use BufferDict::operator =
	// than CopyVars(), so take that shortcut if we can.

	if( s.whichDict != &s.errorDict )
	    errorDict.CopyVars( *s.whichDict );
	else if( !isSelf )
	    errorDict = s.errorDict;

	whichDict = &errorDict;

	// Copy ids over.

	if( !isSelf )
	    for( int i = 0; i < errorCount; i++ )
		ids[i] = s.ids[i];

	// Snap ids[].fmt.
	// If self-assign, we skip this if they are already in the fmtBuf.
	// Otherwise, we skip only if they are constants (via Error::Set())
	// and thus global.

	if( isSelf ? ( fmtSource != isFmtBuf ) : ( fmtSource != isConst ) )
	{
	    int i;

	    fmtbuf.Clear();

	    for( i = 0; i < errorCount; i++ )
	    {
		fmtbuf.Append( ids[i].fmt );
		fmtbuf.Extend( 0 );
	    }

	    char *p = fmtbuf.Text();

	    for( i = 0; i < errorCount; i++ )
	    {
		ids[i].fmt = p;
		p += strlen( p ) + 1;
	    }

	    fmtSource = isFmtBuf;
	}

	// Copy arg walk state as offset from last id's fmt.

	if ( s.walk )
	    walk = ids[errorCount-1].fmt + (s.walk - s.ids[errorCount-1].fmt);
}

void
ErrorPrivate::Merge( const ErrorPrivate *ep )
{
	if( ep == this || ep->errorCount == 0 )
	    return;

	int	i;
	int	mergeCount = ep->errorCount;

	if( errorCount + mergeCount > ErrorMax )
	    mergeCount = ErrorMax - errorCount;

	for( i = 0; i < mergeCount; ++i )
	    ids[ errorCount + i ] = ep->ids[ i ];

	// errorDict.CopyVars( *ep->whichDict );
	// we can't use copy because we want to merge
	StrRef var, val;
	for( i = 0; ep->whichDict->GetVar( i, var, val ); i++ )
	    errorDict.SetVar( var, val );

	whichDict = &errorDict;

	errorCount += mergeCount;

	if( ep->fmtSource != isConst )
	{
	    StrBuf newfmt;

	    for( i = 0; i < errorCount; i++ )
	    {
		newfmt.Append( ids[i].fmt );
		newfmt.Extend( 0 );
	    }

	    fmtbuf.Set( newfmt );
	    char *p = fmtbuf.Text();

	    for( i = 0; i < errorCount; i++ )
	    {
		ids[i].fmt = p;
		p += strlen( p ) + 1;
	    }

	    fmtSource = isFmtBuf;
	}
}

/*
 * ErrorPrivate::SetArg() - provide formatting parameters
 */

void
ErrorPrivate::SetArg( const StrPtr &arg )
{
	/* If we've already finished walking the fmt string */
	/* we can't really format any more parameters. */

	if( !walk )
	    return;

	/* Loop past %%'s and %'stuff'% looking for %param% */

	while( ( walk = strchr( walk, '%' ) ) )
	{
	    if( *++walk == '\'' )
	    {
		walk = strchr( walk, '%' );
		if( !walk )
		    return;
	    }
	    else if( *walk == '%' )
		;
	    else
		break;
	    ++walk;
	}

	// No more %?s

	if( !walk )
	    return;

	/* The %parameter% name is in the fmt string. */
	/* Just bail if there is no ending %. */

	const char *p;
	if( !( p = strchr( walk, '%' ) ) )
	    return;

	// %var% - set variable to arg
	// %!var% - ignore arg (leave variable unset)

	if( *walk != '!' )
	    whichDict->SetVar( StrRef( walk, p - walk ), arg );

	walk = p + 1;
}

/*
 * Error::Dump()
 * ErrorPrivate::Dump() - debugging
 */

void
Error::Dump( const char *trace )
{
	printf( "Error %s %p\n", trace, this );
	printf( "\tSeverity %d (%s)\n", severity, FmtSeverity() );

	if( severity == E_EMPTY )
	    return;

	printf( "\tGeneric %d\n", genericCode );

	ep->Dump();
}

void
ErrorPrivate::Dump()
{
	int i;
	StrRef r, l;

	printf( "\tCount %d\n", errorCount );

	for( i = 0; i < errorCount; i++ )
	{
	    printf( "\t\t%d: %d (sub %d sys %d gen %d args %d sev %d code %d)\n",
		i,
		ids[i].code,
		ids[i].SubCode(),
		ids[i].Subsystem(),
		ids[i].Generic(),
		ids[i].ArgCount(),
		ids[i].Severity(),
		ids[i].UniqueCode() );
	    printf( "\t\t%d: %s\n", i, ids[i].fmt );
	}

	for( i = 0; whichDict->GetVar( i, r, l ); i++ )
	{
	    // For null termination
	    StrBuf r1, l1;
	    r1 = r; l1 = l;
	    printf( "\t\t%s = %s\n", r1.Text(), l1.Text() );
	}
}
