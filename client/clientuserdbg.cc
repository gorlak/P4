/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include <strbuf.h>
# include <strops.h>
# include <enviro.h>
# include <error.h>
# include <strarray.h>
# include <strdict.h>
# include <strtable.h>
# include <spec.h>
# include <options.h>

# include <filesys.h>

# include "clientuser.h"
# include "clientuserdbg.h"

/*
 * ClientUserDebug -- version of output that always to stdout
 */

void
ClientUserDebug::OutputError( const char *errBuf )
{
	OutputTag( "error", errBuf, strlen( errBuf ) );
}

void
ClientUserDebug::OutputInfo( char level, const char *data )
{
	switch( level )
	{
	default: OutputTag( "info", data, strlen( data ) ); break;
	case '1': OutputTag( "info1", data, strlen( data ) ); break;
	case '2': OutputTag( "info2", data, strlen( data ) ); break;
	}
}

void
ClientUserDebug::OutputText( const char *data, int length )
{
	OutputTag( "text", data, length );
}

void
ClientUserDebug::OutputTag( const char *tag, const char *data, int length )
{
	char *p;

	while( p = (char *)memchr( data, '\n', length ) )
	{
	    printf( "%s: ", tag );
	    fwrite( data, 1, p + 1 - data, stdout );
	    length -= p + 1 - data;
	    data = p + 1;
	}

	if( length )
	{
	    printf( "%s: ", tag );
	    fwrite( data, 1, length, stdout );
	    printf( "\n" );
	}
}

/*
 * ClientUserDebugMsg -- message debugging ("-e" global opt)
 */

void
ClientUserDebugMsg::Message( Error *err )
{
	ClientUserDebug::Message( err );

	// print error subcodes for each ErrorId

	ErrorId* id;
	for ( int i = 0 ; id = err->GetId( i ) ; i++ )
	    printf( "code%d %d (sub %d sys %d gen %d args %d sev %d uniq %d)\n",
		i,
		id->code,
		id->SubCode(),
		id->Subsystem(),
		id->Generic(),
		id->ArgCount(),
		id->Severity(),
		id->UniqueCode() );

	// use base ClientUser OutputStat/Info() to print dict

	ClientUser ui;
	if ( err->GetDict() )
	    ui.OutputStat( err->GetDict() );
}

void
ClientUserDebugMsg::Prompt( Error *err, StrBuf &rsp, int noEcho, Error *e )
{
	ClientUserDebug::Prompt( err, rsp, noEcho, e );

	// print error subcodes for each ErrorId

	ErrorId* id;
	for ( int i = 0 ; id = err->GetId( i ) ; i++ )
	    printf( "code%d %d (sub %d sys %d gen %d args %d sev %d uniq %d)\n",
		i,
		id->code,
		id->SubCode(),
		id->Subsystem(),
		id->Generic(),
		id->ArgCount(),
		id->Severity(),
		id->UniqueCode() );

	// use base ClientUser OutputStat/Info() to print dict

	ClientUser ui;
	if ( err->GetDict() )
	    ui.OutputStat( err->GetDict() );
}

/*
 * ClientUserFmt -- user-specified formatting ("-F" global opt)
 */

void
ClientUserFmt::Message( Error *err )
{
	OutputStat( err->GetDict() );
}

void
ClientUserFmt::OutputStat( StrDict *dict )
{
	if( !dict )
	    return;

	StrBuf out;
	StrOps::Expand2( out, *fmt, *dict );
	if( out.Length() )
	    printf( "%s\n", out.Text() );
}

/*
 * ClientUserMunge -- user-specified munging ("--field" global opt)
 */

ClientUserMunge::ClientUserMunge(Options &opts, int autoLoginPrompt) :
	ClientUser( autoLoginPrompt )
{
	// Get the list of field substitutions from the Options.
	
	const StrPtr *s;
	done = 0;

	for( int i = 0 ; s = opts.GetValue( Options::Field, i ) ; i++ )
	    fields.Put( *s );
}

void 
ClientUserMunge::OutputStat( StrDict *dict )
{
	if( done )
	    return;

	Munge( dict, &fields, this );

	done = 1; // prevent us from spitting multiple error messages
		  // when the user runs the wrong command
}

void
ClientUserMunge::Munge( StrDict *dict, StrPtrArray *fields, ClientUser *ui )
{
	StrPtr *specdef = dict->GetVar( "specdef" );
	if( !specdef )
	{
	    ui->OutputError( "This command did not return a spec."
				    "  Try 'p4 (spectype) -o'?\n" );
	    return;
	}

	Error e;

	// Build the spec.

	Spec spec( specdef->Text(), "", &e );
	if( e.Test() )
	    return ui->HandleError( &e );

	// Copy and modify the dict.

	StrBufDict d( *dict );
	StrBuf field, value;

	for( int i = 0 ; i < fields->Count() ; i++ )
	{
	    const StrPtr *s = fields->Get( i );
	    int plus = 0;

	    const char *eq = s->Contains( StrRef( "=" ) );
	    if( !eq || eq == s->Text() )
		return ui->OutputError( "Usage: --field Field=value\n" );

	    field.Set( s->Text(), eq - s->Text() );
	    if( field.Text()[ field.Length() - 1 ] == '+' )
	    {
		plus = 1;
		field.SetLength( field.Length() - 1 );
	    }
	    field.Terminate();

	    SpecElem *elem = spec.Find( field, &e );
	    if( !elem )
		return ui->HandleError( &e );

	    value.Clear();
	    int x = 0;

	    if( plus && !elem->IsList() )
	    {
		// Single entry, get existing.

		if( d.GetVar( field ) )
		    value.Append( d.GetVar( field ) );
	    }
	    if( elem->IsList() )
	    {
		// List entry, get index for last item.

		for( int j = 0 ; d.GetVar( field, j ) ; j++ )
		    x = j + 1;
	    }
	    if( x && !plus )
	    {
		// Go back and remove existing list items.

		StrBuf fn;
		StrNum y;
		while( x )
		{
		    x--;
		    fn = field;
		    y = x;
		    fn.Append( y.Text() );
		    d.RemoveVar( fn );
		}
	    }

	    value.Append( eq + 1 );
	    
	    if( elem->IsList() )
		d.SetVar( field, x, value );
	    else
	        d.ReplaceVar( field, value );
	}

	// Format spec.

	SpecDataTable data( &d );
	StrBuf result;
	spec.Format( &data, &result );

	ui->OutputText( result.Text(), result.Length() );
}
