/*
 * Copyright 1995, 2016 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# define NEED_FILE
# define NEED_WINDOWSH

# include <stdhdrs.h>

# include <strbuf.h>
# include <strdict.h>
# include <vararray.h>
# include <strtable.h>
# include <strops.h>
# include <enviro.h>
# include <error.h>
# include <debug.h>

# include <filesys.h>

# include <maptable.h>
# include <maphalf.h>
# include <mapitem.h>

# include <msgclient.h>
# include <msgserver.h>

# include "clientuser.h"
# include "clientusercolor.h"


/*
 * Setup ANSI color coding constants
 * Mostly Windows specific mappings
 */

const int ESC = '\033';

const StrRef csi( "\033[" );
const StrRef r( "0" );
const StrRef m( "m" );

# ifdef OS_NT
# ifdef OS_MINGW
#define COMMON_LVB_UNDERSCORE 0x8000
# endif

int WinColors[] = {
    0, // 30,40 Black
    4, // 31,41 Red
    2, // 32,42 Green
    6, // 33,43 Yellow
    1, // 34,44 Blue
    5, // 35,45 Magenta
    3, // 36,46 Cyan
    7  // 37,47 Gray
} ;

int Types[] = {
    0, // Reset/Normal
    FOREGROUND_INTENSITY, // Bold
    0, // Faint (noop)
    0, // Italic (noop)
    COMMON_LVB_UNDERSCORE  // Underline
} ;

#endif

static void
FixWildcards( StrBuf &o )
{
	StrBuf tmp;
	StrOps::Replace( tmp, o, StrRef("*"), StrRef("...") );
	if( !tmp.Contains( StrRef( "...." ) ) )
	{
	    o = tmp;
	    return;
	}

	o.Clear();
	int d = 0, l = 0, i = 0;
	for( ; i < tmp.Length(); i++ )
	{
	    if( tmp.Text()[i] == '.' )
	        d++;

	    if( tmp.Text()[i] == '.' && d == 3 && i != l + d - 3 )
	    {
	        o.Append( tmp.Text() + l, i - l + 1 );
	        l = i;
	    }
	    else if( tmp.Text()[i] != '.' )
	    {
	        if( d >= 3 )
	            l = i;
	        d = 0;
	    }
	}
	if( i - l > 0 && d < 3 )
	    o.Append( tmp.Text() + l, i - l + 1 );
}

/*
 * ClientUserColor -- version of output that displays ANSI colors
 */

ClientUserColor::ClientUserColor( int forceColors, int autoLoginPrompt ) :
    ClientUser( autoLoginPrompt )
{
	quiet = 0;
	colors = 0;
	conditionals = 0;

	outColor = 0;
	errColor = 0;

#ifdef OS_NT
	// Windows check for console
	// We also need to stash the console handles and original colors

	hConsoleOut = GetStdHandle( STD_OUTPUT_HANDLE );
	hConsoleErr = GetStdHandle( STD_ERROR_HANDLE );

	CONSOLE_SCREEN_BUFFER_INFO info;
	GetConsoleScreenBufferInfo(hConsoleOut, &info);
	oldColors = info.wAttributes;
#endif

	// Check for TTY (or force)
	
	if( forceColors )
	{
	    outColor = 1;
	    errColor = 1;
	    return;
	}

	if( isatty( fileno( stdout ) ) )
	    outColor = 1;

	if( isatty( fileno( stderr ) ) )
	    errColor = 1;

}

ClientUserColor::~ClientUserColor()
{
	if( colors )
	    delete colors;
	if( conditionals )
	    delete conditionals;

	if( outColor )
	    ResetColor( stdout );
	if( errColor )
	    ResetColor( stderr );

#ifdef OS_NT
	fflush( stdout );
	fflush( stderr );
	CloseHandle( hConsoleOut );
	CloseHandle( hConsoleErr );
#endif
}


void
ClientUserColor::HandleError( Error *err )
{

	StrBuf buf;
	if( ColorMessage( err, errColor, buf, EF_NEWLINE ) )
	    OutputAnsiStream( buf.Text(), stderr );
	else
	    OutputError( buf.Text() );
}

void
ClientUserColor::Message( Error *err )
{
	int keepfile = 0;

	if( err->IsInfo() )
	{
	    // Info
	    StrBuf buf;
	    if( ColorMessage( err, outColor, buf, EF_PLAIN ) )
	        OutputAnsiInfo( (char) err->GetGeneric() + '0', buf.Text() );
	    else
	        OutputInfo( (char) err->GetGeneric() + '0', buf.Text() );

	    if( err->CheckId( MsgServer::SpecNotCorrect ) )
	        keepfile = 1;
	}
	else
	{
	    // warn, failed, fatal
	    HandleError( err );
	    
	    // report file name left
	    if( !err->CheckId( MsgServer::ErrorInSpec ) )
	        keepfile = 1;
	}

	if( editFile.Length() > 0 )
	{
	    if( keepfile )
	    {
	        Error other;
	        other.Set( MsgClient::FileKept ) << editFile.Text();
	        HandleError( &other );
	    }
	    else
	    {
	        FileSys *f = File( FST_UNICODE );
	        f->Set( editFile );
	        f->Unlink( err );
	        delete f;
	    }
	    editFile.Clear();
	}
}

void
ClientUserColor::SetQuiet()
{
	quiet = 1;
	ClientUser::SetQuiet();
}


void
ClientUserColor::OutputAnsiInfo( char level, const char *data )
{
	if( quiet )
	    return;

	switch( level )
	{
	default:
	case '0': break;
	case '1': printf( "... " ); break;
	case '2': printf( "... ... " ); break;
	}

	OutputAnsiStream( data, stdout );
	fputc( '\n', stdout );
}


int
ClientUserColor::ColorMessage( Error *err, int color, StrBuf &out, int flag )
{
	StrRef var, val;
	StrPtr *b = 0;
	StrBuf buf;
	MapItem *mi;

	StrDict* tags = err->GetDict();
	MapTable colors;
	if( !color || !GetColors( tags, colors ) )
	{
	    err->Fmt( out, flag );
	    return 0;
	}

	buf << "@" << err->FmtSeverity();
	if( ( mi = colors.Check( LHS, buf ) ) )
	    b = mi->Rhs();
	buf.Clear();

	StrBufDict ctags;
	int i = 0;
	while( tags && tags->GetVar( i++, var, val ) )
	{
	    if( ( mi = colors.Check( LHS, var ) ) )
	    {
	        buf.Clear();
	        buf << csi << mi->Rhs() << m << val << csi << ( b ? b : &r ) << m;
	        ctags.SetVar( var, buf );
	    }
	    else
	        ctags.SetVar( var, val );
	}

	buf.Clear();
	FmtError( buf, err, flag, &ctags );
	if( b )
	    out << csi << b << m << buf << csi << r << m;
	else
	    out << buf;

	return 1;
}

void
ClientUserColor::FmtError( StrBuf &buf, Error *err, int opts, StrDict *tags )
{
	if( !err->GetSeverity() )
	    return;

	if( !err->IsInfo() ) 
	    buf.Clear();
	
	StrBuf lfmt;
	StrPtr *l = 0;

	if( !( opts & EF_NOXLATE ) )
	{
	    lfmt.Set( "lfmt" );
	    l = &lfmt;
	}

	for( int i = err->GetErrorCount(); i-- > 0; )
	{
	    if( opts & EF_CODE )
	    {
	        buf << StrNum( err->GetId( i )->UniqueCode() );
	        buf.Extend( ':' );
	    }

	    if( opts & EF_INDENT ) buf.Append( "\t", 1 );

	    StrPtr *s;
	    StrRef fmt;

	    if( !l || !( s = tags->GetVar( *l, i ) ) )
	    {
	        fmt.Set( (char *)err->GetId( i )->fmt );
	        s = &fmt;
	    }

	    StrOps::Expand2( buf, *s, *tags );

	    // Always insert; sometimes append

	    if( i || opts & EF_NEWLINE )
	        buf.Append( "\n", 1 );
	}
}

void
ClientUserColor::OutputStream( const char *text, int length, FILE *stream )
{
# ifdef OS_VMS
	// Note - VMS likes the args this way,  Mac the other,
	// UNIX doesn't care.
	//
	fwrite( text, length, 1, stream );
# else
	fwrite( text, 1, length, stream );
# endif
}


void
ClientUserColor::SetColor( int type, int fg, int bg, FILE *stream )
{
#ifdef OS_NT
	short fcolor = 0;
	short bcolor = 0;
	short newColors = 0;
	if( fg )
	    fcolor = WinColors[fg - 30];
	if( bg )
	    bcolor = WinColors[bg - 40] * 16;
	
	newColors = fcolor + bcolor + Types[type];
	if( stream == stdout )
	    SetConsoleTextAttribute( hConsoleOut, newColors );
	else
	    SetConsoleTextAttribute( hConsoleErr, newColors );
#else
	char buf[25];
	int len = 0;
	len = sprintf( buf, "\033[%d", type );
	if( fg )
	    len += sprintf( buf + len, ";%d", fg );
	if( bg )
	    len += sprintf( buf + len, ";%d", bg );
	len += sprintf( buf + len, "m" );
	OutputStream( buf, len, stream );
#endif
}

void
ClientUserColor::ResetColor( FILE *stream )
{
#ifdef OS_NT
	if( stream == stdout )
	    SetConsoleTextAttribute( hConsoleOut, oldColors );
	else
	    SetConsoleTextAttribute( hConsoleErr, oldColors );
#else
	OutputStream( "\033[0m", 4, stream );
#endif
}

void
ClientUserColor::OutputAnsiStream( const char *text, FILE *stream )
{
	fflush( stream );

	const char *p;

	// We already know whether we can render colors or not, but we still
	// iterate over the string so that any characters that 

	while( ( p = strchr( text, ESC ) ) )
	{
	    int length = strlen( text );

	    // Print stuff before the maker

	    if( p > text )
	        OutputStream( text, p - text, stream );

	    // Check for the reset marker (easy)

	    if( ( p - text + 4 ) <= length && !strncmp( p + 1, "[0m", 3 ) )
	    {
	        text = p += 4;
	        ResetColor( stream );
	        continue;
	    }

	    int type = 0;
	    int fg = 0;
	    int bg = 0;

	    int temp = 0;

	    // Jump over the CSI ^[[

	    if( ( p - text + 2 ) <= length && p[1] == '[' )
	        p += 2;

	    // Loop over the string until we reach a terminator

	    while( ( p - text ) <= length )
	        if( *p - '0' >= 0 && *p - '0' <= 9 ) // Interpret digit
	            temp = ( temp * 10 ) + ( *p++ - '0' );
	        else if( *p == ';' || ( *p >= 64 && *p <= 126 ) )
	        {
	            // Convert to meaning
	            if( temp >= 0 && temp <= 4 )
	                type = temp;
	            else if( temp >= 30 && temp <= 37 )
	                fg = temp;
	            else if( temp >= 40 && temp <= 47 )
	                bg = temp;

	            if( *p == 'm' )
	            {
	                // Apply color
	                SetColor( type, fg, bg, stream );
	                p++;
	                break;
	            }
	            else if( *p >= 64 && *p <= 126 )
	            {
	                // End of sequence (no color application)
	                p++;
	                break;
	            }

	            temp = 0;
	            p++;
	        }
	        else
	            p++;

	    text = p; 
	}
	
	// Print anything after the last marker

	OutputStream( text, strlen( text ), stream );

	// Back to default
	
	ResetColor( stream );
}

StrDict *
ClientUserColor::GetColors()
{
	char *c = 0, *c0;
	StrRef var, val;

	if( colors && colors->GetVar( 0, var, val ) )
	{
	    // OK.
	    return colors;
	}
	else if ( ( c = enviro->Get( "P4COLORS" ) ) )
	{
	    if( !colors )
	        colors = new StrBufDict;
	    if( !conditionals )
	        conditionals = new MapTable;

	    char *l = c + strlen( c );
	    char *s = 0, *e, *q, *p, *r = 0;
	    StrBuf var1, val1, val2, patten;
	    StrBufDict tmpColors;

	    /*
	     * Colors come in three types.
	     *
	     *  1. Static:
	     *
	     *    var=color:
	     *    c  e     s
	     *
	     *  2. Conditional:
	     *
	     *    (var=val)var=color:
	     *    c   p   qc  e     s
	     *
	     *  2. Conditional-multi:
	     *
	     *    (var=val)[var=color:var=color]:
	     *    c   p   qcc  e     sc  e     rs
	     *
	     * Notes:
	     *  c is promoted during condition parse
	     *  the trailing : may not exist for the last statement
	     */


	    while( c <= l &&
	            ( ( s = strchr( c, ':' ) ) ||
	              ( strlen( c ) && ( s = strlen( c ) + c ) ) ) )
	    {
	        q = 0;
	        p = 0;

	        if( !r )
	            patten.Clear();

	        // Check if the value is a conditional
	        if( *c == '(' )
	        {
	            c0 = c;

	            // find the end of the condition, or skip
	            if( !( q = strchr( c0, ')' ) ) || q >= s )
	            {
	                c = s + 1;
	                continue;
	            }

	            c = q + 1;

	            // there must be a separator inside the condition
	            if( !( p = strchr( c0, '=' ) ) || p >= q )
	            {
	                q = 0;
	                p = 0;
	            }

	            if( q )
	            {
	                // Save the matcher pattern
	                patten.Set( c0 + 1, q - c0 - 1  );
	                FixWildcards( patten );
	            }
	            else
	            {
	                c = s + 1;
	                continue;
	            }
	        }

	        // Check if this is a group of values (skip [ within [])
	        if( r && c < r && *c == '[' )
	            c++;

	        if( *c == '[' && ( r = strchr( ++c, ']' ) ) )
	        {
	            // Cant have conditionals in groups
	            if( ( q = strchr( c, '(' ) ) && q <= r )
	            {
	                c0 = strchr( r, ':' );
	                if( !c0 )
	                    c0 = strlen( c ) + c;
	                c = c0;
	                continue;
	            }

	            tmpColors.Clear();
	        }


	        // Make sure there's an = before the :, otherwise skip
	        if( !( e = strchr( c, '=' ) ) || e >= s )
	        {
	            if( r && r < s )
	            {
	                // Persist the group
	                val1.Clear();
	                int i = 0;
	                if( patten.Length() )
	                {
	                    while( tmpColors.GetVar( i++, var, val ) )
	                        val1 << var << "=" << val << ":";
	                    conditionals->Insert( patten, val1 );
	                }
	                else
	                    while( tmpColors.GetVar( i++, var, val ) )
	                        colors->SetVar( var, val );
	                r = 0;
	            }
	            c = s + 1;
	            continue;
	        }

	        if( r && r < s )
	            s = r;

	        // Get the tag pattern

	        var1.Set( c, e - c );
	        FixWildcards( var1 );

	        // Get the value

	        val1.Set( e + 1, s - e - 1 );
	        for( int i = 0; i < val1.Length(); i++ )
	            if( val1.Text()[i] != ';' &&
	                !( val1.Text()[i] >= '0' &&
	                    val1.Text()[i] <= '9' ) )
	            {
	                // Invalid value, skip it by unsetting the var
	                var1.SetLength( 0 );
	                var1.Terminate();
	                break;
	            }

	        StrOps::Replace( val2, val1, StrRef("00"), StrRef("0") );
	        val1.Clear();
	        val1 << var1.Text() << "=" << val2.Text();

	        if( r && var1.Length() && val2.Length() )
	            tmpColors.SetVar( var1, val2 );
	        else if( patten.Length() && var1.Length() && val2.Length() )
	            conditionals->Insert( patten, val1 );
	        else if( var1.Length() && val2.Length() )
	            colors->SetVar( var1, val2 );
	        if( r && r <= s )
	        {
	            // Persist the group
	            val1.Clear();
	            int i = 0;
	            if( patten.Length() )
	            {
	                while( tmpColors.GetVar( i++, var, val ) )
	                    val1 << var.Text() << "=" << val.Text() << ":";
	                if( val1.Length() )
	                    conditionals->Insert( patten, val1 );
	            }
	            else
	                while( tmpColors.GetVar( i++, var, val ) )
	                    colors->SetVar( var, val );
	            r = 0;
	        }

	        c = s + 1;
	    }
	}
	else
	{
	    if( !colors )
	        colors = new StrBufDict;
	    else
	        colors->Clear();

	    if( !conditionals )
	        conditionals = new MapTable;
	    else
	        conditionals->Clear();
	}

	return colors;
}

int
ClientUserColor::GetColors( StrDict *tags, MapTable &c )
{
	int count = 0, i = 0;
	StrRef var, val;
	StrBuf tmp;
	StrBufDict d;

	// Fill the new dict
	GetColors();
	while( colors && colors->GetVar( count++, var, val ) )
	    d.SetVar( var, val );

	StrBuf match;
	MapItem *mi;

	while( tags && tags->GetVar( i++, var, val ) )
	{
	    match.Clear();
	    match << var << "=" << val;
	    if( ( mi = conditionals->Check( LHS, match ) ) )
	    {
	        char *s = mi->Rhs()->Text();
	        char *l = mi->Rhs()->Text() + mi->Rhs()->Length();
	        char *q = 0, *p;
	        StrBuf var1, val1;
	        while( s < l &&
	                ( ( q = strchr( s, ':' ) ) ||
	                  ( strlen( s ) && ( q = strlen( s ) + s ) ) ) )
	        {
	            p = strchr( s, '=' );
	            if( !p && s++ )
	                continue;

	            var1.Set( s, p - s );
	            val1.Set( p + 1, q - p - 1 );

	            if( !d.GetVar( var1 ) )
	                d.SetVar( var1, val1 );
	            else
	                d.ReplaceVar( var1, val1 );
	            s = q + 1;
	        }
	    }
	}

	count = 0;
	while( d.GetVar( count++, var, val ) )
	    c.Insert( var, val );

	return count;
}
