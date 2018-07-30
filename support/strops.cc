/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * strings.cc - support for StrBuf, StrPtr
 */

# define CHARHASH(h, c) ( 293 * (h) + (c) );
# define NEED_QUOTE

# include <stdhdrs.h>
# include <charman.h>
# include <charset.h>
# include <debug.h>
# include <validate.h>
# include <error.h>
# include <regmatch.h>

# include "strbuf.h"
# include "strdict.h"
# include "strops.h"

/*
 * StrOps::Words() - break a string apart at white space
 *
 * Quotes are handles as thus:
 *
 *	"foo bar" -> (foo) (bar)
 *	foo" "bar -> (foo) (bar)
 *	"foo""bar" -> (foo"bar)
 *	foo""bar -> (foo"bar)
 *
 * Note that the only user of Words() that requires quote handling
 * is RunCommand::RunChild() on UNIX, which is used for P4PORT=rsh:
 */

int
StrOps::Words( StrBuf &tmp, const char *buf, char *vec[], int maxVec )
{
	// Ensure tmp clear and big enough to avoid realloc

	tmp.Clear();
	tmp.Alloc( strlen( buf ) + 1 );
	tmp.Clear();

	int count = 0;

	while( count < maxVec )
	{
	    // Skip blanks 

	    while( isAspace( buf ) ) buf++;
	    if( !*buf ) break;

	    // First letter of new word 

	    vec[ count++ ] = tmp.End();

	    // Eat word 

	    int quote = 0;

	    for( ; *buf; ++buf )
	    {
		if( buf[0] == '"' && buf[1] == '"' )
		    tmp.Extend( buf[0] ), ++buf;
		else if( buf[0] == '"' )
		    quote = !quote;
		else if( quote || !isAspace( buf ) )
		    tmp.Extend( buf[0] );
		else break;
	    }

	    tmp.Extend( '\0' );
	}

	return count;
}

int
StrOps::Words( StrBuf &tmp, const char *buf, char *vec[], int maxVec, char s )
{
	// Ensure tmp clear and big enough to avoid realloc

	tmp.Clear();
	tmp.Alloc( strlen( buf ) + 1 );
	tmp.Clear();

	int count = 0;

	while( count < maxVec )
	{
	    // Skip blanks 

	    while( *buf == s ) buf++;
	    if( !*buf ) break;

	    // First letter of new word 

	    vec[ count++ ] = tmp.End();

	    // Eat word 

	    int quote = 0;

	    for( ; *buf; ++buf )
	    {
		if( buf[0] == '"' && buf[1] == '"' )
		    tmp.Extend( buf[0] ), ++buf;
		else if( buf[0] == '"' )
		    quote = !quote;
		else if( quote || *buf != s )
		    tmp.Extend( buf[0] );
		else break;
	    }

	    tmp.Extend( '\0' );
	}

        return count;
}

int
StrOps::WordsQ( StrBuf &tmp, StrRef cmd, char *words[], int maxVec, Error *e )
{
	RegMatch m;

	//  a b          -> (a) (b)
	// 'a b' | "a b" -> (a b)
	// 'a "b c" d'   -> (a) (b c) (d)
	// unescaped regex:  "([^"]*)"|'([^']*)'|([^"' 	]+)

	m.compile( "\"([^\"]*)\"|'([^']*)'|([^\"' 	]+)", e );

	if( e->Test() )
	    return 0;

	tmp.Clear();
	tmp.Alloc( cmd.Length() + 1 );
	tmp.Clear();

	int count = 0;

	char *p = cmd.Text();

	words[ count ] = tmp.Text();

	while( count < maxVec && p < cmd.Text() + cmd.Length() )
	{
	    if( m.matches( p, e ) )
	    {
	        if( e->Test() )
	            return 0;

	        if( isBlank( *p ) )
	        {
	            p += 1;
	            continue;
	        }

	        if( *p == '\'' || *p == '"' )
	            tmp.Extend( p + 1, m.len() - 2 );
	        else
	            tmp.Extend( p, m.len() );

	        p += m.end() + 1;
	        tmp.Extend( '\0' );
	        words[ count + 1 ] = tmp.End();
	        count++;
	    }
	    else
	        break;
	}

	return count;
}

/*
 * StrPtr::Lines() - break a string apart at line endings.
 *                   Supports '\r', '\n', and '\r\n' termination.
 */

int
StrOps::Lines( StrBuf &o, char *vec[], int maxVec )
{
	int count = 0;
    	int lastwas_cr = 0;
	char *buf = o.Text();

    	while ( count < maxVec ) 
	{
	    if ( *buf ) 
		vec[ count++ ] = buf;
	    else
		break;
	    
	    while ( *buf ) 
	    {
		if ( *buf == '\r' )
		    lastwas_cr =1;
		else if ( *buf == '\n' && lastwas_cr )
		{
		    *(buf-1) = '\0';
		    *buf = '\0';
		    buf++;
		    lastwas_cr = 0;
		    break;
		}
		else if ( *buf == '\n' )
		{
		    *buf = '\0';
		    buf++;
		    break;
		}
		else if ( lastwas_cr ) 
		{
		    // '\r' line termination only
		    *(buf-1) = '\0';
		    lastwas_cr = 0;
		    break;
		}
		buf++;
	    }
	    if ( lastwas_cr )
	    {
		// Final \r of a \r line terminated buffer
		*(buf-1) = '\0';
	    }
	}

	return count;
}

/*
 * StrPtr::Dump() - print out a string for debugging purposes
 */

void
StrOps::Dump( const StrPtr &o ) 
{
	unsigned char *s = o.UText();
	unsigned char *e = o.UEnd();

	for( ; s < e; s++ )
	{
	    if( isprint( *s ) )
		p4debug.printf( "%c", *s );
	    else
		p4debug.printf( "<%02x>", *s );
	}
	p4debug.printf( "\n" );
}

/*
 * StrPtr::Lower() - lowercase each character (in place) in a string
 */

void
StrOps::Lower( StrBuf &o )
{
	char *p = o.Text();
	int l = o.Length();

	for( ; l--; p++ )
	    *p = tolowerq( *p );
}

/*
 * StrPtr::Upper() - uppercase each character (in place) in a string
 */

void
StrOps::Upper( StrBuf &o )
{
	char *p = o.Text();
	int l = o.Length();

	for( ; l--; p++ )
	    *p = toupperq( *p );
}

/*
 * StrPtr::Caps() - uppercase first character (in place) in a string
 */

void
StrOps::Caps( StrBuf &o )
{
	char *p = o.Text();

	if( o.Length() && !isAhighchar( p ) && islower( *p ) )
	    *p = toAupper( p );
}

/*
 * StrBuf::Ident() - copy in a string, indenting a tabstop
 */

void
StrOps::Indent( StrBuf &o, const StrPtr &buf )
{
	const char *p = buf.Text();
	const char *t;

	while( *p )
	{
	    o.Append( "\t", 1 );

	    if( t = strchr( p, '\n' ) )
	    {
		o.Append( p, t - p + 1 );
		p = t + 1;
	    }
	    else
	    {
		// just in case - all lines end with \n
		o.Append( p );
		o.Append( "\n", 1 );
		p += strlen( p );
	    }
	}
}

/*
 * StrBuf::Sub() - replace one character with another
 */

void
StrOps::Sub( StrPtr &string, char target, char replacement )
{
	for ( char * temp = string.Text();
	      *temp != '\0';
	      temp++ )
	{
	    if ( *temp == target )
	    	*temp = replacement;
	}
}

/*
 * StrOps::Replace() - Replace substrings. Replaces all occurrences of
 * string s in string i with string r and writes the results to o.
 */

void
StrOps::Replace( StrBuf &o, const StrPtr &i, const StrPtr &s, const StrPtr &r )
{
	char	*start, *end;

	o.Clear();
	start = i.Text();
	while ( end = strstr( start, s.Text() ) )
	{
	    o.Append( start, end - start );
	    o.Append( r.Text() );
	    start +=  end - start + s.Length();
	}
	if ( *start )
	    o.Append( start );
}

/*
 * StrOps::ReplaceWild() - Replace '*' with '...' but sometimes
 *                         %%1...  if previous character is '.'
 */

void
StrOps::ReplaceWild( StrBuf &o, const StrPtr &i )
{
	const char *n = "123456789";
	char	*start, *end;
	int     j = 0;

	o.Clear();
	start = i.Text();
	while ( end = strstr( start, "*" ) )
	{
	    o.Append( start, end - start );
	    if( end > start && *(end - 1) == '.' )
	    {
	        o.Append( "%%" );
	        o.Append( n + j, 1 );
	    	if( ++j >= 9)
	            j = 0;
	    }
	    o.Append( "..." );
	    start +=  end - start + 1;
	}
	if ( *start )
	    o.Append( start );
}

/*
 * StrBuf::Expand() - expand a string doing %var%, %x substitutions
 */

void
StrOps::Expand( StrBuf &o, const StrPtr &buf, StrDict &dict, StrDict *u )
{
	StrPtr *val;
	const char *p = buf.Text();
	const char *q;

	while( q = strchr( p, '%' ) )
	{
	    // look for closing %

	    o.Append( p, q++ - p );

	    if( !( p = strchr( q, '%' ) ) )
	    {
		// handle %junk
		p = q;
		break;
	    }
	    else if( p == q )
	    {
		// handle %%
		o.Extend( '%' );
	    }
	    else 
	    {
		// handle %var%
		StrBuf var;
		var.Extend( q, p - q );
		var.Terminate();
		if( val = dict.GetVar( var ) )
		    o.Append( val );
	        else
	        {
	            o << "%" << var << "%";
	            if( u )
	                u->SetVar( var.Text() );
	        }
	    }

	    ++p;
	}

	o.Append( p );
}

/*
 * StrOps::Expand2() - expand a string doing [%var%|opt] substitutions
 */

void
StrOps::Expand2( StrBuf &o, const StrPtr &buf, StrDict &dict )
{
	StrPtr *val;
	const char *p = buf.Text();
	const char *q, *r, *s, *t;

	// Handle sequences of
	//	text %var% ...
	//	text [ stuff1 %var% stuff2 ] ...

	while( q = strchr( p, '%' ) )
	{
	    if( q[1] == '\'' ) // %' stuff '%: include stuff, uninspected...
	    {
	        for( s = q + 2; *s; s++ )
	            if( s[0] == '\'' && s[1] == '%' )
	                break;
	        if( ! *s )
		    break; // %'junk
		o.UAppend( p, q - p );
		q += 2;
		o.UAppend( q, s - q );
		p = s + 2;
		continue;
	    }

	    // variables: (p)text (r)[ stuff (q)%var(s)% stuff2 (t)]

	    if( !( s = strchr( q + 1, '%' ) ) )
	    {
		// %junk
		break;
	    }
	    else if( s == q + 1 )
	    {
		// %% - [ %% ] not handled!
		o.Append( p, s - p );
		p = s + 1;
		continue;
	    }

	    // Pick out var name and look up value

	    StrVarName var( q + 1, s - q - 1 );
	    val = dict.GetVar( var );

	    // Now handle %var% or [ %var% | alt ]

	    if( !( r = (char*)memchr( p, '[', q - p ) ) )
	    {
		// %var%

		o.Append( p, q - p );
		if( val ) o.Append( val );
		p = s + 1;

	    }
	    else if( !( t = strchr( s + 1, ']' ) ) )
	    {
		// [ junk
		break;
	    }
	    else
	    {
		// [ stuff1 %var% stuff2 | alternate ]

		o.Append( p, r - p );

		// [ | alternate ]

		const char *v = (char *)memchr( s, '|', t - s );
		if( !v ) v = t;

		if( val && val->Length() )
		{
		    // stuff1, val, stuff2
		    o.Append( r + 1, q - r - 1 );
		    o.Append( val );
		    o.Append( s + 1, v - s - 1 );
		}
		else if( v < t )
		{
		    // alternate
		    o.Append( v + 1, t - v - 1 );
		}

		p = t + 1;
	    }
	}

	o.Append( p );
}

/*
 * StrOps::RmUniquote() - Remove %'text'% quote from a string
 */

void
StrOps::RmUniquote( StrBuf &o, const StrPtr &buf )
{
	const char *p = buf.Text();
	const char *q = p;
	const char *r;

	while( ( q = strchr( q, '%' ) ) )
	{
	    r = strchr( ++q, '%' );
	    if( !r )
		break;
	    if( q == r )
	    {
		q++;
		continue;
	    }
	    if( *q == '\'' )
	    {
		o.UAppend( p, q++ - p - 1 );
		o.UAppend( q, r - q - 1 );
		q = p = r + 1;
	    }
	    else
		q = r + 1;
	}

	o.UAppend( p );
}

/*
 * StrBuf::OtoX() - turn an octet stream into hex
 */

void
StrOps::OtoX( const StrPtr &octet, StrBuf &hex )
{
	OtoX( (const unsigned char *)octet.Text(), octet.Length(), hex );
}

void
StrOps::OtoX( const unsigned char *octet, p4size_t octetLen, StrBuf &hex )
{
	char *b = hex.Alloc( 2 * octetLen );

	for( int i = 0; i < octetLen; i++ )
	{
	    *b++ = OtoX( ( octet[i] >> 4 ) & 0x0f );
	    *b++ = OtoX( ( octet[i] >> 0 ) & 0x0f );
	}

	hex.Terminate();
}

char
StrOps::OtoXlower( unsigned char o )
{
	return o >= 10 ? o - 10 + 'a' : o + '0';
}

void
StrOps::OtoXlower( const StrPtr &octet, StrBuf &hex )
{
	OtoXlower( (const unsigned char *)octet.Text(), octet.Length(), hex );
}

void
StrOps::OtoXlower( const unsigned char *octet, p4size_t octetLen, StrBuf &hex )
{
	char *b = hex.Alloc( 2 * octetLen );

	for( int i = 0; i < octetLen; i++ )
	{
	    *b++ = OtoXlower( ( octet[i] >> 4 ) & 0x0f );
	    *b++ = OtoXlower( ( octet[i] >> 0 ) & 0x0f );
	}

	hex.Terminate();
}

/*
 * StrOps::XtoO() - turn hex into an octet stream 
 *
 * No error checking.
 */

void
StrOps::XtoO( const StrPtr &hex, StrBuf &octet )
{
	int len = hex.Length() / 2;

	XtoO( hex.Text(), (unsigned char *)octet.Alloc( len ), len );

	octet.Terminate();
}

void
StrOps::XtoO( char *hex, unsigned char *octet, int octetLen )
{
	for( ; octetLen--; hex += 2 )
	{
	    *octet++ 
		= ( XtoO( hex[0] ) << 4 )
		| ( XtoO( hex[1] ) << 0 );
	}
}

static const char valid[] = "0123456789abcdefABCDEF";
static int
IsX( char p )
{
	for( int i = 0; i < sizeof valid; i++ )
	    if( valid[i] == p )
	        return 1;
	return 0;
}

int
StrOps::IsDigest( const StrPtr &hex )
{
	if( hex.Length() != 32 )
	    return 0;

	for( int i = 0; i < 32; i++ )
	    if( !IsX( hex.Text()[i] ) )
		return 0;

	return 1;
}

int
StrOps::IsSha1( const StrPtr &hex )
{
	if( hex.Length() < 6 || hex.Length() > 40 )
	    return 0;

	for( int i = 0; i < hex.Length(); i++ )
	    if( !IsX( hex.Text()[i] ) )
		return 0;

	return 1;
}

static const char base64map[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int
StrOps::Base64Len( p4size_t len )
{
	int v = ( ( len + 2 ) / 3 ) * 4;

	switch( len % 3 )
	{
	case 1:
	    --v;
	case 2:
	    --v;
	}
	return v;
}

void
StrOps::OtoBase64( const unsigned char *octet, p4size_t len, StrBuf &base )
{
	char *p = base.Alloc( Base64Len( len ) );

	while( len >= 3 )
	{
	    unsigned int v = *octet++;
	    v <<= 8;
	    v |= *octet++;
	    v <<= 8;
	    v |= *octet++;

	    *p++ = base64map[ v >> 18 ];
	    v &= 0x3ffff;
	    *p++ = base64map[ v >> 12 ];
	    v &= 0xfff;
	    *p++ = base64map[ v >> 6 ];
	    *p++ = base64map[ v & 0x3f ];

	    len -= 3;
	}
	if( len == 2 )
	{
	    unsigned int v = *octet++;
	    *p++ = base64map[ v >> 2 ];
	    v &= 3;
	    v <<= 8;
	    v |= *octet;
	    *p++ = base64map[ v >> 4 ];
	    *p = base64map[ ( v & 0xf ) << 2 ];
	}
	else if( len == 1 )
	{
	    unsigned char v = *octet;
	    *p++ = base64map[ v >> 2 ];
	    *p = base64map[ ( v & 3 ) << 4 ];
	}

	base.Terminate();
}

inline static int BtoO( char b )
{
	const char *p = strchr( base64map, b );
	if( p )
	    return p - base64map;
	return -1;
}

void
StrOps::Base64toO( const char *base, unsigned char *octet, int octLen )
{
	while( octLen >= 3 )
	{
	    // full block loop
	    unsigned int v;
	    v = BtoO( *base++ ) << 18;
	    v |= BtoO( *base++ ) << 12;
	    v |= BtoO( *base++ ) << 6;
	    v |= BtoO( *base++ );
	    *octet++ = v >> 16;
	    *octet++ = ( v >> 8 ) & 0xff;
	    *octet++ = v & 0xff;
	    octLen -= 3;
	}
	if( octLen == 2 )
	{
	    unsigned int v;
	    v = BtoO( *base++ ) << 10;
	    v |= BtoO( *base++ ) << 4;
	    v |= BtoO( *base ) >> 2;
	    *octet++ = v >> 8;
	    *octet = v & 0xff;
	}
	else if( octLen == 1 )
	{
	    unsigned char v;
	    v = BtoO( *base++ ) << 2;
	    v |= BtoO( *base ) >> 4;
	    *octet = v;
	}
}

/*
 * StrOps::WildToStr() - turn wildcards into %x escaped string
 *
 * No error checking.
 */

void
StrOps::WildToStr( const StrPtr &i, StrBuf &o )
{
	// format special characters '@#*%'

	WildToStr( i, o, "@#%*" );
}

void
StrOps::WildToStr( const StrPtr &i, StrBuf &o, const char *t )
{

	o.Clear();

	char *p = i.Text();
	const char *f;
	char *s;

	while( *p )
	{
	    s = p;

	    while( *p )
	    {
	        f = t;

	        while( *f && *f != *p )
	            ++f;

	        if( *f )
	            break;

	        ++p;
	    }

	    o.Append( s, p - s );

	    if( *p )
	    {
	        char buf[3];

	        buf[0] = '%';
	        buf[1] = OtoX( ( *p >> 4 ) & 0x0f );
	        buf[2] = OtoX( ( *p++ >> 0 ) & 0x0f );

	        o.Append( buf, 3 );
	    }
	}
}

void
StrOps::MaskNonPrintable( const StrPtr &i, StrBuf &o )
{
	o.Clear();
	o.Alloc( i.Length() + 1 );
	o.Clear();

	unsigned char *s = i.UText();
	unsigned char *e = i.UEnd();

	for( ; s < e; s++ )
	{
	    if( isAprint( s ) )
	        o.Extend( *s );
	    else
	        o.Extend( '_' );
	}
	o.Terminate();
}

/*
 * StrOps::StrToWild() - turn %x escaped string into wildcards.
 *
 * No error checking.
 */

void
StrOps::StrToWild( const StrPtr &i, StrBuf &o )
{
	// expand %x character back to '@#*%'
	StrToWild( i, o, "@#%*" );
}

void
StrOps::StrToWild( const StrPtr &i, StrBuf &o, const char *t )
{

	o.Clear();

	char *p = i.Text();
	char *s;

	while( *p )
	{
	    s = p;

	    while( *p )
	    {
	        if( p[0] == '%' && p[1] == '%' )
	           p += 2;
	        else if( p[0] != '%' )
	           p++;
	        else
	           break;
	    }

	    o.Append( s, p - s );

	    if( *p && ( p + 2 < i.End() ) )
	    {
	        char b[2];

	        b[0] = ( XtoO( p[1] ) << 4 ) | ( XtoO( p[2] ) << 0 );

	        // Only translate the wildcards in *t

	        if( strchr( t, b[0] ) )
	            o.Append( b, 1 );
	        else
	            o.Append( p, 3 );

	        if( *(p+2) == '\0')
	            break;

	        p += 3;
	    }
	    else if( *p )
	    {
	        o.Append( p++, 1 );
	    }
	    else
	    {
	        break;
	    }
	}
}

/*
 * StrOps::WildCompat() - turn %%d into %d for 'p4 where' compatability.
 *
 * No error checking.
 */

void
StrOps::WildCompat( const StrPtr &i, StrBuf &o )
{
	// turn %%d into %d

	o.Clear();

	char *p = i.Text();
	char *s;

	while( *p )
	{
	    s = p;

	    while( *p )
	    {
	        if( p[0] == '%' && p[1] == '%' && p[2] >= '0' && p[2] <= '9' )
	           break;
		++p;
	    }

	    o.Append( s, p - s );

	    if( *p )
	    {
	        o.Append( ++p, 2 );
	        p += 2;
	    }
	}
}

/*
 * StrBuf::PackInt() - marshalling function
 * StrBuf::PackChar() - marshalling function
 * StrBuf::PackOctet() - marshalling function
 * StrBuf::PackString() - marshalling function
 * StrPtr::UnpackInt() - marshalling function
 * StrPtr::UnpackChar() - marshalling function
 * StrBuf::UnpackOctet() - marshalling function
 * StrPtr::UnpackString() - marshalling function
 */

void
StrOps::PackInt( StrBuf &o, int v )
{
	char *b = o.Alloc( 4 );
	const unsigned int vv = (unsigned int)v;

	b[0] = ( vv / 0x1 ) % 0x100;
	b[1] = ( vv / 0x100 ) % 0x100;
	b[2] = ( vv / 0x10000 ) % 0x100;
	b[3] = ( vv / 0x1000000 ) % 0x100;
}

void
StrOps::PackInt64( StrBuf &o, P4INT64 v )
{
	char *b = o.Alloc( 8 );
	unsigned P4INT64 vv = (unsigned P4INT64)v;

	b[0] = ( vv / 0x1 ) % 0x100;
	b[1] = ( vv / 0x100 ) % 0x100;
	b[2] = ( vv / 0x10000 ) % 0x100;
	b[3] = ( vv / 0x1000000 ) % 0x100;

	// On machines Without int64's, two >>16
	// will avoid complaints and zero v.

	vv >>= 16; 
	vv >>= 16;

	b[4] = ( vv / 0x1 ) % 0x100;
	b[5] = ( vv / 0x100 ) % 0x100;
	b[6] = ( vv / 0x10000 ) % 0x100;
	b[7] = ( vv / 0x1000000 ) % 0x100;
}

void
StrOps::PackIntA( StrBuf &o, int v )
{
	o << v;
	o.Extend(0);
}

void
StrOps::PackChar( StrBuf &o, const char *c, int length )
{
	char *end;

	// Append up to null, or whole thing if no null

	if( end = (char *)memchr( c, 0, length ) )
	    length = end + 1 - c;

	o.Append( c, length );
}

void
StrOps::PackOctet( StrBuf &o, const StrPtr &s )
{
	o.Append( &s );
}

void
StrOps::PackString( StrBuf &o, const StrPtr &s )
{
	PackInt( o, s.Length() );
	o.Append( &s );
}

void
StrOps::PackStringA( StrBuf &o, const StrPtr &s )
{
	PackIntA( o, s.Length() );
	o.Append( &s );
}

int
StrOps::UnpackInt( StrRef &o )
{
	if( o.Length() < 4 )
	    return 0;

	const char *b = o.Text();

	o += 4;

	return
	    (unsigned char)b[0] * (unsigned int)0x1 + 
	    (unsigned char)b[1] * (unsigned int)0x100 +
	    (unsigned char)b[2] * (unsigned int)0x10000 +
	    (unsigned char)b[3] * (unsigned int)0x1000000;
}

P4INT64
StrOps::UnpackInt64( StrRef &o )
{
	if( o.Length() < 8 )
	    return 0;

	const char *b = o.Text();

	o += 8;

	P4INT64 v = 
	    (unsigned char)b[4] * (unsigned int)0x1 + 
	    (unsigned char)b[5] * (unsigned int)0x100 +
	    (unsigned char)b[6] * (unsigned int)0x10000 +
	    (unsigned char)b[7] * (unsigned int)0x1000000;

	// On machines without int64, this will just overflow
	// and zero v, without complaint from the compiler.

	v <<= 16; v <<= 16;

	return v +
	    (unsigned char)b[0] * (unsigned int)0x1 + 
	    (unsigned char)b[1] * (unsigned int)0x100 +
	    (unsigned char)b[2] * (unsigned int)0x10000 +
	    (unsigned char)b[3] * (unsigned int)0x1000000;
}

int
StrOps::UnpackIntA( StrRef &o )
{
	char *buffer = o.Text();
	int length = o.Length();

	int v = 0;
	int s = length && *buffer == '-';

	if( s )
	    ++buffer, --length;

	while( length && *buffer )
	{
	    v = v * 10 + *buffer - '0';
	    ++buffer, --length;
	}

	if( length )
	    ++buffer, --length;

	o.Set( buffer, length );

	return s ? -v : v;
}

void
StrOps::UnpackChar( StrRef &o, char *c, int l )
{
	if( l > o.Length() )
	    l = o.Length();

	char *end;

	// Unpack whole thing

	if( end = (char *)memccpy( c, o.Text(), 0, l ) )
	    l = end - c;

	o += l;
}

void
StrOps::UnpackOctet( StrRef &o, const StrPtr &s )
{
	int l = s.Length();

	if( l > o.Length() )
	    l = o.Length();

	memcpy( s.Text(), o.Text(), l );

	o += l;
}

void
StrOps::UnpackString( StrRef &o, StrBuf &s )
{
	int l = UnpackInt( o );

	if( l > o.Length() )
	    l = o.Length();

	s.Set( o.Text(), l );

	o += l;
}

void
StrOps::UnpackStringA( StrRef &o, StrBuf &s )
{
	int l = UnpackIntA( o );

	if( l > o.Length() )
	    l = o.Length();

	s.Set( o.Text(), l );

	o += l;
}

void
StrOps::UnpackString( StrRef &o, StrRef &s )
{
	int l = UnpackInt( o );

	if( l > o.Length() )
	    l = o.Length();

	s.Set( o.Text(), l );

	o += l;
}

void
StrOps::UnpackStringA( StrRef &o, StrRef &s )
{
	int l = UnpackIntA( o );

	if( l > o.Length() )
	    l = o.Length();

	s.Set( o.Text(), l );

	o += l;
}

/*
 * i18n
 */

int
StrOps::CharCnt( const StrPtr &s )
{
	int cs = GlobalCharSet::Get();

	if( !cs )
	    return s.Length();

	CharStep *step = CharStep::Create( s.Text(), cs );

	int ret = step->CountChars( s.End() );

	delete step;

	return ret;
}

void
StrOps::CharCopy( const StrPtr &s, StrBuf &t, int length )
{
	int charSet;

	if( s.Length() < length )
	{
	    length = s.Length();
	}
	else if( s.Length() > length && ( charSet = GlobalCharSet::Get() ) )
	{
	    // i18n -- copy 'length' characters (possibly many more bytes)

	    int i = 0;

	    CharStep *ss = CharStep::Create( s.Text(), charSet );

	    while( ss->Next() < s.End() && ++i < length )
		;

	    length = ss->Ptr() - s.Text();

	    delete ss;
	}

	t.Set( s.Text(), length );
}

int
StrOps::SafeLen( const StrPtr &s )
{
	int cs = GlobalCharSet::Get();

	if( cs == 1 ) // utf8
	{
	    CharSetUTF8Valid v;
	    const char *rp;

	    if( v.Valid( s.Text(), s.Length(), &rp ) != 1 )
		return rp - s.Text();
	}
	return s.Length();
}

/*
 * StrOps::ScrunchArgs() - try to display argv in a limited output buffer.
 *
 * This scrunches in two ways:
 *
 *	1. If any argument is too long (more than 1/4 the output if there
 *	   are 4 or more args), the argument is clipped to be left...right.
 *
 *	2. If we run out of room even to display even clipped arguments,
 *	   we just output (number-of-skipped-args) and then the last argument.
 */

void
StrOps::ScrunchArgs( StrBuf &out, int argc, StrPtr *argv, int targetLength,
	       int delim, const char *unsafeChars )
{
	if( !argc )
	    return;

	StrBuf dStr;
	dStr.Extend( (char)delim );
	dStr.Terminate();

	// Each arg gets at most 1/4th the targetLength,
	// unless there are fewer than 4 args.

	int pieces = argc < 4 ? argc : 4;
	int eachSpace = targetLength / pieces;

	// Leave room for last argument -- we like to see it.

	int endPost = CharCnt(out) + targetLength;

	int lastargLen = CharCnt(argv[argc-1]);

	endPost -= lastargLen < eachSpace ? lastargLen : eachSpace;

	// For each arg

	for( ; argc--; ++argv )
	{
	    StrBuf argBuf, maskBuf;
	    StrPtr *theArg = argv;
	    if( unsafeChars )
	    {
	        WildToStr( *argv, maskBuf, unsafeChars );
		EncodeNonPrintable( maskBuf, argBuf );
		theArg = &argBuf;
	    }

	    int mySpace = CharCnt(*theArg);
	    int myLength = mySpace;

	    // If there are more args coming, we can take only our
	    // alloted eachSpace, and we may have to skip out on
	    // printing anything if we're already against the endPost.

	    if( argc )
	    {
		// Back off to 1/4 targetLength max

		if( mySpace > eachSpace )
		    mySpace = eachSpace;

		// Will no more args fit?
		// Just mention # of args skipped.
		// We'll still dump the last arg.

		if( mySpace + CharCnt(out) > endPost )
		{
		    out << "(" << argc << ")" << dStr;
		    argv += argc - 1;
		    argc = 1;
		    continue;
		}
	    }

	    // If this arg is bigger than our allocated space,
	    // dump out left...right of arg.
	    // Otherwise, dump whole arg.

	    if( myLength > mySpace )
	    {
		int side = ( mySpace - 3 ) / 2;
		int cs = GlobalCharSet::Get();

		if( !cs )
		{
		    out << StrRef( theArg->Text(), side );
		    out << "...";
		    out << StrRef( theArg->End() - side, side );
		}
		else
		{
		    CharStep *step = CharStep::Create( theArg->Text(), cs );

		    out << StrRef( theArg->Text(),
				step->Next( side ) - theArg->Text() );
		    out << "...";

		    step->Next( myLength - 2 * side );
		    out << StrRef( step->Ptr(), theArg->End() - step->Ptr() );

		    delete step;
		}
	    }
	    else
	    {
		out << *theArg;
	    }

	    // blank between args

	    if( argc )
		out << dStr;
	}
}

/*
 * StrOps::GetDepotFileExtension() - Extracts the .xyz from a path, sans dot.
 */

void
StrOps::GetDepotFileExtension( const StrBuf &path, StrBuf &ext )
{
	const char *dot = strrchr( path.Text(), '.' );
	const char *sep = strrchr( path.Text(), '/' );

	// file
	// di.r/file
	
	if( !dot || sep >= dot )
	    return;

	// file..
	if( ( path.Length() - ( dot - path.Text() ) ) > 0 )
	    // file.txt -> 'txt'
	    ext.Set( dot + 1 );
}

/*
 * StrOps::GetDepotName() - extracts the depot name from a depot path
 */

void
StrOps::GetDepotName( const char *d, StrBuf &n )
{
	const char *s = strstr( d, "//" );
	const char *p = d + 2;

	if( !s || s != d )
	    return;

	s = strstr( p, "/" );

	if( !s )
	    return;

	n.Append( p, s - p );
}


/*
 * StrOps::StreamNameInPath() - extract stream name from a depotFile & depth
 */

int
StrOps::StreamNameInPath( const char *dFile, int depth, StrBuf &name )
{

	int slash = 0;
	const char *t = ( dFile  + 2 );

	// string to depth+1 slashes then remove trailing slash

	for( slash = 0; slash < depth + 1; slash++, t++ )
	{
	    t = strchr( t, '/' );
	    if( !t ) return 0;
	}

	name.Append( dFile, --t - dFile );

	return --slash;

}

/*
 * StrOps::CommonPath() - Build a common file path given multiple depotpaths.
 *
 * Common path result is passed in as the first argument,  the second
 * argument maintains a state that will indicate that paths are from multiple
 * directories (will need ...) appended. The third argument is the next
 * depotfile for consideration.
 *
 * e.g.
 *	StrBuf root;
 *	int mdir = 0;
 *
 *	StrOps::CommonPath( root, mdir, depotPath1 );
 *	StrOps::CommonPath( root, mdir, depotPath2 );
 *	StrOps::CommonPath( root, mdir, depotPath3 );
 *	StrOps::CommonPath( root, mdir, depotPath4 );
 *	StrOps::CommonPath( root, mdir, depotPath5 );
 *
 *	if( mdir )
 *	    root.Append( "..." );
 *	else
 *	    root.Append( "*" );
 */

void
StrOps::CommonPath( StrBuf &o, int &mdir, const StrPtr &n )
{
	if( o.Length()  )
	{
	    char *op = o.Text();
	    char *np = n.Text();

	    while( op < o.End() && StrPtr::SEqual( *op, *np ) )
	        ++op, ++np;

	    // check to see if multiple directories

	    if( !mdir && ( strchr( op, '/' ) || strchr( np, '/' ) ) )
	        mdir = 1;

	    if( mdir && op[-1] == '.' )
	        o.SetEnd( op - 1 );
	    else
	        o.SetEnd( op );
	}
	else
	{
	    o = n;

	    char *s = o.Text();
	    char *e = o.End();

	    while( e > s && *e != '/')
	        --e;

	    o.SetEnd( ++e );
	}
}

/*
 * StrOps::StripNewline() - strip \r\n from end of buffer
 */

void
StrOps::StripNewline( StrBuf &o )
{
	if( o.Length() && o.End()[ -1 ] == '\n' )
	    o.SetEnd( o.End() -1 );
	if( o.Length() && o.End()[ -1 ] == '\r' )
	    o.SetEnd( o.End() -1 );

	o.Terminate();
}

void
StrOps::EncodeNonPrintable( const StrPtr &i, StrBuf &o, int maskp, int cmdSafe)
{
	o.Clear();

	char *p = i.Text();
	char *s;

	while( *p )
	{
	    s = p;

	    while( *p )
	    {
	        if( !cmdSafe && !isAprint( p ) )
	            break;
	        else if( cmdSafe && ( isAhighchar( p ) || !isAalnum( p ) ) )
	            break;
	        else if( maskp && *p == '%' )
	            break;

	        ++p;
	    }

	    o.Append( s, p - s );

	    if( *p )
	    {
	        char buf[3];

	        buf[0] = '%';
	        buf[1] = OtoX( ( *p >> 4 ) & 0x0f );
	        buf[2] = OtoX( ( *p++ >> 0 ) & 0x0f );

	        o.Append( buf, 3 );
	    }
	}
}

void
StrOps::DecodeNonPrintable( const StrPtr &i, StrBuf &o )
{
	o.Clear();

	char *p = i.Text();
	char *s;

	while( *p )
	{
	    s = p;

	    while( *p )
	    {
	        if( p[0] == '%' && p[1] == '%' )
	           p += 2;
	        else if( p[0] != '%' )
	           p++;
	        else
	           break;
	    }

	    o.Append( s, p - s );

	    if( *p )
	    {
	        char b[2];

	        b[0] = ( XtoO( p[1] ) << 4 ) | ( XtoO( p[2] ) << 0 );

	        o.Append( b, 1 );

	        p += 3;
	    }
	}
}

void
StrOps::LFtoCRLF( const StrBuf *in, StrBuf *out )
{
	out->Clear();

        const char *s = in->Text(), *p = s;
        while( ( p - s ) < in->Length() )
        {
            if( *p == '\n' )
                out->Extend( '\r' );
            out->Extend( *p );
            p++;
        }

        out->Terminate();
}

unsigned int
StrOps::HashStringToBucket( const StrPtr &in, int buckets )
{
	unsigned int tot = 0;
	unsigned char *s = (unsigned char *)in.Text();
	for( int i = 0; i<in.Length(); ++i )
	    tot = CHARHASH( tot, *s++ );
	return( tot%buckets );
}
