/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * specdef.cc -- SpecElem methods
 */

# include <stdhdrs.h>

# include <strbuf.h>
# include <vararray.h>
# include <error.h>

# include "spec.h"
# include <msgdb.h>

const char *const SpecTypes[] = {

	"word",		// SDT_WORD
	"wlist",	// SDT_WORDLIST
	"select",	// SDT_SELECT
	"line",		// SDT_LINE
	"llist",	// SDT_LINELIST
	"date",		// SDT_DATE
	"text",		// SDT_TEXT
	"bulk",		// SDT_BULK
	0,		

} ;

const char *const SpecOpts[] = {

	"optional",	// SDO_OPTIONAL
	"default",	// SDO_DEFAULT
	"required",	// SDO_REQUIRED
	"once",		// SDO_ONCE
	"always",	// SDO_ALWAYS
	"key",		// SDO_KEY
	"empty",	// SDO_KEY
	0
} ;

const char *const SpecFmts[] = {
	
	"normal",	// SDF_NORMAL
	"L",		// SDF_LEFT
	"R",		// SDF_RIGHT
	"I",		// SDF_INDENT
	"C",		// SDF_COMMENT
	0
} ;

const char *const SpecOpens[] = {

	"none",		// SDO_NOTOPEN
	"isolate",	// SDO_ISOLATE
	"propagate",	// SDO_PROPAGATE
	0
} ;

const char *
SpecElem::FmtType()
{
	return SpecTypes[ type ];
}

const char *
SpecElem::FmtOpt()
{
	return SpecOpts[ opt ];
}

const char *
SpecElem::FmtFmt()
{
	return SpecFmts[ fmt ];
}

const char *
SpecElem::FmtOpen()
{
	return SpecOpens[ open ];
}

void
SpecElem::SetType( const char *typeName, Error *e )
{
	for( int j = 0; SpecTypes[j]; j++ )
	    if( !strcmp( SpecTypes[j], typeName ) )
	{
	    type = (SpecType)j;
	    return;
	}

	e->Set( MsgDb::FieldTypeBad ) << typeName << tag;
}

void
SpecElem::SetFmt( const char *fmtName, Error *e )
{
	for( int j = 0; SpecFmts[j]; j++ )
	    if( !strcmp( SpecFmts[j], fmtName ) )
	{
	    fmt = (SpecFmt)j;
	    return;
	}

	// Error is optional.
	// Unknown FMT codes allowed.

	if( !e )
	    return;

	e->Set( MsgDb::FieldTypeBad ) << fmtName << tag;
}

void
SpecElem::SetOpt( const char *optName, Error *e )
{
	for( int j = 0; SpecOpts[j]; j++ )
	    if( !strcmp( SpecOpts[j], optName ) )
	{
	    opt = (SpecOpt)j;
	    return;
	}

	e->Set( MsgDb::FieldOptBad ) << optName << tag;
}

void
SpecElem::SetOpen( const char *openName, Error *e )
{
	for( int j = 0; SpecOpens[j]; j++ )
	    if( !strcmp( SpecOpens[j], openName ) )
	{
	    open = (SpecOpen)j;
	    return;
	}

	e->Set( MsgDb::FieldOptBad ) << openName << tag;
}

/*
 * SpecElem::Compare() - compare SpecElems from different specs
 */

int
SpecElem::Compare( const SpecElem &other )
{
	// These can change:
	// fmt, seq, maxLength, preset

	return 
	    tag != other.tag || code != other.code ||
	    type != other.type || opt != other.opt ||
	    nWords != other.nWords || values != other.values ||
	    open != other.open;
}

/*
 * SpecElem::Encode() -- encode a single SpecElem elem
 * SpecElem::Decode() -- decode a single SpecElem elem
 */

void
SpecElem::Encode( StrBuf *s, int c )
{
	// SDO_KEY is internal only, introduced in 2003.1

	*s << tag;

	if( code != c )
	    *s << ";code:" << code;

	if( type != SDT_WORD )
	    *s << ";type:" << SpecTypes[ type ];

	if( opt != SDO_OPTIONAL && opt != SDO_KEY && opt != SDO_EMPTY )
	    *s << ";opt:" << SpecOpts[ opt ];

	if( fmt != SDF_NORMAL )
	    *s << ";fmt:" << SpecFmts[ fmt ];

	if( open != SDO_NOTOPEN )
	    *s << ";open:" << SpecOpens[ open ];

	if( IsWords() && nWords != 1 )
	    *s << ";words:" << nWords;

	if( IsWords() && maxWords != 0 )
	    *s << ";maxwords:" << maxWords;

	if( IsRequired() )
	    *s << ";rq";

	if( IsReadOnly() )
	    *s << ";ro";

	if( AllowEmpty() )
	    *s << ";z";

	if( seq )
	    *s << ";seq:" << seq;

	if( maxLength )
	    *s << ";len:" << maxLength;

	if( HasPresets() )
	    *s << ";pre:" << GetPresets();

	if( values.Length() )
	    *s << ";val:" << values;

	*s << ";;";
}

void
SpecElem::Decode( StrRef *s, Error *e )
{
	// ro and rq from 98.2 specs.

	int isReadOnly = 0;
	int isRequired = 0;

	// other pseudo options

	int allowEmpty = 0;

	// w = beginning, y = end, b = char after first ;

	char *w = s->Text();
	char *y = w + s->Length();
	char *b;

	if( b = strchr( w, ';' ) ) *b++ = 0; else b = y;

	// save tag

	tag = w;

	// walk remaining formatter

	while( b != y )
	{
	    char *q;
	    w = b;

	    if( b = strchr( w, ';' ) ) *b++ = 0; else b = y;
	    if( q = strchr( w, ':' ) ) *q++ = 0; else q = b;

	    if( !*w ) break;

	    if( !strcmp( w, "words" ) ) nWords = atoi( q );
	    else if( !strcmp( w, "maxwords" ) ) maxWords = atoi( q );
	    else if( !strcmp( w, "code" ) ) code = atoi( q );
	    else if( !strcmp( w, "type" ) ) SetType( q, e );
	    else if( !strcmp( w, "opt" ) ) SetOpt( q, e );
	    else if( !strcmp( w, "pre" ) ) SetPresets( q );
	    else if( !strcmp( w, "val" ) ) values = q;
	    else if( !strcmp( w, "rq" ) ) isRequired = 1;
	    else if( !strcmp( w, "ro" ) ) isReadOnly = 1;
	    else if( !strcmp( w, "len" ) ) maxLength = atoi( q );
	    else if( !strcmp( w, "seq" ) ) seq = atoi( q );
	    else if( !strcmp( w, "fmt" ) ) SetFmt( q, 0 );
	    else if( !strcmp( w, "open" ) ) SetOpen( q, e );
	    else if( !strcmp( w, "z" ) ) allowEmpty = 1;

	    // OK if we don't recognise code!
	}

	/*
	 * opt: was supposed to supplant the ro/rq flags, but as of
	 * 2003.1 it shows up (a) as opt:default for a few built-in
	 * spec strings, (b) as opt:required (wrongly!) when p4 change
	 * re-encodes its ro;rq spec string, and (c) in job specs.
	 *
	 * For cases other than these, we map ro/rq to an opt.  Note
	 * that ro;rq maps to SDO_KEY, just so that IsReadOnly() and
	 * IsRequired() can return true.
	 *
	 * ro rq z               IsReadOnly() IsRequired()
	 * 0  0  x -> SDO_OPTIONAL     0           0       
	 * 0  1  x -> SDO_REQUIRED     0           1
	 * x  x  x -> SDO_ONCE         1           0
	 * 1  0  x -> SDO_ALWAYS       1           0
	 * 1  1  x -> SDO_KEY          1           1
	 * x  x  1 -> SDO_EMPTY        0           1
	 *
	 * For (b), where pre-2003.1 servers mistakenly encoded ro;rq 
	 * as SDO_REQUIRED, we combine that with ro to make it SDO_KEY.
	 */

	if( allowEmpty )
	{
	    opt = SDO_EMPTY;
	}
	else if( opt == SDO_OPTIONAL )
	{
	    if( isRequired && isReadOnly ) opt = SDO_KEY;
	    else if( isRequired ) opt = SDO_REQUIRED;
	    else if( isReadOnly ) opt = SDO_ALWAYS;
	}
	else if( opt == SDO_REQUIRED && isReadOnly )
	{
	    opt = SDO_KEY;
	}

	s->Set( b, y - b );
}

/*
 * SpecElem::CheckValue() - ensure value is one of the SpecElem::values
 */

int
SpecElem::CheckValue( StrBuf &value )
{
	// No values - anything is AOK
	// We don't check lines, yet.

	if( !values.Length() || type != SDT_SELECT )
	    return 1;

	// Split those suckers at / and look for a value

	StrBuf split = values;
	char *p = split.Text();

	for(;;)
	{
	    char *np;
	    StrRef r;

	    // Break at next /

	    if( np = strchr( p, '/' ) )
	    {
		r.Set( p, np - p );
		*np = 0;
	    }
	    else
	    {
		r.Set( p );
	    }

	    // If match (while folding case)
	    // save case-correct value from 'values'

	    if( !value.CCompare( r ) )
	    {
		value.Set( r );
		return 1;
	    }

	    // No more /'s?

	    if( !np )
		return 0;

	    p = np + 1;
	}
}

const StrPtr
SpecElem::GetPreset( const char *name )
{
	// Only SELECT allows for presets of condition/val

	if( type != SDT_SELECT )
	    return name ? StrRef::Null() : presets;

	// Look for a preset with the named condition

	int l = name ? strlen( name ) : 0;
	const char *p = presets.Text();
	const char *e = presets.End();

	for(;;)
	{
	    const char *c = strchr( p, ',' );
	    const char *s = strchr( p, '/' );

	    // foo
	    // foo,more
	    // foo,more/more

	    if( !l && ( !s || c && c < s ) )
	    {
		preset.Set( p, ( c ? c : e ) - p );
		return preset;
	    }

	    // name/foo
	    // name/foo,more

	    if( l == s - p && !strncmp( name, p, l ) && ( !c || c > s ) )
	    {
		preset.Set( s + 1, ( c ? c : e ) - s - 1 );
		return preset;
	    }

	    // try next

	    if( !c )
		return StrRef::Null();

	    p = c + 1;
	}
}

