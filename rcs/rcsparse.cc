/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsparse.c - parse an RCS file into an RcsArchive structure
 *
 * Methods defined:
 *
 *	RcsArchive::Parse() - parse the whole RCS archive
 *
 * Internal classes:
 *
 *	RcsParse - the parser
 *
 * Internal methods:
 *
 *	RcsParse::Put() - create RcsParse struct
 *	RcsParse::Free() - free RcsParse struct
 *	RcsParse::SetError() - emit an error and quit
 *	RcsParse::Token() - read a single token (could be a big block)
 *	RcsParse::Lookup() - lookup token as a keyword
 *	RcsParse::Expect() - read a token and quit if it isn't the right one
 *	RcsParse::List() - parse the accces, lock, symbol or branch list 
 *	RcsParse::RevHeaders() - parse a revision header
 *	RcsParse::Description() - parse a reivison description
 *	RcsParse::RevLogs() - parse a revision log
 *
 * History:
 *	5-13-95 (seiwald) - added lost support for 'branch rev' in ,v header.
 *	12-17-95 (seiwald) - added support for 'expand flag' in ,v header.
 *	2-18-97 (seiwald) - translated to C++.
 *	10-25-97 (seiwald) - added support for MKS "format binary" and
 *				"ext @xxx@" fields.
 */

# define NEED_TYPES

# include <stdhdrs.h>
# include <ctype.h>

# include <error.h>
# include <debug.h>
# include <strbuf.h>
# include <readfile.h>

# include "rcsdebug.h"
# include "rcsarch.h"
# include "rcsrev.h"
# include <msglbr.h>

const int RCS_MAX_TOKEN = 128;

enum RcsToken
{
	RCS_T_EOF = 0, RCS_T_SEMICOLON, RCS_T_COLON,
	RCS_T_ATBLOCK, RCS_T_COMMA, RCS_T_HEAD,
	RCS_T_ACCESS, RCS_T_SYMBOLS, RCS_T_LOCKS,
	RCS_T_STRICT, RCS_T_COMMENT, RCS_T_DATE,
	RCS_T_BRANCHES, RCS_T_AUTHOR, RCS_T_STATE,
	RCS_T_NEXT, RCS_T_DESC, RCS_T_LOG, RCS_T_TEXT,
	RCS_T_NAME, RCS_T_STRING, RCS_T_REVISION, 
	RCS_T_BRANCH, RCS_T_EXPAND, RCS_T_FORMAT, 
	RCS_T_EXT

} ;

struct RcsParse
{
    public:
			RcsParse( ReadFile *file );

	void		Expect( RcsToken token, Error *e );
	void		List( RcsList **headPtr, Error *e );
	void		OptRev( RcsText *t, const char *trace, Error *e );
	void		RevHeaders( RcsArchive *ra, Error *e );
	void		RevLogs( RcsArchive *archive, Error *e );
	void		SetError( Error *e );
	RcsToken	Token( Error *e );
	RcsToken	Lookup( RcsToken token );

    public:

	ReadFile *file;

	/* Tracing purposes only */

	int	lineno;

	/* Scanned chunks */

	RcsChunk chunk;

	/* Scanned text */

	int	textlen;
	char	text[ RCS_MAX_TOKEN ];

} ;

static const char *const tokenNames[] =
{
	"EOF",
	";",
	":",
	"@",
	",",
	"head",
	"access",
	"symbols",
	"locks",
	"strict",
	"comment",
	"date",
	"branches",
	"author",
	"state",
	"next",
	"desc",
	"log",
	"text",
	"name",
	"<string>",
	"<rev>",
	"branch",
	"expand",
	"format",
	"ext"
} ;

static const struct {
	char		name[9];
	int		length;
	RcsToken	token;
} tokens[] = {
	/* Longest to shortest! */

	"branches",	8,	RCS_T_BRANCHES,
	"symbols",	7,	RCS_T_SYMBOLS,
	"comment",	7,	RCS_T_COMMENT,
	"strict",	6,	RCS_T_STRICT,
	"branch",	6,	RCS_T_BRANCH,
	"author",	6,	RCS_T_AUTHOR,
	"access",	6,	RCS_T_ACCESS,
	"expand",	6,	RCS_T_EXPAND,
	"format",	6,	RCS_T_FORMAT,
	"state",	5,	RCS_T_STATE,
	"locks",	5,	RCS_T_LOCKS,
	"text",		4,	RCS_T_TEXT,
	"next",		4,	RCS_T_NEXT,
	"head",		4,	RCS_T_HEAD,
	"desc",		4,	RCS_T_DESC,
	"date",		4,	RCS_T_DATE,
	"ext",		3,	RCS_T_EXT,
	"log",		3,	RCS_T_LOG,
	"",		-1,	RCS_T_EOF
} ;

/* see if a character is RCS whitespace, immune from ctype. */

static const char whiteTab[] = {
    0,0,0,0,0,0,0,0,1,1,1,1,1,1,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
} ;

# define iswhite(c) whiteTab[ (unsigned char)(c) ]

RcsParse::RcsParse( 
	ReadFile *rf )
{
	file = rf;
	lineno = 1;
	textlen = 0;
}

void
RcsParse::SetError( Error *e )
{
	e->Set( MsgLbr::Parse ) << lineno;
}

RcsToken
RcsParse::Token( Error *e )
{
	register ReadFile * const rf = file;

	/* suck up whitespace */

	while( !rf->Eof() && iswhite( rf->Char() ) )
	{
	    if( rf->Char() == '\n' )
		++lineno;
	    rf->Next();
	}

	/* single character tokens */

	if( rf->Eof() )
	    return RCS_T_EOF;

	switch( rf->Char() )
	{
	case ';': rf->Next(); return( RCS_T_SEMICOLON );
	case ':': rf->Next(); return( RCS_T_COLON );
	case ',': rf->Next(); return( RCS_T_COMMA );
	case '%': rf->Next();

		/* Handle blocks preceeded with %bytes */

		{
		    int n;
		    char linebuf[ 32 ];

		    n = rf->Memccpy( linebuf, '\n', sizeof( linebuf ) - 1 );

		    linebuf[ n ] = '\0';

		    chunk.file = rf;
		    chunk.offset = rf->Tell();
		    chunk.length = StrRef( linebuf ).Atoi64();
		    chunk.atWork = RCS_CHUNK_ATCLEAN;

		    rf->Seek( chunk.offset + chunk.length );

		    return RCS_T_ATBLOCK;
		}

	case '@': rf->Next();

		/* Handle blocks quoted with @'s */

		chunk.file = rf;
		chunk.offset = rf->Tell();
		chunk.atWork = RCS_CHUNK_ATCLEAN;

		for(;;)
		{
		    if( rf->Eof() )
		    {
			e->Set( MsgLbr::EofAt );
			return RCS_T_EOF;
		    }

		    /* This blows the lineno, but is really fast. */
		    /* Lineno is good for errors and tracing, though */

		    if( !DEBUG_ANY )
			rf->Memchr( '@', -1 );

		    if( rf->Eof() )
		    {
			e->Set( MsgLbr::EofAt );
			return RCS_T_EOF;
		    }

		    switch( rf->Char() )
		    {
		    case '@':
			/* Check for @@ (quoted @) */

			rf->Next();

			if( rf->Eof() || rf->Char() != '@' )
			{
			    chunk.length = rf->Tell() - 1 - chunk.offset;
			    return RCS_T_ATBLOCK;
			}

			/* Note that this block contains quoted @'s */

			chunk.atWork = RCS_CHUNK_ATDOUBLE;

			break;

		    case '\n':
			++lineno;
			break;

		    default:
			break;
		    }

		    rf->Next();
		}
		/* NOTREACHED */

	}

	/* Parse a word */

	int isx = 1;

	{
	    char *p = text;

	    do 
	    {
		if( p >= text + RCS_MAX_TOKEN )
		{
		    e->Set( MsgLbr::TooBig );
		    return RCS_T_EOF;
		}

		if( isx && !( isdigit( rf->Char() ) || rf->Char() == '.' ) )
		    isx = 0;

		*p++ = rf->Char();
		rf->Next();

	    } while( !rf->Eof() && !iswhite( rf->Char() ) && 
			rf->Char() != ':' && 
			rf->Char() != ';' && 
			rf->Char() != '@' );

	    textlen = p - text;

	    *p++ = 0;
	}

	/* revision numbers */

	if( textlen && isx )
	    return( RCS_T_REVISION );


	return( RCS_T_STRING );
}

RcsToken 
RcsParse::Lookup( RcsToken token )
{
	/* Now look for wordy tokens */
	/* Token list is sorted by length - abort search early if possible. */

	if( token != RCS_T_STRING )
	    return token;

	for( int i = 0; textlen <= tokens[i].length; i++ )
	{
	    if( textlen == tokens[i].length &&
		!strcmp( text, tokens[i].name ) )
	    {
		if( DEBUG_PARSE_FINE )
	    	    p4debug.printf( "%d: %s\n", lineno, text );
		 return( tokens[i].token );
	    }
	}

	return RCS_T_STRING;
}

void
RcsParse::Expect(
	RcsToken token, 
	Error *e )
{
	RcsToken nt = Token( e );

	if( e->Test() )
	    return;

	if( token != RCS_T_STRING )
	    nt = Lookup( nt );

	if( nt != token )
	    e->Set( MsgLbr::Expect ) << tokenNames[ token ] << tokenNames[ nt ];
}

void
RcsParse::OptRev( 
	RcsText *t,
	const char *trace,
	Error *e )
{
	switch( Token( e ) )
	{
	case RCS_T_REVISION:
		t->Save( text, textlen, trace );
		Expect( RCS_T_SEMICOLON, e );
		break;

	case RCS_T_SEMICOLON:
		break;

	default:
		e->Set( MsgLbr::ExpRev );
		break;
	}
}

void
RcsParse::List(
	RcsList **headPtr,
	Error *e )
{
	RcsList *list = 0;
	int last = 0;

	*headPtr = 0;

	while( !e->Test() )
	{
	    switch( Token( e ) )
	    {
	    case RCS_T_COMMA:
		Expect( RCS_T_STRING, e );
		/* fall through */

	    case RCS_T_STRING:
		list = new RcsList( headPtr );
		list->string.Save( text, textlen, "str" );
		last = RCS_T_STRING;
		break;

	    case RCS_T_COLON:
		Expect( RCS_T_REVISION, e );

		if( e->Test() )
		    break;

		/* fall through */

	    case RCS_T_REVISION:
		if( last != RCS_T_STRING )
		    list = new RcsList( headPtr );
		list->revision.Save( text, textlen, "rev" );
		last = RCS_T_REVISION;
		break;

	    case RCS_T_SEMICOLON:
		return;

	    default:
		e->Set( MsgLbr::ExpSemi );
		break;
	    }
	}
}

void
RcsParse::RevHeaders(
	RcsArchive *ra,
	Error *e )
{
	RcsRev *rev = ra->AddRevision( text, 1, 0, e );

	if( !rev )
	    return;

	Expect( RCS_T_DATE, e );
	Expect( RCS_T_REVISION, e );
	rev->date.Save( text, textlen, "date" );
	Expect( RCS_T_SEMICOLON, e );

	Expect( RCS_T_AUTHOR, e );
	Expect( RCS_T_STRING, e );
	rev->author.Save( text, textlen, "author" );
	Expect( RCS_T_SEMICOLON, e );

	Expect( RCS_T_STATE, e );
	Expect( RCS_T_STRING, e );
	rev->state.Save( text, textlen, "state" );
	Expect( RCS_T_SEMICOLON, e );

	Expect( RCS_T_BRANCHES, e );
	List( &rev->branches, e ); 

	Expect( RCS_T_NEXT, e );
	OptRev( &rev->next, "next", e );
}

void
RcsParse::RevLogs(
	RcsArchive *archive,
	Error *e )
{
	RcsRev *rev = archive->FindRevision( text, e );

	if( DEBUG_PARSE )
	    p4debug.printf( "rev %s = %x\n", text, rev );

	if( !rev )
	{
	    e->Set( MsgLbr::RevLess );
	    return;
	}

	if( rev->text.file )
	{
	    if( DEBUG_PARSE )
		p4debug.printf( "rev %s duplicate log! ignoring duplicate\n", text );

	    Expect( RCS_T_LOG, e );
	    Expect( RCS_T_ATBLOCK, e );

	    Expect( RCS_T_TEXT, e );
	    Expect( RCS_T_ATBLOCK, e );

	    return;
	}

	Expect( RCS_T_LOG, e );
	Expect( RCS_T_ATBLOCK, e );
	rev->log.Save( &chunk, "log" );

	Expect( RCS_T_TEXT, e );
	Expect( RCS_T_ATBLOCK, e );
	rev->text.Save( &chunk, "text" );
}

void
RcsArchive::Parse(
	ReadFile *rf,
	const char *toThisRev,
	Error *e )
{
	RcsParse *rp = new RcsParse( rf );
	int bail = 0;

	if( DEBUG_PARSE )
		p4debug.printf( "*** - archive header - ***\n" );

	while( !e->Test() )
	{
	    switch( rp->Lookup( rp->Token( e ) ) )
	    {
	    case RCS_T_HEAD:
		rp->Expect( RCS_T_REVISION, e );
		headRev.Save( rp->text, rp->textlen, "head" );
		rp->Expect( RCS_T_SEMICOLON, e );
		break;

	    case RCS_T_BRANCH:
		rp->OptRev( &branchRev, "branch", e );
		break;

	    case RCS_T_ACCESS:
		rp->List( &accessList, e );
		break;

	    case RCS_T_SYMBOLS:
		rp->List( &symbolList, e );
		break;

	    case RCS_T_LOCKS:
		rp->List( &lockList, e );
		break;

	    case RCS_T_STRICT:
		strict = 1;
		rp->Expect( RCS_T_SEMICOLON, e );
		break;

	    case RCS_T_COMMENT:
		rp->Expect( RCS_T_ATBLOCK, e );
		comment.Save( &rp->chunk, "comment" );
		rp->Expect( RCS_T_SEMICOLON, e );
		break;

	    case RCS_T_EXPAND:
		rp->Expect( RCS_T_ATBLOCK, e );
		expand.Save( &rp->chunk, "expand" );
		rp->Expect( RCS_T_SEMICOLON, e );
		break;

	    case RCS_T_REVISION:
		rp->RevHeaders( this, e );
		break;

	    case RCS_T_FORMAT:
		rp->Expect( RCS_T_STRING, e );
		rp->Expect( RCS_T_SEMICOLON, e );
		break;

	    case RCS_T_EXT:
		rp->Expect( RCS_T_ATBLOCK, e );
		break;

	    case RCS_T_DESC:
		rp->Expect( RCS_T_ATBLOCK, e );
		desc.Save( &rp->chunk, "desc");
		goto next;

	    default:
		e->Set( MsgLbr::ExpDesc );
		goto next;
	    }
	}

    next:
	if( DEBUG_PARSE )
		p4debug.printf( "*** - revision logs - ***\n" );

	/* Only shortcut toThisRev if it is on the trunk */

	if( toThisRev && headRev.text )
	{
	    switch( RcsRevCmp( headRev.text, toThisRev ) )
	    {
		default:
		    toThisRev = 0;

		case REV_CMP_EQUAL:
		case REV_CMP_UP_TRUNK:
		    break;
	    }
	}

	while( !e->Test() && !bail )
	{
	    switch( rp->Token( e ) )
	    {
	    case RCS_T_REVISION:

		if( toThisRev && !strcmp( rp->text, toThisRev ) )
		    bail++;

		rp->RevLogs( this, e );
		continue;

	    case RCS_T_EOF:	
		goto done;

	    default:
		e->Set( MsgLbr::ExpEof );
		goto done;
	    }
	}
    
    done:

	/* Add our own error */

	if( e->Test() )
	    rp->SetError( e );

	/* Clean up and return */

	if( rp )
	    delete rp;
}
