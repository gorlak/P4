/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * specparse.cc - tokenizer for ascii 'specifications'
 *
 *	This is a scanner whose job it is to return elements from a 
 *	change/client/branch/label/etc form.  It doesn't recognize any 
 *	of the keywords, but uses indentation, punctuation (:), and 
 *	newlines to tokenize.  The scanner is embodied in a simple state 
 *	transition table.
 *
 *	This scanner returns one token for each call.  If it isn't an
 *	error or EOS (end of string), the value is returned in the provided
 *	StrBuf buffer.
 *
 *	If isTextBlock is set, the scanner works a little differently:
 *	instead of returning individual lines, it returns all lines as
 *	one big clump.  In this case #comments are ignored, unless they
 *	begin the line.
 *
 * This scanner accepts the following input:
 *
 *	# comments at the beginning of lines are always stripped
 *
 *	Tag1:	word ...
 *
 *	Tag2:
 *		word ... #ending comment is stripped
 *		word ... #comment is stripped
 *
 *	Tag3:
 *		Text block spanning
 *		multiple lines
 *	# left comment is a comment
 *		#indented comment is part of text block
 */

# include <stdhdrs.h>

# include <error.h>
# include <strbuf.h>
# include <debug.h>

# include "specchar.h"
# include <msgdb.h>
# include "specparse.h"

# define DEBUG_PARSE	( p4debug.GetLevel( DT_SPEC ) >= 5 )

enum SpecParseState {
	sS,	// START - no input
	sT,	// TAG - in tag, seeking :
	stU,	// TAGV - after :, skipping whitespace 
	stV,	// VAL - in value, seeking newline
	stX,	// LOOK - is this indent or tag?
	stY,	// IND - in indent, seeking value
	sQ,	// QUOTE - in quote, seeking endquote
	sR,	// QUOTE2 - 2nd+ line of quote, seeking endquote
	sbU,	// TAGV - looking for start of text block
	sbV,	// VAL - in text block, seeking newline
	sbX,	// LOOK - is this indent or tag?
	sbY	// IND - in indent, seeking text block
} ;

enum SpecParseActions {
	a0, // return EOS (no advance)
	aA, // advance past char in input
	aB, // advance past blank in input
	aC, // comment - advance until past EOL
	aD, // return value (no advance)
	aE, // return error (no advance)
	aG, // return error "no endquote"
	aN, // advance & count newline
	aR, // advance, save start
	aQ, // save end of line
	aS, // save start, advance
	aT, // return tag, advance
	aV, // return value at newline, advance until past EOL
	aW, // append line to textBlock
	aX // append line & newline to textBlock
} ;

static const struct transition {
	SpecParseState		state;
	SpecParseActions	act;
} trans[12][7] = {

/*		cSPACE	cNL	cCOLON	cPOUND	cQUOTE	cMISC	cEOS */
/*------------------------------------------------------------------ */
/* S START */ {	sS,aA,  sS,aA,  sS,aE,  sS,aC,  sT,aS,  sT,aS,  sS,a0 },  
/* T TAG */   {	sS,aE,  sS,aE,  stU,aT, sS,aE,  sT,aA,  sT,aA,  sS,aE },  

/* tU TAGV */ {	stU,aA, stX,aA, stV,aS, stU,aC, sQ,aS,  stV,aS, sS,aE },  
/* tV VAL */  {	stV,aB, stX,aV, stV,aA, stX,aV, sQ,aA,  stV,aA, stX,aV },
/* tX LOOK */ {	stY,aR, stX,aN, sS,aE,  stX,aC, sS,aD,  sS,aD,  sS,aD },  
/* tY IND */  {	stY,aR, stX,aN, stV,aA, stX,aC, sQ,aA,  stV,aA, sS,aE },  

/* Q QUOTE */ {	sQ,aA,  sR,aQ,  sQ,aA,  sQ,aA,  stV,aA, sQ,aA,  sR,aQ },
/* R QUOTE2*/ {	sR,aA,  sR,aA,  sR,aA,  sR,aA,  stV,aA, sR,aA,  sQ,aG },

/* bU TAGV */ {	sbU,aA, sbX,aA, sbV,aS, sbV,aS, sbV,aS, sbV,aS, sS,aE },  
/* bV VAL */  {	sbV,aA, sbX,aW, sbV,aA, sbV,aA, sbV,aA, sbV,aA, sbX,aX },
/* bX LOOK */ {	sbY,aR, sbX,aN, sS,aE,  sbX,aC, sS,aD,  sS,aD,  sS,aD },  
/* bY IND */  {	sbY,aA, sbX,aN, sbV,aA, sbV,aA, sbV,aA, sbV,aA, sS,aE },  

};

const char *const stateNames[] = { 
	"START",
	"TAG",
	"tTAGV",
	"tVAL",
	"tLOOK",
	"tIND",
	"QUOTE",
	"QUOTE2",
	"bTAGV",
	"bVAL",
	"bLOOK",
	"bIND",
};

const char *const actNames[] = { 
	"EOS",
	"advance",
	"advance blank",
	"comment",
	"done values",
	"error",
	"no endquote",
	"add newline",
	"save start after advance",
	"save eol",
	"save start",
	"return tag",
	"return value",
	"append line",
	"append line + nl",
};

SpecParse::SpecParse( 
	const char *buffer )
{
	state = sS;
	c.Set( buffer );
}

SpecParseReturn
SpecParse::GetToken(
	int isTextBlock,
	StrBuf *value,
	Error *e )
{
	const char *start = c.p, *end = c.p;
	const char *eol = 0;
	addNewLine = 0;

	if( isTextBlock )
	{
	    value->Set( "",0 );
	    savedBlankLines = 0;
	}

	for(;;)
	{
	    // Start of ':', comments are single line

	    if( state == stU )
	        ++addNewLine;

	    // For text blocks, skip into block mode

	    if( isTextBlock && state == stU ) 
		state = sbU;

	    // Do state transition.

	    const struct transition *t = &trans[ state ][ c.cc ];

	    if( DEBUG_PARSE )
		p4debug.printf( "x[%s][%s] -> %s\n", 
		    stateNames[ state ],
		    c.CharName(),
		    actNames[ t->act ] );

	    state = t->state;

	    // Do state table's action.

	    switch( t->act )
	    {
	    case a0: // EOS
		return SR_EOS;

	    case aA: // advance
		c.Advance();
		end = c.p;
		break;

	    case aB: // advance blank
		c.Advance();
		break;

	    case aC: // comment
		if( c.cc == cEOS || c.cc == cNL )
	            break;
	        c.Advance();
	        if( c.cc == cPOUND )
	        {
	            while( c.cc != cEOS && c.cc != cNL )
	                c.Advance();
	            end = c.p;
	            value->Set( start, end - start );
	            return addNewLine ? SR_COMMENT_NL
	                              : SR_COMMENT;
	        }
	        while( c.cc != cEOS && c.cc != cNL )
	            c.Advance();
	        break;

	    case aD: // done with values
		return isTextBlock ? SR_VALUE : SR_DONEV;

	    case aE: // error
		value->Set( start, end - start );
		e->Set( MsgDb::Syntax ) << *value;
		return SR_EOS;

	    case aG: // no endquote 
		value->Set( start, eol - start );
		e->Set( MsgDb::NoEndQuote ) << *value;
		return SR_EOS;

	    case aN: // add newline
		c.Advance();
		++addNewLine;
		if( isTextBlock )
		    ++savedBlankLines;
		continue;

	    case aQ: // save end of line 
		eol = c.p;
		break;

	    case aR: // save start after advance
		c.Advance();
		start = end = c.p;
		break;

	    case aS: // save start
		start = c.p;
		c.Advance();
		end = c.p;
		break;

	    case aT: // return tag
		value->Set( start, end - start );
		c.Advance();
		return SR_TAG;

	    case aV: // return value
		value->Set( start, end - start );
		return SR_VALUE;

	    case aW: // append line to textBlock
		// Use c.p to include whitespace.
		c.Advance();
		for( ; savedBlankLines; --savedBlankLines )
		    value->Append( "\n", 1 );
		value->Append( start, c.p - start );
		continue;

	    case aX: // append line and newline to textBlock
		for( ; savedBlankLines; --savedBlankLines )
		    value->Append( "\n", 1 );
		value->Append( start, c.p - start );
		value->Append( "\n", 1 );
		continue;
	    }
	}
}

void
SpecParse::ErrorLine( Error *e )
{
	e->Set( MsgDb::LineNo ) << c.line;
}
