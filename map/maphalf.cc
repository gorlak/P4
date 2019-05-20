/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <error.h>
# include <ctype.h>
# include <errornum.h>
# include <msgdb.h>

# include <debug.h>
# include <tunable.h>

# include "maphalf.h"
# include "mapchar.h"
# include "mapstring.h"
# include "mapdebug.h"

//
// MapHalf - half of a mapping, i.e. a pattern
//
// Methods defined:
//
//	MapHalf::MapHalf() - convert pattern to internal form and save
//	MapHalf::~MapHalf() - dispose of saved internal form of map
//	MapHalf::Compare() - strcmp() two MapHalf patterns for sorting
//	MapHalf::GetCommonLen() - match non-wild initial substring of pattern
//	MapHalf::Get() - return the pattern as a char *
//	MapHalf::HasEmbWild() - returns non-zero on embedded/leading wildcards
//	MapHalf::HasPosWild() - returns non-zero on positional wildcards
//	MapHalf::Match() - fast match a string against a map pattern
//	MapHalf::Expand() - expand result of Match using a pattern
//	MapHalf::Join() - join two MapHalfs together
// 	MapHalf::Validate() - do these patterns have the same wildcards
//
// Internal routines:
//	JoinWild() - push retry on stack when wildcard encountered in pattern
//

//
// MapHalf::MapHalf() - convert pattern to internal form and save
//

void
MapHalf::operator =( const StrPtr &newHalf )
{
	// Allocate

	char *p = newHalf.Text();
	int l = newHalf.Length() + 1;

	// Save the string; passed outwards by MapTable::Strings

	Set( newHalf );
	delete []mapChar;
	mapChar = new MapChar[ l ];

	// Compile into internal form.

	int nStars = 0;
	int nDots = 0;
	MapChar *mc = mapChar;

	while( mc->Set( p, nStars, nDots, caseMode ) )
	    ++mc;

	// Find non-wildcard tail

	mapEnd = mc;

	while( mc > mapChar && ( mc[-1].cc == cCHAR || mc[-1].cc == cSLASH ) )
	    --mc;

	mapTail = mc;

	// Find the length of the non-wildcard initial substring
	// This is used by MapTable::Strings to figure out what
	// initial substrings to use for table probes.

	mc = mapChar;

	while( mc->cc == cCHAR || mc->cc == cSLASH )
	    ++mc;

	isWild = mc->cc != cEOS;
	fixedLen = mc - mapChar;

	// Count number of wildcards in string

	for( nWilds = 0, mc = mapChar; mc->cc != cEOS; mc++ )
	    if( mc->IsWild() )
	    	++nWilds;
}

int
MapHalf::TooWild( Error *e )
{
	if( nWilds > p4tunable.Get( P4TUNE_MAP_MAXWILD ) )
	{
	    e->Set( MsgDb::TooWild2 );
	    return 1;
	}
	return 0;
}

int
MapHalf::HasSubDirs( int match )
{
	MapChar *mc = mapChar + match;

	// Can this pattern match a subdirectory after its 
	// non-wildcard initial substring?   

	while( mc->cc != cEOS && mc->cc != cSLASH && mc->cc != cDOTS )
	    ++mc;

	return mc->cc != cEOS;
}

int
MapHalf::HasEndSlashEllipses()
{
	// Test for '/...', or '\..' (UNC path) at end of string

	MapChar *mc = mapEnd - 1;

	if( !isWild )
	    return 0;
	    
	if( mc == mapChar ||
	  ( ( mc - 1 )->cc != cSLASH && ( mc - 1 )->c != '\\' ) )
	    return 0;
	    
	return mc->cc == cDOTS;
}

//
// MapHalf::~MapHalf() - dispose of saved internal form of map
//

MapHalf::~MapHalf()
{
	delete []mapChar;
}

//
// MapHalf::Compare() - strcmp() two MapHalf patterns for sorting
//

static const int CmpGrid[6][6] = {
/*              EOS 	CHAR     SLASH    PERC     STAR     DOTS */

/* EOS */	0,	-1,	 -1,	  0,	   0,	    0,
/* CHAR */	1,	-2,	 -2,	  1,	   1,	    1,
/* SLASH */	1,	-2,	 2,	  1,	   1,	    1,
/* PERC */	0,	-1,	 -1,	  0,	   0,	    0,
/* STAR */	0,	-1,	 -1,	  0,	   0,	    0,
/* DOTS */	0,	-1,	 -1,	  0,	   0,	    0,
} ;

int
MapHalf::Compare( const MapHalf &item ) const
{
	MapChar *mc1 = mapChar;
	MapChar *mc2 = item.mapChar;

	// Do a quick strcmp of non-wildcard initial string

	int l = fixedLen < item.fixedLen ? 
		fixedLen : item.fixedLen;

	for( ; l-- && !( *mc1 - *mc2 ); ++mc1, ++mc2 )
	    ;

	// Now do more sensitive compare

	for( ;; ++mc1, ++mc2 )
	{
	    int d;

	    switch( CmpGrid[ mc1->cc ][ mc2->cc ] )
	    {
	    case -1:	return -1;
	    case 1:	return 1;
	    case 0:	return 0;
	    case -2:	if( d = ( *mc1 - *mc2 ) )
			    return d;
	    case 2:	break;
	    }
	}
}

//
// MapHalf::Validate() - do these patterns have the same wildcards
//

void
MapHalf::FindParams( char *params, Error *e )
{
	MapChar *mc = mapChar;
	MapChar *mn = mapChar;
	int wilds = 0;

	for( ; mc->cc != cEOS; ++mc )
	{
	    switch( mc->cc )
	    {
	    case cDOTS:
		if( mc->paramNumber >= PARAM_BASE_TOP )
		{
		    e->Set( MsgDb::ExtraDots ) << *this;
		    return;
		}

		params[ mc->paramNumber ] = 1;
		wilds++;
		break;

	    case cSTAR:
		if( mc->paramNumber >= PARAM_BASE_DOTS )
		{
		    e->Set( MsgDb::ExtraStars ) << *this;
		    return;
		}
		// fall through

	    case cPERC:
		if( params[ mc->paramNumber ] )
		{
		    e->Set( MsgDb::Duplicate ) << *this;
		    return;
		}
		params[ mc->paramNumber ] = 1;
		wilds++;
		break;

	    default:
		mn = mc;
		break;
	    }

	    if( mn < mc - 1 )
	    {
		e->Set( MsgDb::Juxtaposed ) << *this;
		return;
	    }
	}

	if( wilds > p4tunable.Get( P4TUNE_MAP_MAXWILD ) )
	{
	    e->Set( MsgDb::TooWild2 );
	    return;
	}
	// We don't validate the params yet.
}

void
MapHalf::Validate( MapHalf *item, Error *e )
{
	int i;
	char params[2][ PARAM_VECTOR_LENGTH ];

	for( i = 0; i < PARAM_VECTOR_LENGTH; i++ )
	    params[0][i] = params[1][i] = 0;

	FindParams( params[0], e );

	if( e->Test() )
	    return;

	// If no item provided, just check the half.

	if( !item )
	    return;

	item->FindParams( params[1], e );

	if( e->Test() )
	    return;

	for( i = 0; i < PARAM_VECTOR_LENGTH; i++ )
	    if( params[0][i] != params[1][i] )
	{
	    e->Set( MsgDb::WildMismatch ) << *this << *item;
	    return;
	}
}


void
MapHalf::SanitizeStars( Error *e )
{
	if( !isWild )
	    return;

	StrBuf tmp;

	int wilds = 0;
	MapChar *mc = mapChar;
	while( mc->cc != cEOS )
	{
	    if( mc->IsWild() )
	        mc->MakeParam( tmp, mc, wilds );
	    else
	        tmp.Extend( mc->c );
	    mc++;
	}
	tmp.Terminate();
	
	*this = tmp;
}

void
MapHalf::SetCaseMode( int caseMode )
{
	this->caseMode = caseMode;
	if( mapChar )
	    for( MapChar *mc = mapChar; mc->cc != cEOS; mc++ )
	        mc->caseMode = caseMode;
}

//
// MapHalf::GetCommonLen() - match non-wild initial substring of pattern
//

int
MapHalf::GetCommonLen( MapHalf *prev )
{
	int matchLen = 0;
	MapChar *mc1 = mapChar;
	MapChar *mc2 = prev->mapChar;

	// Non-wildcard ("fixed"), matching prev

	while( matchLen < fixedLen && !( *mc1 - *mc2 ) )
	{
	    ++matchLen;
	    ++mc1, ++mc2;
	}

	return matchLen;
}

//
// MapHalf::Match() - fast match a string against a map pattern
//
// Broken into two parts: Match1 does the initial constant string match,
// optionally starting only at the point where the string differs from
// the previously matched string.  Match2 does the harder wildcarding
// match.
//
// Match1 compares and returns <0, 0, or >0.
// Match2 return 0 (no match) and 1 (match).
//
// Match1 against another MapHalf only compares up to smallest fixedLen.
//

int
MapHalf::Match1( const StrPtr &from, int &coff )
{
	// 1st half matching: match the initial non-wildcard portion

	// coff allows us to start at the point where this pattern
	// differs from the previous (parent) pattern.

	for( ; coff < fixedLen && coff < from.Length(); ++coff )
	    if( int r = ( mapChar[ coff ] - from[ coff ] ) )
		return -r;

	if( from.Length() < fixedLen )
	    return -1;

	return 0;
}

int
MapHalf::Match2( const StrPtr &from, MapParams &params )
{
	// 2nd half matching: match the wildcard portion.

	if( from.Length() < fixedLen )
	    return 0;

	char *input;
	MapChar *mc;

	// Check non-wildcard tail.  Handles '....gif' efficiently.

	if( isWild )
	{
	    char *ll = from.Text(); // lower limit of input
	    for( input = from.End(), mc = mapEnd; mc > mapTail && input > ll; )
	        if( *--mc - *--input )
	            return 0;
	}

	// Full match after initial fixed string.

	mc = mapChar + fixedLen;
	input = from.Text() + fixedLen;

	// If the MapChar::Sort() in Match1() was insufficient to
	// check the initial fixedLen of the map, we'll do it now.
	// See comments in strbuf.cc.

	if( StrPtr::CaseHybrid() )
	    input -= fixedLen, mc -= fixedLen;

	struct {
		MapChar	*mc;
		MapParam	*param;
	} backups[ PARAM_MAX_BACKTRACK * 2 ], *backup = backups;

	for(;;)
	{
	    if( DEBUG_MATCH )
		p4debug.printf("matching %c vs %s\n", mc->c, input );

	    switch( mc->cc )
	    {
	    case cDOTS:
	    case cPERC:
	    case cSTAR:
		backup->param = params.vector + mc->paramNumber;
		backup->param->start = input - from.Text();

		if( mc->cc == cDOTS )
		    while( *input ) ++input;
		else
		    while( *input && *input != '/' ) ++input;

		backup->param->end = input - from.Text();
		backup->mc = ++mc;
		backup++;
		break;

	    case cSLASH:
	    case cCHAR:
		do {
		    if( !( *mc++ == *input++ ) )
			goto retry;
		} while( mc->cc == cCHAR || mc->cc == cSLASH );
		break;

	    case cEOS:
		if( *input != '\0' )
		    goto retry;
		return 1;

	    retry:
		for( ;; --backup )
		{
		    if( backup <= backups )
			return 0;

		    mc = backup[-1].mc;
		    input = from.Text() + --( backup[-1].param->end );
		    if( input >= from.Text() + backup[-1].param->start )
			break;
		}
		break;
	    }
	}
}

//
// MapHalf::Match() - match a pattern against another
//
// Unlike MapTable::Join(), this just checks to see if one map is a superset
// of a 2nd.  
//

int
MapHalf::Match( const MapHalf &from )
{
	MapChar *mc = mapChar;
	MapChar *mc2 = from.mapChar;

	struct {
		MapChar	*mc;
		MapChar *mc2start;
		MapChar *mc2end;
	} backups[ PARAM_MAX_BACKTRACK * 2 ], *backup = backups;


	for(;;)
	{
	    switch( mc->cc )
	    {
	    case cDOTS:
		backup->mc2start = mc2;

		while( mc2->cc != cEOS ) 
		    ++mc2;

		backup->mc2end = mc2;
		backup->mc = ++mc;
		backup++;
		break;

	    case cPERC:
	    case cSTAR:
		backup->mc2start = mc2;

		while( mc2->cc != cEOS && 
		       mc2->cc != cSLASH && 
		       mc2->cc != cDOTS ) 
			++mc2;

		backup->mc2end = mc2;
		backup->mc = ++mc;
		backup++;
		break;

	    case cSLASH:
	    case cCHAR:
		do {
		    if( mc->cc != mc2->cc || !( mc++->c == mc2++->c ) )
			goto retry;
		} while( mc->cc == cCHAR || mc->cc == cSLASH );
		break;

	    case cEOS:
		if( mc2->cc != cEOS )
		    goto retry;

		return 1;

	    retry:
		for( ;; --backup )
		{
		    if( backup <= backups )
			return 0;

		    mc = backup[-1].mc;
		    mc2 = --( backup[-1].mc2end );
		    if( mc2 >= backup[-1].mc2start )
			break;
		}
		break;
	    }
	}
}

//
// MapHalf::MatchHead()
// MapHalf::MatchTail() 
//
//	Compares the non-wildcard initial substring or tailing 
//	substring of the two MapHalfs.  
//

int
MapHalf::MatchHead( const MapHalf &other )
{
	// non-wildcard matching for map joins

	int coff = 0;

	for( ; coff < fixedLen && coff < other.fixedLen; ++coff )
	    if( int r = ( mapChar[ coff ] - other.mapChar[ coff ] ) )
		return -r;

	return 0;
}

int
MapHalf::MatchTail( const MapHalf &other )
{
	MapChar *mc1 = mapEnd;
	MapChar *mc2 = other.mapEnd;

	while( mc1 > mapTail && mc2 > other.mapTail )
	    if( *--mc1 - *--mc2 )
		return 1;

	return 0;
}

//
// MapHalf::Expand() - expand result of Match using a pattern
//

void
MapHalf::Expand( const StrPtr &from, StrBuf &output, MapParams &params )
{
	MapChar *mc = mapChar;
	int slot;

	if( DEBUG_MATCH )
	    p4debug.printf( "Expand %s\n", Text() );

	output.Clear();

	for( ; mc->cc != cEOS; ++mc )
	{
	    if( mc->IsWild() )
	    {
		slot = mc->paramNumber;
		char *in = from.Text() + params.vector[ slot ].start;
		char *end = from.Text() + params.vector[ slot ].end;

		if( DEBUG_MATCH )
		    p4debug.printf( "... %d %p to '%.*s'\n", slot, 
			&params.vector[ slot ], end - in, in );

		output.Extend( in, end - in );
	    }
	    else
	    {
		output.Extend( mc->c );
	    }
	}

	output.Terminate();

	if( DEBUG_MATCH )
	    p4debug.printf( "Expanded to %s\n", output.Text() );
}

//
// begin support for MapHalf::Join()
//

// Retry - state for retrying a wildcard after a mismatch
//
// If two patterns fail to match on literal characters, then
// any wildcards previously encountered in the patterns get
// 'retried'.  That is, they match one more character than
// they did before and then the whole matching process is
// reattempted.
//

enum Backup {
	BACKUP_NONE,		// in forward match
	BACKUP_LHS,		// backing up LHS
	BACKUP_RHS		// backing up RHS
} ;

struct Retry {
	MapChar		*mc1;
	MapChar		*mc2;
	MapParam	*param;
	Backup		backup;
	int		wilds;
} ; 


// ActionGrid - control comparison of pattern characters
//
// While trying to join two patterns to make a third, we must compare
// the current character in each pattern and decide what to do.  This
// grid makes that decision.  There are five potential outcomes:
//
//	aMATCH		The characters match, so just advance to the
//			next character in both patterns.
//
//	aLWILD,R	The left (right) pattern is at a wildcard; save the
//			current state (for retry) and advance past
//			the wildcard.
//
//	aLBACK,R	Match failed, and retrying left (right) wildcard; 
//			we consume a character on the right (copying it
//			into the param buf that holds the data matched
//			by the wildcard), save the state (for further
//			retry), and advance past the wildcard.
//
//	aLSTAR,R	Match failed, and retrying left (right) wildcard,
//			but now there is a wildcard on the other side; we
//			produce a wildcard into the param buf, save the
//			current state (for further retry), and start a new
//			retry for the other side.
//
//	aMISS		The characters are different, so back up the
//			retry list (setting "backup") and try again.
//
//	aOK		At the end of both patterns.  Return.
//

enum Action {
	aMATCH,		
	aLWILD,	
	aLBACK,
	aRWILD,
	aRBACK,
	aSTAR,
	aLSTAR,
	aRSTAR,
	aMISS,	
	aOK
} ;

static const char *const actionNames[] = {
	"MATCH",
	"LHS-WILD",
	"LHS-NEXT",
	"RHS-WILD",
	"RHS-NEXT",
	"BOTH-STAR",
	"LHS-STAR",
	"RHS-STAR",
	"MISS",
	"OK"
} ;

static const Action Grid[3][6][6] = {
/* Map \/ Pattern -> */
/*              EOS      CHAR     SLASH    PERC     STAR     DOTS */

/* BACKUP_NONE */
/* EOS */       aOK,     aMISS,   aMISS,   aRWILD,  aRWILD,  aRWILD,
/* CHAR */      aMISS,   aMATCH,  aMISS,   aRWILD,  aRWILD,  aRWILD,
/* SLASH */     aMISS,   aMISS,   aMATCH,  aRWILD,  aRWILD,  aRWILD,
/* PERC */      aLWILD,  aLWILD,  aLWILD,  aSTAR,   aSTAR,   aSTAR,
/* STAR */      aLWILD,  aLWILD,  aLWILD,  aSTAR,   aSTAR,   aSTAR,
/* DOTS */      aLWILD,  aLWILD,  aLWILD,  aSTAR,   aSTAR,   aSTAR,

/* BACKUP_LHS */
/* EOS */       aOK,     aMISS,   aMISS,   aMISS,   aMISS,   aMISS,
/* CHAR */      aMISS,   aMATCH,  aMISS,   aRBACK,  aRBACK,  aRBACK,
/* SLASH */     aMISS,   aMISS,   aMATCH,  aMISS,   aMISS,   aRBACK,
/* PERC */      aMISS,   aLBACK,  aMISS,   aLSTAR,  aLSTAR,  aLSTAR,
/* STAR */      aMISS,   aLBACK,  aMISS,   aLSTAR,  aLSTAR,  aLSTAR,
/* DOTS */      aMISS,   aLBACK,  aLBACK,  aLSTAR,  aLSTAR,  aLSTAR,

/* BACKUP_RHS */
/* EOS */       aOK,     aMISS,   aMISS,   aMISS,   aMISS,   aMISS,
/* CHAR */      aMISS,   aMATCH,  aMISS,   aRBACK,  aRBACK,  aRBACK,
/* SLASH */     aMISS,   aMISS,   aMATCH,  aMISS,   aMISS,   aRBACK,
/* PERC */      aMISS,   aLBACK,  aMISS,   aRSTAR,  aRSTAR,  aRSTAR,
/* STAR */      aMISS,   aLBACK,  aMISS,   aRSTAR,  aRSTAR,  aRSTAR,
/* DOTS */      aMISS,   aLBACK,  aLBACK,  aRSTAR,  aRSTAR,  aRSTAR

} ;

//
// MapHalf::Join() - join two MapHalfs together
//

void
MapHalf::Join( MapHalf *map2, Joiner &joiner )
{
	Retry retrys[32];	// XXX core dump when overflowed!
	Retry *retry = retrys;
	joiner.Clear();
	int backup = BACKUP_NONE;
	int wilds = 0;
	int maxWildChars = p4tunable.Get( P4TUNE_MAP_MAXWILD );

	if( DEBUG_JOINHALF )
	    p4debug.printf( "--- '%s','%s' ----\n", Text(), map2->Text() );

	// Optimization: match the non-wild initial substrings first.
	// Do it backwards, to eliminate mismatches quickly.  This helps
	// with large maps and large protections tables.

	int nonWild = map2->fixedLen;
	if( fixedLen < nonWild )
	    nonWild = fixedLen;

	MapChar *mc1 = mapChar + nonWild;
	MapChar *mc2 = map2->mapChar + nonWild;

	while( mc1 > mapChar )
	    if( !( *--mc1 == *--mc2 ) )
		return;

	// Now on with the show

	mc1 = mapChar + nonWild;
	mc2 = map2->mapChar + nonWild;

	for(;;)
	{
	    Action a = Grid[ backup ][ mc1->cc ][ mc2->cc ];

	    // Change aMATCH to aMISS is the characters differ

	    if( a == aMATCH && !( *mc1 == *mc2 ) )
		a = aMISS;

	    if( DEBUG_JOINHALF )
	    {
		MapChar *c;
		char x;

		x = backup == BACKUP_LHS ? '=' : '-';

		p4debug.printf( "(" );

		for( c = mapChar; c->cc != cEOS; ++c ) 
		{
		    if( c == mc1 ) p4debug.printf( "%c", x );
		    p4debug.printf( "%c", c->c );
		}
		if( c == mc1 ) p4debug.printf( "%c", x );

		p4debug.printf( ") (" );

		x = backup == BACKUP_RHS ? '=' : '-';

		for( c = map2->mapChar; c->cc != cEOS; ++c )
		{
		    if( c == mc2 ) p4debug.printf( "%c", x );
		    p4debug.printf( "%c", c->c );
		}
		if( c == mc2 ) p4debug.printf( "%c", x );

		p4debug.printf( ") %d-> %s\n", retry - retrys, actionNames[ a ] );
	    }

	    // Act according to the relationship of the current
	    // characters in each input pattern.

	    backup = BACKUP_NONE;

	    switch( a )
	    {
	    case aMATCH:	
		// Both the same: copy current character to 
		// result and advance both input patterns.
		++mc1, ++mc2;
		break;

	    case aLWILD:
		// starting wildcard on left; initially match no chars
		retry->wilds = wilds;
		retry->backup = BACKUP_LHS;
		retry->param = joiner.params.vector + mc1->paramNumber;
		retry->param->start = joiner.Length();
		retry->param->end = joiner.Length();
		retry->mc1 = mc1++;
		retry->mc2 = mc2;
		++retry;
		break;

	    case aRWILD:
		// starting wildcard on right; initially match no chars
		retry->wilds = wilds;
		retry->backup = BACKUP_RHS;
		retry->param = joiner.params2.vector + mc2->paramNumber;
		retry->param->start = joiner.Length();
		retry->param->end = joiner.Length();
		retry->mc1 = mc1;
		retry->mc2 = mc2++;
		++retry;
		break;

	    case aLBACK:
		// retrying wildcard on left; consume a char on right
		joiner.Extend( mc2++->c );
		retry->param->end = joiner.Length();
		retry->mc2 = mc2;

		if( Grid[ retry->backup ][ mc1->cc ][ mc2->cc ] == aLSTAR )
		{
		    backup = retry->backup;
		}
		else
		{
		    retry->mc1 = mc1++;
		    ++retry;
		}
		break;

	    case aRBACK:
		// retrying wildcard on right; consume a char on left

		joiner.Extend( mc1++->c );
		retry->param->end = joiner.Length();
		retry->mc1 = mc1;

		// If the next character is a wildcard, keep consuming
		// this avoids wildcards matching empties next to wildcards

		if( Grid[ retry->backup ][ mc1->cc ][ mc2->cc ] == aRSTAR )
		{
		    backup = retry->backup;
		}
		else
		{
		    retry->mc2 = mc2++;
		    ++retry;
		}
		break;

	    case aSTAR:
		// two wildcards at the same time
		// make a new wildcard 

		retry[0].param = joiner.params.vector + mc1->paramNumber;
		retry[0].param->start = joiner.Length();
		retry[0].backup = BACKUP_LHS;

		// fall thru

	    case aLSTAR:
		// retrying wildcard on left consumes wildcard on right
		// make a new wildcard and start a RWILD

		retry[1].param = joiner.params2.vector + mc2->paramNumber;
		retry[1].param->start = joiner.Length();

		mc1->MakeParam( joiner, mc2, wilds );

		retry[0].param->end = joiner.Length();
		retry[1].param->end = joiner.Length();
		retry[0].mc1 = mc1++;
		retry[1].mc1 = mc1;
		retry[1].mc2 = mc2++;
		retry[0].mc2 = mc2;
		retry[1].backup = BACKUP_RHS;
		retry[0].wilds = wilds;
		retry[1].wilds = wilds;
		retry += 2;
		break;

	    case aRSTAR:
		// retrying wildcard on right consumes wildcard on left
		// make a new wildcard and start a LWILD

		retry[1].param = joiner.params.vector + mc1->paramNumber;
		retry[1].param->start = joiner.Length();

		mc1->MakeParam( joiner, mc2, wilds );

		retry[0].param->end = joiner.Length();
		retry[1].param->end = joiner.Length();
		retry[1].mc1 = mc1++;
		retry[0].mc1 = mc1;
		retry[0].mc2 = mc2++;
		retry[1].mc2 = mc2;
		retry[1].backup = BACKUP_LHS;
		retry[0].wilds = wilds;
		retry[1].wilds = wilds;
		retry += 2;
		break;

	    case aOK:		
		// Full match: save result.
	        if( wilds > maxWildChars )
		{
		    joiner.badJoin = 1;
		    return;
		}

		joiner.Insert();

		// We fall through and produce other valid matches
		// at this point.

	    case aMISS:	
		// A mismatch: back up and try again.
		// We try each retry.

		// If we've exhausted all retries, we've failed.

		if( --retry < retrys )
		    return;

		mc1 = retry->mc1;
		mc2 = retry->mc2;
		backup = retry->backup;
		joiner.SetLength( retry->param->end );
		wilds = retry->wilds;

		// An ugly fix: 
		//
		// In the *STAR cases, we pushed two retries on the retry
		// stack: one for the wildcard on the left and one for the
		// wildcard on the right.  Both retry's param pointers include
		// MakeParams() newly made output wildcard.  At this point,
		// the wildcard on the top of the stack matched nothing except
		// the other wildcard, and we must make the param pointer 
		// reflect that.  However, it still includes characters after 
		// the wildcard that eventually failed to match.  So we 
		// back up our this retry->param->end to be the lower retry's 
		// param->end (to include just the generated output wildcard).
		//
		// We only do this if there were at least two retries on the
		// stack, as we have no real way of checking if this is the
		// result of a *STAR case.  But it is harmless if not (I
		// think).
		//
		// This whole module needs to be rewritten again.
		// 

		if( retry > retrys )
		    retry->param->end = retry[-1].param->end;

		break;
	    }

	    if( DEBUG_JOINHALF )
	    {
		int i; 
		int j;

		for( i = 0; retrys + i < retry; i++ )
		{
		    MapParam *p = retrys[i].param;
		    p4debug.printf( "\t\t\t\t%p ", p );
		    for( j = 0; j < p->start; j++ ) p4debug.printf( " " );
		    p4debug.printf( "\"" );
		    for( j = p->start; j < p->end; j++ ) p4debug.printf( "%c", joiner[j] );
		    p4debug.printf( "\"\n" );
		}
		p4debug.printf( "\t\t\t\t%p  ", joiner.Text() );
		for( j = 0; j < joiner.Length(); j++ ) p4debug.printf( "*" );
		p4debug.printf( "\n" );
	    }
	}
}

int
MapHalf::HasPosWild( StrPtr &h )
{

	if( char *p = strstr( h.Text(), "%%") )
	    if( p[2] >= '0' && p[2] <= '9' )
	        return 1;

	return 0;
}


// 
//  MapHalf::HasEmbWild( StrPtr, int )
// 
//  Returns 1 should StrPtr contain chars following a wildcard such as
//  ellipsis, positional, or asterisk.  The routine checks for leading wilds
//  not just embedded wilds.  Invoked with int set to 1, we were called with 
//  an Ignored stream-path; the one path type allowing for leading ellipsis.
//

int
MapHalf::HasEmbWild( StrPtr &h, int ignore )
{
	char *hPtr = h.Text();
	char *p;
	int prevwild = 0;    // reference to previous char fetched

	for ( p = hPtr; *p != '\0'; p++ )
	{
	    if( *p == '.' &&  p[1] == '.' && p[2] == '.' )
	    {
	        prevwild++;
	        p += 2;
	    }
	    else if( *p == '%' && p[1] == '%' && p[2] >= '0' && p[2] <= '9' )
	    {
	        prevwild++;
	        p += 2;
	    }
	    else if( *p == '*' )
	    {
	        prevwild++;
	    }
	    else if( *p == '\0' )
	    {
	        break;
	    }
	    else    // alphanumeric,slash,dot,percent: non-wild path chars
	    {
	        // for job050063 - check for no further paths, ellipsis, wilds,
	        // so we might assume remaining chars are a file-extension.

	        if( !strchr( p, '/' )  && !strchr( p, '*') && 
	            !strstr( p, "...") )
	        {
	            if( p4debug.GetLevel( DT_VIEWGEN ) >= 1 )
	                p4debug.printf( "Stream Path embedded wild:[%s]\n", \
	                    hPtr );
	            break;
	        }

	        if( ( prevwild && !ignore ) || ( ignore && prevwild > 1 ) )
	            return 1;
	    }
	}

	return 0;
}
