/*
 * Copyright 2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

#include <ctype.h>

# define NEED_TYPES

#include <stdhdrs.h>
#include <error.h>
#include <strbuf.h>
#include <readfile.h>

#include "diffsp.h"
#include "diffsr.h"

# if USE_CR
# define NEWLINE '\r'
# else
# define NEWLINE '\n'
# endif

/*
 * diffsr.cc -- diff's Sequence's Sequencer
 */

/*
 * CHARHASH
 *
 * 293 is a good number because it's 2^8 + 2^5 + 2^2 + 2^0
 *	The 2^8 assures that no two adjacent characters can cause an
 *	identical hash and that the acumulated hash variable which is
 *	32 bits (at least) in size gets large pretty quickly for even
 *	small strings.  When we hash we're combining many bits into
 *	a small fixed number of bits.  If the multiplier here is small
 *	like 3 we will not fill 32 bits until we have a string which is
 *	about 26 characters long so small strings would not provide
 *	much diversity of hash values. On the downsize, 256 being 2^8
 *	will overflow 2^32 in just 4 iterations/characters. So the 2^5
 *	and 2^2 add permutations for longer strings and long strings are
 *	very unlikely to produce identical hashs.  293 is also
 *	a prime number, but that's not very imporant in this case
 *	because we're not divideing into buckets here.  We are only
 *	checking for probable equality. --- anton 5-feb-2004
 */
# define CHARHASH(h, c)	( 293 * (h) + (c) )

/*
 * LineReader - a diff sequencer for ordinary file of lines
 */

/*
 * LineReader::Load() - build list of hashed lines
 *
 * At EOF, we always store what we have and bail.
 * At NL, we store what we have and start a new line.
 * Previous implementation thought we had chars if
 * h != 0, but that didn't handle a null-only tail
 * of a file.
 */

void 
LineReader::Load( Error *e )
{
	HashVal h = 0;

	if( !src->Eof() ) 
	    while( !e->Test() )
	{
	    UChar c = src->Char();
	    src->Next();

	    h = CHARHASH(h, c);

	    if( src->Eof() )
	    {
		A->StoreLine( h, e );
		break;
	    }
	    else if( c == NEWLINE )
	    {
		A->StoreLine( h, e );
		h = 0;
	    }
	}
}

/*
 * LineReader::Equal() - compare two lines
 */

int 
LineReader::Equal(LineNo lineA, Sequence *B, LineNo lineB)
{
	// hashes lready checked by Sequence::Equal() 
	// length unequal -> lines unequal

	if( A->Length( lineA ) != B->Length( lineB ) )
	    return 0;

	// same hash, same length -> we have to check the actual file contents

	A->SeekLine( lineA );
	B->SeekLine( lineB );

	return !src->Memcmp( B->sequencer->src, A->Length( lineA ) );
}

/*
 * WordReader - a diff sequencer for file words separated by whitespace
 */

void 
WordReader::Load( Error *e )
{
	HashVal h = 0;

	if( !src->Eof() ) 
	    while( !e->Test() )
	{
	    UChar c = src->Char();
	    src->Next();

	    h = CHARHASH(h, c);

	    if( src->Eof() )
	    {
		A->StoreLine( h, e );
		break;
	    }
	    else if( isspace( c ) )
	    {
		A->StoreLine( h, e );
		h = 0;
	    }
	}
}

/*
 * WClassReader - a diff sequencer for classes of characters
 */

void 
WClassReader::Load( Error *e )
{
	HashVal h = 0;

	int lastcharclass = 0;
	UChar c = 0;

	if( src->Eof() )
	    return;

	do
	{
	    c = src->Char();

	    int charclass;

	    if( c == '\r' )
	    {
		charclass = 1;
	    }
	    else if( c == '\n' )
	    {
		charclass = 5;
	    }
	    else if( isalnum( c ) || ( c & 0x80 ) )
	    {
		charclass = 2;
	    }
	    else if( isspace( c ) )
	    {
		charclass = 3;
	    }
	    else
	    {
		charclass = 4;
	    }

	    if( charclass != lastcharclass )
	    {
		if( charclass == 5 )
		{
		    charclass = 6;
		    if( lastcharclass == 1 )
			lastcharclass = 0;
		}
		if( lastcharclass )
		{
		    A->StoreLine( h, e );
		    h = 0;
		}
		lastcharclass = charclass;
	    }

	    h = CHARHASH(h, c);

	    src->Next();

	} while( !src->Eof() && !e->Test() );

	if( e->Test() )
	    return;

	A->StoreLine( h, e );
}

/*
 * DifflReader - a diff Sequencer for lines, eol characters ignored
 *
 * Ignores line ending,  treat "\r\n" same as "\n" and "\r"
 */

/*
 * DifflReader::Load() - hash lines
 */

void 
DifflReader::Load( Error *e )
{
	HashVal h = 0;

	while( !src->Eof() && !e->Test() )
	{
	    UChar c = src->Char();
	    src->Next();

	    if( NewLine( c ) )
	    {
	        if( !src->Eof() && c == '\r' && src->Char() == '\n' )
	            src->Next();
 
	        c = '\n';
	    }
 
	    h = CHARHASH(h, c);

	    // Add hash newline if last line didn't have one

	    if( src->Eof() && c != '\n' )
	        h = CHARHASH( h, '\n' );
 
	    if( src->Eof() || c == '\n' )
	    {
	        A->StoreLine( h, e );
	        h = 0;
	    }
	}
}

/*
 * DifflReader::Equal() - Compare for equality, ignoring eol characters
 */

int 
DifflReader::Equal(LineNo lineA, Sequence *B, LineNo lineB)
{
	Sequencer *Bs = B->sequencer;

	LineLen la = A->Length( lineA );
	LineLen lb = B->Length( lineB );

	// hashes already checked by Sequence::Equal() 
	// length can be out by a maximum of 1 character \r\n <> \n
	// quick optimization (modified to allow for unsigned)

	if( la > ( lb + 1 ) || ( la + 1 ) < lb )
	    return 0;

	// same hash, we have to check the actual file contents

	A->SeekLine( lineA );
	B->SeekLine( lineB );

	UChar ca, cb;

	while( la && lb )
	{
	    // Load next char

	    ca = src->Get();
	    cb = Bs->src->Get();

	    if( ca != cb )
		break;

	    // used ca, cb

	    --la, --lb;
	}

	// Last line might have no newline (with -dl)

	if( ( !la && lb == 1 && NewLine( Bs->src->Get() ) ) ||
	    ( !lb && la == 1 && NewLine( src->Get() ) ) )
	    return 1;

	return !( ( la || lb ) && !NewLine( ca ) && !NewLine( cb ) ); 
}

/*
 * DiffbReader - a diff Sequencer for lines, whitespace changes ignored
 *
 * Ignores amount (1 or more chars) of embedded whitespace and presense 
 * of whitespace at end of line, but not presence of whitespace at beginning 
 * of line.
 */

/*
 * DiffbReader::Load() - hash lines, compressing whitespace
 */

void 
DiffbReader::Load( Error *e )
{
	HashVal h = 0;

	while( !src->Eof() && !e->Test() ) 
	{
	    UChar c = src->Char();
	    src->Next();

	    // Absorb whitespace into a single space

	    if( Whitespace( c ) )
	    {
	        c = ' ';

	        while( !src->Eof() && Whitespace( src->Char() ) )
	            src->Next();

	        // hash in the single space, unless eof or eol

	        if( src->Eof() )
	        {
	            A->StoreLine( h, e );
	            break;
	        }

	        if( !NewLine( src->Char() ) )
		    h = CHARHASH(h, c);

	        c = src->Char();
	        src->Next();
	    }

	    // skip the '\r' otherwise the next stored line
	    // will begin with '\n'

	    if( !src->Eof() && c == '\r' && src->Char() == '\n' )
	        src->Next();

	    // don't hash the newline

	    if( !NewLine( c ) )
		h = CHARHASH(h, c);

	    if( src->Eof() || NewLine( c ) )
	    {
	        A->StoreLine( h, e );
	        h = 0;
	    }
	}
}

/*
 * DiffbReader::Equal() - Compare for equality, ignoring whitespace.
 */

int 
DiffbReader::Equal(LineNo lineA, Sequence *B, LineNo lineB)
{
	Sequencer *Bs = B->sequencer;

	// Start at line beginning

	A->SeekLine( lineA );
	B->SeekLine( lineB );

	LineLen la = A->Length( lineA );
	LineLen lb = B->Length( lineB );

	UChar ca = la ? src->Get() : 0, cb = lb ? Bs->src->Get() : 0;

	// While more lines

	while( la && lb )
	{
	    // If we're looking at Whitespace() or newline in BOTH
	    // then eat up Whitespace() (but not newline) in both.
	    // This handles change of whitespace amount and change
	    // of whitespace presence at EOL.

	    if( ( Whitespace( ca ) || NewLine( ca ) )
	     && ( Whitespace( cb ) || NewLine( cb ) ) )
	    {
		while( Whitespace( ca ) && --la )
		    ca = src->Get();
		while( Whitespace( cb ) && --lb )
		    cb = Bs->src->Get();
		if( !la || !lb )
		    break;
	    }

	    // Whitespace gone; now safe to check chars.

	    if( ca != cb )
		break;

	    // Load next char

	    if( --la )
	        ca = src->Get();
	    if( --lb )
	        cb = Bs->src->Get();
	}

	// Any mismatching chars? (whitespace/newline characters don't count)
	
	while( la && ( Whitespace( ca ) || NewLine( ca ) ) && --la )
	    ca = src->Get();

	while( lb && ( Whitespace( cb ) || NewLine( cb ) ) && --lb )
	    cb = Bs->src->Get();

	return !la && !lb;
}

/*
 * DiffwReader - a diff Sequencer for lines, all whitespace ignored
 */

/*
 * DiffwReader::Load() - hash lines, compressing whitespace
 */

void 
DiffwReader::Load( Error *e )
{
	HashVal h = 0;

	while( !src->Eof() && !e->Test() ) 
	{
	    UChar c = src->Char();
	    src->Next();

	    // Eliminate whitespace

	    while( Whitespace( c ) && !src->Eof() )
	    {
	        c = src->Char();
	        src->Next();
	    }

	    // skip the '\r' otherwise the next stored line
	    // will begin with '\n'

	    if( !src->Eof() && c == '\r' && src->Char() == '\n' )
	        src->Next();

	    // don't hash the newline, nor any whitespace at EOF

	    if( !NewLine( c ) && !Whitespace( c ) )
		h = CHARHASH(h, c);

	    if( src->Eof() || NewLine( c ) )
	    {
	        A->StoreLine( h, e );
	        h = 0;
	    }
	}
}

/*
 * DiffwReader::Equal() - Compare for equality, ignoring whitespace.
 */

int 
DiffwReader::Equal(LineNo lineA, Sequence *B, LineNo lineB)
{
	Sequencer *Bs = B->sequencer;

	// Start at line beginning

	A->SeekLine( lineA );
	B->SeekLine( lineB );

	LineLen la = A->Length( lineA );
	LineLen lb = B->Length( lineB );

	UChar ca = la ? src->Get() : 0, cb = lb ? Bs->src->Get() : 0;

	// While more lines

	while( la && lb )
	{
	    // Eliminate whitespace

	    while( Whitespace( ca ) && --la )
		ca = src->Get();
	    while( Whitespace( cb ) && --lb )
		cb = Bs->src->Get();

	    if( !la || !lb )
		break;

	    // Whitespace gone; now safe to check chars.

	    if( ca != cb )
		break;

	    // Load next char

	    if( --la )
	        ca = src->Get();
	    if( --lb )
	        cb = Bs->src->Get();
	}

	// Any mismatching chars? (whitespace/newline characters don't count)
	
	while( la && ( Whitespace( ca ) || NewLine( ca ) ) && --la )
	    ca = src->Get();

	while( lb && ( Whitespace( cb ) || NewLine( cb ) ) && --lb )
	    cb = Bs->src->Get();
	
	return !la && !lb;
}
