/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * strings.cc - support for StrBuf, StrPtr
 */

# include <stdhdrs.h>
# include <charman.h>
# include <math.h>

# include "strbuf.h"
# include "strdict.h"
# include "strops.h"

/*
 * Null strings for StrRef::Null() and empty StrBuf
 */

char StrBuf::nullStrBuf[8] = "\0\0\0\0\0\0\0";
StrRef StrRef::null( "", 0 );

/*
 * StrPtr::CCompare/SCompare/SCompareN/SEqual
 *
 * These following methods alone handle the case sensitivity switch
 * between UNIX and NT servers.  They include support for an experimental
 * "hybrid" form of case handling.
 *
 * Even the case insensitive comparators start with a case sensitive
 * compare, since that is faster and handles the bulk of data.  Only
 * if the case sensitive compare finds a difference, and we are being
 * case insensitive, do we proceed to the slower case folding compare.
 *
 * Here are the case handling modes:
 *
 *	ST_UNIX: Compare with case significant.
 *
 *		Ax < ax
 *		aa > AX
 *
 *	ST_WINDOWS: Compare with case ignored.
 *
 *		Ax == ax
 *		aa < AX
 *
 *	ST_HYBRID: First compare with case ignored, then significant.
 *
 *		Ax < ax
 *		aa < AX
 *
 *		This leads to an ordering like:
 *
 *			//depot/main/a
 *			//depot/main/b
 *			//depot/Main/c
 *			//depot/main/c
 *			//depot/main/d
 *
 *		That is, it looks like WINDOWS order, but still maintains
 *		uniqueness.  Because ordering depends on seeing the whole
 *		string before going back and looking for case differences,
 *		this can complicate code which attempts to do its own char
 *		by char sorting.  Thus the character based SCompare() and
 *		SEqual() differ only for the HYBRID case: SCompare ignores
 *		the case, while SEqual() heeds it.
 *
 * And the methods:
 *
 *	StrPtr::CCompare() 
 *		Compare with case ignored.
 *
 *	StrPtr::NCompare() 
 *		Compare with case ignored, natural order comparison.
 *
 *	StrPtr::SCompare( string )
 *		Compare with case significant (UNIX).
 *		Compare with case ignored (WINDOWS)
 *		Compare with case ignored then significant (HYBRID)
 *
 *	StrPtr::SCompareN( string, len )
 *		Compare with case significant (UNIX).
 *		Compare with case ignored (WINDOWS)
 *		Compare with case ignored; if EOS then significant (HYBRID)
 *
 *	StrPtr::SCompare( char )
 *		Compare with case significant (UNIX).
 *		Compare with case ignored (WINDOWS,HYBRID)
 *
 *	StrPtr::SEqual( char )
 *		Compare with case significant (UNIX,HYBRID).
 *		Compare with case ignored (WINDOWS)
 */

# ifdef CASE_INSENSITIVE
StrPtr::CaseUse StrPtr::caseUse = ST_WINDOWS;
# else
StrPtr::CaseUse StrPtr::caseUse = ST_UNIX;
# endif
bool		StrPtr::foldingSet = 0;

int 
StrPtr::CCompare( const char *sa, const char *sb )
{
	const unsigned char *a = (const unsigned char *)sa;
	const unsigned char *b = (const unsigned char *)sb;

	// Case significant part (fast)

	while( *a && *a == *b )
	    ++a, ++b;

	// Case ignored part (slow)

	while( *a && tolowerq( *a ) == tolowerq( *b ) )
	    ++a, ++b;

	return tolowerq( *a ) - tolowerq( *b );
}

int 
StrPtr::SCompare( const char *sa, const char *sb )
{
	const unsigned char *a = (const unsigned char *)sa;
	const unsigned char *b = (const unsigned char *)sb;

	// Case significant compare for UNIX

	while( *a && *a == *b )
	    ++a, ++b;

	int cmpCased = *a - *b;

	if( caseUse == ST_UNIX )
	    return cmpCased;

	// Proceed with case ignored compare for WINDOWS, HYBRID

	while( *a && tolowerq( *a ) == tolowerq( *b ) )
	    ++a, ++b;

	int cmpFolded = tolowerq( *a ) - tolowerq( *b );

	if( cmpFolded || caseUse == ST_WINDOWS ) 
	    return cmpFolded;

	// If case-ignored matched and HYBRID, now return first case mismatch

	return cmpCased;
}

/*
 * NCompare(),  original code taken from:
 *
 * strnatcmp.c -- Perform 'natural order' comparisons of strings in C.
 * Copyright (C) 2000, 2004 by Martin Pool <mbp sourcefrog net>
 *
 * see:   
 * http://computer.perforce.com/newwiki/index.php?title=3rd_Party_Software
 * 
 */

int
StrPtr::NCompare( const char *a, const char *b )
{
	const unsigned char *ca = (const unsigned char *)a;
	const unsigned char *cb = (const unsigned char *)b;
	int result;

	for( ;; )
	{
	    while( isAspace( ca ) ) ++ca;
	    while( isAspace( cb ) ) ++cb;

	    if( !*ca && !*cb )
	        return 0;

	    if ( isAdigit( ca ) && isAdigit( cb ) ) 
	    {
	        if( *ca == '0' || *cb == '0' ) 
	        {
	            if( ( result = NCompareLeft( ca, cb ) ) != 0 )
	                return result;
	        }
	        else 
	        {
	            if( ( result = NCompareRight( ca, cb ) ) != 0 )
	                return result;
	        }
	    }

	    // For now,  always ignore case

	    if( tolowerq( *ca ) < tolowerq( *cb ) ) return -1;
	    if( tolowerq( *ca ) > tolowerq( *cb ) ) return +1;

	    ++ca; ++cb;
	}
}

int 
StrPtr::NCompareLeft( const unsigned char *a, const unsigned char *b )
{
	for( ;; a++, b++ ) 
	{
	    if ( !isAdigit( a ) && !isAdigit( b ) ) 
	        return 0;
            else if( !isAdigit( a ) ) 
	        return -1;
	    else if( !isAdigit( b ) ) 
	        return +1;
	    else if( *a < *b ) 
	        return -1;
	    else if( *a > *b ) 
	        return +1;
	}  
	// NOT-REACHED!
}

int 
StrPtr::NCompareRight( const unsigned char *a, const unsigned char *b )
{
	int bias = 0;

	for( ;; a++, b++ ) 
	{
	    if( !isAdigit( a ) && !isAdigit( b ) ) 
	        return bias;
	    else if( !isAdigit( a ) ) 
	        return -1;
	    else if( !isAdigit( b ) ) 
	        return +1;
	    else if( *a < *b ) 
	        { if( !bias ) bias = -1; } 
	    else if (*a > *b) 
	        { if( !bias ) bias = +1; } 
	    else if ( !*a && !*b )
	        return bias;
	}
	// NOT-REACHED!
}

int     
StrPtr::SCompareN( const StrPtr &s ) const
{
	const unsigned char *a = (const unsigned char *)buffer;
	const unsigned char *b = (const unsigned char *)s.buffer;
	int n = length;

	// Case significant compare for UNIX

	while( n && *a && *a == *b )
	    ++a, ++b, --n;

	if( !n )
	    return 0;

	int cmpCased = *a - *b;

	if( caseUse == ST_UNIX )
	    return cmpCased;

	// Proceed with case folding compare for WINDOWS, HYBRID

	while( n && *a && tolowerq( *a ) == tolowerq( *b ) )
	    ++a, ++b, --n;

	if( !n ) 
	    return 0;

	int cmpFolded = tolowerq( *a ) - tolowerq( *b );

	if( cmpFolded || caseUse == ST_WINDOWS ) 
	    return cmpFolded;

	// If case-ignored matched and HYBRID, now return first case mismatch

	return cmpCased;
}

int 
StrPtr::SCompareF( unsigned char a, unsigned char b )
{
	return caseUse == ST_UNIX ? a-b : tolowerq( a ) - tolowerq( b );
}

int 
StrPtr::SEqualF( unsigned char a, unsigned char b )
{
	return caseUse == ST_WINDOWS ? tolowerq( a ) == tolowerq( b ) : a==b;
}

/*
 * StrPtr::Atoi64() - our own strtoll()
 * StrPtr::Itoa64() - a cheesy sprintf()
 */

P4INT64
StrPtr::Atoi64( const char *p )
{
	P4INT64 value = 0;
	int sign = 0;

	/* Skip any leading blanks.  */

	while( isAspace( p ) )
	    ++p;

	/* Check for a sign.  */

	if( *p == '+' )
	    ++p;
	else if( *p == '-' ) 
	    ++p, sign = 1;

	/* Convert the digits */

	while( isAdigit( p ) )
	    value = value * 10 + ( *p++ - '0' );

	/* Add the sign */

	return sign ? -value : value;
}

char *
StrPtr::Itoa64( P4INT64 v, char *buffer )
{
	// Our own cheesy sprintf( buf, "%d", v );
	// We work backwards from the end of the buffer.
	// We return the beginning of the buffer

	int neg;
	if( neg = ( v < 0 ) )
	    v = -v;

	*--buffer = 0;

	do
	{
	    *--buffer = ( v % 10 ) + '0';
	    v = v / 10;
	}
	while( v );

	if( neg )
	    *--buffer = '-';

	return buffer;
}

char *
StrPtr::Itox( unsigned int v, char *buffer )
{
	// Our own cheesy sprintf( buf, "%x", v );
	// We work backwards from the end of the buffer.
	// We return the beginning of the buffer

	*--buffer = 0;

	do
	{
	    *--buffer = StrOps::OtoX( v & 0xf );
	    v >>= 4;
	}
	while( v );

	*--buffer = 'x';
	*--buffer = '0';

	return buffer;
}

// A legal number follows the simple grammar: ( )*[+-]\d+
//
bool
StrPtr::IsNumeric() const
{
	const char *p = Text();

	while( isAspace( p ) ) ++p;

	if( *p == '+' || *p == '-' ) ++p;

	const char *q = p;

	while( isAdigit( p ) ) ++p;

	return *p == '\0' && ( p - q ) > 0;
}

int
StrPtr::StartsWith( const char *s, int l ) const
{
	if( Length() < l )
	    return 0;

	const char *p = Text();

	while( l-- > 0 )
	    if( *p++ != *s++ )
	        return 0;

	return 1;
}

int
StrPtr::EndsWith( const char *s, int l ) const
{
	if( Length() < l )
	    return 0;

	const char *p = Text() + ( Length() - l );

	while( l-- > 0 )
	    if( *p++ != *s++ )
	        return 0;

	return 1;
}

/*
 * StrBuf::Append() - append to a buffer
 */

void
StrBuf::Append( const char *buf, p4size_t len )
{
	// This code is the functional equivalent of:
	//
	//	Extend( buf, len );
	//	Terminate();
	//

	char *s = Alloc( len + 1 );
	memmove( s, buf, len );
	s[ len ] = '\0'; 
	--length;
}

void
StrBuf::Append( const char *buf )
{
	// Use buf's EOS
	int len = strlen( buf ) + 1;
	memmove( Alloc( len ), buf, len );
	--length;
}

void
StrBuf::Append( const StrPtr *t )
{
	char *s = Alloc( t->Length() + 1 );
	memmove( s, t->Text(), t->Length() );
	s[ t->Length() ] = '\0'; 
	--length;
}

void
StrBuf::UAppend( const char *buf, p4size_t len )
{
	// This code is the functional equivalent of:
	//
	//	Extend( buf, len );
	//	Terminate();
	//

	char *s = Alloc( len + 1 );
	memcpy( s, buf, len );
	s[ len ] = '\0'; 
	--length;
}

void
StrBuf::UAppend( const char *buf )
{
	// Use buf's EOS
	int len = strlen( buf ) + 1;
	memcpy( Alloc( len ), buf, len );
	--length;
}

void
StrBuf::UAppend( const StrPtr *t )
{
	char *s = Alloc( t->Length() + 1 );
	memcpy( s, t->Text(), t->Length() );
	s[ t->Length() ] = '\0'; 
	--length;
}

/*
 * StrBuf::Grow() - grow a string buffer
 */

void
StrBuf::Grow( p4size_t oldlen )
{
	// Resize?
	// If Growing an existing string, double needed size ('cause
	// we'll grow again).  But if allocating a string to begin
	// with, add an extra byte for the null terminator that gets
	// tacked on.

	size = length;

	if( buffer != nullStrBuf )
	{
	    // geometric growth
	    if( size >= 0x70000000 )
	        size =  0xffffffff;
	    else
	        size = ( size + 30 ) * 3 / 2;
	    char *o = buffer;
	    buffer = new char[ size ];
	    memcpy( buffer, o, oldlen );
	    delete []o;
	}
	else
	{
	    if( size < 4096 )
		size += 1;
	    buffer = new char[ size ];
	}
}

/*
 * StrBuf::BlockAppend() - append a large block to a buffer
 */

void
StrBuf::BlockAppend( const char *buf, p4size_t len )
{
	// This code is the functional equivalent of:
	//
	//	Extend( buf, len );
	//	Terminate();
	//
	// except that it doesn't over-allocate

	char *s = BlockAlloc( len + 1 );
	memmove( s, buf, len );
	s[ len ] = '\0'; 
	--length;
}

void
StrBuf::BlockAppend( const char *buf )
{
	// Use buf's EOS
	int len = strlen( buf ) + 1;
	memmove( BlockAlloc( len ), buf, len );
	--length;
}

void
StrBuf::BlockAppend( const StrPtr *t )
{
	char *s = BlockAlloc( t->Length() + 1 );
	memmove( s, t->Text(), t->Length() );
	s[ t->Length() ] = '\0'; 
	--length;
}

void
StrBuf::UBlockAppend( const char *buf, p4size_t len )
{
	// This code is the functional equivalent of:
	//
	//	Extend( buf, len );
	//	Terminate();
	//
	// except that it doesn't over-allocate

	char *s = BlockAlloc( len + 1 );
	memcpy( s, buf, len );
	s[ len ] = '\0'; 
	--length;
}

void
StrBuf::UBlockAppend( const char *buf )
{
	// Use buf's EOS
	int len = strlen( buf ) + 1;
	memcpy( BlockAlloc( len ), buf, len );
	--length;
}

void
StrBuf::UBlockAppend( const StrPtr *t )
{
	char *s = BlockAlloc( t->Length() + 1 );
	memcpy( s, t->Text(), t->Length() );
	s[ t->Length() ] = '\0'; 
	--length;
}

/*
 * StrBuf::Reserve() - Ensure that there is the requested  space
 * - don't over-allocate
 * - intended for large requests (>= 128 KB)
 */

void
StrBuf::Reserve( p4size_t oldlen )
{
	size = length;

	if( buffer != nullStrBuf )
	{
	    // geometric growth
	    char *o = buffer;
	    buffer = new char[ size ];
	    memcpy( buffer, o, oldlen );
	    delete []o;
	}
	else
	{
	    buffer = new char[ size ];
	}
}

void
StrBuf::Fill(const char *buf, p4size_t len)
{
    if (len > Length() )
        len = Length();
    memset( Text(), *buf, len);
}

void
StrBuf::TruncateBlanks()
{
	const char *p = buffer;
	const char *blank = 0;
	while( *p )
	{
	    if( *p != ' ' )
		blank = 0;
	    else if( !blank )
	        blank = p;

	    p++;
	}
	if( blank )
	{
	    SetEnd( (char *)blank );
	    Terminate();
	}
}

void
StrBuf::TrimBlanks()
{
	const char *start = buffer;
	const char *blank = 0;
	while( *start == ' ' )
	    start++;

	const char *p = start;
	while( *p )
	{
	    if( *p != ' ' )
		blank = 0;
	    else if( !blank )
	        blank = p;

	    p++;
	}
	int l = blank ? blank - start : p - start;
	if( l != length )
	{
	    memmove( buffer, start, l );
	    buffer[ l ] = '\0'; 
	    length = l;
	}
}

/**
 * StrBuf::CompressTail
 *
 * @brief Chop the common substring off tail and
 *        prepend with the offset value of the substring
 *        in the passed string.
 *
 * @param the string to match
 * @return offset into string argument
 *         -1 if error
 *         0 if not compressed
 */
int
StrBuf::EncodeTail( StrPtr &s, const char *replaceBytes )
{
	/*
	 * If replaceBytes is NULL, then ASSUME we shall compress
	 * the string. If replaceBytes is not NULL and the contents
	 * does not match the first two bytes of our buffer (e.g. "//")
	 * then we return assuming that the buffer has already been
	 * compressed. (This happens in DbOpen::Put since the record
	 * is written in two parts, the keys then the non key columns).
	 * To compress our string, compare a string with a supplied argument s.
	 * Find the count of trailing identical characters then
	 * truncate the common substring from the end. The
	 * get the offset value for the common string into the supplied
	 * argument, convert to 2-byte hex value and prepend to the leading
	 * non-matching piece. (max offset 255 for FF)
	 */

	// job075871: advance past the client name so that substring
	// is not considered in the match process.
	int i = 2;
	while( i < s.Length() && s.buffer[i] != '/' )
	    i++;
	if( s.buffer[i] != '/' )
	    return 0;

	int shortest = length < (s.Length() - i)? length : (s.Length() - i);
	// bail early if one string is empty
	if( shortest == 0 )
	    return 0;

	// reset counter
	i = 0;

	const unsigned char *a = (const unsigned char *)(s.buffer + s.Length() - 1);
	const unsigned char *b = (const unsigned char *)(buffer + length - 1);

	if( replaceBytes && strncmp(buffer, replaceBytes, 2) != 0)
		return 0;
	while( i < shortest && *a == *b )
	{
	    a--;
	    b--;
	    i++;
	}

	// sanity check
	if ( i > (length - 2) )
	{
	    // If client path contains full depot path
	    // back off a character so that we have enough
	    // room to store offset.
	    if( i == (length - 1) )
		i--;
	    else
		return -1;
	}

	/*
	 * get the offset value into the passed StrPtr where the
	 * common substring starts.
	 */
	int v = s.Length() - i;

	if ((i == 0) || (v > 255) )
	{
	    // nothing to compress or
	    // the offset is too large do not compress the tail
	    return 0;
	}

	// chop off common part of path
	length -= i;
	Terminate();

	// prepend this value to the first 2 bytes of our buffer
	*(buffer+1) = StrOps::OtoX( v & 0xf ); v >>= 4;
	*(buffer)   = v ? StrOps::OtoX( v & 0xf ) : '0';
	return (s.Length() - i);
}

int
StrBuf::DecodeTail( StrPtr &s, const char *replaceBytes )
{
	/*
	 * If replaceBytes is NULL, then ASSUMES a compressed string.
	 * If replaceBytes is not NULL and contains the
	 * identical first two bytes of our buffer (e.g. "//")
	 * then we return assuming that the buffer is uncompressed.
	 * This StrBuf will may grow to accommodate the common
	 * substring which will be appended.  If replacedBytes
	 * is non-NULL then the first two bytes will replace
	 * those currently in the buffer.
	 */

	/* Sanity Checks */

	// bail early if target string is empty
	if( s.Length() == 0 )
	    return -1;

	// bail if not enough room for offset in source
	if( length < 2 )
	    return 0;

	// bail if passed replacement string and it has already been replaced
	if( replaceBytes && strlen(replaceBytes) >= 2 && strncmp(buffer, replaceBytes, 2) == 0)
	    return 0;

	int v = ( StrOps::XtoO( buffer[0] ) << 4 )
	      | ( StrOps::XtoO( buffer[1] ) << 0 );

	// santity check offset value
	if( v <= 2 || v > 255 )
	    return -1;

	if( replaceBytes && strlen(replaceBytes) >= 2 )
	{
	    buffer[0] = replaceBytes[0];
	    buffer[1] = replaceBytes[1];
	}
	if( s.Length() >= v )
	    Append( s.buffer + v );
	else
	    return -1;
	return v;
}

void
StrBuf::Compress( StrPtr *s )
{
	// Compare a string with a supplied argument 
	// Find the count of leading identical characters then
	// convert to 2-byte hex value and append the trailing 
	// non-matching piece.  (max 255 for FF)

	const unsigned char *a = (const unsigned char *)buffer;
	const unsigned char *b = (const unsigned char *)s->buffer;
	int n = length;
	int i = 0;

	while( n && *a && *a == *b && ++i < 256 )
	    ++a, ++b, --n;

	// leading characters in common (max 255)

	int v = ( length - n );
	int newSize = (length - v) + 4;
	int l = v;

	char *newBuffer = new char[ newSize ];
	*(newBuffer+1) = StrOps::OtoX( v & 0xf ); v >>= 4;
	*(newBuffer)   = v ? StrOps::OtoX( v & 0xf ) : '0';
	memcpy( newBuffer + 2, buffer + l, n );
	newBuffer[ n + 2 ] = '\0';

	delete []buffer;

	buffer = newBuffer;
	length = n + 2;
	size = newSize;
}

void
StrBuf::UnCompress( StrPtr *s )
{
	// ASSUMES a compressed string, note uncompressed size
	// could be much bigger since Alloc uses Grow(), but
	// typically this strbuf will be copied into another
	// record format where it will be correctly sized.

	int n = length;

	int v = ( StrOps::XtoO( buffer[0] ) << 4 )
	      | ( StrOps::XtoO( buffer[1] ) << 0 );

	int extra = v - 2;

	if( extra > 0 )
	    Alloc( extra + 1 );

	memmove( buffer + v, buffer + 2, n - 2 );
	memcpy( buffer, s->buffer, v );
	buffer[ n + extra ] = '\0';
	length = n + extra;
}

void
StrFixed::SetBufferSize( p4size_t l )
{
	if( length == l )
	    return;

	delete []buffer;
	this->length = l;
	this->buffer = new char[ l ];
}

/*
 * Converts a 64-bit integer to a "human-readable" format. Is passed the
 * end of the buffer, works backward, returns the beginning of the buffer.
 */
char *
StrHuman::Itoa64( P4INT64 v, char *buffer, int f )
{
	static const char suffix[] = "BKMGTP";
	P4INT64 factor = f;
 
	P4INT64 current = v;
	int     remainder = 0;
	const char *s = suffix;
 
	for( ; s < suffix + 6; s++)
	{
	    if( current < factor )
	        break;
	    else
	    {
	        remainder = (current * 100 / factor ) % 100;
	        current = current / factor;
	    }
	}
	// remainder is a percentage (0 .. 99). Now round that to the nearest
	// 10, and if we get a 10, carry that up to increment current.

# if OS_NT
	// Visual Studio versions prior to VS2013 don't have "round"...
	remainder = (int)floor( ( remainder / (double)10 ) + 0.5 );
# else
	remainder = (int)round( remainder / (double)10 );
# endif

	*--buffer = 0;
	*--buffer = *s;
 
	if( remainder == 10 )
	    current++;
	else if( remainder )
	{
	    do
	    {
	        *--buffer = ( remainder % 10 ) + '0';
	        remainder = remainder / 10;
	    }
	    while( remainder );
 
	    *--buffer = '.';
	}
 
	do
	{
	    *--buffer = ( current % 10 ) + '0';
	    current = current / 10;
	}
	while( current );
 
	return buffer;
}

