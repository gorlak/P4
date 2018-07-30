// -*- mode: C++; tab-width: 8; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/**
 * jnlpos.cc
 *
 * Description:
 * - Manage journal positions:
 *   	{jnlNum, jnlOffset}
 *   and text representation:
 *   	"jnlNum/jnlOffset"
 *
 * Copyright (c) 2013 Perforce Software
 * Confidential.  All Rights Reserved.
 * Original Author:	Mark Wittenberg
 *
 * IDENTIFICATION
 *    $Header: $
 */

#include <stdlib.h>
#include <stdhdrs.h>
#include <strbuf.h>

#include "jnlpos.h"

bool
operator<(const JnlPos &lhs, const JnlPos &rhs)
{
	if( lhs.GetJnlNum() < rhs.GetJnlNum() )
	    return true;
	if( lhs.GetJnlNum() > rhs.GetJnlNum() )
	    return false;

	// same journal number
	return lhs.GetJnlOffset() < rhs.GetJnlOffset();
}

bool
operator==(const JnlPos &lhs, const JnlPos &rhs)
{
	return (lhs.GetJnlNum() == rhs.GetJnlNum()) &&
		(lhs.GetJnlOffset() == rhs.GetJnlOffset());
}

bool
operator!=(const JnlPos &lhs, const JnlPos &rhs)
{
	return !(lhs == rhs);
}

bool
operator<=(const JnlPos &lhs, const JnlPos &rhs)
{
	return (lhs == rhs) || (lhs < rhs);
}

bool
operator>(const JnlPos &lhs, const JnlPos &rhs)
{
	return !(lhs <= rhs);
}

bool
operator>=(const JnlPos &lhs, const JnlPos &rhs)
{
	return (lhs == rhs) || (lhs > rhs);
}

const JnlPos &
JnlPos::Min( const JnlPos &rhs ) const
{
    return JnlPos::Min( *this, rhs );
}

// [static]
const JnlPos &
JnlPos::Min( const JnlPos &a, const JnlPos &b )
{
    return (a < b) ? a : b;
}


const JnlPos &
JnlPos::Max( const JnlPos &rhs ) const
{
    return JnlPos::Max( *this, rhs );
}

// [static]
const JnlPos &
JnlPos::Max( const JnlPos &a, const JnlPos &b )
{
    return (a > b) ? a : b;
}

void
JnlPos::Parse( const char *txt )
{
	char	*endptr = NULL;

	journalNumber = strtol( txt, &endptr, 10 );
	if( *endptr == '/' )
	    SetJnlOffset( strtol(endptr+1, NULL, 10) );
	else
	    SetJnlOffset( 0 );
}

void
JnlPos::Parse( const StrPtr &txt )
{
	Parse( txt.Text() );
}
