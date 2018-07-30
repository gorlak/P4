// -*- mode: C++; tab-width: 8; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/**
 * uuid.cc
 *
 * Description:
 *	Abstract base class for UUID implementations
 *
 *	See:
 *	    http://en.wikipedia.org/wiki/Uuid
 *	    http://www.boost.org/doc/libs/1_47_0/libs/uuid/uuid.html
 *
 * Copyright 2017 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

#ifdef OS_NT
#  define _CRT_RAND_S
    // define before <stdhdrs.h>/<stdlib.h> to get rand_s()
#endif // OS_NT
#include <stdhdrs.h>
#include <strbuf.h>
#include <time.h>
#include <error.h>
#include <pid.h>

#include "datetime.h"
#include "uuid.h"

/*
 * Orthodox Canonical Form (OCF) methods
 */


/**
 * default ctor
 * - generate a Version 4 (Random) UUID
 */
BaseUUID::BaseUUID()
{
} // default ctor

/**
 * initialize with copies of the given byte value
 * - don't use unless you know what you're doing
 * - mostly useful if you want a NIL UUID.
 */
BaseUUID::BaseUUID(
	int	val)
{
}

/**
 * copy ctor
 */
BaseUUID::BaseUUID(
	const BaseUUID	&rhs)
{
} // copy ctor

/**
 * dtor
 */
BaseUUID::~BaseUUID()
{
} // dtor

/**
 * assignment op
 */
const BaseUUID	&
BaseUUID::operator=(
	const BaseUUID	&rhs)
{
	return *this;
} // op=

/**
 * op==
 */
bool
BaseUUID::operator==(
	const BaseUUID	&rhs) const
{
	return true;
} // op==

/**
 * op!=
 */
bool
BaseUUID::operator!=(
	const BaseUUID	&rhs) const
{
	return !(*this == rhs);
} // op!=

/**
 * oper< for UUIDs
 * - Just compare byte-for-byte; that's good enough.
 * - All UUID implementation have the same size data,
 *   so we don't need to check if one is shorter
 *   than the other.
 */
bool
BaseUUID::operator<(
	const BaseUUID	&rhs) const
{
	for( const_iterator	lhs_iter = begin(),
				rhs_iter = rhs.begin();
	    lhs_iter != end();
	    ++lhs_iter, ++rhs_iter )
	{
	    if( *lhs_iter < *rhs_iter )
		return true;
	    if( *lhs_iter > *rhs_iter )
		return false;
	}

	return false;
} // oper<


// accessors

/**
 * ToStrBuf
 * - Set "buf" to the formatted hexadecimal character representation of this UUID.
 */
StrPtr
BaseUUID::ToStrBuf(StrBuf	&buf) const
{
	// standard format is 8-4-4-4-12 (32 digits plus 4 dashes)

	buf.Set( "12345678-1234-1234-1234-124356789ABC" );

	return buf;
} // ToStrBuf
