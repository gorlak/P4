
// -*- mode: C++; tab-width: 8; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/**
 * utils.cc
 *
 * Copyright 2017 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */


// global utility funciton

/**
 * ISHex
 * - return true if c is a valid character for a hex value, 
 * - otherwise return false.
 */

#include "utils.h"

bool
IsHex( char c )
{
	if( ( c >= '0' && c <= '9' ) ||
	    ( c >= 'a' && c <= 'f' ) ||
	    ( c >= 'A' && c <= 'F' ) )
	    return true;
	else
	    return false;
} // IsHex

