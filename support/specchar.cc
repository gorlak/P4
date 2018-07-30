/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include "specchar.h"

void
SpecChar::Set( const char *p )
{
	this->p = p - 1;
	this->line = 1;
	this->cc = cEOS;
	this->Advance();
}

void
SpecChar::Advance( void )
{
	char c = *++p;

	if( cc == cNL ) ++line;

	switch( c )
	{
	case ' ':	cc = cSPACE; break;
	case '\t':	cc = cSPACE; break;
	case '\r':	cc = cSPACE; break;
	case '\n':	cc = cNL; break;
	case ':':	cc = cCOLON; break;
	case '#':	cc = cPOUND; break;
	case '\"':	cc = cQUOTE; break;
	case '\0':	cc = cEOS; break;
	default:	cc = cMISC; break;
	}
}

const char *const charNames[] = { 
	"sp", "nl", ":", "#", "\"", "*", "EOS"
} ;

const char *
SpecChar::CharName( void )
{
	return charNames[ this->cc ];
}
