/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

enum SpecCharClass {
	cSPACE,
	cNL,
	cCOLON,
	cPOUND,
	cQUOTE,
	cMISC,
	cEOS
} ;

class SpecChar {
    
    public:

	void 		Set( const char *p );
	void 		Advance( void );
	const char * 	CharName( void );

	const char		*p;
	SpecCharClass	cc;
	int		line;
} ;


