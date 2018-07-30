/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * MapChar -- a MapHalf's character string
 *
 * Public Methods:
 *
 *	MapChar::Set() - initialize MapChar, given the string
 *	MapChar::Advance() - advance to the next lexical element
 *	MapChar::ParamNumber() - return wildcard slot of current element
 *			%x = x
 *			* = 10 + nStars
 *			... = 20 + nDots
 *	MapChar::MakeParam() - format a parameter element
 *	MapChar::Name() - dump out current element name for debugging
 *
 * Public attributes:
 *	p - pointer to current element
 *	cc - current element's type
 *	ccPre - previous element's type
 */

const int PARAM_BASE_PERCENT = 0;	// parameter slots for %x
const int PARAM_BASE_STARS = 10;	// parameter slots for *'s
const int PARAM_BASE_DOTS = 20;		// parameter slots for ...'s
const int PARAM_BASE_TOP = 23;		// last slot

enum MapCharClass {
	cEOS,		// \0
	cCHAR,		// any char
	cSLASH,		// /
	cPERC,		// %x
	cSTAR,		// *
	cDOTS		// ...
} ;

class MapChar {

    public:
	int 		Set( char *&p, int &nStars, int &nDots,
			     int caseMode = -1 );

	void		MakeParam( StrBuf &buf, MapChar *mc2, int &wildSlot );

	const char 	*Name() { return mapCharNames[ cc ]; }// debugging only

	int		IsWild() { return cc >= cPERC; }

	int	operator -( MapChar &mc ) { return this->operator-(mc.c); }

	int 	operator -( char oc );

	int	operator ==( MapChar &mc ) { return this->operator==(mc.c); }

	int 	operator ==( char oc );

    public:
	char		c;			// current character
	char		paramNumber;		// current ParamNumber
	MapCharClass	cc;			// current char's type
	int		caseMode;		// case handling

    private:
	static const char * const mapCharNames[];
} ;

inline int
MapChar::Set( char *&p, int &nStars, int &nDots, int caseMode )
{
	this->c = *p;
	this->caseMode = caseMode;

	if( c == '/' )
	{
		cc = cSLASH;
		++p;
	}
	else if( c == '.' && p[1] == '.' && p[2] == '.' )
	{
		cc = cDOTS;
		paramNumber = PARAM_BASE_DOTS + nDots++;
		p += 3;
	}
	else if( c == '%' && p[1] == '%' && p[2] >= '0' && p[2] <= '9' )
	{
		cc = cPERC;
		paramNumber = PARAM_BASE_PERCENT + ( p[2] - '0' );
		p += 3;
	}
	else if( c == '*' )
	{
		cc = cSTAR;
		paramNumber = PARAM_BASE_STARS + nStars++;
		++p;
	}
	else if( c == '\0' )
	{
		cc = cEOS;
		return 0;
	}
	else 
	{
		cc = cCHAR;
		++p;
	}

	return 1;
}

inline void
MapChar::MakeParam( StrBuf &p, MapChar *mc2, int &wildSlot )
{
	if( cc == cDOTS && mc2->cc == cDOTS )
	{
	    p << "...";
	}
	else
	{
	    p << "%%" << ++wildSlot;
	}
}
