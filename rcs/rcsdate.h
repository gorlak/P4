/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsdate.h - format today's date in RCS format
 *
 * Classes defined:
 *
 *	RcsDate - an 18 byte string yy.mm.dd.hh.mm.ss for dates before 2000
 *                 a 20 byte string yyyy.mm.dd.hh.mm.ss otherwise
 *
 * Public methods:
 *
 *	RcsDate::Now() - format today's date in RCS format
 *	RcsDate::Parse() - turn RCS format date into a UNIX date
 *	RcsDate::Text() - get string format
 *
 * History:
 *	2-18-97 (seiwald) - translated to C++.
 */

const int RCS_DATE_BUF_SIZE = 20;

class RcsDate
{
    public:

	inline char	*Text() { return buffer; }

	void		Set( char *value );
	void		Set( time_t clock );
	void		Now();

	time_t		Parse();

    private:

	char	buffer[ RCS_DATE_BUF_SIZE ];
} ;
