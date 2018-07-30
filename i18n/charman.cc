/*
 * Copyright 1995, 2001 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * CharMan - Character manipulation support for i18n environments
 */

# include "charman.h"
# include "i18napi.h"
# include "charcvt.h"

char *
CharStep::Next()
{
	return ++ptr;
}

int
CharStep::CountChars( char *e )
{
	int ret = 0;

	if (Ptr() < e)
	    do {
		++ret;
	    } while (Next() < e);

	return ret;
}

char *
CharStep::Next( int cnt )
{
	while( cnt-- > 0 && *Next() )
	    ;
	return Ptr();
}

char *
CharStepUTF8::Next()
{
	int c = 0xff & *ptr;

	/*
	 * Note that if we see a starting byte like 0b10xxxxxx
	 * We're in the middle of a UTF-8 sequence which should
	 * not happen but may if we're not really dealing with UTF-8.
	 * We could scan forward until the next valid UTF-8 char
	 * is seen, but we'll instead skip byte by byte in
	 * an attempt to handle other character sets with some
	 * chance of success as well as not to overrun the buffer.
	 * Also, the invalid 0xfe and 0xff are advanced only one byte.
	 */

	if ( c >= 192 )
	{
	    if ( c <= 223 )
		++ptr;
	    else if ( c <= 239 )
		ptr += 2;
	    else if ( c <= 247 )
		ptr += 3;
	    else if ( c <= 251 )
		ptr += 4;
	    else if ( c <= 253 )
		ptr += 5;
	}

	return ++ptr;
}

char *
CharStepShiftJis::Next()
{
	int c = 0xff & *ptr;

	if ( c >= 129 && c <= 239 && ( c <= 159 || c >= 224) )
	    if (*++ptr == 0)
		return ptr;

	return ++ptr;
}

char *
CharStepEUCJP::Next()
{
	int c = 0xff & *ptr;

	if ( c >= 161 && c <= 254 || c == 142 )
	{
	    if (*++ptr == 0)
		return ptr;
	}	
	else if ( c == 143 )
	{
	    if (*++ptr == 0)
		return ptr;
	    if (*++ptr == 0)
		return ptr;
	}

	return ++ptr;
}

char *
CharStepCP949::Next()
{
	int c = 0xff & *ptr;

	if ( c >= 0x81 && c <= 0xfd && c != 0xc9 )
	    if (*++ptr == 0)
		return ptr;

	return ++ptr;
}

char *
CharStepCN::Next()
{
	int c = 0xff & *ptr;

	if ( c >= 0x81 && c <= 0xfe )
	    if (*++ptr == 0)
		return ptr;

	return ++ptr;
}

CharStep *
CharStep::Create( char * p, int charset )
{
	switch ((CharSetCvt::CharSet) charset)
	{
	case CharSetCvt::SHIFTJIS:
	    return new CharStepShiftJis( p );
	case CharSetCvt::UTF_8:
	    return new CharStepUTF8( p );
	case CharSetCvt::EUCJP:
	    return new CharStepEUCJP( p );
	case CharSetCvt::CP949:
	    return new CharStepCP949( p );
	default:
	    return new CharStep( p );
	}
}
