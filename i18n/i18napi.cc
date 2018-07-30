/*
 * Copyright 2001 Perforce Software.  All rights reserved.
 *
 */

/*
 * i18napi.cc - API support for charset conversion identifiers
 *
 */

// this NEED_GETPID triggers loading windows.h
#define NEED_GETPID

#include <stdhdrs.h>
#include <strbuf.h>

#include "i18napi.h"
#include "enviro.h"

static const char *charsetname[] = {
    "none",
    "utf8",
    "iso8859-1",
    "utf16-nobom",
    "shiftjis",
    "eucjp",
    "winansi",
    "winoem",
    "macosroman",
    "iso8859-15",
    "iso8859-5",
    "koi8-r",
    "cp1251",
    "utf16le",
    "utf16be",
    "utf16le-bom",
    "utf16be-bom",
    "utf16",
    "utf8-bom",
    "utf32-nobom",
    "utf32le",
    "utf32be",
    "utf32le-bom",
    "utf32be-bom",
    "utf32",
    "utf8unchecked",
    "utf8unchecked-bom",
    "cp949",
    "cp936",
    "cp950",
    "cp850",
    "cp858",
    "cp1253",
    "cp737",
    "iso8859-7",
    "cp1250",
    "cp852",
    "iso8859-2"
};

static unsigned int charsetcount = sizeof(charsetname) / sizeof(*charsetname);

unsigned int 
CharSetApi::CharSetCount()
{
    return charsetcount;
}

const char *
CharSetApi::Name(CharSetApi::CharSet c)
{
	unsigned int i = (unsigned int) c;
	if( i < charsetcount )
	    return charsetname[i];
	return NULL;
}

CharSetApi::CharSet
CharSetApi::Lookup(const char *s, Enviro *env)
{
	StrRef st( s );

	if( st == "auto" )
	    return Discover( env );

	for( unsigned int i = 0; i < charsetcount; ++i)
	    if( st == charsetname[i] )
		return (CharSet) i;
	return CSLOOKUP_ERROR;
}

CharSetApi::CharSet
CharSetApi::Discover(Enviro *enviro)
{
#if defined( OS_NT )

        UINT codePage = GetConsoleCP();

	if( codePage == 0 )
		codePage = GetACP();

        switch (codePage)
        {
	case 437:   return WIN_US_OEM;
//	case 737:   return CP737;
	case 850:   return CP850;
	case 852:   return CP852;
	case 858:   return CP858;
	case 932:   return SHIFTJIS;
	case 936:   return CP936;
	case 949:   return CP949;
	case 950:   return CP950;
	case 1200:  return UTF_16_LE_BOM;
	case 1201:  return UTF_16_BE_BOM;
	case 1250:  return CP1250;
	case 1251:  return WIN_CP_1251;
	case 1252:  return WIN_US_ANSI;
	case 1253:  return CP1253;
	case 10000: return MACOS_ROMAN;
	case 12000: return UTF_32_LE_BOM;
	case 12001: return UTF_32_BE_BOM;
	case 20866: return KOI8_R;
	case 20932: return EUCJP;
	case 28591: return ISO8859_1;
	case 28592: return ISO8859_2;
	case 28595: return ISO8859_5;
	case 28597: return ISO8859_7;
	case 28605: return ISO8859_15;
	case 65001: return UTF_8;
        }
	return (CharSet) -1;

#else

        const char *setInEnv = NULL;

	if( enviro )
	    setInEnv = enviro->Get( "LANG" );
	if( !setInEnv )
	    setInEnv = getenv( "LANG" );

        if( !setInEnv )  // Without LANG, we'll assume UTF-8
            return UTF_8;

        int begin = 0;
	int len = strlen( setInEnv );

        // if it is just set to C, use UTF_8
        if( len == 1 && setInEnv[0] == 'C' )
            return UTF_8;

        // Now we search for this pattern
        // [language[_territory][.codeset][@modifier]]
        // See http://osr507doc.sco.com/en/man/html.M/locale.M.html
        // We are interested in the codeset so look for '.'
        for( begin=0; begin < len; begin++ )
            if( setInEnv[ begin ] == '.' )
                break;

        // modifier is optional
        if( begin < len )
        {
            int end;
            begin++;

            for( end = begin; end < len; end++)
                if( setInEnv[ end ] == '@' )
                    break;
            
            StrBuf charset;
            charset.Set( &(setInEnv[ begin ]), end - begin );
	    setInEnv = charset.Text();

            if( !StrPtr::CCompare(setInEnv, "ISO8859-1") )
                return ISO8859_1;
            if( !StrPtr::CCompare(setInEnv, "ISO8859-2") )
                return ISO8859_2;
            if( !StrPtr::CCompare(setInEnv, "ISO8859-5") )
                return ISO8859_5;
            if( !StrPtr::CCompare(setInEnv, "ISO8859-7") )
                return ISO8859_7;
            if( !StrPtr::CCompare(setInEnv, "ISO8859-15") )
                return ISO8859_15;
            if( !StrPtr::CCompare(setInEnv, "JISX0201.1976-0") )
                return SHIFTJIS;
            if( !StrPtr::CCompare(setInEnv, "JISX0208.1983-0") )
                return SHIFTJIS;
            if( !StrPtr::CCompare(setInEnv, "EUC-JP") )
                return EUCJP;
            if( !StrPtr::CCompare(setInEnv, "UTF-8") )
                return UTF_8;
            if( !StrPtr::CCompare(setInEnv, "GB2312.1980-0") )
                return CP936;
            if( !StrPtr::CCompare(setInEnv, "GB18030") )
                return CP936;
            if( !StrPtr::CCompare(setInEnv, "KSC5601.1987-0") )
                return CP949;
        }

        return UTF_8;

#endif
}

int
CharSetApi::isUnicode(CharSetApi::CharSet c)
{
	switch( c )
	{
	case UTF_8:
	case UTF_8_BOM:
	case UTF_8_UNCHECKED:
	case UTF_8_UNCHECKED_BOM:
	case UTF_16:
	case UTF_16_LE:
	case UTF_16_BE:
	case UTF_16_BOM:
	case UTF_16_LE_BOM:
	case UTF_16_BE_BOM:
	case UTF_32:
	case UTF_32_LE:
	case UTF_32_BE:
	case UTF_32_BOM:
	case UTF_32_LE_BOM:
	case UTF_32_BE_BOM:
	    return 1;
	}
	return 0;
}

int
CharSetApi::Granularity(CharSetApi::CharSet c)
{
	if( c == UTF_16 || c >= UTF_16_LE && c <= UTF_16_BOM )
	    return 2;
	if( c >= UTF_32 && c <= UTF_32_BOM )
	    return 4;
	if( (unsigned int)c < charsetcount )
	    return 1;
	return 0;
}
