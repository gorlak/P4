/*
 * Copyright 2001 Perforce Software.  All rights reserved.
 *
 */

/*
 * charcvt.cc - Real character set conversion code
 *
 * This is seporate from basecvt.cc so that unless you are really
 * possibly going to do character set conversions you will not link
 * in the large conversion tables.
 */

#include <stdhdrs.h>

#include "i18napi.h"
#include "charcvt.h"
#include "charman.h"
#include "debug.h"

class CharSetCvtCache
{
public:
        CharSetCvtCache()
        {
            fromUtf8To = NULL;
            toUtf8From = NULL;
        }

        ~CharSetCvtCache();

        CharSetCvt * FindCvt(CharSetCvt::CharSet from, CharSetCvt::CharSet to);
        void         InsertCvt(CharSetCvt::CharSet from, CharSetCvt::CharSet to, CharSetCvt * cvt);
private:
        CharSetCvt ** fromUtf8To;
        CharSetCvt ** toUtf8From;
};

static CharSetCvtCache gCharSetCvtCache;


CharSetCvtCache::~CharSetCvtCache()
{
        const int charSetCount = CharSetApi::CharSetCount();

        if (fromUtf8To)
        {
            for (int i=0; i<charSetCount; i++)
                delete fromUtf8To[i];
            delete [] fromUtf8To;
            fromUtf8To = NULL;
        }

        if (toUtf8From)
        {
            for (int i=0; i<charSetCount; i++)
                delete toUtf8From[i];
            delete [] toUtf8From;
            toUtf8From = NULL;
        }
}


CharSetCvt *
CharSetCvtCache::FindCvt(CharSetCvt::CharSet from, CharSetCvt::CharSet to)
{
        const int charSetCount = CharSetApi::CharSetCount();

        if (from < 0 || from >= charSetCount)
            return NULL;
        if (to < 0 || to >= charSetCount)
            return NULL;

        if (from == CharSetApi::UTF_8)
        {
            if (!fromUtf8To)
            {
                fromUtf8To = new CharSetCvt*[charSetCount];
                for (int i=0; i<charSetCount; i++)
                   fromUtf8To[i] = NULL;
            }
            if (fromUtf8To[to] != NULL)
            {
                CharSetCvt * charSetCvt = fromUtf8To[to];
                charSetCvt->ResetErr();
                return charSetCvt;
            }
        }
        if (to == CharSetApi::UTF_8)
        {
            if (!toUtf8From)
            {
                toUtf8From = new CharSetCvt*[charSetCount];
                for (int i=0; i<charSetCount; i++)
                    toUtf8From[i] = NULL;
            }
            if (toUtf8From[from] != NULL)
            {
                CharSetCvt * charSetCvt = toUtf8From[from];
                charSetCvt->ResetErr();
                return charSetCvt;
            }
        }
        return NULL;
}

void
CharSetCvtCache::InsertCvt(CharSetCvt::CharSet from, CharSetCvt::CharSet to, CharSetCvt * cvt)
{
        if (from == CharSetApi::UTF_8)
            fromUtf8To[to] = cvt;
        else if (to == CharSetApi::UTF_8)
            toUtf8From[from] = cvt;
}

CharSetCvt *
CharSetCvt::FindCvt(CharSetCvt::CharSet from, CharSetCvt::CharSet to)
{
	switch( from )
	{
	case UTF_8:
	    switch( to )
	    {
	    case UTF_16:
		return new CharSetCvtUTF816; // byte order should match machine
	    case UTF_16_LE:
		return new CharSetCvtUTF816(1);
	    case UTF_16_BE:
		return new CharSetCvtUTF816(0);
	    case UTF_16_BOM:
		return new CharSetCvtUTF816(-1, 1);
	    case UTF_16_LE_BOM:
		return new CharSetCvtUTF816(1, 1);
	    case UTF_16_BE_BOM:
		return new CharSetCvtUTF816(0, 1);
	    case UTF_8_UNCHECKED:
		return new CharSetCvt;
	    case UTF_8_UNCHECKED_BOM:
		return new CharSetCvtUTF8UTF8(1, UTF8_WRITE_BOM);
	    case ISO8859_1:
		return new CharSetCvtUTF8to8859_1;
	    case SHIFTJIS:
		return new CharSetCvtUTF8toShiftJis;
	    case EUCJP:
		return new CharSetCvtUTF8toEUCJP;
	    case WIN_US_ANSI:
		return new CharSetCvtUTF8toSimple(6);
	    case WIN_US_OEM:
		return new CharSetCvtUTF8toSimple(0);
	    case MACOS_ROMAN:
		return new CharSetCvtUTF8toSimple(1);
	    case ISO8859_15:
		return new CharSetCvtUTF8toSimple(2);
	    case ISO8859_5:
		return new CharSetCvtUTF8toSimple(3);
	    case KOI8_R:
		return new CharSetCvtUTF8toSimple(4);
	    case WIN_CP_1251:
		return new CharSetCvtUTF8toSimple(5);
	    case CP850:
		return new CharSetCvtUTF8toSimple(7);
	    case CP858:
		return new CharSetCvtUTF8toSimple(8);
	    case UTF_32:
		return new CharSetCvtUTF832; // byte order should match machine
	    case UTF_32_LE:
		return new CharSetCvtUTF832(1);
	    case UTF_32_BE:
		return new CharSetCvtUTF832(0);
	    case UTF_32_BOM:
		return new CharSetCvtUTF832(-1, 1);
	    case UTF_32_LE_BOM:
		return new CharSetCvtUTF832(1, 1);
	    case UTF_32_BE_BOM:
		return new CharSetCvtUTF832(0, 1);
	    case UTF_8:
		return new CharSetCvtUTF8UTF8(1, UTF8_VALID_CHECK);
	    case UTF_8_BOM:
		return new CharSetCvtUTF8UTF8(1, UTF8_VALID_CHECK|UTF8_WRITE_BOM);
	    case CP949:
		return new CharSetCvtUTF8toCp949;
	    case CP936:
		return new CharSetCvtUTF8toCp936;
	    case CP950:
		return new CharSetCvtUTF8toCp950;
	    case CP737:
		return new CharSetCvtUTF8toSimple(11);
	    case CP1253:
		return new CharSetCvtUTF8toSimple(9);
	    case ISO8859_7:
		return new CharSetCvtUTF8toSimple(10);
	    case CP852:
		return new CharSetCvtUTF8toSimple(13);
	    case CP1250:
		return new CharSetCvtUTF8toSimple(12);
	    case ISO8859_2:
		return new CharSetCvtUTF8toSimple(14);
	    }
	    break;
	case UTF_8_UNCHECKED_BOM:
	    if (to == UTF_8)
		return new CharSetCvtUTF8UTF8(-1, UTF8_WRITE_BOM);
	    break;
	case UTF_8_UNCHECKED:
	    if (to == UTF_8)
		return new CharSetCvt;
	    break;
	case UTF_8_BOM:
	    if (to == UTF_8)
		return new CharSetCvtUTF8UTF8(-1, UTF8_VALID_CHECK|UTF8_WRITE_BOM);
	    break;
	case UTF_16:
	    if (to == UTF_8)
		return new CharSetCvtUTF168;
	    break;
	case UTF_16_BE:
	    if (to == UTF_8)
		return new CharSetCvtUTF168(0);
	    break;
	case UTF_16_LE:
	    if (to == UTF_8)
		return new CharSetCvtUTF168(1);
	    break;
	case UTF_16_BOM:
	    if (to == UTF_8)
		return new CharSetCvtUTF168(-1, 1);
	    break;
	case UTF_16_BE_BOM:
	    if (to == UTF_8)
		return new CharSetCvtUTF168(0, 1);
	    break;
	case UTF_16_LE_BOM:
	    if (to == UTF_8)
		return new CharSetCvtUTF168(1, 1);
	    break;
	case ISO8859_1:
	    if (to == UTF_8)
		return new CharSetCvt8859_1toUTF8;
	    break;
	case ISO8859_15:
	    if (to == UTF_8)
		return new CharSetCvtSimpletoUTF8(2);
	    break;
	case ISO8859_5:
	    if (to == UTF_8)
		return new CharSetCvtSimpletoUTF8(3);
	    break;
	case KOI8_R:
	    if (to == UTF_8)
		return new CharSetCvtSimpletoUTF8(4);
	    break;
	case WIN_CP_1251:
	    if (to == UTF_8)
		return new CharSetCvtSimpletoUTF8(5);
	    break;
	case CP850:
	    if (to == UTF_8)
		return new CharSetCvtSimpletoUTF8(7);
	    break;
	case CP858:
	    if (to == UTF_8)
		return new CharSetCvtSimpletoUTF8(8);
	    break;
	case CP737:
	    if (to == UTF_8)
		return new CharSetCvtSimpletoUTF8(11);
	    break;
	case CP1253:
	    if (to == UTF_8)
		return new CharSetCvtSimpletoUTF8(9);
	    break;
	case ISO8859_7:
	    if (to == UTF_8)
		return new CharSetCvtSimpletoUTF8(10);
	    break;
	case SHIFTJIS:
	    if (to == UTF_8)
		return new CharSetCvtShiftJistoUTF8;
	    break;
	case EUCJP:
	    if (to == UTF_8)
		return new CharSetCvtEUCJPtoUTF8;
	    break;
	case WIN_US_ANSI:
	    if (to == UTF_8)
		return new CharSetCvtSimpletoUTF8(6);
	    break;
	case WIN_US_OEM:
	    if (to == UTF_8)
		return new CharSetCvtSimpletoUTF8(0);
	    break;
	case MACOS_ROMAN:
	    if (to == UTF_8)
		return new CharSetCvtSimpletoUTF8(1);
	    break;
	case CP949:
	    if (to == UTF_8)
		return new CharSetCvtCp949toUTF8;
	    break;
	case CP936:
	    if (to == UTF_8)
		return new CharSetCvtCp936toUTF8;
	    break;
	case CP950:
	    if (to == UTF_8)
		return new CharSetCvtCp950toUTF8;
	    break;
	case UTF_32:
	    if (to == UTF_8)
		return new CharSetCvtUTF328;
	    break;
	case UTF_32_BE:
	    if (to == UTF_8)
		return new CharSetCvtUTF328(0);
	    break;
	case UTF_32_LE:
	    if (to == UTF_8)
		return new CharSetCvtUTF328(1);
	    break;
	case UTF_32_BOM:
	    if (to == UTF_8)
		return new CharSetCvtUTF328(-1, 1);
	    break;
	case UTF_32_BE_BOM:
	    if (to == UTF_8)
		return new CharSetCvtUTF328(0, 1);
	    break;
	case UTF_32_LE_BOM:
	    if (to == UTF_8)
		return new CharSetCvtUTF328(1, 1);
	    break;
	case CP852:
	    if (to == UTF_8)
		return new CharSetCvtSimpletoUTF8(13);
	    break;
	case CP1250:
	    if (to == UTF_8)
		return new CharSetCvtSimpletoUTF8(12);
	    break;
	case ISO8859_2:
	    if (to == UTF_8)
		return new CharSetCvtSimpletoUTF8(14);
	    break;
	}
	return NULL;
}

CharSetCvt *
CharSetCvt::FindCachedCvt(CharSetCvt::CharSet from, CharSetCvt::CharSet to)
{
        CharSetCvt * cvt = gCharSetCvtCache.FindCvt(from, to);
        if (cvt)
            return cvt;
        cvt = FindCvt(from, to);
        if (cvt)
            gCharSetCvtCache.InsertCvt(from, to, cvt);
        return cvt;
}

CharSetCvt *
CharSetCvtUTF8toShiftJis::Clone()
{
	return new CharSetCvtUTF8toShiftJis;
}

CharSetCvt *
CharSetCvtUTF8toShiftJis::ReverseCvt()
{
	return new CharSetCvtShiftJistoUTF8;
}

void
CharSetCvtUTF8toShiftJis::printmap(unsigned short f, unsigned short t, unsigned short b)
{
	if( b == 0xfffe )
	    p4debug.printf("U+%04x -> %04x -> unknown\n", f, t);
	else
	    p4debug.printf("U+%04x -> %04x -> U+%04x\n", f, t, b);
}

void
CharSetCvtShiftJistoUTF8::printmap(unsigned short f, unsigned short t, unsigned short b)
{
	if( b == 0xfffe )
	    p4debug.printf("%04x -> U+%04x -> unknown\n", f, t);
	else
	    p4debug.printf("%04x -> U+%04x -> %04x\n", f, t, b);
}

void
CharSetCvtUTF8toShiftJis::printmap(unsigned short f, unsigned short t)
{
	p4debug.printf("U+%04x -> %04x\n", f, t);
}

void
CharSetCvtShiftJistoUTF8::printmap(unsigned short f, unsigned short t)
{
	p4debug.printf("%04x -> U+%04x\n", f, t);
}

CharSetCvt *
CharSetCvtShiftJistoUTF8::Clone()
{
	return new CharSetCvtShiftJistoUTF8;
}

CharSetCvt *
CharSetCvtShiftJistoUTF8::ReverseCvt()
{
	return new CharSetCvtUTF8toShiftJis;
}

int
CharSetCvtUTF8toShiftJis::Cvt(const char **sourcestart, const char *sourceend,
		    char **targetstart, char *targetend)
{
	unsigned int v, newv;

	while (*sourcestart < sourceend && *targetstart < targetend)
	{
	    v = **sourcestart & 0xff;
	    int l;
	    if (v & 0x80)
	    {
		l = bytesFromUTF8[v];
		if (l + *sourcestart >= sourceend)
		{
		    lasterr = PARTIALCHAR;
		    return 0;
		}
		switch (l)
		{
		case 2:
		    v <<= 6;
		    v += 0xff & *++*sourcestart;
		case 1:
		    v <<= 6;
		    v += 0xff & *++*sourcestart;
		    v -= offsetsFromUTF8[l];
# ifdef STRICT_UTF8
		    if( v < minimumFromUTF8[l] )
		    {
			// illegal over long UTF8 sequence
			lasterr = NOMAPPING;
			*sourcestart -= l;
			return 0;
		    }
# endif
		    // at this point v is UCS 2
		    newv = MapThru(v, UCS2toShiftJis, MapCount(), 0xfffd);
		    if (newv != 0xfffd)
		    {
		    emitit:		    
			if (newv > 0xff)
			{
			    if (2 + *targetstart >= targetend)
			    {
				lasterr = PARTIALCHAR;
				*sourcestart -= l;
				return 0;
			    }
			    *(*targetstart)++ = newv >> 8;
			}
			**targetstart = newv & 0xff;
			break;
		    }
		    // Check if this is a 'user-defined character'
		    if (v >= 0xE000 && v <= 0xE757)
		    {
			// yup...
			v -= 0xE000;
			newv = v / 0xBC;
			v %= 0xBC;
			v += 0x40 + (v >= 0x3F);
			newv = 0xF000 + (newv << 8) + v;
			goto emitit;
		    }
		    if (checkBOM && v == 0xfeff)
		    {
			checkBOM = 0;
			++*sourcestart;
			continue;	// suppress BOM
		    }
		    *sourcestart -= l;
		    // note fall through
		default:
		    lasterr = NOMAPPING;
		    return 0;
		}
	    }
	    else
	    {
		// almost simple ASCII
#ifdef UNICODEMAPPING
		if (v == 0x5c)
		{
		    // map to 0x815F
		    l = 1;
		    v = 0x815f;
		    goto emitit;
		}
		else if (v == 0x7e /* TILDE */)
		{
		    // we'll keep this anyway?
		    lasterr = NOMAPPING;
		    return 0;
		}
		else
#endif
		    **targetstart = v;
	    }
	    ++charcnt;
	    if( v == '\n' ) {
		++linecnt;
		charcnt = 0;
	    }
	    ++*sourcestart;
	    ++*targetstart;
	    checkBOM = 0;
	}    
	return 0;
}

int
CharSetCvtShiftJistoUTF8::Cvt(const char **sourcestart, const char *sourceend,
		    char **targetstart, char *targetend)
{
    unsigned int v, oldv;

    while (*sourcestart < sourceend && *targetstart < targetend)
    {
	v = **sourcestart & 0xff;
	int l = 0;
	if ((v & 0x80) && (v < 0xa1 || v >= 0xe0))
	{
	    if (1 + *sourcestart >= sourceend)
	    {
		lasterr = PARTIALCHAR;
		return 0;
	    }
	    l = 1;
	    v <<= 8;
	    v |= *++*sourcestart & 0xff;
	}
	oldv = v;
	if (v > 0x20)
	    v = MapThru(v, ShiftJistoUCS2, MapCount(), 0xfffd);
	if (v == 0xfffd)
	{
	    int upper, lower;

	    // Check if this is a 'user-defined character'
	    upper = oldv >> 8;
	    lower = oldv & 0xff;
	    if (upper >= 0xF0 && upper <= 0xF9
		  && lower >= 0x40 && lower <= 0xFC && lower != 0x7F)
	    {
		// Is a "user-defined character"
		// compute UTF8
		v = (upper - 0xF0) * 0xBC + 0xE000 - 0x40 +
		    lower - (lower > 0x7F);
	    }
	    else
	    {
		lasterr = NOMAPPING;
		if (l)
		    --*sourcestart;
		return 0;
	    }
	}
	if (v >= 0x800)
	{
	    if (2 + *targetstart >= targetend)
	    {
		lasterr = PARTIALCHAR;
		if (l)
		    --*sourcestart;
		return 0;
	    }
	    **targetstart = 0xe0 | (v >> 12);
	    *++*targetstart = 0x80 | ((v >> 6) & 0x3f);
	    *++*targetstart = 0x80 | (v & 0x3f);
	}
	else if (v >= 0x80)
	{
	    if (1 + *targetstart >= targetend)
	    {
		lasterr = PARTIALCHAR;
		if (l)
		    --*sourcestart;
		return 0;
	    }
	    **targetstart = 0xc0 | (v >> 6);
	    *++*targetstart = 0x80 | (v & 0x3f);
	}
	else
	    **targetstart = v;
	++charcnt;
	if( v == '\n' ) {
	    ++linecnt;
	    charcnt = 0;
	}
	++*targetstart;
	++*sourcestart;
    }
    return 0;
}

CharStep *
CharSetCvtShiftJistoUTF8::FromCharStep( char *p )
{
	return new CharStepShiftJis( p );
}

CharSetCvt *
CharSetCvtUTF8toEUCJP::Clone()
{
    return new CharSetCvtUTF8toEUCJP;
}

CharSetCvt *
CharSetCvtUTF8toEUCJP::ReverseCvt()
{
    return new CharSetCvtEUCJPtoUTF8;
}

CharSetCvt *
CharSetCvtEUCJPtoUTF8::Clone()
{
    return new CharSetCvtEUCJPtoUTF8;
}

CharSetCvt *
CharSetCvtEUCJPtoUTF8::ReverseCvt()
{
    return new CharSetCvtUTF8toEUCJP;
}

int
CharSetCvtUTF8toEUCJP::Cvt(const char **sourcestart, const char *sourceend,
		          char **targetstart, char *targetend)
{
	unsigned int v, oldv;

	while (*sourcestart < sourceend && *targetstart < targetend)
	{
	    v = **sourcestart & 0xff;

	    int l = 0; // extra characters expected
	    int t = 2; // characters output
	
	    if (v > 0x20)
	    {
		l = bytesFromUTF8[v];
		if (l + *sourcestart >= sourceend)
		{
		    lasterr = PARTIALCHAR;
		    return 0;
		}
		switch (l)
		{
		case 2:
		    v <<= 6;
		    v += 0xff & *++*sourcestart;
		case 1:
		    v <<= 6;
		    v += 0xff & *++*sourcestart;
		    v -= offsetsFromUTF8[l];
# ifdef STRICT_UTF8
		    if( v < minimumFromUTF8[l] )
		    {
			// illegal over long UTF8 sequence
			lasterr = NOMAPPING;
			*sourcestart -= l;
			return 0;
		    }
# endif
		    // at this point v is UCS 2
		case 0:
		    oldv = v;
		    v = MapThru(v, UCS2toEUCJP, MapCount(), 0xfffd);
		    if (v == 0xfffd && oldv >= 0xe000 && oldv <= 0xe757)
		    {
			// user defined character
			oldv -= 0xe000;
			int line = oldv / 94;
			v = (line << 8) + (oldv % 94) + (line < 10 ? 0xf5a1 : 0x6B21);
		    }
		    if (v != 0xfffd)
		    {
			if (v > 0xa0) // codeset (1,2,3)
			{
			    if ((v > 0xdf) && (v>>8 < 0xa1))
				t = 3;   // code set 3 (3 chars output)

			    if ((t + *targetstart) >= targetend)
			    {
				lasterr = PARTIALCHAR;
				*sourcestart -= l;
				return 0;
			    }

			    if (t == 3)
			    {
				// code set 3,  prepend 0x8f and offset 0x8080
				*(*targetstart)++ = 0x8f;
				v += 0x8080;
			    }
	                
			    if (v < 0xe0) 
			    {
				// code set 2, prepend 0x8e
				*(*targetstart)++ = 0x8e;
			    }
			    else
			    {
				*(*targetstart)++ = v >> 8;
			    }
			}
			**targetstart = v & 0xff;
			break;
		    }
		    if (checkBOM && oldv == 0xfeff)
		    {
			// suppress BOM
			checkBOM = 0;
			++*sourcestart;
			continue;
		    }
		    *sourcestart -= l;
		    // note fall through
		default:
		    lasterr = NOMAPPING;
		    return 0;
		}
	    }
	    else
	    {
		**targetstart = v;
	    }
	    ++*sourcestart;
	    ++*targetstart;
	    checkBOM = 0;
	    ++charcnt;
	    if( v == '\n' ) {
		++linecnt;
		charcnt = 0;
	    }
	}    
	return 0;
}

int
CharSetCvtEUCJPtoUTF8::Cvt(const char **sourcestart, const char *sourceend,
		    char **targetstart, char *targetend)
{
	unsigned int v, oldv;

	while( (*sourcestart < sourceend) && (*targetstart < targetend) )
	{
	    v = **sourcestart & 0xff;

	    int l = 0; // extra characters expected
	    int c = 0; // code set detection (0-3)

	    if ( v > 0x7e ) // another char rqrd
	    {
		// which codeset (1-3)
		c = (v == 0x8e) ? 2 : ((v == 0x8f) ? 3 : 1);
		l = (c == 3) ? 2 : 1;

		if( (l + *sourcestart) >= sourceend )
		{
		    lasterr = PARTIALCHAR;
		    return 0;
		}

		if( c > 1 ) // lose the first byte its info only
		    v = *++*sourcestart & 0xff;
	    
		if( (c == 1) || (c == 3) )
		{
		    v <<= 8;
		    v |= *++*sourcestart & 0xff;
		}

		// if codeset is 3, subtract offset
		if (c == 3)
		    v -= 0x8080;
	    }
	    oldv = v;
	    if ( v > 0x20 )
		v = MapThru(v, EUCJPtoUCS2, MapCount(), 0xfffd);
	    if (v == 0xfffd)
	    {
		// check for user-defined character
		if ( c == 3 )
		    oldv += 0x8080;
		int c1 = oldv >> 8;
		int c2 = oldv & 0xff;

		if ( c1 >= 0xF5 && c1 <= 0xFE && c2 >= 0xA1 && c2 <=0xFE )
		{
		    // is a user-defined character
		    c1 -= 0xF5;
		    c2 -= 0xA1;
		    v = 0xE000 + (c1 * 94) + c2;
		    if (c == 3)
			v += 940;
		}
		else
		{
		    lasterr = NOMAPPING;
		    while(l--)
			--*sourcestart;
		    return 0;
		}
	    }
	    if (v >= 0x800)  // 3 UTF8 bytes required
	    {
		if (2 + *targetstart >= targetend)
		{
		    lasterr = PARTIALCHAR;
		    while(l--)
			--*sourcestart;
		    return 0;
		}
		**targetstart = 0xe0 | (v >> 12);
		*++*targetstart = 0x80 | ((v >> 6) & 0x3f);
		*++*targetstart = 0x80 | (v & 0x3f);
	    }
	    else if (v >= 0x80) // 2 UTF8 bytes required
	    {
		if (1 + *targetstart >= targetend)
		{
		    lasterr = PARTIALCHAR;
		    while(l--)
			--*sourcestart;
		    return 0;
		}
		**targetstart = 0xc0 | (v >> 6);
		*++*targetstart = 0x80 | (v & 0x3f);
	    }
	    else
		**targetstart = v; // 1 UTF8 byte required
	    ++*targetstart;
	    ++*sourcestart;
	    ++charcnt;
	    if( v == '\n' ) {
		++linecnt;
		charcnt = 0;
	    }
	}
	return 0;
}

CharStep *
CharSetCvtEUCJPtoUTF8::FromCharStep( char *p )
{
	return new CharStepEUCJP( p );
}

static char *
cvteucval(unsigned short v)
{
	static char obuf[20];

	if (v > 0x7f && v < 0x8000)
	{
	    if (v <= 0xff)
		sprintf(obuf, "  8e%2x", v);
	    else
		sprintf(obuf, "8f%4x", v ^ 0x8080);
	}
	else
	    sprintf(obuf, "%6x", v);
	return obuf;
}

void
CharSetCvtUTF8toEUCJP::printmap(unsigned short f, unsigned short t, unsigned short b)
{
	if( b == 0xfffe )
	    p4debug.printf("U+%04x -> %s -> unknown\n", f, cvteucval(t));
	else
	    p4debug.printf("U+%04x -> %s -> U+%04x\n", f, cvteucval(t), b);
}

void
CharSetCvtEUCJPtoUTF8::printmap(unsigned short f, unsigned short t, unsigned short b)
{
	if( b == 0xfffe )
	    p4debug.printf("%s -> U+%04x -> unknown\n", cvteucval(f), t);
	else
	{
	    p4debug.printf("%s", cvteucval(f));
	    p4debug.printf(" -> U+%04x -> %s\n", t, cvteucval(b));
	}
}
void
CharSetCvtUTF8toEUCJP::printmap(unsigned short f, unsigned short t)
{
	p4debug.printf("U+%04x -> %s\n", f, cvteucval(t));
}

void
CharSetCvtEUCJPtoUTF8::printmap(unsigned short f, unsigned short t)
{
	p4debug.printf("%s -> U+%04x\n", cvteucval(f), t);
}

CharSetCvt *
CharSetCvtUTF8toCp949::Clone()
{
	return new CharSetCvtUTF8toCp949;
}

CharSetCvt *
CharSetCvtUTF8toCp949::ReverseCvt()
{
	return new CharSetCvtCp949toUTF8;
}

CharSetCvt *
CharSetCvtUTF8toCp936::Clone()
{
	return new CharSetCvtUTF8toCp936;
}

CharSetCvt *
CharSetCvtUTF8toCp936::ReverseCvt()
{
	return new CharSetCvtCp936toUTF8;
}

CharSetCvt *
CharSetCvtUTF8toCp950::Clone()
{
	return new CharSetCvtUTF8toCp950;
}

CharSetCvt *
CharSetCvtUTF8toCp950::ReverseCvt()
{
	return new CharSetCvtCp950toUTF8;
}

void
CharSetCvtUTF8toCp::printmap(unsigned short f, unsigned short t, unsigned short b)
{
	if( b == 0xfffe )
	    p4debug.printf("U+%04x -> %04x -> unknown\n", f, t);
	else
	    p4debug.printf("U+%04x -> %04x -> U+%04x\n", f, t, b);
}

void
CharSetCvtCptoUTF8::printmap(unsigned short f, unsigned short t, unsigned short b)
{
	if( b == 0xfffe )
	    p4debug.printf("%04x -> U+%04x -> unknown\n", f, t);
	else
	    p4debug.printf("%04x -> U+%04x -> %04x\n", f, t, b);
}

void
CharSetCvtUTF8toCp::printmap(unsigned short f, unsigned short t)
{
	p4debug.printf("U+%04x -> %04x\n", f, t);
}

void
CharSetCvtCptoUTF8::printmap(unsigned short f, unsigned short t)
{
	p4debug.printf("%04x -> U+%04x\n", f, t);
}

int
CharSetCvtUTF8toCp::Cvt(const char **sourcestart, const char *sourceend,
		    char **targetstart, char *targetend)
{
	unsigned int v, newv;

	while (*sourcestart < sourceend && *targetstart < targetend)
	{
	    v = **sourcestart & 0xff;
	    int l;
	    if (v & 0x80)
	    {
		l = bytesFromUTF8[v];
		if (l + *sourcestart >= sourceend)
		{
		    lasterr = PARTIALCHAR;
		    return 0;
		}
		switch (l)
		{
		case 2:
		    v <<= 6;
		    v += 0xff & *++*sourcestart;
		case 1:
		    v <<= 6;
		    v += 0xff & *++*sourcestart;
		    v -= offsetsFromUTF8[l];
# ifdef STRICT_UTF8
		    if( v < minimumFromUTF8[l] )
		    {
			// illegal over long UTF8 sequence
			lasterr = NOMAPPING;
			*sourcestart -= l;
			return 0;
		    }
# endif
		    // at this point v is UCS 2
		    newv = MapThru(v, toMap, toMapSize, 0xfffd);
		    if (newv != 0xfffd)
		    {
			if (newv > 0xff)
			{
			    if (2 + *targetstart >= targetend)
			    {
				lasterr = PARTIALCHAR;
				*sourcestart -= l;
				return 0;
			    }
			    *(*targetstart)++ = newv >> 8;
			}
			**targetstart = newv & 0xff;
			break;
		    }
		    if (checkBOM && v == 0xfeff)
		    {
			checkBOM = 0;
			++*sourcestart;
			continue;	// suppress BOM
		    }
		    *sourcestart -= l;
		    // note fall through
		default:
		    lasterr = NOMAPPING;
		    return 0;
		}
	    }
	    else
	    {
		**targetstart = v;
	    }
	    ++charcnt;
	    if( v == '\n' ) {
		++linecnt;
		charcnt = 0;
	    }
	    ++*sourcestart;
	    ++*targetstart;
	    checkBOM = 0;
	}    
	return 0;
}

CharSetCvt *
CharSetCvtCp949toUTF8::Clone()
{
	return new CharSetCvtCp949toUTF8;
}

CharSetCvt *
CharSetCvtCp949toUTF8::ReverseCvt()
{
	return new CharSetCvtUTF8toCp949;
}

CharSetCvt *
CharSetCvtCp936toUTF8::Clone()
{
	return new CharSetCvtCp936toUTF8;
}

CharSetCvt *
CharSetCvtCp936toUTF8::ReverseCvt()
{
	return new CharSetCvtUTF8toCp936;
}

CharSetCvt *
CharSetCvtCp950toUTF8::Clone()
{
	return new CharSetCvtCp950toUTF8;
}

CharSetCvt *
CharSetCvtCp950toUTF8::ReverseCvt()
{
	return new CharSetCvtUTF8toCp950;
}

int
CharSetCvtCp936toUTF8::isDoubleByte( int leadByte )
{
	return leadByte >= 0x81 && leadByte <= 0xfe;
}

int
CharSetCvtCp949toUTF8::isDoubleByte( int leadByte )
{
	return leadByte >= 0x81 && leadByte <= 0xfd && leadByte != 0xc9;
}

int
CharSetCvtCp950toUTF8::isDoubleByte( int leadByte )
{
	return leadByte >= 0xa1 && leadByte <= 0xc6
	    || leadByte >= 0xc9 && leadByte <= 0xf9;
}

int
CharSetCvtCptoUTF8::Cvt(const char **sourcestart, const char *sourceend,
		    char **targetstart, char *targetend)
{
    unsigned int v;

    while (*sourcestart < sourceend && *targetstart < targetend)
    {
	v = **sourcestart & 0xff;
	int l = 0;
	if ( isDoubleByte( v ) )
	{
	    if (1 + *sourcestart >= sourceend)
	    {
		lasterr = PARTIALCHAR;
		return 0;
	    }
	    l = 1;
	    v <<= 8;
	    v |= *++*sourcestart & 0xff;
	}
	if (v > 0x7f)
	    v = MapThru(v, toMap, toMapSize, 0xfffd);
	if (v == 0xfffd)
	{
	    lasterr = NOMAPPING;
	    if (l)
		--*sourcestart;
	    return 0;
	}
	if (v >= 0x800)
	{
	    if (2 + *targetstart >= targetend)
	    {
		lasterr = PARTIALCHAR;
		if (l)
		    --*sourcestart;
		return 0;
	    }
	    **targetstart = 0xe0 | (v >> 12);
	    *++*targetstart = 0x80 | ((v >> 6) & 0x3f);
	    *++*targetstart = 0x80 | (v & 0x3f);
	}
	else if (v >= 0x80)
	{
	    if (1 + *targetstart >= targetend)
	    {
		lasterr = PARTIALCHAR;
		if (l)
		    --*sourcestart;
		return 0;
	    }
	    **targetstart = 0xc0 | (v >> 6);
	    *++*targetstart = 0x80 | (v & 0x3f);
	}
	else
	    **targetstart = v;
	++charcnt;
	if( v == '\n' ) {
	    ++linecnt;
	    charcnt = 0;
	}
	++*targetstart;
	++*sourcestart;
    }
    return 0;
}

CharStep *
CharSetCvtCp949toUTF8::FromCharStep( char *p )
{
	return new CharStepCP949( p );
}

CharStep *
CharSetCvtCp936toUTF8::FromCharStep( char *p )
{
	return new CharStepCN( p );
}

CharStep *
CharSetCvtCp950toUTF8::FromCharStep( char *p )
{
	return new CharStepCN( p );
}
