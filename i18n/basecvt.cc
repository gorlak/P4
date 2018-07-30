/*
 * Copyright 2001 Perforce Software.  All rights reserved.
 *
 */

/*
 * basecvt.cc - Character set conversion code base class
 *
 * This is seporate from other converters so that unless you are really
 * possibly going to do character set conversions you will not link
 * in those large tables into the server.  The NT server needs
 * UTF-8 to UTF-16 conversions.
 */

#include <stdhdrs.h>
#include <strbuf.h>
#include <debug.h>

#include "i18napi.h"
#include "charcvt.h"
#include "charman.h"

CharSetCvt::~CharSetCvt()
{
	delete [] fastbuf;
}

unsigned long CharSetCvt::offsetsFromUTF8[6] =
	{0x00000000UL, 0x00003080UL, 0x000E2080UL,
	 0x03C82080UL, 0xFA082080UL, 0x82082080UL};

unsigned long CharSetCvt::minimumFromUTF8[6] =
	{0x00000000UL, 0x00000080UL, 0x00000800UL,
	 0x00010000UL, 0x00200000UL, 0x04000000UL};

char CharSetCvt::bytesFromUTF8[256] = {
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 3,3,3,3,3,3,3,3,4,4,4,4,5,5,5,5};

int
CharSetCvt::LastErr()
{
	return lasterr;
}

void
CharSetCvt::ResetErr()
{
	lasterr = NONE;
}

CharSetCvt *
CharSetCvt::Clone()
{
	return new CharSetCvt;
}

CharSetCvt *
CharSetCvt::ReverseCvt()
{
	return Clone();
}

int
CharSetCvt::Cvt(const char **sourcestart, const char *sourceend,
	       char **targetstart, char *targetend)
{
	int slen = sourceend - *sourcestart;
	int tlen = targetend - *targetstart;

	if (tlen < slen)
	    slen = tlen;

	memcpy((void *)*targetstart, (void *)*sourcestart, slen);
	*sourcestart += slen;
	*targetstart += slen;

	return 0;
}

char *
CharSetCvt::CvtBuffer(const char *s, int slen, int *retlen)
{
	const char *ss, *se, *lastsserr = NULL;
	char *retbuf;
	char *ts, *te;
	int rlen;

	rlen = slen;
	if( rlen & 1 )	// force result length to be even
	    ++rlen;
	se = s + slen;
	for (;;)
	{
	    ResetErr();
	    ts = retbuf = new char[rlen+2];
	    te = ts + rlen;
	    ss = s;

	    Cvt(&ss, se, &ts, te);

	    if (ss == se)
		break;

	    delete [] retbuf;

	    if (LastErr() == NOMAPPING)
		return NULL;

	    if (LastErr() == PARTIALCHAR)
	    {
		if (lastsserr == ss)
		    return NULL;
		lastsserr = ss;
	    }
	    rlen <<= 1;
	}
	if (retlen)
	    *retlen = ts-retbuf;
	*ts++ = '\0';
	*ts = '\0';

	return retbuf;
}

const char *
CharSetCvt::FastCvt(const char *s, int slen, int *retlen)
{
	const char *ss, *se, *lastsserr = NULL;
	char *ts, *te;
	int rlen;

	if (slen + 2 > fastsize) {
	    fastsize = 2 * slen + 2; // make fast buffer big and even in length
	    delete [] fastbuf;
	    fastbuf = new char[fastsize];
	}
	rlen = fastsize - 2;
	se = s + slen;
	for (;;)
	{
	    ResetErr();
	    ts = fastbuf;
	    te = ts + rlen;
	    ss = s;

	    Cvt(&ss, se, &ts, te);

	    if (ss == se)
		break;

	    if (LastErr() == NOMAPPING)
		return NULL;

	    if (LastErr() == PARTIALCHAR)
	    {
		// This ts + 10 is to check if the parial char
		// is due to the source being a partial char
		// not the target as determined by seeing
		// that there is plenty of space (10 bytes)
		// in the target to have completed that character
		if (ts + 10 < te || lastsserr == ss)
		    return NULL;
		lastsserr = ss;
	    }
	    delete [] fastbuf;
	    fastsize <<= 1;
	    fastbuf = new char[fastsize];
	    rlen = fastsize - 2;
	}
	if (retlen)
	    *retlen = ts-fastbuf;
	*ts++ = '\0';
	*ts = '\0';

	return fastbuf;
}

const char *
CharSetCvt::FastCvtQues(const char *s, int slen, int *retlen)
{
	const char *ss, *se, *lastsserr = NULL;
	char *ts, *te;
	int rlen;

	if ( slen + 2 > fastsize ) {
	    fastsize = 2 * slen + 2; // make fast buffer big and even in length
	    delete [] fastbuf;
	    fastbuf = new char[ fastsize ];
	}
	rlen = fastsize - 2;
	se = s + slen;
	for (;;)
	{
	    ResetErr();
	    ts = fastbuf;
	    te = ts + rlen;
	    ss = s;

	restart:
	    Cvt( &ss, se, &ts, te );

	    if ( ss >= se )
		break;

	    if ( ts != te && LastErr() == NOMAPPING )
	    {
		*ts++ = '?';
		CharStep *stepper = FromCharStep( (char *)ss );
		ss = stepper->Next();
		delete stepper;
		if ( ss >= se )
		    break;
		goto restart;
	    }

	    if ( LastErr() == PARTIALCHAR )
	    {
		// This ts + 10 is to check if the parial char
		// is due to the source being a partial char
		// not the target as determined by seeing
		// that there is plenty of space (10 bytes)
		// in the target to have completed that character
		if ( ts + 10 < te || lastsserr == ss )
		    return NULL;
		lastsserr = ss;
	    }
	    delete [] fastbuf;
	    fastsize <<= 1;
	    fastbuf = new char[fastsize];
	    rlen = fastsize - 2;
	}
	if ( retlen )
	    *retlen = ts-fastbuf;
	*ts++ = '\0';
	*ts = '\0';

	return fastbuf;
}

void
CharSetCvt::IgnoreBOM()
{
}

void
CharSetCvt::printmap(unsigned short f, unsigned short t, unsigned short b)
{
	if( b == 0xfffe )
	    p4debug.printf("%04x -> %04x -> unknown\n", f, t);
	else
	    p4debug.printf("%04x -> %04x -> %04x\n", f, t, b);
}

void
CharSetCvt::printmap(unsigned short f, unsigned short t)
{
	p4debug.printf("%04x -> %04x\n", f, t);
}

CharStep *
CharSetCvt::FromCharStep(char *p)
{
	return new CharStep( p );
}

CharSetCvtUTF16::CharSetCvtUTF16(int i, int b)
    : bom( b )
{
	if( i == -1 ) {
	    // detect byte ordering
	    unsigned short s = 1;
	    i = *(unsigned char *)&s;
	}
	fileinvert = invert = i;
}

void
CharSetCvtUTF16::IgnoreBOM()
{
	CharSetCvtFromUTF8::IgnoreBOM();
	fileinvert = invert;
}

CharSetCvt *
CharSetCvtUTF816::Clone()
{
	return new CharSetCvtUTF816( invert, bom );
}

CharSetCvt *
CharSetCvtUTF168::Clone()
{
	return new CharSetCvtUTF168( invert, bom );
}

CharSetCvt *
CharSetCvtUTF816::ReverseCvt()
{
	return new CharSetCvtUTF168( invert, bom );
}

CharSetCvt *
CharSetCvtUTF168::ReverseCvt()
{
	return new CharSetCvtUTF816( invert, bom );
}

int
CharSetCvtUTF816::Cvt(const char **sourcestart, const char *sourceend,
	       char **targetstart, char *targetend)
{
	unsigned int v;

	if( checkBOM && bom )
	{
	    if( *targetstart >= targetend - 2 )
	    {
		lasterr = PARTIALCHAR;
		return 0;
	    }
	    if( fileinvert )
	    {
		**targetstart = 0xff;
		*++*targetstart = 0xfe;
	    }
	    else
	    {
		**targetstart = 0xfe;
		*++*targetstart = 0xff;
	    }
	    ++*targetstart;
	}

	while( *sourcestart < sourceend && *targetstart < targetend - 1 )
	{
	    v = **sourcestart & 0xff;
	    int l;
	    if ( v & 0x80 )
	    {
		l = bytesFromUTF8[v];
		if ( l + *sourcestart >= sourceend )
		{
		    lasterr = PARTIALCHAR;
		    return 0;
		}
		switch( l )
		{
		default:
		    lasterr = NOMAPPING;
		    return 0;
		case 3:
		    // surrogates are needed - check for more target space
		    if( *targetstart > targetend - 4 )
		    {
			lasterr = PARTIALCHAR;
			return 0;
		    }
		    v <<= 6;
		    v += 0xff & *++*sourcestart;
		    // fall through...
		case 2:
		    v <<= 6;
		    v += 0xff & *++*sourcestart;
		    // fall through...
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
#endif
		    // at this point v is a unicode position
		    if( checkBOM && v == 0xfeff )
		    {
			checkBOM = 0;
			++*sourcestart;
			continue;
		    }
		    // note fall through
		}
	    }
	    checkBOM = 0;
# ifdef STRICT_UTF8
	    // check for invalid unicode positions
	    if( ( v & 0x1ff800 ) == 0xd800 || ( v >= 0xfdd0 && v <= 0xfdef ) )
	    {
		lasterr = NOMAPPING;
		*sourcestart -= l;
		return 0;
	    }
# endif
	    ++charcnt;
	    if( v == '\n' ) {
		++linecnt;
		charcnt = 0;
	    }
	    // handle UTF16 surrogates
	    if( v > 0xffff )
	    {
		unsigned int s = ( v >> 10 ) + 0xd7c0;

		if( fileinvert )
		{
		    **targetstart = s & 0xff;
		    *++*targetstart = (s >> 8) & 0xff;
		}
		else
		{
		    **targetstart = (s >> 8) & 0xff;
		    *++*targetstart = s & 0xff;
		}
		++*targetstart;
		v = 0xdc00 | (v & 0x3ff);
	    }

	    if( fileinvert )
	    {
		**targetstart = v & 0xff;
		*++*targetstart = (v >> 8) & 0xff;
	    }
	    else
	    {
		**targetstart = (v >> 8) & 0xff;
		*++*targetstart = v & 0xff;
	    }
	    ++*targetstart;
	    ++*sourcestart;
	}
	if( *sourcestart < sourceend && *targetstart < targetend )
	    lasterr = PARTIALCHAR;
	return 0;
}

int
CharSetCvtUTF168::Cvt(const char **sourcestart, const char *sourceend,
	       char **targetstart, char *targetend)
{
	unsigned int v;

	while( *sourcestart < sourceend-1 && *targetstart < targetend )
	{
	    if( fileinvert )
	    {
		v = **sourcestart & 0xff;
		v |= (*++*sourcestart & 0xff) << 8;
	    }
	    else
	    {
		v = (**sourcestart & 0xff) << 8;
		v |= *++*sourcestart & 0xff;
	    }
	    ++*sourcestart;
	    if( checkBOM )
	    {
		checkBOM = 0;
		switch( v )
		{
		case 0xfffe:
		    fileinvert ^= 1;
		    // fall through...
		case 0xfeff:
		    // suppress BOM
		    continue;
		}
	    }
	    // is this the start of surrogate pair?
	    if( ( v & 0xfc00 ) == 0xd800 )
	    {
		// it is...
		unsigned int s;

		if( *sourcestart >= sourceend-1 )
		{
		    lasterr = PARTIALCHAR;
		    *sourcestart -= 2;
		    return 0;
		}

		if( fileinvert )
		{
		    s = **sourcestart & 0xff;
		    s |= (*++*sourcestart & 0xff) << 8;
		}
		else
		{
		    s = (**sourcestart & 0xff) << 8;
		    s |= *++*sourcestart & 0xff;
		}
		++*sourcestart;
		if( ( s & 0xfc00 ) != 0xdc00 )
		{
		    // trailing surrogate not correct
		    lasterr = NOMAPPING;
		    *sourcestart -= 4;
		    return 0;
		}
		v = ( v << 10 ) + s - 0x35fdc00;	// magic
	    }
	    // emit UTF8 of v
	    if( ( v & 0x1ff800 ) == 0xd800 || ( v >= 0xfdd0 && v <= 0xfdef ) )
	    {
		lasterr = NOMAPPING;
		*sourcestart -= 2;
		if( v >= 0x10000 )
		    *sourcestart -= 2;
		return 0;
	    }
	    if( v >= 0x10000 )
	    {
		// Extended multilingual plane - 4 byte UTF8
		if (3 + *targetstart >= targetend)
		{
		    lasterr = PARTIALCHAR;
		    *sourcestart -= 4;	// 4 because of UTF 16 surrogates
		    return 0;
		}
		**targetstart = 0xf0 | (v >> 18);
		*++*targetstart = 0x80 | ((v >> 12) & 0x3f);
		*++*targetstart = 0x80 | ((v >> 6) & 0x3f);
		*++*targetstart = 0x80 | (v & 0x3f);
	    }
	    else if( v >= 0x800 )
	    {
		if (2 + *targetstart >= targetend)
		{
		    lasterr = PARTIALCHAR;
		    *sourcestart -= 2;
		    return 0;
		}
		**targetstart = 0xe0 | (v >> 12);
		*++*targetstart = 0x80 | ((v >> 6) & 0x3f);
		*++*targetstart = 0x80 | (v & 0x3f);
	    }
	    else if( v >= 0x80 )
	    {
		if (1 + *targetstart >= targetend)
		{
		    lasterr = PARTIALCHAR;
		    *sourcestart -= 2;
		    return 0;
		}
		**targetstart = 0xc0 | (v >> 6);
		*++*targetstart = 0x80 | (v & 0x3f);
	    }
	    else
		**targetstart = v;
	    ++*targetstart;
	}
	if( *sourcestart < sourceend && *targetstart < targetend )
	    lasterr = PARTIALCHAR;
	++charcnt;
	if( v == '\n' ) {
	    ++linecnt;
	    charcnt = 0;
	}
	return 0;
}
CharStep *
CharSetCvtFromUTF8::FromCharStep(char *p)
{
	return new CharStepUTF8( p );
}

void
CharSetCvtFromUTF8::IgnoreBOM()
{
	checkBOM = 1;
}

unsigned short
CharSetCvt::MapThru(unsigned short v,
		   const CharSetCvt::MapEnt *m,
		   int n,
		   unsigned short d)
{
	const MapEnt *e = m + n;
	const MapEnt *c;

	while (m < e)
	{
	    c = (e - m) / 2 + m;
	    if (c->cfrom == v)
		return c->cto;
	    if (c->cfrom < v)
		m = c + 1;
	    else
		e = c;
	}

	return d;
}
