/*
 * Copyright 2005 Perforce Software.  All rights reserved.
 *
 */

/*
 * unicvt.cc - Character set conversion code between unicode encodings
 *	       which are never needed inside the p4d server.  In a
 *	       seporate file to keep server size low.
 */

#include <stdhdrs.h>
#include <strbuf.h>

#include "i18napi.h"
#include "charcvt.h"
#include "charman.h"
#include "validate.h"

CharSetCvtUTF8UTF8::CharSetCvtUTF8UTF8( int dir, int f )
    : flags( f ), validator( NULL )
{
	// do not validate from the server
	if( ( direction = dir ) == -1 && ( flags & UTF8_VALID_CHECK ) )
	    validator = new CharSetUTF8Valid;
}

CharSetCvtUTF8UTF8::~CharSetCvtUTF8UTF8()
{
	delete validator;
}

/*
 * direction controls BOM prepending
 *
 * 0 means never prepend BOM
 * 1 means prepend BOM
 * -1 means only prepend BOM in the reverse direction
 *
 * This allows us to always eliminate the BOM when going into the
 * server while prepending the BOM when going to the client
 * and still use the same code to always suppress a BOM
 */

CharSetCvt *
CharSetCvtUTF8UTF8::Clone()
{
	return new CharSetCvtUTF8UTF8( direction, flags );
}

CharSetCvt *
CharSetCvtUTF8UTF8::ReverseCvt()
{
	return new CharSetCvtUTF8UTF8( -direction, flags );
}

int
CharSetCvtUTF8UTF8::Cvt(const char **sourcestart, const char *sourceend,
		    char **targetstart, char *targetend)
{
	int slen = sourceend - *sourcestart;
	int tlen = targetend - *targetstart;

	if( checkBOM && slen >= 1 && (**sourcestart & 0xff) == 0xef )
	{
	    if( slen < 3 )
	    {
		lasterr = PARTIALCHAR;
		return 0;
	    }
	       
	    if( ((*sourcestart)[1] & 0xff) == 0xbb &&
		((*sourcestart)[2] & 0xff) == 0xbf )
	    {
		*sourcestart += 3;
		slen -= 3;
	    }
	}
	if( checkBOM && ( flags & UTF8_WRITE_BOM ) && direction == 1 )
	{
	    // write a BOM to target
	    if( tlen < 3 )
	    {
		lasterr = PARTIALCHAR;
		return 0;
	    }
	    **targetstart = 0xef;
	    *++*targetstart = 0xbb;
	    *++*targetstart = 0xbf;
	    ++*targetstart;
	    tlen -= 3;
	}
	checkBOM = 0;

	if( tlen < slen )
	    slen = tlen;

	if( validator )
	{
	    const char *ep, *sp;
	    sp = (const char *)*sourcestart;
	    switch ( validator->Valid( sp, slen, &ep ) )
	    {
	    case 0:
		// eventually not valid
		lasterr = NOMAPPING;
		slen = ep - sp;
		validator->Reset();
		break;
	    case 3:
		// valid to a partial char
		lasterr = PARTIALCHAR;
		slen = ep - sp;
		validator->Reset();
		break;
	    case 1:
		// valid, do nothing
		break;
	    }

	    // sigh... need to count newlines...
	    while ( sp < ep )
	    {
		if ( !( sp = (const char *)memchr( sp, '\n', ep - sp ) ) )
			break;
		++linecnt;
		++sp;
	    }
	}

	memcpy( (void *)*targetstart, (void *)*sourcestart, slen );
	*sourcestart += slen;
	*targetstart += slen;

	return 0;
}

CharSetCvt *
CharSetCvtUTF832::Clone()
{
	return new CharSetCvtUTF832( invert, bom );
}

CharSetCvt *
CharSetCvtUTF328::Clone()
{
	return new CharSetCvtUTF328( invert, bom );
}

CharSetCvt *
CharSetCvtUTF832::ReverseCvt()
{
	return new CharSetCvtUTF328( invert, bom );
}

CharSetCvt *
CharSetCvtUTF328::ReverseCvt()
{
	return new CharSetCvtUTF832( invert, bom );
}

int
CharSetCvtUTF832::Cvt(const char **sourcestart, const char *sourceend,
	       char **targetstart, char *targetend)
{
	unsigned int v;

	if( checkBOM && bom )
	{
	    if( 4+*targetstart >= targetend )
	    {
		lasterr = PARTIALCHAR;
		return 0;
	    }
	    if( fileinvert )
	    {
		**targetstart = 0xff;
		*++*targetstart = 0xfe;
		*++*targetstart = 0;
		*++*targetstart = 0;
	    }
	    else
	    {
		**targetstart = 0;
		*++*targetstart = 0;
		*++*targetstart = 0xfe;
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
	    if( fileinvert )
	    {
		**targetstart = v & 0xff;
		*++*targetstart = (v >> 8) & 0xff;
		*++*targetstart = (v >> 16) & 0xff;
		*++*targetstart = (v >> 24) & 0xff;
	    }
	    else
	    {
		**targetstart = (v >> 24) & 0xff;
		*++*targetstart = (v >> 16) & 0xff;
		*++*targetstart = (v >> 8) & 0xff;
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
CharSetCvtUTF328::Cvt(const char **sourcestart, const char *sourceend,
	       char **targetstart, char *targetend)
{
	unsigned int v;

	while( 3+*sourcestart < sourceend && *targetstart < targetend )
	{
	    if( fileinvert )
	    {
		v = **sourcestart & 0xff;
		v |= (*++*sourcestart & 0xff) << 8;
		v |= (*++*sourcestart & 0xff) << 16;
		v |= (*++*sourcestart & 0xff) << 24;
	    }
	    else
	    {
		v = (**sourcestart & 0xff) << 24;
		v |= (*++*sourcestart & 0xff) << 16;
		v |= (*++*sourcestart & 0xff) << 8;
		v |= *++*sourcestart & 0xff;
	    }
	    ++*sourcestart;
	    if( checkBOM )
	    {
		checkBOM = 0;
		switch( v )
		{
		case 0xfffe0000:
		    fileinvert ^= 1;
		    // fall through...
		case 0xfeff:
		    // suppress BOM
		    continue;
		}
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
