/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD5Context structure, pass it to MD5Init, call MD5Update as
 * needed on buffers full of bytes, and then call MD5Final, which
 * will fill a supplied 16-byte array with the digest.
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <strops.h>

# include "md5.h"

/*
 * Note: this code does not perturb data on little-endian machines.
 */

static void 
load32( uint32 *target, unsigned const char *buf, unsigned longs )
{
#ifdef MD5NOBUF
    MD5BufUnion bufUnion;
    bufUnion.i=(uint32 *)buf;
#endif

    do {
#ifdef MD5NOBUF
        *target++=(uint32)*bufUnion.i++;
#else
	*target++ = (uint32) 
	    ((unsigned) buf[3] << 8 | buf[2]) << 16 |
	    ((unsigned) buf[1] << 8 | buf[0]);
	buf += 4;
#endif
    } while (--longs);
}

static void
save32( unsigned char *buf, const uint32 *source, unsigned longs )
{
    do {
	uint32 t = *source++;
	buf[0] = ( t >> 0 ) & 0xff;
	buf[1] = ( t >> 8 ) & 0xff;
	buf[2] = ( t >> 16 ) & 0xff;
	buf[3] = ( t >> 24 ) & 0xff;
	buf += 4;
    } while (--longs);
}

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */

MD5::MD5()
{
    md5[0] = 0x67452301;
    md5[1] = 0xefcdab89;
    md5[2] = 0x98badcfe;
    md5[3] = 0x10325476;
    bytes = 0;
    bits = 0;
    bufSelector = USE_ODDBUF;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */

void 
MD5::Update( const StrPtr &a )
{
    unsigned len = a.Length();
    inbuf = a.UText();
    int t;

    /* Update bitcount */

    t = bytes;
    bytes = ( bytes + len ) % 64;
    bits += len * 8;

    /* Handle any leading odd-sized chunks */

    if (t) {
	unsigned char *p = oddbuf + t;

	t = 64 - t;
	if (len < t) {
	    memcpy(p, inbuf, len);
	    return;
	}
	memcpy(p, inbuf, t);
#ifdef MD5NOBUF
	bufSelector=USE_ODDBUF;
#else
	load32(work, oddbuf, 16);
#endif
	Transform();
	inbuf += t;
	len -= t;
    }

    /* Process data in 64-byte chunks */

#ifdef MD5NOBUF
    bufSelector=USE_INBUF;
#endif
    while (len >= 64) {
#ifndef MD5NOBUF
	load32(work, inbuf, 16);
#endif
	Transform();
	inbuf += 64;
	len -= 64;
    }

    /* Handle any remaining bytes of data. */

    memcpy(oddbuf, inbuf, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern 
 * 1 0* (64-bit count of bits processed, MSB-first)
 */

void 
MD5::Final( unsigned char digest[16] )
{
    unsigned count;
    unsigned char *p;

    /* Set the first char of padding to 0x80.  This is safe since there is
       always at least one byte free */
    p = oddbuf + bytes;
    *p++ = 0x80;

    /* Bytes of padding needed to make 64 bytes */
    count = 64 - 1 - bytes;

    /* Pad out to 56 mod 64 */

    if (count < 8) {
	/* Two lots of padding:  Pad the first block to 64 bytes */
	memset(p, 0, count);
#ifdef MD5NOBUF
	bufSelector=USE_ODDBUF;
#else
	load32( work, oddbuf, 16 );
#endif
	Transform();

	/* Now fill the next block with 56 bytes */
	memset( oddbuf, 0, 56 );
    } else {
	/* Pad block to 56 bytes */
	memset(p, 0, count - 8);
    }

    bufSelector=USE_WORKBUF;
    load32( work, oddbuf, 14);


    /* Append length in bits and transform */

    work[14] = bits >> 0;
    work[15] = bits >> 32;

    Transform();
    save32( digest, md5, 4 );
}

/* The four core functions - F1 is optimized somewhat */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */

/* Source of the non-Windows macros Wei Dai crypto++ 5.6.1, "Public Domain" */
#ifdef OS_NT
#	define MD5STEP(f, w, x, y, z, data, s) \
		( w+= f(x, y, z) + data, w = w<<s | w>>(32-s), w += x )
#else
#	define rotlFixed(x,y) \
        ((x<<y) | (x>>(32-y)))
#	define MD5STEP(f, w, x, y, z, data, s) \
        w = rotlFixed(w + f(x, y, z) + data, s) + x
#endif
	
/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */

void 
MD5::Transform()
{
    register uint32 a, b, c, d;
#ifdef MD5NOBUF
    MD5BufUnion bufUnion;
    bufUnion.i=(uint32 *)(USE_INBUF==bufSelector?inbuf:oddbuf);

    if (USE_WORKBUF==bufSelector)
        bufUnion.i=work;

#   define SOURCEPTR(y) (*(bufUnion.i+y))
#else
    uint32 const *in = work;
#   define SOURCEPTR(y) (*(in+y))
#endif


    a = md5[0];
    b = md5[1];
    c = md5[2];
    d = md5[3];

    MD5STEP(F1, a, b, c, d, SOURCEPTR(0) + 0xd76aa478, 7);
    MD5STEP(F1, d, a, b, c, SOURCEPTR(1) + 0xe8c7b756, 12);
    MD5STEP(F1, c, d, a, b, SOURCEPTR(2) + 0x242070db, 17);
    MD5STEP(F1, b, c, d, a, SOURCEPTR(3) + 0xc1bdceee, 22);
    MD5STEP(F1, a, b, c, d, SOURCEPTR(4) + 0xf57c0faf, 7);
    MD5STEP(F1, d, a, b, c, SOURCEPTR(5) + 0x4787c62a, 12);
    MD5STEP(F1, c, d, a, b, SOURCEPTR(6) + 0xa8304613, 17);
    MD5STEP(F1, b, c, d, a, SOURCEPTR(7) + 0xfd469501, 22);
    MD5STEP(F1, a, b, c, d, SOURCEPTR(8) + 0x698098d8, 7);
    MD5STEP(F1, d, a, b, c, SOURCEPTR(9) + 0x8b44f7af, 12);
    MD5STEP(F1, c, d, a, b, SOURCEPTR(10) + 0xffff5bb1, 17);
    MD5STEP(F1, b, c, d, a, SOURCEPTR(11) + 0x895cd7be, 22);
    MD5STEP(F1, a, b, c, d, SOURCEPTR(12) + 0x6b901122, 7);
    MD5STEP(F1, d, a, b, c, SOURCEPTR(13) + 0xfd987193, 12);
    MD5STEP(F1, c, d, a, b, SOURCEPTR(14) + 0xa679438e, 17);
    MD5STEP(F1, b, c, d, a, SOURCEPTR(15) + 0x49b40821, 22);

    MD5STEP(F2, a, b, c, d, SOURCEPTR(1) + 0xf61e2562, 5);
    MD5STEP(F2, d, a, b, c, SOURCEPTR(6) + 0xc040b340, 9);
    MD5STEP(F2, c, d, a, b, SOURCEPTR(11) + 0x265e5a51, 14);
    MD5STEP(F2, b, c, d, a, SOURCEPTR(0) + 0xe9b6c7aa, 20);
    MD5STEP(F2, a, b, c, d, SOURCEPTR(5) + 0xd62f105d, 5);
    MD5STEP(F2, d, a, b, c, SOURCEPTR(10) + 0x02441453, 9);
    MD5STEP(F2, c, d, a, b, SOURCEPTR(15) + 0xd8a1e681, 14);
    MD5STEP(F2, b, c, d, a, SOURCEPTR(4) + 0xe7d3fbc8, 20);
    MD5STEP(F2, a, b, c, d, SOURCEPTR(9) + 0x21e1cde6, 5);
    MD5STEP(F2, d, a, b, c, SOURCEPTR(14) + 0xc33707d6, 9);
    MD5STEP(F2, c, d, a, b, SOURCEPTR(3) + 0xf4d50d87, 14);
    MD5STEP(F2, b, c, d, a, SOURCEPTR(8) + 0x455a14ed, 20);
    MD5STEP(F2, a, b, c, d, SOURCEPTR(13) + 0xa9e3e905, 5);
    MD5STEP(F2, d, a, b, c, SOURCEPTR(2) + 0xfcefa3f8, 9);
    MD5STEP(F2, c, d, a, b, SOURCEPTR(7) + 0x676f02d9, 14);
    MD5STEP(F2, b, c, d, a, SOURCEPTR(12) + 0x8d2a4c8a, 20);

    MD5STEP(F3, a, b, c, d, SOURCEPTR(5) + 0xfffa3942, 4);
    MD5STEP(F3, d, a, b, c, SOURCEPTR(8) + 0x8771f681, 11);
    MD5STEP(F3, c, d, a, b, SOURCEPTR(11) + 0x6d9d6122, 16);
    MD5STEP(F3, b, c, d, a, SOURCEPTR(14) + 0xfde5380c, 23);
    MD5STEP(F3, a, b, c, d, SOURCEPTR(1) + 0xa4beea44, 4);
    MD5STEP(F3, d, a, b, c, SOURCEPTR(4) + 0x4bdecfa9, 11);
    MD5STEP(F3, c, d, a, b, SOURCEPTR(7) + 0xf6bb4b60, 16);
    MD5STEP(F3, b, c, d, a, SOURCEPTR(10) + 0xbebfbc70, 23);
    MD5STEP(F3, a, b, c, d, SOURCEPTR(13) + 0x289b7ec6, 4);
    MD5STEP(F3, d, a, b, c, SOURCEPTR(0) + 0xeaa127fa, 11);
    MD5STEP(F3, c, d, a, b, SOURCEPTR(3) + 0xd4ef3085, 16);
    MD5STEP(F3, b, c, d, a, SOURCEPTR(6) + 0x04881d05, 23);
    MD5STEP(F3, a, b, c, d, SOURCEPTR(9) + 0xd9d4d039, 4);
    MD5STEP(F3, d, a, b, c, SOURCEPTR(12) + 0xe6db99e5, 11);
    MD5STEP(F3, c, d, a, b, SOURCEPTR(15) + 0x1fa27cf8, 16);
    MD5STEP(F3, b, c, d, a, SOURCEPTR(2) + 0xc4ac5665, 23);

    MD5STEP(F4, a, b, c, d, SOURCEPTR(0) + 0xf4292244, 6);
    MD5STEP(F4, d, a, b, c, SOURCEPTR(7) + 0x432aff97, 10);
    MD5STEP(F4, c, d, a, b, SOURCEPTR(14) + 0xab9423a7, 15);
    MD5STEP(F4, b, c, d, a, SOURCEPTR(5) + 0xfc93a039, 21);
    MD5STEP(F4, a, b, c, d, SOURCEPTR(12) + 0x655b59c3, 6);
    MD5STEP(F4, d, a, b, c, SOURCEPTR(3) + 0x8f0ccc92, 10);
    MD5STEP(F4, c, d, a, b, SOURCEPTR(10) + 0xffeff47d, 15);
    MD5STEP(F4, b, c, d, a, SOURCEPTR(1) + 0x85845dd1, 21);
    MD5STEP(F4, a, b, c, d, SOURCEPTR(8) + 0x6fa87e4f, 6);
    MD5STEP(F4, d, a, b, c, SOURCEPTR(15) + 0xfe2ce6e0, 10);
    MD5STEP(F4, c, d, a, b, SOURCEPTR(6) + 0xa3014314, 15);
    MD5STEP(F4, b, c, d, a, SOURCEPTR(13) + 0x4e0811a1, 21);
    MD5STEP(F4, a, b, c, d, SOURCEPTR(4) + 0xf7537e82, 6);
    MD5STEP(F4, d, a, b, c, SOURCEPTR(11) + 0xbd3af235, 10);
    MD5STEP(F4, c, d, a, b, SOURCEPTR(2) + 0x2ad7d2bb, 15);
    MD5STEP(F4, b, c, d, a, SOURCEPTR(9) + 0xeb86d391, 21);

    md5[0] += a;
    md5[1] += b;
    md5[2] += c;
    md5[3] += d;
}

void
MD5::Final( StrBuf &output )
{
	unsigned char digest[16];

	Final( digest );

	output.Clear();
	StrOps::OtoX( digest, sizeof( digest ), output );
}
