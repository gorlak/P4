/*
 * This code implements the lucifer encryption/decryption
 * code but has been modified to work just on small strings.
 *
 * Originally written by Arthur Sorkin in 1984 in FORTRAN
 *
 * Rewritten in 1991 by Jonathan M. Smith
 *
 * This code is in the public domain.  Patents have expired.
 *
 * To encrypt a string (must be 16 bytes or less) instantiate
 * a Mangle object, call In() passing the string, key and an
 * output buffer to store the result.  To decrypt the string
 * instantiate a Mangle object, call Out() passing in the 32
 * character (hex) string and the originally key, string will
 * be returned in the output buffer in the same way as In().
 * 
 * Notes:
 *
 * data must be 16 bytes or less (except see below).
 * key will be truncated to a maximum of 16 characters.
 *
 * As part of the security improvements the digest stored in the
 * server is no longer usable on the client, in order to mangle
 * the 32 character digest (data > 16 characters) alternative
 * interfaces InMD5() and OutMD5() handle the "raw" digest.
 */
#include <stdhdrs.h>
#include <error.h>
#include <strbuf.h>
#include <strops.h>
#include <msgsupp.h>
#include "mangle.h"

#define BPB 8   

Mangle::Mangle()
{
	// diffusion pattern 

	o[0] = 7; o[1] = 6; o[2] = 2; o[3] = 1; 
	o[4] = 5; o[5] = 0; o[6] = 3; o[7] = 4;

	// inverse of fixed permutation

	pr[0] = 2; pr[1] = 5; pr[2] = 4; pr[3] = 0;
	pr[4] = 3; pr[5] = 1; pr[6] = 7; pr[7] = 6;

	// S-box permutations

	s0[0] = 12;  s0[1] = 15;  s0[2] = 7;   s0[3] = 10; 
        s0[4] = 14;  s0[5] = 13;  s0[6] = 11;  s0[7] = 0;  
	s0[8] = 2;   s0[9] = 6;   s0[10] = 3;  s0[11] = 1;
	s0[12] = 9;  s0[13] = 4;  s0[14] = 5;  s0[15] = 8;

	s1[0] = 7;   s1[1] = 2;   s1[2] = 14;  s1[3] = 9;  
	s1[4] = 3;   s1[5] = 11;  s1[6] = 0;   s1[7] = 4;  
	s1[8] = 12;  s1[9] = 13;  s1[10] = 1;  s1[11] = 10;
	s1[12] = 6;  s1[13] = 15; s1[14] = 8;  s1[15] = 5;

	// S-box mix
	s2[0] = 10; s2[1] = 1; s2[2] = 13; s2[3] = 12;
	s2[4] = 4;  s2[5] = 0; s2[6] = 11; s2[7] = 3;
}

void
Mangle::DoIt( 
	const StrPtr &data, 
	const StrPtr &key, 
	StrBuf &result,
	int decipher, 
	int digest,
	Error *e )
{
	int m[128];					
	int k[128];					
	char *p, *q;
	char src[17];
	char enc[17];
	char buf[17];
	int counter;
	int output;
	int c, i, j;

	if( ( decipher && data.Length() != 32 && data.Length() != 0 ) ||
	    ( !decipher && data.Length() > 16 && !digest ) ||
	    ( !decipher && data.Length() != 32 && digest ) )
	{
	    e->Set( MsgSupp::BadMangleParams );
	}

	if( e->Test() )
	    return;

	memset( src, 0, 17 );
	memset( enc, 0, 17 );
	memset( buf, 0, 17 );

	// truncate key to 16 character max

	memcpy( buf, key.Text(), key.Length() > 16 ? 16 : key.Length() );

	if( decipher || digest )
	    StrOps::XtoO( data.Text(), (unsigned char *)src, 16 );
	else
	    memcpy( src, data.Text(), data.Length() );

	p = src;
	q = enc;

	for( counter = 0; counter < 16; counter += 1 )
	{
	    c = buf[counter] & 0xFF;
	    for( i = 0; i < BPB; i += 1 )
	    {
	        k[(BPB*counter)+i] = c & 0x1;
	        c = c>>1;
	    }
	}

	counter = 0;

	/* Mix it up a bit
	 */
	if( decipher )
	{ 
	    s1[4] = s2[0]; s1[5] = s2[1]; s1[6] = s2[2];  s1[7] = s2[3]; 
	}

	/* Lose check for NULL, since its a valid character, assume its a 
	 * 16 byte cipher block (thats all it ever should be, lose the
	 * while( (c=*p++) != '\0' )
	 */

	for( j = 0; j < 16; ++j )
        {
	    c = *p++;
	    if( counter == 16 )
	    {
	        Getdval( decipher, m, k );

	        for( counter = 0; counter < 16; counter += 1 )
	        {
	            output = 0;
	            for( i = BPB-1; i >= 0; i -= 1 )
	                output = (output<<1) + m[(BPB*counter)+i];
	            *q++ = output;
	        }
	        counter = 0;
	    }
	    for( i = 0; i < BPB; i += 1 )
	    {
	        m[(BPB*counter)+i] = c & 0x1;
	        c = c>>1;
	    }
	    counter += 1;
	}

	for( ;counter < 16; counter += 1 )
	    for( i = 0; i < BPB; i += 1 )
                m[(BPB*counter)+i] = 0;

	Getdval( decipher, m, k );

	for( counter = 0; counter < 16; counter += 1 )
	{
	    output = 0;
            for( i = BPB-1; i >= 0; i -= 1 )
                output = (output<<1) + m[(BPB*counter)+i];
            *q++ = output;
	}

	*q = '\0';        

	result.Clear();
    
	if( decipher && !digest )
	    result.Set( enc );
	else
	    StrOps::OtoX( (const unsigned char *)enc, 16, result );
}

void	
Mangle::In( const StrPtr &in, const StrPtr &key, StrBuf &result, Error *e ) 
{ 
	StrBuf mangledValue;
	StrBuf inputSegment;
	int    inputLen = in.Length();
	int    offset = 0;

	while( offset < inputLen )
	{
	    StrBuf data, mangledChunk;
	    int chunkSize = inputLen - offset;
	    if( chunkSize > 16 ) chunkSize = 16;
	    data.Extend( &in.Text()[offset], chunkSize );
	    data.Terminate();
	    DoIt( data, key, mangledChunk, 0, 0, e );     

	    if( e->Test() )
	        return;
	    mangledValue.Append( &mangledChunk );
	    offset += chunkSize;
	}

	result = mangledValue;
}

void	
Mangle::Out( const StrPtr &out, const StrPtr  &key, StrBuf &result, Error *e ) 
{ 
	// Extract the password (cleartext) using the key
	StrBuf extractedValue;
	StrBuf inputSegment;
	int    inputLen = out.Length();
	int    offset = 0;

	while( offset < inputLen )
	{
	    StrBuf data, extractedChunk;
	    int chunkSize = inputLen - offset;
	    if( chunkSize > 32 ) chunkSize = 32;
	    data.Extend( &out.Text()[offset], chunkSize );
	    data.Terminate();
	    DoIt( data, key, extractedChunk, 1, 0, e ); 
	    if( e->Test() )
	        return;
	    extractedValue.Append( &extractedChunk );
	    offset += chunkSize;
	}
	result = extractedValue;
}

void
Mangle::Getdval( int decipher, int m[], int k[] )
{
	int tcbindex, tcbcontrol; /* transfer control byte indices */
	int round, hi, lo, h_0, h_1;
	int bit, temp1;
	int byte, index, v, tr[BPB];

	h_0 = 0;
	h_1 = 1;

	tcbcontrol = decipher  ? 8 : 0;

	/* mix it up a bit
	 */
	if( decipher )
	{ 
	    s1[8] = s2[4]; s1[9] = s2[5]; s1[10] = s2[6]; s1[11] = s2[7]; 
	}

	for( round=0; round<16; round += 1 )
	{
	    if( decipher )
	        tcbcontrol = (tcbcontrol+1) & 0xF;
	    tcbindex = tcbcontrol;
	    for( byte = 0; byte < 8; byte +=1 )
	    {
	        lo = (m[(h_1*64)+(BPB*byte)+7])*8
	            +(m[(h_1*64)+(BPB*byte)+6])*4
	            +(m[(h_1*64)+(BPB*byte)+5])*2
	            +(m[(h_1*64)+(BPB*byte)+4]);
	        hi = (m[(h_1*64)+(BPB*byte)+3])*8
	            +(m[(h_1*64)+(BPB*byte)+2])*4
	            +(m[(h_1*64)+(BPB*byte)+1])*2
	            +(m[(h_1*64)+(BPB*byte)+0]);

	        v = (s0[lo]+16*s1[hi])*(1-k[(BPB*tcbindex)+byte])
	            +(s0[hi]+16*s1[lo])*k[(BPB*tcbindex)+byte];

	        for( temp1 = 0; temp1 < BPB; temp1 += 1 )
	        {
	            tr[temp1] = v & 0x1;
	            v = v>>1;
	        }

	        for( bit = 0; bit < BPB; bit += 1 )
	        {
	            index = (o[bit]+byte) & 0x7;
	            temp1 = m[(h_0*64)+(BPB*index)+bit]
	            	+k[(BPB*tcbcontrol)+pr[bit]]
	            	+tr[pr[bit]];
	            m[(h_0*64)+(BPB*index)+bit] = temp1 & 0x1;
	        }
	    
	        if( byte<7 || decipher )
	            tcbcontrol = (tcbcontrol+1) & 0xF;
	    }

	    temp1 = h_0;
	    h_0 = h_1;
	    h_1 = temp1;
	}

	/* final swap */
	for( byte = 0; byte < 8; byte += 1 )
	{
	    for( bit = 0; bit < BPB; bit += 1 )
	    {
	        temp1 = m[(BPB*byte)+bit];
	        m[(BPB*byte)+bit] = m[64+(BPB*byte)+bit];
	        m[64+(BPB*byte)+bit] = temp1;
	    }
	}
}

void
Mangle::XOR( 
	StrBuf &data, 
	const StrPtr &key, 
	Error *e )
{
	if( data.Length() != 32 && key.Length() != 32 ) 
	    e->Set( MsgSupp::BadMangleParams );

	if( e->Test() )
	    return;

	char src[17];
	char enc[17];
	char buf[17];

	StrOps::XtoO( data.Text(), (unsigned char *)src, 16 );
	StrOps::XtoO( key.Text(), (unsigned char *)enc, 16 );

	for( int i = 0; i < 16; ++i )
	    buf[i] = src[i] ^ enc[i];

	data.Clear();
	StrOps::OtoX( (const unsigned char *)buf, 16, data );
}
