# include <stdhdrs.h>
# include <strbuf.h>
# include "jsonescapes.h"

static void codepointToUtf8( StrBuf &out, unsigned int codepoint );

// Look for and replace:
// \" \\ \/ \b \f \n \r \t \uxxxx
// We silently discard all control characters  (0x00-0x1f),
// unknown escape characters (e.g. \a) and incomplete
// sequences, e.g. \uxxx
void
jsonEscapes( const char *input, int len, StrBuf &out )
{
	const char *in = input;
	int c;
	// We want to avoid 'Append'ing one character at a time
	// to the 'out' StrBuf, so we just remember the unescaped
	// characters we have not copied to the 'out' yet. When
	// we spot an escape sequence we 'flush' these characters,
	// and reset 'begin' so we don't flush them again.
	// At the end of the loop see if we have any to flush.
	// Most strings won't have any escapes, so this just costs
	// us the scan.
	const char *begin = in;

	// 0 = normal
	// 1-4, number of hex bytes to process (after a \u sequence)
	// -1, have seen a '\'
	int state = 0;
	unsigned int codepoint;
	while( in < &input[len] )
	{
	    if( !begin && ( state == 0) )
	        begin = in;

	    c = ( unsigned int )*in++;

	    if( state == 0 )
	    {
	        if( c == '\\' )
	        {
	            state = -1;
	            if( ( in - begin - 1 ) > 0 )
	                out.Append(begin, in - begin - 1);
	            begin = 0;
	        }
	        else
	        {
	            if( ( ( c >= 0 ) && ( c <= 0x1f ) ) )
	            {
	                // we are not allowed a control character
	                // in a JSON string. Silently ignore it.
	                if( ( in - begin - 1 ) > 0 )
	                    out.Append(begin, in - begin - 1);
	                begin = 0;
	            }
	        }
	    }
	    else
	    {
	        if( state == -1 )
	        {
	            switch( c )
	            {
	            case '"':
	                out << "\"";
	                state = 0;
	                begin = 0;
	                break;
	            case '\\':
	                out << "\\";
	                state = 0;
	                begin = 0;
	                break;
	            case '/':
	                out << "/";
	                state = 0;
	                begin = 0;
	                break;
	            case 'b':
	                out << "\b";
	                state = 0;
	                begin = 0;
	                break;
	            case 'f':
	                out << "\f";
	                state = 0;
	                begin = 0;
	                break;
	            case 'n':
	                out << "\n";
	                state = 0;
	                begin = 0;
	                break;
	            case 'r':
	                out << "\r";
	                state = 0;
	                begin = 0;
	                break;
	            case 't':
	                out << "\t";
	                state = 0;
	                begin = 0;
	                break;
	            case 'u':
	                state = 4;
	                codepoint = 0;
	                break;
	            default:
	                // silently discard
	                state = 0;
	                begin = 0;
	                break;
	            }
	        }
	        else
	        {
	            codepoint <<= 4;
	            if( ( c >= '0' ) && ( c <= '9' ) )
	            {
	                codepoint += c - '0';
	            }
	            else
	            {
	                if( ( c >= 'a' ) && ( c <= 'f' ) )
	                {
	                    codepoint += c - 'a' + 10;
	                }
	                else
	                {
	                    if( ( c >= 'A' ) && ( c <= 'F' ) )
	                    {
	                        codepoint += c - 'A' + 10;
	                    }
	                    else
	                    {
	                        // a bad character, backup and
	                        // discard
	                        in--;
	                        state = 0;
	                        begin = 0;
	                        continue;
	                    }
	                }
	            }
	            state--;

	            if( state == 0 )
	            {
	                // check for a hidden null.
	                if( codepoint )
	                {
	                    // push this codepoint coded as utf8
	                    // on to the output stream.
	                    codepointToUtf8( out, codepoint );
	                }
	                begin = 0;
	            }
	        }
	    }
	}
	if( begin && ( ( in - begin ) > 0 ) )
	        out.Append( begin, in - begin );
	out.Terminate();
}

// Convert the codepoint into the correct sequence of utf8
// bytes.
void
codepointToUtf8( StrBuf &out, unsigned int c )
{
	char b[4];
	int len = 0;
	// Ranges taken from https://en.wikipedia.org/wiki/UTF-8
	if( c <= 0x7f )
	{
	    b[0] = c;
	    len = 1;
	}
	else if( ( c >= 0x80 ) && ( c <= 0x7ff ) )
	{
	    b[0] = 0xc0 | ( ( c >> 6 ) & 0x1f );
	    b[1] = 0x80 | ( c & 0x3f );
	    len = 2;
	} else if( ( c >= 0x800 ) && ( c <= 0xffff ) )
	{
	    b[0] = 0xe0 | ( ( c >> 12 ) & 0xf );
	    b[1] = 0x80 | ( ( c >> 6 ) & 0x3f );
	    b[2] = 0x80 | ( c & 0x3f ) ;
	    len = 3;
	} else if( ( c <= 0x10000 ) && ( c <= 0x10ffff ) )
	{
	    b[0] = 0xf0 | ( ( c >> 18 ) & 0x7 );
	    b[1] = 0x80 | ( ( c >> 12 ) & 0x3f );
	    b[2] = 0x80 | ( ( c >> 6 ) & 0x3f );
	    b[3] = 0x80 | ( c & 0x3f );
	    len = 4;
	}
	if( len )
	    out.Append( b, len );
}
