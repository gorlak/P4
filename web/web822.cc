/*
 * Copyright 1999, 2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <strops.h>
# include <strdict.h>
# include <strtable.h>
# include <error.h>

# include <keepalive.h>
# include "netportparser.h"
# include <netconnect.h>
# include <netbuffer.h>
# include "web822.h"

/*
 * Web822.cc -- read and set RFC822 style headers
 *
 * LoadHeaders() uses a simple state machine to parse headers, reading
 * from the underlying NetBuffer (a buffered NetTransport) one byte at
 * a time.
 *
 * The following deficiencies come to mind:
 *
 *	It currently accepts lines without the required :, since the
 *	operation request in HTTP doesn't have it.  This should be
 *	special cased for the first line.
 *
 *	It reads a byte at a time from its source.  Ouch!
 *
 *	It uses the new, wildly inefficient StrBufDict to store the
 *	values.
 *
 *	Decent error messages aren't set on parse error.
 *
 * NetBuffer normally requires flushing, even before closing.
 * But Web822::LoadHeaders() flushes any previous Sends(), and
 * ~Web822() also flushes, so our caller shouldn't worry.
 */

/*
 * Michael's 2 second description of RFC822 style headers.
 * Note state numbers ^x:
 *
 *	Header <HS*> :  <HS*> value* <VS>
 *	^1     ^2    ^3 ^4    ^5     ^6
 *	<HS+> value* <VS>
 *	^7    ^5     ^6
 *
 * HS is space or tab
 * VS is CR, LF, CRLF, LFCR, or CRLF NULL
 */

enum CharClass {
	C_CHAR,		// non-white character
	C_COLON,	// the : char
	C_HS,		// horizontal space (tab, space)
	C_VS,		// lf, cr, crlf, lfcr, crlf\0
	C_LAST
} ;

enum ParseState {
	S_0, S_1, S_2, S_3, 
	S_4, S_5, S_6, S_7, 
	S_ERR, S_END, S_LAST
} ;

ParseState StateTable[ S_LAST ][ C_LAST ] = {

/*		CHAR	COLON	HS	VS */
/* 0 */ {	S_1,	S_ERR,	S_ERR,	S_END	},
/* 1 */ {	S_1,	S_3,	S_2,	S_ERR	},
/* 2 */	{	S_5,	S_3,	S_2,	S_ERR	},
/* 3 */	{	S_5,	S_5,	S_4,	S_ERR	},
/* 4 */	{	S_5,	S_5,	S_4,	S_ERR	},
/* 5 */	{	S_5,	S_5,	S_5,	S_6	},
/* 6 */ {	S_1,	S_ERR,	S_7,	S_END	},
/* 7 */ {	S_5,	S_5,	S_7,	S_ERR	}

} ;

int
Web822::LoadHeader()
{
	// Loading the headers clears both the incoming and the
	// outgoing, and flushes any data sent on previous request.

	transport.Flush( &e );
	recvHeaders.Clear();
	sendHeaders.Clear();
	recvBody.Clear();
	haveReadBody = 0;
	
	/*
	 * We need to handle the crazy vertical space definition,
	 * accepting CR, LF, CRLF, or LFCR.  To do so, we remember
	 * if the previous character was a CR or LF, and soak up a
	 * LF or CR from the input stream.
	 */

	enum Vs {
		V_OK,		// not in vertical space
		V_LF,		// just saw LF, soak a CR
		V_CR		// just saw CR, soak a LF
	} ;

	ParseState state = S_0;
	Vs vs = V_OK;
	StrBuf var, val;
	char c;
	
	while( Receive( &c, 1 ) == 1 )
	{
	    // Save old state, vertical spacing

	    ParseState oldState = state;
	    Vs oldVs = vs;
	    vs = V_OK;

	    // Get the character class, handling vertical spacing

	    CharClass cc;

	    switch( c )
	    {
	    // Null - skip always

	    case 0: continue;

	    // The easy ones

	    default: cc = C_CHAR; break;
	    case ':': cc = C_COLON; break;
	    case ' ': cc = C_HS; break;
	    case '\t': cc = C_HS; break;

	    // Soak up CR if just saw an LF

	    case '\r': 
		if( oldVs == V_LF )
		    continue;
		cc = C_VS;
		vs = V_CR;
		break;

	    // Soak up LF if just saw a CR

	    case '\n': 
		if( oldVs == V_CR )
		    continue;
		cc = C_VS;
		vs = V_LF;
		break;
	    }

	    // Jump to new state, given current state and input

	    state = StateTable[ state ][ cc ];

	    // If we've finished the vertical spacing after
	    // the value, and aren't seeing indenting on the next
	    // line, it is time to save the var/value pair.

	    if( oldState == S_6 && state != S_7 )
	    {
		// save the result
		var.Terminate();
		val.Terminate();
		StrOps::Lower( var );
		recvHeaders.SetVar( var, val );
		var.Clear();
		val.Clear();
	    }

	    // S_1/S_5 -- save var/value
	    // S_END/S_ERR -- return success or failure

	    switch( state )
	    {
	    case S_1: var.Extend( c ); break;
	    case S_5: val.Extend( c ); break;
	    case S_END: return 1;
	    case S_ERR: return 0;
	    }
	}

	// sudden EOF? bail.

	return 0;
}

int
Web822::LoadBody()
{
	// Loading the body flushes any data sent on previous request.
	
	transport.Flush( &e );
	recvBody.Clear();
	haveReadBody = 1;

	// Determine how many bytes to read

	StrPtr * contentlength = GetVar( StrRef ( "content-length" ) );

	if ( contentlength == NULL )
		return 0;

	int nbytes = atoi( contentlength->Value() );
	int nread = 0;
	int currRead = 0;
	char c;

	// Read number of bytes specified in Content-length variable
	// and save result, stripping out leading \n

	while ( nread < nbytes )
	{
	    currRead = Receive( &c, 1 );

		if (!currRead)
			break;		// bail

		if( nread == 0 && c == '\n' )
	    	continue;

	    nread += currRead;

	    *recvBody.Alloc(1) = c;
	}

	recvBody.Terminate();

	return nread;
}

void
Web822::GetRecvHeaders(StrBuf *headers)
{
	StrRef var, val;
	
	for( int i = 0; recvHeaders.GetVar( i, var, val ); i++ )
		*headers << var << ": " << val << "\r\n";
}

char *
Web822::GetBodyData()
{
	// If body data hasn't been read, do it now
	if( !haveReadBody )
	   (void)LoadBody();
	   
	if( recvBody.Length() == 0 )
	    return NULL;
	    
	return recvBody.Text(); 
}

int
Web822::GetBodyLgth()
{
	// If body data hasn't been read, do it now
	if( !haveReadBody )
	   (void)LoadBody();
	   
	return recvBody.Length(); 
}

void
Web822::SendHeader( const StrPtr *response )
{
	// send the http 1.0 response

	*this << "HTTP/1.0 ";
	if( response ) *this << *response;
	*this << "\r\n";

	// Step through the headers

	StrRef var, val;

	for( int i = 0; sendHeaders.GetVar( i, var, val ); i++ )
		*this << var << ": " << val << "\r\n";

	*this << "\r\n";
}

void
Web822::SendRecvHeaders()
{
	StrBuf	headers;
	StrRef var, val;
	
	headers << "Receive headers:\r\n";

	for( int i = 0; recvHeaders.GetVar( i, var, val ); i++ )
		headers << var << ": " << val << "\r\n";

	headers << "End Receive headers\r\n";
	
	Send (headers.Text(), headers.Length() );
}

void
Web822::SendSendHeaders()
{
	StrBuf	headers; 
	StrRef var, val;
	
	headers << "Send headers:\r\n";

	for( int i = 0; sendHeaders.GetVar( i, var, val ); i++ )
	    headers << var << ": " << val << "\r\n";

	headers << "End Send headers\r\n";
	
	Send (headers.Text(), headers.Length() );
}

StrPtr *
Web822::GetAddress( int raf_flags )
{
	return transport.GetAddress( raf_flags );
}

StrPtr *
Web822::GetPeerAddress( int raf_flags )
{
	return transport.GetPeerAddress( raf_flags );
}
