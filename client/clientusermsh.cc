/*
 * Copyright 1995, 2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * ClientUserMarshal - Classes for doing ClientUser I/O as 
 *		       marshalled data for scripting languages.
 */


# define NEED_FILE

# ifdef OS_NT
# define NEED_FCNTL
# endif

# include <stdhdrs.h>

# include <strbuf.h>
# include <strops.h>
# include <strdict.h>
# include <strtable.h>
# include <enviro.h>
# include <error.h>

# include <signaler.h>
# include <filesys.h>
# include <diff.h>

# include <spec.h>
# include <msgclient.h>
# include <p4tags.h>

# include "clientuser.h"
# include "clientusermsh.h"

# ifdef OS_SCO
# define INLINE /**/
# else
# define INLINE inline
# endif

/*******************************************************************************
 * Local class definitions
 ******************************************************************************/

/*
 * MarshalDict : a StrBuf that holds a marshalled Dictionary Object
 *
 * Virtual base class for language specific marshalling. 
 */
class MarshalDict : public StrBuf
{
    public:

	virtual		~MarshalDict();

	// Read/Write

	virtual void	StartWrite( const char *code ) = 0;
	virtual void	EndWrite() = 0;

	virtual void	StartRead( Error *e ) = 0;
	virtual void	EndRead( Error *e ) = 0;

	// Writing dictionary pairs

	void		Add( const char *code, const StrPtr &value )
			{ AddString( StrRef( code ) ); AddString( value ); }

	void		Add( const StrPtr &code, const StrPtr &value )
			{ AddString( code ); AddString( value ); }

	void		Add( const char *code, int value )
			{ AddString( StrRef( code ) ); AddInt( value ); }


	// Reading dictionary pairs

	virtual int Get( StrBuf &var, StrBuf &val ) = 0;

    protected:

	// Low level string/int/etc

	virtual void	AddInt( int value ) = 0;
	virtual void	AddString( const StrPtr &value ) = 0;

	void		AddCode( char c )
			{ Extend( c ); }

	INLINE int	GetChar( char c );

	StrRef		s;	// StrRef access to the buffer


} ;

/*
 * PythonDict : a MarshalDict that holds a marshalled Python Dictionary Object
 *
 * This class either reads or writes (from stdin/stdout) a Python
 * dictionary object in Python's "marshalling" format.
 *
 * PythonDict will write the object if the constructor is given a
 * "code" value, which will appear in the dictionary as "code" : code.
 */

class PythonDict : public MarshalDict
{
    public:

	// Read/Write

	void		StartWrite( const char *code );
	void		EndWrite();

	void		StartRead( Error *e );
	void		EndRead( Error *e );


	// Reading dictionary pairs

	INLINE int	Get( StrBuf &var, StrBuf &val );

    protected:

	// Low level string/int/etc

	void		AddInt( int value )
			{ AddCode( 'i' ); StrOps::PackInt( *this, value ); }

	void		AddString( const StrPtr &value )
			{ AddCode( 's' ); StrOps::PackString( *this, value ); }

} ;

/*
 * RubyDict : a MarshalDict that holds a marshalled Ruby Hash Object
 *
 * This class either reads or writes (from stdin/stdout) a Ruby
 * hash object in Ruby's "marshalled" format.  This differs from the
 * Python version in that Ruby marshalled objects have their length at
 * the beginning so we have to save the actual write till the end when
 * we know what the length should be.
 *
 */


/*
 * Minimum Ruby marshalling format supported. If the major number of any
 * input matches, we'll try and read it even if the minor number differs.
 * For output, we'll always use this version.
 */
#define RUBY_SUPPORTED_MAJOR		4
#define RUBY_SUPPORTED_MINOR		6

/*
 * Some macros to help with version handling
 */
#define RUBY_VERSION( maj, min )	( (maj << 8) | min  )
#define RUBY_MAJOR( ver )		( (ver >> 8) & 0x0f )
#define RUBY_MINOR( ver )		( ver & 0x0f )

class RubyDict : public MarshalDict
{
    public:

	// Read/Write

	void		StartWrite( const char *code );
	void		EndWrite();

	void		StartRead( Error *e );
	void		EndRead( Error *e );


	// Reading dictionary pairs

	INLINE int	Get( StrBuf &var, StrBuf &val );

    private:

	// Low level string/int/etc to implement MarshalDict interface

	void		AddInt( int value );
	void		AddString( const StrPtr &value );

	// Class Methods supporting Ruby Marshalled format

	static void	PackInt(   StrBuf &dict, int value );
	static int	UnpackInt( StrRef &str );
	static void	UnpackString( StrRef &str, StrBuf &buf );
	static int	UnpackVersion( StrRef &str );

    private:
	int		elemCount;	// Number of elements in the hash

} ;


/*
 * PhpDict : a MarshalDict that holds a serialized PHP array.
 *
 * This class either reads or writes (from stdin/stdout) an array
 * in Serialized PHP format.
 */
class PhpDict : public MarshalDict
{
    public:

    // Read/Write

    void        StartWrite( const char *code );
    void        EndWrite();

    void        StartRead( Error *e );
    void        EndRead( Error *e );


    // Reading dictionary pairs

    INLINE int  Get( StrBuf &var, StrBuf &val );

    protected:

    // Low level string/int/etc to implement MarshalDict interface

    void        AddInt( int value );
    void        AddString( const StrPtr &value );

    // Class method supporting string de-serialization

    static int  UnpackString( StrRef &str, StrBuf &buf );
    
    private:
    int     elemCount;  // Number of elements in the array

} ;


/*******************************************************************************
 * MarshalDict methods
 ******************************************************************************/

// empty virtual destructor
MarshalDict::~MarshalDict()
{
}

/*
 * Checks whether or not the next char in the input is what is expected.
 * returns 1 if it is, and zero if it's not.
 */

INLINE int
MarshalDict::GetChar( char c ) 
{
	if( !s.Length() || s[0] != c )
	    return 0;
	s.Set( s.Text() + 1, s.Length() - 1 );
	return 1;
}


/*******************************************************************************
 *  PythonDict methods
 ******************************************************************************/

/*
 * Get a variable and value pair from a Marshalled Python dictionary
 * Returns non-zero on success.
 */

INLINE int
PythonDict::Get( StrBuf &var, StrBuf &val )
{
	if( !GetChar('s') && !GetChar('u') )
		// Return if input is neither a string nor an Unicode
		// string (Python 3.x uses Unicode strings by default).
		return 0;

	StrOps::UnpackString( s, var ); // bytes in 'u' strings are always 
	                                // UTF-8 encoded.
	
	if( !GetChar('s') && !GetChar('u') )
		return 0;
	StrOps::UnpackString( s, val );

	return 1;
}

/*
 * Prepare a Python Marhsalled dictionary for writing. Just involves
 * opening the dictionary with a "{" character and writing the "code"
 * member.
 */

void
PythonDict::StartWrite( const char *code ) 
{ 
    	Clear();
	AddCode( '{' );
	Add( "code", StrRef( code ) );
	s.Set( 0, 0 ); 
}

/*
 * Close a marshalled dictionary and write it to stdout.
 */

void
PythonDict::EndWrite() 
{ 
	AddCode( '0' ); 
}

/*
 * Start reading a Python marshalled dictionary. 
 */

void
PythonDict::StartRead( Error *e )
{
    	s.Set( *this );
	if( !GetChar( '{' ) )
	    e->Set( MsgClient::BadMarshalInput );
}

/*
 * Finish off the read of a Python marshalled dictionary. Just involves
 * reading the trailing '0'
 */

void
PythonDict::EndRead( Error *e )
{
	if( !GetChar( '0' ) )
	    e->Set( MsgClient::BadMarshalInput );
}

/*******************************************************************************
 *  RubyDict methods
 ******************************************************************************/

/*
 * Read the next key = value pair from the marshalled hash. When reading
 * the elemcount is the number of pairs so we only decrease it by one.
 */

INLINE int
RubyDict::Get( StrBuf &var, StrBuf &val )
{
    	if( ! elemCount ) return 0;

	if( !GetChar( '"' ) ) return 0;
	UnpackString( s, var );

	if( ! GetChar( '"' ) ) return 0;
	UnpackString( s, val );

	--elemCount;
	return 1;
}

/*
 * Append an integer to the marshalled data in Ruby marshalled format.
 */

void
RubyDict::AddInt( int value )
{
	AddCode( 'i' );
	PackInt( *this, value );
	elemCount++;
}

/*
 * Append a string to the marshalled data in Ruby marshalled format
 */


void 
RubyDict::AddString( const StrPtr &value )
{
	AddCode( '"' );
	PackInt( *this, value.Length() );
	Append( value.Text(), value.Length() );
	elemCount++;
}

/*
 * Initialise the Ruby marshalled hash. We don't write the preamble at
 * this point because we don't know the length of the hash. 
 */

void
RubyDict::StartWrite( const char *code ) 
{ 
    	Clear();
	elemCount = 0;		// No of elements (i.e 1 per key, 1 per value)
	Add( "code", StrRef( code ) );
	s.Set( 0, 0 ); 
}

/*
 * Terminate the hash. Now that we know the number of elements, we can
 * wite out the preamble and the hash data itself.
 */

void
RubyDict::EndWrite() 
{ 
	/*
	 * Because Ruby marshalled hashes contain their length, we can't
	 * write the preamble until we know the number of elements in the
	 * hash. So the string is built without any preamble and we
	 * now have to work out the number of hash pairs from elemCount
	 * and write the preamble accordingly
	 */

    	StrBuf  tmp;
	char *t = tmp.Alloc( 4 );

	t[0] = RUBY_SUPPORTED_MAJOR;
	t[1] = RUBY_SUPPORTED_MINOR;
	t[2] = '{'; 			// Marks the start of a hash
	tmp.SetEnd( t + 3 );

	PackInt( tmp, elemCount / 2 );

	// Append our current contents to the header
	tmp << *this;

	// Copy the final result into our buffer
	Set( tmp );
}


/*
 * Start reading a Ruby marshalled hash. It should be prefixed by
 * the major and minor marshalling numbers to make sure we're using the
 * right version of the marshalling format. 
 */

void
RubyDict::StartRead( Error *e )
{
    	s.Set( *this );

    	int valid = 1;
	int version = UnpackVersion( s );

	if( RUBY_MAJOR( version ) != RUBY_SUPPORTED_MAJOR )
	    valid = 0;

	if( RUBY_MINOR( version ) < RUBY_SUPPORTED_MINOR )
	    valid = 0;

	if( valid )
	    valid = GetChar( '{' );

	if( !valid )
	{
	    e->Set( MsgClient::BadMarshalInput );
	    return;
	}

	// On a read elemCount is the number of *pairs*
	elemCount = UnpackInt( s );
}

/*
 * Read any termination for a Ruby marshalled hash (there is none).
 */
 
void
RubyDict::EndRead( Error *e )
{
	// Nothing to do for Ruby.
	return;
}


/*
 * Pack an integer in Ruby format. This is mostly taken from ruby's marshal.c
 * and is pretty arcane stuff. The basic idea is this:
 *
 * The first byte of a ruby marshalled int tells you (a) whether or not
 * the value is negative and (b) either the number itself or the number of
 * following bytes in which the number is encoded. 
 *
 * Since there will never (ha!) be more than 4 bytes of encoding (marshal.c 
 * does not support marshalling longs - at the moment) Matz has chosen to use
 * this to pack numbers in the range -123 <= x <= 122 in a single byte. i.e.
 * ( -128 + 5 ) <= x <= ( 127 - 5 ).
 *
 * If the first byte is in the range -4 <= x <= 4 then this indicates the
 * number of following bytes in which the rest of the number is marshalled.
 *
 * Negative numbers always have the high bit set in the first byte.
 */

void
RubyDict::PackInt( StrBuf &dict, int value )
{
	/*
	 * 64-bit ints are not supported by Ruby's marshalling code at this 
	 * time (1.6.8) so we assume we're packing a 32-bit int. This also
	 * seems reasonable since Perforce are 32-bit so we should not
	 * need to pack 64-bit ints for some time.
	 */

#define PACKSIZE	4
    	char		buf[ PACKSIZE ];
	int		len = 0;

	if( 0 < value && value < ( 127 - PACKSIZE ) )
	    buf[ len++ ] = value + PACKSIZE + 1;

	else if( value > ( PACKSIZE - 128 ) && value < 0 )
	    buf[ len++ ] = (value - PACKSIZE - 1) & 0xff;

	// If it's packed in a single byte, we're out easy.

	if ( len )
	{
	    dict.Append( buf, len );
	    return;
	}

	// More than one byte required.

	for( len = 1; len < 5; len++ )
	{
	    buf[ len ] = value & 0xff;
	    value = value >> 8;

	    if( value == 0 )
	    {
		buf[ 0 ] = len;
		break;
	    }

	    if( value == -1 )
	    {
		buf[ 0 ] = -len;
		break;
	    }
	}
	dict.Append( buf, len + 1 );
}


/*
 * Unpack an integer packed in Ruby format. See comments on PackInt for
 * a description of the packed format.
 */

int
RubyDict::UnpackInt( StrRef &str )
{
	int		i = 0;
	int		isneg = 0;
	int		len;
	int		value;

	if( ! str.Length() ) return 0;

	value = str[ i++ ];
	str += 1;

	if( value == 0 ) return 0;

	if( 4    < value && value < 128 ) 	return value - 5;
	if( -129 < value && value <  -4 ) 	return value + 5;

	// what we've got so far is just the number of bytes 

	len = value;
	value = 0;

	if( isneg = ( len < 0 ) )
	{
	    len = -len;
	    value = -1;
	}

	// Make sure the buffer is long enough first

	if( str.Length() < len ) return 0;

	for( i = 0; i < len; i++ )
	{
	    if( isneg )
		value &= ~( (long)0xff << ( 8 * i ) );
	    value |= ( ((long)str[i] & 0xff) << ( 8 * i ) );
	}
	
	str += len;
	return value;
}


/*
 * Unpack a string into a buffer. Just a matter of unpacking the length
 * of the string first, then you can just extract the string directly.
 */

void
RubyDict::UnpackString( StrRef &str, StrBuf &buf )
{
	int len = UnpackInt( str );
	if( ! len ) return;

	buf.Set( str.Text(), len );
	str += len;
}

/*
 * Unpack the Ruby marshalling format into an int. This is coded as two
 * bytes at the start of the input. They're not encoded using the normal
 * PackInt()/UnpackInt() code above, just raw.
 */
int
RubyDict::UnpackVersion( StrRef &str )
{
    int major;
    int minor;

    // Must be at least two bytes there.
    if( str.Length() < 2 ) return 0;
    
    major = str[ 0 ];
    minor = str[ 1 ];
    str += 2;

    return RUBY_VERSION( major,  minor );
}

/*******************************************************************************
 *  PhpDict methods
 ******************************************************************************/

/*
 * Begin writing a block of output. Each output block is represented
 * as a serialized PHP array. The first element is always the "code"
 * (or output type).
 *
 * PHP serializes arrays as "a:<n>:{<element>,<element>,...}".
 * Therefore, we defer writing the beginning of the array because
 * we don't know the length. All we write at this point is the "code"
 * element. We will both open and close the array in EndWrite.
 */

void
PhpDict::StartWrite( const char *code )
{
    Clear();
    elemCount = 0;
    Add( "code", StrRef( code ) );
}


/*
 * Append a integer to the current block of output.
 */

void
PhpDict::AddInt( int value )
{
    Append( "i:" );
    *this << value;
    Append( ";" );

    // Bump the element count.
    elemCount++;
}


/*
 * Append a string to the current block of output.
 */

void
PhpDict::AddString( const StrPtr &value )
{
    Append( "s:" );
    *this << value.Length();
    Append( ":\"" );
    Append( &value );
    Append( "\";" );

    // Bump the element count.
    elemCount++;
}


/*
 * Finish writing a block of output. Arrays are closed with "}".
 * Now that we know the number of elements we can properly open
 * the array (which was deferred in StartWrite).
 */

void
PhpDict::EndWrite()
{
    // Open the array.
    StrBuf tmp;
    tmp.Append( "a:" );
    tmp << elemCount / 2;
    tmp.Append( ":{" );
    tmp << *this;
    Set( tmp );

    // Close the array.
    Append( "}" );
}


/*
 * Start reading a serialized PHP array.
 */

void
PhpDict::StartRead( Error *e )
{
    s.Set( *this );

    // Input array begins with 'a:<n>:{'
    // Read to opening bracket
    while ( s.Length() )
    {
        if( GetChar( '{' ) ) return;
        s.Set( s.Text() + 1, s.Length() - 1 );
    }
    e->Set( MsgClient::BadMarshalInput );
}


/*
 * Get a variable and value pair from a serialized PHP array.
 * Returns non-zero on success.
 */

INLINE int
PhpDict::Get( StrBuf &var, StrBuf &val )
{
    if( !GetChar( 's' ) || !UnpackString( s, var ) )
        return 0;

    if( !GetChar( 's' ) || !UnpackString( s, val ) )
        return 0;

    return 1;
}


/*
 * Unpack a PHP serialized string into a buffer. Just a matter of 
 * reading the length of the string first, then we can skip past the
 * delimiters and extract the string directly. Returns non-zero on success.
 */

int
PhpDict::UnpackString( StrRef &str, StrBuf &buf )
{
    // Determine length of string
    StrBuf len;
    str.Set( str.Text() + 1, str.Length() - 1 );
    while ( str[0] != ':' && str.Length() > 0 )
    {
        len.Append( str.Text(), 1 );
        str.Set( str.Text() + 1, str.Length() - 1 );
    }

    // Verify len won't exceed str length
    // Note: strings are wrapped in two characters on either side
    if( str.Length() < len.Atoi() + 4 ) return 0;

    // Extract string to buf and advance str reference
    buf.Set( str.Text() + 2, len.Atoi() );
    str.Set( str.Text() + buf.Length() + 4, str.Length() - buf.Length() - 4 );

    return 1;
}


/*
 * Finish off the read of a serialized PHP array.
 * Just involves reading the trailing '}'
 */

void
PhpDict::EndRead( Error *e )
{
    if( !GetChar( '}' ) )
        e->Set( MsgClient::BadMarshalInput );
}


/*******************************************************************************
 *  ClientUserMarshal methods
 ******************************************************************************/

/*
 * Constructor. 
 */

ClientUserMarshal::ClientUserMarshal()
{
# ifdef OS_NT
	// both python and ruby marshalled formats are binary

        setmode( fileno( stdin ), O_BINARY );
        setmode( fileno( stdout ), O_BINARY );
# endif
	result = NULL;
}

/*
 * Destructor.
 */

ClientUserMarshal::~ClientUserMarshal()
{
	if( result ) delete result;
}

/*
 * Write any errors into the output dictionary/hash
 */

void
ClientUserMarshal::HandleError( Error *err )
{
	StrBuf msg;
	err->Fmt( msg, EF_NEWLINE );

	result->StartWrite( "error" );
	result->Add( "data", msg );
	result->Add( "severity", err->GetSeverity() );
	result->Add( "generic", err->GetGeneric() );
	result->EndWrite();
	WriteOutput( result );
}

/*
 * Write text errors into the output
 */

void
ClientUserMarshal::OutputError( const char *errBuf )
{
	result->StartWrite( "error" );
	result->Add( "data", StrRef( errBuf ) );
	result->EndWrite();
	WriteOutput( result );
}

/*
 * Write text output with level indicator into the output
 */

void
ClientUserMarshal::OutputInfo( char level, const char *data )
{
	result->StartWrite( "info" );
	result->Add( "level", level - '0' );
	result->Add( "data", StrRef( data ) );
	result->EndWrite();
	WriteOutput( result );
}

/*
 * Write plain text output.
 */

void
ClientUserMarshal::OutputText( const char *data, int length )
{
	result->StartWrite( "text" );
	result->Add( "data", StrRef( data, length ) );
	result->EndWrite();
	WriteOutput( result );
}

/*
 * Write binary output into the hash. The binary data is just 
 * encoded as a string.
 */

void
ClientUserMarshal::OutputBinary( const char *data, int length )
{
	result->StartWrite( "binary" );
	result->Add( P4Tag::v_data, StrRef( data, length ) );
	result->EndWrite();
	WriteOutput( result );
}

/*
 * Tagged output support. If we have both a data and specdef members of
 * the StrDict, then we try to parse the form directly into a StrDict and
 * add that to the output rather than the enclosing StrDict. 
 */

void
ClientUserMarshal::OutputStat( StrDict *varList )
{
	SpecDataTable specData;

	StrPtr *data = varList->GetVar( P4Tag::v_data );
	StrPtr *spec = varList->GetVar( P4Tag::v_specdef );
	StrPtr *specFormatted = varList->GetVar( P4Tag::v_specFormatted );
	StrDict *dict = varList;

	/*
	 *  Normally, we scan the ClientUser::varList and
	 *  add variable into the python dictionary object.
	 *  But if we're dealing with form output, let's go
	 *  ahead and try to parse the form.
	 */

	if( spec && data )
	{
	    
	    /*
	     * Parse the form data using the spec,
	     * and load the result into the SpecDataTable.
	     * That stores its contents in a StrDict.
	     * Use that for our results.
	     */

	     Error e;
	     Spec s( spec->Text(), "", &e );
	     if( !e.Test() ) 
	     	s.ParseNoValid( data->Text(), &specData, &e );

	     if( e.Test() ) 
	     {
		 HandleError( &e );
		 return;
	     }

	     dict = specData.Dict();
	}

	result->StartWrite( P4Tag::v_stat );

	// Don't put in the 'func' (that's for us).
	// Don't put in 'specFormatted' (tagged forms are formatted 
	// by the server in 5.2).
	// Don't put in 'specdef' unless this is not spec data formatted 
	// by the server. 'p4 jobs -G' needs specdef to be set.


	int i;
	StrRef var, val;

	for( i = 0; dict->GetVar( i, var, val ); i++ )
	    if( var != P4Tag::v_func && var != P4Tag::v_specFormatted &&
	      ( var != P4Tag::v_specdef || !specFormatted ) )
		result->Add( var, val );

	result->EndWrite();
	WriteOutput( result );
}

/*
 * Diff output support. Extends parent to collect output in a temp file
 * so that it can be routed through OutputText() and serialized.
 */

void
ClientUserMarshal::Diff( FileSys *f1, FileSys *f2, int doPage, char *df, Error *e )
{
	// Create temp file to collect output.
	FileSys *t = File( FileSysType( ( f1->GetType() & FST_L_MASK )
				| FST_UNICODE ) );
	t->MakeGlobalTemp();

	// Perform diff
	ClientUser::Diff(f1, f2, t, doPage, df, e);

	// Stream diffs to OutputText()
	t->Open( FOM_READ, e );
	if( !e->Test() )
	{
	    char buf[4096];
	    int i;

	    while( (i = t->Read( buf, sizeof(buf), e )) > 0
		&& !e->Test() )
		OutputText( buf, i );

	    t->Close( e );
	}
	t->Unlink( e );

	delete t;
}

/*
 * Input -- parse a marshalled object!
 */

void
ClientUserMarshal::InputData( StrBuf *buf, Error *e )
{
	/*
	 * If no spec, we'll just pass to ClientUser.
	 * A sorry default, but only forms related commands 
	 * use InputData.
	 */

	StrPtr *spec = varList->GetVar( P4Tag::v_specdef );

	if( !spec )
	{
	    ClientUser::InputData( buf, e );
	    return;
	}

	/*
	 * We've got a spec form: read the dictionary
	 * entry from stdin and format it using the spec.
	 */

	StrBuf var, val;
	SpecDataTable specData;

	/*
	 * Load the input from the user
	 */
	ReadInput( result, e );

	/* Read dictionary entries */
	/* and put them into our table. */

	result->StartRead( e );
	while( result->Get( var, val ) )
	    specData.Dict()->SetVar( var, val );
	result->EndRead( e );

	/*
	 * Errors here are not fatal to the client, but they
	 * need to be reported. 
	 */
	if( e->Test() )
	{
	    HandleError( e );
	    e->Clear();
	    return;
	}
	    
	/* Using our table and the spec, */
	/* format and return the form. */

	Spec s( spec->Text(), "", e );
	if( e->Test() )
	{
	    HandleError( e );
	    e->Clear();
	    return;
	}

	s.Format( &specData, buf );

}

// 
// Read input from stdin and load it into a buffer
//
void
ClientUserMarshal::ReadInput( StrBuf *buf, Error *e )
{
	int n;
	int size = FileSys::BufferSize();

	do {
	    char *b = buf->Alloc( size );
	    n = read( 0, b, size );
	    if( n < 0 )
	    {
		e->Sys( "read", "stdin" );
		break;
	    }
	    buf->SetEnd( b + n );
	} while( n > 0 );

}

//
// Write the result buffer to stdout. Subclasses can override to 
// redirect the output elsewhere
//
void
ClientUserMarshal::WriteOutput( StrPtr *buf )
{
    	fwrite( buf->Text(), 1, buf->Length(), stdout );
}

/*******************************************************************************
 *  ClientUserPython methods
 ******************************************************************************/

/*
 * ClientUserPython - ClientUser I/O is marshalled Python data
 * 
 * Just ClientUserMarshal but with a Python dictionary.
 */

ClientUserPython::ClientUserPython()
{
	result = new PythonDict;
}

/*******************************************************************************
 *  ClientUserRuby methods
 ******************************************************************************/

/*
 * ClientUserRuby - ClientUser I/O is marshalled Ruby data
 * 
 * Just ClientUserMarshal but with a Ruby dictionary.
 */

ClientUserRuby::ClientUserRuby()
{
	result = new RubyDict;
}


/*******************************************************************************
 *  ClientUserPhp methods
 ******************************************************************************/

/*
 * ClientUserPhp - ClientUser I/O is serialized PHP data
 *
 * Differs from other ClientUserMarshal classes in that all
 * output is buffered until the ClientUser object is destroyed.
 */

ClientUserPhp::ClientUserPhp()
{
	result 		 = new PhpDict;
	outputBuffer = new StrBuf;
	outputCount  = 0;
}

ClientUserPhp::~ClientUserPhp()
{
	// Now that all output has been collected, wrap it
	// in an array and write it to stdout
	StrBuf output;
	output.Append( "a:" );
	output << outputCount;
	output.Append( ":{" );
	output.Append( outputBuffer );
	output.Append( "}" );
	fwrite( output.Text(), 1, output.Length(), stdout );
	delete outputBuffer;
}


/*
 * Buffer all output. Output blocks are encapsulated in an array the
 * size of which cannot be known until ClientUser is deconstructed.
 */

void
ClientUserPhp::WriteOutput( StrPtr *buf )
{
	outputBuffer->Append( "i:" );
	*outputBuffer << outputCount;
	outputBuffer->Append( ";" );
	outputBuffer->Append( buf );
	outputCount++;
}

/*
 * ClientUser::Prompt() - don't prompt the user, just collect the response.
 */

void
ClientUserPhp::Prompt( const StrPtr &msg, StrBuf &buf, int noEcho, Error *e )
{
    ClientUser::Prompt( msg, buf, noEcho, 1, e );
}
