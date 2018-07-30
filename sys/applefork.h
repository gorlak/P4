/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * appleforks.h - build/split an AppleSingle/Double stream
 *
 * These classes provide the pieces for manipulating AppleSingle and
 * AppleDouble format files.  Nothing in this interface or implementation
 * is Macintosh specific, save the rediculous file format.
 *
 * We refer to each piece of a AppleSingle file as a fork, but really
 * only the resource and data portions are forks.  Unfortunately, Apple
 * didn't really name the pieces except as "entries".
 *
 * To combine forks into a single stream:
 *
 *	AppleForkCombine combine;
 *
 *	for( <each fork> )
 *	{
 *	    combine.WriteOpen( id, e );
 *	    // can repeat next line
 *	    combine.Write( buf, len, e );
 *	    combine.WriteClose( e );
 *	}
 *
 *	// read the combined data
 *
 *	while( len = combine.Read( buf, sizeof( buf ), &e )
 *		; // have data
 *
 * To split an AppleSingle stream:
 *
 *	// Assume we want to handle two forks and combine the
 *	// rest into another AppleSingle stream.
 *
 *	Special1AppleFork special1;
 *	Special2AppleFork special2;
 *	AppleForkCombine combine;
 *	AppleForkSplit split;
 *	Error e;
 *
 *	split.AddHandler( &special1 );
 *	split.AddHandler( &special2 );
 *	split.AddHandler( &combine );
 *
 *	// Write the AppleSingle stream into the splitter
 *	// special1 and special2 will be called for their pieces.
 *	// combine will get the rest.
 *
 *	while( <data> )
 *		split.Write( buf, len, &e );
 *	split.Done( &e );
 *
 *	// just for fun, read the combined data
 *
 *	while( len = combine.Read( buf, sizeof( buf ), &e )
 *		; // have data
 *
 * Note that because of the layout of the AppleSingle data (with Offs
 * embedded in the header), AppleForkCombine must buffer its results before 
 * it can make them available via Read().  It will resort to a temp
 * file if it buffers more than 100K.
 *
 * See applefile.h for the low-down on AppleSingle format.  We don't
 * use it ourselves.  rfc1740 describes the format as well.
 *
 * Classes defined:
 *
 *	AppleData - just a StrBuf with calls to access big-endian ints
 *
 *	AppleFork - a handle for dispatching a single fork
 *	AppleForkSplit - process a stream, calling AppleForks for each fork
 *	AppleForkCombine - build a stream (subclass of AppleFork)
 *
 * Public methods:
 *
 *	AppleFork::WillHandle() - return 1 if this handler will accept
 *		this entry type.  AppleForkSplit calls this for each
 *		AppleFork handler registered with it until it finds a
 *		willing handler.
 *
 *	AppleFork::Open/Write/Close() - write out fork data.  AppleForkSplit
 *		calls these (if WillHandle() has returned 1) to dispose
 *		of the fork's data.
 *
 *	AppleForkSplit::AddHandler() - register a AppleFork handler.  The
 *		last handler should accept any entry types.
 *
 *	AppleForkSplit::Write() - dispose of AppleSingle data.  Write()
 *		buffers the AppleSingle header and then starts calling
 *		AppleFork handlers to dispose of the actual data.
 *
 *	AppleForkSplit::Done() - called after the last Write() to verify
 *		that AppleForkSplit is actually done (it is a data error
 *		if not).
 *
 *	AppleForkCombine::WillHandle() - returns 1, indicating that it
 *		(a AppleFork handler) will accept any type of fork.
 *
 *	AppleForkCombine::Open/Write/Close() - consumes individual fork
 *		data, buffering the result.
 *
 *	AppleForkCombine::Read() - return AppleSingle/Double data from the
 *		combined forks.  The magic header is set to AppleSingle
 *		if a data fork is included; if not, the type is set to
 *		AppleDouble (assuming the data fork lives elsewhere).
 */

typedef unsigned int EntryId;

const int SizeHeader = 26;
const int SizeEntry = 12;

const int MagicAppleSingle = 0x00051600;
const int MagicAppleDouble = 0x00051607;
const int MagicVersion = 0x00020000;
const int EntryIdData = 1;
const int EntryIdResource = 2;
const int EntryIdRealname = 3;
const int EntryIdComment = 4;
const int EntryIdFinderInfo = 9;

// Offsets into header, Entry

const int OffHeaderMagic = 0;
const int OffHeaderVersion = 4;
const int OffHeaderNumEntries = 24;

const int OffEntryId = 0;
const int OffEntryOff = 4;
const int OffEntryLength = 8;

class AppleData : public StrBuf {

    public:

	int	GetMagic() { return Get32( OffHeaderMagic ); }
	int	GetVersion() { return Get32( OffHeaderVersion ); }
	int	GetNumEntries() { return Get16( OffHeaderNumEntries ); }
	int	GetEntryId( int x ) { return Get32( x, OffEntryId ); }
	int	GetEntryLen( int x ) { return Get32( x, OffEntryLength ); }

	void	SetMagic( int v ) { Set32( OffHeaderMagic, v ); }
	void	SetVersion( int v ) { Set32( OffHeaderVersion, v ); }
	void	SetNumEntries( int v ) { Set16( OffHeaderNumEntries, v ); }

	void	SetEntryId( int x, int v ) { Set32( x, OffEntryId, v ); }
	void	SetEntryOff( int x, int v ) { Set32( x, OffEntryOff, v ); }
	void	SetEntryLen( int x, int v ) { Set32( x, OffEntryLength, v ); }

	void	AllocHeader()
		{
		    Alloc( SizeHeader );
		    memset( Text(), 0, SizeHeader );
		    SetMagic( MagicAppleDouble );
		    SetVersion( MagicVersion );
		    SetNumEntries( 0 );
		}

	void	AllocEntry( int x, EntryId id )
		{
		    Alloc( SizeEntry );
		    SetEntryId( x, id );
		    SetEntryOff( x, 0 );
		    SetEntryLen( x, 0 );
		}

    private:

	int	Get32( int x, int o ) 
		{ 
		    return Get32( SizeHeader + x * SizeEntry + o ); 
		}

	void	Set32( int x, int o, int v ) 
		{
		    Set32( SizeHeader + x * SizeEntry + o, v ); 
		}

	int	Get32( int off )
		{
		    return 
			C( off + 0 ) * 0x1000000 + 
			C( off + 1 ) * 0x10000 +
			C( off + 2 ) * 0x100 + 
			C( off + 3 ) * 0x1;
		}

	int	Get16( int off )
		{
		    return C( off + 0 ) * 0x100 + C( off + 1 ) * 0x1;
		}

	void	Set32( int off, int val )
		{
			S( off + 0 ) = ( val / 0x1000000 ) % 0x100;
			S( off + 1 ) = ( val / 0x10000 ) % 0x100;
			S( off + 2 ) = ( val / 0x100 ) % 0x100;
			S( off + 3 ) = ( val / 0x1 ) % 0x100;
		}

	void	Set16( int off, int val )
		{
			S( off + 0 ) = ( val / 0x100 ) % 0x100;
			S( off + 1 ) = ( val / 0x1 ) % 0x100;
		}

	char &		S(int x) { return Text()[x]; }
	unsigned char 	C(int x) { return UText()[x]; }

} ;

class AppleFork {

    public:
	virtual		~AppleFork();

	virtual int	WillHandle( EntryId id ) = 0;

	virtual void	WriteOpen( EntryId id, Error *e ) = 0;
	virtual void	Write( const char *buf, int length, Error *e ) = 0;
	virtual void	WriteClose( Error *e ) = 0;

} ;

class AppleForkSplit {

    public:
			AppleForkSplit();

	void		AddHandler( AppleFork *handler );
	void		Write( const char *buf, int length, Error *e );
	void		Done( Error *e );

    private:

	AppleFork	*handler[ 5 ];
	int		numHandlers;

	AppleData	header;
	int		needed;

	int		numEntries;
	int		currentEntry;
	AppleFork	*currentHandler;

	enum State {
		BeforeEndOfHeader,	// filling header
		BeforeEndOfIndex,	// filling entry index
		StartingFork,		// looking to fill a fork
		InFork			// filling a fork
	} state;
} ;

class AppleForkCombine : public AppleFork {

    public:
			AppleForkCombine();
			~AppleForkCombine();

	// from AppleFork

	virtual int	WillHandle( EntryId id );
	virtual void	WriteOpen( EntryId id, Error *e );
	virtual void	Write( const char *buf, int length, Error *e );
	virtual void	WriteClose( Error *e );

	// to read the results

	int		Read( char *buf, int length, Error *e );
	int		IsAppleSingle() { return isSingle; }

    private:

	AppleData	header;		// apple header and entries
	StrBuf		data;		// fork contents
	int		numEntries;	// number of entries in header
	int		dataLength;	// track per-fork length
	int		isSingle;	// has data fork

	class FileSys 	*dataBack;	// for big data

	enum State {
		Start,		// initialize for Read()
		Header,		// Read() from header
		Data,		// Read() from data
		Done		// Read() returns 0
	} state ;
} ;
