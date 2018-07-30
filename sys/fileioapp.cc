/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include <error.h>
# include <strbuf.h>
# include <datetime.h>

# include "filesys.h"
# include "fileio.h"
# include "pathsys.h"
# include "applefork.h"

# if !defined ( OS_MACOSX )

/*
 * FileIOApple -- AppleSingle/Double on non-mac platforms
 */

/*
 * DataFork -- write the data fork for AppleSplit
 */

class DataFork : public AppleFork {

    public:
	DataFork( FileIO *f ) {
	    file = f;
	}

	// AppleFork Virtuals

	int WillHandle( EntryId id ) { 
		return id == EntryIdData; 
	}

	void WriteOpen( EntryId id, Error *e ) {
	    file->Open( FOM_WRITE, e );
	}

	void Write( const char *buf, int length, Error *e ) {
	    file->Write( buf, length, e );
	}

	void WriteClose( Error *e ) {
	    file->Close( e );
	}

    private:
	FileIO *file; 	// Just a pointer back to the original
} ;

/*
 * FileIOApple
 */

FileIOApple::FileIOApple()
{
	split = new AppleForkSplit;
	combine = new AppleForkCombine;
	data = new FileIOBinary;
	header = new FileIOBinary;
	dataFork = 0;
}

FileIOApple::~FileIOApple()
{
	Cleanup();

	delete split;
	delete combine;
	delete data;
	delete header;
	delete dataFork;
}

void
FileIOApple::Set( const StrPtr &s )
{
	Set( s, 0 );
}

void
FileIOApple::Set( const StrPtr &s, Error *e )
{
	// Our name

	FileIO::Set( s, e );

	// Data fork name

	data->Set( s, e );

	// Make %file name

	StrBuf file;

	PathSys *p = PathSys::Create();

	p->Set( s );
	p->ToParent( &file );
	p->SetLocal( *p, StrRef( "%", 1 ) );
	p->Append( &file );

	header->Set( *p, e );

	delete p;
}

// Just a set of wrappers to get both the header and data forks

int
FileIOApple::Stat()
{
	// Exists if either exists.
	// Writeable if either writable.

	return  header->Stat() | data->Stat();
}

int
FileIOApple::StatModTime()
{
	// Return later of the two.

	int h = header->StatModTime();
	int d = data->StatModTime();

	return h > d ? h : d;
}

void
FileIOApple::StatModTimeHP(DateTimeHighPrecision *modTime)
{
	// Return later of the two.

	DateTimeHighPrecision h;
	DateTimeHighPrecision d;

	header->StatModTimeHP(&h);
	data->StatModTimeHP(&d);

	*modTime = h > d ? h : d;
}

void
FileIOApple::Truncate( offL_t offset, Error *e )
{
}

void
FileIOApple::Truncate( Error *e )
{
	// XXX Not really thought out.
	// Only the server uses truncate.

	header->Truncate( e );
	data->Truncate( e );
}
bool
FileIOApple::HasOnlyPerm( FilePerm perms )
{
	return ( (header->HasOnlyPerm(perms)) && (data->HasOnlyPerm(perms)) );
}

void
FileIOApple::Chmod( FilePerm perms, Error *e )
{
	header->Chmod( perms, e );
	data->Chmod( perms, e );
}

void
FileIOApple::ChmodTime( int modTime, Error *e )
{
	header->ChmodTime( modTime, e );
	data->ChmodTime( modTime, e );
}

void
FileIOApple::ChmodTimeHP( const DateTimeHighPrecision &modTime, Error *e )
{
	header->ChmodTimeHP( modTime, e );
	data->ChmodTimeHP( modTime, e );
}

void
FileIOApple::Unlink( Error *e )
{
	header->Unlink( e );
	data->Unlink( e );
}

void
FileIOApple::Rename( FileSys *target, Error *e )
{
	FileIOApple *apple = 0;

	if ( !( target->GetType() & FST_M_APPLE ) )
	{
	    // Target isn't a FileIOApple?  
	    // Make one so that we can write both forks.

	    apple = new FileIOApple;
	    apple->Set( StrRef( target->Name() ), e );
	    target = apple;
	}
	
	header->Rename( ((FileIOApple *)target)->header, e );
	data->Rename( ((FileIOApple *)target)->data, e );

	// file deleted, clear the flag

	ClearDeleteOnClose();
	
	delete apple;
}

/*
 * FileIOApple::Open
 * FileIOApple::Write
 * FileIOApple::Read
 * FileIOApple::Close
 *
 * The meat of the matter.
 *
 * For FOM_READ, the work is done by Open().
 * For FOM_WRITE, 

	Reading:

	    FileIOBinary(%file) -> AppleForkSplit -> AppleForkCombine
	    FileIOBinary(file) -------------------/

	Writing:

	    AppleForkSplit -> AppleForkCombine -> FileIOBinary(%file)
			   \--------------------> FileIOBinary(file)
 */

void
FileIOApple::Open( FileOpenMode mode, Error *e )
{
	/* 
	 * For read, we do all the work in the Open. 
	 * Build a AppleForkSplit -> AppleForkCombine pipeline.
	 * Send the AppleDouble %file down the splitter.
	 * Send the data fork directly to the combiner.
	 */

	this->mode = mode;

	if( mode == FOM_READ )
	{
	    int l;
	    StrFixed buf( BufferSize() );

	    /*
	     * Build the splitter -> combiner relationship.
	     * Only one handler: to build the AppleSingle stream.
	     */

	    split->AddHandler( combine );

	    /*
	     * Read the AppleDouble %file
	     */

	    header->Open( FOM_READ, e );

	    if( e->Test() )
	    {
		e->Set( E_FAILED, "Unable to read AppleDouble Header." );
		return;
	    }

	    while( !e->Test() && 
		( l = header->Read( buf.Text(), buf.Length(), e ) ) )
		    split->Write( buf.Text(), l, e );

	    split->Done( e );

	    header->Close( e );

	    if( e->Test() ) return;

	    /*
	     * Already a datafork?  Don't read user's data fork then.
	     */

	    if( combine->IsAppleSingle() )
		return;

	    /*
	     * Read the data portion and write it down the combiner.
	     */

	    data->Open( FOM_READ, e );

	    if( e->Test() )
	    {
		e->Set( E_FAILED, "Unable to read AppleDouble Data." );
		return;
	    }

	    combine->WriteOpen( 1, e );

	    while( !e->Test() && 
		( l = data->Read( buf.Text(), buf.Length(), e ) ) )
		    combine->Write( buf.Text(), l, e );

	    combine->WriteClose( e );

	    data->Close( e );

	    if( e->Test() ) return;
	}

	if( mode == FOM_WRITE )
	{
	    dataFork = new DataFork( data );
	    split->AddHandler( dataFork );
	    split->AddHandler( combine );
	}
}

void
FileIOApple::Write( const char *buf, int len, Error *e )
{
	split->Write( buf, len, e );
}

int
FileIOApple::Read( char *buf, int len, Error *e )
{
	return combine->Read( buf, len, e );
}

void
FileIOApple::Close( Error *e )
{
	if( mode == FOM_WRITE )
	{
	    /*
	     * Prevent double closure
	     */

	    mode = FOM_READ;

	    /*
	     * Write out the AppleDouble Header file
	     */

	    int l;
	    StrFixed buf( BufferSize() );

	    header->Open( FOM_WRITE, e );

	    if( e->Test() )
	    {
		e->Set( E_FAILED, "Unable to write AppleDouble Header." );
		return;
	    }

	    while( !e->Test() && 
		( l = combine->Read( buf.Text(), buf.Length(), e ) ) )
		    header->Write( buf.Text(), l, e );

	    split->Done( e );

	    header->Close( e );
	}
}

# endif /* OS_MACOSX */
