/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include <error.h>
# include <strbuf.h>
# include <datetime.h>

# if defined ( OS_MACOSX )

# include "i18napi.h"
# include "macfile.h"
# include "filesys.h"
# include "fileio.h"
# include "applefork.h"


/*
 * FileIOApple -- AppleSingle/Double on the mac 
 *
 * This implementation does AppleSingle decoding (when writing the
 * local file) and encoding (when reading the local file).  It only
 * implements the Data, Resource, and FInfo components of the 
 * AppleSingle file.
 */
 
class ReadableAppleFork : public AppleFork {

    public:
	virtual void	ReadOpen( Error *e ) = 0;
	virtual int	Read( char *buf, int length, Error *e ) = 0;
	virtual void	ReadClose( Error *e ) = 0;

	// to write a whole applefork
	
	void Copy( EntryId id, AppleFork *target, Error *e )
	{
		StrFixed buf( FileSys::BufferSize() );
		int l;
		
		ReadOpen( e );
	
		if( e->Test() ) return;
			
		target->WriteOpen( id, e );
	
		while( !e->Test() && 
		    ( l = Read( buf.Text(), buf.Length(), e ) ) )
		    	target->Write( buf.Text(), l, e );
	
		target->WriteClose( e );
	
		ReadClose( e );
	}
} ;

class BufferAppleFork : public AppleFork, public StrBuf {

    public:
    	// AppleFork Virtuals

	void WriteOpen( EntryId id, Error *e ) { Clear(); }
	void Write( const char *buf, int length, Error *e ) { 
		Append( buf, length ); 
	}
	void WriteClose( Error *e ) { }

	// to write a whole applefork
	
	void Copy( EntryId id, AppleFork *target, Error *e )
	{
		target->WriteOpen( id, e );
		if( e->Test() ) return;
		target->Write( Text(), Length(), e );
		target->WriteClose( e );
	}
} ;

/*
 * DataFork -- write the data fork for AppleSplit
 */

class DataFork : public ReadableAppleFork {

    public:
	DataFork( char *name ) {
	    /*
	     * The data fork is left RW, so that the Close() can write the
	     * other data.  Our Close() resets the perms.
	     */
	    file.Set( name );
	    file.Perms( FPM_RW );
	}
	
	// AppleFork Virtuals

	int WillHandle( EntryId id ) { 
	    return id == EntryIdData; 
	}

	void WriteOpen( EntryId id, Error *e ) {
	    file.Open( FOM_WRITE, e );
	}

	void Write( const char *buf, int length, Error *e ) {
	    file.Write( buf, length, e );
	}

	void WriteClose( Error *e ) {
	    file.Close( e );
	}
	
	void ReadOpen( Error *e ) {
	    file.Open( FOM_READ, e );
	}
	
	int Read( char *buf, int l, Error *e ) {
	    return file.Read( buf, l, e );
	}
	
	void ReadClose( Error *e ) {
	    file.Close( e );
	}

    private:
	FileIOBinary file; 	// Just a pointer back to the original
} ;

class ResourceFork : public ReadableAppleFork {

    public:
    	ResourceFork( MacFile * mf )
	{
	    this->mf = mf;
	}
	
	// AppleFork Virtuals

	int WillHandle( EntryId id ) { return id == EntryIdResource; }
	
	void WriteOpen( EntryId id, Error *e )
	{
	    if( mf->OpenResourceFork( fsWrPerm ) != noErr )
	    	e->Set( E_FAILED, "Can't write resource fork of file %path%." ) << mf->GetPrintableFullPath();
	    len = 0;
	}

	void Write( const char *buf, int length, Error *e )
	{
	    ByteCount l = length;
	    if( mf->WriteResourceFork( l, (const void *)buf, &l ) != noErr )
		e->Set( E_FAILED, "Error writing resource fork of %path%." ) << mf->GetPrintableFullPath();
	    len += length;
	}
	
	void WriteClose( Error *e ) 
	{
	    if( !e->Test() )
	    	mf->CloseResourceFork();
	}
	
	void ReadOpen( Error *e )
	{
	    if( mf->OpenResourceFork( fsRdPerm ) != noErr )
	    {
		e->Set( E_FAILED, "Can't read resource fork of file %path%." ) << mf->GetPrintableFullPath();
		return;
	    }
	    
	    len = mf->GetResourceForkSize();
	}

	int Read( char *buf, int length, Error *e )
	{
	    ByteCount l = len < length ? len : length;
	    
	    if( l && mf->ReadResourceFork( l, (void *)buf, &l ) != noErr )
	    {
		e->Set( E_FAILED, "Error reading resource fork of %path%." ) << mf->GetPrintableFullPath();
		return 0;
	    }
	    
	    len -= l;
	    return l;
	}
	
	void ReadClose( Error *e )
	{
	    mf->CloseResourceFork();
	}
 
    private:
    	MacFile * mf;
	short rsrcRef;
	long len;
} ;

class FinfoFork : public BufferAppleFork {

    public:
	// AppleFork Virtuals

	int WillHandle( EntryId id ) { return id == EntryIdFinderInfo; }
	
	// Misc
	
	void Load( const FInfo * fInfo, const FXInfo * fxInfo )
	{
	    Clear();
	    
	    // We can't have the files differ just because they are locked,
	    // so we temporarily zero the fdXflags word.  This is "reserved",
	    // but appears to be where the "locked" flag is.
	    
	    FXInfo s = *fxInfo;
	    s.fdXFlags = 0;
	    
	    FInfo i = *fInfo;
	    
	    MacFile::SwapFInfo( &i );
	    MacFile::SwapFXInfo( &s );
	    Extend( (char *)&i, sizeof( FInfo ) );
	    Extend( (char *)&s, sizeof( FXInfo ) );
	}
	
	void Save( FInfo * fInfo, FXInfo * fxInfo, Error *e )
	{
	    if( Length() != sizeof( FInfo ) + sizeof( FXInfo ) )
	    {
	        e->Set(
	            E_FAILED,
	            "Malformed FInfo/FXInfo structure! File not updated." );
		return;
	    }
	    
	    memcpy( fInfo, Text(), sizeof( FInfo ) );
	    memcpy( fxInfo, Text() + sizeof( FInfo ), sizeof( FXInfo ) );
	    MacFile::SwapFInfo( fInfo );
	    MacFile::SwapFXInfo( fxInfo );
	}

} ;

class CommentFork : public BufferAppleFork {

    public:
	// AppleFork Virtuals

	int WillHandle( EntryId id ) { return id == EntryIdComment; }
	
	// Misc
	
	void Load( const MacFile * mf, Error *e )
	{
	    Clear();
	    int actualLength = 0;
	    const char * comment = mf->GetComment( &actualLength );

	    Extend( comment, actualLength );
	    SetLength( actualLength );
	}
	
	void Save( MacFile * mf, Error *e )
	{
	    if( mf->SetComment( Text(), Length() ) != noErr )
	    {
	    	e->Set( E_FAILED, "Unable to set comment!" );
		return;
	    }
	}

} ;

/*
 * FileIOApple
 */

FileIOApple::FileIOApple()
{
	split = 0;
	combine = 0;
	dataFork = 0;
	resourceFork = 0;
	finfoFork = 0;
	commentFork = 0;
}

FileIOApple::~FileIOApple()
{
	Cleanup();

	delete split;
	delete combine;
	delete dataFork;
	delete resourceFork;
	delete finfoFork;
	delete commentFork;
}

/*
 * FileIOApple::Open
 * FileIOApple::Write
 * FileIOApple::Read
 * FileIOApple::Close
 *
 * The meat of the matter.
 */

void
FileIOApple::Open( FileOpenMode mode, Error *e )
{
	this->mode = mode;

	MacFile * macfile = GetMacFile( e );

	if( mode == FOM_READ )
	{
	    if( !macfile )
	    {
	    	e->Set( E_FAILED, "Can't find file %path%." ) << Name();
		return;
	    }

	    /* 
	     * For read, we do all the work in the Open. 
	     * Build a AppleForkCombine and put the finder info,
	     * the resource fork, and the data fork into it.
	     */

	    combine = new AppleForkCombine;


	    // Finfo block.
	    FinfoFork finfoFork;
	    finfoFork.Load( macfile->GetFInfo(), macfile->GetFXInfo() );
	    finfoFork.Copy( EntryIdFinderInfo, combine, e );

	    if( e->Test() ) return;

	    // Comment block.

	    CommentFork commentFork;
	    commentFork.Load( macfile, e );
	    commentFork.Copy( EntryIdComment, combine, e );

	    if( e->Test() ) return;

	    // Resource fork.

	    ResourceFork resourceFork( macfile );
	    resourceFork.Copy( EntryIdResource, combine, e );
	    if( e->Test() ) return;

	    // Data fork.
	    
	    DataFork datafork( Name() );    
	    datafork.Copy( EntryIdData, combine, e );
	    if( e->Test() ) return;
	}
	else if( mode == FOM_WRITE )
	{
	    /*
	     * Create the file if needed.  Unless the data fork is
	     * written first (which it isn't), nothing else knows to
	     * create the file.
	     */
	    if( !macfile )
	    {
		e->Clear();
		macfile = CreateMacFile( e );
		if( e->Test() ) return;
	    }
	    
	    /*
	     * We need to split the data into three parts (finfo, resource
	     * fork, data fork).  The data and resource forks get written directly, 
	     * but the finfo and resource get buffered for Close().
	     */

	    finfoFork = new FinfoFork;
	    resourceFork = new ResourceFork( macfile );
	    commentFork = new CommentFork;
	    dataFork = new DataFork( Name() );
	    split = new AppleForkSplit;

	    split->AddHandler( finfoFork );
	    split->AddHandler( resourceFork );
	    split->AddHandler( commentFork );
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
	if( mode == FOM_READ )
	{
	    /*
	     * Clear for possible reuse.
	     */

	    delete combine;
	    combine = 0;
	}
	else if( mode == FOM_WRITE )
	{
	    /*
	     * Prevent double closure
	     */

	    mode = FOM_READ;

	    /*
	     * No mangled data?
	     */

	    if( split )
	    {
		split->Done( e );
		delete split;
		split = 0;
	    }
	    else
	    {
	    	e->Set( E_FAILED, "No AppleForkSplit for %path%." ) << Name();
	    }
	    
	    if( e->Test() )
		return;

	    /*
	     * The data fork has been written.  Now we just save
	     * off the resource and finfo pieces.
	     */

	    MacFile * macfile = GetMacFile( e );
	    
	    if( !macfile )
	    {
	    	e->Set( E_FAILED, "Can't get file info block for %path%." ) << Name();
		return;
	    }
	    
	    FInfo tempInfo;
	    FXInfo tempxInfo;
	    
	    finfoFork->Save( &tempInfo, &tempxInfo, e );
	    macfile->SetFInfo( &tempInfo );
	    macfile->SetFXInfo( &tempxInfo );

	    commentFork->Save( macfile, e );
	    
	    /*
	     * Now finalize the perms.
	     */
	     
	    if( modTime )
	    	ChmodTime( modTime, e );

	    Chmod( perms, e );
	}
}

int
FileIOApple::HasResourceFork()
{
	Error e;
	MacFile * macfile = GetMacFile( &e );
	
	if ( !macfile )
	    return 0;
	return macfile->HasResourceFork();
}

# endif /* OS_MACOSX */
