/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# define NEED_STAT

# include <stdhdrs.h>

# if defined ( OS_MACOSX )


# include <error.h>
# include <errornum.h>
# include <msgos.h>
# include <strbuf.h>
# include <strarray.h>

# include <i18napi.h>
# include <charcvt.h>
# include <datetime.h>

# include "filesys.h"
# include "fileio.h"

# include "macfile.h"

static const OSType kUnknownSignature = FOUR_CHAR_CONSTANT('?','?','?','?');

extern int global_umask;

FileIOMac::FileIOMac()
{
	mf = 0;
}

FileIOMac::~FileIOMac()
{
	delete mf;
}

void
FileIOMac::Set( const StrPtr &name )
{
	Set( name, 0 );
}

void
FileIOMac::Set( const StrPtr &name, Error *e )
{
	//
	// The MacFile will no longer refer to this new name,
	// so delete it.
	//
	delete mf;
	mf = 0;
	FileSys::Set( name, e );
}

MacFile * FileIOMac::GetMacFile( Error *e )
{
	OSErr err;
	
	if ( !mf )
	{
	    MacFile * macFile = MacFile::GetFromPath(
	                        Name(),
	                        &err);

	    if ( !macFile )
	    {
		if ( e ) e->Sys("open", Name() );
		return NULL;
	    }
	    
	    mf = macFile;
	}
	
	return mf;
}


MacFile * FileIOMac::CreateMacFile( Error *e )
{
	OSErr err;
	
	if ( !mf )
	{
	    MacFile * tempMf = MacFile::CreateFromPath(
	                        Name(),
	                        false,
	                        &err);

	    if ( !tempMf )
	    {
		if ( e ) e->Sys("open", Name() );
		return NULL;
	    }
	    
	    mf = tempMf;
	}
	
	return mf;
}


void
FileIOMac::Open( FileOpenMode mode, Error *e )
{
	// Save mode for write, close

	this->mode = mode;

	// Short circuit stdio

	if( Name()[0] == '-' && !Name()[1] )
	    return;

	int perm = mode == FOM_WRITE ? fsWrPerm : fsRdPerm;

	// Get handles for real file 
    
	MacFile * macFile = GetMacFile( e );
	
	if ( perm == fsWrPerm )
	{
	    if ( !macFile )
	    {
		e->Clear();
		macFile = CreateMacFile( e );
	    }
	}
	
	if ( macFile )
	{
     
	    if( macFile->OpenDataFork( perm ) != noErr )
	    {
		e->Sys("open", Name() );
		return;
	    }
	}
}

void
FileIOMac::Close( Error *e )
{
	if( !mf )
	    return;
    
	if( (mf)->CloseDataFork() < 0 )
	    e->Sys( "close", Name() );	

	if( mode == FOM_WRITE && modTime )
	    ChmodTime( modTime, e );

	if( mode == FOM_WRITE )
	    Chmod( perms, e );
        
        // This needs to happen only on Mac OS 10.0.0.x
        // versions of the OS. The FSRef (inside MacFile) will
        // be maintained through another app editing it on Mac OS 10.1
        //
        delete mf;
        mf = NULL;
}

int
FileIOMac::Read( char *buf, int len, Error *e )
{
	// Short circuit stdio

	if( Name()[0] == '-' && !Name()[1] )
	{
	    return fread( buf, 1, len, stdin );
	}

	ByteCount size = len;
    
	OSErr err = mf->ReadDataFork( size, buf, &size );

	if ( err == noErr || err == eofErr )
	    return size;

	e->Sys( "read", Name() );
	return -1;
}

void
FileIOMac::Write( const char *buf, int len, Error *e )
{
	// Short circuit stdio

	if( Name()[0] == '-' && !Name()[1] )
	{
	    fwrite( buf, 1, len, stdout );
	    return;
	}

	ByteCount size = len;
	
	if ( mf )
	{
	    if ( mf->WriteDataFork( size, buf, &size ) != noErr )
	    e->Sys( "write", Name() );
	}
}

offL_t
FileIOMac::GetSize()
{
	if ( mf )
	{
	    return mf->GetDataForkSize();
	}
	else
	    return 0;
}

void
FileIOMac::Seek( offL_t offset, Error * )
{
	if ( mf )
	{
	    mf->SetDataForkPosition( offset );
	}
}


/*
 * FileIOMac::Stat() -- workaround broken CW stat()
 */

int
FileIOMac::Stat( bool includeRsrcFork )
{
	int flags = 0;

	flags = FileIO::Stat();
	
	if ( !includeRsrcFork )
	    return flags;

	if ( !(flags & FSF_EXISTS) )
	    return flags;

	if ( flags & FSF_DIRECTORY )
	    return flags;

	if ( flags & FSF_SYMLINK )
	    return flags;

	if ( !(flags & FSF_EMPTY) )
	    return flags;

	// If the file is empty, double-check for the resource fork
	//
	Error e;
	const MacFile * fileEntity = GetMacFile( &e );

	if( fileEntity && fileEntity->GetResourceForkSize() > 0 )
	    flags &= ~FSF_EMPTY;

	return flags;
}

void
FileIOMac::Rename( FileSys *target, Error *e )
{
	// copy, rather than rename, to preserve any data/resource fork
	
	if ( ( target->GetType() & FST_MASK ) != FST_SYMLINK )
	{
	    // make target writeable first

	    Chmod( FPM_RW, e );

	    if( e->Test() )
	    {
		e->Clear();

		// raw chmod failed... try unlink...
		// This is pretty safe I think because
		// if the unlink succeeds then we know we can write
		// the directory so create the file with the copy
		// below.  If the unlink fails, we give up because
		// we will not be able to write the resource fork
		// or some other problem will happen...

		if( target->Stat() & FSF_EXISTS )
		{
		    target->Unlink( e );
		    if( e->Test() )
			return;
		    target->ClearDeleteOnClose();
		}
	    }

	    Copy( target, FPM_RW, e );

	    if( e->Test() )
		return;

	    Unlink( e );

	    // reset the target to our perms

	    target->Perms( perms );
	    target->Chmod( e );
	}
	else if( rename( Name(), target->Name() ) < 0 )
	{
	    e->Sys( "rename", target->Name() );
	    return;
	}

	// source file has been deleted,  clear the flag

	ClearDeleteOnClose();
}
 
/*
 * FileIOMac::Unlink() - remove apple file
 *
 * This is special because it will cleanup resource fork
 * hidden files which mess up Rename via Copy.
 */

void
FileIOMac::Unlink( Error *e )
{
	if( !*Name() )
	    return;

	Chmod( FPM_RW, 0 );

	MacFile *macFile = GetMacFile( e );

	if( ( !macFile || macFile->Delete() != noErr ) && e )
	    e->Sys( "unlink", Name() );
}

/*
 * FileIOResource support
 */
 
FileIOResource::FileIOResource()
{
	resourceData = 0;
}

FileIOResource::~FileIOResource()
{
	Cleanup();
}

# if defined ( OS_MACOSX )

/*
 * MAC FileSys::Set() - set file name, recognizing .file as resource
 */

void
FileIOResource::Set( const StrPtr &name )
{
	Set( name, 0 );
}
void
FileIOResource::Set( const StrPtr &name, Error *e )
{
	// Set colon to file component (after final :)
	const char *colon = NULL;
	colon = strrchr( name.Text(), GetSystemFileSeparator() ); // unix paths
	colon = colon ? colon + 1 : name.Text();
	hasDotInName = *colon == '.';

	// Is this a .file ?
	// If so, note that the name indicates a resource fork.
	// It is really if resource fork if SetType is told so,
	// but we use this information to cue CheckType().

	if( hasDotInName )
	{
	    // Name sans dot
	    path.Set( name.Text(), colon - name.Text() );
	    path.Append( colon + 1 );
	}
	else
	{
	    // No.  Plain file.
	    path.Set( name );
	}
}

# else

void
FileIOResource::Set( const StrPtr &name )
{
	Set( name, 0 );
}
void
FileIOResource::Set( const StrPtr &name, Error *e )
{
	path.Set( name );
}

# endif


void
FileIOResource::Open( FileOpenMode mode, Error *e )
{
	// Save mode for write, close

	this->mode = mode;

	resourceData = new StrBuf;

	// If we're opening the resource fork for read, fill temp file and
	// open that.
	
	if( mode == FOM_READ )
	{

	    ByteCount size;		// bytes to write to file
	    char *buf;
            OSErr err;

	    ioOffset = 0;
	    resourceData->Clear();

	    MacFile * macFile = MacFile::GetFromPath(
	                        Name(),
	                        &err );

	    if ( !macFile )
	    {
		e->Sys( "File not found for resource encoding!", Name() );
		return;
	    }

	    if( macFile->OpenResourceFork( fsRdPerm ) != noErr )
	    {
		e->Sys("Can't open resource fork for encoding!", Name() );
    		delete macFile;
		return;
	    }

	    /*
	     * Put file info into resource fork.
	     */

	    size = sizeof( FInfo );
	    buf = resourceData->Alloc( size );
	    const FInfo *fi = macFile->GetFInfo();
	    memcpy( buf, fi, size );
	    MacFile::SwapFInfo( (FInfo *)buf );

	    size = macFile->GetResourceForkSize();
	    buf = resourceData->Alloc( size );
        
	    if( macFile->ReadResourceFork( size, buf, &size ) != noErr )
	    {
    		e->Sys( "Error reading from resource fork!", Name());
	    }
	    
            macFile->CloseResourceFork();
    	
    	    delete macFile;
        
	}
}

void
FileIOResource::Write( const char *buf, int len, Error *e )
{
	resourceData->Append( buf, len );
}

int
FileIOResource::Read( char *buf, int len, Error *e )
{
	int l = resourceData->Length() - ioOffset;

	if( len < l )
	    l = len;

	memcpy( buf, resourceData->Text() + ioOffset, l );

	ioOffset += l;

	return l;
}

void
FileIOResource::Close( Error *e )
{
	if( !resourceData )
	    return;

	if( mode == FOM_WRITE )
	{
	    ByteCount size;		// bytes to read from file
	    
	    char *buf = resourceData->Text();

	    if( resourceData->Length() < sizeof( FInfo ) )
	    {
		e->Set( MsgOs::EmptyFork ) << Name();
		return;
	    }

	    OSErr err;
	    
            MacFile * macFile =  MacFile::GetFromPath(
	                                Name(),
	                                &err );
	    if ( !macFile )
	    {
		macFile = MacFile::CreateFromPath(
	                Name(),
	                false,
	                &err );
	    }

	    if ( !macFile )
	    {
		e->Sys("open", Name() );
		return;
	    }

	    if ( macFile->IsDir() )
	    {
		e->Sys( "File not found for resource encoding!", Name() );
		return;
	    }
	    
	    if( macFile->OpenResourceFork( fsWrPerm ) != noErr )
	    {
		e->Sys( "Can't open resource fork of file %s.", Name() );
    		delete macFile;
    		return;
	    }

	    FInfo info;
	    size = sizeof(FInfo);
	    memcpy( &info, buf, size );
	    MacFile::SwapFInfo( &info );
	    buf += size;

	    // Write contents of resource fork.
	    // Truncate it, too, because Mac is special.

	    size = resourceData->Length() - sizeof( FInfo );

	    if ( macFile->WriteResourceFork( size, buf, &size ) != noErr )
		    e->Sys( "Error writing resource fork of %s.", Name() );
		
	    if ( macFile->CloseResourceFork() != noErr )
		    e->Sys( "Error closing resource fork of %s.", Name() );

	    // save FileInfo & close off file

	    if ( macFile->SetFInfo( &info ) != noErr )
		    e->Sys( "Error writing Finder Info of %s.", Name() );
	    
	    // Set readonly/rw as necessary
	    
	    Chmod( perms, e );
	    
	    delete macFile;

	}

	delete resourceData;
	resourceData = 0;
}

void
FileIOResource::Unlink( Error *e )
{
	// do nothing for the resource fork.
}

# endif /* OS_MACOSX */

