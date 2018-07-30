/*
 * Copyright 2001-2002 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * macfile.cpp - Abstract file layer to handle the many differences on
 *               Mac OS X and Classic Mac OS
 */

# include <unistd.h>

# include <sys/mount.h>

# include <stdhdrs.h>
# include <strbuf.h>
# include <strarray.h>
# include <i18napi.h>

# include "macfile.h"

static bool
IsBigEndian()
{
	// detect byte ordering
	static unsigned short s = 1;
	return *(unsigned char *)&s != (unsigned char)1;
}


/* ============================= *\
 *
 *       PRIVATE METHODS
 *
\* ============================= */

UniChar        GetFileSeparator( CFURLPathStyle pathStyle );
CFURLPathStyle GetSystemPathStyle();

char * FSRefToPath( const FSRef * ref );

const HFSUniStr255 * GetDataForkName();
const HFSUniStr255 * GetRsrcForkName();



/* ============================= *\
 *
 *       UTILITY METHODS
 *
\* ============================= */

UniChar GetFileSeparator( CFURLPathStyle pathStyle )
{
    switch ( pathStyle )
    {
        case kCFURLPOSIXPathStyle:
            return (UniChar)'/';
        
        case kCFURLHFSPathStyle:
            return (UniChar)':';
        
        default:
            return (UniChar)'\\';
    }
}

UniChar GetSystemFileSeparator()
{
    return GetFileSeparator( GetSystemPathStyle() );
}

char * FSRefToPath( const FSRef * ref )
{
    unsigned long length   = 256;
    char *        fullPath = NULL;
    OSStatus      status   = noErr;
    
    // Use the FSRef calls to get the path
    //
    fullPath = new char[ length ];
    status = FSRefMakePath( ref, (UInt8 *)fullPath, length );
    
    while ( status == pathTooLongErr || status == buffersTooSmall )
    {
	length += 256;
	delete [] fullPath;
	fullPath = new char[ length ];
	status = FSRefMakePath( ref, (UInt8 *)fullPath, length );
    }

    if ( status != noErr )
    {
	delete [] fullPath;
        fullPath = NULL;
    }

    return fullPath;
    
}

CFURLPathStyle GetSystemPathStyle()
{
    return kCFURLPOSIXPathStyle;
}


const HFSUniStr255 * GetDataForkName()
{
    static int gotName = 0;
    static HFSUniStr255 dataForkName;
    
    if ( gotName )
    	return &dataForkName;

    FSGetDataForkName( &dataForkName );
    gotName = 1;
    
    return &dataForkName;
    
}

const HFSUniStr255 * GetRsrcForkName()
{
    static int gotName = 0;
    static HFSUniStr255 rsrcForkName;
    
    if ( gotName )
    	return &rsrcForkName;

    FSGetResourceForkName( &rsrcForkName );
    gotName = 1;

    return &rsrcForkName;
    
}






/* ============================= *\
 *
 *    MacFile
 *
\* ============================= */



MacFile *
MacFile::GetFromPath(
    const char * path,
    OSErr * error )
{
    FSRef ref;
    Boolean isDir;
    
    OSStatus status = FSPathMakeRef( (const UInt8 *)path, &ref, &isDir );
    
    if ( status != noErr )
    {
        if ( error )
            *error = status;
        return NULL;
    }
    
    return GetFromFSRef( &ref, error );
}

CFStringRef CreateStringAsFilename( CFStringRef path )
{
    CFRange range = CFStringFind( path, CFSTR("/"), kCFCompareBackwards );
    
    range.location += 1;
    range.length = CFStringGetLength( path ) - range.location;
    
    return CFStringCreateWithSubstring( kCFAllocatorDefault, path, range );
}


CFStringRef CreateStringWithParent( CFStringRef path )
{
    CFRange range = CFStringFind( path, CFSTR("/"), kCFCompareBackwards );
    
    range.length = range.location;
    range.location = 0;
    
    return CFStringCreateWithSubstring( kCFAllocatorDefault, path, range );
}

MacFile *
MacFile::CreateFromDirAndName(
    const FSRef &       dir,
    CFStringRef         name,
    Boolean             isDirectory,
    OSErr *             outErr )
{
    FSRef *  fsref = new FSRef;
    OSErr err;
    if ( isDirectory )
    {
        err = FSCreateDirectoryUnicode(
                &dir,
                CFStringGetLength(name),
                CFStringGetCharactersPtr(name),
                kFSCatInfoNone,
                NULL,
                fsref,
                NULL,
                NULL );
    }
    else
    {
        CFDataRef data = CFStringCreateExternalRepresentation(kCFAllocatorDefault, name,
        IsBigEndian() ? kCFStringEncodingUTF16BE : kCFStringEncodingUTF16LE, 0 );
        err = FSCreateFileUnicode(
                &dir, 
                CFDataGetLength(data)/2,
                (const UniChar*)CFDataGetBytePtr(data),
                kFSCatInfoNone, 
                NULL, 
                fsref, 
                NULL);
        CFRelease( data );
    }

    if ( outErr )
        *outErr = err;
        
    if ( err != noErr )
        return NULL;

    return new MacFile( fsref );
}


MacFile *
MacFile::CreateFromPath(
    const char * path,
    Boolean isDirectory,
    OSErr * error )
{
    FSRef ref;
    Boolean isDir;
    
    CFStringRef strRef = CFStringCreateWithFileSystemRepresentation( kCFAllocatorDefault, path );
    
    CFStringRef parent = CreateStringWithParent( strRef );
    CFStringRef fileName = CreateStringAsFilename( strRef );

    CFRelease( strRef );
    
    int parentPathLength = CFStringGetMaximumSizeOfFileSystemRepresentation( parent );
    char * parentPath = (char*)malloc( parentPathLength );
    Boolean success = CFStringGetFileSystemRepresentation( parent, parentPath, parentPathLength );
    CFRelease( parent );
    
    if ( !success )
    {
        CFRelease( fileName );
        free( parentPath );
        return NULL;
    }

    
    OSStatus status = FSPathMakeRef( (const UInt8 *)parentPath, &ref, &isDir );
    free( parentPath );
    
    if ( status != noErr )
    {
        if ( error )
            *error = status;
        CFRelease( fileName );
        return NULL;
    }
    
    MacFile * returnVal = MacFile::CreateFromDirAndName( ref, fileName, isDirectory, error );
    CFRelease( fileName );
    return returnVal;
}




/* ============================= *\
 *
 *    MacFile
 *
\* ============================= */

MacFile *
MacFile::GetFromFSRef(
    const FSRef * ref,
    OSErr *       err )
{
    FSRef * temp = new FSRef;
    *temp = *ref;

    return new MacFile( temp );
}


MacFile::MacFile( FSRef * file )
{
    this->file = file;
    
    LoadCatalogInfo();
    this->changedInfoBitmap = 0;
    
    this->fullPath = FSRefToPath( file );

    dataForkRef = rsrcForkRef = 0;
    
    this->comment = NULL;
    this->commentLength = -1;	
}


MacFile::~MacFile()
{
    delete file;
    delete [] fullPath;
    delete [] comment;
}


OSErr
MacFile::Delete()
{
    if ( !file )
	return fnfErr;

    OSErr ret;

    ret = FSDeleteFork(
	file,
	GetRsrcForkName()->length, 
	GetRsrcForkName()->unicode );
    if( ret != noErr )
	return ret;

    return FSDeleteObject( file );
}


int
MacFile::GetFileSystemType() const
{
    int result = FS_HFS;

# if defined( OS_MACOSX ) && !defined( MAC_MWPEF )

    const char * path = GetPrintableFullPath();

    struct statfs buf;
    statfs( path, &buf );
    
    if ( !strcmp( buf.f_fstypename, "hfs" ) )
    	result = FS_HFS;
    else if ( !strcmp( buf.f_fstypename, "ufs" ) )
    	result = FS_UFS;
    else if ( !strcmp( buf.f_fstypename, "nfs" ) )
    	result = FS_NFS;
        
# endif // OS_MACOSX

    return result;
}

Boolean
MacFile::IsDir() const
{
    return fileInfo.nodeFlags & kFSNodeIsDirectoryMask;
}

OSErr
MacFile::LoadCatalogInfo() const
{
    FSCatalogInfoBitmap info =
          kFSCatInfoFinderInfo
        | kFSCatInfoNodeFlags
        | kFSCatInfoFinderXInfo
        | kFSCatInfoDataSizes
        | kFSCatInfoRsrcSizes;
    
    OSErr err = FSGetCatalogInfo(
		this->file,
		info,
		&this->fileInfo,
		NULL,
		NULL,
		NULL );
    
    return err;
}

OSErr
MacFile::SaveCatalogInfo()
{
    if ( !this->changedInfoBitmap )
    	return noErr;
    
    OSErr err = FSSetCatalogInfo(
                this->file,
                this->changedInfoBitmap,
                &this->fileInfo );
    
    this->changedInfoBitmap = 0;
    
    return err;
}

const FSRef *
MacFile::GetFSRef( FSRef * ref ) const
{
    if ( ref ) *ref = *file;
    return file;
}


const FInfo *
MacFile::GetFInfo() const
{
    return (const FInfo *)&this->fileInfo.finderInfo;
}



OSErr
MacFile::SetFInfo( const FInfo * fInfo)
{
    FInfo * localInfo = (FInfo *)&(this->fileInfo.finderInfo);
    if ( fInfo ) *localInfo = *fInfo;
    changedInfoBitmap |= kFSCatInfoFinderInfo;
    return SaveCatalogInfo();
}



Boolean
MacFile::IsHidden() const
{
    FInfo * localInfo = (FInfo *)&(this->fileInfo.finderInfo);
    return (localInfo->fdFlags & kIsInvisible) != 0;
}


Boolean
MacFile::IsUnbundledApp() const
{
    FInfo * info = (FInfo *)&fileInfo.finderInfo;
    return info->fdType == 'APPL';
}


CFBundleRef
MacFile::CreateBundle() const
{

    CFURLRef    bundleURL;
    CFBundleRef myBundle;

    // Make a CFURLRef from the CFString representation of the 
    // bundle's path. See the Core Foundation URL Services chapter 
    // for details.
    //
    bundleURL = CFURLCreateFromFSRef( NULL, file );

    if ( !bundleURL ) return NULL;
    
    // Make a bundle instance using the URLRef.
    //
    myBundle = CFBundleCreate( NULL, bundleURL );
    CFRelease( bundleURL );
    
    return myBundle;
}


Boolean
MacFile::IsBundledApp() const
{

    CFBundleRef myBundle = CreateBundle();

    if ( !myBundle ) return false;
    
    CFDictionaryRef bundleInfoDict;

    // Get an instance of the info plist.
    //
    bundleInfoDict = CFBundleGetInfoDictionary( myBundle );

    // If we succeeded, look for our property.
    //
    if ( bundleInfoDict == NULL )
    {
	CFRelease( myBundle );
	return false;
    }
    
    // Get the URL for the executable and see if it exists
    //
    CFURLRef urlRef = CFBundleCopyExecutableURL( myBundle );
    
    if ( urlRef )
    {
	CFRelease( urlRef );
	CFRelease( myBundle );
	return true;
    }

    // Any CF objects returned from functions with "create" or 
    // "copy" in their names must be released by us!
    //
    CFRelease( myBundle );
    
    return false;
}

Boolean
MacFile::IsLocked() const
{
    return this->fileInfo.nodeFlags & kioFlAttribLockedMask;
}

OSErr
MacFile::SetLocked( Boolean lock )
{
    if ( lock == IsLocked() )
    	return noErr;

    if ( lock )
    	this->fileInfo.nodeFlags |= kioFlAttribLockedMask;
    else
	this->fileInfo.nodeFlags &= ~kioFlAttribLockedMask;

    this->changedInfoBitmap |= kFSCatInfoNodeFlags;
    
    return SaveCatalogInfo();
}

const char *
MacFile::GetPrintableFullPath() const
{
    return this->fullPath;
}

const FXInfo *
MacFile::GetFXInfo() const
{
    return (const FXInfo *)&fileInfo.extFinderInfo;
}

OSErr
MacFile::SetFXInfo( const FXInfo * fInfo)
{
    FXInfo * localInfo = (FXInfo *)&(fileInfo.extFinderInfo);
    
    if ( fInfo )
    	*localInfo = *fInfo;
    
    changedInfoBitmap |= kFSCatInfoFinderXInfo;
    return SaveCatalogInfo();
}

Boolean
MacFile::HasDataFork() const
{
    return GetDataForkSize() > 0;
}

ByteCount
MacFile::GetDataForkSize() const
{
	LoadCatalogInfo();
    return fileInfo.dataLogicalSize;
}

OSErr MacFile::OpenDataFork( SInt8 permissions )
{
    return FSOpenFork(
	file, 
	GetDataForkName()->length, 
	GetDataForkName()->unicode, 
	permissions, 
	&dataForkRef );
}

OSErr
MacFile::ReadDataFork(
    ByteCount   requestCount,
    void *      buffer,
    ByteCount * actualCount )
{
    if ( !dataForkRef )
	return noErr;

    return FSReadFork(
	dataForkRef,
	fsAtMark,
	0,
	requestCount,
	buffer,
	actualCount);
}

OSErr
MacFile::WriteDataFork(
    ByteCount    requestCount,
    const void * buffer,
    ByteCount *  actualCount )
{

    if ( !dataForkRef )
	return noErr;

    return FSWriteFork(
    	dataForkRef,
    	fsAtMark,
    	0,
    	requestCount,
    	buffer,
    	actualCount );
}

OSErr
MacFile::SetDataForkPosition( ByteCount offset )
{
    if ( !dataForkRef )
	return noErr;

    return FSSetForkPosition( dataForkRef, fsFromStart, offset );
}

OSErr MacFile::CloseDataFork()
{
    if ( !dataForkRef )
	return noErr;
	
    OSErr err = noErr;
    SInt64 pos = 0;

    FSGetForkPosition( dataForkRef, &pos );
    FSSetForkSize( dataForkRef, fsFromStart, pos );

    err = FSCloseFork( dataForkRef );
    dataForkRef = 0;
    return err;
}

Boolean
MacFile::HasResourceFork() const
{
    return GetResourceForkSize() > 0;
}

ByteCount
MacFile::GetResourceForkSize() const
{
	LoadCatalogInfo();
    return fileInfo.rsrcLogicalSize;
}

OSErr
MacFile::OpenResourceFork( SInt8 permissions )
{
    return FSOpenFork (
	file, 
	GetRsrcForkName()->length, 
	GetRsrcForkName()->unicode, 
	permissions, 
	&rsrcForkRef );
}

OSErr
MacFile::ReadResourceFork(
    ByteCount   requestCount,
    void *      buffer,
    ByteCount * actualCount )
{
    if ( !rsrcForkRef )
	return noErr;

    return FSReadFork(
	rsrcForkRef,
	fsAtMark,
	0,
	requestCount,
	buffer,
	actualCount);
}

OSErr
MacFile::WriteResourceFork(
    ByteCount requestCount,
    const void * buffer,
    ByteCount * actualCount )
{
    if ( !rsrcForkRef )
	return noErr;

    return FSWriteFork(
    	rsrcForkRef,
    	fsAtMark,
    	0,
    	requestCount,
    	buffer,
    	actualCount );
}

OSErr
MacFile::CloseResourceFork()
{
    if ( !rsrcForkRef )
	return noErr;

    OSErr err = noErr;
    SInt64 pos = 0;

    FSGetForkPosition( rsrcForkRef, &pos );
    FSSetForkSize( rsrcForkRef, fsFromStart, pos );

    err = FSCloseFork( rsrcForkRef );
    rsrcForkRef = 0;

    return err;
}

OSErr
MacFile::PreloadComment() const
{
    OSErr error = noErr;

    return error;
}

const char *
MacFile::GetComment( int *bufferLength ) const
{
    *bufferLength = 0;
    return NULL;
    
    PreloadComment();
    *bufferLength = commentLength;
    return comment;
}


OSErr
MacFile::SetComment( char * buffer, int bufferLength )
{
    //
    // we don't do anything with this right now
    //
    
    return noErr;
}

OSErr
MacFile::GetTypeAndCreator( UInt32 * type, UInt32 * creator ) const
{
    FInfo * info = (FInfo *)&fileInfo.finderInfo;

    if (type)    *type    = info->fdType;
    if (creator) *creator = info->fdCreator;
    
    return noErr;
}

OSErr
MacFile::SetTypeAndCreator( UInt32 type, UInt32 creator )
{
    FInfo * info = (FInfo *)&fileInfo.finderInfo;

    info->fdType = type;
    info->fdCreator = creator;

    changedInfoBitmap |= kFSCatInfoFinderInfo;
    return SaveCatalogInfo();
}

#define	M_32_SWAP(a) {							\
	uint32_t _tmp = a;						\
	((char *)&a)[0] = ((char *)&_tmp)[3];				\
	((char *)&a)[1] = ((char *)&_tmp)[2];				\
	((char *)&a)[2] = ((char *)&_tmp)[1];				\
	((char *)&a)[3] = ((char *)&_tmp)[0];				\
}

#define	M_16_SWAP(a) {							\
	uint16_t _tmp = a;						\
	((char *)&a)[0] = ((char *)&_tmp)[1];				\
	((char *)&a)[1] = ((char *)&_tmp)[0];				\
}

void
MacFile::SwapFInfo( FInfo *f )
{
	if ( IsBigEndian() )
	    return;

	M_32_SWAP( f->fdType );
	M_32_SWAP( f->fdCreator );
	M_16_SWAP( f->fdFlags );
	M_16_SWAP( f->fdLocation.v );
	M_16_SWAP( f->fdLocation.h );
	M_16_SWAP( f->fdFldr );
}

void
MacFile::SwapFXInfo( FXInfo *f )
{
	if ( IsBigEndian() )
	    return;

	M_16_SWAP( f->fdIconID );
# ifdef notdef
	M_16_SWAP( (f->fdUnused[0]) );
	M_16_SWAP( (f->fdUnused[1]) );
	M_16_SWAP( (f->fdUnused[2]) );
# endif
	M_16_SWAP( f->fdComment );
	M_32_SWAP( f->fdPutAway );
}
