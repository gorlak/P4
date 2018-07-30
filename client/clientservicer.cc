/*
 * Copyright 1995, 2001 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# ifdef USE_EBCDIC
# define NEED_EBCDIC
# endif

# include <stdhdrs.h>

# include <strbuf.h>
# include <strdict.h>
# include <strops.h>
# include <strarray.h>
# include <strtable.h>
# include <error.h>
# include <mapapi.h>
# include <handler.h>
# include <rpc.h>
# include <i18napi.h>
# include <charcvt.h>
# include <transdict.h>
# include <ignore.h>
# include <debug.h>
# include <tunable.h>

# include <p4tags.h>
# include <msgclient.h>
# include <msgsupp.h>

# include <filesys.h>
# include <pathsys.h>
# include <enviro.h>

# include <readfile.h>
# include <diffsp.h>
# include <diffan.h>
# include <diff.h>

# include "clientuser.h"
# include "client.h"
# include "clientprog.h"

# include "clientservice.h"

/*
 * ReconcileHandle - handle reconcile's list of files to skip when adding
 */

class ReconcileHandle : public LastChance {

    public:
			ReconcileHandle() 
			{ 
			    pathArray = new StrArray;
			    delCount = 0; 
			}
			~ReconcileHandle() 
			{ 
			    delete pathArray; 
			}

			StrArray *pathArray;
			int delCount;
} ;

/*
 * SendDir - utility method used by clientTraverseShort to decide if a
 *	     filename should be output as a file or as a directory (status -s)
 */
int
SendDir( PathSys *fileName, StrPtr *cwd, StrArray *dirs, int &idx, int skip )
{
	int isDir = 0;

	// Skip printing file in current directory and just report subdirectory

	if( skip )
	{
	    fileName->SetLocal( *cwd, StrRef( "..." ) );
	    return 1;
	}

	// If file is in the current directory: isDirs is unset so that our
	// caller will send back the original file.

	fileName->ToParent();

	if( !fileName->SCompare( *cwd ) )
	    return isDir;

	// Set path to the directory under cwd containing this file.
	// 'dirs' is the list of dirs in cwd on workspace.

	for( ; idx < dirs->Count() && !isDir; idx++ )
	{
	    if( fileName->IsUnderRoot( *dirs->Get( idx ) ) )
	    {
		fileName->SetLocal( *dirs->Get(idx), StrRef( "..." ));
		++isDir;
	    }
	}

	return isDir;
}

void
clientReconcileFlush( Client *client, Error *e )
{
	// Delete the client's reconcile handle

	StrRef skipAdd( "skipAdd" );
	ReconcileHandle *recHandle =
			(ReconcileHandle *)client->handles.Get( &skipAdd );

	if( recHandle )
	    delete recHandle;
}

/*
 * clientReconcileEdit() -- "inquire" about file, for 'p4 reconcile'
 *
 * This routine performs clientCheckFile's scenario 1 checking, but
 * also saves the list of files that are in the depot so they can be
 * compared to the list of files on the client when reconciling later for add.
 *
 */

void
clientReconcileEdit( Client *client, Error *e )
{
	client->NewHandler();
	StrPtr *clientType = client->GetVar( P4Tag::v_type );
	StrPtr *digest = client->GetVar( P4Tag::v_digest );
	StrPtr *digestType = client->GetVar( P4Tag::v_digestType );
	StrPtr *confirm = client->GetVar( P4Tag::v_confirm, e );
	StrPtr *fileSize = client->GetVar( P4Tag::v_fileSize );
	StrPtr *submitTime = client->GetVar( P4Tag::v_time );

	if( e->Test() && !e->IsFatal() )
	{
	    client->OutputError( e );
	    return;
	}

	const char *status = "exists";
	const char *ntype = clientType ? clientType->Text() : "text";

	// For adding files,  checkSize is a maximum (or use alt type)
	// For flush,  checkSize is an optimization check on binary files.

	offL_t checkSize = fileSize ? fileSize->Atoi64() : 0;

	/*
	 * If we do know the type, we want to know if it's missing.
	 * If it isn't missing and a digest is given, we want to know if
	 * it is the same.
	*/

	FileSys *f = ClientSvc::File( client, e );

	if( e->Test() || !f )
	    return;
	int statVal = f->Stat();

	// Save the list of depot files. We'll diff it against the list of all
	// files on client to find files to add in clientReconcileAdd

	StrRef skipAdd( "skipAdd" );
	ReconcileHandle *recHandle =
			(ReconcileHandle *)client->handles.Get( &skipAdd );

	if( !recHandle )
	{
	    recHandle = new ReconcileHandle;
	    client->handles.Install( &skipAdd, recHandle, e );

	    if( e->Test() )
		return;
	}

	if( !( statVal & ( FSF_SYMLINK|FSF_EXISTS ) ) )
	{
	    status = "missing";
	    recHandle->delCount++;
	} 
	else if ( ( !( statVal & FSF_SYMLINK ) && ( f->IsSymlink() ) ) 
                || ( ( statVal & FSF_SYMLINK ) && !( f->IsSymlink() ) ) ) 
	{
	    recHandle->pathArray->Put()->Set( f->Name() );
	}
	else if( digest )
	{
	    recHandle->pathArray->Put()->Set( f->Name() );
	    if( digestType )
	    {
		StrBuf localDigest;
		FileDigestType digType;
		if( !digestType->Compare( StrRef( P4Tag::v_digestTypeMD5 ) ) )
		    digType = FS_DIGEST_MD5;
		else if( !digestType->Compare(
				    StrRef( P4Tag::v_digestTypeGitText ) ) )
		    digType = FS_DIGEST_GIT_TEXT_SHA1;
		else if( !digestType->Compare(
				    StrRef( P4Tag::v_digestTypeGitBinary ) ) )
		    digType = FS_DIGEST_GIT_BINARY_SHA1;
		else if( !digestType->Compare(
				    StrRef( P4Tag::v_digestTypeSHA256 ) ) )
		    digType = FS_DIGEST_SHA256;

		f->ComputeDigest( digType, &localDigest, e );
		if( !e->Test() && !localDigest.XCompare( *digest ) )
		    status = "same";

	    } 
	    else if( !checkSize || checkSize == f->GetSize() )
	    {
		StrBuf localDigest;
		f->Translator( ClientSvc::XCharset( client, FromClient ) );

		// Bypass expensive digest computation with -m unless the
		// local file's timestamp is different from the server's.

		if( !submitTime ||
		    ( submitTime && ( f->StatModTime() != submitTime->Atoi()) ) )
		{
		    f->Digest( &localDigest, e );

		    if( !e->Test() && !localDigest.XCompare( *digest ) )
			status = "same";
		}
		else if( submitTime )
		    status = "same";
	    }

	    // If we can't read the file (for some reason -- wrong type?)
	    // we consider the files different.

	    e->Clear();
	}

	delete f;

	// tell the server 

	client->SetVar( P4Tag::v_type, ntype );
	client->SetVar( P4Tag::v_status, status );
	client->Confirm( confirm );

	// Report non-fatal error and clear it.

	client->OutputError( e );
}

int
clientTraverseShort( Client *client, StrPtr *cwd, const char *dir, int traverse,
		    int noIgnore, int initial, int skipCheck, int skipCurrent,
		    MapApi *map, StrArray *files, StrArray *dirs, int &idx,
		    StrArray *depotFiles, int &ddx, const char *config, 
		    Error *e )
{
	// Variant of clientTraverseDirs that computes the files to be
	// added during traversal of directories instead of at the end,
	// and returns directories and files rather than all files.
	// This is used by 'status -s'.

	// Scan the directory.

	FileSys *f = client->GetUi()->File( FST_BINARY );
	f->SetContentCharSetPriv( client->content_charset );
	f->Set( StrRef( dir ) );
	int fstat = f->Stat();

	Ignore *ignore = client->GetIgnore();
	StrPtr ignored = client->GetIgnoreFile();
	StrBuf from;
	StrBuf to;
	CharSetCvt *cvt = ( (TransDict *)client->transfname )->ToCvt();
	const char *fileName;
	int found = 0;

	// Use server case-sensitivity rules to find files to add
	// from.SetCaseFolding( client->protocolNocase );

	// With unicode server and client using character set, we need
	// to send files back as utf8.

	if( client != client->translated )
	{
	    fileName = cvt->FastCvt( f->Name(), strlen(f->Name()), 0 );
	    if( !fileName )
		fileName = f->Name();
	}
	else
	    fileName = f->Name();

	// If this is a file, not a directory, and not to be ignored,
	// save the filename 

	if( !( fstat & FSF_DIRECTORY ) )
	{
	    if( ( fstat & FSF_EXISTS ) || ( fstat & FSF_SYMLINK ) )
	    {
		if( noIgnore || 
	           !ignore->Reject( StrRef(f->Name()), ignored, config ) )
		{
		    files->Put()->Set( fileName );
		    found = 1;
		}
	    }
	    delete f;
	    return found;
	}

	// If this is a symlink to a directory, and not to be ignored,
	// return filename and quit

	if( ( fstat & FSF_SYMLINK ) && ( fstat & FSF_DIRECTORY ) )
	{
	    if( noIgnore || 
	        !ignore->Reject( StrRef(f->Name()), ignored, config ) )
	    {
		files->Put()->Set( fileName );
		found = 1;
	    }
	    delete f;
	    return found;
	}

	// This is a directory to be scanned.

	StrArray *ua = f->ScanDir( e );

	if( e->Test() )
	{
	    // report error but keep moving

	    delete f;
	    client->OutputError( e );
	    return 0;
	}

	// PathSys for concatenating dir and local path,
	// to get full path

	PathSys *p = PathSys::Create();
	p->SetCharSet( f->GetCharSetPriv() );

	// Attach path delimiter to dirs so Sort() works correctly, and also to
	// save relevant Stat() information.

	StrArray *a = new StrArray();
	StrBuf dirDelim;
	StrBuf symDelim;

#ifdef OS_NT
	dirDelim.Set( "\\" );
	symDelim.Set( "\\\\" );
#else
	dirDelim.Set( "/" );
	symDelim.Set( "//" );
#endif

	// Now files & dirs at this level from ScanDir() will be sorted
	// in the same order as the depotFiles array. And delimiters tell us
	// the Stat() of those files.

	for( int i = 0; i < ua->Count(); i++ )
	{
	    p->SetLocal( StrRef( dir ), *ua->Get(i) );
	    f->Set( *p );
	    int stat = f->Stat();
	    StrBuf out;

	    if( ( stat & FSF_DIRECTORY ) && !( stat & FSF_SYMLINK ) )
		out << ua->Get( i ) << dirDelim;
	    else if( ( stat & FSF_DIRECTORY ) && ( stat & FSF_SYMLINK ) )
		out << ua->Get( i ) << symDelim;
	    else if( ( stat & FSF_EXISTS ) || ( stat & FSF_SYMLINK ) )
		out << ua->Get(i);
	    else
		continue;

	    a->Put()->Set( out );
	}
	a->Sort( !StrBuf::CaseUsage() );
	delete ua;

	// If directory is unknown to p4, we don't need to check that files
	// are in depot (they aren't), so just return after the first file
	// is found and bypass checking. 

	int doSkipCheck = skipCheck;

	int dddx = 0;
	int matched;
	StrArray *depotDirs = new StrArray();

	// First time through we save depot dirs

	if( initial )
	{
	    StrPtr *ddir;
	    for( int j=0; ddir=client->GetVar( StrRef("depotDirs"), j); j++)
	    {
		StrBuf dirD;
		dirD << ddir << dirDelim;
		depotDirs->Put()->Set( dirD );
	    }
	    depotDirs->Sort( !StrBuf::CaseUsage() );
	}

	// For each directory entry.

	for( int i = 0; i < a->Count(); i++ )
	{
	    // Strip delimiters and use the hints to determine stat

	    int isDir = 0;
	    int isSymDir = 0;
	    StrBuf fName;
	    if( a->Get(i)->EndsWith( symDelim.Text(), 2 ) )
	    {
		++isDir;
		++isSymDir;
		fName.Set( a->Get(i)->Text(), a->Get(i)->Length() - 2 );
	    }
	    else if( a->Get(i)->EndsWith( dirDelim.Text(), 1 ) )
	    {
		++isDir;
		fName.Set( a->Get(i)->Text(), a->Get(i)->Length() - 1 );
	    }
	    else
		fName.Set( a->Get(i) );
		
	    // Check mapping, ignore files before sending file or symlink back

	    p->SetLocal( StrRef( dir ), fName );
	    f->Set( *p );
	    int checkFile = 0;

	    if( client != client->translated )
	    {
		fileName = cvt->FastCvt( f->Name(), strlen(f->Name()) );
		if( !fileName )
		    fileName = f->Name();
	    }
	    else
		fileName = f->Name();

	    if( isDir )
	    {
		if( isSymDir )
		{
		    from.Set( fileName );
		    from << "/";

	            if( client->protocolNocase != StrBuf::CaseUsage() )
	            {
	                from.SetCaseFolding( client->protocolNocase );
	                matched = map->Translate( from, to, MapLeftRight );
	                from.SetCaseFolding( !client->protocolNocase );
	            }
	            else
	                matched = map->Translate( from, to, MapLeftRight );

		    if( !matched )
			continue;

		    if( noIgnore || 
	                !ignore->Reject( StrRef(f->Name()), ignored, config ) )
		    {
			if( doSkipCheck )
			{
			    p->Set( fileName );
			    (void)SendDir( p, cwd, dirs, idx, skipCurrent );
			    files->Put()->Set( p );
			    found = 1;
			    break;
			}
			else
			   ++checkFile;
		    }
		}
		else if( traverse )
		{
		    if( initial )
		    {
			dirs->Put()->Set( fileName );
			int foundOne = 0;
			int l;

			// If this directory is unknown to the depot, we don't
			// need to compare against depot files. 

			for( ; dddx < depotDirs->Count() && !foundOne; dddx++)
			{
			    StrBuf fName;
			    fName << fileName << dirDelim;
			    const StrPtr *ddir = depotDirs->Get( dddx );
			    p->SetLocal( *cwd, *ddir );
			    l =  fName.SCompare( *p );
			    if( !l )
				++foundOne;
			    else if( l < 0 )
				break;
			}
			skipCheck = !foundOne ? 1 : 0;
		    }

		    found = clientTraverseShort( client, cwd, f->Name(),
						traverse, noIgnore, 0,
						skipCheck, skipCurrent, map,
						files, dirs, idx, depotFiles,
						ddx, config, e );

		    // Stop traversing directories when we have a file to
		    // to add, unless we are at the top and need to check
		    // for files in the current directory.

		    if( found && !initial )
			break;
		    else if( found && initial && !skipCurrent )
			found = 0;
		    if( found )
			break;
		}
	    }
	    else
	    {
		from.Set( fileName );

	        if( client->protocolNocase != StrBuf::CaseUsage() )
	        {
	            from.SetCaseFolding( client->protocolNocase );
	            matched = map->Translate( from, to, MapLeftRight );
	            from.SetCaseFolding( !client->protocolNocase );
	        }
	        else
	            matched = map->Translate( from, to, MapLeftRight );

		if( !matched )
		    continue;

		if( noIgnore || 
	            !ignore->Reject( StrRef(f->Name()), ignored, config ) )
		{
		    if( doSkipCheck )
		    {
			p->Set( fileName );
			(void)SendDir( p, cwd, dirs, idx, skipCurrent );
			files->Put()->Set( p );
			found = 1;
			break;
		    }
		    else
			++checkFile;
		}
	    }

	    // See if file is in depot and if not, either set the file
	    // or directory to be reported back to the server.

	    if( checkFile )
	    {
		int l = 0;
		int finished = 0;
		while ( !finished )
		{
		    if( ddx >= depotFiles->Count())
			l = -1;
		    else
			l = StrRef( fileName ).SCompare( *depotFiles->Get(ddx));

		    if( !l )
		    {
			++ddx;
			++finished;
		    }
		    else if( l < 0 )
		    {
			p->Set( fileName );
			if( initial && skipCurrent )
			{
			    p->ToParent();
			    p->SetLocal( *p, StrRef("...") );
			    files->Put()->Set( p );
			}
			else if( SendDir( p, cwd, dirs, idx, skipCurrent ) )
			    files->Put()->Set( p );
			else
			    files->Put()->Set( fileName );
			found = 1;
			break;
		    }
		    else
			++ddx;
		}
		if( ( !initial || skipCurrent ) && found )
		    break;
	    }
	}

	delete p;
	delete a;
	delete f;
	delete depotDirs;

	return found;
}

void
clientTraverseDirs( Client *client, const char *dir, int traverse, int noIgnore,
		    int getDigests, MapApi *map, StrArray *files,
		    StrArray *sizes, StrArray *digests,
		    int &hasIndex, StrArray *hasList, const char *config, 
		    Error *e )
{
	// Return all files in dir, and optionally traverse dirs in dir,
	// while checking each file against map before returning it

	// Scan the directory.

	FileSys *f = client->GetUi()->File( FST_BINARY );
	f->SetContentCharSetPriv( client->content_charset );
	f->Set( StrRef( dir ) );
	int fstat = f->Stat();

	Ignore *ignore = client->GetIgnore();
	StrPtr ignored = client->GetIgnoreFile();
	StrBuf from;
	StrBuf to;
	CharSetCvt *cvt = ( (TransDict *)client->transfname )->ToCvt();
	const char *fileName;
	StrBuf localDigest;

	// With unicode server and client using character set, we need
	// to send files back as utf8.

	if( client != client->translated )
	{
	    fileName = cvt->FastCvt( f->Name(), strlen(f->Name()), 0 );
	    if( !fileName )
		fileName = f->Name();
	}
	else
	    fileName = f->Name();

	// If this is a file, not a directory, and not to be ignored,
	// save the filename 

	if( !( fstat & FSF_DIRECTORY ) )
	{
	    if( ( fstat & FSF_EXISTS ) || ( fstat & FSF_SYMLINK ) )
	    {
		if( noIgnore || 
	            !ignore->Reject( StrRef(f->Name()), ignored, config ) )
		{
		    files->Put()->Set( fileName );
		    sizes->Put()->Set( StrNum( f->GetSize() ) );
		    if( getDigests )
		    {
			f->Translator( ClientSvc::XCharset(client,FromClient));
			f->Digest( &localDigest, e );
			digests->Put()->Set( localDigest );
		    }
		}
	    }
	    delete f;
	    return;
	}

	// If this is a symlink to a directory, and not to be ignored,
	// return filename and quit

	if( ( fstat & FSF_SYMLINK ) && ( fstat & FSF_DIRECTORY ) )
	{
	    if( noIgnore || 
	        !ignore->Reject( StrRef(f->Name()), ignored, config ) )
	    {
		files->Put()->Set( fileName );
		sizes->Put()->Set( StrNum( f->GetSize() ) );
		if( getDigests )
		{
		    f->Translator( ClientSvc::XCharset(client,FromClient));
		    f->Digest( &localDigest, e );
		    digests->Put()->Set( localDigest );
		}
	    }
	    delete f;
	    return;
	}

	// Directory might be ignored,  bail

	if( !noIgnore && 
	    ignore->RejectDir( StrRef( f->Name() ), ignored, config ) )
	{
	    delete f;
	    return;
	}

	// This is a directory to be scanned.

	StrArray *a = f->ScanDir( e );

	if( e->Test() )
	{
	    // report error but keep moving

	    delete f;
	    client->OutputError( e );
	    return;
	}

	// Sort in case sensitivity of client
	a->Sort( !StrBuf::CaseUsage() );

	// PathSys for concatenating dir and local path,
	// to get full path

	PathSys *p = PathSys::Create();
	p->SetCharSet( f->GetCharSetPriv() );
	int matched;

	// For each directory entry.

	for( int i = 0; i < a->Count(); i++ )
	{
	    // Check mapping, ignore files before sending file or symlink back

	    p->SetLocal( StrRef( dir ), *a->Get(i) );
	    f->Set( *p );

	    if( client != client->translated )
	    {
		fileName = cvt->FastCvt( f->Name(), strlen(f->Name()) );
		if( !fileName )
		    fileName = f->Name();
	    }
	    else
		fileName = f->Name();

	    // Do compare with array list (skip files if possible)
	    int cmp = -1;

	    while( hasList && hasIndex < hasList->Count() )
	    {
	        cmp = f->Path()->SCompare( *hasList->Get( hasIndex ) );

	        if( cmp < 0 )
	            break;

	        hasIndex++;

	        if( cmp == 0 )
	            break;
	    }

	    // Don't stat if we matched a file from the edit list

	    if( cmp == 0 )
	        continue;

	    int stat = f->Stat();

	    if( stat & FSF_DIRECTORY )
	    {
		if( stat & FSF_SYMLINK )
		{
		    from.Set( fileName );
		    from << "/";

	            if( client->protocolNocase != StrBuf::CaseUsage() )
	            {
	                from.SetCaseFolding( client->protocolNocase );
	                matched = map->Translate( from, to, MapLeftRight );
	                from.SetCaseFolding( !client->protocolNocase );
	            }
	            else
	                matched = map->Translate( from, to, MapLeftRight );

		    if( !matched )
			continue;

		    if( noIgnore || 
	                !ignore->Reject( StrRef(f->Name()), ignored, config ) )
		    {
			files->Put()->Set( fileName );
			sizes->Put()->Set( StrNum( f->GetSize() ) );
			if( getDigests )
			{
			    f->Translator( ClientSvc::XCharset(client,FromClient));
			    f->Digest( &localDigest, e );
			    digests->Put()->Set( localDigest );
			}
		    }
		}
		else if( traverse )
		    clientTraverseDirs( client, f->Name(), traverse, noIgnore,
					getDigests, map, files, sizes,
					digests, hasIndex, hasList, 
	                                config, e );
	    }
	    else if( ( stat & FSF_EXISTS ) || ( stat & FSF_SYMLINK ) )
	    {
		from.Set( fileName );

	        if( client->protocolNocase != StrBuf::CaseUsage() )
	        {
	            from.SetCaseFolding( client->protocolNocase );
	            matched = map->Translate( from, to, MapLeftRight );
	            from.SetCaseFolding( !client->protocolNocase );
	        }
	        else
	            matched = map->Translate( from, to, MapLeftRight );

		if( !matched )
		    continue;

		if( noIgnore || 
	            !ignore->Reject( StrRef(f->Name()), ignored, config ) )
		{
		    files->Put()->Set( fileName );
		    sizes->Put()->Set( StrNum( f->GetSize() ) );
		    if( getDigests )
		    {
			f->Translator( ClientSvc::XCharset(client,FromClient));
			f->Digest( &localDigest, e );
			digests->Put()->Set( localDigest );
		    }
		}
	    }
	}

	delete p;
	delete a;
	delete f;
}

void
clientReconcileAdd( Client *client, Error *e )
{
	/*
	 * Reconcile add confirm
	 *
	 * Scans the directory (local syntax) and returns
	 * files in the directory using the full path.  This
	 * differs from clientScanDir in that it returns full
	 * paths, supports traversing subdirectories, and checks
	 * against a mapTable.
	 */

	client->NewHandler();
	StrPtr *dir = client->transfname->GetVar( P4Tag::v_dir, e );
	StrPtr *confirm = client->GetVar( P4Tag::v_confirm, e );
	StrPtr *traverse = client->GetVar( "traverse" );
	StrPtr *summary = client->GetVar( "summary" );
	StrPtr *skipIgnore = client->GetVar( "skipIgnore" );
	StrPtr *skipCurrent = client->GetVar( "skipCurrent" );
	StrPtr *sendDigest = client->GetVar( "sendDigest" );
	StrPtr *mapItem;

	if( e->Test() )
	    return;

	MapApi *map = new MapApi;
	StrArray *files = new StrArray();
	StrArray *sizes = new StrArray();
	StrArray *dirs = new StrArray();
	StrArray *depotFiles = new StrArray();
	StrArray *digests = new StrArray();

	// Construct a MapTable object from the strings passed in by server

	for( int i = 0; mapItem = client->GetVar( StrRef("mapTable"), i ); i++)
	{
	    MapType m;
	    int j;
	    char *c = mapItem->Text();
	    switch( *c )
	    {
	    case '-': m = MapExclude; j = 1; break;
	    case '+': m = MapOverlay; j = 1; break;
	    default:  m = MapInclude; j = 0; break;
	    }
	    map->Insert( StrRef( c+j ), StrRef( c+j ), m );
	}

	// If we have a list of files we know are in the depot already,
	// filter them out of our list of files to add. For -s option,
	// we need to have this list of depot files for computing files
	// and directories to add (even if it is an empty list).

	StrRef skipAdd( "skipAdd" );
	ReconcileHandle *recHandle =
			(ReconcileHandle *)client->handles.Get( &skipAdd );

	if( recHandle )
	{
	    recHandle->pathArray->Sort( !StrBuf::CaseUsage() );
	}
	else if( !recHandle && summary != 0 )
	{
	    recHandle = new ReconcileHandle;
	    client->handles.Install( &skipAdd, recHandle, e );

	    if( e->Test() )
	    {
	        delete files;
	        delete sizes;
	        delete dirs;
	        delete depotFiles;
	        delete digests;
	        delete map;
		return;
	     }
	}

	// status -s also needs the list of files opened for add appended
	// to the list of depot files.

	if( summary != 0 )
	{
	    const StrPtr *dfile;
	    for( int j=0; dfile=client->GetVar( StrRef("depotFiles"), j); j++)
		depotFiles->Put()->Set( dfile );
	    for( int j=0; dfile=recHandle->pathArray->Get(j); j++ )
		depotFiles->Put()->Set( dfile );
	    depotFiles->Sort( !StrBuf::CaseUsage() );
	}

	// status -s will output files in the current directory and paths
	// rather than all of the files individually. Compare against depot
	// files early so we can abort traversal early if we can.

	int hasIndex = 0;
	const char *config = client->GetEnviro()->Get( "P4CONFIG" );

	if( summary != 0 )
	{
	    int idx = 0;
	    int ddx = 0;
	    (void)clientTraverseShort( client, dir, dir->Text(), traverse != 0,
				      skipIgnore != 0, 1, 0, skipCurrent != 0,
				      map, files, dirs, idx,
				      depotFiles, ddx, config, e );
	}
	else
	    clientTraverseDirs( client, dir->Text(), traverse != 0,
				skipIgnore != 0, sendDigest != 0, map,
				files, sizes, digests, hasIndex, 
				recHandle ? recHandle->pathArray : 0, 
	                        config, e );
	delete map;

	// Compare list of files on client with list of files in the depot
	// if we have this list from ReconcileEdit. Skip this comparison
	// if summary because it was done already.

	if( recHandle && !summary )
	{
	    int i1 = 0, i2 = 0, i0 = 0, l = 0;

	    while( i1 < files->Count() )
	    {
		if( i2 >= recHandle->pathArray->Count())
		    l = -1;
		else
		    l = files->Get( i1 )->SCompare( 
		        *recHandle->pathArray->Get( i2 ) );

		if( !l )
		{
		    ++i1;
		    ++i2;
		}
		else if( l < 0 )
		{
		    client->SetVar( P4Tag::v_file, i0, *files->Get( i1 ) );
		    if( !sendDigest && recHandle->delCount )
		    {
			// Deleted files?  Send filesize info so the
			// server can try to pair up moves.

			client->SetVar( P4Tag::v_fileSize, 
					i0, *sizes->Get( i1 ) );
		    }
		    if( sendDigest )
			client->SetVar( P4Tag::v_digest, i0, *digests->Get(i1));
		    ++i0;
		    ++i1;
		}
		else
		{
		    ++i2;
		}
	    }
	}
	else
	{
	    for( int j = 0; j < files->Count(); j++ )
	    {
		client->SetVar( P4Tag::v_file, j, *files->Get(j) );
		if( sendDigest )
		    client->SetVar( P4Tag::v_digest, j, *digests->Get(j) );
	    }
	}

	client->Confirm( confirm );
	delete files;
	delete sizes;
	delete dirs;
	delete depotFiles;
	delete digests;
}

void
clientExactMatch( Client *client, Error *e )
{
	// Compare existing digest to list of
	// new client files, return match, or not.

	// Args:
	// type     = existing file type (clientpart)
	// digest   = existing file digest
	// fileSize = existing file size
	// charSet  = existing file charset
	// toFileN  = new file local path
	// indexN   = new file index
	// confirm  = return callback
	//
	// Return:
	// toFile   = exact match
	// index    = exact match

	client->NewHandler();
	StrPtr *digest = client->GetVar( P4Tag::v_digest );
	StrPtr *confirm = client->GetVar( P4Tag::v_confirm, e );

	if( e->Test() )
	    return;

	StrPtr *matchFile = 0;
	StrPtr *matchIndex = 0;
	FileSys *f = 0;

	for( int i = 0 ; 
	     client->GetVar( StrRef( P4Tag::v_toFile ), i ) ;
	     i++ )
	{
	    delete f;

	    StrVarName path = StrVarName( StrRef( P4Tag::v_toFile ), i );
	    f = ClientSvc::FileFromPath( client, path.Text(), e );

	    // If we encounter a problem with a file, we just don't return
	    // it as a match.  No need to blat out lots of errors.

	    if( e->Test() || !f )
	    {
		e->Clear();
		continue;
	    }

	    int statVal = f->Stat();

	    // Skip files that are symlinks when we
	    // aren't looking for symlinks.

	    if( ( !( statVal & ( FSF_SYMLINK|FSF_EXISTS ) ) )
		|| ( !( statVal & FSF_SYMLINK ) && ( f->IsSymlink() ) )  
                || ( ( statVal & FSF_SYMLINK ) && !( f->IsSymlink() ) ) )
		continue;

	    if( !digest )
	        continue;

	    StrBuf localDigest;
	    f->Translator( ClientSvc::XCharset( client, FromClient ) );
	    f->Digest( &localDigest, e );

	    if( e->Test() )
	    {
		e->Clear();
		continue;
	    }

	    if( !localDigest.XCompare( *digest ) )
	    {
		matchFile  = client->GetVar( StrRef(P4Tag::v_toFile), i );
		matchIndex = client->GetVar( StrRef(P4Tag::v_index), i );
		break; // doesn't get any better
	    }
	}

	delete f;

	if( matchFile && matchIndex )
	{
	    client->SetVar( P4Tag::v_toFile, matchFile );
	    client->SetVar( P4Tag::v_index, matchIndex );
	}

	client->Confirm( confirm );
}

void
clientOpenMatch( Client *client, ClientFile *f, Error *e )
{
	// Follow on from clientOpenFile, not called by server directly.

	// Grab RPC vars and attach them to the file handle so that
	// clientCloseMatch can use them for N-way diffing.

	StrPtr *fromFile = client->GetVar( P4Tag::v_fromFile, e );
	StrPtr *key	 = client->GetVar( P4Tag::v_key, e );
	StrPtr *flags    = client->GetVar( P4Tag::v_diffFlags );
	if( e->Test() )
	    return;
	
	f->matchDict = new StrBufDict;
	f->matchDict->SetVar( P4Tag::v_fromFile, fromFile );
	f->matchDict->SetVar( P4Tag::v_key, key );
	if( flags )
	    f->matchDict->SetVar( P4Tag::v_diffFlags, flags );
	for( int i = 0 ; ; i++ )
	{
	    StrPtr *index = client->GetVar( 
		    StrRef( P4Tag::v_index ),  i );
	    StrPtr *file  = client->GetVar( 
		    StrRef( P4Tag::v_toFile ), i );
	    if( !index || !file )
		break;
	    f->matchDict->SetVar( 
		   StrRef( P4Tag::v_index ),  i, *index );
	    f->matchDict->SetVar( 
		   StrRef( P4Tag::v_toFile ), i, *file );
	}
}

void
clientCloseMatch( Client *client, ClientFile *f1, Error *e )
{
	// Follow on from clientCloseFile, not called by server directly.

	// Compare temp file to existing client files.  Figure out the
	// best match, along with a quantitative measure of how good
	// the match was (lines matched vs total lines).  Stash it
	// in the handle so clientAckMatch can report it back.

	if( !f1->matchDict )
	{
	    e->Set( MsgSupp::NoParm ) << "clientCloseMatch";
	    return;
	}

	StrPtr *fname;
	FileSys *f2 = 0;
	DiffFlags flags;
	if( StrPtr* diffFlags = f1->matchDict->GetVar( P4Tag::v_diffFlags ) )
	    flags.Init( diffFlags );

	int bestNum = 0;
	int bestSame = 0; 
	int totalLines = 0;

	for( int i = 0 ; 
	     fname = f1->matchDict->GetVar( StrRef( P4Tag::v_toFile ), i ) ;
	     i++ )
	{
	    delete f2;

	    f2 = client->GetUi()->File( f1->file->GetType() );
	    f2->SetContentCharSetPriv( f1->file->GetContentCharSetPriv() );
	    f2->Set( *fname );

	    if( e->Test() || !f2 )
	    {
		// don't care
		e->Clear();
		continue;
	    }

	    Sequence s1( f1->file, flags, e );
	    Sequence s2( f2,       flags, e );
	    if ( e->Test() )
	    {
		// still don't care
		e->Clear();
		continue;
	    }

	    DiffAnalyze diff( &s1, &s2 );

	    int same = 0;
	    for( Snake *s = diff.GetSnake() ; s ; s = s->next )
	    {
		same += ( s->u - s->x );
		if( s->u > totalLines )
		    totalLines = s->u;
	    }

	    if( same > bestSame )
	    {
		bestNum = i;
		bestSame = same;
	    }
	}

	delete f2;
	f1->file->Close( e );

	totalLines++; // snake lines start at zero

	if( bestSame )
	{
	    f1->matchDict->SetVar( P4Tag::v_index,
		f1->matchDict->GetVar( StrRef( P4Tag::v_index ), bestNum ) );
	    f1->matchDict->SetVar( P4Tag::v_toFile, 
		f1->matchDict->GetVar( StrRef( P4Tag::v_toFile ), bestNum ) );

	    f1->matchDict->SetVar( P4Tag::v_lower, bestSame );
	    f1->matchDict->SetVar( P4Tag::v_upper, totalLines );
	}

	// clientAckMatch will send this back
}

void
clientAckMatch( Client *client, Error *e )
{
	StrPtr *handle = client->GetVar( P4Tag::v_handle, e );
	StrPtr *confirm = client->GetVar( P4Tag::v_confirm, e );
	
	if( e->Test() )
	    return;

	// Get handle.

	ClientFile *f = (ClientFile *)client->handles.Get( handle, e );

	if( e->Test() )
	    return;

	// Fire everything back.

	StrPtr *fromFile = f->matchDict->GetVar( P4Tag::v_fromFile );
	StrPtr *key	 = f->matchDict->GetVar( P4Tag::v_key );
	StrPtr *toFile   = f->matchDict->GetVar( P4Tag::v_toFile );
	StrPtr *index    = f->matchDict->GetVar( P4Tag::v_index );
	StrPtr *lower    = f->matchDict->GetVar( P4Tag::v_lower );
	StrPtr *upper    = f->matchDict->GetVar( P4Tag::v_upper );

	if( fromFile && key )
	{
	    client->SetVar( P4Tag::v_fromFile,	fromFile );
	    client->SetVar( P4Tag::v_key,	key );
	}
	else
	{
	    e->Set( MsgSupp::NoParm ) << "fromFile/key";
	    return;
	}
	if( toFile && index && lower && upper )
	{
	    client->SetVar( P4Tag::v_toFile, toFile );
	    client->SetVar( P4Tag::v_index,  index );
	    client->SetVar( P4Tag::v_lower,  lower );
	    client->SetVar( P4Tag::v_upper,  upper );
	}

	client->Confirm( confirm );
	delete f;	    
}
