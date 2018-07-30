/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include <strbuf.h>
# include <error.h>
# include <handler.h>

# include <filesys.h>
# include <md5.h>

# include "clientuser.h"
# include <msgclient.h>
# include "clientmerge.h"
# include "clientmerge2.h"

static const char *const mergeHelp[] = {
    "Two-way merge options:",
    "",
    "    Accept:",
    "            at              Keep only changes to their file.",
    "            ay              Keep only changes to your file.",
    "",
    "    Diff:",
    "            d               Diff their file against yours->",
    "",
    "    Edit:",
    "            et              Edit their file (read/write).",
    "            ey              Edit your file (read/write).",
    "",
    "    Misc:",
    "            s               Skip this file.",
    "            h               Print this help message.",
    "            ^C              Quit the resolve operation.",
    "",
    0 
};

ClientMerge2::ClientMerge2( ClientUser *ui,
			    FileSysType type,
			    FileSysType theirType )
{
	// Save UI for future use
	this->ui = ui;

	// Set up files.

	yours = ui->File( type );
	theirs = ui->File( theirType );

	// Make theirs temp

	theirs->SetDeleteOnClose();

	// And zonk counters for chunks

	chunksYours = 
	chunksTheirs =
	chunksConflict =
	chunksBoth = 0;

	// 2003.1 server sends base digests

	theirsMD5 = new MD5;
	hasDigests = 0;
}

ClientMerge2::~ClientMerge2()
{
	delete yours;
	delete theirs;

	delete theirsMD5;
}

void
ClientMerge2::Open( StrPtr *name, Error *e, CharSetCvt *cvt, int charset )
{
	yours->Set( *name );

	if( hasDigests )
	{
	    // calculate digest for yours file

	    yours->Digest( &yoursDigest, e );
	}

	theirs->MakeLocalTemp( name->Text() );
	theirs->Perms( FPM_RW );
	theirs->Open( FOM_WRITE, e );
	theirs->Translator( cvt );

	if( charset )
	{
	    yours->SetContentCharSetPriv( charset );
	    theirs->SetContentCharSetPriv( charset );
	}
}

void
ClientMerge2::Write( StrPtr *buf, StrPtr *bits, Error *e )
{
	theirs->Write( buf, e );

	if( hasDigests )
	    theirsMD5->Update( *buf );
}

void
ClientMerge2::Close( Error *e )
{
	theirs->Close( e );

	if( hasDigests )
	{
	    theirsMD5->Final( theirsDigest );

	    // Assign the chunk variables - there can be only one.
	    //
	    // base == yours,   base != theirs,  yours != theirs   1 theirs
	    // base != yours,   base != theirs,  yours != theirs   1 conflicting
	    // base != yours,   base != theirs,  yours == theirs   1 both
	    // base != yours,   base == theirs,  yours != theirs   1 yours

	    if( baseDigest == yoursDigest )
	    {
	        if( baseDigest != theirsDigest )
	            chunksTheirs = 1;
	    }
	    else if( baseDigest != theirsDigest )
	    {
	        if( yoursDigest != theirsDigest )
	            chunksConflict = 1;
	        else
	            chunksBoth = 1;
	    }
	    else
	        chunksYours = 1;
	}
}

void
ClientMerge2::Chmod( const char *perms, Error *e )
{
	yours->Chmod2( perms, e ); 
}

void
ClientMerge2::CopyDigest( StrPtr *digest, Error *e )
{
	// copy the base digest from the server

	baseDigest.Set( digest );
	hasDigests = 1;
}

void
ClientMerge2::SetTheirModTime( StrPtr *modTime )
{
	theirs->ModTime( modTime );
}

MergeStatus
ClientMerge2::AutoResolve( MergeForce force )
{
        Error e;

	// pre 2003.1 server doesn't send digest

	if( !hasDigests )
	{
	    if( !yours->Compare( theirs, &e ) )
	    {
                e.Set( MsgClient::MergeMsg2 ) << 0 << 0 << 1 << 0;
	        ui->Message( &e );
	        return CMS_THEIRS;
	    }

	    if( force == CMF_FORCE )
	        e.Set( MsgClient::NonTextFileMerge );
	    else
	        e.Set( MsgClient::ResolveManually );
	    ui->Message( &e );

	    return CMS_SKIP;
	}

        e.Set( MsgClient::MergeMsg2 ) << chunksYours
                                      << chunksTheirs
                                      << chunksBoth
                                      << chunksConflict;
        ui->Message( &e );

	if( chunksConflict )
	    return CMS_SKIP;

	// Now we know there are no conflicts

	if( !chunksYours )
	    return CMS_THEIRS;

	return CMS_YOURS;
}

MergeStatus
ClientMerge2::Resolve( Error *e )
{
	/* If the files are identical, autoaccept theirs */
	/* We prefer theirs over ours, because then integration history */
	/* marks it as a "copy" and we know the files are now identical. */
	/* Note that this silently swallows chunksBoth... */

	/* Get autoresolve suggestion */

	MergeStatus autoStat = AutoResolve( CMF_FORCE );

	/* Iterative try to get the user to select one of the two files. */

	StrBuf buf;

	for(;;)
	{
	    const char *autoSuggest;

	    // No default action, either suggest at or ay if applicable.

	    switch( autoStat )
	    {
	    default:
	    case CMS_SKIP:      autoSuggest = "" ; break;
	    case CMS_THEIRS:    autoSuggest = "at" ; break;
	    case CMS_YOURS:     autoSuggest = "ay" ; break;
	    }

	    // Prompt.  If no response, use auto

	    buf.Clear();
	    e->Clear();

	    if( yours->IsTextual() && theirs->IsTextual() )
	        e->Set( MsgClient::MergePrompt2Edit ) << autoSuggest;
	    else
	        e->Set( MsgClient::MergePrompt2 ) << autoSuggest;

	    e->Fmt( buf, EF_PLAIN );
	    e->Clear();
	    ui->Prompt( buf, buf, 0, e );
	    
	    if( e->Test() )
		return CMS_QUIT;

	    if( !buf[0] )
	        buf = autoSuggest;

	    // Do the user-requested operation

	    # define pair( a, b ) ( (a) << 8 | (b) )

	    switch( pair( buf[0], buf[1] ) )
	    {
	    // accept yours
	    case pair( 'a', 'y' ):
	        return CMS_YOURS;

	    // accept theirs
	    case pair( 'a', 't' ):
	        return CMS_THEIRS;

	    // edit yours
	    case pair( 'e', 'y' ):
	        ui->Edit( yours, e );
	        break;

	    // edit theirs
	    case pair( 'e', 't' ):
	        ui->Edit( theirs, e );
	        break;

	    // diff
	    case pair( 'd', 0 ):
	        ui->Diff( theirs, yours, 1, 0, e );
	        break;

	    // skip
	    case pair( 's', 0 ):
	        return CMS_SKIP;

	    // help
	    case pair( '?', 0 ):
	    case pair( 'h', 0 ):
		ui->Help( mergeHelp );
		break;

	    default:
	        e->Set( MsgClient::BadFlag );
	        break;
	    }

	    // Report Errors

	    if( e->Test() )
	    {
		ui->Message( e );
		e->Clear();
	    }
	}
}

void
ClientMerge2::Select( MergeStatus stat, Error *e )
{
	// Given the automatic or manual selection, now move the proper
	// file into place.  Usually it is already in place.

	switch( stat )
	{
	case CMS_THEIRS:
	    // accept theirs
	    theirs->Chmod( FPM_RW, e );
	    theirs->Rename( yours, e );
	    // swap around yours and theirs objects for file type changing
	    theirs->Set( yours->Name() );
	    delete yours;
	    yours = theirs;
	    theirs = NULL;
	    return;

	default:
	    return;
	}
}

MergeStatus
ClientMerge2::DetectResolve() const
{
	return CMS_SKIP;
}

const StrPtr *
ClientMerge2::GetYourDigest() const
{
	return &yoursDigest;
}

const StrPtr *
ClientMerge2::GetTheirDigest() const
{
	return &theirsDigest;
}
