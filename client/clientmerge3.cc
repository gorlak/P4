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
# include <i18napi.h>
# include <charcvt.h>

# include <diffmerge.h>

# include <msgclient.h>

# include "clientuser.h"
# include "clientmerge.h"
# include "clientmerge3.h"


static const char *const mergeHelp[] = {
    "Three-way merge options:",
    "",
    "    Accept:",
    "            at              Keep only changes to their file.",
    "            ay              Keep only changes to your file.",
    "            am              Keep merged file.",
    "            ae              Keep merged and edited file.",
    "            a               Keep autoselected file.",
    "",
    "    Diff:",
    "            dt              See their changes alone.",
    "            dy              See your changes alone.",
    "            dm              See merged changes.",
    "            d               Diff your file against merged file.",
    "",
    "    Edit:",
    "            et              Edit their file (read only).",
    "            ey              Edit your file (read/write).",
    "            e               Edit merged file (read/write).",
    "",
    "    Misc:",
    "            m               Run '$P4MERGE base theirs yours merged'.",
    "            s               Skip this file.",
    "            h               Print this help message.",
    "            ^C              Quit the resolve operation.",
    "",
    "The autoselected 'accept' option is shown in []'s on the prompt.",
    "",
    0 
};

ClientMerge3::ClientMerge3( ClientUser *ui,
			    FileSysType type,
			    FileSysType resType,
			    FileSysType theirType,
			    FileSysType baseType )
{
    	// Save UI for future use
    	this->ui = ui;

	// Set up files.

	yours  = ui->File( type );
	result = ui->File( resType );
	theirs = ui->File( theirType );
	base   = ui->File( baseType );

	// make base,theirs,result temp

	base->SetDeleteOnClose();
	theirs->SetDeleteOnClose();
	result->SetDeleteOnClose();

	// Digests for seeing if edited result matches inputs

	yoursMD5 = new MD5;
	theirsMD5 = new MD5;
	resultMD5 = new MD5;

	showAll = 0;

	theirs_cvt = NULL;
	result_cvt = NULL;
}

ClientMerge3::~ClientMerge3()
{
	delete yours;
	delete base;
	delete theirs;
	delete result;

	delete yoursMD5;
	delete theirsMD5;
	delete resultMD5;

	delete theirs_cvt;
	delete result_cvt;
}

void
ClientMerge3::SetNames( StrPtr *b, StrPtr *t, StrPtr *y )
{
	int i;
	StrPtr n = StrRef::Null();

	if( !b ) b = &n;
	if( !t ) t = &n;
	if( !y ) y = &n;

	for( i = 0; i < MarkerLast; i++ )
	    markertab[i].Clear();

	markertab[ MarkerOriginal ] << ">>>> ORIGINAL " << b;
	markertab[ MarkerTheirs ] << "==== THEIRS " << t;
	markertab[ MarkerYours ] << "==== YOURS " << y;
	markertab[ MarkerBoth ] << "==== BOTH " << t << " " << y;
	markertab[ MarkerEnd ] << "<<<<";
}

void
ClientMerge3::Open( StrPtr *name, Error *e, CharSetCvt *cvt, int charset )
{
	// No names?

	if( !markertab[0].Length() )
	    SetNames( 0, 0, 0 );

	// Open the various temps for writing.
	// Figure if the first one succeeds then the others
	// probably will, too.

	yours->Set( *name );

	if( charset )
	{
	    base->SetContentCharSetPriv( charset );
	    theirs->SetContentCharSetPriv( charset );
	    yours->SetContentCharSetPriv( charset );
	    result->SetContentCharSetPriv( charset );
	}

	base->MakeLocalTemp( name->Text() );
	theirs->MakeLocalTemp( name->Text() );
	result->MakeLocalTemp( name->Text() );

	base->Open( FOM_WRITE, e );

	if( e->Test() )
	    return;

	result->Perms( FPM_RW );
	theirs->Open( FOM_WRITE, e );
	result->Open( FOM_WRITE, e );

	if( cvt )
	{
	    theirs_cvt = cvt->Clone();
	    result_cvt = cvt->Clone();

	    base->Translator( cvt );
	    theirs->Translator( theirs_cvt );
	    result->Translator( result_cvt );
	}

	// And zonk counters for chunks

	chunksYours = 
	chunksTheirs =
	chunksConflict =
	chunksBoth = 0;

	oldBits = 0;
	markersInFile = 0;
	needNl = 0;
}

void
ClientMerge3::Write( StrPtr *buf, StrPtr *bits, Error *e )
{
	Marker3 marker = MarkerOriginal;

	int b = bits ? bits->Atoi() : 0;

	if( oldBits && oldBits != b )
	{
	    switch( b )
	    {
	    case SEL_BASE|SEL_CONF:
		++chunksConflict;

	    default:
	    case SEL_BASE:
	    case SEL_BASE|SEL_LEG1:
	    case SEL_BASE|SEL_LEG2:
		marker = MarkerOriginal;
		break;

	    case SEL_LEG1|SEL_RSLT:
		++chunksTheirs;

	    case SEL_LEG1|SEL_RSLT|SEL_CONF:
		marker = MarkerTheirs;
		break;

	    case SEL_LEG2|SEL_RSLT:
		++chunksYours;

	    case SEL_LEG2|SEL_RSLT|SEL_CONF:
		marker = MarkerYours;
		break;

	    case SEL_LEG1|SEL_LEG2|SEL_RSLT:
		marker = MarkerBoth;
		++chunksBoth;
		break;

	    case SEL_ALL:
		marker = MarkerEnd;
		break;
	    }

	    if( showAll || b & SEL_CONF || b == SEL_ALL && oldBits & SEL_CONF )
	    {
		if( needNl ) result->Write( "\n", 1, e );
		result->Write( &markertab[ marker ], e );
		result->Write( "\n", 1, e );
		++markersInFile;
	    }
	}

	oldBits = b;

	// Just a shortcut - we get back empty buffers as marker placeholders.

	if( !buf->Length() )
	    return;

	// Write to each file, according to the bits.
	// We don't need to write 'yours', because that is what is
	// already on the client.

	// We compute the md5 digest of each file at this point.
	// We'll use that later to provide a default for 'accept'.

	// The extra check in writing result is that we want to write
	// out the original version (the base) for any conflicts.  If
	// a chunk is only in the base, then leg1 and leg2 must be in
	// conflict for that chunk.

	if( b & SEL_BASE )
	{
	    base->Write( buf, e );
	    // no base digest -- can't accept it
	}

	if( b & SEL_LEG1 )
	{
	    theirs->Write( buf, e );
	    theirsMD5->Update( *buf );
	}

	if( b & SEL_LEG2 )
	{
	    // no writing yours -- already there!
	    yoursMD5->Update( *buf );
	}

	if( b & SEL_RSLT )
	{
	    resultMD5->Update( *buf );
	}

	if( ( b & SEL_RSLT ) || showAll || b == ( SEL_BASE | SEL_CONF ) )
	{
	    result->Write( buf, e );
	}

	// If this block didn't end in a linefeed, we may need to add
	// one before putting out the next marker.  This can happen if
	// some yoyo has a conflict on the last line of a file, and that
	// line has no newline.

	needNl = buf->Text()[ buf->Length() - 1 ] != '\n';
}

void
ClientMerge3::Close( Error *e )
{
	base->Close( e );
	theirs->Close( e );
	result->Close( e );

	theirsMD5->Final( theirsDigest );
	yoursMD5->Final( yoursDigest );
	resultMD5->Final( resultDigest );
}

void
ClientMerge3::Chmod( const char *perms, Error *e )
{
	yours->Chmod2( perms, e ); 
}

void
ClientMerge3::SetTheirModTime( StrPtr *modTime )
{
	theirs->ModTime( modTime );
}

MergeStatus
ClientMerge3::AutoResolve( MergeForce force )
{
	/*
	 * Automatic logic: 
	 */

	/* If showing all markers, always merge */
	/* If conflict -- skip or merge (if forced) */
	/* If we have no unique changes, accept theirs */
	/* If they have no unique changes, take ours */
	/* If we both have changes -- merge or skip (if safe). */

	Error	e;
	e.Set( MsgClient::MergeMsg3 ) << chunksYours 
	    			      << chunksTheirs
				      << chunksBoth
				      << chunksConflict;

	ui->Message( &e );

	if( showAll && force == CMF_FORCE )
	    return CMS_EDIT;

	if( chunksConflict )
	    return force == CMF_FORCE ? CMS_EDIT : CMS_SKIP;

	/* Now we know there are no conflicts. */

	if( !chunksYours )
	    return CMS_THEIRS;

	if( !chunksTheirs )
	    return CMS_YOURS;

	// There can be markers in the file without conflicts if
	// showAll (resolve -v) was selected.

	if( markersInFile )
	    return force == CMF_FORCE ? CMS_EDIT : CMS_SKIP;

	/* We both have changes. */

	switch( force )
	{
	case CMF_AUTO:	return CMS_MERGED;
	case CMF_SAFE:	return CMS_SKIP;
	case CMF_FORCE:	return CMS_MERGED;
	}

	/* not reached */

	return CMS_SKIP;
}

MergeStatus
ClientMerge32::AutoResolve( MergeForce force )
{
	/*
	 * It's just a two-way diff, so we accept theirs if forced
	 * to or if there are no differences.
	 */

    	Error	e;

	e.Set( MsgClient::MergeMsg32 ) << chunksTheirs;
	ui->Message( &e );

	/* Hmmm.  showAll for 32?  I don't think so. */
	/* But just in case. */

	if( showAll && force == CMF_FORCE )
	    return CMS_EDIT;

	/* No changes -- better to take theirs */

	if( !chunksTheirs )
	    return CMS_THEIRS;

	/* Some changes */

	switch( force )
	{
	case CMF_AUTO:	return CMS_SKIP;
	case CMF_SAFE:	return CMS_SKIP;
	case CMF_FORCE:	return CMS_THEIRS;
	}

	/* not reached */

	return CMS_SKIP;
}

MergeStatus
ClientMerge3::Resolve( Error *e )
{
	/* If the files are identical, autoaccept theirs */
	/* We prefer theirs over ours, because then integration history */
	/* marks it as a "copy" and we know the files are now identical. */
	/* Note that this silently swallows chunksBoth... */

	/* get autoresolve's suggestion */

	MergeStatus autoStat = AutoResolve( CMF_FORCE );

	/* Iteratively prompt the user for what to do. */

	StrBuf buf;

	for(;;)
	{
	    const char *autoSuggest;
	    int resultEdited = 0;

	    // default action: edit if conflict, else accept suggestion
	    // made by autoResolve.

	    switch( autoStat )
	    {
	    default:		
	    case CMS_SKIP:	autoSuggest = "s" ; break;
	    case CMS_THEIRS:	autoSuggest = "at" ; break;
	    case CMS_YOURS:	autoSuggest = "ay" ; break;
	    case CMS_MERGED:	autoSuggest = "am" ; break;
	    case CMS_EDIT:	autoSuggest = markersInFile ? "e" : "ae"; break;
	    }

	    // Prompt.  If no response, use auto

	    buf.Clear();
	    e->Clear();
	    e->Set( MsgClient::MergePrompt ) << autoSuggest;
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
	    case pair( 'a', 0 ):
		// take suggestion
		// But if merged, check for conflicts.

		if( autoStat != CMS_EDIT )
		    return autoStat;

		// fall through

	    case pair( 'a', 'e' ): 
		// accept edited result
		if( markersInFile )
		{
		    e->Set( MsgClient::ConfirmMarkers );
		    if ( !Verify( e, e ) ) break;
		}
		return CMS_EDIT; 

	    case pair( 'a', 'm' ): 
		// accept result
		if( autoStat == CMS_EDIT ) 
		{
		    e->Set( MsgClient::ConfirmEdit );
		    if ( !Verify( e, e ) ) break;
		}
		return CMS_MERGED; 

	    case pair( 'a', 't' ):
		// accept theirs
		if( chunksYours + chunksConflict )
		{
		    e->Set( MsgClient::Confirm );
		    if ( !Verify( e, e ) ) break;
		}
		return CMS_THEIRS;

	    case pair( 'a', 'y' ): 
		// accept yours 
		return CMS_YOURS;

	    case pair( 'e', 't' ): 
		// edit theirs
		ui->Edit( theirs, e );
		break; 

	    case pair( 'e', 'y' ): 
		// edit yours 
		ui->Edit( yours, e );
		break;

	    case pair( 'e', 0 ):
		// edit the merged result
		// If no markers are left in the file, zero the
		// conflict count.  Once edited, the default becomes
		// to accept the merge.

		ui->Edit( result, e ); 
		resultEdited = 1;
		break;

	    case pair( 'd', 't' ): 
		// diff theirs
		ui->Diff( base, theirs, 1, flags.Text(), e );
		break;

	    case pair( 'd', 'y' ): 
		// diff yours
		ui->Diff( base, yours, 1, flags.Text(), e );
		break;

	    case pair( 'd', 'm' ): 
		// diff merge
		ui->Diff( base, result, 1, flags.Text(), e );
		break;

	    case pair( 'd', 0 ): 
		// diff result
		ui->Diff( yours, result, 1, flags.Text(), e );
		break;

	    case pair( 'm', 0 ):
		// merge
		ui->Merge( base, theirs, yours, result, e );
		resultEdited = 1;
		break;

	    case pair( 's', 0 ):
		// skip
		return CMS_SKIP;

	    case pair( '?', 0 ):
	    case pair( 'h', 0 ):
		// help
		ui->Help( mergeHelp );
		break;

	    default:
		e->Set( MsgClient::BadFlag );
		break;
	    }

	    // If the result was edited, we're going to have to
	    // try to pick a new result.  We have the digest of
	    // yours/theirs/result, so we just compute the digest
	    // of the current result and see which it matches.  
	    // If none match, it's an original edit.

	    if( !e->Test() && resultEdited )
	    {
		autoStat = DetectResolve();

		// Edited result has markers if (a) it
		// isn't theirs/yours/merged, (b) it had markers before,
		// and (c) CheckForMarkers() finds some.

		markersInFile = 
		    markersInFile && 
		    autoStat == CMS_EDIT && 
		    CheckForMarkers( result, e  );

		// If the edited result equals yours, suggest edit instead.
		// In most cases if the user has picked out the yours diff
		// in an editor, they will want to reverse-integrate it.

		if( autoStat == CMS_YOURS )
		    autoStat = CMS_EDIT;
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
ClientMerge3::Select( MergeStatus stat, Error *e )
{
	// Given the automatic or manual selection, now move the proper
	// file into place.  Usually it is already in place.

	switch( stat )
	{
	case CMS_THEIRS:
	    // accept theirs
	    theirs->Chmod( FPM_RW, e );
	    theirs->Rename( yours, e );

	    if( e->Test() )
	        return;

	    // in case the file type has changed, move the filesys objects
	    // around to leave the yours object with a result file type
	    theirs->Set( yours->Name() );
	    delete yours;
	    yours = theirs;
	    theirs = NULL;
	    return;

	case CMS_MERGED:
	case CMS_EDIT:
	    // accept result
	    result->Rename( yours, e );

	    if( e->Test() )
	        return;

	    // in case the file type has changed, move the filesys objects
	    // around to leave the yours object with a result file type
	    result->Set( yours->Name() );
	    delete yours;
	    yours = result;
	    result = NULL;
	    return;

	default:
	    return;
	}

}

int
ClientMerge3::CheckForMarkers( FileSys *f, Error *e ) const
{
	StrBuf l1;

	int markers = 0;

	f->Open( FOM_READ, e );

	if( e->Test() )
	    return 0;

	while( !markers )
	{
	    if( !f->ReadLine( &l1, e ) )
		break;

	    if( !l1.Length() || !strchr( "<>==", l1.Text()[0] ) )
		continue;

	    for( int i = 0; i < MarkerLast; i++ )
		if( l1 == markertab[ i ] )
		    ++markers;
	}

	f->Close( e );

	return markers > 0;
}

int
ClientMerge3::IsAcceptable() const
{
	// For the GUI: no error; we'll assume a missing
	// result will be seen downstream!

	Error e;

	return !markersInFile || !CheckForMarkers( result, &e );
}

MergeStatus
ClientMerge3::DetectResolve() const
{
	StrBuf d;
	Error e[1];
	CharSetCvt *icvt = 0;

	if( result_cvt )
	{
	    icvt = result_cvt->ReverseCvt();
	    result->Translator( icvt );
	}

	// Get & Compare digest of result against various legs
	// Blow off errors -- if we can't get to the result we'll
	// find out sooner or later.

	result->Digest( &d, e );
	delete icvt;

	if( d == theirsDigest ) 	return CMS_THEIRS;
	else if( d == yoursDigest ) 	return CMS_YOURS;
	else if( d == resultDigest ) 	return CMS_MERGED;
	else 				return CMS_EDIT;
}

const StrPtr *
ClientMerge3::GetMergeDigest() const
{
	// If the file has conflicts, do not report merge digest

	if( markersInFile || chunksConflict )
	    return NULL;

	return &resultDigest;
}

const StrPtr *
ClientMerge3::GetYourDigest() const
{
	return &yoursDigest;
}

const StrPtr *
ClientMerge3::GetTheirDigest() const
{
	return &theirsDigest;
}
