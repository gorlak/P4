/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsco.c - combine revisions to produce an output file
 *
 * Classes defined:
 *
 *	RcsCkout - control block for a checkout
 *
 * Public methods:
 *
 *	RcsCkout::RcsCkOut() - set up for checkout
 *	RcsCkout::~RcsCkout() - finish and dispose of an RcsCkout
 *	RcsCkout::Ckout() - build up the piece table for given rev
 *	RcsCkout::Read() - read text from a revision recreated by Ckout()
 *
 * Private methods:
 *
 *	RcsCkout::ApplyExit() - apply a revision's worth of diffs
 *
 * Internal classes/structures:
 *
 * 	RcsEdit - a single add or delete block from a diff
 * 	RcsPiece - a piece of an RcsEdit
 *
 * Internal routines:
 *
 *	RcsPieceSplit() - split an entry in piece table 
 *	RcsPiecePosition() - move currPtr to point to piece to be edited
 *	RcsPieceInsert() - make an insertion edit before the current piece
 *	RcsPieceDelete() - make a deletion edit at the current piece
 *
 *	RcsEditSkip() - read and toss whole lines from file
 * 	RcsAtStrip() - turn @@'s into @'s, handling @@ split across calls
 *
 * Description:
 *
 *	This module takes an RcsArchive and a revision number, and manifests
 *	the revision as a stream that can be read in arbitrary amounts.
 *
 *	This module does not do keyword expansion.  It does elide the quoted,
 *	double @ signs from the RCS file.
 *
 * Sample usage:
 *
 *	RcsCkout *co = new RcsCkout( archive );
 *	char buf[ 1024 ];
 *	int l;
 *
 *	co = co->Ckout( revName, errorStruct );
 *
 *	while( ( l = co->Read( buf, sizeof( buf ) ) ) != 0 ) 
 *		fwrite( stdout, 1, buf, l );
 *
 *	delete co;
 *
 * History:
 *	2-18-97 (seiwald) - translated to C++.
 */

# define NEED_TYPES

# include <stdhdrs.h>
# include <ctype.h>

# include <error.h>
# include <debug.h>
# include <tunable.h>
# include <strbuf.h>
# include <readfile.h>

# include "rcsdebug.h"
# include "rcsarch.h"
# include "rcsrev.h"
# include "rcsco.h"
# include <msglbr.h>

/*
 * RcsEdit - a single add or delete block from a diff
 *
 * Each RCS revision, other than the head, is stored as a delta.  Each
 * delta is the output of a "diff -n" command, which contains one or more
 * edits.  Each edit is either a "d" delete line or an "a" add line,
 * followed by the text to be added.  An RcsEdit points to the text 
 * lines of an "a" edit.
 *
 * The head revision is treated like an "a" edit of all the lines of
 * the revision.
 */

struct RcsEdit
{
	struct RcsEdit *chain;	/* just for freeing */
	RcsChunk	chunk;		/* actual location of edit text */
	RcsChunk	readChunk;	/* chunk copy eaten by RcsCkoutRead */
	RcsLine		readLineOffset;	/* # lines between chunk & readChunk */

} ;

/*
 * RcsPiece - a piece of an RcsEdit
 *
 * To describe a current revision you'd like to be able to string together
 * all the RcsEdits that contributed lines to that revision.  Unfortunately,
 * add and deletes can occur in the middle of the lines added in a single
 * edit, and so we instead string together the active pieces of RcsEdits.  
 * Each RcsPiece points back to the original RcsEdit, and says what subset 
 * of the lines in that edit are still active.
 */

struct RcsPiece
{
	struct RcsPiece *chain;
	RcsLine		lineOffset;	/* offset into chunk - 0 base */
	RcsLine		lineCount;	/* bogusly big == whole edit */
	RcsEdit		*edit;

} ;

/*
 * Piece table routines.
 */

/*
 * RcsPieceSplit() - split an entry in piece table 
 *
 * We need to make an edit (add or delete a piece) in the middle of
 * and old piece.  We always make our inserts between pieces and our
 * deletions from the head of a piece, so we split the old piece in
 * two.  The part we are not interested in is the "split", which
 * the currPtr moves past.  The part we are interested in lives on
 * as the "piece".
 *
 * Both the split piece and the original point to the same "chunk":
 * that is, the same piece of the RCS file that contains the lines
 * to be added.  The pieces differ in their lineOffset and lineCount
 * values: the two new pieces point to their respective shares of the
 * old piece's lines.
 *
 * ***
 *
 * Ok, General, why the three stars on currPtr?
 *
 * We actually reference three things with this:
 *
 *	We reference and update the contents of the current piece
 *	via piece->xxx (which is (**currPtr)->xxx.
 *
 *	The pointer to the current piece is actually kept as the
 *	previous piece's next pointer.  If we insert a new piece, 
 *	we have to update that previous piece's next pointer
 *	by setting **currPtr.
 *
 *	As we sweep past pieces in search of the currLineNumber,
 *	we note our progress by updating the caller's pointer
 *	to the previous piece's next pointer.  That's *currPtr.
 */

static void
RcsPieceSplit(
	RcsPiece ***currPtr,
	RcsLine *currLineNumber,
	RcsLine splitCount,
	Error *e )
{
	RcsPiece *piece = **currPtr;
	RcsPiece *split = new RcsPiece;

	/* split piece contains first half */

	split->chain = piece;
	split->edit = piece->edit;
	split->lineOffset = piece->lineOffset;
	split->lineCount = splitCount;
	**currPtr = split;

	/* old piece contains second half */

	piece->lineOffset += split->lineCount;
	piece->lineCount -= split->lineCount;

	if( DEBUG_EDIT_FINE )
	    p4debug.printf( "split moved lineOffset to %d by %d\n", 
			piece->lineOffset, split->lineCount );

	/* advance past the split piece */

	*currLineNumber += split->lineCount;
	*currPtr = &split->chain;

	if( DEBUG_EDIT_FINE )
	    p4debug.printf( "split skipped to line %d\n", *currLineNumber );
}


/*
 * RcsPiecePosition() - move currPtr to point to piece to be edited
 *
 * We need to make an edit, so we scan down the piece list, moving
 * currPtr, until we find the piece that contains the first line
 * affected by the edit.  If the first line affected is in the middle
 * of a piece, we split that piece up.
 */

static void
RcsPiecePosition(
	RcsPiece ***currPtr,
	RcsLine *currLineNumber,
	RcsLine editLineNumber, 
	Error *e )
{
	RcsPiece *piece = **currPtr;
	RcsLine splitCount;

	/* Advance until we find the piece that contains editLineNumber. */
	/* We assume that it is this piece or after. */

	if( editLineNumber < *currLineNumber )
	{
	    e->Set( MsgLbr::Edit0 );
	    return;
	}

	while( piece && editLineNumber >= *currLineNumber + piece->lineCount )
	{
	    *currLineNumber += piece->lineCount;
	    *currPtr = &piece->chain;
	    piece = piece->chain;
	}

	if( DEBUG_EDIT_FINE )
	    p4debug.printf( "advance skipped to line %d\n", *currLineNumber );

	/* If the new piece starts in the middle of the old, we have */
	/* to split off the front of the old. */

	if( ( splitCount = editLineNumber - *currLineNumber ) > 0 )
	    RcsPieceSplit( currPtr, currLineNumber, splitCount, e );
}

/*
 * RcsPieceInsert() - make an insertion edit before the current piece
 *
 * This handles the diff 'aX Y' edits: add lines.  Since we are already
 * positioned before the first line affected, we just insert our new
 * piece.
 */

static void
RcsPieceInsert(
	RcsPiece ***currPtr,
	RcsLine *currLineNumber,
	RcsLine editLineCount,
	RcsEdit *edit,
	Error *e )
{
	RcsPiece *newPiece = new RcsPiece;

	newPiece->lineOffset = 0;
	newPiece->lineCount = editLineCount;
	newPiece->edit = edit;

	/* Now we just insert the newPiece before piece */

	newPiece->chain = **currPtr;
	**currPtr = newPiece;

	/* Advance past the new piece */

	*currPtr = &newPiece->chain;
}

/*
 * RcsPieceDelete() - make a deletion edit at the current piece
 *
 * This handles the diff 'dX Y' edits: delete lines.  We are already
 * positioned at the first line affected, so we delete (and free)
 * whole pieces as necessary to delete lines, and then, if the lines
 * to be deleted end in the middle of a piece, delete the lines from
 * the beginning of that piece.  We do that simply by adjusting the
 * piece's lineOffset and lineCount, which say where in the chunk 
 * are the piece's lines.
 */

static void
RcsPieceDelete( 
	RcsPiece ***currPtr,
	RcsLine *currLineNumber,
	RcsLine editLineCount,
	Error *e )
{
	RcsPiece *piece = **currPtr;

	/* Delete any pieces that are wholly deleted by this edit. */

	while( piece && editLineCount >= piece->lineCount )
	{
	    /* Point past the curr piece */

	    **currPtr = piece->chain;
	    *currLineNumber += piece->lineCount;
	    editLineCount -= piece->lineCount;

	    if( DEBUG_EDIT_FINE )
		p4debug.printf( "delete skipped to line %d\n", *currLineNumber );

	    delete piece;

	    piece = **currPtr;
	}

	/* The edit may delete the initial part of the remaining piece. */

	if( editLineCount )
	{
	    if( !piece )
	    {
		e->Set( MsgLbr::Edit1 );
		return;
	    }

	    piece->lineOffset += editLineCount;
	    piece->lineCount -= editLineCount;
	    *currLineNumber += editLineCount;

	    if( DEBUG_EDIT_FINE )
		p4debug.printf( "delete skipped to line %d\n", *currLineNumber );
	}
}

/*
 * Edit routines.
 */

/*
 * RcsEditSkip() - read and toss whole lines from file
 *
 * A piece, originally pointing to a whole chunk (which is itself
 * a pointer to an edit in the RCS file), may wind up pointing to only
 * part of a chunk.  This can happen after a piece is split or if part
 * of it is deleted by an edit.  RcsSkipEdit is used to skip to the first
 * requested line in a chunk after seeking to that chunk in the file.
 */

static RcsSize
RcsEditSkip(
	ReadFile *rf,
	RcsLine lines,
	RcsSize length )
{
	RcsSize l = length;

	while( lines-- && l > 0 )
	{
	    /* If we hit a newline, soak it up, too */
	    /* XXX Memchr() takes int, not RcsSize */

	    if( l -= rf->Memchr( '\n', l ) )
		--l, rf->Next();
	}

	return length - l;
}

/*
 * RcsCkout::ApplyEdit() - given an RcsCkout, apply a revision's worth of diffs
 *
 * Once an RcsCkout has been created, it contains the head revision in
 * one big piece.  That RcsCkout can be made to contain previous reivions
 * by applying the diffs that bring the head back to that revision. 
 * RcsEditApply() applies one revision's diffs to the current RcsCkout.
 *
 * Bad things can happen if the wrong diff is applied.
 */

void
RcsCkout::ApplyEdit(
	RcsRev *rev,
	Error *e )
{
	RcsSize chunkOffset;
	RcsPiece **piecePtr;
	RcsLine lineNumber;

	/* Position file for scanning text */

	if( DEBUG_EDIT )
	    p4debug.printf( "applying edit for %s: %lld bytes at %lld\n",
			rev->revName.text, rev->text.length, rev->text.offset );

	if( !rev->text.file )
	{
	    e->Set( MsgLbr::NoRev3 ) << rev->revName.text;
	    return;
	}

	rev->text.file->Seek( rev->text.offset );

	/* Initialize sweep. */

	lineNumber = 1;
	piecePtr = &pieces;

	/* As long as there is something left in this revision... */

	for( chunkOffset = 0; chunkOffset < rev->text.length; )
	{
	    RcsLine editLineNumber;
	    RcsLine editLineCount;
	    char editAction;
	    char line[ 64 ], *p;
	    RcsEdit *edit;
	    int l;

	    /* Get the action line */

	    l = rev->text.file->Memccpy( line, '\n', sizeof( line ) - 1 );
	    line[ l ] = '\0';
	    chunkOffset += l;

	    editAction = line[0];
	    editLineNumber = 0;
	    editLineCount = 0;

	    for( p = line + 1; isdigit( *p ); p++ )
		editLineNumber = editLineNumber * 10 + *p - '0';

	    if( *p == ' ' )
		p++;

	    for( ; isdigit( *p ); p++ )
		editLineCount = editLineCount * 10 + *p - '0';

	    if( DEBUG_EDIT_FINE )
		p4debug.printf( "action %c%d,%d curlin %d\n",
		    editAction,editLineNumber,
		    editLineNumber+editLineCount-1,
		    lineNumber );

	    /* Skip any lines of text. */

	    if( editAction == 'a' )
	    {
		edit = new RcsEdit;

		/* add means add after; we mean before */

		editLineNumber++;	

		/* Point new edit at the insertion lines from file */

		edit->chunk.file = rev->text.file;
		edit->chunk.offset = rev->text.offset + chunkOffset;
		edit->chunk.atWork = rev->text.atWork;
		edit->chunk.length = RcsEditSkip( 
				rev->text.file,
				editLineCount,
				rev->text.length - chunkOffset );

		/* Initialize readChunk for RcsCkout::Read() */

		edit->readChunk = edit->chunk;
		edit->readLineOffset = 0;

		/* Chain edits so they can be freed */

		edit->chain = edits;
		edits = edit;

		chunkOffset += edit->chunk.length;
	    }

	    /* Advance throught the pieces list until we find the piece */
	    /* with our editLineNumber.  Split that piece, if necessary, */
	    /* to make piecePtr point to the insertion/deletion position. */

	    RcsPiecePosition( &piecePtr, &lineNumber, editLineNumber, e );

	    if( e->Test() )
		return;

	    /* Now insert/delete the new piece. */

	    switch( editAction )
	    {
	    case 'a':
		RcsPieceInsert( &piecePtr, &lineNumber, editLineCount, 
					edit, e );
		break;

	    case 'd':
		RcsPieceDelete( &piecePtr, &lineNumber, editLineCount, e );
		break;
	    
	    default:
		e->Set( MsgLbr::Edit2 ) << line;
		return;
	    }

	    if( e->Test() )
		return;
	}
}

/*
 * RcsAtStrip() - turn @@'s into @'s, handling @@ split across calls
 */

static int
RcsAtStrip(
	char *buf,
	char *atIn,
	int len,
	int *halfAt )
{
	char *atOut = atIn;

	*halfAt = 0;

	for(;;)
	{
	    char *a, *src;
	    int llen;

	    /* We now point to the 2nd @ - the first one has already */
	    /* been copied.  If we're at the end of the string, we'll */
	    /* have to save our 2nd @ processing for the next round. */

	    if( buf + len <= atOut )
	    {
		*halfAt = 1;
		break;
	    }

	    ++atIn;	/* hope that 2nd char is an @ */
	    --len;

	    // replace a call to:
	    // a = (char *)memccpy( atOut, atIn, '@', buf + len - atOut );
	    llen = buf + len - atOut;
	    src = atIn;
	    a = atOut;
	    bool foundat = false;
	    while( llen-- > 0 )
	        if( ( *a++ = *src++ ) == '@' )
	        {
	            foundat = true;
	            break;
	        }

	    if( !foundat )
	        break;

	    atIn += a - atOut;
	    atOut = a;
	}

	return len;
}

/*
 * External routines.
 */

/*
 * RcsCkout() - create an RcsCkout for a particular revision
 *
 * RcsCkout() calls RcsEditPut() to create an RcsCkout with
 * the head revision, and then, following the "next" link info 
 * associated with each revision, applies diffs with RcsEditApply()
 * until the RcsCkout reflects the desired revision.
 *
 * The result can be read with RcsCkout::Read().
 */

RcsCkout::RcsCkout(
	RcsArchive *archive )
{
	this->archive = archive;
	this->pieces = 0;
	this->edits = 0;
}

/*
 * RcsCkout::~RcsCkout() - Free stuff allocated with Ckout()
 */

RcsCkout::~RcsCkout()
{
	/* Free the pieces */

	for( RcsPiece *piece = pieces; piece; )
	{
	    RcsPiece *next = piece->chain;
	    delete piece;
	    piece = next;
	}

	/* Free the chunks */

	for( RcsEdit *chunk = edits; chunk; )
	{
	    RcsEdit *next = chunk->chain;
	    delete chunk;
	    chunk = next;
	}
}

/*
 * RcsCkout::Ckout() - build up the piece table for given rev
 *
 * This creates a single piece for the head rev, and then applies all
 * the edits for the various revs that lead from the head rev to the
 * desired rev.  The result is a big chain of pieces that Read() can
 * string together.
 */

void
RcsCkout::Ckout(
	const char *revName,
	Error *e )
{
	RcsRev *rev;
	RcsPiece **piecesp;
	RcsEdit *edit;
	RcsLine lineNumber;

	const RcsLine maxInsert = p4tunable.Get( P4TUNE_RCS_MAXINSERT );

	/* 
	 * Create the initial edit for the head rev contents.
	 */

	if( !( rev = archive->FindRevision( archive->headRev.text, e ) ) )
	    goto fail;

	if( !rev->text.file )
	{
	    e->Set( MsgLbr::NoRev3 ) << rev->revName.text;
	    goto fail;
	}

	/* Create first edit chunk */

	edit = new RcsEdit;

	edit->chunk = rev->text;
	edit->readChunk = rev->text;
	edit->readLineOffset = 0;
	edit->chain = 0;
	edits = edit;

	lineNumber = 1;
	piecesp = &pieces;

	/*
	 * This will cap the co/sync to 1 billion lines.  It used
	 * to be 10,000,00 then 50,000,000 but with support for files
	 * beyond 2GB these limits were short-sighted.
	 */

	RcsPieceInsert( &piecesp, &lineNumber, maxInsert - 1, edit, e );

	if( e->Test() )
	    goto fail;

	/*
	 * Now step through the revs, all the way to the desired one,
	 * editing in the pieces.
	 */

	/* Default revName to headRev's */

	revName = revName ? revName : archive->headRev.text;

	while( strcmp( rev->revName.text, revName ) )
	{
	    if( !( rev = archive->FollowRevision( rev, revName, e ) ) )
		goto fail;

	    ApplyEdit( rev, e );

	    if( e->Test() )
		goto fail;
	}

	/* Prepare for RcsCkout::Read's scan */

	readPiece = pieces;
	readPieceCount = 0;
	halfAt = 0;

	return;

    fail:
	/* Add our own message. */

	e->Set( MsgLbr::Checkout ) << revName;
}

/*
 * RcsCkout::Read() - read text from a revision recreated by Ckout()
 *
 * Read() reads a block of text from the revision recreated by
 * Ckout().  It allows any block size to be provided.
 *
 * Returns the number of bytes read.  Returns 0 when edit is finished.
 */

int
RcsCkout::Read( 
	char *buf,
	int length )
{
	char *oldBuf = buf;

	while( readPiece && length )
	{
	    RcsPiece 	*piece = readPiece;
	    RcsEdit 	*edit = piece->edit;

	    if( DEBUG_EDIT_FINE )
		p4debug.printf( "piece lines %d,%d now %d; chunk %lld,+%lld\n",
			piece->lineOffset,
			piece->lineOffset + piece->lineCount,
			edit->readLineOffset,
			edit->readChunk.offset,
			edit->readChunk.length );

	    /* Position ourselves for reading: seek to the beginning of the */
	    /* chunk and then skip the number of lines necessary to reach */
	    /* the desired line in the chunk.  We only do this if we have */
	    /* not been left in position by a previous RcsCkout::Read(). */

	    if( !readPieceCount )
	    {
		RcsLine linesToSkip = piece->lineOffset - edit->readLineOffset;
		RcsSize bytesSkipped;

		edit->readChunk.file->Seek( edit->readChunk.offset );

		bytesSkipped = RcsEditSkip( 
				edit->readChunk.file, 
				linesToSkip, 
				edit->readChunk.length );

		edit->readChunk.offset += bytesSkipped;
		edit->readChunk.length -= bytesSkipped;
		edit->readLineOffset += linesToSkip;
	    }

	    /* Now fill the users buffer with the number of lines in piece, */
	    /* minus any whole lines already read by RcsCkout::Read(). */
	    /* We have to check readChunk.length too because the last */
	    /* piece->lineCount has a bogus high value. */

	    while( length && edit->readChunk.length &&
		readPieceCount < piece->lineCount )
	    {
		int l = length;  // bytesRead

		if( l > edit->readChunk.length )
		    l = edit->readChunk.length;

		l = edit->readChunk.file->Memccpy( buf, '\n', l );

		/* Consume the source chunk */

		edit->readChunk.offset += l;
		edit->readChunk.length -= l;

# ifdef USE_CRLF
		/* NT CRLF -> LF translation: if we read a whole line */
		/* ending in a CR/LF we'll turns the CR to an LF and drop */
		/* the bytesRead count one. */

		if( l > 1 &&
		    buf[ l - 1 ] == '\n' && 
		    buf[ l - 2 ] == '\r' )
		{
		    --l;
		    buf[ l - 1 ] = '\n';
		}

		/* If this buffer ended in CR, it's because we ran out */
		/* of room or hit eof (weird!).  We peek ahead and see */
		/* if the next character is a LF.  If so, we replace */
		/* the CR with LF and consume the LF in the input. */
	
		else if( buf[ l - 1 ] == '\r' && 
		    !edit->readChunk.file->Eof() &&
		    edit->readChunk.file->Char() == '\n' )
		{
		    edit->readChunk.offset++;
		    edit->readChunk.length--;
		    edit->readChunk.file->Next();
		    buf[ l - 1 ] = '\n';
		}
# endif

		/* Bump line counts if we read a whole one. */

		if( buf[ l - 1 ] == '\n' )
		{
		    ++readPieceCount;
		    ++edit->readLineOffset;
		}

		/* RCS files doubled @s to quote them.  If this chunk */
		/* came from an RCS file, we'll need to elide any @@'s. */
		/* This may diminish 'bytesRead'. */

		if( edit->readChunk.atWork == RCS_CHUNK_ATDOUBLE )
		{
		    char *atIn;

		    if( halfAt )
			l = RcsAtStrip( buf, buf, l, &halfAt );

		    else if( atIn = (char *)memchr( buf, '@', l ) )
			l = RcsAtStrip( buf, atIn + 1, l, &halfAt );
		}

		/* Consume the dest buf. */

		length -= l;
		buf += l;
	    }

	    /* More space in buffer - move to next piece in chain. */

	    if( length )
	    {
		readPiece = piece->chain;
		readPieceCount = 0;
	    }
	}

	return buf - oldBuf;
}
