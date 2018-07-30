/*
 * Copyright 2002 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * MultiMerge - merge a bunch of files and return a merged list
 */

# include <stdhdrs.h>
# include <error.h>
# include <errorlog.h>
# include <strbuf.h>
# include <filesys.h>
# include <debug.h>

# include <readfile.h>
# include <diffsp.h>
# include "diffan.h"
# include "diff.h"
# include "diffmulti.h"

/*
 * MergeSequence -- FileSys, (diff) Sequence, and id
 *
 * MergeSequence just holds diff Sequence and its FileSys together,
 * along with a revision number for identification.
 *
 * Note that ~MergeSequence() deletes both the FileSys and Sequence.
 */

struct MergeSequence {

		MergeSequence() { s = 0; f = 0; }
		~MergeSequence() { delete s; delete f; }

	FileSys		*f;
	Sequence	*s;
	int		revId;
	int		chgId;

} ;

/*
 * MergeLine::AddLines() - insert new lines into a MergeLine chain
 *
 * Inserts into the chain at the point of *p lines x thru y of sequence f.
 * (i.e. inserts between p and *p).
 *
 * p points to the previous entry's 'next' pointer for easy manipulation,
 * and is left pointing to the 'next' pointer of the last entry added.
 *
 * All lines are marked with lowerRev = upperRev = current rev.
 */

MergeLine **
MergeLine::AddLines(
	MergeLine **p,
	MergeSequence *f,
	MultiMerge *m,
	LineNo x,
	LineNo y )
{
	// Seek once, then copy all lines

	f->s->SeekLine( x );

	// From x to y

	while( x < y )
	{
	    MergeLine *c = new MergeLine;

	    // Get line text.
	    // XXX LineTypeRaw?
	    // XXX Impose junky limit on lines

	    LineLen l = f->s->Length( x );
	    int xtrunc = 0;

	    if( l > 10000 )
	    {
		l = 10000;
	        xtrunc = x + 1;
	    }

	    f->s->CopyLines( x, x + 1, c->buf.Alloc( l ), l, LineTypeRaw );

	    if( xtrunc )
	    {
	        // terminate line
	        c->buf.Extend('\n');
	        c->buf.Terminate();

	        // position on next line
	        f->s->SeekLine( xtrunc );
	        x = xtrunc;
	    }

	    // New lines have this MergeSequence's revId

	    c->lowerRev = 
	    c->upperRev = f->revId;

	    c->lowerChg =
	    c->upperChg = f->chgId;

	    c->from = 0;
	    c->merge = m;

	    // Dance to insert between p and *p, moving p up

	    c->next = *p;
	    *p = c;
	    p = &c->next;
	}

	// Return last entry's 'next'

	return p;
}

/*
 * MergeLines::MarkLines() - mark current lines in chain with last rev seen
 *
 * For lines at the rev of the previous file, mark them with the given
 * rev.  We ignore lines whose rev is less than the rev of the previous
 * file, as they didn't participate in the diff we're now merging.
 */

MergeLine **
MergeLine::MarkLines( MergeLine **p, LineNo count, 
		      int prevRev, int nextRev, int prevChg, int nextChg )
{
	for( ; count; p = &(*p)->next )
	    if( (*p)->upperChg == prevChg )
	{
	    (*p)->upperRev = nextRev;
	    (*p)->upperChg = nextChg;
	    --count;
	}

	return p;
}

/*
 * MultiMerge::MultiMerge() - minimal initialization
 */

MultiMerge::MultiMerge( StrPtr *diffFlags )
	: flags( diffFlags )
{
	fx = 0;
	chain = 0;
	reader = 0;
	index = 0;
}

/*
 * MultiMerge::~MultiMerge() - zonk MergeLine chain and leftover MergeSequence
 */

MultiMerge::~MultiMerge()
{
	delete fx;

	// Delete what's left of the chain

	while( chain )
	{
	    MergeLine *next = chain->next;
	    delete chain;
	    chain = next;
	}
}

/*
 * MultiMerge::Add() - add another file for delta display
 */

void
MultiMerge::Add( FileSys *f, int revId, int chgId, Error *e )
{
	// Make next sequence.  We need a pair for diffing.

	MergeSequence *fy = new MergeSequence;

	// We use chgId for sorting because it's useful across branches,
	// but spec depots don't have changes, so fake it with revId.

	if ( chgId < 1 )
	    chgId = revId;

	fy->f = f;
	fy->s = new Sequence( fy->f, flags, e );
	fy->revId = revId;
	fy->chgId = chgId;

	if( e->Test() )
	{
	    delete fy;
	    return;
	}

	// If we don't have a previous sequence, 
	// we'll just add this one wholesale.

	if( !fx )
	{
	    fx = fy;
	    MergeLine::AddLines( &chain, fx, this, 0, fx->s->Lines() );
	    reader = chain;
	    return;
	}

	// Create the diff between last and current sequence,
	// and walk the snake, merging the new sequence with the chain.

	DiffAnalyze *diff = new DiffAnalyze( fx->s, fy->s );
	Snake *s = diff->GetSnake();
	Snake *t;

	// We walk with *p, so that we can update the
	// head (chain) or next easily.

	MergeLine **p = &chain;

	for( ; t = s->next; s = t )
	{
	    // I'm sure you forgot:

	    // s->x -> s->u common lines in fx leading to next diff
	    // s->y -> s->v common lines in fy leading to next diff
	    // s->u -> t->x lines unique to fx
	    // s->v -> t->y lines unique to fy

	    // Mark old lines s->x -> s->u as current (new revId)
	    // Mark old lines s->u -> t->x as no longer current (old revId)
	    // Insert fy's lines s->v -> t->y as current

	    p = MergeLine::MarkLines( p, s->u - s->x, 
		    fx->revId, fy->revId, fx->chgId, fy->chgId );
	    p = MergeLine::MarkLines( p, t->x - s->u, 
		    fx->revId, fx->revId, fx->chgId, fx->chgId );
	    p = MergeLine::AddLines( p, fy, this, s->v, t->y );
	}

	// Mark (last) lines s->x -> s->u as current.

	MergeLine::MarkLines( p, s->u - s->x, 
	    fx->revId, fy->revId, fx->chgId, fy->chgId );

	// Done diffing fx & fy.
	// So fy becomes fx for the next round.

	delete diff;
	delete fx;
	fx = fy;

	// For Read()
	// Gets set many times, but so what.

	reader = chain;
}

/*
 * MultiMerge::Dump() - dump MergeLine chain for debugging
 */

void
MultiMerge::Dump()
{
	MergeLine *c;

	for( c = chain; c; c = c->next )
	{
	    c->buf.Terminate();
	    p4debug.printf("%d->%d %s", c->lowerRev, c->upperRev, c->buf.Text() );
	}
}

/*
 * MultiMerge::Read() - extra the merged result, a line at a time
 */

MergeLine *
MultiMerge::Read( int &lower, int &upper, int &change, StrPtr &string, int chg )
{
	if( !reader )
	    return 0;

	// For deep annotate, get lower from earliest integ source.
	// If no deep annotate, from is 0, so this is harmless.

	MergeLine *source = reader;
	while ( source->from )
	    source = source->from;

	// Need the change number to blame contributor

	change = source->lowerChg;

	if ( chg )
	{
	    lower = source->lowerChg;
	    upper = reader->upperChg;
	}
	else
	{
	    lower = source->lowerRev;
	    upper = reader->upperRev;
	}
	string = reader->buf;

	MergeLine *r = reader;

	reader = reader->next;

	return r;
}

# if 0

// sample use

main( int argc, char *argv[] )
{
	argc--, argv++;

	MultiMerge dd;
	int revId = 0;
	Error e;

	while( argc-- )
	{
	    FileSys *f = FileSys::Create( FST_BINARY );
	    f->Set( *argv++ );
	    ++revId;
	    dd.Add( f, revId, revId, &e );
	}

	AssertLog.Abort( &e );

	dd.Dump();

	return 0;
}

# endif
