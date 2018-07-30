/*
 * Copyright 2010 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

 /*
  * Implementation of MultiMultiMerge.
  *
  */

# include <stdhdrs.h>
# include <error.h>
# include <errorlog.h>
# include <strbuf.h>
# include <filesys.h>
# include <debug.h>
# include <vararray.h>

# include <readfile.h>
# include "diffsp.h"
# include "diffan.h"
# include "diff.h"
# include "diffmulti.h"

# include "diffmultimulti.h"

/*
 *   FileMultiMerge - FileSys that lets Diff read a MultiMerge's contents.
 */

class FileMultiMerge : public FileSys
{
    public:

		FileMultiMerge( MultiMerge *m, int rev );

	// FileSys methods needed by ReadFile

	int	Read( char *buf, int len, Error *e );
	void	Open( FileOpenMode mode, Error *e );
	offL_t	GetSize();
	void	Seek( offL_t offset, Error * );

	// FileSys stubs

	void	Close( Error *e ) {};
	void	Write( const char *buf, int len, Error *e ) {};
	int	Stat() { return FSF_EXISTS; }
	int	StatModTime() { return 0; }
	void	Truncate( Error *e ) {};
	void	Truncate( offL_t offset, Error *e ) {};
	void	Unlink( Error *e = 0 ) {};
	void	Rename( FileSys *target, Error *e ) {};
	void	Chmod( FilePerm perms, Error *e ) {};
	void	ChmodTime( Error *e ) {};

	// InRev returns same line if in rev, or next line in rev.

	MergeLine*	InRev( MergeLine* line );

    private:

	MultiMerge	*m;
	int		rev;

	MergeLine	*line;
	int		offset;
};

struct MMEntry
{
	StrBuf id;
	MultiMerge* m;
};

/*
 *   MultiMultiMerge - a collection of MultiMerges.
 *
 */

MultiMultiMerge::MultiMultiMerge( StrPtr* diffFlags )
{
	multiMerges = new VarArray;
	flags.Init( diffFlags );
}

MultiMultiMerge::~MultiMultiMerge()
{
	MMEntry *m;
	for ( int i = 0 ; i < multiMerges->Count() ; i++ )
	{
	    m = (MMEntry *)multiMerges->Get( i );
	    delete m->m;
	    delete m;
	}
	delete multiMerges;
}

void
MultiMultiMerge::Put( const StrPtr &id, MultiMerge *merge )
{
	merge->index = multiMerges->Count();

	MMEntry *m = new MMEntry;
	m->id = id;
	m->m  = merge;
	multiMerges->Put( m );
}

MultiMerge*
MultiMultiMerge::Get( const StrPtr &id )
{
	MMEntry *m;
	for ( int i = 0 ; i < multiMerges->Count() ; i++ )
	{
	    m = (MMEntry *)multiMerges->Get( i );
	    if ( m->id == id )
	       return m->m;
	}
	return 0;
}

MultiMerge*
MultiMultiMerge::Get( int i )
{
	return ((MMEntry *)multiMerges->Get( i ))->m;
}

const StrPtr&
MultiMultiMerge::IdOf( MergeLine *line )
{
	return ((MMEntry *)multiMerges->Get( line->merge->index ))->id;
}

/*
 * MultiMultiMerge::Credit() - This is where the magic happens.  We get
 *	the source and target revs, diff them, and connect them up at
 *	points where it seems likely that the target line came from the
 *	source originally.
 */

void
MultiMultiMerge::Credit( const StrPtr& fromId, int sRev, int eRev,
			 const StrPtr& toId, int tRev, Error *e )
{
	// Set up the diff.

	MultiMerge* srcM = Get( fromId );
	MultiMerge* tgtM = Get( toId );
	if ( !srcM || !tgtM )
	    return;

	FileMultiMerge srcF( srcM, eRev );
	FileMultiMerge tgtF( tgtM, tRev );
	Sequence srcS( &srcF, flags, e );
	Sequence tgtS( &tgtF, flags, e );
	if ( e->Test() )
	    return;

	DiffAnalyze diff( &srcS, &tgtS );

	// Get ready to walk through the two files.  Note that
	// the first line is number 0, and that we're
	// careful to only count lines that exist in the rev,
	// since those are the lines that the diff has seen.

	MergeLine *srcL = srcF.InRev( srcM->FirstLine() );
	MergeLine *tgtL = tgtF.InRev( tgtM->FirstLine() );
	int srcN = 0;
	int tgtN = 0;
	Snake *s;

	// s->x = start of source common chunk
	// s->y = start of target common chunk
	// s->u = end of source common chunk + 1
	// s->v = end of target common chunk + 1

	for ( s = diff.GetSnake() ; s ; s = s->next )
	{
	   // Line source and target up with beginning of snake.
	   
	   while ( srcL && srcN < s->x )
	   {
		srcL = srcF.InRev( srcL->next );
		srcN++;
	   }
	   while ( tgtL && tgtN < s->y )
	   {
		tgtL = tgtF.InRev( tgtL->next );
		tgtN++;
	   }
	   if ( !srcL || !tgtL ) // this should never happen
	       return; 

	   // Walk though the snake and match up lines.

	   while ( srcL && tgtL && srcN < s->u )
	   {
		// Only match lines that were introduced at/after sRev.
	        // If they were introduced into the source at some point
		// outside of the credit range, they probably came into
	        // the target via some other means.
		   
		// Only set the "from" if it gives us a lower lowerChg.
	        // We're trying to find the "original" (oldest) source.
	        // This also guarantees against introducing cycles.

		if ( srcL->lowerRev >= sRev &&
		     tgtL->lowerChg > srcL->lowerChg &&
		     !(tgtL->from && tgtL->from->lowerChg < srcL->lowerChg) )
		    tgtL->from = srcL;  // It's good!  Match it up.

		// Move to the next line.

		srcL = srcF.InRev( srcL->next );
		tgtL = tgtF.InRev( tgtL->next );
		srcN++;
		tgtN++;
	   }

	   // We're now past that snake and pointed at the beginning of
	   // the next difference (or at the EOF).  On to the next.
	}
}

void
MultiMultiMerge::Dump()
{
	MMEntry *m;
	for ( int i = 0 ; i < multiMerges->Count() ; i++ )
	{
	    m = (MMEntry *)multiMerges->Get( i );
	    printf( "\n%s\n", m->id.Text() );
	    m->m->Dump();
	}
}

FileMultiMerge::FileMultiMerge( MultiMerge *m, int rev )
{
	this->m   = m;
	this->rev = rev;
	line = 0;
	offset = 0;
}

void
FileMultiMerge::Open( FileOpenMode mode, Error *e )
{
	if ( mode == FOM_WRITE )
	    e->Set( E_FATAL, "can't write to a FileMultiMerge!" );

	line = InRev( m->FirstLine() );
	offset = 0;
}

int
FileMultiMerge::Read( char *buf, int len, Error * )
{
	int read = 0;
	for ( ;; )
	{
	    if ( !line ) // end of file
		return read;

	    if ( line->buf.Length() == offset )
	    {
		// Done with this line, move on to the next.
		
		offset = 0;
		line = InRev( line->next );
		continue;
	    }

	    if ( len - read <= line->buf.Length() - offset )
	    {
		// This line has enough to finish our read.

	        memcpy( buf + read, line->buf.Value() + offset, len - read );
		offset += ( len - read );
		return len;
	    }

	    // Finish out this line and advance.

	    memcpy( buf + read, line->buf.Value()  + offset, 
				line->buf.Length() - offset );
	    read += line->buf.Length() - offset;
	    offset = 0;
	    line = InRev( line->next );
	}
}

offL_t
FileMultiMerge::GetSize()
{
	offL_t size = 0;

	for ( MergeLine* L = m->FirstLine() ; L ; L = InRev( L->next ) )
	     size += L->buf.Length();

	return size;
}

void
FileMultiMerge::Seek( offL_t off, Error * )
{
	line = InRev( m->FirstLine() );
	while( line && line->buf.Length() <= off )
	{
	    off -= line->buf.Length();
	    line = InRev( line->next );
	}

	offset = off;
}

MergeLine*
FileMultiMerge::InRev( MergeLine* L )
{
	for ( ; L ; L = L->next )
	{
	    if ( L->lowerRev > rev || L->upperRev < rev )
	        continue;
	    return L;
	}
	return 0;
}
