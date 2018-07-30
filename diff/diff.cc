/*
 * Copyright 1997 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 *
 * Diff code written by James Strickland, May 1997.
 */

/*
 * Diff output generators.
 */

#define NEED_TYPES
#define NEED_SLEEP
#define NEED_FILE

#include <stdhdrs.h>
#include <error.h>
#include <strbuf.h>
#include <readfile.h>
#include <filesys.h>
#include <charset.h>
#include <i18napi.h>
#include <charcvt.h>

#include "diffsp.h"
#include "diffan.h"
#include "diff.h"

// NT CRLF handling -- out output files are raw (binary) because our
// input files were raw (according to ReadFile).  So we have to handle
// the proper CR when we print our lines.

Diff::Diff()
{
	out = 0;
	spx = 0;
	spy = 0;
	diff = 0;
	flags = 0;
	lineType = LineTypeRaw;
	closeOut = 0;
	fastMaxD = 0;
	chunkCnt = 0;

# ifdef USE_CRLF
	newLines = "\r\n";
# else
	newLines = "\n";
# endif
}

Diff::~Diff()
{
	delete diff;
	delete spx;
	delete spy;
	if( closeOut ) fclose( out );
}



void
Diff::DiffUnifiedDeleteFile( FileSys *f, Error *e )
{
    StrBuf buf;

    int lineCount = 0;
    while( f->ReadLine( &buf, e ) )
        lineCount++;

    // ignore errors when diffing deleted files.
    if( e->Test() )
    {
        e->Clear();
        return;
    } 

    f->Seek( 0, e );
    fprintf( out, "@@ -1,%d +1,0 @@\n", lineCount );

    while( f->ReadLine( &buf, e ) )
        fprintf( out, "-%s\n", buf.Text() );

}
  

void
Diff::SetInput( FileSys *fx, FileSys *fy, const DiffFlags &flags, Error *e )
{
	// diff -h does it by word; see DiffWithFlags below.

	spx = new Sequence( fx, flags, e );
	this->flags = &flags;
	if( !e->Test() )
	    spy = new Sequence( fy, flags, e );

	if( e->Test() )
	    return;

	diff = new DiffAnalyze( spx, spy, fastMaxD );
}

void
Diff::SetOutput( const char *fout, Error *e )
{
	// NT CRLF handling: raw writes

#ifdef OS_NT
	// XXX Hate to have Windows specific code here but there is
	// no easy fix short of using FileSys here...
	if( CharSetApi::isUnicode((CharSetApi::CharSet)GlobalCharSet::Get()) )
	{
	    CharSetCvtUTF816 cvt;
	    int newlen = 0;

	    const char *wname = cvt.FastCvt( fout, strlen( fout ), &newlen );

	    if( newlen > ( MAX_PATH * 2 ) )
	    {
		SetLastError( ERROR_BUFFER_OVERFLOW );
		goto errorout;
	    }

	    if( cvt.LastErr() == CharSetCvt::NONE &&
		( out = _wfopen( (const wchar_t *)wname, L"wb" ) ) )
	        goto done;
	}
#endif
	// If wfopen() fails, we intentionally fall through.
	if( !( out = fopen( fout, "wb" ) ) )
	{
#ifdef OS_NT
	errorout:
#endif
	    e->Sys( "write", fout );
	    return;
	}
#ifdef OS_NT
done:
#endif

#ifdef OS_NT
	SetHandleInformation( (HANDLE)_get_osfhandle( fileno(out) ), 
		HANDLE_FLAG_INHERIT, 0 );
#endif

	closeOut = 1;
}

void
Diff::SetOutput( FILE *fout )
{
	out = fout;
	lineType = LineTypeLocal;
	newLines = "\n";
}

void
Diff::CloseOutput( Error *e )
{
	// If SetInput never opened a file, CloseOutput won't
	// touch it.  Normally, that means 'out' is stdout, but
	// if not, caveat caller.

	if( !closeOut )
	    return;

	// Flush and check for output error.
	// Don't stack this error against others.

	if( fflush( out ) < 0 || ferror( out ) )
	    if( !e->Test() )
		e->Sys( "write", "diff" );

	fclose( out );
	closeOut = 0;
}

void
Diff::Walker(
	const char *flags,
	Sequence *sp,
	LineNo sx, LineNo ex )
{
	sp->SeekLine( sx );

	bool lineEnd = true;

	for( ; sx < ex; ++sx ) {
	    fputs( flags, out );
	    lineEnd = sp->Dump( out, sx, sx + 1, lineType );
	}

	if( lineEnd == false && this->flags->type == DiffFlags::Unified ) 
	    fprintf(out, "\n\\ No newline at end of file\n" );
}

void
Diff::DiffWithFlags( const DiffFlags &flags )
{
	// allow 'c' and 'u' (as well as 'C' and 'U') to take a count.
	// if it breaks, it defaults to 0 (which is then treated as 3).

	switch( flags.type )
	{
	case DiffFlags::Normal:	 DiffNorm(); break;
	case DiffFlags::Context: DiffContext( flags.contextCount ); break;
	case DiffFlags::Unified: DiffUnified( flags.contextCount ); break;
	case DiffFlags::Summary: DiffSummary(); break;
	case DiffFlags::HTML: 	 DiffHTML(); break;
	case DiffFlags::Rcs:	 DiffRcs(); break;
	}
}

void		
Diff::DiffNorm()
{
	Snake *s = diff->GetSnake();
	Snake *t;

	for( ; t = s->next; s = t )
	{
	    /* Print edit operator */

	    char c;
	    LineNo nx = s->u, ny = s->v;

	    if( s->u < t->x && s->v < t->y )	c = 'c', ++nx, ++ny;
	    else if( s->u < t->x ) 		c = 'd', ++nx;
	    else if( s->v < t->y ) 		c = 'a', ++ny;
	    else				continue;

				    	fprintf( out, "%d", nx );
	    if( t->x > nx )		fprintf( out, ",%d", t->x );
				    	fprintf( out, "%c%d", c, ny );
	    if( t->y > ny )		fprintf( out, ",%d", t->y );
	    				fprintf( out, "%s", newLines );

	    /* Line lines that differ */

	    Walker( "< ", spx, s->u, t->x );

	    if( c == 'c' ) 		fprintf( out, "---%s", newLines );

	    Walker( "> ", spy, s->v, t->y );
	}
}

void
Diff::DiffRcs()
{
	Snake *s = diff->GetSnake();
	Snake *t;

	for( ; t = s->next; s = t )
	{
	    if( s->u < t->x )
	    {
		fprintf( out, "d%d %d%s", s->u + 1, t->x - s->u, newLines );
		chunkCnt++;
	    }
	    if( s->v < t->y )
	    {
		fprintf( out, "a%d %d%s", t->x, t->y - s->v, newLines );
		chunkCnt++;
		spy->SeekLine( s->v );
		spy->Dump( out, s->v, t->y, lineType );
	    }
	}
}

void
Diff::DiffHTML()
{
	Snake *s = diff->GetSnake();
	Snake *t;

	for( ; t = s->next; s = t )
	{
	    // Dump the common stuff

	    spx->SeekLine( s->x );
	    spy->SeekLine( s->v );
	    spx->Dump( out, s->x, s->u, lineType );

	    // Dump spx

	    fprintf( out, "<font color=red>" );
	    spx->Dump( out, s->u, t->x, lineType );

	    // dump spy

	    fprintf( out, "</font><font color=blue>" );
	    spy->Dump( out, s->v, t->y, lineType );

	    // Done

	    fprintf( out, "</font>" );
	}
}

/*
 * DiffUnified
 */

void
Diff::DiffUnified( int c )
{
	// s,t bound the diffs being displayed.
	// First we move t forward until the snake is bigger than
	// 2 * CONTEXT, then we display [s,t], then iterate for [t,...].

	// Remember: a snake is a matching chunk.  Diffs are inbetween
	// snakes, before the first snake, or after the last snake.

	if( c < 0 ) c = 3;
	Snake *s = diff->GetSnake();
	Snake *t;

	while( t = s->next )
	{
	    // Look for snake > 2 * CONTEXT

	    while( t->next && t->x + 2 * c >= t->u )
		t = t->next;

	    // Compute first/last lines of diff block

	    LineNo sx = s->u - c > 0 ? s->u - c : 0;
	    LineNo sy = s->v - c > 0 ? s->v - c : 0;
	    LineNo ex = t->x + c < spx->Lines() ? t->x + c : spx->Lines();
	    LineNo ey = t->y + c < spy->Lines() ? t->y + c : spy->Lines();

	    // Display [s,t]

	    fprintf( out, "@@ -%d,%d +%d,%d @@%s",
		 sx+1, ex-sx, sy+1, ey-sy, newLines );

	    // Now walk the snake between s,t, displaying the diffs

	    do
	    {
		LineNo nx = s->u;
		LineNo ny = s->v;

		Walker( " ", spx, sx, nx );

		s = s->next;
		sx = s->x;
		sy = s->y;

		Walker( "-", spx, nx, sx );
		Walker( "+", spy, ny, sy );
	    }
	    while( s != t );

	    // Display the tail of the chunk

	    Walker( " ", spx, sx, ex );
	}
}

/*
 * DiffContext
 */

void
Diff::DiffContext( int c )
{
	// s,t bound the diffs being displayed.
	// First we move t forward until the snake is bigger than
	// 2 * CONTEXT, then we display [s,t], then iterate for [t,...].

	// Remember: a snake is a matching chunk.  Diffs are inbetween
	// snakes, before the first snake, or after the last snake.

	if( c < 0 ) c = 3;
	Snake *s = diff->GetSnake();
	Snake *t;

	for( ; t = s->next; s = t )
	{
	    // Look for snake > 2 * CONTEXT

	    while( t->next && t->x + 2 * c >= t->u )
		t = t->next;

	    // Compute first/last lines of diff block

	    LineNo sx = s->u - c > 0 ? s->u - c : 0;
	    LineNo sy = s->v - c > 0 ? s->v - c : 0;
	    LineNo ex = t->x + c < spx->Lines() ? t->x + c : spx->Lines();
	    LineNo ey = t->y + c < spy->Lines() ? t->y + c : spy->Lines();

	    // Display [s,t]

	    fprintf( out, "***************%s", newLines );

	    // File 1

	    fprintf( out, "*** %d,%d ****%s", sx+1, ex, newLines );

	    // Now walk the snake between s,t, displaying the diffs

	    Snake *ss, *tt;

	    for( ss = s; ss != t; ss = tt )
	    {
		tt = ss->next;

		if( ss->u < tt->x )
		{
		    Walker( "  ", spx, sx, ss->u );
		    const char *mark = ss->v < tt->y ? "! " : "- ";
		    Walker( mark, spx, ss->u, tt->x );
		    sx = tt->x;
		}
	    }

	    if( s->u < sx )
		Walker( "  ", spx, sx, ex );

	    // File 2

	    fprintf( out, "--- %d,%d ----%s", sy+1, ey, newLines );

	    // Now walk the snake between s,t, displaying the diffs

	    for( ss = s; ss != t; ss = tt )
	    {
		tt = ss->next;

		if( ss->v < tt->y )
		{
		    Walker( "  ", spy, sy, ss->v );
		    const char *mark = ss->u < tt->x ? "! " : "+ ";
		    Walker( mark, spy, ss->v, tt->y );
		    sy = tt->y;
		}
	    }

	    if( s->v < sy )
		Walker( "  ", spy, sy, ey );
	}
}

/*
 * DiffSummary
 */

void
Diff::DiffSummary()
{
	Snake *s = diff->GetSnake();
	Snake *t;

	LineNo l_deleted = 0;
	LineNo l_added = 0;
	LineNo l_edited_in = 0;
	LineNo l_edited_out = 0;

	LineNo c_deleted = 0;
	LineNo c_added = 0;
	LineNo c_edited = 0;

	for( ; t = s->next; s = t )
	{
	    /* Print edit operator */

	    if( s->u < t->x && s->v < t->y ) 
	    {
		l_edited_in += (t->x - s->u);
		l_edited_out += (t->y - s->v);
		++c_edited;
	    } 
	    else if (s->v < t->y) 
	    {
	    	l_added += (t->y - s->v);
		++c_added;
	    } 
	    else if( s->u < t->x )
	    {
	    	l_deleted += (t->x - s->u);
		++c_deleted;
	    }
	}

	fprintf( out, 
		"add %d chunks %d lines\n"
		"deleted %d chunks %d lines\n"
		"changed %d chunks %d / %d lines\n",
			c_added, l_added,
			c_deleted, l_deleted,
			c_edited, l_edited_in, l_edited_out );
}
