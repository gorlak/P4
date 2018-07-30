/*
 * Copyright 1997-2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 *
 * Diff code written by James Strickland, May 1997.
 */

/*
 * This file implements the algorithm described in
 * "An O(ND) Difference Algorithm and Its Variations", Eugene W Myers,
 * Algorithmica (1986) 1: 251-266
 *
 * Most of the notation used in the paper is used here; sequences are numbered
 * 1..N, 1..M, Delta=N-M, furthest reaching D-paths are stored in
 * SymmetricVector types fV and rV, diagonal indices are k.
 *
 * The main deviation in notation is that I use the same indices
 * in calculating the reverse furthest reaching paths as I do for
 * the forward paths.  Thus the k forward diagonal is the k-Delta
 * reverse diagonal.
 *
 * The paper uses the term "snake", which likely originated from the game
 * Snakes & Ladders.  A snake is a diagonal in the edit graph; this corresponds
 * to a common subsequence of the two sequences (i.e. a bunch of contiguous
 * matching lines).  Note that on p263 of the paper a snake is taken to be
 * from (x,y) to (u,v) where x<=u, but p261 states x>=u.  This is confusing
 * at best. :-)  Here, I take snakes to be from (x,y) to (u,v), x<=u.
 *
 * The overall structure of the algorithm is based on divide and conquer;
 * the longest common subsequence (LCS) of the whole is composed of
 * the LCS of the first part plus the "snake in the middle"
 * (found using FindSnake) plus the LCS of the last part.
 *
 * The FindSnake algorithm exhibits the following properties:
 * - the furthest reaching D-path is calculated for incrementing D,
 *   starting at D=0
 * - for each value of D information needs to be stored for
 *   "diagonals" k=-D,..,D in steps of 2
 *   (well, not quite -- from k=mink,..,maxk where mink>=-D and maxk<=D)
 * - the value for a given D and k is based on the value for D-1
 *   and k-1, k+1
 * 
 * Visually:
 *        k =  -3  -2  -1   0   1   2   3
 * D=0                      *
 * D=1                  *   ^   *
 * D=2              *   ^   *   ^   *
 * D=3          *   ^   *   ^   *   ^   *
 * 
 * and so on.  * denotes a value computed at that iteration, ^ a value
 * computed at the previous iteration which is consulted in the calculation
 * of values on either side.
 *
 * Storing the whole table requires O(D^2) space, which is untenable
 * for large D (consider two completely different 100 000 line files!).
 *
 * The algorithm guarantees optimal output (largest "longest common
 * subsequence" (LCS) or shortest edit script) EXCEPT when a heuristic is
 * used to avoid the huge cost of optimal output.  (Remember those two
 * completely different 100 000 line files?  Well, what if I told you there
 * was only one line in common, but I didn't tell you where?  You'd have to
 * make 5 billion comparisons (10^10/2) to find it in the average case.)
 *
 * There may be more than one output which is optimal!
 * Since the three way merge algorithm compares the output of two diffs,
 * it's important that we produce a canonical form of output.  This is
 * done in ApplyForwardBias().
 *
 * For example, to change AbBbC to AbC you can either delete bB or Bb.
 * This corresponds to either matching Ab and C or matching A and bC.
 * If the algorithm chooses A and bC then ApplyForwardBias() will
 * extend A to Ab and shorten bC to C, thus matching Ab and bC, giving
 * the answer "delete Bb" rather than "delete bB".  In practical terms
 * "b" is usually a blank line, but it can in fact be any line
 * or block of lines.
 *
 */

#ifndef DEBUGLEVEL
#define DEBUGLEVEL 0
#endif

#if DEBUGLEVEL > 0
#include <iostream.h>
#endif

#define NEED_TYPES

#include <stdhdrs.h>
#include <error.h>
#include <strbuf.h>
#include <readfile.h>
#include <debug.h>
#include <tunable.h>

#include "diffsp.h"
#include "diffan.h"

#if DEBUGLEVEL > 2
void
SymmetricVector::Dump(LineNo D)
{
	p4debug.printf("index: ");
    LineNo i;
	for(i=-D;i<=D;i+=2)
	    p4debug.printf("%3d ",i);
	p4debug.printf("\nline:  ");
	for(i=-D;i<=D;i+=2) {
	    p4debug.printf("%3d ",this->operator[](i));
	}
	p4debug.printf("\n");
};
#endif

static inline LineNo 
mapxtoy(LineNo x,       
	LineNo diagonal, 
	LineNo originx,
	LineNo originy)
{
	return x-(diagonal+(originx-originy));
}

inline void 
DiffAnalyze::FollowDiagonal(
	LineNo &x,
	LineNo &y,
	LineNo endx,
	LineNo endy)
{
	while( x<endx && y<endy && A->ProbablyEqual(x,B,y) )
	    ++x,++y;
}

inline void 
DiffAnalyze::FollowReverseDiagonal(
	LineNo &x,
	LineNo &y,
	LineNo startx,
	LineNo starty)
{
	while( x>startx && y>starty && A->ProbablyEqual(x-1,B,y-1) )
	    --x,--y;
}

// FindSnake normally returns the middle snake (potentially zero length)
// of the longest common subsequence, but is free to return *any* snake
// (other than a zero length one at endx,endy) if there is a heuristic
// which suggests doing so would be a Good Idea.
//
// The correctness of the algorithm does not depend on the middle snake
// being returned, only the optimality of the output is potentially affected.
//
// Note that this function should not be called with maxD==0.  We could add
// a test here, but the only time maxD should be zero is when one of the inputs
// is zero length, and there's a short-circuit test for that at a higher level.

inline void 
DiffAnalyze::FindSnake(
	Snake &s,
	LineNo startx,
	LineNo starty, 
	LineNo endx,
	LineNo endy)
{
	const LineNo N = endx-startx;
	const LineNo M = endy-starty;
	const LineNo Delta = N - M;

	// note that ==1 wouldn't work (-1%2==-1)
	const int DeltaEven = ((Delta%2)==0); 

#if DEBUGLEVEL > 1
	p4debug.printf("FindSnake(%d,%d,%d,%d)\n",startx,starty,endx,endy);
	if(N<=0||M<=0||maxD<=0) {
            p4debug.printf("N<=0 or M<=0 or maxD<=0 - that's not good!\n"); fflush(stdout);
	    abort();
	}
#endif

	// initialize values for D=0

	fV[0]=s.x=s.u=startx;
	      s.y=s.v=starty;

	// advances s.u,s.v to end of snake
	FollowDiagonal(s.u,s.v,endx,endy); 

	// Heuristic: return immediately with initial prefix

	if(s.u>s.x) {
#if DEBUGLEVEL > 2
	    p4debug.printf("FindSnake returning with initial prefix %d to %d\n",s.x,s.u);
#endif
	    return;
	}

	rV[0]=s.x=s.u=endx;
	      s.y=s.v=endy;
	
	// s.x,s.y set to start of snake
	FollowReverseDiagonal(s.x,s.y,startx,starty); 

	// Heuristic: return immediately with initial suffix

	if(s.u>s.x) {
#if DEBUGLEVEL > 2
	    p4debug.printf("FindSnake returning with initial suffix %d to %d\n",s.x,s.u);
#endif
	    return;
	}

	for(LineNo D=1; D<=maxD; D++) {

	    const LineNo minkF = (D<=M) ? -D : -(2*M-D);
	    const LineNo maxkF = (D<=N) ?  D :   2*N-D;
	    const LineNo minkR = -maxkF;
	    const LineNo maxkR = -minkF;
	    LineNo k;

#if DEBUGLEVEL > 3
	    p4debug.printf("D=%d Forward min,max (%d,%d) Reverse min,max (%d,%d)\n",D,minkF,maxkF,minkR,maxkR);
#endif

	    // search from top left of edit graph ("forward")

	    for(k=minkF;k<=maxkF;k+=2) {

		if(k==minkF || (k!=maxkF && fV[k+1] > fV[k-1] ) )
		    s.x=fV[k+1];   // down in edit graph
		else
		    s.x=fV[k-1]+1; // to the right in edit graph

		// Follow the (possibly 0 length) diagonal in the 
		// edit graph (aka snake)

		s.u=s.x;
		s.v=mapxtoy(s.u,k,startx,starty);

		// advances s.u,s.v to end of snake
		FollowDiagonal(s.u,s.v,endx,endy);

		if( !DeltaEven ) { // Delta odd

		    // check if path overlaps end of furthest reaching 
		    // reverse (D-1)-path

		    const LineNo DR=D-1;
		    const LineNo pminkR = (DR<=N) ? -DR : -(2*N-DR);
		    const LineNo pmaxkR = (DR<=M) ?  DR :   2*M-DR;

#if DEBUGLEVEL > 3
		    p4debug.printf("DR=%d Reverse min,max (%d,%d)\n",DR,pminkR,pmaxkR);
#endif

		    if(k-Delta>=pminkR && k-Delta<=pmaxkR) {
#if DEBUGLEVEL > 3
			p4debug.printf("s.u %d rv[%d] %d\n",s.u,k-Delta,rV[k-Delta]);
#endif
			if( s.u >= rV[k-Delta] ) {
			    // fill in the fields of s which haven't 
			    // already been filled in

			    s.y=mapxtoy(s.x,k,startx,starty);
#if DEBUGLEVEL > 2
			    p4debug.printf("FindSnake returning during forward search (%d,%d) to (%d,%d)\n",s.x,s.y,s.u,s.v);
#endif
			    return; // finished!
			}
		    }
		}

		fV[k]=s.u; // ok, now set it to the end of the snake
	    }

#if DEBUGLEVEL > 2
	    p4debug.printf("Forward D=%d\n",D);
	    fV.Dump(D);
#endif

	    // search from bottom right of edit graph ("reverse")

	    for(k=minkR;k<=maxkR;k+=2) {

		if(k==maxkR || (k!=minkR && rV[k-1] < rV[k+1] ) )
		    s.u=rV[k-1]; // up
		else
		    s.u=rV[k+1]-1; // to the left

		s.x=s.u;
		s.y=mapxtoy(s.x,k,endx,endy);
		FollowReverseDiagonal(s.x,s.y,startx,starty);

		// check if path overlaps end of furthest reaching 
		// forward D-path

		if( DeltaEven ) {

		    if( k+Delta>=minkF && k+Delta<=maxkF ) {
#if DEBUGLEVEL > 3
		      	p4debug.printf("s.x %d fV[%d] %d\n",s.x,k+Delta,fV[k+Delta]);
#endif
		      if( s.x <= fV[k+Delta]) {
			  // fill in the fields of s which haven't 
			  // already been filled in
			  s.v=mapxtoy(s.u,k,endx,endy);
#if DEBUGLEVEL > 2
			    p4debug.printf("FindSnake returning during reverse search (%d,%d) to (%d,%d)\n",s.x,s.y,s.u,s.v);
#endif
			  return; // finished!
		      }
		    }
		}
		rV[k]=s.x; // ok, now set it to the end of the snake
	    }

#if DEBUGLEVEL > 2
	    p4debug.printf("Reverse D=%d\n",D);
	    rV.Dump(D);
#endif
	}

	// we only get to this point if we've failed to make ends meet within 
	// maxD iterations.  Just return the midpoint so that we're sure we're 
	// doing log N rather than N.  If we're fortunate enough to have 
	// stumbled upon a snake in the middle, then extend it to its 
	// maximum length.

	s.x=s.u=startx+(endx-startx)/2;
	s.y=s.v=starty+(endy-starty)/2;

#if DEBUGLEVEL > 2
	p4debug.printf("exceeded maxD midpt (%d,%d)\n",s.x,s.y);
#endif

	FollowReverseDiagonal(s.x,s.y,startx,starty);
	FollowDiagonal(s.u,s.v,endx,endy);

#if DEBUGLEVEL > 2
	p4debug.printf("after extending: (%d,%d) to (%d,%d)\n",s.x,s.y,s.u,s.v);
#endif
}


void 
DiffAnalyze::LCS(
	LineNo startx,
	LineNo starty,
	LineNo endx,
	LineNo endy)
{
	Snake s;
	FindSnake(s,startx,starty,endx,endy); // s is a reference parameter for speed

	if( s.x > startx && s.y > starty) {

#if DEBUGLEVEL > 0
	    p4debug.printf("LCS %d , %d , %d , %d\n",startx,starty,s.x,s.y);
	    if(s.x==endx&&s.y==endy) {
		p4debug.printf("INFINITE RECURSION!\n"); fflush(stdout);
		abort();
	    }
#endif
	    LCS(startx,starty,s.x,s.y);
	}

	if(s.u>s.x) { // snake has nonzero length

#if DEBUGLEVEL > 1
	    int snakes_added=0;
	    p4debug.printf("SNAKE (%d,%d) to (%d,%d)\n",s.x,s.y,s.u,s.v);
#endif
	    // verify actual sequence contents, splitting snake up if there 
	    // are any pairs of lines which are ProbablyEqual() but not Equal()

	    LineNo cx,cy;
	    for(cx=s.x, cy=s.y; cx < s.u ; cx++,cy++) {

		for(s.x=cx,s.y=cy;cx<s.u && A->Equal(cx,B,cy); cx++,cy++)
		    ;

		if(cx>s.x) { // nonzero length snake to add
		    Snake *toadd = new Snake;

		    toadd->next=0;
		    toadd->x=s.x; toadd->y=s.y;
		    toadd->u=cx;  toadd->v=cy;

#if DEBUGLEVEL > 1
		    snakes_added++;
		    p4debug.printf("Adding snake (%d,%d) to (%d,%d)\n",toadd->x,toadd->y,toadd->u,toadd->v);
#endif

		    // add snake to end of linked list

		    if(FirstSnake) { 
			// already found first one
			LastSnake->next=toadd;
			LastSnake=toadd;
		    } else {
			FirstSnake=LastSnake=toadd;
		    }
		}
	    }
#if DEBUGLEVEL > 1
	    if(snakes_added==0)
		p4debug.printf("SNAKE WAS COMPLETELY BOGUS!!!\n");
	    if(snakes_added>1)
		p4debug.printf("Snake was broken into %d parts!\n",snakes_added);
#endif
	}

	if( endx > s.u && endy > s.v) {

#if DEBUGLEVEL > 0
	  p4debug.printf("LCS %d , %d , %d , %d\n",s.u,s.v,endx,endy);
	  if(s.u==startx&&s.v==starty) {
	      p4debug.printf("INFINITE RECURSION!\n");
	      abort();
	  }
#endif

	  LCS(s.u,s.v,endx,endy);
      }
}

/*
 * DiffAnalyze::BracketSnake() - put on leading and trailing Snakes
 */

void
DiffAnalyze::BracketSnake()
{
	Snake *s; 

	// If the first snake doesn't include the first lines of
	// both files, make a "null" snake for the beginning.
	// Note that if there is no snake (files completely unmatched)
	// we'll add a start snake anyhow.

	s = FirstSnake;

	if( !s || s->x || s->y )
	{
	    Snake *toadd = new Snake;

	    toadd->x = toadd->u =
	    toadd->y = toadd->v = 0;
	    toadd->next = s;

	    if( !s ) 
		LastSnake = toadd;

	    FirstSnake = toadd;
	}

	// If the last snake doesn't include the last lines of
	// both files, make a "null" snake for the end.
	// If we added a start snake for completely unmatched files
	// above, then we'll only wind up adding a tailing snake
	// if the files are not both empty.

	s = LastSnake;

	if( s->u < A->Lines() || s->v < B->Lines() )
	{
	    Snake *toadd = new Snake;

	    toadd->x = toadd->u = A->Lines();
	    toadd->y = toadd->v = B->Lines();
	    toadd->next = 0;

	    s->next = toadd;
	    LastSnake = toadd;
	}
}


void
DiffAnalyze::ApplyForwardBias()
{
	Snake *s,*next; 
	LineNo endx = A->Lines();
	LineNo endy = B->Lines();

	// Traverse the list of snakes, extending any which can be extended.
	// If the current snake extends into the next snake, then that snake
	// is shortened.  If the second snake is totally consumed then it is
	// removed.

	for( s = FirstSnake, next = s->next; next; s = next, next = next->next ) 
	{
	    while( s->u < endx && s->v < endy && A->Equal(s->u,B,s->v) ) 
	    {
	        // start stretching current chunk

	        ++s->u, ++s->v;

	        // if we are in an adjacent chunk then start compacting it

	        if( s->u > next->x || s->v > next->y )
	        {

	            ++next->x, ++next->y;

	            // if its totally consumed remove it (unless its the last).

	            if( next->x == next->u && next != LastSnake ) 
	            {
	                // handle special case of snake completely eating up the
	                // next snake - but don't delete the last snake!

	                s->next = next->next;
	                delete next;
	                next = s->next;
	            }
	        }
	    }
	}
}

DiffAnalyze::DiffAnalyze(
	Sequence *fromFile,
	Sequence *toFile,
	int fastMaxD )
{
	A = fromFile;
	B = toFile;

	// Calculate a limit on the amount of searching FindSnake does, so as to have
	// a reasonable upper bound on compute time (and space, although that's less relevant;
	// it's only 2*maxD elements of length LineNo, i.e. typically 8*maxD bytes).
	// FindSnake does a two-sided search, -D to +D, hence the variable name maxD
	// and its default value of half the sum of the number of lines in the two files.
	// With that value maxD does not limit the search in FindSnake.
	// If this value is beyond what results in a "reasonable" compute time
	// on modern hardware, then maxD is adjusted downwards, trading off potentially
	// poorer diff output for a reasonable running time.  The way to determine
	// the constants used here is to determine the compute time given the
	// worst case inputs, which are two files which are completely different.

	// maxD calculation change
	//
	// This new calculation reduces maxD for bigger files.
	//
	// Added sLimit:
	//
	// "sLimit" is used to control the value of maxD so that as avgLines 
	// becomes large maxD begins to tail off (reducing search time).
	// For RCS files we need maxD to tail off more rapidly as its important
	// that submit/checkin happens as quick as possible.
	//
	// An upper limit of 50000 lines of code has also been factored in to
	// cause maxD to significantly reduce the searching that FindSnake
	// will do.

	LineNo avgLines = (A->Lines() + B->Lines())/2;

	const int sThresh = p4tunable.Get( P4TUNE_DIFF_STHRESH );
	const int sLimit1 = p4tunable.Get( P4TUNE_DIFF_SLIMIT1 );
	const int sLimit2 = p4tunable.Get( P4TUNE_DIFF_SLIMIT2 );

	const int sLimit = 
		(!fastMaxD && avgLines < sThresh) 
		? sLimit2 : sLimit1;

	maxD = sLimit / (avgLines ? avgLines : 1);

	if( maxD > avgLines )
	    maxD = avgLines;

	if( maxD < 42 )
	    maxD = 42;

	// fV and rV are shared by all invocations of FindSnake()
	// This is required in order for the algorithm to take O(D) space
	// rather than O(D^2).  (See Myers p264.)  Thus we just make fV and 
	// rV large enough to handle the worst case, then leave 'em alone.

	fV.Resize( maxD );
	rV.Resize( maxD );

	FirstSnake=LastSnake=0;

#if DEBUGLEVEL > 0
	p4debug.printf("N %d M %d maxD %d\n",A->Lines(),B->Lines(),maxD);
#endif

	// find the longest common subsequence - note that there will
	// never be a common subsequence if one of the files is empty,
	// so don't call LCS in this case (this is not just an optimization,
	// this is necessary for correctness!)

	if(A->Lines() > 0 && B->Lines() > 0)
	    LCS(0, 0, A->Lines(), B->Lines());

	// Free vectors now that we will not need them anymore
	fV.Resize( 0 );
	rV.Resize( 0 );

	// Ensure there's a snake at the beginning by adding a zero-length
	// snake if necessary - this makes life easier for the code
	// which processes the list of snakes.  It also is used by
	// ApplyForwardBias()
	BracketSnake();

	// Select optimal output which is of a canonical form so that
	// the 3 way merge algorithm, which compares diff outputs,
	// does not see any bogus conflicts.
	// The term "forward bias" is intended to mean that given a choice
	// between two optimal outputs the result will be the one which
	// you would find by a forward search, rather than a reverse search.
	ApplyForwardBias();
}

DiffAnalyze::~DiffAnalyze()
{
	while( FirstSnake ) {
	    Snake *next = FirstSnake->next;
	    delete FirstSnake;
	    FirstSnake = next;
	}
}
