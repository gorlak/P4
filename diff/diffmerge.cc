/*
 * Copyright 1995, 2007 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * diffmerge.cc - 3 way file merge
 *
 * Classes defined:
 *
 *	DiffMerge - control block for merging
 *
 * Public methods:
 *
 *	DiffMerge::DiffMerge() - Merge 3 files to produce integrated result
 *	DiffMerge::~DiffMerge() - dispose of DiffMerge and its contents
 *	DiffMerge::Read() - produce next part of integrated result
 *
 * Internal classes:
 *
 *	DiffFfile - line oriented ReadFile
 *	DiffDFile - a diff stream
 *
 * Private methods:
 *
 *	DiffDFile::DiffDFile() - start a diff(1) between the base and one leg
 *
 * History:
 *	2-18-97 (seiwald) - translated to C++.
 */

# define NEED_TYPES
# define NEED_FILE

# include <stdhdrs.h>

# include <error.h>
# include <debug.h>
# include <strbuf.h>
# include <filesys.h>

# include <readfile.h>

# include <diff.h>
# include <diffsp.h>
# include <diffan.h>
# include <diffmerge.h>

# define DEBUG_MERGE ( p4debug.GetLevel( DT_DIFF ) >= 3 )

/*
 * selbitTab - how to output each leg given the next pair of diffs
 *
 * DiffLeg represents the leg we're looking to output, and DiffDiffs
 * is how DiffDiff() said the next pair of diffs merged. 
 */

enum DiffLeg { DL_BASE, DL_LEG1, DL_LEG2, DL_LAST } ;

const int selbitTab[ DL_LAST ][ DD_LAST ] = {

/* BASE	at */ 	/* EOF */	0,		
		/* LEG1	*/	SEL_BASE|SEL_LEG2,	// base == leg2
		/* LEG2	*/	SEL_BASE|SEL_LEG1,	// base == leg1
		/* BOTH	*/	SEL_BASE,	
		/* CONF	*/	SEL_BASE|SEL_CONF,	
		/* ALL */	SEL_ALL,

/* LEG1	at */ 	/* EOF */	0,		
		/* LEG1	*/	SEL_LEG1|SEL_RSLT,
		/* LEG2	*/	0,			
		/* BOTH	*/	SEL_LEG1|SEL_LEG2|SEL_RSLT, // leg1 == leg2
		/* CONF	*/	SEL_LEG1|SEL_RSLT|SEL_CONF, // leg1 != leg2
		/* ALL */	0,

/* LEG2 at */ 	/* EOF */	0,
		/* LEG1	*/	0,
		/* LEG2	*/	SEL_LEG2|SEL_RSLT,
		/* BOTH	*/	0,			// == leg1
		/* CONF	*/	SEL_LEG2|SEL_RSLT|SEL_CONF, // leg1 != leg2
		/* ALL */	0,

};

/* 
 * MergeState - state for Read()'s state machine
 */

enum MergeState {
	MS_DIFFDIFF,	/* do diff diff */
	MS_BASE,	/* dumping the original */
	MS_LEG1,	/* dumping leg1 */
	MS_LEG2,	/* dumping leg2 */
	MS_DONE		/* return 0 */
} ;

/*
 * DiffDFile::DiffDFile() - popen(3) a diff(1) between the base and one leg
 */

inline LineNo dmin( LineNo a, LineNo b )  { return a < b ? a : b; }

/*
 * DiffFfile - line oriented ReadFile
 */

class DiffFfile : public Sequence { 

    public:
			DiffFfile( 
			    FileSys *file,
			    const DiffFlags &flags,
			    LineType lt,
			    Error *e ) 
			    : Sequence( file, flags, e )
			{ 
			    lineType = lt;
			    end = 0;
			}

    	LineLen  	MaxLineLength() const;

	LineType	lineType;

	/* Track our progress for output */

	LineNo		start;	/* first line to output */
	LineNo		end;	/* last line, and sync point */

} ;

/*
 * DiffDFile - a diff stream
 */

class DiffDFile : public DiffAnalyze {

    public:
			DiffDFile( DiffFfile *base, DiffFfile *leg )
			: DiffAnalyze( base, leg ) 
			{ 
				this->base = base;
				this->leg = leg;
				s = *GetSnake(); 
			}

	LineNo		StartLeg() { return s.y - leg->end; }
	LineNo		StartBase() { return s.x - base->end; }
	LineNo		EndLeg() { return s.v - leg->end; }
	LineNo		EndBase() { return s.u - base->end; }

	// alias the above for the leg1 leg2 snake ONLY

	LineNo		StartL1() { return StartBase(); }
	LineNo		StartL2() { return StartLeg(); }
	LineNo		EndL1() { return EndBase(); }
	LineNo		EndL2() { return EndLeg(); }

	void		AdvanceAndSync();

    public:

	Snake		s;		/* snake of differences */

    private:

	DiffFfile	*base;	/* for StartBase()/EndBase() */
	DiffFfile	*leg;	/* for StartLeg()/EndLeg() */

} ;

void
DiffDFile::AdvanceAndSync()
{
	// Advance

	while( s.next && ( EndLeg() <= 0 || EndBase() <= 0 ) ) 
	    s = *s.next;

	// Sync up to starting point

	LineNo adj = dmin( StartLeg(), StartBase() );
	if( adj < 0 ) { s.y += -adj; s.x += -adj; }
}

void
SnakeDump( const char *t, Snake *s )
{
	p4debug.printf( "snake %s\n", t );

	while( s )
	{
	    p4debug.printf("s %x %d %d %d %d\n", s, s->x, s->u, s->y, s->v );
	    s = s->next;
	}
}

/*
 * DiffMerge::DiffMerge() - Merge 3 files to produce integrated result
 */

DiffMerge::DiffMerge( 
	FileSys *base,
	FileSys *leg1,
	FileSys *leg2,
	const DiffFlags &flags,
	LineType lineType,
	Error *e )
{
	readFile = 0;
	emptyFile = 0;
	bf = lf1 = lf2 = 0;
	df1 = df2 = df3 = 0;
	diff3behavior = 0;
	oldMode = 0;
	
	switch( flags.grid )
	{
	case DiffFlags::Optimal:
	    gridType = GRT_OPTIMAL;
	    break;
	case DiffFlags::GuardedDiff3:
	    diff3behavior = 1;
	case DiffFlags::Guarded:
	    gridType = GRT_GUARDED;
	    break;
	case DiffFlags::Diff3:
	    diff3behavior = 1;
	    break;
	case DiffFlags::TwoWay:
	    gridType = GRT_TWOWAY;
	    emptyFile = FileSys::Create( FST_EMPTY );
	    break;
	}

	state = MS_DIFFDIFF;

	if( DEBUG_MERGE )
	    p4debug.printf( "merging %s x %s x %s\n", base->Name(),
	        leg1->Name(), leg2->Name() );

	/*
	**  Open the three input files.
	*/

	bf = new DiffFfile( emptyFile ? emptyFile : base, flags, lineType, e );
	lf1 = new DiffFfile( leg1, flags, lineType, e );
	lf2 = new DiffFfile( leg2, flags, lineType, e );

	if( e->Test() )
	    return;

	/*
	**  Fork off the two diffs, between the base and l1, and between
	**  base and l2.  Prime the diff file structures by reading the
	**  first two diffs.
	*/

	df1 = new DiffDFile( bf, lf1 );
	df2 = new DiffDFile( bf, lf2 );
	df3 = new DiffDFile( lf1, lf2 );

	if( DEBUG_MERGE )
	{
	    SnakeDump( "df1", &df1->s );
	    SnakeDump( "df2", &df2->s );
	    SnakeDump( "df3", &df3->s );
	}
}

/*
 * DiffMerge::~DiffMerge() - dispose of DiffMerge and its contents
 */

DiffMerge::~DiffMerge()
{
	delete bf;
	delete lf1;
	delete lf2;

	delete df1;
	delete df2;
	delete df3;

	delete emptyFile;
}

/*
 * DiffMerge::Read() - produce next part of integrated result
 */

int
DiffMerge::Read( char *buf, int len, int *outlen )
{
	for(;;)
	{
	    /*
	     * If readFile is set, we're still returning output from
	     * one of the file legs.  Keep doing so until the user's
	     * buffer is satisfied, or we've output this chunk.
	     */

	    if( readFile )
	    {
		*outlen = readFile->CopyLines( 
		    readFile->start, 
		    readFile->end,
		    buf, len, 
		    readFile->lineType );

		if( !*outlen )
		    readFile = 0;

		return selbits;
	    }

	    switch( state )
	    {
	    case MS_DIFFDIFF:	

		/* do diff diff */

		if( ( diffDiff = DiffDiff() ) == DD_EOF )
		{
		    state = MS_DONE;
		    break;
		}

	        if( diffDiff != DD_ALL)
		{
		    *outlen = 0;
		    state = MS_BASE;
		    return SEL_ALL;
		}

	    case MS_BASE:		/* dumping the original */

		if( selbits = selbitTab[ DL_BASE ][ diffDiff ] )
		{
		    readFile = bf;
		    readFile->SeekLine( bf->start );
		    state = MS_LEG1;
		    break;
		}

	    case MS_LEG1:		/* dumping leg1 */

		if( selbits = selbitTab[ DL_LEG1 ][ diffDiff ] )
		{
		    readFile = lf1;
		    readFile->SeekLine( lf1->start );
		    state = MS_LEG2;
		    break;
		}

	    case MS_LEG2:		/* dumping leg2 */

		if( selbits = selbitTab[ DL_LEG2 ][ diffDiff ] )
		{
		    readFile = lf2;
		    readFile->SeekLine( lf2->start );
		}

		state = MS_DIFFDIFF;
		break;

	    case MS_DONE:		/* return 0 */

		*outlen = 0;
		return 0;
	    }
	}
}

/*
 * DiffMerge::BitNames() - turn out mnemonic(?) names for the flags
 */

const char *
DiffMerge::BitNames( int bits )
{
	switch( bits )
	{
	case SEL_ALL:			return "ALL";
	case SEL_BASE:			return "BASE";
	case SEL_BASE|SEL_CONF:		return "BASE CONFLICT";
	case SEL_BASE|SEL_LEG1:		return "BASE L1";
	case SEL_BASE|SEL_LEG2:		return "BASE L2";
	case SEL_LEG1|SEL_RSLT|SEL_CONF:return "L1 CONFLICT";
	case SEL_LEG2|SEL_RSLT|SEL_CONF:return "L2 CONFLICT";
	case SEL_LEG1|SEL_RSLT:		return "L1";
	case SEL_LEG2|SEL_RSLT:		return "L2";
	case SEL_LEG1|SEL_LEG2|SEL_RSLT:return "L1 L2";
	default:			return "?";
	}
}

/*
 * DiffMerge::MaxLineLength() - find the maximum length of a line in any file
 */

LineLen 
DiffMerge::MaxLineLength() const
{
	LineLen l, m = bf->MaxLineLength();

	if( ( l = lf1->MaxLineLength() ) > m ) m = l;
	if( ( l = lf2->MaxLineLength() ) > m ) m = l;

	return m;
}

/*
 * DiffFfile::MaxLineLength() - find the maximum length of a line
 */

LineLen 
DiffFfile::MaxLineLength() const
{
	LineLen m = 0;

	for( LineNo l = 0; l < Lines(); l++ )
	    if( m < Length( l ) )
		 m = Length( l );

	return  m;
}

enum Mode {
	ALL, ALL1, ALL2, 
	BOTH, BOTHX, 
	BOTHX1, BOTHX2, CONF,
	DEL1, DEL2,
	DELB, DELB1, DELB2,
	EDIT1, EDIT2,
	EDITC1, EDITC2,
	INSX1, INSX2,
	INSX3, INSX4,
	INSY1, INSY2,
	INS12, INSX12, INSY12,
	INS1, INS2, 
	INSC1, INSC2, 
	INSC3, INSC4,
	INSC5, INSC6,
	INSC7, INSC8,
	NONE
} ;

const char *ModeNames[] = {
	"ALL", "ALL1", "ALL2", 
	"BOTH", "BOTHX", 
	"BOTHX1", "BOTHX2", "CONF",
	"DEL1", "DEL2", 
	"DELB", "DELB1", "DELB2", 
	"EDIT1", "EDIT2",
	"EDITC1", "EDITC2",
	"INSX1", "INSX2",
	"INSX3", "INSX4",
	"INSY1", "INSY2",
	"INS12", "INSX12", "INSY12",
	"INS1", "INS2", 
	"INSC1", "INSC2", 
	"INSC3", "INSC4",
	"INSC5", "INSC6",
	"INSC7", "INSC8",
	"NONE"
} ;

struct DiffGrid {

	Mode		mode;
	DiffDiffs	diffs;

} ;

const DiffGrid twoWayGrid[2][2][2][2][2][2] = {

//    ---- BASE/LEG1         ---- BASE/LEG2         ---- LEG1/LEG2
//    ||                     ||                     ||
//    __   __   __      __   __   _X      __   __   X_      __   __   XX  
//    __   _X   __      __   _X   _X      __   _X   X_      __   _X   XX  
//    __   X_   __      __   X_   _X      __   X_   X_      __   X_   XX  
//    __   XX   __      __   XX   _X      __   XX   X_      __   XX   XX  

      CONF,DD_CONF,     CONF,DD_CONF,     CONF,DD_CONF,     BOTH,DD_BOTH,
      CONF,DD_CONF,     CONF,DD_CONF,     CONF,DD_CONF,     BOTH,DD_BOTH,
      CONF,DD_CONF,     CONF,DD_CONF,     CONF,DD_CONF,     BOTH,DD_BOTH,
      CONF,DD_CONF,     CONF,DD_CONF,     CONF,DD_CONF,     BOTH,DD_BOTH,

//    _X   __   __      _X   __   _X      _X   __   X_      _X   __   XX  
//    _X   _X   __      _X   _X   _X      _X   _X   X_      _X   _X   XX  
//    _X   X_   __      _X   X_   _X      _X   X_   X_      _X   X_   XX  
//    _X   XX   __      _X   XX   _X      _X   XX   X_      _X   XX   XX  

      CONF,DD_CONF,     CONF,DD_CONF,     CONF,DD_CONF,     BOTH,DD_BOTH,
      CONF,DD_CONF,     CONF,DD_CONF,     CONF,DD_CONF,     BOTH,DD_BOTH,
      CONF,DD_CONF,     CONF,DD_CONF,     CONF,DD_CONF,     BOTH,DD_BOTH,
      CONF,DD_CONF,     CONF,DD_CONF,     CONF,DD_CONF,     BOTH,DD_BOTH,

//    X_   __   __      X_   __   _X      X_   __   X_      X_   __   XX  
//    X_   _X   __      X_   _X   _X      X_   _X   X_      X_   _X   XX  
//    X_   X_   __      X_   X_   _X      X_   X_   X_      X_   X_   XX  
//    X_   XX   __      X_   XX   _X      X_   XX   X_      X_   XX   XX  

      CONF,DD_CONF,     CONF,DD_CONF,     CONF,DD_CONF,     BOTH,DD_BOTH,
      CONF,DD_CONF,     CONF,DD_CONF,     CONF,DD_CONF,     BOTH,DD_BOTH,
      CONF,DD_CONF,     CONF,DD_CONF,     CONF,DD_CONF,     BOTH,DD_BOTH,
      CONF,DD_CONF,     CONF,DD_CONF,     CONF,DD_CONF,     BOTH,DD_BOTH,

//    XX   __   __      XX   __   _X      XX   __   X_      XX   __   XX  
//    XX   _X   __      XX   _X   _X      XX   _X   X_      XX   _X   XX  
//    XX   X_   __      XX   X_   _X      XX   X_   X_      XX   X_   XX  
//    XX   XX   __      XX   XX   _X      XX   XX   X_      XX   XX   XX  

      CONF,DD_CONF,     CONF,DD_CONF,     CONF,DD_CONF,     BOTH,DD_BOTH,
      CONF,DD_CONF,     CONF,DD_CONF,     CONF,DD_CONF,     BOTH,DD_BOTH,
      CONF,DD_CONF,     CONF,DD_CONF,     CONF,DD_CONF,     BOTH,DD_BOTH,
      CONF,DD_CONF,     CONF,DD_CONF,     CONF,DD_CONF,     BOTH,DD_BOTH
} ;

const DiffGrid optimalGrid[2][2][2][2][2][2] = {

//    ---- BASE/LEG1         ---- BASE/LEG2         ---- LEG1/LEG2
//    ||                     ||                     ||
//    __   __   __      __   __   _X      __   __   X_      __   __   XX  
//    __   _X   __      __   _X   _X      __   _X   X_      __   _X   XX  
//    __   X_   __      __   X_   _X      __   X_   X_      __   X_   XX  
//    __   XX   __      __   XX   _X      __   XX   X_      __   XX   XX  

      CONF,DD_CONF,     INSX1,DD_LEG1,    INSX2,DD_LEG2,    BOTHX,DD_BOTH,
      CONF,DD_CONF,     INSC6,DD_CONF,    INSX2,DD_LEG2,    BOTH,DD_BOTH,
      CONF,DD_CONF,     CONF,DD_CONF,     DELB,DD_BOTH,     DELB,DD_BOTH,
      EDITC1,DD_CONF,   EDIT1,DD_LEG1,    EDIT1,DD_LEG1,    ALL2,DD_ALL,

//    _X   __   __      _X   __   _X      _X   __   X_      _X   __   XX  
//    _X   _X   __      _X   _X   _X      _X   _X   X_      _X   _X   XX  
//    _X   X_   __      _X   X_   _X      _X   X_   X_      _X   X_   XX  
//    _X   XX   __      _X   XX   _X      _X   XX   X_      _X   XX   XX  

      CONF,DD_CONF,     INSX1,DD_LEG1,    INSC5,DD_CONF,    BOTH,DD_BOTH,
      INS12,DD_CONF,    INSX12,DD_CONF,   INSY12,DD_CONF,   BOTH,DD_BOTH,
      CONF,DD_CONF,     CONF,DD_CONF,     INSC3,DD_CONF,    INSC3,DD_CONF,
      INSX3,DD_LEG1,    INSX1,DD_LEG1,    INSC1,DD_CONF,    ALL2,DD_ALL,

//    X_   __   __      X_   __   _X      X_   __   X_      X_   __   XX  
//    X_   _X   __      X_   _X   _X      X_   _X   X_      X_   _X   XX  
//    X_   X_   __      X_   X_   _X      X_   X_   X_      X_   X_   XX  
//    X_   XX   __      X_   XX   _X      X_   XX   X_      X_   XX   XX  

      CONF,DD_CONF,     DELB,DD_BOTH,     CONF,DD_CONF,     DELB,DD_BOTH,
      CONF,DD_CONF,     INSC4,DD_CONF,    CONF,DD_CONF,     INSC4,DD_CONF,
      DELB,DD_BOTH,     DELB,DD_BOTH,     DELB,DD_BOTH,     DELB,DD_BOTH,
      DEL1,DD_LEG1,     DEL1,DD_LEG1,     INSC8,DD_CONF,    ALL2,DD_ALL,

//    XX   __   __      XX   __   _X      XX   __   X_      XX   __   XX  
//    XX   _X   __      XX   _X   _X      XX   _X   X_      XX   _X   XX  
//    XX   X_   __      XX   X_   _X      XX   X_   X_      XX   X_   XX  
//    XX   XX   __      XX   XX   _X      XX   XX   X_      XX   XX   XX  

      EDITC2,DD_CONF,   EDIT2,DD_LEG2,    EDIT2,DD_LEG2,    ALL1,DD_ALL,
      INSX4,DD_LEG2,    INSC2,DD_CONF,    INSX2,DD_LEG2,    ALL1,DD_ALL,
      DEL2,DD_LEG2,     INSC7,DD_CONF,    DEL2,DD_LEG2,     ALL1,DD_ALL,
      ALL,DD_ALL,       ALL,DD_ALL,       ALL,DD_ALL,       ALL,DD_ALL
} ;

const DiffGrid conservativeGrid[2][2][2][2][2][2] = {

//    ---- BASE/LEG1         ---- BASE/LEG2         ---- LEG1/LEG2
//    ||                     ||                     ||
//    __   __   __      __   __   _X      __   __   X_      __   __   XX  
//    __   _X   __      __   _X   _X      __   _X   X_      __   _X   XX  
//    __   X_   __      __   X_   _X      __   X_   X_      __   X_   XX  
//    __   XX   __      __   XX   _X      __   XX   X_      __   XX   XX  

      NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,     BOTHX,DD_CONF,
      NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,     BOTH,DD_CONF,
      NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,
      NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,

//    _X   __   __      _X   __   _X      _X   __   X_      _X   __   XX  
//    _X   _X   __      _X   _X   _X      _X   _X   X_      _X   _X   XX  
//    _X   X_   __      _X   X_   _X      _X   X_   X_      _X   X_   XX  
//    _X   XX   __      _X   XX   _X      _X   XX   X_      _X   XX   XX  

      NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,     BOTH,DD_CONF,
      NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,     BOTH,DD_CONF,
      NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,     BOTHX1,DD_CONF,
      NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,

//    X_   __   __      X_   __   _X      X_   __   X_      X_   __   XX  
//    X_   _X   __      X_   _X   _X      X_   _X   X_      X_   _X   XX  
//    X_   X_   __      X_   X_   _X      X_   X_   X_      X_   X_   XX  
//    X_   XX   __      X_   XX   _X      X_   XX   X_      X_   XX   XX  

      NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,
      NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,     BOTHX2,DD_CONF,
      NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,
      NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,

//    XX   __   __      XX   __   _X      XX   __   X_      XX   __   XX  
//    XX   _X   __      XX   _X   _X      XX   _X   X_      XX   _X   XX  
//    XX   X_   __      XX   X_   _X      XX   X_   X_      XX   X_   XX  
//    XX   XX   __      XX   XX   _X      XX   XX   X_      XX   XX   XX  

      NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,
      NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,
      NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,
      NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL,     NONE, DD_ALL
} ;

DiffDiffs
DiffMerge::DiffDiff()
{
	/* All legs completely output? */

	if( bf->end == bf->Lines() &&
	    lf1->end == lf1->Lines() &&
	    lf2->end == lf2->Lines() )
		return( DD_EOF );

	/* Advance to next snake, if past old one. */

	df1->AdvanceAndSync();
	df2->AdvanceAndSync();
	df3->AdvanceAndSync();

	LineNo lb = 0, l1 = 0, l2 = 0;

	DiffGrid d;
	d.mode = NONE;

	// '-dg' (guarded) flag informs merge to use the conservative grid,
	// if no mode is returned then fallback to the optimal grid.

	// '-dt' (twoway) flag informs merge to use the twoway grid,

	if( gridType == GRT_TWOWAY ) d = twoWayGrid
		[ df1->StartLeg() == 0 ][ df1->StartBase() == 0 ]
		[ df2->StartLeg() == 0 ][ df2->StartBase() == 0 ]
		[ df3->StartL1() == 0 ][ df3->StartL2() == 0 ];

	if( gridType == GRT_GUARDED ) d = conservativeGrid
		[ df1->StartLeg() == 0 ][ df1->StartBase() == 0 ]
		[ df2->StartLeg() == 0 ][ df2->StartBase() == 0 ]
		[ df3->StartL1() == 0 ][ df3->StartL2() == 0 ];
	
	if( d.mode == NONE ) d = optimalGrid
		[ df1->StartLeg() == 0 ][ df1->StartBase() == 0 ]
		[ df2->StartLeg() == 0 ][ df2->StartBase() == 0 ]
		[ df3->StartL1() == 0 ][ df3->StartL2() == 0 ];

	Mode initialMode = d.mode;

	// Pre-process rules,  typically the outer snake information
	// contradicts the inner snake, its not perfect, but we use
	// the length of the snake to determine the best outcome.

	// Advance files

	switch( d.mode )
	{
	case INSC1:
	    // Trust outer, unless previous mode was INSX3
	    // and merge is trying to behave more like diff3

	    if( ( oldMode != INSX3 || !diff3behavior ) && 
	        ( df3->EndL1() > df2->EndBase() ) )
	    { d.mode = INSY2; d.diffs = DD_LEG2; break; }

	    d.mode = INS1; d.diffs = DD_LEG1;     // trust inner - insert L1
	    break;

	case INSC2:
	    // Trust outer, unless previous mode was INSX4
	    // and merge is trying to behave more like diff3

	    if( ( oldMode != INSX4 || !diff3behavior) && 
	        ( df3->EndL2() > df1->EndBase() ) )
	    { d.mode = INSY1; d.diffs = DD_LEG1; break; }

	    d.mode = INS2; d.diffs = DD_LEG2;     // trust inner = insert L1
	    break;

	case INSC3:
	    if( df3->EndL1() >= df1->EndLeg() )   // trust outer - delete base
	    { d.mode = DELB1; d.diffs = DD_BOTH; break; }

	    d.mode = INS1; d.diffs = DD_LEG1;     // trust inner - insert L1
	    break;

	case INSC4:
	    if( df3->EndL2() >= df2->EndLeg() )   // trust outer - delete base
	    { d.mode = DELB2; d.diffs = DD_BOTH; break; }

	    d.mode = INS2; d.diffs = DD_LEG2;     // trust inner - insert L2
	    break;

	case INSC5:
	    if( df3->EndL1() >= df1->EndLeg() )   // trust outer - delete base
	    { d.mode = DELB1; d.diffs = DD_BOTH; break; }

	    if( df3->EndL1() >= df1->EndBase() )  // trust outer - insert L2
	    { d.mode = INSX2; d.diffs = DD_LEG2; break; }

	    d.mode = INS1; d.diffs = DD_LEG1;     // trust inner - insert L1
	    break;

	case INSC6:
	    if( df3->EndL2() >= df2->EndLeg() )   // trust outer - delete base
	    { d.mode = DELB2; d.diffs = DD_BOTH; break; }

	    if( df3->EndL2() >= df2->EndBase() )  // trust outer - insert L1
	    { d.mode = INSX1; d.diffs = DD_LEG1; break; }

	    d.mode = INS2; d.diffs = DD_LEG2;     // trust inner - insert L2
	    break;

	case INSC7:
	   if( df1->EndBase() > df2->StartBase() ||   // overlap in delete
	       df2->EndBase() == df2->StartBase() )   // eof detection
	   { d.mode = DEL2; d.diffs = DD_LEG2; }
	   break;

	case INSC8:
	   if( df2->EndBase() > df1->StartBase() ||   // overlap in delete
	       df1->EndBase() == df1->StartBase() )   // eof detection
	   { d.mode = DEL1; d.diffs = DD_LEG1; }
	   break;

	case INSX12:
	    if( df3->StartL1() < df1->StartLeg() &&
	        df3->EndL1() >= df1->StartLeg() &&
	        df3->EndL2() >= df2->StartLeg() ) // trust outer - insert L1
	    { d.mode = INSY1; d.diffs = DD_LEG1; }
	    break;

	case INSY12:
	    if( df3->StartL2() < df2->StartLeg() &&
	        df3->EndL2() >= df2->StartLeg() &&
	        df3->EndL1() >= df1->StartLeg() ) // trust outer - insert L2
	    { d.mode = INSY2; d.diffs = DD_LEG2; }
	    break;
	}

	oldMode = d.mode;

	switch( d.mode )
	{
	case ALL1:
	    lb = l1 = l2 = dmin( df1->EndBase(), df3->EndL1() );
	    break;

	case ALL2:
	    lb = l1 = l2 = dmin( df2->EndBase(), df3->EndL2() );
	    break;

	case ALL:
	    lb = l1 = l2 = dmin( df1->EndBase(), df2->EndBase() );
	    break;

	case BOTH:
	    lb = dmin( df1->StartBase(), df2->StartBase() );
	    l1 = dmin( df1->StartLeg(), df3->EndL1() );
	    l2 = dmin( df2->StartLeg(), df3->EndL2() );
	    l1 = l2 = dmin( l1, l2 );
	    break;

	case BOTHX:
	    lb = dmin( df1->StartBase(), df2->StartBase() );
	    l1 = dmin( df1->StartLeg(), df3->EndL1() );
	    l2 = dmin( df2->StartLeg(), df3->EndL2() );
	    l1 = l2 = dmin( l1, l2 );
	    lb = dmin( lb, l1 );
	    d.mode = BOTH;
	    break;

	case BOTHX1:
	    l1 = l2 = dmin( df1->StartLeg(), df3->EndL1() );
	    d.mode = BOTH;
	    break;

	case BOTHX2:
	    l1 = l2 = dmin( df2->StartLeg(), df3->EndL2() );
	    d.mode = BOTH;
	    break;

	case DELB:
	    lb = dmin( df1->StartBase(), df2->StartBase() );
	    break;

	case DELB1:
	    lb = df1->EndBase();
	    break;

	case DELB2:
	    lb = df2->EndBase();
	    break;

	case DEL1:
	    lb = l2 = dmin( df1->StartBase(), df2->EndBase() );
	    break;

	case DEL2:
	    lb = l1 = dmin( df2->StartBase(), df1->EndBase() );
	    break;

	case EDIT1:
	case EDITC1:
	    l1 = dmin( df1->StartLeg(), df3->StartL1() );
	    lb = l2 = dmin( df1->StartBase(), df2->EndBase() );
	    break;

	case EDIT2:
	case EDITC2:
	    l2 = dmin( df2->StartLeg(), df3->StartL2() );
	    lb = l1 = dmin( df1->EndBase(), df2->StartBase() );
	    break;

	case INSX1:
	case INSX3:
	    l1 = dmin( df1->StartLeg(), df3->StartL1() );
	    break;

	case INSX2:
	case INSX4:
	    l2 = dmin( df2->StartLeg(), df3->StartL2() );
	    break;

	case INSY1:
	    l1 = df3->StartL1();
	    break;

	case INSY2:
	    l2 = df3->StartL2();
	    break;

	case INS1:
	    l1 = df1->StartLeg();
	    break;

	case INS2:
	    l2 = df2->StartLeg();
	    break;

	case INSX12:
	    l1 = dmin( df1->StartLeg(), df3->StartL1() );
	    l2 = df2->StartLeg();
	    break;

	case INSY12:
	    l1 = df1->StartLeg();
	    l2 = dmin( df2->StartLeg(), df3->StartL2() );
	    break;

	case CONF:
	    lb = dmin( df1->StartBase(), df2->StartBase() );
	    // fall through

	case INS12:
	    l1 = dmin( df1->StartLeg(), df3->StartL1() );
	    l2 = dmin( df2->StartLeg(), df3->StartL2() );
	    break;
	}

	if( DEBUG_MERGE )
	{
	    p4debug.printf("\nMMMM df1(%d,%d)B(%d,%d)L df2(%d,%d)B(%d,%d)L ",
	        df1->StartBase(),df1->EndBase(),df1->StartLeg(),df1->EndLeg(),
	        df2->StartBase(),df2->EndBase(),df2->StartLeg(),df2->EndLeg());

	    p4debug.printf("df3(%d,%d)L1(%d,%d)L2 [%c%c %c%c %c%c]\n",
	        df3->StartL1(),df3->EndL1(),df3->StartL2(),df3->EndL2(),
	        df1->StartLeg() == 0 ? 'X' : '_', 
	        df1->StartBase() == 0 ? 'X' : '_',
	        df2->StartLeg() == 0 ? 'X' : '_',
	        df2->StartBase() == 0 ? 'X' : '_',
	        df3->StartL1() == 0 ? 'X' : '_', 
	        df3->StartL2() == 0 ? 'X' : '_');

	    p4debug.printf("MMMM %s%s%s advancing %+d,%+d,%+d\n", 
	        ModeNames[ initialMode ], 
	        d.mode != initialMode ? " -> " : "",
	        d.mode != initialMode ? ModeNames[ d.mode ] : "",
	        lb, l1, l2 );
	}

	/* Set output range (start/end).  End is new sync point. */

	bf->start = bf->end;
	lf1->start = lf1->end;
	lf2->start = lf2->end;

	bf->end += lb;
	lf1->end += l1;
	lf2->end += l2;

	/* If an action may be downgraded from a conflict (currently only
	 * EDITC1 and EDITC2 fit that category), make sure they actually get
	 * through the processing or downgrade it now.
	 *
	 * 2007.2  Added BOTH (guarded mode)
	 */

	if( bf->end == bf->Lines() &&
	    lf1->end == lf1->Lines() &&
	    lf2->end == lf2->Lines() )
	{
	    if( d.mode == EDITC1 ) d.diffs = DD_LEG1; 
	    if( d.mode == EDITC2 ) d.diffs = DD_LEG2; 
	    if( d.mode == BOTH ) d.diffs = DD_BOTH; 
	}

	/* Handle Conflicts (post processing) 
	 * 
	 * Sometimes it is necessary to extend the conflict area to produce
	 * the best conflict.  Advance all snakes to the conflict end region 
	 * and see what happens next.  Depending  on the result,  we may grow 
	 * the conflict several times before returning.
	 *
	 * 2007.2 added the guarded flag (-dg) which uses the conservative 
	 * grid to change the action of "BOTH" processing.  Note that during
	 * conflict extension only (-dg) processed files will see "BOTH" as
	 * the conflict mode.
	 */

	DiffGrid n;
	int extendConflict = 0;

	while( d.diffs == DD_CONF && ( bf->end != bf->Lines() || 
	                               lf1->end != lf1->Lines() || 
	                               lf2->end != lf2->Lines() ) )
	{
	    LineNo ab = 0, a1 = 0, a2 = 0;
	    oldMode = 0;

	    // Conflict caused by inserting on L1 and L2 can never extend
	    // the base.

	    int noBaseAdvance = ( d.mode == INS12 
	                       || d.mode == INSX12 
	                       || d.mode == INSY12 );

	    df1->AdvanceAndSync();
	    df2->AdvanceAndSync();
	    df3->AdvanceAndSync();

	    n = optimalGrid
	        [ df1->StartLeg() == 0 ][ df1->StartBase() == 0 ]
		[ df2->StartLeg() == 0 ][ df2->StartBase() == 0 ]
		[ gridType == GRT_GUARDED && df3->StartL1() == 0 
	                                  && df3->StartL2() == 0 ]
		[ gridType == GRT_GUARDED && df3->StartL1() == 0 
	                                  && df3->StartL2() == 0 ];
	
	    switch( n.mode )
	    {
	    case INSX1: 
	    case INSX3: 
	        if( d.mode == INSC7 && extendConflict < 2 )
	        { d.diffs = DD_LEG2; break; }
	    case INS1:
	        a1 = df1->StartLeg();
	        break;
	    case INSX2: 
	    case INSX4: 
	        if( d.mode == INSC8 && extendConflict < 2 )
	        { d.diffs = DD_LEG1; break; }
	    case INS2:
	        a2 = df2->StartLeg();
	        break;
	    case DEL1:
	        ab = a2 = dmin( df1->StartBase(), df2->EndBase() );
	        break;
	    case DEL2: 
	        ab = a1 = dmin( df2->StartBase(), df1->EndBase() );
	        break;
	    case DELB:
	        // Prior to adding EDITC1 and EDITC2,  DELB would not 
	        // extend the conflict area, lets keep it that way.
	        // Added INSC7 and INSC8 for 2010.2.
	        if( d.mode != EDITC1 && d.mode != EDITC2 && 
	            d.mode != INSC7  && d.mode != INSC8 )
	            break;
	    case INSC3:
	    case INSC4:
	    case CONF:
	        ab = dmin( df1->StartBase(), df2->StartBase() );
	    case INS12:
	        if( d.mode == BOTH )
	        { 
	            a1 = df1->StartLeg(); 
	            a2 = df2->StartLeg(); 
	            break;
	        }

	        if( !noBaseAdvance )
	        {
	            a1 = dmin( df1->StartLeg(), df3->StartL1() );
	            a2 = dmin( df2->StartLeg(), df3->StartL2() );
	            break;
	        }

	        // INS12,INSX12,INSY12 (conflict) made a bad decision and 
	        // went with an outer snake,  since we are still in the 
	        // inner snake/ make up for that now by advancing to 
	        // inner startlegs.

	        if( df1->StartLeg() > df3->EndL1() &&
	            df2->StartLeg() > df3->EndL2() )
	        { 
	            a1 = df1->StartLeg(); 
	            a2 = df2->StartLeg(); 
	        }
	        break;
	    case EDITC1:
	        if( gridType == GRT_GUARDED ) 
	        {
	            a1 = dmin( df1->StartLeg(), df3->StartL1() );
	            ab = a2 = dmin( df1->StartBase(), df2->EndBase() );
	        }
	        break;
	    case EDITC2:
	        if( gridType == GRT_GUARDED )
	        {
	            a2 = dmin( df2->StartLeg(), df3->StartL2() );
	            ab = a1 = dmin( df1->EndBase(), df2->StartBase() );
	        }
	        break;
	    case BOTH:
	        a1 = dmin( df1->StartLeg(), df3->EndL1() );
	        a2 = dmin( df2->StartLeg(), df3->EndL2() );
	        break;

	    default:
	        break;
	    }

	    // if EDITC (conflict)  doesn't advance in the deleted leg
	    // then this isn't a conflict (fall back to edit).  
	    // if BOTH (conflict)  doesn't advance then fall back to both.

	    if( !extendConflict )
	    {
	        switch( d.mode )
	        {
	        case EDITC1:  if( !ab && !a2) d.diffs = DD_LEG1;
	                      break;
	        case EDITC2:  if( !ab && !a1) d.diffs = DD_LEG2;
	                      break;
	        case BOTH:    if( !ab && !a1 && !a2 ) d.diffs = DD_BOTH;
	                      break;
	        }
	    }

	    // INS12 (conflict) cannot advance base - bail
	    
	    if( noBaseAdvance && ab ) 
	        break;

	    // No conflict extension  - bail

	    if( !ab && !a1 && !a2 )
	        break;

	    // No longer a conflict - bail

	    if( d.diffs != DD_CONF )
	        break;

	    if( DEBUG_MERGE )
	        p4debug.printf("MMMM %s/%s adjustment %+d,%+d,%+d\n",
	            ModeNames[ d.mode ], ModeNames[ n.mode ], ab, a1, a2 );

	    bf->end += ab;
	    lf1->end += a1;
	    lf2->end += a2;

	    extendConflict++;
	}

	return d.diffs;
}

