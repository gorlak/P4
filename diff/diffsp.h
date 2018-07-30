/*
 * Copyright 1997 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 *
 * Diff code written by James Strickland, May 1997.
 */

/*
 * Diffsp.h - diff's sequence object
 *
 * The Sequence class implements the abstraction of a file as a sequence
 * of elements.  It's job is to count elements (lines) and compare them.
 *
 * To do comparisons quickly, Sequence builds in memory a list of hashes
 * and offsets for each line.  ProbablyEqual() compares this hash, which 
 * may return false positives.  Equal() must do the full check, actually 
 * looking at file contents.
 *
 * Sequence uses Sequencer, an abstract base class, for actual hashing 
 * and comparing: there are different Sequencer implementations for 
 * regular text files, files broken apart at whitespace, and files where
 * whitespace is ignored.  Which is selected by the flag to sequence.
 *
 * Sequence relies on ReadFile's ability to handle text files of different
 * line endings, and thus takes a LineType flag for CopyLines() and Dump().
 *
 * Classes defined:
 *
 *	Sequence - a file as an abstract sequence of elements
 *
 * Public methods:
 *
 *	Sequence::Sequence() - open file and hash lines
 *	Sequence::~Sequence() - close file
 *
 *	Sequence::Lines() - return # of lines read
 *	Sequence::SeekLink() - position ReadFile at given line
 *	Sequence::CopyLines() - copy given lines into buffer
 *	Sequence::Dump() - copy given lines into FILE
 *	Sequence::Length() - return raw length of lines
 *	Sequence::Equal() - return whether lines are identical
 *	Sequence::ProbablyEqual() - return false if lines are not identical
 *
 * Private classed:
 *
 *	Sequencer - abstract base utility class for parsing file
 *	VarInfo - single line's hash and offset
 *
 * Private methods:
 *
 *	Sequence::GrowLineBuf() - grow hash/offset list table
 *	Sequence::StoreLine() - add hash/offset to list
 *	Sequencer::Load() - build list of hashed lines
 *	Sequencer::Equal() - compare two lines
 */

# ifdef Length		// Ugh - MS headers
# undef Length
# endif

class Sequence;
class DiffFlags;

typedef offL_t LineLen;
typedef signed int LineNo;	// no 16 bit machines please
typedef unsigned int HashVal;

typedef unsigned long UChar;

/*
 * VarInfo - single line's hash and offset
 */

struct VarInfo {
	HashVal 	hash;
	offL_t 		offset;
};

/*
 * Sequencer - abstract base utility class for parsing file
 */

class Sequencer {

    public:

	virtual		~Sequencer() {}

	virtual int	Equal( LineNo lA, Sequence *B, LineNo lB ) = 0;
	virtual	void	Load( Error *e ) = 0;

	Sequence	*A;
	ReadFile	*src;

};

/*
 * Sequence - a file as an abstract sequence of elements
 */

class Sequence {

    public:

			Sequence( FileSys *f, const DiffFlags &fl, Error *e );
			~Sequence();

	LineNo		Lines() const { return lineCount; }
	void		SeekLine( LineNo l ) { readfile->Seek( Off( l ) ); }

	int 		CopyLines( LineNo &l, LineNo m,
			    char *buf, int length, LineType t );

	bool		Dump( FILE *out, LineNo l, LineNo m, LineType t );

	LineLen		Length( LineNo l ) const 
				{ return Off(l+1) - Off(l); }
	LineLen		Length( LineNo l, LineNo m ) const 
				{ return Off( m ) - Off( l ); }
	LineLen		LengthLeft( LineNo l ) 
				{ return Off(l+1) - readfile->Tell(); }

	int		Equal( LineNo lA, Sequence *B, LineNo lB ) {
			    return ProbablyEqual( lA, B, lB ) &&
				    sequencer->Equal( lA, B, lB );
			}

	int		ProbablyEqual( LineNo lA, Sequence *B, LineNo lB ) {
			    return Hash( lA ) == B->Hash( lB );
			}

	void 		StoreLine( HashVal HashValue, Error *e );

    private:

	HashVal 	Hash( LineNo l ) const { return line[l].hash; }
	offL_t		Off( LineNo l ) const { return line[l].offset; }

	/* Variable length list of lines */

	void		GrowLineBuf( Error *e );

	VarInfo 	*line;
	LineNo 		lineCount;
	LineNo 		lineMax;
	int 		reallocCount;

    public:
	/* Actual underlying file reader */

	Sequencer	*sequencer;
	ReadFile	*readfile;

};

