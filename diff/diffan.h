/*
 * Copyright 1997 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 *
 * Diff code written by James Strickland, May 1997.
 */

/*
 * DiffAnalyze.h - interface for low-level diff operation
 *
 * Public classes:
 *
 *	DiffAnalyze::AnalyzeDiff( from, to ) - build up difference of files
 *
 * Internal classes:
 *
 *	Snake - a chain of the matching chunks in the files
 *	SymmetricVector - array with index symmetric about 0
 */

struct Snake {
	Snake 	*next;
	// u-x == v-y 'cause they match
	LineNo 	x,u;	// matching part of first file
	LineNo 	y,v;	// matching part of second file
};

class SymmetricVector {

    public:

	SymmetricVector() { HalfSize=0; Vec=0; }
	~SymmetricVector() { if( Vec ) delete[] ( Vec - HalfSize ); };

	inline LineNo& operator[]( LineNo k ) { return Vec[k]; }

	void Resize( LineNo NewHalfSize ) {
	    // harmless to delete 0, except on AS400!
	    if( Vec ) delete[] (Vec-HalfSize); 
	    HalfSize = NewHalfSize;
	    Vec = ( new LineNo[ HalfSize * 2 + 1 ] ) + HalfSize;
	}

	void Dump( LineNo D );

    private:

	LineNo 	HalfSize;
	LineNo	*Vec;

};

class DiffAnalyze {

    public:

	DiffAnalyze( Sequence *fromFile, Sequence *toFile, int fastMaxD = 0);
	~DiffAnalyze();

	Sequence	*GetFromFile() { return A; };
	Sequence	*GetToFile() { return B; };
	Snake		*GetSnake() { return FirstSnake; };

    private:

	LineNo		maxD;
	Sequence	*A;
	Sequence	*B;

	Snake 		*FirstSnake;
	Snake		*LastSnake;

	SymmetricVector fV;
	SymmetricVector rV;

	void		BracketSnake();

	void		ApplyForwardBias();

	void 		FollowDiagonal(
				LineNo &x, LineNo &y,
				LineNo endx, LineNo endy);

	void 		FollowReverseDiagonal(
				LineNo &x, LineNo &y,
			        LineNo startx, LineNo starty);

	void 		FindSnake(Snake &s, 
				LineNo startx, LineNo starty,
				LineNo endx, LineNo endy );

	void 		LCS(
				LineNo startx, LineNo starty,
				LineNo endx, LineNo endy );

};
