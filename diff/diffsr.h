/*
 * Copyright 2002 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * diffsr.h -- diff's Sequence's Sequencer
 *
 * Public classes:
 *
 * 	LineReader - a diff Sequencer for lines
 * 	WordReader - a diff Sequencer for words separated by whitespace
 *	WClassReader - a diff Sequencer for classes of characters
 * 	DifflReader - a diff Sequencer for lines, line endings ignored
 * 	DiffbReader - a diff Sequencer for lines, whitespace changes ignored
 * 	DiffwReader - a diff Sequencer for lines, all whitespace ignored
 */

class LineReader : public Sequencer {

    public:
	virtual int	Equal( LineNo lA, Sequence *B, LineNo lB );
	virtual void	Load( Error *e );
} ;

class WordReader : public LineReader {

    public:
	virtual void	Load( Error *e );
} ;

class WClassReader : public LineReader {

    public:
	virtual void	Load( Error *e );
} ;

class DifflReader : public Sequencer {

    public:
	virtual int	Equal( LineNo lA, Sequence *B, LineNo lB );
	virtual void	Load( Error *e );

	// any newline character

	int		NewLine( UChar c ) { return c == '\r' || c == '\n'; }
} ;

class DiffbReader : public DifflReader {

    public:
	virtual int	Equal( LineNo lA, Sequence *B, LineNo lB );
	virtual void	Load( Error *e );

	// for purposes of diff -b: what is whitespace?

	int		Whitespace( UChar c ) { return c == ' ' || c == '\t'; }
} ;

class DiffwReader : public DiffbReader {

    public:
	virtual int	Equal( LineNo lA, Sequence *B, LineNo lB );
	virtual void	Load( Error *e );
} ;

