/*
 * Copyright 2002 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * MultiMerge - merge a bunch of files and return a merged list
 *
 * MultiMerge is the basis for an 'annotate' command, which shows
 * all version of a file combined into a single stream, with each
 * line marked with the applicable revisions.
 *
 * MutliMerge does the work of merging a bunch of separate files
 * (each distinguished internally by revId) and producing the resulting
 * stream.  It does so taking one file at a time, diffing it against the
 * previous, and using the diff to merge the new file's lines into the 
 * existing list of lines.  The result is a list (chain, actually) of all
 * the lines of all the files, with each line marked with the first and
 * last revision the line was seen in.
 *
 * If a line disappears in one rev and reappears in a later, it will seem
 * to be two separate lines, as we can only represent a single range of
 * revs and doing the n x n diffs would be too expensie anyhow.
 *
 * Classes defined:
 *	MultiMerge - the multiple file merger
 *
 * Public methods:
 *	MultiMerge::Add() - add the next file to the merged stream
 *	MultiMerge::Dump() - (debugging) write the merged stream to stdout
 *	MultiMerge::Read() - extra the merged result, a line at a time
 *
 * Note:
 *	MultiMerge::Add() takes possession of the FileSys handed it,
 *	and deletes it when done.
 */

struct MergeLine;
struct MergeSequence;

class MultiMerge
{
    public:

		MultiMerge( StrPtr *diffFlags = 0 );
		~MultiMerge();

	void	Add( FileSys *f, int revId, int chgId, Error *e );

	void	Dump();

	MergeLine *Read( int &lower, int &upper, int &change, 
	                 StrPtr &string, int chg );

	MergeLine *FirstLine() { return chain; } // for FileMultiMerge

	int	index; // for MultiMultiMerge

    private:

	MergeSequence	*fx;
	MergeLine	*chain;
	MergeLine	*reader;
	DiffFlags 	flags;
} ;

/*
 * MergeLine - a list of lines representing the merge of many files
 *
 * A MergeLine chain represents the merge of many files.  It starts as 
 * linked list of lines of one file.  (The lines are actually the entries 
 * of a diff sequence, usually the same thing.) Each time a file is merged 
 * in, the diff between the previous file and the new file dictates the
 * insertion of new lines into the chain.
 *
 * Each line is marked with a lowerRev and upperRev.  The lowerRev is the
 * rev when the line is added.  The upperRev is the highest rev the line
 * was seen in.  When a new file is diffed against the previous, there are
 * three possible states for existing lines:
 *
 *	upperRev < rev of previous file: 
 *		these are ignored when counting lines, as they didn't
 *		participate in the diff.
 *
 *	upperRev == rev of previous file, and line is in new file as well:
 *		upperRev gets reset to rev of new file
 *
 *	upperRev == rev of previous file, but line not in new file:
 *		upperRev is left as rev of previous file, thus being 
 *		ignored on subsequent passes.
 */

struct MergeLine
{
	MergeLine	*next;

	int		lowerRev;
	int		upperRev;

	int		lowerChg;
	int		upperChg;

	MergeLine	*from; // integ source

	StrBuf		buf;

	MultiMerge	*merge;

	static MergeLine **AddLines( 
		MergeLine **p,
		MergeSequence *f,
		MultiMerge *m,
		LineNo s,
		LineNo e );

	static MergeLine **MarkLines( 
		MergeLine **p,
		LineNo count,
		int prevRev,
		int nextRev,
		int prevChg,
		int nextChg );
} ;
