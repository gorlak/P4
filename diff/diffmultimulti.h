/*
 * Copyright 2010 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * MultiMultiMerge - collect and connect a bunch of MultiMerges.
 *
 * MultiMultiMerge is the basis for an 'annotate -I' command, which
 * collects the results of multiple 'annotate' commands and follows
 * integration records to locate the original source of each line that
 * has been merged into the starting file.
 *
 * A MultiMerge object represents the results of a normal 'annotate',
 * and collects all of the revisions of a file, indicating a revision range
 * for each line that indicates which revisions the line is present in.
 * MultiMultiMerge stores an array of these representing a "family" of
 * files related by integration history, and then is asked to connect
 * lines between the files based on individual integration records.
 *
 * Each integration record fed into MultiMultiMerge results in a diff
 * between the source and target revs.  Lines that are identical between
 * them which were introduced to the target at the target rev and introduced
 * to the source at some point within the source rev range are considered to
 * have been merged into the target as a result of that integration.
 *
 * Classes defined:
 *	MultiMultiMerge - the multiple MultiMerge merger
 *                        (try saying that three times fast)
 *
 *
 */

struct MergeLine;
class MultiMerge;
class VarArray;

class MultiMultiMerge
{
    public:
			MultiMultiMerge( StrPtr *diffFlags = 0 );
			~MultiMultiMerge();

	void		Put( const StrPtr& id, MultiMerge* );
	MultiMerge*	Get( int i );
	const StrPtr&	IdOf( MergeLine *line );

	void		Credit( const StrPtr& fromId, int sRev, int eRev,
				const StrPtr& toId, int tRev, Error *e );

	void		Dump();

    private:

	MultiMerge*	Get( const StrPtr& id );

	VarArray*	multiMerges;
	DiffFlags	flags;

};
