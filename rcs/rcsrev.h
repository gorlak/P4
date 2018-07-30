/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsrev.h - RCS revision number mangling
 *
 * Classes defined
 *
 *	RcsRevPlace - a little handle for finding revision insertion points
 *
 * External routines:
 *
 *	RcsRevCmp() - compare current rev number with desired one.
 *
 * History:
 *	2-18-97 (seiwald) - translated to C++.
 */

/*
 * RcsRevPlace - return values from RcsRevPlace()
 */

enum RevPlace
{
	RCS_REV_PLACE_TRUNK,	/* on trunk */
	RCS_REV_PLACE_BRANCH,	/* on existing branch */
	RCS_REV_PLACE_NEWBR	/* on new branch */
};

struct RcsRevPlace 
{
    public:
	int		Locate( RcsArchive *ar, const char *targetRev, 
				Error *e );

    public:
	RevPlace	place;

	// as we follow from 'head' down the trunk and out the branch

	RcsRev		*prevRev;	// previous rev
	RcsRev		*currRev;	// current rev
	RcsRev		*nextRev;	// next rev

	RcsText		*thisPtr;	// what pointed to currRev

};

/* values for RcsRevCmp() */

enum RevCmp {
	REV_CMP_EQUAL,		/* t and c are the same revision */
	REV_CMP_MISMATCH,	/* t and c not equal & none of the following: */
	REV_CMP_DOWN_TRUNK,	/* t or c on the trunk; t older than c */
	REV_CMP_UP_TRUNK,	/* t or c on the trunk, t younger than c */
	REV_CMP_AT_BRANCH,	/* t descended from c */
	REV_CMP_NUM_BRANCH,	/* t descended from branch number c */
	REV_CMP_OUT_BRANCH,	/* t and c on same branch; c is younger */
	REV_CMP_IN_BRANCH	/* t and c on same branch; c is older */
};

/*
 * Note: The distinction between REV_CMP_AT_BRANCH and
 *       REV_CMP_NUM_BRANCH is that, for the latter, c names a "branch
 *       number", i.e., s has a odd number of "."-separated numbers.
 * 
 * For example, consider this RCS revision tree:
 *
 *                      --> 1.2.2.1.1.1           
 *                     /                        <- "downward"
 *                --> 1.2.2.1 --> 1.2.2.2
 *               /
 *      1.1 <-- 1.2 <-- 1.3 <-- 2.1 <- head
 *               \        \
 *                \        \--> 1.3.1.1
 *                 \
 *                  --> 1.2.1.1 --> 1.2.1.3
 * 
 *  This is the example from the rcsfile(5) man page; arrows signify
 *  the path of deltas to be applied when retrieving a particular
 *  revision; RCS stores the complete text of the head revision (2.1,
 *  in this example), and derives all other revisions by applying a
 *  series of deltas to it.
 *
 * with this tree in mind (it's easier to visualize with it!), we have:
 *
 * RcsRevCmp("1.3.1.1", "1.3.1.1") = REV_CMP_EQUAL
 * RcsRevCmp("1.2.2.1.1.1", "1.2.1.3") = REV_CMP_MISMATCH
 * RcsRevCmp("1.2.2.1", "1.2.2.1.1.1") = REV_CMP_MISMATCH
 * RcsRevCmp("1.1", "2.1") = REV_CMP_DOWN_TRUNK
 * RcsRevCmp("2.1", "1.1") = REV_CMP_UP_TRUNK
 * RcsRevCmp("1.2.2.2", "1.1") = REV_CMP_UP_TRUNK
 * RcsRevCmp("1.2.2.1.1.1", "1.3") = REV_CMP_DOWN_TRUNK
 * RcsRevCmp("1.2.2.1", "1.2.2.2") = REV_CMP_IN_BRANCH
 * RcsRevCmp("1.2.2.2", "1.2.2.1") = REV_CMP_OUT_BRANCH
 * RcsRevCmp("1.2.2.1.1.1", "1.2.2.1") = REV_CMP_AT_BRANCH
 * RcsRevCmp("1.2.2.1.1.1", "1.2.2") = REV_CMP_NUM_BRANCH
 * RcsRevCmp("1.2.2.1.1.1", "1.2") = REV_CMP_AT_BRANCH
 * RcsRevCmp("1.2.2.1.1.1", "1") = REV_CMP_NUM_BRANCH
 */

/* External routines */

RevCmp 	RcsRevCmp( const char *t, const char *c );
void 	RcsRevTest( RcsArchive *archive, const char *targetRev, Error *e );
