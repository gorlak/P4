/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsco.h - combine revisions to produce an output file
 *
 * Classes defined:
 *
 *	RcsCkout - control block for a checkout
 *
 * Public methods:
 *
 *	RcsCkout::RcsCkOut() - set up for checkout
 *	RcsCkout::~RcsCkout() - finish and dispose of an RcsCkout
 *	RcsCkout::Ckout() - build up the piece table for given rev
 *	RcsCkout::Read() - read text from a revision recreated by Ckout()
 *
 * Private methods:
 *
 *	RcsCkout::ApplyExit() - apply a revision's worth of diffs
 *
 * History:
 *	2-18-97 (seiwald) - translated to C++.
 */

/*
 * RcsCkout - control block for checkout
 *
 * RcsCkout houses the info necessary to orchestrate a checkout.  It
 * is the handle that is returned by RcsCkoutInit, which the caller then
 * passes to each invocation of RcsCkoutRead.
 */

struct RcsPiece;
struct RcsEdit;

struct RcsCkout
{
    public:
			RcsCkout( RcsArchive *archive );
			~RcsCkout();

	void		Ckout( const char *revName, Error *e );

	int		Read( char *buf, int len );


    private:

	void 		ApplyEdit( RcsRev *rev, Error *e );

    public:

	RcsArchive	*archive;
	RcsPiece	*pieces;	/* we can can scan them */
	RcsEdit		*edits;		/* so we can free them */

	/* used by RcsCkoutRead */

	RcsPiece	*readPiece;	/* scans pieces during read */
	RcsLine		readPieceCount;	/* offset into readPiece */
	int		halfAt;		/* read suspended between @@ */

} ;

