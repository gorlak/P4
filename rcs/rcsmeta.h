/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsmeta.h - print out RCS metadata, given an RcsArchive structure
 *
 * Classes defined:
 *
 *	RcsGenMeta - control block for generating metadata
 *
 * Public methods:
 *
 *	RcsGenMeta::RcsGenMeta -- set up for metadata generation
 *	RcsGenMeta::Generate - write metadata to stdio file
 *
 * History:
 *	2-18-97 (seiwald) - translated to C++.
 */

class FileSys;
struct RcsRevMeta;

class RcsGenMeta : public RcsGenFile
{
    public:
			RcsGenMeta( FileSys *wf, RcsArchive *ar, char *arch );
	void		Generate( Error *e );

    private:

	void		Trunk( RcsRevMeta *rm, Error *e );
	void		Branch( RcsRevMeta *rm, Error *e ) ;
	void		Branches( RcsRevMeta *rm, RcsRev *rev, Error *e );
	void		Rev( RcsRevMeta *rm, RcsRev *rev );
	void		File3( const char *domain, const char *branch, 
				const char *path );

	RcsArchive 	*ar;
	const char	*archName;
	char		path[256];
	int		isDead;
} ;
