/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsarch.h - in-memory RCS file RcsArchive
 *
 * Classes defined:
 *
 *	RcsArchive - parsed, in memory copy of RCS file
 *	RcsList - string lists for locks, symbols, access, branches
 *	RcsRev - all information about a revision
 *	RcsChunk - a pointer/length back into the RCS file for @ text
 *	RcsText - an allocated string with its strlen().
 *
 * Public methods:
 *
 *	RcsArchive::RcsArchive() - initialize RcsArchive
 *	RcsArchive::~RcsArchive() - free everything allocated to RcsArchive
 *	RcsArchive::AddRevision() - chain a revision onto the archive's list
 *	RcsArchive::FindRevision() - find a revision on the chain
 *	RcsArchive::NextRevision() - conveniently follow the rev's next pointer
 *	RcsArchive::Parse() - parse the whole RCS archive
 * 	RcsArchive::FollowRevision() - compute successor to current rev
 *
 *	RcsList::RcsList() - append new list member onto chain
 *
 * 	RcsText::Save() - copy text into a new buffer
 *
 *	RcsChunk::Save() - save offset/length pointers of @ block
 *
 * Note that just about everyone looks at these structures.  Only
 * the routines above should update them, though.
 *
 * History:
 *	5-13-95 (seiwald) - added lost support for 'branch rev' in ,v header.
 *	12-17-95 (seiwald) - added support for 'expand flag' in ,v header.
 *	2-18-97 (seiwald) - translated to C++.
 */

class FileSys;
class ReadFile;

typedef int RcsLine;		// when counting lines
typedef offL_t RcsSize;		// when counting bytes in file

/*
 * RcsChunk - a pointer/length back into the RCS file for @ text
 */

enum RcsChunkAt {
	RCS_CHUNK_ATCLEAN = 0, /* no @'s in chunk */
	RCS_CHUNK_ATSINGLE = 1, /* has single, unquoted @'s */
	RCS_CHUNK_ATDOUBLE = 2 /* has doubled @'s to quote them */
};
	
struct RcsChunk
{
	inline		RcsChunk() { file = 0; }

	void		Save( RcsChunk *src, const char *trace );
	void 		Save( FileSys *newFile, Error *e );

	ReadFile 	*file;		/* source file */
	RcsSize		offset;		/* offset into file */
	RcsSize		length;		/* length of chunk */
	RcsChunkAt	atWork;		/* what to do with @'s */
};

/*
 * RcsText - an allocated string with its strlen().
 */

struct RcsText
{
	inline		RcsText() { text = 0; len = 0; }
	inline		~RcsText() { delete [] text; }
	inline void	Clear() { delete [] text; text = 0; len = 0; }

	void 		Save( const char *ntext, int nlen, const char *trace );

	inline void	Save( RcsText &ntext, const char *trace )
			{ Save( ntext.text, ntext.len, trace ); }

	inline void 	Save( const char *ntext, const char *trace )
			{ Save( ntext, strlen( ntext ), trace ); }

	char		*text;
	int		len;
};

/*
 * RcsList - string lists for locks, symbols, access, branches
 */

struct RcsList
{
			RcsList( RcsList **headPtr );

	RcsList 	*qNext;
	RcsList 	*qTail;		/* valid only for head */

	RcsText		string;		/* user, symbol */
	RcsText		revision;	/* for locked list */

};

/*
 * RcsRev - all information about a revision
 */

struct RcsRev
{
	RcsRev 		*qNext;

	/* Stuff in the header */

	int		deleted;	/* zonked by RcsDelete */
	int		revHash;	/* revname for fast searches */

	RcsText		revName;
	RcsText		date;
	RcsText		author;
	RcsText		state;
	RcsList		*branches;
	RcsText		next;

	/* Stuff in the log */

	RcsChunk	log;
	RcsChunk	text;

};

/*
 * RcsArchive - parsed, in memory copy of RCS file
 */

class RcsArchive
{
    public:
			RcsArchive();
			~RcsArchive();

	void    	Parse( ReadFile *file, 
				const char *toThisRev, Error *e );

	RcsRev		*AddRevision( const char *revName, 
				int insert, RcsRev *prevRev, Error *e );
	RcsRev		*FindRevision( const char *revName, Error *e );
	RcsRev		*NextRevision( RcsRev *rev, Error *e );
	RcsRev		*FollowRevision( RcsRev *rev, const char *targ, 
				Error *e );

	int		GetChunkCnt( ) { return( chunkCnt ); }
	void		SetChunkCnt( int cnt ) { chunkCnt = cnt; }

    public:
	/* The header */

	RcsText		headRev;
	RcsText		branchRev;
	RcsList		*accessList;
	RcsList		*symbolList;
	RcsList		*lockList;
	char		strict;
	RcsChunk	comment;
	RcsChunk	expand;

	/* The break */

	RcsChunk	desc;

	/* The revisions */

	RcsRev		*revHead;
	RcsRev		*revTail;
	RcsRev		*lastFoundRev;	

	int		chunkCnt;

};
