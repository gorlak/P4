/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsci.h - check a new revision into an RcsArchive
 *
 * Classes defined:
 *
 *	RcsCkin - control block for checkin operation
 *	RcsCkinChunk - a chunk for checkin, either a diff or whole file
 *
 * Public methods:
 *
 *	RcsCkin::RcsCkin() - create/repalce a head/post-head revision
 *	RcsCkin::~RcsCkin() - free up resources created by RcsCkin()
 *
 * These are separate because you have to write the new RCS file with
 * RcsGenerate in the interim.
 *
 * History:
 *	2-18-97 (seiwald) - translated to C++.
 */

/*
 * RcsCkinChunk - a chunk for checkin, either a diff or whole file
 */

class RcsCkinChunk : public RcsChunk
{
    public:
			RcsCkinChunk();
			~RcsCkinChunk();

	void 		Diff( RcsArchive *archive, const char *revName, 
				FileSys *newFile, int flags, Error *e );

    public:

	FileSys		*diffFile;               // write FST_TEXT
	FileSys		*diffFileBinary;         // read FST_BINARY

} ;

/*
 * RcsCkin - control block for checkin interface
 */

class RcsCkin
{

    public:

			RcsCkin( RcsArchive *archive, 
				FileSys *newFile, const char *newRev, 
				RcsChunk *log, const char *author, 
				const char *state, time_t modTime,
				Error *e );

    private:

	RcsCkinChunk	currChunk;
	RcsCkinChunk	nextChunk;

} ;
