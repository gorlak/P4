/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsvfile.h - open & close the RCS ,v file and its temp successor
 *
 * External routines:
 *
 *	RcsVfile::RcsVfile() - open the RCS ,v file and its temp successor
 *	RcsVfile::~RcsVfile() - close the RCS ,v file and discard its temp 
 * 	RcsVfile::Commit() - replace the RCS ,v file with its successor
 *
 * External structures:
 *
 *	RcsVfile - opened RCS ,v file and its successor
 *
 * History:
 *	2-18-97 (seiwald) - translated to C++.
 */

/*
 * RcsVfile - opened RCS ,v file and its successor
 */

enum RcsVfileMode {

	RCS_VFILE_READ 		= 0x01,	/* open ,v file */
	RCS_VFILE_WRITE 	= 0x02,	/* open ,temp, file */
	RCS_VFILE_UPDATE 	= 0x03,	/* both */
	RCS_VFILE_NOLOCK 	= 0x04,	/* trash existing ,temp, file */
	RCS_VFILE_DELETE 	= 0x08	/* all revs deleted - delete file */

} ;

class FileSys;

struct RcsVfile
{
    public:

			RcsVfile( char *fileName, int modes, int nocase,
				Error *e );
			~RcsVfile();

	void		Commit( Error *e );

	inline void	Delete() { modes |= RCS_VFILE_DELETE; }

    public:
	/* Names of files */

	FileSys		*rcsFile;
	FileSys		*writeFile;

	/* I/O descriptors */

	ReadFile 	*readFd;

	/* remembered mode */

	int 		modes;
	int		readCasefullPath;

	StrBuf		*originalFilename;	// for nocase operation
} ;
