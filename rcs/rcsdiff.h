/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsdiff.h - diff a file against a revision in an RcsArchive
 *
 * External routines:
 *
 *	RcsDiff() - make a diff file between a file and generated rev
 *
 * History:
 *	2-18-97 (seiwald) - translated to C++.
 */

# define RCS_DIFF_USER   	0x00	/* make a normal, viewable diff */
# define RCS_DIFF_RCSN  	0x01	/* make a -n diff for RCS */

# define RCS_DIFF_NORMAL	0x00	/* forward diff */
# define RCS_DIFF_REVERSE	0x02	/* reverse diff */

void	RcsDiff( RcsArchive *archive, const char *revName, 
		FileSys *fileName, const char *outFile,
		int diffType, Error *e );

