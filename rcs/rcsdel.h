/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsdel.h - delete revision in RcsArchive with a new revision
 */

/*
 * RcsDelete() - create a post-head revision/replace the head revision
 */

int RcsDelete( RcsArchive *archive, const char *oldRev, Error *e );
