/*
 * Copyright 2001 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * ResvMem() - is there plenty of memory around?
 *
 * Just allocates and frees plentyMem, to be a little more confident
 * the process can grow that far.
 */

int ResvMem( int plentyMem, int plentyMem2 );

int SetStackSize( int stack_size );
