/*
 * Copyright 2001 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# define NEED_BRK

# include <stdhdrs.h>

# include <resvmem.h>

# ifdef OS_LINUX

#   include <sys/resource.h>

# endif

/*
 * ResvMem() - is there plenty of memory around?
 *
 * Note that using malloc() for this is usually bad, because we're
 * asking for a large power of 2, and malloc usually does some ugly
 * rounding (after adding its header).
 */

int
ResvMem( int plentyMem, int plentyMem2 )
{
# ifdef HAVE_BRK

	// Use sbrk() to allocate and relinquish memory,
	// just to make sure it is there.

	plentyMem += plentyMem2;
	
	if( sbrk( plentyMem ) == (char *)-1 )
	    return 0;

	sbrk( - plentyMem );

# else

	// No sbrk() -- just use malloc/free.
	// shrink plentyMem to allow for a header

	void *p;
	void *p2;

	if( plentyMem > 1024 )
	    plentyMem -= 32;

	if( !( p = malloc( plentyMem ) ) )
	    return 0;

	if( plentyMem2 )
	{
	    if( !( p2 = malloc( plentyMem2 ) ) )
	    {
	        free( p );
	        return 0;
	    }
	    free( p2 );
	}

	free( p );

# endif
	
	return 1;
}

/*
 * Set the process stack size 
 *
 * this has only been adaquatly tested under linux, so
 * its only implemented there...
 *
 * Really only works on 64 bit platforms, as the stack
 * on the 32 bit is set to the max allowed...
 *
 * this won't reduce the stack, or set it above the max
 * because this seemed unreliable durring testing.
 */
int SetStackSize( int size )
{

# ifdef OS_LINUX
	if( size )
	{
	    long ssize;
	    struct rlimit limInfo;

	    if( size == 0 )
		return ( -1 );

	    ssize = 1024L * size ;

	    getrlimit( RLIMIT_STACK, &limInfo );

	    if( ssize > limInfo.rlim_max )
		ssize = limInfo.rlim_max;

	    limInfo.rlim_cur = ssize;
	    
	    setrlimit( RLIMIT_STACK, &limInfo );
 	}
# endif
	return ( 0 );
}
