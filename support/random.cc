/*
 * Copyright 2006 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

#define NEED_TIME

// Add defined tests here as needed for build problems...

# if defined(OS_MINGW) || defined(OS_MVS) || defined(OS_AS400)
# define NEED_OLD_RAND
# endif

# if defined(OS_NT) && !defined(OS_MINGW)
# define NEED_RAND_S
# define _CRT_RAND_S
# endif

#include <stdhdrs.h>
#include <pid.h>
#include <strbuf.h>
#include "random.h"


static void
Initialize()
{
# ifndef NEED_RAND_S
	MT_STATIC int inited = 0;

	if( !inited )
	{
	    int tim = time( NULL ) ^ Pid().GetID();
# ifdef NEED_OLD_RAND
	    srand( tim );
# else
	    srandom( tim );
# endif
	    inited = 1;
	}
# endif
}

int
Random::Integer( int low, int high )
{
	Initialize();

# ifdef NEED_RAND_S
	unsigned int r;
	rand_s( &r );
	r = r >> 2;
# elif defined(NEED_OLD_RAND)
	int r = rand() >> 2;
# else
	int r = random();
# endif

	return low + r % ( high - low + 1 );
}

void
Random::String( StrBuf *b, int length, char lowchar, char hichar )
{
	Initialize();
	unsigned int rng = hichar - lowchar + 1;
	unsigned int r;
	char *p;

	b->Clear();
	p = b->Alloc( length + 1 );

	while( length-- > 0 )
	{
# ifdef NEED_RAND_S
	    rand_s( &r );
	    r = r >> 2;		// old lowest bit not random
# elif defined(NEED_OLD_RAND)
	    r = rand() >> 2;	// old lowest bit not random
# else
	    r = random();
# endif
	    *p++ = lowchar + r % rng;
	}
	*p = '\0';
	b->SetEnd( p );
}
