/*
 * Copyright 1995, 2014 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include <strbuf.h>
# include <strops.h>
# include <enviro.h>
# include <error.h>

# include <filesys.h>

# include "clientuser.h"
# include "clientusernull.h"

/*
 * ClientUserNULL -- version of output that always to stdout
 */

void
ClientUserNULL::HandleError( Error *e )
{
	if( return_error )
	{
	    *return_error = *e;
	    return_error->Snap();
	}
}

void
ClientUserNULL::OutputError( const char * )
{
}

void
ClientUserNULL::OutputInfo( char, const char * )
{
}

void
ClientUserNULL::OutputText( const char *, int )
{
}

void
ClientUserNULL::OutputTag( const char *, const char *, int )
{
}
