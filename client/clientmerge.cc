/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include <strbuf.h>
# include <error.h>
# include <handler.h>

# include <filesys.h>

# include "clientuser.h"
# include "clientmerge.h"
# include "clientmerge2.h"
# include "clientmerge3.h"

// ClientMerge::Create with two types preserved for old API users.

ClientMerge *
ClientMerge::Create( ClientUser *ui,
		     FileSysType type,
		     FileSysType resType,
		     MergeType mt )
{
	return Create( ui, type, resType, resType, type, mt );
}

ClientMerge *
ClientMerge::Create( ClientUser *ui,
		     FileSysType type,
		     FileSysType resType,
		     FileSysType theirType,
		     FileSysType baseType,
		     MergeType mt )
{
	switch( mt )
	{
	case CMT_BINARY: return new ClientMerge2
		( ui, type, theirType );
	default:
	case CMT_3WAY: return new ClientMerge3
		( ui, type, resType, theirType, baseType );
	case CMT_2WAY: return new ClientMerge32
		( ui, type, resType, theirType, baseType );
	}
}

ClientMerge::~ClientMerge()
{
}

int
ClientMerge::Verify( const Error *message, Error *e )
{
	StrBuf buf;
	message->Fmt( buf, EF_PLAIN );

	for(;;)
	{
	    ui->Prompt( buf, buf, 0, e );

	    if( e->Test() ) 
		return 0;

	    switch( buf[0] )
	    {
	    case 'Y':
	    case 'y':
		return 1;

	    case 'n':
	    case 'N':
		return 0;
	    }
	}
}

