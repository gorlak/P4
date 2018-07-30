/*
 * Copyright 2011 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>
# include <error.h>
# include <errorlog.h>
# include <strbuf.h>
# include <filesys.h>

# include "filestrbuf.h"

FileStrPtr::FileStrPtr( StrPtr *s )
{
	ptr = s;
	offset = 0;
}

void
FileStrPtr::Open( FileOpenMode mode, Error *e )
{
	if( mode == FOM_WRITE )
	    e->Set( E_FATAL, "can't write to a FileStrPtr!" );

	offset = 0;
}

int
FileStrPtr::Read( char *buf, int len, Error * )
{
	if( len < 1 )
	    return 0;

	int avail = ptr->Length() - offset;

	// Already read everything?

	if( avail < 1 )
	    return 0;

	// Asked to read more than we have?

	if( avail < len )
	{
	    memcpy( buf, ptr->Value() + offset, avail );
	    offset = ptr->Length();
	    return avail;
	}

	// Asked to read less than we have?

	memcpy( buf, ptr->Value() + offset, len );
	offset += len;
	return len;
}

void
FileStrPtr::Seek( offL_t offset, Error *e )
{
	this->offset = offset;
}

offL_t
FileStrPtr::Tell()
{
	return offset;
}

offL_t
FileStrPtr::GetSize()
{
	return ptr->Length();
}
