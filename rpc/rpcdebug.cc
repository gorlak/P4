/**
 * @file rhdebug.cc
 *
 * @brief 
 *
 * @date   May 14, 2013
 * @author wheffner
 *
 * Copyright (c) 2013 Perforce Software  
 * Confidential.  All Rights Reserved.
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <strdict.h>
# include <strtable.h>
# include <strops.h>
# include <error.h>
# include <debug.h>
# include "rpcdebug.h"

void DumpError( Error &e, const char *func )
{
	StrBuf buf;
	e.Fmt( buf, EF_NEWLINE );
	StrBuf msg = "Error in ";
	msg << func << ": " << buf << "\n";

	p4debug.printf( msg.Text() );
}
