/*
 * Copyright 2018 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <string>
# include <stdhdrs.h>
# include <error.h>
# include <strbuf.h>

# include "errorlua.h"

std::string ErrorLua::Fmt()
{
	StrBuf fmt;
	Error::Fmt( &fmt );
	return std::string( fmt.Text() );
}

const bool ErrorLua::Test()
{
	return Error::Test() ? true : false;
}

void ErrorLua::Clear()
{
	Error::Clear();
}
