/*
 * Copyright 2018 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

class ErrorLua : public Error
{
	public:

	    std::string Fmt();

	    const bool Test();

	    void Clear();
} ;
