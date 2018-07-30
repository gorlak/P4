/*
 * Copyright 1995, 2007 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * ntinvargs.h -- handle C runtime invalid parameters
 *
 * Classes:
 *
 *	NtInvArgs - Static constructor setup of a C runtime invalid
 *		  parameter handler.  Only one per application.
 *
 */


class NtInvArgs {

    public:

		NtInvArgs();

    private:

		static const int i=0;

} ;

