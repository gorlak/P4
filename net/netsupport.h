// -*- mode: C++; tab-width: 4; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/*
 * Copyright 2011 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * netsupport - Utility definitions for network support
 *
 * Symbols Defined:
 *
 * RAF_NAME, RAF_PORT
 * - Address translation option flags
 *   These are also defined in "rpc/rpc.h" so
 *   that rpc clients don't need access to " net / * ";
 *   this is arguably wrong, but it's the way it is.
 *   Making net use the rpc definitions would create
 *   a circular dependency.  Perhaps the correct fix
 *   is to make rpc and all of its clients dependent
 *   on net and use the definitions here, but that's
 *   ugly too.  So for now we'll leave the duplicate
 *   definitions and just be careful (these names and
 *   values are very stable).
 *   NB: These names and values must match those in
 *   "rpc/rpc.h".
 */

# define RAF_NAME 0x01    // get symbolic name
# define RAF_PORT 0x02    // append port number
