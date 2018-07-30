/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsdebug.h - define debugging symbols
 */

# define DEBUG_ANY		( p4debug.GetLevel( DT_RCS ) >= 2 )
# define DEBUG_REVNUM		( p4debug.GetLevel( DT_RCS ) >= 2 )
# define DEBUG_CORE		( p4debug.GetLevel( DT_RCS ) >= 4 )
# define DEBUG_EDIT		( p4debug.GetLevel( DT_RCS ) >= 2 )
# define DEBUG_EDIT_FINE	( p4debug.GetLevel( DT_RCS ) >= 3 )
# define DEBUG_PARSE		( p4debug.GetLevel( DT_RCS ) >= 2 )
# define DEBUG_PARSE_FINE	( p4debug.GetLevel( DT_RCS ) >= 4 )
# define DEBUG_CKIN		( p4debug.GetLevel( DT_RCS ) >= 2 )
# define DEBUG_VFILE		( p4debug.GetLevel( DT_RCS ) >= 2 )

