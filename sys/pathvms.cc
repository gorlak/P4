/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * PathVMS - pathname manipuation for VMS.
 *
 * What a VMS pathname looks like:
 *
 *	device:[dir.dir.dir]file.suffix
 *
 * Suffix note: 
 *
 *	VMS has a penchange for providing a (wrong) file suffix when none 
 *	is present.  To deal with this, the routines which produce local 
 *	file names (SetCanon() and SetLocal()) append a . if 
 *	none is present, and GetCanon() strip it if it is the 
 *	last character in the file name.  This makes it not possible to 
 *	refer to a file that just ends in . in the depot, though.
 *
 * Methods defined:
 *
 *	PathSys::SetCanon() - combine (local) root and canonical path
 *
 *	    ROOT		PATH		RESULT
 *	    -----------------------------------------------
 *	    x:[d1.d2]		+ f		x:[d1.d2]f
 *	    x:[d1.d2]		+ d3/f		x:[d1.d2.d3]f
 *	    x:[000000]		+ f		x:[000000]f
 *	    x:[000000]		+ d3/f		x:[d3]f
 *
 *	PathSys::SetLocal() - combine (local) root and local path
 *
 *	    CWD			PATH		RESULT
 *	    -----------------------------------------------
 *	    x:[d1.d2]		+ f		x:[d1.d2]f
 *	    x:[d1.d2]		+ [.d3]f	x:[d1.d2.d3]f
 *	    x:[d1.d2]		+ [d3]f		x:[d3]f
 *	    x:[d1.d2]		+ x2:[d3]f	x2:[d3]f
 *	    x:[000000]		+ f		x:[000000]f
 *	    x:[000000]		+ [d3]f		x:[d3]f
 *	    x:[000000]		+ [.d3]f	x:[d3]f
 *
 *	    x:[d1.d2]		+ [-]f		x:[d1]f
 *	    x:[d1.d2]		+ [--]f		x:[000000]f
 *	    x:[d1.d2]		+ [---]f	x:[000000]f
 *	    x:[d1.d2]		+ [-.d3]f	x:[d1.d3]f
 *
 *	    logical:		+ f		logical:f
 *
 *	PathSys::GetCanon() - strip root and return rest as canon
 *
 *	    ROOT		PATH		RESULT
 *	    -----------------------------------------------
 *	    x:[d1.d2]		- x:[d1.d2]f	f
 *	    x:[d1]		- x:[d1.d2]f	d2/f
 *	    x:[000000]		- x:[000000]f	f
 *	    x:			- x:[d1]f	d1/f
 *
 *	PathSys::ToParent() - strip last element of path
 *
 *	    PATH		PARENT
 *	    -----------------------------------------------
 *	    x:[d1.d2]f		x:[d1.d2]
 *	    x:[d1.d2]		x:[d1]
 *	    x:[d1]		x:[000000]
 *	    x:[000000]		x:[000000]
 *
 * Private methods:
 *
 * 	PathVMS::GetPointers() - set up pointers to the []'s in the path
 * 	PathVMS::ToRoot() - reset the path to be the root dir on the device
 * 	PathVMS::AddDirectory() - add a directory component onto end of path
 *
 */

# include <stdhdrs.h>
# include <ctype.h>

# include <error.h>
# include <strbuf.h>
# include <pathsys.h>
# include <pathvms.h>

/*
 * PathVMS::GetPointers() - set up pointers to the []'s in the path
 */

void
PathVMS::GetPointers()
{
	char *l, *r;

	if( ( l = strchr( Text(), '[' ) ) && ( r = strchr( l, ']' ) ) )
	{
	    lbrace = l - Text();
	    rbrace = r - Text();
	    atroot = r - l == 7 && !strncmp( "[000000]", l, 8 );
	}
	else
	{
	    // no braces mean it's "logical:" -- we're at the root
	    lbrace = rbrace = -1;
	    atroot = 1;
	}
}

int
PathVMS::IsUnderRoot( const StrPtr &root )
{
	return 0;
}

/*
 * PathVMS::ToRoot() - reset the path to be the root dir on the device
 */

void
PathVMS::ToRoot()
{
	// If there are no braces, we can't go to the e
	// root ('cause we're already there)

	if( lbrace >= 0 )
	{
	    SetLength( lbrace );
	    Append( "[000000]" );
	    rbrace = Length() - 1;
	}
	atroot = 1;
}

/*
 * PathVMS::AddDirectory() - add a directory component onto end of path
 */

void
PathVMS::AddDirectory( const char *dir, int len )
{
	// logical + dir = logical:[dir]
	// dev:[000000] + dir = dev:[dir]
	// dev:[dir0] + dir = dev:[dir0.dir]

	if( lbrace < 0 )
	{
	    lbrace = Length();
	    Append( "[" );
	    atroot = 0;
	}
	else if( atroot )
	{
	    SetLength( lbrace + 1 );
	    atroot = 0;
	}
	else
	{
	    SetLength( rbrace );
	    Append( "." );
	}

	// Append directory

	Append( dir, len );

	// Set new rbrace

	rbrace = Length();

	// Append closing brace

	Append( "]" );
}

/*
 * PathSys::ToParent() - strip last element of path
 */

int
PathVMS::ToParent( StrBuf *file )
{
	GetPointers();

	if( file )
	    file->Set( Text() + rbrace + 1 );

	return ToParentHavePointers();
}

int
PathVMS::ToParentHavePointers()
{
	// Actually, lbrace<0 implies atroot (i.e. implies logical:)
	// But we like to be safe.

	if( lbrace < 0 || atroot )
	    return 0;

	// Truncate filename if there is one.

	if( Length() > rbrace + 1 )
	{
	    SetLength( rbrace + 1 );
	    // geeze, shouldn't SetLength do this?
	    Terminate();	
	    return 1;
	}

	// Look for previous directory name

	while( --rbrace > lbrace )
	    if( Text()[rbrace] == '.' )
		break;

	// If it's there, back over it.
	// Else, set to root.

	if( rbrace > lbrace )
	{
	    SetLength( rbrace );
	    Append( "]" );
	}
	else
	{
	    ToRoot();
	}

	return 1;
}

/*
 * PathSys::SetCanon() - combine local root and canonical path
 */

void
PathVMS::SetCanon( const StrPtr &root, const StrPtr &canon )
{
	// Step 1: use root as basis, but find the pieces.

	if( &root != this )
	    Set( root );

	GetPointers();

	// Step 2: Add each directory component

	const char *c;
	const char *cn = canon.Text();

	for( ; c = strchr( cn, '/' ); cn = c + 1 )
	    AddDirectory( cn, c - cn );

	// Step 3: add file component

	Append( cn );

	// Step 4: append . if none in file name

	if( !strchr( cn, '.' ) )
	    Append( ".", 1 );
}

/*
 * PathSys::SetLocal() - combine (local) root and local path
 */

void
PathVMS::SetLocal( const StrPtr &root, const StrPtr &localptr )
{
	// Step 1: if local has a ":" in it, just use local wholesale.

	if( strchr( localptr.Text(), ':' ) )
	{
	    Set( localptr );
	    return;
	}

	// Step 2: use root as basis, but find the pieces.

	if( this != &root )
	    Set( root );

	GetPointers();

	// Step 3: handle directory stuff "[xxxx]"

	const char *local = localptr.Text();

	if( local[0] == '[' )
	{
	    // If it isn't [-xxx] or [.xxx], we start at the root

	    ++local;
	    if( *local != '-' && *local != '.' )
		ToRoot();

	    // Handler [-whatever]

	    for( ; *local == '-'; ++local )
		ToParentHavePointers();

	    // We've already accounted for a leading .

	    if( *local == '.' )
		++local;

	    // Now tack on directories, dot by dot, until we hit ]

	    const char *rbrack = strchr( local, ']' );
	    const char *d;

	    // Directories before .

	    while( ( d = strchr( local, '.' ) ) && d < rbrack )
	    {
		AddDirectory( local, d - local );
		local = d + 1;
	    }

	    // Directory before ]

	    if( local < rbrack )
		AddDirectory( local, rbrack - local );

	    if( rbrack )
		local = rbrack + 1;
	}

	// Step 4: add file

	Append( local );

	// Step 5: append . if none in file name

	if( !strchr( local, '.' ) )
	    Append( ".", 1 );
}

/*
 * PathSys::GetCanon() - strip root and return rest as canon
 */

int
PathVMS::GetCanon( const StrPtr &root, StrBuf &target )
{
	const char *r = root.Text();
	const char *s = Text();
	const char *t;

	// Step 1: See how far strings match.

	while( *s && tolower( *s ) == tolower( *r ) )
	    ++s, ++r;

	// Root (r) must match entirely or to its ].
	// If matched to its ], then remaining path (s) must be .xxx]

	if( *r != ']' ? *r : *s++ != '.' )
	    return 0;

	// Root (r) may not have had a [] component, which leaves 
	// remaining path (s) beginning with a [.  Strip it.

	if( !*r && *s == '[' )
	    ++s;

	// Step 2: Tack on directory components, separated by /'s

	if( *s )
	    target.Append( "/" );

	// 2a: directories before .'s

	const char *rbrack = strchr( s, ']' );

	while( ( t = strchr( s, '.' ) ) && t < rbrack )
	{
	    target.Append( s, t - s );
	    target.Append( "/" );
	    s = t + 1;
	}

	// 2b: directory before ]

	if( s < rbrack )
	{
	    target.Append( s, rbrack - s );
	    target.Append( "/" );
	}

	if( rbrack )
	    s = rbrack + 1;

	// Step 3: Add file, stripping a trailing .

	if( !( t = strchr( s, '.' ) ) || t[1] )
	    t = s + strlen( s );

	target.Append( s, t - s );

	return 1;
}
