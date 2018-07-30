/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * PathMac - pathname manipuation for Mac.
 *
 * Mac file syntax, for the dumb:
 *
 *	vol:dir1:dir2:file
 *
 * If it's:
 *
 *	f 		-> vol:dir1:dir2:file
 *	:dir3:f		-> vol:dir1:dir2:dir3:f		
 *	::f		-> vol:dir1:f		
 *	:::f		-> vol:f
 *	::::f		-> vol:f
 *
 * Directories should end with :, but that is not required.
 *
 * Files should not begin with .'s or have :'s in them.
 */

# include <stdhdrs.h>
# include <ctype.h>

# include <error.h>
# include <strbuf.h>
# include <pathsys.h>
# include <pathmac.h>

/*
 * IsUnder( path, root ) - is 'path under 'root'?
 */

static int
IsUnder( StrRef *path, const char *root )
{
	char *s = path->Text();

	// Make sure initial string matches
	// s=foo:bar:ola root=foo:bar -> s=ola
	// s=foo:bar:ola root=foo:bar: -> s=:ola

	while( *s && ( tolower( *s ) == tolower( *root ) ) )
	    ++s, ++root;

	// Make sure we ended at the end of root, and at a : in path.

	if( *root || root[-1] != ':' && *s && *s++ != ':' )
	    return 0;

	// Reset path to exclude initial 'root' substring.

	path->Set( s, path->Text() + path->Length() - s );

	return 1;
}

int
PathMAC::IsUnderRoot( const StrPtr &root )
{
	StrRef pathTmp( *this );
	return IsUnder( &pathTmp, root.Text() );
}

void
PathMAC::SetLocal( const StrPtr &root, const StrPtr &local )
{
	// (local) root + (local) local -> absolute local path
	// local may be relative.

	if( local[0] != ':' && strchr( local.Text(), ':' ) )
	{
	    // Absolute path - foo:bar but not :foo:bar

	    Set( local );
	}
	else
	{
	    // Relative path - :foo:bar, ::foo:bar, or just bar
	    // Start with root; allow SetLocal( this, ... )

	    if( this != &root )
		Set( root );

	    StrRef l( local );

	    // Leading : indicated relative path; skip it

	    if( l[0] == ':' )
		l += 1;

	    // Each leading : left in path means up a directory in root.

	    while( IsUnder( &l, ":" ) )
		ToParent();

	    // Ensure local (if any) is separated from root with :.

	    if( !Length() || ( Text()[ Length() - 1 ] != ':' ) && l.Length() )
		Append( ":", 1 );

	    // Finally, append what's left of local.

	    Append( &l );
	}
}

void
PathMAC::SetCanon( const StrPtr &root, const StrPtr &canon )
{
	// (local) root + (canon) canon -> absolute local path
	// canon cannot be relative.

	// Start with root

	Set( root );

	// Separate with : (if root didn't end in one)

	if( !Length() || Text()[ Length() - 1 ] != ':' )
	    Append( ":", 1 );

	// Remember starting point of canon

	int len = Length();

	// Append canon and canon / with MAC's :

	Append( &canon );

	for( ; len < Length(); ++len )
	{
	    if( Text()[len] == '/' )
		Text()[len] = ':';
	}
}

int
PathMAC::GetCanon( const StrPtr &root, StrBuf &target )
{
	// (local) this - (local) root = (canon) target
	// this and root are absolute paths.

	// We start with our local syntax path

	StrRef here;
	here.Set( this );

	// We strip off the root, leaving the relative path.

	if( !IsUnder( &here, root.Text() ) )
	    return 0;

	// If there is no relative path left, leave target as is.

	if( !here.Length() )
	    return 1;

	// Separate 'this' from target with /
	// We shouldn't need this check, but if someone enters
	// a rel path beginning with a /, we don't want two

	if( here.Text()[0] != '/' )
	    target.Append( "/", 1 );

	// Target gets appended with canonical relative path
	// Replace MAC's : with canon /

	int len = target.Length();

	target.Append( &here );

	for( ; len < target.Length(); ++len )
	{
	    if( target.Text()[len] == ':' )
		target.Text()[len] = '/';
	}
	
	return 1;
}

int
PathMAC::ToParent( StrBuf *file )
{
	char *start = Text();
	char *end = start + Length();
	char *oldEnd = end;

	// strip off trialing :
	// find preceeding :
	// Save file
	// strip preceeding :

	if( end > start && end[-1] == ':' )
	    --end;
	while( end > start && end[-1] != ':' )
	    --end;

	if( file )
	    file->Set( end, oldEnd - end );

	if( end > start && end[-1] == ':' )
	    --end;

	// If there was no :, we can't go to the parent.

	if( end == oldEnd || end == start )
	    return 0;

	SetEnd( end );
	Terminate();

	return 1;
}
