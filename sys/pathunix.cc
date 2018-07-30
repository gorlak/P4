/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include <error.h>
# include <strbuf.h>
# include <pathsys.h>
# include <pathunix.h>

static int
IsUnder( StrRef *path, const char *under )
{
	char *s = path->Text();

	while( *s && StrRef::SEqual( *s, *under ) )
	    ++s, ++under;

	if( *under || under[-1] != '/' && *s && *s++ != '/' )
	    return 0;

	// move past initial substring 'under'

	path->Set( s, path->Text() + path->Length() - s );

	return 1;
}

int
PathUNIX::IsUnderRoot( const StrPtr &root )
{
	StrRef pathTmp( *this );
	return IsUnder( &pathTmp, root.Text() );
}

void
PathUNIX::SetLocal( const StrPtr &root, const StrPtr &local )
{
	if( local[0] == '/' )
	{
	    Set( local );
	}
	else
	{
	    // Allow SetLocal( this, ... )

	    if( this != &root )
		Set( root );

	    StrRef l( local );

	    // back off our path value while eating local's '..'s

	    for(;;)
	    {
		if( IsUnder( &l, ".." ) ) ToParent();
		else if( !IsUnder( &l, "." ) ) break;
	    }

	    // Ensure local (if any) is separated from root with /.

	    if( Length() && ( Text()[ Length() - 1 ] != '/' ) && l.Length() )
		Append( "/", 1 );

	    Append( &l );
	}
}

void
PathUNIX::SetCanon( const StrPtr &root, const StrPtr &canon )
{
	Set( root );
	// Separate with / (if root didn't end in one)

	if( !Length() || Text()[ Length() - 1 ] != '/' )
	    Append( "/", 1 );

	Append( &canon );	// No translation on UNIX
}

int
PathUNIX::GetCanon( const StrPtr &root, StrBuf &target )
{
	StrRef here;
	here.Set( this );

	if( !IsUnder( &here, root.Text() ) )
	    return 0;

	if( here.Length() && here.Text()[0] != '/' )
	    target.Append( "/", 1 );
	
	target.Append( &here );	// XXX No translation on UNIX

	return 1;
}

int
PathUNIX::ToParent( StrBuf *file )
{
	char *start = Text();
	char *end = start + Length();
	char *oldEnd = end;

	// Don't allow us to climb up past /

	if( start[0] == '/' )
	    ++start;

	if( end > start && end[-1] == '/' )
	    --end;
	while( end > start && end[-1] != '/' )
	    --end;

	if( file )
	    file->Set( end, oldEnd - end );

	if( end > start && end[-1] == '/' )
	    --end;

	SetEnd( end );
	Terminate();

	return end != oldEnd;
}
