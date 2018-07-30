/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * PathNT - pathname manipuation for NT.
 *
 * This code go to great troubles to permit both / and \ anywhere.
 */

# include <stdhdrs.h>
# include <charman.h>
# include <charset.h>

# include <error.h>
# include <strbuf.h>
# include <pathsys.h>
# include <pathnt.h>

static inline int isSlash( char c ) { return c == '/' || c == '\\'; }

PathNT::PathNT()
: charset( GlobalCharSet::Get() )
{}

void
PathNT::SetCharSet( int x )
{
	charset = x;
}

int
PathNT::EndsWithSlash() const
{
	int r = 0;
	CharStep *s = CharStep::Create( Text(), charset );

	for( char *ep = End(); s->Ptr() < ep; s->Next() )
	    r = isSlash( *s->Ptr() );
	
	delete s;

	return r;
}

int
PathNT::IsUnder( StrRef *path, const char *under ) const
{
	CharStep *s, *u;

	s = CharStep::Create( path->Text(), charset );
	u = CharStep::Create( (char *)under, charset );
	int lastuslash = 0;

	while( *s->Ptr() && ( toAlower( s->Ptr() ) == toAlower( u->Ptr() ) || 
			isSlash( *s->Ptr() ) && isSlash( *u->Ptr() ) ) )
	{
	    lastuslash = isSlash( *u->Ptr() );
	    s->Next();
	    u->Next();
	}

	if( *u->Ptr() || *s->Ptr() && !lastuslash && !isSlash( *s->Ptr() ) )
	{
	    delete u;
	    delete s;
	    return 0;
	}

	if( isSlash( *s->Ptr() ) )
	    s->Next();

	// move past initial substring 'under'

	path->Set( s->Ptr(), path->Text() + path->Length() - s->Ptr() );

	delete u;
	delete s;
	return 1;
}

int
PathNT::IsUnderRoot( const StrPtr &root )
{
	StrRef pathTmp( *this );
	return IsUnder( &pathTmp, root.Text() );
}

void
PathNT::SetLocal( const StrPtr &root, const StrPtr &local )
{
	// The goal here is to sensibly append 'root' and 'local' to
	// form a path.  All of these paths are in NT syntax.  

	StrBuf r; r.Set( root );
	StrRef l( local );
	Clear(); // After saving root, because root may == *this

	// Whose drive (x:) should we use, from root or from local?

	// If local has a drive, use it.
	// If local is in UNC, use no drive.
	// If root has a drive, use it.

	if( l.Length() >= 2 && l.Text()[1] == ':' )
	{
	    Set( l.Text(), 2 );
	    l.Set( l.Text() + 2, l.Length() - 2 );
	}
	else if( l.Length() >= 2 && l.Text()[0] == '\\' && l.Text()[1] == '\\' )
	{
	    // Local is UNC.  Don't use root's drive.
	}
	else if( r.Length() >= 2 && r.Text()[1] == ':' )
	{
	    Set( r.Text(), 2 );
	    StrBuf t( r );
	    r.Set( t.Text() + 2, t.Length() - 2 );
	}

	// If local is rooted, root is irrelevant.

	if( l.Length() && isSlash( l.Text()[0] ) )
	{
	    Append( &l );
	    return;
	}

	// Start with root.
	// Climb up root for every .. in local

	Append( &r );

	for(;;)
	{
	    if( IsUnder( &l, ".." ) ) ToParent();
	    else if( !IsUnder( &l, "." ) ) break;
	}

	// Ensure local (if any) is separated from root with backslash.

	if( Length() && !EndsWithSlash() && l.Length() )
	    Append( "\\", 1 );

	Append( &l );
}

void
PathNT::SetCanon( const StrPtr &root, const StrPtr &canon )
{
	// Start off with root.
	// Treat a root of "null" as the empty string

	Clear();
	if( root != "null" )
	    Set( root );

	// Separate with \ (if root didn't end in one)

	if( Length() && !EndsWithSlash() )
	    Append( "\\", 1 );

	int len = Length();
	Append( &canon );

	// Replace canon's / with NT's \\ (slash to backslash)

	for( ; len < Length(); ++len )
	{
	    if( Text()[len] == '/' )
		Text()[len] = '\\';
	}
}

int
PathNT::GetCanon( const StrPtr &root, StrBuf &target )
{
	// Strip (local) root from (local) path, and place (canonized)
	// result into target.

	StrRef here;
	here.Set( this );

	// Treat a root of "null" as the empty string.

	if( root != "null" && !IsUnder( &here, root.Text() ) )
	    return 0;

	if( here.Length() && here.Text()[0] != '/' )
	    target.Append( "/", 1 );
	
	int len = target.Length();

	target.Append( &here );	// XXX No translation on NT

	// Replace NT's \\ with canon /

	CharStep *s = CharStep::Create( target.Text() + len, charset );
	
	for ( char *ep = s->Ptr() + target.Length() - len;
			 s->Ptr() < ep; s->Next() )
	{
	    if (*s->Ptr() == '\\')
		*s->Ptr() = '/';
	}
	
	delete s;

	return 1;
}

int
PathNT::ToParent( StrBuf *file )
{
	char *start = Text();
	char *end = start + Length();
	char *oldEnd = end;

	CharStep *s = CharStep::Create( start, charset );

	// Path is not normalized, account for both '/' and '\'

	if( start[0] && start[1] == ':' )
	{
	    // Don't allow climbing above a drive spec (C:\)

	    s->Next(); s->Next();
	}
	else if( ( start[0] == '\\' && start[1] == '\\' ) ||
		( start[0] == '/' && start[1] == '/' ) )
	{
	    // Don't allow climbing above a UNC root '\\host\share\'

	    int cnt=0;

	    s->Next(); s->Next();

	    while ( s->Ptr() < end )
	    {
		if ( isSlash(*s->Ptr()) && ++cnt == 2 )
		    break;

		s->Next();
	    }

	}

	// Don't allow us to climb up past /, the root already exists

	if( isSlash( *s->Ptr() ) )
	    s->Next();

	start = s->Ptr();
	char *slast, *snotquitelast;
	slast = snotquitelast = NULL;

	while ( s->Ptr() < end )
	{
	    if ( isSlash(*s->Ptr()) )
	    {
		snotquitelast = slast;
		slast = s->Ptr();
	    }
	    s->Next();
	}

	delete s;

	if( slast + 1 == end )
	    slast = snotquitelast;

	if ( slast )
	{
	    end = slast;

	    if ( file )
		file->Set( end + 1, oldEnd - end - 1 );
	}
	else
	{
	    end = start;

	    if ( file )
		file->Set( end, oldEnd - end );
	}

	SetEnd( end );
	Terminate();

	return end != oldEnd;
}

