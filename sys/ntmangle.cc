/*
 * Copyright 1995, 1997 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * ntmangle.cc -- demangle paths on NT
 */

# define WIN32_LEAN_AND_MEAN

# include <windows.h>

# include <stdhdrs.h>
# include <strbuf.h>
# include <charman.h>
# include <charset.h>
# include <error.h>
# include <ntmangle.h>

// Function to fix bogus paths.  This code produces an unmangled,
// case-correct paths for paths with case errors and 8.3 mangled names

void
NtDemanglePath( char *path83, StrBuf *dest )
{
	CharStep *p = CharStep::Create( path83, GlobalCharSet::Get() );

	dest->Clear();
	
	// Make sure that the drive letter is lower case.
	if( path83[0] && path83[1] == ':' )
	{
		if( path83[0] >= 'A' && path83[0] <= 'Z' )
			path83[0] = 'a' + ( path83[0] - 'A' );
	}

	// For each path component.

	while( *p->Ptr() )
	{
	    int here = dest->Length();
	    char *start83 = p->Ptr();

	    // Add next path component to our buffer

	    while( *p->Ptr() != '\\' && *p->Next() )
		continue;

	    dest->Append( start83, p->Ptr() - start83 );
	
	    // FindFirstFile return the long name of only the last
	    // piece of the path.
	    // Replace that last piece with FindFirstFile's results.
	    // Only do this if we're past the d:\ and if FindFirstFile
	    // actually works!

	    if( here )
	    {
		WIN32_FIND_DATA findData;
		HANDLE h = FindFirstFile( dest->Text(), &findData );

		if( h != INVALID_HANDLE_VALUE )
		{
		    dest->SetLength( here );
		    dest->Append( findData.cFileName );
		    FindClose( h );
		}
	    }

	    // If we're at a path separator, skip over it.

	    if( *p->Ptr() )
	    {
		p->Next();
		dest->Append( "\\", 1 );
	    }
	}
	delete p;
}

# ifdef TEST
# include <direct.h>

int main()
{
	char buf[1024];
	StrBuf fixed;

	long start=GetTickCount();

	for(int i=0; i<1000; i++)
		_getcwd(buf, 1024);

	long mid=GetTickCount();

	for(i=0; i< 1000; i++)
		NtDemanglePath( buf, &fixed );

	long end=GetTickCount();

	printf("Getcwd returned: %s\r\n", buf);
	printf("Long path is: %s\r\n", fixed.Text());

	printf("Getcwd ate       %ld mSecs for 1000 reps\r\n", mid-start);
	printf("Expand83Path ate %ld mSecs for 1000 reps\r\n", end-mid);

	return 0;
}

# endif
