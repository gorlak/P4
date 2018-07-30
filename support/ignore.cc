/*
 * Copyright 1995, 2003 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 *
 * Git style ignore file for add/reconcile
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <strops.h>
# include <error.h>
# include <strarray.h>
# include <vararray.h>
# include <debug.h>

# include <pathsys.h>
# include <filesys.h>

# include <maptable.h>

# include "ignore.h"

# ifdef OS_NT
# define SLASH "\\"
# else
# define SLASH "/"
# endif

# define ELLIPSE "..."


/*
 * IgnoreTable -- cached ignore rules
 */

class IgnoreItem {
    public:
			IgnoreItem()  { ignoreList = new StrArray; }
			~IgnoreItem() { delete ignoreList; }

	void		AppendToList( StrArray *list )
			{
			    for( int i = 0; i < ignoreList->Count(); i++ )
			        list->Put()->Set( ignoreList->Get( i ) );
			}

	StrBuf		ignoreFile;
	StrArray*	ignoreList;
} ;

class IgnoreTable : public VarArray {

    public:
			~IgnoreTable();

	IgnoreItem	*GetItem( const StrRef &file );
	IgnoreItem	*PutItem( const StrRef &file );
} ;

IgnoreTable::~IgnoreTable()
{
	for( int i = 0; i < Count(); i++ )
	    delete (IgnoreItem *) Get( i );
}

IgnoreItem *
IgnoreTable::GetItem( const StrRef &file )
{
	IgnoreItem *a;

	for( int i = 0; i < Count(); i++ )
	{
	    a = (IgnoreItem *)Get(i);

	    if( !a->ignoreFile.SCompare( file ) )
	        return a;
	}

	return 0;
}

IgnoreItem *
IgnoreTable::PutItem( const StrRef &file )
{
	IgnoreItem *a = GetItem( file );

	if( !a )
	{
	    a = new IgnoreItem;
	    a->ignoreFile.Set( file );
	    VarArray::Put( a );
	}

	return a;
}


/*
 * Ignore
 *
 * Loads ignore rules from ignore files and checks to see if files match
 * those fules.
 */

Ignore::Ignore()
{
	ignoreTable = new IgnoreTable;
	ignoreFiles = new StrArray;
	ignoreList = 0;
}

Ignore::~Ignore()
{
	delete ignoreTable;
	delete ignoreFiles;
	if( ignoreList )
	    delete ignoreList;
}

int
Ignore::Reject( 
	const StrPtr &path, 
	const StrPtr &ignoreName,
	const char *configName,
	StrBuf *line )
{
	return Build( path, ignoreName, configName ) &&
	    RejectCheck( path, 0, line ) ? 1 : 0;
}

int
Ignore::RejectDir( const StrPtr &path,
	const StrPtr &ignoreName,
	const char *configName,
	StrBuf *line )
{
	return Build( path, ignoreName, configName ) &&
	    RejectCheck( path, 1, line ) ? 1 : 0;
}

int
Ignore::List( const StrPtr &path,
	const StrPtr &ignoreName,
	const char *configName,
	StrArray *outList )
{
	Build( path, ignoreName, configName );

	for( int j = 0; j < ignoreList->Count(); ++j )
	    outList->Put()->Set( ignoreList->Get( j ) );

	return outList->Count();
}


int
Ignore::GetIgnoreFiles( const StrPtr &ignoreName,
	int absolute,
	int relative,
	StrArray &ignoreFiles )
{
	StrRef slash( SLASH );
	const StrBuf *ign = 0;
	int i = 0;
	int res = 0;

	BuildIgnoreFiles( ignoreName );
	while( ( ign = this->ignoreFiles->Get( i++ ) ) )
	{
	    if( ign->Contains( slash ) && absolute )
	    {
	        ignoreFiles.Put()->Set( ign );
	        res++;
	    }
	    else if( !ign->Contains( slash ) && relative )
	    {
	        ignoreFiles.Put()->Set( ign );
	        res++;
	    }
	}

	return res;
}

int
Ignore::Build( const StrPtr &path,
	const StrPtr &ignoreName,
	const char *configName )
{
	// If we don't have an ignore file, we can just load up the defaults
	// and test against those. If we've already loaded them, lets not do
	// it again and use the existing list instead.
	
	if( !strcmp( ignoreName.Text(), "unset" ) )
	{
	    if( !ignoreList )
	        ignoreList = new StrArray;

	    if( !ignoreList->Count() )
	        InsertDefaults( ignoreList, configName );

	    return 1;
	}


	PathSys *p = PathSys::Create();
	p->Set( path );
	p->ToParent();

	StrBuf saveDepth;

	// Try real hard not to regenerate the ignorelist, this
	// optimization uses the current directory depth and the
	// last found ignorefile depth to reduce the search for
	// config files.

	if( ignoreList && dirDepth.Length() )
	{
	    if( !dirDepth.SCompare( *p ) )
	    {
	        // matching depth bail early

	        delete p;
	        return 1;
	    }
	    else if( !dirDepth.SCompareN( *p ) )
	    {
	        // descending directories can be shortcut.

	        saveDepth << dirDepth;
	    }
	    else if( !p->SCompareN( dirDepth ) &&
	             foundDepth.Length() && !foundDepth.SCompareN( *p ) )
	    {
	        // ascending directories can be shortcut.

	        dirDepth.Set( *p );
	        delete p;
	        return 1;
	    }
	    else if( !dirDepth.SCompareN( *p ) )
	    {
	        // descending directories can be shortcut.

	        saveDepth << dirDepth;
	    }
	    else if( !p->SCompareN( dirDepth ) &&
	             foundDepth.Length() && !foundDepth.SCompareN( *p ) )
	    {
	        // ascending directories can be shortcut.

	        dirDepth.Set( *p );
	        delete p;
	        return 1;
	    }
	}
	
	
	// Split the potential ignoreName list into a real list
	
	BuildIgnoreFiles( ignoreName );


	StrBuf line;
	StrBuf closestFound;
	int found = 0;
	Error e;
	PathSys *q = PathSys::Create();
	FileSys *f = FileSys::Create( FileSysType( FST_TEXT|FST_L_CRLF ) );
	IgnoreItem *ignoreItem = 0;
	const StrBuf *ignoreFile;

	closestFound.Clear();
	dirDepth.Set( *p );

	// No descending optimization, remove list we will recreate it


	StrArray newList;
	InsertDefaults( &newList, configName );

	for( int m = 0; m < ignoreFiles->Count(); m++ )
	{
	    ignoreFile = ignoreFiles->Get( m );
	    
	    if( ignoreFile->Contains( StrRef( SLASH ) ) )
	    {
	        // load the file; we have a path, so no need to wander the
	        // tree looking for it

	        if( !( ignoreItem = ignoreTable->GetItem( *ignoreFile ) ) )
	        {
	            ignoreItem = ignoreTable->PutItem( *ignoreFile );

	            f->Set( *ignoreFile );
	            if( !ParseFile( f, "", ignoreItem->ignoreList ) )
	                continue;

	            found++;
	        }

	        ignoreItem->AppendToList( &newList );

	    }
	    else
	    {
	        // starting from the directory in which the argument supplied
	        // file lives,  walk up the tree collecting ignore files as
	        // we go

	        p->Set( path );
	        p->ToParent();

	        do {
	            q->SetLocal( *p, *ignoreFile );

	            if( !( ignoreItem = ignoreTable->GetItem( *q ) ) )
	            {
	                ignoreItem = ignoreTable->PutItem( *q );

	                f->Set( *q );
	                if( !ParseFile( f, p->Text(), ignoreItem->ignoreList ) )
	                    continue;

	                found++;

	                if( closestFound.Length() < p->Length() )
	                    closestFound = *p;
	            }

	            ignoreItem->AppendToList( &newList );

	        } while( p->ToParent() );
	    }
	}

	if( closestFound.Length() && !foundDepth.SCompareN( closestFound ) )
	{
	    found++;
	    foundDepth = closestFound;
	}

	if( found || !ignoreList )
	{
	    if( ignoreList )
	        delete ignoreList;

	    ignoreList = new StrArray;

	    for( int i = 0; i < newList.Count(); i++ )
	        ignoreList->Put()->Set( newList.Get( i ) );
	}

	delete q;
	delete p;
	delete f;

	if( DEBUG_LIST )
	{
	    p4debug.printf( "\n\tIgnore list:\n\n" );
	    for( int j = 0; j < ignoreList->Count(); ++j )
	    {
	         char *p = ignoreList->Get( j )->Text();
	         p4debug.printf( "\t%s\n", p );
	    }
	    p4debug.printf( "\n" );
	}

	return 1;
}

void
Ignore::InsertDefaults( StrArray *list, const char *configName )
{
	StrArray defaultsList;
	int l = 0;

	StrBuf configDirLine;
	configDirLine.Clear();

	// Always add in .p4root and P4CONFIG to the top of new lists

	if( configName )
	{
	    StrBuf line;
	    line << "**/" << configName;
	    Insert( &defaultsList, line.Text(), "", ++l );
	    configDirLine << ".../" << configName << SLASH << "...";
	}

	Insert( &defaultsList, "**/.p4root", "", ++l );

	// Add debug line

	list->Put()->Set( StrRef( "#FILE - defaults" ) );

	// Add the generated lines to the ignore list (in reverse)

	StrBuf line;
	for( int i = defaultsList.Count(); i > 0; --i )
	{
	    if( configName && *defaultsList.Get( i - 1 ) == configDirLine )
	        continue;

	    line.Set( defaultsList.Get( i - 1 ) );
#ifdef OS_NT
	    // On NT slash is \ but the matcher's * wildcard only uses /,
	    // so we need to convert our slashes

	    StrOps::Sub( line, '\\', '/' );
#endif
	    list->Put()->Set( line );
	}
}

void
Ignore::Insert( StrArray *subList, const char *ignore, const char *cwd, int lineno )
{
	StrBuf buf;
	StrBuf buf2;
	StrBuf raw = ignore;
	const char *lastCwdChar = cwd + strlen( cwd ) - 1;
	const char *lastIgnChar = ignore + strlen( ignore ) - 1;
	char *terminating = (char *)SLASH;

	int reverse = ( *ignore == '!' );
	int isWild = strchr( ignore, '*' ) != 0;
	// One slash at the end is a sign that we're just matching directories
	int isDir = ( *lastIgnChar == *terminating );

	if( strstr( ignore, "*****" ) || strstr( ignore, "..." ) )
	    buf << "### SENSELESS JUXTAPOSITION ";

	if( reverse )
	{
	    buf << "!";
	    ignore++;
	}

	// If the ignore line starts with a slash, it's relative to this ingore file

	int isRel = ( *ignore == *terminating );
	if( isRel )
	    ignore++;

	// Add the base path - in needs a trailing / unless it's not set (global)

	buf << cwd;
	if( strlen( cwd ) && *lastCwdChar != *terminating )
	    buf << SLASH;
	
	// buf contains the relative path
	// buf2 contains the non-relative path
	// If the path is relative (starts with /) then we don't want to
	// add .../ to the start.
	// Otherwise we will need both (to include files here and in
	// directories below us)

	buf2 << buf << ELLIPSE;
	buf << ignore;

	if( !isRel && *ignore == '*' )
	{
	    // The path isn't relative, so we'll use buf2.
	    // If it starts with a * (or **) lets not add the slash.
	    // E.g. *.foo/bar -> ....foo/bar (not .../*.foo/bar)

	    while( *ignore == '*' )
	        ignore++;

	    buf2 << ignore;
	}
	else
	    buf2 << SLASH << ignore;

	if( isDir )
	{
	    // The path ends with a shash, so add the ...

	    buf << ELLIPSE;
	    buf2 << ELLIPSE;
	}

	// It's possible that we've expanded out buf2 so that we no longer
	// need buf (E.g. *.foo/bar). If the path was wild, but isn't
	// anymore, then lets not add it.

	if( isRel || !isWild || ( isWild && strchr( ignore, '*' ) != 0 ) )
	    StrOps::Replace( *subList->Put(), buf,
	                     StrRef( "**" ), StrRef( ELLIPSE ));

	if( !isRel )
	    StrOps::Replace( *subList->Put(), buf2,
	                     StrRef( "**" ), StrRef( ELLIPSE ));

	// If the path was not explicitly a directory, it might be one.
	// Unless of course it edded with a or **

	if( !isDir && !buf.EndsWith( "**", 2 ) )
	{
	    buf << SLASH << ELLIPSE;
	    buf2 << SLASH << ELLIPSE;

	    if( isRel || !isWild || ( isWild && strchr( ignore, '*' ) != 0 ) )
	        StrOps::Replace( *subList->Put(), buf,
	                          StrRef( "**" ), StrRef( ELLIPSE ));

	    if( !isRel )
	        StrOps::Replace( *subList->Put(), buf2,
	                          StrRef( "**" ), StrRef( ELLIPSE ));
	}

	// Add the debug line
	
	buf.Clear();
	buf << "#LINE " << lineno << ":" << raw;
	subList->Put()->Set( buf );
}

int
Ignore::ParseFile( FileSys *f, const char *cwd, StrArray *list )
{
	Error e;
	StrBuf line;
	StrBuf dline;
	StrArray tmpList;

	f->Open( FOM_READ, &e );
	
	if( e.Test() )
	    return 0;

	for( int l = 1; f->ReadLine( &line, &e ); l++ )
	{
	    line.TrimBlanks();
	    if( !line.Length() || line.Text()[0] == '#' )
	        continue;

	    if( line.Text()[0] == '\\' && line.Text()[1] == '#' )
	    {
	        StrBuf tmp( line.Text() + 1 );
	        line = tmp;
	    }

#ifdef OS_NT
	    // On NT slash is \ so we need to normalise our slashes to
	    // avoid cross platform issues.

	    StrOps::Sub( line, '/', '\\' );
#endif

	    Insert( &tmpList, line.Text(), cwd, l );
	}

	f->Close( &e );

	line.Clear();
	line << "#FILE " << f->Name();
	list->Put()->Set( line );

	
	// Add the read lines to the target list (in reverse)

	for( int i = tmpList.Count(); i > 0; --i )
	{
	    line.Set( tmpList.Get( i - 1 ) );

#ifdef OS_NT
	    // On NT slash is \ but the matcher's * wildcard only uses /,
	    // so we need to convert our slashes

	    StrOps::Sub( line, '\\', '/' );
#endif

	    list->Put()->Set( line );
	}

	return 1;
}

int
Ignore::RejectCheck( const StrPtr &path, int isDir, StrBuf *line )
{
	char *ignoreFile = 0;
	char *ignoreLine = 0;

	// Fix the path separators

	StrBuf cpath( path );
	StrOps::Sub( cpath, '\\', '/' );

	// Dirs must have trailing / for matching /...
	
	if( isDir && !cpath.EndsWith( "/", 1 ) )
	    cpath << "/";

	// Dirs have /... tails when checking in reverse

	StrBuf dpath( cpath );
	dpath << "...";

	for( int i = 0; i < ignoreList->Count(); ++i )
	{
	    char *p = ignoreList->Get( i )->Text();

	    if( !strncmp( p, "#FILE ", 6 ) )
	    {
	        ignoreFile = p+6;
	        continue;
	    }

	    if( !strncmp( p, "#LINE ", 6 ) )
	    {
	        ignoreLine = p+6;
	        continue;
	    }

	    int doAdd = ( *p == '!' );

	    if( doAdd )
	        ++p;

	    // If we're checking against a directory and this is a reverse
	    // include, it might allow files below this directoryt, even if
	    // this directory is ignored. To deal with this, we need to look
	    // both ways check match in either direction)

	    if( MapTable::Match( StrRef( p ), cpath ) ||
	        ( isDir && doAdd && MapTable::Match( dpath, StrRef( p ) ) ) )
	    {
	        if( DEBUG_MATCH )
	            p4debug.printf(
	                "\n\t%s[%s]\n\tmatch[%s%s]%s\n\tignore[%s]\n\n",
	                isDir ? "dir" : "file", path.Text(), doAdd ? "+" : "-",
	                p, doAdd ? "KEEP" : "REJECT", ignoreFile );

	        // If an ignoreLine pointer was passed, populate it with the
	         // ignoreFile, line number and rule that we matched.

	         if( line && ignoreFile && ignoreLine )
	         {
	             line->Set( ignoreFile );
	             line->UAppend( ":" );
	             line->UAppend( ignoreLine );
	         }

	        return doAdd ? 0 : 1;
	    }
	}

	return 0;
}


void
Ignore::BuildIgnoreFiles( const StrPtr &ignoreNames )
{
	if( ignoreStr == ignoreNames )
	    return;

	if( ignoreFiles )
	    delete ignoreFiles;

	ignoreFiles = new StrArray;


	// We might have more than one ignore file name set: split them up

	if( strchr( ignoreNames.Text(), ';' ) ||
	    ( SLASH[0] == '/' && strchr( ignoreNames.Text(), ':' ) ) )
	{
	    StrBuf iname = ignoreNames;

	    // Do some work to make sure we have the right path seaprators
	    // and normalise the split characters.

#ifdef OS_NT
	    StrOps::Sub( iname, '/', '\\' );
#else
	    StrOps::Sub( iname, '\\', '/' );
	    StrOps::Sub( iname, ':', ';' );
#endif

	    char *c;
	    char *n = iname.Text();
	    while( c = strchr( n, ';' ) )
	    {
	        if( c > n )
	            ignoreFiles->Put()->Set( StrRef( n, c - n ) );
	        n = c + 1;
	    }
	    if( strlen( n ) )
	        ignoreFiles->Put()->Set( StrRef( n, strlen( n ) ) );
	}
	else
	    ignoreFiles->Put()->Set( ignoreNames );

	ignoreStr = ignoreNames;
}
