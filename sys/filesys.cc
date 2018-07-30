/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# define NEED_FILE
# define NEED_CHDIR

# include <stdhdrs.h>
# include <charman.h>

# include <i18napi.h>
# include <charcvt.h>
# include <charset.h>

# include <error.h>
# include <debug.h>
# include <tunable.h>
# include <strbuf.h>
# include <strops.h>
# include <md5.h>
# include <datetime.h>

# include "pathsys.h"
# include "filesys.h"
# include "macfile.h"
# include "fileio.h"
# include "signaler.h"
# include "enviro.h"
# include "errno.h"
# include "hostenv.h"
# define USE_ERRNO

# include <msgos.h>

void
FileSysCleanup( FileSys *f )
{
	if( f->IsDeleteOnClose() )
	    f->Cleanup();
}

FileSys *
FileSys::Create( FileSysType t )
{
	FileSys *f;
	LineType lt;

	// Pull the LineType out of the FileSysType.

	switch( t & FST_L_MASK )
	{
	case FST_L_LOCAL: 	lt = LineTypeLocal; break;
	case FST_L_LF:		lt = LineTypeRaw; break;
	case FST_L_CR:		lt = LineTypeCr; break;
	case FST_L_CRLF:	lt = LineTypeCrLf; break;
	case FST_L_LFCRLF:	lt = LineTypeLfcrlf; break;
	default: 		lt = LineTypeLocal; 
	}

	// Apple's an odd mod: it's a mod, but totally supplants
	// the text/binary type.  So include it in the switch.
	// The other mods don't affect the base type.

	switch( t & ( FST_MASK | FST_M_APPLE | FST_M_APPEND ) )
	{
	case FST_TEXT:		
		f = new FileIOBuffer( lt ); 
		break;
	case FST_UNICODE:
		f = new FileIOUnicode( lt ); 
		break;

	case FST_BINARY:
	    if( t & FST_C_MASK )
		f = new FileIOCompress;
	    else
		f = new FileIOBinary;
	    break;

	case FST_RESOURCE:
		f = new FileIOResource;
		break;

	case FST_APPLETEXT:
	case FST_APPLEFILE:
		f = new FileIOApple;
		break;

	case FST_SYMLINK:
	        if( SymlinksSupported() )
	            f = new FileIOSymlink;
	        else
	            f = new FileIOBinary;
		break;

	case FST_ATEXT:
		f = new FileIOAppend( lt );
		break;

	case FST_UTF8:
		f = new FileIOUTF8( lt );
		break;

	case FST_UTF16:
		f = new FileIOUTF16( lt );
		break;

	case FST_EMPTY:
	        f = new FileIOEmpty;
	        break;
	
	default:
		return NULL;
	}

	// Replace the type.

	f->type = t;

	// Arrange for temps to blow on exit.

	signaler.OnIntr( (SignalFunc)FileSysCleanup, f );

	return f;
}

FileSys::FileSys()
{
	// start off with permission bits as the umask;

	mode = FOM_READ;
	perms = FPM_RO;
	modTime = 0;
	sizeHint = 0;
	checksum = 0;
	cacheHint = 0;
	preserveCWD = 0;
	charSet = GlobalCharSet::Get();
	content_charSet = GlobalCharSet::Get();

	type = FST_TEXT;

# ifdef OS_NT
	LFN = 0;
# endif

	isTemp = 0;

# ifdef OS_CYGWIN
	// cygwin 1.3.12: rmdir() exits(!) if passwd CWD.
	preserveCWD = 1;
# endif
}

FileSys::~FileSys()
{
	// Once gone, we don't need to delete it
	// on interrupt anymore.

	signaler.DeleteOnIntr( this );
}

int
FileSys::BufferSize()
{
	return p4tunable.Get( P4TUNE_FILESYS_BUFSIZE );
}

void
FileSys::Cleanup()
{
	Error e;
	Close( &e );
	if( IsDeleteOnClose() )
	    Unlink();
}

# ifdef OS_NT
void
FileSys::SetLFN( const StrPtr &name )
{
	int lfn_val = p4tunable.Get( P4TUNE_FILESYS_WINDOWS_LFN );
	if( lfn_val )
	{
	    // For LFN nt_wname will convert from ANSI to UNICODE.
	    //
	    // Use GetCwdbyCS as it determines UTF8 or ANSI.  It
	    // also provides a better representation of cwd length.
	    if( IsRelative( name ) )
	    {
		StrBuf cwd;
		HostEnv::GetCwdbyCS( cwd, GlobalCharSet::Get());

		// If the absolute path is over 255, use LFN support.
		// If the tunable is 10, LFN is always on for Testing.
		if( lfn_val == 10 || ( cwd.Length() + name.Length() > 255 ) )
		    LFN = LFN_ENABLED;
	    }
	    else
	    {
		// Here the path is already absolute, assume a drive spec.
		if( lfn_val == 10 || ( name.Length() > 255 ) )
		    LFN = LFN_ENABLED;
	    }

	    if( LFN )
	    {
		// If UNC path, later we use "\\?\UNC" instead of "\\?\"
		if( IsUNC( name ) )
		    LFN |= LFN_UNCPATH;
	    }
	}

	// If DOUNICODE, This flag will cause nt_wname to convert
	// from UTF8 to UNICODE.
	if( DOUNICODE )
	    LFN |= LFN_UTF8;
}
# endif

void
FileSys::Set( const StrPtr &name )
{
# if defined(OS_NT) && (_MSC_VER >= 1800)
	if( name.Text()[0] != '-' )
	    SetLFN( name );
# endif
	path.Set( name );
}

void
FileSys::Set( const StrPtr &name, Error *e )
{
# ifdef OS_NT
# if (_MSC_VER >= 1800)
	if( name.Text()[0] != '-' )
	    SetLFN( name );
# endif
	if( !LFN )
	{
	    // For a relative path, this does not take into account p4root.
	    int maxLen = 260; // MAX_PATH from <windows.h>
	    if( e && name.Text() && name.Length() > maxLen )
		e->Set( MsgOs::NameTooLong ) << name <<
		    StrNum( (int)name.Length() ) << StrNum( maxLen );
	}
# endif
	path.Set( name );
}

void
FileSys::SetDigest( MD5 *m )
{
	checksum = m;
}

int
FileSys::DoIndirectWrites()
{
# if defined( OS_MACOSX )
	return ( ( type & FST_MASK ) == FST_SYMLINK );
# else
	return 1;
# endif
}

void
FileSys::Translator( CharSetCvt * )
{
}

void
FileSys::LowerCasePath()
{
	if( CharSetApi::isUnicode( (CharSetApi::CharSet)GetCharSetPriv()) )
	{
	    StrBuf res;

	    if( CharSetCvt::Utf8Fold( &path, &res ) == 0 )
	    {
		path = res;
		return;
	    }
	    // if Utf8 fold failed... fall through...
	}
	StrOps::Lower( path );
}

/*
 * FileSys::GetFd()
 * FileSys::GetSize()
 * FileSys::Seek()
 *
 * Non-functional stubs.
 */

int
FileSys::GetFd()
{
	return -1;
}

int
FileSys::GetOwner()
{
	return 0;
}

void
FileSys::StatModTimeHP(DateTimeHighPrecision *modTime)
{
	*modTime = DateTimeHighPrecision();
}

bool
FileSys::HasOnlyPerm( FilePerm perms )
{
	return true;
}

offL_t
FileSys::GetSize()
{
	return 0;
}

void
FileSys::Seek( offL_t offset, Error * )
{
}

offL_t
FileSys::Tell()
{
	return 0;
}

/*
 * FileSys::Perms() - translate permission
 */

FilePerm
FileSys::Perm( const char *perms )
{
	return strcmp( perms, "rw" ) ? FPM_RO : FPM_RW;
}

static int ContainsTraversal( const char *p )
{
	while( p && *p )
	{
	    if( p[0] == '.' && p[1] == '.' &&
		( p[2] == '\0' || p[2] == '/'
# ifdef OS_NT
		|| p[2] == '\\'
# endif
		    ) )
	        return 1;
	    do {
		if( *++p == '/'
# ifdef OS_NT
		    || *p == '\\'
# endif
		    )
		{
		    ++p;
		    break;
		}
	    } while( *p != '\0' );
	}
	return 0;
}


bool
FileSys::IsRelative( const StrPtr &path )
{
	const char *p = path.Text();

	if( *p == '/' )
	    return false;
#ifdef OS_NT
	if( *p == '\\' )
	    return false;
	if( p[0] && p[1] == ':' )
	    return false;
#endif
	return true;
}

#ifdef OS_NT
bool
FileSys::IsUNC( const StrPtr &path )
{
	const char *p = path.Text();

	// At a minimum we are looking for "\\host\share".
	if( (p[0] == '/' || p[0] == '\\') && (p[1] == '/' || p[1] == '\\') )
	{
	    if( strchr( &(p[2]), '/' ) || strchr( &(p[2]), '\\' ) )
		return true;
	}
	return false;
}
#endif

static int UnderRootCheck( const char *name, const char *root, int rootLen )
{
	int result;
	PathSys *p = PathSys::Create();
	p->Set( name );
	StrBuf r;
	if( *root == '.' )
	{
	    HostEnv h;
	    Enviro e;
	    StrBuf b;
	    h.GetCwd( b, &e );
	    r << b << StrRef( root + 1, rootLen - 1 );
	}
	else
	    r.Set( root, rootLen );

	result = p->IsUnderRoot( r );

	delete p;

	return result;
}

/**
 * FileExists
 *
 * @brief Verify that the file exists
 *
 * @param  filepath
 * @return boolean true if exists false otherwise
 * @throws
 */
bool
FileSys::FileExists( const char *filepath )
{
	if( !filepath )
	    return false;

	FileSys *f = FileSys::Create( FST_BINARY );
	f->Set( filepath );
	if( f->Stat() & FSF_EXISTS )
	{
	    delete f;
	    return true;
	}
	delete f;
	return false;
}

// NeedMkDir - Checks if the parent directory exists
bool
FileSys::NeedMkDir()
{
	PathSys *path = PathSys::Create();
	path->Set( Path() );
	path->ToParent();
	bool res = ! FileSys::FileExists( path->Text() );
	delete path;
	return res;
}

// Enforces P4CLIENTPATH restrictions
int
FileSys::IsUnderPath( const StrPtr &roots )
{
	if( roots.Length() == 0 )
	    return 1;

	HostEnv h;
	Enviro e;
	StrBuf b;
	const char *n = Name();
	if( ContainsTraversal( n ) )
	    return 0;
	if( IsRelative( StrRef( n ) ) )
	{
	    h.GetCwd( b, &e );
	    n = b.Text();
	}

	char listSep = ';';
	const char *p = roots.Text();
	const char *s = p;
	while( *p )
	{
	    if( *p == listSep )
	    {
	        if( p != s )
	        {
	            if( UnderRootCheck( n, s, p - s ) )
	                return 1;
	        }
	        s = p + 1;
	    }
	    p++;
	}
	if( p != s )
	    return UnderRootCheck( n, s, p - s );
	return 0;
}
