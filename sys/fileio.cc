/*
 * Copyright 1995, 2003 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * fileio -- FileIO, FileIOBinary, FileIOAppend methods
 *
 * Hacked to hell for OS implementations.
 */

# define NEED_FLOCK
# define NEED_FSYNC
# define NEED_FCNTL
# define NEED_FILE
# define NEED_STAT
# define NEED_UTIME
# define NEED_UTIMES
# define NEED_TIME_HP
# define NEED_ERRNO
# define NEED_READLINK

# include <stdhdrs.h>

# include <error.h>
# include <errornum.h>
# include <debug.h>
# include <tunable.h>
# include <msgsupp.h>
# include <strbuf.h>
# include <datetime.h>
# include <i18napi.h>
# include <charcvt.h>
# include <largefile.h>
# include <fdutil.h>
# include <md5.h>

# include <msgos.h>

# include "filesys.h"
# include "fileio.h"

// We need to know the user's umask so that Chmod() doesn't give
// away permissions beyond the umask.

int global_umask = -1;

# ifndef O_BINARY
# define O_BINARY 0
# endif

const FileIOBinary::OpenMode FileIOBinary::openModes[4] = {
	"open for read",
		O_RDONLY|O_BINARY,
		O_RDONLY|O_BINARY,
		0,
	"open for write",
		O_WRONLY|O_CREAT|O_TRUNC|O_BINARY,
		O_WRONLY|O_CREAT|O_APPEND,
		1,
	"open for read/write",
		O_RDWR|O_CREAT|O_BINARY,
		O_RDWR|O_CREAT|O_APPEND,
		1,
	"open for untranslated write",
		O_WRONLY|O_CREAT|O_TRUNC|O_BINARY,
		O_WRONLY|O_CREAT|O_APPEND|O_BINARY,
		1
} ;

FileIO::FileIO()
{
	// Get the umask if we don't know it already.

	if( global_umask < 0 )
	{
	    global_umask = umask( 0 );
	    (void)umask( global_umask );
	}
}

# if !defined( OS_VMS ) && !defined( OS_NT )

void
FileIO::Rename( FileSys *target, Error *e )
{
	// yeech - must not exist to rename

# if defined(OS_OS2) || defined(OS_AS400)
	target->Unlink( 0 );
# endif

# if defined( OS_MACOSX ) || defined( OS_DARWIN )
	// On mac, deal with a possible immutable *uchg) flag

	struct stat sb;

	if( stat( Name(), &sb ) >= 0 && ( sb.st_flags & UF_IMMUTABLE ) )
	    chflags( Name(), sb.st_flags & ~UF_IMMUTABLE );
	if( stat( target->Name(), &sb ) >= 0 && ( sb.st_flags & UF_IMMUTABLE ) )
	    chflags( target->Name(), sb.st_flags & ~UF_IMMUTABLE );
# endif
	// Run on all other UNIX variants, including Mac OS X

	if( rename( Name(), target->Name() ) < 0 )
	{
	    e->Sys( "rename", target->Name() );
	    return;
	}

	// source file has been deleted,  clear the flag

	ClearDeleteOnClose();
}

void
FileIO::ChmodTime( int modTime, Error *e )
{
# ifdef HAVE_UTIME
	struct utimbuf t;
	DateTime now;

	now.SetNow();
	t.actime = DateTime::Localize( now.Value() );
	t.modtime = DateTime::Localize( modTime );

	if( utime( Name(), &t ) < 0 )
	    e->Sys( "utime", Name() );
# endif // HAVE_UTIME
}

void
FileIO::ChmodTimeHP( const DateTimeHighPrecision &modTime, Error *e )
{
	DateTimeHighPrecision now;

	now.Now();

# if defined(HAVE_UTIMENSAT)
	struct timespec tv[2];

	tv[0].tv_sec = DateTime::Localize( now.Seconds() );
	tv[0].tv_nsec = now.Nanos();
	tv[1].tv_sec = DateTime::Localize( modTime.Seconds() );
	tv[1].tv_nsec = modTime.Nanos();

	if( utimensat( AT_FDCWD, Name(), tv, 0 ) < 0 )
	    e->Sys( "utimensat", Name() );
# elif defined(HAVE_UTIMES)
	struct timeval	tv[2];

	tv[0].tv_sec = DateTime::Localize( now.Seconds() );
	tv[0].tv_usec = now.Nanos() / 1000;
	tv[1].tv_sec = DateTime::Localize( modTime.Seconds() );
	tv[1].tv_usec = modTime.Nanos() / 1000;

	if( utimes( Name(), tv ) < 0 )
	    e->Sys( "utimes", Name() );
# else
	ChmodTime( modtime.Seconds(), e )
# endif
}

# endif // !OS_VMS && !OS_NT


void
FileIO::ChmodTime( Error *e )
{
	if( modTime )
	    ChmodTime( modTime, e );
}

# if !defined( OS_NT )

void
FileIO::Truncate( offL_t offset, Error *e )
{
	// Don't bother if non-existent.

	if( !( Stat() & FSF_EXISTS ) )
	    return;

# ifdef HAVE_TRUNCATE
	if( truncate( Name(), offset ) >= 0 )
	    return;
# endif // HAVE_TRUNCATE

	e->Sys( "truncate", Name() );
}

void
FileIO::Truncate( Error *e )
{
	// Don't bother if non-existent.

	if( !( Stat() & FSF_EXISTS ) )
	    return;

	// Try truncate first; if that fails (as it will on secure NCR's),
	// then open O_TRUNC.

# ifdef HAVE_TRUNCATE
	if( truncate( Name(), 0 ) >= 0 )
	    return;
# endif // HAVE_TRUNCATE

	int fd;

# if !defined ( OS_MACOSX ) || OS_VER >= 1010
	if( ( fd = checkFd( openL( Name(), O_WRONLY|O_TRUNC, PERM_0666 ) ) ) >= 0 )
# else
	if( ( fd = checkFd( openL( Name(), O_WRONLY|O_TRUNC ) ) ) >= 0 )
# endif // OS_MACOSX
	{
	    close( fd );
	    return;
	}

	e->Sys( "truncate", Name() );
}

# endif // !defined( OS_NT )

/*
 * FileIO::Stat() - return flags if file exists
 */

# ifndef OS_NT

int
FileIO::Stat()
{
	// Stat & check for missing, special

	int flags = 0;
	struct statbL sb;

# ifdef HAVE_SYMLINKS
	// With symlinks, we first stat the link
	// and if it is a link, then stat the actual file.
	// A symlink without an underlying file appears
	// as FSF_SYMLINK.  With an underlying file
	// as FSF_SYMLINK|FSF_EXISTS.

	if( lstatL( Name(), &sb ) < 0 )
	    return flags;

	if( S_ISLNK( sb.st_mode ) )
	    flags |= FSF_SYMLINK;

	if( S_ISLNK( sb.st_mode ) && statL( Name(), &sb ) < 0 )
	    return flags;
# else
	// No symlinks: just stat the file.

	if( statL( Name(), &sb ) < 0 )
	    return flags;
# endif

	flags |= FSF_EXISTS;

	if( sb.st_mode & S_IWUSR ) flags |= FSF_WRITEABLE;
	if( sb.st_mode & S_IXUSR ) flags |= FSF_EXECUTABLE;
	if( S_ISDIR( sb.st_mode ) ) flags |= FSF_DIRECTORY;
	if( !S_ISREG( sb.st_mode ) ) flags |= FSF_SPECIAL;
	if( !sb.st_size ) flags |= FSF_EMPTY;

# if defined ( OS_DARWIN ) || defined( OS_MACOSX )
	// If the immutable bit is set, we can't write this file
	// Chmod() will unset the immutable bit if it needs to.
	//
	if( sb.st_flags & UF_IMMUTABLE ) flags &= ~FSF_WRITEABLE;
# endif

	return flags;
}

# endif

# if !defined( OS_NT )
int
FileIO::GetOwner()
{
	int uid = 0;
	struct statbL sb;

# ifdef HAVE_SYMLINKS
	// With symlinks, we first stat the link
	// and if it is a link, then stat the actual file.
	// A symlink without an underlying file appears
	// as FSF_SYMLINK.  With an underlying file
	// as FSF_SYMLINK|FSF_EXISTS.

	if( lstatL( Name(), &sb ) < 0 )
	    return uid;

	if( S_ISLNK( sb.st_mode ) && statL( Name(), &sb ) < 0 )
	    return uid;
# else
	// No symlinks: just stat the file.

	if( statL( Name(), &sb ) < 0 )
	    return uid;
# endif

	return sb.st_uid;
}
# endif

# if !defined( OS_NT )
bool
FileIO::HasOnlyPerm( FilePerm perms )
{
	struct statbL sb;
	mode_t modeBits = 0;

	if( statL( Name(), &sb ) < 0 )
	    return false;

	switch (perms)
	{
	case FPM_RO:
	    modeBits = PERM_0222;
	    break;
	case FPM_RW:
	    modeBits = PERM_0666;
	    break;
	case FPM_ROO:
	    modeBits = PERM_0400;
	    break;
	case FPM_RXO:
	    modeBits = PERM_0500;
	    break;
	case FPM_RWO:
	    modeBits = PERM_0600;
	    break;
	case FPM_RWXO:
	    modeBits = PERM_0700;
	    break;
	}
	/*
	 * In this case we want an exact match of permissions
	 * We don't want to "and" to a mask, since we also want
	 * to verify that the other bits are off.
	 */
	if( (sb.st_mode & PERMSMASK) == modeBits )
		return true;

	return false;
}
# endif // not defined OS_NT

# if !defined( OS_NT )
int
FileIO::StatModTime()
{
	struct statbL sb;

	if( statL( Name(), &sb ) < 0 )
	    return 0;

	return (int)( DateTime::Centralize( sb.st_mtime ) );
}

void
FileIO::StatModTimeHP(DateTimeHighPrecision *modTime)
{
	struct statbL sb;

	if( statL( Name(), &sb ) < 0 )
	{
	    *modTime = DateTimeHighPrecision();
	    return;
	}

	time_t	seconds = DateTime::Centralize( sb.st_mtime );
	int	nanosecs = 0;

// nanosecond support for stat is a bit of a portability mess
#if defined(OS_LINUX)
  #if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
    #if defined(_BSD_SOURCE) || defined(_SVID_SOURCE) \
	|| (__GLIBC_PREREQ(2, 12) \
	    && ((_POSIX_C_SOURCE >= 200809L) || (_XOPEN_SOURCE >= 700)))
	nanosecs = sb.st_mtim.tv_nsec;
    #else
	nanosecs = sb.st_mtimensec;
    #endif
  #else   
	nanosecs = sb.st_mtim.tv_nsec;
  #endif
#elif defined(OS_MACOSX) && OS_VER < 1010
	/*
	 * HFS+ stores timestamps in 1-second resolution
	 * so nanosecs will always be zero, but maybe
	 * someone will run on a filesystem that does support
	 * finer-grained timestamps (eg, ext4).
	 */
	nanosecs = sb.st_mtimespec.tv_nsec;
#endif

	*modTime = DateTimeHighPrecision( seconds, nanosecs );
}

# endif

/*
 * FileIO::Unlink() - remove single file (error optional)
 */

# if !defined( OS_VMS ) && !defined( OS_NT )

void
FileIO::Unlink( Error *e )
{

# if defined(OS_OS2) || defined(OS_DARWIN) || defined(OS_MACOSX)

	// yeech - must be writable to remove
	// even on Darwin because the uchg flag might be set
	// but only for real files, otherwise the chmod
	// will propagate to the target file.

	Chmod( FPM_RW, 0 );

# endif

	if( *Name() && unlink( Name() ) < 0 && e )
	    e->Sys( "unlink", Name() );
}

void
FileIO::Chmod( FilePerm perms, Error *e )
{
	// Don't set perms on symlinks

	if( ( GetType() & FST_MASK ) == FST_SYMLINK )
	    return;

	// Permissions for readonly/readwrite, exec vs no exec

	int bits = IsExec() ? PERM_0777 : PERM_0666;

	switch( perms )
	{
	case FPM_RO: bits &= ~PERM_0222; break;
	case FPM_ROO: bits &= ~PERM_0266; break;
	case FPM_RWO: bits = PERM_0600; break; // for key file, set exactly to rwo
	case FPM_RXO: bits = PERM_0500; break;
	case FPM_RWXO: bits = PERM_0700; break;
	}

	if( chmod( Name(), bits & ~global_umask ) >= 0 )
	    return;

# if defined( OS_MACOSX ) || defined( OS_DARWIN )

	// On mac, try unlocking the immutable bit and chmoding again.

	struct stat sb;

	if( stat( Name(), &sb ) >= 0 &&
	    chflags( Name(), sb.st_flags & ~UF_IMMUTABLE ) >= 0 &&
	    chmod( Name(), bits & ~global_umask ) >= 0 )
		return;
# endif

	// Can be called with e==0 to ignore error.

	if( e )
	    e->Sys( "chmod", Name() );
}

# endif /* !OS_VMS && !OS_NT */

/*
 * FileIoText Support
 * FileIOBinary support
 */

FileIOBinary::~FileIOBinary()
{
	Cleanup();
}

# if !defined( OS_NT )

void
FileIOBinary::Open( FileOpenMode mode, Error *e )
{
	// Save mode for write, close

	this->mode = mode;

	// Get bits for (binary) open

	int bits = openModes[ mode ].bflags;

	// Reset the isStd flag

	isStd = 0;

	// Handle exclusive open (must not already exist)

# ifdef O_EXCL
	// Set O_EXCL to ensure we create the file when we open it.

	if( GetType() & FST_M_EXCL )
	    bits |= O_EXCL;
# else
	// No O_EXCL: we'll manually check if file already exists.
	// Not atomic, but what can one do?

	if( ( GetType() & FST_M_EXCL ) && ( Stat() & FSF_EXISTS ) )
	{
	    e->Set( E_FAILED, "file exists" );

	    // if file is set delete on close unset that because we
	    // didn't create the file...
	    ClearDeleteOnClose();
	    return;
	}
# endif

	// open stdin/stdout or real file
	
	if( Name()[0] == '-' && !Name()[1] )
	{
	    // we do raw output: flush stdout
	    // for nice mixing of messages.

	    if( mode == FOM_WRITE )
		fflush( stdout );
            
	    fd = openModes[ mode ].standard;
            checkStdio( fd );
	    isStd = 1;
	}
	else if( ( fd = checkFd( openL( Name(), bits, PERM_0666 ) ) ) < 0 )
	{
	    e->Sys( openModes[ mode ].modeName, Name() );
# ifdef O_EXCL
	    // if we failed to create the file probably due to the
	    // file already existing (O_EXCL)
	    // then unset delete on close because we didn't create it...
	    if( ( bits & (O_EXCL|O_CREAT) ) == (O_EXCL|O_CREAT) )
		ClearDeleteOnClose();
# endif
	}

}

# endif

void
FileIOBinary::Close( Error *e )
{
	if( isStd || fd < 0 )
	    return;

	if( ( GetType() & FST_M_SYNC ) )
	    Fsync( e );

# ifdef OS_LINUX
	if( cacheHint && p4tunable.Get( P4TUNE_FILESYS_CACHEHINT ) )
	  (void) posix_fadvise64( fd, 0, 0, POSIX_FADV_DONTNEED );
# endif

	if( close( fd ) < 0 )
	    e->Sys( "close", Name() );

	fd = -1;

	if( mode == FOM_WRITE && modTime )
	    ChmodTime( modTime, e );

	if( mode == FOM_WRITE )
	    Chmod( perms, e );
}

void
FileIOBinary::Fsync( Error *e )
{
# ifdef HAVE_FSYNC
	if( fd >= 0 && fsync( fd ) < 0 )
	    e->Sys( "fsync", Name() );
# endif
}

void
FileIOBinary::Write( const char *buf, int len, Error *e )
{
	// Raw, unbuffered write

	int l;

	if( ( l = write( fd, buf, len ) ) < 0 )
	    e->Sys( "write", Name() );
	else
	    tellpos += l;

	if( checksum && l > 0 )
	    checksum->Update( StrRef( buf, l ) );
}

int
FileIOBinary::Read( char *buf, int len, Error *e )
{
	// Raw, unbuffered read

	int l;

	if( ( l = read( fd, buf, len ) ) < 0 )
	    e->Sys( "read", Name() );
	else
	    tellpos += l;

	return l;
}

# if !defined( OS_NT )

offL_t
FileIOBinary::GetSize()
{
	struct statbL sb;

	if( fd >= 0 && fstatL( fd, &sb ) < 0 )
	    return -1;
	if( fd < 0 && statL( Name(), &sb ) < 0 )
	    return -1;

	return sb.st_size;
}

void
FileIOBinary::Seek( offL_t offset, Error *e )
{
	if( lseekL( fd, offset, 0 ) == -1 )
	    e->Sys( "seek", Name() );
	tellpos = offset;
}

# endif

offL_t
FileIOBinary::Tell()
{
	return tellpos;
}

FileIODir::FileIODir()
{
}

FileIODir::~FileIODir()
{
	Cleanup();
}

void
FileIODir::Open( FileOpenMode mode, Error *e )
{
}

void
FileIODir::Write( const char *buf, int len, Error *e )
{
}

int
FileIODir::Read( char *buf, int len, Error *e )
{
	return 0;
}

void
FileIODir::Close( Error *e )
{
}

int
FileIODir::GetFd()
{
	return 0;
}

offL_t
FileIODir::GetSize()
{
	return 0;
}

void
FileIODir::Seek( offL_t offset, Error *e )
{
}

offL_t
FileIODir::Tell()
{
	return 0;
}

void
FileIODir::Fsync( Error *e )
{
}

void
FileIODir::Cleanup()
{
	Error e;

	if( IsDeleteOnClose() && Path()->Length() )
	    PurgeDir( Path()->Text(), &e );
}

/*
 * FileIOAppend support
 *
 * On UNIX, FileIOAppend::Write() and Rename() obey a special
 * protocol to provide for atomic rotating of files that may
 * be open by active processes.
 *
 * Rename() opens & locks the file, renames it, and then changes
 * the permission on the renamed file to read-only.
 *
 * Write() locks and then fstats the file, to see if it is still
 * writeable.  If not, it assumes it has been renamed, so it closes
 * and reopens the original file (which should always be writeable),
 * and then relocks it.  It can then write and unlock.
 *
 * There is the possibility that rapid fire Rename() calls may get
 * between Write()'s reopen for write and its lock.  In this odd case,
 * we retry 10 times.
 */

FileIOAppend::~FileIOAppend()
{
	// Need to set mode to read so it doesn't try to chmod the
	// file in the destructor

	mode = FOM_READ;
}

# if !defined( OS_NT )

void
FileIOAppend::Open( FileOpenMode mode, Error *e )
{
	// Save mode for write, close

	this->mode = mode;

	// Reset the isStd flag

	isStd = 0;

	// open stdin/stdout or real file

	if( Name()[0] == '-' && !Name()[1] )
	{
	    fd = openModes[ mode ].standard;
            checkStdio( fd );
	    isStd = 1;
	}
	else if( ( fd = checkFd( openL( Name(), openModes[ mode ].aflags, PERM_0666 ) ) ) < 0 )
	{
	    e->Sys( openModes[ mode ].modeName, Name() );
	    ClearDeleteOnClose();
	}

	// Clear send/receive buffers

	rcv = snd = 0;
}

offL_t
FileIOAppend::GetSize()
{
	offL_t s = 0;

	if( !lockFile( fd, LOCKF_SH ) )
	{
	    s = FileIOBinary::GetSize();

	    lockFile( fd, LOCKF_UN );
	}
	else
	    s = FileIOBinary::GetSize();

	return s;
}

void
FileIOAppend::Write( const char *buf, int len, Error *e )
{
	// Lock and check for writeability.
	// If made read-only by Rename(), close and reopen.
	// If file keeps becomming read-only, give up after
	// trying a while.

	int tries = 10;

	while( --tries )
	{
	    struct statbL sb;

	    if( lockFile( fd, LOCKF_EX ) < 0 )
	    {
		e->Sys( "lock", Name() );
		return;
	    }

	    if( fstatL( fd, &sb ) < 0 )
	    {
		e->Sys( "fstat", Name() );
		return;
	    }

	    if( sb.st_mode & S_IWUSR )
		break;

	    if( close( fd ) < 0 )
	    {
		e->Sys( "close", Name() );
		return;
	    }

	    Open( mode, e );

	    if( e->Test() )
		return;
	}

	if( !tries )
	{
	    e->Set( E_FAILED, "Tired of waiting for %file% to be writeable." )
		<< Name();
	    return;
	}

	FileIOBinary::Write( buf, len, e );

	if( lockFile( fd, LOCKF_UN ) < 0 )
	{
	    e->Sys( "unlock", Name() );
	    return;
	}
}

void
FileIOAppend::Rename( FileSys *target, Error *e )
{
	// Open, lock for write, rename, chmod to RO, and close

	Open( FOM_WRITE, e );

	if( e->Test() )
	    return;

	if( lockFile( fd, LOCKF_EX ) < 0 )
	{
	    e->Sys( "lock", Name() );
	    return;
	}

	if( rename( Name(), target->Name() ) < 0 )
	{
	    // Uh oh -- we can't rename.  Maybe cross device?
	    // Do the dumb way: copy/truncate.

	    mode = FOM_READ;

	    Close( e );
	    Copy( target, FPM_RO, e );

	    if( e->Test() )
		return;

	    Truncate( e );
	    return;
	}

	target->Chmod( FPM_RO, e );

	// Need to set mode to read so it doesn't try to chmod the
	// file in the destructor

	mode = FOM_READ;

	if( e->Test() )
	    return;

	struct statbL sb;

	if( fstatL( fd, &sb ) < 0 )
	{
	    e->Sys( "fstat", Name() );
	    return;
	}

	if( sb.st_mode & S_IWUSR )
	{
	    P4INT64 bigINode = sb.st_ino;
	    P4INT64 bigMode  = sb.st_mode;
	    e->Set( MsgOs::ChmodBetrayal ) <<
	            Name() << target->Name() <<
	            StrNum( bigMode ) << StrNum( bigINode );
	    return;
	}

	Close( e );
}

# endif

void
FileIOAppend::Close( Error *e )
{
	mode = FOM_READ;

	FileIOBuffer::Close( e );
}

