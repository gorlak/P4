/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# define NEED_SLEEP
# define NEED_STATFS
# define NEED_STATVFS

# include <stdhdrs.h>

# include <error.h>
# include <strbuf.h>
# include <debug.h>
# include <tunable.h>

# include "filesys.h"
# include "pathsys.h"

/*
 * FileSys::GetDiskSpace -- fill in details about disk space usage.
 */

DiskSpaceInfo::DiskSpaceInfo()
{
	this->fsType = new StrBuf();
	blockSize = totalBytes = usedBytes = freeBytes = 0;
	pctUsed = 0;
}

DiskSpaceInfo::~DiskSpaceInfo()
{
	delete this->fsType;
}

void
FileSys::GetDiskSpace( DiskSpaceInfo *info, Error *e )
{
	info->fsType->Set( "unknown" );
# ifdef OS_NT
	char buffer[1024];
	char *lpp;

	if( !GetFullPathName( Name(), sizeof( buffer ), buffer, &lpp ) )
	{
	    e->Sys( "GetFullPathName", Name() );
	    return;
	}
	if( lpp )
	    *lpp = '\0';

	ULARGE_INTEGER freeBytesAvailable;
	ULARGE_INTEGER totalNumberOfBytes;
	ULARGE_INTEGER totalNumberOfFreeBytes;

	if( !GetDiskFreeSpaceEx( buffer,
				&freeBytesAvailable,
				&totalNumberOfBytes,
				&totalNumberOfFreeBytes ) )
	{
	    e->Sys( "GetDiskFreeSpaceEx", Name() );
	    return;
	}
	info->blockSize = -1;
	info->freeBytes = freeBytesAvailable.QuadPart;
	info->totalBytes= totalNumberOfBytes.QuadPart;

	char vName[1024];
	char fsName[1024];
	char *which = 0;
	if( buffer[1] == ':' )
	{
	    buffer[2] = '\\';
	    buffer[3] = '\0';
	    which = buffer;
	}
	if( !GetVolumeInformation( which, 
				vName, sizeof( vName ),
				(LPDWORD)0, (LPDWORD)0, (LPDWORD)0,
				fsName, sizeof( fsName) ) )
	{
	    e->Sys( "GetVolumeInformation", Name() );
	    return;
	}
	info->fsType->Set( fsName );
	info->usedBytes = info->totalBytes - info->freeBytes;
	double usage = 1.0;
	if( info->totalBytes > 0 )
	    usage = (double)info->usedBytes / (double)info->totalBytes;
	info->pctUsed = (int)( usage * 100 );
# else
	if( !strchr( Name(), '/' ) )
	{
	    StrBuf nm;
	    nm << "./" << Name();
	    Set( nm );
	}
	PathSys *ps = PathSys::Create();
	ps->Set( Name() );
	ps->ToParent();
	Set( ps->Text() );
	delete ps;

	struct statvfs df;

	if( statvfs( Name(), &df ) == -1 )
	{
	    e->Sys( "statvfs", Name() );
	    return;
	}

	info->blockSize = df.f_frsize;
	info->freeBytes  = (P4INT64) ( (double) df.f_frsize * df.f_bfree  );
	info->totalBytes = (P4INT64) ( (double) df.f_frsize * df.f_blocks );
	info->usedBytes  = info->totalBytes - info->freeBytes;
	info->freeBytes  = (P4INT64) ( (double) df.f_frsize * df.f_bavail );
	double usage = 1.0;
	if( info->totalBytes > 0 )
	    usage = (double)info->usedBytes /
	            (double)(info->usedBytes + info->freeBytes);
	info->pctUsed = (int)( usage * 100 );

	// Note that used + free may not equal total, and also note that
	// used/total does not match pctUsed. This is because
	// the filesystem may also have 'reserved' space, which is
	// available only to privileged users, and we are attemptint
	// to return the non-privileged information, like df does.

# ifdef HAVE_STATVFS_BASETYPE
	info->fsType->Set( df.f_basetype );
# endif

# endif

# ifdef HAVE_STATFS
	struct statfs sys_fs;

	if( statfs( Name(), &sys_fs ) == -1 )
	{
	    e->Sys( "statfs", Name() );
	    return;
	}

# ifdef HAVE_STATFS_FSTYPENAME
	info->fsType->Set( sys_fs.f_fstypename );
# else
	switch( sys_fs.f_type )
	{
	case 0x6969: 
	    info->fsType->Set( "nfs" );
	    break;
	case 0xEF53: 
	    info->fsType->Set( "ext2" );
	    break;
	case 0x58465342: 
	    info->fsType->Set( "xfs" );
	    break;
	case 0x1021994: 
	    info->fsType->Set( "tmpfs" );
	    break;
	case 0x858458f6: 
	    info->fsType->Set( "ramfs" );
	    break;
	case 0x00011954: 
	    info->fsType->Set( "ufs" );
	    break;
	case 0x52654973: 
	    info->fsType->Set( "reiserfs" );
	    break;
	default:
	    info->fsType->Set( StrNum( (P4INT64) sys_fs.f_type ) );
	    break;
	}
# endif

# endif
}
