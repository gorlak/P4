/*
 * Copyright 1995, 2003 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * zipfile.cc - ZipFile methods
 */

# include <stdhdrs.h>

# include <error.h>
# include <strbuf.h>
# include <debug.h>
# include <filesys.h>

# include <zip.h>
# include <unzip.h>

# include <msgos.h>

# include "zipfile.h"

ZipFile::ZipFile()
{
	zf = 0;
}

ZipFile::~ZipFile()
{
	if( zf )
	    Close();
}

void
ZipFile::Open( const char *fName, Error *e )
{
	FileSys *f = FileSys::Create( FST_BINARY );
	f->Set( fName );
	int exists = f->Stat() & FSF_EXISTS;
	delete f;
	if( exists )
	{
	    e->Set( MsgOs::ZipExists ) << StrRef( fName );
	    return;
	}

	this->zfName.Set( fName );

	if( p4debug.GetLevel( DT_DVCS ) >= 1 )
	    p4debug.printf( "Will create zip file %s\n", fName );

	zf = zipOpen64( fName, APPEND_STATUS_CREATE );
}

void
ZipFile::Close()
{
	zipClose( zf, 0 );
	zf = 0;
}

offL_t	
ZipFile::GetSize()
{
	FileSys *f = FileSys::Create( FST_BINARY );
	f->Set( zfName );
	offL_t result = f->GetSize();
	delete f;
	return result;
}

void	
ZipFile::StartEntry( const char *entry, Error *e )
{
	zip_fileinfo zi;
        zi.tmz_date.tm_sec = zi.tmz_date.tm_min = zi.tmz_date.tm_hour =
        zi.tmz_date.tm_mday = zi.tmz_date.tm_mon = zi.tmz_date.tm_year = 0;
        zi.dosDate = 0;
        zi.internal_fa = 0;
        zi.external_fa = 0;
	int result = zipOpenNewFileInZip64( zf, entry, &zi, 0, 0, 0, 0, 0,
	                     Z_DEFLATED, Z_DEFAULT_COMPRESSION, 1 );

	if( result < 0 )
	{
	    p4debug.printf("FAILED to open entry\n");
	    e->Set( MsgOs::ZipOpenEntryFailed )
	            << StrNum( result ) << StrRef( entry );
	}
}

void	
ZipFile::FinishEntry( Error *e )
{
	int result = zipCloseFileInZip( zf );

	if( result < 0 )
	{
	    p4debug.printf("FAILED to close entry\n");
	    e->Set( MsgOs::ZipCloseEntryFailed ) << StrNum( result );
	}
}

void
ZipFile::AppendBytes( const char *buf, p4size_t len, Error *e )
{
	int result = zipWriteInFileInZip( zf, buf, len );

	if( result < 0 )
	{
	    p4debug.printf("FAILED to write bytes\n");
	    e->Set( MsgOs::ZipWriteFailed )
	            << StrNum( result ) << StrNum( (P4INT64)len );
	}
}

UnzipFile::UnzipFile()
{
	zf = 0;
}

UnzipFile::~UnzipFile()
{
	if( zf )
	    Close();
}

void
UnzipFile::Open( const char *fName, Error *e )
{
	FileSys *f = FileSys::Create( FST_BINARY );
	f->Set( fName );
	int exists = f->Stat() & FSF_EXISTS;
	delete f;
	if( !exists )
	{
	    e->Set( MsgOs::ZipMissing ) << StrRef( fName );
	    return;
	}

	this->zfName.Set( fName );

	if( p4debug.GetLevel( DT_DVCS ) >= 1 )
	    p4debug.printf( "Will read zip file %s\n", fName );

	zf = unzOpen64( fName );
}

void
UnzipFile::Close()
{
	unzClose( zf );
	zf = 0;
}

offL_t	
UnzipFile::GetSize()
{
	FileSys *f = FileSys::Create( FST_BINARY );
	f->Set( zfName );
	offL_t result = f->GetSize();
	delete f;
	return result;
}

int	
UnzipFile::HasEntry( const char *entry )
{
	int err;

	err = unzLocateFile( zf, entry, 0 );
	if( err != UNZ_OK && err != UNZ_END_OF_LIST_OF_FILE )
	{
	    p4debug.printf("FAILED (%d) to locate  %s\n", err, entry);
	    return 0;
	}
	return err == UNZ_END_OF_LIST_OF_FILE ? 0 : 1;
}

void	
UnzipFile::OpenEntry( const char *entry, Error *e )
{
	int err;

	err = unzLocateFile( zf, entry, 0 );
	if( err != UNZ_OK )
	{
	    p4debug.printf("FAILED (%d) to locate  %s\n", err, entry);
	    e->Set( MsgOs::ZipNoEntry )
	            << StrNum( err ) << StrRef( entry );
	    return;
	}
	err = unzOpenCurrentFile( zf );
	if( err != UNZ_OK )
	{
	    p4debug.printf("FAILED to open %s\n", entry);
	    e->Set( MsgOs::ZipOpenEntry )
	            << StrNum( err ) << StrRef( entry );
	    return;
	}
}

void
UnzipFile::CloseEntry()
{
	unzCloseCurrentFile( zf );
}

int
UnzipFile::ReadBytes( char *buf, p4size_t len, Error *e )
{
	int result = unzReadCurrentFile( zf, buf, len );

	if( result < 0 )
	{
	    p4debug.printf("FAILED to read bytes\n");
	    e->Set( MsgOs::ZipReadFailed )
	            << StrNum( result ) << StrNum( (P4INT64)len );
	}
	return result;
}
