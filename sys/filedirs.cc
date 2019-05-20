/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# define NEED_ACCESS
# define NEED_ERRNO
# define NEED_STAT

# include <stdhdrs.h>

# include <error.h>
# include <strbuf.h>
# include <strarray.h>

# include "pathsys.h"
# include "filesys.h"

/* OS headers */

# ifdef OS_NT
# define GOT_DIRSCAN

# include <io.h>
# include <wchar.h>
# include <i18napi.h>
# include <charcvt.h>
# include "fileio.h"

extern void nt_free_wname( const wchar_t *wname );

StrArray *
FileSys::ScanDir( Error *e )
{
	StrBuf fs;
	struct _finddata_t finfo;

	/* Now enter contents of directory */

	fs << path << "\\*";

	StrArray *r = new StrArray;
	intptr_t handle = 0;

	if( DOUNICODE || LFN )
	{
	    struct _wfinddata_t winfo;

	    const wchar_t *wname;
	    if( ( wname = FileIO::UnicodeName( &fs, LFN ) ) &&
		( handle = _wfindfirst( wname, &winfo ) ) >= 0 )
	    {
		CharSetCvtUTF168 rcvt;

		do {
		    wchar_t *n = winfo.name;

		    // Explicitly exclude ., ..

		    if( n[0] != '.' || n[1] != 0 && ( n[1] != '.' || n[2] != 0 ) )
		    {
			const char *rname = rcvt.FastCvt( (const char *)n, 2 * wcslen( n ) );
			if( rcvt.LastErr() == CharSetCvt::NONE )
			    r->Put()->Set( rname );
		    }

		} while( !_wfindnext( handle, &winfo ) );
	    }
	    if( wname )
		nt_free_wname( wname );
	}
	else
	if( ( handle = _findfirst( fs.Text(), &finfo ) ) >= 0 )
	{
	    do {
		char *n = finfo.name;

		// Explicitly exclude ., ..

		if( n[0] != '.' || n[1] != 0 && ( n[1] != '.' || n[2] != 0 ) )
		    r->Put()->Set( n );

	    } while( !_findnext( handle, &finfo ) );
	}

	_findclose( handle );

	return r;
}

# endif /* NT */

# ifdef OS_OS2
# define GOT_DIRSCAN

# include <io.h>
# include <dos.h>

StrArray *
FileSys::ScanDir( Error *e )
{
	StrBuf fs;
	struct _find_t finfo[1];

	/* Now enter contents of directory */
	/* Don't append / if one already there */

	char s = path.End()[-1];
	fs << path << ( s == '/' || s == '\\' ? "*" : "/*" );

	StrArray *r = new StrArray;

	if( !_dos_findfirst( fs.Text(), _A_NORMAL|_A_RDONLY|_A_SUBDIR, finfo ) )
	{
	    do {
		char *n = finfo->name;

		// Explicitly exclude ., ..

		if( n[0] != '.' || n[1] != 0 && ( n[1] != '.' || n[2] != 0 ) )
		    r->Put()->Set( n );

	    } while( !_dos_findnext( finfo ) );
	}

	return r;
}

# endif

# ifdef OS_VMS
# define GOT_DIRSCAN

# include <rms.h>
# include <lib$routines.h>
# include <starlet.h>

# define DEFAULT_FILE_SPECIFICATION "[]*.*;0"

# define min( a,b ) ((a)<(b)?(a):(b))

StrArray *
FileSys::ScanDir( Error *e )
{
	struct FAB xfab;
	struct NAM xnam;
	struct XABDAT xab;
	char esa[256];
	char filename[256];
	int status;

	/* Now enter contents of directory */

	xnam = cc$rms_nam;
	xnam.nam$l_esa = esa;
	xnam.nam$b_ess = sizeof( esa ) - 1;
	xnam.nam$l_rsa = filename;
	xnam.nam$b_rss = min( sizeof( filename ) - 1, NAM$C_MAXRSS );

	xab = cc$rms_xabdat;            /* initialize extended attributes */
	xab.xab$b_cod = XAB$C_DAT;	/* ask for date */
	xab.xab$l_nxt = NULL;           /* terminate XAB chain      */

	xfab = cc$rms_fab;
	xfab.fab$l_dna = DEFAULT_FILE_SPECIFICATION;
	xfab.fab$b_dns = sizeof( DEFAULT_FILE_SPECIFICATION ) - 1;
	xfab.fab$l_fop = FAB$M_NAM;
	xfab.fab$l_fna = path.Text();	/* address of file name	    */
	xfab.fab$b_fns = path.Length(); /* length of file name	    */
	xfab.fab$l_nam = &xnam;		/* address of NAB block	    */
	xfab.fab$l_xab = (char *)&xab;  /* address of XAB block     */

	status = sys$parse( &xfab );

	if ( !( status & 1 ) )
	{
	    e->Sys( "parse", path.Text() );
	    return 0;
	}

	StrArray *r = new StrArray;

	while ( (status = sys$search( &xfab )) & 1 )
	{
	    /* What we do with the name depends on the suffix: */
	    /* .dir is a directory */
	    /* .xxx is a file with a suffix */
	    /* . is no suffix at all */
	
	    StrBuf *n = r->Put();

	    if( xnam.nam$b_type == 4 && !strncmp( xnam.nam$l_type, ".DIR", 4 ) )
	    {
		/* directory */

		*n << "[.";
		n->Append( xnam.nam$l_name, xnam.nam$b_name );
		*n << "]";
	    }
	    else if( xnam.nam$b_type == 1 && xnam.nam$l_type[0] == '.' )
	    {
		/* file with no suffix */

		n->Append( xnam.nam$l_name, xnam.nam$b_name );
	    }
	    else
	    {
		/* normal file with a suffix */

		n->Append( xnam.nam$l_name, xnam.nam$b_name );
	        n->Append( xnam.nam$l_type, xnam.nam$b_type );
	    }
	}

	if ( status != RMS$_NMF && status != RMS$_FNF )
	    lib$signal( xfab.fab$l_sts, xfab.fab$l_stv );

	return r;
}    

# endif /* VMS */

# ifndef GOT_DIRSCAN

# if defined( OS_RHAPSODY ) || \
     (!defined ( MAC_MWPEF ) && defined( OS_MACOSX )) || \
     defined( OS_NEXT )
/* need unistd for rhapsody's proper lseek */
# include <sys/dir.h>
# include <unistd.h>
# define STRUCT_DIRENT struct direct 
# else
# include <dirent.h>
# define STRUCT_DIRENT struct dirent 
# endif

/*
 * file_dirscan() - scan a directory for files
 */

StrArray *
FileSys::ScanDir( Error *e )
{
	DIR *d;
	STRUCT_DIRENT *dirent;

	/* Now enter contents of directory */

	if( !( d = opendir( Name() ) ) )
	{
	    e->Sys( "opendir", Name() );
	    return 0;
	}

	StrArray *r = new StrArray;

	while( dirent = readdir( d ) )
	{
	    char *n = dirent->d_name;

	    // Explicitly exclude ., ..

	    if( n[0] != '.' || n[1] != 0 && ( n[1] != '.' || n[2] != 0 ) )
		    r->Put()->Set( n );
	}

	closedir( d );

	return r;
}

# endif /* USE_FILEUNIX */

