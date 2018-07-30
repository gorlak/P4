/*
 * Copyright 1995, 2004 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * fileiovms -- FileIO methods for VMS
 */

# define NEED_FCNTL
# define NEED_FILE
# define NEED_STAT
# define NEED_ERRNO

# include <stdhdrs.h>

# include <error.h>
# include <errornum.h>
# include <msgsupp.h>
# include <strbuf.h>
# include <datetime.h>

# include "filesys.h"
# include "fileio.h"

# include <sys/types.h>
# include <utime.h>

# include <rms.h>
# include <starlet.h>
# include <descrip.h>
# include <iodef.h>
# include <atrdef.h>
# include <fibdef.h>

// # include <lib$routines.h>


extern int global_umask;

/* We avoid using the C runtime "chmod" function provided by OpenVMS, among
 * others, because that routine updates the timestamp on a file when you
 * change permissions.
 *
 * Typically the way one alters attributes like modification time or file
 * protections is through the use of RMS routines and extended attribute
 * (XAB) control blocks.  However, you can only do that if you can open the
 * file in the first place.  If a file is read-only, you can't modify
 * anything; not even the filesystem attributes of the file!
 *
 * Instead, we have to use QIO (Queue I/O services), which are a lower
 * layer which RMS itself uses.  With that interface, we don't have to open
 * a file in order to request a metadata operation on it.  Unfortunately,
 * because it's fairly low-level it's also quite tedious to use.
 *
 * This function encapsulates most of the work.
 */
static int
vms_attr_frob( char *filename, struct atrdef attrs[], unsigned int func )
{
  struct FAB fab;
  struct NAM nam;
  struct fibdef fib;

  char filename_expanded[ NAM$C_MAXRSS ];
  char filename_result[ NAM$C_MAXRSS ];

  struct dsc$descriptor_s filename_d = { 0,          DSC$K_DTYPE_T, DSC$K_CLASS_S, filename };
  struct dsc$descriptor_s dev_d      = { 0,          DSC$K_DTYPE_T, DSC$K_CLASS_S, &(nam.nam$t_dvi[1]) };
  struct dsc$descriptor   fib_d      = { sizeof fib, DSC$K_DTYPE_Z, DSC$K_CLASS_S, (char *) &fib };

  short int iosb[4]; /* i/o status block */

  short int dev_chan;
  int status;
  int i;

  fab = cc$rms_fab; /* initialize fields */
  fab.fab$l_fna = filename;
  fab.fab$b_fns = strlen( filename );

  nam = cc$rms_nam; /* initialize fields */
  nam.nam$l_esa = filename_expanded;
  nam.nam$b_ess = sizeof( filename_expanded );
  nam.nam$l_rsa = filename_result;
  nam.nam$b_rss = sizeof( filename_result );
  fab.fab$l_nam = &nam; /* chain to fab */

  status = sys$parse( &fab );
  if( !(status & 1) )
    {
      // lib$signal( status, fab.fab$l_stv );
      return -1;
    }

  /* Now we have a NAM block; use that to create a device channel, which we
     require in order to modify file metadata without opening it.
  */
  dev_d.dsc$w_length = nam.nam$t_dvi[0];
  status = sys$assign( &dev_d, &dev_chan, 0, 0 );
  if( !(status & 1) )
    {
      // lib$signal( status );
      return -1;
    }

  filename_d.dsc$a_pointer = nam.nam$l_name;
  filename_d.dsc$w_length  = nam.nam$b_name + nam.nam$b_type + nam.nam$b_ver;

  /* Initialize the fib */
  memset (&fib, 0, sizeof fib);
  for( i=0; i < 3; i++ )
    {
      fib.fib$w_fid[i] = nam.nam$w_fid[i];
      fib.fib$w_did[i] = nam.nam$w_did[i];
    }

  /* Don't update modtime due to any modifications.

     This is the very heart of this routine.  If this is not set, then when
     the protections on a file are updated, or various time fields are set,
     the modification time of the file is updated as well.
  */
  fib.fib$l_acctl = FIB$M_NORECORD;

  /* Set new file attributes.

     The meaning of variable parameters P1-6 (starting at the 7th overall
     parameter to this system routine) are dependent on the device type (we
     assume a file in a filesystem here) and the function we're performing
     (e.g. IO$_MODIFY).  These come from the openvms I/O reference manual:
     P1 - fib descriptor
     P2 - address of file name descriptor
     P3 - addr of word to receive length of filename result (don't care)
     P4 - address of filename result buffer (don't care)
     P5 - attribute descriptor list
     P6 - null
  */
  status = sys$qiow( NULL, /* no event flag */
                     dev_chan, func, &iosb,
                     NULL, NULL, /* no AST procedure or arg */
                     /* our request-specific parameters */
                     &fib_d, &filename_d, NULL, NULL, attrs, NULL );
  sys$dassgn( dev_chan ); /* close channel */

  if( !(status & 1) )
    {
      // lib$signal( status );
      return -1;
    }

  return 0;  /* success! */
}


static int
vms_attr_get( char *filename, struct atrdef attrs[] )
{
  return vms_attr_frob( filename, attrs, IO$_ACCESS );
}

static int
vms_attr_set( char *filename, struct atrdef attrs[] )
{
  return vms_attr_frob( filename, attrs, IO$_MODIFY );
}

int
vms_chmod( char *filename, unsigned int u_mode )
{
  /* Unix modes contain 'user', 'group', and 'other' fields.
   * There are three bits for each field:
   *     0x4 (r) - file can be read
   *     0x2 (w) - file can be mangled
   *     0x1 (x) - file contains bugs
   * Setting these *enable* access.
   *
   * VMS has system, owner, group, and world fields.
   * There are four bits for each field:
   *     0x8 (D) - If set, deletion prohibited
   *     0x4 (E) - If set, execution prohibited
   *     0x2 (W) - If set, writing prohibited
   *     0x1 (R) - If set, reading prohibited
   *  That is, setting these bits *disables* corresponding access.
   *
   * Since we are converting from unix to vms, we don't have as many
   * fields or mode bits, so we set write and delete to the same value.
   * Likewise, we set system and owner permissions to be the same.
   *
   * Note that we do not handle setuid/setgid/sticky bits here; those
   * require adding (or modifying) a POSIX extended access control entry
   * and we are only handling basic permissions.
   */
  unsigned short int v_mode
    = ~(  (((u_mode >> 0) & 2) << (12 + 2))  /* o(w) -> W(D) */
        | (((u_mode >> 0) & 1) << (12 + 2))  /* o(x) -> W(E) */
        | (((u_mode >> 0) & 2) << (12 + 0))  /* o(w) -> W(W) */
        | (((u_mode >> 0) & 4) << (12 - 2))  /* o(r) -> W(R) */

        | (((u_mode >> 3) & 2) << ( 8 + 2))  /* g(w) -> G(D) */
        | (((u_mode >> 3) & 1) << ( 8 + 2))  /* g(x) -> G(E) */
        | (((u_mode >> 3) & 2) << ( 8 + 0))  /* g(w) -> G(W) */
        | (((u_mode >> 3) & 4) << ( 8 - 2))  /* g(r) -> G(R) */

        | (((u_mode >> 6) & 2) << ( 4 + 2))  /* u(w) -> O(D) */
        | (((u_mode >> 6) & 1) << ( 4 + 2))  /* u(x) -> O(E) */
        | (((u_mode >> 6) & 2) << ( 4 + 0))  /* u(w) -> O(W) */
        | (((u_mode >> 6) & 4) << ( 4 - 2))  /* u(r) -> O(R) */

        | (((u_mode >> 6) & 2) << ( 0 + 2))  /* u(w) -> S(D) */
        | (((u_mode >> 6) & 1) << ( 0 + 2))  /* u(x) -> S(E) */
        | (((u_mode >> 6) & 2) << ( 0 + 0))  /* u(w) -> S(W) */
        | (((u_mode >> 6) & 4) >> ( 0 + 2))  /* u(r) -> S(R) */
        );

  struct atrdef attrs[] = { { sizeof v_mode, ATR$C_FPRO, &v_mode },
                            { 0, 0, 0 } };

  return vms_attr_set( filename, attrs );
}

int
vms_utime( char *filename, time_t modtime )
{
# if 0
  /* The vms-epoch timestamps passed to vms_attr_set have to be in local
     time, which means adjusting the unix time by the current timezone.
     This only returns the correct result if the timezone and offset (and
     DST status) are configured correctly by the system manager.
  */
  char *timezone = getenv( "SYS$TIMEZONE_DIFFERENTIAL" );
  if( timezone )
    modtime += atoi( timezone );  /* convert to localtime */
  /* convert unix epoch to openvms epoch with nanosecond resolution */
  __int64 mtime = ((__int64) modtime * 10000000UL) + 0x007c95674beb4000UL;

  /* The above is error-prone, so instead, we'll use the unix utime() call
     to set the modtime, then fetch the converted modtime using qiow and
     use that to also set creation time, revtime, etc.
  */
# endif

  struct utimbuf utm;
  utm.modtime = modtime;
  utm.actime = time(0) + atoi( timezone );
  if( utime( filename, &utm ) < 0)
    return -1;

  __int64 mtime;
  struct atrdef gattrs[] = { { sizeof mtime, ATR$C_MODDATE, &mtime },
                             { 0, 0, 0 } };
  if( vms_attr_get( filename, gattrs ) < 0)
    return -1;

  struct atrdef sattrs[] = { { sizeof mtime, ATR$C_CREDATE, &mtime },
                             { sizeof mtime, ATR$C_MODDATE, &mtime },
                             { sizeof mtime, ATR$C_REVDATE, &mtime },
                             // This is probably too aggressive:
                             // { sizeof mtime, ATR$C_ACCDATE, &mtime },
                             // { sizeof mtime, ATR$C_ATTDATE, &mtime },
                            { 0, 0, 0 } };
  return vms_attr_set( filename, sattrs );
}


void
FileIO::Chmod( FilePerm perms, Error *e )
{
	// Don't set perms on symlinks

	if( GetType() & FST_MASK == FST_SYMLINK )
	    return;

	// Permissions for readonly/readwrite, exec vs no exec

	int bits = IsExec() ? PERM_0777 : PERM_0666;

	switch( perms )
	{
	case FPM_RO: bits &= ~PERM_0222; break;
	case FPM_ROO: bits &= ~PERM_0266; break;
	case FPM_RXO: bits = PERM_0500; break;
	case FPM_RWO: bits = PERM_0600; break;
	case FPM_RWXO:  bits = PERM_0700; break;
	}

	if( vms_chmod( Name(), bits & ~global_umask ) >= 0 )
	    return;

	// Can be called with e==0 to ignore error.

	if( e )
	    e->Sys( "chmod", Name() );
}


void
FileIO::ChmodTime( int mtime, Error *e )
{
	if( vms_utime( Name(), DateTime::Localize( mtime ) ) < 0)
	    e->Sys( "utime", Name() );
}

void
FileIO::Rename( FileSys *target, Error *e )
{
	struct stat st;
        stat( Name(), &st );

	// On VMS and Novelle, the source must be writable (deletable,
	// actually) for the rename() to unlink it.  So we give it write
	// perm first and then revert it to original perms after.

	Chmod( FPM_RW, e );

	// Don't unlink the target unless the source exists,
	// as our rename isn't atomic (like on UNIX) and some
	// stumblebum user may have removed the source file.

	if( e->Test() )
	    return;

	// One customer (in Iceland) wanted this for IRIX as well.
	// You need if you are you running NFS aginst NT as well
	// if you are running on NT.  Gag me!

	target->Unlink( 0 ); // yeech - must not exist to rename

	if( rename( Name(), target->Name() ) < 0 )
	{
	    e->Sys( "rename", target->Name() );

	    // failed, reset target perms anyway.

	    target->Perms( perms );
	    target->Chmod( e );
            vms_utime( target->Name(), modTime );
	    return;
	}

	// reset the target to our perms

	target->Perms( perms );
	target->Chmod( e );
        vms_utime( target->Name(), st.st_mtime );

	// source file has been deleted,  clear the flag

	ClearDeleteOnClose();
}


/*
 * FileIO::Unlink() - remove single file (error optional)
 */

void
FileIO::Unlink( Error *e )
{
	if( !*Name() )
	    return;

	// yeech - must be writable to remove

	Chmod( FPM_RW, 0 );

	if( remove( Name() ) < 0 )
	{
	    if( e )
		e->Sys( "remove", Name() );
	    return;
	}

	// VMS versions files (RMS): delete them all.
	// (Supposedly remove() takes care of this, but
	// apparently not.)

	while( remove( Name() ) >= 0 )
	    ;
}
