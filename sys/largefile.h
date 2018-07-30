/*
 * Copyright 2009 Perforce Software.  All rights reserved.
 */

/*
 * Large file I/O
 *
 * We define:
 *
 *	fstatL
 *	lseekL
 *	lstatL -- not NT
 *	statL
 *	statbL -- the stat buffer, if different
 *	openL
 *
 *	preadL
 *	pwriteL
 *
 * to be either the call that takes 64 bit offsets or, in the case of no
 * such interface, the 32 bit calls.  In the latter case, we're thinking
 * offL_t (define in sys/stdhdrs.h) will be 32 bits as well.
 */

/* AIX et al */

# if defined(OS_AIX43) || \
     defined(OS_LINUX) && defined(__USE_LARGEFILE64) || \
     defined(OS_HPUX11) && defined(_LARGEFILE64_SOURCE) || \
     defined(OS_SOLARIS) && !(OS_SOLARIS25) || \
     defined(OS_UNIXWARE7) 

# define fopenL fopen64
# define fstatL fstat64
# define lseekL lseek64
# define lstatL lstat64
# define openL open64
# define statL stat64
# define statbL stat64
# endif 

/* OS_IRIX */

# ifdef OS_IRIX
# define fopenL fopen
# define fstatL fstat64
# define lseekL lseek64
# define lstatL lstat64
# define openL open
# define statL stat64
# define statbL stat64 // guessing here
# endif 

/* NT */

# if defined(OS_NT)
# define fopenL fopen
# define fstatL _fstati64
# define lseekL _lseeki64
# define statL _stati64
# define openL open
# define statbL _stati64
# endif 

/* 32 bit or native default */

# ifndef fstatL
# define fopenL fopen
# define fstatL ::fstat
# define lseekL lseek
# define lstatL lstat
# define openL open
# define statL stat
# define statbL stat
# endif

/* pread & pread64 */

# if defined(OS_FREEBSD) && !defined(OS_FREEBSD22) || \
     defined(OS_LINUX) && defined(__USE_UNIX98) && !defined(__USE_LARGEFILE64)
# define preadL pread
# define pwriteL pwrite
# endif

# if defined(OS_AIX43) || \
     defined(OS_HPUX11) && defined(_LARGEFILE64_SOURCE) || \
     defined(OS_LINUX) && defined(__USE_UNIX98) && defined(__USE_LARGEFILE64)||\
     defined(OS_SOLARIS) && !(OS_SOLARIS25) || \
     defined(OS_UNIXWARE7)
# define preadL pread64
# define pwriteL pwrite64
# endif
