/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * stdhdrs.cc - standard things that ain't right
 */

# if defined( OS_MACOSX ) || defined( OS_DARWIN )
# define NEED_CHMOD
# endif

# ifdef OS_VMS62
# define NEED_FILE
# endif

# include <stdhdrs.h>
# include <strbuf.h>
# include <error.h>
# include <filesys.h>

# ifdef BAD_MEMCCPY

void *
memccpy( void *t, const void *f, int c, size_t n)
{

	if (n) {
		unsigned char *tp = (unsigned char *)t;
		const unsigned char *fp = (unsigned char *)f;
		unsigned char uc = c;
		do {
			if ((*tp++ = *fp++) == uc)
				return (tp);
		} while (--n != 0);
	}
	return (0);
}

#endif


# ifdef OS_VMS62

int
rmdir( const char *name )
{
	return remove( name );
}

# endif
