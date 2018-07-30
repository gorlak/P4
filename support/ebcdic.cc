/*
 * Copyright 2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * ebcdic.cc - etoa and atoe for the AS400
 *
 * Thank you Peter Eberlein.
 */

# ifdef OS_AS400

# include <iconv.h>

static iconv_t etoa = iconv_open("IBMCCSID00819\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 
                                 "IBMCCSID000000000100\0\0\0\0\0\0\0\0\0\0\0");
static iconv_t atoe = iconv_open("IBMCCSID00000\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 
                                 "IBMCCSID008190000100\0\0\0\0\0\0\0\0\0\0\0");

void __etoa_l(char *c, unsigned long l)
{
  char *from = c;
  char *to   = c;
  size_t from_size = (size_t)l;
  size_t to_size   = (size_t)l;

  iconv(etoa, &from, &from_size, &to, &to_size);
}

void __atoe_l(char *c, unsigned long l)
{
  char *from = c;
  char *to   = c;
  size_t from_size = (size_t)l;
  size_t to_size   = (size_t)l;

  iconv(atoe, &from, &from_size, &to, &to_size);
}

# endif
