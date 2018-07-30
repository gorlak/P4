/*
 * Copyright 2006 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * random.h - provide some pseudo-random values
 */

class Random {

    public:

	static int	Integer( int low, int high );
	static void	String( StrBuf *, int length,
				char lowchar, char hichar );
};
