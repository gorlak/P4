/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * intarray.h -- a cheesy, zero-based, automatically resized int array
 */

class IntArray {

    public:
		IntArray( int nInts = 4 )
		{
		    ints = 0;
		    lInts = 0;
	            count = 0;
		    ReAlloc( nInts );
		}

		~IntArray()
		{
		    delete []ints;
		}

	int& operator []( int x ) 
		{ 
		    // geometric growth
		    if( x >= lInts ) ReAlloc( x * 3 / 2 );
		    return ints[x];
		}

	void	SetCount( int ct ) { count = ct; }
	int	Find( int v );
	bool	Contains( int v ) { return Find( v ) != -1; }

    private:

	void	ReAlloc( int nInts )
		{
		    int i = 0;
		    int *old = ints;
		    ints = new int[nInts];
		    for( ; i < lInts; i++ ) ints[i] = old[i];
		    for( ; i < nInts; i++ ) ints[i] = 0;
		    lInts = nInts;
		    delete []old;
		}

	int	lInts;
	int	*ints;
	int	count; // only used by Find()/Contains()

};

