/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * Mapstrings.h - mapping table intial substrings
 *
 * Public Classes:
 *
 * 	MapStrings - probe strings for fast mapping
 *
 * Public Methods:
 *
 *	MapStrings::Count()
 *		Returns the number of initial substrings found in the
 *		MapStrings.
 *
 *	MapStrings::Dump()
 *		Print out the strings on the standard output.
 *
 *	MapStrings::Get( int n )
 *		Gets the n'th string (starting at 0) from the MapStrings.
 */

class VarArray;
class MapHalf;

class MapStrings {

    public:
			MapStrings();
			~MapStrings();

	void		Add( MapHalf *mapHalf, int hasSubDirs );
	int 		Count();
	void		Dump();
	void		Get( int n, StrRef &string, int &hasSubDirs );

    private:

	VarArray	*strs;
} ;

