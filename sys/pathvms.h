/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * Pathvms.h - filenames on VMS
 *
 * Public classes:
 *
 *	PathVMS - a StrPtr for a VMS path
 *
 * Public methods:
 */

class PathVMS : public PathSys {

    private:
	void	GetPointers();
	void	AddDirectory( const char *dir, int len );
	int	ToParentHavePointers();
	void 	ToRoot();

	int	lbrace;		// offset of [, -1 if none
	int	rbrace;		// offset of ], -1 if none
	int	atroot;		// it's foo: or foo:[000000]

    public:
	void	SetCanon( const StrPtr &root, const StrPtr &canon );
	void	SetLocal( const StrPtr &root, const StrPtr &local );
	int	GetCanon( const StrPtr &root, StrBuf &target );
	int	ToParent( StrBuf *file = 0 );
	int	IsUnderRoot( const StrPtr &root );
} ;
