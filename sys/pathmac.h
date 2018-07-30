/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * PathMAC.h - filenames on MAC
 *
 * Public classes:
 *
 *	PathMAC - a StrPtr for a MAC path
 *
 * Public methods:
 */

class PathMAC : public PathSys {

    public:
	void	SetCanon( const StrPtr &root, const StrPtr &canon );
	void	SetLocal( const StrPtr &root, const StrPtr &local );
	int	GetCanon( const StrPtr &root, StrBuf &target );
	int	ToParent( StrBuf *file = 0 );
	int	IsUnderRoot( const StrPtr &root );
} ;
