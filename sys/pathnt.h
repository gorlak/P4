/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * PathNT.h - filenames on NT
 *
 * Public classes:
 *
 *	PathNT - a StrPtr for a NT path
 *
 * Public methods:
 */

class PathNT : public PathSys {

    public:
	PathNT();
	void	SetCanon( const StrPtr &root, const StrPtr &canon );
	void	SetLocal( const StrPtr &root, const StrPtr &local );
	int	GetCanon( const StrPtr &root, StrBuf &target );
	int	ToParent( StrBuf *file = 0 );
	void	SetCharSet( int = 0 );
	int	IsUnderRoot( const StrPtr &root );

    private:
	int	EndsWithSlash() const;
	int	IsUnder( StrRef *, const char * ) const;

	int	charset;
} ;
