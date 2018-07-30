/*
 * Copyright 2001 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * hash.h - simple in-memory hashing routines 
 *
 * This class implements a simple hashing scheme.  The client is
 * expected to subclass Hash, providing type-specific Compare(),
 * Key(), Delete(), and New() methods for the hashed data.
 *
 * The default Compare(), Key(), and Delete() assume that the
 * hashed item begins with a char * key.
 * 
 * Classes:
 *
 *	Hash - simple in-memory hashing routines
 *
 * Methods:
 *
 *	Hash::Find() - lookup item, possibly entering it
 *	Hash::Enter() - enter item into table
 *	Hash::Check() - lookup item, without entering it
 *	Hash::Keystring() - produce an integer hash of a string
 *	Hash::Stats() - dump out hash table statistics (stdout) 
 *
 * Virtual Methods, provided by subclass:
 *
 *	Hash::Compare() - compare two items
 *	Hash::Key() - produce an integer hash of item's key
 *	Hash::Delete() - delete an item
 *	Hash::New() - create an item
 */

struct Hash {

    public:
	int		Find( void **data, int enter );
	int		Enter( void **data ) { return !Find( data, !0 ); }
	int		Check( void **data ) { return Find( data, 0 ); }

    public:
			Hash( char *name );
	virtual		~Hash();

	virtual int 	Compare( void *d1, void *d2 );
	virtual int 	Key( void *d1 );
	virtual void 	Delete( void *d1 );
	virtual void *	New() = 0;

	int 		KeyString( const char *s );

	void		Stats();

    private:

	void		Rehash();

	struct Hasher	*hp;

} ;
