/*
 * Copyright 2001 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>
# include <debug.h>

# include "hash.h"

/* 
 * hash.cc - simple in-memory hashing routines 
 */

/* Header attached to all data items entered into a hash table. */

struct HashItem {

	HashItem *next;
	int 	keyval;			/* for quick comparisons */
	void 	*data;

} ;

# define MAX_LISTS 32

struct Hasher 
{
	/*
	 * the hash table, just an array of item pointers
	 */

	struct {
	    int nel;
	    HashItem **base;
	} tab;

	int bloat;	/* tab.nel / items.nel */
	int inel; 	/* initial number of elements */

	/*
	 * the array of records, maintained by these routines
	 * essentially a microallocator
	 */ 

	struct {

	    int more;	/* how many more items fit in lists[ list ] */
	    HashItem *next;	/* where to put more items in lists[ list ] */
	    int nel;	/* total HashItems held by all lists[] */
	    int list;	/* index into lists[] */

	    struct {
		int nel;	/* total HashItems held by this list */
		HashItem *base;	/* base of HashItems array */
	    } lists[ MAX_LISTS ];

	} items;

	char *name;	/* just for hashstats() */
} ;

/*
 * hashinit() - initialize a hash table, returning a handle
 */

Hash::Hash( char *name )
{
	hp = new Hasher;

	hp->bloat = 3;
	hp->tab.nel = 0;
	hp->tab.base = 0;
	hp->items.more = 0;
	hp->items.list = -1;
	hp->items.nel = 0;
	hp->inel = 11;
	hp->name = name;
}

/*
 * hashdone() - free a hash table, given its handle
 */

Hash::~Hash()
{
	if( !hp )
	    return;

	if( hp->tab.base )
		delete []hp->tab.base;

	for( int i = 0; i <= hp->items.list; i++ )
	{
	    for( int j = 0; j < hp->items.lists[i].nel; j++ )
		Delete( hp->items.lists[i].base[j].data );

	    delete []hp->items.lists[i].base;
	}

	delete hp;
}


/*
 * hashitem() - find a record in the table, and optionally enter a new one
 */

int
Hash::Find(
	void **data,
	int enter )
{
	/* Full? Make room. */
	/* Empty? Don't look. */

	if( enter && !hp->items.more )
	    Rehash();

	if( !enter && !hp->items.nel )
	    return 0;

	/* Hash data to come up with semi-unique keyval. */
	/* Look in tables.  Use Compare() to verify values. */

	int keyval = Key( *data );
	HashItem **base = hp->tab.base + ( keyval % hp->tab.nel );
	HashItem *i;

	for( i = *base; i; i = i->next )
	    if( keyval == i->keyval && !Compare( i->data, *data ) )
	{
	    *data = i->data;
	    return !0;
	}

	/* Not there. Enter if requested. */

	if( enter ) 
	{
	    i = (HashItem *)hp->items.next;
	    i->keyval = keyval;
	    i->next = *base;
	    i->data = *data = New();
	    *base = i;
	    hp->items.next++;
	    hp->items.more--;
	}

	return 0;
}

/*
 * hashrehash() - resize and rebuild hp->tab, the hash table
 */

void 
Hash::Rehash()
{
	int i = ++hp->items.list;

	hp->items.more = i ? 2 * hp->items.nel : hp->inel;
	hp->items.next = new HashItem[ hp->items.more ];

	hp->items.lists[i].nel = hp->items.more;
	hp->items.lists[i].base = hp->items.next;
	hp->items.nel += hp->items.more;

	if( hp->tab.base )
	    delete []hp->tab.base;

	hp->tab.nel = hp->items.nel * hp->bloat;
	hp->tab.base = new HashItem *[ hp->tab.nel ];

	for( i = 0; i < hp->tab.nel; i++ )
	    hp->tab.base[ i ] = 0;

	for( i = 0; i < hp->items.list; i++ )
	{
	    int nel = hp->items.lists[i].nel;
	    HashItem *j = hp->items.lists[i].base;

	    for( ; nel--; j++ )
	    {
		HashItem **ip = hp->tab.base + j->keyval % hp->tab.nel;
		j->next = *ip;
		*ip = j;
	    }
	}
}

/* ---- */

void
Hash::Stats()
{
	HashItem **tab = hp->tab.base;
	int nel = hp->tab.nel;
	int count = 0;
	int sets = 0;
	int run = ( tab[ nel - 1 ] != (HashItem *)0 );
	int i, here;

	for( i = nel; i > 0; i-- )
	{
		if( here = ( *tab++ != (HashItem *)0 ) )
			count++;
		if( here && !run )
			sets++;
		run = here;
	}

	p4debug.printf( "%s table: %d+%d+%d (%dK+%dK) items+table+hash, %f density\n",
		hp->name, 
		count, 
		hp->items.nel,
		hp->tab.nel,
		hp->items.nel / 1024,
		hp->tab.nel * sizeof( HashItem ** ) / 1024,
		(float)count / (float)sets );
}

/* --- */
/* Virtual members for different data types */

/* What we think the user is normally hashing. */
/* It can be anything, as long as Compare, Key, and Delete */
/* are modified accordingly. */

struct HashData {
	char	*s;
} ;

int
Hash::Compare( void *d1, void *d2 )
{
	return strcmp( ((HashData *)d1)->s, ((HashData *)d2)->s );
}

int
Hash::Key( void *d1 )
{
	return KeyString( ((HashData *)d1)->s );
}

int
Hash::KeyString( const char *s )
{
	int keyval = *s;
	while( *s ) keyval = keyval * 2147059363 + *s++;
	return keyval & 0x7FFFFFFF;
}

void
Hash::Delete( void *d1 )
{
	/* nada */
}
