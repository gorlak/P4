/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# define NEED_SLEEP
# include <stdhdrs.h>

# include <strbuf.h>
# include <error.h>
# include <debug.h>
# include <vararray.h>
# include <sha1.h>

# include "objhashmap.h"

ObjectHashMap::ObjectHashMap( int size )
{
    // Force size to be reasonable:

    switch( size )
    {
    default:
        size = SMALL;
        // fall-through...

    case EXTRA_SMALL:
    case SMALL:
    case MEDIUM:
    case LARGE:
    case EXTRA_LARGE:
        tableSize = size;
        break;
    }

    numObjects = 0;

    table = new ObjectHashBucket[ tableSize ];

    memset( table, 0, tableSize * sizeof( ObjectHashBucket ) );
}

ObjectHashMap::~ObjectHashMap()
{
    Clear();
    delete []table;
}

void
ObjectHashMap::Clear()
{
    for( int i = 0; i < tableSize; i++ )
    {
        ObjectHashBucket *b = &table[ i ];
        ObjectHashTableEntry *hte = b->head, *hteNext;

        while( hte )
        {
            hteNext = hte->next;
            delete hte;
            hte = hteNext;
        }
        b->head = 0;
    }
    numObjects = 0;
}

void
ObjectHashMap::DumpSummary()
{
    int n = 0;
    p4debug.printf("Summary of hashmap with %d objects\n", numObjects);

    for( int i = 0; i < tableSize; i++ )
    {
        ObjectHashBucket *b = &table[ i ];
        ObjectHashTableEntry *hte = b->head;

        while( hte )
        {
	    n++;
	    StrBuf shaBuf;
	    hte->sha1.Fmt( shaBuf );
	    p4debug.printf("Obj %d: %s @%p\n", n, shaBuf.Text(), hte->object );
            hte = hte->next;
        }
    }
}

int
ObjectHashMap::Contains( const Sha1 &sha )
{
    return Get( sha ) != 0;
}

int
ObjectHashMap::Contains( const unsigned char *sha )
{
    return Get( sha ) != 0;
}

void *
ObjectHashMap::Get( const Sha1 &sha )
{
	return Get( sha.data );
}

void *
ObjectHashMap::Get( const unsigned char *sha )
{
    ObjectHashBucket *b = Bucket( sha );
    ObjectHashTableEntry *hte = b->head;

    while( hte )
    {
        int cmp = hte->Compare( sha );

        if( !cmp )
            return hte->object;
        if( cmp > 0 )
            return 0;
        hte = hte->next;
    }
    return 0;
}

int
ObjectHashMap::Put( const Sha1 &sha, void *object )
{
    if( numObjects >= MAX_OBJECTS )
        return 0;

    ObjectHashBucket *b = Bucket( sha );
    ObjectHashTableEntry *hte = b->head;
    ObjectHashTableEntry *last = 0;

    while( hte )
    {
        int cmp = hte->Compare( sha );

        if( !cmp )
            return 0; // already exists, can't add

        if( cmp > 0 )
        {
            // The new object goes immediately before this one:

            ObjectHashTableEntry *e = new ObjectHashTableEntry;
	    e->sha1 = sha;
            e->object = object;
            e->next = hte;
            e->prev = hte->prev;
            if( !last )
                b->head = e;
            else
                last->next = e;
            hte->prev = e;
            CheckForResize();
            return 1;
        }
        last = hte;
        hte = hte->next;
    }
    // The new object goes at the end of the chain:

    ObjectHashTableEntry *e = new ObjectHashTableEntry;
    e->sha1 = sha;
    e->object = object;
    e->next = 0;
    e->prev = last;
    if( !last )
        b->head = e;
    else
        last->next = e;
    CheckForResize();

    return 1;
}

void *
ObjectHashMap::Remove( const Sha1 &sha )
{
    ObjectHashBucket *b = Bucket( sha );
    ObjectHashTableEntry *hte = b->head;

    while( hte )
    {
        int cmp = hte->Compare( sha );

        if( !cmp )
        {
            void *result = hte->object;
            if( hte->next )
                hte->next->prev = hte->prev;
            if( hte->prev )
                hte->prev->next = hte->next;
            else
                b->head = hte->next;
            delete hte;
	    numObjects--;
            return result;
        }

        if( cmp > 0 )
            return 0;
        hte = hte->next;
    }
    return 0;
}

int
ObjectHashMap::Size()
{
    return numObjects;
}

void
ObjectHashMap::CheckForResize()
{
    ++numObjects;
    if( tableSize == EXTRA_SMALL && numObjects == EXTRA_SMALL )
        Resize( SMALL );
    else if( tableSize == SMALL && numObjects == SMALL )
        Resize( MEDIUM );
    else if( tableSize == MEDIUM && numObjects == MEDIUM )
        Resize( LARGE );
    else if( tableSize == LARGE && numObjects == LARGE )
        Resize( EXTRA_LARGE );
}

void
ObjectHashMap::Resize( int newSize )
{
    // allocate a new table
    // copy all the objects to the new table
    // clear and delete the old table
    // use the new table

    ObjectHashBucket *newTable = new ObjectHashBucket[ newSize ];
    memset( newTable, 0, newSize * sizeof( ObjectHashBucket ) );

    for( int i = 0; i < tableSize; i++ )
    {
        ObjectHashBucket *b = &table[ i ];
        ObjectHashTableEntry *hte = b->head;

        while( hte )
        {
            PutInNewTable( hte, newTable, newSize );
            hte = hte->next;
        }
    }

    int oCount = numObjects;

    Clear();
    delete []table;

    table = newTable;
    tableSize = newSize;
    numObjects = oCount;
}

ObjectHashBucket *
ObjectHashMap::Bucket( const Sha1 &sha )
{
	return Bucket( tableSize, table, sha.data );
}

ObjectHashBucket *
ObjectHashMap::Bucket(
	int sz,
	ObjectHashBucket *tb,
	const unsigned char *sha )
{
    int bucketNo;

    switch( sz )
    {
    case EXTRA_SMALL:					// 8 bits
        bucketNo =   sha[0];
        break;

    case SMALL:						// 12 bits
        bucketNo = ( sha[0] << 4 )   |
	    ( ( sha[1] >> 4 ) & 0x0f ) ;
        break;

    case MEDIUM:					// 16 bits
        bucketNo = ( sha[0] << 8 )   |
	             sha[1];
        break;

    case LARGE:						// 18 bits
        bucketNo = ( sha[0] << 10 )  |
                   ( sha[1] <<  2 )  |
	    ( ( sha[2] >> 6 ) & 0x03 ) ;
        break;

    case EXTRA_LARGE:					// 20 bits
        bucketNo = ( sha[0] << 12 )  |
                   ( sha[1] <<  4 )  |
	    ( ( sha[2] >> 4 ) & 0x0f ) ;
        break;

    }

    return tb + bucketNo;
}

void
ObjectHashMap::PutInNewTable(
    ObjectHashTableEntry *o,
    ObjectHashBucket *newTable,
    int newSize )
{
    ObjectHashBucket *b = Bucket( newSize, newTable, o->sha1.data );

    ObjectHashTableEntry *hte = b->head;
    ObjectHashTableEntry *last = 0;

    while( hte )
    {
        int cmp = hte->Compare( o->sha1 );

        if( !cmp )
            return; // (can't happen, since old table contained no dups)

        if( cmp > 0 )
        {
            // The new object goes immediately before this one:

            ObjectHashTableEntry *e = new ObjectHashTableEntry;
	    e->sha1 = o->sha1;
            e->object = o->object;
            e->next = hte;
            e->prev = hte->prev;
            if( !last )
                b->head = e;
            else
                last->next = e;
            hte->prev = e;
            return;
        }
        last = hte;
        hte = hte->next;
    }
    // The new object goes at the end of the chain:

    ObjectHashTableEntry *e = new ObjectHashTableEntry;
    e->sha1 = o->sha1;
    e->object = o->object;
    e->next = 0;
    e->prev = last;
    if( !last )
        b->head = e;
    else
        last->next = e;
}

/***********************************************************************/

int
ObjectHashMapIterator::Next( Sha1 &sha, void **object )
{
    if( entry && entry->next )
    {
        entry = entry->next;
	sha = entry->sha1;
        *object = entry->object;
        return 1;
    }

    while( 1 )
    {
        bucketNo++;

        if( bucketNo >= map->tableSize )
            return 0;

        ObjectHashBucket *b = map->table + bucketNo;
    
        if( b->head )
        {
            entry = b->head;
	    sha = entry->sha1;
            *object = entry->object;
            return 1;
        }
    }
}
