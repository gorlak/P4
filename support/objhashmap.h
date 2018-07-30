/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * ObjectHashMap is a simple collection data structure for working
 * with Graph Depot objects. It can be used to manage a cache of
 * objects, to detect already-seen objects, or just to remember a
 * set of objects for later use.
 *
 * Method Summary:
 *
 *    Clear        Removes all entries from the map
 *    Contains(sha)    Returns whether this map contains this sha
 *    Get(sha)    Returns the object with this sha, or 0
 *    Put(sha,object) Adds an entry to the map, error if exists
 *    Remove(sha)    Removes and returns the object
 *    Size        Returns the number of entries
 *
 * The underlying data structure is relatively crude, and gets its
 * runtime performance behaviors via the properties of the SHA1
 * hashing of Graph Depot objects. ObjectHashMap instances come
 * in 5 sizes, from extra-small through extra-large, though hopefully
 * most usages will typically only use small and medium.
 *
 * The current implementation is not intended to be used for truly
 * massive collections, and refuses to add more than MAX_OBJECTS
 * entries to a single ObjectHashMap.
 *
 * We work with the raw (unsigned char [20]) 160-bit binary SHA1
 * values in this class, typically passed in and out as a crude
 * (unsigned char *) datatype, which is assumed to point to the
 * corresponding 20-byte buffer.
 *
 * If you don't tell the ObjectHashMap what size you want, you get
 * a small map to start, and the map automatically resizes from
 * small to medium when you add the 4096 object, and from medium
 * to large when you add the 65,536th object. Maps never resize
 * to a smaller size, even when you clear() them.
 *
 * Each bucket, if non-empty, is a doubly-linked list of Graph
 * Depot object instances which hash to that bucket; the hash
 * chains are maintained in SHA1 order so that searching a chain
 * for a particular object traverses, on average, half of the
 * objects in the chain.
 *
 * The table, itself is an array of ObjectHashBucket instances,
 * and each item in a ObjectHashBucket hash chain is an
 * ObjectHashTableEntry instance.
 *
 * You can enumerate the objects in an ObjectHashMap; if you do,
 * they come back in SHA1 order. You use the ObjectHashMapIterator
 * to make such a traversal.
 *
 * THERE IS NO LOCKING OR CONCURRENCY CONTROL IN THIS DATA
 * STRUCTURE! IT IS ENTIRELY UNSYNCHRONIZED AND NOT THREAD SAFE!
 */

class ObjectHashTableEntry
{
    public:

	ObjectHashTableEntry    *next;
	ObjectHashTableEntry    *prev;
	void                    *object;
	Sha1                     sha1;

    	int            Compare( const unsigned char *o )
                       { return sha1.Compare( o ); }
	               
    	int            Compare( const Sha1 &o )
                       { return sha1.Compare( o ); }
} ;

class ObjectHashBucket
{
    public:

    ObjectHashTableEntry    *head;
} ;


class ObjectHashMap
{
    public:

    	enum HashMapSize {
	        EXTRA_SMALL = 256,   	// 8 bits
	        SMALL       = 4096,  	// 12 bits
	        MEDIUM      = 65536,	// 16 bits
	        LARGE       = 262144,	// 18 bits
	        EXTRA_LARGE = 1048576	// 20 bits
	} ;

    static const int MAX_OBJECTS = 10 * 1024 * 1024;

                ObjectHashMap( int size = SMALL );
                ~ObjectHashMap();

    void            Clear();

    int            Contains( const Sha1 &sha );
    int            Contains( const unsigned char * );

    void            *Get( const Sha1 &sha );
    void            *Get( const unsigned char * );

    int            Put( const Sha1 &sha, void *object );

    void            *Remove( const Sha1 &sha );

    int            Size();

	void		DumpSummary();

    private:

    void            CheckForResize();

    void            Resize( int newSize );

    	ObjectHashBucket    *Bucket( const Sha1 &sha );

    	static ObjectHashBucket    *Bucket(
	                                int sz,
	                                ObjectHashBucket *table,
	                                const unsigned char *sha );

    void            PutInNewTable(
                                ObjectHashTableEntry *o,
                                ObjectHashBucket *newTable,
                                int newSize );

    int            numObjects;
    int            tableSize;
    ObjectHashBucket    *table;

    friend class ObjectHashMapIterator;
} ;

class ObjectHashMapIterator
{
    public:

                ObjectHashMapIterator(
                                ObjectHashMap *map )
                {
                    this->map = map;
                    this->bucketNo = -1;
                    this->entry = 0;
                }

                ~ObjectHashMapIterator() { }

    int            Next(
                                Sha1 &sha,
                                void **object );

    private:

    ObjectHashMap        *map;
    ObjectHashTableEntry    *entry;
    int            bucketNo;
} ;

