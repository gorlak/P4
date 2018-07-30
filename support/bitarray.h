/*
 * Copyright 2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

class BitArray {
public:
    typedef unsigned int Index;

    // BitBlock needs to match the type used by the select fd_set arrays
    // and needs to be 32 bits.
    // I can not find a portable way to do that for sure
    // but int is pretty safe for that
    typedef long BitBlock;

    BitArray( Index nBits );
    ~BitArray() { delete [] w; }
    int tas( Index );
    int operator []( Index ) const;
    int clear( Index );
    void *fdset() { return (void *)w; }
private:
    BitBlock *w;
};
