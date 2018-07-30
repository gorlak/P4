/*
 * Copyright 1995, 2003 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * MapItem -- mapping entries on a chain
 *
 * A MapItem holds two MapHalfs that constitute a single entry in
 * a MapTable.  MapItem also implement fast searching for entries
 * for MapTable::Check() and MapTable::Translate().
 */

class MapItemArray;
class MapItem {

    public:
			MapItem( 
			    MapItem *c, const StrPtr &l, 
			    const StrPtr &r, MapFlag f, int s,
			    int caseMode = -1 ) 
			{
			    *Lhs() = l;
			    *Rhs() = r;
			    mapFlag = f;
			    chain = c;
			    slot = s;
			    halves[0].left = 0;
			    halves[0].center = 0;
			    halves[0].right = 0;
			    halves[1].left = 0;
			    halves[1].center = 0;
			    halves[1].right = 0;
			    if( caseMode == 0 || caseMode == 1 )
			    {
			        halves[0].half.SetCaseMode( caseMode );
			        halves[1].half.SetCaseMode( caseMode );
			    }
			}

	MapHalf *	Lhs() { return Half( LHS ); }
	MapHalf *	Rhs() { return Half( RHS ); }
	MapHalf *	Ths( MapTableT dir ) { return Half( dir ); }
	MapHalf *	Ohs( MapTableT dir ) { return Half( 1 - dir ); }
	MapItem *	Next() { return chain; }
	MapFlag		Flag() { return mapFlag; }
	int		Slot() { return slot; }

	MapItem *	Reverse();
	MapItem *	Move( int slot );

    public:

	/*
	 * Trinary tree construction and access for fast access to the
	 * right MapItem when matching.
	 */

	void		Dump( MapTableT d, const char *name, int l = 0 );

	MapItem *	Match( MapTableT dir, const StrPtr &from,
			    MapItemArray *ands = 0 );

	static MapItem *Tree( MapItem **s, MapItem **e,
			    MapTableT dir, MapItem *parent,
			    int &depth );

    private:
    public:

	/*
	 * chain - linked list
	 * mapFlag - represent +map, or -map
	 * slot - precedence (higher is better) on the chain
	 */

        MapItem   	*chain;
	MapFlag	    	mapFlag;
	int		slot;

	/*
	 * halves - MapHalf and trinary tree for each direction
	 *
	 * Trinary tree?
	 *
	 *	left: 	less than this mapping
	 *	right: 	greater than this mapping
	 *	center:	included in this mapping
	 *
	 * e.g. a center for //depot/... might be //depot/main/...
	 */

	struct MapWhole {
		MapHalf	half;

		MapItem	*left;
		MapItem	*center;
		MapItem *right;

		int	maxSlot;
		int	overlap;
		int	hasands;
		int	maxSlotNoAnds;
	} halves[2]; 

	MapWhole *	Whole( int dir ) { return &halves[dir]; }
	MapHalf *	Half( int dir ) { return &halves[dir].half; }

	int		IsParent( MapItem *other, MapTableT dir )
			{
			    return 
				Ths( dir )->GetFixedLen() ==
			    	Ths( dir )->GetCommonLen( other->Ths( dir ) );
			}

} ;

class MapTree {

    public:
		MapTree() { sort = 0; tree = 0; }
		~MapTree() { delete []sort; }

	void	Clear() { delete []sort; sort = 0; tree = 0; }

	MapItem **sort;
	MapItem *tree;
	int depth;

};

/*
 * MapPair - pair of MapItem entries that are candidates for Join
 */

class MapPair {

    public:

	MapPair( MapItem *item1, MapItem *tree2, MapHalf *h1, MapHalf *h2 )
	{
	    this->item1 = item1;
	    this->tree2 = tree2;
	    this->h1 = h1;
	    this->h2 = h2;
	}

	// For MapPairArray::Sort()

	int CompareSlot( MapPair *o )
	{
	    int r;

	    if( !( r = item1->slot - o->item1->slot ) )
	           r = tree2->slot - o->tree2->slot;

	    return -r;
	}

    public:

	MapItem *item1;
	MapItem *tree2;
	MapHalf *h1;
	MapHalf *h2;

} ;

/*
 * MapPairArray - array of MapPairs, candidates for MapHalf::Join
 *
 *	MapPairArray::Match() - match a MapItem against the tree,
 *		adding any potentially matching entries to the
 *		array.
 *
 *	MapPairArray::Sort() - resort entries according to their
 *		map precedence rather than tree order.
 *
 *	MapPairArray::Get() - retrieve an entry suitable for
 *		calling MapHalf::Join().
 */

class MapPairArray : public VVarArray {

    public:
			MapPairArray( MapTableT dir1, MapTableT dir2 )
			{
			    this->dir1 = dir1;
			    this->dir2 = dir2;
			}

	void		Match( MapItem *item1, MapItem *tree2 );

	MapPair		*Get( int i ) { return (MapPair*)VarArray::Get(i); }

    private:

	virtual int	Compare( const void *a1, const void *a2 ) const;
	virtual void	Destroy( void *a1 ) const {}

	MapTableT 	dir1;
	MapTableT	dir2;

};

/*
 * MapItemArray - array of MapItems, means for returning multiple results
 *                from Match()
 *
 *	MapPairArray::Get() - retrieve an item to the array ordered by slot.
 *
 *	MapPairArray::Put() - adds an item to the array ordered by slot.
 */

class MapItemArray : public VarArray {

    public:
			~MapItemArray();
	MapItem *	Get( int i );
	StrPtr  *	GetTranslation( int i );
	MapItem *	Put( MapItem *i, StrPtr *t = 0 );
	int		PutTree( MapItem *i, MapTableT dir );
	void		Dump( const char *name );
};

