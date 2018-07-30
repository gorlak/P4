/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * MapTable.h - mapping table interface
 *
 * Public Classes:
 *
 * 	MapTable - a mapping table
 *
 * Public Methods:
 *
 *	MapTable::Better( MapTable &other, MapTableT dir )
 *		Compares the depths of MapTree used for matching to see
 *		which table would provide quicker matching.
 *
 *	MapTable::Check( MapTableT direction, char *from )
 *		Does the matching part of Translate(), but not the generating
 *		of the target string.  Returns 0 on no match and a MapItem *
 *		on match.
 *
 *	MapTable::Clear()
 *		Empties the table.
 *
 *	MapTable::Count()
 *		Returns the number of map entries.
 *	
 *	MapTable::Disambiguate()
 *		Mappings provided by the user (client views, branch views)
 *		can be ambiguous since later mappings can override earlier
 *		ones.  Disambiguate() adds explicit exclusion (-) mappings 
 *		for any ambiguous mappings, so that Join() and Translate()
 *		don't have to worry about them.
 *		
 *	MapTable::Dump( char *trace )
 *		Print out the mapping on the standard output.
 *
 *	MapTable::EmptyReason()
 *		Return what was set by SetReason() or Join().
 *
 *	MapTable::Get( int n )
 *		Gets the n'th map table entry, returning a MapItem *.
 *
 *	MapTable::GetFlag( MapItem *m )
 *		Gets MapItem m's map flag.
 *
 *	MapTable::GetStr( MapItem *m, MapTableT dir )
 *		Gets MapItem m's map string for dir.
 *
 *	MapTable::Insert( const StrPtr &lhs, const StrPtr &rhs, MapFlag f )
 *		Insert a mapping entry.  The following wildcards are 
 *		supported: %1-%9, *, "...".  lhs and rhs must agree 
 *		in wildcards.
 *		
 *	MapTable::InsertByPattern( StrBuf &lhs, StrBuf &rhs, MapFlag f )
 *		Takes two strings and makes a pattern out of them by 
 *		replacing the righthand common substrings with ... or *
 *		depending on whether the substrings included a '/'.
 *		Won't replace the first 3 '/'s (i.e. //depot/).
 *		
 *	MapTable::IsEmpty()
 *		Returns 1 if there are no map table entries, or
 *		if all entries are unmappings.
 *
 *	MapTable::HasOverlays()
 *		Returns 1 if there are + mappings in the table.
 *
 *	MapTable::IsSingle()
 *		Returns 1 if there exactly one mapping and it contains no
 *		wildcards.
 *
 *	MapTable::Join( MapTableT d1, MapTable *m2, MapTableT d2, ErrorId *r )
 *		Joins the d1 side of this mapping against the d2 side of
 *		the mapping in m2, filling in the MapTable.  The result is 
 *		the revised (limited) lhs and rhs of the map.  r is the
 *		emptyReason used if the join turns up empty but neither map
 *		was empty.
 *
 *	MapTable::Join2( MapTableT d1,MapTable *m2, MapTableT d2, ErrorId *r )
 *		Joins the mapping in this mapping against the mapping in m2, 
 *		filling in the MapTable.  The rhs of the map is joined with 
 *		the lhs of maps2, and the result is the revised lhs of 
 *		m1 and the revised rhs of m2.
 *
 *	MapTable::JoinCheck( MapTableT dir, const StrPtr &lhs )
 *		Returns 1 if lhs joined agains the dir of this MapTable 
 *		produces any rows, i.e. if this MapTable includes lhs.
 *
 *	MapTable::Match( char *lhs, char *from )
 *		Matches the pattern lhs against from.  Returns 1 on match
 *		and 0 on no match.  Cheesy access to MapHalf::Match().
 *
 *	MapTable::Reverse()
 *		Turn the order of the mapping around, to make them appear
 *		if they were appended instead of inserted.
 *
 *	Maptable::SetReason( char *emptyReason )
 *		Set reason to be returned by EmptyReason().  The reason 
 *		strings are assumed to be global.  This reason string is
 *		used by DbPipeMap* (if set) if the map is empty or filtered
 *		out all the incoming rows.
 *
 *	MapTable::Strings( MapTableT direction )
 *		Returns a MapStrings object which contains sorted initial
 *		substrings for finding candidates pathnames that will map
 *		through the MapTable.  Direction == LHS (0) or RHS (1),
 *		meaning find strings for all lhs or rhs sides of the mapping.
 *
 *	MapTable::StripMap( MapFlag mapFlag )
 *		Returns a copy of the MapTable, without any of the mapFlag 
 *		entries.
 *
 *	MapTable::Translate( MapTableT dir, char *from, StrBuf *to )
 *		Maps 'from' to 'to' returning the MapItem that matched, or 0
 *		if nothing matches.  Direction is LHS (0) if 'from' 
 *		matches lhs, and RHS (1) if 'from' matches rhs.
 *
 *	MapTable::Validate( char *lhs, char *rhs, Error *e )
 *		Verifies that a mapping has the same wildcards on both
 *		sides.
 *
 *	MapTable::ValidHalf( MapTableT direction, Error *e )
 *		Verifies that a mapping has the permitted number of 
 *		wildcards.
 */

class MapItem;
class MapJoiner;
struct MapParams;
class MapStrings;
class MapTree;
class MapHalf;
class StrBuf;
class MapItemArray;

enum MapTableT { 
	LHS, 		// do operation on left-hand-side strings
	RHS 		// do operation on right-hand-side strings
} ;

enum MapFlag {
	MfMap,		// map
	MfUnmap,	// -map
	MfRemap,	// +map
	MfHavemap,	// $map
	MfChangemap,	// @map
	MfAndmap,	// &map
			// empty
			// empty
			// empty
			// empty
	MfStream1 = 10,	// Stream, Paths 
	MfStream2 = 11,	// Stream, Remapped
	MfStream3 = 12,	// Stream, Ignored 
	MfStream5 = 14,	// Stream, Paths: shared
	MfStream6 = 15,	// Stream, Paths: public 
	MfStream7 = 16,	// Stream, Paths: private
	MfStream8 = 17	// Stream, Paths: excluded
} ;

class MapTable {

    public:

			MapTable();
			~MapTable();

	MapTable& operator=( MapTable &f );

	int		Better( MapTable &other, MapTableT direction );
	MapItem *	Check( MapTableT direction, const StrPtr &from );
	void		Clear();
	int		Count() { return count; }
	void		Disambiguate();
	void		Dump( const char *trace, int fmt=0 );
	void		DumpTree( MapTableT dir, const char *trace );
	void		Insert( const StrPtr &l, 
			    const StrPtr &r = StrRef::Null(), 
			    MapFlag f = MfMap );
	void		Insert( const StrPtr &l, int slot,
			    const StrPtr &r = StrRef::Null(), 
			    MapFlag f = MfMap );
 
	void		Insert( MapTable *table, int fwd = 1, int rev = 0 );
	void 		InsertByPattern( const StrPtr &l, const StrPtr &r, 
			                 MapFlag f );
	int		IsEmpty() const { return !hasMaps; }
	int		JoinError() const { return joinError; }
	int		HasOverlays() const { return hasOverlays; }
	int		HasHavemaps() const { return hasHavemaps; }
	int		HasAndmaps() const { return hasAndmaps; }
	int		IsSingle() const;
	void 		JoinOptimizer( MapTableT dir2 );
	MapTable *	Join(  MapTableT dir1, MapTable *m2, 
			       MapTableT dir2, const ErrorId *reason = 0 );
	MapTable *	Join2( MapTableT dir1, MapTable *m2, 
			       MapTableT dir2, const ErrorId *reason = 0 );
	int		JoinCheck( MapTableT dir, const StrPtr &lhs );
	int		JoinCheck( MapTableT dir, MapTable *c,
			           MapTableT dir2 = LHS);
	static int 	Match( const StrPtr &lhs, const StrPtr &rhs );
	static int 	Match( MapHalf *l, const StrPtr &rhs );
	static int	ValidDepotMap( const StrPtr &map );
	void		Remove( int slot );
	void		Reverse();
	MapStrings *	Strings( MapTableT dir );
	MapTable *	StripMap( MapFlag mapFlag );
	MapTable *	Swap( MapTable *m );
	int		CountByFlag( MapFlag mapFlag );
	MapItem *	Translate( MapTableT dir, const StrPtr &f, StrBuf &t );
	MapItemArray *	Explode( MapTableT dir, const StrPtr &f );
	void		Validate( const StrPtr &l, const StrPtr &r, Error *e );
	void		ValidHalf( MapTableT dir, Error *e );
	int		GetHash();

	void		SetReason( const ErrorId *e ) { emptyReason = e; }
	const ErrorId *	EmptyReason() { return emptyReason; }

    public:

	// MapItem access, so we don't have to declare the MapItem here.

	MapItem *		Get( int n );

	int			GetSlot( MapItem *m );
	static MapFlag		GetFlag( MapItem *m );
	static MapItem *	GetNext( MapItem *m );
	static const StrPtr *	GetStr( MapItem *m, MapTableT direction );

	const StrPtr *		Get( int n, MapTableT direction )
				{ return GetStr( Get( n ), direction ); }

	static int		Translate( MapItem *m, MapTableT dir, 
					const StrPtr &f, StrBuf &t );

    public:

	// For internal use.

	void		InsertNoDups( const StrPtr &l, const StrPtr &r, 
				    MapFlag flag );

	MapItem **	Sort( MapTableT, int streamFlag=0 );

	void		SetCaseSensitivity( int mode );


    private:

	void		Join( MapTable *m1, MapTableT dir1, 
			      MapTable *m2, MapTableT dir2,
			      MapJoiner *j, const ErrorId *reason );

	// For building the string table for MapStrings and the
	// MapTree for Match() and Translate().

	void		MakeTree( MapTableT );

	// count is length of entry chain.
	// entry is the chain of mappings.
	// trees is the pair of search trees for Match() and Translate()

	int		count;
	MapItem *	entry;
	MapTree *	trees;

	const ErrorId *	emptyReason;
	int		joinError;

	// For IsEmpty/HasOverlays/HasHavemaps/hasAndmaps

	int		hasMaps;
	int		hasOverlays;
	int		hasHavemaps;
	int		hasAndmaps;

	int		caseMode;

} ;
