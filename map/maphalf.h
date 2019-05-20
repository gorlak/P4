/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * maphalf.h - half a mapping, i.e. a pattern
 *
 * Public classes:
 *
 *	MapHalf - a half mapping, i.e. a StrBuf holding a pattern
 *	MapParams - slots for wildcard parameters
 *
 * Public methods:
 *
 *	MapHalf::operator =( char *newHalf )
 *		Create a new pattern.
 *
 *	MapHalf::Compare( const MapHalf &item )
 *		Just strcmp the pattern with the handed in one.
 *
 *	MapHalf::GetCommonLen( MapHalf *prev )
 *		Returns the length of initial substring of non-wildcard 
 *		chararacters common to both MapHalf patterns.
 *
 *	MapHalf::GetFixedLen()
 *		Returns the length of the initial substring of non-wildcard
 *		characters in the MapHalf pattern.
 *
 *	MapHalf::Expand( StrPtr &in, StrBuf *output, MapParams *params )
 *		Expand the pattern into the output buffer, using the 
 *		wildcard values in params. 
 *
 *	MapHalf::IsWild()
 *		Return 1 if the MapHalf contains wildcards.
 *
 *	MapHalf::Join( MapHalf *map2, Joiner &j )
 *		Join the pattern against against the handed in pattern map2.
 *		Stores pointers to the strings matched by wildcards for each
 *		patterm in params and params2, and uses paramBuf as a temp
 *		buffer (of uncontrolled size XXX) for those strings.
 *		Because Join() can produce more than one result for a
 *		given pair of patterns, it calls j.Insert() for each match.
 *
 *	MapHalf::Match( char *input, MapParams *params )
 *		Match the pattern against the input, putting pointers to
 *		the strings matched by wildcards into params.  Returns 1
 *		if the pattern matches, 0 else.  Uses Match1 and Match2.
 *
 *	MapHalf::Match1( char *input, int &coff )
 *		Compares the non-wildcard initial portion of the MapHalf
 *		to the input, return <0, 0, or >0.  coff is the starting 
 *		offset (first character to match) and then the ending 
 *		offset (first character mismatched), which can be used 
 *		to avoid re-comparing portions that are common in a tree
 *		of MapHalf's.
 *
 *	MapHalf::Match2( char *input, MapParams *params )
 *		Match the wildcard portion of the MapHalf pattern against 
 *		the input, putting pointers to the strings matched by 
 *		wildcards into params.  Returns 1 if the pattern matches, 
 *		0 else.  Assumes Match1 has already been called.
 *
 *	MapHalf::MatchHead( const MapHalf &other )
 *	MapHalf::MatchTail( const MapHalf &other )
 *		Compares the non-wildcard initial substring or tailing 
 *		substring of the two MapHalfs.  MatchHead() compares
 *		for sorting; MatchTail() just for equality.
 *
 *	MapHalf::Validate( MapHalf *item, Error *e )
 *		Checks if the pattern and the handed in pattern have the
 *		same wildcards.  If item is null, just checks that the
 *		single pattern is valid.
 */

/*
 * Note that in mapchar.h we only allow 3 ...'s, but alloc room for 10.
 * That's because Joining or disambiguating a map can increase the number
 * of ...'s.  10 isn't a solid number, either, alas.  It really should
 * check for overflow. XXX
 */

const int PARAM_VECTOR_LENGTH = 30; // %0 - %9, 10 *'s, and 10 ...'s
const int PARAM_MAX_BACKTRACK = 10;
const int PARAM_MAX_WILDS = 10;

class MapChar;
class MapHalf;
struct MapString;

struct MapParam {
	int	start;		// offsets into Joiner::StrBuf::Text()
	int	end;
} ;

struct MapParams {
	MapParam vector[ PARAM_VECTOR_LENGTH ];	
} ;

class Joiner : public StrBuf {

    public:

	virtual void	Insert() = 0;

        int             badJoin;
	MapParams	params;		
	MapParams	params2;

} ;

class MapHalf : public StrBuf {

    public:

			MapHalf() { mapChar = 0; caseMode = -1; }
			MapHalf( const StrPtr &n )
			{ mapChar = 0; caseMode = -1; *this = n; }
			~MapHalf();

	void		operator =( const StrPtr &newHalf );

	int		Compare( const MapHalf &item ) const;
	int		GetCommonLen( MapHalf *prev );
	int		GetFixedLen() { return fixedLen; }
	void		Expand( const StrPtr &from, StrBuf &to, MapParams &p );
	int		HasSubDirs( int matchLen );
	int		HasEmbWild( StrPtr &h, int ignore );
	int		HasEndSlashEllipses();
	int		HasPosWild( StrPtr &h );
	int		IsWild() { return isWild; }
	int		TooWild( Error *e );
	int		WildcardCount() { return nWilds; }
	void		Join(  MapHalf *map2, Joiner &joiner );

	int 		Match1( const StrPtr &from, int &coff );
	int		Match2( const StrPtr &input, MapParams &params );

	int		Match( const StrPtr &i, MapParams &p )
			{ int o = 0; return !Match1( i, o ) && Match2( i, p ); }

	int		Match( const MapHalf &from );

	int 		MatchHead( const MapHalf &other );
	int 		MatchTail( const MapHalf &other );

	void		Validate( MapHalf *item, Error *e );

	void		SetCaseMode( int caseMode );

	void		SanitizeStars( Error *e );

    private:

	void		FindParams( char *params, Error *e );

	MapChar		*mapChar;	// compiled version 
	MapChar		*mapTail;	// non-wildcard tail start
	MapChar		*mapEnd;	// non-wildcard tail end
	int		fixedLen;	// How much until wildcard
	int		isWild;		// has a wildcard at all?
	int		nWilds;		// number of wildcards
	int		caseMode;	// case sensitivity mode
} ;

