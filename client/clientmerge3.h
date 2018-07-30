/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * ClientMerge3 - full 3-way merge
 * ClientMerge32 - present 2-way diff as 3-way merge
 */

class MD5;

class ClientMerge3 : public ClientMerge {

    public:
	    		ClientMerge3( ClientUser *ui,
				      FileSysType type,
				      FileSysType resType,
				      FileSysType theirType,
				      FileSysType baseType );
			~ClientMerge3();

	virtual int	IsAcceptable() const;

	virtual FileSys *GetBaseFile() const { return base; }
	virtual FileSys *GetYourFile() const { return yours; }
	virtual FileSys *GetTheirFile() const { return theirs; }
	virtual FileSys *GetResultFile() const { return result; }

	virtual int	GetYourChunks() const { return chunksYours; }
	virtual int	GetTheirChunks() const { return chunksTheirs; }
	virtual int	GetBothChunks() const { return chunksBoth; }
	virtual int	GetConflictChunks() const { return chunksConflict; }

	virtual void	Open( StrPtr *name, Error *e, CharSetCvt * = 0,
				int charset = 0 );
	virtual void	Write( StrPtr *buf, StrPtr *bits, Error *e );
	virtual void	Close( Error *e );
	virtual void	Select( MergeStatus stat, Error *e );
	virtual void	Chmod( const char *perms, Error *e );
	virtual void	SetTheirModTime( StrPtr *modTime );

	virtual MergeStatus 	Resolve( Error *e );
	virtual MergeStatus 	AutoResolve( MergeForce forceMerge );
	virtual MergeStatus 	DetectResolve() const;

	virtual const StrPtr *GetMergeDigest() const;
	virtual const StrPtr *GetYourDigest() const;
	virtual const StrPtr *GetTheirDigest() const;

	void		SetShowAll() { showAll = 1; }
	void		SetNames( StrPtr *b, StrPtr *t, StrPtr *y );
	void		SetDiffFlags( const StrPtr *f ) { flags.Set( *f ); }

    protected:

	enum Marker3 {
		MarkerOriginal,	// >>>> ORIGINAL
		MarkerTheirs,	// ==== THEIRS
		MarkerYours,	// ==== YOURS
		MarkerBoth,	// ==== BOTH
		MarkerEnd,	// <<<<
		MarkerLast
	} ;

	StrBuf		markertab[ MarkerLast ];

	FileSys *	yours;
	FileSys *	base;
	FileSys *	theirs;
	FileSys *	result;

	MD5 *		yoursMD5;
	MD5 *		theirsMD5;
	MD5 *		resultMD5;

	StrBuf		yoursDigest;
	StrBuf		theirsDigest;
	StrBuf		resultDigest;

	int		chunksYours;
	int		chunksTheirs;
	int		chunksConflict;
	int		chunksBoth;

	int		oldBits;
	int		markersInFile;
	int		showAll;
	int		needNl;
	StrBuf		flags; // for diff

	int		CheckForMarkers( FileSys *f, Error *e ) const;

	CharSetCvt	*theirs_cvt;
	CharSetCvt	*result_cvt;
} ;

class ClientMerge32 : public ClientMerge3 {

    public:
	    		ClientMerge32( ClientUser *ui,
				       FileSysType type,
				       FileSysType resType,
				       FileSysType theirType,
				       FileSysType baseType ) :
				ClientMerge3
				    ( ui, type, resType, theirType, baseType )
				{}

	MergeStatus 	AutoResolve( MergeForce forceMerge );

} ;

