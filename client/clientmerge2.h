/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * ClientMerge2 - present user with two (binary) files
 */

class MD5;

class ClientMerge2 : public ClientMerge {

    public:
			ClientMerge2( ClientUser *ui,
				      FileSysType type,
				      FileSysType theirType );
			~ClientMerge2();

	virtual int	IsAcceptable() const { return 1; }

	virtual FileSys *GetBaseFile() const { return 0; }
	virtual FileSys *GetYourFile() const { return yours; }
	virtual FileSys *GetTheirFile() const { return theirs; }
	virtual FileSys *GetResultFile() const { return 0; }

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
	virtual void	CopyDigest( StrPtr *digest, Error *e );
	virtual void	SetTheirModTime( StrPtr *modTime );

	virtual MergeStatus Resolve( Error *e );
	virtual MergeStatus AutoResolve( MergeForce forceMerge );
	virtual MergeStatus DetectResolve() const;

	virtual const StrPtr *GetYourDigest() const;
	virtual const StrPtr *GetTheirDigest() const;

    protected:

	FileSys		*yours;
	FileSys		*theirs;

	MD5 *           theirsMD5;

	StrBuf          baseDigest;
	StrBuf          yoursDigest;
	StrBuf          theirsDigest;

	int             chunksYours;
	int             chunksTheirs;
	int             chunksConflict;
	int             chunksBoth;

	int		hasDigests;         // 2003.1 sends 'base' digest
} ;
