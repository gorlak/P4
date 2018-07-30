/*
 * Copyright 2001 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

class TransDictQues : public StrBufDict {
	StrDict *other;
	CharSetCvt *fromOther;
public:
	TransDictQues( StrDict *o, CharSetCvt *f )
	    : other(o), fromOther(f) {}
	~TransDictQues();
private:
	StrPtr *VGetVar( const StrPtr &var );
	int	VGetVarX( int, StrRef &, StrRef & );
};

class TransDict : public StrBufDict {
	StrDict *other;
	CharSetCvt *fromOther, *toOther;
public:
	TransDict(StrDict *o, CharSetCvt *f, Error *lastError = 0);
	~TransDict();
	TransDictQues *CreateErrorOutputDict()
	    { return new TransDictQues( other, fromOther ); }
	CharSetCvt *FromCvt() { return fromOther; }
	CharSetCvt *ToCvt() { return toOther; }

private:
	StrPtr *VGetVar( const StrPtr &var );
	void	VSetVar( const StrPtr &var, const StrPtr &val );
	int	VGetVarX( int, StrRef &, StrRef & );
	void	VSetError( const StrPtr &, Error * );
	void	SetTransErr( CharSetCvt *cvt, const StrPtr &var );
	void	ResetTransErr(CharSetCvt *cvt);

	int transerr;
	Error *lastError;
	StrBuf notransbuf;
};
