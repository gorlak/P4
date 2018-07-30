/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * strtable.cc - support for StrBuf, StrPtr
 */

# include <stdhdrs.h>
# include <vararray.h>

# include "strbuf.h"
# include "strdict.h"
# include "strtable.h"


struct StrPtrEntry {
	StrPtr	var;
	StrPtr	val;
} ;

struct StrBufEntry {
	StrBuf	var;
	StrBuf	val;

# ifdef OS_UNIXWARE

    // unixwhore squalks about ambiguous default assignment op
    // so we declare one explicitly.

	void		operator =( const StrBufEntry &s )
			{ var = s.var; val = s.val; }
# endif

} ;

StrPtrDict::StrPtrDict()
{
	elems = new VarArray;
	tabSize = 0;
	tabLength = 0;
}

StrPtrDict::~StrPtrDict()
{
	for( int i = 0; i < tabSize; i++ )
	{
	    StrPtrEntry *s = (StrPtrEntry *)elems->Get(i);
	    delete s;
	}

	delete elems;
}

StrPtr *
StrPtrDict::VGetVar( const StrPtr &var )
{
	for( int i = 0; i < tabLength; i++ )
	{
	    StrPtrEntry *s = (StrPtrEntry *)elems->Get(i);

	    if( s->var == var ) 
		return &s->val;
	}

	return 0;
}

int
StrPtrDict::VGetVarX( int x, StrRef &var, StrRef &val )
{
	if( x >= tabLength )
	    return 0;

	StrPtrEntry *s = (StrPtrEntry *)elems->Get(x);

	var = s->var;
	val = s->val;

	return 1;
}

void
StrPtrDict::VSetVar( const StrPtr &var, const StrPtr &val )
{
	// Realloc with spare room

	if( tabLength == tabSize )
	{
	    elems->Put( new StrPtrEntry );
	    ++tabSize;
	}

	StrPtrEntry *s = (StrPtrEntry *)elems->Get( tabLength++ );

	s->var = var;
	s->val = val;
}

void
StrPtrDict::VRemoveVar( const StrPtr &var )
{
	for( int i = 0; i < tabLength; i++ )
	{
	    StrPtrEntry *s = (StrPtrEntry *)elems->Get(i);

	    if( s->var == var ) 
	    {
		elems->Exchange(i, --tabLength);

		return;
	    }
	}
}

/* StrBufDict */

StrBufDict::StrBufDict()
{
	elems = new VarArray;
	tabSize = 0;
	tabLength = 0;
}

StrBufDict::StrBufDict( StrDict &dict )
{
	elems = new VarArray;
	tabSize = 0;
	tabLength = 0;
	CopyVars( dict );
}

StrBufDict &
StrBufDict::operator =( StrDict & dict )
{
	CopyVars( dict );
	return *this;
}

StrBufDict::~StrBufDict()
{
	for( int i = 0; i < tabSize; i++ )
	{
	    StrBufEntry *s = (StrBufEntry *)elems->Get(i);
	    delete s;
	}

	delete elems;
}

StrPtr *
StrBufDict::VGetVar( const StrPtr &var )
{
	for( int i = 0; i < tabLength; i++ )
	{
	    StrBufEntry *s = (StrBufEntry *)elems->Get(i);

	    if( s->var == var ) 
		return &s->val;
	}

	return 0;
}

StrPtr *
StrBufDict::GetVarN( const StrPtr &var )
{
	for( int i = 0; i < tabLength; i++ )
	{
	    StrBufEntry *s = (StrBufEntry *)elems->Get(i);

	    if( var.XCompareN( s->var ) == 0 )
		return &s->val;
	}

	return 0;
}

/*
 StrBufDict::KeepOne() -- use a StrBufDict as a string table.
    Store one copy of var and return a pointer to it.
*/

StrBuf *
StrBufDict::KeepOne( const StrPtr &var )
{
	for( int i = 0 ; i < tabLength ; i++ )
	{
	    StrBufEntry *s = (StrBufEntry *)elems->Get(i);

	    if( s->var == var )
		return &s->var;
	}

	// Realloc with spare room

	if( tabLength == tabSize )
	{
	    elems->Put( new StrBufEntry );
	    ++tabSize;
	}

	StrBufEntry *s = (StrBufEntry *)elems->Get( tabLength++ );

	s->var = var;
	s->val.Clear();

	return &s->var;
}

int
StrBufDict::VGetVarX( int x, StrRef &var, StrRef &val )
{
	if( x >= tabLength )
	    return 0;

	StrBufEntry *s = (StrBufEntry *)elems->Get(x);

	var = s->var;
	val = s->val;

	return 1;
}

void
StrBufDict::VSetVar( const StrPtr &var, const StrPtr &val )
{
	// Realloc with spare room

	if( tabLength == tabSize )
	{
	    elems->Put( new StrBufEntry );
	    ++tabSize;
	}

	StrBufEntry *s = (StrBufEntry *)elems->Get( tabLength++ );

	s->var = var;
	s->val = val;
}

void
StrBufDict::VRemoveVar( const StrPtr &var )
{
	for( int i = 0; i < tabLength; i++ )
	{
	    StrBufEntry *s = (StrBufEntry *)elems->Get(i);

	    if( s->var == var ) 
	    {
		elems->Exchange(i, --tabLength);

		return;
	    }
	}
}

/* BufferDict */

BufferDict &
BufferDict::operator =( const BufferDict &s ) 
{
	buf = s.buf;
	count = s.count;

	for( int i = 0; i < count; i++ )
	    vars[i] = s.vars[i];

	return *this;
}

StrPtr *
BufferDict::VGetVar( const StrPtr &v )
{
	for( int i = 0; i < count; i++ )
	{
	    const Var *vr = &vars[i];

	    if( v.Length() != vr->varLen || 
		memcmp( buf.Text() + vr->varOff, v.Text(), v.Length() ) )
		    continue;

	    varRef.Set( buf.Text() + vr->valOff, vr->valLen );
	    return &varRef;
	}

	return 0;
}

int
BufferDict::VGetVarX( int i, StrRef &var, StrRef &val )
{
	if( i < 0 || i >= count )
	    return 0;

	const Var *vr = &vars[i];
	var.Set( buf.Text() + vr->varOff, vr->varLen );
	val.Set( buf.Text() + vr->valOff, vr->valLen );

	return 1;
}

void
BufferDict::VSetVar( const StrPtr &var, const StrPtr &val )
{
	/* var and val get safely copied into buf. */
	/* var gets terminated 'cause people do strcmps */
	/* val gets terminated just for display and safety */

	if( count == BufferDictMax )
	    --count;

	Var *ev = vars + count++;

	ev->varOff = buf.Length();
	ev->varLen = var.Length();
	buf.Extend( var.Text(), var.Length() );
	buf.Extend(0);

	ev->valOff = buf.Length();
	ev->valLen = val.Length();
	buf.Extend( val.Text(), val.Length() );
	buf.Extend(0);
}

void
BufferDict::VRemoveVar( const StrPtr &v )
{
	if ( !count ) 
	    return;

	/* XXX - this only works to remove the last var */

	Var *vr = vars + --count;

	if( v.Length() != vr->varLen || 
	    memcmp( buf.Text() + vr->varOff, v.Text(), v.Length() ) )
		++count;
}
