/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include <debug.h>
# include <strbuf.h>
# include <strdict.h>
# include <strtable.h>
# include <strops.h>
# include <error.h>
# include <errornum.h>
# include <msgsupp.h>

# include "i18napi.h"
# include "charcvt.h"
# include "transdict.h"

TransDict::TransDict(StrDict *o, CharSetCvt *f, Error *e)
    : other(o), fromOther(f), lastError(e)
{
	toOther = f->ReverseCvt();
}

TransDict::~TransDict()
{
	delete fromOther;
	delete toOther;
}

void
TransDict::VSetVar( const StrPtr &var, const StrPtr &val )
{
	int translen;
	const char *transbuf;

	ResetTransErr( toOther );
	transbuf = toOther->FastCvt(val.Text(),	val.Length(), &translen);
	if (transbuf)
	{
	    other->SetVar(var.Text(), StrRef(transbuf, translen));
	    // careful about the order here...
	    StrBufDict::VSetVar(var, val);
	}
	else
	{
	    // what do we do if the translation fails????
	    notransbuf = val;
	}
	SetTransErr( toOther, var );
}

StrPtr *
TransDict::VGetVar( const StrPtr &var )
{
	ResetTransErr( toOther );
	ResetTransErr( fromOther );

	StrPtr *ret = StrBufDict::VGetVar( var );
	if (!ret)
	{
	    const char *cp = toOther->FastCvt( var.Text(), var.Length() );

	    if( !cp )
	    {
		notransbuf = var;
		SetTransErr( toOther, var );
		return NULL;
	    }

	    ret = other->GetVar( cp );

	    if (ret)
	    {
		int translen;
		const char *transbuf = fromOther->FastCvt( ret->Text(),
							   ret->Length(),
							   &translen );
		// XXX if the translation failed we should probably
		// have an error indication of translation failure
		if( transbuf )
		{
		    // XXX Set the translated value
		    StrBufDict::VSetVar( var,
					StrRef( transbuf, translen ) );
		    ret = StrBufDict::VGetVar( var );
		}
		else
		{
		    notransbuf = *ret;
		    ret = NULL;
		}
	    }
	}
	SetTransErr( fromOther, var );
	return ret;
}

int
TransDict::VGetVarX( int x, StrRef &var, StrRef &val )
{
	int ret;
	ResetTransErr( fromOther );

	ret = other->GetVar( x, var, val );
	if( ret )
	{
	    int translen;
	    const char *cp = fromOther->FastCvt( var.Text(),
					       var.Length(),
					       &translen );

	    StrBuf holdvar;

	    if( cp )
		holdvar = StrRef( cp, translen );
	    else {
		notransbuf = var;
		holdvar = StrVarName( StrRef( "variable" ), x );
		SetTransErr( fromOther, holdvar );
	    }
		
	    const char *transbuf = fromOther->FastCvt( val.Text(),
						       val.Length(),
						       &translen );
	    // XXX if the translation failed we should probably
	    // have an error indication of translation failure
	    if( transbuf )
	    {
		// XXX Set the translated value
		StrBufDict::VSetVar( holdvar, StrRef( transbuf, translen ) );
	    }
	    else
	    {
		StrBufDict::VSetVar( holdvar, StrRef( "untranslatable" ) );
		notransbuf = val;
		SetTransErr( fromOther, holdvar );
	    }

	    // XXX this is needed to get var and val pointing at
	    // stable memory
	    ret = StrBufDict::VGetVarX( GetCount() - 1, var, val );
	}
	return ret;
}

void
TransDict::VSetError( const StrPtr &var, Error *e )
{
	if( transerr )
	{
	    StrBuf hexBuf;

	    StrOps::OtoX( notransbuf, hexBuf );
	    e->Set( MsgSupp::NoTransVar ) << var << hexBuf;
	}
	else
	    StrBufDict::VSetError( var, e );
}

void
TransDict::ResetTransErr( CharSetCvt *cvt )
{
	cvt->ResetErr();

	if( lastError )
	    lastError->Clear();

}

void
TransDict::SetTransErr( CharSetCvt *cvt, const StrPtr &var )
{
	transerr = cvt->LastErr();

	if( !lastError )
	    return;

	lastError->Clear();
	if( transerr )
	    VSetError( var, lastError );
}

StrPtr *
TransDictQues::VGetVar( const StrPtr &var )
{
	StrPtr *ret;
	StrPtr *val = other->GetVar( var );
	if ( !val )
	    return NULL;
	fromOther->ResetErr();
	int translen;
	const char *transbuf = fromOther->FastCvtQues( val->Text(),
						       val->Length(),
						       &translen );
	if( transbuf )
	{
	    // XXX Set the translated value
	    StrBufDict::VSetVar( var, StrRef( transbuf, translen ) );
	    ret = StrBufDict::VGetVar( var );
	    return ret;
	}
	return NULL;
}


int
TransDictQues::VGetVarX( int x, StrRef &var, StrRef &val )
{
	int ret;
	ret = other->GetVar( x, var, val );
	if( !ret )
	    return 0;
	fromOther->ResetErr();
	int translen;
	const char *transbuf = fromOther->FastCvt( val.Text(),
						    val.Length(),
						    &translen );
	if( transbuf )
	{
	    // XXX Set the translated value
	    StrBufDict::VSetVar( var, StrRef( transbuf, translen ) );
	    ret = StrBufDict::VGetVarX( GetCount() - 1, var, val );
	    return ret;
	}
	return 0;
}

TransDictQues::~TransDictQues()
{
}
