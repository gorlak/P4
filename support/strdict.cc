/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * strdict.cc - support for StrDict
 */

# include <stdhdrs.h>
# include <error.h>
# include <errornum.h>
# include <msgsupp.h>

# include "strbuf.h"
# include "strdict.h"

StrDict::~StrDict()
{
}

void
StrDict::CopyVars( StrDict &dict )
{
	StrRef var, val;

	Clear();

	for( int i = 0; dict.GetVar( i, var, val ); i++ )
	    SetVar( var, val );
}

void
StrDict::SetVar( const StrPtr &var, int x, const StrPtr &val )
{
	SetVar( StrVarName( var, x ), val );
}

void
StrDict::SetVar( const char *var, int x, const StrPtr &val )
{
	SetVar( StrVarName( StrRef( var ), x ), val );
}

void
StrDict::SetVar( const char *var, int x, int y, const StrPtr &val )
{
	SetVar( StrVarName( StrRef( var ), x, y ), val );
}

void		
StrDict::SetVar( const char *var )
{
	VSetVar( StrRef( (char*)var ), StrRef::Null() );
}

void		
StrDict::SetVar( const char *var, int value )
{
	VSetVar( StrRef( (char*)var ), StrNum( value ) );
}

void		
StrDict::SetVar( const char *var, const char *value )
{
	if( value )
	    VSetVar( StrRef( (char*)var ), StrRef( (char*)value ) );
}

void		
StrDict::ReplaceVar( const char *var, const char *value )
{
	if( value )
	{
	    StrPtr *temp = this->GetVar( var );
	    
	    if( temp )
	    {
		RemoveVar( var );
	    }
	    
	    VSetVar( StrRef( (char*)var ), StrRef( (char*)value ) );
	}
}

void		
StrDict::ReplaceVar( const StrPtr &var, const StrPtr &value )
{
	StrPtr *temp = this->GetVar( var );
	    
	if( temp )
	    RemoveVar( var );
	    
	VSetVar( var, value );
}

void		
StrDict::RemoveVar( const char *var )
{
	VRemoveVar( StrRef( (char*)var ) );
}

void		
StrDict::SetVar( const char *var, const StrPtr *value )
{
	if( value )
	    VSetVar( StrRef( (char*)var ), *value );
}

void		
StrDict::SetVar( const char *var, const StrPtr &value )
{
	VSetVar( StrRef( (char*)var ), value );
}

void
StrDict::SetArgv( int argc, char *const *argv )
{
	for( int i = 0; i < argc; i++ )
	    VSetVar( StrRef::Null(), StrRef( argv[i] ) );
}

void
StrDict::SetVarV( const char *arg )
{
	const char *p;

	if( p = strchr( arg, '=' ) )
	{
	    StrBuf var = StrRef( (char *) arg, p - arg );
	    var.Terminate();
	    SetVar( var, StrRef( (char *)p + 1 ) );
	}
	else
	{
	    SetVar( StrRef( (char *)arg ), StrRef::Null() );
	}
}

StrPtr *
StrDict::GetVar( const StrPtr &var, int x )
{
	return VGetVar( StrVarName( var, x ) );
}

StrPtr *
StrDict::GetVar( const StrPtr &var, int x, int y )
{
	return VGetVar( StrVarName( var, x, y ) );
}

StrPtr *
StrDict::GetVar( const char *var )
{
	return VGetVar( StrRef( (char *)var ) );
}

StrPtr *
StrDict::GetVar( const char *var, Error *e )
{
	StrRef varref((char *)var);
	StrPtr *p = VGetVar( varref );

	if( !p )
	    VSetError( varref, e );

	return p;
}

int
StrDict::GetVarCCompare( const char *var, StrBuf &val )
{
	return GetVarCCompare( StrRef( (char *) var ), val );
}

int
StrDict::GetVarCCompare( const StrPtr &var, StrBuf &val )
{
	int i = 0;
	StrRef k, v;

	val.Clear();

	while( VGetVarX( i++, k, v ) )
	{
	    if( !k.CCompare( var ) )
	    {
		val.Set( v );
		return 1;
	    }
	}
	
	return 0;
}

int 
StrDict::Save( FILE * out )
{
	StrRef var, val;
	unsigned int i = 0;
	
	while ( GetVar( i++, var, val ) )
	    fprintf( out, "%s=%s\n", var.Text(), val.Text() );
	
	return 1;
}

int 
StrDict::Load( FILE * in )
{
	//
	// Read file in, line by line
	// Note that a line cannot be any larger than 4k.
	// Ignore lines beginning with #
	//

	char val[4096], *e;
	
	while( fscanf( in, "%4096[^\n]\n", val ) == 1 )
	    if( *val != '#' && ( e = strchr( val, '=' ) ) )
		SetVar( StrRef( val, e - val ), StrRef( e + 1 ) );
	
	return 1;
}

void
StrDict::VSetVar( const StrPtr &var, const StrPtr &val )
{
	// null default implementation
}

int
StrDict::VGetVarX( int x, StrRef &var, StrRef &val )
{
	// null default implementation
	return 0;
}

void
StrDict::VRemoveVar( const StrPtr &var )
{
	// null default implementation
}

void
StrDict::VSetError( const StrPtr &var, Error *e )
{
	e->Set( MsgSupp::NoParm ) << var;
}

void
StrDict::VClear()
{
	// null default implementation
}

StrVarName::StrVarName( const StrPtr &name, int x, int y )
{
	name.StrCpy( varName );
	StrNum( x ).StrCat( varName );
	strcat( varName, "," );
	StrNum( y ).StrCat( varName );
	Set( varName );
}

StrVarName::StrVarName( const StrPtr &name, int x )
{
	name.StrCpy( varName );
	StrNum( x ).StrCat( varName );
	Set( varName );
}

