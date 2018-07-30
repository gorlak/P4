/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include <strbuf.h>
# include <error.h>
# include <errornum.h>
# include <msgos.h>
# include <debug.h>

# include "handler.h"

# define DEBUG_SET	( p4debug.GetLevel( DT_HANDLE ) >= 1 )
# define DEBUG_GET	( p4debug.GetLevel( DT_HANDLE ) >= 1 )
# define DEBUG_RM	( p4debug.GetLevel( DT_HANDLE ) >= 1 )
# define DEBUG_ERROR	( p4debug.GetLevel( DT_HANDLE ) >= 1 )

LastChance::~LastChance()
{
	if( handler )
	{
	    if( DEBUG_RM )
		p4debug.printf("finish handle %s\n", handler->name.Text() );

	    handler->lastChance = 0;
	    handler->anyErrors |= isError;
	}
}

Handlers::Handlers()
{
	numHandlers = 0;
}

Handlers::~Handlers()
{
	for( int i = 0; i < numHandlers; i++ )
	    delete table[ i ].lastChance;
}
 
void
Handlers::Install( const StrPtr *name, LastChance *lastChance, Error *e )
{
	int i;

	if( DEBUG_SET )
	    p4debug.printf("set handle %s\n", name->Text() );

	for( i = 0; i < numHandlers; i++ )
	{
	    if( table[ i ].name == *name )
		break;
	    if( !table[ i ].lastChance && !table[ i ].anyErrors )
		break;
	}

	if( i == numHandlers )
	{
	    if( i == maxHandlers )
	    {
		e->Set( MsgOs::TooMany ) << *name;
		return;
	    }
	    ++numHandlers;

	    // anyErrors gets cleared on Install or after AnErrors() check.

	    table[ i ].anyErrors = 0;
	}

	table[ i ].name = *name;
	table[ i ].lastChance = lastChance;
	lastChance->Install( &table[ i ] );
}

LastChance *
Handlers::Get( const StrPtr *name, Error *e ) 
{
	Handler *h;

	if( DEBUG_GET )
	    p4debug.printf("get handle %s\n", name->Text() );

	if( !( h = Find( name, e ) ) )
	    return 0;

	if( h->lastChance )
	    return h->lastChance;

	if( e )
	    e->Set( MsgOs::Deleted ) << *name;

	h->anyErrors++;

	return 0;
}

int
Handlers::AnyErrors( const StrPtr *name )
{
	Handler *h;
	int n = 0;

	if( h = Find( name ) )
	{
	    n = h->anyErrors;
	    h->anyErrors = 0;
	}

	if( DEBUG_ERROR )
	    p4debug.printf("anyError handle %s = %d\n", name->Text(), n );

	return n;
}

void
Handlers::SetError( const StrPtr *name, Error *e )
{
	Handler *h = Find( name );

	if( h ) 
	{
	    h->anyErrors = 1;
	    return;
	}

	LastChance last;

	Install( name, &last, e );

	if( e->Test() )
	    return;

	if( h = Find( name ) )
	{
	    h->anyErrors = 1;
	    return;
	}
	
	e->Set( MsgOs::NoSuch ) << *name;
}

Handler *
Handlers::Find( const StrPtr *name, Error *e ) 
{
	for( int i = 0; i < numHandlers; i++ )
	    if( !table[ i ].name.XCompare( *name ) )
		return &table[i];

	if( e )
	    e->Set( MsgOs::NoSuch ) << *name;

	return 0;
}
