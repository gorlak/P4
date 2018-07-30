#include "mapapi.h"

#include <stdhdrs.h>
#include <strbuf.h>
#include <vararray.h>
#include <strarray.h>
#include <error.h>
#include <maptable.h>
#include <maphalf.h>
#include <mapitem.h>

MapApi::MapApi(void)
{
	Init();
	table = new MapTable();
}

MapApi::~MapApi(void)
{
	delete table;
}

MapApi::MapApi( MapTable* t )
{
	Init();
	table = t;
}

int MapApi::Count()
{
	//Rather than exposing Disambiguate() to the user, enforce disambiguity
	//on every read.
	Disambiguate();
	return table->Count();
}

const StrPtr* MapApi::GetLeft( int i )
{
	//Invert the index so that this interface matches the client-visible form
	//rather than the internal "bottom-up" ordering.  This also disambiguates.
	i = Count() - i - 1;

	return table->Get( i, LHS );
}

const StrPtr* MapApi::GetRight( int i )
{
	i = Count() - i - 1;

	return table->Get( i, RHS );
}

MapType MapApi::GetType( int i )
{
	i = Count() - i - 1;
	
	switch( table->GetFlag( table->Get( i ) ) )
	{
	case MfMap:
		return MapInclude;
	case MfUnmap:
		return MapExclude;
	case MfRemap:
		return MapOverlay;
	case MfAndmap:
		return MapOneToMany;
	}

	// We should never get to this point, since we should never be
	// inserting any haveMap entries into our private table!
	return MapInclude;
}

void MapApi::Clear()
{
	table->Clear();
	ambiguous = 0;
}

void MapApi::Insert( const StrPtr& l, MapType t )
{
	Insert( l, l, t );
}

void MapApi::Insert( const StrPtr& l, const StrPtr& r, MapType t )
{
	MapFlag f;
	switch ( t )
	{
	case MapInclude:
	default:
		f = MfMap;
		break;
	case MapExclude:
		f = MfUnmap;
		break;
	case MapOverlay:
		f = MfRemap;
		break;
	case MapOneToMany:
		f = MfAndmap;
		break;
	}

	table->Insert( l, r, f );

	ambiguous = 1;
}

void MapApi::SetCaseSensitivity( MapCase mode )
{
	table->SetCaseSensitivity( mode );
}

int MapApi::Translate( const StrPtr& from, StrBuf& to, MapDir d )
{
	MapTableT dir = ( d == MapRightLeft ? RHS : LHS );

	Disambiguate();

	if ( table->Translate( dir, from, to ) )
		return 1;
	else
		return 0;
}

int MapApi::Translate( const StrPtr& from, StrArray& to, MapDir d )
{
	MapTableT dir = ( d == MapRightLeft ? RHS : LHS );
	to.Clear();

	Disambiguate();
	MapItemArray *mia = table->Explode( dir, from );

	if( !mia || !mia->Count() )
	{
	    if( mia )
	        delete mia;
	    return 0;
	}

	StrPtr *tmp;
	for( int i = 0; ( tmp = mia->GetTranslation( i ) ); i++ )
	    to.Put()->Set( tmp );

	delete mia;
	return 1;
}

MapApi* MapApi::Join( MapApi* m1, MapDir d1, MapApi* m2, MapDir d2 )
{
	MapTableT t1 = RHS;
	MapTableT t2 = LHS;
	if ( d1 == MapRightLeft ) t1 = LHS;
	if ( d2 == MapRightLeft ) t2 = RHS;
	
	m1->Disambiguate();
	m2->Disambiguate();

	return new MapApi( m1->table->Join2( t1, m2->table, t2 ) );
}

void MapApi::Init()
{
	ambiguous = 0;
}

void MapApi::Disambiguate()
{
	if ( !ambiguous ) return;

	table->Disambiguate();
	ambiguous = 0;
}
