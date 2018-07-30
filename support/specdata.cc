/*
 * Copyright 1995, 2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * specdata.cc -- SpecWords, SpecData, SpecDataTable
 */

# include <stdhdrs.h>
# include <charman.h>
# include <debug.h>

# include <strbuf.h>
# include <strdict.h>
# include <strtable.h>

# include <error.h>
# include <errorlog.h>

# include "spec.h"
# include <msgdb.h>

/*
 * SpecWords -- array of words in a spec value, allowing surrounding "'s
 */

int
SpecWords::Split()
{
	int wc = 0;
	char *buf = Text();

	while( wc < SpecWordsMax )
	{
	    // Skip blanks 

	    while( isAspace( buf ) ) buf++;
	    if( !*buf ) break;

	    // First letter of new word 

	    if( *buf == '"' ) 
	    {
		// quoted

		wv[ wc++ ] = ++buf;
		while( *buf && *buf != '"' ) buf++;
	    }
	    else
	    {
		// Non-quoted

		wv[ wc++ ] = buf;
		while( *buf && !isAspace( buf ) ) buf++;
	    }

	    if( !*buf ) break;

	    // First blank after word 

	    *buf++ = '\0';
	}

	wv[ wc ] = 0;
	return wc;
}

void
SpecWords::Join( int wc )
{
	// To handle single line comments, there are no values
	// returned in **words, just **cmts,  check for any null
	// values and return a null string.

	for( int i = 0; i < wc; i++ )
	{
	    if( !wv[i] )
	    {
	        *this << "";
	        return;
	    }
	}

	for( int i = 0; i < wc; i++ )
	{
	    if( i )
		*this << " ";
	    // quote if spaces or null
	    if( !*wv[i] || strchr( wv[i], ' ' ) || strchr( wv[i], '#' ) )
		*this << "\"" << wv[i] << "\"";
	    else
		*this << wv[i];
	}
}

/*
 * SpecData -- default Get()/Set() that do line splitting/joining
 */

StrPtr *
SpecData::GetLine( SpecElem *sd, int x, const char **cmt )
{
	if( !Get( sd, x, tVal.wv, cmt ) )
	    return 0;

	if( sd->IsWords() )
	{
	    tVal.Clear();

	    // join the maximum number of words.
	    if( sd->maxWords && tVal.wv[sd->maxWords-1] ) 
	        tVal.Join( sd->maxWords );
	    else 
	        tVal.Join( sd->nWords );
	}
	else
	{
	    tVal.Set( tVal.wv[0] );
	}

	return &tVal;
}

void
SpecData::SetLine( SpecElem *sd, int x, const StrPtr *val, Error *e )
{
	if( sd->IsWords() )
	{
	    tVal.Set( *val );
	    int wordCount = tVal.Split();
	    int wordMax = sd->maxWords ? sd->maxWords : sd->nWords;

	    if( wordCount < sd->nWords || wordCount > wordMax)
	    {
		e->Set( MsgDb::FieldWords ) << sd->tag;
		return;
	    } 
	}
	else
	{
	    tVal.wv[0] = val->Text();
	    // Need to terminate list.
	    tVal.wv[1] = 0;
	}

	Set( sd, x, tVal.wv, e );
}

void
SpecData::SetComment( SpecElem *sd, int x, const StrPtr *val, int nl, Error *e )
{
	tVal.wv[0] = val->Text();
	Comment( sd, x, tVal.wv, nl, e );
}

int
SpecData::Get( SpecElem *sd, int x, const char **wv, const char **cmt )
{
	return Get( sd, x, (char **)wv, (char **)cmt );
}

void	
SpecData::Set( SpecElem *sd, int x, const char **wv, Error *e )
{
	Set( sd, x, (char **)wv, e );
}

void
SpecData::Comment( SpecElem *sd, int x, const char **wv, int nl, Error *e )
{
	Comment( sd, x, (char **)wv, nl, e );
}

int
SpecData::Get( SpecElem *sd, int x, char **wv, char **cmt )
{
	AssertError.Set( E_FATAL, "SpecData::Get called!" );
	AssertLog.Abort( &AssertError );
	return 0;
}

void	
SpecData::Set( SpecElem *sd, int x, char **wv, Error *e )
{
	e->Set( E_FATAL, "SpecData::Set called!" );
}

void
SpecData::Comment( SpecElem *sd, int x, char **wv, int nl, Error *e )
{
	// No message,  comments will be ignored.
}

/*
 * SpecDataTable -- a SpecData interface to a StrDict 
 */

SpecDataTable::SpecDataTable( StrDict *dict )
{
	empty.Clear();
	if( dict )
	{
	    table = dict;
	    privateTable = 0;
	}
	else
	{
	    table = new StrBufDict;
	    privateTable = 1;
	}
}

SpecDataTable::~SpecDataTable()
{
	if( privateTable )
	    delete table;
}

StrPtr *
SpecDataTable::GetLine( SpecElem *sd, int x, const char **cmt )
{
	*cmt = 0;

	StrPtr *l, *c;
	StrBuf cTag = sd->tag;
	cTag << "Comment";

	if( sd->IsList() )
	    l = table->GetVar( sd->tag, x );
	else
	    l = table->GetVar( sd->tag );

	if( !l )
	    return 0;

	if( sd->IsList() )
	    c = table->GetVar( cTag, x );
	else
	    c = table->GetVar( cTag );

	if( c && c->Length() )
	{
	    // We store and send the comments with the hashes, but then append
	    // them during form formatting: got to strip the off now.

	    *cmt = c->Text();
	    while( **cmt == '#' )
	        *cmt = *cmt + 1;
	}

	return l;
}

void
SpecDataTable::SetLine( SpecElem *sd, int x, const StrPtr *val, Error *e )
{
	if( sd->IsList() )
	    table->SetVar( sd->tag, x, *val );
	else
	    table->SetVar( sd->tag, *val );
}

void
SpecDataTable::SetComment( SpecElem *sd, int x, const StrPtr *val, int nl, Error *e )
{
	StrBuf name;
	name << sd->tag << "Comment";

	if( sd->IsList() )
	{
	    table->SetVar( name, x - (nl ? 0 : 1), *val );
	    table->SetVar( sd->tag, x, empty );
	}
	else
	    table->SetVar( name, *val );
}
