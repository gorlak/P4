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
# include <error.h>
# include <i18napi.h>
# include <charset.h>
# include <charcvt.h>
# include <transdict.h>
# include <options.h>
# include <handler.h>
# include <rpc.h>
# include <ident.h>
# include <enviro.h>

# include <filesys.h>

# include <msgclient.h>
# include <p4tags.h>

# include "clientuser.h"
# include "clientservice.h"
# include "clientmerge.h"
# include "client.h"
# include "regexp.h"

void
Client::SetTrans( int output,
		  int content,
		  int fnames,
		  int dialog )
{
	CharSetCvt *converter = NULL;

	// SetTrans called, don't do server mode discovery
	unknownUnicode = 0;

	if( dialog == -2 )
	    dialog = output;
	if( content == -2 )
	    content = output;
	if( fnames == -2 )
	    fnames = content;

	// if we were already in unicode mode, take that down
	if( is_unicode )
	    CleanupTrans();

	// if all args are 0, disable translation
	if( !( output | content | fnames | dialog ) )
	{
	    content_charset = 0;
	    GlobalCharSet::Set( 0 );
	    return;
	}

	// we are in unicode mode now...
	is_unicode = 1;

	enviro->SetCharSet( output );
	content_charset = content;
	output_charset = output;
	GlobalCharSet::Set( fnames );
	// our concept of current directory could change at this point
	if( ownCwd )
	    cwd = "";
	enviro->Config( GetCwd() );

	if( output != 0 )
	{
	    converter = CharSetCvt::FindCvt( CharSetCvt::UTF_8,
	                                     (CharSetCvt::CharSet)output );
	    if( converter )
	    {
	        // TransDict will delete the converter
	        translated = new TransDict( this, converter, &transErr );
	        if( fnames == output )
	            transfname = translated;
	    }
	}
	if( fnames != 0 && fnames != output )
	{
	    converter = CharSetCvt::FindCvt( CharSetCvt::UTF_8,
	                                     (CharSetCvt::CharSet)fnames );
	    if( converter )
	    {
	        // TransDict will delete the converter
	        transfname = new TransDict( this, converter, &transErr );
 	    }
	}
	if( dialog != 0 )
	{
	    fromTransDialog = CharSetCvt::FindCvt( CharSetCvt::UTF_8,
	                                     (CharSetCvt::CharSet)dialog );
	    if( fromTransDialog )
	        toTransDialog = fromTransDialog->ReverseCvt();
	}
}

void
Client::CleanupTrans()
{
	if( transfname != this && transfname != translated )
	    delete transfname;
	if( translated != this )
	    delete translated;

	translated = this;
	transfname = this;

	delete fromTransDialog;
	delete toTransDialog;
	fromTransDialog = toTransDialog = NULL;

	is_unicode = 0;
	content_charset = 0;
	output_charset = 0;
	enviro->SetCharSet( 0 );
}

int
Client::ContentCharset()
{
	// Content charset is overridden by server-provided charset if present

	StrPtr *charset = GetVar( P4Tag::v_charset );

	return charset ? charset->Atoi() : content_charset;
}

int
Client::GuessCharset()
{
	return CharSetApi::Discover( enviro );
}
