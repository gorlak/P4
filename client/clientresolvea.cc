# include <stdhdrs.h>

# include <strbuf.h>
# include <error.h>
# include <handler.h>

# include <filesys.h>

# include <clientuser.h>

# include "clientresolvea.h"

ClientResolveA::ClientResolveA( ClientUser *u )
{
	ui = u;
}

MergeStatus 
ClientResolveA::AutoResolve( MergeForce force ) const
{
	switch( force )
	{
	case CMF_AUTO:
	    return suggest;

	case CMF_SAFE:
	    if ( suggest == CMS_THEIRS || suggest == CMS_YOURS )
	        return suggest;
	    else
	        return CMS_SKIP;

	case CMF_FORCE:
	    if ( suggest == CMS_SKIP )
	        return CMS_MERGED;
	    else
	        return suggest;
	}

	return CMS_SKIP;
}

MergeStatus
ClientResolveA::Resolve( int preview, Error *e )
{
	Error err;
	StrBuf buf;
	StrBuf autoSuggest;

	StrBuf a, s, h, at, ay, am;

	autoO.Fmt( a, EF_PLAIN );
	skipO.Fmt( s, EF_PLAIN );
	helpO.Fmt( h, EF_PLAIN ); // ?
	theirO.Fmt( at, EF_PLAIN );
	yoursO.Fmt( ay, EF_PLAIN );
	mergeO.Fmt( am, EF_PLAIN );

	MergeStatus autoStat = AutoResolve( CMF_AUTO );

	switch( autoStat )
	{
	default:		
	case CMS_SKIP:		autoSuggest = s  ; break;
	case CMS_THEIRS:	autoSuggest = at ; break;
	case CMS_YOURS:		autoSuggest = ay ; break;
	case CMS_MERGED:	autoSuggest = am ; break;
	// there is no CMS_EDIT for an action resolve
	}

	for ( ;; )
	{
	    // tell them what sort of resolve it is

	    if ( typeP.GetId( 0 ) )
	    {
		err.Clear();
		buf.Clear();
		err = typeP;
		type.Fmt( buf, EF_PLAIN );
		err << buf;
		ui->Message( &err );
	    }

	    // show options -- we always have at/ay, sometimes am

	    if ( theirA.GetId( 0 ) )
	    {
	        err.Clear();
		buf.Clear();
		err = theirP;
		theirA.Fmt( buf, EF_PLAIN );
		err << buf;
		ui->Message( &err );
	    }

	    if ( yoursA.GetId( 0 ) )
	    {
	        err.Clear();
		buf.Clear();
		err = yoursP;
		yoursA.Fmt( buf, EF_PLAIN );
		err << buf;
		ui->Message( &err );
	    }

	    if ( mergeA.GetId( 0 ) )
	    {
		err.Clear();
		buf.Clear();
		err = mergeP;
		mergeA.Fmt( buf, EF_PLAIN );
		err << buf;
		ui->Message( &err );
	    }

	    if ( preview )
	        return CMS_SKIP;

	    // prompt

	    err.Clear();
	    buf.Clear();
	    err = prompt;
	    err << autoSuggest;
	    err.Fmt( buf, EF_PLAIN );
	    ui->Prompt( buf, buf, 0, e );

	    if( e->Test() )
		return CMS_QUIT;

	    if( !buf[0] )
		buf = autoSuggest;

	    // process input option

	    if ( buf == s )
	        return CMS_SKIP;

	    if ( buf == a && autoStat != CMS_SKIP )
		return autoStat;

	    if ( buf == at && theirA.GetId( 0 ) )
		return CMS_THEIRS;

	    if ( buf == ay && yoursA.GetId( 0 ) )
		return CMS_YOURS;

	    if ( buf == am && mergeA.GetId( 0 ) )
		return CMS_MERGED;

	    if ( buf == h || buf == "h" )
	    {
	        // cheesy backward compatibility -- "h" for "help" if not used
		
	        err.Clear();
		buf.Clear();
		err = help;
		type.Fmt( buf, EF_PLAIN );
		err << buf;
		ui->Message( &err );
		continue;
	    }

	    // None of these?  Show usage error and ask again.

	    err.Clear();
	    err = error;
	    err << buf;
	    ui->Message( &err );
	    continue;
	}

	return CMS_SKIP;
}
