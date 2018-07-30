/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsmeta.c - print out RCS metadata, given an RcsArchive structure
 *
 * Classes defined:
 *
 *	RcsGenMeta - control block for generating metadata
 *
 * Public methods:
 *
 *	RcsGenMeta::RcsGenMeta -- set up for metadata generation
 *	RcsGenMeta::Generate - write metadata to stdio file
 *
 * Private structures:
 *
 *	RcsRevMeta - metadata info about a single rev
 *
 * History:
 *	2-18-97 (seiwald) - translated to C++.
 */

# define NEED_TYPES

# include <stdhdrs.h>

# include <strbuf.h>
# include <error.h>
# include <errorlog.h>
# include <filesys.h>

# include "readfile.h"
# include "rcsarch.h"
# include "rcsrev.h"
# include "rcsgen.h"
# include "rcsdate.h"
# include "rcsmeta.h"

/* CHEAT! from dmtypes.h! */

enum DmtActionType {
	DAT_ADD 	= 0,
	DAT_EDIT 	= 1,
	DAT_DELETE 	= 2,
	DAT_BRANCH	= 3,
	DAT_INTEG	= 4
} ;

/*
 * Generate output of the form:
 *
 *   rev:
 *	"rev" //depot/branch/path rev ishead action 
 *	      change-date change-code change-user 
 *	      //depot/IMPORT/arch-path arch-rev
 *
 *   label:
 *	"label" label //label/branch/path //depot/branch/path rev change-date
 *
 *   change:
 *	"change" change-date change-code change-user @text@
 *
 */


struct RcsRevMeta
{
	const char	*branch;
	const char	*revName;
	int		revNum;
	int		isHead;
	int		action;
} ;

RcsGenMeta::RcsGenMeta(
	FileSys *wf, 
	RcsArchive *ar,
	char *archName )
{
	this->wf = wf;
	this->ar = ar;
	this->archName = archName;

	/* In the attic? */

	char *a = archName;

	while( ( a = strchr( a, 'A' ) ) && strncmp( a, "Attic/", 6 ) )
		++a;

	if( isDead = ( a != 0 ) )
	{
	    strncpy( path, archName, a - archName );
	    strcpy( path + ( a - archName ), a + 6 );
	}
	else
	{
	    strcpy( path, archName );
	}
}

void
RcsGenMeta::Generate(
	Error *e )
{
	RcsRevMeta	rm;

	/* (Recursively) dump out the trunk */

	rm.branch = "main";
	rm.revName = ar->headRev.text;
	rm.isHead = 1;
	rm.revNum = 1;
	rm.action = DAT_ADD;

	Trunk( &rm, e );

	AssertLog.Report( e );
}

void
RcsGenMeta::Trunk(
	RcsRevMeta *rm,
	Error *e )
{
	RcsRev *rev;

	/* Find the rev */

	rev = ar->FindRevision( rm->revName, e );

	if( e->Test() )
	    return;

	/* Figure action */

	rm->action = DAT_EDIT;

	/* Recurse, to count down to the trunk. */

	if( rev->next.text )
	{
	    RcsRevMeta nrm[1];

	    nrm->branch = rm->branch;
	    nrm->isHead = 0;
	    nrm->revName = rev->next.text;
	    nrm->revNum = 1;
	    nrm->action = DAT_EDIT;	/* reset later */
	    Trunk( nrm, e );
	    rm->revNum += nrm->revNum;

	    if( e->Test() )
		return;

	    /* If nrm shows the previous rev was deleted, we'll make this */
	    /* rev an add. */

	    if( nrm->action == DAT_DELETE )
		rm->action = DAT_ADD;
	}
	else
	{
	    rm->action = DAT_ADD;
	}

	/* Dump out this rev. */

	Rev( rm, rev );

	/* Now, dump out branches */

	Branches( rm, rev, e );
}

void
RcsGenMeta::Branch(
	RcsRevMeta *rm,
	Error *e )
{
	RcsRev *rev;

	/* Find the rev */

	rev = ar->FindRevision( rm->revName, e );

	if( e->Test() )
	    return;

	/* Action always EDIT, since BRANCH is handled by RcsMetaBranches */
	/* actually, always EDIT */

	rm->isHead = !rev->next.text;
	rm->action = DAT_EDIT;

	/* Dump out this rev. */

	Rev( rm, rev );

	/* Now, dump out branches */

	Branches( rm, rev, e );

	if( e->Test() )
	    return;

	/* Recurse to next */

	if( rev->next.text )
	{
	    RcsRevMeta nrm[1];

	    nrm->branch = rm->branch;
	    nrm->revName = rev->next.text;
	    nrm->revNum = rm->revNum + 1;
	    /* isHead computed later */
	    /* action computed later */

	    Branch( nrm, e );
	}
}

void
RcsGenMeta::Branches(
	RcsRevMeta *rm,
	RcsRev *rev, 
	Error *e )
{
	RcsList *s;

	for( s = rev->branches; s; s = s->qNext )
	{
	    RcsList *t;
	    RcsRevMeta nrm[1];
	    char *r = s->revision.text;

	    /* Find the symbol for this branch */

	    for( t = ar->symbolList; t; t = t->qNext )
		if( RcsRevCmp( r, t->revision.text ) == REV_CMP_NUM_BRANCH )
		    break;

	    if( !t )
	    {
		fprintf( stderr, "%s/%s has no branch\n", archName, r );
		continue;
	    }

	    /* Generate branch point -- sames as orig */

	    nrm->branch = t->string.text;
	    nrm->revName = rm->revName;
	    nrm->revNum = 1;
	    nrm->isHead = 0;
	    nrm->action = DAT_BRANCH;

	    Rev( nrm, rev );

	    /* Now generate remaining revs 2+ in branch */

	    nrm->branch = t->string.text;
	    nrm->revName = s->revision.text;
	    nrm->revNum = 2;
	    nrm->isHead = 0;		/* dummy */
	    nrm->action = DAT_EDIT;	/* dummy */

	    Branch( nrm, e );

	    if( e->Test() )
		return;

	    /* Generate integration record & reverse integ record. */

	    GenString( "integ" );
	    File3( "depot", t->string.text, path ); /* to */
	    File3( "depot", rm->branch, path ); /* from */
	    GenNum( 0 );	/* startFromRev */
	    GenNum( rm->revNum );	/* endFromRev */
	    GenNum( 1 );	/* toRev */
	    GenNum( 2 );	/* BRANCH */
	    GenNum( 1 );	/* commited */
	    GenNum( 1 );	/* resolved */
	    GenNum( 0 );	/* changeCode */
	    GenNL();

	    GenString( "integ" );
	    File3( "depot", rm->branch, path ); /* from */
	    File3( "depot", t->string.text, path ); /* to */
	    GenNum( 0 );	/* startFromRev */
	    GenNum( 1 );	/* endFromRev */
	    GenNum( rm->revNum );	/* toRev */
	    GenNum( 3 );	/* BRANCH_R */
	    GenNum( 1 );	/* commited */
	    GenNum( 1 );	/* resolved */
	    GenNum( 0 );	/* changeCode */
	    GenNL();
	}
}

void
RcsGenMeta::Rev(
	RcsRevMeta *rm,
	RcsRev *rev )
{
	/* Dump out a revision */

	RcsList *s;
	int changeDate;
	unsigned int changeCode;
	RcsDate date;

	/* Turn action of "dead" rev's into delete. */

    	if( !strcmp( rev->state.text, "dead" ) || isDead && rm->isHead )
		rm->action = DAT_DELETE;

	/* Hash the change text. */

	{
	    RcsSize len;
	    changeCode = 0;

	    rev->log.file->Seek( rev->log.offset );

	    for( len = rev->log.length; len && !rev->log.file->Eof(); --len )
	    {
		changeCode = ( changeCode * 2903657531u ) 
			     ^ rev->log.file->Char() ;
		rev->log.file->Next();
	    }
	}

	/* And get the date */

	date.Set( rev->date.text );
	changeDate = date.Parse();

	/* Dump change */

	GenString( "change" );
	GenNum( changeDate );
	GenNum( changeCode );
	GenString( rev->author.text );
	GenChunk( &rev->log, 0 );
	GenNL();

	/* Dump rev */

	GenString( "rev" );
	File3( "depot", rm->branch, path );
	GenNum( rm->revNum );
	GenNum( rm->isHead );
	GenNum( rm->action );
	GenNum( changeDate );
	File3( "depot", "IMPORT", archName );
	GenString( rev->revName.text );
	GenNum( changeCode );
	GenString( rev->author.text );
	GenNL();

	/* Dump labels if there are any. */

	for( s = ar->symbolList; s; s = s->qNext )
	{
	    char label[ 64 ]; /* XXX DmtLDomain */

	    switch( RcsRevCmp( rev->revName.text, s->revision.text ) )
	    {
	    case REV_CMP_EQUAL:
		/* Truncate label at 63 chars */

		strncpy( label, s->string.text, sizeof( label ) );
		label[sizeof(label)-1] = 0;

		/* Symbol for this rev - write label entry */
		GenString( "label" );
		GenString( label );
		File3( label, rm->branch, path );
		File3( "depot", rm->branch, path );
		GenNum( rm->revNum );
		GenNum( changeDate );
		GenNL();
		break;
	    }
	}
}

void
RcsGenMeta::File3( 
	const char *domain,
	const char *branch,
	const char *path )
{
	char buf[1024];
	sprintf( buf, "//%s/%s/%s", domain, branch, path );
	GenString( buf );
}
