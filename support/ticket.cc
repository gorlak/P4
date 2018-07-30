/*
 * Copyright 2004 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * ticket.cc - get/replace/delete stored tickets from ticketfile.
 *
 * Perforce tickets were introduced in 2003.2 (undoc).  Initially only
 * NT supported seemless setting/getting of these tickets although this
 * was limited to one server through the P4PASSWD registry variable.
 *
 * 2004.1 introduces a ticket file:
 *
 * $USERPROFILE/p4tickets.txt          --  windows(NT)
 * $HOME/.p4tickets                    --  UNIX
 * $P4TICKETS                          --  user-defined fullpath to file
 *
 * This code manipulates the users ticket file.  Tickets are issued when the
 * user runs the 'p4 login' command,  they are deleted by running 'p4 logout'
 * and they do expire after a default 12 hours or as set by group access.
 * 
 * Any operation on the file will first begin by reading the current ticket
 * file and populating an in-memory array.  Typically this will only contain
 * a few entries.  The array is modified and written back out to the file
 * using Rename() if a delete/replace/insert operation has occurred.
 *
 * Currently only one operation is allowed per object creation.
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <error.h>
# include <vararray.h>
# include <pathsys.h>
# include <filesys.h>
# include <enviro.h>
# include "ticket.h"

# ifdef OS_NT
# include <windows.h>
# endif

struct TicketItem {
	StrBuf port;
	StrBuf user;
	StrBuf ticket;
	int deleted;
};

/*
 * TicketTable -- array of available tickets
 */

class TicketTable : public VarArray {
 
    public:
			~TicketTable();
        TicketItem	*GetItem( const StrRef &port, const StrRef &user );
        void		DeleteItem( const StrRef &port, const StrRef &user );
        void      	PutItem( const StrRef &port, const StrRef &user,
			         const StrRef &ticket );
        void      	AddItem( const StrRef &port, const StrRef &user,
			         const StrRef &ticket );
};

Ticket::Ticket( const StrPtr *path )
{
        ticketTab = 0;
	ticketFile = 0;
	this->path = path;
}

Ticket::~Ticket()
{
	delete ticketTab;
	delete ticketFile;
}

int
Ticket::Init()
{
	// only one operation allowed, bail if already initialized

	if( ticketFile != 0 )
	    return 1;

	if( !ticketTab )
            ticketTab = new TicketTable;

	if( !path->Length() )
	    return 1;

	ticketFile = FileSys::Create( (FileSysType)(FST_TEXT|FST_L_LFCRLF) );
	ticketFile->Set( *path );

	// Make sure user-defined ticket is not a directory

	int stat = ticketFile->Stat();

	if( ( stat & FSF_EXISTS ) && ( stat & FSF_DIRECTORY ) )
	    return 1;

	return 0;
}

void
Ticket::List( StrBuf &b )
{
	if( Init() )
	    return;

	Error e;

	ReadTicketFile( &e );

	if( e.Test() )
	    return;

	TicketItem *t;

	for( int i = 0; i < ticketTab->Count(); i++ )
	{
	    t = (TicketItem *)ticketTab->Get( i );

	    b << t->port << " (" << t->user << ") " << t->ticket << "\n";
	}
}

void
Ticket::ListUser( const StrPtr &u, StrBuf &b )
{
	if( Init() )
	    return;

	Error e;

	ReadTicketFile( &e );

	if( e.Test() )
	    return;

	TicketItem *t;

	for( int i = 0; i < ticketTab->Count(); i++ )
	{
	    t = (TicketItem *)ticketTab->Get( i );

	    if( u == t->user )
		b << t->port << " " << t->ticket << "\n";
	}
}

char *
Ticket::GetTicket( StrPtr &port, StrPtr &user )
{
	if( Init() )
	    return( ( char *) 0 );

	Error e;

	ReadTicketFile( &e );

	if( e.Test() )
	    return( ( char * ) 0 );

	StrBuf validPort;

	// prefix local ports with localhost:

	if( !strchr( port.Text(), ':' ) )
	{
	    validPort.Set( "localhost:" );
	    validPort.Append( port.Text() );
	}
	else
	    validPort.Set( port.Text() );

	TicketItem *t = ticketTab->GetItem( validPort, user );

	if( t )
	    return( t->ticket.Text() );
	else
	    return( ( char *) 0 );
}

void		
Ticket::UpdateTicket( 
	const StrPtr &port, 
	StrPtr &user, 
	StrPtr &ticket, 
	int remove,
	Error *e )
{
	if( Init() )
	    return;

	FileSys *lock;
	lock = FileSys::CreateLock( ticketFile, e );

	if( e->Test() )
	    return;

	ReadTicketFile( e );

	if( e->Test() )
	{
	    delete lock;
	    return;
	}

	StrBuf validPort;

	// prefix local ports with localhost:

	if( !strchr( port.Text(), ':' ) )
	{
	    validPort.Set( "localhost:" );
	    validPort.Append( port.Text() );
	}
	else
	    validPort.Set( port.Text() );

	if( remove )
	    ticketTab->DeleteItem( validPort, user );
	else
	    ticketTab->PutItem( validPort, user, ticket );

	WriteTicketFile( e );

	delete lock;
}

void
Ticket::ReadTicketFile( Error *e )
{
	if( !( ticketFile->Stat() & FSF_EXISTS ) )
	    return;

	ticketFile->Open( FOM_READ, e );

	if( e->Test() )
	    return;

	// Special markers used by trust files.
	StrRef dummy( "**++**" );
	StrRef alt( "++++++" );
	StrRef wild( "******" );

	StrBuf line, port, user;

	// read contents of ticket file into array

	while( ticketFile->ReadLine( &line, e ) )
	{
	    char *equals, *colon;

	    if( !( equals = strchr( line.Text(), '=' ) ) )
	        continue;
                                                                                
	    port.Set( line.Text(), equals++ - line.Text() );

	    int isTrust = !strncmp( equals, dummy.Text(), dummy.Length() ) ||
	                  !strncmp( equals, alt.Text(), alt.Length() )   ||
	                  !strncmp( equals, wild.Text(), wild.Length() );

	    colon = isTrust ? strchr( equals, ':' ) : strrchr( equals, ':' );
	    if( !colon )
	        continue;

	    user.Set( equals, colon - equals );

	    ticketTab->AddItem( port, user, colon + 1 );
	}

	ticketFile->Close( e );
}

void
Ticket::WriteTicketFile( Error *e )
{
	// create a temporary file

	FileSys *tmpFile = FileSys::CreateTemp( FST_TEXT );
        tmpFile->MakeLocalTemp( path->Text() );
	tmpFile->Perms( FPM_RW );
	tmpFile->Open( FOM_WRITE, e );

	if( e->Test() )
	{
	    delete tmpFile;
	    return;
	}

	TicketItem *t;
	StrBuf line;

	// write out file contents to temporary file

	for( int i = 0; i < ticketTab->Count(); i++ )
	{
	    t = (TicketItem *)ticketTab->Get( i );

	    if( t->deleted )
	        continue;
	
	    line.Clear();
	    line << t->port << "=" << t->user << ":" << t->ticket << "\n";

	    tmpFile->Write( &line, e );

	    if( e->Test() )
	        break;
	}

	// rename to the target ticket file

	tmpFile->ClearDeleteOnClose();
	tmpFile->Close( e );
	tmpFile->Rename( ticketFile, e );

	// make the file readonly by owner

	ticketFile->Chmod( FPM_ROO, e );

	delete tmpFile;
}

TicketTable::~TicketTable()
{
	for( int i = 0; i < Count(); i++ )
	    delete (TicketItem *)Get(i);
}

void
TicketTable::AddItem( 
	const StrRef &port, 
	const StrRef &user, 
	const StrRef &ticket )
{
	TicketItem *t = new TicketItem;

	t->port.Set( port );
	t->user.Set( user );
	t->ticket.Set( ticket.Text() );
	t->deleted = 0;

	VarArray::Put( t );
}

void
TicketTable::PutItem( 
	const StrRef &port, 
	const StrRef &user, 
	const StrRef &ticket )
{
	TicketItem *t = GetItem( port, user );

	if( t )
	{
	    t->ticket.Set( ticket );

	    // we need to set user just in case source or target user
	    // was a wild card.

	    t->user.Set( user );  
	}
	else
	    AddItem( port, user, ticket );
}

void
TicketTable::DeleteItem( 
	const StrRef &port, 
	const StrRef &user )
{
	TicketItem *t = GetItem( port, user );

	if( t )
	    t->deleted = 1;
}

TicketItem *
TicketTable::GetItem( 
	const StrRef &port, 
	const StrRef &user )
{
	TicketItem *t;
	StrRef userWild( "******" );

	for( int i = 0; i < Count(); ++i )
	{
	    t = (TicketItem * )Get(i);

	    if( t->port.CCompare( port ) )
	        continue;

	    if( !t->user.Compare( user ) || 
	        !t->user.Compare( userWild ) ||
	        !user.Compare( userWild ) )
	    {
	        return( t );
	    }
	}

	return( ( TicketItem * ) 0 );
}
