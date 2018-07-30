/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * appleforks.cc - build/split an AppleSingle/Double stream
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <error.h>

# include <filesys.h>

# include "applefork.h"

/*
 * AppleFork - a handle for dispatching a single fork
 */

AppleFork::~AppleFork()
{
}

/*
 * AppleForkSplit - process a stream, calling AppleForks for each fork
 */

AppleForkSplit::AppleForkSplit()
{
	numHandlers = 0;
	state = BeforeEndOfHeader;
	needed = SizeHeader;
}

void
AppleForkSplit::AddHandler( AppleFork *h )
{
	handler[ numHandlers++ ] = h;
}

void
AppleForkSplit::Write( const char *buf, int length, Error *e )
{
	int l;
	unsigned int magic, version;
	EntryId id;

	// don't cascade errors

	if( e->Test() )
	    return;

	for(;;)
	    switch( state )
	{
	case BeforeEndOfHeader:

	    // Fill in header; if need more, return for it.

	    l = length < needed ? length : needed;
	    header.Extend( buf, l );
	    buf += l;
	    length -= l;
	    needed -= l;

	    if( needed )
		return;

	    // Got header: now we need the number of entries

	    magic = header.GetMagic();
	    version = header.GetVersion();
	    numEntries = header.GetNumEntries();

	    // Humanity -- we need some sanity

	    if( version != MagicVersion || 
		magic != MagicAppleSingle && 
		magic != MagicAppleDouble ||
		numEntries < 0 || numEntries > 1000 )
	    {
		e->Set( E_FAILED, "Bad AppleSingle/Double header." );
		return;
	    }

	    // New needed

	    needed = numEntries * SizeEntry;
	    state = BeforeEndOfIndex;

	    // Fall thru

	case BeforeEndOfIndex:

	    // Fill in header; if need more, return for it.

	    l = length < needed ? length : needed;
	    header.Extend( buf, l );
	    buf += l;
	    length -= l;
	    needed -= l;

	    if( needed )
		return;

	    // Got index entries: start dispatching

	    state = StartingFork;
	    currentEntry = 0;

	    // Fall Thru

	case StartingFork:

	    if( currentEntry >= numEntries )
	    {
		// Done.  Better be no more data!

		if( length )
		    e->Set( E_FAILED, "AppleSingle/Double corrupted." );

		return;
	    }

	    // Look for a handler.

	    id = header.GetEntryId( currentEntry );
	    needed = header.GetEntryLen( currentEntry );
	    currentHandler = 0;

	    for( l = 0; l < numHandlers; l++ )
		if( handler[l]->WillHandle( id ) )
	    {
		currentHandler = handler[l];
		break;
	    }

	    if( !currentHandler )
	    {
		e->Set( E_FATAL, "Missing AppleSingle/Double handler." );
		return;
	    }

	    // Open the sucker.

	    currentHandler->WriteOpen( id, e );

	    if( e->Test() )
		return;

	    state = InFork;

	    // Fall thru

	case InFork:

	    // Write data; if more needed return for it.

	    l = length < needed ? length : needed;
	    currentHandler->Write( buf, l, e );
	    buf += l;
	    length -= l;
	    needed -= l;

	    if( needed || e->Test() )
		return;

	    // End of data; close 'er off.

	    currentHandler->WriteClose( e );

	    if( e->Test() )
		return;

	    // And look for the next one

	    ++currentEntry;
	    state = StartingFork;
	    break;
	}
}

void
AppleForkSplit::Done( Error *e )
{
	// don't cascade errors

	if( e->Test() )
	    return;

	// Just ensure they didn't stop in the middle of a fork.

	if( state == InFork )
	{
	    currentHandler->WriteClose( e );
	    e->Set( E_FAILED, "Premature end of AppleSingle/Double data." );
	    return;
	}

	// reset state,  there is a chance that we will split again.

	numHandlers = 0;
	state = BeforeEndOfHeader;
	needed = SizeHeader;

	header.Clear();
}

/*
 * AppleForkCombine - build a stream (subclass of AppleFork)
 */

AppleForkCombine::AppleForkCombine()
{
	header.AllocHeader();
	numEntries = 0;
	isSingle = 0;
	state = Start;
	dataBack = 0;
}

AppleForkCombine::~AppleForkCombine()
{
	delete dataBack;
}

int
AppleForkCombine::WillHandle( EntryId id )
{
	// Will handle anything.

	return 1;
}

void
AppleForkCombine::WriteOpen( EntryId id, Error *e )
{
	// Create the slot

	isSingle |= id == EntryIdData;

	header.AllocEntry( numEntries, id );

	dataLength = 0;
}

void
AppleForkCombine::Write( const char *buf, int len, Error *e )
{
	// Just append to internal buffer, tracking length.
	// If internal buffer gets too big, go to backing file.

	if( data.Length() > 102400 )
	{
	    // Create backing file and flush existing data there.

	    dataBack = FileSys::CreateGlobalTemp( FST_BINARY );
	    dataBack->Open( FOM_WRITE, e );
	    if( e->Test() ) return;
	    dataBack->Write( data.Text(), data.Length(), e );
	    if( e->Test() ) return;
	    data.Clear();
	}

	// Write to backing file or append to internal buffer.

	if( dataBack )
	    dataBack->Write( buf, len, e );
	else
	    data.Extend( buf, len );

	dataLength += len;
}

void
AppleForkCombine::WriteClose( Error *e )
{
	// Now we know the length

	header.SetEntryLen( numEntries++, dataLength );
}

int
AppleForkCombine::Read( char *buf, int length, Error *e )
{
	int l;
	int dataOffset;
	char *obuf = buf;

	// First initialize
	// Then read from the header buffer.
	// Then read from the data buffer.
	// Then return 0.
	// We never set Error.

	// Note: we usurp dataLength for our own purposes here,
	// to count the bytes read in header or data.

	for(;;)
	    switch( state )
	{
	case Start:

	    // Our only chance between last Close() and first Read()
	    // to initialize things.  We touch up the offsets here,
	    // to reflect their distance from the head of the file.

	    dataOffset = header.Length();

	    for( l = 0; l < numEntries; l++ )
	    {
		// Set new offset according to the accumulated length.

		header.SetEntryOff( l, dataOffset );
		dataOffset += header.GetEntryLen( l );
	    }

	    header.SetNumEntries( numEntries );

	    // If there is a data fork, we go to AppleSingle

	    if( IsAppleSingle() )
		header.SetMagic( MagicAppleSingle );

	    // If using backing file, close write/reopen read.

	    if( dataBack )
	    {
		dataBack->Close( e );
		dataBack->Open( FOM_READ, e );
		if( e->Test() ) return 0;
	    }

	    // Now on to reading header

	    dataLength = 0;
	    state = Header;

	    // Fall through

	case Header:

	    // Reading the header.
	    // Just read from internal buffer.
	    // dataLength tracks how much we have.

	    l = header.Length() - dataLength;

	    if( length < l )
		l = length;

	    memcpy( buf, header.Text() + dataLength, l );

	    buf += l;
	    length -= l;
	    dataLength += l;

	    if( !length )
		return buf - obuf;

	    // On to data

	    dataLength = 0;
	    state = Data;

	    // Fall through

# ifdef OS_NTIA64
	    // The ia64 compiler got internal errors with this
	    // switch statement.  A random break seems to help.

	    break;
# endif

	case Data:

	    // Reading the forks.
	    // Just read from internal buffer.
	    // dataLength tracks how much we have.

	    if( dataBack )
	    {
		// using backing file -- read from it.

		l = dataBack->Read( buf, length, e );
		if( e->Test() ) return 0;
	    }
	    else
	    {
		// Using internal buffer -- copy from it.

		l = data.Length() - dataLength;

		if( length < l )
		    l = length;

		memcpy( buf, data.Text() + dataLength, l );
	    }

	    buf += l;
	    dataLength += l;

	    // no more?

	    if( !l )
		state = Done;

	case Done:

	    return buf - obuf;
	}
}
