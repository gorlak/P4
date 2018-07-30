/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include <debug.h>

# include "varlist.h"

# define DEBUG_RECORDS	( p4debug.GetLevel( DT_RECORDS ) >= 4 )
# define DEBUG_EXTEND	( p4debug.GetLevel( DT_RECORDS ) >= 5 )

/*
 * VarList - list of VarListNodes
 */

VarList::VarList()
{
	numElems = -1;
	sentinel = new VarListNode( this, 0 );
}

VarList::~VarList()
{
	Clear();
	Remove( sentinel );
}

void
VarList::Clear()
{
	while( numElems )
	    Remove( sentinel->next );
}

VarListNode *
VarList::First() const
{
	return numElems ? sentinel->next : 0;
}

VarListNode *
VarList::Last() const
{
	return numElems ? sentinel->prev : 0;
}

VarListNode *
VarList::Put( void *v )
{
	return sentinel->PutPrev( v );
}

void
VarList::Remove( VarListNode *n )
{
	// subclasses can do cleanup on n->Value()

	numElems--;

	n->prev->next = n->next;
	n->next->prev = n->prev;

	delete n;

	if( n == sentinel )
	    sentinel = 0;
}


/*
 * VarListNode - element of a VarList
 */

VarListNode::VarListNode( VarList *list, void *value )
{
	this->list = list;
	this->value = value;

	this->prev = this;
	this->next = this;

	list->numElems++;
}

VarListNode *
VarListNode::Prev() const
{
	return prev == list->sentinel ? 0 : prev;
}

VarListNode *
VarListNode::Next() const
{
	return next == list->sentinel ? 0 : next;
}

VarListNode *
VarListNode::PutPrev( void *v )
{
	VarListNode *n = new VarListNode( list, v );
	SetPrev( n );
	return n;
}

VarListNode *
VarListNode::PutNext( void *v )
{
	VarListNode *n = new VarListNode( list, v );
	SetNext( n );
	return n;
}

void
VarListNode::SetPrev( VarListNode *n )
{
	if( !n || n == this )
	    return;

	n->prev->next = n->next;
	n->next->prev = n->prev;

	n->prev = prev;
	n->next = this;

	prev->next = n;
	prev = n;
}

void
VarListNode::SetNext( VarListNode *n )
{
	if( !n || n == this )
	    return;

	n->prev->next = n->next;
	n->next->prev = n->prev;

	n->next = next;
	n->prev = this;

	next->prev = n;
	next = n;
}
