/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 */

/*
 * VarList.h - manage a list of void *'s
 *
 * Class Defined:
 *
 *	VarList     - list of void *'s
 *	VarListNode - element in a VarList
 *
 * Public methods:
 *
 *	VarList::Clear() - remove all elements
 *	VarList::Count() - return count of elements
 *	VarList::First() - return the first node
 *	VarList::Last() - return the last node
 *	VarList::Put(v) - append to the end
 *	VarList::Remove(n) - remove node
 *
 *	VarListNode::Prev() - prev node, 0 if first
 *	VarListNode::Next() - next node, 0 if last
 *	VarListNode::Value() - void *
 *	VarListNode::PutPrev(v) - insert before this node
 *	VarListNode::PutNext(v) - insert after this node
 *	VarListNode::SetPrev(n) - relocate node to before this one
 *	VarListNode::SetNext(n) - relocate node to after this one
 */

class VarListNode;

class VarList {
	
    public:

			VarList();
	virtual		~VarList();

	void		Clear();
	int		Count() const { return numElems; }

	VarListNode *	First() const;
	VarListNode *	Last()  const;

	VarListNode *	Put( void *value );
	virtual void	Remove( VarListNode *n );

    private:
	friend class VarListNode;

	int		numElems;
	VarListNode *	sentinel;
} ;

class VarListNode {

    public:

	VarListNode *	Prev() const;
	VarListNode *	Next() const;
	void *		Value() const { return value; }

	VarListNode *	PutPrev( void *v ); // insert new node before this one
	VarListNode *	PutNext( void *v ); // insert new node after this one

	void		SetPrev( VarListNode *n ); // make other node my prev
	void		SetNext( VarListNode *n ); // make other node my next

    private:
	friend class VarList;

			VarListNode( VarList *list, void *value );

	VarListNode *	prev;
	VarListNode *	next;

	void *		value;

	VarList *	list;

};
