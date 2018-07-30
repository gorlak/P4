/*
 * Copyright 1995, 2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * NtThreadList - Class supporting Threader::Reap for NT
 *
 * Public methods:
 *
 *	NtThreadList::NtThreadList()
 *	NtThreadList::~NtThreadList()
 *
 *	NtThreadList::AddThread()
 *	NtThreadList::RemoveThread()
 *	NtThreadList::GetThread()
 */

#ifndef NTTHDLIST_H__
#define NTTHDLIST_H__

class NtThreadList
{
    struct NtThreadEntry {
	    void                 *key;
	    DWORD                 tid;
	    struct NtThreadEntry *next;
	    struct NtThreadEntry *prev;
    } ;

    public:

		    NtThreadList();
    	virtual	    ~NtThreadList();

	void		AddThread( void *k, DWORD tid );
	int		RemoveThread( void *k );
	void		SuspendThreads();
	int		Empty();

	int		GetThreadCount();

    private:

	NtThreadEntry		*head;
	CRITICAL_SECTION	section;
	int			listSize;
};

#endif // NTTHDLIST_H__
