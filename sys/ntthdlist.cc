
/*
 * /+\
 * +\	Copyright 1995, 2000 Perforce Software.	 All rights reserved.
 * \+/
 *
 * This file is part of Perforce - the FAST SCM System.
 */

#include <windows.h>
#include <stdio.h>
#include <winsvc.h>
#include "ntthdlist.h"


NtThreadList::NtThreadList()
{
	head = 0;
	listSize = 0;

	InitializeCriticalSection( &section );
}

NtThreadList::~NtThreadList()
{
	NtThreadEntry *entry;

	EnterCriticalSection( &section );
	while( ( entry = head ) )
	{
	    head = head->next;
	    delete entry;
	}
	LeaveCriticalSection( &section );
	DeleteCriticalSection( &section );
}

void
NtThreadList::AddThread( void *k, DWORD t )
{
	NtThreadEntry *entry = new NtThreadEntry();
	entry->key = k;
	entry->tid = t;
	entry->prev = 0;

	EnterCriticalSection( &section );
	entry->next = head;
	if( head )
	    head->prev = entry;
	head = entry;
	listSize++;
	LeaveCriticalSection( &section );
}

int
NtThreadList::RemoveThread( void *k )
{
	NtThreadEntry *entry;

	EnterCriticalSection( &section );
	entry = head;
	while( entry )
	{
	    if( entry->key == k )
	    {
	        if( entry->next )
	            entry->next->prev = entry->prev;
		if( entry->prev )
	            entry->prev->next = entry->next;
		if( head == entry )
	            head = entry->next;
	        break;
	    }
	    entry = entry->next;
	}
	listSize--;
	LeaveCriticalSection( &section );

	if( entry )
	{
	    delete entry;
	    return 1;
	}

	return 0;
}

void
NtThreadList::SuspendThreads()
{
	NtThreadEntry *entry;
	HANDLE h;

	EnterCriticalSection( &section );
	entry = head;
	while( entry )
	{
	    h = OpenThread( THREAD_ALL_ACCESS, FALSE, entry->tid );
	    if( h != NULL )
	    {
		SuspendThread( h );
		CloseHandle( h );
	    }
	    entry = entry->next;
	}
	LeaveCriticalSection( &section );
}

#if 0
int
NtThreadList::GetThread( DWORD *tid )
{
	NtThreadEntry *entry;

	EnterCriticalSection( &section );
	entry = head;
	if( entry )
	{
	    head = entry->next;
	    if( head )
		head->prev = 0;
	}
	LeaveCriticalSection( &section );

	if( entry )
	{
	    *tid = entry->tid;
	    delete entry;
	    return 1;
	}
	return 0;
}
#endif

int
NtThreadList::Empty()
{
	int result;

	EnterCriticalSection( &section );
	result = head == 0;
	LeaveCriticalSection( &section );
	return result;
}

int
NtThreadList::GetThreadCount()
{
	int result;

	EnterCriticalSection( &section );
	result = listSize;
	LeaveCriticalSection( &section );
	return result;
}
