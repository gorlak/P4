/*
 * Copyright 1995, 2010 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * shstub.cc -- Stubs to resolve Smart Heap symbols.
 */

# if defined(USE_SMARTHEAP) && !defined(OS_NTIA64)

# define NEED_SMARTHEAP

#undef MEM_DEBUG

# include <stdhdrs.h>
# include <shhandler.h>

# undef MEM_ENTRY1
# define MEM_ENTRY1

MEM_POOL MemDefaultPool;

_shAPI(MEM_BOOL, MemRegisterTask)( _dbgARGS1 )
{ return( 1 ); }

_shAPI(MEM_BOOL, MemUnregisterTask)( _dbgARGS1 )
{ return( 1 ); }

MEM_ENTRY1 MEM_ERROR_FN MEM_ENTRY MemSetErrorHandler( MEM_ERROR_FN )
{ return( (MEM_ERROR_FN) 0 ); }

_shAPI(MEM_SIZET, MemPoolSetCeiling)(MEM_POOL, MEM_SIZET _dbgARGS)
{ return( (MEM_SIZET) 0 ); }

MEM_ENTRY1 MEM_SIZET MEM_ENTRY MemPoolSetFreeBytes( MEM_POOL, MEM_SIZET )
{ return( (MEM_SIZET) 0 ); }

MEM_SIZET MEM_ENTRY MemProcessSetFreeBytes( MEM_SIZET )
{ return( (MEM_SIZET) 0 ); }

MEM_ENTRY1 MEM_SIZET MEM_ENTRY MemPoolSetGrowIncrement( MEM_POOL, MEM_SIZET )
{ return( (MEM_SIZET) 0 ); }

MEM_ENTRY1 MEM_SIZET MEM_ENTRY MemProcessSetGrowIncrement( MEM_SIZET )
{ return( (MEM_SIZET) 0 ); }

MEM_ENTRY1 MEM_BOOL MEM_ENTRY MemPoolSetMaxSubpools( MEM_POOL, unsigned )
{ return( (MEM_BOOL) 0 ); }

MEM_ENTRY1 MEM_BOOL MEM_ENTRY MemPoolLock( MEM_POOL )
{ return( (MEM_BOOL) 0 ); }

MEM_ENTRY1 MEM_BOOL MEM_ENTRY MemPoolUnlock( MEM_POOL )
{ return( (MEM_BOOL) 0 ); }

MEM_ENTRY1 MEM_POOL_STATUS MEM_ENTRY MemPoolFirst( MEM_POOL_INFO MEM_FAR *, MEM_BOOL )
{ return( (MEM_POOL_STATUS) 0 ); }

MEM_ENTRY1 MEM_POOL_STATUS MEM_ENTRY MemPoolNext( MEM_POOL_INFO MEM_FAR *, MEM_BOOL )
{ return( (MEM_POOL_STATUS) 0 ); }

MEM_ENTRY1 MEM_POOL_STATUS MEM_ENTRY MemPoolWalk( MEM_POOL, MEM_POOL_ENTRY MEM_FAR * )
{ return( (MEM_POOL_STATUS) 0 ); }

MEM_ENTRY1 MEM_SIZET MEM_ENTRY MemPoolCount( MEM_POOL )
{ return( (MEM_BOOL) 0 ); }

MEM_ENTRY1 MEM_SIZET MEM_ENTRY MemPoolSize( MEM_POOL )
{ return( (MEM_BOOL) 0 ); }

MEM_ENTRY1 MEM_SIZET MEM_ENTRY MemPoolShrink( MEM_POOL )
{ return( (MEM_BOOL) 0 ); }

MEM_ENTRY1 MEM_VERSION MEM_ENTRY MemVersion( void )
{ return ( 1 ); }

# endif // USE_SMARTHEAP && !OS_NTIA64
