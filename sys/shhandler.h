/*
 * Copyright 1995, 2009 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * shhandler.h -- Smart Heap support code.
 *
 * Classes:
 *
 *	SHHandler - Static constructor for the setup of a Smart Heap.
 *	            Only one per application.
 *
 */


class StrPtr;
class StrBuf;

class SHHandler {

    public:

	SHHandler();

	void Tunables();

	void SetTunable( int index, unsigned int *value );

	int SetTunable( StrBuf &name, StrBuf &value );

	void UnsetTunable( int index );

	int UnsetTunable( const char *name );

	void Close();

	int Checkpoint( const char *tag, int ckpt );

	void ReportLeakage( int ckpt1, int ckpt2 );

	void MemCheckAll ();

	void ListAllPools( const char *tag,
			    unsigned int detail );

    private:

	MEM_BOOL ValidatePool( MEM_POOL pool );

	void ListPool( MEM_POOL pool,
			const char *tag,
			unsigned int detail );

	void ListEntry( const MEM_POOL_ENTRY *entry,
			int show_unused );

	MEM_SIZET FlushPool( MEM_POOL pool );

	int Config2Membytes( const char *value );

	static const int i=0;

	// Retain the previous value from the first call of the SH API.
	MEM_SIZET initial_procfree;
	MEM_SIZET initial_poolfree;
	MEM_SIZET initial_ceiling;
	MEM_SIZET initial_procgrowinc;
	MEM_SIZET initial_poolgrowinc;

	int cur_ckpt;
	int max_ckpt;

# ifdef OS_NT
	CRITICAL_SECTION section;
# endif // OS_NT

} ;

