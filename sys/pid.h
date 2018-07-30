/*
 * Copyright 2001 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * Pid.h - provide process/thread information
 *
 * Class Defined:
 *
 *      Pid - process/thread identifier
 *
 * Public methods:
 *
 *      Pid::GetID() - get identifier for current process/thread
 *      Pid::GetProcID() - get identifier for the entire process,
                           not just a thread (Windows is different.)
 *      Pid::CheckID() - check to see if (our) thread is still
 *                       running (note: recycled process/thread are
 *                       not explicitly checked for).
 */

class Pid {

    public:

	int	GetID();
	int	GetProcID();
	int	CheckID( int id );
} ;

