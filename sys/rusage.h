/*
 * Copyright 2001 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * Rusage -- CPU, etc usage measuring
 *
 * Rusage is a OS specific object that measures CPU time from its 
 * creation, for use in reporting on server speed.
 *
 * Classes:
 *	Rusage - CPU timer
 *
 * Public methods:
 *	Rusage::Start() - restart the timer
 *	Rusage::Message() - format an OS-specific resource usage message
 *	Rusage::Time() - return CPU time in ms
 */

class StrBuf;
struct UsageContext;

struct RusageTrack {
	int	trackable;
	P4INT64	utime;
	P4INT64	stime;
	P4INT64	io_in;
	P4INT64	io_out;
	P4INT64	net_in;
	P4INT64	net_out;
	P4INT64	maxrss;
	P4INT64	page_faults;
} ;

class Rusage {

    public:

    		Rusage();
		~Rusage();

	void	Start();
	void	Message( StrBuf &msg );
	void	GetTrack( int level, RusageTrack *track );
	P4INT64	Time();

    private:

	UsageContext	*tc;		// OS specific

} ;

