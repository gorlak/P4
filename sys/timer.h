/*
 * Copyright 2001 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * Timer - lapse timer
 *
 * Timer is a OS specific object that measures lapse time.
 *
 * Classes:
 *	Timer - lapse and CPU timer
 *	FmtMs() - format milliseconds with varying precision
 *
 * Public methods:
 *	Timer::Start() - restart the timer
 *	Timer::Message() - format an OS-specific resource usage message
 *	Timer::Time() - return MS since Start()
 *	Timer::Reset() - restart the timer to the time of the last check
 */

class StrBuf;

class StrMs : public StrPtr {

    public:
		StrMs( int ms );

    private:

	char	buf[ 24 ];

} ;
 
class Timer {

    public:
	void	        Start();
        void	        Message( StrBuf &msg ) 
                        { msg << StrMs( Time() ) << "s"; }
        int	        Time();
	void		Restart();

        const StrPtr &	Fmt( StrBuf &b ) const;
        void		Parse( const StrPtr &v );

    private:

	struct timer {
		long	sec;
		long	usec;
	} start, stop;

	static void Set( struct timer &t );

} ;

