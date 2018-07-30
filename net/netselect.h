/*
 * Copyright 2009 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * NetTcpSelector -- isolation of select() call for TCP
 *
 * Public methods:
 *
 *	NetTcpSelector( int t ) - create a selector for file descriptor t
 *
 *	NetTcpSelector::Select( int &read, int &write, int usec, Error *e )
 *
 *	    Blocks waiting for read (if read set) and/or write 
 *	    (if write set).  Sets read if data ready to read, write
 *	    if data ready to write.
 *
 *	    Waits at most usec microseconds, or forever if usec < 0.
 *
 *	    Returns 0 if timeout.
 *	    Returns -1 on error (with Error set).
 *	    Returns >0 on data ready.
 *
 *	NetTcpSelector::Peek()
 *
 *	    Returns 1 if data is available to read, 0 if not (EOF).
 *	    Call Select() first.
 */


# if defined( AF_UNIX ) || defined( OS_NT )
# if !defined( OS_UNIXWARE7 ) && !defined( OS_SINIX ) && !defined( OS_OS2 )

// Add HPUX11 to standard select using fd_set,  anything greater than 256
// causes select() to sleep. 

# if defined( OS_HPUX11 ) || defined( OS_NT )
# define USE_SELECT_FDSET
# else
# define USE_SELECT_BITARRAY
# endif

# define USE_SELECTOR

# endif
# endif

class NetTcpSelector
{

    public:

# ifdef USE_SELECT_BITARRAY

	// Choose the max of ( fd + 1 ) and FD_SETSIZE in case the
	// select call always expects at least FD_SETSIZE large...
	// This is a safety measure mostly, but I have observed that
	// the FreeBSD select man page says it always looks at 256
	// descriptors so I'm erring on the conservative side..

	NetTcpSelector( int t )
	{
	    fd = t;
	    if( ++t < FD_SETSIZE )
		t = FD_SETSIZE;
	    rfd = new BitArray( t );
	    wfd = new BitArray( t );
	}

	~NetTcpSelector()
	{
	    delete rfd;
	    delete wfd;
	}

	void SetRead() { rfd->tas( fd ); }
	void ClearRead() { rfd->clear( fd ); }
	int CheckRead() { return (*rfd)[ fd ]; }
	fd_set *Rfds() { return (fd_set*)rfd->fdset(); }

	void SetWrite() { wfd->tas( fd ); }
	void ClearWrite() { wfd->clear( fd ); }
	int CheckWrite() { return (*wfd)[ fd ]; }
	fd_set *Wfds() { return (fd_set*)wfd->fdset(); }

	BitArray	*rfd;
	BitArray	*wfd;

# endif

# ifdef USE_SELECT_FDSET

	NetTcpSelector( int t ) 
	{
	    fd = t;
	    FD_ZERO( &rfd );
	    FD_ZERO( &wfd );
	}

	void SetRead() { FD_SET( fd, &rfd ); }
	void ClearRead() { FD_CLR( fd, &rfd ); }
	int CheckRead() { return FD_ISSET( fd, &rfd ); }
	fd_set *Rfds() { return &rfd; }

	void SetWrite() { FD_SET( fd, &wfd ); }
	void ClearWrite() { FD_CLR( fd, &wfd ); }
	int CheckWrite() { return FD_ISSET( fd, &wfd ); }
	fd_set *Wfds() { return &wfd; }

	fd_set		rfd;
	fd_set		wfd;

# endif

# ifdef USE_SELECTOR

	/* Select() that works with BitArray or fd_set */

	int Select( int &read, int &write, int msec )
	{
	    for( ;; )
	    {
	        struct timeval tv;

	        if( read ) SetRead(); else ClearRead();
	        if( write ) SetWrite(); else ClearWrite();

		if( msec < 1000 )
		{
		    tv.tv_sec = 0;
		    tv.tv_usec = msec * 1000;
		}
		else
		{
		    tv.tv_sec = msec / 1000;
		    tv.tv_usec = ( msec % 1000 ) * 1000;
		}

	        switch( select( fd+1, Rfds(), Wfds(), 0, msec >= 0 ? &tv : 0 ) )
	        {
	        case -1:	
	            if( errno == EINTR )
	                continue;
		    return -1;

	        case 0:	
		    // duh linux leaves fd_sets set on timeout
		    read = write = 0;
		    return 0;

	        default: 
		    read = CheckRead();
		    write = CheckWrite();
		    return 1;
	        }
	    }
	}

# if defined(OS_NT) || defined(OS_SOLARIS)

	int Peek()
	{
	    char buf[2];
	    return recv( fd, buf, 1, MSG_PEEK ) > 0;
	}

# else

	int Peek()
	{
	    int nread;
	    return ioctl( fd, FIONREAD, &nread ) >= 0 && nread > 0;
	}

# endif

	int fd;

# else

	/* Braindead version: ignorance is bliss */

	NetTcpSelector( int ) {}

	int Select( int &read, int &write, int time )
	{
	    read = write = 1;
	    return 1;
	}

	int Peek()
	{
	    return 1;
	}

# endif

} ;

