# define NEED_SOCKET_IO
# define NEED_TIME_HP
# define NEED_ERRNO

# include <stdhdrs.h>
# include <debug.h>
# include <error.h>
# include <strbuf.h>
# include <keepalive.h>
# include <netport.h>
# include <netportparser.h>
# include <netconnect.h>
# include <netmulti.h>
# include <netbuffer.h>
# include <bitarray.h>

NetMulti::NetMulti()
{
	fds = NULL;
	Clear();
}

NetMulti::~NetMulti()
{
	delete fds;
}

void
NetMulti::Clear()
{
	delete fds;
# ifdef USE_SELECT_BITARRAY
	fds = new BitArray( 1024 );
# else
	fds = new fd_set;
	FD_ZERO( fds );
# endif
	maxfd = -1;
}

void
NetMulti::Select( int block, Error *e )
{
	struct timeval tv;
	tv.tv_sec = tv.tv_usec = 0;

	int r;

	if( maxfd < 0 )
	    return;
# ifdef USE_SELECT_BITARRAY
	r = select( maxfd+1, (fd_set *)fds->fdset(), NULL, NULL,
			block ? NULL : &tv );
# else
	r = select( maxfd+1, fds, NULL, NULL,
			block ? NULL : &tv );
# endif

	// do something about errors XXX
}

void
NetMulti::AddTransport( NetTransport *r, Error *e )
{
	int fd = r->GetFd();

	if( fd >= 0 )
	{
# ifdef USE_SELECT_BITARRAY
	    fds->tas( fd );
# else
	    FD_SET( fd, fds );
# endif
	    if( fd > maxfd )
		maxfd = fd;
	}
}

int
NetMulti::Readable( NetTransport *r, Error *e )
{
	int fd = r->GetFd();

	if( fd < 0 )
	    return 0;
# ifdef USE_SELECT_BITARRAY
	return (*fds)[ fd ];
# else
	return FD_ISSET( fd, fds );
# endif
}
