class BitArray;

class NetMulti {
    public:
	NetMulti();
	~NetMulti();

	/* remove all transports from multiple read i/o */
	void Clear();

	/* poll for readable transports */
	void Select( int block, Error *e );

	/* Add a transport for read i/o */
	void AddTransport( NetTransport *, Error *e );

	/* after a Select method, this call tells if a transport is readable */
	int Readable( NetTransport *, Error *e );

    private:
# ifdef USE_SELECT_BITARRAY
	BitArray *fds;
# else
	fd_set	*fds;
# endif
	int	maxfd;
};
