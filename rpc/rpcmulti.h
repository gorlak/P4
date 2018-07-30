/*
 * A class to allow multiple RPC polling and dispatching
 */

class RpcMulti
{
    public:
	RpcMulti();
	~RpcMulti();

	// add an rpc object to the group
	int Add( Rpc *, RpcDispatcher * );
	// remove an rpc object from the group
	int Remove( Rpc * );

	// test if any rpc object in the group is active
	int AnyActive();

	// Multi Dispatch! returns count of Rpc objects dispatched
	// timeout in milliseconds
	// or zero if timeout, < zero for errors
	int Dispatch( Error *e );

	void MultiRead( int blocking, Error *e );
	
    private:
	VarArray	RpcArray;
	VarArray	DispatcherArray;
};
