/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * RpcBuffer.h - manipulate a buffer full of symbols
 *
 * Classes Defined:
 *
 *	RpcBuffer - an RPC symbol table
 *
 * Public Methods:
 *
 *	RpcBuffer::Clear() - clear out previous symbols
 *
 *	RpcBuffer::SetVar() - set a new symbol in the buffer
 *	RpcBuffer::MakeVar() - return StrBuf for variable contents
 *
 *	RpcBuffer::Parse() - parse a formatted buffer, finding the symbols
 *	RpcBuffer::GetVar() - get the value of a symbol in a parsed buffer
 *
 *	RpcBuffer::CopyVars() - copy all variables from another RpcBuffer
 *
 * Private methods:
 *
 *	RpcBuffer::EndVar() - set actual length from MakeVar
 *
 */

class RpcRecvBuffer 
{
    public:
			RpcRecvBuffer()
			{  isAccepted=false;  }

	void		Parse( Error * );

	StrPtr *	GetVar( const StrPtr &v ) 
			{ return syms.GetVar( v ); }

	StrPtr *	GetVar( const char *v )
			{ return syms.GetVar( v ); }

	int		GetVar( int x, StrRef &var, StrRef &val ) 
			{ return syms.GetVar( x, var, val ); }

	void		RemoveVar( const StrPtr &v )
			{ syms.RemoveVar( v.Text() ); }

	int		GetArgc() { return args.Count(); }
	StrPtr *	GetArgv() { return args.Table(); }

	StrBuf *	GetBuffer() 
			{ 
			    args.Clear();
			    syms.Clear();
			    ioBuffer.Clear();
			    return &ioBuffer; 
			}

	int		GetBufferSize()
			{ return ioBuffer.Length(); }

	void		CopyBuffer( const RpcRecvBuffer *fromBuffer )
			{ ioBuffer.Set( fromBuffer->ioBuffer ); }

	void		CopyBuffer( const StrPtr *fromBuffer )
			{ ioBuffer.Set( fromBuffer ); }
	void		SetAccepted()
			{ isAccepted=true; }

    private:
    friend class RpcSendBuffer;

	StrBuf 		ioBuffer;	// data area
	StrPtrDict	syms;		// for named symbols
	StrPtrArray	args;		// for unnamed symbols
	bool		isAccepted;

} ;

class RpcSendBuffer
{
    public:
			RpcSendBuffer() 
			{ lastLength = 0; isAccepted=false; }

	void		Clear()
			{ lastLength = 0; ioBuffer.Clear(); }

	void		SetVar( const StrPtr &var, const StrPtr &value );
	void		SetVar( const char *var, const StrPtr &value );

	StrBuf *	MakeVar( const StrPtr &var );

	StrBuf *	GetBuffer() 
			{ if( lastLength ) EndVar(); return &ioBuffer; }

	int		GetBufferSize()
			{ return ioBuffer.Length(); }

	void		CopyBuffer( const RpcSendBuffer *fromBuffer )
			{ ioBuffer.Set( fromBuffer->ioBuffer ); }

	void		CopyVars( RpcRecvBuffer *fromBuffer );
	void		SetAccepted()
			{ isAccepted=true; }
    private:
	void		EndVar();

	StrBuf 		ioBuffer;	// data area
	int		lastLength;	// from last MakeVar call
	bool		isAccepted;

} ;

