/*
 * Copyright 1995, 2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * ClientUserMarshal - ClientUser I/O is marshalled data for a scripting
 *                     language
 *
 * This implementation of ClientUser generates on stdout hash/
 * dictionary objects in the marshalled data format either Ruby or
 * Python. ClientUser::InputData reads such data from stdin.
 *
 * For ClientUser::OutputStat and InputData, if the 'spec' variable
 * is set (indicating that the data transferred is a cheesy ASCII form)
 * the 'spec' information is used to parse the form into or assemble the
 * form from its constituent variables.
 *
 * Note that many ClientUser methods are defaulted, and they
 * can't be used, because this implementation is batch mode only:
 *
 *	Prompt 
 *	ErrorPause 
 *	Edit
 *	Merge (temp files to merge are gone when proess exits)
 *	Help (used only by Merge)
 *
 * These methods are defined to produce the following dictionaries:
 *
 * ClientUser::HandleError() (99.1+ servers):
 *
 *	result = {
 *		"code" : "error",
 *		"data" : "text of error message"
 *		severity : severity code (see error.h)
 *		generic : generic code (see errornum.h)
 *	}
 *
 * ClientUser::OutputError() (pre-99.1 servers):
 *
 *	result = {
 *		"code" : "error",
 *		"data" : "text of error message"
 *	}
 *
 * ClientUser::OutputInfo() 
 *
 *	result = {
 *		"code" : "info",
 *		"level" : indentation sub-level
 *		"data" : "text of error message"
 *	}
 *
 * ClientUser::OutputText()
 *
 *	result = {
 *		"code" : "text",
 *		"data" : data
 *	}
 *
 * ClientUser::OutputBinary()
 *
 *	result = {
 *		"code" : "binary",
 *		"data" : data
 *	}
 *
 * ClientUser::OutputStat()
 *
 *	result = {
 *		"code" : "stat",
 *		"var" : "val"
 *		.
 *		.
 *		.
 *	}
 */

class MarshalDict;
class ClientUserMarshal : public ClientUser {

    public:
			ClientUserMarshal();
			~ClientUserMarshal();

	virtual void	InputData( StrBuf *strbuf, Error *e );

	virtual void 	HandleError( Error *err );
	virtual void 	OutputError( const char *errBuf );
	virtual void	OutputInfo( char level, const char *data );
	virtual void 	OutputBinary( const char *data, int length );
	virtual void 	OutputText( const char *data, int length );

	virtual void	OutputStat( StrDict *varList );

	virtual void	Diff( FileSys *f1, FileSys *f2, int doPage,
				char *diffFlags, Error *e );

	//
	// All Marshalled output is surfaced to the interface through this
	// method.
	//
	virtual void	WriteOutput( StrPtr *buf );

	//
	// All input from the interface is read through this method
	//
	virtual void	ReadInput( StrBuf *buf, Error *e );

    protected:
	MarshalDict	*result;

} ;

class ClientUserPython : public ClientUserMarshal {

    public:
			ClientUserPython();
} ;

class ClientUserRuby : public ClientUserMarshal {

    public:
			ClientUserRuby();
} ;


/*
 * ClientUserPhp differs from the other ClientUserMarshal classes
 * in that it buffers all output until all output has been dispatched.
 * This requirement stems from the need to encapsulate all of the output
 * blocks in an array the size of which must be stated when the array
 * is opened. For example:
 *
 *  a:<n>:{<output>,<output>,...}
 *
 * Note that prompt is also overridden to suppress the output and only
 * collect the input. This is necessary to ensure that the output is
 * still valid serialized PHP.
 */
 
class ClientUserPhp : public ClientUserMarshal {

    public:
			ClientUserPhp();
			~ClientUserPhp();

	virtual void	WriteOutput( StrPtr *buf );
	virtual void	Prompt( const StrPtr &msg, StrBuf &buf, int noEcho,
			        Error *e );

    private:
	int		outputCount;   // The number of times output is written
	StrBuf		*outputBuffer; // The deferred output buffer
} ;
