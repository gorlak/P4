/*
 * Copyright 2002 Perforce Software.  All rights reserved.
 */

/*
 * ErrorPrivate - list of errors stored in an Error
 *
 * Classes defined:
 *
 *	ErrorPrivate - private part of Error that holds a list of
 *		errors, as well as the pre- and post-formatted
 *		messages and a StrDict of parameters to reformat
 *		the messages.
 *
 * Public methods:
 *
 *	ErrorPrivate::Clear() - prepare for Set()
 *	ErrorPrivate::operator = - copy ErrorPrivate
 *	ErrorPrivate::Set() - add another error message
 *	ErrorPrivate::SetArg() - provide an argument for last error message
 *	ErrorPrivate::AddVar() - add var/value parameter for SetArg()
 *	ErrorPrivate::Dump() - dump structure for debugging
 */

const int OldErrorMax = 8;
const int ErrorMax = 20; // As of Release 2014.1

class ErrorPrivate {

    public:

	void		operator =( const ErrorPrivate &source );

	void		Clear()
			{
			    errorCount = 0;
			    errorDict.Clear();
			    whichDict = &errorDict;
			    fmtSource = isConst;
			    walk = 0;
			}

	/* Setting errors */

	void		Set( const ErrorId &id )
			{
			    if( errorCount == ErrorMax )
				--errorCount;

			    /* Save everything */

			    ids[ errorCount++ ] = id;
			    walk = id.fmt;
			}

	void		SetArg( const StrPtr &arg );

	void		Dump();

	void		Merge( const ErrorPrivate * );

    public:

	/* Embedded variables and their values */

	StrDict		*whichDict;	// = errorDict unless UnMarshalled
	BufferDict	errorDict;

    public:

	// Errors and their values

	int		errorCount;
	ErrorId		ids[ ErrorMax ];
	StrBuf		fmtbuf;		// local storage for UnMarshall

	// What data ids[].fmt points to -- needed for operator =

	enum { isConst, isFmtBuf, isShared } fmtSource;

	const char	*walk;		// for SetArg's walk

} ;

