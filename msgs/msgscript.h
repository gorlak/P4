/*
 * Copyright 2018 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * msgscript.h - definitions of errors for scripting subsystem.
 */

class MsgScript {

    public:

	static ErrorId ScriptRuntimeError;
	static ErrorId ScriptMaxRunErr;
	static ErrorId DoNotBlameTheScript;

	static ErrorId ExtAddChangeDesc;
	static ErrorId ExtEditChangeDesc;

	static ErrorId ExtLoadErr;
};
