
/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

class Enviro;
class HostEnv;
class FileSys;
class VarArray;
class Options;
class Client;
class StrDict;
class RegMatch;
class StrPtrLineReader;

/*
 * Class and function definitions for the aliasing facility of the command line.
 *
 * - ClientCommand
 * - CommandAlias
 * - CommandPattern
 * - CommandTransformation
 * - ClientAliases
 * - ClientUserStrBuf
 * - OperatorP4Subst
 */

int clientRunCommand(
	int argc,
	char **argv,
	Options &opts,
	ClientUser *ui,
	int &uidebug,
	Error *e );

void clientParseOptions( Options &opts, int &argc, StrPtr *&argv, Error *e );
void clientParseOptions( Options &opts, int &argc, char **&argv, Error *e );
void clientSetVariables( Client &client, Options &opts );
int  clientPrepareEnv  ( Client &client, Options &opts, Enviro &enviro );

class CommandPattern;

/*
 * ClientUserStrBuf: Enables aliases to capture the output of a command,
 *                   as well as to provide the input of a command.
 */
class ClientUserStrBuf : public ClientUserMunge
{

    public:
	                ClientUserStrBuf( Options &opts,
	                                  int autoLoginPrompt = 1 );
	                ~ClientUserStrBuf();

	virtual void	OutputInfo( char level, const char *data );
	virtual void 	OutputError( const char *errBuf );
	virtual void 	OutputText( const char *data, int length );
	virtual void	OutputStat( StrDict *dict );
	virtual void	HandleError( Error *err );
	virtual void	Message( Error *err );

	virtual void	InputData( StrBuf *strbuf, Error *e );

	void		SetFormat( const StrPtr *fmt );
	void		SetInputData( const StrPtr *data );

	const StrPtr	*GetOutput();

	int		GetSeverity();
	int		CommandFailed();

    private:

	void		Append( const char *s );

	StrBuf		input;
	StrBuf		output;
	StrBuf		format;
	
	int		severity;
	int		autoLogin;
} ;

/*
 * A ClientCommand is a single command to be run. The actual command is
 * constructed by processing the user's command according to the alias
 * definitions. Initially, the user's command is read, and stored in
 * a semi-parsed format. Then we iteratively transform that command, possibly
 * multiple times, until we arrive at a command that we're ready to run,
 * and then we run it.
 */
class ClientCommand
{
    public:

			ClientCommand();
			~ClientCommand();

	int		RunCommand( StrDict *dict, Error *e );

	void		CopyArguments(
	                    int argc,
	                    char **argv,
	                    Error *e );

	void		ParseOptions( Error *e );

	void		UpdateWorkingCommand(
	                    int n_argn,
	                    StrBuf *n_args,
	                    Error *e );

	int		Matches( CommandPattern *, StrPtr *text );

	void		Transform(
	                    int actual,
	                    char **vec,
	                    int numNamedArgs,
	                    StrDict *namedArgs,
	                    ClientCommand *result,
	                    Error *e );

	void		GetActual( int ac, StrRef *val );

	const StrPtr	*GetInput();
	const StrPtr	*GetOutput();
	void		SetInput( const StrPtr *);
	void		SetOutput( const StrPtr *);

    private:

	void		PrepareIO( StrDict *dict, Error *e );

	void		HandleOutput( StrDict *dict, Error *e );

	void		FormatCommand( StrBuf &b );

	int		FunctionMatches( StrPtr *text );

	int		HandleSpecialOperators(
	                    int argc,
	                    char **argv,
	                    Options &opts,
	                    Error *e );

	void		SplitArgs( Error *e );

	int		w_argc;   // #args starting with the function word
	int		w_argn;   // total #args, including client args
	int		w_argf;   // position of the function word in args
	StrPtr		*w_argv;  // pointer to the function word
	StrRef		*w_argp;  // array of pointers, for option parsing
	StrBuf		*w_args;  // the complete set of arguments
	Options		*w_opts;  // the parsed client arguments.
	char		**c_args;  // the args passed to clientRunCommand.

	StrBuf		inputVariable;
	StrBuf		outputVariable;

	ClientUserStrBuf *ui;
} ;

/*
 * A CommandPattern is the "left hand side" of an alias, and describes which
 * user commands should be transformed by this alias.
 */
class CommandPattern
{
    public:
			CommandPattern();
			~CommandPattern();

	void		Set( const StrPtr s );

	void		Compile( Error *e );

	void		Show( StrBuf &buf );

	int		Matches( ClientCommand *cmd );

	int		Formals();

	void		GetFormal( int ac, StrRef *var );

	int		IsAVariable( int ac );

    private:

	void		ValidateFormals( Error *e );

	StrBuf		text;

	StrBuf		wordsBuf;
	char		**vec;
	int		maxVec;
	int		actual;
	StrRef		w0;
	StrBuf		*formals;
	int		*formalTypes;

	enum FormalTypes { LITERAL = 1, VARIABLE = 2 } ;
} ;

/*
 * A CommandTransformation is the "right hand side" of an alias, and
 * describes how to modify the command and its arguments.
 */
class CommandTransformation
{
    public:
			CommandTransformation();
			~CommandTransformation();

	void		Set( const StrPtr *s );

	void		Compile( Error *e );

	void		Show( StrBuf &buf );

	void		Transform(
	                    ClientCommand *cmd,
	                    int transformNo,
	                    int numTransforms,
	                    int numNamedArgs,
	                    StrDict *namedArgs,
	                    VarArray *resultCommands,
	                    Error *e );

	const StrPtr	*GetInput();
	const StrPtr	*GetOutput();

    private:

	void		CompileRedirection( Error *e );

	void		CompileSpecialOperators( Error *e );

	static int	Words( StrBuf &tmp, const char *w, 
				char *vec[], int maxVec );

	StrBuf		text;

	StrBuf		wordsBuf;
	char		**vec;
	int		maxVec;
	int		actual;

	Options		*opts;
	int		argc;
	char		**argv;
	int		fulcrum;

	StrBuf		inputVariable;
	StrBuf		outputVariable;
} ;

/*
 * A CommandAlias combines a CommandPattern and 1+ CommandTransformation(s)
 */
class CommandAlias
{
    public:
			CommandAlias();
			~CommandAlias();

	void		Consume( StrPtr *line );

	int		Complete();

	void		Compile( Error *e );

	void		Show( StrBuf &buf );

	int		AlreadyUsed();

	int		Matches( ClientCommand *cmd );

	void		Transform(
	                    ClientCommand *cmd,
	                    VarArray *resultCommands,
	                    Error *e );

    private:

	void		AddTransform( const StrPtr *xf, Error *e );

	void		CompileTransforms( const StrPtr *xfms, Error *e );

	void		BuildDictionary( ClientCommand *cmd, Error *e );

	StrBuf		text;
	CommandPattern	pattern;
	VarArray	*transforms;
	int		used;
	StrDict		*dict;
} ;

/*
 * ClientAliases: manages the overall set of aliases, from the aliases file.
 *
 * Also provides a single static function that is the hook from ClientMain.
 */
class ClientAliases
{
    public:
			ClientAliases(
	                    int argc,
	                    char **argv,
	                    Enviro *env,
	                    HostEnv *hostEnv,
	                    Error *e );
			~ClientAliases();

	static int	ProcessAliases(
	                    int argc,
	                    char **argv,
	                    int &result,
	                    Error *e );

	void		LoadAliases( Error *e );

	int		HasCharsetError();
	int		HasAliases();
	int		HasAliasesDisabled();

	void		ShowAliases();

	void		ExpandAliases(
	                    int argc,
	                    char **argv,
	                    Error *e );

	int		WasExpanded();

	int		RunCommands( Error *e );

    private:

	void		ReadAliasesFile( Error *e );

	int		IsComment( StrPtr *line );

	void		UpdateCommands( int c, VarArray *resultCommands );

	int		CheckDryRun( int argc, char **argv, Error *e );

	int		WasAliasesCommand(
	                    int &result,
	                    Error *e );

	int		hasAliases;
	int		wasExpanded;
	Enviro		*env;
	HostEnv		*hostEnv;
	StrBuf		aliasesFilePath;
	FileSys		*aliasesFile;
	VarArray	*aliases;
	VarArray	*commands;
	StrBufDict	*ioDict;
	int		hasCharsetError;
	int		hasAliasesDisabled;
	int		parsedArgc;
	char		**parsedArgv;
} ;

/*
 * AliasSubstitution: utilities for handling variable substitutions.
 */
class AliasSubstitution
{
    public:
			AliasSubstitution( Client *c, StrDict *d );
			~AliasSubstitution();

	int		Substitute( StrBuf *b );

    private:

	void		GetValue( StrPtr &var, StrBuf *val );

	Client		*client;
	StrDict		*dict;
} ;

/*
 * OperatorP4Subst: uses our Regex engine to perform text substitutions.
 */
class OperatorP4Subst
{
    public:
			OperatorP4Subst();
			~OperatorP4Subst();

	void		Substitute(
	                    int argc,
	                    char **argv,
	                    Options &opts,
	                    ClientUser *ui,
	                    Error *e );

    private:

	void		UpdateLine(
	                    StrBuf *line,
	                    StrBuf *result,
	                    RegMatch *matcher,
	                    const char *replace );

	StrBuf		rawData;
	StrPtrLineReader *splr;
} ;
