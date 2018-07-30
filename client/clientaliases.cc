/*
 * Copyright 1995, 2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# define NEED_QUOTE

# include <stdhdrs.h>
# include <charman.h>

# include <debug.h>
# include <strbuf.h>
# include <strdict.h>
# include <strtable.h>
# include <strarray.h>
# include <strops.h>
# include <splr.h>
# include <error.h>
# include <options.h>
# include <handler.h>
# include <vararray.h>
# include <rpc.h>

# include <pathsys.h>
# include <filesys.h>

# include <ticket.h>
# include <enviro.h>
# include <i18napi.h>
# include <charcvt.h>
# include <charset.h>
# include <hostenv.h>
# include <errorlog.h>
# include <p4tags.h>

# include <regmatch.h>

# include <msgclient.h>
# include <msgsupp.h>
# include <msghelp.h>

# include "client.h"
# include "clientmerge.h"
# include "clientuser.h"
# include "clientuserdbg.h"
# include "clientusermsh.h"
# include "clientaliases.h"

/*
 * This file contains the implementation of the various classes used in the
 * command-line client aliases feature:
 *
 * - ClientAliases
 * - ClientCommand
 * - CommandAlias
 * - CommandPattern
 * - CommandTransformation
 *
 * A single static function (ClientAliases::ProcessAliases) provides the
 * overall "hook" used by clientMain to handle aliasing.
 */

int
ClientAliases::ProcessAliases(
	int argc,
	char **argv,
	int &result,
	Error *e )
{
	// Pseudocode:
	//     LoadAliases
	//     if error return 1
	//     if no aliases return 0
	//
	//     ExpandAliases
	//     if error return 1
	//     if no relevant aliases return 0
	//
	//     ProcessExpandedCommand

	Enviro env;
	HostEnv hostEnv;

	ClientAliases clientAliases( argc, argv, &env, &hostEnv, e );
	if( e->Test() || clientAliases.HasCharsetError() )
	    return result = 1;
	if( clientAliases.HasAliasesDisabled() )
	    return 0;

	result = 0;

	clientAliases.LoadAliases( e );
	if( e->Test() )
	    return result = 1;

	if( clientAliases.WasAliasesCommand( result, e ) )
	    return 1;

	if( !clientAliases.HasAliases() )
	    return result = clientAliases.CheckDryRun( argc, argv, e );

	clientAliases.ExpandAliases( argc, argv, e );
	if( e->Test() )
	    return result = 1;
	if( !clientAliases.WasExpanded() )
	    return result = clientAliases.CheckDryRun( argc, argv, e );

	result = clientAliases.RunCommands( e );

	if( e->Test() )
	    return result = 1;
	return 1;
}

ClientAliases::ClientAliases(
	int argc,
	char **argv,
	Enviro *env,
	HostEnv *hostEnv,
	Error *e )
{
	aliases = new VarArray;
	commands = new VarArray;
	hasAliases = 0;
	hasAliasesDisabled = 0;
	hasCharsetError = 0;
	wasExpanded = 0;

	this->env = env;
	this->hostEnv = hostEnv;

	aliasesFile = 0;
	ioDict = 0;

	Client client;
	Options opts;
	parsedArgc = argc;
	parsedArgv = argv;
	clientParseOptions( opts, parsedArgc, parsedArgv, e );
	if( e->Test() )
	    return;
	if( clientPrepareEnv( client, opts, *(this->env) ) )
	{
	    hasCharsetError = 1;
	    return;
	}
	const StrPtr *aliasHandling = opts[ Options::Aliases ];
	if( aliasHandling && !strncmp( aliasHandling->Text(), "no", 2 ) )
	    hasAliasesDisabled = 1;
}

ClientAliases::~ClientAliases()
{
	delete ioDict;
	if( aliases )
	{
	    for( int i = 0; i < aliases->Count(); i++ )
	    {
	        CommandAlias *a = (CommandAlias *)aliases->Get( i );
	        delete a;
	    }
	    delete aliases;
	}
	if( commands )
	{
	    for( int i = 0; i < commands->Count(); i++ )
	    {
	        ClientCommand *a = (ClientCommand *)commands->Get( i );
	        delete a;
	    }
	    delete commands;
	}
	delete aliasesFile;
}

void
ClientAliases::LoadAliases(
	Error *e )
{
	// First implementation is very crude, and supports only a single
	// aliases file, side by side with your tickets file.
	//
	// Following (sort of) our other conventions, the file is named
	//   $HOME/.p4aliases on Unix-y systems, and
	//   %USERPROFILE%\p4aliases.txt on Windows

	hostEnv->GetAliasesFile( aliasesFilePath, env );

	aliasesFile = FileSys::Create( (FileSysType)(FST_TEXT|FST_L_LFCRLF) );
	aliasesFile->Set( aliasesFilePath );

	int stat = aliasesFile->Stat();
	if( ( stat & FSF_EXISTS ) )
	{
	    // Ignore ~/.p4aliases if it is a directory:

	    if( ( stat & FSF_DIRECTORY ) )
	        return; // FIXME: too quiet?

	    ReadAliasesFile( e );
	    if( e->Test() )
	        return;
	}
	hasAliases = aliases->Count() > 0;
}

int
ClientAliases::HasAliases()
{
	return hasAliases;
}

int
ClientAliases::HasAliasesDisabled()
{
	return hasAliasesDisabled;
}

int
ClientAliases::HasCharsetError()
{
	return hasCharsetError;
}

void
ClientAliases::ReadAliasesFile(
	Error *e )
{
	aliasesFile->Open( FOM_READ, e );
	if( e->Test() )
	    return;

	StrBuf line;
	CommandAlias *alias = new CommandAlias;


	while( !e->Test() && aliasesFile->ReadLine( &line, e ) )
	{
	    line.TrimBlanks();

	    if( IsComment( &line ) )
	        continue;

	    alias->Consume( &line );

	    if( alias->Complete() )
	    {
	        alias->Compile( e );
	        if( !e->Test() )
	        {
	            aliases->Put( alias );
	            alias = new CommandAlias;
	        }
	    }
	}
	if( !alias->Complete() )
	    e->Set( MsgClient::AliasPartial );

	aliasesFile->Close( e );

	delete alias;
}

int
ClientAliases::IsComment( StrPtr *line )
{
	const char *p = line->Text();
	int len = 0;

	while( p && *p )
	{
	    if( *p == '#' )
	        return 1;
	    if( *p != ' ' && *p != '\t' )
	        return 0;

	    len++;
	    p++;
	}
	if( len )
	    return 0;

	return 1; // empty line counts as a comment.
}

void
ClientAliases::ShowAliases()
{
	for( int i = 0; i < aliases->Count(); i++ )
	{
	    CommandAlias *a = (CommandAlias *)aliases->Get( i );

	    StrBuf aBuf;

	    a->Show( aBuf );

	    printf("%s\n", aBuf.Text());
	}
}

void
ClientAliases::ExpandAliases(
	int argc,
	char **argv,
	Error *e )
{
	// We iteratively attempt to apply our aliases. Each time we
	// successfully apply an alias, we restart the entire process.
	//
	// We stop when:
	// - we encounter an error, or
	// - we went all the way through and nothing changed
	//
	// If we successfully expanded the user's command using our aliases,
	// we can then run the results of the expansion
	//
	// Note that, initially, we are trying to match/transform the user's
	// raw command (in argc/argv), but subsequently we are trying to
	// match the working command, which is a copy.
	//
	// And since a single alias may expand to a list of commands, in the
	// end we may have multiple commands to run.

	ClientCommand *cmd = new ClientCommand;
	commands->Put( cmd );
	cmd->CopyArguments( argc, argv, e );

restart:

	if( e->Test() )
	    return;

	for( int c = 0; c < commands->Count(); c++ )
	{
	    cmd = (ClientCommand *)commands->Get( c );

	    for( int i = 0; i < aliases->Count(); i++ )
	    {
	        CommandAlias *a = (CommandAlias *)aliases->Get( i );

	        if( a->Matches( cmd ) )
	        {
	            VarArray resultCommands;
	            a->Transform( cmd, &resultCommands, e );
	            if( e->Test() )
	                return;

	            if( resultCommands.Count() > 0 )
	            {
	                UpdateCommands( c, &resultCommands );
	                wasExpanded = 1;
	                goto restart;
	            }
	        }
	    }
	}
}

int
ClientAliases::WasExpanded()
{
	return wasExpanded;
}


void
ClientAliases::UpdateCommands( int which, VarArray *resultCommands )
{
	ClientCommand *oldOne = (ClientCommand *)commands->Get( which );

	VarArray *revisedCommands = new VarArray;

	for( int i = 0; i < commands->Count(); i++ )
	{
	    if( i != which )
	    {
	        revisedCommands->Put( commands->Get( i ) );
	    }
	    else
	    {
	        for( int j = 0; j < resultCommands->Count(); j++ )
	            revisedCommands->Put( resultCommands->Get( j ) );
	    }
	}
	delete oldOne;
	delete commands;
	commands = revisedCommands;
}

int
ClientAliases::RunCommands( Error *e )
{
	ioDict = new StrBufDict;

	for( int c = 0; !e->Test() && c < commands->Count(); c++ )
	{
	    ClientCommand *cmd = (ClientCommand *)commands->Get( c );

	    if( cmd->RunCommand( ioDict, e ) )
	        return 1;
	}
	return 0;
}

// Returns 1 if this was a dry run, with an appropriate message, else returns 0
//
int
ClientAliases::CheckDryRun( 
	int argc,
	char **argv,
	Error *e )
{
	Options opts;
	int origArgc = argc;
	char **origArgv = argv;
	clientParseOptions( opts, argc, argv, e );
	if( e->Test() )
	    return 1;

	const StrPtr *aliasHandling = opts[ Options::Aliases ];
	if( aliasHandling && 
	    ( *aliasHandling == "dry-run" || *aliasHandling == "echo" ) )
	{
	    StrBuf buf;
	    buf << "p4 ";
	    int firstArg = 1;
	    for( int ac = 0; ac < origArgc; ac++ )
	    {
	        if( !strncmp(origArgv[ac], "--aliases", 9 ) )
	            continue;

	        if( !firstArg )
	            buf << " ";
	        buf << origArgv[ac];
	        firstArg = 0;
	    }
	    e->Set( MsgClient::CommandNotAliased ) << buf;
	    return 1;
	}
	return 0;
}

int
ClientAliases::WasAliasesCommand(
	int &result,
	Error *e )
{
	if( parsedArgc >= 1 && !strcmp( parsedArgv[0], "aliases" ) )
	{
	    if( parsedArgc >= 2 &&
	        ( !strcmp( parsedArgv[1], "help" ) ||
	          !strcmp( parsedArgv[1], "-h" ) ||
	          !strcmp( parsedArgv[1], "-?" ) ||
	          !strcmp( parsedArgv[1], "?" ) ) )
	    {
	        e->Set( MsgHelp::HelpAliases );
		return 1;
	    }
	    if( !HasAliases() )
	    {
	        e->Set( MsgClient::NoAliasesFound );
		return result = 1;
	    }
	    ShowAliases();
	    return 1;
	}
	return 0;
}

/**************************************************************************
 * CommandAlias: class for working with a single concrete alias           *
 **************************************************************************/

CommandAlias::CommandAlias()
{
	used = 0;
	transforms = new VarArray;
	dict = 0;
}

CommandAlias::~CommandAlias()
{
	delete dict;

	if( transforms )
	{
	    for( int i = 0; i < transforms->Count(); i++ )
	    {
	        CommandTransformation *t =
	                (CommandTransformation *)transforms->Get( i );
	        delete t;
	    }
	    delete transforms;
	}
}

void
CommandAlias::Consume( StrPtr *line )
{
	text << *line;
}

int
CommandAlias::Complete()
{
	// Looking at the end of the alias, we decide whether the alias
	// is complete, or whether the next line should be added on to
	// this alias. There are two line continuation conventions: && at
	// the end of the line, or '\' at the end of the line. The trailing
	// backslash, if present, is removed.

	text.TrimBlanks();
	char *p = text.Text();
	while( p && *p && *(p+1) )
	{
	    if( *p == '&' && *(p+1) == '&' && *(p+2) == '\0' )
	    {
	        return 0;
	    }
	    if(              *(p+1) == '\\' && *(p+2) == '\0' )
	    {
	        p++;
	        *p = ' ';
	        text.SetEnd( p );
	        text.Terminate();
	        return 0;
	    }
	    p++;
	}
	return 1;
}

void
CommandAlias::Compile( Error *e )
{
	const char *equals = 0;
	const char *p = text.Text();

	while( p && *p )
	{
	    if( *p == '=' )
	    {
	        if( equals )
	        {
	            e->Set( MsgClient::AliasTooManyEquals ) << text;
	            return;
	        }
	        equals = p;
	    }
	    p++;
	}
	if( !equals )
	{
	    e->Set( MsgClient::AliasMissingEquals ) << text;
	    return;
	}
	if( equals - text.Text() <= 0 )
	{
	    e->Set( MsgClient::AliasEmptyPattern ) << text;
	    return;
	}

	pattern.Set( StrRef( text.Text(), equals - text.Text() ) );

	pattern.Compile( e );
	if( e->Test() )
	    return;

	StrRef xf( equals + 1 );
	CompileTransforms( &xf, e );
	if( e->Test() )
	    return;
}

void
CommandAlias::AddTransform( const StrPtr *xf, Error *e)
{
	CommandTransformation *t = new CommandTransformation;

	transforms->Put( t );
	t->Set( xf );
	t->Compile( e );
}

void
CommandAlias::CompileTransforms( const StrPtr *xfms, Error *e )
{
	// Split apart the multiple commands (if any) at the '&&' points.

	const char *p = xfms->Text();
	const char *s = p;

	while( p && *p )
	{
	    if( p[0] == '&' && p[1] == '&' )
	    {
	        StrRef xf( s, p - s );
	        AddTransform( &xf, e );
	        if( e->Test() )
	            return;
	        p++;
	        s = p + 1;
	    }

	    p++;
	}
	if( s != p )
	{
	    StrRef xf( s, p - s );
	    AddTransform( &xf, e );
	}
	if( e->Test() )
	    return;

	if( !transforms->Count() )
	    e->Set( MsgClient::AliasNoTransform ) << text;
}

void
CommandAlias::Show( StrBuf &display )
{
	pattern.Show( display );
	display << " => ";
	for( int i = 0; i < transforms->Count(); i++ )
	{
	    CommandTransformation *t =
	                (CommandTransformation *)transforms->Get( i );
	    StrBuf msg;

	    if( i > 0 )
	        display << " && ";

	    t->Show( msg );
	    display << msg;
	}
}

int
CommandAlias::Matches( ClientCommand *cmd )
{
	return !used && pattern.Matches( cmd );
}

int
CommandAlias::AlreadyUsed()
{
	return used;
}

void
CommandAlias::Transform(
	ClientCommand *cmd,
	VarArray *resultCommands,
	Error *e )
{
	used = 1;
	BuildDictionary( cmd, e );

	for( int i = 0; !e->Test() && i < transforms->Count(); i++ )
	{
	    CommandTransformation *t =
	                (CommandTransformation *)transforms->Get( i );

	    t->Transform( cmd, i, transforms->Count(),
	                  pattern.Formals(), dict, resultCommands, e );
	}
}

void
CommandAlias::BuildDictionary( ClientCommand *cmd, Error *e )
{
	// If the alias included any formal arguments, for example:
	//     recent-by-user $(u) $(m) = changes -u $(u) -m $(m)
	// then build up a dictionary providing values for those arguments
	// from the actual command arguments.

	int n_args = pattern.Formals();
	if( n_args > 0 )
	{
	    StrRef var, val;
	    dict = new StrBufDict();

	    for( int ac = 0; ac < n_args; ac++ )
	    {
	        if( pattern.IsAVariable( ac ) )
	        {
	            pattern.GetFormal( ac, &var );
	            cmd->GetActual( ac, &val );

	            dict->SetVar( var, val );
	        }
	    }
	}
}

/**************************************************************************
 * CommandPattern: manages the "left hand side" of an alias definition    *
 **************************************************************************/

CommandPattern::CommandPattern()
{
	actual = 0;
	maxVec = 0;
	vec = 0;
	formals = 0;
	formalTypes = 0;
}

CommandPattern::~CommandPattern()
{
	delete [] vec;
	delete [] formals;
	delete [] formalTypes;
}

void
CommandPattern::Set( const StrPtr s )
{
	text << s;
}

void
CommandPattern::Compile( Error *e )
{
	text.TrimBlanks();

	maxVec = 100;
	vec = new char *[ maxVec ];
	actual = StrOps::Words( wordsBuf, text.Text(), vec, maxVec );

	if( actual >= maxVec )
	    e->Set( MsgClient::AliasTooComplex ) << text << StrNum( maxVec );
	else if( actual <= 0 )
	    e->Set( MsgClient::AliasEmptyPattern ) << text;
	if( e->Test() )
	    return;

	w0 = vec[0];

	if( Formals() > 0 )
	    ValidateFormals( e );
}

void
CommandPattern::Show( StrBuf &buf )
{
	buf << text;
}

int
CommandPattern::Matches( ClientCommand *cmd )
{
	return cmd->Matches( this, &w0 );
}

int
CommandPattern::Formals()
{
	return actual - 1;
}

void
CommandPattern::ValidateFormals( Error *e )
{
	formals = new StrBuf[ Formals() ];
	formalTypes = new int[ Formals() ];

	// For each formal argument, it should be of the form $(var).
	// Extract the variable name and remember it.

	for( int ac = 1; ac < actual; ac++ )
	{
	    const char *s = vec[ ac ];

	    if( s[0] != '$' || s[1] != '(' )
	    {
	        formals[ ac - 1 ] = StrRef( s );
	        formalTypes[ ac - 1 ] = LITERAL;
	        continue;
	    }
	    const char *p = s + 2;
	    while( p && *p )
	    {
	        if( p[0] == ')' )
	        {
	            if( p[1] != '\0' )
	            {
	                e->Set( MsgClient::AliasArgSyntax )
	                        << vec[ ac ] << text;
	                return;
	            }
	            formals[ ac - 1 ] = StrRef( s + 2, p - s - 2 );
	            formalTypes[ ac - 1 ] = VARIABLE;
	        }
	        p++;
	    }
	}
}

void
CommandPattern::GetFormal( int ac, StrRef *var )
{
	if( ac >= 0 && ac < Formals() )
	    var->Set( formals[ ac ] );
}

int
CommandPattern::IsAVariable( int ac )
{
	if( ac >= 0 && ac < Formals() )
	    return formalTypes[ ac ] == VARIABLE;
	return 0;
}

/***************************************************************************
  * CommandTransformation: manages the "right hand side" of an alias       *
  **************************************************************************/

CommandTransformation::CommandTransformation()
{
	opts = new Options;
	actual = 0;
	maxVec = 0;
	vec = 0;
}

CommandTransformation::~CommandTransformation()
{
	delete opts;
	delete [] vec;
}

void
CommandTransformation::Set( const StrPtr *s )
{
	text << s;
}

void
CommandTransformation::Compile( Error *e )
{
	text.TrimBlanks();

	CompileRedirection( e );
	if( e->Test() )
	    return;

	maxVec = 100;
	vec = new char *[ maxVec ];
	actual = Words( wordsBuf, text.Text(), vec, maxVec );

	if( actual >= maxVec )
	    e->Set( MsgClient::AliasTooComplex ) << text << StrNum( maxVec );
	else if( actual <= 0 )
	    e->Set( MsgClient::AliasEmptyTransform );
	if( e->Test() )
	    return;

	// find the fulcrum

	argc = actual;
	argv = &vec[0];

	clientParseOptions( *opts, argc, argv, e );

	if( e->Test() )
	{
	    e->Set( MsgClient::AliasSyntaxError ) << text;
	    return;
	}

	fulcrum = actual - argc;

	if( !argc )
	{
	    e->Set( MsgClient::AliasMissingCommand ) << text;
	    return;
	}

	CompileSpecialOperators( e );
	if( e->Test() )
	    return;
}

// Like StrOps::Words, but with slightly different quotes handling
int
CommandTransformation::Words(
	StrBuf &tmp,
	const char *buf,
	char *vec[],
	int maxVec )
{
	tmp.Clear();
	tmp.Alloc( strlen( buf ) + 1 );
	tmp.Clear();

	int count = 0;

	while( count < maxVec )
	{
	    while( isAspace( buf ) ) buf++;
	    if( !*buf ) break;

	    vec[ count++ ] = tmp.End();

	    int quote = 0;

	    for( ; *buf; ++buf )
	    {
		if( quote && buf[0] == '"' && buf[1] == '"' )
		    tmp.Extend( buf[0] ), ++buf;
		else if( buf[0] == '"' )
		    quote = !quote;
		else if( quote || !isAspace( buf ) )
		    tmp.Extend( buf[0] );
		else break;
	    }

	    tmp.Extend( '\0' );
	}

        return count;
}

void
CommandTransformation::CompileSpecialOperators( Error *e )
{
	if( !strcmp( vec[ fulcrum ], "p4subst" ) )
	{
	    // p4subst must have two arguments, and both input and output
	    // must be redirected.

	    if( actual != 3 )
	        e->Set( MsgClient::AliasSubstArgs );
	    else if( !inputVariable.Length() )
	        e->Set( MsgClient::AliasSubstInput );
	    else if( !outputVariable.Length() )
	        e->Set( MsgClient::AliasSubstOutput );
	    return;
	}
}

void
CommandTransformation::Show( StrBuf &buf )
{
	buf << text;

	if( inputVariable.Length() )
	    buf << " < $(" << inputVariable << ")";

	if( outputVariable.Length() )
	    buf << " > $(" << outputVariable << ")";
}

void
CommandTransformation::Transform(
	ClientCommand *cmd,
	int xformNo,
	int numXforms,
	int numNamedArgs,
	StrDict *namedArgs,
	VarArray *resultCommands,
	Error *e )
{
	ClientCommand *result = new ClientCommand;

	if( xformNo == 0 && cmd->GetInput()->Length() )
	    result->SetInput( cmd->GetInput() );
	if( xformNo == numXforms - 1 && cmd->GetOutput()->Length() )
	    result->SetOutput( cmd->GetOutput() );
	if( GetInput()->Length() && !result->GetInput()->Length() )
	    result->SetInput( GetInput() );
	if( GetOutput()->Length() && !result->GetOutput()->Length() )
	    result->SetOutput( GetOutput() );

	cmd->Transform( actual, vec, numNamedArgs, namedArgs, result, e );

	if( e->Test() )
	{
	    delete result;
	    return;
	}

	resultCommands->Put( result );
}

void
CommandTransformation::CompileRedirection( Error *e )
{
	// Look for patterns of the form:
	//     > $(variable)
	// and
	//     < $(variable)
	//
	// If we find either or both, excise them from the main body of
	// the transform and record them for later use.

	int state = 0;
	                    // States:
	                    // 0: Looking for '<' or '>'
	                    // 1: Looking for '$('
	                    // 2: Looking for ')'
	const char *p;
	const char *pStart; // Location of the < or >
	const char *vStart; // Start of the variable name
	StrBuf buf;
	int redirType = 0;  // 0: none; 1: input; 2: output

	p = text.Text();

	while( p && *p )
	{
	    if( state == 0 )
	    {
	        if( p[0] == '<' || p[0] == '>' )
	        {
	            pStart = p;
	            redirType = p[0] == '<' ? 1 : 2;
	            state = 1;
	        }
	    }
	    else if( state == 1 )
	    {
	        if( p[0] == '$' && p[1] == '(' ) 
	        {
	            vStart = p + 2;
	            state = 2;
	            p++;
	        }
	        else if( p[0] != ' ' )
	        {
	            e->Set( MsgClient::AliasIOSyntax )
	                    << StrRef( p, 1 )
	                    << text;
	            return;
	        }
	    }
	    else if( state == 2 )
	    {
	        if( p[0] == ')' ) 
	        {
	            if( redirType == 1 )
	            {
	                if( inputVariable.Length() > 0 )
	                {
	                    e->Set( MsgClient::AliasInputMultiple ) << text;
	                    return;
	                }
	                inputVariable.Set( vStart, p - vStart );
	            }
	            else
	            {
	                if( outputVariable.Length() > 0 )
	                {
	                    e->Set( MsgClient::AliasOutputMultiple ) << text;
	                    return;
	                }
	                outputVariable.Set( vStart, p - vStart );
	            }

	            buf.Clear();
	            buf << StrRef( text.Text(), pStart - text.Text() )
	                << StrRef( p + 1 );
	            text.Set( buf );
	            redirType = 0;
	            state = 0;
	            p = text.Text();
	            continue;
	        }
	    }
	    p++;
	}
	if( state != 0 )
	{
	    e->Set( MsgClient::AliasRedirection ) << text;
	    return;
	}
	text.TrimBlanks();

}

const StrPtr *
CommandTransformation::GetInput()
{
	return &inputVariable;
}

const StrPtr *
CommandTransformation::GetOutput()
{
	return &outputVariable;
}

/****************************************************************************
 * ClientCommand: a single command, in semi-parsed format, with lots of     *
 * utility functions for manipulating the command.                          *
 ****************************************************************************/

ClientCommand::ClientCommand()
{

	w_argc = 0;
	w_argn = 0;
	w_argf = 0;
	w_argv = 0;
	w_argp = 0;
	w_args = 0;
	w_opts = 0;
	c_args = 0;

	ui = 0;
}

ClientCommand::~ClientCommand()
{
	delete w_opts;
	delete [] w_args;
	delete [] w_argp;
	delete [] c_args;

	delete ui;
}

int
ClientCommand::RunCommand( StrDict *dict, Error *e )
{
	// Time to run this command! First, though, finalize any
	// variable references, first looking for those that may influence
	// the client object itself (-u, -h, -p, etc.), then processing
	// those variables that will be arguments to the server command.

	Client client;
	AliasSubstitution subst( &client, dict );

	for( int ac = 0; ac < w_argf; ac++ )
	{
	    subst.Substitute( &w_args[ac] );
	    w_argp[ac].Set( w_args[ac] );
	}
	w_argc = w_argn;
	ParseOptions( e );
	if( e->Test() )
	    return 1;

	clientSetVariables( client, *w_opts );

	for( int ac = 0; ac < w_argn; ac++ )
	{
	    subst.Substitute( &w_args[ac] );
	    if( ac < w_argf )
	        w_argp[ac].Set( w_args[ac] );
	}

	// Variable substitutions may have left some of the variables
	// with multiple values in the variable, separated by newlines.
	// If this particular command has such values, burst them out
	// into separate arguments now.
	//
	SplitArgs( e );
	if( e->Test() )
	    return 1;

	const StrPtr *aliasHandling = (*w_opts)[ Options::Aliases ];
	if( aliasHandling && 
	    ( *aliasHandling == "dry-run" || *aliasHandling == "echo" ) )
	{
	    StrBuf fmtBuf;
	    FormatCommand( fmtBuf );
	    printf("%s\n", fmtBuf.Text() );
	    if ( *aliasHandling == "dry-run" )
	        return 0;
	}

	// We let clientMain do the heavy lifting here, but we typically
	// provide a custom ClientUser object so that we can control the
	// input and output of the command we run.

	PrepareIO( dict, e );
	if( e->Test() )
	    return 1;

	int uidebug;
	const char *noCommand = "";
	char **argv = (char **)&noCommand;
	if( w_argc > 0 )
	{
	    c_args = new char *[ w_argc ];
	    argv = &c_args[0];
	}

	for( int ac = w_argf; ac < w_argn; ac++ )
	    c_args[ac - w_argf] = w_args[ac].Text();

	if( !HandleSpecialOperators( w_argc, argv, *w_opts, e ) )
	    clientRunCommand( w_argc, argv, *w_opts, ui, uidebug, e );

	HandleOutput( dict, e );

	return ui && ui->CommandFailed();
}

void
ClientCommand::HandleOutput( StrDict *dict, Error *e )
{
	if( ui )
	{
	    if( dict && outputVariable.Length() )
	    {
	        dict->SetVar( outputVariable, *(ui->GetOutput()) );
	    }
	    if( !outputVariable.Length() || ui->CommandFailed() )
	    {
	        const StrPtr *results = ui->GetOutput();
	        if( results && results->Text() )
	            printf( "%s\n", results->Text() );
	    }
	}
}

void
ClientCommand::FormatCommand( StrBuf &b )
{
	b << "p4 ";
	int firstArg = 1;
	for( int ac = 0; ac < w_argn; ac++ )
	{
	    if( w_args[ac] == "--aliases=dry-run" ||
	        w_args[ac] == "--aliases=echo" )
	        continue;

	    if( !firstArg )
	        b << " ";
	    b << w_args[ac];
	    firstArg = 0;
	}

	if( inputVariable.Length() )
	    b << " < $(" << inputVariable << ")";

	if( outputVariable.Length() )
	    b << " > $(" << outputVariable << ")";
}

void
ClientCommand::SplitArgs( Error *e )
{
	int additionsNeeded = 0;

	for( int ac = w_argf; ac < w_argn; ac++ )
	{
	    StrPtrLineReader splr( &w_args[ ac ] );
	    int linesInArg = splr.CountLines();
	    if( linesInArg )
	        additionsNeeded += ( linesInArg - 1 );
	}
	if( additionsNeeded )
	{
	    int n_argn = w_argn + additionsNeeded;
	    StrBuf *n_args = new StrBuf[ (n_argn) ];

	    int dst = 0;

	    for( int ac = 0; ac < w_argf; ac++ )
	        n_args[dst++].Set( w_args[ac] );
	    for( int ac = w_argf; ac < w_argn; ac++ )
	    {
	        StrBuf line;
	        StrPtrLineReader splr( &w_args[ ac ] );
	        while( splr.GetLine( &line ) )
	            n_args[dst++].Set( line );
	    }
	    UpdateWorkingCommand( n_argn, n_args, e );
	}
}

void
ClientCommand::CopyArguments( int cargc, char **argv, Error *e )
{
	w_argc = w_argn = cargc;
	w_args = new StrBuf[ w_argn ];
	w_argp = new StrRef[ w_argn ];

	for( int ac = 0; ac < w_argn; ac++ )
	{
	    w_args[ac].Set( StrRef( argv[ac] ) );
	    w_argp[ac].Set( w_args[ac] );
	}
	
	ParseOptions( e );
}

void
ClientCommand::UpdateWorkingCommand( int n_argn, StrBuf *n_args, Error *e )
{
	w_argc = w_argn = n_argn;

	delete [] w_args;
	delete [] w_argp;

	w_args = n_args;
	w_argp = new StrRef[ w_argn ];

	for( int ac = 0; ac < w_argn; ac++ )
	    w_argp[ac].Set( w_args[ac] );
	
	ParseOptions( e );
}

void
ClientCommand::ParseOptions( Error *e )
{
	w_argv = &w_argp[0];

	delete w_opts;
	w_opts = new Options;

	clientParseOptions( *w_opts, w_argc, w_argv, e );

	if( !w_argc )
	    w_argv = 0;

	w_argf = w_argn - w_argc;
}

void
ClientCommand::Transform(
	int actual,
	char **vec,
	int numNamedArgs,
	StrDict *namedArgs,
	ClientCommand *result,
	Error *e )
{
	// Transformation involves:
	// - the replacement of the function with replacement text+options
	// - the matching of supplied values to named formal args in the alias
	//
	// So we first copy everything from before the function, then we
	// copy the replacement text, then we copy everything from after
	// the function.
	//
	// Note that we don't transform in place. Rather, we build an entirely
	// new result command.

	int n_argn = w_argn + ( actual - 1 ) - numNamedArgs;
	StrBuf *n_args = new StrBuf[ (n_argn) ];

	int dst = 0;

	for( int ac = 0; ac < w_argf; ac++ )
	    n_args[dst++].Set( w_args[ac] );
	for( int ac = 0; ac < actual; ac++ )
	    n_args[dst++].Set( vec[ac] );

	if( numNamedArgs )
	{
	    AliasSubstitution subst( 0, namedArgs );
	    for( int ac = 0; ac < n_argn; ac++ )
	        subst.Substitute( &n_args[ac] );
	}
	else
	{
	    for( int ac = w_argf+1; ac < w_argn; ac++ )
	        n_args[dst++].Set( w_args[ac] );
	}

	result->UpdateWorkingCommand( n_argn, n_args, e );
}

const StrPtr *
ClientCommand::GetInput()
{
	return &inputVariable;
}

const StrPtr *
ClientCommand::GetOutput()
{
	return &outputVariable;
}

void
ClientCommand::SetInput( const StrPtr *in )
{
	inputVariable.Set( in );
}

void
ClientCommand::SetOutput( const StrPtr *out )
{
	outputVariable.Set( out );
}

int
ClientCommand::Matches( CommandPattern *pattern, StrPtr *text )
{
	// If the alias has named formal arguments, then the invocation must
	// exactly match that with the same number of variable values, since
	// we replace the variables by values using their position in the
	// list. But if the alias has no named formal arguments, then the
	// invocation can have any number of arguments, because we'll just
	// glom them on at the end.
	//
	// Either way, the invocation's function name must exactly match
	// the name of this alias.

	if( !FunctionMatches( text ) )
	    return 0;

	int n_args = pattern->Formals();
	if( n_args > 0 && n_args != ( w_argn - w_argf - 1 ) )
	    return 0;

	for( int ac = 0; ac < n_args; ac++ )
	{
	    if( pattern->IsAVariable( ac ) )
	        continue;

	    StrRef var, val;

	    pattern->GetFormal( ac, &var );
	    GetActual( ac, &val );

	    if( var != val.Text() )
	        return 0;
	}
	return 1;
}

int
ClientCommand::FunctionMatches( StrPtr *text )
{
	return ( w_argv != 0 && ( (*text) == (*w_argv) ) );
}

void
ClientCommand::GetActual( int ac, StrRef *val )
{
	if( ac >= 0 && ac < ( w_argn - w_argf - 1 ) )
	    val->Set( w_args[ w_argf + ac + 1 ] );
}

void
ClientCommand::PrepareIO( StrDict *dict, Error *e )
{
	ui = new ClientUserStrBuf( *w_opts );
	ui->SetFormat( (*w_opts)[ 'F' ] );

	if( inputVariable.Length() && dict )
	{
	    ui->SetInputData( dict->GetVar( inputVariable ) );
	    StrPtr *xArg = (*w_opts)[ 'x' ];
	    if( xArg && xArg->Text()[0] == '-' )
	        xArg->Text()[0] = '<';
	}
}

// Returns non-zero if this was a special operator, and was completed, or
// if there is an error. Otherwise, returns 0.
//
int
ClientCommand::HandleSpecialOperators(
	int argc,
	char **argv,
	Options &opts,
	Error *e )
{
	if( argc && !strcmp( argv[0], "p4subst" ) )
	{
	    OperatorP4Subst oper;
	    oper.Substitute( argc, argv, opts, ui, e );
	    return 1;
	}
	return 0;
}

/**************************************************************************
 * AliasSubstitution: manages substituting variables in commands.         *
 **************************************************************************/

AliasSubstitution::AliasSubstitution(
	Client *c,
	StrDict *d )
{
	this->client = c;
	this->dict = d;
}

AliasSubstitution::~AliasSubstitution()
{
}

int
AliasSubstitution::Substitute( StrBuf *b )
{
	// Variable references take the form $(var). When we find one of those
	// in the buffer, we replace it with the variable's value. If we
	// can't find a value, we leave the variable entirely alone, since
	// it may get transformed subsequently by some other pass which knows
	// the correct value for this variable.
	//
	// We return a code summarizing what we did:
	// - 0: this buffer had no variable references, was unchanged
	// - 1: this buffer had at least one var, successfully replaced
	// - 2: this buffer had at least one var, at least one was unknown
	// - 3: this buffer had a malformed reference, it seems.

	int result = 0;
	const char *p = b->Text();
	const char *s = 0;
	StrBuf value;
	StrBuf b2;
	StrBuf var;

	while( p && *p )
	{
	    if( s && ( *p == ')' ) )
	    {
	        // we've found the end of a variable reference.
	        var.Set( StrRef( s + 2, p - s - 2 ) );
	        GetValue( var, &value );
	        if( value.Length() )
	        {
	            b2.Clear();
	            b2 << StrRef( b->Text(), s - b->Text() );
	            b2 << value;
	            b2 << StrRef( p + 1 );
	            b->Set( b2 );
	            p = b->Text();
	        }
	        s = 0;

	        if( !result )
	            result = value.Length() > 0 ? 1 : 2;
	        else if( value.Length() == 0 )
	            result = 2;
	    }
	    else if( !s && ( *p == '$' && *(p+1) == '(' ) )
	    {
	        // we've found the start of a variable reference
	        s = p;
		p += 2;
	    }
	    else
	    {
	        p++;
	    }
	}
	if( s )
	    result = 3;

	return result;
}

void
AliasSubstitution::GetValue( StrPtr &var, StrBuf *val )
{
	val->Clear();

	if( var == "LT" )
	{
	    val->Set( "<" );
	    return;
	}
	if( var == "GT" )
	{
	    val->Set( ">" );
	    return;
	}
	if( var == "EQ" )
	{
	    val->Set( "=" );
	    return;
	}

	if( client )
	{
	    if( var == "P4USER" )
	        val->Set( client->GetUser() );
	    else if( var == "P4CLIENT" )
	        val->Set( client->GetClient() );
	    else if( var == "P4HOST" )
	        val->Set( client->GetHost() );
	    else if( var == "P4LANGUAGE" )
	        val->Set( client->GetLanguage() );
	    else if( var == "CWD" )
	        val->Set( client->GetCwd() );
	    else if( var == "OS" )
	        val->Set( client->GetOs() );
	}
	if( val->Length() > 0 )
	    return;

	if( dict )
	{
	    const StrPtr *s = dict->GetVar( var );
	    if( s )
	        val->Set( s );
	}
}

/*************************************************************************
 * ClientUserStrBuf: custom command line UI subclass of ClientUser which *
 * is able to collect all the output of a command into a StrBuf object   *
 * and can then give that output to a subsequent command for its use.    *
 *************************************************************************/

ClientUserStrBuf::ClientUserStrBuf( Options &opts, int autoLoginPrompt )
	: ClientUserMunge( opts, autoLoginPrompt )
{
	severity = E_EMPTY;
	autoLogin = 0;
}

ClientUserStrBuf::~ClientUserStrBuf()
{
}

void
ClientUserStrBuf::Append( const char *s )
{
	if( output.Length() > 0 )
	    output << "\n";
	output << s;
}

int
ClientUserStrBuf::GetSeverity()
{
	return severity;
}

int
ClientUserStrBuf::CommandFailed()
{
	return GetSeverity() > E_INFO; // Should this be E_WARN?
}

void
ClientUserStrBuf::OutputError( const char *errBuf )
{
	Append( errBuf );
}

void
ClientUserStrBuf::OutputInfo( char level, const char *data )
{
	Append( data );
}

void
ClientUserStrBuf::OutputText( const char *data, int length )
{
	StrRef text( data, length );
	if( length && data[length-1] == '\n' )
	    text.Set( (char *)data, --length );
	if( length && data[length-1] == '\r' )
	    text.Set( (char *)data, --length );

	if( output.Length() > 0 )
	    output << "\n";
	output << text;
}

void
ClientUserStrBuf::HandleError( Error *err )
{
	Message( err );
}

static ErrorId BadPasswordWarn   = { ErrorOf( 7, 21,  E_WARN, 0x24, 0 ), "" };
static ErrorId LoggedOutWarn     = { ErrorOf( 7, 318, E_WARN, 0x04, 0 ), "" };
static ErrorId LoggingUserIn     = { ErrorOf( 7, 859, E_INFO, 0x00, 2 ), "" };
static ErrorId LoginExpiredWarn  = { ErrorOf( 7, 312, E_WARN, 0x04, 0 ), "" };
static ErrorId LoginUser         = { ErrorOf( 7, 325, E_INFO, 0x00, 1 ), "" };
static ErrorId BadPassword0      = { ErrorOf( 7, 38,  E_FAILED, 0x04, 0 ), ""};
static ErrorId PasswordExpired   = { ErrorOf( 7, 455, E_FAILED, 0x04, 0 ), ""};

void
ClientUserStrBuf::Message( Error *err )
{
	// FIXME -- probably need to think about:
	//
	// if( err->IsInfo() )
	//     ...
	// else
	//     ...

	// Special case for autoLogin messages (print them)
	// Same for authentication errors (warnings = autoLogin retrt atempt)
	if( err->CheckId( LoggingUserIn ) ||
	    ( autoLogin && err->CheckId( LoginUser ) ) ||
	    err->CheckId( BadPasswordWarn ) ||
	    err->CheckId( LoggedOutWarn ) ||
	    err->CheckId( LoginExpiredWarn ) ||
	    err->CheckId( BadPassword0 )||
	    err->CheckId( PasswordExpired ) )
	{
	    if( err->IsWarning() || err->CheckId( LoggingUserIn ) )
	        autoLogin = 1;
	    else if( autoLogin && err->CheckId( LoginUser ) )
	        autoLogin = 0;
	    else if( err->IsError() )
	    {
	        severity = E_FAILED;
	        autoLogin = 0;
	    }

	    ClientUser cu;
	    cu.Message( err );
	    return;
	}

	if( err->GetSeverity() > severity )
	    severity = err->GetSeverity();

	if( format.Length() )
	{
	    OutputStat( err->GetDict() );
	}
	else
	{
	    StrBuf msg;
	    err->Fmt( msg, EF_PLAIN );
	    OutputInfo( 0, msg.Text() );
	}
}

void
ClientUserStrBuf::OutputStat( StrDict *dict )
{
	if( !format.Length() && dict )
	{
	    if( dict->GetVar( "specdef" ) )
	        ClientUserMunge::OutputStat( dict );
	    else
	        ClientUser::OutputStat( dict );
	    return;
	}

	if( !dict )
	    return;

	StrBuf out;
	StrOps::Expand2( out, format, *dict );

	Append( out.Text() );
}

const StrPtr *
ClientUserStrBuf::GetOutput()
{
	return &output;
}

void
ClientUserStrBuf::SetFormat( const StrPtr *fmt )
{
	if( fmt )
	    format.Set( fmt );
}

void
ClientUserStrBuf::SetInputData( const StrPtr *data )
{
	if( data )
	    input.Set( data );
}

void
ClientUserStrBuf::InputData( StrBuf *b, Error *e )
{
	if( input.Length() )
	    b->Set( input );
	else
	    ClientUserMunge::InputData( b, e );
}

/***************************************************************************
 * OperatorP4Subst: allows simple string substitutions in aliases          *
 ***************************************************************************/

OperatorP4Subst::OperatorP4Subst()
{
	splr = 0;
}

OperatorP4Subst::~OperatorP4Subst()
{
	delete splr;
}

void
OperatorP4Subst::Substitute(
	int argc,
	char **argv,
	Options &opts,
	ClientUser *ui,
	Error *e )
{
	StrBuf line, result;

	ui->InputData( &rawData, e );
	if( e->Test() )
	    return;
	splr = new StrPtrLineReader( &rawData );

	RegMatch matcher( RegMatch::grep );
	matcher.compile( argv[1], e );
	if( e->Test() )
	    return;

	int ln = 1, lnCount = splr->CountLines();

	while( splr->GetLine( &line ) )
	{
	    if( matcher.matches( line.Text(), e ) )
	        UpdateLine( &line, &result, &matcher, argv[2] );
	    else
	        result.Set( line );
	    
	    if( ln++ < lnCount )
	        result << "\n";

	    ui->OutputInfo( 0, result.Text() );
	}
}

void
OperatorP4Subst::UpdateLine(
	StrBuf *line,
	StrBuf *result,
	RegMatch *matcher,
	const char *replace )
{
	result->Clear();
	(*result) << StrRef( line->Text(), matcher->begin() );
	(*result) << replace;
	if( matcher->end() < line->Length() )
	    (*result) << line->Text() + matcher->end();
}
