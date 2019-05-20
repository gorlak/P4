/*
 * Copyright 1995, 2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * msgclient.cc - definitions of errors for client subsystem.
 *
 * Note:
 *
 * Never re-use an error code value,  these may have already been 
 * translated and while deleting the error is OKAY using it for a 
 * different error is not.
 *
 * Its okay to add a message in the middle of the file.
 *
 * When adding a new error make sure its greater than the current high
 * value and update the following number:
 *
 * Current high value for a MsgClient error code is: 89
 */

# include <error.h>
# include <errornum.h>
# include "msgclient.h"

ErrorId MsgClient::Connect             = { ErrorOf( ES_CLIENT, 1, E_FAILED, EV_COMM, 0 ), "Connect to server failed; check $P4PORT." } ;
ErrorId MsgClient::Fatal               = { ErrorOf( ES_CLIENT, 2, E_FATAL, EV_CLIENT, 0 ), "Fatal client error; disconnecting!" } ;
ErrorId MsgClient::BadFlag             = { ErrorOf( ES_CLIENT, 3, E_FAILED, EV_USAGE, 0 ), "Unknown flag.  Try ? for help." } ;
ErrorId MsgClient::ClobberFile         = { ErrorOf( ES_CLIENT, 4, E_FAILED, EV_CLIENT, 1 ), "Can't clobber writable file %file%" } ;
ErrorId MsgClient::MkDir               = { ErrorOf( ES_CLIENT, 5, E_FAILED, EV_CLIENT, 1 ), "can't create directory for %file%" } ;
ErrorId MsgClient::Eof                 = { ErrorOf( ES_CLIENT, 6, E_FAILED, EV_CLIENT, 0 ), "EOF reading terminal." } ;
ErrorId MsgClient::FileOpenError       = { ErrorOf( ES_CLIENT, 40, E_FAILED, EV_CLIENT, 0 ), "Error opening file." } ;
ErrorId MsgClient::CantEdit            = { ErrorOf( ES_CLIENT, 7, E_FAILED, EV_CLIENT, 1 ), "%type% - can't edit this type of file!" } ;
ErrorId MsgClient::NoMerger            = { ErrorOf( ES_CLIENT, 8, E_FAILED, EV_CLIENT, 0 ), "No merge program specified with $P4MERGE or $MERGE." } ;
ErrorId MsgClient::CheckFileBadPath    = { ErrorOf( ES_CLIENT, 9, E_INFO, EV_CLIENT, 2 ), "%file% - symlink at '%dir%', file can't be added." };
ErrorId MsgClient::ToolServer2         = { ErrorOf( ES_CLIENT, 10, E_FAILED, EV_CLIENT, 0 ), "Could not start another ToolServer.  Tool is running under ToolServer." } ;
ErrorId MsgClient::ToolServer          = { ErrorOf( ES_CLIENT, 11, E_FAILED, EV_CLIENT, 0 ), "Could not start ToolServer." } ;
ErrorId MsgClient::ToolCmdCreate       = { ErrorOf( ES_CLIENT, 12, E_FAILED, EV_CLIENT, 0 ), "Could not create command to send to ToolServer." } ;
ErrorId MsgClient::ToolCmdSend         = { ErrorOf( ES_CLIENT, 13, E_FAILED, EV_CLIENT, 0 ), "Could not send command to ToolServer." } ;
ErrorId MsgClient::Memory              = { ErrorOf( ES_CLIENT, 14, E_FATAL, EV_CLIENT, 0 ), "Out of memory!" } ;
ErrorId MsgClient::CantFindApp         = { ErrorOf( ES_CLIENT, 15, E_FATAL, EV_CLIENT, 0 ), "Could not find application!" } ;
ErrorId MsgClient::BadSignature        = { ErrorOf( ES_CLIENT, 16, E_FATAL, EV_CLIENT, 0 ), "EDITOR_SIGNATURE must be 4 characters exactly!" } ;
ErrorId MsgClient::BadMarshalInput     = { ErrorOf( ES_CLIENT, 29, E_FAILED, EV_CLIENT, 0 ), "Invalid marshalled data supplied as input." } ;
ErrorId MsgClient::ResolveManually     = { ErrorOf( ES_CLIENT, 18, E_INFO, EV_CLIENT, 0 ), "Must resolve manually." } ;
ErrorId MsgClient::NonTextFileMerge    = { ErrorOf( ES_CLIENT, 19, E_INFO, EV_CLIENT, 0 ), "Non-text file merge." } ;
ErrorId MsgClient::MergeMsg2           = { ErrorOf( ES_CLIENT, 28, E_INFO, EV_CLIENT, 4 ), "Non-text diff: %yours% yours + %theirs% theirs + %both% both + %conflicting% conflicting" } ;
ErrorId MsgClient::MergeMsg3           = { ErrorOf( ES_CLIENT, 20, E_INFO, EV_CLIENT, 4 ), "Diff chunks: %yours% yours + %theirs% theirs + %both% both + %conflicting% conflicting" } ;
ErrorId MsgClient::MergeMsg32          = { ErrorOf( ES_CLIENT, 21, E_INFO, EV_CLIENT, 1 ), "Diff chunks: %chunks% between yours and theirs (no common base)" } ;
ErrorId MsgClient::MergePrompt         = { ErrorOf( ES_CLIENT, 22, E_INFO, EV_CLIENT, 1 ), "Accept(a) Edit(e) Diff(d) Merge (m) Skip(s) Help(?) [%mergeDefault%]: " };
ErrorId MsgClient::MergePrompt2        = { ErrorOf( ES_CLIENT, 26, E_INFO, EV_CLIENT, 1 ), "Accept (at/ay) Skip (s) Help (?) [%mergeDefault%]: " };
ErrorId MsgClient::MergePrompt2Edit    = { ErrorOf( ES_CLIENT, 27, E_INFO, EV_CLIENT, 1 ), "Accept (at/ay) Edit (et/ey) Skip (s) Help (?) [%mergeDefault%]: " };
ErrorId MsgClient::ConfirmMarkers      = { ErrorOf( ES_CLIENT, 23, E_INFO, EV_CLIENT, 0 ), "There are still change markers: confirm accept (y/n)? " };
ErrorId MsgClient::ConfirmEdit         = { ErrorOf( ES_CLIENT, 24, E_INFO, EV_CLIENT, 0 ), "Use 'ae' to indicate original edits: confirm accept merge (y/n)? " };
ErrorId MsgClient::Confirm             = { ErrorOf( ES_CLIENT, 25, E_INFO, EV_CLIENT, 0 ), "This overrides your changes: confirm accept (y/n)? " };
ErrorId MsgClient::CheckFileAssume     = { ErrorOf( ES_CLIENT, 30, E_INFO, EV_CLIENT, 3 ), "%file% - %type%, assuming %type2%." };
ErrorId MsgClient::CheckFileAssumeWild = { ErrorOf( ES_CLIENT, 41, E_INFO, EV_CLIENT, 4 ), "%file% - %type%, assuming %type2% (%modified%)." };
ErrorId MsgClient::CheckFileSubst      = { ErrorOf( ES_CLIENT, 31, E_INFO, EV_CLIENT, 3 ), "%file% - using %type% instead of %type2%" };
ErrorId MsgClient::CheckFileCant       = { ErrorOf( ES_CLIENT, 32, E_INFO, EV_CLIENT, 2 ), "%file% - %type% file can't be added." };
ErrorId MsgClient::FileExists          = { ErrorOf( ES_CLIENT, 34, E_FAILED, EV_CLIENT, 1 ), "%file% - can't overwrite existing file." };
ErrorId MsgClient::NoSuchFile          = { ErrorOf( ES_CLIENT, 35, E_FAILED, EV_CLIENT, 1 ), "%file% - file does not exist." };
ErrorId MsgClient::LoginPrintTicket    = { ErrorOf( ES_CLIENT, 36, E_INFO, EV_NONE, 1 ), "%ticket%" } ;
ErrorId MsgClient::DigestMisMatch      = { ErrorOf( ES_CLIENT, 37, E_FAILED, EV_CLIENT, 3 ), "%clientFile% corrupted during transfer (or bad on the server) %clientDigest% vs %serverDigest%" } ;
ErrorId MsgClient::NotUnderPath        = { ErrorOf( ES_CLIENT, 38, E_FAILED, EV_CLIENT, 2 ), "File %clientFile% is not inside permitted filesystem path %clientPath%" } ;
ErrorId MsgClient::LineTooLong         = { ErrorOf( ES_CLIENT, 39, E_FAILED, EV_CLIENT, 1 ), "Command line too long. Maximum length is %maxLineLen%. This length can be increased by setting filesys.bufsize in P4CONFIG or using -v." };
ErrorId MsgClient::UnknownCharset      = { ErrorOf( ES_CLIENT, 42, E_FATAL, EV_CLIENT, 1 ), "Unknown P4CHARSET %charset%." };
ErrorId MsgClient::FileKept            = { ErrorOf( ES_CLIENT, 43, E_FAILED, EV_CLIENT, 1 ), "Edited File %file% kept due to errors." } ;

ErrorId MsgClient::LockCheckFail       = { ErrorOf( ES_CLIENT, 44, E_FAILED, EV_CLIENT, 0 ), "File locking check failed, Perforce server can not run." } ;
ErrorId MsgClient::ChdirFail           = { ErrorOf( ES_CLIENT, 45, E_FAILED, EV_CLIENT, 1), "Failed to change to direcitory '%dir%'." };

ErrorId MsgClient::InitRootExists      = { ErrorOf( ES_CLIENT, 46, E_FAILED, EV_CLIENT, 1 ), "Nothing to do - existing dvcs tree at %dir%" };
ErrorId MsgClient::NoDvcsServer        = { ErrorOf( ES_CLIENT, 47, E_FAILED, EV_CLIENT, 0 ), "No server root found" };

ErrorId MsgClient::InitServerFail      = { ErrorOf( ES_CLIENT, 48, E_FAILED, EV_CLIENT, 0), "\np4d server failed to initialize.  A 2015.1 or later p4d server\nmust be in your path and runable." };
ErrorId MsgClient::CloneCantFetch      = { ErrorOf( ES_CLIENT, 49, E_FAILED, EV_CLIENT, 1 ), "Remote server '%port%' not configured to clone (server.allowfetch)." };
ErrorId MsgClient::NotValidStreamName  = { ErrorOf( ES_CLIENT, 50, E_FAILED, EV_CLIENT, 1 ), "'%path%' is not a valid mainline stream name." };
ErrorId MsgClient::CloneStart          = { ErrorOf( ES_CLIENT, 51, E_INFO,   EV_CLIENT, 1 ), "Cloning from '%port%'..." };
ErrorId MsgClient::CloneNeedLogin1     = { ErrorOf( ES_CLIENT, 52, E_FAILED, EV_CLIENT, 2 ), "'%user%' is not currently logged in to '%port%'" };
ErrorId MsgClient::CloneNeedLogin2     = { ErrorOf( ES_CLIENT, 53, E_FAILED, EV_CLIENT, 2 ), "run 'p4 -u %user% -p %port% login' to authenticate" };
ErrorId MsgClient::CloneTooWide        = { ErrorOf( ES_CLIENT, 54, E_FAILED, EV_CLIENT, 1 ), "Remote map entry '%path%' cannot be allocated a stream name:\nClone requires at least //<depotname>/<streamname>/ on the left hand side of the map\n" };
ErrorId MsgClient::CloneRemoteInvalid  = { ErrorOf( ES_CLIENT, 55, E_FAILED, EV_CLIENT, 0 ), "Remote clone spec invalid!" };
ErrorId MsgClient::CloneTooManyDepots  = { ErrorOf( ES_CLIENT, 56, E_FAILED, EV_CLIENT, 1 ), "Remote spec references multiple depots on the left hand side of map : %depots%" };
ErrorId MsgClient::CloneNoRemote       = { ErrorOf( ES_CLIENT, 57, E_FAILED, EV_CLIENT, 2 ), "Remote server '%port%' does not have a remote spec '%remote%'" };
ErrorId MsgClient::ClonePathNoMap      = { ErrorOf( ES_CLIENT, 58, E_FAILED, EV_CLIENT, 1 ), "Filepath '%path%' cannot be mapped" };
ErrorId MsgClient::ClonePathTooWide    = { ErrorOf( ES_CLIENT, 59, E_FAILED, EV_CLIENT, 1 ), "Filepath '%path%' is too wide open" };
ErrorId MsgClient::ClonePathHasWild    = { ErrorOf( ES_CLIENT, 60, E_FAILED, EV_CLIENT, 1 ), "Filepath '%path%' contains embedded wildcard" };
ErrorId MsgClient::ClonePathHasIllegal = { ErrorOf( ES_CLIENT, 61, E_FAILED, EV_CLIENT, 1 ), "Filepath '%path%' contains illegal characters [@%#*]" };
ErrorId MsgClient::RemoteAlreadySet    = { ErrorOf( ES_CLIENT, 62, E_FAILED, EV_CLIENT, 1 ), "Remote '%remote%' is already cached" };
ErrorId MsgClient::NoRemoteToSet       = { ErrorOf( ES_CLIENT, 63, E_FAILED, EV_CLIENT, 0 ), "No remote in cache" };
ErrorId MsgClient::InitCaseFlagUnset   = { ErrorOf( ES_CLIENT, 64, E_FAILED, EV_CLIENT, 0 ), "CaseFlag must be set to -C0 or -C1" };
ErrorId MsgClient::InitUnicodeUnset    = { ErrorOf( ES_CLIENT, 65, E_FAILED, EV_CLIENT, 0 ), "Unicode must be set to 0 or 1" };
ErrorId MsgClient::CloneFetchCounts    = { ErrorOf( ES_CLIENT, 66, E_INFO,   EV_CLIENT, 2 ), "%changes% change(s) containing a total of %revs% file revision(s) were successfully fetched." };
ErrorId MsgClient::LocalRemoteMismatch = { ErrorOf( ES_CLIENT, 67, E_FAILED, EV_CLIENT, 0 ), "ServerHelperApi already refers to a local Perforce Server." };
ErrorId MsgClient::RemoteLocalMismatch = { ErrorOf( ES_CLIENT, 68, E_FAILED, EV_CLIENT, 0 ), "ServerHelperApi already refers to a remote Perforce Server." };

ErrorId MsgClient::AliasTooManyEquals  = { ErrorOf( ES_CLIENT, 69, E_FAILED, EV_USAGE, 1 ), "Alias syntax error: extra equals sign in '%alias%'" };
ErrorId MsgClient::AliasMissingEquals  = { ErrorOf( ES_CLIENT, 70, E_FAILED, EV_USAGE, 1 ), "Alias syntax error: missing equals sign in '%alias%'" };
ErrorId MsgClient::AliasTooComplex     = { ErrorOf( ES_CLIENT, 71, E_FAILED, EV_USAGE, 1 ), "Alias definition '%alias%' exceeds the complexity limit of %limit%." };
ErrorId MsgClient::AliasMissingCommand = { ErrorOf( ES_CLIENT, 72, E_FAILED, EV_USAGE, 1 ), "Alias definition '%alias%' does not contain the command to run." };
ErrorId MsgClient::AliasArgSyntax      = { ErrorOf( ES_CLIENT, 73, E_FAILED, EV_USAGE, 2 ), "Alias syntax error: '%arg%' not understood in '%alias%'." };
ErrorId MsgClient::AliasIOSyntax       = { ErrorOf( ES_CLIENT, 74, E_FAILED, EV_USAGE, 2 ), "Alias syntax error: unexpected character '%redirChar%' found in alias '%alias%'." };
ErrorId MsgClient::AliasInputMultiple  = { ErrorOf( ES_CLIENT, 75, E_FAILED, EV_USAGE, 1 ), "Alias syntax error: multiple input redirections were found in alias '%alias%'." };
ErrorId MsgClient::AliasOutputMultiple = { ErrorOf( ES_CLIENT, 76, E_FAILED, EV_USAGE, 1 ), "Alias syntax error: multiple output redirections were found in alias '%alias%'." };
ErrorId MsgClient::AliasRedirection    = { ErrorOf( ES_CLIENT, 77, E_FAILED, EV_USAGE, 1 ), "Alias syntax error: unrecognized redirection syntax in alias '%alias%'." };
ErrorId MsgClient::NoAliasesFound      = { ErrorOf( ES_CLIENT, 78, E_INFO, EV_CLIENT, 0 ), "You have no aliases defined." };
ErrorId MsgClient::AliasNoTransform    = { ErrorOf( ES_CLIENT, 79, E_FAILED, EV_USAGE, 1 ), "Alias syntax error: no transformation found in '%alias%'." };
ErrorId MsgClient::AliasEmptyTransform = { ErrorOf( ES_CLIENT, 80, E_FAILED, EV_USAGE, 0 ), "Alias syntax error: empty transformation not allowed." };
ErrorId MsgClient::AliasPartial        = { ErrorOf( ES_CLIENT, 81, E_FAILED, EV_USAGE, 0 ), "Alias syntax error: alias definition incomplete." };
ErrorId MsgClient::AliasSubstArgs      = { ErrorOf( ES_CLIENT, 82, E_FAILED, EV_USAGE, 0 ), "Alias syntax error: p4subst should have exactly two arguments." };
ErrorId MsgClient::AliasSubstInput     = { ErrorOf( ES_CLIENT, 83, E_FAILED, EV_USAGE, 0 ), "Alias syntax error: p4subst input should be redirected." };
ErrorId MsgClient::AliasSubstOutput    = { ErrorOf( ES_CLIENT, 84, E_FAILED, EV_USAGE, 0 ), "Alias syntax error: p4subst output should be redirected" };
ErrorId MsgClient::AliasSyntaxError    = { ErrorOf( ES_CLIENT, 85, E_FAILED, EV_USAGE, 1 ), "Alias syntax error: '%alias%' not understood." };
ErrorId MsgClient::CommandNotAliased   = { ErrorOf( ES_CLIENT, 86, E_FAILED, EV_USAGE, 1 ), "There is no alias which applies to '%cmd%'." };
ErrorId MsgClient::AliasEmptyPattern   = { ErrorOf( ES_CLIENT, 87, E_FAILED, EV_USAGE, 1 ), "Alias syntax error: no pattern found in '%alias%'" };
ErrorId MsgClient::NoModifiedFile      = { ErrorOf( ES_CLIENT, 88, E_FAILED, EV_CLIENT, 2 ), "Can't %action% modified file %file%" };
ErrorId MsgClient::DevErr              = { ErrorOf( ES_CLIENT, 89, E_FATAL, EV_CLIENT, 1 ), "Programming error:  %err%" };

// ErrorId graveyard: retired/deprecated ErrorIds.

ErrorId MsgClient::ZCResolve           = { ErrorOf( ES_CLIENT, 33, E_FAILED, EV_COMM, 2 ), "Zeroconf resolved '%name%' to '%port%'." } ; // DEPRECATED 2013.1 removed ZeroConf
