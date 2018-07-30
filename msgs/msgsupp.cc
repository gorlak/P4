/*
 * Copyright 1995, 2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * msgsupp - definitions of errors for zlib C++ interface
 *
 * Note:
 *
 * Never re-use an error code value,  these may have already been 
 * translated, so using it for a different error is not OK.
 *
 * ErrorIds which are no longer used should be moved to the bottom
 * of the list, with a trailing comment like this: // DEPRECATED.
 * We keep these to maintain compatibility between newer api clients
 * and older servers which send old ErrorIds.
 *
 * Its okay to add a message in the middle of the file.
 *
 * When adding a new error make sure its greater than the current high
 * value and update the following number:
 *
 * Current high value for a MsgSupp error code is: 324
 */

# include <error.h>
# include <errornum.h>
# include <msgsupp.h>

ErrorId MsgSupp::NoTransVar            = { ErrorOf( ES_SUPP, 1, E_WARN, EV_ILLEGAL, 2 ), "No Translation for parameter '%arg%' value '%value%'!" } ;

ErrorId MsgSupp::InvalidDate           = { ErrorOf( ES_SUPP, 2, E_FAILED, EV_USAGE, 1 ), "Invalid date '%date%'." } ;
ErrorId MsgSupp::InvalidCharset        = { ErrorOf( ES_SUPP, 244, E_FAILED, EV_USAGE, 1 ), "Invalid charset '%charset%'." } ;

ErrorId MsgSupp::TooMany               = { ErrorOf( ES_SUPP, 3, E_FATAL, EV_FAULT, 0 ), "Too many options on command!" } ;
ErrorId MsgSupp::Invalid               = { ErrorOf( ES_SUPP, 4, E_FAILED, EV_USAGE, 1 ), "Invalid option: -%option%." } ;
ErrorId MsgSupp::NeedsArg              = { ErrorOf( ES_SUPP, 5, E_FAILED, EV_USAGE, 1 ), "Option: -%option% needs argument." } ;
ErrorId MsgSupp::NeedsNonNegArg        = { ErrorOf( ES_SUPP, 33, E_FAILED, EV_USAGE, 1 ), "Option: -%option% needs a non-negative integer argument." } ;
ErrorId MsgSupp::Needs2Arg              = { ErrorOf( ES_SUPP, 23, E_FAILED, EV_USAGE, 1 ), "Option: -%option% needs a flag and an argument." } ;
ErrorId MsgSupp::ExtraArg              = { ErrorOf( ES_SUPP, 6, E_FAILED, EV_USAGE, 0 ), "Unexpected arguments." } ;
ErrorId MsgSupp::WrongArg              = { ErrorOf( ES_SUPP, 7, E_FAILED, EV_USAGE, 0 ), "Missing/wrong number of arguments." } ;
ErrorId MsgSupp::Usage                 = { ErrorOf( ES_SUPP, 8, E_FAILED, EV_USAGE, 1 ), "Usage: %text%" } ;
ErrorId MsgSupp::OptionData            = { ErrorOf( ES_SUPP, 31, E_INFO, EV_NONE, 3 ), "-%flag%%flag2%='%value%'" } ;

ErrorId MsgSupp::NoParm                = { ErrorOf( ES_SUPP, 9, E_FATAL, EV_FAULT, 1 ), "Required parameter '%arg%' not set!" } ; //NOTRANS

ErrorId MsgSupp::NoUnixReg             = { ErrorOf( ES_SUPP, 10, E_WARN, EV_NONE, 0 ), "Can't set registry on UNIX." } ;
ErrorId MsgSupp::NoSuchVariable        = { ErrorOf( ES_SUPP, 34, E_WARN, EV_NONE, 1 ), "Unrecognized variable name %varName%. Comment lines should contain '#' in column 1." } ;
ErrorId MsgSupp::HidesVar              = { ErrorOf( ES_SUPP, 11, E_WARN, EV_NONE, 1 ), "Warning: environment variable hides registry definition of %name%." } ;
ErrorId MsgSupp::NoP4Config            = { ErrorOf( ES_SUPP, 12, E_WARN, EV_NONE, 0 ), "Can't save in config if %'P4CONFIG'% not set." } ;
ErrorId MsgSupp::VariableData          = { ErrorOf( ES_SUPP, 32, E_INFO, EV_NONE, 3 ), "%name%=%value% %source%" } ;

ErrorId MsgSupp::PartialChar           = { ErrorOf( ES_SUPP, 13, E_INFO, EV_ILLEGAL, 0 ), "Partial character in translation" } ;
ErrorId MsgSupp::NoTrans               = { ErrorOf( ES_SUPP, 14, E_WARN, EV_ILLEGAL, 2 ), "Translation of file content failed near line %arg%[ file %name%]" } ;
ErrorId MsgSupp::ConvertFailed         = { ErrorOf( ES_SUPP, 36, E_WARN, EV_ILLEGAL, 3 ), "Translation of %path% from %charset1% to %charset2% failed -- correct before proceeding." } ;

ErrorId MsgSupp::BadMangleParams       = { ErrorOf( ES_SUPP, 22, E_FATAL, EV_FAULT, 0 ), "Bad parameters passed to mangler!"} ; //NOTRANS

ErrorId MsgSupp::BadOS                 = { ErrorOf( ES_SUPP, 15, E_FATAL, EV_FAULT, 1 ), "Don't know how to translate paths for OS '%arg%'!" } ; //NOTRANS

ErrorId MsgSupp::Deflate               = { ErrorOf( ES_SUPP, 16, E_FATAL, EV_FAULT, 0 ), "Deflate failed!" } ; //NOTRANS
ErrorId MsgSupp::DeflateEnd            = { ErrorOf( ES_SUPP, 17, E_FATAL, EV_FAULT, 0 ), "DeflateEnd failed!" } ; //NOTRANS
ErrorId MsgSupp::DeflateInit           = { ErrorOf( ES_SUPP, 18, E_FATAL, EV_FAULT, 0 ), "DeflateInit failed!" } ; //NOTRANS
ErrorId MsgSupp::Inflate               = { ErrorOf( ES_SUPP, 19, E_FATAL, EV_FAULT, 0 ), "Inflate failed!" } ; //NOTRANS
ErrorId MsgSupp::InflateInit           = { ErrorOf( ES_SUPP, 20, E_FATAL, EV_FAULT, 0 ), "InflateInit failed!" } ; //NOTRANS
ErrorId MsgSupp::MagicHeader           = { ErrorOf( ES_SUPP, 21, E_FATAL, EV_FAULT, 0 ), "Gzip magic header wrong!" } ; //NOTRANS

ErrorId MsgSupp::RegexError            = { ErrorOf( ES_SUPP, 30, E_FAILED, EV_USAGE, 1 ), "Regular expression error: %text%" } ;

ErrorId MsgSupp::UnknownTunable        = { ErrorOf( ES_SUPP, 319, E_FAILED, EV_USAGE, 1 ), "Unknown configurable: %conf%" } ;
ErrorId MsgSupp::TunableValueTooLow    = { ErrorOf( ES_SUPP, 320, E_FAILED, EV_USAGE, 2 ), "Configurable '%config%' cannot be set to a value less than '%minVal%'." } ;
ErrorId MsgSupp::TunableValueTooHigh   = { ErrorOf( ES_SUPP, 321, E_FAILED, EV_USAGE, 2 ), "Configurable '%config%' cannot be set to a value greater than '%maxVal%'." } ;

ErrorId MsgSupp::OptionChange          = { ErrorOf( ES_SUPP, 37, E_INFO, EV_NONE, 0 ), "%'--change (-c)'%: specifies the changelist to use for the command." } ;
ErrorId MsgSupp::OptionPort            = { ErrorOf( ES_SUPP, 38, E_INFO, EV_NONE, 0 ), "%'--port (-p)'%: specifies the network address of the server." } ;
ErrorId MsgSupp::OptionUser            = { ErrorOf( ES_SUPP, 39, E_INFO, EV_NONE, 0 ), "%'--user (-u)'%: specifies the user name." } ;
ErrorId MsgSupp::OptionClient          = { ErrorOf( ES_SUPP, 40, E_INFO, EV_NONE, 0 ), "%'--client (-c)'%: specifies the client workspace name." } ;
ErrorId MsgSupp::OptionPreview         = { ErrorOf( ES_SUPP, 41, E_INFO, EV_NONE, 0 ), "%'--preview (-n)'%: specifies that the command should display a preview of the results, but not execute them." } ;
ErrorId MsgSupp::OptionDelete          = { ErrorOf( ES_SUPP, 42, E_INFO, EV_NONE, 0 ), "%'--delete (-d)'%: specifies that the object should be deleted." } ;
ErrorId MsgSupp::OptionForce           = { ErrorOf( ES_SUPP, 43, E_INFO, EV_NONE, 0 ), "%'--force (-f)'%: overrides the normal safety checks." } ;
ErrorId MsgSupp::OptionInput           = { ErrorOf( ES_SUPP, 44, E_INFO, EV_NONE, 0 ), "%'--input (-i)'%: specifies that the data should be read from standard input." } ;
ErrorId MsgSupp::OptionOutput          = { ErrorOf( ES_SUPP, 45, E_INFO, EV_NONE, 0 ), "%'--output (-o)'%: specifies that the data should be written to standard output." } ;
ErrorId MsgSupp::OptionMax             = { ErrorOf( ES_SUPP, 46, E_INFO, EV_NONE, 0 ), "%'--max (-m)'%: specifies the maximum number of objects." } ;
ErrorId MsgSupp::OptionQuiet           = { ErrorOf( ES_SUPP, 47, E_INFO, EV_NONE, 0 ), "%'--quiet (-q)'%: suppresses normal information output." } ;
ErrorId MsgSupp::OptionShort           = { ErrorOf( ES_SUPP, 48, E_INFO, EV_NONE, 0 ), "%'--short (-s)'%: displays a brief version of the results." } ;
ErrorId MsgSupp::OptionLong            = { ErrorOf( ES_SUPP, 49, E_INFO, EV_NONE, 0 ), "%'--long (-l)'%: displays a complete version of the results." } ;
ErrorId MsgSupp::OptionAll             = { ErrorOf( ES_SUPP, 50, E_INFO, EV_NONE, 0 ), "%'--all (-a)'%: specifies that the command should include all objects." } ;
ErrorId MsgSupp::OptionFiletype        = { ErrorOf( ES_SUPP, 51, E_INFO, EV_NONE, 0 ), "%'--filetype (-t)'%: specifies the filetype to be used." } ;
ErrorId MsgSupp::OptionStream          = { ErrorOf( ES_SUPP, 52, E_INFO, EV_NONE, 0 ), "%'--stream (-S)'%: specifies the stream to be used." } ;
ErrorId MsgSupp::OptionParent          = { ErrorOf( ES_SUPP, 53, E_INFO, EV_NONE, 0 ), "%'--parent (-P)'%: specifies the stream to be used as the parent." } ;
ErrorId MsgSupp::OptionClientName      = { ErrorOf( ES_SUPP, 54, E_INFO, EV_NONE, 0 ), "%'--client (-C)'%: specifies the client workspace name." } ;
ErrorId MsgSupp::OptionHost            = { ErrorOf( ES_SUPP, 55, E_INFO, EV_NONE, 0 ), "%'--host (-H)'%: specifies the host name, overriding the value from the network configuration." } ;
ErrorId MsgSupp::OptionPassword        = { ErrorOf( ES_SUPP, 56, E_INFO, EV_NONE, 0 ), "%'--password (-P)'%: specifies the password to be used." } ;
ErrorId MsgSupp::OptionCharset         = { ErrorOf( ES_SUPP, 57, E_INFO, EV_NONE, 0 ), "%'--charset (-C)'%: specifies the client's character set." } ;
ErrorId MsgSupp::OptionCmdCharset      = { ErrorOf( ES_SUPP, 58, E_INFO, EV_NONE, 0 ), "%'--cmd-charset (-Q)'%: specifies the client's command character set." } ;
ErrorId MsgSupp::OptionVariable        = { ErrorOf( ES_SUPP, 59, E_INFO, EV_NONE, 0 ), "%'--variable (-v)'%: specifies the value of a configurable variable." } ;
ErrorId MsgSupp::OptionHelp            = { ErrorOf( ES_SUPP, 60, E_INFO, EV_NONE, 0 ), "%'--help (-h)'%: provides help." } ;
ErrorId MsgSupp::OptionVersion         = { ErrorOf( ES_SUPP, 61, E_INFO, EV_NONE, 0 ), "%'--version (-V)'%: displays version information." } ;
ErrorId MsgSupp::OptionBatchsize       = { ErrorOf( ES_SUPP, 62, E_INFO, EV_NONE, 0 ), "%'--batchsize (-b)'%: specifies the number of objects in a single batch." } ;
ErrorId MsgSupp::OptionMessageType     = { ErrorOf( ES_SUPP, 63, E_INFO, EV_NONE, 0 ), "%'--message-type (-s)'%: includes message type information in the output." } ;
ErrorId MsgSupp::OptionXargs           = { ErrorOf( ES_SUPP, 64, E_INFO, EV_NONE, 0 ), "%'--xargs (-x)'%: reads input arguments from the specified file." } ;
ErrorId MsgSupp::OptionExclusive       = { ErrorOf( ES_SUPP, 65, E_INFO, EV_NONE, 0 ), "%'--exclusive (-x)'%: indicates that the command should process files of type +l." } ;
ErrorId MsgSupp::OptionProgress        = { ErrorOf( ES_SUPP, 66, E_INFO, EV_NONE, 0 ), "%'--progress (-I)'%: indicates that the command should display progress information." } ;
ErrorId MsgSupp::OptionDowngrade       = { ErrorOf( ES_SUPP, 67, E_INFO, EV_NONE, 0 ), "%'--downgrade (-d)'%: indicates that the operation should be downgraded." } ;
ErrorId MsgSupp::OptionDirectory       = { ErrorOf( ES_SUPP, 68, E_INFO, EV_NONE, 0 ), "%'--directory (-d)'%: specifies the directory to be used as the current directory." } ;
ErrorId MsgSupp::OptionRetries         = { ErrorOf( ES_SUPP, 69, E_INFO, EV_NONE, 0 ), "%'--retries (-r)'%: specifies the number of times the command may be retried." } ;
ErrorId MsgSupp::OptionNoIgnore        = { ErrorOf( ES_SUPP, 70, E_INFO, EV_NONE, 0 ), "%'--no-ignore (-I)'%: specifies that the command should ignore the %'P4IGNORE'% settings." } ;
ErrorId MsgSupp::OptionCentralUsers    = { ErrorOf( ES_SUPP, 71, E_INFO, EV_NONE, 0 ), "%'--central-only (-c)'%: include user information from the central server only." } ;
ErrorId MsgSupp::OptionReplicaUsers    = { ErrorOf( ES_SUPP, 72, E_INFO, EV_NONE, 0 ), "%'--replica-only (-r)'%: include user information from the replica server only." } ;
ErrorId MsgSupp::OptionFullBranch      = { ErrorOf( ES_SUPP, 73, E_INFO, EV_NONE, 0 ), "%'--full-branch (-F)'%: include the full generated branch spec in the output." } ;
ErrorId MsgSupp::OptionSpecFixStatus   = { ErrorOf( ES_SUPP, 74, E_INFO, EV_NONE, 0 ), "%'--status (-s)'%: include the fix status for each job in the spec." } ;
ErrorId MsgSupp::OptionChangeType      = { ErrorOf( ES_SUPP, 75, E_INFO, EV_NONE, 0 ), "%'--type (-t)'%: specify the type of this change (public or restricted)." } ;
ErrorId MsgSupp::OptionChangeUpdate    = { ErrorOf( ES_SUPP, 76, E_INFO, EV_NONE, 0 ), "%'--update (-u)'%: allows the owner of a submitted change to update it." } ;
ErrorId MsgSupp::OptionOriginal        = { ErrorOf( ES_SUPP, 77, E_INFO, EV_NONE, 0 ), "%'--original (-O)'%: specifies the original change number of a renumbered change." } ;
ErrorId MsgSupp::OptionChangeUser      = { ErrorOf( ES_SUPP, 78, E_INFO, EV_NONE, 0 ), "%'--new-user (-U)'%: specifies the new user of an empty pending change." } ;
ErrorId MsgSupp::OptionTemplate        = { ErrorOf( ES_SUPP, 79, E_INFO, EV_NONE, 0 ), "%'--template (-t)'%: specifies the template for a client or label." } ;
ErrorId MsgSupp::OptionSwitch          = { ErrorOf( ES_SUPP, 80, E_INFO, EV_NONE, 0 ), "%'--switch (-s)'%: specifies to switch this client to a different stream." } ;
ErrorId MsgSupp::OptionTemporary       = { ErrorOf( ES_SUPP, 81, E_INFO, EV_NONE, 0 ), "%'--temporary (-x)'%: specifies to create a temporary client." } ;
ErrorId MsgSupp::OptionOwner           = { ErrorOf( ES_SUPP, 82, E_INFO, EV_NONE, 0 ), "%'--owner (-a)'%: enables an owner of the group to update it." } ;
ErrorId MsgSupp::OptionAdministrator   = { ErrorOf( ES_SUPP, 83, E_INFO, EV_NONE, 0 ), "%'--administrator (-A)'%: enables an administrator to create a new group." } ;
ErrorId MsgSupp::OptionGlobal          = { ErrorOf( ES_SUPP, 84, E_INFO, EV_NONE, 0 ), "%'--global (-g)'%: enables modifying a global label from an Edge Server." } ;
ErrorId MsgSupp::OptionStreamType      = { ErrorOf( ES_SUPP, 85, E_INFO, EV_NONE, 0 ), "%'--type (-t)'%: specifies the type of stream" } ;
ErrorId MsgSupp::OptionVirtualStream   = { ErrorOf( ES_SUPP, 86, E_INFO, EV_NONE, 0 ), "%'--virtual (-v)'%: specifies this is a virtual stream." } ;
ErrorId MsgSupp::OptionBrief           = { ErrorOf( ES_SUPP, 87, E_INFO, EV_NONE, 0 ), "%'--brief (-L)'%: displays truncated changelist description." } ;
ErrorId MsgSupp::OptionInherited       = { ErrorOf( ES_SUPP, 88, E_INFO, EV_NONE, 0 ), "%'--inherited (-i)'%: includes changes integrated into the files." } ;
ErrorId MsgSupp::OptionShowTime        = { ErrorOf( ES_SUPP, 89, E_INFO, EV_NONE, 0 ), "%'--show-time (-t)'%: includes the time in the output."} ;
ErrorId MsgSupp::OptionChangeStatus    = { ErrorOf( ES_SUPP, 90, E_INFO, EV_NONE, 0 ), "%'--status (-s)'%: specifies the change status." } ;
ErrorId MsgSupp::OptionLimitClient     = { ErrorOf( ES_SUPP, 91, E_INFO, EV_NONE, 0 ), "%'--client (-C)'%: limit the results to this client workspace." } ;
ErrorId MsgSupp::OptionLabelName       = { ErrorOf( ES_SUPP, 92, E_INFO, EV_NONE, 0 ), "%'--label (-l)'%: specifies the name of the label." } ;
ErrorId MsgSupp::OptionRunOnMaster     = { ErrorOf( ES_SUPP, 93, E_INFO, EV_NONE, 0 ), "%'--global (-M)'%: create this list on the master server." } ;
ErrorId MsgSupp::OptionArchive         = { ErrorOf( ES_SUPP, 94, E_INFO, EV_NONE, 0 ), "%'--archive (-A)'%: enables access to the archive depot" } ;
ErrorId MsgSupp::OptionBlocksize       = { ErrorOf( ES_SUPP, 95, E_INFO, EV_NONE, 0 ), "%'--blocksize (-b)'%: specifies the blocksize to be used for calculations." } ;
ErrorId MsgSupp::OptionHuman1024       = { ErrorOf( ES_SUPP, 96, E_INFO, EV_NONE, 0 ), "%'--human (-h)'%: displays output using human-friendly abbreviations." } ;
ErrorId MsgSupp::OptionHuman1000       = { ErrorOf( ES_SUPP, 97, E_INFO, EV_NONE, 0 ), "%'--human-1000 (-H)'%: displays human-friendly output using units of 1000." } ;
ErrorId MsgSupp::OptionSummary         = { ErrorOf( ES_SUPP, 98, E_INFO, EV_NONE, 0 ), "%'--summary (-s)'%: displays summary information." } ;
ErrorId MsgSupp::OptionShelved         = { ErrorOf( ES_SUPP, 99, E_INFO, EV_NONE, 0 ), "%'--shelved (-S)'%: specifies to access shelved files." } ;
ErrorId MsgSupp::OptionUnload          = { ErrorOf( ES_SUPP, 100, E_INFO, EV_NONE, 0 ), "%'--unload (-U)'%: enables access to unloaded objects." } ;
ErrorId MsgSupp::OptionUnloadLimit     = { ErrorOf( ES_SUPP, 264, E_INFO, EV_NONE, 0 ), "%'--unload-limit (-u)'%: threshold number of days after which an unused client will be unloaded." } ;
ErrorId MsgSupp::OptionOmitLazy        = { ErrorOf( ES_SUPP, 101, E_INFO, EV_NONE, 0 ), "%'--omit-lazy (-z)'%: omits lazy copies from the results." } ;
ErrorId MsgSupp::OptionLeaveKeywords   = { ErrorOf( ES_SUPP, 102, E_INFO, EV_NONE, 0 ), "%'--leave-keywords (-k)'%: specifies that RCS keywords are not to be expanded in the output." } ;
ErrorId MsgSupp::OptionOutputFile      = { ErrorOf( ES_SUPP, 103, E_INFO, EV_NONE, 0 ), "%'--file (-o)'%: specifies the name of the output file." } ;
ErrorId MsgSupp::OptionExists          = { ErrorOf( ES_SUPP, 104, E_INFO, EV_NONE, 0 ), "%'--exists (-e)'%: includes only files which are not deleted." } ;
ErrorId MsgSupp::OptionContent         = { ErrorOf( ES_SUPP, 105, E_INFO, EV_NONE, 0 ), "%'--content (-h)'%: display file content history instead of file name history." } ;
ErrorId MsgSupp::OptionOmitPromoted    = { ErrorOf( ES_SUPP, 106, E_INFO, EV_NONE, 0 ), "%'--omit-promoted (-p)'%: disables following content of promoted task streams." } ;
ErrorId MsgSupp::OptionOmitMoved       = { ErrorOf( ES_SUPP, 107, E_INFO, EV_NONE, 0 ), "%'--omit-moved (-1)'%: disables following renames resulting from '%'p4 move'%'." } ;
ErrorId MsgSupp::OptionKeepClient      = { ErrorOf( ES_SUPP, 108, E_INFO, EV_NONE, 0 ), "%'--keep-client (-k)'%: leaves the client's copy of the files untouched." } ;
ErrorId MsgSupp::OptionFileCharset     = { ErrorOf( ES_SUPP, 109, E_INFO, EV_NONE, 0 ), "%'--file-charset (-Q)'%: specifies a character set override for this file." } ;
ErrorId MsgSupp::OptionVirtual         = { ErrorOf( ES_SUPP, 110, E_INFO, EV_NONE, 0 ), "%'--virtual (-v)'%: performs the action on the server without updating client data." } ;
ErrorId MsgSupp::OptionGenerate        = { ErrorOf( ES_SUPP, 111, E_INFO, EV_NONE, 0 ), "%'--generate (-g)'%: generate a new unique value." } ;
ErrorId MsgSupp::OptionConfigure        = { ErrorOf( ES_SUPP, 276, E_INFO, EV_NONE, 0 ), "%'--configure (-c)'%: configure edge or commit server." } ;
ErrorId MsgSupp::OptionUsage           = { ErrorOf( ES_SUPP, 112, E_INFO, EV_NONE, 0 ), "%'--usage (-u)'%: display the current usage levels." } ;
ErrorId MsgSupp::OptionTags            = { ErrorOf( ES_SUPP, 113, E_INFO, EV_NONE, 0 ), "%'--tags (-T)'%: specify which tags to include in the results." } ;
ErrorId MsgSupp::OptionFilter          = { ErrorOf( ES_SUPP, 114, E_INFO, EV_NONE, 0 ), "%'--filter (-F)'%: specify filters which limit the results." } ;
ErrorId MsgSupp::OptionJob             = { ErrorOf( ES_SUPP, 115, E_INFO, EV_NONE, 0 ), "%'--job (-j)'%: specifies the job name." } ;
ErrorId MsgSupp::OptionExpression      = { ErrorOf( ES_SUPP, 116, E_INFO, EV_NONE, 0 ), "%'--expression (-e)'%: specifies the expression to filter the results." } ;
ErrorId MsgSupp::OptionNoCaseExpr      = { ErrorOf( ES_SUPP, 117, E_INFO, EV_NONE, 0 ), "%'--no-case-expression (-E)'%: specifies the case-insensitive expression to filter the results." } ;
ErrorId MsgSupp::OptionIncrement       = { ErrorOf( ES_SUPP, 118, E_INFO, EV_NONE, 0 ), "%'--increment (-i)'%: specifies that the value is to be incremented by 1." } ;
ErrorId MsgSupp::OptionDiffFlags       = { ErrorOf( ES_SUPP, 119, E_INFO, EV_NONE, 0 ), "%'--diff-flags (-d)'%: specifies flags for diff behavior." } ;
ErrorId MsgSupp::OptionFixStatus       = { ErrorOf( ES_SUPP, 120, E_INFO, EV_NONE, 0 ), "%'--fix-status (-s)'%: specifies the status for this fix." } ;
ErrorId MsgSupp::OptionShelf           = { ErrorOf( ES_SUPP, 121, E_INFO, EV_NONE, 0 ), "%'--shelf (-s)'%: specifies the shelved changelist number to use." } ;
ErrorId MsgSupp::OptionReplace         = { ErrorOf( ES_SUPP, 122, E_INFO, EV_NONE, 0 ), "%'--replace (-r)'%: specifies to replace all shelved files in the changelist." } ;
ErrorId MsgSupp::OptionShelveOpts      = { ErrorOf( ES_SUPP, 123, E_INFO, EV_NONE, 0 ), "%'--shelve-options (-a)'%: specifies options for handling unchanged files." } ;
ErrorId MsgSupp::OptionBranch          = { ErrorOf( ES_SUPP, 124, E_INFO, EV_NONE, 0 ), "%'--branch (-b)'%: specifies the branch name to use." } ;
ErrorId MsgSupp::OptionSubmitShelf     = { ErrorOf( ES_SUPP, 125, E_INFO, EV_NONE, 0 ), "%'--shelf (-e)'%: specifies the shelved changelist to submit." } ;
ErrorId MsgSupp::OptionSubmitOpts      = { ErrorOf( ES_SUPP, 126, E_INFO, EV_NONE, 0 ), "%'--submit-options (-f)'%: specifies options for handling unchanged files." } ;
ErrorId MsgSupp::OptionReopen          = { ErrorOf( ES_SUPP, 127, E_INFO, EV_NONE, 0 ), "%'--reopen (-r)'%: specifies that the files should be reopened after submit." } ;
ErrorId MsgSupp::OptionDescription     = { ErrorOf( ES_SUPP, 128, E_INFO, EV_NONE, 0 ), "%'--description (-d)'%: specifies the description of the change." } ;
ErrorId MsgSupp::OptionTamper          = { ErrorOf( ES_SUPP, 129, E_INFO, EV_NONE, 0 ), "%'--tamper-check (-t)'%: specifies that file digests should be used to detect tampering." } ;
ErrorId MsgSupp::OptionCompress        = { ErrorOf( ES_SUPP, 130, E_INFO, EV_NONE, 0 ), "%'--compress (-z)'%: specifies that the output should be compressed." } ;
ErrorId MsgSupp::OptionDate            = { ErrorOf( ES_SUPP, 131, E_INFO, EV_NONE, 0 ), "%'--date (-d)'%: specifies to unload all objects older than that date." } ;
ErrorId MsgSupp::OptionStreamName      = { ErrorOf( ES_SUPP, 132, E_INFO, EV_NONE, 0 ), "%'--stream (-s)'%: specifies the stream name." } ;
ErrorId MsgSupp::OptionReverse         = { ErrorOf( ES_SUPP, 133, E_INFO, EV_NONE, 0 ), "%'--reverse (-r)'%: specifies to reverse the direction of the branch view." } ;
ErrorId MsgSupp::OptionWipe            = { ErrorOf( ES_SUPP, 134, E_INFO, EV_NONE, 0 ), "%'--erase (-w)'%: removes the object from the client machine." } ;
ErrorId MsgSupp::OptionUnchanged       = { ErrorOf( ES_SUPP, 135, E_INFO, EV_NONE, 0 ), "%'--unchanged (-a)'%: specifies that only unchanged files are affected." } ;
ErrorId MsgSupp::OptionDepot           = { ErrorOf( ES_SUPP, 136, E_INFO, EV_NONE, 0 ), "%'--depot (-D)'%: specifies the depot name." } ;
ErrorId MsgSupp::OptionDepot2          = { ErrorOf( ES_SUPP, 324, E_INFO, EV_NONE, 0 ), "%'--depot (-d)'%: specifies the depot name." } ;
ErrorId MsgSupp::OptionKeepHead        = { ErrorOf( ES_SUPP, 137, E_INFO, EV_NONE, 0 ), "%'--keep-head (-h)'%: specifies the head revision is not to be processed." } ;
ErrorId MsgSupp::OptionPurge           = { ErrorOf( ES_SUPP, 138, E_INFO, EV_NONE, 0 ), "%'--purge (-p)'%: specifies that the revisions are to be purged." } ;
ErrorId MsgSupp::OptionForceText       = { ErrorOf( ES_SUPP, 139, E_INFO, EV_NONE, 0 ), "%'--force-text (-t)'%: specifies that text revisions are to be processed." } ;
ErrorId MsgSupp::OptionBinaryAsText    = { ErrorOf( ES_SUPP, 140, E_INFO, EV_NONE, 0 ), "%'--binary-as-text (-t)'%: specifies that binary files are to be processed." } ;
ErrorId MsgSupp::OptionBypassFlow      = { ErrorOf( ES_SUPP, 141, E_INFO, EV_NONE, 0 ), "%'--bypass-flow (-F)'%: forces the command to process against a stream's expected flow." } ;
ErrorId MsgSupp::OptionShowChange      = { ErrorOf( ES_SUPP, 142, E_INFO, EV_NONE, 0 ), "%'--show-change (-c)'%: show changelist numbers rather than revision numbers." } ;
ErrorId MsgSupp::OptionFollowBranch    = { ErrorOf( ES_SUPP, 143, E_INFO, EV_NONE, 0 ), "%'--follow-branch (-i)'%: include the revisions of the source file up to the branch point." } ;
ErrorId MsgSupp::OptionFollowInteg     = { ErrorOf( ES_SUPP, 144, E_INFO, EV_NONE, 0 ), "%'--follow-integ (-I)'%: include all integrations into the file." } ;
ErrorId MsgSupp::OptionSourceFile      = { ErrorOf( ES_SUPP, 145, E_INFO, EV_NONE, 0 ), "%'--source-file (-s)'%: treat fromFile as the source and both sides of the branch view as the target." } ;
ErrorId MsgSupp::OptionOutputFlags     = { ErrorOf( ES_SUPP, 146, E_INFO, EV_NONE, 0 ), "%'--output-flags (-O)'%: specifies codes controlling the command output." } ;
ErrorId MsgSupp::OptionResolveFlags    = { ErrorOf( ES_SUPP, 148, E_INFO, EV_NONE, 0 ), "%'--resolve-flags (-A)'%: controls which types of resolves are performed." } ;
ErrorId MsgSupp::OptionAcceptFlags     = { ErrorOf( ES_SUPP, 149, E_INFO, EV_NONE, 0 ), "%'--accept-flags (-a)'%: specifies the level of automatic resolves accepted." } ;
ErrorId MsgSupp::OptionIntegFlags      = { ErrorOf( ES_SUPP, 150, E_INFO, EV_NONE, 0 ), "%'--integ-flags (-R)'%: specifies how integrate should schedule resolves." } ;
ErrorId MsgSupp::OptionDeleteFlags     = { ErrorOf( ES_SUPP, 151, E_INFO, EV_NONE, 0 ), "%'--delete-flags (-D)'%: specifies how integration should handle deleted files." } ;
ErrorId MsgSupp::OptionRestrictFlags   = { ErrorOf( ES_SUPP, 152, E_INFO, EV_NONE, 0 ), "%'--restrict-flags (-R)'%: limits the output to specific files." } ;
ErrorId MsgSupp::OptionSortFlags       = { ErrorOf( ES_SUPP, 153, E_INFO, EV_NONE, 0 ), "%'--sort-flags (-S)'%: changes the order of output." } ;
ErrorId MsgSupp::OptionForceFlag       = { ErrorOf( ES_SUPP, 175, E_INFO, EV_NONE, 0 ), "%'--force-flag (-F)'%: optional force behavior when deleting clients." } ;
ErrorId MsgSupp::OptionUseList         = { ErrorOf( ES_SUPP, 154, E_INFO, EV_NONE, 0 ), "%'--use-list (-L)'%: collects multiple file arguments into an in-memory list." } ;
ErrorId MsgSupp::OptionPublish         = { ErrorOf( ES_SUPP, 155, E_INFO, EV_NONE, 0 ), "%'--publish (-p)'%: populates the client workspace but does not update the server." } ;
ErrorId MsgSupp::OptionSafe            = { ErrorOf( ES_SUPP, 156, E_INFO, EV_NONE, 0 ), "%'--safe (-s)'%: performs a safety check before sending the file." } ;
ErrorId MsgSupp::OptionIsGroup         = { ErrorOf( ES_SUPP, 157, E_INFO, EV_NONE, 0 ), "%'--group (-g)'%: indicates that the argument is a group name." } ;
ErrorId MsgSupp::OptionIsUser          = { ErrorOf( ES_SUPP, 158, E_INFO, EV_NONE, 0 ), "%'--user (-u)'%: indicates that the argument is a user name." } ;
ErrorId MsgSupp::OptionIsOwner         = { ErrorOf( ES_SUPP, 159, E_INFO, EV_NONE, 0 ), "%'--owner (-o)'%: indicates that the argument is an owner." } ;
ErrorId MsgSupp::OptionVerbose         = { ErrorOf( ES_SUPP, 160, E_INFO, EV_NONE, 0 ), "%'--verbose (-v)'%: includes additional information in the output." } ;
ErrorId MsgSupp::OptionLineNumber      = { ErrorOf( ES_SUPP, 161, E_INFO, EV_NONE, 0 ), "%'--line-number (-n)'%: print line number with output lines." } ;
ErrorId MsgSupp::OptionInvertMatch     = { ErrorOf( ES_SUPP, 162, E_INFO, EV_NONE, 0 ), "%'--invert-match (-v)'%: select non-matching lines." } ;
ErrorId MsgSupp::OptionFilesWithMatches  = { ErrorOf( ES_SUPP, 163, E_INFO, EV_NONE, 0 ), "%'--files-with-matches (-l)'%: only print files containing matches." } ;
ErrorId MsgSupp::OptionFilesWithoutMatch = { ErrorOf( ES_SUPP, 164, E_INFO, EV_NONE, 0 ), "%'--files-without-match (-L)'%: only print files containing no match." } ;
ErrorId MsgSupp::OptionNoMessages      = { ErrorOf( ES_SUPP, 165, E_INFO, EV_NONE, 0 ), "%'--no-messages (-s)'%: specifies no line-too-long messages." } ;
ErrorId MsgSupp::OptionFixedStrings    = { ErrorOf( ES_SUPP, 166, E_INFO, EV_NONE, 0 ), "%'--fixed-strings (-F)'%: specifies a fixed string." } ;
ErrorId MsgSupp::OptionBasicRegexp     = { ErrorOf( ES_SUPP, 167, E_INFO, EV_NONE, 0 ), "%'--basic-regexp (-G)'%: specifies a basic regular expression." } ;
ErrorId MsgSupp::OptionExtendedRegexp  = { ErrorOf( ES_SUPP, 168, E_INFO, EV_NONE, 0 ), "%'--extended-regexp (-E)'%: specifies an extended regular expression." } ;
ErrorId MsgSupp::OptionPerlRegexp      = { ErrorOf( ES_SUPP, 169, E_INFO, EV_NONE, 0 ), "%'--perl-regexp (-P)'%: specifies a Perl regular expression" } ;
ErrorId MsgSupp::OptionRegexp          = { ErrorOf( ES_SUPP, 170, E_INFO, EV_NONE, 0 ), "%'--regexp (-e)'%: specifies the regular expression" } ;
ErrorId MsgSupp::OptionAfterContext    = { ErrorOf( ES_SUPP, 171, E_INFO, EV_NONE, 0 ), "%'--after-context (-A)'%: specifies the number of lines after the match." } ;
ErrorId MsgSupp::OptionBeforeContext   = { ErrorOf( ES_SUPP, 172, E_INFO, EV_NONE, 0 ), "%'--before-context (-B)'%: specifies the number of lines before the match." } ;
ErrorId MsgSupp::OptionContext         = { ErrorOf( ES_SUPP, 173, E_INFO, EV_NONE, 0 ), "%'--context (-C)'%: specifies the number of lines of context." } ;
ErrorId MsgSupp::OptionIgnoreCase      = { ErrorOf( ES_SUPP, 174, E_INFO, EV_NONE, 0 ), "%'--ignore-case (-i)'%: causes the pattern-matching to be case-insensitive." } ;
ErrorId MsgSupp::OptionJournalPrefix   = { ErrorOf( ES_SUPP, 176, E_INFO, EV_NONE, 0 ), "%'--journal-prefix (-J)'%: specifies the journal file name prefix." } ;
ErrorId MsgSupp::OptionRepeat          = { ErrorOf( ES_SUPP, 177, E_INFO, EV_NONE, 0 ), "%'--repeat (-i)'%: specifies the repeat interval in seconds." } ;
ErrorId MsgSupp::OptionBackoff         = { ErrorOf( ES_SUPP, 178, E_INFO, EV_NONE, 0 ), "%'--backoff (-b)'%: specifies the error backoff period in seconds." } ;
ErrorId MsgSupp::OptionArchiveData     = { ErrorOf( ES_SUPP, 179, E_INFO, EV_NONE, 0 ), "%'--archive-data (-u)'%: specifies to retrieve file content." } ;
ErrorId MsgSupp::OptionStatus          = { ErrorOf( ES_SUPP, 180, E_INFO, EV_NONE, 0 ), "%'--status (-l)'%: specifies that status information should be displayed" } ;
ErrorId MsgSupp::OptionJournalPosition = { ErrorOf( ES_SUPP, 181, E_INFO, EV_NONE, 0 ), "%'--journal-position (-j)'%: specifies to display journal position status." } ;
ErrorId MsgSupp::OptionPullServerid    = { ErrorOf( ES_SUPP, 182, E_INFO, EV_NONE, 0 ), "%'--serverid (-P)'%: specifies to use filtering specifications of this server." } ;
ErrorId MsgSupp::OptionExcludeTables   = { ErrorOf( ES_SUPP, 183, E_INFO, EV_NONE, 0 ), "%'--exclude-tables (-T)'%: specifies tables to exclude." } ;
ErrorId MsgSupp::OptionFile            = { ErrorOf( ES_SUPP, 184, E_INFO, EV_NONE, 0 ), "%'--file (-f)'%: specifies the file." } ;
ErrorId MsgSupp::OptionRevision        = { ErrorOf( ES_SUPP, 185, E_INFO, EV_NONE, 0 ), "%'--revision (-r)'%: specifies the revision." } ;
ErrorId MsgSupp::OptionNoRejournal     = { ErrorOf( ES_SUPP, 186, E_INFO, EV_NONE, 0 ), "%'--no-rejournal'%: specifies that the pull command should not re-journal records which are replicated from the target server." } ;
ErrorId MsgSupp::OptionAppend          = { ErrorOf( ES_SUPP, 187, E_INFO, EV_NONE, 0 ), "%'--append (-a)'%: specifies that information is to be appended." } ;
ErrorId MsgSupp::OptionSequence        = { ErrorOf( ES_SUPP, 188, E_INFO, EV_NONE, 0 ), "%'--sequence (-c)'%: specifies the sequence value." } ;
ErrorId MsgSupp::OptionCounter         = { ErrorOf( ES_SUPP, 189, E_INFO, EV_NONE, 0 ), "%'--counter (-t)'%: specifies the counter name." } ;
ErrorId MsgSupp::OptionHostName        = { ErrorOf( ES_SUPP, 190, E_INFO, EV_NONE, 0 ), "%'--host (-h)'%: specifies the host name to use." } ;
ErrorId MsgSupp::OptionPrint           = { ErrorOf( ES_SUPP, 191, E_INFO, EV_NONE, 0 ), "%'--print (-p)'%: specifies that the result is to be displayed." } ;
ErrorId MsgSupp::OptionStartPosition   = { ErrorOf( ES_SUPP, 192, E_INFO, EV_NONE, 0 ), "%'--start (-s)'%: specifies the starting position." } ;
ErrorId MsgSupp::OptionEncoded         = { ErrorOf( ES_SUPP, 193, E_INFO, EV_NONE, 0 ), "%'--encoded (-e)'%: specifies that the value is to be encoded." } ;
ErrorId MsgSupp::OptionLogName         = { ErrorOf( ES_SUPP, 194, E_INFO, EV_NONE, 0 ), "%'--log (-l)'%: specifies the name of the log." } ;
ErrorId MsgSupp::OptionLoginStatus     = { ErrorOf( ES_SUPP, 195, E_INFO, EV_NONE, 0 ), "%'--status (-s)'%: displays the current status." } ;
ErrorId MsgSupp::OptionCompressCkp     = { ErrorOf( ES_SUPP, 196, E_INFO, EV_NONE, 0 ), "%'--compress-ckp (-Z)'%: compress the checkpoint, but not the journal." } ;
ErrorId MsgSupp::OptionSpecType        = { ErrorOf( ES_SUPP, 197, E_INFO, EV_NONE, 0 ), "%'--spec (-s)'%: specifies the type of spec to be processed." } ;
ErrorId MsgSupp::OptionMaxAccess       = { ErrorOf( ES_SUPP, 198, E_INFO, EV_NONE, 0 ), "%'--max-access (-m)'%: displays a single word summary of the maximum access level." } ;
ErrorId MsgSupp::OptionGroupName       = { ErrorOf( ES_SUPP, 199, E_INFO, EV_NONE, 0 ), "%'--group (-g)'%: specifies the group name." } ;
ErrorId MsgSupp::OptionShowFiles       = { ErrorOf( ES_SUPP, 200, E_INFO, EV_NONE, 0 ), "%'--show-files (-f)'%: specifies to display the individual files." } ;
ErrorId MsgSupp::OptionName            = { ErrorOf( ES_SUPP, 201, E_INFO, EV_NONE, 0 ), "%'--name (-n)'%: specifies the object name." } ;
ErrorId MsgSupp::OptionValue           = { ErrorOf( ES_SUPP, 202, E_INFO, EV_NONE, 0 ), "%'--value (-v)'%: specifies the object value." } ;
ErrorId MsgSupp::OptionPropagating     = { ErrorOf( ES_SUPP, 203, E_INFO, EV_NONE, 0 ), "%'--propagating (-p)'%: specifies the attribute is propagating." } ;
ErrorId MsgSupp::OptionOpenAdd         = { ErrorOf( ES_SUPP, 204, E_INFO, EV_NONE, 0 ), "%'--add (-a)'%: specifies files should be opened for add." } ;
ErrorId MsgSupp::OptionOpenEdit        = { ErrorOf( ES_SUPP, 205, E_INFO, EV_NONE, 0 ), "%'--edit (-e)'%: specifies files should be opened for edit." } ;
ErrorId MsgSupp::OptionOpenDelete      = { ErrorOf( ES_SUPP, 206, E_INFO, EV_NONE, 0 ), "%'--delete (-d)'%: specifies files should be opened for delete." } ;
ErrorId MsgSupp::OptionUseModTime      = { ErrorOf( ES_SUPP, 207, E_INFO, EV_NONE, 0 ), "%'--modtime (-m)'%: specifies the file modification time should be checked." } ;
ErrorId MsgSupp::OptionLocal           = { ErrorOf( ES_SUPP, 208, E_INFO, EV_NONE, 0 ), "%'--local (-l)'%: specifies local syntax for filenames." } ;
ErrorId MsgSupp::OptionOutputBase      = { ErrorOf( ES_SUPP, 209, E_INFO, EV_NONE, 0 ), "%'--output-base (-o)'%: specifies to display the revision used as the base." } ;
ErrorId MsgSupp::OptionSystem          = { ErrorOf( ES_SUPP, 210, E_INFO, EV_NONE, 0 ), "%'--system (-s)'%: specifies the value should apply to all users on the system." } ;
ErrorId MsgSupp::OptionService         = { ErrorOf( ES_SUPP, 211, E_INFO, EV_NONE, 0 ), "%'--service (-S)'%: specifies the value applies to the named service." } ;
ErrorId MsgSupp::OptionHistogram       = { ErrorOf( ES_SUPP, 212, E_INFO, EV_NONE, 0 ), "%'--histogram (-h)'%: specifies to display a histogram." } ;
ErrorId MsgSupp::OptionTableNotUnlocked = { ErrorOf( ES_SUPP, 213, E_INFO, EV_NONE, 0 ), "%'--table-not-unlocked (-U)'%: runs only the table-not-unlocked check." } ;
ErrorId MsgSupp::OptionTableName       = { ErrorOf( ES_SUPP, 214, E_INFO, EV_NONE, 0 ), "%'--table (-t)'%: specifies the table." } ;
ErrorId MsgSupp::OptionAllClients      = { ErrorOf( ES_SUPP, 215, E_INFO, EV_NONE, 0 ), "%'--all-clients (-C)'%: specifies to process all client workspaces." } ;
ErrorId MsgSupp::OptionCheckSize       = { ErrorOf( ES_SUPP, 216, E_INFO, EV_NONE, 0 ), "%'--size (-s)'%: specifies that file size should be checked." } ;
ErrorId MsgSupp::OptionTransfer        = { ErrorOf( ES_SUPP, 217, E_INFO, EV_NONE, 0 ), "%'--transfer (-t)'%: specifies damaged or missing files should be retransferred." } ;
ErrorId MsgSupp::OptionUpdate          = { ErrorOf( ES_SUPP, 218, E_INFO, EV_NONE, 0 ), "%'--update (-u)'%: specifies to process only files that have no saved digest." } ;
ErrorId MsgSupp::OptionVerify          = { ErrorOf( ES_SUPP, 219, E_INFO, EV_NONE, 0 ), "%'--verify (-v)'%: specifies to recompute digests for all files." } ;
ErrorId MsgSupp::OptionNoArchive       = { ErrorOf( ES_SUPP, 220, E_INFO, EV_NONE, 0 ), "%'--no-archive (-X)'%: specifies to skip files with the +X filetype." } ;
ErrorId MsgSupp::OptionServerid        = { ErrorOf( ES_SUPP, 221, E_INFO, EV_NONE, 0 ), "%'--serverid (-s)'%: specifies the serverid." } ;
ErrorId MsgSupp::OptionUnified         = { ErrorOf( ES_SUPP, 222, E_INFO, EV_NONE, 0 ), "%'--unified (-u)'%: specifies to display the diff in unified format." } ;
ErrorId MsgSupp::OptionPreviewNC       = { ErrorOf( ES_SUPP, 223, E_INFO, EV_NONE, 0 ), "%'--preview-noncontent (-N)'%: previews the operation, including non-content." } ;
ErrorId MsgSupp::OptionEstimates       = { ErrorOf( ES_SUPP, 224, E_INFO, EV_NONE, 0 ), "%'--estimates (-N)'%: specifies to display estimates about the work required." } ;
ErrorId MsgSupp::OptionLocked          = { ErrorOf( ES_SUPP, 225, E_INFO, EV_NONE, 0 ), "%'--locked (-L)'%: specifies that locked objects are to be included." } ;
ErrorId MsgSupp::OptionUnloadAll       = { ErrorOf( ES_SUPP, 226, E_INFO, EV_NONE, 0 ), "%'--unload-all (-a)'%: specifies that multiple objects are to be unloaded." } ;
ErrorId MsgSupp::OptionKeepHave        = { ErrorOf( ES_SUPP, 227, E_INFO, EV_NONE, 0 ), "%'--keep-have (-h)'%: specifies to leave target files at the currently synced revision." } ;
ErrorId MsgSupp::OptionYes             = { ErrorOf( ES_SUPP, 228, E_INFO, EV_NONE, 0 ), "%'--yes (-y)'%: causes prompts to be automatically accepted." } ;
ErrorId MsgSupp::OptionNo              = { ErrorOf( ES_SUPP, 229, E_INFO, EV_NONE, 0 ), "%'--no (-n)'%: causes prompts to be automatically refused." } ;
ErrorId MsgSupp::OptionInputValue      = { ErrorOf( ES_SUPP, 230, E_INFO, EV_NONE, 0 ), "%'--value (-i)'%: specifies the value." } ;
ErrorId MsgSupp::OptionReplacement     = { ErrorOf( ES_SUPP, 231, E_INFO, EV_NONE, 0 ), "%'--replacement (-r)'%: specifies that a replacement is affected." } ;
ErrorId MsgSupp::OptionFrom            = { ErrorOf( ES_SUPP, 232, E_INFO, EV_NONE, 0 ), "%'--from'%: specifies the old value." } ;
ErrorId MsgSupp::OptionTo              = { ErrorOf( ES_SUPP, 233, E_INFO, EV_NONE, 0 ), "%'--to'%: specifies the new value." } ;
ErrorId MsgSupp::OptionRebuild         = { ErrorOf( ES_SUPP, 234, E_INFO, EV_NONE, 0 ), "%'--rebuild (-R)'%: rebuild the database." } ;
ErrorId MsgSupp::OptionEqual           = { ErrorOf( ES_SUPP, 235, E_INFO, EV_NONE, 0 ), "%'--equal (-e)'%: specifies the exact changelist." } ;
ErrorId MsgSupp::OptionAttrPattern     = { ErrorOf( ES_SUPP, 236, E_INFO, EV_NONE, 0 ), "%'--attribute-pattern (-A)'%: displays only attributes that match the pattern." } ;
ErrorId MsgSupp::OptionDiffListFlag    = { ErrorOf( ES_SUPP, 237, E_INFO, EV_NONE, 0 ), "%'--diff-list-flag (-s)'%: lists files that satisfy the flag value." } ;
ErrorId MsgSupp::OptionArguments       = { ErrorOf( ES_SUPP, 238, E_INFO, EV_NONE, 0 ), "%'--arguments (-a)'%: displays the arguments." } ;
ErrorId MsgSupp::OptionEnvironment     = { ErrorOf( ES_SUPP, 239, E_INFO, EV_NONE, 0 ), "%'--environment (-e)'%: displays the environment." } ;
ErrorId MsgSupp::OptionTaskStatus      = { ErrorOf( ES_SUPP, 240, E_INFO, EV_NONE, 0 ), "%'--status (-s)'%: displays only commands that match the status." } ;
ErrorId MsgSupp::OptionAllUsers        = { ErrorOf( ES_SUPP, 241, E_INFO, EV_NONE, 0 ), "%'--all-users (-A)'%: specifies the command applies to all users." } ;
ErrorId MsgSupp::OptionParallel        = { ErrorOf( ES_SUPP, 242, E_INFO, EV_NONE, 0 ), "%'--parallel=threads=N,batch=N,batchsize=N,min=N,minsize=N'%: specify file transfer parallelism." } ;
ErrorId MsgSupp::OptionParallelSubmit        = { ErrorOf( ES_SUPP, 35, E_INFO, EV_NONE, 0 ), "%'--parallel=threads=N,batch=N,min=N'%: specify file transfer parallelism." } ;
ErrorId MsgSupp::OptionPromote         = { ErrorOf( ES_SUPP, 243, E_INFO, EV_NONE, 0 ), "%'--promote (-p)'%: specifies to promote the shelf to the Commit Server." } ;
ErrorId MsgSupp::OptionInputFile       = { ErrorOf( ES_SUPP, 245, E_INFO, EV_NONE, 0 ), "%'--input-file'%: specifies the name of the input file." } ;
ErrorId MsgSupp::OptionPidFile         = { ErrorOf( ES_SUPP, 246, E_INFO, EV_NONE, 0 ), "%'--pid-file'%: specifies the name of the PID file." } ;
ErrorId MsgSupp::OptionLocalJournal    = { ErrorOf( ES_SUPP, 247, E_INFO, EV_NONE, 0 ), "%'--local-journal'%: specifies that the pull command should read journal records from a local journal file rather than from the target server." } ;
ErrorId MsgSupp::OptionTest            = { ErrorOf( ES_SUPP, 248, E_INFO, EV_NONE, 0 ), "%'--test (-t)'%: specifies a user to test against the LDAP configuration." } ;
ErrorId MsgSupp::OptionActive          = { ErrorOf( ES_SUPP, 249, E_INFO, EV_NONE, 0 ), "%'--active (-A)'%: only list the active LDAP configurations." } ;
ErrorId MsgSupp::OptionNoRetransfer    = { ErrorOf( ES_SUPP, 250, E_INFO, EV_NONE, 0 ), "%'--noretransfer'%: override submit.noretransfer configurable behavior." } ;
ErrorId MsgSupp::OptionForceNoRetransfer    = { ErrorOf( ES_SUPP, 251, E_INFO, EV_NONE, 0 ), "%'--forcenoretransfer'%: skip file transfer if archive files are found (undoc and not recommended)." } ;
ErrorId MsgSupp::OptionDurableOnly     = { ErrorOf( ES_SUPP, 252, E_INFO, EV_NONE, 0 ), "%'--durable-only'%: deliver only durable journal records." } ;
ErrorId MsgSupp::OptionNonAcknowledging = { ErrorOf( ES_SUPP, 253, E_INFO, EV_NONE, 0 ), "%'--non-acknowledging'%: this request does not acknowledge previous journal records." } ;
ErrorId MsgSupp::OptionReplicationStatus = { ErrorOf( ES_SUPP, 254, E_INFO, EV_NONE, 0 ), "%'--replication-status (-J)'%: show the replication status of the server and of its replicas." } ;
ErrorId MsgSupp::OptionGroupMode       = { ErrorOf( ES_SUPP, 255, E_INFO, EV_NONE, 0 ), "%'--groups (-g)'%: updates Perforce group users with LDAP group members." } ;
ErrorId MsgSupp::OptionUserMode        = { ErrorOf( ES_SUPP, 285, E_INFO, EV_NONE, 0 ), "%'--users (-u)'%: updates Perforce users from LDAP user." } ;
ErrorId MsgSupp::OptionUserModeCreate  = { ErrorOf( ES_SUPP, 286, E_INFO, EV_NONE, 0 ), "%'--create (-c)'%: creates new users found in LDAP." } ;
ErrorId MsgSupp::OptionUserModeCreateStrict = { ErrorOf( ES_SUPP, 322, E_INFO, EV_NONE, 0 ), "%'--create-strict (-C)'%: creates new users found in LDAP, only if they would have access." } ;
ErrorId MsgSupp::OptionUserModeUpdate  = { ErrorOf( ES_SUPP, 287, E_INFO, EV_NONE, 0 ), "%'--update (-U)'%: updates existing users found in LDAP." } ;
ErrorId MsgSupp::OptionUserModeDelete  = { ErrorOf( ES_SUPP, 288, E_INFO, EV_NONE, 0 ), "%'--delete (-d)'%: deletes users not found in LDAP." } ;
ErrorId MsgSupp::OptionBypassExlusiveLock = { ErrorOf( ES_SUPP, 256, E_INFO, EV_NONE, 0 ), "%'--bypass-exclusive-lock'%: allow command on (+l) filetype even if already exclusively opened." } ;
ErrorId MsgSupp::OptionRetainLbrRevisions = { ErrorOf( ES_SUPP, 261, E_INFO, EV_NONE, 0 ), "%'--retain-lbr-revisions'%: don't rename library archive files with the renamed changelist number." } ;
ErrorId MsgSupp::OptionCreate             = { ErrorOf( ES_SUPP, 257, E_INFO, EV_NONE, 0 ), "%'--create (-c)'%: Create a new stream and populate it with files from the current stream. (dvcs only)" } ;
ErrorId MsgSupp::OptionList               = { ErrorOf( ES_SUPP, 258, E_INFO, EV_NONE, 0 ), "%'--list (-l)'%: list all the streams available to your client." } ;
ErrorId MsgSupp::OptionMainline           = { ErrorOf( ES_SUPP, 259, E_INFO, EV_NONE, 0 ), "%'--mainline (-m)'%: Create this stream as an empty mainline (no parent)." } ;
ErrorId MsgSupp::OptionMoveChanges        = { ErrorOf( ES_SUPP, 260, E_INFO, EV_NONE, 0 ), "%'--movechanges (-r)'%: Move open files to the stream you are switching to, instead of shelving and reverting them." } ;
ErrorId MsgSupp::OptionJavaProtocol       = { ErrorOf( ES_SUPP, 262, E_INFO, EV_NONE, 0 ), "%'--java'%: enable Java support via the rsh protocol." } ;
ErrorId MsgSupp::OptionPullBatch          = { ErrorOf( ES_SUPP, 263, E_INFO, EV_NONE, 0 ), "%'--batch'%: pull N archives in a single request to master." } ;
ErrorId MsgSupp::OptionDepotType          = { ErrorOf( ES_SUPP, 265, E_INFO, EV_NONE, 0 ), "%'--depot-type (-t)'%: specifies the type of depot" } ;
ErrorId MsgSupp::OptionClientType         = { ErrorOf( ES_SUPP, 280, E_INFO, EV_NONE, 0 ), "%'--client-type'%: specifies the type of client." } ;
ErrorId MsgSupp::OptionGlobalLock         = { ErrorOf( ES_SUPP, 266, E_INFO, EV_NONE, 0 ), "%'--global (-g)'%: reports or changes global locks from Edge Server" } ;
ErrorId MsgSupp::OptionEnableDVCSTriggers = { ErrorOf( ES_SUPP, 267, E_INFO, EV_NONE, 0 ), "%'--enable-dvcs-triggers'%: fires any push-* triggers for changelists imported by this unzip command." } ;
ErrorId MsgSupp::OptionUsers	          = { ErrorOf( ES_SUPP, 269, E_INFO, EV_NONE, 0 ), "%'--users (-u)'%: show the user who modifed the line." } ;
ErrorId MsgSupp::OptionConvertAdminComments = { ErrorOf( ES_SUPP, 270, E_INFO, EV_NONE, 0 ), "%'--convert-p4admin-comments'%: When used with -o option converts P4Admin style comments into new ## native spec comments." } ;
ErrorId MsgSupp::OptionRemoteSpec         = { ErrorOf( ES_SUPP, 271, E_INFO, EV_NONE, 0 ), "%'--remote'%: Specifies the remote spec to be used." } ;
ErrorId MsgSupp::OptionP4UserUser         = { ErrorOf( ES_SUPP, 272, E_INFO, EV_NONE, 0 ), "%'--me'%: Shorthand for -u $P4USER" } ;
ErrorId MsgSupp::OptionAliases            = { ErrorOf( ES_SUPP, 273, E_INFO, EV_NONE, 0 ), "%'--aliases'%: specifies alias-handling behavior." } ;
ErrorId MsgSupp::OptionField		  = { ErrorOf( ES_SUPP, 274, E_INFO, EV_NONE, 0 ), "%'--field'%: Modify spec fields from the command line." } ;
ErrorId MsgSupp::OptionTab                = { ErrorOf( ES_SUPP, 275, E_INFO, EV_NONE, 0 ), "%'--tab[=N] (-T)'%: Align output to tab stops." } ;
ErrorId MsgSupp::OptionForceDelete                = { ErrorOf( ES_SUPP, 277, E_INFO, EV_NONE, 0 ), "%'--force-delete'%: delete entity from protects and groups." } ;
ErrorId MsgSupp::OptionStorageType                = { ErrorOf( ES_SUPP, 278, E_INFO, EV_NONE, 0 ), "%'--type'% (-T): specifies the type of client (writeable/readonly/graph)." } ;
ErrorId MsgSupp::OptionAtomicPush         = { ErrorOf( ES_SUPP, 279, E_INFO, EV_NONE, 0 ), "%'--atomic'%: specifies that all references must pass their checks in order for any reference updates to occur." } ;
ErrorId MsgSupp::OptionColor              = { ErrorOf( ES_SUPP, 281, E_INFO, EV_NONE, 0 ), "%'--color'%: Force color output on the command line." } ;
ErrorId MsgSupp::OptionChangeFiles        = { ErrorOf( ES_SUPP, 282, E_INFO, EV_NONE, 0 ), "%'--show-files'%: specifies to display the individual files." } ;
ErrorId MsgSupp::OptionDiscardArchives    = { ErrorOf( ES_SUPP, 283, E_INFO, EV_NONE, 0 ), "%'--discard-archives=N'%: specifies to discard any packfiles received more than N days ago. Specifying N=0 discards all packfiles except the one(s) just received by this command." } ;
ErrorId MsgSupp::OptionLicenseInfo        = { ErrorOf( ES_SUPP, 284, E_INFO, EV_NONE, 0 ), "%'--license-info'%: report license status information." } ;
ErrorId MsgSupp::OptionRename        = { ErrorOf( ES_SUPP, 290, E_INFO, EV_NONE, 0 ), "%'--rename (-r)'%: rename existing files without changing content." } ;

ErrorId MsgSupp::TooManyLockTrys	  = { ErrorOf( ES_SUPP, 268, E_FATAL, EV_FAULT, 1 ), "Too many trys to get lock %file%." } ;
ErrorId MsgSupp::OptionRemoteUser         = { ErrorOf( ES_SUPP, 289, E_INFO, EV_NONE, 0 ), "%'--remote-user=name'%: specifies the name of the remote user to connect as. This option, if specificed, overrides the RemoteUser: field, if present, in the remote spec." } ;
ErrorId MsgSupp::OptionIgnoreCMap         = { ErrorOf( ES_SUPP, 291, E_INFO, EV_NONE, 0 ), "%'--ignore-changeview'%: Ignore the limits imposed by the changview." } ;
ErrorId MsgSupp::OptionMirror             = { ErrorOf( ES_SUPP, 292, E_INFO, EV_NONE, 0 ), "%'--mirror'%: specifies that this update is for a mirrored repo." } ;
ErrorId MsgSupp::OptionDaemonSafe         = { ErrorOf( ES_SUPP, 293, E_INFO, EV_NONE, 0 ), "%'--daemonsafe'%: Start server as daemon with stdio closed." } ;
ErrorId MsgSupp::OptionTrigger            = { ErrorOf( ES_SUPP, 294, E_INFO, EV_NONE, 0 ), "%'--trigger'%: Pull archive content using an external trigger." } ;
ErrorId MsgSupp::OptionIgnoreHave         = { ErrorOf( ES_SUPP, 295, E_INFO, EV_NONE, 0 ), "%'--ignore-have'%: specifies that the publish option (-p) ignore any have records." } ;
ErrorId MsgSupp::OptionGraphOnly          = { ErrorOf( ES_SUPP, 296, E_INFO, EV_NONE, 0 ), "%'--graph-only'%: skip any non-graph results." } ;
ErrorId MsgSupp::OptionMinSize            = { ErrorOf( ES_SUPP, 297, E_INFO, EV_NONE, 0 ), "%'--min-size'%: Pull archive trigger min file size." } ;
ErrorId MsgSupp::OptionMaxSize            = { ErrorOf( ES_SUPP, 298, E_INFO, EV_NONE, 0 ), "%'--max-size'%: Pull archive trigger max file size." } ;
ErrorId MsgSupp::OptionNameOnly           = { ErrorOf( ES_SUPP, 299, E_INFO, EV_NONE, 0 ), "%'--name-only'%: List only filenames." } ;
ErrorId MsgSupp::OptionNoFastForward      = { ErrorOf( ES_SUPP, 300, E_INFO, EV_NONE, 0 ), "%'--no-ff'%: Create a merge commit even when the merge resolves as a fast-forward." } ;
ErrorId MsgSupp::OptionFastForwardOnly    = { ErrorOf( ES_SUPP, 301, E_INFO, EV_NONE, 0 ), "%'--ff-only'%: Refuse to merge unless the current HEAD is already up-to-date or merge can be resolved as a fast-forward." } ;
ErrorId MsgSupp::OptionMustExist          = { ErrorOf( ES_SUPP, 302, E_INFO, EV_NONE, 0 ), "%'--exists'%: Only output spec if it exists." } ;
ErrorId MsgSupp::OptionRepoName           = { ErrorOf( ES_SUPP, 303, E_INFO, EV_NONE, 0 ), "%'--repo'%: specifies the repo for a non-interactive merge." } ;
ErrorId MsgSupp::OptionTargetBranch       = { ErrorOf( ES_SUPP, 304, E_INFO, EV_NONE, 0 ), "%'--target'%: specifies the target branch for a non-interactive merge." } ;
ErrorId MsgSupp::OptionByUser             = { ErrorOf( ES_SUPP, 305, E_INFO, EV_NONE, 0 ), "%'--user (-u)'%: limit output to repos readable by specified user or group." } ;
ErrorId MsgSupp::OptionByOwner            = { ErrorOf( ES_SUPP, 306, E_INFO, EV_NONE, 0 ), "%'--owner (-O)'%: limit output to repos owned by specified user or group." } ;
ErrorId MsgSupp::OptionSquash             = { ErrorOf( ES_SUPP, 307, E_INFO, EV_NONE, 0 ), "%'--squash'%: Create a single commit on top of the specified branch, with content from the merge." } ;
ErrorId MsgSupp::OptionAllowEmpty         = { ErrorOf( ES_SUPP, 308, E_INFO, EV_NONE, 0 ), "%'--allow-empty'%: allows submitting empty repo commit." } ;
ErrorId MsgSupp::OptionAdded              = { ErrorOf( ES_SUPP, 309, E_INFO, EV_NONE, 0 ), "%'--added (-a)'%: display content of added files." } ;
ErrorId MsgSupp::OptionCreateIndex        = { ErrorOf( ES_SUPP, 310, E_INFO, EV_NONE, 0 ), "%'--create-index'%: create repo index for direct file history access." } ;
ErrorId MsgSupp::OptionDropIndex          = { ErrorOf( ES_SUPP, 311, E_INFO, EV_NONE, 0 ), "%'--drop-index'%: drop repo index." } ;
ErrorId MsgSupp::OptionRepoName2          = { ErrorOf( ES_SUPP, 323, E_INFO, EV_NONE, 0 ), "%'--repo (-n)'%: specifies the repo." } ;
ErrorId MsgSupp::OptionRetry              = { ErrorOf( ES_SUPP, 318, E_INFO, EV_NONE, 0 ), "%'--retry (-R)'%: retry transfer of files that failed to transfer." } ;
ErrorId MsgSupp::OptionReference          = { ErrorOf( ES_SUPP, 325, E_INFO, EV_NONE, 0 ), "%'--reference (-r)'%: specifies the reference." } ;
ErrorId MsgSupp::OptionPerm               = { ErrorOf( ES_SUPP, 326, E_INFO, EV_NONE, 0 ), "%'--permission (-p)'%: specifies the permission." } ;

ErrorId MsgSupp::JsmnBadType              = { ErrorOf( ES_SUPP, 312, E_FAILED, EV_CONFIG, 3 ), "JSON error: token not expected type. Token number %index% Expected type %expected% Observed type %observed%." } ;
ErrorId MsgSupp::JsmnBadParent            = { ErrorOf( ES_SUPP, 313, E_FAILED, EV_CONFIG, 3 ), "JSON error: token does not have the expected parent. Token number %index% Expected parent index %expected% Observed parent index %observed%." } ;
ErrorId MsgSupp::JsmnBadMem               = { ErrorOf( ES_SUPP, 314, E_FAILED, EV_CONFIG, 1 ), "JSON error: parse failed, input has too many tokens. Limit is %limit%." } ;
ErrorId MsgSupp::JsmnBadSyn               = { ErrorOf( ES_SUPP, 315, E_FAILED, EV_CONFIG, 0 ), "JSON error: parse failed, bad syntax." } ;
ErrorId MsgSupp::JsmnTooFew               = { ErrorOf( ES_SUPP, 316, E_FAILED, EV_CONFIG, 0 ), "JSON error: parse failed, missing tokens." } ;
ErrorId MsgSupp::JsmnKeyNotFound          = { ErrorOf( ES_SUPP, 317, E_FAILED, EV_CONFIG, 2 ), "JSON error: not found key name \"%tname%\" in token at index %index%." } ;

// ErrorId graveyard'%: retired/deprecated ErrorIds.

ErrorId MsgSupp::ZCLoadLibFailed       = { ErrorOf( ES_SUPP, 24, E_WARN, EV_ADMIN, 0 ), "Perforce failed to load zeroconf dynamic libraries." } ; // DEPRECATED ZeroConf NOTRANS
ErrorId MsgSupp::ZCInvalidName         = { ErrorOf( ES_SUPP, 25, E_FAILED, EV_USAGE, 1 ), "Invalid name '%name%'." } ; // DEPRECATED ZeroConf NOTRANS
ErrorId MsgSupp::ZCRequireName         = { ErrorOf( ES_SUPP, 26, E_FAILED, EV_USAGE, 0 ), "Perforce requires IDname '-In' to register with zeroconf." } ; // DEPRECATED ZeroConf NOTRANS
ErrorId MsgSupp::ZCNameConflict        = { ErrorOf( ES_SUPP, 27, E_FATAL, EV_ADMIN, 3 ), "*** WARNING duplicate of '%name%' at '%host%:%port%' ***" } ; // DEPRECATED ZeroConf NOTRANS
ErrorId MsgSupp::ZCRegistryFailed      = { ErrorOf( ES_SUPP, 28, E_WARN, EV_ADMIN, 1 ), "Perforce could not register with zeroconf: error is %err%" } ; // DEPRECATED ZeroConf NOTRANS
ErrorId MsgSupp::ZCBrowseFailed        = { ErrorOf( ES_SUPP, 29, E_WARN, EV_ADMIN, 2 ), "Perforce could not browse zeroconf/%implementation%: error is %err%" } ; // DEPRECATED ZeroConf NOTRANS
ErrorId MsgSupp::OptionShowFlags       = { ErrorOf( ES_SUPP, 147, E_INFO, EV_NONE, 0 ), "%'--show-flags (-s)'%: lists the files that satisfy the condition." } ; // NEVER USED NOTRANS
