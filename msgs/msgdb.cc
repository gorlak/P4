/*
 * Copyright 1995, 2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * msgdb.cc - definitions of errors for Db subsystem.
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
 * Current high value for a MsgDb error code is: 93
 */

# include <error.h>
# include <errornum.h>
# include "msgdb.h"

ErrorId MsgDb::JnlEnd                  = { ErrorOf( ES_DB, 1, E_FATAL, EV_ADMIN, 0 ), "End of input in middle of word!" } ;//NOTRANS
ErrorId MsgDb::JnlWord2Big             = { ErrorOf( ES_DB, 2, E_FATAL, EV_ADMIN, 0 ), "Word too big for buffer!" } ;//NOTRANS
ErrorId MsgDb::JnlOct2Long             = { ErrorOf( ES_DB, 3, E_FATAL, EV_ADMIN, 0 ), "Octet stream too long!" } ;//NOTRANS
ErrorId MsgDb::JnlOctSize              = { ErrorOf( ES_DB, 4, E_FATAL, EV_ADMIN, 0 ), "Octet stream size mismatch!" } ;//NOTRANS
ErrorId MsgDb::JnlNum2Big              = { ErrorOf( ES_DB, 5, E_FATAL, EV_ADMIN, 0 ), "Word too big for a number!" } ;//NOTRANS
ErrorId MsgDb::JnlQuoting              = { ErrorOf( ES_DB, 6, E_FATAL, EV_ADMIN, 1 ), "Bad quoting in journal file at line %line%!" } ;//NOTRANS
ErrorId MsgDb::JnlOpcode               = { ErrorOf( ES_DB, 7, E_FATAL, EV_ADMIN, 1 ), "Bad opcode '%operation%' journal record!" } ;//NOTRANS
ErrorId MsgDb::JnlNoVers               = { ErrorOf( ES_DB, 8, E_FATAL, EV_ADMIN, 0 ), "Missing version number in journal record!" } ;//NOTRANS
ErrorId MsgDb::JnlNoName               = { ErrorOf( ES_DB, 9, E_FATAL, EV_ADMIN, 0 ), "Missing table name in journal record!" } ;//NOTRANS
ErrorId MsgDb::JnlNoTVers              = { ErrorOf( ES_DB, 10, E_FATAL, EV_ADMIN, 0 ), "Missing table version in journal record!" } ;//NOTRANS
ErrorId MsgDb::JnlBadVers              = { ErrorOf( ES_DB, 11, E_FATAL, EV_ADMIN, 0 ), "Record version not known in journal record!" } ;//NOTRANS
ErrorId MsgDb::JnlReplay               = { ErrorOf( ES_DB, 12, E_FATAL, EV_ADMIN, 0 ), "Journal record replay failed!" } ;
ErrorId MsgDb::JnlDeleteFailed         = { ErrorOf( ES_DB, 89, E_FATAL, EV_ADMIN, 2 ), "In table %tableName%, the following row was not present or could not be deleted. It may be possible to use the '%'-f'%' flag to proceed beyond this point. Row data: \"%rowData%\"" } ;
ErrorId MsgDb::JnlSeqBad               = { ErrorOf( ES_DB, 13, E_WARN, EV_ADMIN, 1 ), "Journal file '%file%' skipped (out of sequence)." } ;
ErrorId MsgDb::JnlFileBad              = { ErrorOf( ES_DB, 14, E_FATAL, EV_ADMIN, 2 ), "Journal file '%file%' replay failed at line %line%!" } ;
ErrorId MsgDb::JnlBadMarker            = { ErrorOf( ES_DB, 76, E_FATAL, EV_ADMIN, 0 ), "Bad transaction marker!" } ;//NOTRANS
ErrorId MsgDb::JnlCaseUsageBad         = { ErrorOf( ES_DB, 80, E_FATAL, EV_ADMIN, 2 ), "Case-handling mismatch: server uses %caseUsage% but journal flags are %flags%!" } ;
ErrorId MsgDb::JnlVersionMismatch      = { ErrorOf( ES_DB, 81, E_INFO, EV_NONE, 2 ), "Server version %serverVersion% is replaying a version %journalVersion% journal/checkpoint." } ;
ErrorId MsgDb::CheckpointNoOverwrite   = { ErrorOf( ES_DB, 90, E_FATAL, EV_NONE, 0 ), "A full checkpoint should not be replayed into a non-empty database. Please remove the existing %'db.*'% files and retry the operation. The '%'-jrF'%' flag can be specified to bypass this check." } ;
ErrorId MsgDb::TableCheckSum           = { ErrorOf( ES_DB, 84, E_INFO, EV_NONE, 6 ), "Table %table% checksums %result%. %when% version %tableVersion%: expected %expected%, actual %actual%." } ;
ErrorId MsgDb::JnlVersionError         = { ErrorOf( ES_DB, 82, E_FAILED, EV_NONE, 2 ), "Server version %serverVersion% cannot replay a version %journalVersion% journal/checkpoint." } ;
ErrorId MsgDb::DbOpen                  = { ErrorOf( ES_DB, 15, E_FATAL, EV_ADMIN, 1 ), "Database open error on %table%!" } ;
ErrorId MsgDb::WriteNoLock             = { ErrorOf( ES_DB, 16, E_FATAL, EV_FAULT, 1 ), "dbput %table%: no write lock!" } ;//NOTRANS
ErrorId MsgDb::Write                   = { ErrorOf( ES_DB, 17, E_FATAL, EV_FAULT, 1 ), "Database write error on %table%!" } ;//NOTRANS
ErrorId MsgDb::ReadNoLock              = { ErrorOf( ES_DB, 18, E_FATAL, EV_FAULT, 1 ), "dbget %table%: no read lock!" } ;//NOTRANS
ErrorId MsgDb::Read                    = { ErrorOf( ES_DB, 19, E_FATAL, EV_FAULT, 1 ), "Database get error on %table%!" } ;//NOTRANS
ErrorId MsgDb::Stumblebum              = { ErrorOf( ES_DB, 20, E_FATAL, EV_ADMIN, 0 ), "Database must be 98.1 through " ID_REL " format." } ;//NOTRANS
ErrorId MsgDb::GetFormat               = { ErrorOf( ES_DB, 21, E_FATAL, EV_FAULT, 2 ), "dbget: %table% record format %level% unsupported!" } ;//NOTRANS
ErrorId MsgDb::ScanNoLock              = { ErrorOf( ES_DB, 22, E_FATAL, EV_FAULT, 1 ), "dbscan %table%: no read lock!" } ;//NOTRANS
ErrorId MsgDb::Scan                    = { ErrorOf( ES_DB, 23, E_FATAL, EV_FAULT, 1 ), "Database scan error on %table%!" } ;//NOTRANS
ErrorId MsgDb::ScanFormat              = { ErrorOf( ES_DB, 24, E_FATAL, EV_FAULT, 2 ), "dbscan: %table% record format %level% unsupported!" } ;//NOTRANS
ErrorId MsgDb::DelNoLock               = { ErrorOf( ES_DB, 25, E_FATAL, EV_FAULT, 1 ), "dbdel %table%: no write lock!" } ;//NOTRANS
ErrorId MsgDb::Delete                  = { ErrorOf( ES_DB, 26, E_FATAL, EV_FAULT, 1 ), "Database delete error on %table%!" } ;//NOTRANS
ErrorId MsgDb::Locking                 = { ErrorOf( ES_DB, 27, E_FATAL, EV_FAULT, 1 ), "Database locking error on %table%!" } ;//NOTRANS
ErrorId MsgDb::EndXact                 = { ErrorOf( ES_DB, 28, E_FATAL, EV_FAULT, 1 ), "End xact with %table% still locked!" } ;//NOTRANS
ErrorId MsgDb::GetNoGet                = { ErrorOf( ES_DB, 64, E_FATAL, EV_FAULT, 1 ), "GetDb of %table% without prior get!" } ;//NOTRANS
ErrorId MsgDb::ValidationFoundProblems = { ErrorOf( ES_DB, 86, E_FAILED, EV_ADMIN, 1 ), "Problems were found in %numTables% table(s)." } ;
ErrorId MsgDb::TableUnknown            = { ErrorOf( ES_DB, 29, E_FAILED, EV_USAGE, 1 ), "Table %table% not known." } ;
ErrorId MsgDb::TableObsolete           = { ErrorOf( ES_DB, 78, E_FAILED, EV_USAGE, 1 ), "Table %table% is obsolete." } ;
ErrorId MsgDb::LockOrder               = { ErrorOf( ES_DB, 30, E_FATAL, EV_FAULT, 2 ), "Locking failure: %table% locked after %table2%!" } ;//NOTRANS
ErrorId MsgDb::LockUpgrade             = { ErrorOf( ES_DB, 31, E_FATAL, EV_FAULT, 1 ), "Locking failure: no upgrading %table%'s lock!" } ;//NOTRANS
ErrorId MsgDb::MaxMemory               = { ErrorOf( ES_DB, 33, E_FATAL, EV_TOOBIG, 0 ), "Request too large for server memory (try later?)." } ;//NOTRANS
ErrorId MsgDb::KeyTooBig               = { ErrorOf( ES_DB, 34, E_FATAL, EV_FAULT, 0 ), "Record key exceeds max size!" } ;//NOTRANS
ErrorId MsgDb::XactOutstandingRestart  = { ErrorOf( ES_DB, 85, E_INFO, EV_NONE, 1 ), "Server restarted while %count% transaction(s) outstanding." } ;
                               
ErrorId MsgDb::ExtraDots               = { ErrorOf( ES_DB, 35, E_FAILED, EV_USAGE, 1 ), "Only three %'...'% permitted in '%arg%'." } ;
ErrorId MsgDb::ExtraStars              = { ErrorOf( ES_DB, 36, E_FAILED, EV_USAGE, 1 ), "Too many %'*'%'s in '%arg%'." } ;//CONTENTIOUS
ErrorId MsgDb::Duplicate               = { ErrorOf( ES_DB, 37, E_FAILED, EV_USAGE, 1 ), "Duplicate wildcards in '%arg%'." } ;
ErrorId MsgDb::WildMismatch            = { ErrorOf( ES_DB, 38, E_FAILED, EV_USAGE, 2 ), "Incompatible wildcards '%arg%' %'<->'% '%arg2%'." } ;
ErrorId MsgDb::TooWild                 = { ErrorOf( ES_DB, 73, E_FAILED, EV_TOOBIG, 0 ), "Excessive combinations of wildcard %'...'% in path and maps." } ;
ErrorId MsgDb::TooWild2                 = { ErrorOf( ES_DB, 79, E_FAILED, EV_TOOBIG, 0 ), "Excessive combinations of wildcards in path and maps." } ;
ErrorId MsgDb::Juxtaposed              = { ErrorOf( ES_DB, 74, E_FAILED, EV_TOOBIG, 1 ), "Senseless juxtaposition of wildcards in '%arg%'." } ;
                               
ErrorId MsgDb::ParseErr                = { ErrorOf( ES_DB, 41, E_FAILED, EV_USAGE, 1 ), "Expression parse error at '%line%'." } ;
                               
ErrorId MsgDb::Field2Many              = { ErrorOf( ES_DB, 42, E_FAILED, EV_USAGE, 1 ), "Too many entries for field '%field%'." } ;
ErrorId MsgDb::FieldBadVal             = { ErrorOf( ES_DB, 43, E_FAILED, EV_USAGE, 2 ), "Value for field '%field%' must be one of %text%." } ;
ErrorId MsgDb::FieldWords              = { ErrorOf( ES_DB, 44, E_FAILED, EV_USAGE, 1 ), "Wrong number of words for field '%field%'." } ;
ErrorId MsgDb::FieldMissing            = { ErrorOf( ES_DB, 45, E_FAILED, EV_USAGE, 1 ), "Missing required field '%field%'." } ;
ErrorId MsgDb::FieldBadIndex           = { ErrorOf( ES_DB, 46, E_FAILED, EV_USAGE, 0 ), "Can't find numbered field in spec." } ;
ErrorId MsgDb::FieldUnknown            = { ErrorOf( ES_DB, 47, E_FAILED, EV_USAGE, 1 ), "Unknown field name '%field%'." } ;
ErrorId MsgDb::FieldTypeBad            = { ErrorOf( ES_DB, 48, E_FAILED, EV_USAGE, 2 ), "Unknown type '%type%' for field '%field%'." } ;
ErrorId MsgDb::FieldOptBad             = { ErrorOf( ES_DB, 49, E_FAILED, EV_USAGE, 2 ), "Unknown option '%option%' for field '%field%'." } ;
ErrorId MsgDb::NoEndQuote              = { ErrorOf( ES_DB, 63, E_FAILED, EV_USAGE, 1 ), "No matching end quote in '%value%'." } ;
ErrorId MsgDb::Syntax                  = { ErrorOf( ES_DB, 50, E_FAILED, EV_USAGE, 1 ), "Syntax error in '%value%'." } ;
ErrorId MsgDb::LineNo                  = { ErrorOf( ES_DB, 51, E_FAILED, EV_USAGE, 1 ), "Error detected at line %line%." } ;
                               
ErrorId MsgDb::LicenseExp              = { ErrorOf( ES_DB, 52, E_FAILED, EV_ADMIN, 0 ), "License expired." } ;
ErrorId MsgDb::SupportExp              = { ErrorOf( ES_DB, 53, E_FAILED, EV_ADMIN, 0 ), "Support expired." } ;
ErrorId MsgDb::ServerTooNew            = { ErrorOf( ES_DB, 54, E_FAILED, EV_ADMIN, 0 ), "Server newer than current date." } ;
ErrorId MsgDb::MustExpire              = { ErrorOf( ES_DB, 55, E_FAILED, EV_ADMIN, 0 ), "License must expire." } ;
ErrorId MsgDb::Checksum                = { ErrorOf( ES_DB, 56, E_FAILED, EV_ADMIN, 0 ), "Invalid checksum string." } ;
ErrorId MsgDb::WrongApp                = { ErrorOf( ES_DB, 57, E_FAILED, EV_ADMIN, 1 ), "This server is only licensed for %users% use." } ;
ErrorId MsgDb::PlatPre972              = { ErrorOf( ES_DB, 58, E_FAILED, EV_UPGRADE, 0 ), "Can't have platforms for pre-97.2 servers." } ;
ErrorId MsgDb::LicenseRead             = { ErrorOf( ES_DB, 59, E_FAILED, EV_ADMIN, 0 ), "Error reading license file." } ;
ErrorId MsgDb::LicenseBad              = { ErrorOf( ES_DB, 60, E_FAILED, EV_ADMIN, 0 ), "License file invalid." } ;
ErrorId MsgDb::AddressChanged          = { ErrorOf( ES_DB, 75, E_FAILED, EV_ADMIN, 0 ), "Server license %'IP'%address changed, cannot proceed." } ;
ErrorId MsgDb::LicenseNeedsApplication = { ErrorOf( ES_DB, 83, E_FAILED, EV_ADMIN, 0 ), "License needs an application." } ;
ErrorId MsgDb::BadIPservice            = { ErrorOf( ES_DB, 88, E_FAILED, EV_ADMIN, 0 ), "Licensed client service cannot be %'localhost'% %'(127.0.0.1'% or %'::1)'%" } ;//CONTENTIOS

ErrorId MsgDb::TreeCorrupt	       = { ErrorOf( ES_DB, 66, E_FATAL, EV_FAULT, 0 ), "BTree is corrupt!" } ;
ErrorId MsgDb::TreeNotOpened	       = { ErrorOf( ES_DB, 67, E_FATAL, EV_FAULT, 0 ), "BTree could not be opened or created!" } ;//NOTRANS
ErrorId MsgDb::InternalUsage	       = { ErrorOf( ES_DB, 68, E_FATAL, EV_FAULT, 0 ), "Internal BTree usage is not supported!" } ;//NOTRANS
ErrorId MsgDb::TreeAllocation	       = { ErrorOf( ES_DB, 69, E_FATAL, EV_FAULT, 0 ), "Allocation failure in db!" } ;//NOTRANS
ErrorId MsgDb::TreeNotSupported	       = { ErrorOf( ES_DB, 70, E_FATAL, EV_FAULT, 0 ), "BTree variation is not supported!" } ;//NOTRANS
ErrorId MsgDb::TreeAlreadyUpgraded     = { ErrorOf( ES_DB, 87, E_FATAL, EV_FAULT, 0 ), "BTree has already been accessed by a later version of the Perforce server!" } ;
ErrorId MsgDb::TreeInternal	       = { ErrorOf( ES_DB, 71, E_FATAL, EV_FAULT, 0 ), "Internal BTree system failure!" } ;//NOTRANS
ErrorId MsgDb::TreeNewerVersion	       = { ErrorOf( ES_DB, 91, E_FATAL, EV_FAULT, 1 ), "BTree %file% from a newer server version" } ;
ErrorId MsgDb::TreeOlderVersion	       = { ErrorOf( ES_DB, 92, E_FATAL, EV_FAULT, 1 ), "BTree %file% from an older server version - 2013.2 or earlier" } ;
ErrorId MsgDb::DoNotBlameTheDb         = { ErrorOf( ES_DB, 93, E_FATAL, EV_FAULT, 0 ), "Error object passed to database already set with an error" } ;

ErrorId MsgDb::MapCheckFail	       = { ErrorOf( ES_DB, 72, E_FAILED, EV_TOOBIG, 0 ), "%'MapCheck'% rejected too many rows." } ;

ErrorId MsgDb::CaseMismatch	       = { ErrorOf( ES_DB, 77, E_FATAL, EV_FAULT, 0 ), "BTree Case Order Mismatch! Check %'p4d -Cx'% flag usage." } ;

// ErrorId graveyard: retired/deprecated ErrorIds. 

ErrorId MsgDb::MaxResults              = { ErrorOf( ES_DB, 32, E_FAILED, EV_ADMIN, 1 ), "Request too large (over %maxResults%); see 'p4 help maxresults'." } ;//NOTRANS
ErrorId MsgDb::MaxScanRows             = { ErrorOf( ES_DB, 61, E_FAILED, EV_ADMIN, 1 ), "Too many rows scanned (over %maxScanRows%); see 'p4 help maxscanrows'." } ;//NOTRANS
ErrorId MsgDb::NotUnderRoot            = { ErrorOf( ES_DB, 39, E_FAILED, EV_CONTEXT, 2 ), "Path '%path%' is not under client's root '%root%'." } ;//NOTRANS
ErrorId MsgDb::NotUnderClient          = { ErrorOf( ES_DB, 40, E_FAILED, EV_CONTEXT, 2 ), "Path '%path%' is not under client '%client%'." } ;//NOTRANS
ErrorId MsgDb::ClientGone              = { ErrorOf( ES_DB, 62, E_FATAL, EV_ADMIN, 0 ), "Client has dropped connection, terminating request." } ;//NOTRANS
ErrorId MsgDb::CommandCancelled        = { ErrorOf( ES_DB, 62, E_FATAL, EV_ADMIN, 0 ), "Command has been cancelled, terminating request." } ;//NOTRANS
ErrorId MsgDb::DbStat                  = { ErrorOf( ES_DB, 65, E_INFO, EV_NONE, 4 ), "--- %table% pos %position% get %get% scan %scan%" };//NOTRANS
