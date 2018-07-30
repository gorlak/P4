/*
 * Copyright 1995, 2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * msgdm.cc - definitions of errors for data manager core subsystem.
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
 * Current high value for a MsgDm error code is: 963
 */

# include <error.h>
# include <errornum.h>
# include <msgdm.h>

// This is only for work in progress and should not be in released code, since it's untranslated.
ErrorId MsgDm::DevMsg                  = { ErrorOf( ES_DM, 902, E_INFO, EV_NONE, 1 ), "%text%" }; // NOTRANS
// This is fine in released code, but only for internal error conditions that we do not expect users to ever encounter.
ErrorId MsgDm::DevErr                  = { ErrorOf( ES_DM, 903, E_FATAL, EV_FAULT, 1 ), "Internal error: %text%" }; // NOTRANS

// MARK MEARS add delimiters below this line
                               
ErrorId MsgDm::CheckFailed             = { ErrorOf( ES_DM, 1, E_FAILED, EV_FAULT, 2 ), "%table%/%table2% inconsistencies found." } ;
ErrorId MsgDm::InvalidType             = { ErrorOf( ES_DM, 2, E_FAILED, EV_USAGE, 2 ), "Invalid %type% '%arg%'." } ;
ErrorId MsgDm::IdTooLong               = { ErrorOf( ES_DM, 3, E_FAILED, EV_USAGE, 0 ), "Identifiers too long.  Must not be longer than 1024 bytes of UTF-8." } ;
ErrorId MsgDm::LineTooLong             = { ErrorOf( ES_DM, 673, E_FAILED, EV_USAGE, 1 ), "Logfile line too long. Maximum length is %maxLineLen%. This length can be increased by setting the filesys.bufsize configurable." };
ErrorId MsgDm::NoSuchServerlog         = { ErrorOf( ES_DM, 714, E_FAILED, EV_UNKNOWN, 1 ), "No such logfile '%logfile%'." } ;
ErrorId MsgDm::IdHasDash               = { ErrorOf( ES_DM, 4, E_FAILED, EV_USAGE, 1 ), "Initial dash character not allowed in '%id%'." } ;
ErrorId MsgDm::IdEmpty                 = { ErrorOf( ES_DM, 5, E_FAILED, EV_USAGE, 0 ), "Empty identifier not allowed." } ;
ErrorId MsgDm::IdNonPrint              = { ErrorOf( ES_DM, 6, E_FAILED, EV_USAGE, 1 ), "Non-printable characters not allowed in '%id%'." } ;
ErrorId MsgDm::IdHasRev                = { ErrorOf( ES_DM, 7, E_FAILED, EV_USAGE, 1 ), "Revision chars (@, #) not allowed in '%id%'." } ;
ErrorId MsgDm::IdHasSlash              = { ErrorOf( ES_DM, 8, E_FAILED, EV_USAGE, 1 ), "Slashes (/) not allowed in '%id%'." } ;
ErrorId MsgDm::IdHasComma              = { ErrorOf( ES_DM, 485, E_FAILED, EV_USAGE, 1 ), "Commas (,) not allowed in '%id%'." } ;
ErrorId MsgDm::IdHasPercent              = { ErrorOf( ES_DM, 642, E_FAILED, EV_USAGE, 1 ), "Percent character not allowed in '%id%'." } ;
ErrorId MsgDm::IdNullDir               = { ErrorOf( ES_DM, 9, E_FAILED, EV_USAGE, 1 ), "Null directory (//) not allowed in '%id%'." } ;
ErrorId MsgDm::IdRelPath               = { ErrorOf( ES_DM, 10, E_FAILED, EV_USAGE, 1 ), "Relative paths (., ..) not allowed in '%id%'." } ;
ErrorId MsgDm::IdWild                  = { ErrorOf( ES_DM, 11, E_FAILED, EV_USAGE, 1 ), "Wildcards (*, %%%%x, ...) not allowed in '%id%'." } ;
ErrorId MsgDm::IdNumber                = { ErrorOf( ES_DM, 12, E_FAILED, EV_USAGE, 1 ), "Purely numeric name not allowed - '%id%'." } ;
ErrorId MsgDm::IdEmbeddedNul           = { ErrorOf( ES_DM, 749, E_FAILED, EV_USAGE, 1 ), "Embedded null bytes not allowed - '%id%'." } ;
ErrorId MsgDm::BadOption               = { ErrorOf( ES_DM, 13, E_FAILED, EV_USAGE, 2 ), "Invalid option '%option%' in %field% option field." } ;
ErrorId MsgDm::BadChange               = { ErrorOf( ES_DM, 14, E_FAILED, EV_USAGE, 1 ), "Invalid changelist number '%change%'." } ;
ErrorId MsgDm::BadMaxResult            = { ErrorOf( ES_DM, 15, E_FAILED, EV_USAGE, 1 ), "Invalid maximum value '%value%'." } ;
ErrorId MsgDm::BadTimeout              = { ErrorOf( ES_DM, 422, E_FAILED, EV_USAGE, 1 ), "Invalid Timeout value '%value%'." } ;
ErrorId MsgDm::BadRevision             = { ErrorOf( ES_DM, 17, E_FAILED, EV_USAGE, 1 ), "Invalid revision number '%rev%'." } ;
ErrorId MsgDm::BadTypeMod              = { ErrorOf( ES_DM, 18, E_FAILED, EV_USAGE, 1 ), "Invalid file type modifier on '%arg%'; see '%'p4 help filetypes'%'." } ;
ErrorId MsgDm::BadStorageCombo         = { ErrorOf( ES_DM, 19, E_FAILED, EV_USAGE, 1 ), "Only one storage modifier +C +D +F or +S allowed on '%arg%'." } ;
ErrorId MsgDm::BadVersionCount         = { ErrorOf( ES_DM, 460, E_FAILED, EV_USAGE, 1 ), "Bad version count '+S%count%', only values 1-10,16,32,64,128,256,512 allowed." } ;
ErrorId MsgDm::BadTypeCombo            = { ErrorOf( ES_DM, 20, E_FAILED, EV_USAGE, 2 ), "Disallowed modifier (%option%) on '%arg%'; see '%'p4 help filetypes'%'." } ;
ErrorId MsgDm::BadType                 = { ErrorOf( ES_DM, 21, E_FAILED, EV_USAGE, 1 ), "Invalid file type '%type%'; see '%'p4 help filetypes'%'." } ;
ErrorId MsgDm::BadDigest               = { ErrorOf( ES_DM, 418, E_FAILED, EV_USAGE, 1 ), "Invalid digest string '%digest%'." } ;
ErrorId MsgDm::BadTypePartial          = { ErrorOf( ES_DM, 435, E_FAILED, EV_USAGE, 0 ), "A partial file type is not allowed here." };
ErrorId MsgDm::BadTypeAuto	       = { ErrorOf( ES_DM, 624, E_FAILED, EV_USAGE, 0 ), "Automatic type detection is not allowed here." };
ErrorId MsgDm::NeedsUpgrades           = { ErrorOf( ES_DM, 22, E_FAILED, EV_ADMIN, 3 ), "Database is at old upgrade level %level%.  Use '%'p4d -r '%%root%%' -xu'%' to upgrade to level %level2%." } ;
ErrorId MsgDm::PastUpgrade             = { ErrorOf( ES_DM, 23, E_FAILED, EV_ADMIN, 2 ), "Database is at upgrade level %level% past this server's level %level2%." } ;
ErrorId MsgDm::Unicode                 = { ErrorOf( ES_DM, 24, E_FAILED, EV_ADMIN, 1 ), "Database has %value% tables with non-UTF8 text and can't be switched to Unicode mode." } ;
                               
ErrorId MsgDm::DescMissing             = { ErrorOf( ES_DM, 25, E_FATAL, EV_FAULT, 1 ), "%key% description missing!" } ;
ErrorId MsgDm::NoSuchChange            = { ErrorOf( ES_DM, 26, E_FAILED, EV_UNKNOWN, 1 ), "%change% unknown." } ;
ErrorId MsgDm::AlreadyCommitted        = { ErrorOf( ES_DM, 27, E_FAILED, EV_CONTEXT, 1 ), "%change% is already committed." } ;
ErrorId MsgDm::WrongClient             = { ErrorOf( ES_DM, 28, E_FAILED, EV_CONTEXT, 2 ), "%change% belongs to client %client%." } ;
ErrorId MsgDm::WrongUser               = { ErrorOf( ES_DM, 29, E_FAILED, EV_CONTEXT, 2 ), "%change% belongs to user %user%." } ;
ErrorId MsgDm::NoSuchCounter           = { ErrorOf( ES_DM, 30, E_FAILED, EV_UNKNOWN, 1 ), "No such counter '%counter%'." } ;
ErrorId MsgDm::NoSuchKey           = { ErrorOf( ES_DM, 643, E_FAILED, EV_UNKNOWN, 1 ), "No such key '%key%'." } ;
ErrorId MsgDm::NotThatCounter          = { ErrorOf( ES_DM, 31, E_FAILED, EV_USAGE, 1 ), "Too dangerous to touch counter '%counter%'." } ;
ErrorId MsgDm::MayNotBeNegative        = { ErrorOf( ES_DM, 615, E_FAILED, EV_USAGE, 1 ), "Negative value not allowed for counter '%counter%'." } ;
ErrorId MsgDm::MustBeNumeric           = { ErrorOf( ES_DM, 617, E_FAILED, EV_USAGE, 1 ), "Non-numeric value not allowed for counter '%counter%'." } ;
ErrorId MsgDm::NoSuchDepot             = { ErrorOf( ES_DM, 32, E_FAILED, EV_UNKNOWN, 1 ), "Depot '%depot%' doesn't exist." } ;
ErrorId MsgDm::NoSuchDepot2            = { ErrorOf( ES_DM, 33, E_FAILED, EV_UNKNOWN, 1 ), "Depot '%depot%' unknown - use '%'depot'%' to create it." } ;
ErrorId MsgDm::NoSuchDomain            = { ErrorOf( ES_DM, 34, E_FAILED, EV_UNKNOWN, 2 ), "%type% '%name%' doesn't exist." } ;
ErrorId MsgDm::NoSuchDomain2           = { ErrorOf( ES_DM, 35, E_FAILED, EV_UNKNOWN, 3 ), "%type% '%name%' unknown - use '%command%' command to create it." } ;
ErrorId MsgDm::WrongDomain             = { ErrorOf( ES_DM, 36, E_FAILED, EV_CONTEXT, 3 ), "%name% is a %type%, not a %type2%." } ;
ErrorId MsgDm::TooManyClients          = { ErrorOf( ES_DM, 37, E_FAILED, EV_ADMIN, 0 ), "Can't add client - over license quota." } ;
ErrorId MsgDm::NoSuchJob               = { ErrorOf( ES_DM, 38, E_FAILED, EV_UNKNOWN, 1 ), "Job '%job%' doesn't exist." } ;
ErrorId MsgDm::NoSuchJob2              = { ErrorOf( ES_DM, 39, E_FAILED, EV_UNKNOWN, 1 ), "Job '%job%' unknown - use 'job' to create it." } ;
ErrorId MsgDm::NoSuchFix               = { ErrorOf( ES_DM, 40, E_FAILED, EV_UNKNOWN, 0 ), "No such fix." } ;
ErrorId MsgDm::NoPerms                 = { ErrorOf( ES_DM, 41, E_FAILED, EV_PROTECT, 0 ), "You don't have permission for this operation." } ;
ErrorId MsgDm::OperatorNotAllowed      = { ErrorOf( ES_DM, 632, E_FAILED, EV_PROTECT, 2 ), "Operator user %userName% may not perform operation %funcName%" } ;
ErrorId MsgDm::NoSuchRelease           = { ErrorOf( ES_DM, 537, E_FAILED, EV_USAGE, 1 ), "There was no Perforce release named '%release%'." } ;
ErrorId MsgDm::ClientTooOld            = { ErrorOf( ES_DM, 538, E_FAILED, EV_USAGE, 0 ), "You may not set %'minClient'% to a release newer than your client." } ;
ErrorId MsgDm::NoProtect               = { ErrorOf( ES_DM, 123, E_FAILED, EV_PROTECT, 1 ), "Access for user '%user%' has not been enabled by '%'p4 protect'%'." };
ErrorId MsgDm::PathNotUnder            = { ErrorOf( ES_DM, 42, E_FAILED, EV_CONTEXT, 2 ), "Path '%depotFile%' is not under '%prefix%'." } ;
ErrorId MsgDm::TooManyUsers            = { ErrorOf( ES_DM, 43, E_FAILED, EV_ADMIN, 0 ), "Can't create a new user - over license quota." } ;
ErrorId MsgDm::MapNotUnder             = { ErrorOf( ES_DM, 44, E_FAILED, EV_CONTEXT, 2 ), "Mapping '%depotFile%' is not under '%prefix%'." } ;
ErrorId MsgDm::MapNoListAccess         = { ErrorOf( ES_DM, 432, E_FAILED, EV_CONTEXT, 0 ), "User does not have list access for mapped depots." } ;
                               
                               
ErrorId MsgDm::DepotMissing            = { ErrorOf( ES_DM, 45, E_FATAL, EV_FAULT, 1 ), "Depot %depot% missing from depot table!" } ;     // NOTRANS
ErrorId MsgDm::UnloadNotOwner          = { ErrorOf( ES_DM, 708, E_FAILED, EV_USAGE, 1 ), "Client, label, or task stream %domainName% is not owned by you." } ;
ErrorId MsgDm::UnloadNotPossible       = { ErrorOf( ES_DM, 776, E_FAILED, EV_USAGE, 2 ), "%domainType% %domainName% has file(s) exclusively or globally opened or has promoted shelves, and may not be unloaded. Revert these opened files and delete the promoted shelves, then retry the unload." } ;
ErrorId MsgDm::ReloadNotOwner          = { ErrorOf( ES_DM, 709, E_FAILED, EV_USAGE, 1 ), "Unloaded client, label, or task stream %domainName% is not owned by you." } ;
ErrorId MsgDm::UnloadDepotMissing      = { ErrorOf( ES_DM, 707, E_FAILED, EV_USAGE, 0 ), "No unload depot has been defined for this server." } ;
ErrorId MsgDm::UnloadData              = { ErrorOf( ES_DM, 715, E_INFO, EV_NONE, 2 ), "%object% %name% unloaded." } ;
ErrorId MsgDm::ReloadData              = { ErrorOf( ES_DM, 716, E_INFO, EV_NONE, 2 ), "%object% %name% reloaded." } ;
ErrorId MsgDm::DepotVsDomains          = { ErrorOf( ES_DM, 46, E_FATAL, EV_FAULT, 0 ), "Depot and domains table out of sync!" } ;    // NOTRANS
ErrorId MsgDm::RevVsRevCx              = { ErrorOf( ES_DM, 47, E_FATAL, EV_FAULT, 0 ), "Revision table out of sync with index!" } ;  // NOTRANS
ErrorId MsgDm::NoPrevRev               = { ErrorOf( ES_DM, 616, E_INFO, EV_NONE, 2 ), "Unable to show the differences for file %depotFile% because the revision prior to %depotRev% is missing from the revisions table. If the prior revisions of this file were obliterated, this is a normal situation; otherwise it may indicate repository damage and should be investigated further." } ;
ErrorId MsgDm::CantFindChange          = { ErrorOf( ES_DM, 49, E_FATAL, EV_FAULT, 1 ), "Can't find %change%!" } ;
ErrorId MsgDm::BadIntegFlag            = { ErrorOf( ES_DM, 50, E_FATAL, EV_FAULT, 0 ), "DmtIntegData unknown DBT_OPEN_FLAG!" } ;
ErrorId MsgDm::BadJobTemplate          = { ErrorOf( ES_DM, 51, E_FATAL, EV_FAULT, 0 ), "Job template unusable!" } ;                   // NOTRANS
ErrorId MsgDm::NeedJobUpgrade          = { ErrorOf( ES_DM, 52, E_FATAL, EV_ADMIN, 0 ), "Jobs database must be upgraded with '%'p4 jobs -R'%'!" } ;
ErrorId MsgDm::BadJobPresets           = { ErrorOf( ES_DM, 53, E_FATAL, EV_ADMIN, 0 ), "Presets in jobspec unusable!" } ;             // NOTRANS
ErrorId MsgDm::JobNameMissing          = { ErrorOf( ES_DM, 54, E_FATAL, EV_ADMIN, 0 ), "Missing job name field!" } ;
ErrorId MsgDm::HaveVsRev               = { ErrorOf( ES_DM, 55, E_FATAL, EV_FAULT, 1 ), "File %depotFile% isn't in revisions table!" } ;   // NOTRANS
ErrorId MsgDm::AddHaveVsRev               = { ErrorOf( ES_DM, 792, E_FAILED, EV_FAULT, 1 ), "File %depotFile% isn't in revisions table. The file may have been obliterated by an administrator. Make a backup copy of your local file before proceeding. Then use 'p4 sync' to synchronize your client state with the server. Then copy the desired file back into your workspace location. Then retry the add." } ; // NOTRANS
ErrorId MsgDm::ReloadSuspicious         = { ErrorOf( ES_DM, 800, E_FAILED, EV_USAGE, 1 ), "Input file contains an incorrect record for %tableName%." } ;   // NOTRANS
ErrorId MsgDm::BadOpenFlag             = { ErrorOf( ES_DM, 56, E_FATAL, EV_FAULT, 0 ), "DmOpenData unhandled DBT_OPEN_FLAG!" } ;     // NOTRANS
ErrorId MsgDm::NameChanged             = { ErrorOf( ES_DM, 57, E_FATAL, EV_FAULT, 1 ), "File %depotFile% changed it's name!" } ;     // NOTRANS
ErrorId MsgDm::WorkingVsLocked         = { ErrorOf( ES_DM, 58, E_FATAL, EV_FAULT, 0 ), "Working and locked tables out of sync!" } ;   // NOTRANS
ErrorId MsgDm::IntegVsRev              = { ErrorOf( ES_DM, 59, E_FATAL, EV_FAULT, 1 ), "%depotFile% is missing from the rev table!" } ;  // NOTRANS
ErrorId MsgDm::IntegVsWork             = { ErrorOf( ES_DM, 60, E_FATAL, EV_FAULT, 1 ), "%depotFile% is missing from the working table!" } ;   // NOTRANS
ErrorId MsgDm::ConcurrentFileChange    = { ErrorOf( ES_DM, 640, E_FAILED, EV_USAGE, 1 ), "%depotFile% was altered during the course of the submit. Verify the contents of the changelist and retry the submit." } ;
ErrorId MsgDm::AtMostOne               = { ErrorOf( ES_DM, 61, E_FAILED, EV_NOTYET, 1 ), "In the change being submitted, %depotFile% has more than one 'branch' or 'delete' integration. Use '%'p4 resolved'%' to display the integrations that are contained in this change. Revert any file(s) containing multiple 'branch' or 'delete' integrations. Then re-integrate those files containing at most one such integration. Then retry the submit." } ;
ErrorId MsgDm::IntegVsShelve              = { ErrorOf( ES_DM, 631, E_FAILED, EV_FAULT, 2 ), "%depotFile%%rev%: can't resolve (shelved change was deleted); must %'revert'%, or %'revert -k'% and edit before submit." } ;
                               
ErrorId MsgDm::MissingDesc             = { ErrorOf( ES_DM, 62, E_FAILED, EV_USAGE, 0 ), "Change description missing.  You must enter one." } ;
ErrorId MsgDm::BadJobView              = { ErrorOf( ES_DM, 63, E_FAILED, EV_CONFIG, 0 ), "Invalid JobView.  Set with '%'p4 user'%'." } ;
ErrorId MsgDm::NoModComChange          = { ErrorOf( ES_DM, 64, E_FAILED, EV_CONTEXT, 1 ), "Can't update committed change %change%." } ;
ErrorId MsgDm::TheseCantChange         = { ErrorOf( ES_DM, 65, E_FAILED, EV_ILLEGAL, 0 ), "Client and status cannot be changed." } ;
ErrorId MsgDm::OwnerCantChange	       = { ErrorOf( ES_DM, 467, E_FAILED, EV_ILLEGAL, 0 ), "Client, user, date and status cannot be changed." };
ErrorId MsgDm::UserCantChange	       = { ErrorOf( ES_DM, 750, E_FAILED, EV_ILLEGAL, 0 ), "User cannot be changed in a committed change." };
ErrorId MsgDm::OpenFilesCantChange     = { ErrorOf( ES_DM, 473, E_FAILED, EV_ILLEGAL, 0 ), "Change has files open, client cannot be modified." };
ErrorId MsgDm::OpenFilesCantChangeUser = { ErrorOf( ES_DM, 509, E_FAILED, EV_ILLEGAL, 0 ), "Change has files open, user cannot be modified." };
ErrorId MsgDm::CantOpenHere            = { ErrorOf( ES_DM, 66, E_FAILED, EV_ILLEGAL, 0 ), "Can't include file(s) not already opened.\nOpen new files with %'p4 add'%, %'p4 edit'%, etc." } ;
ErrorId MsgDm::OpenAttrRO	       = { ErrorOf( ES_DM, 687, E_FAILED, EV_ILLEGAL, 2 ), "%file% - can't %action% file with propagating attributes from an edge server" } ;
ErrorId MsgDm::ReconcileBadName        = { ErrorOf( ES_DM, 676, E_WARN, EV_ILLEGAL, 1 ), "%file% - can't %'reconcile'% filename with illegal characters." } ;
ErrorId MsgDm::ReconcileNeedForce      = { ErrorOf( ES_DM, 677, E_WARN, EV_ILLEGAL, 1 ), "%file% - can't %'reconcile'% filename with wildcards [@#%%*]. Use -f to force %'reconcile'%." } ;
ErrorId MsgDm::StatusSuccess             = { ErrorOf( ES_DM, 684, E_INFO, EV_NONE, 4 ), "%localfile% - reconcile to %action% %depotFile%%workRev%" } ;
ErrorId MsgDm::StatusOpened             = { ErrorOf( ES_DM, 852, E_INFO, EV_NONE, 5 ), "%localfile% - submit change %change% to %action% %depotFile%%workRev%" } ;
ErrorId MsgDm::PurgeFirst              = { ErrorOf( ES_DM, 67, E_FAILED, EV_NOTYET, 1 ), "Depot %depot% isn't empty. To delete a depot, all file revisions must be removed and all lazy copy references from other depots must be severed. Use '%'p4 obliterate'%' or '%'p4 snap'%' to break file linkages from other depots, then clear this depot with '%'p4 obliterate'%', then retry the deletion." } ;
ErrorId MsgDm::SnapFirst               = { ErrorOf( ES_DM, 619, E_FAILED, EV_NOTYET, 1 ), "Depot %depot% isn't empty of archive contents. One or more files are still present in the depot directory. Other depots may have branched or integrated from files in this depot. Break those linkages with '%'p4 snap'%' and/or remove references from other depots with '%'p4 obliterate'%' first. Next, remove all non-Perforce files from the depot prior to depot deletion. Once all references have been removed, either remove any remaining physical files and directories from the depot directory and retry the operation, or specify '-f' to bypass this check and delete the depot." } ;
ErrorId MsgDm::DepotHasStreams         = { ErrorOf( ES_DM, 751, E_FAILED, EV_NOTYET, 1 ), "Depot '%depot%' is the location of existing streams; cannot delete until they are removed." } ;
ErrorId MsgDm::DepotNotEmptyNoChange         = { ErrorOf( ES_DM, 897, E_FAILED, EV_NOTYET, 2 ), "Cannot update depot %depot% type while it contains %objects%." } ;
ErrorId MsgDm::ReloadFirst             = { ErrorOf( ES_DM, 722, E_FAILED, EV_NOTYET, 1 ), "Unload depot %depot% isn't empty of unload files; reload any unloaded clients or labels with '%'p4 reload'%' first. All labels with the '%'autoreload'%' option set must be deleted prior to deleting the unload depot. Remove all non-Perforce files from the depot prior to depot deletion." } ;
ErrorId MsgDm::MustForceUnloadDepot    = { ErrorOf( ES_DM, 775, E_FAILED, EV_USAGE, 1 ), "The Commit Server cannot tell whether unload depot %depot% may still be in use by unloaded clients or labels on one or more Edge Servers. First, reload any unloaded clients or labels at each Edge Server with '%'p4 reload'%'. Next, all labels on each Edge Server with the '%'autoreload'%' option set must be deleted prior to deleting the unload depot. Next, remove all non-Perforce files from the depot prior to depot deletion. Finally, specify -f to bypass this check and force the unload depot deletion." } ;
ErrorId MsgDm::LockedUpdate            = { ErrorOf( ES_DM, 68, E_FAILED, EV_PROTECT, 3 ), "Locked %type% '%name%' owned by '%user%'; use -f to force update." } ;
ErrorId MsgDm::LockedDelete            = { ErrorOf( ES_DM, 70, E_FAILED, EV_PROTECT, 2 ), "%type% '%name%' is locked and can't be deleted." } ;
ErrorId MsgDm::OpenedDelete            = { ErrorOf( ES_DM, 71, E_FAILED, EV_NOTYET, 1 ), "Client '%client%' has files opened. To delete the client, revert any opened files and delete any pending changes first. An administrator may specify -f to force the delete of another user's client." } ;
ErrorId MsgDm::OpenedSwitch            = { ErrorOf( ES_DM, 607, E_FAILED, EV_NOTYET, 1 ), "Client '%client%' has files opened; use -f to force switch." } ;
ErrorId MsgDm::OpenedTaskSwitch        = { ErrorOf( ES_DM, 743, E_FAILED, EV_NOTYET, 1 ), "Client '%client%' has files opened from a task stream; must %'revert'%, or %'revert -k'% before switching." } ;
ErrorId MsgDm::ClassicSwitch           = { ErrorOf( ES_DM, 685, E_FAILED, EV_NOTYET, 1 ), "Client '%client%' has a static view that will be overwritten; use -f to force switch." } ;
ErrorId MsgDm::PendingDelete           = { ErrorOf( ES_DM, 447, E_FAILED, EV_NOTYET, 1 ), "Client '%client%' has pending changes. To delete the client, delete any pending changes first. An administrator may specify -f to force the delete of another user's client." } ;
ErrorId MsgDm::ShelvedDelete            = { ErrorOf( ES_DM, 524, E_FAILED, EV_NOTYET, 1 ), "Client '%client%' has files shelved; use '%'shelve -df'%' to remove them, and then try again,\nor use '%'client -df -Fs'%' to delete the client and leave the shelved changes intact." } ;
ErrorId MsgDm::ShelveNotChanged    = { ErrorOf( ES_DM, 688, E_INFO, EV_NONE, 2 ), "%depotFile%%depotRev% - unchanged, not shelved" } ;
ErrorId MsgDm::NoSuchGroup             = { ErrorOf( ES_DM, 72, E_FAILED, EV_UNKNOWN, 1 ), "Group '%group%' doesn't exist." } ;
ErrorId MsgDm::NoIntegOverlays         = { ErrorOf( ES_DM, 421, E_FAILED, EV_USAGE, 0 ), "Overlay (+) mappings are not allowed in branch views." } ;
ErrorId MsgDm::NoIntegHavemaps	       = { ErrorOf( ES_DM, 448, E_FAILED, EV_USAGE, 0 ), "Havemap entries found in non-client view!" } ;
ErrorId MsgDm::BadMappedFileName       = { ErrorOf( ES_DM, 73, E_FAILED, EV_USAGE, 0 ), "Branch mapping produced illegal filename." } ;
ErrorId MsgDm::JobNameJob              = { ErrorOf( ES_DM, 74, E_FAILED, EV_USAGE, 0 ), "The job name 'job' is reserved." } ;
ErrorId MsgDm::JobDescMissing          = { ErrorOf( ES_DM, 75, E_FAILED, EV_USAGE, 1 ), "'%field%' field blank.  You must provide it." } ;
ErrorId MsgDm::JobHasChanged           = { ErrorOf( ES_DM, 434, E_FAILED, EV_UNKNOWN, 0 ), "Job has been modified by another user, clear date field to overwrite." } ;
ErrorId MsgDm::JobFieldAlways          = { ErrorOf( ES_DM, 441, E_FAILED, EV_USAGE, 2 ), "%field% is a read-only always field and can't be changed from '%value%'.\nThe [%spec%|job] may have been updated while you were editing." } ;
ErrorId MsgDm::BadSpecType             = { ErrorOf( ES_DM, 412, E_FAILED, EV_USAGE, 1 ), "Unknown spec type %type%." } ;
ErrorId MsgDm::LameCodes               = { ErrorOf( ES_DM, 410, E_FAILED, EV_USAGE, 3 ), "Field codes must be between %low%-%hi% for %type% specs." } ;
ErrorId MsgDm::JobFieldReadOnly        = { ErrorOf( ES_DM, 77, E_FAILED, EV_USAGE, 2 ), "%field% is read-only and can't be changed from '%value%'." } ;
ErrorId MsgDm::MultiWordDefault        = { ErrorOf( ES_DM, 78, E_FAILED, EV_USAGE, 1 ), "%field% can't have a default multi-word value." } ;
ErrorId MsgDm::ProtectedCodes          = { ErrorOf( ES_DM, 411, E_FAILED, EV_USAGE, 1 ), "Builtin field %code% cannot be changed." } ;
ErrorId MsgDm::LabelOwner              = { ErrorOf( ES_DM, 80, E_FAILED, EV_PROTECT, 2 ), "Can't modify label '%label%' owned by '%user%'." } ;
ErrorId MsgDm::LabelLocked             = { ErrorOf( ES_DM, 81, E_FAILED, EV_PROTECT, 1 ), "Can't modify locked label '%label%'.\nUse 'label' to change label options." } ;
ErrorId MsgDm::LabelHasRev             = { ErrorOf( ES_DM, 438, E_FAILED, EV_NOTYET, 1 ), "Label '%label%' has a Revision field and must remain empty." };
ErrorId MsgDm::WildAdd                 = { ErrorOf( ES_DM, 82, E_FAILED, EV_USAGE, 0 ), "Can't add filenames with wildcards [@#%*] in them.\nUse -f option to force add." } ;
ErrorId MsgDm::WildAddFilename         = { ErrorOf( ES_DM, 921, E_FAILED, EV_USAGE, 1 ), "The file named '%filename%' contains wildcards [@#%*]." } ;
ErrorId MsgDm::WildAddTripleDots       = { ErrorOf( ES_DM, 637, E_FAILED, EV_USAGE, 0 ), "Can't add filenames containing the ellipsis wildcard (...)." } ;
ErrorId MsgDm::InvalidEscape           = { ErrorOf( ES_DM, 433, E_FAILED, EV_USAGE, 0 ), "Target file has illegal escape sequence [%xx]." } ;
ErrorId MsgDm::UserOrGroup             = { ErrorOf( ES_DM, 83, E_FAILED, EV_USAGE, 1 ), "Indicator must be 'user' or 'group', not '%value%'." } ;
ErrorId MsgDm::CantChangeUser          = { ErrorOf( ES_DM, 84, E_FAILED, EV_USAGE, 1 ), "User name can't be changed from '%user%'." } ;
ErrorId MsgDm::CantChangeUserAuth      = { ErrorOf( ES_DM, 802, E_FAILED, EV_USAGE, 0 ), "User's authentication method can't be changed; use -f to force switch." } ;
ErrorId MsgDm::CantChangeOwnDetails    = { ErrorOf( ES_DM, 963, E_FAILED, EV_USAGE, 0 ), "User's full name and email address can't be changed; use -f to force update." } ;
ErrorId MsgDm::CantChangeUserType      = { ErrorOf( ES_DM, 577, E_FAILED, EV_USAGE, 0 ), "User type can't be changed." } ;
ErrorId MsgDm::Passwd982               = { ErrorOf( ES_DM, 85, E_FAILED, EV_UPGRADE, 0 ), "You need a 98.2 or newer client to set a password." } ;
ErrorId MsgDm::NoClearText             = { ErrorOf( ES_DM, 419, E_FAILED, EV_USAGE, 0 ), "Passwords can only be set by 'p4 passwd' at this security level." } ;
ErrorId MsgDm::WrongUserDelete         = { ErrorOf( ES_DM, 86, E_FAILED, EV_PROTECT, 1 ), "Not user '%user%'; use -f to force delete." } ;
ErrorId MsgDm::DfltBranchView          = { ErrorOf( ES_DM, 87, E_FAILED, EV_USAGE, 0 ), "You cannot use the default branch view; it is just a sample." } ;
ErrorId MsgDm::LabelNoSync             = { ErrorOf( ES_DM, 437, E_FAILED, EV_NOTYET, 0 ), "The Revision field can only be added to empty labels." } ;
ErrorId MsgDm::FixBadVal               = { ErrorOf( ES_DM, 88, E_FAILED, EV_USAGE, 1 ), "Job fix status must be one of %values%." } ;
                               
ErrorId MsgDm::ParallelOptions         = { ErrorOf( ES_DM, 795, E_FAILED, EV_USAGE, 0 ), "Usage: threads=N,batch=N,batchsize=N,min=N,minsize=N" } ;     // NOTRANS
ErrorId MsgDm::ParSubOptions         = { ErrorOf( ES_DM, 856, E_FAILED, EV_USAGE, 0 ), "Usage: threads=N,batch=N,min=N" } ;     // NOTRANS
ErrorId MsgDm::ParallelNotEnabled      = { ErrorOf( ES_DM, 796, E_FAILED, EV_USAGE, 0 ), "Parallel file transfer must be enabled using %'net.parallel.max'%" } ;
ErrorId MsgDm::ParThreadsTooMany      = { ErrorOf( ES_DM, 900, E_FAILED, EV_USAGE, 2 ), "Number of threads (%threads%) exceeds net.parallel.max (%maxthreads%)." } ;
ErrorId MsgDm::NoClient                = { ErrorOf( ES_DM, 89, E_FATAL, EV_FAULT, 1 ), "%clientFile% - can't translate to local path -- no client!" } ;
ErrorId MsgDm::NoDepot                 = { ErrorOf( ES_DM, 90, E_FATAL, EV_FAULT, 1 ), "Can't find %depot% in depot map!" } ;
ErrorId MsgDm::NoArchive               = { ErrorOf( ES_DM, 91, E_FATAL, EV_FAULT, 1 ), "Can't map %lbrFile% to archive!" } ;

ErrorId MsgDm::EmptyRelate             = { ErrorOf( ES_DM, 92, E_FATAL, EV_FAULT, 0 ), "RelateMap has empty maps!" } ;
ErrorId MsgDm::BadCaller               = { ErrorOf( ES_DM, 93, E_FAILED, EV_CONFIG, 0 ), "Invalid user (P4USER) or client (P4CLIENT) name." } ;
ErrorId MsgDm::DomainIsUnloaded        = { ErrorOf( ES_DM, 702, E_FAILED, EV_CONFIG, 2 ), "%domainType% %domain% has been unloaded, and must be reloaded to be used." } ;
ErrorId MsgDm::NotClientOrLabel        = { ErrorOf( ES_DM, 703, E_FAILED, EV_CONFIG, 2 ), "%domain% must be a %domainType%." } ;
ErrorId MsgDm::NotUnloaded             = { ErrorOf( ES_DM, 704, E_FAILED, EV_CONFIG, 1 ), "%domain% does not require reloading." } ;
ErrorId MsgDm::AlreadyUnloaded         = { ErrorOf( ES_DM, 705, E_FAILED, EV_CONFIG, 1 ), "%domain% has already been unloaded." } ;
ErrorId MsgDm::CantChangeUnloadedOpt   = { ErrorOf( ES_DM, 706, E_FAILED, EV_USAGE, 0 ), "The autoreload/noautoreload option may not be modified." } ;
ErrorId MsgDm::NoUnloadedAutoLabel     = { ErrorOf( ES_DM, 717, E_FAILED, EV_USAGE, 0 ), "An automatic label may not specify the autoreload option." } ;
ErrorId MsgDm::StreamIsUnloaded        = { ErrorOf( ES_DM, 748, E_FAILED, EV_CONFIG, 2 ), "Client %client% cannot be used with unloaded stream %stream%, switch to another stream or reload it." } ;
ErrorId MsgDm::StreamNotGraph          = { ErrorOf( ES_DM, 957, E_FAILED, EV_USAGE, 0 ), "Stream client cannot be of type '%'graph'%'." } ;
ErrorId MsgDm::NoStorageDir            = { ErrorOf( ES_DM, 886, E_FAILED, EV_CONFIG, 1 ), "'%type%' client type has not been configured for this server.\nStorage location '%'client.readonly.dir'%' needs to be set by the administrator." } ;
ErrorId MsgDm::NotAsService            = { ErrorOf( ES_DM, 571, E_FAILED, EV_CONFIG, 0 ), "Command not allowed for a service user." } ;
ErrorId MsgDm::LockedClient            = { ErrorOf( ES_DM, 94, E_FAILED, EV_PROTECT, 2 ), "Locked client '%client%' can only be used by owner '%user%'." } ;
ErrorId MsgDm::LockedHost              = { ErrorOf( ES_DM, 95, E_FAILED, EV_PROTECT, 2 ), "Client '%client%' can only be used from host '%host%'." } ;
ErrorId MsgDm::ClientBoundToServer     = { ErrorOf( ES_DM, 672, E_FAILED, EV_PROTECT, 2 ), "Client '%client%' is restricted to use on server '%serverID%'." } ;
ErrorId MsgDm::CantChangeTypeOpened    = { ErrorOf( ES_DM, 958, E_FAILED, EV_USAGE, 0 ), "Can't change client type when files are open!" } ;
ErrorId MsgDm::NotBoundToServer        = { ErrorOf( ES_DM, 762, E_FAILED, EV_PROTECT, 3 ), "%objectType% '%objectName%' is not restricted to use on server '%serverID%'." } ;
ErrorId MsgDm::BindingNotAllowed       = { ErrorOf( ES_DM, 773, E_FAILED, EV_USAGE, 3 ), "%objectType% '%objectName%' should not be restricted to use on server '%serverID%'." } ;
ErrorId MsgDm::BoundToOtherServer      = { ErrorOf( ES_DM, 761, E_FAILED, EV_PROTECT, 4 ), "%objectType% '%objectName%' is restricted to use on server '%domainServerID%', not on server '%serverID%'." } ;
ErrorId MsgDm::UnidentifiedServer      = { ErrorOf( ES_DM, 670, E_FAILED, EV_USAGE, 0 ), "Server identity has not been defined, use '%'p4d -xD'%' to specify it." } ;
ErrorId MsgDm::TooManyCommitServers    = { ErrorOf( ES_DM, 769, E_FAILED, EV_USAGE, 1 ), "At most one commit-server may be defined. Server %serverid% is already specified to be a commit-server." } ;
ErrorId MsgDm::ServiceNotProvided      = { ErrorOf( ES_DM, 671, E_FAILED, EV_USAGE, 0 ), "Server does not provide this service." } ;
ErrorId MsgDm::EmptyFileName           = { ErrorOf( ES_DM, 96, E_FAILED, EV_USAGE, 0 ), "An empty string is not allowed as a file name." } ;
ErrorId MsgDm::NoRev                   = { ErrorOf( ES_DM, 97, E_FAILED, EV_USAGE, 0 ), "A revision specification (# or @) cannot be used here." } ;
ErrorId MsgDm::NoRevRange              = { ErrorOf( ES_DM, 98, E_FAILED, EV_USAGE, 0 ), "A revision range cannot be used here." } ;
ErrorId MsgDm::NeedClient              = { ErrorOf( ES_DM, 99, E_FAILED, EV_CONFIG, 2 ), "%arg% - must create client '%client%' to access local files." } ;
ErrorId MsgDm::ReferClient             = { ErrorOf( ES_DM, 100, E_FAILED, EV_UNKNOWN, 2 ), "%path% - must refer to client '%client%'." } ;
ErrorId MsgDm::BadAtRev                = { ErrorOf( ES_DM, 101, E_FAILED, EV_ILLEGAL, 1 ), "Invalid changelist/client/label/date '@%arg%'." } ;
ErrorId MsgDm::BadRevSpec              = { ErrorOf( ES_DM, 102, E_FAILED, EV_USAGE, 1 ), "Unintelligible revision specification '%arg%'." } ;
ErrorId MsgDm::BadRevRel               = { ErrorOf( ES_DM, 103, E_FAILED, EV_USAGE, 1 ), "Can't yet do relative operations on '%rev%'." } ;
ErrorId MsgDm::BadRevPend              = { ErrorOf( ES_DM, 426, E_FAILED, EV_USAGE, 0 ), "Can't use a pending changelist number for this command." } ;
ErrorId MsgDm::ManyRevSpec             = { ErrorOf( ES_DM, 436, E_FAILED, EV_USAGE, 1 ), "Too many revision specifications (max %max%)." } ;
ErrorId MsgDm::LabelLoop               = { ErrorOf( ES_DM, 455, E_FAILED, EV_USAGE, 1 ), "Too many automatic labels (label '%label%' may refer to itself)." };
ErrorId MsgDm::TwistedMap	       = { ErrorOf( ES_DM, 439, E_FAILED, EV_TOOBIG, 0 ), "Client map too twisted for directory list." } ;
ErrorId MsgDm::EmptyResults            = { ErrorOf( ES_DM, 104, E_WARN, EV_EMPTY, 1 ), "%reason%." } ;
ErrorId MsgDm::LimitBadArg             = { ErrorOf( ES_DM, 625, E_FAILED, EV_USAGE, 1 ), "%path% - must refer to a local depot in depot syntax." } ;
ErrorId MsgDm::BadChangeMap            = { ErrorOf( ES_DM, 888, E_FAILED, EV_USAGE, 1 ), "Could not translate '%change%' into a changelist number. Change maps can only use changelist numbers or automatic labels. Please check your client or stream mappings." };
ErrorId MsgDm::LabelNotAutomatic       = { ErrorOf( ES_DM, 889, E_FAILED, EV_USAGE, 1 ), "Label '%name%' isn't an automatic label. The Revision field is empty." };
ErrorId MsgDm::LabelRevNotChange       = { ErrorOf( ES_DM, 890, E_FAILED, EV_USAGE, 1 ), "The Revision field in label '%name%' isn't set to a changelist or date." };

ErrorId MsgDm::NoDelete                = { ErrorOf( ES_DM, 105, E_FATAL, EV_FAULT, 1 ), "%path% - can't delete remote file!" } ;
ErrorId MsgDm::NoCheckin               = { ErrorOf( ES_DM, 106, E_FATAL, EV_FAULT, 1 ), "%path% - can't checkin remote file!" } ;
ErrorId MsgDm::RmtError                = { ErrorOf( ES_DM, 107, E_FAILED, EV_FAULT, 1 ), "%text%" } ;
ErrorId MsgDm::TooOld                  = { ErrorOf( ES_DM, 108, E_FAILED, EV_UPGRADE, 0 ), "Remote server is too old to support remote access.  Install a new server." } ;
ErrorId MsgDm::DbFailed                = { ErrorOf( ES_DM, 109, E_FAILED, EV_FAULT, 1 ), "Remote depot '%depot%' database access failed." } ;
ErrorId MsgDm::ArchiveFailed           = { ErrorOf( ES_DM, 110, E_FAILED, EV_FAULT, 1 ), "Remote depot '%depot%' archive access failed." } ;
ErrorId MsgDm::NoRmtInterop            = { ErrorOf( ES_DM, 111, E_FAILED, EV_ADMIN, 0 ), "Remote depot access is not supported between UNIX and NT prior to 99.2." } ;
ErrorId MsgDm::RmtAuthFailed           = { ErrorOf( ES_DM, 124, E_FAILED, EV_FAULT, 0 ), "Remote authorization server access failed." } ;
ErrorId MsgDm::RmtAddChangeFailed      = { ErrorOf( ES_DM, 783, E_FAILED, EV_FAULT, 1 ), "Commit server access failed while trying to add change %change%." } ;
ErrorId MsgDm::RmtDeleteChangeFailed   = { ErrorOf( ES_DM, 784, E_FAILED, EV_FAULT, 1 ), "Commit server access failed while trying to delete change %change%." } ;

// MARKW add delimiters below this line
ErrorId MsgDm::RemoteChangeExists      = { ErrorOf( ES_DM, 785, E_FAILED, EV_FAULT, 1 ), "Change %change% already exists in this installation." } ;
ErrorId MsgDm::RemoteChangeMissing     = { ErrorOf( ES_DM, 786, E_FAILED, EV_FAULT, 1 ), "There is no change %change% in this installation." } ;
ErrorId MsgDm::ChangeNotShelved        = { ErrorOf( ES_DM, 787, E_FAILED, EV_FAULT, 1 ), "%change% is not currently shelved." } ;
ErrorId MsgDm::RmtAddDomainFailed      = { ErrorOf( ES_DM, 757, E_FAILED, EV_FAULT, 1 ), "Commit server access failed while trying to add a domain named %domainName%." } ;
ErrorId MsgDm::RmtDeleteDomainFailed   = { ErrorOf( ES_DM, 754, E_FAILED, EV_FAULT, 1 ), "Commit server access failed while trying to delete a domain named %domainName%." } ;
ErrorId MsgDm::RmtExclusiveLockFailed  = { ErrorOf( ES_DM, 758, E_FAILED, EV_FAULT, 0 ), "Commit server access failed while trying to get/release exclusive (+l) filetype." } ;
ErrorId MsgDm::RmtGlobalLockFailed  = { ErrorOf( ES_DM, 876, E_FAILED, EV_FAULT, 0 ), "Commit server access failed while trying to get/release global lock on file." } ;
ErrorId MsgDm::RemoteDomainExists      = { ErrorOf( ES_DM, 755, E_FAILED, EV_FAULT, 1 ), "A domain named %domainName% already exists in this installation." } ;
ErrorId MsgDm::RemoteDomainMissing     = { ErrorOf( ES_DM, 756, E_FAILED, EV_FAULT, 1 ), "There is no domain named %domainName% in this installation." } ;
ErrorId MsgDm::ServiceUserLogin        = { ErrorOf( ES_DM, 720, E_FAILED, EV_FAULT, 0 ), "Remote server refused request. Please verify that service user is correctly logged in to remote server, then retry." } ;
ErrorId MsgDm::RmtSequenceFailed       = { ErrorOf( ES_DM, 482, E_FATAL, EV_FAULT, 1 ), "Remote '%counter%' counter update failed." } ;	//NOTRANS
ErrorId MsgDm::OutOfSequence           = { ErrorOf( ES_DM, 483, E_FATAL, EV_FAULT, 2 ), "Sequence error:  local 'change' counter '%local%' vs remote '%remote%'!" } ;	//NOTRANS
ErrorId MsgDm::ChangeExists            = { ErrorOf( ES_DM, 484, E_FATAL, EV_FAULT, 1 ), "Sequence error:  next changelist '%change%' already exists!" };	//NOTRANS
ErrorId MsgDm::RmtJournalWaitFailed    = { ErrorOf( ES_DM, 651, E_FAILED, EV_FAULT, 0 ), "Remote %'journalwait'% failed!" } ;
ErrorId MsgDm::NoRevisionOverwrite     = { ErrorOf( ES_DM, 741, E_FATAL, EV_FAULT, 2 ), "Revision %depotFile%#%depotRev% already exists! A submit operation attempted to overwrite this revision with a new file at the same revision. This should never happen, and therefore the server has aborted the submit. It is possible that the Perforce database files have been corrupted by a disk failure, system crash, or improper restore operation. Please contact Perforce technical support for assistance. Please do not perform any further operations on the server until the problem can be resolved. Please save all server logs, journals, and database tables for use in determining the necessary recovery operations." };	//NOTRANS	// CONTENTIOUS
                               
                               
ErrorId MsgDm::BadTemplate             = { ErrorOf( ES_DM, 112, E_FATAL, EV_ADMIN, 1 ), "%key% spec template unusable!" } ;	//NOTRANS
ErrorId MsgDm::FieldMissing            = { ErrorOf( ES_DM, 113, E_FAILED, EV_USAGE, 1 ), "Field %field% missing from form." } ;
ErrorId MsgDm::NoNotOp                 = { ErrorOf( ES_DM, 114, E_FAILED, EV_USAGE, 0 ), "Can't handle ^ (not) operator there." } ;
ErrorId MsgDm::SameCode                = { ErrorOf( ES_DM, 116, E_FAILED, EV_USAGE, 2 ), "Fields '%field%' and '%field2%' have the same code." } ;
ErrorId MsgDm::SameTag                 = { ErrorOf( ES_DM, 413, E_FAILED, EV_USAGE, 2 ), "Fields '%field%' and '%field2%' have the same tag." } ;
ErrorId MsgDm::NoDefault               = { ErrorOf( ES_DM, 117, E_FAILED, EV_USAGE, 2 ), "Field '%field%' needs a preset value to be type '%opt%'." } ;
ErrorId MsgDm::SemiInDefault           = { ErrorOf( ES_DM, 118, E_FAILED, EV_USAGE, 1 ), "Default for '%field%' can't have ;'s in it." } ;
                               
ErrorId MsgDm::LicensedClients         = { ErrorOf( ES_DM, 119, E_INFO, EV_ADMIN, 2 ), "License count: %count% clients used of %max% licensed.\n" } ;
ErrorId MsgDm::LicensedUsers           = { ErrorOf( ES_DM, 120, E_INFO, EV_ADMIN, 2 ), "License count: %count% users used of %max% licensed.\n" } ;
ErrorId MsgDm::LicensedRepos           = { ErrorOf( ES_DM, 956, E_INFO, EV_ADMIN, 2 ), "License count: %count% repos used of %max% licensed.\n" } ;
ErrorId MsgDm::TryDelClient            = { ErrorOf( ES_DM, 121, E_INFO, EV_ADMIN, 0 ), "Try deleting old clients with '%'client -d'%'." } ;
ErrorId MsgDm::TryDelUser              = { ErrorOf( ES_DM, 122, E_INFO, EV_ADMIN, 0 ), "Try deleting old users with '%'user -d'%'." } ;
ErrorId MsgDm::TooManyRoots            = { ErrorOf( ES_DM, 123, E_FAILED, EV_USAGE, 0 ), "Too many client root alternatives -- only 2 allowed." } ;
ErrorId MsgDm::TryEvalLicense          = { ErrorOf( ES_DM, 470, E_INFO, EV_ADMIN, 0 ), "For additional licenses, contact Perforce Sales at sales@perforce.com." } ;

ErrorId MsgDm::AnnotateTooBig	       = { ErrorOf( ES_DM, 572, E_FAILED, EV_TOOBIG, 1 ), "File size exceeds %'dm.annotate.maxsize'% (%maxSize% bytes)." } ;

ErrorId MsgDm::NotBucket	       = { ErrorOf( ES_DM, 558, E_FAILED, EV_USAGE, 1 ), "%depot% is not an archive depot." } ;
ErrorId MsgDm::BucketAdd	       = { ErrorOf( ES_DM, 559, E_INFO, EV_NONE, 3 ), "Archiving %depotFile%%depotRev% to %archiveFile%." } ;
ErrorId MsgDm::BucketRestore	       = { ErrorOf( ES_DM, 560, E_INFO, EV_NONE, 3 ), "Restoring %depotFile%%depotRev% from %archiveFile%." } ;
ErrorId MsgDm::BucketPurge	       = { ErrorOf( ES_DM, 561, E_INFO, EV_NONE, 2 ), "Purged %depotFile%%depotRev%." } ;
ErrorId MsgDm::BucketSkipHead	       = { ErrorOf( ES_DM, 562, E_INFO, EV_NONE, 2 ), "Not archiving %depotFile%%depotRev%: head revision." } ;
ErrorId MsgDm::BucketSkipLazy	       = { ErrorOf( ES_DM, 563, E_INFO, EV_NONE, 2 ), "Not archiving %depotFile%%depotRev%: lazy copy." } ;
ErrorId MsgDm::BucketSkipBranched      = { ErrorOf( ES_DM, 564, E_INFO, EV_NONE, 2 ), "Not archiving %depotFile%%depotRev%: content used elsewhere." } ;
ErrorId MsgDm::BucketSkipBucketed      = { ErrorOf( ES_DM, 585, E_INFO, EV_NONE, 2 ), "Not archiving %depotFile%%depotRev%: trait '%'archiveBucket'%' has been set."} ;
ErrorId MsgDm::BucketSkipType	       = { ErrorOf( ES_DM, 565, E_INFO, EV_NONE, 2 ), "Not archiving %depotFile%%depotRev%: stored in delta format (+D)." } ;
ErrorId MsgDm::BucketSkipResolving     = { ErrorOf( ES_DM, 898, E_INFO, EV_NONE, 3 ), "Not archiving %depotFile%%depotRev%: content needed by a client with a pending resolve to %clientFile%." } ;
ErrorId MsgDm::BucketSkipShelving      = { ErrorOf( ES_DM, 899, E_INFO, EV_NONE, 3 ), "Not archiving %depotFile%%depotRev%: content needed by a shelf with a pending resolve to %shelfFile%." } ;
ErrorId MsgDm::BucketNoFilesToArchive  = { ErrorOf( ES_DM, 566, E_WARN, EV_USAGE, 1 ), "[%argc% - no|No] revisions can be archived." } ;
ErrorId MsgDm::BucketNoFilesToRestore  = { ErrorOf( ES_DM, 567, E_WARN, EV_USAGE, 1 ), "[%argc% - no|No] revisions can be restored." } ;
ErrorId MsgDm::BucketNoFilesToPurge    = { ErrorOf( ES_DM, 568, E_WARN, EV_USAGE, 1 ), "[%argc% - no|No] revisions can be purged." } ;
ErrorId MsgDm::CachePurgeFile          = { ErrorOf( ES_DM, 791, E_INFO, EV_NONE, 3 ), "Purging content of %lbrFile% %lbrRev% size %archiveSize%." } ;
ErrorId MsgDm::ChangeCreated           = { ErrorOf( ES_DM, 200, E_INFO, EV_NONE, 3 ), "%change% created[ with %workCount% open file(s)][ fixing %jobCount% job(s)]." } ;
ErrorId MsgDm::ChangeUpdated           = { ErrorOf( ES_DM, 201, E_INFO, EV_NONE, 5 ), "%change% updated[, adding %workCount% file(s)][, removing %workCount2% file(s)][, adding %jobCount% fix(es)][, removing %jobCount2% fix(es)]." } ;
ErrorId MsgDm::ChangeDeleteOpen        = { ErrorOf( ES_DM, 202, E_INFO, EV_NONE, 2 ), "%change% has %count% open file(s) associated with it and can't be deleted." } ;
ErrorId MsgDm::ChangeDeleteHasFix      = { ErrorOf( ES_DM, 203, E_INFO, EV_NONE, 2 ), "%change% has %count% fixes associated with it and can't be deleted." } ;
ErrorId MsgDm::ChangeDeleteHasFiles    = { ErrorOf( ES_DM, 204, E_INFO, EV_NONE, 2 ), "%change% has %count% files associated with it and can't be deleted." } ;
ErrorId MsgDm::ChangeDeleteShelved    = { ErrorOf( ES_DM, 517, E_FAILED, EV_CONTEXT, 1 ), "%change% has shelved files associated with it and can't be deleted." } ;
ErrorId MsgDm::ChangeDeleteSuccess     = { ErrorOf( ES_DM, 205, E_INFO, EV_NONE, 1 ), "%change% deleted." } ;
ErrorId MsgDm::ChangeNotOwner	       = { ErrorOf( ES_DM, 468, E_FAILED, EV_USAGE, 2 ), "%change% can only be updated by user %user%." };
ErrorId MsgDm::CommittedNoPerm	       = { ErrorOf( ES_DM, 573, E_FAILED, EV_USAGE, 2 ), "%change% can only be updated by user %user% with -u, or by admin user with -f." };
ErrorId MsgDm::PendingNoPerm	       = { ErrorOf( ES_DM, 574, E_FAILED, EV_USAGE, 2 ), "%change% can only be updated by user %user%, or by admin user with -f." };
                               
ErrorId MsgDm::PropertyData            = { ErrorOf( ES_DM, 731, E_INFO, EV_NONE, 2 ), "%settingName% = %settingNalue%" } ;
ErrorId MsgDm::PropertyDataUser        = { ErrorOf( ES_DM, 732, E_INFO, EV_NONE, 3 ), "%settingName% = %settingNalue% (user %userName%)" } ;
ErrorId MsgDm::PropertyDataGroup       = { ErrorOf( ES_DM, 733, E_INFO, EV_NONE, 3 ), "%settingName% = %settingNalue% (group %groupName%)" } ;
ErrorId MsgDm::NoSuchProperty          = { ErrorOf( ES_DM, 734, E_FAILED, EV_UNKNOWN, 4 ), "No such property '%settingName%' sequence %settingSequence% user %settingUser% group %settingGroup%." } ;
ErrorId MsgDm::PropertyAllData         = { ErrorOf( ES_DM, 774, E_INFO, EV_NONE, 5 ), "%settingName% = %settingNalue% (%appliesToType%[ %appliesTo%]) [%sequence%]" } ;
ErrorId MsgDm::BadSequence             = { ErrorOf( ES_DM, 747, E_FAILED, EV_USAGE, 1 ), "Invalid sequence number '%seq%'." } ;
ErrorId MsgDm::ExPROPERTY              = { ErrorOf( ES_DM, 735, E_WARN, EV_EMPTY, 1 ), "[%settingName% - no|No] such property." } ;

ErrorId MsgDm::ChangesData             = { ErrorOf( ES_DM, 206, E_INFO, EV_NONE, 5 ), "%change% on %date% by %user%@%client%%description%" } ;
ErrorId MsgDm::ChangesDataPending      = { ErrorOf( ES_DM, 207, E_INFO, EV_NONE, 5 ), "%change% on %date% by %user%@%client% *pending*%description%" } ;

ErrorId MsgDm::ConfigData              = { ErrorOf( ES_DM, 545, E_INFO, EV_NONE, 3 ), "%serverName%: %variableName% = %variableValue%" } ;
ErrorId MsgDm::NoSuchConfig            = { ErrorOf( ES_DM, 546, E_FAILED, EV_UNKNOWN, 1 ), "No such configuration variable '%config%'." } ;
ErrorId MsgDm::ConfigWasNotSet         = { ErrorOf( ES_DM, 547, E_FAILED, EV_UNKNOWN, 1 ), "Configuration variable '%config%' did not have a value." } ;
ErrorId MsgDm::UseConfigure            = { ErrorOf( ES_DM, 548, E_FAILED, EV_UNKNOWN, 0 ), "Usage: { %'set [name#]var=value | unset [name#]var'% }" } ;

ErrorId MsgDm::CopyOpenTarget          = { ErrorOf( ES_DM, 569, E_FAILED, EV_ILLEGAL, 0 ), "Can't copy to target path with files already open." } ;
ErrorId MsgDm::CopyMoveMapFrom         = { ErrorOf( ES_DM, 778, E_INFO, EV_USAGE, 1 ), "can't open as move/add because %movedFrom% is not mapped correctly." } ;
ErrorId MsgDm::CopyMoveNoFrom          = { ErrorOf( ES_DM, 779, E_INFO, EV_USAGE, 1 ), "can't open as move/add because %movedFrom% is not being opened for delete." } ;
ErrorId MsgDm::CopyMoveExTo            = { ErrorOf( ES_DM, 780, E_INFO, EV_USAGE, 0 ), "can't open as move/add because a file already exists in this location." } ;
ErrorId MsgDm::CopyMapSummary          = { ErrorOf( ES_DM, 781, E_WARN, EV_NONE, 0 ), "Some files couldn't be opened for move.  Try expanding the mapping?" } ;
ErrorId MsgDm::CopyChangeSummary       = { ErrorOf( ES_DM, 782, E_WARN, EV_NONE, 1 ), "Some files couldn't be opened for move.[  Try copying from @%change% instead?]" } ;

ErrorId MsgDm::CountersData            = { ErrorOf( ES_DM, 208, E_INFO, EV_NONE, 2 ), "%counterName% = %counterValue%" } ;

ErrorId MsgDm::DeleteMoved	       = { ErrorOf( ES_DM, 627, E_WARN, EV_NONE, 1 ), "%clientFile% - can't delete moved file; must undo move first" } ;

ErrorId MsgDm::DirsData                = { ErrorOf( ES_DM, 209, E_INFO, EV_NONE, 1 ), "%dirName%" } ;
                               
ErrorId MsgDm::DepotSave               = { ErrorOf( ES_DM, 210, E_INFO, EV_NONE, 1 ), "Depot %depotName% saved." } ;
ErrorId MsgDm::DepotNoChange           = { ErrorOf( ES_DM, 211, E_INFO, EV_NONE, 1 ), "Depot %depotName% not changed." } ;
ErrorId MsgDm::DepotDelete             = { ErrorOf( ES_DM, 212, E_INFO, EV_NONE, 1 ), "Depot %depotName% deleted." } ;
ErrorId MsgDm::DepotTypeDup            = { ErrorOf( ES_DM, 885, E_FAILED, EV_CONTEXT, 2 ), "There is already a %depotType% depot called '%depot%'." };
ErrorId MsgDm::DepotUnloadDup          = { ErrorOf( ES_DM, 701, E_FAILED, EV_CONTEXT, 1 ), "There is already an %'unload'% depot called '%depot%'." };	//CONTENTIOUS
ErrorId MsgDm::NoDepotTypeChange       = { ErrorOf( ES_DM, 618, E_FAILED, EV_ILLEGAL, 0 ), "Depot %'type'% cannot be changed." } ;	//CONTENTIOUS
ErrorId MsgDm::DepotMapInvalid         = { ErrorOf( ES_DM, 442, E_FAILED, EV_USAGE, 1 ), "%'Map'% entry '%map%' must have only 1 wildcard which must be a trailing '/...' or '\\...'." }; //CONTENTIOUS
ErrorId MsgDm::DepotNotStream          = { ErrorOf( ES_DM, 507, E_FAILED, EV_NONE, 1 ), "Depot %'type'% for '%depot%' must be '%'stream'%'." };	//CONTENTIOUS
ErrorId MsgDm::DepotNotSpec            = { ErrorOf( ES_DM, 675, E_FAILED, EV_NONE, 0 ), "%'SpecMap'% entries may only be added for a depot of type '%'spec'%'." };	//CONTENTIOUS
ErrorId MsgDm::ImportNotUnder             = { ErrorOf( ES_DM, 544, E_FAILED, EV_CONTEXT, 1 ), "Import path '%depotFile%' is not under an accessible depot." } ;
ErrorId MsgDm::InvalidParent             = { ErrorOf( ES_DM, 542, E_FAILED, EV_CONTEXT, 1 ), "Invalid parent field '%parent%'. Check stream, parent and type." } ;
ErrorId MsgDm::StreamOverflow            = { ErrorOf( ES_DM, 549, E_FAILED, EV_USAGE, 0 ), "Stream hierarchy in endless loop!" } ;
ErrorId MsgDm::NoStreamAtChange          = { ErrorOf( ES_DM, 550, E_FAILED, EV_CONTEXT, 2 ), "No stream '%stream%' existed at change %change%" } ;
ErrorId MsgDm::NotStreamReady            = { ErrorOf( ES_DM, 557, E_FAILED, EV_USAGE, 1 ), "Client '%client%' requires an application that can fully support streams." } ;
ErrorId MsgDm::MissingStream             = { ErrorOf( ES_DM, 575, E_FAILED, EV_UNKNOWN, 2 ), "Missing stream '%name%' in stream hierarchy for '%stream%'." } ;
ErrorId MsgDm::InvalidStreamFmt          = { ErrorOf( ES_DM, 576, E_FAILED, EV_NONE, 1), "Stream '%stream%' is not the correct format of '//depotname/string'" } ;
ErrorId MsgDm::StreamNotRelative	 = { ErrorOf( ES_DM, 872, E_FAILED, EV_NONE, 0), "Must specify a full stream path if not currently using a stream client." } ;
ErrorId MsgDm::StreamPathRooted          = { ErrorOf( ES_DM, 578, E_FAILED, EV_NONE, 1), "View '%view%' must be relative and not contain leading slashes "  } ;
ErrorId MsgDm::StreamPathSlash           = { ErrorOf( ES_DM, 579, E_FAILED, EV_NONE, 1), "Imported path '%view%' requires leading slashes in full depot path "  } ;
ErrorId MsgDm::StreamHasChildren        = { ErrorOf( ES_DM, 580, E_FAILED, EV_NOTYET, 1 ), "Stream '%stream%' has child streams; cannot delete until they are removed." } ;
ErrorId MsgDm::StreamHasClients         = { ErrorOf( ES_DM, 581, E_FAILED, EV_NOTYET, 1 ), "Stream '%stream%' has %type% clients; cannot delete until they are removed." } ;
ErrorId MsgDm::StreamIncompatibleP      = { ErrorOf( ES_DM, 583, E_FAILED, EV_CONTEXT, 4 ), "Stream '%stream%' (%type%) not compatible with Parent %parent% (%parentType%); use -u to force update." } ;
ErrorId MsgDm::StreamIncompatibleC      = { ErrorOf( ES_DM, 584, E_FAILED, EV_CONTEXT, 3 ), "Stream '%stream%' (%oldType% -> %type%) not compatible with child streams; use -u to force update." } ;
ErrorId MsgDm::StreamOwnerUpdate           = { ErrorOf( ES_DM, 586, E_FAILED, EV_NONE, 2), "Stream '%stream%' owner '%owner%' required for -u force update."  } ;
ErrorId MsgDm::StreamIsMainline            = { ErrorOf( ES_DM, 630, E_FAILED, EV_USAGE, 1 ), "Stream '%name%' has no parent, therefore (command not allowed)." } ;
ErrorId MsgDm::StreamNoFlow	= { ErrorOf( ES_DM, 680, E_FAILED, EV_CONTEXT, 1 ), "Stream '%stream%' type of %'virtual'% cannot have '%'toparent'%' or '%'fromparent'%' options set." } ;
ErrorId MsgDm::StreamIsVirtual            = { ErrorOf( ES_DM, 681, E_FAILED, EV_USAGE, 1 ), "Stream '%name%' is a virtual stream (command not allowed)." } ;
ErrorId MsgDm::StreamNoReparent          = { ErrorOf( ES_DM, 729, E_FAILED, EV_NONE, 3), "Cannot change Parent '%parent%' in %type% stream '%stream%'."  } ;
ErrorId MsgDm::StreamNoConvert           = { ErrorOf( ES_DM, 736, E_FAILED, EV_USAGE, 1), "Cannot convert '%type%' stream to '%'task'%' stream." } ;
ErrorId MsgDm::StreamConverted           = { ErrorOf( ES_DM, 738, E_INFO, EV_NONE, 2), "Stream '%name%' converted from '%'task'%' to '%type%'." } ;
ErrorId MsgDm::StreamParentIsTask        = { ErrorOf( ES_DM, 739, E_FAILED, EV_USAGE, 1), "Parent stream '%name%' is a task stream, child streams not allowed." } ;
ErrorId MsgDm::StreamBadConvert          = { ErrorOf( ES_DM, 740, E_FAILED, EV_USAGE, 1), "Cannot convert '%'task'%' stream to '%type%' - parent from different depot." } ;

ErrorId MsgDm::ClientNoSwitch    = { ErrorOf( ES_DM, 821, E_FAILED, EV_NONE, 1 ), "Client '%client%' already exists; use a new client or -s without -o to switch to different stream." } ;
ErrorId MsgDm::DepotsData              = { ErrorOf( ES_DM, 213, E_INFO, EV_NONE, 6 ), "%type% %depotName% %updateDate% %location% %map% '%description%'" } ;
ErrorId MsgDm::DepotsDataExtra         = { ErrorOf( ES_DM, 214, E_INFO, EV_NONE, 7 ), "%type% %depotName% %updateDate% %location% %address% %map% '%description%'" } ;

ErrorId MsgDm::RemoteSave              = { ErrorOf( ES_DM, 836, E_INFO, EV_NONE, 1 ), "Remote %remoteName% saved." } ;
ErrorId MsgDm::RemoteNoChange          = { ErrorOf( ES_DM, 837, E_INFO, EV_NONE, 1 ), "Remote %remoteName% not changed." } ;
ErrorId MsgDm::RemoteDelete            = { ErrorOf( ES_DM, 838, E_INFO, EV_NONE, 1 ), "Remote %remoteName% deleted." } ;
ErrorId MsgDm::NoSuchRemote            = { ErrorOf( ES_DM, 839, E_FAILED, EV_UNKNOWN, 1 ), "Remote '%remote%' doesn't exist." } ;
ErrorId MsgDm::RemotesData             = { ErrorOf( ES_DM, 840, E_INFO, EV_NONE, 3 ), "%remoteID% %address% '%description%'" } ;

ErrorId MsgDm::ServerSave              = { ErrorOf( ES_DM, 661, E_INFO, EV_NONE, 1 ), "Server %serverName% saved." } ;
ErrorId MsgDm::ServerNoChange          = { ErrorOf( ES_DM, 662, E_INFO, EV_NONE, 1 ), "Server %serverName% not changed." } ;
ErrorId MsgDm::ServerDelete            = { ErrorOf( ES_DM, 663, E_INFO, EV_NONE, 1 ), "Server %serverName% deleted." } ;
ErrorId MsgDm::NoSuchServer            = { ErrorOf( ES_DM, 664, E_FAILED, EV_UNKNOWN, 1 ), "Server '%server%' doesn't exist." } ;
ErrorId MsgDm::ServersData             = { ErrorOf( ES_DM, 665, E_INFO, EV_NONE, 6 ), "%serverID% %type% %name% %address% %services% '%description%'" } ;
ErrorId MsgDm::ServerTypeMismatch      = { ErrorOf( ES_DM, 719, E_FAILED, EV_CONTEXT, 0 ), "Server type is not appropriate for specified server services." } ;
ErrorId MsgDm::ServerViewMap           = { ErrorOf( ES_DM, 745, E_FAILED, EV_CONTEXT, 0 ), "This type of view mapping may not be provided for this server." } ;
ErrorId MsgDm::FiltersReplicaOnly      = { ErrorOf( ES_DM, 746, E_FAILED, EV_CONTEXT, 0 ), "Data Filters should be specified only for replica servers." } ;
ErrorId MsgDm::ServerConfigUsage      = { ErrorOf( ES_DM, 931, E_FAILED, EV_CONTEXT, 0 ), "Invalid DistributedConfig syntax: must use 'var=value'" } ;
ErrorId MsgDm::ServerConfigInvalidVar      = { ErrorOf( ES_DM, 932, E_FAILED, EV_CONTEXT, 1 ), "Configuration variable '%name%' cannot be set from here." } ;
ErrorId MsgDm::ServerConfigRO      = { ErrorOf( ES_DM, 933, E_FAILED, EV_CONTEXT, 2 ), "Configuration variable '%name%' must be set to '%value%'." } ;
ErrorId MsgDm::ServerCantConfig      = { ErrorOf( ES_DM, 934, E_FAILED, EV_CONTEXT, 0 ), "%'DistributedConfig'% can only be set with %'-c'% option." } ;
ErrorId MsgDm::ServerSvcInvalid      = { ErrorOf( ES_DM, 935, E_FAILED, EV_CONTEXT, 2 ), "Configuration for '%services%' cannot be set on server that uses '%existingSvc%' Services." } ;
ErrorId MsgDm::DescribeChange          = { ErrorOf( ES_DM, 215, E_INFO, EV_NONE, 5 ), "%change% by %user%@%client% on %date%%description%" } ;
ErrorId MsgDm::DescribeChangePending   = { ErrorOf( ES_DM, 216, E_INFO, EV_NONE, 5 ), "%change% by %user%@%client% on %date% *pending*%description%" } ;
ErrorId MsgDm::DescribeData            = { ErrorOf( ES_DM, 217, E_INFO, EV_USAGE, 3 ), "%depotFile%%depotRev% %action%" } ;
ErrorId MsgDm::DescribeMove            = { ErrorOf( ES_DM, 495, E_INFO, EV_USAGE, 4 ), "%depotFile%%depotRev% moved from %depotFile2%%depotRev2%" } ;
ErrorId MsgDm::DescribeDiff            = { ErrorOf( ES_DM, 218, E_INFO, EV_NONE, 4 ), "\n==== %depotFile%%depotRev% (%type%[/%type2%]) ====\n" } ;
                               
ErrorId MsgDm::DiffData                = { ErrorOf( ES_DM, 219, E_INFO, EV_NONE, 4 ), "==== %depotFile%%depotRev% - %localPath% ====[ (%type%)]" } ;
                               
ErrorId MsgDm::Diff2DataLeft           = { ErrorOf( ES_DM, 220, E_INFO, EV_NONE, 2 ), "==== %depotFile%%depotRev% - <none> ===" } ;
ErrorId MsgDm::Diff2DataRight          = { ErrorOf( ES_DM, 221, E_INFO, EV_NONE, 2 ), "==== <none> - %depotFile%%depotRev% ====" } ;
ErrorId MsgDm::Diff2DataRightPre041    = { ErrorOf( ES_DM, 423, E_INFO, EV_NONE, 2 ), "==== < none > - %depotFile%%depotRev% ====" } ;
ErrorId MsgDm::Diff2DataContent        = { ErrorOf( ES_DM, 222, E_INFO, EV_NONE, 6 ), "==== %depotFile%%depotRev% (%type%) - %depotFile2%%depotRev2% (%type2%) ==== content" } ;
ErrorId MsgDm::Diff2DataTypes          = { ErrorOf( ES_DM, 223, E_INFO, EV_NONE, 6 ), "==== %depotFile%%depotRev% (%type%) - %depotFile2%%depotRev2% (%type2%) ==== types" } ;
ErrorId MsgDm::Diff2DataIdentical      = { ErrorOf( ES_DM, 224, E_INFO, EV_NONE, 6 ), "==== %depotFile%%depotRev% (%type%) - %depotFile2%%depotRev2% (%type2%) ==== identical" } ;
ErrorId MsgDm::Diff2DataUnified        = { ErrorOf( ES_DM, 225, E_INFO, EV_NONE, 4 ), "--- %depotFile%\t%depotDate%\n+++ %depotFile2%\t%depotDate2%" } ;
ErrorId MsgDm::Diff2DataUnifiedDiffer  = { ErrorOf( ES_DM, 471, E_INFO, EV_NONE, 4 ), "Binary files %depotFile%%depotRev% and %depotFile2%%depotRev2% differ" } ;
                               
ErrorId MsgDm::DomainSave              = { ErrorOf( ES_DM, 226, E_INFO, EV_NONE, 2 ), "%domainType% %domainName% saved." } ;
ErrorId MsgDm::DomainNoChange          = { ErrorOf( ES_DM, 227, E_INFO, EV_NONE, 2 ), "%domainType% %domainName% not changed." } ;
ErrorId MsgDm::DomainDelete            = { ErrorOf( ES_DM, 228, E_INFO, EV_NONE, 2 ), "%domainType% %domainName% deleted." } ;
ErrorId MsgDm::DomainSwitch            = { ErrorOf( ES_DM, 608, E_INFO, EV_NONE, 2 ), "%domainType% %domainName% switched." } ;
                               
ErrorId MsgDm::DomainsDataClient       = { ErrorOf( ES_DM, 229, E_INFO, EV_NONE, 5 ), "%domainType% %domainName% %updateDate% %'root'% %domainMount% '%description%'" } ;	//CONTENTIOUS
ErrorId MsgDm::DomainsData             = { ErrorOf( ES_DM, 230, E_INFO, EV_NONE, 4 ), "%domainType% %domainName% %updateDate% '%description%'" } ;

ErrorId MsgDm::DupOK                   = { ErrorOf( ES_DM, 462, E_INFO, EV_NONE, 4 ), "%file%%rev% duplicated from %file2%%rev2%" } ;
ErrorId MsgDm::DupExists               = { ErrorOf( ES_DM, 463, E_INFO, EV_NONE, 2 ), "%file%%rev% already exists" } ;
ErrorId MsgDm::DupLocked               = { ErrorOf( ES_DM, 464, E_INFO, EV_NONE, 4 ), "%file%%rev% is opened for %action% on client %client%" } ;
                               
ErrorId MsgDm::FilelogData             = { ErrorOf( ES_DM, 231, E_INFO, EV_NONE, 1 ), "%depotFile%" } ;
ErrorId MsgDm::FilelogRevDefault       = { ErrorOf( ES_DM, 232, E_INFO, EV_USAGE, 4 ), "%depotRev% %change% %action% on %date%" } ;
ErrorId MsgDm::FilelogRevMessage       = { ErrorOf( ES_DM, 233, E_INFO, EV_USAGE, 8 ), "%depotRev% %change% %action% on %date% by %user%@%client% (%type%)%description%" } ;
ErrorId MsgDm::FilelogInteg            = { ErrorOf( ES_DM, 234, E_INFO, EV_UNKNOWN, 3 ), "%how% %fromFile%%fromRev%" } ;
                               
ErrorId MsgDm::FilesData               = { ErrorOf( ES_DM, 235, E_INFO, EV_NONE, 5 ), "%depotFile%%depotRev% - %action% %change% (%type%)" } ;
ErrorId MsgDm::FilesSummary            = { ErrorOf( ES_DM, 446, E_INFO, EV_NONE, 4 ), "%path% %fileCount% files %fileSize% bytes [%blockCount% blocks]" } ;
ErrorId MsgDm::FilesDiskUsage          = { ErrorOf( ES_DM, 454, E_INFO, EV_NONE, 4 ), "%depotFile%%depotRev% %fileSize% bytes [%blockCount% blocks]" } ;
ErrorId MsgDm::FilesSummaryHuman       = { ErrorOf( ES_DM, 788, E_INFO, EV_NONE, 4 ), "%path% %fileCount% files %fileSize% [%blockCount% blocks]" } ;
ErrorId MsgDm::FilesDiskUsageHuman     = { ErrorOf( ES_DM, 789, E_INFO, EV_NONE, 4 ), "%depotFile%%depotRev% %fileSize% [%blockCount% blocks]" } ;
                               
ErrorId MsgDm::FixAdd                  = { ErrorOf( ES_DM, 236, E_INFO, EV_NONE, 3 ), "%job% fixed by %change% (%status%)." } ;
ErrorId MsgDm::FixDelete               = { ErrorOf( ES_DM, 238, E_INFO, EV_NONE, 2 ), "Deleted fix %job% by %change%." } ;
                               
ErrorId MsgDm::FixesData               = { ErrorOf( ES_DM, 239, E_INFO, EV_NONE, 6 ), "%job% fixed by %change% on %date% by %user%@%client% (%status%)" } ;

ErrorId MsgDm::GrepOutput              = { ErrorOf( ES_DM, 531, E_INFO, EV_NONE, 4 ), "%depotFile%#%depotRev%%separator%%linecontent%" };
ErrorId MsgDm::GrepFileOutput         = { ErrorOf( ES_DM, 532, E_INFO, EV_NONE, 2 ), "%depotFile%#%depotRev%" };
ErrorId MsgDm::GrepWithLineNumber      = { ErrorOf( ES_DM, 533, E_INFO, EV_NONE, 6 ), "%depotFile%#%depotRev%%separator1%%linenumber%%separator2%%linecontent%" };
ErrorId MsgDm::GrepLineTooLong         = { ErrorOf( ES_DM, 534, E_WARN, EV_NONE, 4 ), "%depotFile%#%depotRev% - line %linenumber%: maximum line length of %maxlinelength% exceeded" };
ErrorId MsgDm::GrepMaxRevs            = { ErrorOf( ES_DM, 535, E_FAILED, EV_USAGE, 1 ), "Grep revision limit exceeded (over %maxRevs%)." } ;
ErrorId MsgDm::GrepSeparator          = { ErrorOf( ES_DM, 536, E_INFO, EV_NONE, 0 ), "--" } ;

ErrorId MsgDm::GroupCreated            = { ErrorOf( ES_DM, 241, E_INFO, EV_NONE, 1 ), "Group %group% created." } ;
ErrorId MsgDm::GroupNotCreated         = { ErrorOf( ES_DM, 242, E_INFO, EV_NONE, 1 ), "Group %group% not created." } ;
ErrorId MsgDm::GroupDeleted            = { ErrorOf( ES_DM, 243, E_INFO, EV_NONE, 1 ), "Group %group% deleted." } ;
ErrorId MsgDm::GroupNotUpdated         = { ErrorOf( ES_DM, 244, E_INFO, EV_NONE, 1 ), "Group %group% not updated." } ;
ErrorId MsgDm::GroupUpdated            = { ErrorOf( ES_DM, 245, E_INFO, EV_NONE, 1 ), "Group %group% updated." } ;
ErrorId MsgDm::GroupNotOwner	       = { ErrorOf( ES_DM, 472, E_FAILED, EV_NONE, 2), "User '%user%' is not an owner of group '%group%'." } ;
ErrorId MsgDm::GroupExists             = { ErrorOf( ES_DM, 718, E_FAILED, EV_NONE, 1), "No permission to modify existing group %group%." };
ErrorId MsgDm::GroupLdapIncomplete     = { ErrorOf( ES_DM, 861, E_FAILED, EV_CONTEXT, 0), "All three LDAP fields must be set for LDAP group synchronization." };
ErrorId MsgDm::GroupLdapNoOwner        = { ErrorOf( ES_DM, 862, E_FAILED, EV_CONTEXT, 0), "At least one group owner is required for LDAP group synchronization." } ;

ErrorId MsgDm::GroupsData              = { ErrorOf( ES_DM, 246, E_INFO, EV_NONE, 1 ), "%group%" } ;
ErrorId MsgDm::GroupsDataVerbose       = { ErrorOf( ES_DM, 474, E_INFO, EV_NONE, 5 ), "%group% %maxresults% %maxscanrows% %maxtimeout% %timeout%" };
                               
ErrorId MsgDm::HaveData                = { ErrorOf( ES_DM, 247, E_INFO, EV_NONE, 3 ), "%depotFile%%haveRev% - %lp%" } ;
                               
ErrorId MsgDm::IntegAlreadyOpened      = { ErrorOf( ES_DM, 250, E_INFO, EV_NONE, 2 ), "%depotFile% - can't %action% (already opened on this client)" } ;
ErrorId MsgDm::IntegIntoReadOnly       = { ErrorOf( ES_DM, 251, E_INFO, EV_NONE, 2 ), "%depotFile% - can only %action% into file in a local depot" } ;
ErrorId MsgDm::IntegIntoReadOnlyAndMap = { ErrorOf( ES_DM, 926, E_INFO, EV_NONE, 2 ), "%clientFile% - can't %action% into file that is additionally mapped in client's View" } ;
ErrorId MsgDm::IntegIntoReadOnlyCMap   = { ErrorOf( ES_DM, 927, E_INFO, EV_NONE, 2 ), "%clientFile% - can't %action% into file that is restricted by client's ChangeView mapping" } ;
ErrorId MsgDm::IntegXOpened            = { ErrorOf( ES_DM, 252, E_INFO, EV_NONE, 2 ), "%depotFile% - can't %action% exclusive file already opened" } ;
ErrorId MsgDm::IntegBadAncestor        = { ErrorOf( ES_DM, 253, E_INFO, EV_NONE, 5 ), "%depotFile% - can't %action% from %fromFile%%fromRev% without %'-d'% or %flag% flag" } ;

// WENDY add delimiters below this line
ErrorId MsgDm::IntegBadBase            = { ErrorOf( ES_DM, 254, E_INFO, EV_NONE, 4 ), "%depotFile% - can't %action% from %fromFile%%fromRev% without -i flag" } ;
ErrorId MsgDm::IntegBadAction          = { ErrorOf( ES_DM, 255, E_INFO, EV_NONE, 4 ), "%depotFile% - can't %action% (already opened for %badAction%)[ (remapped from %movedFrom%)]" } ;
ErrorId MsgDm::IntegBadClient          = { ErrorOf( ES_DM, 256, E_INFO, EV_NONE, 2 ), "%depotFile% - is already opened by client %client%" } ;
ErrorId MsgDm::IntegBadUser            = { ErrorOf( ES_DM, 257, E_INFO, EV_NONE, 2 ), "%depotFile% - is already opened by user %user%" } ;
ErrorId MsgDm::IntegCantAdd            = { ErrorOf( ES_DM, 258, E_INFO, EV_NONE, 2 ), "%depotFile% - can't %action% existing file" } ;
ErrorId MsgDm::IntegCantModify         = { ErrorOf( ES_DM, 259, E_INFO, EV_NONE, 2 ), "%depotFile% - can't %action% deleted file" } ;
ErrorId MsgDm::IntegMustSync           = { ErrorOf( ES_DM, 260, E_INFO, EV_NONE, 1 ), "%toFile% - must sync before integrating." } ;
ErrorId MsgDm::IntegOpenOkayBase       = { ErrorOf( ES_DM, 424, E_INFO, EV_NONE, 8 ), "%depotFile%%workRev% - %action% from %fromFile%%fromRev%[ using base %baseFile%][%baseRev%][ (remapped from %remappedFrom%)]" } ;
ErrorId MsgDm::IntegSyncBranch         = { ErrorOf( ES_DM, 262, E_INFO, EV_NONE, 5 ), "%depotFile%%workRev% - %action%/%'sync'% from %fromFile%%fromRev%" } ;
ErrorId MsgDm::IntegSyncIntegBase      = { ErrorOf( ES_DM, 427, E_INFO, EV_NONE, 8 ), "%depotFile%%workRev% - %'sync'%/%action% from %fromFile%%fromRev%[ using base %baseFile%][%baseRev%][ (remapped from %remappedFrom%)]" } ;
ErrorId MsgDm::IntegNotHandled         = { ErrorOf( ES_DM, 264, E_INFO, EV_NONE, 3 ), "%depotFile%%workRev% - flag %flag% not handled!" } ;
ErrorId MsgDm::IntegTooVirtual         = { ErrorOf( ES_DM, 449, E_INFO, EV_NONE, 2 ), "%depotFile% - can't %action% file branched with %'integrate -v'%" };
ErrorId MsgDm::IntegIncompatable       = { ErrorOf( ES_DM, 461, E_INFO, EV_NONE, 2 ), "%depotFile% - file type of %fromFile% incompatible" };
ErrorId MsgDm::IntegMovedUnmapped      = { ErrorOf( ES_DM, 551, E_INFO, EV_NONE, 2 ), "%depotFile% - not in client view (remapped from %movedFrom%)" };
ErrorId MsgDm::IntegMovedNoAccess      = { ErrorOf( ES_DM, 552, E_INFO, EV_NONE, 2 ), "%depotFile% - no permission (remapped from %movedFrom%)" };
ErrorId MsgDm::IntegMovedOutScope      = { ErrorOf( ES_DM, 556, E_INFO, EV_NONE, 2 ), "%depotFile% - not in branch view (remapped from %movedFrom%)" };
ErrorId MsgDm::IntegMovedNoFrom        = { ErrorOf( ES_DM, 721, E_INFO, EV_NONE, 5 ), "%depotFile% - can't %action% from %fromFile%%fromRev% (moved from %movedFrom%; provide a branch view that maps this file, or use -Di to disregard move/deletes)" };
ErrorId MsgDm::IntegMovedNoFromS       = { ErrorOf( ES_DM, 759, E_INFO, EV_NONE, 5 ), "%depotFile% - can't %action% from %fromFile%%fromRev% (moved from %movedFrom%; provide a branch/stream view that maps this file, or use 'p4 copy' to force)" };
ErrorId MsgDm::IntegBaselessMove       = { ErrorOf( ES_DM, 682, E_WARN, EV_NONE, 3 ), "%depotFile% - resolve move to %moveFile% before integrating from %fromFile%" };
ErrorId MsgDm::IntegPreviewResolve     = { ErrorOf( ES_DM, 710, E_INFO, EV_USAGE, 5 ), "must resolve %resolveType% from %fromFile%%fromRev%[ using base %baseFile%][%baseRev%]" } ;
ErrorId MsgDm::IntegPreviewResolveMove = { ErrorOf( ES_DM, 711, E_INFO, EV_USAGE, 2 ), "must resolve move to %fromFile%[ using base %baseFile%]" } ;
ErrorId MsgDm::IntegPreviewResolved    = { ErrorOf( ES_DM, 768, E_INFO, EV_USAGE, 3 ), "%how% %fromFile%%fromRev%" } ;

ErrorId MsgDm::IntegedData             = { ErrorOf( ES_DM, 265, E_INFO, EV_NONE, 5 ), "%toFile%%toRev% - %how% %fromFile%%fromRev%" } ;
                               
ErrorId MsgDm::JobSave                 = { ErrorOf( ES_DM, 266, E_INFO, EV_NONE, 1 ), "Job %job% saved." } ;
ErrorId MsgDm::JobNoChange             = { ErrorOf( ES_DM, 267, E_INFO, EV_NONE, 1 ), "Job %job% not changed." } ;
ErrorId MsgDm::JobDelete               = { ErrorOf( ES_DM, 268, E_INFO, EV_NONE, 1 ), "Job %job% deleted." } ;
ErrorId MsgDm::JobDescription          = { ErrorOf( ES_DM, 269, E_INFO, EV_NONE, 5 ), "%job%[ on %date%][ by %user%][ *%status%*][%description%]" } ;
ErrorId MsgDm::JobDeleteHasFix      = { ErrorOf( ES_DM, 465, E_INFO, EV_NONE, 2 ), "%job% has %count% fixes associated with it and can't be deleted." } ;
                               
ErrorId MsgDm::LabelSyncAdd            = { ErrorOf( ES_DM, 272, E_INFO, EV_NONE, 2 ), "%depotFile%%haveRev% - added" } ;
ErrorId MsgDm::LabelSyncDelete         = { ErrorOf( ES_DM, 273, E_INFO, EV_NONE, 2 ), "%depotFile%%haveRev% - deleted" } ;
ErrorId MsgDm::LabelSyncReplace        = { ErrorOf( ES_DM, 274, E_INFO, EV_NONE, 2 ), "%depotFile%%haveRev% - replaced" } ;
ErrorId MsgDm::LabelSyncUpdate         = { ErrorOf( ES_DM, 275, E_INFO, EV_NONE, 2 ), "%depotFile%%haveRev% - updated" } ;

ErrorId MsgDm::LdapConfBadPerms        = { ErrorOf( ES_DM, 806, E_FATAL, EV_NONE, 0 ), "LDAP configuration directory must have 700 permissions." } ;
ErrorId MsgDm::LdapConfBadOwner        = { ErrorOf( ES_DM, 805, E_FATAL, EV_NONE, 0 ), "LDAP configuration directory or files not owned by Perforce process effective user." } ;
ErrorId MsgDm::BadPortNumber           = { ErrorOf( ES_DM, 803, E_FAILED, EV_CONTEXT, 0 ), "Port numbers must be in the range 1 to 65535." } ;
ErrorId MsgDm::LdapData                = { ErrorOf( ES_DM, 804, E_INFO, EV_NONE, 5 ), "%name% %host%:%port% %type% (%status%)" } ;
ErrorId MsgDm::LdapSave                = { ErrorOf( ES_DM, 807, E_INFO, EV_NONE, 1 ), "LDAP configuration %name% saved." } ;
ErrorId MsgDm::LdapNoChange            = { ErrorOf( ES_DM, 808, E_INFO, EV_NONE, 1 ), "LDAP configuration %name% not changed." } ;
ErrorId MsgDm::LdapDelete              = { ErrorOf( ES_DM, 809, E_INFO, EV_NONE, 1 ), "LDAP configuration %name% deleted." } ;
ErrorId MsgDm::NoSuchLdap              = { ErrorOf( ES_DM, 810, E_FAILED, EV_UNKNOWN, 1 ), "LDAP configuration '%name%' doesn't exist." } ;
ErrorId MsgDm::LdapRequiredField0      = { ErrorOf( ES_DM, 811, E_FAILED, EV_CONTEXT, 0 ), "Bind type 'simple' requires SimplePattern to be set." } ;
ErrorId MsgDm::LdapRequiredField1      = { ErrorOf( ES_DM, 812, E_FAILED, EV_CONTEXT, 0 ), "Bind type 'search' requires SearchBaseDN to be set." } ;
ErrorId MsgDm::LdapRequiredField2      = { ErrorOf( ES_DM, 813, E_FAILED, EV_CONTEXT, 0 ), "Bind type 'search' requires SearchFilter to be set." } ;
ErrorId MsgDm::LdapRequiredField3      = { ErrorOf( ES_DM, 814, E_FAILED, EV_CONTEXT, 0 ), "GroupSearchFilter requires SearchBaseDN or GroupBaseDN to be set." } ;

ErrorId MsgDm::LicenseSave             = { ErrorOf( ES_DM, 450, E_INFO, EV_NONE, 0 ), "License file saved." } ;
ErrorId MsgDm::LicenseNoChange         = { ErrorOf( ES_DM, 451, E_INFO, EV_NONE, 0 ), "License file not changed." } ;

ErrorId MsgDm::LockSuccess             = { ErrorOf( ES_DM, 276, E_INFO, EV_NONE, 1 ), "%depotFile% - locking" } ;
ErrorId MsgDm::LockAlready             = { ErrorOf( ES_DM, 277, E_INFO, EV_NONE, 1 ), "%depotFile% - already locked" } ;
ErrorId MsgDm::LockAlreadyOther        = { ErrorOf( ES_DM, 278, E_INFO, EV_NONE, 3 ), "%depotFile% - already locked by %user%@%client%" } ;
ErrorId MsgDm::LockAlreadyCommit        = { ErrorOf( ES_DM, 912, E_FAILED, EV_NOTYET, 4 ), "%depotFile% - already locked on Commit Server by %user%@%client% at change %change%" } ;
ErrorId MsgDm::LockNoPermission        = { ErrorOf( ES_DM, 279, E_INFO, EV_NONE, 1 ), "%depotFile% - no permission to lock file" } ;
ErrorId MsgDm::LockBadUnicode          = { ErrorOf( ES_DM, 525, E_INFO, EV_NONE, 1 ), "%depotFile% - cannot submit unicode type file using non-unicode server" } ;
ErrorId MsgDm::LockUtf16NotSupp        = { ErrorOf( ES_DM, 526, E_INFO, EV_NONE, 1 ), "%depotFile% - utf16 files can not be submitted by pre-2007.2 clients" } ;

ErrorId MsgDm::UnLockSuccess           = { ErrorOf( ES_DM, 280, E_INFO, EV_NONE, 1 ), "%depotFile% - unlocking" } ;
ErrorId MsgDm::UnLockAlready           = { ErrorOf( ES_DM, 281, E_INFO, EV_NONE, 1 ), "%depotFile% - already unlocked" } ;
ErrorId MsgDm::UnLockAlreadyOther      = { ErrorOf( ES_DM, 282, E_INFO, EV_NONE, 3 ), "%depotFile% - locked by %user%@%client%" } ;
ErrorId MsgDm::ShelvedHasWorking           = { ErrorOf( ES_DM, 742, E_INFO, EV_NONE, 2 ), "Cannot submit - files are open by client %client% at change %change%." } ;
                               
ErrorId MsgDm::LoggerData              = { ErrorOf( ES_DM, 283, E_INFO, EV_NONE, 3 ), "%sequence% %key% %attribute%" } ;

ErrorId MsgDm::MergeBadBase            = { ErrorOf( ES_DM, 638, E_INFO, EV_NONE, 3 ), "%depotFile% - can't merge unrelated file %fromFile%%fromRev%" } ;

ErrorId MsgDm::MoveSuccess             = { ErrorOf( ES_DM, 487, E_INFO, EV_NONE, 4 ), "%toFile%%toRev% - moved from %fromFile%%fromRev%" } ;
ErrorId MsgDm::MoveBadAction           = { ErrorOf( ES_DM, 488, E_INFO, EV_NONE, 2 ), "%depotFile% - can't move (already opened for %badAction%)" } ;
ErrorId MsgDm::MoveDeleted	       = { ErrorOf( ES_DM, 626, E_WARN, EV_NONE, 2 ), "%clientFile% - can't move (open for %action%); must accept other resolve(s) or ignore" } ;
ErrorId MsgDm::MoveExists              = { ErrorOf( ES_DM, 489, E_INFO, EV_NONE, 1 ), "%depotFile% - can't move to an existing file" } ;
ErrorId MsgDm::MoveMisMatch            = { ErrorOf( ES_DM, 490, E_FATAL, EV_FAULT, 0 ), "Mismatched move on client!" } ;
ErrorId MsgDm::MoveNoMatch             = { ErrorOf( ES_DM, 491, E_INFO, EV_NONE, 3 ), "%depotFile% - needs %direction%file %movedFile%" } ;
ErrorId MsgDm::MoveNoInteg             = { ErrorOf( ES_DM, 763, E_FAILED, EV_NONE, 2 ), "%depotFile% - moved from %movedFile% but has no matching resolve record; must 'add -d' or 'move' to correct." } ;
ErrorId MsgDm::MoveReadOnly            = { ErrorOf( ES_DM, 494, E_INFO, EV_NONE, 1 ), "%depotFile% - can't move to a spec or remote depot" } ;
ErrorId MsgDm::MoveReadOnlySrc         = { ErrorOf( ES_DM, 952, E_INFO, EV_NONE, 1 ), "%depotFile% - can't move from a spec or remote depot" } ;
ErrorId MsgDm::MoveNotSynced           = { ErrorOf( ES_DM, 528, E_INFO, EV_NONE, 1 ), "%depotFile% - not synced, can't force move" } ;
ErrorId MsgDm::MoveNotResolved         = { ErrorOf( ES_DM, 529, E_INFO, EV_NONE, 1 ), "%depotFile% - is unresolved, can't force move" } ;
ErrorId MsgDm::MoveNeedForce           = { ErrorOf( ES_DM, 530, E_INFO, EV_NONE, 1 ), "%clientFile% - is synced; use -f to force move" } ;
ErrorId MsgDm::MoveCantForce           = { ErrorOf( ES_DM, 953, E_INFO, EV_NONE, 1 ), "%clientFile% - is synced; can't use -r with existing target" } ;
                               
ErrorId MsgDm::OpenAlready             = { ErrorOf( ES_DM, 284, E_INFO, EV_NONE, 2 ), "%depotFile% - can't %action% (already opened on this client)" } ;
ErrorId MsgDm::OpenReadOnly            = { ErrorOf( ES_DM, 285, E_INFO, EV_NONE, 2 ), "%depotFile% - can only %action% file in a local depot" } ;
ErrorId MsgDm::OpenReadOnlyAndMap      = { ErrorOf( ES_DM, 930, E_INFO, EV_NONE, 2 ), "%clientFile% - can't %action% file that is additionally mapped in client's View" } ;
ErrorId MsgDm::OpenReadOnlyCMap        = { ErrorOf( ES_DM, 925, E_INFO, EV_NONE, 2 ), "%clientFile% - can't %action% file that is restricted by client's ChangeView mapping" } ;
ErrorId MsgDm::OpenXOpened             = { ErrorOf( ES_DM, 286, E_INFO, EV_NONE, 2 ), "%depotFile% - can't %action% exclusive file already opened" } ;
ErrorId MsgDm::OpenXOpenedFailed       = { ErrorOf( ES_DM, 777, E_FAILED, EV_NONE, 2 ), "%depotFile% - can't %action% exclusive file already opened" } ;
ErrorId MsgDm::OpenBadAction           = { ErrorOf( ES_DM, 287, E_INFO, EV_NONE, 3 ), "%depotFile% - can't %action% (already opened for %badAction%)" } ;
ErrorId MsgDm::OpenBadClient           = { ErrorOf( ES_DM, 288, E_INFO, EV_NONE, 2 ), "%depotFile% - is already opened by client %client%" } ;
ErrorId MsgDm::OpenBadUser             = { ErrorOf( ES_DM, 289, E_INFO, EV_NONE, 2 ), "%depotFile% - is already opened by user %user%" } ;
ErrorId MsgDm::OpenBadChange           = { ErrorOf( ES_DM, 290, E_INFO, EV_NONE, 2 ), "%depotFile% - can't change from %change% - use '%'reopen'%'" } ;
ErrorId MsgDm::OpenBadType             = { ErrorOf( ES_DM, 291, E_INFO, EV_NONE, 2 ), "%depotFile% - can't change from %type% - use '%'reopen'%'" } ;
ErrorId MsgDm::OpenReOpen              = { ErrorOf( ES_DM, 292, E_INFO, EV_NONE, 3 ), "%depotFile%%workRev% - reopened for %action%" } ;
ErrorId MsgDm::OpenUpToDate            = { ErrorOf( ES_DM, 293, E_INFO, EV_NONE, 3 ), "%depotFile%%workRev% - currently opened for %action%" } ;
ErrorId MsgDm::OpenCantExists          = { ErrorOf( ES_DM, 294, E_INFO, EV_NONE, 2 ), "%depotFile% - can't %action% existing file" } ;
ErrorId MsgDm::OpenCantDeleted         = { ErrorOf( ES_DM, 295, E_INFO, EV_NONE, 2 ), "%depotFile% - can't %action% deleted file" } ;
ErrorId MsgDm::OpenCantMissing         = { ErrorOf( ES_DM, 860, E_INFO, EV_NONE, 2 ), "%depotFile% - can't %action% missing file" } ;
ErrorId MsgDm::OpenSuccess             = { ErrorOf( ES_DM, 296, E_INFO, EV_NONE, 3 ), "%depotFile%%workRev% - opened for %action%" } ;
ErrorId MsgDm::OpenMustResolve         = { ErrorOf( ES_DM, 297, E_INFO, EV_USAGE, 2 ), "%depotFile% - must %'sync'%/%'resolve'% %workRev% before submitting" } ;
ErrorId MsgDm::OpenIsLocked            = { ErrorOf( ES_DM, 298, E_INFO, EV_USAGE, 3 ), "%depotFile% - locked by %user%@%client%" } ;
ErrorId MsgDm::OpenIsOpened            = { ErrorOf( ES_DM, 299, E_INFO, EV_USAGE, 3 ), "%depotFile% - also opened by %user%@%client%" } ;
ErrorId MsgDm::OpenWarnExists          = { ErrorOf( ES_DM, 300, E_INFO, EV_USAGE, 2 ), "%depotFile% - warning: %action% of existing file" } ;
ErrorId MsgDm::OpenWarnDeleted         = { ErrorOf( ES_DM, 301, E_INFO, EV_USAGE, 2 ), "%depotFile% - warning: %action% of deleted file" } ;
ErrorId MsgDm::OpenWarnMoved           = { ErrorOf( ES_DM, 493, E_INFO, EV_USAGE, 2 ), "%depotFile% - warning: %action% of moved file" } ;
ErrorId MsgDm::OpenWarnOpenStream      = { ErrorOf( ES_DM, 553, E_INFO, EV_USAGE, 1 ), "%depotFile% - warning: cannot submit from non-stream client" } ;
ErrorId MsgDm::OpenWarnOpenNotStream   = { ErrorOf( ES_DM, 554, E_INFO, EV_USAGE, 2 ), "%depotFile% - warning: cannot submit from stream %stream% client" } ;
ErrorId MsgDm::OpenWarnFileNotMapped   = { ErrorOf( ES_DM, 570, E_INFO, EV_USAGE, 2 ), "%depotFile% - warning: file not mapped in stream %stream% client" } ;
ErrorId MsgDm::OpenWarnChangeMap       = { ErrorOf( ES_DM, 799, E_INFO, EV_USAGE, 2 ), "%depotFile% - warning: cannot submit file that is restricted [to %change% ]by client's ChangeView mapping" } ;
ErrorId MsgDm::OpenWarnAndmap          = { ErrorOf( ES_DM, 929, E_INFO, EV_USAGE, 2 ), "%clientFile% - warning: cannot submit file that is additionally mapped in client's View" } ;
ErrorId MsgDm::OpenOtherDepot          = { ErrorOf( ES_DM, 724, E_FAILED, EV_NONE, 3 ), "%clientFile% - can't open %depotFile% (already opened as %depotFile2%)" } ;
ErrorId MsgDm::OpenTaskNotMapped       = { ErrorOf( ES_DM, 752, E_INFO, EV_NONE, 2 ), "%clientFile% - can't open %depotFile% (not mapped in client), must sync first." } ;
ErrorId MsgDm::OpenHasResolve          = { ErrorOf( ES_DM, 815, E_FAILED, EV_ILLEGAL, 2 ), "%clientFile% - can't %action% file with pending integrations." } ;
ErrorId MsgDm::OpenWarnReaddMoved      = { ErrorOf( ES_DM, 825, E_INFO, EV_USAGE, 1 ), "opened for %action% as new file; use '%'move'%' to recover moved files."} ;

ErrorId MsgDm::OpenedData              = { ErrorOf( ES_DM, 302, E_INFO, EV_NONE, 5 ), "%depotFile%%workRev% - %action% %change% (%type%)" } ;
ErrorId MsgDm::OpenedOther             = { ErrorOf( ES_DM, 303, E_INFO, EV_NONE, 7 ), "%depotFile%%workRev% - %action% %change% (%type%) by %user%@%client%" } ;
ErrorId MsgDm::OpenedLocked            = { ErrorOf( ES_DM, 304, E_INFO, EV_NONE, 5 ), "%depotFile%%workRev% - %action% %change% (%type%) *locked*" } ;
ErrorId MsgDm::OpenedOtherLocked       = { ErrorOf( ES_DM, 305, E_INFO, EV_NONE, 7 ), "%depotFile%%workRev% - %action% %change% (%type%) by %user%@%client% *locked*" } ;
ErrorId MsgDm::OpenedXData             = { ErrorOf( ES_DM, 635, E_INFO, EV_NONE, 5 ), "%depotFile%%workRev% - %action% %change% (%type%) *exclusive*" } ;
ErrorId MsgDm::OpenedXOther            = { ErrorOf( ES_DM, 636, E_INFO, EV_NONE, 7 ), "%depotFile%%workRev% - %action% %change% (%type%) by %user%@%client% *exclusive*" } ;
ErrorId MsgDm::OpenedDataS             = { ErrorOf( ES_DM, 644, E_INFO, EV_NONE, 3 ), "%depotFile% - %action% %change%" } ;
ErrorId MsgDm::OpenedOtherS            = { ErrorOf( ES_DM, 645, E_INFO, EV_NONE, 5 ), "%depotFile% - %action% %change% by %user%@%client%" } ;
ErrorId MsgDm::OpenedLockedS           = { ErrorOf( ES_DM, 646, E_INFO, EV_NONE, 3 ), "%depotFile% - %action% %change% *locked*" } ;
ErrorId MsgDm::OpenedOtherLockedS      = { ErrorOf( ES_DM, 647, E_INFO, EV_NONE, 5 ), "%depotFile% - %action% %change% by %user%@%client% *locked*" } ;
ErrorId MsgDm::OpenedXDataS            = { ErrorOf( ES_DM, 648, E_INFO, EV_NONE, 3 ), "%depotFile% - %action% %change% *exclusive*" } ;
ErrorId MsgDm::OpenedXOtherS           = { ErrorOf( ES_DM, 649, E_INFO, EV_NONE, 5 ), "%depotFile% - %action% %change% by %user%@%client% *exclusive*" } ;

ErrorId MsgDm::OpenExclOrphaned        = { ErrorOf( ES_DM, 770, E_INFO, EV_NONE, 3 ), "%depotFile% - %user%@%client% *orphaned*" } ;
ErrorId MsgDm::OpenExclLocked          = { ErrorOf( ES_DM, 771, E_INFO, EV_NONE, 3 ), "%depotFile% - %user%@%client% *exclusive*" } ;
ErrorId MsgDm::OpenExclOther           = { ErrorOf( ES_DM, 772, E_INFO, EV_NONE, 4 ), "%depotFile% - %user%@%client% %server%" } ;

ErrorId MsgDm::PopulateDesc            = { ErrorOf( ES_DM, 679, E_INFO, EV_NONE, 2 ), "Populate %target%[ from %source%]." } ;
ErrorId MsgDm::PopulateTargetExists    = { ErrorOf( ES_DM, 678, E_FAILED, EV_ILLEGAL, 0 ), "Can't populate target path when files already exist." } ;
ErrorId MsgDm::PopulateTargetMixed     = { ErrorOf( ES_DM, 726, E_FAILED, EV_ILLEGAL, 0 ), "Can't update target with mixed stream/non-stream paths." } ;
ErrorId MsgDm::PopulateInvalidStream   = { ErrorOf( ES_DM, 727, E_FAILED, EV_ILLEGAL, 1 ), "Can't update stream target with '%depotFile%'" } ;
ErrorId MsgDm::PopulateMultipleStreams = { ErrorOf( ES_DM, 728, E_FAILED, EV_ILLEGAL, 0 ), "Can't update multiple streams with single command."} ;

ErrorId MsgDm::ProtectSave             = { ErrorOf( ES_DM, 306, E_INFO, EV_NONE, 0 ), "Protections saved." } ;
ErrorId MsgDm::ProtectNoChange         = { ErrorOf( ES_DM, 307, E_INFO, EV_NONE, 0 ), "Protections not changed." } ;
ErrorId MsgDm::ProtectNoOwner          = { ErrorOf( ES_DM, 951, E_FAILED, EV_ADMIN, 0 ), "No 'owner' entry matching provided path." } ;

ErrorId MsgDm::ProtectsData            = { ErrorOf( ES_DM, 440, E_INFO, EV_NONE, 6 ), "%perm% %isgroup% %user% %ipaddr% %mapFlag%%depotFile%" };
ErrorId MsgDm::ProtectsMaxData         = { ErrorOf( ES_DM, 452, E_INFO, EV_NONE, 1 ), "%perm%" };
ErrorId MsgDm::ProtectsEmpty           = { ErrorOf( ES_DM, 456, E_FAILED, EV_ADMIN, 0 ), "Protections table is empty." } ;
ErrorId MsgDm::ProtectsNoSuper         = { ErrorOf( ES_DM, 469, E_FAILED, EV_ADMIN, 0 ), "Can't delete last valid 'super' entry from protections table." } ;
ErrorId MsgDm::ProtectsNotCompatible   = { ErrorOf( ES_DM, 587, E_FAILED, EV_ADMIN, 0 ), "Helix P4Admin tool not compatible with '##' comments in protection table.\nIf you wish to continue using Helix P4Admin to administer the protection table please remove all '##' comments." } ;
ErrorId MsgDm::ProtectsBadPerm         = { ErrorOf( ES_DM, 939, E_FAILED, EV_ADMIN, 0 ), "Can't add '%perm%' entry to sub-protections table." } ;
ErrorId MsgDm::ProtectsPathOutOfScope  = { ErrorOf( ES_DM, 940, E_FAILED, EV_ADMIN, 0 ), "All paths in sub-protections table must be under path '%path%'." } ;
ErrorId MsgDm::ProtectsOwnerEnds       = { ErrorOf( ES_DM, 941, E_FAILED, EV_ADMIN, 0 ), "Paths in 'owner' entries must end with '/...'." } ;
ErrorId MsgDm::ProtectsOwnerWildcards  = { ErrorOf( ES_DM, 942, E_FAILED, EV_ADMIN, 0 ), "Can't add 'owner' entry with embedded wildcards in path." } ;
ErrorId MsgDm::ProtectsOwnerPath       = { ErrorOf( ES_DM, 943, E_FAILED, EV_ADMIN, 0 ), "No 'owner' entry matching path '%path%'." } ;
ErrorId MsgDm::ProtectsDuplicateOwner  = { ErrorOf( ES_DM, 944, E_FAILED, EV_ADMIN, 0 ), "Multiple 'owner' entries matching path '%path%' found." } ;
ErrorId MsgDm::ProtectsOwnerTooWide    = { ErrorOf( ES_DM, 954, E_FAILED, EV_ADMIN, 0 ), "Paths in 'owner' entries must be more specific than '//...'." } ;
ErrorId MsgDm::ProtectsOwnerUnmap      = { ErrorOf( ES_DM, 955, E_FAILED, EV_ADMIN, 0 ), "Can't add exclusionary 'owner' entries." } ;

ErrorId MsgDm::PurgeSnapData           = { ErrorOf( ES_DM, 308, E_INFO, EV_NONE, 4 ), "%depotFile%%depotRev% - copy from %lbrFile% %lbrRev%" } ;
ErrorId MsgDm::PurgeDeleted            = { ErrorOf( ES_DM, 309, E_INFO, EV_NONE, 6 ), "Deleted [%onHave% client ][%onLabel% label ][%onInteg% integration ][%onWorking% opened ][%onRev% revision ][and added %synInteg% integration ]record(s)." } ;
ErrorId MsgDm::PurgeCheck              = { ErrorOf( ES_DM, 310, E_INFO, EV_NONE, 6 ), "Would delete [%onHave% client ][%onLabel% label ][%onInteg% integration ][%onWorking% opened ][%onRev% revision ][and add %synInteg% integration ]record(s)." } ;
ErrorId MsgDm::PurgeNoRecords          = { ErrorOf( ES_DM, 311, E_INFO, EV_NONE, 0 ), "No records to delete." } ;
ErrorId MsgDm::PurgeData               = { ErrorOf( ES_DM, 312, E_INFO, EV_NONE, 2 ), "%depotFile%%depotRev% - purged" } ;
ErrorId MsgDm::PurgeActiveTask         = { ErrorOf( ES_DM, 737, E_FAILED, EV_ILLEGAL, 2 ), "Can't %action% active task stream files - '%depotFile%'" } ;
ErrorId MsgDm::PurgeUnloadedTask       = { ErrorOf( ES_DM, 959, E_FAILED, EV_ILLEGAL, 2 ), "Can't %action% unloaded task stream files - '%depotFile%'" } ;
                               
ErrorId MsgDm::ReleaseHasPending       = { ErrorOf( ES_DM, 313, E_INFO, EV_NONE, 2 ), "%depotFile%%haveRev% - has pending integrations, not reverted" } ;
ErrorId MsgDm::ReleaseAbandon          = { ErrorOf( ES_DM, 314, E_INFO, EV_NONE, 3 ), "%depotFile%%haveRev% - was %action%, abandoned" } ;
ErrorId MsgDm::ReleaseClear            = { ErrorOf( ES_DM, 315, E_INFO, EV_NONE, 3 ), "%depotFile%%haveRev% - was %action%, cleared" } ;
ErrorId MsgDm::ReleaseDelete           = { ErrorOf( ES_DM, 316, E_INFO, EV_NONE, 3 ), "%depotFile%%haveRev% - was %action%, deleted" } ;
ErrorId MsgDm::ReleaseRevert           = { ErrorOf( ES_DM, 317, E_INFO, EV_NONE, 3 ), "%depotFile%%haveRev% - was %action%, reverted" } ;
ErrorId MsgDm::ReleaseUnlockAbandon    = { ErrorOf( ES_DM, 318, E_INFO, EV_NONE, 3 ), "%depotFile%%haveRev% - was %action%, unlocked and abandoned" } ;
ErrorId MsgDm::ReleaseUnlockClear      = { ErrorOf( ES_DM, 319, E_INFO, EV_NONE, 3 ), "%depotFile%%haveRev% - was %action%, unlocked and cleared" } ;
ErrorId MsgDm::ReleaseUnlockDelete     = { ErrorOf( ES_DM, 320, E_INFO, EV_NONE, 3 ), "%depotFile%%haveRev% - was %action%, unlocked and deleted" } ;
ErrorId MsgDm::ReleaseUnlockRevert     = { ErrorOf( ES_DM, 321, E_INFO, EV_NONE, 3 ), "%depotFile%%haveRev% - was %action%, unlocked and reverted" } ;
ErrorId MsgDm::ReleaseNotOwner         = { ErrorOf( ES_DM, 443, E_INFO, EV_NONE, 3 ), "%depotFile%%haveRev% - belongs to user %user%, not reverted" } ;
ErrorId MsgDm::ReleaseHasMoved         = { ErrorOf( ES_DM, 486, E_INFO, EV_NONE, 2 ), "%depotFile%%haveRev% - has been moved, not reverted" } ;
                               
ErrorId MsgDm::ReopenData              = { ErrorOf( ES_DM, 322, E_INFO, EV_NONE, 5 ), "%depotFile%%workRev% - reopened[; user %user%][; type %type%][; %change%]" } ;
ErrorId MsgDm::ReopenDataNoChange      = { ErrorOf( ES_DM, 323, E_INFO, EV_NONE, 5 ), "%depotFile%%workRev% - nothing changed[; user %user%][; type %type%][; %change%]" } ;
ErrorId MsgDm::ReopenCharSet           = { ErrorOf( ES_DM, 767, E_INFO, EV_NONE, 3 ), "%depotFile%%workRev% - reopened; charset %charset%" } ;
ErrorId MsgDm::ReopenBadType           = { ErrorOf( ES_DM, 760, E_INFO, EV_NONE, 2 ), "%depotFile%%workRev% - can't change +l type with reopen; use revert -k and then edit -t to change type." } ;
                               
ErrorId MsgDm::ResolveAction           = { ErrorOf( ES_DM, 590, E_INFO, EV_NONE, 6 ), "%localPath% - resolving %resolveType% from %fromFile%%fromRev%[ using base %baseFile%][%baseRev%]" } ;
ErrorId MsgDm::ResolveActionMove       = { ErrorOf( ES_DM, 622, E_INFO, EV_NONE, 3 ), "%localPath% - resolving move to %fromFile%[ using base %baseFile%]" } ;
ErrorId MsgDm::ResolveDelete           = { ErrorOf( ES_DM, 324, E_INFO, EV_NONE, 1 ), "%localPath% - has been deleted - %'revert'% and %'sync'%." } ;
ErrorId MsgDm::ResolveShelveDelete     = { ErrorOf( ES_DM, 639, E_FAILED, EV_FAULT, 2 ), "%depotFile%%rev%: can't resolve (shelved file was deleted); must %'revert'%, or %'revert -k'% and edit before submit." } ;
ErrorId MsgDm::ResolveDoBranch	       = { ErrorOf( ES_DM, 594, E_INFO, EV_NONE, 0 ), "Branch resolve" } ;
ErrorId MsgDm::ResolveDoBranchActionT  = { ErrorOf( ES_DM, 595, E_INFO, EV_NONE, 0 ), "branch" } ;
ErrorId MsgDm::ResolveDoBranchActionY  = { ErrorOf( ES_DM, 596, E_INFO, EV_NONE, 0 ), "ignore" } ;
ErrorId MsgDm::ResolveDoDelete         = { ErrorOf( ES_DM, 597, E_INFO, EV_NONE, 0 ), "Delete resolve" } ;
ErrorId MsgDm::ResolveDoDeleteActionT  = { ErrorOf( ES_DM, 598, E_INFO, EV_NONE, 0 ), "delete" } ;
ErrorId MsgDm::ResolveDoDeleteActionY  = { ErrorOf( ES_DM, 599, E_INFO, EV_NONE, 0 ), "ignore" } ;
ErrorId MsgDm::ResolveFiletype         = { ErrorOf( ES_DM, 591, E_INFO, EV_NONE, 0 ), "Filetype resolve" } ;
ErrorId MsgDm::ResolveFiletypeAction   = { ErrorOf( ES_DM, 592, E_INFO, EV_NONE, 1 ), "(%type%)" } ;
ErrorId MsgDm::ResolveMove             = { ErrorOf( ES_DM, 600, E_INFO, EV_NONE, 0 ), "Filename resolve" } ;
ErrorId MsgDm::ResolveMoveAction       = { ErrorOf( ES_DM, 601, E_INFO, EV_NONE, 1 ), "%depotPath%" };
ErrorId MsgDm::ResolveTrait            = { ErrorOf( ES_DM, 666, E_INFO, EV_NONE, 0 ), "Attribute resolve" } ;
ErrorId MsgDm::ResolveTraitActionT     = { ErrorOf( ES_DM, 667, E_INFO, EV_NONE, 1 ), "overwrite your open attributes with their set of [%count% ]attribute(s)" } ;
ErrorId MsgDm::ResolveTraitActionY     = { ErrorOf( ES_DM, 668, E_INFO, EV_NONE, 1 ), "leave your set of [%count% ]open attribute(s) unchanged" } ;
ErrorId MsgDm::ResolveTraitActionM     = { ErrorOf( ES_DM, 669, E_INFO, EV_NONE, 1 ), "merge their [%count% ]propagating attribute(s) with your set of attribute(s)" } ;
ErrorId MsgDm::ResolveCharset          = { ErrorOf( ES_DM, 764, E_INFO, EV_NONE, 0 ), "Charset resolve" } ;
ErrorId MsgDm::ResolveCharsetActionT   = { ErrorOf( ES_DM, 765, E_INFO, EV_NONE, 1 ), "overwrite your open character set with their character set of %charset%" } ;
ErrorId MsgDm::ResolveCharsetActionY   = { ErrorOf( ES_DM, 766, E_INFO, EV_NONE, 1 ), "leave your character set of %charset% unchanged" } ;
ErrorId MsgDm::Resolve2WayRaw          = { ErrorOf( ES_DM, 325, E_INFO, EV_NONE, 3 ), "%localPath% - vs %fromFile%%fromRev%" } ;
ErrorId MsgDm::Resolve3WayRaw          = { ErrorOf( ES_DM, 326, E_INFO, EV_NONE, 7 ), "%localPath% - %baseType%/%headType% merge %fromFile%%fromRev%[ using base %baseFile%][%baseRev%]" } ;
ErrorId MsgDm::Resolve3WayText         = { ErrorOf( ES_DM, 327, E_INFO, EV_NONE, 3 ), "%localPath% - merging %fromFile%%fromRev%" } ;
ErrorId MsgDm::Resolve3WayTextBase     = { ErrorOf( ES_DM, 425, E_INFO, EV_NONE, 5 ), "%localPath% - merging %fromFile%%fromRev% using base %baseFile%%baseRev%" } ;
ErrorId MsgDm::ResolveMustIgnore       = { ErrorOf( ES_DM, 798, E_FAILED, EV_NONE, 1 ), "%clientFile% - their revision is unavailable; %'resolve -ay'% (ignore) or revert?" } ;

ErrorId MsgDm::ResolvedAction          = { ErrorOf( ES_DM, 593, E_INFO, EV_NONE, 6 ), "%localPath% - resolved %resolveType% from %fromFile%%fromRev%[ using base %baseFile%][%baseRev%]" } ;
ErrorId MsgDm::ResolvedActionMove      = { ErrorOf( ES_DM, 623, E_INFO, EV_NONE, 4 ), "%localPath% - resolved move (%how% %fromFile%)[ using base %baseFile%]" } ;
ErrorId MsgDm::ResolvedData            = { ErrorOf( ES_DM, 328, E_INFO, EV_NONE, 4 ), "%localPath% - %how% %fromFile%%fromRev%" } ;
ErrorId MsgDm::ResolvedDataBase        = { ErrorOf( ES_DM, 428, E_INFO, EV_NONE, 6 ), "%localPath% - %how% %fromFile%%fromRev% base %baseFile%%baseRev%" } ;

ErrorId MsgDm::RetypeData              = { ErrorOf( ES_DM, 459, E_INFO, EV_NONE, 4 ), "%depotFile%%depotRev% - %oldType% now %newType%" } ;
                               
ErrorId MsgDm::ReviewData              = { ErrorOf( ES_DM, 329, E_INFO, EV_NONE, 4 ), "%change% %user% <%email%> (%fullName%)" } ;
                               
ErrorId MsgDm::ReviewsData             = { ErrorOf( ES_DM, 330, E_INFO, EV_NONE, 3 ), "%user% <%email%> (%fullname%)" } ;


// MICHAELS add delimiters below this line
                               
ErrorId MsgDm::SpecSave                = { ErrorOf( ES_DM, 414, E_INFO, EV_NONE, 1 ), "Spec %type% saved." } ;
ErrorId MsgDm::SpecNoChange            = { ErrorOf( ES_DM, 415, E_INFO, EV_NONE, 1 ), "Spec %type% not changed." } ;
ErrorId MsgDm::SpecDeleted             = { ErrorOf( ES_DM, 416, E_INFO, EV_NONE, 1 ), "Spec %type% deleted." } ;
ErrorId MsgDm::SpecNotDefined          = { ErrorOf( ES_DM, 417, E_FAILED, EV_UNKNOWN, 1 ), "Spec %type% not defined." } ;

ErrorId MsgDm::ShelveCantUpdate        = { ErrorOf( ES_DM, 512, E_FAILED, EV_USAGE , 1 ), "%depotFile% - already shelved, use %'-f'% to update." } ;
ErrorId MsgDm::ShelveLocked            = { ErrorOf( ES_DM, 518, E_INFO, EV_NONE, 1 ), "%depotFile% - shelved file locked, try again later." } ;
ErrorId MsgDm::ShelveUnlocked          = { ErrorOf( ES_DM, 519, E_INFO, EV_NONE, 1 ), "%depotFile% - shelved file unlocked, try again later." } ;
ErrorId MsgDm::ShelveIncompatible      = { ErrorOf( ES_DM, 522, E_FAILED, EV_USAGE, 1 ), "%depotFile% - can't overwrite a shelved moved file, use %'-r'% to replace." } ;
ErrorId MsgDm::ShelveMaxFiles          = { ErrorOf( ES_DM, 523, E_FAILED, EV_USAGE, 1 ), "Shelve file limit exceeded (over %maxFiles%)." } ;
ErrorId MsgDm::ShelveNoPerm            = { ErrorOf( ES_DM, 541, E_INFO, EV_NONE, 1 ), "%depotFile% - no permission to shelve file" } ;
ErrorId MsgDm::ShelveNeedsResolve      = { ErrorOf( ES_DM, 620, E_FAILED, EV_NONE, 3 ), "%depotFile% - must %'resolve'% %file%%srev% before shelving" } ;
ErrorId MsgDm::ShelveOpenResolves      = { ErrorOf( ES_DM, 633, E_FAILED, EV_NONE, 3 ), "%depotFile% - unshelved file for [%user%@]%client% needs %'resolve'%" } ;
ErrorId MsgDm::FieldCount              = { ErrorOf( ES_DM, 496, E_FAILED, EV_USAGE, 1 ), "'%tag%' unknown or wrong number of fields for path-type." } ;
ErrorId MsgDm::StreamNotOwner          = { ErrorOf( ES_DM, 497, E_FAILED, EV_NONE, 2), "Stream '%stream%' is owned by '%owner%'." } ;
ErrorId MsgDm::StreamTargetExists      = { ErrorOf( ES_DM, 753, E_FAILED, EV_NONE, 1), "%stream% - can't create stream where files already exist." } ;
ErrorId MsgDm::StreamsData             = { ErrorOf( ES_DM, 498, E_INFO, EV_NONE, 5 ), "Stream %stream% %type% %parent% '%title%'[ %status%]" } ;
ErrorId MsgDm::StreamRootErr           = { ErrorOf( ES_DM, 499, E_FAILED, EV_NONE, 1), "Stream '%stream%' must begin with '%'//'%'." } ;
ErrorId MsgDm::StreamNested            = { ErrorOf( ES_DM, 501, E_FAILED, EV_NONE, 2), "Streams cannot be nested. '%stream%' contains existing stream '%nested%'." } ;
ErrorId MsgDm::StreamDoubleSlash       = { ErrorOf( ES_DM, 502, E_FAILED, EV_NONE, 1), "Stream '%stream%' contains embedded double slashes (%'//'%)." } ;
ErrorId MsgDm::StreamEqDepot           = { ErrorOf( ES_DM, 503, E_FAILED, EV_NONE, 1), "Stream '%stream%' must be below depot level." } ;
ErrorId MsgDm::StreamDepthErr          = { ErrorOf( ES_DM, 504, E_FAILED, EV_NONE, 1), "Stream '%stream%' must reside in first folder below depot level." } ;
ErrorId MsgDm::StreamEndSlash          = { ErrorOf( ES_DM, 505, E_FAILED, EV_NONE, 1), "Trailing slash not allowed in '%id%'." } ;
ErrorId MsgDm::StreamVsDomains         = { ErrorOf( ES_DM, 506, E_FATAL, EV_FAULT, 0 ), "Stream and domains table out of sync!" } ; // NOTRANS
ErrorId MsgDm::StreamVsTemplate        = { ErrorOf( ES_DM, 816, E_FATAL, EV_FAULT, 1 ), "Stream and template table out of sync for stream %stream%!" } ; // NOTRANS
ErrorId MsgDm::LocWild                 = { ErrorOf( ES_DM, 514, E_FAILED, EV_USAGE, 2 ), "%loc% wildcards (*, ...) not allowed in path: '%path%'." } ;
ErrorId MsgDm::EmbWild                 = { ErrorOf( ES_DM, 543, E_FAILED, EV_USAGE, 1 ), "Embedded wildcards (*, ...) not allowed in '%path%'." } ;
ErrorId MsgDm::EmbEllipse              = { ErrorOf( ES_DM, 924, E_FAILED, EV_USAGE, 1 ), "Embedded wildcards (...) not allowed in '%path%'." } ;
ErrorId MsgDm::EmbSpecChar             = { ErrorOf( ES_DM, 700, E_FAILED, EV_USAGE, 1 ), "Embedded special characters (*, %%, #, @) not allowed in '%path%'." } ;
ErrorId MsgDm::PosWild                 = { ErrorOf( ES_DM, 515, E_FAILED, EV_USAGE, 1 ), "Positional wildcards (%%%%x) not allowed in path: '%path%'." } ;

ErrorId MsgDm::StreamOpened	       = { ErrorOf( ES_DM, 904, E_INFO, EV_NONE, 2 ), "Stream %stream%[@%haveChange%] - opened on this client" } ;
ErrorId MsgDm::StreamIsOpen            = { ErrorOf( ES_DM, 905, E_WARN, EV_NOTYET, 1 ), "Stream %stream% is already open on this client." } ;
ErrorId MsgDm::StreamReverted          = { ErrorOf( ES_DM, 907, E_INFO, EV_NONE, 1 ), "Stream %stream% reverted." } ;
ErrorId MsgDm::StreamShelveMismatch    = { ErrorOf( ES_DM, 913, E_FAILED, EV_NOTYET, 2 ), "Shelved stream %shelvedStream% does not match client stream [%clientStream%|(none)]." };
ErrorId MsgDm::StreamNotOpen           = { ErrorOf( ES_DM, 914, E_WARN, EV_NOTYET, 1 ), "Client %client% does not have an open stream." } ;
ErrorId MsgDm::StreamSwitchOpen        = { ErrorOf( ES_DM, 915, E_FAILED, EV_NOTYET, 1 ), "Can't switch to %stream% while current stream spec has pending changes.  Use 'p4 stream revert' to discard." } ;
ErrorId MsgDm::StreamMustResolve       = { ErrorOf( ES_DM, 916, E_WARN, EV_NOTYET, 1 ), "Stream %stream% is out of date; run 'p4 stream resolve'." } ;
ErrorId MsgDm::StreamShelved           = { ErrorOf( ES_DM, 917, E_INFO, EV_NONE, 1 ), "Stream %stream% shelved." };
ErrorId MsgDm::StreamUnshelved         = { ErrorOf( ES_DM, 918, E_INFO, EV_NONE, 1 ), "Stream %stream% unshelved." };
ErrorId MsgDm::StreamOpenBadType       = { ErrorOf( ES_DM, 919, E_FAILED, EV_ILLEGAL, 1 ), "Not permitted to open stream spec with type '%type%'." } ;
ErrorId MsgDm::StreamTaskAndImport     = { ErrorOf( ES_DM, 363, E_FAILED, EV_USAGE, 1 ), "Not permitted to update a task stream and Import+ file at the same time '%depotFile%'." } ;

ErrorId MsgDm::StreamResolve           = { ErrorOf( ES_DM, 908, E_INFO, EV_NONE, 5 ), "%localStream% %field% - resolving %fromStream%@%fromChange%[ using base @%baseChange%]" } ;
ErrorId MsgDm::StreamResolved          = { ErrorOf( ES_DM, 909, E_INFO, EV_NONE, 5 ), "%localStream% %field% - %how% %fromStream%@%fromChange%" } ;
ErrorId MsgDm::StreamResolveField      = { ErrorOf( ES_DM, 910, E_INFO, EV_NONE, 1 ), "%field% resolve" } ;
ErrorId MsgDm::StreamResolveAction     = { ErrorOf( ES_DM, 911, E_INFO, EV_NONE, 1 ), "%text%" } ;

ErrorId MsgDm::StreamOwnerReq          = { ErrorOf( ES_DM, 582, E_FAILED, EV_NONE, 1), "Owner field of Stream '%stream%' required." } ;
ErrorId MsgDm::SubmitUpToDate          = { ErrorOf( ES_DM, 331, E_INFO, EV_NONE, 2 ), "%depotFile% - opened at head rev %workRev%" } ;
ErrorId MsgDm::SubmitWasAdd            = { ErrorOf( ES_DM, 332, E_INFO, EV_NONE, 2 ), "%depotFile% - %action% of added file; must %'revert'%" } ;
ErrorId MsgDm::SubmitWasDelete         = { ErrorOf( ES_DM, 333, E_INFO, EV_NONE, 2 ), "%depotFile% - %action% of deleted file; must %'revert'%" } ;
ErrorId MsgDm::SubmitWasDeleteCanReadd = { ErrorOf( ES_DM, 539, E_INFO, EV_NONE, 2 ), "%depotFile% - %action% of deleted file; must %'sync'% & %'add -d'% or %'revert'%" } ;
ErrorId MsgDm::SubmitMustResolve       = { ErrorOf( ES_DM, 334, E_INFO, EV_NONE, 1 ), "%depotFile% - must %'resolve'% before submitting" } ;
ErrorId MsgDm::SubmitTransfer          = { ErrorOf( ES_DM, 335, E_INFO, EV_NONE, 3 ), "%action% %depotFile%%depotRev%" } ; // NOTRANS
ErrorId MsgDm::SubmitRefresh           = { ErrorOf( ES_DM, 336, E_INFO, EV_NONE, 2 ), "%depotFile%%depotRev% - refreshing" } ;
ErrorId MsgDm::SubmitReverted          = { ErrorOf( ES_DM, 444, E_INFO, EV_NONE, 2 ), "%depotFile%%depotRev% - unchanged, reverted" } ;
ErrorId MsgDm::SubmitMovedToDefault    = { ErrorOf( ES_DM, 445, E_INFO, EV_NONE, 2 ), "%depotFile%%depotRev% - unchanged, moved to default changelist" } ;
ErrorId MsgDm::SubmitResolve           = { ErrorOf( ES_DM, 337, E_INFO, EV_NONE, 3 ), "%toFile% - must %'resolve'% %fromFile%%fromRev%" } ;
ErrorId MsgDm::SubmitNewResolve        = { ErrorOf( ES_DM, 338, E_INFO, EV_NONE, 2 ), "%fromFile% - must %'resolve'% %fromRev%" } ;
ErrorId MsgDm::SubmitChanges           = { ErrorOf( ES_DM, 339, E_INFO, EV_NONE, 2 ), "Use '%'p4 submit -c '%%change%' to submit file(s) in pending %newChange%." } ;
                               
ErrorId MsgDm::SyncAdd                 = { ErrorOf( ES_DM, 340, E_INFO, EV_NONE, 3 ), "%depotFile%%depotRev% - added as %localPath%" } ;
ErrorId MsgDm::SyncDelete              = { ErrorOf( ES_DM, 341, E_INFO, EV_NONE, 3 ), "%depotFile%%haveRev% - deleted as %localPath%" } ;
ErrorId MsgDm::SyncReplace             = { ErrorOf( ES_DM, 342, E_INFO, EV_NONE, 3 ), "%depotFile%%depotRev% - replacing %localPath%" } ;
ErrorId MsgDm::SyncCantDelete          = { ErrorOf( ES_DM, 343, E_INFO, EV_NONE, 3 ), "%depotFile%%workRev% - is opened for %action% and can't be deleted" } ;
ErrorId MsgDm::SyncCantReplace         = { ErrorOf( ES_DM, 344, E_INFO, EV_NONE, 3 ), "%depotFile%%workRev% - is opened for %action% and can't be replaced" } ;
ErrorId MsgDm::SyncUpdate              = { ErrorOf( ES_DM, 345, E_INFO, EV_NONE, 3 ), "%depotFile%%depotRev% - updating %localPath%" } ;
ErrorId MsgDm::SyncRefresh             = { ErrorOf( ES_DM, 346, E_INFO, EV_NONE, 3 ), "%depotFile%%depotRev% - refreshing %localPath%" } ;
ErrorId MsgDm::SyncIntegUpdate         = { ErrorOf( ES_DM, 347, E_INFO, EV_NONE, 2 ), "%depotFile%%workRev% - is opened and not being changed" } ;
ErrorId MsgDm::SyncIntegDelete         = { ErrorOf( ES_DM, 348, E_INFO, EV_NONE, 3 ), "%depotFile%%workRev% - is opened for %action% - not changed" } ;
ErrorId MsgDm::SyncIntegBackwards      = { ErrorOf( ES_DM, 349, E_INFO, EV_NONE, 2 ), "%depotFile%%workRev% - is opened at a later revision - not changed" } ;
ErrorId MsgDm::SyncUptodate            = { ErrorOf( ES_DM, 350, E_INFO, EV_NONE, 2 ), "%depotFile%%haveRev% - is up-to-date" } ;
ErrorId MsgDm::SyncResolve             = { ErrorOf( ES_DM, 351, E_INFO, EV_USAGE, 2 ), "%depotFile% - must %'resolve'% %revRange% before submitting" } ;
ErrorId MsgDm::SyncCantPublishIsOpen   = { ErrorOf( ES_DM, 457, E_INFO, EV_NONE, 1 ), "%depotFile% - can't %'sync -p'% a file that's opened" } ;
ErrorId MsgDm::SyncCantPublishOnHave   = { ErrorOf( ES_DM, 458, E_INFO, EV_NONE, 1 ), "%depotFile% - can't %'sync -p'% a file that's synced" } ;
ErrorId MsgDm::SyncMissingMoveSource   = { ErrorOf( ES_DM, 492, E_INFO, EV_NONE, 2 ), "%depotFile% - can't sync moved file,  %fromFile% is missing from the rev table!" } ; // NOTRANS
ErrorId MsgDm::SyncNotSafeAdd          = { ErrorOf( ES_DM, 602, E_INFO, EV_NONE, 3 ), "%depotFile%%depotRev% - can't overwrite existing file %localPath%" } ;
ErrorId MsgDm::SyncNotSafeDelete       = { ErrorOf( ES_DM, 603, E_INFO, EV_NONE, 3 ), "%depotFile%%depotRev% - can't delete modified file %localPath%" } ;
ErrorId MsgDm::SyncNotSafeUpdate       = { ErrorOf( ES_DM, 604, E_INFO, EV_NONE, 3 ), "%depotFile%%depotRev% - can't update modified file %localPath%" } ;
ErrorId MsgDm::SyncNotSafeReplace      = { ErrorOf( ES_DM, 605, E_INFO, EV_NONE, 3 ), "%depotFile%%depotRev% - can't replace modified file %localPath%" } ;
ErrorId MsgDm::SyncIndexOutOfBounds    = { ErrorOf( ES_DM, 606, E_FATAL, EV_FAULT, 2 ), "Index out of range %index% of %total%" } ; // NOTRANS

ErrorId MsgDm::TangentBadSource        = { ErrorOf( ES_DM, 878, E_FAILED, EV_FAULT, 2 ), "Can't create a tangent of %depotFile% because it is in a %badPlace%." } ;
ErrorId MsgDm::TangentBlockedDepot     = { ErrorOf( ES_DM, 879, E_FAILED, EV_FAULT, 1 ), "A %depotType% depot called '%'tangent'%' already exists; must create a new %'tangent'% depot." } ;
ErrorId MsgDm::TangentBranchedFile     = { ErrorOf( ES_DM, 880, E_INFO, EV_NONE, 2 ), "%depotFile%%depotRev% - branched to tangent" } ;
ErrorId MsgDm::TangentMovedFile        = { ErrorOf( ES_DM, 881, E_INFO, EV_NONE, 2 ), "%depotFile%%depotRev% - relocated to tangent" } ;

ErrorId MsgDm::TraitCleared            = { ErrorOf( ES_DM, 429, E_INFO, EV_NONE, 3 ), "%depotFile%%depotRev% - %name% cleared" } ;
ErrorId MsgDm::TraitNotSet             = { ErrorOf( ES_DM, 430, E_INFO, EV_NONE, 3 ), "%depotFile%%depotRev% - %name% not set" } ;
ErrorId MsgDm::TraitSet                = { ErrorOf( ES_DM, 431, E_INFO, EV_NONE, 3 ), "%depotFile%%depotRev% - %name% set" } ;
ErrorId MsgDm::TraitIsOpen             = { ErrorOf( ES_DM, 686, E_FAILED, EV_CONTEXT, 0 ), "Cannot set propagating traits on currently opened file(s)." } ;
                               
ErrorId MsgDm::TriggerSave             = { ErrorOf( ES_DM, 352, E_INFO, EV_NONE, 0 ), "Triggers saved." } ;
ErrorId MsgDm::TriggerNoChange         = { ErrorOf( ES_DM, 353, E_INFO, EV_NONE, 0 ), "Triggers not changed." } ;
ErrorId MsgDm::TriggerNoDepotFile      = { ErrorOf( ES_DM, 793, E_FAILED, EV_USAGE, 2 ), "Trigger depot file '%file%' not found, purged or wrong type for trigger '%trigger%'." } ;
ErrorId MsgDm::TriggerNoArchiveType    = { ErrorOf( ES_DM, 794, E_FAILED, EV_USAGE, 0 ), "Archive trigger may not use trigger depot files." } ;
ErrorId MsgDm::TriggerDuplicateType    = { ErrorOf( ES_DM, 960, E_FAILED, EV_USAGE, 1 ), "Only one trigger of type %type% allowed." } ;
ErrorId MsgDm::TriggerIncomplete2FA    = { ErrorOf( ES_DM, 961, E_FAILED, EV_USAGE, 0 ), "Incomplete set of second factor authentication triggers defined." } ;

ErrorId MsgDm::TypeMapSave             = { ErrorOf( ES_DM, 354, E_INFO, EV_NONE, 1 ), "%type% saved." } ;
ErrorId MsgDm::TypeMapNoChange         = { ErrorOf( ES_DM, 355, E_INFO, EV_NONE, 1 ), "%type% not changed." } ;
                               
ErrorId MsgDm::UnshelveBadAction       = { ErrorOf( ES_DM, 510, E_INFO, EV_NONE, 2 ), "%depotFile% - can't unshelve (already opened for %badAction%)" } ;
ErrorId MsgDm::UnshelveBadClientView       = { ErrorOf( ES_DM, 641, E_INFO, EV_NONE, 2 ), "%depotFile% - can't unshelve (already opened for %action% using a different client view path)" } ;
ErrorId MsgDm::UnshelveBadAdd       = { ErrorOf( ES_DM, 520, E_INFO, EV_NONE, 2 ), "Can't unshelve %depotFile% to open for %badAdd%: file already exists." } ;
ErrorId MsgDm::UnshelveBadEdit       = { ErrorOf( ES_DM, 521, E_INFO, EV_NONE, 2 ), "Can't unshelve %depotFile% to open for %badEdit%: file does not exist or has been deleted." } ;
ErrorId MsgDm::UnshelveSuccess         = { ErrorOf( ES_DM, 511, E_INFO, EV_NONE, 3 ), "%depotFile%%depotRev% - unshelved, opened for %action%" } ;
ErrorId MsgDm::UnshelveIsLocked        = { ErrorOf( ES_DM, 513, E_FAILED, EV_USAGE , 0 ), "File(s) in this shelve are locked - try again later!" } ;
ErrorId MsgDm::UnshelveResolve           = { ErrorOf( ES_DM, 621, E_INFO, EV_USAGE, 3 ), "%depotFile% - must %'resolve'% %fromFile%%rev% before submitting" } ;
ErrorId MsgDm::UnshelveNotTask         = { ErrorOf( ES_DM, 744, E_FAILED, EV_USAGE, 2 ), "%depotFile% - can't unshelve for %action%, task stream client required." } ;
ErrorId MsgDm::UnshelveFromRemote      = { ErrorOf( ES_DM, 797, E_INFO, EV_NONE, 2 ), "%depotFile% - can't unshelve from remote server (already opened for %badAction%)" } ;
ErrorId MsgDm::UnshelveBadChangeView   = { ErrorOf( ES_DM, 820, E_FAILED, EV_NOTYET, 2 ), "%depotFile% - can't unshelve from revision at change %change% (restricted by client's ChangeView)" } ;
ErrorId MsgDm::UnshelveBadAndmap       = { ErrorOf( ES_DM, 928, E_FAILED, EV_NOTYET, 2 ), "%clientFile% - can't unshelve from revision at change %change% (additionally mapped in client's View)" } ;

ErrorId MsgDm::UserSave                = { ErrorOf( ES_DM, 356, E_INFO, EV_NONE, 1 ), "User %user% saved." } ;
ErrorId MsgDm::UserNoChange            = { ErrorOf( ES_DM, 357, E_INFO, EV_NONE, 1 ), "User %user% not changed." } ;
ErrorId MsgDm::UserNotExist            = { ErrorOf( ES_DM, 358, E_FAILED, EV_UNKNOWN, 1 ), "User %user% doesn't exist." } ;
ErrorId MsgDm::UserCantDelete          = { ErrorOf( ES_DM, 359, E_INFO, EV_NONE, 2 ), "User %user% has file(s) open on %value% client(s) and can't be deleted." } ;
ErrorId MsgDm::UserDelete              = { ErrorOf( ES_DM, 360, E_INFO, EV_NONE, 1 ), "User %user% deleted." } ;
                               
ErrorId MsgDm::UsersData               = { ErrorOf( ES_DM, 361, E_INFO, EV_NONE, 4 ), "%user% <%email%> (%fullName%) accessed %accessDate%" } ;
ErrorId MsgDm::UsersDataLong           = { ErrorOf( ES_DM, 555, E_INFO, EV_NONE, 7 ), "%user% <%email%> (%fullName%) accessed %accessDate% type %type% ticket expires %endDate% password last changed %passDate%" } ;
                               
ErrorId MsgDm::VerifyData              = { ErrorOf( ES_DM, 362, E_INFO, EV_NONE, 7 ), "%depotFile%%depotRev% - %action% %change% (%type%) %digest%[ %status%]" } ; // NOTRANS
ErrorId MsgDm::VerifyDataProblem       = { ErrorOf( ES_DM, 730, E_FAILED, EV_NONE, 7 ), "%depotFile%%depotRev% - %action% %change% (%type%) %digest% %status%" } ; // NOTRANS
                               
ErrorId MsgDm::WhereData               = { ErrorOf( ES_DM, 364, E_INFO, EV_NONE, 4 ), "%mapFlag%%depotFile% %clientFile% %localPath%" } ; // NOTRANS
                               
ErrorId MsgDm::ExARCHIVES              = { ErrorOf( ES_DM, 790, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] such cached archive(s)." } ;
ErrorId MsgDm::ExCHANGE                = { ErrorOf( ES_DM, 365, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] such changelist." } ;
ErrorId MsgDm::ExSTREAM                = { ErrorOf( ES_DM, 508, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] such stream." } ;
ErrorId MsgDm::ExUSER                  = { ErrorOf( ES_DM, 366, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] such user(s)." } ;

ErrorId MsgDm::ExSTREAMOPEN            = { ErrorOf( ES_DM, 906, E_WARN, EV_EMPTY, 1 ), "[%argc% - stream|Stream] not opened on this client." } ;
                               
ErrorId MsgDm::ExVIEW                  = { ErrorOf( ES_DM, 367, E_WARN, EV_EMPTY, 1 ), "[%argc% - file(s)|File(s)] not in client view." } ;
ErrorId MsgDm::ExVIEW2                 = { ErrorOf( ES_DM, 477, E_WARN, EV_EMPTY, 2 ), "%!%[%argc% - file(s)|File(s)] not in client view." } ;
ErrorId MsgDm::ExSVIEW                 = { ErrorOf( ES_DM, 478, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] source file(s) in branch view." } ;
ErrorId MsgDm::ExTVIEW                 = { ErrorOf( ES_DM, 479, E_WARN, EV_EMPTY, 2 ), "%!%[%argc% - no|No] target file(s) in branch view." } ;
ErrorId MsgDm::ExBVIEW                 = { ErrorOf( ES_DM, 368, E_WARN, EV_EMPTY, 2 ), "%!%[%argc% - no|No] target file(s) in both client and branch view." } ;

ErrorId MsgDm::ExPROTECT               = { ErrorOf( ES_DM, 369, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] permission for operation on file(s)." } ;
ErrorId MsgDm::ExPROTECT2              = { ErrorOf( ES_DM, 480, E_WARN, EV_EMPTY, 2 ), "%!%[%argc% - no|No] permission for operation on file(s)." } ;
ErrorId MsgDm::ExPROTNAME              = { ErrorOf( ES_DM, 370, E_WARN, EV_EMPTY, 1 ), "[%argc% - protected|Protected] namespace - access denied." } ;
ErrorId MsgDm::ExPROTNAME2             = { ErrorOf( ES_DM, 481, E_WARN, EV_EMPTY, 2 ), "%!%[%argc% - protected|Protected] namespace - access denied." } ;
                               
ErrorId MsgDm::ExINTEGPEND             = { ErrorOf( ES_DM, 371, E_WARN, EV_EMPTY, 1 ), "[%argc% - all|All] revision(s) already integrated in pending changelist." } ;
ErrorId MsgDm::ExINTEGPERM             = { ErrorOf( ES_DM, 372, E_WARN, EV_EMPTY, 1 ), "[%argc% - all|All] revision(s) already integrated." } ;
ErrorId MsgDm::ExINTEGMOVEDEL          = { ErrorOf( ES_DM, 725, E_WARN, EV_EMPTY, 1 ), "[%argc% - move/delete(s)|Move/delete(s)] must be integrated along with matching move/add(s)." } ;
                               
ErrorId MsgDm::ExDIFF                  = { ErrorOf( ES_DM, 373, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] differing files." } ;
ErrorId MsgDm::ExDIFFPre101                  = { ErrorOf( ES_DM, 527, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] file(s) to diff." } ;
ErrorId MsgDm::ExDIGESTED              = { ErrorOf( ES_DM, 374, E_WARN, EV_EMPTY, 1 ), "[%argc% - file(s)|File(s)] already have digests." } ;
ErrorId MsgDm::ExUNLOADED              = { ErrorOf( ES_DM, 901, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] such unloaded client(s), label(s), or task stream(s)." } ;
ErrorId MsgDm::ExFILE                  = { ErrorOf( ES_DM, 375, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] such file(s)." } ;
ErrorId MsgDm::ExHAVE                  = { ErrorOf( ES_DM, 376, E_WARN, EV_EMPTY, 1 ), "[%argc% - file(s)|File(s)] not on client." } ;
ErrorId MsgDm::ExINTEGED               = { ErrorOf( ES_DM, 377, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] file(s) integrated." } ;
ErrorId MsgDm::ExLABEL                 = { ErrorOf( ES_DM, 378, E_WARN, EV_EMPTY, 1 ), "[%argc% - file(s)|File(s)] not in label." } ;
ErrorId MsgDm::ExLABSYNC               = { ErrorOf( ES_DM, 379, E_WARN, EV_EMPTY, 1 ), "[%argc% - label|Label] in sync." } ;
ErrorId MsgDm::ExOPENALL               = { ErrorOf( ES_DM, 380, E_WARN, EV_EMPTY, 1 ), "[%argc% - file(s)|File(s)] not opened anywhere." } ;
ErrorId MsgDm::ExOPENCHANGE            = { ErrorOf( ES_DM, 381, E_WARN, EV_EMPTY, 1 ), "[%argc% - file(s)|File(s)] not opened in that changelist." } ;
ErrorId MsgDm::ExUNLOCKCHANGE            = { ErrorOf( ES_DM, 650, E_WARN, EV_EMPTY, 1 ), "[%argc% - shelved|Shelved] file(s) not locked in that changelist." } ;
ErrorId MsgDm::ExOPENCLIENT            = { ErrorOf( ES_DM, 382, E_WARN, EV_EMPTY, 1 ), "[%argc% - file(s)|File(s)] not opened on this client." } ;
ErrorId MsgDm::ExOPENNOTEDIT           = { ErrorOf( ES_DM, 383, E_WARN, EV_EMPTY, 1 ), "[%argc% - file(s)|File(s)] not opened for edit." } ;
ErrorId MsgDm::ExOPENNOTEDITADD           = { ErrorOf( ES_DM, 849, E_WARN, EV_EMPTY, 1 ), "[%argc% - file(s)|File(s)] not opened for edit or add." } ;
ErrorId MsgDm::ExOPENDFLT              = { ErrorOf( ES_DM, 384, E_WARN, EV_EMPTY, 1 ), "[%argc% - file(s)|File(s)] not opened in default changelist." } ;
ErrorId MsgDm::ExRESOLVED              = { ErrorOf( ES_DM, 385, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] file(s) resolved." } ;
ErrorId MsgDm::ExTORESOLVE             = { ErrorOf( ES_DM, 387, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] file(s) to resolve." } ;
ErrorId MsgDm::ExTORETYPE              = { ErrorOf( ES_DM, 674, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] file(s) to retype." } ;
ErrorId MsgDm::ExUPTODATE              = { ErrorOf( ES_DM, 388, E_WARN, EV_EMPTY, 1 ), "[%argc% - file(s)|File(s)] up-to-date." } ;
ErrorId MsgDm::ExTOUNSHELVE             = { ErrorOf( ES_DM, 516, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] file(s) to unshelve." } ;
ErrorId MsgDm::ExTORECONCILE             = { ErrorOf( ES_DM, 683, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] file(s) to reconcile." } ;
                               
ErrorId MsgDm::ExABOVECHANGE           = { ErrorOf( ES_DM, 389, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] revision(s) above those at that changelist number." } ;
ErrorId MsgDm::ExABOVEDATE             = { ErrorOf( ES_DM, 390, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] revision(s) after that date." } ;
ErrorId MsgDm::ExABOVEHAVE             = { ErrorOf( ES_DM, 391, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] revision(s) above those on client." } ;
ErrorId MsgDm::ExABOVELABEL            = { ErrorOf( ES_DM, 392, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] revision(s) above those in label." } ;
ErrorId MsgDm::ExABOVEREVISION         = { ErrorOf( ES_DM, 393, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] revision(s) above that revision." } ;
                               
ErrorId MsgDm::ExATCHANGE              = { ErrorOf( ES_DM, 394, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] file(s) at that changelist number." } ;
ErrorId MsgDm::ExATDATE                = { ErrorOf( ES_DM, 395, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] file(s) as of that date." } ;
ErrorId MsgDm::ExATHAVE                = { ErrorOf( ES_DM, 396, E_WARN, EV_EMPTY, 1 ), "[%argc% - file(s)|File(s)] not on client." } ;
ErrorId MsgDm::ExATLABEL               = { ErrorOf( ES_DM, 397, E_WARN, EV_EMPTY, 1 ), "[%argc% - file(s)|File(s)] not in label." } ;
ErrorId MsgDm::ExATREVISION            = { ErrorOf( ES_DM, 398, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] file(s) at that revision." } ;
ErrorId MsgDm::ExATACTION              = { ErrorOf( ES_DM, 399, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] file(s) with that action." } ;
ErrorId MsgDm::ExATTEXT              = { ErrorOf( ES_DM, 540, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] file(s) of type %'text'%." } ;
                               
ErrorId MsgDm::ExBELOWCHANGE           = { ErrorOf( ES_DM, 400, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] revision(s) below those at that changelist number." } ;
ErrorId MsgDm::ExBELOWDATE             = { ErrorOf( ES_DM, 401, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] revision(s) before that date." } ;
ErrorId MsgDm::ExBELOWHAVE             = { ErrorOf( ES_DM, 402, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] revision(s) below those on client." } ;
ErrorId MsgDm::ExBELOWLABEL            = { ErrorOf( ES_DM, 403, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] revision(s) below those in label." } ;
ErrorId MsgDm::ExBELOWREVISION         = { ErrorOf( ES_DM, 404, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] revision(s) below that revision." } ;

ErrorId MsgDm::OpenWarnPurged          = { ErrorOf( ES_DM, 405, E_INFO, EV_USAGE, 2 ), "%depotFile% - warning: %action% of purged file" } ;

ErrorId MsgDm::MonitorData             = { ErrorOf( ES_DM, 406, E_INFO, EV_NONE, 9 ), "%id% [%prog% ][%host% ][%runstate%|T] %user% [%client% ]%elapsed% %function% %args%" } ; // NOTRANS
ErrorId MsgDm::MonitorClear            = { ErrorOf( ES_DM, 407, E_INFO, EV_NONE, 1 ), "** process '%id%' record cleared **" } ;
ErrorId MsgDm::MonitorPause            = { ErrorOf( ES_DM, 609, E_INFO, EV_NONE, 1 ), "** process '%id%' record paused **" } ;
ErrorId MsgDm::MonitorResume           = { ErrorOf( ES_DM, 610, E_INFO, EV_NONE, 1 ), "** process '%id%' record resumed **" } ;
ErrorId MsgDm::MonitorTerminate        = { ErrorOf( ES_DM, 408, E_INFO, EV_NONE, 1 ), "** process '%id%' marked for termination **" } ;
ErrorId MsgDm::MonitorCantTerminate    = { ErrorOf( ES_DM, 409, E_INFO, EV_NONE, 1 ), "** process '%id%' can't terminate, runtime < 10 seconds **" } ;

ErrorId MsgDm::AdminSpecData           = { ErrorOf( ES_DM, 466, E_INFO, EV_NONE, 1 ), "%depotFile% - created" } ;
ErrorId MsgDm::AdminPasswordData       = { ErrorOf( ES_DM, 723, E_INFO, EV_NONE, 1 ), "%user% - must reset password" } ;
ErrorId MsgDm::AdminSetLdapUserData    = { ErrorOf( ES_DM, 867, E_INFO, EV_NONE, 1 ), "%user% - now authenticates against LDAP" } ;
ErrorId MsgDm::AdminSetLdapUserNoSuper = { ErrorOf( ES_DM, 875, E_FAILED, EV_USAGE, 0 ), "At least one super user with AuthMethod of 'perforce' must exist to perform this operation." } ;

// Plucked from msgdb.cc.
// XXX These should be ES_DM.

ErrorId MsgDm::NotUnderRoot            = { ErrorOf( ES_DB, 39, E_FAILED, EV_CONTEXT, 2 ), "Path '%path%' is not under client's root '%root%'." } ;
ErrorId MsgDm::NotUnderClient          = { ErrorOf( ES_DB, 40, E_FAILED, EV_CONTEXT, 2 ), "Path '%path%' is not under client '%client%'." } ;

ErrorId MsgDm::CommandCancelled        = { ErrorOf( ES_DB, 62, E_FAILED, EV_COMM, 0 ), "Command terminated because client closed connection." } ;
ErrorId MsgDm::MaxResults              = { ErrorOf( ES_DB, 32, E_FAILED, EV_ADMIN, 1 ), "Request too large (over %maxResults%); see '%'p4 help maxresults'%'." } ;
ErrorId MsgDm::MaxScanRows             = { ErrorOf( ES_DB, 61, E_FAILED, EV_ADMIN, 1 ), "Too many rows scanned (over %maxScanRows%); see '%'p4 help maxscanrows'%'." } ;
ErrorId MsgDm::MaxLockTime             = { ErrorOf( ES_DM, 453, E_FAILED, EV_ADMIN, 1 ), "Operation took too long (over %maxLockTime% seconds); see '%'p4 help maxlocktime'%'." } ;
ErrorId MsgDm::MaxOpenFiles            = { ErrorOf( ES_DM, 500, E_FAILED, EV_ADMIN, 1 ), "Opening too many files (over %maxOpenFiles%); see '%'p4 help maxopenfiles'%'." } ;
ErrorId MsgDm::UnknownReplicationMode  = { ErrorOf( ES_DM, 611, E_FAILED, EV_FAULT, 1 ), "Unknown replication mode '%mode%'." } ;
ErrorId MsgDm::UnknownReplicationTarget = { ErrorOf( ES_DM, 612, E_FAILED, EV_FAULT, 1 ), "Unknown replication target '%target%'." } ;

ErrorId MsgDm::AdminLockDataEx         = { ErrorOf( ES_DM, 475, E_INFO, EV_ADMIN, 1 ), "Write: %name%" } ; // NOTRANS CONTENTIOUS: lockstat output sent to support?
ErrorId MsgDm::AdminLockDataSh         = { ErrorOf( ES_DM, 476, E_INFO, EV_ADMIN, 1 ), "Read : %name%" } ; // NOTRANS CONTENTIOUS: lockstat output sent to support?

ErrorId MsgDm::DiskSpaceMinimum        = { ErrorOf( ES_DM, 613, E_FAILED, EV_UNKNOWN, 3 ), "The filesystem '%filesys%' has only %freeSpace% free, but the server configuration requires at least %cfgSpace% available." } ;
ErrorId MsgDm::DiskSpaceEstimated      = { ErrorOf( ES_DM, 614, E_FAILED, EV_UNKNOWN, 3 ), "The filesystem '%filesys%' has only %freeSpace% free, but the command estimates it needs at least %estSpace% available." } ;

ErrorId MsgDm::ResourceAlreadyLocked   = { ErrorOf( ES_DM, 628, E_FATAL, EV_FAULT, 2 ), "Resource %objType%#%objName% is already locked!" } ; // NOTRANS
ErrorId MsgDm::NoSuchResource          = { ErrorOf( ES_DM, 629, E_FATAL, EV_FAULT, 2 ), "Resource %objType%#%objName% was never locked!" } ; // NOTRANS
ErrorId MsgDm::ServersJnlAckData       = { ErrorOf( ES_DM, 801, E_INFO, EV_NONE, 9 ),
    "%serverID% '%lastUpdate%' %serverType% %persistedJnl%/%persistedPos% %appliedJnl%/%appliedPos% %jaFlags% %isAlive%" } ; // NOTRANS
ErrorId MsgDm::NoSharedRevision        = { ErrorOf( ES_DM, 817, E_FAILED, EV_USAGE, 1 ), "Cannot import %depotFile% because there is no existing revision." } ;
ErrorId MsgDm::NoSharedHistory         = { ErrorOf( ES_DM, 853, E_FAILED, EV_USAGE, 2 ), "Cannot import %depotFile%%depotRev% because it is not common to both file histories." } ;
ErrorId MsgDm::ImportNoPermission         = { ErrorOf( ES_DM, 846, E_FAILED, EV_CONTEXT, 1 ), "Cannot import '%depotFile%' - protected namespace - access denied" } ;
ErrorId MsgDm::ImportNoDepot           = { ErrorOf( ES_DM, 847, E_FAILED, EV_CONTEXT, 1 ), "Cannot import '%depotFile%' because it is in an unknown depot." } ;
ErrorId MsgDm::ImportDepotReadOnly     = { ErrorOf( ES_DM, 848, E_FAILED, EV_CONTEXT, 1 ), "Cannot import '%depotFile%' because this is a read-only depot." } ;
ErrorId MsgDm::DepotDepthDiffers     = { ErrorOf( ES_DM, 883, E_FAILED, EV_CONTEXT, 1 ), "Cannot change stream depth '%depotDepth%' when streams or depot archives already exist." } ;
ErrorId MsgDm::StreamDepthDiffers     = { ErrorOf( ES_DM, 893, E_FAILED, EV_CONTEXT, 2 ), "Stream %stream% name does not reflect depot depth-field '%depotDepth%'." } ;
ErrorId MsgDm::DepotStreamDepthReq     = { ErrorOf( ES_DM, 896, E_FAILED, EV_CONTEXT, 1 ), "Depot '%depot%' of type stream requires StreamDepth field between 1-10." } ;
ErrorId MsgDm::ZipIntegMismatch        = { ErrorOf( ES_DM, 834, E_FAILED, EV_FAULT, 0 ), "Integration record mismatch." } ;
ErrorId MsgDm::ZipBranchDidntMap       = { ErrorOf( ES_DM, 835, E_FAILED, EV_USAGE, 1 ), "Specified branch map is missing an entry for %depotFile%." } ;
ErrorId MsgDm::UnrecognizedRevision    = { ErrorOf( ES_DM, 823, E_FAILED, EV_USAGE, 1 ), "Cannot import %depotFile% because its history is unrecognizable." } ;
ErrorId MsgDm::NoLazySource            = { ErrorOf( ES_DM, 824, E_FAILED, EV_USAGE, 1 ), "Cannot import %depotFile%#%depotRev% because the source revision cannot be found." } ;
ErrorId MsgDm::RevisionAlreadyPresent  = { ErrorOf( ES_DM, 822, E_FAILED, EV_USAGE, 1 ), "Cannot import %depotFile% because there is already an existing revision." } ;
ErrorId MsgDm::SharedActionMismatch    = { ErrorOf( ES_DM, 818, E_FAILED, EV_USAGE, 3 ), "Conflict: %change% %depotFile%%depotRev% (%action%)." } ;
ErrorId MsgDm::SharedDigestMismatch    = { ErrorOf( ES_DM, 819, E_FAILED, EV_USAGE, 6 ), "Cannot import %importFile%%importRev% (%importDigest%) over %depotFile%%depotRev% (%digest%)" } ;
ErrorId MsgDm::ImportedChange          = { ErrorOf( ES_DM, 841, E_INFO, EV_NONE, 2 ), "Change %change% imported as change %finalChange%." } ;
ErrorId MsgDm::ImportedFile            = { ErrorOf( ES_DM, 842, E_INFO, EV_NONE, 3 ), "File %depotFile%%depotRev% imported as %targetRev%." } ;
ErrorId MsgDm::ImportedIntegration     = { ErrorOf( ES_DM, 843, E_INFO, EV_NONE, 2 ), "Integration imported from %fromFile% to %toFile%." } ;
ErrorId MsgDm::ImportSkippedInteg      = { ErrorOf( ES_DM, 851, E_INFO, EV_NONE, 2 ), "Integration from %fromFile% to %toFile% was already present in the target repository." } ;
ErrorId MsgDm::ImportWouldAddChange    = { ErrorOf( ES_DM, 891, E_INFO, EV_NONE, 1 ), "Change %change% would be imported to the target repository." } ;
ErrorId MsgDm::ImportDanglingInteg     = { ErrorOf( ES_DM, 857, E_INFO, EV_NONE, 2 ), "Integration from %fromFile% to %toFile% ignored due to missing revision." } ;
ErrorId MsgDm::ImportSkippedChange     = { ErrorOf( ES_DM, 844, E_INFO, EV_NONE, 1 ), "Change %change% was already present in the target repository." } ;
ErrorId MsgDm::ImportSkippedFile       = { ErrorOf( ES_DM, 845, E_INFO, EV_NONE, 1 ), "File %depotFile%%depotRev% was already present in the target repository." } ;
ErrorId MsgDm::InvalidZipFormat        = { ErrorOf( ES_DM, 826, E_FAILED, EV_FAULT, 1 ), "Invalid zipfile format: %details%." } ;
ErrorId MsgDm::UnzipCouldntLock        = { ErrorOf( ES_DM, 858, E_FAILED, EV_USAGE, 1 ), "Cannot import revisions. Not all files could be %action%." } ;
ErrorId MsgDm::UnzipIsTaskStream       = { ErrorOf( ES_DM, 877, E_FAILED, EV_USAGE, 3 ), "File %depotFile%%depotRev% cannot be imported. This version of the server does not support copying changes from a remote server into the task stream %streamName%. Exclude the task stream's files from the remote map, or map them to an alternate destination, or delete the task stream from the destination server, and retry the operation." } ;
ErrorId MsgDm::UnzipIsLocked           = { ErrorOf( ES_DM, 859, E_FAILED, EV_USAGE, 3 ), "%depotFile% - locked by %user%@%client%" } ;
ErrorId MsgDm::ResubmitNoFiles         = { ErrorOf( ES_DM, 864, E_FAILED, EV_USAGE, 1 ), "Cannot resubmit shelved %change% because no shelved files were found." } ;
ErrorId MsgDm::ResubmitStreamClassic   = { ErrorOf( ES_DM, 865, E_FAILED, EV_USAGE, 0 ), "Cannot resubmit these changes because some affect stream depots while others affect classic depots." } ;
ErrorId MsgDm::ResubmitMultiStream     = { ErrorOf( ES_DM, 866, E_FAILED, EV_USAGE, 1 ), "Cannot resubmit change %change% because it affects multiple stream depots." } ;
ErrorId MsgDm::UnsubmittedChange       = { ErrorOf( ES_DM, 855, E_INFO, EV_NONE, 1 ), "Change %change% unsubmitted and shelved." } ;
ErrorId MsgDm::UnsubmittedRenamed      = { ErrorOf( ES_DM, 868, E_INFO, EV_NONE, 2 ), "Change %change% renamed as %origChange%, unsubmitted and shelved." } ;
ErrorId MsgDm::UnsubmitNotHead         = { ErrorOf( ES_DM, 827, E_FAILED, EV_USAGE, 3 ), "Cannot unsubmit %depotFile%%depotRev% because the head revision is %headRev%" } ;
ErrorId MsgDm::UnsubmitNoTraits        = { ErrorOf( ES_DM, 850, E_FAILED, EV_USAGE, 2 ), "Cannot unsubmit %depotFile%%depotRev% because it has associated attributes." } ;
ErrorId MsgDm::UnsubmitOpened          = { ErrorOf( ES_DM, 828, E_FAILED, EV_USAGE, 3 ), "Cannot unsubmit %depotFile%%depotRev% because it is currently opened by %client%" } ;
ErrorId MsgDm::UnsubmitArchived        = { ErrorOf( ES_DM, 854, E_FAILED, EV_USAGE, 3 ), "Cannot unsubmit %depotFile%%depotRev% - %action% has occurred." } ;
ErrorId MsgDm::UnsubmitTaskStream      = { ErrorOf( ES_DM, 863, E_FAILED, EV_USAGE, 2 ), "Cannot unsubmit %depotFile%%depotRev% - it is in an active task stream." } ;
ErrorId MsgDm::UnsubmitNotSubmitted    = { ErrorOf( ES_DM, 829, E_FAILED, EV_USAGE, 1 ), "Cannot unsubmit change %change% because it is not a submitted change." } ;
ErrorId MsgDm::UnsubmitEmptyChange     = { ErrorOf( ES_DM, 884, E_FAILED, EV_USAGE, 1 ), "Cannot unsubmit change %change% because it is an empty change." } ;
ErrorId MsgDm::UnsubmitWrongUser       = { ErrorOf( ES_DM, 830, E_FAILED, EV_USAGE, 1 ), "Cannot unsubmit change %change% because it was submitted by another user." } ;
ErrorId MsgDm::UnsubmitWrongClient     = { ErrorOf( ES_DM, 831, E_FAILED, EV_USAGE, 1 ), "Cannot unsubmit change %change% because it was submitted by another client." } ;
ErrorId MsgDm::UnsubmitIntegrated      = { ErrorOf( ES_DM, 832, E_FAILED, EV_USAGE, 3 ), "Cannot unsubmit %change% because %depotFile%%depotRev% has been integrated elsewhere." } ;
ErrorId MsgDm::UnsubmitNoInteg         = { ErrorOf( ES_DM, 833, E_FAILED, EV_FAULT, 0 ), "Integration record mismatch." } ;
ErrorId MsgDm::UnsubmitNoChanges       = { ErrorOf( ES_DM, 874, E_FAILED, EV_USAGE, 1 ), "No changes were found matching %filespec% that could be unsubmitted." } ;
ErrorId MsgDm::UnzipChangePresent      = { ErrorOf( ES_DM, 869, E_FATAL, EV_FAULT, 1 ), "An attempt was made to import %change% into this server, but a change record for that change is already present!" } ;
ErrorId MsgDm::UnzipNoSuchArchive      = { ErrorOf( ES_DM, 882, E_FAILED, EV_FAULT, 1 ), "Input zip file does not contain an archive entry for %archiveEntry%." } ;
ErrorId MsgDm::UnzipRevisionPresent    = { ErrorOf( ES_DM, 870, E_FATAL, EV_FAULT, 2 ), "An attempt was made to import %depotFile%%depotRev% into this server, but a revision record for that revision is already present!" } ;
ErrorId MsgDm::UnzipIntegrationPresent = { ErrorOf( ES_DM, 871, E_FATAL, EV_FAULT, 4 ), "An attempt was made to import integration %toFile% %how% %fromFile% %fromRevRange% into this server, but an integration record for that integration is already present!" } ;
ErrorId MsgDm::UnzipArchiveUnknown     = { ErrorOf( ES_DM, 873, E_FATAL, EV_FAULT, 4 ), "Partner server sent an unexpected archive! For index %index%, the supplied archive was %lbrFile% %lbrRev%, but our archive decision was %decision%." } ;
ErrorId MsgDm::ChangeIdentityAlready   = { ErrorOf( ES_DM, 887, E_FAILED, EV_USAGE, 3 ), "%change% may not be given identity %identity% because that identity has already been used by %existingChange%." } ;
ErrorId MsgDm::ReservedClientName      = { ErrorOf( ES_DM, 892, E_FAILED, EV_USAGE, 1 ), "Client may not be named '%clientName%'; that is a reserved name." } ;
ErrorId MsgDm::CannotChangeStorageType = { ErrorOf( ES_DM, 894, E_FAILED, EV_USAGE, 0 ), "Client storage type cannot be changed after client is created." } ;
ErrorId MsgDm::ServerLocksOrder        = { ErrorOf( ES_DM, 895, E_FATAL, EV_FAULT, 4 ), "Server locking failure: %objectType% %objectName% %lockOrder% locked after %currentLockOrder%!" } ;//NOTRANS
ErrorId MsgDm::CounterNoTAS            = { ErrorOf( ES_DM, 920, E_FAILED, EV_USAGE, 2 ), "New value for %counterName% not set. Current value is %counterValue%." } ;
ErrorId MsgDm::JoinMax1TooSmall	       = { ErrorOf( ES_DM, 922, E_FAILED, EV_FAULT, 1 ), "Command exceeded map.joinmax1 size (%joinmax1% bytes).  This length can be increased by setting the map.joinmax1 configurable." } ;
ErrorId MsgDm::RevMissing              = { ErrorOf( ES_DM, 962, E_FATAL, EV_FAULT, 2 ), "Revision %depotFile%%depotRev% is missing from the metadata! (Perhaps it was obliterated?)" } ;
ErrorId MsgDm::RevChangedDuringPush    = { ErrorOf( ES_DM, 923, E_FAILED, EV_USAGE, 2 ), "Conflict: A concurrent modification to %depotFile%%depotRev% occurred during this push/fetch/unzip operation, causing the import step to be halted." } ;
ErrorId MsgDm::UnknownReadonlyDir      = { ErrorOf( ES_DM, 936, E_FAILED, EV_ADMIN, 1 ), "Client %clientName% cannot be accessed, because clients of type %'readonly'% are unavailable if the %'client.readonly.dir'% configuration variable is invalid or unset." } ;
ErrorId MsgDm::ShelveNotSubmittable    = { ErrorOf( ES_DM, 937, E_FAILED, EV_NOTYET, 1 ), "Shelved file %depotFile% has no submitted revisions. Perhaps the file was obliterated after the shelf was created, or perhaps the shelf was pushed from another server where the underlying file exists. You may unshelve the file and resolve it to specify that the new file should be added, or you may remove the file from the shelf, or you may submit the underlying revision first, but you may not submit this shelf as-is." } ;
ErrorId MsgDm::NoSplitMoves            = { ErrorOf( ES_DM, 938, E_FAILED, EV_NOTYET, 4 ), "Change %change% performs a %action% on %file%%rev%, but the parameters of this fetch, push, or zip command include only part of the full action. Specify a wider view to include both the source and target of the change, or specify a narrower view to exclude both the source and target of the change." } ;
ErrorId MsgDm::CallerMustForward       = { ErrorOf( ES_DM, 945, E_FATAL, EV_FAULT, 0 ), "Client requires forwarding." }; // NOTRANS
ErrorId MsgDm::CantForwardDelete       = { ErrorOf( ES_DM, 946, E_FAILED, EV_USAGE, 0 ), "Delete operation cancelled, main server is not reachable at the moment, try again later!" } ;
ErrorId MsgDm::LogFilenameInvalid      = { ErrorOf( ES_DM, 947, E_FAILED, EV_USAGE, 0 ), "Log filename is invalid." } ;
ErrorId MsgDm::LogFormatInvalid        = { ErrorOf( ES_DM, 948, E_FAILED, EV_USAGE, 0 ), "Log format is invalid." } ;
ErrorId MsgDm::LogNumericInvalid       = { ErrorOf( ES_DM, 949, E_FAILED, EV_USAGE, 1 ), "Log %property% must be numeric." } ;
ErrorId MsgDm::LogEventsUnmatched      = { ErrorOf( ES_DM, 950, E_FAILED, EV_USAGE, 0 ), "Log captures no events." } ;

// ErrorId graveyard: retired/deprecated ErrorIds. 

ErrorId MsgDm::BadMaxScanRow           = { ErrorOf( ES_DM, 16, E_FAILED, EV_USAGE, 1 ), "Invalid %'MaxScanRow'% number '%value%'." } ;  // NOTRANS
ErrorId MsgDm::ErrorInSpec             = { ErrorOf( ES_DM, 69, E_FAILED, EV_ILLEGAL, 1 ), "Error in %domain% specification." } ; //NOTRANS
ErrorId MsgDm::JobName101              = { ErrorOf( ES_DM, 79, E_FAILED, EV_USAGE, 0 ), "A job name field with code %'101'% must be present." } ; //NOTRANS
ErrorId MsgDm::NoCodeZero              = { ErrorOf( ES_DM, 115, E_FAILED, EV_USAGE, 1 ), "Code %'0'% not allowed on field '%field%'." } ; // NOTRANS
ErrorId MsgDm::FixAddDefault           = { ErrorOf( ES_DM, 237, E_INFO, EV_NONE, 2 ), "%job% fixed by %change%." } ; // NOTRANS
ErrorId MsgDm::FixesDataDefault        = { ErrorOf( ES_DM, 240, E_INFO, EV_NONE, 5 ), "%job% fixed by %change% on %date% by %user%@%client%" } ; // NOTRANS
ErrorId MsgDm::InfoUnknownDomain       = { ErrorOf( ES_DM, 248, E_INFO, EV_NONE, 1 ), "%domainType% unknown." } ; // NOTRANS
ErrorId MsgDm::InfoDomain              = { ErrorOf( ES_DM, 249, E_INFO, EV_NONE, 2 ), "%domainType% root: %root%" } ; // NOTRANS
ErrorId MsgDm::EditSpecSave             = { ErrorOf( ES_DM, 270, E_INFO, EV_NONE, 1 ), "Spec %type% saved." } ; // NOTRANS
ErrorId MsgDm::EditSpecNoChange         = { ErrorOf( ES_DM, 271, E_INFO, EV_NONE, 1 ), "Spec %type% not changed." } ; // NOTRANS
ErrorId MsgDm::ExTOINTEG               = { ErrorOf( ES_DM, 386, E_WARN, EV_EMPTY, 1 ), "[%argc% - no|No] file(s) to integrate." } ; // NOTRANS
ErrorId MsgDm::IntegOpenOkay           = { ErrorOf( ES_DM, 261, E_INFO, EV_NONE, 5 ), "%depotFile%%workRev% - %action% from %fromFile%%fromRev%" } ; // NOTRANS
ErrorId MsgDm::IntegSyncDelete         = { ErrorOf( ES_DM, 263, E_INFO, EV_NONE, 5 ), "%depotFile%%workRev% - %'sync'%/%action% from %fromFile%%fromRev%" } ; // NOTRANS
ErrorId MsgDm::NoNextRev               = { ErrorOf( ES_DM, 48, E_FATAL, EV_FAULT, 1 ), "Can't find %depotFile%'s successor rev!" } ; // NOTRANS
ErrorId MsgDm::DepotSpecDup            = { ErrorOf( ES_DM, 420, E_FAILED, EV_CONTEXT, 1 ), "There is already a %'spec'% depot called '%depot%'." };	// NOTRANS
