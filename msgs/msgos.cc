/*
 * Copyright 1995, 2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * msgos.cc - definitions of errors for zlib C++ interface
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
 * Current high value for a MsgOs error code is: 25
 */

# include <error.h>
# include <errornum.h>
# include <msgos.h>

ErrorId MsgOs::Sys                     = { ErrorOf( ES_OS, 1, E_FAILED, EV_FAULT, 3 ), "%operation%: %arg%: %errmsg%" } ;
ErrorId MsgOs::Sys2                    = { ErrorOf( ES_OS, 9, E_FAILED, EV_FAULT, 3 ), "%operation2%: %arg2%: %errmsg2%" } ;  // like Sys but different parm names
ErrorId MsgOs::SysUn                   = { ErrorOf( ES_OS, 2, E_FAILED, EV_FAULT, 3 ), "%operation%: %arg%: unknown errno %errno%" } ;
ErrorId MsgOs::SysUn2                  = { ErrorOf( ES_OS, 10, E_FAILED, EV_FAULT, 3 ), "%operation2%: %arg2%: unknown errno %errno2%" } ;  // like SysUn but different parm names
ErrorId MsgOs::ChmodBetrayal           = { ErrorOf( ES_OS, 11, E_FATAL, EV_FAULT, 4 ), "File mode modification failed! File %oldname% was successfully renamed to %newname% but the file permissions were not correctly changed to read-only. The current permissions are %perms% and the file inode number is %inode%." } ;

// Windows specific
ErrorId MsgOs::Net                     = { ErrorOf( ES_OS, 3, E_FAILED, EV_COMM, 3 ), "%operation%: %arg%: %errmsg%" } ;
ErrorId MsgOs::NetUn                   = { ErrorOf( ES_OS, 4, E_FAILED, EV_COMM, 3 ), "%operation%: %arg%: unknown network error %errno%" } ;

ErrorId MsgOs::TooMany                 = { ErrorOf( ES_OS, 5, E_FATAL, EV_FAULT, 1 ), "%handle%: too many handles!" } ;
ErrorId MsgOs::Deleted                 = { ErrorOf( ES_OS, 6, E_FATAL, EV_FAULT, 1 ), "%handle%: deleted handled!" } ;
ErrorId MsgOs::NoSuch                  = { ErrorOf( ES_OS, 7, E_FATAL, EV_FAULT, 1 ), "%handle%: no such handle!" } ;

ErrorId MsgOs::EmptyFork               = { ErrorOf( ES_OS, 8, E_FAILED, EV_CLIENT, 1 ), "Resource fork for %file% from server is empty." } ;

ErrorId MsgOs::NameTooLong             = { ErrorOf( ES_OS, 12, E_FAILED, EV_FAULT, 3 ), "Filename '%filename%' is length %actual% which exceeds the internal length limit of %maxlen%." } ;

ErrorId MsgOs::ZipExists               = { ErrorOf( ES_OS, 13, E_FAILED, EV_FAULT, 1 ), "Output zip file %file% already exists." } ;
ErrorId MsgOs::ZipOpenEntryFailed      = { ErrorOf( ES_OS, 14, E_FAILED, EV_FAULT, 2 ), "Error %errorcode% creating new entry %entry% in zip" } ;
ErrorId MsgOs::ZipCloseEntryFailed     = { ErrorOf( ES_OS, 15, E_FAILED, EV_FAULT, 1 ), "Error %errorcode% closing entry in zip" } ;
ErrorId MsgOs::ZipWriteFailed          = { ErrorOf( ES_OS, 16, E_FAILED, EV_FAULT, 2 ), "Error %errorcode% writing buffer of length %len% in zip" } ;
ErrorId MsgOs::ZipMissing              = { ErrorOf( ES_OS, 17, E_FAILED, EV_FAULT, 1 ), "Input zip file %file% is missing." } ;
ErrorId MsgOs::ZipNoEntry              = { ErrorOf( ES_OS, 18, E_FAILED, EV_FAULT, 2 ), "Error %errorcode% locating entry %entry% in zip." } ;
ErrorId MsgOs::ZipOpenEntry            = { ErrorOf( ES_OS, 19, E_FAILED, EV_FAULT, 2 ), "Error %errorcode% opening entry %entry% in zip." } ;
ErrorId MsgOs::ZipReadFailed           = { ErrorOf( ES_OS, 20, E_FAILED, EV_FAULT, 2 ), "Error %errorcode% reading buffer of length %len% from zip." } ;
ErrorId MsgOs::ZlibInflateInit         = { ErrorOf( ES_OS, 21, E_FAILED, EV_FAULT, 2 ), "inflateInit failed: for file %file%, inflateInit returned %retCode%." } ;
ErrorId MsgOs::ZlibInflateEOF          = { ErrorOf( ES_OS, 22, E_FAILED, EV_FAULT, 1 ), "Premature end of compressed object data in file %file%" } ;
ErrorId MsgOs::ZlibInflate             = { ErrorOf( ES_OS, 23, E_FAILED, EV_FAULT, 2 ), "inflate returned error: for file %file%, inflate returned %retCode%." } ;
ErrorId MsgOs::ZlibDeflateInit         = { ErrorOf( ES_OS, 24, E_FAILED, EV_FAULT, 2 ), "deflateInit failed: for file %file%, deflateInit returned %retCode%." } ;
ErrorId MsgOs::ZlibInflateInitSeek     = { ErrorOf( ES_OS, 25, E_FAILED, EV_FAULT, 3 ), "inflateInit failed: for file %file%, inflateInit returned %retCode% after seek to position %seekPos%." } ;

// ErrorId graveyard: retired/deprecated ErrorIds. 
