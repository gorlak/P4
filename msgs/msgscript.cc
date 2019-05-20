/*
 * Copyright 2018 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * msgserver.cc - definitions of errors for scripting subsystem.
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
 * Current high value for a MsgServer error code is: 6
 */

# include <error.h>
# include <errornum.h>
# include "msgscript.h"

ErrorId MsgScript::ScriptRuntimeError  = { ErrorOf( ES_SCRIPT, 1, E_FATAL, EV_FAULT, 2 ), "%lang% runtime error:  %error%." } ;
ErrorId MsgScript::ScriptMaxRunErr     = { ErrorOf( ES_SCRIPT, 2, E_FATAL, EV_FAULT, 2 ), "Script ran over %type% limit of %limit%[ %suffix%|]." } ;
ErrorId MsgScript::DoNotBlameTheScript = { ErrorOf( ES_SCRIPT, 3, E_FATAL, EV_FAULT, 0 ), "Error object passed to scripting already set with an error." } ;

ErrorId MsgScript::ExtAddChangeDesc    = { ErrorOf( ES_SCRIPT, 4, E_INFO , EV_NONE , 2 ), "Installing extension: %extName%\nVersion: %extVersion%" } ;
ErrorId MsgScript::ExtEditChangeDesc   = { ErrorOf( ES_SCRIPT, 5, E_INFO , EV_NONE , 3 ), "Updating extension: %extName%\nVersion: %toExtVersion%\nPrevious version: %fromExtVersion%" } ;

ErrorId MsgScript::ExtLoadErr          = { ErrorOf( ES_SCRIPT, 6, E_FATAL, EV_FAULT, 2 ), "Could not load extension '%extName%', rev '%extRev%'." } ;

// ErrorId graveyard: retired/deprecated ErrorIds. 
