#include <Foundation/Foundation.h>
#include <ApplicationServices/ApplicationServices.h>


#include <macutil.h>

bool WindowServicesAvailable()
{
    CFDictionaryRef sessionInfoDict = CGSessionCopyCurrentDictionary();
    
    if ( sessionInfoDict == NULL )
        return false;
    
    CFRelease( sessionInfoDict );
    
    return true;
}

/*
//   If 'Terminal' is running already, run the command in a new Window
//   If 'Terminal' is not yet running, run the command the front most (just  opened) Window.
*/
bool RunCommandInNewTerminalWithCFStrRef( CFStringRef command )
{
	NSString * s = [[NSString alloc] initWithFormat:@" tell application \"System Events\""
		"\n set isRunning to (name of processes) contains \"Terminal\""
		"\n end tell"
		"\n tell application \"Terminal\""
		"\n activate"
		"\n if (isRunning) then"
		"\n do script  \"%@\""
		"\n else"
		"\n do script  \"%@\" in window 1"
		"\n end if"
		"\n end tell",
		(NSString*)command, (NSString*)command];
		
    NSAppleScript * as = [[NSAppleScript alloc] initWithSource: s];
    NSAppleEventDescriptor * desc = [as executeAndReturnError:nil];
    [as release];
    [s release];
    return desc != nil;
}

bool RunCommandInNewTerminal( const char * command )
{
    NSString * cmd = [[NSString alloc] initWithCString:command encoding:[NSString defaultCStringEncoding]];
    
    bool result = RunCommandInNewTerminalWithCFStrRef( (CFStringRef)cmd );
    
    [cmd release];
    
    return result;
}

char * CreateFullPathToApplicationBundle( const char * path )
{
    NSString * bundlePath = [[NSString alloc] initWithCString:path encoding:[NSString defaultCStringEncoding]];
    
    NSBundle * bundle = [NSBundle bundleWithPath:bundlePath];
    
    NSString * executablePath = [bundle executablePath];
    
    if ( !executablePath )
        return NULL;
    
    const char * cString = [executablePath cStringUsingEncoding:[NSString defaultCStringEncoding]];
    int memSize =  strlen(cString) + 1;
    char * returnVal = malloc( memSize );
    
    if ([executablePath getCString:returnVal maxLength:memSize encoding:[NSString defaultCStringEncoding]])
        return returnVal;
    free(returnVal);
    return NULL;
    
}


