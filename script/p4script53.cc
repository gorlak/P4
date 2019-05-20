/*
 * Copyright 2018 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>
# include <error.h>
# include <msgscript.h>
# include <debug.h>

# include <p4script.h>

# ifdef HAS_CPP17

# include <map>
# include <functional>
# include <fstream>
# include <iostream>

/*
// For printf PRIu32
# define __STDC_FORMAT_MACROS
# include <inttypes.h>
// #include <cinttypes> ?
// printf("thz fn %" PRIu32 "\n", z->parent.maxRam );
*/

# include "p4script53.h"
# include "lua_cjson_redefines.h"

# include "errorlua.h"
# include "clientapi.h"
# include "clientapilua.h"

// We include all of Lua here, compiled as C++ so exceptions work properly,
// for easier symbol redefinition (to prevent namespace clashes), and for
// potential performance improvements since the compiler can see everything
// at once.

# include "lua-5.3/one.cc"

int p4script::impl53::os_execute( void* Lv )
{
	auto lua = cast_sol_State( l );
	lua_State *L = lua->lua_state();
	const char *cmd = luaL_optstring( L, 1, NULL );

	RunArgv args;
	RunCommand rcmd;
	Error e;
	int fds[ 2 ];
	fds[ 0 ] = fds[ 1 ] = -1;
	args.AddCmd( cmd );
	rcmd.RunChild( args, ( RCO_AS_SHELL | RCO_USE_STDOUT ), fds, &e );

	// Polling instead of blocking here like system() means we'll be
	// slower when spawning many short-lived commands.

	while( !rcmd.PollChild( 100 ) )
	{
	    if( parent.checkTime() )
	    {
	        realError.Set( MsgScript::ScriptMaxRunErr )
	            << "time"
	            << parent.fmtDuration( parent.maxTime ).c_str();

	        if( p4debug.GetLevel( DT_SCRIPT ) > 3 )
	            p4debug.printf( "SCRIPT p4/os_execute scriptCancelMsg"
	                            " block\n" );

	        parent.scriptCancelled = true;
	        rcmd.StopChild();
	        // The subprocess can still be hanging around at this point
	        // despite us sending a signal.  We don't want to stall here,
	        // so we just disassociate ourselves with it and continue on.
	        rcmd.SetAbandon();
	        luaL_error( L, "p4/os_execute" );
	        break;
	    }

	    std::this_thread::sleep_for( std::chrono::milliseconds( 50 ) );
	}

	if( e.Test() )
	{
	    StrBuf fmt;
	    e.Fmt( &fmt );
	    fprintf( stderr, "%s", fmt.Text() );
	}

	int status = rcmd.WaitChild();

	if( cmd != NULL )
	    return luaL_execresult( L, e.Test() || status );
	else
	{
	    lua_pushboolean( L, e.Test() || status );
	    return 1;
	}
}

bool p4script::impl53::timeBreakCb( void* Lv )
{
	auto lua = cast_sol_State( l );
	lua_State *L = lua->lua_state();
	void *ud = nullptr;
	lua_getallocf( L, &ud );
	auto z = static_cast< p4script::impl53* >( ud );

	if( parent.checkTime() )
	{
	    realError.Set( MsgScript::ScriptMaxRunErr )
	        << "time"
	        << parent.fmtDuration( parent.maxTime ).c_str();

	    if( p4debug.GetLevel( DT_SCRIPT ) > 3 )
	        p4debug.printf( "SCRIPT p4/timeBreakCb scriptCancelMsg"
	                        " block\n" );
	    parent.scriptCancelled = true;
	    luaL_error( L, "p4/timeBreakCb" );
	    return true;
	}

	return false;
}

void p4script::impl53::debugHook( void *Lv, void *arv )
{
	lua_State* L  = (lua_State*)Lv;
	lua_Debug* ar = (lua_Debug*)arv;

	void *ud = nullptr;
	lua_getallocf( L, &ud );

	auto z = static_cast< p4script::impl53* >( ud );

	if( !z->parent.scriptCancelled && z->parent.checkTime() )
	{
	    z->realError.Set( MsgScript::ScriptMaxRunErr )
	        << "time"
	        << z->parent.fmtDuration( z->parent.maxTime ).c_str();

	    if( p4debug.GetLevel( DT_SCRIPT ) > 3 )
	        p4debug.printf( "SCRIPT p4script::impl53::debugHook "
	                        "scriptCancelMsg block\n" );
	    z->parent.scriptCancelled = true;
	    luaL_error( L, "debugHook" );
	}
}

void* p4script::impl53::allocator( void *ud, void *ptr, size_t osize,
	                                   size_t nsize )
{
	auto z = static_cast< p4script::impl53* >( ud );

	if( !z->parent.scriptCancelled && z->parent.checkTime() )
	{
	    if( p4debug.GetLevel( DT_SCRIPT ) > 3 )
	        p4debug.printf( "SCRIPT p4script::impl53::allocator "
	                        "scriptCancel block\n" );
	    z->parent.scriptCancelled = true;
	    return nullptr;
	}

	z->parent.curMem += nsize - osize;

	if( nsize == 0 ) // a free is always allowed
	{
	    free( ptr );
	    return nullptr;
	}

	if( !z->parent.scriptCancelled && z->parent.checkMem() &&
	    !z->realError.Test() )
	{
	    z->realError.Set( MsgScript::ScriptMaxRunErr )
	        << "memory"
	        << z->parent.fmtMem( z->parent.maxMem ).c_str()
	        << "bytes";

	    z->parent.scriptCancelled = true;

	    if( p4debug.GetLevel( DT_SCRIPT ) > 3 )
	        p4debug.printf( "SCRIPT p4script::impl53::allocator "
	                        "checkMem block\n" );

	    return NULL;
	}

	return realloc( ptr, nsize );
}

const char* p4script::impl53::getImplName() const
{
	return implName;
}

const char* p4script::impl53::getImplVersion() const
{
	return implVersion;
}

p4script::impl53::impl53( p4script& p, Error *e ) : impl( p, e )
{
	if( e->Test() )
	    e->Set( MsgScript::DoNotBlameTheScript );

	parent.beginTime();

	auto lua = new sol::state( nullptr, allocator, this );

	if( !lua )
	{
	    e->Set( MsgScript::ScriptRuntimeError )
	        << "Couldn't create interpreter - Out of memory?";
	    return;
	}
	lua_State *L = lua->lua_state();
	lua_sethook( L, ((void (*)(lua_State*, lua_Debug*))debugHook),
	             LUA_MASKCOUNT, maxInsStep );
	sol::set_default_state( L );

	lua->open_libraries( sol::lib::base, sol::lib::package,
	                     sol::lib::coroutine, sol::lib::string,
	                     sol::lib::os, sol::lib::math, sol::lib::table,
	                    /*no debug*/ sol::lib::bit32, sol::lib::io,
	                    /* no ffi/jit*/ sol::lib::count );
	l = lua;
	doBindings();
}

p4script::impl53::~impl53()
{
	delete cast_sol_State( l );
}

void* p4script::impl53::getState()
{
	return l;
}

bool p4script::impl53::doStr( const char *buf, Error *e )
{
	if( e->Test() )
	{
	    e->Set( MsgScript::DoNotBlameTheScript );
	    return false;
	}

	bool ret = true;
	auto lua = cast_sol_State( l );

	parent.beginTime();

	try
	{
	    lua->safe_script( buf );
	}
	catch( const sol::error& err )
	{
	    if( realError.Test() )
	    {
	         *e = realError;
	         e->Snap();
	         realError.Clear();
	    }
	    else
	        e->Set( MsgScript::ScriptRuntimeError )
	            << getImplName() << err.what();

	    ret = false;
	}

	parent.addTime();

	return ret;
}

std::optional< std::any >
p4script::impl53::doScriptFn( const char* name, Error* e )
{
	if( e->Test() )
	{
	    e->Set( MsgScript::DoNotBlameTheScript );
	    return {};
	}

	auto lua = cast_sol_State( l );

	parent.beginTime();

	try {
	    auto multi = lua->get< sol::protected_function >( name );
	    auto mret = multi();

	    if( !mret.valid() )
	    {
	        sol::error err = mret;

	        if( realError.Test() )
	        {
	             *e = realError;
	             e->Snap();
	             realError.Clear();
	        }
	        else
	            e->Set( MsgScript::ScriptRuntimeError )
	                << getImplName() << err.what();

	        return {};
	    }

	    return std::make_any< sol::object >( mret );
	}
	catch( const sol::error& err )
	{
	    if( realError.Test() )
	    {
	         *e = realError;
	         e->Snap();
	         realError.Clear();
	    }
	    e->Set( MsgScript::ScriptRuntimeError )
	        << getImplName() << err.what();

	    return {};
	}

	parent.addTime();

	return {};
}

class FileSysLua : public FileSys {

	public:

	    sol::table data;

	     FileSysLua( FileSysType type );
	    ~FileSysLua();

	    static std::unique_ptr< FileSysLua > Make( FileSysType type );

	    void Open( FileOpenMode mode, Error *e );
	    void Write( const char *buf, int len, Error *e );
	    int  Read( char *buf, int len, Error *e );
	    int  ReadLine( StrBuf *buf, Error *e );
	    void Close( Error *e );
	    int  Stat();
	    int  StatModTime();
	    void Truncate( Error *e );
	    void Truncate( offL_t offset, Error *e ) ;
	    void Unlink( Error *e = 0 );
	    void Rename( FileSys *target, Error *e );
	    void Chmod( FilePerm perms, Error *e );
	    void ChmodTime( Error *e );

	    std::string fPath() { std::string p( path.Text() ); return p; }

	    std::function< void( FileOpenMode mode, Error *e ) > fOpen, fOpenO;
	    std::function< void( const char *buf, int len, Error *e ) > fWrite, fWriteO;
	    std::function< int( char *buf, int len, Error *e ) > fRead, fReadO;
	    std::function< int( StrBuf *buf, Error *e ) > fReadLine, fReadLineO;
	    std::function< void( Error *e ) > fClose, fCloseO;
	    std::function< int() > fStat, fStatO;
	    std::function< int() > fStatModTime, fStatModTimeO;
	    std::function< void( Error *e ) > fTruncate, fTruncateO;
	    std::function< void( offL_t offset, Error *e ) > fTruncate1, fTruncate1O;
	    std::function< void( Error *e ) > fUnlink, fUnlinkO;
	    std::function< void( FileSys *target, Error *e ) > fRename, fRenameO;
	    std::function< void( FilePerm perms, Error *e ) > fChmod, fChmodO;
	    std::function< void( Error *e ) > fChmodTime, fChmodTimeO;
} ;

FileSysLua::FileSysLua( FileSysType type )
{
	fOpenO = fOpen = [&]( FileOpenMode mode, Error *e )
	    { printf( "In FileSysLua::Open() '%s'\n", Path()->Text() ); };
	fWrite = fWriteO = [&]( const char *buf, int len, Error *e )
	    { printf( "In FileSysLua::Write()\n" ); };
	fRead = fReadO = [&]( char *buf, int len, Error *e )
	    { printf( "In FileSysLua::Read()\n" ); return 0; };
	fReadLine = fReadLineO = [&]( StrBuf *buf, Error *e )
	    { printf( "In FileSysLua::ReadLine()\n" ); return 0; };
	fClose = fCloseO = [&]( Error *e )
	    { printf( "In FileSysLua::Close()\n" ); };
	fStat = fStatO = [&]()
	    { printf( "In FileSysLua::Stat()\n" ); return 0; };
	fStatModTime = fStatModTimeO = [&]()
	    { printf( "In FileSysLua::StatModTime()\n" ); return 0; };
	fTruncate = fTruncateO = [&]( Error *e )
	    { printf( "In FileSysLua::Truncate()\n" );  };
	fTruncate1 = fTruncate1O = [&]( offL_t offset, Error *e )
	    { printf( "In FileSysLua::Truncate1()\n" ); };
	fUnlink = fUnlinkO = [&]( Error *e )
	    { printf( "In FileSysLua::Unlink()\n" ); };
	// todo: filesyslua as the argument type?
	fRename = fRenameO = [&]( FileSys *target, Error *e )
	    { printf( "In FileSysLua::Rename()\n" ); };
	fChmod = fChmodO = [&]( FilePerm perms, Error *e )
	    { printf( "In FileSysLua::Chmod()\n" );  };
	fChmodTime = fChmodTimeO = [&]( Error *e )
	    { printf( "In FileSysLua::ChmodTime()\n" ); };
}

FileSysLua::~FileSysLua()
{

}

std::unique_ptr< FileSysLua > FileSysLua::Make( FileSysType type )
{
	return std::unique_ptr< FileSysLua >( new FileSysLua( type ) );
}

void FileSysLua::Open( FileOpenMode mode, Error *e )
{
	fOpen ? fOpen( mode, (ErrorLua*)e ) : fOpenO( mode, (ErrorLua*)e );
}

void FileSysLua::Write( const char *buf, int len, Error *e )
{
	fWrite ? fWrite ( buf, len, (ErrorLua*)e )
	       : fWriteO( buf, len, (ErrorLua*)e );
}

int FileSysLua::Read( char *buf, int len, Error *e )
{
	return fRead ? fRead ( buf, len, (ErrorLua*)e )
	             : fReadO( buf, len, (ErrorLua*)e );
}

int FileSysLua::ReadLine( StrBuf *buf, Error *e )
{
	return fReadLine ? fReadLine ( buf, (ErrorLua*)e )
	                 : fReadLineO( buf, (ErrorLua*)e );
}

void FileSysLua::Close( Error *e )
{
	fClose ? fClose( (ErrorLua*)e ) : fCloseO( (ErrorLua*)e );
}

int FileSysLua::Stat()
{
	return fStat ? fStat() : fStatO();
}

int FileSysLua::StatModTime()
{
	return fStatModTime ? fStatModTime() : fStatModTimeO();
}

void FileSysLua::Truncate( Error *e )
{
	fTruncate ? fTruncate( (ErrorLua*)e ) : fTruncateO( (ErrorLua*)e );
}

 void FileSysLua::Truncate( offL_t offset, Error *e ) 
{
	fTruncate1 ? fTruncate1 ( offset, (ErrorLua*)e )
	           : fTruncate1O( offset, (ErrorLua*)e );
}

void FileSysLua::Unlink( Error *e )
{
	Error e1;
	Error *e2 = e ? e : &e1;
	fUnlink ? fUnlink( (ErrorLua*)e2 ) : fUnlinkO( (ErrorLua*)e2 );
}

void FileSysLua::Rename( FileSys *target, Error *e )
{
	fRename ? fRename ( (FileSysLua*)target, (ErrorLua*)e )
	        : fRenameO( (FileSysLua*)target, (ErrorLua*)e );
}

void FileSysLua::Chmod( FilePerm perms, Error *e )
{
	fChmod ? fChmod( perms, (ErrorLua*)e ) : fChmodO( perms, (ErrorLua*)e );
}

void FileSysLua::ChmodTime( Error *e )
{
	fChmodTime ? fChmodTime( (ErrorLua*)e ) : fChmodTimeO( (ErrorLua*)e );
}

class ClientUserLua : public ClientUser
{
	public:

	     ClientUserLua();
	    ~ClientUserLua();

	    void InputData( StrBuf *strbuf, Error *e );

	    void OutputText( const char *data, int length );
	    void OutputBinary( const char *data, int length );
	    void OutputInfo( char level, const char *data );
	    void OutputStat( StrDict *dict );
	    void HandleError( Error *err );
	    void OutputError( const char *err );
	    void Message( Error *err );
	    void Edit( FileSys *f1, Error *e );

	    void Prompt( Error *err, StrBuf &rsp, int noEcho, Error *e );
	    void ErrorPause( char *errBuf, Error *e );
	    FileSys *File( FileSysType type );

	    std::function< void( const char* ) >
	        fOutputError, fOutputErrorO;
	    std::function< void( ErrorLua* ) >
	        fHandleError, fHandleErrorO;
	    std::function< void( ErrorLua* ) >
	        fMessage, fMessageO;
	    std::function< std::string( ErrorLua* ) >
	        fInputData, fInputDataO;
	    std::function< void( char level, const char* data ) >
	        fOutputInfo, fOutputInfoO;
	    std::function< void( const char* data, int length) >
	        fOutputText, fOutputTextO;
	    std::function< void( std::string data, int length ) >
	        fOutputBinary, fOutputBinaryO;
	    std::function<
	        void( std::map< std::string, std::string > ) >
	        fOutputStat, fOutputStatO;

	    std::unique_ptr< FileSysLua > ff;
	    sol::function fFile;

	    std::function< std::unique_ptr< FileSysLua >&( FileSysType type ) > fFileO;

	    std::function<
	        void( ErrorLua *err, std::string rsp, int noEcho, ErrorLua *e ) >
	        fPrompt, fPromptO;

};

ClientUserLua::ClientUserLua() : ClientUser()
{
	fOutputError = fOutputErrorO = []( const char * err )
	    { printf( "P4::Lua default OutputError: %s\n", err ); };
	fHandleError = fHandleErrorO = []( ErrorLua *err )
	    { StrBuf buf; ((Error*)err)->Fmt( buf, EF_NEWLINE );
	      printf( "P4::Lua default HandleError: %s\n",buf.Text() );
	    };
	fMessage = fMessageO = []( ErrorLua *err )
	    { StrBuf buf; ((Error*)err)->Fmt( buf, EF_NEWLINE );
	      printf( "P4::Lua default Message: %s\n",buf.Text() );
	    };
	fInputData = fInputDataO = []( ErrorLua *e )
	    { printf( "P4::Lua default InputData" ); return std::string( "blat" ); };
	fOutputInfo = fOutputInfoO = []( char level, const char* data )
	    { printf( "P4::Lua default OutputInfo: %s\n", data ); };
	fOutputText = fOutputTextO = []( const char* data, int length )
	    { printf( "P4::Lua default OutputText: %s\n",data ); };
	fOutputBinary = fOutputBinaryO = []( std::string data, int length )
	    { printf( "P4::Lua default OutputBinary: len %d\n", length ); };
	fOutputStat = fOutputStatO =
	    []( std::map< std::string, std::string > m )
	    {
	        for( auto const& [key, val] : m )
	            // todo: these are already filtered, so we don't need
	            // to do it again.
	            if( key != "func" && key != "specFormatted" &&
	                key != "altArg" )
	                std::cout << "P4::Lua default OutputStat: "
	                          << key << ':' << val << std::endl;
	    };
	fFileO = [&]( FileSysType type ) -> std::unique_ptr< FileSysLua >&
	{
	    printf( "ClientUserLua::fFileO\n" );
	    if( !ff.get() )
	        ff = FileSysLua::Make( type );
	    return ff;
	};
	fPrompt = fPromptO =
	    [&]( ErrorLua *err, std::string rsp, int noEcho, ErrorLua *e )
	    { printf( "ClientUserLua::PromptO fPrompt: %s\n", rsp.c_str() ); };
}

ClientUserLua::~ClientUserLua()
{
}

void ClientUserLua::Message( Error *err )
{
	fMessage ? fMessage( (ErrorLua*)err ) : fMessage( (ErrorLua*)err );
}

void ClientUserLua::InputData( StrBuf *strbuf, Error *e )
{
	std::string buf =
	  fInputData ? fInputData ( (ErrorLua*)e )
	             : fInputDataO( (ErrorLua*)e );
	strbuf->Set( buf.c_str() );
}

void ClientUserLua::Edit( FileSys *f1, Error *e )
{
	printf( "ClientUserLua::Edit\n" );
	ClientUser::Edit( f1, e );
}

void ClientUserLua::Prompt( Error *err, StrBuf &rsp, int noEcho, Error *e )
{
	std::string s( rsp.Text() );
	fPrompt ? fPrompt ( (ErrorLua*)err, s, noEcho, (ErrorLua*)e )
	        : fPromptO( (ErrorLua*)err, s, noEcho, (ErrorLua*)e );
}

void ClientUserLua::ErrorPause( char *errBuf, Error *e )
{
	printf("ClientUserLua::ErrorPause\n");
}

void ClientUserLua::OutputError( const char *err )
{
	fOutputError ? fOutputError( err ) : fOutputErrorO( err );
}

void ClientUserLua::HandleError( Error *err )
{
	fHandleError ? fHandleError ( (ErrorLua*)err )
	             : fHandleErrorO( (ErrorLua*)err );
}

void ClientUserLua::OutputInfo( char level, const char *data )
{
	fOutputInfo ? fOutputInfo( level, data ) : fOutputInfoO( level, data );
}

void ClientUserLua::OutputText( const char *data, int length )
{
	fOutputText ? fOutputText ( data, length )
	            : fOutputTextO( data, length );
}

void ClientUserLua::OutputBinary( const char *data, int length )
{
	fOutputBinary ? fOutputBinary ( std::string( data ), length )
	              : fOutputBinaryO( std::string( data ), length );
}

void ClientUserLua::OutputStat( StrDict *dict )
{
	std::map< std::string, std::string > m;
	StrRef var, val;

	for( int i = 0; dict->GetVar( i, var, val ); i++ )
	    if( strcmp( var.Text(), "func" ) && 
	        strcmp( var.Text(), "specFormatted" ) &&
	        strcmp( var.Text(), "altArg" ) )
	{
	    m[ std::string( var.Text() ) ] =  std::string( val.Text() );
	}

	fOutputStat ? fOutputStat( m ) : fOutputStatO( m );
}

FileSys *ClientUserLua::File( FileSysType type )
{
	std::unique_ptr< FileSysLua >& f( fFile ? fFile ( type )
	                                        : fFileO( type ) );
	return f.release();
}

extern int luaopen_cjson( lua_State *l );
extern int luaopen_lsqlite3( lua_State *L );
extern int luaopen_lcurl( lua_State *L );
extern int luaopen_lcurl_safe( lua_State *L );

# include "libs/lua-curlv3/lua/cURL/impl/curl.lua.c"
# include "libs/lua-curlv3/lua/cURL/safe.lua.c"
# include "libs/lua-curlv3/lua/cURL/utils.lua.c"
# include "libs/lua-curlv3/lua/curl.lua.c"

static int loadInlineLuaModule( lua_State *L )
{
	const StrRef name( luaL_checkstring( L, 1 ) );
	StrBuf filename = "@Internal/";
	filename << name;

	const auto fn = [&]( const char* data )
	{
	    if( luaL_loadbuffer( L, data, strlen( data ),
	                         filename.Text() ) == LUA_OK )
	    {
	        lua_pushstring( L, filename.Text() );
	        return 2;
	    }

	    return luaL_error( L, "module loading error '%s' from"
	                          " file '%s':\n\t%s",
	                           lua_tostring( L, 1 ), filename.Text(),
	                          lua_tostring( L, -1 ) );
	};

	if( name == "cURL" )
	    return fn( curl_str );

	if( name == "cURL.safe" )
	    return fn( curlsafe_str );

	if( name == "cURL.utils" )
	    return fn( curlutils_str );

	if( name == "cURL.impl.cURL" )
	    return fn( curlimpl_str );

	return 1;
}

void p4script::impl53::doBindings()
{
	auto lua = cast_sol_State( l );

	sol::table ns = lua->create_named_table( "Perforce" );

	luaL_requiref( lua->lua_state(), "cjson", luaopen_cjson, 1 );

	// LuaSQLite3 - normally its import for the statically-linked version
	// is 'lsqlite3complete', but that's a bit long so we just call it by
	// the normal name.
	luaL_requiref( lua->lua_state(), "lsqlite3", luaopen_lsqlite3, 1 );

	luaL_requiref( lua->lua_state(), "lcurl", luaopen_lcurl, 1 );
	luaL_requiref( lua->lua_state(), "lcurl.safe", luaopen_lcurl_safe, 1 );

	sol::table searchers = (*lua)[ "package" ][ "searchers" ];
	searchers.add( loadInlineLuaModule );

	ns.new_enum( "ErrorSeverity",
	    "E_EMPTY" , ErrorSeverity::E_EMPTY,
	    "E_INFO"  , ErrorSeverity::E_INFO,
	    "E_WARN"  , ErrorSeverity::E_WARN,
	    "E_FAILED", ErrorSeverity::E_FAILED,
	    "E_FATAL" , ErrorSeverity::E_FATAL
	);

	ns.new_usertype< ErrorLua >( "Error",
	    "Test" , &ErrorLua::Test,
	    "Fmt"  , &ErrorLua::Fmt,
//	    "Test" , &Error::Test,
	    "Clear", &ErrorLua::Clear
//	    "Clear", &Error::Clear
	);

	ns.new_usertype< ClientUserLua >( "ClientUserLua",
	    "OutputError" , &ClientUserLua::fOutputError,
	    "HandleError" , &ClientUserLua::fHandleError,
	    "Message"     , &ClientUserLua::fMessage,
	    "InputData"   , &ClientUserLua::fInputData,
	    "OutputInfo"  , &ClientUserLua::fOutputInfo,
	    "OutputText"  , &ClientUserLua::fOutputText,
	    "OutputBinary", &ClientUserLua::fOutputBinary,
	    "OutputStat"  , &ClientUserLua::fOutputStat,
	    "Prompt"      , &ClientUserLua::fPrompt,
	    "File"        , &ClientUserLua::fFile,
	    sol::base_classes, sol::bases< ClientUser >()
	);

	ns.new_usertype< FileSysLua >( "FileSysLua", 
	    "Open"        , &FileSysLua::fOpen,
	    "Write"       , &FileSysLua::fWrite,
	    "Read"        , &FileSysLua::fRead,
	    "ReadLine"    , &FileSysLua::fReadLine,
	    "Close"       , &FileSysLua::fClose,
	    "Stat"        , &FileSysLua::fStat,
	    "StatModeTime", &FileSysLua::fStatModTime,
	    "Truncate"    , sol::overload( &FileSysLua::fTruncate,
	                                   &FileSysLua::fTruncate1 ),
	    "Unlink"      , &FileSysLua::fUnlink,
	    "Rename"      , &FileSysLua::fRename,
	    "Chmod"       , &FileSysLua::fChmod,
	    "ChmodTime"   , &FileSysLua::fChmodTime,
	    "Path"        , &FileSysLua::fPath,
	    "data"        , &FileSysLua::data,
	    "new"         , sol::factories( &FileSysLua::Make ),
	    sol::base_classes, sol::bases< FileSys >()
	);

	ns.new_usertype< ClientApiLua >( "ClientApiLua",
	   "new", sol::factories( [=]() {
	              auto ca = std::make_unique< ClientApiLua >( lua );
	              for( const auto& fn : parent.ClientApiBindCfgs )
	                  fn( *ca );
	              return ca;
		} ),
	    "Init"       , &ClientApiLua::fInit,
	    "Final"      , &ClientApiLua::fFinal,
	    "Run"        , &ClientApiLua::fRun,
	    "SetClient"  , &ClientApiLua::fSetClient,
	    "SetUser"    , &ClientApiLua::fSetUser,
	    "SetPort"    , &ClientApiLua::fSetPort,
	    "SetVersion" , &ClientApiLua::fSetVersion,
	    "SetProg"    , &ClientApiLua::fSetProg,
	    "SetVar"     , &ClientApiLua::fSetVar,
	    "SetProtocol", &ClientApiLua::SetProtocol,
	    "SetPassword", &ClientApiLua::fSetPassword,
	    "GetPort"    , &ClientApiLua::fGetPort,
	    "GetUser"    , &ClientApiLua::fGetUser,
	    "IsUnicode"  , &ClientApi::IsUnicode,
	    "SetTrans"   , &ClientApi::SetTrans,
	    "Null"       , &ClientApiLua::Null
	);
}

# else

/*

// Diagnostics to see why we ended up here.

#ifdef OS_NT

#define STRING2(x) #x
#define STRING(x) STRING2(x)

#pragma message("_MSC_VER")
#pragma message(STRING(_MSC_VER))
#pragma message("__cplusplus")
#pragma message(STRING(__cplusplus))

#endif // OS_NT

error

*/

# endif // HAS_CPP17
