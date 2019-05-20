/*
 * Copyright 2018 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# ifndef P4SCRIPT_H
# define P4SCRIPT_H

# include <error.h>

enum SCR_VERSION
{
	P4SCRIPT_LUA_53,
	P4SCRIPT_LUA_LATEST
};

enum SCR_BINDING_LIBNAME
{
	P4SCRIPT_CLIENTAPI
};

# ifdef HAS_CPP17

# include <chrono>
# include <future>
# include <optional>
# include <any>
# include <vector>
# include <functional>

using scriptClock_t   = std::chrono::steady_clock;
using scriptTime_t    = scriptClock_t::duration;
using scriptTimeInc_t = std::chrono::time_point< scriptClock_t >;
using scriptMem_t     = uint32_t;

class p4scriptImpl53;
class ClientApiLua;

class p4script
{
	public:

	    ~p4script();
	     p4script( const SCR_VERSION v, Error *e );

	    void SetMaxTime( const uint32_t max );
	    void SetMaxMem ( const scriptMem_t max );

	    void ConfigBinding( const SCR_BINDING_LIBNAME lib, std::any cfg,
	                        Error* e );

	    // Execute the named file.
	    bool doFile( const char *name, Error *e );
	    // Execute the supplied script code. 
	    bool doStr ( const char *s, Error *e );
	    // Call a script function.
	    std::optional< std::any > doScriptFn( const char* name, Error* e );

	    std::string getElapsedTime() const;

	    const char* getImplName() const;
	    const char* getImplVersion() const;

	    // These are not intended to be public, but is for the
	    // sake of expediency.
	    //
	    // os_execute() is a non-blocking version of the Lua function.
	    static int os_execute( void* Lv );
	    // Callback for use in non-blocking versions of Lua functions.
	    static bool timeBreakCb( void* Lv );

protected:

	    class impl;
	    class impl53;

	    std::unique_ptr< impl > pimpl;

private:

	    // Script memory allocation count (bytes).
	    scriptMem_t curMem{};

	    // Maximum allowed allocation before aborting script execution.
	    scriptMem_t maxMem{};

	    // Has the script used too much?
	    bool checkMem() const;

	    // Time spent executing the script, and the maximum allowed.
	    scriptTime_t curTime{}, maxTime{};

	    scriptTimeInc_t startTime{};

	    // Has the script run too long?
	    bool checkTime();

	    void beginTime();
	    void   addTime();

	    scriptTimeInc_t Now() const;

	    std::string fmtDuration( const scriptTime_t &dur ) const;
	    std::string fmtMem     ( const scriptMem_t  &mem ) const;

	    // Once the scriptCancelMsg is received, we set this so that
	    // we only return failure to the Lua runtime once.  It's possible
	    // to crash the runtime if we return errors multiple times in the
	    // memory allocator.
	    bool scriptCancelled = false;

	    const SCR_VERSION scriptType;

	    std::vector< std::function< void( ClientApiLua& ) > >
	        ClientApiBindCfgs;
} ;

class p4script::impl
{
	public:

	             impl( p4script& p, Error *e );
	    virtual ~impl();

	    virtual bool doFile( const char *name, Error *e );
	    virtual bool doStr ( const char *buf , Error *e );
	    virtual std::optional< std::any > doScriptFn( const char* name,
	                                                  Error* e ) = 0;

	    virtual const char* getImplName() const;
	    virtual const char* getImplVersion() const;

	    virtual int os_execute( void* Lv ) = 0;
	    virtual bool timeBreakCb( void* Lv ) = 0;

	protected:

	    friend class p4script;
	    friend class Extension;
	    p4script& parent;

	    virtual void* getState() = 0;

};

class p4script::impl53 : public p4script::impl
{
	public:

	     impl53( p4script& p, Error *e );
	    ~impl53();

	    bool doStr ( const char *buf , Error *e );
	    std::optional< std::any > doScriptFn( const char* name, Error* e );

	    const char* getImplName() const;
	    const char* getImplVersion() const;

	    int os_execute( void* Lv );
	    bool timeBreakCb( void* Lv );

	protected:

	    void* getState();

	private:

	    void doBindings();

	    static void*
	    allocator( void *ud, void *ptr, size_t osize, size_t nsize );

	    static void debugHook( void *Lv, void *arv );

	    // Break script execution every N instructions to give us a
	    // chance to abort.  This number was pulled out of a bag as
	    // appearing not too long or short (on the assumption that
	    // breaking too often would be inefficient) while allowing
	    // our checks to occur often enough.
	    const uint32_t maxInsStep = 32768;

	    // A separate error that we set to distinguish between Lua
	    // errors we caused (we interrupted the script) and ones we
	    // didn't.
	    Error realError{};

	    // Pointer to the script runtime.
	    void *l{};

	    const char* implName    = "Lua";
	    const char* implVersion = "5.3.4";
};

# else // HAS_CPP17

# include <inttypes.h>

typedef uint32_t scriptMem_t;

class p4script
{
	public:

	    ~p4script();
	     p4script( const SCR_VERSION v, Error *e );

	    void SetMaxTime( const uint32_t max );
	    void SetMaxMem ( const scriptMem_t max );

	    bool doFile( const char *name, Error *e );

};

# endif // HAS_CPP17
# endif // P4SCRIPT_H
