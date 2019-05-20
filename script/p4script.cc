/*
 * Copyright 2018 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

#include <iomanip>
#include <sstream>

// For doFile()
#include <stdhdrs.h>
#include <error.h>
#include <strbuf.h>
#include <filesys.h>

#include <p4script.h>
#include <msgscript.h>
#include <msgdm.h>
#include <debug.h>

# ifdef HAS_CPP17

p4script::impl::impl( p4script& p, Error *e )
: parent( p )
{
}

p4script::impl::~impl()
{
}

bool p4script::impl::doFile( const char *name, Error *e )
{
	return false;
}

bool p4script::impl::doStr( const char *buf, Error *e )
{
	return false;
}

const char* p4script::impl::getImplName() const
{
	return "no scripting engine";
}

const char* p4script::impl::getImplVersion() const
{
	return "no scripting engine version";
}

int p4script::os_execute( void* Lv )
{
	switch( ((p4script::impl*) Lv)->parent.scriptType )
	{
	    case P4SCRIPT_LUA_53:
	        return ((p4script::impl53*)Lv)->os_execute( Lv );
	        break;
	    default:
	        p4debug.printf( "p4script::os_execute() bad case!\n" );
	        return 1;
	}
}

bool p4script::timeBreakCb( void* Lv )
{
	switch( ((p4script::impl*) Lv)->parent.scriptType )
	{
	    case P4SCRIPT_LUA_53:
	        return ((p4script::impl53*)Lv)->timeBreakCb( Lv );
	        break;
	    default:
	        p4debug.printf( "p4script::timeBreakCb() bad case!\n" );
	        return 1;
	}
}

p4script::~p4script() {}

p4script::p4script( const SCR_VERSION v, Error *e ) : scriptType( v )
{
	switch( v )
	{
	    case P4SCRIPT_LUA_53:
	        pimpl = std::make_unique< p4script::impl53 >( *this, e );
	        break;
	    default:
	        StrBuf msg = "p4script::p4script() bad case!";
	        e->Set( MsgDm::DevErr ) << msg;
	        return;
	}
}

void p4script::SetMaxTime( const uint32_t max )
{
	maxTime = (std::chrono::seconds)max;
}

void p4script::SetMaxMem( const scriptMem_t max )
{
	maxMem = max;
}

void p4script::ConfigBinding( const SCR_BINDING_LIBNAME lib, std::any cfg,
	                      Error* e )
{
	try
	{
	switch( lib )
	{
	    case P4SCRIPT_CLIENTAPI:
	        ClientApiBindCfgs.push_back(
	            std::any_cast< std::function< void( ClientApiLua& ) >
	                         >( cfg ) );
	        break;
	    default:
	        StrBuf msg = "p4script::ConfigBinding() bad case!";
	        e->Set( MsgDm::DevErr ) << msg;
	        return;
	}
	}
	catch( const std::bad_any_cast& err )
	{
	   StrBuf msg = "p4script::ConfigBinding() error! ";
	   msg << err.what();
	   e->Set( MsgDm::DevErr ) << msg;
	   return;
	}
}

bool p4script::checkMem() const
{
	return maxMem ? curMem >= maxMem : false;
}

bool p4script::checkTime()
{
	addTime();

	return maxTime.count() ? curTime >= maxTime : false;
}

void p4script::beginTime()
{
	startTime = Now();
}

void p4script::addTime()
{
	curTime += scriptTime_t( Now() - startTime );
	beginTime();
}

scriptTimeInc_t p4script::Now() const
{
	return scriptClock_t::now();
}

bool p4script::doFile( const char *name, Error *e )
{
	if( e->Test() )
	{
	    e->Set( MsgScript::DoNotBlameTheScript );
	    return false;
	}

	StrBuf results;
	auto scr = FileSys::CreateUPtr( FST_BINARY );
	(*scr)->Set( name );
	(*scr)->Open( FOM_READ, e );

	if( e->Test() )
	    return false;

	(*scr)->ReadWhole( &results, e );

	if( e->Test() )
	    return false;

	return doStr( results.Text(), e );

}

bool p4script::doStr( const char *buf, Error *e )
{
	if( e->Test() )
	{
	    e->Set( MsgScript::DoNotBlameTheScript );
	    return false;
	}

	return pimpl->doStr( buf, e );
}

std::optional< std::any > p4script::doScriptFn( const char* name, Error* e )
{
	if( e->Test() )
	{
	    e->Set( MsgScript::DoNotBlameTheScript );
	    return {};
	}

	return pimpl->doScriptFn( name, e );
}

std::string p4script::fmtDuration( const scriptTime_t &dur ) const
{
	std::stringstream buf;

	auto millis = std::chrono::duration_cast
	              < std::chrono::milliseconds >( dur ).count();

	int hours = ( millis / ( 1000 * 60 * 60 ) );
	int mins  = ( millis / ( 1000 * 60 ) ) % 60;
	int secs  = ( millis / 1000) % 60;

	buf << std::setfill( '0' ) << std::setw( 2 ) << hours << ":";
	buf << std::setfill( '0' ) << std::setw( 2 ) << mins  << ":";
	buf << std::setfill( '0' ) << std::setw( 2 ) << secs        ;

	return buf.str();
}

std::string p4script::fmtMem( const scriptMem_t &mem ) const
{
	std::stringstream buf;
	buf << mem;
	return buf.str();
}

std::string p4script::getElapsedTime() const
{
	return fmtDuration( curTime );
}

const char* p4script::getImplName() const
{
	return pimpl->getImplName();
}

const char* p4script::getImplVersion() const
{
	return pimpl->getImplVersion();
}

# else // HAS_CPP17

# include <stdio.h>

p4script::p4script( const SCR_VERSION v, Error *e )
{
	fprintf( stderr, "Warning: scripting support is not "
	                 "compiled into this program.\n" );
}

p4script::~p4script() {}

bool p4script::doFile( const char *name, Error *e )
{
	return false;
}

void p4script::SetMaxTime( const uint32_t max )
{
}

void p4script::SetMaxMem( const scriptMem_t max )
{
}

# endif
