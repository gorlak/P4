// -*- mode: C++; tab-width: 8; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/**
 * netprotectaddr.h - Store an IPv4 or IPv6 protects table address and compare it with match strings.
 *
 * Copyright 2012 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

#include <stdhdrs.h>
#include <strbuf.h>
#include "netport.h"
#include "netportipv6.h"
#include "netipaddr.h"
#include "netprotectaddr.h"

// uncomment to enable address parse/match debugging
//#define NPA_DEBUG

#ifdef NPA_DEBUG
  #include "debug.h"
#endif

/*
 * Orthodox Canonical Form (OCF) methods
 */


/**
 * default ctor
 */
NetProtectAddr::NetProtectAddr()
: m_proxy(PROXY_NONE)
, m_addr()
, m_prefixlen(NetIPAddr::CIDR_UNSPEC)
, m_type(NetProtectAddr::PROT_ADDR_TEXT)
{
} // default ctor

NetProtectAddr::NetProtectAddr(
	const StrPtr &addr)
: m_proxy(PROXY_NONE)
, m_addr(addr)
, m_prefixlen(NetIPAddr::CIDR_UNSPEC)
, m_type(NetProtectAddr::PROT_ADDR_TEXT)
{
	Parse();
}

/**
 * copy ctor
 */
NetProtectAddr::NetProtectAddr(
	const NetProtectAddr	&rhs)
: m_proxy(rhs.m_proxy)
, m_addr(rhs.m_addr)
, m_prefixlen(rhs.m_prefixlen)
, m_type(rhs.m_type)
, m_nipa(rhs.m_nipa)
{
} // copy ctor

/**
 * dtor
 */
NetProtectAddr::~NetProtectAddr()
{
} // dtor

/**
 * assignment op
 */
const NetProtectAddr	&
NetProtectAddr::operator=(
	const NetProtectAddr	&rhs)
{
	if( this != &rhs ) {
	    m_proxy = rhs.m_proxy;
	    m_addr = rhs.m_addr;
	    m_prefixlen = rhs.m_prefixlen;
	    m_type = rhs.m_type;
	    m_nipa = rhs.m_nipa;
	}

	return *this;
} // op=

/**
 * op==
 */
bool
NetProtectAddr::operator==(
	const NetProtectAddr	&rhs) const
{
	if( this == &rhs ) {
	        return true;
	}

	if( m_proxy != rhs.m_proxy
	    || m_addr != rhs.m_addr
	    || m_prefixlen != rhs.m_prefixlen
	    || m_type != rhs.m_type
	    || m_nipa != rhs.m_nipa )
	{
	    return false;
	}

	return true;
} // op==

/**
 * op!=
 */
bool
NetProtectAddr::operator!=(
	const NetProtectAddr	&rhs) const
{
	return !(*this == rhs);
} // op!=


/*
 * Other methods
 */


/**
 * Parse a string into its components:
 * regex:
 *    [proxy-]Address[/[pfxlen]]
 * BNF:
 *    ProtectEntry    ::= OptProxyPrefix Address OptPrefixLen ;
 *    OptProxyPrefix  ::= 'proxy-'
 *                    |
 *                    ;
 *    Address         ::= IPv4Address
 *                    | IPv6Address 
 *                    | WildAddress
 *                    ;
 *    IPv4Address     ::= [0-9]{1,3}.[0-9]{1,3}.[0-9]{0,3}.[0-9]{0,3} ;
 *    IPv6Address     ::= // I won't describe IPv6 in a single regex! 8 fields of 16 bits: [0-9a-fA-F]{0,4} ;
 *    WildAddress     := * ;    // any text string; '*' is special
 *    OptPrefixLen    ::= '/' number
 *                    | '/'
 *                    |
 *                    ;
 */
void
NetProtectAddr::Parse()
{
	const char *cp = m_addr.Text();
	StrBuf tmpbuf; // used to avoid overlapping src/dst in StrBuf::Set() calls

	// check for a proxy prefix
	if( !StrRef("proxy-").XCompareN(m_addr) )
	{
	    m_proxy = PROXY_SET;
	    cp += 6;	// skip the proxy stuff
	}
	else if( *cp == '*' )
	{
	    m_proxy = PROXY_OPT;
	    cp++;	// skip the optional proxy flag
	}
	else
	{
	    m_proxy = PROXY_NONE;
	}

	// check for a netmask (network prefix len in "slash" notation)
	if( const char *p = strchr(cp, '/') )
	{
	    tmpbuf.Set( cp, p - cp );
	    m_addr.Set( tmpbuf.Text() );
	    m_prefixlen = StrPtr::Atoi( p + 1 );

	    // pin cidr values to the allowed range boundaries
	    if( m_prefixlen < NetIPAddr::CIDR_MIN )
	        m_prefixlen = NetIPAddr::CIDR_MIN;
	    else if( m_prefixlen > NetIPAddr::CIDR_MAX_V6 )
	        m_prefixlen = NetIPAddr::CIDR_MAX_V6;
	}
	else
	{
	    m_prefixlen = NetIPAddr::CIDR_UNSPEC;
	    tmpbuf.Set( cp );
	    m_addr.Set( tmpbuf.Text() );
	}

	m_nipa.Set(m_addr, m_prefixlen);
	if( m_nipa.IsTypeV4() )
	{
	    m_type = PROT_ADDR_V4;
	    if( m_prefixlen > NetIPAddr::CIDR_MAX_V4 )
	        m_prefixlen = NetIPAddr::CIDR_MAX_V4;
	}
	else if( m_nipa.IsTypeV6() )
	{
	    m_type = PROT_ADDR_V6;
	    if( m_prefixlen > NetIPAddr::CIDR_MAX_V6 )
	        m_prefixlen = NetIPAddr::CIDR_MAX_V6;
	}
	else
	{
	    // optimize common case
	    if( m_addr == "*" )
	        m_type = PROT_ADDR_ANY;
	    else
	        m_type = PROT_ADDR_TEXT;
	    m_prefixlen = NetIPAddr::CIDR_UNSPEC;
	}
}


bool
NetProtectAddr::Match( const NetProtectAddr &rhs ) const
{
#ifdef NPA_DEBUG
	StrBuf	buf;
	StrBuf	rhsbuf;

	ToString(buf);
	rhs.ToString(rhsbuf);
	p4debug.printf( "  NetProtectAddr::Match(%s, %s)\n", buf.Text(), rhsbuf.Text() );
#endif

	if( !m_nipa.IsTypeValid() )
	    return false;

	switch( rhs.m_proxy )
	{
	case PROXY_NONE:
	    if( m_proxy == PROXY_SET )
	        return false;
	    break;
	case PROXY_SET:
	    if( m_proxy == PROXY_NONE )
	        return false;
	    break;
	case PROXY_OPT:
	    // fall through
	    break;
	}

	switch( rhs.m_type )
	{
	case PROT_ADDR_ANY:
	    // short-circuit most common case
	    return true;
	case PROT_ADDR_V4:
	case PROT_ADDR_V6:
	    return m_nipa.Match(rhs.m_nipa);
	case PROT_ADDR_TEXT:
	    return false;	// caller must handle [opt wildcard] text, eg, by calling MatchTable::Match()
	}

	return false;
}

/**
 * Match
 * Common usage (eg, from dmprotects.cc):
 * NetProtectAddr npa( myhostaddress );
 * while (entry = get next protect table entry)
 * {
 *     if( npa.Match(entry.host) )
 *     {
 *         ...
 *     }
 * }
 */
bool
NetProtectAddr::Match( const StrPtr &cidr ) const
{
#ifdef NPA_DEBUG
	StrBuf buf;

	ToString(buf);
	p4debug.printf( "  NetProtectAddr::Match(\"%s\") against %s\n", buf.Text(), cidr.Text() );
#endif

	const NetProtectAddr npa( cidr );

	return Match(npa);
}

/*
 * Debugging -- generate a textual representation of the address type
 * [static]
 */
const char *
NetProtectAddr::TypeName(ProtAddrType t)
{
	switch( t )
	{
	case PROT_ADDR_V4:	return "v4";
	case PROT_ADDR_V6:	return "v6";
	case PROT_ADDR_TEXT:	return "txt";
	case PROT_ADDR_ANY:	return "*";
	}

	// quiet warning c4715: not all control paths return a value
	return "<unknown>";
}

/*
 * Debugging -- generate a textual representation of the proxy type
 * [static]
 */
const char *
NetProtectAddr::ProxyName(ProxyType t)
{
	switch( t )
	{
	case PROXY_NONE:	return "";
	case PROXY_SET:		return "proxy-";
	case PROXY_OPT:		return "*";
	}

	// quiet warning c4715: not all control paths return a value
	return "<unknown>";
}

/*
 * Debugging -- generate a textual representation of the address type
 */
const char *
NetProtectAddr::TypeName() const
{
	return TypeName(m_type);
}

/*
 * Debugging -- generate a textual representation of the proxy type
 */
const char *
NetProtectAddr::ProxyName() const
{
	return ProxyName(m_proxy);
}

/*
 * Debugging -- generate a textual representation of this object
 */
void
NetProtectAddr::ToString(StrBuf &buf) const
{
	char numbuf[64];
	const char *num = StrBuf::Itoa(m_prefixlen, &numbuf[sizeof(numbuf)-1]);
	StrBuf	nipabuf;
	m_nipa.ToString(nipabuf);

	buf.Set( "{" );
	buf.Append( ProxyName() );
	buf.Append( nipabuf.Text() );
	buf.Append( "/" );
	buf.Append( num );
	buf.Append( "%" );
	buf.Append( TypeName() );
	buf.Append( "}" );
}
