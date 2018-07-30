// -*- mode: C++; tab-width: 4; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/*
 * netaddrinfo.cc
 *
 * Copyright 2011 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <error.h>
# include <msgrpc.h>
# include "netaddrinfo.h"
# include "netutils.h"

// ctor
NetAddrInfo::NetAddrInfo(
	const StrPtr &hostname,
	const StrPtr &portname)
: m_serverinfo(NULL),
  m_hostname(hostname),
  m_portname(portname),
  m_status(0)
{
	::memset(&m_hints, 0, sizeof m_hints);
	m_hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
	m_hints.ai_socktype = SOCK_STREAM;
}

// dtor
NetAddrInfo::~NetAddrInfo()
{
	if( m_serverinfo )
	    ::freeaddrinfo(m_serverinfo); // free the linked list
}

// get family
int
NetAddrInfo::GetHintsFamily() const
{
	return m_hints.ai_family;
}

// set family
void
NetAddrInfo::SetHintsFamily(int family)
{
	m_hints.ai_family = family;
}

// get socktype
NetAddrInfo::SockType
NetAddrInfo::GetHintsSockType() const
{
	return m_hints.ai_socktype == SOCK_STREAM ? SockTypeStream : SockTypeDatagram;
}

// set socktype
void
NetAddrInfo::SetHintsSockType(NetAddrInfo::SockType type)
{
	m_hints.ai_socktype = (type == SockTypeStream ? SOCK_STREAM : SOCK_DGRAM);
}

// get hints
int
NetAddrInfo::GetHintsFlags() const
{
	return m_hints.ai_flags;
}

// set hints
void
NetAddrInfo::SetHintsFlags(int flags)
{
	m_hints.ai_flags = flags;
}

// call getaddrinfo
bool
NetAddrInfo::GetInfo(Error *e)
{
	const char *hname = (m_hostname.Length() == 0) ? NULL : m_hostname.Text();
# ifdef OS_AIX
    // job063437: getaddrinfo() on AIX clears ai_socktype and ai_protocol if pname is NULL
  # define GAI_DEFAULT_PORT_VALUE	"0"
# else
  # define GAI_DEFAULT_PORT_VALUE	NULL
# endif
	const char *pname = (m_portname.Length() == 0) ? GAI_DEFAULT_PORT_VALUE : m_portname.Text();


	// calling GetInfo again? free memory allocated by the previous call
	if( m_serverinfo )
	{
	    ::freeaddrinfo( m_serverinfo );
	    m_serverinfo = NULL;
	}

	if( (m_status = ::getaddrinfo(hname, pname, &m_hints, &m_serverinfo)) != 0 )
	{
	    e->Set( MsgRpc::NameResolve ) << gai_strerror( m_status );
	    return false;
	}

	// the m_serverinfo MUST live for the lifetime of this object

	return true;
}

