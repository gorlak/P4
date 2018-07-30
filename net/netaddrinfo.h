// -*- mode: C++; tab-width: 4; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/*
 * netaddrinfo.h - network address encoding and decoding
 *
 * Copyright 2011 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 *
 * Classes Defined:
 *
 *	NetAddrInfo - Transform a network address string into a format suitable
 *	           for accept/connect
 */

# include "netportipv6.h"
# include "netport.h"

// encapsulate a struct addrinfo and its operations
class NetAddrInfo
{
public:
	enum SockType
	{
	    SockTypeStream,
	    SockTypeDatagram
	};

	NetAddrInfo(
	    const StrPtr &hostname,
	    const StrPtr &portname);

	~NetAddrInfo();

	int
	GetHintsFamily() const;

	void
	SetHintsFamily(int family);

	int
	GetHintsFlags() const;

	void
	SetHintsFlags(int flags);

	SockType
	GetHintsSockType() const;

	void
	SetHintsSockType(SockType type);

	bool
	GetInfo(Error *e);

	int
	GetStatus()
	{
	    return m_status;
	}

	const StrPtr
	Host()
	{
	    return m_hostname;
	}

	const StrPtr
	Port()
	{
	    return m_portname;
	}

	// fake iterator-like methods
	const addrinfo *
	begin() const
	{
	    return m_serverinfo;
	}

	const addrinfo *
	end() const
	{
	    return NULL;
	}

private:
	addrinfo	*m_serverinfo;
	addrinfo	m_hints;
	const StrPtr	m_hostname;
	const StrPtr	m_portname;
	int		m_status;
};
