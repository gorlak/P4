// -*- mode: C++; tab-width: 8; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/**
 * netipaddr.h - Parse an IPv4 or IPv6 address and compare it (honoring CIDR).
 * - supports a prefix length
 * Differs from NetProtectAddr by:
 * - allows only full addresses (no partial addresses)
 * - does not allow any prefix or wildcards
 *
 * Copyright 2012 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

class NetIPAddr
{
public:
	enum IPAddrType
	{
	    IPADDR_V4,
	    IPADDR_V6,
	    IPADDR_INVALID
	};

	enum CIDR_LIMITS
	{
	    CIDR_UNSPEC = -1,
	    CIDR_MIN = 0,
	    CIDR_MAX_V4 = 32,
	    CIDR_MAX_V6 = 128
	};

	/*
	 * I am not using struct sockaddr_storage here because it would require
	 * all users of this header to include "net/netport.h", which is too
	 * much baggage.  We must reserve room at least for a short word (16 bits)
	 * of address family, possibly a pad short for alignment (16 bits)
	 * and 4 ints (32 bits each) for IPv6, for a minimum of 5 ints.
	 *
	 * Linux declares the struct as a short family, possible a short for
	 * alignment, and pads to a total of 128 bytes for the address itself.
	 *
	 * We'll be conservative and reserve 128 bytes just like linux does
	 * (declared as uint32_t to get sufficient alignment).
	 *
	 * We always access the contents via socket casts, and never through
	 * the members of the structure, so we don't need to worry about
	 * any other alignment details.
	 */
	static const int IPADDR_STORAGE_WORDS = 32;
	typedef unsigned int uint32_t;
	struct ipaddr_storage
	{
	    uint32_t	word[IPADDR_STORAGE_WORDS];
	};

	static bool
	IPAddrStorageEquals(const ipaddr_storage &lhs, const ipaddr_storage &rhs);

	NetIPAddr();
	NetIPAddr(const StrPtr &addr, int prefixlen);
	NetIPAddr(const NetIPAddr &rhs);
	~NetIPAddr();

	const NetIPAddr &
	operator=(const NetIPAddr &rhs);

	bool
	operator==(const NetIPAddr &rhs) const;

	bool
	operator!=(const NetIPAddr &rhs) const;

	const NetIPAddr
	MapV4toV6() const;

	void	Set(const StrPtr &addr, int prefixlen);
	void	Parse();
	bool	Match(const NetIPAddr &addr) const;
	bool	Match(const StrPtr &addr, int prefixlen) const;

	bool	IsTypeV4() const { return m_type == IPADDR_V4; }
	bool	IsTypeV6() const { return m_type == IPADDR_V6; }
	bool	IsTypeValid() const { return m_type == IPADDR_V4 || m_type == IPADDR_V6; }

	// debugging support
	static const char *TypeName(IPAddrType t);
	const char	  *TypeName() const;
	void		  ToString(StrBuf &buf) const;
	const StrPtr	  &ZoneID() const { return m_zoneid; }

private:
	StrBuf		m_text;		// textual representation
	StrBuf		m_zoneid;	// if present (eg, "%eth0")
	int		m_prefixlen;	// network prefix length
	IPAddrType	m_type;		// IPv4, IPv6, or invalid
	ipaddr_storage	m_addr;		// meaningful only when IsTypeValid(); parsed representation
};
