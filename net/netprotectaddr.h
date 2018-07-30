// -*- mode: C++; tab-width: 8; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/**
 * netprotectaddr.h - Store an IPv4 or IPv6 protects table address and compare it with match strings.
 * Differs from NetIPAddr by:
 * - allows partial addresses (not enough IPv4 octets)
 * - allows prefix of "proxy-" and "*"
 *   NB: The only wildcard handled here is a leading "*" (meaning either proxy or non-proxy);
 *       all other wildcards (and non-leading "*"s) are handled by the pattern-matching text code,
 *       which is currently in MapTable::Match().
 *
 * Copyright 2012 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

class NetProtectAddr
{
public:
	enum ProtAddrType
	{
	    PROT_ADDR_V4,
	    PROT_ADDR_V6,
	    PROT_ADDR_TEXT,		// text, maybe with wildcards
	    PROT_ADDR_ANY		// just plain "*"
	};

	enum ProxyType
	{
	    PROXY_NONE,
	    PROXY_SET,
	    PROXY_OPT
	};

	NetProtectAddr();

	NetProtectAddr(const StrPtr &addr);

	NetProtectAddr(const NetProtectAddr &rhs);

	const NetProtectAddr &
	operator=(const NetProtectAddr &rhs);

	bool
	operator==(const NetProtectAddr &rhs) const;

	bool
	operator!=(const NetProtectAddr &rhs) const;

	~NetProtectAddr();

	void	Parse();

	bool	Match(const NetProtectAddr &rhs) const;

	bool	Match(const StrPtr &addr) const;

	// debugging support
	static const char *ProxyName(ProxyType t);
	static const char *TypeName(ProtAddrType t);
	const char	*ProxyName() const;
	const char	*TypeName() const;
	void		ToString(StrBuf &buf) const;

private:
	ProxyType	m_proxy;	// prefixed by "proxy-"?
	StrBuf		m_addr;		// the text of the host address itself
	int		m_prefixlen;	// network prefix length
	ProtAddrType	m_type;		// IPv4, IPv6, or text (wildcard)
	NetIPAddr	m_nipa;		// binary representation of the host address
};
