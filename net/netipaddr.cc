// -*- mode: C++; tab-width: 8; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/**
 * netipaddr.cc - Parse an IPv4 or IPv6 address and compare it (honoring CIDR).
 *
 * Copyright 2012 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */
#include <stdhdrs.h>
#include <strbuf.h>
#include "netportipv6.h"
#include "netport.h"
#include "netutils.h"
#include "netipaddr.h"

// we know that an IPv6 address is 128 bits (16 bytes)
#define IPV6_ADDR_LEN	16

// uncomment to enable address parse/match debugging
//#define NIPA_DEBUG

#ifdef NIPA_DEBUG
  #include "debug.h"
#endif // NIPA_DEBUG

/*
 * Orthodox Canonical Form (OCF) methods
 */


// default ctor
NetIPAddr::NetIPAddr()
: m_text()
, m_prefixlen(CIDR_UNSPEC)
, m_type(IPADDR_INVALID)
{
}

// normal ctor
NetIPAddr::NetIPAddr(const StrPtr &addr, int prefixlen)
: m_text(addr)
, m_prefixlen(prefixlen)
, m_type(IPADDR_INVALID)
{
	Parse();
}

// copy ctor
NetIPAddr::NetIPAddr(const NetIPAddr &rhs)
: m_text(rhs.m_text)
, m_prefixlen(rhs.m_prefixlen)
, m_type(rhs.m_type)
, m_addr(rhs.m_addr)
{
}

// dtor
NetIPAddr::~NetIPAddr()
{
}

// assignment op
const NetIPAddr	&
NetIPAddr::operator=(
	const NetIPAddr	&rhs)
{
	if( this != &rhs ) {
	    m_text = rhs.m_text;
	    m_prefixlen = rhs.m_prefixlen;
	    m_type = rhs.m_type;
	    m_addr = rhs.m_addr;
	}

	return *this;
} // op=

// op==
bool
NetIPAddr::operator==(
	const NetIPAddr	&rhs) const
{
	if( this == &rhs ) {
	    return true;
	}

	if( m_text != rhs.m_text
	    || (m_prefixlen != rhs.m_prefixlen)
	    || m_type != rhs.m_type )
	{
	    return false;
	}

	// m_addr is meaningful only if we're IPv4 or IPv6
	if( IsTypeValid() && !IPAddrStorageEquals(m_addr, rhs.m_addr) )
	    return false;

	return true;
} // op==

// op!=
bool
NetIPAddr::operator!=(
	const NetIPAddr	&rhs) const
{
	return !(*this == rhs);
} // op!=


/*
 * Other methods
 */

void
NetIPAddr::Parse()
{
	const char *cp = m_text.Text();

	m_type = IPADDR_INVALID;

	// try IPv4 first (most common), then IPv6
	if( NetUtils::IsIpV4Address(cp, NetUtils::IPADDR_PREFIX_ALLOW) )
	{
	    // inet_aton will handle partial IPv4 addresses
	    struct in_addr	addr;
	    if( inet_aton(cp, &addr) )
	    {
	        struct sockaddr_in *sin = reinterpret_cast<struct sockaddr_in *>(&m_addr);
	        sin->sin_family = AF_INET;
	        sin->sin_port = 0;
	        sin->sin_addr = addr;
	        m_type = IPADDR_V4;
	    }
	}
	else if( NetUtils::IsIpV6Address(cp, NetUtils::IPADDR_PREFIX_PROHIBIT) )
	{
	    StrBuf	txt;
	    const char	*bp = cp;
	    const char	*ep = &cp[m_text.Length()-1];

	    // ignore surrounding brackets
	    if( (*bp == '[') && (ep > bp) && (*ep == ']') )
	    {
	        bp++;
	        ep--;
	    }

	    // ignore any trailing %zoneid
	    for( const char *p = ep; p > bp; p-- )
	    {
	        if( *p == '%' )
	        {
		    m_zoneid.Set( p, ep-p+1 );	// but remember it
	            ep = p - 1;	// and ignore it for inet_pton()
	            break;
	        }
	    }

	    txt.Set( bp, ep-bp+1 );
	    cp = txt.Text();

	    struct sockaddr_in6 *sin6 = reinterpret_cast<struct sockaddr_in6 *>(&m_addr);
	    if( inet_pton(AF_INET6, cp, &sin6->sin6_addr) == 1 )
	    {
	        sin6->sin6_family = AF_INET6;
	        sin6->sin6_port = 0;
	        m_type = IPADDR_V6;
	    }
	}
}

void
NetIPAddr::Set(const StrPtr &addr, int prefixlen)
{
    m_text = addr;
    m_prefixlen = prefixlen;
    Parse();
}

/*
 * Return this IPv4 address mapped to its IPv6 equivalent.
 * Just return ourselves if we're not IPv4.
 *
 * We can't convert anything but valid IPADDR_V4:
 *   IPADDR_V6 conversion is a no-op
 *   IPADDR_V4 maps into IPv6 (eg, prepend ::FFFF:)
 *   IPADDR_INVALID (eg, text) returns itself
 * Our caller must check that conversion succeeded.
 *
 * Mapping:
 *    80 bits of 0 (10 bytes of 0x00)
 *    16 bits of 1 (2 bytes of 0xFF)
 *    32 bits of IPv4 address (4 bytes)
 */
const NetIPAddr
NetIPAddr::MapV4toV6() const
{
	// We convert only valid IPv4 addresses
	if( m_type != IPADDR_V4 )
	    return *this;

	NetIPAddr	v6( *this );

	v6.m_text.Set("::FFFF:");
	v6.m_text.Append(m_text.Text());
	v6.m_prefixlen = (m_prefixlen == CIDR_UNSPEC ? m_prefixlen : m_prefixlen + 96);

	// it's a little easier just to return v6.Parse(), but it's a little faster this way
	const sockaddr	*v4_saddr = reinterpret_cast<const sockaddr *>(&m_addr);
	const sockaddr	*v6_saddr = reinterpret_cast<const sockaddr *>(&v6.m_addr);

	const unsigned char *cv4_addr = static_cast<const unsigned char *>(NetUtils::GetInAddr(v4_saddr));
	const unsigned char *cv6_addr = static_cast<const unsigned char *>(NetUtils::GetInAddr(v6_saddr));

	unsigned char *v4_addr = const_cast<unsigned char *>(cv4_addr);
	unsigned char *v6_addr = const_cast<unsigned char *>(cv6_addr);

	int i;

	// left-pad 80 bits with 0
	for( i = 0; i < 10; i++ )
	{
	    v6_addr[i] = 0;
	}

	// then pad 16 bits with 1
	for( ; i < 12; i++ )
	{
	    v6_addr[i] = 0xFF;
	}

	// append the IPv4 address
	for( ; i < 16; i++ )
	{
	    v6_addr[i] = v4_addr[i-12];
	}

	v6.m_type = IPADDR_V6;

	return v6;

}

/*
 * Construct a netmask corresponding to the given prefix length.
 * Set the leading prefixlen bits and clear the rest
 * Assume (correctly) that IPv6 addresses are stored as an array of 16 bytes.
 */
void
Netmask6FromPrefixLen(struct in6_addr *mask, unsigned int prefixlen)
{
	unsigned char	*maskp = mask->s6_addr;

	if( prefixlen > NetIPAddr::CIDR_MAX_V6 )
	    prefixlen = NetIPAddr::CIDR_MAX_V6;

	memset( maskp, 0, IPV6_ADDR_LEN );
	for( int i = prefixlen, j = 0; i > 0; i -= 8, ++j )
	{
	    maskp[j] = ((i >= 8) ? 0xFF : (0xFF << (8-i)) & 0xFF);
	}
}

/*
 * Compare two IPv6 socket addresses, masking by the prefix.
 * That is, compare that their network bits are equal.
 * Assume (correctly) that IPv6 addresses are stored as an array of 16 bytes.
 */
bool
NetEqualsV6(
	const struct in6_addr *a,
	const struct in6_addr *b,
	int prefixlen)
{
	// huh?
	if( !a || !b )
	    return false;

	struct in6_addr	mask;

	Netmask6FromPrefixLen( &mask, (prefixlen == NetIPAddr::CIDR_UNSPEC ? NetIPAddr::CIDR_MAX_V6 : prefixlen) );

#ifdef NIPA_DEBUG
	char aaddr[36];
	char baddr[36];
	char maddr[36];
	for( int i = 0; i < 16; i++ )
	    sprintf(&aaddr[2*i], "%02X", a->s6_addr[i]);
	for( int i = 0; i < 16; i++ )
	    sprintf(&baddr[2*i], "%02X", b->s6_addr[i]);
	for( int i = 0; i < 16; i++ )
	    sprintf(&maddr[2*i], "%02X", mask.s6_addr[i]);
	p4debug.printf( "%d: %s\n", __LINE__, aaddr );
	p4debug.printf( "%d: %s\n", __LINE__, baddr );
	p4debug.printf( "%d: %s\n", __LINE__, maddr );
#endif

	for( int i = 0; i < IPV6_ADDR_LEN; i++ )
	{
	    unsigned int mbyte = mask.s6_addr[i] & 0xFF;
	    unsigned int abyte = a->s6_addr[i] & mbyte;
	    unsigned int bbyte = b->s6_addr[i] & mbyte;

	    if( abyte != bbyte )
	        return false;
	}

	return true;
}

bool
NetIPAddr::Match(const NetIPAddr &target) const
{
#ifdef NIPA_DEBUG
	StrBuf mybuf;
	StrBuf tgtbuf;

	ToString(mybuf);
	target.ToString(tgtbuf);
	p4debug.printf("  NetIPAddr::Match(%s, %s)\n", mybuf.Text(), tgtbuf.Text());
#endif

	if( !IsTypeValid() || !target.IsTypeValid() )
	    return false;

	int netmaskbits = target.m_prefixlen;

	switch( m_type )
	{
	case IPADDR_V4:
	    if( target.IsTypeV6() )
	    {
	        NetIPAddr v6( MapV4toV6() );

	        // return false if for some reason we couldn't convert to IPv6
	        return v6.IsTypeV6() ? v6.Match( target ) : false;
	    }

	    // do the first n bits match, where n == 0?  yes
	    if( netmaskbits == CIDR_MIN )
	        return true;

	    // if no mask specified, they must all match
	    if( netmaskbits == CIDR_UNSPEC )
	        netmaskbits = CIDR_MAX_V4;

	    {
	        const sockaddr	*our_saddr = reinterpret_cast<const sockaddr *>(&m_addr);
	        const sockaddr	*tgt_saddr = reinterpret_cast<const sockaddr *>(&target.m_addr);

	        /*
	         * NB: inet_pton() etc always store addresses in network byte order,
	         * for both IPv4 and IPv6.  This is different than, eg, inet_addr(),
	         * which returns a 32-bit address in host byte order.
	         */

	        if( netmaskbits == CIDR_MAX_V4 )
	        {
	            const void	*our_addrp = NetUtils::GetInAddr(our_saddr);
	            const void	*tgt_addrp = NetUtils::GetInAddr(tgt_saddr);

	            if( !our_addrp || !tgt_addrp )
	                return false;

	            in_addr_t	our_addr = *static_cast<const in_addr_t *>(our_addrp);
	            in_addr_t	tgt_addr = *static_cast<const in_addr_t *>(tgt_addrp);

	            // all bits are network bits (!) so all must match
	            return IN_ADDR_VAL(our_addr) == IN_ADDR_VAL(tgt_addr);
	        }
	        else
	        {
	            const void	*our_addrp = NetUtils::GetInAddr(our_saddr);
	            const void	*tgt_addrp = NetUtils::GetInAddr(tgt_saddr);

	            // huh?
	            if( !our_addrp || !tgt_addrp )
	                return false;

	            in_addr_t	our_addr = *static_cast<const in_addr_t *>(our_addrp);
	            in_addr_t	tgt_addr = *static_cast<const in_addr_t *>(tgt_addrp);

	            int netmask = ( 1 << (32 - netmaskbits) ) - 1;
	            netmask = ~netmask;

	            return (ntohl(IN_ADDR_VAL(our_addr)) & netmask) == (ntohl(IN_ADDR_VAL(tgt_addr)) & netmask);
	        }
	    }
	    break;
	case IPADDR_V6:
	    if( !target.IsTypeV6() )
	    {
	        if( target.m_type == IPADDR_V4 )
	        {
	            NetIPAddr	tgt6 = target.MapV4toV6();

	            // return false if for some reason we couldn't convert to IPv6
	            return tgt6.IsTypeV6() ? Match( tgt6 ) : false;
	        }
	        else
	        {
	            return false;
	        }
	    }

	    // do the first n bits match, where n == 0?  yes
	    if( netmaskbits == CIDR_MIN )
	        return true;

	    // we know we're IPv6, so we know the actual type that GetInAddr will return
	    {
	        const sockaddr	*our_saddr = reinterpret_cast<const sockaddr *>(&m_addr);
	        const sockaddr	*tgt_saddr = reinterpret_cast<const sockaddr *>(&target.m_addr);

	        return NetEqualsV6(static_cast<const in6_addr *>(NetUtils::GetInAddr(our_saddr)),
	                       static_cast<const in6_addr *>(NetUtils::GetInAddr(tgt_saddr)),
	                       netmaskbits);
	    }
	    break;
	case IPADDR_INVALID:
	    return false;
	}

	// quiet warning c4715: not all control paths return a value
	return false;
}

bool
NetIPAddr::Match( const StrPtr &target, int prefixlen ) const
{
	switch( m_type )
	{
	case IPADDR_V4:
	case IPADDR_V6:
	    return Match( NetIPAddr(target, prefixlen) );
	case IPADDR_INVALID:
	    return false;
	}

	// quiet warning c4715: not all control paths return a value
	return false;
}

/*
 * Compare two (IPv4 or IPv6) addresses for equality, byte-by-byte
 * [static]
 */
bool
NetIPAddr::IPAddrStorageEquals(
	const ipaddr_storage &lhs,
	const ipaddr_storage &rhs)
{
	const sockaddr	*lhs_saddr = reinterpret_cast<const sockaddr *>(&lhs);
	const sockaddr	*rhs_saddr = reinterpret_cast<const sockaddr *>(&rhs);

	size_t	lhs_size = NetUtils::GetAddrSize(lhs_saddr);
	size_t	rhs_size = NetUtils::GetAddrSize(rhs_saddr);

	if( lhs_size != rhs_size )
	    return false;

	const unsigned char *lhs_addr = static_cast<const unsigned char *>(NetUtils::GetInAddr(lhs_saddr));
	const unsigned char *rhs_addr = static_cast<const unsigned char *>(NetUtils::GetInAddr(rhs_saddr));

	for( int i = 0; i < lhs_size; i++ )
	{
	    if( lhs_addr[i] != rhs_addr[i] )
	        return false;
	}

	return true;
}

/*
 * Debugging -- return textual version of the address type
 * [static]
 */
const char *
NetIPAddr::TypeName(IPAddrType t)
{
	switch( t )
	{
	case IPADDR_V4:
	    return "IPv4";
	case IPADDR_V6:
	    return "IPv6";
	case IPADDR_INVALID:
	    return "<invalid>";
	default:
	    return "<unknown>";
	}
}

/*
 * Debugging -- return textual version of the address type
 */
const char *
NetIPAddr::TypeName() const
{
	return TypeName(m_type);
}

/*
 * Debugging -- generate a textual representation of the address
 */
void
NetIPAddr::ToString(StrBuf &buf) const
{
	char numbuf[64];
	const char *num = StrBuf::Itoa(m_prefixlen, &numbuf[63]);

	buf.Set("<");
	buf.Append(m_text.Text());
	buf.Append("/");
	buf.Append(num);

	switch( m_type )
	{
	case IPADDR_V4:
	    buf.Append( "%v4" );
	    break;
	case IPADDR_V6:
	    buf.Append( "%v6" );
	    break;
	case IPADDR_INVALID:
	    buf.Append( "%!!" );
	    break;
	}
	buf.Append(">");
}
