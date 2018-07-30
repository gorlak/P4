// -*- mode: C++; tab-width: 8; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/**
 * netportparser.cc
 *
 * Copyright 2011 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 *
 * Description:
 *     Parse a P4PORT into pieces.
 *     pseudo-regex syntax loose definition:
 *
 *     p4port         ::= [prefix:][host:]port ;
 *     prefix         ::= "jsh"|"rsh"|"tcp"|"tcp4"|"tcp6"|"ssl"|"ssl4"|"ssl6" ;
 *       NB: "tcp"   means non-ssl, IPv4 only
 *           "tcp4"  means non-ssl, IPv4 only (synonym for "tcp")
 *           "tcp6"  means non-ssl, IPv6 only
 *           "tcp46" means non-ssl, IPv4 or IPv6 (IPv4 preferred)
 *           "tcp64" means non-ssl, IPv4 or IPv6 (IPv6 preferred)
 *           "ssl"   means ssl,     IPv4 or IPv6 (IPv4 preferred)
 *           "ssl4"  means ssl,     IPv4 only (synonym for "ssl")
 *           "ssl6"  means ssl,     IPv6 only
 *           "ssl46" means ssl,     IPv4 or IPv6 (IPv4 preferred)
 *           "ssl64" means ssl,     IPv4 or IPv6 (IPv6 preferred)
 *     NB: host may optionally be enclosed in square brackets: [...]
 *     host           := hostname |ipv4dottedquad | ipv6hex | ipv6mappedv4 ;
 *     hostname       := label[. label]* ;
 *     label          := [A-Za-z0-9-_]+ ;    // LDH; by convention (but all octets are allowed)
 *     ipv4dottedquad := decoctet.decoctet.decoctet.decoctet ;
 *     digit          := [0-9] ;
 *     decoctet       := digit{1,3} ;
 *     hexchar        := [0-9A-Fa-f] ;
 *     hexword        := hexchar{1,4} ;
 *       NB: leading 0s may (but need not) be omitted
 *     ipv6hex        := hexword:hexword:hexword:hexword:hexword:hexword ;
 *       NB: 64-bit network prefix and 64-bit interface id [eg, host address]
 *                  (unless high 3 bits are 0)
 *           Exactly one pair of adjacent colons indicates enough 0 hexwords to fill to 8 hexwords total
 *
 *           unspecified    ::0 (IN6ADDR_ANY)
 *           loopback       ::1 (IN6ADDR_LOOPBACK)
 *           link-local     FE80::* (FE80::/10, 54 bits 0,         64-bits interface id)
 *           site-local     FEC0::* (FEC0::/10, 54 bits subnet id, 64-bits interface id) [deprecated]
 *           anycast        interface id of 0
 *
 *           See RFC 4291 "IP Version 6 Addressing Architecture"
 *           See RFC 5952 "A Recommendation for IPv6 Address Text Representation"
 *     ipv6mappedv4   := hexword:hexword:hexword:hexword:ipv4dottedquad 
 *                    |  hexword:hexword:hexword:hexword:hexword:hexword ;
 *       NB: Upper 80 bits are 0, then 16 bits of 1, then 32-bit IPv4 address in dotted-quad or hex
 *           So normally written as ::FFFF:127.0.0.1
 *           See RFC 6052 "IPv6 Addressing of IPv4/IPv6 Translators"
 *
 *     (1) If the text from the beginning of the string to the first colon
 *         matches one of our known prefixes, remember it as the prefix
 *         and skip past the colon.
 *     (2) The host portion may be enclosed in square brackets; if so, the port
 *         is the part after the right bracket (it may/should be preceded by a colon).
 *         See "RFC 3986 : Uniform Resource Identifier (URI): Generic Syntax",
 *             "Section 3.2.2.  Host".
 *     (3) Otherwise the text after the last colon (or the entire string if no colon)
 *         is the port.  It is allowed to be empty (for bind() OS chooses port).
 *     (4) Anything left is the host (name or address [IPv4 or IPv6]).
 *
 *     (a) IPv4: ":0" means "localhost:0" for connect, and "*:0" for bind
 *     (b) IPv4: "" and ":" mean ":0"
 *     (c) IPv6: ":::nnnn" means host="::", port="nnnn"
 *     (d) IPv6: ":::0" means "localhost::0" for connect, and "*::0" for bind
 *
 *     We don't parse the host field!  But we do grovel through it a bit ...
 *
 *     Hostname syntax:
 *     * see RFC 952 "DOD INTERNET HOST TABLE SPECIFICATION"
 *       - DNS labels are LDH (Letters, Digits, and Hyphen), and start with a letter.
 *     * see RFC 1123 "Requirements for Internet Hosts -- Application and Support"
 *       - now DNS labels may also start with a digit.
 *     * see RFC 2181 "Clarifications to the DNS Specification"
 *       - DNS label octets may contain any binary value (but we don't support this).
 *     * IDNA (non-ASCII DNS names [eg, Unicode])
 *       - we do NOT support IDNA at this time.
 *       - see RFC 3492 "Punycode: A Bootstring encoding of Unicode
 *                           for Internationalized Domain Names in Applications (IDNA)"
 *       - see RFC 5890 "Internationalized Domain Names for Applications (IDNA):
 *                           Definitions and Document Framework"
 *       - see RFC 5891 "Internationalized Domain Names in Applications (IDNA): Protocol"
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <ctype.h>
# include <error.h>
# include <msgserver.h>
# include <msgrpc.h>
# include <hostenv.h>
# include "netport.h"
# include "netportipv6.h"
# include "netportparser.h"
# include "netutils.h"
# include "debug.h"
# include "tunable.h"

/*
 * In 2012.1 and 2012.2, IPv6 infrastructure is in place but is neither documented
 * nor supported.  Customers will use only IPv4; IPv6 is reserved for internal use
 * and testing.  Therefore we force all P4PORT strings to use IPv4 unless they
 * explicitly specify IPv6.  Transport prefixes of "tcp:" or "ssl:" (or none)
 * therefore are equivalent to "tcp4:" and "ssl4:"
 *
 * In 2013.1 IPv6 will be fully documented and supported, and we will continue
 * to support IPv4.  Users will be able to force IPv4, force IPv6, prefer IPv4,
 * or prefer IPv6.  At that time, the meaning of no prefix, "tcp:", and "ssl:"
 * will change: always forcing IPv4 will be optional during address resolution.
 *
 * If the user requests compliance with RFC 3484 via the "net.rfc3484" tunable,
 * then the prefixes "tcp:" and "ssl:" will mean that we let the OS choose between
 * IPv4 and IPv6 in conformance to RFC 3484, which specifies the precedence in
 * which addresses should be resolved.
 * If they don't set "net.rfc3484" (or set it to 0) then they will continue to
 * prefer IPv4, as in earlier releases.
 *
 * See RFC 3484 "Default Address Selection for Internet Protocol version 6 (IPv6)".
 * Note that it is optional for host administrators to be able to modify this
 * precedence table:
 * - linux/Unix:        edit /etc/gai.conf
 * - Windows:           netsh.exe interface ipv6
 * - Mac OS X:          appears to modify precedence dynamically based on
 *                      routing timing to favor working addresses.
 *
 * Uncomment the definition of RFC_3484_COMPLIANT to enable the 2013.1 behavior
 * (and do the same in <tests/portparsertest.cc> to pass the unit tests).
 * In 2013.1 we can remove this macro and the ifdef's, but for now this allows
 * us easily to test both current and new behavior.
 */

# define RFC_3484_COMPLIANT

/*
 * If we allow RFC 3484 compliance, return true iff the user has enabled it
 * (via the "net.rfc3484" tunable).  Otherwise return false.
 */
static bool
HonorRFC3484()
{
# ifdef RFC_3484_COMPLIANT
	return p4tunable.Get( P4TUNE_NET_RFC3484 );
# else
	return false;
# endif // RFC_3484_COMPLIANT
}

/*
 * Orthodox Canonical Form (OCF) methods
 */


/**
 * default ctor
 */
NetPortParser::NetPortParser()
: mPortString("")
, mTransport("")
, mHost("")
, mPort("")
, mHostPort("")
, mPortColon(false)
, mExtraTransports(NULL)
{
	mPrefix.mType = PT_NONE;
	mPrefix.mName = "";
} // default ctor

NetPortParser::NetPortParser(
	const StrRef &portstr)
: mPortString(portstr)
, mTransport("")
, mHost("")
, mPort("")
, mHostPort("")
, mPortColon(false)
, mExtraTransports(NULL)
{
	mPrefix.mType = PT_NONE;
	mPrefix.mName = "";
	Parse();
}

NetPortParser::NetPortParser(
	const StrRef &portstr,
	const Prefix *extraTransports)
: mPortString(portstr)
, mTransport("")
, mHost("")
, mPort("")
, mHostPort("")
, mPortColon(false)
, mExtraTransports(extraTransports)
{
	mPrefix.mType = PT_NONE;
	mPrefix.mName = "";
	Parse();
}

NetPortParser::NetPortParser(
	const char *portstr)
: mPortString(portstr)
, mTransport("")
, mHost("")
, mPort("")
, mHostPort("")
, mPortColon(false)
, mExtraTransports(NULL)
{
	mPrefix.mType = PT_NONE;
	mPrefix.mName = "";
	Parse();
}

/**
 * copy ctor
 */
NetPortParser::NetPortParser(
	const NetPortParser &rhs)
: mPortString(rhs.mPortString)
, mTransport(rhs.mTransport)
, mHost(rhs.mHost)
, mPort(rhs.mPort)
, mHostPort(rhs.mHostPort)
, mPortColon(rhs.mPortColon)
, mPrefix(rhs.mPrefix)
, mExtraTransports(rhs.mExtraTransports)
{
} // copy ctor

/**
 * dtor
 */
NetPortParser::~NetPortParser()
{
} // dtor

/**
 * assignment op
 */
const NetPortParser    &
NetPortParser::operator=(
	const NetPortParser &rhs)
{
	if( this != &rhs ) {
	    mPortString = rhs.mPortString;
	    mTransport = rhs.mTransport;
	    mHost = rhs.mHost;
	    mPort = rhs.mPort;
	    mHostPort = rhs.mHostPort;
	    mPortColon = rhs.mPortColon;
	    mPrefix = rhs.mPrefix;
	    mExtraTransports = rhs.mExtraTransports;
	}

	return *this;
} // op=

/**
 * op==
 */
bool
NetPortParser::operator==(
	const NetPortParser &rhs) const
{
	if( this == &rhs ) {
	    return true;
	}

	if( mPortString != rhs.mPortString )
	    return false;
	if( mTransport != rhs.mTransport )
	    return false;
	if( mHost != rhs.mHost )
	    return false;
	if( mPort != rhs.mPort )
	    return false;
	if( mHostPort != rhs.mHostPort )
	    return false;
	if( mPortColon != rhs.mPortColon )
	    return false;
	if( mPrefix.mType != rhs.mPrefix.mType )
	    return false;
	if( mExtraTransports != rhs.mExtraTransports )
	    return false;

	return true;
} // op==

/**
 * op!=
 */
bool
NetPortParser::operator!=(
	const NetPortParser &rhs) const
{
	return !(*this == rhs);
} // op!=

// accessors

/*
 * RFC 3484 specifies a precedence for deciding the order of returned
 * addresses to be used for connect/bind.  If we're following RFC 3484
 * we use the list returned by getaddrinfo() as-is.  Otherwise we'll
 * filter out rejected families (via MustIPv4() and MustIPv6()) and then
 * try the preferred family (if any) first.  This filtering and ordering
 * is applied to the already-ordered list returned by getaddrinfo().
 *
 * In 2012.1, NetPortParser.MustRfc3484() will always return false,
 * but in 2013.1 and later it will return the value of "-v net.rfc3484"
 * if the transport didn't specify an IPv4 or IPv6 preference; eg,
 * no transport prefix, or a prefix of "tcp:" or "ssl:" (and the host
 * wasn't a numeric address).
 *
 * If this causes problems for customers then we might want
 * to continue to return false until a later date.
 *
 * See RFC 3484 "Default Address Selection for Internet Protocol version 6 (IPv6)".
 */
bool
NetPortParser::MustRfc3484() const
{
	switch( mPrefix.mType )
	{
	case PT_NONE:
	case PT_TCP:
	case PT_SSL:
	    return HonorRFC3484();
	default:
	    return false;
	}
}

bool
NetPortParser::MayIPv4() const
{
	switch( mPrefix.mType )
	{
	case PT_NONE:
	case PT_TCP:
	case PT_TCP4:
	case PT_TCP46:
	case PT_TCP64:
	case PT_SSL:
	case PT_SSL4:
	case PT_SSL46:
	case PT_SSL64:
	    return true;
	default:
	    return false;
	}
}

bool
NetPortParser::MayIPv6() const
{
	switch( mPrefix.mType )
	{
	case PT_TCP6:
	case PT_TCP46:
	case PT_TCP64:
	case PT_SSL6:
	case PT_SSL46:
	case PT_SSL64:
	    return true;
	case PT_NONE:
	case PT_TCP:
	case PT_SSL:
	    return HonorRFC3484();
	default:
	    return false;
	}
}

bool
NetPortParser::PreferIPv4() const
{
	switch( mPrefix.mType )
	{
	case PT_NONE:
	case PT_TCP:
	case PT_SSL:
	    return !HonorRFC3484();
	case PT_TCP4:
	case PT_TCP46:
	case PT_SSL4:
	case PT_SSL46:
	    return true;
	default:
	    return false;
	}
}

bool
NetPortParser::PreferIPv6() const
{
	switch( mPrefix.mType )
	{
	case PT_TCP6:
	case PT_TCP64:
	case PT_SSL6:
	case PT_SSL64:
	    return true;
	default:
	    return false;
	}
}

// explicitly listed IPv6?
bool
NetPortParser::WantIPv6() const
{
	switch( mPrefix.mType )
	{
	case PT_TCP6:
	case PT_TCP46:
	case PT_TCP64:
	case PT_SSL6:
	case PT_SSL46:
	case PT_SSL64:
	    return true;
	default:
	    return false;
	}
}

bool
NetPortParser::MayJSH() const
{
	// JSH is never optional; either you must use JSH or you must not
	return MustJSH();
}

bool
NetPortParser::MustJSH() const
{
	return mPrefix.mType == PT_JSH;
}

bool
NetPortParser::MayRSH() const
{
	// RSH is never optional; either you must use RSH or you must not
	return MustRSH();
}

bool
NetPortParser::MustRSH() const
{
	return mPrefix.mType == PT_RSH;
}

bool
NetPortParser::MustSSL() const
{
	switch( mPrefix.mType )
	{
	case PT_SSL:
	case PT_SSL4:
	case PT_SSL6:
	case PT_SSL46:
	case PT_SSL64:
	    return true;
	default:
	    return false;
	}
}

bool
NetPortParser::MustIPv4() const
{
	switch( mPrefix.mType )
	{
	case PT_NONE:
	case PT_TCP:
	case PT_SSL:
	    return !HonorRFC3484();
	case PT_TCP4:
	case PT_SSL4:
	    return true;
	default:
	    return false;
	}
}

bool
NetPortParser::MustIPv6() const
{
	return mPrefix.mType == PT_TCP6 || mPrefix.mType == PT_SSL6;
}

const StrBuf
NetPortParser::String(
	PPOpts opts) const
{
	StrBuf result;
	StrBuf tmp;

	if( opts & PPO_TRANSPORT )
	{
	    tmp = Transport();
	    if( tmp.Length() && (tmp != "tcp") )    // don't report the default transport
	    {
	        result.Set( tmp );
	        result.Append( ":" );
	    }
	}

	tmp = Host();
	if( tmp.Length() )
	{
	    result.Append( &tmp );
	}

	if( opts & PPO_PORT )
	{
	    result.Append( ":" );
	    tmp = Port();
	    result.Append( &tmp );
	}

	return result;
}
/**
 * NetPortParser::GetQualifiedP4Port
 *
 * @brief  Return the external view of P4PORT, if current
 *         p4port does not contain a host/ip addr try using
 *         the value of the addr stored in the server spec
 *
 * @param serverSpecAddr, string server spec address field
 * @param e,              Error reference to hand back any error
 */
const StrBuf
NetPortParser::GetQualifiedP4Port( StrBuf &serverSpecAddr, Error &e ) const
{
	StrBuf result;
	StrBuf tmpHost;

	// sanity check that the numeric port suffix exists.
	if( mPort.Length() == 0 )
	{
	    e.Set( MsgRpc::BadP4Port ) << String();
	    return String();
	}

	// if host is present just return the port string
	if( mHost.Length() != 0 )
	{
	    return String();
	}

	if( serverSpecAddr.Length() )
	{
	    NetPortParser npp( serverSpecAddr );
	    if( npp.mHost.Length() )
	    {
		return npp.String();
	    }
	}
	e.Set( MsgRpc::NoHostnameForPort );
	return String();
}

int
NetPortParser::PortNum() const
{
	return Port().Atoi();
}

/*
 * Other methods
 */

const NetPortParser::Prefix *
NetPortParser::FindPrefix(
	const char *prefix,
	int len)
{
	static const Prefix prefixes[] = {
	    {"jsh",     PT_JSH},	// java flavor of rsh
	    {"rsh",     PT_RSH},
	    {"tcp",     PT_TCP},
	    {"tcp4",    PT_TCP4},
	    {"tcp6",    PT_TCP6},
	    {"tcp46",   PT_TCP46},
	    {"tcp64",   PT_TCP64},
	    {"ssl",     PT_SSL},
	    {"ssl4",    PT_SSL4},
	    {"ssl6",    PT_SSL6},
	    {"ssl46",   PT_SSL46},
	    {"ssl64",   PT_SSL64},
	    {"",        PT_NONE}
	};
	static const int kNoPrefix = sizeof(prefixes)/sizeof(prefixes[0]) - 1;    // index of the PT_NONE entry

	if( (len < 3) || (len > 5) )
	{
	    // all of our prefixes are 3, 4, or 5 chars long
	    return &prefixes[kNoPrefix];
	}

	const Prefix *pfx;
	for( pfx = prefixes; pfx->mName[0]; ++pfx )
	{
	    if( strncmp(prefix, pfx->mName, len) == 0 )
	        return pfx;
	}

	// try the user-supplied table
	if( mExtraTransports )
	{
	    for( pfx = mExtraTransports; pfx->mName[0]; ++pfx )
	    {
		if( strncmp(prefix, pfx->mName, len) == 0 )
		    return pfx;
	    }
	}

	return pfx;
}

void
NetPortParser::Parse()
{
	const Prefix *pfx = FindPrefix( "", 0 );    // init to PT_NONE
	const char *str = mPortString.Text();

	// find the prefix
	const char *p = strchr(str, ':');
	if( p )
	{
	    pfx = FindPrefix( str, p-str );
	    if( pfx->mType != PT_NONE )
	    {
	        // skip past valid prefix
	        str = ++p;
	    }

	    // don't parse rsh: or jsh: cmd
	    // store the cmd in the host field
	    if( pfx->mType == PT_JSH || pfx->mType == PT_RSH )
	    {
	        mPrefix = *pfx;
	        mHost.Set( str );
	        mHostPort.Set( str );
	        mTransport = mPrefix.mName;
	        return;
	    }
	}
	else if( strcmp(str, "jsh") == 0 )
	{
	    // java flavor of "rsh"
	    // "jsh" should be used only by p4d after seeing "-ij"
	    pfx = FindPrefix( "jsh", 3 );
	    mPrefix = *pfx;
	    mHost.Set( str );
	    mHostPort.Set( str );
	    mTransport = mPrefix.mName;
	    return;
	}
	else if( strcmp(str, "rsh") == 0 )
	{
	    pfx = FindPrefix( "rsh", 3 );
	    mPrefix = *pfx;
	    mHost.Set( str );
	    mHostPort.Set( str );
	    mTransport = mPrefix.mName;
	    return;
	}

	// address is optionally enclosed in square brackets
	const char *rbracket = NULL;
	if( *str == '[' )
	{
	    rbracket = strrchr(str, ']');
	    if( rbracket )
		++str;		// skip past the lbracket
	}

	// count the colons after the prefix (if any)
	int numColons = 0;
	const char *lastColon = NULL;
	for( const char *cp = str; *cp; cp++ )
	{
	    if( *cp == ':' )
	    {
	        lastColon = cp;
	        numColons++;
	    }
	}

	if( rbracket )
	{
	    mHost.Set( str, rbracket - str );
	    --str;	// backup to include the left bracket
	    mHostPort.Set( str );

	    // If there are matched brackets, the host is everything inside the brackets
	    // and the port is everything after the right bracket (skipping the
	    // following colon).
	    if( rbracket[1] == ':' )
	    {
		rbracket++;
		numColons--;    // don't count the port-marking colon
		mPortColon = true;
	    }
	    mPort.Set( rbracket+1 );    // may be empty
	}
	else if( lastColon )
	{
	    // if there is a colon, the port is everything after the last colon
	    // and host is everything before it (after the optional prefix)
	    mPort.Set( lastColon+1 );    // may be empty
	    mHost.Set( str, lastColon - str );
	    mHostPort.Set( str );
	    numColons--;    // don't count the port-marking colon
	    mPortColon = true;
	}
	else
	{
	    // if no colon, the entire string is the port
	    mPort.Set( str );
	    mHostPort.Set( str );
	}

	if( NetUtils::IsIpV6Address(mHost.Text()) )
	{
	    const char	*bp = mHost.Text();
	    const char	*ep = &bp[mHost.Length()-1];

	    // store the trailing %zoneid, if any
	    for( const char *p = ep; p > bp; p-- )
	    {
	        if( *p == '%' )
	        {
	            mZoneID.Set( p, ep-p+1 );
	            break;
	        }
	    }
	}

	// remember the prefix
	mPrefix = *pfx;

	// If neither IPv4 nor IPv6 was specified but a numeric address was given,
	// determine the transport type from the address.
	bool	ssl = false;
	switch( pfx->mType )
	{
	case PT_SSL:
	    ssl = true;
	    // Fall through!
	case PT_NONE:
	case PT_TCP:
	    /*
	     * If there are 2 or more colons and it's a numeric IPv6 address,
	     * default to "tcp6"; (IPv6 numeric addresses must have at least
	     * 2 colons, and we don't accept colons in a hostname, so 2 or more
	     * means numeric IPv6 address).
	     *
	     * If 0 or 1 colons, default to "tcp4" if the host
	     * is an IPv4 numeric address.
	     */
	    if( numColons >= 2 )
	    {
	        if( NetUtils::IsIpV6Address(mHost.Text()) )
	            mPrefix = *FindPrefix( ssl ? "ssl6" : "tcp6", 4 );
	    }
	    else
	    {
	        if( NetUtils::IsIpV4Address(mHost.Text(), NetUtils::IPADDR_PREFIX_PROHIBIT) )
	            mPrefix = *FindPrefix( ssl ? "ssl4" : "tcp4", 4 );
	    }
	    break;
	}

	mTransport = mPrefix.mName;
}

// JIRA P4-10855, job065290
bool
NetPortParser::IsValid(Error *e) const
{
	if( !MustJSH() && !MustRSH() && !mPortColon && (mPort.Length() <= 0) )
	{
	    e->Set( MsgServer::PortMissing ) << String();
	    return false;
	}

	return true;
}

void
NetPortParser::Parse(const StrRef    &portstr)
{
	mPortString = portstr;
	Parse();
}
