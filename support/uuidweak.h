// -*- mode: C++; tab-width: 8; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/**
 * uuidweak.h
 *
 * Description:
 *	A simple implementation of UUIDs.
 *
 *	See:
 *	    http://en.wikipedia.org/wiki/Uuid
 *	    http://www.boost.org/doc/libs/1_47_0/libs/uuid/uuid.html
 *
 * Copyright 2011 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

class WeakUUID : public BaseUUID {
public:
	enum
	{
	    kDataSize = 16,	// 128 bits, per RFC-4122
	    kStringSize = 36	// 2 hex digits per byte + 4 hyphens
	};

	// buffer big enough to hold the raw uuid data (implementation-dependent)
	typedef ValueType	DataType[kDataSize];

	// Orthodox Canonical Form (OCF) methods
	WeakUUID();		// generate a random UUID

	// generate UUID data as copies of "val" byte
	WeakUUID(
	    int		val);

	WeakUUID(
	    const WeakUUID	&rhs);

	~WeakUUID();

	virtual const WeakUUID &
	operator=(
	    const WeakUUID	&rhs);

	virtual bool
	operator==(
	    const WeakUUID	&rhs) const;

	virtual bool
	operator!=(
	    const WeakUUID	&rhs) const;

	// accessors

	virtual bool
	IsNil() const;

	// return the variant type of this UUID
	virtual TypeVariant
	VariantType() const;

	// return the version of this UUID variant
	virtual TypeVersion
	VersionType() const;

	// copy the raw uuid data bytes
	void
	Data(DataType &data) const;

	// return the size of the underlying boost uuid data
	virtual unsigned int
	SizeofData() const;

	// mutators

	// swap the underlying uuid data bytes with rhs
	virtual void
	Swap(WeakUUID	&rhs);

	// iterators

	virtual iterator
	begin()
	{
	    return &m_uuid[0];
	}

	virtual iterator
	end()
	{
	    return &m_uuid[kDataSize];
	}

	virtual const_iterator
	begin() const
	{
	    return &m_uuid[0];
	}

	virtual const_iterator
	end() const
	{
	    return &m_uuid[kDataSize];
	}

	// Other methods

	// Set "buf" to the formatted hexadecimal character representation
	// of this UUID.
	virtual StrPtr
	ToStrBuf(StrBuf	&buf) const;

protected:

private:
	DataType	m_uuid;
};
