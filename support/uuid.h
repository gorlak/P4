// -*- mode: C++; tab-width: 8; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/**
 * uuid.h
 *
 * Description:
 *	Abstract base class for UUID implementations
 *
 *	See:
 *	    http://en.wikipedia.org/wiki/Uuid
 *	    http://www.boost.org/doc/libs/1_47_0/libs/uuid/uuid.html
 *
 * Copyright 2017 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

class BaseUUID {
public:
	typedef unsigned char	ValueType;
	typedef ValueType	*iterator;
	typedef const ValueType	*const_iterator;

	enum TypeVersion {
	    kVersionUnknown = -1,
	    kVersionTimeBased = 1,
	    kVersionDceSecurity = 2,
	    kVersionNameBasedMd5 = 3,
	    kVersionRandomNumberBased = 4,
	    kVersionNameBasedSha1 = 5
	};

	enum TypeVariant {
	    kVariantNil = 0,
	    kVariantRfc4122 = 1,
	    kVariantMicrosoft = 2,
	    kVariantFuture = 3
	};

	// Orthodox Canonical Form (OCF) methods
	BaseUUID();		// generate a random UUID

	// generate UUID data as copies of "val" byte
	BaseUUID(
	    int		val);

	BaseUUID(
	    const BaseUUID	&rhs);

	~BaseUUID();

	const BaseUUID &
	operator=(
	    const BaseUUID	&rhs);

	virtual bool
	operator==(
	    const BaseUUID	&rhs) const;

	virtual bool
	operator!=(
	    const BaseUUID	&rhs) const;

	// accessors

	virtual bool
	IsNil() const
	{
	    return true;
	}

	// return the variant type of this UUID
	virtual TypeVariant
	VariantType() const = 0;

	// return the version of this UUID variant
	virtual TypeVersion
	VersionType() const = 0;

	// return the size of the underlying boost uuid data
	virtual unsigned int
	SizeofData() const = 0;

	// mutators

	// swap the underlying uuid data bytes with rhs
	virtual void
	Swap(BaseUUID	&rhs)
	{
	}


	// iterators

	virtual iterator
	begin() = 0;

	virtual iterator
	end() = 0;

	virtual const_iterator
	begin() const = 0;

	virtual const_iterator
	end() const = 0;


	// Other methods

	virtual bool
	operator<(const BaseUUID &rhs) const;

	// Set "buf" to the formatted hexadecimal character representation
	// of this UUID.
	virtual StrPtr
	ToStrBuf(StrBuf	&buf) const;

protected:

private:
};
