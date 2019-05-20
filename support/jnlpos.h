// -*- mode: C++; tab-width: 8; -*-
// vi:ts=8 sw=4 noexpandtab autoindent

/**
 * jnlpos.h
 *
 * Description:
 * - Manage journal positions:
 *   	{jnlNum, jnlOffset}
 *   and text representation:
 *   	"jnlNum/jnlOffset"
 *
 * Copyright (c) 2013 Perforce Software
 * Confidential.  All Rights Reserved.
 * Original Author:	Mark Wittenberg
 *
 * IDENTIFICATION
 *    $Header: $
 */

class JnlPos {
public:
	enum JnlPosSpecial {
	    POS_MAX
	};

	inline
	JnlPos( int num = 0, P4INT64 offset = 0 )
	: journalNumber(num)
	, journalOffset(offset)
	{
	}

	inline
	JnlPos( const JnlPos &rhs )
	: journalNumber(rhs.journalNumber)
	, journalOffset(rhs.journalOffset)
	{
	}

	inline
	JnlPos( const char *txt )
	: journalNumber(0)
	, journalOffset(0)
	{
	    Parse( txt );
	}

	// construct a JnlPos with the max possible journalNumber and journalOffset
	inline
	JnlPos( JnlPosSpecial what )
	: journalNumber(((unsigned int)~0) >> 1), journalOffset(((unsigned P4INT64)~0) >> 1 )
	{
	}

	int
	GetJnlNum() const { return journalNumber; }

	P4INT64
	GetJnlOffset() const { return journalOffset; }

	void
	SetJnlNum(int jnlNum) { journalNumber = jnlNum; }

	void
	SetJnlOffset(P4INT64 jnlOffset) { journalOffset = jnlOffset; }

	inline
	bool
	IsZero() const
	{
	    return (journalNumber == 0) && (journalOffset == 0);
	}

	inline
	bool
	IsPosMax() const
	{
	    const JnlPos PosMax = JnlPos( POS_MAX );

	    return journalNumber == PosMax.GetJnlNum() &&
		journalOffset == PosMax.GetJnlOffset();
	}

	inline
	JnlPos &
	operator=( const JnlPos &rhs )
	{
	    if( this != &rhs )
	    {
		journalNumber = rhs.journalNumber;
		journalOffset = rhs.journalOffset;
	    }

	    return *this;
	}

	const JnlPos &
	Min( const JnlPos &rhs ) const;

	static
	const JnlPos &
	Min( const JnlPos &a, const JnlPos &b );

	const JnlPos &
	Max( const JnlPos &rhs ) const;

	static
	const JnlPos &
	Max( const JnlPos &a, const JnlPos &b );

	void
	Parse( const char *txt );

	void
	Parse( const StrPtr &txt );

	const StrPtr &
	Fmt( StrBuf &buf );

	bool
	GetVar( StrDict *dict, const char *tagNum, const char *tagSequence );

	void
	SetVar( StrDict *dict, const char *tagNum, const char *tagSequence );

private:
	int	journalNumber;
	P4INT64	journalOffset;
};

bool
operator<(const JnlPos &lhs, const JnlPos &rhs);

bool
operator==(const JnlPos &lhs, const JnlPos &rhs);

bool
operator!=(const JnlPos &lhs, const JnlPos &rhs);

bool
operator<=(const JnlPos &lhs, const JnlPos &rhs);

bool
operator>(const JnlPos &lhs, const JnlPos &rhs);

bool
operator>=(const JnlPos &lhs, const JnlPos &rhs);
