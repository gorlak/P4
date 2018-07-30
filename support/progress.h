/*
 * Copyright 1995, 2011 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# define CPP_NORMAL	0
# define CPP_DONE	1
# define CPP_FAILDONE	2
# define CPP_FLUSH	3

# define CP_DESC	0x01
# define CP_UNITS	0x02
# define CP_TOTAL	0x04
# define CP_POS		0x08
# define CP_NEW		0x10

class ProgressReport {
    public:
	ProgressReport();
	virtual ~ProgressReport();
	virtual void Description( const StrPtr & );
	virtual void Units( int );
	virtual void Total( long );

	virtual void Position( long, int = CPP_NORMAL );
	virtual void Increment( long = 1, int = CPP_NORMAL );
    protected:
	int	fieldChanged;
	StrBuf	description;
	int	units;
	long	total;
	long	position, lastReportedPosition;
	int	needfinal;

	Timer	tm;

	virtual void ConsiderReport( int );
	virtual void DoReport( int );
};
