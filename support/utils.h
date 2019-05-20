/*
 * @file utils.h
 *
 * @brief miscellaneous utilties available to all
 *
 * Threading: none
 *
 * @invariants:
 *
 * Copyright (c) 2012 Perforce Software
 * Confidential.  All Rights Reserved.
 * @author Wendy Heffner
 *
 * Creation Date: December 5, 2012
 */

////////////////////////////////////////////////////////////////////////////
//  RefCount - CLASS                                                      //
////////////////////////////////////////////////////////////////////////////
class RefCount
{
public:
	RefCount()
	{
	    count=0;
	}

	const int &Increment()
	{
	    ++count;
	    return count;
	}
	const int &Decrement()
	{
	    --count;
	    return count;
	}
	int Value()
	{
	    return count;
	}

private:
	int count;
};

////////////////////////////////////////////////////////////////////////////
//  SmartPointer - CLASS                                                  //
////////////////////////////////////////////////////////////////////////////
/*
 * Reference counted smart pointer.  If last smart pointer referencing the object
 * of type T leaves allocation scope then the destructor of smart pointer
 * will delete the referenced T object.
 */
template < typename T > class SmartPointer
{
public:
	SmartPointer() : pData(0), ref(0)
	{
	    ref = new RefCount();
	    ref->Increment();
	};

	SmartPointer(T* t) : pData(t), ref(0)
	{
	    ref = new RefCount();
	    ref->Increment();
	};

	SmartPointer(const SmartPointer<T>& ptr) : pData(ptr.pData), ref(ptr.ref)
	{
	    ref->Increment();
	};

	~SmartPointer()
	{
	    if( ref->Decrement() == 0)
	    {
		delete pData;
		delete ref;
	    }
	};

	T& operator* ()
	{
	    return *pData;
	};

	T* operator-> ()
	{
	    return pData;
	};

	SmartPointer<T>& operator = (const SmartPointer<T>& ptr)
	{
	    // Am I on both rhs and lhs if so skip
	    if (this != &ptr)
	    {
		if( ref->Decrement() == 0)
		{
		    delete pData;
		    delete ref;
		}

		pData = ptr.pData;
		ref = ptr.ref;
		ref->Increment();
	    }
	    return *this;
	};

private:
	T*        pData;       // data pointer
	RefCount* ref;         // reference count
};


// global utility funciton

/**
 * ISHex
 * - return true if c is a valid character for a hex value, 
 * - otherwise return false.
 */

bool IsHex( char c );
