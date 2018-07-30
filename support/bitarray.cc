# include <stdhdrs.h>

# include "bitarray.h"

#define NBW (8 * sizeof(BitArray::BitBlock))
#define MASK (NBW-1)

BitArray::BitArray( BitArray::Index nBits )
    : w(new BitBlock[1+nBits/NBW])
{
    BitBlock *s, *e;
    e = w + 1+nBits/NBW;
    for (s = w; s < e; ++s)
	*s = 0;
}

int
BitArray::operator []( BitArray::Index p ) const
{
    BitBlock *bp = w + (p / NBW);
    return ((((BitBlock)1) << (p & MASK)) & *bp) != 0;
}

int
BitArray::tas( BitArray::Index p )
{
    BitBlock *bp = w + (p / NBW);
    BitBlock bit = (((BitBlock)1) << (p & MASK));
    if ((bit & *bp) != 0)
	return 1;
    *bp |= bit;
    return 0;
}

int
BitArray::clear( BitArray::Index p )
{
    BitBlock *bp = w + (p / NBW);
    BitBlock bit = (((BitBlock)1) << (p & MASK));
    int ret;
    ret = ((bit & *bp) != 0);
    *bp &= ~bit;
    return ret;
}
