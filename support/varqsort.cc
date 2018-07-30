/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

# include <stdhdrs.h>
# include <strbuf.h>

# include <vararray.h>

#define min(a, b)	(a) < (b) ? a : b

/*
 * Qsort routine from Bentley & McIlroy's "Engineering a Sort Function".
 */

int
VVarArray::Med3( int a, int b, int c ) const
{
	return Compare(a, b) < 0 ?
	    (Compare(b, c) < 0 ? b : (Compare(a, c) < 0 ? c : a ))
	  : (Compare(b, c) > 0 ? b : (Compare(a, c) < 0 ? a : c ));
}

void
VVarArray::Sort( int a, int n )
{
	int pa, pb, pc, pd, pl, pm, pn;
	int r, swap_cnt;

    loop:
	swap_cnt = 0;

	/* For small n, do insertion sort. */

	if (n < 7) 
	{
	    for (pm = a + 1; pm <  a + n; ++pm)
		for (pl = pm; pl > a && Compare(pl - 1, pl) > 0; --pl)
			Swap(pl, pl - 1);

	    return;
	}

	/* Pick the median */
	/* With a large enough sample, we pick the middle of three */

	pm = a + n / 2;

	if (n > 7) 
	{
	    pl = a;
	    pn = a + n - 1;
	    if (n > 40) 
	    {
		    int d = n / 8;
		    pl = Med3( pl, pl + d, pl + 2 * d );
		    pm = Med3( pm - d, pm, pm + d );
		    pn = Med3( pn - 2 * d, pn - d, pn );
	    }
	    pm = Med3( pl, pm, pn );
	}

	/* Do it */

	Swap(a, pm);

	pa = pb = a + 1;
	pc = pd = a + n - 1;

	for (;;) 
	{
	    while (pb <= pc && (r = Compare(pb, a)) <= 0)
	    {
		if( !r )
		{
		    swap_cnt = 1;
		    Swap( pa++, pb );
		}
		++pb;
	    }

	    while (pb <= pc && (r = Compare(pc, a)) >= 0) 
	    {
		if( !r )
		{
		    swap_cnt = 1;
		    Swap( pc, pd-- );
		}
		--pc;
	    }

	    if (pb > pc)
		break;

	    swap_cnt = 1;
	    Swap( pb++, pc-- );
	}

	pn = a + n;
	r = min(pa - a, pb - pa);
	Swap(a, pb - r, r);
	r = min(pd - pc, pn - pd - 1);
	Swap(pb, pn - r, r);

	/* Switch to insertion sort */
	/* This is not in the Bentley paper, but saves time for already */
	/* sorted data.  This used to be before the vecswaps, but that */
	/* was wrong. */

	if (swap_cnt == 0) 
	{  
	    for (pm = a + 1; pm <  a + n; ++pm)
	    {
		for (pl = pm; pl >  a && Compare(pl - 1, pl) > 0; --pl)
		    Swap(pl, pl - 1);

		/* Be prudent: swap_cnt can be zero if the data is */
		/* unsorted to either side of the median, but just */
		/* happens to be partitioned properly about the */
		/* median.  You don't want to risk an insertion sort */
		/* on a large body of data, so we bail back to qsort if */
		/* we're moving data too far. */

		if( ( swap_cnt += ( pm - pl ) ) > 1024 )
		    goto recurse;
	    }

	    return;
	}

    recurse:
	/* Recurse */

	if ((r = pb - pa) > 1)
		Sort( a, r );

	/* Iterate rather than recurse to save stack space */

	if ((r = pd - pc) > 1) 
	{
		a = pn - r;
		n = r;
		goto loop;
	}
}
