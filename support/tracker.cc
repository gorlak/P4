/*
 * Copyright 2005 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include "tracker.h"

/*
 * tracker.cc -- server performance tracking threshholds
 *
 * Note special level -1 does old dbstat: only rows in/out and locks
 * taken, which can be meausured determistically.
 */

const int Alot = 1000000000;

static int grid[ TT_LAST ][ 7 ] = {

/*                        -1      0  1  2       3        4         5       */
/*                        dbstat  any   <10     <100     <1000     more    */
/* ----------------------------------------------------------------------- */
/* SERVER_FATAL */        Alot,   1, 1, 1,      1,       1,        1,
/* SERVER_AUTH  */        Alot,   1, 1, 1,      1,       1,        1,
/* SERVER_CLOCK (ms) */   Alot,   1, 1, 60000,  60000,   60000,    60000,
/* SERVER_CPU (ms) */     Alot,   1, 1, 1000,   10000,   10000,    10000,
/* DB_LOCKS */            1,      1, 1, 1000,   10000,   100000,   100000,
/* DB_ROWS_IN */          1,      1, 1, 10000,  100000,  1000000,  10000000,
/* DB_ROWS_OUT */         1,      1, 1, 1000,   10000,   100000,   100000,
/* DB_PAGE_IN */          1,      1, 1, 1000,   10000,   100000,   100000,
/* DB_PAGE_OUT */         1,      1, 1, 100,    1000,    10000,    10000,
/* DB_READ_WAIT (ms) */   Alot,   1, 1, 100,    1000,    5000,     5000,
/* DB_WRITE_WAIT (ms) */  Alot,   1, 1, 100,    1000,    5000,     5000,
/* DB_PEEK_WAIT (ms) */	  Alot,   1, 1, 100,    1000,    5000,     5000,
/* DB_READ_HELD (ms) */   Alot,   1, 1, 100,    100,     5000,     5000,
/* DB_WRITE_HELD (ms) */  Alot,   1, 1, 100,    100,     500,      500,
/* DB_PEEK_HELD (ms) */	  Alot,   1, 1, 100,    100,     500,      500,
/* DB_WEDGED */           Alot,   1, 1, 1,      1,       1,        1,
/* DB_REORG_CNT */        Alot,   1, 1, 1,      1,       1,        1,
/* DB_SPLIT_CNT */        Alot,   1, 1, 10,     100,     1000,     10000,
/* TT_RPC_MSGS */         Alot,   1, 1, 10000,  10000,   10000,    10000,
/* TT_RPC_MBYTES */       Alot,   1, 1, 10,     100,     100,      100,
/* TT_RPC_ERRORS */       Alot,   1, 1, 1,      1,       1,        1,
/* TT_RMTDB_ROWS */       Alot,   1, 1, 1000,   1000,    1000,     1000,
/* TT_RMTDB_TIME */       Alot,   1, 1, 1000,   1000,    1000,     1000,
/* TT_TRIGGER_TIME (ms)*/ Alot,   1, 1, 1000,   2000,    2000,     5000,
/* PX_SUB_ADDS */         Alot,   1, 1, 100,    1000,    10000,    10000,
/* PX_SUB_FAILS */        Alot,   1, 1, 1,      1,       1,        1,    
/* PX_FAULTS */           Alot,   1, 1, 100,    1000,    10000,    10000,
/* PX_FAULTS_MB */        Alot,   1, 1, 10,     100,     1000,     10000,
/* PX_FAULTS_OTH */       Alot,   1, 1, 1,      1,       1,        1,    
/* PX_FLUSHES */          Alot,   1, 1, 100,    1000,    10000,    10000,
/* PX_DELIVERIES */       Alot,   1, 1, 1000,   10000,   100000,   100000,
/* PX_DELIVERIES_BYTES */ Alot,   1, 1, 100000000, 100000000, 100000000, 100000000,
/* PX_TOT_FAULTS */       Alot,   1, 1, 100,    1000,    10000,    10000,
/* PX_TOT_FAULTS_BYTES */ Alot,   1, 1, 100000000, 100000000, 100000000, 100000000,
/* PX_DIRECT_COUNT */     Alot,   1, 1, 100,    1000,    10000,    10000,
/* PX_DIRECT_BYTES */     Alot,   1, 1, 100000000, 100000000, 100000000, 100000000,

} ;

int
Tracker::Over( TrackerType type, P4INT64 amount )
{
	// level -1 use dbstat slot in table

	if( level < -1 ) level = -1;
	if( level > 5 ) level = 5;

	return amount >= grid[ type ][ level + 1 ];
}

int
Tracker::UsersToLevel( int users )
{
	if( users < 5 ) 	return 2;
	else if( users < 100 ) 	return 3;
	else if( users < 1000 ) return 4;
	else 			return 5;
}
