/*
 * Copyright 1995, 2004 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/* 
 * P4Tagl.cc - definition of rpc variable names for protocol levels
 */

/* PROTOCOL LEVELS ARE DEFINED HERE! */

# include <p4tags.h>

// see client/client.cc

// client protocol 1: has clientErrorPause (#2635) 97.1
// client protocol 2: supports resolve -as (#2933) 97.2
// client protocol 3: resolve supports -v (#4229) 97.3
// client protocol 4: print uses OutputBinary (#5309) 98.1
// client protocol 5: has client-Crypto password (#6323) 98.2
// client protocol 6: has link compression (#8565) 99.1
//		      has HandleError (#9052) 99.1
// client protocol 7: clientDelete noclobber doesn't core dump
//		      HandleError using portable format
// client protocol 8: chmodFile takes modTime 99.2
// client protocol 9: client-sendFile sends modTime, takes perms
// client protocol 50: client-checkFile honors forceType
// client protocol 51: client-CloseMerge can return 'edit' merge 2001.1
// client protocol 52: 2001.2
// client protocol 53: pre-2002.1 
// client protocol 54: client-Message 2002.1
// client protocol 55: 2002.2
// client protocol 56: 2003.2 client supports new security model
// client protocol 57: 2004.1 support for uncompressing (x)binary files 
// client protocol 58: 2005.2 client can handle new tagged commands
// client protocol 59: 2006.1 client expects submit to revert unchanged files
// client protocol 60: 2006.2 
// client protocol 61: 2007.2 client can change file type via merge
// client protocol 62: 2007.3 api gets trigger stdout
// client protocol 63: 2008.1
// client protocol 64: 2008.2
// client protocol 65: 2009.1
// client protocol 66: 2009.2
// client protocol 67: 2010.1 client daddr, dhash for MiM checking
// client protocol 68: 2010.2 
// client protocol 69: 2011.1
// client protocol 70: 2011.1 with action resolve
// client protocol 71: 2012.1 
// client protocol 72: 2012.2 
// client protocol 73: 2013.1 
// client protocol 74: 2013.2 
// client protocol 75: 2013.3 
// client protocol 76: 2014.1
// client protocol 77: 2014.2
// client protocol 78: 2015.1
// client protocol 79: 2015.2
// client protocol 80: 2016.1
// client protocol 81: 2016.2
// client protocol 82: 2017.1
// client protocol 83: 2017.2
// client protocol 84: 2018.1
// client protocol 85: 2018.2

const char P4Tag::l_client[] = "85"; // Also update knownReleases in dmtypes.cc

// see server/rhmain.cc

// server level 1: 97.1
// server level 2: 97.2
// server level 3: 97.3
// server level 4: 98.2 (early)
// server level 5: 98.2
// server level 6: 99.1 (early)
// server level 7: 99.1
// server level 8: 99.2
// server level 9: 2000.1
// server level 10: 2000.2
// server level 11: 2001.1
// server level 12: 2001.2
// server level 13: 2002.1
// server level 14: 2002.2
// server level 15: 2003.1 (early)
// server level 16: 2003.1
// server level 17: 2003.2
// server level 18: 2004.2
// server level 19: 2005.1
// server level 20: 2005.2
// server level 21: 2006.1
// server level 22: 2006.2
// server level 23: 2007.2
// server level 24: 2007.3
// server level 25: 2008.1
// server level 26: 2008.2
// server level 27: 2009.1
// server level 28: 2009.2
// server level 29: 2010.1 // server mim checking
// server level 30: 2010.2
// server level 31: 2011.1
// server level 32: 2012.1
// server level 33: 2012.2 // unload depots
// server level 34: 2013.1 // task streams
// server level 35: 2013.2 // distributed
// server level 36: 2013.3 // new btree and lockless reads
// server level 37: 2014.1 // change maps, command triggers and depot file exe
// server level 38: 2014.2
// server level 39: 2015.1
// server level 40: 2015.2
// server level 41: 2016.1
// server level 42: 2016.2
// server level 43: 2017.1
// server level 44: 2017.2
// server level 45: 2018.1
// server level 46: 2018.2

const char P4Tag::l_xfiles[] = "7"; // see clientservice.cc
const char P4Tag::l_server[] = "3"; // 97.3 GUI is stuck here!
const char P4Tag::l_server2[] = "46"; // generic server level

// proxy level 4: 2006.1	p4 print w/o -o via proxy
// proxy level 5: 2007.3	submit cacheing
// proxy level 6: 2008.1	proxy handling uncompress on client
// proxy level 7: 2010.1	intermediate service authentication & MiM check
// proxy level 8: 2012.2	proxy understands brokered 'p4 info'
// proxy level 9: 2017.2	proxy caches and delivers graph objects

// see proxy/pxservice.cc, proxy/pxclient.cc
const char P4Tag::l_proxy[] = "9"; // proxy level
