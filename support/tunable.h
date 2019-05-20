/*
 * Copyright 2008 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

enum P4TunableName {

	P4TUNE_CLUSTER_JOURNAL_SHARED = DT_LAST,// see db/dbjournal2.cc
	P4TUNE_DB_ISALIVE,
	P4TUNE_DB_JNLACK_SHARED,
	P4TUNE_DB_MONITOR_INTERVAL,
	P4TUNE_DB_MONITOR_SHARED,
	P4TUNE_DB_PAGE_MIGRATE,
	P4TUNE_DB_PEEKING,
	P4TUNE_DB_PEEKING_USEMAXLOCK,
	P4TUNE_DB_REORG_DISABLE,
	P4TUNE_DB_REORG_MISORDER,
	P4TUNE_DB_REORG_OCCUP,
	P4TUNE_DB_TRYLOCK,			// see dbschema.cc
	P4TUNE_DBARRAY_PUTCHECK,		// see dbarray.cc
	P4TUNE_DBARRAY_RESERVE,			// see dbarray.cc
	P4TUNE_DBJOURNAL_BUFSIZE,		// see dbjournal2.cc
	P4TUNE_DBJOURNAL_WORDSIZE,		// see dbjournal2.cc
	P4TUNE_DBOPEN_CACHE,			// see dbopen.cc
	P4TUNE_DBOPEN_CACHE_WIDE,		// see dbopen.cc
	P4TUNE_DBOPEN_FREEPCT,			// see dbopen.cc
	P4TUNE_DBOPEN_MISMATCH_DELAY,		// see bt_fio.cc
	P4TUNE_DBOPEN_NOFSYNC,			// see btree.cc
	P4TUNE_DBOPEN_PAGESIZE,			// see dbopen.cc
	P4TUNE_DBOPEN_RETRY,			// see bt_fio.cc
	P4TUNE_DIFF_BINARY_RCS,			// see dmtypes.cc
	P4TUNE_DIFF_SLIMIT1,
	P4TUNE_DIFF_SLIMIT2,
	P4TUNE_DIFF_STHRESH,
	P4TUNE_DM_ANNOTATE_MAXSIZE,
	P4TUNE_DM_BATCH_DOMAINS,		// see dmdomains.cc
	P4TUNE_DM_CHANGES_THRESH1,		// set dmchanges.cc
	P4TUNE_DM_CHANGES_THRESH2,		// set dmchanges.cc
	P4TUNE_DM_CHANGEVIEW_OPENABLE,		// see dmlimit.cc
	P4TUNE_DM_COPY_MOVEWARN,
	P4TUNE_DM_DOMAIN_ACCESSUPDATE,		// see dmadomain.cc
	P4TUNE_DM_DOMAIN_ACCESSFORCE,		// see dmadomain.cc
	P4TUNE_DM_FLUSHFORCE,
	P4TUNE_DM_FLUSHTRY,
	P4TUNE_DM_FSTAT_MAXCONTENT,		// see userfstat.cc
	P4TUNE_DM_GRAPH_ENABLED,		// see rhservice.cc
	P4TUNE_DM_GREP_MAXLINELENGTH,
	P4TUNE_DM_GREP_MAXREVS,
	P4TUNE_DM_GREP_MAXCONTEXT,
	P4TUNE_DM_INFO_HIDE,
	P4TUNE_DM_INTEG_ENGINE,
	P4TUNE_DM_INTEG_MAXACT,
	P4TUNE_DM_INTEG_TWEAKS,
	P4TUNE_DM_INTEG_UNDO,
	P4TUNE_DM_ISALIVE,			// set dmcaller.cc
	P4TUNE_DM_KEYS_HIDE,			// see dmcounters.cc
	P4TUNE_DM_MAXKEY,			// see dmtypes.cc
	P4TUNE_DM_PASSWORD_MINLENGTH,
	P4TUNE_DM_PROTECTS_ALLOW_ADMIN,
	P4TUNE_DM_PROTECTS_HIDE,
	P4TUNE_DM_PROXY_PROTECTS,
	P4TUNE_DM_QUICK_CLIENTS,
	P4TUNE_DM_QUICK_DOMAINS,
	P4TUNE_DM_QUICK_HAVE,
	P4TUNE_DM_QUICK_INTEG,
	P4TUNE_DM_QUICK_RESOLVE,
	P4TUNE_DM_QUICK_REV,
	P4TUNE_DM_QUICK_WORKING,
	P4TUNE_DM_REPO_NOAUTOCREATE,		// see dmgraph.cc
	P4TUNE_DM_RESOLVE_ATTRIB,
	P4TUNE_DM_REVCX_THRESH1,
	P4TUNE_DM_REVCX_THRESH2,
	P4TUNE_DM_ROTATELOGWITHJNL,
	P4TUNE_DM_SHELVE_ACCESSUPDATE,		// see dmachange.cc
	P4TUNE_DM_SHELVE_MAXFILES,
	P4TUNE_DM_SHELVE_MAXSIZE,
	P4TUNE_DM_SHELVE_PROMOTE,
	P4TUNE_DM_STATUS_MATCHLINES,		// see userreconcile.cc
	P4TUNE_DM_STATUS_MATCHSIZE,		// see dmreconcile.cc
	P4TUNE_DM_SUBPROTECTS_GRANT_ADMIN,
	P4TUNE_DM_USER_ACCESSUPDATE,		// see dmauser.cc
	P4TUNE_DM_USER_ACCESSFORCE,		// see dmauser.cc
	P4TUNE_DM_USER_ALLOWSELFUPDATE,		// see dmsuser.cc
	P4TUNE_DM_USER_INSECURELOGIN,		// see userlogin.cc
	P4TUNE_DM_USER_LOGINATTEMPTS,		// see dmauser.cc
	P4TUNE_DM_USER_NOAUTOCREATE,		// see dmauser.cc
	P4TUNE_DM_USER_NUMERIC,		// see dmauser.cc
	P4TUNE_DM_USER_RESETPASSWORD,		// see dmauser.cc
	P4TUNE_FILESYS_BINARYSCAN,		// see filecheck.cc
	P4TUNE_FILESYS_BUFSIZE,			// see filesys.h
	P4TUNE_FILESYS_CACHEHINT,		// see filesys.cc
	P4TUNE_FILESYS_CHECKLINKS,		// see clientservice.cc and useropen.cc
	P4TUNE_FILESYS_DETECTUNICODE,		// see filesys.cc
	P4TUNE_FILESYS_DETECTUTF8,		// see filecheck.cc
	P4TUNE_FILESYS_LOCKDELAY,		// see filetmp.ccc
	P4TUNE_FILESYS_LOCKTRY,			// see filetmp.cc
	P4TUNE_FILESYS_MAKETMP,
	P4TUNE_FILESYS_MAXMAP,			// see readfile.cc
	P4TUNE_FILESYS_MAXSYMLINK,		// see fileiosym.cc
	P4TUNE_FILESYS_MAXTMP,
	P4TUNE_FILESYS_UTF8BOM,			// see fileiouni.cc
	P4TUNE_FILESYS_EXTENDLOWMARK,
	P4TUNE_FILESYS_WINDOWS_LFN,		// see filesys.cc
	P4TUNE_FILESYS_CLIENT_NULLSYNC,		// see clientservice.cc
	P4TUNE_INDEX_DOMAIN_OWNER,              // see dmdomains.cc
	P4TUNE_LBR_AUTOCOMPRESS,		// see submit
	P4TUNE_LBR_BUFSIZE,			// see lbr.h
	P4TUNE_LBR_FABRICATE,			// see lbrservice.h
	P4TUNE_LBR_PROXY_CASE,			// see pxclient.cc
	P4TUNE_LBR_RCS_EXISTCHECK,		// see usersubmit.cc
	P4TUNE_LBR_RCS_MAXLEN,			// see lbrkeyed.cc
	P4TUNE_LBR_REPLICA_NOTRANSFER,		// see rhservice.cc
	P4TUNE_LBR_RETRY_MAX,			// see lbrstatus.cc
	P4TUNE_LBR_STAT_INTERVAL,		// see pxclient.cc and lbrstatus.cc
	P4TUNE_LBR_VERIFY_IN,			// see lbrservice.cc
	P4TUNE_LBR_VERIFY_OUT,			// see rhservice.cc
	P4TUNE_LBR_VERIFY_SCRIPT_OUT,		// see rhservice.cc
	P4TUNE_LOG_ORIGINHOST,			// see rhloggable.cc
	P4TUNE_MAP_JOINMAX1,
	P4TUNE_MAP_JOINMAX2,
	P4TUNE_MAP_MAXWILD,
	P4TUNE_NET_AUTOTUNE,
	P4TUNE_NET_BUFSIZE,			// see netbuffer.h
	P4TUNE_NET_KEEPALIVE_DISABLE,		// see nettcptransport.cc
	P4TUNE_NET_KEEPALIVE_IDLE,		// see nettcptransport.cc
	P4TUNE_NET_KEEPALIVE_INTERVAL,		// see nettcptransport.cc
	P4TUNE_NET_KEEPALIVE_COUNT,		// see nettcptransport.cc
	P4TUNE_NET_MAX_FAULT_PUB,		// see proxy/pxclient.cc
	P4TUNE_NET_MAXCLOSEWAIT,		// see nettcptransport.cc, netssltrancport.cc
	P4TUNE_NET_MAXWAIT,			// see nettcptransport.cc, netssltrancport.cc
	P4TUNE_NET_PARALLEL_MAX,		// see dmparsend.cc
	P4TUNE_NET_PARALLEL_THREADS,		// see usersync.cc
	P4TUNE_NET_PARALLEL_BATCH,		// see usersync.cc
	P4TUNE_NET_PARALLEL_BATCHSIZE,		// see usersync.cc
	P4TUNE_NET_PARALLEL_MIN,		// see usersync.cc
	P4TUNE_NET_PARALLEL_MINSIZE,		// see usersync.cc
	P4TUNE_NET_PARALLEL_SHELVE_THREADS,	// see usershelve.cc
	P4TUNE_NET_PARALLEL_SHELVE_BATCH,	// see usershelve.cc
	P4TUNE_NET_PARALLEL_SHELVE_MIN,		// see usershelve.cc
	P4TUNE_NET_PARALLEL_SUBMIT_THREADS,	// see usersubmit.cc
	P4TUNE_NET_PARALLEL_SUBMIT_BATCH,	// see usersubmit.cc
	P4TUNE_NET_PARALLEL_SUBMIT_MIN,		// see usersubmit.cc
	P4TUNE_NET_PARALLEL_SYNC_SVRTHREADS,	// see usersync.cc
	P4TUNE_NET_RCVBUFLOWMARK,		// see netbuffer.cc
	P4TUNE_NET_RCVBUFMAXSIZE,		// see netbuffer.cc
	P4TUNE_NET_RCVBUFSIZE,			// see netbuffer.h
	P4TUNE_NET_REUSEPORT,			// see nettcpendpoint.cc
	P4TUNE_NET_RFC3484,			// see nettcpendpoint.cc
	P4TUNE_NET_SENDLIMIT,			// set netbuffer.cc
	P4TUNE_NET_TCPSIZE,			// set nettcp.cc
	P4TUNE_NET_BACKLOG,			// see nettcp.cc
	P4TUNE_NET_X3_MINSIZE,			// see rmtservice.cc
	P4TUNE_PROXY_DELIVER_FIX,
	P4TUNE_PROXY_MONITOR_INTERVAL,		// see pxmonitor.cc
	P4TUNE_PROXY_MONITOR_LEVEL,		// see pxmonitor.cc
	P4TUNE_RCS_MAXINSERT,
	P4TUNE_RCS_NOFSYNC,			// see rcsvfile.cc
	P4TUNE_RPC_DURABLEWAIT,			// see rhservice.cc
	P4TUNE_RPC_HIMARK,
	P4TUNE_RPC_LOWMARK,
	P4TUNE_RPC_IPADDR_MISMATCH,		// see rhservice.cc, rpcfwd.cc
	P4TUNE_RPL_ARCHIVE_GRAPH,		// see server / rpl.cc
	P4TUNE_RPL_AWAITJNL_COUNT,		// See server / rmtservice.cc
	P4TUNE_RPL_AWAITJNL_INTERVAL,		// See server / rmtservice.cc
	P4TUNE_RPL_CHECKSUM_AUTO,
	P4TUNE_RPL_CHECKSUM_CHANGE,
	P4TUNE_RPL_CHECKSUM_TABLE,
	P4TUNE_RPL_COMPRESS,			// See server / rpl.cc
	P4TUNE_RPL_COUNTER_HOOK,		// See server / userpull.cc
	P4TUNE_RPL_JNL_BATCH_SIZE,		// See server / rpl.cc
	P4TUNE_RPL_JNLWAIT_ADJUST,		// See server / rhservice.cc
	P4TUNE_RPL_JNLWAIT_INTERVAL,		// See server / rhservice.cc
	P4TUNE_RPL_JNLWAIT_MAX,			// See server / rhservice.cc
	P4TUNE_RPL_JOURNAL_ACK,			// See server / rmtservice.cc
	P4TUNE_RPL_JOURNAL_ACK_MIN,		// See server / rmtservice.cc
	P4TUNE_RPL_JOURNALCOPY_LOCATION,	// See server / rpl.cc
	P4TUNE_RPL_LABELS_GLOBAL,		// See userlabel/userlabsync
	P4TUNE_RPL_REPLAY_USERRP,		// See server / rpl.cc
	P4TUNE_RPL_VERIFY_CACHE,		// See rhservice.cc
	P4TUNE_RUN_MOVE_ALLOW,			// see usermove.cc
	P4TUNE_RUN_OBLITERATE_ALLOW,		// see userpurge.cc
	P4TUNE_RUN_PRUNE_ALLOW,			// see userpurge.cc
	P4TUNE_RUN_UNZIP_USER_ALLOW,		// see userzip.cc
	P4TUNE_RUN_USERS_AUTHORIZE,		// see userusers.cc
	P4TUNE_SERVER_COMMANDLIMITS,		// see dmcaller.cc
	P4TUNE_SERVER_FILECHARSET,
	P4TUNE_SERVER_LOCKS_ARCHIVE,		// see userarchive.cc
	P4TUNE_SERVER_LOCKS_SYNC,		// see usersync.cc
	P4TUNE_SERVER_LOCKS_GLOBAL,		// see userlock.cc
	P4TUNE_SERVER_ALLOWFETCH,		// DVCS feature enabling
	P4TUNE_SERVER_ALLOWPUSH,		// DVCS feature enabling
	P4TUNE_SERVER_ALLOWREMOTELOCKING,	// DVCS feature enabling
	P4TUNE_SERVER_ALLOWREWRITE,		// DVCS feature enabling
	P4TUNE_SERVER_GLOBAL_CLIENT_VIEWS,	// see dmr/dmrprobe.cc
	P4TUNE_SERVER_MAXCOMMANDS,		// see rhmain.cc
	P4TUNE_SERVER_START_UNLICENSED,		// see rhmain.cc
	P4TUNE_FILETYPE_BYPASSLOCK,		// see useropen.cc
	P4TUNE_FILETYPE_MAXTEXTSIZE,		// set useropen.cc
	P4TUNE_SPEC_HASHBUCKETS,		// see rhspecmgr.cc
	P4TUNE_SPEC_CUSTOM,			// see userspec.cc
	P4TUNE_STREAMVIEW_DOTS_LOW,		// see maptable.cc
	P4TUNE_STREAMVIEW_SORT_REMAP,		// see viewgen.cc
	P4TUNE_SUBMIT_COLLISIONCHECK,		// see usersubmit.cc
	P4TUNE_SUBMIT_FORCENORETRANSFER,	// see usersubmit.cc
	P4TUNE_SUBMIT_NORETRANSFER,		// see usersubmit.cc
	P4TUNE_SUBMIT_UNLOCK_LOCKED,		// see usersubmit.cc
	// vv Smart Heap tunables must be a continuous group vv
	P4TUNE_SYS_MEMORY_POOLFREE,		// see shhandler.cc
	P4TUNE_SYS_MEMORY_PROCFREE,		// see shhandler.cc
	P4TUNE_SYS_MEMORY_POOLGROWINC,		// see shhandler.cc
	P4TUNE_SYS_MEMORY_PROCGROWINC,		// see shhandler.cc
	P4TUNE_SYS_MEMORY_SUBPOOLS,		// see shhandler.cc
	P4TUNE_SYS_MEMORY_LIMIT,		// see shhandler.cc
	P4TUNE_SYS_MEMORY_DEBUG,		// see shhandler.cc
	P4TUNE_CMD_MEMORY_POOLFREE,		// see shhandler.cc
	P4TUNE_CMD_MEMORY_PROCFREE,		// see shhandler.cc
	P4TUNE_CMD_MEMORY_LIMIT,		// see shhandler.cc
	P4TUNE_CMD_MEMORY_FLUSHPOOL,		// see shhandler.cc
	P4TUNE_CMD_MEMORY_LISTPOOLS,		// see shhandler.cc
	P4TUNE_CMD_MEMORY_CHKPT,		// see shhandler.cc
	// ^^ Smart Heap tunables must be a continuous group ^^
	P4TUNE_SYS_MEMORY_STACKSIZE,
	P4TUNE_SYS_RENAME_MAX,			// see fileiont.cc
	P4TUNE_SYS_RENAME_WAIT,			// see fileiont.cc
	P4TUNE_RPL_FORWARD_ALL,
	P4TUNE_RPL_FORWARD_LOGIN,		// see rhmain.cc
	P4TUNE_RPL_PULL_POSITION,		// see userpull.cc
	P4TUNE_RPL_PULL_RELOAD,			// see userpull.cc
	P4TUNE_SSL_SECONDARY_SUITE,             // see netssltransport.cc
	P4TUNE_SSL_CLIENT_TIMEOUT,		// see netssltransport.cc
	P4TUNE_SSL_TLS_VERSION_MIN,		// see netssltransport.cc
	P4TUNE_SSL_TLS_VERSION_MAX,		// see netssltransport.cc
	P4TUNE_TRIGGERS_IO,			// see rhtrigger.cc
	P4TUNE_ISTAT_MIMIC_ICHANGES,		// see dmistat.cc & DIOR_SPLIT
	P4TUNE_INFO_P4AUTH_USERCHECK,		// see userinfo.cc
	P4TUNE_AUTH_AUTOLOGIN,			// see rhservice.cc
	P4TUNE_RPL_SUBMIT_NOCOPY,		// see usersubmit.cc
	P4TUNE_AUTH_2FA_PERSIST,		// see login2.cc
	P4TUNE_AUTH_TICKETS_NOUNLOCKED,		// see login.cc
	P4TUNE_AUTH_SSO_ALLOW_PASSWD,		// see login.cc
	P4TUNE_AUTH_SSO_NONLDAP,		// see login.cc

	P4TUNE_LAST

}  ;
