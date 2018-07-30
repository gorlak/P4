/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>

# include <error.h>
# include <errornum.h>
# include <msgsupp.h>
# include <strbuf.h>

# include "options.h"

/*
 * option.cc - command line option processing
 *
 * {o >o
 *  \<>) "Process command line options as defined in <option.h>.
 */

/*
 * Table of long-form options and their behavior. The second column in this
 * table must be unique (that is, each long-form option should only be listed
 * once), but the other columns are not unique.
 *
 * The rows in this table can be in any order, but we look them up linearly
 * so arguably the most common options should be toward the front.
 *
 * Note: Not all long-form options have corresponding single-character forms.
 *       In general, the ones that do are the ones for the single-letter flags
 *       that existed prior to the introduction of long-form options in 2014.1
 */
Options::OptionInfo Options::list[] = {
	"change",             Options::Change,       'c', ':',
	                      &MsgSupp::OptionChange,
	"port",               Options::Port,         'p', ':',
	                      &MsgSupp::OptionPort,
	"user",               Options::User,         'u', ':',
	                      &MsgSupp::OptionUser,
	"client",             Options::Client,       'c', ':',
	                      &MsgSupp::OptionClient,
	"preview",            Options::Preview,      'n', 0,
	                      &MsgSupp::OptionPreview,
	"delete",             Options::Delete,       'd', 0,
	                      &MsgSupp::OptionDelete,
	"force",              Options::Force,        'f', 0,
	                      &MsgSupp::OptionForce,
	"added",              Options::DoAdded,      'a', 0,
	                      &MsgSupp::OptionAdded,
	"input",              Options::Input,        'i', 0,
	                      &MsgSupp::OptionInput,
	"output",             Options::Output,       'o', 0,
	                      &MsgSupp::OptionOutput,
	"max",                Options::Max,          'm', '#',
	                      &MsgSupp::OptionMax,
	"quiet",              Options::Quiet,        'q', 0,
	                      &MsgSupp::OptionQuiet,
	"short",              Options::Short,        's', 0,
	                      &MsgSupp::OptionShort,
	"long",               Options::Long,         'l', 0,
	                      &MsgSupp::OptionLong,
	"all",	              Options::All,          'a', 0,
	                      &MsgSupp::OptionAll,
	"filetype",           Options::Filetype,     't', ':',
	                      &MsgSupp::OptionFiletype,
	"stream",             Options::Stream,       'S', ':',
	                      &MsgSupp::OptionStream,
	"shelf",              Options::Shelf,        's', ':',
	                      &MsgSupp::OptionShelf,
	"diff-flags",         Options::DiffFlags,    'd', ':',
	                      &MsgSupp::OptionDiffFlags,
	"tags",               Options::Tags,         'T', ':',
	                      &MsgSupp::OptionTags,
	"filter",             Options::Filter,       'F', ':',
	                      &MsgSupp::OptionFilter,
	"parent",             Options::Parent,       'P', ':',
	                      &MsgSupp::OptionParent,
	"inherited",          Options::Inherited,    'i', 0,
	                      &MsgSupp::OptionInherited,
	"shelved",            Options::Shelved,      'S', 0,
	                      &MsgSupp::OptionShelved,
	"show-time",          Options::ShowTime,     't', 0,
	                      &MsgSupp::OptionShowTime,
	"brief",              Options::Brief,        'L', 0,
	                      &MsgSupp::OptionBrief,
	"status",             Options::ChangeStatus, 's', ':',
	                      &MsgSupp::OptionChangeStatus,
	"client",             Options::ClientName,   'C', ':',
	                      &MsgSupp::OptionClientName,
	"host",               Options::Host,         'H', ':',
	                      &MsgSupp::OptionHost,
	"password",           Options::Password,     'P', ':',
	                      &MsgSupp::OptionPassword,
	"charset",            Options::Charset,      'C', ':',
	                      &MsgSupp::OptionCharset,
	"command-charset",    Options::CmdCharset,   'Q', ':',
	                      &MsgSupp::OptionCmdCharset,
	"variable",           Options::Variable,     'v', ':',
	                      &MsgSupp::OptionVariable,
	"help",               Options::Help,         'h', 0,
	                      &MsgSupp::OptionHelp,
	"version",            Options::Version,      'V', 0,
	                      &MsgSupp::OptionVersion,
	"batchsize",          Options::Batchsize,    'b', '#',
	                      &MsgSupp::OptionBatchsize,
	"blocksize",          Options::Blocksize,    'b', '#',
	                      &MsgSupp::OptionBlocksize,
	"message-type",       Options::MessageType,  's', 0,
	                      &MsgSupp::OptionMessageType,
	"xargs",              Options::Xargs,        'x', ':',
	                      &MsgSupp::OptionXargs,
	"exclusive",          Options::Exclusive,    'x', 0,
	                      &MsgSupp::OptionExclusive,
	"progress",           Options::Progress,     'I', 0,
	                      &MsgSupp::OptionProgress,
	"compress",           Options::Compress,     'z', 0,
	                      &MsgSupp::OptionCompress,
	"downgrade",          Options::Downgrade,    'd', 0,
	                      &MsgSupp::OptionDowngrade,
	"directory",          Options::Directory,    'd', ':',
	                      &MsgSupp::OptionDirectory,
	"retries",            Options::Retries,      'r', '#',
	                      &MsgSupp::OptionRetries,
	"no-ignore",          Options::NoIgnore,     'I', 0,
	                      &MsgSupp::OptionNoIgnore,
	"central-only",       Options::CentralUsers, 'c', 0,
	                      &MsgSupp::OptionCentralUsers,
	"replica-only",       Options::ReplicaUsers, 'r', 0,
	                      &MsgSupp::OptionReplicaUsers,
	"branch",             Options::Branch,       'b', ':',
	                      &MsgSupp::OptionBranch,
	"reverse",            Options::Reverse,      'r', 0,
	                      &MsgSupp::OptionReverse,
	"full-branch",        Options::FullBranch,   'r', 0,
	                      &MsgSupp::OptionFullBranch,
	"status",             Options::SpecFixStatus,'s', 0,
	                      &MsgSupp::OptionSpecFixStatus,
	"type",               Options::ChangeType,   't', ':',
	                      &MsgSupp::OptionChangeType,
	"update",             Options::ChangeUpdate, 'u', 0,
	                      &MsgSupp::OptionChangeUpdate,
	"original",           Options::Original,     'O', 0,
	                      &MsgSupp::OptionOriginal,
	"new-user",           Options::ChangeUser,   'U', 0,
	                      &MsgSupp::OptionChangeUser,
	"template",           Options::Template,     't', ':',
	                      &MsgSupp::OptionTemplate,
	"switch",             Options::Switch,       's', 0,
	                      &MsgSupp::OptionSwitch,
	"temporary",          Options::Temporary,    'x', 0,
	                      &MsgSupp::OptionTemporary,
	"owner",              Options::Owner,        'a', 0,
	                      &MsgSupp::OptionOwner,
	"administrator",      Options::Administrator,'A', 0,
	                      &MsgSupp::OptionAdministrator,
	"global",             Options::Global,       'g', 0,
	                      &MsgSupp::OptionGlobal,
	"type",               Options::StreamType,   't', ':',
	                      &MsgSupp::OptionStreamType,
	"virtual",            Options::VirtualStream,'v', 0,
	                      &MsgSupp::OptionVirtualStream,
	"client",             Options::LimitClient,  'C', 0,
	                      &MsgSupp::OptionLimitClient,
	"label",              Options::LabelName,    'l', ':',
	                      &MsgSupp::OptionLabelName,
	"summary",            Options::Summary,      's', 0,
	                      &MsgSupp::OptionSummary,
	"global",             Options::RunOnMaster,  'M', 0,
	                      &MsgSupp::OptionRunOnMaster,
	"human",              Options::Human1024,    'h', 0,
	                      &MsgSupp::OptionHuman1024,
	"human-1000",         Options::Human1000,    'H', 0,
	                      &MsgSupp::OptionHuman1000,
	"omit-lazy",          Options::OmitLazy,     'z', 0,
	                      &MsgSupp::OptionOmitLazy,
	"leave-keywords",     Options::LeaveKeywords,'k', 0,
	                      &MsgSupp::OptionLeaveKeywords,
	"file",               Options::OutputFile,   'o', ':',
	                      &MsgSupp::OptionOutputFile,
	"input-file",         Options::InputFile,    'i', ':',
	                      &MsgSupp::OptionInputFile,
	"archive",            Options::Archive,      'A', 0,
	                      &MsgSupp::OptionArchive,
	"unload",             Options::Unload,       'U', 0,
	                      &MsgSupp::OptionUnload,
	"unload-limit",       Options::UnloadLimit,  'u', 0,
	                      &MsgSupp::OptionUnloadLimit,
	"exists",             Options::Exists,       'e', 0,
	                      &MsgSupp::OptionExists,
	"content",            Options::Content,      'h', 0,
	                      &MsgSupp::OptionContent,
	"omit-promoted",      Options::OmitPromoted, 'p', 0,
	                      &MsgSupp::OptionOmitPromoted,
	"omit-moved",         Options::OmitMoved,    '1', 0,
	                      &MsgSupp::OptionOmitMoved,
	"keep-client",        Options::KeepClient,   'k', 0,
	                      &MsgSupp::OptionKeepClient,
	"file-charset",       Options::FileCharset,  'Q', ':',
	                      &MsgSupp::OptionFileCharset,
	"virtual",            Options::Virtual,      'v', 0,
	                      &MsgSupp::OptionVirtual,
	"generate",           Options::Generate,     'g', 0,
	                      &MsgSupp::OptionGenerate,
	"configure",          Options::Configure,    'c', ':',
	                      &MsgSupp::OptionConfigure,
	"usage",              Options::Usage,        'u', 0,
	                      &MsgSupp::OptionUsage,
	"job",                Options::Job,          'j', ':',
	                      &MsgSupp::OptionJob,
	"expression",         Options::Expression,   'e', ':',
	                      &MsgSupp::OptionExpression,
	"no-case-expression", Options::NoCaseExpr,   'E', ':',
	                      &MsgSupp::OptionNoCaseExpr,
	"increment",          Options::Increment,    'i', 0,
	                      &MsgSupp::OptionIncrement,
	"fix-status",         Options::FixStatus,    's', ':',
	                      &MsgSupp::OptionFixStatus,
	"replace",            Options::Replace,      'r', 0,
	                      &MsgSupp::OptionReplace,
	"shelve-options",     Options::ShelveOpts,   'a', ':',
	                      &MsgSupp::OptionShelveOpts,
	"submit-options",     Options::SubmitOpts,   'f', ':',
	                      &MsgSupp::OptionSubmitOpts,
	"shelf",              Options::SubmitShelf,  'e', ':',
	                      &MsgSupp::OptionSubmitShelf,
	"reopen",             Options::Reopen,       'r', 0,
	                      &MsgSupp::OptionReopen,
	"description",        Options::Description,  'd', ':',
	                      &MsgSupp::OptionDescription,
	"date",               Options::Date,         'd', ':',
	                      &MsgSupp::OptionDate,
	"tamper-check",       Options::Tamper,       't', 0,
	                      &MsgSupp::OptionTamper,
	"stream",             Options::StreamName,   's', ':',
	                      &MsgSupp::OptionStreamName,
	"erase",              Options::Wipe,         'w', 0,
	                      &MsgSupp::OptionWipe,
	"unchanged",          Options::Unchanged,    'a', 0,
	                      &MsgSupp::OptionUnchanged,
	"depot",              Options::Depot,        'D', ':',
	                      &MsgSupp::OptionDepot,
	"keep-head",          Options::KeepHead,     'h', 0,
	                      &MsgSupp::OptionKeepHead,
	"purge",              Options::Purge,        'p', 0,
	                      &MsgSupp::OptionPurge,
	"force-text",         Options::ForceText,    't', 0,
	                      &MsgSupp::OptionForceText,
	"binary-as-text",     Options::BinaryAsText, 't', 0,
	                      &MsgSupp::OptionBinaryAsText,
	"bypass-flow",        Options::BypassFlow,   'F', 0,
	                      &MsgSupp::OptionBypassFlow,
	"show-change",        Options::ShowChange,   'c', 0,
	                      &MsgSupp::OptionShowChange,
	"follow-branch",      Options::FollowBranch, 'i', 0,
	                      &MsgSupp::OptionFollowBranch,
	"follow-integ",       Options::FollowInteg,  'I', 0,
	                      &MsgSupp::OptionFollowInteg,
	"source-file",        Options::SourceFile,   's', ':',
	                      &MsgSupp::OptionSourceFile,
	"output-flags",       Options::OutputFlags,  'O', ':',
	                      &MsgSupp::OptionOutputFlags,
	"resolve-flags",      Options::ResolveFlags, 'A', ':',
	                      &MsgSupp::OptionResolveFlags,
	"accept-flags",       Options::AcceptFlags,  'a', ':',
	                      &MsgSupp::OptionAcceptFlags,
	"integ-flags",        Options::IntegFlags,   'R', ':',
	                      &MsgSupp::OptionIntegFlags,
	"delete-flags",       Options::DeleteFlags,  'D', ':',
	                      &MsgSupp::OptionDeleteFlags,
	"restrict-flags",     Options::RestrictFlags,'R', ':',
	                      &MsgSupp::OptionRestrictFlags,
	"sort-flags",         Options::SortFlags,    'S', ':',
	                      &MsgSupp::OptionSortFlags,
	"force-flag",         Options::ForceFlag,    'F', ':',
	                      &MsgSupp::OptionForceFlag,
	"use-list",           Options::UseList,      'L', 0,
	                      &MsgSupp::OptionUseList,
	"publish",            Options::Publish,      'p', 0,
	                      &MsgSupp::OptionPublish,
	"safe",               Options::Safe,         's', 0,
	                      &MsgSupp::OptionSafe,
	"group",              Options::IsGroup,      'g', 0,
	                      &MsgSupp::OptionIsGroup,
	"user",               Options::IsUser,       'u', 0,
	                      &MsgSupp::OptionIsUser,
	"owner",              Options::IsOwner,      'o', 0,
	                      &MsgSupp::OptionIsOwner,
	"verbose",            Options::Verbose,      'v', 0,
	                      &MsgSupp::OptionVerbose,
	"line-number",        Options::LineNumber,   'n', 0,
	                      &MsgSupp::OptionLineNumber,
	"invert-match",       Options::InvertMatch,  'v', 0,
	                      &MsgSupp::OptionInvertMatch,
	"files-with-matches", Options::FilesWithMatches,'l', 0,
	                      &MsgSupp::OptionFilesWithMatches,
	"files-without-match",Options::FilesWithoutMatch,'L', 0,
	                      &MsgSupp::OptionFilesWithoutMatch,
	"no-messages",        Options::NoMessages,   's', 0,
	                      &MsgSupp::OptionNoMessages,
	"fixed-strings",      Options::FixedStrings, 'F', 0,
	                      &MsgSupp::OptionFixedStrings,
	"basic-regexp",       Options::BasicRegexp,  'G', 0,
	                      &MsgSupp::OptionBasicRegexp,
	"extended-regexp",    Options::ExtendedRegexp,'E', 0,
	                      &MsgSupp::OptionExtendedRegexp,
	"perl-regexp",        Options::PerlRegexp,   'P', 0,
	                      &MsgSupp::OptionPerlRegexp,
	"regexp",             Options::Regexp,       'e', ':',
	                      &MsgSupp::OptionRegexp,
	"after-context",      Options::AfterContext, 'A', ':',
	                      &MsgSupp::OptionAfterContext,
	"before-context",     Options::BeforeContext,'B', ':',
	                      &MsgSupp::OptionBeforeContext,
	"context",            Options::Context,      'C', ':',
	                      &MsgSupp::OptionContext,
	"ignore-case",        Options::IgnoreCase,   'i', 0,
	                      &MsgSupp::OptionIgnoreCase,
	"journal-prefix",     Options::JournalPrefix,'J', ':',
	                      &MsgSupp::OptionJournalPrefix,
	"repeat",             Options::Repeat,       'i', '#',
	                      &MsgSupp::OptionRepeat,
	"backoff",            Options::Backoff,      'b', '#',
	                      &MsgSupp::OptionBackoff,
	"archive-data",       Options::ArchiveData,  'u', 0,
	                      &MsgSupp::OptionArchiveData,
	"status",             Options::Status,       'l', 0,
	                      &MsgSupp::OptionStatus,
	"status",             Options::LoginStatus,  's', 0,
	                      &MsgSupp::OptionLoginStatus,
	"local-journal",      Options::LocalJournal, 'L', 0,
	                      &MsgSupp::OptionLocalJournal,
	"journal-position",   Options::JournalPosition, 'j', 0,
	                      &MsgSupp::OptionJournalPosition,
	"serverid",           Options::PullServerid, 'P', ':',
	                      &MsgSupp::OptionPullServerid,
	"exclude-tables",     Options::ExcludeTables,'T', ':',
	                      &MsgSupp::OptionExcludeTables,
	"file",               Options::File,         'f', ':',
	                      &MsgSupp::OptionFile,
	"revision",           Options::Revision,     'r', ':',
	                      &MsgSupp::OptionRevision,
	"append",             Options::Append,       'a', 0,
	                      &MsgSupp::OptionAppend,
	"sequence",           Options::Sequence,     'c', ':',
	                      &MsgSupp::OptionSequence,
	"counter",            Options::Counter,      't', ':',
	                      &MsgSupp::OptionCounter,
	"host",               Options::HostName,     'h', ':',
	                      &MsgSupp::OptionHostName,
	"print",              Options::Print,        'p', 0,
	                      &MsgSupp::OptionPrint,
	"start",              Options::StartPosition,'s', '#',
	                      &MsgSupp::OptionStartPosition,
	"encoded",            Options::Encoded,      'e', 0,
	                      &MsgSupp::OptionEncoded,
	"log",                Options::LogName,      'l', ':',
	                      &MsgSupp::OptionLogName,
	"compress-ckp",       Options::CompressCkp,  'Z', 0,
	                      &MsgSupp::OptionCompressCkp,
	"spec",               Options::SpecType,     's', ':',
	                      &MsgSupp::OptionSpecType,
	"max-access",         Options::MaxAccess,    'm', 0,
	                      &MsgSupp::OptionMaxAccess,
	"group",              Options::GroupName,    'g', ':',
	                      &MsgSupp::OptionGroupName,
	"show-files",         Options::ShowFiles,    'f', 0,
	                      &MsgSupp::OptionShowFiles,
	"name",               Options::Name,         'n', ':',
	                      &MsgSupp::OptionName,
	"value",              Options::Value,        'v', ':',
	                      &MsgSupp::OptionValue,
	"propagating",        Options::Propagating,  'p', 0,
	                      &MsgSupp::OptionPropagating,
	"add",                Options::OpenAdd,      'a', 0,
	                      &MsgSupp::OptionOpenAdd,
	"edit",               Options::OpenEdit,     'e', 0,
	                      &MsgSupp::OptionOpenEdit,
	"delete",             Options::OpenDelete,   'd', 0,
	                      &MsgSupp::OptionOpenDelete,
	"modtime",            Options::UseModTime,   'm', 0,
	                      &MsgSupp::OptionUseModTime,
	"local",              Options::Local,        'l', 0,
	                      &MsgSupp::OptionLocal,
	"output-base",        Options::OutputBase,   'o', 0,
	                      &MsgSupp::OptionOutputBase,
	"system",             Options::System,       's', 0,
	                      &MsgSupp::OptionSystem,
	"service",            Options::Service,      'S', ':',
	                      &MsgSupp::OptionService,
	"histogram",          Options::Histogram,    'h', 0,
	                      &MsgSupp::OptionHistogram,
	"table-not-unlocked", Options::TableNotUnlocked,'U', 0,
	                      &MsgSupp::OptionTableNotUnlocked,
	"table",              Options::TableName,    't', ':',
	                      &MsgSupp::OptionTableName,
	"all-clients",        Options::AllClients,   'C', 0,
	                      &MsgSupp::OptionAllClients,
	"size",               Options::CheckSize,    's', 0,
	                      &MsgSupp::OptionCheckSize,
	"transfer",           Options::Transfer,     't', 0,
	                      &MsgSupp::OptionTransfer,
	"update",             Options::Update,       'u', 0,
	                      &MsgSupp::OptionUpdate,
	"verify",             Options::Verify,       'v', 0,
	                      &MsgSupp::OptionVerify,
	"no-archive",         Options::NoArchive,    'X', 0,
	                      &MsgSupp::OptionNoArchive,
	"serverid",           Options::Serverid,     's', ':',
	                      &MsgSupp::OptionServerid,
	"unified",            Options::Unified,      'u', 0,
	                      &MsgSupp::OptionUnified,
	"preview-noncontent", Options::PreviewNC,    'N', 0,
	                      &MsgSupp::OptionPreviewNC,
	"estimates",          Options::Estimates,    'N', 0,
	                      &MsgSupp::OptionEstimates,
	"locked",             Options::Locked,       'L', 0,
	                      &MsgSupp::OptionLocked,
	"unload-all",         Options::UnloadAll,    'a', ':',
	                      &MsgSupp::OptionUnloadAll,
	"keep-have",          Options::KeepHave,     'h', 0,
	                      &MsgSupp::OptionKeepHave,
	"yes",                Options::Yes,          'y', 0,
	                      &MsgSupp::OptionYes,
	"no",                 Options::No,           'n', 0,
	                      &MsgSupp::OptionNo,
	"value",              Options::InputValue,   'i', ':',
	                      &MsgSupp::OptionInputValue,
	"replacement",        Options::Replacement,  'r', 0,
	                      &MsgSupp::OptionReplacement,
	"rebuild",            Options::Rebuild,      'R', 0,
	                      &MsgSupp::OptionRebuild,
	"equal",              Options::Equal,        'e', ':',
	                      &MsgSupp::OptionEqual,
	"attribute-pattern",  Options::AttrPattern,  'A', ':',
	                      &MsgSupp::OptionAttrPattern,
	"diff-list-flag",     Options::DiffListFlag, 's', ':',
	                      &MsgSupp::OptionDiffListFlag,
	"arguments",          Options::Arguments,    'a', 0,
	                      &MsgSupp::OptionArguments,
	"environment",        Options::Environment,  'e', 0,
	                      &MsgSupp::OptionEnvironment,
	"status",             Options::TaskStatus,   's', ':',
	                      &MsgSupp::OptionTaskStatus,
	"all-users",          Options::AllUsers,     'A', 0,
	                      &MsgSupp::OptionAllUsers,
	"promote",            Options::Promote,      'p', 0,
	                      &MsgSupp::OptionPromote,
	"test",               Options::Test,         't', ':',
	                      &MsgSupp::OptionTest,
	"active",             Options::Active,       'A', 0,
	                      &MsgSupp::OptionActive,
	"groups",             Options::GroupMode,    'g', 0,
	                      &MsgSupp::OptionGroupMode,
	"users",              Options::UserMode,     'u', 0,
	                      &MsgSupp::OptionUserMode,
	"create",             Options::UserModeCreate, 'c', 0,
	                      &MsgSupp::OptionUserModeCreate,
	"create-strict",      Options::UserModeCreateStrict, 'C', 0,
	                      &MsgSupp::OptionUserModeCreate,
	"update",             Options::UserModeUpdate, 'U', 0,
	                      &MsgSupp::OptionUserModeUpdate,
	"delete",             Options::UserModeDelete, 'd', 0,
	                      &MsgSupp::OptionUserModeDelete,
	"create",             Options::Create,       'c', 0,
	                      &MsgSupp::OptionCreate,
	"list",               Options::List,         'l', 0,
	                      &MsgSupp::OptionList,
	"mainline",           Options::Mainline,     'm', 0,
	                      &MsgSupp::OptionMainline,
	"movechanges",        Options::MoveChanges,  'r', 0,
	                      &MsgSupp::OptionMoveChanges,
	"replication-status", Options::ReplicationStatus, 'J', 0,
	                      &MsgSupp::OptionReplicationStatus,
	"depot-type",         Options::DepotType,   't', ':',
	                      &MsgSupp::OptionDepotType,
	"global",             Options::GlobalLock, 'g', 0,
	                      &MsgSupp::OptionGlobalLock,
	"users",              Options::Users, 'u', 0,
	                      &MsgSupp::OptionUsers,
	"tab",                Options::Tab, 'T', '?',
	                      &MsgSupp::OptionTab,
	"force-delete",       Options::ForceDelete, 'F', 0,
	                      &MsgSupp::OptionForceDelete,
	"rename",             Options::Rename, 'r', 0,
	                      &MsgSupp::OptionRename,
	"retry",              Options::Retry, 'R', 0,
	                      &MsgSupp::OptionRetry,
	"type",               Options::StorageType,  'T', ':',
	                      &MsgSupp::OptionStorageType,
	"user",               Options::ByUser, 'u', ':',
	                      &MsgSupp::OptionByUser,
	"owner",              Options::ByOwner, 'O', ':',
	                      &MsgSupp::OptionByOwner,
	"repo",               Options::RepoName2, 'n', ':',
	                      &MsgSupp::OptionRepoName2,
	"depot",              Options::Depot2, 'd', ':',
	                      &MsgSupp::OptionDepot2,
	"reference",          Options::Reference, 'r', ':',
	                      &MsgSupp::OptionReference,
	"permission",         Options::Perm, 'p', ':',
	                      &MsgSupp::OptionPerm,

	// Options below this line have no short-form equivalent:

	"no-rejournal",       Options::NoRejournal,  0, 0,
	                      &MsgSupp::OptionNoRejournal,
	"from",               Options::From,         0, ':',
	                      &MsgSupp::OptionFrom,
	"to",                 Options::To,           0, ':',
	                      &MsgSupp::OptionTo,
	"parallel",           Options::Parallel,     0, ':',
	                      &MsgSupp::OptionParallel,
	"parallel",           Options::ParallelSubmit,     0, ':',
	                      &MsgSupp::OptionParallelSubmit,
	"pid-file",           Options::PidFile,     0, '?',
	                      &MsgSupp::OptionPidFile,
	"noretransfer",       Options::NoRetransfer, 0, '#',
	                      &MsgSupp::OptionNoRetransfer,
	"forcenoretransfer",  Options::ForceNoRetransfer, 0, 0,
	                      &MsgSupp::OptionForceNoRetransfer,
	"durable-only",       Options::DurableOnly, 0, 0,
	                      &MsgSupp::OptionDurableOnly,
	"non-acknowledging",  Options::NonAcknowledging, 0, 0,
	                      &MsgSupp::OptionNonAcknowledging,
	"bypass-exclusive-lock",
	                      Options::BypassExclusiveLock, 0, 0,
	                      &MsgSupp::OptionBypassExlusiveLock,
	"retain-lbr-revisions",  Options::RetainLbrRevisions, 0, 0,
	                      &MsgSupp::OptionRetainLbrRevisions,
	"java",               Options::JavaProtocol, 0, 0,
	                      &MsgSupp::OptionJavaProtocol,
	"batch",              Options::PullBatch, 0, '#',
	                      &MsgSupp::OptionPullBatch,
	"enable-dvcs-triggers", Options::EnableDVCSTriggers, 0, 0,
	                      &MsgSupp::OptionEnableDVCSTriggers,
	"convert-p4admin-comments",
	                      Options::ConvertAdminComments, 0, 0,
	                      &MsgSupp::OptionConvertAdminComments,
	"remote",             Options::RemoteSpec, 0, ':',
	                      &MsgSupp::OptionRemoteSpec,
	"me",                 Options::P4UserUser, 0, 0,
	                      &MsgSupp::OptionP4UserUser,
	"aliases",            Options::Aliases, 0, ':',
	                      &MsgSupp::OptionAliases,
	"field",              Options::Field, 0, ':',
	                      &MsgSupp::OptionField,
	"atomic",             Options::AtomicPush, 0, 0,
	                      &MsgSupp::OptionAtomicPush,
	"client-type",        Options::ClientType,   0, ':',
	                      &MsgSupp::OptionClientType,
	"color",              Options::Color, 0, 0,
	                      &MsgSupp::OptionColor,
	"show-files",         Options::ChangeFiles, 0, 0,
	                      &MsgSupp::OptionChangeFiles,
	"discard-archives",   Options::DiscardArchives, 0, '#',
	                      &MsgSupp::OptionDiscardArchives,
	"license-info",       Options::LicenseInfo, 0, 0,
	                      &MsgSupp::OptionLicenseInfo,
	"remote-user",        Options::RemoteUser, 0, ':',
	                      &MsgSupp::OptionRemoteUser,
	"ignore-changeview",  Options::IgnoreCMap, 0, 0,
	                      &MsgSupp::OptionIgnoreCMap,
	"mirror",             Options::Mirror, 0, 0,
	                      &MsgSupp::OptionMirror,
	"daemonsafe",	      Options::DaemonSafe,  0, 0,
	                      &MsgSupp::OptionDaemonSafe,
	"trigger",	      Options::Trigger,  0, 0,
	                      &MsgSupp::OptionTrigger,
	"ignore-have",        Options::IgnoreHave,  0, 0,
	                      &MsgSupp::OptionIgnoreHave,
	"graph-only",         Options::GraphOnly,  0, 0,
	                      &MsgSupp::OptionGraphOnly,
	"min-size",           Options::MinSize, 0, ':',
	                      &MsgSupp::OptionMinSize,
	"max-size",           Options::MaxSize, 0, ':',
	                      &MsgSupp::OptionMaxSize,
	"name-only",          Options::NameOnly, 0, 0,
	                      &MsgSupp::OptionNameOnly,
	"no-ff",              Options::NoFastForward, 0, 0,
	                      &MsgSupp::OptionNoFastForward,
	"ff-only",            Options::FastForwardOnly, 0, 0,
	                      &MsgSupp::OptionFastForwardOnly,
	"exists",             Options::MustExist, 0, 0,
	                      &MsgSupp::OptionMustExist,
	"repo",               Options::RepoName, 0, ':',
	                      &MsgSupp::OptionRepoName,
	"target",             Options::TargetBranch, 0, ':',
	                      &MsgSupp::OptionTargetBranch,
	"squash",             Options::Squash, 0, 0,
	                      &MsgSupp::OptionSquash,
	"allow-empty",        Options::AllowEmpty, 0, 0,
	                      &MsgSupp::OptionAllowEmpty,
	"create-index",       Options::CreateIndex, 0, 0,
	                      &MsgSupp::OptionCreateIndex,
	"drop-index",         Options::DropIndex, 0, 0,
	                      &MsgSupp::OptionDropIndex,
	"first-parent",       Options::FirstParent, 0, 0,
	                      &MsgSupp::OptionDropIndex,
	0, 0, 0, 0, 0
} ;

void
Options::Parse( int &argc, StrPtr *&argv, const char *opts, 
		int flag, const ErrorId &usage, Error *e )
{
	int longOpts[] = { 0 };
	ParseLong( argc, argv, opts, longOpts, flag, usage, e );
}

void
Options::ParseLong( int &argc, StrPtr *&argv, const char *opts, 
		const int *longOpts, int flag, const ErrorId &usage, Error *e )
{
	int explainMode = 0;

	for( ; argc; argc--, argv++ )
	{
	    char *arg;
	    char *av = argv->Text();

	    if( av[0] != '-' || !av[1] )
		break;

	    if( av[1] == '-' )
	    {
	        // Long-form option (--force, --change, --user, etc.)

	        const char *opt_s = &av[2];
	        const char *opt_e = opt_s;
		StrBuf optName, optMsg;

		while( *opt_e && *opt_e != '=' )
	            opt_e++;

		optName.Set( opt_s, ( opt_e - opt_s ) );
	        optMsg << "-" << optName;

	        if( !explainMode && optName == StrRef( "explain" ) )
	        {
	            explainMode = 1;
	            continue;
		}

		int i, l;
	        int matches = 0;
	        for( l = 0; longOpts[ l ]; l++ )
	        {
		    for( i = 0; list[i].name; i++ )
	            {
	                if( list[i].optionCode == longOpts[l] )
	                {
	                    matches = !strcmp( optName.Text(), list[i].name );
	                    break;
		        }
		    }
	            if( matches )
	                break;
	        }

		if( !matches )
		{
		    e->Set( MsgSupp::Invalid ) << optMsg;
		    goto usage;
		}

		if( explainMode )
		{
	            e->Set( usage );
		    e->Set( *list[i].help );
		    return;
		}

		if( optc == N_OPTS )
		{
		    e->Set( MsgSupp::TooMany );
		    return;
		}

		if( ! ( flags[ optc ] = list[i].shortForm ) )
		        flags[ optc ] = list[i].optionCode;

		flags2[ optc ] = 0;

		switch( list[i].valueType )
		{
		default:
		    if( *opt_e == '=' )
		    {
			e->Set( MsgSupp::ExtraArg );
			goto usage;
		    }
		    vals[ optc++ ] = "true";
		    continue;
		case '?':
		    if( *opt_e == '=' )
			vals[ optc++ ] = &opt_e[1];
	            else
	                vals[ optc++ ] = StrRef::Null();
	            break;
		case ':':
		case '#':
		    // : is --option=value or --option value
		    // # is --option=N or --option N, N >= 0

		    if( *opt_e == '=' )
		    {
			vals[ optc++ ] = &opt_e[1];
		    }
		    else if( --argc )
		    {
			vals[ optc++ ] = *++argv;
		    }
		    else
		    {
			e->Set( MsgSupp::NeedsArg ) << optMsg;
			goto usage;
		    }

		    if( list[i].valueType == '#' && 
	                (!vals[ optc - 1 ].IsNumeric() ||
			  vals[ optc - 1 ].Atoi64() < 0 ) )
		    {
			e->Set( MsgSupp::NeedsNonNegArg ) << optMsg;
			goto usage;
		    }
		    break;
		}
	        continue;
	    }

	    // Short-form option (-c, -p, -i, etc.)

	    for( arg = &av[1]; *arg; arg++ )
	    {
		const char *f;

		for( f = opts; *f; f++ )
		    if( *f == *arg )
			break;

		if( !*f )
		{
		    e->Set( MsgSupp::Invalid ) << arg;
		    goto usage;
		}

		if( explainMode )
		{
		    int i, l;
	            int matches = 0;
	            for( l = 0; longOpts[ l ]; l++ )
	            {
		        for( i = 0; list[i].name; i++ )
	                {
	                    if( list[i].optionCode == longOpts[l] )
	                    {
	                        if( matches = ( ( *f ) == list[i].shortForm ) )
	                            break;
		            }
		        }
	                if( matches )
	                    break;
	            }
	            e->Set( usage );
	            if( matches )
		        e->Set( *list[i].help );
	            else if( longOpts[ 0 ] )
		        e->Set( MsgSupp::Invalid ) << arg;
		    return;
		}

		if( optc == N_OPTS )
		{
		    e->Set( MsgSupp::TooMany );
		    return;
		}

		flags[ optc ] = *f;
		flags2[ optc ] = 0;

		switch( f[1] )
		{
		default:
		    // a : -a 
		    vals[ optc++ ] = "true";
		    continue;

		case '.':
		    // a. : -avalue
		    vals[ optc++ ] = &arg[1];
		    break;

		case '+':
		    // a+ : -axvalue or -ax value

		    if( !( flags2[ optc ] = *++arg ) )
		    {
			StrRef a( f, 1 );
			e->Set( MsgSupp::Needs2Arg ) << a;
			goto usage;
		    }

		    // fall thru

		case ':':
		case '#':
		    // a: : -avalue or -a value
		    // a# : -aN or -a N, N >= 0

		    if( arg[1] )
		    {
			vals[ optc++ ] = &arg[1];
		    }
		    else if( --argc )
		    {
			vals[ optc++ ] = *++argv;
		    }
		    else
		    {
			StrRef a( f, 1 );
			e->Set( MsgSupp::NeedsArg ) << a;
			goto usage;
		    }

		    if( f[1] == '#' && 
	                (!vals[ optc - 1 ].IsNumeric() ||
			  vals[ optc - 1 ].Atoi64() < 0 ) )
		    {
			StrRef a( f, 1 );
			e->Set( MsgSupp::NeedsNonNegArg ) << a;
			goto usage;
		    }
		}

		break;
	    }
	}
	if( explainMode )
	    goto usage;

	if( argc == 0 && ( flag & OPT_NONE ) )
	    return;

	if( argc == 1 && ( flag & OPT_ONE ) )
	    return;

	if( argc == 2 && ( flag & OPT_TWO ) ) 
	    return;

	if( argc == 3 && ( flag & OPT_THREE ) ) 
	    return;

	if( argc > 3 && ( flag & OPT_MORE ) )
	    return;

	if( argc == 0 && ( flag & OPT_MAKEONE ) )
	{
	    argc = 1;
	    argv = 0;
	    return;
	}

	if( flag & OPT_NONE )
	    e->Set( MsgSupp::ExtraArg );
	else
	    e->Set( MsgSupp::WrongArg );

    usage:
	e->Set( usage );

	if( explainMode )
	{
	    for( int l = 0; longOpts[ l ]; l++ )
	    {
		for( int i = 0; list[i].name; i++ )
	        {
	            if( list[i].optionCode == longOpts[l] )
	            {
	                e->Set( *list[i].help );
	                break;
	            }
	        }
	    }
	}
}

void
Options::ParseTest( int &argc, StrPtr *&argv, const char *opts, 
		const int *longOpts, Error *e )
{
	int argi = argc;
	for( ; argi; argi--, argv[argc - argi] )
	{
	    char *arg;
	    char *av = argv[argc - argi].Text();

	    if( av[0] != '-' || !av[1] )
		break;

	    if( av[1] == '-' )
	    {
	        // Long-form option (--force, --change, --user, etc.)

	        const char *opt_s = &av[2];
	        const char *opt_e = opt_s;
		StrBuf optName, optMsg;

		while( *opt_e && *opt_e != '=' )
	            opt_e++;

		optName.Set( opt_s, ( opt_e - opt_s ) );
	        optMsg << "-" << optName;

		int i, l;
	        int matches = 0;
	        for( l = 0; longOpts[ l ]; l++ )
	        {
		    for( i = 0; list[i].name; i++ )
	            {
	                if( list[i].optionCode == longOpts[l] )
	                {
	                    matches = !strcmp( optName.Text(), list[i].name );
	                    break;
		        }
		    }
	            if( matches )
	                break;
	        }

		if( !matches )
		    continue;

		if( optc == N_OPTS )
		{
		    e->Set( MsgSupp::TooMany );
		    return;
		}

		if( ! ( flags[ optc ] = list[i].shortForm ) )
		        flags[ optc ] = list[i].optionCode;

		flags2[ optc ] = 0;

		switch( list[i].valueType )
		{
		default:
		    if( *opt_e == '=' )
		    {
			e->Set( MsgSupp::ExtraArg );
			continue;
		    }
		    vals[ optc++ ] = "true";
		    continue;
		case '?':
		    if( *opt_e == '=' )
			vals[ optc++ ] = &opt_e[1];
	            else
	                vals[ optc++ ] = StrRef::Null();
	            break;
		case ':':
		case '#':
		    // : is --option=value or --option value
		    // # is --option=N or --option N, N >= 0

		    if( *opt_e == '=' )
		    {
			vals[ optc++ ] = &opt_e[1];
		    }
		    else if( --argc )
		    {
			vals[ optc++ ] = *++argv;
		    }
		    else
		    {
			e->Set( MsgSupp::NeedsArg ) << optMsg;
			continue;
		    }

		    if( list[i].valueType == '#' && 
	                (!vals[ optc - 1 ].IsNumeric() ||
			  vals[ optc - 1 ].Atoi64() < 0 ) )
		    {
			e->Set( MsgSupp::NeedsNonNegArg ) << optMsg;
			continue;
		    }
		    break;
		}
	        continue;
	    }

	    // Short-form option (-c, -p, -i, etc.)

	    for( arg = &av[1]; *arg; arg++ )
	    {
		const char *f;

		for( f = opts; *f; f++ )
		    if( *f == *arg )
			break;

		if( !*f )
		    continue;

		if( optc == N_OPTS )
		{
		    e->Set( MsgSupp::TooMany );
		    return;
		}

		flags[ optc ] = *f;
		flags2[ optc ] = 0;

		switch( f[1] )
		{
		default:
		    // a : -a 
		    vals[ optc++ ] = "true";
		    continue;

		case '.':
		    // a. : -avalue
		    vals[ optc++ ] = &arg[1];
		    break;

		case '+':
		    // a+ : -axvalue or -ax value

		    if( !( flags2[ optc ] = *++arg ) )
		    {
			StrRef a( f, 1 );
			e->Set( MsgSupp::Needs2Arg ) << a;
			continue;
		    }

		    // fall thru

		case ':':
		case '#':
		    // a: : -avalue or -a value
		    // a# : -aN or -a N, N >= 0

		    if( arg[1] )
		    {
			vals[ optc++ ] = &arg[1];
		    }
		    else if( --argc )
		    {
			vals[ optc++ ] = *++argv;
		    }
		    else
		    {
			StrRef a( f, 1 );
			e->Set( MsgSupp::NeedsArg ) << a;
			continue;
		    }

		    if( f[1] == '#' && 
	                (!vals[ optc - 1 ].IsNumeric() ||
			  vals[ optc - 1 ].Atoi64() < 0 ) )
		    {
			StrRef a( f, 1 );
			e->Set( MsgSupp::NeedsNonNegArg ) << a;
			continue;
		    }
		}

		break;
	    }
	}
}

/*
 * Options::Parse() -- version for char **argv
 */

void
Options::Parse( int &argc, char **&argv, const char *opts, 
		int flag, const ErrorId &usage, Error *e )
{
	int longOpts[] = { 0 };
	ParseLong( argc, argv, opts, longOpts, flag, usage, e );
}

void
Options::ParseLong( int &argc, char **&argv, const char *opts, 
		const int *longOpts, int flag, const ErrorId &usage, Error *e )
{
	StrRef *sargv = new StrRef[ argc ];
	StrPtr *s = sargv;

	for( int i = 0; i < argc; i++ )
	    sargv[ i ].Set( argv[i] );

	ParseLong( argc, s, opts, longOpts, flag, usage, e );

	argv += s - (StrPtr*)sargv;

	delete []sargv;
}

/*
 * Name: getoptval() - find an option given its character
 */

StrPtr *
Options::GetValue( int opt, char flag2, int subopt )
{
	int i;

	for( i = 0; i < optc; i++ )
	    if( flags[i] == opt && flags2[i] == flag2 && !subopt-- )
		return &vals[i];

	return 0;
}

int
Options::FormatOption( int i, Error *e )
{
	if( i >= 0 && i < optc )
	{
	    StrBuf f;  
	    f.Extend( (char)flags[i]  );
	    StrBuf f2;
	    if( flags2[i] )
	        f2.Extend( (char)flags2[i] );

	    e->Set( MsgSupp::OptionData ) << f << f2 << vals[i];
	    return 1;
	}
	return 0;
}

int
Options::FormatOption( int i, StrBuf &f ) const
{
	if( i >= 0 && i < optc )
	{
	    f.Extend( '-' );
	    f.Extend( (char)flags[i]  );
	    if( flags2[i] )
	        f.Extend( (char)flags2[i] );
	    f.Extend( ' ' );

	    f.Append( &vals[i] );
	    return 1;
	}
	return 0;
}

int
Options::HasOption( int i )
{
	return i >= 0 && i < optc;
}
void	
Options::GetOptionName( int i, StrBuf &sb )
{
	if( HasOption( i ) )
	{
	    sb.Clear();
	    sb.Extend( (char)flags[i]  );
	    if( flags2[i] )
	        sb.Extend( (char)flags2[i] );
	    sb.Terminate();
	}
}
void	
Options::GetOptionValue( int i, StrBuf &sb )
{
	if( HasOption( i ) )
	    sb.Set( vals[i] );
}
