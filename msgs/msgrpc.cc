/*
 * Copyright 1995, 2000 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * msgrpc.cc - definitions of errors for Rpc subsystem.
 *
 * Note:
 *
 * Never re-use an error code value,  these may have already been 
 * translated, so using it for a different error is not OK.
 *
 * ErrorIds which are no longer used should be moved to the bottom
 * of the list, with a trailing comment like this: // DEPRECATED.
 * We keep these to maintain compatibility between newer api clients
 * and older servers which send old ErrorIds.
 *
 * Its okay to add a message in the middle of the file.
 *
 * When adding a new error make sure its greater than the current high
 * value and update the following number:
 *
 * Current high value for a MsgRpc error code is: 75
 * 03/01/12 - main high value : 49,  nimble (2012.2) start at 60
 */

# include <error.h>
# include <errornum.h>
# include "msgrpc.h"

ErrorId MsgRpc::Closed                 = { ErrorOf( ES_RPC, 1, E_FAILED, EV_COMM, 0 ), "Partner exited unexpectedly." } ;
ErrorId MsgRpc::Listen                 = { ErrorOf( ES_RPC, 3, E_FAILED, EV_COMM, 1 ), "Listen %address% failed." } ;
ErrorId MsgRpc::NoPoss                 = { ErrorOf( ES_RPC, 5, E_FAILED, EV_COMM, 0 ), "Required positional parameter missing." } ;
ErrorId MsgRpc::NotP4                  = { ErrorOf( ES_RPC, 6, E_FAILED, EV_COMM, 0 ), "RpcTransport: partner is not a Perforce client/server." } ;
ErrorId MsgRpc::BadOrder               = { ErrorOf( ES_RPC, 74, E_FATAL, EV_COMM, 0 ), "Rpc: partner violated message ordering rules for %func%." } ;
ErrorId MsgRpc::Operat                 = { ErrorOf( ES_RPC, 7, E_FAILED, EV_COMM, 1 ), "Operation '%operation%' failed." } ;
ErrorId MsgRpc::Read                   = { ErrorOf( ES_RPC, 8, E_FAILED, EV_COMM, 0 ), "RpcTransport: partial message read" } ;
ErrorId MsgRpc::Select                 = { ErrorOf( ES_RPC, 61, E_FAILED, EV_COMM, 1 ), "Select call failed with error: %error%." } ;
ErrorId MsgRpc::Reconn                 = { ErrorOf( ES_RPC, 9, E_FATAL, EV_COMM, 0 ), "Can't connect an existing connection!" } ;
ErrorId MsgRpc::Stdio                  = { ErrorOf( ES_RPC, 10, E_FATAL, EV_COMM, 0 ), "Can't make outbound connection via stdio!" } ;
ErrorId MsgRpc::TcpAccept              = { ErrorOf( ES_RPC, 11, E_FAILED, EV_COMM, 0 ), "TCP connection accept failed." } ;
ErrorId MsgRpc::TcpConnect             = { ErrorOf( ES_RPC, 12, E_FAILED, EV_COMM, 1 ), "TCP connect to %host% failed." } ;
ErrorId MsgRpc::TcpHost                = { ErrorOf( ES_RPC, 13, E_FAILED, EV_COMM, 1 ), "%host%: host unknown." } ;
ErrorId MsgRpc::TcpListen              = { ErrorOf( ES_RPC, 14, E_FAILED, EV_COMM, 1 ), "TCP listen on %service% failed." } ;
ErrorId MsgRpc::TcpPortInvalid         = { ErrorOf( ES_RPC, 22, E_FAILED, EV_COMM, 1 ), "TCP port number %service% is out of range." } ;
ErrorId MsgRpc::TcpRecv                = { ErrorOf( ES_RPC, 15, E_FAILED, EV_COMM, 0 ), "TCP receive failed." } ;
ErrorId MsgRpc::TcpSend                = { ErrorOf( ES_RPC, 16, E_FAILED, EV_COMM, 0 ), "TCP send failed." } ;
ErrorId MsgRpc::TcpService             = { ErrorOf( ES_RPC, 17, E_FAILED, EV_COMM, 1 ), "%service%: service unknown." } ;
ErrorId MsgRpc::TcpPeerSsl             = { ErrorOf( ES_RPC, 31, E_FAILED, EV_COMM, 0 ), "Failed client SSL connection setup, server not using SSL." } ;
ErrorId MsgRpc::TooBig                 = { ErrorOf( ES_RPC, 18, E_FATAL, EV_COMM, 0 ), "Rpc buffer too big to send!" } ;
ErrorId MsgRpc::UnReg                  = { ErrorOf( ES_RPC, 19, E_FATAL, EV_COMM, 1 ), "Internal function '%function%' unregistered!" } ;
ErrorId MsgRpc::Unconn                 = { ErrorOf( ES_RPC, 20, E_FATAL, EV_COMM, 0 ), "Connection attempt on unopened rpc!" } ;
ErrorId MsgRpc::Break                  = { ErrorOf( ES_RPC, 21, E_FAILED, EV_COMM, 0 ), "TCP receive interrupted by client." } ;
ErrorId MsgRpc::MaxWait                = { ErrorOf( ES_RPC, 39, E_FAILED, EV_COMM, 2 ), "TCP %operation% exceeded maximum configured duration of %seconds% seconds." } ;
ErrorId MsgRpc::NameResolve            = { ErrorOf( ES_RPC, 37, E_FAILED, EV_COMM, 1 ), "%errortext%" } ;  //  unique error for name resolution failure
ErrorId MsgRpc::SslAccept              = { ErrorOf( ES_RPC, 38, E_FAILED, EV_COMM, 1 ), "SSL connection accept failed %error%.\n\tClient must add SSL protocol prefix to P4PORT." } ;
ErrorId MsgRpc::SslConnect             = { ErrorOf( ES_RPC, 23, E_FAILED, EV_COMM, 2 ), "SSL connect to %host% failed %error%.\n\tRemove SSL protocol prefix from P4PORT or fix the TLS settings." } ;
ErrorId MsgRpc::SslListen              = { ErrorOf( ES_RPC, 24, E_FAILED, EV_COMM, 1 ), "SSL listen on %service% failed." } ;
ErrorId MsgRpc::SslRecv                = { ErrorOf( ES_RPC, 25, E_FAILED, EV_COMM, 0 ), "SSL receive failed." } ;
ErrorId MsgRpc::SslSend                = { ErrorOf( ES_RPC, 26, E_FAILED, EV_COMM, 0 ), "SSL send failed." } ;
ErrorId MsgRpc::SslClose               = { ErrorOf( ES_RPC, 27, E_FAILED, EV_COMM, 0 ), "SSL close failed." } ;
ErrorId MsgRpc::SslInvalid             = { ErrorOf( ES_RPC, 28, E_FAILED, EV_COMM, 1 ), "Invalid operation for SSL on %service%." } ;
ErrorId MsgRpc::SslCtx                 = { ErrorOf( ES_RPC, 29, E_FAILED, EV_COMM, 1 ), "Fail create ctx on %service%." } ;
ErrorId MsgRpc::SslShutdown            = { ErrorOf( ES_RPC, 30, E_FAILED, EV_COMM, 0 ), "SSL read/write failed since in Shutdown." } ;
ErrorId MsgRpc::SslInit                = { ErrorOf( ES_RPC, 32, E_FATAL, EV_COMM, 0 ), "Failed to initialize SSL library." } ;
ErrorId MsgRpc::SslCleartext           = { ErrorOf( ES_RPC, 33, E_FAILED, EV_COMM, 0 ), "Failed client connect, server using SSL.\nClient must add SSL protocol prefix to P4PORT." } ;
ErrorId MsgRpc::SslCertGen             = { ErrorOf( ES_RPC, 34, E_FATAL, EV_COMM, 0 ), "Unable to generate certificate or private key for server." } ;
ErrorId MsgRpc::SslNoSsl               = { ErrorOf( ES_RPC, 35, E_FATAL, EV_COMM, 0 ), "Trying to use SSL when SSL library has not been compiled into program." } ;
ErrorId MsgRpc::SslBadKeyFile          = { ErrorOf( ES_RPC, 36, E_FATAL, EV_COMM, 0 ), "Either privatekey.txt or certificate.txt files do not exist." } ;


ErrorId MsgRpc::SslGetPubKey           = { ErrorOf( ES_RPC, 40, E_FATAL, EV_COMM, 0 ), "Unable to get public key for token generation." } ;
ErrorId MsgRpc::SslBadDir              = { ErrorOf( ES_RPC, 41, E_FATAL, EV_COMM, 0 ), "P4SSLDIR not defined or does not reference a valid directory." } ;
ErrorId MsgRpc::SslBadFsSecurity       = { ErrorOf( ES_RPC, 42, E_FATAL, EV_COMM, 0 ), "P4SSLDIR directory or key and certificate files not secure." } ;
ErrorId MsgRpc::SslDirHasCreds         = { ErrorOf( ES_RPC, 43, E_FATAL, EV_COMM, 0 ), "P4SSLDIR contains credentials, please remove key and certificate files." } ;
ErrorId MsgRpc::SslCredsBadOwner       = { ErrorOf( ES_RPC, 44, E_FATAL, EV_COMM, 0 ), "P4SSLDIR or credentials files not owned by Perforce process effective user." } ;
ErrorId MsgRpc::SslCertBadDates        = { ErrorOf( ES_RPC, 45, E_FATAL, EV_COMM, 0 ), "Certificate date range invalid." } ;
ErrorId MsgRpc::SslNoCredentials       = { ErrorOf( ES_RPC, 46, E_FATAL, EV_COMM, 0 ), "SSL credentials do not exist." } ;
ErrorId MsgRpc::SslFailGetExpire       = { ErrorOf( ES_RPC, 47, E_FAILED, EV_COMM, 0 ), "Failed to get certificate's expiration date." } ;
ErrorId MsgRpc::HostKeyUnknown         = { ErrorOf( ES_RPC, 48, E_FAILED, EV_COMM, 3 ), "The authenticity of '%host%' can't be established,\n"
	"this may be your first attempt to connect to this P4PORT.\n"
	"The fingerprint for the key sent to your client is\n"
	"%key%[\nTo allow connection use the '%cmd%' command.]" } ;
ErrorId MsgRpc::HostKeyMismatch        = { ErrorOf( ES_RPC, 49, E_FAILED, EV_COMM, 3 ), "******* WARNING P4PORT IDENTIFICATION HAS CHANGED! *******\n"
	"It is possible that someone is intercepting your connection\n"
	"to the Perforce P4PORT '%host%'\n"
	"If this is not a scheduled key change, then you should contact\n"
	"your Perforce administrator.\n"
	"The fingerprint for the mismatched key sent to your client is\n"
	"%key%[\nTo allow connection use the '%cmd%' command.]" } ;


ErrorId MsgRpc::ServiceNoTrust         = { ErrorOf( ES_RPC, 50, E_FAILED, EV_COMM, 1 ), "%server% cannot forward your request; target failed SSL/trust verification." } ;
ErrorId MsgRpc::SslLibMismatch         = { ErrorOf( ES_RPC, 51, E_FAILED, EV_COMM, 1 ), "SSL library must be at least version %sslversion%." } ;
ErrorId MsgRpc::PxRemoteSvrFail        = { ErrorOf( ES_RPC, 52, E_FAILED, EV_COMM, 0 ), "Proxy unable to communicate with remote server:" } ;
ErrorId MsgRpc::SslCfgExpire           = { ErrorOf( ES_RPC, 53, E_FAILED, EV_COMM, 1 ), "Certificate config.txt: invalid EX value \"%exValue%\", must be number > 0 and <= 24855 days." } ;
ErrorId MsgRpc::SslCfgUnits            = { ErrorOf( ES_RPC, 54, E_FAILED, EV_COMM, 0 ), "Certificate config.txt: invalid UNITS value, must be either secs, mins, hours, or days." } ;
ErrorId MsgRpc::SslKeyNotRSA           = { ErrorOf( ES_RPC, 55, E_FAILED, EV_COMM, 0 ), "Fail load key, not of type RSA." } ;
ErrorId MsgRpc::SslProtocolError       = { ErrorOf( ES_RPC, 56, E_FAILED, EV_COMM, 1 ), "SSL protocol: %errortext%" } ;

ErrorId MsgRpc::WakeupInit             = { ErrorOf( ES_RPC, 62, E_FAILED, EV_COMM, 2 ), "Fail to setup wake-up socket during %function% with error: %error%." } ;
ErrorId MsgRpc::WakeupAttempt          = { ErrorOf( ES_RPC, 63, E_FAILED, EV_COMM, 2 ), "Fail wake-up attempt in %function% with error: %error%." } ;
ErrorId MsgRpc::ZksInit                = { ErrorOf( ES_RPC, 64, E_FATAL, EV_COMM, 2 ), "Fail to setup p4zk socket during %function% with error: %error%." } ;
ErrorId MsgRpc::ZksSend                = { ErrorOf( ES_RPC, 65, E_FAILED, EV_COMM, 1 ), "Fail to send on p4zk socket with error: %error%." } ;
ErrorId MsgRpc::ZksRecv                = { ErrorOf( ES_RPC, 66, E_FAILED, EV_COMM, 1 ), "Fail to receive on p4zk socket with error: %error%." } ;
ErrorId MsgRpc::ZksDisconnect          = { ErrorOf( ES_RPC, 67, E_FATAL, EV_COMM, 0 ),  "Cluster lifeline connection to p4zk closed, must shutdown." } ;
ErrorId MsgRpc::ZksState               = { ErrorOf( ES_RPC, 68, E_FAILED, EV_COMM, 3 ), "p4zk connection state incorrect for %function%, expected %state1%, found %state2%" } ;
ErrorId MsgRpc::ZksNoZK                = { ErrorOf( ES_RPC, 73, E_FATAL, EV_COMM, 1 ), "p4zk unable to register with Zookeeper Servers: %place%." } ;
ErrorId MsgRpc::UnixDomainOpen         = { ErrorOf( ES_RPC, 69, E_FATAL, EV_COMM, 2 ), "Fail to setup Unix-domain socket during %function% with error: %error%." } ;
ErrorId MsgRpc::BadP4Port              = { ErrorOf( ES_RPC, 70, E_FATAL, EV_COMM, 1 ), "P4PORT for this server is not valid: %p4port%." } ;
ErrorId MsgRpc::NoHostnameForPort      = { ErrorOf( ES_RPC, 71, E_FATAL, EV_COMM, 0 ), "Cannot find hostname to use for P4PORT." } ;
ErrorId MsgRpc::NoConnectionToZK       = { ErrorOf( ES_RPC, 72, E_FATAL, EV_COMM, 0 ), "Cannot connect to p4zk." } ;
// ErrorId graveyard: retired/deprecated ErrorIds. 
