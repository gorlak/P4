/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

#ifndef __CLIENTSERVICE__
#define __CLIENTSERVICE__

class Client;
class ClientFile;
extern const RpcDispatch clientDispatch[];

void clientBailoutFile( void *arg );
void clientOpenFile( Client *client, Error *e );
void clientWriteFile( Client *client, Error *e );
void clientCloseFile( Client *client, Error *e );
void clientDeleteFile( Client *client, Error *e );
void clientChmodFile( Client *client, Error *e );
void clientConvertFile( Client *client, Error *e );
void clientCheckFile( Client *client, Error *e );
void clientReconcileEdit( Client *client, Error *e );
void clientReconcileAdd( Client *client, Error *e );
void clientReconcileFlush( Client *client, Error *e );
void clientRenameFile( Client *client, Error *e );
void clientActionResolve( Client *client, Error *e );
void clientBailoutMerge( void *arg );
void clientOpenMerge( Client *client, Error *e );
void clientWriteMerge( Client *client, Error *e );
void clientCloseMerge( Client *client, Error *e );
void clientSendFile( Client *client, Error *e );
void clientEditData( Client *client, Error *e );
void clientInputData( Client *client, Error *e );
void clientErrorPause( Client *client, Error *e );
void clientOutputError( Client *client, Error *e );
void clientOutputInfo( Client *client, Error *e );
void clientOutputText( Client *client, Error *e );
void clientFstatInfo( Client *client, Error *e );
void clientAck( Client *client, Error *e );
void clientCheckCharSet( Client *client, Error *e );

void clientReconcileEdit( Client *client, Error *e );
void clientReconcileAdd( Client *client, Error *e );
void clientReconcileFlush( Client *client, Error *e );
void clientExactMatch( Client *client, Error *e );
void clientOpenMatch( Client *client, ClientFile *f, Error *e );
void clientCloseMatch( Client *client, ClientFile *f, Error *e );
void clientAckMatch( Client *client, Error *e );

enum XDir { FromServer, FromClient };

class ClientSvc
{
    public:
	static FileSys *File( Client *client, Error *e );
	static FileSys *FileFromPath( Client *client, const char *vName, 
			              Error *e );

	static CharSetCvt *XCharset( Client *client, XDir d );
};

/*
 * ClientFile - handle client interaction with files
 */

class ClientFile : public LastChance {

    public:
			ClientFile( FileSys *fs = 0 );
			~ClientFile();

    public:

	FileSys		*file;
	FileSys		*indirectFile;

	int		isDiff;

	StrBuf		diffName;
	StrBuf		diffFlags;

	StrBuf		serverDigest;
	MD5		*checksum;

	StrBufDict	*matchDict;
} ;

#endif // __CLIENTSERVICE__
