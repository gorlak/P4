/*
 * Copyright 1995, 1997 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

/*
 * enviro.cc - get/set environment variables/registry entries
 *
 * This code does a bit of extra work on NT to deal with the
 * the registry: it lets the environment take precedence, but
 * still looks for variables in two places in the registry:
 * in the machine area and in the user area.  If the user sets
 * a registry variable that is masked by an environment var,
 * a warning is sputtered out.
 *
 * This code attempts to cache registry values to avoid having
 * to ask too many times and because the RegQueryValueEx call requires
 * the caller's storage.  Whenever a variable is set, the cache
 * is updated.
 *
 * Unfortunately, this code lists the variables it deals with.
 */

# include <stdhdrs.h>
# include <strbuf.h>
# include <strops.h>
# include <error.h>
# include <errornum.h>
# include <msgsupp.h>
# include <vararray.h>
# include <strarray.h>
# include <pathsys.h>
# include <filesys.h>
# include <i18napi.h>
# include <charcvt.h>
# include <debug.h>
# include <tunable.h>
# include "enviro.h"

// The global definition

Enviro enviro;

const char p4passwd[] = "P4PASSWD";
const char p4enviro[] = "P4ENVIRO";

// Cheesy -- known env vars
// Keep alpha sort.
// Keep in sync with HelpEnvironment in msgs/msghelp.cc

const static char *const envVars[] = {
	"P4ALIASES",
	"P4AUDIT",
	"P4AUTH",
	"P4BROKEROPTIONS",
	"P4CHANGE",
	"P4CHARSET",
	"P4CLIENT",
	"P4CLIENTPATH",
	"P4COLORS",
	"P4COMMANDCHARSET",
	"P4CONFIG",
	"P4DEBUG",
	"P4DESCRIPTION",
	"P4DIFF",
	"P4DIFFUNICODE",
	"P4EDITOR",
	p4enviro,
	"P4FTPCHANGE",
	"P4FTPDEBUG",
	"P4FTPLOG",
	"P4FTPOPTIONS",
	"P4FTPPORT",
	"P4FTPPREFIX",
	"P4FTPSYSLOG",
	"P4FTPTEMPLATE",
	"P4HOST",
	"P4IGNORE",
	"P4INITROOT",
	"P4JOURNAL",
	"P4LANGUAGE",
	"P4LOG",
	"P4LOGINSSO",
	"P4MERGE",
	"P4MERGEUNICODE",
	"P4NAME",
	"P4PAGER",
	p4passwd,
	"P4PCACHE",
	"P4PFSIZE",
	"P4POPTIONS",
	"P4PORT",
	"P4ROOT",
	"P4SSLDIR",
	"P4TARGET",
	"P4TICKETS",
	"P4TRUST",
	"P4USER",
	"P4WEBPORT",
	"P4WEBSERVICEFLAGS",
	"P4WEBVIEWER",
	"P4ZEROSYNC",
	0
};

struct EnviroItem {
	StrBuf	var;
	StrBuf	value;
	Enviro::ItemType type;
	StrBuf	origin;
	int	checked;
} ;

/*
 * EnviroTable -- cached variable settings
 */

class EnviroTable : public VarArray {

    public:
			~EnviroTable();

	EnviroItem	*GetItem( const StrRef &var );
	EnviroItem	*PutItem( const StrRef &var );
	void		RemoveType( Enviro::ItemType ty );
} ;

const StrPtr *Enviro::sServiceNameStrP = NULL;

const char *
Enviro::ServiceName()
{
	return serviceName.Length()? serviceName.Text() : 0;
}

const StrPtr *Enviro::GetCachedServerName()
{
	return sServiceNameStrP;
}

/*
 * Enviro on NT
 */

# ifdef OS_NT

# define WIN32_LEAN_AND_MEAN
# include <windows.h>

struct KeyPair {
	HKEY	hkey;
	char	*key;
} ;

KeyPair userKey = { HKEY_CURRENT_USER, "software\\perforce\\environment" };
KeyPair serverKey = { HKEY_LOCAL_MACHINE, "software\\perforce\\environment" };

void	GetRegKey( void *h, const KeyPair *keyPair, Error *e );
int 	GetRegValue( const char *key, StrBuf *valBuf, const KeyPair *keyPair );
int 	GetRegValueW( const char *key, StrBuf *valBuf, const KeyPair *keyPair );
static bool GetEnv(const char* var, EnviroItem* item = 0);
static bool GetEnvW(const char* var, EnviroItem* item = 0);

Enviro::Enviro()
{
	symbolTab = 0;
	setKey = &userKey;
	serviceKey = 0;
	charset = 0;
	configFiles = new StrArray;
}

Enviro::~Enviro()
{
	delete symbolTab;
	delete serviceKey;
	delete configFiles;
}

int
Enviro::BeServer( const StrPtr *name, int checkName )
{
	if( name )
	{
	    // cache service name for NetSslCredentials constructor
	    sServiceNameStrP = name;

	    // Variables under service 'name'
	    serviceName.Set( *name );
	    serviceKeyName.Clear();
	    serviceKeyName << "SYSTEM\\CurrentControlSet\\Services\\"
			   << *name
			   << "\\Parameters";

	    delete serviceKey;
	    serviceKey = new KeyPair;
	    serviceKey->hkey = HKEY_LOCAL_MACHINE;
	    serviceKey->key = serviceKeyName.Value();

	    setKey = serviceKey;

	    if( checkName )
	    {
		HKEY svcKey;
	        int serviceKeyExists = RegOpenKeyEx(
		        serviceKey->hkey, 
		        serviceKey->key,
		        0,
# ifdef OS_NTX64
		        KEY_READ|KEY_WRITE|KEY_WOW64_32KEY,
# else /* OS_NTX64 */
		        KEY_READ|KEY_WRITE,
# endif /* OS_NTX64 */
	                &svcKey ) == ERROR_SUCCESS;

	        if( serviceKeyExists )
	            RegCloseKey( svcKey );
	        else
	            return 0;
	    }
	}
	else
	{
	    // Server variables

	    serviceName.Clear();
	    setKey = &serverKey;
	}
	return 1;
}

void
Enviro::OsServer()
{
	delete serviceKey;
	serviceKey = new KeyPair;
	serviceKey->hkey = HKEY_LOCAL_MACHINE;
	serviceKey->key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
}

bool
Enviro::ReadItemPlatform( ItemType type, const char *var, EnviroItem * a )
{
	bool isUnicode = CharSetApi::isUnicode( (CharSetApi::CharSet)charset );

	switch ( type )
	{
	    case SVC:
	        if( serviceKey )
	        {
	            // from service-specific area of the registry

	            if( isUnicode &&
	                GetRegValueW( var, &a->value, serviceKey ) ||
	                GetRegValue( var, &a->value, serviceKey ) )
	            {
	                a->type = SVC;
	                return true;
	            }
	        }
	    break;
        
	    case ENV:
	        if( isUnicode && GetEnvW( var, a ) || GetEnv( var, a ) )
	            return true;
	    break;

	    // from user area of the registry

	    case USER:
	        if( isUnicode &&
	            GetRegValueW( var, &a->value, &userKey ) ||
	            GetRegValue( var, &a->value, &userKey ) )
	        {
	            a->type = USER;
	            return true;
	        }
	    break;

	    // from machine area of the registry

	    case SYS:
                /*
                 * Only Admin can write a shared registry key,
                 * but GetRegValue() and GetRegValueW() try
                 * to create a read/write key, and so will
                 * normally fail.
                 *
                 * The only shared registry keys that we currently
                 * fetch (and don't write) are "CurrentVersion"
                 * and "CSDVersion" (see rhmain.cc), so we
                 * special-case them and use GetVersionEx() instead.
                 */
                if( !strcmp(var, "CurrentVersion") )
                {
                    OSVERSIONINFOEX     info;

                    memset( &info, '\0', sizeof info );
                    info.dwOSVersionInfoSize = sizeof info;
                    if( GetVersionEx( reinterpret_cast<OSVERSIONINFO *>(&info) ) )
                    {
                        a->value.Clear();
                        a->value << info.dwMajorVersion << "." << info.dwMinorVersion;
                        a->type = SYS;
                        return true;
                    }
                    return false;
                }
                else if( !strcmp(var, "CSDVersion") )
                {
                    OSVERSIONINFOEX     info;

                    memset( &info, '\0', sizeof info );
                    info.dwOSVersionInfoSize = sizeof info;
                    if( GetVersionEx( reinterpret_cast<OSVERSIONINFO *>(&info) ) )
                    {
                        a->value.Set( info.szCSDVersion) ;
                        a->type = SYS;
                        return true;
                    }
                    return false;
                }

                // not one of our special lookups, so go get it from the registry
	        if( isUnicode &&
	            GetRegValueW( var, &a->value, &serverKey ) ||
	            GetRegValue( var, &a->value, &serverKey ) )
	        {
	            a->type = SYS;
	            return true;
	        }
	    break;

	    default:
	        // Fall through to the failure at the end of the method
	    break;
	}

	a->type = UNSET;
	return false;
}

void
Enviro::Set( const char *var, const char *value, Error *e )
{
	// Make sure symbol tab is there

	Setup();

	// Do not set p4passwd in enviro file
	if( var && stricmp( var, p4passwd ) && !SetEnviro( var, value, e ) )
	    return;

	// Get from registry

	HKEY	hKeyEnv;

	GetRegKey( &hKeyEnv, setKey, e );

	if( e->Test() )
	    return;

	if( value && *value )
	{
	    if( CharSetApi::isUnicode( (CharSetApi::CharSet)charset ) )
	    {
		CharSetCvtUTF816 cvtvar, cvtval;

		WCHAR *val = (WCHAR *)cvtval.FastCvt( value, strlen( value ) );

		if( !val || RegSetValueExW( 
		    hKeyEnv, 
		    (WCHAR *)cvtvar.FastCvt( var, strlen( var ) ),
		    0, 
		    REG_SZ, 
		    (LPBYTE)val,
		    sizeof(WCHAR)*( wcslen( val ) + 1 ) ) != ERROR_SUCCESS )
		{
		    e->Sys( "registry", "set key" );
		}
	    }
	    else
	    {
		if( RegSetValueExA( 
		    hKeyEnv, 
		    var, 
		    0, 
		    REG_SZ, 
		    (LPBYTE)value,
		    strlen( value ) + 1 ) != ERROR_SUCCESS )
		{
		    e->Sys( "registry", "set key" );
		}
	    }
	}
	else
	{
	    if( RegDeleteValue( hKeyEnv, var ) < ERROR_SUCCESS )
	    {
		e->Sys( "registry", "delete key" );
	    }
	}

	RegCloseKey( hKeyEnv );

	// warn the user if the env variable is also set.

	if( value && 
		( CharSetApi::isUnicode( (CharSetApi::CharSet)charset )
		    && GetEnvW( var ) || GetEnv( var ) ) )
	    e->Set( MsgSupp::HidesVar ) << var;

	// Make symbol undefined, so next Get resets it

	EnviroItem *a = symbolTab->GetItem( StrRef( (char *)var ) );

	if( a  && a->type >= USER)
	    a->type = NEW;

	if( !StrBuf::SCompare( var[0], 'P' ) && var[1] == '4' && !IsKnown( var ) )
	    e->Set( MsgSupp::NoSuchVariable ) << var;
}

/*
 * GetRegKey -- Get the NT-specific handle for the registry key.
 */

void
GetRegKey( void *hKeyEnv, const KeyPair *keyPair, Error *e )
{
	DWORD	disp;
	long 	stat;

	if( RegCreateKeyEx(
		keyPair->hkey, 
		keyPair->key,
		0,
		NULL, 
		REG_OPTION_NON_VOLATILE,
# ifdef OS_NTX64
		KEY_READ|KEY_WRITE|KEY_WOW64_32KEY,
# else /* OS_NTX64 */
		KEY_READ|KEY_WRITE,
# endif /* OS_NTX64 */
		NULL,
		(HKEY *)hKeyEnv,
		&disp ) != ERROR_SUCCESS )
	{
	    e->Sys( "registry", "create key" );
	}
}

/*
 * GetRegValue() - get a value from the registry. using MultiByte API
 */

int
GetRegValue( const char *var, StrBuf *valBuf, const KeyPair *keyPair )
{
	HKEY	hKeyEnv;
	Error e;
	long stat;
	DWORD type;
	DWORD length = 0;

	GetRegKey( &hKeyEnv, keyPair, &e );

	if( e.Test() )
	    return 0;

	// once to get the length

	stat = RegQueryValueExA(
		hKeyEnv,
		var,
		0,
		&type, 
		0,
		&length );


	if( stat && stat != ERROR_MORE_DATA )
	{
		RegCloseKey( hKeyEnv );
		return 0;
	}

	// once to get the data

	valBuf->Clear();

	stat = RegQueryValueExA(
		hKeyEnv,
		var,
		0,
		&type, 
		(LPBYTE)(valBuf->Alloc( length )),
		&length );

	RegCloseKey( hKeyEnv );

	return 1;
}

/*
 * GetRegValueW() - get a value from the registry, using Unicode API
 */

int
GetRegValueW( const char *var, StrBuf *valBuf, const KeyPair *keyPair )
{
	HKEY	hKeyEnv;
	Error e;
	long stat;
	DWORD type;
	DWORD length = 0;

	GetRegKey( &hKeyEnv, keyPair, &e );

	if( e.Test() )
	    return 0;

	CharSetCvtUTF816 cvtvar;

	WCHAR *wvar = (WCHAR *)cvtvar.FastCvt( var, strlen( var ) );

	// once to get the length, in bytes

	stat = RegQueryValueExW(
		hKeyEnv,
		wvar,
		0,
		&type, 
		0,
		&length );


	if( stat && stat != ERROR_MORE_DATA )
	{
		RegCloseKey( hKeyEnv );
		return 0;
	}

	// allocate enough space for the value; note that length may
	// not represent an integral number of WCHARs

	WCHAR *val = new WCHAR[(length + 1)/sizeof(WCHAR)];

	// once to get the data

	stat = RegQueryValueExW(
		hKeyEnv,
		wvar,
		0,
		&type, 
		(LPBYTE)val,
		&length );

	// adjust length, since RegQueryValueExW sometimes gifts us with
	// an extra byte of garbage following the terminating null.

	length = sizeof(WCHAR)*(wcslen(val) + 1);

	CharSetCvtUTF168 cvtval;
	int retlen;
	const char *retval = cvtval.FastCvt( (const char *)val, length, &retlen );

	delete [] val;

	RegCloseKey( hKeyEnv );

	if( !retval )
	    return 0;

	valBuf->Set( retval, retlen );

	return 1;
}

/*
 * GetEnv() - get a value from the environment, using MultiByte API
 */

static bool
GetEnv( const char * var, EnviroItem * item )
{
	StrBuf result;
	int len = GetEnvironmentVariableA( var, result.Alloc( 80 ), 80 );
	if( len == 0 && GetLastError() == ERROR_ENVVAR_NOT_FOUND )
	    return false;

	if ( !item )
	    return true;

	if ( len > 80 )
	{
	    // refetch with longer length

	    item->value.Clear();
	    len = GetEnvironmentVariableA( var, item->value.Alloc( len ), len );
	    item->value.SetLength( len );
	}
	else
	{
	    result.SetLength( len );
	    item->value.Set( result );
	}
	item->type = Enviro::ENV;
	return true;
}

/*
 * GetEnvW() - get a value from the environment, using Unicode API
 */

static bool
GetEnvW( const char * var, EnviroItem * item )
{
	CharSetCvtUTF816 cvtvar;
	WCHAR *wvar = (WCHAR *)cvtvar.FastCvt( var, strlen( var ) );

	StrBuf result;
	int len = GetEnvironmentVariableW( wvar, (wchar_t *)result.Alloc( 160 ), 80 );
	if( len == 0 && GetLastError() == ERROR_ENVVAR_NOT_FOUND )
	    return false;

	if( !item )
	    return true;

	if( len > 80 )
	{
	    // refetch with longer length

	    result.Clear();
	    len = GetEnvironmentVariableW( wvar, (wchar_t *)result.Alloc( len * 2 ), len );
	}
	result.SetLength( 2 * len );

	CharSetCvtUTF168 cvtval;
	const char *retval = cvtval.FastCvt( result.Text(), result.Length() );
	if ( !retval )
	    return false;
	item->value.Set( retval );
	item->type = Enviro::ENV;
	return true;
}

void
Enviro::SetCharSet( int i )
{
	charset = i;
	Reload();
}

int
Enviro::GetCharSet()
{
	return charset;
}

# else

/*
 * Enviro on UNIX, etc
 */

Enviro::Enviro()
{
	symbolTab = 0;
	configFiles = new StrArray;
}

Enviro::~Enviro()
{
	delete symbolTab;
	delete configFiles;
}

int
Enviro::BeServer( const StrPtr *name, int checkName )
{
	sServiceNameStrP = name;
	return 1;
}

void
Enviro::OsServer()
{
}

void
Enviro::Set( const char *var, const char *value, Error *e )
{
	if ( !var || !strcasecmp( var, p4passwd ) )
	    return;

	if( SetEnviro( var, value, e ) )
	    e->Set( MsgSupp::NoUnixReg );
}

bool
Enviro::ReadItemPlatform( ItemType type, const char *var, EnviroItem * a )
{
	if ( type != ENV )
	    return false;

	char *c = NULL;
	if( c = getenv( var ) )
	{
	    a->value.Set( c );
	    a->type = ENV;
	    return true;
	}
	
	return false;
}

void
Enviro::SetCharSet( int i )
{
	// nothing - only important for win32 - so far...
}

int
Enviro::GetCharSet()
{
	// nothing - only important for win32 - so far...
	return 0;
}

# endif


/*
 * Platform independent
 */

EnviroTable::~EnviroTable()
{
	for( int i = 0; i < Count(); i++ )
	    delete (EnviroItem *)Get(i);
}

void
Enviro::Reload()
{
	delete symbolTab;
	symbolTab = 0;
}

EnviroItem *
EnviroTable::GetItem( const StrRef &var )
{
	EnviroItem *a;

	for( int i = 0; i < Count(); i++ )
	{
	    a = (EnviroItem *)Get(i);

	    if( !a->var.SCompare( var ) )
		return a;
	}

	return 0;
}

EnviroItem *
EnviroTable::PutItem( const StrRef &var )
{
	EnviroItem *a = GetItem( var );

	if( !a )
	{
	    a = new EnviroItem;
	    a->type = Enviro::NEW;
	    a->var.Set( var );
	    a->value.Clear();
	    a->origin.Clear();
	    a->checked = 0;
	    VarArray::Put( a );
	}

	return a;
}

void
EnviroTable::RemoveType( Enviro::ItemType ty )
{
	EnviroItem *a;

	for( int i = Count(); i > 0 ; )
	{
	    a = (EnviroItem *)Get( --i );

	    if( a->type < ty )
	        continue;

	    delete a;
	    VarArray::Remove( i );
	}
}

void
Enviro::List( int quiet )
{
	const char *const *i;

	for( i = envVars; *i; i++ )
	    Print( *i, quiet );
}

int
Enviro::FormatVariable( int i, StrBuf *sb )
{
	if( i >= 0 && i < (sizeof(envVars)/sizeof(envVars[0])) && envVars[i] )
	{
	    Format( envVars[i], sb );
	    return 1;
	}
	return 0;
}

int	
Enviro::IsKnown( const char *nm )
{
	StrRef name( nm );
	const char *const *i;

	for( i = envVars; *i; i++ )
	    if( !name.SCompare( StrRef( *i ) ) )
	        return 1;
	if( !strncmp( name.Text(), "P4_", 3 ) &&
		name.EndsWith( "_CHARSET", 8 ) )
	    return 1;
	return 0;
}

int	
Enviro::HasVariable( int i )
{
	return i >= 0 && i < (sizeof(envVars)/sizeof(envVars[0])) && envVars[i];
}
void	
Enviro::GetVarName( int i, StrBuf &sb )
{
	if( HasVariable( i ) )
	{
	    EnviroItem *a = GetItem( envVars[i] );
	    sb.Set( a->var );
	}
}

void	
Enviro::GetVarValue( int i, StrBuf &sb )
{
	if( HasVariable( i ) )
	{
	    EnviroItem *a = GetItem( envVars[i] );
	    sb.Set( a->value );
	}
}

char *
Enviro::Get( const char *var )
{
	EnviroItem *a = GetItem( var );

	return a->value.Length() ? a->value.Text() : 0;
}

EnviroItem *
Enviro::GetItem( const char *var )
{
	// Make sure symbol tab is there

	Setup();

	// attempt to return cached value
	// null string means unset

	EnviroItem *a = symbolTab->PutItem( StrRef( (char *)var ) );

	if( ( a->type != ENVIRO && a->type != NEW ) ||
	    ( a->type == ENVIRO && a->checked ) ||
	    ( a->type != ENVIRO && ReadItemPlatform( SVC, var, a ) ) ||
	    ( a->type != ENVIRO && ReadItemPlatform( ENV, var, a ) ) ||
	    a->type == ENVIRO ||
	    ReadItemPlatform( USER, var, a ) ||
	    ReadItemPlatform( SYS, var, a ) )
	{
	    a->checked = 1;

	    // If we're resolving home, don't recurse

	    if( !strcmp( var, "HOME" ) || !strcmp( var, "USERPROFILE" ) )
	        return a;

	    StrRef homedir( "$home" );
	    if( a->value.Contains( homedir ) )
	    {
	        // If value contains $home then use real home dir

	        StrBuf t, h;
	        GetHome( h );

	        StrOps::Replace( t, a->value, homedir, h );

	        // We cache the new value so we don't have to do this again

	        a->value.Set( t );
	    }

	    return a;
	}

	a->type = UNSET;

	return a;
}

Enviro::ItemType
Enviro::GetType( const char *var )
{
	EnviroItem *a = GetItem( var );

	return a->type;
}

int
Enviro::FromRegistry( const char *var )
{
	EnviroItem *a = GetItem( var );

	return( a->type == SVC || a->type == USER || a->type == SYS );
}

void
Enviro::Update( const char *var, const char *value )
{
	EnviroItem *a = GetItem( var );

	a->type = UPDATE;
	a->value.Set( value );
}	

void
Enviro::Print( const char *var, int quiet )
{
	StrBuf buf;
	Format( var, &buf, quiet );
	if( buf.Length() )
	    printf( "%s\n", buf.Text() );
}

void
Enviro::Format( const char *var, StrBuf *sb, int quiet )
{
	EnviroItem *a = GetItem( var );
	sb->Clear();

	int isSet = 1;

	switch( a->type )
	{
	case ENV:
		*sb << a->var.Text() << "=" << a->value.Text();
		break;
	case CONFIG:
		*sb << a->var.Text() << "=" << a->value.Text();
		if( !quiet )
		    *sb << " (config '" << a->origin.Text() << "')";
		break;
	case ENVIRO:
		*sb << a->var.Text() << "=" << a->value.Text();
		if( !quiet )
		    *sb << " (enviro)";
		break;
	case SVC:
		*sb << a->var.Text() << "=" << a->value.Text();
		if( !quiet )
		    *sb << " (set -S)";
		break;
	case USER:
		*sb << a->var.Text() << "=" << a->value.Text();
		if( !quiet )
		    *sb << " (set)";
		break;
	case SYS:
		*sb << a->var.Text() << "=" << a->value.Text();
		if( !quiet )
		    *sb << " (set -s)";
		break;
	default:
		isSet = 0;
		break;
	}

	if( isSet && !quiet && a->var == "P4CONFIG" )
	{
	    if( !configFiles->Count() )
		*sb << " (config '" << GetConfig() << "')";
	    else
	    {
		const StrBuf *buf;
		*sb << " (config '";
		for( int i = 0; ( buf = configFiles->Get( i ) ); i++ )
		    *sb << ( i ? "', '" : "" ) << buf;
		*sb << "' )";
	    }
	}
}

void
Enviro::ReadConfig( FileSys *f, Error *e, int checkSyntax, Enviro::ItemType ty )
{
	StrBuf line, var;

	while( f->ReadLine( &line, e ) )
	{
	    line.TruncateBlanks();

	    char *equals = strchr( line.Text(), '=' );
	    if( !equals ) continue;

	    // tunable ?

	    p4debug.SetLevel( line.Text() );

	    // Just variable name

	    var.Set( line.Text(), equals - line.Text() );

	    if( checkSyntax &&
	            var.Text()[0] != '#' && !IsKnown( var.Text() ) &&
	            !p4tunable.IsKnown( var.Text() ) )
	    {
		StrBuf errBuf;
		e->Set( MsgSupp::NoSuchVariable ) << var;
		e->Fmt( &errBuf );
		p4debug.printf( "%s", errBuf.Text() );
		e->Clear();
	    }

	    // Set as config'ed

	    EnviroItem *a = GetItem( var.Text() );
	    if( a->type <  ty ) continue;
	    if( a->type == ty && a->origin.Length() ) continue;

	    StrRef cnfdir( "$configdir" );
	    if( configFile.Length() && line.Contains( cnfdir ) )
	    {
		// if value is $configdir then use real config dir
		PathSys *p = PathSys::Create();

		p->Set( configFile );
		p->ToParent();

		StrBuf t;

		StrOps::Replace( t, StrRef( equals+1 ), cnfdir, *p );

		a->value.Set( t );

		delete p;
	    }
	    else
		a->value.Set( equals + 1 );

	    a->type = ty;
	    a->origin.Set( f->Path() );
	    a->checked = 0;
	}
}

void
Enviro::Setup()
{
	if( !symbolTab )
	{
	    symbolTab = new EnviroTable;

	    LoadEnviro( 0 );
	}
}

void
Enviro::Config( const StrPtr &cwd )
{
	LoadConfig( cwd, 0 );
}

void
Enviro::LoadConfig( const StrPtr &cwd, int checkSyntax )
{
	// We don't care about errors

	Error e;

	// Only load P4CONFIG file if it is set.

	StrBuf setFile;
	char *s;
	if( ( s = Get( "P4CONFIG" ) ) )
	    setFile.Set( s );
	else
	    return;

	// Make sure symbol tab is there

	Setup();

	// If we're reloading after changing directory, we need to drop any
	// settings from previously loaded P4CONFIG files.

	symbolTab->RemoveType( CONFIG );
	LoadEnviro( 0 );
	configFile.Clear();
	configFiles->Clear();

	// client up the directory tree, looking for setFile

	PathSys *p = PathSys::Create();
	PathSys *q = PathSys::Create();
	FileSys *f = FileSys::Create( FileSysType( FST_TEXT|FST_L_CRLF ) );

# if defined(OS_NT)
	if( charset )
	{
	    p->SetCharSet( charset );
	    q->SetCharSet( charset );
	    f->SetCharSetPriv( charset );
	}
# endif

	// Start with current dir

	p->Set( cwd );

	do {
	    // Can we find the file?

	    e.Clear();
	    q->SetLocal( *p, setFile );
	    f->Set( *q );
	    f->Open( FOM_READ, &e );

	    if( e.Test() )
		continue;

	    // Save the name of the config file
	    
	    configFile.Set( f->Name() );
	    configFiles->Put()->Set( f->Name() );

	    // Slurp contents into client name

	    ReadConfig( f, &e, checkSyntax, CONFIG );

	    f->Close( &e );
	}
	while( p->ToParent() );

	// free & clear

	delete f;
	delete q;
	delete p;
}

void
Enviro::LoadEnviro( int checkSyntax )
{
	Error e;

	const StrPtr *envFile = GetEnviroFile();

	if( !envFile )
	    return;

	// client up the directory tree, looking for setFile

	FileSys *f = FileSys::Create( FileSysType( FST_TEXT|FST_L_CRLF ) );

# if defined(OS_NT)
	if( charset )
	    f->SetCharSetPriv( charset );
# endif

	// Can we find the file?

	e.Clear();
	f->Set( *envFile );
	f->Open( FOM_READ, &e );

	if( !e.Test() )
	{
	    // Slurp contents into symbol table

	    ReadConfig( f, &e, checkSyntax, ENVIRO );

	    f->Close( &e );
	}

	// free & clear

	delete f;
}

static void
WriteItem( FileSys *newf, const char *var, const char *value, Error *e )
{
	newf->Write( var, strlen( var ), e );
	newf->Write( "=", 1, e );
	newf->Write( value, strlen( value ), e );
	newf->Write( "\n", 1, e );
}

void
Enviro::SetEnviroFile( const char *f )
{
	if( ( f && symbolTab && enviroFile.Compare( StrRef( f ) ) ) ||
	    ( !f && enviroFile.Length() ) )
	{
	    symbolTab->RemoveType( ENVIRO );
	    LoadEnviro( 0 );
	}

	enviroFile.Set( f ? f : "" );

}

const StrPtr *
Enviro::GetEnviroFile()
{
	// If BeServer, do not use enviroment file at all
	if( sServiceNameStrP )
	    return NULL;

	if( !enviroFile.Length() )
	{	    
	    char *setFile = Get( p4enviro );

	    if( setFile )
	    {
		enviroFile.Set( setFile );
	    }
	    else
	    {
# if defined( OS_NT )
		return NULL;
# else
		// defaults for Unix platforms...
		setFile = Get( "HOME" );
		if( setFile )
		{
		    enviroFile.Set( setFile );
		    enviroFile.Append( "/.p4enviro" );
		}
		else
		    return NULL;
# endif
	    }
	}
	return &enviroFile;
}

int
Enviro::SetEnviro( const char *var, const char *value, Error *e )
{
	int didwrite = 0;
	const StrPtr *envFile = GetEnviroFile();

	if( !envFile )
	    return 1;

	// client up the directory tree, looking for setFile

	FileSys *f = FileSys::Create( FileSysType( FST_TEXT|FST_L_CRLF ) );
	FileSys *newf = FileSys::Create( FileSysType( FST_TEXT ) );

# if defined(OS_NT)
	if( charset )
	{
	    f->SetCharSetPriv( charset );
	    newf->SetCharSetPriv( charset );
	}
# endif

	// Can we find the file?

	e->Clear();
	f->Set( *envFile );
	f->Open( FOM_READ, e );

	if( !e->Test() )
	{
	    newf->MakeLocalTemp( envFile->Text() );
	    newf->SetDeleteOnClose();
	    newf->Perms( FPM_RW );

	    newf->Open( FOM_WRITE, e );

	    if( !e->Test() )
	    {
		// got both files - do the work

		StrBuf line, filevar;
		StrRef svar( var );

		while( !e->Test() && f->ReadLine( &line, e ) )
		{
		    line.TruncateBlanks();

		    char *equals = strchr( line.Text(), '=' );
		    if( !didwrite && equals && line.Text()[0] != '#')
		    {
			// Just variable name

			filevar.Set( line.Text(), equals - line.Text() );
			if( !filevar.SCompare( svar ) )
			{
			    // This is the one!
			    if( value && *value )
				WriteItem( newf, var, value, e );

			    didwrite = 1;

			    // do not duplicate this line in the temp file
			    continue;
			}
		    }
		    line.Extend( '\n' );
		    newf->Write( line.Text(), line.Length(), e );
		}

		if( !didwrite && value && *value )
		{
		    WriteItem( newf, var, value, e );
		    didwrite = 1;
		}

		newf->Close( e );
	    }

	    f->Close( e );

	    if( !e->Test() && didwrite )
	    {
		newf->Rename( f, e );

		if( !e->Test() )
		    newf->ClearDeleteOnClose();
	    }
	}
	else
	{
	    // could not open the enviro file, try to write it...
	    e->Clear();
	    f->Perms( FPM_RW );
	    f->Open( FOM_WRITE, e );
	    if( !e->Test() )
	    {
		WriteItem( f, var, value, e );
		didwrite = 1;
		f->Close( e );
	    }
	}

	delete newf;
	delete f;

	// Update the cache, assuming we don't already have a higher
	// presedence value.
	if( symbolTab )
	{
	    EnviroItem *a = symbolTab->PutItem( StrRef( (char *) var ) );
	    if( a->type >= ENVIRO )
	    {
	        a->type = ENVIRO;
	        a->value.Set( value );
	        a->origin.Set( envFile );
	    }
	}

	// warn the user if the env variable is also set.
	if( value && getenv( var ) )
	    e->Set( MsgSupp::HidesVar ) << var;

	return e->Test() || !didwrite;
}

const StrPtr &
Enviro::GetConfig()
{
	// configFile - name of last P4CONFIG file found by Config()

	if( !configFile.Length() )
	    configFile.Set( "noconfig" );

	return configFile;
}

const StrArray *
Enviro::GetConfigs()
{
	// configFiles - names of all P4CONFIG files found by Config()

	return configFiles;
}

int
Enviro::GetHome( StrBuf &result )
{

# ifdef OS_NT

        // On NT, try $USERPROFILE, if not use windows directory.

	const char *home = Get( "USERPROFILE" );
                                                                                
	if( home )
	    result.Set( home );
	else
	{
	    int length;
	    char buffer[MAX_PATH];
	    WCHAR wbuffer[MAX_PATH];

	    if( !CharSetApi::isUnicode( (CharSetApi::CharSet)GetCharSet() ) && 
		GetWindowsDirectoryA( buffer, sizeof( buffer ) ) )
	    {
	        result.Set( buffer );
	    }
	    else if( length = GetWindowsDirectoryW( wbuffer,
				sizeof( wbuffer )/sizeof( WCHAR ) ) )
	    {
		CharSetCvtUTF168 cvtval;
		const char *retval = 
			cvtval.FastCvt( (const char *)wbuffer,
					sizeof( WCHAR ) * length );
		if( retval )
		    result.Set( retval );
	    }
	}

# else

	const char *home = Get( "HOME" );
 
	if( home )
	    result.Set( home );

# endif

	// Strip the trailing slash, if there is one

	if( result.EndsWith( "/", 1 ) || result.EndsWith( "\\", 1 ) )
	{
	    result.SetLength( result.Length() - 1 );
	    result.Terminate();
	}

	return( result.Length() ? 1 : 0 );
}

