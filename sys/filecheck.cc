/*
 * FileSys::CheckType() - look at the file and see if it is binary, etc
 */

# include <stdhdrs.h>
# include <charman.h>
# include <i18napi.h>
# include <charcvt.h>
# include <validate.h>
# include <debug.h>
# include <tunable.h>

# define BestFiletype(t)	(FileSysType)(t)

# ifdef OS_VMS
# include <unistd.h>
# include <dirent.h>
# endif

# include <error.h>
# include <strbuf.h>

# include "filesys.h"
# include "fileio.h"

FileSysType
FileSys::CheckType( int scan )
{
	if( scan < 0 || p4tunable.IsSet( P4TUNE_FILESYS_BINARYSCAN ) )
	{
	    // How far to look in a file for binary characters

	    scan = p4tunable.Get( P4TUNE_FILESYS_BINARYSCAN );
	}

	// Stat & check for missing, special

	int fsf = Stat();

	if(  ( fsf & FSF_SYMLINK ) ) return FST_SYMLINK;
	if( !( fsf & FSF_EXISTS ) ) return FST_MISSING;
	if(  ( fsf & FSF_DIRECTORY ) ) return FST_DIRECTORY;
	if(  ( fsf & FSF_SPECIAL ) ) return FST_SPECIAL;

	// Remember if it is executable.

	int execbits = fsf & FSF_EXECUTABLE;

# if defined ( OS_MACOSX )

	if( fsf & FSF_EMPTY )
	{
	    // !data + resource == apple
	    
	    FileIOApple f;
	    f.Set( Name() );
	    if( f.HasResourceFork() )
		return execbits ? FST_XAPPLEFILE : FST_APPLEFILE;

	    return BestFiletype( FST_EMPTY );
	}

# else
	if( fsf & FSF_EMPTY )
	    return FST_EMPTY;
# endif

	// otherwise, we need to read the file to test for ubinary

	// Open file to read some

	Error e;

	Open( FOM_READ, &e );

	if( e.Test() )
	    return BestFiletype( FST_CANTTELL );

	// Read some 

	StrFixed fileBuf( scan );
	char *buf = fileBuf.Text();
	int len = Read( buf, fileBuf.Length(), &e );
	char *p = buf;
	int l = len;

	Close( &e );

	if( e.Test() || !l )
	    return BestFiletype( FST_EMPTY );

	// Look for binary chars.

	int highbit = 0;
	int controlchar = 0;
	int zero = 0;

	for( ; l--; p++ )
	{
	    highbit |= 0x80 & *p;
	    zero |= !*p;
	    controlchar |= isAcntrl( p ) && !isAspace( p );
	}

	// But text with just %PDF- is still binary (yuk)

	static unsigned char pdfMagic[] = { '%', 'P', 'D', 'F', '-' };

	if( len < 5 || memcmp( buf, pdfMagic, sizeof( pdfMagic ) ) )
	{
	    CharSetCvt *cvt;
	    int rettype = FST_TEXT;
	    // Always look for a utf8 bom...
	    int utf8bomPresent = len >= 3 && !memcmp( buf, "\xef\xbb\xbf", 3 );

	    if( utf8bomPresent )
	    {
		if( controlchar )
		    goto somebinary;

		CharSetUTF8Valid utf8test;
		if( p4tunable.Get( P4TUNE_FILESYS_DETECTUTF8 ) > 0
			&& utf8test.Valid( buf, len ) )
		    rettype = FST_UTF8;
	    }

	    // is there an UTF16 BOM at the start
	    if( len > 1 && ( *(unsigned short *)buf == 0xfeff ||
		  *(unsigned short *)buf == 0xfffe ) &&
		((unsigned short *)buf)[1] != 0 ) // second word of zero means UTF-32
	    {
		// might be utf16...
		rettype = FST_UTF16;
		content_charSet = CharSetCvt::UTF_16;
		goto like16;
	    }

	    switch( (CharSetCvt::CharSet)content_charSet )
	    {
	    case CharSetCvt::UTF_8:
	    case CharSetCvt::UTF_8_BOM:
		if( controlchar )
		    goto somebinary;

		if( highbit && rettype == FST_TEXT )
		{
		    // run special UTF_8 validator...

		    CharSetUTF8Valid utf8test;
		    if( utf8test.Valid( buf, len ) )
			rettype = FST_UNICODE;
		}

		// else?  should we do unicode if no highbit?

		break;

	    case CharSetCvt::UTF_32:
	    case CharSetCvt::UTF_32_LE:
	    case CharSetCvt::UTF_32_BE:
	    case CharSetCvt::UTF_32_LE_BOM:
	    case CharSetCvt::UTF_32_BE_BOM:
	    case CharSetCvt::UTF_32_BOM:
		if( !zero && !highbit && !controlchar || utf8bomPresent )
		    break;

		rettype = FST_UNICODE;

		// is there a BOM at the start
		if( *(unsigned long *)buf == 0xfeff ||
		    *(unsigned long *)buf == 0xfffe0000 )
		    break;

		// is there a UTF16 BOM at start... consider binary...
		if( *(unsigned short *)buf == 0xfeff ||
		    *(unsigned short *)buf == 0xfffe )
		    goto somebinary;
		goto like16;

	    case CharSetCvt::UTF_16:
	    case CharSetCvt::UTF_16_LE:
	    case CharSetCvt::UTF_16_BE:
	    case CharSetCvt::UTF_16_LE_BOM:
	    case CharSetCvt::UTF_16_BE_BOM:
	    case CharSetCvt::UTF_16_BOM:
		if( !zero && !highbit && !controlchar || utf8bomPresent )
		    break;

		rettype = FST_UNICODE;

		// is there a BOM at the start
		if( *(unsigned short *)buf == 0xfeff ||
		    *(unsigned short *)buf == 0xfffe )
		{
		    // second word of zero means UTF-32
		    if( ((unsigned short *)buf)[1] == 0 )
			goto somebinary;
		    break;
		}

		// is there a UTF32 BOM at start... consider binary...
		if( *(unsigned short *)buf == 0 )
		    goto somebinary;

	    like16:
		cvt = CharSetCvt::FindCvt((CharSetCvt::CharSet)content_charSet,
			CharSetCvt::UTF_8);
		if( cvt )
		{
		    StrFixed tbuf( scan * 2 );
		    cvt->ResetErr();
		    const char *ss = buf;
		    p = tbuf.Text();
		    if( cvt->Cvt( &ss, buf + len,
				  &p, tbuf.Text() + tbuf.Length() ) != 0
			|| cvt->LastErr() == CharSetCvt::NOMAPPING )
		    {
			// it does not convert... consider it binary...
			delete cvt;
			goto somebinary;
		    }
		    delete cvt;
		    // it did convert... see if it looks like utf8 text...
		    // we think it is text if there are more than
		    // 1 space character every 40 characters or so...
		    int cnt = 0, ccnt = 0;
		    CharStepUTF8 step( tbuf.Text() );
		    while( step.Ptr() < p )
		    {
			if( isAspace( step.Ptr() ) )
			    ++cnt;
			++ccnt;
			step.Next();
		    }
		    if( 40 * cnt < ccnt )
			goto somebinary;
		}

		break;


	    case CharSetCvt::NOCONV:
		// non-unicode mode goes here...

		if( controlchar )
		    goto somebinary;

		break;

	    default:
		// most 8-bit charsets go here...

		if( controlchar )
		    goto somebinary;

		if( utf8bomPresent )
		    break;

		if( highbit )
		{
		    // Found a high bit and a charset is set...
		    cvt = CharSetCvt::FindCvt((CharSetCvt::CharSet)content_charSet,
			CharSetCvt::UTF_8);
		    if( cvt )
		    {
			StrFixed tbuf( scan * 3 );
			cvt->ResetErr();
			const char *ss = buf;
			p = tbuf.Text();
			if( cvt->Cvt( &ss, buf + len,
				  &p, tbuf.Text() + tbuf.Length() ) == 0
				&& cvt->LastErr() != CharSetCvt::NOMAPPING )
			{
			    // it converts... consider it unicode...
			    rettype = FST_UNICODE;
			}
			delete cvt;
		    }
		}
	    }

	    if( rettype == FST_UNICODE )
	    {
		if( highbit )
		{
		    CharSetUTF8Valid utf8test;
		    if( p4tunable.Get( P4TUNE_FILESYS_DETECTUTF8 ) == 1
			    && utf8test.Valid( buf, len ) )
			rettype = FST_UTF8;
		}
		if( rettype == FST_UNICODE &&
			!p4tunable.Get( P4TUNE_FILESYS_DETECTUNICODE ) )
		    rettype = FST_TEXT;
	    }

	    if( execbits )
		rettype |= FST_M_EXEC;
	    return BestFiletype( (FileSysType)rettype );
	}

 somebinary:
	// It's binary.  Let's see if it is a known compressed type.
	// Yuk -- what a list!

	static unsigned char gifMagic[] = { 'G', 'I', 'F' };
	static unsigned char jpgMagic[] = { 0377, 0330, 0377, 0356 };
	static unsigned char jpegMagic[] = { 0377, 0330, 0377, 0340 };
	static unsigned char exifMagic[] = { 0377, 0330, 0377, 0341 };
	static unsigned char gzipMagic[] = { 037, 0213 };
	static unsigned char pkzipMagic[] = { 'P', 'K', 03, 04 };
	static unsigned char compaMagic[] = { 0377, 037 };
	static unsigned char comprMagic[] = { 037, 0235 };

	if( !execbits && len >= 5 &&
	      ( !memcmp( buf, gifMagic, sizeof( gifMagic ) ) ||
		!memcmp( buf, jpgMagic, sizeof( jpgMagic ) ) ||
		!memcmp( buf, jpegMagic, sizeof( jpegMagic ) ) ||
		!memcmp( buf, exifMagic, sizeof( exifMagic ) ) ||
		!memcmp( buf, gzipMagic, sizeof( gzipMagic ) ) ||
		!memcmp( buf, pkzipMagic, sizeof( pkzipMagic ) ) ||
		!memcmp( buf, compaMagic, sizeof( compaMagic ) ) ||
		!memcmp( buf, comprMagic, sizeof( comprMagic ) ) ) )
	    return FST_CBINARY;

# if defined ( OS_MACOSX )
	{
	    // binary data + resource == apple
	    
	    FileIOApple f;
	    f.Set( Name() );
	    if( f.HasResourceFork() )
		return execbits ? FST_XAPPLEFILE : FST_APPLEFILE;
	}
# endif

	return execbits ? FST_XBINARY : FST_BINARY;
}
