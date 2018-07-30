/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

# include <stdhdrs.h>
# include "strbuf.h"
# include "base64.h"
        
# ifdef USE_SSL
extern "C"
{ // OpenSSL
# include <openssl/bio.h>
# include <openssl/evp.h>
}

int Base64::Decode( StrPtr &in, StrBuf &out )
{
        int padding = 0;
        BIO *bio, *b64;

        // Calculate decoded length
        if( *(in.End()-1) == '=' )
        {
            ++padding;
            if( *(in.End()-2) == '=' )
                ++padding;
        }
        int decodeLen = (in.Length()*3)/4 - padding;
        out.Alloc( decodeLen + 1 );

        bio = BIO_new_mem_buf(in.Text(), -1);
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);

        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        int length = BIO_read(bio, out.Text(), in.Length());
        BIO_free_all(bio);

        out.SetLength( decodeLen );
	out.Terminate();

        return length != decodeLen;
}

void Base64::Encode(StrPtr &in, StrBuf &out )
{
        BIO *bio, *b64;
        int length;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);

        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
        BIO_write(bio, in.Text(), in.Length());
        BIO_flush(bio);
        bio = BIO_pop(b64);
        length = BIO_ctrl_pending(bio);
        out.Alloc( length + 1 );
        int len = BIO_read( bio, out.Text(), length );
        out.SetLength( len );
        BIO_free_all(bio);
        BIO_free_all(b64);
}

# else
int Base64::Decode( StrPtr &in, StrBuf &out )
{
        // nothing happens
	return 1;
}
void Base64::Encode( StrPtr &in, StrBuf &out )
{
        // nothing happens
}
# endif


