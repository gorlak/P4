/**
 * @file ssl.h
 *
 * @brief Perforce's API stubbed out version of openssl/ssl.h
 *
 * Threading: 
 *
 * @date   November 18, 2011
 * @author Wendy Heffner (wheffner)
 *
 * Copyright (c) 2011 Perforce Software  
 * Confidential.  All Rights Reserved.
 */

#ifndef HEADER_SSL_H 
#define HEADER_SSL_H 

# include <errno.h>

#include "openssl/x509v3.h"
#include "openssl/bio.h"

////////////////////////////////////////////////////////////////////////////
//			       DEFINES                                    //
////////////////////////////////////////////////////////////////////////////
// Datatypes
# define ASN1_INTEGER int
# define ASN1_PCTX void
# define ASN1_TIME void
# define EVP_MD void
# define RSA void
# define SSL_METHOD void
# define SSL void
# ifndef SSL_CTX
# define SSL_CTX int
# endif // SSL_CTX
# ifndef X509
# define X509 void
# endif //X509
# define X509_STORE_CTX void

# ifndef SHA_CTX
#    define SHA_CTX	void
# endif // SHA_CTX

# ifndef SHA256_CTX
#    define SHA256_CTX	void
# endif // SHA256_CTX

// needed for our TLS version selection code:
//	NetSslTransport::CreateAndInitializeSslContext()
# define SSL_OP_NO_SSLv2                                 0x01000000L
# define SSL_OP_NO_SSLv3                                 0x02000000L
# define SSL_OP_NO_TLSv1                                 0x04000000L
# define SSL_OP_NO_TLSv1_2                               0x08000000L
# define SSL_OP_NO_TLSv1_1                               0x10000000L

// Constants
# define SSL_CTRL_MODE                  33
# define SSL_MODE_ENABLE_PARTIAL_WRITE  0x00000001L
# define SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER 0x00000002L
# define SSL_FILETYPE_PEM               1
# define SSL_VERIFY_NONE                0x00
# define BIO_NOCLOSE                    0x00
# define SSL_ERROR_NONE			0
# define SSL_ERROR_SSL			1
# define SSL_ERROR_WANT_READ		2
# define SSL_ERROR_WANT_WRITE		3
# define SSL_ERROR_WANT_X509_LOOKUP	4
# define SSL_ERROR_SYSCALL		5
# define SSL_ERROR_ZERO_RETURN		6
# define SSL_ERROR_WANT_CONNECT		7
# define SSL_ERROR_WANT_ACCEPT		8
# define SSL_RECEIVED_SHUTDOWN          2

// Macro
#define SSL_CTX_set_mode(ctx,op) \
	SSL_CTX_ctrl((ctx),SSL_CTRL_MODE,(op),NULL)

////////////////////////////////////////////////////////////////////////////
//			       METHOD STUBS                               //
////////////////////////////////////////////////////////////////////////////
int SSL_accept (SSL *ssl);
int SSL_clear (SSL *ssl);
int SSL_connect (SSL *ssl);
long SSL_CTX_ctrl (SSL_CTX *ctx,int cmd, long larg, void *parg);
SSL_CTX * SSL_CTX_new (const SSL_METHOD *meth);
void SSL_CTX_set_verify (SSL_CTX *ctx, int mode, 
                         int (*callback)(int, X509_STORE_CTX *));
int SSL_CTX_use_certificate (SSL_CTX *ctx, X509 *x);
int SSL_CTX_use_certificate_file (SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_use_PrivateKey (SSL_CTX *ctx, EVP_PKEY *pkey);
int SSL_CTX_use_PrivateKey_file (SSL_CTX *ctx, const char *file, int type);
int SSL_free (SSL *ssl);
int SSL_get_error (const SSL *s,int ret_code);
X509 * SSL_get_peer_certificate (const SSL *ssl);
int SSL_get_shutdown (const SSL *ssl);
int SSL_library_init (void);
void SSL_load_error_strings (void);
SSL * SSL_new (SSL_CTX *ctx);
int SSL_pending (const SSL *s);
int SSL_read (SSL *ssl,void *buf,int num);
void SSL_set_bio (SSL *s, BIO *rbio,BIO *wbio);
int SSL_shutdown (SSL *ssl);
int SSL_write (SSL *ssl,const void *buf,int num);
const SSL_METHOD * TLSv1_method (void);
const char  * SSL_get_cipher_list(const SSL *s,int n);
int	SSL_set_cipher_list(SSL *s, const char *str);

const SSL_METHOD *SSLv23_method(void);
long SSL_CTX_set_options(SSL_CTX *ctx, long options);
const char *SSL_get_version(const SSL *ssl);

int EVP_PKEY_print_private(BIO *out, const EVP_PKEY *pkey,
				int indent, ASN1_PCTX *pctx);
unsigned long SSLeay(void);
int CRYPTO_num_locks(void);
void CRYPTO_set_locking_callback(void (*func)(int mode,int type,
					      const char *file,int line));
void CRYPTO_set_id_callback(unsigned long (*func)(void));
void CRYPTO_set_dynlock_create_callback(struct CRYPTO_dynlock_value *
        (*dyn_create_function)(const char *file, int line));
void CRYPTO_set_dynlock_lock_callback(void (*dyn_lock_function)
        (int mode, struct CRYPTO_dynlock_value *l,
        const char *file, int line));
void CRYPTO_set_dynlock_destroy_callback(void (*dyn_destroy_function)
        (struct CRYPTO_dynlock_value *l, const char *file, int line));

int SHA1_Init(SHA_CTX *c);
int SHA1_Update(SHA_CTX *c, const void *data, unsigned long len);
int SHA1_Final(unsigned char *md, SHA_CTX *c);

int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
unsigned char * HMAC(const EVP_MD *evp_md, const void *key, int key_len,
                    const unsigned char *d, size_t n, unsigned char *md,
                    unsigned int *md_len);
#endif // HEADER_SSL_H 
