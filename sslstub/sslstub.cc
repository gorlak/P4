/**
 * @file sslstub.cc
 *
 * @brief 
 *
 * Threading: 
 *
 * @date   November 18,2011
 * @author Wendy Heffner (wheffner)
 *
 * Copyright (c) 2011 Perforce Software  
 * Confidential.  All Rights Reserved.
 */

# ifndef NULL
# define NULL 0
# endif // NULL

extern "C"
{ // OpenSSL

# include "openssl/x509v3.h"
# include "openssl/bio.h"
# include "openssl/ssl.h"
# include "openssl/err.h"

}
static EVP_PKEY mypkey = { 6, NULL };
int 
ASN1_INTEGER_set(ASN1_INTEGER *a, long  v)
{
	return 0;
}

int
ASN1_TIME_print(BIO *bp, const ASN1_TIME *tm)
{
    return 0;
}

void
BIO_free_all(BIO *a)
{
}



BIO *
BIO_new_socket(int sock, int close_flag)
{
	return NULL;
}

int
BIO_printf (BIO *bio, const char *format, ...)
{
    return 0;
}

BIO *
BIO_pop(BIO *b)
{
	return NULL;
}

BIO *
BIO_new_fd(int fd, int close_flag)
{
	return NULL;
}

BIO *
BIO_new_fp(FILE *stream, int close_flag)
{
	return NULL;
}

BIO *
BIO_new(BIO_METHOD *type)
{
	return NULL;
}

long  
BIO_ctrl(BIO *bp,int cmd,long larg,void *parg)
{
	return 0;
}

BIO_METHOD *
BIO_s_mem(void)
{
	return NULL;
}

BIO *
BIO_new_mem_buf(void *buf, int len)
{
	return NULL;
}

size_t
BIO_ctrl_pending(BIO *b)
{
	return 0;
}

int
BIO_read(BIO *b, void *buf, int len)
{
	return 0;
}

int
BIO_write(BIO *b, const void *buf, int len)
{
	return 0;
}

void
BIO_set_flags(BIO *b, int flags)
{
	return;
}

BIO *
BIO_push(BIO *b,BIO *append)
{
	return NULL;
}

int
BIO_flush(BIO *b)
{
	return 0;
}

BIO_METHOD *
BIO_f_base64(void)
{
	return NULL;
}

int
SHA1_Init(SHA_CTX *c)
{
	return 0;
}

int
SHA1_Update(SHA_CTX *c, const void *data, unsigned long len)
{
	return 0;
}

int
SHA1_Final(unsigned char *md, SHA_CTX *c)
{
	return 0;
}

int
SHA256_Init(SHA256_CTX *c)
{
	return 0;
}

int
SHA256_Update(SHA256_CTX *c, const void *data, unsigned long len)
{
	return 0;
}

int
SHA256_Final(unsigned char *md, SHA256_CTX *c)
{
	return 0;
}

unsigned char *
SHA256(const unsigned char *d, size_t n, unsigned char *md)
{
	return NULL;
}


////////////////////////////////////////////////////////////////////////////
//	STATIC MEMBERS, DEFINES, GLOBAL METHODS				  //
////////////////////////////////////////////////////////////////////////////

char *
ERR_error_string(unsigned long  e, char *buf)
{
	return NULL;
}



unsigned long
ERR_get_error(void)
{
	return 0;
}



void
ERR_load_BIO_strings(void)
{
}

void
ERR_remove_thread_state(const CRYPTO_THREADID *not_used)
{
}

int
EVP_PKEY_assign(EVP_PKEY *pkey, int type, void *key)
{
	return 0;
}

void 
EVP_PKEY_free(EVP_PKEY *pkey)
{
}

EVP_PKEY *
EVP_PKEY_new(void)
{
	return NULL;
}

EVP_PKEY *
X509_get_pubkey(X509 *a)
{
	return NULL;
}
EVP_MD *
EVP_sha1(void)
{
	return NULL;
}

int
EVP_Digest(const void *data, size_t count,
	unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl)
{
	return 0;
}


RSA *
RSA_generate_key(int bits, unsigned long  e, void(*callback)(int, int, void*), void *cb_arg)
{
	return NULL;
}



int
SSL_accept(SSL *ssl)
{
	return 0;
}



int
SSL_clear(SSL *ssl)
{
	return 0;
}



int
SSL_connect(SSL *ssl)
{
	return 0;
}



long
SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long  larg, void *parg)
{
	return 0;
}



SSL_CTX *
SSL_CTX_new(const SSL_METHOD *meth)
{
	return NULL;
}



void
SSL_CTX_set_verify(SSL_CTX *ctx, int mode, int (*callback)(int, X509_STORE_CTX*))
{
}



int
SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x)
{
	return 0;
}



int
SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type)
{
	return 0;
}



int
SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)
{
	return 0;
}



int
SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type)
{
	return 0;
}



int
SSL_free(SSL *ssl)
{
	return 0;
}



int
SSL_get_error(const SSL *s, int ret_code)
{
	return 0;
}



X509 *SSL_get_peer_certificate(const SSL *ssl)
{
	return NULL;
}



int
SSL_get_shutdown(const SSL *ssl)
{
	return 0;
}



int
SSL_library_init(void)
{
	return 0;
}



void
SSL_load_error_strings(void)
{
}



SSL *
SSL_new(SSL_CTX *ctx)
{
	return NULL;
}



int
SSL_pending(const SSL *s)
{
	return 0;
}



int
SSL_read(SSL *ssl, void *buf, int num)
{
	return 0;
}



void
SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio)
{
}



int
SSL_shutdown(SSL *ssl)
{
	return 0;
}



int
SSL_write(SSL *ssl, const void *buf, int num)
{
	return 0;
}



const SSL_METHOD *
TLSv1_method(void)
{
	return NULL;
}

int
X509_cmp_time(const ASN1_TIME *ctm, time_t *cmp_time)
{
    return 0;
}

int
X509_digest(const X509 *data, const EVP_MD *type,
	    unsigned char *md, unsigned int *len)
{
    return 0;
}

int
X509_pubkey_digest(const X509 *data, const EVP_MD *type, unsigned char *md,
	     unsigned int *len)
{
    return 0;
}

void
X509_free(X509 *a)
{
}



X509_NAME *
X509_get_issuer_name(X509 *a)
{
	return NULL;
}



ASN1_INTEGER *
X509_get_serialNumber(X509 *a)
{
	return NULL;
}



X509_NAME *
X509_get_subject_name(X509 *a)
{
	return NULL;
}



ASN1_TIME *
X509_gmtime_adj(ASN1_TIME *s, long  adj)
{
	return NULL;
}



int
X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type, const unsigned char *bytes, int len, int loc, int set)
{
	return 0;
}



char *
X509_NAME_oneline(X509_NAME *a, char *buf, int size)
{
	return NULL;
}



X509 *
X509_new(void)
{
	return NULL;
}



int
X509_set_issuer_name(X509 *x, X509_NAME *name)
{
	return 0;
}



int
X509_set_pubkey(X509 *x, EVP_PKEY *pkey)
{
	return 0;
}



int
X509_set_version(X509 *x, long  version)
{
	return 0;
}



int
X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md)
{
	return 0;
}
const char  *
SSL_get_cipher_list(const SSL *s,int n)
{
	return NULL;
}

int
SSL_set_cipher_list(SSL *s, const char *str)
{
	return 0;
}

const SSL_METHOD *
SSLv23_method(void)
{
	return NULL;
}

long
SSL_CTX_set_options(SSL_CTX *ctx, long options)
{
	return 0;
}

const char *
SSL_get_version(const SSL *ssl)
{
	return "";
}

int
EVP_PKEY_print_private(BIO *out, const EVP_PKEY *pkey,
				int indent, ASN1_PCTX *pctx)
{
	return 0;
}

EVP_PKEY *
PEM_read_PrivateKey(FILE *fp, EVP_PKEY **x,
                    pem_password_cb *cb, void *u)
{
	return NULL;
}

X509 *
PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u)
{
	return NULL;
}

X509 *
PEM_read_X509(FILE *fp, X509 **x, pem_password_cb *cb, void *u)
{
	return NULL;
}

int
PEM_write_PrivateKey(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc,
                     unsigned char *kstr, int klen,
                     pem_password_cb *cb, void *u)
{
	return 0;
}

int
PEM_write_X509(FILE *fp, X509 *x)
{
	return 0;
}

unsigned long
SSLeay(void)
{
	return 0L;
}

int
i2d_X509_PUBKEY(X509_PUBKEY *xpk, unsigned char **pp)
{
	return 0;
}

int CRYPTO_num_locks(void)
{
	return 0;
}
void CRYPTO_set_locking_callback(void (*func)(int mode,int type,
					      const char *file,int line))
{
}

void CRYPTO_set_id_callback(unsigned long (*func)(void))
{
}

void CRYPTO_set_dynlock_create_callback(struct CRYPTO_dynlock_value *
        (*dyn_create_function)(const char *file, int line))
{
}
void CRYPTO_set_dynlock_lock_callback(void (*dyn_lock_function)
        (int mode, struct CRYPTO_dynlock_value *l,
        const char *file, int line))
{
}

void
CRYPTO_set_dynlock_destroy_callback(void (*dyn_destroy_function)
        (struct CRYPTO_dynlock_value *l, const char *file, int line))
{
}

unsigned char *
HMAC(const EVP_MD *evp_md, const void *key, int key_len,
                    const unsigned char *d, size_t n, unsigned char *md,
                    unsigned int *md_len)
{
	return NULL;
}
