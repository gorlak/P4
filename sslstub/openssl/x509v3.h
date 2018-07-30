/**
 * @file x509v3.h
 *
 * @brief Perforce's API stubbed out version of openssl/x509v3.h
 *
 * Threading: 
 *
 * @date   November 18, 2011
 * @author Wendy Heffner (wheffner)
 *
 * Copyright (c) 2011 Perforce Software  
 * Confidential.  All Rights Reserved.
 */

#ifndef HEADER_X509V3_H
#define HEADER_X509V3_H

# include <stdio.h>
# include <sys/types.h>


////////////////////////////////////////////////////////////////////////////
//			       DEFINES                                    //
////////////////////////////////////////////////////////////////////////////

# define ASN1_INTEGER int
# define ASN1_TIME void
# define ENGINE void
# define EVP_CIPHER  void
# define EVP_MD void
# define ASN1_INTEGER			int
# define ASN1_TIME			void
# define ENGINE				void
# define EVP_CIPHER			void
# define EVP_MD				void
# define RSA				void
# define pem_password_cb		void

# ifndef BIO
# define BIO void
# endif //BIO

# define X509_NAME			void
# define X509_PUBKEY			void
# define RSA_F4				0x10001L
# define EVP_MAX_MD_SIZE		64
# define EVP_PKEY_RSA			6
# define EVP_PKEY_assign_RSA(pkey,rsa)	0
# define X509_get_notBefore(x)		0
# define X509_get_notAfter(x)		0
# define MBSTRING_ASC			0
# define CRYPTO_LOCK			0x01
# define CRYPTO_UNLOCK			0x02
# define CRYPTO_READ			0x04
# define CRYPTO_WRITE			0x08

# ifndef X509
typedef struct x509_cinf_st
{
	X509_PUBKEY *key;
} X509_CINF;
struct x509_st
{
	X509_CINF *cert_info;
};
# define X509				struct x509_st
# endif //X509

# define X509_get_X509_PUBKEY(x)	((x)->cert_info->key)

typedef struct evp_pkey_st
{
	int type;
	void *data;
} EVP_PKEY;

////////////////////////////////////////////////////////////////////////////
//			       METHOD STUBS                               //
////////////////////////////////////////////////////////////////////////////
int ASN1_INTEGER_set (ASN1_INTEGER *a, long v); 
int EVP_PKEY_assign (EVP_PKEY *pkey,int type,void *key);
void EVP_PKEY_free (EVP_PKEY *pkey);
int	EVP_Digest(const void *data, size_t count,
		unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl);
EVP_PKEY * EVP_PKEY_new (void);
EVP_PKEY * X509_get_pubkey(X509 *a);

EVP_MD * EVP_sha1 (void);
const char *	OBJ_nid2sn(int n);

RSA * RSA_generate_key (int bits, unsigned long e,
                        void (*callback)(int,int,void *),void *cb_arg);
int X509_cmp_time(const ASN1_TIME *ctm, time_t *cmp_time);
void X509_free (X509 *a);
X509_NAME * X509_get_issuer_name (X509 *a);
ASN1_INTEGER * X509_get_serialNumber (X509 *a);
X509_NAME * X509_get_subject_name (X509 *a);
ASN1_TIME * X509_gmtime_adj (ASN1_TIME *s, long adj);
int ASN1_TIME_print(BIO *bp, const ASN1_TIME *tm);
int X509_NAME_add_entry_by_txt (X509_NAME *name, const char *field, 
                                int type, const unsigned char *bytes, 
                                int len, int loc, int set);
char * X509_NAME_oneline (X509_NAME *a,char *buf,int size);
X509 * X509_new (void);
int X509_digest(const X509 *data, const EVP_MD *type,
        unsigned char *md, unsigned int *len);
int X509_pubkey_digest(const X509 *data, const EVP_MD *type,
	unsigned char *md, unsigned int *len);
int X509_set_issuer_name (X509 *x, X509_NAME *name);
int X509_set_pubkey (X509 *x, EVP_PKEY *pkey);
int X509_set_version (X509 *x,long version);
int X509_sign (X509 *x, EVP_PKEY *pkey, const EVP_MD *md);
EVP_PKEY *PEM_read_PrivateKey(FILE *fp, EVP_PKEY **x,
                              pem_password_cb *cb, void *u);
X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u);
X509 *PEM_read_X509(FILE *fp, X509 **x, pem_password_cb *cb, void *u);
int PEM_write_PrivateKey(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc,
                                        unsigned char *kstr, int klen,
                                        pem_password_cb *cb, void *u);
int PEM_write_X509(FILE *fp, X509 *x);
int i2d_X509_PUBKEY(X509_PUBKEY *a, unsigned char **out);

#endif // HEADER_X509V3_H
