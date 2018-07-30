/**
 * @file bio.h
 *
 * @brief Perforce's API stubbed out version of openssl/bio.h
 *
 * Threading: 
 *
 * @date   November 18, 2011
 * @author Wendy Heffner (wheffner)
 *
 * Copyright (c) 2011 Perforce Software  
 * Confidential.  All Rights Reserved.
 */

#ifndef HEADER_BIO_H
#define HEADER_BIO_H

# include <stdio.h>
# include <sys/types.h>

////////////////////////////////////////////////////////////////////////////
//			       DEFINES                                    //
////////////////////////////////////////////////////////////////////////////
# ifndef BIO
# define BIO void
# endif //BIO

#define BIO_C_GET_BUF_MEM_PTR			115
# define BIO_METHOD void
typedef struct buf_mem_st
 {
        int length;
        char *data;
        int max;
 } BUF_MEM;

// needed by our base64 code : Base64::Encode() and Base64::Decode()
# define BIO_FLAGS_BASE64_NO_NL  0x100

#define BIO_get_mem_ptr(b,pp)	BIO_ctrl(b,BIO_C_GET_BUF_MEM_PTR,0,(char *)pp)
////////////////////////////////////////////////////////////////////////////
//			       METHOD STUBS                               //
////////////////////////////////////////////////////////////////////////////
void BIO_free_all (BIO *a);
BIO * BIO_new_socket (int sock, int close_flag);
BIO * BIO_pop (BIO *b);
BIO * BIO_new_fd(int fd, int close_flag);
BIO * BIO_new_fp(FILE *stream, int close_flag);
BIO * BIO_new(BIO_METHOD *type);
long  BIO_ctrl(BIO *bp,int cmd,long larg,void *parg);
int BIO_printf (BIO *bio, const char *format, ...);
BIO_METHOD *BIO_s_mem(void);
BIO * BIO_new_mem_buf(void *buf, int len);

size_t BIO_ctrl_pending(BIO *b);
int    BIO_read(BIO *b, void *buf, int len);
int    BIO_write(BIO *b, const void *buf, int len);
void   BIO_set_flags(BIO *b, int flags);
BIO *  BIO_push(BIO *b,BIO *append);
int    BIO_flush(BIO *b);
BIO_METHOD * BIO_f_base64(void);
#endif // HEADER_BIO_H

