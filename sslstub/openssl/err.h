/**
 * @file err.h
 *
 * @brief Perforce's API stubbed out version of openssl/err.h
 *
 * Threading: 
 *
 * @date   November 18, 2011
 * @author Wendy Heffner (wheffner)
 *
 * Copyright (c) 2011 Perforce Software  
 * Confidential.  All Rights Reserved.
 */

#ifndef HEADER_ERR_H
#define HEADER_ERR_H

#define CRYPTO_THREADID void
////////////////////////////////////////////////////////////////////////////
//			       METHOD STUBS                               //
////////////////////////////////////////////////////////////////////////////
char * ERR_error_string (unsigned long e,char *buf);
unsigned long ERR_get_error (void); 
void ERR_load_BIO_strings (void);
void ERR_remove_thread_state(const CRYPTO_THREADID *not_used);
#endif // HEADER_ERR_H





