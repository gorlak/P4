/**
 * @file netsslmacros.h
 *
 * @brief A series of macros to report back results
 * and errors for OpenSSL library calls.
 *
 * Threading: underlying SSL library contains threading
 *
 * @invariants:
 *
 * Copyright (c) 2011 Perforce Software
 * Confidential.  All Rights Reserved.
 * @author Wendy Heffner
 *
 * Creation Date: August 19, 2011
 */

/**
 * NOTE:
 * The following 4 macro defines are required 
 * regardless of the compile status of SSL
 * they should be defined outside of the #ifdef USE_SSL
 */
// Used when checking msg header for handshake after accept.
#define SSLHDR_SIZE 3
#define SSLPROTOCOL 0x16
#define SSLVERSION_BYTE1 0x03
#define SSLVERSION_BYTE2 0x01

/**
 * NOTE:
 * The following file only defined if USE_SSL true.
 * The setting of this definition is controlled by
 * the Jamrules file.  If the jam build is specified
 * with -sSSL=yes this class will be defined.
 */
# ifdef USE_SSL
////////////////////////////////////////////////////////////////////////////
//  MACROS                                                                //
////////////////////////////////////////////////////////////////////////////
# define DARWIN_MAX 32*1024
# define HALF_SECOND 500

#define P4CHECKERROR( err, func, tag ) \
    do { \
        if ( (err)->Test() ) \
        { \
            if( SSLDEBUG_ERROR ) \
            { \
        	StrBuf buf; \
        	Error::StrError(buf); \
                p4debug.printf("%s Failed: %s\n", func, buf.Text());  \
            } \
            goto tag; \
        } \
        else \
        { \
            if( SSLDEBUG_FUNCTION ) \
                p4debug.printf("%s Successfully called.\n", func );  \
        } \
    } while(0);

#define SSLCHECKERROR( err, func, msgtag, tag ) \
    do { \
        if ( ( ERR_get_error()) > 1 ) \
        { \
            char sslError[256]; \
            ERR_error_string( ERR_get_error(), sslError ); \
            if( SSLDEBUG_ERROR ) \
                p4debug.printf("%s Failed: %s\n", func, sslError);  \
            (err)->Net( func, sslError ); \
            (err)->Set( msgtag ); \
            goto tag; \
        } \
        else \
        { \
            if( SSLDEBUG_FUNCTION ) \
                p4debug.printf("%s Successfully called.\n", func );  \
        } \
    } while(0);

#define SSLNULLHANDLER(x, err, func, tag) \
    do { \
        if ( ( x ) == NULL ) \
        { \
            char sslError[256]; \
            ERR_error_string( ERR_get_error(), sslError ); \
            if( SSLDEBUG_ERROR )  \
                p4debug.printf("%s Failed: %s\n", func, sslError); \
            (err)->Net( func, sslError ); \
            goto tag; \
        }  \
        else \
        { \
            if( SSLDEBUG_FUNCTION )   \
                p4debug.printf("%s Successfully called.\n", func ); \
        } \
    } while(0);


#define SSLLOGFUNCTION( func ) \
    do { \
        if( SSLDEBUG_FUNCTION ) \
        { \
            long x = ERR_get_error(); \
            if ( ( x ) > 1 ) \
            { \
                char sslError[256]; \
                ERR_error_string( x, sslError ); \
                if( SSLDEBUG_ERROR ) \
                    p4debug.printf("%s Failed: %s\n", func, sslError); \
            } else \
                p4debug.printf("%s: Successfully called\n", func );  \
        }  \
    } while(0);

#define SSLHANDLEFAIL( x, err, func, msgtag, tag ) \
    do { \
        if ( !x ) \
        { \
            if( SSLDEBUG_ERROR ) \
                p4debug.printf("%s Failed.\n", func);  \
            (err)->Net( func, "failed" ); \
            (err)->Set( msgtag ); \
            goto tag; \
        } \
        else \
        { \
            if( SSLDEBUG_FUNCTION ) \
                p4debug.printf("%s Successfully called.\n", func );  \
        } \
    } while(0);

# endif //USE_SSL
