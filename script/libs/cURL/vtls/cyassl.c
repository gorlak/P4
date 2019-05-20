/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

/*
 * Source file for all CyaSSL-specific code for the TLS/SSL layer. No code
 * but vtls.c should ever call or use these functions.
 *
 */

#include "curl_setup.h"

#ifdef USE_CYASSL

#define WOLFSSL_OPTIONS_IGNORE_SYS
/* CyaSSL's version.h, which should contain only the version, should come
before all other CyaSSL includes and be immediately followed by build config
aka options.h. https://curl.haxx.se/mail/lib-2015-04/0069.html */
#include <cyassl/version.h>
#if defined(HAVE_CYASSL_OPTIONS_H) && (LIBCYASSL_VERSION_HEX > 0x03004008)
#if defined(CYASSL_API) || defined(WOLFSSL_API)
/* Safety measure. If either is defined some API include was already included
and that's a problem since options.h hasn't been included yet. */
#error "CyaSSL API was included before the CyaSSL build options."
#endif
#include <cyassl/options.h>
#endif

/* To determine what functions are available we rely on one or both of:
   - the user's options.h generated by CyaSSL/wolfSSL
   - the symbols detected by curl's configure
   Since they are markedly different from one another, and one or the other may
   not be available, we do some checking below to bring things in sync. */

/* HAVE_ALPN is wolfSSL's build time symbol for enabling ALPN in options.h. */
#ifndef HAVE_ALPN
#ifdef HAVE_WOLFSSL_USEALPN
#define HAVE_ALPN
#endif
#endif

/* WOLFSSL_ALLOW_SSLV3 is wolfSSL's build time symbol for enabling SSLv3 in
   options.h, but is only seen in >= 3.6.6 since that's when they started
   disabling SSLv3 by default. */
#ifndef WOLFSSL_ALLOW_SSLV3
#if (LIBCYASSL_VERSION_HEX < 0x03006006) || \
    defined(HAVE_WOLFSSLV3_CLIENT_METHOD)
#define WOLFSSL_ALLOW_SSLV3
#endif
#endif

/* HAVE_SUPPORTED_CURVES is wolfSSL's build time symbol for enabling the ECC
   supported curve extension in options.h. Note ECC is enabled separately. */
#ifndef HAVE_SUPPORTED_CURVES
#if defined(HAVE_CYASSL_CTX_USESUPPORTEDCURVE) || \
    defined(HAVE_WOLFSSL_CTX_USESUPPORTEDCURVE)
#define HAVE_SUPPORTED_CURVES
#endif
#endif

#include <limits.h>

#include "urldata.h"
#include "sendf.h"
#include "inet_pton.h"
#include "vtls.h"
#include "parsedate.h"
#include "connect.h" /* for the connect timeout */
#include "select.h"
#include "strcase.h"
#include "x509asn1.h"
#include "curl_printf.h"

#include <cyassl/openssl/ssl.h>
#include <cyassl/ssl.h>
#ifdef HAVE_CYASSL_ERROR_SSL_H
#include <cyassl/error-ssl.h>
#else
#include <cyassl/error.h>
#endif
#include <cyassl/ctaocrypt/random.h>
#include <cyassl/ctaocrypt/sha256.h>

#include "cyassl.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

#if LIBCYASSL_VERSION_HEX < 0x02007002 /* < 2.7.2 */
#define CYASSL_MAX_ERROR_SZ 80
#endif

/* KEEP_PEER_CERT is a product of the presence of build time symbol
   OPENSSL_EXTRA without NO_CERTS, depending on the version. KEEP_PEER_CERT is
   in wolfSSL's settings.h, and the latter two are build time symbols in
   options.h. */
#ifndef KEEP_PEER_CERT
#if defined(HAVE_CYASSL_GET_PEER_CERTIFICATE) || \
    defined(HAVE_WOLFSSL_GET_PEER_CERTIFICATE) || \
    (defined(OPENSSL_EXTRA) && !defined(NO_CERTS))
#define KEEP_PEER_CERT
#endif
#endif

struct ssl_backend_data {
  SSL_CTX* ctx;
  SSL*     handle;
};

#define BACKEND connssl->backend

static Curl_recv cyassl_recv;
static Curl_send cyassl_send;


static int do_file_type(const char *type)
{
  if(!type || !type[0])
    return SSL_FILETYPE_PEM;
  if(strcasecompare(type, "PEM"))
    return SSL_FILETYPE_PEM;
  if(strcasecompare(type, "DER"))
    return SSL_FILETYPE_ASN1;
  return -1;
}

/*
 * This function loads all the client/CA certificates and CRLs. Setup the TLS
 * layer and do all necessary magic.
 */
static CURLcode
cyassl_connect_step1(struct connectdata *conn,
                     int sockindex)
{
  char error_buffer[CYASSL_MAX_ERROR_SZ];
  char *ciphers;
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data* connssl = &conn->ssl[sockindex];
  SSL_METHOD* req_method = NULL;
  curl_socket_t sockfd = conn->sock[sockindex];
#ifdef HAVE_SNI
  bool sni = FALSE;
#define use_sni(x)  sni = (x)
#else
#define use_sni(x)  Curl_nop_stmt
#endif

  if(connssl->state == ssl_connection_complete)
    return CURLE_OK;

  if(SSL_CONN_CONFIG(version_max) != CURL_SSLVERSION_MAX_NONE) {
    failf(data, "CyaSSL does not support to set maximum SSL/TLS version");
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* check to see if we've been told to use an explicit SSL/TLS version */
  switch(SSL_CONN_CONFIG(version)) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
#if LIBCYASSL_VERSION_HEX >= 0x03003000 /* >= 3.3.0 */
    /* minimum protocol version is set later after the CTX object is created */
    req_method = SSLv23_client_method();
#else
    infof(data, "CyaSSL <3.3.0 cannot be configured to use TLS 1.0-1.2, "
          "TLS 1.0 is used exclusively\n");
    req_method = TLSv1_client_method();
#endif
    use_sni(TRUE);
    break;
  case CURL_SSLVERSION_TLSv1_0:
#ifdef WOLFSSL_ALLOW_TLSV10
    req_method = TLSv1_client_method();
    use_sni(TRUE);
#else
    failf(data, "CyaSSL does not support TLS 1.0");
    return CURLE_NOT_BUILT_IN;
#endif
    break;
  case CURL_SSLVERSION_TLSv1_1:
    req_method = TLSv1_1_client_method();
    use_sni(TRUE);
    break;
  case CURL_SSLVERSION_TLSv1_2:
    req_method = TLSv1_2_client_method();
    use_sni(TRUE);
    break;
  case CURL_SSLVERSION_TLSv1_3:
#ifdef WOLFSSL_TLS13
    req_method = wolfTLSv1_3_client_method();
    use_sni(TRUE);
    break;
#else
    failf(data, "CyaSSL: TLS 1.3 is not yet supported");
    return CURLE_SSL_CONNECT_ERROR;
#endif
  case CURL_SSLVERSION_SSLv3:
#ifdef WOLFSSL_ALLOW_SSLV3
    req_method = SSLv3_client_method();
    use_sni(FALSE);
#else
    failf(data, "CyaSSL does not support SSLv3");
    return CURLE_NOT_BUILT_IN;
#endif
    break;
  case CURL_SSLVERSION_SSLv2:
    failf(data, "CyaSSL does not support SSLv2");
    return CURLE_SSL_CONNECT_ERROR;
  default:
    failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
    return CURLE_SSL_CONNECT_ERROR;
  }

  if(!req_method) {
    failf(data, "SSL: couldn't create a method!");
    return CURLE_OUT_OF_MEMORY;
  }

  if(BACKEND->ctx)
    SSL_CTX_free(BACKEND->ctx);
  BACKEND->ctx = SSL_CTX_new(req_method);

  if(!BACKEND->ctx) {
    failf(data, "SSL: couldn't create a context!");
    return CURLE_OUT_OF_MEMORY;
  }

  switch(SSL_CONN_CONFIG(version)) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
#if LIBCYASSL_VERSION_HEX > 0x03004006 /* > 3.4.6 */
    /* Versions 3.3.0 to 3.4.6 we know the minimum protocol version is whatever
    minimum version of TLS was built in and at least TLS 1.0. For later library
    versions that could change (eg TLS 1.0 built in but defaults to TLS 1.1) so
    we have this short circuit evaluation to find the minimum supported TLS
    version. We use wolfSSL_CTX_SetMinVersion and not CyaSSL_SetMinVersion
    because only the former will work before the user's CTX callback is called.
    */
    if((wolfSSL_CTX_SetMinVersion(BACKEND->ctx, WOLFSSL_TLSV1) != 1) &&
       (wolfSSL_CTX_SetMinVersion(BACKEND->ctx, WOLFSSL_TLSV1_1) != 1) &&
       (wolfSSL_CTX_SetMinVersion(BACKEND->ctx, WOLFSSL_TLSV1_2) != 1)
#ifdef WOLFSSL_TLS13
       && (wolfSSL_CTX_SetMinVersion(BACKEND->ctx, WOLFSSL_TLSV1_3) != 1)
#endif
      ) {
      failf(data, "SSL: couldn't set the minimum protocol version");
      return CURLE_SSL_CONNECT_ERROR;
    }
#endif
    break;
  }

  ciphers = SSL_CONN_CONFIG(cipher_list);
  if(ciphers) {
    if(!SSL_CTX_set_cipher_list(BACKEND->ctx, ciphers)) {
      failf(data, "failed setting cipher list: %s", ciphers);
      return CURLE_SSL_CIPHER;
    }
    infof(data, "Cipher selection: %s\n", ciphers);
  }

#ifndef NO_FILESYSTEM
  /* load trusted cacert */
  if(SSL_CONN_CONFIG(CAfile)) {
    if(1 != SSL_CTX_load_verify_locations(BACKEND->ctx,
                                      SSL_CONN_CONFIG(CAfile),
                                      SSL_CONN_CONFIG(CApath))) {
      if(SSL_CONN_CONFIG(verifypeer)) {
        /* Fail if we insist on successfully verifying the server. */
        failf(data, "error setting certificate verify locations:\n"
              "  CAfile: %s\n  CApath: %s",
              SSL_CONN_CONFIG(CAfile)?
              SSL_CONN_CONFIG(CAfile): "none",
              SSL_CONN_CONFIG(CApath)?
              SSL_CONN_CONFIG(CApath) : "none");
        return CURLE_SSL_CACERT_BADFILE;
      }
      else {
        /* Just continue with a warning if no strict certificate
           verification is required. */
        infof(data, "error setting certificate verify locations,"
              " continuing anyway:\n");
      }
    }
    else {
      /* Everything is fine. */
      infof(data, "successfully set certificate verify locations:\n");
    }
    infof(data,
          "  CAfile: %s\n"
          "  CApath: %s\n",
          SSL_CONN_CONFIG(CAfile) ? SSL_CONN_CONFIG(CAfile):
          "none",
          SSL_CONN_CONFIG(CApath) ? SSL_CONN_CONFIG(CApath):
          "none");
  }

  /* Load the client certificate, and private key */
  if(SSL_SET_OPTION(cert) && SSL_SET_OPTION(key)) {
    int file_type = do_file_type(SSL_SET_OPTION(cert_type));

    if(SSL_CTX_use_certificate_file(BACKEND->ctx, SSL_SET_OPTION(cert),
                                     file_type) != 1) {
      failf(data, "unable to use client certificate (no key or wrong pass"
            " phrase?)");
      return CURLE_SSL_CONNECT_ERROR;
    }

    file_type = do_file_type(SSL_SET_OPTION(key_type));
    if(SSL_CTX_use_PrivateKey_file(BACKEND->ctx, SSL_SET_OPTION(key),
                                    file_type) != 1) {
      failf(data, "unable to set private key");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
#endif /* !NO_FILESYSTEM */

  /* SSL always tries to verify the peer, this only says whether it should
   * fail to connect if the verification fails, or if it should continue
   * anyway. In the latter case the result of the verification is checked with
   * SSL_get_verify_result() below. */
  SSL_CTX_set_verify(BACKEND->ctx,
                     SSL_CONN_CONFIG(verifypeer)?SSL_VERIFY_PEER:
                                                 SSL_VERIFY_NONE,
                     NULL);

#ifdef HAVE_SNI
  if(sni) {
    struct in_addr addr4;
#ifdef ENABLE_IPV6
    struct in6_addr addr6;
#endif
    const char * const hostname = SSL_IS_PROXY() ? conn->http_proxy.host.name :
      conn->host.name;
    size_t hostname_len = strlen(hostname);
    if((hostname_len < USHRT_MAX) &&
       (0 == Curl_inet_pton(AF_INET, hostname, &addr4)) &&
#ifdef ENABLE_IPV6
       (0 == Curl_inet_pton(AF_INET6, hostname, &addr6)) &&
#endif
       (CyaSSL_CTX_UseSNI(BACKEND->ctx, CYASSL_SNI_HOST_NAME, hostname,
                          (unsigned short)hostname_len) != 1)) {
      infof(data, "WARNING: failed to configure server name indication (SNI) "
            "TLS extension\n");
    }
  }
#endif

#ifdef HAVE_SUPPORTED_CURVES
  /* CyaSSL/wolfSSL does not send the supported ECC curves ext automatically:
     https://github.com/wolfSSL/wolfssl/issues/366
     The supported curves below are those also supported by OpenSSL 1.0.2 and
     in the same order. */
  CyaSSL_CTX_UseSupportedCurve(BACKEND->ctx, 0x17); /* secp256r1 */
  CyaSSL_CTX_UseSupportedCurve(BACKEND->ctx, 0x19); /* secp521r1 */
  CyaSSL_CTX_UseSupportedCurve(BACKEND->ctx, 0x18); /* secp384r1 */
#endif

  /* give application a chance to interfere with SSL set up. */
  if(data->set.ssl.fsslctx) {
    CURLcode result = CURLE_OK;
    result = (*data->set.ssl.fsslctx)(data, BACKEND->ctx,
                                      data->set.ssl.fsslctxp);
    if(result) {
      failf(data, "error signaled by ssl ctx callback");
      return result;
    }
  }
#ifdef NO_FILESYSTEM
  else if(SSL_CONN_CONFIG(verifypeer)) {
    failf(data, "SSL: Certificates couldn't be loaded because CyaSSL was built"
          " with \"no filesystem\". Either disable peer verification"
          " (insecure) or if you are building an application with libcurl you"
          " can load certificates via CURLOPT_SSL_CTX_FUNCTION.");
    return CURLE_SSL_CONNECT_ERROR;
  }
#endif

  /* Let's make an SSL structure */
  if(BACKEND->handle)
    SSL_free(BACKEND->handle);
  BACKEND->handle = SSL_new(BACKEND->ctx);
  if(!BACKEND->handle) {
    failf(data, "SSL: couldn't create a context (handle)!");
    return CURLE_OUT_OF_MEMORY;
  }

#ifdef HAVE_ALPN
  if(conn->bits.tls_enable_alpn) {
    char protocols[128];
    *protocols = '\0';

    /* wolfSSL's ALPN protocol name list format is a comma separated string of
       protocols in descending order of preference, eg: "h2,http/1.1" */

#ifdef USE_NGHTTP2
    if(data->set.httpversion >= CURL_HTTP_VERSION_2) {
      strcpy(protocols + strlen(protocols), NGHTTP2_PROTO_VERSION_ID ",");
      infof(data, "ALPN, offering %s\n", NGHTTP2_PROTO_VERSION_ID);
    }
#endif

    strcpy(protocols + strlen(protocols), ALPN_HTTP_1_1);
    infof(data, "ALPN, offering %s\n", ALPN_HTTP_1_1);

    if(wolfSSL_UseALPN(BACKEND->handle, protocols,
                       (unsigned)strlen(protocols),
                       WOLFSSL_ALPN_CONTINUE_ON_MISMATCH) != SSL_SUCCESS) {
      failf(data, "SSL: failed setting ALPN protocols");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
#endif /* HAVE_ALPN */

  /* Check if there's a cached ID we can/should use here! */
  if(SSL_SET_OPTION(primary.sessionid)) {
    void *ssl_sessionid = NULL;

    Curl_ssl_sessionid_lock(conn);
    if(!Curl_ssl_getsessionid(conn, &ssl_sessionid, NULL, sockindex)) {
      /* we got a session id, use it! */
      if(!SSL_set_session(BACKEND->handle, ssl_sessionid)) {
        Curl_ssl_sessionid_unlock(conn);
        failf(data, "SSL: SSL_set_session failed: %s",
              ERR_error_string(SSL_get_error(BACKEND->handle, 0),
              error_buffer));
        return CURLE_SSL_CONNECT_ERROR;
      }
      /* Informational message */
      infof(data, "SSL re-using session ID\n");
    }
    Curl_ssl_sessionid_unlock(conn);
  }

  /* pass the raw socket into the SSL layer */
  if(!SSL_set_fd(BACKEND->handle, (int)sockfd)) {
    failf(data, "SSL: SSL_set_fd failed");
    return CURLE_SSL_CONNECT_ERROR;
  }

  connssl->connecting_state = ssl_connect_2;
  return CURLE_OK;
}


static CURLcode
cyassl_connect_step2(struct connectdata *conn,
                     int sockindex)
{
  int ret = -1;
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data* connssl = &conn->ssl[sockindex];
  const char * const hostname = SSL_IS_PROXY() ? conn->http_proxy.host.name :
    conn->host.name;
  const char * const dispname = SSL_IS_PROXY() ?
    conn->http_proxy.host.dispname : conn->host.dispname;
  const char * const pinnedpubkey = SSL_IS_PROXY() ?
                        data->set.str[STRING_SSL_PINNEDPUBLICKEY_PROXY] :
                        data->set.str[STRING_SSL_PINNEDPUBLICKEY_ORIG];

  conn->recv[sockindex] = cyassl_recv;
  conn->send[sockindex] = cyassl_send;

  /* Enable RFC2818 checks */
  if(SSL_CONN_CONFIG(verifyhost)) {
    ret = CyaSSL_check_domain_name(BACKEND->handle, hostname);
    if(ret == SSL_FAILURE)
      return CURLE_OUT_OF_MEMORY;
  }

  ret = SSL_connect(BACKEND->handle);
  if(ret != 1) {
    char error_buffer[CYASSL_MAX_ERROR_SZ];
    int  detail = SSL_get_error(BACKEND->handle, ret);

    if(SSL_ERROR_WANT_READ == detail) {
      connssl->connecting_state = ssl_connect_2_reading;
      return CURLE_OK;
    }
    else if(SSL_ERROR_WANT_WRITE == detail) {
      connssl->connecting_state = ssl_connect_2_writing;
      return CURLE_OK;
    }
    /* There is no easy way to override only the CN matching.
     * This will enable the override of both mismatching SubjectAltNames
     * as also mismatching CN fields */
    else if(DOMAIN_NAME_MISMATCH == detail) {
#if 1
      failf(data, "\tsubject alt name(s) or common name do not match \"%s\"\n",
            dispname);
      return CURLE_PEER_FAILED_VERIFICATION;
#else
      /* When the CyaSSL_check_domain_name() is used and you desire to continue
       * on a DOMAIN_NAME_MISMATCH, i.e. 'conn->ssl_config.verifyhost == 0',
       * CyaSSL version 2.4.0 will fail with an INCOMPLETE_DATA error. The only
       * way to do this is currently to switch the CyaSSL_check_domain_name()
       * in and out based on the 'conn->ssl_config.verifyhost' value. */
      if(SSL_CONN_CONFIG(verifyhost)) {
        failf(data,
              "\tsubject alt name(s) or common name do not match \"%s\"\n",
              dispname);
        return CURLE_PEER_FAILED_VERIFICATION;
      }
      else {
        infof(data,
              "\tsubject alt name(s) and/or common name do not match \"%s\"\n",
              dispname);
        return CURLE_OK;
      }
#endif
    }
#if LIBCYASSL_VERSION_HEX >= 0x02007000 /* 2.7.0 */
    else if(ASN_NO_SIGNER_E == detail) {
      if(SSL_CONN_CONFIG(verifypeer)) {
        failf(data, "\tCA signer not available for verification\n");
        return CURLE_SSL_CACERT_BADFILE;
      }
      else {
        /* Just continue with a warning if no strict certificate
           verification is required. */
        infof(data, "CA signer not available for verification, "
                    "continuing anyway\n");
      }
    }
#endif
    else {
      failf(data, "SSL_connect failed with error %d: %s", detail,
          ERR_error_string(detail, error_buffer));
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  if(pinnedpubkey) {
#ifdef KEEP_PEER_CERT
    X509 *x509;
    const char *x509_der;
    int x509_der_len;
    curl_X509certificate x509_parsed;
    curl_asn1Element *pubkey;
    CURLcode result;

    x509 = SSL_get_peer_certificate(BACKEND->handle);
    if(!x509) {
      failf(data, "SSL: failed retrieving server certificate");
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    x509_der = (const char *)CyaSSL_X509_get_der(x509, &x509_der_len);
    if(!x509_der) {
      failf(data, "SSL: failed retrieving ASN.1 server certificate");
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    memset(&x509_parsed, 0, sizeof(x509_parsed));
    if(Curl_parseX509(&x509_parsed, x509_der, x509_der + x509_der_len))
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;

    pubkey = &x509_parsed.subjectPublicKeyInfo;
    if(!pubkey->header || pubkey->end <= pubkey->header) {
      failf(data, "SSL: failed retrieving public key from server certificate");
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    result = Curl_pin_peer_pubkey(data,
                                  pinnedpubkey,
                                  (const unsigned char *)pubkey->header,
                                  (size_t)(pubkey->end - pubkey->header));
    if(result) {
      failf(data, "SSL: public key does not match pinned public key!");
      return result;
    }
#else
    failf(data, "Library lacks pinning support built-in");
    return CURLE_NOT_BUILT_IN;
#endif
  }

#ifdef HAVE_ALPN
  if(conn->bits.tls_enable_alpn) {
    int rc;
    char *protocol = NULL;
    unsigned short protocol_len = 0;

    rc = wolfSSL_ALPN_GetProtocol(BACKEND->handle, &protocol, &protocol_len);

    if(rc == SSL_SUCCESS) {
      infof(data, "ALPN, server accepted to use %.*s\n", protocol_len,
            protocol);

      if(protocol_len == ALPN_HTTP_1_1_LENGTH &&
         !memcmp(protocol, ALPN_HTTP_1_1, ALPN_HTTP_1_1_LENGTH))
        conn->negnpn = CURL_HTTP_VERSION_1_1;
#ifdef USE_NGHTTP2
      else if(data->set.httpversion >= CURL_HTTP_VERSION_2 &&
              protocol_len == NGHTTP2_PROTO_VERSION_ID_LEN &&
              !memcmp(protocol, NGHTTP2_PROTO_VERSION_ID,
                      NGHTTP2_PROTO_VERSION_ID_LEN))
        conn->negnpn = CURL_HTTP_VERSION_2;
#endif
      else
        infof(data, "ALPN, unrecognized protocol %.*s\n", protocol_len,
              protocol);
    }
    else if(rc == SSL_ALPN_NOT_FOUND)
      infof(data, "ALPN, server did not agree to a protocol\n");
    else {
      failf(data, "ALPN, failure getting protocol, error %d", rc);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
#endif /* HAVE_ALPN */

  connssl->connecting_state = ssl_connect_3;
#if (LIBCYASSL_VERSION_HEX >= 0x03009010)
  infof(data, "SSL connection using %s / %s\n",
        wolfSSL_get_version(BACKEND->handle),
        wolfSSL_get_cipher_name(BACKEND->handle));
#else
  infof(data, "SSL connected\n");
#endif

  return CURLE_OK;
}


static CURLcode
cyassl_connect_step3(struct connectdata *conn,
                     int sockindex)
{
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  DEBUGASSERT(ssl_connect_3 == connssl->connecting_state);

  if(SSL_SET_OPTION(primary.sessionid)) {
    bool incache;
    SSL_SESSION *our_ssl_sessionid;
    void *old_ssl_sessionid = NULL;

    our_ssl_sessionid = SSL_get_session(BACKEND->handle);

    Curl_ssl_sessionid_lock(conn);
    incache = !(Curl_ssl_getsessionid(conn, &old_ssl_sessionid, NULL,
                                      sockindex));
    if(incache) {
      if(old_ssl_sessionid != our_ssl_sessionid) {
        infof(data, "old SSL session ID is stale, removing\n");
        Curl_ssl_delsessionid(conn, old_ssl_sessionid);
        incache = FALSE;
      }
    }

    if(!incache) {
      result = Curl_ssl_addsessionid(conn, our_ssl_sessionid,
                                     0 /* unknown size */, sockindex);
      if(result) {
        Curl_ssl_sessionid_unlock(conn);
        failf(data, "failed to store ssl session");
        return result;
      }
    }
    Curl_ssl_sessionid_unlock(conn);
  }

  connssl->connecting_state = ssl_connect_done;

  return result;
}


static ssize_t cyassl_send(struct connectdata *conn,
                           int sockindex,
                           const void *mem,
                           size_t len,
                           CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  char error_buffer[CYASSL_MAX_ERROR_SZ];
  int  memlen = (len > (size_t)INT_MAX) ? INT_MAX : (int)len;
  int  rc     = SSL_write(BACKEND->handle, mem, memlen);

  if(rc < 0) {
    int err = SSL_get_error(BACKEND->handle, rc);

    switch(err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      /* there's data pending, re-invoke SSL_write() */
      *curlcode = CURLE_AGAIN;
      return -1;
    default:
      failf(conn->data, "SSL write: %s, errno %d",
            ERR_error_string(err, error_buffer),
            SOCKERRNO);
      *curlcode = CURLE_SEND_ERROR;
      return -1;
    }
  }
  return rc;
}

static void Curl_cyassl_close(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  if(BACKEND->handle) {
    (void)SSL_shutdown(BACKEND->handle);
    SSL_free(BACKEND->handle);
    BACKEND->handle = NULL;
  }
  if(BACKEND->ctx) {
    SSL_CTX_free(BACKEND->ctx);
    BACKEND->ctx = NULL;
  }
}

static ssize_t cyassl_recv(struct connectdata *conn,
                           int num,
                           char *buf,
                           size_t buffersize,
                           CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = &conn->ssl[num];
  char error_buffer[CYASSL_MAX_ERROR_SZ];
  int  buffsize = (buffersize > (size_t)INT_MAX) ? INT_MAX : (int)buffersize;
  int  nread    = SSL_read(BACKEND->handle, buf, buffsize);

  if(nread < 0) {
    int err = SSL_get_error(BACKEND->handle, nread);

    switch(err) {
    case SSL_ERROR_ZERO_RETURN: /* no more data */
      break;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      /* there's data pending, re-invoke SSL_read() */
      *curlcode = CURLE_AGAIN;
      return -1;
    default:
      failf(conn->data, "SSL read: %s, errno %d",
            ERR_error_string(err, error_buffer),
            SOCKERRNO);
      *curlcode = CURLE_RECV_ERROR;
      return -1;
    }
  }
  return nread;
}


static void Curl_cyassl_session_free(void *ptr)
{
  (void)ptr;
  /* CyaSSL reuses sessions on own, no free */
}


static size_t Curl_cyassl_version(char *buffer, size_t size)
{
#if LIBCYASSL_VERSION_HEX >= 0x03006000
  return snprintf(buffer, size, "wolfSSL/%s", wolfSSL_lib_version());
#elif defined(WOLFSSL_VERSION)
  return snprintf(buffer, size, "wolfSSL/%s", WOLFSSL_VERSION);
#elif defined(CYASSL_VERSION)
  return snprintf(buffer, size, "CyaSSL/%s", CYASSL_VERSION);
#else
  return snprintf(buffer, size, "CyaSSL/%s", "<1.8.8");
#endif
}


static int Curl_cyassl_init(void)
{
  return (CyaSSL_Init() == SSL_SUCCESS);
}


static bool Curl_cyassl_data_pending(const struct connectdata* conn,
                                     int connindex)
{
  const struct ssl_connect_data *connssl = &conn->ssl[connindex];
  if(BACKEND->handle)   /* SSL is in use */
    return (0 != SSL_pending(BACKEND->handle)) ? TRUE : FALSE;
  else
    return FALSE;
}


/*
 * This function is called to shut down the SSL layer but keep the
 * socket open (CCC - Clear Command Channel)
 */
static int Curl_cyassl_shutdown(struct connectdata *conn, int sockindex)
{
  int retval = 0;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  if(BACKEND->handle) {
    SSL_free(BACKEND->handle);
    BACKEND->handle = NULL;
  }
  return retval;
}


static CURLcode
cyassl_connect_common(struct connectdata *conn,
                      int sockindex,
                      bool nonblocking,
                      bool *done)
{
  CURLcode result;
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  curl_socket_t sockfd = conn->sock[sockindex];
  time_t timeout_ms;
  int what;

  /* check if the connection has already been established */
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(ssl_connect_1 == connssl->connecting_state) {
    /* Find out how much more time we're allowed */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    result = cyassl_connect_step1(conn, sockindex);
    if(result)
      return result;
  }

  while(ssl_connect_2 == connssl->connecting_state ||
        ssl_connect_2_reading == connssl->connecting_state ||
        ssl_connect_2_writing == connssl->connecting_state) {

    /* check allowed time left */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    /* if ssl is expecting something, check if it's available. */
    if(connssl->connecting_state == ssl_connect_2_reading
       || connssl->connecting_state == ssl_connect_2_writing) {

      curl_socket_t writefd = ssl_connect_2_writing ==
        connssl->connecting_state?sockfd:CURL_SOCKET_BAD;
      curl_socket_t readfd = ssl_connect_2_reading ==
        connssl->connecting_state?sockfd:CURL_SOCKET_BAD;

      what = Curl_socket_check(readfd, CURL_SOCKET_BAD, writefd,
                               nonblocking?0:timeout_ms);
      if(what < 0) {
        /* fatal error */
        failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
        return CURLE_SSL_CONNECT_ERROR;
      }
      else if(0 == what) {
        if(nonblocking) {
          *done = FALSE;
          return CURLE_OK;
        }
        else {
          /* timeout */
          failf(data, "SSL connection timeout");
          return CURLE_OPERATION_TIMEDOUT;
        }
      }
      /* socket is readable or writable */
    }

    /* Run transaction, and return to the caller if it failed or if
     * this connection is part of a multi handle and this loop would
     * execute again. This permits the owner of a multi handle to
     * abort a connection attempt before step2 has completed while
     * ensuring that a client using select() or epoll() will always
     * have a valid fdset to wait on.
     */
    result = cyassl_connect_step2(conn, sockindex);
    if(result || (nonblocking &&
                  (ssl_connect_2 == connssl->connecting_state ||
                   ssl_connect_2_reading == connssl->connecting_state ||
                   ssl_connect_2_writing == connssl->connecting_state)))
      return result;
  } /* repeat step2 until all transactions are done. */

  if(ssl_connect_3 == connssl->connecting_state) {
    result = cyassl_connect_step3(conn, sockindex);
    if(result)
      return result;
  }

  if(ssl_connect_done == connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    conn->recv[sockindex] = cyassl_recv;
    conn->send[sockindex] = cyassl_send;
    *done = TRUE;
  }
  else
    *done = FALSE;

  /* Reset our connect state machine */
  connssl->connecting_state = ssl_connect_1;

  return CURLE_OK;
}


static CURLcode Curl_cyassl_connect_nonblocking(struct connectdata *conn,
                                                int sockindex, bool *done)
{
  return cyassl_connect_common(conn, sockindex, TRUE, done);
}


static CURLcode Curl_cyassl_connect(struct connectdata *conn, int sockindex)
{
  CURLcode result;
  bool done = FALSE;

  result = cyassl_connect_common(conn, sockindex, FALSE, &done);
  if(result)
    return result;

  DEBUGASSERT(done);

  return CURLE_OK;
}

static CURLcode Curl_cyassl_random(struct Curl_easy *data,
                                   unsigned char *entropy, size_t length)
{
  RNG rng;
  (void)data;
  if(InitRng(&rng))
    return CURLE_FAILED_INIT;
  if(length > UINT_MAX)
    return CURLE_FAILED_INIT;
  if(RNG_GenerateBlock(&rng, entropy, (unsigned)length))
    return CURLE_FAILED_INIT;
  return CURLE_OK;
}

static CURLcode Curl_cyassl_sha256sum(const unsigned char *tmp, /* input */
                                  size_t tmplen,
                                  unsigned char *sha256sum /* output */,
                                  size_t unused)
{
  Sha256 SHA256pw;
  (void)unused;
  InitSha256(&SHA256pw);
  Sha256Update(&SHA256pw, tmp, (word32)tmplen);
  Sha256Final(&SHA256pw, sha256sum);
  return CURLE_OK;
}

static void *Curl_cyassl_get_internals(struct ssl_connect_data *connssl,
                                       CURLINFO info UNUSED_PARAM)
{
  (void)info;
  return BACKEND->handle;
}

const struct Curl_ssl Curl_ssl_cyassl = {
  { CURLSSLBACKEND_WOLFSSL, "WolfSSL" }, /* info */

#ifdef KEEP_PEER_CERT
  SSLSUPP_PINNEDPUBKEY |
#endif
  SSLSUPP_SSL_CTX,

  sizeof(struct ssl_backend_data),

  Curl_cyassl_init,                /* init */
  Curl_none_cleanup,               /* cleanup */
  Curl_cyassl_version,             /* version */
  Curl_none_check_cxn,             /* check_cxn */
  Curl_cyassl_shutdown,            /* shutdown */
  Curl_cyassl_data_pending,        /* data_pending */
  Curl_cyassl_random,              /* random */
  Curl_none_cert_status_request,   /* cert_status_request */
  Curl_cyassl_connect,             /* connect */
  Curl_cyassl_connect_nonblocking, /* connect_nonblocking */
  Curl_cyassl_get_internals,       /* get_internals */
  Curl_cyassl_close,               /* close_one */
  Curl_none_close_all,             /* close_all */
  Curl_cyassl_session_free,        /* session_free */
  Curl_none_set_engine,            /* set_engine */
  Curl_none_set_engine_default,    /* set_engine_default */
  Curl_none_engines_list,          /* engines_list */
  Curl_none_false_start,           /* false_start */
  Curl_none_md5sum,                /* md5sum */
  Curl_cyassl_sha256sum            /* sha256sum */
};

#endif
