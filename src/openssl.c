/* ==========================================================================
 * openssl.c - Lua OpenSSL
 * --------------------------------------------------------------------------
 * Copyright (c)
 *    2012-2017  William Ahern <william@25thandClement.com>
 *    2015-2019  Daurnimator <quae@daurnimator.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
 * NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 * ==========================================================================
 */
#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <limits.h>       /* INT_MAX INT_MIN LLONG_MAX LLONG_MIN UCHAR_MAX ULLONG_MAX */
#include <stdint.h>       /* uintptr_t */
#include <string.h>       /* memset(3) strerror_r(3) */
#include <math.h>         /* INFINITY fabs(3) floor(3) frexp(3) fmod(3) round(3) isfinite(3) */
#include <time.h>         /* struct tm time_t strptime(3) time(2) */
#include <ctype.h>        /* isdigit(3), isxdigit(3), tolower(3) */
#include <errno.h>        /* ENOMEM ENOTSUP EOVERFLOW errno */
#include <assert.h>       /* assert */

#include <sys/stat.h>     /* struct stat stat(2) */
#ifdef _WIN32
#include <winsock2.h>     /* AF_INET, AF_INET6 */
#include <inaddr.h>       /* struct in_addr, struct in6_addr */
#include <ws2tcpip.h>     /* inet_pton */
#include <wincrypt.h>     /* CryptAcquireContext(), CryptGenRandom(), CryptReleaseContext() */
#include <windows.h>      /* CreateMutex(), GetLastError(), GetModuleHandleEx(), GetProcessTimes(), InterlockedCompareExchangePointer() */
#define EXPORT  __declspec (dllexport)
#else
#include <arpa/inet.h>    /* inet_pton(3) */
#include <dlfcn.h>        /* dladdr(3) dlopen(3) */
#include <fcntl.h>        /* O_RDONLY O_CLOEXEC open(2) */
#include <netinet/in.h>   /* struct in_addr struct in6_addr */
#include <pthread.h>      /* pthread_mutex_init(3) pthread_mutex_lock(3) pthread_mutex_unlock(3) */
#include <sys/resource.h> /* RUSAGE_SELF struct rusage getrusage(2) */
#include <sys/socket.h>   /* AF_INET AF_INET6 */
#include <sys/time.h>     /* struct timeval gettimeofday(2) */
#include <sys/types.h>    /* ssize_t pid_t */
#include <sys/utsname.h>  /* struct utsname uname(3) */
#include <unistd.h>       /* close(2) getpid(2) */
#define EXPORT
#endif

#if __APPLE__
#include <mach/mach_time.h> /* mach_absolute_time() */
#endif

#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/des.h>
#include <openssl/ocsp.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#if LUA_VERSION_NUM < 503
#include "../vendor/compat53/c-api/compat-5.3.h"
#endif

#ifndef LUAOSSL_USE_47BIT_LIGHTUSERDATA_HACK
/* LuaJIT only supports pointers with the low 47 bits set */
#if defined(LUA_JITLIBNAME) && (defined(_LP64) || defined(_LLP64) || defined(__arch64__) || defined (__arm64__) || defined (__aarch64__) || defined(_WIN64))
#define LUAOSSL_USE_47BIT_LIGHTUSERDATA_HACK 1
#else
#define LUAOSSL_USE_47BIT_LIGHTUSERDATA_HACK 0
#endif
#endif

#if LUAOSSL_USE_47BIT_LIGHTUSERDATA_HACK
#define LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(p) ((void *)((intptr_t)(p) & ((1UL<<47)-1)))
#else
#define LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(p) ((void *)(p))
#endif


#define GNUC_2VER(M, m, p) (((M) * 10000) + ((m) * 100) + (p))
#define GNUC_PREREQ(M, m, p) (__GNUC__ > 0 && GNUC_2VER(__GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__) >= GNUC_2VER((M), (m), (p)))

#define MSC_2VER(M, m, p) ((((M) + 6) * 10000000) + ((m) * 1000000) + (p))
#define MSC_PREREQ(M, m, p) (_MSC_FULL_VER > 0 && _MSC_FULL_VER >= MSC_2VER((M), (m), (p)))

#ifdef LIBRESSL_VERSION_NUMBER
#define OPENSSL_PREREQ(M, m, p) (0)
#define LIBRESSL_PREREQ(M, m, p) \
	(LIBRESSL_VERSION_NUMBER >= (((M) << 28) | ((m) << 20) | ((p) << 12)))
#else
#define OPENSSL_PREREQ(M, m, p) \
	(OPENSSL_VERSION_NUMBER >= (((M) << 28) | ((m) << 20) | ((p) << 12)))
#define LIBRESSL_PREREQ(M, m, p) (0)
#endif


#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#ifndef __has_extension
#define __has_extension(x) 0
#endif

#ifndef HAVE_C___ASSUME
#define HAVE_C___ASSUME MSC_PREREQ(8,0,0)
#endif

#ifndef HAVE_C___BUILTIN_UNREACHABLE
#define HAVE_C___BUILTIN_UNREACHABLE (GNUC_PREREQ(4,5,0) || __has_builtin(__builtin_unreachable))
#endif

#ifndef HAVE_C___DECLSPEC_NORETURN
#define HAVE_C___DECLSPEC_NORETURN MSC_PREREQ(8,0,0)
#endif

#ifndef HAVE_OPENSSL_ZALLOC
#define HAVE_OPENSSL_ZALLOC OPENSSL_PREREQ(1,1,0)
#endif

#ifndef HAVE_OPENSSL_CLEAR_FREE
#define HAVE_OPENSSL_CLEAR_FREE OPENSSL_PREREQ(1,1,0)
#endif

#ifndef HAVE_OPENSSL_MEMDUP
#define HAVE_OPENSSL_MEMDUP OPENSSL_PREREQ(1,1,0)
#endif

#ifndef HAVE_ASN1_STRING_GET0_DATA
#define HAVE_ASN1_STRING_GET0_DATA (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_DH_GET0_KEY
#define HAVE_DH_GET0_KEY (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_DH_GET0_PQG
#define HAVE_DH_GET0_PQG (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_DH_SET0_KEY
#define HAVE_DH_SET0_KEY (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_DH_SET0_PQG
#define HAVE_DH_SET0_PQG (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_DSA_GET0_KEY
#define HAVE_DSA_GET0_KEY (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_DSA_GET0_PQG
#define HAVE_DSA_GET0_PQG (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_DSA_SET0_KEY
#define HAVE_DSA_SET0_KEY (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_DSA_SET0_PQG
#define HAVE_DSA_SET0_PQG (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_DTLSV1_CLIENT_METHOD
#ifdef OPENSSL_NO_DTLS1
#define HAVE_DTLSV1_CLIENT_METHOD (0)
#else
#define HAVE_DTLSV1_CLIENT_METHOD (1)
#endif
#endif

#ifndef HAVE_DTLSV1_SERVER_METHOD
#define HAVE_DTLSV1_SERVER_METHOD HAVE_DTLSV1_CLIENT_METHOD
#endif

#ifndef HAVE_DTLS_CLIENT_METHOD
#ifdef OPENSSL_NO_DTLS1
#define HAVE_DTLS_CLIENT_METHOD (0)
#else
#define HAVE_DTLS_CLIENT_METHOD OPENSSL_PREREQ(1,0,2)
#endif
#endif

#ifndef HAVE_DTLS_SERVER_METHOD
#define HAVE_DTLS_SERVER_METHOD HAVE_DTLS_CLIENT_METHOD
#endif

#ifndef HAVE_DTLSV1_2_CLIENT_METHOD
#ifdef OPENSSL_NO_DTLS1
#define HAVE_DTLSV1_2_CLIENT_METHOD (0)
#else
#define HAVE_DTLSV1_2_CLIENT_METHOD OPENSSL_PREREQ(1,0,2)
#endif
#endif

#ifndef HAVE_DTLSV1_2_SERVER_METHOD
#define HAVE_DTLSV1_2_SERVER_METHOD HAVE_DTLSV1_2_CLIENT_METHOD
#endif

#ifndef HAVE_EVP_CIPHER_CTX_FREE
#define HAVE_EVP_CIPHER_CTX_FREE (OPENSSL_PREREQ(1,0,0) || LIBRESSL_PREREQ(2,0,0))
#endif

#ifndef HAVE_EVP_CIPHER_CTX_NEW
#define HAVE_EVP_CIPHER_CTX_NEW (OPENSSL_PREREQ(1,0,0) || LIBRESSL_PREREQ(2,0,0))
#endif

#ifndef HAVE_EVP_KDF_CTX
#define HAVE_EVP_KDF_CTX OPENSSL_PREREQ(3,0,0)
#endif

#ifndef HAVE_OSSL_PARAM
#define HAVE_OSSL_PARAM OPENSSL_PREREQ(3,0,0)
#endif

#ifndef HAVE_PKCS5_PBKDF2_HMAC
#define HAVE_PKCS5_PBKDF2_HMAC (OPENSSL_PREREQ(1,0,0) || LIBRESSL_PREREQ(2,0,0))
#endif

#ifndef HAVE_SCRYPT
#define HAVE_SCRYPT OPENSSL_PREREQ(1,1,0)
#endif

#ifndef HAVE_EVP_MD_CTX_FREE
#define HAVE_EVP_MD_CTX_FREE (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_EVP_MD_CTX_NEW
#define HAVE_EVP_MD_CTX_NEW (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_EVP_PKEY_GET_DEFAULT_DIGEST_NID
#define HAVE_EVP_PKEY_GET_DEFAULT_DIGEST_NID (OPENSSL_PREREQ(1,0,0) || LIBRESSL_PREREQ(2,0,0))
#endif

#ifndef HAVE_EVP_PKEY_BASE_ID
#define HAVE_EVP_PKEY_BASE_ID (OPENSSL_PREREQ(1,0,0) || LIBRESSL_PREREQ(2,0,0))
#endif

#ifndef HAVE_EVP_PKEY_CTX_NEW
#define HAVE_EVP_PKEY_CTX_NEW (OPENSSL_PREREQ(1,0,0) || LIBRESSL_PREREQ(2,0,0))
#endif

#ifndef HAVE_EVP_PKEY_CTX_KDF
#define HAVE_EVP_PKEY_CTX_KDF OPENSSL_PREREQ(1,1,0)
#endif

#ifndef HAVE_EVP_PKEY_CTX_HKDF_MODE
#define HAVE_EVP_PKEY_CTX_HKDF_MODE (HAVE_EVP_PKEY_CTX_KDF && OPENSSL_PREREQ(1,1,1))
#endif

#ifndef HAVE_EVP_PKEY_GET0
#define HAVE_EVP_PKEY_GET0 (OPENSSL_PREREQ(1,0,0) || LIBRESSL_PREREQ(2,0,0))
#endif

#ifndef HAVE_EVP_PKEY_GET0_RSA
#define HAVE_EVP_PKEY_GET0_RSA (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,5))
#endif

#ifndef HAVE_EVP_PKEY_GET0_DSA
#define HAVE_EVP_PKEY_GET0_DSA (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,5))
#endif

#ifndef HAVE_EVP_PKEY_GET0_DH
#define HAVE_EVP_PKEY_GET0_DH (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,5))
#endif

#ifndef HAVE_EVP_PKEY_GET0_EC_KEY
#define HAVE_EVP_PKEY_GET0_EC_KEY (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,5))
#endif

#ifndef HAVE_EVP_PKEY_ID
#define HAVE_EVP_PKEY_ID (OPENSSL_PREREQ(1,0,0) || LIBRESSL_PREREQ(2,0,0))
#endif

#ifndef HAVE_EVP_PKEY_KEYGEN
#define HAVE_EVP_PKEY_KEYGEN (OPENSSL_PREREQ(1,0,0) || LIBRESSL_PREREQ(2,0,0))
#endif

#ifndef HAVE_EVP_PKEY_RAW
#define HAVE_EVP_PKEY_RAW OPENSSL_PREREQ(1,1,1)
#endif

#ifndef HAVE_HMAC_CTX_FREE
#define HAVE_HMAC_CTX_FREE (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_HMAC_CTX_NEW
#define HAVE_HMAC_CTX_NEW (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_I2D_RE_X509_REQ_TBS
#define HAVE_I2D_RE_X509_REQ_TBS OPENSSL_PREREQ(1,1,0)
#endif

#ifndef HAVE_RSA_GET0_CRT_PARAMS
#define HAVE_RSA_GET0_CRT_PARAMS (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_RSA_GET0_FACTORS
#define HAVE_RSA_GET0_FACTORS (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_RSA_GET0_KEY
#define HAVE_RSA_GET0_KEY (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_RSA_SET0_CRT_PARAMS
#define HAVE_RSA_SET0_CRT_PARAMS (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_RSA_SET0_FACTORS
#define HAVE_RSA_SET0_FACTORS (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_RSA_SET0_KEY
#define HAVE_RSA_SET0_KEY (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_SSL_CLIENT_VERSION
#define HAVE_SSL_CLIENT_VERSION OPENSSL_PREREQ(1,1,0)
#endif

#ifndef HAVE_SSL_CTX_ADD_CUSTOM_EXT
#define HAVE_SSL_CTX_ADD_CUSTOM_EXT OPENSSL_PREREQ(1,1,1)
#endif

#ifndef HAVE_SSL_CTX_GET0_CHAIN_CERTS
#define HAVE_SSL_CTX_GET0_CHAIN_CERTS OPENSSL_PREREQ(1,0,2)
#endif

#ifndef HAVE_SSL_CTX_GET0_PARAM
#define HAVE_SSL_CTX_GET0_PARAM (OPENSSL_PREREQ(1,0,2) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_SSL_CTX_GET0_CERTIFICATE
#define HAVE_SSL_CTX_GET0_CERTIFICATE (OPENSSL_PREREQ(1,0,2) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_SSL_CTX_SET_CIPHERSUITES
#define HAVE_SSL_CTX_SET_CIPHERSUITES OPENSSL_PREREQ(1,1,1)
#endif

#ifndef HAVE_SSL_CTX_SET_CURVES_LIST
#define HAVE_SSL_CTX_SET_CURVES_LIST (OPENSSL_PREREQ(1,0,2) || LIBRESSL_PREREQ(2,5,1))
#endif

#ifndef HAVE_SSL_CTX_SET_GROUPS_LIST
#if OPENSSL_PREREQ(1,1,1)
#define HAVE_SSL_CTX_SET_GROUPS_LIST 1
#elif HAVE_SSL_CTX_SET_CURVES_LIST
#define SSL_CTX_set1_groups_list SSL_CTX_set1_curves_list
#define HAVE_SSL_CTX_SET_GROUPS_LIST 1
#else
#define HAVE_SSL_CTX_SET_GROUPS_LIST 0
#endif
#endif

#ifndef HAVE_SSL_CTX_SET_GROUPS_LIST
#define HAVE_SSL_CTX_SET_GROUPS_LIST OPENSSL_PREREQ(1,1,1)
#endif

#ifndef HAVE_SSL_CTX_SET_ECDH_AUTO
#define HAVE_SSL_CTX_SET_ECDH_AUTO ((OPENSSL_PREREQ(1,0,2) && !OPENSSL_PREREQ(1,1,0)) || LIBRESSL_PREREQ(2,1,2))
#endif

#ifndef HAVE_SSL_CTX_SET_ALPN_PROTOS
#define HAVE_SSL_CTX_SET_ALPN_PROTOS (OPENSSL_PREREQ(1,0,2) || LIBRESSL_PREREQ(2,1,3))
#endif

#ifndef HAVE_SSL_CTX_SET_ALPN_SELECT_CB
#define HAVE_SSL_CTX_SET_ALPN_SELECT_CB HAVE_SSL_CTX_SET_ALPN_PROTOS
#endif

#ifndef HAVE_SSL_CTX_SET_TLSEXT_SERVERNAME_CALLBACK
#define HAVE_SSL_CTX_SET_TLSEXT_SERVERNAME_CALLBACK (OPENSSL_PREREQ(1,0,0) || LIBRESSL_PREREQ(2,0,0))
#endif

#ifndef HAVE_SSL_CTX_SET1_CERT_STORE
#define HAVE_SSL_CTX_SET1_CERT_STORE (HAVE_SSL_CTX_set1_cert_store || OPENSSL_PREREQ(1,1,1)) /* backwards compatible with old macro name */
#endif

#ifndef HAVE_SSL_CTX_SET1_CHAIN
#define HAVE_SSL_CTX_SET1_CHAIN OPENSSL_PREREQ(1,0,2)
#endif

#ifndef HAVE_SSL_CTX_SET1_PARAM
#define HAVE_SSL_CTX_SET1_PARAM (OPENSSL_PREREQ(1,0,2) || LIBRESSL_PREREQ(2,1,0))
#endif

#ifndef HAVE_SSL_CTX_UP_REF
#define HAVE_SSL_CTX_UP_REF (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_SSL_CTX_CERT_STORE
#define HAVE_SSL_CTX_CERT_STORE (!OPENSSL_PREREQ(1,1,0))
#endif

#ifndef HAVE_SSL_CTX_SET_TLSEXT_STATUS_TYPE
#define HAVE_SSL_CTX_SET_TLSEXT_STATUS_TYPE OPENSSL_PREREQ(1,1,0)
#endif

#ifndef HAVE_SSL_CTX_GET_TLSEXT_STATUS_TYPE
#define HAVE_SSL_CTX_GET_TLSEXT_STATUS_TYPE OPENSSL_PREREQ(1,1,0)
#endif

#ifndef HAVE_SSL_CTX_SET_TLSEXT_TICKET_KEYS
#define HAVE_SSL_CTX_SET_TLSEXT_TICKET_KEYS OPENSSL_PREREQ(1,0,0)
#endif

#ifndef HAVE_SSL_CTX_GET_TLSEXT_TICKET_KEYS
#define HAVE_SSL_CTX_GET_TLSEXT_TICKET_KEYS OPENSSL_PREREQ(1,0,0)
#endif

#ifndef HAVE_SSL_CTX_USE_SERVERINFO
#define HAVE_SSL_CTX_USE_SERVERINFO OPENSSL_PREREQ(1,0,2)
#endif

#ifndef HAVE_SSL_CTX_USE_SERVERINFO_EX
#define HAVE_SSL_CTX_USE_SERVERINFO_EX OPENSSL_PREREQ(1,1,1)
#endif

#ifndef HAVE_SSL_CTX_USE_SERVERINFO_FILE
#define HAVE_SSL_CTX_USE_SERVERINFO_FILE OPENSSL_PREREQ(1,0,2)
#endif

#ifndef HAVE_SSL_EXTENSION_SUPPORTED
#define HAVE_SSL_EXTENSION_SUPPORTED OPENSSL_PREREQ(1,0,2)
#endif

#ifndef HAVE_SSL_GET0_ALPN_SELECTED
#define HAVE_SSL_GET0_ALPN_SELECTED HAVE_SSL_CTX_SET_ALPN_PROTOS
#endif

#ifndef HAVE_SSL_GET0_CHAIN_CERTS
#define HAVE_SSL_GET0_CHAIN_CERTS OPENSSL_PREREQ(1,0,2)
#endif

#ifndef HAVE_SSL_GET0_PARAM
#define HAVE_SSL_GET0_PARAM (OPENSSL_PREREQ(1,0,2) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_SSL_SET_ALPN_PROTOS
#define HAVE_SSL_SET_ALPN_PROTOS HAVE_SSL_CTX_SET_ALPN_PROTOS
#endif

#ifndef HAVE_SSL_SET1_CHAIN_CERT_STORE
#define HAVE_SSL_SET1_CHAIN_CERT_STORE OPENSSL_PREREQ(1,0,2)
#endif

#ifndef HAVE_SSL_SET1_VERIFY_CERT_STORE
#define HAVE_SSL_SET1_VERIFY_CERT_STORE OPENSSL_PREREQ(1,0,2)
#endif

#ifndef HAVE_SSL_SET_CIPHERSUITES
#define HAVE_SSL_SET_CIPHERSUITES OPENSSL_PREREQ(1,1,1)
#endif

#ifndef HAVE_SSL_SET_CURVES_LIST
#define HAVE_SSL_SET_CURVES_LIST (OPENSSL_PREREQ(1,0,2) || LIBRESSL_PREREQ(2,5,1))
#endif

#ifndef HAVE_SSL_SET_GROUPS_LIST
#if OPENSSL_PREREQ(1,1,1)
#define HAVE_SSL_SET_GROUPS_LIST 1
#elif HAVE_SSL_SET_CURVES_LIST
#define SSL_set1_groups_list SSL_set1_curves_list
#define HAVE_SSL_SET_GROUPS_LIST 1
#else
#define HAVE_SSL_SET_GROUPS_LIST 0
#endif
#endif

#ifndef HAVE_SSL_SET1_CHAIN
#define HAVE_SSL_SET1_CHAIN OPENSSL_PREREQ(1,0,2)
#endif

#ifndef HAVE_SSL_SET1_PARAM
#define HAVE_SSL_SET1_PARAM (OPENSSL_PREREQ(1,0,2) || LIBRESSL_PREREQ(2,5,1))
#endif

#ifndef HAVE_SSL_GET_CLIENT_RANDOM
#define HAVE_SSL_GET_CLIENT_RANDOM (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_SSL_GET_SERVER_TMP_KEY
#define HAVE_SSL_GET_SERVER_TMP_KEY (OPENSSL_PREREQ(1,0,2) || LIBRESSL_PREREQ(2,5,3))
#endif

#ifndef HAVE_SSL_GET_TLSEXT_STATUS_TYPE
#define HAVE_SSL_GET_TLSEXT_STATUS_TYPE OPENSSL_PREREQ(1,1,0)
#endif

#ifndef HAVE_SSL_UP_REF
#define HAVE_SSL_UP_REF (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_SSL_OP_NO_SSL_MASK
#ifdef SSL_OP_NO_SSL_MASK
#define HAVE_SSL_OP_NO_SSL_MASK (1)
#else
#define HAVE_SSL_OP_NO_SSL_MASK (0)
#endif
#endif

#ifndef HAVE_SSL_OP_NO_DTLS_MASK
#ifdef SSL_OP_NO_DTLS_MASK
#define HAVE_SSL_OP_NO_DTLS_MASK (1)
#else
#define HAVE_SSL_OP_NO_DTLS_MASK (0)
#endif
#endif

#ifndef HAVE_SSL_SESSION_MASTER_KEY
#define HAVE_SSL_SESSION_MASTER_KEY (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_STACK_OPENSSL_STRING_FUNCS
#define HAVE_STACK_OPENSSL_STRING_FUNCS (OPENSSL_PREREQ(1,0,0) || LIBRESSL_PREREQ(2,0,0))
#endif

#ifndef HAVE_X509_CHAIN_UP_REF
#define HAVE_X509_CHAIN_UP_REF OPENSSL_PREREQ(1,0,2)
#endif

#ifndef HAVE_X509_CRL_GET0_LASTUPDATE
#define HAVE_X509_CRL_GET0_LASTUPDATE (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_X509_CRL_GET0_NEXTUPDATE
#define HAVE_X509_CRL_GET0_NEXTUPDATE (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_X509_CRL_GET0_BY_CERT
#define HAVE_X509_CRL_GET0_BY_CERT (OPENSSL_PREREQ(1,0,0) || LIBRESSL_PREREQ(2,0,0))
#endif

#ifndef HAVE_X509_CRL_GET0_BY_SERIAL
#define HAVE_X509_CRL_GET0_BY_SERIAL (OPENSSL_PREREQ(1,0,0) || LIBRESSL_PREREQ(2,0,0))
#endif

#ifndef HAVE_X509_CRL_SET1_LASTUPDATE
#define HAVE_X509_CRL_SET1_LASTUPDATE (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_X509_CRL_SET1_NEXTUPDATE
#define HAVE_X509_CRL_SET1_NEXTUPDATE (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_X509_GET_SIGNATURE_NID
#define HAVE_X509_GET_SIGNATURE_NID (OPENSSL_PREREQ(1,0,2) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_X509_STORE_REFERENCES
#define HAVE_X509_STORE_REFERENCES (!OPENSSL_PREREQ(1,1,0))
#endif

#ifndef HAVE_X509_STORE_UP_REF
#define HAVE_X509_STORE_UP_REF (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_X509_UP_REF
#define HAVE_X509_UP_REF (OPENSSL_PREREQ(1,1,0) || LIBRESSL_PREREQ(2,5,1))
#endif

#ifndef HAVE_X509_VERIFY_PARAM_ADD1_HOST
#define HAVE_X509_VERIFY_PARAM_ADD1_HOST (OPENSSL_PREREQ(1,0,2) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_X509_VERIFY_PARAM_SET_AUTH_LEVEL
#define HAVE_X509_VERIFY_PARAM_SET_AUTH_LEVEL OPENSSL_PREREQ(1,1,0)
#endif

#ifndef HAVE_X509_VERIFY_PARAM_SET1_EMAIL
#define HAVE_X509_VERIFY_PARAM_SET1_EMAIL (OPENSSL_PREREQ(1,0,2) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_X509_VERIFY_PARAM_SET1_HOST
#define HAVE_X509_VERIFY_PARAM_SET1_HOST (OPENSSL_PREREQ(1,0,2) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HAVE_X509_VERIFY_PARAM_SET1_IP_ASC
#define HAVE_X509_VERIFY_PARAM_SET1_IP_ASC (OPENSSL_PREREQ(1,0,2) || LIBRESSL_PREREQ(2,7,0))
#endif

#ifndef HMAC_INIT_EX_INT
#define HMAC_INIT_EX_INT OPENSSL_PREREQ(1,0,0)
#endif

#if HAVE_EVP_PKEY_CTX_KDF || HAVE_EVP_KDF_CTX
#include <openssl/kdf.h>
#endif

#if HAVE_EVP_KDF_CTX
#include <openssl/core_names.h>
#endif

#ifndef STRERROR_R_CHAR_P
#ifdef __GLIBC__
#define STRERROR_R_CHAR_P (_GNU_SOURCE || !(_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600))
#else
#define STRERROR_R_CHAR_P (0)
#endif
#endif

#ifndef LIST_HEAD
#define LIST_HEAD(name, type) struct name { struct type *lh_first; }
#define LIST_ENTRY(type) struct { struct type *le_next, **le_prev; }
#define LIST_INIT(head) do { LIST_FIRST((head)) = NULL; } while (0)
#define LIST_FIRST(head) ((head)->lh_first)
#define LIST_NEXT(elm, field) ((elm)->field.le_next)
#define LIST_REMOVE(elm, field) do { \
	if (LIST_NEXT((elm), field) != NULL) \
		LIST_NEXT((elm), field)->field.le_prev = (elm)->field.le_prev; \
	*(elm)->field.le_prev = LIST_NEXT((elm), field); \
} while (0)
#define LIST_INSERT_HEAD(head, elm, field) do { \
	if ((LIST_NEXT((elm), field) = LIST_FIRST((head))) != NULL) \
		LIST_FIRST((head))->field.le_prev = &LIST_NEXT((elm), field); \
	LIST_FIRST((head)) = (elm); \
	(elm)->field.le_prev = &LIST_FIRST((head)); \
} while (0)
#endif

#define BIGNUM_CLASS     "BIGNUM*"
#define PKEY_CLASS       "EVP_PKEY*"
#define EC_GROUP_CLASS   "EVP_GROUP*"
#define X509_NAME_CLASS  "X509_NAME*"
#define X509_GENS_CLASS  "GENERAL_NAMES*"
#define X509_EXT_CLASS   "X509_EXTENSION*"
#define X509_CERT_CLASS  "X509*"
#define X509_CHAIN_CLASS "STACK_OF(X509)*"
#define X509_CSR_CLASS   "X509_REQ*"
#define X509_CRL_CLASS   "X509_CRL*"
#define X509_STORE_CLASS "X509_STORE*"
#define X509_VERIFY_PARAM_CLASS "X509_VERIFY_PARAM*"
#define X509_STCTX_CLASS "X509_STORE_CTX*"
#define PKCS12_CLASS     "PKCS12*"
#define SSL_CTX_CLASS    "SSL_CTX*"
#define SSL_CLASS        "SSL*"
#define DIGEST_CLASS     "EVP_MD_CTX*"
#define HMAC_CLASS       "HMAC_CTX*"
#define CIPHER_CLASS     "EVP_CIPHER_CTX*"
#define OCSP_RESPONSE_CLASS "OCSP_RESPONSE*"
#define OCSP_BASICRESP_CLASS "OCSP_BASICRESP*"


#if __GNUC__
#define NOTUSED __attribute__((unused))
#else
#define NOTUSED
#endif

#if HAVE_C___BUILTIN_UNREACHABLE
#define NOTREACHED __builtin_unreachable()
#elif HAVE_C___ASSUME
#define NOTREACHED __assume(0)
#else
#define NOTREACHED (void)0
#endif

#define countof(a) (sizeof (a) / sizeof *(a))
#define endof(a) (&(a)[countof(a)])

#define CLAMP(i, min, max) (((i) < (min))? (min) : ((i) > (max))? (max) : (i))

#undef MIN
#define MIN(a, b) (((a) < (b))? (a) : (b))

#ifdef _WIN32
#if !defined(S_ISDIR) && defined(_S_IFDIR) && defined(_S_IFDIR)
#define S_ISDIR(m) (((m) & _S_IFDIR) == _S_IFDIR)
#endif

#define stricmp(a, b) _stricmp((a), (b))
#else
#include <strings.h>      /* strcasecmp(3) */
#define stricmp(a, b) strcasecmp((a), (b))
#endif
#define strieq(a, b) (!stricmp((a), (b)))

#define xtolower(c) tolower((unsigned char)(c))

#define SAY_(file, func, line, fmt, ...) \
	fprintf(stderr, "%s:%d: " fmt "%s", __func__, __LINE__, __VA_ARGS__)

#define SAY(...) SAY_(__FILE__, __func__, __LINE__, __VA_ARGS__, "\n")

#define HAI SAY("hai")


#define xitoa_putc(c) do { if (p < lim) dst[p] = (c); p++; } while (0)

static const char *xitoa(char *dst, size_t lim, long i) {
	size_t p = 0;
	unsigned long d = 1000000000UL, n = 0, r;

	if (i < 0) {
		xitoa_putc('-');
		i *= -1;
	}

	if ((i = MIN(2147483647L, i))) {
		do {
			if ((r = i / d) || n) {
				i -= r * d;
				n++;
				xitoa_putc('0' + r);
			}
		} while (d /= 10);
	} else {
		xitoa_putc('0');
	}

	if (lim)
		dst[MIN(p, lim - 1)] = '\0';

	return dst;
} /* xitoa() */


static _Bool checkbool(lua_State *L, int idx) {
	luaL_checktype(L, idx, LUA_TBOOLEAN);
	return lua_toboolean(L, idx);
} /* optbool() */


static _Bool optbool(lua_State *L, int idx, _Bool d) {
	if (lua_isnoneornil(L, idx))
		return d;
	return checkbool(L, idx);
} /* optbool() */


static void *prepudata(lua_State *L, size_t size, const char *tname, int (*gc)(lua_State *)) {
	void *p = memset(lua_newuserdata(L, size), 0, size);

	if (tname) {
		luaL_setmetatable(L, tname);
	} else {
		lua_newtable(L);
		lua_pushcfunction(L, gc);
		lua_setfield(L, -2, "__gc");
		lua_setmetatable(L, -2);
	}

	return p;
} /* prepudata() */


static void *prepsimple(lua_State *L, const char *tname, int (*gc)(lua_State *)) {
	void **p = prepudata(L, sizeof (void *), tname, gc);
	return p;
} /* prepsimple() */

#define EXPAND( x ) x
#define prepsimple_(a, b, c, ...) prepsimple((a), (b), (c))
#define prepsimple(...) EXPAND( prepsimple_(__VA_ARGS__, 0, 0) )


static void *checksimple(lua_State *L, int index, const char *tname) {
	void **p;

	if (tname) {
		p = luaL_checkudata(L, index, tname);
	} else {
		luaL_checktype(L, index, LUA_TUSERDATA);
		p = lua_touserdata(L, index);
	}

	return *p;
} /* checksimple() */


static void *testsimple(lua_State *L, int index, const char *tname) {
	void **p;

	if (tname) {
		p = luaL_testudata(L, index, tname);
	} else {
		luaL_checktype(L, index, LUA_TUSERDATA);
		p = lua_touserdata(L, index);
	}

	return (p)? *p : (void *)0;
} /* testsimple() */


static int auxL_swapmetatable(lua_State *, const char *);
static int auxL_swapmetasubtable(lua_State *, const char *, const char *);

static int interpose(lua_State *L, const char *mt) {
	if (!strncmp("__", luaL_checkstring(L, lua_absindex(L, -2)), 2)) {
		return auxL_swapmetatable(L, mt);
	} else {
		return auxL_swapmetasubtable(L, mt, "__index");
	}
} /* interpose() */

static int auxL_checkoption(lua_State *, int, const char *, const char *const *, _Bool);

#define X509_ANY 0x01
#define X509_PEM 0x02
#define X509_DER 0x04
#define X509_TXT 0x08 /* "pretty" */
#define X509_ALL (X509_PEM|X509_DER)

static int optencoding(lua_State *L, int index, const char *def, int allow) {
	static const char *const opts[] = { "*", "pem", "der", "pretty", NULL };
	int type = 0;

	switch (auxL_checkoption(L, index, def, opts, 1)) {
	case 0:
		type = X509_ANY;
		break;
	case 1:
		type = X509_PEM;
		break;
	case 2:
		type = X509_DER;
		break;
	case 3:
		type = X509_TXT;
		break;
	}

	if (!(type & allow))
		luaL_argerror(L, index, lua_pushfstring(L, "invalid option %s", luaL_checkstring(L, index)));

	return type;
} /* optencoding() */


static _Bool rawgeti(lua_State *L, int index, int n) {
	lua_rawgeti(L, index, n);

	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);

		return 0;
	} else {
		return 1;
	}
} /* rawgeti() */


/* check ALPN protocols and add to buffer of length-prefixed strings */
static void checkprotos(luaL_Buffer *B, lua_State *L, int index) {
	int n;

	luaL_checktype(L, index, LUA_TTABLE);

	for (n = 1; rawgeti(L, index, n); n++) {
		const char *tmp;
		size_t len;

		switch (lua_type(L, -1)) {
		case LUA_TSTRING:
			break;
		default:
			luaL_argerror(L, index, "array of strings expected");
		}

		tmp = luaL_checklstring(L, -1, &len);
		luaL_argcheck(L, len > 0 && len <= UCHAR_MAX, index, "proto string length invalid");
		luaL_addchar(B, (unsigned char)len);
		luaL_addlstring(B, tmp, len);
		lua_pop(L, 1);
	}
} /* checkprotos() */

static void pushprotos(lua_State *L, const unsigned char *p, size_t n) {
	const unsigned char *pe = &p[n];
	int i = 0;

	lua_newtable(L);

	while (p < pe) {
		n = *p++;

		if ((size_t)(pe - p) < n)
			luaL_error(L, "corrupt ALPN protocol list (%zu > %zu)", n, (size_t)(pe - p));

		lua_pushlstring(L, (const void *)p, n);
		lua_rawseti(L, -2, ++i);
		p += n;
	}
} /* pushprotos() */


static _Bool getfield(lua_State *L, int index, const char *k) {
	lua_getfield(L, index, k);

	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);

		return 0;
	} else {
		return 1;
	}
} /* getfield() */


static _Bool (loadfield)(lua_State *L, int index, const char *k, int type, void *p, size_t *l) {
	if (!getfield(L, index, k))
		return 0;

	switch (type) {
	case LUA_TSTRING:
		*(const char **)p = luaL_checklstring(L, -1, l);
		break;
	case LUA_TNUMBER:
		*(lua_Number *)p = luaL_checknumber(L, -1);
		break;
	default:
		luaL_error(L, "loadfield(type=%d): invalid type", type);
		break;
	} /* switch() */

	lua_pop(L, 1); /* table keeps reference */

	return 1;
} /* loadfield() */
#define loadfield_(L, idx, k, type, p, l, ...) loadfield((L), (idx), (k), (type), (p), (l))
#define loadfield(...) EXPAND( loadfield_(__VA_ARGS__, NULL) )


static void *loadfield_udata(lua_State *L, int index, const char *k, const char *tname) {
	if (!getfield(L, index, k))
		return NULL;

	void **p = luaL_checkudata(L, -1, tname);

	lua_pop(L, 1); /* table keeps reference */

	return *p;
} /* loadfield_udata() */


/* Forward declaration */
static void ssl_push(lua_State *, SSL *);


/*
 * Auxiliary C routines
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define AUX_MIN(a, b) (((a) < (b))? (a) : (b))

static size_t aux_strlcpy(char *dst, const char *src, size_t lim) {
	size_t n = strlen(src);

	if (lim > 0) {
		size_t m = AUX_MIN(lim - 1, n);

		memcpy(dst, src, m);
		dst[m] = '\0';
	}

	return n;
} /* aux_strlcpy() */

#define aux_strerror(error) aux_strerror_r((error), (char[256]){ 0 }, 256)

static const char *aux_strerror_r(int error, char *dst, size_t lim) {
	static const char unknown[] = "Unknown error: ";
	size_t n;

#if _WIN32
	errno_t rv = strerror_s(dst, lim, error);

	if (rv)
		return dst;
#elif STRERROR_R_CHAR_P
	char *rv = strerror_r(error, dst, lim);

	if (rv != NULL)
		return rv;
#else
	int rv = strerror_r(error, dst, lim);

	if (0 == rv)
		return dst;
#endif

	/*
	 * glibc snprintf can fail on memory pressure, so format our number
	 * manually.
	 */
	n = MIN(sizeof unknown - 1, lim);
	memcpy(dst, unknown, n);

	return xitoa(&dst[n], lim - n, error);
} /* aux_strerror_r() */


/*
 * Auxiliary OpenSSL API routines
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static void auxS_bn_free_and_set0(BIGNUM **dst, BIGNUM *src) {
	if (*dst) {
		BN_clear_free(*dst);
	}
	*dst = src;
} /* auxS_bn_free_and_set0() */

static size_t auxS_nid2sn(void *dst, size_t lim, int nid) {
	const char *sn;

	if (nid == NID_undef || !(sn = OBJ_nid2sn(nid)))
		return 0;

	return aux_strlcpy(dst, sn, lim);
} /* aux2_nid2sn() */

static size_t auxS_obj2sn(void *dst, size_t lim, const ASN1_OBJECT *obj) {
	return auxS_nid2sn(dst, lim, OBJ_obj2nid(obj));
} /* auxS_obj2sn() */

static size_t auxS_nid2ln(void *dst, size_t lim, int nid) {
	const char *ln;

	if (nid == NID_undef || !(ln = OBJ_nid2ln(nid)))
		return 0;

	return aux_strlcpy(dst, ln, lim);
} /* aux2_nid2ln() */

static size_t auxS_obj2ln(void *dst, size_t lim, const ASN1_OBJECT *obj) {
	return auxS_nid2ln(dst, lim, OBJ_obj2nid(obj));
} /* auxS_obj2ln() */

static size_t auxS_obj2id(void *dst, size_t lim, const ASN1_OBJECT *obj) {
	int n = OBJ_obj2txt(dst, AUX_MIN(lim, INT_MAX), obj, 1);

	/* TODO: push custom errors onto error stack */
	if (n == 0) {
		return 0; /* obj->data == NULL */
	} else if (n < 0) {
		return 0; /* memory allocation error */
	} else {
		return n;
	}
} /* auxS_obj2id() */

static size_t auxS_nid2id(void *dst, size_t lim, int nid) {
	ASN1_OBJECT *obj;

	/* TODO: push custom error onto error stack */
	if (!(obj = OBJ_nid2obj(nid)))
		return 0;

	return auxS_obj2id(dst, lim, obj);
} /* auxS_nid2id() */

static size_t auxS_nid2txt(void *dst, size_t lim, int nid) {
	size_t n;

	if ((n = auxS_nid2sn(dst, lim, nid)))
		return n;
	if ((n = auxS_nid2ln(dst, lim, nid)))
		return n;

	return auxS_nid2id(dst, lim, nid);
} /* auxS_nid2txt() */

static size_t auxS_obj2txt(void *dst, size_t lim, const ASN1_OBJECT *obj) {
	size_t n;

	if ((n = auxS_obj2sn(dst, lim, obj)))
		return n;
	if ((n = auxS_obj2ln(dst, lim, obj)))
		return n;

	return auxS_obj2id(dst, lim, obj);
} /* auxS_obj2txt() */

static const EVP_MD *auxS_todigest(const char *name, EVP_PKEY *key, const EVP_MD *def);

static _Bool auxS_isoid(const char *txt) {
	return (*txt >= '0' && *txt <= '9');
} /* auxS_isoid() */

static _Bool auxS_txt2obj(ASN1_OBJECT **obj, const char *txt) {
	int nid;

	if ((nid = OBJ_sn2nid(txt)) != NID_undef
	||  (nid = OBJ_ln2nid(txt)) != NID_undef) {
		return NULL != (*obj = OBJ_nid2obj(nid));
	} else if (auxS_isoid(txt)) {
		return NULL != (*obj = OBJ_txt2obj(txt, 1));
	} else {
		*obj = NULL;
		return 1;
	}
} /* auxS_txt2obj() */

static _Bool auxS_txt2nid(int *nid, const char *txt) {
	/* try builtins first */
	if ((*nid = OBJ_sn2nid(txt)) != NID_undef
	||  (*nid = OBJ_ln2nid(txt)) != NID_undef) {
		return 1;
	}

	/* OBJ_txt2nid creates a temporary ASN1_OBJECT; call sparingly */
	if (auxS_isoid(txt) && (*nid = OBJ_txt2nid(txt)) != NID_undef) {
		return 1;
	}

	return 0;
} /* auxS_txt2nid() */


/*
 * Auxiliary Lua API routines
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

typedef int auxref_t;
typedef int auxtype_t;

static void auxL_unref(lua_State *L, auxref_t *ref) {
	luaL_unref(L, LUA_REGISTRYINDEX, *ref);
	*ref = LUA_NOREF;
} /* auxL_unref() */

static void auxL_ref(lua_State *L, int index, auxref_t *ref) {
	auxL_unref(L, ref);
	lua_pushvalue(L, index);
	*ref = luaL_ref(L, LUA_REGISTRYINDEX);
} /* auxL_ref() */

NOTUSED static auxtype_t auxL_getref(lua_State *L, auxref_t ref) {
	if (ref == LUA_NOREF || ref == LUA_REFNIL) {
		lua_pushnil(L);
	} else {
		lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
	}

	return lua_type(L, -1);
} /* auxL_getref() */

static int auxL_testoption(lua_State *L, int index, const char *def, const char *const *optlist, _Bool nocase) {
	const char *optname = (def)? luaL_optstring(L, index, def) : luaL_checkstring(L, index);
	int (*optcmp)() = (nocase)?
#ifdef _WIN32
		&_stricmp
#else
		&strcasecmp
#endif
		: &strcmp;
	int i;

	for (i = 0; optlist[i]; i++) {
		if (0 == optcmp(optlist[i], optname))
			return i;
	}

	return -1;
} /* auxL_testoption() */

static int auxL_checkoption(lua_State *L, int index, const char *def, const char *const *optlist, _Bool nocase) {
	int i;

	if ((i = auxL_testoption(L, index, def, optlist, nocase)) >= 0)
		return i;

	return luaL_argerror(L, index, lua_pushfstring(L, "invalid option '%s'", luaL_optstring(L, index, def)));
} /* auxL_checkoption() */

/*
 * Lua 5.3 distinguishes integers and numbers, and by default uses 64-bit
 * integers. The following routines try to preserve this distinction and
 * where possible detect range issues.
 *
 * The signed range checking assumes two's complement, no padding bits, and
 * sizeof lua_Integer <= sizeof long long. Which is a safe bet where OpenSSL
 * is typically used.
 */
#define auxL_Integer long long
#define auxL_IntegerMin LLONG_MIN
#define auxL_IntegerMax LLONG_MAX
#define auxL_Unsigned unsigned long long
#define auxL_UnsignedMin 0
#define auxL_UnsignedMax ULLONG_MAX

#define lua_IntegerMax ((1ULL << (sizeof (lua_Integer) * 8 - 1)) - 1)
#define lua_IntegerMin (-lua_IntegerMax - 1)

static void auxL_pushinteger(lua_State *L, auxL_Integer i) {
	/*
	 * TODO: Check value explicitly, but will need to silence compiler
	 * diagnostics about useless comparisons.
	 */
	if (sizeof (lua_Integer) >= sizeof i) {
		lua_pushinteger(L, i);
	} else {
		/* TODO: Check overflow. */
		lua_pushnumber(L, i);
	}
} /* auxL_pushinteger() */

static void auxL_pushunsigned(lua_State *L, auxL_Unsigned i) {
	if (i <= lua_IntegerMax) {
		lua_pushinteger(L, i);
	} else if (i == (auxL_Unsigned)(lua_Number)i) {
		lua_pushnumber(L, i);
	} else {
		luaL_error(L, "unsigned integer value not representable as lua_Integer or lua_Number");
	}
} /* auxL_pushunsigned() */

#define auxL_checkinteger_(a, b, c, d, ...) auxL_checkinteger((a), (b), (c), (d))
#define auxL_checkinteger(...) EXPAND( auxL_checkinteger_(__VA_ARGS__, auxL_IntegerMin, auxL_IntegerMax, 0) )

static auxL_Integer (auxL_checkinteger)(lua_State *L, int index, auxL_Integer min, auxL_Integer max) {
	auxL_Integer i;

	if (sizeof (lua_Integer) >= sizeof (auxL_Integer)) {
		i = luaL_checkinteger(L, index);
	} else {
		/* TODO: Check overflow. */
		i = (auxL_Integer)luaL_checknumber(L, index);
	}

	if (i < min || i > max)
		luaL_error(L, "integer value out of range");

	return i;
} /* auxL_checkinteger() */

#define auxL_optinteger_(a, b, c, d, e, ...) auxL_optinteger((a), (b), (c), (d), (e))
#define auxL_optinteger(...) EXPAND( auxL_optinteger_(__VA_ARGS__, auxL_IntegerMin, auxL_IntegerMax, 0))

static auxL_Integer (auxL_optinteger)(lua_State *L, int index, auxL_Integer def, auxL_Integer min, auxL_Integer max) {
	return (lua_isnoneornil(L, index))? def : auxL_checkinteger(L, index, min, max);
} /* auxL_optinteger() */

#define auxL_checkunsigned_(a, b, c, d, ...) auxL_checkunsigned((a), (b), (c), (d))
#define auxL_checkunsigned(...) EXPAND( auxL_checkunsigned_(__VA_ARGS__, auxL_UnsignedMin, auxL_UnsignedMax, 0))

static auxL_Unsigned (auxL_checkunsigned)(lua_State *L, int index, auxL_Unsigned min, auxL_Unsigned max) {
	auxL_Unsigned i;

	if (sizeof (lua_Integer) >= sizeof (auxL_Unsigned)) {
		/* TODO: Check sign. */
		i = luaL_checkinteger(L, index);
	} else {
		/* TODO: Check sign and overflow. */
		i = (auxL_Integer)luaL_checknumber(L, index);
	}

	if (i < min || i > max)
		luaL_error(L, "integer value out of range");

	return i;
} /* auxL_checkunsigned() */

#define auxL_optunsigned_(a, b, c, d, e, ...) auxL_optunsigned((a), (b), (c), (d), (e))
#define auxL_optunsigned(...) EXPAND( auxL_optunsigned_(__VA_ARGS__, auxL_UnsignedMin, auxL_UnsignedMax, 0) )

static auxL_Unsigned (auxL_optunsigned)(lua_State *L, int index, auxL_Unsigned def, auxL_Unsigned min, auxL_Unsigned max) {
	return (lua_isnoneornil(L, index))? def : auxL_checkunsigned(L, index, min, max);
} /* auxL_optunsigned() */

static int auxL_size2int(lua_State *L, size_t n) {
	if (n > INT_MAX)
		luaL_error(L, "integer value out of range (%zu > INT_MAX)", n);

	return (int)n;
} /* auxL_size2int() */

typedef struct {
	const char *name;
	auxL_Integer value;
} auxL_IntegerReg;

static void auxL_setintegers(lua_State *L, const auxL_IntegerReg *l) {
	for (; l->name; l++) {
		auxL_pushinteger(L, l->value);
		lua_setfield(L, -2, l->name);
	}
} /* auxL_setintegers() */

#define AUXL_REG_NULL (&(auxL_Reg[]){ 0 })

typedef struct {
	const char *name;
	lua_CFunction func;
	unsigned nups; /* in addition to nups specified to auxL_setfuncs */
} auxL_Reg;

static inline size_t auxL_liblen(const auxL_Reg *l) {
	size_t n = 0;

	while ((l++)->name)
		n++;

	return n;
} /* auxL_liblen() */

#define auxL_newlibtable(L, l) \
	lua_createtable((L), 0, countof((l)) - 1)

#define auxL_newlib(L, l, nups) \
	(auxL_newlibtable((L), (l)), lua_insert((L), -(nups + 1)), auxL_setfuncs((L), (l), (nups)))

static void auxL_setfuncs(lua_State *L, const auxL_Reg *l, int nups) {
	for (; l->name; l++) {
		int i;

		/* copy shared upvalues */
		luaL_checkstack(L, nups, "too many upvalues");
		for (i = 0; i < nups; i++)
			lua_pushvalue(L, -nups);

		/* nil-fill local upvalues */
		luaL_checkstack(L, l->nups, "too many upvalues");
		lua_settop(L, lua_gettop(L) + l->nups);

		/* set closure */
		luaL_checkstack(L, 1, "too many upvalues");
		lua_pushcclosure(L, l->func, nups + l->nups);
		lua_setfield(L, -(nups + 2), l->name);
	}

	lua_pop(L, nups);

	return;
} /* auxL_setfuncs() */

static void auxL_clear(lua_State *L, int tindex) {
	tindex = lua_absindex(L, tindex);

	lua_pushnil(L);
	while (lua_next(L, tindex)) {
		lua_pop(L, 1);
		lua_pushvalue(L, -1);
		lua_pushnil(L);
		lua_rawset(L, tindex);
	}
} /* auxL_clear() */

static _Bool auxL_newmetatable(lua_State *L, const char *name, _Bool reset) {
	if (luaL_newmetatable(L, name))
		return 1;
	if (!reset)
		return 0;

	/*
	 * NB: Keep existing table as it may be cached--e.g. in
	 * another module that isn't being reloaded. But scrub it
	 * clean so function interposition--which will presumably
	 * run again if the C module is being reloaded--doesn't
	 * result in loops.
	 */
	auxL_clear(L, -1);
	lua_pushnil(L);
	lua_setmetatable(L, -2);
#if LUA_VERSION_NUM >= 502
	lua_pushnil(L);
	lua_setuservalue(L, -2);
#endif

	return 0;
} /* auxL_newmetatable() */

static _Bool auxL_newclass(lua_State *L, const char *name, const auxL_Reg *methods, const auxL_Reg *metamethods, _Bool reset) {
	_Bool fresh = auxL_newmetatable(L, name, reset);
	int n;

	if (!reset && !fresh)
		return fresh;

	auxL_setfuncs(L, metamethods, 0);

	if ((n = auxL_liblen(methods))) {
		lua_createtable(L, 0, auxL_size2int(L, n));
		auxL_setfuncs(L, methods, 0);
		lua_setfield(L, -2, "__index");
	}

	return fresh;
} /* auxL_newclass() */

#define auxL_addclass(L, ...) \
	EXPAND( (auxL_newclass((L), __VA_ARGS__), lua_pop((L), 1)) )

static int auxL_swaptable(lua_State *L, int index) {
	index = lua_absindex(L, index);

	lua_pushvalue(L, -2);   /* push key */
	lua_gettable(L, index); /* push old value */

	lua_pushvalue(L, -3);   /* push key */
	lua_pushvalue(L, -3);   /* push new value */
	lua_settable(L, index); /* replace old value */

	lua_replace(L, -3);
	lua_pop(L, 1);

	return 1; /* return old value */
} /* auxL_swaptable() */

static int auxL_swapmetatable(lua_State *L, const char *name) {
	luaL_getmetatable(L, name);

	lua_pushvalue(L, -3);
	lua_pushvalue(L, -3);
	auxL_swaptable(L, -3);

	lua_replace(L, -4);
	lua_pop(L, 2);

	return 1;
} /* auxL_swapmetatable() */

static int auxL_swapmetasubtable(lua_State *L, const char *name, const char *subname) {
	luaL_getmetatable(L, name);
	lua_getfield(L, -1, subname);

	lua_pushvalue(L, -4);
	lua_pushvalue(L, -4);
	auxL_swaptable(L, -3);

	lua_replace(L, -5);
	lua_pop(L, 3);

	return 1;
} /* auxL_swapmetasubtable() */

#define auxL_EDYLD -2
#define auxL_EOPENSSL -1

static const char *auxL_pusherror(lua_State *L, int error, const char *fun) {
	if (error == auxL_EOPENSSL) {
		unsigned long code;
		const char *path, *file;
		int line;
		char txt[256];

		if (!ERR_peek_error())
			return lua_pushliteral(L, "oops: no OpenSSL errors set");

#if OPENSSL_PREREQ(3,0,0)
		code = ERR_get_error_all(&path, &line, NULL, NULL, NULL);
#else
		code = ERR_get_error_line(&path, &line);
#endif

		if ((file = strrchr(path, '/'))) {
			++file;
		} else {
			file = path;
		}

		ERR_clear_error();

		ERR_error_string_n(code, txt, sizeof txt);

		if (fun) {
			return lua_pushfstring(L, "%s: %s:%d:%s", fun, file, line, txt);
		} else {
			return lua_pushfstring(L, "%s:%d:%s", file, line, txt);
		}
#if HAVE_DLADDR
	} else if (error == auxL_EDYLD) {
		const char *const fmt = (fun)? "%s: %s" : "%.0s%s";

		return lua_pushfstring(L, fmt, (fun)? fun : "", dlerror());
#endif
	} else {
		const char *const fmt = (fun)? "%s: %s" : "%.0s%s";

		return lua_pushfstring(L, fmt, (fun)? fun : "", aux_strerror(error));
	}
} /* auxL_pusherror() */

static int auxL_error(lua_State *L, int error, const char *fun) {
	auxL_pusherror(L, error, fun);
	lua_error(L);
	NOTREACHED;
	return 0;
} /* auxL_error() */

static const char *auxL_pushnid(lua_State *L, int nid) {
	char txt[256] = { 0 };
	size_t n;

	if (!(n = auxS_nid2txt(txt, sizeof txt, nid)) || n >= sizeof txt)
		luaL_error(L, "%d: invalid ASN.1 NID", nid);

	lua_pushlstring(L, txt, n);

	return lua_tostring(L, -1);
} /* auxL_pushnid() */

static const EVP_MD *auxL_optdigest(lua_State *L, int index, EVP_PKEY *key, const EVP_MD *def);


/*
 * dl - dynamically loaded module management
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/*
 * Prevent loader from unlinking us if we've registered a callback with
 * OpenSSL by taking another reference to ourselves.
 */
/* dl_anchor must not be called from multiple threads at once */
static int dl_anchor(void) {
#if _WIN32
	EXPORT extern int luaopen__openssl(lua_State *);

	HMODULE dummy;
	if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_PIN|GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (void *)&luaopen__openssl, &dummy))
		return GetLastError();

	return 0;
#elif HAVE_DLADDR
	extern int luaopen__openssl(lua_State *);
	static void *anchor;
	Dl_info info;
	int error = 0;

	if (anchor)
		goto epilog;

	if (!dladdr((void *)&luaopen__openssl, &info))
		goto dlerr;

	if (!(anchor = dlopen(info.dli_fname, RTLD_NOW|RTLD_LOCAL)))
		goto dlerr;
epilog:
	return error;
dlerr:
	error = auxL_EDYLD;

	goto epilog;
#else
	return 0;//ENOTSUP;
#endif
} /* dl_anchor() */


/*
 * compat - OpenSSL API compatibility and bug workarounds
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if !HAVE_OPENSSL_ZALLOC
static void *OPENSSL_zalloc(size_t num) {
	void *ret = OPENSSL_malloc(num);

	if (ret != NULL)
		memset(ret, 0, num);
	return ret;
}
#endif

#if !HAVE_OPENSSL_CLEAR_FREE
static void OPENSSL_clear_free(void *str, size_t num) {
	if (str == NULL)
		return;
	if (num)
		OPENSSL_cleanse(str, num);
	CRYPTO_free(str);
} /* CRYPTO_clear_free() */
#endif

#if !HAVE_OPENSSL_MEMDUP
static void *OPENSSL_memdup(const void *data, size_t siz) {
	return BUF_memdup(data, siz);
} /* OPENSSL_memdup() */
#endif

#define COMPAT_X509_STORE_FREE_BUG 0x01

static struct {
	int flags;

	void (*X509_STORE_free)(X509_STORE *);

	struct {
		X509_STORE *store;
	} tmp;
} compat = {
	.flags = 0,
	.X509_STORE_free = &X509_STORE_free,
};

#if !HAVE_ASN1_STRING_GET0_DATA
#define ASN1_STRING_get0_data(s) ASN1_STRING_data((s))
#endif

#if !HAVE_DH_GET0_KEY
#define DH_get0_key(...) EXPAND( compat_DH_get0_key(__VA_ARGS__) )

static void compat_DH_get0_key(const DH *d, const BIGNUM **pub_key, const BIGNUM **priv_key) {
	if (pub_key)
		*pub_key = d->pub_key;
	if (priv_key)
		*priv_key = d->priv_key;
} /* compat_DH_get0_key() */
#endif

#if !HAVE_DH_GET0_PQG
#define DH_get0_pqg(...) EXPAND( compat_DH_get0_pqg(__VA_ARGS__) )

static void compat_DH_get0_pqg(const DH *d, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g) {
	if (p)
		*p = d->p;
	if (q)
		*q = d->q;
	if (g)
		*g = d->g;
} /* compat_DH_get0_pqg() */
#endif

#if !HAVE_DH_SET0_KEY
#define DH_set0_key(...) EXPAND( compat_DH_set0_key(__VA_ARGS__) )

static void compat_DH_set0_key(DH *d, BIGNUM *pub_key, BIGNUM *priv_key) {
	if (pub_key)
		auxS_bn_free_and_set0(&d->pub_key, pub_key);
	if (priv_key)
		auxS_bn_free_and_set0(&d->priv_key, priv_key);
} /* compat_DH_set0_key() */
#endif

#if !HAVE_DH_SET0_PQG
#define DH_set0_pqg(...) EXPAND( compat_DH_set0_pqg(__VA_ARGS__) )

static void compat_DH_set0_pqg(DH *d, BIGNUM *p, BIGNUM *q, BIGNUM *g) {
	if (p)
		auxS_bn_free_and_set0(&d->p, p);
	if (q)
		auxS_bn_free_and_set0(&d->q, q);
	if (g)
		auxS_bn_free_and_set0(&d->g, g);
} /* compat_DH_set0_pqg() */
#endif

#if !HAVE_DSA_GET0_KEY
#define DSA_get0_key(...) EXPAND( compat_DSA_get0_key(__VA_ARGS__) )

static void compat_DSA_get0_key(const DSA *d, const BIGNUM **pub_key, const BIGNUM **priv_key) {
	if (pub_key)
		*pub_key = d->pub_key;
	if (priv_key)
		*priv_key = d->priv_key;
} /* compat_DSA_get0_key() */
#endif

#if !HAVE_DSA_GET0_PQG
#define DSA_get0_pqg(...) EXPAND( compat_DSA_get0_pqg(__VA_ARGS__) )

static void compat_DSA_get0_pqg(const DSA *d, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g) {
	if (p)
		*p = d->p;
	if (q)
		*q = d->q;
	if (g)
		*g = d->g;
} /* compat_DSA_get0_pqg() */
#endif

#if !HAVE_DSA_SET0_KEY
#define DSA_set0_key(...) EXPAND( compat_DSA_set0_key(__VA_ARGS__) )

static void compat_DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key) {
	if (pub_key)
		auxS_bn_free_and_set0(&d->pub_key, pub_key);
	if (priv_key)
		auxS_bn_free_and_set0(&d->priv_key, priv_key);
} /* compat_DSA_set0_key() */
#endif

#if !HAVE_DSA_SET0_PQG
#define DSA_set0_pqg(...) EXPAND( compat_DSA_set0_pqg(__VA_ARGS__) )

static void compat_DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g) {
	if (p)
		auxS_bn_free_and_set0(&d->p, p);
	if (q)
		auxS_bn_free_and_set0(&d->q, q);
	if (g)
		auxS_bn_free_and_set0(&d->g, g);
} /* compat_DSA_set0_pqg() */
#endif

#if !HAVE_EVP_CIPHER_CTX_FREE
#define EVP_CIPHER_CTX_free(ctx) compat_EVP_CIPHER_CTX_free((ctx))

static void compat_EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx) {
	EVP_CIPHER_CTX_cleanup(ctx);
	OPENSSL_free(ctx);
} /* compat_EVP_CIPHER_CTX_free() */
#endif

#if !HAVE_EVP_CIPHER_CTX_NEW
#define EVP_CIPHER_CTX_new() compat_EVP_CIPHER_CTX_new()

static EVP_CIPHER_CTX *compat_EVP_CIPHER_CTX_new(void) {
	EVP_CIPHER_CTX *ctx;

	if (!(ctx = OPENSSL_malloc(sizeof *ctx)))
		return NULL;
	memset(ctx, 0, sizeof *ctx);
	EVP_CIPHER_CTX_init(ctx);

	return ctx;
} /* compat_EVP_CIPHER_CTX_new() */
#endif

#if !HAVE_EVP_MD_CTX_FREE
#define EVP_MD_CTX_free(md) EVP_MD_CTX_destroy((md))
#endif

#if !HAVE_EVP_MD_CTX_NEW
#define EVP_MD_CTX_new() EVP_MD_CTX_create()
#endif

#if !HAVE_EVP_PKEY_ID
#define EVP_PKEY_id(key) ((key)->type)
#endif

#if !HAVE_EVP_PKEY_BASE_ID
#define EVP_PKEY_base_id(key) compat_EVP_PKEY_base_id((key))

static int compat_EVP_PKEY_base_id(EVP_PKEY *key) {
	return EVP_PKEY_type(EVP_PKEY_id(key));
} /* compat_EVP_PKEY_base_id() */
#endif

#if !HAVE_EVP_PKEY_GET_DEFAULT_DIGEST_NID
#define EVP_PKEY_get_default_digest_nid(...) \
	EXPAND( compat_EVP_PKEY_get_default_digest_nid(__VA_ARGS__) )

static int compat_EVP_PKEY_get_default_digest_nid(EVP_PKEY *key, int *nid) {
	switch (EVP_PKEY_base_id(key)) {
	case EVP_PKEY_RSA:
		*nid = EVP_MD_nid(EVP_sha1());
		break;
	case EVP_PKEY_DSA:
		*nid = EVP_MD_nid(EVP_dss1());
		break;
	case EVP_PKEY_EC:
		*nid = EVP_MD_nid(EVP_ecdsa());
		break;
	default:
		*nid = EVP_MD_nid(EVP_sha1());
		break;
	}

	return 1;
} /* compat_EVP_PKEY_get_default_digest_nid() */
#endif

#if !HAVE_EVP_PKEY_GET0_RSA
#define EVP_PKEY_get0_RSA(key) compat_EVP_PKEY_get0_RSA((key))

static RSA *compat_EVP_PKEY_get0_RSA(EVP_PKEY *key) {
	RSA *ptr = EVP_PKEY_get1_RSA(key);
	RSA_free(ptr);
	return ptr;
} /* compat_EVP_PKEY_get0_RSA() */
#endif

#if !HAVE_EVP_PKEY_GET0_DSA
#define EVP_PKEY_get0_DSA(key) compat_EVP_PKEY_get0_DSA((key))

static DSA *compat_EVP_PKEY_get0_DSA(EVP_PKEY *key) {
	DSA *ptr = EVP_PKEY_get1_DSA(key);
	DSA_free(ptr);
	return ptr;
} /* compat_EVP_PKEY_get0_DSA() */
#endif

#if !HAVE_EVP_PKEY_GET0_DH
#define EVP_PKEY_get0_DH(key) compat_EVP_PKEY_get0_DH((key))

static DH *compat_EVP_PKEY_get0_DH(EVP_PKEY *key) {
	DH *ptr = EVP_PKEY_get1_DH(key);
	DH_free(ptr);
	return ptr;
} /* compat_EVP_PKEY_get0_DH() */
#endif

#if !HAVE_EVP_PKEY_GET0_EC_KEY && !defined(OPENSSL_NO_EC)
#define EVP_PKEY_get0_EC_KEY(key) compat_EVP_PKEY_get0_EC_KEY((key))

static EC_KEY *compat_EVP_PKEY_get0_EC_KEY(EVP_PKEY *key) {
	EC_KEY *ptr = EVP_PKEY_get1_EC_KEY(key);
	EC_KEY_free(ptr);
	return ptr;
} /* compat_EVP_PKEY_get0_EC_KEY() */
#endif

#if !HAVE_EVP_PKEY_GET0
#define EVP_PKEY_get0(key) compat_EVP_PKEY_get0((key))

static void *compat_EVP_PKEY_get0(EVP_PKEY *key) {
	void *ptr = NULL;

	switch (EVP_PKEY_base_id(key)) {
	case EVP_PKEY_RSA:
		return EVP_PKEY_get0_RSA(key);
	case EVP_PKEY_DSA:
		return EVP_PKEY_get0_DSA(key);
	case EVP_PKEY_DH:
		return EVP_PKEY_get0_DH(key);
#ifndef OPENSSL_NO_EC
	case EVP_PKEY_EC:
		return EVP_PKEY_get0_EC_KEY(key);
#endif
	default:
		/* TODO: Use ERR_put_error */

		break;
	}

	return ptr;
} /* compat_EVP_PKEY_get0() */
#endif

#if !HAVE_HMAC_CTX_FREE
#define HMAC_CTX_free(ctx) compat_HMAC_CTX_free((ctx))

static void compat_HMAC_CTX_free(HMAC_CTX *ctx) {
	HMAC_CTX_cleanup(ctx);
	OPENSSL_free(ctx);
} /* compat_HMAC_CTX_free() */
#endif

#if !HAVE_HMAC_CTX_NEW
#define HMAC_CTX_new() compat_HMAC_CTX_new()

static HMAC_CTX *compat_HMAC_CTX_new(void) {
	HMAC_CTX *ctx;

	if (!(ctx = OPENSSL_malloc(sizeof *ctx)))
		return NULL;
	memset(ctx, 0, sizeof *ctx);

	return ctx;
} /* compat_HMAC_CTX_new() */
#endif

#if !HAVE_RSA_GET0_CRT_PARAMS
#define RSA_get0_crt_params(...) EXPAND( compat_RSA_get0_crt_params(__VA_ARGS__) )

static void compat_RSA_get0_crt_params(const RSA *r, const BIGNUM **dmp1, const BIGNUM **dmq1, const BIGNUM **iqmp) {
	if (dmp1)
		*dmp1 = r->dmp1;
	if (dmq1)
		*dmq1 = r->dmq1;
	if (iqmp)
		*iqmp = r->iqmp;
} /* compat_RSA_get0_crt_params() */
#endif

#if !HAVE_RSA_GET0_FACTORS
#define RSA_get0_factors(...) EXPAND( compat_RSA_get0_factors(__VA_ARGS__) )

static void compat_RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q) {
	if (p)
		*p = r->p;
	if (q)
		*q = r->q;
} /* compat_RSA_get0_factors() */
#endif

#if !HAVE_RSA_GET0_KEY
#define RSA_get0_key(...) EXPAND( compat_RSA_get0_key(__VA_ARGS__) )

static void compat_RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d) {
	if (n)
		*n = r->n;
	if (e)
		*e = r->e;
	if (d)
		*d = r->d;
} /* compat_RSA_get0_key() */
#endif

#if !HAVE_RSA_SET0_CRT_PARAMS
#define RSA_set0_crt_params(...) EXPAND( compat_RSA_set0_crt_params(__VA_ARGS__) )

static void compat_RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp) {
	if (dmp1)
		auxS_bn_free_and_set0(&r->dmp1, dmp1);
	if (dmq1)
		auxS_bn_free_and_set0(&r->dmq1, dmq1);
	if (iqmp)
		auxS_bn_free_and_set0(&r->iqmp, iqmp);
} /* compat_RSA_set0_crt_params() */
#endif

#if !HAVE_RSA_SET0_FACTORS
#define RSA_set0_factors(...) EXPAND( compat_RSA_set0_factors(__VA_ARGS__) )

static void compat_RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q) {
	if (p)
		auxS_bn_free_and_set0(&r->p, p);
	if (q)
		auxS_bn_free_and_set0(&r->q, q);
} /* compat_RSA_set0_factors() */
#endif

#if !HAVE_RSA_SET0_KEY
#define RSA_set0_key(...) EXPAND( compat_RSA_set0_key(__VA_ARGS__) )

static void compat_RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
	if (n)
		auxS_bn_free_and_set0(&r->n, n);
	if (e)
		auxS_bn_free_and_set0(&r->e, e);
	if (d)
		auxS_bn_free_and_set0(&r->d, d);
} /* compat_RSA_set0_key() */
#endif

#if !HAVE_SSL_GET_CLIENT_RANDOM
#define SSL_get_client_random(...) EXPAND( compat_SSL_get_client_random(__VA_ARGS__) )
static size_t compat_SSL_get_client_random(const SSL *ssl, unsigned char *out, size_t outlen) {
	if (outlen == 0)
		return sizeof(ssl->s3->client_random);
	if (outlen > sizeof(ssl->s3->client_random))
		outlen = sizeof(ssl->s3->client_random);
	memcpy(out, ssl->s3->client_random, outlen);
	return outlen;
}
#endif

#if !HAVE_SSL_SESSION_MASTER_KEY
#define SSL_SESSION_get_master_key(...) EXPAND( compat_SSL_SESSION_get_master_key(__VA_ARGS__) )
static size_t compat_SSL_SESSION_get_master_key(const SSL_SESSION *session, unsigned char *out, size_t outlen) {
	if (session->master_key_length < 0) {
		/* Should never happen */
		return 0;
	}
	if (outlen == 0)
		return session->master_key_length;
	if (outlen > (size_t)session->master_key_length)
		outlen = session->master_key_length;
	memcpy(out, session->master_key, outlen);
	return outlen;
}
#endif

#if !HAVE_SSL_CLIENT_VERSION
#define SSL_client_version(...) EXPAND( compat_SSL_client_version(__VA_ARGS__) )

static int compat_SSL_client_version(const SSL *ssl) {
	return ssl->client_version;
} /* compat_SSL_client_version() */
#endif

#if !HAVE_SSL_GET0_PARAM
#define SSL_get0_param(ssl) compat_SSL_get0_param((ssl))

static X509_VERIFY_PARAM *compat_SSL_get0_param(SSL *ssl) {
	return ssl->param;
} /* compat_SSL_get0_param() */
#endif

#if !HAVE_SSL_SET1_PARAM
#define SSL_set1_param(ssl, vpm) compat_SSL_set1_param((ssl), (vpm))

static int compat_SSL_set1_param(SSL *ssl, X509_VERIFY_PARAM *vpm) {
	return X509_VERIFY_PARAM_set1(ssl->param, vpm);
} /* compat_SSL_set1_param() */
#endif

#if !HAVE_SSL_UP_REF
#define SSL_up_ref(...) EXPAND( compat_SSL_up_ref(__VA_ARGS__) )

static int compat_SSL_up_ref(SSL *ssl) {
	/* our caller should already have had a proper reference */
	if (CRYPTO_add(&ssl->references, 1, CRYPTO_LOCK_SSL) < 2)
		return 0; /* fail */

	return 1;
} /* compat_SSL_up_ref() */
#endif

#if !HAVE_SSL_OP_NO_SSL_MASK
/* SSL_OP_NO_SSL_MASK was introduced in 1.0.2
   1.0.1 had up to TLSv1_2
   0.9.8-1.0.0 had up to TLSv1
*/
#ifdef SSL_OP_NO_TLSv1_2
#define SSL_OP_NO_SSL_MASK (SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1_2)
#else
#define SSL_OP_NO_SSL_MASK (SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1)
#endif
#endif

#if !HAVE_SSL_OP_NO_DTLS_MASK && HAVE_DTLS_CLIENT_METHOD
#define SSL_OP_NO_DTLS_MASK (SSL_OP_NO_DTLSv1|SSL_OP_NO_DTLSv1_2)
#endif

#if !HAVE_SSL_CTX_GET0_PARAM
#define SSL_CTX_get0_param(ctx) compat_SSL_CTX_get0_param((ctx))

static X509_VERIFY_PARAM *compat_SSL_CTX_get0_param(SSL_CTX *ctx) {
	return ctx->param;
} /* compat_SSL_CTX_get0_param() */
#endif

#if !HAVE_SSL_CTX_SET1_PARAM
#define SSL_CTX_set1_param(ctx, vpm) compat_SSL_CTX_set1_param((ctx), (vpm))

static int compat_SSL_CTX_set1_param(SSL_CTX *ctx, X509_VERIFY_PARAM *vpm) {
	return X509_VERIFY_PARAM_set1(ctx->param, vpm);
} /* compat_SSL_CTX_set1_param() */
#endif

#if !HAVE_SSL_CTX_UP_REF
#define SSL_CTX_up_ref(...) EXPAND( compat_SSL_CTX_up_ref(__VA_ARGS__) )

static int compat_SSL_CTX_up_ref(SSL_CTX *ctx) {
	/* our caller should already have had a proper reference */
	if (CRYPTO_add(&ctx->references, 1, CRYPTO_LOCK_SSL_CTX) < 2)
		return 0; /* fail */

	return 1;
} /* compat_SSL_CTX_up_ref() */
#endif

#if !HAVE_STACK_OPENSSL_STRING_FUNCS
#define sk_OPENSSL_STRING_num(s) sk_num(s)
#define sk_OPENSSL_STRING_value(s, i) sk_value((s), (i))
#define sk_OPENSSL_STRING_free(s) X509_email_free(s)
#endif

#if !HAVE_X509_GET0_EXT
#define X509_get0_ext(crt, i) X509_get_ext((crt), (i))
#endif

#if !HAVE_X509_GET_SIGNATURE_NID
#define X509_get_signature_nid(crt) OBJ_obj2nid((crt)->sig_alg->algorithm)
#endif

#if !HAVE_X509_CRL_GET0_EXT
#define X509_CRL_get0_ext(crt, i) X509_CRL_get_ext((crt), (i))
#endif

#if !HAVE_X509_CRL_GET0_LASTUPDATE
#define X509_CRL_get0_lastUpdate(crl) ((const ASN1_TIME*)X509_CRL_get_lastUpdate(crl))
#endif

#if !HAVE_X509_CRL_GET0_NEXTUPDATE
#define X509_CRL_get0_nextUpdate(crl) ((const ASN1_TIME*)X509_CRL_get_nextUpdate(crl))
#endif

#if !HAVE_X509_CRL_SET1_LASTUPDATE
#define X509_CRL_set1_lastUpdate(crl, s) X509_CRL_set_lastUpdate((crl), (ASN1_TIME*)(s))
#endif

#if !HAVE_X509_CRL_SET1_NEXTUPDATE
#define X509_CRL_set1_nextUpdate(crl, s) X509_CRL_set_nextUpdate((crl), (ASN1_TIME*)(s))
#endif

#if !HAVE_X509_EXTENSION_GET0_OBJECT
#define X509_EXTENSION_get0_object(ext) X509_EXTENSION_get_object((ext))
#endif

#if !HAVE_X509_EXTENSION_GET0_DATA
#define X509_EXTENSION_get0_data(ext) X509_EXTENSION_get_data((ext))
#endif

#if HAVE_X509_STORE_REFERENCES
/*
 * X509_STORE_free in OpenSSL versions < 1.0.2 doesn't obey reference count
 */
#define X509_STORE_free(store) \
	(compat.X509_STORE_free)((store))

/* to support preprocessor detection below */
#define compat_X509_STORE_free(store) \
	compat_X509_STORE_free((store))

static void (compat_X509_STORE_free)(X509_STORE *store) {
	int i;

	i = CRYPTO_add(&store->references, -1, CRYPTO_LOCK_X509_STORE);
	if (i > 0)
		return;

	(X509_STORE_free)(store);
} /* compat_X509_STORE_free() */
#endif

#if !HAVE_SSL_CTX_SET1_CERT_STORE

#define SSL_CTX_set1_cert_store(ctx, store) \
	compat_SSL_CTX_set1_cert_store((ctx), (store))

static void (compat_SSL_CTX_set1_cert_store)(SSL_CTX *ctx, X509_STORE *store) {
#if !HAVE_SSL_CTX_CERT_STORE || !HAVE_X509_STORE_REFERENCES
	if (store != NULL)
		X509_STORE_up_ref(store);
	SSL_CTX_set_cert_store(ctx, store);
#else
	int n;

	/*
	 * This isn't thead-safe, but using X509_STORE or SSL_CTX objects
	 * from different threads isn't safe generally.
	 */
	if (ctx->cert_store) {
		X509_STORE_free(ctx->cert_store);
		ctx->cert_store = NULL;
	}

	n = store->references;

	SSL_CTX_set_cert_store(ctx, store);

	if (n == store->references)
		CRYPTO_add(&store->references, 1, CRYPTO_LOCK_X509_STORE);
#endif
} /* compat_SSL_CTX_set1_cert_store() */

#endif

#if HAVE_SSL_CTX_CERT_STORE

static void compat_init_SSL_CTX_onfree(void *_ctx, void *data NOTUSED, CRYPTO_EX_DATA *ad NOTUSED, int idx NOTUSED, long argl NOTUSED, void *argp NOTUSED) {
	SSL_CTX *ctx = _ctx;

	if (ctx->cert_store) {
		X509_STORE_free(ctx->cert_store);
		ctx->cert_store = NULL;
	}
} /* compat_init_SSL_CTX_onfree() */

#endif

#if defined compat_X509_STORE_free
/* helper routine to determine if X509_STORE_free obeys reference count */
static void compat_init_X509_STORE_onfree(void *store, void *data NOTUSED, CRYPTO_EX_DATA *ad NOTUSED, int idx NOTUSED, long argl NOTUSED, void *argp NOTUSED) {
	/* unfortunately there's no way to remove a handler */
	if (store != compat.tmp.store)
		return;

	/* signal that we were freed by nulling our reference */
	compat.tmp.store = NULL;
} /* compat_init_X509_STORE_onfree() */
#endif


#if !HAVE_X509_STORE_UP_REF
#define X509_STORE_up_ref(...) EXPAND( compat_X509_STORE_up_ref(__VA_ARGS__) )

static int compat_X509_STORE_up_ref(X509_STORE *crt) {
	/* our caller should already have had a proper reference */
	if (CRYPTO_add(&crt->references, 1, CRYPTO_LOCK_X509_STORE) < 2)
		return 0; /* fail */

	return 1;
} /* compat_X509_STORE_up_ref() */
#endif

#if !HAVE_X509_UP_REF
#define X509_up_ref(...) EXPAND( compat_X509_up_ref(__VA_ARGS__) )

static int compat_X509_up_ref(X509 *crt) {
	/* our caller should already have had a proper reference */
	if (CRYPTO_add(&crt->references, 1, CRYPTO_LOCK_X509) < 2)
		return 0; /* fail */

	return 1;
} /* compat_X509_up_ref() */
#endif

#if !HAVE_X509_CHAIN_UP_REF
/*
 * NB: this operation dups the chain (but not the certificates within it)
 */
#define X509_chain_up_ref(...) EXPAND( compat_X509_chain_up_ref(__VA_ARGS__) )

STACK_OF(X509) *compat_X509_chain_up_ref(STACK_OF(X509) *chain) {
    STACK_OF(X509) *ret;
    int i;
    ret = sk_X509_dup(chain);
    for (i = 0; i < sk_X509_num(ret); i++) {
        X509 *x = sk_X509_value(ret, i);
        X509_up_ref(x);
    }
    return ret;
} /* compat_X509_chain_up_ref() */
#endif

#if !HAVE_X509_VERIFY_PARAM_SET1_EMAIL
/*
 * NB: Cannot emulate. Requires dereferencing X509_VERIFY_PARAM_ID objects,
 * which were always opaque.
 */
#endif

#if !HAVE_X509_VERIFY_PARAM_SET1_HOST
/*
 * NB: See HAVE_X509_VERIFY_PARAM_SET1_EMAIL.
 */
#endif


#if !HAVE_EVP_KDF_CTX
/*
 * Emulate EVP_KDF_CTX API (introduced in OpenSSL 3.0.0)
 */

#ifndef ERR_LIB_KDF
#define ERR_LIB_KDF 0
#endif

#ifndef KDFerr
#define KDFerr(f,r) ERR_PUT_error(ERR_LIB_KDF,f,(r),__FILE__,__LINE__)
#endif

#ifndef EVP_F_EVP_KDF_CTRL
#define EVP_F_EVP_KDF_CTRL 0
#endif

#ifndef EVP_F_EVP_KDF_CTX_NEW_ID
#define EVP_F_EVP_KDF_CTX_NEW_ID 0
#endif

#ifndef EVP_R_UNSUPPORTED_ALGORITHM
#define EVP_R_UNSUPPORTED_ALGORITHM EVP_R_UNKNOWN_OPTION
#endif

#ifndef EVP_R_COMMAND_NOT_SUPPORTED
#define EVP_R_COMMAND_NOT_SUPPORTED EVP_R_UNKNOWN_OPTION
#endif

typedef struct {
	int nid;
	union {
#if HAVE_PKCS5_PBKDF2_HMAC
		/* Arguments for PKCS5_PBKDF2_HMAC */
		struct {
			unsigned char *pass;
			size_t passlen;
			unsigned char *salt;
			size_t saltlen;
			int iter;
			const EVP_MD *md;
		} pbkdf2;
#endif

#if HAVE_SCRYPT
		/* Arguments for EVP_PBE_scrypt */
		struct {
			unsigned char *pass;
			size_t passlen;
			unsigned char *salt;
			size_t saltlen;
			uint64_t N;
			uint32_t r;
			uint32_t p;
			uint64_t maxmem_bytes;
		} scrypt;
#endif

#if HAVE_EVP_PKEY_CTX_KDF
		EVP_PKEY_CTX *pctx;
#endif
	};
} EVP_KDF_CTX;

static void EVP_KDF_CTX_free(EVP_KDF_CTX *kctx) {
	if (kctx == NULL)
		return;

	switch(kctx->nid) {
#if HAVE_PKCS5_PBKDF2_HMAC
	case NID_id_pbkdf2:
		OPENSSL_clear_free(kctx->pbkdf2.pass, kctx->pbkdf2.passlen);
		OPENSSL_clear_free(kctx->pbkdf2.salt, kctx->pbkdf2.saltlen);
		break;
#endif
#if HAVE_SCRYPT
	case NID_id_scrypt:
		OPENSSL_clear_free(kctx->scrypt.pass, kctx->scrypt.passlen);
		OPENSSL_clear_free(kctx->scrypt.salt, kctx->scrypt.saltlen);
		break;
#endif
#if HAVE_EVP_PKEY_CTX_KDF
	case NID_tls1_prf:
	case NID_hkdf:
		EVP_PKEY_CTX_free(kctx->pctx);
		break;
#endif
	}

	OPENSSL_free(kctx);
} /* EVP_KDF_CTX_free() */

typedef int LUAOSSL_EVP_KDF_PTR;
#define LUAOSSL_EVP_KDF_UNDEF NID_undef

static LUAOSSL_EVP_KDF_PTR EVP_KDF_fetch(void *libctx, const char *algorithm, const char *properties) {
    LUAOSSL_EVP_KDF_PTR kdf;
    (void)libctx;
    (void)properties;

    if(!auxS_txt2nid(&kdf,algorithm)) {
        return LUAOSSL_EVP_KDF_UNDEF;
    }
    return kdf;
}

static EVP_KDF_CTX *EVP_KDF_CTX_new(LUAOSSL_EVP_KDF_PTR kdf) {
	EVP_KDF_CTX *ret;

	ret = OPENSSL_zalloc(sizeof(*ret));
	if (ret == NULL) {
		EVPerr(EVP_F_EVP_KDF_CTX_NEW_ID, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	ret->nid = kdf;

	switch(kdf) {
#if HAVE_PKCS5_PBKDF2_HMAC
	case NID_id_pbkdf2:
		break;
#endif
#if HAVE_SCRYPT
	case NID_id_scrypt:
		break;
#endif
#if HAVE_EVP_PKEY_CTX_KDF
	case NID_tls1_prf:
	case NID_hkdf: {
			ret->pctx = EVP_PKEY_CTX_new_id(kdf, NULL);
			if (!ret->pctx) {
				OPENSSL_free(ret);
				return NULL;
			}
			if (EVP_PKEY_derive_init(ret->pctx) <= 0) {
				EVP_KDF_CTX_free(ret);
				return NULL;
			}
			break;
		}
		break;
#endif
	default:
		OPENSSL_free(ret);
		EVPerr(EVP_F_EVP_KDF_CTX_NEW_ID, EVP_R_UNSUPPORTED_ALGORITHM);
		return NULL;
	}

	return ret;
} /* EVP_KDF_CTX_new() */

static int set_membuf(unsigned char **buffer, size_t *buflen, const unsigned char *new_buffer, size_t new_buflen) {
	if (new_buffer == NULL)
		return 1;
	OPENSSL_clear_free(*buffer, *buflen);
	if (new_buflen > 0) {
		*buffer = OPENSSL_memdup(new_buffer, new_buflen);
	} else {
		*buffer = OPENSSL_malloc(1);
	}
	if (*buffer == NULL) {
		KDFerr(EVP_F_EVP_KDF_CTRL, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	*buflen = new_buflen;
	return 1;
}

#define EVP_KDF_CTRL_SET_PASS          0x01 /* unsigned char *, size_t */
#define EVP_KDF_CTRL_SET_SALT          0x02 /* unsigned char *, size_t */
#define EVP_KDF_CTRL_SET_ITER          0x03 /* int */
#define EVP_KDF_CTRL_SET_MD            0x04 /* EVP_MD * */
#define EVP_KDF_CTRL_SET_KEY           0x05 /* unsigned char *, size_t */
#define EVP_KDF_CTRL_SET_MAXMEM_BYTES  0x06 /* uint64_t */
#define EVP_KDF_CTRL_SET_TLS_SECRET    0x07 /* unsigned char *, size_t */
#define EVP_KDF_CTRL_RESET_TLS_SEED    0x08
#define EVP_KDF_CTRL_ADD_TLS_SEED      0x09 /* unsigned char *, size_t */
#define EVP_KDF_CTRL_RESET_HKDF_INFO   0x0a
#define EVP_KDF_CTRL_ADD_HKDF_INFO     0x0b /* unsigned char *, size_t */
#define EVP_KDF_CTRL_SET_HKDF_MODE     0x0c /* int */
#define EVP_KDF_CTRL_SET_SCRYPT_N      0x0d /* uint64_t */
#define EVP_KDF_CTRL_SET_SCRYPT_R      0x0e /* uint32_t */
#define EVP_KDF_CTRL_SET_SCRYPT_P      0x0f /* uint32_t */

#ifdef EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND
#define EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND
#elif HAVE_EVP_PKEY_CTX_KDF
#define EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND 0
#endif

#ifdef EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY
#define EVP_KDF_HKDF_MODE_EXTRACT_ONLY EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY
#endif

#ifdef EVP_PKEY_HKDEF_MODE_EXPAND_ONLY
#define EVP_KDF_HKDF_MODE_EXPAND_ONLY EVP_PKEY_HKDEF_MODE_EXPAND_ONLY
#endif

static int EVP_KDF_vctrl(EVP_KDF_CTX *kctx, int cmd, va_list args) {
	const EVP_MD *md;
	const unsigned char *p;
	size_t len;
	uint64_t u64_value;
	uint32_t value;
	int iter, mode;

	if (kctx == NULL)
		return 0;

	switch (kctx->nid) {
#if HAVE_PKCS5_PBKDF2_HMAC
	case NID_id_pbkdf2: {
		switch (cmd) {
		case EVP_KDF_CTRL_SET_PASS:
			p = va_arg(args, const unsigned char *);
			len = va_arg(args, size_t);
			return set_membuf(&kctx->pbkdf2.pass, &(kctx->pbkdf2.passlen), p, len);

		case EVP_KDF_CTRL_SET_SALT:
			p = va_arg(args, const unsigned char *);
			len = va_arg(args, size_t);
			return set_membuf(&kctx->pbkdf2.salt, &kctx->pbkdf2.saltlen, p, len);

		case EVP_KDF_CTRL_SET_ITER:
			iter = va_arg(args, int);
			if (iter < 1)
				return 0;
			kctx->pbkdf2.iter = iter;
			return 1;

		case EVP_KDF_CTRL_SET_MD:
			md = va_arg(args, const EVP_MD *);
			if (md == NULL)
				return 0;
			kctx->pbkdf2.md = md;
			return 1;

		default:
			EVPerr(EVP_F_EVP_KDF_CTRL, EVP_R_COMMAND_NOT_SUPPORTED);
			return -2;
		}
	}
#endif
#if HAVE_SCRYPT
	case NID_id_scrypt: {
		switch (cmd) {
		case EVP_KDF_CTRL_SET_PASS:
			p = va_arg(args, const unsigned char *);
			len = va_arg(args, size_t);
			return set_membuf(&kctx->scrypt.pass, &kctx->scrypt.passlen, p, len);

		case EVP_KDF_CTRL_SET_SALT:
			p = va_arg(args, const unsigned char *);
			len = va_arg(args, size_t);
			return set_membuf(&kctx->scrypt.salt, &kctx->scrypt.saltlen, p, len);

		case EVP_KDF_CTRL_SET_SCRYPT_N:
			u64_value = va_arg(args, uint64_t);
			if ((u64_value <= 1) || ((u64_value & (u64_value - 1)) != 0)) /* is_power_of_two check */
				return 0;
			kctx->scrypt.N = u64_value;
			return 1;

		case EVP_KDF_CTRL_SET_SCRYPT_R:
			value = va_arg(args, uint32_t);
			if (value < 1)
				return 0;
			kctx->scrypt.r = value;
			return 1;

		case EVP_KDF_CTRL_SET_SCRYPT_P:
			value = va_arg(args, uint32_t);
			if (value < 1)
				return 0;
			kctx->scrypt.p = value;
			return 1;

		case EVP_KDF_CTRL_SET_MAXMEM_BYTES:
			u64_value = va_arg(args, uint64_t);
			if (u64_value < 1)
				return 0;
			kctx->scrypt.maxmem_bytes = u64_value;
			return 1;

		default:
			EVPerr(EVP_F_EVP_KDF_CTRL, EVP_R_COMMAND_NOT_SUPPORTED);
			return -2;
		}
	}
#endif
#if HAVE_EVP_PKEY_CTX_KDF
	case NID_tls1_prf: {
		switch (cmd) {
		case EVP_KDF_CTRL_SET_MD:
			md = va_arg(args, const EVP_MD *);
			return EVP_PKEY_CTX_set_tls1_prf_md(kctx->pctx, md);

		case EVP_KDF_CTRL_SET_TLS_SECRET:
			p = va_arg(args, const unsigned char *);
			len = va_arg(args, size_t);
			/* XXX: the old api resets the seed when you set the secret. When
			 * using this compat routine, make sure you set the secret before
			 * the seed.
			 * https://github.com/openssl/openssl/issues/7728
			 */
			return EVP_PKEY_CTX_set1_tls1_prf_secret(kctx->pctx, p, len);

		case EVP_KDF_CTRL_ADD_TLS_SEED:
			p = va_arg(args, const unsigned char *);
			len = va_arg(args, size_t);
			return EVP_PKEY_CTX_add1_tls1_prf_seed(kctx->pctx, p, len);

		default:
			EVPerr(EVP_F_EVP_KDF_CTRL, EVP_R_COMMAND_NOT_SUPPORTED);
			return -2;
		}
	}
	case NID_hkdf: {
		switch (cmd) {
		case EVP_KDF_CTRL_SET_SALT:
			p = va_arg(args, const unsigned char *);
			len = va_arg(args, size_t);
			return EVP_PKEY_CTX_set1_hkdf_salt(kctx->pctx, p, len);

		case EVP_KDF_CTRL_SET_MD:
			md = va_arg(args, const EVP_MD *);
			return EVP_PKEY_CTX_set_hkdf_md(kctx->pctx, md);

		case EVP_KDF_CTRL_SET_KEY:
			p = va_arg(args, const unsigned char *);
			len = va_arg(args, size_t);
			return EVP_PKEY_CTX_set1_hkdf_key(kctx->pctx, p, len);

		case EVP_KDF_CTRL_ADD_HKDF_INFO:
			p = va_arg(args, const unsigned char *);
			len = va_arg(args, size_t);
			return EVP_PKEY_CTX_add1_hkdf_info(kctx->pctx, p, len);

		case EVP_KDF_CTRL_SET_HKDF_MODE:
			mode = va_arg(args, int);
#if HAVE_EVP_PKEY_CTX_HKDF_MODE
			return EVP_PKEY_CTX_hkdf_mode(kctx->pctx, mode);
#else
			if (mode == EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND)
				return 1;
			else
				/* XXX: OpenSSL doesn't set an error here */
				return 0;

#endif
		default:
			EVPerr(EVP_F_EVP_KDF_CTRL, EVP_R_COMMAND_NOT_SUPPORTED);
			return -2;
		}
	}
#endif
	default:
		(void)cmd;
		(void)args;
		return 0;
	}
} /* EVP_KDF_vctrl() */

static int EVP_KDF_ctrl(EVP_KDF_CTX *kctx, int cmd, ...) {
	int ret;
	va_list args;
	va_start(args, cmd);
	ret = EVP_KDF_vctrl(kctx, cmd, args);
	va_end(args);
	if (ret == -2)
		EVPerr(EVP_F_EVP_KDF_CTRL, EVP_R_COMMAND_NOT_SUPPORTED);
	return ret;
} /* EVP_KDF_ctrl() */

static size_t EVP_KDF_CTX_get_kdf_size(EVP_KDF_CTX *kctx) {
	if (kctx == NULL)
		return 0;

	switch(kctx->nid) {
#if HAVE_EVP_PKEY_CTX_KDF
	case NID_tls1_prf:
	case NID_hkdf: {
			size_t outlen = 0;
			EVP_PKEY_derive(kctx->pctx, NULL, &outlen);
			return outlen;
		}
#endif
	default:
		return SIZE_MAX;
	}
} /* EVP_KDF_CTX_get_kdf_size() */

static int EVP_KDF_derive(EVP_KDF_CTX *kctx, unsigned char *out, size_t outlen, void *params) {
	switch(kctx->nid) {
#if HAVE_PKCS5_PBKDF2_HMAC
	case NID_id_pbkdf2:
		return PKCS5_PBKDF2_HMAC((const char*)kctx->pbkdf2.pass, kctx->pbkdf2.passlen,
			kctx->pbkdf2.salt, kctx->pbkdf2.saltlen,
			kctx->pbkdf2.iter,
			kctx->pbkdf2.md,
			outlen, out);
#endif
#if HAVE_SCRYPT
	case NID_id_scrypt:
		return EVP_PBE_scrypt((const char*)kctx->scrypt.pass, kctx->scrypt.passlen,
			kctx->scrypt.salt, kctx->scrypt.saltlen,
			kctx->scrypt.N, kctx->scrypt.r, kctx->scrypt.p,
			kctx->scrypt.maxmem_bytes,
			out, outlen);
#endif
#if HAVE_EVP_PKEY_CTX_KDF
	case NID_tls1_prf:
	case NID_hkdf:
		return EVP_PKEY_derive(kctx->pctx, out, &outlen);
#endif
	default:
		(void)out;
		(void)outlen;
		(void)params;
		return 0;
	}
} /* EVP_KDF_derive() */

#else
typedef EVP_KDF *LUAOSSL_EVP_KDF_PTR;
#define LUAOSSL_EVP_KDF_UNDEF NULL
#endif


/* compat_init must not be called from multiple threads at once */
static int compat_init(void) {
	static int store_index = -1, ssl_ctx_index = -1, done;
	int error = 0;

	if (done)
		goto epilog;

#if defined compat_X509_STORE_free
	/*
	 * We need to unconditionally install at least one external
	 * application data callback. Because these can never be
	 * uninstalled, we can never be unloaded.
	 */
	if ((error = dl_anchor()))
		goto epilog;

	/*
	 * Test if X509_STORE_free obeys reference counts by installing an
	 * onfree callback.
	 */
	if (store_index == -1
	&&  -1 == (store_index = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE, 0, NULL, NULL, NULL, &compat_init_X509_STORE_onfree)))
		goto sslerr;

	if (!(compat.tmp.store = X509_STORE_new()))
		goto sslerr;

	CRYPTO_add(&compat.tmp.store->references, 1, CRYPTO_LOCK_X509_STORE);
	X509_STORE_free(compat.tmp.store);

	if (compat.tmp.store) {
		/*
		 * Because our onfree callback didn't execute, we assume
		 * X509_STORE_free obeys reference counts. Alternatively,
		 * our callback might not have executed for some other
		 * reason. We assert the truth of our assumption by checking
		 * again after calling X509_STORE_free once more.
		 */
		X509_STORE_free(compat.tmp.store);
		assert(compat.tmp.store == NULL);
		compat.tmp.store = NULL; /* in case assertions disabled */
	} else {
		/*
		 * Because our onfree callback was invoked, X509_STORE_free
		 * appears not to obey reference counts. Use our fixed
		 * version in our own code.
		 */
		compat.X509_STORE_free = &compat_X509_STORE_free;

		 /*
		 * Ensure that our fixed version is called on SSL_CTX
		 * destruction.
		 *
		 * NB: We depend on the coincidental order of operations in
		 * SSL_CTX_free that user data destruction occurs before
		 * free'ing the cert_store member. Ruby's OpenSSL bindings
		 * also depend on this order as we both use the onfree
		 * callback to clear the member.
		 */
		if (ssl_ctx_index == -1
		&&  -1 == (ssl_ctx_index = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, 0, NULL, NULL, NULL, &compat_init_SSL_CTX_onfree)))
			goto sslerr;

		compat.flags |= COMPAT_X509_STORE_FREE_BUG;
	}
#endif

	done = 1;
epilog:
	if (compat.tmp.store) {
		X509_STORE_free(compat.tmp.store);
		compat.tmp.store = NULL;
	}

	return error;
sslerr:
	error = auxL_EOPENSSL;

	goto epilog;
} /* compat_init() */


/*
 * Auxiliary OpenSSL API routines (with dependencies on OpenSSL compat)
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static const EVP_MD *auxS_todigest(const char *name, EVP_PKEY *key, const EVP_MD *def) {
	const EVP_MD *md;
	int nid;

	if (name) {
		if ((md = EVP_get_digestbyname(name)))
			return md;
	} else if (key) {
		if ((EVP_PKEY_get_default_digest_nid(key, &nid) > 0)) {
			if ((md = EVP_get_digestbynid(nid)))
				return md;
		}
	}

	return def;
} /* auxS_todigest() */


/*
 * Auxiliary Lua API routines (with dependencies on OpenSSL compat)
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static const EVP_MD *auxL_optdigest(lua_State *L, int index, EVP_PKEY *key, const EVP_MD *def) {
	const char *name = luaL_optstring(L, index, NULL);
	const EVP_MD *md;

	if ((md = auxS_todigest(name, key, NULL)))
		return md;

	if (name) {
		luaL_argerror(L, index, lua_pushfstring(L, "invalid digest type (%s)", name));
		NOTREACHED;
	} else if (key) {
		luaL_argerror(L, index, lua_pushfstring(L, "no digest type for key type (%d)", EVP_PKEY_base_id(key)));
		NOTREACHED;
	}

	return def;
} /* auxL_optdigest() */


/*
 * External Application Data Hooks
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct ex_state {
	lua_State *L;
	LIST_HEAD(, ex_data) data;
}; /* struct ex_state */

#ifndef EX_DATA_MAXARGS
#define EX_DATA_MAXARGS 8
#endif

struct ex_data {
	struct ex_state *state;
	int refs;
	auxref_t arg[EX_DATA_MAXARGS];
	LIST_ENTRY(ex_data) le;
}; /* struct ex_data */

enum {
	EX_SSL_CTX_ALPN_SELECT_CB,
	EX_SSL_CTX_TLSEXT_SERVERNAME_CB,
	EX_SSL_CTX_CUSTOM_EXTENSION_ADD_CB,
	EX_SSL_CTX_CUSTOM_EXTENSION_PARSE_CB,
};

static struct ex_type {
	int class_index; /* OpenSSL object type identifier */
	int index; /* OpenSSL-allocated external data identifier */
	void *(*get_ex_data)();
	int (*set_ex_data)();
} ex_type[] = {
	[EX_SSL_CTX_ALPN_SELECT_CB] = { CRYPTO_EX_INDEX_SSL_CTX, -1, &SSL_CTX_get_ex_data, &SSL_CTX_set_ex_data },
	[EX_SSL_CTX_TLSEXT_SERVERNAME_CB] = { CRYPTO_EX_INDEX_SSL_CTX, -1, &SSL_CTX_get_ex_data, &SSL_CTX_set_ex_data },
	[EX_SSL_CTX_CUSTOM_EXTENSION_ADD_CB] = { CRYPTO_EX_INDEX_SSL_CTX, -1, &SSL_CTX_get_ex_data, &SSL_CTX_set_ex_data },
	[EX_SSL_CTX_CUSTOM_EXTENSION_PARSE_CB] = { CRYPTO_EX_INDEX_SSL_CTX, -1, &SSL_CTX_get_ex_data, &SSL_CTX_set_ex_data },
};

#if OPENSSL_PREREQ(1,1,0)
typedef const CRYPTO_EX_DATA const_CRYPTO_EX_DATA;
#else
typedef CRYPTO_EX_DATA const_CRYPTO_EX_DATA;
#endif

#if OPENSSL_PREREQ(3,0,0)
/* the function signature was fixed in version 3.0.0 */
static int ex_ondup(CRYPTO_EX_DATA *to NOTUSED, const_CRYPTO_EX_DATA *from NOTUSED, void **from_d, int idx NOTUSED, long argl NOTUSED, void *argp NOTUSED) {
#else
static int ex_ondup(CRYPTO_EX_DATA *to NOTUSED, const_CRYPTO_EX_DATA *from NOTUSED, void *from_d, int idx NOTUSED, long argl NOTUSED, void *argp NOTUSED) {
#endif
	struct ex_data **data = (struct ex_data **)from_d;

	if (*data)
		(*data)->refs++;

	return 1;
} /* ex_ondup() */

static void ex_onfree(void *parent NOTUSED, void *_data, CRYPTO_EX_DATA *ad NOTUSED, int idx NOTUSED, long argl NOTUSED, void *argp NOTUSED) {
	struct ex_data *data = _data;

	if (!data || --data->refs > 0)
		return;

	if (data->state) {
		int i;

		for (i = 0; i < (int)countof(data->arg); i++) {
			auxL_unref(data->state->L, &data->arg[i]);
		}

		LIST_REMOVE(data, le);
	}

	free(data);
} /* ex_onfree() */

/* ex_init must not be called from multiple threads at once */
static int ex_init(void) {
	static int done;
	struct ex_type *type;
	int error = 0;

	if (done)
		goto epilog;

	/*
	 * Our callbacks can never be uninstalled, so ensure we're never
	 * unloaded.
	 */
	if ((error = dl_anchor()))
		goto epilog;

	for (type = ex_type; type < endof(ex_type); type++) {
		if (type->index != -1)
			continue;

		if (-1 == (type->index = CRYPTO_get_ex_new_index(type->class_index, 0, NULL, NULL, &ex_ondup, &ex_onfree)))
			goto sslerr;
	};

	done = 1;
epilog:
	return error;
sslerr:
	error = auxL_EOPENSSL;

	goto epilog;
} /* ex_init() */

static int ex__gc(lua_State *L) {
	struct ex_state *state = lua_touserdata(L, 1);
	struct ex_data *data;

	if (!state)
		return 0;

	/* invalidate back references to Lua state */
	for (data = LIST_FIRST(&state->data); data; data = LIST_NEXT(data, le)) {
		data->state = NULL;
	}

	return 0;
} /* ex__gc() */

static _Bool ex_hasstate(lua_State *L) {
	_Bool has;

	lua_pushlightuserdata(L, LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(&ex__gc));
	lua_gettable(L, LUA_REGISTRYINDEX);
	has = !lua_isnil(L, -1);
	lua_pop(L, 1);

	return has;
} /* ex_hasstate() */

static void ex_newstate(lua_State *L) {
	struct ex_state *state;
	struct lua_State *thr;

	if (ex_hasstate(L))
		return;

	state = prepudata(L, sizeof *state, NULL, &ex__gc);
	LIST_INIT(&state->data);

	/*
	 * XXX: Don't reuse mainthread because if an error occurs in a
	 * callback Lua might longjmp across the OpenSSL call stack.
	 * Instead, we'll install our own panic handlers.
	 */
#if defined LUA_RIDX_MAINTHREAD
	(void)thr;
	lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_MAINTHREAD);
	state->L = lua_tothread(L, -1);
	lua_pop(L, 1);
#else
	lua_pushvalue(L, -1);
	thr = lua_newthread(L);
	lua_settable(L, LUA_REGISTRYINDEX);
	state->L = thr;
#endif

	lua_pushlightuserdata(L, LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(&ex__gc));
	lua_pushvalue(L, -2);
	lua_settable(L, LUA_REGISTRYINDEX);

	lua_pop(L, 1);
} /* ex_newstate() */

static struct ex_state *ex_getstate(lua_State *L) {
	struct ex_state *state;

	lua_pushlightuserdata(L, LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(&ex__gc));
	lua_gettable(L, LUA_REGISTRYINDEX);

	luaL_checktype(L, -1, LUA_TUSERDATA);
	state = lua_touserdata(L, -1);
	lua_pop(L, 1);

	return state;
} /* ex_getstate() */

static size_t ex_getdata(lua_State **L, int _type, void *obj) {
	struct ex_type *type = &ex_type[_type];
	struct ex_data *data;
	size_t i;

	if (!(data = type->get_ex_data(obj, type->index)))
		return 0;
	if (!data->state)
		return 0;

	if (!*L)
		*L = data->state->L;

	if (!lua_checkstack(*L, countof(data->arg)))
		return 0;

	for (i = 0; i < countof(data->arg) && data->arg[i] != LUA_NOREF; i++) {
		lua_rawgeti(*L, LUA_REGISTRYINDEX, data->arg[i]);
	}

	return i;
} /* ex_getdata() */

/* returns 0 on success, otherwise error (>0 == errno, -1 == OpenSSL error) */
static int ex_setdata(lua_State *L, int _type, void *obj, size_t n) {
	struct ex_type *type = &ex_type[_type];
	struct ex_state *state;
	struct ex_data *data;
	size_t i, j;

	if (n > countof(data->arg))
		return EOVERFLOW;

	if ((data = type->get_ex_data(obj, type->index)) && data->state) {
		for (i = 0; i < countof(data->arg); i++) {
			auxL_unref(L, &data->arg[i]);
		}
	} else {
		state = ex_getstate(L);

		if (!(data = malloc(sizeof *data)))
			return errno;

		if (!type->set_ex_data(obj, type->index, data))
			return auxL_EOPENSSL;

		data->state = state;
		data->refs = 1;
		for (i = 0; i < countof(data->arg); i++)
			data->arg[i] = LUA_NOREF;
		LIST_INSERT_HEAD(&state->data, data, le);
	}

	for (i = n, j = 0; i > 0 && j < countof(data->arg); i--, j++) {
		auxL_ref(L, -(int)i, &data->arg[j]);
	}

	lua_pop(L, n);

	return 0;
} /* ex_setdata() */

static void initall(lua_State *L);


/*
 * compat - Lua OpenSSL
 *
 * Bindings to our internal feature detection, compatability, and workaround
 * code.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

EXPORT int luaopen__openssl_compat(lua_State *L) {
	initall(L);

	lua_newtable(L);
	lua_pushboolean(L, !!(compat.flags & COMPAT_X509_STORE_FREE_BUG));
	lua_setfield(L, -2, "X509_STORE_FREE_BUG");

	return 1;
} /* luaopen__openssl_compat() */


/*
 * OPENSSL - openssl
 *
 * Miscellaneous global interfaces.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int ossl_version(lua_State *L) {
	if (lua_isnoneornil(L, 1)) {
		auxL_pushunsigned(L, SSLeay());
	} else {
		lua_pushstring(L, SSLeay_version(auxL_checkinteger(L, 1, INT_MIN, INT_MAX)));
	}

	return 1;
} /* ossl_version() */


#if HAVE_SSL_EXTENSION_SUPPORTED
static int ossl_extensionSupported(lua_State *L) {
	unsigned int ext_type = auxL_checkunsigned(L, 1);

	lua_pushboolean(L, SSL_extension_supported(ext_type));

	return 1;
} /* ossl_extensionSupported() */
#endif


static const auxL_Reg ossl_globals[] = {
	{ "version", &ossl_version },
#if HAVE_SSL_EXTENSION_SUPPORTED
	{ "extensionSupported", &ossl_extensionSupported },
#endif
	{ NULL,      NULL },
};

/*
 * NOTE: Compile-time cipher exclusions from openssl-1.0.1i/util/mkdef.pl.
 */
static const char opensslconf_no[][20] = {
#ifdef OPENSSL_NO_RC2
	{ "NO_RC2" },
#endif
#ifdef OPENSSL_NO_RC4
	{ "NO_RC4" },
#endif
#ifdef OPENSSL_NO_RC5
	{ "NO_RC5" },
#endif
#ifdef OPENSSL_NO_IDEA
	{ "NO_IDEA" },
#endif
#ifdef OPENSSL_NO_DES
	{ "NO_DES" },
#endif
#ifdef OPENSSL_NO_BF
	{ "NO_BF" },
#endif
#ifdef OPENSSL_NO_CAST
	{ "NO_CAST" },
#endif
#ifdef OPENSSL_NO_WHIRLPOOL
	{ "NO_WHIRLPOOL" },
#endif
#ifdef OPENSSL_NO_CAMELLIA
	{ "NO_CAMELLIA" },
#endif
#ifdef OPENSSL_NO_SEED
	{ "NO_SEED" },
#endif
#ifdef OPENSSL_NO_MD2
	{ "NO_MD2" },
#endif
#ifdef OPENSSL_NO_MD4
	{ "NO_MD4" },
#endif
#ifdef OPENSSL_NO_MD5
	{ "NO_MD5" },
#endif
#ifdef OPENSSL_NO_SHA
	{ "NO_SHA" },
#endif
#ifdef OPENSSL_NO_RIPEMD
	{ "NO_RIPEMD" },
#endif
#ifdef OPENSSL_NO_MDC2
	{ "NO_MDC2" },
#endif
#ifdef OPENSSL_NO_RSA
	{ "NO_RSA" },
#endif
#ifdef OPENSSL_NO_DSA
	{ "NO_DSA" },
#endif
#ifdef OPENSSL_NO_DH
	{ "NO_DH" },
#endif
#ifdef OPENSSL_NO_HMAC
	{ "NO_HMAC" },
#endif
#ifdef OPENSSL_NO_AES
	{ "NO_AES" },
#endif
#ifdef OPENSSL_NO_KRB5
	{ "NO_KRB5" },
#endif
#ifdef OPENSSL_NO_EC
	{ "NO_EC" },
#endif
#ifdef OPENSSL_NO_ECDSA
	{ "NO_ECDSA" },
#endif
#ifdef OPENSSL_NO_ECDH
	{ "NO_ECDH" },
#endif
#ifdef OPENSSL_NO_ENGINE
	{ "NO_ENGINE" },
#endif
#ifdef OPENSSL_NO_HW
	{ "NO_HW" },
#endif
#ifdef OPENSSL_NO_FP_API
	{ "NO_FP_API" },
#endif
#ifdef OPENSSL_NO_STATIC_ENGINE
	{ "NO_STATIC_ENGINE" },
#endif
#ifdef OPENSSL_NO_GMP
	{ "NO_GMP" },
#endif
#ifdef OPENSSL_NO_DEPRECATED
	{ "NO_DEPRECATED" },
#endif
#ifdef OPENSSL_NO_RFC3779
	{ "NO_RFC3779" },
#endif
#ifdef OPENSSL_NO_PSK
	{ "NO_PSK" },
#endif
#ifdef OPENSSL_NO_TLSEXT
	{ "NO_TLSEXT" },
#endif
#ifdef OPENSSL_NO_CMS
	{ "NO_CMS" },
#endif
#ifdef OPENSSL_NO_CAPIENG
	{ "NO_CAPIENG" },
#endif
#ifdef OPENSSL_NO_JPAKE
	{ "NO_JPAKE" },
#endif
#ifdef OPENSSL_NO_SRP
	{ "NO_SRP" },
#endif
#ifdef OPENSSL_NO_SSL2
	{ "NO_SSL2" },
#endif
#ifdef OPENSSL_NO_EC2M
	{ "NO_EC2M" },
#endif
#ifdef OPENSSL_NO_NISTP_GCC
	{ "NO_NISTP_GCC" },
#endif
#ifdef OPENSSL_NO_NEXTPROTONEG
	{ "NO_NEXTPROTONEG" },
#endif
#ifdef OPENSSL_NO_SCTP
	{ "NO_SCTP" },
#endif
#ifdef OPENSSL_NO_UNIT_TEST
	{ "NO_UNIT_TEST" },
#endif
	{ "" } /* in case nothing is defined above */
}; /* opensslconf_no[] */

static const auxL_IntegerReg openssl_integers[] = {
#ifdef SSLEAY_VERSION_NUMBER
	{ "SSLEAY_VERSION_NUMBER", SSLEAY_VERSION_NUMBER },
#endif
#ifdef SSLEAY_VERSION
	{ "SSLEAY_VERSION", SSLEAY_VERSION },
#endif
#ifdef SSLEAY_OPTIONS
	{ "SSLEAY_OPTIONS", SSLEAY_OPTIONS },
#endif
#ifdef SSLEAY_CFLAGS
	{ "SSLEAY_CFLAGS", SSLEAY_CFLAGS },
#endif
#ifdef SSLEAY_BUILT_ON
	{ "SSLEAY_BUILT_ON", SSLEAY_BUILT_ON },
#endif
#ifdef SSLEAY_PLATFORM
	{ "SSLEAY_PLATFORM", SSLEAY_PLATFORM },
#endif
#ifdef SSLEAY_DIR
	{ "SSLEAY_DIR", SSLEAY_DIR },
#endif
#ifdef LIBRESSL_VERSION_NUMBER
	{ "LIBRESSL_VERSION_NUMBER", LIBRESSL_VERSION_NUMBER },
#endif
#ifdef OPENSSL_VERSION_NUMBER
	{ "OPENSSL_VERSION_NUMBER", OPENSSL_VERSION_NUMBER },
#endif
#ifdef LIBRESSL_VERSION_NUMBER
	{ "VERSION_NUMBER", LIBRESSL_VERSION_NUMBER },
#elif OPENSSL_VERSION_NUMBER
	{ "VERSION_NUMBER", OPENSSL_VERSION_NUMBER },
#else
	{ "VERSION_NUMBER", SSLEAY_VERSION_NUMBER },
#endif
	{ NULL, 0 },
};

EXPORT int luaopen__openssl(lua_State *L) {
	size_t i;

	auxL_newlib(L, ossl_globals, 0);

	for (i = 0; i < countof(opensslconf_no); i++) {
		if (*opensslconf_no[i]) {
			lua_pushboolean(L, 1);
			lua_setfield(L, -2, opensslconf_no[i]);
		}
	}

	auxL_setintegers(L, openssl_integers);

	lua_pushstring(L, OPENSSL_VERSION_TEXT);
	lua_setfield(L, -2, "VERSION_TEXT");

#ifdef SHLIB_VERSION_HISTORY
	lua_pushstring(L, SHLIB_VERSION_HISTORY);
	lua_setfield(L, -2, "SHLIB_VERSION_HISTORY");
#endif

#ifdef SHLIB_VERSION_NUMBER
	lua_pushstring(L, SHLIB_VERSION_NUMBER);
	lua_setfield(L, -2, "SHLIB_VERSION_NUMBER");
#endif

	return 1;
} /* luaopen__openssl() */


/*
 * BIGNUM - openssl.bignum
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static BIGNUM *bn_push(lua_State *L) {
	BIGNUM **ud = prepsimple(L, BIGNUM_CLASS);

	if (!(*ud = BN_new()))
		auxL_error(L, auxL_EOPENSSL, "bignum.new");

	return *ud;
} /* bn_push() */


static BIGNUM *bn_dup(lua_State *L, const BIGNUM *src) {
	BIGNUM **ud = prepsimple(L, BIGNUM_CLASS);

	if (!(*ud = BN_dup(src)))
		auxL_error(L, auxL_EOPENSSL, "bignum");

	return *ud;
} /* bn_dup() */


static BIGNUM *bn_dup_nil(lua_State *L, const BIGNUM *src) {
	return (src)? bn_dup(L, src) : (lua_pushnil(L), (BIGNUM *)0);
} /* bn_dup_nil() */


#define checkbig_(a, b, c, ...) checkbig((a), (b), (c))
#define checkbig(...) EXPAND( checkbig_(__VA_ARGS__, &(_Bool){ 0 }, 0) )

static BIGNUM *(checkbig)(lua_State *, int, _Bool *);

static int bn_new(lua_State *L) {
	int i, n;

	if ((n = lua_gettop(L)) > 0) {
		for (i = 1; i <= n; i++)
			checkbig(L, i);

		return n;
	} else {
		bn_push(L);

		return 1;
	}
} /* bn_new() */


static int bn_fromBinary(lua_State *L) {
	size_t len;
	const char *s = luaL_checklstring(L, 1, &len);
	BIGNUM *bn = bn_push(L);
	if (!BN_bin2bn((const unsigned char*)s, len, bn)) {
		auxL_error(L, auxL_EOPENSSL, "bignum");
	}
	return 1;
} /* bn_fromBinary() */


static int bn_interpose(lua_State *L) {
	return interpose(L, BIGNUM_CLASS);
} /* bn_interpose() */


/* return integral part */
static inline double intof(double f) {
	return (isfinite(f))? floor(fabs(f)) : 0.0;
} /* intof() */


/* convert integral to BN_ULONG. returns success or failure. */
static _Bool int2ul(BN_ULONG *ul, double f) {
	int exp;

	frexp(f, &exp);

	if (exp > (int)sizeof *ul * 8)
		return 0;

	*ul = (BN_ULONG)f;

	return 1;
} /* int2ul() */


/* convert integral BIGNUM. returns success or failure. */
static _Bool int2bn(BIGNUM **bn, double q) {
	unsigned char nib[32], bin[32], *p;
	size_t i, n;
	double r;

	p = nib;

	while (q >= 1.0 && p < endof(nib)) {
		r = fmod(q, 256.0);
		*p++ = r;
		q = round((q - r) / 256.0);
	}

	n = p - nib;

	for (i = 0; i < n; i++) {
		bin[i] = *--p;
	}

	if (!(*bn = BN_bin2bn(bin, n, *bn)))
		return 0;

	return 1;
} /* int2bn() */


/* convert double to BIGNUM. returns success or failure. */
static _Bool f2bn(BIGNUM **bn, double f) {
	double i = intof(f);
	BN_ULONG lu;

	if (int2ul(&lu, i)) {
		if (!*bn && !(*bn = BN_new()))
			return 0;

		if (!BN_set_word(*bn, lu))
			return 0;
	} else if (!int2bn(bn, i))
		return 0;

	BN_set_negative(*bn, signbit(f));

	return 1;
} /* f2bn() */


static BIGNUM *(checkbig)(lua_State *L, int index, _Bool *lvalue) {
	BIGNUM **bn;
	const char *str;
	size_t len, i;
	_Bool neg, hex;

	index = lua_absindex(L, index);

	switch (lua_type(L, index)) {
	case LUA_TSTRING:
		*lvalue = 0;

		str = lua_tolstring(L, index, &len);

		neg = (str[0] == '-');
		hex = (str[neg] == '0' && (str[neg+1] == 'x' || str[neg+1] == 'X'));

		if (hex) {
			luaL_argcheck(L, len > 2+(size_t)neg, index, "invalid hex string");
			for (i = 2+neg; i < len; i++) {
				if (!isxdigit((unsigned char)str[i]))
					luaL_argerror(L, 1, "invalid hex string");
			}
		} else {
			luaL_argcheck(L, len > neg, index, "invalid decimal string");
			for (i = neg; i < len; i++) {
				if (!isdigit((unsigned char)str[i]))
					luaL_argerror(L, 1, "invalid decimal string");
			}
		}

		bn = prepsimple(L, BIGNUM_CLASS);

		if (hex) {
			if (!BN_hex2bn(bn, str+2+neg))
				auxL_error(L, auxL_EOPENSSL, "bignum");
			if (neg)
				BN_set_negative(*bn, 1);
		} else {
			if (!BN_dec2bn(bn, str))
				auxL_error(L, auxL_EOPENSSL, "bignum");
		}

		lua_replace(L, index);

		return *bn;
	case LUA_TNUMBER:
		*lvalue = 0;

		bn = prepsimple(L, BIGNUM_CLASS);

#if LUA_VERSION_NUM >= 503
		if (lua_isinteger(L, index)) {
			lua_Integer n = lua_tointeger(L, index);
			auxL_Unsigned lu;

			if (!*bn && !(*bn = BN_new()))
				auxL_error(L, auxL_EOPENSSL, "bignum");

			neg = n < 0;
			lu = neg ? (0 - n) : n;

			if (!BN_set_word(*bn, lu))
				auxL_error(L, auxL_EOPENSSL, "bignum");

			if (neg)
				BN_set_negative(*bn, 1);
		} else
#endif
		if (!f2bn(bn, lua_tonumber(L, index)))
			auxL_error(L, auxL_EOPENSSL, "bignum");

		lua_replace(L, index);

		return *bn;
	default:
		*lvalue = 1;

		return checksimple(L, index, BIGNUM_CLASS);
	} /* switch() */
} /* checkbig() */


/* prepare number at top of stack for unary operation, and push result object onto stack  */
static void bn_prepuop(lua_State *L, BIGNUM **r, BIGNUM **a, _Bool commute) {
	_Bool lvalue = 1;

	*a = checkbig(L, -1, &lvalue);

	if (!lvalue && commute) {
		lua_pushvalue(L, -1);
	} else {
		bn_push(L);
	}

	*r = *(BIGNUM **)lua_touserdata(L, -1);
} /* bn_prepuop() */


/* prepare numbers at top of stack for binary operation, and push result object onto stack  */
static void bn_prepbop(lua_State *L, BIGNUM **r, BIGNUM **a, BIGNUM **b, _Bool commute) {
	_Bool a_lvalue, b_lvalue;

	*a = checkbig(L, -2, &a_lvalue);
	*b = checkbig(L, -1, &b_lvalue);

	if (commute && !a_lvalue) {
		lua_pushvalue(L, -2);
	} else if (commute && !b_lvalue) {
		lua_pushvalue(L, -1);
	} else {
		bn_push(L);
	}

	*r = *(BIGNUM **)lua_touserdata(L, -1);
} /* bn_prepbop() */


/* prepare numbers at top of stack for ternary operation, and push result object onto stack  */
static void bn_preptop(lua_State *L, BIGNUM **r, BIGNUM **a, BIGNUM **b, BIGNUM **c) {
	_Bool a_lvalue, b_lvalue, c_lvalue;

	*a = checkbig(L, 1, &a_lvalue);
	*b = checkbig(L, 2, &b_lvalue);
	*c = checkbig(L, 3, &c_lvalue);

	bn_push(L);

	*r = *(BIGNUM **)lua_touserdata(L, -1);
} /* bn_preptop() */


static int ctx__gc(lua_State *L) {
	BN_CTX **ctx = lua_touserdata(L, 1);

	if (*ctx) {
		BN_CTX_free(*ctx);
		*ctx = NULL;
	}

	return 0;
} /* ctx__gc() */

static BN_CTX *getctx(lua_State *L) {
	BN_CTX **ctx;

	lua_pushlightuserdata(L, LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(&ctx__gc));
	lua_gettable(L, LUA_REGISTRYINDEX);

	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);

		ctx = prepsimple(L, NULL, &ctx__gc);

		if (!(*ctx = BN_CTX_new()))
			auxL_error(L, auxL_EOPENSSL, "bignum");

		lua_pushlightuserdata(L, LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(&ctx__gc));
		lua_pushvalue(L, -2);
		lua_settable(L, LUA_REGISTRYINDEX);
	}

	ctx = lua_touserdata(L, -1);
	lua_pop(L, 1);

	return *ctx;
} /* getctx() */


static int bn_toBinary(lua_State *L) {
	BIGNUM *bn = checksimple(L, 1, BIGNUM_CLASS);
	size_t len;
	void *dst;

	len = BN_num_bytes(bn);
	dst = lua_newuserdata(L, len);
	BN_bn2bin(bn, dst);
	lua_pushlstring(L, dst, len);

	return 1;
} /* bn_toBinary() */


static int bn__add(lua_State *L) {
	BIGNUM *r, *a, *b;

	lua_settop(L, 2);
	bn_prepbop(L, &r, &a, &b, 1);

	if (!BN_add(r, a, b))
		return auxL_error(L, auxL_EOPENSSL, "bignum:__add");

	return 1;
} /* bn__add() */


static int bn__sub(lua_State *L) {
	BIGNUM *r, *a, *b;

	lua_settop(L, 2);
	bn_prepbop(L, &r, &a, &b, 0);

	if (!BN_sub(r, a, b))
		return auxL_error(L, auxL_EOPENSSL, "bignum:__sub");

	return 1;
} /* bn__sub() */


static int bn__mul(lua_State *L) {
	BIGNUM *r, *a, *b;

	lua_settop(L, 2);
	bn_prepbop(L, &r, &a, &b, 1);

	if (!BN_mul(r, a, b, getctx(L)))
		return auxL_error(L, auxL_EOPENSSL, "bignum:__mul");

	return 1;
} /* bn__mul() */


static int bn_sqr(lua_State *L) {
	BIGNUM *r, *a;

	lua_settop(L, 1);
	bn_prepuop(L, &r, &a, 1);

	if (!BN_sqr(r, a, getctx(L)))
		return auxL_error(L, auxL_EOPENSSL, "bignum:sqr");

	return 1;
} /* bn_sqr() */


static int bn__idiv(lua_State *L) {
	BIGNUM *dv, *a, *b;

	lua_settop(L, 2);
	bn_prepbop(L, &dv, &a, &b, 0);

	if (!BN_div(dv, NULL, a, b, getctx(L)))
		return auxL_error(L, auxL_EOPENSSL, "bignum:__idiv");

	return 1;
} /* bn__idiv() */


static int bn__mod(lua_State *L) {
	BIGNUM *r, *a, *b;

	lua_settop(L, 2);
	bn_prepbop(L, &r, &a, &b, 0);

	if (!BN_mod(r, a, b, getctx(L)))
		return auxL_error(L, auxL_EOPENSSL, "bignum:__mod");

	/* lua has different rounding behaviour for mod than C */
	if (!BN_is_zero(r) && (BN_is_negative(a) ^ BN_is_negative(b))) {
		if (!BN_add(r, r, b))
			return auxL_error(L, auxL_EOPENSSL, "bignum:__mod");
	}

	return 1;
} /* bn__mod() */


static int bn_nnmod(lua_State *L) {
	BIGNUM *r, *a, *b;

	lua_settop(L, 2);
	bn_prepbop(L, &r, &a, &b, 0);

	if (!BN_nnmod(r, a, b, getctx(L)))
		return auxL_error(L, auxL_EOPENSSL, "bignum:nnmod");

	return 1;
} /* bn_nnmod() */


static int bn_mod_add(lua_State *L) {
	BIGNUM *r, *a, *b, *c;

	lua_settop(L, 3);
	bn_preptop(L, &r, &a, &b, &c);

	if (!BN_mod_add(r, a, b, c, getctx(L)))
		return auxL_error(L, auxL_EOPENSSL, "bignum:mod_add");

	return 1;
} /* bn_mod_add() */


static int bn_mod_sub(lua_State *L) {
	BIGNUM *r, *a, *b, *c;

	lua_settop(L, 3);
	bn_preptop(L, &r, &a, &b, &c);

	if (!BN_mod_sub(r, a, b, c, getctx(L)))
		return auxL_error(L, auxL_EOPENSSL, "bignum:mod_sub");

	return 1;
} /* bn_mod_sub() */


static int bn_mod_mul(lua_State *L) {
	BIGNUM *r, *a, *b, *c;

	lua_settop(L, 3);
	bn_preptop(L, &r, &a, &b, &c);

	if (!BN_mod_mul(r, a, b, c, getctx(L)))
		return auxL_error(L, auxL_EOPENSSL, "bignum:mod_mul");

	return 1;
} /* bn_mod_mul() */


static int bn_mod_sqr(lua_State *L) {
	BIGNUM *r, *a, *b;

	lua_settop(L, 2);
	bn_prepbop(L, &r, &a, &b, 0);

	if (!BN_mod_sqr(r, a, b, getctx(L)))
		return auxL_error(L, auxL_EOPENSSL, "bignum:mod_sqr");

	return 1;
} /* bn_mod_sqr() */


static int bn__pow(lua_State *L) {
	BIGNUM *r, *a, *b;

	lua_settop(L, 2);
	bn_prepbop(L, &r, &a, &b, 0);

	if (!BN_exp(r, a, b, getctx(L)))
		return auxL_error(L, auxL_EOPENSSL, "bignum:__pow");

	return 1;
} /* bn__pow() */


static int bn_mod_exp(lua_State *L) {
	BIGNUM *r, *a, *b, *c;

	lua_settop(L, 3);
	bn_preptop(L, &r, &a, &b, &c);

	if (!BN_mod_exp(r, a, b, c, getctx(L)))
		return auxL_error(L, auxL_EOPENSSL, "bignum:mod_exp");

	return 1;
} /* bn_mod_exp() */


static int bn_gcd(lua_State *L) {
	BIGNUM *r, *a, *b;

	lua_settop(L, 2);
	bn_prepbop(L, &r, &a, &b, 1);

	if (!BN_gcd(r, a, b, getctx(L)))
		return auxL_error(L, auxL_EOPENSSL, "bignum:gcd");

	return 1;
} /* bn_gcd() */


static int bn__shl(lua_State *L) {
	BIGNUM *r, *a;
	int n;

	a = checkbig(L, 1);
	n = luaL_checkinteger(L, 2);
	r = bn_push(L);

	if (!BN_lshift(r, a, n))
		return auxL_error(L, auxL_EOPENSSL, "bignum:__shl");

	return 1;
} /* bn__shl() */


static int bn__shr(lua_State *L) {
	BIGNUM *r, *a;
	int n;

	a = checkbig(L, 1);
	n = luaL_checkinteger(L, 2);
	r = bn_push(L);

	if (!BN_rshift(r, a, n))
		return auxL_error(L, auxL_EOPENSSL, "bignum:__shr");

	return 1;
} /* bn__shr() */


static int bn__unm(lua_State *L) {
	BIGNUM *a = checksimple(L, 1, BIGNUM_CLASS);
	BIGNUM *r = bn_dup(L, a);

	BN_set_negative(r, !BN_is_negative(a));

	return 1;
} /* bn__unm() */


static int bn__eq(lua_State *L) {
	BIGNUM *a = checksimple(L, 1, BIGNUM_CLASS);
	BIGNUM *b = checksimple(L, 2, BIGNUM_CLASS);

	lua_pushboolean(L, 0 == BN_cmp(a, b));

	return 1;
} /* bn__eq() */


static int bn__lt(lua_State *L) {
	BIGNUM *a = checksimple(L, 1, BIGNUM_CLASS);
	BIGNUM *b = checksimple(L, 2, BIGNUM_CLASS);
	int cmp = BN_cmp(a, b);

	lua_pushboolean(L, cmp == -1);

	return 1;
} /* bn__lt() */


static int bn__le(lua_State *L) {
	BIGNUM *a = checksimple(L, 1, BIGNUM_CLASS);
	BIGNUM *b = checksimple(L, 2, BIGNUM_CLASS);
	int cmp = BN_cmp(a, b);

	lua_pushboolean(L, cmp <= 0);

	return 1;
} /* bn__le() */


static int bn__gc(lua_State *L) {
	BIGNUM **ud = luaL_checkudata(L, 1, BIGNUM_CLASS);

	if (*ud) {
		BN_clear_free(*ud);
		*ud = NULL;
	}

	return 0;
} /* bn__gc() */


static int bn_generatePrime(lua_State *L) {
	int bits = luaL_checkinteger(L, 1);
	_Bool safe = optbool(L, 2, 0);
	const BIGNUM *add = lua_isnoneornil(L, 3) ? NULL : checkbig(L, 3);
	const BIGNUM *rem = lua_isnoneornil(L, 4) ? NULL : checkbig(L, 4);
	BIGNUM *bn = bn_push(L);

	if (!BN_generate_prime_ex(bn, bits, safe, add, rem, NULL))
		return auxL_error(L, auxL_EOPENSSL, "bignum.generatePrime");

	return 1;
} /* bn_generatePrime() */


static int bn_isPrime(lua_State *L) {
	BIGNUM *bn = checksimple(L, 1, BIGNUM_CLASS);
	int nchecks = luaL_optinteger(L, 2, BN_prime_checks);
#if OPENSSL_PREREQ(3,0,0)
	int res = BN_check_prime(bn, getctx(L), NULL);
#else
	int res = BN_is_prime_ex(bn, nchecks, getctx(L), NULL);
#endif

	if (res == -1)
		return auxL_error(L, auxL_EOPENSSL, "bignum:isPrime");

	lua_pushboolean(L, res);

	return 1;
} /* bn_isPrime() */


static BIO *getbio(lua_State *);

static int bn_toDecimal(lua_State *L) {
	BIGNUM *bn = checksimple(L, 1, BIGNUM_CLASS);
	char *txt = NULL;
	BIO *bio;
	BUF_MEM *buf;

	if (!(txt = BN_bn2dec(bn)))
		goto sslerr;

	/* use GC-visible BIO as temporary buffer */
	bio = getbio(L);

	if (BIO_puts(bio, txt) < 0)
		goto sslerr;

	OPENSSL_free(txt);
	txt = NULL;

	BIO_get_mem_ptr(bio, &buf);
	lua_pushlstring(L, buf->data, buf->length);

	return 1;
sslerr:
	OPENSSL_free(txt);

	return auxL_error(L, auxL_EOPENSSL, "bignum:toDecimal");
} /* bn_toDecimal() */


static int bn_toHex(lua_State *L) {
	BIGNUM *bn = checksimple(L, 1, BIGNUM_CLASS);
	char *txt = NULL;
	BIO *bio;
	BUF_MEM *buf;

	if (!(txt = BN_bn2hex(bn)))
		goto sslerr;

	/* use GC-visible BIO as temporary buffer */
	bio = getbio(L);

	if (BIO_puts(bio, txt) < 0)
		goto sslerr;

	OPENSSL_free(txt);
	txt = NULL;

	BIO_get_mem_ptr(bio, &buf);
	lua_pushlstring(L, buf->data, buf->length);

	return 1;
sslerr:
	OPENSSL_free(txt);

	return auxL_error(L, auxL_EOPENSSL, "bignum:toHex");
} /* bn_toHex() */


static const auxL_Reg bn_methods[] = {
	{ "add",       &bn__add },
	{ "sub",       &bn__sub },
	{ "mul",       &bn__mul },
	{ "sqr",       &bn_sqr },
	{ "idiv",      &bn__idiv },
	{ "mod",       &bn__mod },
	{ "nnmod",     &bn_nnmod },
	{ "mod_add",   &bn_mod_add },
	{ "mod_sub",   &bn_mod_sub },
	{ "mod_mul",   &bn_mod_mul },
	{ "mod_sqr",   &bn_mod_sqr },
	{ "exp",       &bn__pow },
	{ "mod_exp",   &bn_mod_exp },
	{ "gcd",       &bn_gcd },
	{ "lshift",    &bn__shl },
	{ "rshift",    &bn__shr },
	{ "isPrime",   &bn_isPrime },
	{ "toBinary",  &bn_toBinary },
	{ "toDecimal", &bn_toDecimal },
	{ "toHex",     &bn_toHex },
	/* deprecated */
	{ "tobin",     &bn_toBinary },
	{ "todec",     &bn_toDecimal },
	{ "tohex",     &bn_toHex },
	{ NULL,        NULL },
};

static const auxL_Reg bn_metatable[] = {
	{ "__add",      &bn__add },
	{ "__sub",      &bn__sub },
	{ "__mul",      &bn__mul },
	{ "__div",      &bn__idiv },
	{ "__idiv",     &bn__idiv },
	{ "__mod",      &bn__mod },
	{ "__pow",      &bn__pow },
	{ "__unm",      &bn__unm },
	{ "__shl",      &bn__shl },
	{ "__shr",      &bn__shr },
	{ "__eq",       &bn__eq },
	{ "__lt",       &bn__lt },
	{ "__le",       &bn__le },
	{ "__gc",       &bn__gc },
	{ "__tostring", &bn_toDecimal },
	{ NULL,         NULL },
};


static const auxL_Reg bn_globals[] = {
	{ "new",           &bn_new },
	{ "interpose",     &bn_interpose },
	{ "fromBinary",    &bn_fromBinary },
	{ "generatePrime", &bn_generatePrime },
	{ NULL,            NULL },
};

EXPORT int luaopen__openssl_bignum(lua_State *L) {
	initall(L);

	auxL_newlib(L, bn_globals, 0);

	return 1;
} /* luaopen__openssl_bignum() */


/*
 * EVP_PKEY - openssl.pkey
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int bio__gc(lua_State *L) {
	BIO **bio = lua_touserdata(L, 1);

	if (*bio) {
		BIO_free(*bio);
		*bio = NULL;
	}

	return 0;
} /* bio__gc() */

static BIO *getbio(lua_State *L) {
	BIO **bio;

	lua_pushlightuserdata(L, LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(&bio__gc));
	lua_gettable(L, LUA_REGISTRYINDEX);

	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);

		bio = prepsimple(L, NULL, &bio__gc);

		if (!(*bio = BIO_new(BIO_s_mem())))
			auxL_error(L, auxL_EOPENSSL, "BIO_new");

		lua_pushlightuserdata(L, LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(&bio__gc));
		lua_pushvalue(L, -2);
		lua_settable(L, LUA_REGISTRYINDEX);
	}

	bio = lua_touserdata(L, -1);
	lua_pop(L, 1);

	BIO_reset(*bio);

	return *bio;
} /* getbio() */


static int pk_new(lua_State *L) {
	EVP_PKEY **ud;

	/* #1 table or key; if key, #2 format and #3 type */
	lua_settop(L, 3);

	if (lua_istable(L, 1) || lua_isnil(L, 1)) {
		int type = EVP_PKEY_RSA;
		unsigned bits = 1024;
		BIGNUM *exp = NULL;
		int generator = 2;
		int curve = NID_X9_62_prime192v1;
		const char *id;
		const char *dhparam = NULL;
		lua_Number n;

		if (lua_istable(L, 1)) {
			if (loadfield(L, 1, "type", LUA_TSTRING, (void*)&id)) {
				static const struct { int nid; const char *sn; } types[] = {
					{ EVP_PKEY_RSA, "RSA" },
					{ EVP_PKEY_DSA, "DSA" },
					{ EVP_PKEY_DH,  "DH" },
					{ EVP_PKEY_EC,  "EC" },
				};
				unsigned i;

				if (NID_undef == (type = EVP_PKEY_type(OBJ_sn2nid(id)))) {
					for (i = 0; i < countof(types); i++) {
						if (strieq(id, types[i].sn)) {
							type = types[i].nid;
							break;
						}
					}
				}

				luaL_argcheck(L, type != NID_undef, 1, lua_pushfstring(L, "%s: invalid key type", id));
			}

			switch(type) {
			case EVP_PKEY_RSA:
				if (loadfield(L, 1, "bits", LUA_TNUMBER, &n)) {
					luaL_argcheck(L, n > 0 && n < UINT_MAX, 1, lua_pushfstring(L, "%f: `bits' invalid", n));
					bits = (unsigned)n;
				}

				if (getfield(L, 1, "exp")) {
					exp = checkbig(L, -1);
				}
				break;
			case EVP_PKEY_DH:
				/* dhparam field can contain a PEM encoded string.
				   The "dhparam" field takes precedence over "bits" */
				if (loadfield(L, 1, "dhparam", LUA_TSTRING, (void*)&dhparam))
					break;

				if (loadfield(L, 1, "bits", LUA_TNUMBER, &n)) {
					luaL_argcheck(L, n > 0 && n < UINT_MAX, 1, lua_pushfstring(L, "%f: `bits' invalid", n));
					bits = (unsigned)n;
				}

				/* compat: DH used to use the 'exp' field for the generator */
				if (loadfield(L, 1, "generator", LUA_TNUMBER, &n) || loadfield(L, 1, "exp", LUA_TNUMBER, &n)) {
					luaL_argcheck(L, n > 0 && n <= INT_MAX, 1, lua_pushfstring(L, "%f: `exp' invalid", n));
					generator = (int)n;
				}
				break;
			case EVP_PKEY_EC:
				if (loadfield(L, 1, "curve", LUA_TSTRING, (void*)&id)) {
					if (!auxS_txt2nid(&curve, id))
						luaL_argerror(L, 1, lua_pushfstring(L, "%s: invalid curve", id));
				}
				break;
			}
		}

		/* defaults that require allocation */
		switch (type) {
		case EVP_PKEY_RSA:
			if(!exp) {
				/* default to 65537 */
				exp = bn_push(L);
				if (!BN_add_word(exp, 65537))
					return auxL_error(L, auxL_EOPENSSL, "pkey.new");
			}
			break;
		}

		ud = prepsimple(L, PKEY_CLASS);

		switch (type) {
		case EVP_PKEY_RSA: {
			RSA *rsa;

			if (!(*ud = EVP_PKEY_new()))
				return auxL_error(L, auxL_EOPENSSL, "pkey.new");

			if (!(rsa = RSA_new()))
				return auxL_error(L, auxL_EOPENSSL, "pkey.new");

			if (!RSA_generate_key_ex(rsa, bits, exp, 0)) {
				RSA_free(rsa);
				return auxL_error(L, auxL_EOPENSSL, "pkey.new");
			}

			EVP_PKEY_set1_RSA(*ud, rsa);

			RSA_free(rsa);

			break;
		}
		case EVP_PKEY_DSA: {
			DSA *dsa;

			if (!(*ud = EVP_PKEY_new()))
				return auxL_error(L, auxL_EOPENSSL, "pkey.new");

			if (!(dsa = DSA_new()))
				return auxL_error(L, auxL_EOPENSSL, "pkey.new");

			if (!DSA_generate_parameters_ex(dsa, bits, 0, 0, 0, 0, 0)) {
				DSA_free(dsa);
				return auxL_error(L, auxL_EOPENSSL, "pkey.new");
			}

			if (!DSA_generate_key(dsa)) {
				DSA_free(dsa);
				return auxL_error(L, auxL_EOPENSSL, "pkey.new");
			}

			EVP_PKEY_set1_DSA(*ud, dsa);

			DSA_free(dsa);

			break;
		}
		case EVP_PKEY_DH: {
			DH *dh;

			if (!(*ud = EVP_PKEY_new()))
				return auxL_error(L, auxL_EOPENSSL, "pkey.new");

			/* DH Parameter Generation can take a long time, therefore we look
			 * at the "dhparam" field, provided by the user.
			 * The "dhparam" field takes precedence over "bits"
			 */
			if (dhparam) {
				BIO *bio = BIO_new_mem_buf((void*)dhparam, strlen(dhparam));
				if (!bio)
					return auxL_error(L, auxL_EOPENSSL, "pkey.new");

				dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
				BIO_free(bio);
				if (!dh)
					return auxL_error(L, auxL_EOPENSSL, "pkey.new");
			} else {
				if (!(dh = DH_new()))
					return auxL_error(L, auxL_EOPENSSL, "pkey.new");

				if (!DH_generate_parameters_ex(dh, bits, generator, 0)) {
					DH_free(dh);
					return auxL_error(L, auxL_EOPENSSL, "pkey.new");
				}
			}


			if (!DH_generate_key(dh)) {
				DH_free(dh);
				return auxL_error(L, auxL_EOPENSSL, "pkey.new");
			}

			EVP_PKEY_set1_DH(*ud, dh);

			DH_free(dh);

			break;
		}
#ifndef OPENSSL_NO_EC
		case EVP_PKEY_EC: {
			EC_GROUP *grp;
			EC_KEY *key;

			if (!(*ud = EVP_PKEY_new()))
				return auxL_error(L, auxL_EOPENSSL, "pkey.new");

			if (!(grp = EC_GROUP_new_by_curve_name(curve)))
				return auxL_error(L, auxL_EOPENSSL, "pkey.new");

			EC_GROUP_set_asn1_flag(grp, OPENSSL_EC_NAMED_CURVE);

			/* compressed points patented */
			EC_GROUP_set_point_conversion_form(grp, POINT_CONVERSION_UNCOMPRESSED);

			if (!(key = EC_KEY_new())) {
				EC_GROUP_free(grp);
				return auxL_error(L, auxL_EOPENSSL, "pkey.new");
			}

			EC_KEY_set_group(key, grp);

			EC_GROUP_free(grp);

			if (!EC_KEY_generate_key(key)) {
				EC_KEY_free(key);
				return auxL_error(L, auxL_EOPENSSL, "pkey.new");
			}

			EVP_PKEY_set1_EC_KEY(*ud, key);

			EC_KEY_free(key);

			break;
		}
#endif
		default:
#if HAVE_EVP_PKEY_KEYGEN
		{
			EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(type, NULL);
			if (!ctx)
				return auxL_error(L, auxL_EOPENSSL, "pkey.new");

			if (EVP_PKEY_keygen_init(ctx) <= 0) {
				EVP_PKEY_CTX_free(ctx);
				return auxL_error(L, auxL_EOPENSSL, "pkey.new");
			}

			if (EVP_PKEY_keygen(ctx, ud) != 1) {
				EVP_PKEY_CTX_free(ctx);
				return auxL_error(L, auxL_EOPENSSL, "pkey.new");
			}

			break;
		}
#else
			return luaL_error(L, "%d: unsupported EVP_PKEY base type", EVP_PKEY_type(type));
#endif
		} /* switch() */
	} else if (lua_isstring(L, 1)) {
		int type = optencoding(L, 2, "*", X509_ANY|X509_PEM|X509_DER);
		int pubonly = 0, prvtonly = 0;
		const char *opt, *data;
		size_t len;
		BIO *bio;
		EVP_PKEY *pub = NULL, *prvt = NULL;
		int goterr = 0;

		/* check if specified publickey or privatekey */
		if ((opt = luaL_optstring(L, 3, NULL))) {
			if (xtolower(opt[0]) == 'p' && xtolower(opt[1]) == 'u') {
				pubonly = 1;
			} else if (xtolower(opt[0]) == 'p' && xtolower(opt[1]) == 'r') {
				prvtonly = 1;
			} else {
				return luaL_argerror(L, 3, lua_pushfstring(L, "invalid option %s", opt));
			}
		}

		data = luaL_checklstring(L, 1, &len);

		ud = prepsimple(L, PKEY_CLASS);

		if (!(bio = BIO_new_mem_buf((void *)data, len)))
			return auxL_error(L, auxL_EOPENSSL, "pkey.new");

		if (type == X509_PEM || type == X509_ANY) {
			if (!prvtonly && !pub) {
				/*
				 * BIO_reset is a rewind for read-only
				 * memory buffers. See mem_ctrl in
				 * crypto/bio/bss_mem.c of OpenSSL source.
				 */
				BIO_reset(bio);

				if (!(pub = PEM_read_bio_PUBKEY(bio, NULL, 0, "")))
					goterr = 1;
			}

			if (!pubonly && !prvt) {
				BIO_reset(bio);

				if (!(prvt = PEM_read_bio_PrivateKey(bio, NULL, 0, "")))
					goterr = 1;
			}
		}

		if (type == X509_DER || type == X509_ANY) {
			if (!prvtonly && !pub) {
				BIO_reset(bio);

				if (!(pub = d2i_PUBKEY_bio(bio, NULL)))
					goterr = 1;
			}

			if (!pubonly && !prvt) {
				BIO_reset(bio);

				if (!(prvt = d2i_PrivateKey_bio(bio, NULL)))
					goterr = 1;
			}
		}

		if (prvt) {
#if 0
			/* TODO: Determine if this is necessary. */
			if (pub && EVP_PKEY_missing_parameters(prvt)) {
				if (!EVP_PKEY_copy_parameters(prvt, pub)) {
					/*
					 * NOTE: It's not necessarily true
					 * that any internal errors were
					 * set. But we fixed pusherror() to
					 * handle that situation.
					 */
					goterr = 1;

					goto done;
				}
			}
#endif

			*ud = prvt;
			prvt = NULL;
		} else if (pub) {
			*ud = pub;
			pub = NULL;
		}
done:
		BIO_free(bio);

		if (pub)
			EVP_PKEY_free(pub);

		if (prvt)
			EVP_PKEY_free(prvt);

		if (!*ud) {
			if (goterr)
				return auxL_error(L, auxL_EOPENSSL, "pkey.new");

			/* we should never get here */
			return luaL_error(L, "failed to load key for some unexpected reason");
		} else if (goterr) {
			/* clean up our mess from testing input formats */
			ERR_clear_error();
		}
	} else {
		return luaL_error(L, "%s: unknown key initializer", lua_typename(L, lua_type(L, 1)));
	}

	return 1;
} /* pk_new() */


static int pk_interpose(lua_State *L) {
	lua_settop(L, 2);

	luaL_getmetatable(L, PKEY_CLASS);
	if (!strncmp("__", luaL_checkstring(L, 1), 2)) {
		lua_insert(L, 1);
	} else {
		lua_getfield(L, -1, "__index");
		lua_getupvalue(L, -1, 1);
		lua_insert(L, 1);
		lua_pop(L, 2);
	}

	return auxL_swaptable(L, 1);
} /* pk_interpose() */


static int pk_type(lua_State *L) {
	EVP_PKEY *key = checksimple(L, 1, PKEY_CLASS);
	int nid = EVP_PKEY_id(key);

	auxL_pushnid(L, nid);

	return 1;
} /* pk_type() */


static int pk_setPublicKey(lua_State *L) {
	EVP_PKEY **key = luaL_checkudata(L, 1, PKEY_CLASS);
	const char *data;
	size_t len;
	BIO *bio;
	int type, ok = 0;

	data = luaL_checklstring(L, 2, &len);
	type = optencoding(L, 3, "*", X509_ANY|X509_PEM|X509_DER);

	if (!(bio = BIO_new_mem_buf((void *)data, len)))
		return auxL_error(L, auxL_EOPENSSL, "pkey.new");

	if (type == X509_ANY || type == X509_PEM) {
		ok = !!PEM_read_bio_PUBKEY(bio, key, 0, "");
	}

	if (!ok && (type == X509_ANY || type == X509_DER)) {
		ok = !!d2i_PUBKEY_bio(bio, key);
	}

	BIO_free(bio);

	if (!ok)
		return auxL_error(L, auxL_EOPENSSL, "pkey.new");

	lua_pushboolean(L, 1);

	return 1;
} /* pk_setPublicKey() */


static int pk_setPrivateKey(lua_State *L) {
	EVP_PKEY **key = luaL_checkudata(L, 1, PKEY_CLASS);
	const char *data;
	size_t len;
	BIO *bio;
	int type, ok = 0;

	data = luaL_checklstring(L, 2, &len);
	type = optencoding(L, 3, "*", X509_ANY|X509_PEM|X509_DER);

	if (!(bio = BIO_new_mem_buf((void *)data, len)))
		return auxL_error(L, auxL_EOPENSSL, "pkey.new");

	if (type == X509_ANY || type == X509_PEM) {
		ok = !!PEM_read_bio_PrivateKey(bio, key, 0, "");
	}

	if (!ok && (type == X509_ANY || type == X509_DER)) {
		ok = !!d2i_PrivateKey_bio(bio, key);
	}

	BIO_free(bio);

	if (!ok)
		return auxL_error(L, auxL_EOPENSSL, "pkey.new");

	lua_pushboolean(L, 1);

	return 1;
} /* pk_setPrivateKey() */

#if HAVE_EVP_PKEY_CTX_NEW
static int pk_decrypt(lua_State *L) {
	size_t outlen, inlen;
	EVP_PKEY *key = checksimple(L, 1, PKEY_CLASS);
	EVP_PKEY_CTX *ctx;
	const char *str = luaL_checklstring(L, 2, &inlen);
	BIO *bio;
	BUF_MEM *buf;
	int rsaPadding = RSA_PKCS1_PADDING; /* default for `openssl rsautl` */
	int base_type = EVP_PKEY_base_id(key);

	if (lua_istable(L, 3)) {
		if (base_type == EVP_PKEY_RSA) {
			lua_getfield(L, 3, "rsaPadding");
			rsaPadding = luaL_optinteger(L, -1, rsaPadding);
			lua_pop(L, 1);
		}
	}

	bio = getbio(L);
	BIO_get_mem_ptr(bio, &buf);

	if (!(ctx = EVP_PKEY_CTX_new(key, NULL)))
		goto sslerr;

	if (EVP_PKEY_decrypt_init(ctx) <= 0)
		goto sslerr;

	if (base_type == EVP_PKEY_RSA && !EVP_PKEY_CTX_set_rsa_padding(ctx, rsaPadding))
		goto sslerr;

	if (EVP_PKEY_decrypt(ctx, NULL, &outlen, (const unsigned char *)str, inlen) <= 0)
		goto sslerr;

	if (!BUF_MEM_grow_clean(buf, outlen))
		goto sslerr;

	if (EVP_PKEY_decrypt(ctx, (unsigned char *)buf->data, &outlen, (const unsigned char *)str, inlen) <= 0)
		goto sslerr;

	EVP_PKEY_CTX_free(ctx);
	ctx = NULL;

	lua_pushlstring(L, buf->data, outlen);

	BIO_reset(bio);

	return 1;
sslerr:
	if (ctx) {
		EVP_PKEY_CTX_free(ctx);
		ctx = NULL;
	}
	BIO_reset(bio);

	return auxL_error(L, auxL_EOPENSSL, "pkey:decrypt");
} /* pk_decrypt() */
#endif

#if HAVE_EVP_PKEY_CTX_NEW
static int pk_encrypt(lua_State *L) {
	size_t outlen, inlen;
	EVP_PKEY *key = checksimple(L, 1, PKEY_CLASS);
	EVP_PKEY_CTX *ctx;
	const char *str = luaL_checklstring(L, 2, &inlen);
	BIO *bio;
	BUF_MEM *buf;
	int rsaPadding = RSA_PKCS1_PADDING; /* default for `openssl rsautl` */
	int base_type = EVP_PKEY_base_id(key);

	if (lua_istable(L, 3)) {
		if (base_type == EVP_PKEY_RSA) {
			lua_getfield(L, 3, "rsaPadding");
			rsaPadding = luaL_optinteger(L, -1, rsaPadding);
			lua_pop(L, 1);
		}
	}

	bio = getbio(L);
	BIO_get_mem_ptr(bio, &buf);

	if (!(ctx = EVP_PKEY_CTX_new(key, NULL)))
		goto sslerr;

	if (EVP_PKEY_encrypt_init(ctx) <= 0)
		goto sslerr;

	if (base_type == EVP_PKEY_RSA && !EVP_PKEY_CTX_set_rsa_padding(ctx, rsaPadding))
		goto sslerr;

	if (EVP_PKEY_encrypt(ctx, NULL, &outlen, (const unsigned char *)str, inlen) <= 0)
		goto sslerr;

	if (!BUF_MEM_grow_clean(buf, outlen))
		goto sslerr;

	if (EVP_PKEY_encrypt(ctx, (unsigned char *)buf->data, &outlen, (const unsigned char *)str, inlen) <= 0)
		goto sslerr;

	EVP_PKEY_CTX_free(ctx);
	ctx = NULL;

	lua_pushlstring(L, buf->data, outlen);

	BIO_reset(bio);

	return 1;
sslerr:
	if (ctx) {
		EVP_PKEY_CTX_free(ctx);
		ctx = NULL;
	}
	BIO_reset(bio);

	return auxL_error(L, auxL_EOPENSSL, "pkey:encrypt");
} /* pk_encrypt() */
#endif

static int pk_sign(lua_State *L) {
	EVP_PKEY *key = checksimple(L, 1, PKEY_CLASS);
	EVP_MD_CTX *md = checksimple(L, 2, DIGEST_CLASS);
	luaL_Buffer B;
	unsigned n = EVP_PKEY_size(key);

	if (!EVP_SignFinal(md, (void *)luaL_buffinitsize(L, &B, n), &n, key))
		return auxL_error(L, auxL_EOPENSSL, "pkey:sign");

	luaL_pushresultsize(&B, n);

	return 1;
} /* pk_sign() */


static int pk_verify(lua_State *L) {
	EVP_PKEY *key = checksimple(L, 1, PKEY_CLASS);
	size_t len;
	const void *sig = luaL_checklstring(L, 2, &len);
	EVP_MD_CTX *md = checksimple(L, 3, DIGEST_CLASS);

	switch (EVP_VerifyFinal(md, sig, len, key)) {
	case 0: /* WRONG */
		ERR_clear_error();
		lua_pushboolean(L, 0);

		break;
	case 1: /* OK */
		lua_pushboolean(L, 1);

		break;
	default:
		return auxL_error(L, auxL_EOPENSSL, "pkey:verify");
	}

	return 1;
} /* pk_verify() */


static int pk_toPEM(lua_State *L) {
	EVP_PKEY *key = checksimple(L, 1, PKEY_CLASS);
	int top, i, ok;
	BIO *bio;
	char *pem;
	long len;

	if (1 == (top = lua_gettop(L))) {
		lua_pushliteral(L, "publickey");
		++top;
	}

	bio = getbio(L);

	for (i = 2; i <= top; i++) {
		static const char *const opts[] = {
			"public", "PublicKey",
			"private", "PrivateKey",
//			"params", "Parameters",
			NULL,
		};

		switch (auxL_checkoption(L, i, NULL, opts, 1)) {
		case 0: case 1: /* public, PublicKey */
			if (!PEM_write_bio_PUBKEY(bio, key))
				return auxL_error(L, auxL_EOPENSSL, "pkey:__tostring");

			len = BIO_get_mem_data(bio, &pem);
			lua_pushlstring(L, pem, len);
			BIO_reset(bio);

			break;
		case 2: case 3: /* private, PrivateKey */
			if (!PEM_write_bio_PrivateKey(bio, key, 0, 0, 0, 0, 0))
				return auxL_error(L, auxL_EOPENSSL, "pkey:__tostring");

			len = BIO_get_mem_data(bio, &pem);
			lua_pushlstring(L, pem, len);
			BIO_reset(bio);

			break;
#if 0
		case 4: case 5: /* params, Parameters */
			/* EVP_PKEY_base_id not in OS X */
			switch (EVP_PKEY_base_id(key)) {
			case EVP_PKEY_RSA:
				break;
			case EVP_PKEY_DSA: {
				DSA *dsa = EVP_PKEY_get1_DSA(key);

				ok = !!PEM_write_bio_DSAparams(bio, dsa);

				DSA_free(dsa);

				if (!ok)
					return auxL_error(L, auxL_EOPENSSL, "pkey:__tostring");

				break;
			}
			case EVP_PKEY_DH: {
				DH *dh = EVP_PKEY_get1_DH(key);

				ok = !!PEM_write_bio_DHparams(bio, dh);

				DH_free(dh);

				if (!ok)
					return auxL_error(L, auxL_EOPENSSL, "pkey:__tostring");

				break;
			}
#ifndef OPENSSL_NO_EC
			case EVP_PKEY_EC: {
				EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key);
				const EC_GROUP *grp = EC_KEY_get0_group(ec);

				ok = !!PEM_write_bio_ECPKParameters(bio, grp);

				EC_KEY_free(ec);

				if (!ok)
					return auxL_error(L, auxL_EOPENSSL, "pkey:__tostring");

				break;
			}
#endif
			default:
				return luaL_error(L, "%d: unsupported EVP_PKEY base type", EVP_PKEY_base_id(key));
			}

			lua_pushlstring(L, pem, len);

			BIO_reset(bio);

			break;
#endif
		default:
			lua_pushnil(L);

			break;
		} /* switch() */
	} /* for() */

	return lua_gettop(L) - top;
} /* pk_toPEM() */


static int pk_getDefaultDigestName(lua_State *L) {
	EVP_PKEY *key = checksimple(L, 1, PKEY_CLASS);
	int nid;

	if (!(EVP_PKEY_get_default_digest_nid(key, &nid) > 0))
		return auxL_error(L, auxL_EOPENSSL, "pkey:getDefaultDigestName");

	auxL_pushnid(L, nid);

	return 1;
} /* pk_getDefaultDigestName() */


enum pk_param  {
#define PK_RSA_OPTLIST { "n", "e", "d", "p", "q", "dmp1", "dmq1", "iqmp", NULL }
#define PK_RSA_OPTOFFSET PK_RSA_N
	PK_RSA_N = 1,
	PK_RSA_E,
	PK_RSA_D,
	PK_RSA_P,
	PK_RSA_Q,
	PK_RSA_DMP1,
	PK_RSA_DMQ1,
	PK_RSA_IQMP,

#define PK_DSA_OPTLIST { "p", "q", "g", "pub_key", "priv_key", NULL }
#define PK_DSA_OPTOFFSET PK_DSA_P
	PK_DSA_P,
	PK_DSA_Q,
	PK_DSA_G,
	PK_DSA_PUB_KEY,
	PK_DSA_PRIV_KEY,

#define PK_DH_OPTLIST { "p", "g", "pub_key", "priv_key", NULL }
#define PK_DH_OPTOFFSET PK_DH_P
	PK_DH_P,
	PK_DH_G,
	PK_DH_PUB_KEY,
	PK_DH_PRIV_KEY,

/*
 * NB: group MUST come before pub_key as setting pub_key requires the group
 * to be defined. :setParameters will do the requested assignments in the
 * order defined by this array.
 */
#define PK_EC_OPTLIST { "group", "pub_key", "priv_key", NULL }
#define PK_EC_OPTOFFSET PK_EC_GROUP
	PK_EC_GROUP,
	PK_EC_PUB_KEY,
	PK_EC_PRIV_KEY,

#define PK_RAW_OPTLIST { "pub_key", "priv_key", NULL }
#define PK_RAW_OPTOFFSET PK_RAW_PUB_KEY
	PK_RAW_PUB_KEY,
	PK_RAW_PRIV_KEY,
}; /* enum pk_param */

static const char *const pk_rsa_optlist[] = PK_RSA_OPTLIST;
static const char *const pk_dsa_optlist[] = PK_DSA_OPTLIST;
static const char *const pk_dh_optlist[] = PK_DH_OPTLIST;
static const char *const pk_ec_optlist[] = PK_EC_OPTLIST;
static const char *const pk_raw_optlist[] = PK_RAW_OPTLIST;

const char *const *pk_getoptlist(int type, int *_nopts, int *_optoffset) {
	const char *const *optlist = NULL;
	int nopts = 0, optoffset = 0;

	switch (type) {
	case EVP_PKEY_RSA:
		optlist = pk_rsa_optlist;
		nopts = countof(pk_rsa_optlist) - 1;
		optoffset = PK_RSA_OPTOFFSET;

		break;
	case EVP_PKEY_DSA:
		optlist = pk_dsa_optlist;
		nopts = countof(pk_dsa_optlist) - 1;
		optoffset = PK_DSA_OPTOFFSET;

		break;
	case EVP_PKEY_DH:
		optlist = pk_dh_optlist;
		nopts = countof(pk_dh_optlist) - 1;
		optoffset = PK_DH_OPTOFFSET;

		break;
	case EVP_PKEY_EC:
		optlist = pk_ec_optlist;
		nopts = countof(pk_ec_optlist) - 1;
		optoffset = PK_EC_OPTOFFSET;

		break;
#if HAVE_EVP_PKEY_RAW
	case EVP_PKEY_X25519:
	case EVP_PKEY_X448:
	case EVP_PKEY_ED25519:
	case EVP_PKEY_ED448:
		optlist = pk_raw_optlist;
		nopts = countof(pk_raw_optlist) - 1;
		optoffset = PK_RAW_OPTOFFSET;

		break;
#endif
	}

	if (_nopts)
		*_nopts = nopts;
	if (_optoffset)
		*_optoffset = optoffset;

	return optlist;
} /* pk_getoptlist() */

#ifndef OPENSSL_NO_EC
static EC_GROUP *ecg_dup_nil(lua_State *, const EC_GROUP *);
#endif

static void pk_pushparam(lua_State *L, EVP_PKEY *pkey, enum pk_param which) {
	const BIGNUM *i;
	luaL_Buffer B;
	size_t len;

	switch (which) {
	case PK_RSA_N:
		/* RSA public modulus n */
		RSA_get0_key(EVP_PKEY_get0_RSA(pkey), &i, NULL, NULL);
		bn_dup_nil(L, i);

		break;
	case PK_RSA_E:
		/* RSA public exponent e */
		RSA_get0_key(EVP_PKEY_get0_RSA(pkey), NULL, &i, NULL);
		bn_dup_nil(L, i);

		break;
	case PK_RSA_D:
		/* RSA secret exponent d */
		RSA_get0_key(EVP_PKEY_get0_RSA(pkey), NULL, NULL, &i);
		bn_dup_nil(L, i);

		break;
	case PK_RSA_P:
		/* RSA secret prime p */
		RSA_get0_factors(EVP_PKEY_get0_RSA(pkey), &i, NULL);
		bn_dup_nil(L, i);

		break;
	case PK_RSA_Q:
		/* RSA secret prime q with p < q */
		RSA_get0_factors(EVP_PKEY_get0_RSA(pkey), NULL, &i);
		bn_dup_nil(L, i);

		break;
	case PK_RSA_DMP1:
		/* exponent1 */
		RSA_get0_crt_params(EVP_PKEY_get0_RSA(pkey), &i, NULL, NULL);
		bn_dup_nil(L, i);

		break;
	case PK_RSA_DMQ1:
		/* exponent2 */
		RSA_get0_crt_params(EVP_PKEY_get0_RSA(pkey), NULL, &i, NULL);
		bn_dup_nil(L, i);

		break;
	case PK_RSA_IQMP:
		/* coefficient */
		RSA_get0_crt_params(EVP_PKEY_get0_RSA(pkey), NULL, NULL, &i);
		bn_dup_nil(L, i);

		break;
	case PK_DSA_P:
		DSA_get0_pqg(EVP_PKEY_get0_DSA(pkey), &i, NULL, NULL);
		bn_dup_nil(L, i);

		break;
	case PK_DSA_Q:
		DSA_get0_pqg(EVP_PKEY_get0_DSA(pkey), NULL, &i, NULL);
		bn_dup_nil(L, i);

		break;
	case PK_DSA_G:
		DSA_get0_pqg(EVP_PKEY_get0_DSA(pkey), NULL, NULL, &i);
		bn_dup_nil(L, i);

		break;
	case PK_DSA_PUB_KEY:
		DSA_get0_key(EVP_PKEY_get0_DSA(pkey), &i, NULL);
		bn_dup_nil(L, i);

		break;
	case PK_DSA_PRIV_KEY:
		DSA_get0_key(EVP_PKEY_get0_DSA(pkey), NULL, &i);
		bn_dup_nil(L, i);

		break;
	case PK_DH_P:
		DH_get0_pqg(EVP_PKEY_get0_DH(pkey), &i, NULL, NULL);
		bn_dup_nil(L, i);

		break;
	case PK_DH_G:
		DH_get0_pqg(EVP_PKEY_get0_DH(pkey), NULL, NULL, &i);
		bn_dup_nil(L, i);

		break;
	case PK_DH_PUB_KEY:
		DH_get0_key(EVP_PKEY_get0_DH(pkey), &i, NULL);
		bn_dup_nil(L, i);

		break;
	case PK_DH_PRIV_KEY:
		DH_get0_key(EVP_PKEY_get0_DH(pkey), NULL, &i);
		bn_dup_nil(L, i);

		break;
#ifndef OPENSSL_NO_EC
	case PK_EC_GROUP:
		ecg_dup_nil(L, EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey)));

		break;
	case PK_EC_PUB_KEY: {
		const EC_GROUP *group;
		const EC_POINT *pub_key;

		if ((group = EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey))) && (pub_key = EC_KEY_get0_public_key(EVP_PKEY_get0_EC_KEY(pkey)))) {
			bn_dup_nil(L, EC_POINT_point2bn(group, pub_key, EC_KEY_get_conv_form(EVP_PKEY_get0_EC_KEY(pkey)), NULL, getctx(L)));
		} else {
			lua_pushnil(L);
		}

		break;
	}
	case PK_EC_PRIV_KEY:
		bn_dup_nil(L, EC_KEY_get0_private_key(EVP_PKEY_get0_EC_KEY(pkey)));

		break;
#endif
#if HAVE_EVP_PKEY_RAW
	case PK_RAW_PUB_KEY:
		EVP_PKEY_get_raw_public_key(pkey, NULL, &len);
		EVP_PKEY_get_raw_public_key(pkey, (unsigned char*)luaL_buffinitsize(L, &B, len), &len);
		luaL_pushresultsize(&B, len);

		break;
	case PK_RAW_PRIV_KEY:
		EVP_PKEY_get_raw_private_key(pkey, NULL, &len);
		EVP_PKEY_get_raw_private_key(pkey, (unsigned char*)luaL_buffinitsize(L, &B, len), &len);
		luaL_pushresultsize(&B, len);

		break;
#endif
	default:
		luaL_error(L, "%d: invalid EVP_PKEY parameter", which);
	}

	return;
} /* pk_pushparam() */


#define pk_setparam_bn_dup(L, index, dst) do { \
	BIGNUM *tmp = checkbig((L), (index)); \
	if (!(*dst = BN_dup(tmp))) \
		goto sslerr; \
} while (0)

static void pk_setparam(lua_State *L, EVP_PKEY *pkey, enum pk_param which, int index) {
	BIGNUM *i;

	switch (which) {
	case PK_RSA_N:
		pk_setparam_bn_dup(L, index, &i);
		RSA_set0_key(EVP_PKEY_get0_RSA(pkey), i, NULL, NULL);

		break;
	case PK_RSA_E:
		pk_setparam_bn_dup(L, index, &i);
		RSA_set0_key(EVP_PKEY_get0_RSA(pkey), NULL, i, NULL);

		break;
	case PK_RSA_D:
		pk_setparam_bn_dup(L, index, &i);
		RSA_set0_key(EVP_PKEY_get0_RSA(pkey), NULL, NULL, i);

		break;
	case PK_RSA_P:
		pk_setparam_bn_dup(L, index, &i);
		RSA_set0_factors(EVP_PKEY_get0_RSA(pkey), i, NULL);

		break;
	case PK_RSA_Q:
		pk_setparam_bn_dup(L, index, &i);
		RSA_set0_factors(EVP_PKEY_get0_RSA(pkey), NULL, i);

		break;
	case PK_RSA_DMP1:
		pk_setparam_bn_dup(L, index, &i);
		RSA_set0_crt_params(EVP_PKEY_get0_RSA(pkey), i, NULL, NULL);

		break;
	case PK_RSA_DMQ1:
		pk_setparam_bn_dup(L, index, &i);
		RSA_set0_crt_params(EVP_PKEY_get0_RSA(pkey), NULL, i, NULL);

		break;
	case PK_RSA_IQMP:
		pk_setparam_bn_dup(L, index, &i);
		RSA_set0_crt_params(EVP_PKEY_get0_RSA(pkey), NULL, NULL, i);

		break;
	case PK_DSA_P:
		pk_setparam_bn_dup(L, index, &i);
		DSA_set0_pqg(EVP_PKEY_get0_DSA(pkey), i, NULL, NULL);

		break;
	case PK_DSA_Q:
		pk_setparam_bn_dup(L, index, &i);
		DSA_set0_pqg(EVP_PKEY_get0_DSA(pkey), NULL, i, NULL);

		break;
	case PK_DSA_G:
		pk_setparam_bn_dup(L, index, &i);
		DSA_set0_pqg(EVP_PKEY_get0_DSA(pkey), NULL, NULL, i);

		break;
	case PK_DSA_PUB_KEY:
		pk_setparam_bn_dup(L, index, &i);
		DSA_set0_key(EVP_PKEY_get0_DSA(pkey), i, NULL);

		break;
	case PK_DSA_PRIV_KEY:
		pk_setparam_bn_dup(L, index, &i);
		DSA_set0_key(EVP_PKEY_get0_DSA(pkey), NULL, i);

		break;
	case PK_DH_P:
		pk_setparam_bn_dup(L, index, &i);
		DH_set0_pqg(EVP_PKEY_get0_DH(pkey), i, NULL, NULL);

		break;
	case PK_DH_G:
		pk_setparam_bn_dup(L, index, &i);
		DH_set0_pqg(EVP_PKEY_get0_DH(pkey), NULL, NULL, i);

		break;
	case PK_DH_PUB_KEY:
		pk_setparam_bn_dup(L, index, &i);
		DH_set0_key(EVP_PKEY_get0_DH(pkey), i, NULL);

		break;
	case PK_DH_PRIV_KEY:
		pk_setparam_bn_dup(L, index, &i);
		DH_set0_key(EVP_PKEY_get0_DH(pkey), NULL, i);

		break;
#ifndef OPENSSL_NO_EC
	case PK_EC_GROUP: {
		const EC_GROUP *group = checksimple(L, index, EC_GROUP_CLASS);

		if (!EC_KEY_set_group(EVP_PKEY_get0_EC_KEY(pkey), group))
			goto sslerr;

		break;
	}
	case PK_EC_PUB_KEY: {
		const BIGNUM *n = checkbig(L, index);
		const EC_GROUP *group;
		EC_POINT *pub_key;
		_Bool okay;

		if (!(group = EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey))))
			luaL_error(L, "unable to set EC pub_key (no group defined)");

		if (!(pub_key = EC_POINT_bn2point(group, n, NULL, getctx(L))))
			goto sslerr;

		/* NB: copies key, doesn't share or take ownership */
		okay = EC_KEY_set_public_key(EVP_PKEY_get0_EC_KEY(pkey), pub_key);
		EC_POINT_free(pub_key);
		if (!okay)
			goto sslerr;

		break;
	}
	case PK_EC_PRIV_KEY: {
		const BIGNUM *n = checkbig(L, index);

		/* NB: copies key, doesn't share or take ownership */
		if (!EC_KEY_set_private_key(EVP_PKEY_get0_EC_KEY(pkey), n))
			goto sslerr;

		break;
	}
#endif
#if HAVE_EVP_PKEY_RAW
	case PK_RAW_PUB_KEY:
	case PK_RAW_PRIV_KEY:
		luaL_error(L, "%d: EVP_PKEY parameter is immutable", which);

		break;
#endif
	default:
		luaL_error(L, "%d: invalid EVP_PKEY parameter", which);
	}

	return;
sslerr:
	auxL_error(L, auxL_EOPENSSL, "pkey:setParameters");

	return;
} /* pk_setparam() */


static int pk_getParameters(lua_State *L) {
	EVP_PKEY *key = checksimple(L, 1, PKEY_CLASS);
	int base_type = EVP_PKEY_base_id(key);
	const char *const *optlist;
	int nopts, optoffset, otop, index, tindex;

	if (!(optlist = pk_getoptlist(base_type, &nopts, &optoffset)))
		return luaL_error(L, "%d: unsupported EVP_PKEY base type", base_type);

	if (lua_isnoneornil(L, 2)) {
		const char *const *optname;

		/*
		 * Use special "{" parameter to tell loop to push table.
		 * Subsequent parameters will be assigned as fields.
		 */
		lua_pushliteral(L, "{");
		luaL_checkstack(L, nopts, "too many arguments");
		for (optname = optlist; *optname; optname++) {
			lua_pushstring(L, *optname);
		}
	}

	otop = lua_gettop(L);

	/* provide space for results and working area */
	luaL_checkstack(L, (otop - 1) + LUA_MINSTACK, "too many arguments");

	/* no table index, yet */
	tindex = 0;

	for (index = 2; index <= otop; index++) {
		const char *optname = luaL_checkstring(L, index);
		int optid;

		if (*optname == '{') {
			lua_newtable(L);
			tindex = lua_gettop(L);
		} else {
			optid = luaL_checkoption(L, index, NULL, optlist) + optoffset;
			pk_pushparam(L, key, optid);

			if (tindex) {
				lua_setfield(L, tindex, optname);
			}
		}
	}

	return lua_gettop(L) - otop;
} /* pk_getParameters() */


static int pk_setParameters(lua_State *L) {
	EVP_PKEY *key = checksimple(L, 1, PKEY_CLASS);
	int base_type = EVP_PKEY_base_id(key);
	const char *const *optlist;
	int optindex, optoffset;

	luaL_checktype(L, 2, LUA_TTABLE);

	if (!(optlist = pk_getoptlist(base_type, NULL, &optoffset)))
		return luaL_error(L, "%d: unsupported EVP_PKEY base type", base_type);

	for (optindex = 0; optlist[optindex]; optindex++) {
		if (getfield(L, 2, optlist[optindex])) {
			pk_setparam(L, key, optindex + optoffset, -1);
			lua_pop(L, 1);
		}
	}

	return 0;
} /* pk_setParameters() */


static int pk__tostring(lua_State *L) {
	EVP_PKEY *key = checksimple(L, 1, PKEY_CLASS);
	int type = optencoding(L, 2, "pem", X509_PEM|X509_DER);
	BIO *bio = getbio(L);
	char *data;
	long len;

	switch (type) {
	case X509_PEM:
		if (!PEM_write_bio_PUBKEY(bio, key))
			return auxL_error(L, auxL_EOPENSSL, "pkey:__tostring");
		break;
	case X509_DER:
		if (!i2d_PUBKEY_bio(bio, key))
			return auxL_error(L, auxL_EOPENSSL, "pkey:__tostring");
		break;
	} /* switch() */

	len = BIO_get_mem_data(bio, &data);

	lua_pushlstring(L, data, len);

	return 1;
} /* pk__tostring() */


static int pk__index(lua_State *L) {
	EVP_PKEY *key = checksimple(L, 1, PKEY_CLASS);
	const char *const *optlist;
	int optoffset, listoffset;

	lua_pushvalue(L, lua_upvalueindex(1));
	lua_pushvalue(L, 2);
	lua_gettable(L, -2);

	if (!lua_isnil(L, -1))
		return 1;

	if (!lua_isstring(L, 2))
		return 0;
	if (!(optlist = pk_getoptlist(EVP_PKEY_base_id(key), NULL, &optoffset)))
		return 0;
	if (-1 == (listoffset = auxL_testoption(L, 2, NULL, optlist, 0)))
		return 0;

	pk_pushparam(L, key, listoffset + optoffset);

	return 1;
} /* pk__index() */


static int pk__newindex(lua_State *L) {
	EVP_PKEY *key = checksimple(L, 1, PKEY_CLASS);
	const char *const *optlist;
	int optoffset, listoffset;

	if (!lua_isstring(L, 2))
		return 0;
	if (!(optlist = pk_getoptlist(EVP_PKEY_base_id(key), NULL, &optoffset)))
		return 0;
	if (-1 == (listoffset = auxL_testoption(L, 2, NULL, optlist, 0)))
		return 0;

	pk_setparam(L, key, listoffset + optoffset, 3);

	return 0;
} /* pk__newindex() */


static int pk__gc(lua_State *L) {
	EVP_PKEY **ud = luaL_checkudata(L, 1, PKEY_CLASS);

	if (*ud) {
		EVP_PKEY_free(*ud);
		*ud = NULL;
	}

	return 0;
} /* pk__gc() */


static const auxL_Reg pk_methods[] = {
	{ "type",          &pk_type },
	{ "setPublicKey",  &pk_setPublicKey },
	{ "setPrivateKey", &pk_setPrivateKey },
	{ "getDefaultDigestName", &pk_getDefaultDigestName },
	{ "getParameters", &pk_getParameters },
	{ "setParameters", &pk_setParameters },
#if HAVE_EVP_PKEY_CTX_NEW
	{ "decrypt",       &pk_decrypt },
	{ "encrypt",       &pk_encrypt },
#endif
	{ "sign",          &pk_sign },
	{ "toPEM",         &pk_toPEM },
	{ "tostring",      &pk__tostring },
	{ "verify",        &pk_verify },
	{ NULL,            NULL },
};

static const auxL_Reg pk_metatable[] = {
	{ "__tostring", &pk__tostring },
	{ "__index",    &pk__index, 1 },
	{ "__newindex", &pk__newindex, 1 },
	{ "__gc",       &pk__gc },
	{ NULL,         NULL },
};


static const auxL_Reg pk_globals[] = {
	{ "new",       &pk_new },
	{ "interpose", &pk_interpose },
	{ NULL,        NULL },
};

static void pk_luainit(lua_State *L, _Bool reset) {
	char **k;
	if (!auxL_newmetatable(L, PKEY_CLASS, reset))
		return;
	auxL_setfuncs(L, pk_metatable, 0);
	auxL_newlib(L, pk_methods, 0);
	for (k = (char *[]){ "__index", "__newindex", 0 }; *k; k++) {
		lua_getfield(L, -2, *k); /* closure */
		lua_pushvalue(L, -2);   /* method table */
		lua_setupvalue(L, -2, 1);
	}
	lua_pop(L, 2);
} /* pk_luainit() */

static const auxL_IntegerReg pk_rsa_pad_opts[] = {
	{ "RSA_PKCS1_PADDING", RSA_PKCS1_PADDING }, // PKCS#1 padding
#if RSA_SSLV23_PADDING
	{ "RSA_SSLV23_PADDING", RSA_SSLV23_PADDING }, // SSLv23 padding
#endif
	{ "RSA_NO_PADDING", RSA_NO_PADDING }, // no padding
	{ "RSA_PKCS1_OAEP_PADDING", RSA_PKCS1_OAEP_PADDING }, // OAEP padding (encrypt and decrypt only)
	{ "RSA_X931_PADDING", RSA_X931_PADDING }, // (signature operations only)
#if RSA_PKCS1_PSS_PADDING
	{ "RSA_PKCS1_PSS_PADDING", RSA_PKCS1_PSS_PADDING }, // (sign and verify only)
#endif
	{ NULL, 0 },
};

EXPORT int luaopen__openssl_pkey(lua_State *L) {
	initall(L);

	auxL_newlib(L, pk_globals, 0);
	auxL_setintegers(L, pk_rsa_pad_opts);

	return 1;
} /* luaopen__openssl_pkey() */


/*
 * Deprecated module name.
 */
EXPORT int luaopen__openssl_pubkey(lua_State *L) {
	return luaopen__openssl_pkey(L);
} /* luaopen__openssl_pubkey() */


/*
 * EC_GROUP - openssl.ec.group
 *
 * NOTE: Ensure copy-by-value semantics when passing EC_GROUP objects as it
 * doesn't support reference counting. The only persistent reference should
 * be the Lua userdata value.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef OPENSSL_NO_EC

static EC_GROUP *ecg_dup(lua_State *L, const EC_GROUP *src) {
	EC_GROUP **ud = prepsimple(L, EC_GROUP_CLASS);

	if (!(*ud = EC_GROUP_dup(src)))
		auxL_error(L, auxL_EOPENSSL, "group");

	return *ud;
} /* ecg_dup() */

static EC_GROUP *ecg_dup_nil(lua_State *L, const EC_GROUP *src) {
	return (src)? ecg_dup(L, src) : (lua_pushnil(L), (EC_GROUP *)0);
} /* ecg_dup_nil() */

static EC_GROUP *ecg_push_by_nid(lua_State *L, int nid) {
	EC_GROUP **group = prepsimple(L, EC_GROUP_CLASS);

	if (!(*group = EC_GROUP_new_by_curve_name(nid)))
		goto oops;

	EC_GROUP_set_asn1_flag(*group, OPENSSL_EC_NAMED_CURVE);

	/* compressed points may be patented */
	EC_GROUP_set_point_conversion_form(*group, POINT_CONVERSION_UNCOMPRESSED);

	return *group;
oops:
	lua_pop(L, 1);

	return NULL;
} /* ecg_push_by_nid() */

static int ecg_new(lua_State *L) {
	switch (lua_type(L, 1)) {
	case LUA_TSTRING: {
		const char *data;
		size_t datalen;
		int nid, type, goterr;
		BIO *bio;
		EC_GROUP **group;

		data = luaL_checklstring(L, 1, &datalen);

		if (auxS_txt2nid(&nid, data)) {
			if (!ecg_push_by_nid(L, nid))
				goto sslerr;
		} else {
			type = optencoding(L, 2, "*", X509_ANY|X509_PEM|X509_DER);
			group = prepsimple(L, EC_GROUP_CLASS);

			luaL_argcheck(L, datalen < INT_MAX, 1, "string too long");
			if (!(bio = BIO_new_mem_buf((void *)data, datalen)))
				return auxL_error(L, auxL_EOPENSSL, "group.new");

			goterr = 0;

			if (type == X509_PEM || type == X509_ANY) {
				goterr |= !(*group = PEM_read_bio_ECPKParameters(bio, NULL, 0, ""));
			}

			if (!*group && (type == X509_DER || type == X509_ANY)) {
				BIO_reset(bio);
				goterr |= !(*group = d2i_ECPKParameters_bio(bio, NULL));
			}

			BIO_free(bio);

			if (!*group)
				return auxL_error(L, auxL_EOPENSSL, "group.new");
			if (goterr)
				ERR_clear_error();
		}

		return 1;
	}
	case LUA_TNUMBER: {
		int nid = luaL_checkinteger(L, 2);

		if (!ecg_push_by_nid(L, nid))
			goto sslerr;

		return 1;
	}
	default:
		return luaL_error(L, "%s: unknown group initializer", lua_typename(L, lua_type(L, 1)));
	} /* switch() */

	return 0;
sslerr:
	return auxL_error(L, auxL_EOPENSSL, "group.new");
} /* ecg_new() */

static int ecg_interpose(lua_State *L) {
	return interpose(L, EC_GROUP_CLASS);
} /* ecg_interpose() */


static int ecg_toPEM(lua_State *L) {
	EC_GROUP *group = checksimple(L, 1, EC_GROUP_CLASS);
	BIO *bio = getbio(L);
	size_t len;
	char *bytes;

	if (!PEM_write_bio_ECPKParameters(bio, group))
		return auxL_error(L, auxL_EOPENSSL, "group:toPEM");

	len = BIO_get_mem_data(bio, &bytes);
	lua_pushlstring(L, bytes, len);

	return 1;
} /* ecg_toPEM() */


static int ecg_tostring(lua_State *L) {
	EC_GROUP *group = checksimple(L, 1, EC_GROUP_CLASS);
	int how = optencoding(L, 2, "pem", X509_PEM|X509_DER|X509_TXT);
	BIO *bio = getbio(L);
	char *bytes;
	int len, indent;

	switch (how) {
	case X509_PEM:
		if (!PEM_write_bio_ECPKParameters(bio, group))
			goto sslerr;
		break;
	case X509_DER:
		if (!i2d_ECPKParameters_bio(bio, group))
			goto sslerr;
		break;
	case X509_TXT:
		indent = auxL_optinteger(L, 3, 0, 0, INT_MAX);
		if (!ECPKParameters_print(bio, group, indent))
			goto sslerr;
		break;
	}

	len = BIO_get_mem_data(bio, &bytes);
	lua_pushlstring(L, bytes, len);

	return 1;
sslerr:
	return auxL_error(L, auxL_EOPENSSL, "group:__tostring");
} /* ecg_tostring() */

static int ecg__tostring(lua_State *L) {
	return ecg_tostring(L);
} /* ecg__tostring() */

static int ecg__gc(lua_State *L) {
	EC_GROUP **ud = luaL_checkudata(L, 1, EC_GROUP_CLASS);

	if (*ud) {
		EC_GROUP_clear_free(*ud);
		*ud = NULL;
	}

	return 0;
} /* ecg__gc() */

static const auxL_Reg ecg_methods[] = {
	{ "toPEM",    &ecg_toPEM },
	{ "tostring", &ecg_tostring },
	{ NULL,       NULL },
};

static const auxL_Reg ecg_metatable[] = {
	{ "__tostring", &ecg__tostring },
	{ "__gc",       &ecg__gc },
	{ NULL,         NULL },
};

static const auxL_Reg ecg_globals[] = {
	{ "new",       &ecg_new },
	{ "interpose", &ecg_interpose },
	{ NULL,        NULL },
};

#endif /* OPENSSL_NO_EC */

EXPORT int luaopen__openssl_ec_group(lua_State *L) {
#ifndef OPENSSL_NO_EC
	initall(L);

	auxL_newlib(L, ecg_globals, 0);

	return 1;
#else
	return 0;
#endif
} /* luaopen__openssl_ec_group() */


/*
 * X509_NAME - openssl.x509.name
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static X509_NAME *xn_dup(lua_State *L, X509_NAME *name) {
	X509_NAME **ud = prepsimple(L, X509_NAME_CLASS);

	if (!(*ud = X509_NAME_dup(name)))
		auxL_error(L, auxL_EOPENSSL, "x509.name.dup");

	return *ud;
} /* xn_dup() */


static int xn_new(lua_State *L) {
	X509_NAME **ud = prepsimple(L, X509_NAME_CLASS);

	if (!(*ud = X509_NAME_new()))
		return auxL_error(L, auxL_EOPENSSL, "x509.name.new");

	return 1;
} /* xn_new() */


static int xn_interpose(lua_State *L) {
	return interpose(L, X509_NAME_CLASS);
} /* xn_interpose() */


static int xn_add(lua_State *L) {
	X509_NAME *name = checksimple(L, 1, X509_NAME_CLASS);
	const char *nid = luaL_checkstring(L, 2);
	size_t len;
	const char *txt = luaL_checklstring(L, 3, &len);
	ASN1_OBJECT *obj;
	int ok;

	if (!(obj = OBJ_txt2obj(nid, 0)))
		return luaL_error(L, "x509.name:add: %s: invalid NID", nid);

	ok = !!X509_NAME_add_entry_by_OBJ(name, obj, MBSTRING_ASC, (unsigned char *)txt, len, -1, 0);

	ASN1_OBJECT_free(obj);

	if (!ok)
		return auxL_error(L, auxL_EOPENSSL, "x509.name:add");

	lua_pushvalue(L, 1);

	return 1;
} /* xn_add() */


static int xn_all(lua_State *L) {
	X509_NAME *name = checksimple(L, 1, X509_NAME_CLASS);
	int count = X509_NAME_entry_count(name);
	X509_NAME_ENTRY *entry;
	ASN1_OBJECT *obj;
	const char *id;
	char txt[256];
	int i, nid, len;

	lua_newtable(L);

	for (i = 0; i < count; i++) {
		if (!(entry = X509_NAME_get_entry(name, i)))
			continue;

		lua_newtable(L);

		obj = X509_NAME_ENTRY_get_object(entry);
		nid = OBJ_obj2nid(obj);

		if (0 > (len = OBJ_obj2txt(txt, sizeof txt, obj, 1)))
			return auxL_error(L, auxL_EOPENSSL, "x509.name:all");

		lua_pushlstring(L, txt, len);

		if (nid != NID_undef && ((id = OBJ_nid2ln(nid)) || (id = OBJ_nid2sn(nid))))
			lua_pushstring(L, id);
		else
			lua_pushvalue(L, -1);

		if (nid != NID_undef && (id = OBJ_nid2sn(nid)))
			lua_pushstring(L, id);
		else
			lua_pushvalue(L, -1);

		lua_setfield(L, -4, "sn");
		lua_setfield(L, -3, "ln");
		lua_setfield(L, -2, "id");

		len = ASN1_STRING_length(X509_NAME_ENTRY_get_data(entry));
		lua_pushlstring(L, (char *)ASN1_STRING_get0_data(X509_NAME_ENTRY_get_data(entry)), len);

		lua_setfield(L, -2, "blob");

		lua_rawseti(L, -2, i + 1);
	}

	return 1;
} /* xn_all() */


static int xn__next(lua_State *L) {
	X509_NAME *name = checksimple(L, lua_upvalueindex(1), X509_NAME_CLASS);
	X509_NAME_ENTRY *entry;
	ASN1_OBJECT *obj;
	char txt[256];
	int i, n, len;

	lua_settop(L, 0);

	i = lua_tointeger(L, lua_upvalueindex(2));
	n = X509_NAME_entry_count(name);

	while (i < n) {
		if (!(entry = X509_NAME_get_entry(name, i++)))
			continue;

		obj = X509_NAME_ENTRY_get_object(entry);

		if (!(len = auxS_obj2txt(txt, sizeof txt, obj)))
			return auxL_error(L, auxL_EOPENSSL, "x509.name:__pairs");
		lua_pushlstring(L, txt, len);

		len = ASN1_STRING_length(X509_NAME_ENTRY_get_data(entry));
		lua_pushlstring(L, (char *)ASN1_STRING_get0_data(X509_NAME_ENTRY_get_data(entry)), len);

		break;
	}

	lua_pushinteger(L, i);
	lua_replace(L, lua_upvalueindex(2));

	return lua_gettop(L);
} /* xn__next() */

static int xn__pairs(lua_State *L) {
	lua_settop(L, 1);
	lua_pushinteger(L, 0);

	lua_pushcclosure(L, &xn__next, 2);

	return 1;
} /* xn__pairs() */


static int xn__gc(lua_State *L) {
	X509_NAME **ud = luaL_checkudata(L, 1, X509_NAME_CLASS);

	if (*ud) {
		X509_NAME_free(*ud);
		*ud = NULL;
	}

	return 0;
} /* xn__gc() */


static int xn__tostring(lua_State *L) {
	X509_NAME *name = checksimple(L, 1, X509_NAME_CLASS);
	char txt[1024] = { 0 };

	/* FIXME: oneline is deprecated */
	X509_NAME_oneline(name, txt, sizeof txt);

	lua_pushstring(L, txt);

	return 1;
} /* xn__tostring() */


static const auxL_Reg xn_methods[] = {
	{ "add", &xn_add },
	{ "all", &xn_all },
	{ "each", &xn__pairs },
	{ NULL,  NULL },
};

static const auxL_Reg xn_metatable[] = {
	{ "__pairs",    &xn__pairs },
	{ "__gc",       &xn__gc },
	{ "__tostring", &xn__tostring },
	{ NULL,         NULL },
};


static const auxL_Reg xn_globals[] = {
	{ "new",       &xn_new },
	{ "interpose", &xn_interpose },
	{ NULL,        NULL },
};

EXPORT int luaopen__openssl_x509_name(lua_State *L) {
	initall(L);

	auxL_newlib(L, xn_globals, 0);

	return 1;
} /* luaopen__openssl_x509_name() */


/*
 * GENERAL_NAMES - openssl.x509.altname
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static GENERAL_NAMES *gn_dup(lua_State *L, GENERAL_NAMES *gens) {
	GENERAL_NAMES **ud = prepsimple(L, X509_GENS_CLASS);

	if (!(*ud = sk_GENERAL_NAME_dup(gens)))
		auxL_error(L, auxL_EOPENSSL, "x509.altname.dup");

	return *ud;
} /* gn_dup() */


static int gn_new(lua_State *L) {
	GENERAL_NAMES **ud = prepsimple(L, X509_GENS_CLASS);

	if (!(*ud = sk_GENERAL_NAME_new_null()))
		return auxL_error(L, auxL_EOPENSSL, "x509.altname.new");

	return 1;
} /* gn_new() */


static int gn_interpose(lua_State *L) {
	return interpose(L, X509_GENS_CLASS);
} /* gn_interpose() */


static int gn_checktype(lua_State *L, int index) {
	static const struct { int type; const char *name; } table[] = {
		{ GEN_EMAIL,   "RFC822Name" },
		{ GEN_EMAIL,   "RFC822" },
		{ GEN_EMAIL,   "email" },
		{ GEN_URI,     "UniformResourceIdentifier" },
		{ GEN_URI,     "URI" },
		{ GEN_DNS,     "DNSName" },
		{ GEN_DNS,     "DNS" },
		{ GEN_IPADD,   "IPAddress" },
		{ GEN_IPADD,   "IP" },
		{ GEN_DIRNAME, "DirName" },
	};
	const char *type = luaL_checkstring(L, index);
	unsigned i;

	for (i = 0; i < countof(table); i++) {
		if (strieq(table[i].name, type))
			return table[i].type;
	}

	return luaL_error(L, "%s: invalid type", type), 0;
} /* gn_checktype() */


static int gn_add(lua_State *L) {
	GENERAL_NAMES *gens = checksimple(L, 1, X509_GENS_CLASS);
	int type = gn_checktype(L, 2);
	X509_NAME *name;
	size_t len;
	const char *txt;
	GENERAL_NAME *gen = NULL;
	union { struct in6_addr in6; struct in_addr in; } ip;

	switch (type) {
	case GEN_DIRNAME:
		name = checksimple(L, 3, X509_NAME_CLASS);

		if (!(gen = GENERAL_NAME_new()))
			goto error;

		gen->type = type;

		if (!(gen->d.dirn = X509_NAME_dup(name)))
			goto error;

		break;
	case GEN_IPADD:
		txt = luaL_checkstring(L, 3);

		if (strchr(txt, ':')) {
			if (1 != inet_pton(AF_INET6, txt, &ip.in6))
				return luaL_error(L, "%s: invalid address", txt);

			txt = (char *)ip.in6.s6_addr;
			len = 16;
		} else {
			if (1 != inet_pton(AF_INET, txt, &ip.in))
				return luaL_error(L, "%s: invalid address", txt);

			txt = (char *)&ip.in.s_addr;
			len = 4;
		}

		goto text;
	default:
		txt = luaL_checklstring(L, 3, &len);
text:
		if (!(gen = GENERAL_NAME_new()))
			goto error;

		gen->type = type;

		if (!(gen->d.ia5 = ASN1_STRING_type_new(V_ASN1_IA5STRING)))
			goto error;

		if (!ASN1_STRING_set(gen->d.ia5, (unsigned char *)txt, len))
			goto error;
		break;
	} /* switch() */

	sk_GENERAL_NAME_push(gens, gen);

	lua_pushvalue(L, 1);

	return 1;
error:
	GENERAL_NAME_free(gen);

	return auxL_error(L, auxL_EOPENSSL, "x509.altname:add");
} /* gn_add() */


#define GN_PUSHSTRING(L, o) \
	lua_pushlstring((L), (char *)ASN1_STRING_get0_data((o)), ASN1_STRING_length((o)))

static int gn__next(lua_State *L) {
	GENERAL_NAMES *gens = checksimple(L, lua_upvalueindex(1), X509_GENS_CLASS);
	int i = lua_tointeger(L, lua_upvalueindex(2));
	int n = sk_GENERAL_NAME_num(gens);

	lua_settop(L, 0);

	while (i < n) {
		GENERAL_NAME *name;
		const char *txt;
		size_t len;
		union { struct in_addr in; struct in6_addr in6; } ip;
		char buf[INET6_ADDRSTRLEN + 1];
		int af;

		if (!(name = sk_GENERAL_NAME_value(gens, i++)))
			continue;

		switch (name->type) {
		case GEN_EMAIL:
			lua_pushliteral(L, "email");
			GN_PUSHSTRING(L, name->d.rfc822Name);

			break;
		case GEN_URI:
			lua_pushliteral(L, "URI");
			GN_PUSHSTRING(L, name->d.uniformResourceIdentifier);

			break;
		case GEN_DNS:
			lua_pushliteral(L, "DNS");
			GN_PUSHSTRING(L, name->d.dNSName);

			break;
		case GEN_IPADD:
			txt = (char *)ASN1_STRING_get0_data(name->d.iPAddress);
			len = ASN1_STRING_length(name->d.iPAddress);

			switch (len) {
			case 16:
				memcpy(ip.in6.s6_addr, txt, 16);
				af = AF_INET6;

				break;
			case 4:
				memcpy(&ip.in.s_addr, txt, 4);
				af = AF_INET;

				break;
			default:
				continue;
			}

			if (!(txt = inet_ntop(af, &ip, buf, sizeof buf)))
				continue;

			lua_pushliteral(L, "IP");
			lua_pushstring(L, txt);

			break;
		case GEN_DIRNAME:
			lua_pushliteral(L, "DirName");
			xn_dup(L, name->d.dirn);

			break;
		default:
			continue;
		} /* switch() */

		break;
	} /* while() */

	lua_pushinteger(L, i);
	lua_replace(L, lua_upvalueindex(2));

	return lua_gettop(L);
} /* gn__next() */

static int gn__pairs(lua_State *L) {
	lua_settop(L, 1);
	lua_pushinteger(L, 0);
	lua_pushcclosure(L, &gn__next, 2);

	return 1;
} /* gn__pairs() */


static int gn__gc(lua_State *L) {
	GENERAL_NAMES **ud = luaL_checkudata(L, 1, X509_GENS_CLASS);

	if (*ud) {
		sk_GENERAL_NAME_pop_free(*ud, GENERAL_NAME_free);
		*ud = NULL;
	}

	return 0;
} /* gn__gc() */


static const auxL_Reg gn_methods[] = {
	{ "add", &gn_add },
	{ NULL,  NULL },
};

static const auxL_Reg gn_metatable[] = {
	{ "__pairs", &gn__pairs },
	{ "__gc",    &gn__gc },
	{ NULL,      NULL },
};


static const auxL_Reg gn_globals[] = {
	{ "new",       &gn_new },
	{ "interpose", &gn_interpose },
	{ NULL,        NULL },
};

EXPORT int luaopen__openssl_x509_altname(lua_State *L) {
	initall(L);

	auxL_newlib(L, gn_globals, 0);

	return 1;
} /* luaopen__openssl_x509_altname() */


/*
 * X509_EXTENSION - openssl.x509.extension
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static _Bool xe_new_isder(const char *value, _Bool *crit) {
	if (!strcmp(value, "critical,DER"))
		return (*crit = 1), 1;
	if (!strcmp(value, "DER"))
		return (*crit = 0), 1;

	return 0;
} /* xs_new_isder() */

static CONF* loadconf(lua_State *L, int idx) {
	CONF *conf;
	size_t len;
	const char *cdata = luaL_checklstring(L, idx, &len);
	BIO *bio = getbio(L);
	if (BIO_write(bio, cdata, len) < 0)
		return NULL;

	if (!(conf = NCONF_new(NULL)))
		return NULL;

	if (!NCONF_load_bio(conf, bio, NULL)) {
		NCONF_free(conf);
		return NULL;
	}

	return conf;
}

static int xe_new(lua_State *L) {
	const char *name = luaL_checkstring(L, 1);
	const char *value = luaL_checkstring(L, 2);
	ASN1_OBJECT *obj = NULL;
	ASN1_STRING *oct = NULL;
	CONF *conf = NULL;
	X509V3_CTX cbuf = { 0 }, *ctx = NULL;
	X509_EXTENSION **ud;
	_Bool crit;

	lua_settop(L, 3);
	ud = prepsimple(L, X509_EXT_CLASS);

	if (xe_new_isder(value, &crit)) {
		size_t len;
		const char *cdata = lua_tolstring(L, 3, &len);
		if (!(obj = OBJ_txt2obj(name, 0)))
			goto error;
		if (!(oct = ASN1_STRING_new()))
			goto error;
		if (!ASN1_STRING_set(oct, cdata, len))
			goto error;
		if (!(*ud = X509_EXTENSION_create_by_OBJ(NULL, obj, crit, oct)))
			goto error;

		ASN1_OBJECT_free(obj);
		ASN1_STRING_free(oct);

		return 1;
	}

	switch (lua_type(L, 3)) {
	case LUA_TNONE:
	case LUA_TNIL:
		break;
	case LUA_TSTRING: {
		if (!(conf = loadconf(L, 3)))
			goto error;

		ctx = &cbuf;
		X509V3_set_nconf(ctx, conf);
		break;
	}
	case LUA_TTABLE: {
		X509 *issuer = NULL;
		X509 *subject = NULL;
		X509_REQ *request = NULL;
		X509_CRL *crl = NULL;
		int flags = 0;

		ctx = &cbuf;

		if (lua_getfield(L, 3, "db") != LUA_TNIL) {
			if (!(conf = loadconf(L, -1)))
				goto error;
			X509V3_set_nconf(ctx, conf);
		}
		lua_pop(L, 1);

		if (lua_getfield(L, 3, "issuer") != LUA_TNIL) {
			issuer = checksimple(L, -1, X509_CERT_CLASS);
		}
		lua_pop(L, 1);

		if (lua_getfield(L, 3, "subject") != LUA_TNIL) {
			subject = checksimple(L, -1, X509_CERT_CLASS);
		}
		lua_pop(L, 1);

		if (lua_getfield(L, 3, "request") != LUA_TNIL) {
			request = checksimple(L, -1, X509_CSR_CLASS);
		}
		lua_pop(L, 1);

		if (lua_getfield(L, 3, "crl") != LUA_TNIL) {
			crl = checksimple(L, -1, X509_CRL_CLASS);
		}
		lua_pop(L, 1);

		if (lua_getfield(L, 3, "flags") != LUA_TNIL) {
			flags = luaL_checkinteger(L, -1);
		}
		lua_pop(L, 1);

		X509V3_set_ctx(ctx, issuer, subject, request, crl, flags);
		break;
	}
	default:
		return luaL_argerror(L, 3, "invalid extra parameter (expected string, table or nil)");
	}

	/*
	 * NOTE: AFAICT neither name nor value are modified. The API just
	 * doesn't have the proper const-qualifiers. See
	 * crypto/x509v3/v3_conf.c in OpenSSL.
	 *
	 * Also seems to be okay to pass NULL conf. Both NCONF_get_section
	 * and sk_CONF_VALUE_num can handle NULL arguments. See do_ext_nconf
	 * in v3_conf.c.
	 */
	if (!(*ud = X509V3_EXT_nconf(conf, ctx, (char *)name, (char *)value)))
		goto error;

	if (conf)
		NCONF_free(conf);

	return 1;
error:
	if (obj)
		ASN1_OBJECT_free(obj);
	if (oct)
		ASN1_STRING_free(oct);
	if (conf)
		NCONF_free(conf);

	return auxL_error(L, auxL_EOPENSSL, "x509.extension.new");
} /* xe_new() */


static int xe_interpose(lua_State *L) {
	return interpose(L, X509_EXT_CLASS);
} /* xe_interpose() */


static int xe_getID(lua_State *L) {
	X509_EXTENSION *ext = checksimple(L, 1, X509_EXT_CLASS);
	ASN1_OBJECT *obj = X509_EXTENSION_get0_object(ext);
	char txt[256];
	int len;

	if (!(len = auxS_obj2id(txt, sizeof txt, obj)))
		return auxL_error(L, auxL_EOPENSSL, "x509.extension:getID");

	lua_pushlstring(L, txt, len);

	return 1;
} /* xe_getID() */


static int xe_getName(lua_State *L) {
	X509_EXTENSION *ext = checksimple(L, 1, X509_EXT_CLASS);
	char txt[256];
	int len;

	if (!(len = auxS_obj2txt(txt, sizeof txt, X509_EXTENSION_get0_object(ext))))
		return auxL_error(L, auxL_EOPENSSL, "x509.extension:getName");

	lua_pushlstring(L, txt, len);

	return 1;
} /* xe_getName() */


static int xe_getShortName(lua_State *L) {
	X509_EXTENSION *ext = checksimple(L, 1, X509_EXT_CLASS);
	char txt[256];
	int len;

	if (!(len = auxS_obj2sn(txt, sizeof txt, X509_EXTENSION_get0_object(ext))))
		return 0;

	lua_pushlstring(L, txt, len);

	return 1;
} /* xe_getShortName() */


static int xe_getLongName(lua_State *L) {
	X509_EXTENSION *ext = checksimple(L, 1, X509_EXT_CLASS);
	char txt[256];
	int len;

	if (!(len = auxS_obj2ln(txt, sizeof txt, X509_EXTENSION_get0_object(ext))))
		return 0;

	lua_pushlstring(L, txt, len);

	return 1;
} /* xe_getLongName() */


static int xe_getData(lua_State *L) {
	ASN1_STRING *data = X509_EXTENSION_get0_data(checksimple(L, 1, X509_EXT_CLASS));

	lua_pushlstring(L, (char *)ASN1_STRING_get0_data(data), ASN1_STRING_length(data));

	return 1;
} /* xe_getData() */


static int xe_getCritical(lua_State *L) {
	lua_pushboolean(L, X509_EXTENSION_get_critical(checksimple(L, 1, X509_EXT_CLASS)));

	return 1;
} /* xe_getCritical() */


static int xe_text(lua_State *L) {
	X509_EXTENSION *ext = checksimple(L, 1, X509_EXT_CLASS);
	unsigned long flags = auxL_optunsigned(L, 2, 0, 0, ULONG_MAX);
	int indent = auxL_optinteger(L, 3, 0, 0, INT_MAX);
	BIO *bio = getbio(L);
	char *data;
	size_t len;

	if (!X509V3_EXT_print(bio, ext, flags, indent))
		return auxL_error(L, auxL_EOPENSSL, "x509.extension:text");

	len = BIO_get_mem_data(bio, &data);

	lua_pushlstring(L, data, len);

	return 1;
} /* xe_text() */


static int xe__gc(lua_State *L) {
	X509_EXTENSION **ud = luaL_checkudata(L, 1, X509_EXT_CLASS);

	if (*ud) {
		X509_EXTENSION_free(*ud);
		*ud = NULL;
	}

	return 0;
} /* xe__gc() */


static const auxL_Reg xe_methods[] = {
	{ "getID",        &xe_getID },
	{ "getName",      &xe_getName },
	{ "getShortName", &xe_getShortName },
	{ "getLongName",  &xe_getLongName },
	{ "getData",      &xe_getData },
	{ "getCritical",  &xe_getCritical },
	{ "text",         &xe_text },
	{ NULL,           NULL },
};

static const auxL_Reg xe_metatable[] = {
	{ "__gc", &xe__gc },
	{ NULL,   NULL },
};


static const auxL_Reg xe_globals[] = {
	{ "new",       &xe_new },
	{ "interpose", &xe_interpose },
	{ NULL,        NULL },
};

static const auxL_IntegerReg xe_textopts[] = {
	{ "UNKNOWN_MASK", X509V3_EXT_UNKNOWN_MASK },
	{ "DEFAULT", X509V3_EXT_DEFAULT },
	{ "ERROR_UNKNOWN", X509V3_EXT_ERROR_UNKNOWN },
	{ "PARSE_UNKNOWN", X509V3_EXT_PARSE_UNKNOWN },
	{ "DUMP_UNKNOWN", X509V3_EXT_DUMP_UNKNOWN },
	{ NULL, 0 },
};

EXPORT int luaopen__openssl_x509_extension(lua_State *L) {
	initall(L);

	auxL_newlib(L, xe_globals, 0);
	auxL_setintegers(L, xe_textopts);

	return 1;
} /* luaopen__openssl_x509_extension() */


/*
 * X509 - openssl.x509.cert
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static void xc_dup(lua_State *L, X509 *x509) {
	X509 **ud = prepsimple(L, X509_CERT_CLASS);

	if (!(*ud = X509_dup(x509)))
		goto error;

	return;
error:
	auxL_error(L, auxL_EOPENSSL, "X509_dup");
} /* xc_dup() */


static int xc_new(lua_State *L) {
	const char *data;
	size_t len;
	X509 **ud;

	lua_settop(L, 2);

	ud = prepsimple(L, X509_CERT_CLASS);

	if ((data = luaL_optlstring(L, 1, NULL, &len))) {
		int type = optencoding(L, 2, "*", X509_ANY|X509_PEM|X509_DER);
		BIO *tmp;
		int ok = 0;

		if (!(tmp = BIO_new_mem_buf((char *)data, len)))
			return auxL_error(L, auxL_EOPENSSL, "x509.cert.new");

		if (type == X509_PEM || type == X509_ANY) {
			ok = !!(*ud = PEM_read_bio_X509(tmp, NULL, 0, "")); /* no password */
		}

		if (!ok && (type == X509_DER || type == X509_ANY)) {
			BIO_reset(tmp);
			ok = !!(*ud = d2i_X509_bio(tmp, NULL));
		}

		BIO_free(tmp);

		if (!ok)
			return auxL_error(L, auxL_EOPENSSL, "x509.cert.new");
	} else {
		if (!(*ud = X509_new()))
			return auxL_error(L, auxL_EOPENSSL, "x509.cert.new");

		X509_gmtime_adj(X509_get_notBefore(*ud), 0);
		X509_gmtime_adj(X509_get_notAfter(*ud), 0);
	}

	return 1;
} /* xc_new() */


static int xc_interpose(lua_State *L) {
	return interpose(L, X509_CERT_CLASS);
} /* xc_interpose() */


static int xc_getVersion(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);

	lua_pushinteger(L, X509_get_version(crt) + 1);

	return 1;
} /* xc_getVersion() */


static int xc_setVersion(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	int version = luaL_checkinteger(L, 2);

	if (!X509_set_version(crt, version - 1))
		return luaL_error(L, "x509.cert:setVersion: %d: invalid version", version);

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setVersion() */


static int xc_getSerial(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	BIGNUM *serial = bn_push(L);
	ASN1_INTEGER *i;

	if ((i = X509_get_serialNumber(crt))) {
		if (!ASN1_INTEGER_to_BN(i, serial))
			return auxL_error(L, auxL_EOPENSSL, "x509.cert:getSerial");
	}

	return 1;
} /* xc_getSerial() */


static int xc_setSerial(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	ASN1_INTEGER *serial;

	if (!(serial = BN_to_ASN1_INTEGER(checkbig(L, 2), NULL)))
		goto error;

	if (!X509_set_serialNumber(crt, serial))
		goto error;

	ASN1_INTEGER_free(serial);

	lua_pushboolean(L, 1);

	return 1;
error:
	ASN1_INTEGER_free(serial);

	return auxL_error(L, auxL_EOPENSSL, "x509.cert:setSerial");
} /* xc_setSerial() */


static int xc_digest(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	const char *type = luaL_optstring(L, 2, "sha1");
	int format = luaL_checkoption(L, 3, "x", (const char *[]){ "s", "x", "n", NULL });
	const EVP_MD *ctx;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned len;

	lua_settop(L, 3); /* self, type, hex */

	if (!(ctx = EVP_get_digestbyname(type)))
		return luaL_error(L, "x509.cert:digest: %s: invalid digest type", type);

	X509_digest(crt, ctx, md, &len);

	switch (format) {
	case 2: {
		BIGNUM *bn = bn_push(L);

		if (!BN_bin2bn(md, len, bn))
			return auxL_error(L, auxL_EOPENSSL, "x509.cert:digest");

		break;
	}
	case 1: {
		static const unsigned char x[16] = "0123456789abcdef";
		luaL_Buffer B;
		unsigned i;

		luaL_buffinitsize(L, &B, 2 * len);

		for (i = 0; i < len; i++) {
			luaL_addchar(&B, x[0x0f & (md[i] >> 4)]);
			luaL_addchar(&B, x[0x0f & (md[i] >> 0)]);
		}

		luaL_pushresult(&B);

		break;
	}
	default:
		lua_pushlstring(L, (const char *)md, len);

		break;
	} /* switch() */

	return 1;
} /* xc_digest() */


static _Bool isleap(int year) {
	if (year >= 0)
		return !(year % 4) && ((year % 100) || !(year % 400));
	else
		return isleap(-(year + 1));
} /* isleap() */


static int yday(int year, int mon, int mday) {
	static const int past[12] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
	int yday = past[CLAMP(mon, 0, 11)] + CLAMP(mday, 1, 31) - 1;

	return yday + (mon > 1 && isleap(year));
} /* yday() */


static int tm_yday(const struct tm *tm) {
	return (tm->tm_yday)? tm->tm_yday : yday(1900 + tm->tm_year, tm->tm_mon, tm->tm_mday);
} /* tm_yday() */


static int leaps(int year) {
	if (year >= 0)
		return (year / 400) + (year / 4) - (year / 100);
	else
		return -(leaps(-(year + 1)) + 1);
} /* leaps() */


static double tm2unix(const struct tm *tm, int gmtoff) {
	int year = tm->tm_year + 1900;
	double ts;

	ts = 86400.0 * 365.0 * (year - 1970);
	ts += 86400.0 * (leaps(year - 1) - leaps(1969));
	ts += 86400 * tm_yday(tm);
	ts += 3600 * tm->tm_hour;
	ts += 60 * tm->tm_min;
	ts += CLAMP(tm->tm_sec, 0, 59);
	ts += (year < 1970)? gmtoff : -gmtoff;

	return ts;
} /* tm2unix() */


static _Bool scan(int *i, char **cp, int n, int signok) {
	int sign = 1;

	*i = 0;

	if (signok) {
		if (**cp == '-') {
			sign = -1;
			++*cp;
		} else if (**cp == '+') {
			++*cp;
		}
	}

	while (n-- > 0) {
		if (**cp < '0' || **cp > '9')
			return 0;

		*i *= 10;
		*i += *(*cp)++ - '0';
	}

	*i *= sign;

	return 1;
} /* scan() */


static double timeutc(const ASN1_TIME *time) {
	char buf[32] = "", *cp;
	struct tm tm = { 0 };
	int gmtoff = 0, year, i;

	if (!ASN1_TIME_check((ASN1_STRING *)time))
		return 0;

	cp = strncpy(buf, (const char *)ASN1_STRING_get0_data((ASN1_STRING *)time), sizeof buf - 1);

	if (ASN1_STRING_type((ASN1_STRING *)time) == V_ASN1_GENERALIZEDTIME) {
		if (!scan(&year, &cp, 4, 1))
			goto badfmt;
	} else {
		if (!scan(&year, &cp, 2, 0))
			goto badfmt;
		year += (year < 50)? 2000 : 1900;
	}

	tm.tm_year = year - 1900;

	if (!scan(&i, &cp, 2, 0))
		goto badfmt;

	tm.tm_mon = CLAMP(i, 1, 12) - 1;

	if (!scan(&i, &cp, 2, 0))
		goto badfmt;

	tm.tm_mday = CLAMP(i, 1, 31);

	tm.tm_yday = yday(year, tm.tm_mon, tm.tm_mday);

	if (!scan(&i, &cp, 2, 0))
		goto badfmt;

	tm.tm_hour = CLAMP(i, 0, 23);

	if (!scan(&i, &cp, 2, 0))
		goto badfmt;

	tm.tm_min = CLAMP(i, 0, 59);

	if (*cp >= '0' && *cp <= '9') {
		if (!scan(&i, &cp, 2, 0))
			goto badfmt;

		tm.tm_sec = CLAMP(i, 0, 59);
	}

	if (*cp == '+' || *cp == '-') {
		int sign = (*cp++ == '-')? -1 : 1;
		int hh, mm;

		if (!scan(&hh, &cp, 2, 0) || !scan(&mm, &cp, 2, 0))
			goto badfmt;

		gmtoff = (CLAMP(hh, 0, 23) * 3600)
		       + (CLAMP(mm, 0, 59) * 60);

		gmtoff *= sign;
	}

	return tm2unix(&tm, gmtoff);
badfmt:
	return INFINITY;
} /* timeutc() */


static int xc_getLifetime(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	double begin = INFINITY, end = INFINITY;
	const ASN1_TIME *time;

	if ((time = X509_get_notBefore(crt)))
		begin = timeutc(time);

	if ((time = X509_get_notAfter(crt)))
		end = timeutc(time);

	if (isfinite(begin))
		lua_pushnumber(L, begin);
	else
		lua_pushnil(L);

	if (isfinite(end))
		lua_pushnumber(L, end);
	else
		lua_pushnil(L);

	if (isfinite(begin) && isfinite(end) && begin <= end)
		lua_pushnumber(L, fabs(end - begin));
	else
		lua_pushnumber(L, 0.0);

	return 3;
} /* xc_getLifetime() */


static int xc_setLifetime(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	double ut;
	const char *dt;

	lua_settop(L, 3);

	if (lua_isnumber(L, 2)) {
		ut = lua_tonumber(L, 2);

		if (!ASN1_TIME_set(X509_get_notBefore(crt), ut))
			return auxL_error(L, auxL_EOPENSSL, "x509.cert:setLifetime");
#if 0
	} else if ((dt = luaL_optstring(L, 2, 0))) {
		if (!ASN1_TIME_set_string(X509_get_notBefore(crt), dt))
			return auxL_error(L, auxL_EOPENSSL, "x509.cert:setLifetime");
#endif
	}

	if (lua_isnumber(L, 3)) {
		ut = lua_tonumber(L, 3);

		if (!ASN1_TIME_set(X509_get_notAfter(crt), ut))
			return auxL_error(L, auxL_EOPENSSL, "x509.cert:setLifetime");
#if 0
	} else if ((dt = luaL_optstring(L, 3, 0))) {
		if (!ASN1_TIME_set_string(X509_get_notAfter(crt), dt))
			return auxL_error(L, auxL_EOPENSSL, "x509.cert:setLifetime");
#endif
	}

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setLifetime() */


static int xc_getIssuer(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	X509_NAME *name;

	if (!(name = X509_get_issuer_name(crt)))
		return 0;

	xn_dup(L, name);

	return 1;
} /* xc_getIssuer() */


static int xc_setIssuer(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	X509_NAME *name = checksimple(L, 2, X509_NAME_CLASS);

	if (!X509_set_issuer_name(crt, name))
		return auxL_error(L, auxL_EOPENSSL, "x509.cert:setIssuer");

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setIssuer() */


static int xc_getSubject(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	X509_NAME *name;

	if (!(name = X509_get_subject_name(crt)))
		return 0;

	xn_dup(L, name);

	return 1;
} /* xc_getSubject() */


static int xc_setSubject(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	X509_NAME *name = checksimple(L, 2, X509_NAME_CLASS);

	if (!X509_set_subject_name(crt, name))
		return auxL_error(L, auxL_EOPENSSL, "x509.cert:setSubject");

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setSubject() */


static void xc_setCritical(X509 *crt, int nid, _Bool yes) {
	X509_EXTENSION *ext;
	int loc;

	if ((loc = X509_get_ext_by_NID(crt, nid, -1)) >= 0
	&&  (ext = X509_get_ext(crt, loc)))
		X509_EXTENSION_set_critical(ext, yes);
} /* xc_setCritical() */


static _Bool xc_getCritical(X509 *crt, int nid) {
	X509_EXTENSION *ext;
	int loc;

	if ((loc = X509_get_ext_by_NID(crt, nid, -1)) >= 0
	&&  (ext = X509_get_ext(crt, loc)))
		return X509_EXTENSION_get_critical(ext);
	else
		return 0;
} /* xc_getCritical() */


static int xc_getIssuerAlt(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	GENERAL_NAMES *gens;

	if (!(gens = X509_get_ext_d2i(crt, NID_issuer_alt_name, 0, 0)))
		return 0;

	gn_dup(L, gens);

	return 1;
} /* xc_getIssuerAlt() */


static int xc_setIssuerAlt(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	GENERAL_NAMES *gens = checksimple(L, 2, X509_GENS_CLASS);

	if (!X509_add1_ext_i2d(crt, NID_issuer_alt_name, gens, 0, X509V3_ADD_REPLACE))
		return auxL_error(L, auxL_EOPENSSL, "x509.altname:setIssuerAlt");

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setIssuerAlt() */


static int xc_getSubjectAlt(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	GENERAL_NAMES *gens;

	if (!(gens = X509_get_ext_d2i(crt, NID_subject_alt_name, 0, 0)))
		return 0;

	gn_dup(L, gens);

	return 1;
} /* xc_getSubjectAlt() */


static int xc_setSubjectAlt(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	GENERAL_NAMES *gens = checksimple(L, 2, X509_GENS_CLASS);

	if (!X509_add1_ext_i2d(crt, NID_subject_alt_name, gens, 0, X509V3_ADD_REPLACE))
		return auxL_error(L, auxL_EOPENSSL, "x509.altname:setSubjectAlt");

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setSubjectAlt() */


static int xc_getIssuerAltCritical(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);

	lua_pushboolean(L, xc_getCritical(crt, NID_issuer_alt_name));

	return 1;
} /* xc_getIssuerAltCritical() */


static int xc_setIssuerAltCritical(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);

	luaL_checkany(L, 2);
	xc_setCritical(crt, NID_issuer_alt_name, lua_toboolean(L, 2));

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setIssuerAltCritical() */


static int xc_getSubjectAltCritical(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);

	lua_pushboolean(L, xc_getCritical(crt, NID_subject_alt_name));

	return 1;
} /* xc_getSubjectAltCritical() */


static int xc_setSubjectAltCritical(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);

	luaL_checkany(L, 2);
	xc_setCritical(crt, NID_subject_alt_name, lua_toboolean(L, 2));

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setSubjectAltCritical() */


static int xc_getBasicConstraint(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	BASIC_CONSTRAINTS *bs;
	int CA, pathLen;

	if (!(bs = X509_get_ext_d2i(crt, NID_basic_constraints, 0, 0))) {
		/* FIXME: detect error or just non-existent */

		if (lua_gettop(L) > 1)
			return 0;

		lua_newtable(L);

		return 1;
	}

	CA = bs->ca;
	pathLen = ASN1_INTEGER_get(bs->pathlen);

	BASIC_CONSTRAINTS_free(bs);

	if (lua_gettop(L) > 1) {
		int n = 0, i, top;

		for (i = 2, top = lua_gettop(L); i <= top; i++) {
			switch (auxL_checkoption(L, i, 0, (const char *[]){ "CA", "pathLen", "pathLenConstraint", NULL }, 1)) {
			case 0:
				lua_pushboolean(L, CA);
				n++;
				break;
			case 1:
				/* FALL THROUGH */
			case 2:
				lua_pushinteger(L, pathLen);
				n++;
				break;
			}
		}

		return n;
	} else {
		lua_newtable(L);

		lua_pushboolean(L, CA);
		lua_setfield(L, -2, "CA");

		lua_pushinteger(L, pathLen);
		lua_setfield(L, -2, "pathLen");

		return 1;
	}
} /* xc_getBasicConstraint() */


static int xc_setBasicConstraint(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	BASIC_CONSTRAINTS *bs = 0;
	int CA = -1, pathLen = -1;
	int critical = 0;

	luaL_checkany(L, 2);

	if (lua_istable(L, 2)) {
		lua_getfield(L, 2, "CA");
		if (!lua_isnil(L, -1))
			CA = lua_toboolean(L, -1);
		lua_pop(L, 1);

		lua_getfield(L, 2, "pathLen");
		pathLen = luaL_optinteger(L, -1, pathLen);
		lua_pop(L, 1);

		lua_getfield(L, 2, "pathLenConstraint");
		pathLen = luaL_optinteger(L, -1, pathLen);
		lua_pop(L, 1);

		if (!(bs = BASIC_CONSTRAINTS_new()))
			goto error;
	} else {
		lua_settop(L, 3);

		switch (auxL_checkoption(L, 2, 0, (const char *[]){ "CA", "pathLen", "pathLenConstraint", NULL }, 1)) {
		case 0:
			luaL_checktype(L, 3, LUA_TBOOLEAN);
			CA = lua_toboolean(L, 3);

			break;
		case 1:
			/* FALL THROUGH */
		case 2:
			pathLen = luaL_checkinteger(L, 3);

			break;
		}

		if (!(bs = X509_get_ext_d2i(crt, NID_basic_constraints, &critical, 0))) {
			/* FIXME: detect whether error or just non-existent */
			if (!(bs = BASIC_CONSTRAINTS_new()))
				goto error;
		}
	}

	if (CA != -1)
		bs->ca = CA ? 0xFF : 0; /* use DER value */

	if (pathLen >= 0) {
		ASN1_INTEGER_free(bs->pathlen);

		if (!(bs->pathlen = ASN1_STRING_type_new(V_ASN1_INTEGER)))
			goto error;

		if (!ASN1_INTEGER_set(bs->pathlen, pathLen))
			goto error;
	}

	if (!X509_add1_ext_i2d(crt, NID_basic_constraints, bs, critical, X509V3_ADD_REPLACE))
		goto error;

	BASIC_CONSTRAINTS_free(bs);

	lua_pushboolean(L, 1);

	return 1;
error:
	BASIC_CONSTRAINTS_free(bs);

	return auxL_error(L, auxL_EOPENSSL, "x509.cert:setBasicConstraint");
} /* xc_setBasicConstraint() */


static int xc_getBasicConstraintsCritical(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);

	lua_pushboolean(L, xc_getCritical(crt, NID_basic_constraints));

	return 1;
} /* xc_getBasicConstraintsCritical() */


static int xc_setBasicConstraintsCritical(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);

	luaL_checkany(L, 2);
	xc_setCritical(crt, NID_basic_constraints, lua_toboolean(L, 2));

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setBasicConstraintsCritical() */


static int xc_addExtension(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	X509_EXTENSION *ext = checksimple(L, 2, X509_EXT_CLASS);

	/* NOTE: Will dup extension in X509v3_add_ext. */
	if (!X509_add_ext(crt, ext, -1))
		return auxL_error(L, auxL_EOPENSSL, "x509.cert:addExtension");

	lua_pushboolean(L, 1);

	return 1;
} /* xc_addExtension() */


static int xc_setExtension(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	X509_EXTENSION *ext = checksimple(L, 2, X509_EXT_CLASS);
	int nid, crit;
	void *value;

	nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));
	crit = X509_EXTENSION_get_critical(ext);
	value = X509_EXTENSION_get_data(ext);

	if (!X509_add1_ext_i2d(crt, nid, value, crit, X509V3_ADD_REPLACE))
		return auxL_error(L, auxL_EOPENSSL, "x509.cert:setExtension");

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setExtension() */


static int xc_getExtension(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	X509_EXTENSION *ext = NULL, **ud;
	int i;

	luaL_checkany(L, 2);

	if (lua_type(L, 2) == LUA_TNUMBER) {
		/* NB: Lua 1-based indexing */
		i = auxL_checkinteger(L, 2, 1, INT_MAX) - 1;
	} else {
		ASN1_OBJECT *obj;

		if (!auxS_txt2obj(&obj, luaL_checkstring(L, 2))) {
			goto error;
		} else if (!obj) {
			goto undef;
		}

		i = X509_get_ext_by_OBJ(crt, obj, -1);

		ASN1_OBJECT_free(obj);
	}

	ud = prepsimple(L, X509_EXT_CLASS);

	if (i < 0 || !(ext = X509_get0_ext(crt, i)))
		goto undef;

	if (!(*ud = X509_EXTENSION_dup(ext)))
		goto error;

	return 1;
undef:
	return 0;
error:
	return auxL_error(L, auxL_EOPENSSL, "x509.cert:getExtension");
} /* xc_getExtension() */


static int xc_getExtensionCount(lua_State *L) {
	auxL_pushinteger(L, X509_get_ext_count(checksimple(L, 1, X509_CERT_CLASS)));

	return 1;
} /* xc_getExtensionCount() */


static int sk_openssl_string__gc(lua_State *L) {
	STACK_OF(OPENSSL_STRING) **res = lua_touserdata(L, 1);

	if (*res) {
		sk_OPENSSL_STRING_free(*res);
		*res = NULL;
	}

	return 0;
} /* sk_openssl_string__gc() */


static int xc_getOCSP(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	STACK_OF(OPENSSL_STRING) **res = prepsimple(L, NULL, &sk_openssl_string__gc);
	int num, i;

	*res = X509_get1_ocsp(crt);
	if (!*res)
		return 0;

	num = sk_OPENSSL_STRING_num(*res);
	luaL_checkstack(L, num, "too many authorityInfoAccess");
	for (i = 0; i < num; i++) {
		lua_pushstring(L, sk_OPENSSL_STRING_value(*res, i));
	}

	sk_OPENSSL_STRING_free(*res);
	*res = NULL;

	return num;
} /* xc_getOCSP */


static int xc_isIssuedBy(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	X509 *issuer = checksimple(L, 2, X509_CERT_CLASS);
	EVP_PKEY *key;
	int ok, why = 0;

	ERR_clear_error();

	if (X509_V_OK != (why = X509_check_issued(issuer, crt)))
		goto done;

	if (!(key = X509_get_pubkey(issuer))) {
		why = X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY;
		goto done;
	}

	ok = (1 == X509_verify(crt, key));

	EVP_PKEY_free(key);

	if (!ok)
		why = X509_V_ERR_CERT_SIGNATURE_FAILURE;

done:
	if (why != X509_V_OK) {
		lua_pushboolean(L, 0);
		lua_pushstring(L, X509_verify_cert_error_string(why));

		return 2;
	} else {
		lua_pushboolean(L, 1);

		return 1;
	}
} /* xc_isIssuedBy() */


static int xc_getPublicKey(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	EVP_PKEY **key = prepsimple(L, PKEY_CLASS);

	if (!(*key = X509_get_pubkey(crt)))
		return auxL_error(L, auxL_EOPENSSL, "x509.cert:getPublicKey");

	return 1;
} /* xc_getPublicKey() */


static int xc_setPublicKey(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	EVP_PKEY *key = checksimple(L, 2, PKEY_CLASS);

	if (!X509_set_pubkey(crt, key))
		return auxL_error(L, auxL_EOPENSSL, "x509.cert:setPublicKey");

	lua_pushboolean(L, 1);

	return 1;
} /* xc_setPublicKey() */


static int xc_getPublicKeyDigest(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	EVP_PKEY *key;
	const EVP_MD *md;
	ASN1_BIT_STRING *bitstr;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int len;

	if (!(key = X509_get_pubkey(crt)))
		return luaL_argerror(L, 1, "no public key");
	md = auxL_optdigest(L, 2, key, NULL);
	bitstr = X509_get0_pubkey_bitstr(crt);

	if (!EVP_Digest(bitstr->data, bitstr->length, digest, &len, md, NULL))
		return auxL_error(L, auxL_EOPENSSL, "x509.cert:getPublicKeyDigest");
	lua_pushlstring(L, (char *)digest, len);

	return 1;
} /* xc_getPublicKeyDigest() */


static int xc_getSignatureName(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	int nid;

	if (NID_undef == (nid = X509_get_signature_nid(crt)))
		return 0;

	auxL_pushnid(L, nid);

	return 1;
} /* xc_getSignatureName() */


static int xc_sign(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	EVP_PKEY *key = checksimple(L, 2, PKEY_CLASS);

	if (!X509_sign(crt, key, auxL_optdigest(L, 3, key, NULL)))
		return auxL_error(L, auxL_EOPENSSL, "x509.cert:sign");

	lua_pushboolean(L, 1);

	return 1;
} /* xc_sign() */


static int xc_verify(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	X509_STORE *store = NULL;
	STACK_OF(X509) *chain = NULL;
	X509_VERIFY_PARAM *params = NULL;
	X509_STORE_CTX *ctx = NULL;
	int ok, why;
	STACK_OF(X509) **proof;

	if (lua_istable(L, 2)) {
		if (lua_getfield(L, 2, "store") != LUA_TNIL) {
			store = checksimple(L, -1, X509_STORE_CLASS);
		} else if (!(OPENSSL_PREREQ(1,0,2) || LIBRESSL_PREREQ(2,7,5))) {
			/*
			Without .store OpenSSL 1.0.1 crashes e.g.

			#0  X509_STORE_get_by_subject (vs=vs@entry=0x6731b0, type=type@entry=1, name=name@entry=0x66a360, ret=ret@entry=0x7fffffffe580) at x509_lu.c:293
			#1  0x00007ffff69653ca in X509_STORE_CTX_get1_issuer (issuer=0x7fffffffe620, ctx=0x6731b0, x=0x665db0) at x509_lu.c:604
			#2  0x00007ffff696117c in X509_verify_cert (ctx=ctx@entry=0x6731b0) at x509_vfy.c:256

			Was fixed in LibreSSL somewhere between 2.6.5 and 2.7.5
			*/
			luaL_argerror(L, 2, ".store required in OpenSSL <= 1.0.1");
		}
		lua_pop(L, 1);

		if (lua_getfield(L, 2, "chain") != LUA_TNIL) {
			chain = checksimple(L, -1, X509_CHAIN_CLASS);
		}
		lua_pop(L, 1);

		if (lua_getfield(L, 2, "params") != LUA_TNIL) {
			params = checksimple(L, -1, X509_VERIFY_PARAM_CLASS);
		}
		lua_pop(L, 1);

		if (lua_getfield(L, 2, "crls") != LUA_TNIL) {
			luaL_argerror(L, 2, "crls not yet supported");
		}
		lua_pop(L, 1);

		if (lua_getfield(L, 2, "dane") != LUA_TNIL) {
			luaL_argerror(L, 2, "dane not yet supported");
		}
		lua_pop(L, 1);
	}

	/* pre-allocate space for a successful return */
	proof = prepsimple(L, X509_CHAIN_CLASS);

	if (chain && !(chain = X509_chain_up_ref(chain)))
		goto eossl;

	if (!(ctx = X509_STORE_CTX_new()) || !X509_STORE_CTX_init(ctx, store, crt, chain)) {
		sk_X509_pop_free(chain, X509_free);
		goto eossl;
	}

	if (params) {
		X509_VERIFY_PARAM *params_copy = X509_VERIFY_PARAM_new();
		if (!params_copy)
			goto eossl;

		ok = X509_VERIFY_PARAM_inherit(params_copy, params);
		if (!ok) {
			X509_VERIFY_PARAM_free(params_copy);
			goto eossl;
		}

		X509_STORE_CTX_set0_param(ctx, params_copy);
	}

	ERR_clear_error();

	ok = X509_verify_cert(ctx);

	switch (ok) {
	case 1: /* verified */
		if (!(*proof = X509_STORE_CTX_get1_chain(ctx)))
			goto eossl;
		X509_STORE_CTX_free(ctx);

		lua_pushboolean(L, 1);
		lua_pushvalue(L, -2);

		return 2;
	case 0: /* not verified */
		why = X509_STORE_CTX_get_error(ctx);
		X509_STORE_CTX_free(ctx);

		lua_pushboolean(L, 0);
		lua_pushstring(L, X509_verify_cert_error_string(why));

		return 2;
	default:
		goto eossl;
	}

eossl:
	if (ctx)
		X509_STORE_CTX_free(ctx);

	return auxL_error(L, auxL_EOPENSSL, "x509.cert:verify");
} /* xc_verify() */


static int xc_text(lua_State *L) {
	static const struct { const char *kw; unsigned int flag; } map[] = {
		{ "no_header", X509_FLAG_NO_HEADER },
		{ "no_version", X509_FLAG_NO_VERSION },
		{ "no_serial", X509_FLAG_NO_SERIAL },
		{ "no_signame", X509_FLAG_NO_SIGNAME },
		{ "no_validity", X509_FLAG_NO_VALIDITY },
		{ "no_subject", X509_FLAG_NO_SUBJECT },
		{ "no_issuer", X509_FLAG_NO_ISSUER },
		{ "no_pubkey", X509_FLAG_NO_PUBKEY },
		{ "no_extensions", X509_FLAG_NO_EXTENSIONS },
		{ "no_sigdump", X509_FLAG_NO_SIGDUMP },
		{ "no_aux", X509_FLAG_NO_AUX },
		{ "no_attributes", X509_FLAG_NO_ATTRIBUTES },
		{ "ext_default", X509V3_EXT_DEFAULT },
		{ "ext_error", X509V3_EXT_ERROR_UNKNOWN },
		{ "ext_parse", X509V3_EXT_PARSE_UNKNOWN },
		{ "ext_dump", X509V3_EXT_DUMP_UNKNOWN }
	};

	lua_settop(L, 2);

	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);

	unsigned int flags = 0;
	const char *kw;
	int found;
	unsigned int i;

	BIO *bio = getbio(L);
	char *data;
	long len;

	if (!lua_isnil(L, 2)) {
		lua_pushnil(L);
		while (lua_next(L, 2)) {
			kw = luaL_checkstring(L, -1);
			found = 0;
			for (i = 0; i < countof(map); i++)
				if (!strcmp(kw, map[i].kw)) {
					flags |= map[i].flag;
					found = 1;
				}
			if (!found)
				luaL_argerror(L, 2, lua_pushfstring(L, "invalid flag: %s", kw));
			lua_pop(L, 1);
		}
	}

	if (!X509_print_ex(bio, crt, 0, flags))
		return auxL_error(L, auxL_EOPENSSL, "x509.cert:text");

	len = BIO_get_mem_data(bio, &data);

	lua_pushlstring(L, data, len);

	return 1;
} /* xc_text() */


static int xc_toPEM(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	BIO *bio = getbio(L);
	size_t len;
	char *bytes;

	if (!PEM_write_bio_X509(bio, crt))
		return auxL_error(L, auxL_EOPENSSL, "x509.cert:toPEM");

	len = BIO_get_mem_data(bio, &bytes);
	lua_pushlstring(L, bytes, len);

	return 1;
} /* xc_toPEM() */


static int xc__tostring(lua_State *L) {
	X509 *crt = checksimple(L, 1, X509_CERT_CLASS);
	int type = optencoding(L, 2, "pem", X509_PEM|X509_DER);
	BIO *bio = getbio(L);
	char *data;
	long len;

	switch (type) {
	case X509_PEM:
		if (!PEM_write_bio_X509(bio, crt))
			return auxL_error(L, auxL_EOPENSSL, "x509.cert:__tostring");
		break;
	case X509_DER:
		if (!i2d_X509_bio(bio, crt))
			return auxL_error(L, auxL_EOPENSSL, "x509.cert:__tostring");
		break;
	} /* switch() */

	len = BIO_get_mem_data(bio, &data);

	lua_pushlstring(L, data, len);

	return 1;
} /* xc__tostring() */


static int xc__gc(lua_State *L) {
	X509 **ud = luaL_checkudata(L, 1, X509_CERT_CLASS);

	if (*ud) {
		X509_free(*ud);
		*ud = NULL;
	}

	return 0;
} /* xc__gc() */


static const auxL_Reg xc_methods[] = {
	{ "getVersion",    &xc_getVersion },
	{ "setVersion",    &xc_setVersion },
	{ "getSerial",     &xc_getSerial },
	{ "setSerial",     &xc_setSerial },
	{ "digest",        &xc_digest },
	{ "getLifetime",   &xc_getLifetime },
	{ "setLifetime",   &xc_setLifetime },
	{ "getIssuer",     &xc_getIssuer },
	{ "setIssuer",     &xc_setIssuer },
	{ "getSubject",    &xc_getSubject },
	{ "setSubject",    &xc_setSubject },
	{ "getIssuerAlt",  &xc_getIssuerAlt },
	{ "setIssuerAlt",  &xc_setIssuerAlt },
	{ "getSubjectAlt", &xc_getSubjectAlt },
	{ "setSubjectAlt", &xc_setSubjectAlt },
	{ "getIssuerAltCritical",  &xc_getIssuerAltCritical },
	{ "setIssuerAltCritical",  &xc_setIssuerAltCritical },
	{ "getSubjectAltCritical", &xc_getSubjectAltCritical },
	{ "setSubjectAltCritical", &xc_setSubjectAltCritical },
	{ "getBasicConstraints", &xc_getBasicConstraint },
	{ "getBasicConstraint",  &xc_getBasicConstraint },
	{ "setBasicConstraints", &xc_setBasicConstraint },
	{ "setBasicConstraint",  &xc_setBasicConstraint },
	{ "getBasicConstraintsCritical", &xc_getBasicConstraintsCritical },
	{ "setBasicConstraintsCritical", &xc_setBasicConstraintsCritical },
	{ "addExtension",  &xc_addExtension },
	{ "setExtension",  &xc_setExtension },
	{ "getExtension",  &xc_getExtension },
	{ "getExtensionCount", &xc_getExtensionCount },
	{ "getOCSP",       &xc_getOCSP },
	{ "isIssuedBy",    &xc_isIssuedBy },
	{ "getPublicKey",  &xc_getPublicKey },
	{ "setPublicKey",  &xc_setPublicKey },
	{ "getPublicKeyDigest", &xc_getPublicKeyDigest },
	{ "getSignatureName", &xc_getSignatureName },
	{ "sign",          &xc_sign },
	{ "verify",        &xc_verify },
	{ "text",          &xc_text },
	{ "toPEM",         &xc_toPEM },
	{ "tostring",      &xc__tostring },
	{ NULL,            NULL },
};

static const auxL_Reg xc_metatable[] = {
	{ "__tostring", &xc__tostring },
	{ "__gc",       &xc__gc },
	{ NULL,         NULL },
};


static const auxL_Reg xc_globals[] = {
	{ "new",       &xc_new },
	{ "interpose", &xc_interpose },
	{ NULL,        NULL },
};

EXPORT int luaopen__openssl_x509_cert(lua_State *L) {
	initall(L);

	auxL_newlib(L, xc_globals, 0);

	return 1;
} /* luaopen__openssl_x509_cert() */


/*
 * X509_REQ - openssl.x509.csr
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int xr_new(lua_State *L) {
	const char *data;
	size_t len;
	X509_REQ **ud;
	X509 *crt;

	lua_settop(L, 2);

	ud = prepsimple(L, X509_CSR_CLASS);

	if ((crt = testsimple(L, 1, X509_CERT_CLASS))) {
		if (!(*ud = X509_to_X509_REQ(crt, 0, 0)))
			return auxL_error(L, auxL_EOPENSSL, "x509.csr.new");
	} else if ((data = luaL_optlstring(L, 1, NULL, &len))) {
		int type = optencoding(L, 2, "*", X509_ANY|X509_PEM|X509_DER);
		BIO *tmp;
		int ok = 0;

		if (!(tmp = BIO_new_mem_buf((char *)data, len)))
			return auxL_error(L, auxL_EOPENSSL, "x509.csr.new");

		if (type == X509_PEM || type == X509_ANY) {
			ok = !!(*ud = PEM_read_bio_X509_REQ(tmp, NULL, 0, "")); /* no password */
		}

		if (!ok && (type == X509_DER || type == X509_ANY)) {
			BIO_reset(tmp);
			ok = !!(*ud = d2i_X509_REQ_bio(tmp, NULL));
		}

		BIO_free(tmp);

		if (!ok)
			return auxL_error(L, auxL_EOPENSSL, "x509.csr.new");
	} else {
		if (!(*ud = X509_REQ_new()))
			return auxL_error(L, auxL_EOPENSSL, "x509.csr.new");
	}

	return 1;
} /* xr_new() */


static int xr_interpose(lua_State *L) {
	return interpose(L, X509_CSR_CLASS);
} /* xr_interpose() */


static int xr_getVersion(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);

	lua_pushinteger(L, X509_REQ_get_version(csr) + 1);

	return 1;
} /* xr_getVersion() */


static int xr_setVersion(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	int version = luaL_checkinteger(L, 2);

	if (!X509_REQ_set_version(csr, version - 1))
		return luaL_error(L, "x509.csr:setVersion: %d: invalid version", version);

	lua_pushboolean(L, 1);

	return 1;
} /* xr_setVersion() */


static int xr_getSubject(lua_State *L) {
	X509_REQ *crt = checksimple(L, 1, X509_CSR_CLASS);
	X509_NAME *name;

	if (!(name = X509_REQ_get_subject_name(crt)))
		return 0;

	xn_dup(L, name);

	return 1;
} /* xr_getSubject() */


static int xr_setSubject(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	X509_NAME *name = checksimple(L, 2, X509_NAME_CLASS);

	if (!X509_REQ_set_subject_name(csr, name))
		return auxL_error(L, auxL_EOPENSSL, "x509.csr:setSubject");

	lua_pushboolean(L, 1);

	return 1;
} /* xr_setSubject() */


static int xr_getPublicKey(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	EVP_PKEY **key = prepsimple(L, PKEY_CLASS);

	if (!(*key = X509_REQ_get_pubkey(csr)))
		return auxL_error(L, auxL_EOPENSSL, "x509.csr:getPublicKey");

	return 1;
} /* xr_getPublicKey() */


static int xr_setPublicKey(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	EVP_PKEY *key = checksimple(L, 2, PKEY_CLASS);

	if (!X509_REQ_set_pubkey(csr, key))
		return auxL_error(L, auxL_EOPENSSL, "x509.csr:setPublicKey");

	lua_pushboolean(L, 1);

	return 1;
} /* xr_setPublicKey() */


static int xr_modifyRequestedExtension(X509_REQ *csr, int target_nid, int crit, void* value, unsigned long flags) {
	STACK_OF(X509_EXTENSION) *sk = NULL;
	int has_attrs=0;

	/*
	 * Replace existing if it's there. Extensions are stored in a CSR in
	 * an interesting way:
	 *
	 * They are stored as a list under either (most likely) the
	 * "official" NID_ext_req or under NID_ms_ext_req which means
	 * everything is stored under a list in a single "attribute" so we
	 * can't use X509_REQ_add1_attr or similar.
	 *
	 * Instead we have to get the extensions, find and replace the extension
	 * if it's in there, then *replace* the extensions in the list of
	 * attributes. (If we just try to add it the old ones are found
	 * first and don't take priority.)
	 */
	has_attrs = X509_REQ_get_attr_count(csr);

	sk = X509_REQ_get_extensions(csr);
	if (!X509V3_add1_i2d(&sk, target_nid, value, crit, flags))
		goto error;
	if (X509_REQ_add_extensions(csr, sk) == 0)
		goto error;
	sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);
	sk = NULL;

	/*
	 * Delete the old extensions attribute, so that the one we just
	 * added takes priority.
	 */
	if (has_attrs) {
		X509_ATTRIBUTE *attr = NULL;
		int idx, *pnid;

		for (pnid = X509_REQ_get_extension_nids(); *pnid != NID_undef; pnid++) {
			idx = X509_REQ_get_attr_by_NID(csr, *pnid, -1);
			if (idx == -1)
				continue;
			if (!(attr = X509_REQ_delete_attr(csr, idx)))
				goto error;
			X509_ATTRIBUTE_free(attr);
			break;
		}
		if (!attr)
			goto error;
	}

	/*
	 * We have to mark the encoded form as invalid, otherwise when we
	 * write it out again it will use the loaded version.
	 */
#if HAVE_I2D_RE_X509_REQ_TBS
	(void)i2d_re_X509_REQ_tbs(csr, NULL); /* sets csr->req_info->enc.modified */
#else
	csr->req_info->enc.modified = 1;
#endif

	return 0;
error:
	if (sk)
		sk_X509_EXTENSION_pop_free(sk, X509_EXTENSION_free);

	return 1;
} /* xr_modifyRequestedExtension() */


static int xr_getAttribute(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	const char *attr_name = luaL_checkstring(L, 2);
	int nid = OBJ_txt2nid(attr_name);
	int lastpos = luaL_optinteger(L, 3, -1);
	const char *err;

	if(nid==0)
		return luaL_error(L, "no oid for attribute '%s'", attr_name);


	int index =  X509_REQ_get_attr_by_NID(csr, nid, lastpos);
	X509_ATTRIBUTE *a = X509_REQ_get_attr(csr, index);
	ASN1_OBJECT *aobj = X509_ATTRIBUTE_get0_object(a);

	int val_count = X509_ATTRIBUTE_count(a);
	ASN1_BIT_STRING *bs = NULL;

	if (val_count == 0)
		return luaL_error(L, "x509_r_invalid_attributes");

	lua_createtable(L, val_count, 0);

	for(int i=0; i < val_count; i++) {
		ASN1_TYPE *at = X509_ATTRIBUTE_get0_type(a, i);
		int type = at->type;
		bs = at->value.asn1_string;

		switch (type) {
		case V_ASN1_PRINTABLESTRING:
		case V_ASN1_T61STRING:
		case V_ASN1_NUMERICSTRING:
		case V_ASN1_UTF8STRING:
		case V_ASN1_IA5STRING:
			lua_pushlstring(L, (char *)bs->data, bs->length);
			break;
		default:
			lua_pushnil(L);
			break;
		}
		lua_seti(L, -2, i + 1);
	}

	lua_pushinteger(L, index);
	return 2;
}

static int xr_getAttributeTypes(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);

	int buf_len = 80;
	char * buf = 0;
	char * err = 0;
	int attr_count =  X509_REQ_get_attr_count(csr);

	buf = malloc(buf_len);

	lua_createtable(L, attr_count, 0);
	int table = lua_gettop(L);

	for (int i = 0; i < attr_count; i++) {
		X509_ATTRIBUTE *a;
		ASN1_BIT_STRING *bs = NULL;
		ASN1_OBJECT *aobj;
		int name_len, val_count = 1;

		a = X509_REQ_get_attr(csr, i);
		aobj = X509_ATTRIBUTE_get0_object(a);

		name_len = OBJ_obj2txt(buf, buf_len, aobj, 0);
		if(name_len <= 0) continue;
		if(name_len >= buf_len) {
			buf_len = name_len;
			buf = realloc(buf, buf_len);
			OBJ_obj2txt(buf, buf_len, aobj, 0);
		}
		lua_pushnumber(L, i + 1);
		lua_pushlstring(L, buf, name_len);
		lua_settable(L, table);
	}
	if(buf) free(buf);
	return 1;

  failed:
	if(buf) free(buf);
	return luaL_error(L, "%s", err);
}

static int xr_addAttribute(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	const char *attr_name = luaL_checkstring(L, 2);
	int num_values;
	unsigned long val_type = luaL_optinteger(L, 4, MBSTRING_ASC);

	lua_len(L, 3);
	num_values = lua_tointeger(L, -1);

	int nid = OBJ_txt2nid(attr_name);
	if(nid==0) return 0;

	X509_ATTRIBUTE *attr =  X509_ATTRIBUTE_new();
	if(!attr)
		return luaL_error(L, "X509_ATTRIBUTE_new failed");

	if(!X509_ATTRIBUTE_set1_object(attr, OBJ_txt2obj(attr_name, 0)))
		return luaL_error(L, "X509_ATTRIBUTE_set1_object failed");

	for(int i = 1; i <= num_values; i++) {
		lua_geti(L, 3, i);
		size_t data_len = 0;
		char *data = lua_tolstring(L, -1, &data_len);
		if(! X509_ATTRIBUTE_set1_data(attr, val_type, data,  data_len))
			return luaL_error(L, "X509_ATTRIBUTE_set1_data failed");
	}

	if(! X509_REQ_add1_attr(csr, attr))
		return luaL_error(L, "X509_REQ_add1_attr failed");

	lua_pushboolean(L, 1);
	return 1;
}

static int xr_deleteAttribute(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	int index = luaL_checkinteger(L, 2);

	lua_pushboolean(L, !! X509_REQ_delete_attr(csr, index));
	return 1;
}


static int xr_setSubjectAlt(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	GENERAL_NAMES *gens = checksimple(L, 2, X509_GENS_CLASS);

	if (xr_modifyRequestedExtension(csr, NID_subject_alt_name, 0, gens, X509V3_ADD_REPLACE))
		return auxL_error(L, auxL_EOPENSSL, "x509.csr:setSubjectAlt");

	lua_pushboolean(L, 1);
	return 1;
} /* xr_setSubjectAlt */


static int xr_getSubjectAlt(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	STACK_OF(X509_EXTENSION) *exts;
	GENERAL_NAMES *gens;

	exts = X509_REQ_get_extensions(csr);
	gens = X509V3_get_d2i(exts, NID_subject_alt_name, NULL, NULL);
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	if (!gens) goto error;

	gn_dup(L, gens);

	return 1;
error:
	return 0;
} /* xr_getSubjectAlt() */


static int xr_addRequestedExtension(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	X509_EXTENSION *ext = checksimple(L, 2, X509_EXT_CLASS);
	int nid, crit;
	void *value;

	nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));
	crit = X509_EXTENSION_get_critical(ext);
	value = X509_EXTENSION_get_data(ext);

	if (xr_modifyRequestedExtension(csr, nid, crit, value, X509V3_ADD_APPEND))
		return auxL_error(L, auxL_EOPENSSL, "x509.csr:addRequestedExtension");

	lua_pushboolean(L, 1);
	return 1;
} /* xr_addRequestedExtension() */


static int xr_setRequestedExtension(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	X509_EXTENSION *ext = checksimple(L, 2, X509_EXT_CLASS);
	int nid, crit;
	void *value;

	nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));
	crit = X509_EXTENSION_get_critical(ext);
	value = X509_EXTENSION_get_data(ext);

	if (xr_modifyRequestedExtension(csr, nid, crit, value, X509V3_ADD_REPLACE))
		return auxL_error(L, auxL_EOPENSSL, "x509.csr:setRequestedExtension");

	lua_pushboolean(L, 1);
	return 1;
} /* xr_setRequestedExtension() */


static int xr_getRequestedExtension(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	STACK_OF(X509_EXTENSION) *exts = NULL;
	X509_EXTENSION *ext = NULL, **ud;
	int i;

	luaL_checkany(L, 2);

	ud = prepsimple(L, X509_EXT_CLASS);

	if (lua_type(L, 2) == LUA_TNUMBER) {
		/* NB: Lua 1-based indexing */
		i = auxL_checkinteger(L, 2, 1, INT_MAX) - 1;
		exts = X509_REQ_get_extensions(csr);
	} else {
		ASN1_OBJECT *obj;

		if (!auxS_txt2obj(&obj, luaL_checkstring(L, 2))) {
			goto error;
		} else if (!obj) {
			goto undef;
		}

		exts = X509_REQ_get_extensions(csr);
		i = X509v3_get_ext_by_OBJ(exts, obj, -1);

		ASN1_OBJECT_free(obj);
	}

	if (i < 0 || !(ext = X509v3_get_ext(exts, i)))
		goto undef;

	if (!(*ud = X509_EXTENSION_dup(ext)))
		goto error;

	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	exts = NULL;

	return 1;
undef:
	if (exts)
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	return 0;
error:
	if (exts)
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	return auxL_error(L, auxL_EOPENSSL, "x509.csr:getRequestedExtension");
} /* xr_getRequestedExtension() */


static int xr_getRequestedExtensionCount(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	STACK_OF(X509_EXTENSION) *exts = NULL;
	auxL_Integer len = 0;

	exts = X509_REQ_get_extensions(csr);
	len = sk_X509_EXTENSION_num(exts);
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

	auxL_pushinteger(L, len);

	return 1;
} /* xr_getRequestedExtensionCount() */


static int xr_sign(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	EVP_PKEY *key = checksimple(L, 2, PKEY_CLASS);

	if (!X509_REQ_sign(csr, key, auxL_optdigest(L, 3, key, NULL)))
		return auxL_error(L, auxL_EOPENSSL, "x509.csr:sign");

	lua_pushboolean(L, 1);

	return 1;
} /* xr_sign() */


static int xr_toPEM(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	BIO *bio = getbio(L);
	size_t len;
	char *bytes;

	if (!PEM_write_bio_X509_REQ(bio, csr))
		return auxL_error(L, auxL_EOPENSSL, "x509.csr:toPEM");

	len = BIO_get_mem_data(bio, &bytes);
	lua_pushlstring(L, bytes, len);

	return 1;
} /* xr_toPEM() */


static int xr__tostring(lua_State *L) {
	X509_REQ *csr = checksimple(L, 1, X509_CSR_CLASS);
	int type = optencoding(L, 2, "pem", X509_PEM|X509_DER);
	BIO *bio = getbio(L);
	char *data;
	long len;

	switch (type) {
	case X509_PEM:
		if (!PEM_write_bio_X509_REQ(bio, csr))
			return auxL_error(L, auxL_EOPENSSL, "x509.csr:__tostring");
		break;
	case X509_DER:
		if (!i2d_X509_REQ_bio(bio, csr))
			return auxL_error(L, auxL_EOPENSSL, "x509.csr:__tostring");
		break;
	} /* switch() */

	len = BIO_get_mem_data(bio, &data);

	lua_pushlstring(L, data, len);

	return 1;
} /* xr__tostring() */


static int xr__gc(lua_State *L) {
	X509_REQ **ud = luaL_checkudata(L, 1, X509_CSR_CLASS);

	if (*ud) {
		X509_REQ_free(*ud);
		*ud = NULL;
	}

	return 0;
} /* xr__gc() */

static const auxL_Reg xr_methods[] = {
	{ "getVersion",   &xr_getVersion },
	{ "setVersion",   &xr_setVersion },
	{ "getSubject",   &xr_getSubject },
	{ "setSubject",   &xr_setSubject },
	{ "getPublicKey", &xr_getPublicKey },
	{ "setPublicKey", &xr_setPublicKey },
	{ "getAttributeTypes", &xr_getAttributeTypes },
	{ "getAttribute", &xr_getAttribute },
	{ "addAttribute", &xr_addAttribute },
	{ "deleteAttribute", &xr_deleteAttribute },
	{ "getSubjectAlt", &xr_getSubjectAlt },
	{ "setSubjectAlt", &xr_setSubjectAlt },
	{ "getRequestedExtension", &xr_getRequestedExtension },
	{ "getRequestedExtensionCount", &xr_getRequestedExtensionCount },
	{ "addRequestedExtension", &xr_addRequestedExtension },
	{ "setRequestedExtension", &xr_setRequestedExtension },
	{ "sign",         &xr_sign },
	{ "toPEM",        &xr_toPEM },
	{ "tostring",     &xr__tostring },
	{ NULL,           NULL },
};

static const auxL_Reg xr_metatable[] = {
	{ "__tostring", &xr__tostring },
	{ "__gc",       &xr__gc },
	{ NULL,         NULL },
};


static const auxL_Reg xr_globals[] = {
	{ "new",       &xr_new },
	{ "interpose", &xr_interpose },
	{ NULL,        NULL },
};

EXPORT int luaopen__openssl_x509_csr(lua_State *L) {
	initall(L);

	auxL_newlib(L, xr_globals, 0);

	return 1;
} /* luaopen__openssl_x509_csr() */


/*
 * X509_CRL - openssl.x509.crl
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int xx_new(lua_State *L) {
	const char *data;
	size_t len;
	X509_CRL **ud;

	lua_settop(L, 2);

	ud = prepsimple(L, X509_CRL_CLASS);

	if ((data = luaL_optlstring(L, 1, NULL, &len))) {
		int type = optencoding(L, 2, "*", X509_ANY|X509_PEM|X509_DER);
		BIO *tmp;
		int ok = 0;

		if (!(tmp = BIO_new_mem_buf((char *)data, len)))
			return auxL_error(L, auxL_EOPENSSL, "x509.crl.new");

		if (type == X509_PEM || type == X509_ANY) {
			ok = !!(*ud = PEM_read_bio_X509_CRL(tmp, NULL, 0, "")); /* no password */
		}

		if (!ok && (type == X509_DER || type == X509_ANY)) {
			BIO_reset(tmp);
			ok = !!(*ud = d2i_X509_CRL_bio(tmp, NULL));
		}

		BIO_free(tmp);

		if (!ok)
			return auxL_error(L, auxL_EOPENSSL, "x509.crl.new");
	} else {
		ASN1_TIME *tm;

		if (!(*ud = X509_CRL_new()))
			return auxL_error(L, auxL_EOPENSSL, "x509.crl.new");

		/* initialize last updated time to now */
		if (!(tm = ASN1_TIME_set(NULL, time(NULL))))
			return auxL_error(L, auxL_EOPENSSL, "x509.crl.new");

		if (!X509_CRL_set1_lastUpdate(*ud, tm)) {
			ASN1_TIME_free(tm);
			return auxL_error(L, auxL_EOPENSSL, "x509.crl.new");
		}

		ASN1_TIME_free(tm);
	}

	return 1;
} /* xx_new() */


static int xx_interpose(lua_State *L) {
	return interpose(L, X509_CRL_CLASS);
} /* xx_interpose() */


static int xx_getVersion(lua_State *L) {
	X509_CRL *crl = checksimple(L, 1, X509_CRL_CLASS);

	lua_pushinteger(L, X509_CRL_get_version(crl) + 1);

	return 1;
} /* xx_getVersion() */


static int xx_setVersion(lua_State *L) {
	X509_CRL *crl = checksimple(L, 1, X509_CRL_CLASS);
	int version = luaL_checkinteger(L, 2);

	if (!X509_CRL_set_version(crl, version - 1))
		return luaL_error(L, "x509.crl:setVersion: %d: invalid version", version);

	lua_pushboolean(L, 1);

	return 1;
} /* xx_setVersion() */


static int xx_getLastUpdate(lua_State *L) {
	X509_CRL *crl = checksimple(L, 1, X509_CRL_CLASS);
	double updated = INFINITY;
	const ASN1_TIME *time;

	if ((time = X509_CRL_get0_lastUpdate(crl)))
		updated = timeutc(time);

	if (isfinite(updated))
		lua_pushnumber(L, updated);
	else
		lua_pushnil(L);

	return 1;
} /* xx_getLastUpdate() */


static int xx_setLastUpdate(lua_State *L) {
	X509_CRL *crl = checksimple(L, 1, X509_CRL_CLASS);
	double updated = luaL_checknumber(L, 2);
	ASN1_TIME *time;

	if (!(time = ASN1_TIME_set(NULL, updated)))
		goto error;

	if (!X509_CRL_set1_lastUpdate(crl, time))
		goto error;

	lua_pushboolean(L, 1);

	return 1;
error:
	ASN1_TIME_free(time);

	return auxL_error(L, auxL_EOPENSSL, "x509.crl:setLastUpdate");
} /* xx_setLastUpdate() */


static int xx_getNextUpdate(lua_State *L) {
	X509_CRL *crl = checksimple(L, 1, X509_CRL_CLASS);
	double updateby = INFINITY;
	const ASN1_TIME *time;

	if ((time = X509_CRL_get0_nextUpdate(crl)))
		updateby = timeutc(time);

	if (isfinite(updateby))
		lua_pushnumber(L, updateby);
	else
		lua_pushnil(L);

	return 1;
} /* xx_getNextUpdate() */


static int xx_setNextUpdate(lua_State *L) {
	X509_CRL *crl = checksimple(L, 1, X509_CRL_CLASS);
	double updateby = luaL_checknumber(L, 2);
	ASN1_TIME *time;

	if (!(time = ASN1_TIME_set(NULL, updateby)))
		goto error;

	if (!X509_CRL_set1_nextUpdate(crl, time))
		goto error;

	lua_pushboolean(L, 1);

	return 1;
error:
	ASN1_TIME_free(time);

	return auxL_error(L, auxL_EOPENSSL, "x509.crl:setNextUpdate");
} /* xx_setNextUpdate() */


static int xx_getIssuer(lua_State *L) {
	X509_CRL *crl = checksimple(L, 1, X509_CRL_CLASS);
	X509_NAME *name;

	if (!(name = X509_CRL_get_issuer(crl)))
		return 0;

	xn_dup(L, name);

	return 1;
} /* xx_getIssuer() */


static int xx_setIssuer(lua_State *L) {
	X509_CRL *crl = checksimple(L, 1, X509_CRL_CLASS);
	X509_NAME *name = checksimple(L, 2, X509_NAME_CLASS);

	if (!X509_CRL_set_issuer_name(crl, name))
		return auxL_error(L, auxL_EOPENSSL, "x509.crl:setIssuer");

	lua_pushboolean(L, 1);

	return 1;
} /* xx_setIssuer() */


static int xx_add(lua_State *L) {
	X509_CRL *crl = checksimple(L, 1, X509_CRL_CLASS);
	BIGNUM *bn = checkbig(L, 2);
	double ut = luaL_optnumber(L, 3, time(NULL));
	X509_REVOKED *rev = NULL;
	ASN1_INTEGER *serial = NULL;
	ASN1_TIME *date = NULL;

	if (!(rev = X509_REVOKED_new()))
		goto error;

	if (!(serial = BN_to_ASN1_INTEGER(bn, NULL)))
		goto error;

	if (!X509_REVOKED_set_serialNumber(rev, serial)) /* duplicates serial */
		goto error;

	ASN1_INTEGER_free(serial);
	serial = NULL;

	if (!(date = ASN1_TIME_new()))
		goto error;

	if (!ASN1_TIME_set(date, ut))
		goto error;

	if (!X509_REVOKED_set_revocationDate(rev, date)) /* duplicates date */
		goto error;

	ASN1_TIME_free(date);
	date = NULL;

	if (!X509_CRL_add0_revoked(crl, rev)) /* takes ownership of rev */
		goto error;

	lua_pushboolean(L, 1);

	return 1;
error:
	if (date)
		ASN1_TIME_free(date);
	if (serial)
		ASN1_INTEGER_free(serial);
	if (rev)
		X509_REVOKED_free(rev);

	return auxL_error(L, auxL_EOPENSSL, "x509.crl:add");
} /* xx_add() */


#if HAVE_X509_CRL_GET0_BY_SERIAL
static int xx_lookupSerial(lua_State *L) {
	X509_CRL *crl = checksimple(L, 1, X509_CRL_CLASS);
	ASN1_INTEGER *serial;
	int status;

	if (!(serial = BN_to_ASN1_INTEGER(checkbig(L, 2), NULL)))
		return auxL_error(L, auxL_EOPENSSL, "x509.crl:lookupSerial");

	status = X509_CRL_get0_by_serial(crl, NULL, serial);

	ASN1_INTEGER_free(serial);

	switch(status) {
	case 0: /* failure (not on CRL) */
		lua_pushnil(L);
		return 1;
	case 1: /* succeeds (on CRL) */
		lua_pushboolean(L, 1);
		return 1;
	case 2: /* *was* on CRL, but not any more */
		lua_pushboolean(L, 0);
		return 1;
	default:
		return luaL_error(L, "x509.crl:lookupSerial: unexpected return value");
	}
} /* xx_lookupSerial() */
#endif


#if HAVE_X509_CRL_GET0_BY_CERT
static int xx_lookupCertificate(lua_State *L) {
	X509_CRL *crl = checksimple(L, 1, X509_CRL_CLASS);
	X509 *crt = checksimple(L, 2, X509_CERT_CLASS);

	switch(X509_CRL_get0_by_cert(crl, NULL, crt)) {
	case 0: /* failure (not on CRL) */
		lua_pushnil(L);
		return 1;
	case 1: /* succeeds (on CRL) */
		lua_pushboolean(L, 1);
		return 1;
	case 2: /* *was* on CRL, but not any more */
		lua_pushboolean(L, 0);
		return 1;
	default:
		return luaL_error(L, "x509.crl:lookupCertificate: unexpected return value");
	}
} /* xx_lookupCertificate() */
#endif


static int xx_addExtension(lua_State *L) {
	X509_CRL *crl = checksimple(L, 1, X509_CRL_CLASS);
	X509_EXTENSION *ext = checksimple(L, 2, X509_EXT_CLASS);

	/* NOTE: Will dup extension in X509v3_add_ext. */
	if (!X509_CRL_add_ext(crl, ext, -1))
		return auxL_error(L, auxL_EOPENSSL, "x509.crl:addExtension");

	lua_pushboolean(L, 1);

	return 1;
} /* xx_addExtension() */


static int xx_setExtension(lua_State *L) {
	X509_CRL *crl = checksimple(L, 1, X509_CRL_CLASS);
	X509_EXTENSION *ext = checksimple(L, 2, X509_EXT_CLASS);
	int nid, crit;
	void *value;

	nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));
	crit = X509_EXTENSION_get_critical(ext);
	value = X509_EXTENSION_get_data(ext);

	if (!X509_CRL_add1_ext_i2d(crl, nid, value, crit, X509V3_ADD_REPLACE))
		return auxL_error(L, auxL_EOPENSSL, "x509.crl:setExtension");

	lua_pushboolean(L, 1);

	return 1;
} /* xx_setExtension() */


static int xx_getExtension(lua_State *L) {
	X509_CRL *crl = checksimple(L, 1, X509_CRL_CLASS);
	X509_EXTENSION *ext = NULL, **ud;
	int i;

	luaL_checkany(L, 2);

	if (lua_type(L, 2) == LUA_TNUMBER) {
		/* NB: Lua 1-based indexing */
		i = auxL_checkinteger(L, 2, 1, INT_MAX) - 1;
	} else {
		ASN1_OBJECT *obj;

		if (!auxS_txt2obj(&obj, luaL_checkstring(L, 2))) {
			goto error;
		} else if (!obj) {
			goto undef;
		}

		i = X509_CRL_get_ext_by_OBJ(crl, obj, -1);

		ASN1_OBJECT_free(obj);
	}

	ud = prepsimple(L, X509_EXT_CLASS);

	if (i < 0 || !(ext = X509_CRL_get0_ext(crl, i)))
		goto undef;

	if (!(*ud = X509_EXTENSION_dup(ext)))
		goto error;

	return 1;
undef:
	return 0;
error:
	return auxL_error(L, auxL_EOPENSSL, "x509.crl:getExtension");
} /* xx_getExtension() */


static int xx_getExtensionCount(lua_State *L) {
	auxL_pushinteger(L, X509_CRL_get_ext_count(checksimple(L, 1, X509_CRL_CLASS)));

	return 1;
} /* xx_getExtensionCount() */


static int xx_sign(lua_State *L) {
	X509_CRL *crl = checksimple(L, 1, X509_CRL_CLASS);
	EVP_PKEY *key = checksimple(L, 2, PKEY_CLASS);

	if (!X509_CRL_sign(crl, key, auxL_optdigest(L, 3, key, NULL)))
		return auxL_error(L, auxL_EOPENSSL, "x509.crl:sign");

	lua_pushboolean(L, 1);

	return 1;
} /* xx_sign() */


static int xx_verify(lua_State *L) {
	X509_CRL *crl = checksimple(L, 1, X509_CRL_CLASS);
	EVP_PKEY *key = checksimple(L, 2, PKEY_CLASS);

	if (!X509_CRL_verify(crl, key))
		return auxL_error(L, auxL_EOPENSSL, "x509.crl:verify");

	lua_pushboolean(L, 1);

	return 1;
} /* xx_verify() */


static int xx_text(lua_State *L) {
	X509_CRL *crl = checksimple(L, 1, X509_CRL_CLASS);

	BIO *bio = getbio(L);
	char *data;
	long len;

	if (!X509_CRL_print(bio, crl))
		return auxL_error(L, auxL_EOPENSSL, "x509.crl:text");

	len = BIO_get_mem_data(bio, &data);

	lua_pushlstring(L, data, len);

	return 1;
} /* xx_text() */


static int xx_toPEM(lua_State *L) {
	X509_CRL *crl = checksimple(L, 1, X509_CRL_CLASS);
	BIO *bio = getbio(L);
	size_t len;
	char *bytes;

	if (!PEM_write_bio_X509_CRL(bio, crl))
		return auxL_error(L, auxL_EOPENSSL, "x509.crl:toPEM");

	len = BIO_get_mem_data(bio, &bytes);
	lua_pushlstring(L, bytes, len);

	return 1;
} /* xx_toPEM() */


static int xx__tostring(lua_State *L) {
	X509_CRL *crl = checksimple(L, 1, X509_CRL_CLASS);
	int type = optencoding(L, 2, "pem", X509_PEM|X509_DER);
	BIO *bio = getbio(L);
	char *data;
	long len;

	switch (type) {
	case X509_PEM:
		if (!PEM_write_bio_X509_CRL(bio, crl))
			return auxL_error(L, auxL_EOPENSSL, "x509.crl:__tostring");
		break;
	case X509_DER:
		if (!i2d_X509_CRL_bio(bio, crl))
			return auxL_error(L, auxL_EOPENSSL, "x509.crl:__tostring");
		break;
	} /* switch() */

	len = BIO_get_mem_data(bio, &data);

	lua_pushlstring(L, data, len);

	return 1;
} /* xx__tostring() */


static int xx__gc(lua_State *L) {
	X509_CRL **ud = luaL_checkudata(L, 1, X509_CRL_CLASS);

	if (*ud) {
		X509_CRL_free(*ud);
		*ud = NULL;
	}

	return 0;
} /* xx__gc() */

static const auxL_Reg xx_methods[] = {
	{ "getVersion",     &xx_getVersion },
	{ "setVersion",     &xx_setVersion },
	{ "getLastUpdate",  &xx_getLastUpdate },
	{ "setLastUpdate",  &xx_setLastUpdate },
	{ "getNextUpdate",  &xx_getNextUpdate },
	{ "setNextUpdate",  &xx_setNextUpdate },
	{ "getIssuer",      &xx_getIssuer },
	{ "setIssuer",      &xx_setIssuer },
	{ "add",            &xx_add },
#if HAVE_X509_CRL_GET0_BY_SERIAL
	{ "lookupSerial",   &xx_lookupSerial },
#endif
#if HAVE_X509_CRL_GET0_BY_CERT
	{ "lookupCertificate", &xx_lookupCertificate },
#endif
	{ "addExtension",   &xx_addExtension },
	{ "setExtension",   &xx_setExtension },
	{ "getExtension",   &xx_getExtension },
	{ "getExtensionCount", &xx_getExtensionCount },
	{ "sign",           &xx_sign },
	{ "verify",         &xx_verify },
	{ "text",           &xx_text },
	{ "toPEM",          &xx_toPEM },
	{ "tostring",       &xx__tostring },
	{ NULL,             NULL },
};

static const auxL_Reg xx_metatable[] = {
	{ "__tostring", &xx__tostring },
	{ "__gc",       &xx__gc },
	{ NULL,         NULL },
};


static const auxL_Reg xx_globals[] = {
	{ "new",       &xx_new },
	{ "interpose", &xx_interpose },
	{ NULL,        NULL },
};

EXPORT int luaopen__openssl_x509_crl(lua_State *L) {
	initall(L);

	auxL_newlib(L, xx_globals, 0);

	return 1;
} /* luaopen__openssl_x509_crl() */


/*
 * STACK_OF(X509) - openssl.x509.chain
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static void xl_dup(lua_State *L, STACK_OF(X509) *src, _Bool copy) {
	STACK_OF(X509) **dst = prepsimple(L, X509_CHAIN_CLASS);

	if (copy) {
		int i, n;

		if (!(*dst = sk_X509_new_null()))
			goto error;

		n = sk_X509_num(src);

		for (i = 0; i < n; i++) {
			X509 *crt;

			if (!(crt = sk_X509_value(src, i)))
				continue;

			if (!(crt = X509_dup(crt)))
				goto error;

			if (!sk_X509_push(*dst, crt)) {
				X509_free(crt);
				goto error;
			}
		}
	} else {
		if (!(*dst = X509_chain_up_ref(src)))
			goto error;
	}

	return;
error:
	auxL_error(L, auxL_EOPENSSL, "xl_dup");
} /* xl_dup() */


static int xl_new(lua_State *L) {
	STACK_OF(X509) **chain = prepsimple(L, X509_CHAIN_CLASS);

	if (!(*chain = sk_X509_new_null()))
		return auxL_error(L, auxL_EOPENSSL, "x509.chain.new");

	return 1;
} /* xl_new() */


static int xl_interpose(lua_State *L) {
	return interpose(L, X509_CHAIN_CLASS);
} /* xl_interpose() */


static int xl_add(lua_State *L) {
	STACK_OF(X509) *chain = checksimple(L, 1, X509_CHAIN_CLASS);
	X509 *crt = checksimple(L, 2, X509_CERT_CLASS);
	X509 *dup;

	if (!(dup = X509_dup(crt)))
		return auxL_error(L, auxL_EOPENSSL, "x509.chain:add");

	if (!sk_X509_push(chain, dup)) {
		X509_free(dup);
		return auxL_error(L, auxL_EOPENSSL, "x509.chain:add");
	}

	lua_pushvalue(L, 1);

	return 1;
} /* xl_add() */


static int xl__next(lua_State *L) {
	STACK_OF(X509) *chain = checksimple(L, lua_upvalueindex(1), X509_CHAIN_CLASS);
	int i = lua_tointeger(L, lua_upvalueindex(2));
	int n = sk_X509_num(chain);

	lua_settop(L, 0);

	while (i < n) {
		X509 *crt, **ret;

		if (!(crt = sk_X509_value(chain, i++)))
			continue;

		lua_pushinteger(L, i);

		xc_dup(L, crt);

		break;
	}

	lua_pushinteger(L, i);
	lua_replace(L, lua_upvalueindex(2));

	return lua_gettop(L);
} /* xl__next() */

static int xl__pairs(lua_State *L) {
	lua_settop(L, 1);
	lua_pushinteger(L, 0);
	lua_pushcclosure(L, &xl__next, 2);

	return 1;
} /* xl__pairs() */


static int xl__gc(lua_State *L) {
	STACK_OF(X509) **chain = luaL_checkudata(L, 1, X509_CHAIN_CLASS);

	if (*chain) {
		sk_X509_pop_free(*chain, X509_free);
		*chain = NULL;
	}

	return 0;
} /* xl__gc() */


static const auxL_Reg xl_methods[] = {
	{ "add", &xl_add },
	{ NULL,  NULL },
};

static const auxL_Reg xl_metatable[] = {
	{ "__pairs",  &xl__pairs },
	{ "__ipairs", &xl__pairs },
	{ "__gc",     &xl__gc },
	{ NULL,       NULL },
};

static const auxL_Reg xl_globals[] = {
	{ "new",       &xl_new },
	{ "interpose", &xl_interpose },
	{ NULL,        NULL },
};

EXPORT int luaopen__openssl_x509_chain(lua_State *L) {
	initall(L);

	auxL_newlib(L, xl_globals, 0);

	return 1;
} /* luaopen__openssl_x509_chain() */


/*
 * X509_STORE - openssl.x509.store
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int xs_new(lua_State *L) {
	X509_STORE **ud = prepsimple(L, X509_STORE_CLASS);

	if (!(*ud = X509_STORE_new()))
		return auxL_error(L, auxL_EOPENSSL, "x509.store");

	return 1;
} /* xs_new() */


static X509_STORE *xs_push(lua_State *L, X509_STORE *store) {
	X509_STORE **ud = prepsimple(L, X509_STORE_CLASS);

	X509_STORE_up_ref(store);
	*ud = store;

	return *ud;
} /* xs_push() */


static int xs_interpose(lua_State *L) {
	return interpose(L, X509_STORE_CLASS);
} /* xs_interpose() */


static int xs_add(lua_State *L) {
	X509_STORE *store = checksimple(L, 1, X509_STORE_CLASS);
	int i, top = lua_gettop(L);
	X509 *crt, *crt_dup;
	X509_CRL *crl, *crl_dup;

	for (i = 2; i <= top; i++) {
		if ((crt = testsimple(L, i, X509_CERT_CLASS))) {
			if (!(crt_dup = X509_dup(crt)))
				return auxL_error(L, auxL_EOPENSSL, "x509.store:add");

			if (!X509_STORE_add_cert(store, crt_dup)) {
				X509_free(crt_dup);
				return auxL_error(L, auxL_EOPENSSL, "x509.store:add");
			}
		} else if ((crl = testsimple(L, i, X509_CRL_CLASS))) {
			if (!(crl_dup = X509_CRL_dup(crl)))
				return auxL_error(L, auxL_EOPENSSL, "x509.store:add");

			if (!X509_STORE_add_crl(store, crl_dup)) {
				X509_CRL_free(crl_dup);
				return auxL_error(L, auxL_EOPENSSL, "x509.store:add");
			}
		} else {
			const char *path = luaL_checkstring(L, i);
			struct stat st;
			int ok;

			if (0 != stat(path, &st))
				return luaL_error(L, "%s: %s", path, aux_strerror(errno));

			if (S_ISDIR(st.st_mode))
				ok = X509_STORE_load_locations(store, NULL, path);
			else {
				/* X509_STORE_load_locations on a file returns 0 if no certs were found */
				ERR_clear_error();
				ok = X509_STORE_load_locations(store, path, NULL);
				if (ok == 0 && !ERR_peek_error())
					ok = 1;
			}

			if (!ok)
				return auxL_error(L, auxL_EOPENSSL, "x509.store:add");
		}
	}

	lua_pushvalue(L, 1);

	return 1;
} /* xs_add() */


static int xs_addDefaults(lua_State *L) {
	X509_STORE *store = checksimple(L, 1, X509_STORE_CLASS);

	if (!X509_STORE_set_default_paths(store))
		return auxL_error(L, auxL_EOPENSSL, "x509.store:addDefaults");

	lua_pushvalue(L, 1);

	return 1;
} /* xs_addDefaults() */


static int xs_verify(lua_State *L) {
	X509_STORE *store = checksimple(L, 1, X509_STORE_CLASS);
	X509 *crt = checksimple(L, 2, X509_CERT_CLASS);
	STACK_OF(X509) *chain = NULL, **proof;
	X509_STORE_CTX *ctx = NULL;
	int ok, why;

	/* pre-allocate space for a successful return */
	lua_settop(L, 3);
	proof = prepsimple(L, X509_CHAIN_CLASS);

	if (!lua_isnoneornil(L, 3)) {
		if (!(chain = X509_chain_up_ref(checksimple(L, 3, X509_CHAIN_CLASS))))
			goto eossl;
	}

	if (!(ctx = X509_STORE_CTX_new()) || !X509_STORE_CTX_init(ctx, store, crt, chain)) {
		sk_X509_pop_free(chain, X509_free);
		goto eossl;
	}

	ERR_clear_error();

	ok = X509_verify_cert(ctx);

	switch (ok) {
	case 1: /* verified */
		if (!(*proof = X509_STORE_CTX_get1_chain(ctx)))
			goto eossl;
		X509_STORE_CTX_free(ctx);

		lua_pushboolean(L, 1);
		lua_pushvalue(L, -2);

		return 2;
	case 0: /* not verified */
		why = X509_STORE_CTX_get_error(ctx);
		X509_STORE_CTX_free(ctx);

		lua_pushboolean(L, 0);
		lua_pushstring(L, X509_verify_cert_error_string(why));

		return 2;
	default:
		goto eossl;
	}

eossl:
	if (ctx)
		X509_STORE_CTX_free(ctx);

	return auxL_error(L, auxL_EOPENSSL, "x509.store:verify");
} /* xs_verify() */


static int xs__gc(lua_State *L) {
	X509_STORE **ud = luaL_checkudata(L, 1, X509_STORE_CLASS);

	if (*ud) {
		X509_STORE_free(*ud);
		*ud = NULL;
	}

	return 0;
} /* xs__gc() */


static const auxL_Reg xs_methods[] = {
	{ "add",         &xs_add },
	{ "addDefaults", &xs_addDefaults },
	{ "verify",      &xs_verify },
	{ NULL,          NULL },
};

static const auxL_Reg xs_metatable[] = {
	{ "__gc", &xs__gc },
	{ NULL,   NULL },
};

static const auxL_Reg xs_globals[] = {
	{ "new",       &xs_new },
	{ "interpose", &xs_interpose },
	{ NULL,        NULL },
};

EXPORT int luaopen__openssl_x509_store(lua_State *L) {
	initall(L);

	auxL_newlib(L, xs_globals, 0);

	lua_pushstring(L, X509_get_default_cert_dir());
	lua_setfield(L, -2, "CERT_DIR");
	lua_pushstring(L, X509_get_default_cert_file());
	lua_setfield(L, -2, "CERT_FILE");
	lua_pushstring(L, X509_get_default_cert_dir_env());
	lua_setfield(L, -2, "CERT_DIR_EVP");
	lua_pushstring(L, X509_get_default_cert_file_env());
	lua_setfield(L, -2, "CERT_FILE_EVP");

	return 1;
} /* luaopen__openssl_x509_store() */


/*
 * X509_STORE_CTX - openssl.x509.store.context
 *
 * This object is intended to be a temporary container in OpenSSL, so the
 * memory management is quite clumsy. In particular, it doesn't take
 * ownership of the X509_STORE object, which means the reference must be
 * held externally for the life of the X509_STORE_CTX object.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
#if 0
static int stx_new(lua_State *L) {
	X509_STORE_CTX **ud = prepsimple(L, X509_STCTX_CLASS);
	STACK_OF(X509) *chain;

	if (!(*ud = X509_STORE_CTX_new()))
		return auxL_error(L, auxL_EOPENSSL, "x509.store.context");

	return 1;
} /* stx_new() */


static int stx_interpose(lua_State *L) {
	return interpose(L, X509_STCTX_CLASS);
} /* stx_interpose() */


static int stx_add(lua_State *L) {
	X509_STORE_CTX *ctx = checksimple(L, 1, X509_STCTX_CLASS);

	return 0;
} /* stx_add() */


static int stx__gc(lua_State *L) {
	X509_STORE **ud = luaL_checkudata(L, 1, X509_STORE_CLASS);

	if (*ud) {
		X509_STORE_free(*ud);
		*ud = NULL;
	}

	return 0;
} /* stx__gc() */


static const auxL_Reg stx_methods[] = {
	{ "add", &stx_add },
	{ NULL,  NULL },
};

static const auxL_Reg stx_metatable[] = {
	{ "__gc", &stx__gc },
	{ NULL,   NULL },
};

static const auxL_Reg stx_globals[] = {
	{ "new",       &stx_new },
	{ "interpose", &stx_interpose },
	{ NULL,        NULL },
};

EXPORT int luaopen__openssl_x509_store_context(lua_State *L) {
	initall(L);

	auxL_newlib(L, stx_globals, 0);

	return 1;
} /* luaopen__openssl_x509_store_context() */
#endif


/*
 * PKCS12 - openssl.pkcs12
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int p12_new(lua_State *L) {
	char *pass = NULL;
	loadfield(L, 1, "password", LUA_TSTRING, &pass);

	EVP_PKEY *key = loadfield_udata(L, 1, "key", PKEY_CLASS);
	STACK_OF(X509) *certs = loadfield_udata(L, 1, "certs", X509_CHAIN_CLASS);

	PKCS12 **ud = prepsimple(L, PKCS12_CLASS);

	int i;
	int no_kcert = 0;
	X509 *cert = NULL;
	X509 *kcert = NULL;
	STACK_OF(X509) *ca;

	if (!(ca = sk_X509_new_null()))
		goto error;

	for (i = 0; i < sk_X509_num(certs); i++) {
		cert = sk_X509_value(certs, i);
		if (key && X509_check_private_key(cert, key)) {
			if (!(kcert = X509_dup(cert)))
				goto error;
			X509_keyid_set1(kcert, NULL, 0);
			X509_alias_set1(kcert, NULL, 0);
		}
		else sk_X509_push(ca, cert);
	}
	if (key && !kcert) {
		no_kcert = 1;
		goto error;
	}

	if (!(*ud = PKCS12_create(pass, NULL, key, kcert, ca, 0, 0, 0, 0, 0)))
		goto error;

	if (kcert)
		X509_free(kcert);
	sk_X509_free(ca);

	return 1;

error:
	if (kcert)
		X509_free(kcert);
	if (ca)
		sk_X509_free(ca);

	if (no_kcert)
		luaL_argerror(L, 1, lua_pushfstring(L, "certificate matching the key not found"));

	return auxL_error(L, auxL_EOPENSSL, "pkcs12.new");
} /* p12_new() */


static int p12_interpose(lua_State *L) {
	return interpose(L, PKCS12_CLASS);
} /* p12_interpose() */


static int p12_parse(lua_State *L) {
	/* parse a p12 binary string and return the parts */
	PKCS12 *p12;

	/* gather input parameters */
	size_t len;
	const char *blob = luaL_checklstring(L, 1, &len);
	const char *passphrase = luaL_optstring(L, 2, NULL);

	/* prepare return values */
	EVP_PKEY **ud_pkey = prepsimple(L, PKEY_CLASS);
	X509 **ud_cert = prepsimple(L, X509_CERT_CLASS);
	STACK_OF(X509) **ud_chain = prepsimple(L, X509_CHAIN_CLASS);
	/* Note: *ud_chain must be initialised to NULL, which prepsimple does. */

	/* read PKCS#12 data into OpenSSL memory buffer */
	BIO *bio = BIO_new_mem_buf((void*)blob, len);
	if (!bio)
		return auxL_error(L, auxL_EOPENSSL, "pkcs12.parse");
	p12 = d2i_PKCS12_bio(bio, NULL);
	BIO_free(bio);
	if (!p12)
		return auxL_error(L, auxL_EOPENSSL, "pkcs12.parse");

	/* the p12 pointer holds the data we're interested in */
	int rc = PKCS12_parse(p12, passphrase, ud_pkey, ud_cert, ud_chain);
	PKCS12_free(p12);
	if (!rc)
		auxL_error(L, auxL_EOPENSSL, "pkcs12.parse");

	/* replace the return values by nil if the ud pointers are NULL */
	if (*ud_pkey == NULL) {
		lua_pushnil(L);
		lua_replace(L, -4);
	}

	if (*ud_cert == NULL) {
		lua_pushnil(L);
		lua_replace(L, -3);
	}

	/* other certificates (a chain, STACK_OF(X509) *) */
	if (*ud_chain == NULL) {
		lua_pop(L, 1);
		lua_pushnil(L);
	}

	return 3;
} /* p12_parse() */


static int p12__tostring(lua_State *L) {
	PKCS12 *p12 = checksimple(L, 1, PKCS12_CLASS);
	BIO *bio = getbio(L);
	char *data;
	long len;

	if (!i2d_PKCS12_bio(bio, p12))
		return auxL_error(L, auxL_EOPENSSL, "pkcs12:__tostring");

	len = BIO_get_mem_data(bio, &data);

	lua_pushlstring(L, data, len);

	return 1;
} /* p12__tostring() */


static int p12__gc(lua_State *L) {
	PKCS12 **ud = luaL_checkudata(L, 1, PKCS12_CLASS);

	if (*ud) {
		PKCS12_free(*ud);
		*ud = NULL;
	}

	return 0;
} /* p12__gc() */


static const auxL_Reg p12_methods[] = {
	{ "tostring", &p12__tostring },
	{ NULL,         NULL },
};

static const auxL_Reg p12_metatable[] = {
	{ "__tostring", &p12__tostring },
	{ "__gc",       &p12__gc },
	{ NULL,         NULL },
};

static const auxL_Reg p12_globals[] = {
	{ "new",       &p12_new },
	{ "interpose", &p12_interpose },
	{ "parse",     &p12_parse },
	{ NULL,        NULL },
};

EXPORT int luaopen__openssl_pkcs12(lua_State *L) {
	initall(L);

	auxL_newlib(L, p12_globals, 0);

	return 1;
} /* luaopen__openssl_pkcs12() */


/*
 * SSL_CTX - openssl.ssl.context
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static void sx_push(lua_State *L, SSL_CTX *ctx) {
	lua_rawgetp(L, LUA_REGISTRYINDEX, LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(&initall));
	if (LUA_TNIL == lua_rawgetp(L, -1, LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(ctx))) {
		SSL_CTX **ud;

		lua_pop(L, 1); /* pop nil */

		ud = prepsimple(L, SSL_CTX_CLASS);

		SSL_CTX_up_ref(ctx);
		*ud = ctx;

		/* Add to cache */
		lua_pushvalue(L, -1);
		lua_rawsetp(L, -3, LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(ctx));
	}
	lua_remove(L, -2);
} /* sx_push() */


static int sx_pushffi(lua_State *L) {
	SSL_CTX *ptr;

	lua_pushvalue(L, lua_upvalueindex(1));
	lua_pushvalue(L, 1);
	lua_call(L, 1, 1);
	luaL_argcheck(L, lua_toboolean(L, -1), 1, "SSL_CTX* ffi pointer expected");
	lua_pop(L, 1);
	ptr = *(SSL_CTX**)lua_topointer(L, 1);
	luaL_argcheck(L, ptr, 1, "SSL_CTX* pointer must be non-null");

	sx_push(L, ptr);

	return 1;
} /* ssl_pushffi() */


static int sx_new(lua_State *L) {
	static const char *const opts[] = {
		[0] = "SSL",
		[1] = "TLS",
		[2] = "SSLv2",
		[3] = "SSLv3",
		[4] = "SSLv23",
		[5] = "TLSv1", [6] = "TLSv1.0",
		[7] = "TLSv1_1", [8] = "TLSv1.1",
		[9] = "TLSv1_2", [10] = "TLSv1.2",
		[11] = "TLSv1_3", [12] = "TLSv1.3",
		[13] = "DTLS",
		[14] = "DTLSv1", [15] = "DTLSv1.0",
		[16] = "DTLSv1_2", [17] = "DTLSv1.2",
		NULL
	};
	int method_enum;
	_Bool srv;
	SSL_CTX **ud;
	int options = 0;

	lua_settop(L, 2);
	method_enum = auxL_checkoption(L, 1, "TLS", opts, 1);
	srv = lua_toboolean(L, 2);

	switch (method_enum) {
	case 0: /* SSL */
		options = SSL_OP_NO_SSLv2;
		break;
	case 1: /* TLS */
		options = SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3;
		break;
	case 2: /* SSLv2 */
		options = SSL_OP_NO_SSL_MASK & ~SSL_OP_NO_SSLv2;
		break;
	case 3: /* SSLv3 */
		options = SSL_OP_NO_SSL_MASK & ~SSL_OP_NO_SSLv3;
		break;
	case 4: /* SSLv23 */
		break;
	case 5: /* TLSv1 */
	case 6: /* TLSv1.0 */
		options = SSL_OP_NO_SSL_MASK & ~SSL_OP_NO_TLSv1;
		break;
#if defined SSL_OP_NO_TLSv1_1
	case 7: /* TLSv1_1 */
	case 8: /* TLSv1.1 */
		options = SSL_OP_NO_SSL_MASK & ~SSL_OP_NO_TLSv1_1;
		break;
#endif
#if defined SSL_OP_NO_TLSv1_2
	case 9: /* TLSv1_2 */
	case 10: /* TLSv1.2 */
		options = SSL_OP_NO_SSL_MASK & ~SSL_OP_NO_TLSv1_2;
		break;
#endif
#if defined SSL_OP_NO_TLSv1_3
	case 11: /* TLSv1_3 */
	case 12: /* TLSv1.3 */
		options = SSL_OP_NO_SSL_MASK & ~SSL_OP_NO_TLSv1_3;
		break;
#endif
#if HAVE_DTLS_CLIENT_METHOD
	case 13: /* DTLS */
		break;
#ifdef SSL_OP_NO_DTLSv1
	case 14: /* DTLSv1 */
	case 15: /* DTLSv1.0 */
		options = SSL_OP_NO_DTLS_MASK & ~SSL_OP_NO_DTLSv1;
		break;
#endif
#ifdef SSL_OP_NO_DTLSv1_2
	case 16: /* DTLSv1_2 */
	case 17: /* DTLSv1.2 */
		options = SSL_OP_NO_DTLS_MASK & ~SSL_OP_NO_DTLSv1_2;
		break;
#endif
#endif
	default:
		return luaL_argerror(L, 1, "invalid option");
	}

	ud = prepsimple(L, SSL_CTX_CLASS);

	switch (method_enum) {
	case 0: /* SSL */
	case 1: /* TLS */
	case 2: /* SSLv2 */
	case 3: /* SSLv3 */
	case 4: /* SSLv23 */
	case 5: /* TLSv1 */
	case 6: /* TLSv1.0 */
	case 7: /* TLSv1_1 */
	case 8: /* TLSv1.1 */
	case 9: /* TLSv1_2 */
	case 10: /* TLSv1.2 */
	case 11: /* TLSv1_3 */
	case 12: /* TLSv1.3 */
		*ud = SSL_CTX_new(srv?SSLv23_server_method():SSLv23_client_method());
		break;
#if HAVE_DTLS_CLIENT_METHOD
	case 13: /* DTLS */
	case 14: /* DTLSv1 */
	case 15: /* DTLSv1.0 */
	case 16: /* DTLSv1_2 */
	case 17: /* DTLSv1.2 */
		*ud = SSL_CTX_new(srv?DTLS_server_method():DTLS_client_method());
		break;
#endif
	default:
		NOTREACHED;
	}

	if (!*ud)
		return auxL_error(L, auxL_EOPENSSL, "ssl.context.new");

	SSL_CTX_set_options(*ud, options);

#if HAVE_SSL_CTX_SET_ECDH_AUTO
	/* OpenSSL 1.0.2 introduced SSL_CTX_set_ecdh_auto to automatically select
	 * from the curves set via SSL_CTX_set1_curves_list. However as of OpenSSL
	 * 1.1.0, the functionality was turned on permanently and the option
	 * removed. */
	if (!SSL_CTX_set_ecdh_auto(*ud, 1))
		return auxL_error(L, auxL_EOPENSSL, "ssl.context.new");
#endif

	/* Add to cache */
	lua_rawgetp(L, LUA_REGISTRYINDEX, LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(&initall));
	lua_pushvalue(L, -2);
	lua_rawsetp(L, -2, LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(*ud));
	lua_pop(L, 1);

	return 1;
} /* sx_new() */


static int sx_interpose(lua_State *L) {
	return interpose(L, SSL_CTX_CLASS);
} /* sx_interpose() */


static int sx_setOptions(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	auxL_Integer options = auxL_checkinteger(L, 2);

	auxL_pushinteger(L, SSL_CTX_set_options(ctx, options));

	return 1;
} /* sx_setOptions() */


static int sx_getOptions(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);

	auxL_pushinteger(L, SSL_CTX_get_options(ctx));

	return 1;
} /* sx_getOptions() */


static int sx_clearOptions(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	auxL_Integer options = auxL_checkinteger(L, 2);

	auxL_pushinteger(L, SSL_CTX_clear_options(ctx, options));

	return 1;
} /* sx_clearOptions() */


static int sx_setReadAhead(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	int yes = checkbool(L, 2);

	SSL_CTX_set_read_ahead(ctx, yes);

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setReadAhead() */


static int sx_getReadAhead(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);

	lua_pushboolean(L, SSL_CTX_get_read_ahead(ctx));

	return 1;
} /* sx_getReadAhead() */


static int sx_setStore(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	X509_STORE *store = checksimple(L, 2, X509_STORE_CLASS);

	SSL_CTX_set1_cert_store(ctx, store);

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setStore() */


static int sx_getStore(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	X509_STORE *store;

	if((store = SSL_CTX_get_cert_store(ctx))) {
		xs_push(L, store);
	} else {
		lua_pushnil(L);
	}

	return 1;
} /* sx_getStore() */


static int sx_setParam(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	X509_VERIFY_PARAM *xp = checksimple(L, 2, X509_VERIFY_PARAM_CLASS);

	if (!SSL_CTX_set1_param(ctx, xp))
		return auxL_error(L, auxL_EOPENSSL, "ssl.context:setParam");

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setParam() */


static int sx_getParam(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	X509_VERIFY_PARAM **ud, *from;

	/* X509_VERIFY_PARAM is not refcounted; create a new object and copy into it. */
	ud = prepsimple(L, X509_VERIFY_PARAM_CLASS);
	if (!(*ud = X509_VERIFY_PARAM_new()))
		return auxL_error(L, auxL_EOPENSSL, "ssl.context:getParam");

	from = SSL_CTX_get0_param(ctx);

	if (!(X509_VERIFY_PARAM_set1(*ud, from)))
		/* Note: openssl doesn't set an error as it should for some cases */
		return auxL_error(L, auxL_EOPENSSL, "ssl.context:getParam");

	return 1;
} /* sx_getParam() */


static int sx_setVerify(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	int mode = luaL_optinteger(L, 2, -1);
	int depth = luaL_optinteger(L, 3, -1);

	if (mode != -1)
		SSL_CTX_set_verify(ctx, mode, 0);

	if (depth != -1)
		SSL_CTX_set_verify_depth(ctx, depth);

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setVerify() */


static int sx_getVerify(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);

	lua_pushinteger(L, SSL_CTX_get_verify_mode(ctx));
	lua_pushinteger(L, SSL_CTX_get_verify_depth(ctx));

	return 2;
} /* sx_getVerify() */


static int sx_setCertificate(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	X509 *crt = X509_dup(checksimple(L, 2, X509_CERT_CLASS));
	int ok;

	ok = SSL_CTX_use_certificate(ctx, crt);
	X509_free(crt);

	if (!ok)
		return auxL_error(L, auxL_EOPENSSL, "ssl.context:setCertificate");

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setCertificate() */


#if HAVE_SSL_CTX_GET0_CERTIFICATE
static int sx_getCertificate(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	X509 *x509;

	if (!(x509 = SSL_CTX_get0_certificate(ctx)))
		return 0;

	xc_dup(L, x509);

	return 1;
} /* sx_getCertificate() */
#endif


#if HAVE_SSL_CTX_SET1_CHAIN
static int sx_setCertificateChain(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	STACK_OF(X509) *certs = checksimple(L, 2, X509_CHAIN_CLASS);

	if (!SSL_CTX_set1_chain(ctx, certs))
		return auxL_error(L, auxL_EOPENSSL, "ssl.context:setCertificateChain");

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setCertificateChain() */
#endif


#if HAVE_SSL_CTX_GET0_CHAIN_CERTS
static int sx_getCertificateChain(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	STACK_OF(X509) *certs;

	if (!SSL_CTX_get0_chain_certs(ctx, &certs))
		return auxL_error(L, auxL_EOPENSSL, "ssl.context:getCertificateChain");

	xl_dup(L, certs, 1);

	return 1;
} /* sx_getCertificateChain() */
#endif


static int sx_setPrivateKey(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	EVP_PKEY *key = checksimple(L, 2, PKEY_CLASS);

	/*
	 * NOTE: No easy way to dup the key, but a shared reference should
	 * be okay as keys are less mutable than certificates.
	 *
	 * FIXME: SSL_CTX_use_PrivateKey will return true even if the
	 * EVP_PKEY object has no private key. Instead, we'll just get a
	 * segfault during the SSL handshake. We need to check that a
	 * private key is actually defined in the object.
	 */
	if (!SSL_CTX_use_PrivateKey(ctx, key))
		return auxL_error(L, auxL_EOPENSSL, "ssl.context:setPrivateKey");

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setPrivateKey() */


static int sx_setCipherList(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	const char *ciphers = luaL_checkstring(L, 2);

	if (!SSL_CTX_set_cipher_list(ctx, ciphers))
		return auxL_error(L, auxL_EOPENSSL, "ssl.context:setCipherList");

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setCipherList() */


#if HAVE_SSL_CTX_SET_CIPHERSUITES
static int sx_setCipherSuites(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	const char *ciphers = luaL_checkstring(L, 2);

	if (!SSL_CTX_set_ciphersuites(ctx, ciphers))
		return auxL_error(L, auxL_EOPENSSL, "ssl.context:setCipherSuites");

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setCipherSuites() */
#endif


static int sx_setEphemeralKey(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	EVP_PKEY *key = checksimple(L, 2, PKEY_CLASS);
	void *tmp;

	/*
	 * NOTE: SSL_CTX_set_tmp duplicates the keys, so we don't need to
	 * worry about lifetimes. EVP_PKEY_get0 doesn't increment the
	 * reference count.
	 */
	switch (EVP_PKEY_base_id(key)) {
	case EVP_PKEY_RSA:
		if (!(tmp = EVP_PKEY_get0(key)))
			return auxL_error(L, auxL_EOPENSSL, "ssl.context:setEphemeralKey");

		if (!SSL_CTX_set_tmp_rsa(ctx, tmp))
			return auxL_error(L, auxL_EOPENSSL, "ssl.context:setEphemeralKey");

		break;
	case EVP_PKEY_DH:
		if (!(tmp = EVP_PKEY_get0(key)))
			return auxL_error(L, auxL_EOPENSSL, "ssl.context:setEphemeralKey");

		if (!SSL_CTX_set_tmp_dh(ctx, tmp))
			return auxL_error(L, auxL_EOPENSSL, "ssl.context:setEphemeralKey");

		break;
	case EVP_PKEY_EC:
		if (!(tmp = EVP_PKEY_get0(key)))
			return auxL_error(L, auxL_EOPENSSL, "ssl.context:setEphemeralKey");

		if (!SSL_CTX_set_tmp_ecdh(ctx, tmp))
			return auxL_error(L, auxL_EOPENSSL, "ssl.context:setEphemeralKey");

		break;
	default:
		return luaL_error(L, "%d: unsupported EVP base type", EVP_PKEY_base_id(key));
	} /* switch() */

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setEphemeralKey() */


#if HAVE_SSL_CTX_SET_GROUPS_LIST
static int sx_setGroups(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	const char *list = luaL_checkstring(L, 2);

	if (!SSL_CTX_set1_groups_list(ctx, list))
		return auxL_error(L, auxL_EOPENSSL, "ssl.context:setGroups");

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setGroups() */
#endif


#if HAVE_SSL_CTX_SET_ALPN_PROTOS
static int sx_setAlpnProtos(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	luaL_Buffer B;
	size_t len;
	const char *tmp;

	luaL_buffinit(L, &B);
	checkprotos(&B, L, 2);
	luaL_pushresult(&B);
	tmp = lua_tolstring(L, -1, &len);

	/* OpenSSL 1.0.2 doesn't update the error stack on failure. */
	ERR_clear_error();
	if (0 != SSL_CTX_set_alpn_protos(ctx, (const unsigned char*)tmp, len)) {
		if (!ERR_peek_error()) {
			return luaL_error(L, "unable to set ALPN protocols: %s", aux_strerror(ENOMEM));
		} else {
			return auxL_error(L, auxL_EOPENSSL, "ssl.context:setAlpnProtos");
		}
	}

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setAlpnProtos() */
#endif


#if HAVE_SSL_CTX_SET_ALPN_SELECT_CB

typedef struct {
	/* input arguments */
	SSL *ssl;
	const unsigned char *in;
	unsigned int inlen;

	/* space to store the selected protocol in our callback */
	unsigned char selected[UCHAR_MAX];
} sx_setAlpnSelect_cb_struct;


static int sx_setAlpnSelect_cb_helper(lua_State *L) {
	sx_setAlpnSelect_cb_struct *tmpbuf = lua_touserdata(L, 1);

	/* swap out nil for SSL object */
	ssl_push(L, tmpbuf->ssl);
	lua_replace(L, 3);

	/* swap out nil for actual protos */
	pushprotos(L, tmpbuf->in, tmpbuf->inlen);
	lua_replace(L, 4);

	lua_call(L, lua_gettop(L)-2, 1);

	return 1;
} /* sx_setAlpnSelect_cb_helper() */


static int sx_setAlpnSelect_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *_ctx) {
	SSL_CTX *ctx = _ctx;
	lua_State *L = NULL;
	size_t n, protolen;
	int otop;
	const void *proto;
	sx_setAlpnSelect_cb_struct *tmpbuf;

	*out = NULL;
	*outlen = 0;

	/* expect at least five values: helper, space, userfunc, nil, nil */
	if ((n = ex_getdata(&L, EX_SSL_CTX_ALPN_SELECT_CB, ctx)) < 5)
		return SSL_TLSEXT_ERR_ALERT_FATAL;

	otop = lua_gettop(L) - n;

	tmpbuf = lua_touserdata(L, -n+1);
	tmpbuf->ssl = ssl;
	tmpbuf->in = in;
	tmpbuf->inlen = inlen;

	/* call protected helper */
	if (LUA_OK != lua_pcall(L, n - 1, 1, 0))
		goto fatal;

	/* did we get a string result? */
	if (!(proto = lua_tolstring(L, -1, &protolen)))
		goto noack;

	/* will it fit in our return buffer? */
	if (protolen > UCHAR_MAX)
		goto fatal;

	memcpy(tmpbuf->selected, proto, protolen);

	/*
	 * NB: Our return buffer is anchored using the luaL_ref API, so even
	 * once we pop the stack it will remain valid.
	 */
	*out = tmpbuf->selected;
	*outlen = protolen;

	lua_settop(L, otop);

	return SSL_TLSEXT_ERR_OK;
fatal:
	lua_settop(L, otop);

	return SSL_TLSEXT_ERR_ALERT_FATAL;
noack:
	lua_settop(L, otop);

	return SSL_TLSEXT_ERR_NOACK;
} /* sx_setAlpnSelect_cb() */


static int sx_setAlpnSelect(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	int error;

	luaL_checktype(L, 2, LUA_TFUNCTION);

	/* need to do actual call in protected function. push helper */
	lua_pushcfunction(L, sx_setAlpnSelect_cb_helper);
	lua_newuserdata(L, sizeof(sx_setAlpnSelect_cb_struct));
	/* move space and helper to bottom of stack */
	lua_rotate(L, 2, 2);

	/* room for SSL parameter and protos */
	lua_pushnil(L);
	lua_pushnil(L);
	lua_rotate(L, 5, 2);
	/* stack: self, helper, space, userfunc, nil, nil, ... */

	if ((error = ex_setdata(L, EX_SSL_CTX_ALPN_SELECT_CB, ctx, lua_gettop(L) - 1))) {
		if (error > 0) {
			return luaL_error(L, "unable to set ALPN protocol selection callback: %s", aux_strerror(error));
		} else if (error == auxL_EOPENSSL && !ERR_peek_error()) {
			return luaL_error(L, "unable to set ALPN protocol selection callback: Unknown internal error");
		} else {
			return auxL_error(L, error, "ssl.context:setAlpnSelect");
		}
	}

	SSL_CTX_set_alpn_select_cb(ctx, &sx_setAlpnSelect_cb, ctx);

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setAlpnSelect() */
#endif


#if HAVE_SSL_CTX_SET_TLSEXT_SERVERNAME_CALLBACK

typedef struct {
	SSL *ssl;
} sx_setHostNameCallback_struct;


static int sx_setHostNameCallback_helper(lua_State *L) {
	sx_setHostNameCallback_struct *tmpbuf = lua_touserdata(L, 1);

	ssl_push(L, tmpbuf->ssl);
	lua_replace(L, 3);

	lua_call(L, lua_gettop(L)-2, 2);

	return 2;
}


static int sx_setHostNameCallback_cb(SSL *ssl, int *ad, void *_ctx) {
	SSL_CTX *ctx = _ctx;
	lua_State *L = NULL;
	size_t n;
	int otop, status, ret = SSL_TLSEXT_ERR_ALERT_FATAL;
	sx_setHostNameCallback_struct *tmpbuf;

	*ad = SSL_AD_INTERNAL_ERROR;

	/* expect at least four values: helper, space, userfunc, nil */
	if ((n = ex_getdata(&L, EX_SSL_CTX_TLSEXT_SERVERNAME_CB, ctx)) < 4)
		return SSL_TLSEXT_ERR_ALERT_FATAL;

	otop = lua_gettop(L) - n;

	tmpbuf = lua_touserdata(L, -n+1);
	tmpbuf->ssl = ssl;

	if (LUA_OK != (status = lua_pcall(L, n - 1, 2, 0)))
		goto done;

	/* callback should return a boolean for OK/NOACK
	 * or nil + an integer for a controlled error
	 * everything else will be a fatal internal error
	 */
	if (lua_isboolean(L, -2)) {
		ret = lua_toboolean(L, -2) ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_NOACK;
	} else {
		ret = SSL_TLSEXT_ERR_ALERT_FATAL;
		if (lua_isnil(L, -2) && lua_isinteger(L, -1))
			*ad = lua_tointeger(L, -1);
	}

done:
	lua_settop(L, otop);

	return ret;
} /* sx_setHostNameCallback_cb() */


static int sx_setHostNameCallback(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	int error;

	luaL_checktype(L, 2, LUA_TFUNCTION);

	/* need to do actual call in protected function. push helper */
	lua_pushcfunction(L, sx_setHostNameCallback_helper);
	lua_newuserdata(L, sizeof(sx_setHostNameCallback_struct));
	/* move space and helper to bottom of stack */
	lua_rotate(L, 2, 2);

	/* room for SSL parameter */
	lua_pushnil(L);
	lua_rotate(L, 5, 1);

	if ((error = ex_setdata(L, EX_SSL_CTX_TLSEXT_SERVERNAME_CB, ctx, lua_gettop(L) - 1))) {
		if (error > 0) {
			return luaL_error(L, "unable to set hostname selection callback: %s", aux_strerror(error));
		} else if (error == auxL_EOPENSSL && !ERR_peek_error()) {
			return luaL_error(L, "unable to set hostname selection callback: Unknown internal error");
		} else {
			return auxL_error(L, error, "ssl.context:setHostNameCallback");
		}
	}
	SSL_CTX_set_tlsext_servername_callback(ctx, sx_setHostNameCallback_cb);
	SSL_CTX_set_tlsext_servername_arg(ctx, ctx);

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setHostNameCallback() */
#endif


int TLSEXT_STATUSTYPEs[] = { TLSEXT_STATUSTYPE_ocsp };
const char *TLSEXT_STATUSTYPEs_names[] = { "ocsp", NULL };
#define checkTLSEXT_STATUSTYPE(L, idx) \
	(TLSEXT_STATUSTYPEs[luaL_checkoption((L), (idx), NULL, TLSEXT_STATUSTYPEs_names)])


#if HAVE_SSL_CTX_SET_TLSEXT_STATUS_TYPE
static int sx_setTLSextStatusType(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	int type = checkTLSEXT_STATUSTYPE(L, 2);

	if(!SSL_CTX_set_tlsext_status_type(ctx, type))
		return auxL_error(L, auxL_EOPENSSL, "ssl.context:setTLSextStatusType");

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setTLSextStatusType() */
#endif


#if HAVE_SSL_CTX_GET_TLSEXT_STATUS_TYPE
static int sx_getTLSextStatusType(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);

	int type = SSL_CTX_get_tlsext_status_type(ctx);
	switch(type) {
	case -1:
		lua_pushnil(L);
		break;
	case TLSEXT_STATUSTYPE_ocsp:
		lua_pushliteral(L, "ocsp");
		break;
	default:
		luaL_error(L, "unknown TLS extension %d", type);
	}

	return 1;
} /* sx_getTLSextStatusType() */
#endif


#if HAVE_SSL_CTX_SET_TLSEXT_TICKET_KEYS
static int sx_getTicketKeysLength(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);

	int res = SSL_CTX_set_tlsext_ticket_keys(ctx, NULL, 0);

	lua_pushinteger(L, res);

	return 1;
} /* sx_getTicketKeysLength() */


static int sx_setTicketKeys(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	size_t keylen;
	const char *keys = luaL_checklstring(L, 2, &keylen);

	if (!SSL_CTX_set_tlsext_ticket_keys(ctx, (void*)keys, keylen))
		return auxL_error(L, auxL_EOPENSSL, "ssl.context:setTicketKeys");

	lua_pushboolean(L, 1);

	return 1;
} /* sx_setTicketKeys() */
#endif


#if HAVE_SSL_CTX_GET_TLSEXT_TICKET_KEYS
static int sx_getTicketKeys(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	int keylen;
	char *out;
	luaL_Buffer B;

	keylen = SSL_CTX_get_tlsext_ticket_keys(ctx, NULL, 0);
	out = luaL_buffinitsize(L, &B, keylen);
	if (!SSL_CTX_get_tlsext_ticket_keys(ctx, out, keylen))
		return auxL_error(L, auxL_EOPENSSL, "ssl.context:getTicketKeys");

	luaL_pushresultsize(&B, keylen);

	return 1;
} /* sx_getTicketKeys() */
#endif


#if HAVE_SSL_CTX_USE_SERVERINFO_FILE
static int sx_useServerInfoFile(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	const char *file = luaL_checkstring(L, 2);

	if (!SSL_CTX_use_serverinfo_file(ctx, file))
		return auxL_error(L, auxL_EOPENSSL, "ssl.context:useServerInfoFile");

	lua_pushboolean(L, 1);

	return 1;
} /* sx_useServerInfoFile() */
#endif


#if HAVE_SSL_CTX_USE_SERVERINFO_EX || HAVE_SSL_CTX_USE_SERVERINFO
static int sx_useServerInfo(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	unsigned int version = auxL_checkunsigned(L, 2, 1, (HAVE_SSL_CTX_USE_SERVERINFO_EX) ? auxL_UnsignedMax : 1);
	size_t serverinfo_length;
	const unsigned char *serverinfo = (const unsigned char *)luaL_checklstring(L, 3, &serverinfo_length);

#if HAVE_SSL_CTX_USE_SERVERINFO_EX
	if (!SSL_CTX_use_serverinfo_ex(ctx, version, serverinfo, serverinfo_length))
#else
	if (!SSL_CTX_use_serverinfo(ctx, serverinfo, serverinfo_length))
#endif
		return auxL_error(L, auxL_EOPENSSL, "ssl.context:useServerInfo");

	lua_pushboolean(L, 1);

	return 1;
} /* sx_useServerInfoFile() */
#endif


#if HAVE_SSL_CTX_ADD_CUSTOM_EXT

typedef struct {
	/* input arguments */
	SSL *ssl;
	unsigned int ext_type;
	unsigned int context;
	X509 *x;
	size_t chainidx;
} sx_custom_ext_add_cb_struct;


static int sx_custom_ext_add_cb_helper(lua_State *L) {
	sx_custom_ext_add_cb_struct *tmpbuf = lua_touserdata(L, 1);

	ssl_push(L, tmpbuf->ssl);
	lua_pushinteger(L, tmpbuf->ext_type);
	lua_pushinteger(L, tmpbuf->context);
	if (tmpbuf->x) {
		xc_dup(L, tmpbuf->x);
		lua_pushinteger(L, tmpbuf->chainidx);
	} else {
		lua_pushnil(L);
		lua_pushnil(L);
	}

	lua_call(L, 5, 2);

	return 2;
} /* sx_custom_ext_add_cb_helper() */


static int sx_custom_ext_add_cb(SSL *s, unsigned int ext_type,
	unsigned int context, const unsigned char **out, size_t *outlen,
	X509 *x, size_t chainidx, int *al, void *add_arg NOTUSED)
{
	SSL_CTX *ctx = SSL_get_SSL_CTX(s);
	lua_State *L = NULL;

	*al = SSL_AD_INTERNAL_ERROR;

	/* expect three values: helper_function, space, table of callbacks indexed by ext_type */
	if (ex_getdata(&L, EX_SSL_CTX_CUSTOM_EXTENSION_ADD_CB, ctx) != 3)
		return -1;

	sx_custom_ext_add_cb_struct *tmpbuf = lua_touserdata(L, -2);
	tmpbuf->ssl = s;
	tmpbuf->ext_type = ext_type;
	tmpbuf->context = context;
	tmpbuf->x = x;
	tmpbuf->chainidx = chainidx;

	/* replace table with callback of interest */
	lua_rawgeti(L, -1, ext_type);
	lua_remove(L, -2);

	/* call protected helper */
	if (LUA_OK != lua_pcall(L, 2, 2, 0))
		/* leave error on the stack */
		return -1;

	/* callback should return a string for OK, 'false' to skip,
	 * or nil + an integer for a controlled error
	 * everything else will be a fatal internal error
	 */
	if (lua_isstring(L, -2)) {
		*out = (const unsigned char*)lua_tolstring(L, -2, outlen);

		/* leave `out` on the stack, we need it to remain valid */
		lua_pop(L, 1);

		return 1;
	} else if (lua_isboolean(L, -2) && !lua_toboolean(L, -2)) {

		/* leave false on the stack */
		lua_pop(L, 1);

		return 0;
	} else {
		if (lua_isnil(L, -2) && lua_isinteger(L, -1))
			*al = lua_tointeger(L, -1);

		/* leave something on the stack */
		lua_pop(L, 1);

		return -1;
	}
} /* sx_custom_ext_add_cb() */


static void sx_custom_ext_free_cb(SSL *s, unsigned int ext_type NOTUSED,
	unsigned int context NOTUSED, const unsigned char *out NOTUSED, void *add_arg NOTUSED)
{
	SSL_CTX *ctx = SSL_get_SSL_CTX(s);
	lua_State *L = NULL;
	size_t n;

	if ((n = ex_getdata(&L, EX_SSL_CTX_CUSTOM_EXTENSION_ADD_CB, ctx)) < 1)
		return; /* should be unreachable */

	/* pop data pushed by ex_getdata
	 * TODO: ex_getdata alternative that doesn't push in the first place?
	 */
	lua_pop(L, n);

	/* pop the item left on the stack by add_cb */
	lua_pop(L, 1);
} /* sx_custom_ext_free_cb() */


typedef struct {
	/* input arguments */
	SSL *ssl;
	unsigned int ext_type;
	unsigned int context;
	const unsigned char *in;
	size_t inlen;
	X509 *x;
	size_t chainidx;
} sx_custom_ext_parse_cb_struct;


static int sx_custom_ext_parse_cb_helper(lua_State *L) {
	sx_custom_ext_parse_cb_struct *tmpbuf = lua_touserdata(L, 1);

	ssl_push(L, tmpbuf->ssl);
	lua_pushinteger(L, tmpbuf->ext_type);
	lua_pushinteger(L, tmpbuf->context);
	lua_pushlstring(L, (const char*)tmpbuf->in, tmpbuf->inlen);
	if (tmpbuf->x) {
		xc_dup(L, tmpbuf->x);
		lua_pushinteger(L, tmpbuf->chainidx);
	} else {
		lua_pushnil(L);
		lua_pushnil(L);
	}

	lua_call(L, 6, 2);

	return 2;
} /* sx_custom_ext_parse_cb_helper() */


static int sx_custom_ext_parse_cb(SSL *s, unsigned int ext_type,
	unsigned int context, const unsigned char *in, size_t inlen,
	X509 *x, size_t chainidx, int *al, void *parse_arg NOTUSED)
{
	SSL_CTX *ctx = SSL_get_SSL_CTX(s);
	lua_State *L = NULL;

	*al = SSL_AD_INTERNAL_ERROR;

	/* expect three values: helper_function, space, table of callbacks indexed by ext_type */
	if (ex_getdata(&L, EX_SSL_CTX_CUSTOM_EXTENSION_PARSE_CB, ctx) != 3)
		return -1;

	sx_custom_ext_parse_cb_struct *tmpbuf = lua_touserdata(L, -2);
	tmpbuf->ssl = s;
	tmpbuf->ext_type = ext_type;
	tmpbuf->context = context;
	tmpbuf->in = in;
	tmpbuf->inlen = inlen;
	tmpbuf->x = x;
	tmpbuf->chainidx = chainidx;

	/* replace table with callback of interest */
	lua_rawgeti(L, -1, ext_type);
	lua_remove(L, -2);

	/* call protected helper */
	if (LUA_OK != lua_pcall(L, 2, 2, 0)) {
		lua_pop(L, 1);
		return -1;
	}

	/* callback should return true
	 * or nil + an integer for a controlled error
	 * everything else will be a fatal internal error
	 */
	if (lua_isboolean(L, -2) && lua_toboolean(L, -2)) {
		lua_pop(L, 2);
		return 1;
	} else {
		if (lua_isnil(L, -2) && lua_isinteger(L, -1))
			*al = lua_tointeger(L, -1);
		lua_pop(L, 2);
		return -1;
	}
} /* sx_custom_ext_parse_cb() */


static int sx_addCustomExtension(lua_State *L) {
	int error;
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	unsigned int ext_type = auxL_checkunsigned(L, 2, 0, 65535);
	unsigned int context = auxL_checkunsigned(L, 3);
	SSL_custom_ext_add_cb_ex add_cb = NULL;
	SSL_custom_ext_free_cb_ex free_cb = NULL;
	SSL_custom_ext_parse_cb_ex parse_cb = NULL;
	lua_settop(L, 5);

	if (!lua_isnoneornil(L, 4)) {
		luaL_checktype(L, 4, LUA_TFUNCTION);

		switch (ex_getdata(&L, EX_SSL_CTX_CUSTOM_EXTENSION_ADD_CB, ctx)) {
		case 0: { /* first time */
			lua_createtable(L, 0, 1);
			/* need to do actual call in protected function. push helper */
			lua_pushcfunction(L, sx_custom_ext_add_cb_helper);
			lua_newuserdata(L, sizeof(sx_custom_ext_add_cb_struct));
			lua_pushvalue(L, -3);
			if ((error = ex_setdata(L, EX_SSL_CTX_CUSTOM_EXTENSION_ADD_CB, ctx, 3))) {
				if (error > 0) {
					return luaL_error(L, "unable to add custom extension add callback: %s", aux_strerror(error));
				} else if (error == auxL_EOPENSSL && !ERR_peek_error()) {
					return luaL_error(L, "unable to add custom extension add callback: Unknown internal error");
				} else {
					return auxL_error(L, error, "ssl.context:addCustomExtension");
				}
			}
			break;
		}
		case 2:
			lua_remove(L, -2);
			break;
		default:
			return luaL_error(L, "unable to add custom extension add callback");
		}

		lua_pushvalue(L, 4);
		lua_rawseti(L, -2, ext_type);
		lua_pop(L, 1);
		add_cb = sx_custom_ext_add_cb;
		free_cb = sx_custom_ext_free_cb;
	}

	if (!lua_isnoneornil(L, 5)) {
		luaL_checktype(L, 5, LUA_TFUNCTION);

		switch (ex_getdata(&L, EX_SSL_CTX_CUSTOM_EXTENSION_PARSE_CB, ctx)) {
		case 0: { /* first time */
			lua_createtable(L, 0, 1);
			/* need to do actual call in protected function. push helper */
			lua_pushcfunction(L, sx_custom_ext_parse_cb_helper);
			lua_newuserdata(L, sizeof(sx_custom_ext_parse_cb_struct));
			lua_pushvalue(L, -3);
			if ((error = ex_setdata(L, EX_SSL_CTX_CUSTOM_EXTENSION_PARSE_CB, ctx, 3))) {
				if (error > 0) {
					return luaL_error(L, "unable to add custom extension parse callback: %s", aux_strerror(error));
				} else if (error == auxL_EOPENSSL && !ERR_peek_error()) {
					return luaL_error(L, "unable to add custom extension parse callback: Unknown internal error");
				} else {
					return auxL_error(L, error, "ssl.context:addCustomExtension");
				}
			}
			break;
		}
		case 2:
			lua_remove(L, -2);
			break;
		default:
			return luaL_error(L, "unable to add custom extension add callback");
		}

		lua_pushvalue(L, 5);
		lua_rawseti(L, -2, ext_type);
		lua_pop(L, 1);
		parse_cb = sx_custom_ext_parse_cb;
	}

	if (!SSL_CTX_add_custom_ext(ctx, ext_type, context, add_cb, free_cb, NULL, parse_cb, NULL))
		/* In OpenSSL 1.1.1, no error is set */
		return luaL_error(L, "ssl.context:addCustomExtension: extension type already handled or internal error");

	lua_pushboolean(L, 1);

	return 1;
} /* sx_addCustomExtension() */
#endif


static int sx__gc(lua_State *L) {
	SSL_CTX **ud = luaL_checkudata(L, 1, SSL_CTX_CLASS);

	if (*ud) {
		SSL_CTX_free(*ud);
		*ud = NULL;
	}

	return 0;
} /* sx__gc() */


static const auxL_Reg sx_methods[] = {
	{ "setOptions",       &sx_setOptions },
	{ "getOptions",       &sx_getOptions },
	{ "clearOptions",     &sx_clearOptions },
	{ "setReadAhead",     &sx_setReadAhead },
	{ "getReadAhead",     &sx_getReadAhead },
	{ "setStore",         &sx_setStore },
	{ "getStore",         &sx_getStore },
	{ "setParam",         &sx_setParam },
	{ "getParam",         &sx_getParam },
	{ "setVerify",        &sx_setVerify },
	{ "getVerify",        &sx_getVerify },
	{ "setCertificate",   &sx_setCertificate },
#if HAVE_SSL_CTX_GET0_CERTIFICATE
	{ "getCertificate",   &sx_getCertificate },
#endif
#if HAVE_SSL_CTX_SET1_CHAIN
	{ "setCertificateChain", &sx_setCertificateChain },
#endif
#if HAVE_SSL_CTX_GET0_CHAIN_CERTS
	{ "getCertificateChain", &sx_getCertificateChain },
#endif
	{ "setPrivateKey",    &sx_setPrivateKey },
	{ "setCipherList",    &sx_setCipherList },
#if HAVE_SSL_CTX_SET_CIPHERSUITES
	{ "setCipherSuites",  &sx_setCipherSuites },
#endif
	{ "setEphemeralKey",  &sx_setEphemeralKey },
#if HAVE_SSL_CTX_SET_GROUPS_LIST
	{ "setCurvesList",    &sx_setGroups }, /* old alias */
	{ "setGroups",        &sx_setGroups },
#endif
#if HAVE_SSL_CTX_SET_ALPN_PROTOS
	{ "setAlpnProtos",    &sx_setAlpnProtos },
#endif
#if HAVE_SSL_CTX_SET_ALPN_SELECT_CB
	{ "setAlpnSelect",    &sx_setAlpnSelect },
#endif
#if HAVE_SSL_CTX_SET_TLSEXT_SERVERNAME_CALLBACK
	{ "setHostNameCallback", &sx_setHostNameCallback },
#endif
#if HAVE_SSL_CTX_SET_TLSEXT_STATUS_TYPE
	{ "setTLSextStatusType", &sx_setTLSextStatusType },
#endif
#if HAVE_SSL_CTX_GET_TLSEXT_STATUS_TYPE
	{ "getTLSextStatusType", &sx_getTLSextStatusType },
#endif
#if HAVE_SSL_CTX_SET_TLSEXT_TICKET_KEYS
	{ "getTicketKeysLength", &sx_getTicketKeysLength },
	{ "setTicketKeys", &sx_setTicketKeys },
#endif
#if HAVE_SSL_CTX_GET_TLSEXT_TICKET_KEYS
	{ "getTicketKeys", &sx_getTicketKeys },
#endif
#if HAVE_SSL_CTX_USE_SERVERINFO_FILE
	{ "useServerInfoFile", &sx_useServerInfoFile },
#endif
#if HAVE_SSL_CTX_USE_SERVERINFO_EX || HAVE_SSL_CTX_USE_SERVERINFO
	{ "useServerInfo", &sx_useServerInfo },
#endif
#if HAVE_SSL_CTX_ADD_CUSTOM_EXT
	{ "addCustomExtension", &sx_addCustomExtension },
#endif
	{ NULL, NULL },
};

static const auxL_Reg sx_metatable[] = {
	{ "__gc", &sx__gc },
	{ NULL,   NULL },
};

static const auxL_Reg sx_globals[] = {
	{ "new",       &sx_new },
	{ "pushffi",   &sx_pushffi, 1 },
	{ "interpose", &sx_interpose },
	{ NULL,        NULL },
};

static const auxL_IntegerReg sx_verify[] = {
	{ "VERIFY_NONE", SSL_VERIFY_NONE },
	{ "VERIFY_PEER", SSL_VERIFY_PEER },
	{ "VERIFY_FAIL_IF_NO_PEER_CERT", SSL_VERIFY_FAIL_IF_NO_PEER_CERT },
	{ "VERIFY_CLIENT_ONCE", SSL_VERIFY_CLIENT_ONCE },
	{ NULL, 0 },
};

static const auxL_IntegerReg sx_option[] = {
	{ "OP_MICROSOFT_SESS_ID_BUG", SSL_OP_MICROSOFT_SESS_ID_BUG },
	{ "OP_NETSCAPE_CHALLENGE_BUG", SSL_OP_NETSCAPE_CHALLENGE_BUG },
	{ "OP_LEGACY_SERVER_CONNECT", SSL_OP_LEGACY_SERVER_CONNECT },
	{ "OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG", SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG },
#ifdef SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
	{ "OP_SSLREF2_REUSE_CERT_TYPE_BUG", SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG },
#endif
#ifdef SSL_OP_TLSEXT_PADDING
	{ "OP_TLSEXT_PADDING", SSL_OP_TLSEXT_PADDING },
#endif
	{ "OP_MICROSOFT_BIG_SSLV3_BUFFER", SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER },
#ifdef SSL_OP_SAFARI_ECDHE_ECDSA_BUG5
	{ "OP_SAFARI_ECDHE_ECDSA_BUG", SSL_OP_SAFARI_ECDHE_ECDSA_BUG },
#endif
	{ "OP_MSIE_SSLV2_RSA_PADDING", SSL_OP_MSIE_SSLV2_RSA_PADDING },
	{ "OP_SSLEAY_080_CLIENT_DH_BUG", SSL_OP_SSLEAY_080_CLIENT_DH_BUG },
	{ "OP_TLS_D5_BUG", SSL_OP_TLS_D5_BUG },
	{ "OP_TLS_BLOCK_PADDING_BUG", SSL_OP_TLS_BLOCK_PADDING_BUG },
#ifdef SSL_OP_ALLOW_NO_DHE_KEX
	{ "OP_ALLOW_NO_DHE_KEX", SSL_OP_ALLOW_NO_DHE_KEX },
#endif
	{ "OP_DONT_INSERT_EMPTY_FRAGMENTS", SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS },
	{ "OP_NO_QUERY_MTU", SSL_OP_NO_QUERY_MTU },
	{ "OP_COOKIE_EXCHANGE", SSL_OP_COOKIE_EXCHANGE },
	{ "OP_NO_TICKET", SSL_OP_NO_TICKET },
	{ "OP_CISCO_ANYCONNECT", SSL_OP_CISCO_ANYCONNECT },
	{ "OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION", SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION },
#ifdef SSL_OP_NO_COMPRESSION
	{ "OP_NO_COMPRESSION", SSL_OP_NO_COMPRESSION },
#endif
	{ "OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION", SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION },
	{ "OP_SINGLE_ECDH_USE", SSL_OP_SINGLE_ECDH_USE },
#ifdef SSL_OP_NO_ENCRYPT_THEN_MAC5
	{ "OP_NO_ENCRYPT_THEN_MAC", SSL_OP_NO_ENCRYPT_THEN_MAC },
#endif
	{ "OP_SINGLE_DH_USE", SSL_OP_SINGLE_DH_USE },
	{ "OP_EPHEMERAL_RSA", SSL_OP_EPHEMERAL_RSA },
#ifdef SSL_OP_PRIORITIZE_CHACHA
	{ "OP_PRIORITIZE_CHACHA", SSL_OP_PRIORITIZE_CHACHA },
#endif
#ifdef SSL_OP_ENABLE_MIDDLEBOX_COMPAT
	{ "OP_ENABLE_MIDDLEBOX_COMPAT", SSL_OP_ENABLE_MIDDLEBOX_COMPAT },
#endif
#ifdef SSL_OP_NO_ANTI_REPLAY
	{ "OP_NO_ANTI_REPLAY", SSL_OP_NO_ANTI_REPLAY },
#endif
	{ "OP_CIPHER_SERVER_PREFERENCE", SSL_OP_CIPHER_SERVER_PREFERENCE },
	{ "OP_TLS_ROLLBACK_BUG", SSL_OP_TLS_ROLLBACK_BUG },
	{ "OP_NO_SSLv2", SSL_OP_NO_SSLv2 },
	{ "OP_NO_SSLv3", SSL_OP_NO_SSLv3 },
	{ "OP_NO_TLSv1", SSL_OP_NO_TLSv1 },
#ifdef SSL_OP_NO_DTLSv1
	{ "OP_NO_DTLSv1", SSL_OP_NO_DTLSv1 },
#endif
#ifdef SSL_OP_NO_TLSv1_2
	{ "OP_NO_TLSv1_2", SSL_OP_NO_TLSv1_2 },
#endif
#ifdef SSL_OP_NO_DTLSv1_2
	{ "OP_NO_DTLSv1_2", SSL_OP_NO_DTLSv1_2 },
#endif
#ifdef SSL_OP_NO_TLSv1_1
	{ "OP_NO_TLSv1_1", SSL_OP_NO_TLSv1_1 },
#endif
	{ "OP_NETSCAPE_CA_DN_BUG", SSL_OP_NETSCAPE_CA_DN_BUG },
#ifdef SSL_OP_NO_TLSv1_3
	{ "OP_NO_TLSv1_3", SSL_OP_NO_TLSv1_3 },
#endif
	{ "OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG", SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG },
#ifdef SSL_OP_NO_RENEGOTIATION
	{ "OP_NO_RENEGOTIATION", SSL_OP_NO_RENEGOTIATION },
#endif
#ifdef SSL_OP_CRYPTOPRO_TLSEXT_BUG
	{ "OP_CRYPTOPRO_TLSEXT_BUG", SSL_OP_CRYPTOPRO_TLSEXT_BUG },
#endif
	{ "OP_PKCS1_CHECK_1", SSL_OP_PKCS1_CHECK_1 },
	{ "OP_PKCS1_CHECK_2", SSL_OP_PKCS1_CHECK_2 },
	{ "OP_NO_SSL_MASK", SSL_OP_NO_SSL_MASK },
#ifdef SSL_OP_NO_DTLS_MASK
	{ "OP_NO_DTLS_MASK", SSL_OP_NO_DTLS_MASK },
#endif
	{ "OP_ALL", SSL_OP_ALL },
	{ NULL, 0 },
};

static const auxL_IntegerReg sx_ext[] = {
#ifdef SSL_EXT_TLS_ONLY
	{ "EXT_TLS_ONLY", SSL_EXT_TLS_ONLY },
#endif
#ifdef SSL_EXT_DTLS_ONLY
	{ "EXT_DTLS_ONLY", SSL_EXT_DTLS_ONLY },
#endif
#ifdef SSL_EXT_TLS_IMPLEMENTATION_ONLY
	{ "EXT_TLS_IMPLEMENTATION_ONLY", SSL_EXT_TLS_IMPLEMENTATION_ONLY },
#endif
#ifdef SSL_EXT_SSL3_ALLOWED
	{ "EXT_SSL3_ALLOWED", SSL_EXT_SSL3_ALLOWED },
#endif
#ifdef SSL_EXT_TLS1_2_AND_BELOW_ONLY
	{ "EXT_TLS1_2_AND_BELOW_ONLY", SSL_EXT_TLS1_2_AND_BELOW_ONLY },
#endif
#ifdef SSL_EXT_TLS1_3_ONLY
	{ "EXT_TLS1_3_ONLY", SSL_EXT_TLS1_3_ONLY },
#endif
#ifdef SSL_EXT_IGNORE_ON_RESUMPTION
	{ "EXT_IGNORE_ON_RESUMPTION", SSL_EXT_IGNORE_ON_RESUMPTION },
#endif
#ifdef SSL_EXT_CLIENT_HELLO
	{ "EXT_CLIENT_HELLO", SSL_EXT_CLIENT_HELLO },
#endif
#ifdef SSL_EXT_TLS1_2_SERVER_HELLO
	{ "EXT_TLS1_2_SERVER_HELLO", SSL_EXT_TLS1_2_SERVER_HELLO },
#endif
#ifdef SSL_EXT_TLS1_3_SERVER_HELLO
	{ "EXT_TLS1_3_SERVER_HELLO", SSL_EXT_TLS1_3_SERVER_HELLO },
#endif
#ifdef SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS
	{ "EXT_TLS1_3_ENCRYPTED_EXTENSIONS", SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS },
#endif
#ifdef SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST
	{ "EXT_TLS1_3_HELLO_RETRY_REQUEST", SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST },
#endif
#ifdef SSL_EXT_TLS1_3_CERTIFICATE
	{ "EXT_TLS1_3_CERTIFICATE", SSL_EXT_TLS1_3_CERTIFICATE },
#endif
#ifdef SSL_EXT_TLS1_3_NEW_SESSION_TICKET
	{ "EXT_TLS1_3_NEW_SESSION_TICKET", SSL_EXT_TLS1_3_NEW_SESSION_TICKET },
#endif
#ifdef SSL_EXT_TLS1_3_CERTIFICATE_REQUEST
	{ "EXT_TLS1_3_CERTIFICATE_REQUEST", SSL_EXT_TLS1_3_CERTIFICATE_REQUEST },
#endif
	{ NULL, 0 },
};

EXPORT int luaopen__openssl_ssl_context(lua_State *L) {
	initall(L);

	auxL_newlib(L, sx_globals, 0);
	/* FFI argument checking */
	lua_getfield(L, -1, "pushffi");
	luaL_loadstring(L,
		"local ffi = require 'ffi'\n"                 \
		"if not pcall(ffi.typeof, 'SSL_CTX*') then\n"     \
		"    ffi.cdef 'typedef struct ssl_ctx_st SSL_CTX;'\n" \
		"end\n"                                       \
		"local ffi_istype = ffi.istype\n"             \
		"local SSL_CTXp = ffi.typeof('SSL_CTX*')\n"           \
		"return function(p) return ffi_istype(SSL_CTXp, p) end\n"
	);
	if (lua_pcall(L, 0, 1, 0)) {
		/* failed (probably no ffi library available) */
		lua_pop(L, 1);
		/* use dummy function instead */
		luaL_loadstring(L, "return false\n");
	};
	lua_setupvalue(L, -2, 1);
	lua_pop(L, 1);

	auxL_setintegers(L, sx_verify);
	auxL_setintegers(L, sx_option);
	auxL_setintegers(L, sx_ext);

	return 1;
} /* luaopen__openssl_ssl_context() */


/*
 * SSL - openssl.ssl
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static void ssl_push(lua_State *L, SSL *ssl) {
	lua_rawgetp(L, LUA_REGISTRYINDEX, LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(&initall));
	if (LUA_TNIL == lua_rawgetp(L, -1, LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(ssl))) {
		SSL **ud;

		lua_pop(L, 1); /* pop nil */

		ud = prepsimple(L, SSL_CLASS);

		SSL_up_ref(ssl);
		*ud = ssl;

		/* Add to SSL* cache */
		lua_pushvalue(L, -1);
		lua_rawsetp(L, -3, LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(ssl));
	}
	lua_remove(L, -2);
} /* ssl_push() */


static int ssl_pushffi(lua_State *L) {
	SSL *ptr;

	lua_pushvalue(L, lua_upvalueindex(1));
	lua_pushvalue(L, 1);
	lua_call(L, 1, 1);
	luaL_argcheck(L, lua_toboolean(L, -1), 1, "SSL* ffi pointer expected");
	lua_pop(L, 1);
	ptr = *(SSL**)lua_topointer(L, 1);
	luaL_argcheck(L, ptr, 1, "SSL* pointer must be non-null");

	ssl_push(L, ptr);

	return 1;
} /* ssl_pushffi() */


static int ssl_new(lua_State *L) {
	SSL_CTX *ctx = checksimple(L, 1, SSL_CTX_CLASS);
	SSL **ud = prepsimple(L, SSL_CLASS);

	*ud = SSL_new(ctx);

	if (!*ud)
		return auxL_error(L, auxL_EOPENSSL, "ssl.new");

	/* Add to SSL* cache */
	lua_rawgetp(L, LUA_REGISTRYINDEX, LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(&initall));
	lua_pushvalue(L, -2);
	lua_rawsetp(L, -2, LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(*ud));
	lua_pop(L, 1);

	return 1;
} /* ssl_new() */


static int ssl_interpose(lua_State *L) {
	return interpose(L, SSL_CLASS);
} /* ssl_interpose() */


static int ssl_setContext(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	SSL_CTX *ctx = checksimple(L, 2, SSL_CTX_CLASS);

	if (!SSL_set_SSL_CTX(ssl, ctx))
		return auxL_error(L, auxL_EOPENSSL, "ssl:setContext");

	lua_pushboolean(L, 1);

	return 1;
} /* ssl_setContext() */


static int ssl_getContext(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);

	SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);

	sx_push(L, ctx);

	return 1;
} /* ssl_getContext() */


static int ssl_setOptions(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	auxL_Integer options = auxL_checkinteger(L, 2);

	auxL_pushinteger(L, SSL_set_options(ssl, options));

	return 1;
} /* ssl_setOptions() */


static int ssl_getOptions(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);

	auxL_pushinteger(L, SSL_get_options(ssl));

	return 1;
} /* ssl_getOptions() */


static int ssl_clearOptions(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	auxL_Integer options = auxL_checkinteger(L, 2);

	auxL_pushinteger(L, SSL_clear_options(ssl, options));

	return 1;
} /* ssl_clearOptions() */


static int ssl_setReadAhead(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	int yes = checkbool(L, 2);

	SSL_set_read_ahead(ssl, yes);

	lua_pushboolean(L, 1);

	return 1;
} /* ssl_setReadAhead() */


static int ssl_getReadAhead(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);

	lua_pushboolean(L, SSL_get_read_ahead(ssl));

	return 1;
} /* ssl_getReadAhead() */


#if HAVE_SSL_SET1_CHAIN_CERT_STORE
static int ssl_setChainStore(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	X509_STORE *store = checksimple(L, 2, X509_STORE_CLASS);

	SSL_set1_chain_cert_store(ssl, store);

	lua_pushboolean(L, 1);

	return 1;
} /* ssl_setChainStore() */
#endif


#if HAVE_SSL_SET1_VERIFY_CERT_STORE
static int ssl_setVerifyStore(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	X509_STORE *store = checksimple(L, 2, X509_STORE_CLASS);

	SSL_set1_verify_cert_store(ssl, store);

	lua_pushboolean(L, 1);

	return 1;
} /* ssl_setVerifyStore() */
#endif


static int ssl_setParam(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	X509_VERIFY_PARAM *xp = checksimple(L, 2, X509_VERIFY_PARAM_CLASS);

	if (!SSL_set1_param(ssl, xp))
		return auxL_error(L, auxL_EOPENSSL, "ssl:setParam");

	lua_pushboolean(L, 1);

	return 1;
} /* ssl_setParam() */


static int ssl_getParam(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	X509_VERIFY_PARAM **ud, *from;

	/* X509_VERIFY_PARAM is not refcounted; create a new object and copy into it. */
	ud = prepsimple(L, X509_VERIFY_PARAM_CLASS);
	if (!(*ud = X509_VERIFY_PARAM_new()))
		return auxL_error(L, auxL_EOPENSSL, "ssl:getParam");

	from = SSL_get0_param(ssl);

	if (!(X509_VERIFY_PARAM_set1(*ud, from)))
		/* Note: openssl doesn't set an error as it should for some cases */
		return auxL_error(L, auxL_EOPENSSL, "ssl:getParam");

	return 1;
} /* ssl_getParam() */


static int ssl_setVerify(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	int mode = luaL_optinteger(L, 2, -1);
	int depth = luaL_optinteger(L, 3, -1);

	if (mode != -1)
		SSL_set_verify(ssl, mode, 0);

	if (depth != -1)
		SSL_set_verify_depth(ssl, depth);

	lua_pushboolean(L, 1);

	return 1;
} /* ssl_setVerify() */


static int ssl_getVerify(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);

	lua_pushinteger(L, SSL_get_verify_mode(ssl));
	lua_pushinteger(L, SSL_get_verify_depth(ssl));

	return 2;
} /* ssl_getVerify() */


static int ssl_getVerifyResult(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	long res = SSL_get_verify_result(ssl);
	lua_pushinteger(L, res);
	lua_pushstring(L, X509_verify_cert_error_string(res));
	return 2;
} /* ssl_getVerifyResult() */


static int ssl_setCertificate(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	X509 *crt = X509_dup(checksimple(L, 2, X509_CERT_CLASS));
	int ok;

	ok = SSL_use_certificate(ssl, crt);
	X509_free(crt);

	if (!ok)
		return auxL_error(L, auxL_EOPENSSL, "ssl:setCertificate");

	lua_pushboolean(L, 1);

	return 1;
} /* ssl_setCertificate() */


#if HAVE_SSL_SET1_CHAIN
static int ssl_setCertificateChain(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	STACK_OF(X509) *certs = checksimple(L, 2, X509_CHAIN_CLASS);

	if (!SSL_set1_chain(ssl, certs))
		return auxL_error(L, auxL_EOPENSSL, "ssl:setCertificateChain");

	lua_pushboolean(L, 1);

	return 1;
} /* ssl_setCertificateChain() */
#endif


#if HAVE_SSL_GET0_CHAIN_CERTS
static int ssl_getCertificateChain(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	STACK_OF(X509) *certs;

	if (!SSL_get0_chain_certs(ssl, &certs))
		return auxL_error(L, auxL_EOPENSSL, "ssl:getCertificateChain");

	xl_dup(L, X509_chain_up_ref(certs), 1);

	return 1;
} /* ssl_getCertificateChain() */
#endif


static int ssl_setPrivateKey(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	EVP_PKEY *key = checksimple(L, 2, PKEY_CLASS);
	/*
	 * NOTE: No easy way to dup the key, but a shared reference should
	 * be okay as keys are less mutable than certificates.
	 *
	 * FIXME: SSL_use_PrivateKey will return true even if the
	 * EVP_PKEY object has no private key. Instead, we'll just get a
	 * segfault during the SSL handshake. We need to check that a
	 * private key is actually defined in the object.
	 */
	if (!SSL_use_PrivateKey(ssl, key))
		return auxL_error(L, auxL_EOPENSSL, "ssl:setPrivateKey");

	lua_pushboolean(L, 1);

	return 1;
} /* ssl_setPrivateKey() */


static int ssl_getCertificate(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	X509 *x509;

	if (!(x509 = SSL_get_certificate(ssl)))
		return 0;

	xc_dup(L, x509);

	return 1;
} /* ssl_getCertificate() */


static int ssl_getPeerCertificate(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	X509 **x509 = prepsimple(L, X509_CERT_CLASS);

	if (!(*x509 = SSL_get_peer_certificate(ssl)))
		return 0;

	return 1;
} /* ssl_getPeerCertificate() */


static int ssl_getPeerChain(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	STACK_OF(X509) *chain;

	if (!(chain = SSL_get_peer_cert_chain(ssl)))
		return 0;

	xl_dup(L, chain, 0);

	return 1;
} /* ssl_getPeerChain() */


static int ssl_getCipherInfo(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	const SSL_CIPHER *cipher;
	char descr[256];

	if (!(cipher = SSL_get_current_cipher(ssl)))
		return 0;

	lua_newtable(L);

	lua_pushstring(L, SSL_CIPHER_get_name(cipher));
	lua_setfield(L, -2, "name");

	lua_pushinteger(L, SSL_CIPHER_get_bits(cipher, 0));
	lua_setfield(L, -2, "bits");

	lua_pushstring(L, SSL_CIPHER_get_version(cipher));
	lua_setfield(L, -2, "version");

	lua_pushstring(L, SSL_CIPHER_description(cipher, descr, sizeof descr));
	lua_setfield(L, -2, "description");

	return 1;
} /* ssl_getCipherInfo() */


static int ssl_setCipherList(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	const char *ciphers = luaL_checkstring(L, 2);

	if (!SSL_set_cipher_list(ssl, ciphers))
		return auxL_error(L, auxL_EOPENSSL, "ssl:setCipherList");

	lua_pushboolean(L, 1);

	return 1;
} /* ssl_setCipherList() */


#if HAVE_SSL_SET_CIPHERSUITES
static int ssl_setCipherSuites(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	const char *ciphers = luaL_checkstring(L, 2);

	if (!SSL_set_ciphersuites(ssl, ciphers))
		return auxL_error(L, auxL_EOPENSSL, "ssl:setCipherSuites");

	lua_pushboolean(L, 1);

	return 1;
} /* ssl_setCipherSuites() */
#endif


#if HAVE_SSL_SET_GROUPS_LIST
static int ssl_setGroups(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	const char *list = luaL_checkstring(L, 2);

	if (!SSL_set1_groups_list(ssl, list))
		return auxL_error(L, auxL_EOPENSSL, "ssl:setGroups");

	lua_pushboolean(L, 1);

	return 1;
} /* ssl_setGroups() */
#endif


static int ssl_getHostName(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	const char *host;

	if (!(host = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)))
		return 0;

	lua_pushstring(L, host);

	return 1;
} /* ssl_getHostName() */


static int ssl_setHostName(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	const char *host = luaL_optstring(L, 2, NULL);

	if (!SSL_set_tlsext_host_name(ssl, host))
		return auxL_error(L, auxL_EOPENSSL, "ssl:setHostName");

	lua_pushboolean(L, 1);

	return 1;
} /* ssl_setHostName() */


static int ssl_getVersion(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	int format = luaL_checkoption(L, 2, "d", (const char *[]){ "d", ".", "f", NULL });
	int version = SSL_version(ssl);
	int major, minor;

	switch (format) {
	case 1: case 2:
		major = 0xff & ((version >> 8));
		minor = (0xff & version);

		luaL_argcheck(L, minor < 10, 2, "unable to convert SSL version to float because minor version >= 10");
		lua_pushnumber(L, major + ((double)minor / 10));

		break;
	default:
		lua_pushinteger(L, version);

		break;
	}

	return 1;
} /* ssl_getVersion() */


static int ssl_getClientRandom(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	luaL_Buffer B;
	size_t len;
	unsigned char *out;

	len = SSL_get_client_random(ssl, NULL, 0);
	out = (unsigned char*)luaL_buffinitsize(L, &B, len);
	len = SSL_get_client_random(ssl, out, len);
	luaL_pushresultsize(&B, len);

	return 1;
} /* ssl_getClientRandom() */


static int ssl_getMasterKey(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	SSL_SESSION *session;
	luaL_Buffer B;
	size_t len;
	unsigned char *out;

	session = SSL_get0_session(ssl);
	if (!session) {
		lua_pushnil(L);
		return 1;
	}

	len = SSL_SESSION_get_master_key(session, NULL, 0);
	out = (unsigned char*)luaL_buffinitsize(L, &B, len);
	len = SSL_SESSION_get_master_key(session, out, len);
	luaL_pushresultsize(&B, len);

	return 1;
} /* ssl_getMasterKey() */


#if HAVE_SSL_GET_SERVER_TMP_KEY
static int ssl_getServerTemporaryKey(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	EVP_PKEY **key = prepsimple(L, PKEY_CLASS);

	if (!SSL_get_server_tmp_key(ssl, key))
		return 0;

	return 1;
} /* ssl_getServerTemporaryKey() */
#endif

static int ssl_getClientVersion(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	int format = luaL_checkoption(L, 2, "d", (const char *[]){ "d", ".", "f", NULL });
	int version = SSL_client_version(ssl);
	int major, minor;

	switch (format) {
	case 1: case 2:
		major = 0xff & ((version >> 8));
		minor = (0xff & version);

		luaL_argcheck(L, minor < 10, 2, "unable to convert SSL client version to float because minor version >= 10");
		lua_pushnumber(L, major + ((double)minor / 10));

		break;
	default:
		lua_pushinteger(L, version);

		break;
	}

	return 1;
} /* ssl_getClientVersion() */


#if HAVE_SSL_GET0_ALPN_SELECTED
static int ssl_getAlpnSelected(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	const unsigned char *data;
	unsigned len;
	SSL_get0_alpn_selected(ssl, &data, &len);
	if (0 == len) {
		lua_pushnil(L);
	} else {
		lua_pushlstring(L, (const char *)data, len);
	}
	return 1;
} /* ssl_getAlpnSelected() */
#endif


#if HAVE_SSL_SET_ALPN_PROTOS
static int ssl_setAlpnProtos(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	luaL_Buffer B;
	size_t len;
	const char *tmp;

	luaL_buffinit(L, &B);
	checkprotos(&B, L, 2);
	luaL_pushresult(&B);
	tmp = lua_tolstring(L, -1, &len);

	/* OpenSSL 1.0.2 doesn't update the error stack on failure. */
	ERR_clear_error();
	if (0 != SSL_set_alpn_protos(ssl, (const unsigned char*)tmp, len)) {
		if (!ERR_peek_error()) {
			return luaL_error(L, "unable to set ALPN protocols: %s", aux_strerror(ENOMEM));
		} else {
			return auxL_error(L, auxL_EOPENSSL, "ssl:setAlpnProtos");
		}
	}

	lua_pushboolean(L, 1);

	return 1;
} /* ssl_setAlpnProtos() */
#endif


static int ssl_setTLSextStatusType(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	int type = checkTLSEXT_STATUSTYPE(L, 2);

	if(!SSL_set_tlsext_status_type(ssl, type))
		return auxL_error(L, auxL_EOPENSSL, "ssl:setTLSextStatusType");

	lua_pushboolean(L, 1);

	return 1;
} /* ssl_setTLSextStatusType() */


#if HAVE_SSL_GET_TLSEXT_STATUS_TYPE
static int ssl_getTLSextStatusType(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);

	int type = SSL_get_tlsext_status_type(ssl);
	switch(type) {
	case -1:
		lua_pushnil(L);
		break;
	case TLSEXT_STATUSTYPE_ocsp:
		lua_pushliteral(L, "ocsp");
		break;
	default:
		luaL_error(L, "unknown TLS extension %d", type);
	}

	return 1;
} /* ssl_getTLSextStatusType() */
#endif


static int ssl_setTLSextStatusOCSPResp(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);
	OCSP_RESPONSE *or = testsimple(L, 2, OCSP_RESPONSE_CLASS);

	unsigned char *resp = NULL;
	long resp_len;

	if (or) {
		resp_len = i2d_OCSP_RESPONSE(or, &resp);
		if (resp_len <= 0)
			return auxL_error(L, auxL_EOPENSSL, "ssl:setTLSextStatusOCSPResp");
	} else {
		resp_len = 0;
	}

	if (!SSL_set_tlsext_status_ocsp_resp(ssl, resp, resp_len))
		return auxL_error(L, auxL_EOPENSSL, "ssl:setTLSextStatusOCSPResp");

	lua_pushboolean(L, 1);

	return 1;
} /* ssl_setTLSextStatusOCSPResp() */


static int ssl_getTLSextStatusOCSPResp(lua_State *L) {
	SSL *ssl = checksimple(L, 1, SSL_CLASS);

	OCSP_RESPONSE **ud = prepsimple(L, OCSP_RESPONSE_CLASS);
	const unsigned char *resp;
	long resp_len;

	resp_len = SSL_get_tlsext_status_ocsp_resp(ssl, &resp);
	if (resp == NULL) {
		lua_pushnil(L);
		return 1;
	}
	if (resp_len == -1)
		return auxL_error(L, auxL_EOPENSSL, "ssl:getTLSextStatusOCSPResp");

	*ud = d2i_OCSP_RESPONSE(NULL, &resp, resp_len);
	if(*ud == NULL)
		return auxL_error(L, auxL_EOPENSSL, "ssl:getTLSextStatusOCSPResp");

	return 1;
} /* ssl_getTLSextStatusOCSPResp() */


static int ssl__gc(lua_State *L) {
	SSL **ud = luaL_checkudata(L, 1, SSL_CLASS);

	if (*ud) {
		SSL_free(*ud);
		*ud = NULL;
	}

	return 0;
} /* ssl__gc() */


static const auxL_Reg ssl_methods[] = {
	{ "setContext",       &ssl_setContext },
	{ "getContext",       &ssl_getContext },
	{ "setOptions",       &ssl_setOptions },
	{ "getOptions",       &ssl_getOptions },
	{ "clearOptions",     &ssl_clearOptions },
	{ "setReadAhead",     &ssl_setReadAhead },
	{ "getReadAhead",     &ssl_getReadAhead },
#if HAVE_SSL_SET1_CHAIN_CERT_STORE
	{ "setChainStore",    &ssl_setChainStore },
#endif
#if HAVE_SSL_SET1_VERIFY_CERT_STORE
	{ "setVerifyStore",   &ssl_setVerifyStore },
#endif
	{ "setParam",         &ssl_setParam },
	{ "getParam",         &ssl_getParam },
	{ "setVerify",        &ssl_setVerify },
	{ "getVerify",        &ssl_getVerify },
	{ "getVerifyResult",  &ssl_getVerifyResult },
	{ "setCertificate",   &ssl_setCertificate },
#if HAVE_SSL_SET1_CHAIN
	{ "setCertificateChain", &ssl_setCertificateChain },
#endif
#if HAVE_SSL_GET0_CHAIN_CERTS
	{ "getCertificateChain", &ssl_getCertificateChain },
#endif
	{ "setPrivateKey",    &ssl_setPrivateKey },
	{ "getCertificate",   &ssl_getCertificate },
	{ "getPeerCertificate", &ssl_getPeerCertificate },
	{ "getPeerChain",     &ssl_getPeerChain },
	{ "getCipherInfo",    &ssl_getCipherInfo },
	{ "setCipherList",    &ssl_setCipherList },
#if HAVE_SSL_SET_CIPHERSUITES
	{ "setCipherSuites",  &ssl_setCipherSuites },
#endif
#if HAVE_SSL_SET_GROUPS_LIST
	{ "setCurvesList",    &ssl_setGroups }, /* old alias */
	{ "setGroups",        &ssl_setGroups },
#endif
	{ "getHostName",      &ssl_getHostName },
	{ "setHostName",      &ssl_setHostName },
	{ "getVersion",       &ssl_getVersion },
	{ "getClientRandom",  &ssl_getClientRandom },
	{ "getMasterKey",     &ssl_getMasterKey },
#if HAVE_SSL_GET_SERVER_TMP_KEY
	{ "getServerTemporaryKey", &ssl_getServerTemporaryKey },
#endif
	{ "getClientVersion", &ssl_getClientVersion },
#if HAVE_SSL_GET0_ALPN_SELECTED
	{ "getAlpnSelected",  &ssl_getAlpnSelected },
#endif
#if HAVE_SSL_SET_ALPN_PROTOS
	{ "setAlpnProtos",    &ssl_setAlpnProtos },
#endif
	{ "setTLSextStatusType", &ssl_setTLSextStatusType },
#if HAVE_SSL_GET_TLSEXT_STATUS_TYPE
	{ "getTLSextStatusType", &ssl_getTLSextStatusType },
#endif
	{ "setTLSextStatusOCSPResp", &ssl_setTLSextStatusOCSPResp },
	{ "getTLSextStatusOCSPResp", &ssl_getTLSextStatusOCSPResp },
	{ NULL,            NULL },
};

static const auxL_Reg ssl_metatable[] = {
	{ "__gc", &ssl__gc },
	{ NULL,   NULL },
};

static const auxL_Reg ssl_globals[] = {
	{ "new",       &ssl_new },
	{ "pushffi",   &ssl_pushffi, 1 },
	{ "interpose", &ssl_interpose },
	{ NULL,        NULL },
};

static const auxL_IntegerReg ssl_version[] = {
	{ "SSL2_VERSION", SSL2_VERSION },
	{ "SSL3_VERSION", SSL3_VERSION },
	{ "TLS1_VERSION", TLS1_VERSION },
#if defined TLS1_1_VERSION
	{ "TLS1_1_VERSION", TLS1_1_VERSION },
#endif
#if defined TLS1_2_VERSION
	{ "TLS1_2_VERSION", TLS1_2_VERSION },
#endif
	{ NULL, 0 },
};


EXPORT int luaopen__openssl_ssl(lua_State *L) {
	initall(L);

	auxL_newlib(L, ssl_globals, 0);
	/* FFI argument checking */
	lua_getfield(L, -1, "pushffi");
	luaL_loadstring(L,
		"local ffi = require 'ffi'\n"                 \
		"if not pcall(ffi.typeof, 'SSL*') then\n"     \
		"    ffi.cdef 'typedef struct ssl_st SSL;'\n" \
		"end\n"                                       \
		"local ffi_istype = ffi.istype\n"             \
		"local SSLp = ffi.typeof('SSL*')\n"           \
		"return function(p) return ffi_istype(SSLp, p) end\n"
	);
	if (lua_pcall(L, 0, 1, 0)) {
		/* failed (probably no ffi library available) */
		lua_pop(L, 1);
		/* use dummy function instead */
		luaL_loadstring(L, "return false\n");
	};
	lua_setupvalue(L, -2, 1);
	lua_pop(L, 1);

	auxL_setintegers(L, ssl_version);
	auxL_setintegers(L, sx_verify);
	auxL_setintegers(L, sx_option);

	return 1;
} /* luaopen__openssl_ssl() */


/*
 * X509_VERIFY_PARAM
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int xp_new(lua_State *L) {
	X509_VERIFY_PARAM **ud = prepsimple(L, X509_VERIFY_PARAM_CLASS);

	if (!(*ud = X509_VERIFY_PARAM_new()))
		return auxL_error(L, auxL_EOPENSSL, "x509.verify_param.new");

	return 1;
} /* xp_new() */


static int xp_interpose(lua_State *L) {
	return interpose(L, X509_VERIFY_PARAM_CLASS);
} /* xp_interpose() */


/*
 * NB: Per the OpenSSL source, "[t]he 'inh_flags' field determines how this
 * function behaves". (Referring to X509_VERIFY_PARAM_inherit.) The way to
 * set inh_flags prior to OpenSSL 1.1 was by OR'ing flags into the inh_flags
 * member and restoring it after the call. The OpenSSL 1.1 API makes the
 * X509_VERIFY_PARAM object opaque, X509_VERIFY_PARAM_inherit, and there's
 * no other function to set the flags argument; therefore it's not possible
 * to control the inherit behavior from OpenSSL 1.1.
 *
 * For more details see
 * 	https://github.com/openssl/openssl/issues/2054 and the original
 * 	https://github.com/wahern/luaossl/pull/76/commits/db6e414d68c0f94c2497d363f6131b4de1710ba9
 */
static int xp_inherit(lua_State *L) {
	X509_VERIFY_PARAM *dest = checksimple(L, 1, X509_VERIFY_PARAM_CLASS);
	X509_VERIFY_PARAM *src = testsimple(L, 2, X509_VERIFY_PARAM_CLASS);
	int ret;

	if (!src) {
		luaL_argcheck(L, lua_isstring(L, 2), 2, "expected " X509_VERIFY_PARAM_CLASS " or string");
		src = (X509_VERIFY_PARAM*)X509_VERIFY_PARAM_lookup(lua_tostring(L, 2));
		luaL_argcheck(L, src != NULL, 2, "unknown param preset");
	}

	ret = X509_VERIFY_PARAM_inherit(dest, src);
	if (!ret)
		/* Note: openssl doesn't set an error as it should for some cases */
		return auxL_error(L, auxL_EOPENSSL, "x509.verify_param:inherit");

	lua_pushboolean(L, 1);
	return 1;
} /* xp_inherit() */


static const X509_PURPOSE *purpose_checktype(lua_State *L, int index) {
	const char *purpose_name;
	int purpose_id;
	int purpose_idx;
	const X509_PURPOSE *purpose;

	if (lua_isnumber(L, index)) {
		purpose_id = luaL_checkinteger(L, index);
		purpose_idx = X509_PURPOSE_get_by_id(purpose_id);
		if (purpose_idx < 0)
			luaL_argerror(L, index, lua_pushfstring(L, "%d: invalid purpose", purpose_id));
	} else {
		purpose_name = luaL_checkstring(L, index);
		purpose_idx = X509_PURPOSE_get_by_sname((char*)purpose_name);
		if (purpose_idx < 0)
			luaL_argerror(L, index, lua_pushfstring(L, "%s: invalid purpose", purpose_name));
	}

	purpose = X509_PURPOSE_get0(purpose_idx);
	return purpose;
} /* purpose_checktype() */


static int xp_setPurpose(lua_State *L) {
	X509_VERIFY_PARAM *xp = checksimple(L, 1, X509_VERIFY_PARAM_CLASS);
	const X509_PURPOSE *purpose = purpose_checktype(L, 2);

	if (!X509_VERIFY_PARAM_set_purpose(xp, X509_PURPOSE_get_id((X509_PURPOSE*)purpose)))
		return auxL_error(L, auxL_EOPENSSL, "x509.verify_param:setPurpose");

	lua_pushboolean(L, 1);
	return 1;
} /* xp_setPurpose() */


static int xp_setTime(lua_State *L) {
	X509_VERIFY_PARAM *xp = checksimple(L, 1, X509_VERIFY_PARAM_CLASS);
	time_t t = luaL_checkinteger(L, 2);

	X509_VERIFY_PARAM_set_time(xp, t);

	lua_pushboolean(L, 1);
	return 1;
} /* xp_setTime() */


static int xp_setDepth(lua_State *L) {
	X509_VERIFY_PARAM *xp = checksimple(L, 1, X509_VERIFY_PARAM_CLASS);
	int depth = luaL_checkinteger(L, 2);

	X509_VERIFY_PARAM_set_depth(xp, depth);

	lua_pushboolean(L, 1);
	return 1;
} /* xp_setDepth() */


static int xp_getDepth(lua_State *L) {
	X509_VERIFY_PARAM *xp = checksimple(L, 1, X509_VERIFY_PARAM_CLASS);

	int depth = X509_VERIFY_PARAM_get_depth(xp);

	lua_pushinteger(L, depth);
	return 1;
} /* xp_getDepth() */


#if HAVE_X509_VERIFY_PARAM_SET_AUTH_LEVEL
static int xp_setAuthLevel(lua_State *L) {
	X509_VERIFY_PARAM *xp = checksimple(L, 1, X509_VERIFY_PARAM_CLASS);
	int auth_level = luaL_checkinteger(L, 2);

	X509_VERIFY_PARAM_set_auth_level(xp, auth_level);

	lua_pushboolean(L, 1);
	return 1;
} /* xp_setAuthLevel() */


static int xp_getAuthLevel(lua_State *L) {
	X509_VERIFY_PARAM *xp = checksimple(L, 1, X509_VERIFY_PARAM_CLASS);

	int auth_level = X509_VERIFY_PARAM_get_auth_level(xp);

	lua_pushinteger(L, auth_level);
	return 1;
} /* xp_getAuthLevel() */
#endif


#if HAVE_X509_VERIFY_PARAM_SET1_HOST
static int xp_setHost(lua_State *L) {
	X509_VERIFY_PARAM *xp = checksimple(L, 1, X509_VERIFY_PARAM_CLASS);
	size_t len;
	const char *str = luaL_optlstring(L, 2, NULL, &len); /* NULL = clear hosts */

	if (!X509_VERIFY_PARAM_set1_host(xp, str, len))
		/* Note: openssl doesn't set an error as it should for some cases */
		return auxL_error(L, auxL_EOPENSSL, "x509.verify_param:setHost");

	lua_pushboolean(L, 1);
	return 1;
} /* xp_setHost() */
#endif


#if HAVE_X509_VERIFY_PARAM_ADD1_HOST
static int xp_addHost(lua_State *L) {
	X509_VERIFY_PARAM *xp = checksimple(L, 1, X509_VERIFY_PARAM_CLASS);
	size_t len;
	const char *str = luaL_checklstring(L, 2, &len);

	if (!X509_VERIFY_PARAM_add1_host(xp, str, len))
		/* Note: openssl doesn't set an error as it should for some cases */
		return auxL_error(L, auxL_EOPENSSL, "x509.verify_param:addHost");

	lua_pushboolean(L, 1);
	return 1;
} /* xp_addHost() */
#endif


#if HAVE_X509_VERIFY_PARAM_SET1_EMAIL
static int xp_setEmail(lua_State *L) {
	X509_VERIFY_PARAM *xp = checksimple(L, 1, X509_VERIFY_PARAM_CLASS);
	size_t len;
	const char *str = luaL_checklstring(L, 2, &len);

	if (!X509_VERIFY_PARAM_set1_email(xp, str, len))
		/* Note: openssl doesn't set an error as it should for some cases */
		return auxL_error(L, auxL_EOPENSSL, "x509.verify_param:setEmail");

	lua_pushboolean(L, 1);
	return 1;
} /* xp_setEmail() */
#endif


#if HAVE_X509_VERIFY_PARAM_SET1_IP_ASC
static int xp_setIP(lua_State *L) {
	X509_VERIFY_PARAM *xp = checksimple(L, 1, X509_VERIFY_PARAM_CLASS);
	const char *str = luaL_checkstring(L, 2);

	if (!X509_VERIFY_PARAM_set1_ip_asc(xp, str))
		/* Note: openssl doesn't set an error as it should for some cases */
		return auxL_error(L, auxL_EOPENSSL, "x509.verify_param:setIP");

	lua_pushboolean(L, 1);
	return 1;
} /* xp_setIP() */
#endif


static int xp__gc(lua_State *L) {
	X509_VERIFY_PARAM **ud = luaL_checkudata(L, 1, X509_VERIFY_PARAM_CLASS);

	X509_VERIFY_PARAM_free(*ud);
	*ud = NULL;

	return 0;
} /* xp__gc() */


static const auxL_Reg xp_methods[] = {
	{ "inherit", &xp_inherit },
	{ "setPurpose", &xp_setPurpose },
	{ "setTime", &xp_setTime },
	{ "setDepth", &xp_setDepth },
	{ "getDepth", &xp_getDepth },
#if HAVE_X509_VERIFY_PARAM_SET_AUTH_LEVEL
	{ "setAuthLevel", &xp_setAuthLevel },
	{ "getAuthLevel", &xp_getAuthLevel },
#endif
#if HAVE_X509_VERIFY_PARAM_SET1_HOST
	{ "setHost", &xp_setHost },
#endif
#if HAVE_X509_VERIFY_PARAM_ADD1_HOST
	{ "addHost", &xp_addHost },
#endif
#if HAVE_X509_VERIFY_PARAM_SET1_EMAIL
	{ "setEmail", &xp_setEmail },
#endif
#if HAVE_X509_VERIFY_PARAM_SET1_IP_ASC
	{ "setIP", &xp_setIP },
#endif
	{ NULL, NULL },
};

static const auxL_Reg xp_metatable[] = {
	{ "__gc", &xp__gc },
	{ NULL, NULL },
};

static const auxL_Reg xp_globals[] = {
	{ "new", &xp_new },
	{ "interpose", &xp_interpose },
	{ NULL, NULL },
};

static const auxL_IntegerReg xp_inherit_flags[] = {
	{ "DEFAULT", X509_VP_FLAG_DEFAULT },
	{ "OVERWRITE", X509_VP_FLAG_OVERWRITE },
	{ "RESET_FLAGS", X509_VP_FLAG_RESET_FLAGS },
	{ "LOCKED", X509_VP_FLAG_LOCKED },
	{ "ONCE", X509_VP_FLAG_ONCE },
	{ NULL, 0 }
};

EXPORT int luaopen__openssl_x509_verify_param(lua_State *L) {
	initall(L);

	auxL_newlib(L, xp_globals, 0);
	auxL_setintegers(L, xp_inherit_flags);

	return 1;
} /* luaopen__openssl_x509_verify_param() */


/*
 * Digest - openssl.digest
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


static const EVP_MD *md_checkdigest(lua_State *L, int index) {
	const char *name = luaL_checkstring(L, index);
	const EVP_MD *type;

	if (!(type = EVP_get_digestbyname(name)))
		luaL_argerror(L, index, lua_pushfstring(L, "%s: invalid digest type", name));

	return type;
} /* md_checkdigest() */


static const EVP_MD *md_optdigest(lua_State *L, int index) {
	if (lua_isnoneornil(L, index))
		return EVP_get_digestbyname("sha1");

	return md_checkdigest(L, index);
} /* md_optdigest() */


static int md_new(lua_State *L) {
	const EVP_MD *type = md_optdigest(L, 1);
	EVP_MD_CTX **ctx;

	ctx = prepsimple(L, DIGEST_CLASS, NULL);
	if (!(*ctx = EVP_MD_CTX_new()) || !EVP_DigestInit_ex(*ctx, type, NULL))
		return auxL_error(L, auxL_EOPENSSL, "digest.new");

	return 1;
} /* md_new() */


static int md_interpose(lua_State *L) {
	return interpose(L, DIGEST_CLASS);
} /* md_interpose() */


static void md_update_(lua_State *L, EVP_MD_CTX *ctx, int from, int to) {
	int i;

	for (i = from; i <= to; i++) {
		const void *p;
		size_t n;

		p = luaL_checklstring(L, i, &n);

		if (!EVP_DigestUpdate(ctx, p, n))
			auxL_error(L, auxL_EOPENSSL, "digest:update");
	}
} /* md_update_() */


static int md_update(lua_State *L) {
	EVP_MD_CTX *ctx = checksimple(L, 1, DIGEST_CLASS);

	md_update_(L, ctx, 2, lua_gettop(L));

	lua_pushvalue(L, 1);

	return 1;
} /* md_update() */


static int md_final(lua_State *L) {
	EVP_MD_CTX *ctx = checksimple(L, 1, DIGEST_CLASS);
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned len;

	md_update_(L, ctx, 2, lua_gettop(L));

	if (!EVP_DigestFinal_ex(ctx, md, &len))
		return auxL_error(L, auxL_EOPENSSL, "digest:final");

	lua_pushlstring(L, (char *)md, len);

	return 1;
} /* md_final() */


static int md__gc(lua_State *L) {
	EVP_MD_CTX **ctx = luaL_checkudata(L, 1, DIGEST_CLASS);

	EVP_MD_CTX_free(*ctx);
	*ctx = NULL;

	return 0;
} /* md__gc() */


static const auxL_Reg md_methods[] = {
	{ "update", &md_update },
	{ "final",  &md_final },
	{ NULL,     NULL },
};

static const auxL_Reg md_metatable[] = {
	{ "__gc", &md__gc },
	{ NULL,   NULL },
};

static const auxL_Reg md_globals[] = {
	{ "new",       &md_new },
	{ "interpose", &md_interpose },
	{ NULL,        NULL },
};

EXPORT int luaopen__openssl_digest(lua_State *L) {
	initall(L);

	auxL_newlib(L, md_globals, 0);

	return 1;
} /* luaopen__openssl_digest() */


/*
 * HMAC - openssl.hmac
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int hmac_new(lua_State *L) {
	const void *key;
	size_t len;
	const EVP_MD *type;
	HMAC_CTX **ctx;

	key = luaL_checklstring(L, 1, &len);
	type = md_optdigest(L, 2);

	ctx = prepsimple(L, HMAC_CLASS, NULL);
	if (!(*ctx = HMAC_CTX_new()))
		goto eossl;

#if HMAC_INIT_EX_INT
	if (!HMAC_Init_ex(*ctx, key, len, type, NULL))
		goto eossl;
#else
	HMAC_Init_ex(*ctx, key, len, type, NULL);
#endif

	return 1;
eossl:
	return auxL_error(L, auxL_EOPENSSL, "hmac.new");
} /* hmac_new() */


static int hmac_interpose(lua_State *L) {
	return interpose(L, HMAC_CLASS);
} /* hmac_interpose() */


static void hmac_update_(lua_State *L, HMAC_CTX *ctx, int from, int to) {
	int i;

	for (i = from; i <= to; i++) {
		const void *p;
		size_t n;

		p = luaL_checklstring(L, i, &n);

		HMAC_Update(ctx, p, n);
	}
} /* hmac_update_() */


static int hmac_update(lua_State *L) {
	HMAC_CTX *ctx = checksimple(L, 1, HMAC_CLASS);

	hmac_update_(L, ctx, 2, lua_gettop(L));

	lua_pushvalue(L, 1);

	return 1;
} /* hmac_update() */


static int hmac_final(lua_State *L) {
	HMAC_CTX *ctx = checksimple(L, 1, HMAC_CLASS);
	unsigned char hmac[EVP_MAX_MD_SIZE];
	unsigned len;

	hmac_update_(L, ctx, 2, lua_gettop(L));

	HMAC_Final(ctx, hmac, &len);

	lua_pushlstring(L, (char *)hmac, len);

	return 1;
} /* hmac_final() */


static int hmac__gc(lua_State *L) {
	HMAC_CTX **ctx = luaL_checkudata(L, 1, HMAC_CLASS);

	HMAC_CTX_free(*ctx);
	*ctx = NULL;

	return 0;
} /* hmac__gc() */


static const auxL_Reg hmac_methods[] = {
	{ "update", &hmac_update },
	{ "final",  &hmac_final },
	{ NULL,     NULL },
};

static const auxL_Reg hmac_metatable[] = {
	{ "__gc", &hmac__gc },
	{ NULL,   NULL },
};

static const auxL_Reg hmac_globals[] = {
	{ "new",       &hmac_new },
	{ "interpose", &hmac_interpose },
	{ NULL,        NULL },
};

EXPORT int luaopen__openssl_hmac(lua_State *L) {
	initall(L);

	auxL_newlib(L, hmac_globals, 0);

	return 1;
} /* luaopen__openssl_hmac() */


/*
 * Cipher - openssl.cipher
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static const EVP_CIPHER *cipher_checktype(lua_State *L, int index) {
	const char *name = luaL_checkstring(L, index);
	const EVP_CIPHER *type;

	if (!(type = EVP_get_cipherbyname(name)))
		luaL_argerror(L, index, lua_pushfstring(L, "%s: invalid cipher type", name));

	return type;
} /* cipher_checktype() */


static int cipher_new(lua_State *L) {
	const EVP_CIPHER *type;
	EVP_CIPHER_CTX **ctx;
	unsigned char key[EVP_MAX_KEY_LENGTH] = { 0 };

	type = cipher_checktype(L, 1);

	ctx = prepsimple(L, CIPHER_CLASS, NULL);
	if (!(*ctx = EVP_CIPHER_CTX_new()))
		goto eossl;

	/*
	 * NOTE: For some ciphers like AES calling :update or :final without
	 * setting a key causes a SEGV. Set a dummy key here. Same solution
	 * as used by Ruby OSSL.
	 */
	if (!EVP_CipherInit_ex(*ctx, type, NULL, key, NULL, -1))
		goto eossl;

	return 1;
eossl:
	return auxL_error(L, auxL_EOPENSSL, "cipher.new");
} /* cipher_new() */


static int cipher_interpose(lua_State *L) {
	return interpose(L, CIPHER_CLASS);
} /* cipher_interpose() */


static int cipher_init(lua_State *L, _Bool encrypt) {
	EVP_CIPHER_CTX *ctx = checksimple(L, 1, CIPHER_CLASS);
	const void *key, *iv;
	size_t n, m;

	key = luaL_checklstring(L, 2, &n);
	m = (size_t)EVP_CIPHER_CTX_key_length(ctx);
	luaL_argcheck(L, n == m, 2, lua_pushfstring(L, "%d: invalid key length (should be %d)", (int)n, (int)m));

	iv = luaL_optlstring(L, 3, NULL, &n);
	/* Set the IV length before init */
#if defined EVP_CTRL_AEAD_SET_IVLEN
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, n, NULL) <= 0) {
#elif defined EVP_CTRL_GCM_SET_IVLEN
	/* https://github.com/openssl/openssl/issues/8330#issuecomment-516838331 */
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, n, NULL) <= 0) {
#else
	{
#endif
		/* wasn't able to set IV len; check if it's already correct */
		m = (size_t)EVP_CIPHER_CTX_iv_length(ctx);
		luaL_argcheck(L, n == m, 3, lua_pushfstring(L, "%d: invalid IV length (should be %d)", (int)n, (int)m));
	}

	if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, encrypt))
		goto sslerr;

	if (!lua_isnoneornil(L, 4)) {
		luaL_checktype(L, 4, LUA_TBOOLEAN);

		if (!EVP_CIPHER_CTX_set_padding(ctx, lua_toboolean(L, 4)))
			goto sslerr;
	}

	lua_settop(L, 1);

	return 1;
sslerr:
	return auxL_error(L, auxL_EOPENSSL, (encrypt)? "cipher:encrypt" : "cipher:decrypt");
} /* cipher_init() */


static int cipher_encrypt(lua_State *L) {
	return cipher_init(L, 1);
} /* cipher_encrypt() */


static int cipher_decrypt(lua_State *L) {
	return cipher_init(L, 0);
} /* cipher_decrypt() */


static _Bool cipher_update_(lua_State *L, EVP_CIPHER_CTX *ctx, luaL_Buffer *B, int from, int to) {
	const unsigned char *p;
	size_t n;
	int i, out;

	for (i = from; i <= to; i++) {
		p = (const unsigned char *)luaL_checklstring(L, i, &n);

		if (!EVP_CipherUpdate(ctx, (void *)luaL_prepbuffsize(B, n+EVP_MAX_BLOCK_LENGTH), &out, p, n))
			return 0;

		luaL_addsize(B, out);
	}

	return 1;
} /* cipher_update_() */


static int cipher_update(lua_State *L) {
	EVP_CIPHER_CTX *ctx = checksimple(L, 1, CIPHER_CLASS);
	luaL_Buffer B;
	int top = lua_gettop(L);

	luaL_buffinit(L, &B);

	if (!cipher_update_(L, ctx, &B, 2, top))
		goto sslerr;

	luaL_pushresult(&B);

	return 1;
sslerr:
	lua_pushnil(L);
	auxL_pusherror(L, auxL_EOPENSSL, NULL);

	return 2;
} /* cipher_update() */


static int cipher_final(lua_State *L) {
	EVP_CIPHER_CTX *ctx = checksimple(L, 1, CIPHER_CLASS);
	luaL_Buffer B;
	size_t block;
	int out;
	int top = lua_gettop(L);

	luaL_buffinit(L, &B);

	if (!cipher_update_(L, ctx, &B, 2, top))
		goto sslerr;

	block = EVP_CIPHER_CTX_block_size(ctx);

	if (!EVP_CipherFinal(ctx, (void *)luaL_prepbuffsize(&B, block), &out))
		goto sslerr;

	luaL_pushresultsize(&B, out);

	return 1;
sslerr:
	lua_pushnil(L);
	auxL_pusherror(L, auxL_EOPENSSL, NULL);

	return 2;
} /* cipher_final() */


static int cipher_get_tag(lua_State *L) {
	EVP_CIPHER_CTX *ctx = checksimple(L, 1, CIPHER_CLASS);
	luaL_Buffer tag;
	size_t tag_size = luaL_checkinteger(L, 2);

	luaL_buffinit(L, &tag);

	/* EVP_CTRL_GCM_GET_TAG is works for both GCM and CCM and across all
	 * supported OpenSSL versions. We can switch to the unified identifier
	 * 'EVP_CTRL_AEAD_GET_TAG' in OpenSSL 1.1+.
	 */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_size, (void*)luaL_prepbuffsize(&tag, tag_size))) {
		goto sslerr;
	}

	luaL_pushresultsize(&tag, tag_size);

	return 1;

sslerr:
	lua_pushnil(L);
	auxL_pusherror(L, auxL_EOPENSSL, NULL);

	return 2;
} /* cipher_get_tag() */


static int cipher_set_tag(lua_State *L) {
	EVP_CIPHER_CTX *ctx = checksimple(L, 1, CIPHER_CLASS);
	size_t tag_size;
	const char* tag = luaL_checklstring(L, 2, &tag_size);
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_size, (void*)tag)) {
		goto sslerr;
	}

	lua_pushlstring(L, tag, tag_size);

	return 1;

sslerr:
	lua_pushnil(L);
	auxL_pusherror(L, auxL_EOPENSSL, NULL);

	return 2;
} /* cipher_set_tag() */


static int cipher__gc(lua_State *L) {
	EVP_CIPHER_CTX **ctx = luaL_checkudata(L, 1, CIPHER_CLASS);

	EVP_CIPHER_CTX_free(*ctx);
	*ctx = NULL;

	return 0;
} /* cipher__gc() */


static const auxL_Reg cipher_methods[] = {
	{ "encrypt", &cipher_encrypt },
	{ "decrypt", &cipher_decrypt },
	{ "update",  &cipher_update },
	{ "final",   &cipher_final },
	{ "getTag",  &cipher_get_tag },
	{ "setTag",  &cipher_set_tag },
	{ NULL,      NULL },
};

static const auxL_Reg cipher_metatable[] = {
	{ "__gc", &cipher__gc },
	{ NULL,   NULL },
};

static const auxL_Reg cipher_globals[] = {
	{ "new",       &cipher_new },
	{ "interpose", &cipher_interpose },
	{ NULL,        NULL },
};

EXPORT int luaopen__openssl_cipher(lua_State *L) {
	initall(L);

	auxL_newlib(L, cipher_globals, 0);

	return 1;
} /* luaopen__openssl_cipher() */


/*
 * openssl.kdf
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int EVP_KDF__gc(lua_State *L) {
	EVP_KDF_CTX **res = lua_touserdata(L, 1);

	if (*res) {
		EVP_KDF_CTX_free(*res);
		*res = NULL;
	}

	return 0;
} /* EVP_KDF__gc() */


static int kdf_derive(lua_State *L) {
	LUAOSSL_EVP_KDF_PTR kdf;
	luaL_Buffer b;
	EVP_KDF_CTX *kctx, **kctxp;
#if HAVE_OSSL_PARAM
	OSSL_PARAM params[15], *param = params;
#endif
	unsigned char* out;
	size_t outlen = 0;
	const char *str = NULL;
	size_t len;
	_Bool seed = 0;
	int mode;
	unsigned int iter;
	uint64_t maxmem_bytes, scrypt_n;
	uint32_t scrypt_r, scrypt_p;

	luaL_checktype(L, 1, LUA_TTABLE);

	{
		const char* type;
		if (!loadfield(L, 1, "type", LUA_TSTRING, &type))
			return luaL_argerror(L, 1, "missing 'type' field");
		if ((kdf = EVP_KDF_fetch(NULL, type, NULL)) == LUAOSSL_EVP_KDF_UNDEF)
			return luaL_argerror(L, 1, "unknown 'type'");
	}

	/* ensure EVP_KDF_CTX is collected on error */
	kctxp = prepudata(L, sizeof(EVP_KDF_CTX*), NULL, &EVP_KDF__gc);
	if (!(kctx = EVP_KDF_CTX_new(kdf)))
		return auxL_error(L, auxL_EOPENSSL, "kdf.derive");
	*kctxp = kctx;


	lua_pushnil(L);
	while (lua_next(L, 1)) {
		switch (auxL_testoption(L, -2, 0, (const char *[]){
			/* special fields */
			"type",
			"outlen",
			/* general options */
			"pass",
			"salt",
			"iter",
			"md",
			"key",
			"maxmem_bytes",
			/* KDF specific */
			"secret",
			"seed",
			"info",
			"hkdf_mode",
			"N",
			"r",
			"p",
		NULL }, 0)) {
		case 0: /* skip 'type' */
			break;

		case 1:
			outlen = auxL_checkunsigned(L, -1, 1, SIZE_MAX-1);
			break;

		case 2:
			str = luaL_checklstring(L, -1, &len);
#if HAVE_OSSL_PARAM
			*param++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)str, len);
#else
			if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_PASS, (const unsigned char*)str, len) <= 0)
				goto error;
#endif
			break;

		case 3:
			str = luaL_checklstring(L, -1, &len);
#if HAVE_OSSL_PARAM
			*param++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)str, len);
#else
			if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, (const unsigned char*)str, len) <= 0)
				goto error;
#endif
			break;

		case 4:
			iter = auxL_checkunsigned(L, -1, 1, (int)-1);
#if HAVE_OSSL_PARAM
			*param++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iter);
#else
			if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_ITER, iter) <= 0)
				goto error;
#endif
			break;

		case 5:
#if HAVE_OSSL_PARAM
			str = luaL_checklstring(L, -1, &len);
			*param++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (void *)str, len);
#else
			if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, md_checkdigest(L, -1)) <= 0)
				goto error;
#endif
			break;

		case 6:
			str = luaL_checklstring(L, -1, &len);
#if HAVE_OSSL_PARAM
			*param++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)str, len);
#else
			if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_KEY, (const unsigned char*)str, len) <= 0)
				goto error;
#endif
			break;

		case 7:
			maxmem_bytes = auxL_checkunsigned(L, -1, 0, UINT64_MAX);
#if HAVE_OSSL_PARAM
			*param++ = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM, &maxmem_bytes);
#else
			if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MAXMEM_BYTES, maxmem_bytes) <= 0)
				goto error;
#endif
			break;

		case 8:
			str = luaL_checklstring(L, -1, &len);
#if HAVE_OSSL_PARAM
			*param++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, (void *)str, len);
#else
			if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_TLS_SECRET, (const unsigned char*)str, len) <= 0)
				goto error;
#endif
			break;

		case 9:
			str = luaL_checklstring(L, -1, &len);
#if HAVE_OSSL_PARAM
			*param++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, (void *)str, len);
#else
            seed = 1;
#endif
			break;

		case 10:
			str = luaL_checklstring(L, -1, &len);
#if HAVE_OSSL_PARAM
			*param++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)str, len);
#else
			if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_ADD_HKDF_INFO, (const unsigned char*)str, len) <= 0)
				goto error;
#endif
			break;

		case 11:
			mode = ((int[]){
#ifdef EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
				EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND,
#endif
#ifdef EVP_KDF_HKDF_MODE_EXTRACT_ONLY
				EVP_KDF_HKDF_MODE_EXTRACT_ONLY,
#endif
#ifdef EVP_KDF_HKDF_MODE_EXPAND_ONLY
				EVP_KDF_HKDF_MODE_EXPAND_ONLY,
#endif
			0 })[auxL_checkoption(L, -1, 0, (const char *[]){
#ifdef EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
				"extract_and_expand",
#endif
#ifdef EVP_KDF_HKDF_MODE_EXTRACT_ONLY
				"extract_only",
#endif
#ifdef EVP_KDF_HKDF_MODE_EXPAND_ONLY
				"expand_only",
#endif
			NULL }, 0)];
#if HAVE_OSSL_PARAM
			*param++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
#else
			if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_HKDF_MODE, mode) <= 0)
				goto error;
#endif
			break;

		case 12:
			scrypt_n = auxL_checkunsigned(L, -1, 0, UINT64_MAX);
#if HAVE_OSSL_PARAM
			*param++ = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &scrypt_n);
#else
			if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SCRYPT_N, scrypt_n) <= 0)
				goto error;
#endif
			break;

		case 13:
			scrypt_r = auxL_checkunsigned(L, -1, 0, UINT32_MAX);
#if HAVE_OSSL_PARAM
			*param++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R, &scrypt_r);
#else
			if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SCRYPT_R, scrypt_r) <= 0)
				goto error;
#endif
			break;

		case 14:
			scrypt_p = auxL_checkunsigned(L, -1, 0, UINT32_MAX);
#if HAVE_OSSL_PARAM
			*param++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P, &scrypt_p);
#else
			if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SCRYPT_P, scrypt_p) <= 0)
				goto error;
#endif
			break;

		default:
			return luaL_argerror(L, 1, lua_pushfstring(L, "unknown field '%s'", lua_tostring(L, -2)));
		}
		lua_pop(L, 1);
	}

#if HAVE_OSSL_PARAM
	*param = OSSL_PARAM_construct_end();

	if(EVP_KDF_CTX_set_params(kctx,params) <= 0) {
		goto error;
	}
#else
	/* XXX: seed must be set *after* secret
	 * https://github.com/openssl/openssl/issues/7728 */
	if (seed) {
		lua_getfield(L, 1, "seed");
		str = luaL_checklstring(L, -1, &len);
		if (EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_ADD_TLS_SEED, (const unsigned char*)str, len) <= 0)
			goto error;
		lua_pop(L, 1);
	}
#endif

	if (outlen == 0) {
		outlen = EVP_KDF_CTX_get_kdf_size(kctx);
		if (outlen == 0)
			goto error;
		if (outlen == SIZE_MAX)
			return luaL_argerror(L, 1, "missing 'outlen' field");
	}

	out = (unsigned char *)luaL_buffinitsize(L, &b, outlen);

	if (EVP_KDF_derive(kctx, out, outlen, NULL) <= 0)
		goto error;

	EVP_KDF_CTX_free(kctx);
	*kctxp = NULL;

	luaL_pushresultsize(&b, outlen);

	return 1;

error:
	if (*kctxp) {
		EVP_KDF_CTX_free(kctx);
		*kctxp = NULL;
	}
	return auxL_error(L, auxL_EOPENSSL, "kdf.derive");
} /* kdf_derive */


static const auxL_Reg kdf_globals[] = {
	{ "derive",    &kdf_derive },
	{ NULL,        NULL },
};

int luaopen__openssl_kdf(lua_State *L) {
	initall(L);

	auxL_newlib(L, kdf_globals, 0);

	return 1;
} /* luaopen__openssl_kdf() */


/*
 * OCSP_RESPONSE - openssl.ocsp.response
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int or_tostring(lua_State *L) {
	OCSP_RESPONSE *resp = checksimple(L, 1, OCSP_RESPONSE_CLASS);
	BIO *bio = getbio(L);
	size_t len;
	char *bytes;

	if (!OCSP_RESPONSE_print(bio, resp, 0))
		return auxL_error(L, auxL_EOPENSSL, "OCSP_RESPONSE:tostring");

	len = BIO_get_mem_data(bio, &bytes);
	lua_pushlstring(L, bytes, len);

	return 1;
} /* or__tostring() */


static int or_toPEM(lua_State *L) {
	OCSP_RESPONSE *resp = checksimple(L, 1, OCSP_RESPONSE_CLASS);
	BIO *bio = getbio(L);
	size_t len;
	char *bytes;

	if (!PEM_write_bio_OCSP_RESPONSE(bio, resp))
		return auxL_error(L, auxL_EOPENSSL, "OCSP_RESPONSE:toPEM");

	len = BIO_get_mem_data(bio, &bytes);
	lua_pushlstring(L, bytes, len);

	return 1;
} /* or_toPEM() */


static int or_getBasic(lua_State *L) {
	OCSP_RESPONSE *resp = checksimple(L, 1, OCSP_RESPONSE_CLASS);

	OCSP_BASICRESP **basic = prepsimple(L, OCSP_BASICRESP_CLASS);

	*basic = OCSP_response_get1_basic(resp);
	if (!*basic)
		return auxL_error(L, auxL_EOPENSSL, "OCSP_RESPONSE:getBasic");

	return 1;
} /* or_getBasic() */


static int or__gc(lua_State *L) {
	OCSP_RESPONSE **ud = luaL_checkudata(L, 1, OCSP_RESPONSE_CLASS);

	if (*ud) {
		OCSP_RESPONSE_free(*ud);
		*ud = NULL;
	}

	return 0;
} /* or__gc() */

static const auxL_Reg or_methods[] = {
	{ "tostring", &or_tostring },
	{ "toPEM",    &or_toPEM },
	{ "getBasic", &or_getBasic },
	{ NULL,       NULL },
};

static const auxL_Reg or_metatable[] = {
	{ "__tostring", &or_tostring },
	{ "__gc",       &or__gc },
	{ NULL,         NULL },
};

static const auxL_Reg or_globals[] = {
	{ NULL, NULL },
};

EXPORT int luaopen__openssl_ocsp_response(lua_State *L) {
	initall(L);

	auxL_newlib(L, or_globals, 0);

	return 1;
} /* luaopen__openssl_ocsp_response() */


/*
 * OCSP_BASICRESP - openssl.ocsp.basic
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int ob_verify(lua_State *L) {
	OCSP_BASICRESP *basic = checksimple(L, 1, OCSP_BASICRESP_CLASS);
	STACK_OF(X509) *certs = testsimple(L, 2, X509_CHAIN_CLASS);
	X509_STORE *store = testsimple(L, 3, X509_STORE_CLASS);
	unsigned long flags = luaL_optinteger(L, 4, 0);

	int res = OCSP_basic_verify(basic, certs, store, flags);
	if (res == -1)
		return auxL_error(L, auxL_EOPENSSL, "OCSP_BASICRESP:verify");

	lua_pushboolean(L, res);
	if (res) {
		return 1;
	} else {
		auxL_pusherror(L, auxL_EOPENSSL, NULL);
		return 2;
	}
} /* ob_verify() */


static int ob__gc(lua_State *L) {
	OCSP_BASICRESP **ud = luaL_checkudata(L, 1, OCSP_BASICRESP_CLASS);

	if (*ud) {
		OCSP_BASICRESP_free(*ud);
		*ud = NULL;
	}

	return 0;
} /* or__gc() */


static const auxL_Reg ob_methods[] = {
	{ "verify", &ob_verify },
	{ NULL, NULL },
};

static const auxL_Reg ob_metatable[] = {
	{ "__gc", &ob__gc },
	{ NULL,   NULL },
};

static const auxL_Reg ob_globals[] = {
	{ NULL,   NULL },
};

static const auxL_IntegerReg ob_verify_flags[] = {
	{ "NOSIGS", OCSP_NOSIGS},
	{ "NOVERIFY", OCSP_NOVERIFY},
	{ "NOCHAIN", OCSP_NOCHAIN},
	{ "NOCHECKS", OCSP_NOCHECKS},
	{ "NOEXPLICIT", OCSP_NOEXPLICIT},
	{ "TRUSTOTHER", OCSP_TRUSTOTHER},
	{ "NOINTERN", OCSP_NOINTERN},
	{ "TRUSTOTHER", OCSP_TRUSTOTHER},
	{ NULL, 0 },
};

EXPORT int luaopen__openssl_ocsp_basic(lua_State *L) {
	initall(L);

	auxL_newlib(L, ob_globals, 0);
	auxL_setintegers(L, ob_verify_flags);

	return 1;
} /* luaopen__openssl_ocsp_basic() */


/*
 * Rand - openssl.rand
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct randL_state {
#ifdef _WIN32
	DWORD pid;
#else
	pid_t pid;
#endif
}; /* struct randL_state */

static struct randL_state *randL_getstate(lua_State *L) {
	return lua_touserdata(L, lua_upvalueindex(1));
} /* randL_getstate() */

#if HAVE_SYS_SYSCALL_H
#include <sys/syscall.h> /* SYS_getrandom syscall(2) */
#endif

#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h> /* CTL_KERN KERN_RANDOM RANDOM_UUID sysctl(2) */
#endif

static int randL_stir(struct randL_state *st, unsigned rqstd) {
	unsigned count = 0;
	int error;
	unsigned char data[256];

#ifdef _WIN32
	HCRYPTPROV hCryptProv;
	BOOL ok;

	if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		error = GetLastError();
		goto error;
	}
	while (count < rqstd) {
		ok = CryptGenRandom(hCryptProv, sizeof data, (BYTE*)data);
		if (!ok) {
			CryptReleaseContext(hCryptProv, 0);
			error = GetLastError();
			goto error;
		}

		RAND_seed(data, sizeof data);

		count += sizeof data;
	}

	CryptReleaseContext(hCryptProv, 0);

	st->pid = GetCurrentProcessId();
#else
#if HAVE_ARC4RANDOM_BUF
	while (count < rqstd) {
		size_t n = MIN(rqstd - count, sizeof data);

		arc4random_buf(data, n);

		RAND_seed(data, n);

		count += n;
	}
#endif

#if HAVE_SYSCALL && HAVE_DECL_SYS_GETRANDOM
	while (count < rqstd) {
		size_t lim = MIN(rqstd - count, sizeof data);
		int n;

		n = syscall(SYS_getrandom, data, lim, 0);

		if (n == -1) {
			break;
		}

		RAND_seed(data, n);

		count += n;
	}
#endif

#if HAVE_SYS_SYSCTL_H && HAVE_DECL_RANDOM_UUID
	while (count < rqstd) {
		int mib[] = { CTL_KERN, KERN_RANDOM, RANDOM_UUID };
		size_t n = MIN(rqstd - count, sizeof data);

		if (0 != sysctl(mib, countof(mib), data, &n, (void *)0, 0))
			break;

		RAND_seed(data, n);

		count += n;
	}

#endif

	if (count < rqstd) {
#if defined O_CLOEXEC && (!defined _AIX /* O_CLOEXEC overflows int */)
		int fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC);
#else
		int fd = open("/dev/urandom", O_RDONLY);
#endif

		if (fd == -1) {
			error = errno;
			goto error;
		}

		while (count < rqstd) {
			ssize_t n = read(fd, data, MIN(rqstd - count, sizeof data));

			switch (n) {
			case 0:
				errno = EIO;

				/* FALL THROUGH */
			case -1:
				if (errno == EINTR)
					continue;

				error = errno;

				close(fd);

				goto error;
			default:
				RAND_seed(data, n);

				count += n;
			}
		}

		close(fd);
	}

	st->pid = getpid();
#endif /* _WIN32 */

	return 0;
error:;
	struct {
#ifdef _WIN32
		DWORD pid;
		SYSTEMTIME tv;
		FILETIME ftCreation, ftExit, ftKernel, ftUser;
#else
		pid_t pid;
		struct timeval tv;
		struct rusage ru;
		struct utsname un;
#endif
		uintptr_t aslr;
#if defined __APPLE__
		uint64_t mt;
#elif defined __sun
		struct timespec mt;
#endif
	} junk;

#ifdef _WIN32
	junk.pid = GetCurrentProcessId();
	GetSystemTime(&junk.tv);
	GetProcessTimes(GetCurrentProcess(), &junk.ftCreation, &junk.ftExit, &junk.ftKernel, &junk.ftUser);
#else
	junk.pid = getpid();
	gettimeofday(&junk.tv, NULL);
	getrusage(RUSAGE_SELF, &junk.ru);
	uname(&junk.un);
#endif
	junk.aslr = (uintptr_t)&strcpy ^ (uintptr_t)&randL_stir;
#if defined __APPLE__
	junk.mt = mach_absolute_time();
#elif defined __sun
	/*
	 * NOTE: Linux requires -lrt for clock_gettime, and in any event
	 * should have RANDOM_UUID or getrandom. (Though, some middle-aged
	 * kernels might have neither). The BSDs have arc4random which
	 * should be using KERN_URND, KERN_ARND, and more recently
	 * getentropy. (Though, again, some older BSD kernels used an
	 * arc4random implementation that opened /dev/urandom.)
	 *
	 * Just do this for Solaris to keep things simple. We've already
	 * crossed the line of what can be reasonably accomplished on
	 * unreasonable platforms.
	 */
	clock_gettime(CLOCK_MONOTONIC, &junk.mt);
#endif

	RAND_add(&junk, sizeof junk, 0.1);

#ifdef _WIN32
	st->pid = GetCurrentProcessId();
#else
	st->pid = getpid();
#endif

	return error;
} /* randL_stir() */


static void randL_checkpid(struct randL_state *st) {
#ifdef _WIN32
	if (st->pid != GetCurrentProcessId())
#else
	if (st->pid != getpid())
#endif
		(void)randL_stir(st, 16);
} /* randL_checkpid() */


static int rand_stir(lua_State *L) {
	int error = randL_stir(randL_getstate(L), auxL_optunsigned(L, 1, 16, 0, UINT_MAX));

	if (error) {
		lua_pushboolean(L, 0);
		lua_pushstring(L, aux_strerror(error));
		lua_pushinteger(L, error);

		return 3;
	} else {
		lua_pushboolean(L, 1);

		return 1;
	}
} /* rand_stir() */


static int rand_add(lua_State *L) {
	const void *buf;
	size_t len;
	lua_Number entropy;

	buf = luaL_checklstring(L, 1, &len);
	entropy = luaL_optnumber(L, 2, len);

	RAND_add(buf, len, entropy);

	lua_pushboolean(L, 1);

	return 1;
} /* rand_add() */


static int rand_bytes(lua_State *L) {
	int size = luaL_checkinteger(L, 1);
	luaL_Buffer B;

	randL_checkpid(randL_getstate(L));

	if (!RAND_bytes((void *)luaL_buffinitsize(L, &B, size), size))
		return auxL_error(L, auxL_EOPENSSL, "rand.bytes");

	luaL_pushresultsize(&B, size);

	return 1;
} /* rand_bytes() */


static int rand_ready(lua_State *L) {
	lua_pushboolean(L, RAND_status() == 1);

	return 1;
} /* rand_ready() */


static unsigned long long rand_llu(lua_State *L) {
	unsigned long long llu;

	if (!RAND_bytes((void *)&llu, sizeof llu))
		auxL_error(L, auxL_EOPENSSL, "rand.uniform");

	return llu;
} /* rand_llu() */

/*
 * The following algorithm for rand_uniform() is taken from OpenBSD's
 * arc4random_uniform, written by Otto Moerbeek, with subsequent
 * simplification by Jorden Verwer. Otto's source code comment reads
 *
 *   Uniformity is achieved by generating new random numbers until the one
 *   returned is outside the range [0, 2**32 % upper_bound). This guarantees
 *   the selected random number will be inside [2**32 % upper_bound, 2**32)
 *   which maps back to [0, upper_bound) after reduction modulo upper_bound.
 *
 * --
 * A more bit-efficient approach by the eminent statistician Herman Rubin
 * can be found in this sci.crypt Usenet post.
 *
 *   From: hrubin@odds.stat.purdue.edu (Herman Rubin)
 *   Newsgroups: sci.crypt
 *   Subject: Re: Generating a random number between 0 and N-1
 *   Date: 14 Nov 2002 11:20:37 -0500
 *   Organization: Purdue University Statistics Department
 *   Lines: 40
 *   Message-ID: <ar0igl$1ak2@odds.stat.purdue.edu>
 *   References: <yO%y9.19646$RO1.373975@weber.videotron.net> <3DCD8D75.40408@nospam.com>
 *   NNTP-Posting-Host: odds.stat.purdue.edu
 *   X-Trace: mozo.cc.purdue.edu 1037290837 9316 128.210.141.13 (14 Nov 2002 16:20:37 GMT)
 *   X-Complaints-To: ne...@news.purdue.edu
 *   NNTP-Posting-Date: Thu, 14 Nov 2002 16:20:37 +0000 (UTC)
 *   Xref: archiver1.google.com sci.crypt:78935
 *
 *   In article <3DCD8D7...@nospam.com>,
 *   Michael Amling  <nos...@nospam.com> wrote:
 *   >Carlos Moreno wrote:
 *
 *   I have already posted on this, but a repeat might be
 *   in order.
 *
 *   If one can trust random bits, the most bitwise efficient
 *   manner to get a single random integer between 0 and N-1
 *   can be obtained as follows; the code can be made more
 *   computationally efficient.  I believe it is easier to
 *   understand with gotos.  I am assuming N>1.
 *
 *   	i = 0;	j = 1;
 *
 *   loop:	j=2*j; i=2*i+RANBIT;
 *   	if (j < N) goto loop;
 *   	if (i >= N) {
 *   		i = i - N;
 *   		j = j - N;
 *   		goto loop:}
 *   	else return (i);
 *
 *   The algorithm works because at each stage i is uniform
 *   between 0 and j-1.
 *
 *   Another possibility is to generate k bits, where 2^k >= N.
 *   If 2^k = c*N + remainder, generate the appropriate value
 *   if a k-bit random number is less than c*N.
 *
 *   For N = 17 (numbers just larger than powers of 2 are "bad"),
 *   the amount of information is about 4.09 bits, the best
 *   algorithm to generate one random number takes about 5.765
 *   bits, taking k = 5 uses 9.412 bits, taking k = 6 or 7 uses
 *   7.529 bits.  These are averages, but the tails are not bad.
 *
 * (https://groups.google.com/forum/message/raw?msg=sci.crypt/DMslf6tSrD8/rv9rk6oP3r4J)
 */
static int rand_uniform(lua_State *L) {
	unsigned long long r;

	randL_checkpid(randL_getstate(L));

	if (lua_isnoneornil(L, 1)) {
		r = rand_llu(L);
	} else {
		unsigned long long N, m;

		N = auxL_checkunsigned(L, 1);

		luaL_argcheck(L, N > 1, 1, lua_pushfstring(L, "[0, %d): interval is empty", (int)N));

		m = -N % N;

		do {
			r = rand_llu(L);
		} while (r < m);

		r = r % N;
	}

	auxL_pushunsigned(L, r);

	return 1;
} /* rand_uniform() */


static const auxL_Reg rand_globals[] = {
	{ "stir",    &rand_stir },
	{ "add",     &rand_add },
	{ "bytes",   &rand_bytes },
	{ "ready",   &rand_ready },
	{ "uniform", &rand_uniform },
	{ NULL,      NULL },
};

EXPORT int luaopen__openssl_rand(lua_State *L) {
	struct randL_state *st;

	initall(L);

	st = lua_newuserdata(L, sizeof *st);
	memset(st, 0, sizeof *st);
	auxL_newlib(L, rand_globals, 1);

	return 1;
} /* luaopen__openssl_rand() */


/*
 * DES - openssl.des
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static int de5_string_to_key(lua_State *L) {
	DES_cblock key;

	DES_string_to_key(luaL_checkstring(L, 1), &key);
	lua_pushlstring(L, (char *)key, sizeof key);

	return 1;
} /* de5_string_to_key() */

static int de5_set_odd_parity(lua_State *L) {
	const char *src;
	size_t len;
	DES_cblock key;

	src = luaL_checklstring(L, 1, &len);
	memset(&key, 0, sizeof key);
	memcpy(&key, src, MIN(len, sizeof key));

	DES_set_odd_parity(&key);
	lua_pushlstring(L, (char *)key, sizeof key);

	return 1;
} /* de5_set_odd_parity() */

static const auxL_Reg des_globals[] = {
	{ "string_to_key",  &de5_string_to_key },
	{ "set_odd_parity", &de5_set_odd_parity },
	{ NULL,            NULL },
};

EXPORT int luaopen__openssl_des(lua_State *L) {
	initall(L);

	auxL_newlib(L, des_globals, 0);

	return 1;
} /* luaopen__openssl_des() */


#if !OPENSSL_PREREQ(1,1,0)
/*
 * Multithread Reentrancy Protection
 *
 * Pre-1.0.2, OpenSSL needs to be given locking primitives
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static struct {
#if _WIN32
	HANDLE *lock;
#else
	pthread_mutex_t *lock;
#endif
	int nlock;
} mt_state;

static void mt_lock(int mode, int type, const char *file NOTUSED, int line NOTUSED) {
	if (mode & CRYPTO_LOCK)
#if _WIN32
		WaitForSingleObject(mt_state.lock[type], INFINITE);
#else
		pthread_mutex_lock(&mt_state.lock[type]);
#endif
	else
#if _WIN32
		ReleaseMutex(mt_state.lock[type]);
#else
		pthread_mutex_unlock(&mt_state.lock[type]);
#endif
} /* mt_lock() */

/*
 * Sources include Google and especially the Wine Project. See get_unix_tid
 * at http://source.winehq.org/git/wine.git/?a=blob;f=dlls/ntdll/server.c.
 */
#if __FreeBSD__
#include <sys/thr.h> /* thr_self(2) */
#elif __NetBSD__
#include <lwp.h> /* _lwp_self(2) */
#endif

static unsigned long mt_gettid(void) {
#if __APPLE__
	return pthread_mach_thread_np(pthread_self());
#elif __DragonFly__
	return lwp_gettid();
#elif  __FreeBSD__
	long id;

	thr_self(&id);

	return id;
#elif __NetBSD__
	return _lwp_self();
#elif _WIN32
	return GetCurrentThreadId();
#else
	/*
	 * pthread_t is an integer on Solaris and Linux, an unsigned integer
	 * on AIX, and a unique pointer on OpenBSD.
	 */
	return (unsigned long)pthread_self();
#endif
} /* mt_gettid() */

/* mt_init must not be called from multiple threads at once */
static int mt_init(void) {
	static int done, bound;
	int error = 0;

	if (done)
		goto epilog;

	if (!CRYPTO_get_locking_callback()) {
		if (!mt_state.lock) {
			int i;

			mt_state.nlock = CRYPTO_num_locks();

			if (!(mt_state.lock = malloc(mt_state.nlock * sizeof *mt_state.lock))) {
				error = errno;
				goto epilog;
			}

			for (i = 0; i < mt_state.nlock; i++) {
#if _WIN32
				if (!(mt_state.lock[i] = CreateMutex(NULL, FALSE, NULL))) {
					error = GetLastError();
#else
				if ((error = pthread_mutex_init(&mt_state.lock[i], NULL))) {
#endif
					while (i > 0) {
#if _WIN32
						CloseHandle(mt_state.lock[--i]);
#else
						pthread_mutex_destroy(&mt_state.lock[--i]);
#endif
					}

					free(mt_state.lock);
					mt_state.lock = NULL;

					goto epilog;
				}
			}
		}

		CRYPTO_set_locking_callback(&mt_lock);
		bound = 1;
	}

	if (!CRYPTO_get_id_callback()) {
		CRYPTO_set_id_callback(&mt_gettid);
		bound = 1;
	}

	if (bound && (error = dl_anchor()))
		goto epilog;

	done = 1;
epilog:
	return error;
} /* mt_init() */

#endif /* !OPENSSL_PREREQ(1,1,0) */


static void initall(lua_State *L) {
	static int initssl;
	int error = 0;

#if _WIN32
	static volatile HANDLE mutex = NULL;
	if (mutex == NULL) {
		HANDLE p;
		if (!(p = CreateMutex(NULL, FALSE, NULL)))
			auxL_error(L, GetLastError(), "openssl.init");
		if (InterlockedCompareExchangePointer((PVOID*)&mutex, (PVOID)p, NULL) != NULL)
			CloseHandle(p);
	}
	if (WaitForSingleObject(mutex, INFINITE) == WAIT_FAILED)
		auxL_error(L, GetLastError(), "openssl.init");
#else
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_lock(&mutex);
#endif

#if !OPENSSL_PREREQ(1,1,0)
	if (!error)
		error = mt_init();

	if (!error && !initssl) {
		initssl = 1;

		SSL_load_error_strings();
		SSL_library_init();
		OpenSSL_add_all_algorithms();

		/*
		 * TODO: Figure out a way to detect whether OpenSSL has
		 * already been configured.
		 */
		OPENSSL_config(NULL);
	}
#endif

	if (!error)
		error = compat_init();

	if (!error)
		error = ex_init();

#if _WIN32
	ReleaseMutex(mutex);
#else
	pthread_mutex_unlock(&mutex);
#endif

	if (error)
		auxL_error(L, error, "openssl.init");

	ex_newstate(L);

	auxL_addclass(L, BIGNUM_CLASS, bn_methods, bn_metatable, 0);
	pk_luainit(L, 0);
#ifndef OPENSSL_NO_EC
	auxL_addclass(L, EC_GROUP_CLASS, ecg_methods, ecg_metatable, 0);
#endif
	auxL_addclass(L, X509_NAME_CLASS, xn_methods, xn_metatable, 0);
	auxL_addclass(L, X509_GENS_CLASS, gn_methods, gn_metatable, 0);
	auxL_addclass(L, X509_EXT_CLASS, xe_methods, xe_metatable, 0);
	auxL_addclass(L, X509_CERT_CLASS, xc_methods, xc_metatable, 0);
	auxL_addclass(L, X509_CSR_CLASS, xr_methods, xr_metatable, 0);
	auxL_addclass(L, X509_CRL_CLASS, xx_methods, xx_metatable, 0);
	auxL_addclass(L, X509_CHAIN_CLASS, xl_methods, xl_metatable, 0);
	auxL_addclass(L, X509_STORE_CLASS, xs_methods, xs_metatable, 0);
	auxL_addclass(L, X509_VERIFY_PARAM_CLASS, xp_methods, xp_metatable, 0);
	auxL_addclass(L, PKCS12_CLASS, p12_methods, p12_metatable, 0);
	auxL_addclass(L, SSL_CTX_CLASS, sx_methods, sx_metatable, 0);
	auxL_addclass(L, SSL_CLASS, ssl_methods, ssl_metatable, 0);
	auxL_addclass(L, DIGEST_CLASS, md_methods, md_metatable, 0);
	auxL_addclass(L, HMAC_CLASS, hmac_methods, hmac_metatable, 0);
	auxL_addclass(L, CIPHER_CLASS, cipher_methods, cipher_metatable, 0);
	auxL_addclass(L, OCSP_RESPONSE_CLASS, or_methods, or_metatable, 0);
	auxL_addclass(L, OCSP_BASICRESP_CLASS, ob_methods, ob_metatable, 0);

	if (LUA_TNIL == lua_rawgetp(L, LUA_REGISTRYINDEX, LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(&initall))) {
		/* Create cache for pointers */
		lua_newtable(L);
		lua_createtable(L, 0, 2);
		lua_pushliteral(L, "kv");
		lua_setfield(L, -2, "__mode");
		lua_pushliteral(L, "luaossl cache");
		lua_setfield(L, -2, "__name");
		lua_setmetatable(L, -2);
		lua_rawsetp(L, LUA_REGISTRYINDEX, LUAOSSL_UNIQUE_LIGHTUSERDATA_MASK(&initall));
	}
	lua_pop(L, 1);
} /* initall() */
