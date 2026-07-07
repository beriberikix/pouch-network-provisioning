/*
 * Copyright (c) 2026 Jonathan Beri
 * SPDX-License-Identifier: Apache-2.0
 *
 * Appended to the mbedTLS config (CONFIG_MBEDTLS_USER_CONFIG_FILE) to
 * enable on-device X.509 certificate creation, which Zephyr's Kconfig
 * exposes as MBEDTLS_X509_CRT_WRITE_C but whose internal prerequisite
 * MBEDTLS_X509_CREATE_C is not surfaced.
 */

#ifndef MBEDTLS_X509_CREATE_C
#define MBEDTLS_X509_CREATE_C
#endif
#ifndef MBEDTLS_OID_C
#define MBEDTLS_OID_C
#endif
#ifndef MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_ASN1_WRITE_C
#endif
#ifndef MBEDTLS_PK_WRITE_C
#define MBEDTLS_PK_WRITE_C
#endif
#ifndef MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_PARSE_C
#endif

/* pouch's saead build parses the server certificate and base64-encodes the
 * session id; these are pulled in transitively by the Golioth SDK in pouch's
 * own example but must be requested explicitly for a standalone build. */
#ifndef MBEDTLS_X509_USE_C
#define MBEDTLS_X509_USE_C
#endif
#ifndef MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CRT_PARSE_C
#endif
#ifndef MBEDTLS_BASE64_C
#define MBEDTLS_BASE64_C
#endif
