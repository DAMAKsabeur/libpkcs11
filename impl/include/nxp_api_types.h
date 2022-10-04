/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

/*
 * nxp_api_types.h
 */
#ifndef _NXP_API_TYPES_H_
#define _NXP_API_TYPES_H_

#include <stdint.h>
#include "sha512.h"
#include "sha384.h"
#include "sha256.h"
#include "sha224.h"
#include "sha1.h"
#include "sha.h"
#include "md5.h"
/*
 * Return Codes.
 */

typedef uint16_t NXP_RET_CODE;

/* Error/status word */
#define NXP_OK                        (0x9000) /* Operation successful */

#define NXP_ERR_NOT_SUPPORTED         (0x7080) /* The function and/or parameters are not supported by the library */

#define NXP_ERR_GENERAL_ERROR         (0x7021) /* Non-specific error code */
#define NXP_ERR_SHORT_BUFFER          (0x7026) /* Buffer provided is too small */
#define NXP_ERR_CRYPTO_ENGINE_FAILED  (0x7027) /* The crypto engine (implemented underneath a crypto abstraction layer) failed to provide a crypto service. */
#define NXP_ERR_IDENT_IDX_RANGE       (0x7032) /* Identifier or Index of Reference Key is out of bounds */

#define NXP_ERR_INIT_FAILED           (0x6001) /* If anything related to underlying component initialization failed */
#define NXP_ERR_TEE_API               (0x6002) /* The return code is an error that originated within the TEE Client API implementation */
#define NXP_ERR_TEE_COMM              (0x6003) /* Some error occured in communication stack b/w Rich OS and TEE */
#define NXP_ERR_TEE_OS                (0x6004) /* The return code is an error that originated within the common TEE code. */

#define NXP_ERR_ACCESS_DENIED         (0x6005) /* Access privileges are not sufficient */
#define NXP_ERR_CANCEL                (0x6006) /* The operation was cancelled */
#define NXP_ERR_ACCESS_CONFLICT       (0x6007) /* Concurrent accesses caused conflict*/
#define NXP_ERR_EXCESS_DATA           (0x6008) /* Too much data for the requested operation was passed.*/
#define NXP_ERR_BAD_FORMAT            (0x6009) /* Input data was of invalid format.*/
#define NXP_ERR_BAD_PARAMETERS        (0x6010) /* Input parameters were invalid.*/
#define NXP_ERR_BAD_STATE             (0x6011) /* Operation is not valid in the current state.*/
#define NXP_ERR_ITEM_NOT_FOUND        (0x6012) /* The requested data item is not found.*/
#define NXP_ERR_NOT_IMPLEMENTED       (0x6013) /* The requested operation should exist but is not yet implemented.*/
#define NXP_ERR_NO_DATA               (0x6015) /* Expected data was missing.*/
#define NXP_ERR_OUT_OF_MEMORY         (0x6016) /* System ran out of resources. */
#define NXP_ERR_BUSY                  (0x6017) /* The system is busy working on something else.*/
#define NXP_ERR_COMMUNICATION         (0x6018) /* Communication with a remote party failed.*/
#define NXP_ERR_SECURITY              (0x6019) /* A security fault was detected.*/
#define NXP_ERR_OBJECT_HANDLE_INVALID (0x6020) /* Object Handle Invalid */


/*
 * A type for all the defines.
 */
typedef uint32_t NXP_TYPE;

/*
 * An Object Type definition.
 */
typedef NXP_TYPE NXP_OBJECT_TYPE;

/*
 * Enumerates the various logical objects existing on the Secure Element.
 */
#define NXP_ANY_TYPE        0x00000000 /* For the Enumeration of all the objects */
#define NXP_KEY_PAIR        0x00010000 /* Asymmetric Key Pairs */
#define NXP_PUBLIC_KEY      0x00020000 /* Asymmetric Public Key in Uncompressed format */


typedef NXP_TYPE NXP_KEY_TYPE;

#define NXP_RSA            0x00000000U
#define NXP_EC             0x00000001U

/*
 * An Object Handle.
 */
typedef NXP_TYPE NXP_OBJECT_HANDLE;

/*
 * An Attribute Type.
 */
typedef NXP_TYPE NXP_ATTRIBUTE_TYPE;

#define NXP_ATTR_OBJECT_TYPE         0 /* The object type (Mandatory in Create) */
#define NXP_ATTR_OBJECT_INDEX        1 /* The object index (Mandatory in Create) */
#define NXP_ATTR_OBJECT_LABEL        2 /* The object label (Mandatory in Create) */
#define NXP_ATTR_OBJECT_VALUE        3 /*  Value of Object */
#define NXP_ATTR_KEY_TYPE            5 /* Key Type RSA/EC (Mandatory with key type objects) */
#define NXP_ATTR_PRIVATE             6 /* Object is private/public (PKCS Requirement)*/

/* Attributes For RSA Key Pair */
#define NXP_ATTR_MODULUS_BITS       30 /* Length in bits of modulus n */
#define NXP_ATTR_MODULUS            31 /* Big integer Modulus n */
#define NXP_ATTR_PUBLIC_EXPONENT    32 /* Big integer Public exponent e */

#define NXP_ATTR_PRIVATE_EXPONENT   33 /* Big integer Private exponent e */
#define NXP_ATTR_PRIME_1            34 /* Big Integer Prime p */
#define NXP_ATTR_PRIME_2            35 /* Big Integer Prime q */
#define NXP_ATTR_EXPONENT_1         36 /* Big integer Private exponent d modulo p-1 */
#define NXP_ATTR_EXPONENT_2         37 /* Big integer Private exponent d modulo q-1 */
#define NXP_ATTR_COEFFICIENT        38 /* Big integer CRT coefficient q-1 mod p */

/* Attributes For ECC Key Pair */
#define NXP_ATTR_PARAMS             50 /* DER encoding of namedcurve */
#define NXP_ATTR_POINT              51 /* Public point in octet uncompressed format */
#define NXP_ATTR_PRIV_VALUE         52 /* Private Value */

/*
 * Stores all the information required for an object's attribute - its type, value and value length.
 */
typedef struct NXP_ATTRIBUTE{
    NXP_ATTRIBUTE_TYPE  type;        /* The attribute's type */
    uint8_t                *value;        /* The attribute's value */
    uint16_t            valueLen;    /* The length in bytes of \p value. */
} NXP_ATTRIBUTE;


/*
  * A Context Handle - may point to any stucture.
 */
typedef void NXP_CONTEXT_HANDLE;


/*******************************************************************
 * Cryptographic Operations TBD
 *******************************************************************/

typedef NXP_TYPE NXP_MECHANISM_TYPE;

/*
 * Mechanism Type enum.
 * Enumerates the various Cryptographic Mechanisms that may be supported by the library.
 */

/*******************************************************************
 * Mechanisms
 *******************************************************************/
#define        NXP_RSAES_PKCS1_V1_5                101
#define        NXP_RSAES_PKCS1_OAEP_MGF1_SHA1      102 /* Currently not supported */
#define        NXP_RSAES_PKCS1_OAEP_MGF1_SHA224    103 /* Currently not supported */
#define        NXP_RSAES_PKCS1_OAEP_MGF1_SHA256    104 /* Currently not supported */
#define        NXP_RSAES_PKCS1_OAEP_MGF1_SHA384    105 /* Currently not supported */
#define        NXP_RSAES_PKCS1_OAEP_MGF1_SHA512    106 /* Currently not supported */
#define        NXP_RSA_PKCS_NOPAD                  107
#define        NXP_RSASSA_PKCS1_V1_5_MD5           111
#define        NXP_RSASSA_PKCS1_V1_5_SHA1          112
#define        NXP_RSASSA_PKCS1_V1_5_SHA224        113
#define        NXP_RSASSA_PKCS1_V1_5_SHA256        114
#define        NXP_RSASSA_PKCS1_V1_5_SHA384        115
#define        NXP_RSASSA_PKCS1_V1_5_SHA512        116
#define        NXP_RSASSA_PKCS1_PSS_MGF1_SHA1      117 /* Currently not supported */
#define        NXP_RSASSA_PKCS1_PSS_MGF1_SHA224    118 /* Currently not supported */
#define        NXP_RSASSA_PKCS1_PSS_MGF1_SHA256    119 /* Currently not supported */
#define        NXP_RSASSA_PKCS1_PSS_MGF1_SHA384    120 /* Currently not supported */
#define        NXP_RSASSA_PKCS1_PSS_MGF1_SHA512    121 /* Currently not supported */
#define        NXP_MD5                             131
#define        NXP_SHA1                            132
#define        NXP_SHA224                          133
#define        NXP_SHA256                          134
#define        NXP_SHA384                          135
#define        NXP_SHA512                          136
#define        NXP_RSA_PKCS_KEY_PAIR_GEN           141

#define        NXP_ECDSA                           150
#define        NXP_ECDSA_SHA1                      151
#define        NXP_ECDSA_SHA256                    152
#define        NXP_ECDSA_SHA384                    153
#define        NXP_ECDSA_SHA512                    154

#define        NXP_EC_PKCS_KEY_PAIR_GEN            161

/*
 * Specifying the required information in order to use a mechanism,
 */
typedef struct NXP_MECHANISM_INFO {
    /* The Mechanism type (see MechanismType). */
    NXP_MECHANISM_TYPE mechanism;
    /* An additional optional parameter required in using this mechanism. */
    void               *pParameter;
    /* The length in bytes of parameter */
    uint16_t           ulParameterLen;
} NXP_MECHANISM_INFO;

/*
 * Stores all the information required to continue SignUpdate, DigestUpdate etc.
 */

typedef struct NXP_CONTEXT_INFO_T {
    NXP_CONTEXT_HANDLE *tee_ctx_handle; /* TEE Context Handle */
    NXP_CONTEXT_HANDLE *tee_sess_handle;/* TEE Session Handle */
    SHA256_State       SHA256_ctx;
    SHA512_State       SHA512_ctx;
    SHA512_State       SHA224_ctx;
    SHA512_State       SHA384_ctx;
    SHA1_CTX           SHA1_ctx;
    SHA_State          SHA_ctx;
    MD5_CTX            MD5_ctx;
    NXP_MECHANISM_INFO mech;
    uint16_t           chunkLen;       /* Last Buffer length. */
    void               *chunk;          /* Last Buffer (Not part of Digest)*/
} NXP_CONTEXT_INFO;

#endif /* _NXP_API_TYPES_H_ */
