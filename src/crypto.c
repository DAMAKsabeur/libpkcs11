/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <cryptoki.h>
#include <crypto.h>
#include <general.h>
#include <objects.h>
#include "nxp_slot.h"
#include "nxp_api.h"
#include "nxp_api_types.h"

char P256[] = "prime256v1";
char P384[] = "secp384r1";

/* EC Curve in DER encoding */
char prime256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
char secp384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };

struct ec_curves supported_ec_curves[SUPPORTED_EC_CURVES] = {
    {P256, 256, prime256, sizeof(prime256)},
    {P384, 384, secp384, sizeof(secp384)},
};

static NXP_MECHANISM_TYPE get_NXP_Mechanism(CK_MECHANISM_TYPE mechId)
{
    NXP_MECHANISM_TYPE mechanism;

    switch (mechId) {
    case CKM_SHA_1:
        mechanism = NXP_SHA1;
        break;
    case CKM_SHA256:
        mechanism = NXP_SHA256;
        break;
    case CKM_SHA384:
        mechanism = NXP_SHA384;
        break;
    case CKM_SHA512:
        mechanism = NXP_SHA512;
        break;
    case CKM_MD5:
        mechanism = NXP_MD5;
        break;
    default:
        mechanism = CKR_MECHANISM_INVALID;
    }

    return mechanism;
}

CK_RV mechanism_get_info(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                         CK_MECHANISM_INFO_PTR pInfo)
{
    CK_RV rc = CKR_OK;

    switch (slotID) {
        case NXP_S32G_HSM_SLOT_ID:
            rc = Get_NXP_MechanismInfo(type, pInfo);
            break;
        default:
            rc = CKR_SLOT_ID_INVALID;
    }

    return rc;
}

CK_BBOOL mechanism_is_valid(CK_SLOT_ID slotID, CK_MECHANISM_PTR pMechanism, CK_FLAGS flags)
{
    CK_RV rc = CKR_OK;
    CK_MECHANISM_INFO info;

    if (pMechanism) {
        memset(&info, 0, sizeof(info));
        rc = mechanism_get_info(slotID,
                pMechanism->mechanism, &info);

        if (rc != CKR_OK || !(info.flags & (flags)))
            return CK_FALSE;
    } else
        return CK_FALSE;

    return CK_TRUE;
}

CK_RV mechanism_template_check_consistency( CK_MECHANISM_PTR pMechanism,
                                            CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                            CK_ULONG ulPublicKeyAttributeCount,
                                            CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                            CK_ULONG ulPrivateKeyAttributeCount,
                                            CK_ULONG *subclass)
{
    CK_RV rc = CKR_OK;
    CK_ULONG publ_attr_count = 0, priv_attr_count = 0;
    CK_ATTRIBUTE_PTR public_temp = NULL, priv_temp = NULL;
    CK_ULONG i = 0, class_tmp = 0, subclass_tmp = 0;

    publ_attr_count = ulPublicKeyAttributeCount;
    priv_attr_count = ulPrivateKeyAttributeCount;

    public_temp = pPublicKeyTemplate;
    priv_temp = pPrivateKeyTemplate;

    for (i=0; i < publ_attr_count; i++) {
        if (public_temp[i].type == CKA_CLASS) {
            class_tmp = *(CK_OBJECT_CLASS *)public_temp[i].pValue;
            if (class_tmp != CKO_PUBLIC_KEY){
                rc = CKR_TEMPLATE_INCONSISTENT;
                goto end;
            }
        }

        if (public_temp[i].type == CKA_KEY_TYPE)
            subclass_tmp = *(CK_ULONG *)public_temp[i].pValue;

        class_tmp = CKO_PUBLIC_KEY;
    }

    for (i=0; i < priv_attr_count; i++) {
        if (priv_temp[i].type == CKA_CLASS) {
            class_tmp = *(CK_OBJECT_CLASS *)priv_temp[i].pValue;
            if (class_tmp != CKO_PRIVATE_KEY){
                rc = CKR_TEMPLATE_INCONSISTENT;
                goto end;
            }
        }

        if (priv_temp[i].type == CKA_KEY_TYPE) {
            CK_ULONG temp = *(CK_ULONG *)priv_temp[i].pValue;
            if (temp != subclass_tmp){
                rc = CKR_TEMPLATE_INCONSISTENT;
                goto end;
            }
        }

        class_tmp = CKO_PRIVATE_KEY;
    }

    switch (pMechanism->mechanism) {
        case CKM_RSA_PKCS_KEY_PAIR_GEN:
            if (subclass_tmp != 0 && subclass_tmp != CKK_RSA) {
                rc = CKR_TEMPLATE_INCONSISTENT;
                goto end;
            }

            subclass_tmp = CKK_RSA;
            break;

        case CKM_EC_KEY_PAIR_GEN:
            if (subclass_tmp != 0 && subclass_tmp != CKK_EC) {
                rc = CKR_TEMPLATE_INCONSISTENT;
                goto end;
            }

            subclass_tmp = CKK_EC;
            break;
        default:
            rc = CKR_MECHANISM_INVALID;
    }

    *subclass = subclass_tmp;
end:
    return rc;
}

/* Init for decrypt mechanism */
CK_RV decrypt_init(CK_SESSION_HANDLE hSession, encr_decr_context *ctx, CK_MECHANISM *mech, CK_OBJECT_HANDLE key)
{
    CK_ATTRIBUTE attr[4] = {0};
    CK_BYTE *ptr = NULL;
    CK_KEY_TYPE keytype;
    CK_OBJECT_CLASS class;
    CK_BBOOL decrypt = FALSE, found = FALSE;
    CK_MECHANISM_TYPE_PTR obj_mechanisms = NULL;
    CK_ULONG n;
    CK_RV rc;

    if (ctx->active == TRUE) {
        rc = CKR_OPERATION_ACTIVE;
        goto out;
    }

    /* Get all object attributes needed */
    attr[0].type = CKA_DECRYPT;
    attr[1].type = CKA_ALLOWED_MECHANISMS;
    attr[2].type = CKA_KEY_TYPE;
    attr[3].type = CKA_CLASS;

    /* Check if key supports decrypt attribute */
    rc = get_attr_value(hSession, key, attr, 1);
    if (rc != CKR_OK) {
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto out;
    }

    rc = get_attr_value(hSession, key, &attr[1], 3);
    if (rc != CKR_OK)
        goto out;

    obj_mechanisms =
        (CK_MECHANISM_TYPE_PTR)malloc(attr[1].ulValueLen);
    if (!obj_mechanisms) {
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    attr[0].pValue = &decrypt;
    attr[1].pValue = obj_mechanisms;
    attr[2].pValue = &keytype;
    attr[3].pValue = &class;
    rc = get_attr_value(hSession, key, attr, 4);
    if (rc != CKR_OK)
        goto out;

    /* Check if object can support decrypt mechanism */
    if (decrypt != TRUE) {
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto out;
    }

    /* Check if object can support decrypt mechanism type */
    for (n = 0; n < (attr[1].ulValueLen/sizeof(CK_MECHANISM_TYPE)); n++) {
        if (mech->mechanism ==
            *((CK_MECHANISM_TYPE_PTR)attr[1].pValue + n)) {
            found = TRUE;
            break;
        }
    }

    if (found != TRUE) {
        rc = CKR_MECHANISM_INVALID;
        goto out;
    }

    /* Check for key attributes if they match with mechanism provided */
    switch (mech->mechanism) {
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_OAEP:
        /* Key type must be RSA */
        if (keytype != CKK_RSA) {
            rc = CKR_KEY_TYPE_INCONSISTENT;
            goto out;
        }
        break;

    default:
        rc = CKR_MECHANISM_INVALID;
        goto out;
    }

    if (mech->mechanism == CKM_RSA_PKCS) {
        if (mech->ulParameterLen != 0) {
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto out;
        }
    }

    /* Key class must be Private */
    if (class != CKO_PRIVATE_KEY) {
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto out;
    }

    /* Currently we don't support multi-part ops */
    ctx->context_len = 0;
    ctx->context     = NULL;

    if (mech->ulParameterLen > 0) {
        ptr = (CK_BYTE *)malloc(mech->ulParameterLen);
        if (!ptr) {
            rc = CKR_HOST_MEMORY;
            goto out;
        }
        memcpy(ptr, mech->pParameter, mech->ulParameterLen);
    }

    /* Keeping the sign information in session ctx */
    ctx->key                 = key;
    ctx->mech.ulParameterLen = mech->ulParameterLen;
    ctx->mech.mechanism      = mech->mechanism;
    ctx->mech.pParameter     = ptr;
    ctx->multi               = FALSE;
    ctx->active              = TRUE;

out:
    if (obj_mechanisms)
        free(obj_mechanisms);

    return rc;
}

static CK_RV rsa_decrypt(CK_SESSION_HANDLE hSession, session *sess,
                         CK_BYTE_PTR pEncryptedData,
                         CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                         CK_ULONG_PTR pulDataLen)
{
    CK_RV rc = CKR_OK;
    encr_decr_context *ctx = &sess->decr_ctx;
    CK_ATTRIBUTE attr = {0};
    CK_ULONG req_data_len = 0;
    CK_RSA_PKCS_OAEP_PARAMS *oaep_params = NULL;

    NXP_FUNCTION_LIST_PTR nxp_funcs = NULL;
    NXP_RET_CODE ret = NXP_OK;
    NXP_MECHANISM_INFO mechType = {0};
    NXP_OBJECT_HANDLE nxp_key;

    /* Get required pData buffer size from size of modulus */
    attr.type = CKA_MODULUS;
    rc = get_attr_value(hSession, ctx->key, &attr, 1);
    if (rc != CKR_OK)
        goto out;
    req_data_len = attr.ulValueLen;

    /*
     * If pData buffer is NULL then return size of
     * buffer to be allocated.
     */
    if (!pData) {
        *pulDataLen = req_data_len;
        rc = CKR_OK;
        goto out;
    }

    print_info("ulDataLen = %lu, enc_len = %lu\n",
        *pulDataLen, ulEncryptedDataLen);
    /* Data Len length should not be less than required size */
    if (*pulDataLen < req_data_len) {
        rc = CKR_BUFFER_TOO_SMALL;
        goto out;
    }

    /* Maps RSA Decrypt --> NXP_decrypt for private key operation */
    nxp_funcs = get_slot_function_list(sess->session_info.slotID);
    if (!nxp_funcs)
        return CKR_ARGUMENTS_BAD;

    switch (ctx->mech.mechanism) {
        case CKM_RSA_PKCS:
            mechType.mechanism = NXP_RSAES_PKCS1_V1_5;
            break;
        case CKM_RSA_PKCS_OAEP:
            oaep_params = (CK_RSA_PKCS_OAEP_PARAMS *)ctx->mech.pParameter;
            switch (oaep_params->hashAlg) {
                case CKM_SHA_1:
                    mechType.mechanism = NXP_RSAES_PKCS1_OAEP_MGF1_SHA1;
                    break;
                case CKM_SHA224:
                    mechType.mechanism = NXP_RSAES_PKCS1_OAEP_MGF1_SHA224;
                    break;
                case CKM_SHA256:
                    mechType.mechanism = NXP_RSAES_PKCS1_OAEP_MGF1_SHA256;
                    break;
                case CKM_SHA384:
                    mechType.mechanism = NXP_RSAES_PKCS1_OAEP_MGF1_SHA384;
                    break;
                case CKM_SHA512:
                    mechType.mechanism = NXP_RSAES_PKCS1_OAEP_MGF1_SHA512;
                    break;
                default:
                    rc = CKR_MECHANISM_PARAM_INVALID;
                    goto out;
            }
            break;

        default:
            rc = CKR_MECHANISM_INVALID;
            goto out;
    }

    nxp_key = ((struct object_node *)ctx->key)->object.nxp_obj_handle;

    print_info("ulEncryptedDataLen = %lu, pulDataLen = %lu\n",
            ulEncryptedDataLen, *pulDataLen);
    ret = nxp_funcs->NXP_Decrypt(&mechType, nxp_key, pEncryptedData,
                ulEncryptedDataLen, pData,
                (uint16_t *)pulDataLen);
    if (ret != NXP_OK) {
        print_error("NXP_Decrypt failed with ret code 0x%x\n", ret);
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

out:
    return rc;
}

/* Implementation of decrypt api */
CK_RV decrypt(CK_SESSION_HANDLE hSession, session *sess,
              CK_BYTE_PTR pEncryptedData,
              CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
              CK_ULONG_PTR pulDataLen)
{
    encr_decr_context *ctx = &sess->decr_ctx;
    CK_RV rc = CKR_OK;

    if (ctx->active == FALSE) {
        rc = CKR_OPERATION_NOT_INITIALIZED;
        goto out;
    }

    switch (ctx->mech.mechanism) {
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_OAEP:
        rc = rsa_decrypt(hSession, sess, pEncryptedData,
                ulEncryptedDataLen, pData,
                pulDataLen);
        if (((rc == CKR_OK) && (pData == NULL)) ||
            (rc == CKR_BUFFER_TOO_SMALL))
            goto out;
        break;

    default:
        rc = CKR_MECHANISM_INVALID;
        goto out;
    }

    ctx->key = 0;
    ctx->mech.ulParameterLen = 0;
    ctx->mech.mechanism = 0;
    ctx->multi = FALSE;
    ctx->active = FALSE;
    ctx->context_len = 0;

    if (ctx->mech.pParameter) {
        free(ctx->mech.pParameter);
        ctx->mech.pParameter = NULL;
    }

    if (ctx->context) {
        free(ctx->context);
        ctx->context = NULL;
    }

out:
    return rc;
}


CK_RV digest_init(session *sess, digest_ctx *ctx, CK_MECHANISM *mech)
{
    CK_RV rc = CKR_OK;
    CK_BYTE *ptr = NULL;
    NXP_RET_CODE ret = NXP_OK;
    NXP_FUNCTION_LIST_PTR nxp_funcs = NULL;
    NXP_MECHANISM_INFO digestType = {0};

    if (ctx->active != FALSE) {
        print_error("Previous Digest Init Operation is not concluded.\n");
        rc = CKR_OPERATION_ACTIVE;
        goto out;
    }

    /* Maps to Digest Init API in SK. --> NXP_DigestInit */
    nxp_funcs = get_slot_function_list(sess->session_info.slotID);
    if (!nxp_funcs) {
        print_error("Invalid Mechanism\n");
        rc = CKR_ARGUMENTS_BAD;
        goto out;
    }
    memcpy(&ctx->mech, mech, sizeof(CK_MECHANISM));
    digestType.mechanism = get_NXP_Mechanism(ctx->mech.mechanism);

    if (digestType.mechanism == CKR_MECHANISM_INVALID) {
        print_error("Un-support or Invalid mechanism.\n");
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto out;
    }
    if (mech->ulParameterLen != 0) {
        print_error("Err: Mechanism Param length[%lu] should be zero.\n", mech->ulParameterLen);
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto out;
    }

    ctx->context = NULL;
    ctx->context = malloc(sizeof(NXP_CONTEXT_INFO));

    if (!ctx->context) {
        print_error("Insufficient Memory.\n");
        rc = CKR_HOST_MEMORY;
        goto out;
    }
    ctx->context_len = sizeof(NXP_CONTEXT_INFO);

    ret = nxp_funcs->NXP_DigestInit(&digestType, (NXP_CONTEXT_INFO *)ctx->context);
    if (ret != NXP_OK) {
        print_error("NXP_DigestInit failed with ret code 0x%x\n", ret);
        rc = CKR_GENERAL_ERROR;
        if (ctx->context) {
            free(ctx->context);
            ctx->context = NULL;
        }
        ctx->active = FALSE;
        goto out;
    }

    ctx->mech.ulParameterLen = mech->ulParameterLen;
    ctx->mech.mechanism = mech->mechanism;
    ctx->mech.pParameter = ptr;
    ctx->multi_init = FALSE;
    ctx->multi = FALSE;
    ctx->active = TRUE;

out:
    return rc;
}

CK_RV digest(session *sess, digest_ctx *ctx, CK_BYTE_PTR pData,
             CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
             CK_ULONG_PTR pDigestLen)
{
    CK_RV rc = CKR_OK;
    NXP_RET_CODE ret = NXP_OK;
    NXP_FUNCTION_LIST_PTR nxp_funcs = NULL;
    NXP_MECHANISM_INFO digestType = {0};

    if (ctx->active == FALSE) {
        print_error("Digest Operation is not initialized.");
        rc = CKR_OPERATION_NOT_INITIALIZED;
        goto out;
    }

    if (ctx->multi_init == FALSE) {
        ctx->multi = FALSE;
        ctx->multi_init = TRUE;
    }

    if (ctx->multi == TRUE) {
        print_error("Digest Update operation is ongoing.\n");
        rc = CKR_OPERATION_ACTIVE;
        goto out;
    }

    /* Maps to Digest API in SK --> NXP_Digest */
    nxp_funcs = get_slot_function_list(sess->session_info.slotID);
    if (!nxp_funcs)
        return CKR_ARGUMENTS_BAD;

    digestType.mechanism = get_NXP_Mechanism(ctx->mech.mechanism);
    if (digestType.mechanism == CKR_MECHANISM_INVALID) {
        print_error("Un-support or Invalid mechanism.\n");
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto out;
    }

    ret = nxp_funcs->NXP_Digest(&digestType, pData, ulDataLen, pDigest,
                  (uint16_t *)&pDigestLen);

    if ((ret == NXP_OK) && (pDigest == NULL))
        goto out;

    if (ret != NXP_OK) {
        print_error("NXP_Digest failed with ret code 0x%x\n", ret);
        rc = CKR_GENERAL_ERROR;
    }

    ctx->mech.ulParameterLen = 0;
    ctx->mech.mechanism = 0;
    ctx->multi_init = FALSE;
    ctx->multi = FALSE;
    ctx->active = FALSE;
    ctx->context_len = 0;

    if (ctx->mech.pParameter) {
        free(ctx->mech.pParameter);
        ctx->mech.pParameter = NULL;
    }

    if (ctx->context != NULL) {
        free(ctx->context);
        ctx->context = NULL;
    }
out:
    return rc;
}

/* Digest Update for  mechanism */
CK_RV digest_update(session *sess, digest_ctx *ctx, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    CK_RV rc = CKR_OK;
    NXP_RET_CODE ret = NXP_OK;
    NXP_FUNCTION_LIST_PTR nxp_funcs = NULL;

    if (ctx->active == FALSE) {
        print_error("Digest Operation is not initialized.");
        rc = CKR_OPERATION_NOT_INITIALIZED;
        goto out;
    }

    if (ctx->multi_init == FALSE) {
        ctx->multi = TRUE;
        ctx->multi_init = TRUE;
    }

    if (ctx->multi == FALSE) {
        print_error("Digest is called before current call of Digest Update.\n");
        rc = CKR_OPERATION_ACTIVE;
        goto out;
    }

    /* Maps to Digest API in SK --> NXP_DigestUpdate  */
    nxp_funcs = get_slot_function_list(sess->session_info.slotID);
    if (!nxp_funcs)
        return CKR_ARGUMENTS_BAD;

    ret = nxp_funcs->NXP_DigestUpdate((NXP_CONTEXT_INFO *)ctx->context, pPart, ulPartLen);
    if (ret != NXP_OK) {
        print_error("NXP_DigestUpdate failed with ret code 0x%x\n", ret);
        rc = CKR_GENERAL_ERROR;
    }

    if (rc != CKR_OK) {
        ctx->mech.ulParameterLen = 0;
        ctx->mech.mechanism = 0;
        ctx->multi_init = FALSE;
        ctx->multi = FALSE;
        ctx->active = FALSE;
        ctx->context_len = 0;

        if (ctx->mech.pParameter) {
            free(ctx->mech.pParameter);
            ctx->mech.pParameter = NULL;
        }

        if (ctx->context != NULL) {
            free(ctx->context);
            ctx->context = NULL;
        }
    }
out:
    return rc;
}

CK_RV digest_final(session *sess, digest_ctx *ctx, CK_BYTE_PTR pDigest, CK_ULONG_PTR pDigestLen)
{
    CK_RV rc = CKR_OK;
    NXP_RET_CODE ret = NXP_OK;
    NXP_FUNCTION_LIST_PTR nxp_funcs = NULL;

    if (ctx->active == FALSE) {
        print_error("Digest Operation is not initialized.");
        rc = CKR_OPERATION_NOT_INITIALIZED;
        goto out;
    }

    if (ctx->multi_init == FALSE) {
        ctx->multi = TRUE;
        ctx->multi_init = TRUE;
    }

    if (ctx->multi == FALSE) {
        print_error("Digest operation is ongoing.\n");
        rc = CKR_OPERATION_ACTIVE;
        goto out;
    }

    /* Maps C_DigestFinal --> NXP_DigestFinal */
    nxp_funcs = get_slot_function_list(sess->session_info.slotID);
    if (!nxp_funcs)
        return CKR_ARGUMENTS_BAD;

    ret = nxp_funcs->NXP_DigestFinal((NXP_CONTEXT_INFO *)ctx->context, pDigest, (uint16_t *)pDigestLen);

    if ((ret == NXP_OK) && (pDigest == NULL))
        goto out;

    if (ret != NXP_OK) {
        print_error("NXP_DigestFinal failed with ret code 0x%x\n", ret);
        rc = CKR_GENERAL_ERROR;
    }

    ctx->mech.ulParameterLen = 0;
    ctx->mech.mechanism = 0;
    ctx->multi_init = FALSE;
    ctx->multi = FALSE;
    ctx->active = FALSE;
    ctx->context_len = 0;

    if (ctx->mech.pParameter) {
        free(ctx->mech.pParameter);
        ctx->mech.pParameter = NULL;
    }

    if (ctx->context != NULL) {
        free(ctx->context);
        ctx->context = NULL;
    }

out:
    return rc;
}

/* Init for sign mechanism */
CK_RV sign_init(CK_SESSION_HANDLE hSession, sign_verify_context *ctx,
                CK_MECHANISM *mech, CK_BBOOL recover_mode,
                CK_OBJECT_HANDLE key)
{
    CK_ATTRIBUTE attr[4] = {0};
    CK_BYTE *ptr = NULL;
    CK_KEY_TYPE keytype;
    CK_OBJECT_CLASS class;
    CK_BBOOL sign = FALSE, found = FALSE;
    CK_MECHANISM_TYPE_PTR obj_mechanisms = NULL;
    CK_ULONG n;
    CK_RV rc;

    if (ctx->active == TRUE) {
        rc = CKR_OPERATION_ACTIVE;
        goto out;
    }

    /* Get all object attributes needed */
    attr[0].type = CKA_SIGN;
    attr[1].type = CKA_ALLOWED_MECHANISMS;
    attr[2].type = CKA_KEY_TYPE;
    attr[3].type = CKA_CLASS;
    /* Check if key supports sign attribute */
    rc = get_attr_value(hSession, key, attr, 1);
    if (rc != CKR_OK) {
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto out;
    }
    rc = get_attr_value(hSession, key, &attr[1], 3);
    if (rc != CKR_OK)
        goto out;
    obj_mechanisms =
        (CK_MECHANISM_TYPE_PTR)malloc(attr[1].ulValueLen);
    if (!obj_mechanisms) {
        rc = CKR_HOST_MEMORY;
        goto out;
    }
    attr[0].pValue = &sign;
    attr[1].pValue = obj_mechanisms;
    attr[2].pValue = &keytype;
    attr[3].pValue = &class;
    rc = get_attr_value(hSession, key, attr, 4);
    if (rc != CKR_OK)
        goto out;

    /* Check if object can support sign mechanism */
    if (sign != TRUE) {
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto out;
    }

    /* Check if object can support sign mechanism type */
    for (n = 0; n < (attr[1].ulValueLen/sizeof(CK_MECHANISM_TYPE)); n++) {
        if (mech->mechanism ==
            *((CK_MECHANISM_TYPE_PTR)attr[1].pValue + n)) {
            found = TRUE;
            break;
        }
    }
    if (found != TRUE) {
        rc = CKR_MECHANISM_INVALID;
        goto out;
    }

    /* Check for key attributes if they match with mechanism provided */
    switch (mech->mechanism) {
    case CKM_RSA_PKCS:
    case CKM_MD5_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
        /* Key type must be RSA */
        if (keytype != CKK_RSA) {
            rc = CKR_KEY_TYPE_INCONSISTENT;
            goto out;
        }
        break;

    case CKM_ECDSA:
    case CKM_ECDSA_SHA1:
        /* Key type must be ECC */
        if (keytype != CKK_EC) {
            rc = CKR_KEY_TYPE_INCONSISTENT;
            goto out;
        }
        break;

    default:
        rc = CKR_MECHANISM_INVALID;
        goto out;
    }

    if (mech->ulParameterLen != 0) {
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto out;
    }

    /* Key class must be Private */
    if (class != CKO_PRIVATE_KEY) {
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto out;
    }

    /* Multi-part ops is supported.
     * Memory will be allocated as part of the Update procedure.
     */
    ctx->context_len = 0;
    ctx->context     = NULL;

    if (mech->ulParameterLen > 0) {
        ptr = (CK_BYTE *)malloc(mech->ulParameterLen);
        if (!ptr) {
            rc = CKR_HOST_MEMORY;
            goto out;
        }
        memcpy(ptr, mech->pParameter, mech->ulParameterLen);
    }

    /* Keeping the sign information in session ctx */
    ctx->key                 = key;
    ctx->mech.ulParameterLen = mech->ulParameterLen;
    ctx->mech.mechanism      = mech->mechanism;
    ctx->mech.pParameter     = ptr;
    ctx->multi               = FALSE;
    ctx->multi_init          = FALSE;
    ctx->active              = TRUE;
    ctx->recover             = recover_mode;

out:
    if (obj_mechanisms)
        free(obj_mechanisms);

    return rc;
}

/* Implementation of raw sign api */
static CK_RV rsa_sign_pkcs(CK_SESSION_HANDLE hSession, session *sess,
                           CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                           CK_BYTE_PTR pSignature,
                           CK_ULONG_PTR pulSignatureLen)
{
    CK_RV rc = CKR_OK;
    sign_verify_context *ctx = &sess->sign_ctx;
    CK_ATTRIBUTE attr = {0};
    CK_ULONG req_sig_len = 0, padding_len, i;
    CK_BYTE data[MAX_RSA_KEYLEN];
    NXP_FUNCTION_LIST_PTR nxp_funcs = NULL;
    NXP_RET_CODE ret = NXP_OK;
    NXP_MECHANISM_INFO mechType = {0};
    NXP_OBJECT_HANDLE nxp_key;

    /* Get required signature buffer size from size of modulus */
    attr.type = CKA_MODULUS;
    rc = get_attr_value(hSession, ctx->key, &attr, 1);
    if (rc != CKR_OK)
        goto out;
    req_sig_len = attr.ulValueLen;

    /*
     * If signature buffer is NULL then return size of
     * buffer to be allocated.
     */
    if (!pSignature) {
        *pulSignatureLen = req_sig_len;
        rc = CKR_OK;
        goto out;
    }

    /* Signature length should not be less than required size */
    if (*pulSignatureLen < req_sig_len) {
        rc = CKR_BUFFER_TOO_SMALL;
        goto out;
    }

    /*
     * Check if input data length > (key_length - 11), if yes
     * return error as PKCS 1.5 Block type = 01 (used in RSA signature
     * scheme) requires input data to be less  than or equal to
     * key_length - 11.
     */
    if (ulDataLen > (req_sig_len - 11)) {
        rc = CKR_DATA_LEN_RANGE;
        goto out;
    }

    print_info("Digest before Padding & NXP_Decrypt.\n");
    for (i = 0; i < ulDataLen; i++) {
        print_info("%x", pData[i]);
    }
    print_info("\n");
    /* The padding string PS shall consist of k-3-||D|| octets. */
    padding_len = req_sig_len - 3 - ulDataLen;

    /*
     * For block type 01, PS shall have value FF.
     * EB = 00 || 01 || PS * i || 00 || D
     */
    data[0] = (CK_BYTE)0;
    data[1] = (CK_BYTE)RSA_PKCS_BT_1;
    for (i = 2; i < (padding_len + 2); i++)
        data[i] = (CK_BYTE)0xff;
    data[i] = (CK_BYTE)0;
    i++;
    memcpy(&data[i], pData, ulDataLen);

    /* Maps RSA sign --> NXP_decrypt for private key operation */
    nxp_funcs = get_slot_function_list(sess->session_info.slotID);
    if (!nxp_funcs)
        return CKR_ARGUMENTS_BAD;

    mechType.mechanism = NXP_RSA_PKCS_NOPAD;
    nxp_key = ((struct object_node *)ctx->key)->object.nxp_obj_handle;

    ret = nxp_funcs->NXP_Decrypt(&mechType, nxp_key, data, req_sig_len,
                   pSignature, (uint16_t *)pulSignatureLen);
    if (ret != NXP_OK) {
        print_error("NXP_Decrypt failed with ret code 0x%x\n", ret);
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

out:
    return rc;
}

/* Implementation of hash based sign api */
static CK_RV rsa_hash_sign_pkcs(CK_SESSION_HANDLE hSession, session *sess,
                                CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                                CK_BYTE_PTR pSignature,
                                CK_ULONG_PTR pulSignatureLen)
{
    CK_RV rc = CKR_OK;
    sign_verify_context *ctx = &sess->sign_ctx;
    CK_ATTRIBUTE attr = {0};
    CK_ULONG req_sig_len = 0;
    CK_BYTE hash[MAX_HASH_LEN];
    CK_ULONG hash_len = MAX_HASH_LEN;
    NXP_FUNCTION_LIST_PTR nxp_funcs = NULL;
    NXP_RET_CODE ret = NXP_OK;
    NXP_MECHANISM_INFO signType = {0}, digestType = {0};
    NXP_OBJECT_HANDLE nxp_key;

    /* Get required signature buffer size from size of modulus */
    attr.type = CKA_MODULUS;
    rc = get_attr_value(hSession, ctx->key, &attr, 1);
    if (rc != CKR_OK)
        goto out;
    req_sig_len = attr.ulValueLen;

    /*
     * If signature buffer is NULL then return size of
     * buffer to be allocated.
     */
    if (!pSignature) {
        *pulSignatureLen = req_sig_len;
        rc = CKR_OK;
        goto out;
    }

    /* Signature length should not be less than required size */
    if (*pulSignatureLen < req_sig_len) {
        rc = CKR_BUFFER_TOO_SMALL;
        goto out;
    }

    /* Maps RSA hash based sign --> NXP_Digest and NXP_Sign */
    nxp_funcs = get_slot_function_list(sess->session_info.slotID);
    if (!nxp_funcs)
        return CKR_ARGUMENTS_BAD;

    switch (ctx->mech.mechanism) {
    case CKM_MD5_RSA_PKCS:
        signType.mechanism = NXP_RSASSA_PKCS1_V1_5_MD5;
        digestType.mechanism = NXP_MD5;
        break;
    case CKM_SHA1_RSA_PKCS:
        signType.mechanism = NXP_RSASSA_PKCS1_V1_5_SHA1;
        digestType.mechanism = NXP_SHA1;
        break;
    case CKM_SHA256_RSA_PKCS:
        signType.mechanism = NXP_RSASSA_PKCS1_V1_5_SHA256;
        digestType.mechanism = NXP_SHA256;
        break;
    case CKM_SHA384_RSA_PKCS:
        signType.mechanism = NXP_RSASSA_PKCS1_V1_5_SHA384;
        digestType.mechanism = NXP_SHA384;
        break;
    case CKM_SHA512_RSA_PKCS:
        signType.mechanism = NXP_RSASSA_PKCS1_V1_5_SHA512;
        digestType.mechanism = NXP_SHA512;
        break;
    default:
        rc = CKR_MECHANISM_INVALID;
        goto out;
    }

    nxp_key = ((struct object_node *)ctx->key)->object.nxp_obj_handle;

    ret = nxp_funcs->NXP_Digest(&digestType, pData, ulDataLen, hash,
                  (uint16_t *)&hash_len);
    if (ret != NXP_OK) {
        print_error("NXP_Digest failed with ret code 0x%x\n", ret);
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    ret = nxp_funcs->NXP_Sign(&signType, nxp_key, hash, hash_len,
                pSignature, (uint16_t *)pulSignatureLen);
    if (ret != NXP_OK) {
        print_error("NXP_Sign failed with ret code 0x%x\n", ret);
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

out:
    return rc;
}

/* Implementation of hash based sign api */
static CK_RV rsa_hash_update_sign_pkcs(session *sess, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    CK_RV rc = CKR_OK;
    sign_verify_context *ctx = &sess->sign_ctx;
    rsa_ec_digest_ctx *rsa_digest_context = (rsa_ec_digest_ctx *) ctx->context;

    NXP_FUNCTION_LIST_PTR nxp_funcs = NULL;

    /* Maps RSA hash-update based C_SignUpdate --> NXP_DigestUpdate */
    nxp_funcs = get_slot_function_list(sess->session_info.slotID);
    if (!nxp_funcs)
        return CKR_ARGUMENTS_BAD;

    if (rsa_digest_context->start_flag == FALSE) {

        switch (ctx->mech.mechanism) {
        case CKM_MD5_RSA_PKCS:
            rsa_digest_context->dgt_ctx.mech.mechanism = CKM_MD5;
            break;
        case CKM_SHA1_RSA_PKCS:
            rsa_digest_context->dgt_ctx.mech.mechanism = CKM_SHA_1;
            break;
        case CKM_SHA256_RSA_PKCS:
            rsa_digest_context->dgt_ctx.mech.mechanism = CKM_SHA256;
            break;
        case CKM_SHA384_RSA_PKCS:
            rsa_digest_context->dgt_ctx.mech.mechanism = CKM_SHA384;
            break;
        case CKM_SHA512_RSA_PKCS:
            rsa_digest_context->dgt_ctx.mech.mechanism = CKM_SHA512;
            break;
        default:
            rc = CKR_MECHANISM_INVALID;
            goto out;
        }

        rc = digest_init(sess, &rsa_digest_context->dgt_ctx, &(rsa_digest_context->dgt_ctx.mech));

        if (rc != CKR_OK)
            goto out;

        rsa_digest_context->start_flag = TRUE;
    }

    rc = digest_update(sess, &rsa_digest_context->dgt_ctx, pPart, ulPartLen);
out:
    return rc;
}

/* Implementation of hash based sign api */
static CK_RV rsa_hash_final_sign_pkcs(CK_SESSION_HANDLE hSession, session *sess,
                                      CK_BYTE_PTR pSignature,
                                      CK_ULONG_PTR pulSignatureLen)
{
    CK_RV rc = CKR_OK;
    sign_verify_context *ctx = &sess->sign_ctx;
    rsa_ec_digest_ctx *rsa_digest_context = (rsa_ec_digest_ctx *) ctx->context;
    CK_ATTRIBUTE attr = {0};
    CK_ULONG req_sig_len = 0;
    CK_BYTE hash[MAX_HASH_LEN];
    CK_ULONG hash_len = MAX_HASH_LEN;
    NXP_FUNCTION_LIST_PTR nxp_funcs = NULL;
    NXP_RET_CODE ret = NXP_OK;
    NXP_MECHANISM_INFO signType = {0};
    NXP_OBJECT_HANDLE nxp_key;

    /* Get required signature buffer size from size of modulus */
    attr.type = CKA_MODULUS;
    rc = get_attr_value(hSession, ctx->key, &attr, 1);
    if (rc != CKR_OK)
        goto out;

    req_sig_len = attr.ulValueLen;

    /*
     * If signature buffer is NULL then return size of
     * buffer to be allocated.
     */
    if (!pSignature) {
        *pulSignatureLen = req_sig_len;
        rc = CKR_OK;
        goto out;
    }

    /* Signature length should not be less than required size */
    if (*pulSignatureLen < req_sig_len) {
        rc = CKR_BUFFER_TOO_SMALL;
        goto out;
    }

    /* Maps RSA hash-final based C_SignFinal --> NXP_DigestFinal and NXP_Sign */
    nxp_funcs = get_slot_function_list(sess->session_info.slotID);
    if (!nxp_funcs)
        return CKR_ARGUMENTS_BAD;

    switch (ctx->mech.mechanism) {
    case CKM_MD5_RSA_PKCS:
        signType.mechanism = NXP_RSASSA_PKCS1_V1_5_MD5;
        rsa_digest_context->dgt_ctx.mech.mechanism = CKM_MD5;
        break;
    case CKM_SHA1_RSA_PKCS:
        signType.mechanism = NXP_RSASSA_PKCS1_V1_5_SHA1;
        rsa_digest_context->dgt_ctx.mech.mechanism = CKM_SHA_1;
        break;
    case CKM_SHA256_RSA_PKCS:
        signType.mechanism = NXP_RSASSA_PKCS1_V1_5_SHA256;
        rsa_digest_context->dgt_ctx.mech.mechanism = CKM_SHA256;
        break;
    case CKM_SHA384_RSA_PKCS:
        signType.mechanism = NXP_RSASSA_PKCS1_V1_5_SHA384;
        rsa_digest_context->dgt_ctx.mech.mechanism = CKM_SHA384;
        break;
    case CKM_SHA512_RSA_PKCS:
        signType.mechanism = NXP_RSASSA_PKCS1_V1_5_SHA512;
        rsa_digest_context->dgt_ctx.mech.mechanism = CKM_SHA512;
        break;
    default:
        rc = CKR_MECHANISM_INVALID;
        goto out;
    }

    nxp_key = ((struct object_node *)ctx->key)->object.nxp_obj_handle;

    /* Checking for the scenario where sign_final is called after sign_init.
     * i.e., without calling sign_update.
     */
    if (rsa_digest_context->dgt_ctx.context == NULL) {
        rc = CKR_OPERATION_NOT_INITIALIZED;
        goto out;
    }

    rc = digest_final(sess, &rsa_digest_context->dgt_ctx, hash, &hash_len);
    if (rc != CKR_OK)
        goto out;

    print_info("Digest before Sign Final\n");
    for (uint32_t i = 0; i < hash_len; i++)    {
        print_info("%x", hash[i]);
    }
    print_info("\n");

    ret = nxp_funcs->NXP_Sign(&signType, nxp_key, hash, hash_len,
                pSignature, (uint16_t *)pulSignatureLen);
    if (ret != NXP_OK) {
        print_error("NXP_Sign failed with ret code 0x%x\n", ret);
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

out:
    return rc;
}

static CK_RV get_ec_obj_size(CK_ATTRIBUTE *attr, uint32_t *obj_size)
{
    uint8_t i = 0, found = 0;

    for (i = 0; i < SUPPORTED_EC_CURVES; i++) {
        if (!memcmp((char *)attr->pValue,
            supported_ec_curves[i].data, attr->ulValueLen)) {
            *obj_size = supported_ec_curves[i].curve_len;
            found = 1;
        }
    }

    if (found)
        return CKR_OK;
    else
        return CKR_ARGUMENTS_BAD;
}

/* Implementation of ECC DSA */
static CK_RV ecc_hash_sign_pkcs(CK_SESSION_HANDLE hSession, session *sess,
                                CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                                CK_BYTE_PTR pSignature,
                                CK_ULONG_PTR pulSignatureLen)
{
    CK_RV rc = CKR_OK;
    sign_verify_context *ctx = &sess->sign_ctx;
    CK_ATTRIBUTE attr = {0};
    CK_ULONG req_sig_len = 0;
    CK_BYTE hash[MAX_HASH_LEN];
    CK_ULONG hash_len = MAX_HASH_LEN;
    NXP_FUNCTION_LIST_PTR nxp_funcs = NULL;
    NXP_RET_CODE ret = NXP_OK;
    NXP_MECHANISM_INFO signType = {0}, digestType = {0};
    NXP_OBJECT_HANDLE nxp_key;
    char *ec_params;
    uint32_t ec_key_len = 0;

    /* Get required signature buffer size from EC PARAMS */
    attr.type = CKA_EC_PARAMS;
    rc = get_attr_value(hSession, ctx->key, &attr, 1);
    if (rc != CKR_OK)
        goto out;

    ec_params = malloc(attr.ulValueLen);
    if (!ec_params)
        goto out;
    attr.pValue = ec_params;

    rc = get_attr_value(hSession, ctx->key, &attr, 1);
    if (rc != CKR_OK)
        goto out;

    rc = get_ec_obj_size(&attr, &ec_key_len);
    if (rc != CKR_OK)
        goto out;

    req_sig_len = 2 * ec_key_len;
    /*
     * If signature buffer is NULL then return size of
     * buffer to be allocated.
     */
    if (!pSignature) {
        *pulSignatureLen = req_sig_len;
        rc = CKR_OK;
        goto out;
    }

    /* Signature length should not be less than required size */
    if (*pulSignatureLen < req_sig_len) {
        rc = CKR_BUFFER_TOO_SMALL;
        goto out;
    }

    /* Maps EC hash based sign --> NXP_Digest and NXP_Sign */
    nxp_funcs = get_slot_function_list(sess->session_info.slotID);
    if (!nxp_funcs)
        return CKR_ARGUMENTS_BAD;

    switch (ctx->mech.mechanism) {
    case CKM_ECDSA:
        signType.mechanism = NXP_ECDSA;
        digestType.mechanism = 0;
        break;
    case CKM_ECDSA_SHA1:
        signType.mechanism = NXP_ECDSA_SHA1;
        digestType.mechanism = NXP_SHA1;
        break;
    default:
        rc = CKR_MECHANISM_INVALID;
        goto out;
    }

    nxp_key = ((struct object_node *)ctx->key)->object.nxp_obj_handle;

    if (digestType.mechanism) {
        ret = nxp_funcs->NXP_Digest(&digestType, pData, ulDataLen, hash,
                      (uint16_t *)&hash_len);
        if (ret != NXP_OK) {
            print_error("NXP_Digest failed with ret code 0x%x\n", ret);
            rc = CKR_GENERAL_ERROR;
            goto out;
        }

        ret = nxp_funcs->NXP_Sign(&signType, nxp_key, hash, hash_len,
                pSignature, (uint16_t *)pulSignatureLen);
        if (ret != NXP_OK) {
            print_error("NXP_Sign failed with ret code 0x%x\n", ret);
            rc = CKR_GENERAL_ERROR;
        }
        goto out;
    }

    ret = nxp_funcs->NXP_Sign(&signType, nxp_key, pData, ulDataLen,
                pSignature, (uint16_t *)pulSignatureLen);
    if (ret != NXP_OK) {
        print_error("NXP_Sign failed with ret code 0x%x\n", ret);
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

out:
    return rc;
}

/* Implementation of hash update based sign api for ECC keys.*/
static CK_RV ecc_hash_update_sign_pkcs(session *sess, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    CK_RV rc = CKR_OK;
    sign_verify_context *ctx = &sess->sign_ctx;
    rsa_ec_digest_ctx *ec_digest_context = (rsa_ec_digest_ctx *) ctx->context;

    NXP_FUNCTION_LIST_PTR nxp_funcs = NULL;

    /* Maps EC hash-update based C_SignUpdate --> NXP_DigestUpdate */
    nxp_funcs = get_slot_function_list(sess->session_info.slotID);
    if (!nxp_funcs)
        return CKR_ARGUMENTS_BAD;

    if (ec_digest_context->start_flag == FALSE) {

        switch (ctx->mech.mechanism) {
        case CKM_ECDSA_SHA1:
            ec_digest_context->dgt_ctx.mech.mechanism = CKM_MD5;
            break;
        default:
            rc = CKR_MECHANISM_INVALID;
            goto out;
        }

        digest_init(sess, &ec_digest_context->dgt_ctx, &(ec_digest_context->dgt_ctx.mech));
        if (rc != CKR_OK)
            goto out;

        ec_digest_context->start_flag = TRUE;
    }
    rc = digest_update(sess, &ec_digest_context->dgt_ctx, pPart, ulPartLen);
out:
    return rc;
}

/* Implementation of hash final based sign final api for ECC key.*/
static CK_RV ecc_hash_final_sign_pkcs(CK_SESSION_HANDLE hSession, session *sess,
                                      CK_BYTE_PTR pSignature,
                                      CK_ULONG_PTR pulSignatureLen)
{
    CK_RV rc = CKR_OK;
    sign_verify_context *ctx = &sess->sign_ctx;
    rsa_ec_digest_ctx *ec_digest_context = (rsa_ec_digest_ctx *) ctx->context;
    CK_ATTRIBUTE attr = {0};
    CK_ULONG req_sig_len = 0;
    CK_BYTE hash[MAX_HASH_LEN];
    CK_ULONG hash_len = MAX_HASH_LEN;
    NXP_FUNCTION_LIST_PTR nxp_funcs = NULL;
    NXP_RET_CODE ret = NXP_OK;
    NXP_MECHANISM_INFO signType = {0};
    NXP_OBJECT_HANDLE nxp_key;

    /* Get required signature buffer size from size of modulus */
    attr.type = CKA_MODULUS;
    rc = get_attr_value(hSession, ctx->key, &attr, 1);
    if (rc != CKR_OK)
        goto out;

    req_sig_len = attr.ulValueLen;

    /*
     * If signature buffer is NULL then return size of
     * buffer to be allocated.
     */
    if (!pSignature) {
        *pulSignatureLen = req_sig_len;
        rc = CKR_OK;
        goto out1;
    }

    /* Signature length should not be less than required size */
    if (*pulSignatureLen < req_sig_len) {
        rc = CKR_BUFFER_TOO_SMALL;
        goto out1;
    }

    /* Maps EC hash-final based C_SignFinal --> NXP_DigestFinal and NXP_Sign */
    nxp_funcs = get_slot_function_list(sess->session_info.slotID);
    if (!nxp_funcs)
        return CKR_ARGUMENTS_BAD;

    switch (ctx->mech.mechanism) {
    case CKM_ECDSA_SHA1:
        signType.mechanism = NXP_ECDSA_SHA1;
        break;
    default:
        rc = CKR_MECHANISM_INVALID;
        goto out;
    }

    nxp_key = ((struct object_node *)ctx->key)->object.nxp_obj_handle;

    /* Checking for the scenario where sign_final is called after sign_init.
     * i.e., without calling sign_update.
     */
    if (ec_digest_context->dgt_ctx.context == NULL) {
        rc = CKR_OPERATION_NOT_INITIALIZED;
        goto out;
    }

    rc = digest_final(sess, &ec_digest_context->dgt_ctx, hash, &hash_len);
    if (rc != CKR_OK)
        goto out;

    ret = nxp_funcs->NXP_Sign(&signType, nxp_key, hash, hash_len,
                pSignature, (uint16_t *)pulSignatureLen);
    if (ret != NXP_OK) {
        print_error("NXP_Sign failed with ret code 0x%x\n", ret);
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

out:
    if (ec_digest_context->dgt_ctx.context) {
        free(ec_digest_context->dgt_ctx.context);
        ec_digest_context->dgt_ctx.context = NULL;
    }

out1:
    return rc;
}

/* NOTE: If mechanism also include calculating the digest please note
  * API supports calculating digest for upto 512bytes.
  */
/* Implementation of sign api */
CK_RV sign(CK_SESSION_HANDLE hSession, session *sess, CK_BYTE_PTR pData,
           CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
           CK_ULONG_PTR pulSignatureLen)
{
    sign_verify_context *ctx = &sess->sign_ctx;
    CK_RV rc = CKR_OK;

    if (ctx->active == FALSE) {
        rc = CKR_OPERATION_NOT_INITIALIZED;
        goto out;
    }

    if (ctx->multi_init == FALSE) {
        ctx->multi = FALSE;
        ctx->multi_init = TRUE;
    }
    /* Check if SignUpdate is called before Sign */
    if (ctx->multi == TRUE) {
        rc = CKR_OPERATION_ACTIVE;
        goto out;
    }

    switch (ctx->mech.mechanism) {
    case CKM_RSA_PKCS:
        rc = rsa_sign_pkcs(hSession, sess, pData, ulDataLen,
                     pSignature, pulSignatureLen);
        if (((rc == CKR_OK) && (pSignature == NULL)) ||
            (rc == CKR_BUFFER_TOO_SMALL))
            goto out;
        break;

    case CKM_MD5_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
        rc = rsa_hash_sign_pkcs(hSession, sess, pData, ulDataLen,
                      pSignature, pulSignatureLen);
        if (((rc == CKR_OK) && (pSignature == NULL)) ||
            (rc == CKR_BUFFER_TOO_SMALL))
            goto out;
        break;
    case CKM_ECDSA:
    case CKM_ECDSA_SHA1:
        rc = ecc_hash_sign_pkcs(hSession, sess, pData, ulDataLen,
            pSignature, pulSignatureLen);
        if (((rc == CKR_OK) && (pSignature == NULL)) ||
            (rc == CKR_BUFFER_TOO_SMALL))
            goto out;
        break;
    default:
        rc = CKR_MECHANISM_INVALID;
        goto out;
    }

    ctx->key = 0;
    ctx->mech.ulParameterLen = 0;
    ctx->mech.mechanism = 0;
    ctx->multi = FALSE;
    ctx->multi_init = FALSE;
    ctx->active = FALSE;
    ctx->recover = FALSE;
    ctx->context_len = 0;

    if (ctx->mech.pParameter) {
        free( ctx->mech.pParameter );
        ctx->mech.pParameter = NULL;
    }

    if (ctx->context) {
        free( ctx->context );
        ctx->context = NULL;
    }

out:
    return rc;
}

/* NOTE: If mechanism also include calculating the digest please note
 * API supports calculating digest for upto 512bytes.
 */
/* Implementation of sign api */
CK_RV sign_update(session *sess, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    sign_verify_context *ctx = &sess->sign_ctx;
    CK_RV rc = CKR_OK;

    if (ctx->active == FALSE) {
        rc = CKR_OPERATION_NOT_INITIALIZED;
        goto out;
    }
    if (ctx->multi_init == FALSE) {
        ctx->multi = TRUE;
        ctx->multi_init = TRUE;

        ctx->context_len = sizeof(rsa_ec_digest_ctx);
        ctx->context = (CK_BYTE *) malloc(sizeof(rsa_ec_digest_ctx));
        if (!ctx->context) {
            print_error("Insufficient CKR_HOST_MEMORY.\n");
            rc = CKR_HOST_MEMORY;
            goto clean_up;
        }
        memset(ctx->context, 0x0, sizeof(rsa_ec_digest_ctx));
    }
    /* Sign is called before SignUpdate */
    if (ctx->multi == FALSE) {
        rc = CKR_OPERATION_ACTIVE;
        goto out;
    }
    switch (ctx->mech.mechanism) {
    case CKM_MD5_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
        rc = rsa_hash_update_sign_pkcs(sess, pPart, ulPartLen);
        if ((rc == CKR_HOST_MEMORY) || (rc == CKR_GENERAL_ERROR)) {
            print_error("Error : CKR_HOST_MEMORY or CKR_GENERAL_ERROR.\n");
            goto clean_up;
        }
        goto out;
    case CKM_ECDSA_SHA1:
        rc = ecc_hash_update_sign_pkcs(sess, pPart, ulPartLen);
        if ((rc == CKR_HOST_MEMORY) || (rc == CKR_GENERAL_ERROR)) {
            print_error("Error : CKR_HOST_MEMORY or CKR_GENERAL_ERROR.\n");
            goto clean_up;
        }
        goto out;
    default:
        rc = CKR_MECHANISM_INVALID;
        goto out;
    }

clean_up:
    ctx->key = 0;
    ctx->mech.ulParameterLen = 0;
    ctx->mech.mechanism = 0;
    ctx->multi = FALSE;
    ctx->multi_init = FALSE;
    ctx->active = FALSE;
    ctx->recover = FALSE;
    ctx->context_len = 0;

    if (ctx->mech.pParameter) {
        free(ctx->mech.pParameter);
        ctx->mech.pParameter = NULL;
    }

    if (ctx->context) {
        free(ctx->context);
        ctx->context = NULL;
    }

out:
    return rc;
}

/* NOTE: If mechanism also include calculating the digest please note
 * API supports calculating digest for upto 512bytes.
 */
/* Implementation of sign api */
CK_RV sign_final(CK_SESSION_HANDLE hSession, session *sess,
		         CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    sign_verify_context *ctx = &sess->sign_ctx;
    CK_RV rc = CKR_OK;

    if (ctx->active == FALSE) {
        rc = CKR_OPERATION_NOT_INITIALIZED;
        goto out;
    }
    switch (ctx->mech.mechanism) {
    case CKM_MD5_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
        if (ctx->context == NULL) {
            rc = CKR_OPERATION_NOT_INITIALIZED;
            goto out;
        }
        rc = rsa_hash_final_sign_pkcs(hSession, sess, pSignature, pulSignatureLen);
        if (((rc == CKR_OK) && (pSignature == NULL)) ||
            (rc == CKR_BUFFER_TOO_SMALL)) {
            goto out;
        }
        break;
    case CKM_ECDSA_SHA1:
        if (ctx->context == NULL) {
            rc = CKR_OPERATION_NOT_INITIALIZED;
            goto out;
        }
        rc = ecc_hash_final_sign_pkcs(hSession, sess, pSignature, pulSignatureLen);
        if (((rc == CKR_OK) && (pSignature == NULL)) ||
            (rc == CKR_BUFFER_TOO_SMALL)) {
            goto out;
        }
        break;
    default:
        rc = CKR_MECHANISM_INVALID;
        goto out;
    }

    ctx->key = 0;
    ctx->mech.ulParameterLen = 0;
    ctx->mech.mechanism = 0;
    ctx->multi = FALSE;
    ctx->active = FALSE;
    ctx->recover = FALSE;
    ctx->context_len = 0;

    if (ctx->mech.pParameter) {
        free(ctx->mech.pParameter);
        ctx->mech.pParameter = NULL;
    }

    if (ctx->context) {
        free(ctx->context);
        ctx->context = NULL;
    }

out:
    return rc;
}
CK_RV get_digest(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
                 CK_UTF8CHAR_PTR newPinHash)
{
    CK_RV rc = CKR_OK;
    NXP_FUNCTION_LIST_PTR nxp_funcs = NULL;
    NXP_RET_CODE ret = NXP_OK;
    NXP_MECHANISM_INFO digestType = {0};
    uint8_t pinHash[SHA256_LEN];
    int16_t pinHashLen = SHA256_LEN;

    digestType.mechanism = NXP_SHA256;

    nxp_funcs = get_slot_function_list(0);
    if (!nxp_funcs) {
        print_error("NXP_Digest nxp_funcs is null \n");
        rc = CKR_ARGUMENTS_BAD;
        goto out;
    }

    ret = nxp_funcs->NXP_Digest(&digestType, pPin, ulPinLen, pinHash,
                (uint16_t *)&pinHashLen);
    if (ret != NXP_OK) {
        print_error("NXP_Digest failed with ret code 0x%x\n", ret);
        rc = CKR_GENERAL_ERROR;
        goto out;
    }

    memcpy(newPinHash, pinHash, pinHashLen);
out:
    return rc;
}

CK_RV Random_gen(session *sess, random_ctx *ctx, CK_BYTE_PTR pRandom, CK_ULONG_PTR pRandomLen)
{
    CK_RV rc = CKR_OK;
    NXP_RET_CODE ret = NXP_OK;
    NXP_FUNCTION_LIST_PTR nxp_funcs = NULL;
    /* Maps C_GenerateRandom --> NXP_GenerateRandom */
    nxp_funcs = get_slot_function_list(sess->session_info.slotID);
    if (!nxp_funcs)
        return CKR_ARGUMENTS_BAD;

    ret = nxp_funcs->NXP_GenerateRandom((NXP_CONTEXT_INFO *)ctx->context, pRandom, (uint16_t *)pRandomLen);

    if ((ret == NXP_OK) && (pRandom == NULL))
        goto out;

    if (ret != NXP_OK) {
        print_error("NXP_GenerateRandom failed with ret code 0x%x\n", ret);
        rc = CKR_GENERAL_ERROR;
    }

    ctx->mech.ulParameterLen = 0;
    ctx->mech.mechanism = 0;
    ctx->context_len = 0;

    if (ctx->mech.pParameter) {
        free(ctx->mech.pParameter);
        ctx->mech.pParameter = NULL;
    }

    if (ctx->context != NULL) {
        free(ctx->context);
        ctx->context = NULL;
    }

out:
    return rc;
}
