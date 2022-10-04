/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <stdio.h>
#include <cryptoki.h>
#include <string.h>
#include <nxp_slot.h>



mechanisms_t nxp_mechanisms[MAX_MECHANISM_COUNT] =
{
    {
        .algo = CKM_MD5,
        .info =
        {
            .ulMinKeySize = 0,
            .ulMaxKeySize = 0,
            .flags = CKF_DIGEST
        }
    },
    {
        .algo = CKM_SHA_1,
        .info =
        {
            .ulMinKeySize = 0,
            .ulMaxKeySize = 0,
            .flags = CKF_DIGEST
        }
    },
    {
        .algo = CKM_SHA256,
        .info =
        {
            .ulMinKeySize = 0,
            .ulMaxKeySize = 0,
            .flags = CKF_DIGEST
        }
    },
    {
        .algo = CKM_SHA384,
        .info =
        {
            .ulMinKeySize = 0,
            .ulMaxKeySize = 0,
            .flags = CKF_DIGEST
        }
    },
    {
        .algo = CKM_SHA512,
        .info =
        {
            .ulMinKeySize = 0,
            .ulMaxKeySize = 0,
            .flags = CKF_DIGEST
        }
    },
    {
        .algo = CKM_RSA_PKCS,
        .info =
        {
            .ulMinKeySize = 512,
            .ulMaxKeySize = 2048,
            .flags = CKF_SIGN | CKF_DECRYPT
        }
    },
    {
        .algo = CKM_MD5_RSA_PKCS,
        .info =
        {
            .ulMinKeySize = 512,
            .ulMaxKeySize = 2048,
            .flags = CKF_SIGN
        }
    },
    {
        .algo = CKM_SHA1_RSA_PKCS,
        .info =
        {
            .ulMinKeySize = 512,
            .ulMaxKeySize = 2048,
            .flags = CKF_SIGN
        }
    },
    {
        .algo = CKM_SHA256_RSA_PKCS,
        .info =
        {
            .ulMinKeySize = 512,
            .ulMaxKeySize = 2048,
            .flags = CKF_SIGN
        }
    },
    {
        .algo = CKM_SHA384_RSA_PKCS,
        .info =
        {
            .ulMinKeySize = 512,
            .ulMaxKeySize = 2048,
            .flags = CKF_SIGN
        }
    },
    {
        .algo = CKM_SHA512_RSA_PKCS,
        .info =
        {
            .ulMinKeySize = 512,
            .ulMaxKeySize = 2048,
            .flags = CKF_SIGN
        }
    },
    {
        .algo = CKM_ECDSA_SHA1,
        .info =
        {
            .ulMinKeySize = 256,
            .ulMaxKeySize = 384,
            .flags = CKF_SIGN
        }
    },
    {
        .algo = CKM_ECDSA,
        .info =
        {
            .ulMinKeySize = 256,
            .ulMaxKeySize = 384,
            .flags = CKF_SIGN
        }
    },
    {
        .algo = CKM_RSA_PKCS_KEY_PAIR_GEN,
        .info =
        {
            .ulMinKeySize = 1024,
            .ulMaxKeySize = 2048,
            .flags = CKF_GENERATE_KEY_PAIR
        }
    },
    {
        .algo = CKM_EC_KEY_PAIR_GEN,
        .info =
        {
            .ulMinKeySize = 256,
            .ulMaxKeySize = 384,
            .flags = CKF_GENERATE_KEY_PAIR
        }
    },
    {
        .algo = CKM_RSA_PKCS_OAEP,
        .info =
        {
            .ulMinKeySize = 1024,
            .ulMaxKeySize = 2048,
            .flags = CKF_DECRYPT
        }
    }
};

CK_RV Get_NXP_SlotInfo(CK_SLOT_INFO_PTR pInfo)
{
    CK_RV rc = CKR_OK;
    memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
    strncpy((char *)pInfo->slotDescription, SLOT_ESCRIPTION, strlen(SLOT_ESCRIPTION));

    memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
    strncpy((char *)pInfo->manufacturerID, MANUFACTER_ID, strlen(MANUFACTER_ID));

    pInfo->flags = CKF_TOKEN_PRESENT;
    pInfo->hardwareVersion.major = 0x01;
    pInfo->hardwareVersion.minor = 0x01;
    pInfo->firmwareVersion.major = 0x01;
    pInfo->firmwareVersion.minor = 0x00;

    return (rc);
}

CK_RV Get_NXP_TokenInfo(CK_TOKEN_INFO_PTR pInfo)
{
    CK_RV rc = CKR_OK;

    memset(pInfo->label, ' ', sizeof(pInfo->label));
    strncpy((char *)pInfo->label, TOKEN_LABEL,  strlen(TOKEN_LABEL));

    memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
    strncpy((char *)pInfo->manufacturerID, MANUFACTER_ID, strlen(MANUFACTER_ID));

    memset(pInfo->model, ' ', sizeof(pInfo->model));
    strncpy((char *)pInfo->model, TOKEN_MODEL, strlen(TOKEN_MODEL));

    memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
    strncpy((char *)pInfo->serialNumber, TOKEN_SERIAL_NUMBER, strlen(TOKEN_SERIAL_NUMBER));

    pInfo->flags = 0;
    pInfo->ulMaxSessionCount = 10;
    pInfo->ulSessionCount = 0;
    pInfo->ulMaxRwSessionCount = 5;
    pInfo->ulRwSessionCount = 0;
    pInfo->ulMaxPinLen = 8;
    pInfo->ulMinPinLen = 4;
    pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->hardwareVersion.major = 0x01;
    pInfo->hardwareVersion.minor = 0x01;
    pInfo->firmwareVersion.major = 0x01;
    pInfo->firmwareVersion.minor = 0x00;
    memset(pInfo->utcTime, '0', sizeof(pInfo->utcTime));

    return (rc);
}

CK_RV Get_NXP_MechanismList(CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
    unsigned int i;
    CK_RV rc = CKR_OK;

    if (NULL == pMechanismList)
    {
        goto exit;
    }
    if (MAX_MECHANISM_COUNT > *pulCount)
    {
        rc =  CKR_BUFFER_TOO_SMALL;
        goto exit;
    }

    for (i = 0; i < MAX_MECHANISM_COUNT; i++)
    {
        pMechanismList[i] = nxp_mechanisms[i].algo;
    }

exit:
    *pulCount = MAX_MECHANISM_COUNT;
    return (rc);
}

CK_RV Get_NXP_MechanismInfo(CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    unsigned int i, found = 0;

    for (i = 0; i < MAX_MECHANISM_COUNT; i++) {
        if (type == nxp_mechanisms[i].algo) {
            memcpy(pInfo, &nxp_mechanisms[i].info, sizeof(CK_MECHANISM_INFO));
            found = 1;
            break;
        }
    }

    if (found)
        return CKR_OK;
    else
        return CKR_MECHANISM_INVALID;
}

