/*
  * Copyright 2017-19 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

/*
* nxp_api.c
*/


#include "nxp_api_types.h"
#include "nxp_mp.h"
#include "nxp_api.h"
#include <stdio.h>
#include <sys/queue.h>

static NXP_FUNCTION_LIST global_function_list;

NXP_RET_CODE NXP_GetFunctionList(NXP_FUNCTION_LIST_PTR_PTR  ppFuncList)
{
    printf("NXP_GetFunctionList\n");
    NXP_RET_CODE rc = NXP_OK;
    if (NULL == ppFuncList)
    {
        rc = NXP_ERR_BAD_PARAMETERS;
        goto exit;
    }
    global_function_list.NXP_GetObjectAttribute = NXP_HSE_GetObjectAttribute;
    global_function_list.NXP_EnumerateObjects   = NXP_HSE_EnumerateObjects;
    global_function_list.NXP_Sign               = NXP_HSE_Sign;
    global_function_list.NXP_Decrypt            = NXP_HSE_Decrypt;
    global_function_list.NXP_Digest             = NXP_HSE_Digest;
    global_function_list.NXP_DigestInit         = NXP_HSE_DigestInit;
    global_function_list.NXP_DigestUpdate       = NXP_HSE_DigestUpdate;
    global_function_list.NXP_DigestFinal        = NXP_HSE_DigestFinal;
    global_function_list.NXP_GenerateKeyPair    = NXP_HSE_GenerateKeyPair;
    global_function_list.NXP_EraseObject        = NXP_HSE_EraseObject;
    global_function_list.NXP_CreateObject       = NXP_HSE_CreateObject;
    global_function_list.NXP_GenerateRandom     = NXP_HSE_GenerateRandom;

    *ppFuncList = &global_function_list;
exit:
    return (rc);
}

NXP_RET_CODE NXP_HSE_Init(void)
{
    printf("NXP_HSE_Init\n");
    return (NXP_OK);
}

NXP_RET_CODE NXP_HSE_EnumerateObjects(NXP_ATTRIBUTE *pTemplate,
                                      uint32_t attrCount, NXP_OBJECT_HANDLE *phObject,
                                      uint32_t maxObjects, uint32_t *pulObjectCount)
{
    printf("NXP_HSE_EnumerateObjects\n");
    *pulObjectCount = 0x01;
    maxObjects = 0x01;
    *phObject = 0x00;
    attrCount = 0x13;

    return (NXP_OK);
}
void convert_type_to_string (uint8_t value)
{

	switch (value)
     {
         case NXP_ATTR_OBJECT_TYPE:
         {
             printf("NXP_ATTR_OBJECT_TYPE\n");
         }
         break;
         case NXP_ATTR_OBJECT_INDEX:
         {
             printf("NXP_ATTR_OBJECT_INDEX\n");
         }
         break;
         case NXP_ATTR_OBJECT_LABEL:
         {
             printf("NXP_ATTR_OBJECT_LABEL\n");
         }
         break;
         case NXP_ATTR_OBJECT_VALUE:
         {
             printf("NXP_ATTR_OBJECT_VALUE\n");
         }
         break;
         case NXP_ATTR_KEY_TYPE:
         {
             printf("NXP_ATTR_KEY_TYPE\n");
         }
         break;
         case NXP_ATTR_PRIVATE:
         {
             printf("NXP_ATTR_PRIVATE\n");
         }
         break;
         case NXP_ATTR_MODULUS_BITS:
         {
             printf("NXP_ATTR_MODULUS_BITS\n");
         }
         break;
         case NXP_ATTR_MODULUS:
         {
             printf("NXP_ATTR_MODULUS\n");
         }
         break;
         case NXP_ATTR_PUBLIC_EXPONENT:
         {
             printf("NXP_ATTR_PUBLIC_EXPONENT\n");
         }
         break;
         case NXP_ATTR_PRIVATE_EXPONENT:
         {
             printf("NXP_ATTR_PRIVATE_EXPONENT\n");
         }
         break;
         case NXP_ATTR_PRIME_1:
         {
             printf("NXP_ATTR_PRIME_1\n");
         }
         break;
         case NXP_ATTR_PRIME_2:
         {
             printf("NXP_ATTR_PRIME_2\n");
         }
         break;
         case NXP_ATTR_EXPONENT_1:
         {
             printf("NXP_ATTR_EXPONENT_1\n");
         }
         break;
         case NXP_ATTR_EXPONENT_2:
         {
             printf("NXP_ATTR_EXPONENT_2\n");
         }
         break;
         case NXP_ATTR_PARAMS:
         {
             printf("NXP_ATTR_PARAMS\n");
         }
         break;
         case NXP_ATTR_POINT:
         {
             printf("NXP_ATTR_POINT\n");
         }
         break;
         case NXP_ATTR_PRIV_VALUE:
         {
             printf("NXP_ATTR_PRIV_VALUE\n");
         }
         break;
         case NXP_ATTR_COEFFICIENT:
         {
             printf("NXP_ATTR_COEFFICIENT\n");
         }
         break;
         default:
         {
             printf("invalid \n");
         }
         break;

     }
}
NXP_RET_CODE NXP_HSE_CreateObject(NXP_ATTRIBUTE* attr, uint16_t attrCount, NXP_OBJECT_HANDLE *phObject)
{
    printf("NXP_HSE_CreateObject\n");
    printf ("attrCount= %d\n",attrCount);
    printf ("Object= %d\n",*phObject);
    for (int i = 0x00; i < attrCount; i++)
    {
    	printf ("type= %x\n",(NXP_ATTRIBUTE *)(attr+i)->type);
    	convert_type_to_string((NXP_ATTRIBUTE *)(attr+i)->type);
    	printf ("valueLen= %x\n",(NXP_ATTRIBUTE *)(attr+i)->valueLen);
    	printf ("attr->value = \n");
    	for (int j = 0x00; j < (NXP_ATTRIBUTE *)(attr+i)->valueLen ; j++)
    	{
    		if (0 == (j%16))
    		{
    			printf("\n");
    		}
            printf ("%.3d ,",(uint8_t) ((NXP_ATTRIBUTE *)(attr+i)->value[j]));
    	}
    	printf("\n");
    }
    return (NXP_OK);
}

NXP_RET_CODE NXP_HSE_GenerateKeyPair(NXP_MECHANISM_INFO *pMechanism,
                                     NXP_ATTRIBUTE *attr, uint16_t attrCount,
                                     NXP_OBJECT_HANDLE *pPublic_key,
                                     NXP_OBJECT_HANDLE *pPrivate_key)
{
    printf("NXP_HSE_GenerateKeyPair\n");
    return (NXP_OK);
}

NXP_RET_CODE NXP_HSE_EraseObject(NXP_OBJECT_HANDLE hObject)
{
    printf("NXP_HSE_EraseObject\n");
    return (NXP_OK);
}

NXP_RET_CODE NXP_HSE_GetObjectAttribute(NXP_OBJECT_HANDLE hObject,
                                        NXP_ATTRIBUTE *attribute,
                                        uint32_t attrCount)
{
    printf("NXP_HSE_GetObjectAttribute\n");

    return (NXP_OK);
}

NXP_RET_CODE NXP_HSE_Sign(NXP_MECHANISM_INFO *pMechanismType,
                          NXP_OBJECT_HANDLE hObject, const uint8_t *inDigest,
                          uint16_t inDigestLen, uint8_t *outSignature,
                          uint16_t *outSignatureLen)
{
    printf("NXP_HSE_Sign\n");
    return (NXP_OK);
}

NXP_RET_CODE NXP_HSE_Decrypt(NXP_MECHANISM_INFO *pMechanismType,
                             NXP_OBJECT_HANDLE hObject, const uint8_t *inData,
                             uint16_t inDataLen, uint8_t *outData,
                             uint16_t *outDataLen)
{
    printf("NXP_HSE_Decrypt\n");
    return (NXP_OK);
}

NXP_RET_CODE NXP_HSE_Digest(NXP_MECHANISM_INFO *pMechanismType,
                            const uint8_t *inData, uint16_t inDataLen, uint8_t *outDigest,
                            uint16_t *outDigestLen)
{
    printf("NXP_HSE_Digest\n");
    return (NXP_OK);
}

NXP_RET_CODE NXP_HSE_DigestInit(NXP_MECHANISM_INFO *pMechanismType, NXP_CONTEXT_INFO *nxp_ctx)
{

    NXP_RET_CODE ret = NXP_OK;
    printf("NXP_HSE_DigestInit\n");
    nxp_ctx->mech.mechanism = pMechanismType->mechanism;
    switch (nxp_ctx->mech.mechanism)
    {
        case NXP_SHA1:
        {
            SHA1Init(&nxp_ctx->SHA1_ctx);
        }
        break;

        case NXP_SHA256:
        {
            SHA256_Init(&nxp_ctx->SHA256_ctx);
        }
        break;

        case NXP_MD5:
        {
            MD5Init(&nxp_ctx->MD5_ctx);
        }
        break;
        case NXP_SHA512:
        {
            SHA512_Init(&nxp_ctx->SHA512_ctx);
        }
        break;

        case NXP_SHA384:
        {
            SHA384_Init(&nxp_ctx->SHA384_ctx);
        }
        break;
        default:
        {
            ret = NXP_ERR_GENERAL_ERROR;
        }
        break;
    }

    return (ret);
}

NXP_RET_CODE NXP_HSE_DigestUpdate(NXP_CONTEXT_INFO *nxp_ctx, const uint8_t *inPart, uint16_t inPartLen)
{
    NXP_RET_CODE ret = NXP_OK;
    printf("NXP_HSE_DigestUpdate\n");
    /*nxp_ctx->chunk = inPart;
    nxp_ctx->chunkLen = inPartLen;*/

    switch (nxp_ctx->mech.mechanism)
    {
        case NXP_SHA1:
        {
            SHA1Update(&nxp_ctx->SHA1_ctx, inPart, inPartLen);
        }
        break;

        case NXP_SHA256:
        {
            SHA256_Bytes(&nxp_ctx->SHA256_ctx, inPart, inPartLen);
        }
        break;

        case NXP_MD5:
        {
            MD5Update(&nxp_ctx->MD5_ctx, inPart, inPartLen);
        }
        break;
        case NXP_SHA512:
        {
            SHA512_Bytes(&nxp_ctx->SHA512_ctx, inPart, inPartLen);
        }
        break;

        case NXP_SHA384:
        {
            SHA384_Bytes(&nxp_ctx->SHA384_ctx, inPart, inPartLen);
        }
        break;
        default:
        {
            ret = NXP_ERR_GENERAL_ERROR;
        }
        break;
    }

    return (ret);
}

NXP_RET_CODE NXP_HSE_DigestFinal(NXP_CONTEXT_INFO *nxp_ctx, uint8_t *outDigest, uint16_t *outDigestLen)
{
    NXP_RET_CODE ret = NXP_OK;
    printf("NXP_HSE_DigestFinal\n");

    switch (nxp_ctx->mech.mechanism)
    {
        case NXP_SHA1:
        {
            SHA1Final(&nxp_ctx->SHA1_ctx, outDigest);
            *outDigestLen = 20;
        }
        break;

        case NXP_SHA256:
        {
            SHA256_Final(&nxp_ctx->SHA256_ctx, outDigest);
            *outDigestLen = 32;
        }
        break;

        case NXP_MD5:
        {
            MD5Final (&nxp_ctx->MD5_ctx, outDigest);
            *outDigestLen = 16;
        }
        break;

        case NXP_SHA512:
        {
            SHA512_Final(&nxp_ctx->SHA512_ctx, outDigest);
            *outDigestLen = 64;
        }
        break;
        case NXP_SHA384:
        {
            SHA384_Final(&nxp_ctx->SHA512_ctx, outDigest);
            *outDigestLen = 64;
        }
        break;
        default:
        {
            ret = NXP_ERR_GENERAL_ERROR;
        }
        break;
    }
    for (int i = 0x00 ; i< *outDigestLen ; i++)
    {
        printf("%.2x",outDigest[i]);
    }
    printf("\n");
    return (ret);
}

NXP_RET_CODE NXP_HSE_GenerateRandom(NXP_CONTEXT_INFO *nxp_ctx, uint8_t *outrng, uint16_t *outrngLen)
{
    printf("NXP_HSE_GenerateRandom\n");
    return (NXP_OK);
}
