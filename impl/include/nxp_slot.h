/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#ifndef ___NXP_SLOT_H_INC___
#define ___NXP_SLOT_H_INC___

#include <cryptoki.h>
#include <stdint.h>
/* the slot id that we will assign to the NXP */
#define NXP_S32G_HSM_SLOT_ID 0

#define MAX_MECHANISM_COUNT    16

#define SLOT_ESCRIPTION "S32G_NXP_HSM_BASED_SLOT"
#define TOKEN_LABEL "TS32G_NXP_HSM_BASED_TOKEN"
#define MANUFACTER_ID "NXP-Semiconductors"
#define TOKEN_MODEL "S32G_NXP"
#define TOKEN_SERIAL_NUMBER "FF:FF:FF:FF"


typedef struct mechanisms {
    CK_MECHANISM_TYPE algo ;
    CK_MECHANISM_INFO info;
}mechanisms_t;

CK_RV Get_NXP_SlotInfo(CK_SLOT_INFO_PTR pInfo);
CK_RV Get_NXP_TokenInfo(CK_TOKEN_INFO_PTR pInfo);
CK_RV Get_NXP_MechanismList(CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
CK_RV Get_NXP_MechanismInfo(CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);

#endif /*___NXP_SLOT_H_INC___*/
