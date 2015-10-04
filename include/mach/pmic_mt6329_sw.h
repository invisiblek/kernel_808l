/* Copyright Statement:
 *
 * This software/firmware and related documentation ("MediaTek Software") are
 * protected under relevant copyright laws. The information contained herein
 * is confidential and proprietary to MediaTek Inc. and/or its licensors.
 * Without the prior written permission of MediaTek inc. and/or its licensors,
 * any reproduction, modification, use or disclosure of MediaTek Software,
 * and information contained herein, in whole or in part, shall be strictly prohibited.
 *
 * MediaTek Inc. (C) 2010. All rights reserved.
 *
 * BY OPENING THIS FILE, RECEIVER HEREBY UNEQUIVOCALLY ACKNOWLEDGES AND AGREES
 * THAT THE SOFTWARE/FIRMWARE AND ITS DOCUMENTATIONS ("MEDIATEK SOFTWARE")
 * RECEIVED FROM MEDIATEK AND/OR ITS REPRESENTATIVES ARE PROVIDED TO RECEIVER ON
 * AN "AS-IS" BASIS ONLY. MEDIATEK EXPRESSLY DISCLAIMS ANY AND ALL WARRANTIES,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE OR NONINFRINGEMENT.
 * NEITHER DOES MEDIATEK PROVIDE ANY WARRANTY WHATSOEVER WITH RESPECT TO THE
 * SOFTWARE OF ANY THIRD PARTY WHICH MAY BE USED BY, INCORPORATED IN, OR
 * SUPPLIED WITH THE MEDIATEK SOFTWARE, AND RECEIVER AGREES TO LOOK ONLY TO SUCH
 * THIRD PARTY FOR ANY WARRANTY CLAIM RELATING THERETO. RECEIVER EXPRESSLY ACKNOWLEDGES
 * THAT IT IS RECEIVER'S SOLE RESPONSIBILITY TO OBTAIN FROM ANY THIRD PARTY ALL PROPER LICENSES
 * CONTAINED IN MEDIATEK SOFTWARE. MEDIATEK SHALL ALSO NOT BE RESPONSIBLE FOR ANY MEDIATEK
 * SOFTWARE RELEASES MADE TO RECEIVER'S SPECIFICATION OR TO CONFORM TO A PARTICULAR
 * STANDARD OR OPEN FORUM. RECEIVER'S SOLE AND EXCLUSIVE REMEDY AND MEDIATEK'S ENTIRE AND
 * CUMULATIVE LIABILITY WITH RESPECT TO THE MEDIATEK SOFTWARE RELEASED HEREUNDER WILL BE,
 * AT MEDIATEK'S OPTION, TO REVISE OR REPLACE THE MEDIATEK SOFTWARE AT ISSUE,
 * OR REFUND ANY SOFTWARE LICENSE FEES OR SERVICE CHARGE PAID BY RECEIVER TO
 * MEDIATEK FOR SUCH MEDIATEK SOFTWARE AT ISSUE.
 *
 * The following software/firmware and/or related documentation ("MediaTek Software")
 * have been modified by MediaTek Inc. All revisions are subject to any receiver's
 * applicable license agreements with MediaTek Inc.
 */


/*****************************************************************************
 *
 * Filename:
 * ---------
 *    pmic_mt6329_sw.h
 *
 * Project:
 * --------
 *   Android_Software
 *
 * Description:
 * ------------
 *   This file is intended for PMU 6329 driver.
 *
 * Author:
 * -------
 * -------
 *
 ****************************************************************************/

#ifndef _MT6575_PMIC_SW_BANK0_H_
#define _MT6575_PMIC_SW_BANK0_H_

#include "upmu_sw.h"

//==============================================================================
// The CHIP SPEC of each block
//==============================================================================
typedef enum
{
	BUCK_VPROC = 0,
	BUCK_VCORE,
	BUCK_VRF18,
	BUCK_VIO18,
	BUCK_VPA,
	
	BUCK_MAX
}upmu_buck_list_enum;
extern upmu_buck_profile_entry upmu_buck_profile[];

typedef enum
{
	//Digital LDO
	LDO_VM12_1 = 0,
	LDO_VM12_2,	
	LDO_VM12_INT,
	LDO_VIO28,
	LDO_VSIM,
	LDO_VSIM2,
	LDO_VUSB,
	LDO_VCAMD,
	LDO_VCAM_IO,
	LDO_VCAM_AF,
	LDO_VMC,
	LDO_VMCH,
	LDO_VGP,
	LDO_VGP2,
	LDO_VIBR,

	//Analog LDO
	LDO_VRF,
	LDO_VTCXO,
	LDO_VA1,
	LDO_VA2,
	LDO_VCAMA,
	LDO_VRTC,
	
	LDO_MAX
}upmu_ldo_list_enum;
extern upmu_ldo_profile_entry upmu_ldo_profile[];


//==============================================================================
// PMIC6329 Status Code
//==============================================================================
#define PMIC_TEST_PASS               0x0000
#define PMIC_TEST_FAIL               0xB001
#define PMIC_EXCEED_I2C_FIFO_LENGTH  0xB002
#define PMIC_CHRDET_EXIST            0xB003
#define PMIC_CHRDET_NOT_EXIST        0xB004

//==============================================================================
// PMIC6329 Exported Function
//==============================================================================
extern kal_uint32 pmic_read_interface (kal_uint8 RegNum, kal_uint8 *val, kal_uint8 MASK, kal_uint8 SHIFT);
extern kal_uint32 pmic_config_interface (kal_uint8 RegNum, kal_uint8 val, kal_uint8 MASK, kal_uint8 SHIFT);
extern kal_uint32 pmic_int_en_interface (kal_uint8 RegNum, kal_uint8 sel, kal_bool enable);

extern int mt6329_multi_read_byte(u8 cmd, u8 *returnData, int len);
extern int mt6329_multi_write_byte(u8 *cmd, u8 *writeData, int len);

#endif // _MT6575_PMIC_SW_BANK0_H_

