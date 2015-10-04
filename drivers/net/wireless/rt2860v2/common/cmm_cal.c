/*
 ***************************************************************************
 * Ralink Tech Inc.
 * 4F, No. 2 Technology 5th Rd.
 * Science-based Industrial Park
 * Hsin-chu, Taiwan, R.O.C.
 *
 * (c) Copyright 2002-2009, Ralink Technology, Inc.
 *
 * All rights reserved. Ralink's source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of Ralink Tech. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of Ralink Technology, Inc. is obtained.
 ***************************************************************************

	Module Name:
	cmm_rf_cal.c

	Abstract:
	RF calibration and profile related functions

	Revision History:
	Who         When          What
	--------    ----------    ----------------------------------------------
	Arvin Tai     2012/05/02
*/

#include "rt_config.h"

REG_PAIR RT6352_VGA_TABLE[] =
{/* Gain(dB), BBP_R66 */
	{0, 0x10},
	{2, 0x14},
	{4, 0x18},
	{6, 0x1C},
	{8, 0x20},
	{10, 0x30},
	{12, 0x34},
	{14, 0x38},
	{16, 0x3C},
	{18, 0x40},
	{20, 0x44},
	{22, 0x60},
	{24, 0x64},
	{26, 0x68},
	{28, 0x6C},
	{30, 0x70},
	{32, 0x74},
	{34, 0x78},
	{36, 0x7C},
};

UCHAR RT6352_VGA_TABLE_PARMS = (sizeof(RT6352_VGA_TABLE) / sizeof(REG_PAIR));

INT32 CalcCalibration(
	IN PRTMP_ADAPTER pAd,
	IN COMPLEX_VALUE iqData[][3],
	IN INT numSamples)
{
	UCHAR ii;
	INT32 sum = 0;

	for (ii= 0; ii < numSamples ; ii++)
	{
		sum += iqData[ii][0].q;
	}

	return (sum / 16);
}

INT32 CalcRCalibrationCode(
	IN PRTMP_ADAPTER pAd,
	IN INT32 D1,
	IN INT32 D2)
{
	INT32 CalCode, CalCode1;

	CalCode = ((D2 - D1) * 1000) / 48;
	CalCode1 = CalCode % 10;
	CalCode = ((D2 - D1) * 100) / 48;

	if (CalCode1 >= 5)
		CalCode++;

	return CalCode;
}

UINT32 *DataCapSaveMacData(
	IN PRTMP_ADAPTER pAd)
{
	UINT32 *saveData, *sdPtr, macAddr, maxAddr;

	/* Save 48KB MAC data. */
	if (os_alloc_mem(pAd, (UCHAR **)&saveData, 0xC000)!= NDIS_STATUS_SUCCESS)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s():Alloc memory failed\n", __FUNCTION__));
		return NULL;
	}

	maxAddr = 0x10000;

	for (sdPtr=saveData, macAddr=0x4000; macAddr<maxAddr; macAddr += 4, sdPtr++) {
		RTMP_IO_READ32(pAd, macAddr, sdPtr);
	}
	return saveData;
}

VOID DataCapRestoreMacData(
	IN PRTMP_ADAPTER pAd,
	IN UINT32 *saveData)
{
	UINT32 *sdPtr, macAddr, maxAddr;

	maxAddr = 0x10000;

	for (sdPtr=saveData, macAddr=0x4000; macAddr<maxAddr; macAddr += 4, sdPtr++)
	{
		RTMP_IO_WRITE32(pAd, macAddr, *sdPtr);
	}
}

/*
	ReadCaptureData - Read capture data from MAC memory
		iqData - used to return the data read. Array of samples for three RF chains
		numSamples - the number of samples to read
*/
VOID ReadCaptureDataFromMemory(
	IN PRTMP_ADAPTER pAd,
	IN COMPLEX_VALUE iqData[][3],
	IN INT numSamples)
{
	UINT32 CaptureStartAddr;
	UINT32 PKT_Addr;
	UINT32 SMM_Addr;
	int i;

	/*********************************************************/
	/* Read [0x440] bit[12:0] */
	RTMP_IO_READ32(pAd, PBF_CAP_CTRL, &CaptureStartAddr);
	CaptureStartAddr = CaptureStartAddr & 0x00001FFF;

	//printk("2. CaptureStartAddr is 0x%lx \n", CaptureStartAddr);

	PKT_Addr = 0x8000+(CaptureStartAddr*4);
	SMM_Addr = 0x4000+(CaptureStartAddr*2);

	for (i=0; i<numSamples; i++) {
		CAPTURE_MODE_PACKET_BUFFER SMM, PKT1, PKT2;

		RTMP_IO_READ32(pAd, SMM_Addr, &SMM.Value);
		SMM_Addr += 4;
		if (SMM_Addr >= 0x8000)  SMM_Addr = SMM_Addr - 0x4000;		

		RTMP_IO_READ32(pAd, PKT_Addr, &PKT1.Value);
		//printk("PKT1 are 0x%08X \n", PKT1.Value);
		PKT_Addr += 4;
		if (PKT_Addr >= 0x10000) PKT_Addr = PKT_Addr - 0x8000;

		RTMP_IO_READ32(pAd, PKT_Addr, &PKT2.Value);
		//printk("PKT2 are 0x%08X \n", PKT2.Value);
		PKT_Addr += 4;
		if (PKT_Addr >= 0x10000) PKT_Addr = PKT_Addr - 0x8000;

		/* Reorder samples so iqData[i][0] is Ant0, iqData[i][1] is Ant1, iqData[i][2] is Ant2 */
		if (IS_RT6352(pAd))
		{
			iqData[i][2].i = SMM.field.BYTE1;
			iqData[i][2].q = SMM.field.BYTE0;
			iqData[i][1].i = PKT1.field.BYTE3;
			iqData[i][1].q = PKT1.field.BYTE2;
			iqData[i][0].i = PKT1.field.BYTE1;
			iqData[i][0].q = PKT1.field.BYTE0;
			if (++i >= numSamples)
				break;

			iqData[i][2].i = SMM.field.BYTE3;
			iqData[i][2].q = SMM.field.BYTE2;
			iqData[i][1].i = PKT2.field.BYTE3;
			iqData[i][1].q = PKT2.field.BYTE2;
			iqData[i][0].i = PKT2.field.BYTE1;
			iqData[i][0].q = PKT2.field.BYTE0;
		}
		else
		{
			iqData[i][2].i = SMM.field.BYTE0;
			iqData[i][2].q = SMM.field.BYTE1;
			iqData[i][1].i = PKT1.field.BYTE2;
			iqData[i][1].q = PKT1.field.BYTE3;
			iqData[i][0].i = PKT1.field.BYTE0;
			iqData[i][0].q = PKT1.field.BYTE1;
			if (++i >= numSamples)
				break;

			iqData[i][2].i = SMM.field.BYTE2;
			iqData[i][2].q = SMM.field.BYTE3;
			iqData[i][1].i = PKT2.field.BYTE2;
			iqData[i][1].q = PKT2.field.BYTE3;
			iqData[i][0].i = PKT2.field.BYTE0;
			iqData[i][0].q = PKT2.field.BYTE1;
		}
	}

	return;
}


/*
	DumpCaptureData - Display capture data
		iqData - 3 channels of IQ data
		numSamples - number of samples to display
*/
VOID DumpCaptureData(
	IN COMPLEX_VALUE iqData[][3],
	IN INT StartIndex,
	IN INT numSamples)
{
	int i;

	for (i = StartIndex; i < (StartIndex + numSamples); i++)
	{
		DBGPRINT(RT_DEBUG_WARN, ("%4d\t%4d\t%4d\t%4d\t%4d\t%4d\n",
					iqData[i][0].i, iqData[i][0].q,
					iqData[i][1].i, iqData[i][1].q,
					iqData[i][2].i, iqData[i][2].q));
	}
}

VOID CaptureDataMode(
	IN PRTMP_ADAPTER pAd,
	IN COMPLEX_VALUE iqData[][3])
{
	UINT32 saveSysCtrl, savePbfCfg;
	UINT32 capCtrl, i_count, CaptureStartAddr;
	UINT8 saveBbp196, BbpReg;
	UINT32 CaptureModeOffset = 0x200;

	/* Disable Tx/Rx */
	RTMP_IO_WRITE32(pAd, MAC_SYS_CTRL, 0x00);

	RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R1, &BbpReg);
	BbpReg |= 0x04;
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R1, BbpReg);

	/* Disable Tx/Rx Queue */
	RTMP_IO_READ32(pAd, PBF_CFG, &savePbfCfg);
	RTMP_IO_WRITE32(pAd, PBF_CFG, 0x00000000);

	/* Enable PBF/MAC/DMA clock. */
	RTMP_IO_WRITE32(pAd, PBF_SYS_CTRL, 0x2E00);

	/* Change the PBF SRAM from normal mode to BBP capture mode */
	RTMP_IO_READ32(pAd, PBF_SYS_CTRL, &capCtrl);
	capCtrl |= 0x4000;
	RTMP_IO_WRITE32(pAd, PBF_SYS_CTRL, capCtrl);

	/* Data scope indirect index  */
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R251, 0x64);
	/* ADC capture is selected */
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R252, 0x0);

	/* Save BBP Register */
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R195, 0x0);
	RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R196, &saveBbp196);
	/* Disable Packet detection  */
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R196, 0x80);

	/* IB-INTF indirect index */
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R142, 0x10);
	/* Manual Rx Enable */
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R143, 0x01);

	/* Setup the trigger offset time */
	RTMP_IO_READ32(pAd, PBF_CAP_CTRL, &capCtrl);
	capCtrl &= (~0x80008000); //set bit[31]=0, bit[15]=0 for ADC 8
	RTMP_IO_WRITE32(pAd, PBF_CAP_CTRL, capCtrl);

	/* trigger offset */
	RTMP_IO_READ32(pAd, PBF_CAP_CTRL, &capCtrl);
	capCtrl &= ~(0x1FFF0000);
	RTMP_IO_WRITE32(pAd, PBF_CAP_CTRL, capCtrl);

	if ((CaptureModeOffset > 0) && (CaptureModeOffset <= 0x1FFF))
	{
		RTMP_IO_READ32(pAd, PBF_CAP_CTRL, &capCtrl);
		capCtrl |= CaptureModeOffset << 16;
		RTMP_IO_WRITE32(pAd, PBF_CAP_CTRL, capCtrl);
	}

	/* start capturing */
	RTMP_IO_READ32(pAd, PBF_CAP_CTRL, &capCtrl);
	capCtrl |= 0x40000000;
	RTMP_IO_WRITE32(pAd, PBF_CAP_CTRL, capCtrl);

	RtmpOsMsDelay(100);

	/* Manual Trigger Enable */
	RTMP_IO_READ32(pAd, PBF_CAP_CTRL, &capCtrl);
	capCtrl |= 0x20000000;
	RTMP_IO_WRITE32(pAd, PBF_CAP_CTRL, capCtrl);

	RtmpOsMsDelay(100);

	/* Wait up to 1ms for capture buffer to fill */
	for (i_count=0; i_count < 1000; i_count++)
	{
		RTMP_IO_READ32(pAd, PBF_CAP_CTRL, &capCtrl);
		if ((capCtrl & 0x40000000)==0)
			break;
		RTMPusecDelay(50);
	}
	
	if (i_count >= 1000)
		DBGPRINT(RT_DEBUG_ERROR, ("%s(): Monitor the finish of capturing fail !!!\n", __FUNCTION__));

	/* Read [0x440] bit[12:0] */
	RTMP_IO_READ32(pAd, PBF_CAP_CTRL, &CaptureStartAddr);
	DBGPRINT(RT_DEBUG_WARN, ("PBF_CAP_CTRL = %08x\n", CaptureStartAddr));

	CaptureStartAddr = CaptureStartAddr & 0x00001FFF;

	//printk("0. CaptureStartAddr is 0x%lx \n", CaptureStartAddr);

	RTMP_IO_READ32(pAd, PBF_SYS_CTRL, &saveSysCtrl);
	saveSysCtrl &= (~0x00004000);
	RTMP_IO_WRITE32(pAd, PBF_SYS_CTRL, saveSysCtrl);

	ReadCaptureDataFromMemory(pAd, iqData, MAX_CAPTURE_LENGTH);

	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R195, 0x0);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R196, saveBbp196);

	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R142, 0x10);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R143, 0x0);

	/*	reset packet buffer */
	RTMP_IO_WRITE32(pAd, PBF_CTRL, 0x00000020);

	RTMP_IO_WRITE32(pAd, PBF_CFG, savePbfCfg);

	return; 
}


VOID R_Calibration(
	IN PRTMP_ADAPTER pAd)
{
	UINT32 saveMacSysCtrl, saveSysCtrl;
	UINT32 savePbfCfg, saveDmaCtrl;
	UINT32 saveMacPwrPinCfg;
	UCHAR  saveRfB0R1, saveRfB0R34, saveRfB0R35;
	UCHAR  saveRfB5R4, saveRfB5R17, saveRfB5R18;
	UCHAR  saveRfB5R19, saveRfB5R20;
	UCHAR byteValue = 0;
	INT32 D1 = 0, D2 = 0;
	INT32 RCalCode;

	PCAP_IQ_DATA capIqData = NULL;
	INT allocSize = MAX_CAPTURE_LENGTH * sizeof(COMPLEX_VALUE) * 3;

	/* Allocate buffer for capture data */
	capIqData = (PCAP_IQ_DATA) kmalloc(allocSize, MEM_ALLOC_FLAG);

	if (capIqData == NULL)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("%s():Alloc memory failed\n", __FUNCTION__));
		return;
	}

	/* Save MAC registers */
	RTMP_IO_READ32(pAd, MAC_SYS_CTRL, &saveMacSysCtrl);
	RTMP_IO_READ32(pAd, PBF_SYS_CTRL, &saveSysCtrl);
	RTMP_IO_READ32(pAd, PBF_CFG, &savePbfCfg);
	RTMP_IO_READ32(pAd, WPDMA_GLO_CFG, &saveDmaCtrl);
	RTMP_IO_READ32(pAd, PWR_PIN_CFG, &saveMacPwrPinCfg);

	{
		UINT32 dmaCfg, macCfg, macStatus, txrxPgcnt;
		UINT32 DTxCycle, DRxCycle, MTxCycle, MRxCycle;
		ULONG stTime, dt_time, dr_time, mt_time, mr_time;

		DTxCycle = DRxCycle = MTxCycle = MRxCycle = 0;
		RTMP_IO_READ32(pAd, 0x438, &txrxPgcnt);

		/* Disable DMA Tx and wait DMA Tx status in idle state */
		NdisGetSystemUpTime(&stTime);
		RTMP_IO_READ32(pAd, WPDMA_GLO_CFG, &dmaCfg);
		dmaCfg &= (~0x1);
		RTMP_IO_WRITE32(pAd, WPDMA_GLO_CFG, dmaCfg);
		for (DTxCycle = 0; DTxCycle < 10000; DTxCycle++)
		{
            RTMP_IO_READ32(pAd, WPDMA_GLO_CFG, &dmaCfg);
			if (dmaCfg & 0x2)
                RTMPusecDelay(50);
			else
				break;
		}
		NdisGetSystemUpTime(&dt_time);
		dt_time -= stTime;	
		if (DTxCycle == 10000)
		{
			DBGPRINT(RT_DEBUG_WARN, ("%s(cnt=%d,time=0x%lx):stop DTx,dmaCfg=%d!\n",
				__FUNCTION__, DTxCycle, dt_time, dmaCfg));
		}

		/* stop PBF txQ */
		RTMP_IO_WRITE32(pAd, PBF_CFG, (savePbfCfg & (~0x14)));

		/* Disable MAC Tx and MAC Rx and wait MAC Tx/Rx status in idle state */
		/* MAC Tx */
		NdisGetSystemUpTime(&stTime);
		RTMP_IO_READ32(pAd, MAC_SYS_CTRL, &macCfg);
		macCfg &= (~0x04);
		RTMP_IO_WRITE32(pAd, MAC_SYS_CTRL, macCfg);
		for (MTxCycle = 0; MTxCycle < 10000; MTxCycle++)
		{
			RTMP_IO_READ32(pAd, MAC_STATUS_CFG, &macStatus);
			if (macStatus & 0x1)
                RTMPusecDelay(50);
			else
				break;
		}
		NdisGetSystemUpTime(&mt_time);
		mt_time -= stTime;
		if (MTxCycle == 10000)
		{
			DBGPRINT(RT_DEBUG_WARN, ("%s(cnt=%d,time=0x%lx):stop MTx,macStatus=0x%x!\n", 
				__FUNCTION__, MTxCycle, mt_time, macStatus));
		}
		
		/* MAC Rx */
		NdisGetSystemUpTime(&stTime);
		RTMP_IO_READ32(pAd, MAC_SYS_CTRL, &macCfg);
		macCfg &= (~0x08);
		RTMP_IO_WRITE32(pAd, MAC_SYS_CTRL, macCfg);
		for (MRxCycle = 0; MRxCycle < 10000; MRxCycle++)
		{
			RTMP_IO_READ32(pAd, MAC_STATUS_CFG, &macStatus);
			if (macStatus & 0x2)
				RTMPusecDelay(50);
			else
				break;
		}
		NdisGetSystemUpTime(&mr_time);
		mr_time -= stTime;
		if (MRxCycle == 10000)
		{
			DBGPRINT(RT_DEBUG_WARN, ("%s(cnt=%d,time=0x%lx):stop MRx, macStatus=%d!\n",
				__FUNCTION__, MRxCycle, mr_time, macStatus));
		}

		/* stop PBF rxQ */
		RTMP_IO_WRITE32(pAd, PBF_CFG, (savePbfCfg & (~0x1e)));

		/* Disable DMA Rx */
		NdisGetSystemUpTime(&stTime);
		RTMP_IO_READ32(pAd, WPDMA_GLO_CFG, &dmaCfg);
		dmaCfg &= (~0x4);
		RTMP_IO_WRITE32(pAd, WPDMA_GLO_CFG, dmaCfg);
		for (DRxCycle = 0; DRxCycle < 10000; DRxCycle++)
		{
			RTMP_IO_READ32(pAd, WPDMA_GLO_CFG, &dmaCfg);
			if (dmaCfg & 0x8)
				RTMPusecDelay(50);
			else
				break;
		}
		NdisGetSystemUpTime(&dr_time);
		dr_time -= stTime;
		if (DRxCycle == 10000)
		{
			DBGPRINT(RT_DEBUG_WARN, ("%s(cnt=%d,time=0x%lx):stop DRx, dmaCfg=%d!\n",
					__FUNCTION__, DRxCycle, dr_time, dmaCfg));
		}
	}

	/* Save RF Register */
	RT635xReadRFRegister(pAd, RF_BANK0, RF_R01, &saveRfB0R1);
	RT635xReadRFRegister(pAd, RF_BANK0, RF_R34, &saveRfB0R34);
	RT635xReadRFRegister(pAd, RF_BANK0, RF_R35, &saveRfB0R35);
	RT635xReadRFRegister(pAd, RF_BANK5, RF_R04, &saveRfB5R4);
	RT635xReadRFRegister(pAd, RF_BANK5, RF_R17, &saveRfB5R17);
	RT635xReadRFRegister(pAd, RF_BANK5, RF_R18, &saveRfB5R18);
	RT635xReadRFRegister(pAd, RF_BANK5, RF_R19, &saveRfB5R19);
	RT635xReadRFRegister(pAd, RF_BANK5, RF_R20, &saveRfB5R20);

	/* Enable PBF/MAC/DMA clock. */
	RTMP_IO_WRITE32(pAd, PBF_SYS_CTRL, 0x2E00);

	/* Disable Tx/Rx */
	RTMP_IO_WRITE32(pAd, MAC_SYS_CTRL, 0x7000);

	/* RF bypass MAC */
	RTMP_IO_WRITE32(pAd, RF_BYPASS0, 0x0000FFFF);
	RTMP_IO_WRITE32(pAd, RF_CONTROL0, 0x0000000A);

	RTMP_IO_WRITE32(pAd, PWR_PIN_CFG, 0x00000001);

	RTMP_IO_WRITE32(pAd, RF_BYPASS1, 0x00007FFF);
	RTMP_IO_WRITE32(pAd, RF_BYPASS2, 0x00003331);
	RTMP_IO_WRITE32(pAd, RF_CONTROL2, 0x00003031);

	RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R4, &byteValue);
	byteValue &= (~0x18);
	byteValue |= 0x10;
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R4, byteValue);

	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R04, 0x27);
	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R17, 0x80);
	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R18, 0x83);
	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R19, 0x00);
	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R20, 0x20);

	RT635xWriteRFRegister(pAd, RF_BANK0, RF_R01, 0x00);
	RT635xWriteRFRegister(pAd, RF_BANK0, RF_R34, 0x13);
	RT635xWriteRFRegister(pAd, RF_BANK0, RF_R35, 0x00);

	CaptureDataMode(pAd, capIqData);
	DumpCaptureData(capIqData, 0, 512);

	D1 = CalcCalibration(pAd, capIqData, 16);

	RT635xWriteRFRegister(pAd, RF_BANK0, RF_R35, 0x01);

	CaptureDataMode(pAd, capIqData);
	DumpCaptureData(capIqData, 0, 512);

	D2 = CalcCalibration(pAd, capIqData, 16);

	RCalCode = CalcRCalibrationCode(pAd, D1, D2);

	printk("D1 = %d, D2 = %d, CalCode = %d !!!\n", D1, D2, RCalCode);


	/* Restore RF Register */
	RT635xWriteRFRegister(pAd, RF_BANK0, RF_R01, saveRfB0R1);
	RT635xWriteRFRegister(pAd, RF_BANK0, RF_R34, saveRfB0R34);
	RT635xWriteRFRegister(pAd, RF_BANK0, RF_R35, saveRfB0R35);
	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R04, saveRfB5R4);
	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R17, saveRfB5R17);
	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R18, saveRfB5R18);
	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R19, saveRfB5R19);
	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R20, saveRfB5R20);

	/* Restore BBP registers */
	RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R4, &byteValue);
	byteValue &= (~0x18);
	if (pAd->CommonCfg.BBPCurrentBW == BW_40)
		byteValue |= 0x10;
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R4, byteValue);

	/* Restore registers */
	RTMP_IO_WRITE32(pAd, RF_BYPASS0, 0x0);
	RTMP_IO_WRITE32(pAd, RF_CONTROL0, 0x0);
	RTMP_IO_WRITE32(pAd, RF_BYPASS1, 0x0);
	RTMP_IO_WRITE32(pAd, RF_BYPASS2, 0x0);
	RTMP_IO_WRITE32(pAd, RF_CONTROL2, 0x0);

	/*	Return to normal mode */
	RTMP_IO_WRITE32(pAd, PWR_PIN_CFG, saveMacPwrPinCfg);
	RTMP_IO_WRITE32(pAd, PBF_SYS_CTRL, saveSysCtrl);
	RTMP_IO_WRITE32(pAd, PBF_CFG, savePbfCfg);
	RTMP_IO_WRITE32(pAd, MAC_SYS_CTRL, saveMacSysCtrl);
	RTMP_IO_WRITE32(pAd, WPDMA_GLO_CFG, saveDmaCtrl);

	if (capIqData != NULL)
		os_free_mem(pAd, capIqData);
}

VOID R_Calibration_2(
	IN PRTMP_ADAPTER pAd)
{
	UINT32 saveMacSysCtrl;
	UINT32 savePbfCfg, saveDmaCtrl;
	UCHAR  saveRfB0R1, saveRfB0R34, saveRfB0R35;
	UCHAR  saveRfB5R4, saveRfB5R17, saveRfB5R18;
	UCHAR  saveRfB5R19, saveRfB5R20;
	UCHAR byteValue = 0;
	INT32 RCalCode;
	UCHAR R_Cal_Code = 0;
	CHAR D1 = 0, D2 = 0;

	/* Save MAC registers */
	RTMP_IO_READ32(pAd, MAC_SYS_CTRL, &saveMacSysCtrl);
	RTMP_IO_READ32(pAd, PBF_CFG, &savePbfCfg);
	RTMP_IO_READ32(pAd, WPDMA_GLO_CFG, &saveDmaCtrl);

	{
		UINT32 dmaCfg, macCfg, macStatus, txrxPgcnt;
		UINT32 DTxCycle, DRxCycle, MTxCycle, MRxCycle;
		ULONG stTime, dt_time, dr_time, mt_time, mr_time;

		DTxCycle = DRxCycle = MTxCycle = MRxCycle = 0;
		RTMP_IO_READ32(pAd, 0x438, &txrxPgcnt);

		/* Disable DMA Tx and wait DMA Tx status in idle state */
		NdisGetSystemUpTime(&stTime);
		RTMP_IO_READ32(pAd, WPDMA_GLO_CFG, &dmaCfg);
		dmaCfg &= (~0x1);
		RTMP_IO_WRITE32(pAd, WPDMA_GLO_CFG, dmaCfg);
		for (DTxCycle = 0; DTxCycle < 10000; DTxCycle++)
		{
            RTMP_IO_READ32(pAd, WPDMA_GLO_CFG, &dmaCfg);
			if (dmaCfg & 0x2)
                RTMPusecDelay(50);
			else
				break;
		}
		NdisGetSystemUpTime(&dt_time);
		dt_time -= stTime;	
		if (DTxCycle == 10000)
		{
			DBGPRINT(RT_DEBUG_WARN, ("%s(cnt=%d,time=0x%lx):stop DTx,dmaCfg=%d!\n",
				__FUNCTION__, DTxCycle, dt_time, dmaCfg));
		}

		/* stop PBF txQ */
		RTMP_IO_WRITE32(pAd, PBF_CFG, (savePbfCfg & (~0x14)));

		/* Disable MAC Tx and MAC Rx and wait MAC Tx/Rx status in idle state */
		/* MAC Tx */
		NdisGetSystemUpTime(&stTime);
		RTMP_IO_READ32(pAd, MAC_SYS_CTRL, &macCfg);
		macCfg &= (~0x04);
		RTMP_IO_WRITE32(pAd, MAC_SYS_CTRL, macCfg);
		for (MTxCycle = 0; MTxCycle < 10000; MTxCycle++)
		{
			RTMP_IO_READ32(pAd, MAC_STATUS_CFG, &macStatus);
			if (macStatus & 0x1)
                RTMPusecDelay(50);
			else
				break;
		}
		NdisGetSystemUpTime(&mt_time);
		mt_time -= stTime;
		if (MTxCycle == 10000)
		{
			DBGPRINT(RT_DEBUG_WARN, ("%s(cnt=%d,time=0x%lx):stop MTx,macStatus=0x%x!\n", 
				__FUNCTION__, MTxCycle, mt_time, macStatus));
		}
		
		/* MAC Rx */
		NdisGetSystemUpTime(&stTime);
		RTMP_IO_READ32(pAd, MAC_SYS_CTRL, &macCfg);
		macCfg &= (~0x08);
		RTMP_IO_WRITE32(pAd, MAC_SYS_CTRL, macCfg);
		for (MRxCycle = 0; MRxCycle < 10000; MRxCycle++)
		{
			RTMP_IO_READ32(pAd, MAC_STATUS_CFG, &macStatus);
			if (macStatus & 0x2)
				RTMPusecDelay(50);
			else
				break;
		}
		NdisGetSystemUpTime(&mr_time);
		mr_time -= stTime;
		if (MRxCycle == 10000)
		{
			DBGPRINT(RT_DEBUG_WARN, ("%s(cnt=%d,time=0x%lx):stop MRx, macStatus=%d!\n",
				__FUNCTION__, MRxCycle, mr_time, macStatus));
		}

		/* stop PBF rxQ */
		RTMP_IO_WRITE32(pAd, PBF_CFG, (savePbfCfg & (~0x1e)));

		/* Disable DMA Rx */
		NdisGetSystemUpTime(&stTime);
		RTMP_IO_READ32(pAd, WPDMA_GLO_CFG, &dmaCfg);
		dmaCfg &= (~0x4);
		RTMP_IO_WRITE32(pAd, WPDMA_GLO_CFG, dmaCfg);
		for (DRxCycle = 0; DRxCycle < 10000; DRxCycle++)
		{
			RTMP_IO_READ32(pAd, WPDMA_GLO_CFG, &dmaCfg);
			if (dmaCfg & 0x8)
				RTMPusecDelay(50);
			else
				break;
		}
		NdisGetSystemUpTime(&dr_time);
		dr_time -= stTime;
		if (DRxCycle == 10000)
		{
			DBGPRINT(RT_DEBUG_WARN, ("%s(cnt=%d,time=0x%lx):stop DRx, dmaCfg=%d!\n",
					__FUNCTION__, DRxCycle, dr_time, dmaCfg));
		}
	}

	/* Save RF Register */
	RT635xReadRFRegister(pAd, RF_BANK0, RF_R01, &saveRfB0R1);
	RT635xReadRFRegister(pAd, RF_BANK0, RF_R34, &saveRfB0R34);
	RT635xReadRFRegister(pAd, RF_BANK0, RF_R35, &saveRfB0R35);
	RT635xReadRFRegister(pAd, RF_BANK5, RF_R04, &saveRfB5R4);
	RT635xReadRFRegister(pAd, RF_BANK5, RF_R17, &saveRfB5R17);
	RT635xReadRFRegister(pAd, RF_BANK5, RF_R18, &saveRfB5R18);
	RT635xReadRFRegister(pAd, RF_BANK5, RF_R19, &saveRfB5R19);
	RT635xReadRFRegister(pAd, RF_BANK5, RF_R20, &saveRfB5R20);

	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R04, 0x27);
	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R17, 0x80);
	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R18, 0x83);
	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R19, 0x00);
	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R20, 0x20);

	RT635xWriteRFRegister(pAd, RF_BANK0, RF_R01, 0x00);
	RT635xWriteRFRegister(pAd, RF_BANK0, RF_R34, 0x13);
	RT635xWriteRFRegister(pAd, RF_BANK0, RF_R35, 0x00);

	/* RF bypass MAC */
	RTMP_IO_WRITE32(pAd, RF_BYPASS0, 0x00003004);

	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R47, 0x04);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R22, 0x80);
	RTMPusecDelay(50);
	RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R49, &byteValue);
	if (byteValue > 127)
		D1= byteValue - 256;
	else
		D1 = (CHAR)byteValue;
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R22, 0x0);

	RT635xWriteRFRegister(pAd, RF_BANK0, RF_R35, 0x01);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R22, 0x80);
	RTMPusecDelay(50);
	RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R49, &byteValue);
	if (byteValue > 127)
		D2= byteValue - 256;
	else
		D2 = (CHAR)byteValue;
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R22, 0x0);

	RCalCode = CalcRCalibrationCode(pAd, D1, D2);
	if (RCalCode < 0)
		R_Cal_Code = 256 + RCalCode;
	else
		R_Cal_Code = (UCHAR)RCalCode;

	printk("D1 = %d, D2 = %d, CalCode = %d !!!\n", D1, D2, RCalCode);


	/* Restore RF Register */
	RT635xWriteRFRegister(pAd, RF_BANK0, RF_R01, saveRfB0R1);
	RT635xWriteRFRegister(pAd, RF_BANK0, RF_R34, saveRfB0R34);
	RT635xWriteRFRegister(pAd, RF_BANK0, RF_R35, saveRfB0R35);
	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R04, saveRfB5R4);
	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R17, saveRfB5R17);
	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R18, saveRfB5R18);
	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R19, saveRfB5R19);
	RT635xWriteRFRegister(pAd, RF_BANK5, RF_R20, saveRfB5R20);

	RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R21, &byteValue);
	byteValue |= 0x1;
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R21, byteValue);
	RtmpOsMsDelay(1);
	RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R21, &byteValue);
	byteValue &= (~0x1);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R21, byteValue);

	/* Restore registers */
	RTMP_IO_WRITE32(pAd, RF_BYPASS0, 0x0);

	/*	Return to normal mode */
	RTMP_IO_WRITE32(pAd, PBF_CFG, savePbfCfg);
	RTMP_IO_WRITE32(pAd, MAC_SYS_CTRL, saveMacSysCtrl);
	RTMP_IO_WRITE32(pAd, WPDMA_GLO_CFG, saveDmaCtrl);

	RT635xReadRFRegister(pAd, RF_BANK0, RF_R04, &byteValue);
	byteValue = byteValue | 0x80; /* bit 7=vcocal_en*/
	RT635xWriteRFRegister(pAd, RF_BANK0, RF_R04, byteValue);
}


INT Set_TestRCalibration_Proc(
	IN RTMP_ADAPTER	*pAd,
	IN PSTRING arg)
{
	printk("TestRCalibration !!!\n");
	R_Calibration(pAd);

	return TRUE;
}

VOID RtmpKickOutHwNullFrame(
	IN PRTMP_ADAPTER pAd)
{
	UINT8 TXWISize = pAd->chipCap.TXWISize;
	TXWI_STRUC NullTxWI;
	PTXWI_STRUC pTxWI = NULL;
	PUCHAR pNullFrame;
	NDIS_STATUS NState;
	PHEADER_802_11 pNullFr;
	ULONG Length;
	UCHAR *ptr;
	UINT i;
	UINT32 longValue, macStatus;
	USHORT k_count = 0;
	HTTRANSMIT_SETTING MlmeTransmit;

	NState = MlmeAllocateMemory(pAd, (PUCHAR *)&pNullFrame);

	NdisZeroMemory(pNullFrame, 48);

	if (NState == NDIS_STATUS_SUCCESS) 
	{
		pTxWI = &NullTxWI;
		NdisZeroMemory(pTxWI, TXWISize);

		pNullFr = (PHEADER_802_11) pNullFrame;
		Length = sizeof(HEADER_802_11);

		pNullFr->FC.Type = BTYPE_DATA;
		pNullFr->FC.SubType = SUBTYPE_NULL_FUNC;
		pNullFr->FC.ToDs = 0;
		pNullFr->FC.FrDs = 1;

		COPY_MAC_ADDR(pNullFr->Addr1, BROADCAST_ADDR);
		COPY_MAC_ADDR(pNullFr->Addr2, pAd->CurrentAddress);
		COPY_MAC_ADDR(pNullFr->Addr3, pAd->CommonCfg.Bssid);
	
		pNullFr->FC.PwrMgmt = 0;

		pNullFr->Duration = pAd->CommonCfg.Dsifs + RTMPCalcDuration(pAd, pAd->CommonCfg.TxRate, 14);
	
		/* sequence is increased in MlmeHardTx */
		pNullFr->Sequence = pAd->Sequence;
		pAd->Sequence = (pAd->Sequence+1) & MAXSEQ; /* next sequence  */

		MlmeTransmit.word = 0;
		MlmeTransmit.field.MCS = 15;
		MlmeTransmit.field.MODE = MODE_HTMIX;
		MlmeTransmit.field.BW = 0;
		
		RTMPWriteTxWI(pAd,
					pTxWI,
					FALSE,
					FALSE,
					FALSE,
					FALSE,
					FALSE,
					TRUE,
					0,
					1,
					Length,
					15,
					0,
					15,
					IFS_HTTXOP,
					FALSE,
					&MlmeTransmit);

		pTxWI->MCS = 15;
		pTxWI->PHYMODE = MODE_HTMIX;
		pTxWI->BW = 0;

		ptr = (PUCHAR)&NullTxWI;

#ifdef RT_BIG_ENDIAN
		RTMPWIEndianChange(pAd, ptr, TYPE_TXWI);
#endif
		for (i=0; i < TXWISize; i+=4)
		{
			longValue =  *ptr + (*(ptr + 1) << 8) + (*(ptr + 2) << 16) + (*(ptr + 3) << 24);

			RTMP_IO_WRITE32(pAd, HW_CS_CTS_BASE + i, longValue);

			ptr += 4;
		}

		ptr = pNullFrame;

#ifdef RT_BIG_ENDIAN
		RTMPFrameEndianChange(pAd, ptr, DIR_WRITE, FALSE);
#endif
		for (i= 0; i< Length; i+=4)
		{
			longValue =  *ptr + (*(ptr + 1) << 8) + (*(ptr + 2) << 16) + (*(ptr + 3) << 24);

			RTMP_IO_WRITE32(pAd, HW_CS_CTS_BASE + TXWISize+ i, longValue);

			ptr += 4;
		}
	}

	if (pNullFrame)
		MlmeFreeMemory(pAd, pNullFrame);

	/* kick NULL frame #0 */
	RTMP_IO_WRITE32(pAd, PBF_CTRL, 0x80);

	/* Check MAC Tx/Rx idle */
	for (k_count = 0; k_count < 10000; k_count++)
	{
		RTMP_IO_READ32(pAd, PBF_CTRL, &macStatus);
		if (macStatus & 0x80)
			RTMPusecDelay(50);
		else
			break;
	}

	if (k_count == 10000)
	{
		DBGPRINT(RT_DEBUG_ERROR, ("Wait Null Frame SendOut to MAX  !!!\n"));
	}

	return;
}


BOOLEAN DPD_Calibration(
	IN PRTMP_ADAPTER pAd,
	IN UCHAR AntIdx)
{
	UCHAR index, Max_Retry = 0, Pass_Thres = 0,byteValue = 0;
	UINT32 macStatus;
	UINT32 saveMacSysCtrl, saveTxPinCfg;
	USHORT AM_SUM =0, AM_10 = 0, k_count = 0;
	BOOLEAN DPD_Cal_success = FALSE;
	UCHAR saveBbpR27, saveBbpR65, SaveBbpR66;
	UCHAR saveBbpR242, saveBbpR244;
	UCHAR saveRfB0R1;
	UCHAR saveRfB4R19, saveRfB4R21, saveRfB4R22;
	UCHAR saveRfB5R17, saveRfB5R18, saveRfB5R19, saveRfB5R20;
	UCHAR saveRfB6R19, saveRfB6R21, saveRfB6R22;
	UCHAR saveRfB7R17, saveRfB7R18, saveRfB7R19, saveRfB7R20;
	UCHAR VGA_Upper_Bound, VGA_Lower_Bound, AM_63 = 0;
	UCHAR VGA_code = 0;
	CHAR VGA_code_idx = 0;

	/* Save MAC SYS CTRL registers */
	RTMP_IO_READ32(pAd, MAC_SYS_CTRL, &saveMacSysCtrl);

	/* Save TX PIN CFG registers */
	RTMP_IO_READ32(pAd, TX_PIN_CFG, &saveTxPinCfg);

	/* Save BBP registers */
	RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R27, &saveBbpR27);
	RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R65, &saveBbpR65);
	RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R66, &SaveBbpR66);
	RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R242, &saveBbpR242);
	RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R244, &saveBbpR244);

	/* Save RF registers */
	RT635xReadRFRegister(pAd, RF_BANK0, RF_R01, &saveRfB0R1);
	RT635xReadRFRegister(pAd, RF_BANK4, RF_R19, &saveRfB4R19);
	RT635xReadRFRegister(pAd, RF_BANK4, RF_R21, &saveRfB4R21);
	RT635xReadRFRegister(pAd, RF_BANK4, RF_R22, &saveRfB4R22);
	RT635xReadRFRegister(pAd, RF_BANK5, RF_R17, &saveRfB5R17);
	RT635xReadRFRegister(pAd, RF_BANK5, RF_R18, &saveRfB5R18);
	RT635xReadRFRegister(pAd, RF_BANK5, RF_R19, &saveRfB5R19);
	RT635xReadRFRegister(pAd, RF_BANK5, RF_R20, &saveRfB5R20);
	RT635xReadRFRegister(pAd, RF_BANK6, RF_R19, &saveRfB6R19);
	RT635xReadRFRegister(pAd, RF_BANK6, RF_R21, &saveRfB6R21);
	RT635xReadRFRegister(pAd, RF_BANK6, RF_R22, &saveRfB6R22);
	RT635xReadRFRegister(pAd, RF_BANK7, RF_R17, &saveRfB7R17);
	RT635xReadRFRegister(pAd, RF_BANK7, RF_R18, &saveRfB7R18);
	RT635xReadRFRegister(pAd, RF_BANK7, RF_R19, &saveRfB7R19);
	RT635xReadRFRegister(pAd, RF_BANK7, RF_R20, &saveRfB7R20);

	/* Disable Tx/Rx */
	RTMP_IO_WRITE32(pAd, MAC_SYS_CTRL, 0x00);

	/* Check MAC Tx/Rx idle */
	for (k_count = 0; k_count < 10000; k_count++)
	{
		RTMP_IO_READ32(pAd, MAC_STATUS_CFG, &macStatus);
		if (macStatus & 0x3)
			RTMPusecDelay(50);
		else
			break;
	}

	switch (AntIdx)
	{
		case 0:
			RTMP_IO_WRITE32(pAd, MAC_SYS_CTRL, 0x04);
			RtmpKickOutHwNullFrame(pAd);
			RTMP_IO_WRITE32(pAd, MAC_SYS_CTRL, 0x00);

			/* Setup the MAC to Transmit-Idle Mode through MAC registers */
			RTMP_IO_WRITE32(pAd, TX_PIN_CFG, 0x000C0020);

			/* Connect RF loopback through MAC registers  */
			RT635xWriteRFRegister(pAd, RF_BANK0, RF_R01, 0x41);
			RT635xWriteRFRegister(pAd, RF_BANK5, RF_R17, 0x80);
			RT635xWriteRFRegister(pAd, RF_BANK5, RF_R18, 0xF1);
			RT635xWriteRFRegister(pAd, RF_BANK5, RF_R19, 0xA1);
			RT635xWriteRFRegister(pAd, RF_BANK5, RF_R20, 0x01);
			RT635xWriteRFRegister(pAd, RF_BANK4, RF_R19, 0xA0);
			RT635xWriteRFRegister(pAd, RF_BANK4, RF_R21, 0x17);
			RT635xWriteRFRegister(pAd, RF_BANK4, RF_R22, 0xA1);
			break;

		case 1:
			RTMP_IO_WRITE32(pAd, MAC_SYS_CTRL, 0x04);
			RtmpKickOutHwNullFrame(pAd);
			RTMP_IO_WRITE32(pAd, MAC_SYS_CTRL, 0x00);

			/* Setup the MAC to Transmit-Idle Mode through MAC registers */
			RTMP_IO_WRITE32(pAd, TX_PIN_CFG, 0x000C0080);

			/* Connect RF loopback through MAC registers  */
			RT635xWriteRFRegister(pAd, RF_BANK0, RF_R01, 0x42);
			RT635xWriteRFRegister(pAd, RF_BANK7, RF_R17, 0x80);
			RT635xWriteRFRegister(pAd, RF_BANK7, RF_R18, 0xF1);
			RT635xWriteRFRegister(pAd, RF_BANK7, RF_R19, 0xA1);
			RT635xWriteRFRegister(pAd, RF_BANK7, RF_R20, 0x01);
			RT635xWriteRFRegister(pAd, RF_BANK6, RF_R19, 0xA0);
			RT635xWriteRFRegister(pAd, RF_BANK6, RF_R21, 0x17);
			RT635xWriteRFRegister(pAd, RF_BANK6, RF_R22, 0xA1);
			break;

		default:
			break;
	}

	/* Set BBP DPD parameters through MAC registers  */
	if (AntIdx == 0)
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R23, 0x00);
	else
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R24, 0x00);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R109, 0x00);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R110, 0x00);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R27, 0x00);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R65, 0x39);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x00);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R187, 0x02);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R188, 0x0A);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R187, 0x03);
	if (AntIdx == 0)
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R188, 0x41);
	else
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R188, 0x21);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R242, 0x10);

	Max_Retry = DPD_CAL_MAX_RETRY;
	Pass_Thres = DPD_CAL_PASS_THRES;

	/* Init VGA Gain */
	VGA_code_idx = 5;
	VGA_Upper_Bound = 245;
	VGA_Lower_Bound = 180;

	RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R4, &byteValue);
	byteValue &= (~0x18);
	byteValue |= 0x10;
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R4, byteValue);

	for (index = 0; index < Max_Retry; index++)
	{
		while ((VGA_code_idx >= 0) && (VGA_code_idx <= 18))
		{
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R27, 0x00);
			VGA_code = RT6352_VGA_TABLE[VGA_code_idx].Value;
			DBGPRINT(RT_DEBUG_WARN, ("VGA Gain(%d), R66(%x)\n", RT6352_VGA_TABLE[VGA_code_idx].Register, VGA_code));
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R66, VGA_code);

			/* Turn on debug tone and start DPD calibration through MAC registers */
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R244, 0x2A);
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x00);
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R187, 0x01);
			if (AntIdx == 0)
				RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R188, 0x80);
			else
				RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R188, 0x82);

			/* Wait up to 1ms for capture buffer to fill */
			for (k_count = 0; k_count < 1000; k_count++)
			{
				RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R188, &byteValue);
				if ((byteValue & 0x80)==0)
					break;
				RTMPusecDelay(50);
			}

			if (k_count == 1000)
				DBGPRINT(RT_DEBUG_ERROR, ("Wait capture buffer to MAX  !!!\n"));

			/* Turn off debug tone */
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R244, 0x00);

			/* Check if VGA is appropriate (signal has large swing but not clipped in ADC) */
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x01);
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R187, 0xFF);
			RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R188, &byteValue);
			AM_63 = byteValue;
			DBGPRINT(RT_DEBUG_WARN, ("AM_63 (%d)\n", AM_63));

			if (AM_63 < VGA_Lower_Bound)
				VGA_code_idx++;
			else if (AM_63 > VGA_Upper_Bound)
				VGA_code_idx--;
			else
				break;
		}

		/* VGA_code cannot be found, report error and stop DPD calibration */
		if ((VGA_code_idx < 0) || (VGA_code_idx > 18))
		{
			DBGPRINT(RT_DEBUG_ERROR, (" VGA Code idx overflow(%d) !!!\n", VGA_code_idx));
			DPD_Cal_success = FALSE;
			break;
		}
			
		AM_SUM = 0;
		AM_10 = 0;

		/* DPD calibration protection mechanism */
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x01);

		for (k_count = 0; k_count < 11; k_count++)
		{
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R187, ((4 * k_count) + 3));
			RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R188, &byteValue);
			AM_SUM += byteValue;
		}

		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R187, 0x43);
		RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R188, &byteValue);
		AM_10 = byteValue;

		DBGPRINT(RT_DEBUG_WARN, ("AM_SUM = %d, AM_10 = %d !!!\n", AM_SUM, AM_10));

		{
			RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x01);
		
			for (k_count = 0; k_count < 64; k_count++)
			{
				RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R187, ((4 * k_count) + 3));
				RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R188, &byteValue);
				DBGPRINT(RT_DEBUG_WARN, ("%s(): AM[%d] = %d !\n", __FUNCTION__, k_count, byteValue));
			}
		}
	
		if ((AM_SUM - ((11 * AM_10) / 2)) < Pass_Thres)
		{
			if (AntIdx == 0)
				DBGPRINT(RT_DEBUG_WARN, ("DPD Calibration Pass for TX0 !!!\n"));
			else
				DBGPRINT(RT_DEBUG_WARN, ("DPD Calibration Pass for TX1 !!!\n"));

			DPD_Cal_success = TRUE;
			break;
		}

		if (index == 3)
		{
			Pass_Thres += 3;
		}
	}

	/* Restore RF registers */
	RT635xWriteRFRegister(pAd, RF_BANK0, RF_R01, saveRfB0R1);
	if (AntIdx == 0)
	{
		RT635xWriteRFRegister(pAd, RF_BANK5, RF_R17, saveRfB5R17);
		RT635xWriteRFRegister(pAd, RF_BANK5, RF_R18, saveRfB5R18);
		RT635xWriteRFRegister(pAd, RF_BANK5, RF_R19, saveRfB5R19);
		RT635xWriteRFRegister(pAd, RF_BANK5, RF_R20, saveRfB5R20);
		RT635xWriteRFRegister(pAd, RF_BANK4, RF_R19, saveRfB4R19);
		RT635xWriteRFRegister(pAd, RF_BANK4, RF_R21, saveRfB4R21);
		RT635xWriteRFRegister(pAd, RF_BANK4, RF_R22, saveRfB4R22);
	}
	else
	{
		RT635xWriteRFRegister(pAd, RF_BANK7, RF_R17, saveRfB7R17);
		RT635xWriteRFRegister(pAd, RF_BANK7, RF_R18, saveRfB7R18);
		RT635xWriteRFRegister(pAd, RF_BANK7, RF_R19, saveRfB7R19);
		RT635xWriteRFRegister(pAd, RF_BANK7, RF_R20, saveRfB7R20);
		RT635xWriteRFRegister(pAd, RF_BANK6, RF_R19, saveRfB6R19);
		RT635xWriteRFRegister(pAd, RF_BANK6, RF_R21, saveRfB6R21);
		RT635xWriteRFRegister(pAd, RF_BANK6, RF_R22, saveRfB6R22);
	}

	/* Restore BBP registers */
	RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R4, &byteValue);
	byteValue &= (~0x18);
	if (pAd->CommonCfg.BBPCurrentBW == BW_40)
		byteValue |= 0x10;
#ifdef RALINK_ATE
	if (ATE_ON(pAd))
	{
		PATE_INFO pATEInfo = &(pAd->ate);

		if (pATEInfo->TxWI.BW == BW_40)
			byteValue |= 0x10;
	}
#endif /* RALINK_ATE */
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R4, byteValue);

	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R27, saveBbpR27);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R65, saveBbpR65);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R66, SaveBbpR66);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R242, saveBbpR242);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R244, saveBbpR244);

	/* Resore MAC registers */
	RTMP_IO_WRITE32(pAd, RF_CONTROL3, 0x0);
	RTMP_IO_WRITE32(pAd, RF_BYPASS3, 0x0);

	/* Reset MAC soft-reset */
	RTMP_IO_WRITE32(pAd, MAC_SYS_CTRL, 0x01);
	RTMP_IO_WRITE32(pAd, MAC_SYS_CTRL, 0x0);

	/* Restore TX PIN CFG registers */
	RTMP_IO_WRITE32(pAd, TX_PIN_CFG, saveTxPinCfg);

	/* Restore MAC SYS CTRL registers */
	RTMP_IO_WRITE32(pAd, MAC_SYS_CTRL, saveMacSysCtrl);

#ifdef RALINK_ATE
	if (!ATE_ON(pAd))
		RTMPSetAGCInitValue(pAd, pAd->CommonCfg.BBPCurrentBW);
#endif /* RALINK_ATE */

	return DPD_Cal_success;
}

VOID DoDPDCalibration(
	IN PRTMP_ADAPTER pAd)
{
	BOOLEAN Ant0 = FALSE, Ant1 = FALSE;
	UCHAR byteValue = 0;
#ifdef RALINK_ATE
	UCHAR saveBbpR1 = 0, saveRfB0R2 = 0, BBPValue = 0, RFValue = 0;
#endif /* RALINK_ATE */

	printk(" Do DPD Calibration !!!\n");

#ifdef RALINK_ATE
	if (ATE_ON(pAd))
	{
		ATE_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R1, &saveBbpR1);
		BBPValue = saveBbpR1;
		BBPValue &= (~0x18);
		BBPValue |= 0x10;
		ATE_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R1, BBPValue);

		ATE_RF_IO_READ8_BY_REG_ID(pAd, RF_BANK0, RF_R02, &saveRfB0R2);
		RFValue = saveRfB0R2;
		RFValue |= 0x33;
		ATE_RF_IO_WRITE8_BY_REG_ID(pAd, RF_BANK0, RF_R02, RFValue);
	}
#endif /* RALINK_ATE */

	Ant0 = DPD_Calibration(pAd, 0);
	Ant1 = DPD_Calibration(pAd, 1);

#ifdef RALINK_ATE
	if (ATE_ON(pAd))
	{
		ATE_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R1, saveBbpR1);
		ATE_RF_IO_WRITE8_BY_REG_ID(pAd, RF_BANK0, RF_R02, saveRfB0R2);
	}
#endif /* RALINK_ATE */

	if (Ant0 & Ant1)
	{
		/* Disable DPD Compensation for Pa_mode 1 and 3 */
		RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R4, &byteValue);
		byteValue &= (~0x18);
		byteValue |= 0x10;
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R4, byteValue);

		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x03);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x03);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x05);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x05);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x06);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x06);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x07);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x07);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x08);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x08);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x09);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x09);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0A);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0A);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0B);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0B);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0C);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0C);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0D);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0D);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);

		RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R4, &byteValue);
		byteValue &= (~0x18);
		if (pAd->CommonCfg.BBPCurrentBW == BW_40)
			byteValue |= 0x10;
#ifdef RALINK_ATE
		if (ATE_ON(pAd))
		{
			PATE_INFO pATEInfo = &(pAd->ate);

			if (pATEInfo->TxWI.BW == BW_40)
				byteValue |= 0x10;
		}
#endif /* RALINK_ATE */
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R4, byteValue);

		printk(" Enable DPD Compensation !!!\n");
		/* Enable DPD Compensation */
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x00);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R187, 0x04);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R188, 0x1C);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R187, 0x05);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R188, 0x1C);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R187, 0x00);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R188, 0x40);
	}
}

INT Set_TestDPDCalibration_Proc(
	IN RTMP_ADAPTER	*pAd,
	IN PSTRING arg)
{
	printk("TestDPDCalibration !!!\n");

	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x00);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R187, 0x00);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R188, 0x00);

	DoDPDCalibration(pAd);

	return TRUE;
}

INT Set_TestDPDCalibrationTX0_Proc(
	IN RTMP_ADAPTER	*pAd,
	IN PSTRING arg)
{
	BOOLEAN Ant0 = FALSE;
	UCHAR byteValue = 0;
#ifdef RALINK_ATE
	UCHAR saveBbpR1 = 0, saveRfB0R2 = 0, BBPValue = 0, RFValue = 0;
#endif /* RALINK_ATE */

	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x00);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R187, 0x00);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R188, 0x00);

	printk("TestDPDCalibrationTX0 !!!\n");

#ifdef RALINK_ATE
	if (ATE_ON(pAd))
	{
		ATE_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R1, &saveBbpR1);
		BBPValue = saveBbpR1;
		BBPValue &= (~0x18);
		BBPValue |= 0x10;
		ATE_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R1, BBPValue);

		ATE_RF_IO_READ8_BY_REG_ID(pAd, RF_BANK0, RF_R02, &saveRfB0R2);
		RFValue = saveRfB0R2;
		RFValue |= 0x33;
		ATE_RF_IO_WRITE8_BY_REG_ID(pAd, RF_BANK0, RF_R02, RFValue);
	}
#endif /* RALINK_ATE */

	Ant0 = DPD_Calibration(pAd, 0);

#ifdef RALINK_ATE
	if (ATE_ON(pAd))
	{
		ATE_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R1, saveBbpR1);
		ATE_RF_IO_WRITE8_BY_REG_ID(pAd, RF_BANK0, RF_R02, saveRfB0R2);
	}
#endif /* RALINK_ATE */

	if (Ant0)
	{
		/* Disable DPD Compensation for Pa_mode 1 and 3 */
		RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R4, &byteValue);
		byteValue &= (~0x18);
		byteValue |= 0x10;
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R4, byteValue);

		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x03);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x03);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x05);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x05);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x06);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x06);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x07);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x07);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x08);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x08);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x09);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x09);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0A);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0A);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0B);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0B);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0C);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0C);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0D);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0D);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);

		RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R4, &byteValue);
		byteValue &= (~0x18);
		if (pAd->CommonCfg.BBPCurrentBW == BW_40)
			byteValue |= 0x10;
#ifdef RALINK_ATE
		if (ATE_ON(pAd))
		{
			PATE_INFO pATEInfo = &(pAd->ate);

			if (pATEInfo->TxWI.BW == BW_40)
				byteValue |= 0x10;
		}
#endif /* RALINK_ATE */
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R4, byteValue);

		printk(" Enable DPD Compensation !!!\n");
		/* Enable DPD Compensation */
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x00);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R187, 0x04);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R188, 0x1C);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R187, 0x05);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R188, 0x1C);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R187, 0x00);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R188, 0x40);
	}

	return TRUE;
}

INT Set_TestDPDCalibrationTX1_Proc(
	IN RTMP_ADAPTER	*pAd,
	IN PSTRING arg)
{
	BOOLEAN Ant1 = FALSE;
	UCHAR byteValue = 0;
#ifdef RALINK_ATE
		UCHAR saveBbpR1 = 0, saveRfB0R2 = 0, BBPValue = 0, RFValue = 0;
#endif /* RALINK_ATE */

	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x00);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R187, 0x00);
	RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R188, 0x00);

	printk("TestDPDCalibrationTX1 !!!\n");

#ifdef RALINK_ATE
	if (ATE_ON(pAd))
	{
		ATE_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R1, &saveBbpR1);
		BBPValue = saveBbpR1;
		BBPValue &= (~0x18);
		BBPValue |= 0x10;
		ATE_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R1, BBPValue);

		ATE_RF_IO_READ8_BY_REG_ID(pAd, RF_BANK0, RF_R02, &saveRfB0R2);
		RFValue = saveRfB0R2;
		RFValue |= 0x33;
		ATE_RF_IO_WRITE8_BY_REG_ID(pAd, RF_BANK0, RF_R02, RFValue);
	}
#endif /* RALINK_ATE */

	Ant1 = DPD_Calibration(pAd, 1);

#ifdef RALINK_ATE
	if (ATE_ON(pAd))
	{
		ATE_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R1, saveBbpR1);
		ATE_RF_IO_WRITE8_BY_REG_ID(pAd, RF_BANK0, RF_R02, saveRfB0R2);
	}
#endif /* RALINK_ATE */

	if (Ant1)
	{
		/* Disable DPD Compensation for Pa_mode 1 and 3 */
		RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R4, &byteValue);
		byteValue &= (~0x18);
		byteValue |= 0x10;
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R4, byteValue);

		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x03);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x03);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x05);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x05);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x06);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x06);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x07);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x07);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x08);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x08);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x09);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x09);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0A);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0A);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0B);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0B);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0C);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0C);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0D);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x0D);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R189, 0x0F);

		RTMP_BBP_IO_READ8_BY_REG_ID(pAd, BBP_R4, &byteValue);
		byteValue &= (~0x18);
		if (pAd->CommonCfg.BBPCurrentBW == BW_40)
			byteValue |= 0x10;
#ifdef RALINK_ATE
		if (ATE_ON(pAd))
		{
			PATE_INFO pATEInfo = &(pAd->ate);

			if (pATEInfo->TxWI.BW == BW_40)
				byteValue |= 0x10;
		}
#endif /* RALINK_ATE */
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R4, byteValue);

		printk(" Enable DPD Compensation !!!\n");
		/* Enable DPD Compensation */
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R186, 0x00);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R187, 0x04);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R188, 0x1C);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R187, 0x05);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R188, 0x1C);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R187, 0x00);
		RTMP_BBP_IO_WRITE8_BY_REG_ID(pAd, BBP_R188, 0x40);
	}

	return TRUE;
}

