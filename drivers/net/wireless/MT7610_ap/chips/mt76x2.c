#include "rt_config.h"

#ifdef MT7662
#include "mcu/MT7662_firmware.h"
#endif

#ifdef MT7612
#include "mcu/MT7612_firmware.h"
#endif

static RTMP_REG_PAIR MT76x2_MACRegTable[] = {
	{PBF_SYS_CTRL, 0x80c00},
	{PBF_CFG, 0x77723c1f},
	{FCE_PSE_CTRL, 0x1},
	{AMPDU_MAX_LEN_20M1S, 0xAA842211},
	{TX_SW_CFG0, 0x604},
	{TX_SW_CFG1, 0x0},
	{TX_SW_CFG2, 0x0},
	{0xa44,	0x0},
	{AUX_CLK_CFG, 0x0},
	{BB_PA_MODE_CFG0, 0x010055FF},
	{BB_PA_MODE_CFG1, 0x00550055},
	{RF_PA_MODE_CFG0, 0x010055FF},
	{RF_PA_MODE_CFG1, 0x00550055},
	{TX_ALC_CFG_0, 0x5},
	{TX0_BB_GAIN_ATTEN, 0x00000000},
	{TX0_RF_GAIN_CORR, 0x00190000},
	{TX_ALC_VGA3, 0x0005000C},
	{TX_PWR_CFG_0, 0x3A3A3A3A},
	{TX_PWR_CFG_1, 0x3A3A3A3A},
	{TX_PWR_CFG_2, 0x3A3A3A3A},
	{TX_PWR_CFG_3, 0x3A3A3A3A},
	{TX_PWR_CFG_4, 0x3A3A3A3A},
	{TX_PWR_CFG_7, 0x3A3A3A3A},
	{TX_PWR_CFG_8, 0x3A},
	{TX_PWR_CFG_9, 0x3A},
	{MT7650_EFUSE_CTRL, 0xD000},
	{PER_PORT_PAUSE_ENABLE_CONTROL1, 0x0},
};

static VOID MT76x2_ChipBBPAdjust(RTMP_ADAPTER *pAd)
{
	static char *ext_str[]={"extNone", "extAbove", "", "extBelow"};
	UCHAR rf_bw, ext_ch;

#ifdef DOT11_N_SUPPORT
	if (get_ht_cent_ch(pAd, &rf_bw, &ext_ch) == FALSE)
#endif /* DOT11_N_SUPPORT */
	{
		rf_bw = BW_20;
		ext_ch = EXTCHA_NONE;
		pAd->CommonCfg.CentralChannel = pAd->CommonCfg.Channel;
	}

#ifdef DOT11_VHT_AC
	if (WMODE_CAP(pAd->CommonCfg.PhyMode, WMODE_AC) &&
		(pAd->CommonCfg.Channel > 14) &&
		(rf_bw == BW_40) &&
		(pAd->CommonCfg.vht_bw == VHT_BW_80) &&
		(pAd->CommonCfg.vht_cent_ch != pAd->CommonCfg.CentralChannel))
	{
		rf_bw = BW_80;
		pAd->CommonCfg.vht_cent_ch = vht_cent_ch_freq(pAd, pAd->CommonCfg.Channel);
	}

//+++Add by shiang for debug
	DBGPRINT(RT_DEBUG_OFF, ("%s():rf_bw=%d, ext_ch=%d, PrimCh=%d, HT-CentCh=%d, VHT-CentCh=%d\n",
				__FUNCTION__, rf_bw, ext_ch, pAd->CommonCfg.Channel,
				pAd->CommonCfg.CentralChannel, pAd->CommonCfg.vht_cent_ch));
//---Add by shiang for debug
#endif /* DOT11_VHT_AC */

	rtmp_bbp_set_bw(pAd, rf_bw);

	/* TX/Rx : control channel setting */
	rtmp_mac_set_ctrlch(pAd, ext_ch);
	rtmp_bbp_set_ctrlch(pAd, ext_ch);
		
#ifdef DOT11_N_SUPPORT
	DBGPRINT(RT_DEBUG_TRACE, ("%s() : %s, ChannelWidth=%d, Channel=%d, ExtChanOffset=%d(%d) \n",
					__FUNCTION__, ext_str[ext_ch],
					pAd->CommonCfg.HtCapability.HtCapInfo.ChannelWidth,
					pAd->CommonCfg.Channel,
					pAd->CommonCfg.RegTransmitSetting.field.EXTCHA,
					pAd->CommonCfg.AddHTInfo.AddHtInfo.ExtChanOffset));
#endif /* DOT11_N_SUPPORT */
}

static VOID MT76x2_ChipSwitchChannel(
	struct _RTMP_ADAPTER *pAd,
	UCHAR Channel,
	BOOLEAN	 bScan)
{



}

static VOID MT76x2_InitMacRegisters(RTMP_ADAPTER *pAd)
{

}

static VOID MT76x2_InitBbpRegisters(RTMP_ADAPTER *pAd)
{

}

static VOID MT76x2_InitRFRegisters(RTMP_ADAPTER *pAd)
{

}

static VOID MT76x2_AsicAntennaDefaultReset(
	IN struct _RTMP_ADAPTER	*pAd,
	IN EEPROM_ANTENNA_STRUC *pAntenna)
{
	pAntenna->word = 0;
	pAntenna->field.RfIcType = 0xf;
	pAntenna->field.TxPath = 2;
	pAntenna->field.RxPath = 2;
}


VOID MT76x2_AsicExtraPowerOverMAC(
	IN PRTMP_ADAPTER pAd)
{
	UINT32 ExtraPwrOverMAC = 0;
	UINT32 ExtraPwrOverTxPwrCfg7 = 0, ExtraPwrOverTxPwrCfg8 = 0, ExtraPwrOverTxPwrCfg9 = 0;

	/* For OFDM_54 and HT_MCS_7, extra fill the corresponding register value into MAC 0x13D4 */
	RTMP_IO_READ32(pAd, 0x1318, &ExtraPwrOverMAC);  
	ExtraPwrOverTxPwrCfg7 |= (ExtraPwrOverMAC & 0x0000FF00) >> 8; /* Get Tx power for OFDM 54 */
	RTMP_IO_READ32(pAd, 0x131C, &ExtraPwrOverMAC);  
	ExtraPwrOverTxPwrCfg7 |= (ExtraPwrOverMAC & 0x0000FF00) << 8; /* Get Tx power for HT MCS 7 */			
	RTMP_IO_WRITE32(pAd, TX_PWR_CFG_7, ExtraPwrOverTxPwrCfg7);

		
	DBGPRINT(RT_DEBUG_INFO, ("Offset =0x13D8, TxPwr = 0x%08X, ", (UINT)ExtraPwrOverTxPwrCfg8));
	
	DBGPRINT(RT_DEBUG_INFO, ("Offset = 0x13D4, TxPwr = 0x%08X, Offset = 0x13DC, TxPwr = 0x%08X\n", 
		(UINT)ExtraPwrOverTxPwrCfg7, 
		(UINT)ExtraPwrOverTxPwrCfg9));
}

static const RTMP_CHIP_CAP MT76x2_ChipCap = {
	.MaxNss = 2,
	.TXWISize = 20,
	.RXWISize = 28,
	.WPDMABurstSIZE = 3,
#ifdef RTMP_FLASH_SUPPORT
	.eebuf = MT76x2_EeBuffer,
#endif
	.SnrFormula = SNR_FORMULA2,
	.FlgIsHwWapiSup = TRUE,
	.VcoPeriod = 10,
	.FlgIsVcoReCalMode = VCO_CAL_MODE_3,
	.FlgIsHwAntennaDiversitySup = FALSE,
#ifdef STREAM_MODE_SUPPORT
	.FlgHwStreamMode = FALSE,
#endif
#ifdef TXBF_SUPPORT
	.FlgHwTxBfCap = FALSE,
#endif
#ifdef FIFO_EXT_SUPPORT
	.FlgHwFifoExtCap = TRUE,
#endif
	.asic_caps |= (fASIC_CAP_PMF_ENC),
	.phy_caps = (fPHY_CAP_24G | fPHY_CAP_5G | fPHY_CAP_HT | fPHY_CAP_VHT),
	.RfReg17WtMethod = RF_REG_WT_METHOD_STEP_ON,
	.MaxNumOfRfId = MAX_RF_ID,
	.pRFRegTable = NULL,
	.MaxNumOfBbpId = 200,
	.pBBPRegTable = NULL,
	.bbpRegTbSize = 0,
#ifdef DFS_SUPPORT
	.DfsEngineNum = 5,
#endif
#ifdef NEW_MBSSID_MODE
	.MBSSIDMode = MBSSID_MODE1,
#else
	.MBSSIDMode = MBSSID_MODE0,
#endif
#ifdef RTMP_EFUSE_SUPPORT
	.EFUSE_USAGE_MAP_START = 0x1e0,
	.EFUSE_USAGE_MAP_END = 0x1fd,    
	.EFUSE_USAGE_MAP_SIZE = 30,
#endif
#ifdef CONFIG_ANDES_SUPPORT
	.WlanMemmapOffset = 0x410000,
	.InbandPacketMaxLen = 192,
	.CmdRspRxRing = RX_RING1,
#endif
	.MCUType = ANDES,
	.FWImageName = MT7662_FirmwareImage,
#ifdef CARRIER_DETECTION_SUPPORT
	.carrier_func = TONE_RADAR_V2;
#endif
};

static const RTMP_CHIP_OP MT76x2_ChipOp = {
	.ChipBBPAdjust = MT76x2_ChipBBPAdjust,
	.ChipSwitchChannel = MT76x2_ChipSwitchChannel,
	.AsicMacInit = MT76x2_InitMacRegisters,
	.AsicBbpInit = MT76x2_InitBbpRegisters,
	.AsicRfInit = MT76x2_InitRFRegisters,
	.AsicAntennaDefaultReset = MT76x2_AsicAntennaDefaultReset,
#ifdef CARRIER_DETECTION_SUPPORT
	.ToneRadarProgram = ToneRadarProgram_v2,
#endif
	.AsicGetTxPowerOffset = AsicGetTxPowerOffset,
	.AsicExtraPowerOverMAC = MT76x2_AsicExtraPowerOverMAC,
};

VOID RT76x2_Init(RTMP_ADAPTER *pAd)
{
	RTMP_CHIP_CAP *pChipCap = &pAd->chipCap;
	UINT32 Value;

	memcpy(&pAd->chipCap, &MT76x2_ChipCap, sizeof(RTMP_CHIP_CAP));
	memcpy(&pAd->chipOps, &MT76x2_ChipOp, sizeof(RTMP_CHIP_OP));
	
	RTMP_IO_READ32(pAd, 0x00, &Value);	
	pChipCap->ChipID = Value;
	
	if (IS_MT7662(pAd))
		pChipCap->IsComboChip = TRUE;

	RTMP_DRS_ALG_INIT(pAd, RATE_ALG_GRP);
		
	rlt_bcn_buf_init(pAd);
}
