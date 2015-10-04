obj-$(CONFIG_RAETH) += raeth.o
raeth-objs := raether.o ra_mac.o mii_mgr.o ra_rfrw.o

#EXTRA_CFLAGS   += -DCONFIG_RAETH_MULTIPLE_RX_RING
#EXTRA_CFLAGS = -Idrivers/net/raeth/rtl8367b/include -DCHIP_RTL8367RB -D_LITTLE_ENDIAN -DMDC_MDIO_OPERATION

ifneq ($(CONFIG_P5_RGMII_TO_MAC_MODE),)
EXTRA_CFLAGS = -Idrivers/net/raeth/rtl8367b/include -DCHIP_RTL8367RB -D_LITTLE_ENDIAN -DMDC_MDIO_OPERATION
raeth-objs += rtl8367b/rtk_api.o
raeth-objs += rtl8367b/rtl8367b_asicdrv.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_storm.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_port.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_green.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_dot1x.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_eeelldp.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_interrupt.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_mirror.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_rrcp.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_autofallback.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_rldp.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_inbwctrl.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_pkg.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_gpio.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_eeep.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_svlan.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_hsb.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_eee.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_led.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_vlan.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_oam.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_rma.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_cputag.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_scheduling.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_eav.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_misc.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_acl.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_mib.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_lut.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_fc.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_specialCongest.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_igmp.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_portIsolation.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_phy.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_trunking.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_qos.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_unknownMulticast.o
raeth-objs += rtl8367b/rtl8367b_asicdrv_meter.o
raeth-objs += rtl8367b/rtl8367b_drv.o
raeth-objs += rtl8367b/mld_acl.o
endif

ifeq ($(CONFIG_RAETH_QOS),y)
raeth-objs += ra_qos.o
endif

ifeq ($(CONFIG_ETHTOOL),y)
ifeq ($(CONFIG_RAETH_ROUTER),y)
raeth-objs += ra_ethtool.o
endif
endif

ifeq ($(CONFIG_RALINK_RT3052_MP2),y)
raeth-objs += mcast.o
endif

ifeq ($(CONFIG_RAETH_NETLINK),y)
raeth-objs += ra_netlink.o
endif

ifeq ($(CONFIG_RAETH_GMAC2),y)
EXTRA_CFLAGS += -DCONFIG_PSEUDO_SUPPORT
endif

ifeq ($(CONFIG_RT2860V2_AP_MEMORY_OPTIMIZATION),y)
EXTRA_CFLAGS   += -DMEMORY_OPTIMIZATION
endif

ifeq ($(CONFIG_RA_NETWORK_WORKQUEUE_BH),y)
EXTRA_CFLAGS   += -DWORKQUEUE_BH
endif

ifeq ($(CONFIG_TASKLET_WORKQUEUE_SW),y)
EXTRA_CFLAGS   += -DTASKLET_WORKQUEUE_SW
endif
