	.file	1 "ra_mac.c"
	.section .mdebug.abi32
	.previous
#APP
	.macro _ssnop; sll $0, $0, 1; .endm
	.macro _ehb; sll $0, $0, 3; .endm
	.macro mtc0_tlbw_hazard; _ehb; .endm
	.macro tlbw_use_hazard; _ehb; .endm
	.macro tlb_probe_hazard; _ehb; .endm
	.macro irq_enable_hazard; _ehb; .endm
	.macro irq_disable_hazard; _ehb; .endm
	.macro back_to_back_c0_hazard; _ehb; .endm
	.macro enable_fpu_hazard; _ehb; .endm
	.macro disable_fpu_hazard; _ehb; .endm
		.macro	raw_local_irq_enable				
	.set	push						
	.set	reorder						
	.set	noat						
	ei							
	irq_enable_hazard					
	.set	pop						
	.endm
		.macro	raw_local_irq_disable
	.set	push						
	.set	noat						
	di							
	irq_disable_hazard					
	.set	pop						
	.endm							

		.macro	raw_local_save_flags flags			
	.set	push						
	.set	reorder						
	mfc0	\flags, $12					
	.set	pop						
	.endm							

		.macro	raw_local_irq_save result			
	.set	push						
	.set	reorder						
	.set	noat						
	di	\result					
	andi	\result, 1					
	irq_disable_hazard					
	.set	pop						
	.endm							

		.macro	raw_local_irq_restore flags			
	.set	push						
	.set	noreorder					
	.set	noat						
	beqz	\flags, 1f					
	 di							
	ei							
1:								
	irq_disable_hazard					
	.set	pop						
	.endm							

#NO_APP
	.section	__ksymtab,"a",@progbits
	.align	2
	.type	__ksymtab_procRegDir, @object
	.size	__ksymtab_procRegDir, 8
__ksymtab_procRegDir:
	.word	procRegDir
	.word	__kstrtab_procRegDir
	.section	__ksymtab_strings,"a",@progbits
	.type	__kstrtab_procRegDir, @object
	.size	__kstrtab_procRegDir, 11
__kstrtab_procRegDir:
	.ascii	"procRegDir\000"
	.globl	lan_ipaddr
	.data
	.align	2
	.type	lan_ipaddr, @object
	.size	lan_ipaddr, 16
lan_ipaddr:
	.ascii	"192.168.0.1\000"
	.space	4
	.globl	proc_rx_debug_type
	.align	1
	.type	proc_rx_debug_type, @object
	.size	proc_rx_debug_type, 2
proc_rx_debug_type:
	.half	-31011
	.globl	proc_tx_debug_type
	.align	1
	.type	proc_tx_debug_type, @object
	.size	proc_tx_debug_type, 2
proc_tx_debug_type:
	.half	-31011
	.globl	proc_rx_debug
	.section	.bss
	.align	2
	.type	proc_rx_debug, @object
	.size	proc_rx_debug, 4
proc_rx_debug:
	.space	4
	.globl	proc_tx_debug
	.align	2
	.type	proc_tx_debug, @object
	.size	proc_tx_debug, 4
proc_tx_debug:
	.space	4
	.section	.text.ra2880stop,"ax",@progbits
	.align	2
	.globl	ra2880stop
	.ent	ra2880stop
	.type	ra2880stop, @function
ra2880stop:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$2,$2,0xa04
	lw	$3,0($2)
	li	$4,-70			# 0xffffffffffffffba
	and	$3,$3,$4
	sw	$3,0($2)
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	ra2880stop
	.section	.text.ei_irq_clear,"ax",@progbits
	.align	2
	.globl	ei_irq_clear
	.ent	ei_irq_clear
	.type	ei_irq_clear, @function
ei_irq_clear:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$2,-1341128704			# 0xffffffffb0100000
	li	$3,-1			# 0xffffffffffffffff
	ori	$2,$2,0xa20
	sw	$3,0($2)
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	ei_irq_clear
	.section	.text.rt2880_gmac_hard_reset,"ax",@progbits
	.align	2
	.globl	rt2880_gmac_hard_reset
	.ent	rt2880_gmac_hard_reset
	.type	rt2880_gmac_hard_reset, @function
rt2880_gmac_hard_reset:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$2,-1342177280			# 0xffffffffb0000000
	ori	$2,$2,0x34
	li	$3,2097152			# 0x200000
	sw	$3,0($2)
	sw	$0,0($2)
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	rt2880_gmac_hard_reset
	.section	.text.ra2880EnableInterrupt,"ax",@progbits
	.align	2
	.globl	ra2880EnableInterrupt
	.ent	ra2880EnableInterrupt
	.type	ra2880EnableInterrupt, @function
ra2880EnableInterrupt:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$2,$2,0xa28
	lw	$3,0($2)
	sw	$3,0($2)
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	ra2880EnableInterrupt
	.section	.text.ra2880MacAddressSet,"ax",@progbits
	.align	2
	.globl	ra2880MacAddressSet
	.ent	ra2880MacAddressSet
	.type	ra2880MacAddressSet, @function
ra2880MacAddressSet:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lbu	$2,0($4)
	lbu	$3,1($4)
	li	$6,-1341063168			# 0xffffffffb0110000
	sll	$2,$2,8
	or	$3,$2,$3
	ori	$8,$6,0x3fe8
	sw	$3,0($8)
	lbu	$2,2($4)
	lbu	$3,3($4)
	lbu	$5,4($4)
	lbu	$7,5($4)
	sll	$3,$3,16
	sll	$2,$2,24
	or	$2,$2,$3
	sll	$5,$5,8
	or	$2,$2,$5
	or	$3,$2,$7
	ori	$6,$6,0x3fe4
	lw	$2,0($8)
	sw	$3,0($6)
	lw	$2,0($6)
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	ra2880MacAddressSet
	.section	.text.ethtool_init,"ax",@progbits
	.align	2
	.globl	ethtool_init
	.ent	ethtool_init
	.type	ethtool_init, @function
ethtool_init:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	ethtool_init
	.section	.text.dump_reg,"ax",@progbits
	.align	2
	.globl	dump_reg
	.ent	dump_reg
	.type	dump_reg, @function
dump_reg:
	.frame	$sp,24,$31		# vars= 0, regs= 6/0, args= 0, gp= 0
	.mask	0x003f0000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$2,-1341128704			# 0xffffffffb0100000
	addiu	$sp,$sp,-24
	sw	$19,12($sp)
	sw	$18,8($sp)
	sw	$17,4($sp)
	sw	$16,0($sp)
	sw	$21,20($sp)
	sw	$20,16($sp)
	ori	$19,$2,0x90c
	ori	$3,$2,0xa28
	ori	$4,$2,0xa0c
	ori	$16,$2,0x83c
	ori	$17,$2,0x900
	ori	$18,$2,0x904
	ori	$5,$2,0x800
	ori	$6,$2,0x808
	ori	$7,$2,0x80c
	ori	$8,$2,0x810
	ori	$9,$2,0x818
	ori	$10,$2,0x81c
	ori	$11,$2,0x820
	ori	$12,$2,0x828
	ori	$13,$2,0x82c
	ori	$14,$2,0x830
	ori	$15,$2,0x838
	ori	$2,$2,0x908
	lw	$20,0($3)
	lw	$21,0($4)
	lw	$20,16($sp)
	lw	$3,0($5)
	lw	$21,20($sp)
	lw	$4,0($6)
	lw	$3,0($7)
	lw	$4,0($8)
	lw	$3,0($9)
	lw	$4,0($10)
	lw	$3,0($11)
	lw	$4,0($12)
	lw	$3,0($13)
	lw	$4,0($14)
	lw	$3,0($15)
	lw	$4,0($16)
	lw	$3,0($17)
	lw	$16,0($sp)
	lw	$4,0($18)
	lw	$17,4($sp)
	lw	$3,0($2)
	lw	$18,8($sp)
	lw	$4,0($19)
	lw	$19,12($sp)
	j	$31
	addiu	$sp,$sp,24

	.set	macro
	.set	reorder
	.end	dump_reg
	.section	.text.dump_cp0,"ax",@progbits
	.align	2
	.globl	dump_cp0
	.ent	dump_cp0
	.type	dump_cp0, @function
dump_cp0:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
#APP
	.set	push
	.set	reorder
	mfc0	$2,$0
	.set	pop
	.set	push
	.set	reorder
	mfc0	$3,$1
	.set	pop
	.set	push
	.set	reorder
	mfc0	$2,$2
	.set	pop
	.set	push
	.set	reorder
	mfc0	$3,$3
	.set	pop
	.set	push
	.set	reorder
	mfc0	$2,$3
	.set	pop
	.set	push
	.set	reorder
	mfc0	$3,$4
	.set	pop
	.set	push
	.set	reorder
	mfc0	$2,$5
	.set	pop
	.set	push
	.set	reorder
	mfc0	$3,$6
	.set	pop
	.set	push
	.set	reorder
	mfc0	$2,$7
	.set	pop
	.set	push
	.set	reorder
	mfc0	$3,$8
	.set	pop
	.set	push
	.set	reorder
	mfc0	$2,$9
	.set	pop
	.set	push
	.set	reorder
	mfc0	$3,$10
	.set	pop
	.set	push
	.set	reorder
	mfc0	$2,$11
	.set	pop
	.set	push
	.set	reorder
	mfc0	$3,$12
	.set	pop
	.set	push
	.set	reorder
	mfc0	$2,$13
	.set	pop
	.set	push
	.set	reorder
	mfc0	$3,$14
	.set	pop
	.set	push
	.set	reorder
	mfc0	$2,$15
	.set	pop
	.set	push
	.set	reorder
	mfc0	$3,$16
	.set	pop
	.set	push
	.set	reorder
	mfc0	$2,$17
	.set	pop
	.set	push
	.set	reorder
	mfc0	$3,$18
	.set	pop
	.set	push
	.set	reorder
	mfc0	$2,$19
	.set	pop
	.set	push
	.set	reorder
	mfc0	$3,$20
	.set	pop
	.set	push
	.set	reorder
	mfc0	$2,$21
	.set	pop
	.set	push
	.set	reorder
	mfc0	$3,$22
	.set	pop
	.set	push
	.set	reorder
	mfc0	$2,$23
	.set	pop
	.set	push
	.set	reorder
	mfc0	$3,$24
	.set	pop
	.set	push
	.set	reorder
	mfc0	$2,$25
	.set	pop
	.set	push
	.set	reorder
	mfc0	$3,$26
	.set	pop
	.set	push
	.set	reorder
	mfc0	$2,$27
	.set	pop
	.set	push
	.set	reorder
	mfc0	$3,$28
	.set	pop
	.set	push
	.set	reorder
	mfc0	$2,$29
	.set	pop
	.set	push
	.set	reorder
	mfc0	$3,$30
	.set	pop
	.set	push
	.set	reorder
	mfc0	$2,$31
	.set	pop
#NO_APP
	j	$31
	.end	dump_cp0
	.section	.text.RegReadMain,"ax",@progbits
	.align	2
	.globl	RegReadMain
	.ent	RegReadMain
	.type	RegReadMain, @function
RegReadMain:
	.frame	$sp,24,$31		# vars= 0, regs= 1/0, args= 16, gp= 0
	.mask	0x80000000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-24
	sw	$31,16($sp)
	jal	dump_reg
	nop

	lw	$31,16($sp)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,24

	.set	macro
	.set	reorder
	.end	RegReadMain
	.section	.text.SkbFreeRead,"ax",@progbits
	.align	2
	.globl	SkbFreeRead
	.ent	SkbFreeRead
	.type	SkbFreeRead, @function
SkbFreeRead:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$2,255			# 0xff
	addiu	$2,$2,-1
$L76:
	bgez	$2,$L76
	addiu	$2,$2,-1

	addiu	$2,$2,1
	j	$31
	move	$2,$0

	.set	macro
	.set	reorder
	.end	SkbFreeRead
	.section	.text.TxRingRead,"ax",@progbits
	.align	2
	.globl	TxRingRead
	.ent	TxRingRead
	.type	TxRingRead, @function
TxRingRead:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$2,255			# 0xff
	addiu	$2,$2,-1
$L86:
	bgez	$2,$L86
	addiu	$2,$2,-1

	addiu	$2,$2,1
	j	$31
	move	$2,$0

	.set	macro
	.set	reorder
	.end	TxRingRead
	.section	.text.RxRingRead,"ax",@progbits
	.align	2
	.globl	RxRingRead
	.ent	RxRingRead
	.type	RxRingRead, @function
RxRingRead:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$2,255			# 0xff
	addiu	$2,$2,-1
$L96:
	bgez	$2,$L96
	addiu	$2,$2,-1

	addiu	$2,$2,1
	j	$31
	move	$2,$0

	.set	macro
	.set	reorder
	.end	RxRingRead
	.section	.text.CP0RegRead,"ax",@progbits
	.align	2
	.globl	CP0RegRead
	.ent	CP0RegRead
	.type	CP0RegRead, @function
CP0RegRead:
	.frame	$sp,24,$31		# vars= 0, regs= 1/0, args= 16, gp= 0
	.mask	0x80000000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-24
	sw	$31,16($sp)
	jal	dump_cp0
	nop

	lw	$31,16($sp)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,24

	.set	macro
	.set	reorder
	.end	CP0RegRead
	.section	.text.EswCntRead,"ax",@progbits
	.align	2
	.globl	EswCntRead
	.ent	EswCntRead
	.type	EswCntRead, @function
EswCntRead:
	.frame	$sp,40,$31		# vars= 0, regs= 9/0, args= 0, gp= 0
	.mask	0x40ff0000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-40
	li	$2,-1341128704			# 0xffffffffb0100000
	sw	$fp,32($sp)
	sw	$23,28($sp)
	sw	$22,24($sp)
	sw	$21,20($sp)
	sw	$20,16($sp)
	sw	$19,12($sp)
	sw	$18,8($sp)
	sw	$17,4($sp)
	sw	$16,0($sp)
	ori	$5,$2,0x1324
	ori	$16,$2,0x1348
	ori	$17,$2,0x134c
	ori	$18,$2,0x1368
	ori	$19,$2,0x136c
	ori	$20,$2,0x1370
	ori	$21,$2,0x1374
	ori	$4,$2,0x1304
	ori	$6,$2,0x1308
	ori	$7,$2,0x130c
	ori	$8,$2,0x1328
	ori	$9,$2,0x132c
	ori	$10,$2,0x1330
	ori	$11,$2,0x1334
	ori	$12,$2,0x1338
	ori	$13,$2,0x133c
	ori	$14,$2,0x1344
	ori	$15,$2,0x1364
	ori	$2,$2,0x1378
	lw	$4,0($4)
	li	$3,-1341063168			# 0xffffffffb0110000
	lw	$4,0($5)
	lw	$4,0($6)
	lw	$5,0($7)
	lw	$4,0($8)
	lw	$5,0($9)
	lw	$4,0($10)
	lw	$5,0($11)
	lw	$4,0($12)
	lw	$5,0($13)
	lw	$4,0($14)
	lw	$5,0($15)
	lw	$4,0($16)
	lw	$5,0($17)
	lw	$4,0($18)
	lw	$5,0($19)
	lw	$4,0($20)
	lw	$5,0($21)
	lw	$4,0($2)
	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$22,$3,0x4620
	ori	$23,$3,0x4610
	ori	$fp,$3,0x4020
	ori	$24,$3,0x4720
	ori	$25,$3,0x4710
	ori	$2,$2,0x137c
	lw	$5,0($2)
	lw	$2,0($22)
	lw	$4,0($22)
	lw	$2,0($23)
	lw	$4,0($23)
	lw	$2,0($24)
	lw	$4,0($24)
	lw	$2,0($25)
	lw	$4,0($25)
	lw	$2,0($fp)
	li	$2,-1341063168			# 0xffffffffb0110000
	ori	$2,$2,0x4010
	lw	$4,0($2)
	lw	$2,0($fp)
	li	$2,-1341063168			# 0xffffffffb0110000
	ori	$2,$2,0x4010
	lw	$4,0($2)
	li	$4,-1341063168			# 0xffffffffb0110000
	ori	$4,$4,0x4120
	lw	$2,0($4)
	li	$2,-1341063168			# 0xffffffffb0110000
	ori	$2,$2,0x4110
	lw	$4,0($2)
	li	$4,-1341063168			# 0xffffffffb0110000
	ori	$4,$4,0x4120
	lw	$2,0($4)
	li	$2,-1341063168			# 0xffffffffb0110000
	ori	$2,$2,0x4110
	lw	$4,0($2)
	li	$4,-1341063168			# 0xffffffffb0110000
	ori	$4,$4,0x4220
	lw	$2,0($4)
	li	$2,-1341063168			# 0xffffffffb0110000
	ori	$2,$2,0x4210
	lw	$4,0($2)
	li	$4,-1341063168			# 0xffffffffb0110000
	ori	$4,$4,0x4220
	lw	$2,0($4)
	li	$2,-1341063168			# 0xffffffffb0110000
	ori	$2,$2,0x4210
	lw	$4,0($2)
	li	$4,-1341063168			# 0xffffffffb0110000
	ori	$4,$4,0x4320
	lw	$2,0($4)
	li	$2,-1341063168			# 0xffffffffb0110000
	ori	$2,$2,0x4310
	lw	$4,0($2)
	li	$4,-1341063168			# 0xffffffffb0110000
	ori	$4,$4,0x4320
	lw	$2,0($4)
	li	$2,-1341063168			# 0xffffffffb0110000
	ori	$2,$2,0x4310
	lw	$4,0($2)
	li	$4,-1341063168			# 0xffffffffb0110000
	ori	$4,$4,0x4420
	lw	$2,0($4)
	li	$2,-1341063168			# 0xffffffffb0110000
	ori	$2,$2,0x4410
	lw	$4,0($2)
	li	$4,-1341063168			# 0xffffffffb0110000
	ori	$4,$4,0x4420
	lw	$2,0($4)
	li	$2,-1341063168			# 0xffffffffb0110000
	ori	$3,$3,0x4520
	ori	$2,$2,0x4410
	lw	$4,0($2)
	lw	$2,0($3)
	li	$2,-1341063168			# 0xffffffffb0110000
	ori	$2,$2,0x4510
	lw	$4,0($2)
	lw	$2,0($3)
	li	$2,-1341063168			# 0xffffffffb0110000
	ori	$2,$2,0x4510
	lw	$4,0($2)
	lw	$fp,32($sp)
	lw	$23,28($sp)
	lw	$22,24($sp)
	lw	$21,20($sp)
	lw	$20,16($sp)
	lw	$19,12($sp)
	lw	$18,8($sp)
	lw	$17,4($sp)
	lw	$16,0($sp)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,40

	.set	macro
	.set	reorder
	.end	EswCntRead
	.section	.rodata.str1.4,"aMS",@progbits,1
	.align	2
$LC106:
	.ascii	"TX_DEBUG=%d\n\000"
	.section	.text.TxDebugRead,"ax",@progbits
	.align	2
	.ent	TxDebugRead
	.type	TxDebugRead, @function
TxDebugRead:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lui	$5,%hi($LC106)
	addiu	$5,$5,%lo($LC106)
	blez	$6,$L156
	lw	$3,16($sp)

	li	$2,1			# 0x1
	sw	$2,0($3)
	j	$31
	move	$2,$0

$L156:
	lui	$2,%hi(proc_tx_debug)
	j	sprintf
	lw	$6,%lo(proc_tx_debug)($2)

	.set	macro
	.set	reorder
	.end	TxDebugRead
	.section	.text.TxDebugWrite,"ax",@progbits
	.align	2
	.ent	TxDebugWrite
	.type	TxDebugWrite, @function
TxDebugWrite:
	.frame	$sp,16,$31		# vars= 8, regs= 1/0, args= 0, gp= 0
	.mask	0x80000000,-8
	.fmask	0x00000000,0
	addiu	$sp,$sp,-16
	sltu	$2,$6,2
	sw	$31,8($sp)
	move	$13,$6
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L157
	li	$4,-14			# 0xfffffffffffffff2
	.set	macro
	.set	reorder

	addiu	$2,$5,1
	.set	noreorder
	.set	nomacro
	beq	$5,$0,$L159
	or	$7,$2,$5
	.set	macro
	.set	reorder

	lw	$2,24($28)
	move	$4,$sp
	and	$2,$7,$2
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L159
	li	$6,1			# 0x1
	.set	macro
	.set	reorder

#APP
	.set	noreorder
	jal	__copy_user
	.set	noat
	addu	$1, $5, $6
	.set	at
	.set	reorder
#NO_APP
	.set	noreorder
	.set	nomacro
	bne	$6,$0,$L170
	lw	$31,8($sp)
	.set	macro
	.set	reorder

	lb	$3,0($sp)
	li	$2,49			# 0x31
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L169
	lui	$2,%hi(proc_tx_debug)
	.set	macro
	.set	reorder

	sw	$0,%lo(proc_tx_debug)($2)
	move	$4,$13
$L157:
	lw	$31,8($sp)
	move	$2,$4
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,16
	.set	macro
	.set	reorder

$L159:
	lw	$31,8($sp)
$L170:
	li	$4,-14			# 0xfffffffffffffff2
	move	$2,$4
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,16
	.set	macro
	.set	reorder

$L169:
	li	$3,1			# 0x1
	move	$4,$13
	.set	noreorder
	.set	nomacro
	j	$L157
	sw	$3,%lo(proc_tx_debug)($2)
	.set	macro
	.set	reorder

	.end	TxDebugWrite
	.section	.rodata.str1.4
	.align	2
$LC107:
	.ascii	"TX_DEBUG_TYPE=0x%x\n\000"
	.section	.text.TxDebugTypeRead,"ax",@progbits
	.align	2
	.ent	TxDebugTypeRead
	.type	TxDebugTypeRead, @function
TxDebugTypeRead:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lui	$5,%hi($LC107)
	addiu	$5,$5,%lo($LC107)
	blez	$6,$L174
	lw	$3,16($sp)

	li	$2,1			# 0x1
	sw	$2,0($3)
	j	$31
	move	$2,$0

$L174:
	lui	$2,%hi(proc_tx_debug_type)
	j	sprintf
	lhu	$6,%lo(proc_tx_debug_type)($2)

	.set	macro
	.set	reorder
	.end	TxDebugTypeRead
	.section	.rodata.str1.4
	.align	2
$LC108:
	.ascii	"%x\000"
	.section	.text.TxDebugTypeWrite,"ax",@progbits
	.align	2
	.ent	TxDebugTypeWrite
	.type	TxDebugTypeWrite, @function
TxDebugTypeWrite:
	.frame	$sp,40,$31		# vars= 16, regs= 2/0, args= 16, gp= 0
	.mask	0x80010000,-4
	.fmask	0x00000000,0
	addiu	$sp,$sp,-40
	sltu	$2,$6,2
	sw	$16,32($sp)
	sw	$31,36($sp)
	move	$16,$6
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L175
	li	$4,-14			# 0xfffffffffffffff2
	.set	macro
	.set	reorder

	addu	$2,$5,$6
	or	$2,$2,$5
	.set	noreorder
	.set	nomacro
	beq	$5,$0,$L175
	or	$7,$2,$6
	.set	macro
	.set	reorder

	lw	$2,24($28)
	addiu	$13,$sp,16
	move	$3,$6
	and	$2,$7,$2
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L178
	move	$4,$13
	.set	macro
	.set	reorder

#APP
	.set	noreorder
	jal	__copy_user
	.set	noat
	addu	$1, $5, $6
	.set	at
	.set	reorder
#NO_APP
	move	$3,$6
$L178:
	lui	$5,%hi($LC108)
	lui	$6,%hi(proc_tx_debug_type)
	move	$4,$13
	addiu	$5,$5,%lo($LC108)
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L185
	addiu	$6,$6,%lo(proc_tx_debug_type)
	.set	macro
	.set	reorder

	li	$4,-14			# 0xfffffffffffffff2
$L175:
	lw	$31,36($sp)
	lw	$16,32($sp)
	move	$2,$4
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,40
	.set	macro
	.set	reorder

$L185:
	jal	sscanf
	move	$4,$16
	lw	$31,36($sp)
	lw	$16,32($sp)
	move	$2,$4
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,40
	.set	macro
	.set	reorder

	.end	TxDebugTypeWrite
	.section	.rodata.str1.4
	.align	2
$LC109:
	.ascii	"RX_DEBUG=%d\n\000"
	.section	.text.RxDebugRead,"ax",@progbits
	.align	2
	.ent	RxDebugRead
	.type	RxDebugRead, @function
RxDebugRead:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lui	$5,%hi($LC109)
	addiu	$5,$5,%lo($LC109)
	blez	$6,$L189
	lw	$3,16($sp)

	li	$2,1			# 0x1
	sw	$2,0($3)
	j	$31
	move	$2,$0

$L189:
	lui	$2,%hi(proc_rx_debug)
	j	sprintf
	lw	$6,%lo(proc_rx_debug)($2)

	.set	macro
	.set	reorder
	.end	RxDebugRead
	.section	.text.RxDebugWrite,"ax",@progbits
	.align	2
	.ent	RxDebugWrite
	.type	RxDebugWrite, @function
RxDebugWrite:
	.frame	$sp,16,$31		# vars= 8, regs= 1/0, args= 0, gp= 0
	.mask	0x80000000,-8
	.fmask	0x00000000,0
	addiu	$sp,$sp,-16
	sltu	$2,$6,2
	sw	$31,8($sp)
	move	$13,$6
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L190
	li	$4,-14			# 0xfffffffffffffff2
	.set	macro
	.set	reorder

	addiu	$2,$5,1
	.set	noreorder
	.set	nomacro
	beq	$5,$0,$L192
	or	$7,$2,$5
	.set	macro
	.set	reorder

	lw	$2,24($28)
	move	$4,$sp
	and	$2,$7,$2
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L192
	li	$6,1			# 0x1
	.set	macro
	.set	reorder

#APP
	.set	noreorder
	jal	__copy_user
	.set	noat
	addu	$1, $5, $6
	.set	at
	.set	reorder
#NO_APP
	.set	noreorder
	.set	nomacro
	bne	$6,$0,$L203
	lw	$31,8($sp)
	.set	macro
	.set	reorder

	lb	$3,0($sp)
	li	$2,49			# 0x31
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L202
	lui	$2,%hi(proc_rx_debug)
	.set	macro
	.set	reorder

	sw	$0,%lo(proc_rx_debug)($2)
	move	$4,$13
$L190:
	lw	$31,8($sp)
	move	$2,$4
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,16
	.set	macro
	.set	reorder

$L192:
	lw	$31,8($sp)
$L203:
	li	$4,-14			# 0xfffffffffffffff2
	move	$2,$4
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,16
	.set	macro
	.set	reorder

$L202:
	li	$3,1			# 0x1
	move	$4,$13
	.set	noreorder
	.set	nomacro
	j	$L190
	sw	$3,%lo(proc_rx_debug)($2)
	.set	macro
	.set	reorder

	.end	RxDebugWrite
	.section	.rodata.str1.4
	.align	2
$LC110:
	.ascii	"RX_DEBUG_TYPE=0x%x\n\000"
	.section	.text.RxDebugTypeRead,"ax",@progbits
	.align	2
	.ent	RxDebugTypeRead
	.type	RxDebugTypeRead, @function
RxDebugTypeRead:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lui	$5,%hi($LC110)
	addiu	$5,$5,%lo($LC110)
	blez	$6,$L207
	lw	$3,16($sp)

	li	$2,1			# 0x1
	sw	$2,0($3)
	j	$31
	move	$2,$0

$L207:
	lui	$2,%hi(proc_rx_debug_type)
	j	sprintf
	lhu	$6,%lo(proc_rx_debug_type)($2)

	.set	macro
	.set	reorder
	.end	RxDebugTypeRead
	.section	.text.RxDebugTypeWrite,"ax",@progbits
	.align	2
	.ent	RxDebugTypeWrite
	.type	RxDebugTypeWrite, @function
RxDebugTypeWrite:
	.frame	$sp,40,$31		# vars= 16, regs= 2/0, args= 16, gp= 0
	.mask	0x80010000,-4
	.fmask	0x00000000,0
	addiu	$sp,$sp,-40
	sltu	$2,$6,2
	sw	$16,32($sp)
	sw	$31,36($sp)
	move	$16,$6
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L208
	li	$4,-14			# 0xfffffffffffffff2
	.set	macro
	.set	reorder

	addu	$2,$5,$6
	or	$2,$2,$5
	.set	noreorder
	.set	nomacro
	beq	$5,$0,$L208
	or	$7,$2,$6
	.set	macro
	.set	reorder

	lw	$2,24($28)
	addiu	$13,$sp,16
	move	$3,$6
	and	$2,$7,$2
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L211
	move	$4,$13
	.set	macro
	.set	reorder

#APP
	.set	noreorder
	jal	__copy_user
	.set	noat
	addu	$1, $5, $6
	.set	at
	.set	reorder
#NO_APP
	move	$3,$6
$L211:
	lui	$5,%hi($LC108)
	lui	$6,%hi(proc_rx_debug_type)
	move	$4,$13
	addiu	$5,$5,%lo($LC108)
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L218
	addiu	$6,$6,%lo(proc_rx_debug_type)
	.set	macro
	.set	reorder

	li	$4,-14			# 0xfffffffffffffff2
$L208:
	lw	$31,36($sp)
	lw	$16,32($sp)
	move	$2,$4
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,40
	.set	macro
	.set	reorder

$L218:
	jal	sscanf
	move	$4,$16
	lw	$31,36($sp)
	lw	$16,32($sp)
	move	$2,$4
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,40
	.set	macro
	.set	reorder

	.end	RxDebugTypeWrite
	.section	.rodata.str1.4
	.align	2
$LC111:
	.ascii	"%d/%d/%d/%d\n\000"
	.section	.text.readESW_RXTX,"ax",@progbits
	.align	2
	.ent	readESW_RXTX
	.type	readESW_RXTX, @function
readESW_RXTX:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$2,-1341063168			# 0xffffffffb0110000
	ori	$8,$2,0x4610
	ori	$3,$2,0x4420
	ori	$5,$2,0x4410
	ori	$2,$2,0x4620
	lw	$9,0($3)
	lw	$10,0($5)
	lw	$3,0($2)
	lw	$7,0($8)
	lui	$5,%hi($LC111)
	addiu	$5,$5,%lo($LC111)
	subu	$3,$3,$9
	subu	$7,$7,$10
	blez	$6,$L222
	lw	$8,16($sp)

	li	$2,1			# 0x1
	sw	$2,0($8)
	j	$31
	move	$2,$0

$L222:
	move	$6,$3
	sw	$9,16($sp)
	j	sprintf
	sw	$10,20($sp)

	.set	macro
	.set	reorder
	.end	readESW_RXTX
	.section	.rodata.str1.4
	.align	2
$LC112:
	.ascii	"%s\000"
	.section	.text.setLanIp,"ax",@progbits
	.align	2
	.ent	setLanIp
	.type	setLanIp, @function
setLanIp:
	.frame	$sp,40,$31		# vars= 16, regs= 2/0, args= 16, gp= 0
	.mask	0x80010000,-4
	.fmask	0x00000000,0
	addiu	$sp,$sp,-40
	sltu	$2,$6,2
	sw	$16,32($sp)
	sw	$31,36($sp)
	move	$16,$6
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L223
	li	$4,-14			# 0xfffffffffffffff2
	.set	macro
	.set	reorder

	addu	$2,$5,$6
	or	$2,$2,$5
	.set	noreorder
	.set	nomacro
	beq	$5,$0,$L223
	or	$7,$2,$6
	.set	macro
	.set	reorder

	lw	$2,24($28)
	addiu	$13,$sp,16
	move	$3,$6
	and	$2,$7,$2
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L226
	move	$4,$13
	.set	macro
	.set	reorder

#APP
	.set	noreorder
	jal	__copy_user
	.set	noat
	addu	$1, $5, $6
	.set	at
	.set	reorder
#NO_APP
	move	$3,$6
$L226:
	lui	$5,%hi($LC112)
	lui	$6,%hi(lan_ipaddr)
	move	$4,$13
	addiu	$5,$5,%lo($LC112)
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L233
	addiu	$6,$6,%lo(lan_ipaddr)
	.set	macro
	.set	reorder

	li	$4,-14			# 0xfffffffffffffff2
$L223:
	lw	$31,36($sp)
	lw	$16,32($sp)
	move	$2,$4
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,40
	.set	macro
	.set	reorder

$L233:
	jal	sscanf
	move	$4,$16
	lw	$31,36($sp)
	lw	$16,32($sp)
	move	$2,$4
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,40
	.set	macro
	.set	reorder

	.end	setLanIp
	.section	.rodata.str1.4
	.align	2
$LC114:
	.ascii	"gmac\000"
	.align	2
$LC115:
	.ascii	"skb_free\000"
	.align	2
$LC116:
	.ascii	"tx_ring\000"
	.align	2
$LC117:
	.ascii	"rx_ring\000"
	.align	2
$LC118:
	.ascii	"cp0\000"
	.align	2
$LC119:
	.ascii	"esw_cnt\000"
	.align	2
$LC120:
	.ascii	"tx_debug_enable\000"
	.align	2
$LC121:
	.ascii	"tx_debug_type\000"
	.align	2
$LC122:
	.ascii	"rx_debug_enable\000"
	.align	2
$LC123:
	.ascii	"rx_debug_type\000"
	.align	2
$LC124:
	.ascii	"rxtx\000"
	.align	2
$LC125:
	.ascii	"lanip\000"
	.align	2
$LC113:
	.ascii	"mt7620\000"
	.section	.text.debug_proc_init,"ax",@progbits
	.align	2
	.globl	debug_proc_init
	.ent	debug_proc_init
	.type	debug_proc_init, @function
debug_proc_init:
	.frame	$sp,24,$31		# vars= 0, regs= 2/0, args= 16, gp= 0
	.mask	0x80010000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-24
	sw	$16,16($sp)
	lui	$16,%hi(procRegDir)
	lw	$2,%lo(procRegDir)($16)
	beq	$2,$0,$L249
	sw	$31,20($sp)

$L235:
	lui	$4,%hi($LC114)
	addiu	$4,$4,%lo($LC114)
	move	$6,$2
	jal	create_proc_entry
	move	$5,$0

	move	$3,$2
	lui	$2,%hi(procGmac)
	beq	$3,$0,$L236
	sw	$3,%lo(procGmac)($2)

	lui	$2,%hi(RegReadMain)
	addiu	$2,$2,%lo(RegReadMain)
	sw	$2,64($3)
$L236:
	lw	$6,%lo(procRegDir)($16)
	lui	$4,%hi($LC115)
	addiu	$4,$4,%lo($LC115)
	jal	create_proc_entry
	move	$5,$0

	move	$3,$2
	lui	$2,%hi(procSkbFree)
	beq	$3,$0,$L237
	sw	$3,%lo(procSkbFree)($2)

	lui	$2,%hi(SkbFreeRead)
	addiu	$2,$2,%lo(SkbFreeRead)
	sw	$2,64($3)
$L237:
	lw	$6,%lo(procRegDir)($16)
	lui	$4,%hi($LC116)
	addiu	$4,$4,%lo($LC116)
	jal	create_proc_entry
	move	$5,$0

	move	$3,$2
	lui	$2,%hi(procTxRing)
	beq	$3,$0,$L238
	sw	$3,%lo(procTxRing)($2)

	lui	$2,%hi(TxRingRead)
	addiu	$2,$2,%lo(TxRingRead)
	sw	$2,64($3)
$L238:
	lw	$6,%lo(procRegDir)($16)
	lui	$4,%hi($LC117)
	addiu	$4,$4,%lo($LC117)
	jal	create_proc_entry
	move	$5,$0

	move	$3,$2
	lui	$2,%hi(procRxRing)
	beq	$3,$0,$L239
	sw	$3,%lo(procRxRing)($2)

	lui	$2,%hi(RxRingRead)
	addiu	$2,$2,%lo(RxRingRead)
	sw	$2,64($3)
$L239:
	lw	$6,%lo(procRegDir)($16)
	lui	$4,%hi($LC118)
	addiu	$4,$4,%lo($LC118)
	jal	create_proc_entry
	move	$5,$0

	move	$3,$2
	lui	$2,%hi(procSysCP0)
	beq	$3,$0,$L240
	sw	$3,%lo(procSysCP0)($2)

	lui	$2,%hi(CP0RegRead)
	addiu	$2,$2,%lo(CP0RegRead)
	sw	$2,64($3)
$L240:
	lw	$6,%lo(procRegDir)($16)
	lui	$4,%hi($LC119)
	addiu	$4,$4,%lo($LC119)
	jal	create_proc_entry
	move	$5,$0

	move	$3,$2
	lui	$2,%hi(procEswCnt)
	beq	$3,$0,$L241
	sw	$3,%lo(procEswCnt)($2)

	lui	$2,%hi(EswCntRead)
	addiu	$2,$2,%lo(EswCntRead)
	sw	$2,64($3)
$L241:
	lw	$6,%lo(procRegDir)($16)
	lui	$4,%hi($LC120)
	addiu	$4,$4,%lo($LC120)
	jal	create_proc_entry
	move	$5,$0

	lui	$4,%hi(tx_debug_enable)
	move	$3,$2
	beq	$2,$0,$L242
	sw	$2,%lo(tx_debug_enable)($4)

	lui	$2,%hi(TxDebugRead)
	addiu	$2,$2,%lo(TxDebugRead)
	sw	$2,64($3)
	lw	$3,%lo(tx_debug_enable)($4)
	lui	$2,%hi(TxDebugWrite)
	addiu	$2,$2,%lo(TxDebugWrite)
	sw	$2,68($3)
$L242:
	lw	$6,%lo(procRegDir)($16)
	lui	$4,%hi($LC121)
	addiu	$4,$4,%lo($LC121)
	jal	create_proc_entry
	move	$5,$0

	lui	$4,%hi(tx_debug_type)
	move	$3,$2
	beq	$2,$0,$L243
	sw	$2,%lo(tx_debug_type)($4)

	lui	$2,%hi(TxDebugTypeRead)
	addiu	$2,$2,%lo(TxDebugTypeRead)
	sw	$2,64($3)
	lw	$3,%lo(tx_debug_type)($4)
	lui	$2,%hi(TxDebugTypeWrite)
	addiu	$2,$2,%lo(TxDebugTypeWrite)
	sw	$2,68($3)
$L243:
	lw	$6,%lo(procRegDir)($16)
	lui	$4,%hi($LC122)
	addiu	$4,$4,%lo($LC122)
	jal	create_proc_entry
	move	$5,$0

	lui	$4,%hi(rx_debug_enable)
	move	$3,$2
	beq	$2,$0,$L244
	sw	$2,%lo(rx_debug_enable)($4)

	lui	$2,%hi(RxDebugRead)
	addiu	$2,$2,%lo(RxDebugRead)
	sw	$2,64($3)
	lw	$3,%lo(rx_debug_enable)($4)
	lui	$2,%hi(RxDebugWrite)
	addiu	$2,$2,%lo(RxDebugWrite)
	sw	$2,68($3)
$L244:
	lw	$6,%lo(procRegDir)($16)
	lui	$4,%hi($LC123)
	addiu	$4,$4,%lo($LC123)
	jal	create_proc_entry
	move	$5,$0

	lui	$4,%hi(rx_debug_type)
	move	$3,$2
	beq	$2,$0,$L245
	sw	$2,%lo(rx_debug_type)($4)

	lui	$2,%hi(RxDebugTypeRead)
	addiu	$2,$2,%lo(RxDebugTypeRead)
	sw	$2,64($3)
	lw	$3,%lo(rx_debug_type)($4)
	lui	$2,%hi(RxDebugTypeWrite)
	addiu	$2,$2,%lo(RxDebugTypeWrite)
	sw	$2,68($3)
$L245:
	lw	$6,%lo(procRegDir)($16)
	lui	$4,%hi($LC124)
	addiu	$4,$4,%lo($LC124)
	jal	create_proc_entry
	move	$5,$0

	move	$3,$2
	lui	$2,%hi(rxtx)
	beq	$3,$0,$L246
	sw	$3,%lo(rxtx)($2)

	lui	$2,%hi(readESW_RXTX)
	addiu	$2,$2,%lo(readESW_RXTX)
	sw	$2,64($3)
$L246:
	lw	$6,%lo(procRegDir)($16)
	lui	$4,%hi($LC125)
	addiu	$4,$4,%lo($LC125)
	jal	create_proc_entry
	move	$5,$0

	move	$3,$2
	lui	$2,%hi(lanip)
	beq	$3,$0,$L247
	sw	$3,%lo(lanip)($2)

	lui	$2,%hi(setLanIp)
	addiu	$2,$2,%lo(setLanIp)
	sw	$2,68($3)
$L247:
	lw	$31,20($sp)
	lw	$16,16($sp)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,24

$L249:
	lui	$4,%hi($LC113)
	addiu	$4,$4,%lo($LC113)
	jal	proc_mkdir
	move	$5,$0

	j	$L235
	sw	$2,%lo(procRegDir)($16)

	.set	macro
	.set	reorder
	.end	debug_proc_init
	.section	.text.debug_proc_exit,"ax",@progbits
	.align	2
	.globl	debug_proc_exit
	.ent	debug_proc_exit
	.type	debug_proc_exit, @function
debug_proc_exit:
	.frame	$sp,24,$31		# vars= 0, regs= 1/0, args= 16, gp= 0
	.mask	0x80000000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-24
	sw	$31,16($sp)
	lui	$2,%hi(procSysCP0)
	lw	$3,%lo(procSysCP0)($2)
	bne	$3,$0,$L258
	lui	$2,%hi(procRegDir)

	lui	$2,%hi(procGmac)
$L268:
	lw	$3,%lo(procGmac)($2)
	bne	$3,$0,$L259
	lui	$2,%hi(procRegDir)

	lui	$2,%hi(procSkbFree)
$L267:
	lw	$3,%lo(procSkbFree)($2)
	bne	$3,$0,$L260
	lui	$2,%hi(procRegDir)

	lui	$2,%hi(procTxRing)
$L266:
	lw	$3,%lo(procTxRing)($2)
	bne	$3,$0,$L261
	lui	$2,%hi(procRegDir)

	lui	$2,%hi(procRxRing)
$L265:
	lw	$3,%lo(procRxRing)($2)
	bne	$3,$0,$L262
	lui	$2,%hi(procRegDir)

	lui	$2,%hi(procEswCnt)
$L264:
	lw	$3,%lo(procEswCnt)($2)
	bne	$3,$0,$L263
	lw	$31,16($sp)

	j	$31
	addiu	$sp,$sp,24

$L263:
	lui	$2,%hi(procRegDir)
	lw	$5,%lo(procRegDir)($2)
	lui	$4,%hi($LC119)
	jal	remove_proc_entry
	addiu	$4,$4,%lo($LC119)

	lw	$31,16($sp)
	j	$31
	addiu	$sp,$sp,24

$L262:
	lw	$5,%lo(procRegDir)($2)
	lui	$4,%hi($LC117)
	jal	remove_proc_entry
	addiu	$4,$4,%lo($LC117)

	j	$L264
	lui	$2,%hi(procEswCnt)

$L261:
	lw	$5,%lo(procRegDir)($2)
	lui	$4,%hi($LC116)
	jal	remove_proc_entry
	addiu	$4,$4,%lo($LC116)

	j	$L265
	lui	$2,%hi(procRxRing)

$L260:
	lw	$5,%lo(procRegDir)($2)
	lui	$4,%hi($LC115)
	jal	remove_proc_entry
	addiu	$4,$4,%lo($LC115)

	j	$L266
	lui	$2,%hi(procTxRing)

$L259:
	lw	$5,%lo(procRegDir)($2)
	lui	$4,%hi($LC114)
	jal	remove_proc_entry
	addiu	$4,$4,%lo($LC114)

	j	$L267
	lui	$2,%hi(procSkbFree)

$L258:
	lw	$5,%lo(procRegDir)($2)
	lui	$4,%hi($LC118)
	jal	remove_proc_entry
	addiu	$4,$4,%lo($LC118)

	j	$L268
	lui	$2,%hi(procGmac)

	.set	macro
	.set	reorder
	.end	debug_proc_exit
	.globl	procRegDir
	.section	.bss
	.align	2
	.type	procRegDir, @object
	.size	procRegDir, 4
procRegDir:
	.space	4
	.local	procGmac
	.comm	procGmac,4,4
	.local	procSysCP0
	.comm	procSysCP0,4,4
	.local	procTxRing
	.comm	procTxRing,4,4
	.local	procRxRing
	.comm	procRxRing,4,4
	.local	procSkbFree
	.comm	procSkbFree,4,4
	.local	procEswCnt
	.comm	procEswCnt,4,4
	.local	tx_debug_enable
	.comm	tx_debug_enable,4,4
	.local	tx_debug_type
	.comm	tx_debug_type,4,4
	.local	rx_debug_enable
	.comm	rx_debug_enable,4,4
	.local	rx_debug_type
	.comm	rx_debug_type,4,4
	.local	rxtx
	.comm	rxtx,4,4
	.local	lanip
	.comm	lanip,4,4
	.ident	"GCC: (GNU) 3.4.2"
