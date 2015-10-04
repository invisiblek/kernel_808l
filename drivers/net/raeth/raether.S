	.file	1 "raether.c"
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
	.section	.exitcall.exit,"aw",@progbits
	.align	2
	.type	__exitcall_ra2882eth_cleanup_module, @object
	.size	__exitcall_ra2882eth_cleanup_module, 4
__exitcall_ra2882eth_cleanup_module:
	.word	ra2882eth_cleanup_module
	.section	.initcall6.init,"aw",@progbits
	.align	2
	.type	__initcall_ra2882eth_init6, @object
	.size	__initcall_ra2882eth_init6, 4
__initcall_ra2882eth_init6:
	.word	ra2882eth_init
	.globl	clientsocket
	.section	.bss
	.align	2
	.type	clientsocket, @object
	.size	clientsocket, 4
clientsocket:
	.space	4
	.globl	non_check
	.align	2
	.type	non_check, @object
	.size	non_check, 4
non_check:
	.space	4
	.local	tx_cpu_owner_idx0
	.comm	tx_cpu_owner_idx0,4,4
	.local	tx_ring_full
	.comm	tx_ring_full,4,4
	.rdata
	.align	2
	.type	ei_netdev_ops, @object
	.size	ei_netdev_ops, 108
ei_netdev_ops:
	.word	rather_probe
	.space	4
	.word	ei_open
	.word	ei_close
	.word	ei_start_xmit_fake
	.space	16
	.word	eth_mac_addr
	.word	eth_validate_addr
	.word	ei_ioctl
	.space	4
	.word	ei_change_mtu
	.space	12
	.word	ra_get_stats
	.space	36
	.section	.rodata.str1.4,"aMS",@progbits,1
	.align	2
$LC0:
	.ascii	"up\000"
	.align	2
$LC1:
	.ascii	"down\000"
	.section	.text.info_ncc,"ax",@progbits
	.align	2
	.ent	info_ncc
	.type	info_ncc, @function
info_ncc:
	.frame	$sp,136,$31		# vars= 96, regs= 3/0, args= 24, gp= 0
	.mask	0x80030000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-136
	sw	$16,120($sp)
	lui	$16,%hi(wan_port_status)
	lw	$2,%lo(wan_port_status)($16)
	lui	$5,%hi($LC0)
	sw	$17,124($sp)
	sw	$31,128($sp)
	move	$17,$4
	addiu	$5,$5,%lo($LC0)
	addiu	$4,$sp,64
	sw	$0,64($sp)
	sw	$0,68($sp)
	sw	$0,72($sp)
	sw	$0,76($sp)
	sw	$0,80($sp)
	sw	$0,84($sp)
	sw	$0,88($sp)
	bne	$2,$0,$L7
	sw	$0,92($sp)

	lui	$5,%hi($LC1)
	addiu	$5,$5,%lo($LC1)
	addiu	$4,$sp,64
$L7:
	jal	sprintf
	nop

	lw	$3,%lo(wan_port_status)($16)
	li	$2,67502080			# 0x4060000
	addiu	$9,$sp,24
	or	$3,$3,$2
	li	$2,261			# 0x105
	li	$8,16			# 0x10
	sw	$2,96($sp)
	sw	$3,100($sp)
	addiu	$2,$sp,96
	move	$4,$17
	addiu	$5,$sp,32
	li	$3,1			# 0x1
	move	$6,$9
	li	$7,1			# 0x1
	sw	$2,24($sp)
	sw	$3,44($sp)
	sw	$8,16($sp)
	sw	$0,104($sp)
	sw	$0,108($sp)
	sw	$0,112($sp)
	sw	$8,28($sp)
	sw	$9,40($sp)
	sw	$0,32($sp)
	sw	$0,36($sp)
	sw	$0,48($sp)
	sw	$0,52($sp)
	jal	kernel_sendmsg
	sw	$0,56($sp)

	lw	$31,128($sp)
	lw	$17,124($sp)
	lw	$16,120($sp)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,136

	.set	macro
	.set	reorder
	.end	info_ncc
	.section	.text.wan_detect_timer,"ax",@progbits
	.align	2
	.ent	wan_detect_timer
	.type	wan_detect_timer, @function
wan_detect_timer:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$2,-1341063168			# 0xffffffffb0110000
	addiu	$2,$2,1024
	lw	$3,12296($2)
	lui	$5,%hi(wan_port_status)
	lw	$2,%lo(wan_port_status)($5)
	andi	$3,$3,0x1
	beq	$2,$3,$L13
	lui	$2,%hi(clientsocket)

	lw	$4,%lo(clientsocket)($2)
	j	info_ncc
	sw	$3,%lo(wan_port_status)($5)

$L13:
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	wan_detect_timer
	.section	.text.send_info_to_ncc,"ax",@progbits
	.align	2
	.globl	send_info_to_ncc
	.ent	send_info_to_ncc
	.type	send_info_to_ncc, @function
send_info_to_ncc:
	.frame	$sp,32,$31		# vars= 0, regs= 3/0, args= 16, gp= 0
	.mask	0x80030000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-32
	sw	$17,20($sp)
	sw	$31,24($sp)
	sw	$16,16($sp)
	lui	$17,%hi(wan_port_status)
	lui	$2,%hi(clientsocket)
	sw	$4,%lo(wan_port_status)($17)
	lw	$4,%lo(clientsocket)($2)
	lui	$3,%hi(dev_raether)
	jal	info_ncc
	lw	$16,%lo(dev_raether)($3)

	lw	$3,%lo(wan_port_status)($17)
	bne	$3,$0,$L17
	addiu	$4,$16,828

	lw	$31,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	j	$31
	addiu	$sp,$sp,32

$L17:
	lw	$31,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	j	schedule_work
	addiu	$sp,$sp,32

	.set	macro
	.set	reorder
	.end	send_info_to_ncc
	.section	.text.set_fe_pdma_glo_cfg,"ax",@progbits
	.align	2
	.globl	set_fe_pdma_glo_cfg
	.ent	set_fe_pdma_glo_cfg
	.type	set_fe_pdma_glo_cfg, @function
set_fe_pdma_glo_cfg:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$3,-2147483648			# 0xffffffff80000000
	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$3,$3,0x65
	ori	$2,$2,0xa04
	sw	$3,0($2)
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	set_fe_pdma_glo_cfg
	.section	.text.forward_config,"ax",@progbits
	.align	2
	.globl	forward_config
	.ent	forward_config
	.type	forward_config, @function
forward_config:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$5,-1341128704			# 0xffffffffb0100000
	li	$2,196608			# 0x30000
	ori	$9,$5,0x600
	ori	$6,$5,0x430
	ori	$7,$5,0x434
	li	$3,65536			# 0x10000
	ori	$2,$2,0x2
	lw	$15,0($9)
	sw	$3,0($6)
	sw	$2,0($7)
	li	$3,327680			# 0x50000
	li	$2,458752			# 0x70000
	ori	$8,$5,0x438
	ori	$10,$5,0x43c
	ori	$3,$3,0x4
	ori	$2,$2,0x6
	sw	$3,0($8)
	sw	$2,0($10)
	li	$3,589824			# 0x90000
	li	$2,720896			# 0xb0000
	ori	$11,$5,0x440
	ori	$12,$5,0x444
	ori	$3,$3,0x8
	ori	$2,$2,0xa
	sw	$3,0($11)
	sw	$2,0($12)
	li	$3,851968			# 0xd0000
	li	$2,983040			# 0xf0000
	ori	$13,$5,0x448
	ori	$14,$5,0x44c
	ori	$3,$3,0xc
	ori	$2,$2,0xe
	sw	$3,0($13)
	li	$8,-8			# 0xfffffffffffffff8
	sw	$2,0($14)
	lw	$6,100($4)
	ori	$7,$5,0x400
	and	$15,$15,$8
	li	$2,4194304			# 0x400000
	lw	$10,0($7)
	or	$15,$15,$2
	li	$2,2097152			# 0x200000
	or	$15,$15,$2
	li	$3,1048576			# 0x100000
	or	$15,$15,$3
	ori	$6,$6,0x82
	sw	$6,100($4)
	and	$10,$10,$8
	sw	$15,0($9)
	ori	$5,$5,0xc
	li	$15,1			# 0x1
	sw	$10,0($7)
	sw	$15,0($5)
	sw	$0,0($5)
	lw	$10,0($7)
	lw	$15,0($9)
	j	$31
	li	$2,1			# 0x1

	.set	macro
	.set	reorder
	.end	forward_config
	.section	.text.ra_get_stats,"ax",@progbits
	.align	2
	.globl	ra_get_stats
	.ent	ra_get_stats
	.type	ra_get_stats, @function
ra_get_stats:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	j	$31
	addiu	$2,$4,1928

	.set	macro
	.set	reorder
	.end	ra_get_stats
	.section	.rodata.str1.4
	.align	2
$LC8:
	.ascii	"/var/run/udhcpc.pid\000"
	.section	.text.kill_sig_workq,"ax",@progbits
	.align	2
	.globl	kill_sig_workq
	.ent	kill_sig_workq
	.type	kill_sig_workq, @function
kill_sig_workq:
	.frame	$sp,40,$31		# vars= 8, regs= 3/0, args= 16, gp= 0
	.mask	0x80030000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lui	$4,%hi($LC8)
	addiu	$sp,$sp,-40
	addiu	$4,$4,%lo($LC8)
	move	$5,$0
	move	$6,$0
	sw	$16,24($sp)
	sw	$31,32($sp)
	jal	filp_open
	sw	$17,28($sp)

	move	$16,$2
	sltu	$2,$2,-4095
	xori	$2,$2,0x1
	bne	$2,$0,$L31
	lw	$31,32($sp)

	lw	$2,16($16)
	beq	$2,$0,$L32
	move	$4,$16

	lw	$2,8($2)
	addiu	$7,$16,32
	addiu	$5,$sp,16
	bne	$2,$0,$L30
	li	$6,8			# 0x8

$L27:
	move	$4,$16
$L32:
	jal	filp_close
	move	$5,$0

	lw	$31,32($sp)
$L31:
	lw	$17,28($sp)
	lw	$16,24($sp)
	j	$31
	addiu	$sp,$sp,40

$L30:
	jal	$2
	nop

	li	$6,10			# 0xa
	move	$5,$0
	blez	$2,$L27
	addiu	$4,$sp,16

	jal	simple_strtoul
	nop

	jal	find_get_pid
	move	$4,$2

	move	$4,$2
	jal	pid_task
	move	$5,$0

	move	$17,$2
	li	$4,17			# 0x11
	move	$5,$2
	beq	$2,$0,$L27
	move	$6,$0

	jal	send_sig
	nop

	move	$5,$17
	li	$4,16			# 0x10
	jal	send_sig
	move	$6,$0

	move	$4,$16
	jal	filp_close
	move	$5,$0

	j	$L31
	lw	$31,32($sp)

	.set	macro
	.set	reorder
	.end	kill_sig_workq
	.section	.text.ei_receive,"ax",@progbits
	.align	2
	.globl	ei_receive
	.ent	ei_receive
	.type	ei_receive, @function
ei_receive:
	.frame	$sp,56,$31		# vars= 0, regs= 10/0, args= 16, gp= 0
	.mask	0xc0ff0000,-4
	.fmask	0x00000000,0
	addiu	$sp,$sp,-56
	sw	$18,24($sp)
	sw	$31,52($sp)
	sw	$fp,48($sp)
	sw	$23,44($sp)
	sw	$22,40($sp)
	sw	$21,36($sp)
	sw	$20,32($sp)
	sw	$19,28($sp)
	sw	$17,20($sp)
	sw	$16,16($sp)
	lui	$2,%hi(dev_raether)
	lui	$3,%hi(tx_ring_full)
	lw	$22,%lo(dev_raether)($2)
	lw	$2,%lo(tx_ring_full)($3)
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L35
	addiu	$18,$22,800
	.set	macro
	.set	reorder

	lui	$3,%hi(rx_calc_idx0)
	lw	$2,%lo(rx_calc_idx0)($3)
	move	$fp,$0
	addiu	$4,$2,1
	slt	$3,$4,0
	addiu	$2,$2,256
	movz	$2,$4,$3
	sra	$2,$2,8
	sll	$2,$2,8
	subu	$4,$4,$2
	lui	$2,%hi(rx_dma_owner_idx0)
	sw	$4,%lo(rx_dma_owner_idx0)($2)
$L38:
	sltu	$2,$fp,3
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L97
	addiu	$fp,$fp,1
	.set	macro
	.set	reorder

	lui	$3,%hi(rx_dma_owner_idx0)
	lw	$4,%lo(rx_dma_owner_idx0)($3)
	lw	$5,1224($18)
	sll	$2,$4,4
	addu	$6,$2,$5
	lw	$3,4($6)
	.set	noreorder
	.set	nomacro
	bgez	$3,$L75
	sll	$2,$4,2
	.set	macro
	.set	reorder

	lui	$21,%hi(rx_ring)
	lui	$20,%hi(rx_dma_owner_idx)
	sw	$4,%lo(rx_dma_owner_idx)($20)
	sw	$5,%lo(rx_ring)($21)
	addu	$2,$2,$18
	lw	$16,1228($2)
	lhu	$19,6($6)
	lw	$3,172($16)
	andi	$19,$19,0x3fff
	sw	$19,76($16)
	addiu	$4,$3,2
	addu	$2,$4,$19
	sw	$2,160($16)
	sw	$4,172($16)
	lui	$2,%hi(proc_rx_debug)
	lw	$3,%lo(proc_rx_debug)($2)
	.set	noreorder
	.set	nomacro
	bne	$3,$0,$L99
	lui	$3,%hi(proc_rx_debug_type)
	.set	macro
	.set	reorder

	move	$4,$16
$L102:
	sw	$22,20($16)
	.set	noreorder
	.set	nomacro
	jal	eth_type_trans
	move	$5,$22
	.set	macro
	.set	reorder

	sh	$2,98($16)
	lw	$2,%lo(rx_dma_owner_idx)($20)
	lw	$4,%lo(rx_ring)($21)
	sll	$2,$2,4
	addu	$2,$2,$4
	lw	$3,12($2)
	srl	$3,$3,23
	andi	$3,$3,0x1
	.set	noreorder
	.set	nomacro
	bne	$3,$0,$L63
	lui	$2,%hi(non_check)
	.set	macro
	.set	reorder

	lw	$3,%lo(non_check)($2)
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L62
	li	$3,-13			# 0xfffffffffffffff3
	.set	macro
	.set	reorder

$L63:
	lw	$2,96($16)
	li	$3,-13			# 0xfffffffffffffff3
	and	$2,$2,$3
	ori	$2,$2,0x4
$L98:
	sw	$2,96($16)
	lui	$23,%hi(ra_sw_nat_hook_rx)
	lw	$2,%lo(ra_sw_nat_hook_rx)($23)
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L65
	li	$2,114			# 0x72
	.set	macro
	.set	reorder

	lw	$4,168($16)
	li	$3,117			# 0x75
	sb	$2,1($4)
	sb	$3,0($4)
	lw	$2,%lo(rx_dma_owner_idx)($20)
	lw	$4,%lo(rx_ring)($21)
	lw	$5,168($16)
	sll	$2,$2,4
	addu	$2,$2,$4
	lw	$3,12($2)
	sw	$3,2($5)
	lw	$4,168($16)
	lbu	$2,4($4)
	sb	$0,5($4)
	andi	$2,$2,0x3f
	sb	$2,4($4)
$L65:
	jal	skbmgr_alloc_skb2k
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L96
	move	$17,$2
	.set	macro
	.set	reorder

	lw	$2,172($2)
	lw	$3,160($17)
	addiu	$2,$2,80
	addiu	$3,$3,80
	sw	$2,172($17)
	sw	$3,160($17)
	lw	$2,%lo(ra_sw_nat_hook_rx)($23)
	beq	$2,$0,$L72
	.set	noreorder
	.set	nomacro
	jal	$2
	move	$4,$16
	.set	macro
	.set	reorder

	beq	$2,$0,$L71
$L72:
	.set	noreorder
	.set	nomacro
	jal	netif_rx
	move	$4,$16
	.set	macro
	.set	reorder

$L71:
	lw	$2,1128($18)
	lw	$3,1136($18)
	li	$4,100663296			# 0x6000000
	addiu	$2,$2,1
	addu	$3,$3,$19
	sw	$2,1128($18)
	sw	$3,1136($18)
	lw	$5,%lo(rx_dma_owner_idx)($20)
	lw	$2,%lo(rx_ring)($21)
	li	$6,1536			# 0x600
	sll	$5,$5,4
	addu	$5,$5,$2
	lw	$3,4($5)
	li	$2,-1073741824			# 0xffffffffc0000000
	ori	$2,$2,0xffff
	and	$3,$3,$2
	or	$3,$3,$4
	sw	$3,4($5)
	lw	$4,%lo(rx_dma_owner_idx)($20)
	lw	$2,%lo(rx_ring)($21)
	li	$7,2			# 0x2
	sll	$4,$4,4
	addu	$4,$4,$2
	lw	$3,4($4)
	li	$2,-1073807360			# 0xffffffffbfff0000
	ori	$2,$2,0xffff
	and	$3,$3,$2
	sw	$3,4($4)
	lw	$5,%lo(rx_dma_owner_idx)($20)
	lw	$2,%lo(rx_ring)($21)
	move	$4,$0
	sll	$5,$5,4
	addu	$5,$5,$2
	lw	$3,4($5)
	li	$2,2147418112			# 0x7fff0000
	ori	$2,$2,0xffff
	and	$3,$3,$2
	sw	$3,4($5)
	lw	$16,%lo(rx_dma_owner_idx)($20)
	lw	$2,%lo(rx_ring)($21)
	lw	$5,172($17)
	sll	$16,$16,4
	.set	noreorder
	.set	nomacro
	jal	dma_map_single
	addu	$16,$16,$2
	.set	macro
	.set	reorder

	sw	$2,0($16)
	lw	$4,%lo(rx_dma_owner_idx)($20)
	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$2,$2,0x908
	sll	$3,$4,2
	addu	$3,$3,$18
	sw	$4,0($2)
	sw	$17,1228($3)
	lw	$5,%lo(rx_dma_owner_idx)($20)
	addiu	$4,$5,1
	slt	$3,$4,0
	addiu	$2,$5,256
	movz	$2,$4,$3
	sra	$2,$2,8
	sll	$2,$2,8
	subu	$4,$4,$2
	lui	$3,%hi(rx_dma_owner_idx0)
	lui	$2,%hi(rx_calc_idx0)
	sw	$4,%lo(rx_dma_owner_idx0)($3)
	.set	noreorder
	.set	nomacro
	j	$L38
	sw	$5,%lo(rx_calc_idx0)($2)
	.set	macro
	.set	reorder

$L62:
	lw	$2,96($16)
	.set	noreorder
	.set	nomacro
	j	$L98
	and	$2,$2,$3
	.set	macro
	.set	reorder

$L35:
	addiu	$5,$22,860
#APP
			

#NO_APP
	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L100
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

#APP
	raw_local_irq_save	$2
#NO_APP
	lw	$4,864($22)
	lw	$3,864($22)
	andi	$4,$4,0x1
	ori	$3,$3,0x1
	sw	$3,864($22)
#APP
	raw_local_irq_restore	$2
			

#NO_APP
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L104
	lw	$31,52($sp)
	.set	macro
	.set	reorder

$L103:
	lw	$fp,48($sp)
	lw	$23,44($sp)
	lw	$22,40($sp)
	lw	$21,36($sp)
	lw	$20,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,56
	.set	macro
	.set	reorder

$L100:
#APP
		.set	push					
	.set	noreorder				
	.set	mips3					
1:	ll	$3, 864($22)		# test_and_set_bit	
	or	$4, $3, $2				
	sc	$4, 864($22)					
	beqz	$4, 2f					
	 and	$4, $3, $2				
	.subsection 2					
2:	b	1b					
	 nop						
	.previous					
	.set	pop					

			

#NO_APP
	.set	noreorder
	.set	nomacro
	bne	$4,$0,$L103
	lw	$31,52($sp)
	.set	macro
	.set	reorder

$L104:
	lw	$fp,48($sp)
	lw	$23,44($sp)
	lw	$22,40($sp)
	lw	$21,36($sp)
	lw	$20,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	move	$4,$5
	.set	noreorder
	.set	nomacro
	j	__tasklet_schedule
	addiu	$sp,$sp,56
	.set	macro
	.set	reorder

$L96:
	lw	$2,1152($18)
	addiu	$2,$2,1
	sw	$2,1152($18)
$L97:
	addiu	$5,$18,60
#APP
			

#NO_APP
	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L79
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

#APP
		.set	push					
	.set	noreorder				
	.set	mips3					
1:	ll	$3, 64($18)		# test_and_set_bit	
	or	$4, $3, $2				
	sc	$4, 64($18)					
	beqz	$4, 2f					
	 and	$4, $3, $2				
	.subsection 2					
2:	b	1b					
	 nop						
	.previous					
	.set	pop					

#NO_APP
$L78:
#APP
			

#NO_APP
	.set	noreorder
	.set	nomacro
	bne	$4,$0,$L103
	lw	$31,52($sp)
	.set	macro
	.set	reorder

	lw	$fp,48($sp)
	lw	$23,44($sp)
	lw	$22,40($sp)
	lw	$21,36($sp)
	lw	$20,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	move	$4,$5
	.set	noreorder
	.set	nomacro
	j	__tasklet_hi_schedule
	addiu	$sp,$sp,56
	.set	macro
	.set	reorder

$L79:
#APP
	raw_local_irq_save	$2
#NO_APP
	lw	$4,64($18)
	lw	$3,64($18)
	andi	$4,$4,0x1
	ori	$3,$3,0x1
	sw	$3,64($18)
#APP
	raw_local_irq_restore	$2
#NO_APP
	j	$L78
$L99:
	lhu	$4,16($4)
	lhu	$2,%lo(proc_rx_debug_type)($3)
#APP
		wsbh	$2, $2			

#NO_APP
	andi	$2,$2,0xffff
	.set	noreorder
	.set	nomacro
	bne	$4,$2,$L102
	move	$4,$16
	.set	macro
	.set	reorder

	li	$2,47			# 0x2f
	addiu	$2,$2,-1
$L105:
	.set	noreorder
	.set	nomacro
	bgez	$2,$L105
	addiu	$2,$2,-1
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L102
	move	$4,$16
	.set	macro
	.set	reorder

$L75:
	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$2,$2,0xa28
	lw	$3,0($2)
	li	$4,1073741824			# 0x40000000
	or	$3,$3,$4
	sw	$3,0($2)
	.set	noreorder
	.set	nomacro
	j	$L103
	lw	$31,52($sp)
	.set	macro
	.set	reorder

	.end	ei_receive
	.section	.text.esw_link_status_changed,"ax",@progbits
	.align	2
	.ent	esw_link_status_changed
	.type	esw_link_status_changed, @function
esw_link_status_changed:
	.frame	$sp,24,$31		# vars= 0, regs= 2/0, args= 16, gp= 0
	.mask	0x80010000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-24
	sw	$16,16($sp)
	sll	$2,$4,8
	move	$16,$4
	li	$4,-1341063168			# 0xffffffffb0110000
	sw	$31,20($sp)
	addu	$2,$2,$4
	lw	$3,12296($2)
	andi	$3,$3,0x1
	beq	$3,$0,$L111
	li	$2,4			# 0x4

	beq	$16,$2,$L115
	addiu	$4,$5,828

$L111:
	lui	$4,%hi(wan_detect)
$L117:
	li	$2,4			# 0x4
	beq	$16,$2,$L116
	addiu	$4,$4,%lo(wan_detect)

	lw	$31,20($sp)
	lw	$16,16($sp)
	j	$31
	addiu	$sp,$sp,24

$L116:
	lui	$2,%hi(jiffies)
	lw	$5,%lo(jiffies)($2)
	lw	$31,20($sp)
	lw	$16,16($sp)
	addiu	$5,$5,750
	j	mod_timer
	addiu	$sp,$sp,24

$L115:
	jal	schedule_work
	nop

	j	$L117
	lui	$4,%hi(wan_detect)

	.set	macro
	.set	reorder
	.end	esw_link_status_changed
	.section	.text.esw_interrupt,"ax",@progbits
	.align	2
	.ent	esw_interrupt
	.type	esw_interrupt, @function
esw_interrupt:
	.frame	$sp,40,$31		# vars= 0, regs= 6/0, args= 16, gp= 0
	.mask	0x801f0000,-4
	.fmask	0x00000000,0
	addiu	$sp,$sp,-40
	sw	$18,24($sp)
	sw	$31,36($sp)
	sw	$20,32($sp)
	sw	$19,28($sp)
	sw	$17,20($sp)
	sw	$16,16($sp)
	move	$18,$5
#APP
	raw_local_irq_save	$17
#NO_APP
	li	$20,-1341063168			# 0xffffffffb0110000
	ori	$19,$20,0x700c
	lw	$16,0($19)
	srl	$2,$16,5
	andi	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L148
	srl	$2,$16,4
	.set	macro
	.set	reorder

	andi	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L155
	li	$4,4			# 0x4
	.set	macro
	.set	reorder

	srl	$2,$16,3
$L159:
	andi	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L156
	li	$4,3			# 0x3
	.set	macro
	.set	reorder

	srl	$2,$16,2
$L160:
	andi	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L157
	li	$4,2			# 0x2
	.set	macro
	.set	reorder

	srl	$2,$16,1
$L161:
	andi	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L158
	li	$4,1			# 0x1
	.set	macro
	.set	reorder

	andi	$2,$16,0x1
$L162:
	bne	$2,$0,$L153
$L133:
	srl	$2,$16,15
$L154:
	andi	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L134
	ori	$3,$20,0x8
	.set	macro
	.set	reorder

	lw	$2,0($3)
	sw	$2,0($3)
$L134:
	sw	$16,0($19)
#APP
	raw_local_irq_restore	$17
#NO_APP
	lw	$31,36($sp)
	lw	$20,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	li	$2,1			# 0x1
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,40
	.set	macro
	.set	reorder

$L148:
	.set	noreorder
	.set	nomacro
	jal	esw_link_status_changed
	li	$4,5			# 0x5
	.set	macro
	.set	reorder

	srl	$2,$16,4
	andi	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L159
	srl	$2,$16,3
	.set	macro
	.set	reorder

	li	$4,4			# 0x4
$L155:
	.set	noreorder
	.set	nomacro
	jal	esw_link_status_changed
	move	$5,$18
	.set	macro
	.set	reorder

	srl	$2,$16,3
	andi	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L160
	srl	$2,$16,2
	.set	macro
	.set	reorder

	li	$4,3			# 0x3
$L156:
	.set	noreorder
	.set	nomacro
	jal	esw_link_status_changed
	move	$5,$18
	.set	macro
	.set	reorder

	srl	$2,$16,2
	andi	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L161
	srl	$2,$16,1
	.set	macro
	.set	reorder

	li	$4,2			# 0x2
$L157:
	.set	noreorder
	.set	nomacro
	jal	esw_link_status_changed
	move	$5,$18
	.set	macro
	.set	reorder

	srl	$2,$16,1
	andi	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L162
	andi	$2,$16,0x1
	.set	macro
	.set	reorder

	li	$4,1			# 0x1
$L158:
	.set	noreorder
	.set	nomacro
	jal	esw_link_status_changed
	move	$5,$18
	.set	macro
	.set	reorder

	andi	$2,$16,0x1
	beq	$2,$0,$L133
$L153:
	move	$5,$18
	.set	noreorder
	.set	nomacro
	jal	esw_link_status_changed
	move	$4,$0
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L154
	srl	$2,$16,15
	.set	macro
	.set	reorder

	.end	esw_interrupt
	.section	.text.ei_start_xmit_fake,"ax",@progbits
	.align	2
	.ent	ei_start_xmit_fake
	.type	ei_start_xmit_fake, @function
ei_start_xmit_fake:
	.frame	$sp,40,$31		# vars= 0, regs= 5/0, args= 16, gp= 0
	.mask	0x800f0000,-8
	.fmask	0x00000000,0
$L164:
	addiu	$sp,$sp,-40
	sw	$19,28($sp)
	sw	$18,24($sp)
	sw	$17,20($sp)
	sw	$31,32($sp)
	sw	$16,16($sp)
	lui	$2,%hi(proc_tx_debug)
	lw	$3,%lo(proc_tx_debug)($2)
	move	$17,$5
	move	$18,$4
	.set	noreorder
	.set	nomacro
	bne	$3,$0,$L281
	addiu	$19,$5,800
	.set	macro
	.set	reorder

	lui	$3,%hi(ra_sw_nat_hook_tx)
$L285:
	lw	$2,%lo(ra_sw_nat_hook_tx)($3)
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L286
	lui	$2,%hi(jiffies)
	.set	macro
	.set	reorder

#APP
	raw_local_irq_save	$16
#NO_APP
	lw	$2,%lo(ra_sw_nat_hook_tx)($3)
	move	$4,$18
	.set	noreorder
	.set	nomacro
	jal	$2
	li	$5,1			# 0x1
	.set	macro
	.set	reorder

	li	$3,1			# 0x1
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L282
	move	$4,$18
	.set	macro
	.set	reorder

$L280:
	jal	kfree_skb
#APP
	raw_local_irq_restore	$16
#NO_APP
	lw	$31,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	move	$2,$0
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,40
	.set	macro
	.set	reorder

$L282:
#APP
	raw_local_irq_restore	$16
#NO_APP
	lui	$2,%hi(jiffies)
$L286:
	lw	$3,%lo(jiffies)($2)
	sw	$3,484($17)
#APP
	raw_local_irq_save	$16
#NO_APP
	lw	$5,172($18)
	lw	$6,76($18)
	move	$4,$0
	.set	noreorder
	.set	nomacro
	jal	dma_cache_sync
	li	$7,1			# 0x1
	.set	macro
	.set	reorder

	lui	$8,%hi(tx_cpu_owner_idx0)
	lw	$5,%lo(tx_cpu_owner_idx0)($8)
	move	$9,$8
	sll	$10,$5,2
	addu	$2,$10,$19
	lw	$4,100($2)
	addiu	$3,$5,1
	.set	noreorder
	.set	nomacro
	bne	$4,$0,$L231
	andi	$2,$3,0xff
	.set	macro
	.set	reorder

	sll	$2,$2,2
	addu	$2,$2,$19
	lw	$3,100($2)
	.set	noreorder
	.set	nomacro
	bne	$3,$0,$L231
	addiu	$7,$17,800
	.set	macro
	.set	reorder

	lw	$6,1220($7)
	sll	$2,$5,4
	addu	$2,$2,$6
	lw	$3,4($2)
	.set	noreorder
	.set	nomacro
	bltz	$3,$L278
	lw	$11,76($18)
	.set	macro
	.set	reorder

	lw	$4,1148($7)
	addiu	$4,$4,1
$L287:
	sw	$4,1148($7)
	lw	$2,%lo(tx_cpu_owner_idx0)($9)
	sll	$2,$2,4
	addu	$2,$2,$6
	lw	$3,4($2)
	.set	noreorder
	.set	nomacro
	bgez	$3,$L287
	addiu	$4,$4,1
	.set	macro
	.set	reorder

$L278:
	lw	$2,%lo(tx_cpu_owner_idx0)($8)
	lw	$4,172($18)
	li	$3,-2147483648			# 0xffffffff80000000
	sll	$2,$2,4
	addu	$4,$4,$3
	addu	$2,$2,$6
	sw	$4,0($2)
	lw	$5,%lo(tx_cpu_owner_idx0)($8)
	lw	$2,1220($7)
	andi	$4,$11,0x3fff
	sll	$5,$5,4
	addu	$5,$5,$2
	lw	$3,4($5)
	li	$2,-1073741824			# 0xffffffffc0000000
	ori	$2,$2,0xffff
	and	$3,$3,$2
	sll	$4,$4,16
	or	$3,$3,$4
	sw	$3,4($5)
	lw	$4,%lo(tx_cpu_owner_idx0)($8)
	lw	$2,1220($7)
	sll	$4,$4,4
	addu	$4,$4,$2
	lw	$3,12($4)
	li	$2,-267452416			# 0xfffffffff00f0000
	ori	$2,$2,0xffff
	and	$3,$3,$2
	sw	$3,12($4)
	lw	$2,96($18)
	li	$3,12			# 0xc
	andi	$2,$2,0xc
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L283
	lui	$2,%hi(tx_cpu_owner_idx0)
	.set	macro
	.set	reorder

	lw	$4,%lo(tx_cpu_owner_idx0)($2)
	lw	$5,1220($7)
	li	$2,536805376			# 0x1fff0000
	sll	$4,$4,4
	addu	$4,$4,$5
	lw	$3,12($4)
	ori	$2,$2,0xffff
	and	$3,$3,$2
	sw	$3,12($4)
$L238:
	lhu	$3,144($18)
	andi	$5,$3,0xffff
	srl	$2,$5,12
	andi	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L239
	lw	$2,%lo(tx_cpu_owner_idx0)($8)
	.set	macro
	.set	reorder

	lw	$4,%lo(tx_cpu_owner_idx0)($8)
	srl	$2,$5,13
	lw	$5,1220($7)
	andi	$3,$3,0xf
	sll	$2,$2,4
	or	$2,$2,$3
	sll	$4,$4,4
	li	$3,-128
	addu	$4,$4,$5
	or	$2,$2,$3
	sb	$2,12($4)
$L240:
	lw	$3,168($18)
	lbu	$2,1($3)
	lbu	$4,0($3)
	li	$3,29302			# 0x7276
	sll	$2,$2,8
	or	$2,$2,$4
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L284
	lui	$2,%hi(ra_sw_nat_hook_rx)
	.set	macro
	.set	reorder

$L241:
	lw	$4,%lo(tx_cpu_owner_idx0)($8)
$L291:
	lw	$2,1220($7)
	sll	$4,$4,4
	addu	$4,$4,$2
	lw	$3,4($4)
	li	$2,2147418112			# 0x7fff0000
	ori	$2,$2,0xffff
	and	$3,$3,$2
	sw	$3,4($4)
	lw	$2,%lo(tx_cpu_owner_idx0)($8)
	addiu	$2,$2,1
	andi	$2,$2,0xff
	sw	$2,%lo(tx_cpu_owner_idx0)($8)
	lw	$6,1220($7)
	sll	$2,$2,4
	addu	$2,$2,$6
	lw	$3,4($2)
	.set	noreorder
	.set	nomacro
	bltz	$3,$L288
	lw	$3,%lo(tx_cpu_owner_idx0)($8)
	.set	macro
	.set	reorder

	lw	$4,1148($7)
	addiu	$2,$4,1
$L289:
	sw	$2,1148($7)
	move	$4,$2
	lw	$2,%lo(tx_cpu_owner_idx0)($8)
	sll	$2,$2,4
	addu	$2,$2,$6
	lw	$3,4($2)
	.set	noreorder
	.set	nomacro
	bgez	$3,$L289
	addiu	$2,$4,1
	.set	macro
	.set	reorder

	lw	$3,%lo(tx_cpu_owner_idx0)($8)
$L288:
	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$2,$2,0x808
	sw	$3,0($2)
	lw	$4,1132($7)
	lw	$2,1140($7)
	addu	$5,$10,$19
	addiu	$4,$4,1
	addu	$2,$2,$11
	sw	$2,1140($7)
	sw	$18,100($5)
	sw	$4,1132($7)
#APP
	raw_local_irq_restore	$16
#NO_APP
	lw	$31,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	move	$2,$0
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,40
	.set	macro
	.set	reorder

$L231:
	lw	$2,1156($19)
	move	$4,$18
	addiu	$2,$2,1
	.set	noreorder
	.set	nomacro
	j	$L280
	sw	$2,1156($19)
	.set	macro
	.set	reorder

$L239:
	lw	$3,1220($7)
	sll	$2,$2,4
	addu	$2,$2,$3
	.set	noreorder
	.set	nomacro
	j	$L240
	sb	$0,12($2)
	.set	macro
	.set	reorder

$L281:
	lw	$4,172($4)
	lui	$3,%hi(proc_tx_debug_type)
	lhu	$2,%lo(proc_tx_debug_type)($3)
	lhu	$5,16($4)
#APP
		wsbh	$2, $2			

#NO_APP
	andi	$2,$2,0xffff
	.set	noreorder
	.set	nomacro
	bne	$5,$2,$L285
	lui	$3,%hi(ra_sw_nat_hook_tx)
	.set	macro
	.set	reorder

	li	$2,47			# 0x2f
	addiu	$2,$2,-1
$L290:
	.set	noreorder
	.set	nomacro
	bgez	$2,$L290
	addiu	$2,$2,-1
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L285
	lui	$3,%hi(ra_sw_nat_hook_tx)
	.set	macro
	.set	reorder

$L284:
	lw	$3,%lo(ra_sw_nat_hook_rx)($2)
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L291
	lw	$4,%lo(tx_cpu_owner_idx0)($8)
	.set	macro
	.set	reorder

	lw	$5,%lo(tx_cpu_owner_idx0)($8)
	lw	$2,1220($7)
	li	$4,134217728			# 0x8000000
	sll	$5,$5,4
	addu	$5,$5,$2
	lw	$3,12($5)
	li	$2,-267452416			# 0xfffffffff00f0000
	ori	$2,$2,0xffff
	and	$3,$3,$2
	or	$3,$3,$4
	.set	noreorder
	.set	nomacro
	j	$L241
	sw	$3,12($5)
	.set	macro
	.set	reorder

$L283:
	lw	$3,%lo(tx_cpu_owner_idx0)($8)
	lw	$4,1220($7)
	sll	$3,$3,4
	addu	$3,$3,$4
	lw	$2,12($3)
	li	$4,-536870912			# 0xffffffffe0000000
	or	$2,$2,$4
	.set	noreorder
	.set	nomacro
	j	$L238
	sw	$2,12($3)
	.set	macro
	.set	reorder

	.end	ei_start_xmit_fake
	.section	.text.dump_phy_reg,"ax",@progbits
	.align	2
	.globl	dump_phy_reg
	.ent	dump_phy_reg
	.type	dump_phy_reg, @function
dump_phy_reg:
	.frame	$sp,40,$31		# vars= 8, regs= 3/0, args= 16, gp= 0
	.mask	0x80030000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-40
	sw	$17,28($sp)
	sw	$31,32($sp)
	sw	$16,24($sp)
	move	$17,$4
	sw	$0,16($sp)
	bne	$7,$0,$L293
	lw	$6,56($sp)

	andi	$6,$6,0x7
	sll	$6,$6,12
	li	$4,1			# 0x1
	jal	mii_mgr_write
	li	$5,31			# 0x1f

	li	$16,16			# 0x10
	move	$5,$16
$L317:
	move	$4,$17
	addiu	$16,$16,1
	jal	mii_mgr_read
	addiu	$6,$sp,16

	sltu	$3,$16,32
	bne	$3,$0,$L317
	move	$5,$16

	lw	$31,32($sp)
	lw	$17,28($sp)
	lw	$16,24($sp)
	j	$31
	addiu	$sp,$sp,40

$L293:
	andi	$6,$6,0x7
	sll	$6,$6,12
	ori	$6,$6,0x8000
	li	$4,1			# 0x1
	jal	mii_mgr_write
	li	$5,31			# 0x1f

	li	$16,16			# 0x10
	move	$5,$16
$L318:
	move	$4,$17
	addiu	$16,$16,1
	jal	mii_mgr_read
	addiu	$6,$sp,16

	sltu	$3,$16,32
	bne	$3,$0,$L318
	move	$5,$16

	lw	$31,32($sp)
	lw	$17,28($sp)
	lw	$16,24($sp)
	j	$31
	addiu	$sp,$sp,40

	.set	macro
	.set	reorder
	.end	dump_phy_reg
	.section	.text.ei_ioctl,"ax",@progbits
	.align	2
	.globl	ei_ioctl
	.ent	ei_ioctl
	.type	ei_ioctl, @function
ei_ioctl:
	.frame	$sp,120,$31		# vars= 80, regs= 3/0, args= 24, gp= 0
	.mask	0x80030000,-8
	.fmask	0x00000000,0
	li	$2,-65536			# 0xffffffffffff0000
	ori	$2,$2,0x760f
	addu	$2,$6,$2
	addiu	$sp,$sp,-120
	sltu	$3,$2,10
	sw	$16,104($sp)
	sw	$31,112($sp)
	sw	$17,108($sp)
	move	$16,$5
	sw	$0,96($sp)
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L319
	li	$4,-122			# 0xffffffffffffff86
	.set	macro
	.set	reorder

	lui	$3,%hi($L434)
	sll	$2,$2,2
	addiu	$3,$3,%lo($L434)
	addu	$2,$2,$3
	lw	$4,0($2)
	j	$4
	.rdata
	.align	2
$L434:
	.word	$L347
	.word	$L363
	.word	$L321
	.word	$L336
	.word	$L413
	.word	$L423
	.word	$L372
	.word	$L320
	.word	$L320
	.word	$L320
	.section	.text.ei_ioctl
$L347:
	lw	$5,16($5)
	lw	$3,24($28)
	addiu	$2,$5,8
	or	$2,$2,$5
	and	$2,$2,$3
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L348
	addiu	$7,$sp,56
	.set	macro
	.set	reorder

	move	$4,$7
	li	$6,8			# 0x8
#APP
	.set	noreorder
	jal	__copy_user
	.set	noat
	addu	$1, $5, $6
	.set	at
	.set	reorder
#NO_APP
$L348:
	lw	$3,56($sp)
	li	$2,458752			# 0x70000
	ori	$2,$2,0xffff
	sltu	$2,$2,$3
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L319
	li	$4,-22			# 0xffffffffffffffea
	.set	macro
	.set	reorder

	li	$2,-1341063168			# 0xffffffffb0110000
	addu	$2,$3,$2
	lw	$4,0($2)
	lw	$5,16($16)
	sw	$4,60($sp)
	lw	$3,24($28)
	addiu	$2,$5,8
	or	$2,$2,$5
	and	$2,$2,$3
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L320
	move	$4,$5
	.set	macro
	.set	reorder

	li	$6,8			# 0x8
	move	$5,$7
#APP
	jal	__copy_user
	
#NO_APP
$L320:
	move	$4,$0
$L319:
	lw	$31,112($sp)
$L451:
	lw	$17,108($sp)
	lw	$16,104($sp)
	move	$2,$4
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,120
	.set	macro
	.set	reorder

$L372:
	lw	$5,16($5)
	lw	$3,24($28)
	addiu	$2,$5,8
	or	$2,$2,$5
	and	$2,$2,$3
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L373
	addiu	$4,$sp,56
	.set	macro
	.set	reorder

	li	$6,8			# 0x8
#APP
	.set	noreorder
	jal	__copy_user
	.set	noat
	addu	$1, $5, $6
	.set	at
	.set	reorder
#NO_APP
$L373:
	lw	$4,60($sp)
	li	$2,32			# 0x20
	.set	noreorder
	.set	nomacro
	bne	$4,$2,$L402
	move	$16,$0
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L450
	move	$17,$0
	.set	macro
	.set	reorder

$L444:
$L402:
	move	$5,$16
	addiu	$6,$sp,96
	.set	noreorder
	.set	nomacro
	jal	mii_mgr_read
	addiu	$16,$16,1
	.set	macro
	.set	reorder

	sltu	$3,$16,16
	.set	noreorder
	.set	nomacro
	bne	$3,$0,$L444
	lw	$4,60($sp)
	.set	macro
	.set	reorder

	move	$16,$0
$L406:
	sw	$16,16($sp)
$L452:
	li	$4,1			# 0x1
	addiu	$16,$16,1
	li	$5,16			# 0x10
	li	$6,31			# 0x1f
	.set	noreorder
	.set	nomacro
	jal	dump_phy_reg
	move	$7,$0
	.set	macro
	.set	reorder

	sltu	$2,$16,5
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L406
	lw	$4,60($sp)
	.set	macro
	.set	reorder

	li	$2,32			# 0x20
	.set	noreorder
	.set	nomacro
	bne	$4,$2,$L407
	li	$5,16			# 0x10
	.set	macro
	.set	reorder

	move	$16,$0
$L411:
	move	$4,$16
	li	$5,16			# 0x10
	li	$6,31			# 0x1f
	li	$7,1			# 0x1
	.set	noreorder
	.set	nomacro
	jal	dump_phy_reg
	sw	$0,16($sp)
	.set	macro
	.set	reorder

	move	$4,$16
	li	$2,1			# 0x1
	li	$5,16			# 0x10
	li	$6,31			# 0x1f
	li	$7,1			# 0x1
	.set	noreorder
	.set	nomacro
	jal	dump_phy_reg
	sw	$2,16($sp)
	.set	macro
	.set	reorder

	move	$4,$16
	li	$2,2			# 0x2
	li	$5,16			# 0x10
	li	$6,31			# 0x1f
	li	$7,1			# 0x1
	.set	noreorder
	.set	nomacro
	jal	dump_phy_reg
	sw	$2,16($sp)
	.set	macro
	.set	reorder

	li	$2,3			# 0x3
	move	$4,$16
	li	$5,16			# 0x10
	addiu	$16,$16,1
	li	$6,31			# 0x1f
	li	$7,1			# 0x1
	.set	noreorder
	.set	nomacro
	jal	dump_phy_reg
	sw	$2,16($sp)
	.set	macro
	.set	reorder

	sltu	$2,$16,5
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L411
	move	$4,$0
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L451
	lw	$31,112($sp)
	.set	macro
	.set	reorder

$L363:
	lw	$5,16($5)
	lw	$3,24($28)
	addiu	$2,$5,8
	or	$2,$2,$5
	and	$2,$2,$3
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L364
	addiu	$4,$sp,56
	.set	macro
	.set	reorder

	li	$6,8			# 0x8
#APP
	.set	noreorder
	jal	__copy_user
	.set	noat
	addu	$1, $5, $6
	.set	at
	.set	reorder
#NO_APP
$L364:
	lw	$3,56($sp)
	li	$2,458752			# 0x70000
	ori	$2,$2,0xffff
	sltu	$2,$2,$3
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L319
	li	$4,-22			# 0xffffffffffffffea
	.set	macro
	.set	reorder

	li	$2,-1341063168			# 0xffffffffb0110000
	addu	$2,$3,$2
	lw	$3,60($sp)
	sw	$3,0($2)
	.set	noreorder
	.set	nomacro
	j	$L319
	move	$4,$0
	.set	macro
	.set	reorder

$L321:
	lw	$5,16($5)
	lw	$3,24($28)
	addiu	$2,$5,16
	or	$2,$2,$5
	and	$2,$2,$3
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L322
	addiu	$17,$sp,80
	.set	macro
	.set	reorder

	move	$4,$17
	li	$6,16			# 0x10
#APP
	.set	noreorder
	jal	__copy_user
	.set	noat
	addu	$1, $5, $6
	.set	at
	.set	reorder
#NO_APP
$L322:
	lw	$4,80($sp)
	lw	$5,84($sp)
	.set	noreorder
	.set	nomacro
	jal	mii_mgr_read
	addiu	$6,$sp,92
	.set	macro
	.set	reorder

	lw	$4,16($16)
	lw	$3,24($28)
	addiu	$2,$4,16
	or	$2,$2,$4
	and	$2,$2,$3
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L320
	move	$5,$17
	.set	macro
	.set	reorder

	li	$6,16			# 0x10
#APP
	jal	__copy_user
	
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L319
	move	$4,$0
	.set	macro
	.set	reorder

$L336:
	lw	$5,16($5)
	lw	$3,24($28)
	addiu	$2,$5,16
	or	$2,$2,$5
	and	$2,$2,$3
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L337
	li	$6,16			# 0x10
	.set	macro
	.set	reorder

	addiu	$4,$sp,80
#APP
	.set	noreorder
	jal	__copy_user
	.set	noat
	addu	$1, $5, $6
	.set	at
	.set	reorder
#NO_APP
$L337:
	lw	$4,80($sp)
	lw	$5,84($sp)
	.set	noreorder
	.set	nomacro
	jal	mii_mgr_write
	lw	$6,88($sp)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L319
	move	$4,$0
	.set	macro
	.set	reorder

$L413:
	lw	$5,16($5)
	lw	$3,24($28)
	addiu	$2,$5,12
	or	$2,$2,$5
	and	$2,$2,$3
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L414
	addiu	$4,$sp,64
	.set	macro
	.set	reorder

	li	$6,12			# 0xc
#APP
	.set	noreorder
	jal	__copy_user
	.set	noat
	addu	$1, $5, $6
	.set	at
	.set	reorder
#NO_APP
$L414:
	lw	$2,68($sp)
	li	$3,-1341063168			# 0xffffffffb0110000
	sll	$2,$2,8
	addiu	$16,$2,4224
	addu	$5,$16,$3
	lw	$4,0($5)
	lw	$3,64($sp)
	li	$2,-65536			# 0xffffffffffff0000
	and	$4,$4,$2
	li	$2,1			# 0x1
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L448
	sw	$4,96($sp)
	.set	macro
	.set	reorder

$L431:
	lw	$2,96($sp)
	sw	$2,0($5)
	.set	noreorder
	.set	nomacro
	j	$L319
	move	$4,$0
	.set	macro
	.set	reorder

$L423:
	lw	$5,16($5)
	lw	$3,24($28)
	addiu	$2,$5,12
	or	$2,$2,$5
	and	$2,$2,$3
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L424
	addiu	$4,$sp,64
	.set	macro
	.set	reorder

	li	$6,12			# 0xc
#APP
	.set	noreorder
	jal	__copy_user
	.set	noat
	addu	$1, $5, $6
	.set	at
	.set	reorder
#NO_APP
$L424:
	lw	$2,68($sp)
	li	$3,-1341063168			# 0xffffffffb0110000
	sll	$2,$2,8
	addiu	$16,$2,4160
	addu	$5,$16,$3
	lw	$4,0($5)
	lw	$3,64($sp)
	li	$2,-65536			# 0xffffffffffff0000
	and	$4,$4,$2
	li	$2,1			# 0x1
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L431
	sw	$4,96($sp)
	.set	macro
	.set	reorder

$L448:
	lw	$2,72($sp)
	ori	$3,$4,0x8300
	or	$2,$2,$3
	sw	$2,96($sp)
	lw	$2,96($sp)
	sw	$2,0($5)
	.set	noreorder
	.set	nomacro
	j	$L319
	move	$4,$0
	.set	macro
	.set	reorder

$L407:
	li	$6,31			# 0x1f
	li	$7,1			# 0x1
	.set	noreorder
	.set	nomacro
	jal	dump_phy_reg
	sw	$0,16($sp)
	.set	macro
	.set	reorder

	lw	$4,60($sp)
	li	$2,1			# 0x1
	li	$5,16			# 0x10
	li	$6,31			# 0x1f
	li	$7,1			# 0x1
	.set	noreorder
	.set	nomacro
	jal	dump_phy_reg
	sw	$2,16($sp)
	.set	macro
	.set	reorder

	lw	$4,60($sp)
	li	$2,2			# 0x2
	li	$5,16			# 0x10
	li	$6,31			# 0x1f
	li	$7,1			# 0x1
	.set	noreorder
	.set	nomacro
	jal	dump_phy_reg
	sw	$2,16($sp)
	.set	macro
	.set	reorder

	lw	$4,60($sp)
	li	$2,3			# 0x3
	li	$5,16			# 0x10
	li	$6,31			# 0x1f
	li	$7,1			# 0x1
	.set	noreorder
	.set	nomacro
	jal	dump_phy_reg
	sw	$2,16($sp)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L319
	move	$4,$0
	.set	macro
	.set	reorder

$L393:
$L450:
	move	$5,$16
$L449:
	move	$4,$17
	addiu	$16,$16,1
	.set	noreorder
	.set	nomacro
	jal	mii_mgr_read
	addiu	$6,$sp,96
	.set	macro
	.set	reorder

	sltu	$3,$16,16
	.set	noreorder
	.set	nomacro
	bne	$3,$0,$L449
	move	$5,$16
	.set	macro
	.set	reorder

	addiu	$17,$17,1
	slt	$2,$17,5
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L393
	move	$16,$0
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L452
	sw	$16,16($sp)
	.set	macro
	.set	reorder

	.end	ei_ioctl
	.section	.text.ei_change_mtu,"ax",@progbits
	.align	2
	.ent	ei_change_mtu
	.type	ei_change_mtu, @function
ei_change_mtu:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	addiu	$2,$4,800
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L453
	li	$3,-6			# 0xfffffffffffffffa
	.set	macro
	.set	reorder

#APP
	raw_local_irq_save	$3
#NO_APP
	addiu	$2,$5,-64
	sltu	$2,$2,4033
	beq	$2,$0,$L507
	slt	$2,$5,1501
	beq	$2,$0,$L507
	sw	$5,236($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	move	$3,$0
$L453:
	.set	noreorder
	.set	nomacro
	j	$31
	move	$2,$3
	.set	macro
	.set	reorder

$L507:
#APP
	raw_local_irq_restore	$3
#NO_APP
	li	$3,-22			# 0xffffffffffffffea
	.set	noreorder
	.set	nomacro
	j	$31
	move	$2,$3
	.set	macro
	.set	reorder

	.end	ei_change_mtu
	.section	.text.ra2880_setup_dev_fptable,"ax",@progbits
	.align	2
	.globl	ra2880_setup_dev_fptable
	.ent	ra2880_setup_dev_fptable
	.type	ra2880_setup_dev_fptable, @function
ra2880_setup_dev_fptable:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lui	$2,%hi(ei_netdev_ops)
	li	$3,1250			# 0x4e2
	addiu	$2,$2,%lo(ei_netdev_ops)
	sw	$3,488($4)
	j	$31
	sw	$2,212($4)

	.set	macro
	.set	reorder
	.end	ra2880_setup_dev_fptable
	.section	.text.fe_reset,"ax",@progbits
	.align	2
	.globl	fe_reset
	.ent	fe_reset
	.type	fe_reset, @function
fe_reset:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$4,-1342177280			# 0xffffffffb0000000
	ori	$4,$4,0x34
	lw	$3,0($4)
	li	$2,2097152			# 0x200000
	or	$3,$3,$2
	li	$2,-10551296			# 0xffffffffff5f0000
	ori	$2,$2,0xffff
	sw	$3,0($4)
	and	$3,$3,$2
	sw	$3,0($4)
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	fe_reset
	.section	.text.ei_tx_timeout,"ax",@progbits
	.align	2
	.globl	ei_tx_timeout
	.ent	ei_tx_timeout
	.type	ei_tx_timeout, @function
ei_tx_timeout:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	j	schedule_work
	addiu	$4,$4,844

	.set	macro
	.set	reorder
	.end	ei_tx_timeout
	.section	.text.setup_statistics,"ax",@progbits
	.align	2
	.globl	setup_statistics
	.ent	setup_statistics
	.type	setup_statistics, @function
setup_statistics:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	sw	$0,12($4)
	sw	$0,1132($4)
	sw	$0,1140($4)
	sw	$0,1156($4)
	sw	$0,1148($4)
	sw	$0,1192($4)
	sw	$0,1196($4)
	sw	$0,1200($4)
	sw	$0,1204($4)
	sw	$0,1208($4)
	sw	$0,1128($4)
	sw	$0,1136($4)
	sw	$0,1152($4)
	sw	$0,1144($4)
	sw	$0,1168($4)
	sw	$0,1172($4)
	sw	$0,1176($4)
	sw	$0,1180($4)
	sw	$0,1184($4)
	sw	$0,1188($4)
	j	$31
	sw	$0,1164($4)

	.set	macro
	.set	reorder
	.end	setup_statistics
	.rdata
	.align	2
$LC26:
	.byte	-1
	.byte	-1
	.byte	-1
	.byte	-1
	.byte	-1
	.byte	-1
	.section	.rodata.str1.4
	.align	2
$LC27:
	.ascii	"Factory\000"
	.rdata
	.align	2
$LC28:
	.byte	0
	.byte	12
	.byte	67
	.byte	40
	.byte	-128
	.section	.init.text,"ax",@progbits
	.align	2
	.globl	rather_probe
	.ent	rather_probe
	.type	rather_probe, @function
rather_probe:
	.frame	$sp,88,$31		# vars= 48, regs= 4/0, args= 24, gp= 0
	.mask	0x80070000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-88
	lui	$3,%hi($LC26)
	sw	$31,84($sp)
	sw	$18,80($sp)
	sw	$17,76($sp)
	sw	$16,72($sp)
	addiu	$2,$3,%lo($LC26)
	lwl	$5,3($2)
	lbu	$6,5($2)
	lbu	$7,4($2)
	lwr	$5,%lo($LC26)($3)
	move	$17,$4
	sb	$6,45($sp)
	sw	$5,40($sp)
	sb	$7,44($sp)
	sw	$0,48($sp)
	jal	fe_reset
	sh	$0,52($sp)

	lui	$4,%hi($LC27)
	addiu	$4,$4,%lo($LC27)
	li	$6,40			# 0x28
	addiu	$16,$sp,26
	li	$2,6			# 0x6
	move	$7,$0
	sw	$2,16($sp)
	jal	ra_mtd_read_nm
	sw	$16,20($sp)

	addiu	$18,$17,800
	addiu	$5,$sp,40
	li	$6,6			# 0x6
	bltz	$2,$L516
	move	$4,$16

	jal	memcmp
	nop

	addiu	$5,$sp,48
	li	$6,6			# 0x6
	bne	$2,$0,$L525
	move	$4,$16

$L516:
	lui	$2,%hi($LC28)
	addiu	$6,$2,%lo($LC28)
$L528:
	lwl	$5,3($6)
	lui	$3,%hi(jiffies)
	lw	$4,%lo(jiffies)($3)
	lwr	$5,%lo($LC28)($2)
	lbu	$3,4($6)
	sw	$5,56($sp)
	jal	srandom32
	sb	$3,60($sp)

	move	$4,$16
	addiu	$5,$sp,56
	jal	memcpy
	li	$6,5			# 0x5

	jal	random32
	nop

	sb	$2,31($sp)
$L515:
	lw	$4,356($17)
	lbu	$6,285($17)
	jal	memcpy
	move	$5,$16

	lw	$3,72($17)
	andi	$3,$3,0x1
	beq	$3,$0,$L526
	move	$4,$16

	jal	ether_setup
	move	$4,$17

	jal	setup_statistics
	move	$4,$18

	lw	$31,84($sp)
	lw	$18,80($sp)
	lw	$17,76($sp)
	lw	$16,72($sp)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,88

$L526:
	jal	ra2880MacAddressSet
	nop

	jal	ether_setup
	move	$4,$17

	jal	setup_statistics
	move	$4,$18

	lw	$31,84($sp)
	lw	$18,80($sp)
	lw	$17,76($sp)
	lw	$16,72($sp)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,88

$L525:
	jal	memcmp
	nop

	bne	$2,$0,$L515
	lui	$2,%hi($LC28)

	j	$L528
	addiu	$6,$2,%lo($LC28)

	.set	macro
	.set	reorder
	.end	rather_probe
	.section	.text.ei_xmit_housekeeping,"ax",@progbits
	.align	2
	.globl	ei_xmit_housekeeping
	.ent	ei_xmit_housekeeping
	.type	ei_xmit_housekeeping, @function
ei_xmit_housekeeping:
	.frame	$sp,48,$31		# vars= 0, regs= 7/0, args= 16, gp= 0
	.mask	0x803f0000,-8
	.fmask	0x00000000,0
	addiu	$sp,$sp,-48
	sw	$18,24($sp)
	sw	$31,40($sp)
	sw	$21,36($sp)
	sw	$20,32($sp)
	sw	$19,28($sp)
	sw	$17,20($sp)
	sw	$16,16($sp)
	lui	$2,%hi(dev_raether)
	lw	$20,%lo(dev_raether)($2)
	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$2,$2,0x80c
	addiu	$18,$20,800
	lw	$17,1124($18)
	lw	$3,0($2)
	sll	$2,$17,2
	addu	$4,$2,$18
	lw	$2,100($4)
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L531
	lw	$19,1220($18)
	.set	macro
	.set	reorder

	sll	$2,$17,4
	addu	$2,$2,$19
	lw	$3,4($2)
	.set	noreorder
	.set	nomacro
	bltz	$3,$L548
	move	$16,$4
	.set	macro
	.set	reorder

$L531:
	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$2,$2,0xa28
	lw	$3,0($2)
	lw	$31,40($sp)
	lw	$21,36($sp)
	lw	$20,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	li	$4,268435456			# 0x10000000
	or	$3,$3,$4
	addiu	$sp,$sp,48
	sw	$3,0($2)
	j	$31
$L548:
	li	$21,1			# 0x1
$L534:
	.set	noreorder
	.set	nomacro
	jal	dev_kfree_skb_any
	lw	$4,100($16)
	.set	macro
	.set	reorder

	addiu	$2,$17,1
	andi	$17,$2,0xff
	sll	$3,$17,4
	sll	$2,$17,2
	sw	$0,100($16)
	addu	$3,$3,$19
	addu	$16,$2,$18
	lw	$2,4($3)
	srl	$2,$2,31
	bne	$2,$21,$L533
	lw	$2,100($16)
	bne	$2,$0,$L534
$L533:
	lw	$6,464($20)
#APP
			

#NO_APP
	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L541
#APP
	1:	ll	$2, 8($6)		# test_and_clear_bit	
	ext    $5, $2, 0, 1				
	ins    $2, $0, 0, 1				
	sc	$2, 8($6)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					

#NO_APP
$L538:
#APP
			

#NO_APP
	.set	noreorder
	.set	nomacro
	bne	$5,$0,$L549
	lui	$2,%hi(tx_ring_full)
	.set	macro
	.set	reorder

	sw	$0,%lo(tx_ring_full)($2)
	sw	$17,1124($18)
$L550:
	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$2,$2,0xa28
	lw	$3,0($2)
	lw	$31,40($sp)
	lw	$21,36($sp)
	lw	$20,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	li	$4,268435456			# 0x10000000
	or	$3,$3,$4
	addiu	$sp,$sp,48
	sw	$3,0($2)
	j	$31
$L549:
	.set	noreorder
	.set	nomacro
	jal	__netif_schedule
	lw	$4,4($6)
	.set	macro
	.set	reorder

	lui	$2,%hi(tx_ring_full)
	sw	$0,%lo(tx_ring_full)($2)
	.set	noreorder
	.set	nomacro
	j	$L550
	sw	$17,1124($18)
	.set	macro
	.set	reorder

$L541:
#APP
	raw_local_irq_save	$4
#NO_APP
	lw	$5,8($6)
	lw	$2,8($6)
	li	$3,-2			# 0xfffffffffffffffe
	andi	$5,$5,0x1
	and	$2,$2,$3
	sw	$2,8($6)
#APP
	raw_local_irq_restore	$4
#NO_APP
	j	$L538
	.end	ei_xmit_housekeeping
	.section	.text.ei_interrupt,"ax",@progbits
	.align	2
	.ent	ei_interrupt
	.type	ei_interrupt, @function
ei_interrupt:
	.frame	$sp,40,$31		# vars= 0, regs= 5/0, args= 16, gp= 0
	.mask	0x800f0000,-8
	.fmask	0x00000000,0
	addiu	$sp,$sp,-40
	sw	$17,20($sp)
	sw	$31,32($sp)
	sw	$19,28($sp)
	sw	$18,24($sp)
	sw	$16,16($sp)
	move	$17,$5
	.set	noreorder
	.set	nomacro
	beq	$5,$0,$L551
	move	$2,$0
	.set	macro
	.set	reorder

#APP
	raw_local_irq_save	$18
#NO_APP
	li	$19,-1341128704			# 0xffffffffb0100000
	ori	$5,$19,0xa20
	lw	$3,0($5)
	li	$2,1342177280			# 0x50000000
	move	$4,$0
	srl	$3,$3,30
	sw	$2,0($5)
	.set	noreorder
	.set	nomacro
	jal	ei_xmit_housekeeping
	andi	$16,$3,0x1
	.set	macro
	.set	reorder

	li	$4,1			# 0x1
	.set	noreorder
	.set	nomacro
	beq	$16,$4,$L566
	li	$6,1			# 0x1
	.set	macro
	.set	reorder

	lui	$2,%hi(pending_recv)
	lw	$3,%lo(pending_recv)($2)
	.set	noreorder
	.set	nomacro
	beq	$3,$4,$L592
	lui	$2,%hi(tx_ring_full)
	.set	macro
	.set	reorder

	li	$2,1			# 0x1
$L593:
	.set	noreorder
	.set	nomacro
	beq	$16,$2,$L590
	lui	$2,%hi(tx_ring_full)
	.set	macro
	.set	reorder

$L575:
#APP
	raw_local_irq_restore	$18
#NO_APP
	li	$2,1			# 0x1
$L551:
	lw	$31,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,40
	.set	macro
	.set	reorder

$L566:
	lui	$2,%hi(tx_ring_full)
$L592:
	lw	$3,%lo(tx_ring_full)($2)
	.set	noreorder
	.set	nomacro
	bne	$3,$0,$L593
	li	$2,1			# 0x1
	.set	macro
	.set	reorder

	ori	$4,$19,0xa28
	lw	$3,0($4)
	li	$2,-1073807360			# 0xffffffffbfff0000
	ori	$2,$2,0xffff
	and	$3,$3,$2
	lui	$2,%hi(pending_recv)
	sw	$3,0($4)
	addiu	$5,$17,860
	sw	$0,%lo(pending_recv)($2)
#APP
			

#NO_APP
	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	bne	$2,$0,$L591
#APP
	raw_local_irq_save	$2
#NO_APP
	lw	$4,864($17)
	lw	$3,864($17)
	andi	$4,$4,0x1
	ori	$3,$3,0x1
	sw	$3,864($17)
#APP
	raw_local_irq_restore	$2
#NO_APP
$L569:
#APP
			

#NO_APP
	bne	$4,$0,$L575
	.set	noreorder
	.set	nomacro
	jal	__tasklet_hi_schedule
	move	$4,$5
	.set	macro
	.set	reorder

	j	$L575
$L590:
	lw	$3,%lo(tx_ring_full)($2)
	.set	noreorder
	.set	nomacro
	bne	$3,$16,$L575
	lui	$2,%hi(pending_recv)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L575
	sw	$3,%lo(pending_recv)($2)
	.set	macro
	.set	reorder

$L591:
#APP
		.set	push					
	.set	noreorder				
	.set	mips3					
1:	ll	$2, 864($17)		# test_and_set_bit	
	or	$4, $2, $6				
	sc	$4, 864($17)					
	beqz	$4, 2f					
	 and	$4, $2, $6				
	.subsection 2					
2:	b	1b					
	 nop						
	.previous					
	.set	pop					

#NO_APP
	j	$L569
	.end	ei_interrupt
	.section	.text.ei_close,"ax",@progbits
	.align	2
	.globl	ei_close
	.ent	ei_close
	.type	ei_close, @function
ei_close:
	.frame	$sp,40,$31		# vars= 0, regs= 5/0, args= 16, gp= 0
	.mask	0x800f0000,-8
	.fmask	0x00000000,0
	addiu	$sp,$sp,-40
	sw	$18,24($sp)
	sw	$17,20($sp)
	sw	$31,32($sp)
	sw	$19,28($sp)
	sw	$16,16($sp)
	move	$17,$4
	addiu	$18,$4,800
#APP
	raw_local_irq_save	$19
#NO_APP
	.set	noreorder
	.set	nomacro
	jal	cancel_work_sync
	addiu	$4,$4,844
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L609
	lw	$4,464($17)
	.set	macro
	.set	reorder

	li	$2,-1			# 0xffffffffffffffff
#APP
	1:	ll	$3, 8($4)			# set_bit	
	ins    $3, $2, 0, 1				
	sc	$3, 8($4)					
	beqz	$3, 2f					
	.subsection 2					
2:	b	1b					
	.previous					

#NO_APP
$L614:
	.set	noreorder
	.set	nomacro
	jal	ra2880stop
	move	$4,$18
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	msleep
	li	$4,10			# 0xa
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	tasklet_kill
	addiu	$4,$18,80
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	tasklet_kill
	addiu	$4,$18,60
	.set	macro
	.set	reorder

	lw	$4,64($17)
	move	$5,$17
	.set	noreorder
	.set	nomacro
	jal	free_irq
	move	$16,$18
	.set	macro
	.set	reorder

	move	$5,$17
	.set	noreorder
	.set	nomacro
	jal	free_irq
	li	$4,17			# 0x11
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L619
	li	$17,255			# 0xff
	.set	macro
	.set	reorder

$L617:
	.set	noreorder
	.set	nomacro
	bltz	$17,$L647
	addiu	$16,$16,4
	.set	macro
	.set	reorder

$L619:
	lw	$2,1228($16)
	addiu	$17,$17,-1
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L617
	move	$4,$2
	.set	macro
	.set	reorder

	jal	consume_skb
	sw	$0,1228($16)
	.set	noreorder
	.set	nomacro
	bgez	$17,$L619
	addiu	$16,$16,4
	.set	macro
	.set	reorder

$L647:
	lw	$6,1220($18)
	bne	$6,$0,$L648
	lw	$7,20($18)
	lw	$6,1224($18)
	move	$4,$0
	.set	noreorder
	.set	nomacro
	jal	dma_free_coherent
	li	$5,4096			# 0x1000
	.set	macro
	.set	reorder

	jal	fe_reset
#APP
	raw_local_irq_restore	$19
#NO_APP
	.set	noreorder
	.set	nomacro
	jal	module_put
	move	$4,$0
	.set	macro
	.set	reorder

	lw	$31,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	move	$2,$0
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,40
	.set	macro
	.set	reorder

$L609:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,8($4)
	ori	$2,$2,0x1
	sw	$2,8($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	j	$L614
$L648:
	lw	$7,16($18)
	move	$4,$0
	.set	noreorder
	.set	nomacro
	jal	dma_free_coherent
	li	$5,4096			# 0x1000
	.set	macro
	.set	reorder

	lw	$7,20($18)
	lw	$6,1224($18)
	move	$4,$0
	.set	noreorder
	.set	nomacro
	jal	dma_free_coherent
	li	$5,4096			# 0x1000
	.set	macro
	.set	reorder

	jal	fe_reset
#APP
	raw_local_irq_restore	$19
#NO_APP
	.set	noreorder
	.set	nomacro
	jal	module_put
	move	$4,$0
	.set	macro
	.set	reorder

	lw	$31,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	move	$2,$0
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,40
	.set	macro
	.set	reorder

	.end	ei_close
	.section	.text.rt_gsw_init,"ax",@progbits
	.align	2
	.globl	rt_gsw_init
	.ent	rt_gsw_init
	.type	rt_gsw_init, @function
rt_gsw_init:
	.frame	$sp,24,$31		# vars= 0, regs= 2/0, args= 16, gp= 0
	.mask	0x80010000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-24
	li	$3,-1342177280			# 0xffffffffb0000000
	sw	$16,16($sp)
	sw	$31,20($sp)
	ori	$4,$3,0xc
	ori	$3,$3,0x14
	lw	$2,0($3)
	lw	$7,0($4)
	li	$5,31			# 0x1f
	ori	$2,$2,0x100
	li	$4,1			# 0x1
	srl	$7,$7,16
	li	$6,16384			# 0x4000
	sw	$2,0($3)
	jal	mii_mgr_write
	andi	$16,$7,0x1

	li	$4,1			# 0x1
	li	$5,17			# 0x11
	jal	mii_mgr_write
	li	$6,29764			# 0x7444

	beq	$16,$0,$L650
	li	$4,1			# 0x1

	li	$5,19			# 0x13
	li	$6,276			# 0x114
$L654:
	jal	mii_mgr_write
	nop

	li	$4,1			# 0x1
	li	$5,22			# 0x16
	jal	mii_mgr_write
	li	$6,4303			# 0x10cf

	li	$4,1			# 0x1
	li	$5,25			# 0x19
	jal	mii_mgr_write
	li	$6,25106			# 0x6212

	li	$4,1			# 0x1
	li	$5,26			# 0x1a
	jal	mii_mgr_write
	li	$6,1911			# 0x777

	li	$4,1			# 0x1
	li	$5,29			# 0x1d
	jal	mii_mgr_write
	li	$6,16384			# 0x4000

	li	$4,1			# 0x1
	li	$5,28			# 0x1c
	jal	mii_mgr_write
	li	$6,49271			# 0xc077

	li	$4,1			# 0x1
	li	$5,24			# 0x18
	jal	mii_mgr_write
	move	$6,$0

	li	$4,1			# 0x1
	li	$5,31			# 0x1f
	jal	mii_mgr_write
	li	$6,12288			# 0x3000

	li	$4,1			# 0x1
	li	$5,17			# 0x11
	jal	mii_mgr_write
	li	$6,18488			# 0x4838

	li	$4,1			# 0x1
	li	$5,31			# 0x1f
	jal	mii_mgr_write
	li	$6,8192			# 0x2000

	beq	$16,$0,$L652
	li	$4,1			# 0x1

	li	$5,21			# 0x15
	jal	mii_mgr_write
	li	$6,1301			# 0x515

	li	$4,1			# 0x1
	li	$5,22			# 0x16
	jal	mii_mgr_write
	li	$6,83			# 0x53

	li	$4,1			# 0x1
	li	$5,23			# 0x17
	jal	mii_mgr_write
	li	$6,191			# 0xbf

	li	$4,1			# 0x1
	li	$5,24			# 0x18
	jal	mii_mgr_write
	li	$6,2735			# 0xaaf

	li	$4,1			# 0x1
	li	$5,25			# 0x19
	jal	mii_mgr_write
	li	$6,4013			# 0xfad

	li	$4,1			# 0x1
	li	$5,26			# 0x1a
	li	$6,4033			# 0xfc1
$L655:
	jal	mii_mgr_write
	nop

	li	$4,1			# 0x1
	li	$5,31			# 0x1f
	jal	mii_mgr_write
	li	$6,4096			# 0x1000

	li	$4,1			# 0x1
	li	$5,17			# 0x11
	jal	mii_mgr_write
	li	$6,59384			# 0xe7f8

	li	$4,1			# 0x1
	li	$5,31			# 0x1f
	jal	mii_mgr_write
	li	$6,32768			# 0x8000

	move	$4,$0
	li	$5,30			# 0x1e
	jal	mii_mgr_write
	li	$6,40960			# 0xa000

	li	$4,1			# 0x1
	li	$5,30			# 0x1e
	jal	mii_mgr_write
	li	$6,40960			# 0xa000

	li	$4,2			# 0x2
	li	$5,30			# 0x1e
	jal	mii_mgr_write
	li	$6,40960			# 0xa000

	li	$4,3			# 0x3
	li	$5,30			# 0x1e
	jal	mii_mgr_write
	li	$6,40960			# 0xa000

	li	$4,4			# 0x4
	li	$5,30			# 0x1e
	jal	mii_mgr_write
	li	$6,40960			# 0xa000

	move	$4,$0
	li	$5,4			# 0x4
	jal	mii_mgr_write
	li	$6,1505			# 0x5e1

	li	$4,1			# 0x1
	li	$5,4			# 0x4
	jal	mii_mgr_write
	li	$6,1505			# 0x5e1

	li	$4,2			# 0x2
	li	$5,4			# 0x4
	jal	mii_mgr_write
	li	$6,1505			# 0x5e1

	li	$4,3			# 0x3
	li	$5,4			# 0x4
	jal	mii_mgr_write
	li	$6,1505			# 0x5e1

	li	$4,4			# 0x4
	li	$5,4			# 0x4
	jal	mii_mgr_write
	li	$6,1505			# 0x5e1

	li	$4,1			# 0x1
	li	$5,31			# 0x1f
	jal	mii_mgr_write
	li	$6,40960			# 0xa000

	move	$4,$0
	li	$5,16			# 0x10
	jal	mii_mgr_write
	li	$6,4369			# 0x1111

	li	$4,1			# 0x1
	li	$5,16			# 0x10
	jal	mii_mgr_write
	li	$6,4112			# 0x1010

	li	$4,2			# 0x2
	li	$5,16			# 0x10
	jal	mii_mgr_write
	li	$6,5397			# 0x1515

	li	$4,3			# 0x3
	li	$5,16			# 0x10
	jal	mii_mgr_write
	li	$6,3855			# 0xf0f

	li	$4,4			# 0x4
	li	$5,16			# 0x10
	jal	mii_mgr_write
	li	$6,4883			# 0x1313

	li	$5,-1342177280			# 0xffffffffb0000000
	ori	$9,$5,0x14
	ori	$5,$5,0x60
	lw	$8,0($5)
	lw	$6,0($9)
	li	$4,-1341063168			# 0xffffffffb0110000
	li	$2,327680			# 0x50000
	lw	$31,20($sp)
	lw	$16,16($sp)
	ori	$7,$4,0x3600
	ori	$2,$2,0xe33b
	li	$3,2139029504			# 0x7f7f0000
	sw	$2,0($7)
	ori	$10,$4,0x3500
	ori	$6,$6,0xc000
	ori	$8,$8,0x600
	ori	$4,$4,0x10
	ori	$3,$3,0x7fe0
	li	$2,32768			# 0x8000
	addiu	$sp,$sp,24
	sw	$3,0($4)
	sw	$2,0($10)
	sw	$6,0($9)
	j	$31
	sw	$8,0($5)

$L650:
	li	$5,19			# 0x13
	j	$L654
	li	$6,279			# 0x117

$L652:
	li	$5,21			# 0x15
	jal	mii_mgr_write
	li	$6,1303			# 0x517

	li	$4,1			# 0x1
	li	$5,22			# 0x16
	jal	mii_mgr_write
	li	$6,4050			# 0xfd2

	li	$4,1			# 0x1
	li	$5,23			# 0x17
	jal	mii_mgr_write
	li	$6,191			# 0xbf

	li	$4,1			# 0x1
	li	$5,24			# 0x18
	jal	mii_mgr_write
	li	$6,2731			# 0xaab

	li	$4,1			# 0x1
	li	$5,25			# 0x19
	jal	mii_mgr_write
	li	$6,174			# 0xae

	li	$4,1			# 0x1
	li	$5,26			# 0x1a
	j	$L655
	li	$6,4095			# 0xfff

	.set	macro
	.set	reorder
	.end	rt_gsw_init
	.section	.text.fe_sw_init,"ax",@progbits
	.align	2
	.globl	fe_sw_init
	.ent	fe_sw_init
	.type	fe_sw_init, @function
fe_sw_init:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	j	rt_gsw_init
	nop

	.set	macro
	.set	reorder
	.end	fe_sw_init
	.rdata
	.align	2
	.type	__func__.0, @object
	.size	__func__.0, 8
__func__.0:
	.ascii	"ei_open\000"
	.section	.rodata.str1.4
	.align	2
$LC43:
	.ascii	"Ralink_ESW\000"
	.align	2
$LC44:
	.ascii	"eth2\000"
	.align	2
$LC46:
	.ascii	"127.0.0.1\000"
	.section	.text.ei_open,"ax",@progbits
	.align	2
	.globl	ei_open
	.ent	ei_open
	.type	ei_open, @function
ei_open:
	.frame	$sp,72,$31		# vars= 24, regs= 6/0, args= 24, gp= 0
	.mask	0x801f0000,-4
	.fmask	0x00000000,0
$L679:
	addiu	$sp,$sp,-72
	sw	$18,56($sp)
	addiu	$18,$4,800
	sw	$19,60($sp)
	sw	$31,68($sp)
	sw	$20,64($sp)
	sw	$17,52($sp)
	sw	$16,48($sp)
	move	$19,$4
	.set	noreorder
	.set	nomacro
	beq	$18,$0,$L657
	li	$3,-6			# 0xfffffffffffffffa
	.set	macro
	.set	reorder

	addiu	$16,$4,2028
	li	$17,255			# 0xff
$L701:
	.set	noreorder
	.set	nomacro
	jal	skbmgr_alloc_skb2k
	addiu	$17,$17,-1
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L695
	move	$4,$2
	.set	macro
	.set	reorder

	lw	$2,172($2)
	lw	$3,160($4)
	addiu	$2,$2,80
	addiu	$3,$3,80
	sw	$2,172($4)
	sw	$3,160($4)
$L695:
	sw	$4,0($16)
	.set	noreorder
	.set	nomacro
	bgez	$17,$L701
	addiu	$16,$16,4
	.set	macro
	.set	reorder

#APP
	raw_local_irq_save	$20
#NO_APP
	lw	$4,64($19)
	lui	$5,%hi(ei_interrupt)
	addiu	$5,$5,%lo(ei_interrupt)
	move	$6,$0
	li	$7,32			# 0x20
	sw	$19,16($sp)
	.set	noreorder
	.set	nomacro
	jal	request_threaded_irq
	sw	$19,20($sp)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L657
	move	$3,$2
	.set	macro
	.set	reorder

	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$4,$2,0xa04
$L807:
	lw	$10,0($4)
	srl	$2,$10,3
	srl	$3,$10,1
	andi	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L807
	andi	$3,$3,0x1
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$3,$0,$L807
	addiu	$2,$18,100
	.set	macro
	.set	reorder

	li	$17,255			# 0xff
$L722:
	addiu	$17,$17,-1
	sw	$0,0($2)
	.set	noreorder
	.set	nomacro
	bgez	$17,$L722
	addiu	$2,$2,4
	.set	macro
	.set	reorder

	sw	$0,1124($18)
	move	$4,$0
	li	$5,4096			# 0x1000
	addiu	$6,$18,16
	.set	noreorder
	.set	nomacro
	jal	dma_alloc_coherent
	li	$7,32			# 0x20
	.set	macro
	.set	reorder

	move	$17,$0
	.set	noreorder
	.set	nomacro
	j	$L732
	sw	$2,1220($18)
	.set	macro
	.set	reorder

$L802:
	lw	$2,1220($18)
$L732:
	sll	$16,$17,4
	addu	$4,$2,$16
	move	$5,$0
	.set	noreorder
	.set	nomacro
	jal	memset
	li	$6,16			# 0x10
	.set	macro
	.set	reorder

	lw	$4,1220($18)
	li	$3,1073741824			# 0x40000000
	addiu	$17,$17,1
	addu	$4,$16,$4
	lw	$2,4($4)
	slt	$5,$17,256
	or	$2,$2,$3
	sw	$2,4($4)
	lw	$3,1220($18)
	addu	$16,$16,$3
	lw	$2,4($16)
	li	$3,-2147483648			# 0xffffffff80000000
	or	$2,$2,$3
	.set	noreorder
	.set	nomacro
	bne	$5,$0,$L802
	sw	$2,4($16)
	.set	macro
	.set	reorder

	move	$4,$0
	li	$5,4096			# 0x1000
	addiu	$6,$18,20
	.set	noreorder
	.set	nomacro
	jal	dma_alloc_coherent
	li	$7,32			# 0x20
	.set	macro
	.set	reorder

	move	$17,$0
	.set	noreorder
	.set	nomacro
	j	$L741
	sw	$2,1224($18)
	.set	macro
	.set	reorder

$L803:
	lw	$2,1224($18)
$L741:
	sll	$16,$17,4
	addu	$4,$2,$16
	move	$5,$0
	.set	noreorder
	.set	nomacro
	jal	memset
	li	$6,16			# 0x10
	.set	macro
	.set	reorder

	lw	$4,1224($18)
	li	$2,2147418112			# 0x7fff0000
	ori	$2,$2,0xffff
	addu	$4,$16,$4
	lw	$3,4($4)
	sll	$8,$17,2
	addu	$8,$8,$18
	and	$3,$3,$2
	sw	$3,4($4)
	lw	$5,1224($18)
	li	$2,-1073807360			# 0xffffffffbfff0000
	ori	$2,$2,0xffff
	addu	$5,$16,$5
	lw	$3,4($5)
	addiu	$17,$17,1
	move	$4,$0
	and	$3,$3,$2
	sw	$3,4($5)
	lw	$7,1224($18)
	li	$2,-1073741824			# 0xffffffffc0000000
	ori	$2,$2,0xffff
	addu	$7,$16,$7
	lw	$5,4($7)
	li	$3,100663296			# 0x6000000
	li	$6,1536			# 0x600
	and	$5,$5,$2
	or	$5,$5,$3
	sw	$5,4($7)
	lw	$2,1228($8)
	lw	$3,1224($18)
	li	$7,2			# 0x2
	lw	$5,172($2)
	.set	noreorder
	.set	nomacro
	jal	dma_map_single
	addu	$16,$16,$3
	.set	macro
	.set	reorder

	slt	$3,$17,256
	.set	noreorder
	.set	nomacro
	bne	$3,$0,$L803
	sw	$2,0($16)
	.set	macro
	.set	reorder

	li	$16,-1341128704			# 0xffffffffb0100000
	ori	$2,$16,0xa04
	lw	$10,0($2)
	li	$5,536805376			# 0x1fff0000
	ori	$5,$5,0xffff
	andi	$10,$10,0xff
	sw	$10,0($2)
	lw	$3,16($18)
	lw	$10,0($2)
	ori	$4,$16,0x800
	and	$3,$3,$5
	lui	$2,%hi(tx_cpu_owner_idx0)
	sw	$3,0($4)
	li	$8,256			# 0x100
	sw	$0,%lo(tx_cpu_owner_idx0)($2)
	ori	$9,$16,0xa08
	ori	$7,$16,0x808
	ori	$6,$16,0x804
	li	$2,1			# 0x1
	sw	$8,0($6)
	sw	$0,0($7)
	sw	$2,0($9)
	lw	$3,20($18)
	ori	$2,$16,0x900
	ori	$6,$16,0x908
	and	$3,$3,$5
	sw	$3,0($2)
	ori	$4,$16,0x904
	li	$2,255			# 0xff
	sw	$8,0($4)
	sw	$2,0($6)
	lw	$4,0($6)
	li	$3,65536			# 0x10000
	lui	$2,%hi(rx_calc_idx0)
	sw	$4,%lo(rx_calc_idx0)($2)
	sw	$3,0($9)
	lui	$2,%hi(rx_dma_owner_idx0)
	.set	noreorder
	.set	nomacro
	jal	set_fe_pdma_glo_cfg
	sw	$4,%lo(rx_dma_owner_idx0)($2)
	.set	macro
	.set	reorder

	jal	fe_sw_init
	lw	$4,356($19)
	bne	$4,$0,$L808
	li	$2,-1342177280			# 0xffffffffb0000000
$L810:
	li	$4,131072			# 0x20000
	ori	$2,$2,0x234
	li	$3,-1341063168			# 0xffffffffb0110000
	sw	$4,0($2)
	ori	$3,$3,0x7008
	lw	$4,0($3)
	li	$2,-65536			# 0xffffffffffff0000
	ori	$2,$2,0x7fc0
	and	$4,$4,$2
	lui	$2,%hi(kill_sig_workq)
	addiu	$5,$18,32
	addiu	$2,$2,%lo(kill_sig_workq)
	li	$17,512			# 0x200
	sw	$4,0($3)
	sw	$17,28($18)
	sw	$5,32($18)
	sw	$5,4($5)
	sw	$2,40($18)
	lui	$5,%hi(esw_interrupt)
	lui	$2,%hi($LC43)
	addiu	$2,$2,%lo($LC43)
	addiu	$5,$5,%lo(esw_interrupt)
	li	$4,17			# 0x11
	move	$6,$0
	li	$7,32			# 0x20
	sw	$2,16($sp)
	.set	noreorder
	.set	nomacro
	jal	request_threaded_irq
	sw	$19,20($sp)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L657
	move	$3,$2
	.set	macro
	.set	reorder

	li	$2,-2080112640			# 0xffffffff84040000
	ori	$5,$16,0xa0c
	ori	$2,$2,0x8404
	sw	$2,0($5)
	lui	$2,%hi(ei_reset_task)
	addiu	$4,$18,48
	li	$3,1342177280			# 0x50000000
	addiu	$2,$2,%lo(ei_reset_task)
	ori	$6,$16,0xa28
	lui	$5,%hi(ei_receive)
	sw	$3,0($6)
	addiu	$5,$5,%lo(ei_receive)
	sw	$17,44($18)
	sw	$4,48($18)
	sw	$4,4($4)
	move	$6,$0
	sw	$2,56($18)
	.set	noreorder
	.set	nomacro
	jal	tasklet_init
	addiu	$4,$18,60
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L764
	lw	$5,464($19)
	.set	macro
	.set	reorder

#APP
	1:	ll	$2, 8($5)			# clear_bit	
	ins    $2, $0, 0, 1				
	sc	$2, 8($5)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					

#NO_APP
$L769:
#APP
	raw_local_irq_restore	$20
#NO_APP
	.set	noreorder
	.set	nomacro
	jal	forward_config
	move	$4,$19
	.set	macro
	.set	reorder

	lui	$3,%hi($LC44)
	addiu	$3,$3,%lo($LC44)
#APP
	.set	noreorder
	.set	noat
	lbu	$2,($19)
1:	lbu	$1,($3)
	addiu	$19,1
	bne	$1,$2,2f
	addiu	$3,1
	bnez	$2,1b
	lbu	$2,($19)
	move	$2,$1
2:	subu	$2,$1
3:	.set	at
	.set	reorder
#NO_APP
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L809
	lui	$16,%hi(clientsocket)
	.set	macro
	.set	reorder

$L783:
	move	$3,$0
$L657:
	lw	$31,68($sp)
	lw	$20,64($sp)
	lw	$19,60($sp)
	lw	$18,56($sp)
	lw	$17,52($sp)
	lw	$16,48($sp)
	move	$2,$3
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,72
	.set	macro
	.set	reorder

$L809:
	li	$4,2			# 0x2
	li	$5,2			# 0x2
	li	$6,6			# 0x6
	.set	noreorder
	.set	nomacro
	jal	sock_create
	addiu	$7,$16,%lo(clientsocket)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bltz	$2,$L783
	li	$2,2
	.set	macro
	.set	reorder

	lui	$4,%hi($LC46)
	addiu	$4,$4,%lo($LC46)
	.set	noreorder
	.set	nomacro
	jal	in_aton
	sh	$2,32($sp)
	.set	macro
	.set	reorder

	lw	$4,%lo(clientsocket)($16)
	sw	$2,36($sp)
	li	$2,-32513
	sh	$2,34($sp)
	lw	$3,24($4)
	addiu	$5,$sp,32
	li	$6,16			# 0x10
	lw	$2,16($3)
	.set	noreorder
	.set	nomacro
	jal	$2
	move	$7,$0
	.set	macro
	.set	reorder

	bgez	$2,$L783
	.set	noreorder
	.set	nomacro
	jal	sock_release
	lw	$4,%lo(clientsocket)($16)
	.set	macro
	.set	reorder

	move	$3,$0
	.set	noreorder
	.set	nomacro
	j	$L657
	sw	$0,%lo(clientsocket)($16)
	.set	macro
	.set	reorder

$L808:
	jal	ra2880MacAddressSet
	.set	noreorder
	.set	nomacro
	j	$L810
	li	$2,-1342177280			# 0xffffffffb0000000
	.set	macro
	.set	reorder

$L764:
#APP
	raw_local_irq_save	$2
#NO_APP
	lw	$3,8($5)
	li	$4,-2			# 0xfffffffffffffffe
	and	$3,$3,$4
	sw	$3,8($5)
#APP
	raw_local_irq_restore	$2
#NO_APP
	j	$L769
	.end	ei_open
	.section	.text.ei_reset_task,"ax",@progbits
	.align	2
	.globl	ei_reset_task
	.ent	ei_reset_task
	.type	ei_reset_task, @function
ei_reset_task:
	.frame	$sp,24,$31		# vars= 0, regs= 2/0, args= 16, gp= 0
	.mask	0x80010000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-24
	sw	$31,20($sp)
	sw	$16,16($sp)
	lui	$2,%hi(dev_raether)
	lw	$16,%lo(dev_raether)($2)
	jal	ei_close
	move	$4,$16

	move	$4,$16
	lw	$31,20($sp)
	lw	$16,16($sp)
	j	ei_open
	addiu	$sp,$sp,24

	.set	macro
	.set	reorder
	.end	ei_reset_task
	.section	.init.text
	.align	2
	.globl	ra2882eth_init
	.ent	ra2882eth_init
	.type	ra2882eth_init, @function
ra2882eth_init:
	.frame	$sp,32,$31		# vars= 0, regs= 4/0, args= 16, gp= 0
	.mask	0x80070000,-4
	.fmask	0x00000000,0
	addiu	$sp,$sp,-32
	li	$4,2252			# 0x8cc
	li	$5,1			# 0x1
	sw	$17,20($sp)
	sw	$16,16($sp)
	sw	$31,28($sp)
	.set	noreorder
	.set	nomacro
	jal	alloc_etherdev_mq
	sw	$18,24($sp)
	.set	macro
	.set	reorder

	move	$17,$2
	lui	$2,%hi($LC44)
	addiu	$2,$2,%lo($LC44)
	.set	noreorder
	.set	nomacro
	beq	$17,$0,$L812
	li	$16,-12			# 0xfffffffffffffff4
	.set	macro
	.set	reorder

	move	$3,$17
#APP
	.set	noreorder
	.set	noat
1:	lbu	$1,($2)
	addiu	$2,1
	sb	$1,($3)
	bnez	$1,1b
	addiu	$3,1
	.set	at
	.set	reorder
#NO_APP
	li	$2,3			# 0x3
	li	$3,6
	sw	$2,64($17)
	li	$2,-1341128704			# 0xffffffffb0100000
	sb	$3,285($17)
	move	$4,$17
	.set	noreorder
	.set	nomacro
	jal	rather_probe
	sw	$2,60($17)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	ra2880_setup_dev_fptable
	move	$4,$17
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	ethtool_init
	move	$4,$17
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	jal	register_netdev
	move	$4,$17
	.set	macro
	.set	reorder

	lui	$18,%hi(wan_detect)
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L812
	li	$16,-6			# 0xfffffffffffffffa
	.set	macro
	.set	reorder

	jal	debug_proc_init
	move	$16,$2
	li	$2,-1341063168			# 0xffffffffb0110000
	addiu	$2,$2,1024
	lw	$3,12296($2)
	addiu	$4,$18,%lo(wan_detect)
	lui	$2,%hi(wan_port_status)
	andi	$3,$3,0x1
	move	$5,$0
	move	$6,$0
	.set	noreorder
	.set	nomacro
	jal	init_timer_key
	sw	$3,%lo(wan_port_status)($2)
	.set	macro
	.set	reorder

	lui	$2,%hi(wan_detect_timer)
	addiu	$4,$18,%lo(wan_detect)
	addiu	$2,$2,%lo(wan_detect_timer)
	lui	$3,%hi(dev_raether)
	sw	$2,16($4)
	sw	$17,%lo(dev_raether)($3)
	sw	$0,20($4)
$L812:
	move	$2,$16
	lw	$31,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,32
	.set	macro
	.set	reorder

	.end	ra2882eth_init
	.section	.text.ra2882eth_cleanup_module,"ax",@progbits
	.align	2
	.globl	ra2882eth_cleanup_module
	.ent	ra2882eth_cleanup_module
	.type	ra2882eth_cleanup_module, @function
ra2882eth_cleanup_module:
	.frame	$sp,24,$31		# vars= 0, regs= 2/0, args= 16, gp= 0
	.mask	0x80010000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-24
	lui	$2,%hi(dev_raether)
	sw	$16,16($sp)
	lw	$16,%lo(dev_raether)($2)
	sw	$31,20($sp)
	jal	unregister_netdev
	move	$4,$16

	jal	free_netdev
	move	$4,$16

	lw	$31,20($sp)
	lw	$16,16($sp)
	j	debug_proc_exit
	addiu	$sp,$sp,24

	.set	macro
	.set	reorder
	.end	ra2882eth_cleanup_module
	.globl	dev_raether
	.section	.bss
	.align	2
	.type	dev_raether, @object
	.size	dev_raether, 4
dev_raether:
	.space	4
	.local	rx_dma_owner_idx
	.comm	rx_dma_owner_idx,4,4
	.local	rx_dma_owner_idx0
	.comm	rx_dma_owner_idx0,4,4
	.local	rx_calc_idx0
	.comm	rx_calc_idx0,4,4
	.local	pending_recv
	.comm	pending_recv,4,4
	.local	rx_ring
	.comm	rx_ring,4,4
	.local	wan_detect
	.comm	wan_detect,28,4
	.globl	wan_port_status
	.align	2
	.type	wan_port_status, @object
	.size	wan_port_status, 4
wan_port_status:
	.space	4
	.ident	"GCC: (GNU) 3.4.2"
