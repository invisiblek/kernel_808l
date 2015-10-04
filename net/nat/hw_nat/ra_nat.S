	.file	1 "ra_nat.c"
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

	.globl	init_module
	init_module = PpeInitMod
	.globl	cleanup_module
	cleanup_module = PpeCleanupMod
#NO_APP
	.section	.modinfo,"a",@progbits
	.align	2
	.type	__mod_description3151, @object
	.size	__mod_description3151, 39
__mod_description3151:
	.ascii	"description=Ralink Hardware NAT v2.50\n\000"
	.align	2
	.type	__mod_license3150, @object
	.size	__mod_license3150, 20
__mod_license3150:
	.ascii	"license=Proprietary\000"
	.align	2
	.type	__mod_author3149, @object
	.size	__mod_author3149, 28
__mod_author3149:
	.ascii	"author=Steven Liu/Kurtis Ke\000"
	.globl	update_foe_ts_timer
	.data
	.align	2
	.type	update_foe_ts_timer, @object
	.size	update_foe_ts_timer, 28
update_foe_ts_timer:
	.space	4
	.word	1953723489
	.word	0
	.word	boot_tvec_bases
	.word	update_foe_ts_timer_handler
	.word	0
	.space	4
	.section	.text.RemoveVlanTag,"ax",@progbits
	.align	2
	.globl	RemoveVlanTag
	.ent	RemoveVlanTag
	.type	RemoveVlanTag, @function
RemoveVlanTag:
	.frame	$sp,32,$31		# vars= 0, regs= 4/0, args= 16, gp= 0
	.mask	0x80070000,-4
	.fmask	0x00000000,0
	addiu	$sp,$sp,-32
	sw	$17,20($sp)
	sw	$31,28($sp)
	sw	$18,24($sp)
	sw	$16,16($sp)
	lw	$6,156($4)
	li	$2,129			# 0x81
	move	$17,$4
	lhu	$3,12($6)
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L1
	li	$5,65535			# 0xffff
	.set	macro
	.set	reorder

	lw	$3,96($4)
	lhu	$2,14($6)
	li	$5,32			# 0x20
	andi	$3,$3,0x2
#APP
		wsbh	$2, $2			

#NO_APP
	.set	noreorder
	.set	nomacro
	bne	$3,$0,$L17
	andi	$18,$2,0xffff
	.set	macro
	.set	reorder

$L15:
	lw	$2,180($17)
	xori	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L18
	addiu	$2,$6,4
	.set	macro
	.set	reorder

	lui	$2,%hi(skb_copy)
$L19:
	addiu	$2,$2,%lo(skb_copy)
	jal	$2
	move	$16,$2
	move	$4,$17
	move	$17,$2
	lui	$2,%hi(kfree_skb)
	addiu	$2,$2,%lo(kfree_skb)
	jal	$2
	.set	noreorder
	.set	nomacro
	beq	$16,$0,$L1
	li	$5,65535			# 0xffff
	.set	macro
	.set	reorder

	lw	$6,156($16)
	addiu	$2,$6,4
$L18:
	move	$4,$2
	sw	$2,156($17)
	lui	$2,%hi(memmove)
	move	$5,$6
	sw	$6,172($17)
	addiu	$2,$2,%lo(memmove)
	.set	noreorder
	.set	nomacro
	jal	$2
	li	$6,12			# 0xc
	.set	macro
	.set	reorder

	lui	$2,%hi(skb_pull)
	move	$4,$17
	addiu	$2,$2,%lo(skb_pull)
	.set	noreorder
	.set	nomacro
	jal	$2
	li	$5,4			# 0x4
	.set	macro
	.set	reorder

	lw	$3,172($17)
	lw	$4,156($17)
	move	$5,$18
	addiu	$3,$3,14
	sw	$3,172($17)
	lbu	$2,13($4)
	lbu	$3,12($4)
	sll	$2,$2,8
	or	$2,$2,$3
	sh	$2,98($17)
$L1:
	lw	$31,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	move	$2,$5
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,32
	.set	macro
	.set	reorder

$L17:
	lw	$2,164($17)
	lw	$3,40($2)
	li	$2,1			# 0x1
	andi	$3,$3,0xffff
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L19
	lui	$2,%hi(skb_copy)
	.set	macro
	.set	reorder

	j	$L15
	.end	RemoveVlanTag
	.section	.text.FoeDumpPkt,"ax",@progbits
	.align	2
	.globl	FoeDumpPkt
	.ent	FoeDumpPkt
	.type	FoeDumpPkt, @function
FoeDumpPkt:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	j	$31
	li	$2,1			# 0x1

	.set	macro
	.set	reorder
	.end	FoeDumpPkt
	.section	.text.PpeExtIfRxHandler,"ax",@progbits
	.align	2
	.globl	PpeExtIfRxHandler
	.ent	PpeExtIfRxHandler
	.type	PpeExtIfRxHandler, @function
PpeExtIfRxHandler:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	j	$31
	li	$2,1			# 0x1

	.set	macro
	.set	reorder
	.end	PpeExtIfRxHandler
	.section	.text.PpeExtIfPingPongHandler,"ax",@progbits
	.align	2
	.globl	PpeExtIfPingPongHandler
	.ent	PpeExtIfPingPongHandler
	.type	PpeExtIfPingPongHandler, @function
PpeExtIfPingPongHandler:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	j	$31
	li	$2,1			# 0x1

	.set	macro
	.set	reorder
	.end	PpeExtIfPingPongHandler
	.section	.text.PpeKeepAliveHandler,"ax",@progbits
	.align	2
	.globl	PpeKeepAliveHandler
	.ent	PpeKeepAliveHandler
	.type	PpeKeepAliveHandler, @function
PpeKeepAliveHandler:
	.frame	$sp,48,$31		# vars= 0, regs= 7/0, args= 16, gp= 0
	.mask	0x803f0000,-8
	.fmask	0x00000000,0
	addiu	$sp,$sp,-48
	sw	$31,40($sp)
	sw	$21,36($sp)
	sw	$20,32($sp)
	sw	$19,28($sp)
	sw	$18,24($sp)
	sw	$17,20($sp)
	sw	$16,16($sp)
	lw	$16,172($4)
	lui	$17,%hi(FoeGetMacInfo)
	move	$20,$4
	addiu	$18,$16,-8
	addiu	$16,$16,-14
	addiu	$17,$17,%lo(FoeGetMacInfo)
	move	$4,$16
	move	$21,$5
	move	$5,$18
	lhu	$2,98($20)
#APP
		wsbh	$2, $2			

#NO_APP
	.set	noreorder
	.set	nomacro
	jal	$17
	andi	$19,$2,0xffff
	.set	macro
	.set	reorder

	move	$5,$16
	.set	noreorder
	.set	nomacro
	jal	$17
	move	$4,$18
	.set	macro
	.set	reorder

	li	$2,1
	sb	$2,6($16)
	li	$2,33024			# 0x8100
	move	$6,$0
	move	$7,$0
	.set	noreorder
	.set	nomacro
	beq	$19,$2,$L87
	move	$5,$0
	.set	macro
	.set	reorder

$L36:
	li	$2,2048			# 0x800
	.set	noreorder
	.set	nomacro
	beq	$19,$2,$L88
	li	$2,34525			# 0x86dd
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$19,$2,$L81
	lw	$31,40($sp)
	.set	macro
	.set	reorder

	lw	$21,36($sp)
	lw	$20,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	li	$2,1			# 0x1
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,48
	.set	macro
	.set	reorder

$L88:
	lw	$2,172($20)
	addu	$2,$2,$6
	addu	$2,$2,$7
	addu	$16,$2,$5
	lbu	$3,9($16)
	li	$2,6			# 0x6
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L89
	lui	$2,%hi(FoeToOrgTcpHdr)
	.set	macro
	.set	reorder

	li	$2,17			# 0x11
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L90
	lui	$2,%hi(FoeToOrgUdpHdr)
	.set	macro
	.set	reorder

	lui	$2,%hi(FoeToOrgIpHdr)
$L94:
	move	$4,$21
	addiu	$2,$2,%lo(FoeToOrgIpHdr)
	.set	noreorder
	.set	nomacro
	jal	$2
	move	$5,$16
	.set	macro
	.set	reorder

$L81:
	lw	$2,96($20)
	li	$3,-1793			# 0xfffffffffffff8ff
	lw	$31,40($sp)
	and	$2,$2,$3
	sw	$2,96($20)
	lw	$21,36($sp)
	lw	$20,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	li	$2,1			# 0x1
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,48
	.set	macro
	.set	reorder

$L87:
	lw	$4,172($20)
	lui	$3,%hi(wan_vid)
	lhu	$3,%lo(wan_vid)($3)
	lhu	$2,0($4)
#APP
		wsbh	$2, $2			

#NO_APP
	andi	$2,$2,0xffff
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L91
	li	$6,4			# 0x4
	.set	macro
	.set	reorder

#APP
		wsbh	$2, $3			

#NO_APP
	sh	$2,0($4)
$L93:
	lhu	$2,2($4)
	li	$4,34916			# 0x8864
#APP
		wsbh	$2, $2			

#NO_APP
	andi	$3,$2,0xffff
	.set	noreorder
	.set	nomacro
	beq	$3,$4,$L85
	li	$2,33024			# 0x8100
	.set	macro
	.set	reorder

	beq	$3,$2,$L92
	.set	noreorder
	.set	nomacro
	j	$L36
	move	$19,$3
	.set	macro
	.set	reorder

$L92:
	lw	$3,172($20)
	li	$7,4			# 0x4
	lhu	$2,6($3)
#APP
		wsbh	$2, $2			

#NO_APP
	andi	$2,$2,0xffff
	beq	$2,$4,$L85
	.set	noreorder
	.set	nomacro
	j	$L36
	move	$19,$2
	.set	macro
	.set	reorder

$L85:
	.set	noreorder
	.set	nomacro
	j	$L36
	li	$5,8			# 0x8
	.set	macro
	.set	reorder

$L91:
	lui	$3,%hi(lan_vid)
	lhu	$2,%lo(lan_vid)($3)
#APP
		wsbh	$2, $2			

#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L93
	sh	$2,0($4)
	.set	macro
	.set	reorder

$L89:
	lw	$6,0($16)
	move	$4,$21
	andi	$6,$6,0xf
	sll	$6,$6,2
	addu	$6,$6,$16
	addiu	$2,$2,%lo(FoeToOrgTcpHdr)
	.set	noreorder
	.set	nomacro
	jal	$2
	move	$5,$16
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L94
	lui	$2,%hi(FoeToOrgIpHdr)
	.set	macro
	.set	reorder

$L90:
	lw	$6,0($16)
	move	$4,$21
	andi	$6,$6,0xf
	sll	$6,$6,2
	addu	$6,$6,$16
	addiu	$2,$2,%lo(FoeToOrgUdpHdr)
	.set	noreorder
	.set	nomacro
	jal	$2
	move	$5,$16
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L94
	lui	$2,%hi(FoeToOrgIpHdr)
	.set	macro
	.set	reorder

	.end	PpeKeepAliveHandler
	.section	.text.PpeHitBindForceToCpuHandler,"ax",@progbits
	.align	2
	.globl	PpeHitBindForceToCpuHandler
	.ent	PpeHitBindForceToCpuHandler
	.type	PpeHitBindForceToCpuHandler, @function
PpeHitBindForceToCpuHandler:
	.frame	$sp,24,$31		# vars= 0, regs= 2/0, args= 16, gp= 0
	.mask	0x80010000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-24
	sw	$16,16($sp)
	sw	$31,20($sp)
	lw	$2,0($5)
	move	$16,$4
	srl	$2,$2,25
	andi	$4,$2,0x7
	sltu	$3,$4,2
	beq	$3,$0,$L96
	li	$2,3			# 0x3

	lbu	$2,43($5)
$L107:
	lui	$3,%hi(DstPort)
	addiu	$3,$3,%lo(DstPort)
	andi	$2,$2,0xfc
	addu	$2,$2,$3
	lw	$4,0($2)
	lw	$2,172($16)
	li	$5,14			# 0xe
	sw	$4,20($16)
	sw	$2,152($16)
	lui	$2,%hi(skb_push)
	addiu	$2,$2,%lo(skb_push)
	jal	$2
	move	$4,$16

	lui	$2,%hi(dev_queue_xmit)
	addiu	$2,$2,%lo(dev_queue_xmit)
	jal	$2
	move	$4,$16

	move	$3,$0
$L95:
	lw	$31,20($sp)
	lw	$16,16($sp)
	move	$2,$3
	j	$31
	addiu	$sp,$sp,24

$L96:
	beq	$4,$2,$L106
	nop

	li	$2,4			# 0x4
	beq	$4,$2,$L106
	nop

	li	$2,5			# 0x5
	beq	$4,$2,$L106
	nop

	li	$2,7			# 0x7
	bne	$4,$2,$L95
	li	$3,1			# 0x1

$L106:
	j	$L107
	lbu	$2,55($5)

	.set	macro
	.set	reorder
	.end	PpeHitBindForceToCpuHandler
	.section	.text.PpeHitBindForceMcastToWiFiHandler,"ax",@progbits
	.align	2
	.globl	PpeHitBindForceMcastToWiFiHandler
	.ent	PpeHitBindForceMcastToWiFiHandler
	.type	PpeHitBindForceMcastToWiFiHandler, @function
PpeHitBindForceMcastToWiFiHandler:
	.frame	$sp,40,$31		# vars= 0, regs= 6/0, args= 16, gp= 0
	.mask	0x801f0000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-40
	lui	$2,%hi(RemoveVlanTag)
	sw	$31,36($sp)
	sw	$20,32($sp)
	sw	$19,28($sp)
	sw	$18,24($sp)
	sw	$17,20($sp)
	move	$18,$4
	addiu	$2,$2,%lo(RemoveVlanTag)
	jal	$2
	sw	$16,16($sp)

	lw	$3,172($18)
	lui	$2,%hi(skb_push)
	move	$4,$18
	sw	$3,152($18)
	addiu	$2,$2,%lo(skb_push)
	jal	$2
	li	$5,14			# 0xe

	lui	$2,%hi(DstPort)
	lui	$3,%hi(skb_clone)
	lui	$4,%hi(dev_queue_xmit)
	addiu	$2,$2,%lo(DstPort)
	addiu	$20,$3,%lo(skb_clone)
	addiu	$19,$4,%lo(dev_queue_xmit)
	addiu	$16,$2,44
	j	$L113
	li	$17,47			# 0x2f

$L111:
	bltz	$17,$L116
	addiu	$16,$16,4

$L113:
	lw	$2,0($16)
	move	$4,$18
	li	$5,32			# 0x20
	beq	$2,$0,$L111
	addiu	$17,$17,-1

	jal	$20
	nop

	lw	$3,0($16)
	move	$4,$2
	addiu	$16,$16,4
	jal	$19
	sw	$3,20($2)

	bgez	$17,$L113
	nop

$L116:
	lui	$2,%hi(kfree_skb)
	addiu	$2,$2,%lo(kfree_skb)
	jal	$2
	move	$4,$18

	lw	$31,36($sp)
	lw	$20,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,40

	.set	macro
	.set	reorder
	.end	PpeHitBindForceMcastToWiFiHandler
	.section	.text.PpeRxHandler,"ax",@progbits
	.align	2
	.globl	PpeRxHandler
	.ent	PpeRxHandler
	.type	PpeRxHandler, @function
PpeRxHandler:
	.frame	$sp,24,$31		# vars= 0, regs= 1/0, args= 16, gp= 0
	.mask	0x80000000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-24
	sw	$31,16($sp)
	lw	$8,168($4)
	lui	$2,%hi(PpeFoeBase)
	lw	$7,%lo(PpeFoeBase)($2)
	lbu	$9,3($8)
	lbu	$3,2($8)
	lbu	$2,1($8)
	lbu	$6,0($8)
	andi	$5,$9,0x3f
	sll	$5,$5,8
	or	$5,$5,$3
	sll	$2,$2,8
	or	$2,$2,$6
	sll	$3,$5,2
	lw	$6,172($4)
	addu	$3,$3,$5
	addiu	$2,$2,-29299
	sll	$3,$3,4
	sltu	$2,$2,2
	move	$11,$4
	addu	$12,$3,$7
	beq	$2,$0,$L119
	addiu	$6,$6,-14

	lui	$25,%hi(PpeExtIfRxHandler)
	lw	$31,16($sp)
	addiu	$25,$25,%lo(PpeExtIfRxHandler)
	jr	$25
	addiu	$sp,$sp,24

$L119:
	lbu	$10,4($8)
	srl	$2,$9,6
	li	$5,22			# 0x16
	andi	$3,$10,0x7
	sll	$3,$3,2
	or	$7,$3,$2
	beq	$7,$5,$L140
	li	$3,6			# 0x6

	srl	$2,$10,3
	andi	$2,$2,0x7
	beq	$2,$3,$L141
	li	$2,19			# 0x13

$L123:
	lbu	$2,4($8)
	lbu	$3,3($8)
	li	$4,19			# 0x13
	andi	$2,$2,0x7
	srl	$3,$3,6
	sll	$2,$2,2
	or	$3,$2,$3
	beq	$3,$4,$L117
	li	$2,31			# 0x1f

	beq	$3,$2,$L142
	li	$2,20			# 0x14

	beq	$3,$2,$L143
	li	$2,21			# 0x15

	beq	$3,$2,$L144
	lw	$31,16($sp)

$L117:
	lw	$31,16($sp)
	li	$2,1			# 0x1
	j	$31
	addiu	$sp,$sp,24

$L141:
	beq	$7,$2,$L123
	li	$2,20			# 0x14

	beq	$7,$2,$L123
	li	$2,21			# 0x15

	beq	$7,$2,$L123
	lui	$25,%hi(PpeExtIfPingPongHandler)

	lw	$31,16($sp)
	addiu	$25,$25,%lo(PpeExtIfPingPongHandler)
	jr	$25
	addiu	$sp,$sp,24

$L140:
	lui	$25,%hi(PpeHitBindForceToCpuHandler)
	lw	$31,16($sp)
	move	$5,$12
	addiu	$25,$25,%lo(PpeHitBindForceToCpuHandler)
	jr	$25
	addiu	$sp,$sp,24

$L144:
	li	$2,1
	sb	$2,6($6)
	addiu	$sp,$sp,24
	j	$31
	li	$2,1			# 0x1

$L142:
	lui	$25,%hi(PpeHitBindForceMcastToWiFiHandler)
	lw	$31,16($sp)
	move	$4,$11
	addiu	$25,$25,%lo(PpeHitBindForceMcastToWiFiHandler)
	jr	$25
	addiu	$sp,$sp,24

$L143:
	lui	$2,%hi(PpeKeepAliveHandler)
	move	$4,$11
	addiu	$2,$2,%lo(PpeKeepAliveHandler)
	jal	$2
	move	$5,$12

	lw	$31,16($sp)
	li	$2,1			# 0x1
	j	$31
	addiu	$sp,$sp,24

	.set	macro
	.set	reorder
	.end	PpeRxHandler
	.section	.text.GetPppoeSid,"ax",@progbits
	.align	2
	.globl	GetPppoeSid
	.ent	GetPppoeSid
	.type	GetPppoeSid, @function
GetPppoeSid:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lw	$3,172($4)
	addu	$3,$3,$5
	addiu	$5,$3,14
	lbu	$2,7($5)
	lbu	$4,6($5)
	sll	$2,$2,8
	or	$2,$2,$4
	sh	$2,0($7)
	lbu	$4,14($3)
	move	$3,$2
	li	$2,17			# 0x11
	beq	$4,$2,$L149
	li	$8,1			# 0x1

$L145:
	j	$31
	move	$2,$8

$L149:
	li	$2,8448			# 0x2100
	beq	$3,$2,$L147
	nop

	li	$2,22272			# 0x5700
	bne	$3,$2,$L145
	nop

$L147:
	lbu	$2,3($5)
	lbu	$3,2($5)
	move	$8,$0
	sll	$2,$2,8
	or	$2,$2,$3
	sh	$2,0($6)
	j	$31
	move	$2,$8

	.set	macro
	.set	reorder
	.end	GetPppoeSid
	.section	.text.isSpecialTag,"ax",@progbits
	.align	2
	.globl	isSpecialTag
	.ent	isSpecialTag
	.type	isSpecialTag, @function
isSpecialTag:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	j	$31
	move	$2,$0

	.set	macro
	.set	reorder
	.end	isSpecialTag
	.section	.text.is8021Q,"ax",@progbits
	.align	2
	.globl	is8021Q
	.ent	is8021Q
	.type	is8021Q, @function
is8021Q:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	andi	$4,$4,0xffff
	li	$2,129			# 0x81
	beq	$4,$2,$L156
	move	$3,$0

	j	$31
	move	$2,$3

$L156:
	lui	$2,%hi(PpeParseResult+12)
	li	$3,1			# 0x1
	sh	$4,%lo(PpeParseResult+12)($2)
	j	$31
	move	$2,$3

	.set	macro
	.set	reorder
	.end	is8021Q
	.section	.text.isHwVlanTx,"ax",@progbits
	.align	2
	.globl	isHwVlanTx
	.ent	isHwVlanTx
	.type	isHwVlanTx, @function
isHwVlanTx:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lhu	$2,144($4)
	srl	$2,$2,12
	andi	$2,$2,0x1
	beq	$2,$0,$L157
	move	$3,$0

	li	$3,129
	lui	$2,%hi(PpeParseResult+12)
	sh	$3,%lo(PpeParseResult+12)($2)
	li	$3,1			# 0x1
$L157:
	j	$31
	move	$2,$3

	.set	macro
	.set	reorder
	.end	isHwVlanTx
	.section	.text.PpeParseLayerInfo,"ax",@progbits
	.align	2
	.globl	PpeParseLayerInfo
	.ent	PpeParseLayerInfo
	.type	PpeParseLayerInfo, @function
PpeParseLayerInfo:
	.frame	$sp,64,$31		# vars= 8, regs= 9/0, args= 16, gp= 0
	.mask	0x80ff0000,-8
	.fmask	0x00000000,0
	addiu	$sp,$sp,-64
	sw	$20,40($sp)
	lui	$2,%hi(memset)
	lui	$20,%hi(PpeParseResult)
	sw	$31,56($sp)
	sw	$22,48($sp)
	sw	$19,36($sp)
	sw	$17,28($sp)
	sw	$16,24($sp)
	move	$19,$4
	move	$5,$0
	addiu	$4,$20,%lo(PpeParseResult)
	li	$6,132			# 0x84
	sw	$23,52($sp)
	sw	$21,44($sp)
	addiu	$2,$2,%lo(memset)
	.set	noreorder
	.set	nomacro
	jal	$2
	sw	$18,32($sp)
	.set	macro
	.set	reorder

	lw	$17,172($19)
	lui	$22,%hi(memcpy)
	addiu	$4,$20,%lo(PpeParseResult)
	move	$5,$17
	addiu	$16,$22,%lo(memcpy)
	.set	noreorder
	.set	nomacro
	jal	$16
	li	$6,6			# 0x6
	.set	macro
	.set	reorder

	lui	$4,%hi(PpeParseResult+6)
	addiu	$4,$4,%lo(PpeParseResult+6)
	addiu	$5,$17,6
	.set	noreorder
	.set	nomacro
	jal	$16
	li	$6,6			# 0x6
	.set	macro
	.set	reorder

	lbu	$3,13($17)
	lbu	$2,12($17)
	addiu	$4,$20,%lo(PpeParseResult)
	sll	$3,$3,8
	or	$3,$3,$2
	sh	$3,32($4)
	lbu	$2,0($17)
	andi	$2,$2,0x1
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L161
	li	$2,1
	.set	macro
	.set	reorder

	sb	$2,128($4)
$L163:
	addiu	$16,$20,%lo(PpeParseResult)
	lui	$18,%hi(is8021Q)
	addiu	$2,$18,%lo(is8021Q)
	.set	noreorder
	.set	nomacro
	jal	$2
	lhu	$4,32($16)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L165
	lui	$2,%hi(isSpecialTag)
	.set	macro
	.set	reorder

	addiu	$2,$2,%lo(isSpecialTag)
	.set	noreorder
	.set	nomacro
	jal	$2
	lhu	$4,32($16)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L333
	lui	$2,%hi(isHwVlanTx)
	.set	macro
	.set	reorder

$L165:
	addiu	$16,$20,%lo(PpeParseResult)
	lhu	$3,22($16)
	sh	$0,14($16)
	li	$21,34916			# 0x8864
	addiu	$3,$3,1
	sh	$3,22($16)
	lhu	$2,144($19)
	andi	$2,$2,0xefff
#APP
		wsbh	$2, $2			

#NO_APP
	andi	$2,$2,0xffff
	sh	$2,16($sp)
	lbu	$3,13($17)
	lbu	$4,12($17)
	sh	$2,16($16)
	sll	$3,$3,8
	or	$3,$3,$4
#APP
		wsbh	$2, $3			

#NO_APP
	andi	$2,$2,0xffff
	move	$4,$3
	.set	noreorder
	.set	nomacro
	beq	$2,$21,$L334
	sh	$3,18($sp)
	.set	macro
	.set	reorder

	addiu	$18,$18,%lo(is8021Q)
	jal	$18
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L335
	lhu	$17,18($sp)
	.set	macro
	.set	reorder

$L178:
	lhu	$3,22($16)
	li	$2,4
	sh	$2,18($16)
	addiu	$3,$3,1
	sh	$3,22($16)
	lw	$2,172($19)
	lhu	$5,14($16)
	addu	$2,$2,$5
	lhu	$3,14($2)
	addiu	$17,$2,14
	sh	$3,20($16)
	lhu	$4,2($17)
#APP
		wsbh	$2, $4			

#NO_APP
	andi	$2,$2,0xffff
	.set	noreorder
	.set	nomacro
	beq	$2,$21,$L336
	li	$2,8			# 0x8
	.set	macro
	.set	reorder

	jal	$18
	bne	$2,$0,$L337
	lhu	$2,2($17)
$L327:
	sh	$2,32($16)
$L190:
	lw	$2,172($19)
$L349:
	addiu	$17,$20,%lo(PpeParseResult)
	sw	$2,156($19)
	lhu	$3,14($17)
	lhu	$4,18($17)
	lw	$5,24($17)
	addu	$2,$2,$3
	addu	$2,$2,$4
	addu	$16,$2,$5
	addiu	$18,$16,14
	sw	$18,152($19)
	lhu	$3,32($17)
	li	$2,8			# 0x8
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L198
	li	$2,25736			# 0x6488
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L338
	li	$2,8448			# 0x2100
	.set	macro
	.set	reorder

$L197:
	addiu	$17,$20,%lo(PpeParseResult)
	lhu	$3,32($17)
	li	$2,56710			# 0xdd86
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L214
	li	$2,25736			# 0x6488
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L339
	li	$2,22272			# 0x5700
	.set	macro
	.set	reorder

	li	$4,1			# 0x1
$L160:
	lw	$31,56($sp)
$L353:
	lw	$23,52($sp)
	lw	$22,48($sp)
	lw	$21,44($sp)
	lw	$20,40($sp)
	lw	$19,36($sp)
	lw	$18,32($sp)
	lw	$17,28($sp)
	lw	$16,24($sp)
	move	$2,$4
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,64
	.set	macro
	.set	reorder

$L161:
	.set	noreorder
	.set	nomacro
	j	$L163
	sb	$0,128($4)
	.set	macro
	.set	reorder

$L335:
	lui	$2,%hi(isSpecialTag)
	addiu	$2,$2,%lo(isSpecialTag)
	.set	noreorder
	.set	nomacro
	jal	$2
	andi	$4,$17,0xffff
	.set	macro
	.set	reorder

	bne	$2,$0,$L178
	.set	noreorder
	.set	nomacro
	j	$L190
	sh	$17,32($16)
	.set	macro
	.set	reorder

$L334:
	li	$2,8			# 0x8
	sw	$2,24($16)
	lui	$6,%hi(PpeParseResult+30)
	lui	$7,%hi(PpeParseResult+28)
	lui	$2,%hi(GetPppoeSid)
	move	$4,$19
	addiu	$6,$6,%lo(PpeParseResult+30)
	addiu	$7,$7,%lo(PpeParseResult+28)
	addiu	$2,$2,%lo(GetPppoeSid)
	.set	noreorder
	.set	nomacro
	jal	$2
	move	$5,$0
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L160
	li	$4,1			# 0x1
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L327
	lhu	$2,18($sp)
	.set	macro
	.set	reorder

$L339:
	lhu	$3,28($17)
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L160
	li	$4,1			# 0x1
	.set	macro
	.set	reorder

$L214:
	lui	$4,%hi(PpeParseResult+56)
	addiu	$4,$4,%lo(PpeParseResult+56)
	addiu	$16,$22,%lo(memcpy)
	move	$5,$18
	.set	noreorder
	.set	nomacro
	jal	$16
	li	$6,40			# 0x28
	.set	macro
	.set	reorder

	lbu	$3,6($18)
	li	$2,6			# 0x6
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L340
	li	$2,17			# 0x11
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L341
	li	$2,4			# 0x4
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L342
	lui	$4,%hi(PpeParseResult+36)
	.set	macro
	.set	reorder

	sw	$2,124($17)
$L212:
	lui	$3,%hi(DebugLevel)
$L350:
	lw	$2,%lo(DebugLevel)($3)
	sltu	$2,$2,6
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L347
	move	$4,$0
	.set	macro
	.set	reorder

	addiu	$17,$20,%lo(PpeParseResult)
	lw	$3,124($17)
	li	$2,1			# 0x1
	beq	$3,$2,$L331
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L331
	li	$2,7			# 0x7
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L352
	lui	$16,%hi(Ip2Str)
	.set	macro
	.set	reorder

$L347:
	lw	$31,56($sp)
	lw	$23,52($sp)
	lw	$22,48($sp)
	lw	$21,44($sp)
	lw	$20,40($sp)
	lw	$19,36($sp)
	lw	$18,32($sp)
	lw	$17,28($sp)
	lw	$16,24($sp)
	move	$2,$4
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,64
	.set	macro
	.set	reorder

$L333:
	addiu	$2,$2,%lo(isHwVlanTx)
	.set	noreorder
	.set	nomacro
	jal	$2
	move	$4,$19
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L165
	li	$3,34916			# 0x8864
	.set	macro
	.set	reorder

	lhu	$2,32($16)
#APP
		wsbh	$2, $2			

#NO_APP
	andi	$2,$2,0xffff
	.set	noreorder
	.set	nomacro
	bne	$2,$3,$L190
	li	$2,8			# 0x8
	.set	macro
	.set	reorder

	lhu	$5,14($16)
	sw	$2,24($16)
	lui	$6,%hi(PpeParseResult+30)
	lui	$7,%hi(PpeParseResult+28)
	lui	$2,%hi(GetPppoeSid)
	move	$4,$19
	addiu	$6,$6,%lo(PpeParseResult+30)
	addiu	$2,$2,%lo(GetPppoeSid)
	.set	noreorder
	.set	nomacro
	jal	$2
	addiu	$7,$7,%lo(PpeParseResult+28)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L160
	li	$4,1			# 0x1
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L349
	lw	$2,172($19)
	.set	macro
	.set	reorder

$L337:
	lhu	$2,22($16)
	lhu	$4,14($16)
	addiu	$2,$2,1
	sh	$2,22($16)
	lw	$3,172($19)
	addu	$3,$3,$4
	.set	noreorder
	.set	nomacro
	jal	$18
	lhu	$4,20($3)
	.set	macro
	.set	reorder

	beq	$2,$0,$L190
	lhu	$2,22($16)
	addiu	$2,$2,1
	.set	noreorder
	.set	nomacro
	j	$L190
	sh	$2,22($16)
	.set	macro
	.set	reorder

$L338:
	lhu	$3,28($17)
	bne	$3,$2,$L197
$L198:
	lui	$4,%hi(PpeParseResult+36)
	addiu	$21,$22,%lo(memcpy)
	addiu	$4,$4,%lo(PpeParseResult+36)
	move	$5,$18
	.set	noreorder
	.set	nomacro
	jal	$21
	li	$6,20			# 0x14
	.set	macro
	.set	reorder

	lbu	$3,9($18)
	li	$22,6			# 0x6
	.set	noreorder
	.set	nomacro
	beq	$3,$22,$L343
	li	$23,17			# 0x11
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$3,$23,$L344
	li	$2,47			# 0x2f
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L160
	li	$4,1			# 0x1
	.set	macro
	.set	reorder

	li	$2,41			# 0x29
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L353
	lw	$31,56($sp)
	.set	macro
	.set	reorder

	lw	$2,14($16)
	lui	$4,%hi(PpeParseResult+56)
	addiu	$4,$4,%lo(PpeParseResult+56)
	andi	$2,$2,0xf
	sll	$2,$2,2
	addu	$16,$2,$18
	move	$5,$16
	.set	noreorder
	.set	nomacro
	jal	$21
	li	$6,40			# 0x28
	.set	macro
	.set	reorder

	lbu	$2,6($16)
	.set	noreorder
	.set	nomacro
	beq	$2,$22,$L345
	addiu	$5,$16,40
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$2,$23,$L354
	addiu	$3,$20,%lo(PpeParseResult)
	.set	macro
	.set	reorder

	li	$2,7			# 0x7
	.set	noreorder
	.set	nomacro
	j	$L212
	sw	$2,124($3)
	.set	macro
	.set	reorder

$L336:
	sw	$2,24($16)
	lui	$6,%hi(PpeParseResult+30)
	lui	$7,%hi(PpeParseResult+28)
	lui	$2,%hi(GetPppoeSid)
	move	$4,$19
	addiu	$5,$5,4
	addiu	$6,$6,%lo(PpeParseResult+30)
	addiu	$2,$2,%lo(GetPppoeSid)
	.set	noreorder
	.set	nomacro
	jal	$2
	addiu	$7,$7,%lo(PpeParseResult+28)
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L160
	li	$4,1			# 0x1
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L327
	lhu	$2,2($17)
	.set	macro
	.set	reorder

$L331:
	lui	$16,%hi(Ip2Str)
$L352:
	addiu	$16,$16,%lo(Ip2Str)
	lw	$4,48($17)
#APP
		wsbh	$4, $4			
	rotr	$4, $4, 16		

#NO_APP
	jal	$16
	lw	$4,52($17)
#APP
		wsbh	$4, $4			
	rotr	$4, $4, 16		

#NO_APP
	jal	$16
	.set	noreorder
	.set	nomacro
	j	$L347
	move	$4,$0
	.set	macro
	.set	reorder

$L354:
	lui	$4,%hi(PpeParseResult+116)
	sw	$5,148($19)
	addiu	$4,$4,%lo(PpeParseResult+116)
	.set	noreorder
	.set	nomacro
	jal	$21
	li	$6,2			# 0x2
	.set	macro
	.set	reorder

	lui	$4,%hi(PpeParseResult+118)
	addiu	$4,$4,%lo(PpeParseResult+118)
	addiu	$5,$16,42
	.set	noreorder
	.set	nomacro
	jal	$21
	li	$6,2			# 0x2
	.set	macro
	.set	reorder

	addiu	$3,$20,%lo(PpeParseResult)
$L351:
	li	$2,7			# 0x7
	.set	noreorder
	.set	nomacro
	j	$L212
	sw	$2,124($3)
	.set	macro
	.set	reorder

$L343:
	lw	$5,14($16)
	lui	$4,%hi(PpeParseResult+96)
	addiu	$4,$4,%lo(PpeParseResult+96)
	andi	$5,$5,0xf
	sll	$5,$5,2
	addu	$5,$5,$18
	sw	$5,148($19)
	li	$6,20			# 0x14
$L329:
	jal	$21
	sw	$0,124($17)
	lhu	$2,6($18)
	andi	$2,$2,0xff3f
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L160
	li	$4,1			# 0x1
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L350
	lui	$3,%hi(DebugLevel)
	.set	macro
	.set	reorder

$L344:
	lw	$5,14($16)
	lui	$4,%hi(PpeParseResult+116)
	addiu	$4,$4,%lo(PpeParseResult+116)
	andi	$5,$5,0xf
	sll	$5,$5,2
	addu	$5,$5,$18
	li	$6,8			# 0x8
	.set	noreorder
	.set	nomacro
	j	$L329
	sw	$5,148($19)
	.set	macro
	.set	reorder

$L340:
	addiu	$5,$18,40
	lui	$4,%hi(PpeParseResult+96)
	sw	$5,148($19)
	addiu	$4,$4,%lo(PpeParseResult+96)
	.set	noreorder
	.set	nomacro
	jal	$16
	li	$6,20			# 0x14
	.set	macro
	.set	reorder

	li	$3,5			# 0x5
$L330:
	.set	noreorder
	.set	nomacro
	j	$L212
	sw	$3,124($17)
	.set	macro
	.set	reorder

$L341:
	addiu	$5,$18,40
	lui	$4,%hi(PpeParseResult+116)
	sw	$5,148($19)
	addiu	$4,$4,%lo(PpeParseResult+116)
	.set	noreorder
	.set	nomacro
	jal	$16
	li	$6,8			# 0x8
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L330
	li	$3,5			# 0x5
	.set	macro
	.set	reorder

$L342:
	addiu	$4,$4,%lo(PpeParseResult+36)
	addiu	$5,$18,1600
	.set	noreorder
	.set	nomacro
	jal	$16
	li	$6,20			# 0x14
	.set	macro
	.set	reorder

	li	$3,3			# 0x3
	.set	noreorder
	.set	nomacro
	j	$L212
	sw	$3,124($17)
	.set	macro
	.set	reorder

$L345:
	lui	$4,%hi(PpeParseResult+96)
	sw	$5,148($19)
	addiu	$4,$4,%lo(PpeParseResult+96)
	.set	noreorder
	.set	nomacro
	jal	$21
	li	$6,2			# 0x2
	.set	macro
	.set	reorder

	lui	$4,%hi(PpeParseResult+98)
	addiu	$4,$4,%lo(PpeParseResult+98)
	addiu	$5,$16,42
	.set	noreorder
	.set	nomacro
	jal	$21
	li	$6,2			# 0x2
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L351
	addiu	$3,$20,%lo(PpeParseResult)
	.set	macro
	.set	reorder

	.end	PpeParseLayerInfo
	.section	.text.PpeFillInL2Info,"ax",@progbits
	.align	2
	.globl	PpeFillInL2Info
	.ent	PpeFillInL2Info
	.type	PpeFillInL2Info, @function
PpeFillInL2Info:
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
	lw	$5,0($5)
	li	$3,2			# 0x2
	srl	$2,$5,28
	andi	$2,$2,0x3
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L355
	li	$4,1			# 0x1
	.set	macro
	.set	reorder

	lui	$19,%hi(PpeParseResult)
	addiu	$18,$19,%lo(PpeParseResult)
	lw	$2,124($18)
	sltu	$2,$2,2
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L357
	srl	$2,$5,25
	.set	macro
	.set	reorder

	andi	$2,$2,0x7
	li	$3,3			# 0x3
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L357
	lui	$16,%hi(FoeSetMacInfo)
	.set	macro
	.set	reorder

	addiu	$16,$16,%lo(FoeSetMacInfo)
	addiu	$4,$17,48
	.set	noreorder
	.set	nomacro
	jal	$16
	move	$5,$18
	.set	macro
	.set	reorder

	lui	$5,%hi(PpeParseResult+6)
	addiu	$5,$5,%lo(PpeParseResult+6)
	.set	noreorder
	.set	nomacro
	jal	$16
	addiu	$4,$17,56
	.set	macro
	.set	reorder

	lhu	$2,16($18)
#APP
		wsbh	$2, $2			

#NO_APP
	sh	$2,44($17)
	lhu	$3,30($18)
#APP
		wsbh	$3, $3			

#NO_APP
	sh	$3,60($17)
	lhu	$2,20($18)
#APP
		wsbh	$2, $2			

#NO_APP
	sh	$2,52($17)
	lhu	$3,12($18)
	addiu	$5,$19,%lo(PpeParseResult)
#APP
		wsbh	$3, $3			

#NO_APP
	sh	$3,46($17)
	lhu	$3,22($5)
	lw	$4,0($17)
	li	$2,-524288			# 0xfffffffffff80000
	ori	$2,$2,0xffff
	andi	$3,$3,0x7
	and	$4,$4,$2
	sll	$3,$3,16
	or	$4,$4,$3
	sw	$4,0($17)
	lw	$2,24($5)
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L412
	li	$2,-589824			# 0xfffffffffff70000
	.set	macro
	.set	reorder

	li	$2,524288			# 0x80000
$L413:
	or	$4,$4,$2
$L410:
	li	$2,1048576			# 0x100000
	or	$2,$4,$2
	sw	$2,0($17)
	move	$4,$0
$L355:
	lw	$31,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	move	$2,$4
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,40
	.set	macro
	.set	reorder

$L357:
	lui	$16,%hi(FoeSetMacInfo)
	addiu	$16,$16,%lo(FoeSetMacInfo)
	addiu	$4,$17,64
	.set	noreorder
	.set	nomacro
	jal	$16
	move	$5,$18
	.set	macro
	.set	reorder

	lui	$5,%hi(PpeParseResult+6)
	addiu	$5,$5,%lo(PpeParseResult+6)
	.set	noreorder
	.set	nomacro
	jal	$16
	addiu	$4,$17,72
	.set	macro
	.set	reorder

	lhu	$2,16($18)
#APP
		wsbh	$2, $2			

#NO_APP
	sh	$2,60($17)
	lhu	$3,30($18)
#APP
		wsbh	$3, $3			

#NO_APP
	sh	$3,76($17)
	lhu	$2,20($18)
#APP
		wsbh	$2, $2			

#NO_APP
	sh	$2,68($17)
	lhu	$3,12($18)
	addiu	$5,$19,%lo(PpeParseResult)
#APP
		wsbh	$3, $3			

#NO_APP
	sh	$3,62($17)
	lhu	$3,22($5)
	lw	$4,0($17)
	li	$2,-524288			# 0xfffffffffff80000
	ori	$2,$2,0xffff
	andi	$3,$3,0x7
	and	$4,$4,$2
	sll	$3,$3,16
	or	$4,$4,$3
	sw	$4,0($17)
	lw	$2,24($5)
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L413
	li	$2,524288			# 0x80000
	.set	macro
	.set	reorder

	li	$2,-589824			# 0xfffffffffff70000
$L412:
	ori	$2,$2,0xffff
	.set	noreorder
	.set	nomacro
	j	$L410
	and	$4,$4,$2
	.set	macro
	.set	reorder

	.end	PpeFillInL2Info
	.section	.text.PpeFillInL3Info,"ax",@progbits
	.align	2
	.globl	PpeFillInL3Info
	.ent	PpeFillInL3Info
	.type	PpeFillInL3Info, @function
PpeFillInL3Info:
	.frame	$sp,32,$31		# vars= 0, regs= 3/0, args= 16, gp= 0
	.mask	0x80030000,-8
	.fmask	0x00000000,0
	addiu	$sp,$sp,-32
	lui	$4,%hi(PpeParseResult)
	sw	$17,20($sp)
	sw	$31,24($sp)
	sw	$16,16($sp)
	addiu	$6,$4,%lo(PpeParseResult)
	lhu	$3,32($6)
	li	$2,8			# 0x8
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L416
	move	$17,$5
	.set	macro
	.set	reorder

	li	$2,25736			# 0x6488
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L525
	li	$2,8448			# 0x2100
	.set	macro
	.set	reorder

	addiu	$16,$4,%lo(PpeParseResult)
$L531:
	lhu	$3,32($16)
	li	$2,56710			# 0xdd86
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L453
	li	$2,25736			# 0x6488
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L526
	li	$2,22272			# 0x5700
	.set	macro
	.set	reorder

	lw	$31,24($sp)
$L530:
	lw	$17,20($sp)
	lw	$16,16($sp)
	li	$2,1			# 0x1
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,32
	.set	macro
	.set	reorder

$L526:
	lhu	$3,28($16)
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L530
	lw	$31,24($sp)
	.set	macro
	.set	reorder

$L453:
	lw	$3,124($16)
	addiu	$2,$3,-4
	sltu	$2,$2,2
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L454
	li	$2,3			# 0x3
	.set	macro
	.set	reorder

	lw	$4,0($17)
	li	$3,7			# 0x7
	srl	$2,$4,25
	andi	$2,$2,0x7
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L527
	li	$3,2097152			# 0x200000
	.set	macro
	.set	reorder

	or	$3,$4,$3
	sw	$3,0($17)
	lw	$2,64($16)
#APP
		wsbh	$2, $2			
	rotr	$2, $2, 16		

#NO_APP
	sw	$2,4($17)
	lw	$3,68($16)
#APP
		wsbh	$3, $3			
	rotr	$3, $3, 16		

#NO_APP
	sw	$3,8($17)
	lw	$2,72($16)
#APP
		wsbh	$2, $2			
	rotr	$2, $2, 16		

#NO_APP
	sw	$2,12($17)
	lw	$3,76($16)
#APP
		wsbh	$3, $3			
	rotr	$3, $3, 16		

#NO_APP
	sw	$3,16($17)
	lw	$2,80($16)
#APP
		wsbh	$2, $2			
	rotr	$2, $2, 16		

#NO_APP
	sw	$2,20($17)
	lw	$3,84($16)
#APP
		wsbh	$3, $3			
	rotr	$3, $3, 16		

#NO_APP
	sw	$3,24($17)
	lw	$2,88($16)
#APP
		wsbh	$2, $2			
	rotr	$2, $2, 16		

#NO_APP
	sw	$2,28($17)
	lw	$3,92($16)
#APP
		wsbh	$3, $3			
	rotr	$3, $3, 16		

#NO_APP
	sw	$3,32($17)
$L524:
	lw	$2,56($16)
	lbu	$3,57($16)
	andi	$2,$2,0xf
	sll	$2,$2,4
	srl	$3,$3,4
	or	$2,$2,$3
	sb	$2,59($17)
$L451:
	move	$2,$0
$L529:
	lw	$31,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,32
	.set	macro
	.set	reorder

$L525:
	lhu	$3,28($6)
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L531
	addiu	$16,$4,%lo(PpeParseResult)
	.set	macro
	.set	reorder

$L416:
	lw	$3,124($6)
	sltu	$2,$3,2
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L417
	li	$2,7			# 0x7
	.set	macro
	.set	reorder

	lw	$4,0($17)
	li	$3,3			# 0x3
	srl	$2,$4,25
	andi	$2,$2,0x7
	.set	noreorder
	.set	nomacro
	beq	$2,$3,$L528
	li	$3,2097152			# 0x200000
	.set	macro
	.set	reorder

	or	$3,$4,$3
	sw	$3,0($17)
	lw	$2,48($6)
#APP
		wsbh	$2, $2			
	rotr	$2, $2, 16		

#NO_APP
	sw	$2,20($17)
	lw	$3,52($6)
#APP
		wsbh	$3, $3			
	rotr	$3, $3, 16		

#NO_APP
	sw	$3,24($17)
	lbu	$2,37($6)
	sb	$2,19($17)
	.set	noreorder
	.set	nomacro
	j	$L529
	move	$2,$0
	.set	macro
	.set	reorder

$L417:
	.set	noreorder
	.set	nomacro
	bne	$3,$2,$L451
	lui	$4,%hi(PpeParseResult+36)
	.set	macro
	.set	reorder

	lw	$2,48($6)
#APP
		wsbh	$2, $2			
	rotr	$2, $2, 16		

#NO_APP
	sw	$2,40($17)
	lw	$2,52($6)
	addiu	$4,$4,%lo(PpeParseResult+36)
#APP
		wsbh	$2, $2			
	rotr	$2, $2, 16		

#NO_APP
	sw	$2,44($17)
	lhu	$3,2($4)
	lhu	$2,10($4)
#APP
		wsbh	$3, $3			

		wsbh	$2, $2			

#NO_APP
	andi	$3,$3,0xffff
	andi	$2,$2,0xffff
	nor	$3,$0,$3
	nor	$2,$0,$2
	addu	$2,$2,$3
	srl	$4,$2,16
	sltu	$4,$0,$4
	andi	$2,$2,0xffff
	addu	$2,$2,$4
	srl	$3,$2,16
	addu	$2,$2,$3
	lw	$4,52($17)
	sh	$2,48($17)
	lhu	$3,42($6)
	li	$2,-8			# 0xfffffffffffffff8
#APP
		wsbh	$3, $3			

#NO_APP
	andi	$3,$3,0xffff
	and	$4,$4,$2
	srl	$3,$3,13
	or	$4,$4,$3
	sw	$4,52($17)
	lbu	$2,44($6)
	lw	$3,0($17)
	sb	$2,51($17)
	lbu	$4,37($6)
	li	$2,234881024			# 0xe000000
	or	$3,$3,$2
	move	$2,$0
	sw	$3,0($17)
	.set	noreorder
	.set	nomacro
	j	$L529
	sb	$4,50($17)
	.set	macro
	.set	reorder

$L454:
	bne	$3,$2,$L451
	lw	$2,64($16)
#APP
		wsbh	$2, $2			
	rotr	$2, $2, 16		

#NO_APP
	sw	$2,16($17)
	lw	$3,68($16)
#APP
		wsbh	$3, $3			
	rotr	$3, $3, 16		

#NO_APP
	sw	$3,20($17)
	lw	$2,72($16)
#APP
		wsbh	$2, $2			
	rotr	$2, $2, 16		

#NO_APP
	sw	$2,24($17)
	lw	$3,76($16)
#APP
		wsbh	$3, $3			
	rotr	$3, $3, 16		

#NO_APP
	sw	$3,28($17)
	lw	$2,80($16)
#APP
		wsbh	$2, $2			
	rotr	$2, $2, 16		

#NO_APP
	sw	$2,32($17)
	lw	$3,84($16)
#APP
		wsbh	$3, $3			
	rotr	$3, $3, 16		

#NO_APP
	sw	$3,36($17)
	lw	$2,88($16)
#APP
		wsbh	$2, $2			
	rotr	$2, $2, 16		

#NO_APP
	sw	$2,40($17)
	lw	$2,92($16)
	lui	$5,%hi(PpeParseResult+57)
#APP
		wsbh	$2, $2			
	rotr	$2, $2, 16		

#NO_APP
	sw	$2,44($17)
	lui	$2,%hi(memcpy)
	addiu	$5,$5,%lo(PpeParseResult+57)
	addiu	$4,$17,48
	addiu	$2,$2,%lo(memcpy)
	.set	noreorder
	.set	nomacro
	jal	$2
	li	$6,3			# 0x3
	.set	macro
	.set	reorder

	lw	$3,56($16)
	lw	$4,48($17)
	li	$2,-251723776			# 0xfffffffff0ff0000
	ori	$2,$2,0xffff
	andi	$3,$3,0xf
	and	$4,$4,$2
	sll	$3,$3,24
	or	$4,$4,$3
	lw	$5,0($17)
	sw	$4,48($17)
	li	$2,-234946560			# 0xfffffffff1ff0000
	lbu	$6,63($16)
	ori	$2,$2,0xffff
	and	$5,$5,$2
	li	$3,100663296			# 0x6000000
	or	$5,$5,$3
	move	$2,$0
	sw	$5,0($17)
	.set	noreorder
	.set	nomacro
	j	$L529
	sb	$6,52($17)
	.set	macro
	.set	reorder

$L528:
	li	$2,2097152			# 0x200000
	li	$3,8388608			# 0x800000
	or	$2,$4,$2
	or	$2,$2,$3
	sw	$2,0($17)
	lbu	$3,37($6)
	move	$2,$0
	.set	noreorder
	.set	nomacro
	j	$L529
	sb	$3,59($17)
	.set	macro
	.set	reorder

$L527:
	or	$3,$4,$3
	li	$2,8388608			# 0x800000
	or	$3,$3,$2
	.set	noreorder
	.set	nomacro
	j	$L524
	sw	$3,0($17)
	.set	macro
	.set	reorder

	.end	PpeFillInL3Info
	.section	.text.PpeFillInL4Info,"ax",@progbits
	.align	2
	.globl	PpeFillInL4Info
	.ent	PpeFillInL4Info
	.type	PpeFillInL4Info, @function
PpeFillInL4Info:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	lui	$2,%hi(PpeParseResult)
	addiu	$7,$2,%lo(PpeParseResult)
	lw	$3,124($7)
	.set	noreorder
	.set	nomacro
	bne	$3,$0,$L564
	move	$4,$0
	.set	macro
	.set	reorder

	lw	$6,0($5)
	li	$2,3			# 0x3
	srl	$3,$6,25
	andi	$3,$3,0x7
	beq	$3,$2,$L532
	lbu	$3,45($7)
	li	$2,6			# 0x6
	beq	$3,$2,$L562
	li	$2,1073741824			# 0x40000000
	or	$6,$6,$2
	li	$2,17			# 0x11
	.set	noreorder
	.set	nomacro
	beq	$3,$2,$L563
	li	$4,1			# 0x1
	.set	macro
	.set	reorder

	move	$4,$0
$L532:
$L564:
	.set	noreorder
	.set	nomacro
	j	$31
	move	$2,$4
	.set	macro
	.set	reorder

$L563:
	lhu	$2,116($7)
#APP
		wsbh	$2, $2			

#NO_APP
	sh	$2,30($5)
	move	$2,$4
	lhu	$3,118($7)
	sw	$6,0($5)
#APP
		wsbh	$3, $3			

#NO_APP
	.set	noreorder
	.set	nomacro
	j	$31
	sh	$3,28($5)
	.set	macro
	.set	reorder

$L562:
	li	$3,-1073807360			# 0xffffffffbfff0000
	ori	$3,$3,0xffff
	lhu	$2,96($7)
	and	$6,$6,$3
#APP
		wsbh	$2, $2			

#NO_APP
	move	$4,$0
	sh	$2,30($5)
	lhu	$3,98($7)
	sw	$6,0($5)
#APP
		wsbh	$3, $3			

#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L532
	sh	$3,28($5)
	.set	macro
	.set	reorder

	.end	PpeFillInL4Info
	.section	.text.PpeSetMtrByteInfo,"ax",@progbits
	.align	2
	.globl	PpeSetMtrByteInfo
	.ent	PpeSetMtrByteInfo
	.type	PpeSetMtrByteInfo, @function
PpeSetMtrByteInfo:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	andi	$4,$4,0xffff
	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$2,$2,0x1200
	sll	$4,$4,2
	li	$3,536805376			# 0x1fff0000
	addu	$4,$4,$2
	ori	$3,$3,0xffff
	and	$4,$4,$3
	sll	$6,$6,1
	li	$2,-1610612736			# 0xffffffffa0000000
	sll	$5,$5,3
	or	$4,$4,$2
	or	$5,$5,$6
	li	$2,1			# 0x1
	sw	$5,0($4)
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	PpeSetMtrByteInfo
	.section	.text.PpeSetMtrPktInfo,"ax",@progbits
	.align	2
	.globl	PpeSetMtrPktInfo
	.ent	PpeSetMtrPktInfo
	.type	PpeSetMtrPktInfo, @function
PpeSetMtrPktInfo:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	andi	$4,$4,0xffff
	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$2,$2,0x1200
	sll	$4,$4,2
	addu	$4,$4,$2
	li	$2,536805376			# 0x1fff0000
	sll	$6,$6,1
	ori	$2,$2,0xffff
	sll	$5,$5,8
	or	$5,$5,$6
	and	$4,$4,$2
	li	$3,-1610612736			# 0xffffffffa0000000
	or	$4,$4,$3
	ori	$5,$5,0x1
	li	$2,1			# 0x1
	sw	$5,0($4)
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	PpeSetMtrPktInfo
	.section	.text.PpeSetInfoBlk2,"ax",@progbits
	.align	2
	.ent	PpeSetInfoBlk2
	.type	PpeSetInfoBlk2, @function
PpeSetInfoBlk2:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lw	$3,0($4)
	li	$2,-16			# 0xfffffffffffffff0
	andi	$5,$5,0xf
	and	$3,$3,$2
	li	$2,-262144			# 0xfffffffffffc0000
	ori	$2,$2,0xfff
	or	$3,$3,$5
	andi	$6,$6,0x3f
	and	$3,$3,$2
	sll	$6,$6,12
	li	$2,-16580608			# 0xffffffffff030000
	or	$3,$3,$6
	andi	$7,$7,0x3f
	ori	$2,$2,0xffff
	and	$3,$3,$2
	sll	$7,$7,18
	or	$3,$3,$7
	j	$31
	sw	$3,0($4)

	.set	macro
	.set	reorder
	.end	PpeSetInfoBlk2
	.section	.rodata.str1.4,"aMS",@progbits,1
	.align	2
$LC25:
	.ascii	"ra\000"
	.align	2
$LC26:
	.ascii	"wds\000"
	.align	2
$LC27:
	.ascii	"mesh\000"
	.align	2
$LC28:
	.ascii	"apcli\000"
	.section	.text.PpeSetForcePortInfo,"ax",@progbits
	.align	2
	.globl	PpeSetForcePortInfo
	.ent	PpeSetForcePortInfo
	.type	PpeSetForcePortInfo, @function
PpeSetForcePortInfo:
	.frame	$sp,24,$31		# vars= 0, regs= 1/0, args= 16, gp= 0
	.mask	0x80000000,-8
	.fmask	0x00000000,0
	addiu	$sp,$sp,-24
	sw	$31,16($sp)
	lw	$6,20($4)
	lui	$3,%hi($LC25)
	move	$7,$5
	addiu	$3,$3,%lo($LC25)
	li	$2,2			# 0x2
	move	$5,$6
#APP
	.set	noreorder
	.set	noat
1:	lbu	$4,($5)
	beqz	$2,2f
	lbu	$1,($3)
	subu	$2,1
	bne	$1,$4,3f
	addiu	$5,1
	bnez	$4,1b
	addiu	$3,1
2:
	move	$4,$1
3:	subu	$4,$1
	.set	at
	.set	reorder
#NO_APP
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L574
	lui	$3,%hi($LC26)
	.set	macro
	.set	reorder

	addiu	$3,$3,%lo($LC26)
	li	$2,3			# 0x3
	move	$5,$6
#APP
	.set	noreorder
	.set	noat
1:	lbu	$4,($5)
	beqz	$2,2f
	lbu	$1,($3)
	subu	$2,1
	bne	$1,$4,3f
	addiu	$5,1
	bnez	$4,1b
	addiu	$3,1
2:
	move	$4,$1
3:	subu	$4,$1
	.set	at
	.set	reorder
#NO_APP
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L574
	lui	$3,%hi($LC27)
	.set	macro
	.set	reorder

	addiu	$3,$3,%lo($LC27)
	li	$2,4			# 0x4
	move	$5,$6
#APP
	.set	noreorder
	.set	noat
1:	lbu	$4,($5)
	beqz	$2,2f
	lbu	$1,($3)
	subu	$2,1
	bne	$1,$4,3f
	addiu	$5,1
	bnez	$4,1b
	addiu	$3,1
2:
	move	$4,$1
3:	subu	$4,$1
	.set	at
	.set	reorder
#NO_APP
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L574
	lui	$3,%hi($LC28)
	.set	macro
	.set	reorder

	addiu	$3,$3,%lo($LC28)
	li	$2,5			# 0x5
	move	$5,$6
#APP
	.set	noreorder
	.set	noat
1:	lbu	$4,($5)
	beqz	$2,2f
	lbu	$1,($3)
	subu	$2,1
	bne	$1,$4,3f
	addiu	$5,1
	bnez	$4,1b
	addiu	$3,1
2:
	move	$4,$1
3:	subu	$4,$1
	.set	at
	.set	reorder
#NO_APP
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L574
	lui	$2,%hi(DstPort+248)
	.set	macro
	.set	reorder

	lw	$3,%lo(DstPort+248)($2)
	beq	$6,$3,$L574
	lw	$2,0($7)
	srl	$2,$2,25
	andi	$6,$2,0x7
	sltu	$3,$6,2
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L580
	xori	$3,$6,0x2
	.set	macro
	.set	reorder

	lhu	$2,44($7)
	lui	$3,%hi(lan_vid)
	lhu	$4,%lo(lan_vid)($3)
	andi	$5,$2,0xfff
	.set	noreorder
	.set	nomacro
	beq	$5,$4,$L604
	lui	$2,%hi(wan_vid)
	.set	macro
	.set	reorder

	lhu	$3,%lo(wan_vid)($2)
	.set	noreorder
	.set	nomacro
	bne	$5,$3,$L606
	addiu	$4,$7,16
	.set	macro
	.set	reorder

	lui	$2,%hi(bind_dir)
	lbu	$4,%lo(bind_dir)($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L585
	li	$2,2			# 0x2
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$4,$2,$L585
	li	$3,1			# 0x1
	.set	macro
	.set	reorder

	lw	$31,16($sp)
$L607:
	move	$2,$3
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,24
	.set	macro
	.set	reorder

$L574:
	lw	$31,16($sp)
	li	$3,1			# 0x1
	move	$2,$3
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,24
	.set	macro
	.set	reorder

$L585:
	addiu	$4,$7,16
$L606:
	li	$5,8			# 0x8
	li	$6,63			# 0x3f
	li	$7,1			# 0x1
$L601:
	lui	$2,%hi(PpeSetInfoBlk2)
	addiu	$2,$2,%lo(PpeSetInfoBlk2)
	jal	$2
	lw	$31,16($sp)
$L605:
	move	$3,$0
	move	$2,$3
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,24
	.set	macro
	.set	reorder

$L580:
	xori	$2,$6,0x4
	sltu	$2,$2,1
	sltu	$3,$3,1
	xori	$4,$6,0x5
	or	$3,$3,$2
	sltu	$4,$4,1
	xori	$5,$6,0x7
	or	$3,$3,$4
	sltu	$5,$5,1
	xori	$2,$6,0x3
	or	$3,$3,$5
	sltu	$2,$2,1
	or	$3,$3,$2
	.set	noreorder
	.set	nomacro
	beq	$3,$0,$L605
	lw	$31,16($sp)
	.set	macro
	.set	reorder

	lhu	$2,60($7)
	lui	$3,%hi(wan_vid)
	lhu	$4,%lo(wan_vid)($3)
	andi	$2,$2,0xfff
	.set	noreorder
	.set	nomacro
	bne	$2,$4,$L596
	addiu	$4,$7,56
	.set	macro
	.set	reorder

	lui	$3,%hi(bind_dir)
	lbu	$2,%lo(bind_dir)($3)
	addiu	$2,$2,-1
	andi	$2,$2,0x00ff
	sltu	$2,$2,2
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L607
	li	$3,1			# 0x1
	.set	macro
	.set	reorder

	addiu	$4,$7,56
$L602:
	lui	$2,%hi(PpeSetInfoBlk2)
	li	$5,8			# 0x8
	li	$6,63			# 0x3f
	addiu	$2,$2,%lo(PpeSetInfoBlk2)
	.set	noreorder
	.set	nomacro
	jal	$2
	li	$7,2			# 0x2
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	j	$L605
	lw	$31,16($sp)
	.set	macro
	.set	reorder

$L604:
	lui	$3,%hi(bind_dir)
	lbu	$2,%lo(bind_dir)($3)
	addiu	$4,$7,16
	addiu	$2,$2,-1
	andi	$2,$2,0x00ff
	sltu	$2,$2,2
	.set	noreorder
	.set	nomacro
	bne	$2,$0,$L602
	li	$3,1			# 0x1
	.set	macro
	.set	reorder

	lw	$31,16($sp)
	move	$2,$3
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,24
	.set	macro
	.set	reorder

$L596:
	li	$5,8			# 0x8
	li	$6,63			# 0x3f
	.set	noreorder
	.set	nomacro
	j	$L601
	li	$7,1			# 0x1
	.set	macro
	.set	reorder

	.end	PpeSetForcePortInfo
	.section	.text.PpeSetExtIfNum,"ax",@progbits
	.align	2
	.globl	PpeSetExtIfNum
	.ent	PpeSetExtIfNum
	.type	PpeSetExtIfNum, @function
PpeSetExtIfNum:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	j	$31
	move	$2,$0

	.set	macro
	.set	reorder
	.end	PpeSetExtIfNum
	.section	.text.PpeSetEntryBind,"ax",@progbits
	.align	2
	.globl	PpeSetEntryBind
	.ent	PpeSetEntryBind
	.type	PpeSetEntryBind, @function
PpeSetEntryBind:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$2,$2,0x10
	lw	$6,0($2)
	lw	$3,0($5)
	li	$2,-32768			# 0xffffffffffff8000
	andi	$6,$6,0x7fff
	and	$3,$3,$2
	li	$2,-16842752			# 0xfffffffffeff0000
	or	$3,$3,$6
	ori	$2,$2,0xffff
	and	$3,$3,$2
	li	$6,4194304			# 0x400000
	li	$2,-805371904			# 0xffffffffcfff0000
	or	$3,$3,$6
	ori	$2,$2,0xffff
	and	$3,$3,$2
	li	$6,536870912			# 0x20000000
	or	$3,$3,$6
	sw	$3,0($5)
	lui	$2,%hi(DebugLevel)
	lw	$3,%lo(DebugLevel)($2)
	bne	$3,$0,$L611
	lui	$25,%hi(FoeDumpEntry)

	j	$31
	nop

$L611:
	lw	$2,168($4)
	addiu	$25,$25,%lo(FoeDumpEntry)
	lbu	$4,3($2)
	lbu	$3,2($2)
	andi	$4,$4,0x3f
	sll	$4,$4,8
	jr	$25
	or	$4,$4,$3

	.set	macro
	.set	reorder
	.end	PpeSetEntryBind
	.section	.text.PpeTxHandler,"ax",@progbits
	.align	2
	.globl	PpeTxHandler
	.ent	PpeTxHandler
	.type	PpeTxHandler, @function
PpeTxHandler:
	.frame	$sp,32,$31		# vars= 0, regs= 4/0, args= 16, gp= 0
	.mask	0x80070000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-32
	sw	$18,24($sp)
	sw	$17,20($sp)
	sw	$16,16($sp)
	sw	$31,28($sp)
	lw	$8,168($4)
	lui	$3,%hi(PpeFoeBase)
	lw	$7,%lo(PpeFoeBase)($3)
	lbu	$2,3($8)
	lbu	$3,2($8)
	move	$16,$4
	andi	$2,$2,0x3f
	lbu	$4,1($8)
	sll	$2,$2,8
	or	$2,$2,$3
	lbu	$6,0($8)
	sll	$3,$2,2
	addu	$3,$3,$2
	sll	$4,$4,8
	sll	$3,$3,4
	or	$4,$4,$6
	li	$2,29299			# 0x7273
	addu	$17,$3,$7
	beq	$4,$2,$L616
	move	$18,$5

	li	$2,29301			# 0x7275
	beq	$4,$2,$L616
	li	$2,29300			# 0x7274

	beq	$4,$2,$L616
	nop

$L615:
	lbu	$2,1($8)
	lbu	$4,0($8)
	li	$3,29299			# 0x7273
	sll	$2,$2,8
	or	$4,$2,$4
	beq	$4,$3,$L625
	li	$2,29301			# 0x7275

	beq	$4,$2,$L625
	li	$2,29300			# 0x7274

	beq	$4,$2,$L625
	lw	$31,28($sp)

$L635:
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	li	$2,1			# 0x1
	j	$31
	addiu	$sp,$sp,32

$L616:
	lbu	$5,4($8)
	lbu	$2,3($8)
	li	$4,15			# 0xf
	andi	$3,$5,0x7
	srl	$2,$2,6
	sll	$3,$3,2
	or	$3,$3,$2
	bne	$3,$4,$L615
	srl	$3,$5,6

	lbu	$2,5($8)
	sll	$2,$2,2
	or	$2,$2,$3
	bne	$2,$0,$L615
	lui	$2,%hi(PpeParseLayerInfo)

	addiu	$2,$2,%lo(PpeParseLayerInfo)
	jal	$2
	move	$4,$16

	bne	$2,$0,$L634
	lui	$2,%hi(PpeFillInL2Info)

	move	$4,$16
	addiu	$2,$2,%lo(PpeFillInL2Info)
	jal	$2
	move	$5,$17

	bne	$2,$0,$L634
	lui	$2,%hi(PpeFillInL3Info)

	move	$4,$16
	addiu	$2,$2,%lo(PpeFillInL3Info)
	jal	$2
	move	$5,$17

	bne	$2,$0,$L634
	lui	$2,%hi(PpeFillInL4Info)

	move	$4,$16
	addiu	$2,$2,%lo(PpeFillInL4Info)
	jal	$2
	move	$5,$17

	bne	$2,$0,$L634
	lui	$2,%hi(PpeSetForcePortInfo)

	move	$6,$18
	move	$4,$16
	addiu	$2,$2,%lo(PpeSetForcePortInfo)
	jal	$2
	move	$5,$17

	bne	$2,$0,$L634
	lui	$2,%hi(PpeSetExtIfNum)

	move	$4,$16
	addiu	$2,$2,%lo(PpeSetExtIfNum)
	jal	$2
	move	$5,$17

	bne	$2,$0,$L634
	lui	$2,%hi(PpeSetEntryBind)

	move	$4,$16
	addiu	$2,$2,%lo(PpeSetEntryBind)
	jal	$2
	move	$5,$17

	j	$L635
	lw	$31,28($sp)

$L625:
	lbu	$2,4($8)
	lbu	$3,3($8)
	andi	$2,$2,0x7
	srl	$3,$3,6
	sll	$2,$2,2
	or	$2,$2,$3
	addiu	$2,$2,-20
	sltu	$2,$2,2
	beq	$2,$0,$L635
	lw	$31,28($sp)

	lui	$2,%hi(memset)
	move	$4,$8
	move	$5,$0
	addiu	$2,$2,%lo(memset)
	jal	$2
	li	$6,6			# 0x6

	lw	$31,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,32

$L634:
	lw	$4,168($16)
	lui	$2,%hi(memset)
	move	$5,$0
	addiu	$2,$2,%lo(memset)
	jal	$2
	li	$6,6			# 0x6

	j	$L635
	lw	$31,28($sp)

	.set	macro
	.set	reorder
	.end	PpeTxHandler
	.section	.text.PpeSetFoeEbl,"ax",@progbits
	.align	2
	.globl	PpeSetFoeEbl
	.ent	PpeSetFoeEbl
	.type	PpeSetFoeEbl, @function
PpeSetFoeEbl:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$2,$2,0xe04
	li	$3,1			# 0x1
	lw	$5,0($2)
	beq	$4,$3,$L639
	nop

	li	$3,-12289			# 0xffffffffffffcfff
	li	$2,-196608			# 0xfffffffffffd0000
	and	$5,$5,$3
	ori	$2,$2,0xffff
	and	$5,$5,$2
	li	$3,-18177			# 0xffffffffffffb8ff
	li	$2,-1114112			# 0xffffffffffef0000
	ori	$2,$2,0xffff
	and	$5,$5,$3
	and	$5,$5,$2
	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$2,$2,0xe04
	sw	$5,0($2)
	j	$31
	nop

$L639:
	li	$2,131072			# 0x20000
	ori	$5,$5,0x3000
	or	$5,$5,$2
	li	$3,524288			# 0x80000
	or	$5,$5,$3
	li	$2,1048576			# 0x100000
	ori	$5,$5,0x4700
	or	$5,$5,$2
	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$2,$2,0xe04
	sw	$5,0($2)
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	PpeSetFoeEbl
	.section	.text.PpeSetFoeGloCfgEbl,"ax",@progbits
	.align	2
	.ent	PpeSetFoeGloCfgEbl
	.type	PpeSetFoeGloCfgEbl, @function
PpeSetFoeGloCfgEbl:
	.frame	$sp,40,$31		# vars= 0, regs= 5/0, args= 16, gp= 0
	.mask	0x800f0000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-40
	lui	$2,%hi(RegModifyBits)
	li	$3,1			# 0x1
	sw	$18,24($sp)
	sw	$17,20($sp)
	sw	$16,16($sp)
	sw	$31,32($sp)
	sw	$19,28($sp)
	li	$17,-1341063168			# 0xffffffffb0110000
	addiu	$18,$2,%lo(RegModifyBits)
	li	$5,7			# 0x7
	move	$6,$0
	li	$7,3			# 0x3
	beq	$4,$3,$L644
	li	$16,-1341063168			# 0xffffffffb0110000

	ori	$4,$16,0x4
	move	$5,$0
	li	$6,3			# 0x3
	jal	$18
	li	$7,1			# 0x1

	ori	$2,$16,0x2030
	sw	$0,0($2)
	li	$2,327680			# 0x50000
	ori	$3,$16,0x2130
	ori	$8,$16,0x2230
	ori	$9,$16,0x2330
	ori	$10,$16,0x2430
	ori	$11,$16,0x2530
	ori	$12,$16,0x3700
	ori	$2,$2,0xe330
	sw	$0,0($3)
	ori	$4,$16,0x270c
	sw	$0,0($8)
	move	$25,$18
	sw	$0,0($9)
	lw	$31,32($sp)
	sw	$0,0($10)
	lw	$19,28($sp)
	sw	$0,0($11)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	move	$5,$0
	li	$6,4			# 0x4
	li	$7,1			# 0x1
	sw	$2,0($12)
	jr	$25
	addiu	$sp,$sp,40

$L644:
	jal	$18
	ori	$4,$17,0x4

	ori	$4,$17,0x4
	li	$5,1			# 0x1
	li	$6,3			# 0x3
	jal	$18
	li	$7,1			# 0x1

	li	$3,327680			# 0x50000
	ori	$2,$17,0x3700
	ori	$3,$3,0xe33b
	ori	$4,$17,0x270c
	li	$5,1			# 0x1
	li	$6,4			# 0x4
	li	$7,1			# 0x1
	sw	$3,0($2)
	jal	$18
	nop

	li	$4,-1341128704			# 0xffffffffb0100000
	move	$25,$18
	lw	$31,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	ori	$4,$4,0xe00
	li	$5,1			# 0x1
	li	$6,4			# 0x4
	li	$7,1			# 0x1
	jr	$25
	addiu	$sp,$sp,40

	.set	macro
	.set	reorder
	.end	PpeSetFoeGloCfgEbl
	.section	.text.ra_dev_get_by_name,"ax",@progbits
	.align	2
	.globl	ra_dev_get_by_name
	.ent	ra_dev_get_by_name
	.type	ra_dev_get_by_name, @function
ra_dev_get_by_name:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	move	$5,$4
	lui	$25,%hi(dev_get_by_name)
	lui	$4,%hi(init_net)
	addiu	$25,$25,%lo(dev_get_by_name)
	jr	$25
	addiu	$4,$4,%lo(init_net)

	.set	macro
	.set	reorder
	.end	ra_dev_get_by_name
	.section	.rodata.str1.4
	.align	2
$LC29:
	.ascii	"ra0\000"
	.align	2
$LC30:
	.ascii	"ra1\000"
	.align	2
$LC31:
	.ascii	"ra2\000"
	.align	2
$LC32:
	.ascii	"ra3\000"
	.align	2
$LC33:
	.ascii	"ra4\000"
	.align	2
$LC34:
	.ascii	"ra5\000"
	.align	2
$LC35:
	.ascii	"ra6\000"
	.align	2
$LC36:
	.ascii	"ra7\000"
	.align	2
$LC37:
	.ascii	"ra8\000"
	.align	2
$LC38:
	.ascii	"ra9\000"
	.align	2
$LC39:
	.ascii	"ra10\000"
	.align	2
$LC40:
	.ascii	"ra11\000"
	.align	2
$LC41:
	.ascii	"ra12\000"
	.align	2
$LC42:
	.ascii	"ra13\000"
	.align	2
$LC43:
	.ascii	"ra14\000"
	.align	2
$LC44:
	.ascii	"ra15\000"
	.align	2
$LC45:
	.ascii	"rai0\000"
	.align	2
$LC46:
	.ascii	"rai1\000"
	.align	2
$LC47:
	.ascii	"rai2\000"
	.align	2
$LC48:
	.ascii	"rai3\000"
	.align	2
$LC49:
	.ascii	"rai4\000"
	.align	2
$LC50:
	.ascii	"rai5\000"
	.align	2
$LC51:
	.ascii	"rai6\000"
	.align	2
$LC52:
	.ascii	"rai7\000"
	.align	2
$LC53:
	.ascii	"rai8\000"
	.align	2
$LC54:
	.ascii	"rai9\000"
	.align	2
$LC55:
	.ascii	"rai10\000"
	.align	2
$LC56:
	.ascii	"rai11\000"
	.align	2
$LC57:
	.ascii	"rai12\000"
	.align	2
$LC58:
	.ascii	"rai13\000"
	.align	2
$LC59:
	.ascii	"rai14\000"
	.align	2
$LC60:
	.ascii	"rai15\000"
	.align	2
$LC61:
	.ascii	"eth2\000"
	.align	2
$LC62:
	.ascii	"eth0\000"
	.section	.text.PpeSetDstPort,"ax",@progbits
	.align	2
	.ent	PpeSetDstPort
	.type	PpeSetDstPort, @function
PpeSetDstPort:
	.frame	$sp,32,$31		# vars= 0, regs= 3/0, args= 16, gp= 0
	.mask	0x80030000,-8
	.fmask	0x00000000,0
	addiu	$sp,$sp,-32
	sw	$31,24($sp)
	sw	$17,20($sp)
	.set	noreorder
	.set	nomacro
	bne	$4,$0,$L921
	sw	$16,16($sp)
	.set	macro
	.set	reorder

	lui	$5,%hi(DstPort)
	addiu	$2,$5,%lo(DstPort)
	lw	$4,44($2)
	.set	noreorder
	.set	nomacro
	bne	$4,$0,$L922
	lui	$3,%hi(cpu_data+8)
	.set	macro
	.set	reorder

	addiu	$2,$5,%lo(DstPort)
$L923:
	lw	$4,48($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L955
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L660
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L955:
	lw	$4,52($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L954
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L668
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L954:
	lw	$4,56($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L953
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L676
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L953:
	lw	$4,60($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L952
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L684
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L952:
	lw	$4,64($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L951
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L692
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L951:
	lw	$4,68($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L950
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L700
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L950:
	lw	$4,72($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L949
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L708
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L949:
	lw	$4,76($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L948
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L716
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L948:
	lw	$4,80($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L947
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L724
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L947:
	lw	$4,84($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L946
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L732
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L946:
	lw	$4,88($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L945
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L740
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L945:
	lw	$4,92($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L944
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L748
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L944:
	lw	$4,96($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L943
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L756
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L943:
	lw	$4,100($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L942
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L764
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L942:
	lw	$4,104($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L941
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L772
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L941:
	lw	$4,132($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L940
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L780
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L940:
	lw	$4,136($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L939
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L788
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L939:
	lw	$4,140($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L938
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L796
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L938:
	lw	$4,144($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L937
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L804
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L937:
	lw	$4,148($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L936
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L812
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L936:
	lw	$4,152($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L935
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L820
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L935:
	lw	$4,156($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L934
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L828
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L934:
	lw	$4,160($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L933
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L836
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L933:
	lw	$4,164($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L932
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L844
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L932:
	lw	$4,168($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L931
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L852
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L931:
	lw	$4,172($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L930
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L860
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L930:
	lw	$4,176($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L929
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L868
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L929:
	lw	$4,180($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L928
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L876
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L928:
	lw	$4,184($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L927
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L884
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L927:
	lw	$4,188($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L926
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L892
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L926:
	lw	$4,192($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L925
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L900
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L925:
	lw	$4,240($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L924
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L908
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$2,$5,%lo(DstPort)
$L924:
	lw	$4,248($2)
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L956
	lw	$31,24($sp)
	.set	macro
	.set	reorder

	lui	$3,%hi(cpu_data+8)
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L916
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	lw	$31,24($sp)
$L956:
	lw	$17,20($sp)
	lw	$16,16($sp)
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,32
	.set	macro
	.set	reorder

$L922:
	lhu	$2,%lo(cpu_data+10)($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L652
#APP
		.set	mips3					
1:	ll	$2, 520($4)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($4)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L923
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L921:
	lui	$17,%hi(ra_dev_get_by_name)
	lui	$4,%hi($LC29)
	addiu	$17,$17,%lo(ra_dev_get_by_name)
	addiu	$4,$4,%lo($LC29)
	lui	$16,%hi(DstPort)
	.set	noreorder
	.set	nomacro
	jal	$17
	addiu	$16,$16,%lo(DstPort)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC30)
	addiu	$4,$4,%lo($LC30)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,44($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC31)
	addiu	$4,$4,%lo($LC31)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,48($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC32)
	addiu	$4,$4,%lo($LC32)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,52($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC33)
	addiu	$4,$4,%lo($LC33)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,56($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC34)
	addiu	$4,$4,%lo($LC34)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,60($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC35)
	addiu	$4,$4,%lo($LC35)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,64($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC36)
	addiu	$4,$4,%lo($LC36)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,68($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC37)
	addiu	$4,$4,%lo($LC37)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,72($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC38)
	addiu	$4,$4,%lo($LC38)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,76($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC39)
	addiu	$4,$4,%lo($LC39)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,80($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC40)
	addiu	$4,$4,%lo($LC40)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,84($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC41)
	addiu	$4,$4,%lo($LC41)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,88($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC42)
	addiu	$4,$4,%lo($LC42)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,92($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC43)
	addiu	$4,$4,%lo($LC43)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,96($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC44)
	addiu	$4,$4,%lo($LC44)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,100($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC45)
	addiu	$4,$4,%lo($LC45)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,104($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC46)
	addiu	$4,$4,%lo($LC46)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,132($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC47)
	addiu	$4,$4,%lo($LC47)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,136($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC48)
	addiu	$4,$4,%lo($LC48)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,140($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC49)
	addiu	$4,$4,%lo($LC49)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,144($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC50)
	addiu	$4,$4,%lo($LC50)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,148($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC51)
	addiu	$4,$4,%lo($LC51)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,152($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC52)
	addiu	$4,$4,%lo($LC52)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,156($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC53)
	addiu	$4,$4,%lo($LC53)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,160($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC54)
	addiu	$4,$4,%lo($LC54)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,164($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC55)
	addiu	$4,$4,%lo($LC55)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,168($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC56)
	addiu	$4,$4,%lo($LC56)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,172($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC57)
	addiu	$4,$4,%lo($LC57)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,176($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC58)
	addiu	$4,$4,%lo($LC58)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,180($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC59)
	addiu	$4,$4,%lo($LC59)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,184($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC60)
	addiu	$4,$4,%lo($LC60)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,188($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC61)
	addiu	$4,$4,%lo($LC61)
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,192($16)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC62)
	sw	$2,240($16)
	.set	noreorder
	.set	nomacro
	jal	$17
	addiu	$4,$4,%lo($LC62)
	.set	macro
	.set	reorder

	sw	$2,248($16)
	lw	$31,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,32
	.set	macro
	.set	reorder

$L916:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	lw	$31,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,32
	.set	macro
	.set	reorder

$L908:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L924
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L900:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L925
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L892:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L926
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L884:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L927
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L876:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L928
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L868:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L929
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L860:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L930
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L852:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L931
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L844:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L932
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L836:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L933
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L828:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L934
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L820:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L935
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L812:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L936
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L804:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L937
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L796:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L938
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L788:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L939
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L780:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L940
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L772:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L941
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L764:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L942
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L756:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L943
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L748:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L944
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L740:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L945
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L732:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L946
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L724:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L947
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L716:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L948
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L708:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L949
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L700:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L950
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L692:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L951
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L684:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L952
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L676:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L953
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L668:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L954
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L652:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L923
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

$L660:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($4)
	addiu	$2,$2,-1
	sw	$2,520($4)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L955
	addiu	$2,$5,%lo(DstPort)
	.set	macro
	.set	reorder

	.end	PpeSetDstPort
	.section	.text.SetAclPattern,"ax",@progbits
	.align	2
	.globl	SetAclPattern
	.ent	SetAclPattern
	.type	SetAclPattern, @function
SetAclPattern:
	.frame	$sp,32,$31		# vars= 0, regs= 4/0, args= 16, gp= 0
	.mask	0x80070000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	andi	$2,$7,0xffff
	sll	$6,$6,16
	li	$7,-1341063168			# 0xffffffffb0110000
	addiu	$sp,$sp,-32
	or	$2,$2,$6
	ori	$3,$7,0x94
	lbu	$6,48($sp)
	sw	$2,0($3)
	li	$2,524288			# 0x80000
	andi	$5,$5,0x00ff
	sll	$4,$4,16
	ori	$2,$2,0x3f00
	or	$2,$4,$2
	sll	$5,$5,1
	or	$2,$2,$5
	ori	$3,$7,0x98
	sw	$2,0($3)
	li	$2,-2147483648			# 0xffffffff80000000
	ori	$2,$2,0x5000
	addu	$2,$6,$2
	ori	$7,$7,0x90
	sw	$2,0($7)
	lui	$2,%hi(__udelay)
	sw	$18,24($sp)
	sw	$17,20($sp)
	sw	$16,16($sp)
	move	$18,$7
	addiu	$17,$2,%lo(__udelay)
	move	$16,$0
	j	$L965
	sw	$31,28($sp)

$L970:
	jal	$17
	nop

	sltu	$2,$16,20
	beq	$2,$0,$L971
	lw	$31,28($sp)

$L965:
	lw	$2,0($18)
	addiu	$16,$16,1
	bltz	$2,$L970
	li	$4,1000			# 0x3e8

	lw	$31,28($sp)
$L971:
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	j	$31
	addiu	$sp,$sp,32

	.set	macro
	.set	reorder
	.end	SetAclPattern
	.section	.text.SetAclControl,"ax",@progbits
	.align	2
	.globl	SetAclControl
	.ent	SetAclControl
	.type	SetAclControl, @function
SetAclControl:
	.frame	$sp,48,$31		# vars= 0, regs= 7/0, args= 16, gp= 0
	.mask	0x803f0000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$3,-1341063168			# 0xffffffffb0110000
	ori	$2,$3,0x94
	addiu	$sp,$sp,-48
	sw	$4,0($2)
	li	$2,-2147483648			# 0xffffffff80000000
	ori	$2,$2,0x9000
	sw	$20,32($sp)
	andi	$20,$5,0x00ff
	ori	$4,$3,0x90
	addu	$7,$20,$2
	lui	$2,%hi(__udelay)
	sw	$21,36($sp)
	sw	$19,28($sp)
	sw	$18,24($sp)
	sw	$17,20($sp)
	sw	$16,16($sp)
	ori	$3,$3,0x98
	andi	$19,$6,0xffff
	move	$18,$4
	addiu	$17,$2,%lo(__udelay)
	move	$16,$0
	li	$21,-1341063168			# 0xffffffffb0110000
	sw	$0,0($3)
	sw	$31,40($sp)
	sw	$7,0($4)
	j	$L980
	nop

$L995:
	jal	$17
	nop

	sltu	$2,$16,20
	beq	$2,$0,$L997
	ori	$3,$21,0x94

$L980:
	lw	$7,0($18)
	addiu	$16,$16,1
	bltz	$7,$L995
	li	$4,1000			# 0x3e8

	ori	$3,$21,0x94
$L997:
	li	$2,-2147483648			# 0xffffffff80000000
	sw	$19,0($3)
	ori	$2,$2,0xb000
	ori	$3,$21,0x98
	addu	$7,$20,$2
	sw	$0,0($3)
	li	$2,-1341063168			# 0xffffffffb0110000
	lui	$3,%hi(__udelay)
	sw	$7,0($18)
	addiu	$17,$3,%lo(__udelay)
	ori	$18,$2,0x90
	j	$L990
	move	$16,$0

$L996:
	jal	$17
	nop

	sltu	$2,$16,20
	beq	$2,$0,$L998
	lw	$31,40($sp)

$L990:
	lw	$7,0($18)
	addiu	$16,$16,1
	bltz	$7,$L996
	li	$4,1000			# 0x3e8

	lw	$31,40($sp)
$L998:
	lw	$21,36($sp)
	lw	$20,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	j	$31
	addiu	$sp,$sp,48

	.set	macro
	.set	reorder
	.end	SetAclControl
	.section	.rodata.str1.4
	.align	2
$LC69:
	.ascii	"eth2.2\000"
	.align	2
$LC70:
	.ascii	"br0\000"
	.section	.text.SetAclFwd,"ax",@progbits
	.align	2
	.globl	SetAclFwd
	.ent	SetAclFwd
	.type	SetAclFwd, @function
SetAclFwd:
	.frame	$sp,40,$31		# vars= 0, regs= 4/0, args= 24, gp= 0
	.mask	0x80070000,-4
	.fmask	0x00000000,0
	addiu	$sp,$sp,-40
	sw	$17,28($sp)
	sw	$16,24($sp)
	move	$17,$4
	lui	$16,%hi(ra_dev_get_by_name)
	lui	$4,%hi($LC69)
	addiu	$16,$16,%lo(ra_dev_get_by_name)
	sw	$31,36($sp)
	sw	$18,32($sp)
	.set	noreorder
	.set	nomacro
	jal	$16
	addiu	$4,$4,%lo($LC69)
	.set	macro
	.set	reorder

	lui	$4,%hi($LC70)
	addiu	$4,$4,%lo($LC70)
	.set	noreorder
	.set	nomacro
	jal	$16
	move	$18,$2
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$17,$0,$L1000
	move	$16,$2
	.set	macro
	.set	reorder

	li	$2,536805376			# 0x1fff0000
	li	$3,-1341063168			# 0xffffffffb0110000
	ori	$7,$2,0xffff
	ori	$3,$3,0x2004
	li	$6,-1610612736			# 0xffffffffa0000000
	li	$5,5			# 0x5
	and	$2,$3,$7
$L1033:
	or	$2,$2,$6
	lw	$4,0($2)
	addiu	$5,$5,-1
	addiu	$3,$3,256
	ori	$4,$4,0x400
	sw	$4,0($2)
	.set	noreorder
	.set	nomacro
	bgez	$5,$L1033
	and	$2,$3,$7
	.set	macro
	.set	reorder

	lw	$2,356($16)
	lui	$17,%hi(SetAclPattern)
	addiu	$17,$17,%lo(SetAclPattern)
	lbu	$7,0($2)
	lbu	$3,1($2)
	move	$4,$0
	sll	$7,$7,8
	or	$7,$7,$3
	move	$5,$0
	li	$6,65535			# 0xffff
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$0,16($sp)
	.set	macro
	.set	reorder

	lw	$3,356($16)
	li	$2,1			# 0x1
	move	$4,$0
	lbu	$7,2($3)
	lbu	$8,3($3)
	li	$5,1			# 0x1
	sll	$7,$7,8
	or	$7,$7,$8
	li	$6,65535			# 0xffff
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,16($sp)
	.set	macro
	.set	reorder

	lw	$3,356($16)
	li	$2,2			# 0x2
	move	$4,$0
	lbu	$7,4($3)
	lbu	$8,5($3)
	li	$5,2			# 0x2
	sll	$7,$7,8
	or	$7,$7,$8
	li	$6,65535			# 0xffff
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,16($sp)
	.set	macro
	.set	reorder

	li	$2,3			# 0x3
	move	$4,$0
	move	$5,$0
	li	$6,768			# 0x300
	li	$7,256			# 0x100
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,16($sp)
	.set	macro
	.set	reorder

	lw	$3,356($18)
	li	$2,4			# 0x4
	move	$4,$0
	lbu	$7,0($3)
	lbu	$8,1($3)
	move	$5,$0
	sll	$7,$7,8
	or	$7,$7,$8
	li	$6,65535			# 0xffff
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,16($sp)
	.set	macro
	.set	reorder

	lw	$3,356($18)
	li	$2,5			# 0x5
	move	$4,$0
	lbu	$7,2($3)
	lbu	$8,3($3)
	li	$5,1			# 0x1
	sll	$7,$7,8
	or	$7,$7,$8
	li	$6,65535			# 0xffff
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,16($sp)
	.set	macro
	.set	reorder

	lw	$3,356($18)
	li	$2,6			# 0x6
	move	$4,$0
	lbu	$7,4($3)
	lbu	$8,5($3)
	li	$5,2			# 0x2
	sll	$7,$7,8
	or	$7,$7,$8
	li	$6,65535			# 0xffff
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,16($sp)
	.set	macro
	.set	reorder

	li	$2,8			# 0x8
	li	$4,2			# 0x2
	li	$5,1			# 0x1
	li	$6,65532			# 0xfffc
	li	$7,72			# 0x48
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,16($sp)
	.set	macro
	.set	reorder

	li	$2,9			# 0x9
	li	$4,2			# 0x2
	li	$5,1			# 0x1
	move	$6,$0
	move	$7,$0
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,16($sp)
	.set	macro
	.set	reorder

	li	$2,10			# 0xa
	li	$4,3			# 0x3
	li	$5,2			# 0x2
	li	$6,65532			# 0xfffc
	li	$7,32			# 0x20
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,16($sp)
	.set	macro
	.set	reorder

	li	$2,11			# 0xb
	move	$7,$0
	li	$4,3			# 0x3
	li	$5,2			# 0x2
	move	$6,$0
	sw	$2,16($sp)
	.set	noreorder
	.set	nomacro
	jal	$17
	lui	$16,%hi(SetAclControl)
	.set	macro
	.set	reorder

	addiu	$16,$16,%lo(SetAclControl)
	li	$4,263			# 0x107
	move	$5,$0
	.set	noreorder
	.set	nomacro
	jal	$16
	li	$6,16512			# 0x4080
	.set	macro
	.set	reorder

	li	$4,519			# 0x207
	li	$5,1			# 0x1
	.set	noreorder
	.set	nomacro
	jal	$16
	li	$6,32896			# 0x8080
	.set	macro
	.set	reorder

	li	$4,368			# 0x170
	li	$5,2			# 0x2
	.set	noreorder
	.set	nomacro
	jal	$16
	li	$6,16512			# 0x4080
	.set	macro
	.set	reorder

	li	$4,624			# 0x270
	li	$5,3			# 0x3
	.set	noreorder
	.set	nomacro
	jal	$16
	li	$6,32896			# 0x8080
	.set	macro
	.set	reorder

	li	$4,264			# 0x108
	li	$5,4			# 0x4
	.set	noreorder
	.set	nomacro
	jal	$16
	li	$6,32640			# 0x7f80
	.set	macro
	.set	reorder

	li	$4,520			# 0x208
	li	$5,5			# 0x5
	.set	noreorder
	.set	nomacro
	jal	$16
	li	$6,36736			# 0x8f80
	.set	macro
	.set	reorder

	li	$4,1031			# 0x407
	li	$5,6			# 0x6
	.set	noreorder
	.set	nomacro
	jal	$16
	li	$6,16512			# 0x4080
	.set	macro
	.set	reorder

	li	$4,2055			# 0x807
	li	$5,7			# 0x7
	.set	noreorder
	.set	nomacro
	jal	$16
	li	$6,32896			# 0x8080
	.set	macro
	.set	reorder

	li	$4,1136			# 0x470
	li	$5,8			# 0x8
	.set	noreorder
	.set	nomacro
	jal	$16
	li	$6,16512			# 0x4080
	.set	macro
	.set	reorder

	li	$4,2160			# 0x870
	li	$5,9			# 0x9
	.set	noreorder
	.set	nomacro
	jal	$16
	li	$6,32896			# 0x8080
	.set	macro
	.set	reorder

	li	$4,1032			# 0x408
	li	$5,10			# 0xa
	.set	noreorder
	.set	nomacro
	jal	$16
	li	$6,32640			# 0x7f80
	.set	macro
	.set	reorder

	li	$4,2056			# 0x808
	li	$5,11			# 0xb
	.set	noreorder
	.set	nomacro
	jal	$16
	li	$6,36736			# 0x8f80
	.set	macro
	.set	reorder

	lw	$31,36($sp)
	lw	$18,32($sp)
	lw	$17,28($sp)
	lw	$16,24($sp)
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,40
	.set	macro
	.set	reorder

$L1000:
	li	$2,536805376			# 0x1fff0000
	li	$3,-1341063168			# 0xffffffffb0110000
	ori	$8,$2,0xffff
	ori	$3,$3,0x2004
	li	$7,-1610612736			# 0xffffffffa0000000
	li	$6,-1025			# 0xfffffffffffffbff
	li	$5,5			# 0x5
	and	$2,$3,$8
$L1034:
	or	$2,$2,$7
	lw	$4,0($2)
	addiu	$5,$5,-1
	addiu	$3,$3,256
	and	$4,$4,$6
	sw	$4,0($2)
	.set	noreorder
	.set	nomacro
	bgez	$5,$L1034
	and	$2,$3,$8
	.set	macro
	.set	reorder

	lui	$4,%hi(cpu_data)
	addiu	$3,$4,%lo(cpu_data)
	lhu	$2,10($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L1012
#APP
		.set	mips3					
1:	ll	$2, 520($18)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($18)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	addiu	$3,$4,%lo(cpu_data)
$L1032:
	lhu	$2,10($3)
	andi	$2,$2,0x1
	beq	$2,$0,$L1019
#APP
		.set	mips3					
1:	ll	$2, 520($16)		# atomic_sub		
	subu	$2, 1					
	sc	$2, 520($16)					
	beqz	$2, 2f					
	.subsection 2					
2:	b	1b					
	.previous					
	.set	mips0					

#NO_APP
	move	$2,$0
$L1031:
	lw	$31,36($sp)
	lw	$18,32($sp)
	lw	$17,28($sp)
	lw	$16,24($sp)
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,40
	.set	macro
	.set	reorder

$L1019:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($16)
	addiu	$2,$2,-1
	sw	$2,520($16)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L1031
	move	$2,$0
	.set	macro
	.set	reorder

$L1012:
#APP
	raw_local_irq_save	$3
#NO_APP
	lw	$2,520($18)
	addiu	$2,$2,-1
	sw	$2,520($18)
#APP
	raw_local_irq_restore	$3
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L1032
	addiu	$3,$4,%lo(cpu_data)
	.set	macro
	.set	reorder

	.end	SetAclFwd
	.section	.text.SetGdmaFwd,"ax",@progbits
	.align	2
	.globl	SetGdmaFwd
	.ent	SetGdmaFwd
	.type	SetGdmaFwd, @function
SetGdmaFwd:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$2,$2,0xd00
	lw	$5,0($2)
	beq	$4,$0,$L1036
	nop

	li	$2,-30584			# 0xffffffffffff8888
	li	$3,-1341128704			# 0xffffffffb0100000
	and	$5,$5,$2
	ori	$3,$3,0xd00
	move	$2,$0
	sw	$5,0($3)
	j	$31
	nop

$L1036:
	li	$3,-1341128704			# 0xffffffffb0100000
	ori	$5,$5,0x7777
	ori	$3,$3,0xd00
	move	$2,$0
	sw	$5,0($3)
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	SetGdmaFwd
	.section	.text.PpeSetSwVlanChk,"ax",@progbits
	.align	2
	.ent	PpeSetSwVlanChk
	.type	PpeSetSwVlanChk, @function
PpeSetSwVlanChk:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$2,-16777216			# 0xffffffffff000000
	li	$6,-1341063168			# 0xffffffffb0110000
	ori	$8,$2,0xfffc
	li	$3,12582912			# 0xc00000
	li	$2,16711680			# 0xff0000
	ori	$9,$6,0x2604
	ori	$3,$3,0x1
	ori	$2,$2,0x3
	beq	$4,$0,$L1039
	ori	$6,$6,0x2704

	lw	$4,0($9)
	or	$4,$4,$2
	sw	$4,0($9)
	lw	$4,0($6)
	or	$4,$4,$2
	sw	$4,0($6)
	j	$31
	nop

$L1039:
	lw	$4,0($9)
	and	$4,$4,$8
	or	$4,$4,$3
	sw	$4,0($9)
	lw	$4,0($6)
	and	$4,$4,$8
	or	$4,$4,$3
	sw	$4,0($6)
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	PpeSetSwVlanChk
	.section	.text.update_foe_ts_timer_handler,"ax",@progbits
	.align	2
	.globl	update_foe_ts_timer_handler
	.ent	update_foe_ts_timer_handler
	.type	update_foe_ts_timer_handler, @function
update_foe_ts_timer_handler:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$4,-1341128704			# 0xffffffffb0100000
	ori	$4,$4,0x10
	lw	$2,0($4)
	li	$3,1572864			# 0x180000
	lui	$25,%hi(add_timer)
	andi	$2,$2,0xffff
	addiu	$2,$2,1
	or	$2,$2,$3
	sw	$2,0($4)
	lui	$3,%hi(jiffies)
	lw	$5,%lo(jiffies)($3)
	lui	$2,%hi(update_foe_ts_timer)
	addiu	$2,$2,%lo(update_foe_ts_timer)
	addiu	$5,$5,250
	move	$4,$2
	addiu	$25,$25,%lo(add_timer)
	jr	$25
	sw	$5,8($2)

	.set	macro
	.set	reorder
	.end	update_foe_ts_timer_handler
	.section	.text.foe_ts_update_ebl,"ax",@progbits
	.align	2
	.globl	foe_ts_update_ebl
	.ent	foe_ts_update_ebl
	.type	foe_ts_update_ebl, @function
foe_ts_update_ebl:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$2,-1342177280			# 0xffffffffb0000000
	ori	$2,$2,0xc
	lw	$3,0($2)
	li	$2,257			# 0x101
	andi	$3,$3,0xffff
	beq	$3,$2,$L1048
	move	$5,$4

$L1050:
	j	$31
	nop

$L1048:
	lui	$3,%hi(update_foe_ts_timer)
	addiu	$6,$3,%lo(update_foe_ts_timer)
	bne	$5,$0,$L1049
	move	$4,$6

	lw	$2,%lo(update_foe_ts_timer)($3)
	beq	$2,$0,$L1050
	addiu	$4,$3,%lo(update_foe_ts_timer)

	lui	$25,%hi(del_timer)
	addiu	$25,$25,%lo(del_timer)
	jr	$25
	nop

$L1049:
	lui	$3,%hi(jiffies)
	lw	$2,%lo(jiffies)($3)
	lui	$25,%hi(add_timer)
	addiu	$25,$25,%lo(add_timer)
	addiu	$2,$2,250
	jr	$25
	sw	$2,8($6)

	.set	macro
	.set	reorder
	.end	foe_ts_update_ebl
	.section	.text.PpeInitMod,"ax",@progbits
	.align	2
	.ent	PpeInitMod
	.type	PpeInitMod, @function
PpeInitMod:
	.frame	$sp,32,$31		# vars= 0, regs= 4/0, args= 16, gp= 0
	.mask	0x80070000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-32
	lui	$2,%hi(PpeSetDstPort)
	sw	$31,28($sp)
	sw	$18,24($sp)
	sw	$17,20($sp)
	sw	$16,16($sp)
	addiu	$2,$2,%lo(PpeSetDstPort)
	jal	$2
	li	$4,1			# 0x1

	lui	$2,%hi(PpeRegIoctlHandler)
	addiu	$2,$2,%lo(PpeRegIoctlHandler)
	jal	$2
	li	$16,-1341128704			# 0xffffffffb0100000

	li	$2,131072			# 0x20000
	li	$3,524288			# 0x80000
	ori	$9,$16,0xe4c
	ori	$8,$16,0xe48
	ori	$2,$2,0x1
	ori	$3,$3,0x4
	sw	$2,0($8)
	sw	$3,0($9)
	li	$2,2097152			# 0x200000
	li	$3,8388608			# 0x800000
	ori	$10,$16,0xe50
	ori	$11,$16,0xe54
	ori	$2,$2,0x10
	ori	$3,$3,0x40
	sw	$2,0($10)
	ori	$12,$16,0xe58
	sw	$3,0($11)
	ori	$13,$16,0xe08
	li	$3,-1			# 0xffffffffffffffff
	li	$2,4128768			# 0x3f0000
	lui	$17,%hi(RegModifyBits)
	sw	$2,0($12)
	addiu	$17,$17,%lo(RegModifyBits)
	sw	$3,0($13)
	ori	$4,$16,0xf20
	li	$5,1			# 0x1
	li	$6,9			# 0x9
	jal	$17
	li	$7,1			# 0x1

	ori	$4,$16,0xf20
	move	$5,$0
	li	$6,9			# 0x9
	jal	$17
	li	$7,1			# 0x1

	li	$5,1			# 0x1
	move	$6,$0
	li	$7,1			# 0x1
	jal	$17
	ori	$4,$16,0xf20

	lui	$2,%hi(PpeSetSwVlanChk)
	addiu	$2,$2,%lo(PpeSetSwVlanChk)
	jal	$2
	move	$4,$0

	lui	$2,%hi(PpeSetFoeEbl)
	addiu	$2,$2,%lo(PpeSetFoeEbl)
	jal	$2
	li	$4,1			# 0x1

	lui	$18,%hi(PpePhyFoeBase)
	lui	$2,%hi(dma_alloc_coherent)
	addiu	$6,$18,%lo(PpePhyFoeBase)
	li	$7,208			# 0xd0
	move	$4,$0
	addiu	$2,$2,%lo(dma_alloc_coherent)
	jal	$2
	li	$5,1310720			# 0x140000

	lw	$8,%lo(PpePhyFoeBase)($18)
	ori	$3,$16,0xe20
	lui	$7,%hi(PpeFoeBase)
	sw	$8,0($3)
	move	$4,$2
	sw	$2,%lo(PpeFoeBase)($7)
	lui	$2,%hi(memset)
	move	$5,$0
	addiu	$2,$2,%lo(memset)
	jal	$2
	li	$6,1310720			# 0x140000

	ori	$4,$16,0xe1c
	li	$5,4			# 0x4
	move	$6,$0
	jal	$17
	li	$7,3			# 0x3

	ori	$4,$16,0xe1c
	li	$5,1			# 0x1
	li	$6,14			# 0xe
	jal	$17
	li	$7,2			# 0x2

	li	$2,305397760			# 0x12340000
	ori	$3,$16,0xe44
	ori	$2,$2,0x5678
	sw	$2,0($3)
	ori	$4,$16,0xe1c
	li	$5,1			# 0x1
	li	$6,3			# 0x3
	jal	$17
	li	$7,1			# 0x1

	ori	$4,$16,0xe1c
	li	$5,3			# 0x3
	li	$6,4			# 0x4
	jal	$17
	li	$7,2			# 0x2

	ori	$4,$16,0xe1c
	li	$5,1			# 0x1
	li	$6,7			# 0x7
	jal	$17
	li	$7,1			# 0x1

	ori	$4,$16,0xe1c
	li	$5,1			# 0x1
	li	$6,8			# 0x8
	jal	$17
	li	$7,1			# 0x1

	ori	$4,$16,0xe38
	li	$5,1000			# 0x3e8
	li	$6,16			# 0x10
	jal	$17
	li	$7,16			# 0x10

	ori	$4,$16,0xe38
	li	$5,3			# 0x3
	move	$6,$0
	jal	$17
	li	$7,8			# 0x8

	ori	$4,$16,0xe1c
	li	$5,1			# 0x1
	li	$6,9			# 0x9
	jal	$17
	li	$7,1			# 0x1

	ori	$4,$16,0xe1c
	li	$5,1			# 0x1
	li	$6,10			# 0xa
	jal	$17
	li	$7,1			# 0x1

	ori	$4,$16,0xe1c
	li	$5,1			# 0x1
	li	$6,11			# 0xb
	jal	$17
	li	$7,1			# 0x1

	ori	$4,$16,0xe3c
	li	$5,5			# 0x5
	move	$6,$0
	jal	$17
	li	$7,16			# 0x10

	ori	$4,$16,0xe3c
	li	$5,5			# 0x5
	li	$6,16			# 0x10
	jal	$17
	li	$7,16			# 0x10

	ori	$4,$16,0xe40
	li	$5,5			# 0x5
	li	$6,16			# 0x10
	jal	$17
	li	$7,16			# 0x10

	ori	$4,$16,0xe40
	li	$5,5			# 0x5
	move	$6,$0
	jal	$17
	li	$7,16			# 0x10

	ori	$4,$16,0xe1c
	li	$5,3			# 0x3
	li	$6,12			# 0xc
	jal	$17
	li	$7,2			# 0x2

	ori	$4,$16,0xe34
	li	$5,1			# 0x1
	move	$6,$0
	jal	$17
	li	$7,16			# 0x10

	ori	$4,$16,0xe34
	li	$5,1			# 0x1
	li	$6,16			# 0x10
	jal	$17
	li	$7,8			# 0x8

	ori	$4,$16,0xe34
	li	$5,1			# 0x1
	li	$6,24			# 0x18
	jal	$17
	li	$7,8			# 0x8

	ori	$4,$16,0xe30
	li	$5,1			# 0x1
	li	$6,16			# 0x10
	jal	$17
	li	$7,8			# 0x8

	ori	$4,$16,0xe2c
	li	$5,16383			# 0x3fff
	move	$6,$0
	jal	$17
	li	$7,14			# 0xe

	ori	$4,$16,0xe2c
	li	$5,16383			# 0x3fff
	li	$6,16			# 0x10
	jal	$17
	li	$7,14			# 0xe

	move	$6,$0
	li	$7,14			# 0xe
	li	$5,16383			# 0x3fff
	jal	$17
	ori	$4,$16,0xe30

	ori	$16,$16,0xe28
	li	$3,15			# 0xf
	lui	$2,%hi(PpeSetFoeGloCfgEbl)
	sw	$3,0($16)
	addiu	$2,$2,%lo(PpeSetFoeGloCfgEbl)
	jal	$2
	li	$4,1			# 0x1

	lui	$2,%hi(PpeTxHandler)
	lui	$5,%hi(ra_sw_nat_hook_tx)
	addiu	$2,$2,%lo(PpeTxHandler)
	lui	$3,%hi(PpeRxHandler)
	sw	$2,%lo(ra_sw_nat_hook_tx)($5)
	addiu	$3,$3,%lo(PpeRxHandler)
	lui	$2,%hi(ra_sw_nat_hook_rx)
	sw	$3,%lo(ra_sw_nat_hook_rx)($2)
	lui	$2,%hi(SetAclFwd)
	addiu	$2,$2,%lo(SetAclFwd)
	jal	$2
	li	$4,1			# 0x1

	lui	$2,%hi(SetGdmaFwd)
	addiu	$2,$2,%lo(SetGdmaFwd)
	jal	$2
	li	$4,1			# 0x1

	lui	$2,%hi(foe_ts_update_ebl)
	addiu	$2,$2,%lo(foe_ts_update_ebl)
	jal	$2
	li	$4,1			# 0x1

	lw	$31,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,32

	.set	macro
	.set	reorder
	.end	PpeInitMod
	.section	.text.PpeCleanupMod,"ax",@progbits
	.align	2
	.ent	PpeCleanupMod
	.type	PpeCleanupMod, @function
PpeCleanupMod:
	.frame	$sp,24,$31		# vars= 0, regs= 1/0, args= 16, gp= 0
	.mask	0x80000000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-24
	lui	$2,%hi(SetAclFwd)
	sw	$31,16($sp)
	addiu	$2,$2,%lo(SetAclFwd)
	jal	$2
	move	$4,$0

	lui	$2,%hi(SetGdmaFwd)
	addiu	$2,$2,%lo(SetGdmaFwd)
	jal	$2
	move	$4,$0

	lui	$2,%hi(ra_sw_nat_hook_rx)
	lui	$3,%hi(ra_sw_nat_hook_tx)
	sw	$0,%lo(ra_sw_nat_hook_rx)($2)
	lui	$2,%hi(PpeSetFoeGloCfgEbl)
	sw	$0,%lo(ra_sw_nat_hook_tx)($3)
	addiu	$2,$2,%lo(PpeSetFoeGloCfgEbl)
	jal	$2
	move	$4,$0

	lui	$2,%hi(PpeSetFoeEbl)
	addiu	$2,$2,%lo(PpeSetFoeEbl)
	jal	$2
	move	$4,$0

	lui	$3,%hi(PpeFoeBase)
	lui	$2,%hi(PpePhyFoeBase)
	lw	$6,%lo(PpeFoeBase)($3)
	lw	$7,%lo(PpePhyFoeBase)($2)
	lui	$2,%hi(dma_free_coherent)
	li	$5,1310720			# 0x140000
	addiu	$2,$2,%lo(dma_free_coherent)
	jal	$2
	move	$4,$0

	li	$3,-1341128704			# 0xffffffffb0100000
	ori	$3,$3,0xe20
	lui	$2,%hi(PpeUnRegIoctlHandler)
	sw	$0,0($3)
	addiu	$2,$2,%lo(PpeUnRegIoctlHandler)
	jal	$2
	nop

	lui	$2,%hi(PpeSetSwVlanChk)
	addiu	$2,$2,%lo(PpeSetSwVlanChk)
	jal	$2
	li	$4,1			# 0x1

	lui	$2,%hi(PpeSetDstPort)
	addiu	$2,$2,%lo(PpeSetDstPort)
	jal	$2
	move	$4,$0

	lui	$25,%hi(foe_ts_update_ebl)
	lw	$31,16($sp)
	move	$4,$0
	addiu	$25,$25,%lo(foe_ts_update_ebl)
	jr	$25
	addiu	$sp,$sp,24

	.set	macro
	.set	reorder
	.end	PpeCleanupMod
	.globl	PpeFoeBase
	.section	.bss
	.align	2
	.type	PpeFoeBase, @object
	.size	PpeFoeBase, 4
PpeFoeBase:
	.space	4
	.globl	PpePhyFoeBase
	.align	2
	.type	PpePhyFoeBase, @object
	.size	PpePhyFoeBase, 4
PpePhyFoeBase:
	.space	4
	.globl	DstPort
	.align	2
	.type	DstPort, @object
	.size	DstPort, 252
DstPort:
	.space	252
	.globl	PpeParseResult
	.align	2
	.type	PpeParseResult, @object
	.size	PpeParseResult, 132
PpeParseResult:
	.space	132
	.ident	"GCC: (GNU) 3.4.2"
