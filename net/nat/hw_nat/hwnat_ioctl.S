	.file	1 "hwnat_ioctl.c"
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
	.globl	hw_nat_fops
	.data
	.align	2
	.type	hw_nat_fops, @object
	.size	hw_nat_fops, 100
hw_nat_fops:
	.space	32
	.word	HwNatIoctl
	.space	64
	.globl	DebugLevel
	.align	2
	.type	DebugLevel, @object
	.size	DebugLevel, 4
DebugLevel:
	.word	1
	.globl	wan_vid
	.type	wan_vid, @object
	.size	wan_vid, 1
wan_vid:
	.byte	2
	.globl	lan_vid
	.type	lan_vid, @object
	.size	lan_vid, 1
lan_vid:
	.byte	1
	.globl	bind_dir
	.type	bind_dir, @object
	.size	bind_dir, 1
bind_dir:
	.byte	2
	.section	.text.PpeGetAGCnt,"ax",@progbits
	.align	2
	.globl	PpeGetAGCnt
	.ent	PpeGetAGCnt
	.type	PpeGetAGCnt, @function
PpeGetAGCnt:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lbu	$3,0($4)
	li	$6,-1341128704			# 0xffffffffb0100000
	ori	$2,$6,0x1000
	sll	$3,$3,3
	li	$5,536805376			# 0x1fff0000
	ori	$5,$5,0xffff
	addu	$2,$3,$2
	li	$8,-1610612736			# 0xffffffffa0000000
	and	$2,$2,$5
	or	$2,$2,$8
	lw	$7,0($2)
	ori	$6,$6,0x1004
	addu	$3,$3,$6
	and	$3,$3,$5
	sw	$7,8($4)
	or	$3,$3,$8
	lw	$5,0($3)
	move	$2,$0
	j	$31
	sw	$5,4($4)

	.set	macro
	.set	reorder
	.end	PpeGetAGCnt
	.section	.text.PpeSetBindThreshold,"ax",@progbits
	.align	2
	.globl	PpeSetBindThreshold
	.ent	PpeSetBindThreshold
	.type	PpeSetBindThreshold, @function
PpeSetBindThreshold:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$2,$2,0xe28
	sw	$4,0($2)
	j	$31
	move	$2,$0

	.set	macro
	.set	reorder
	.end	PpeSetBindThreshold
	.section	.rodata.str1.4,"aMS",@progbits,1
	.align	2
$LC0:
	.ascii	"hwnat0\000"
	.section	.text.PpeRegIoctlHandler,"ax",@progbits
	.align	2
	.globl	PpeRegIoctlHandler
	.ent	PpeRegIoctlHandler
	.type	PpeRegIoctlHandler, @function
PpeRegIoctlHandler:
	.frame	$sp,32,$31		# vars= 0, regs= 1/0, args= 24, gp= 0
	.mask	0x80000000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lui	$2,%hi(hw_nat_fops)
	addiu	$sp,$sp,-32
	addiu	$2,$2,%lo(hw_nat_fops)
	sw	$2,16($sp)
	lui	$7,%hi($LC0)
	lui	$2,%hi(__register_chrdev)
	sw	$31,24($sp)
	addiu	$7,$7,%lo($LC0)
	li	$4,220			# 0xdc
	move	$5,$0
	addiu	$2,$2,%lo(__register_chrdev)
	jal	$2
	li	$6,256			# 0x100

	lw	$31,24($sp)
	slt	$3,$2,0
	movz	$2,$0,$3
	j	$31
	addiu	$sp,$sp,32

	.set	macro
	.set	reorder
	.end	PpeRegIoctlHandler
	.section	.text.PpeUnRegIoctlHandler,"ax",@progbits
	.align	2
	.globl	PpeUnRegIoctlHandler
	.ent	PpeUnRegIoctlHandler
	.type	PpeUnRegIoctlHandler, @function
PpeUnRegIoctlHandler:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lui	$7,%hi($LC0)
	lui	$25,%hi(__unregister_chrdev)
	addiu	$7,$7,%lo($LC0)
	li	$4,220			# 0xdc
	move	$5,$0
	addiu	$25,$25,%lo(__unregister_chrdev)
	jr	$25
	li	$6,256			# 0x100

	.set	macro
	.set	reorder
	.end	PpeUnRegIoctlHandler
	.section	.text.PpeSetBindLifetime,"ax",@progbits
	.align	2
	.globl	PpeSetBindLifetime
	.ent	PpeSetBindLifetime
	.type	PpeSetBindLifetime, @function
PpeSetBindLifetime:
	.frame	$sp,40,$31		# vars= 0, regs= 5/0, args= 16, gp= 0
	.mask	0x800f0000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-40
	sw	$17,20($sp)
	sw	$16,16($sp)
	li	$17,-1341128704			# 0xffffffffb0100000
	lui	$16,%hi(RegModifyBits)
	sw	$31,32($sp)
	addiu	$16,$16,%lo(RegModifyBits)
	sw	$19,28($sp)
	sw	$18,24($sp)
	andi	$19,$4,0xffff
	andi	$18,$6,0xffff
	ori	$4,$17,0xe3c
	andi	$5,$5,0xffff
	move	$6,$0
	jal	$16
	li	$7,16			# 0x10

	move	$5,$18
	ori	$4,$17,0xe40
	li	$6,16			# 0x10
	jal	$16
	li	$7,16			# 0x10

	ori	$4,$17,0xe40
	move	$5,$19
	move	$6,$0
	jal	$16
	li	$7,16			# 0x10

	lw	$31,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,40

	.set	macro
	.set	reorder
	.end	PpeSetBindLifetime
	.section	.text.PpeSetUnbindLifeTime,"ax",@progbits
	.align	2
	.globl	PpeSetUnbindLifeTime
	.ent	PpeSetUnbindLifeTime
	.type	PpeSetUnbindLifeTime, @function
PpeSetUnbindLifeTime:
	.frame	$sp,24,$31		# vars= 0, regs= 1/0, args= 16, gp= 0
	.mask	0x80000000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-24
	andi	$5,$4,0x00ff
	lui	$2,%hi(RegModifyBits)
	li	$4,-1341128704			# 0xffffffffb0100000
	sw	$31,16($sp)
	addiu	$2,$2,%lo(RegModifyBits)
	ori	$4,$4,0xe38
	move	$6,$0
	jal	$2
	li	$7,8			# 0x8

	lw	$31,16($sp)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,24

	.set	macro
	.set	reorder
	.end	PpeSetUnbindLifeTime
	.section	.text.PpeSetKaInterval,"ax",@progbits
	.align	2
	.globl	PpeSetKaInterval
	.ent	PpeSetKaInterval
	.type	PpeSetKaInterval, @function
PpeSetKaInterval:
	.frame	$sp,32,$31		# vars= 0, regs= 4/0, args= 16, gp= 0
	.mask	0x80070000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-32
	sw	$17,20($sp)
	sw	$16,16($sp)
	li	$17,-1341128704			# 0xffffffffb0100000
	andi	$4,$4,0x00ff
	lui	$16,%hi(RegModifyBits)
	sw	$31,28($sp)
	sw	$18,24($sp)
	addiu	$16,$16,%lo(RegModifyBits)
	andi	$18,$5,0x00ff
	li	$6,16			# 0x10
	move	$5,$4
	li	$7,8			# 0x8
	jal	$16
	ori	$4,$17,0xe34

	ori	$4,$17,0xe34
	move	$5,$18
	li	$6,24			# 0x18
	jal	$16
	li	$7,8			# 0x8

	lw	$31,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,32

	.set	macro
	.set	reorder
	.end	PpeSetKaInterval
	.section	.text.PpeSetMaxEntryLimit,"ax",@progbits
	.align	2
	.globl	PpeSetMaxEntryLimit
	.ent	PpeSetMaxEntryLimit
	.type	PpeSetMaxEntryLimit, @function
PpeSetMaxEntryLimit:
	.frame	$sp,40,$31		# vars= 0, regs= 5/0, args= 16, gp= 0
	.mask	0x800f0000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-40
	sw	$17,20($sp)
	sw	$16,16($sp)
	li	$17,-1341128704			# 0xffffffffb0100000
	lui	$16,%hi(RegModifyBits)
	sw	$31,32($sp)
	addiu	$16,$16,%lo(RegModifyBits)
	sw	$19,28($sp)
	sw	$18,24($sp)
	move	$19,$4
	move	$18,$5
	ori	$4,$17,0xe2c
	move	$5,$6
	li	$7,14			# 0xe
	jal	$16
	move	$6,$0

	move	$5,$18
	ori	$4,$17,0xe2c
	li	$6,16			# 0x10
	jal	$16
	li	$7,14			# 0xe

	ori	$4,$17,0xe30
	move	$5,$19
	move	$6,$0
	jal	$16
	li	$7,14			# 0xe

	lw	$31,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,40

	.set	macro
	.set	reorder
	.end	PpeSetMaxEntryLimit
	.section	.text.HwNatIoctl,"ax",@progbits
	.align	2
	.globl	HwNatIoctl
	.ent	HwNatIoctl
	.type	HwNatIoctl, @function
HwNatIoctl:
	.frame	$sp,24,$31		# vars= 0, regs= 2/0, args= 16, gp= 0
	.mask	0x80010000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-24
	sltu	$2,$5,30
	sw	$16,16($sp)
	sw	$31,20($sp)
	beq	$2,$0,$L15
	move	$16,$6

	lui	$3,%hi($L32)
	sll	$2,$5,2
	addiu	$3,$3,%lo($L32)
	addu	$2,$2,$3
	lw	$4,0($2)
	j	$4
	nop

	.rdata
	.align	2
$L32:
	.word	$L15
	.word	$L15
	.word	$L21
	.word	$L20
	.word	$L16
	.word	$L17
	.word	$L18
	.word	$L19
	.word	$L22
	.word	$L23
	.word	$L15
	.word	$L15
	.word	$L15
	.word	$L15
	.word	$L15
	.word	$L15
	.word	$L15
	.word	$L15
	.word	$L15
	.word	$L15
	.word	$L15
	.word	$L15
	.word	$L24
	.word	$L25
	.word	$L15
	.word	$L26
	.word	$L27
	.word	$L28
	.word	$L29
	.word	$L30
	.section	.text.HwNatIoctl
$L30:
	lhu	$3,24($6)
	lui	$2,%hi(wan_vid)
	sb	$3,%lo(wan_vid)($2)
	lhu	$4,26($6)
	lui	$2,%hi(lan_vid)
	sb	$4,%lo(lan_vid)($2)
$L15:
	lw	$31,20($sp)
$L41:
	lw	$16,16($sp)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,24

$L29:
	lw	$2,28($6)
	lui	$3,%hi(bind_dir)
	andi	$2,$2,0x3
	j	$L15
	sb	$2,%lo(bind_dir)($3)

$L28:
	lhu	$4,18($6)
	lhu	$5,20($6)
	lui	$2,%hi(PpeSetBindLifetime)
	addiu	$2,$2,%lo(PpeSetBindLifetime)
	jal	$2
	lhu	$6,22($6)

	sw	$2,32($16)
$L38:
	lw	$31,20($sp)
	lw	$16,16($sp)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,24

$L27:
	lui	$2,%hi(PpeSetUnbindLifeTime)
	addiu	$2,$2,%lo(PpeSetUnbindLifeTime)
	jal	$2
	lbu	$4,17($6)

	j	$L38
	sw	$2,32($16)

$L26:
	lw	$4,12($6)
	lbu	$5,16($6)
	lui	$2,%hi(PpeSetKaInterval)
	srl	$4,$4,18
	addiu	$2,$2,%lo(PpeSetKaInterval)
	jal	$2
	andi	$4,$4,0x00ff

	j	$L38
	sw	$2,32($16)

$L25:
	lw	$5,4($6)
	lhu	$4,2($6)
	lui	$2,%hi(PpeSetMaxEntryLimit)
	srl	$6,$5,14
	andi	$4,$4,0x3fff
	andi	$5,$5,0x3fff
	addiu	$2,$2,%lo(PpeSetMaxEntryLimit)
	jal	$2
	andi	$6,$6,0x3fff

	j	$L38
	sw	$2,32($16)

$L24:
	lui	$2,%hi(PpeSetBindThreshold)
	addiu	$2,$2,%lo(PpeSetBindThreshold)
	jal	$2
	lhu	$4,0($6)

	j	$L38
	sw	$2,32($16)

$L23:
	lui	$2,%hi(PpeGetAGCnt)
	addiu	$2,$2,%lo(PpeGetAGCnt)
	jal	$2
	move	$4,$6

	j	$L15
	sw	$2,12($16)

$L22:
	lw	$2,0($6)
	lui	$3,%hi(DebugLevel)
	andi	$2,$2,0x7
	j	$L15
	sw	$2,%lo(DebugLevel)($3)

$L19:
	lui	$2,%hi(FoeDelEntryByNum)
	addiu	$2,$2,%lo(FoeDelEntryByNum)
	jal	$2
	lhu	$4,8($6)

	sw	$2,4($16)
$L40:
	lw	$31,20($sp)
	lw	$16,16($sp)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,24

$L18:
	lui	$2,%hi(FoeUnBindEntry)
	addiu	$2,$2,%lo(FoeUnBindEntry)
	jal	$2
	move	$4,$6

	j	$L40
	sw	$2,4($16)

$L17:
	lui	$2,%hi(FoeBindEntry)
	addiu	$2,$2,%lo(FoeBindEntry)
	jal	$2
	move	$4,$6

	j	$L40
	sw	$2,4($16)

$L16:
	lui	$2,%hi(FoeGetAllEntries)
	addiu	$2,$2,%lo(FoeGetAllEntries)
	jal	$2
	move	$4,$6

	j	$L40
	sw	$2,4($16)

$L20:
	lui	$2,%hi(FoeDumpEntry)
	addiu	$2,$2,%lo(FoeDumpEntry)
	jal	$2
	lhu	$4,8($6)

	j	$L41
	lw	$31,20($sp)

$L21:
	lui	$2,%hi(FoeDumpCacheEntry)
	addiu	$2,$2,%lo(FoeDumpCacheEntry)
	jal	$2
	nop

	j	$L41
	lw	$31,20($sp)

	.set	macro
	.set	reorder
	.end	HwNatIoctl
	.ident	"GCC: (GNU) 3.4.2"
