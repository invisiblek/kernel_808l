	.file	1 "foe_fdb.c"
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
	.section	.text.FoeSetMacInfo,"ax",@progbits
	.align	2
	.globl	FoeSetMacInfo
	.ent	FoeSetMacInfo
	.type	FoeSetMacInfo, @function
FoeSetMacInfo:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lbu	$3,0($5)
	sb	$3,3($4)
	lbu	$2,1($5)
	sb	$2,2($4)
	lbu	$3,2($5)
	sb	$3,1($4)
	lbu	$2,3($5)
	sb	$2,0($4)
	lbu	$3,4($5)
	sb	$3,7($4)
	lbu	$2,5($5)
	j	$31
	sb	$2,6($4)

	.set	macro
	.set	reorder
	.end	FoeSetMacInfo
	.section	.text.FoeGetMacInfo,"ax",@progbits
	.align	2
	.globl	FoeGetMacInfo
	.ent	FoeGetMacInfo
	.type	FoeGetMacInfo, @function
FoeGetMacInfo:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lbu	$3,3($5)
	sb	$3,0($4)
	lbu	$2,2($5)
	sb	$2,1($4)
	lbu	$3,1($5)
	sb	$3,2($4)
	lbu	$2,0($5)
	sb	$2,3($4)
	lbu	$3,7($5)
	sb	$3,4($4)
	lbu	$2,6($5)
	j	$31
	sb	$2,5($4)

	.set	macro
	.set	reorder
	.end	FoeGetMacInfo
	.section	.text.is_request_done,"ax",@progbits
	.align	2
	.ent	is_request_done
	.type	is_request_done, @function
is_request_done:
	.frame	$sp,32,$31		# vars= 0, regs= 4/0, args= 16, gp= 0
	.mask	0x80070000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-32
	li	$2,-1341128704			# 0xffffffffb0100000
	lui	$3,%hi(__udelay)
	sw	$18,24($sp)
	sw	$17,20($sp)
	sw	$16,16($sp)
	ori	$18,$2,0xf20
	addiu	$17,$3,%lo(__udelay)
	li	$16,1000			# 0x3e8
	j	$L4
	sw	$31,28($sp)

$L7:
	jal	$17
	nop

	beq	$16,$0,$L3
	move	$2,$0

$L4:
	lw	$2,0($18)
	addiu	$16,$16,-1
	srl	$2,$2,8
	xori	$2,$2,0x1
	andi	$2,$2,0x1
	beq	$2,$0,$L7
	li	$4,1000			# 0x3e8

	li	$2,1			# 0x1
$L3:
	lw	$31,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	j	$31
	addiu	$sp,$sp,32

	.set	macro
	.set	reorder
	.end	is_request_done
	.rdata
	.align	2
	.type	__func__.0, @object
	.size	__func__.0, 18
__func__.0:
	.ascii	"FoeDumpCacheEntry\000"
	.section	.rodata.cst4,"aM",@progbits,4
	.align	2
$LC8:
	.word	RegModifyBits
	.align	2
$LC9:
	.word	is_request_done
	.section	.text.FoeDumpCacheEntry,"ax",@progbits
	.align	2
	.globl	FoeDumpCacheEntry
	.ent	FoeDumpCacheEntry
	.type	FoeDumpCacheEntry, @function
FoeDumpCacheEntry:
	.frame	$sp,56,$31		# vars= 0, regs= 10/0, args= 16, gp= 0
	.mask	0xc0ff0000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-56
	li	$2,-1341128704			# 0xffffffffb0100000
	sw	$fp,48($sp)
	ori	$4,$2,0xf20
	sw	$31,52($sp)
	sw	$23,44($sp)
	sw	$22,40($sp)
	sw	$21,36($sp)
	sw	$20,32($sp)
	sw	$19,28($sp)
	sw	$18,24($sp)
	sw	$17,20($sp)
	sw	$16,16($sp)
	lw	$3,0($4)
	move	$fp,$0
	andi	$3,$3,0x1
	bne	$3,$0,$L41
	move	$2,$0

	lw	$31,52($sp)
	lw	$fp,48($sp)
	lw	$23,44($sp)
	lw	$22,40($sp)
	lw	$21,36($sp)
	lw	$20,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	j	$31
	addiu	$sp,$sp,56

$L41:
	lui	$2,%hi(RegModifyBits)
	addiu	$16,$2,%lo(RegModifyBits)
	li	$20,-1341128704			# 0xffffffffb0100000
	move	$5,$0
	move	$6,$0
	jal	$16
	li	$7,1			# 0x1

	move	$23,$16
	ori	$21,$20,0xf30
	ori	$22,$20,0xf2c
	ori	$4,$20,0xf28
$L44:
	move	$5,$fp
	move	$6,$0
	jal	$23
	li	$7,15			# 0xf

	ori	$4,$20,0xf28
	li	$5,31			# 0x1f
	li	$6,16			# 0x10
	jal	$23
	li	$7,8			# 0x8

	ori	$4,$20,0xf20
	li	$5,2			# 0x2
	li	$6,12			# 0xc
	jal	$23
	li	$7,2			# 0x2

	ori	$4,$20,0xf20
	li	$5,1			# 0x1
	li	$6,8			# 0x8
	jal	$23
	li	$7,1			# 0x1

	lui	$3,%hi(is_request_done)
	addiu	$3,$3,%lo(is_request_done)
	jal	$3
	nop

	beq	$2,$0,$L42
	ori	$4,$20,0xf20

	lw	$2,0($21)
	lw	$3,0($21)
	ori	$4,$20,0xf20
$L42:
	li	$5,3			# 0x3
	li	$6,12			# 0xc
	jal	$23
	li	$7,2			# 0x2

	ori	$4,$20,0xf20
	li	$5,1			# 0x1
	li	$6,8			# 0x8
	li	$7,1			# 0x1
	sw	$0,0($22)
	jal	$23
	move	$18,$0

	lui	$3,%hi(is_request_done)
	addiu	$3,$3,%lo(is_request_done)
	jal	$3
	li	$17,-1341128704			# 0xffffffffb0100000

	lui	$2,%hi($LC8)
	addiu	$2,$2,%lo($LC8)
	lw	$16,0($2)
	lui	$3,%hi($LC9)
	addiu	$3,$3,%lo($LC9)
	lw	$19,0($3)
	move	$5,$18
$L43:
	ori	$4,$17,0xf28
	li	$6,16			# 0x10
	jal	$16
	li	$7,8			# 0x8

	ori	$4,$17,0xf20
	li	$5,2			# 0x2
	li	$6,12			# 0xc
	jal	$16
	li	$7,2			# 0x2

	ori	$4,$17,0xf20
	li	$5,1			# 0x1
	li	$6,8			# 0x8
	jal	$16
	li	$7,1			# 0x1

	jal	$19
	addiu	$18,$18,1

	ori	$4,$17,0xf20
	li	$5,3			# 0x3
	li	$6,12			# 0xc
	beq	$2,$0,$L30
	li	$7,2			# 0x2

	lw	$2,0($21)
$L30:
	jal	$16
	nop

	ori	$4,$17,0xf20
	li	$5,1			# 0x1
	li	$6,8			# 0x8
	li	$7,1			# 0x1
	sw	$0,0($22)
	jal	$16
	nop

	jal	$19
	nop

	slt	$3,$18,16
	bne	$3,$0,$L43
	move	$5,$18

	addiu	$fp,$fp,1
	slt	$2,$fp,16
	bne	$2,$0,$L44
	ori	$4,$20,0xf28

	lui	$2,%hi(RegModifyBits)
	li	$16,-1341128704			# 0xffffffffb0100000
	addiu	$17,$2,%lo(RegModifyBits)
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

	ori	$4,$16,0xf20
	li	$5,1			# 0x1
	move	$6,$0
	jal	$17
	li	$7,1			# 0x1

	lw	$31,52($sp)
	lw	$fp,48($sp)
	lw	$23,44($sp)
	lw	$22,40($sp)
	lw	$21,36($sp)
	lw	$20,32($sp)
	lw	$19,28($sp)
	lw	$18,24($sp)
	lw	$17,20($sp)
	lw	$16,16($sp)
	li	$2,1			# 0x1
	j	$31
	addiu	$sp,$sp,56

	.set	macro
	.set	reorder
	.end	FoeDumpCacheEntry
	.section	.text.FoeDumpEntry,"ax",@progbits
	.align	2
	.globl	FoeDumpEntry
	.ent	FoeDumpEntry
	.type	FoeDumpEntry, @function
FoeDumpEntry:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lui	$2,%hi(PpeFoeBase)
	sll	$3,$4,2
	lw	$5,%lo(PpeFoeBase)($2)
	addu	$3,$3,$4
	sll	$3,$3,4
	addu	$2,$3,$5
	li	$4,19			# 0x13
	addiu	$4,$4,-1
$L74:
	bgez	$4,$L74
	addiu	$4,$4,-1

	addiu	$4,$4,1
	lw	$2,0($2)
	srl	$2,$2,25
	andi	$3,$2,0x7
	beq	$3,$0,$L76
	li	$2,1			# 0x1

	beq	$3,$2,$L76
	li	$2,2			# 0x2

	beq	$3,$2,$L76
	li	$2,3			# 0x3

	beq	$3,$2,$L76
	li	$2,4			# 0x4

	beq	$3,$2,$L76
	li	$2,5			# 0x5

	beq	$3,$2,$L72
	li	$2,7			# 0x7

	bne	$3,$2,$L76
	li	$2,-1341128704			# 0xffffffffb0100000

	ori	$2,$2,0xe04
	lw	$3,0($2)
$L76:
	j	$31
	nop

$L72:
	li	$2,-1341128704			# 0xffffffffb0100000
	ori	$2,$2,0xe04
	lw	$3,0($2)
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	FoeDumpEntry
	.section	.text.FoeGetAllEntries,"ax",@progbits
	.align	2
	.globl	FoeGetAllEntries
	.ent	FoeGetAllEntries
	.type	FoeGetAllEntries, @function
FoeGetAllEntries:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	move	$9,$0
	li	$2,-1341128704			# 0xffffffffb0100000
	move	$10,$4
	ori	$12,$2,0xe04
	move	$7,$9
	lui	$11,%hi(PpeFoeBase)
	move	$8,$0
	j	$L95
	move	$6,$4

$L80:
	addiu	$7,$7,1
	slt	$2,$7,16384
	beq	$2,$0,$L102
	addiu	$8,$8,80

$L95:
	lw	$4,%lo(PpeFoeBase)($11)
	lw	$3,0($10)
	addu	$5,$8,$4
	lw	$2,0($5)
	srl	$3,$3,3
	andi	$3,$3,0x3
	srl	$2,$2,28
	andi	$2,$2,0x3
	bne	$2,$3,$L80
	nop

	sh	$7,12($6)
	lw	$2,0($5)
	srl	$2,$2,25
	andi	$2,$2,0x7
	sb	$2,14($6)
	lw	$3,0($5)
	li	$2,1			# 0x1
	srl	$3,$3,25
	andi	$3,$3,0x7
	beq	$3,$2,$L103
	nop

	bne	$3,$0,$L84
	li	$2,2			# 0x2

	lw	$3,4($5)
	addiu	$9,$9,1
	sw	$3,36($6)
	lw	$2,8($5)
	sw	$2,40($6)
	lw	$3,20($5)
	sw	$3,76($6)
	lw	$2,24($5)
	sw	$2,80($6)
	lhu	$3,14($5)
	sh	$3,118($6)
	lhu	$2,12($5)
	sh	$2,120($6)
	lhu	$3,30($5)
	sh	$3,122($6)
	lhu	$2,28($5)
	sh	$2,124($6)
	addiu	$6,$6,120
$L108:
	addiu	$7,$7,1
	slt	$2,$7,16384
	bne	$2,$0,$L95
	addiu	$8,$8,80

$L102:
	andi	$3,$9,0xffff
	li	$2,2			# 0x2
	movn	$2,$0,$3
	j	$31
	sh	$9,10($10)

$L84:
	beq	$3,$2,$L104
	li	$2,3			# 0x3

	beq	$3,$2,$L105
	li	$2,4			# 0x4

	beq	$3,$2,$L106
	li	$2,5			# 0x5

	beq	$3,$2,$L107
	li	$2,7			# 0x7

	bne	$3,$2,$L80
	nop

	lw	$3,4($5)
	addiu	$9,$9,1
	sw	$3,44($6)
	lw	$2,8($5)
	sw	$2,48($6)
	lw	$3,12($5)
	sw	$3,52($6)
	lw	$2,16($5)
	sw	$2,56($6)
	lw	$3,20($5)
	sw	$3,60($6)
	lw	$2,24($5)
	sw	$2,64($6)
	lw	$3,28($5)
	sw	$3,68($6)
	lw	$2,32($5)
	sw	$2,72($6)
	lhu	$3,38($5)
	sh	$3,118($6)
	lhu	$4,36($5)
	sh	$4,120($6)
	lw	$2,0($12)
	srl	$2,$2,18
	andi	$2,$2,0x1
	sb	$2,126($6)
	lw	$3,40($5)
	sw	$3,76($6)
	lw	$2,44($5)
	sw	$2,80($6)
$L109:
	j	$L108
	addiu	$6,$6,120

$L103:
	lw	$3,4($5)
	addiu	$9,$9,1
	sw	$3,36($6)
	lw	$2,8($5)
	sw	$2,40($6)
	lw	$3,20($5)
	sw	$3,76($6)
	lw	$2,24($5)
	j	$L109
	sw	$2,80($6)

$L104:
	lw	$3,24($5)
	addiu	$9,$9,1
	sw	$3,60($6)
	lw	$2,20($5)
	sw	$2,64($6)
	lw	$3,8($5)
	sw	$3,68($6)
	lw	$2,4($5)
	sw	$2,72($6)
	j	$L108
	addiu	$6,$6,120

$L105:
	lw	$3,4($5)
	addiu	$9,$9,1
	sw	$3,36($6)
	lw	$2,8($5)
	sw	$2,40($6)
	lhu	$3,14($5)
	sh	$3,118($6)
	lhu	$2,12($5)
	sh	$2,120($6)
	lw	$3,16($5)
	sw	$3,84($6)
	lw	$2,20($5)
	sw	$2,88($6)
	lw	$3,24($5)
	sw	$3,92($6)
	lw	$2,28($5)
	sw	$2,96($6)
	lw	$3,32($5)
	sw	$3,100($6)
	lw	$2,36($5)
	sw	$2,104($6)
	lw	$3,40($5)
	sw	$3,108($6)
	lw	$2,44($5)
	sw	$2,112($6)
	j	$L108
	addiu	$6,$6,120

$L106:
	lw	$3,4($5)
	addiu	$9,$9,1
	sw	$3,44($6)
	lw	$2,8($5)
	sw	$2,48($6)
	lw	$3,12($5)
	sw	$3,52($6)
	lw	$2,16($5)
	sw	$2,56($6)
	lw	$3,20($5)
	sw	$3,60($6)
	lw	$2,24($5)
	sw	$2,64($6)
	lw	$3,28($5)
	sw	$3,68($6)
	lw	$2,32($5)
	sw	$2,72($6)
	lbu	$3,36($5)
	sb	$3,116($6)
	j	$L108
	addiu	$6,$6,120

$L107:
	lw	$3,4($5)
	addiu	$9,$9,1
	sw	$3,44($6)
	lw	$2,8($5)
	sw	$2,48($6)
	lw	$3,12($5)
	sw	$3,52($6)
	lw	$2,16($5)
	sw	$2,56($6)
	lhu	$3,38($5)
	sh	$3,118($6)
	lhu	$2,36($5)
	sh	$2,120($6)
	lw	$3,20($5)
	sw	$3,60($6)
	lw	$2,24($5)
	sw	$2,64($6)
	lw	$3,28($5)
	sw	$3,68($6)
	lw	$4,32($5)
	sw	$4,72($6)
	lw	$2,0($12)
	srl	$2,$2,18
	andi	$2,$2,0x1
	sb	$2,126($6)
	j	$L108
	addiu	$6,$6,120

	.set	macro
	.set	reorder
	.end	FoeGetAllEntries
	.section	.text.FoeBindEntry,"ax",@progbits
	.align	2
	.globl	FoeBindEntry
	.ent	FoeBindEntry
	.type	FoeBindEntry, @function
FoeBindEntry:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lhu	$3,8($4)
	lui	$2,%hi(PpeFoeBase)
	lw	$4,%lo(PpeFoeBase)($2)
	sll	$5,$3,2
	addu	$5,$5,$3
	sll	$5,$5,4
	li	$2,-1341128704			# 0xffffffffb0100000
	addu	$5,$5,$4
	ori	$2,$2,0x10
	lw	$4,0($2)
	lw	$3,0($5)
	li	$2,-32768			# 0xffffffffffff8000
	andi	$4,$4,0x7fff
	and	$3,$3,$2
	li	$2,-805371904			# 0xffffffffcfff0000
	or	$3,$3,$4
	ori	$2,$2,0xffff
	and	$3,$3,$2
	li	$4,536870912			# 0x20000000
	or	$3,$3,$4
	move	$2,$0
	j	$31
	sw	$3,0($5)

	.set	macro
	.set	reorder
	.end	FoeBindEntry
	.section	.text.FoeUnBindEntry,"ax",@progbits
	.align	2
	.globl	FoeUnBindEntry
	.ent	FoeUnBindEntry
	.type	FoeUnBindEntry, @function
FoeUnBindEntry:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lhu	$5,8($4)
	lui	$2,%hi(PpeFoeBase)
	lw	$6,%lo(PpeFoeBase)($2)
	sll	$3,$5,2
	addu	$3,$3,$5
	sll	$3,$3,4
	addu	$3,$3,$6
	lw	$4,0($3)
	li	$2,-805371904			# 0xffffffffcfff0000
	ori	$2,$2,0xffff
	and	$4,$4,$2
	li	$5,268435456			# 0x10000000
	or	$4,$4,$5
	li	$2,-1341128704			# 0xffffffffb0100000
	sw	$4,0($3)
	ori	$2,$2,0x10
	lw	$4,0($2)
	move	$2,$0
	j	$31
	sb	$4,0($3)

	.set	macro
	.set	reorder
	.end	FoeUnBindEntry
	.section	.text.FoeDelEntryByNum,"ax",@progbits
	.align	2
	.globl	FoeDelEntryByNum
	.ent	FoeDelEntryByNum
	.type	FoeDelEntryByNum, @function
FoeDelEntryByNum:
	.frame	$sp,24,$31		# vars= 0, regs= 1/0, args= 16, gp= 0
	.mask	0x80000000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lui	$3,%hi(PpeFoeBase)
	lw	$5,%lo(PpeFoeBase)($3)
	sll	$2,$4,2
	addu	$2,$2,$4
	sll	$2,$2,4
	addiu	$sp,$sp,-24
	addu	$4,$2,$5
	lui	$2,%hi(memset)
	sw	$31,16($sp)
	move	$5,$0
	addiu	$2,$2,%lo(memset)
	jal	$2
	li	$6,80			# 0x50

	lw	$31,16($sp)
	move	$2,$0
	j	$31
	addiu	$sp,$sp,24

	.set	macro
	.set	reorder
	.end	FoeDelEntryByNum
	.section	.text.FoeTblClean,"ax",@progbits
	.align	2
	.globl	FoeTblClean
	.ent	FoeTblClean
	.type	FoeTblClean, @function
FoeTblClean:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	lui	$2,%hi(PpeFoeBase)
	lw	$4,%lo(PpeFoeBase)($2)
	lui	$25,%hi(memset)
	move	$5,$0
	addiu	$25,$25,%lo(memset)
	jr	$25
	li	$6,1310720			# 0x140000

	.set	macro
	.set	reorder
	.end	FoeTblClean
	.ident	"GCC: (GNU) 3.4.2"
