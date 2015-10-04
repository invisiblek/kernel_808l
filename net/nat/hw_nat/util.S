	.file	1 "util.c"
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
	.section	.text.MacReverse,"ax",@progbits
	.align	2
	.globl	MacReverse
	.ent	MacReverse
	.type	MacReverse, @function
MacReverse:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	move	$8,$4
	li	$2,5			# 0x5
$L5:
	addu	$5,$2,$8
	subu	$6,$8,$2
	lbu	$7,0($5)
	lbu	$3,5($6)
	addiu	$2,$2,-1
	andi	$2,$2,0x00ff
	sltu	$4,$2,3
	sb	$3,0($5)
	beq	$4,$0,$L5
	sb	$7,5($6)

	j	$31
	nop

	.set	macro
	.set	reorder
	.end	MacReverse
	.section	.text.GetNext,"ax",@progbits
	.align	2
	.globl	GetNext
	.ent	GetNext
	.type	GetNext, @function
GetNext:
	.frame	$sp,32,$31		# vars= 0, regs= 3/0, args= 16, gp= 0
	.mask	0x80030000,-8
	.fmask	0x00000000,0
	addiu	$sp,$sp,-32
	sw	$17,20($sp)
	sw	$16,16($sp)
	sw	$31,24($sp)
	move	$17,$4
	li	$2,-1			# 0xffffffffffffffff
	.set	noreorder
	.set	nomacro
	beq	$4,$0,$L9
	move	$16,$6
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	beq	$6,$0,$L19
	lw	$31,24($sp)
	.set	macro
	.set	reorder

	lui	$2,%hi(strchr)
	addiu	$2,$2,%lo(strchr)
	jal	$2
	.set	noreorder
	.set	nomacro
	beq	$2,$0,$L16
	subu	$5,$2,$17
	.set	macro
	.set	reorder

	.set	noreorder
	.set	nomacro
	bne	$5,$0,$L17
	move	$4,$16
	.set	macro
	.set	reorder

	addu	$2,$16,$5
$L18:
	sb	$0,0($2)
	addiu	$2,$5,1
$L9:
	lw	$31,24($sp)
$L19:
	lw	$17,20($sp)
	lw	$16,16($sp)
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,32
	.set	macro
	.set	reorder

$L17:
	move	$2,$5
#APP
	.set	noreorder
	.set	noat
1:	lbu	$1,($17)
	subu	$2,1
	sb	$1,($4)
	beqz	$1,2f
	addiu	$4,1
	bnez	$2,1b
	addiu	$17,1
2:
	.set	at
	.set	reorder
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L18
	addu	$2,$16,$5
	.set	macro
	.set	reorder

$L16:
#APP
	.set	noreorder
	.set	noat
1:	lbu	$1,($17)
	addiu	$17,1
	sb	$1,($16)
	bnez	$1,1b
	addiu	$16,1
	.set	at
	.set	reorder
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$L9
	li	$2,-1			# 0xffffffffffffffff
	.set	macro
	.set	reorder

	.end	GetNext
	.local	Buf.0
	.comm	Buf.0,32,4
	.section	.rodata.str1.4,"aMS",@progbits,1
	.align	2
$LC0:
	.ascii	"%d.%d.%d.%d\000"
	.section	.text.Ip2Str,"ax",@progbits
	.align	2
	.globl	Ip2Str
	.ent	Ip2Str
	.type	Ip2Str, @function
Ip2Str:
	.frame	$sp,40,$31		# vars= 8, regs= 2/0, args= 24, gp= 0
	.mask	0x80010000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-40
	sw	$4,40($sp)
	lbu	$8,40($sp)
	lbu	$9,41($sp)
	lbu	$10,42($sp)
	lbu	$11,43($sp)
	sw	$16,32($sp)
	lui	$5,%hi($LC0)
	lui	$16,%hi(Buf.0)
	lui	$2,%hi(sprintf)
	sw	$31,36($sp)
	addiu	$4,$16,%lo(Buf.0)
	sw	$9,16($sp)
	sw	$8,20($sp)
	sb	$8,24($sp)
	sb	$9,25($sp)
	sb	$10,26($sp)
	sb	$11,27($sp)
	addiu	$5,$5,%lo($LC0)
	andi	$6,$11,0x00ff
	addiu	$2,$2,%lo(sprintf)
	jal	$2
	andi	$7,$10,0x00ff

	addiu	$2,$16,%lo(Buf.0)
	lw	$31,36($sp)
	lw	$16,32($sp)
	j	$31
	addiu	$sp,$sp,40

	.set	macro
	.set	reorder
	.end	Ip2Str
	.section	.text.Str2Ip,"ax",@progbits
	.align	2
	.globl	Str2Ip
	.ent	Str2Ip
	.type	Str2Ip, @function
Str2Ip:
	.frame	$sp,176,$31		# vars= 136, regs= 6/0, args= 16, gp= 0
	.mask	0x801f0000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-176
	lui	$2,%hi(_ctype)
	sw	$20,168($sp)
	sw	$19,164($sp)
	sw	$18,160($sp)
	sw	$17,156($sp)
	sw	$16,152($sp)
	sw	$31,172($sp)
	move	$16,$4
	addiu	$19,$2,%lo(_ctype)
	move	$17,$0
	lui	$20,%hi(GetNext)
	addiu	$18,$sp,16
$L30:
	move	$4,$16
	li	$5,46			# 0x2e
	addiu	$2,$20,%lo(GetNext)
	jal	$2
	addiu	$6,$sp,16

	move	$10,$2
	li	$2,-1			# 0xffffffffffffffff
	beq	$10,$2,$L41
	lbu	$5,16($sp)

	addu	$11,$18,$17
	move	$8,$18
	andi	$2,$5,0x00ff
	addu	$2,$2,$19
	lbu	$3,0($2)
	srl	$3,$3,2
	andi	$3,$3,0x1
	beq	$3,$0,$L38
	move	$7,$0

	move	$6,$5
	move	$9,$19
$L28:
	addiu	$8,$8,1
	sll	$5,$6,24
	lbu	$6,0($8)
	sll	$3,$7,2
	addu	$3,$3,$7
	andi	$2,$6,0x00ff
	addu	$2,$2,$9
	lbu	$4,0($2)
	sra	$5,$5,24
	sll	$3,$3,1
	srl	$4,$4,2
	addu	$3,$3,$5
	andi	$4,$4,0x1
	bne	$4,$0,$L28
	addiu	$7,$3,-48

$L38:
	addiu	$17,$17,1
	slt	$2,$17,3
	sb	$7,128($11)
	bne	$2,$0,$L30
	addu	$16,$16,$10

	lbu	$6,0($16)
	lui	$2,%hi(_ctype)
	addiu	$4,$2,%lo(_ctype)
	andi	$2,$6,0x00ff
	addu	$2,$2,$4
	lbu	$3,0($2)
	move	$7,$16
	srl	$3,$3,2
	andi	$3,$3,0x1
	beq	$3,$0,$L40
	move	$8,$0

	move	$9,$4
$L33:
	addiu	$7,$7,1
	sll	$5,$6,24
	lbu	$6,0($7)
	sll	$3,$8,2
	addu	$3,$3,$8
	andi	$2,$6,0x00ff
	addu	$2,$2,$9
	lbu	$4,0($2)
	sra	$5,$5,24
	sll	$3,$3,1
	srl	$4,$4,2
	addu	$3,$3,$5
	andi	$4,$4,0x1
	bne	$4,$0,$L33
	addiu	$8,$3,-48

$L40:
	lbu	$2,144($sp)
	lbu	$3,145($sp)
	lbu	$4,146($sp)
	sll	$2,$2,24
	sll	$3,$3,16
	addu	$2,$2,$3
	sll	$4,$4,8
	lw	$31,172($sp)
	lw	$20,168($sp)
	lw	$19,164($sp)
	lw	$18,160($sp)
	lw	$17,156($sp)
	lw	$16,152($sp)
	addu	$2,$2,$4
	andi	$3,$8,0x00ff
	addu	$2,$2,$3
	sb	$8,147($sp)
	j	$31
	addiu	$sp,$sp,176

$L41:
	lw	$31,172($sp)
	lw	$20,168($sp)
	lw	$19,164($sp)
	lw	$18,160($sp)
	lw	$17,156($sp)
	lw	$16,152($sp)
	li	$2,1			# 0x1
	j	$31
	addiu	$sp,$sp,176

	.set	macro
	.set	reorder
	.end	Str2Ip
	.section	.text.CalIpRange,"ax",@progbits
	.align	2
	.globl	CalIpRange
	.ent	CalIpRange
	.type	CalIpRange, @function
CalIpRange:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	subu	$4,$5,$4
	addiu	$4,$4,1
	j	$L47
	move	$3,$0

$L51:
	sltu	$2,$3,32
	beq	$2,$0,$L52
	li	$2,32			# 0x20

$L47:
	srl	$2,$4,$3
	andi	$2,$2,0x1
	beq	$2,$0,$L51
	addiu	$3,$3,1

	addiu	$3,$3,-1
	li	$2,32			# 0x20
$L52:
	beq	$3,$2,$L48
	srl	$2,$4,$3

	sb	$2,0($6)
	j	$31
	sb	$3,0($7)

$L48:
	sb	$0,0($6)
	j	$31
	sb	$0,0($7)

	.set	macro
	.set	reorder
	.end	CalIpRange
	.section	.text.RegModifyBits,"ax",@progbits
	.align	2
	.globl	RegModifyBits
	.ent	RegModifyBits
	.type	RegModifyBits, @function
RegModifyBits:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	move	$10,$5
	move	$8,$0
	move	$5,$6
	beq	$7,$0,$L59
	move	$6,$0

	li	$9,1			# 0x1
$L57:
	addu	$2,$5,$8
	addiu	$8,$8,1
	sll	$2,$9,$2
	sltu	$3,$8,$7
	bne	$3,$0,$L57
	or	$6,$6,$2

$L59:
	li	$2,536805376			# 0x1fff0000
	ori	$2,$2,0xffff
	and	$2,$4,$2
	li	$3,-1610612736			# 0xffffffffa0000000
	or	$2,$2,$3
	lw	$4,0($2)
	sll	$3,$10,$5
	nor	$5,$0,$6
	and	$4,$4,$5
	and	$3,$3,$6
	or	$4,$4,$3
	sw	$4,0($2)
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	RegModifyBits
	.section	.text.FoeToOrgTcpHdr,"ax",@progbits
	.align	2
	.globl	FoeToOrgTcpHdr
	.ent	FoeToOrgTcpHdr
	.type	FoeToOrgTcpHdr, @function
FoeToOrgTcpHdr:
	.frame	$sp,72,$31		# vars= 32, regs= 5/0, args= 16, gp= 0
	.mask	0x800f0000,-8
	.fmask	0x00000000,0
	addiu	$sp,$sp,-72
	sw	$31,64($sp)
	sw	$19,60($sp)
	sw	$18,56($sp)
	sw	$17,52($sp)
	sw	$16,48($sp)
	lhu	$3,0($6)
	move	$16,$6
	lhu	$6,16($6)
	nor	$3,$0,$3
	lhu	$2,14($4)
	andi	$3,$3,0xffff
	nor	$6,$0,$6
	lui	$17,%hi(csum_partial)
#APP
		wsbh	$2, $2			

#NO_APP
	andi	$2,$2,0xffff
	move	$18,$4
	addiu	$17,$17,%lo(csum_partial)
	move	$19,$5
	addiu	$4,$sp,16
	sw	$3,16($sp)
	andi	$6,$6,0xffff
	li	$5,8			# 0x8
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,20($sp)
	.set	macro
	.set	reorder

	lhu	$3,2($16)
#APP
		.set	push		# csum_fold
	.set	noat		
	sll	$1, $2, 16	
	addu	$2, $1		
	sltu	$1, $2, $1	
	srl	$2, $2, 16	
	addu	$2, $1		
	xori	$2, 0xffff	
	.set	pop
#NO_APP
	andi	$2,$2,0xffff
	sh	$2,16($16)
	nor	$3,$0,$3
	nor	$2,$0,$2
	andi	$3,$3,0xffff
	andi	$6,$2,0xffff
	lhu	$2,12($18)
#APP
		wsbh	$2, $2			

#NO_APP
	andi	$2,$2,0xffff
	addiu	$4,$sp,24
	sw	$3,24($sp)
	li	$5,8			# 0x8
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,28($sp)
	.set	macro
	.set	reorder

#APP
		.set	push		# csum_fold
	.set	noat		
	sll	$1, $2, 16	
	addu	$2, $1		
	sltu	$1, $2, $1	
	srl	$2, $2, 16	
	addu	$2, $1		
	xori	$2, 0xffff	
	.set	pop
#NO_APP
	andi	$2,$2,0xffff
	sh	$2,16($16)
	lw	$3,12($19)
	nor	$2,$0,$2
	andi	$6,$2,0xffff
	nor	$3,$0,$3
	sw	$3,32($sp)
	lw	$2,4($18)
	addiu	$4,$sp,32
	li	$5,8			# 0x8
#APP
		wsbh	$2, $2			
	rotr	$2, $2, 16		

#NO_APP
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,36($sp)
	.set	macro
	.set	reorder

#APP
		.set	push		# csum_fold
	.set	noat		
	sll	$1, $2, 16	
	addu	$2, $1		
	sltu	$1, $2, $1	
	srl	$2, $2, 16	
	addu	$2, $1		
	xori	$2, 0xffff	
	.set	pop
#NO_APP
	andi	$2,$2,0xffff
	sh	$2,16($16)
	lw	$3,16($19)
	nor	$2,$0,$2
	andi	$6,$2,0xffff
	nor	$3,$0,$3
	sw	$3,40($sp)
	lw	$2,8($18)
	addiu	$4,$sp,40
#APP
		wsbh	$2, $2			
	rotr	$2, $2, 16		

#NO_APP
	li	$5,8			# 0x8
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,44($sp)
	.set	macro
	.set	reorder

#APP
		.set	push		# csum_fold
	.set	noat		
	sll	$1, $2, 16	
	addu	$2, $1		
	sltu	$1, $2, $1	
	srl	$2, $2, 16	
	addu	$2, $1		
	xori	$2, 0xffff	
	.set	pop
#NO_APP
	sh	$2,16($16)
	lhu	$2,14($18)
#APP
		wsbh	$2, $2			

#NO_APP
	sh	$2,0($16)
	lhu	$3,12($18)
	lw	$31,64($sp)
#APP
		wsbh	$3, $3			

#NO_APP
	lw	$19,60($sp)
	sh	$3,2($16)
	lw	$18,56($sp)
	lw	$17,52($sp)
	lw	$16,48($sp)
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,72
	.set	macro
	.set	reorder

	.end	FoeToOrgTcpHdr
	.section	.text.FoeToOrgUdpHdr,"ax",@progbits
	.align	2
	.globl	FoeToOrgUdpHdr
	.ent	FoeToOrgUdpHdr
	.type	FoeToOrgUdpHdr, @function
FoeToOrgUdpHdr:
	.frame	$sp,72,$31		# vars= 32, regs= 5/0, args= 16, gp= 0
	.mask	0x800f0000,-8
	.fmask	0x00000000,0
	addiu	$sp,$sp,-72
	sw	$31,64($sp)
	sw	$19,60($sp)
	sw	$18,56($sp)
	sw	$17,52($sp)
	sw	$16,48($sp)
	lhu	$3,0($6)
	move	$16,$6
	lhu	$6,6($6)
	nor	$3,$0,$3
	lhu	$2,14($4)
	andi	$3,$3,0xffff
	nor	$6,$0,$6
	lui	$17,%hi(csum_partial)
#APP
		wsbh	$2, $2			

#NO_APP
	andi	$2,$2,0xffff
	move	$18,$4
	addiu	$17,$17,%lo(csum_partial)
	move	$19,$5
	addiu	$4,$sp,16
	sw	$3,16($sp)
	andi	$6,$6,0xffff
	li	$5,8			# 0x8
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,20($sp)
	.set	macro
	.set	reorder

	lhu	$3,2($16)
#APP
		.set	push		# csum_fold
	.set	noat		
	sll	$1, $2, 16	
	addu	$2, $1		
	sltu	$1, $2, $1	
	srl	$2, $2, 16	
	addu	$2, $1		
	xori	$2, 0xffff	
	.set	pop
#NO_APP
	andi	$2,$2,0xffff
	sh	$2,6($16)
	nor	$3,$0,$3
	nor	$2,$0,$2
	andi	$3,$3,0xffff
	andi	$6,$2,0xffff
	lhu	$2,12($18)
#APP
		wsbh	$2, $2			

#NO_APP
	andi	$2,$2,0xffff
	addiu	$4,$sp,24
	sw	$3,24($sp)
	li	$5,8			# 0x8
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,28($sp)
	.set	macro
	.set	reorder

#APP
		.set	push		# csum_fold
	.set	noat		
	sll	$1, $2, 16	
	addu	$2, $1		
	sltu	$1, $2, $1	
	srl	$2, $2, 16	
	addu	$2, $1		
	xori	$2, 0xffff	
	.set	pop
#NO_APP
	andi	$2,$2,0xffff
	sh	$2,6($16)
	lw	$3,12($19)
	nor	$2,$0,$2
	andi	$6,$2,0xffff
	nor	$3,$0,$3
	sw	$3,32($sp)
	lw	$2,4($18)
	addiu	$4,$sp,32
	li	$5,8			# 0x8
#APP
		wsbh	$2, $2			
	rotr	$2, $2, 16		

#NO_APP
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,36($sp)
	.set	macro
	.set	reorder

#APP
		.set	push		# csum_fold
	.set	noat		
	sll	$1, $2, 16	
	addu	$2, $1		
	sltu	$1, $2, $1	
	srl	$2, $2, 16	
	addu	$2, $1		
	xori	$2, 0xffff	
	.set	pop
#NO_APP
	andi	$2,$2,0xffff
	sh	$2,6($16)
	lw	$3,16($19)
	nor	$2,$0,$2
	andi	$6,$2,0xffff
	nor	$3,$0,$3
	sw	$3,40($sp)
	lw	$2,8($18)
	addiu	$4,$sp,40
#APP
		wsbh	$2, $2			
	rotr	$2, $2, 16		

#NO_APP
	li	$5,8			# 0x8
	.set	noreorder
	.set	nomacro
	jal	$17
	sw	$2,44($sp)
	.set	macro
	.set	reorder

#APP
		.set	push		# csum_fold
	.set	noat		
	sll	$1, $2, 16	
	addu	$2, $1		
	sltu	$1, $2, $1	
	srl	$2, $2, 16	
	addu	$2, $1		
	xori	$2, 0xffff	
	.set	pop
#NO_APP
	sh	$2,6($16)
	lhu	$2,14($18)
#APP
		wsbh	$2, $2			

#NO_APP
	sh	$2,0($16)
	lhu	$3,12($18)
	lw	$31,64($sp)
#APP
		wsbh	$3, $3			

#NO_APP
	lw	$19,60($sp)
	sh	$3,2($16)
	lw	$18,56($sp)
	lw	$17,52($sp)
	lw	$16,48($sp)
	.set	noreorder
	.set	nomacro
	j	$31
	addiu	$sp,$sp,72
	.set	macro
	.set	reorder

	.end	FoeToOrgUdpHdr
	.section	.text.FoeToOrgIpHdr,"ax",@progbits
	.align	2
	.globl	FoeToOrgIpHdr
	.ent	FoeToOrgIpHdr
	.type	FoeToOrgIpHdr, @function
FoeToOrgIpHdr:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	move	$9,$5
	lw	$7,4($9)
	lw	$5,0($5)
	lw	$2,4($4)
#APP
		wsbh	$2, $2			
	rotr	$2, $2, 16		

#NO_APP
	sw	$2,12($9)
	lw	$6,8($4)
	sh	$0,10($9)
	addu	$8,$5,$7
	lw	$3,8($9)
	sltu	$4,$8,$7
	addu	$8,$8,$4
	addu	$8,$8,$3
	sltu	$4,$8,$3
	addu	$8,$8,$4
	addu	$8,$8,$2
	andi	$5,$5,0xf
	sll	$5,$5,2
	sltu	$4,$8,$2
#APP
		wsbh	$6, $6			
	rotr	$6, $6, 16		

#NO_APP
	addu	$8,$8,$4
	sw	$6,16($9)
	addu	$5,$5,$9
	addiu	$3,$9,16
$L135:
	lw	$2,0($3)
	addiu	$3,$3,4
	addu	$8,$8,$2
	sltu	$4,$8,$2
	.set	noreorder
	.set	nomacro
	bne	$3,$5,$L135
	addu	$8,$8,$4
	.set	macro
	.set	reorder

#APP
		.set	push		# csum_fold
	.set	noat		
	sll	$1, $8, 16	
	addu	$8, $1		
	sltu	$1, $8, $1	
	srl	$8, $8, 16	
	addu	$8, $1		
	xori	$8, 0xffff	
	.set	pop
#NO_APP
	.set	noreorder
	.set	nomacro
	j	$31
	sh	$8,10($9)
	.set	macro
	.set	reorder

	.end	FoeToOrgIpHdr
	.ident	"GCC: (GNU) 3.4.2"
