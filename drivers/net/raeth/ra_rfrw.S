	.file	1 "ra_rfrw.c"
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
	.section	.text.rw_rf_reg,"ax",@progbits
	.align	2
	.globl	rw_rf_reg
	.ent	rw_rf_reg
	.type	rw_rf_reg, @function
rw_rf_reg:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$2,-1340604416			# 0xffffffffb0180000
	move	$9,$4
	ori	$8,$2,0x500
	j	$L2
	move	$3,$0

$L17:
	beq	$7,$0,$L15
	nop

$L2:
	lw	$4,0($8)
	addiu	$3,$3,1
	srl	$2,$4,17
	andi	$2,$2,0x1
	bne	$2,$0,$L17
	sltu	$7,$3,10001

	lbu	$2,0($6)
	andi	$3,$5,0x3f
	sll	$3,$3,8
	or	$3,$3,$2
	li	$4,131072			# 0x20000
	beq	$9,$0,$L7
	or	$4,$3,$4

	li	$2,65536			# 0x10000
	or	$4,$4,$2
$L7:
	li	$2,-1340604416			# 0xffffffffb0180000
	sw	$4,0($8)
	move	$3,$0
	j	$L8
	ori	$8,$2,0x500

$L18:
	beq	$7,$0,$L15
	nop

$L8:
	lw	$4,0($8)
	addiu	$3,$3,1
	srl	$2,$4,17
	andi	$2,$2,0x1
	bne	$2,$0,$L18
	sltu	$7,$3,10001

	lw	$4,0($8)
	andi	$3,$5,0x1f
	andi	$2,$4,0x1f00
	srl	$2,$2,8
	bne	$2,$3,$L1
	li	$5,-1			# 0xffffffffffffffff

	andi	$2,$4,0xff
	sw	$2,0($6)
	move	$5,$0
$L1:
	j	$31
	move	$2,$5

$L15:
	li	$5,-1			# 0xffffffffffffffff
	j	$31
	move	$2,$5

	.set	macro
	.set	reorder
	.end	rw_rf_reg
	.ident	"GCC: (GNU) 3.4.2"
