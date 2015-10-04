	.file	1 "mii_mgr.c"
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
	.type	__ksymtab_mii_mgr_read, @object
	.size	__ksymtab_mii_mgr_read, 8
__ksymtab_mii_mgr_read:
	.word	mii_mgr_read
	.word	__kstrtab_mii_mgr_read
	.section	__ksymtab_strings,"a",@progbits
	.type	__kstrtab_mii_mgr_read, @object
	.size	__kstrtab_mii_mgr_read, 13
__kstrtab_mii_mgr_read:
	.ascii	"mii_mgr_read\000"
	.section	__ksymtab
	.align	2
	.type	__ksymtab_mii_mgr_write, @object
	.size	__ksymtab_mii_mgr_write, 8
__ksymtab_mii_mgr_write:
	.word	mii_mgr_write
	.word	__kstrtab_mii_mgr_write
	.section	__ksymtab_strings
	.type	__kstrtab_mii_mgr_write, @object
	.size	__kstrtab_mii_mgr_write, 14
__kstrtab_mii_mgr_write:
	.ascii	"mii_mgr_write\000"
	.section	.text.enable_mdio,"ax",@progbits
	.align	2
	.globl	enable_mdio
	.ent	enable_mdio
	.type	enable_mdio, @function
enable_mdio:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	li	$2,-1342177280			# 0xffffffffb0000000
	ori	$2,$2,0x60
	lw	$3,0($2)
	beq	$4,$0,$L2
	nop

	li	$2,-257			# 0xfffffffffffffeff
	and	$3,$3,$2
	li	$2,-1342177280			# 0xffffffffb0000000
	ori	$2,$2,0x60
	sw	$3,0($2)
	j	$31
	nop

$L2:
	li	$2,-1342177280			# 0xffffffffb0000000
	ori	$3,$3,0x100
	ori	$2,$2,0x60
	sw	$3,0($2)
	j	$31
	nop

	.set	macro
	.set	reorder
	.end	enable_mdio
	.section	.text.mii_mgr_read,"ax",@progbits
	.align	2
	.globl	mii_mgr_read
	.ent	mii_mgr_read
	.type	mii_mgr_read, @function
mii_mgr_read:
	.frame	$sp,56,$31		# vars= 16, regs= 5/0, args= 16, gp= 0
	.mask	0x800f0000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-56
	sw	$0,16($sp)
	sw	$19,44($sp)
	sw	$18,40($sp)
	sw	$17,36($sp)
	sw	$16,32($sp)
	sw	$31,48($sp)
	lui	$16,%hi(jiffies)
	lw	$2,%lo(jiffies)($16)
	move	$18,$4
	li	$4,1			# 0x1
	sw	$2,20($sp)
	move	$19,$6
	move	$17,$5
	sw	$0,24($sp)
	jal	enable_mdio
	nop

	li	$2,-1341063168			# 0xffffffffb0110000
	ori	$6,$2,0x7004
$L6:
	lw	$2,0($6)
	bgez	$2,$L7
	sll	$3,$17,25

	lw	$2,20($sp)
	lw	$3,%lo(jiffies)($16)
	subu	$2,$2,$3
	addiu	$2,$2,1250
	bgez	$2,$L6
	nop

$L18:
	jal	enable_mdio
	move	$4,$0

	move	$2,$0
	lw	$31,48($sp)
	lw	$19,44($sp)
	lw	$18,40($sp)
	lw	$17,36($sp)
	lw	$16,32($sp)
	j	$31
	addiu	$sp,$sp,56

$L7:
	sll	$2,$18,20
	or	$2,$2,$3
	li	$4,589824			# 0x90000
	or	$2,$2,$4
	sw	$2,24($sp)
	lw	$3,24($sp)
	li	$2,-1341063168			# 0xffffffffb0110000
	ori	$5,$2,0x7004
	sw	$3,0($6)
	lw	$4,24($sp)
	li	$3,-2147483648			# 0xffffffff80000000
	or	$4,$4,$3
	sw	$4,24($sp)
	lw	$2,24($sp)
	sw	$2,0($6)
	lw	$3,%lo(jiffies)($16)
	sw	$3,20($sp)
	lw	$2,0($5)
	bgez	$2,$L20
	nop

$L14:
	lw	$2,20($sp)
	lw	$3,%lo(jiffies)($16)
	subu	$2,$2,$3
	addiu	$2,$2,1250
	bltz	$2,$L18
	nop

	lw	$2,0($5)
	bltz	$2,$L14
	nop

$L20:
	lw	$3,0($5)
	move	$4,$0
	sw	$3,16($sp)
	lw	$2,16($sp)
	andi	$2,$2,0xffff
	jal	enable_mdio
	sw	$2,0($19)

	lw	$31,48($sp)
	lw	$19,44($sp)
	lw	$18,40($sp)
	lw	$17,36($sp)
	lw	$16,32($sp)
	li	$2,1			# 0x1
	j	$31
	addiu	$sp,$sp,56

	.set	macro
	.set	reorder
	.end	mii_mgr_read
	.section	.text.mii_mgr_write,"ax",@progbits
	.align	2
	.globl	mii_mgr_write
	.ent	mii_mgr_write
	.type	mii_mgr_write, @function
mii_mgr_write:
	.frame	$sp,56,$31		# vars= 16, regs= 5/0, args= 16, gp= 0
	.mask	0x800f0000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	addiu	$sp,$sp,-56
	sw	$19,44($sp)
	sw	$18,40($sp)
	sw	$17,36($sp)
	sw	$16,32($sp)
	sw	$31,48($sp)
	lui	$16,%hi(jiffies)
	lw	$2,%lo(jiffies)($16)
	move	$19,$4
	li	$4,1			# 0x1
	sw	$2,16($sp)
	move	$17,$5
	jal	enable_mdio
	move	$18,$6

	li	$2,-1341063168			# 0xffffffffb0110000
	ori	$7,$2,0x7004
$L22:
	lw	$2,0($7)
	bgez	$2,$L23
	sll	$3,$17,25

	lw	$2,16($sp)
	lw	$3,%lo(jiffies)($16)
	subu	$2,$2,$3
	addiu	$2,$2,1250
	bgez	$2,$L22
	nop

$L34:
	jal	enable_mdio
	move	$4,$0

	move	$2,$0
	lw	$31,48($sp)
	lw	$19,44($sp)
	lw	$18,40($sp)
	lw	$17,36($sp)
	lw	$16,32($sp)
	j	$31
	addiu	$sp,$sp,56

$L23:
	sll	$2,$19,20
	or	$2,$2,$3
	or	$2,$2,$18
	li	$3,327680			# 0x50000
	or	$2,$2,$3
	sw	$2,20($sp)
	lw	$3,20($sp)
	li	$2,-1341063168			# 0xffffffffb0110000
	ori	$5,$2,0x7004
	sw	$3,0($7)
	lw	$4,20($sp)
	li	$3,-2147483648			# 0xffffffff80000000
	or	$4,$4,$3
	sw	$4,20($sp)
	lw	$2,20($sp)
	sw	$2,0($7)
	lw	$3,%lo(jiffies)($16)
	sw	$3,16($sp)
	lw	$2,0($5)
	bgez	$2,$L36
	nop

$L30:
	lw	$2,16($sp)
	lw	$3,%lo(jiffies)($16)
	subu	$2,$2,$3
	addiu	$2,$2,1250
	bltz	$2,$L34
	nop

	lw	$2,0($5)
	bltz	$2,$L30
	nop

$L36:
	jal	enable_mdio
	move	$4,$0

	lw	$31,48($sp)
	lw	$19,44($sp)
	lw	$18,40($sp)
	lw	$17,36($sp)
	lw	$16,32($sp)
	li	$2,1			# 0x1
	j	$31
	addiu	$sp,$sp,56

	.set	macro
	.set	reorder
	.end	mii_mgr_write
	.ident	"GCC: (GNU) 3.4.2"
