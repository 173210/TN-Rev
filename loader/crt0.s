	.section .text.start
	.align	2
	.set	nomips16
	.set	noreorder

	bal	$start
	lui	$a1, %hi($next) + 0x40000000
$start:
	addiu	$a0, $ra, $next - $start
	ori	$a2, $a1, %lo(end)
	ori	$a1, $a1, %lo($next)
$loopCpy:
	lw	$a3, 0($a0)
	addiu	$a0, $a0, 4
	addiu	$a1, $a1, 4
	sltu	$t0, $a1, $a2
	bnez	$t0, $loopCpy
	sw	$a3, -4($a1)

	lui	$a1, 0x0001
	ori	$a1, $a1, %lo(end)
$loopCache:
	addiu	$a0, $a0, 64
	sltu	$a2, $a0, $a1
	bnez	$a2, $loopCache
	cache	0x14, -64($a0)

	j	_start
	nop
$next:
