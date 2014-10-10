OUTPUT_FORMAT("elf32-littlemips")
OUTPUT_ARCH(mips)

ENTRY(_start)

SECTIONS
{
	. = 0x00010000;
	.text.start : {
		*(.text.start)
	}
	.text : {
		*(.text)
	}
	.rodata : {
		*(.rodata)
	}
	.data : {
		*(.data)
	}
	.bss : {
		*(.bss)
	}
}
