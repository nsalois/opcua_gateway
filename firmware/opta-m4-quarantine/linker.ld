/*
 * Copyright 2026 Nicholas Salois.
 *
 * Licensed under the Apache License, Version 2.0.
 * See the LICENSE file in the repository root for the full license.
 */

/*
 * Dependency-free STM32H747XI Cortex-M4 quarantine image.
 *
 * Only the first 4 KiB of physical Bank 2 may contain programmed bytes. The
 * complete 1 MiB bank identity is defined later by padding the compact binary
 * with 0xFF. The only RAM available to this link is the dedicated 1 KiB CM4
 * alias at the top of D2 SRAM; the linker rejects all initialized/static RAM.
 */
MEMORY
{
    FLASH (rx)  : ORIGIN = 0x08100000, LENGTH = 0x00001000
    STACK (rwx) : ORIGIN = 0x10047C00, LENGTH = 0x00000400
}

ENTRY(quarantine_reset)

SECTIONS
{
    .vector_table ORIGIN(FLASH) : ALIGN(1024)
    {
        KEEP(*(.vector_table))
    } > FLASH

    .text : ALIGN(2)
    {
        KEEP(*(.text.quarantine))
    } > FLASH

    .rodata : ALIGN(4)
    {
        *(.rodata .rodata.*)
    } > FLASH

    .data : ALIGN(4)
    {
        *(.data .data.*)
    } > STACK AT>FLASH

    .bss (NOLOAD) : ALIGN(4)
    {
        *(.bss .bss.*)
        *(COMMON)
    } > STACK

    .uninit (NOLOAD) : ALIGN(4)
    {
        *(.uninit .uninit.*)
    } > STACK

    .got (NOLOAD) :
    {
        KEEP(*(.got .got.*))
    }

    /DISCARD/ :
    {
        *(.ARM.exidx .ARM.exidx.*)
        *(.ARM.extab .ARM.extab.*)
    }
}

__quarantine_flash_origin = ORIGIN(FLASH);
__quarantine_flash_limit = ORIGIN(FLASH) + LENGTH(FLASH);
__quarantine_stack_start = ORIGIN(STACK);
__quarantine_stack_end = ORIGIN(STACK) + LENGTH(STACK);
__quarantine_image_end = ADDR(.text) + SIZEOF(.text);

ASSERT(ADDR(.vector_table) == 0x08100000, "quarantine vector origin changed")
ASSERT(ALIGNOF(.vector_table) >= 1024, "quarantine vector alignment is below 1024")
ASSERT(SIZEOF(.vector_table) == 664, "STM32H747 CM4 vector table must be 166 words")
ASSERT(SIZEOF(.rodata) == 0, "quarantine image must not use read-only data")
ASSERT(SIZEOF(.data) == 0, "quarantine image must not initialize RAM")
ASSERT(SIZEOF(.bss) == 0, "quarantine image must not use BSS")
ASSERT(SIZEOF(.uninit) == 0, "quarantine image must not use uninitialized RAM")
ASSERT(SIZEOF(.got) == 0, "quarantine image must not use a GOT")
ASSERT(__quarantine_image_end <= __quarantine_flash_limit,
       "quarantine image exceeds the 4 KiB programmed prefix")
ASSERT(__quarantine_stack_start == 0x10047C00, "quarantine stack start changed")
ASSERT(__quarantine_stack_end == 0x10048000, "quarantine initial SP changed")
