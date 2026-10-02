/*
 * Build-only STM32H747XI Cortex-M7 memory map for cortex-m-rt.
 *
 * Flash starts at the current product's bootloader-aware M7 application origin:
 * 0x0804_0000. Task 7 caps the executable M7 app before persistent config
 * sectors at 0x080C_0000 and 0x080E_0000; each config slot is one 128 KiB
 * STM32H747 sector. Bank-2/M4 origin remains 0x0810_0000 and is not part of
 * this M7 image. RAM defaults to M7 D1/AXI SRAM. D2/SRAM and SRAM4 are
 * declared for accounting. The default product places the Ethernet packet
 * queue in a dedicated D2 section so the HIL-proven cache-on MPU policy keeps
 * DMA-visible state non-cacheable. ADR 0023 reserves the top 1 KiB of physical
 * D2 SRAM for the inert CM4 exception stack, so normal M7 sections cannot link
 * into that span. A deliberate --no-default-features build retains the
 * historical cache-off scaffold only for build diagnostics.
 */
/*
 * Persistent field-config slots (not linked into the image):
 *   Slot A: 0x080C_0000..0x080D_FFFF (Bank 1 sector 6)
 *   Slot B: 0x080E_0000..0x080F_FFFF (Bank 1 sector 7)
 */

MEMORY
{
    FLASH (rx)     : ORIGIN = 0x08040000, LENGTH = 0x00080000
    RAM   (rwx)    : ORIGIN = 0x24000000, LENGTH = 512K
    RAM_D2 (rwx)   : ORIGIN = 0x30000000, LENGTH = 0x00047C00
    CM4_STACK (rw) : ORIGIN = 0x30047C00, LENGTH = 0x00000400
    SRAM4 (rwx)    : ORIGIN = 0x38000000, LENGTH = 64K
}

__cm4_quarantine_stack_start = ORIGIN(CM4_STACK);
__cm4_quarantine_stack_end = ORIGIN(CM4_STACK) + LENGTH(CM4_STACK);

ASSERT(ORIGIN(RAM_D2) + LENGTH(RAM_D2) == __cm4_quarantine_stack_start,
       "opta-m7 D2 allocation overlaps or leaves a gap before CM4 stack")
ASSERT(__cm4_quarantine_stack_end == 0x30048000,
       "opta-m7 CM4 stack reservation no longer ends at physical D2 limit")

/*
 * 64 KiB release reserve: the bottom 16 KiB is a no-access MPU guard at
 * __stack_limit. The remaining 48 KiB covers the 15,100 B measured direct-call
 * lower bound, a 2,048 B interrupt allowance, and indirect-call unknowns.
 * Target overflow proof remains a separate release gate.
 */
__stack_size = 0x10000;
_stack_start = ORIGIN(RAM) + LENGTH(RAM);
_stack_end = _stack_start - __stack_size;
__stack_top = _stack_start;
__stack_limit = _stack_end;
PROVIDE(__stack = __stack_top);

ASSERT(__stack_limit >= __sheap, "opta-m7 RAM_D1 overflowed")
ASSERT((__stack_limit % 0x4000) == 0, "opta-m7 stack guard base is not 16 KiB aligned")

SECTIONS
{
    /*
     * Default-product Ethernet DMA-visible packet queue section.
     *
     * The accepted ingress-headroom policy configures a 64 KiB MPU region at
     * RAM_D2 origin as Normal, shareable, non-cacheable memory. Keep the
     * linked section at that exact base so the build report can prove the
     * MPU span and DMA-visible objects match.
     */
    .eth_dma ORIGIN(RAM_D2) (NOLOAD) :
    {
        . = ALIGN(32);
        __eth_dma_start = .;
        /* Keep the accepted packet queue at the region base, then append any
         * feature-gated non-cacheable diagnostic subsections. */
        KEEP(*(.eth_dma));
        KEEP(*(.eth_dma.*));
        . = ALIGN(32);
        __eth_dma_end = .;
    } > RAM_D2
}
