OUTPUT_FORMAT ("elf32-littlearm", "elf32-bigarm", "elf32-littlearm")
SEARCH_DIR(.)
GROUP(-lgcc -lc -lnosys)
GROUP(libgcc.a libc.a libm.a libnosys.a)
ENTRY(S_Reset_Handler)

ITCM_NS_START               = 0x00000000;
ITCM_S_START                = 0x10000000;
ITCM_SIZE                   = 0x00040000;

DTCM_NS_START               = 0x20000000;
DTCM_S_START                = 0x30000000;
DTCM_SIZE                   = 0x00040000;

RRAM_NS_START               = 0x22000000;
RRAM_S_START                = 0x32000000;
RRAM_SIZE                   = 0x02000000;

RRAM_NS_SAHB_START          = RRAM_NS_START;
RRAM_S_SAHB_START           = RRAM_S_START;

RRAM_NS_CBUS_START          = 0x02000000;
RRAM_S_CBUS_START           = 0x12000000;

SRAM0_NS_SAHB_START         = 0x24000000;
SRAM0_S_SAHB_START          = 0x34000000;
SRAM0_NS_CBUS_START         = 0x04000000;
SRAM0_S_CBUS_START          = 0x14000000;
SRAM0_SIZE                  = 0x00080000;

SRAM1_NS_SAHB_START         = 0x24080000;
SRAM1_S_SAHB_START          = 0x34080000;
SRAM1_NS_CBUS_START         = 0x04080000;
SRAM1_S_CBUS_START          = 0x14080000;
SRAM1_SIZE                  = 0x00080000;

SOCMEM_NS_RAM_SAHB_START    = 0x26000000;
SOCMEM_S_RAM_SAHB_START     = 0x36000000;
SOCMEM_NS_RAM_CBUS_START    = 0x06000000;
SOCMEM_S_RAM_CBUS_START     = 0x16000000;
SOCMEM_RAM_SIZE             = 0x00500000;

FLASH_NS_SAHB_START         = 0x60000000;
FLASH_S_SAHB_START          = 0x70000000;
FLASH_NS_CBUS_START         = 0x08000000;
FLASH_S_CBUS_START          = 0x18000000;
FLASH_SIZE                  = 0x04000000;

MMIO_NS_M33SYS_START        = 0x42000000;
MMIO_S_M33SYS_START         = 0x52000000;
MMIO_M33SYS_SIZE            = 0x02000000;

MMIO_NS_M55APP_START        = 0x44000000;
MMIO_S_M55APP_START         = 0x54000000;
MMIO_M55APP_SIZE            = 0x01000000;

/*----------------------------------------*/

VECTOR_TABLE_ALIGNMENT        = 1024;

NS_LOAD_ADDR_SIZE           = 0x00000020;

MSP_STACK_SIZE              = 0x0008000;
PSP_STACK_SIZE              = 0x0001000;

HEAP_NS_SIZE                = 0x0001000;
HEAP_S_SIZE                 = 0x0030000;

CODE_VMA                    = SRAM0_S_CBUS_START;
CODE_LMA                    = SRAM0_S_SAHB_START;
CODE_SIZE                   = 0x0006FF00;

CODE_NSC_VMA                = CODE_VMA + CODE_SIZE;
CODE_NSC_LMA                = CODE_LMA + CODE_SIZE;
CODE_NSC_SIZE               = 0x100;

DATA_VMA                    = SRAM0_S_SAHB_START + CODE_SIZE + CODE_NSC_SIZE;
DATA_LMA                    = SRAM0_S_SAHB_START + CODE_SIZE + CODE_NSC_SIZE;
DATA_SIZE                   = 0x00020000 - NS_LOAD_ADDR_SIZE;

NS_LOAD_ADDR                = DATA_VMA + DATA_SIZE;

XIP_VMA                     = FLASH_S_CBUS_START;
XIP_LMA                     = FLASH_S_SAHB_START;
XIP_SIZE                    = FLASH_SIZE;

MPU_ALIGN = 32;

SRAM0_S_SAHB_SIZE = SRAM0_SIZE;
/*                 upgr flg + policy sections*/
CODE_S_CBUS_OFFSET = 0x1000 + 0x400;
CODE_S_CBUS_START = RRAM_S_SAHB_START + CODE_S_CBUS_OFFSET;
CODE_S_CBUS_SIZE = 0x68000 - 0x1000 - 0x400;

CODE_S_SAHB_OFFSET = CODE_S_CBUS_OFFSET;
CODE_S_SAHB_START = RRAM_S_SAHB_START + CODE_S_SAHB_OFFSET;
CODE_S_SAHB_SIZE = CODE_S_CBUS_SIZE;

/*CODE_SRAM0_S_SAHB_OFFSET = 0;*/
CODE_SRAM0_S_SAHB_OFFSET = 0x8000;
/* CODE_SRAM0_S_SAHB_START = SRAM1_S_SAHB_START + CODE_SRAM0_S_SAHB_OFFSET; */
CODE_SRAM0_S_SAHB_START = SRAM0_S_SAHB_START + CODE_SRAM0_S_SAHB_OFFSET;
CODE_SRAM0_S_SAHB_SIZE  = 0x7F000;

DATA_SRAM0_S_SAHB_OFFSET = CODE_SRAM0_S_SAHB_SIZE + CODE_SRAM0_S_SAHB_OFFSET;
/* DATA_SRAM0_S_SAHB_OFFSET = 0; */
DATA_SRAM0_S_SAHB_START = SRAM0_S_SAHB_START + DATA_SRAM0_S_SAHB_OFFSET;
DATA_SRAM0_S_SAHB_SIZE  = 0x90000;

OEM_NVM_SECTION_SAHB_OFFSET = CODE_S_SAHB_OFFSET + CODE_S_SAHB_SIZE;
OEM_NVM_SECTION_SAHB_START = RRAM_S_SAHB_START + OEM_NVM_SECTION_SAHB_OFFSET;
OEM_NVM_SECTION_SAHB_SIZE  = 0x40000 - OEM_NVM_SECTION_SAHB_OFFSET;

OEM_NVM_SECTION_CBUS_OFFSET = OEM_NVM_SECTION_SAHB_OFFSET;
OEM_NVM_SECTION_CBUS_START = RRAM_S_CBUS_START + OEM_NVM_SECTION_CBUS_OFFSET;
OEM_NVM_SECTION_CBUS_SIZE  = OEM_NVM_SECTION_SAHB_SIZE;

RAM_APP_SECTION_SAHB_OFFSET = DATA_SRAM0_S_SAHB_OFFSET + DATA_SRAM0_S_SAHB_SIZE;
RAM_APP_SECTION_SAHB_START = SRAM0_S_SAHB_START + RAM_APP_SECTION_SAHB_OFFSET;
RAM_APP_SECTION_SAHB_SIZE  = SRAM0_SIZE - DATA_SRAM0_S_SAHB_SIZE + SRAM0_SIZE;

RAM_APP_SECTION_CBUS_OFFSET = RAM_APP_SECTION_SAHB_OFFSET;
RAM_APP_SECTION_CBUS_START = SRAM0_S_CBUS_START + RAM_APP_SECTION_CBUS_OFFSET;
RAM_APP_SECTION_CBUS_SIZE  = RAM_APP_SECTION_SAHB_SIZE;


/* The size of the MCU boot header area */
BOOT_HEADER_SIZE = 0;

/* Force symbol to be entered in the output file as an undefined symbol. Doing
* this may, for example, trigger linking of additional modules from standard
* libraries. You may list several symbols for each EXTERN, and you may use
* EXTERN multiple times. This command has the same effect as the -u command-line
* option.
*/
EXTERN(S_Reset_Handler)

/* The MEMORY section below describes the location and size of blocks of memory in the target.
* Use this section to specify the memory regions available for allocation.
*/
MEMORY
{
    /* The ram and code regions control RAM and code memory allocation for the CM33 core.
     */
    code             (rx)    : ORIGIN = CODE_SRAM0_S_SAHB_START,   LENGTH = CODE_SRAM0_S_SAHB_SIZE
    ram_l1           (rwx)   : ORIGIN = DATA_SRAM0_S_SAHB_START,   LENGTH = DATA_SRAM0_S_SAHB_SIZE
}

RAM_BASE_ADDR = SRAM0_S_SAHB_START;
RAM_END = SRAM0_S_SAHB_START + SRAM0_S_SAHB_SIZE;
OEM_RAM_APP_REGION_START = RAM_APP_SECTION_SAHB_START;
OEM_RAM_APP_REGION_END = OEM_RAM_APP_REGION_START + RAM_APP_SECTION_SAHB_SIZE;
OEM_NVM_APP_REGION_START = OEM_NVM_SECTION_SAHB_START;
OEM_NVM_APP_REGION_END = OEM_NVM_APP_REGION_START + OEM_NVM_SECTION_SAHB_SIZE;


/* Library configurations */
GROUP(libgcc.a libc.a libm.a libnosys.a)

/* Linker script to place sections and symbol values. Should be used together
 * with other linker script that defines memory regions FLASH and RAM.
 * It references following symbols, which must be defined in code:
 *  S_Reset_Handler : Entry of reset handler
 *
 * It defines following symbols, which code can use without definition:
 *   __exidx_start
 *   __exidx_end
 *   __copy_table_start__
 *   __copy_table_end__
 *   __zero_table_start__
 *   __zero_table_end__
 *   __etext
 *   __data_start__
 *   __preinit_array_start
 *   __preinit_array_end
 *   __init_array_start
 *   __init_array_end
 *   __fini_array_start
 *   __fini_array_end
 *   __data_end__
 *   __bss_start__
 *   __bss_end__
 *   __end__
 *   end
 *   __HeapLimit
 *   __StackLimit
 *   __StackTop
 *   __stack
 *   __Vectors_End
 *   __Vectors_Size
 */


SECTIONS
{
     /* BOOT_HEADER_SIZE for L1 boot = 0 */
    __image_payload_begin_VMA = ORIGIN(code) + BOOT_HEADER_SIZE;
    __image_payload_begin_LMA = __image_payload_begin_VMA;

     __privileged_text_start = __image_payload_begin_VMA;

    /* Privileged Cortex-M33 application code area .  VECTOR_TABLE_ALIGNMENT has to be at least MPU_ALIGN */
    .text __privileged_text_start : AT (__image_payload_begin_LMA) ALIGN(VECTOR_TABLE_ALIGNMENT)
    {
        /* Cortex-M33 code vector table */
        __text_begin = .;

        __Vectors = . ;
        KEEP(*(.vectors))
        . = ALIGN(4);
        __Vectors_End = .;
        __Vectors_Size = __Vectors_End - __Vectors;
        __end__ = .;

        . = ALIGN(4);
        *(EXCLUDE_FILE(*libg_nano.a:*
                       *dfu_bsp_i2c.o
                       *transport_i2c.o
                       *dfu_bsp_spi.o
                       *transport_spi.o
                       *dfu_bsp_uart.o
                       *transport_uart.o
                       *transport_usb_cdc.o
                       *dfu_mode.o
                       *dfu_user.o
                       *cy_dfu.o
                       *dead_mode.o
                       *cy_syslib_gcc.o
                       *cy_gpio.o
                       *cy_scb_common.o
                       *cy_scb_i2c.o
                       *cy_scb_spi.o
                       *cy_scb_uart.o
                       *cy_syslib.o
                                     ) .text*)
        KEEP(*(.init))
        KEEP(*(.fini))

        /* .ctors */
        *crtbegin.o(.ctors)
        *crtbegin?.o(.ctors)
        *(EXCLUDE_FILE(*crtend?.o *crtend.o) .ctors)
        *(SORT(.ctors.*))
        *(.ctors)

        /* .dtors */
        *crtbegin.o(.dtors)
        *crtbegin?.o(.dtors)
        *(EXCLUDE_FILE(*crtend?.o *crtend.o) .dtors)
        *(SORT(.dtors.*))
        *(.dtors)

        /* Read-only code (constants). */
        *(EXCLUDE_FILE(*libg_nano.a:*
                       *dfu_bsp_i2c.o
                       *transport_i2c.o
                       *dfu_bsp_spi.o
                       *transport_spi.o
                       *dfu_bsp_uart.o
                       *transport_uart.o
                       *transport_usb_cdc.o
                       *dfu_mode.o
                       *dfu_user.o
                       *cy_dfu.o
                       *dead_mode.o
                       *cy_syslib_gcc.o
                       *cy_gpio.o
                       *cy_scb_common.o
                       *cy_scb_i2c.o
                       *cy_scb_spi.o
                       *cy_scb_uart.o
                       *cy_syslib.o
                                     ) .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)

        KEEP(*(.eh_frame*))
        . = ALIGN(4);
        __text_end = .;
    } > code

    __text_size = __text_end - __text_begin;

    .copy.table : AT (__image_payload_begin_LMA + (__text_end - __privileged_text_start))
    {
        . = ALIGN(4);
        __copy_table_start__ = .;
        /* Copy priveleged data section to RAM */
        LONG (priveleged_data_storage_in_NVM_begin)         /* From */
        LONG (__data_start__)                               /* To   */
        LONG (__data_end__ - __data_start__)                /* Size */
        /* Copy unpriveged section to RAM */
        LONG (unpriveleged_data_storage_in_NVM_begin)       /* From */
        LONG (__unpriv_data_start__)                        /* To   */
        LONG (__unpriv_data_end__ - __unpriv_data_start__)  /* Size */
        . = ALIGN(4);
        __copy_table_end__ = .;
    } > code
    __copy_table_size = __copy_table_end__ - __copy_table_start__;

    .ARM.extab : AT (__image_payload_begin_LMA + __text_size)
    {
        *(.ARM.extab* .gnu.linkonce.armextab.*)
    } > code

    __exidx_start = .;

    .ARM.exidx :
    {
        *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    } > code
    __exidx_end = .;


    /* To clear multiple BSS sections,
     * uncomment .zero.table section and,
     * define __STARTUP_CLEAR_BSS_MULTIPLE in CAT1B devices */
    .zero.table :
    {
        . = ALIGN(4);
        __zero_table_start__ = .;
        LONG (__bss_start__)
        LONG ((__bss_end__ - __bss_start__)/4)

        LONG (__unpriv_bss_start__)
        LONG ((__unpriv_bss_end__ - __unpriv_bss_start__)/4)
        . = ALIGN(4);
        __zero_table_end__ = .;
    } > code

    . = ALIGN(MPU_ALIGN);

    /* privileged text end */
    __etext = .;
    __privileged_text_end = .;

    /* privileged text size */
    __privileged_text_size = __privileged_text_end - __privileged_text_start;

    /* Unprivileged Cortex-M33 application code area. Aligned in previous section */
    .serial_mode_text __privileged_text_end : AT (__image_payload_begin_LMA + __privileged_text_size)
    {
        __text_serial_mode_begin = .;
        *libg_nano.a:(.text* .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)
        *dfu_bsp_i2c.o(.text* .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)
        *transport_i2c.o(.text* .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)
        *dfu_bsp_spi.o(.text* .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)
        *transport_spi.o(.text* .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)
        *dfu_bsp_uart.o(.text* .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)
        *transport_uart.o(.text* .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)
        *transport_usb_cdc.o(.text* .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)
        *dfu_mode.o(.text* .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)
        *dfu_user.o(.text* .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)
        *cy_dfu.o(.text* .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)

        *dead_mode.o(.text* .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)
        *cy_syslib_gcc.o(.text* .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)
        *cy_gpio.o(.text* .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)
        *cy_scb_common.o(.text* .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)
        *cy_scb_i2c.o(.text* .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)
        *cy_scb_spi.o(.text* .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)
        *cy_scb_uart.o(.text* .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)
        *cy_syslib.o(.text* .rodata .rodata.* .constdata .constdata.* .conststring .conststring.*)

         . = ALIGN(MPU_ALIGN);
         __text_serial_mode_end = .;
    } > code

     __unprivileged_text_end = .;

    .ramVectors (NOLOAD) : ALIGN(VECTOR_TABLE_ALIGNMENT)
    {
        __ram_vectors_start__ = .;
        KEEP(*(.ram_vectors))
        __ram_vectors_end__   = .;
    } > ram_l1

     priveleged_data_storage_in_NVM_begin = __image_payload_begin_LMA + (__unprivileged_text_end - __image_payload_begin_VMA);
    .data __ram_vectors_end__ : AT (priveleged_data_storage_in_NVM_begin)
    {
        __data_start__ = .;

        *(EXCLUDE_FILE(*libg_nano.a:*
                       *dfu_bsp_i2c.o
                       *transport_i2c.o
                       *dfu_bsp_spi.o
                       *transport_spi.o
                       *dfu_bsp_uart.o
                       *transport_uart.o
                       *transport_usb_cdc.o
                       *dfu_mode.o
                       *dfu_user.o
                       *cy_dfu.o
                       *dead_mode.o
                       *cy_syslib_gcc.o
                       *cy_gpio.o
                       *cy_scb_common.o
                       *cy_scb_i2c.o
                       *cy_scb_spi.o
                       *cy_scb_uart.o
                       *cy_syslib.o
                                     ) vtable)
        *(EXCLUDE_FILE(*libg_nano.a:*
                       *dfu_bsp_i2c.o
                       *transport_i2c.o
                       *dfu_bsp_spi.o
                       *transport_spi.o
                       *dfu_bsp_uart.o
                       *transport_uart.o
                       *transport_usb_cdc.o
                       *dfu_mode.o
                       *dfu_user.o
                       *cy_dfu.o
                       *dead_mode.o
                       *cy_syslib_gcc.o
                       *cy_gpio.o
                       *cy_scb_common.o
                       *cy_scb_i2c.o
                       *cy_scb_spi.o
                       *cy_scb_uart.o
                       *cy_syslib.o
                                     ) .data*)

        . = ALIGN(4);
        /* preinit data */
        PROVIDE_HIDDEN (__preinit_array_start = .);
        KEEP(*(.preinit_array))
       . = ALIGN(4);
        PROVIDE_HIDDEN (__preinit_array_end = .);

        . = ALIGN(4);
        /* init data */
        PROVIDE_HIDDEN (__init_array_start = .);
        KEEP(*(SORT(.init_array.*)))
        KEEP(*(.init_array))
       . = ALIGN(4);
        PROVIDE_HIDDEN (__init_array_end = .);

        . = ALIGN(4);
        /* finit data */
        PROVIDE_HIDDEN (__fini_array_start = .);
        KEEP(*(SORT(.fini_array.*)))
        KEEP(*(.fini_array))
       . = ALIGN(4);
        PROVIDE_HIDDEN (__fini_array_end = .);

       KEEP(*(EXCLUDE_FILE(*libg_nano.a:*
                           *dfu_bsp_i2c.o
                           *transport_i2c.o
                           *dfu_bsp_spi.o
                           *transport_spi.o
                           *dfu_bsp_uart.o
                           *transport_uart.o
                           *transport_usb_cdc.o
                           *dfu_mode.o
                           *dfu_user.o
                           *cy_dfu.o
                           *dead_mode.o
                           *cy_syslib_gcc.o
                           *cy_gpio.o
                           *cy_scb_common.o
                           *cy_scb_i2c.o
                           *cy_scb_spi.o
                           *cy_scb_uart.o
                           *cy_syslib.o
                                          ) .cy_ramfunc*))
        . = ALIGN(4);

        __data_end__ = .;

    } > ram_l1

    /* Place variables in the section that should not be initialized during the
    *  device startup.
    */
    .noinit (NOLOAD) : ALIGN(8)
    {
      KEEP(*(EXCLUDE_FILE(*libg_nano.a:*
                           *dfu_bsp_i2c.o
                           *transport_i2c.o
                           *dfu_bsp_spi.o
                           *transport_spi.o
                           *dfu_bsp_uart.o
                           *transport_uart.o
                           *transport_usb_cdc.o
                           *dfu_mode.o
                           *dfu_user.o
                           *cy_dfu.o
                           *dead_mode.o
                           *cy_syslib_gcc.o
                           *cy_gpio.o
                           *cy_scb_common.o
                           *cy_scb_i2c.o
                           *cy_scb_spi.o
                           *cy_scb_uart.o
                           *cy_syslib.o
                                          ) .noinit))
    } > ram_l1


    /* The uninitialized global or static variables are placed in this section.
    *
    * The NOLOAD attribute tells linker that .bss section does not consume
    * any space in the image. The NOLOAD attribute changes the .bss type to
    * NOBITS, and that  makes linker to A) not allocate section in memory, and
    * A) put information to clear the section with all zeros during application
    * loading.
    *
    * Without the NOLOAD attribute, the .bss section might get PROGBITS type.
    * This  makes linker to A) allocate zeroed section in memory, and B) copy
    * this section to RAM during application loading.
    */
    .bss (NOLOAD):
    {
        . = ALIGN(4);
        __bss_start__ = .;
        *(EXCLUDE_FILE(*libg_nano.a:*
                       *dfu_bsp_i2c.o
                       *transport_i2c.o
                       *dfu_bsp_spi.o
                       *transport_spi.o
                       *dfu_bsp_uart.o
                       *transport_uart.o
                       *transport_usb_cdc.o
                       *dfu_mode.o
                       *dfu_user.o
                       *cy_dfu.o
                       *dead_mode.o
                       *cy_syslib_gcc.o
                       *cy_gpio.o
                       *cy_scb_common.o
                       *cy_scb_i2c.o
                       *cy_scb_spi.o
                       *cy_scb_uart.o
                       *cy_syslib.o
                                     ) .bss*)
        *(EXCLUDE_FILE(*libg_nano.a:*
                       *dfu_bsp_i2c.o
                       *transport_i2c.o
                       *dfu_bsp_spi.o
                       *transport_spi.o
                       *dfu_bsp_uart.o
                       *transport_uart.o
                       *transport_usb_cdc.o
                       *dfu_mode.o
                       *dfu_user.o
                       *cy_dfu.o
                       *dead_mode.o
                       *cy_syslib_gcc.o
                       *cy_gpio.o
                       *cy_scb_common.o
                       *cy_scb_i2c.o
                       *cy_scb_spi.o
                       *cy_scb_uart.o
                       *cy_syslib.o
                                     ) COMMON)

        . = ALIGN(4);
        __bss_end__ = .;
    } > ram_l1


    .heap (NOLOAD):
    {
        . = ALIGN(8);
        __HeapBase = .;
        __end__ = .;
        end = __end__;
        KEEP(*(.heap*))
         . = __HeapBase + HEAP_S_SIZE;
        __HeapLimit = .;
    } > ram_l1


    /* .stack_dummy section doesn't contains any symbols. It is only
     * used for linker to calculate size of stack sections, and assign
     * values to stack symbols later */
    .stack_dummy __HeapLimit (NOLOAD):
    {
        __StackLimit = . ;
        KEEP(*(.stack*))
        . = __StackLimit + MSP_STACK_SIZE;
        __StackTop = . ;
    } > ram_l1

    PROVIDE(__stack = __StackTop);

    . = __StackTop;
    . = ALIGN(MPU_ALIGN);
    __privileged_data_end = .;
    __unprivileged_data_start = . ;

    unpriveleged_data_storage_in_NVM_begin = priveleged_data_storage_in_NVM_begin + (__data_end__ - __data_start__);
    .unpivileged_data_sec __unprivileged_data_start : AT (unpriveleged_data_storage_in_NVM_begin)
    {
        __unpriv_data_start__ = .;

        *libg_nano.a:(vtable .data*)
        *dfu_bsp_i2c.o(vtable .data*)
        *transport_i2c.o(vtable .data*)
        *dfu_bsp_spi.o(vtable .data*)
        *transport_spi.o(vtable .data*)
        *dfu_bsp_uart.o(vtable .data*)
        *transport_uart.o(vtable .data*)
        *transport_usb_cdc.o(vtable .data*)
        *dfu_mode.o(vtable .data*)
        *dfu_user.o(vtable .data*)
        *cy_dfu.o(vtable .data*)

        *dead_mode.o(vtable .data*)
        *cy_syslib_gcc.o(vtable .data*)
        *cy_gpio.o(vtable .data*)
        *cy_scb_common.o(vtable .data*)
        *cy_scb_i2c.o(vtable .data*)
        *cy_scb_spi.o(vtable .data*)
        *cy_scb_uart.o(vtable .data*)
        *cy_syslib.o(vtable .data*)

        . = ALIGN(4);
        KEEP(*libg_nano.a:(.cy_ramfunc*))
        KEEP(*dfu_bsp_i2c.o(.cy_ramfunc*))
        KEEP(*transport_i2c.o(.cy_ramfunc*))
        KEEP(*dfu_bsp_spi.o(.cy_ramfunc*))
        KEEP(*transport_spi.o(.cy_ramfunc*))
        KEEP(*dfu_bsp_uart.o(.cy_ramfunc*))
        KEEP(*transport_uart.o(.cy_ramfunc*))
        KEEP(*transport_usb_cdc.o(.cy_ramfunc*))
        KEEP(*dfu_mode.o(.cy_ramfunc*))
        KEEP(*dfu_user.o(.cy_ramfunc*))
        KEEP(*cy_dfu.o(.cy_ramfunc*))

        KEEP(*dead_mode.o(.cy_ramfunc*))
        KEEP(*cy_syslib_gcc.o(.cy_ramfunc*))
        KEEP(*cy_gpio.o(.cy_ramfunc*))
        KEEP(*cy_scb_common.o(.cy_ramfunc*))
        KEEP(*cy_scb_i2c.o(.cy_ramfunc*))
        KEEP(*cy_scb_spi.o(.cy_ramfunc*))
        KEEP(*cy_scb_uart.o(.cy_ramfunc*))
        KEEP(*cy_syslib.o(.cy_ramfunc*))
        . = ALIGN(4);

        __unpriv_data_end__ = . ;

    } > ram_l1

/* Place variables in the section that should not be initialized during the
    *  device startup.
    */
    .unprivileged_noinit (NOLOAD) : ALIGN(8)
    {
        KEEP(*libg_nano.a:(.noinit))
        KEEP(*dfu_bsp_i2c.o(.noinit))
        KEEP(*transport_i2c.o(.noinit))
        KEEP(*dfu_bsp_spi.o(.noinit))
        KEEP(*transport_spi.o(.noinit))
        KEEP(*dfu_bsp_uart.o(.noinit))
        KEEP(*transport_uart.o(.noinit))
        KEEP(*transport_usb_cdc.o(.noinit))
        KEEP(*dfu_mode.o(.noinit))
        KEEP(*dfu_user.o(.noinit))
        KEEP(*cy_dfu.o(.noinit))

        KEEP(*dead_mode.o(.noinit))
        KEEP(*cy_syslib_gcc.o(.noinit))
        KEEP(*cy_gpio.o(.noinit))
        KEEP(*cy_scb_common.o(.noinit))
        KEEP(*cy_scb_i2c.o(.noinit))
        KEEP(*cy_scb_spi.o(.noinit))
        KEEP(*cy_scb_uart.o(.noinit))
        KEEP(*cy_syslib.o(.noinit))

    } > ram_l1

    .unprivileged_bss (NOLOAD):
    {
        . = ALIGN(4);
        __unpriv_bss_start__ = .;
        *libg_nano.a:(.bss* COMMON)
        *dfu_bsp_i2c.o(.bss* COMMON)
        *transport_i2c.o(.bss* COMMON)
        *dfu_bsp_spi.o(.bss* COMMON)
        *transport_spi.o(.bss* COMMON)
        *dfu_bsp_uart.o(.bss* COMMON)
        *transport_uart.o(.bss* COMMON)
        *transport_usb_cdc.o(.bss* COMMON)
        *dfu_mode.o(.bss* COMMON)
        *dfu_user.o(.bss* COMMON)
        *cy_dfu.o(.bss* COMMON)

        *dead_mode.o(.bss* COMMON)
        *cy_syslib_gcc.o(.bss* COMMON)
        *cy_gpio.o(.bss* COMMON)
        *cy_scb_common.o(.bss* COMMON)
        *cy_scb_i2c.o(.bss* COMMON)
        *cy_scb_spi.o(.bss* COMMON)
        *cy_scb_uart.o(.bss* COMMON)
        *cy_syslib.o(.bss* COMMON)

        . = ALIGN(4);
        __unpriv_bss_end__ = .;
    } > ram_l1

    /* .stack_dummy section doesn't contains any symbols. It is only
     * used for linker to calculate size of stack sections, and assign
     * values to stack symbols later */
    .unpriv_stack_dummy __unpriv_bss_end__ (NOLOAD):
    {
        . = ALIGN(8);
        __UnprivStackLimit = . ;
        KEEP(*libg_nano.a:(.stack*))
        KEEP(*dfu_bsp_i2c.o(.stack*))
        KEEP(*transport_i2c.o(.stack*))
        KEEP(*dfu_bsp_spi.o(.stack*))
        KEEP(*transport_spi.o(.stack*))
        KEEP(*dfu_bsp_uart.o(.stack*))
        KEEP(*transport_uart.o(.stack*))
        KEEP(*transport_usb_cdc.o(.stack*))
        KEEP(*dfu_mode.o(.stack*))
        KEEP(*dfu_user.o(.stack*))
        KEEP(*cy_dfu.o(.stack*))

        KEEP(*dead_mode.o(.stack*))
        KEEP(*cy_syslib_gcc.o(.stack*))
        KEEP(*cy_gpio.o(.stack*))
        KEEP(*cy_scb_common.o(.stack*))
        KEEP(*cy_scb_i2c.o(.stack*))
        KEEP(*cy_scb_spi.o(.stack*))
        KEEP(*cy_scb_uart.o(.stack*))
        KEEP(*cy_syslib.o(.stack*))
        . = __UnprivStackLimit + PSP_STACK_SIZE;
        __UnprivStackTop = . ;
    } > ram_l1


    . = __UnprivStackTop;
    . = ALIGN(MPU_ALIGN);
    __unprivileged_data_end = . ;
}
