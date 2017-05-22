#ifndef _i386_
#define _i386_

#if defined(_X86_)

typedef struct _BOPINSTR{
	UCHAR Instr1;
	UCHAR Instr2;
	UCHAR Instr3;
	UCHAR Instr4;
	UCHAR Instr5;
	UCHAR Instr6;
	UCHAR Instr7;
	UCHAR Instr8;
}BOPINSTR;

// begin_nthal
//
// Trap frame
//
//  NOTE - We deal only with 32bit registers, so the assembler equivalents
//         are always the extended forms.
//
//  NOTE - Unless you want to run like slow molasses everywhere in the
//         the system, this structure must be of DWORD length, DWORD
//         aligned, and its elements must all be DWORD aligned.
//
//  NOTE WELL   -
//
//      The i386 does not build stack frames in a consistent format, the
//      frames vary depending on whether or not a privilege transition
//      was involved.
//
//      In order to make NtContinue work for both user mode and kernel
//      mode callers, we must force a canonical stack.
//
//      If we're called from kernel mode, this structure is 8 bytes longer
//      than the actual frame!
//
//  WARNING:
//
//      X86_KTRAP_FRAME_LENGTH needs to be 16byte integral (at present.)
//

typedef struct _X86_KTRAP_FRAME {


//
//  Following 4 values are only used and defined for DBG systems,
//  but are always allocated to make switching from DBG to non-DBG
//  and back quicker.  They are not DEVL because they have a non-0
//  performance impact.
//

    ULONG   DbgEbp;         // Copy of User EBP set up so KB will work.
    ULONG   DbgEip;         // EIP of caller to system call, again, for KB.
    ULONG   DbgArgMark;     // Marker to show no args here.
    ULONG   DbgArgPointer;  // Pointer to the actual args

//
//  Temporary values used when frames are edited.
//
//
//  NOTE:   Any code that want's ESP must materialize it, since it
//          is not stored in the frame for kernel mode callers.
//
//          And code that sets ESP in a KERNEL mode frame, must put
//          the new value in TempEsp, make sure that TempSegCs holds
//          the real SegCs value, and put a special marker value into SegCs.
//

    ULONG   TempSegCs;
    ULONG   TempEsp;

//
//  Debug registers.
//

    ULONG   Dr0;
    ULONG   Dr1;
    ULONG   Dr2;
    ULONG   Dr3;
    ULONG   Dr6;
    ULONG   Dr7;

//
//  Segment registers
//

    ULONG   SegGs;
    ULONG   SegEs;
    ULONG   SegDs;

//
//  Volatile registers
//

    ULONG   Edx;
    ULONG   Ecx;
    ULONG   Eax;

//
//  Nesting state, not part of context record
//

    ULONG   PreviousPreviousMode;

    PEXCEPTION_REGISTRATION_RECORD ExceptionList;
                                            // Trash if caller was user mode.
                                            // Saved exception list if caller
                                            // was kernel mode or we're in
                                            // an interrupt.

//
//  FS is TIB/PCR pointer, is here to make save sequence easy
//

    ULONG   SegFs;

//
//  Non-volatile registers
//

    ULONG   Edi;
    ULONG   Esi;
    ULONG   Ebx;
    ULONG   Ebp;

//
//  Control registers
//

    ULONG   ErrCode;
    ULONG   Eip;
    ULONG   SegCs;
    ULONG   EFlags;

    ULONG   HardwareEsp;    // WARNING - segSS:esp are only here for stacks
    ULONG   HardwareSegSs;  // that involve a ring transition.

    ULONG   V86Es;          // these will be present for all transitions from
    ULONG   V86Ds;          // V86 mode
    ULONG   V86Fs;
    ULONG   V86Gs;
} X86_KTRAP_FRAME,*PX86_KTRAP_FRAME,*PKEXCEPTION_FRAME;;


#define X86_KTRAP_FRAME_LENGTH  (sizeof(X86_KTRAP_FRAME))
#define X86_KTRAP_FRAME_ALIGN   (sizeof(ULONG))
#define X86_KTRAP_FRAME_ROUND   (X86_KTRAP_FRAME_ALIGN-1)

//
//  Bits forced to 0 in SegCs if Esp has been edited.
//

#define X86_FRAME_EDITED        0xfff8

#define X86_KGDT_NULL       0
#define X86_KGDT_R0_CODE    8
#define X86_KGDT_R0_DATA    16
#define X86_KGDT_R3_CODE    24
#define X86_KGDT_R3_DATA    32
#define X86_KGDT_TSS        40
#define X86_KGDT_R0_PCR     48
#define X86_KGDT_R3_TEB     56
#define X86_KGDT_VDM_TILE   64
#define X86_KGDT_LDT        72
#define X86_KGDT_DF_TSS     80
#define X86_KGDT_NMI_TSS    88

#define X86_EFLAGS_DF_MASK        0x00000400L
#define X86_EFLAGS_INTERRUPT_MASK 0x00000200L
#define X86_EFLAGS_V86_MASK       0x00020000L
#define X86_EFLAGS_ALIGN_CHECK    0x00040000L
#define X86_EFLAGS_IOPL_MASK      0x00003000L
#define X86_EFLAGS_VIF            0x00080000L
#define X86_EFLAGS_VIP            0x00100000L
#define X86_EFLAGS_USER_SANITIZE  0x001e0dd7L


//
//  LDT descriptor entry
//

// begin_winnt begin_wx86

typedef struct _X86_LDT_ENTRY {
    USHORT  LimitLow;
    USHORT  BaseLow;
    union {
        struct {
            UCHAR   BaseMid;
            UCHAR   Flags1;     // Declare as bytes to avoid alignment
            UCHAR   Flags2;     // Problems.
            UCHAR   BaseHi;
        } Bytes;
        struct {
            ULONG   BaseMid : 8;
            ULONG   Type : 5;
            ULONG   Dpl : 2;
            ULONG   Pres : 1;
            ULONG   LimitHi : 4;
            ULONG   Sys : 1;
            ULONG   Reserved_0 : 1;
            ULONG   Default_Big : 1;
            ULONG   Granularity : 1;
            ULONG   BaseHi : 8;
        } Bits;
    } HighWord;
} X86_LDT_ENTRY, *PX86_LDT_ENTRY;

// end_winnt end_wx86

//
// Process Ldt Information
//  NtQueryInformationProcess using ProcessLdtInformation
//

typedef struct _X86_LDT_INFORMATION {
    ULONG Start;
    ULONG Length;
    X86_LDT_ENTRY LdtEntries[1];
} X86_PROCESS_LDT_INFORMATION, *PX86_PROCESS_LDT_INFORMATION;

//
// Process Ldt Size
//  NtSetInformationProcess using ProcessLdtSize
//

typedef struct _X86_LDT_SIZE {
    ULONG Length;
} X86_PROCESS_LDT_SIZE, *PX86_PROCESS_LDT_SIZE;

//
// Thread Descriptor Table Entry
//  NtQueryInformationThread using ThreadDescriptorTableEntry
//

// begin_windbgkd

typedef struct _X86_DESCRIPTOR_TABLE_ENTRY {
    ULONG Selector;
    X86_LDT_ENTRY Descriptor;
} X86_DESCRIPTOR_TABLE_ENTRY, *PX86_DESCRIPTOR_TABLE_ENTRY;



typedef struct _X86_DESCRIPTOR {
    USHORT  Pad;
    USHORT  Limit;
    ULONG   Base;
} X86_KDESCRIPTOR, *PX86_KDESCRIPTOR;

typedef struct _X86_KSPECIAL_REGISTERS {
    ULONG Cr0;
    ULONG Cr2;
    ULONG Cr3;
    ULONG Cr4;
    ULONG KernelDr0;
    ULONG KernelDr1;
    ULONG KernelDr2;
    ULONG KernelDr3;
    ULONG KernelDr6;
    ULONG KernelDr7;
    X86_KDESCRIPTOR Gdtr;
    X86_KDESCRIPTOR Idtr;
    USHORT Tr;
    USHORT Ldtr;
    ULONG Reserved[6];
} X86_KSPECIAL_REGISTERS, *PX86_KSPECIAL_REGISTERS;

//
// Processor State frame: Before a processor freezes itself, it
// dumps the processor state to the processor state frame for
// debugger to examine.
//

typedef struct _X86_KPROCESSOR_STATE {
    struct _CONTEXT ContextFrame;
    struct _KSPECIAL_REGISTERS SpecialRegisters;
} X86_KPROCESSOR_STATE, *PX86_KPROCESSOR_STATE;



//
// i386 Specific portions of mm component
//

//
// Define the page size for the Intel 386 as 4096 (0x1000).
//

#define X86_PAGE_SIZE (ULONG)0x1000

//
// Define the number of trailing zeroes in a page aligned virtual address.
// This is used as the shift count when shifting virtual addresses to
// virtual page numbers.
//

#define X86_PAGE_SHIFT 12L
// Define constants used in selector tests.
//
//  RPL_MASK is the real value for extracting RPL values.  IT IS THE WRONG
//  CONSTANT TO USE FOR MODE TESTING.
//
//  MODE_MASK is the value for deciding the current mode.
//  WARNING:    MODE_MASK assumes that all code runs at either ring-0
//              or ring-3.  Ring-1 or Ring-2 support will require changing
//              this value and all of the code that refers to it.

#define X86_MODE_MASK    1
#define X86_RPL_MASK     3


















#endif // defined(_X86_)


#endif // _i386_
