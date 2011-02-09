#ifndef AMD64_H
#define AMD64_H

#include <ntddk.h>

#define KGDT64_NULL (0 * 16)    // NULL descriptor
#define KGDT64_R0_CODE (1 * 16) // kernel mode 64-bit code
#define KGDT64_R0_DATA (1 * 16) + 8     // kernel mode 64-bit data (stack)
#define KGDT64_R3_CMCODE (2 * 16)       // user mode 32-bit code
#define KGDT64_R3_DATA (2 * 16) + 8     // user mode 32-bit data
#define KGDT64_R3_CODE (3 * 16) // user mode 64-bit code
#define KGDT64_SYS_TSS (4 * 16) // kernel mode system task state
#define KGDT64_R3_CMTEB (5 * 16)        // user mode 32-bit TEB
#define KGDT64_R0_CMCODE (6 * 16)       // kernel mode 32-bit code

#pragma pack (push, 1)

/* 
* Attribute for segment selector. This is a copy of bit 40:47 & 52:55 of the
* segment descriptor. 
*/
typedef union
{
  USHORT UCHARs;
  struct
  {
    USHORT type:4;              /* 0;  Bit 40-43 */
    USHORT s:1;                 /* 4;  Bit 44 */
    USHORT dpl:2;               /* 5;  Bit 45-46 */
    USHORT p:1;                 /* 7;  Bit 47 */
    // gap!       
    USHORT avl:1;               /* 8;  Bit 52 */
    USHORT l:1;                 /* 9;  Bit 53 */
    USHORT db:1;                /* 10; Bit 54 */
    USHORT g:1;                 /* 11; Bit 55 */
    USHORT Gap:4;
  } fields;
} SEGMENT_ATTRIBUTES;

typedef struct _TSS64
{
  ULONG Reserved0;
  PVOID RSP0;
  PVOID RSP1;
  PVOID RSP2;
  ULONG64 Reserved1;
  PVOID IST1;
  PVOID IST2;
  PVOID IST3;
  PVOID IST4;
  PVOID IST5;
  PVOID IST6;
  PVOID IST7;
  ULONG64 Reserved2;
  USHORT Reserved3;
  USHORT IOMapBaseAddress;
} TSS64, *PTSS64;

typedef struct _SEGMENT_SELECTOR
{
  USHORT sel;
  SEGMENT_ATTRIBUTES attributes;
  ULONG32 limit;
  ULONG64 base;
} SEGMENT_SELECTOR, *PSEGMENT_SELECTOR;

typedef struct _SEGMENT_DESCRIPTOR
{
  USHORT limit0;
  USHORT base0;
  UCHAR base1;
  UCHAR attr0;
  UCHAR limit1attr1;
  UCHAR base2;
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;

typedef struct _INTERRUPT_GATE_DESCRIPTOR
{
  USHORT TargetOffset1500;
  USHORT TargetSelector;
  UCHAR InterruptStackTable;
  UCHAR Attributes;
  USHORT TargetOffset3116;
  ULONG32 TargetOffset6332;
  ULONG32 Reserved;
} INTERRUPT_GATE_DESCRIPTOR,
 *PINTERRUPT_GATE_DESCRIPTOR;

#pragma pack (pop)

#define LA_ACCESSED		0x01
#define LA_READABLE		0x02    // for code segments
#define LA_WRITABLE		0x02    // for data segments
#define LA_CONFORMING	0x04    // for code segments
#define LA_EXPANDDOWN	0x04    // for data segments
#define LA_CODE			0x08
#define LA_STANDARD		0x10
#define LA_DPL_0		0x00
#define LA_DPL_1		0x20
#define LA_DPL_2		0x40
#define LA_DPL_3		0x60
#define LA_PRESENT		0x80

#define LA_LDT64		0x02
#define LA_ATSS64		0x09
#define LA_BTSS64		0x0b
#define LA_CALLGATE64	0x0c
#define LA_INTGATE64	0x0e
#define LA_TRAPGATE64	0x0f

#define HA_AVAILABLE	0x01
#define HA_LONG			0x02
#define HA_DB			0x04
#define HA_GRANULARITY	0x08

typedef enum SEGREGS
{
  ES = 0,
  CS,
  SS,
  DS,
  FS,
  GS,
  LDTR,
  TR
};

#define DIVIDE_ERROR_EXCEPTION 0
#define DEBUG_EXCEPTION 1
#define NMI_INTERRUPT 2
#define BREAKPOINT_EXCEPTION 3
#define OVERFLOW_EXCEPTION 4
#define BOUND_EXCEPTION 5
#define INVALID_OPCODE_EXCEPTION 6
#define DEVICE_NOT_AVAILABLE_EXCEPTION 7
#define DOUBLE_FAULT_EXCEPTION 8
#define COPROCESSOR_SEGMENT_OVERRUN 9
#define INVALID_TSS_EXCEPTION 10
#define SEGMENT_NOT_PRESENT 11
#define STACK_FAULT_EXCEPTION 12
#define GENERAL_PROTECTION_EXCEPTION 13
#define PAGE_FAULT_EXCEPTION 14
#define X87_FLOATING_POINT_ERROR 16
#define ALIGNMENT_CHECK_EXCEPTION 17
//#define MACHINE_CHECK_EXCEPTION 18
#define SIMD_FLOATING_POINT_EXCEPTION 19

#define EXTERNAL_INTERRUPT 0
#define HARDWARE_EXCEPTION 3
#define SOFTWARE_INTERRUPT 4
#define PRIVILEGED_SOFTWARE_EXCEPTION 5
#define SOFTWARE_EXCEPTION 6
#define OTHER_EVENT 7

#define EFER_LME     (1<<8)
#define EFER_LMA     (1<<10)

/*
 * Intel CPU flags in CR0
 */
#define X86_CR0_PE              0x00000001      /* Enable Protected Mode    (RW) */
#define X86_CR0_MP              0x00000002      /* Monitor Coprocessor      (RW) */
#define X86_CR0_EM              0x00000004      /* Require FPU Emulation    (RO) */
#define X86_CR0_TS              0x00000008      /* Task Switched            (RW) */
#define X86_CR0_ET              0x00000010      /* Extension type           (RO) */
#define X86_CR0_NE              0x00000020      /* Numeric Error Reporting  (RW) */
#define X86_CR0_WP              0x00010000      /* Supervisor Write Protect (RW) */
#define X86_CR0_AM              0x00040000      /* Alignment Checking       (RW) */
#define X86_CR0_NW              0x20000000      /* Not Write-Through        (RW) */
#define X86_CR0_CD              0x40000000      /* Cache Disable            (RW) */
#define X86_CR0_PG              0x80000000      /* Paging                   (RW) */

/*
 * Intel CPU features in CR4
 */
#define X86_CR4_VME		0x0001  /* enable vm86 extensions */
#define X86_CR4_PVI		0x0002  /* virtual interrupts flag enable */
#define X86_CR4_TSD		0x0004  /* disable time stamp at ipl 3 */
#define X86_CR4_DE		0x0008  /* enable debugging extensions */
#define X86_CR4_PSE		0x0010  /* enable page size extensions */
#define X86_CR4_PAE		0x0020  /* enable physical address extensions */
#define X86_CR4_MCE		0x0040  /* Machine check enable */
#define X86_CR4_PGE		0x0080  /* enable global pages */
#define X86_CR4_PCE		0x0100  /* enable performance counters at ipl 3 */
#define X86_CR4_OSFXSR		0x0200  /* enable fast FPU save and restore */
#define X86_CR4_OSXMMEXCPT	0x0400  /* enable unmasked SSE exceptions */
#define X86_CR4_VMXE		0x2000  /* enable VMX */

/*
 * Intel CPU  MSR
 */

 /* MSRs & bits used for VMX enabling */

#define MSR_IA32_VMX_BASIC   		0x480
#define MSR_IA32_FEATURE_CONTROL 		0x03a
#define MSR_IA32_VMX_PINBASED_CTLS		0x481
#define MSR_IA32_VMX_PROCBASED_CTLS		0x482
#define MSR_IA32_VMX_EXIT_CTLS		0x483
#define MSR_IA32_VMX_ENTRY_CTLS		0x484

#define MSR_IA32_SYSENTER_CS		0x174
#define MSR_IA32_SYSENTER_ESP		0x175
#define MSR_IA32_SYSENTER_EIP		0x176
#define MSR_IA32_DEBUGCTL			0x1d9

/* x86-64 MSR */

#define MSR_EFER 0xc0000080           /* extended feature register */
#define MSR_STAR 0xc0000081           /* legacy mode SYSCALL target */
#define MSR_LSTAR 0xc0000082          /* long mode SYSCALL target */
#define MSR_CSTAR 0xc0000083          /* compatibility mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084   /* EFLAGS mask for syscall */
#define MSR_FS_BASE 0xc0000100                /* 64bit FS base */
#define MSR_GS_BASE 0xc0000101                /* 64bit GS base */
#define MSR_SHADOW_GS_BASE  0xc0000102        /* SwapGS GS shadow */ 

#define CR0 0
#define CR3 3
#define CR4 4
#define CR8 8

#define RAX 0
#define RCX 1
#define RDX 2
#define RBX 3
#define RSP 4
#define RBP 5
#define RSI 6
#define RDI 7
#define R8 8
#define R9 9
#define R10 10
#define R11 11
#define R12 12
#define R13 13
#define R14 14
#define R15 15

//
// Used by the cpuid instruction when eax=1
//

typedef struct _VMX_FEATURES {
    unsigned SSE3        :1;        // SSE3 Extensions
    unsigned RES1        :2;
    unsigned MONITOR     :1;        // MONITOR/WAIT
    unsigned DS_CPL      :1;        // CPL qualified Debug Store
    unsigned VMX         :1;        // Virtual Machine Technology
    unsigned RES2        :1;
    unsigned EST         :1;        // Enhanced Intel© Speedstep Technology
    unsigned TM2         :1;        // Thermal monitor 2
    unsigned SSSE3       :1;        // SSSE3 extensions
    unsigned CID         :1;        // L1 context ID
    unsigned RES3        :2;
    unsigned CX16        :1;        // CMPXCHG16B
    unsigned xTPR        :1;        // Update control
    unsigned PDCM        :1;        // Performance/Debug capability MSR
    unsigned RES4        :2;
    unsigned DCA         :1;
    unsigned RES5        :13;
} VMX_FEATURES;

typedef struct _IA32_FEATURE_CONTROL_MSR {
    unsigned Lock            :1;        // Bit 0 is the lock bit - cannot be
                                        // modified once lock is set, controled by BIOS
    unsigned VmxonInSmx      :1;
    unsigned VmxonOutSmx     :1;
    unsigned Reserved2       :29;
    unsigned Reserved3       :32;
} IA32_FEATURE_CONTROL_MSR;

typedef struct _CR4_REG {
    unsigned VME        :1;            // Virtual Mode Extensions
    unsigned PVI        :1;            // Protected-Mode Virtual Interrupts
    unsigned TSD        :1;            // Time Stamp Disable
    unsigned DE         :1;            // Debugging Extensions
    unsigned PSE        :1;            // Page Size Extensions
    unsigned PAE        :1;            // Physical Address Extension
    unsigned MCE        :1;            // Machine-Check Enable
    unsigned PGE        :1;            // Page Global Enable
    unsigned PCE        :1;            // Performance-Monitoring Counter Enable
    unsigned OSFXSR     :1;            // OS Support for FXSAVE/FXRSTOR
    unsigned OSXMMEXCPT :1;            // OS Support for Unmasked SIMD Floating-Point Exceptions
    unsigned Reserved1  :2;            //
    unsigned VMXE       :1;            // Virtual Machine Extensions Enabled
    unsigned Reserved2  :18;           //
} CR4_REG, *PCR4_REG;


typedef struct _RFLAGS {
    unsigned CF:1;
    unsigned Reserved1:1;
    unsigned PF:1;
    unsigned Reserved2:1;
    unsigned AF:1;
    unsigned Reserved3:1;
    unsigned ZF:1;
    unsigned SF:1;
    unsigned TF:1;
    unsigned IF:1;
    unsigned DF:1;
    unsigned OF:1;
    unsigned IOPL:2;
    unsigned NT:1;
    unsigned Reserved4:1;
    unsigned RF:1;
    unsigned VM:1;
    unsigned AC:1;
    unsigned VIF:1;
    unsigned VIP:1;
    unsigned ID:1;
    unsigned Reserved5:10;
} RFLAGS, *PRFLAGS;

#define TF 0x100 

typedef union _DR6 {
    ULONG Value;
    struct {
        unsigned B0:1;
        unsigned B1:1;
        unsigned B2:1;
        unsigned B3:1;
        unsigned Reserved1:10;
        unsigned BD:1;
        unsigned BS:1;
        unsigned BT:1;
        unsigned Reserved2:16;
    };
} DR6, *PDR6;

typedef union _DR7 {
    ULONG Value;
    struct {
        unsigned L0:1;
        unsigned G0:1;
        unsigned L1:1;
        unsigned G1:1;
        unsigned L2:1;
        unsigned G2:1;
        unsigned L3:1;
        unsigned G3:1;
        unsigned LE:1;
        unsigned GE:1;
        unsigned Reserved1:3;
        unsigned GD:1;
        unsigned Reserved2:2;
        unsigned RW0:2;
        unsigned LEN0:2;
        unsigned RW1:2;
        unsigned LEN1:2;
        unsigned RW2:2;
        unsigned LEN2:2;
        unsigned RW3:2;
        unsigned LEN3:2;
    };
} DR7, *PDR7;

typedef union _IA32_DEBUGCTL_MSR
{
    ULONG Value;
    struct {
        unsigned LBR:1;
        unsigned BTF:1;
        unsigned Reserved1:4;
        unsigned TR:1;
        unsigned BTS:1;
        unsigned BTINT:1;
        unsigned BTS_OFF_OS:1;
        unsigned BTS_OFF_USR:1;
        unsigned FREEZE_LBRS_ON_PMI:1;
        unsigned FREEZE_PERFMON_ON_PMI:1;
        unsigned Reserved2:1;
        unsigned FREEZE_WHILE_SMM_EN:1;
    };
} IA32_DEBUGCTL_MSR, *PIA32_DEBUGCTL_MSR;

typedef struct _MSR {
    ULONG Lo;
    ULONG Hi;
} MSR, *PMSR;

typedef struct _VMX_BASIC_MSR {
    unsigned RevId:32;
    unsigned szVmxOnRegion:12;
    unsigned ClearBit:1;
    unsigned Reserved:3;
    unsigned PhysicalWidth:1;
    unsigned DualMonitor:1;
    unsigned MemoryType:4;
    unsigned VmExitInformation:1;
    unsigned Reserved2:9;
} VMX_BASIC_MSR, *PVMX_BASIC_MSR;

typedef struct _GUEST_REGS
{
  ULONG64 rax;                  
  ULONG64 rcx;
  ULONG64 rdx;                 
  ULONG64 rbx;
  ULONG64 rsp;                  
  ULONG64 rbp;
  ULONG64 rsi;                  
  ULONG64 rdi;
  ULONG64 r8;                   
  ULONG64 r9;
  ULONG64 r10;                  
  ULONG64 r11;
  ULONG64 r12;                  
  ULONG64 r13;
  ULONG64 r14;                  
  ULONG64 r15;
} GUEST_REGS, *PGUEST_REGS;

USHORT _Cs();
USHORT _Ds();
USHORT _Es();
USHORT _Ss();
USHORT _Fs();
USHORT _Gs();
ULONG64 _Cr0();
ULONG64 _Cr2();
VOID _SetCr2(ULONG64 NewCr2);
ULONG64 _Cr3();
ULONG64 _Cr4();
VOID _SetCr4(ULONG32 mask);

ULONG64 _Cr8();
ULONG64 _Rflags();
ULONG64 _Rsp();

ULONG64 _IdtBase();
USHORT _IdtLimit();
ULONG64 _GdtBase();
USHORT _GdtLimit();
USHORT _Ldtr();

USHORT _TrSelector();

ULONG64 _Rbx();
ULONG64 _Rax();

ULONG64 _TSC();

ULONG64 _Dr0();
ULONG64 _Dr1();
ULONG64 _Dr2();
ULONG64 _Dr3();
ULONG64 _Dr6();
ULONG64 _SetDr0();
ULONG64 _SetDr1();
ULONG64 _SetDr2();
ULONG64 _SetDr3();

ULONG64 _SetCr3(PVOID NewCr3);
ULONG64 _SetCr8(ULONG64 NewCr8);

VOID _CpuId(ULONG32 fn, OUT PULONG32 ret_eax, OUT PULONG32 ret_ebx, OUT
        PULONG32 ret_ecx, OUT PULONG32 ret_edx);

ULONG64 _ReadMsr(ULONG32 reg);
VOID _WriteMsr(ULONG32 reg, ULONG64 MsrValue);

VOID _VmxOn(PHYSICAL_ADDRESS PA);
VOID _VmxOff(ULONG64 Rip, ULONG64 Rsp);
ULONG64 _ReadVMCS(ULONG32 Encoding);
VOID _WriteVMCS(ULONG32 Encoding, ULONG64 Value);
VOID _VmPtrLd(PHYSICAL_ADDRESS PA);
VOID _VmClear(PHYSICAL_ADDRESS PA);
ULONG _VmLaunch();
VOID _VmResume();

ULONG32 _VmFailValid();
ULONG32 _VmFailInvalid();

VOID _GuestEntryPoint();
VOID _ExitHandler();
NTSTATUS _StartVirtualization();

VOID _StopVirtualization();
VOID _GuestExit();

VOID _Int3();
VOID _Invd();

VOID _InvalidatePage(ULONG64 Page);
VOID _SetInterrupts();
VOID _ClearInterrupts();

VOID _InitSpinLock(PULONG32 Lock);
VOID _AcquireSpinLock(PULONG32 Lock);
VOID _ReleaseSpinLock(PULONG32 Lock);


#endif
