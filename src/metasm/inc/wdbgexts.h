/*++

Copyright (c) Microsoft Corporation. All rights reserved.

Module Name:

    wdbgexts.h

Abstract:

    This file contains the necessary prototypes and data types for a user
    to write a debugger extension DLL.  This header file is also included
    by the NT debuggers (WINDBG & KD).

    This header file must be included after "windows.h" and "dbghelp.h".

    Please see the NT DDK documentation for specific information about
    how to write your own debugger extension DLL.

Environment:

    Win32 only.

Revision History:

--*/
#ifdef __cplusplus
extern "C" {
#endif


#define VOID void
#define STDCALL __stdcall
#define FASTCALL __fastcall
#define CDECL __cdecl
#define THISCALL __thiscall
#define NEAR 
#define FAR 

typedef signed char INT8;
typedef signed char CHAR;
typedef unsigned char UCHAR;
typedef signed short INT16;
typedef signed int INT32;
typedef signed int BOOL;
typedef signed __int64 INT64;
typedef signed __int64 LONG64;
typedef signed long LONG32;
typedef unsigned char UINT8;
typedef unsigned char BYTE;
typedef unsigned short UINT16;
typedef unsigned short WCHAR;
typedef unsigned int UINT32;
typedef unsigned __int64 UINT64;
typedef unsigned __int64 ULONG64;
typedef unsigned long ULONG32;
typedef float FLOAT32;
typedef double FLOAT64;
typedef struct {unsigned short W[5];} FLOAT80;
typedef struct { __int64 LowPart;__int64 HighPart;} FLOAT128;
typedef double DATE;
typedef signed long HRESULT;
typedef union { struct {unsigned long Lo; long Hi;}; __int64 int64;} CURRENCY;


typedef struct _LIST_ENTRY64 // 2 elements, 0x10 bytes (sizeof) 
          {                                                               
/*0x000*/     UINT64       Flink;                                         
/*0x008*/     UINT64       Blink;                                         
          }LIST_ENTRY64, *PLIST_ENTRY64; 

typedef struct _DBGKD_GET_VERSION64 {
    UINT16  MajorVersion;
    UINT16  MinorVersion;
    UCHAR   ProtocolVersion;
    UCHAR   KdSecondaryVersion; // Cannot be 'A' for compat with dump header
    UINT16  Flags;
    UINT16  MachineType;

    //
    // Protocol command support descriptions.
    // These allow the debugger to automatically
    // adapt to different levels of command support
    // in different kernels.
    //

    // One beyond highest packet type understood, zero based.
    UCHAR   MaxPacketType;
    // One beyond highest state change understood, zero based.
    UCHAR   MaxStateChange;
    // One beyond highest state manipulate message understood, zero based.
    UCHAR   MaxManipulate;

    // Kind of execution environment the kernel is running in,
    // such as a real machine or a simulator.  Written back
    // by the simulation if one exists.
    UCHAR   Simulation;

    UINT16  Unused[1];

    ULONG64 KernBase;
    ULONG64 PsLoadedModuleList;

    //
    // Components may register a debug data block for use by
    // debugger extensions.  This is the address of the list head.
    //
    // There will always be an entry for the debugger.
    //

    ULONG64 DebuggerDataList;

} DBGKD_GET_VERSION64, *PDBGKD_GET_VERSION64;


//
// This structure is used by the debugger for all targets
// It is the same size as DBGKD_DATA_HEADER on all systems
//
typedef struct _DBGKD_DEBUG_DATA_HEADER64 {

    //
    // Link to other blocks
    //

    struct _LIST_ENTRY64 List;

    //
    // This is a unique tag to identify the owner of the block.
    // If your component only uses one pool tag, use it for this, too.
    //

    ULONG32           OwnerTag;

    //
    // This must be initialized to the size of the data block,
    // including this structure.
    //

    ULONG32           Size;

} DBGKD_DEBUG_DATA_HEADER64, *PDBGKD_DEBUG_DATA_HEADER64;


//
// This structure is the same size on all systems.  The only field
// which must be translated by the debugger is Header.List.
//

//
// DO NOT ADD OR REMOVE FIELDS FROM THE MIDDLE OF THIS STRUCTURE!!!
//
// If you remove a field, replace it with an "unused" placeholder.
// Do not reuse fields until there has been enough time for old debuggers
// and extensions to age out.
//
typedef struct _KDDEBUGGER_DATA64 {

    struct _DBGKD_DEBUG_DATA_HEADER64 Header;

    //
    // Base address of kernel image
    //

    ULONG64   KernBase;

    //
    // DbgBreakPointWithStatus is a function which takes an argument
    // and hits a breakpoint.  This field contains the address of the
    // breakpoint instruction.  When the debugger sees a breakpoint
    // at this address, it may retrieve the argument from the first
    // argument register, or on x86 the eax register.
    //

    ULONG64   BreakpointWithStatus;       // address of breakpoint

    //
    // Address of the saved context record during a bugcheck
    //
    // N.B. This is an automatic in KeBugcheckEx's frame, and
    // is only valid after a bugcheck.
    //

    ULONG64   SavedContext;

    //
    // help for walking stacks with user callbacks:
    //

    //
    // The address of the thread structure is provided in the
    // WAIT_STATE_CHANGE packet.  This is the offset from the base of
    // the thread structure to the pointer to the kernel stack frame
    // for the currently active usermode callback.
    //

    UINT16  ThCallbackStack;            // offset in thread data

    //
    // these values are offsets into that frame:
    //

    UINT16  NextCallback;               // saved pointer to next callback frame
    UINT16  FramePointer;               // saved frame pointer

    //
    // pad to a quad boundary
    //
    UINT16  PaeEnabled;

    //
    // Address of the kernel callout routine.
    //

    ULONG64   KiCallUserMode;             // kernel routine

    //
    // Address of the usermode entry point for callbacks.
    //

    ULONG64   KeUserCallbackDispatcher;   // address in ntdll


    //
    // Addresses of various kernel data structures and lists
    // that are of interest to the kernel debugger.
    //

    ULONG64   PsLoadedModuleList;
    ULONG64   PsActiveProcessHead;
    ULONG64   PspCidTable;

    ULONG64   ExpSystemResourcesList;
    ULONG64   ExpPagedPoolDescriptor;
    ULONG64   ExpNumberOfPagedPools;

    ULONG64   KeTimeIncrement;
    ULONG64   KeBugCheckCallbackListHead;
    ULONG64   KiBugcheckData;

    ULONG64   IopErrorLogListHead;

    ULONG64   ObpRootDirectoryObject;
    ULONG64   ObpTypeObjectType;

    ULONG64   MmSystemCacheStart;
    ULONG64   MmSystemCacheEnd;
    ULONG64   MmSystemCacheWs;

    ULONG64   MmPfnDatabase;
    ULONG64   MmSystemPtesStart;
    ULONG64   MmSystemPtesEnd;
    ULONG64   MmSubsectionBase;
    ULONG64   MmNumberOfPagingFiles;

    ULONG64   MmLowestPhysicalPage;
    ULONG64   MmHighestPhysicalPage;
    ULONG64   MmNumberOfPhysicalPages;

    ULONG64   MmMaximumNonPagedPoolInBytes;
    ULONG64   MmNonPagedSystemStart;
    ULONG64   MmNonPagedPoolStart;
    ULONG64   MmNonPagedPoolEnd;

    ULONG64   MmPagedPoolStart;
    ULONG64   MmPagedPoolEnd;
    ULONG64   MmPagedPoolInformation;
    ULONG64   MmPageSize;

    ULONG64   MmSizeOfPagedPoolInBytes;

    ULONG64   MmTotalCommitLimit;
    ULONG64   MmTotalCommittedPages;
    ULONG64   MmSharedCommit;
    ULONG64   MmDriverCommit;
    ULONG64   MmProcessCommit;
    ULONG64   MmPagedPoolCommit;
    ULONG64   MmExtendedCommit;

    ULONG64   MmZeroedPageListHead;
    ULONG64   MmFreePageListHead;
    ULONG64   MmStandbyPageListHead;
    ULONG64   MmModifiedPageListHead;
    ULONG64   MmModifiedNoWritePageListHead;
    ULONG64   MmAvailablePages;
    ULONG64   MmResidentAvailablePages;

    ULONG64   PoolTrackTable;
    ULONG64   NonPagedPoolDescriptor;

    ULONG64   MmHighestUserAddress;
    ULONG64   MmSystemRangeStart;
    ULONG64   MmUserProbeAddress;

    ULONG64   KdPrintCircularBuffer;
    ULONG64   KdPrintCircularBufferEnd;
    ULONG64   KdPrintWritePointer;
    ULONG64   KdPrintRolloverCount;

    ULONG64   MmLoadedUserImageList;

    // NT 5.1 Addition

    ULONG64   NtBuildLab;
    ULONG64   KiNormalSystemCall;

    // NT 5.0 hotfix addition

    ULONG64   KiProcessorBlock;
    ULONG64   MmUnloadedDrivers;
    ULONG64   MmLastUnloadedDriver;
    ULONG64   MmTriageActionTaken;
    ULONG64   MmSpecialPoolTag;
    ULONG64   KernelVerifier;
    ULONG64   MmVerifierData;
    ULONG64   MmAllocatedNonPagedPool;
    ULONG64   MmPeakCommitment;
    ULONG64   MmTotalCommitLimitMaximum;
    ULONG64   CmNtCSDVersion;

    // NT 5.1 Addition

    ULONG64   MmPhysicalMemoryBlock;
    ULONG64   MmSessionBase;
    ULONG64   MmSessionSize;
    ULONG64   MmSystemParentTablePage;

    // Server 2003 addition

    ULONG64   MmVirtualTranslationBase;

    UINT16    OffsetKThreadNextProcessor;
    UINT16    OffsetKThreadTeb;
    UINT16    OffsetKThreadKernelStack;
    UINT16    OffsetKThreadInitialStack;

    UINT16    OffsetKThreadApcProcess;
    UINT16    OffsetKThreadState;
    UINT16    OffsetKThreadBStore;
    UINT16    OffsetKThreadBStoreLimit;

    UINT16    SizeEProcess;
    UINT16    OffsetEprocessPeb;
    UINT16    OffsetEprocessParentCID;
    UINT16    OffsetEprocessDirectoryTableBase;

    UINT16    SizePrcb;
    UINT16    OffsetPrcbDpcRoutine;
    UINT16    OffsetPrcbCurrentThread;
    UINT16    OffsetPrcbMhz;

    UINT16    OffsetPrcbCpuType;
    UINT16    OffsetPrcbVendorString;
    UINT16    OffsetPrcbProcStateContext;
    UINT16    OffsetPrcbNumber;

    UINT16    SizeEThread;

    ULONG64   KdPrintCircularBufferPtr;
    ULONG64   KdPrintBufferSize;

    ULONG64   KeLoaderBlock;

    UINT16    SizePcr;
    UINT16    OffsetPcrSelfPcr;
    UINT16    OffsetPcrCurrentPrcb;
    UINT16    OffsetPcrContainedPrcb;

    UINT16    OffsetPcrInitialBStore;
    UINT16    OffsetPcrBStoreLimit;
    UINT16    OffsetPcrInitialStack;
    UINT16    OffsetPcrStackLimit;

    UINT16    OffsetPrcbPcrPage;
    UINT16    OffsetPrcbProcStateSpecialReg;
    UINT16    GdtR0Code;
    UINT16    GdtR0Data;

    UINT16    GdtR0Pcr;
    UINT16    GdtR3Code;
    UINT16    GdtR3Data;
    UINT16    GdtR3Teb;

    UINT16    GdtLdt;
    UINT16    GdtTss;
    UINT16    Gdt64R3CmCode;
    UINT16    Gdt64R3CmTeb;

    ULONG64   IopNumTriageDumpDataBlocks;
    ULONG64   IopTriageDumpDataBlocks;

    // Longhorn addition

    ULONG64   VfCrashDataBlock;
    ULONG64   MmBadPagesDetected;
    ULONG64   MmZeroedPageSingleBitErrorsDetected;


} KDDEBUGGER_DATA64, *PKDDEBUGGER_DATA64;


