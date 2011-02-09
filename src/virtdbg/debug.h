#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <ntddk.h>
#include "amd64.h"
#include "mem.h"
#include "snprintf.h"
#include <stdarg.h>
#include "vmx.h"

typedef struct _PACKET_HEADER {
    ULONG32 Magic;
    ULONG32 Type;
    ULONG32 Size;
    ULONG32 Id;
    ULONG32 Checksum;
} PACKET_HEADER, *PPACKET_HEADER;

typedef struct _BREAKIN_PACKET {
    ULONG64 Cr3;
} BREAKIN_PACKET, *PBREAKIN_PACKET;

#define CONTINUE_STATUS_SINGLE_STEP 0x1
#define CONTINUE_STATUS_UNLOAD 0x2

typedef struct _CONTINUE_PACKET {
    ULONG32 Status;
} CONTINUE_PACKET, *PCONTINUE_PACKET;

typedef struct _SOFTWARE_BREAKPOINT_PACKET {
    ULONG64 Address;
} SOFTWARE_BREAKPOINT_PACKET, *PSOFTWARE_BREAKPOINT_PACKET;

typedef struct _HARDWARE_BREAKPOINT_PACKET {
    ULONG64 Address;
} HARDWARE_BREAKPOINT_PACKET, *PHARDWARE_BREAKPOINT_PACKET;

typedef struct _MEMORY_BREAKPOINT_PACKET {
    ULONG64 Address;
} MEMORY_BREAKPOINT_PACKET, *PMEMORY_BREAKPOINT_PACKET;

typedef struct _STATE_CHANGE_PACKET {
    ULONG32 Exception;
    ULONG64 Address;
} STATE_CHANGE_PACKET, *PSTATE_CHANGE_PACKET;

typedef struct _READ_VIRTUAL_MEMORY_PACKET {
    ULONG64 Address;
    ULONG32 Size;
} READ_VIRTUAL_MEMORY_PACKET, *PREAD_VIRTUAL_MEMORY_PACKET;

typedef struct _WRITE_VIRTUAL_MEMORY_PACKET {
    ULONG64 Address;
    ULONG32 Size;
} WRITE_VIRTUAL_MEMORY_PACKET, *PWRITE_VIRTUAL_MEMORY_PACKET;

typedef struct _READ_PHYSICAL_MEMORY_PACKET {
    ULONG64 Address;
    ULONG32 Size;
} READ_PHYSICAL_MEMORY_PACKET, *PREAD_PHYSICAL_MEMORY_PACKET;

typedef struct _WRITE_PHYSICAL_MEMORY_PACKET {
    ULONG64 Address;
    ULONG32 Size;
} WRITE_PHYSICAL_MEMORY_PACKET, *PWRITE_PHYSICAL_MEMORY_PACKET;

typedef struct _DEBUG_CONTEXT {
    ULONG64 rax;
    ULONG64 rbx;
    ULONG64 rcx;
    ULONG64 rdx;
    ULONG64 rsi;
    ULONG64 rdi;
    ULONG64 rbp;
    ULONG64 rsp;
    ULONG64 r8;
    ULONG64 r9;
    ULONG64 r10;
    ULONG64 r11;
    ULONG64 r12;
    ULONG64 r13;
    ULONG64 r14;
    ULONG64 r15;
    ULONG64 rip;
    ULONG64 rflags;
    ULONG64 cr0;
    ULONG64 cr3;
    ULONG64 cr4;
    ULONG64 cr8;
    ULONG64 dr0;
    ULONG64 dr1;
    ULONG64 dr2;
    ULONG64 dr3;
    ULONG64 dr6;
    ULONG64 dr7;
    USHORT cs;
    USHORT ds;
    USHORT es;
    USHORT fs;
    USHORT ss;
    USHORT gs;
} DEBUG_CONTEXT, *PDEBUG_CONTEXT;

typedef struct _GET_CONTEXT_PACKET {
    ULONG32 Flags;
} GET_CONTEXT_PACKET, *PGET_CONTEXT_PACKET;

typedef struct _SET_CONTEXT_PACKET {
    ULONG32 Flags;
} SET_CONTEXT_PACKET, *PSET_CONTEXT_PACKET;

typedef struct _MANIPULATE_STATE_PACKET {
    ULONG32 ApiNumber;
    ULONG32 Error;
    union {
        READ_VIRTUAL_MEMORY_PACKET ReadVirtualMemory;
        WRITE_VIRTUAL_MEMORY_PACKET WriteVirtualMemory;
        READ_PHYSICAL_MEMORY_PACKET ReadPhysicalMemory;
        WRITE_PHYSICAL_MEMORY_PACKET WritePhysicalMemory;
        GET_CONTEXT_PACKET GetContext;
        SET_CONTEXT_PACKET SetContext;
    } u;
} MANIPULATE_STATE_PACKET, *PMANIPULATE_STATE_PACKET;

#define PACKET_TYPE_RESET 1
#define PACKET_TYPE_BREAKIN 2
#define PACKET_TYPE_ACK 3
#define PACKET_TYPE_RESEND 4
#define PACKET_TYPE_STATE_CHANGE 5
#define PACKET_TYPE_MANIPULATE_STATE 6
#define PACKET_TYPE_CONTINUE 7

#define READ_VIRTUAL_MEMORY_API 0x41
#define WRITE_VIRTUAL_MEMORY_API 0x42
#define GET_CONTEXT_API 0x43
#define SET_CONTEXT_API 0x44

#define INITIAL_ID 0x41424344
#define PACKET_MAGIC 0xdeadbabe

#define MAX_PACKET_SIZE 0x300

#define SEND_BASE_OFFSET 0x800
#define MAX_RETRIES 0x1000000

#define CONTROL_AREA_SIZE 0x1000

typedef struct _CONTROL_AREA
{
    ULONG Magic1;
    ULONG Magic2;
    PHYSICAL_ADDRESS SendArea;
    PHYSICAL_ADDRESS RecvArea;
    PVOID KernelBase;
    PVOID DebuggerData;
    PVOID LogBuffer;
} CONTROL_AREA, *PCONTROL_AREA;

#define LOGBUFFER_SIZE 0x10000

typedef struct _LOGENTRY
{
    ULONG32 Id;
    ULONG32 Size;
    PVOID Data;
} LOGENTRY, *PLOGENTRY;

PVOID InitLog();
VOID Log(char *format, ...);

//#define DbgLog(_args_) { DbgPrint("vmx[#%d][IRQL=0x%x](%s): ", KeGetCurrentProcessorNumber(), KeGetCurrentIrql(), __FUNCTION__); DbgPrint _args_; }
#define DbgLog(_args_) { Log("vmx[#%d][IRQL=0x%x](%s): ", KeGetCurrentProcessorNumber(), KeGetCurrentIrql(), __FUNCTION__); Log _args_; }

NTSTATUS InitDebugLayer();
VOID ShutdownDebug();
PVOID ReceivePacket(ULONG32 Retries);
BOOLEAN SendPacket(PVOID pPacket, ULONG32 Retries);

VOID ReportException(PVOID pCpu, PGUEST_REGS pGuestRegs, ULONG Exception, ULONG64 Address);
BOOLEAN EnterDebugger(PVOID pCpu, PGUEST_REGS pGuestRegs, ULONG64 Cr3);
VOID DestroyPacket(PVOID pPacket);

VOID FreezeExecution(PVOID pCpu);
VOID ResumeCpus(ULONG32 RunningProcessor);
VOID FreezeCpus(ULONG32 RunningProcessor);

#endif
