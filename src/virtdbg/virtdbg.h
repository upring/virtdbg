#ifndef _VIRTDBG_MAIN_H
#define _VIRTDBG_MAIN_H

#include <ntddk.h>
#include "amd64.h"
#include "vmx.h"
#include "mem.h"
#include "misc.h"
#include "protocol.h"

typedef struct _VIRTDBG_CONTROL_AREA
{
    ULONG32 Magic1;
    ULONG32 Magic2;
    PHYSICAL_ADDRESS SendArea;
    PHYSICAL_ADDRESS RecvArea;
    PVOID KernelBase;
    PVOID DebuggerData;
    PVOID LogBuffer;
} VIRTDBG_CONTROL_AREA, *PVIRTDBG_CONTROL_AREA;

#define CONTROL_AREA_SIZE 0x1000
#define CONTROL_AREA_MAGIC1 0xbabebabe
#define CONTROL_AREA_MAGIC2 0xcafecafe

NTSTATUS VirtDbgStart(PVOID StartContext);
NTSTATUS InitControlArea();
NTSTATUS StartVirtualization(PVOID GuestRsp);

#endif

