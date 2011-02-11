#ifndef _VIRTDBG_DEBUG_H
#define _VIRTDBG_DEBUG_H

#include <ntddk.h>
#include "amd64.h"
#include "vmx.h"
#include "mem.h"
#include "protocol.h"

static BOOLEAN HandleVmInstruction(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs);
static BOOLEAN HandleUnimplemented(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, ULONG64 ExitCode);
static BOOLEAN HandleCpuid(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs);
static BOOLEAN HandleMsrRead(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs);
static BOOLEAN HandleMsrWrite(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs);
static BOOLEAN HandleCrAccess(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs);
static BOOLEAN HandleNmi(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs);
static BOOLEAN HandleInvd(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs);

VOID HandleVmExit(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs);
NTSTATUS InitDebugLayer();

static VOID ReportException(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, ULONG Exception, ULONG64 Address);
static BOOLEAN EnterDebugger(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, ULONG64 Cr3);
static VOID FreezeExecution(PVIRT_CPU pCpu);
static VOID ResumeCpus(ULONG32 RunningProcessor);
static VOID FreezeCpus(ULONG32 RunningProcessor);


#endif
