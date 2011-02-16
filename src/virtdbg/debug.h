// This file is part of Virtdbg
// Copyright (C) 2010-2011 Damien AUMAITRE

//  Licence is GPLv3, see LICENCE.txt in the top-level directory


#ifndef _VIRTDBG_DEBUG_H
#define _VIRTDBG_DEBUG_H

#include <ntddk.h>
#include "amd64.h"
#include "vmx.h"
#include "mem.h"
#include "protocol.h"

NTSTATUS InitDebugLayer();

static BOOLEAN HandleVmInstruction(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs);
static BOOLEAN HandleUnimplemented(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, ULONG64 ExitCode);
static BOOLEAN HandleCpuid(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs);
static BOOLEAN HandleMsrRead(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs);
static BOOLEAN HandleMsrWrite(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs);
static BOOLEAN HandleDrAccess(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs);
static BOOLEAN HandleCrAccess(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs);
static BOOLEAN HandleException(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs);
static BOOLEAN HandleNmi(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs);
static BOOLEAN HandleInvd(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs);

VOID HandleVmExit(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs);

static VOID EnableTF();
static VOID DisableTF();

static VOID ReportException(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, ULONG Exception, ULONG64 Address);
static BOOLEAN EnterDebugger(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, ULONG64 Cr3);
static VOID FreezeExecution(PVIRT_CPU pCpu);
static VOID ResumeCpus(ULONG32 RunningProcessor);
static VOID FreezeCpus(ULONG32 RunningProcessor);

static BOOLEAN HandleClientRequest(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, ULONG64 Cr3);

static BOOLEAN HandleContinuePacket(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, PVOID pPacket);

static BOOLEAN HandleBreakinPacket(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, PVOID pPacket, ULONG64 Cr3);

#endif
