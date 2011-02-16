// This file is part of Virtdbg
// Copyright (C) 2010-2011 Damien AUMAITRE

//  Licence is GPLv3, see LICENCE.txt in the top-level directory


#include "debug.h"

extern LONG g_Initialized;
extern PVIRTDBG_CONTROL_AREA g_ControlArea;

static PKSPIN_LOCK g_FreezeLock = NULL;
static LONG g_pagefaults = 0;


NTSTATUS InitDebugLayer()
{
    g_FreezeLock = AllocateMemory(sizeof(KSPIN_LOCK));

    if (!g_FreezeLock)
        return STATUS_UNSUCCESSFUL;

    KeInitializeSpinLock(g_FreezeLock);

    return STATUS_SUCCESS;
}

/*VOID ShutdownDebug()*/
/*{*/
/*    MmUnmapIoSpace(g_RecvBase, 0x1000);*/
/*    return;*/
/*}*/


static BOOLEAN HandleVmInstruction(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
    ULONG64 InstructionLength, Rip;
    
    Rip = _ReadVMCS(GUEST_RIP);
    DbgLog(("VmInstruction: guest_rip = 0x%llx\n", Rip));
    
    /* _VmFailInvalid */
    _WriteVMCS(GUEST_RFLAGS, _ReadVMCS(GUEST_RFLAGS) | 0x1);

    InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
    _WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP)+InstructionLength);

    return TRUE;
}

static BOOLEAN HandleVmCall(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
    ULONG64 InstructionLength, Rip, Rsp;

    Rip = _ReadVMCS(GUEST_RIP);
    DbgLog(("VmCall: guest_rip = 0x%llx\n", Rip));

    InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);

    if ((pGuestRegs->rax == 0x42424242) && (pGuestRegs->rbx == 0x43434343)) 
    {
        DbgLog(("got magic sequence, terminating\n"));
        Rip = (ULONG64)_GuestExit;
        Rsp = pGuestRegs->rsp;
        DbgLog(("restoring rip=0x%llx, rsp=0x%llx\n", Rip, Rsp));
        _VmxOff(Rip, Rsp);
    }
    else
    {
        _WriteVMCS(GUEST_RIP, Rip+InstructionLength);
    }

    
    return TRUE;
}


static BOOLEAN HandleUnimplemented(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, ULONG64 ExitCode)
{
    ULONG64 InstructionLength;

    DbgLog(("vmx: unimplemented\n"));
    DbgLog(("vmx: exitcode = 0x%llx\n", ExitCode));
    DbgLog(("vmx: guest_rip = 0x%llx\n", _ReadVMCS(GUEST_RIP)));

    InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
    _WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP)+InstructionLength);

    return TRUE;
}

static BOOLEAN InjectInt1(ULONG64 Rip)
{
    ULONG32 InjectEvent;
    PINTERRUPT_INJECT_INFO_FIELD pInjectEvent;

    InjectEvent = 0;
    pInjectEvent = (PINTERRUPT_INJECT_INFO_FIELD)&InjectEvent;

    pInjectEvent->Vector = DEBUG_EXCEPTION; 
    pInjectEvent->InterruptionType = HARDWARE_EXCEPTION;
 
    pInjectEvent->DeliverErrorCode = 0;
    pInjectEvent->Valid = 1;
    _WriteVMCS(VM_ENTRY_INTR_INFO_FIELD, InjectEvent);

    return TRUE;
}


static BOOLEAN HandleCpuid(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
    ULONG32 Function, eax, ebx, ecx, edx;
    ULONG64 InstructionLength;

    Function = (ULONG32)pGuestRegs->rax;
    ecx = (ULONG32)pGuestRegs->rcx;
/*    DbgLog(("vmx: cpuid on processor #%d: Function=0x%x\n",*/
/*            KeGetCurrentProcessorNumber(), Function));*/
/*    DbgLog(("vmx: HandleCpuid(): guest_rip = 0x%llx\n", _ReadVMCS(GUEST_RIP)));*/
    _CpuId(Function, &eax, &ebx, &ecx, &edx);
    pGuestRegs->rax = eax;
    pGuestRegs->rbx = ebx;
    pGuestRegs->rcx = ecx;
    pGuestRegs->rdx = edx;

    InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
    _WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP)+InstructionLength);

    return TRUE;
}

static BOOLEAN HandleMsrRead(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
    LARGE_INTEGER Msr;
    ULONG32 ecx;
    ULONG64 InstructionLength;

    ecx = (ULONG32)pGuestRegs->rcx;

    DbgLog(("vmx: HandleMsrRead(): msr = 0x%x\n", ecx));

    switch (ecx)
    {
        case MSR_IA32_SYSENTER_CS:
            Msr.QuadPart = _ReadVMCS(GUEST_SYSENTER_CS);
            break;
        
        case MSR_IA32_SYSENTER_ESP:
            Msr.QuadPart = _ReadVMCS(GUEST_SYSENTER_ESP);
            break;

        case MSR_IA32_SYSENTER_EIP:
            Msr.QuadPart = _ReadVMCS(GUEST_SYSENTER_EIP);
            break;
    
        case MSR_GS_BASE:
            Msr.QuadPart = _ReadVMCS(GUEST_GS_BASE);
            break;

        case MSR_FS_BASE:
            Msr.QuadPart = _ReadVMCS(GUEST_FS_BASE);
            break;

        default:
            Msr.QuadPart = _ReadMsr(ecx);
            break;
    }

    pGuestRegs->rax = Msr.LowPart;
    pGuestRegs->rdx = Msr.HighPart;

    InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
    _WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP)+InstructionLength);

    return TRUE;
}

static BOOLEAN HandleMsrWrite(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
    LARGE_INTEGER Msr;
    ULONG32 ecx;
    ULONG64 InstructionLength;

    ecx = (ULONG32)pGuestRegs->rcx;

    DbgLog(("vmx: HandleMsrWrite(): msr = 0x%x\n", ecx));
    Msr.LowPart = (ULONG32)pGuestRegs->rax;
    Msr.HighPart = (ULONG32)pGuestRegs->rdx;

    switch (ecx)
    {
        case MSR_IA32_SYSENTER_CS:
            _WriteVMCS(GUEST_SYSENTER_CS, Msr.QuadPart);
            break;
        
        case MSR_IA32_SYSENTER_ESP:
            _WriteVMCS(GUEST_SYSENTER_ESP, Msr.QuadPart);
            break;

        case MSR_IA32_SYSENTER_EIP:
            _WriteVMCS(GUEST_SYSENTER_EIP, Msr.QuadPart);
            break;
    
        case MSR_GS_BASE:
            _WriteVMCS(GUEST_GS_BASE, Msr.QuadPart);
            break;

        case MSR_FS_BASE:
            _WriteVMCS(GUEST_FS_BASE, Msr.QuadPart);
            break;

        default:
            _WriteMsr(ecx, Msr.QuadPart);
            break;
    }

    InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
    _WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP)+InstructionLength);

    return TRUE;
}


static BOOLEAN HandleDrAccess(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
    DbgLog(("DrAccess\n"));
    return TRUE;
}


static BOOLEAN HandleCrAccess(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
    PMOV_CR_QUALIFICATION pExitQualification;
    ULONG64 Exit;
    ULONG64 Cr;
    ULONG64 Reg;
    ULONG64 InstructionLength;

    Exit =_ReadVMCS(EXIT_QUALIFICATION);
    pExitQualification = (PMOV_CR_QUALIFICATION)&Exit;
    
    switch (pExitQualification->ControlRegister)
    {
        case CR0:
            Cr = _ReadVMCS(GUEST_CR0);
            break;

        case CR3:
            Cr = _ReadVMCS(GUEST_CR3);
            break;

        case CR4:
            Cr = _ReadVMCS(GUEST_CR4);
            break;

        default:
            Cr = 0;
            _Int3();
            break;
    }

    switch (pExitQualification->Register)
    {
        case RAX:
            Reg = pGuestRegs->rax;
            break;

        case RCX:
            Reg = pGuestRegs->rcx;
            break;

        case RDX:
            Reg = pGuestRegs->rdx;
            break;

        case RBX:
            Reg = pGuestRegs->rbx;
            break;

        case RSP:
            Reg = pGuestRegs->rsp;
            break;

        case RBP:
            Reg = pGuestRegs->rbp;
            break;

        case RSI:
            Reg = pGuestRegs->rsi;
            break;

        case RDI:
            Reg = pGuestRegs->rdi;
            break;

        case R8:
            Reg = pGuestRegs->r8;
            break;

        case R9:
            Reg = pGuestRegs->r9;
            break;

        case R10:
            Reg = pGuestRegs->r10;
            break;

        case R11:
            Reg = pGuestRegs->r11;
            break;

        case R12:
            Reg = pGuestRegs->r12;
            break;

        case R13:
            Reg = pGuestRegs->r13;
            break;

        case R14:
            Reg = pGuestRegs->r14;
            break;

        case R15:
            Reg = pGuestRegs->r15;
            break;

        default:
            Reg = 0;
            _Int3();
            break;

    }

    switch (pExitQualification->AccessType)
    {
        case MOV_TO_CR:
            switch (pExitQualification->ControlRegister)
            {
                case CR0:
                    _WriteVMCS(GUEST_CR0, Reg);
                    break;

                case CR3:
                    HandleClientRequest(pCpu, pGuestRegs, Reg);
                    _WriteVMCS(GUEST_CR3, Reg);
                    break;

                case CR4:
                    _WriteVMCS(GUEST_CR4, Reg);
                    break;

                default:
                    _Int3();
                    break;
            }
            break;

        case MOV_FROM_CR:
            switch (pExitQualification->Register)
            {
                case RAX:
                    pGuestRegs->rax = Cr;
                    break;

                case RCX:
                    pGuestRegs->rcx = Cr;
                    break;

                case RDX:
                    pGuestRegs->rdx = Cr;
                    break;

                case RBX:
                    pGuestRegs->rbx = Cr;
                    break;

                case RSP:
                    pGuestRegs->rsp = Cr;
                    break;

                case RBP:
                    pGuestRegs->rbp = Cr;
                    break;

                case RSI:
                    pGuestRegs->rsi = Cr;
                    break;

                case RDI:
                    pGuestRegs->rdi = Cr;
                    break;

                case R8:
                    pGuestRegs->r8 = Cr;
                    break;

                case R9:
                    pGuestRegs->r9 = Cr;
                    break;

                case R10:
                    pGuestRegs->r10 = Cr;
                    break;

                case R11:
                    pGuestRegs->r11 = Cr;
                    break;

                case R12:
                    pGuestRegs->r12 = Cr;
                    break;

                case R13:
                    pGuestRegs->r13 = Cr;
                    break;

                case R14:
                    pGuestRegs->r14 = Cr;
                    break;

                case R15:
                    pGuestRegs->r15 = Cr;
                    break;

                default:
                    _Int3();
                    break;
            }

            break;

        default:
            _Int3();
            break;
    }

    InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
    _WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP)+InstructionLength);

    return TRUE;
}

static BOOLEAN HandleException(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
    ULONG32 Event, InjectEvent;
    ULONG64 ErrorCode, ExitQualification, GuestRip;
    PINTERRUPT_INFO_FIELD pEvent;
    PINTERRUPT_INJECT_INFO_FIELD pInjectEvent;

    Event = (ULONG32)_ReadVMCS(VM_EXIT_INTR_INFO);
    pEvent = (PINTERRUPT_INFO_FIELD)&Event;
    
    InjectEvent = 0;
    pInjectEvent = (PINTERRUPT_INJECT_INFO_FIELD)&InjectEvent;
    
    GuestRip = _ReadVMCS(GUEST_RIP);

    switch (pEvent->InterruptionType)
    {
        case NMI_INTERRUPT:
            DbgLog(("vmx: HandleNmi()\n"));
            InjectEvent = 0;
            pInjectEvent->Vector = NMI_INTERRUPT;
            pInjectEvent->InterruptionType = NMI_INTERRUPT;
            pInjectEvent->DeliverErrorCode = 0;
            pInjectEvent->Valid = 1;
            _WriteVMCS(VM_ENTRY_INTR_INFO_FIELD, InjectEvent);
            break;

        case EXTERNAL_INTERRUPT:
            DbgLog(("vmx: HandleExternalInterrupt()\n"));
            break;

        case HARDWARE_EXCEPTION:
            switch (pEvent->Vector)
            {
                case DEBUG_EXCEPTION:
                    DbgLog(("vmx: int1 guest_rip = 0x%llx\n", 
                        GuestRip));

                    ReportException(pCpu, pGuestRegs, pEvent->Vector, GuestRip);
/*                    {*/
/*                        DbgLog(("invalid state\n"));*/
/*                        InjectEvent = 0;*/
/*                        pInjectEvent->Vector = DEBUG_EXCEPTION; */
/*                        pInjectEvent->InterruptionType = HARDWARE_EXCEPTION;*/
/*                        pInjectEvent->DeliverErrorCode = 0;*/
/*                        pInjectEvent->Valid = 1;*/
/*                        _WriteVMCS(VM_ENTRY_INTR_INFO_FIELD, InjectEvent);*/
/*                        _WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP));*/
/*                    }*/
                    break;

                case PAGE_FAULT_EXCEPTION:
                    InterlockedIncrement(&g_pagefaults);
                    ErrorCode = _ReadVMCS(VM_EXIT_INTR_ERROR_CODE);
                    ExitQualification = _ReadVMCS(EXIT_QUALIFICATION);
/*                    if (g_pagefaults < 10)*/
/*                    {*/
/*                        DbgLog(("vmx: Exception(): guest_rip = 0x%llx\n", */
/*                            GuestRip));*/

/*                        DbgLog(("pagefault #%d\n", g_pagefaults));*/
/*                        DbgLog(("vmx: page fault\n"));*/
/*                        DbgLog(("vmx: error=0x%x\n", ErrorCode));*/
/*                        DbgLog(("vmx: address=0x%llx\n", ExitQualification));*/
/*                    }*/
                    
                    _SetCr2(ExitQualification);
                    _WriteVMCS(VM_ENTRY_EXCEPTION_ERROR_CODE, ErrorCode);
                    InjectEvent = 0;
                    pInjectEvent->Vector = PAGE_FAULT_EXCEPTION;
                    pInjectEvent->InterruptionType = HARDWARE_EXCEPTION;
                    pInjectEvent->DeliverErrorCode = 1;
                    pInjectEvent->Valid = 1;
                    _WriteVMCS(VM_ENTRY_INTR_INFO_FIELD, InjectEvent);
                    _WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP));
                    break;

                default:
                    DbgLog(("vmx: Hardware Exception (vector=0x%x)\n",
                        pEvent->Vector));
                    break;
            }

            break;

        case SOFTWARE_EXCEPTION:
            /* #BP (int3) and #OF (into) */
            
            switch (pEvent->Vector)
            {
                case BREAKPOINT_EXCEPTION:
                    DbgLog(("vmx: int3\n"));
                    DbgLog(("vmx: Exception(): guest_rip = 0x%llx\n", 
                        GuestRip));

                    InjectEvent = 0;
                    pInjectEvent->Vector = BREAKPOINT_EXCEPTION;
                    pInjectEvent->InterruptionType = SOFTWARE_INTERRUPT;
                    pInjectEvent->DeliverErrorCode = 0;
                    pInjectEvent->Valid = 1;
                    _WriteVMCS(VM_ENTRY_INTR_INFO_FIELD, InjectEvent);
                    _WriteVMCS(VM_ENTRY_INSTRUCTION_LEN, 1);
                    _WriteVMCS(GUEST_RIP, GuestRip);
                    break;

                case OVERFLOW_EXCEPTION:
                default:
                    DbgLog(("vmx: Software Exception (vector=0x%x)\n",
                        pEvent->Vector));

                    break;
            }
            break;
        
        default:
            DbgLog(("vmx: unknown interruption type\n"));
            break;
    }

    return TRUE;
}

static BOOLEAN HandleInvd(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
    ULONG64 InstructionLength;

    DbgLog(("vmx: invd\n"));
    _Invd();

    InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
    _WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP)+InstructionLength);
    return TRUE;
}

VOID HandleVmExit(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
    ULONG64 ExitCode;
    KIRQL OldIrql, CurrentIrql;
    
    OldIrql = 0;
    CurrentIrql = KeGetCurrentIrql();
    if (CurrentIrql < DISPATCH_LEVEL)
    {
        OldIrql = KeRaiseIrqlToDpcLevel();
    }
   
    pGuestRegs->rsp = _ReadVMCS(GUEST_RSP);
    ExitCode = _ReadVMCS(VM_EXIT_REASON);

    switch (ExitCode)
    {
        case EXIT_REASON_EXCEPTION_NMI:      
            HandleException(pCpu, pGuestRegs);
            break;

        case EXIT_REASON_EXTERNAL_INTERRUPT: 
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_TRIPLE_FAULT:       
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_INIT:               
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_SIPI:               
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_IO_SMI:             
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_OTHER_SMI:          
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_PENDING_INTERRUPT:  
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_TASK_SWITCH:        
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_CPUID:
            HandleCpuid(pCpu, pGuestRegs);
            break;

        case EXIT_REASON_HLT:                
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_INVD:               
            HandleInvd(pCpu, pGuestRegs);
            break;

        case EXIT_REASON_INVLPG:             
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_RDPMC:              
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_RDTSC:              
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_RSM:                
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_VMCALL:             
            HandleVmCall(pCpu, pGuestRegs);
            break;

        case EXIT_REASON_VMCLEAR:            
        case EXIT_REASON_VMLAUNCH:           
        case EXIT_REASON_VMPTRLD:            
        case EXIT_REASON_VMPTRST:            
        case EXIT_REASON_VMREAD:             
        case EXIT_REASON_VMRESUME:           
        case EXIT_REASON_VMWRITE:            
        case EXIT_REASON_VMXOFF:             
        case EXIT_REASON_VMXON:
            HandleVmInstruction(pCpu, pGuestRegs);
            break;

        case EXIT_REASON_CR_ACCESS:
            HandleCrAccess(pCpu, pGuestRegs);
            break;

        case EXIT_REASON_DR_ACCESS:
/*            HandleDrAccess(pCpu, pGuestRegs);*/
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_IO_INSTRUCTION:     
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_MSR_READ:
            HandleMsrRead(pCpu, pGuestRegs);
            break;

        case EXIT_REASON_MSR_WRITE:          
            HandleMsrWrite(pCpu, pGuestRegs);
            break;

        case EXIT_REASON_INVALID_GUEST_STATE:        
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_MSR_LOADING:
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_MWAIT_INSTRUCTION:
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_MONITOR_INSTRUCTION:
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_PAUSE_INSTRUCTION:  
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_MACHINE_CHECK:
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        case EXIT_REASON_TPR_BELOW_THRESHOLD:
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;

        default:
            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);
            break;
    }

    _WriteVMCS(GUEST_RSP, pGuestRegs->rsp);
    if (CurrentIrql < DISPATCH_LEVEL)
    {
        KeLowerIrql(OldIrql);
    }

}

static VOID EnableTF()
{
    ULONG64 Rflags;
    Rflags = _ReadVMCS(GUEST_RFLAGS);

    Rflags |= TF;
    _WriteVMCS(GUEST_RFLAGS, Rflags);

}

static VOID DisableTF()
{
    ULONG64 Rflags;
    Rflags = _ReadVMCS(GUEST_RFLAGS);

    Rflags &= ~TF;
    _WriteVMCS(GUEST_RFLAGS, Rflags);

}

static PVOID ReadVirtualMemory(ULONG64 Address, ULONG32 Size)
{
    NTSTATUS Status;
    PVOID Buffer;
    
    if (Size > 0x800)
        return NULL;

    Status = IsPagePresent(Address); 
    if (Status == STATUS_NO_MEMORY)
        return NULL;

    Buffer = AllocateMemory(Size);

    if (Buffer == NULL)
        return NULL;
    
    RtlCopyMemory(Buffer, (PVOID)Address, Size);
    return Buffer;
}

static VOID DumpContext(PDEBUG_CONTEXT pContext)
{
    DbgLog(("rax = 0x%llx\n", pContext->rax));
    DbgLog(("rbx = 0x%llx\n", pContext->rbx));
    DbgLog(("rcx = 0x%llx\n", pContext->rcx));
    DbgLog(("rdx = 0x%llx\n", pContext->rdx));
    DbgLog(("rsi = 0x%llx\n", pContext->rsi));
    DbgLog(("rdi = 0x%llx\n", pContext->rdi));
    DbgLog(("rbp = 0x%llx\n", pContext->rbp));
    DbgLog(("rsp = 0x%llx\n", pContext->rsp));
    DbgLog(("r8 = 0x%llx\n", pContext->r8));
    DbgLog(("r9 = 0x%llx\n", pContext->r9));
    DbgLog(("r10 = 0x%llx\n", pContext->r10));
    DbgLog(("r11 = 0x%llx\n", pContext->r11));
    DbgLog(("r12 = 0x%llx\n", pContext->r12));
    DbgLog(("r13 = 0x%llx\n", pContext->r13));
    DbgLog(("r14 = 0x%llx\n", pContext->r14));
    DbgLog(("r15 = 0x%llx\n", pContext->r15));
    DbgLog(("rflags = 0x%llx\n", pContext->rflags));
    DbgLog(("rip = 0x%llx\n", pContext->rip));
    DbgLog(("cr0 = 0x%llx\n", pContext->cr0));
    DbgLog(("cr3 = 0x%llx\n", pContext->cr3));
    DbgLog(("cr4 = 0x%llx\n", pContext->cr4));
    DbgLog(("cr8 = 0x%llx\n", pContext->cr8));
    DbgLog(("dr0 = 0x%llx\n", pContext->dr0));
    DbgLog(("dr1 = 0x%llx\n", pContext->dr1));
    DbgLog(("dr2 = 0x%llx\n", pContext->dr2));
    DbgLog(("dr3 = 0x%llx\n", pContext->dr3));
    DbgLog(("dr6 = 0x%llx\n", pContext->dr6));
    DbgLog(("dr7 = 0x%llx\n", pContext->dr7));
}

static VOID DumpMem(PUCHAR Address, ULONG32 Size)
{
    ULONG64 i;
    for (i=0;i<Size;i++)
    {
        DbgLog(("0x%x 0x%x\n", Address+i, *(Address+i)));
    }
}



static PVOID HandleReadVirtualMemoryPacket(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, PVOID pPacket)
{
    PMANIPULATE_STATE_PACKET pData1, pResponseData1;
    PVOID pResponse, pData;
    ULONG64 Address;
    ULONG32 Size, Offset;

    pData1 = (PMANIPULATE_STATE_PACKET)((PUCHAR)pPacket+sizeof(PACKET_HEADER));

    Address = pData1->u.ReadVirtualMemory.Address;
    Size = pData1->u.ReadVirtualMemory.Size;

    DbgLog(("READ_VIRTUAL_MEMORY_API address=0x%llx, size=0x%x\n", Address, Size));

    pData = ReadVirtualMemory(Address, Size);
    if (pData == NULL)
    {
        pResponse = CreateManipulateStatePacket(READ_VIRTUAL_MEMORY_API, 0);
        if (pResponse == NULL)
        {
            /* not enought memory ? */
            return NULL;
        }

        pResponseData1 = (PMANIPULATE_STATE_PACKET)((PUCHAR)pResponse+
                sizeof(PACKET_HEADER));
        pResponseData1->Error = (ULONG32)STATUS_UNSUCCESSFUL;

    }
    else
    {
        pResponse = CreateManipulateStatePacket(READ_VIRTUAL_MEMORY_API, Size);
        if (pResponse == NULL)
        {
            /* not enought memory ? */
            return NULL;
        }
    
        Offset = sizeof(PACKET_HEADER)+sizeof(MANIPULATE_STATE_PACKET);
/*        DbgLog(("offset=0x%08x\n", Offset));*/
/*        DumpMem(pData, Size);*/
        RtlCopyMemory((PUCHAR)pResponse+Offset, pData, Size);
        UnAllocateMemory(pData);

    }
    return pResponse;

}

static PVOID HandleWriteVirtualMemoryPacket(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, PVOID pPacket)
{
    PMANIPULATE_STATE_PACKET pData1, pResponseData1;
    PVOID pResponse;
    ULONG64 Address;
    ULONG32 Size;

    pData1 = (PMANIPULATE_STATE_PACKET)((PUCHAR)pPacket+sizeof(PACKET_HEADER));

    Address = pData1->u.WriteVirtualMemory.Address;
    Size = pData1->u.WriteVirtualMemory.Size;

    DbgLog(("WRITE_VIRTUAL_MEMORY_API address=0x%llx, size=0x%x\n", Address, Size));

    pResponse = CreateManipulateStatePacket(WRITE_VIRTUAL_MEMORY_API, 0);
    if (pResponse == NULL)
    {
        /* not enought memory ? */
        return NULL;
    }

    pResponseData1 = (PMANIPULATE_STATE_PACKET)((PUCHAR)pResponse+
            sizeof(PACKET_HEADER));
    pResponseData1->Error = (ULONG32)STATUS_UNSUCCESSFUL;
    return pResponse;
}


/*    if (Size == pHeader->Size-sizeof(MANIPULATE_STATE_PACKET))*/
/*    {*/
/*        pData = AllocateMemory(Size);*/
/*        if (pData == NULL)*/
/*        {*/
/*             not enought memory */
/*            return NULL;*/
/*        }*/

/*        RtlCopyMemory(pData, (PUCHAR)pData1+sizeof(MANIPULATE_STATE_PACKET), Size);*/
/*        UnAllocateMemory(pData);*/
/*        */
/*        pResponse = CreateManipulateStatePacket(WRITE_VIRTUAL_MEMORY_API, 0);*/
/*        if (pResponse == NULL)*/
/*        {*/
/*             not enought memory */
/*            return NULL;*/
/*        }*/

/*        pResponseHeader = (PPACKET_HEADER)pResponse;*/
/*        pResponseHeader->Id = g_Id;*/
/*        pResponseHeader->Checksum = CalcChecksum((PUCHAR)pResponse+sizeof(PACKET_HEADER),*/
/*                pResponseHeader->Size);*/
/*        SendPacket(pResponse, MAX_RETRIES);*/
/*    }*/

static PVOID HandleGetContextPacket(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, PVOID pPacket)
{
    PMANIPULATE_STATE_PACKET pData1;
    PVOID pResponse;
    PDEBUG_CONTEXT pContext;
    ULONG32 Flags;

    pData1 = (PMANIPULATE_STATE_PACKET)((PUCHAR)pPacket+sizeof(PACKET_HEADER));

    DbgLog(("received GET_CONTEXT_API request\n"));
    Flags = pData1->u.GetContext.Flags;

    pResponse = CreateManipulateStatePacket(GET_CONTEXT_API, sizeof(DEBUG_CONTEXT));
 
    if (pResponse == NULL)
    {
        /* not enought memory ? */
        return NULL;
    }
   
    pContext = (PDEBUG_CONTEXT)((PUCHAR)pResponse+sizeof(PACKET_HEADER)+
            sizeof(MANIPULATE_STATE_PACKET));

    pContext->rax = pGuestRegs->rax;
    pContext->rbx = pGuestRegs->rbx;
    pContext->rcx = pGuestRegs->rcx;
    pContext->rdx = pGuestRegs->rdx;
    pContext->rsi = pGuestRegs->rsi;
    pContext->rdi = pGuestRegs->rdi;
    pContext->rbp = pGuestRegs->rbp;
    pContext->rsp = pGuestRegs->rsp;
    pContext->r8 = pGuestRegs->r8;
    pContext->r9 = pGuestRegs->r9;
    pContext->r10 = pGuestRegs->r10;
    pContext->r11 = pGuestRegs->r11;
    pContext->r12 = pGuestRegs->r12;
    pContext->r13 = pGuestRegs->r13;
    pContext->r14 = pGuestRegs->r14;
    pContext->r15 = pGuestRegs->r15;
    pContext->rflags = _ReadVMCS(GUEST_RFLAGS);
    pContext->rip = _ReadVMCS(GUEST_RIP);
    pContext->cr0 = _ReadVMCS(GUEST_CR0);
    pContext->cr3 = _ReadVMCS(GUEST_CR3);
    pContext->cr4 = _ReadVMCS(GUEST_CR4);
    pContext->dr0 = _Dr0();
    pContext->dr1 = _Dr1();
    pContext->dr2 = _Dr2();
    pContext->dr3 = _Dr3();
    pContext->dr6 = _Dr6();
    pContext->dr7 = _ReadVMCS(GUEST_DR7);
    pContext->cs = _Cs();
    pContext->ds = _Ds();
    pContext->es = _Es();
    pContext->fs = _Fs();
    pContext->ss = _Ss();
    pContext->gs = _Gs();

/*    DumpContext(pContext);*/
    return pResponse;
}

static PVOID HandleSetContextPacket(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, PVOID pPacket)
{
    PMANIPULATE_STATE_PACKET pData1;
    PVOID pResponse;
    PDEBUG_CONTEXT pContext;
    ULONG32 Flags;

    pData1 = (PMANIPULATE_STATE_PACKET)((PUCHAR)pPacket+sizeof(PACKET_HEADER));

    DbgLog(("received SET_CONTEXT_API request\n"));
    Flags = pData1->u.SetContext.Flags;

    pContext = (PDEBUG_CONTEXT)((PUCHAR)pData1+sizeof(MANIPULATE_STATE_PACKET));

    DumpContext(pContext);

    pGuestRegs->rax = pContext->rax;
    pGuestRegs->rbx = pContext->rbx;
    pGuestRegs->rcx = pContext->rcx;
    pGuestRegs->rdx = pContext->rdx;
    pGuestRegs->rsi = pContext->rsi;
    pGuestRegs->rdi = pContext->rdi;
    pGuestRegs->rbp = pContext->rbp;
    pGuestRegs->rsp = pContext->rsp;
    pGuestRegs->r8 = pContext->r8;
    pGuestRegs->r9 = pContext->r9;
    pGuestRegs->r10 = pContext->r10;
    pGuestRegs->r11 = pContext->r11;
    pGuestRegs->r12 = pContext->r12;
    pGuestRegs->r13 = pContext->r13;
    pGuestRegs->r14 = pContext->r14;
    pGuestRegs->r15 = pContext->r15;
    _WriteVMCS(GUEST_RFLAGS, pContext->rflags);
    _WriteVMCS(GUEST_RIP, pContext->rip);
    _SetDr0(pContext->dr0);
    _SetDr1(pContext->dr1);
    _SetDr2(pContext->dr2);
    _SetDr3(pContext->dr3);
    _WriteVMCS(GUEST_DR7, pContext->dr7);

    pResponse = CreateManipulateStatePacket(SET_CONTEXT_API, 0);
    if (pResponse == NULL)
    {
        /* not enought memory ? */
        return NULL;
    }
    return pResponse; 
}

static BOOLEAN HandleManipulateStatePacket(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, PVOID pPacket)
{
    PPACKET_HEADER pHeader;
    PMANIPULATE_STATE_PACKET pData1;
    PVOID pResponse;
    BOOLEAN bRes;

    pHeader = (PPACKET_HEADER)pPacket;
    pData1 = (PMANIPULATE_STATE_PACKET)((PUCHAR)pPacket+sizeof(PACKET_HEADER));

    switch (pData1->ApiNumber)
    {
        case READ_VIRTUAL_MEMORY_API:
            pResponse = HandleReadVirtualMemoryPacket(pCpu, pGuestRegs, pPacket);
            if (pResponse == NULL)
                return FALSE;
            bRes = SendPacket(pResponse, MAX_RETRIES);
            break;

        case WRITE_VIRTUAL_MEMORY_API:
            pResponse = HandleWriteVirtualMemoryPacket(pCpu, pGuestRegs, pPacket);
            if (pResponse == NULL)
                return FALSE;
            bRes = SendPacket(pResponse, MAX_RETRIES);
            break;

        case GET_CONTEXT_API:
            pResponse = HandleGetContextPacket(pCpu, pGuestRegs, pPacket);
            if (pResponse == NULL)
                return FALSE;
            bRes = SendPacket(pResponse, MAX_RETRIES);
            break;

        case SET_CONTEXT_API:
            pResponse = HandleSetContextPacket(pCpu, pGuestRegs, pPacket);
            if (pResponse == NULL)
                return FALSE;
            bRes = SendPacket(pResponse, MAX_RETRIES);
            break;

        default:
            bRes = FALSE;
            break;

    }

    return bRes;
}


static VOID DebugLoop(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
    PVOID pPacket;
    PPACKET_HEADER pHeader;
    BOOLEAN bRes, bInDebug;
    ULONG32 i;

    DbgLog(("Starting debugging loop...\n"));

    bInDebug = TRUE;

    while (bInDebug)
    {
        bRes = FALSE;
        pPacket = ReceivePacket();
        if (pPacket == NULL)
        {
            for(i=0;i<100;i++);
            continue;
        }
        
        pHeader = (PPACKET_HEADER)pPacket;

        switch (pHeader->Type)
        {
            case PACKET_TYPE_CONTINUE:
                bRes = HandleContinuePacket(pCpu, pGuestRegs, pPacket);
                if (bRes)
                {
                    bInDebug = FALSE;
                }
                break;

            case PACKET_TYPE_MANIPULATE_STATE:
                bRes = HandleManipulateStatePacket(pCpu, pGuestRegs, pPacket);
                break;

            default:
                bRes = FALSE;
                break;

        }
        DestroyPacket(pPacket);

    }

    DbgLog(("Ending debugging loop\n"));
}

static VOID ReportException(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, ULONG Exception, ULONG64 Address)
{
    PPACKET_HEADER pResponse;

    DbgLog(("reporting exception\n"));
/*    DbgLog(("GUEST_ACTIVITY_STATE=0x%08x\n", _ReadVMCS(GUEST_ACTIVITY_STATE)));*/
/*    DbgLog(("GUEST_INTERRUPTIBILITY_STATE=0x%08x\n", _ReadVMCS(GUEST_INTERRUPTIBILITY_STATE)));*/
/*    DbgLog(("pending=0x%016x\n", _ReadVMCS(GUEST_PENDING_DBG_EXCEPTIONS)));*/
            

    if (g_ControlArea->State == STATE_BREAKIN)
    {
        DbgLog(("Breakin, disabling TF\n"));
        InterlockedExchange(&(g_ControlArea->State), 0);
        DisableTF();
    }

    FreezeCpus(pCpu->ProcessorNumber);

    pResponse = (PPACKET_HEADER)CreateStateChangePacket(Exception, Address);

    if (pResponse == NULL)
    {
/*         bad ! */
        return;
    }

    SendPacket(pResponse, MAX_RETRIES);
    DebugLoop(pCpu, pGuestRegs);

    ResumeCpus(pCpu->ProcessorNumber);

    DbgLog(("end reporting exception\n"));
}

static VOID FreezeCpuRoutine(PKDPC pDpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    KIRQL OldIrql;
    DbgLog(("cpu frozen\n"));

    KeRaiseIrql(HIGH_LEVEL, &OldIrql);
    KeAcquireSpinLockAtDpcLevel(g_FreezeLock);
    KeReleaseSpinLockFromDpcLevel(g_FreezeLock);
    KeLowerIrql(OldIrql);

    UnAllocateMemory(pDpc);
    DbgLog(("cpu resumed\n"));

}

static VOID FreezeCpus(ULONG32 RunningProcessor)
{
    UCHAR i;
    PKDPC pDpc;
 
    KeAcquireSpinLockAtDpcLevel(g_FreezeLock);
    DbgLog(("Freezing cpus...\n"));
    for (i=0; i<KeNumberProcessors; i++)
    {
        if (i != RunningProcessor)
        {
            DbgLog(("freezing processor %d\n", i));
            pDpc = AllocateMemory(sizeof(KDPC));

            if (!pDpc)
            {
                DbgLog(("Failed to allocate KDPC\n"));
                return;
            }

            KeInitializeDpc(pDpc, FreezeCpuRoutine, NULL);
            KeSetTargetProcessorDpc(pDpc, (CCHAR)i); 
            KeSetImportanceDpc(pDpc, HighImportance);
            KeInsertQueueDpc(pDpc, NULL, NULL);

        }
    }
}
    
static VOID ResumeCpus(ULONG32 RunningProcessor)
{
    DbgLog(("Resuming cpus...\n"));
    KeReleaseSpinLockFromDpcLevel(g_FreezeLock);
}

static VOID DumpPacket(PPACKET_HEADER pHeader)
{
    DbgLog(("pHeader->Magic = 0x%x\n", pHeader->Magic));
    DbgLog(("pHeader->Type = 0x%x\n", pHeader->Type));
    DbgLog(("pHeader->Size = 0x%x\n", pHeader->Size));
    DbgLog(("pHeader->Id = 0x%x\n", pHeader->Id));
    DbgLog(("pHeader->Checksum = 0x%x\n", pHeader->Checksum));
}

static BOOLEAN HandleContinuePacket(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, PVOID pPacket)
{
    PCONTINUE_PACKET pContinue;
    BOOLEAN bRes;
    ULONG64 Rip, Rsp;

    pContinue = (PCONTINUE_PACKET)((PUCHAR)pPacket+sizeof(PACKET_HEADER));
    switch (pContinue->Status)
    {
        case CONTINUE_STATUS_SINGLE_STEP:
            EnableTF();
            bRes = TRUE;
            break;

        case CONTINUE_STATUS_CONTINUE:
            DisableTF();
            bRes = TRUE;
            break;

        case CONTINUE_STATUS_UNLOAD:
            DbgLog(("unloading hypervisor...\n"));
            Rip = (ULONG64)_GuestExit;
            Rsp = pGuestRegs->rsp;
            DbgLog(("restoring rip=0x%llx, rsp=0x%llx\n", Rip, Rsp));
            _VmxOff(Rip, Rsp);
            bRes = TRUE;
            break;

        default:
            bRes = FALSE;
            break;
    }
    return bRes;
}

static BOOLEAN HandleBreakinPacket(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, PVOID pPacket, ULONG64 Cr3)
{
    PBREAKIN_PACKET pBreakinPacket;

    pBreakinPacket = (PBREAKIN_PACKET)((PUCHAR)pPacket+sizeof(PACKET_HEADER));
    if ((pBreakinPacket->Cr3 == 0) || (pBreakinPacket->Cr3 == Cr3))
    {
        EnableTF();
        InterlockedExchange(&(g_ControlArea->State), STATE_BREAKIN);
        return TRUE;
    }
    return FALSE;
}


static BOOLEAN HandleClientRequest(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, ULONG64 Cr3)
{
    PVOID pPacket;
    PPACKET_HEADER pHeader;
    BOOLEAN bRes;

    if (!g_Initialized)
    {
        return FALSE;
    }

/*    if (g_ControlArea->Busy)*/
/*    {*/
/*        return FALSE;*/
/*    }*/

/*    InterlockedIncrement(&(g_ControlArea->Busy));*/
    pPacket = ReceivePacket();
    if (pPacket == NULL)
    {
        return FALSE;
    }

    pHeader = (PPACKET_HEADER)pPacket;

    switch (pHeader->Type)
    {
        case PACKET_TYPE_CONTINUE:
            bRes = HandleContinuePacket(pCpu, pGuestRegs, pPacket);
            break;

        case PACKET_TYPE_BREAKIN:
            bRes = HandleBreakinPacket(pCpu, pGuestRegs, pPacket, Cr3);
            break;

        case PACKET_TYPE_MANIPULATE_STATE:
            bRes = HandleManipulateStatePacket(pCpu, pGuestRegs, pPacket);
            break;

        default:
            bRes = FALSE;
            break;

    }
    DestroyPacket(pPacket);
/*    InterlockedDecrement(&(g_ControlArea->Busy));*/
    return bRes;
}


