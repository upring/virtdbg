
#include "vmx.h" 

ULONG32 g_processors = 0;
ULONG32 g_pagefaults = 0;

extern ULONG32 g_initialized;
extern PVIRT_CPU *g_cpus;

VOID DumpVirtCpu(PVIRT_CPU pCpu)
{
    DbgLog(("pCpu @ %p\n", pCpu));
    DbgLog(("pCpu->Self=0x%llx\n", pCpu->Self));
    DbgLog(("pCpu->ProcessorNumber=0x%lx\n", pCpu->ProcessorNumber));
    DbgLog(("pCpu->State=0x%lx\n", pCpu->State));
    DbgLog(("pCpu->Mailbox=0x%lx\n", pCpu->Mailbox));
}

BOOLEAN IsBitSet(ULONG64 v, UCHAR bitNo)
{
    ULONG64 mask = (ULONG64) 1 << bitNo;
    return (BOOLEAN) ((v & mask) != 0);
}


VOID DumpGuestRegs(PGUEST_REGS pGuestRegs)
{
    DbgPrint("rax=0x%llx\n", pGuestRegs->rax);
    DbgPrint("rbx=0x%llx\n", pGuestRegs->rbx);
    DbgPrint("rcx=0x%llx\n", pGuestRegs->rcx);
    DbgPrint("rdx=0x%llx\n", pGuestRegs->rdx);
    DbgPrint("rbp=0x%llx\n", pGuestRegs->rbp);
    DbgPrint("rsp=0x%llx\n", pGuestRegs->rsp);
    DbgPrint("rdi=0x%llx\n", pGuestRegs->rdi);
    DbgPrint("rsi=0x%llx\n", pGuestRegs->rsi);
    DbgPrint("r8=0x%llx\n", pGuestRegs->r8);
    DbgPrint("r9=0x%llx\n", pGuestRegs->r9);
    DbgPrint("r10=0x%llx\n", pGuestRegs->r10);
    DbgPrint("r11=0x%llx\n", pGuestRegs->r11);
    DbgPrint("r12=0x%llx\n", pGuestRegs->r12);
    DbgPrint("r13=0x%llx\n", pGuestRegs->r13);
    DbgPrint("r14=0x%llx\n", pGuestRegs->r14);
    DbgPrint("r15=0x%llx\n", pGuestRegs->r15);
}

NTSTATUS InitializeSegmentSelector(PSEGMENT_SELECTOR SegmentSelector,
        USHORT Selector, PUCHAR GdtBase) 
{
  PSEGMENT_DESCRIPTOR SegDesc;
  ULONG64 tmp;

  if (!SegmentSelector)
    return STATUS_INVALID_PARAMETER;

  if (Selector & 0x4) {
    DbgPrint("InitializeSegmentSelector(): Given selector (0x%X) points to LDT\n", Selector);
    return STATUS_INVALID_PARAMETER;
  }

  SegDesc = (PSEGMENT_DESCRIPTOR) ((PUCHAR) GdtBase + (Selector & ~0x7));

  SegmentSelector->sel = Selector;
  SegmentSelector->base = SegDesc->base0 | SegDesc->base1 << 16 | SegDesc->base2 << 24;
  SegmentSelector->limit = SegDesc->limit0 | (SegDesc->limit1attr1 & 0xf) << 16;
  SegmentSelector->attributes.UCHARs = SegDesc->attr0 | (SegDesc->limit1attr1 & 0xf0) << 4;

  if (!(SegDesc->attr0 & LA_STANDARD)) {
    // this is a TSS or callgate etc, save the base high part
    tmp = (*(PULONG64) ((PUCHAR) SegDesc + 8));
    SegmentSelector->base = (SegmentSelector->base & 0xffffffff) | (tmp << 32);
  }

  if (SegmentSelector->attributes.fields.g) {
    // 4096-bit granularity is enabled for this segment, scale the limit
    SegmentSelector->limit = (SegmentSelector->limit << 12) + 0xfff;
  }

  return STATUS_SUCCESS;
}

ULONG32 AdjustControls(ULONG32 Ctl, ULONG32 Msr)
{
    LARGE_INTEGER MsrValue;
    MsrValue.QuadPart = _ReadMsr(Msr);
    DbgLog(("Adjusting control for msr 0x%x\n", Msr));
    DbgLog(("Adjusting controls (low): 0x%08x\n", MsrValue.LowPart));
    DbgLog(("Adjusting controls (high): 0x%08x\n", MsrValue.HighPart));
    Ctl &= MsrValue.HighPart;
    Ctl |= MsrValue.LowPart;
    return Ctl;
}


NTSTATUS CheckForVirtualizationSupport()
{
    ULONG32 eax, ebx, ecx, edx;
    /* vmx supported by cpu ? */
    _CpuId(0, &eax, &ebx, &ecx, &edx);
    if (eax < 1) 
    {
        DbgLog(("vmx: error extended CPUID functions not implemented\n"));
        return STATUS_UNSUCCESSFUL;
    }

    /* Intel Genuine */
    if (!(ebx == 0x756e6547 && ecx == 0x6c65746e && edx == 0x49656e69)) 
    {
        DbgLog(("vmx: error not an INTEL processor\n"));
        return STATUS_UNSUCCESSFUL;
    }

    _CpuId(0x1, &eax, &ebx, &ecx, &edx);
    if (!IsBitSet(ecx, 5))
    {
        DbgLog(("vmx: error VMX not supported\n"));
        return STATUS_UNSUCCESSFUL;
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS ResumeGuest()
{
    DbgLog(("Resuming guest...\n"));
    return STATUS_SUCCESS;
}

NTSTATUS FillGuestSelectorData(PVOID GdtBase, ULONG Segreg, USHORT
        Selector) 
{
  SEGMENT_SELECTOR SegmentSelector = { 0 };
  ULONG uAccessRights;

  InitializeSegmentSelector(&SegmentSelector, Selector, GdtBase);
  uAccessRights = ((PUCHAR) & SegmentSelector.attributes)[0] + (((PUCHAR) &
              SegmentSelector.attributes)[1] << 12);

  if (!Selector)
    uAccessRights |= 0x10000;

  _WriteVMCS(GUEST_ES_SELECTOR + Segreg * 2, Selector);
  _WriteVMCS(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.limit);
  _WriteVMCS(GUEST_ES_AR_BYTES + Segreg * 2, uAccessRights);

  if ((Segreg == LDTR) || (Segreg == TR))
    // don't setup for FS/GS - their bases are stored in MSR values
    _WriteVMCS(GUEST_ES_BASE + Segreg * 2, SegmentSelector.base);

  return STATUS_SUCCESS;
}

NTSTATUS SetupVMCS(PVIRT_CPU pCpu, PVOID GuestRsp)
{
    ULONG32 Interceptions, ExceptionBitmap;
    PVOID GdtBase;
    SEGMENT_SELECTOR SegmentSelector;
    ULONG32 i;
    PHYSICAL_ADDRESS pa;
   
    i = KeGetCurrentProcessorNumber();
    DbgLog(("vmx: SetupVMCS(): GuestRsp=%p\n", GuestRsp));   
    
    pa = pCpu->VMCS_pa;
    DbgLog(("vmx: SetupVMCS(): VMCS PHYSICAL_ADDRESS %llx\n", pa));
    _VmClear(pa);
    _VmPtrLd(pa);
    
    _WriteVMCS(GUEST_CR0, _Cr0());
    _WriteVMCS(GUEST_CR3, _Cr3());
    _WriteVMCS(GUEST_CR4, _Cr4());
    _WriteVMCS(GUEST_DR7, 0x400);
    _WriteVMCS(GUEST_RSP, (ULONG64)GuestRsp);     
    _WriteVMCS(GUEST_RIP, (ULONG64)_GuestEntryPoint);  
    _WriteVMCS(GUEST_RFLAGS, _Rflags());
    
    GdtBase = (PVOID) _GdtBase();
    FillGuestSelectorData(GdtBase, ES, _Es());
    FillGuestSelectorData(GdtBase, CS, _Cs());
    FillGuestSelectorData(GdtBase, SS, _Ss());
    FillGuestSelectorData(GdtBase, DS, _Ds());
    FillGuestSelectorData(GdtBase, FS, _Fs());
    FillGuestSelectorData(GdtBase, GS, _Gs());
    FillGuestSelectorData(GdtBase, LDTR, _Ldtr());
    FillGuestSelectorData(GdtBase, TR, _TrSelector());
    _WriteVMCS(GUEST_ES_BASE, 0);
    _WriteVMCS(GUEST_CS_BASE, 0);
    _WriteVMCS(GUEST_SS_BASE, 0);
    _WriteVMCS(GUEST_DS_BASE, 0);
    _WriteVMCS(GUEST_FS_BASE, _ReadMsr(MSR_FS_BASE));
    _WriteVMCS(GUEST_GS_BASE, _ReadMsr(MSR_GS_BASE));
    _WriteVMCS(GUEST_GDTR_BASE, (ULONG64) GdtBase);
    _WriteVMCS(GUEST_IDTR_BASE, _IdtBase());
    _WriteVMCS(GUEST_GDTR_LIMIT, _GdtLimit());
    _WriteVMCS(GUEST_IDTR_LIMIT, _IdtLimit());
    
    _WriteVMCS(GUEST_IA32_DEBUGCTL, _ReadMsr(MSR_IA32_DEBUGCTL) & 0xffffffff);  
    _WriteVMCS(GUEST_IA32_DEBUGCTL_HIGH, _ReadMsr(MSR_IA32_DEBUGCTL) >> 32);
    _WriteVMCS(GUEST_SYSENTER_CS, _ReadMsr(MSR_IA32_SYSENTER_CS));
    _WriteVMCS(GUEST_SYSENTER_ESP, _ReadMsr(MSR_IA32_SYSENTER_ESP));
    _WriteVMCS(GUEST_SYSENTER_EIP, _ReadMsr(MSR_IA32_SYSENTER_EIP));
    
    /* guest non register state */
    _WriteVMCS(GUEST_INTERRUPTIBILITY_INFO, 0);
    _WriteVMCS(GUEST_ACTIVITY_STATE, 0);   
    _WriteVMCS(VMCS_LINK_POINTER, 0xffffffff);
    _WriteVMCS(VMCS_LINK_POINTER_HIGH, 0xffffffff);
    
    /* host state area */
    _WriteVMCS(HOST_CR0, _Cr0());
    _WriteVMCS(HOST_CR3, _Cr3());
    _WriteVMCS(HOST_CR4, _Cr4());
    _WriteVMCS(HOST_RSP, (ULONG64) pCpu);   
    _WriteVMCS(HOST_RIP, (ULONG64) _ExitHandler);     
    
    _WriteVMCS(HOST_ES_SELECTOR, KGDT64_R0_DATA);
    _WriteVMCS(HOST_CS_SELECTOR, KGDT64_R0_CODE);
    _WriteVMCS(HOST_SS_SELECTOR, KGDT64_R0_DATA);
    _WriteVMCS(HOST_DS_SELECTOR, KGDT64_R0_DATA);
    _WriteVMCS(HOST_FS_SELECTOR, (_Fs() & 0xf8));
    _WriteVMCS(HOST_GS_SELECTOR, (_Gs() & 0xf8));
    _WriteVMCS(HOST_TR_SELECTOR, (_TrSelector() & 0xf8));
    _WriteVMCS(HOST_FS_BASE, _ReadMsr(MSR_FS_BASE));
    _WriteVMCS(HOST_GS_BASE, _ReadMsr(MSR_GS_BASE));
    
    InitializeSegmentSelector(&SegmentSelector, _TrSelector(), (PVOID)
            _GdtBase());

    _WriteVMCS(HOST_TR_BASE, SegmentSelector.base);

    _WriteVMCS(HOST_GDTR_BASE, _GdtBase());
    _WriteVMCS(HOST_IDTR_BASE, _IdtBase());
    
    _WriteVMCS(HOST_IA32_SYSENTER_ESP, _ReadMsr(MSR_IA32_SYSENTER_ESP));
    _WriteVMCS(HOST_IA32_SYSENTER_EIP, _ReadMsr(MSR_IA32_SYSENTER_EIP));
    _WriteVMCS(HOST_IA32_SYSENTER_CS, _ReadMsr(MSR_IA32_SYSENTER_CS));
    
    /* VM Execution Control Fields */
    _WriteVMCS(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0,
                MSR_IA32_VMX_PINBASED_CTLS));

    Interceptions = 0;
    Interceptions |= CPU_BASED_ACTIVATE_MSR_BITMAP;
    _WriteVMCS(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(Interceptions,
                MSR_IA32_VMX_PROCBASED_CTLS));

    ExceptionBitmap = 0;
    ExceptionBitmap |= 1<<DEBUG_EXCEPTION;
    ExceptionBitmap |= 1<<BREAKPOINT_EXCEPTION;
    ExceptionBitmap |= 1<<PAGE_FAULT_EXCEPTION;

    _WriteVMCS(EXCEPTION_BITMAP, ExceptionBitmap);  
    _WriteVMCS(PAGE_FAULT_ERROR_CODE_MASK, 0);
    _WriteVMCS(PAGE_FAULT_ERROR_CODE_MATCH, 0);
    _WriteVMCS(IO_BITMAP_A, 0);
    _WriteVMCS(IO_BITMAP_A_HIGH, 0);
    _WriteVMCS(IO_BITMAP_B, 0);
    _WriteVMCS(IO_BITMAP_B_HIGH, 0);
    _WriteVMCS(TSC_OFFSET, 0);
    _WriteVMCS(TSC_OFFSET_HIGH, 0);
    _WriteVMCS(MSR_BITMAP, pCpu->MSR_bitmap_pa.LowPart);
    _WriteVMCS(MSR_BITMAP_HIGH, pCpu->MSR_bitmap_pa.HighPart);
    
    /* VM Exit Control */
    _WriteVMCS(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE |
                VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));

    _WriteVMCS(VM_EXIT_MSR_STORE_COUNT, 0);
    _WriteVMCS(VM_EXIT_MSR_LOAD_COUNT, 0);
    _WriteVMCS(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE,
                MSR_IA32_VMX_ENTRY_CTLS));

    _WriteVMCS(VM_ENTRY_MSR_LOAD_COUNT, 0);
    _WriteVMCS(VM_ENTRY_INTR_INFO_FIELD, 0);
            
    _WriteVMCS(CR0_GUEST_HOST_MASK, X86_CR0_PG);
    _WriteVMCS(CR0_READ_SHADOW, (_Cr0() & X86_CR0_PG) | X86_CR0_PG);
    
    _WriteVMCS(CR4_GUEST_HOST_MASK, X86_CR4_VMXE); 
    _WriteVMCS(CR4_READ_SHADOW, 0);
    
    _WriteVMCS(CR3_TARGET_COUNT, 0);
    _WriteVMCS(CR3_TARGET_VALUE0, 0);      //no use
    _WriteVMCS(CR3_TARGET_VALUE1, 0);      //no use                        
    _WriteVMCS(CR3_TARGET_VALUE2, 0);      //no use
    _WriteVMCS(CR3_TARGET_VALUE3, 0);      //no use

    return STATUS_SUCCESS;
}

NTSTATUS SetupVMX(PVIRT_CPU pCpu)
{
    PHYSICAL_ADDRESS pa;
    ULONG64 msr;
    PVMX_BASIC_MSR pvmx;
    ULONG32 i;
    PVOID va;
    ULONG size;
    
    i = KeGetCurrentProcessorNumber();
    
    pCpu->ProcessorNumber = i;
    msr = _ReadMsr(MSR_IA32_VMX_BASIC);
    pvmx = (PVMX_BASIC_MSR)&msr;
    
    size = pvmx->szVmxOnRegion;
    
    DbgLog(("vmx: VMXON region size: 0x%x\n", size));
    DbgLog(("vmx: VMX revision ID: 0x%x\n", pvmx->RevId));
  
    va = AllocateContiguousMemory(size);
                            
    if (va == NULL)
    {
        DbgLog(("vmx: error can't allocate vmxon region\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    *(ULONG32 *)va = pvmx->RevId;
    pa = MmGetPhysicalAddress(va);
    
    _VmxOn(pa);
    
    if (_VmFailInvalid())
    {
        DbgLog(("vmx: SetupVMX(): _VmxOn failed\n"));
        return STATUS_UNSUCCESSFUL;
    }

    pCpu->VMXON_va = va;
    pCpu->VMXON_pa = pa;
    
    va = AllocateContiguousMemory(size);
                            
    if (va == NULL)
    {
        DbgLog(("vmx: error can't allocate vmcs region\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    *(ULONG32 *)va = pvmx->RevId;        
    pa = MmGetPhysicalAddress(va);
    
    pCpu->VMCS_va = va;
    pCpu->VMCS_pa = pa;
        
    va = AllocateContiguousMemory(0x1000);
    pa = MmGetPhysicalAddress(va);

    if (va == NULL)
    {
        DbgLog(("vmx: error can't allocate msr bitmap\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pCpu->MSR_bitmap_va = va;
    pCpu->MSR_bitmap_pa = pa;

    return STATUS_SUCCESS;    
}

NTSTATUS CheckIfVMXIsEnabled()
{    
    ULONG64 cr4, msr;
    
	/* vmxon supported ? */
    _SetCr4(X86_CR4_VMXE);
    cr4 = _Cr4();

    if (!(cr4 & X86_CR4_VMXE))
    {
        DbgLog(("vmx: error VMXON not supported\n"));
        return STATUS_UNSUCCESSFUL;
    }
    
	/* vmx desactived by bios ? */        
    msr = _ReadMsr(MSR_IA32_FEATURE_CONTROL);
    if (!(msr & 4))
    {
        DbgLog(("vmx: vmx is disabled in bios: MSR_IA32_FEATURE_CONTROL is 0x%llx\n", msr));
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

BOOLEAN HandleVmInstruction(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
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

BOOLEAN HandleVmCall(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
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


BOOLEAN HandleUnimplemented(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, ULONG64 ExitCode)
{
    ULONG64 InstructionLength;

    DbgLog(("vmx: unimplemented\n"));
    DbgLog(("vmx: exitcode = 0x%llx\n", ExitCode));
    DbgLog(("vmx: guest_rip = 0x%llx\n", _ReadVMCS(GUEST_RIP)));

    InstructionLength = _ReadVMCS(VM_EXIT_INSTRUCTION_LEN);
    _WriteVMCS(GUEST_RIP, _ReadVMCS(GUEST_RIP)+InstructionLength);

    return TRUE;
}

BOOLEAN InjectInt1(ULONG64 Rip)
{
    ULONG32 InjectEvent;
    PINTERRUPT_INJECT_INFO_FIELD pInjectEvent;

    if (g_initialized == 1)
    {
        InjectEvent = 0;
        pInjectEvent = (PINTERRUPT_INJECT_INFO_FIELD)&InjectEvent;

        pInjectEvent->Vector = DEBUG_EXCEPTION; 
        pInjectEvent->InterruptionType = HARDWARE_EXCEPTION;
     
        pInjectEvent->DeliverErrorCode = 0;
        pInjectEvent->Valid = 1;
        _WriteVMCS(VM_ENTRY_INTR_INFO_FIELD, InjectEvent);
    }

    return TRUE;
}


BOOLEAN HandleCpuid(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
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

BOOLEAN HandleMsrRead(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
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

BOOLEAN HandleMsrWrite(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
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


BOOLEAN HandleDrAccess(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
    DbgLog(("DrAccess\n"));
    return TRUE;
}


BOOLEAN HandleCrAccess(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
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
                    if ((g_initialized == 1) && (pCpu->ProcessorNumber == 0))
                    {
                        EnterDebugger(pCpu, pGuestRegs, Reg);
                        _WriteVMCS(GUEST_CR3, Reg);
                    }
                    else
                    {
                        _WriteVMCS(GUEST_CR3, Reg);
                    }
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

BOOLEAN HandleException(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
    ULONG32 Event, InjectEvent;
    ULONG64 error, InstructionLength, ErrorCode, ExitQualification, GuestRip;
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

/*                    pBreakpoint = GetBreakpointWithAddress(GuestRip,*/
/*                            SOFTWARE_BREAKPOINT_TYPE); */

/*                    if (pBreakpoint == NULL)*/
/*                    {*/
                    InjectEvent = 0;
                    pInjectEvent->Vector = BREAKPOINT_EXCEPTION;
                    pInjectEvent->InterruptionType = SOFTWARE_INTERRUPT;
                    pInjectEvent->DeliverErrorCode = 0;
                    pInjectEvent->Valid = 1;
                    _WriteVMCS(VM_ENTRY_INTR_INFO_FIELD, InjectEvent);
                    _WriteVMCS(VM_ENTRY_INSTRUCTION_LEN, 1);
                    _WriteVMCS(GUEST_RIP, GuestRip);
/*                    }*/
/*                    else*/
/*                    {*/
/*                        ReportEvent(pBreakpoint);*/
/*                    }*/
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

BOOLEAN HandleInvd(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
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
            HandleDrAccess(pCpu, pGuestRegs);
/*            HandleUnimplemented(pCpu, pGuestRegs, ExitCode);*/
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

NTSTATUS Virtualize(PVIRT_CPU pCpu)
{
    ULONG64 rsp;
    ULONG32 i;
    ULONG result;
    
    i = KeGetCurrentProcessorNumber();
    DbgLog(("vmx: Virtualize(): CPU: 0x%p \n", pCpu));
    DbgLog(("vmx: Virtualize(): rsp: 0x%llx \n", _Rsp()));

    _VmLaunch();
    /* never returns if successful */
    DbgLog(("vmx: Virtualize(): rflags after _VmLaunch: 0x%x\n", _Rflags()));
    if (_VmFailInvalid())
    {
        DbgLog(("vmx: Virtualize(): no current VMCS\n"));
        return STATUS_UNSUCCESSFUL;
    }

    if (_VmFailValid())
    {
        DbgLog(("vmx: Virtualize(): vmlaunch failed\n"));
        DbgLog(("vmx: Virtualize(): _ReadVMCS: 0x%llx\n", _ReadVMCS(VM_INSTRUCTION_ERROR)));
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_UNSUCCESSFUL;
}

NTSTATUS StartVirtualization(PVOID GuestRsp)
{
    NTSTATUS Status;
    PVOID HostKernelStackBase;
    PVIRT_CPU pCpu;

    Status = CheckIfVMXIsEnabled();
    
    if (Status == STATUS_UNSUCCESSFUL)
    {
        return STATUS_UNSUCCESSFUL;
    }
    
    HostKernelStackBase = ExAllocatePoolWithTag(NonPagedPool, 16*0x1000, 0x42424242);
    RtlZeroMemory(HostKernelStackBase, 16*0x1000);
    if (!HostKernelStackBase)
    {
        DbgLog(("vmx: SetupVMX(): can't allocate host kernel stack\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pCpu = (PVIRT_CPU)((PCHAR)HostKernelStackBase+16*0x1000-8-sizeof(VIRT_CPU));
    pCpu->HostKernelStackBase = HostKernelStackBase;
    pCpu->Self = pCpu;
    pCpu->State = STATE_RUNNING;
    pCpu->Mailbox = IPI_RUNNING;

    Status = SetupVMX(pCpu);

    g_cpus[pCpu->ProcessorNumber] = pCpu;
    
    if (Status == STATUS_UNSUCCESSFUL)
    {
        return STATUS_UNSUCCESSFUL;
    }
    
    Status = SetupVMCS(pCpu, GuestRsp);
    
    if (Status == STATUS_UNSUCCESSFUL)
    {
        return STATUS_UNSUCCESSFUL;
    }
    
    InterlockedIncrement(&g_processors);
    
    Status = Virtualize(pCpu);
    
    if (Status == STATUS_UNSUCCESSFUL)
    {
        return STATUS_UNSUCCESSFUL;
    }
    
    return STATUS_SUCCESS;
}




