
#include "vmx.h" 


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
        DbgLog(("error: extended CPUID functions not implemented\n"));
        return STATUS_UNSUCCESSFUL;
    }

    /* Intel Genuine */
    if (!(ebx == 0x756e6547 && ecx == 0x6c65746e && edx == 0x49656e69)) 
    {
        DbgLog(("error: not an INTEL processor\n"));
        return STATUS_UNSUCCESSFUL;
    }

    _CpuId(0x1, &eax, &ebx, &ecx, &edx);
    if (!IsBitSet(ecx, 5))
    {
        DbgLog(("error: VMX not supported\n"));
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
    DbgLog(("GuestRsp=%p\n", GuestRsp));   
    
    pa = pCpu->VMCS_pa;
    DbgLog(("VMCS PHYSICAL_ADDRESS %llx\n", pa));
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
    
    DbgLog(("VMXON region size: 0x%x\n", size));
    DbgLog(("VMX revision ID: 0x%x\n", pvmx->RevId));
  
    va = AllocateContiguousMemory(size);
                            
    if (va == NULL)
    {
        DbgLog(("error: can't allocate vmxon region\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    *(ULONG32 *)va = pvmx->RevId;
    pa = MmGetPhysicalAddress(va);
    
    _VmxOn(pa);
    
    if (_VmFailInvalid())
    {
        DbgLog(("_VmxOn failed\n"));
        return STATUS_UNSUCCESSFUL;
    }

    pCpu->VMXON_va = va;
    pCpu->VMXON_pa = pa;
    
    va = AllocateContiguousMemory(size);
                            
    if (va == NULL)
    {
        DbgLog(("error: can't allocate vmcs region\n"));
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
        DbgLog(("error: can't allocate msr bitmap\n"));
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
        DbgLog(("error: VMXON not supported\n"));
        return STATUS_UNSUCCESSFUL;
    }
    
	/* vmx desactived by bios ? */        
    msr = _ReadMsr(MSR_IA32_FEATURE_CONTROL);
    if (!(msr & 4))
    {
        DbgLog(("vmx is disabled in bios: MSR_IA32_FEATURE_CONTROL is 0x%llx\n", msr));
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}


NTSTATUS Virtualize(PVIRT_CPU pCpu)
{
/*    ULONG64 rsp;*/
    ULONG32 i;
    
    i = KeGetCurrentProcessorNumber();
    DbgLog(("CPU: 0x%p \n", pCpu));
    DbgLog(("rsp: 0x%llx \n", _Rsp()));

    _VmLaunch();
    /* never returns if successful */
    DbgLog(("rflags after _VmLaunch: 0x%x\n", _Rflags()));
    if (_VmFailInvalid())
    {
        DbgLog(("no current VMCS\n"));
        return STATUS_UNSUCCESSFUL;
    }

    if (_VmFailValid())
    {
        DbgLog(("vmlaunch failed\n"));
        DbgLog(("_ReadVMCS: 0x%llx\n", _ReadVMCS(VM_INSTRUCTION_ERROR)));
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_UNSUCCESSFUL;
}





