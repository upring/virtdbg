#include "virtdbg.h"

static KMUTEX g_mutex;
static ULONG32 g_initialized = 0;
static ULONG32 g_processors = 0;

PVIRT_CPU *g_cpus = NULL;
PVIRTDBG_CONTROL_AREA g_ControlArea = NULL;

static PVOID g_SendArea = NULL;
static PVOID g_RecvArea = NULL;

NTSTATUS VirtDbgStart(PVOID StartContext)
{
    NTSTATUS Status;
    CCHAR i;
    KIRQL OldIrql;
    KAFFINITY OldAffinity;

    Status = CheckForVirtualizationSupport();
    if (Status == STATUS_UNSUCCESSFUL)
    {
        DbgLog(("aborting, no virtualisation support\n"));
        return STATUS_UNSUCCESSFUL;
    }
    
    KeInitializeMutex(&g_mutex, 0);
    KeWaitForSingleObject(&g_mutex, Executive, KernelMode, FALSE, NULL);
    DbgLog(("virtualizing %d processors ...\n", KeNumberProcessors));

    g_cpus = ExAllocatePoolWithTag(NonPagedPool, KeNumberProcessors*sizeof(PVIRT_CPU), 0x42424242);

    if (!g_cpus)
    {
        DbgLog(("can't allocate cpus array\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DbgLog(("Allocated g_cpus array @ 0x%llx, size=0x%x\n", g_cpus, KeNumberProcessors*sizeof(PVIRT_CPU)));
    RtlZeroMemory(g_cpus, KeNumberProcessors*sizeof(PVIRT_CPU));
    
    InitControlArea();
    InitProtocolLayer(g_SendArea, g_RecvArea);

    for (i = 0; i < KeNumberProcessors; i++) 
    {
        OldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY) (1 << i));
        OldIrql = KeRaiseIrqlToDpcLevel();
        _StartVirtualization();
        KeLowerIrql(OldIrql);
        KeRevertToUserAffinityThreadEx(OldAffinity);
    }

    DbgLog(("all done...\n"));

    KeReleaseMutex (&g_mutex, FALSE);

    if (KeNumberProcessors != g_processors) 
    {
        DbgLog(("aborting, not all processors are virtualized\n"));
        return STATUS_UNSUCCESSFUL;
    }
    
    InterlockedIncrement(&g_initialized);

/*    for (i = 0; i < KeNumberProcessors; i++)*/
/*    {*/
/*        DumpVirtCpu(g_cpus[i]);*/
/*    }*/
    
    return STATUS_SUCCESS;

}

NTSTATUS InitControlArea()
{
    PHYSICAL_ADDRESS l1, l2, l3;

    l1.QuadPart = 0;
    l2.QuadPart = -1;
    l3.QuadPart = 0x200000;
    
    g_ControlArea = (PVIRTDBG_CONTROL_AREA)MmAllocateContiguousMemorySpecifyCache(CONTROL_AREA_SIZE, 
            l1, l2, l3, MmCached);

    if (g_ControlArea == NULL)
        return STATUS_NO_MEMORY;

    DbgLog(("Allocated CONTROL_AREA structure @ 0x%llx\n", g_ControlArea));
    l1 = MmGetPhysicalAddress(g_ControlArea);
    DbgLog(("CONTROL_AREA phys @ 0x%llx\n", l1.QuadPart));

    RtlZeroMemory(g_ControlArea, CONTROL_AREA_SIZE);

    g_ControlArea->Magic1 = CONTROL_AREA_MAGIC1;
    g_ControlArea->Magic2 = CONTROL_AREA_MAGIC2;

    g_SendArea = AllocateMemory(0x1000);

    if (g_SendArea == NULL)
        return STATUS_NO_MEMORY;

    g_ControlArea->SendArea = MmGetPhysicalAddress(g_SendArea);

    g_RecvArea = AllocateMemory(0x1000);

    if (g_RecvArea == NULL)
        return STATUS_NO_MEMORY;

    g_ControlArea->RecvArea = MmGetPhysicalAddress(g_RecvArea);

    g_ControlArea->KernelBase = 0;
    g_ControlArea->DebuggerData = 0;

    return STATUS_SUCCESS;
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
        DbgLog(("can't allocate host kernel stack\n"));
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

