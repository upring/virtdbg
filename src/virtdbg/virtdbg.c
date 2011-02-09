#include "virtdbg.h"

KMUTEX g_mutex;
ULONG32 g_initialized = 0;
PVIRT_CPU *g_cpus;

extern ULONG32 g_processors;

NTSTATUS DriverUnload(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS Status;
    CCHAR i;
    ULONG64 msr;
    VMX_BASIC_MSR vmxbasic;
    KIRQL OldIrql;
    KAFFINITY OldAffinity;
    
    DbgLog(("unloading hypervisor\n"));

    for (i=0; i<KeNumberProcessors; i++)
    {
        OldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1<<i));
        OldIrql = KeRaiseIrqlToDpcLevel();
        DbgLog(("stopping virtualisation\n"));
        _StopVirtualization();
        KeLowerIrql(OldIrql);
        KeRevertToUserAffinityThreadEx(OldAffinity);
    }
     
    return STATUS_SUCCESS;
}

static NTSTATUS ThreadStart(PVOID StartContext)
{
    NTSTATUS Status;
    CCHAR i;
    KIRQL OldIrql;
    KAFFINITY OldAffinity;

    InitDebugLayer();

    Status = CheckForVirtualizationSupport();
    if (Status == STATUS_UNSUCCESSFUL)
    {
        DbgLog(("vmx: aborting no virtualisation\n"));
        return STATUS_UNSUCCESSFUL;
    }
    
/*    KeInitializeMutex(&g_mutex, 0);*/
/*    */
/*    KeWaitForSingleObject(&g_mutex, Executive, KernelMode, FALSE, NULL);*/
/*    DbgLog(("virtualizing %d processors ...\n", KeNumberProcessors));*/

/*    g_cpus = ExAllocatePoolWithTag(NonPagedPool, KeNumberProcessors*sizeof(PVIRT_CPU), 0x42424242);*/

/*    if (!g_cpus)*/
/*    {*/
/*        DbgLog(("can't allocate cpus array\n"));*/
/*        return STATUS_INSUFFICIENT_RESOURCES;*/
/*    }*/

/*    DbgLog(("Allocated g_cpus array @ 0x%llx, size=0x%x\n", g_cpus, KeNumberProcessors*sizeof(PVIRT_CPU)));*/
/*    RtlZeroMemory(g_cpus, KeNumberProcessors*sizeof(PVIRT_CPU));*/
/*    */
/*    for (i = 0; i < KeNumberProcessors; i++) */
/*    {*/
/*        OldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY) (1 << i));*/
/*        OldIrql = KeRaiseIrqlToDpcLevel();*/
/*        _StartVirtualization();*/
/*        KeLowerIrql(OldIrql);*/
/*        KeRevertToUserAffinityThreadEx(OldAffinity);*/
/*    }*/

/*    DbgLog(("all done...\n"));*/

/*    KeReleaseMutex (&g_mutex, FALSE);*/

/*    if (KeNumberProcessors != g_processors) */
/*    {*/
/*        DbgLog(("vmx: aborting not all processors are virtualized\n"));*/
/*        return STATUS_UNSUCCESSFUL;*/
/*    }*/
/*    */
/*    InterlockedIncrement(&g_initialized);*/

/*    for (i = 0; i < KeNumberProcessors; i++)*/
/*    {*/
/*        DumpVirtCpu(g_cpus[i]);*/
/*    }*/
    
    return STATUS_SUCCESS;

}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status;
    HANDLE hThread = NULL;
    
/*    DriverObject->DriverUnload = DriverUnload;*/

    Status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, ThreadStart, NULL);
    if (!NT_SUCCESS(Status))
    {
/*        DbgLog(("PsCreateSystemThread failed with status 0x%08x\n", Status));*/
        return Status;
    }

    return STATUS_SUCCESS;
}


