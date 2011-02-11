#include "driver.h"

NTSTATUS DriverUnload(PDRIVER_OBJECT DriverObject)
{
    CCHAR i;
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

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status;
    HANDLE hThread = NULL;
    
/*    DriverObject->DriverUnload = DriverUnload;*/

    Status = PsCreateSystemThread(&hThread, 
                                  THREAD_ALL_ACCESS, 
                                  NULL, 
                                  NULL, 
                                  NULL, 
                                  VirtDbgStart, NULL);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    return STATUS_SUCCESS;
}


