// This file is part of Virtdbg
// Copyright (C) 2010-2011 Damien AUMAITRE

//  Licence is GPLv3, see LICENCE.txt in the top-level directory


#include "driver.h"

NTSTATUS DriverUnload(PDRIVER_OBJECT DriverObject)
{
    CCHAR i;
    KIRQL OldIrql;
    KAFFINITY OldAffinity;
    
    for (i=0; i<KeNumberProcessors; i++)
    {
        OldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1<<i));
        OldIrql = KeRaiseIrqlToDpcLevel();
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


