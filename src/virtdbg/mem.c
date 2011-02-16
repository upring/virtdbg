// This file is part of Virtdbg
// Copyright (C) 2010-2011 Damien AUMAITRE

//  Licence is GPLv3, see LICENCE.txt in the top-level directory


#include "mem.h"

PVOID AllocateMemory(ULONG32 Size)
{
    PVOID pMem = NULL;
    pMem = ExAllocatePoolWithTag(NonPagedPool, Size, VIRTDBG_POOLTAG);
    if (pMem == NULL)
        return NULL;

    RtlZeroMemory(pMem, Size);
    return pMem;
}

VOID UnAllocateMemory(PVOID pMem)
{
    ExFreePoolWithTag(pMem, VIRTDBG_POOLTAG);
}

PVOID AllocateContiguousMemory(ULONG size)
{
    PVOID Address;
    PHYSICAL_ADDRESS l1, l2, l3;

    l1.QuadPart = 0;
    l2.QuadPart = -1;
    l3.QuadPart = 0x200000;
    
    Address = MmAllocateContiguousMemorySpecifyCache(size, l1, l2, l3, MmCached);

    if (Address == NULL)
    {
        return NULL;
    }

    RtlZeroMemory(Address, size);
    return Address;
}

NTSTATUS IsPagePresent(ULONG64 PageVA)
{
    ULONG64 Pml4e, Pdpe, Pde, Pte;

    Pml4e = *(PULONG64)(((PageVA >> 36) & 0xff8) + PML4_BASE);

    if (!(Pml4e & P_PRESENT))
        return STATUS_NO_MEMORY;

    Pdpe = *(PULONG64)(((PageVA >> 27) & 0x1ffff8) + PDP_BASE);

    if (!(Pdpe & P_PRESENT))
        return STATUS_NO_MEMORY;

    Pde = *(PULONG64)(((PageVA >> 18) & 0x3ffffff8) + PD_BASE);

    if (!(Pde & P_PRESENT))
        return STATUS_NO_MEMORY;

    if ((Pde & P_LARGE) == P_LARGE)
        return STATUS_SUCCESS;

    Pte = *(PULONG64)(((PageVA >> 9) & 0x7ffffffff8) + PT_BASE);

    if (!(Pte & P_PRESENT))
        return STATUS_NO_MEMORY;

    return STATUS_SUCCESS;

}
