#include "debug.h"

PCONTROL_AREA g_ControlArea = NULL;
static PVOID g_SendArea = NULL;
static PVOID g_RecvArea = NULL;

static ULONG32 g_Id;
static PKSPIN_LOCK g_FreezeLock;

extern PVIRT_CPU *g_cpus;

NTSTATUS InitControlArea()
{
    PHYSICAL_ADDRESS l1, l2, l3;

    l1.QuadPart = 0;
    l2.QuadPart = -1;
    l3.QuadPart = 0x200000;
    
    g_ControlArea = (PCONTROL_AREA)MmAllocateContiguousMemorySpecifyCache(CONTROL_AREA_SIZE, 
            l1, l2, l3, MmCached);

    if (g_ControlArea == NULL)
        return STATUS_NO_MEMORY;

    RtlZeroMemory(g_ControlArea, CONTROL_AREA_SIZE);

    g_ControlArea->Magic1 = 0xbabebabe;
    g_ControlArea->Magic2 = 0xcafecafe;

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


NTSTATUS InitDebugLayer()
{
    PHYSICAL_ADDRESS PhysicalAddress;
    PVOID pLogBuffer;
    
    _Int3();
    InitControlArea();
    g_ControlArea->LogBuffer = InitLog();

    g_FreezeLock = AllocateMemory(sizeof(KSPIN_LOCK));

    if (!g_FreezeLock)
        return STATUS_UNSUCCESSFUL;

    KeInitializeSpinLock(g_FreezeLock);

    return STATUS_SUCCESS;
}

VOID ShutdownDebug()
{
/*    MmUnmapIoSpace(g_RecvBase, 0x1000);*/
    return;
}


ULONG32 CalcChecksum(PVOID Src, ULONG32 Size)
{
    ULONG32 Checksum;
    ULONG32 i;

    Checksum = 0;
    for (i=0;i<Size;i++)
    {
        Checksum += *((PUCHAR)Src+i);
    }

    return Checksum;
}


BOOLEAN SendPacket(PVOID pPacket, ULONG32 MaxRetries)
{
    PPACKET_HEADER pHeader;
    ULONG32 Size, retries;
    BOOLEAN result;
    int i;

    retries = 0;

    pHeader = (PPACKET_HEADER)pPacket;
    pHeader->Id = g_Id;
    Size = pHeader->Size+sizeof(PACKET_HEADER);
    RtlCopyMemory(g_SendArea, pPacket, Size);

    do
    {
        pHeader = (PPACKET_HEADER)((PUCHAR)g_SendArea+Size);
        if (pHeader->Type == PACKET_TYPE_RESET)
        {
            g_Id = INITIAL_ID;
            DbgLog(("resetting id to 0x%x\n", g_Id));
            continue;
        }

        if ((pHeader->Magic == PACKET_MAGIC) && 
                (pHeader->Type == PACKET_TYPE_ACK) && 
                (pHeader->Id == g_Id))
        {
            result = TRUE;
            DbgLog(("Sent packet (id=0x%x)\n", g_Id));
            g_Id++;
            break;
        }

        retries++;
        if (retries >= MaxRetries)
        {
/*            if (retries == MAX_RETRIES)*/
/*                DbgLog(("timeout when sending packet (id=0x%x)\n", g_Id));*/
            result = FALSE;
            break;
        }

    } while (42);

    DestroyPacket(pPacket);
    return result;

}

PVOID ReceivePacket(ULONG32 MaxRetries)
{
    PVOID pPacket;
    PPACKET_HEADER pHeader, pAck;
    ULONG32 HeaderSize, Size, Checksum, retries;
    int i;

    retries = 0;

    do
    {
        pHeader = (PPACKET_HEADER)(g_RecvArea);
        if (pHeader->Type == PACKET_TYPE_RESET)
        {
            if (g_Id != INITIAL_ID)
            {
                DbgLog(("resetting id to 0x%x\n", INITIAL_ID));
                g_Id = INITIAL_ID;
            }
            continue;
        }

        if (pHeader->Id == g_Id)
        {
            HeaderSize = pHeader->Size;
            if (HeaderSize <= MAX_PACKET_SIZE)
            {
                Size = sizeof(PACKET_HEADER) + HeaderSize;
                pPacket = AllocateMemory(Size);
                if (pPacket == NULL)
                {
                    return NULL;
                }
                
                RtlCopyMemory(pPacket, g_RecvArea, Size);

                if (HeaderSize > 0)
                {
                    Checksum = CalcChecksum((PUCHAR)pPacket+sizeof(PACKET_HEADER), HeaderSize);
                    if (Checksum != pHeader->Checksum)
                    {
                        UnAllocateMemory(pPacket);
                        return NULL;
                    }
                }

                pAck = (PPACKET_HEADER)((PUCHAR)(g_RecvArea)+Size);
                pAck->Magic = PACKET_MAGIC;
                pAck->Type = PACKET_TYPE_ACK;
                pAck->Id = g_Id;

                DbgLog(("Received packet (id=0x%x)\n", g_Id));
                g_Id++;

                return pPacket;
            }
        }
        retries++;
        if (retries >= MaxRetries)
        {
/*            if (retries >= MAX_RETRIES)*/
/*                DbgLog(("timeout when receiving packet (id=0x%x) (retries=0x%x)\n", g_Id, retries));*/
            return NULL;
        }

    } while (42);
}


VOID EnableTF()
{
    ULONG64 Rflags;
    Rflags = _ReadVMCS(GUEST_RFLAGS);

    Rflags |= TF;
    _WriteVMCS(GUEST_RFLAGS, Rflags);

}

VOID DisableTF()
{
    ULONG64 Rflags;
    Rflags = _ReadVMCS(GUEST_RFLAGS);

    Rflags &= ~TF;
    _WriteVMCS(GUEST_RFLAGS, Rflags);

}

PVOID CreateBreakinPacket()
{
    PVOID pPacket;
    PPACKET_HEADER pHeader;
    ULONG32 Size;

    Size = sizeof(PACKET_HEADER)+sizeof(BREAKIN_PACKET);

    pPacket = AllocateMemory(Size);
    if (pPacket == NULL)
        return NULL;

    pHeader = (PPACKET_HEADER)pPacket;
    pHeader->Magic = PACKET_MAGIC;
    pHeader->Type = PACKET_TYPE_BREAKIN;
    pHeader->Size = sizeof(BREAKIN_PACKET);

    return pPacket;

}

PVOID CreateManipulateStatePacket(ULONG32 ApiNumber, ULONG32 Data2Size)
{
    PVOID pPacket;
    PPACKET_HEADER pHeader;
    PMANIPULATE_STATE_PACKET pData1;
    ULONG32 Size;

    Size = sizeof(PACKET_HEADER)+sizeof(MANIPULATE_STATE_PACKET)+Data2Size;

    pPacket = AllocateMemory(Size);
    if (pPacket == NULL)
        return NULL;

    pHeader = (PPACKET_HEADER)pPacket;
    pHeader->Magic = PACKET_MAGIC;
    pHeader->Type = PACKET_TYPE_MANIPULATE_STATE;
    pHeader->Size = sizeof(MANIPULATE_STATE_PACKET)+Data2Size;

    pData1 = (PMANIPULATE_STATE_PACKET)((PUCHAR)pPacket+sizeof(PACKET_HEADER));
    pData1->ApiNumber = ApiNumber;
    return pPacket;
}

PVOID CreateStateChangePacket(ULONG32 Exception, ULONG64 Address)
{
    PVOID pPacket;
    PPACKET_HEADER pHeader;

    PSTATE_CHANGE_PACKET pData1;
    ULONG32 Size;

    Size = sizeof(PACKET_HEADER)+sizeof(STATE_CHANGE_PACKET);
    pPacket = AllocateMemory(Size);
    if (pPacket == NULL)
        return NULL;

    pHeader = (PPACKET_HEADER)pPacket;
    pHeader->Magic = PACKET_MAGIC;
    pHeader->Type = PACKET_TYPE_STATE_CHANGE;
    pHeader->Size = sizeof(STATE_CHANGE_PACKET);
    
    pData1 = (PSTATE_CHANGE_PACKET)((PUCHAR)pPacket+sizeof(PACKET_HEADER));
    pData1->Exception = Exception;
    pData1->Address = Address;
    return pPacket;
}

PVOID ReadVirtualMemory(ULONG64 Address, ULONG32 Size)
{
    NTSTATUS Status;
    PVOID Buffer;
    
    if (Size > 0x280)
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

VOID DumpContext(PDEBUG_CONTEXT pContext)
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

VOID DumpMem(PUCHAR Address, ULONG32 Size)
{
    ULONG64 i;
    for (i=0;i<Size;i++)
    {
        DbgLog(("0x%x 0x%x\n", Address+i, *(Address+i)));
    }
}


BOOLEAN HandleManipulateStatePacket(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, PVOID pPacket)
{
    PPACKET_HEADER pHeader, pResponseHeader;
    PMANIPULATE_STATE_PACKET pData1, pResponseData1;
    PVOID pResponse, pData;
    PDEBUG_CONTEXT pContext;
    ULONG64 Address;
    ULONG32 Size, Flags, Offset;

    pHeader = (PPACKET_HEADER)pPacket;
    pData1 = (PMANIPULATE_STATE_PACKET)((PUCHAR)pPacket+sizeof(PACKET_HEADER));

    switch (pData1->ApiNumber)
    {
        case READ_VIRTUAL_MEMORY_API:
            Address = pData1->u.ReadVirtualMemory.Address;
            Size = pData1->u.ReadVirtualMemory.Size;

            DbgLog(("READ_VIRTUAL_MEMORY_API request, address=0x%llx, size=0x%x\n", Address, Size));

            pData = ReadVirtualMemory(Address, Size);

            if (pData == NULL)
            {
                pResponse = CreateManipulateStatePacket(READ_VIRTUAL_MEMORY_API, 0);
                if (pResponse == NULL)
                {
                    /* not enought memory ? */
                    return FALSE;
                }

                pResponseData1 = (PMANIPULATE_STATE_PACKET)((PUCHAR)pResponse+
                        sizeof(PACKET_HEADER));
                pResponseData1->Error = STATUS_UNSUCCESSFUL;

            }
            else
            {
                pResponse = CreateManipulateStatePacket(READ_VIRTUAL_MEMORY_API, Size);
                if (pResponse == NULL)
                {
                    /* not enought memory ? */
                    return FALSE;
                }
            
                Offset = sizeof(PACKET_HEADER)+sizeof(MANIPULATE_STATE_PACKET);
                DbgLog(("offset=0x%08x\n", Offset));
                RtlCopyMemory((PUCHAR)pResponse+Offset, pData, Size);
                UnAllocateMemory(pData);

            }

            pResponseHeader = (PPACKET_HEADER)pResponse;
            pResponseHeader->Id = g_Id;
            pResponseHeader->Checksum = CalcChecksum((PUCHAR)pResponse+sizeof(PACKET_HEADER), 
                    pResponseHeader->Size);
            SendPacket(pResponse, MAX_RETRIES);
            break;

        case WRITE_VIRTUAL_MEMORY_API:
            Address = pData1->u.WriteVirtualMemory.Address;
            Size = pData1->u.WriteVirtualMemory.Size;

            if (Size == pHeader->Size-sizeof(MANIPULATE_STATE_PACKET))
            {
                pData = AllocateMemory(Size);
                if (pData == NULL)
                {
                    /* not enought memory */
                    return FALSE;
                }

                RtlCopyMemory(pData, (PUCHAR)pData1+sizeof(MANIPULATE_STATE_PACKET), Size);
                UnAllocateMemory(pData);
                
                pResponse = CreateManipulateStatePacket(WRITE_VIRTUAL_MEMORY_API, 0);
                if (pResponse == NULL)
                {
                    /* not enought memory */
                    return FALSE;
                }

                pResponseHeader = (PPACKET_HEADER)pResponse;
                pResponseHeader->Id = g_Id;
                pResponseHeader->Checksum = CalcChecksum((PUCHAR)pResponse+sizeof(PACKET_HEADER),
                        pResponseHeader->Size);
                SendPacket(pResponse, MAX_RETRIES);
            }
            break;

        case GET_CONTEXT_API:
            DbgLog(("received GET_CONTEXT_API request\n"));
            Flags = pData1->u.GetContext.Flags;

            pResponse = CreateManipulateStatePacket(GET_CONTEXT_API, sizeof(DEBUG_CONTEXT));
            
            DbgLog(("sizeof(PACKET_HEADER) = 0x%x\n", sizeof(PACKET_HEADER)));
            DbgLog(("sizeof(MANIPULATE_STATE_PACKET) = 0x%x\n", sizeof(MANIPULATE_STATE_PACKET)));
            DbgLog(("sizeof(DEBUG_CONTEXT) = 0x%x\n", sizeof(DEBUG_CONTEXT)));

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

            DumpContext(pContext);

            pResponseHeader = (PPACKET_HEADER)pResponse;
            pResponseHeader->Id = g_Id;
            pResponseHeader->Checksum = CalcChecksum((PUCHAR)pResponse+sizeof(PACKET_HEADER),
                    pResponseHeader->Size);
            SendPacket(pResponse, MAX_RETRIES);

            break;

        case SET_CONTEXT_API:
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
            pResponseHeader = (PPACKET_HEADER)pResponse;
            pResponseHeader->Id = g_Id;
            pResponseHeader->Checksum = CalcChecksum((PUCHAR)pResponse+sizeof(PACKET_HEADER),
                    pResponseHeader->Size);
            SendPacket(pResponse, MAX_RETRIES);

            break;

    }

    return TRUE;
}


VOID DebugLoop(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs)
{
    PPACKET_HEADER pHeader;
    PCONTINUE_PACKET pContinue;
    ULONG64 Rip, Rsp;
    BOOLEAN DoDebug;

    DoDebug = TRUE;
    DbgLog(("Starting debugging loop...\n"));

    pCpu->State = STATE_DEBUGGED;

    do 
    {
        pHeader = (PPACKET_HEADER)ReceivePacket(MAX_RETRIES);
        if (pHeader == NULL)
        {
            continue;
        }

        switch (pHeader->Type)
        {
            case PACKET_TYPE_CONTINUE:
                pContinue = (PCONTINUE_PACKET)((PUCHAR)pHeader+sizeof(PACKET_HEADER));
                if (pContinue->Status == CONTINUE_STATUS_SINGLE_STEP)
                {
                    EnableTF();
                }
                else if (pContinue->Status  == CONTINUE_STATUS_UNLOAD)
                {
                    /* FIXME: unloading both cores */
                    DbgLog(("Terminating...\n"));
                    Rip = (ULONG64)_GuestExit;
                    Rsp = pGuestRegs->rsp;
                    DbgLog(("restoring rip=0x%llx, rsp=0x%llx\n", Rip, Rsp));
/*                    _VmxOff(Rip, Rsp);*/
                }
                DoDebug = FALSE;
                break;

            case PACKET_TYPE_MANIPULATE_STATE:
                HandleManipulateStatePacket(pCpu, pGuestRegs, (PVOID)pHeader);
                break;

        }
        DestroyPacket(pHeader);

    } while (DoDebug);

    DbgLog(("Ending debugging loop\n"));
    pCpu->State = STATE_RUNNING;
}

VOID ReportException(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, ULONG Exception, ULONG64 Address)
{
    PPACKET_HEADER pResponse;

    DbgLog(("reporting exception\n"));
    DbgLog(("GUEST_ACTIVITY_STATE=0x%08x\n", _ReadVMCS(GUEST_ACTIVITY_STATE)));
/*    DbgLog(("GUEST_INTERRUPTIBILITY_STATE=0x%08x\n", _ReadVMCS(GUEST_INTERRUPTIBILITY_STATE)));*/
    DbgLog(("pending=0x%016x\n", _ReadVMCS(GUEST_PENDING_DBG_EXCEPTIONS)));
            

    if (pCpu->State == STATE_BREAKIN)
    {
        DbgLog(("Breakin, disabling TF\n"));
    }
    
    DisableTF();

    FreezeCpus(pCpu->ProcessorNumber);

    pResponse = (PPACKET_HEADER)CreateStateChangePacket(Exception, Address);

    if (pResponse == NULL)
    {
        /* bad ! */
        return;
    }

    pResponse->Id = g_Id;
    pResponse->Checksum = CalcChecksum((PUCHAR)pResponse+sizeof(PACKET_HEADER), 
                    pResponse->Size);

    if (SendPacket(pResponse, MAX_RETRIES))
    {
        DebugLoop(pCpu, pGuestRegs);
    }
    else
    {
        DbgLog(("error when sending packet\n"));
    }

    ResumeCpus(pCpu->ProcessorNumber);

    DbgLog(("exception end\n"));
}

static VOID FreezeCpu(PKDPC pDpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    KIRQL OldIrql;
    
    DbgLog(("cpu frozen\n"));

/*    KeRaiseIrql(HIGH_LEVEL, &OldIrql);*/
    KeAcquireSpinLockAtDpcLevel(g_FreezeLock);
    KeReleaseSpinLockFromDpcLevel(g_FreezeLock);
/*    KeLowerIrql(OldIrql);*/

    UnAllocateMemory(pDpc);
    DbgLog(("cpu resumed\n"));

}

VOID FreezeCpus(ULONG32 RunningProcessor)
{
    CCHAR i;
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

            KeInitializeDpc(pDpc, FreezeCpu, NULL);
            KeSetTargetProcessorDpc(pDpc, i); 
            KeSetImportanceDpc(pDpc, HighImportance);
            KeInsertQueueDpc(pDpc, NULL, NULL);

        }
    }
}
    
VOID ResumeCpus(ULONG32 RunningProcessor)
{
    DbgLog(("Resuming cpus...\n"));
    KeReleaseSpinLockFromDpcLevel(g_FreezeLock);
}

/*VOID FreezeCpus(ULONG32 RunningProcessor)*/
/*{*/
/*    int i, result, count;*/
/*    KIRQL OldIrql;*/

/*    KeRaiseIrql(HIGH_LEVEL, &OldIrql);*/
/*    DbgLog(("Freezing cpus...\n"));*/
/*    for (i=0; i<KeNumberProcessors; i++)*/
/*    {*/
/*        if (i != RunningProcessor)*/
/*        {*/
/*            DbgLog(("IPI_FREEZE on processor %d\n", i));*/
/*            g_cpus[i]->Mailbox = IPI_FREEZE;*/
/*        }*/
/*    }*/

/*    DbgLog(("Sent freeze IPI\n"));*/
/*    DbgLog(("Waiting for response\n"));*/
/*    count = 0;*/

/*    do */
/*    {*/
/*        result = 1;*/
/*        for (i=0; i<KeNumberProcessors; i++)*/
/*        {*/
/*            if (i != RunningProcessor)*/
/*            {*/
/*                if (g_cpus[i]->Mailbox == IPI_FROZEN)*/
/*                {*/
/*                    result += 1;*/
/*                    DbgLog(("processor %d responded IPI_FROZEN, result=%d\n", i, result));*/
/*                }*/
/*            }*/
/*        }*/
/*        count++;*/
/*    } while ((result != KeNumberProcessors) || (count < 0x100000));*/

/*    if (count >= 0x100000)*/
/*        DbgLog(("can't freeze cpus\n"));*/

/*    DbgLog(("Cpus frozen\n"));*/
/*    KeLowerIrql(OldIrql);*/
/*}*/

/*VOID ResumeCpus(ULONG32 RunningProcessor)*/
/*{*/
/*    int i, result;*/

/*    DbgLog(("Resuming cpus...\n"));*/

/*    for (i=0; i<KeNumberProcessors; i++)*/
/*    {*/
/*        if (i != RunningProcessor)*/
/*        {*/
/*            g_cpus[i]->Mailbox = IPI_RESUME;*/
/*        }*/
/*    }*/

/*    do*/
/*    {*/
/*        result = 1;*/
/*        for (i=0; i<KeNumberProcessors; i++)*/
/*        {*/
/*            if (i != RunningProcessor)*/
/*            {*/
/*                if (g_cpus[i]->Mailbox == IPI_RUNNING)*/
/*                {*/
/*                    result += 1;*/
/*                }*/
/*            }*/
/*        }*/
/*    } while (result != KeNumberProcessors);*/

/*    DbgLog(("Cpus resumed\n"));*/

/*}*/

/*VOID FreezeExecution(PVIRT_CPU pCpu)*/
/*{*/
/*    if (pCpu->Mailbox == IPI_FREEZE)*/
/*    {*/
/*        DbgLog(("cpu %d frozen\n", pCpu->ProcessorNumber));*/
/*        pCpu->Mailbox = IPI_FROZEN;*/
/*        pCpu->State = STATE_FROZEN;*/
/*        do*/
/*        {*/

/*        } while (pCpu->Mailbox != IPI_RESUME);*/
/*        DbgLog(("cpu %d running\n", pCpu->ProcessorNumber));*/
/*        pCpu->State = STATE_RUNNING;*/
/*        pCpu->Mailbox = IPI_RUNNING;*/
/*    }*/
/*}*/

VOID DumpPacket(PPACKET_HEADER pHeader)
{
    DbgLog(("pHeader->Magic = 0x%x\n", pHeader->Magic));
    DbgLog(("pHeader->Type = 0x%x\n", pHeader->Type));
    DbgLog(("pHeader->Size = 0x%x\n", pHeader->Size));
    DbgLog(("pHeader->Id = 0x%x\n", pHeader->Id));
    DbgLog(("pHeader->Checksum = 0x%x\n", pHeader->Checksum));
}


BOOLEAN EnterDebugger(PVIRT_CPU pCpu, PGUEST_REGS pGuestRegs, ULONG64 Cr3) 
{
    PPACKET_HEADER pHeader, pResponse;
    PBREAKIN_PACKET pPacket;
    ULONG32 i;
    BOOLEAN result;

    i = pCpu->ProcessorNumber;

    pHeader = (PPACKET_HEADER)ReceivePacket(0x10);
    if (pHeader == NULL)
        return FALSE;

    result = FALSE;
    DumpPacket(pHeader);

    if (pHeader->Type == PACKET_TYPE_BREAKIN)
    {
        pPacket = (PBREAKIN_PACKET)((PUCHAR)pHeader+sizeof(PACKET_HEADER));
        DbgLog(("pPacket->Cr3 = 0x%llx, Cr3=0x%llx\n", pPacket->Cr3, Cr3));
        if ((pPacket->Cr3 == 0) || (pPacket->Cr3 == Cr3))
        {
            DbgLog(("received breakin packet\n"));

            if (pCpu->State == STATE_BREAKIN)
            {
                DbgLog(("warning already in debug\n"));
                result = FALSE;
            }
            else
            {
                DbgLog(("enabling single step\n"));
                pCpu->State = STATE_BREAKIN;
                EnableTF();
                result = TRUE;
            }
        }
    }
    DestroyPacket(pHeader);

    return result;
}


VOID DestroyPacket(PVOID pPacket)
{
    UnAllocateMemory(pPacket);
}


static PVOID g_LogBuffer = NULL;
static ULONG g_LogCount = 0;
static ULONG g_LogIndex = 0;
static PKSPIN_LOCK g_LogLock;

PVOID InitLog()
{
    g_LogBuffer = AllocateMemory(LOGBUFFER_SIZE);

    if (g_LogBuffer == NULL)
        return NULL;

    g_LogLock = AllocateMemory(sizeof(KSPIN_LOCK));

    if (g_LogLock == NULL)
        return NULL;

    KeInitializeSpinLock(g_LogLock);

    return g_LogBuffer;
}

static BOOLEAN InsertLogEntry(char *buffer, unsigned short size)
{
    PLOGENTRY pEntry;
    ULONG32 Id;

    if (g_LogBuffer == NULL)
        return FALSE;

    if (g_LogIndex*sizeof(LOGENTRY) >= LOGBUFFER_SIZE)
    {
        g_LogIndex = 0;
    }

    pEntry = (PLOGENTRY)(g_LogBuffer)+g_LogIndex;

    if (pEntry->Data == NULL)
    {
        pEntry->Data = AllocateMemory(size);
        if (pEntry->Data == NULL)
            return FALSE;
    }
    else
    {
        if (pEntry->Size < size)
        {
            UnAllocateMemory(pEntry->Data);
            pEntry->Data = AllocateMemory(size);
            if (pEntry->Data == NULL)
                return FALSE;
        }
    }

    pEntry->Id = g_LogCount;
    pEntry->Size = size;
    RtlCopyMemory(pEntry->Data, buffer, size);

    g_LogCount++;
    g_LogIndex++;
    return TRUE;

}

VOID Log(char *format, ...)
{
    KIRQL CurrentIrql;

    unsigned short size;
    va_list args;
    UCHAR buffer[1024] = {0};

    RtlZeroMemory(&buffer, sizeof(buffer));
    va_start(args, format);

    CurrentIrql = KeGetCurrentIrql();
    if (CurrentIrql < DISPATCH_LEVEL)
    {
        KeRaiseIrqlToDpcLevel();
    }
    
    KeAcquireSpinLockAtDpcLevel(g_LogLock);

    vsnprintf((PUCHAR)&buffer, sizeof(buffer), (PUCHAR)format, args);
    buffer[1023] = '\0';
    size = strlen(buffer);

    InsertLogEntry(buffer, size);
    
    KeReleaseSpinLockFromDpcLevel(g_LogLock);

    if (CurrentIrql < DISPATCH_LEVEL)
    {
        KeLowerIrql(CurrentIrql);
    }
}


