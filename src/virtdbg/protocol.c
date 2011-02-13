#include "protocol.h"

static LONG g_Id = 0;
static ULONG32 g_LastId = 0;
static ULONG32 g_ClientId = 0;
static PVOID g_SendArea = NULL;
static PVOID g_RecvArea = NULL;

extern PVIRTDBG_CONTROL_AREA g_ControlArea;

NTSTATUS InitProtocolLayer(PVOID SendArea, PVOID RecvArea)
{
    g_SendArea = SendArea;
    g_RecvArea = RecvArea;
    g_Id = INITIAL_ID;
    return STATUS_SUCCESS;
}


static ULONG32 CalcChecksum(PVOID Src, ULONG32 Size)
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

static VOID FixUpPacket(PVOID pPacket)
{
    PPACKET_HEADER pHeader;
    pHeader = (PPACKET_HEADER)pPacket;
    pHeader->Id = g_Id;
    pHeader->ClientId = g_ClientId;
    pHeader->Checksum = CalcChecksum((PUCHAR)pPacket+sizeof(PACKET_HEADER), 
                    pHeader->Size);
}


BOOLEAN SendPacket(PVOID pPacket, ULONG32 MaxRetries)
{
    PPACKET_HEADER pHeader;
    ULONG32 Size, retries;
    
    retries = 0;
    pHeader = (PPACKET_HEADER)pPacket;

    FixUpPacket(pPacket);
    Size = pHeader->Size+sizeof(PACKET_HEADER);

    if (g_SendArea == NULL)
    {
        DbgLog(("not initialized ?\n"));
        return FALSE;
    }

    if (Size > MAX_PACKET_SIZE)
    {
        DbgLog(("packet too big\n"));
        return FALSE;
    }

    RtlCopyMemory(g_SendArea, pPacket, Size);
    DestroyPacket(pPacket);

    while (retries < MaxRetries)
    {
        retries++;
        if (g_ControlArea->LastServerId == pHeader->Id)
        {
            InterlockedIncrement(&g_Id);
            DbgLog(("packet successfully sent\n"));
            return TRUE;
        }
    }
    DbgLog(("no ack after %d retries\n", retries));
    return FALSE;
}

VOID CheckNewClientId()
{
    if (g_ControlArea == NULL)
        return;

    g_ControlArea->ServerId = g_ControlArea->ClientId;
    if (g_ControlArea->ClientId != g_ClientId)
    {
        DbgLog(("new client : 0x%x\n", g_ControlArea->ClientId));
        g_ClientId = g_ControlArea->ClientId;
        g_Id = INITIAL_ID;
        g_LastId = 0;
        DbgLog(("send @ 0x%llx (0x%llx) recv @ 0x%llx (0x%llx)\n", g_SendArea, g_ControlArea->RecvArea, g_RecvArea, g_ControlArea->SendArea));
        DbgLog(("sizeof(MANIPULATE_STATE_PACKET)=0x%x\n", 
                    sizeof(MANIPULATE_STATE_PACKET)));
        DbgLog(("sizeof(PACKET_HEADER)=0x%x\n", 
                    sizeof(PACKET_HEADER)));

    }

}

PVOID ReceivePacket()
{
    PVOID pPacket;
    PPACKET_HEADER pHeader;
    ULONG32 Size, Checksum;

    CheckNewClientId();

    if (g_RecvArea == NULL)
    {
        DbgLog(("not initialized ?\n"));
        return NULL;
    }

    pHeader = (PPACKET_HEADER)(g_RecvArea);
    if (pHeader->Magic != PACKET_MAGIC)
        return NULL;

    if (pHeader->Size > MAX_PACKET_SIZE)
        return NULL;

    if (pHeader->Id <= g_LastId)
        return NULL;

    Size = sizeof(PACKET_HEADER) + pHeader->Size;
    pPacket = AllocateMemory(Size);
    if (pPacket == NULL)
    {
        return NULL;
    }
            
    RtlCopyMemory(pPacket, g_RecvArea, Size);

    if (pHeader->Size > 0)
    {
        Checksum = CalcChecksum((PUCHAR)pPacket+sizeof(PACKET_HEADER), 
                pHeader->Size);
        if (Checksum != pHeader->Checksum)
        {
            UnAllocateMemory(pPacket);
            return NULL;
        }
    }

    g_LastId = pHeader->Id;
    g_ControlArea->LastClientId = g_LastId;
    DbgLog(("Received packet (id=0x%x)\n", g_LastId));
    return pPacket;

}


static PVOID CreateBreakinPacket()
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


VOID DestroyPacket(PVOID pPacket)
{
    UnAllocateMemory(pPacket);
}


