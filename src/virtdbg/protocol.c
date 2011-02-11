#include "protocol.h"

static ULONG32 g_Id = 0;
static PVOID g_SendArea = NULL;
static PVOID g_RecvArea = NULL;

NTSTATUS InitProtocolLayer(PVOID SendArea, PVOID RecvArea)
{
    g_SendArea = SendArea;
    g_RecvArea = RecvArea;
    return STATUS_SUCCESS;
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


VOID DestroyPacket(PVOID pPacket)
{
    UnAllocateMemory(pPacket);
}


