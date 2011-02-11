#include "log.h"

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


