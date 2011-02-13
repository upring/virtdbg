#include "log.h"

PVOID g_LogBuffer = NULL;
static LONG g_LogIndex = 0;
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
    if (g_LogBuffer == NULL)
        return FALSE;

    if (g_LogIndex+size > LOGBUFFER_SIZE)
    {
        RtlZeroMemory(g_LogBuffer, LOGBUFFER_SIZE);
        g_LogIndex = 0;
    }
    
    RtlCopyMemory((PUCHAR)g_LogBuffer+g_LogIndex, buffer, size);
    InterlockedExchangeAdd(&g_LogIndex, size);
    return TRUE;
}

VOID Log(char *format, ...)
{
    KIRQL CurrentIrql;

    unsigned short size;
    va_list args;
    UCHAR buffer[1024] = {0};

    va_start(args, format);

    CurrentIrql = KeGetCurrentIrql();
    if (CurrentIrql < DISPATCH_LEVEL)
    {
        KeRaiseIrqlToDpcLevel();
    }
    
    KeAcquireSpinLockAtDpcLevel(g_LogLock);

/*    RtlZeroMemory(&buffer, sizeof(buffer));*/
/*    vsnprintf((PUCHAR)&buffer, sizeof(buffer), "%d:", g_LogIndex);*/
/*    buffer[1023] = '\0';*/
/*    size = strlen(buffer);*/

/*    InsertLogEntry(buffer, size);*/
/*    */

    RtlZeroMemory(&buffer, sizeof(buffer));
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


