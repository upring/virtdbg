#ifndef VIRTDBG_LOG_H
#define VIRTDBG_LOG_H

#include <ntddk.h>
#include "snprintf.h"
#include <stdarg.h>

#define LOGBUFFER_SIZE 0x10000

typedef struct _LOGENTRY
{
    ULONG32 Id;
    ULONG32 Size;
    PVOID Data;
} LOGENTRY, *PLOGENTRY;

PVOID InitLog();
VOID Log(char *format, ...);


#endif
