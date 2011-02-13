#ifndef VIRTDBG_LOG_H
#define VIRTDBG_LOG_H

#include <ntddk.h>
#include "snprintf.h"
#include "mem.h"
#include <stdarg.h>

#define LOGBUFFER_SIZE 0x1000


PVOID InitLog();
VOID Log(char *format, ...);


#endif
