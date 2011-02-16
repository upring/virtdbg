// This file is part of Virtdbg
// Copyright (C) 2010-2011 Damien AUMAITRE

//  Licence is GPLv3, see LICENCE.txt in the top-level directory


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
