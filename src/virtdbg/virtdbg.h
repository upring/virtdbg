// This file is part of Virtdbg
// Copyright (C) 2010-2011 Damien AUMAITRE

//  Licence is GPLv3, see LICENCE.txt in the top-level directory


#ifndef _VIRTDBG_MAIN_H
#define _VIRTDBG_MAIN_H

#include <ntddk.h>
#include "amd64.h"
#include "vmx.h"
#include "mem.h"
#include "debug.h"
#include "misc.h"
#include "protocol.h"

NTSTATUS VirtDbgStart(PVOID StartContext);
NTSTATUS InitControlArea();
NTSTATUS StartVirtualization(PVOID GuestRsp);
static PVOID FindNtoskrnlBase(PVOID Addr);

#endif

