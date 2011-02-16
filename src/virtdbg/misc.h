// This file is part of Virtdbg
// Copyright (C) 2010-2011 Damien AUMAITRE

//  Licence is GPLv3, see LICENCE.txt in the top-level directory


#ifndef _VIRTDBG_MISC_H
#define _VIRTDBG_MISC_H

#include <ntddk.h>
#include "log.h"

//#define DbgLog(_args_) { DbgPrint("virtdbg[#%d][IRQL=0x%x](%s): ", KeGetCurrentProcessorNumber(), KeGetCurrentIrql(), __FUNCTION__); DbgPrint _args_; }
#define DbgLog(_args_) { Log("vmx[#%d][IRQL=0x%x](%s): ", KeGetCurrentProcessorNumber(), KeGetCurrentIrql(), __FUNCTION__); Log _args_; }


#endif

