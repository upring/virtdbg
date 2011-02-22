#    This file is part of Virtdbg
#    Copyright (C) 2010-2011 Damien AUMAITRE
#
#    Licence is GPLv3, see LICENCE.txt in the top-level directory

require 'metasm'
require 'metasm/dynldr'

include Metasm


module VirtDbg

    class WindowsAPI < DynLdr
        new_api_c File.read(File.join(VIRTDBGDIR, "inc", "ntoskrnl.exe_F8E2A8B5C9B74BF4A6E4A48F18009994.h"))
    end

    class WinDbgAPI < DynLdr
        new_api_c File.read(File.join(VIRTDBGDIR, "inc", "wdbgexts.h"))
    end

    class System

        attr_accessor :mem, :ctypes
        def initialize(mem, info, ctypes)
            @mem = mem
            @kernel = info[:kernelbase]
            @ctypes = ctypes
        end

        def system_process
        end

        def processes
        end

        def modules
        end

    end

    class Process

        def initialize(system, address)
            @system = system
            @address = address
#             offset = 0 # ??
#             @cr3 = system.mem.read_dword(address+offset)
            @eproc = system.ctypes.decode_c_struct("EPROCESS", mem, address)
        end

        def cr3
            @eproc.Pcb.DirectoryTableBase
        end

        def next
            address = @eproc.ActiveProcessLinks.Flink
            offset = offsetof("EPROCESS", "ActiveProcessLinks")
            self.new(@system, address-offset)
        end

    end

    class Module

    end

end

