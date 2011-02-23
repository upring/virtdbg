#    This file is part of Virtdbg
#    Copyright (C) 2010-2011 Damien AUMAITRE
#
#    Licence is GPLv3, see LICENCE.txt in the top-level directory

require 'metasm'
require 'metasm/dynldr'
require 'iconv'

class String
    def utf16_to_iso
        converter = Iconv.new('ISO-8859-1//IGNORE//TRANSLIT', 'UTF-16')
        converter.iconv(self)
    end
end

include Metasm


module VirtDbg

#     class WindowsAPI < DynLdr
#         new_api_c File.read(File.join(VIRTDBGDIR, "inc", "ntoskrnl.exe_F8E2A8B5C9B74BF4A6E4A48F18009994.h"))
#     end

#     class WinDbgAPI < DynLdr
#         new_api_c File.read(File.join(VIRTDBGDIR, "inc", "wdbgexts.h"))
#     end

    class System

        attr_accessor :mem, :ctypes
        def initialize(mem, addr)
            @mem = mem
            @kernelbase = addr

            puts "kernel @ 0x%x" % addr
            
            pe = LoadedPE.load @mem[addr, 0x1000_0000]
            pe.load_address = addr
            pe.decode_header
            pe.decode_debug
            @kernel = pe

            filename = pe.debug[0].data.pdbfilename
            guid = pe.debug[0].data.guid
            guid = '%x%x%x%x%x' % guid.unpack('VvvNN')
            age = pe.debug[0].data.age
            path = "#{filename}_#{guid}#{age}.h"
            @wdbgexts = Class.new(DynLdr)
            @wdbgexts.cp.llp64
            puts "loading wdbgexts header..."
            @wdbgexts.new_api_c File.read(File.join(VIRTDBGDIR, "inc", "wdbgexts.h"))
            @ctypes = Class.new(DynLdr)
            @ctypes.cp.llp64
            puts "loading #{path} header..."
            @ctypes.new_api_c File.read(File.join(VIRTDBGDIR, "inc", path))
            offset = 0x1e9070 # FIXME export this in hypervisor find KDBG sig
            @debugdata = @wdbgexts.decode_c_struct("KDDEBUGGER_DATA64", @mem, addr+offset)
        end

        def offsetof(structname, fieldname)
            st = @ctypes.cp.find_c_struct(structname)
            st.offsetof(nil, fieldname)
        end

        def decode_c_ptr(addr)
            @ctypes.decode_c_ary('void*', 1, @mem, addr)
        end

        def processes
            addr = decode_c_ptr(@debugdata.PsActiveProcessHead)[0]
            offset = offsetof("EPROCESS", "ActiveProcessLinks")
            first = Process.new(self, addr-offset)
            current = first
            while 42
                n = current.next
                break if n.address == first.address
                yield current
                current = n
            end
        end

        def modules
            addr = decode_c_ptr(@debugdata.PsLoadedModuleList)[0]
            first = Module.new(self, addr)
            current = first
            while 42 
                n = current.next
                break if n.address == first.address
                yield current
                current = n
            end
        end

    end

    class Process
        
        attr_accessor :address

        def initialize(system, address)
            @system = system
            @address = address
            @offset = system.offsetof("EPROCESS", "ActiveProcessLinks")
            @eproc = system.ctypes.decode_c_struct("EPROCESS", system.mem, address)
            puts @eproc.to_s
        end

        def cr3
            @eproc.Pcb.DirectoryTableBase
        end

        def pid
            @eproc.UniqueProcessId
        end

        def name
            @eproc.ImageFileName.to_array.pack('C*').strip
        end

        def processlinks
            @eproc.ActiveProcessLinks
        end

        def next
            address = @eproc.ActiveProcessLinks.Flink
            puts "address=%x" % address
            puts "offset=%x" % @offset
            self.class.new(@system, address-@offset)
        end

    end

    class Module
 
        attr_accessor :address

        def initialize(system, address)
            @system = system
            @address = address
            @entry = system.ctypes.decode_c_struct("LDR_DATA_TABLE_ENTRY", system.mem, address)
            puts @entry.to_s
        end

        def next
            addr = @entry.InLoadOrderLinks.Flink
            self.class.new(@system, addr)
        end

        def fullname
            ptr = @entry.FullDllName.Buffer
            len = @entry.FullDllName.Length
            fullname = @system.mem[ptr,len]
            fullname.utf16_to_iso
        end

        def name
            ptr = @entry.BaseDllName.Buffer
            len = @entry.BaseDllName.Length
            name = @system.mem[ptr,len]
            name.utf16_to_iso
        end

        def base
            base = @entry.DllBase
            base
        end

        def size
            size = @entry.SizeOfImage
            size
        end

        def entrypoint
            entrypoint = @entry.EntryPoint
            entrypoint
        end

    end

end

