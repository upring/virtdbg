#    This file is part of Virtdbg
#    Copyright (C) 2010-2011 Damien AUMAITRE
#
#    Licence is GPLv3, see LICENCE.txt in the top-level directory

require 'metasm'
require 'metasm/dynldr'

include Metasm

module VirtDbg

    class VirtDbgMem < VirtualString
        def initialize(impl, addr=0, length=nil)
            @impl = impl
            length ||= 1<<64
            super(addr, length)
            @pagecache_len = 128
            @pagelength = 0x400
        end

        def dup(addr=@addr_start, len=@length)
            self.class.new(@impl, addr, len)
        end

        def rewrite_at(addr, data)
    #         puts "virtdbgmem: rewrite @ #{addr.to_s(16)} #{data.length.to_s(16)} bytes"
            @impl.write_virtual_memory(addr, data)
        end

        def get_page(addr, len=@pagelength)
    #         puts "virtdbgmem: get page @ #{addr.to_s(16)}, #{len} bytes"
            buf = @impl.read_virtual_memory(addr, len)
            buf
        end

        def hexdump(addr, size)
            get_page(addr, size).hexdump(:fmt => ['c','a'], :noend => true)
        end
    end

    class VirtDbg < Debugger
        def initialize(impl)
            @impl = impl
            @cpu = X86_64.new
            @memory = VirtDbgMem.new(impl)
            @context = {}
            super()
            @info = nil
        end

        def state
            @impl.state
        end

        def state=(state)
            @impl.state = state
        end

        def get_reg_value(reg)
            if @context.empty?
                context = @impl.get_context
                return 0 if not context
                @context = context
            end
                
            @context[reg]
        end

        def set_reg_value(reg, val)
            @context[reg] = val
        end

        def invalidate
            if not @context.empty?
                @impl.set_context @context
            end
            @memory.invalidate
            @context.clear
            super()
        end

        def do_continue(*a)
            invalidate
            @impl.continue
            @info = nil
        end

        def do_singlestep(*a)
            invalidate
            @impl.singlestep
            @info = "singlestep"
        end

        def break
            @impl.breakin
        end

        # non blocking
        def do_check_target
            invalidate
            packet = @impl.recv_packet
            if packet and packet.kind_of? StateChangePacket
                @impl.state = :stopped
                @info = "got exception #{packet.exception}"
            else
                puts "do check, got #{packet.inspect}" if packet
            end
        end

        # blocking 
        def do_wait_target
            loop do
                do_check_target
                break if @impl.state == :stopped
            end
        end
      
        def bpx(addr, *a)
            hwbp(addr, :x, 1, *a) 
        end

        def need_stepover(di)
            di and ((di.instruction.prefix and di.instruction.prefix[:rep]) or di.opcode.props[:saveip])
        end

        def enable_bp(addr)
            return if not b = @breakpoint[addr]
            case b.type
            when :hw
                @cpu.dbg_enable_bp(self, addr, b)
            end
            b.state = :active
        end

        def disable_bp(addr)
            return if not b = @breakpoint[addr]
            @cpu.dbg_disable_bp(self, addr, b)
            b.state = :inactive
        end

        def dump_idt(arg=nil)
            puts "dumping idt ! na kidding !"
        end

        def list_processes(arg=nil)
            puts "listing processes ! soon..."
        end

        def dumplog(arg=nil)
            puts @impl.dumplog
        end

        def handshake(arg=nil)
            puts @impl.handshake
        end

        def loadkernel(arg=nil)
            gui.parent_widget.mem.focus_addr @impl.area.kernelbase
            loadsyms @impl.area.kernelbase
        end

        def system(arg=nil)
        end

        def ui_command_setup(ui)
            ui.new_command('idt', 'dump idt') { |arg| dump_idt arg } 
            ui.new_command('processes', 'list processes') { |arg| list_processes arg } 
            ui.new_command('dumplog', 'dump virtdbg log') { |arg| dumplog arg } 
            ui.new_command('handshake', 'negociate a client id with virtdbg') { |arg| handshake arg } 
            ui.new_command('loadkernel', 'load kernel symbols') { |arg| loadkernel arg } 
        end
     
    end

end
