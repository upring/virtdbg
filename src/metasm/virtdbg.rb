require 'metasm'
require 'metasm/dynldr'

include Metasm

# ripped from metasm/misc
class IO
    def hexdump(ctx={})
        ctx[:noend] = true
        while buf = read(512) and not buf.empty?
            buf.hexdump(ctx)
        end
        ctx.delete :noend
        ''.hexdump(ctx)
    end
end

class String
    def hexdump(ctx={})
        fmt = ctx[:fmt] ||= ['c', 'd', 'a']
        ctx[:pos] ||= 0
        ctx[:linelen] ||= 16
        scan(/.{1,#{ctx[:linelen]}}/m) { |s|
            if s != ctx[:lastline]
                ctx[:lastdup] = false
                print '%04x  ' % ctx[:pos]
                print s.unpack('C*').map { |b| '%02x' % b }.join(' ').ljust(3*16-1) + '  ' if fmt.include? 'c'
                print s.unpack('v*').map { |b| '%04x' % b }.join(' ').ljust(5*8-1)  + '  ' if fmt.include? 'w'
                print s.unpack('L*').map { |b| '%08x' % b }.join(' ').ljust(9*4-1)  + '  ' if fmt.include? 'd'
                print s.tr("\0-\x1f\x7f-\xff", '.') if fmt.include? 'a'
                puts
            elsif not ctx[:lastdup]
                ctx[:lastdup] = true
                puts '*'
            end
            ctx[:lastline] = s
            ctx[:pos] += s.length
        }
        puts '%04x' % ctx[:pos] if not ctx[:noend]
    end
end


class Forensic1394 < DynLdr
    new_api_c File.read("forensic1394.h"), "libforensic1394.so"
end

def ptr_size
    return 1.size
end

class Bus
    def initialize
        @bus_ptr = Forensic1394.forensic1394_alloc()
#         ObjectSpace.define_finalizer(self, self.class.finalize(@bus_ptr))
    end

    def self.finalize(bus_ptr)
        proc {Forensic1394.forensic1394_destroy(bus_ptr)}
    end

    def enable_sbp2
        Forensic1394.forensic1394_enable_sbp2(@bus_ptr)
    end

    def devices
        # Query the list of devices attached to the system
        ndev_ptr = (0.chr)*ptr_size()
        devlist = Forensic1394.forensic1394_get_devices(@bus_ptr, ndev_ptr, 0)
        ndev_value = ndev_ptr.unpack('Q').first
        if ndev_value < 0
            puts "error: can't get devices"
            return nil
        end
        devices = []
        ndev_value.times {|i| 
            dev_ptr = Forensic1394.memory_read_int(devlist+i*8)
            devices << Device.new(self, dev_ptr)
        }
        devices
    end
end

class Device

    attr_accessor :nodeid, :guid, :product_name, :product_id, :vendor_name, :vendor_id, :request_size, :csr

    def initialize(bus, dev_ptr)
        @bus = bus
        @dev_ptr = dev_ptr

        @nodeid = Forensic1394.forensic1394_get_device_nodeid(@dev_ptr)
        @guid = Forensic1394.forensic1394_get_device_guid(@dev_ptr)
        @product_name = Forensic1394.forensic1394_get_device_product_name(@dev_ptr)
        @product_name = Forensic1394.memory_read_strz(@product_name)
        @product_id = Forensic1394.forensic1394_get_device_product_id(@dev_ptr)
        @vendor_name = Forensic1394.forensic1394_get_device_vendor_name(@dev_ptr)
        @vendor_name = Forensic1394.memory_read_strz(@vendor_name)
        @vendor_id = Forensic1394.forensic1394_get_device_vendor_id(@dev_ptr)
        @request_size = Forensic1394.forensic1394_get_device_request_size(@dev_ptr)

        @csr = (0.chr)*1024
        Forensic1394.forensic1394_get_device_csr(@dev_ptr, @csr)
#         ObjectSpace.define_finalizer(self, self.class.finalize(@dev_ptr))
    end

    def open
        Forensic1394.forensic1394_open_device(@dev_ptr)
    end

    def close
        Forensic1394.forensic1394_close_device(@dev_ptr)
    end

    def internal_read(address, size)
        buf = (0.chr)*size
        Forensic1394.forensic1394_read_device(@dev_ptr, address, size, buf)
        buf
    end

    def internal_read_v(req)
        buffers = []
        creq_size = Forensic1394.alloc_c_struct("forensic1394_req").length

        creq = req.map {|addr, size|
            creq = Forensic1394.alloc_c_struct("forensic1394_req")
            creq.addr = addr
            creq.len = size
            buf = (0.chr)*size
            buffers << buf
            creq.buf = buf
            creq
        }

        ptr = tmp = Forensic1394.memory_alloc(req.size*creq_size)
        creq.each { |s| Forensic1394.memory_write(tmp, s.str) ; tmp += s.length }
        Forensic1394.forensic1394_read_device_v(@dev_ptr, ptr, req.size)
        buffers
    end

    def read(address, size)
        #FIXME handle read requests > request_size
    end


    def internal_write(address, data)
        Forensic1394.forensic1394_write_device(@dev_ptr, address, data.size, data)
    end

    def internal_write_v(req)
        creq_size = Forensic1394.alloc_c_struct("forensic1394_req").length
        creq = req.map {|addr, data|
            creq = Forensic1394.alloc_c_struct("forensic1394_req")
            creq.addr = addr
            creq.buf = data
            creq.len = data.size
            creq
        }
        ptr = tmp = Forensic1394.memory_alloc(req.size*creq_size)
        creq.each { |s| Forensic1394.memory_write(tmp, s.str) ; tmp += s.length }
        Forensic1394.forensic1394_write_device_v(@dev_ptr, ptr, req.size)
    end

    def write(address, data)
        #FIXME handle write requests > request_size
    end

    def self.finalize(dev_ptr)
        proc {Forensic1394.forensic1394_destroy(dev_ptr)}
    end
end

class FireWireMem < VirtualString
    def initialize(device, addr=0, length=nil)
        @device = device
        length ||= 1<<32
        super(addr, length)
        @pagecache_len = 128
        @pagelength = @device.request_size
    end

    def dup(addr=@addr_start, len=@length)
        self.class.new(@device, addr, len)
    end

    def rewrite_at(addr, data)
#         puts "1394: rewrite @ #{addr.to_s(16)} #{data.length.to_s(16)} bytes"
        @device.internal_write(addr, data)
    end

    def get_page(addr, len=@pagelength)
#         puts "1394: get page @ #{addr.to_s(16)}, #{len} bytes"
        buf = @device.internal_read(addr, len)
        buf
    end

    def close
        @dev.close
    end

    def hexdump(addr, size)
        @device.internal_read(addr, size).hexdump(:fmt => ['c','a'], :noend => true)
    end
end

def init_1394(device)
    bus = Bus.new()
    bus.enable_sbp2
    puts "waiting for dma access..."
    sleep 5
    devices = bus.devices
    dev = devices[device]
    dev.open
    mem = FireWireMem.new(dev)
    puts "testing physical memory access..."
    puts mem.hexdump(0x8000, 0X100)
    mem
end

class VirtDbgAPI < DynLdr
    new_api_c File.read("virtdbg.h")
end

def calc_checksum(data) 
    data.unpack('C*').inject(0) { |sum, byte| sum+byte } 
end

class VirtDbgPacket
    attr_accessor :header, :data1, :data2
    def initialize
        @header = VirtDbgAPI.alloc_c_struct("PACKET_HEADER")
        @header.magic = VirtDbgAPI::PACKET_MAGIC
        @data1 = nil
        @data2 = nil
    end

    def data
        data = @data1 ? @data1.str[@data1.stroff, @data1.length] : ""
        if @data2.kind_of? String
            data << @data2
        elsif @data2
            data << @data2.str[@data2.stroff, @data2.length]
        end
        data
    end

    def encode
        fixup
        raw = @header.str[@header.stroff, @header.length]
        raw << data
        raw
    end

    def to_s
        puts @header.to_s
        puts @data1.to_s if @data1
        puts @data2.to_s if @data2 and not @data2.kind_of? String
    end

    def fixup
        @header.checksum = calc_checksum(data)
        @header.size = (@data1 ? @data1.length : 0) + (@data2 ? @data2.length : 0)
    end
end

class BreakinPacket < VirtDbgPacket
    def initialize(cr3=0)
        super()
        @header.type = VirtDbgAPI::PACKET_TYPE_BREAKIN
        @data1 = VirtDbgAPI.alloc_c_struct("BREAKIN_PACKET")
        @data1.cr3 = cr3
    end
end

class ResetPacket < VirtDbgPacket
    def initialize
        super()
        @header.type = VirtDbgAPI::PACKET_TYPE_RESET
    end
end

class AckPacket < VirtDbgPacket
    def initialize
        super()
        @header.type = VirtDbgAPI::PACKET_TYPE_ACK
    end
end


class ContinuePacket < VirtDbgPacket
    def initialize(status=0)
        super()
        @header.type = VirtDbgAPI::PACKET_TYPE_CONTINUE
        @data1 = VirtDbgAPI.alloc_c_struct("CONTINUE_PACKET")
        @data1.status = status
    end
end

class ManipulateStatePacket < VirtDbgPacket
    def initialize
        super()
        @header.type = VirtDbgAPI::PACKET_TYPE_MANIPULATE_STATE
        @data1 = VirtDbgAPI.alloc_c_struct("MANIPULATE_STATE_PACKET")
    end

    def error
        @data1.error
    end
end

class ReadVirtualMemoryPacket < ManipulateStatePacket
    def initialize(address=0, size=0)
        super()
        @data1.apinumber = VirtDbgAPI::READ_VIRTUAL_MEMORY_API
        @data1.readvirtualmemory.address = address
        @data1.readvirtualmemory.size = size
    end
end

class WriteVirtualMemoryPacket < ManipulateStatePacket
    def initialize(address=0, data="")
        super()
        @data1.apinumber = VirtDbgAPI::WRITE_VIRTUAL_MEMORY_API
        @data1.writevirtualmemory.address = address
        @data1.writevirtualmemory.size = data.size
        @data2 = data
    end
end

class GetContextPacket < ManipulateStatePacket
    def initialize
        super()
        @data1.apinumber = VirtDbgAPI::GET_CONTEXT_API
        @data2 = VirtDbgAPI.alloc_c_struct("DEBUG_CONTEXT")
    end
end

class SetContextPacket < ManipulateStatePacket
    def initialize
        super()
        @data1.apinumber = VirtDbgAPI::SET_CONTEXT_API
        @data2 = VirtDbgAPI.alloc_c_struct("DEBUG_CONTEXT")
    end
end

class StateChangePacket < VirtDbgPacket
    def initialize
        super()
        @header.type = VirtDbgAPI::PACKET_TYPE_STATE_CHANGE
        @data1 = VirtDbgAPI.alloc_c_struct("STATE_CHANGE_PACKET")
    end

    def exception
        @data1.exception
    end
end

PAGE_SIZE = 0x1000
MAX_PFN = 0x80000
# 7c000
MIN_PFN = 0

class VirtDbgImpl
    attr_accessor :mem, :area, :state, :clientid
    def initialize(mem)
        @mem = mem
        @area = nil
        @lastid = 0
        @clientid = 0
        @id = VirtDbgAPI::INITIAL_ID
        @attached = false
        @unexpected_packets = []
        @state = :running
    end

    def new_clientid
        rand(0x100000)
    end

    def setup
        result = find_control_area
        handshake
    end

    def send_area
        @area.recvarea.quadpart if @area
    end

    def recv_area
        @area.sendarea.quadpart if @area
    end

    def find_control_area
        puts "searching control area..."
        magic = [VirtDbgAPI::CONTROL_AREA_MAGIC1, 
            VirtDbgAPI::CONTROL_AREA_MAGIC2].pack("LL")

        pfn = MAX_PFN.downto(MIN_PFN).find {|i|
            header = @mem[i*0x1000, 8]
            header == magic }

        if not pfn
            puts "can't find control area, aborting"
            return false
        end

        control_area_paddr = pfn*PAGE_SIZE
        puts "found control area @ #{control_area_paddr.to_s(16)}"
        @area = VirtDbgAPI.decode_c_struct('VIRTDBG_CONTROL_AREA', 
                                          @mem, control_area_paddr)

#         @send_area = @area.recvarea.quadpart
#         @recv_area = @area.sendarea.quadpart
        puts "send_area @ #{self.send_area.to_s(16)}"
        puts "recv_area @ #{self.recv_area.to_s(16)}"
        true
    end

    def handshake
        @clientid = new_clientid
        @lastid = 0
        @area.clientid = @clientid
        while @area.serverid != @clientid
            @mem.invalidate
        end
        @attached = true
        puts "handshake done (client id 0x#{@clientid.to_s(16)})"
    end

    def dumplog
        @mem.invalidate
        @mem[@area.logbuffer.quadpart,2048]+@mem[@area.logbuffer.quadpart+2048,2048]
    end

    def send_packet_internal(packet)
        packet.header.clientid = @clientid
        packet.header.id = @id
        packet.fixup
#         puts "###sending###"
#         puts packet.to_s
        data = packet.encode
        @mem[self.send_area, data.length] = data
        @id += 1
        data.length
    end

    def send_packet(packet)
        return false if not @attached
        start = Time.now
        length = send_packet_internal(packet)
        while @area.lastclientid != packet.header.id
            @mem.invalidate
            return false if Time.now-start > 2.0
        end
        true 
    end

    def dispatch_packet(packet)
        @unexpected_packets << packet if packet
        puts "got an unexpected packet #{packet.inspect}" if packet
    end

    def recv_packet_with_type(type)
        packet = nil
        start = Time.now
        loop do
            packet = recv_packet
            break if packet.kind_of? type
            break if Time.now-start > 2.0
            dispatch_packet packet
        end
        packet
    end

    def recv_packet
        return if not @attached
        packet = nil
        @mem.invalidate
        packet = recv_packet_internal
        packet
    end

    def recv_packet_internal
        data = @mem[self.recv_area, VirtDbgAPI::HEADER_SIZE]
        header = VirtDbgAPI.decode_c_struct('PACKET_HEADER', data, 0)

        if header.magic != VirtDbgAPI::PACKET_MAGIC
#             puts "no magic number in header"
            return
        end

        if not (0..VirtDbgAPI::MAX_PACKET_SIZE).cover? header.size 
#             puts "packet too big"
            return
        end

        if header.id <= @lastid
#             puts "not a new packet"
            return
        end

        packet_size = VirtDbgAPI::HEADER_SIZE+header.size

        if header.size > 0
            body = @mem[self.recv_area+VirtDbgAPI::HEADER_SIZE, header.size]
            data << body

            sum = calc_checksum(body)
            if sum != header.checksum
                puts "bad checksum, expected #{sum.to_s(16)}, got #{header.checksum.to_s(16)}"
                return
            end
        end

        case header.type
        when VirtDbgAPI::PACKET_TYPE_RESET
            packet = ResetPacket.new
        when VirtDbgAPI::PACKET_TYPE_MANIPULATE_STATE
            data1 = VirtDbgAPI.decode_c_struct('MANIPULATE_STATE_PACKET', 
                                               data, VirtDbgAPI::HEADER_SIZE)
            case data1.apinumber
            when VirtDbgAPI::READ_VIRTUAL_MEMORY_API
                packet = ReadVirtualMemoryPacket.new
                offset = header.length+data1.length
                size = header.size-data1.length
#                 puts "offset=0x#{offset.to_s(16)}, size=0x#{size.to_s(16)}"
                data2 = data[offset, size]
                packet.data2 = data2

            when VirtDbgAPI::WRITE_VIRTUAL_MEMORY_API
                packet = WriteVirtualMemoryPacket.new
            when VirtDbgAPI::GET_CONTEXT_API
                packet = GetContextPacket.new
                offset = header.length+data1.length
                data2 = VirtDbgAPI.decode_c_struct("DEBUG_CONTEXT", 
                                            data, offset)
                packet.data2 = data2

            when VirtDbgAPI::SET_CONTEXT_API
                packet = SetContextPacket.new
            else
                puts "invalid api number"
                return
            end

            packet.data1 = data1

        when VirtDbgAPI::PACKET_TYPE_STATE_CHANGE
            data1 = VirtDbgAPI.decode_c_struct('STATE_CHANGE_PACKET',
                                               data,
                                               VirtDbgAPI::HEADER_SIZE)
            packet = StateChangePacket.new
            packet.data1 = data1

        when VirtDbgAPI::PACKET_TYPE_CONTINUE
            data1 = VirtDbgAPI.decode_c_struct('CONTINUE_PACKET',
                                               data,
                                               VirtDbgAPI::HEADER_SIZE)
            packet = ContinuePacket.new
            packet.data1 = data1

        else
            puts "invalid header type"
            return
        end

        packet.header = header
        @lastid = header.id
#         puts packet.to_s
#         puts data.hexdump

        @area.lastserverid = header.id
        packet
    end

    def breakin
        request = BreakinPacket.new
        send_packet request
        packet = recv_packet
        if packet and packet.kind_of? StateChangePacket
            @state = :stopped
        end
        puts "breakin, got #{packet.inspect}"
        packet
    end

    def continue
        request = ContinuePacket.new(VirtDbgAPI::CONTINUE_STATUS_CONTINUE)
        send_packet request
        @state = :running
    end

    def singlestep
        request = ContinuePacket.new(VirtDbgAPI::CONTINUE_STATUS_SINGLE_STEP)
        send_packet request
        packet = recv_packet
        if packet and packet.kind_of? StateChangePacket
            @state = :stopped
        end
        packet
    end

    def extract_context(response)
        context = {}
        context[:rax] = response.data2.rax
        context[:rbx] = response.data2.rbx
        context[:rcx] = response.data2.rcx
        context[:rdx] = response.data2.rdx
        context[:rsi] = response.data2.rsi
        context[:rdi] = response.data2.rdi
        context[:rbp] = response.data2.rbp
        context[:rsp] = response.data2.rsp
        context[:r8] = response.data2.r8
        context[:r9] = response.data2.r9
        context[:r10] = response.data2.r10
        context[:r11] = response.data2.r11
        context[:r12] = response.data2.r12
        context[:r13] = response.data2.r13
        context[:r14] = response.data2.r14
        context[:r15] = response.data2.r15
        context[:rip] = response.data2.rip
        context[:rflags] = response.data2.rflags
        context[:cr0] = response.data2.cr0
        context[:cr3] = response.data2.cr3
        context[:cr4] = response.data2.cr4
        context[:cr8] = response.data2.cr8
        context[:dr0] = response.data2.dr0
        context[:dr1] = response.data2.dr1
        context[:dr2] = response.data2.dr2
        context[:dr3] = response.data2.dr3
        context[:dr6] = response.data2.dr6
        context[:dr7] = response.data2.dr7
        context
    end

    def fill_context(request, context)
        request.data2.rax = context[:rax] if context[:rax]
        request.data2.rbx = context[:rbx] if context[:rbx]
        request.data2.rcx = context[:rcx] if context[:rcx]
        request.data2.rdx = context[:rdx] if context[:rdx]
        request.data2.rsi = context[:rsi] if context[:rsi]
        request.data2.rdi = context[:rdi] if context[:rdi]
        request.data2.rbp = context[:rbp] if context[:rbp]
        request.data2.rsp = context[:rsp] if context[:rsp]
        request.data2.r8 = context[:r8] if context[:r8]
        request.data2.r9 = context[:r9] if context[:r9]
        request.data2.r10 = context[:r10] if context[:r10]
        request.data2.r11 = context[:r11] if context[:r11]
        request.data2.r12 = context[:r12] if context[:r12]
        request.data2.r13 = context[:r13] if context[:r13]
        request.data2.r14 = context[:r14] if context[:r14]
        request.data2.r15 = context[:r15] if context[:r15]
        request.data2.rip = context[:rip] if context[:rip]
        request.data2.rflags = context[:rflags] if context[:rflags]
        request.data2.cr0 = context[:cr0] if context[:cr0]
        request.data2.cr3 = context[:cr3] if context[:cr3]
        request.data2.cr4 = context[:cr4] if context[:cr4]
        request.data2.cr8 = context[:cr8] if context[:cr8]
        request.data2.dr0 = context[:dr0] if context[:dr0]
        request.data2.dr1 = context[:dr1] if context[:dr1]
        request.data2.dr2 = context[:dr2] if context[:dr2]
        request.data2.dr3 = context[:dr3] if context[:dr3]
        request.data2.dr6 = context[:dr6] if context[:dr6]
        request.data2.dr7 = context[:dr7] if context[:dr7]
        request
    end

    def get_context
        return if @state == :running
        request = GetContextPacket.new
        send_packet request
        response = recv_packet_with_type GetContextPacket
        if response and response.error == 0
            return extract_context(response)
        else
            return nil
        end
    end

    def set_context(context)
        return if @state == :running
        request = SetContextPacket.new
        fill_context request, context
        send_packet request
        response = recv_packet_with_type SetContextPacket
    end

    def read_virtual_memory(address, size)
        return if @state == :running
        request = ReadVirtualMemoryPacket.new(address, size)
        send_packet request
        response = recv_packet_with_type ReadVirtualMemoryPacket
        if response and response.error == 0
            return response.data2
        else
            return nil
        end
    end

    def write_virtual_memory(address, data)
        return if @state == :running
        request = WriteVirtualMemoryPacket.new(address, data)
        send_packet request
        response = recv_packet_with_type WriteVirtualMemoryPacket
    end

end


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
            return 0xbad if not context
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

    def ui_command_setup(ui)
        ui.new_command('idt', 'dump idt') { |arg| dump_idt arg } 
        ui.new_command('processes', 'list processes') { |arg| list_processes arg } 
        ui.new_command('dumplog', 'dump virtdbg log') { |arg| dumplog arg } 
        ui.new_command('handshake', 'negociate a client id with virtdbg') { |arg| handshake arg } 
        ui.new_command('loadkernel', 'load kernel symbols') { |arg| loadkernel arg } 
    end
 
end

$device = 0
$mem = init_1394($device)
$impl = VirtDbgImpl.new($mem)
$impl.setup
$dbg = VirtDbg.new($impl)
w = Gui::DbgWindow.new($dbg, 'virtdbg')
# w.dbg_widget.mem.focus_addr $impl.area.kernelbase
# $dbg.loadsyms $impl.area.kernelbase
Gui.main

# ep = 0x8000
# d = Shellcode.decode(ram, Ia32.new(64)).init_disassembler()
# d.disassemble_fast_deep(ep)
# w = Metasm::Gui::DasmWindow.new('Virtdbg').display(d, [])
# w.focus_addr ep, :hex
# d.load_plugin('hl_opcode')
# Gui.main

