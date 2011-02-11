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
        puts "1394: rewrite @ #{addr.to_s(16)} #{data.length.to_s(16)} bytes"
        @device.internal_write(addr, data)
    end

    def get_page(addr, len=@pagelength)
        puts "1394: get page @ #{addr.to_s(16)}, #{len} bytes"
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
end

FAKE_CONTEXT = {:rax => 1,
    :rbx => 2,
    :rcx => 3,
    :rdx => 4,
    :rsi => 5,
    :rdi => 6,
    :rbp => 7,
    :rsp => 8,
    :r8 => 9,
    :r9 => 10,
    :r10 => 11,
    :r11 => 12,
    :r12 => 12,
    :r13 => 13,
    :r14 => 14,
    :r15 => 15,
    :rip => 16,
    :rflags => 17}


PAGE_SIZE = 0x1000
MAX_PFN = 0x7c000
MIN_PFN = 0

class VirtDbgImpl
    attr_accessor :mem, :timeout
    def initialize(mem)
        @mem = mem
        @area = nil
        @lastid = 0
        @clientid = new_clientid
        @id = VirtDbgAPI::INITIAL_ID
        @timeout=0.1
        @attached = false
    end

    def new_clientid
        rand(0x100000)
    end

    def setup
        result = find_control_area
        handshake
        @attached = true if result
    end

    def send_area
        @area.sendarea.quadpart if @area
    end

    def recv_area
        @area.recvarea.quadpart if @area
    end

    def find_control_area
        puts "searching virtdbg control area..."
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

        @send_area = @area.sendarea.quadpart
        @recv_area = @area.recvarea.quadpart
        puts "send_area @ #{@send_area.to_s(16)}"
        puts "recv_area @ #{@recv_area.to_s(16)}"
        true
#         puts area.to_s
    end

    def handshake
        @area.clientid = @clientid
        while @area.serverid != @clientid
            @mem.invalidate
        end
    end

    def send_packet_internal(packet)
        packet.header.clientid = @clientid
        packet.header.id = @id
        packet.fixup
        data = packet.encode
        @mem[@send_area, data.length] = data
        @id += 1
        data.length
    end

    def send_packet(packet, timeout=@timeout)
        return false if not @attached
        length = send_packet_internal(packet)
        header = VirtDbgAPI.decode_c_struct('PACKET_HEADER', 
                                   @mem, @send_area+length)

        result = false
        delay = 0
        while delay < timeout
            @mem.invalidate
            delay += 0.05
            sleep(0.05)
            next if header.magic != VirtDbgAPI::PACKET_MAGIC
            next if header.clientid != @clientid
            next if header.size != 0
            next if header.type != VirtDbgAPI::PACKET_TYPE_ACK
            next if header.id != packet.id
            result = true
            break
        end 
        result
    end

    def recv_packet(timeout=@timeout)
        return if not @attached
        delay = 0
        packet = nil
        while delay < timeout
            @mem.invalidate
            delay += 0.05
            sleep(0.05)
            packet = recv_packet_internal
            break if packet
        end 
        packet
    end

    def dispatch_packet(packet)
        puts "got an unexpected packet #{packet.inspect}"
        @unexpected_packets << packet
    end

    def recv_packet_with_type(type, timeout=@timeout)
        packet = nil
        iterations = 0
        while not packet
            packet = recv_packet(timeout)
            iterations += 1
            break if packet.kind_of? type or iterations > 10
            dispatch_packet packet
        end
        packet
    end

    def recv_packet_internal
        data = @mem[@recv_area, VirtDbgAPI::HEADER_SIZE]
        header = VirtDbgAPI.decode_c_struct('PACKET_HEADER', data, 0)

        if header.magic != VirtDbgAPI::PACKET_MAGIC
            puts "no magic number in header"
            return
        end

        if not (0..VirtDbgAPI::MAX_PACKET_SIZE).cover? header.size 
            puts "packet too big"
            return
        end

        packet_size = VirtDbgAPI::HEADER_SIZE+header.size

        if header.size > 0
            body = @mem[@recv_area+VirtDbgAPI::HEADER_SIZE, header.size]
            data << body

            sum = calc_checksum(body)
            if sum != header.checksum
                puts "bad checksum, expected #{sum.to_s(16)}, got #{header.checksum.to_s(16)}"
                return
            end
        end

        if header.id <= @lastid
            puts "not a new packet"
            return
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
                size = data1.readvirtualmemory.size
                data2 = data[offset, size]

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

        ack = AckPacket.new
        ack.header.id = header.id
        ack.header.clientid = @clientid

        @mem[@recv_area+packet_size, VirtDbgAPI::HEADER_SIZE] = ack.encode
        packet
    end

    def breakin
        request = BreakinPacket.new
        send_packet request
    end

    def continue(status=0)
        request = ContinuePacket.new(status)
        send_packet request
    end

    def singlestep
        continue(status=VirtDbgAPI::CONTINUE_STATUS_SINGLE_STEP)
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
        request = GetContextPacket.new
        send_packet request
        response = recv_packet_with_type GetContextPacket
        return unless response
        (response.error == 0) ? extract_context(response) : nil
    end

    def set_context(context)
        request = SetContextPacket.new
        fill_context request, context
        send_packet request
        response = recv_packet_with_type SetContextPacket
    end

    def read_virtual_memory(address, size)
        request = ReadVirtualMemoryPacket.new(address, size)
        send_packet request
        response = recv_packet_with_type ReadVirtualMemoryPacket
        return unless response
        (response.error == 0) ? response.data2 : nil
    end

    def write_virtual_memory(address, data)
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
        puts "virtdbgmem: rewrite @ #{addr.to_s(16)} #{data.length.to_s(16)} bytes"
        @impl.write_virtual_memory(addr, data)
    end

    def get_page(addr, len=@pagelength)
        puts "virtdbgmem: get page @ #{addr.to_s(16)}, #{len} bytes"
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
        @state = :running
        @info = nil
    end

    def get_reg_value(reg)
        context = @impl.get_context if @context.empty?
        return 0xdeaddead if not context 
        @context = context
        @context[reg]
    end

    def set_reg_value(reg, val)
        return if @state != :stopped
        puts "set_reg_value #{reg} #{val}"
        @context[reg] = val
    end

    def invalidate
        @impl.set_context @context if not @context.empty?
        @context.clear
        super()
    end

    def do_continue(*a)
        puts "do_continue"
        return if @state != :stopped
		@state = :running
		@info = 'continue'
        @impl.continue
	end

	def do_singlestep(*a)
        puts "do_singlestep"
		return if @state != :stopped
		@state = :running
		@info = 'singlestep'
		@impl.singlestep
	end

    # non blocking
	def do_check_target
        invalidate
        packet = @impl.recv_packet_with_type StateChangePacket
        if packet
            @state = :stopped
            @info = "got exception #{packet.exception}"
        end
        @state = :stopped
	end

    # blocking 
	def do_wait_target
        puts "do_wait_target"
        loop do
            do_check_target
			break if @state == :dead
		end
	end

    def break
        puts "break"
        @impl.breakin
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

    def ui_command_setup(ui)
        ui.new_command('idt', 'dump idt') { |arg| ui.wrap_run { dump_idt arg } }
#         ui.keyboard_callback[:f6] = lambda { ui.wrap_run { syscall } }

        ui.new_command('processes', 'list processes') { |arg| ui.wrap_run { list_processes arg} } 
    end
 
end

$device = 1
$mem = init_1394($device)
$impl = VirtDbgImpl.new($mem)
$impl.setup
$dbg = VirtDbg.new($impl)
w = Gui::DbgWindow.new($dbg, 'virtdbg')
Gui.main

# ep = 0x8000
# d = Shellcode.decode(ram, Ia32.new(64)).init_disassembler()
# d.disassemble_fast_deep(ep)
# w = Metasm::Gui::DasmWindow.new('Virtdbg').display(d, [])
# w.focus_addr ep, :hex
# d.load_plugin('hl_opcode')
# Gui.main

