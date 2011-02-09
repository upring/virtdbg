require 'metasm'
require 'metasm/dynldr'

include Metasm

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
        puts "ndev_value #{ndev_value}"
        if ndev_value < 0

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
        buf = (0.chr)*size

        buf
    end


    def self.finalize(dev_ptr)
        proc {Forensic1394.forensic1394_destroy(dev_ptr)}
    end



end

$bus = Bus.new()
$bus.enable_sbp2

puts "sleeping 5 secs"
sleep 5 

$devices = $bus.devices
$dev = $devices[0]
$dev.open

puts $dev.csr.hexdump(:fmt => ['c','a'], :noend => true)
puts $dev.internal_read(0x8000, 0x100).hexdump(:fmt => ['c','a'], :noend => true)
reqs = [[0x8000, 0x100], [0x9000, 0x100]]
$dev.internal_read_v(reqs).each {|r| puts r.hexdump(:fmt => ['c','a'], :noend => true)}

class FireWireRAM < VirtualString
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
        puts "will rewrite (someday) @ #{addr.to_s(16)} #{length} bytes"
    end

    def get_page(addr, len=@pagelength)
        puts "get page @ #{addr.to_s(16)}, #{len} bytes"
        buf = @device.internal_read(addr, len)
        buf

    end
end

# gui.focus_addr(0x1234, :hex) apres avoir cree le gui pour afficher l'hexa
# struct = Class.new(SerialStruct) ; struct.dword :field1 ; ... ;

ram = FireWireRAM.new($dev)
ep = 0x8000
d = Shellcode.decode(ram, Ia32.new(64)).init_disassembler()
# d.disassemble_fast_deep(ep)
w = Metasm::Gui::DasmWindow.new('Virtdbg').display(d, [])
w.focus_addr ep :hex
d.load_plugin('hl_opcode')
Gui.main

class MyFormat < ExeFormat
    def initialize(str)
        @encoded = EncodedData.new(str)
        @endianness = :little
    end

    def decode_byte( edata = @encoded) ; edata.decode_imm(:u8,  @endianness) end
    def decode_half( edata = @encoded) ; edata.decode_imm(:u16, @endianness) end
    def decode_word( edata = @encoded) ; edata.decode_imm(:u32, @endianness) end
    def decode_word64(edata = @encoded) ; edata.decode_imm(:u64, @endianness) end

end

class DBGKD_GET_VERSION64 < SerialStruct
    new_int_field :word64
    word :MajorVersion
    word :MinorVersion
    byte :ProtocolVersion
    byte :KdSecondaryVersion
    word :Flags
    word :MachineType
    byte :MaxPacketType
    byte :MaxStateChange
    byte :MaxManipulate
    byte :Simulation
    word :Unused
    word64 :KernBase
    word64 :PsLoadedModuleList
    word64 :DebuggerDataList
end

version = "bla"
toto = MyFormat.new(version)
$t = DBGKD_GET_VERSION64.decode(toto)

class VirtDbgAPI

end

class VirtDbg < Debugger
    
    def do_continue(*a)
	end

	def do_singlestep(*a)
	end

	def do_check_target
	end

	def do_wait_target
	end
end


