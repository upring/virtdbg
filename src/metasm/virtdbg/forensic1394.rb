#    This file is part of Virtdbg
#    Copyright (C) 2010-2011 Damien AUMAITRE
#
#    Licence is GPLv3, see LICENCE.txt in the top-level directory


require 'metasm'
require 'metasm/dynldr'

include Metasm

module VirtDbg

    class Forensic1394 < Metasm::DynLdr
        new_api_c File.read(File.join(VIRTDBGDIR, "inc", "forensic1394.h")),
            "libforensic1394.so"
    end

    # FIXME : need to handle 32 bits ruby

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
            ndev_ptr = (0.chr)*8
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

end
