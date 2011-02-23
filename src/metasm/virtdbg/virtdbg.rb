#    This file is part of Virtdbg
#    Copyright (C) 2010-2011 Damien AUMAITRE
#
#    Licence is GPLv3, see LICENCE.txt in the top-level directory

require 'metasm'
require 'metasm/dynldr'

include Metasm

def calc_checksum(data) 
    data.unpack('C*').inject(0) { |sum, byte| sum+byte } 
end

module VirtDbg

    class VirtDbgAPI < DynLdr
        new_api_c File.read(File.join(VIRTDBGDIR, "inc", "virtdbg.h"))
    end

    class VirtDbgPacket
        attr_accessor :header, :data1, :data2
        def initialize
            @header = VirtDbgAPI.alloc_c_struct("PACKET_HEADER")
            @header.Magic = VirtDbgAPI::PACKET_MAGIC
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
            @header.Checksum = calc_checksum(data)
            @header.Size = (@data1 ? @data1.length : 0) + (@data2 ? @data2.length : 0)
        end
    end

    class BreakinPacket < VirtDbgPacket
        def initialize(cr3=0)
            super()
            @header.Type = VirtDbgAPI::PACKET_TYPE_BREAKIN
            @data1 = VirtDbgAPI.alloc_c_struct("BREAKIN_PACKET")
            @data1.Cr3 = cr3
        end
    end

    class ResetPacket < VirtDbgPacket
        def initialize
            super()
            @header.Type = VirtDbgAPI::PACKET_TYPE_RESET
        end
    end

    class AckPacket < VirtDbgPacket
        def initialize
            super()
            @header.Type = VirtDbgAPI::PACKET_TYPE_ACK
        end
    end

    class ContinuePacket < VirtDbgPacket
        def initialize(status=0)
            super()
            @header.Type = VirtDbgAPI::PACKET_TYPE_CONTINUE
            @data1 = VirtDbgAPI.alloc_c_struct("CONTINUE_PACKET")
            @data1.Status = status
        end
    end

    class ManipulateStatePacket < VirtDbgPacket
        def initialize
            super()
            @header.Type = VirtDbgAPI::PACKET_TYPE_MANIPULATE_STATE
            @data1 = VirtDbgAPI.alloc_c_struct("MANIPULATE_STATE_PACKET")
        end

        def error
            @data1.Error
        end
    end

    class ReadVirtualMemoryPacket < ManipulateStatePacket
        def initialize(address=0, size=0)
            super()
            @data1.ApiNumber = VirtDbgAPI::READ_VIRTUAL_MEMORY_API
            @data1.ReadVirtualMemory.Address = address
            @data1.ReadVirtualMemory.Size = size
        end
    end

    class WriteVirtualMemoryPacket < ManipulateStatePacket
        def initialize(address=0, data="")
            super()
            @data1.ApiNumber = VirtDbgAPI::WRITE_VIRTUAL_MEMORY_API
            @data1.WriteVirtualMemory.Address = address
            @data1.WriteVirtualMemory.Size = data.size
            @data2 = data
        end
    end

    class GetContextPacket < ManipulateStatePacket
        def initialize
            super()
            @data1.ApiNumber = VirtDbgAPI::GET_CONTEXT_API
            @data2 = VirtDbgAPI.alloc_c_struct("DEBUG_CONTEXT")
        end
    end

    class SetContextPacket < ManipulateStatePacket
        def initialize
            super()
            @data1.ApiNumber = VirtDbgAPI::SET_CONTEXT_API
            @data2 = VirtDbgAPI.alloc_c_struct("DEBUG_CONTEXT")
        end
    end

    class StateChangePacket < VirtDbgPacket
        def initialize
            super()
            @header.Type = VirtDbgAPI::PACKET_TYPE_STATE_CHANGE
            @data1 = VirtDbgAPI.alloc_c_struct("STATE_CHANGE_PACKET")
        end

        def exception
            @data1.Exception
        end
    end

    PAGE_SIZE = 0x1000
    MAX_PFN = 0x80000
    # 7c000
    MIN_PFN = 0

    class VirtDbgImpl
        attr_accessor :mem, :area, :state, :clientid
        def initialize(mem, max_pfn=MAX_PFN)
            @mem = mem
            @area = nil
            @lastid = 0
            @clientid = 0
            @id = VirtDbgAPI::INITIAL_ID
            @attached = false
            @unexpected_packets = []
            @state = :running
            @max_pfn = max_pfn
        end

        def new_clientid
            rand(0x100000)
        end

        def setup
            result = find_control_area
            if result
                handshake
                return true
            else
                return false
            end
        end

        def send_area
            @area.RecvArea.QuadPart if @area
        end

        def recv_area
            @area.SendArea.QuadPart if @area
        end

        def find_control_area
            puts "searching control area..."
            magic = [VirtDbgAPI::CONTROL_AREA_MAGIC1, 
                VirtDbgAPI::CONTROL_AREA_MAGIC2].pack("LL")

            pfn = @max_pfn.downto(0).find {|i|
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
            @area.ClientId = @clientid
            start = Time.now
            while @area.ServerId != @clientid
                @mem.invalidate
                if Time.now-start > 10.0
                    puts "can't make handshake in 10s, aborting"
                    return false
                end
            end
            @attached = true
            puts "handshake done (client id 0x#{@clientid.to_s(16)})"
            return true
        end

        def dumplog
            @mem.invalidate
            @mem[@area.LogBuffer.QuadPart,2048]+@mem[@area.LogBuffer.QuadPart+2048,2048]
        end

        def send_packet_internal(packet)
            packet.header.ClientId = @clientid
            packet.header.Id = @id
            packet.fixup
            data = packet.encode
            @mem[self.send_area, data.length] = data
            @id += 1
            data.length
        end

        def send_packet(packet)
            return false if not @attached
            start = Time.now
            length = send_packet_internal(packet)
            while @area.LastClientId != packet.header.Id
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

            if header.Magic != VirtDbgAPI::PACKET_MAGIC
    #             puts "no magic number in header"
                return
            end

            if not (0..VirtDbgAPI::MAX_PACKET_SIZE).cover? header.Size 
    #             puts "packet too big"
                return
            end

            if header.Id <= @lastid
    #             puts "not a new packet"
                return
            end

            packet_size = VirtDbgAPI::HEADER_SIZE+header.Size

            if header.Size > 0
                body = @mem[self.recv_area+VirtDbgAPI::HEADER_SIZE, header.Size]
                data << body

                sum = calc_checksum(body)
                if sum != header.Checksum
                    puts "bad checksum, expected #{sum.to_s(16)}, got #{header.Checksum.to_s(16)}"
                    return
                end
            end

            case header.Type
            when VirtDbgAPI::PACKET_TYPE_RESET
                packet = ResetPacket.new
            when VirtDbgAPI::PACKET_TYPE_MANIPULATE_STATE
                data1 = VirtDbgAPI.decode_c_struct('MANIPULATE_STATE_PACKET', 
                                                   data, VirtDbgAPI::HEADER_SIZE)
                case data1.ApiNumber
                when VirtDbgAPI::READ_VIRTUAL_MEMORY_API
                    packet = ReadVirtualMemoryPacket.new
                    offset = header.length+data1.length
                    size = header.Size-data1.length
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
            @lastid = header.Id
    #         puts packet.to_s
    #         puts data.hexdump

            @area.LastServerId = header.Id
            packet
        end

        def breakin
            request = BreakinPacket.new
            send_packet request
            packet = recv_packet
            if packet and packet.kind_of? StateChangePacket
                @state = :stopped
            end
            # FIXME need to handle this better
#             puts "breakin, got #{packet.inspect}"
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

end
