#    This file is part of Virtdbg
#    Copyright (C) 2010-2011 Damien AUMAITRE
#
#    Licence is GPLv3, see LICENCE.txt in the top-level directory


require 'metasm'
require 'virtdbg'
require 'optparse'

$VERBOSE = false

# parse arguments
opts = { :device => 0 }

OptionParser.new { |opt|
	opt.banner = 'Usage: virtdbg.rb [options]'
	opt.on('--list-devices', 'list FireWire devices') { opts[:list] = true }
	opt.on('--device [device]', 'select FireWire device') { |h| opts[:device] = h.to_i }
	opt.on('-v', '--verbose') { $VERBOSE = true }	# default
	opt.on('--debug') { $DEBUG = $VERBOSE = true }
}.parse!(ARGV)

def init_1394(device)
    bus = VirtDbg::Bus.new()
    bus.enable_sbp2
    puts "waiting for dma access..."
    sleep 5
    devices = bus.devices
    dev = devices[device]
    if not dev
        puts "error: requested device not found"
        return nil
    end
    dev.open
    mem = VirtDbg::FireWireMem.new(dev)
    puts "testing physical memory access..."
    puts mem.hexdump(0x8000, 0X100)
    mem
end

mem = init_1394(opts[:device])
impl = VirtDbg::VirtDbgImpl.new(mem)
impl.setup
dbg = VirtDbg::VirtDbg.new(impl)
w = Metasm::Gui::DbgWindow.new(dbg, 'virtdbg')
Metasm::Gui.main


