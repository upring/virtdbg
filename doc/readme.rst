README
======

The purpose of Virtdbg is to implement a kernel debugger
using the hardware virtualization technology provided by Intel (VT-x).
This project is born because when it comes to Windows 7 x64, the available
kernel debuggers tend to be very limited.

We have WinDbg which is very good but need cooperation of the OS. We can't use
it in order to debugging protected parts of the operating system like PatchGuard
for example. Microsoft doesn't allow it.

The other kernel debuggers are local debuggers like SoftICE, Syser or HyperDbg
(which uses the same approach). I made the choice of not using a local debugger
because I find that they are difficult to extend and to script.

Disclaimer
----------

VirtDbg is in very alpha state. So I decline all responsabilities if your
computer bluescreened ;) However I will be happy if you give it a try.
It is under heavy development so expect a lot of changes quickly.

Features
--------

TBW

Dependencies
------------

- Microsoft WDK for compiling virtdbg driver.
- metasm (http://metasm.cr0.org) for the client side (gui and heavy treatments).
- libforensic1394 (https://freddie.witherden.org/tools/libforensic1394/) for handling DMA communications
- FireWire cable for communication between target and client.


Limitations
-----------

- The hypervisor is not currently signed so you need to boot in testsigning mode
  to load it or wait for the "dma loader".
- The "dma loader" is not present in the repository for the moment because
  I need to port some code in ruby. For the interested persons it allows to load
  the virtdbg driver directly with DMA access (no need to reboot and no need for
  a signed driver).
- Only support VT-x extension. For the persons using VT-d you need to disable it
  in the BIOS or the hypervisor won't load.
- You will need to run Linux or MacOSX to be able to control the hypervisor
  because of libforensic1394.


Known bugs
----------

- Sometimes a bluescreen happens when queuing DPCS. The bugcheck says
  "CLOCK_WATCHDOG_TIMEOUT (101)". I need to debug this...


Quickstart
----------

Building
~~~~~~~~

$ cd src/virtdbg
$ make


Usage
~~~~~

First you must load the driver into the targeted system. To do that you can use
the loader available in the src/loader directory. It is very basic but it gets
the job done.

$ loader.exe [path to virtdbg.sys]

Then you need to connect a FireWire cable between the machines.

Last you launch the client gui (which uses the metasm framework).

$ cd samples/ 
$ ruby virtdbg-ui.rb

The gui is very "softice"-like so it will be really familiar to some persons.

