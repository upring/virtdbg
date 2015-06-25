The purpose of virtdbg is to implement a kernel debugger
using the hardware virtualization technology provided by Intel (VT-x).
This project is born because when it comes to Windows 7 x64, the available
kernel debuggers tend to be very limited.

We have WinDbg which is very good but need cooperation of the OS. We can't use
it in order to debugging protected parts of the operating system like PatchGuard
for example.

The other kernel debuggers are local debuggers like !SoftICE, Syser or HyperDbg.
I made the choice of not using a local debugger
because I find that they are difficult to extend and to script.

## Disclaimer ##

virtdbg is in very alpha state. So I decline all responsabilities if your
computer bluescreened ;) However I will be happy if you give it a try.
It is under heavy development so expect a lot of changes quickly.
