ipxemu
IPX protocol emulator using UDP/IP
=======================================================================

ipxemu emulates IPX so that programs can use IPX, while actually using
UDP/IP. This way one can for example play old games that only support
IPX, without actually using IPX.

How to use
=======================================================================

To provide IPX emulation for a program, one must copy one or more of
the ipxemu DLLs (dynamic-link libraries) to the directory of the
program's executable. It is important that the program is linked
against (i.e., actually uses) the DLL for it to work.

For example, if one wants to provide IPX emulation for the game
`Red Alert 2', then one should copy the `wsock32.dll' library to the
directory containing the game's `game.exe' executable, as the
`game.exe' executable links against `wsock32.dll'.

See the `doc\games.html' document for information on which games were
tested with ipxemu and how to use ipxemu with them.

The `thipx32.dll' library uses UDP port 7460. The `wsock32.dll' library
also uses UDP, but the port used depends on the IPX socket number
specified by the program.

System requirements
=======================================================================

The following systems are supported:
    * All Windows versions after Windows NT4.
    * Windows NT4.
    * Windows 9x (95, 98, Me).
    * Or compatible (such as Wine).

On Windows 95, one must have the Winsock 2.0 update installed (which,
among others, installs `msvcrt.dll', `mswsock.dll', and `ws2_32.dll').
See http://support.microsoft.com/kb/182108 for more information.

Known limitations
=======================================================================

The IPv4 protocol is used for emulating the IPX protocol. Currently,
the newer IPv6 protocol is unsupported.

Contact information
=======================================================================

Visit the ipxemu homepage at one of the following URLs for contact
information:
    http://purl.org/net/ipxemu
    http://ipxemu.sourceforge.net/
    http://sourceforge.net/projects/ipxemu/
