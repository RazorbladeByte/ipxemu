This program patches `dpwsockx.dll' (in the system directory, usually
`%windir%\system') so that it loads `ipxemuw.dll' instead of `wsock32.dll'.

After patching the `dpwsockx.dll' library, one should manually copy the ipxemu
`wsock32.dll' library, rename it to `ipxemuw.dll', and put it in the same
directory as the game executable. Or, if one so desires, one can put
`ipxemuw.dll' in the system directory (the directory where `dpwsockx.dll'
resides); it won't cause problems as only the patched `dpwsockx.dll' will use
the `ipxemuw.dll' library.

The patch is needed to make games that use DirectPlay for IPX work on
Windows 9x and Windows NT4. Because when the DirectPlay IPX socket library
`dpwsockx.dll' is loaded, Windows 9x and Windows NT4 first look in the
directory of that library to find `wsock32.dll', instead of looking in the
directory of the caller process (the game) executable. Hence, instead of the
ipxemu `wsock32.dll' library, the system `wsock32.dll' library will be loaded.
