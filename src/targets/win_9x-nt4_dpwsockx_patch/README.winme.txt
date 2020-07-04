In Windows Me, one has to start Windows in safe mode to use the
`win_9x-nt4_dpwsockx_patch.exe' program, as otherwise Windows will restore the
original `dpwsockx.dll' shortly after the patch was applied. This happens
because of the system-file protection feature in Windows Me.

Normally one can press F8 at boot time to get a startup menu where one can
choose to start Windows in safe mode. If this doesn't work, then the next
paragraph should help one get Windows started in safe mode.

Fail-safe method of starting Windows in safe mode:
1. Click `Start', choose `Programs', choose `Accessories', and click
   `MS-DOS Prompt'.
2. Execute the following commands in the order listed. Press ENTER after
   entering each line:
       cd \
       attrib -h -r -s msdos.sys
       copy msdos.sys msdos.sys.bak
       echo BootMenu=1>> msdos.sys
       attrib +h +r +s msdos.sys
3. Restart the computer and choose `Safe mode' in the startup menu.
4. Run `win_9x-nt4_dpwsockx_patch.exe' and follow the instructions on the
   screen.
