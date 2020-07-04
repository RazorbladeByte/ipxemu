Warcraft II BNE `Waiting for response' bugfix
=============================================

If you try to use IPX (or emulated IPX over IPv4 via ipxemu) to play a game of
Warcraft II BNE, the game may not get past the `Waiting for response' message
when joining a game.

How to use
==========

1) Update Warcraft II BNE to version 2.02 (both 2.0.2.0 and 2.0.2.1 are okay).
2) Place the `warcraft_2_bne_bugfix.exe' program in the Warcraft II BNE game
   directory (i.e., the directory where `Warcraft II BNE.exe' can be found).
3) Run `warcraft_2_bne_bugfix.exe' from that location.
4) The program should display the following message on the screen:
   "`Warcraft II BNE.exe' successfully patched. Rerun the patch to restore it."
5) Repeat steps 1 to 4 on every computer participating in the network game.

Note that, if the problem still occurs after these steps, it may well be that
another problem (than the one fixed by this patch) is the cause of not getting
past the `Waiting for response' message.

Details
=======

The problem is caused by a design flaw (or bug) in Warcraft II BNE. Though, it
happens only under particular circumstances, like when using ipxemu. It also
happens when one of the computers that participates in the game has multiple
network interfaces installed, where the secondary network interface (as seen by
the operating system) is the one that is connected to the other players
(instead of the primary network interface).

For communication between two or more computers on the network, Warcraft II BNE
embeds the address that a computer can be reached on in some of the messages
that are sent. Receivers are expected to send replies to that address. This is
a flaw (even more so because the game doesn't always embed the correct
reply address into the message). It is unnecessary to embed such information in
a message, because receivers already know from whom they received a message,
even if that information isn't encoded in the message, since such information
is returned by the operating system's recvfrom() function.

The bugfix changes and adds code to the `Warcraft II BNE.exe' executable
(although it doesn't have to change the size of the file for this) to correct
messages after they have been received. If a message is received that contains
a reply address, it will be corrected. The reply address in the message is
overwritten with the correct address. Since a message also contains a checksum,
it is updated after modifying the message (although if the checksum was
incorrect to begin with, the message is not modified).
