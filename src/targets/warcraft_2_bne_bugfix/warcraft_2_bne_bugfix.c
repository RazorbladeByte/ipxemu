/*
Author: Jelle Geerts

Usage of the works is permitted provided that this instrument is
retained with the works, so that any entity that uses the works is
notified of this instrument.

DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
*/

#include "confirm/confirm.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define FILENAME         "Warcraft II BNE.exe"
#define FILENAME_VERSION "2.02 (both 2.0.2.0 and 2.0.2.1 are okay)"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct patch {
    size_t offset;
    size_t size;
    const unsigned char *original;
    const unsigned char *patch;
};

/* There's a slight difference in the Virtual Size of the .text section between
 * version 2.0.2.0 and 2.0.2.1. Hence we have to check for either, and apply a
 * different patch, such that we can also detect whether the file was already
 * patched, and restore the original instructions.
 */
static const unsigned char patch_text_section_virtual_size_original_2_0_2_0[] = {
    0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0xEE, 0xE2, 0x08, 0x00
};
static const unsigned char patch_text_section_virtual_size_patch_2_0_2_0[] = {
    0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0xE6, 0xE3, 0x08, 0x00
};
struct patch patch_text_section_virtual_size_2_0_2_0 = {
    -1,
    ARRAY_SIZE(patch_text_section_virtual_size_original_2_0_2_0),
    patch_text_section_virtual_size_original_2_0_2_0,
    patch_text_section_virtual_size_patch_2_0_2_0
};

static const unsigned char patch_text_section_virtual_size_original_2_0_2_1[] = {
    0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0x4E, 0xE3, 0x08, 0x00
};
static const unsigned char patch_text_section_virtual_size_patch_2_0_2_1[] = {
    0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0x46, 0xE4, 0x08, 0x00
};
struct patch patch_text_section_virtual_size_2_0_2_1 = {
    -1,
    ARRAY_SIZE(patch_text_section_virtual_size_original_2_0_2_1),
    patch_text_section_virtual_size_original_2_0_2_1,
    patch_text_section_virtual_size_patch_2_0_2_1
};

static const unsigned char patch_bugfix_call_0_original_2_0_2_0[] = {
    /* x86 pseudo-disassembly:
     *   test eax, eax
     *   jz fail
     *   cmp eax, -1
     *   jz fail
     *   mov cl, [esp+18]
     */
    0x85, 0xC0, 0x74, 0x50, 0x83, 0xF8, 0xFF, 0x74, 0x4B, 0x8A
};
static const unsigned char patch_bugfix_call_0_patch_2_0_2_0[] = {
    /* x86 pseudo-disassembly:
     *   CALL bugfix
     *   JMP bugfix_original_instructions_0
     */
    0xE8, 0xAA, 0x25, 0x03, 0x00, 0xE9, 0x61, 0x26, 0x03, 0x00
};
struct patch patch_bugfix_call_0_2_0_2_0 = {
    -1,
    ARRAY_SIZE(patch_bugfix_call_0_original_2_0_2_0),
    patch_bugfix_call_0_original_2_0_2_0,
    patch_bugfix_call_0_patch_2_0_2_0
};

static const unsigned char patch_bugfix_call_0_original_2_0_2_1[] = {
    /* x86 pseudo-disassembly:
     *   test eax, eax
     *   jz fail
     *   cmp eax, -1
     *   jz fail
     *   mov cl, [esp+18]
     */
    0x85, 0xC0, 0x74, 0x50, 0x83, 0xF8, 0xFF, 0x74, 0x4B, 0x8A
};
static const unsigned char patch_bugfix_call_0_patch_2_0_2_1[] = {
    /* x86 pseudo-disassembly:
     *   CALL bugfix
     *   JMP bugfix_original_instructions_0
     */
    0xE8, 0x0A, 0x26, 0x03, 0x00, 0xE9, 0xC1, 0x26, 0x03, 0x00
};
struct patch patch_bugfix_call_0_2_0_2_1 = {
    -1,
    ARRAY_SIZE(patch_bugfix_call_0_original_2_0_2_1),
    patch_bugfix_call_0_original_2_0_2_1,
    patch_bugfix_call_0_patch_2_0_2_1
};

static const unsigned char patch_bugfix_call_1_original_2_0_2_0[] = {
    /* x86 pseudo-disassembly:
     *   test eax, eax
     *   jz fail
     *   cmp eax, -1
     *   jz fail
     *   mov cl, [esp+18]
     */
    0x85, 0xC0, 0x74, 0x1D, 0x83, 0xF8, 0xFF, 0x74, 0x18, 0x8A
};
static const unsigned char patch_bugfix_call_1_patch_2_0_2_0[] = {
    /* x86 pseudo-disassembly:
     *   CALL bugfix
     *   JMP bugfix_original_instructions_1
     */
    0xE8, 0x1A, 0x25, 0x03, 0x00, 0xE9, 0xEB, 0x25, 0x03, 0x00
};
struct patch patch_bugfix_call_1_2_0_2_0 = {
    -1,
    ARRAY_SIZE(patch_bugfix_call_1_original_2_0_2_0),
    patch_bugfix_call_1_original_2_0_2_0,
    patch_bugfix_call_1_patch_2_0_2_0
};

static const unsigned char patch_bugfix_call_1_original_2_0_2_1[] = {
    /* x86 pseudo-disassembly:
     *   test eax, eax
     *   jz fail
     *   cmp eax, -1
     *   jz fail
     *   mov cl, [esp+18]
     */
    0x85, 0xC0, 0x74, 0x1D, 0x83, 0xF8, 0xFF, 0x74, 0x18, 0x8A
};
static const unsigned char patch_bugfix_call_1_patch_2_0_2_1[] = {
    /* x86 pseudo-disassembly:
     *   CALL bugfix
     *   JMP bugfix_original_instructions_1
     */
    0xE8, 0x7A, 0x25, 0x03, 0x00, 0xE9, 0x4B, 0x26, 0x03, 0x00
};
struct patch patch_bugfix_call_1_2_0_2_1 = {
    -1,
    ARRAY_SIZE(patch_bugfix_call_1_original_2_0_2_1),
    patch_bugfix_call_1_original_2_0_2_1,
    patch_bugfix_call_1_patch_2_0_2_1
};

static const unsigned char patch_bugfix_original_2_0_2_0[] = {
    /* x86 disassembly:
     *   fldpi
     *   fstp qword [ebp-8]
     *   wait
     *   leave
     *   ret
     *   <padding>
     */
    0xD9, 0xEB, 0xDD, 0x5D, 0xF8, 0x9B, 0xC9, 0xC3, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const unsigned char patch_bugfix_patch_2_0_2_0[] = {
    /* x86 disassembly:
     *
     *   For the most part, "patch_bugfix_patch_2_0_2_0" and
     *   "patch_bugfix_patch_2_0_2_1" are equal. See the comment for the
     *   "patch_bugfix_patch_2_0_2_1" variable to see the full x86 disassembly.
     *
     *   This is from the first part that differs:
     *   (Note that only the first instruction, at 0048F38E, differs.)
     *
     *   0048F38E  |.  8B0D 1CE24A00    mov     ecx, dword ptr ds:[4AE21C]      ; Condition from the game's own checksum routine.
     *   0048F394  |.  C1EA 10          shr     edx, 10
     *   0048F397  |.  31DA             xor     edx, ebx
     *   0048F399  |.  85C9             test    ecx, ecx
     *   0048F39B  |.  74 06            je      short 0048F3A3
     *   0048F39D  |.  81F2 55AA0000    xor     edx, 0000AA55
     *   0048F3A3  |>  59               pop     ecx
     *   0048F3A4  |.  5B               pop     ebx
     *   0048F3A5  |.  66:8951 04       mov     word ptr ds:[ecx+4], dx         ; Update message checksum, and ...
     *   0048F3A9  \.  C3               retn                                    ; ... return message checksum in DX.
     *
     *   This is the second part that differs:
     *
     *                                  ; These are the original instructions
     *                                  ; from 0x45CD3F that we had to
     *                                  ; overwrite to call the bugfix routine.
     *   0048F3AA  /.  85C0             test    eax, eax
     *   0048F3AC  |.^ 0F84 E1D9FCFF    je      0045CD93
     *   0048F3B2  |.  83F8 FF          cmp     eax, -1
     *   0048F3B5  |.^ 0F84 D8D9FCFF    je      0045CD93
     *   0048F3BB  |.  8A4CE4 18        mov     cl, byte ptr ss:[esp+18]
     *   0048F3BF  \.^ E9 88D9FCFF      jmp     0045CD4C
     *
     *                                  ; These are the original instructions
     *                                  ; from 0x45CDCF that we had to
     *                                  ; overwrite to call the bugfix routine.
     *   0048F3C4  />  85C0             test    eax, eax
     *   0048F3C6  |.^ 0F84 24DAFCFF    je      0045CDF0
     *   0048F3CC  |.  83F8 FF          cmp     eax, -1
     *   0048F3CF  |.^ 0F84 1BDAFCFF    je      0045CDF0
     *   0048F3D5  |.  8A4CE4 18        mov     cl, byte ptr ss:[esp+18]
     *   0048F3D9  \.^ E9 FED9FCFF      jmp     0045CDDC
     */
    0xD9, 0xEB, 0xDD, 0x5D, 0xF8, 0x9B, 0xC9, 0xC3, 0x60, 0x83, 0xF8, 0xFF,
    0x74, 0x67, 0x83, 0xF8, 0x1E, 0x72, 0x62, 0x8D, 0x74, 0xE4, 0x28, 0x83,
    0xFE, 0x00, 0x74, 0x59, 0x8D, 0x54, 0xE4, 0x24, 0x83, 0xFA, 0x00, 0x74,
    0x50, 0x83, 0x3A, 0x0E, 0x72, 0x4B, 0x8D, 0x5C, 0xE4, 0x38, 0x83, 0xC3,
    0x04, 0xFF, 0x73, 0x04, 0x89, 0xD9, 0xE8, 0x3C, 0x00, 0x00, 0x00, 0x58,
    0x66, 0x39, 0xC2, 0x74, 0x06, 0x66, 0x89, 0x43, 0x04, 0xEB, 0x2E, 0x0F,
    0xB6, 0x53, 0x06, 0x6A, 0x0C, 0x59, 0x80, 0xEA, 0x04, 0x80, 0xFA, 0x08,
    0x72, 0x08, 0x80, 0xFA, 0x09, 0x75, 0x1A, 0x83, 0xC1, 0x08, 0x83, 0xC6,
    0x06, 0x8B, 0x16, 0x89, 0x14, 0x19, 0x8B, 0x56, 0x04, 0x66, 0x89, 0x54,
    0x19, 0x04, 0x89, 0xD9, 0xE8, 0x02, 0x00, 0x00, 0x00, 0x61, 0xC3, 0x53,
    0x51, 0x0F, 0xB6, 0x11, 0xBB, 0x44, 0x01, 0x00, 0x00, 0x81, 0xFA, 0x00,
    0x01, 0x00, 0x00, 0x7E, 0x05, 0xBA, 0x00, 0x01, 0x00, 0x00, 0x85, 0xD2,
    0x66, 0xC7, 0x41, 0x04, 0x00, 0x00, 0xEB, 0x0C, 0x90, 0x90, 0x0F, 0xB6,
    0x01, 0x41, 0x31, 0xC3, 0xC1, 0xC3, 0x03, 0x4A, 0x75, 0xF4, 0x89, 0xDA,
    0x8B, 0x0D, 0x1C, 0xE2, 0x4A, 0x00, 0xC1, 0xEA, 0x10, 0x31, 0xDA, 0x85,
    0xC9, 0x74, 0x06, 0x81, 0xF2, 0x55, 0xAA, 0x00, 0x00, 0x59, 0x5B, 0x66,
    0x89, 0x51, 0x04, 0xC3, 0x85, 0xC0, 0x0F, 0x84, 0xE1, 0xD9, 0xFC, 0xFF,
    0x83, 0xF8, 0xFF, 0x0F, 0x84, 0xD8, 0xD9, 0xFC, 0xFF, 0x8A, 0x4C, 0xE4,
    0x18, 0xE9, 0x88, 0xD9, 0xFC, 0xFF, 0x85, 0xC0, 0x0F, 0x84, 0x24, 0xDA,
    0xFC, 0xFF, 0x83, 0xF8, 0xFF, 0x0F, 0x84, 0x1B, 0xDA, 0xFC, 0xFF, 0x8A,
    0x4C, 0xE4, 0x18, 0xE9, 0xFE, 0xD9, 0xFC, 0xFF
};
struct patch patch_bugfix_2_0_2_0 = {
    -1,
    ARRAY_SIZE(patch_bugfix_original_2_0_2_0),
    patch_bugfix_original_2_0_2_0,
    patch_bugfix_patch_2_0_2_0
};

static const unsigned char patch_bugfix_patch_2_0_2_1[] = {
    /* x86 disassembly:
     *   0048F346  |.  D9EB             fldpi
     *   0048F348  |.  DD5D F8          fstp qword ptr [ebp-8]
     *   0048F34B  |.  9B               wait
     *   0048F34C  |>  C9               leave
     *   0048F34D  \.  C3               ret
     *
     *                                  ; Bugfix routine. Filters messages
     *                                  ; received by Warcraft II BNE through
     *                                  ; the recvfrom() function.
     *                                  ; Messages containing a reply address
     *                                  ; will be corrected, as the reply
     *                                  ; address in the message may not
     *                                  ; necessarily be correct.
     *                                  ; Since recvfrom() returns information
     *                                  ; about who sent the message, which is
     *                                  ; the correct reply address, the reply
     *                                  ; address in the message is discarded
     *                                  ; and overwritten with that address.
     *   0048F34E  /$  60               pushad
     *   0048F34F  |.  83F8 FF          cmp     eax, -1                         ; recvfrom() == SOCKET_ERROR ?
     *   0048F352  |.  74 67            je      short 0048F3BB
     *                                  0x1E = minimum size of any message that we patch.
     *   0048F354  |.  83F8 1E          cmp     eax, 1E                         ; Message length insufficient ?
     *   0048F357  |.  72 62            jb      short 0048F3BB
     *   0048F359  |.  8D74E4 28        lea     esi, [esp+28]                   ; Get recvfrom() 'from' parameter.
     *   0048F35D  |.  83FE 00          cmp     esi, 0                          ; from == NULL ?
     *   0048F360  |.  74 59            je      short 0048F3BB
     *   0048F362  |.  8D54E4 24        lea     edx, [esp+24]                   ; Get recvfrom() 'fromlen' parameter.
     *   0048F366  |.  83FA 00          cmp     edx, 0                          ; fromlen == NULL ?
     *   0048F369  |.  74 50            je      short 0048F3BB
     *   0048F36B  |.  833A 0E          cmp     dword ptr ds:[edx], 0E          ; *fromlen < sizeof(struct sockaddr_ipx) ?
     *   0048F36E  |.  72 4B            jb      short 0048F3BB
     *   0048F370  |.  8D5CE4 38        lea     ebx, [esp+38]                   ; Get recvfrom() 'buf' parameter.
     *   0048F374  |.  83C3 04          add     ebx, 4                          ; Skip first 4 bytes in message.
     *   0048F377  |.  FF73 04          push    dword ptr ds:[ebx+4]            ; Save message checksum.
     *   0048F37A  |.  89D9             mov     ecx, ebx                        ; ECX = message pointer.
     *   0048F37C  |.  E8 3C000000      call    0048F3BD                        ; Update checksum (also return it in DX).
     *   0048F381  |.  58               pop     eax                             ; Restore message checksum.
     *   0048F382  |.  66:39C2          cmp     dx, ax                          ; Checksum incorrect ?
     *   0048F385  |.  74 06            je      short 0048F38D
     *   0048F387  |.  66:8943 04       mov     word ptr ds:[ebx+4], ax         ; Then put back the incorrect checksum ...
     *   0048F38B  |.  EB 2E            jmp     short 0048F3BB                  ; ... and return the message as-is.
     *                                  ; Calculate how many bytes we need to
     *                                  ; skip to get to the IPX nodenum field
     *                                  ; in the message.
     *   0048F38D  |>  0FB653 06        movzx   edx, byte ptr ds:[ebx+6]        ; Get message type byte.
     *   0048F391  |.  6A 0C            push    0C                              ; Skip 12 (0x0C) bytes by default.
     *   0048F393  |.  59               pop     ecx
     *   0048F394  |.  80EA 04          sub     dl, 4
     *   0048F397  |.  80FA 08          cmp     dl, 8                           ; Message type < 8 ?
     *   0048F39A  |.  72 08            jb      short 0048F3A4
     *   0048F39C  |.  80FA 09          cmp     dl, 9                           ; Message type != 9 ?
     *   0048F39F  |.  75 1A            jne     short 0048F3BB
     *   0048F3A1  |.  83C1 08          add     ecx, 8                          ; Skip 8 bytes more.
     *   0048F3A4  |>  83C6 06          add     esi, 6                          ; Skip to the IPv4 address or IPX nodenum in the 'from' structure.
     *                                  ; Put the IPv4 address or IPX nodenum
     *                                  ; from the 'from' structure in the
     *                                  ; message.
     *   0048F3A7  |.  8B16             mov     edx, dword ptr ds:[esi]
     *   0048F3A9  |.  891419           mov     dword ptr ds:[ebx+ecx], edx
     *   0048F3AC  |.  8B56 04          mov     edx, dword ptr ds:[esi+4]
     *   0048F3AF  |.  66:895419 04     mov     word ptr ds:[ebx+ecx+4], dx
     *   0048F3B4  |.  89D9             mov     ecx, ebx                        ; ECX = message pointer.
     *   0048F3B6  |.  E8 02000000      call    0048F3BD                        ; Update checksum (also return it in DX).
     *   0048F3BB  |>  61               popad
     *   0048F3BC  \.  C3               retn
     *
     *                                  ; Checksum calculation routine.
     *   0048F3BD  /$  53               push    ebx
     *   0048F3BE  |.  51               push    ecx
     *   0048F3BF  |.  0FB611           movzx   edx, byte ptr ds:[ecx]          ; First byte in message indicates length.
     *   0048F3C2  |.  BB 44010000      mov     ebx, 144
     *   0048F3C7  |.  81FA 00010000    cmp     edx, 100                        ; Message size less than or equal to 256 (0x100) bytes ?
     *   0048F3CD  |.  7E 05            jle     short 0048F3D4
     *   0048F3CF  |.  BA 00010000      mov     edx, 100                        ; Limit number of bytes to checksum to 256 (0x100).
     *   0048F3D4  |>  85D2             test    edx, edx
     *   0048F3D6  |.  66:C741 04 0000  mov     word ptr ds:[ecx+4], 0          ; Zero the checksum, as we don't want the checksum bytes to
     *                                                                          ; have an effect on the checksum calculation.
     *   0048F3DC  |.  EB 0C            jmp     short 0048F3EA
     *   0048F3DE  |   90               nop
     *   0048F3DF  |   90               nop
     *   0048F3E0  |>  0FB601           /movzx   eax, byte ptr ds:[ecx]
     *   0048F3E3  |.  41               |inc     ecx
     *   0048F3E4  |.  31C3             |xor     ebx, eax
     *   0048F3E6  |.  C1C3 03          |rol     ebx, 3
     *   0048F3E9  |.  4A               |dec     edx
     *   0048F3EA  |>^ 75 F4            \jne     short 0048F3E0
     *   0048F3EC  |.  89DA             mov     edx, ebx
     *   0048F3EE  |.  8B0D 6CE24A00    mov     ecx, dword ptr ds:[4AE26C]      ; Condition from the game's own checksum routine, ...
     *   0048F3F4  |.  C1EA 10          shr     edx, 10                         ; ... which can be found by searching for occurrences of ...
     *   0048F3F7  |.  31DA             xor     edx, ebx                        ; ... "chatroom:2" (there should be 2 of them), and going to ...
     *   0048F3F9  |.  85C9             test    ecx, ecx                        ; ... the one with the largest offset, and looking at the ...
     *   0048F3FB  |.  74 06            je      short 0048F403                  ; ... first 'mov edx, [yyy]' instruction, where 'yyy' should ...
     *   0048F3FD  |.  81F2 55AA0000    xor     edx, 0000AA55                   ; ... be equal to 4AE26C, like in our 'mov ecx, [4AE26C]'.
     *   0048F403  |>  59               pop     ecx
     *   0048F404  |.  5B               pop     ebx
     *   0048F405  |.  66:8951 04       mov     word ptr ds:[ecx+4], dx         ; Update message checksum, and ...
     *   0048F409  \.  C3               retn                                    ; ... return message checksum in DX.
     *
     *                                  ; These are the original instructions
     *                                  ; from 0x45CD3F that we had to
     *                                  ; overwrite to call the bugfix routine.
     *   0048F40A  /.  85C0             test    eax, eax
     *   0048F40C  |.^ 0F84 81D9FCFF    je      0045CD93
     *   0048F412  |.  83F8 FF          cmp     eax, -1
     *   0048F415  |.^ 0F84 78D9FCFF    je      0045CD93
     *   0048F41B  |.  8A4CE4 18        mov     cl, byte ptr ss:[esp+18]
     *   0048F41F  \.^ E9 28D9FCFF      jmp     0045CD4C
     *
     *                                  ; These are the original instructions
     *                                  ; from 0x45CDCF that we had to
     *                                  ; overwrite to call the bugfix routine.
     *   0048F424  />  85C0             test    eax, eax
     *   0048F426  |.^ 0F84 C4D9FCFF    je      0045CDF0
     *   0048F42C  |.  83F8 FF          cmp     eax, -1
     *   0048F42F  |.^ 0F84 BBD9FCFF    je      0045CDF0
     *   0048F435  |.  8A4CE4 18        mov     cl, byte ptr ss:[esp+18]
     *   0048F439  \.^ E9 9ED9FCFF      jmp     0045CDDC
     */
    0xD9, 0xEB, 0xDD, 0x5D, 0xF8, 0x9B, 0xC9, 0xC3, 0x60, 0x83, 0xF8, 0xFF,
    0x74, 0x67, 0x83, 0xF8, 0x1E, 0x72, 0x62, 0x8D, 0x74, 0xE4, 0x28, 0x83,
    0xFE, 0x00, 0x74, 0x59, 0x8D, 0x54, 0xE4, 0x24, 0x83, 0xFA, 0x00, 0x74,
    0x50, 0x83, 0x3A, 0x0E, 0x72, 0x4B, 0x8D, 0x5C, 0xE4, 0x38, 0x83, 0xC3,
    0x04, 0xFF, 0x73, 0x04, 0x89, 0xD9, 0xE8, 0x3C, 0x00, 0x00, 0x00, 0x58,
    0x66, 0x39, 0xC2, 0x74, 0x06, 0x66, 0x89, 0x43, 0x04, 0xEB, 0x2E, 0x0F,
    0xB6, 0x53, 0x06, 0x6A, 0x0C, 0x59, 0x80, 0xEA, 0x04, 0x80, 0xFA, 0x08,
    0x72, 0x08, 0x80, 0xFA, 0x09, 0x75, 0x1A, 0x83, 0xC1, 0x08, 0x83, 0xC6,
    0x06, 0x8B, 0x16, 0x89, 0x14, 0x19, 0x8B, 0x56, 0x04, 0x66, 0x89, 0x54,
    0x19, 0x04, 0x89, 0xD9, 0xE8, 0x02, 0x00, 0x00, 0x00, 0x61, 0xC3, 0x53,
    0x51, 0x0F, 0xB6, 0x11, 0xBB, 0x44, 0x01, 0x00, 0x00, 0x81, 0xFA, 0x00,
    0x01, 0x00, 0x00, 0x7E, 0x05, 0xBA, 0x00, 0x01, 0x00, 0x00, 0x85, 0xD2,
    0x66, 0xC7, 0x41, 0x04, 0x00, 0x00, 0xEB, 0x0C, 0x90, 0x90, 0x0F, 0xB6,
    0x01, 0x41, 0x31, 0xC3, 0xC1, 0xC3, 0x03, 0x4A, 0x75, 0xF4, 0x89, 0xDA,
    0x8B, 0x0D, 0x6C, 0xE2, 0x4A, 0x00, 0xC1, 0xEA, 0x10, 0x31, 0xDA, 0x85,
    0xC9, 0x74, 0x06, 0x81, 0xF2, 0x55, 0xAA, 0x00, 0x00, 0x59, 0x5B, 0x66,
    0x89, 0x51, 0x04, 0xC3, 0x85, 0xC0, 0x0F, 0x84, 0x81, 0xD9, 0xFC, 0xFF,
    0x83, 0xF8, 0xFF, 0x0F, 0x84, 0x78, 0xD9, 0xFC, 0xFF, 0x8A, 0x4C, 0xE4,
    0x18, 0xE9, 0x28, 0xD9, 0xFC, 0xFF, 0x85, 0xC0, 0x0F, 0x84, 0xC4, 0xD9,
    0xFC, 0xFF, 0x83, 0xF8, 0xFF, 0x0F, 0x84, 0xBB, 0xD9, 0xFC, 0xFF, 0x8A,
    0x4C, 0xE4, 0x18, 0xE9, 0x9E, 0xD9, 0xFC, 0xFF
};
struct patch patch_bugfix_2_0_2_1 = {
    -1,
    /* We're reusing the original instructions from 2.0.2.0 for 2.0.2.1. */
    ARRAY_SIZE(patch_bugfix_original_2_0_2_0),
    patch_bugfix_original_2_0_2_0,
    patch_bugfix_patch_2_0_2_1
};

static struct patch *patch_list_2_0_2_0[] = {
    /* This patch increases the Virtual Size of the .text section of the
     * Portable Executable (PE), since the bugfix code is added to the end of
     * the .text section.
     */
    &patch_text_section_virtual_size_2_0_2_0,
    /* This patch makes Warcraft jump to the bugfix routine after receiving
     * a message through recvfrom().
     */
    &patch_bugfix_call_0_2_0_2_0,
    /* This patch makes Warcraft jump to the bugfix routine after receiving
     * a message through recvfrom().
     */
    &patch_bugfix_call_1_2_0_2_0,
    /* This patch contains the bugfix routine. */
    &patch_bugfix_2_0_2_0
};

static struct patch *patch_list_2_0_2_1[] = {
    /* This patch increases the Virtual Size of the .text section of the
     * Portable Executable (PE), since the bugfix code is added to the end of
     * the .text section.
     */
    &patch_text_section_virtual_size_2_0_2_1,
    /* This patch makes Warcraft jump to the bugfix routine after receiving
     * a message through recvfrom().
     */
    &patch_bugfix_call_0_2_0_2_1,
    /* This patch makes Warcraft jump to the bugfix routine after receiving
     * a message through recvfrom().
     */
    &patch_bugfix_call_1_2_0_2_1,
    /* This patch contains the bugfix routine. */
    &patch_bugfix_2_0_2_1
};

static struct patch **patch_lists_to_try[] = {
    patch_list_2_0_2_0,
    patch_list_2_0_2_1
};

static size_t num_patches_in_either_patch_list = -1;

static void pause(void)
{
    char input[2];

    printf("Press RETURN to continue ...\n");
    fgets(input, ARRAY_SIZE(input), stdin);
}

int main(void)
{
    int ret = EXIT_FAILURE;
    FILE *file = NULL;
    char *blk = NULL;
    long file_size;
    size_t size_read;
    size_t i;
    int all_patterns_found = 0;
    int do_patch = 0;
    int do_restore = 0;
    struct patch **patch_list = NULL;
    size_t patch_list_index = 0;

    assert(ARRAY_SIZE(patch_list_2_0_2_0) == ARRAY_SIZE(patch_list_2_0_2_1));
    num_patches_in_either_patch_list = ARRAY_SIZE(patch_list_2_0_2_0);

    file = fopen(FILENAME, "rb+");
    if (!file)
    {
        fprintf(stderr, "\
`" FILENAME "' not found or access denied (read-only attribute set?).\n\
Please put this patch in the same directory as `" FILENAME "', make\n\
sure the game is not running, and run the patch again.\n");
        goto done;
    }

    if (fseek(file, 0, SEEK_END))
        goto io_error;
    file_size = ftell(file);
    if (file_size == -1L)
        goto io_error;
    if (fseek(file, 0, SEEK_SET))
        goto io_error;

    blk = malloc(file_size);
    if (!blk)
    {
        fprintf(stderr, "Out of memory.\n");
        goto done;
    }

    size_read = fread(blk, 1, file_size, file);
    if (feof(file))
    {
        fprintf(stderr, "Unexpected end-of-file reached.\n");
        goto done;
    }
    if (ferror(file))
    {
        fprintf(stderr, "Could not read %lu bytes from file.\n", file_size);
        goto done;
    }

    for (i = 0; i < ARRAY_SIZE(patch_lists_to_try); ++i)
    {
        size_t j;

        patch_list = patch_lists_to_try[i];
        patch_list_index = 0;

        /* Try pattern matching at each offset. */
        for (j = 0; j < size_read; ++j)
        {
            struct patch *patch = patch_list[patch_list_index];
            int match = 0;

            if (memcmp(&blk[j], patch->original, patch->size) == 0)
            {
                if (do_restore)
                    goto patch_state_inconsistent;
                do_patch = 1;
                match = 1;
            }
            else if (memcmp(&blk[j], patch->patch, patch->size) == 0)
            {
                if (do_patch)
                    goto patch_state_inconsistent;
                do_restore = 1;
                match = 1;
            }

            if (match)
            {
                patch->offset = j;

                patch_list_index++;
                if (patch_list_index == num_patches_in_either_patch_list)
                {
                    all_patterns_found = 1;
                    break;
                }
            }
        }

        if (all_patterns_found)
            break;
    }

    if (!all_patterns_found)
    {
        fprintf(stderr, "\
Could not find the data to patch (wrong file version?).\n\
Perhaps update the game to version " FILENAME_VERSION " and\n\
rerun the patch.\n");
        goto done;
    }

    if (do_restore)
    {
        if (confirm(CONFIRM_NO, NULL,
                    "`" FILENAME "' is already patched and can be restored. "
                    "Restore it?") != CONFIRM_YES)
        {
            printf("File not modified.\n");
            ret = EXIT_SUCCESS;
            goto done;
        }
    }

    for (i = 0; i < num_patches_in_either_patch_list; ++i)
    {
        const struct patch *patch = patch_list[i];

        if (fseek(file, patch->offset, SEEK_SET))
            goto io_error;
        if (fwrite(do_patch ? patch->patch : patch->original, 1,
                   patch->size, file) != patch->size)
        {
            fprintf(stderr, "Could not write %lu bytes to file.\n",
                    (unsigned long)patch->size);
            goto done;
        }
    }

    if (do_patch)
    {
        printf("`" FILENAME "' successfully patched. Rerun the patch to "
                "restore it.\n");
    }
    else if (do_restore)
    {
        printf("`" FILENAME "' successfully restored. Rerun the patch to "
                "patch it.\n");
    }

    ret = EXIT_SUCCESS;

done:
    if (blk)
        free(blk);
    if (file)
        fclose(file);
    pause();
    return ret;
io_error:
    fprintf(stderr, "I/O error.\n");
    goto done;
patch_state_inconsistent:
    fprintf(stderr,
            "`" FILENAME "' is in an inconsistent state "
            "(half-patched/restored).\n");
    goto done;
}
