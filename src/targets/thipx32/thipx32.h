/*
Author: Jelle Geerts

Usage of the works is permitted provided that this instrument is
retained with the works, so that any entity that uses the works is
notified of this instrument.

DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
*/

#ifndef THIPX32_H
#define THIPX32_H

#include "compiler_specific.h"
#include <windows.h>
#include <winsock2.h>
#include <stdint.h>

typedef uint32_t broadcast_signature_t;

struct ipx_header
{
    unsigned short cksum;
    unsigned short len;
    unsigned char tx_ctl;
    unsigned char pkt_type;
    char dst_netnum[4];
    char dst_nodenum[6];
    unsigned short dst_socket;
    char src_netnum[4];
    char src_nodenum[6];
    unsigned short src_socket;
} ATTRIBUTE_PACKED;

/* Callers assume the structure size is the size of the header plus the size of
 * the data. A few extra bytes are needed to receive a possible broadcast
 * signature, which will be removed before returning the structure to the
 * caller. (See my__IPX_Get_Outstanding_Buffer95().)
 */
struct ipx_packet
{
    struct ipx_header hdr;
#define MSG_DATA_SIZE 1024
    char data[sizeof(broadcast_signature_t) +
        MSG_DATA_SIZE -
        sizeof(struct ipx_header)];
} ATTRIBUTE_PACKED;

int STDCALL my__IPX_Initialise(void);
int STDCALL my__IPX_Open_Socket95(unsigned short socket_number);
void STDCALL my__IPX_Close_Socket95(unsigned short socket_number);
int STDCALL my__IPX_Get_Connection_Number95(void);
void STDCALL my__IPX_Send_Packet95(const void *unknown0, const char *buf,
        int len, const void *unknown1, const char nodenum[6]);
void STDCALL my__IPX_Broadcast_Packet95(const char *buf, int len);
int STDCALL my__IPX_Get_Local_Target95(const void *unknown0,
        const void *unknown1, const void *unknown2, const void *unknown3);
int STDCALL my__IPX_Start_Listening95(void);
void my__IPX_Shut_Down95(void);
int STDCALL my__IPX_Get_Outstanding_Buffer95(struct ipx_packet *msg);

#endif /* !defined(THIPX32_H) */
