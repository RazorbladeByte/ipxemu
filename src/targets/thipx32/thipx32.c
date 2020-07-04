/*
Author: Jelle Geerts

Usage of the works is permitted provided that this instrument is
retained with the works, so that any entity that uses the works is
notified of this instrument.

DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
*/

/* This code is for the `thipx32.dll', which is used by games such as
 * `Red Alert 1' and `Command and Conquer: Tiberian Dawn'.
 */

#include "thipx32.h"
#include "my_wsipx.h"
#include <assert.h>
#include <time.h>

#define PORT 7460

static int winsock_is_initialized = 0;

static SOCKET session_socket = INVALID_SOCKET;

#define BROADCAST_SIGNATURE_MAGIC 0xBA55
static broadcast_signature_t broadcast_signature;

/* Generate a broadcast signature such that one can distinguish between
 * broadcast messages sent by other instances and this instance.
 */
static void generate_broadcast_signature(void)
{
    time_t t;
    DWORD ticks;
    int r;

    t = time(NULL);
    if (t == (time_t)-1) {
        /* Cause the random seed to be reinitialized to its initial value. */
        t = 1;
    }
    srand(t);

    ticks = GetTickCount();
    r = rand();

    /* Generate a broadcast signature such that one can distinguish between
     * broadcast messages sent by other instances and this instance.
     *
     * For good entropy, use 8 bits from rand() and 16 bits from
     * GetTickCount(). If only rand() were used, there's a reasonable chance
     * that two or more instances use the same broadcast signature.
     */
    ticks = ((ticks & 0xFFFF0000) >> 16) ^ (ticks & 0xFFFF);
    ticks = ((ticks & 0xFF00) >> 8) ^ (ticks & 0xFF);
    r = ((r & 0xFF00) >> 8) ^ (r & 0xFF);
    broadcast_signature |= ((r & 0xFF) << 8) | (ticks & 0xFF);

    /* Use the last 16 bits of the broadcast signature as verification bits.
     * This way, the following is true: upper_16_bits == lower_16_bits ^ magic.
     * And thus, we can unmistakably identify a message as being a broadcast
     * message, as it is very unlikely that the same verification scheme with
     * the same magic value is used on any other incoming data.
     */
    broadcast_signature = (broadcast_signature << 16) |
        ((broadcast_signature & 0xFFFF) ^ BROADCAST_SIGNATURE_MAGIC);
}

/* WSAStartup() shouldn't be called from a DllMain(), as it can potentially
 * lead to deadlocks due to it loading protocol-specific helper DLLs.
 * Therefore, simply call WSAStartup() whenever needed.
 */
static int init_winsock(void)
{
    WSADATA d;

    if (winsock_is_initialized)
        return 1;

    generate_broadcast_signature();

    winsock_is_initialized = WSAStartup(0xFFFF, &d) == 0;

    return winsock_is_initialized;
}

static void uninit_winsock(void)
{
    if (winsock_is_initialized) {
        (void)my__IPX_Close_Socket95(0);
        WSACleanup();
        winsock_is_initialized = 0;
    }
}

int STDCALL my__IPX_Initialise(void)
{
    return init_winsock();
}

int STDCALL my__IPX_Open_Socket95(unsigned short socket_number)
{
/* Emulated `socket already opened' error code. */
#define EINUSE 0xFF
/* Anything not zero and not 0xFF means `unspecified error'. */
#define EUNSPEC 1
    int ret = EUNSPEC;
    u_long non_blocking = 1;
    BOOL optval = TRUE;

    (void)socket_number;

    if (!init_winsock())
        return EUNSPEC;

    if (session_socket != INVALID_SOCKET)
        return EINUSE;

    session_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (session_socket == INVALID_SOCKET)
        return EUNSPEC;

    if (ioctlsocket(session_socket, FIONBIO, &non_blocking) == SOCKET_ERROR)
        goto done;

    if (setsockopt(session_socket, SOL_SOCKET, SO_BROADCAST,
                (const char *)&optval, sizeof(optval)) == SOCKET_ERROR) {
        goto done;
    }

    ret = 0;

done:
    if (ret != 0)
        (void)my__IPX_Close_Socket95(0);
    return ret;
#undef EINUSE
#undef EUNSPEC
}

void STDCALL my__IPX_Close_Socket95(unsigned short socket_number)
{
    int ret;

    (void)socket_number;

    if (session_socket == INVALID_SOCKET)
        goto done;

    /* Initializing Winsock here would be useless as the socket wasn't created
     * by the newly initialized instance. So, only check whether Winsock is
     * currently initialized, instead of initializing it.
     */
    if (!winsock_is_initialized) {
        assert(0 && "a socket was open but Winsock was already unloaded");
        goto done;
    }

    ret = closesocket(session_socket);
    assert(ret == 0);
    (void)ret;

done:
    /* Invalidate the socket handle even if closesocket() failed, as the other
     * functions assume that it is invalidated after they call this function,
     * and because nothing else can be done about the situation.
     */
    session_socket = INVALID_SOCKET;
}

int STDCALL my__IPX_Get_Connection_Number95(void)
{
    /* If 0 is returned, the caller shouldn't use
     * my__IPX_Get_Local_Target95().
     */
    return 0;
}

void STDCALL my__IPX_Send_Packet95(const void *unknown0, const char *buf,
        int len, const void *unknown1, const char nodenum[6])
{
    struct sockaddr_in sa;

    (void)unknown0;
    (void)unknown1;

    if (!init_winsock() || session_socket == INVALID_SOCKET)
        return;

    sa.sin_family = AF_INET;
    sa.sin_port = htons(PORT);
    memcpy(&sa.sin_addr, nodenum, 4);
    memset(sa.sin_zero, 0, sizeof(sa.sin_zero));

    (void)sendto(session_socket, buf, len, 0,
            (struct sockaddr *)&sa, sizeof(sa));
}

void STDCALL my__IPX_Broadcast_Packet95(const char *buf, int len)
{
    struct sockaddr_in sa;
    char local_buf[sizeof(broadcast_signature) + MSG_DATA_SIZE];

    if (!init_winsock() || session_socket == INVALID_SOCKET)
        return;

    if (len < 0 || len > MSG_DATA_SIZE) {
        assert(0 && "buffer size larger than expected, not enough "
                "memory reserved");
        return;
    }

    memcpy(&local_buf[0], &broadcast_signature, sizeof(broadcast_signature));
    memcpy(&local_buf[sizeof(broadcast_signature)], buf, len);

    sa.sin_family = AF_INET;
    sa.sin_port = htons(PORT);
    sa.sin_addr.S_un.S_addr = htonl(INADDR_BROADCAST);
    memset(sa.sin_zero, 0, sizeof(sa.sin_zero));

    (void)sendto(session_socket, local_buf, sizeof(broadcast_signature) + len,
            0, (struct sockaddr *)&sa, sizeof(sa));
}

int STDCALL my__IPX_Get_Local_Target95(const void *unknown0,
        const void *unknown1, const void *unknown2, const void *unknown3)
{
    (void)unknown0;
    (void)unknown1;
    (void)unknown2;
    (void)unknown3;

    assert(0 && "my__IPX_Get_Local_Target95() called");

    return 1; /* Fail. */
}

int STDCALL my__IPX_Start_Listening95(void)
{
    struct sockaddr_in sa;

    if (!init_winsock() || session_socket == INVALID_SOCKET)
        return 0;

    sa.sin_family = AF_INET;
    sa.sin_port = htons(PORT);
    sa.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
    memset(sa.sin_zero, 0, sizeof(sa.sin_zero));

    return bind(session_socket, (struct sockaddr *)&sa, sizeof(sa)) == 0;
}

void my__IPX_Shut_Down95(void)
{
    uninit_winsock();
}

int STDCALL my__IPX_Get_Outstanding_Buffer95(struct ipx_packet *msg)
{
    struct sockaddr_in sa;
    int fromlen = sizeof(sa);
    int len;

    if (!init_winsock() || session_socket == INVALID_SOCKET)
        return 0;

    len = recvfrom(session_socket, msg->data, sizeof(msg->data), 0,
            (struct sockaddr *)&sa, &fromlen);
    if (len == SOCKET_ERROR) {
        /* WSAGetLastError() most likely returns WSAEWOULDBLOCK now. And if
         * not, then there's nothing to do about the situation.
         */
        return 0;
    }

    if ((unsigned)len >= sizeof(broadcast_signature)) {
        broadcast_signature_t sig;

        memcpy(&sig, msg->data, sizeof(sig));

        if (broadcast_signature == sig) {
            /* Message was a broadcast message sent by ourself. */
            return 0;
        } else if ((sig >> 16) ==
                ((sig & 0xFFFF) ^ BROADCAST_SIGNATURE_MAGIC)) {
            /* Message was a broadcast message sent by another instance. So,
             * remove the broadcast signature from the message.
             */
            memmove(msg->data, &msg->data[sizeof(broadcast_signature)],
                    sizeof(msg->data) - sizeof(broadcast_signature));
            len -= sizeof(broadcast_signature);
        }
    }

    msg->hdr.cksum = 0xFFFF;
    msg->hdr.len = htons(sizeof(msg->hdr) + len);
    msg->hdr.tx_ctl = 0;
    msg->hdr.pkt_type = 0;
    memset(msg->hdr.dst_netnum, 0, sizeof(msg->hdr.dst_netnum));
    memset(msg->hdr.dst_nodenum, 0, sizeof(msg->hdr.dst_nodenum));
    memset(&msg->hdr.dst_socket, 0, 2);
    memset(msg->hdr.src_netnum, 0, sizeof(msg->hdr.src_netnum));
    memcpy(&msg->hdr.src_nodenum[0], &sa.sin_addr, sizeof(sa.sin_addr));
    memset(&msg->hdr.src_nodenum[4], 0, 2);
    memset(&msg->hdr.src_socket, 0, 2);

    return 1;
}
