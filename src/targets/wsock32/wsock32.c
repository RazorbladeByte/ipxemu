/*
Author: Jelle Geerts

Usage of the works is permitted provided that this instrument is
retained with the works, so that any entity that uses the works is
notified of this instrument.

DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
*/

#include "wsock32.h"
#include "enum_protocols_template.h"
#include "my_wsipx.h"
#include "my_wsnwlink.h"
#include "socktable.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#ifdef DEBUG
# include <stdarg.h>
# include <stdio.h>
static FILE *log_fp = NULL;

static void log_close(void)
{
    if (log_fp != NULL) {
        fclose(log_fp);
        log_fp = NULL;
    }
}

static int log_ensure_opened(void)
{
#define LOG_FILENAME "wsock32-log.txt"
    char filename[2048 + sizeof(LOG_FILENAME)];
    DWORD size = ARRAY_SIZE(filename) -
        (sizeof(LOG_FILENAME) - sizeof(filename[0]));
    DWORD n;

    n = GetTempPath(size, filename);
    if (!n || n > size) {
        assert(0);
        return 0;
    }
    strcat(filename, LOG_FILENAME);

    if (log_fp == NULL)
        log_fp = fopen(filename, "a");
    return log_fp != NULL;
}

#define log_msg(expr) _log_msg expr
static void _log_msg(const char *fmt, ...)
{
    va_list ap;

    if (!log_ensure_opened())
        return;

    va_start(ap, fmt);
    vfprintf(log_fp, fmt, ap);
    fflush(log_fp);
    va_end(ap);
}

static void log_export_call(const char *export_name)
{
    unsigned int ret = 0xC0FFEE;

    if (!log_ensure_opened())
        return;

    log_msg(("export `%s' called\n", export_name));

    __asm__ (
        "mov (%%ebp), %%eax\n"
        "mov 4(%%eax), %%eax\n"
        : "=r" (ret));

    log_msg(("return address pushed by caller "
                "module (may be incorrect): %08X\n", ret));

    log_msg(("\n"));
}
#else /* !defined(DEBUG) */
# define log_close() ((void)0)
# define log_msg(expr) ((void)0)
# define log_export_call(a) ((void)0)
#endif /* !defined(DEBUG) */

/* As this function uses FatalAppExit(), it will only return if a debug version
 * of `kernel32.dll' was loaded and the message box was cancelled; otherwise,
 * the function will not return.
 */
static void panic(const char *export_name)
{
    char *error_msg;

    assert(export_name != NULL);

    /* Using snprintf() here would inflate the executable size considerably (as
     * at the time of writing, this function isn't used elsewhere, and using it
     * here would cause code providing snprintf() to be linked in).
     */
    error_msg = malloc(160 + strlen(export_name));
    if (error_msg) {
        strcpy(error_msg, "The exported function `");
        strcat(error_msg, export_name);
        strcat(error_msg,
                "' of `wsock32.dll' was called. However, it is a dummy "
                "(non-functional) function. "
                "The application will be terminated.");
        FatalAppExit(0, error_msg);
        free(error_msg);
    }
}

#ifdef DEBUG
# define INETSTR_MAX 22
/* The output buffer 'buf' must be able to hold at least INETSTR_MAX
 * characters.
 */
static void inetstr(char *buf, const struct sockaddr_in *sa)
{
    unsigned char *port = (unsigned char *)&sa->sin_port;

    sprintf(buf, "%u.%u.%u.%u:%u",
                sa->sin_addr.S_un.S_un_b.s_b1,
                sa->sin_addr.S_un.S_un_b.s_b2,
                sa->sin_addr.S_un.S_un_b.s_b3,
                sa->sin_addr.S_un.S_un_b.s_b4,
                port[0] << 8 | port[1]);
}
#endif /* defined(DEBUG) */

/* Get the 4-byte IPX network number. */
static void get_ipx_netnum(void *netnum)
{
    memset(netnum, 0, 4);
}

/* Get the 6-byte IPX node number. */
static void get_ipx_nodenum(void *nodenum)
{
    /* As some applications may decide that the address
     * 00-00-00-00-00-00 is indicative of failure, use the address
     * 00-00-00-00-00-01 instead.
     *
     * This is necessary for at least the game `Dune 2000'.
     */
    char *p = nodenum;
    memset(p, 0, 6);
    p[5] = 1;
}

BOOL WINAPI DllMain(HINSTANCE hInstDll, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hInstDll;
    (void)lpvReserved;

    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        log_msg(("DllMain(): DLL_PROCESS_ATTACH\n\n"));
        return TRUE;

    case DLL_PROCESS_DETACH:
        log_msg(("DllMain(): DLL_PROCESS_DETACH\n\n"));
        free_protocol_names();
        free_socktable();
        log_close();
        break;

    default:
        break;
    }

    return TRUE;
}

int STDCALL my_bind(SOCKET s, const struct sockaddr *name, int namelen)
{
    const struct sockaddr *sockaddr_to_use = name;
    struct sockaddr_in sa;

    log_msg(("bind(): s=0x%X (IS%s emulated)\n\n",
                s, is_emulated_socket(s) ? "" : " NOT"));

    if (is_emulated_socket(s)) {
        const struct sockaddr_ipx *sa_ipx = (const struct sockaddr_ipx *)name;

        if (namelen < (signed)sizeof(struct sockaddr_ipx) ||
                name->sa_family != AF_IPX) {
            WSASetLastError(WSAEFAULT);
            return SOCKET_ERROR;
        }

        sa.sin_family = AF_INET;
        sa.sin_port = sa_ipx->sa_socket;
        sa.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
        memset(&sa.sin_zero, 0, sizeof(sa.sin_zero));

        sockaddr_to_use = (const struct sockaddr *)&sa;
        namelen = sizeof(sa);
    }

    return bind(s, sockaddr_to_use, namelen);
}

int STDCALL my_closesocket(SOCKET s)
{
    int ret;

    ret = closesocket(s);

    if (ret == 0 && is_emulated_socket(s))
        remove_emulated_socket(s);

    return ret;
}

int STDCALL my_getsockname(SOCKET s, struct sockaddr *name, int *namelen)
{
    if (is_emulated_socket(s)) {
        struct sockaddr_in sa;
        int local_fromlen = sizeof(sa);
        struct sockaddr_ipx *sa_ipx = (struct sockaddr_ipx *)name;

        if (*namelen < (signed)sizeof(struct sockaddr_ipx)) {
            WSASetLastError(WSAEFAULT);
            return SOCKET_ERROR;
        }

        if (getsockname(s, (struct sockaddr *)&sa,
                    &local_fromlen) == SOCKET_ERROR) {
            return SOCKET_ERROR;
        }

        sa_ipx->sa_family = AF_IPX;
        get_ipx_netnum(sa_ipx->sa_netnum);
        get_ipx_nodenum(sa_ipx->sa_nodenum);
        sa_ipx->sa_socket = sa.sin_port;

        *namelen = sizeof(struct sockaddr_ipx);

        return 0;
    }

    return getsockname(s, name, namelen);
}

int STDCALL my_getsockopt(SOCKET s, int level, int optname, char *optval,
        int *optlen)
{
    if (level == NSPROTO_IPX) {
#define log_unsupported_optname_failure(n)                                    \
        log_msg(("getsockopt(): option %s not "                               \
                    "implemented, returning failure\n\n", n))
        switch (optname) {
        case IPX_MAX_ADAPTER_NUM:
            *(BOOL *)optval = 1;
            return 0;

        case IPX_ADDRESS: {
            IPX_ADDRESS_DATA *p = (IPX_ADDRESS_DATA *)optval;
            p->adapternum = 0;
            get_ipx_netnum(p->netnum);
            get_ipx_nodenum(p->nodenum);
            p->wan = FALSE;
            p->status = TRUE;
            /* 1470 = 1500 (maximum transmission unit for Ethernet) -
             *        30 (IPX packet header size) */
            p->maxpkt = 1470;
            p->linkspeed = 1000000;
            return 0;
        }

        case IPX_PTYPE:
            log_unsupported_optname_failure("IPX_PTYPE");
            return SOCKET_ERROR;
        case IPX_FILTERPTYPE:
            log_unsupported_optname_failure("IPX_FILTERPTYPE");
            return SOCKET_ERROR;
        case IPX_DSTYPE:
            log_unsupported_optname_failure("IPX_DSTYPE");
            return SOCKET_ERROR;
        case IPX_MAXSIZE:
            log_unsupported_optname_failure("IPX_MAXSIZE");
            return SOCKET_ERROR;
        case IPX_GETNETINFO:
            log_unsupported_optname_failure("IPX_GETNETINFO");
            return SOCKET_ERROR;
        case IPX_GETNETINFO_NORIP:
            log_unsupported_optname_failure("IPX_GETNETINFO_NORIP");
            return SOCKET_ERROR;
        case IPX_SPXGETCONNECTIONSTATUS:
            log_unsupported_optname_failure("IPX_SPXGETCONNECTIONSTATUS");
            return SOCKET_ERROR;
        case IPX_ADDRESS_NOTIFY:
            log_unsupported_optname_failure("IPX_ADDRESS_NOTIFY");
            return SOCKET_ERROR;
        case IPX_RERIPNETNUMBER:
            log_unsupported_optname_failure("IPX_RERIPNETNUMBER");
            return SOCKET_ERROR;
        default:
            log_msg(("getsockopt(): option 0x%08X not implemented, "
                        "returning failure\n\n", optname));
            return SOCKET_ERROR;
        }
#undef log_unsupported_optname_failure
    }

    return getsockopt(s, level, optname, optval, optlen);
}

int STDCALL my_recvfrom(SOCKET s, char *buf, int len, int flags,
        struct sockaddr *from, int *fromlen)
{
    struct sockaddr_in sa;
    int local_fromlen = sizeof(sa);
    struct sockaddr_ipx *sa_ipx = (struct sockaddr_ipx *)from;
    int bytes_received;
#ifdef DEBUG
    char address_buf[INETSTR_MAX];
#endif /* defined(DEBUG) */

    if (!is_emulated_socket(s) || fromlen == NULL)
        return recvfrom(s, buf, len, flags, from, fromlen);

    if (*fromlen < (signed)sizeof(struct sockaddr_ipx)) {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    bytes_received = recvfrom(s, buf, len, flags,
            (struct sockaddr *)&sa, &local_fromlen);
    if (bytes_received == SOCKET_ERROR)
        return SOCKET_ERROR;

    sa_ipx->sa_family = AF_IPX;
    get_ipx_netnum(sa_ipx->sa_netnum);
    /* Save the IP address in the `sa_nodenum' field, so that my_sendto()
     * knows which IP address to send to.
     */
    memcpy(&sa_ipx->sa_nodenum[0], &sa.sin_addr, 4);
    memset(&sa_ipx->sa_nodenum[4], 0, 2);
    sa_ipx->sa_socket = sa.sin_port;

    *fromlen = sizeof(struct sockaddr_ipx);

#ifdef DEBUG
    inetstr(address_buf, &sa);
    log_msg(("recvfrom(): emulating incoming IPX packet from %s\n\n",
                address_buf));
#endif /* defined(DEBUG) */

    return bytes_received;
}

int STDCALL my_sendto(SOCKET s, const char *buf, int len, int flags,
        const struct sockaddr *to, int tolen)
{
    const struct sockaddr *sockaddr_to_use = to;
    struct sockaddr_in sa;
#ifdef DEBUG
    char address_buf[INETSTR_MAX];
#endif /* defined(DEBUG) */

    if (is_emulated_socket(s)) {
        const struct sockaddr_ipx *sa_ipx = (const struct sockaddr_ipx *)to;

        if (tolen < (signed)sizeof(struct sockaddr_ipx)) {
            WSASetLastError(WSAEFAULT);
            return SOCKET_ERROR;
        } else if (to->sa_family != AF_IPX) {
            WSASetLastError(WSAEAFNOSUPPORT);
            return SOCKET_ERROR;
        }

        sa.sin_family = AF_INET;
        sa.sin_port = sa_ipx->sa_socket;
        /* Use the first four bytes from the IPX node number as the IP address.
         * This works because in my_recvfrom(), the IP address is saved in the
         * `sa_nodenum' field in the returned `sockaddr_ipx' structure.
         *
         * Conveniently, the broadcast address in IPX is `FF FF FF FF FF FF'.
         * Thus, no special casing is needed to make broadcasting work, since
         * the first four bytes are equal to what is needed for broadcasting
         * over IPv4.
         */
        memcpy(&sa.sin_addr, sa_ipx->sa_nodenum, 4);
        memset(sa.sin_zero, 0, sizeof(sa.sin_zero));

        sockaddr_to_use = (const struct sockaddr *)&sa;
        tolen = sizeof(sa);

#ifdef DEBUG
        inetstr(address_buf, &sa);
        log_msg(("sendto(): emulating outgoing IPX packet to %s\n\n",
                    address_buf));
#endif /* defined(DEBUG) */
    }

    return sendto(s, buf, len, flags, sockaddr_to_use, tolen);
}

int STDCALL my_setsockopt(SOCKET s, int level, int optname, const char *optval,
        int optlen)
{
    if (level == NSPROTO_IPX) {
#define log_unsupported_optname_success(n)                                    \
        log_msg(("setsockopt(): option %s not "                               \
                    "implemented, returning success\n\n", n))
        switch (optname) {
        case IPX_PTYPE:
            log_unsupported_optname_success("IPX_PTYPE");
            return 0;
        case IPX_FILTERPTYPE:
            log_unsupported_optname_success("IPX_FILTERPTYPE");
            return 0;
        case IPX_DSTYPE:
            log_unsupported_optname_success("IPX_DSTYPE");
            return 0;
        case IPX_STOPFILTERPTYPE:
            log_unsupported_optname_success("IPX_STOPFILTERPTYPE");
            return 0;
        case IPX_EXTENDED_ADDRESS:
            log_unsupported_optname_success("IPX_EXTENDED_ADDRESS");
            return 0;
        case IPX_RECVHDR:
            log_unsupported_optname_success("IPX_RECVHDR");
            return 0;
        case IPX_MAXSIZE:
            log_unsupported_optname_success("IPX_MAXSIZE");
            return 0;
        case IPX_ADDRESS:
            log_unsupported_optname_success("IPX_ADDRESS");
            return 0;
        case IPX_GETNETINFO:
            log_unsupported_optname_success("IPX_GETNETINFO");
            return 0;
        case IPX_GETNETINFO_NORIP:
            log_unsupported_optname_success("IPX_GETNETINFO_NORIP");
            return 0;
        case IPX_SPXGETCONNECTIONSTATUS:
            log_unsupported_optname_success("IPX_SPXGETCONNECTIONSTATUS");
            return 0;
        case IPX_ADDRESS_NOTIFY:
            log_unsupported_optname_success("IPX_ADDRESS_NOTIFY");
            return 0;
        case IPX_MAX_ADAPTER_NUM:
            log_unsupported_optname_success("IPX_MAX_ADAPTER_NUM");
            return 0;
        case IPX_RERIPNETNUMBER:
            log_unsupported_optname_success("IPX_RERIPNETNUMBER");
            return 0;
        case IPX_RECEIVE_BROADCAST:
            log_unsupported_optname_success("IPX_RECEIVE_BROADCAST");
            return 0;
        case IPX_IMMEDIATESPXACK:
            log_unsupported_optname_success("IPX_IMMEDIATESPXACK");
            return 0;
        default:
            log_msg(("setsockopt(): option 0x%08X not implemented, "
                        "returning failure\n\n", optname));
            return SOCKET_ERROR;
        }
#undef log_unsupported_optname_success
    }

    return setsockopt(s, level, optname, optval, optlen);
}

SOCKET STDCALL my_socket(int af, int type, int protocol)
{
    SOCKET s;
    int emulate = 0;

    if (af == AF_IPX && type == SOCK_DGRAM && protocol == NSPROTO_IPX) {
        emulate = 1;

        af = AF_INET;
        type = SOCK_DGRAM;
        protocol = IPPROTO_UDP;
    }

    /* If one creates a datagram UDP socket using WSASocket() without passing
     * WSA_FLAG_OVERLAPPED in dwFlags, deadlocks can occur in at least one
     * situation. For example, if one thread is blocking on recvfrom() or
     * WSARecvFrom(), and another thread calls closesocket(), then both the
     * call to recvfrom() or WSARecvFrom() and closesocket() will hang.
     * The bug occurs on:
     *   - Windows 7 SP1
     *   - Windows Vista SP2
     *   - Windows Server 2003 SP2
     *   - Windows XP x64 SP2
     *   - Windows XP x86 SP3
     *   - Windows 2000 SP4
     *   - Windows NT4 SP6a
     * The bug does not occur on:
     *   - Windows 98 SE
     *   - Windows 95
     * Note that this does not occur when using socket() instead of
     * WSASocket().
     *
     * The above bug would occur in Dune 2000 in the DirectX DirectPlay
     * libraries when using WSASocket() here.
     */
    s = socket(af, type, protocol);

    if (emulate && s != INVALID_SOCKET) {
        if (!add_emulated_socket(s)) {
            closesocket(s);

            WSASetLastError(WSAENOBUFS);
            return SOCKET_ERROR;
        }
    }

    log_msg(("socket(): s=0x%X (IS%s emulated)\n\n",
                s, emulate ? "" : " NOT"));

    return s;
}

void dummy_GetAddressByNameA(void)
{
    log_export_call("GetAddressByNameA");
    panic("GetAddressByNameA");
}

void dummy_GetAddressByNameW(void)
{
    log_export_call("GetAddressByNameW");
    panic("GetAddressByNameW");
}

int STDCALL my_EnumProtocolsA(LPINT lpiProtocols, LPVOID lpProtocolBuffer,
        LPDWORD lpdwBufferLength)
{
    return my_EnumProtocolsA_impl(lpiProtocols, lpProtocolBuffer,
            lpdwBufferLength);
}

int STDCALL my_EnumProtocolsW(LPINT lpiProtocols, LPVOID lpProtocolBuffer,
        LPDWORD lpdwBufferLength)
{
    return my_EnumProtocolsW_impl(lpiProtocols, lpProtocolBuffer,
            lpdwBufferLength);
}

void dummy_SetServiceA(void)
{
    log_export_call("SetServiceA");
    panic("SetServiceA");
}

void dummy_SetServiceW(void)
{
    log_export_call("SetServiceW");
    panic("SetServiceW");
}

void dummy_GetServiceA(void)
{
    log_export_call("GetServiceA");
    panic("GetServiceA");
}

void dummy_GetServiceW(void)
{
    log_export_call("GetServiceW");
    panic("GetServiceW");
}
