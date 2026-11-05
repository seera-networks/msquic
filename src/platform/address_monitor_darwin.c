/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Apple backend for the local address monitor: a PF_ROUTE subscription and a
    getifaddrs enumeration.

    Shaped like the Linux backend, which it is much closer to than to Windows:
    a socket to read notifications from, a thread of its own, and the poll
    timeout as the debounce window. The one substitution is the wake-up for
    shutdown -- Linux uses eventfd, which Apple does not have, so this uses a
    pipe and writes one byte into it.

    The design sketch put the route socket on worker 0's kqueue instead. That
    was not taken for the same reason the Linux backend did not take worker 0's
    epoll: the datapath's event queue abstraction carries self-posted
    completions rather than foreign descriptors, and there would still be no
    debounce timer. One thread, created only when a consumer asks for
    monitoring, costs less.

    macOS only, which CI settled rather than speculation: the iOS SDK does not
    ship net/route.h, so there is no routing socket to subscribe to there at
    all -- the question #138 raised about PF_ROUTE delivery to a sandboxed
    application does not even get as far as delivery. address_monitor.h records
    why iOS gets the not-supported stub instead of an enumeration with nothing
    behind it.

--*/

#include "platform_internal.h"
#include "address_monitor.h"

#ifdef QUIC_CLOG
#include "address_monitor_darwin.c.clog.h"
#endif

#if defined(CXPLAT_ADDRESS_MONITOR_SUPPORTED)

#include <ifaddrs.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

//
// Enough for the largest routing message the kernel will hand us in one read.
//
#define CXPLAT_ROUTE_BUFFER_SIZE 4096

//
// How long to wait before retrying an enumeration that failed, doubling to
// this bound. Matches the other backends.
//
#define CXPLAT_ADDRESS_MONITOR_MAX_RETRY_MS 5000

typedef struct CXPLAT_ADDRESS_MONITOR_OS {
    int RouteFd;            // PF_ROUTE subscription, read by the thread
    int ShutdownFds[2];     // pipe; one byte written to stop the thread
    CXPLAT_THREAD Thread;
    BOOLEAN ThreadStarted;
} CXPLAT_ADDRESS_MONITOR_OS;

static
QUIC_STATUS
CxPlatAddressMonitorStatusFromError(
    _In_ int Error
    )
{
    switch (Error) {
    case ENOMEM:
    case ENOBUFS:
        return QUIC_STATUS_OUT_OF_MEMORY;
    case EPERM:
    case EACCES:
        return QUIC_STATUS_NOT_SUPPORTED;
    default:
        return QUIC_STATUS_INTERNAL_ERROR;
    }
}

//
// getifaddrs reports no media type, and there is no equivalent of netlink's
// ARPHRD_* on the interface record. What callers actually key on is loopback --
// the functional tests pick a test interface that way -- so that is reported
// exactly, from IFF_LOOPBACK, and everything else is "other" rather than a
// guess at ethernet. Claiming ethernetCsmacd for a cellular or tunnel
// interface would be worse than admitting it is unknown.
//
static
uint16_t
CxPlatAddressMonitorIfType(
    _In_ unsigned int Flags
    )
{
    return (Flags & IFF_LOOPBACK) ? 24 : 1; // softwareLoopback : other
}

//
// The IPv6 per-address flags, which getifaddrs does not carry. Needs a socket
// to ioctl on; the caller makes one for the whole enumeration rather than one
// per address.
//
static
void
CxPlatAddressMonitorApplyIn6Flags(
    _In_ int Ioctl6Fd,
    _In_z_ const char* Name,
    _In_ const struct sockaddr_in6* Sin6,
    _Inout_ CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Entry
    )
{
    if (Ioctl6Fd == -1) {
        return;
    }

    struct in6_ifreq Request;
    CxPlatZeroMemory(&Request, sizeof(Request));
    CxPlatCopyMemory(Request.ifr_name, Name, CXPLAT_MIN(strlen(Name), sizeof(Request.ifr_name) - 1));
    Request.ifr_ifru.ifru_addr = *Sin6;

    if (ioctl(Ioctl6Fd, SIOCGIFAFLAG_IN6, &Request) != 0) {
        //
        // No flags available for this one. Left as they were rather than
        // guessed: the filter treats a missing DEPRECATED as "not deprecated",
        // which is the same answer it would give for an address the OS does
        // not track lifetimes for.
        //
        return;
    }

    const int Flags6 = Request.ifr_ifru.ifru_flags6;

    if (Flags6 & IN6_IFF_DEPRECATED) {
        Entry->Address.Flags |= CXPLAT_ADDRESS_FLAG_DEPRECATED;
    }
    if (Flags6 & IN6_IFF_TEMPORARY) {
        //
        // Apple reports this one honestly -- unlike Windows, where a randomized
        // interface identifier makes the stable address indistinguishable from
        // the RFC 8981 one -- so the flag is set here.
        //
        Entry->Address.Flags |= CXPLAT_ADDRESS_FLAG_TEMPORARY;
    }
    if (Flags6 & (IN6_IFF_TENTATIVE | IN6_IFF_DUPLICATED)) {
        Entry->Tentative = TRUE;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatAddressMonitorOsEnumerate(
    _Inout_ CXPLAT_ADDRESS_MONITOR* Monitor,
    _Outptr_result_buffer_maybenull_(*RawCount) CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS** Raw,
    _Out_ uint32_t* RawCount
    )
{
    UNREFERENCED_PARAMETER(Monitor);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    struct ifaddrs* Addrs = NULL;
    CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Entries = NULL;
    int Ioctl6Fd = -1;

    *Raw = NULL;
    *RawCount = 0;

    if (getifaddrs(&Addrs) != 0) {
        const int Error = errno;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            (uint32_t)Error,
            "getifaddrs(address monitor) failed");
        return CxPlatAddressMonitorStatusFromError(Error);
    }

    uint32_t Count = 0;
    for (const struct ifaddrs* Iter = Addrs; Iter != NULL; Iter = Iter->ifa_next) {
        if (Iter->ifa_addr == NULL) {
            continue;
        }
        if (Iter->ifa_addr->sa_family == AF_INET ||
            Iter->ifa_addr->sa_family == AF_INET6) {
            ++Count;
        }
    }

    if (Count == 0) {
        //
        // A host with no unicast address at all. An empty snapshot, not a
        // failure.
        //
        goto Exit;
    }

    Entries =
        CXPLAT_ALLOC_NONPAGED(
            Count * sizeof(CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS),
            QUIC_POOL_DATAPATH_ADDRESSES);
    if (Entries == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "address monitor raw addresses",
            (uint64_t)Count * sizeof(CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    //
    // One socket for every SIOCGIFAFLAG_IN6 below. Its failure is not fatal:
    // without it the IPv6 per-address flags are simply unknown, which the
    // filter handles.
    //
    Ioctl6Fd = socket(AF_INET6, SOCK_DGRAM, 0);

    uint32_t Index = 0;
    for (const struct ifaddrs* Iter = Addrs; Iter != NULL && Index < Count; Iter = Iter->ifa_next) {
        if (Iter->ifa_addr == NULL) {
            continue;
        }
        const sa_family_t Family = Iter->ifa_addr->sa_family;
        if (Family != AF_INET && Family != AF_INET6) {
            continue;
        }

        CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Entry = &Entries[Index];
        CxPlatZeroMemory(Entry, sizeof(*Entry));

        if (Family == AF_INET) {
            CxPlatCopyMemory(
                &Entry->Address.Address.Ipv4,
                Iter->ifa_addr,
                sizeof(struct sockaddr_in));
        } else {
            CxPlatCopyMemory(
                &Entry->Address.Address.Ipv6,
                Iter->ifa_addr,
                sizeof(struct sockaddr_in6));
        }
        QuicAddrSetPort(&Entry->Address.Address, 0);

        Entry->Address.InterfaceIndex = if_nametoindex(Iter->ifa_name);
        Entry->Address.InterfaceType = CxPlatAddressMonitorIfType(Iter->ifa_flags);

        //
        // IFF_RUNNING as well as IFF_UP, matching the Linux backend: IFF_UP is
        // the administrative state, and an interface configured up with no
        // carrier is not one to put a connection on.
        //
        Entry->InterfaceUp =
            (Iter->ifa_flags & IFF_UP) && (Iter->ifa_flags & IFF_RUNNING);

        if (Iter->ifa_flags & IFF_LOOPBACK) {
            Entry->Address.Flags |= CXPLAT_ADDRESS_FLAG_LOOPBACK;
        }

        if (Family == AF_INET6) {
            const struct sockaddr_in6* Sin6 = (const struct sockaddr_in6*)Iter->ifa_addr;
            if (IN6_IS_ADDR_LINKLOCAL(&Sin6->sin6_addr)) {
                Entry->Address.Flags |= CXPLAT_ADDRESS_FLAG_LINK_LOCAL;
            }

            //
            // The ioctl is given the address as the kernel handed it over,
            // before the normalization below, because that is the form the
            // kernel indexes its addresses by.
            //
            CxPlatAddressMonitorApplyIn6Flags(Ioctl6Fd, Iter->ifa_name, Sin6, Entry);

            if (IN6_IS_ADDR_LINKLOCAL(&Entry->Address.Address.Ipv6.sin6_addr)) {
                //
                // Apple hands back link-local addresses in the KAME form, with
                // the interface index buried in bytes 2 and 3 of the address
                // and sin6_scope_id left at zero. Nothing else in the tree
                // speaks that dialect -- the header here promises the scope ID
                // is set -- so an address left as-is would compare unequal to
                // the same address seen through a socket, and phase 3's path
                // matching would never recognise it.
                //
                uint8_t* Bytes = Entry->Address.Address.Ipv6.sin6_addr.s6_addr;
                const uint32_t Embedded = ((uint32_t)Bytes[2] << 8) | Bytes[3];
                if (Embedded != 0) {
                    if (Entry->Address.Address.Ipv6.sin6_scope_id == 0) {
                        Entry->Address.Address.Ipv6.sin6_scope_id = Embedded;
                    }
                    Bytes[2] = 0;
                    Bytes[3] = 0;
                }
            }
        } else {
            uint8_t Bytes[4];
            CxPlatCopyMemory(Bytes, &Entry->Address.Address.Ipv4.sin_addr, sizeof(Bytes));
            if (Bytes[0] == 169 && Bytes[1] == 254) {
                Entry->Address.Flags |= CXPLAT_ADDRESS_FLAG_LINK_LOCAL;
            }
        }

        ++Index;
    }

    *Raw = Entries;
    *RawCount = Index;
    Entries = NULL;

Exit:

    if (Ioctl6Fd != -1) {
        close(Ioctl6Fd);
    }
    if (Entries != NULL) {
        CXPLAT_FREE(Entries, QUIC_POOL_DATAPATH_ADDRESSES);
    }
    freeifaddrs(Addrs);
    return Status;
}

//
// Drains everything the route socket has. The content is ignored beyond "is
// this worth a resync": the snapshot comes from re-enumerating, not from the
// message, so parsing the message bodies would only be a second way to be
// wrong.
//
static
void
CxPlatAddressMonitorDrain(
    _In_ int RouteFd,
    _Out_ BOOLEAN* Notified,
    _Inout_ BOOLEAN* RouteChanged
    )
{
    *Notified = FALSE;

    uint8_t Buffer[CXPLAT_ROUTE_BUFFER_SIZE];
    for (;;) {
        const ssize_t Read = recv(RouteFd, Buffer, sizeof(Buffer), MSG_DONTWAIT);
        if (Read <= 0) {
            if (Read < 0 && errno == EINTR) {
                continue;
            }
            //
            // EAGAIN means drained. Anything else is reported by the next
            // poll, and a resync is scheduled anyway if something was read.
            //
            break;
        }

        //
        // A single read can carry several messages back to back.
        //
        size_t Offset = 0;
        while (Offset + sizeof(struct rt_msghdr) <= (size_t)Read) {
            const struct rt_msghdr* Header = (const struct rt_msghdr*)(Buffer + Offset);
            if (Header->rtm_msglen == 0 ||
                Offset + Header->rtm_msglen > (size_t)Read) {
                break;
            }

            switch (Header->rtm_type) {
            case RTM_NEWADDR:
            case RTM_DELADDR:
            case RTM_IFINFO:
                *Notified = TRUE;
                break;
            case RTM_ADD:
            case RTM_DELETE:
            case RTM_CHANGE:
                *Notified = TRUE;
                *RouteChanged = TRUE;
                break;
            default:
                break;
            }

            Offset += Header->rtm_msglen;
        }
    }
}

//
// The subscription thread. Its poll timeout is the debounce window, so a burst
// of messages -- the normal shape of an interface transition -- produces one
// resync once the host has been quiet, rather than one per message.
//
CXPLAT_THREAD_CALLBACK(CxPlatAddressMonitorThread, Context)
{
    CXPLAT_ADDRESS_MONITOR* Monitor = (CXPLAT_ADDRESS_MONITOR*)Context;
    CXPLAT_ADDRESS_MONITOR_OS* Os = Monitor->Os;

    BOOLEAN DebouncePending = FALSE;
    BOOLEAN RouteChanged = FALSE;
    uint64_t DebounceDeadline = 0;
    uint32_t RetryMs = 0;

    for (;;) {
        int Timeout = -1;
        if (DebouncePending) {
            const uint64_t Now = CxPlatTimeUs64();
            //
            // Rounded up. Truncating leaves a timeout of zero for the last
            // sub-millisecond of every window, which returns at once while the
            // deadline check below still says not yet -- a spin until the
            // microseconds ran out.
            //
            Timeout =
                CxPlatTimeAtOrBefore64(DebounceDeadline, Now) ?
                    0 : (int)US_TO_MS_CEIL(DebounceDeadline - Now);
        }

        struct pollfd PollFds[2];
        PollFds[0].fd = Os->ShutdownFds[0];
        PollFds[0].events = POLLIN;
        PollFds[0].revents = 0;
        PollFds[1].fd = Os->RouteFd;
        PollFds[1].events = POLLIN;
        PollFds[1].revents = 0;

        const int Ready = poll(PollFds, 2, Timeout);
        if (Ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                (uint32_t)errno,
                "poll(address monitor) failed");
            break;
        }

        if (PollFds[0].revents != 0) {
            //
            // Shutdown. Any pending debounce is abandoned deliberately: the
            // consumer is going away, so a last callback would be delivered to
            // something on its way out.
            //
            break;
        }

        if (PollFds[1].revents != 0) {
            BOOLEAN Notified = FALSE;
            CxPlatAddressMonitorDrain(Os->RouteFd, &Notified, &RouteChanged);
            if (Notified && !DebouncePending) {
                DebouncePending = TRUE;
                DebounceDeadline =
                    CxPlatTimeUs64() + MS_TO_US((uint64_t)Monitor->DebounceMs);
            }
        }

        if (DebouncePending && CxPlatTimeAtOrBefore64(DebounceDeadline, CxPlatTimeUs64())) {
            if (CxPlatAddressMonitorResync(
                    Monitor, Monitor->WatchRoutes && RouteChanged)) {
                DebouncePending = FALSE;
                RouteChanged = FALSE;
                RetryMs = 0;
            } else {
                //
                // The enumeration failed. The window stays armed and backs off
                // rather than being cleared: there may be no further message to
                // retry on, and an address that appeared during the failure
                // would otherwise stay invisible.
                //
                RetryMs =
                    RetryMs == 0 ?
                        Monitor->DebounceMs :
                        CXPLAT_MIN(RetryMs * 2, CXPLAT_ADDRESS_MONITOR_MAX_RETRY_MS);
                DebounceDeadline = CxPlatTimeUs64() + MS_TO_US((uint64_t)RetryMs);
            }
        }
    }

    CXPLAT_THREAD_RETURN(0);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatAddressMonitorOsInitialize(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ CXPLAT_ADDRESS_MONITOR* Monitor
    )
{
    UNREFERENCED_PARAMETER(Datapath);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    CXPLAT_ADDRESS_MONITOR_OS* Os =
        CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_ADDRESS_MONITOR_OS), QUIC_POOL_DATAPATH);
    if (Os == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "address monitor os state",
            (uint64_t)sizeof(CXPLAT_ADDRESS_MONITOR_OS));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    CxPlatZeroMemory(Os, sizeof(*Os));
    Os->RouteFd = -1;
    Os->ShutdownFds[0] = -1;
    Os->ShutdownFds[1] = -1;
    Monitor->Os = Os;

    //
    // Subscribed before the first enumeration, so a change arriving during
    // startup is not lost: it sits in the socket buffer and the thread sees it
    // on its first poll.
    //
    Os->RouteFd = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
    if (Os->RouteFd == -1) {
        const int Error = errno;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            (uint32_t)Error,
            "socket(PF_ROUTE) failed");
        Status = CxPlatAddressMonitorStatusFromError(Error);
        goto Error;
    }

    if (pipe(Os->ShutdownFds) != 0) {
        const int Error = errno;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            (uint32_t)Error,
            "pipe(address monitor) failed");
        Status = CxPlatAddressMonitorStatusFromError(Error);
        goto Error;
    }

    //
    // The first enumeration is synchronous and silent: callers get a usable
    // snapshot the moment Initialize returns, with no callback for it. Each
    // backend does this; the shared Initialize does not.
    //
    CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Raw = NULL;
    uint32_t RawCount = 0;
    Status = CxPlatAddressMonitorOsEnumerate(Monitor, &Raw, &RawCount);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    //
    // Tested together, not RawCount alone: a successful enumeration with
    // nothing to report hands back a null pointer with a zero count.
    //
    if (Raw != NULL && RawCount != 0) {
        Monitor->Addresses =
            CXPLAT_ALLOC_NONPAGED(
                RawCount * sizeof(CXPLAT_LOCAL_ADDRESS), QUIC_POOL_DATAPATH_ADDRESSES);
        if (Monitor->Addresses == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "address monitor initial snapshot",
                (uint64_t)RawCount * sizeof(CXPLAT_LOCAL_ADDRESS));
            CXPLAT_FREE(Raw, QUIC_POOL_DATAPATH_ADDRESSES);
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }
        CxPlatAddressMonitorFilter(
            Raw, RawCount, Monitor->Addresses, &Monitor->AddressCount);
    }
    if (Raw != NULL) {
        CXPLAT_FREE(Raw, QUIC_POOL_DATAPATH_ADDRESSES);
    }
    Monitor->Generation = 1;

    CXPLAT_THREAD_CONFIG ThreadConfig = {
        0, 0, "quic_addrmon", CxPlatAddressMonitorThread, Monitor
    };
    Status = CxPlatThreadCreate(&ThreadConfig, &Os->Thread);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            (uint32_t)Status,
            "CxPlatThreadCreate(address monitor)");
        goto Error;
    }
    Os->ThreadStarted = TRUE;

    return QUIC_STATUS_SUCCESS;

Error:

    CxPlatAddressMonitorOsUninitialize(Monitor);
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatAddressMonitorOsUninitialize(
    _Inout_ CXPLAT_ADDRESS_MONITOR* Monitor
    )
{
    CXPLAT_ADDRESS_MONITOR_OS* Os = Monitor->Os;
    if (Os == NULL) {
        return;
    }

    if (Os->ThreadStarted) {
        //
        // One byte is all the thread reads for; it checks the descriptor rather
        // than the content.
        //
        const uint8_t One = 1;
        if (write(Os->ShutdownFds[1], &One, sizeof(One)) != (ssize_t)sizeof(One)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                (uint32_t)errno,
                "write(address monitor shutdown) failed");
            //
            // Fall through to the wait regardless. Closing the route socket
            // below would make poll return on it, so the thread still leaves.
            //
        }
        CxPlatThreadWait(&Os->Thread);
        CxPlatThreadDelete(&Os->Thread);
        Os->ThreadStarted = FALSE;
    }

    if (Os->ShutdownFds[0] != -1) {
        close(Os->ShutdownFds[0]);
    }
    if (Os->ShutdownFds[1] != -1) {
        close(Os->ShutdownFds[1]);
    }
    if (Os->RouteFd != -1) {
        close(Os->RouteFd);
    }

    CXPLAT_FREE(Os, QUIC_POOL_DATAPATH);
    Monitor->Os = NULL;
}

#endif // CXPLAT_ADDRESS_MONITOR_SUPPORTED
