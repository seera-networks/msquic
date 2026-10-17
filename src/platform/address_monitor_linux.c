/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Linux backend for the local address monitor: a NETLINK_ROUTE subscription
    and an RTM_GETADDR/RTM_GETLINK enumeration.

    The subscription runs on a thread of its own, and the debounce window is the
    poll timeout rather than a separate timer. The alternative was worker 0's
    event queue, as the design sketched, but the datapath's event queue
    abstraction carries self-posted completions rather than foreign descriptors
    -- epoll watches a descriptor through epoll_ctl, io_uring would need a poll
    submission re-armed per completion -- so that route meant two integrations
    and no debounce timer in either. One thread, only ever created when a
    consumer asks for monitoring, costs less than that.

--*/

#include "platform_internal.h"
#include "address_monitor.h"

#ifdef QUIC_CLOG
#include "address_monitor_linux.c.clog.h"
#endif

//
// linux/if.h rather than net/if.h, for IFF_RUNNING. The two define the IFF_
// values differently, and including the glibc one alongside linux/if_arp.h --
// which brings the kernel definitions with it -- is a redeclaration error
// whichever comes second. Staying entirely on the kernel headers also lets
// these stay in the sorted order clang-tidy asks for.
//
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <sys/eventfd.h>

//
// Larger than the kernel's usual dump chunk. The first chunk of a dump is sized
// from NLMSG_GOODSIZE, which follows the page size, so on a 64K-page kernel it
// can exceed the 8192 that is plenty elsewhere -- and a short read would lose
// the tail of a reply silently, or lose NLMSG_DONE and turn the dump into a
// timeout. MSG_TRUNC below turns any remaining case into an error rather than
// missing addresses.
//
#define CXPLAT_NETLINK_BUFFER_SIZE 32768

//
// A backstop against a kernel that streams a dump without ever sending
// NLMSG_DONE. The poll timeout below is the real termination guarantee -- a
// kernel that stops talking is caught there -- so this only has to be above
// any host that exists: 4096 was not, since thousands of /32 service addresses
// on lo or a dummy interface is an ordinary load balancer. At this bound the
// address array peaks around six megabytes.
//
#define CXPLAT_NETLINK_MAX_DUMP_MESSAGES 65536

//
// Ceiling on the retry backoff after a failed enumeration. Long enough not to
// spin against whatever is wrong, short enough that a host which recovers is
// noticed without waiting for the next address change.
//
#define CXPLAT_ADDRESS_MONITOR_MAX_RETRY_MS 5000

typedef struct CXPLAT_ADDRESS_MONITOR_OS {
    int NetlinkFd;      // Subscription, read by the thread
    int ShutdownFd;     // eventfd, written once to stop the thread
    CXPLAT_THREAD Thread;
    BOOLEAN ThreadStarted;
} CXPLAT_ADDRESS_MONITOR_OS;

//
// An interface's operational state, gathered once per enumeration so each
// address can be judged without a syscall of its own.
//
typedef struct CXPLAT_INTERFACE_STATE {
    uint32_t Index;
    uint16_t Type;
    BOOLEAN Up;
} CXPLAT_INTERFACE_STATE;

typedef struct CXPLAT_INTERFACE_TABLE {
    CXPLAT_INTERFACE_STATE* Entries;
    uint32_t Count;
    uint32_t Capacity;
    //
    // An interface that could not be recorded would leave every address on it
    // looking like it was on a down interface, so the filter would drop them
    // all and the resync would report each as removed -- the very answer
    // CxPlatAddressMonitorResync refuses to give when an enumeration fails.
    // Failing the enumeration instead is the honest outcome.
    //
    BOOLEAN AllocFailed;
} CXPLAT_INTERFACE_TABLE;

static
QUIC_STATUS
CxPlatNetlinkOpen(
    _In_ uint32_t Groups,
    _Out_ int* Fd
    )
{
    const int NetlinkFd =
        socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (NetlinkFd == -1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            errno,
            "socket(AF_NETLINK, NETLINK_ROUTE) failed");
        return (QUIC_STATUS)errno;
    }

    struct sockaddr_nl Address;
    CxPlatZeroMemory(&Address, sizeof(Address));
    Address.nl_family = AF_NETLINK;
    Address.nl_groups = Groups;

    if (bind(NetlinkFd, (struct sockaddr*)&Address, sizeof(Address)) != 0) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            errno,
            "bind(AF_NETLINK) failed");
        close(NetlinkFd);
        return (QUIC_STATUS)errno;
    }

    *Fd = NetlinkFd;
    return QUIC_STATUS_SUCCESS;
}

//
// Sends an RTM_GET* dump request and hands every reply message to Handler.
// Returns once NLMSG_DONE arrives.
//
static
QUIC_STATUS
CxPlatNetlinkDump(
    _In_ uint16_t Type,
    _In_ uint8_t Family,
    _In_ void (*Handler)(const struct nlmsghdr*, void*),
    _In_opt_ void* Context
    )
{
    int Fd = -1;
    QUIC_STATUS Status = CxPlatNetlinkOpen(0, &Fd);
    if (QUIC_FAILED(Status)) {
        return Status;
    }

    struct {
        struct nlmsghdr Header;
        struct rtgenmsg Message;
    } Request;
    CxPlatZeroMemory(&Request, sizeof(Request));
    Request.Header.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    Request.Header.nlmsg_type = Type;
    Request.Header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    Request.Header.nlmsg_seq = 1;
    Request.Message.rtgen_family = Family;

    if (send(Fd, &Request, Request.Header.nlmsg_len, 0) == -1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            errno,
            "send(netlink dump request) failed");
        Status = (QUIC_STATUS)errno;
        goto Exit;
    }

    uint8_t* Buffer =
        CXPLAT_ALLOC_NONPAGED(CXPLAT_NETLINK_BUFFER_SIZE, QUIC_POOL_PLATFORM_TMP_ALLOC);
    if (Buffer == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "netlink dump buffer",
            (uint64_t)CXPLAT_NETLINK_BUFFER_SIZE);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    BOOLEAN Done = FALSE;
    uint32_t MessagesSeen = 0;

    while (!Done) {
        //
        // The request socket is non-blocking, so wait for the reply rather than
        // spinning on EAGAIN.
        //
        struct pollfd PollFd = { .fd = Fd, .events = POLLIN };
        const int Ready = poll(&PollFd, 1, 1000);
        if (Ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            Status = (QUIC_STATUS)errno;
            break;
        }
        if (Ready == 0) {
            //
            // The kernel answers a dump promptly or not at all; a second of
            // silence means something is wrong, and giving up leaves the stored
            // snapshot in place rather than replacing it with a partial one.
            //
            Status = QUIC_STATUS_INTERNAL_ERROR;
            break;
        }

        //
        // MSG_TRUNC makes recv report the datagram's real length rather than
        // what fitted, so a buffer that was too small is an error here instead
        // of silently dropped addresses.
        //
        const ssize_t Received = recv(Fd, Buffer, CXPLAT_NETLINK_BUFFER_SIZE, MSG_TRUNC);
        if (Received < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            Status = (QUIC_STATUS)errno;
            break;
        }
        if ((size_t)Received > CXPLAT_NETLINK_BUFFER_SIZE) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                (uint32_t)Received,
                "netlink dump reply larger than the read buffer");
            Status = QUIC_STATUS_INTERNAL_ERROR;
            break;
        }

        //
        // NLMSG_NEXT consumes from its length argument, so it needs a mutable
        // one of its own.
        //
        uint32_t Length = (uint32_t)Received;
        for (struct nlmsghdr* Header = (struct nlmsghdr*)Buffer;
             NLMSG_OK(Header, Length);
             Header = NLMSG_NEXT(Header, Length)) {

            if (Header->nlmsg_type == NLMSG_DONE) {
                Done = TRUE;
                break;
            }
            if (Header->nlmsg_type == NLMSG_ERROR) {
                Status = QUIC_STATUS_INTERNAL_ERROR;
                Done = TRUE;
                break;
            }
            if (++MessagesSeen > CXPLAT_NETLINK_MAX_DUMP_MESSAGES) {
                Status = QUIC_STATUS_INTERNAL_ERROR;
                Done = TRUE;
                break;
            }
            Handler(Header, Context);
        }
    }

    CXPLAT_FREE(Buffer, QUIC_POOL_PLATFORM_TMP_ALLOC);

Exit:

    close(Fd);
    return Status;
}

static
void
CxPlatInterfaceTableAdd(
    _Inout_ CXPLAT_INTERFACE_TABLE* Table,
    _In_ const CXPLAT_INTERFACE_STATE* Entry
    )
{
    if (Table->Count == Table->Capacity) {
        const uint32_t NewCapacity = Table->Capacity == 0 ? 16 : Table->Capacity * 2;
        CXPLAT_INTERFACE_STATE* NewEntries =
            CXPLAT_ALLOC_NONPAGED(
                NewCapacity * sizeof(CXPLAT_INTERFACE_STATE), QUIC_POOL_PLATFORM_TMP_ALLOC);
        if (NewEntries == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "address monitor interface table",
                NewCapacity * sizeof(CXPLAT_INTERFACE_STATE));
            Table->AllocFailed = TRUE;
            return;
        }
        if (Table->Entries != NULL) {
            CxPlatCopyMemory(
                NewEntries, Table->Entries, Table->Count * sizeof(CXPLAT_INTERFACE_STATE));
            CXPLAT_FREE(Table->Entries, QUIC_POOL_PLATFORM_TMP_ALLOC);
        }
        Table->Entries = NewEntries;
        Table->Capacity = NewCapacity;
    }
    Table->Entries[Table->Count++] = *Entry;
}

static
const CXPLAT_INTERFACE_STATE*
CxPlatInterfaceTableFind(
    _In_ const CXPLAT_INTERFACE_TABLE* Table,
    _In_ uint32_t Index
    )
{
    for (uint32_t i = 0; i < Table->Count; ++i) {
        if (Table->Entries[i].Index == Index) {
            return &Table->Entries[i];
        }
    }
    return NULL;
}

//
// Netlink reports an interface's ARPHRD_* hardware type, but CXPLAT_LOCAL_ADDRESS
// and CXPLAT_ADAPTER_ADDRESS both specify an IANA ifType -- which is what the
// Windows backend gets from GetIfTable2 and what consumers compare against,
// CXPLAT_IF_TYPE_SOFTWARE_LOOPBACK among them. Passing ARPHRD_LOOPBACK (772)
// through as if it were the IANA 24 would mean no caller could ever recognise
// loopback on Linux.
//
// Only the types a QUIC path plausibly runs over are mapped; anything else
// becomes "other", which is the honest answer rather than a guess.
//
static
uint16_t
CxPlatInterfaceTypeFromArpHrd(
    _In_ uint16_t ArpHrd
    )
{
    switch (ArpHrd) {
    case ARPHRD_LOOPBACK:
        return 24;  // softwareLoopback
    case ARPHRD_ETHER:
    case ARPHRD_IEEE802:    // token-ring framing, still ethernetCsmacd here
        return 6;   // ethernetCsmacd
    case ARPHRD_IEEE80211:
        return 71;  // ieee80211
    case ARPHRD_PPP:
        return 23;  // ppp
    case ARPHRD_TUNNEL:
    case ARPHRD_TUNNEL6:
    case ARPHRD_SIT:
    case ARPHRD_IPGRE:
    case ARPHRD_NONE:       // tun, which presents as a tunnel
        return 131; // tunnel
    default:
        return 1;   // other
    }
}

static
void
CxPlatNetlinkOnLinkMessage(
    _In_ const struct nlmsghdr* Header,
    _In_opt_ void* Context
    )
{
    CXPLAT_INTERFACE_TABLE* Table = (CXPLAT_INTERFACE_TABLE*)Context;
    if (Header->nlmsg_type != RTM_NEWLINK ||
        Header->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg))) {
        return;
    }

    const struct ifinfomsg* Info = (const struct ifinfomsg*)NLMSG_DATA(Header);
    CXPLAT_INTERFACE_STATE Entry;
    Entry.Index = (uint32_t)Info->ifi_index;
    Entry.Type = CxPlatInterfaceTypeFromArpHrd(Info->ifi_type);
    //
    // IFF_RUNNING, not IFF_UP: the first says the link has carrier, the second
    // only that the interface is administratively enabled. An address on a
    // cable that is unplugged is not one to hand a consumer.
    //
    Entry.Up = (Info->ifi_flags & IFF_RUNNING) != 0;
    CxPlatInterfaceTableAdd(Table, &Entry);
}

typedef struct CXPLAT_ADDRESS_DUMP_CONTEXT {
    const CXPLAT_INTERFACE_TABLE* Interfaces;
    CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Addresses;
    uint32_t Count;
    uint32_t Capacity;
    BOOLEAN AllocFailed;
} CXPLAT_ADDRESS_DUMP_CONTEXT;

static
void
CxPlatNetlinkOnAddressMessage(
    _In_ const struct nlmsghdr* Header,
    _In_opt_ void* Context
    )
{
    CXPLAT_ADDRESS_DUMP_CONTEXT* Dump = (CXPLAT_ADDRESS_DUMP_CONTEXT*)Context;

    if (Header->nlmsg_type != RTM_NEWADDR ||
        Header->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifaddrmsg))) {
        return;
    }

    const struct ifaddrmsg* Message = (const struct ifaddrmsg*)NLMSG_DATA(Header);
    if (Message->ifa_family != AF_INET && Message->ifa_family != AF_INET6) {
        return;
    }

    //
    // IFA_FLAGS where the kernel provides it, since ifa_flags is only eight
    // bits wide and IFA_F_MANAGETEMPADDR and above do not fit. Falling back
    // keeps this working on kernels older than 3.14.
    //
    uint32_t Flags = Message->ifa_flags;
    const void* AddressBytes = NULL;
    uint32_t AddressLength = 0;

    uint32_t AttributeLength = Header->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    for (const struct rtattr* Attribute = IFA_RTA(Message);
         RTA_OK(Attribute, AttributeLength);
         Attribute = RTA_NEXT(Attribute, AttributeLength)) {
        switch (Attribute->rta_type) {
        case IFA_FLAGS:
            if (RTA_PAYLOAD(Attribute) >= sizeof(uint32_t)) {
                Flags = *(const uint32_t*)RTA_DATA(Attribute);
            }
            break;
        case IFA_ADDRESS:
            //
            // For a point-to-point link IFA_ADDRESS is the peer and IFA_LOCAL
            // is ours, so IFA_LOCAL wins where both appear. IPv6 only ever
            // carries IFA_ADDRESS.
            //
            if (AddressBytes == NULL) {
                AddressBytes = RTA_DATA(Attribute);
                AddressLength = RTA_PAYLOAD(Attribute);
            }
            break;
        case IFA_LOCAL:
            AddressBytes = RTA_DATA(Attribute);
            AddressLength = RTA_PAYLOAD(Attribute);
            break;
        default:
            break;
        }
    }

    if (AddressBytes == NULL) {
        return;
    }

    if (Dump->Count == Dump->Capacity) {
        const uint32_t NewCapacity = Dump->Capacity == 0 ? 32 : Dump->Capacity * 2;
        CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* NewAddresses =
            CXPLAT_ALLOC_NONPAGED(
                NewCapacity * sizeof(CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS),
                QUIC_POOL_DATAPATH_ADDRESSES);
        if (NewAddresses == NULL) {
            Dump->AllocFailed = TRUE;
            return;
        }
        if (Dump->Addresses != NULL) {
            CxPlatCopyMemory(
                NewAddresses,
                Dump->Addresses,
                Dump->Count * sizeof(CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS));
            CXPLAT_FREE(Dump->Addresses, QUIC_POOL_DATAPATH_ADDRESSES);
        }
        Dump->Addresses = NewAddresses;
        Dump->Capacity = NewCapacity;
    }

    CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Entry = &Dump->Addresses[Dump->Count];
    CxPlatZeroMemory(Entry, sizeof(*Entry));

    if (Message->ifa_family == AF_INET) {
        if (AddressLength < sizeof(struct in_addr)) {
            return;
        }
        Entry->Address.Address.Ip.sa_family = QUIC_ADDRESS_FAMILY_INET;
        CxPlatCopyMemory(
            &Entry->Address.Address.Ipv4.sin_addr, AddressBytes, sizeof(struct in_addr));
    } else {
        if (AddressLength < sizeof(struct in6_addr)) {
            return;
        }
        Entry->Address.Address.Ip.sa_family = QUIC_ADDRESS_FAMILY_INET6;
        CxPlatCopyMemory(
            &Entry->Address.Address.Ipv6.sin6_addr, AddressBytes, sizeof(struct in6_addr));
        //
        // The scope ID is what separates the same link-local address on two
        // interfaces, and the monitor's identity comparison uses it.
        //
        if (IN6_IS_ADDR_LINKLOCAL(
                (const struct in6_addr*)&Entry->Address.Address.Ipv6.sin6_addr)) {
            Entry->Address.Address.Ipv6.sin6_scope_id = Message->ifa_index;
        }
    }

    Entry->Address.InterfaceIndex = Message->ifa_index;

    const CXPLAT_INTERFACE_STATE* Interface =
        CxPlatInterfaceTableFind(Dump->Interfaces, Message->ifa_index);
    Entry->Address.InterfaceType = Interface != NULL ? Interface->Type : 0;
    Entry->InterfaceUp = Interface != NULL && Interface->Up;

    Entry->Tentative = (Flags & (IFA_F_TENTATIVE | IFA_F_DADFAILED)) != 0;

    //
    // Only for IPv6. IFA_F_TEMPORARY and IFA_F_SECONDARY are the same bit, so
    // over IPv4 this is set for any alias in a subnet the interface already
    // has -- and the flag is defined as an RFC 8981 privacy address, which core
    // will deprioritise. Reading every IPv4 secondary as one would be wrong in
    // the direction that quietly loses a perfectly good address.
    //
    if (Message->ifa_family == AF_INET6 && (Flags & IFA_F_TEMPORARY)) {
        Entry->Address.Flags |= CXPLAT_ADDRESS_FLAG_TEMPORARY;
    }
    if (Flags & IFA_F_DEPRECATED) {
        Entry->Address.Flags |= CXPLAT_ADDRESS_FLAG_DEPRECATED;
    }
    if (Message->ifa_scope == RT_SCOPE_LINK) {
        Entry->Address.Flags |= CXPLAT_ADDRESS_FLAG_LINK_LOCAL;
    }
    if (Message->ifa_scope == RT_SCOPE_HOST) {
        Entry->Address.Flags |= CXPLAT_ADDRESS_FLAG_LOOPBACK;
    }

    ++Dump->Count;
}

QUIC_STATUS
CxPlatAddressMonitorOsEnumerate(
    _Inout_ CXPLAT_ADDRESS_MONITOR* Monitor,
    _Outptr_result_buffer_(*RawCount) CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS** Raw,
    _Out_ uint32_t* RawCount
    )
{
    UNREFERENCED_PARAMETER(Monitor);

    CXPLAT_INTERFACE_TABLE Interfaces;
    CxPlatZeroMemory(&Interfaces, sizeof(Interfaces));

    //
    // Interfaces first: every address needs its interface's operational state,
    // and asking per address would be a syscall each.
    //
    QUIC_STATUS Status =
        CxPlatNetlinkDump(
            RTM_GETLINK, AF_UNSPEC, CxPlatNetlinkOnLinkMessage, &Interfaces);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }
    if (Interfaces.AllocFailed) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    CXPLAT_ADDRESS_DUMP_CONTEXT Dump;
    CxPlatZeroMemory(&Dump, sizeof(Dump));
    Dump.Interfaces = &Interfaces;

    Status =
        CxPlatNetlinkDump(
            RTM_GETADDR, AF_UNSPEC, CxPlatNetlinkOnAddressMessage, &Dump);
    if (QUIC_FAILED(Status) || Dump.AllocFailed) {
        if (Dump.Addresses != NULL) {
            CXPLAT_FREE(Dump.Addresses, QUIC_POOL_DATAPATH_ADDRESSES);
        }
        Status = QUIC_FAILED(Status) ? Status : QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    *Raw = Dump.Addresses;
    *RawCount = Dump.Count;
    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (Interfaces.Entries != NULL) {
        CXPLAT_FREE(Interfaces.Entries, QUIC_POOL_PLATFORM_TMP_ALLOC);
    }
    return Status;
}

//
// Drains the subscription socket, reporting whether anything arrived and
// whether any of it was about routes.
//
static
void
CxPlatAddressMonitorDrain(
    _In_ int Fd,
    _Out_ BOOLEAN* Notified,
    _Inout_ BOOLEAN* RouteChanged
    )
{
    uint8_t Buffer[CXPLAT_NETLINK_BUFFER_SIZE];
    *Notified = FALSE;

    for (;;) {
        const ssize_t Received = recv(Fd, Buffer, sizeof(Buffer), 0);
        if (Received < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == ENOBUFS) {
                //
                // The kernel dropped notifications because this socket could
                // not keep up. Nothing is lost that matters: the resync reads
                // the whole state anyway, so the dropped messages only would
                // have asked for one.
                //
                *Notified = TRUE;
                continue;
            }
            break; // EAGAIN: drained.
        }
        if (Received == 0) {
            break;
        }

        *Notified = TRUE;

        //
        // The content is ignored beyond whether it concerns routes, since the
        // snapshot comes from the resync rather than from these messages.
        //
        uint32_t Length = (uint32_t)Received;
        for (struct nlmsghdr* Header = (struct nlmsghdr*)Buffer;
             NLMSG_OK(Header, Length);
             Header = NLMSG_NEXT(Header, Length)) {
            if (Header->nlmsg_type == RTM_NEWROUTE ||
                Header->nlmsg_type == RTM_DELROUTE) {
                *RouteChanged = TRUE;
            }
        }
    }
}

static CXPLAT_THREAD_CALLBACK(CxPlatAddressMonitorThread, Context)
{
    CXPLAT_ADDRESS_MONITOR* Monitor = (CXPLAT_ADDRESS_MONITOR*)Context;
    CXPLAT_ADDRESS_MONITOR_OS* Os = Monitor->Os;

    BOOLEAN DebouncePending = FALSE;
    BOOLEAN RouteChanged = FALSE;
    uint64_t DebounceDeadline = 0;
    uint32_t RetryMs = 0;

    for (;;) {
        //
        // The debounce window is this timeout. A notification arms it, every
        // further notification inside it is absorbed, and the resync happens
        // once the host has been quiet for DebounceMs -- which is the whole
        // point: one interface transition produces several notifications, and
        // resyncing on each would mean several callbacks saying the same thing.
        //
        int Timeout = -1;
        if (DebouncePending) {
            const uint64_t Now = CxPlatTimeUs64();
            //
            // Rounded up, not down. Truncating left poll with a timeout of zero
            // for the last sub-millisecond of every window, which returns
            // immediately while the deadline check below still says not yet --
            // a tight loop until the microseconds ran out.
            //
            Timeout =
                CxPlatTimeAtOrBefore64(DebounceDeadline, Now) ?
                    0 : (int)US_TO_MS_CEIL(DebounceDeadline - Now);
        }

        struct pollfd PollFds[2];
        PollFds[0].fd = Os->ShutdownFd;
        PollFds[0].events = POLLIN;
        PollFds[0].revents = 0;
        PollFds[1].fd = Os->NetlinkFd;
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
                errno,
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
            CxPlatAddressMonitorDrain(Os->NetlinkFd, &Notified, &RouteChanged);
            if (Notified && !DebouncePending) {
                DebouncePending = TRUE;
                DebounceDeadline = CxPlatTimeUs64() + MS_TO_US(Monitor->DebounceMs);
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
                // The enumeration failed -- ENOBUFS pressure, a dump that
                // timed out under load, a host past the message bound. The
                // window stays armed and backs off rather than being cleared:
                // there may be no further notification to retry on, and an
                // address that appeared during the failure would otherwise stay
                // invisible to the consumer for the life of the process.
                //
                // RouteChanged is deliberately kept too, so a route change is
                // not lost to a failed address enumeration.
                //
                RetryMs = RetryMs == 0 ? Monitor->DebounceMs : RetryMs * 2;
                if (RetryMs > CXPLAT_ADDRESS_MONITOR_MAX_RETRY_MS) {
                    RetryMs = CXPLAT_ADDRESS_MONITOR_MAX_RETRY_MS;
                }
                DebounceDeadline = CxPlatTimeUs64() + MS_TO_US(RetryMs);
            }
        }
    }

    CXPLAT_THREAD_RETURN(0);
}

QUIC_STATUS
CxPlatAddressMonitorOsInitialize(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ CXPLAT_ADDRESS_MONITOR* Monitor
    )
{
    UNREFERENCED_PARAMETER(Datapath);

    QUIC_STATUS Status;

    CXPLAT_ADDRESS_MONITOR_OS* Os =
        CXPLAT_ALLOC_NONPAGED(
            sizeof(CXPLAT_ADDRESS_MONITOR_OS), QUIC_POOL_DATAPATH_ADDRESSES);
    if (Os == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_ADDRESS_MONITOR_OS",
            sizeof(CXPLAT_ADDRESS_MONITOR_OS));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    CxPlatZeroMemory(Os, sizeof(*Os));
    Os->NetlinkFd = -1;
    Os->ShutdownFd = -1;
    Monitor->Os = Os;

    uint32_t Groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
    if (Monitor->WatchRoutes) {
        Groups |= RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
    }

    //
    // Subscribed before the first enumeration, not after, so that a change
    // landing between the two is still reported. The other order can lose one.
    //
    Status = CxPlatNetlinkOpen(Groups, &Os->NetlinkFd);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Os->ShutdownFd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (Os->ShutdownFd == -1) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            errno,
            "eventfd(address monitor) failed");
        Status = (QUIC_STATUS)errno;
        goto Error;
    }

    //
    // The first enumeration is synchronous and silent: callers get a usable
    // snapshot the moment Initialize returns, with no callback for it.
    //
    CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Raw = NULL;
    uint32_t RawCount = 0;
    Status = CxPlatAddressMonitorOsEnumerate(Monitor, &Raw, &RawCount);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    if (RawCount != 0) {
        Monitor->Addresses =
            CXPLAT_ALLOC_NONPAGED(
                RawCount * sizeof(CXPLAT_LOCAL_ADDRESS), QUIC_POOL_DATAPATH_ADDRESSES);
        if (Monitor->Addresses == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "address monitor initial snapshot",
                RawCount * sizeof(CXPLAT_LOCAL_ADDRESS));
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
        goto Error;
    }
    Os->ThreadStarted = TRUE;

    return QUIC_STATUS_SUCCESS;

Error:

    if (Os->ShutdownFd != -1) {
        close(Os->ShutdownFd);
    }
    if (Os->NetlinkFd != -1) {
        close(Os->NetlinkFd);
    }
    if (Monitor->Addresses != NULL) {
        CXPLAT_FREE(Monitor->Addresses, QUIC_POOL_DATAPATH_ADDRESSES);
        Monitor->Addresses = NULL;
        Monitor->AddressCount = 0;
    }
    CXPLAT_FREE(Os, QUIC_POOL_DATAPATH_ADDRESSES);
    Monitor->Os = NULL;
    return Status;
}

void
CxPlatAddressMonitorOsUninitialize(
    _Inout_ CXPLAT_ADDRESS_MONITOR* Monitor
    )
{
    CXPLAT_ADDRESS_MONITOR_OS* Os = Monitor->Os;

    if (Os->ThreadStarted) {
        //
        // Joining the thread is what makes the interface's promise hold: a
        // callback already running finishes before the wait returns, and no
        // further one starts.
        //
        const uint64_t One = 1;
        if (write(Os->ShutdownFd, &One, sizeof(One)) != sizeof(One)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                errno,
                "write(address monitor shutdown) failed");
        }
        CxPlatThreadWait(&Os->Thread);
        CxPlatThreadDelete(&Os->Thread);
    }

    close(Os->ShutdownFd);
    close(Os->NetlinkFd);
    CXPLAT_FREE(Os, QUIC_POOL_DATAPATH_ADDRESSES);
    Monitor->Os = NULL;
}
