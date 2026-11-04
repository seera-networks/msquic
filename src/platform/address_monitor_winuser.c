/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Windows user-mode backend for the local address monitor: NETIO change
    notifications and a GetAdaptersAddresses enumeration.

    Shaped like the Linux backend rather than like the design sketch. The sketch
    called for a threadpool debounce timer armed from the notification callback;
    there is no threadpool timer abstraction in this tree, and introducing one
    for a single consumer would be more surface than the thing it serves. A
    thread of its own, whose wait timeout *is* the debounce window, is what the
    Linux backend already does and what the primitives here already support.

    It also keeps the notification callbacks trivial -- they set an event and
    return -- which is what makes CancelMibChangeNotify2 safe to call from
    uninitialize. That function waits for running callbacks, so a callback that
    did the resync itself would have to be fenced against teardown; one that
    only signals cannot deadlock against it.

    Enumeration uses GetAdaptersAddresses rather than the sketch's
    GetUnicastIpAddressTable joined with GetIfTable2. One call supplies
    everything the filter needs -- the address, interface index and IANA
    interface type, the per-address DadState, SuffixOrigin and PreferredLifetime,
    and the adapter's OperStatus -- so there is no table join to get wrong, and
    it is the same API this datapath already enumerates addresses with.

--*/

#include "platform_internal.h"
#include "address_monitor.h"

#ifdef QUIC_CLOG
#include "address_monitor_winuser.c.clog.h"
#endif

#if defined(CXPLAT_ADDRESS_MONITOR_SUPPORTED)

//
// How long to wait before retrying an enumeration that failed, doubling to
// this bound. Matches the Linux backend.
//
#define CXPLAT_ADDRESS_MONITOR_MAX_RETRY_MS 5000

typedef struct CXPLAT_ADDRESS_MONITOR_OS {
    //
    // The two NETIO subscriptions. Addresses coming and going is the obvious
    // one; interface state is the other, because an address does not change
    // when the interface under it stops being operationally up, and the filter
    // drops addresses on an interface that is down.
    //
    HANDLE AddressNotify;
    HANDLE InterfaceNotify;

    //
    // Set by the notification callbacks, and by uninitialize to wake the
    // thread. Auto-reset: a wake means "something happened", and the thread
    // re-reads the world rather than counting notifications.
    //
    CXPLAT_EVENT NotifyEvent;

    //
    // Read by the thread after every wake. Written before NotifyEvent is set,
    // so a thread that sees the event set also sees this.
    //
    BOOLEAN volatile Shutdown;

    CXPLAT_THREAD Thread;
    BOOLEAN ThreadStarted;
} CXPLAT_ADDRESS_MONITOR_OS;

//
// Both notifications mean the same thing to us -- re-read the world -- but
// they are declared with different row types, so each needs its own entry
// point. Both do as little as possible: the OS calls them on a thread pool
// thread, and anything slower would hold that thread up.
//
static
void
CxPlatAddressMonitorSignal(
    _In_opt_ PVOID CallerContext
    )
{
    CXPLAT_ADDRESS_MONITOR* Monitor = (CXPLAT_ADDRESS_MONITOR*)CallerContext;
    if (Monitor == NULL || Monitor->Os == NULL) {
        return;
    }
    CxPlatEventSet(Monitor->Os->NotifyEvent);
}

static
VOID
WINAPI
CxPlatAddressMonitorAddressChangeCallback(
    _In_ PVOID CallerContext,
    _In_opt_ PMIB_UNICASTIPADDRESS_ROW Row,
    _In_ MIB_NOTIFICATION_TYPE NotificationType
    )
{
    UNREFERENCED_PARAMETER(Row);
    UNREFERENCED_PARAMETER(NotificationType);
    CxPlatAddressMonitorSignal(CallerContext);
}

static
VOID
WINAPI
CxPlatAddressMonitorInterfaceChangeCallback(
    _In_ PVOID CallerContext,
    _In_opt_ PMIB_IPINTERFACE_ROW Row,
    _In_ MIB_NOTIFICATION_TYPE NotificationType
    )
{
    UNREFERENCED_PARAMETER(Row);
    UNREFERENCED_PARAMETER(NotificationType);
    CxPlatAddressMonitorSignal(CallerContext);
}

//
// Turns one GetAdaptersAddresses unicast entry into the raw form the shared
// filter takes. The flags it cannot see from the address alone -- tentative,
// and whether the interface is up -- are the two booleans the filter uses and
// discards.
//
static
void
CxPlatAddressMonitorFromAdapter(
    _In_ const IP_ADAPTER_ADDRESSES* Adapter,
    _In_ const IP_ADAPTER_UNICAST_ADDRESS_LH* Address,
    _Out_ CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Entry
    )
{
    CxPlatZeroMemory(Entry, sizeof(*Entry));

    //
    // Clamped both ways: SOCKET_ADDRESS reports the length the OS filled in,
    // which for a v4 sockaddr is well short of QUIC_ADDR, and a copy of the
    // full union would read past it.
    //
    const int SockAddrLength = Address->Address.iSockaddrLength;
    if (SockAddrLength > 0) {
        CxPlatCopyMemory(
            &Entry->Address.Address,
            Address->Address.lpSockaddr,
            (size_t)SockAddrLength < sizeof(QUIC_ADDR) ?
                (size_t)SockAddrLength : sizeof(QUIC_ADDR));
    }
    QuicAddrSetPort(&Entry->Address.Address, 0);

    Entry->Address.InterfaceIndex =
        QuicAddrGetFamily(&Entry->Address.Address) == QUIC_ADDRESS_FAMILY_INET ?
            (uint32_t)Adapter->IfIndex : (uint32_t)Adapter->Ipv6IfIndex;
    Entry->Address.InterfaceType = (uint16_t)Adapter->IfType;

    //
    // Deprecated means the preferred lifetime has expired, which is exactly
    // what DadStateDeprecated reports; a zero preferred lifetime says the same
    // thing and is checked too, since the two are set independently.
    //
    if (Address->DadState == IpDadStateDeprecated ||
        Address->PreferredLifetime == 0) {
        Entry->Address.Flags |= CXPLAT_ADDRESS_FLAG_DEPRECATED;
    }

    //
    // TEMPORARY is deliberately not set here, and SuffixOrigin is not the way
    // to set it. Windows randomizes interface identifiers by default
    // (randomizeidentifiers), so the stable public SLAAC address derived from a
    // router advertisement reports SuffixOrigin == IpSuffixOriginRandom exactly
    // like the RFC 8981 temporary address beside it. Keying on that would mark
    // the host's primary global IPv6 address as a privacy address, and phase 3
    // uses this flag to decide which kind of address to stay on -- so a wrong
    // flag actively misdirects selection, while an unset one merely leaves that
    // preference with nothing to say. IP_ADAPTER_UNICAST_ADDRESS_LH carries no
    // field that separates the two; distinguishing them would mean inferring it
    // from the lifetime pair, which is guesswork this is better off without.
    //

    //
    // Scope is read from the address rather than from a flag the OS sets,
    // because that is where it lives: 127/8 and ::1 are on this host,
    // 169.254/16 and fe80::/10 reach only the link.
    //
    if (QuicAddrGetFamily(&Entry->Address.Address) == QUIC_ADDRESS_FAMILY_INET) {
        uint8_t Bytes[4];
        CxPlatCopyMemory(Bytes, &Entry->Address.Address.Ipv4.sin_addr, sizeof(Bytes));
        if (Bytes[0] == 127) {
            Entry->Address.Flags |= CXPLAT_ADDRESS_FLAG_LOOPBACK;
        } else if (Bytes[0] == 169 && Bytes[1] == 254) {
            Entry->Address.Flags |= CXPLAT_ADDRESS_FLAG_LINK_LOCAL;
        }
    } else {
        uint8_t Bytes[16];
        CxPlatCopyMemory(Bytes, &Entry->Address.Address.Ipv6.sin6_addr, sizeof(Bytes));
        if (Bytes[0] == 0xfe && (Bytes[1] & 0xc0) == 0x80) {
            Entry->Address.Flags |= CXPLAT_ADDRESS_FLAG_LINK_LOCAL;
        } else {
            static const uint8_t Loopback[16] = {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
            };
            if (memcmp(Bytes, Loopback, sizeof(Bytes)) == 0) {
                Entry->Address.Flags |= CXPLAT_ADDRESS_FLAG_LOOPBACK;
            }
        }
    }

    //
    // Tentative covers both "still doing duplicate address detection" and
    // "detection failed": binding to either fails or is about to, and the
    // filter drops them. A tentative address reappears on the resync that
    // follows detection completing, which is itself a notification.
    //
    Entry->Tentative =
        Address->DadState == IpDadStateTentative ||
        Address->DadState == IpDadStateInvalid ||
        Address->DadState == IpDadStateDuplicate;

    //
    // IfOperStatusUp, not "not down": an interface that is testing, dormant or
    // unknown is not one to put a connection on.
    //
    Entry->InterfaceUp = Adapter->OperStatus == IfOperStatusUp;
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

    //
    // Anycast and multicast are skipped by the OS rather than by the filter:
    // asking for them and dropping them later would only mean a bigger buffer.
    // Every interface is included, because "is it up" is the filter's call.
    //
    const ULONG Flags =
        GAA_FLAG_INCLUDE_ALL_INTERFACES |
        GAA_FLAG_SKIP_ANYCAST |
        GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER |
        GAA_FLAG_SKIP_FRIENDLY_NAME |
        GAA_FLAG_SKIP_DNS_INFO;

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    IP_ADAPTER_ADDRESSES* Adapters = NULL;
    ULONG AdaptersSize = 0;
    CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Entries = NULL;

    *Raw = NULL;
    *RawCount = 0;

    //
    // Bounded rather than "until it fits": the table can grow between the
    // sizing call and the real one, and an unbounded loop on a host whose
    // addresses are churning is a loop that may not end.
    //
    ULONG Error = ERROR_BUFFER_OVERFLOW;
    for (uint32_t Attempt = 0; Attempt < 4 && Error == ERROR_BUFFER_OVERFLOW; ++Attempt) {
        Error = GetAdaptersAddresses(AF_UNSPEC, Flags, NULL, Adapters, &AdaptersSize);
        if (Error != ERROR_BUFFER_OVERFLOW) {
            break;
        }
        if (Adapters != NULL) {
            CXPLAT_FREE(Adapters, QUIC_POOL_DATAPATH_ADDRESSES);
            Adapters = NULL;
        }
        if (AdaptersSize == 0) {
            break;
        }
        Adapters = CXPLAT_ALLOC_NONPAGED(AdaptersSize, QUIC_POOL_DATAPATH_ADDRESSES);
        if (Adapters == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "address monitor adapter addresses",
                (uint64_t)AdaptersSize);
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Exit;
        }
    }

    if (Error == ERROR_NO_DATA) {
        //
        // A host with no unicast address at all. An empty snapshot, not a
        // failure: the consumer's answer is "nothing to send from", which is a
        // state the core already handles.
        //
        goto Exit;
    }

    if (Error != ERROR_SUCCESS) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Error,
            "GetAdaptersAddresses(address monitor)");
        Status = HRESULT_FROM_WIN32(Error);
        goto Exit;
    }

    uint32_t Count = 0;
    for (const IP_ADAPTER_ADDRESSES* Adapter = Adapters;
            Adapter != NULL;
            Adapter = Adapter->Next) {
        for (const IP_ADAPTER_UNICAST_ADDRESS_LH* Address = Adapter->FirstUnicastAddress;
                Address != NULL;
                Address = Address->Next) {
            if (Address->Address.lpSockaddr == NULL) {
                continue;
            }
            ++Count;
        }
    }

    if (Count == 0) {
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

    uint32_t Index = 0;
    for (const IP_ADAPTER_ADDRESSES* Adapter = Adapters;
            Adapter != NULL && Index < Count;
            Adapter = Adapter->Next) {
        for (const IP_ADAPTER_UNICAST_ADDRESS_LH* Address = Adapter->FirstUnicastAddress;
                Address != NULL && Index < Count;
                Address = Address->Next) {
            if (Address->Address.lpSockaddr == NULL) {
                continue;
            }
            const ADDRESS_FAMILY Family = Address->Address.lpSockaddr->sa_family;
            if (Family != AF_INET && Family != AF_INET6) {
                continue;
            }
            CxPlatAddressMonitorFromAdapter(Adapter, Address, &Entries[Index]);
            ++Index;
        }
    }

    *Raw = Entries;
    *RawCount = Index;
    Entries = NULL;

Exit:

    if (Entries != NULL) {
        CXPLAT_FREE(Entries, QUIC_POOL_DATAPATH_ADDRESSES);
    }
    if (Adapters != NULL) {
        CXPLAT_FREE(Adapters, QUIC_POOL_DATAPATH_ADDRESSES);
    }
    return Status;
}

//
// The subscription thread. Its wait timeout is the debounce window, so a burst
// of notifications -- the normal shape of an interface transition -- produces
// one resync once the host has been quiet, rather than one per notification.
//
CXPLAT_THREAD_CALLBACK(CxPlatAddressMonitorThread, Context)
{
    CXPLAT_ADDRESS_MONITOR* Monitor = (CXPLAT_ADDRESS_MONITOR*)Context;
    CXPLAT_ADDRESS_MONITOR_OS* Os = Monitor->Os;

    BOOLEAN DebouncePending = FALSE;
    uint64_t DebounceDeadline = 0;
    uint32_t RetryMs = 0;

    while (!Os->Shutdown) {
        uint32_t TimeoutMs = UINT32_MAX;
        if (DebouncePending) {
            const uint64_t Now = CxPlatTimeUs64();
            //
            // Rounded up. Truncating would leave a timeout of zero for the last
            // sub-millisecond of every window, which returns at once while the
            // deadline check below still says not yet -- a spin until the
            // microseconds ran out. The Linux backend had exactly that bug.
            //
            TimeoutMs =
                CxPlatTimeAtOrBefore64(DebounceDeadline, Now) ?
                    0 : (uint32_t)US_TO_MS_CEIL(DebounceDeadline - Now);
        }

        BOOLEAN Notified;
        if (TimeoutMs == UINT32_MAX) {
            CxPlatEventWaitForever(Os->NotifyEvent);
            Notified = TRUE;
        } else {
            Notified = CxPlatEventWaitWithTimeout(Os->NotifyEvent, TimeoutMs);
        }

        if (Os->Shutdown) {
            //
            // Any pending debounce is abandoned on purpose: the consumer is
            // going away, and a last callback would be delivered to something
            // on its way out.
            //
            break;
        }

        if (Notified && !DebouncePending) {
            DebouncePending = TRUE;
            DebounceDeadline =
                CxPlatTimeUs64() + MS_TO_US((uint64_t)Monitor->DebounceMs);
        }

        if (DebouncePending &&
            CxPlatTimeAtOrBefore64(DebounceDeadline, CxPlatTimeUs64())) {
            //
            // RouteChanged is always FALSE here: route watching is phase 5, and
            // this backend subscribes to addresses and interfaces only.
            //
            if (CxPlatAddressMonitorResync(Monitor, FALSE)) {
                DebouncePending = FALSE;
                RetryMs = 0;
            } else {
                //
                // The enumeration failed. The window stays armed and backs off
                // rather than being cleared: there may be no further
                // notification to retry on, and an address that appeared during
                // the failure would otherwise stay invisible.
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
    Monitor->Os = Os;

    //
    // Auto-reset, initially unsignalled. Auto-reset because each wake means
    // "re-read the world", not "handle one notification".
    //
    CxPlatEventInitialize(&Os->NotifyEvent, FALSE, FALSE);

    //
    // Subscribed before the thread starts, so a notification arriving during
    // startup is not lost -- it sets the event, and the thread sees it on its
    // first wait.
    //
    // InitialNotification is FALSE: the caller takes its own first snapshot
    // through CxPlatAddressMonitorGetSnapshot, and an immediate callback would
    // only produce a redundant resync.
    //
    DWORD Error =
        NotifyUnicastIpAddressChange(
            AF_UNSPEC,
            CxPlatAddressMonitorAddressChangeCallback,
            Monitor,
            FALSE,
            &Os->AddressNotify);
    if (Error != NO_ERROR) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Error,
            "NotifyUnicastIpAddressChange");
        Status = HRESULT_FROM_WIN32(Error);
        goto Error;
    }

    Error =
        NotifyIpInterfaceChange(
            AF_UNSPEC,
            CxPlatAddressMonitorInterfaceChangeCallback,
            Monitor,
            FALSE,
            &Os->InterfaceNotify);
    if (Error != NO_ERROR) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Error,
            "NotifyIpInterfaceChange");
        Status = HRESULT_FROM_WIN32(Error);
        goto Error;
    }

    //
    // The first enumeration is synchronous and silent: callers get a usable
    // snapshot the moment Initialize returns, with no callback for it. The
    // shared Initialize does not do this -- each backend does -- and without it
    // Generation stays 0, so QuicLibraryAddRefAddressMonitor's "only take a
    // newer generation" seed drops the snapshot and a connection on a quiet
    // host sees no local addresses at all.
    //
    CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Raw = NULL;
    uint32_t RawCount = 0;
    Status = CxPlatAddressMonitorOsEnumerate(Monitor, &Raw, &RawCount);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    //
    // Tested together, not RawCount alone: a successful enumeration with
    // nothing to report hands back a null pointer with a zero count, and a
    // count is not evidence of a pointer. Using the count as a proxy for the
    // pointer is the mistake this feature has now made four times.
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
            Status,
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

    //
    // Unsubscribe first, so no further callback can set the event after the
    // thread has gone.
    //
    // CancelMibChangeNotify2 waits for a callback that is already running,
    // which is why the interface forbids calling uninitialize from inside one.
    // These callbacks only set an event, so there is nothing for that wait to
    // block behind.
    //
    if (Os->InterfaceNotify != NULL) {
        (void)CancelMibChangeNotify2(Os->InterfaceNotify);
        Os->InterfaceNotify = NULL;
    }
    if (Os->AddressNotify != NULL) {
        (void)CancelMibChangeNotify2(Os->AddressNotify);
        Os->AddressNotify = NULL;
    }

    if (Os->ThreadStarted) {
        Os->Shutdown = TRUE;
        CxPlatEventSet(Os->NotifyEvent);
        CxPlatThreadWait(&Os->Thread);
        CxPlatThreadDelete(&Os->Thread);
        Os->ThreadStarted = FALSE;
    }

    if (Os->NotifyEvent != NULL) {
        CxPlatEventUninitialize(Os->NotifyEvent);
        Os->NotifyEvent = NULL;
    }

    CXPLAT_FREE(Os, QUIC_POOL_DATAPATH);
    Monitor->Os = NULL;
}

#endif // CXPLAT_ADDRESS_MONITOR_SUPPORTED
