/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Windows backend for the local address monitor, the half that is the same in
    user mode and in the kernel: the NETIO change subscriptions, the debounce
    thread, and setup and teardown.

    Each mode supplies only CxPlatAddressMonitorOsEnumerate, because that is
    the only part that genuinely differs -- user mode has
    GetAdaptersAddresses, the kernel joins GetUnicastIpAddressTable with
    GetIpInterfaceTable. Everything else was identical, and splitting it this
    way follows datapath_win.c, which shares its common half between the two
    modes for the same reason.

    Shaped like the Linux backend rather than like the design sketch. The sketch
    called for a threadpool debounce timer armed from the notification callback;
    there is no threadpool timer abstraction in this tree, and introducing one
    for a single consumer would be more surface than the thing it serves. A
    thread of its own, whose wait timeout *is* the debounce window, is what the
    Linux backend already does and what the primitives here already support --
    in both modes, since CxPlatThreadCreate and CxPlatEventWaitWithTimeout are
    abstracted over KeWaitForSingleObject as well as WaitForSingleObject.

    It also keeps the notification callbacks trivial -- they set an event and
    return -- which is what makes CancelMibChangeNotify2 safe to call from
    uninitialize. That function waits for running callbacks, so a callback that
    did the resync itself would have to be fenced against teardown; one that
    only signals cannot deadlock against it. In the kernel the same callbacks
    arrive at PASSIVE_LEVEL and do no more there either.

--*/

#include "platform_internal.h"
#include "address_monitor.h"

#ifdef QUIC_CLOG
#include "address_monitor_win.c.clog.h"
#endif

#if defined(CXPLAT_ADDRESS_MONITOR_SUPPORTED)

//
// The NETIOAPI functions do not report failure the same way in the two modes.
// In the kernel they return an NTSTATUS, which is already a QUIC_STATUS and is
// signed; in user mode they return a Win32 error, where zero is success and
// neither NO_ERROR nor HRESULT_FROM_WIN32 exists in the WDK headers. Three
// things differ -- the type, the test and the conversion -- so all three are
// named here rather than #ifdef'd at each call site.
//
#if defined(_KERNEL_MODE)
typedef NTSTATUS CXPLAT_NETIO_RESULT;
#define CxPlatNetioFailed(X)    QUIC_FAILED(X)
#define CxPlatNetioToStatus(X)  ((QUIC_STATUS)(X))
#else
typedef DWORD CXPLAT_NETIO_RESULT;
#define CxPlatNetioFailed(X)    ((X) != NO_ERROR)
#define CxPlatNetioToStatus(X)  HRESULT_FROM_WIN32(X)
#endif

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
// Loopback and link-local, derived from the address itself rather than from a
// flag the OS sets, because that is where scope lives -- and because phase 3
// filters path candidates on it, so a backend that left it unset would make
// every address look routable.
//
// Shared by both modes: the two enumerations read different row types but the
// address bytes mean the same thing in each.
//
void
CxPlatAddressMonitorWinSetScopeFlags(
    _Inout_ CXPLAT_LOCAL_ADDRESS* Address
    )
{
    //
    // Scope is read from the address rather than from a flag the OS sets,
    // because that is where it lives: 127/8 and ::1 are on this host,
    // 169.254/16 and fe80::/10 reach only the link.
    //
    if (QuicAddrGetFamily(&Address->Address) == QUIC_ADDRESS_FAMILY_INET) {
        uint8_t Bytes[4];
        CxPlatCopyMemory(Bytes, &Address->Address.Ipv4.sin_addr, sizeof(Bytes));
        if (Bytes[0] == 127) {
            Address->Flags |= CXPLAT_ADDRESS_FLAG_LOOPBACK;
        } else if (Bytes[0] == 169 && Bytes[1] == 254) {
            Address->Flags |= CXPLAT_ADDRESS_FLAG_LINK_LOCAL;
        }
    } else {
        uint8_t Bytes[16];
        CxPlatCopyMemory(Bytes, &Address->Address.Ipv6.sin6_addr, sizeof(Bytes));
        if (Bytes[0] == 0xfe && (Bytes[1] & 0xc0) == 0x80) {
            Address->Flags |= CXPLAT_ADDRESS_FLAG_LINK_LOCAL;
        } else {
            //
            // ::1 compared through QuicAddrCompareIp rather than memcmp. The
            // kernel build compiles this file too, and memcmp is not something
            // any other kernel-compiled file here relies on, while
            // QuicAddrCompareIp is used throughout and is available in both
            // modes.
            //
            QUIC_ADDR Loopback;
            CxPlatZeroMemory(&Loopback, sizeof(Loopback));
            QuicAddrSetFamily(&Loopback, QUIC_ADDRESS_FAMILY_INET6);
            QuicAddrSetToLoopback(&Loopback);
            if (QuicAddrCompareIp(&Loopback, &Address->Address)) {
                Address->Flags |= CXPLAT_ADDRESS_FLAG_LOOPBACK;
            }
        }
    }
}

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
    CXPLAT_NETIO_RESULT Error =
        NotifyUnicastIpAddressChange(
            AF_UNSPEC,
            CxPlatAddressMonitorAddressChangeCallback,
            Monitor,
            FALSE,
            &Os->AddressNotify);
    if (CxPlatNetioFailed(Error)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            (uint32_t)Error,
            "NotifyUnicastIpAddressChange");
        Status = CxPlatNetioToStatus(Error);
        goto Error;
    }

    Error =
        NotifyIpInterfaceChange(
            AF_UNSPEC,
            CxPlatAddressMonitorInterfaceChangeCallback,
            Monitor,
            FALSE,
            &Os->InterfaceNotify);
    if (CxPlatNetioFailed(Error)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            (uint32_t)Error,
            "NotifyIpInterfaceChange");
        Status = CxPlatNetioToStatus(Error);
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

    //
    // Unconditional, and nothing is assigned back. A kernel CXPLAT_EVENT is a
    // KEVENT -- a structure, not a handle -- so it can be neither compared to
    // NULL nor set to it. There is no path here that has not initialized it:
    // CxPlatEventInitialize runs immediately after the allocation, before the
    // first goto Error, and a failed allocation returns without coming here.
    //
    CxPlatEventUninitialize(Os->NotifyEvent);

    CXPLAT_FREE(Os, QUIC_POOL_DATAPATH);
    Monitor->Os = NULL;
}

#endif // CXPLAT_ADDRESS_MONITOR_SUPPORTED
