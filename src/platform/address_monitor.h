/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Internals of the local address monitor. The snapshot, filter and diff are
    here, platform independent and free of OS calls, so that they can be driven
    from a unit test with a synthetic enumeration. Each backend supplies only
    subscribe, enumerate and unsubscribe.

--*/

#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

//
// Where a backend exists. Decided here rather than by the build so that every
// translation unit agrees -- the shared file, the backend, datapath_unix.c and
// the unit tests each ask this question, and a build flag that reached some of
// them and not others would compile and then behave inconsistently.
//
#if defined(__linux__) && !defined(__FreeBSD__)
#define CXPLAT_ADDRESS_MONITOR_SUPPORTED 1
#endif

//
// What a backend reports for one address before filtering. The two booleans are
// the reasons an address can be dropped that are not visible in
// CXPLAT_ADDRESS_FLAGS, and they never reach a consumer: the filter uses them
// and discards them.
//
typedef struct CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS {
    CXPLAT_LOCAL_ADDRESS Address;
    BOOLEAN Tentative;      // In duplicate address detection, or it failed
    BOOLEAN InterfaceUp;    // Interface is operationally up
} CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS;

//
// Drops what no consumer can use and keeps what only policy can judge.
//
// Dropped: addresses still in duplicate address detection or that failed it, as
// binding to one fails or is about to; addresses on an interface that is not
// operationally up; and multicast, anycast and unspecified addresses, which are
// not source addresses. A tentative address reappears on the resync that
// follows DAD completing, which is itself an OS notification everywhere.
//
// Kept, but flagged: loopback, link-local, temporary and deprecated. Whether to
// use one of those is a policy question, and policy lives in core.
//
// Writes at most RawCount entries and may be called with Addresses pointing
// into the same array as Raw.
//
void
CxPlatAddressMonitorFilter(
    _In_reads_(RawCount) const CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Raw,
    _In_ uint32_t RawCount,
    _Out_writes_to_(RawCount, *Count) CXPLAT_LOCAL_ADDRESS* Addresses,
    _Out_ uint32_t* Count
    );

//
// Diffs two filtered snapshots, keyed on family, address bytes and scope ID --
// not on interface index or flags, so that an address moving interface or
// changing flags reads as UPDATED rather than as a remove and an add.
//
// Because that key is not unique -- the same global address can sit on two
// interfaces -- this pairs entries rather than testing membership, and needs
// Consumed as scratch, one BOOLEAN per Old entry. Its contents on return say
// which Old entries were paired and are of no use to the caller.
//
// Writes at most OldCount + NewCount changes.
//
void
CxPlatAddressMonitorDiff(
    _In_reads_(OldCount) const CXPLAT_LOCAL_ADDRESS* Old,
    _In_ uint32_t OldCount,
    _In_reads_(NewCount) const CXPLAT_LOCAL_ADDRESS* New,
    _In_ uint32_t NewCount,
    _Out_writes_all_(OldCount) BOOLEAN* Consumed,
    _Out_writes_to_(OldCount + NewCount, *ChangeCount) CXPLAT_ADDRESS_CHANGE* Changes,
    _Out_ uint32_t* ChangeCount
    );

#if defined(CXPLAT_ADDRESS_MONITOR_SUPPORTED)

typedef struct CXPLAT_ADDRESS_MONITOR_OS CXPLAT_ADDRESS_MONITOR_OS;

typedef struct CXPLAT_ADDRESS_MONITOR {
    CXPLAT_ADDRESS_CHANGE_CALLBACK* Callback;
    void* Context;
    uint32_t DebounceMs;
    BOOLEAN WatchRoutes;

    //
    // The snapshot, and the lock that readers of it take. Only the backend's
    // own execution context writes it, so the lock is uncontended except
    // against CxPlatAddressMonitorGetSnapshot.
    //
    CXPLAT_DISPATCH_LOCK Lock;
    CXPLAT_LOCAL_ADDRESS* Addresses;
    uint32_t AddressCount;
    uint64_t Generation;

    CXPLAT_ADDRESS_MONITOR_OS* Os;
} CXPLAT_ADDRESS_MONITOR;

//
// Backend hooks. Initialize subscribes and starts delivering; Uninitialize
// stops delivery and waits for any callback already running.
//
QUIC_STATUS
CxPlatAddressMonitorOsInitialize(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Inout_ CXPLAT_ADDRESS_MONITOR* Monitor
    );

void
CxPlatAddressMonitorOsUninitialize(
    _Inout_ CXPLAT_ADDRESS_MONITOR* Monitor
    );

//
// Enumerates every local address the OS knows, unfiltered. The caller frees
// *Raw with CXPLAT_FREE and QUIC_POOL_DATAPATH_ADDRESSES.
//
QUIC_STATUS
CxPlatAddressMonitorOsEnumerate(
    _Inout_ CXPLAT_ADDRESS_MONITOR* Monitor,
    _Outptr_result_buffer_(*RawCount) CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS** Raw,
    _Out_ uint32_t* RawCount
    );

//
// Called by the backend once its debounce window has closed. Re-enumerates,
// filters, diffs against the stored snapshot and, if anything changed or a
// route change is pending, replaces the snapshot, bumps the generation and
// makes the callback.
//
// FALSE when the enumeration failed, in which case the stored snapshot is left
// alone and nothing was reported. The backend is expected to try again rather
// than wait for another notification, which on a quiet host may never come.
//
BOOLEAN
CxPlatAddressMonitorResync(
    _Inout_ CXPLAT_ADDRESS_MONITOR* Monitor,
    _In_ BOOLEAN RouteChanged
    );

#endif // CXPLAT_ADDRESS_MONITOR_SUPPORTED

#if defined(__cplusplus)
}
#endif
