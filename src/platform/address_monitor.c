/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Local address monitor: snapshot, filter and diff.

    Nothing here calls the OS. A backend subscribes to notifications, waits out
    its debounce window and calls CxPlatAddressMonitorResync; everything from
    the re-enumeration onwards happens here, the same way on every platform.

--*/

#include "platform_internal.h"
#include "address_monitor.h"

#ifdef QUIC_CLOG
#include "address_monitor.c.clog.h"
#endif

static
BOOLEAN
CxPlatLocalAddressEqual(
    _In_ const CXPLAT_LOCAL_ADDRESS* A,
    _In_ const CXPLAT_LOCAL_ADDRESS* B
    )
{
    //
    // Identity is family, address bytes and scope ID. Interface index and flags
    // are deliberately not part of it: an address that moves interface or has
    // its flags change is the same address, and reporting it as one UPDATED
    // rather than a REMOVED and an ADDED is what stops a consumer tearing down
    // and rebuilding state it could have kept.
    //
    // QuicAddrCompare covers family, port and address bytes but not the scope
    // ID, which has to be compared here: the same link-local address on two
    // interfaces is two addresses. Both sides come from the filter, which zeroes
    // the port, so the port half of that comparison is always equal.
    //
    if (!QuicAddrCompare(&A->Address, &B->Address)) {
        return FALSE;
    }
    if (QuicAddrGetFamily(&A->Address) == QUIC_ADDRESS_FAMILY_INET6 &&
        A->Address.Ipv6.sin6_scope_id != B->Address.Ipv6.sin6_scope_id) {
        return FALSE;
    }
    return TRUE;
}

//
// No platform helper for this, and it is not the same question as
// QuicAddrIsWildCard: 224.0.0.0/4 over IPv4, ff00::/8 over IPv6.
//
static
BOOLEAN
CxPlatLocalAddressIsMulticast(
    _In_ const QUIC_ADDR* Addr
    )
{
    if (QuicAddrGetFamily(Addr) == QUIC_ADDRESS_FAMILY_INET) {
        const uint8_t* Bytes = (const uint8_t*)&Addr->Ipv4.sin_addr;
        return (Bytes[0] & 0xF0) == 0xE0;
    }
    const uint8_t* Bytes = (const uint8_t*)&Addr->Ipv6.sin6_addr;
    return Bytes[0] == 0xFF;
}

static
BOOLEAN
CxPlatLocalAddressAttributesEqual(
    _In_ const CXPLAT_LOCAL_ADDRESS* A,
    _In_ const CXPLAT_LOCAL_ADDRESS* B
    )
{
    return
        A->InterfaceIndex == B->InterfaceIndex &&
        A->InterfaceType == B->InterfaceType &&
        A->Flags == B->Flags;
}

void
CxPlatAddressMonitorFilter(
    _In_reads_(RawCount) const CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Raw,
    _In_ uint32_t RawCount,
    _Out_writes_to_(RawCount, *Count) CXPLAT_LOCAL_ADDRESS* Addresses,
    _Out_ uint32_t* Count
    )
{
    uint32_t Kept = 0;
    for (uint32_t i = 0; i < RawCount; ++i) {
        const CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Entry = &Raw[i];

        if (Entry->Tentative || !Entry->InterfaceUp) {
            continue;
        }

        const QUIC_ADDRESS_FAMILY Family = QuicAddrGetFamily(&Entry->Address.Address);
        if (Family != QUIC_ADDRESS_FAMILY_INET &&
            Family != QUIC_ADDRESS_FAMILY_INET6) {
            continue;
        }

        //
        // Not a source address: the unspecified address, and anything
        // multicast. Anycast is not distinguishable from the address alone and
        // is left to the backend, which has the OS's own flag for it.
        //
        if (QuicAddrIsWildCard(&Entry->Address.Address) ||
            CxPlatLocalAddressIsMulticast(&Entry->Address.Address)) {
            continue;
        }

        //
        // Written in order, and the caller is allowed to pass the same storage
        // it read from, so Kept <= i has to hold -- it does, since Kept only
        // advances on an entry that is kept.
        //
        Addresses[Kept] = Entry->Address;
        QuicAddrSetPort(&Addresses[Kept].Address, 0);
        ++Kept;
    }
    *Count = Kept;
}

void
CxPlatAddressMonitorDiff(
    _In_reads_(OldCount) const CXPLAT_LOCAL_ADDRESS* Old,
    _In_ uint32_t OldCount,
    _In_reads_(NewCount) const CXPLAT_LOCAL_ADDRESS* New,
    _In_ uint32_t NewCount,
    _Out_writes_all_(OldCount) BOOLEAN* Consumed,
    _Out_writes_to_(OldCount + NewCount, *ChangeCount) CXPLAT_ADDRESS_CHANGE* Changes,
    _Out_ uint32_t* ChangeCount
    )
{
    uint32_t Count = 0;

    //
    // Pairing, not set membership. Identity excludes the interface index on
    // purpose, so the same global address on two interfaces -- an anycast /32
    // on lo alongside a real one -- is two entries under one key. Answering
    // "is this key present" meant deleting one copy produced no change at all,
    // and the caller then discarded the new snapshot and stopped moving the
    // generation, reporting an address on an interface that no longer had it
    // for as long as the process lived.
    //
    // Each Old entry is therefore consumed by at most one New entry, tracked in
    // Consumed. Exact matches -- identity and attributes both -- are paired
    // first, in a pass of their own, so that a dump listing two copies in the
    // other order pairs them with each other and reports nothing, rather than
    // pairing them crosswise and reporting two updates that did not happen.
    //
    for (uint32_t i = 0; i < OldCount; ++i) {
        Consumed[i] = FALSE;
    }

    for (uint32_t i = 0; i < NewCount; ++i) {
        for (uint32_t j = 0; j < OldCount; ++j) {
            if (!Consumed[j] &&
                CxPlatLocalAddressEqual(&Old[j], &New[i]) &&
                CxPlatLocalAddressAttributesEqual(&Old[j], &New[i])) {
                Consumed[j] = TRUE;
                goto NextExact;
            }
        }
        continue;
    NextExact:
        ;
    }

    for (uint32_t i = 0; i < NewCount; ++i) {
        //
        // Already paired exactly in the pass above, so nothing to report.
        //
        BOOLEAN Exact = FALSE;
        for (uint32_t j = 0; j < OldCount; ++j) {
            if (Consumed[j] &&
                CxPlatLocalAddressEqual(&Old[j], &New[i]) &&
                CxPlatLocalAddressAttributesEqual(&Old[j], &New[i])) {
                Exact = TRUE;
                break;
            }
        }
        if (Exact) {
            continue;
        }

        //
        // Otherwise it pairs with a leftover of the same identity, which is an
        // address whose flags or interface changed, or it is new.
        //
        BOOLEAN Updated = FALSE;
        for (uint32_t j = 0; j < OldCount; ++j) {
            if (!Consumed[j] && CxPlatLocalAddressEqual(&Old[j], &New[i])) {
                Consumed[j] = TRUE;
                Updated = TRUE;
                break;
            }
        }

        //
        // At most one change per New entry here and one per leftover Old entry
        // below, which is the OldCount + NewCount the annotation promises.
        // Spelled out because it is spread over three loops, and a static
        // analyzer will not carry the bound across them.
        //
        CXPLAT_DBG_ASSERT(Count < OldCount + NewCount);
        CXPLAT_ANALYSIS_ASSUME(Count < OldCount + NewCount);
        Changes[Count].Type =
            Updated ? CXPLAT_ADDRESS_CHANGE_UPDATED : CXPLAT_ADDRESS_CHANGE_ADDED;
        Changes[Count].Address = New[i];
        ++Count;
    }

    for (uint32_t i = 0; i < OldCount; ++i) {
        if (!Consumed[i]) {
            CXPLAT_DBG_ASSERT(Count < OldCount + NewCount);
            CXPLAT_ANALYSIS_ASSUME(Count < OldCount + NewCount);
            Changes[Count].Type = CXPLAT_ADDRESS_CHANGE_REMOVED;
            Changes[Count].Address = Old[i];
            ++Count;
        }
    }

    *ChangeCount = Count;
}

#if defined(CXPLAT_ADDRESS_MONITOR_SUPPORTED)

BOOLEAN
CxPlatAddressMonitorResync(
    _Inout_ CXPLAT_ADDRESS_MONITOR* Monitor,
    _In_ BOOLEAN RouteChanged
    )
{
    CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Raw = NULL;
    uint32_t RawCount = 0;

    if (QUIC_FAILED(CxPlatAddressMonitorOsEnumerate(Monitor, &Raw, &RawCount))) {
        //
        // The stored snapshot is left alone rather than emptied. An enumeration
        // that fails says nothing about the host's addresses, and reporting them
        // all as removed would be a worse answer than reporting nothing.
        //
        // FALSE, so the backend can try again. It used to say "the next
        // notification enumerates again", which is only true if there is one --
        // on a quiet host an address that appeared during a failed enumeration
        // would have stayed invisible for good.
        //
        return FALSE;
    }

    CXPLAT_LOCAL_ADDRESS* Addresses = NULL;
    uint32_t AddressCount = 0;

    if (RawCount != 0) {
        Addresses =
            CXPLAT_ALLOC_NONPAGED(
                RawCount * sizeof(CXPLAT_LOCAL_ADDRESS), QUIC_POOL_DATAPATH_ADDRESSES);
        if (Addresses == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "address monitor snapshot",
                RawCount * sizeof(CXPLAT_LOCAL_ADDRESS));
            CXPLAT_FREE(Raw, QUIC_POOL_DATAPATH_ADDRESSES);
            return FALSE;
        }
        CxPlatAddressMonitorFilter(Raw, RawCount, Addresses, &AddressCount);
    }

    CXPLAT_FREE(Raw, QUIC_POOL_DATAPATH_ADDRESSES);

    CXPLAT_ADDRESS_CHANGE* Changes = NULL;
    uint32_t ChangeCount = 0;
    const uint32_t MaxChanges = Monitor->AddressCount + AddressCount;

    if (MaxChanges != 0) {
        //
        // The change list and the diff's pairing scratch in one allocation, the
        // scratch after the changes.
        //
        const size_t ChangesSize = MaxChanges * sizeof(CXPLAT_ADDRESS_CHANGE);
        const size_t ScratchSize = Monitor->AddressCount * sizeof(BOOLEAN);
        Changes =
            CXPLAT_ALLOC_NONPAGED(
                ChangesSize + ScratchSize, QUIC_POOL_DATAPATH_ADDRESSES);
        if (Changes == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "address monitor changes",
                (uint64_t)(ChangesSize + ScratchSize));
            if (Addresses != NULL) {
                CXPLAT_FREE(Addresses, QUIC_POOL_DATAPATH_ADDRESSES);
            }
            return FALSE;
        }
        CxPlatAddressMonitorDiff(
            Monitor->Addresses, Monitor->AddressCount,
            Addresses, AddressCount,
            (BOOLEAN*)((uint8_t*)Changes + ChangesSize),
            Changes, &ChangeCount);
    }

    if (ChangeCount == 0 && !RouteChanged &&
        AddressCount == Monitor->AddressCount) {
        //
        // The resync found nothing. This is the common case: most of the OS
        // notifications that reach a backend are about something the snapshot
        // does not record.
        //
        // The count is compared as well as the diff, so that a snapshot which
        // changed size can never be discarded here however the diff behaved.
        // Publishing a change nobody needs costs a consumer one reconciliation
        // that finds nothing; discarding one it needs leaves it wrong until
        // something else happens to change, which on a quiet host is never.
        //
        if (Changes != NULL) {
            CXPLAT_FREE(Changes, QUIC_POOL_DATAPATH_ADDRESSES);
        }
        if (Addresses != NULL) {
            CXPLAT_FREE(Addresses, QUIC_POOL_DATAPATH_ADDRESSES);
        }
        return TRUE;
    }

    CXPLAT_LOCAL_ADDRESS* Previous;
    CXPLAT_ADDRESS_CHANGE_SET ChangeSet;

    CxPlatDispatchLockAcquire(&Monitor->Lock);
    Previous = Monitor->Addresses;
    Monitor->Addresses = Addresses;
    Monitor->AddressCount = AddressCount;
    ChangeSet.Generation = ++Monitor->Generation;
    CxPlatDispatchLockRelease(&Monitor->Lock);

    if (Previous != NULL) {
        CXPLAT_FREE(Previous, QUIC_POOL_DATAPATH_ADDRESSES);
    }

    ChangeSet.RouteChanged = RouteChanged;
    ChangeSet.ChangeCount = ChangeCount;
    ChangeSet.Changes = Changes;
    ChangeSet.AddressCount = AddressCount;
    ChangeSet.Addresses = Addresses;

    //
    // Outside the lock. The callback is not allowed to block, but it is allowed
    // to call back in for a snapshot, and holding the lock across it would make
    // that a deadlock.
    //
    Monitor->Callback(Monitor->Context, &ChangeSet);

    if (Changes != NULL) {
        CXPLAT_FREE(Changes, QUIC_POOL_DATAPATH_ADDRESSES);
    }

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatAddressMonitorInitialize(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const CXPLAT_ADDRESS_MONITOR_CONFIG* Config,
    _Outptr_ CXPLAT_ADDRESS_MONITOR** NewMonitor
    )
{
    CXPLAT_DBG_ASSERT(Config->Callback != NULL);

    CXPLAT_ADDRESS_MONITOR* Monitor =
        CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_ADDRESS_MONITOR), QUIC_POOL_DATAPATH_ADDRESSES);
    if (Monitor == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_ADDRESS_MONITOR",
            sizeof(CXPLAT_ADDRESS_MONITOR));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    CxPlatZeroMemory(Monitor, sizeof(*Monitor));
    Monitor->Callback = Config->Callback;
    Monitor->Context = Config->Context;
    Monitor->DebounceMs =
        Config->DebounceMs != 0 ?
            Config->DebounceMs : CXPLAT_ADDRESS_MONITOR_DEFAULT_DEBOUNCE_MS;
    Monitor->WatchRoutes = Config->WatchRoutes;
    CxPlatDispatchLockInitialize(&Monitor->Lock);

    QUIC_STATUS Status = CxPlatAddressMonitorOsInitialize(Datapath, Monitor);
    if (QUIC_FAILED(Status)) {
        CxPlatDispatchLockUninitialize(&Monitor->Lock);
        CXPLAT_FREE(Monitor, QUIC_POOL_DATAPATH_ADDRESSES);
        return Status;
    }

    *NewMonitor = Monitor;
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatAddressMonitorUninitialize(
    _In_ CXPLAT_ADDRESS_MONITOR* Monitor
    )
{
    //
    // The backend stops delivery and waits for a callback already running, so
    // nothing below races one.
    //
    CxPlatAddressMonitorOsUninitialize(Monitor);

    if (Monitor->Addresses != NULL) {
        CXPLAT_FREE(Monitor->Addresses, QUIC_POOL_DATAPATH_ADDRESSES);
    }
    CxPlatDispatchLockUninitialize(&Monitor->Lock);
    CXPLAT_FREE(Monitor, QUIC_POOL_DATAPATH_ADDRESSES);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
CxPlatAddressMonitorGetSnapshot(
    _In_ CXPLAT_ADDRESS_MONITOR* Monitor,
    _Outptr_result_buffer_(*Count) CXPLAT_LOCAL_ADDRESS** Addresses,
    _Out_ uint32_t* Count,
    _Out_ uint64_t* Generation
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_LOCAL_ADDRESS* Copy = NULL;

    CxPlatDispatchLockAcquire(&Monitor->Lock);

    if (Monitor->AddressCount != 0) {
        Copy =
            CXPLAT_ALLOC_NONPAGED(
                Monitor->AddressCount * sizeof(CXPLAT_LOCAL_ADDRESS),
                QUIC_POOL_DATAPATH_ADDRESSES);
        if (Copy == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Exit;
        }
        CxPlatCopyMemory(
            Copy,
            Monitor->Addresses,
            Monitor->AddressCount * sizeof(CXPLAT_LOCAL_ADDRESS));
    }

    *Addresses = Copy;
    *Count = Monitor->AddressCount;
    *Generation = Monitor->Generation;

Exit:

    CxPlatDispatchLockRelease(&Monitor->Lock);

    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "address monitor snapshot copy",
            (uint64_t)Monitor->AddressCount * sizeof(CXPLAT_LOCAL_ADDRESS));
    }

    return Status;
}

#else // CXPLAT_ADDRESS_MONITOR_SUPPORTED

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatAddressMonitorInitialize(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_ const CXPLAT_ADDRESS_MONITOR_CONFIG* Config,
    _Outptr_ CXPLAT_ADDRESS_MONITOR** Monitor
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    UNREFERENCED_PARAMETER(Config);
    UNREFERENCED_PARAMETER(Monitor);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatAddressMonitorUninitialize(
    _In_ CXPLAT_ADDRESS_MONITOR* Monitor
    )
{
    UNREFERENCED_PARAMETER(Monitor);
    CXPLAT_DBG_ASSERT(FALSE); // Initialize never succeeded, so there is nothing to free.
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
CxPlatAddressMonitorGetSnapshot(
    _In_ CXPLAT_ADDRESS_MONITOR* Monitor,
    _Outptr_result_buffer_(*Count) CXPLAT_LOCAL_ADDRESS** Addresses,
    _Out_ uint32_t* Count,
    _Out_ uint64_t* Generation
    )
{
    UNREFERENCED_PARAMETER(Monitor);
    UNREFERENCED_PARAMETER(Addresses);
    UNREFERENCED_PARAMETER(Count);
    UNREFERENCED_PARAMETER(Generation);
    return QUIC_STATUS_NOT_SUPPORTED;
}

#endif // CXPLAT_ADDRESS_MONITOR_SUPPORTED
