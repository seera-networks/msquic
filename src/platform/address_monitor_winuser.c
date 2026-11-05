/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    The user-mode half of the Windows local address monitor: the enumeration.
    Subscription, debounce and teardown are shared with the kernel in
    address_monitor_win.c.

    GetAdaptersAddresses rather than the design sketch's
    GetUnicastIpAddressTable joined with GetIfTable2. One call supplies
    everything the filter needs -- the address, interface index and IANA
    interface type, the per-address DadState, SuffixOrigin and
    PreferredLifetime, and the adapter's OperStatus -- so there is no table
    join to get wrong, and it is the same API this datapath already
    enumerates addresses with.

--*/

#include "platform_internal.h"
#include "address_monitor.h"

#ifdef QUIC_CLOG
#include "address_monitor_winuser.c.clog.h"
#endif

#if defined(CXPLAT_ADDRESS_MONITOR_SUPPORTED)


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

    CxPlatAddressMonitorWinSetScopeFlags(&Entry->Address);

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

#endif // CXPLAT_ADDRESS_MONITOR_SUPPORTED
