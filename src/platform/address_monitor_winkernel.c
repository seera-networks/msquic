/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    The kernel-mode half of the Windows local address monitor: the enumeration.
    Subscription, debounce and teardown are shared with user mode in
    address_monitor_win.c.

    GetUnicastIpAddressTable joined with GetIpInterfaceTable, which is the pair
    datapath_winkernel.c already uses to answer CxPlatDataPathGetLocalAddresses
    -- there is no GetAdaptersAddresses in the kernel. The address table
    carries everything per-address that the filter wants, including the IANA
    interface type on the LUID; the interface table is needed only for whether
    the interface is up.

--*/

#include "platform_internal.h"
#include "address_monitor.h"

#ifdef QUIC_CLOG
#include "address_monitor_winkernel.c.clog.h"
#endif

#if defined(CXPLAT_ADDRESS_MONITOR_SUPPORTED)

//
// Turns one MIB_UNICASTIPADDRESS_ROW, plus the interface row it belongs to,
// into the raw form the shared filter takes. The flags it cannot see from the
// address alone -- tentative, and whether the interface is up -- are the two
// booleans the filter uses and discards.
//
static
void
CxPlatAddressMonitorFromMibRow(
    _In_ const MIB_UNICASTIPADDRESS_ROW* Row,
    _In_opt_ const MIB_IPINTERFACE_ROW* Interface,
    _Out_ CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Entry
    )
{
    CxPlatZeroMemory(Entry, sizeof(*Entry));

    CxPlatCopyMemory(&Entry->Address.Address, &Row->Address, sizeof(QUIC_ADDR));
    QuicAddrSetPort(&Entry->Address.Address, 0);

    Entry->Address.InterfaceIndex = (uint32_t)Row->InterfaceIndex;
    Entry->Address.InterfaceType = (uint16_t)Row->InterfaceLuid.Info.IfType;

    //
    // Deprecated means the preferred lifetime has expired, which is what
    // DadStateDeprecated reports; a zero preferred lifetime says the same thing
    // and is checked too, since the two are set independently.
    //
    if (Row->DadState == IpDadStateDeprecated ||
        Row->PreferredLifetime == 0) {
        Entry->Address.Flags |= CXPLAT_ADDRESS_FLAG_DEPRECATED;
    }

    //
    // TEMPORARY is deliberately not set, for the reason the user-mode
    // enumeration records at length: Windows randomizes interface identifiers
    // by default, so SuffixOrigin == IpSuffixOriginRandom describes the stable
    // public SLAAC address as well as the RFC 8981 temporary one, and
    // MIB_UNICASTIPADDRESS_ROW carries nothing that separates them. A wrong
    // flag misdirects phase 3's selection; an unset one merely leaves that
    // preference with nothing to say.
    //

    CxPlatAddressMonitorWinSetScopeFlags(&Entry->Address);

    //
    // Tentative covers both "still doing duplicate address detection" and
    // "detection failed": binding to either fails or is about to, and the
    // filter drops them. A tentative address reappears on the resync that
    // follows detection completing, which is itself a notification.
    //
    Entry->Tentative =
        Row->DadState == IpDadStateTentative ||
        Row->DadState == IpDadStateInvalid ||
        Row->DadState == IpDadStateDuplicate;

    //
    // The kernel's notion of "up" is MIB_IPINTERFACE_ROW.Connected, which is
    // what datapath_winkernel.c already maps to CXPLAT_OPERATION_STATUS_UP. An
    // address whose interface is not in the table at all counts as not up:
    // there is nothing to say it is, and the filter's job is to drop what
    // cannot carry traffic.
    //
    Entry->InterfaceUp = Interface != NULL && Interface->Connected;
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
    MIB_IPINTERFACE_TABLE* InterfaceTable = NULL;
    MIB_UNICASTIPADDRESS_TABLE* AddressTable = NULL;
    CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Entries = NULL;

    *Raw = NULL;
    *RawCount = 0;

    Status = GetIpInterfaceTable(AF_UNSPEC, &InterfaceTable);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "GetIpInterfaceTable(address monitor)");
        goto Exit;
    }

    Status = GetUnicastIpAddressTable(AF_UNSPEC, &AddressTable);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "GetUnicastIpAddressTable(address monitor)");
        goto Exit;
    }

    if (AddressTable->NumEntries == 0) {
        //
        // A host with no unicast address at all. An empty snapshot, not a
        // failure: the consumer's answer is "nothing to send from", which is a
        // state the core already handles.
        //
        goto Exit;
    }

    Entries =
        CXPLAT_ALLOC_NONPAGED(
            AddressTable->NumEntries * sizeof(CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS),
            QUIC_POOL_DATAPATH_ADDRESSES);
    if (Entries == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "address monitor raw addresses",
            (uint64_t)AddressTable->NumEntries * sizeof(CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    uint32_t Index = 0;
    for (ULONG i = 0; i < AddressTable->NumEntries; ++i) {
        const MIB_UNICASTIPADDRESS_ROW* Row = &AddressTable->Table[i];

        const ADDRESS_FAMILY Family = Row->Address.si_family;
        if (Family != AF_INET && Family != AF_INET6) {
            continue;
        }

        //
        // Linear, because both tables are small and sorted by nothing in
        // particular. datapath_winkernel.c joins them the same way.
        //
        const MIB_IPINTERFACE_ROW* Interface = NULL;
        for (ULONG j = 0; j < InterfaceTable->NumEntries; ++j) {
            if (InterfaceTable->Table[j].InterfaceIndex == Row->InterfaceIndex) {
                Interface = &InterfaceTable->Table[j];
                break;
            }
        }

        CxPlatAddressMonitorFromMibRow(Row, Interface, &Entries[Index]);
        ++Index;
    }

    *Raw = Entries;
    *RawCount = Index;
    Entries = NULL;

Exit:

    if (Entries != NULL) {
        CXPLAT_FREE(Entries, QUIC_POOL_DATAPATH_ADDRESSES);
    }
    if (AddressTable != NULL) {
        FreeMibTable(AddressTable);
    }
    if (InterfaceTable != NULL) {
        FreeMibTable(InterfaceTable);
    }
    return Status;
}

#endif // CXPLAT_ADDRESS_MONITOR_SUPPORTED
