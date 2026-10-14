/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Datapath Implementation (User Mode)

--*/

#include "platform_internal.h"
#include "address_monitor.h"

#ifdef QUIC_CLOG
#include "datapath_unix.c.clog.h"
#endif

#pragma warning(disable:4116) // unnamed type definition in parentheses

#pragma warning(disable:4100) // unreferenced
#pragma warning(disable:6101) // uninitialized
#pragma warning(disable:6386) // buffer overrun

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(QUIC_SUCCEEDED(return))
QUIC_STATUS
CxPlatDataPathGetLocalAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*Addresses, __drv_allocatesMem(Mem))
        CXPLAT_ADAPTER_ADDRESS** Addresses,
    _Out_ uint32_t* AddressesCount
    )
{
#if defined(CXPLAT_ADDRESS_MONITOR_SUPPORTED)
    //
    // Answered from the address monitor's own enumeration rather than a second
    // implementation of the same thing. The monitor is not required to be
    // running: the enumeration does not depend on a subscription, so this works
    // whether or not anything has asked to be notified.
    //
    UNREFERENCED_PARAMETER(Datapath);

    *Addresses = NULL;
    *AddressesCount = 0;

    CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Raw = NULL;
    uint32_t RawCount = 0;
    QUIC_STATUS Status = CxPlatAddressMonitorOsEnumerate(NULL, &Raw, &RawCount);
    if (QUIC_FAILED(Status)) {
        return Status;
    }

    if (RawCount == 0) {
        return QUIC_STATUS_SUCCESS;
    }

    CXPLAT_LOCAL_ADDRESS* Filtered =
        CXPLAT_ALLOC_NONPAGED(
            RawCount * sizeof(CXPLAT_LOCAL_ADDRESS), QUIC_POOL_DATAPATH_ADDRESSES);
    if (Filtered == NULL) {
        CXPLAT_FREE(Raw, QUIC_POOL_DATAPATH_ADDRESSES);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    uint32_t Count = 0;
    CxPlatAddressMonitorFilter(Raw, RawCount, Filtered, &Count);
    CXPLAT_FREE(Raw, QUIC_POOL_DATAPATH_ADDRESSES);

    if (Count == 0) {
        CXPLAT_FREE(Filtered, QUIC_POOL_DATAPATH_ADDRESSES);
        return QUIC_STATUS_SUCCESS;
    }

    CXPLAT_ADAPTER_ADDRESS* Result =
        CXPLAT_ALLOC_NONPAGED(
            Count * sizeof(CXPLAT_ADAPTER_ADDRESS), QUIC_POOL_DATAPATH_ADDRESSES);
    if (Result == NULL) {
        CXPLAT_FREE(Filtered, QUIC_POOL_DATAPATH_ADDRESSES);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    for (uint32_t i = 0; i < Count; ++i) {
        CxPlatZeroMemory(&Result[i], sizeof(Result[i]));
        Result[i].Address = Filtered[i].Address;
        Result[i].InterfaceIndex = Filtered[i].InterfaceIndex;
        Result[i].InterfaceType = Filtered[i].InterfaceType;
        //
        // The filter already dropped everything on an interface that is not
        // operationally up, so what is left is up by construction.
        //
        Result[i].OperationStatus = CXPLAT_OPERATION_STATUS_UP;
    }

    CXPLAT_FREE(Filtered, QUIC_POOL_DATAPATH_ADDRESSES);

    *Addresses = Result;
    *AddressesCount = Count;
    return QUIC_STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(Datapath);
    *Addresses = NULL;
    *AddressesCount = 0;
    return QUIC_STATUS_NOT_SUPPORTED;
#endif
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathGetLocalAddressForRemote(
    _In_ const QUIC_ADDR* RemoteAddress,
    _Out_ QUIC_ADDR* LocalAddress
    )
{
    UNREFERENCED_PARAMETER(RemoteAddress);
    UNREFERENCED_PARAMETER(LocalAddress);
    return QUIC_STATUS_NOT_SUPPORTED;
}

QUIC_STATUS
CxPlatDataPathGetGatewayAddresses(
    _In_ CXPLAT_DATAPATH* Datapath,
    _Outptr_ _At_(*GatewayAddresses, __drv_allocatesMem(Mem))
        QUIC_ADDR** GatewayAddresses,
    _Out_ uint32_t* GatewayAddressesCount
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    *GatewayAddresses = NULL;
    *GatewayAddressesCount = 0;
    return QUIC_STATUS_NOT_SUPPORTED;
}

// private func
void
CxPlatDataPathPopulateTargetAddress(
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_ ADDRINFO* AddrInfo,
    _Out_ QUIC_ADDR* Address
    )
{
    struct sockaddr_in6* SockAddrIn6 = NULL;
    struct sockaddr_in* SockAddrIn = NULL;

    CxPlatZeroMemory(Address, sizeof(QUIC_ADDR));

    if (AddrInfo->ai_addr->sa_family == AF_INET6) {
        CXPLAT_DBG_ASSERT(sizeof(struct sockaddr_in6) == AddrInfo->ai_addrlen);

        //
        // Is this a mapped ipv4 one?
        //
        SockAddrIn6 = (struct sockaddr_in6*)AddrInfo->ai_addr;
        if (Family == QUIC_ADDRESS_FAMILY_UNSPEC && IN6_IS_ADDR_V4MAPPED(&SockAddrIn6->sin6_addr)) {
            SockAddrIn = &Address->Ipv4;

            //
            // Get the ipv4 address from the mapped address.
            //
            SockAddrIn->sin_family = QUIC_ADDRESS_FAMILY_INET;
            memcpy(&SockAddrIn->sin_addr.s_addr, &SockAddrIn6->sin6_addr.s6_addr[12], 4);
            SockAddrIn->sin_port = SockAddrIn6->sin6_port;

            return;
        }
        Address->Ipv6 = *SockAddrIn6;
        Address->Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
        return;
    }

    if (AddrInfo->ai_addr->sa_family == AF_INET) {
        CXPLAT_DBG_ASSERT(sizeof(struct sockaddr_in) == AddrInfo->ai_addrlen);
        SockAddrIn = (struct sockaddr_in*)AddrInfo->ai_addr;
        Address->Ipv4 = *SockAddrIn;
        Address->Ipv4.sin_family = QUIC_ADDRESS_FAMILY_INET;
        return;
    }

    CXPLAT_FRE_ASSERT(FALSE);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatDataPathResolveAddress(
    _In_ CXPLAT_DATAPATH* Datapath,
    _In_z_ const char* HostName,
    _Inout_ QUIC_ADDR* Address
    )
{
    UNREFERENCED_PARAMETER(Datapath);
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    ADDRINFO Hints = {0};
    ADDRINFO* AddrInfo = NULL;
    int Result = 0;

    //
    // Prepopulate hint with input family. It might be unspecified.
    //
    Hints.ai_family = Address->Ip.sa_family;
    if (Hints.ai_family == QUIC_ADDRESS_FAMILY_INET6) {
        Hints.ai_family = AF_INET6;
    }

    //
    // Try numeric name first.
    //
    Hints.ai_flags = AI_NUMERICHOST;
    Result = getaddrinfo(HostName, NULL, &Hints, &AddrInfo);
    if (Result == 0) {
        CxPlatDataPathPopulateTargetAddress(Hints.ai_family, AddrInfo, Address);
        freeaddrinfo(AddrInfo);
        AddrInfo = NULL;
        goto Exit;
    }

    //
    // Try canonical host name.
    //
    Hints.ai_flags = AI_CANONNAME;
    Result = getaddrinfo(HostName, NULL, &Hints, &AddrInfo);
    if (Result == 0) {
        CxPlatDataPathPopulateTargetAddress(Hints.ai_family, AddrInfo, Address);
        freeaddrinfo(AddrInfo);
        AddrInfo = NULL;
        goto Exit;
    }

    QuicTraceEvent(
        LibraryErrorStatus,
        "[ lib] ERROR, %u, %s.",
        (uint32_t)Result,
        "Resolving hostname to IP");
    QuicTraceLogError(
        DatapathResolveHostNameFailed,
        "[%p] Couldn't resolve hostname '%s' to an IP address",
        Datapath,
        HostName);
    Status = (QUIC_STATUS)Result;

Exit:

    return Status;
}
