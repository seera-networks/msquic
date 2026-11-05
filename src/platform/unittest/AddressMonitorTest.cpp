/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Tests for the address monitor's filter and diff.

    Neither touches the OS, so a synthetic enumeration can put the monitor in
    states a real host is hard to hold still in -- an address part way through
    duplicate address detection, an interface going down under an address, the
    same link-local address on two interfaces.

--*/

#include "main.h"
#include "quic_datapath.h"
#include "address_monitor.h"

#include <vector>
#include <utility>
#include <mutex>

#ifdef QUIC_CLOG
#include "AddressMonitorTest.cpp.clog.h"
#endif

struct AddressMonitorTest : public ::testing::Test
{
    static CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS MakeV4(
        const char* Address,
        uint32_t InterfaceIndex = 2,
        CXPLAT_ADDRESS_FLAGS Flags = CXPLAT_ADDRESS_FLAG_NONE,
        bool Tentative = false,
        bool InterfaceUp = true)
    {
        CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS Entry;
        CxPlatZeroMemory(&Entry, sizeof(Entry));
        EXPECT_TRUE(QuicAddrFromString(Address, 0, &Entry.Address.Address));
        Entry.Address.InterfaceIndex = InterfaceIndex;
        Entry.Address.InterfaceType = 6;
        Entry.Address.Flags = Flags;
        Entry.Tentative = Tentative ? TRUE : FALSE;
        Entry.InterfaceUp = InterfaceUp ? TRUE : FALSE;
        return Entry;
    }

    static CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS MakeV6(
        const char* Address,
        uint32_t ScopeId = 0,
        uint32_t InterfaceIndex = 2,
        bool InterfaceUp = true)
    {
        CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS Entry;
        CxPlatZeroMemory(&Entry, sizeof(Entry));
        EXPECT_TRUE(QuicAddrFromString(Address, 0, &Entry.Address.Address));
        Entry.Address.Address.Ipv6.sin6_scope_id = ScopeId;
        Entry.Address.InterfaceIndex = InterfaceIndex;
        Entry.Address.InterfaceType = 6;
        Entry.InterfaceUp = InterfaceUp ? TRUE : FALSE;
        return Entry;
    }

    static CXPLAT_LOCAL_ADDRESS Filtered(const CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS& Raw)
    {
        CXPLAT_LOCAL_ADDRESS Out[1];
        uint32_t Count = 0;
        CxPlatAddressMonitorFilter(&Raw, 1, Out, &Count);
        EXPECT_EQ(1u, Count);
        return Out[0];
    }
};

TEST_F(AddressMonitorTest, FilterKeepsUsableAddresses)
{
    const CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS Raw[] = {
        MakeV4("192.0.2.10"),
        MakeV6("2001:db8::1"),
    };
    CXPLAT_LOCAL_ADDRESS Out[2];
    uint32_t Count = 0;
    CxPlatAddressMonitorFilter(Raw, 2, Out, &Count);

    ASSERT_EQ(2u, Count);
    //
    // The port is always zero on the way out, whatever the backend reported,
    // because a snapshot entry names an address and not an endpoint.
    //
    ASSERT_EQ(0, QuicAddrGetPort(&Out[0].Address));
    ASSERT_EQ(0, QuicAddrGetPort(&Out[1].Address));
}

TEST_F(AddressMonitorTest, FilterDropsTentativeAndDownAndNonSource)
{
    CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS Raw[6];
    Raw[0] = MakeV4("192.0.2.10");                                  // kept
    Raw[1] = MakeV4("192.0.2.11", 2, CXPLAT_ADDRESS_FLAG_NONE, true);  // tentative
    Raw[2] = MakeV4("192.0.2.12", 2, CXPLAT_ADDRESS_FLAG_NONE, false, false); // down
    Raw[3] = MakeV4("0.0.0.0");                                     // unspecified
    Raw[4] = MakeV4("239.0.0.1");                                   // multicast
    Raw[5] = MakeV6("ff02::1");                                     // multicast

    CXPLAT_LOCAL_ADDRESS Out[6];
    uint32_t Count = 0;
    CxPlatAddressMonitorFilter(Raw, 6, Out, &Count);

    ASSERT_EQ(1u, Count);
    //
    // Zeroed first: QuicAddrFromString sets only what it parses, so the port of
    // a bare local is whatever was on the stack -- and QuicAddrCompare compares
    // ports.
    //
    QUIC_ADDR Expected;
    CxPlatZeroMemory(&Expected, sizeof(Expected));
    ASSERT_TRUE(QuicAddrFromString("192.0.2.10", 0, &Expected));
    ASSERT_TRUE(QuicAddrCompare(&Expected, &Out[0].Address));
}

TEST_F(AddressMonitorTest, FilterKeepsButFlagsPolicyAddresses)
{
    //
    // Loopback, link-local, temporary and deprecated stay in the snapshot. What
    // to do with one of those is policy, and policy is not the platform's call
    // -- dropping them here would take the decision away from the only layer
    // that knows the peer.
    //
    const CXPLAT_LOCAL_ADDRESS Deprecated =
        Filtered(MakeV4("192.0.2.10", 2, CXPLAT_ADDRESS_FLAG_DEPRECATED));
    ASSERT_EQ(
        (uint32_t)CXPLAT_ADDRESS_FLAG_DEPRECATED,
        (uint32_t)(Deprecated.Flags & CXPLAT_ADDRESS_FLAG_DEPRECATED));

    const CXPLAT_LOCAL_ADDRESS Loopback =
        Filtered(MakeV4("127.0.0.1", 1, CXPLAT_ADDRESS_FLAG_LOOPBACK));
    ASSERT_EQ(
        (uint32_t)CXPLAT_ADDRESS_FLAG_LOOPBACK,
        (uint32_t)(Loopback.Flags & CXPLAT_ADDRESS_FLAG_LOOPBACK));
}

TEST_F(AddressMonitorTest, FilterInPlace)
{
    //
    // The contract allows the output to alias the input, which is what the
    // resync path does to avoid a second allocation.
    //
    CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS Raw[3];
    Raw[0] = MakeV4("192.0.2.10", 2, CXPLAT_ADDRESS_FLAG_NONE, true); // dropped
    Raw[1] = MakeV4("192.0.2.11");
    Raw[2] = MakeV4("192.0.2.12");

    uint32_t Count = 0;
    CxPlatAddressMonitorFilter(Raw, 3, (CXPLAT_LOCAL_ADDRESS*)Raw, &Count);

    ASSERT_EQ(2u, Count);
    QUIC_ADDR Expected;
    CxPlatZeroMemory(&Expected, sizeof(Expected));
    ASSERT_TRUE(QuicAddrFromString("192.0.2.11", 0, &Expected));
    ASSERT_TRUE(QuicAddrCompare(&Expected, &((CXPLAT_LOCAL_ADDRESS*)Raw)[0].Address));
}

TEST_F(AddressMonitorTest, DiffAddAndRemove)
{
    CXPLAT_LOCAL_ADDRESS Old[1] = { Filtered(MakeV4("192.0.2.10")) };
    CXPLAT_LOCAL_ADDRESS New[1] = { Filtered(MakeV4("198.51.100.5")) };

    CXPLAT_ADDRESS_CHANGE Changes[2];
    uint32_t Count = 0;
    BOOLEAN Consumed[8] = {0};
    CxPlatAddressMonitorDiff(Old, 1, New, 1, Consumed, Changes, &Count);

    ASSERT_EQ(2u, Count);
    ASSERT_EQ(CXPLAT_ADDRESS_CHANGE_ADDED, Changes[0].Type);
    ASSERT_EQ(CXPLAT_ADDRESS_CHANGE_REMOVED, Changes[1].Type);
}

TEST_F(AddressMonitorTest, DiffNoChange)
{
    CXPLAT_LOCAL_ADDRESS Both[2] = {
        Filtered(MakeV4("192.0.2.10")),
        Filtered(MakeV6("2001:db8::1")),
    };
    CXPLAT_ADDRESS_CHANGE Changes[4];
    uint32_t Count = 0;
    BOOLEAN Consumed[8] = {0};
    CxPlatAddressMonitorDiff(Both, 2, Both, 2, Consumed, Changes, &Count);
    ASSERT_EQ(0u, Count);
}

TEST_F(AddressMonitorTest, DiffReordered)
{
    //
    // A netlink dump does not promise an order, so the same set arriving in a
    // different order has to diff to nothing. Comparing position by position
    // would make every dump look like a change.
    //
    CXPLAT_LOCAL_ADDRESS Old[2] = {
        Filtered(MakeV4("192.0.2.10")),
        Filtered(MakeV4("198.51.100.5")),
    };
    CXPLAT_LOCAL_ADDRESS New[2] = { Old[1], Old[0] };

    CXPLAT_ADDRESS_CHANGE Changes[4];
    uint32_t Count = 0;
    BOOLEAN Consumed[8] = {0};
    CxPlatAddressMonitorDiff(Old, 2, New, 2, Consumed, Changes, &Count);
    ASSERT_EQ(0u, Count);
}

TEST_F(AddressMonitorTest, DiffFlagChangeIsUpdateNotRemoveAndAdd)
{
    //
    // An address whose preferred lifetime expired is the same address. Saying
    // so as one UPDATED rather than a REMOVED and an ADDED is what lets a
    // consumer keep whatever it had bound to it.
    //
    CXPLAT_LOCAL_ADDRESS Old[1] = { Filtered(MakeV4("192.0.2.10")) };
    CXPLAT_LOCAL_ADDRESS New[1] = {
        Filtered(MakeV4("192.0.2.10", 2, CXPLAT_ADDRESS_FLAG_DEPRECATED))
    };

    CXPLAT_ADDRESS_CHANGE Changes[2];
    uint32_t Count = 0;
    BOOLEAN Consumed[8] = {0};
    CxPlatAddressMonitorDiff(Old, 1, New, 1, Consumed, Changes, &Count);

    ASSERT_EQ(1u, Count);
    ASSERT_EQ(CXPLAT_ADDRESS_CHANGE_UPDATED, Changes[0].Type);
}

TEST_F(AddressMonitorTest, DiffInterfaceChangeIsUpdate)
{
    CXPLAT_LOCAL_ADDRESS Old[1] = { Filtered(MakeV4("192.0.2.10", 2)) };
    CXPLAT_LOCAL_ADDRESS New[1] = { Filtered(MakeV4("192.0.2.10", 7)) };

    CXPLAT_ADDRESS_CHANGE Changes[2];
    uint32_t Count = 0;
    BOOLEAN Consumed[8] = {0};
    CxPlatAddressMonitorDiff(Old, 1, New, 1, Consumed, Changes, &Count);

    ASSERT_EQ(1u, Count);
    ASSERT_EQ(CXPLAT_ADDRESS_CHANGE_UPDATED, Changes[0].Type);
    ASSERT_EQ(7u, Changes[0].Address.InterfaceIndex);
}

TEST_F(AddressMonitorTest, DiffScopeIdSeparatesLinkLocals)
{
    //
    // fe80::1 on two interfaces is two addresses. QuicAddrCompare does not look
    // at the scope ID, so identity has to compare it separately -- without
    // that, one of these would hide the other and losing it would go unnoticed.
    //
    CXPLAT_LOCAL_ADDRESS Old[1] = { Filtered(MakeV6("fe80::1", 2, 2)) };
    CXPLAT_LOCAL_ADDRESS New[1] = { Filtered(MakeV6("fe80::1", 3, 3)) };

    CXPLAT_ADDRESS_CHANGE Changes[2];
    uint32_t Count = 0;
    BOOLEAN Consumed[8] = {0};
    CxPlatAddressMonitorDiff(Old, 1, New, 1, Consumed, Changes, &Count);

    ASSERT_EQ(2u, Count);
    ASSERT_EQ(CXPLAT_ADDRESS_CHANGE_ADDED, Changes[0].Type);
    ASSERT_EQ(CXPLAT_ADDRESS_CHANGE_REMOVED, Changes[1].Type);
}

TEST_F(AddressMonitorTest, DiffDadCompletion)
{
    //
    // An address in duplicate address detection is absent from the snapshot and
    // appears once it completes, which is the resync after the OS says so.
    // Before the fix for this the address never appeared at all.
    //
    const CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS Tentative =
        MakeV6("2001:db8::1", 0, 2);
    CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS Raw = Tentative;
    Raw.Tentative = TRUE;

    CXPLAT_LOCAL_ADDRESS Before[1];
    uint32_t BeforeCount = 0;
    CxPlatAddressMonitorFilter(&Raw, 1, Before, &BeforeCount);
    ASSERT_EQ(0u, BeforeCount);

    CXPLAT_LOCAL_ADDRESS After[1];
    uint32_t AfterCount = 0;
    CxPlatAddressMonitorFilter(&Tentative, 1, After, &AfterCount);
    ASSERT_EQ(1u, AfterCount);

    CXPLAT_ADDRESS_CHANGE Changes[1];
    uint32_t Count = 0;
    BOOLEAN Consumed[8] = {0};
    CxPlatAddressMonitorDiff(Before, BeforeCount, After, AfterCount, Consumed, Changes, &Count);
    ASSERT_EQ(1u, Count);
    ASSERT_EQ(CXPLAT_ADDRESS_CHANGE_ADDED, Changes[0].Type);
}

TEST_F(AddressMonitorTest, DiffDuplicateIdentityRemoval)
{
    //
    // The same global address on two interfaces is two entries sharing one
    // identity key, since identity excludes the interface index on purpose and
    // the scope ID is only set for IPv6 link-local. An anycast /32 on lo
    // alongside a real interface is the ordinary way to get here.
    //
    // Matching first-found made deleting one copy produce no change at all,
    // and CxPlatAddressMonitorResync then discarded the new snapshot and never
    // moved the generation again -- so the monitor reported an address on an
    // interface that no longer had it, for the life of the process.
    //
    CXPLAT_LOCAL_ADDRESS Old[2] = {
        Filtered(MakeV4("192.0.2.99", 2)),
        Filtered(MakeV4("192.0.2.99", 3)),
    };
    CXPLAT_LOCAL_ADDRESS New[1] = { Old[0] };

    CXPLAT_ADDRESS_CHANGE Changes[3];
    uint32_t Count = 0;
    BOOLEAN Consumed[8] = {0};
    CxPlatAddressMonitorDiff(Old, 2, New, 1, Consumed, Changes, &Count);

    ASSERT_EQ(1u, Count);
    ASSERT_EQ(CXPLAT_ADDRESS_CHANGE_REMOVED, Changes[0].Type);
    ASSERT_EQ(3u, Changes[0].Address.InterfaceIndex);
}

TEST_F(AddressMonitorTest, DiffDuplicateIdentityAddition)
{
    CXPLAT_LOCAL_ADDRESS Old[1] = { Filtered(MakeV4("192.0.2.99", 2)) };
    CXPLAT_LOCAL_ADDRESS New[2] = {
        Old[0],
        Filtered(MakeV4("192.0.2.99", 3)),
    };

    CXPLAT_ADDRESS_CHANGE Changes[3];
    uint32_t Count = 0;
    BOOLEAN Consumed[8] = {0};
    CxPlatAddressMonitorDiff(Old, 1, New, 2, Consumed, Changes, &Count);

    ASSERT_EQ(1u, Count);
    ASSERT_EQ(CXPLAT_ADDRESS_CHANGE_ADDED, Changes[0].Type);
    ASSERT_EQ(3u, Changes[0].Address.InterfaceIndex);
}

TEST_F(AddressMonitorTest, DiffDuplicateIdentityUnchanged)
{
    //
    // Two copies staying two copies is not a change, whichever order the dump
    // lists them in.
    //
    CXPLAT_LOCAL_ADDRESS Old[2] = {
        Filtered(MakeV4("192.0.2.99", 2)),
        Filtered(MakeV4("192.0.2.99", 3)),
    };
    CXPLAT_LOCAL_ADDRESS New[2] = { Old[1], Old[0] };

    CXPLAT_ADDRESS_CHANGE Changes[4];
    uint32_t Count = 0;
    BOOLEAN Consumed[8] = {0};
    CxPlatAddressMonitorDiff(Old, 2, New, 2, Consumed, Changes, &Count);
    ASSERT_EQ(0u, Count);
}

TEST_F(AddressMonitorTest, DiffEmptySnapshots)
{
    CXPLAT_LOCAL_ADDRESS One[1] = { Filtered(MakeV4("192.0.2.10")) };
    CXPLAT_ADDRESS_CHANGE Changes[2];
    uint32_t Count = 0;

    BOOLEAN Consumed[8] = {0};

    CxPlatAddressMonitorDiff(NULL, 0, One, 1, Consumed, Changes, &Count);
    ASSERT_EQ(1u, Count);
    ASSERT_EQ(CXPLAT_ADDRESS_CHANGE_ADDED, Changes[0].Type);

    CxPlatAddressMonitorDiff(One, 1, NULL, 0, Consumed, Changes, &Count);
    ASSERT_EQ(1u, Count);
    ASSERT_EQ(CXPLAT_ADDRESS_CHANGE_REMOVED, Changes[0].Type);

    CxPlatAddressMonitorDiff(NULL, 0, NULL, 0, Consumed, Changes, &Count);
    ASSERT_EQ(0u, Count);
}

#if defined(CXPLAT_ADDRESS_MONITOR_SUPPORTED)

//
// The real backend, against whatever this host has. It cannot assert a
// particular address exists -- and must not assert that *any* usable one does,
// because a fresh network namespace has only lo and lo is down in one, which is
// exactly the case the "interface is operationally up" filter exists for.
//
TEST_F(AddressMonitorTest, EnumerateRealHost)
{
    CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Raw = NULL;
    uint32_t RawCount = 0;
    ASSERT_TRUE(QUIC_SUCCEEDED(CxPlatAddressMonitorOsEnumerate(NULL, &Raw, &RawCount)));

    CXPLAT_LOCAL_ADDRESS* Filtered = NULL;
    uint32_t Count = 0;
    if (Raw != nullptr && RawCount != 0) {
        Filtered =
            (CXPLAT_LOCAL_ADDRESS*)CXPLAT_ALLOC_NONPAGED(
                RawCount * sizeof(CXPLAT_LOCAL_ADDRESS), QUIC_POOL_DATAPATH_ADDRESSES);
        ASSERT_NE(nullptr, Filtered);
        CxPlatAddressMonitorFilter(Raw, RawCount, Filtered, &Count);
    }

    //
    // Anything that survived has to carry no port and to have come from an
    // interface the enumeration reported up and not tentative.
    //
    for (uint32_t i = 0; i < Count; ++i) {
        ASSERT_EQ(0, QuicAddrGetPort(&Filtered[i].Address));

        bool FoundRaw = false;
        for (uint32_t j = 0; j < RawCount; ++j) {
            if (QuicAddrGetFamily(&Raw[j].Address.Address) ==
                    QuicAddrGetFamily(&Filtered[i].Address) &&
                QuicAddrCompareIp(&Raw[j].Address.Address, &Filtered[i].Address)) {
                ASSERT_TRUE(Raw[j].InterfaceUp);
                ASSERT_FALSE(Raw[j].Tentative);
                FoundRaw = true;
                break;
            }
        }
        ASSERT_TRUE(FoundRaw);
    }

    if (Filtered != NULL) {
        CXPLAT_FREE(Filtered, QUIC_POOL_DATAPATH_ADDRESSES);
    }
    if (Raw != NULL) {
        CXPLAT_FREE(Raw, QUIC_POOL_DATAPATH_ADDRESSES);
    }
}

//
// GetLocalAddresses is answered from the same enumeration, and was
// QUIC_STATUS_NOT_SUPPORTED on POSIX before this. Succeeding with nothing is a
// valid answer for the same reason as above, so what is asserted is that it
// succeeds and that everything it does report is marked up and portless.
//
// POSIX only, as the name says. It was gated on CXPLAT_ADDRESS_MONITOR_SUPPORTED
// instead, which was the same thing until Windows gained a backend -- and both
// assertions are wrong there: datapath_winuser.c passes
// GAA_FLAG_INCLUDE_ALL_INTERFACES and copies OperStatus verbatim, so any host
// with a disconnected NIC or an idle virtual adapter reports one that is not
// up, and it does not clear the port either.
//
#ifndef _WIN32
TEST_F(AddressMonitorTest, GetLocalAddressesOnPosix)
{
    CXPLAT_ADAPTER_ADDRESS* Addresses = NULL;
    uint32_t Count = 0;
    ASSERT_TRUE(
        QUIC_SUCCEEDED(CxPlatDataPathGetLocalAddresses(NULL, &Addresses, &Count)));

    for (uint32_t i = 0; i < Count; ++i) {
        ASSERT_EQ(CXPLAT_OPERATION_STATUS_UP, Addresses[i].OperationStatus);
        ASSERT_EQ(0, QuicAddrGetPort(&Addresses[i].Address));
    }

    if (Addresses != NULL) {
        CXPLAT_FREE(Addresses, QUIC_POOL_DATAPATH_ADDRESSES);
    }
}
#endif // !_WIN32

//
// The ifType is an IANA value, not netlink's ARPHRD_*. Loopback is the one
// consumers actually key on -- GetTestInterfaceIndices in the functional tests
// compares against CXPLAT_IF_TYPE_SOFTWARE_LOOPBACK -- so if the mapping is
// missing, that comparison silently never matches on Linux.
//
TEST_F(AddressMonitorTest, LoopbackReportsIanaIfType)
{
    CXPLAT_ADAPTER_ADDRESS* Addresses = NULL;
    uint32_t Count = 0;
    ASSERT_TRUE(
        QUIC_SUCCEEDED(CxPlatDataPathGetLocalAddresses(NULL, &Addresses, &Count)));

    bool SawLoopbackAddress = false;
    bool SawLoopbackIfType = false;
    for (uint32_t i = 0; i < Count; ++i) {
        QUIC_ADDR Loopback4;
        CxPlatZeroMemory(&Loopback4, sizeof(Loopback4));
        ASSERT_TRUE(QuicAddrFromString("127.0.0.1", 0, &Loopback4));
        if (QuicAddrGetFamily(&Addresses[i].Address) == QUIC_ADDRESS_FAMILY_INET &&
            QuicAddrCompareIp(&Loopback4, &Addresses[i].Address)) {
            SawLoopbackAddress = true;
            if (Addresses[i].InterfaceType == CXPLAT_IF_TYPE_SOFTWARE_LOOPBACK) {
                SawLoopbackIfType = true;
            }
        }
    }

    if (Addresses != NULL) {
        CXPLAT_FREE(Addresses, QUIC_POOL_DATAPATH_ADDRESSES);
    }

    if (!SawLoopbackAddress) {
        GTEST_SKIP() << "no usable loopback address here (a bare namespace has lo down)";
    }
    ASSERT_TRUE(SawLoopbackIfType);
}

//
// A down interface's addresses are dropped. The namespace runs prove this by
// accident -- a fresh namespace has lo and only lo, down, so the raw
// enumeration is non-empty there while the filtered snapshot is empty -- and
// this asserts it on purpose instead.
//
TEST_F(AddressMonitorTest, DownInterfaceAddressesAreDropped)
{
    CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Raw = NULL;
    uint32_t RawCount = 0;
    ASSERT_TRUE(QUIC_SUCCEEDED(CxPlatAddressMonitorOsEnumerate(NULL, &Raw, &RawCount)));

    bool AnyDown = false;
    for (uint32_t j = 0; j < RawCount; ++j) {
        if (!Raw[j].InterfaceUp) {
            AnyDown = true;
            break;
        }
    }
    if (!AnyDown) {
        if (Raw != NULL) {
            CXPLAT_FREE(Raw, QUIC_POOL_DATAPATH_ADDRESSES);
        }
        GTEST_SKIP() << "no down interface on this host to check against";
    }

    CXPLAT_LOCAL_ADDRESS* Filtered =
        (CXPLAT_LOCAL_ADDRESS*)CXPLAT_ALLOC_NONPAGED(
            RawCount * sizeof(CXPLAT_LOCAL_ADDRESS), QUIC_POOL_DATAPATH_ADDRESSES);
    ASSERT_NE(nullptr, Filtered);
    uint32_t Count = 0;
    CxPlatAddressMonitorFilter(Raw, RawCount, Filtered, &Count);

    for (uint32_t j = 0; j < RawCount; ++j) {
        if (Raw[j].InterfaceUp) {
            continue;
        }
        for (uint32_t i = 0; i < Count; ++i) {
            ASSERT_FALSE(
                QuicAddrCompareIp(&Raw[j].Address.Address, &Filtered[i].Address) &&
                QuicAddrGetFamily(&Raw[j].Address.Address) ==
                    QuicAddrGetFamily(&Filtered[i].Address));
        }
    }

    CXPLAT_FREE(Filtered, QUIC_POOL_DATAPATH_ADDRESSES);
    CXPLAT_FREE(Raw, QUIC_POOL_DATAPATH_ADDRESSES);
}

//
// The netlink backend end to end, against a dummy interface in a network
// namespace of its own. Needs to be run under `unshare -rn`, which needs no
// root; outside one it cannot create an interface and skips rather than
// touching whatever the host is really using.
//
struct AddressMonitorRealTest : public ::testing::Test
{
    struct Observed {
        std::mutex Lock;
        uint32_t CallbackCount {0};
        //
        // How many change sets carried RouteChanged, and how many carried it
        // with no address change at all. The second is the one route watching
        // is for: a route moved and the snapshot is identical, which is the
        // case the shared resync discards unless the backend tells it.
        //
        uint32_t RouteChangedCount {0};
        uint32_t RouteOnlyCount {0};
        std::vector<std::pair<CXPLAT_ADDRESS_CHANGE_TYPE, QUIC_ADDR>> Changes;
    };

    static void ChangeCallback(void* Context, const CXPLAT_ADDRESS_CHANGE_SET* Set)
    {
        auto* State = static_cast<Observed*>(Context);
        std::lock_guard<std::mutex> Guard(State->Lock);
        ++State->CallbackCount;
        if (Set->RouteChanged) {
            ++State->RouteChangedCount;
            if (Set->ChangeCount == 0) {
                ++State->RouteOnlyCount;
            }
        }
        for (uint32_t i = 0; i < Set->ChangeCount; ++i) {
            State->Changes.emplace_back(
                Set->Changes[i].Type, Set->Changes[i].Address.Address);
        }
    }

    //
    // Waits for a change set that carried a route change and nothing else.
    //
    bool WaitForRouteOnlyChange(Observed& State)
    {
        for (uint32_t Attempt = 0; Attempt < 50; ++Attempt) {
            CxPlatSleep(100);
            std::lock_guard<std::mutex> Guard(State.Lock);
            if (State.RouteOnlyCount != 0) {
                return true;
            }
        }
        return false;
    }

    static bool Run(const char* Command)
    {
        return system(Command) == 0;
    }

    //
    // Whether this process can make an interface at all, which outside a
    // namespace it cannot without root.
    //
    static bool CanCreateInterface()
    {
        if (!Run("ip link add qmonprobe type dummy >/dev/null 2>&1")) {
            return false;
        }
        Run("ip link del qmonprobe >/dev/null 2>&1");
        return true;
    }

    bool WaitForChange(Observed& State, CXPLAT_ADDRESS_CHANGE_TYPE Type, const char* Address)
    {
        QUIC_ADDR Wanted;
        CxPlatZeroMemory(&Wanted, sizeof(Wanted));
        if (!QuicAddrFromString(Address, 0, &Wanted)) {
            return false;
        }

        //
        // Generous: the debounce window has to close before anything is
        // reported, and the test asserts that the change arrives at all rather
        // than how quickly.
        //
        for (uint32_t Attempt = 0; Attempt < 50; ++Attempt) {
            CxPlatSleep(100);
            std::lock_guard<std::mutex> Guard(State.Lock);
            for (const auto& Change : State.Changes) {
                if (Change.first == Type && QuicAddrCompare(&Wanted, &Change.second)) {
                    return true;
                }
            }
        }
        return false;
    }
};

TEST_F(AddressMonitorRealTest, NotifiesOnAddressAddAndRemove)
{
    if (!CanCreateInterface()) {
        GTEST_SKIP() << "needs a network namespace; run under `unshare -rn`";
    }

    ASSERT_TRUE(Run("ip link add qmontest type dummy"));
    ASSERT_TRUE(Run("ip link set qmontest up"));

    Observed State;

    CXPLAT_ADDRESS_MONITOR_CONFIG Config;
    CxPlatZeroMemory(&Config, sizeof(Config));
    Config.Callback = ChangeCallback;
    Config.Context = &State;
    Config.DebounceMs = 50;

    CXPLAT_ADDRESS_MONITOR* Monitor = nullptr;
    ASSERT_TRUE(QUIC_SUCCEEDED(CxPlatAddressMonitorInitialize(nullptr, &Config, &Monitor)));

    //
    // The first snapshot comes back from Initialize, with no callback for it --
    // a consumer that had to wait for one would have nothing to start from.
    //
    CXPLAT_LOCAL_ADDRESS* Initial = nullptr;
    uint32_t InitialCount = 0;
    uint64_t InitialGeneration = 0;
    ASSERT_TRUE(
        QUIC_SUCCEEDED(
            CxPlatAddressMonitorGetSnapshot(
                Monitor, &Initial, &InitialCount, &InitialGeneration)));
    if (Initial != nullptr) {
        CXPLAT_FREE(Initial, QUIC_POOL_DATAPATH_ADDRESSES);
    }
    {
        std::lock_guard<std::mutex> Guard(State.Lock);
        ASSERT_EQ(0u, State.CallbackCount);
    }

    ASSERT_TRUE(Run("ip addr add 192.0.2.77/24 dev qmontest"));
    ASSERT_TRUE(WaitForChange(State, CXPLAT_ADDRESS_CHANGE_ADDED, "192.0.2.77"));

    //
    // The snapshot has it, and the generation moved -- the two have to agree,
    // since a consumer decides whether to reconcile from the generation.
    //
    CXPLAT_LOCAL_ADDRESS* After = nullptr;
    uint32_t AfterCount = 0;
    uint64_t AfterGeneration = 0;
    ASSERT_TRUE(
        QUIC_SUCCEEDED(
            CxPlatAddressMonitorGetSnapshot(Monitor, &After, &AfterCount, &AfterGeneration)));
    ASSERT_GT(AfterGeneration, InitialGeneration);

    QUIC_ADDR Added;
    CxPlatZeroMemory(&Added, sizeof(Added));
    ASSERT_TRUE(QuicAddrFromString("192.0.2.77", 0, &Added));
    bool FoundInSnapshot = false;
    for (uint32_t i = 0; i < AfterCount; ++i) {
        if (QuicAddrCompare(&Added, &After[i].Address)) {
            FoundInSnapshot = true;
        }
    }
    if (After != nullptr) {
        CXPLAT_FREE(After, QUIC_POOL_DATAPATH_ADDRESSES);
    }
    ASSERT_TRUE(FoundInSnapshot);

    ASSERT_TRUE(Run("ip addr del 192.0.2.77/24 dev qmontest"));
    ASSERT_TRUE(WaitForChange(State, CXPLAT_ADDRESS_CHANGE_REMOVED, "192.0.2.77"));

    CxPlatAddressMonitorUninitialize(Monitor);
    Run("ip link del qmontest >/dev/null 2>&1");
}

TEST_F(AddressMonitorRealTest, DebounceCollapsesABurst)
{
    if (!CanCreateInterface()) {
        GTEST_SKIP() << "needs a network namespace; run under `unshare -rn`";
    }

    ASSERT_TRUE(Run("ip link add qmonburst type dummy"));
    ASSERT_TRUE(Run("ip link set qmonburst up"));

    Observed State;

    CXPLAT_ADDRESS_MONITOR_CONFIG Config;
    CxPlatZeroMemory(&Config, sizeof(Config));
    Config.Callback = ChangeCallback;
    Config.Context = &State;
    Config.DebounceMs = 400;

    CXPLAT_ADDRESS_MONITOR* Monitor = nullptr;
    ASSERT_TRUE(QUIC_SUCCEEDED(CxPlatAddressMonitorInitialize(nullptr, &Config, &Monitor)));

    //
    // Four addresses inside one debounce window. Without the window each would
    // be its own resync and its own callback; with it they arrive as one, which
    // is the whole reason it exists -- a single interface transition on a real
    // host produces several notifications, not one.
    //
    ASSERT_TRUE(Run("ip addr add 192.0.2.81/24 dev qmonburst"));
    ASSERT_TRUE(Run("ip addr add 192.0.2.82/24 dev qmonburst"));
    ASSERT_TRUE(Run("ip addr add 192.0.2.83/24 dev qmonburst"));
    ASSERT_TRUE(Run("ip addr add 192.0.2.84/24 dev qmonburst"));

    ASSERT_TRUE(WaitForChange(State, CXPLAT_ADDRESS_CHANGE_ADDED, "192.0.2.84"));

    uint32_t Callbacks = 0;
    size_t AddedSeen = 0;
    {
        std::lock_guard<std::mutex> Guard(State.Lock);
        Callbacks = State.CallbackCount;
        for (const auto& Change : State.Changes) {
            if (Change.first == CXPLAT_ADDRESS_CHANGE_ADDED) {
                ++AddedSeen;
            }
        }
    }

    ASSERT_GE(AddedSeen, 4u);
    //
    // Not "exactly one": the first address can land before the window opens.
    // The claim is that four changes do not cost four callbacks.
    //
    ASSERT_LT(Callbacks, 4u);

    CxPlatAddressMonitorUninitialize(Monitor);
    Run("ip link del qmonburst >/dev/null 2>&1");
}

//
// A route change with the address snapshot untouched. This is the case phase 5
// exists for -- on a host with two interfaces up, the OS can move the default
// route from one to the other without a single address appearing or
// disappearing -- and nothing else in the suite reaches it: every other test
// drives an address change, which is reported whether routes are watched or
// not.
//
TEST_F(AddressMonitorRealTest, NotifiesOnRouteChange)
{
    if (!CanCreateInterface()) {
        GTEST_SKIP() << "needs a network namespace; run under `unshare -rn`";
    }

    ASSERT_TRUE(Run("ip link add qmonroute type dummy"));
    ASSERT_TRUE(Run("ip link set qmonroute up"));
    ASSERT_TRUE(Run("ip addr add 10.5.5.1/24 dev qmonroute"));

    Observed State;

    CXPLAT_ADDRESS_MONITOR_CONFIG Config;
    CxPlatZeroMemory(&Config, sizeof(Config));
    Config.Callback = ChangeCallback;
    Config.Context = &State;
    Config.DebounceMs = 50;
    Config.WatchRoutes = TRUE;

    CXPLAT_ADDRESS_MONITOR* Monitor = nullptr;
    ASSERT_TRUE(QUIC_SUCCEEDED(CxPlatAddressMonitorInitialize(nullptr, &Config, &Monitor)));

    //
    // A route to somewhere that needs no new address, over an interface that
    // already has one. Adding it changes the routing table and nothing else,
    // so a change set only arrives at all if the route subscription is there
    // and the resync was told to keep an empty diff.
    //
    ASSERT_TRUE(Run("ip route add 10.77.0.0/16 dev qmonroute"));
    ASSERT_TRUE(WaitForRouteOnlyChange(State));

    //
    // Taking it away is a change too, and is reported the same way. Checked
    // separately because the backend keys on RTM_NEWROUTE and RTM_DELROUTE
    // independently.
    //
    {
        std::lock_guard<std::mutex> Guard(State.Lock);
        State.RouteOnlyCount = 0;
    }
    ASSERT_TRUE(Run("ip route del 10.77.0.0/16 dev qmonroute"));
    ASSERT_TRUE(WaitForRouteOnlyChange(State));

    //
    // No address was ever reported, which is what makes this a route test
    // rather than an address test that happened to pass.
    //
    {
        std::lock_guard<std::mutex> Guard(State.Lock);
        ASSERT_TRUE(State.Changes.empty());
    }

    CxPlatAddressMonitorUninitialize(Monitor);
    Run("ip link del qmonroute >/dev/null 2>&1");
}

//
// The negative control for the test above: with WatchRoutes off, the same route
// changes must reach nobody. Without this, that test would pass on a backend
// that subscribed to routes unconditionally and reported every one of them to a
// consumer that never asked -- which is the noisier stream the flag exists to
// keep off.
//
TEST_F(AddressMonitorRealTest, RouteChangeIgnoredWhenNotWatching)
{
    if (!CanCreateInterface()) {
        GTEST_SKIP() << "needs a network namespace; run under `unshare -rn`";
    }

    ASSERT_TRUE(Run("ip link add qmonnoroute type dummy"));
    ASSERT_TRUE(Run("ip link set qmonnoroute up"));
    ASSERT_TRUE(Run("ip addr add 10.6.6.1/24 dev qmonnoroute"));

    Observed State;

    CXPLAT_ADDRESS_MONITOR_CONFIG Config;
    CxPlatZeroMemory(&Config, sizeof(Config));
    Config.Callback = ChangeCallback;
    Config.Context = &State;
    Config.DebounceMs = 50;
    Config.WatchRoutes = FALSE;

    CXPLAT_ADDRESS_MONITOR* Monitor = nullptr;
    ASSERT_TRUE(QUIC_SUCCEEDED(CxPlatAddressMonitorInitialize(nullptr, &Config, &Monitor)));

    ASSERT_TRUE(Run("ip route add 10.88.0.0/16 dev qmonnoroute"));
    ASSERT_TRUE(Run("ip route del 10.88.0.0/16 dev qmonnoroute"));

    //
    // Long enough for several debounce windows to have closed.
    //
    CxPlatSleep(600);

    {
        std::lock_guard<std::mutex> Guard(State.Lock);
        ASSERT_EQ(0u, State.RouteChangedCount);
        ASSERT_TRUE(State.Changes.empty());
    }

    CxPlatAddressMonitorUninitialize(Monitor);
    Run("ip link del qmonnoroute >/dev/null 2>&1");
}

//
// IFA_F_TEMPORARY and IFA_F_SECONDARY are the same bit in linux/if_addr.h, so
// reading it without checking the family marks every IPv4 alias as an RFC 8981
// privacy address -- which core will deprioritise, quietly avoiding a perfectly
// good address.
//
TEST_F(AddressMonitorRealTest, Ipv4SecondaryIsNotTemporary)
{
    if (!CanCreateInterface()) {
        GTEST_SKIP() << "needs a network namespace; run under `unshare -rn`";
    }

    ASSERT_TRUE(Run("ip link add qmonsec type dummy"));
    ASSERT_TRUE(Run("ip link set qmonsec up"));
    ASSERT_TRUE(Run("ip addr add 10.1.1.1/24 dev qmonsec"));
    //
    // Same subnet, so the kernel marks it IFA_F_SECONDARY.
    //
    ASSERT_TRUE(Run("ip addr add 10.1.1.2/24 dev qmonsec"));

    CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS* Raw = NULL;
    uint32_t RawCount = 0;
    ASSERT_TRUE(QUIC_SUCCEEDED(CxPlatAddressMonitorOsEnumerate(NULL, &Raw, &RawCount)));

    QUIC_ADDR Secondary;
    CxPlatZeroMemory(&Secondary, sizeof(Secondary));
    ASSERT_TRUE(QuicAddrFromString("10.1.1.2", 0, &Secondary));

    bool Found = false;
    for (uint32_t i = 0; i < RawCount; ++i) {
        if (QuicAddrGetFamily(&Raw[i].Address.Address) == QUIC_ADDRESS_FAMILY_INET &&
            QuicAddrCompareIp(&Secondary, &Raw[i].Address.Address)) {
            Found = true;
            ASSERT_EQ(
                0u,
                (uint32_t)(Raw[i].Address.Flags & CXPLAT_ADDRESS_FLAG_TEMPORARY));
        }
    }

    if (Raw != NULL) {
        CXPLAT_FREE(Raw, QUIC_POOL_DATAPATH_ADDRESSES);
    }
    Run("ip link del qmonsec >/dev/null 2>&1");
    ASSERT_TRUE(Found);
}

#endif
