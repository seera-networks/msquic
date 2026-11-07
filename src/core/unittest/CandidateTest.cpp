/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the candidate pair table: the enumeration of
    (local address, remote address) combinations and the order they come out in.

    The ordering is the part worth getting wrong, which is why the table was
    built as a pure function -- these tests hand it synthetic inputs and read
    the list back, with no connection and no platform involved.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "CandidateTest.cpp.clog.h"
#endif

struct CandidateTest : public ::testing::Test {

    static CXPLAT_LOCAL_ADDRESS Local(
        const char* Addr,
        CXPLAT_ADDRESS_FLAGS Flags = (CXPLAT_ADDRESS_FLAGS)0,
        uint32_t InterfaceIndex = 1
        )
    {
        CXPLAT_LOCAL_ADDRESS Entry;
        CxPlatZeroMemory(&Entry, sizeof(Entry));
        EXPECT_TRUE(QuicAddrFromString(Addr, 0, &Entry.Address));
        Entry.Flags = Flags;
        Entry.InterfaceIndex = InterfaceIndex;
        return Entry;
    }

    static QUIC_CANDIDATE_REMOTE Remote(
        const char* Addr,
        uint8_t SentinelRank = QUIC_CANDIDATE_BACKUP,
        uint64_t PriorityHint = 0,
        const char* RouteLocal = nullptr
        )
    {
        QUIC_CANDIDATE_REMOTE Entry;
        CxPlatZeroMemory(&Entry, sizeof(Entry));
        EXPECT_TRUE(QuicAddrFromString(Addr, 4433, &Entry.Address));
        Entry.SentinelRank = SentinelRank;
        Entry.PriorityHint = PriorityHint;
        if (RouteLocal != nullptr) {
            EXPECT_TRUE(QuicAddrFromString(RouteLocal, 0, &Entry.RoutePreferredLocal));
            Entry.RoutePreferredLocalValid = TRUE;
        }
        return Entry;
    }

    //
    // The table read back as "local>remote" strings, head first, so a test can
    // assert the whole order in one comparison rather than walking it.
    //
    static std::vector<std::string> Order(const QUIC_CANDIDATE_SET& Set)
    {
        std::vector<std::string> Result;
        for (CXPLAT_LIST_ENTRY* Entry = Set.Pairs.Flink;
                Entry != &Set.Pairs;
                Entry = Entry->Flink) {
            auto Pair = CXPLAT_CONTAINING_RECORD(Entry, QUIC_CANDIDATE_PAIR, Link);
            QUIC_ADDR_STR L, R;
            QuicAddrToString(&Pair->LocalAddress, &L);
            QuicAddrToString(&Pair->RemoteAddress, &R);
            Result.push_back(std::string(L.Address) + ">" + R.Address);
        }
        return Result;
    }

    static uint32_t ListLength(const QUIC_CANDIDATE_SET& Set)
    {
        uint32_t N = 0;
        for (CXPLAT_LIST_ENTRY* E = Set.Pairs.Flink; E != &Set.Pairs; E = E->Flink) {
            N++;
        }
        return N;
    }
};

TEST_F(CandidateTest, EnumeratesTheProduct)
{
    QUIC_CANDIDATE_SET Set;
    QuicCandidateSetInitialize(&Set);

    const CXPLAT_LOCAL_ADDRESS Locals[] = { Local("10.0.0.1"), Local("10.0.0.2") };
    const QUIC_CANDIDATE_REMOTE Remotes[] = { Remote("192.0.2.1"), Remote("192.0.2.2") };

    QuicCandidateSetRebuild(&Set, Locals, 2, Remotes, 2, FALSE);

    //
    // Two locals by two remotes is four pairs. This is the thing neither of the
    // pre-unification subsystems could express.
    //
    ASSERT_EQ(4u, ListLength(Set));
    ASSERT_EQ(4, Set.Count);
}

TEST_F(CandidateTest, FiltersMismatchedFamilies)
{
    QUIC_CANDIDATE_SET Set;
    QuicCandidateSetInitialize(&Set);

    const CXPLAT_LOCAL_ADDRESS Locals[] = { Local("10.0.0.1"), Local("2001:db8::1") };
    const QUIC_CANDIDATE_REMOTE Remotes[] = { Remote("192.0.2.1") };

    QuicCandidateSetRebuild(&Set, Locals, 2, Remotes, 1, FALSE);

    //
    // There is no mapping step: a v4 remote needs a v4 source.
    //
    ASSERT_EQ(1u, ListLength(Set));
    ASSERT_EQ("10.0.0.1>192.0.2.1:4433", Order(Set)[0]);
}

TEST_F(CandidateTest, FiltersScopePerPair)
{
    QUIC_CANDIDATE_SET Set;
    QuicCandidateSetInitialize(&Set);

    const CXPLAT_LOCAL_ADDRESS Locals[] = {
        Local("10.0.0.1"),
        Local("127.0.0.1"),
        Local("169.254.1.1"),
    };

    //
    // A routable remote: neither the loopback nor the link-local local address
    // can carry it. This filter is inherently pair-shaped, which is why it
    // lives here rather than against one remote.
    //
    const QUIC_CANDIDATE_REMOTE Routable[] = { Remote("192.0.2.1") };
    QuicCandidateSetRebuild(&Set, Locals, 3, Routable, 1, FALSE);
    ASSERT_EQ(1u, ListLength(Set));
    ASSERT_EQ("10.0.0.1>192.0.2.1:4433", Order(Set)[0]);

    //
    // A loopback remote, where the loopback local is the only viable one. The
    // global address is rejected too -- nothing sends from 10.0.0.1 to
    // 127.0.0.2 -- which the asymmetric filter this replaces allowed.
    //
    const QUIC_CANDIDATE_REMOTE Loop[] = { Remote("127.0.0.2") };
    QuicCandidateSetRebuild(&Set, Locals, 3, Loop, 1, FALSE);
    ASSERT_EQ(1u, ListLength(Set));
    ASSERT_EQ("127.0.0.1>127.0.0.2:4433", Order(Set)[0]);
}

//
// Key 1. The route-derived pair outranks everything below it, because it is the
// only input that knows which local address actually reaches this remote.
//
TEST_F(CandidateTest, RoutePreferredOutranksEverything)
{
    QUIC_CANDIDATE_SET Set;
    QuicCandidateSetInitialize(&Set);

    const CXPLAT_LOCAL_ADDRESS Locals[] = { Local("10.0.0.1"), Local("10.0.0.2") };

    //
    // 10.0.0.2 is what routing picks, while the other pair is on a remote the
    // server says it prefers and gives a better hint. Route still wins.
    //
    const QUIC_CANDIDATE_REMOTE Remotes[] = {
        Remote("192.0.2.1", QUIC_CANDIDATE_PREFERRED_TO_CURRENT, 0),
        Remote("192.0.2.9", QUIC_CANDIDATE_BACKUP, 99, "10.0.0.2"),
    };

    QuicCandidateSetRebuild(&Set, Locals, 2, Remotes, 2, FALSE);
    ASSERT_EQ("10.0.0.2>192.0.2.9:4433", Order(Set)[0]);
}

//
// Key 2. Preferred-to-current, then the current path's own remote, then
// backups. Three-valued rather than a boolean because the current path is
// neither preferred nor a backup -- it is where the sentinel sits.
//
TEST_F(CandidateTest, SentinelRankOrdersAboveTheHint)
{
    QUIC_CANDIDATE_SET Set;
    QuicCandidateSetInitialize(&Set);

    const CXPLAT_LOCAL_ADDRESS Locals[] = { Local("10.0.0.1") };
    const QUIC_CANDIDATE_REMOTE Remotes[] = {
        Remote("192.0.2.3", QUIC_CANDIDATE_BACKUP, 0),
        Remote("192.0.2.2", QUIC_CANDIDATE_CURRENT, 50),
        Remote("192.0.2.1", QUIC_CANDIDATE_PREFERRED_TO_CURRENT, 99),
    };

    QuicCandidateSetRebuild(&Set, Locals, 1, Remotes, 3, FALSE);

    const auto O = Order(Set);
    ASSERT_EQ(3u, O.size());
    ASSERT_EQ("10.0.0.1>192.0.2.1:4433", O[0]); // preferred, despite hint 99
    ASSERT_EQ("10.0.0.1>192.0.2.2:4433", O[1]); // current
    ASSERT_EQ("10.0.0.1>192.0.2.3:4433", O[2]); // backup, despite hint 0
}

// Key 3. Within one side of the sentinel, the server's hint decides.
TEST_F(CandidateTest, PriorityHintOrdersWithinASide)
{
    QUIC_CANDIDATE_SET Set;
    QuicCandidateSetInitialize(&Set);

    const CXPLAT_LOCAL_ADDRESS Locals[] = { Local("10.0.0.1") };
    const QUIC_CANDIDATE_REMOTE Remotes[] = {
        Remote("192.0.2.2", QUIC_CANDIDATE_BACKUP, 7),
        Remote("192.0.2.1", QUIC_CANDIDATE_BACKUP, 3),
    };

    QuicCandidateSetRebuild(&Set, Locals, 1, Remotes, 2, FALSE);
    ASSERT_EQ("10.0.0.1>192.0.2.1:4433", Order(Set)[0]);
}

// Key 4. A deprecated local address loses to one that is not.
TEST_F(CandidateTest, DeprecatedLocalRanksLast)
{
    QUIC_CANDIDATE_SET Set;
    QuicCandidateSetInitialize(&Set);

    const CXPLAT_LOCAL_ADDRESS Locals[] = {
        Local("10.0.0.1", CXPLAT_ADDRESS_FLAG_DEPRECATED),
        Local("10.0.0.2"),
    };
    const QUIC_CANDIDATE_REMOTE Remotes[] = { Remote("192.0.2.1") };

    QuicCandidateSetRebuild(&Set, Locals, 2, Remotes, 1, FALSE);
    ASSERT_EQ("10.0.0.2>192.0.2.1:4433", Order(Set)[0]);
}

//
// Key 4, the carry-forward. A connection on a privacy address stays on one, and
// a connection on a stable address does not silently acquire one.
//
TEST_F(CandidateTest, TemporaryKindIsCarriedForward)
{
    const CXPLAT_LOCAL_ADDRESS Locals[] = {
        Local("10.0.0.1", CXPLAT_ADDRESS_FLAG_TEMPORARY),
        Local("10.0.0.2"),
    };
    const QUIC_CANDIDATE_REMOTE Remotes[] = { Remote("192.0.2.1") };

    QUIC_CANDIDATE_SET Set;
    QuicCandidateSetInitialize(&Set);
    QuicCandidateSetRebuild(&Set, Locals, 2, Remotes, 1, TRUE);
    ASSERT_EQ("10.0.0.1>192.0.2.1:4433", Order(Set)[0]);

    QuicCandidateSetInitialize(&Set);
    QuicCandidateSetRebuild(&Set, Locals, 2, Remotes, 1, FALSE);
    ASSERT_EQ("10.0.0.2>192.0.2.1:4433", Order(Set)[0]);
}

// Key 5. Equals are separated deterministically, or the connection flaps.
TEST_F(CandidateTest, TiebreakIsDeterministic)
{
    const CXPLAT_LOCAL_ADDRESS Forward[] = {
        Local("10.0.0.1", (CXPLAT_ADDRESS_FLAGS)0, 2),
        Local("10.0.0.2", (CXPLAT_ADDRESS_FLAGS)0, 1),
    };
    const CXPLAT_LOCAL_ADDRESS Reversed[] = { Forward[1], Forward[0] };
    const QUIC_CANDIDATE_REMOTE Remotes[] = { Remote("192.0.2.1") };

    QUIC_CANDIDATE_SET A, B;
    QuicCandidateSetInitialize(&A);
    QuicCandidateSetInitialize(&B);
    QuicCandidateSetRebuild(&A, Forward, 2, Remotes, 1, FALSE);
    QuicCandidateSetRebuild(&B, Reversed, 2, Remotes, 1, FALSE);

    //
    // The lower interface index wins, whatever order the snapshot arrived in,
    // so the same host state always produces the same table.
    //
    ASSERT_EQ(Order(A), Order(B));
    ASSERT_EQ("10.0.0.2>192.0.2.1:4433", Order(A)[0]);
}

//
// Capacity. The product can be 128 x 8; the table holds 16, and the ones it
// keeps must be the best 16 rather than the first 16 enumerated.
//
TEST_F(CandidateTest, CapsAtSixteenKeepingTheBest)
{
    CXPLAT_LOCAL_ADDRESS Locals[20];
    for (uint32_t i = 0; i < 20; ++i) {
        char Buf[32];
        snprintf(Buf, sizeof(Buf), "10.0.0.%u", i + 1);
        Locals[i] = Local(Buf, (CXPLAT_ADDRESS_FLAGS)0, i + 1);
    }

    //
    // Enumerated worst-first on purpose: the highest interface index is offered
    // first, so a table that simply kept what it saw first would hold the wrong
    // sixteen.
    //
    CXPLAT_LOCAL_ADDRESS Reversed[20];
    for (uint32_t i = 0; i < 20; ++i) {
        Reversed[i] = Locals[19 - i];
    }

    const QUIC_CANDIDATE_REMOTE Remotes[] = { Remote("192.0.2.1") };

    QUIC_CANDIDATE_SET Set;
    QuicCandidateSetInitialize(&Set);
    QuicCandidateSetRebuild(&Set, Reversed, 20, Remotes, 1, FALSE);

    ASSERT_EQ(QUIC_MAX_CANDIDATE_PAIRS, Set.Count);
    ASSERT_EQ((uint32_t)QUIC_MAX_CANDIDATE_PAIRS, ListLength(Set));

    const auto O = Order(Set);
    ASSERT_EQ("10.0.0.1>192.0.2.1:4433", O[0]);
    ASSERT_EQ("10.0.0.16>192.0.2.1:4433", O[QUIC_MAX_CANDIDATE_PAIRS - 1]);
}

//
// A rebuild replaces the table rather than adding to it. The ordering depends
// on all the inputs at once -- a route change reorders pairs whose own
// addresses never moved -- so there is nothing to diff against.
//
TEST_F(CandidateTest, RebuildReplaces)
{
    QUIC_CANDIDATE_SET Set;
    QuicCandidateSetInitialize(&Set);

    const CXPLAT_LOCAL_ADDRESS Locals[] = { Local("10.0.0.1"), Local("10.0.0.2") };
    const QUIC_CANDIDATE_REMOTE Two[] = { Remote("192.0.2.1"), Remote("192.0.2.2") };
    QuicCandidateSetRebuild(&Set, Locals, 2, Two, 2, FALSE);
    ASSERT_EQ(4u, ListLength(Set));

    const QUIC_CANDIDATE_REMOTE One[] = { Remote("192.0.2.1") };
    QuicCandidateSetRebuild(&Set, Locals, 2, One, 1, FALSE);
    ASSERT_EQ(2u, ListLength(Set));
    ASSERT_EQ(2, Set.Count);

    //
    // And a rebuild with nothing viable empties it, which is the state a host
    // with no usable address is in.
    //
    const QUIC_CANDIDATE_REMOTE V6[] = { Remote("2001:db8::1") };
    QuicCandidateSetRebuild(&Set, Locals, 2, V6, 1, FALSE);
    ASSERT_EQ(0u, ListLength(Set));
    ASSERT_EQ(0, Set.Count);
}

//
// The list has to stay intact when the entry being displaced is also where the
// new one belongs -- the full-table boundary that is easy to corrupt, since
// inserting before an entry that has just been unlinked walks off the list.
//
TEST_F(CandidateTest, SurvivesDisplacingTheInsertionPoint)
{
    CXPLAT_LOCAL_ADDRESS Locals[QUIC_MAX_CANDIDATE_PAIRS + 2];
    for (uint32_t i = 0; i < QUIC_MAX_CANDIDATE_PAIRS + 1; ++i) {
        char Buf[32];
        snprintf(Buf, sizeof(Buf), "10.0.0.%u", i + 1);
        Locals[i] = Local(Buf, (CXPLAT_ADDRESS_FLAGS)0, i + 1);
    }

    const QUIC_CANDIDATE_REMOTE Remotes[] = { Remote("192.0.2.1") };

    //
    // Offered 1..15, then 17, then 16. When 16 arrives the table is full and
    // its worst entry is 17 -- which is also exactly where 16 belongs. So the
    // entry being evicted is the insertion point, which is the case that
    // corrupts the list if the removal and the position lookup are done in the
    // wrong order.
    //
    // Offering 1..17 in order, as this test first did, never reaches it: 17 is
    // worse than everything held and is dropped without any eviction at all.
    //
    CXPLAT_LOCAL_ADDRESS Offered[QUIC_MAX_CANDIDATE_PAIRS + 2];
    for (uint32_t i = 0; i < QUIC_MAX_CANDIDATE_PAIRS - 1; ++i) {
        Offered[i] = Locals[i];                          // 1..15
    }
    Offered[QUIC_MAX_CANDIDATE_PAIRS - 1] = Locals[QUIC_MAX_CANDIDATE_PAIRS];     // 17
    Offered[QUIC_MAX_CANDIDATE_PAIRS] = Locals[QUIC_MAX_CANDIDATE_PAIRS - 1];     // 16

    QUIC_CANDIDATE_SET Set;
    QuicCandidateSetInitialize(&Set);
    QuicCandidateSetRebuild(&Set, Offered, QUIC_MAX_CANDIDATE_PAIRS + 1, Remotes, 1, FALSE);

    ASSERT_EQ((uint32_t)QUIC_MAX_CANDIDATE_PAIRS, ListLength(Set));

    //
    // Walked backwards too: a corrupted insertion shows up as a Blink chain
    // that disagrees with the Flink chain.
    //
    uint32_t Backwards = 0;
    for (CXPLAT_LIST_ENTRY* E = Set.Pairs.Blink; E != &Set.Pairs; E = E->Blink) {
        Backwards++;
    }
    ASSERT_EQ((uint32_t)QUIC_MAX_CANDIDATE_PAIRS, Backwards);
    ASSERT_EQ("10.0.0.1>192.0.2.1:4433", Order(Set)[0]);

    //
    // 16 displaced 17 and took its place at the tail, which is the eviction
    // this test exists for.
    //
    ASSERT_EQ(
        "10.0.0.16>192.0.2.1:4433",
        Order(Set)[QUIC_MAX_CANDIDATE_PAIRS - 1]);
}
