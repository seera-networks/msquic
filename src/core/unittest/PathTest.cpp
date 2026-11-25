/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit tests for connection path management.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "PathTest.cpp.clog.h"
#endif

//
// Destination CIDs hang off a QUIC_PATHID on this fork rather than off the
// connection, and a path needs one before it can be promoted (QuicPathSetActive
// resets that path ID's congestion control). So the fixture carries a mock path
// id: every path points at it, its reference count is parked high enough that
// the releases in QuicPathRemove cannot free it, and the CIDs a test adds go on
// its list.
//
class PathTest : public ::testing::Test {
protected:
    QUIC_CONNECTION Connection{};
    QUIC_PATHID PathID{};
    QUIC_CID_SLIST_ENTRY SourceCid{};
    QUIC_CID_LIST_ENTRY* EmptyCid{nullptr};

    void SetUp() override
    {
        Connection.Settings.MinimumMtu = 1280;
        Connection.Settings.InitialRttMs = 333;
        Connection.Settings.EcnEnabled = TRUE;
        Connection.Settings.QTIPEnabled = FALSE;
        Connection.Settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC;
        Connection.Settings.InitialWindowPackets = 10;
        Connection.Settings.SendIdleTimeoutMs = 1000;

        PathID.Connection = &Connection;
        PathID.RefCount = 1000;
#if DEBUG
        for (uint32_t i = 0; i < QUIC_PATHID_REF_COUNT; ++i) {
            PathID.RefTypeCount[i] = 1000;
        }
#endif
        CxPlatListInitializeHead(&PathID.DestCids);

        //
        // A path can only send with a source CID on its path id and a
        // destination CID of its own -- QuicPacketBuilderInitialize refuses
        // otherwise, and QuicPathCanSend says the same. The mock carries one
        // of each so that a path in this fixture is sendable by default, and a
        // test that wants the opposite takes one away.
        //
        PathID.SourceCids.Next = &SourceCid.Link;

        EmptyCid = QuicCidNewDestination(0, nullptr);
        ASSERT_NE(nullptr, EmptyCid);
    }

    void TearDown() override
    {
        CXPLAT_FREE(EmptyCid, QUIC_POOL_CIDLIST);
    }

    void InitializePaths(uint8_t Count)
    {
        CxPlatZeroMemory(&Connection.Paths, sizeof(Connection.Paths));
        Connection.Paths.Count = Count;
        Connection.Paths.NextPathId = Count;
        for (uint8_t i = 0; i < Count; ++i) {
            Connection.Paths.Paths[i].ID = i;
            Connection.Paths.Paths[i].InUse = TRUE;
            Connection.Paths.Paths[i].PathID = &PathID;
        }
        Connection.Paths.Paths[0].IsActive = TRUE;
        Connection.Paths.PendingActivePathId = Connection.Paths.Paths[0].ID;
        PathID.Path = &Connection.Paths.Paths[0];

        //
        // Sendable by default, for the reason the source CID above gives.
        //
        for (uint8_t i = 0; i < Count; ++i) {
            Connection.Paths.Paths[i].DestCid = EmptyCid;
        }

        //
        // Promoting a path resets its path id's congestion control, so the mock
        // needs a real one. Cubic's initializer reads the path's MTU, which is
        // why the paths get one above the minimum here.
        //
        for (uint8_t i = 0; i < Count; ++i) {
            Connection.Paths.Paths[i].Mtu = Connection.Settings.MinimumMtu;
        }
        CubicCongestionControlInitialize(&PathID.CongestionControl, &Connection.Settings);
    }

    void AddDestCid(
        QUIC_CID_LIST_ENTRY& Cid,
        bool UsedLocally = false,
        uint32_t AssignedPathId = UINT32_MAX)
    {
        Cid.CID.UsedLocally = UsedLocally ? TRUE : FALSE;
#if DEBUG
        Cid.AssignedPathId = AssignedPathId;
#else
        UNREFERENCED_PARAMETER(AssignedPathId);
#endif
        CxPlatListInsertTail(&PathID.DestCids, &Cid.Link);
    }
};

TEST_F(PathTest, Initialize)
{
    Connection.Settings.MinimumMtu = 1400;
    Connection.Settings.InitialRttMs = 25;

    QuicPathSetInitialize(&Connection.Paths, &Connection);

    ASSERT_EQ(1, Connection.Paths.Count);
    ASSERT_EQ(1U, Connection.Paths.NextPathId);
    ASSERT_EQ(0U, Connection.Paths.PendingActivePathId);

    const QUIC_PATH* Path = QuicPathGetActive(&Connection.Paths);
    ASSERT_EQ(&Connection.Paths.Paths[0], Path);
    ASSERT_EQ(0U, Path->ID);
    ASSERT_TRUE(Path->InUse);
    ASSERT_TRUE(Path->IsActive);
    ASSERT_EQ(1400, Path->Mtu);
    ASSERT_EQ(25000U, Path->SmoothedRtt);
    ASSERT_EQ(12500U, Path->RttVariance);
    ASSERT_EQ(UINT32_MAX, Path->MinRtt);
    ASSERT_EQ(ECN_VALIDATION_TESTING, Path->EcnValidationState);
}

TEST_F(PathTest, GetPathById)
{
    InitializePaths(3);
    Connection.Paths.Paths[0].ID = 10;
    Connection.Paths.Paths[1].ID = 20;
    Connection.Paths.Paths[2].ID = 30;
    Connection.Paths.PendingActivePathId = 10;

    ASSERT_EQ(&Connection.Paths.Paths[0], QuicConnGetPathByID(&Connection, 10));
    ASSERT_EQ(&Connection.Paths.Paths[1], QuicConnGetPathByID(&Connection, 20));
    ASSERT_EQ(&Connection.Paths.Paths[2], QuicConnGetPathByID(&Connection, 30));
    ASSERT_EQ(nullptr, QuicConnGetPathByID(&Connection, 40));
}

TEST_F(PathTest, MatchPacket)
{
    QUIC_PATH Path{};
    ASSERT_TRUE(
        QuicAddrFromString(
            "192.0.2.1", 1000, &Path.Route.LocalAddress));
    ASSERT_TRUE(
        QuicAddrFromString(
            "198.51.100.1", 2000, &Path.Route.RemoteAddress));

    CXPLAT_ROUTE PacketRoute{};
    PacketRoute.LocalAddress = Path.Route.LocalAddress;
    PacketRoute.RemoteAddress = Path.Route.RemoteAddress;
    QUIC_RX_PACKET Packet{};
    Packet._.Route = &PacketRoute;

    ASSERT_TRUE(QuicPathMatchPacket(&Path, &Packet));

    ASSERT_TRUE(
        QuicAddrFromString(
            "192.0.2.2", 1000, &PacketRoute.LocalAddress));
    ASSERT_FALSE(QuicPathMatchPacket(&Path, &Packet));
    PacketRoute.LocalAddress = Path.Route.LocalAddress;

    ASSERT_TRUE(
        QuicAddrFromString(
            "198.51.100.2", 2000, &PacketRoute.RemoteAddress));
    ASSERT_FALSE(QuicPathMatchPacket(&Path, &Packet));
}

TEST_F(PathTest, RemoveFromMiddle)
{
    InitializePaths(4);

    ASSERT_TRUE(QuicPathRemove(&Connection, &Connection.Paths.Paths[2]));

    ASSERT_EQ(3, Connection.Paths.Count);
    ASSERT_EQ(0U, Connection.Paths.Paths[0].ID);
    ASSERT_EQ(1U, Connection.Paths.Paths[1].ID);
    ASSERT_EQ(3U, Connection.Paths.Paths[2].ID);
    ASSERT_FALSE(Connection.Paths.Paths[3].InUse);
}

TEST_F(PathTest, RemoveFromFront)
{
    InitializePaths(4);
    for (uint8_t i = 0; i < Connection.Paths.Count; ++i) {
        Connection.Paths.Paths[i].DestCid = EmptyCid;
        ASSERT_TRUE(
            QuicAddrFromString(
                "198.51.100.1",
                static_cast<uint16_t>(2000 + i),
                &Connection.Paths.Paths[i].Route.RemoteAddress));
    }
    Connection.Paths.Paths[2].IsPeerValidated = TRUE;

    ASSERT_TRUE(QuicPathRemove(&Connection, &Connection.Paths.Paths[0]));

    ASSERT_EQ(3, Connection.Paths.Count);
    ASSERT_EQ(2U, Connection.Paths.Paths[0].ID);
    ASSERT_TRUE(Connection.Paths.Paths[0].IsActive);
    ASSERT_EQ(1U, Connection.Paths.Paths[1].ID);
    ASSERT_EQ(3U, Connection.Paths.Paths[2].ID);
    ASSERT_EQ(2U, Connection.Paths.PendingActivePathId);
    ASSERT_FALSE(Connection.Paths.Paths[3].InUse);
}

TEST_F(PathTest, RemoveWhileIteratingBackward)
{
    InitializePaths(4);

    //
    // Iterate backward when removing path to not invalidate the array.
    //
    for (int i = Connection.Paths.Count - 1; i > 0; --i) {
        QUIC_PATH* Path = &Connection.Paths.Paths[i];
        if (Path->ID == 1 || Path->ID == 2) {
            ASSERT_TRUE(QuicPathRemove(&Connection, Path));
        }
    }

    ASSERT_EQ(2, Connection.Paths.Count);
    ASSERT_EQ(0U, Connection.Paths.Paths[0].ID);
    ASSERT_EQ(3U, Connection.Paths.Paths[1].ID);
    ASSERT_FALSE(Connection.Paths.Paths[2].InUse);
}

//
// Upstream's five GetPathForPacket cases are not carried over. Its version of
// that function matches a packet on addresses alone and takes bindings from the
// active path; here a packet also carries a path id, the path id set has to hand
// one out, and a new path takes its binding from the connection's bound address
// list -- none of which a bare QUIC_CONNECTION on the stack provides. Covering
// it wants a fixture that builds a path id set and a binding, which is its own
// piece of work.
//
//
// #228: a path declared backup is still somewhere for the connection to go.
// The two callers of this -- loss detection giving up on a path and a path
// validation that timed out -- close the connection when it answers FALSE, so
// counting only active paths took the connection down with the one path an
// application had deliberately left active.
//
TEST_F(PathTest, HasOtherUsablePathCountsABackup)
{
    InitializePaths(2);
    Connection.State.MultipathNegotiated = TRUE;
    Connection.State.HandshakeConfirmed = TRUE;

    //
    // The shape an application that wants one stable path ends up in: one
    // active path carrying traffic, and the rest declared backup.
    //
    Connection.Paths.Paths[1].IsActive = FALSE;

    ASSERT_TRUE(QuicConnHasOtherUsablePath(&Connection, &Connection.Paths.Paths[0]));
}

//
// The other half of usable: the send path has to accept it. Each of these is a
// path QuicPacketBuilderInitialize would refuse -- counting one would abandon
// the dead path and leave nothing to carry the PATH_ABANDON frame.
//
TEST_F(PathTest, HasOtherUsablePathRejectsWhatCannotSend)
{
    InitializePaths(2);
    Connection.State.MultipathNegotiated = TRUE;
    Connection.State.HandshakeConfirmed = TRUE;
    Connection.Paths.Paths[1].IsActive = FALSE;

    QUIC_PATH* Excluded = &Connection.Paths.Paths[0];
    QUIC_PATH* Other = &Connection.Paths.Paths[1];

    Other->PathID = nullptr;
    ASSERT_FALSE(QuicConnHasOtherUsablePath(&Connection, Excluded));
    Other->PathID = &PathID;

    Other->DestCid = nullptr;
    ASSERT_FALSE(QuicConnHasOtherUsablePath(&Connection, Excluded));
    Other->DestCid = EmptyCid;

    PathID.SourceCids.Next = nullptr;
    ASSERT_FALSE(QuicConnHasOtherUsablePath(&Connection, Excluded));
    PathID.SourceCids.Next = &SourceCid.Link;

    Other->LocalClose = TRUE;
    ASSERT_FALSE(QuicConnHasOtherUsablePath(&Connection, Excluded));
    Other->LocalClose = FALSE;

    Other->RemoteClose = TRUE;
    ASSERT_FALSE(QuicConnHasOtherUsablePath(&Connection, Excluded));
    Other->RemoteClose = FALSE;

    //
    // And with none of those taken away, it is usable -- so each assertion
    // above failed for the reason it names.
    //
    ASSERT_TRUE(QuicConnHasOtherUsablePath(&Connection, Excluded));
}

//
// Off multipath there is nowhere else by definition: QuicConnChoosePath
// returns slot 0 whatever the other paths say, so neither caller may abandon.
//
TEST_F(PathTest, HasOtherUsablePathNeedsMultipath)
{
    InitializePaths(2);
    Connection.Paths.Paths[1].IsActive = TRUE;

    Connection.State.MultipathNegotiated = FALSE;
    Connection.State.HandshakeConfirmed = TRUE;
    ASSERT_FALSE(QuicConnHasOtherUsablePath(&Connection, &Connection.Paths.Paths[0]));

    Connection.State.MultipathNegotiated = TRUE;
    Connection.State.HandshakeConfirmed = FALSE;
    ASSERT_FALSE(QuicConnHasOtherUsablePath(&Connection, &Connection.Paths.Paths[0]));

    Connection.State.HandshakeConfirmed = TRUE;
    ASSERT_TRUE(QuicConnHasOtherUsablePath(&Connection, &Connection.Paths.Paths[0]));
}

//
// What a connection looks like the instant its only active path is abandoned,
// and the reason the fallback exists: slot 0 cannot send, so returning it
// would put the PATH_ABANDON frame that announces the abandonment -- and every
// packet after it -- on the path being abandoned.
//
TEST_F(PathTest, ChoosePathFallsBackToASendableBackup)
{
    InitializePaths(2);
    Connection.State.MultipathNegotiated = TRUE;
    Connection.State.HandshakeConfirmed = TRUE;

    Connection.Paths.Paths[0].LocalClose = TRUE;
    Connection.Paths.Paths[1].IsActive = FALSE;

    ASSERT_EQ(&Connection.Paths.Paths[1], QuicConnChoosePath(&Connection));

    //
    // With nothing sendable at all it still has to answer, and slot 0 is the
    // only answer there is. The promise this function makes is a path, not a
    // working one.
    //
    Connection.Paths.Paths[1].LocalClose = TRUE;
    ASSERT_EQ(&Connection.Paths.Paths[0], QuicConnChoosePath(&Connection));
}

//
// An active path is still preferred over a backup, which is what makes the
// fallback above a fallback rather than a change of policy.
//
TEST_F(PathTest, ChoosePathPrefersAnActivePath)
{
    InitializePaths(2);
    Connection.State.MultipathNegotiated = TRUE;
    Connection.State.HandshakeConfirmed = TRUE;

    Connection.Paths.Paths[0].IsActive = FALSE;
    Connection.Paths.Paths[1].IsActive = TRUE;

    //
    // Repeated because the choice among active paths is random: one active
    // path means every draw has to be that path.
    //
    for (uint32_t i = 0; i < 20; ++i) {
        ASSERT_EQ(&Connection.Paths.Paths[1], QuicConnChoosePath(&Connection));
    }
}

TEST_F(PathTest, UpdateDestCidsPrioritizesActivePathForReplacement)
{
    InitializePaths(4);

    const uint8_t ActiveCidData[] = {0};
    const uint8_t NonActiveCidData[] = {1};
    const uint8_t ReplacementCidData[] = {2};
    QUIC_CID_LIST_ENTRY* ActiveCid =
        QuicCidNewDestination(sizeof(ActiveCidData), ActiveCidData);
    QUIC_CID_LIST_ENTRY* NonActiveCid =
        QuicCidNewDestination(sizeof(NonActiveCidData), NonActiveCidData);
    QUIC_CID_LIST_ENTRY* ReplacementCid =
        QuicCidNewDestination(sizeof(ReplacementCidData), ReplacementCidData);
    ASSERT_NE(nullptr, ActiveCid);
    ASSERT_NE(nullptr, NonActiveCid);
    ASSERT_NE(nullptr, ReplacementCid);
    AddDestCid(*ActiveCid, true, Connection.Paths.Paths[0].ID);
    AddDestCid(*NonActiveCid, true, Connection.Paths.Paths[1].ID);
    AddDestCid(*ReplacementCid);
    ActiveCid->CID.Retired = TRUE;
    NonActiveCid->CID.Retired = TRUE;
    Connection.Paths.Paths[0].DestCid = ActiveCid;
    Connection.Paths.Paths[1].DestCid = NonActiveCid;

    QuicPathUpdateDestCids(&Connection.Paths, &Connection);

    //
    // The active path takes the one unused CID, and the non-active path whose
    // CID was retired with nothing to replace it is removed. Paths 2 and 3
    // differ from upstream: they have no destination CID at all, which on this
    // fork means their path id is new and the peer has not issued CIDs for it
    // yet (#196 asks and waits), so the sweep leaves them where they are.
    // Upstream removes them, which is why its expectation here is a count of 1.
    //
    ASSERT_EQ(3, Connection.Paths.Count);
    ASSERT_EQ(ReplacementCid, Connection.Paths.Paths[0].DestCid);
    ASSERT_TRUE(ReplacementCid->CID.UsedLocally);
    ASSERT_TRUE(Connection.Paths.Paths[0].InitiatedCidUpdate);
    ASSERT_EQ(0U, Connection.Paths.Paths[0].ID);
    //
    // The removal shifted the two CID-less paths down a slot.
    //
    ASSERT_EQ(2U, Connection.Paths.Paths[1].ID);
    ASSERT_EQ(3U, Connection.Paths.Paths[2].ID);
    ASSERT_FALSE(Connection.Paths.Paths[3].InUse);
#if DEBUG
    ASSERT_EQ(Connection.Paths.Paths[0].ID, ReplacementCid->AssignedPathId);
#endif

    //
    // The list these came from is the path id's, not the connection's.
    //
    CxPlatListEntryRemove(&ActiveCid->Link);
    CxPlatListEntryRemove(&NonActiveCid->Link);
    CxPlatListEntryRemove(&ReplacementCid->Link);
    CXPLAT_FREE(ActiveCid, QUIC_POOL_CIDLIST);
    CXPLAT_FREE(NonActiveCid, QUIC_POOL_CIDLIST);
    CXPLAT_FREE(ReplacementCid, QUIC_POOL_CIDLIST);
}
