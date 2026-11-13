/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the two policy decisions a server makes before answering a
    draft-kozuka-quic-stateless-punch request: whether the address it is being
    asked to punch towards is one it will punch towards, and whether it has any
    punches left to spend.

    Tested here rather than against a peer because the send they guard is
    deliberately unobservable -- one unacknowledged datagram, no path, no
    record of the attempt -- so there is nothing for a functional test to read
    back. What there is to get wrong is the policy, and the policy is a pure
    function of an address and a clock.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "StatelessPunchTest.cpp.clog.h"
#endif

struct StatelessPunchTest : public ::testing::Test {

    //
    // The connection is a correlation id to the trace macros and a pair of
    // counters to the rate limiter; neither function reads anything else off
    // it. Zeroed on the stack, as CubicTest does, so the layout is the real
    // one.
    //
    QUIC_CONNECTION Connection {};

    static QUIC_ADDR Addr(const char* Address, uint16_t Port = 4433)
    {
        QUIC_ADDR Result;
        CxPlatZeroMemory(&Result, sizeof(Result));
        EXPECT_TRUE(QuicAddrFromString(Address, Port, &Result));
        return Result;
    }

    bool Allowed(const char* Address, uint16_t Port = 4433)
    {
        const QUIC_ADDR Target = Addr(Address, Port);
        return QuicConnPunchDestinationAllowed(&Connection, &Target) != FALSE;
    }
};

//
// A client address of the sort this extension exists to reach: a global
// unicast address on a port the client chose.
//
TEST_F(StatelessPunchTest, DestinationAllowsOrdinaryAddress)
{
    ASSERT_TRUE(Allowed("203.0.113.5"));
    ASSERT_TRUE(Allowed("198.51.100.200", 51234));
    ASSERT_TRUE(Allowed("2001:db8::1"));
    ASSERT_TRUE(Allowed("2001:db8:1234::abcd", 51234));
}

//
// Nothing a packet can be delivered to. Port 0 is not a destination, and a
// wildcard address names every interface rather than a peer.
//
TEST_F(StatelessPunchTest, DestinationRefusesUnspecified)
{
    ASSERT_FALSE(Allowed("203.0.113.5", 0));
    ASSERT_FALSE(Allowed("2001:db8::1", 0));
    ASSERT_FALSE(Allowed("0.0.0.0"));
    ASSERT_FALSE(Allowed("::"));
}

//
// The amplifiers. One request producing one packet to one address is the
// bargain this extension offers; a multicast or broadcast destination turns it
// into one packet per host on a segment.
//
TEST_F(StatelessPunchTest, DestinationRefusesMulticastAndBroadcast)
{
    ASSERT_FALSE(Allowed("224.0.0.1"));        // all hosts
    ASSERT_FALSE(Allowed("239.1.2.3"));        // administratively scoped
    ASSERT_FALSE(Allowed("255.255.255.255"));  // limited broadcast
    ASSERT_FALSE(Allowed("ff02::1"));          // link-local all nodes
    ASSERT_FALSE(Allowed("ff0e::1234"));       // global scope

    //
    // 0/8 names this network rather than a host on it, and 224/4 begins one
    // address above the last unicast address -- so the boundary is worth
    // pinning from both sides.
    //
    ASSERT_FALSE(Allowed("0.1.2.3"));
    ASSERT_TRUE(Allowed("223.255.255.255"));
    ASSERT_FALSE(Allowed("224.0.0.0"));
}

//
// Reachable from the server but not from the internet, which makes them the
// addresses a punch request could be used to probe. The server has no reason
// to punch towards its own host.
//
TEST_F(StatelessPunchTest, DestinationRefusesLocalScope)
{
    ASSERT_FALSE(Allowed("127.0.0.1"));
    ASSERT_FALSE(Allowed("127.10.20.30"));
    ASSERT_FALSE(Allowed("169.254.1.1"));
    ASSERT_FALSE(Allowed("::1"));
    ASSERT_FALSE(Allowed("fe80::1"));
}

//
// RFC 9000 section 21.5.6. An unsolicited datagram to one of these provokes a
// reply from something that is not a QUIC peer, which is the reflection this
// list is about -- and the port is the only thing separating them from the
// ordinary addresses the first test allows.
//
TEST_F(StatelessPunchTest, DestinationRefusesSensitivePorts)
{
    //
    // A typed array rather than a braced list in the loop: a braced list of
    // integer literals deduces std::initializer_list<int>, and int to uint16_t
    // is a narrowing conversion MSVC refuses at /W4 /WX (C4244) while gcc says
    // nothing. An aggregate initializer of constants that fit is fine, which
    // is why the production list in connection.c has always been written this
    // way.
    //
    static const uint16_t SensitivePorts[] = {
        53, 123, 137, 161, 389, 1900, 11211
    };
    for (uint16_t Port : SensitivePorts) {
        ASSERT_FALSE(Allowed("203.0.113.5", Port)) << "port " << Port;
        ASSERT_FALSE(Allowed("2001:db8::1", Port)) << "port " << Port;
    }

    //
    // Neighbouring ports are not refused: the list is a list, not a range.
    //
    ASSERT_TRUE(Allowed("203.0.113.5", 52));
    ASSERT_TRUE(Allowed("203.0.113.5", 54));
    ASSERT_TRUE(Allowed("203.0.113.5", 11210));
}

//
// The allowance is spent, not shared: a full window's worth of punches goes
// out and then the next request gets nothing.
//
TEST_F(StatelessPunchTest, RateLimitAllowsWindowThenStops)
{
    for (uint32_t i = 0; i < QUIC_PUNCH_RATE_LIMIT_PER_WINDOW; ++i) {
        ASSERT_TRUE(QuicConnPunchRateAllows(&Connection)) << "punch " << i;
    }
    ASSERT_FALSE(QuicConnPunchRateAllows(&Connection));
    ASSERT_FALSE(QuicConnPunchRateAllows(&Connection));
}

//
// And it comes back. Not by decay -- the window is closed and reopened whole,
// so what follows is another full allowance rather than one punch.
//
TEST_F(StatelessPunchTest, RateLimitWindowReopens)
{
    for (uint32_t i = 0; i < QUIC_PUNCH_RATE_LIMIT_PER_WINDOW; ++i) {
        ASSERT_TRUE(QuicConnPunchRateAllows(&Connection));
    }
    ASSERT_FALSE(QuicConnPunchRateAllows(&Connection));

    //
    // Rewinding the window start is how the clock is moved: waiting out a real
    // window would put a second of sleep in the suite for every assertion
    // about it.
    //
    Connection.PunchWindowStartUs =
        CxPlatTimeUs64() - QUIC_PUNCH_RATE_WINDOW_US;

    for (uint32_t i = 0; i < QUIC_PUNCH_RATE_LIMIT_PER_WINDOW; ++i) {
        ASSERT_TRUE(QuicConnPunchRateAllows(&Connection)) << "punch " << i;
    }
    ASSERT_FALSE(QuicConnPunchRateAllows(&Connection));
}

//
// Not before it is due, which is the half of a fixed window that a sliding one
// would get wrong: most of a window having passed buys nothing.
//
TEST_F(StatelessPunchTest, RateLimitWindowDoesNotReopenEarly)
{
    for (uint32_t i = 0; i < QUIC_PUNCH_RATE_LIMIT_PER_WINDOW; ++i) {
        ASSERT_TRUE(QuicConnPunchRateAllows(&Connection));
    }

    //
    // Set against the clock each time rather than decremented, because a
    // refusal leaves the window start alone and successive decrements would
    // accumulate the real time spent between the assertions. Ten milliseconds
    // short of the boundary rather than one microsecond, for the same reason:
    // the clock these assertions are racing is the one the limiter reads.
    //
    Connection.PunchWindowStartUs =
        CxPlatTimeUs64() - (QUIC_PUNCH_RATE_WINDOW_US / 2);
    ASSERT_FALSE(QuicConnPunchRateAllows(&Connection));

    Connection.PunchWindowStartUs =
        CxPlatTimeUs64() - (QUIC_PUNCH_RATE_WINDOW_US - MS_TO_US(10));
    ASSERT_FALSE(QuicConnPunchRateAllows(&Connection));
}

//
// A connection that has never punched starts with its allowance intact rather
// than with a window that began at zero and expired before the first request.
// The distinction matters because the first call is the one that sets the
// window, and reading it as expired would make every first punch free of the
// accounting that follows.
//
TEST_F(StatelessPunchTest, RateLimitStartsFresh)
{
    ASSERT_EQ(0u, Connection.PunchWindowStartUs);
    ASSERT_TRUE(QuicConnPunchRateAllows(&Connection));
    ASSERT_NE(0u, Connection.PunchWindowStartUs);
    ASSERT_EQ(1u, Connection.PunchesInWindow);
}

//
// Which candidate pairs a client will ask the server to punch for.
//
// Three things have to be true at once, and the value of testing it here is
// that each can be false on its own: the extension negotiated, the pair's
// remote among the addresses the server advertised, and the pair's local
// carrying a candidate whose observed address is somewhere a server could
// actually send. The last one is the application's to supply and the only
// place this client learns how it is seen from outside.
//
struct PunchPairTest : public ::testing::Test {

    QUIC_CONNECTION Connection {};
    QUIC_CANDIDATE_ADDRESS_LIST_ENTRY Candidates[4] {};
    uint8_t CandidateCount {0};

    void SetUp() override
    {
        CxPlatListInitializeHead(&Connection.CandidateAddresses);
        Connection.State.StatelessPunchNegotiated = TRUE;
    }

    static QUIC_ADDR Addr(const char* Address, uint16_t Port = 0)
    {
        QUIC_ADDR Result;
        CxPlatZeroMemory(&Result, sizeof(Result));
        EXPECT_TRUE(QuicAddrFromString(Address, Port, &Result));
        return Result;
    }

    //
    // An address the server told us about, which is what the request names and
    // what the server looks the request up by.
    //
    void Advertise(const char* Address, uint16_t Port)
    {
        Connection.AltAddrs[Connection.AltAddrCount].Address = Addr(Address, Port);
        Connection.AltAddrCount++;
    }

    //
    // A local address the application registered, with the address the server
    // would see this client at.
    //
    void AddCandidate(const char* Host, const char* Observed, uint16_t ObservedPort)
    {
        QUIC_CANDIDATE_ADDRESS_LIST_ENTRY* Entry = &Candidates[CandidateCount++];
        Entry->Address = Addr(Host);
        Entry->ObservedAddress = Addr(Observed, ObservedPort);
        CxPlatListInsertTail(&Connection.CandidateAddresses, &Entry->Link);
    }

    bool Punchable(const char* Local, const char* Remote, uint16_t RemotePort,
                   QUIC_ADDR* Named = nullptr)
    {
        const QUIC_ADDR LocalAddr = Addr(Local);
        const QUIC_ADDR RemoteAddr = Addr(Remote, RemotePort);
        QUIC_ADDR Out;
        const BOOLEAN Result =
            QuicConnPunchableClientAddress(
                &Connection, &LocalAddr, &RemoteAddr, &Out, nullptr);
        if (Named != nullptr) {
            *Named = Out;
        }
        return Result != FALSE;
    }
};

//
// The ordinary case, and the one the whole stage exists for: the request names
// the client's observed address, not its local one. The server cannot reach
// the local address -- that is the entire problem -- so naming it would make
// the punch useless.
//
TEST_F(PunchPairTest, NamesTheObservedAddress)
{
    Advertise("203.0.113.9", 443);
    AddCandidate("192.168.1.50", "198.51.100.7", 51234);

    QUIC_ADDR Named;
    ASSERT_TRUE(Punchable("192.168.1.50", "203.0.113.9", 443, &Named));

    const QUIC_ADDR Expected = Addr("198.51.100.7", 51234);
    ASSERT_TRUE(QuicAddrCompare(&Expected, &Named));
}

//
// Not negotiated means the peer never said it would punch, so the request
// would be a frame it is entitled to treat as a protocol violation.
//
TEST_F(PunchPairTest, RefusesWhenNotNegotiated)
{
    Advertise("203.0.113.9", 443);
    AddCandidate("192.168.1.50", "198.51.100.7", 51234);
    Connection.State.StatelessPunchNegotiated = FALSE;

    ASSERT_FALSE(Punchable("192.168.1.50", "203.0.113.9", 443));
}

//
// A remote the server never advertised. The server looks a request up among
// the addresses it told us about, so this one would be read and dropped --
// the request is not worth the packet.
//
TEST_F(PunchPairTest, RefusesAnUnadvertisedRemote)
{
    Advertise("203.0.113.9", 443);
    AddCandidate("192.168.1.50", "198.51.100.7", 51234);

    ASSERT_FALSE(Punchable("192.168.1.50", "203.0.113.10", 443));

    //
    // The port is part of it: the draft advertises endpoints, and the server
    // matches on the whole endpoint.
    //
    ASSERT_FALSE(Punchable("192.168.1.50", "203.0.113.9", 444));
}

//
// No candidate for this local address means the application never said how
// this client is seen from it, and there is nothing to put in the frame.
//
TEST_F(PunchPairTest, RefusesALocalWithNoCandidate)
{
    Advertise("203.0.113.9", 443);
    AddCandidate("192.168.1.50", "198.51.100.7", 51234);

    ASSERT_FALSE(Punchable("192.168.1.51", "203.0.113.9", 443));
}

//
// An observed address that names nowhere reachable. The server's own
// destination filter would refuse each of these, so queueing the request would
// spend a packet to be told no.
//
TEST_F(PunchPairTest, RefusesAnUnusableObservedAddress)
{
    Advertise("203.0.113.9", 443);

    AddCandidate("192.168.1.50", "127.0.0.1", 51234);      // loopback
    AddCandidate("192.168.1.51", "0.0.0.0", 51234);        // wildcard
    AddCandidate("192.168.1.52", "198.51.100.7", 0);       // no port

    ASSERT_FALSE(Punchable("192.168.1.50", "203.0.113.9", 443));
    ASSERT_FALSE(Punchable("192.168.1.51", "203.0.113.9", 443));
    ASSERT_FALSE(Punchable("192.168.1.52", "203.0.113.9", 443));
}

//
// The frame type carries the family for both addresses, so a client candidate
// of one family cannot be paired with a server address of the other.
//
TEST_F(PunchPairTest, RefusesAFamilyMismatch)
{
    Advertise("2001:db8::9", 443);
    AddCandidate("192.168.1.50", "198.51.100.7", 51234);

    ASSERT_FALSE(Punchable("192.168.1.50", "2001:db8::9", 443));

    //
    // And allows it once both sides agree.
    //
    AddCandidate("2001:db8:1::50", "2001:db8:2::7", 51234);
    ASSERT_TRUE(Punchable("2001:db8:1::50", "2001:db8::9", 443));
}

//
// Several candidates, and the one matching this pair's local address is the one
// named -- not merely the first on the list.
//
TEST_F(PunchPairTest, PicksTheCandidateForThisLocalAddress)
{
    Advertise("203.0.113.9", 443);
    AddCandidate("192.168.1.50", "198.51.100.7", 51234);
    AddCandidate("192.168.1.51", "198.51.100.8", 51235);
    AddCandidate("192.168.1.52", "198.51.100.9", 51236);

    QUIC_ADDR Named;
    ASSERT_TRUE(Punchable("192.168.1.51", "203.0.113.9", 443, &Named));
    const QUIC_ADDR Expected = Addr("198.51.100.8", 51235);
    ASSERT_TRUE(QuicAddrCompare(&Expected, &Named));
}

//
// The local address is matched on the IP alone, because a table pair's local
// address carries no port and a candidate is a host address rather than an
// endpoint.
//
TEST_F(PunchPairTest, MatchesTheLocalAddressIgnoringPort)
{
    Advertise("203.0.113.9", 443);
    AddCandidate("192.168.1.50", "198.51.100.7", 51234);

    QUIC_ADDR LocalWithPort = Addr("192.168.1.50", 9999);
    const QUIC_ADDR RemoteAddr = Addr("203.0.113.9", 443);
    QUIC_ADDR Named;
    ASSERT_TRUE(
        QuicConnPunchableClientAddress(
            &Connection, &LocalWithPort, &RemoteAddr, &Named, nullptr) != FALSE);
}
