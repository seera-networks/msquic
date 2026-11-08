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
