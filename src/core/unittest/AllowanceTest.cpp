/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the amplification protection send allowance threshold.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "AllowanceTest.cpp.clog.h"
#endif

//
// A short header is one byte of flags, the destination connection ID, and up to
// four bytes of packet number.
//
#define MAX_SHORT_HEADER_LENGTH     (1 + QUIC_CID_MAX_LENGTH + 4)

//
// A PATH_CHALLENGE or PATH_RESPONSE: the type byte plus eight bytes of data.
// It is the smallest frame the send path writes on its own, and the one the
// allowance threshold has to leave room for.
//
#define PATH_CHALLENGE_FRAME_LENGTH (1 + 8)

struct MinSendAllowanceTest : public ::testing::TestWithParam<int> {
};

//
// The threshold exists so that a path that clears it can build a packet with
// something in it. The IP and UDP headers come out of the amplification
// allowance along with the payload, so a threshold sized for IPv4 leaves an
// IPv6 datagram 20 bytes shorter than intended: allowances of 76 through 86
// used to clear the guard and leave two bytes for a nine byte frame, which
// aborted QuicSendPathChallenges.
//
TEST_P(MinSendAllowanceTest, LeavesRoomForAControlFrame)
{
    const QUIC_ADDRESS_FAMILY Family = (QUIC_ADDRESS_FAMILY)GetParam();

    const uint32_t Allowance = QUIC_MIN_SEND_ALLOWANCE_FOR_FAMILY(Family);
    ASSERT_LE(Allowance, (uint32_t)UINT16_MAX);

    //
    // Whatever the family costs in headers, the same payload is left over.
    //
    ASSERT_EQ(
        MaxUdpPayloadSizeForFamily(Family, (uint16_t)Allowance),
        QUIC_MIN_SEND_UDP_PAYLOAD_LENGTH);

    //
    // And that payload covers the encryption overhead, the largest short header
    // MsQuic's own connection IDs produce, and the frame.
    //
    ASSERT_GE(
        QUIC_MIN_SEND_UDP_PAYLOAD_LENGTH,
        CXPLAT_ENCRYPTION_OVERHEAD + MAX_SHORT_HEADER_LENGTH + PATH_CHALLENGE_FRAME_LENGTH);
}

INSTANTIATE_TEST_SUITE_P(
    Allowance,
    MinSendAllowanceTest,
    ::testing::Values(QUIC_ADDRESS_FAMILY_INET, QUIC_ADDRESS_FAMILY_INET6),
    [](const ::testing::TestParamInfo<int>& Info) {
        return Info.param == QUIC_ADDRESS_FAMILY_INET ? "v4" : "v6";
    });
