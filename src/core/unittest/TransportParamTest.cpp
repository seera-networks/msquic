/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for the QUIC transport parameter encoding and decoding logic.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "TransportParamTest.cpp.clog.h"
#endif

static QUIC_CONNECTION JunkConnection;

void CompareTransportParams(
    _In_ const QUIC_TRANSPORT_PARAMETERS* A,
    _In_ const QUIC_TRANSPORT_PARAMETERS* B,
    _In_ bool IsServer = false
    )
{
    ASSERT_EQ(A->Flags, B->Flags);
    COMPARE_TP_FIELD(INITIAL_MAX_DATA, InitialMaxData);
    COMPARE_TP_FIELD(INITIAL_MAX_STRM_DATA_BIDI_LOCAL, InitialMaxStreamDataBidiLocal);
    COMPARE_TP_FIELD(INITIAL_MAX_STRM_DATA_BIDI_REMOTE, InitialMaxStreamDataBidiRemote);
    COMPARE_TP_FIELD(INITIAL_MAX_STRM_DATA_UNI, InitialMaxStreamDataUni);
    COMPARE_TP_FIELD(INITIAL_MAX_STRMS_BIDI, InitialMaxBidiStreams);
    COMPARE_TP_FIELD(INITIAL_MAX_STRMS_UNI, InitialMaxUniStreams);
    COMPARE_TP_FIELD(MAX_UDP_PAYLOAD_SIZE, MaxUdpPayloadSize);
    COMPARE_TP_FIELD(ACK_DELAY_EXPONENT, AckDelayExponent);
    COMPARE_TP_FIELD(IDLE_TIMEOUT, IdleTimeout);
    COMPARE_TP_FIELD(MAX_ACK_DELAY, MaxAckDelay);
    COMPARE_TP_FIELD(ACTIVE_CONNECTION_ID_LIMIT, ActiveConnectionIdLimit);
    COMPARE_TP_FIELD(CIBIR_ENCODING, CibirLength);
    COMPARE_TP_FIELD(CIBIR_ENCODING, CibirOffset);
    if (A->Flags & QUIC_TP_FLAG_VERSION_NEGOTIATION) {
        ASSERT_EQ(A->VersionInfoLength, B->VersionInfoLength);
        ASSERT_EQ(
            memcmp(A->VersionInfo, B->VersionInfo, (size_t)A->VersionInfoLength),
            0);
    }
    //COMPARE_TP_FIELD(InitialSourceConnectionID);
    //COMPARE_TP_FIELD(InitialSourceConnectionIDLength);
    if (IsServer) { // TODO
        //COMPARE_TP_FIELD(StatelessResetToken);
        //COMPARE_TP_FIELD(AckPreferredAddressDelayExponent);
        //COMPARE_TP_FIELD(OriginalDestinationConnectionID);
        //COMPARE_TP_FIELD(OriginalDestinationConnectionIDLength);
        //COMPARE_TP_FIELD(RetrySourceConnectionID);
        //COMPARE_TP_FIELD(RetrySourceConnectionIDLength);
    }
}

struct TransportParametersScope
{
    QUIC_TRANSPORT_PARAMETERS* const TP;
    TransportParametersScope(QUIC_TRANSPORT_PARAMETERS* const value) : TP(value) {}
    ~TransportParametersScope() {
        if (TP != nullptr) {
            QuicCryptoTlsCleanupTransportParameters(TP);
        }
    }
};

void EncodeDecodeAndCompare(
    _In_ const QUIC_TRANSPORT_PARAMETERS* Original,
    _In_ bool IsServer = false,
    _In_ bool ShouldDecodeSuccessfully = true
    )
{
    uint32_t BufferLength;
    auto Buffer =
        QuicCryptoTlsEncodeTransportParameters(
            &JunkConnection, IsServer, Original, NULL, &BufferLength);
    ASSERT_NE(nullptr, Buffer);

    ASSERT_TRUE(UINT16_MAX >= (BufferLength - CxPlatTlsTPHeaderSize));

    auto TPBuffer = Buffer + CxPlatTlsTPHeaderSize;
    uint16_t TPBufferLength = (uint16_t)(BufferLength - CxPlatTlsTPHeaderSize);

    QUIC_TRANSPORT_PARAMETERS Decoded = {0};
    TransportParametersScope TPScope(&Decoded);
    BOOLEAN DecodedSuccessfully =
        QuicCryptoTlsDecodeTransportParameters(
            &JunkConnection, IsServer, TPBuffer, TPBufferLength, &Decoded);

    CXPLAT_FREE(Buffer, QUIC_POOL_TLS_TRANSPARAMS);
    ASSERT_EQ(ShouldDecodeSuccessfully, DecodedSuccessfully);
    if (ShouldDecodeSuccessfully) {
        CompareTransportParams(Original, &Decoded, IsServer);
    }
}

void DecodeTwice(
    _In_ const QUIC_TRANSPORT_PARAMETERS* Original,
    _In_ bool IsServer = false
    )
{
    uint32_t BufferLength;
    auto Buffer =
        QuicCryptoTlsEncodeTransportParameters(
            &JunkConnection, IsServer, Original, NULL, &BufferLength);
    ASSERT_NE(nullptr, Buffer);

    ASSERT_TRUE(UINT16_MAX >= (BufferLength - CxPlatTlsTPHeaderSize));

    auto TPBuffer = Buffer + CxPlatTlsTPHeaderSize;
    uint16_t TPBufferLength = (uint16_t)(BufferLength - CxPlatTlsTPHeaderSize);

    QUIC_TRANSPORT_PARAMETERS Decoded = {0};
    TransportParametersScope TPScope(&Decoded);
    BOOLEAN DecodedSuccessfullyOnce =
        QuicCryptoTlsDecodeTransportParameters(
            &JunkConnection, IsServer, TPBuffer, TPBufferLength, &Decoded);
    BOOLEAN DecodedSuccessfullyTwice =
        QuicCryptoTlsDecodeTransportParameters(
            &JunkConnection, IsServer, TPBuffer, TPBufferLength, &Decoded);

    CXPLAT_FREE(Buffer, QUIC_POOL_TLS_TRANSPARAMS);
    ASSERT_TRUE(DecodedSuccessfullyOnce);
    ASSERT_TRUE(DecodedSuccessfullyTwice);
}

/*TEST(TransportParamTest, EmptyClient)
{
    QUIC_TRANSPORT_PARAMETERS Original;
    CxPlatZeroMemory(&Original, sizeof(Original));
    EncodeDecodeAndCompare(&Original);
}

TEST(TransportParamTest, EmptyServer)
{
    QUIC_TRANSPORT_PARAMETERS Original;
    CxPlatZeroMemory(&Original, sizeof(Original));
    EncodeDecodeAndCompare(&Original, true);
}*/

TEST(TransportParamTest, Preset1)
{
    QUIC_TRANSPORT_PARAMETERS Original;
    CxPlatZeroMemory(&Original, sizeof(Original));
    Original.Flags |= QUIC_TP_FLAG_IDLE_TIMEOUT;
    Original.IdleTimeout = 100000;
    EncodeDecodeAndCompare(&Original);
}

TEST(TransportParamTest, Preset1DecodeTwice)
{
    QUIC_TRANSPORT_PARAMETERS Original;
    CxPlatZeroMemory(&Original, sizeof(Original));
    Original.Flags |= QUIC_TP_FLAG_IDLE_TIMEOUT;
    Original.IdleTimeout = 100000;
    DecodeTwice(&Original);
}

TEST(TransportParamTest, ZeroTP)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags =
        QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT |
        QUIC_TP_FLAG_INITIAL_MAX_DATA |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
        QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI |
        QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
    OriginalTP.ActiveConnectionIdLimit = QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_MIN;

    EncodeDecodeAndCompare(&OriginalTP);
}

TEST(TransportParamTest, VersionNegotiationExtension)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    uint8_t VerInfo[21];
    OriginalTP.VersionInfo = VerInfo;
    OriginalTP.VersionInfoLength = sizeof(VerInfo);
    OriginalTP.Flags = QUIC_TP_FLAG_VERSION_NEGOTIATION;

    EncodeDecodeAndCompare(&OriginalTP);
}

TEST(TransportParamTest, VersionNegotiationExtensionDecodeTwice)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    uint8_t VerInfo[21];
    OriginalTP.VersionInfo = VerInfo;
    OriginalTP.VersionInfoLength = sizeof(VerInfo);
    OriginalTP.Flags = QUIC_TP_FLAG_VERSION_NEGOTIATION;

    DecodeTwice(&OriginalTP);
}

TEST(TransportParamTest, CibirEncodingOne)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    OriginalTP.CibirLength = 1;
    EncodeDecodeAndCompare(&OriginalTP);
}

TEST(TransportParamTest, CibirEncodingMax)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    OriginalTP.CibirLength = 255;
    EncodeDecodeAndCompare(&OriginalTP);
}

TEST(TransportParamTest, CibirEncodingMax2)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    OriginalTP.CibirLength = 254;
    OriginalTP.CibirOffset = 1;
    EncodeDecodeAndCompare(&OriginalTP);
}

TEST(TransportParamTest, CibirEncodingZero)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    EncodeDecodeAndCompare(&OriginalTP, false, false);
}

TEST(TransportParamTest, CibirEncodingOverMax)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    OriginalTP.CibirLength = 256;
    EncodeDecodeAndCompare(&OriginalTP, false, false);
}

TEST(TransportParamTest, CibirEncodingOverMax2)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_CIBIR_ENCODING;
    OriginalTP.CibirLength = 255;
    OriginalTP.CibirOffset = 1;
    EncodeDecodeAndCompare(&OriginalTP, false, false);
}

TEST(TransportParamTest, GreaseQuicBit)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_GREASE_QUIC_BIT;
    EncodeDecodeAndCompare(&OriginalTP);
    EncodeDecodeAndCompare(&OriginalTP, true);
}

TEST(TransportParamTest, ReliableResetEnabled)
{
    QUIC_TRANSPORT_PARAMETERS OriginalTP;
    CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
    OriginalTP.Flags = QUIC_TP_FLAG_RELIABLE_RESET_ENABLED;
    EncodeDecodeAndCompare(&OriginalTP);
    EncodeDecodeAndCompare(&OriginalTP, true);
}

TEST(TransportParamTest, ObservedAddress)
{
    const QUIC_VAR_INT Roles[] = {
        QUIC_TP_OBSERVED_ADDRESS_ROLE_SEND_ONLY,
        QUIC_TP_OBSERVED_ADDRESS_ROLE_RECEIVE_ONLY,
        QUIC_TP_OBSERVED_ADDRESS_ROLE_BOTH
    };
    for (size_t i = 0; i < ARRAYSIZE(Roles); ++i) {
        QUIC_TRANSPORT_PARAMETERS OriginalTP;
        CxPlatZeroMemory(&OriginalTP, sizeof(OriginalTP));
        OriginalTP.Flags = QUIC_TP_FLAG_OBSERVED_ADDRESS;
        OriginalTP.ObservedAddressRole = Roles[i];
        EncodeDecodeAndCompare(&OriginalTP);
        EncodeDecodeAndCompare(&OriginalTP, true);
    }
}

//
// draft-munizaga-quic-alternative-server-address-02 alternative_address.
//
// Client to server only, value is a possibly empty list of the address types
// supported beyond the three the draft makes implicit.
//
TEST(TransportParamTest, AlternativeAddressClientRoundTrip)
{
    QUIC_TRANSPORT_PARAMETERS Original = {0};
    Original.Flags = QUIC_TP_FLAG_ALTERNATIVE_ADDRESS;
    EncodeDecodeAndCompare(&Original);
}

//
// A server is forbidden to send it, and the draft makes that
// TRANSPORT_PARAMETER_ERROR rather than something to ignore. Encoding as a
// server and decoding as one has to fail -- if it were merely ignored, a
// client would have no way to tell a conforming server from one that thinks
// this parameter means something coming the other way.
//
TEST(TransportParamTest, AlternativeAddressRejectedFromServer)
{
    QUIC_TRANSPORT_PARAMETERS Original = {0};
    Original.Flags = QUIC_TP_FLAG_ALTERNATIVE_ADDRESS;
    EncodeDecodeAndCompare(&Original, true, false);
}

//
// The hand-built value cases. The encoder only ever writes an empty list, so
// a non-empty or malformed one has to be assembled directly.
//
struct AltAddrTpValueTest : public ::testing::Test {
    static BOOLEAN DecodeWithValue(const uint8_t* Value, uint16_t ValueLength) {
        uint8_t Buffer[64];
        CxPlatZeroMemory(Buffer, sizeof(Buffer));
        uint8_t* Cursor = Buffer;
        Cursor = QuicVarIntEncode(0xff0969d85cULL, Cursor);
        Cursor = QuicVarIntEncode(ValueLength, Cursor);
        if (ValueLength != 0) {
            CxPlatCopyMemory(Cursor, Value, ValueLength);
            Cursor += ValueLength;
        }

        QUIC_TRANSPORT_PARAMETERS Decoded = {0};
        TransportParametersScope TPScope(&Decoded);
        return
            QuicCryptoTlsDecodeTransportParameters(
                &JunkConnection,
                FALSE, // From a client.
                Buffer,
                (uint16_t)(Cursor - Buffer),
                &Decoded);
    }
};

TEST_F(AltAddrTpValueTest, AcceptsStrictlyIncreasingList)
{
    const uint8_t Value[] = { 0x03, 0x04, 0x07 };
    ASSERT_TRUE(DecodeWithValue(Value, sizeof(Value)));
}

TEST_F(AltAddrTpValueTest, RejectsDuplicateTypes)
{
    const uint8_t Value[] = { 0x03, 0x03 };
    ASSERT_FALSE(DecodeWithValue(Value, sizeof(Value)));
}

TEST_F(AltAddrTpValueTest, RejectsDecreasingTypes)
{
    const uint8_t Value[] = { 0x05, 0x04 };
    ASSERT_FALSE(DecodeWithValue(Value, sizeof(Value)));
}

//
// A varint whose length prefix runs past the end of the parameter value.
//
TEST_F(AltAddrTpValueTest, RejectsTruncatedList)
{
    const uint8_t Value[] = { 0x40 }; // Two-byte varint, only one byte present.
    ASSERT_FALSE(DecodeWithValue(Value, sizeof(Value)));
}

TEST_F(AltAddrTpValueTest, AcceptsEmptyList)
{
    ASSERT_TRUE(DecodeWithValue(nullptr, 0));
}

//
// draft-kozuka-quic-stateless-punch stateless_punch.
//
// Empty value, sent by both endpoints -- unlike alternative_address, which is
// client-only. So both directions round-trip.
//
TEST(TransportParamTest, StatelessPunchClientRoundTrip)
{
    QUIC_TRANSPORT_PARAMETERS Original = {0};
    //
    // With alternative_address, because a server receiving stateless_punch
    // without it is required to fail the handshake. The pairing is the
    // draft's one cross-parameter rule and the next test is the other half
    // of it.
    //
    Original.Flags = QUIC_TP_FLAG_STATELESS_PUNCH | QUIC_TP_FLAG_ALTERNATIVE_ADDRESS;
    EncodeDecodeAndCompare(&Original);
}

TEST(TransportParamTest, StatelessPunchServerRoundTrip)
{
    QUIC_TRANSPORT_PARAMETERS Original = {0};
    //
    // No alternative_address here, and that is the point: the prerequisite is
    // on the client's parameters only. A server sends stateless_punch alone
    // and a client must accept it.
    //
    Original.Flags = QUIC_TP_FLAG_STATELESS_PUNCH;
    EncodeDecodeAndCompare(&Original, true, true);
}

//
// A client asking for the extension without alternative_address has asked for
// something that cannot work: the pairing is against the addresses that frame
// carries. The draft makes it TRANSPORT_PARAMETER_ERROR rather than something
// to ignore, so decoding as a server has to fail.
//
TEST(TransportParamTest, StatelessPunchRejectedFromClientWithoutAltAddr)
{
    QUIC_TRANSPORT_PARAMETERS Original = {0};
    Original.Flags = QUIC_TP_FLAG_STATELESS_PUNCH;
    EncodeDecodeAndCompare(&Original, false, false);
}

//
// The value has to be empty. Hand-built, because the encoder only ever writes
// an empty one.
//
struct StatelessPunchTpValueTest : public ::testing::Test {
    static BOOLEAN DecodeWithValue(
        const uint8_t* Value,
        uint16_t ValueLength,
        BOOLEAN FromServer
        ) {
        uint8_t Buffer[64];
        CxPlatZeroMemory(Buffer, sizeof(Buffer));
        uint8_t* Cursor = Buffer;
        Cursor = QuicVarIntEncode(0x5eea9e7aULL, Cursor);
        Cursor = QuicVarIntEncode(ValueLength, Cursor);
        if (ValueLength != 0) {
            CxPlatCopyMemory(Cursor, Value, ValueLength);
            Cursor += ValueLength;
        }
        if (!FromServer) {
            //
            // The prerequisite, so that a rejection here is about the value
            // and not about the missing parameter.
            //
            Cursor = QuicVarIntEncode(0xff0969d85cULL, Cursor);
            Cursor = QuicVarIntEncode(0, Cursor);
        }

        QUIC_TRANSPORT_PARAMETERS Decoded = {0};
        TransportParametersScope TPScope(&Decoded);
        return
            QuicCryptoTlsDecodeTransportParameters(
                &JunkConnection,
                FromServer,
                Buffer,
                (uint16_t)(Cursor - Buffer),
                &Decoded);
    }
};

TEST_F(StatelessPunchTpValueTest, AcceptsEmptyValue)
{
    ASSERT_TRUE(DecodeWithValue(NULL, 0, FALSE));
    ASSERT_TRUE(DecodeWithValue(NULL, 0, TRUE));
}

TEST_F(StatelessPunchTpValueTest, RejectsNonEmptyValue)
{
    const uint8_t Value[] = { 0x00 };
    ASSERT_FALSE(DecodeWithValue(Value, sizeof(Value), FALSE));
    ASSERT_FALSE(DecodeWithValue(Value, sizeof(Value), TRUE));

    const uint8_t Longer[] = { 0x01, 0x02, 0x03, 0x04 };
    ASSERT_FALSE(DecodeWithValue(Longer, sizeof(Longer), FALSE));
    ASSERT_FALSE(DecodeWithValue(Longer, sizeof(Longer), TRUE));
}
