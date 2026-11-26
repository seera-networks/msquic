/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic QMux (QX) Unittest

    QMux connections run the QUIC frame layer over a TCP transport instead of
    UDP. They are created with the ConnectionQmuxOpen/ListenerQmuxOpen APIs;
    everything after that (configuration, streams, shutdown) uses the regular
    MsQuic API surface.

--*/

#include "precomp.h"

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES

//
// Amount of data each side of the stream tests sends.
//
const uint32_t QMuxTestDataLength = 4096;

//
// Shared, immutable send buffer. Sends are asynchronous, so the memory must
// outlive the call; a static buffer is the simplest way to guarantee that.
//
static uint8_t QMuxTestRawBuffer[QMuxTestDataLength];
static QUIC_BUFFER QMuxTestSendBuffer = { QMuxTestDataLength, QMuxTestRawBuffer };

struct QMuxServerContext {
    CxPlatEvent ConnectedEvent;
    CxPlatEvent ShutdownEvent;
    CxPlatEvent StreamShutdownEvent;
    MsQuicConnection* Connection {nullptr};
    uint64_t BytesReceived {0};

    static QUIC_STATUS QUIC_API StreamCallback(
        _In_ MsQuicStream* Stream,
        _In_opt_ void* Context,
        _Inout_ QUIC_STREAM_EVENT* Event
        )
    {
        auto Ctx = static_cast<QMuxServerContext*>(Context);
        switch (Event->Type) {
        case QUIC_STREAM_EVENT_RECEIVE:
            Ctx->BytesReceived += Event->RECEIVE.TotalBufferLength;
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            //
            // The peer is done sending. Echo the same amount of data back and
            // close our send direction along with it.
            //
            Stream->Send(&QMuxTestSendBuffer, 1, QUIC_SEND_FLAG_FIN);
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            Ctx->StreamShutdownEvent.Set();
            break;
        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS QUIC_API ConnCallback(
        _In_ MsQuicConnection* Conn,
        _In_opt_ void* Context,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        )
    {
        auto Ctx = static_cast<QMuxServerContext*>(Context);
        Ctx->Connection = Conn;
        switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            Ctx->ConnectedEvent.Set();
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            new(std::nothrow) MsQuicStream(
                Event->PEER_STREAM_STARTED.Stream,
                CleanUpAutoDelete,
                StreamCallback,
                Context);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            Ctx->Connection = nullptr;
            //
            // Unblock anything still waiting so a failure shows up as a bad
            // value rather than a test hang.
            //
            Ctx->ConnectedEvent.Set();
            Ctx->StreamShutdownEvent.Set();
            Ctx->ShutdownEvent.Set();
            break;
        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }
};

struct QMuxClientContext {
    CxPlatEvent StreamShutdownEvent;
    uint64_t BytesReceived {0};

    static QUIC_STATUS QUIC_API StreamCallback(
        _In_ MsQuicStream* /* Stream */,
        _In_opt_ void* Context,
        _Inout_ QUIC_STREAM_EVENT* Event
        )
    {
        auto Ctx = static_cast<QMuxClientContext*>(Context);
        switch (Event->Type) {
        case QUIC_STREAM_EVENT_RECEIVE:
            Ctx->BytesReceived += Event->RECEIVE.TotalBufferLength;
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            Ctx->StreamShutdownEvent.Set();
            break;
        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }
};

//
// QMux runs over TCP, so it needs a datapath that can create TCP sockets.
// Only the epoll and Windows user-mode datapaths advertise
// CXPLAT_DATAPATH_FEATURE_TCP; io_uring, kqueue and the Windows kernel
// datapath leave SocketCreateTcp and SocketCreateTcpListener as stubs that
// return QUIC_STATUS_NOT_SUPPORTED, so a QMux listener cannot even start
// there -- ListenerStart fails with 0x5f and every QMux test fails with it.
// There is nothing to test in that case, so the tests return early, the way
// the raw-datapath checks in HandshakeTest.cpp and QuicDrill.cpp do.
//
// Call this only once a registration exists. The datapath is created lazily
// -- QuicRegistrationOpen is what calls QuicLibraryLazyInitialize -- and
// QUIC_PARAM_GLOBAL_DATAPATH_FEATURES fails with QUIC_STATUS_INVALID_STATE
// until then, which reads as "no features" and would skip the tests
// everywhere, including on the epoll datapath that does support them.
//
static
bool
QMuxDatapathSupportsTcp()
{
    if (QuitTestIsFeatureSupported(CXPLAT_DATAPATH_FEATURE_TCP)) {
        return true;
    }
    //
    // Leave a mark in the log, so a run that quietly passed every QMux test in
    // no time is distinguishable from one that actually tested something.
    //
    TestScopeLogger Skipped("QMux test skipped: datapath does not support TCP");
    return false;
}

//
// Brings up a QMux listener and returns its bound address. QMux listeners bind
// the supplied address literally (unlike UDP listeners, which always take the
// dual-mode wildcard), so the family passed here is the family actually used.
//
static
void
QMuxStartListener(
    _In_ MsQuicAutoAcceptListener& Listener,
    _In_ int Family,
    _Out_ QuicAddr& ServerLocalAddr
    )
{
    const QUIC_ADDRESS_FAMILY QuicAddrFamily =
        (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    ServerLocalAddr = QuicAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));
}


void
QuicTestQMuxConnect(
    _In_ const FamilyArgs& Params
    )
{
    QMuxServerContext ServerContext;

    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    if (!QMuxDatapathSupportsTcp()) {
        return;
    }

    MsQuicConfiguration ServerConfiguration(
        Registration, "MsQuicTest", MsQuicSettings{}, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(
        Registration, "MsQuicTest", MsQuicSettings{}, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(
        Registration, true, ServerConfiguration, QMuxServerContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());

    QuicAddr ServerLocalAddr;
    QMuxStartListener(Listener, Params.Family, ServerLocalAddr);

    MsQuicConnection Connection(Registration, true);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    //
    // Like UDP, this only queues the start; for QMux the TCP connect and the
    // TLS handshake both complete asynchronously.
    //
    TEST_QUIC_SUCCEEDED(
        Connection.Start(
            ClientConfiguration,
            ServerLocalAddr.GetFamily(),
            QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.ConnectedEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Connection.HandshakeComplete);
    TEST_NOT_EQUAL(nullptr, ServerContext.Connection);

    //
    // The client's remote address must be the address the listener reported.
    //
    QuicAddr ClientLocalAddr, ClientRemoteAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(ClientLocalAddr));
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(ClientRemoteAddr));
    TEST_EQUAL(ServerLocalAddr.GetPort(), ClientRemoteAddr.GetPort());
    TEST_NOT_EQUAL(0, ClientLocalAddr.GetPort());

    Connection.Shutdown(0);
    TEST_TRUE(Connection.ShutdownCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.ShutdownEvent.WaitTimeout(TestWaitTimeout));
}

void
QuicTestQMuxStreamData(
    _In_ const FamilyArgs& Params
    )
{
    QMuxServerContext ServerContext;
    QMuxClientContext ClientContext;

    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    if (!QMuxDatapathSupportsTcp()) {
        return;
    }

    MsQuicSettings Settings;
    Settings.SetPeerBidiStreamCount(1);

    MsQuicConfiguration ServerConfiguration(
        Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(
        Registration, "MsQuicTest", Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(
        Registration, true, ServerConfiguration, QMuxServerContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());

    QuicAddr ServerLocalAddr;
    QMuxStartListener(Listener, Params.Family, ServerLocalAddr);

    MsQuicConnection Connection(Registration, true);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    TEST_QUIC_SUCCEEDED(
        Connection.Start(
            ClientConfiguration,
            ServerLocalAddr.GetFamily(),
            QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.ConnectedEvent.WaitTimeout(TestWaitTimeout));

    {
        MsQuicStream Stream(
            Connection,
            QUIC_STREAM_OPEN_FLAG_NONE,
            CleanUpManual,
            QMuxClientContext::StreamCallback,
            &ClientContext);
        TEST_QUIC_SUCCEEDED(Stream.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Stream.Start());
        TEST_QUIC_SUCCEEDED(Stream.Send(&QMuxTestSendBuffer, 1, QUIC_SEND_FLAG_FIN));

        //
        // The server echoes the same amount of data back with a FIN, which
        // completes the stream in both directions.
        //
        TEST_TRUE(ClientContext.StreamShutdownEvent.WaitTimeout(TestWaitTimeout));
        TEST_TRUE(ServerContext.StreamShutdownEvent.WaitTimeout(TestWaitTimeout));
    }

    TEST_EQUAL(QMuxTestDataLength, ServerContext.BytesReceived);
    TEST_EQUAL(QMuxTestDataLength, ClientContext.BytesReceived);

    Connection.Shutdown(0);
    TEST_TRUE(Connection.ShutdownCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.ShutdownEvent.WaitTimeout(TestWaitTimeout));
}

//
// Receive-only side of QuicTestQMuxUniStreamLimits. Each stream completing is
// what releases a unidirectional stream credit and makes this end send
// MAX_STREAMS.
//
struct QMuxUniStreamServerContext {
    CxPlatEvent ConnectedEvent;
    CxPlatEvent ShutdownEvent;
    CxPlatEvent AllStreamsEvent;
    uint32_t StreamsExpected {0};
    uint32_t StreamsCompleted {0};
    uint64_t BytesReceived {0};

    static QUIC_STATUS QUIC_API StreamCallback(
        _In_ MsQuicStream* Stream,
        _In_opt_ void* Context,
        _Inout_ QUIC_STREAM_EVENT* Event
        )
    {
        auto Ctx = static_cast<QMuxUniStreamServerContext*>(Context);
        switch (Event->Type) {
        case QUIC_STREAM_EVENT_RECEIVE:
            Ctx->BytesReceived += Event->RECEIVE.TotalBufferLength;
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            //
            // Nothing to echo on a unidirectional stream: shutting down is
            // all this end can do, and closing the stream is what returns the
            // credit.
            //
            Stream->Shutdown(0);
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            //
            // Counted here rather than waited for by the client: the client's
            // own stream completes as soon as its FIN is written, which is
            // before this end has finished with it.
            //
            if (++Ctx->StreamsCompleted == Ctx->StreamsExpected) {
                Ctx->AllStreamsEvent.Set();
            }
            break;
        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS QUIC_API ConnCallback(
        _In_ MsQuicConnection* Conn,
        _In_opt_ void* Context,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        )
    {
        auto Ctx = static_cast<QMuxUniStreamServerContext*>(Context);
        Ctx->Connection = Conn;
        switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            Ctx->ConnectedEvent.Set();
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            new(std::nothrow) MsQuicStream(
                Event->PEER_STREAM_STARTED.Stream,
                CleanUpAutoDelete,
                StreamCallback,
                Context);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            Ctx->Connection = nullptr;
            Ctx->ConnectedEvent.Set();
            Ctx->AllStreamsEvent.Set();
            Ctx->ShutdownEvent.Set();
            break;
        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }

    MsQuicConnection* Connection {nullptr};
};

//
// More unidirectional streams than the peer's initial limit, one at a time, so
// every stream after the first needs a MAX_STREAMS frame for the
// unidirectional type to arrive first.
//
// That frame is 0x13, the second of the two MAX_STREAMS codepoints, and QMux
// permits MAX_STREAMS (draft-ietf-quic-qmux-02 section 4). Only 0x12 was in
// the allowed list, so this is what the omission cost: the frame the peer has
// to send to let a second unidirectional stream open was read as a disallowed
// frame type and closed the connection with FRAME_ENCODING_ERROR.
//
//
// Server side of QuicTestQMuxGracefulClose: records how the connection ended,
// which is the only thing that distinguishes a close the peer announced from
// one it was cut off in the middle of.
//
struct QMuxCloseServerContext {
    CxPlatEvent ConnectedEvent;
    CxPlatEvent ShutdownEvent;
    CxPlatEvent StreamShutdownEvent;
    uint64_t BytesReceived {0};
    uint64_t PeerErrorCode {0};
    bool PeerInitiated {false};

    static QUIC_STATUS QUIC_API StreamCallback(
        _In_ MsQuicStream* /* Stream */,
        _In_opt_ void* Context,
        _Inout_ QUIC_STREAM_EVENT* Event
        )
    {
        auto Ctx = static_cast<QMuxCloseServerContext*>(Context);
        switch (Event->Type) {
        case QUIC_STREAM_EVENT_RECEIVE:
            Ctx->BytesReceived += Event->RECEIVE.TotalBufferLength;
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            Ctx->StreamShutdownEvent.Set();
            break;
        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS QUIC_API ConnCallback(
        _In_ MsQuicConnection* /* Conn */,
        _In_opt_ void* Context,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        )
    {
        auto Ctx = static_cast<QMuxCloseServerContext*>(Context);
        switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            Ctx->ConnectedEvent.Set();
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            new(std::nothrow) MsQuicStream(
                Event->PEER_STREAM_STARTED.Stream,
                CleanUpAutoDelete,
                StreamCallback,
                Context);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
            Ctx->PeerInitiated = true;
            Ctx->PeerErrorCode = Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode;
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            Ctx->ConnectedEvent.Set();
            Ctx->StreamShutdownEvent.Set();
            Ctx->ShutdownEvent.Set();
            break;
        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }
};

//
// A close the application asked for reaches the peer as that close, carrying
// its error code, and the stream data written before it is not lost with it.
//
// draft-ietf-quic-qmux-02 section 7.2 asks for the graceful shutdown that
// makes this true: "The use of graceful shutdown mitigates the risk of
// undelivered records and frames becoming lost due to abrupt termination of
// the underlying transport." The Linux datapath used to set SO_LINGER with a
// zero timeout on its TCP sockets to stay out of TIME_WAIT, so close() sent a
// reset; the CONNECTION_CLOSE written a moment earlier went with it, and the
// peer saw an aborted connection with no error code instead.
//
void
QuicTestQMuxGracefulClose(
    _In_ const FamilyArgs& Params
    )
{
    QMuxCloseServerContext ServerContext;

    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    if (!QMuxDatapathSupportsTcp()) {
        return;
    }

    const QUIC_UINT62 CloseErrorCode = 0x1234;

    MsQuicSettings Settings;
    Settings.SetPeerUnidiStreamCount(1);

    MsQuicConfiguration ServerConfiguration(
        Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(
        Registration, "MsQuicTest", Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(
        Registration, true, ServerConfiguration,
        QMuxCloseServerContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());

    QuicAddr ServerLocalAddr;
    QMuxStartListener(Listener, Params.Family, ServerLocalAddr);

    MsQuicConnection Connection(Registration, true);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    TEST_QUIC_SUCCEEDED(
        Connection.Start(
            ClientConfiguration,
            ServerLocalAddr.GetFamily(),
            QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.ConnectedEvent.WaitTimeout(TestWaitTimeout));

    //
    // A stream's worth of data first, and waited for: what the close is asked
    // to preserve is the record carrying the CONNECTION_CLOSE, not whatever
    // the application had queued when it called -- an application close
    // discards that in QUIC too.
    //
    {
        MsQuicStream Stream(
            Connection,
            QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
            CleanUpManual,
            MsQuicStream::NoOpCallback);
        TEST_QUIC_SUCCEEDED(Stream.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Stream.Start());
        TEST_QUIC_SUCCEEDED(Stream.Send(&QMuxTestSendBuffer, 1, QUIC_SEND_FLAG_FIN));
        TEST_TRUE(ServerContext.StreamShutdownEvent.WaitTimeout(TestWaitTimeout));
    }

    Connection.Shutdown(CloseErrorCode);

    TEST_TRUE(Connection.ShutdownCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.ShutdownEvent.WaitTimeout(TestWaitTimeout));

    TEST_TRUE(ServerContext.PeerInitiated);
    TEST_EQUAL(CloseErrorCode, ServerContext.PeerErrorCode);
    TEST_EQUAL(QMuxTestDataLength, ServerContext.BytesReceived);
}

void
QuicTestQMuxUniStreamLimits(
    _In_ const FamilyArgs& Params
    )
{
    QMuxUniStreamServerContext ServerContext;

    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    if (!QMuxDatapathSupportsTcp()) {
        return;
    }

    //
    // One at a time, which is the point: the client cannot open the next
    // stream until the server has released the credit for the last.
    //
    const uint32_t StreamCount = 4;
    ServerContext.StreamsExpected = StreamCount;
    MsQuicSettings Settings;
    Settings.SetPeerUnidiStreamCount(1);

    MsQuicConfiguration ServerConfiguration(
        Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(
        Registration, "MsQuicTest", Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(
        Registration, true, ServerConfiguration,
        QMuxUniStreamServerContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());

    QuicAddr ServerLocalAddr;
    QMuxStartListener(Listener, Params.Family, ServerLocalAddr);

    MsQuicConnection Connection(Registration, true);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    TEST_QUIC_SUCCEEDED(
        Connection.Start(
            ClientConfiguration,
            ServerLocalAddr.GetFamily(),
            QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.ConnectedEvent.WaitTimeout(TestWaitTimeout));

    for (uint32_t i = 0; i < StreamCount; ++i) {
        QMuxClientContext ClientContext;
        MsQuicStream Stream(
            Connection,
            QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
            CleanUpManual,
            QMuxClientContext::StreamCallback,
            &ClientContext);
        TEST_QUIC_SUCCEEDED(Stream.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Stream.Start());
        TEST_QUIC_SUCCEEDED(Stream.Send(&QMuxTestSendBuffer, 1, QUIC_SEND_FLAG_FIN));
        TEST_TRUE(ClientContext.StreamShutdownEvent.WaitTimeout(TestWaitTimeout));
    }

    //
    // Every stream arrived, and the connection is still the one that carried
    // them: a frame refused mid-run would have shut it down instead.
    //
    TEST_TRUE(ServerContext.AllStreamsEvent.WaitTimeout(TestWaitTimeout));
    TEST_EQUAL(StreamCount, ServerContext.StreamsCompleted);
    TEST_EQUAL(QMuxTestDataLength * StreamCount, ServerContext.BytesReceived);
    TEST_FALSE(ServerContext.ShutdownEvent.WaitTimeout(100));

    Connection.Shutdown(0);
    TEST_TRUE(Connection.ShutdownCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.ShutdownEvent.WaitTimeout(TestWaitTimeout));
}

void
QuicTestQMuxKeepAlive(
    _In_ const FamilyArgs& Params
    )
{
    const uint32_t IdleTimeoutMs = 2000;
    const uint32_t KeepAliveIntervalMs = 500;
    const uint32_t IdleWaitMs = IdleTimeoutMs * 2;

    QMuxServerContext ServerContext;

    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    if (!QMuxDatapathSupportsTcp()) {
        return;
    }

    MsQuicSettings Settings;
    Settings.SetIdleTimeoutMs(IdleTimeoutMs);

    MsQuicConfiguration ServerConfiguration(
        Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(
        Registration, "MsQuicTest",
        MsQuicSettings(Settings).SetKeepAlive(KeepAliveIntervalMs),
        ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(
        Registration, true, ServerConfiguration, QMuxServerContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());

    QuicAddr ServerLocalAddr;
    QMuxStartListener(Listener, Params.Family, ServerLocalAddr);

    MsQuicConnection Connection(Registration, true);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    TEST_QUIC_SUCCEEDED(
        Connection.Start(
            ClientConfiguration,
            ServerLocalAddr.GetFamily(),
            QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.ConnectedEvent.WaitTimeout(TestWaitTimeout));

    //
    // Stay idle for longer than the idle timeout. The QX PING frames the
    // keep-alive timer sends must hold both sides open.
    //
    TEST_FALSE(Connection.ShutdownCompleteEvent.WaitTimeout(IdleWaitMs));
    TEST_FALSE(ServerContext.ShutdownEvent.WaitTimeout(0));
    TEST_NOT_EQUAL(nullptr, ServerContext.Connection);

    Connection.Shutdown(0);
    TEST_TRUE(Connection.ShutdownCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.ShutdownEvent.WaitTimeout(TestWaitTimeout));
}

//
// Datagram burst: more DATAGRAM frames queued in one go than fit in a single
// QUIC packet's frame metadata (QUIC_MAX_FRAMES_PER_PACKET). Over QMux this
// used to finalize (and TLS-encrypt) a record without closing its buffer, and
// the flush that followed freed that buffer unsent: the peer then failed to
// decrypt the next record and the connection died. A burst that also left
// less than QUIC_MIN_PACKET_SPARE_SPACE in the record buffer crashed in the
// UDP packet finalizer instead (a QMux path has no PathID).
//
const uint32_t QMuxDatagramBurstCount = 32;
const uint16_t QMuxDatagramBurstLength = 1200;
static uint8_t QMuxDatagramRawBuffer[QMuxDatagramBurstLength];
static QUIC_BUFFER QMuxDatagramSendBuffer = { QMuxDatagramBurstLength, QMuxDatagramRawBuffer };

struct QMuxDatagramServerContext {
    CxPlatEvent ConnectedEvent;
    CxPlatEvent ShutdownEvent;
    uint32_t SendFailures {0};

    static QUIC_STATUS QUIC_API ConnCallback(
        _In_ MsQuicConnection* Conn,
        _In_opt_ void* Context,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        )
    {
        auto Ctx = static_cast<QMuxDatagramServerContext*>(Context);
        switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            //
            // Queue the whole burst from the callback: the connection's worker
            // cannot flush until it returns, so every datagram is pending in
            // the same send flush.
            //
            for (uint32_t i = 0; i < QMuxDatagramBurstCount; ++i) {
                if (QUIC_FAILED(
                    MsQuic->DatagramSend(
                        *Conn, &QMuxDatagramSendBuffer, 1, QUIC_SEND_FLAG_NONE, nullptr))) {
                    ++Ctx->SendFailures;
                }
            }
            Ctx->ConnectedEvent.Set();
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            Ctx->ConnectedEvent.Set();
            Ctx->ShutdownEvent.Set();
            break;
        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }
};

struct QMuxDatagramClientContext {
    CxPlatEvent AllReceivedEvent;
    CxPlatEvent ShutdownEvent;
    uint32_t Received {0};
    uint32_t WrongLength {0};

    static QUIC_STATUS QUIC_API ConnCallback(
        _In_ MsQuicConnection* /* Conn */,
        _In_opt_ void* Context,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        )
    {
        auto Ctx = static_cast<QMuxDatagramClientContext*>(Context);
        switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
            if (Event->DATAGRAM_RECEIVED.Buffer->Length != QMuxDatagramBurstLength) {
                ++Ctx->WrongLength;
            }
            if (++Ctx->Received == QMuxDatagramBurstCount) {
                Ctx->AllReceivedEvent.Set();
            }
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            //
            // A connection lost mid-burst unblocks the wait; the counts then
            // say what was missing.
            //
            Ctx->AllReceivedEvent.Set();
            Ctx->ShutdownEvent.Set();
            break;
        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }
};

void
QuicTestQMuxDatagramBurst(
    _In_ const FamilyArgs& Params
    )
{
    QMuxDatagramServerContext ServerContext;
    QMuxDatagramClientContext ClientContext;

    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    if (!QMuxDatapathSupportsTcp()) {
        return;
    }

    MsQuicSettings Settings;
    Settings.SetDatagramReceiveEnabled(true);

    MsQuicConfiguration ServerConfiguration(
        Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(
        Registration, "MsQuicTest", Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(
        Registration, true, ServerConfiguration,
        QMuxDatagramServerContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());

    QuicAddr ServerLocalAddr;
    QMuxStartListener(Listener, Params.Family, ServerLocalAddr);

    MsQuicConnection Connection(
        Registration, true, CleanUpManual,
        QMuxDatagramClientContext::ConnCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    TEST_QUIC_SUCCEEDED(
        Connection.Start(
            ClientConfiguration,
            ServerLocalAddr.GetFamily(),
            QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()),
            ServerLocalAddr.GetPort()));

    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.ConnectedEvent.WaitTimeout(TestWaitTimeout));
    TEST_EQUAL(0u, ServerContext.SendFailures);

    //
    // QMux runs over TCP, so nothing may be lost: every datagram of the burst
    // arrives, and the connection is still up afterwards.
    //
    TEST_TRUE(ClientContext.AllReceivedEvent.WaitTimeout(TestWaitTimeout));
    TEST_EQUAL(QMuxDatagramBurstCount, ClientContext.Received);
    TEST_EQUAL(0u, ClientContext.WrongLength);
    TEST_FALSE(ClientContext.ShutdownEvent.WaitTimeout(0));
    TEST_FALSE(ServerContext.ShutdownEvent.WaitTimeout(0));

    Connection.Shutdown(0);
    TEST_TRUE(Connection.ShutdownCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.ShutdownEvent.WaitTimeout(TestWaitTimeout));
}

#endif // QUIC_API_ENABLE_PREVIEW_FEATURES
