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
