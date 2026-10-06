/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    MsQuic Path Unittest

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "PathTest.cpp.clog.h"
#endif

struct PathTestContext {
    CxPlatEvent HandshakeCompleteEvent;
    CxPlatEvent ShutdownEvent;
    MsQuicConnection* Connection {nullptr};
    CxPlatEvent PeerAddrChangedEvent;
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
    CxPlatEvent AddedPathValidatedEvent;
    CxPlatEvent PathAddedEvent;
    CxPlatEvent PathRemovedEvent;
    CxPlatEvent PeerStreamChangedEvent;
#endif

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection* Conn, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        PathTestContext* Ctx = static_cast<PathTestContext*>(Context);
        Ctx->Connection = Conn;
        if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            Ctx->Connection = nullptr;
            Ctx->PeerAddrChangedEvent.Set();
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
            Ctx->AddedPathValidatedEvent.Set();
            Ctx->PathAddedEvent.Set();
            Ctx->PathRemovedEvent.Set();
            Ctx->PeerStreamChangedEvent.Set();
#endif
            Ctx->ShutdownEvent.Set();
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED) {
            MsQuicSettings Settings;
            Conn->GetSettings(&Settings);
            Settings.IsSetFlags = 0;
            Settings.SetPeerBidiStreamCount(Settings.PeerBidiStreamCount + 1);
            Conn->SetSettings(Settings);
            Ctx->PeerAddrChangedEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
        } else if (Event->Type == QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE) {
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
            Ctx->PeerStreamChangedEvent.Set();
#endif
        }
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
        else if (Event->Type == QUIC_CONNECTION_EVENT_PATH_ADDED) {
            Ctx->PathAddedEvent.Set();
        }
        else if (Event->Type == QUIC_CONNECTION_EVENT_PATH_REMOVED) {
            Ctx->PathRemovedEvent.Set();
        }
        else if (Event->Type == QUIC_CONNECTION_EVENT_PATH_VALIDATED) {
            QuicAddr LocalAddr, RemoteAddr;
            Conn->GetLocalAddr(LocalAddr);
            Conn->GetRemoteAddr(RemoteAddr);
            if (!QuicAddrCompare(&LocalAddr.SockAddr, Event->PATH_VALIDATED.LocalAddress) ||
                !QuicAddrCompare(&RemoteAddr.SockAddr, Event->PATH_VALIDATED.RemoteAddress)) {
                Ctx->AddedPathValidatedEvent.Set();
            }
        }
#endif
        return QUIC_STATUS_SUCCESS;
    }
};

struct PathTestClientContext {
    CxPlatEvent HandshakeCompleteEvent;
    CxPlatEvent ShutdownEvent;
    MsQuicConnection* Connection {nullptr};
    CxPlatEvent StreamCountEvent;
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
    CxPlatEvent PathAddedEvent;
    CxPlatEvent PathRemovedEvent;
    CxPlatEvent PeerStreamChangedEvent;
#endif

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection* Conn, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        PathTestClientContext* Ctx = static_cast<PathTestClientContext*>(Context);
        Ctx->Connection = Conn;
        if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            Ctx->Connection = nullptr;
            Ctx->StreamCountEvent.Set();
            Ctx->ShutdownEvent.Set();
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
        } else if (Event->Type == QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE) {
            Ctx->StreamCountEvent.Set();
        }
        return QUIC_STATUS_SUCCESS;
    }

#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
    static QUIC_STATUS ClientCallback(_In_ MsQuicConnection* Conn, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        PathTestClientContext* Ctx = static_cast<PathTestClientContext*>(Context);
        Ctx->Connection = Conn;
        if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            Ctx->Connection = nullptr;
            Ctx->PathAddedEvent.Set();
            Ctx->PathRemovedEvent.Set();
            Ctx->PeerStreamChangedEvent.Set();
            Ctx->StreamCountEvent.Set();
            Ctx->ShutdownEvent.Set();
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PATH_ADDED) {
            Ctx->PathAddedEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PATH_REMOVED) {
            Ctx->PathRemovedEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
        } else if (Event->Type == QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE) {
            Ctx->PeerStreamChangedEvent.Set();
        }
        return QUIC_STATUS_SUCCESS;
    }
#endif
};

static
QUIC_STATUS
QUIC_API
ClientCallback(
    _In_ MsQuicConnection* /* Connection */,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) noexcept
{
    if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
        MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
    } else if (Event->Type == QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE) {
        CxPlatEvent* StreamCountEvent = static_cast<CxPlatEvent*>(Context);
        StreamCountEvent->Set();
    }
    return QUIC_STATUS_SUCCESS;
}

void
QuicTestLocalPathChanges(
    const FamilyArgs& Params
    )
{
    const int Family = Params.Family;
    PathTestContext Context;
    CxPlatEvent PeerStreamsChanged;
    MsQuicRegistration Registration{true};
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    MsQuicSettings Settings;
    Settings.SetMinimumMtu(1280).SetMaximumMtu(1280);

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", Settings, MsQuicCredentialConfig{});
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, CleanUpManual, ClientCallback, &PeerStreamsChanged);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);
    TEST_TRUE(Context.Connection->HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));

    QuicAddr OrigLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(OrigLocalAddr));
    ReplaceAddressHelper AddrHelper(OrigLocalAddr.SockAddr, OrigLocalAddr.SockAddr);

    uint16_t ServerPort = ServerLocalAddr.GetPort();
    for (int i = 0; i < 50; i++) {
        uint16_t NextPort = QuicAddrGetPort(&AddrHelper.New) + 1;
        if (NextPort == ServerPort) {
            // Skip the port if it is same as that of server
            // This is to avoid Loopback test failure
            NextPort++;
        }
        QuicAddrSetPort(&AddrHelper.New, NextPort);
        Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(25));

        TEST_TRUE(Context.PeerAddrChangedEvent.WaitTimeout(1500));
        Context.PeerAddrChangedEvent.Reset();
        QuicAddr ServerRemoteAddr;
        TEST_QUIC_SUCCEEDED(Context.Connection->GetRemoteAddr(ServerRemoteAddr));
        TEST_TRUE(QuicAddrCompare(&AddrHelper.New, &ServerRemoteAddr.SockAddr));
        Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(0));
        TEST_TRUE(PeerStreamsChanged.WaitTimeout(1500));
        PeerStreamsChanged.Reset();
    }
}

#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
static
QUIC_STATUS
QUIC_API
ClientCallback2(
    _In_ MsQuicConnection* Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) noexcept
{
    if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
        MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
    } else if (Event->Type == QUIC_CONNECTION_EVENT_PATH_VALIDATED) {
        CxPlatEvent* AddedPathValidatedEvent = static_cast<CxPlatEvent*>(Context);
        QuicAddr LocalAddr, RemoteAddr;
        Connection->GetLocalAddr(LocalAddr);
        Connection->GetRemoteAddr(RemoteAddr);
        if (!QuicAddrCompare(&LocalAddr.SockAddr, Event->PATH_VALIDATED.LocalAddress) ||
            !QuicAddrCompare(&RemoteAddr.SockAddr, Event->PATH_VALIDATED.RemoteAddress)) {
            AddedPathValidatedEvent->Set();
        }
    }
    return QUIC_STATUS_SUCCESS;
}

void
QuicTestProbePath(
    _In_ int Family,
    _In_ BOOLEAN ShareBinding,
    _In_ BOOLEAN DeferConnIDGen,
    _In_ uint32_t DropPacketCount
    )
{
    PathTestContext Context;
    CxPlatEvent PeerStreamsChanged;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    if (DeferConnIDGen) {
        BOOLEAN DisableConnIdGeneration = TRUE;
        TEST_QUIC_SUCCEEDED(
            ServerConfiguration.SetParam(
                QUIC_PARAM_CONFIGURATION_CONN_ID_GENERATION_DISABLED,
                sizeof(DisableConnIdGeneration),
                &DisableConnIdGeneration));
    }

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, CleanUpManual, ClientCallback, &PeerStreamsChanged);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    if (ShareBinding) {
        Connection.SetShareUdpBinding();
    }

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    //
    // Wait for handshake confirmation.
    //
    CxPlatSleep(100);

    QuicAddr SecondLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondLocalAddr));
    SecondLocalAddr.SetEphemeralPort();
    QuicAddr RemoteAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(RemoteAddr));
    QUIC_PATH_PARAM PathParam = { &SecondLocalAddr.SockAddr, &RemoteAddr.SockAddr };
    PathProbeHelper *ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), DropPacketCount, DropPacketCount);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t Try = 0;
    do {
        Status = Connection.SetParam(
            QUIC_PARAM_CONN_ADD_PATH,
            sizeof(PathParam),
            &PathParam);

        if (QUIC_FAILED(Status)) {
            delete ProbeHelper;
            SecondLocalAddr.SetEphemeralPort();
            ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), DropPacketCount, DropPacketCount);
        }
    } while (QUIC_FAILED(Status) && ++Try <= 3);
    TEST_EQUAL(Status, QUIC_STATUS_SUCCESS);

    if (DeferConnIDGen) {
        BOOLEAN ReplaceExistingCids = FALSE;
        TEST_QUIC_SUCCEEDED(Context.Connection->SetParam(QUIC_PARAM_CONN_GENERATE_CONN_ID, sizeof(ReplaceExistingCids), &ReplaceExistingCids));
    }
    
    TEST_TRUE(ProbeHelper->ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    TEST_TRUE(ProbeHelper->ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    delete ProbeHelper;
}

void
QuicTestProbePath_NoShareBinding(
    const ProbePathArgs& Params
    )
{
    QuicTestProbePath(Params.Family, FALSE, Params.DeferConnIDGen, Params.DropPacketCount);
}

void
QuicTestProbePath_WithShareBinding(
    const ProbePathArgs& Params
    )
{
    QuicTestProbePath(Params.Family, TRUE, Params.DeferConnIDGen, Params.DropPacketCount);
}


void
QuicTestProbePathFailed(
    _In_ int Family,
    _In_ BOOLEAN ShareBinding
    )
{
    PathTestContext Context;
    CxPlatEvent PeerStreamsChanged;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, CleanUpManual, ClientCallback, &PeerStreamsChanged);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    if (ShareBinding) {
        Connection.SetShareUdpBinding();
    }

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    //
    // Wait for handshake confirmation.
    //
    CxPlatSleep(100);

    QuicAddr SecondLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondLocalAddr));
    SecondLocalAddr.SetEphemeralPort();
    QuicAddr RemoteAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(RemoteAddr));
    QUIC_PATH_PARAM PathParam = { &SecondLocalAddr.SockAddr, &RemoteAddr.SockAddr };
    PathProbeHelper *ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), 255, 255);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t Try = 0;
    do {
        Status = Connection.SetParam(
            QUIC_PARAM_CONN_ADD_PATH,
            sizeof(PathParam),
            &PathParam);

        if (QUIC_FAILED(Status)) {
            delete ProbeHelper;
            SecondLocalAddr.SetEphemeralPort();
            ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), 255, 255);
        }
    } while (QUIC_FAILED(Status) && ++Try <= 3);
    TEST_EQUAL(Status, QUIC_STATUS_SUCCESS);

    CxPlatSleep(5000);

    delete ProbeHelper;
}

void
QuicTestProbePathFailed_NoShareBinding(
    const FamilyArgs& Params
    )
{
    QuicTestProbePathFailed(Params.Family, FALSE);
}

void
QuicTestProbePathFailed_WithShareBinding(
    const FamilyArgs& Params
    )
{
    QuicTestProbePathFailed(Params.Family, TRUE);
}

void
QuicTestAddPathBeforeStart(
    _In_ int Family,
    _In_ BOOLEAN ShareBinding,
    _In_ BOOLEAN DeferConnIDGen
    )
{
    PathTestContext Context;
    CxPlatEvent AddedPathValidatedEvent;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    //
    // Both sides wait on QUIC_CONNECTION_EVENT_PATH_VALIDATED below, which is
    // only indicated when the application asks for it.
    //
    MsQuicSettings Settings;
    Settings.SetPathValidatedEventEnabled(true);

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    if (DeferConnIDGen) {
        BOOLEAN DisableConnIdGeneration = TRUE;
        TEST_QUIC_SUCCEEDED(
            ServerConfiguration.SetParam(
                QUIC_PARAM_CONFIGURATION_CONN_ID_GENERATION_DISABLED,
                sizeof(DisableConnIdGeneration),
                &DisableConnIdGeneration));
    }

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    QuicAddr RemoteAddr(QuicAddrFamily);
    if (UseDuoNic) {
        QuicAddrSetToDuoNic(&RemoteAddr.SockAddr);
        RemoteAddr.SetPort(ServerLocalAddr.GetPort());
    } else {
        if (Family == 4) {
            QuicAddrFromString("127.0.0.1", ServerLocalAddr.GetPort(), &RemoteAddr.SockAddr);
        } else {
            QuicAddrFromString("::1", ServerLocalAddr.GetPort(), &RemoteAddr.SockAddr);
        }
    }

    MsQuicConnection* Connection = nullptr;
    QuicAddr FirstLocalAddr(QuicAddrFamily), SecondLocalAddr(QuicAddrFamily);
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t Try = 0;
    do {
        Connection = new(std::nothrow) MsQuicConnection(Registration, CleanUpManual, ClientCallback2, &AddedPathValidatedEvent);
        TEST_QUIC_SUCCEEDED(Connection->GetInitStatus());

        if (ShareBinding) {
            Connection->SetShareUdpBinding();
        }

        FirstLocalAddr.SetEphemeralPort();
        TEST_QUIC_SUCCEEDED(Connection->SetParam(
            QUIC_PARAM_CONN_LOCAL_ADDRESS,
            sizeof(FirstLocalAddr.SockAddr),
            &FirstLocalAddr.SockAddr));
        QUIC_PATH_PARAM PathParam = { &SecondLocalAddr.SockAddr, &RemoteAddr.SockAddr };
        
        TEST_QUIC_SUCCEEDED(Connection->SetParam(
            QUIC_PARAM_CONN_ADD_PATH,
            sizeof(PathParam),
            &PathParam));

        TEST_QUIC_SUCCEEDED(Connection->Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
        TEST_TRUE(Connection->HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
        if (Connection->TransportShutdownStatus == 0) {
            break;
        }
        Status = Connection->TransportShutdownStatus;
        delete Connection;
    } while (QUIC_FAILED(Status) && ++Try < 3);

    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    if (DeferConnIDGen) {
        BOOLEAN ReplaceExistingCids = FALSE;
        TEST_QUIC_SUCCEEDED(Context.Connection->SetParam(QUIC_PARAM_CONN_GENERATE_CONN_ID, sizeof(ReplaceExistingCids), &ReplaceExistingCids));
    }

    TEST_TRUE(AddedPathValidatedEvent.WaitTimeout(TestWaitTimeout * 20));
    TEST_TRUE(Context.AddedPathValidatedEvent.WaitTimeout(TestWaitTimeout * 20));

    delete Connection;
}

void
QuicTestAddPathBeforeStart_NoShareBinding(
    const AddPathBeforeStartArgs& Params
    )
{
    QuicTestAddPathBeforeStart(Params.Family, FALSE, Params.DeferConnIDGen);
}

void
QuicTestAddPathBeforeStart_WithShareBinding(
    const AddPathBeforeStartArgs& Params
    )
{
    QuicTestAddPathBeforeStart(Params.Family, TRUE, Params.DeferConnIDGen);
}

void
QuicTestMigration(
    _In_ int Family,
    _In_ BOOLEAN ShareBinding,
    _In_ QUIC_MIGRATION_ADDRESS_TYPE AddressType,
    _In_ QUIC_MIGRATION_TYPE Type
    )
{
    PathTestContext Context;
    CxPlatEvent PeerStreamsChanged;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, MsQuicCleanUpMode::CleanUpManual, ClientCallback, &PeerStreamsChanged);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    if (ShareBinding) {
        Connection.SetShareUdpBinding();
    }

    Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(25));
    MsQuicSettings Settings;
    Connection.GetSettings(&Settings);

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    //
    // Wait for handshake confirmation.
    //
    CxPlatSleep(100);

    QuicAddr SecondAddr;
    QuicAddr PairAddr;
    QUIC_PATH_PARAM PathParam = { 0 };
    if (AddressType == NewLocalAddress) {
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondAddr));
        SecondAddr.SetEphemeralPort();
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(PairAddr));
    } else if (AddressType == NewRemoteAddress) {
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(SecondAddr));
        SecondAddr.SetEphemeralPort();
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(PairAddr));
    } else {
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(SecondAddr));
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(PairAddr));
        PairAddr.SetEphemeralPort();
    }

    if (Type == MigrateWithProbe || Type == DeleteAndMigrate) {
        QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
        PathProbeHelper* ProbeHelper = new(std::nothrow) PathProbeHelper(SecondAddr.GetPort(), 0, 0, AddressType == NewRemoteAddress);
        int Try = 0;

        do {
            if (AddressType == NewLocalAddress) {
                PathParam = { &SecondAddr.SockAddr, &PairAddr.SockAddr };
                Status = Connection.SetParam(
                    QUIC_PARAM_CONN_ADD_PATH,
                    sizeof(PathParam),
                    &PathParam);
            } else {
                Status = Context.Connection->SetParam(
                    QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                    sizeof(SecondAddr.SockAddr),
                    &SecondAddr.SockAddr);
            }
            if (QUIC_FAILED(Status)) {
                delete ProbeHelper;
                SecondAddr.SetEphemeralPort();
                ProbeHelper = new(std::nothrow) PathProbeHelper(SecondAddr.GetPort(), 0, 0, AddressType == NewRemoteAddress);
            }
        } while (QUIC_FAILED(Status) && ++Try <= 3);
        TEST_QUIC_SUCCEEDED(Status);

        if (AddressType == NewRemoteAddress) {
            PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            Status = Connection.SetParam(
                QUIC_PARAM_CONN_ADD_PATH,
                sizeof(PathParam),
                &PathParam);
            if (ShareBinding) {
#if defined(_WIN32)
                if (!Settings.QTIPEnabled) {
                    TEST_TRUE(QUIC_FAILED(Status));
                    delete ProbeHelper;
                    return;
                } else {
                    TEST_QUIC_SUCCEEDED(Status);
                }
#else
                TEST_QUIC_SUCCEEDED(Status);
#endif
            } else {
                if (!Settings.QTIPEnabled) {
                    TEST_TRUE(QUIC_FAILED(Status));
                    delete ProbeHelper;
                    return;
                } else {
                    TEST_QUIC_SUCCEEDED(Status);
                }
            }
        } else if (AddressType == NewBothAddresses) {
            PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            Try = 0;
            do {
                Status = Connection.SetParam(
                    QUIC_PARAM_CONN_ADD_PATH,
                    sizeof(PathParam),
                    &PathParam);
                if (QUIC_FAILED(Status)) {
                    PairAddr.SetEphemeralPort();
                }
            } while (QUIC_FAILED(Status) && ++Try <= 3);
        }

        TEST_TRUE(ProbeHelper->ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
        TEST_TRUE(ProbeHelper->ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
        delete ProbeHelper;

        if (Type == MigrateWithProbe) {
            TEST_QUIC_SUCCEEDED(
                Connection.SetParam(
                    QUIC_PARAM_CONN_ACTIVATE_PATH,
                    sizeof(PathParam),
                    &PathParam));
        } else {
            QuicAddr FirstServerLocalAddr, FirstClientLocalAddr;
            TEST_QUIC_SUCCEEDED(Context.Connection->GetLocalAddr(FirstServerLocalAddr));
            TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(FirstClientLocalAddr));
            PathParam = { &FirstClientLocalAddr.SockAddr, &FirstServerLocalAddr.SockAddr };
            TEST_QUIC_SUCCEEDED(
                Connection.SetParam(
                    QUIC_PARAM_CONN_REMOVE_PATH,
                    sizeof(PathParam),
                    &PathParam));
        }
    } else {

        QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
        int Try = 0;
        do {
            if (AddressType == NewLocalAddress) {
                PathParam = { &SecondAddr.SockAddr, &PairAddr.SockAddr };
                Status = Connection.SetParam(
                    QUIC_PARAM_CONN_ACTIVATE_PATH,
                    sizeof(PathParam),
                    &PathParam);
            } else {
                Status = Context.Connection->SetParam(
                    QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                    sizeof(SecondAddr.SockAddr),
                    &SecondAddr.SockAddr);
            }
            if (QUIC_FAILED(Status)) {
                SecondAddr.SetEphemeralPort();
            }
        } while (QUIC_FAILED(Status) && ++Try <= 3);
        TEST_QUIC_SUCCEEDED(Status);
        if (AddressType == NewRemoteAddress) {
            PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            Status = Connection.SetParam(
                QUIC_PARAM_CONN_ACTIVATE_PATH,
                sizeof(PathParam),
                &PathParam);
            if (ShareBinding) {
#if defined(_WIN32)
                if (!Settings.QTIPEnabled) {
                    TEST_TRUE(QUIC_FAILED(Status));
                    return;
                }
                else {
                    TEST_QUIC_SUCCEEDED(Status);
                }
#else
                TEST_QUIC_SUCCEEDED(Status);
#endif
            } else {
                if (!Settings.QTIPEnabled) {
                    TEST_TRUE(QUIC_FAILED(Status));
                    return;
                }
                else {
                    TEST_QUIC_SUCCEEDED(Status);
                }
            }
        } else if (AddressType == NewBothAddresses) {
            PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            Try = 0;
            do {
                Status = Connection.SetParam(
                    QUIC_PARAM_CONN_ACTIVATE_PATH,
                    sizeof(PathParam),
                    &PathParam);
                if (QUIC_FAILED(Status)) {
                    PairAddr.SetEphemeralPort();
                }
            } while (QUIC_FAILED(Status) && ++Try <= 3);
        }
    }

    TEST_TRUE(Context.PeerAddrChangedEvent.WaitTimeout(1500));
    QuicAddr ServerNewRemoteAddr, ServerNewLocalAddr;
    TEST_QUIC_SUCCEEDED(Context.Connection->GetRemoteAddr(ServerNewRemoteAddr));
    TEST_QUIC_SUCCEEDED(Context.Connection->GetLocalAddr(ServerNewLocalAddr));
    if (AddressType == NewLocalAddress) {
        TEST_TRUE(QuicAddrCompare(&SecondAddr.SockAddr, &ServerNewRemoteAddr.SockAddr));
    } else if (AddressType == NewRemoteAddress) {
        TEST_TRUE(QuicAddrCompare(&SecondAddr.SockAddr, &ServerNewLocalAddr.SockAddr));
    } else {
        TEST_TRUE(QuicAddrCompare(&SecondAddr.SockAddr, &ServerNewLocalAddr.SockAddr));
        TEST_TRUE(QuicAddrCompare(&PairAddr.SockAddr, &ServerNewRemoteAddr.SockAddr));
    }
    Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(0));
#if defined(_WIN32)
    if (Type != MigrateWithProbe && AddressType == NewRemoteAddress && Settings.QTIPEnabled) {
        TEST_FALSE(PeerStreamsChanged.WaitTimeout(1500));
    } else
#endif
    {
        TEST_TRUE(PeerStreamsChanged.WaitTimeout(1500));
    }
}

void
QuicTestMigration_NoShareBinding(
    const MigrationArgs& Params
    )
{
    QuicTestMigration(Params.Family, FALSE, Params.AddressType, Params.Type);
}

void
QuicTestMigration_WithShareBinding(
    const MigrationArgs& Params
    )
{
    QuicTestMigration(Params.Family, TRUE, Params.AddressType, Params.Type);
}

struct AddressDiscoveryTestContext {
    CxPlatEvent HandshakeCompleteEvent;
    CxPlatEvent ShutdownEvent;
    MsQuicConnection* Connection {nullptr};
    CxPlatEvent ObservedAddrEvent;
    QuicAddr ObservedAddress;

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection* Conn, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        AddressDiscoveryTestContext* Ctx = static_cast<AddressDiscoveryTestContext*>(Context);
        Ctx->Connection = Conn;
        if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            Ctx->Connection = nullptr;
            Ctx->ObservedAddrEvent.Set();
            Ctx->ShutdownEvent.Set();
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_NOTIFY_OBSERVED_ADDRESS) {
            Ctx->ObservedAddress.SockAddr = *Event->NOTIFY_OBSERVED_ADDRESS.ObservedAddress;
            Ctx->ObservedAddrEvent.Set();
        }
        return QUIC_STATUS_SUCCESS;
    }
};

void
QuicTestAddressDiscovery(
    const FamilyArgs& Params
    )
{
    AddressDiscoveryTestContext ServerContext;
    AddressDiscoveryTestContext* ClientContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    //
    // Address discovery is opt-in, and this test expects both sides to report
    // the peer's observed address, so enable both directions on both ends.
    //
    MsQuicSettings Settings;
    Settings.SetSendObservedAddressReports(TRUE).SetReceiveObservedAddressReports(TRUE);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, AddressDiscoveryTestContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Params.Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    QuicAddr ClientLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    QuicAddr ServerObservedAddr(QuicAddrFamily);
    QuicAddr ClientObservedAddr(QuicAddrFamily);
    if (UseDuoNic) {
        QuicAddrSetToDuoNic(&ServerObservedAddr.SockAddr);
        ServerObservedAddr.SetPort(ServerLocalAddr.GetPort());
        QuicAddrSetToDuoNicClient(&ClientLocalAddr.SockAddr);
    } else {
        if (Params.Family == 4) {
            QuicAddrFromString("127.0.0.1", ServerLocalAddr.GetPort(), &ServerObservedAddr.SockAddr);
            QuicAddrFromString("127.0.0.1", 0, &ClientLocalAddr.SockAddr);
        } else {
            QuicAddrFromString("::1", ServerLocalAddr.GetPort(), &ServerObservedAddr.SockAddr);
            QuicAddrFromString("::1", 0, &ClientLocalAddr.SockAddr);
        }
    }

    MsQuicConnection* Connection = nullptr;
    ReplaceAddressHelper* ReplaceHelper = nullptr;
    uint32_t Try = 0;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    do {
        ClientContext = new(std::nothrow) AddressDiscoveryTestContext();
        Connection = new(std::nothrow) MsQuicConnection(Registration, CleanUpManual, AddressDiscoveryTestContext::ConnCallback, ClientContext);
        TEST_QUIC_SUCCEEDED(Connection->GetInitStatus());

        ClientLocalAddr.SetEphemeralPort();
        TEST_QUIC_SUCCEEDED(Connection->SetParam(
            QUIC_PARAM_CONN_LOCAL_ADDRESS,
            sizeof(ClientLocalAddr.SockAddr),
            &ClientLocalAddr.SockAddr));
        ClientObservedAddr = ClientLocalAddr;
        ClientObservedAddr.IncrementPort();

        ReplaceHelper = new(std::nothrow) ReplaceAddressHelper(ClientLocalAddr.SockAddr, ClientObservedAddr.SockAddr);

        TEST_QUIC_SUCCEEDED(Connection->Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
        TEST_TRUE(Connection->HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
        if (Connection->TransportShutdownStatus == 0) {
            break;
        }
        Status = Connection->TransportShutdownStatus;
        delete ReplaceHelper;
        delete Connection;
        delete ClientContext;            
    } while (QUIC_FAILED(Status) && ++Try < 3);

    TEST_TRUE(ServerContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, ClientContext->Connection);
    TEST_NOT_EQUAL(nullptr, ServerContext.Connection);
    TEST_TRUE(ClientContext->ObservedAddrEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(QuicAddrCompare(&ClientObservedAddr.SockAddr, &ClientContext->ObservedAddress.SockAddr));
    TEST_TRUE(ServerContext.ObservedAddrEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(QuicAddrCompare(&ServerObservedAddr.SockAddr, &ServerContext.ObservedAddress.SockAddr));
    Connection->Shutdown(QUIC_TEST_NO_ERROR);
    TEST_TRUE(ClientContext->ShutdownEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.ShutdownEvent.WaitTimeout(TestWaitTimeout));
    delete ReplaceHelper;
    delete Connection;
    delete ClientContext;
}

void
QuicTestServerProbePath(
    const ProbePathArgs& Params
    )
{
    PathTestContext ClientContext;
    PathTestClientContext ServerContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicSettings Settings;
    Settings.SetServerMigrationEnabled(TRUE);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    if (Params.DeferConnIDGen) {
        BOOLEAN DisableConnIdGeneration = TRUE;
        TEST_QUIC_SUCCEEDED(
            ClientConfiguration.SetParam(
                QUIC_PARAM_CONFIGURATION_CONN_ID_GENERATION_DISABLED,
                sizeof(DisableConnIdGeneration),
                &DisableConnIdGeneration));
    }

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestClientContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Params.Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, CleanUpManual, PathTestContext::ConnCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    Connection.SetShareUdpBinding();

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, ServerContext.Connection);

    //
    // Wait for handshake confirmation.
    //
    CxPlatSleep(100);

    QuicAddr SecondLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(SecondLocalAddr));
    SecondLocalAddr.SetEphemeralPort();
    QuicAddr SecondRemoteAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondRemoteAddr));
    SecondRemoteAddr.SetEphemeralPort();
    PathProbeHelper *ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), Params.DropPacketCount, Params.DropPacketCount);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t Try = 0;
    do {
        Status = Connection.SetParam(
            QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
            sizeof(SecondRemoteAddr.SockAddr),
            &SecondRemoteAddr.SockAddr);

        if (QUIC_FAILED(Status)) {
            SecondRemoteAddr.SetEphemeralPort();
        }
    } while (QUIC_FAILED(Status) && ++Try <= 3);
    TEST_EQUAL(Status, QUIC_STATUS_SUCCESS);

    Try = 0;
    do {
        QUIC_PATH_PARAM PathParam = { &SecondLocalAddr.SockAddr, &SecondRemoteAddr.SockAddr };
        Status = ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_ADD_PATH,
            sizeof(PathParam),
            &PathParam);

        if (QUIC_FAILED(Status)) {
            delete ProbeHelper;
            SecondLocalAddr.SetEphemeralPort();
            ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), Params.DropPacketCount, Params.DropPacketCount);
        }
    } while (QUIC_FAILED(Status) && ++Try <= 3);
    TEST_EQUAL(Status, QUIC_STATUS_SUCCESS);

    if (Params.DeferConnIDGen) {
        BOOLEAN ReplaceExistingCids = FALSE;
        TEST_QUIC_SUCCEEDED(Connection.SetParam(QUIC_PARAM_CONN_GENERATE_CONN_ID, sizeof(ReplaceExistingCids), &ReplaceExistingCids));
    }
    
    TEST_TRUE(ProbeHelper->ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    TEST_TRUE(ProbeHelper->ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    delete ProbeHelper;
}

void
QuicTestServerMigration(
    const MigrationArgs& Params
    )
{
    PathTestContext ClientContext;
    PathTestClientContext ServerContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicSettings Settings;
    Settings.SetServerMigrationEnabled(TRUE);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestClientContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Params.Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, MsQuicCleanUpMode::CleanUpManual, PathTestContext::ConnCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    Connection.SetShareUdpBinding();

    Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(25));

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, ServerContext.Connection);

    //
    // Wait for handshake confirmation.
    //
    CxPlatSleep(100);

    QuicAddr SecondAddr;
    QuicAddr PairAddr;
    QUIC_PATH_PARAM PathParam = { 0 };
    if (Params.AddressType == NewLocalAddress) {
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(SecondAddr));
        SecondAddr.SetEphemeralPort();
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(PairAddr));
    } else if (Params.AddressType == NewRemoteAddress) {
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondAddr));
        SecondAddr.SetEphemeralPort();
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(PairAddr));
    } else {
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondAddr));
        SecondAddr.SetEphemeralPort();
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(PairAddr));
        PairAddr.SetEphemeralPort();
    }

    if (Params.Type == MigrateWithProbe || Params.Type == DeleteAndMigrate) {
        QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
        PathProbeHelper* ProbeHelper = new(std::nothrow) PathProbeHelper(SecondAddr.GetPort(), 0, 0, Params.AddressType == NewRemoteAddress);
        int Try = 0;

        if (Params.AddressType == NewLocalAddress) {
            Status = Connection.SetParam(
                QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                sizeof(PairAddr.SockAddr),
                &PairAddr.SockAddr);
#if defined(_WIN32)
            TEST_TRUE(QUIC_FAILED(Status));
            delete ProbeHelper;
            return;
#endif
        } else {
            do {
                Status = Connection.SetParam(
                    QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                    sizeof(SecondAddr.SockAddr),
                    &SecondAddr.SockAddr);
                if (QUIC_FAILED(Status)) {
                    delete ProbeHelper;
                    SecondAddr.SetEphemeralPort();
                    ProbeHelper = new(std::nothrow) PathProbeHelper(SecondAddr.GetPort(), 0, 0, Params.AddressType == NewRemoteAddress);
                }
            } while (QUIC_FAILED(Status) && ++Try <= 3);
        }
        TEST_QUIC_SUCCEEDED(Status);
        if (Params.AddressType == NewRemoteAddress) {
            PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            Status = ServerContext.Connection->SetParam(
                QUIC_PARAM_CONN_ADD_PATH,
                sizeof(PathParam),
                &PathParam);
            TEST_TRUE(QUIC_FAILED(Status));
            delete ProbeHelper;
            return;
        } else {
            if (Params.AddressType == NewLocalAddress) {
                PathParam = { &SecondAddr.SockAddr, &PairAddr.SockAddr };
            } else {
                PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            }
            Try = 0;
            do {
                Status = ServerContext.Connection->SetParam(
                    QUIC_PARAM_CONN_ADD_PATH,
                    sizeof(PathParam),
                    &PathParam);
                if (QUIC_FAILED(Status)) {
                    PairAddr.SetEphemeralPort();
                }
            } while (QUIC_FAILED(Status) && ++Try <= 3);
        }

        TEST_TRUE(ProbeHelper->ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
        TEST_TRUE(ProbeHelper->ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
        delete ProbeHelper;

        if (Params.Type == MigrateWithProbe) {
            TEST_QUIC_SUCCEEDED(
                ServerContext.Connection->SetParam(
                    QUIC_PARAM_CONN_ACTIVATE_PATH,
                    sizeof(PathParam),
                    &PathParam));
        } else {
            QuicAddr FirstServerLocalAddr, FirstClientLocalAddr;
            TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(FirstServerLocalAddr));
            TEST_QUIC_SUCCEEDED(ServerContext.Connection->GetLocalAddr(FirstClientLocalAddr));
            PathParam = { &FirstClientLocalAddr.SockAddr, &FirstServerLocalAddr.SockAddr };
            TEST_QUIC_SUCCEEDED(
                ServerContext.Connection->SetParam(
                    QUIC_PARAM_CONN_REMOVE_PATH,
                    sizeof(PathParam),
                    &PathParam));
        }
    } else {
        QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
        int Try = 0;
        if (Params.AddressType == NewLocalAddress) {
            Status = Connection.SetParam(
                QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                sizeof(PairAddr.SockAddr),
                &PairAddr.SockAddr);
#if defined(_WIN32)
            TEST_TRUE(QUIC_FAILED(Status));
            return;
#endif
        } else {
            do {
                Status = Connection.SetParam(
                    QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                    sizeof(SecondAddr.SockAddr),
                    &SecondAddr.SockAddr);
                if (QUIC_FAILED(Status)) {
                    SecondAddr.SetEphemeralPort();
                }
            } while (QUIC_FAILED(Status) && ++Try <= 3);
        }
        TEST_QUIC_SUCCEEDED(Status);
        if (Params.AddressType == NewRemoteAddress) {
            PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            Status = ServerContext.Connection->SetParam(
                QUIC_PARAM_CONN_ACTIVATE_PATH,
                sizeof(PathParam),
                &PathParam);
            TEST_TRUE(QUIC_FAILED(Status));
            return;
        } else {
            if (Params.AddressType == NewLocalAddress) {
                PathParam = { &SecondAddr.SockAddr, &PairAddr.SockAddr };
            } else {
                PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            }
            Try = 0;
            do {
                Status = ServerContext.Connection->SetParam(
                    QUIC_PARAM_CONN_ACTIVATE_PATH,
                    sizeof(PathParam),
                    &PathParam);
                if (QUIC_FAILED(Status)) {
                    PairAddr.SetEphemeralPort();
                }
            } while (QUIC_FAILED(Status) && ++Try <= 3);
        }
    }

    TEST_TRUE(ClientContext.PeerAddrChangedEvent.WaitTimeout(1500));
    QuicAddr ServerNewRemoteAddr, ServerNewLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(ServerNewRemoteAddr));
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(ServerNewLocalAddr));
    if (Params.AddressType == NewLocalAddress) {
        TEST_TRUE(QuicAddrCompare(&SecondAddr.SockAddr, &ServerNewRemoteAddr.SockAddr));
    } else { // Params.AddressType == NewBothAddresses
        TEST_TRUE(QuicAddrCompare(&SecondAddr.SockAddr, &ServerNewLocalAddr.SockAddr));
        TEST_TRUE(QuicAddrCompare(&PairAddr.SockAddr, &ServerNewRemoteAddr.SockAddr));
    }
    Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(0));
    TEST_TRUE(ServerContext.StreamCountEvent.WaitTimeout(1500));
}


void
QuicTestMultipath(
    _In_ const FamilyArgs& Params
    )
{
    const int Family = Params.Family;
    PathTestContext Context;
    PathTestClientContext ClientContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration,
        "MsQuicTest",
        MsQuicSettings{}.SetMultipathEnabled(TRUE),
        ServerSelfSignedCredConfig);

    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration,
        "MsQuicTest",
        MsQuicSettings{}.SetMultipathEnabled(TRUE),
        ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, MsQuicCleanUpMode::CleanUpManual, PathTestClientContext::ClientCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    Connection.SetShareUdpBinding();
    
    Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(25));

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    QuicAddr FirstLocalAddr, SecondLocalAddr, PairAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(FirstLocalAddr));
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondLocalAddr));
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(PairAddr));
    SecondLocalAddr.SetEphemeralPort();

    PathProbeHelper* ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort());

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    QUIC_PATH_PARAM PathParam = { &SecondLocalAddr.SockAddr, &PairAddr.SockAddr };
    int Try = 0;
    do {
        Status = Connection.SetParam(
            QUIC_PARAM_CONN_ADD_PATH,
            sizeof(PathParam),
            &PathParam);
        if (QUIC_FAILED(Status)) {
            delete ProbeHelper;
            SecondLocalAddr.SetEphemeralPort();
            ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort());
        }
    } while (QUIC_FAILED(Status) && ++Try <= 3);

    TEST_QUIC_SUCCEEDED(Status);

    TEST_TRUE(ProbeHelper->ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ProbeHelper->ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
    delete ProbeHelper;

    QUIC_STATISTICS_V2 Stats;
    uint32_t Size = sizeof(Stats);
    TEST_QUIC_SUCCEEDED(
        Connection.GetParam(
            QUIC_PARAM_CONN_STATISTICS_V2_PLAT,
            &Size,
            &Stats));
    TEST_EQUAL(Stats.RecvDroppedPackets, 0);

    TEST_TRUE(Context.PathAddedEvent.WaitTimeout(1500));
    TEST_TRUE(ClientContext.PathAddedEvent.WaitTimeout(1500));
    
    PathParam = { &FirstLocalAddr.SockAddr, &PairAddr.SockAddr };
    TEST_QUIC_SUCCEEDED(
        Connection.SetParam(
            QUIC_PARAM_CONN_REMOVE_PATH,
            sizeof(PathParam),
            &PathParam));

    TEST_TRUE(Context.PathRemovedEvent.WaitTimeout(1500));
    TEST_TRUE(ClientContext.PathRemovedEvent.WaitTimeout(1500));

    MsQuicSettings Settings;
    Context.Connection->GetSettings(&Settings);
    Settings.IsSetFlags = 0;
    Settings.SetPeerBidiStreamCount(Settings.PeerBidiStreamCount + 1);
    Context.Connection->SetSettings(Settings);

    TEST_TRUE(ClientContext.PeerStreamChangedEvent.WaitTimeout(1500));

    Connection.GetSettings(&Settings);
    Settings.IsSetFlags = 0;
    Settings.SetPeerBidiStreamCount(Settings.PeerBidiStreamCount + 1);
    Connection.SetSettings(Settings);

    TEST_TRUE(Context.PeerStreamChangedEvent.WaitTimeout(1500));

}

//
// Counts the datagrams the client sends on one particular local port, so a test
// can tell whether a given path is carrying anything.
//
struct PathSendCounter : public DatapathHook
{
    uint16_t PathPort;
    long Count {0};
    PathSendCounter(uint16_t Port) : PathPort(Port) {
        DatapathHooks::Instance->AddHook(this);
    }
    ~PathSendCounter() {
        DatapathHooks::Instance->RemoveHook(this);
    }
    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN
    Receive(
        _Inout_ struct CXPLAT_RECV_DATA* Datagram
        ) {
        if (QuicAddrGetPort(&Datagram->Route->RemoteAddress) == PathPort) {
            InterlockedIncrement(&Count);
        }
        return FALSE;
    }
};

void
QuicTestPathKeepAlive(
    _In_ const FamilyArgs& Params
    )
{
    const int Family = Params.Family;

    //
    // Neither side has a connection keep alive and the application sends
    // nothing, so once both paths are up the only thing that can put a packet
    // on either of them is the client's per-path keep alive.
    //
    const uint32_t PathKeepAliveMs = 100;
    const uint32_t ObserveMs = 600;

    //
    // MTU discovery would otherwise probe both paths during the window below
    // and be counted as traffic. Pinning the MTU leaves it nothing to search.
    //
    const uint16_t FixedMtu = 1280;

    PathTestContext Context;
    PathTestClientContext ClientContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration,
        "MsQuicTest",
        MsQuicSettings{}.SetMultipathEnabled(TRUE).SetMinimumMtu(FixedMtu).SetMaximumMtu(FixedMtu),
        ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration,
        "MsQuicTest",
        MsQuicSettings{}.SetMultipathEnabled(TRUE).SetMinimumMtu(FixedMtu).SetMaximumMtu(FixedMtu).SetPathKeepAlive(PathKeepAliveMs),
        ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, MsQuicCleanUpMode::CleanUpManual, PathTestClientContext::ClientCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    Connection.SetShareUdpBinding();

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    QuicAddr FirstLocalAddr, SecondLocalAddr, PairAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(FirstLocalAddr));
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondLocalAddr));
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(PairAddr));
    SecondLocalAddr.SetEphemeralPort();

    PathProbeHelper* ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort());
    TEST_NOT_EQUAL(nullptr, ProbeHelper);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_PATH_PARAM PathParam = { &SecondLocalAddr.SockAddr, &PairAddr.SockAddr };
    int Try = 0;
    do {
        Status = Connection.SetParam(
            QUIC_PARAM_CONN_ADD_PATH,
            sizeof(PathParam),
            &PathParam);
        if (QUIC_FAILED(Status)) {
            delete ProbeHelper;
            SecondLocalAddr.SetEphemeralPort();
            ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort());
        }
    } while (QUIC_FAILED(Status) && ++Try <= 3);
    TEST_QUIC_SUCCEEDED(Status);

    TEST_TRUE(ProbeHelper->ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ProbeHelper->ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
    delete ProbeHelper;

    TEST_TRUE(Context.PathAddedEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ClientContext.PathAddedEvent.WaitTimeout(TestWaitTimeout));

    //
    // Both paths are validated and the connection goes quiet from here. Every
    // datagram the server now sees is a keep alive, and each path has to get
    // its own: keeping the connection alive is not the same as keeping the
    // paths alive.
    //
    PathSendCounter FirstPathCounter(FirstLocalAddr.GetPort());
    PathSendCounter SecondPathCounter(SecondLocalAddr.GetPort());
    CxPlatSleep(ObserveMs);

    //
    // Half the expected count, to leave room for scheduling slop.
    //
    const long Expected = (long)((ObserveMs / PathKeepAliveMs) / 2);
    TEST_TRUE(FirstPathCounter.Count >= Expected);
    TEST_TRUE(SecondPathCounter.Count >= Expected);
}

void
QuicTestPathStatistics(
    _In_ const FamilyArgs& Params
    )
{
    const int Family = Params.Family;

    PathTestContext Context;
    PathTestClientContext ClientContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration,
        "MsQuicTest",
        MsQuicSettings{}.SetMultipathEnabled(TRUE),
        ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration,
        "MsQuicTest",
        MsQuicSettings{}.SetMultipathEnabled(TRUE),
        ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, MsQuicCleanUpMode::CleanUpManual, PathTestClientContext::ClientCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    Connection.SetShareUdpBinding();

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    //
    // One path so far, so a buffer sized for one is exactly what is asked for.
    //
    uint32_t Size = 0;
    TEST_EQUAL(
        QUIC_STATUS_BUFFER_TOO_SMALL,
        Connection.GetParam(QUIC_PARAM_CONN_PATH_STATISTICS, &Size, nullptr));
    TEST_EQUAL(sizeof(QUIC_PATH_STATISTICS), Size);

    QUIC_PATH_STATISTICS OnePath[QUIC_MAX_PATH_COUNT];
    Size = sizeof(OnePath);
    TEST_QUIC_SUCCEEDED(
        Connection.GetParam(QUIC_PARAM_CONN_PATH_STATISTICS, &Size, OnePath));
    TEST_EQUAL(sizeof(QUIC_PATH_STATISTICS), Size);
    TEST_TRUE(OnePath[0].Mtu > 0);

    //
    // Bring up a second path, then expect the array to grow by exactly one.
    //
    QuicAddr FirstLocalAddr, SecondLocalAddr, PairAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(FirstLocalAddr));
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondLocalAddr));
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(PairAddr));
    SecondLocalAddr.SetEphemeralPort();

    PathProbeHelper* ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort());
    TEST_NOT_EQUAL(nullptr, ProbeHelper);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_PATH_PARAM PathParam = { &SecondLocalAddr.SockAddr, &PairAddr.SockAddr };
    int Try = 0;
    do {
        Status = Connection.SetParam(QUIC_PARAM_CONN_ADD_PATH, sizeof(PathParam), &PathParam);
        if (QUIC_FAILED(Status)) {
            delete ProbeHelper;
            SecondLocalAddr.SetEphemeralPort();
            ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort());
        }
    } while (QUIC_FAILED(Status) && ++Try <= 3);
    TEST_QUIC_SUCCEEDED(Status);

    TEST_TRUE(ProbeHelper->ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ProbeHelper->ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
    delete ProbeHelper;

    TEST_TRUE(Context.PathAddedEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ClientContext.PathAddedEvent.WaitTimeout(TestWaitTimeout));

    QUIC_PATH_STATISTICS PathStats[QUIC_MAX_PATH_COUNT];
    Size = sizeof(PathStats);
    TEST_QUIC_SUCCEEDED(
        Connection.GetParam(QUIC_PARAM_CONN_PATH_STATISTICS, &Size, PathStats));
    TEST_EQUAL(2 * sizeof(QUIC_PATH_STATISTICS), Size);

    //
    // Every path reports itself, not a copy of the first one: distinct path IDs,
    // and an MTU that was actually filled in.
    //
    TEST_NOT_EQUAL(PathStats[0].PathId, PathStats[1].PathId);
    for (uint32_t i = 0; i < 2; ++i) {
        TEST_TRUE(PathStats[i].Mtu > 0);
        TEST_TRUE(PathStats[i].Rtt > 0);
        //
        // Both are zero on a path with no RTT sample yet; the sentinel MinRtt
        // carries internally must not reach the caller.
        //
        TEST_TRUE(PathStats[i].MinRtt <= PathStats[i].MaxRtt);
        TEST_TRUE(PathStats[i].NetworkStatistics.CongestionWindow > 0);
        //
        // The network statistics are read out of the path's own congestion
        // control, so this has to agree with the path's RTT above rather than
        // with whichever path came first.
        //
        TEST_EQUAL(PathStats[i].Rtt, PathStats[i].NetworkStatistics.SmoothedRTT);
    }

    //
    // A buffer one entry short is refused, and says how much is needed.
    //
    Size = sizeof(QUIC_PATH_STATISTICS);
    TEST_EQUAL(
        QUIC_STATUS_BUFFER_TOO_SMALL,
        Connection.GetParam(QUIC_PARAM_CONN_PATH_STATISTICS, &Size, PathStats));
    TEST_EQUAL(2 * sizeof(QUIC_PATH_STATISTICS), Size);
}

//
// The shared PathTestClientContext sets PathRemovedEvent on SHUTDOWN_COMPLETE
// as well, to unblock whoever is waiting. That makes it useless here: the
// behaviour under test is precisely "path removed instead of connection shut
// down", so the two must not set the same event. This context keeps them apart.
//
struct PathDeathClientContext {
    CxPlatEvent HandshakeCompleteEvent;
    CxPlatEvent PathAddedEvent;
    CxPlatEvent PathRemovedEvent;
    CxPlatEvent ShutdownEvent;
    CxPlatEvent StreamCountEvent;
    MsQuicConnection* Connection {nullptr};

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection* Conn, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        PathDeathClientContext* Ctx = static_cast<PathDeathClientContext*>(Context);
        Ctx->Connection = Conn;
        if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            Ctx->Connection = nullptr;
            Ctx->ShutdownEvent.Set();
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PATH_ADDED) {
            Ctx->PathAddedEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PATH_REMOVED) {
            Ctx->PathRemovedEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
        } else if (Event->Type == QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE) {
            Ctx->StreamCountEvent.Set();
        }
        return QUIC_STATUS_SUCCESS;
    }
};

//
// Drops every datagram to or from one local port once armed, so the path using
// it goes dead in both directions while the other path keeps working.
//
struct PathBlackholeHelper : public DatapathHook
{
    uint16_t PathPort;
    bool Armed {false};
    PathBlackholeHelper(uint16_t Port) : PathPort(Port) {
        DatapathHooks::Instance->AddHook(this);
    }
    ~PathBlackholeHelper() {
        DatapathHooks::Instance->RemoveHook(this);
    }
    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN
    Receive(
        _Inout_ struct CXPLAT_RECV_DATA* Datagram
        ) {
        return
            Armed &&
            (QuicAddrGetPort(&Datagram->Route->LocalAddress) == PathPort ||
             QuicAddrGetPort(&Datagram->Route->RemoteAddress) == PathPort);
    }
};

void
QuicTestMultipathPathDeath(
    _In_ const FamilyArgs& Params
    )
{
    const int Family = Params.Family;

    //
    // A packet has to sit unacknowledged on the dead path for this long, so it
    // is turned right down from the 16 second default: the shorter the window,
    // the less chance the path drains before the deadline passes.
    //
    const uint32_t DisconnectTimeoutMs = 200;

    PathTestContext Context;
    PathDeathClientContext ClientContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicSettings Settings;
    Settings.SetMultipathEnabled(TRUE).SetDisconnectTimeoutMs(DisconnectTimeoutMs);

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, MsQuicCleanUpMode::CleanUpManual, PathDeathClientContext::ConnCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    Connection.SetShareUdpBinding();

    //
    // Keeps both paths carrying packets, so the one that gets blackholed has
    // something outstanding for its loss detection to time out on.
    //
    Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(25));

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    QuicAddr FirstLocalAddr, SecondLocalAddr, PairAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(FirstLocalAddr));
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondLocalAddr));
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(PairAddr));
    SecondLocalAddr.SetEphemeralPort();

    PathProbeHelper* ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort());
    TEST_NOT_EQUAL(nullptr, ProbeHelper);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_PATH_PARAM PathParam = { &SecondLocalAddr.SockAddr, &PairAddr.SockAddr };
    int Try = 0;
    do {
        Status = Connection.SetParam(
            QUIC_PARAM_CONN_ADD_PATH,
            sizeof(PathParam),
            &PathParam);
        if (QUIC_FAILED(Status)) {
            delete ProbeHelper;
            SecondLocalAddr.SetEphemeralPort();
            ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort());
        }
    } while (QUIC_FAILED(Status) && ++Try <= 3);
    if (QUIC_FAILED(Status)) {
        delete ProbeHelper;
    }
    TEST_QUIC_SUCCEEDED(Status);

    TEST_TRUE(ProbeHelper->ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ProbeHelper->ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
    delete ProbeHelper;

    TEST_TRUE(Context.PathAddedEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ClientContext.PathAddedEvent.WaitTimeout(TestWaitTimeout));

    //
    // Two live paths. Kill the second one outright.
    //
    PathBlackholeHelper Blackhole(SecondLocalAddr.GetPort());
    Blackhole.Armed = true;

    //
    // The client's own loss detection gives up on the dead path and abandons
    // it, which is what PATH_REMOVED here reports. Without the change there is
    // no PATH_REMOVED at all: that code path called QuicConnCloseLocally and
    // took the whole connection down.
    //
    // Two things are deliberately not asserted, both because they depend on
    // more than the decision under test:
    //
    //  - the server seeing the path removed. It learns by receiving the
    //    client's PATH_ABANDON, which can itself be lost.
    //  - the connection still being up afterwards. With DisconnectTimeoutMs
    //    this low the surviving path can be judged dead a moment later on a
    //    loaded machine, and closing is then the right answer -- it is the last
    //    usable path.
    //
    const uint32_t PathDeathTimeout = 5000;
    TEST_TRUE(ClientContext.PathRemovedEvent.WaitTimeout(PathDeathTimeout));
}

void
QuicTestMultipathPathValidationFailed(
    _In_ const FamilyArgs& Params
    )
{
    const int Family = Params.Family;

    //
    // Path validation waits max(3 PTO, 6 x InitialRtt), so a small initial RTT
    // is what keeps this test short rather than any change in behaviour.
    //
    const uint32_t InitialRttMs = 50;

    PathTestContext Context;
    PathDeathClientContext ClientContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicSettings Settings;
    Settings.SetMultipathEnabled(TRUE).SetInitialRttMs(InitialRttMs);

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, MsQuicCleanUpMode::CleanUpManual, PathDeathClientContext::ConnCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    Connection.SetShareUdpBinding();

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    //
    // Path validation only starts once the handshake is confirmed.
    //
    CxPlatSleep(100);

    QuicAddr SecondLocalAddr, PairAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondLocalAddr));
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(PairAddr));
    SecondLocalAddr.SetEphemeralPort();

    //
    // 255 drops in each direction, so neither the PATH_CHALLENGE nor the
    // PATH_RESPONSE ever lands and validation runs out of time.
    //
    PathProbeHelper* ProbeHelper =
        new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), 255, 255);
    TEST_NOT_EQUAL(nullptr, ProbeHelper);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_PATH_PARAM PathParam = { &SecondLocalAddr.SockAddr, &PairAddr.SockAddr };
    int Try = 0;
    do {
        Status = Connection.SetParam(
            QUIC_PARAM_CONN_ADD_PATH,
            sizeof(PathParam),
            &PathParam);
        if (QUIC_FAILED(Status)) {
            delete ProbeHelper;
            SecondLocalAddr.SetEphemeralPort();
            ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), 255, 255);
        }
    } while (QUIC_FAILED(Status) && ++Try <= 3);
    if (QUIC_FAILED(Status)) {
        delete ProbeHelper;
    }
    TEST_QUIC_SUCCEEDED(Status);

    //
    // The path that never came up is abandoned, so the client indicates it
    // removed. Without that it was taken out of the path array silently: no
    // event, no PATH_ABANDON for the peer, and the path ID left in the set
    // with nothing attached to it.
    //
    TEST_TRUE(ClientContext.PathRemovedEvent.WaitTimeout(TestWaitTimeout));

    //
    // Unlike the dead-path test, nothing here is working against a shortened
    // disconnect timeout -- the original path is healthy throughout -- so the
    // connection surviving is worth asserting, and so is it still carrying
    // traffic afterwards.
    //
    TEST_FALSE(ClientContext.ShutdownEvent.WaitTimeout(100));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    MsQuicSettings UpdatedSettings;
    Context.Connection->GetSettings(&UpdatedSettings);
    UpdatedSettings.IsSetFlags = 0;
    UpdatedSettings.SetPeerBidiStreamCount(UpdatedSettings.PeerBidiStreamCount + 1);
    Context.Connection->SetSettings(UpdatedSettings);
    TEST_TRUE(ClientContext.StreamCountEvent.WaitTimeout(TestWaitTimeout));

    delete ProbeHelper;
}

void
QuicTestMultipathPathIdReclaimed(
    _In_ const FamilyArgs& Params
    )
{
    const int Family = Params.Family;
    const uint32_t InitialRttMs = 50;

    //
    // One more doomed path than there are path ID slots. Each round opens a
    // path whose probe never lands, so validation times out and both ends
    // abandon it. If a path ID is not reclaimed on either side the supply runs
    // out and QUIC_PARAM_CONN_ADD_PATH starts refusing, which is what this
    // asserts does not happen.
    //
    const uint32_t Rounds = QUIC_ACTIVE_PATH_ID_LIMIT + 1;

    PathTestContext Context;
    PathDeathClientContext ClientContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicSettings Settings;
    Settings.SetMultipathEnabled(TRUE).SetInitialRttMs(InitialRttMs);

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, MsQuicCleanUpMode::CleanUpManual, PathDeathClientContext::ConnCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    Connection.SetShareUdpBinding();

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    CxPlatSleep(100);

    QuicAddr PairAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(PairAddr));

    for (uint32_t Round = 0; Round < Rounds; ++Round) {
        QuicAddr DoomedLocalAddr;
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(DoomedLocalAddr));
        DoomedLocalAddr.SetEphemeralPort();

        PathProbeHelper* ProbeHelper =
            new(std::nothrow) PathProbeHelper(DoomedLocalAddr.GetPort(), 255, 255);
        TEST_NOT_EQUAL(nullptr, ProbeHelper);

        QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
        QUIC_PATH_PARAM PathParam = { &DoomedLocalAddr.SockAddr, &PairAddr.SockAddr };
        int Try = 0;
        do {
            Status = Connection.SetParam(
                QUIC_PARAM_CONN_ADD_PATH,
                sizeof(PathParam),
                &PathParam);
            //
            // Running out of path IDs is the failure this test is looking for,
            // so that one is never retried -- picking another port would paper
            // over exactly what is being measured. Anything else is the local
            // address not being obtainable, which is worth another port: an
            // earlier version retried only QUIC_STATUS_ADDRESS_IN_USE and hit
            // WSAEACCES on Windows, where a bind can be refused for a port in
            // an excluded or exclusive-use range.
            //
            if (Status == QUIC_STATUS_OUT_OF_MEMORY || QUIC_SUCCEEDED(Status)) {
                break;
            }
            delete ProbeHelper;
            DoomedLocalAddr.SetEphemeralPort();
            ProbeHelper = new(std::nothrow) PathProbeHelper(DoomedLocalAddr.GetPort(), 255, 255);
        } while (++Try <= 3);

        if (QUIC_FAILED(Status)) {
            delete ProbeHelper;
        }
        TEST_QUIC_SUCCEEDED(Status);

        //
        // The client's own loss of the path, which also tells us the round is
        // over and the abandon exchange has started.
        //
        TEST_TRUE(ClientContext.PathRemovedEvent.WaitTimeout(TestWaitTimeout));
        ClientContext.PathRemovedEvent.Reset();

        //
        // Both sides need their close timer, three PTO, before the path ID is
        // actually back. The doomed path never took an RTT sample, so its PTO
        // rests on InitialRttMs: 3 x (SmoothedRtt + 4 x RttVariance +
        // MaxAckDelay) is already over ten initial RTTs, and review caught an
        // earlier version of this sleeping for six and calling it comfortable.
        // Waiting too little would let QUIC_PARAM_CONN_ADD_PATH fail for want
        // of a Paths slot rather than a path ID, which is the one thing this
        // test must not confuse.
        //
        CxPlatSleep(20 * InitialRttMs);

        delete ProbeHelper;
    }
}

//
// The connection's ACK state -- the QUIC_CONN_SEND_FLAG_ACK flag and the
// delayed ACK timer -- is connection-wide, while the ack-eliciting packets it
// stands for are counted per path ID, which is what
// QuicSendHasAckElicitingPacketsToAcknowledge walks the path ID set to find.
// Taking a path ID out of the set can therefore change that answer, and
// QuicPathIDSetTryFreePathID did so without reconciling the two: the last path
// ID holding ack-eliciting packets would leave with the timer still armed for
// packets no longer reachable, and the next QuicSendSetSendFlag would trip
// QuicSendValidate.
//
// Removing every path is what makes this observable. QuicSendValidate's third
// branch is skipped for a closed connection but its second is not, and a
// closing connection stops writing ACK frames, so the timer stays armed over
// the path ID frees that follow.
//
// Issue #122. The abort is timing-dependent -- the delayed ACK timer has to be
// armed when the free lands -- at about one round in two, so the sequence runs
// several times over fresh connections.
//
void
QuicTestMultipathPathIdFreeAckState(
    _In_ const FamilyArgs& Params
    )
{
    const int Family = Params.Family;
    const uint32_t InitialRttMs = 50;
    const uint32_t Rounds = 4;

    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicSettings Settings;
    Settings.SetMultipathEnabled(TRUE).SetInitialRttMs(InitialRttMs);

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;

    PathTestContext Context;
    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    for (uint32_t Round = 0; Round < Rounds; ++Round) {
        PathDeathClientContext ClientContext;
        MsQuicConnection Connection(Registration, MsQuicCleanUpMode::CleanUpManual, PathDeathClientContext::ConnCallback, &ClientContext);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

        Connection.SetShareUdpBinding();

        TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
        TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));

        //
        // Paths only open once the handshake is confirmed.
        //
        CxPlatSleep(100);

        QuicAddr LocalAddr, PairAddr;
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(LocalAddr));
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(PairAddr));

        //
        // A path whose probes are all dropped, so validation times out and its
        // path ID is freed. The issue reports this precondition as mattering:
        // without a path ID freed just before, the sequence completes.
        //
        QuicAddr DoomedLocalAddr = LocalAddr;
        DoomedLocalAddr.SetEphemeralPort();
        PathProbeHelper* ProbeHelper =
            new(std::nothrow) PathProbeHelper(DoomedLocalAddr.GetPort(), 255, 255);
        TEST_NOT_EQUAL(nullptr, ProbeHelper);

        QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
        QUIC_PATH_PARAM DoomedParam = { &DoomedLocalAddr.SockAddr, &PairAddr.SockAddr };
        int Try = 0;
        do {
            Status = Connection.SetParam(QUIC_PARAM_CONN_ADD_PATH, sizeof(DoomedParam), &DoomedParam);
            if (Status == QUIC_STATUS_OUT_OF_MEMORY || QUIC_SUCCEEDED(Status)) {
                break;
            }
            delete ProbeHelper;
            DoomedLocalAddr.SetEphemeralPort();
            ProbeHelper = new(std::nothrow) PathProbeHelper(DoomedLocalAddr.GetPort(), 255, 255);
        } while (++Try <= 3);
        if (QUIC_FAILED(Status)) {
            delete ProbeHelper;
        }
        TEST_QUIC_SUCCEEDED(Status);

        TEST_TRUE(ClientContext.PathRemovedEvent.WaitTimeout(TestWaitTimeout));

        //
        // Its path ID goes three PTO after the abandon, and the doomed path
        // never took an RTT sample, so that rests on InitialRttMs.
        //
        CxPlatSleep(10 * InitialRttMs);
        delete ProbeHelper;

        //
        // A path that does validate, so its path ID receives ack-eliciting
        // packets and arms the connection's delayed ACK timer.
        //
        QuicAddr GoodLocalAddr = LocalAddr;
        GoodLocalAddr.SetEphemeralPort();
        QUIC_PATH_PARAM GoodParam = { &GoodLocalAddr.SockAddr, &PairAddr.SockAddr };
        Try = 0;
        do {
            Status = Connection.SetParam(QUIC_PARAM_CONN_ADD_PATH, sizeof(GoodParam), &GoodParam);
            if (Status == QUIC_STATUS_OUT_OF_MEMORY || QUIC_SUCCEEDED(Status)) {
                break;
            }
            GoodLocalAddr.SetEphemeralPort();
            GoodParam.LocalAddress = &GoodLocalAddr.SockAddr;
        } while (++Try <= 3);
        TEST_QUIC_SUCCEEDED(Status);

        CxPlatSleep(4 * InitialRttMs);

        //
        // A wildcard local address, so the remote alone selects. Both paths
        // share it, so every path goes and the connection closes with nowhere
        // left to send -- which is the state the frees below have to survive.
        //
        QuicAddr WildcardLocalAddr(QuicAddrFamily, (uint16_t)0);
        QUIC_PATH_PARAM RemoveParam = { &WildcardLocalAddr.SockAddr, &PairAddr.SockAddr };
        TEST_QUIC_SUCCEEDED(
            Connection.SetParam(QUIC_PARAM_CONN_REMOVE_PATH, sizeof(RemoveParam), &RemoveParam));

        //
        // Long enough for every remaining path ID's close timer to run, which
        // is where the abort landed.
        //
        CxPlatSleep(10 * InitialRttMs);
    }
}

//
// Coverage for a validated multipath path being made active and then removed,
// which is the shape QuicSendWritePathAckFrames' set walk has to keep working
// for. No existing test activates a path it added and then takes it away.
//
// This is not a regression test for the asymmetry that walk fixes: the
// QUIC_PARAM_CONN_REMOVE_PATH route does not reach it, because the multipath
// branch of QuicConnRemovePath leaves the path in Connection->Paths until
// QuicPathIDSetTryFreePathID takes both away together. See the pull request
// for the measurement that established that.
//
void
QuicTestMultipathRemovedPathAcks(
    _In_ const FamilyArgs& Params
    )
{
    const int Family = Params.Family;
    const uint32_t InitialRttMs = 50;

    PathTestContext Context;
    PathTestClientContext ClientContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicSettings Settings;
    Settings.SetMultipathEnabled(TRUE).SetInitialRttMs(InitialRttMs);

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", Settings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", Settings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestContext::ConnCallback, &Context);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, MsQuicCleanUpMode::CleanUpManual, PathTestClientContext::ConnCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    Connection.SetShareUdpBinding();

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    //
    // Paths only open once the handshake is confirmed.
    //
    CxPlatSleep(100);

    QuicAddr LocalAddr, PairAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(LocalAddr));
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(PairAddr));

    QuicAddr SecondLocalAddr = LocalAddr;
    SecondLocalAddr.SetEphemeralPort();
    QUIC_PATH_PARAM AddParam = { &SecondLocalAddr.SockAddr, &PairAddr.SockAddr };
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Try = 0;
    do {
        Status = Connection.SetParam(QUIC_PARAM_CONN_ADD_PATH, sizeof(AddParam), &AddParam);
        if (QUIC_SUCCEEDED(Status)) {
            break;
        }
        SecondLocalAddr.SetEphemeralPort();
        AddParam.LocalAddress = &SecondLocalAddr.SockAddr;
    } while (++Try <= 3);
    TEST_QUIC_SUCCEEDED(Status);

    //
    // The server indicating the path is how the client learns the probe landed.
    //
    TEST_TRUE(Context.PathAddedEvent.WaitTimeout(TestWaitTimeout));
    CxPlatSleep(4 * InitialRttMs);

    //
    // Send on the new path, so the server answers on it and the client's second
    // path ID is where those packets land and have to be acknowledged from.
    //
    QUIC_PATH_PARAM ActivateParam = { &SecondLocalAddr.SockAddr, &PairAddr.SockAddr };
    TEST_QUIC_SUCCEEDED(
        Connection.SetParam(QUIC_PARAM_CONN_ACTIVATE_PATH, sizeof(ActivateParam), &ActivateParam));
    CxPlatSleep(2 * InitialRttMs);

    //
    // Ack-eliciting traffic from the server, left in flight, and then the path
    // carrying it is taken away.
    //
    MsQuicSettings Poke;
    for (uint32_t i = 0; i < 20; ++i) {
        Context.Connection->GetSettings(&Poke);
        Poke.IsSetFlags = 0;
        Poke.SetPeerBidiStreamCount(Poke.PeerBidiStreamCount + 1);
        Context.Connection->SetSettings(Poke);
    }

    QUIC_PATH_PARAM RemoveParam = { &SecondLocalAddr.SockAddr, &PairAddr.SockAddr };
    TEST_QUIC_SUCCEEDED(
        Connection.SetParam(QUIC_PARAM_CONN_REMOVE_PATH, sizeof(RemoveParam), &RemoveParam));

    //
    // Past the removed path ID's three PTO close timer.
    //
    CxPlatSleep(30 * InitialRttMs);

    //
    // The original path carries the connection on: it is back to being the one
    // that sends, and it still carries traffic in both directions.
    //
    TEST_FALSE(ClientContext.ShutdownEvent.WaitTimeout(100));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    //
    // The pokes above already signalled these once, so both are reset first.
    //
    ClientContext.StreamCountEvent.Reset();
    Context.PeerStreamChangedEvent.Reset();

    MsQuicSettings UpdatedSettings;
    Context.Connection->GetSettings(&UpdatedSettings);
    UpdatedSettings.IsSetFlags = 0;
    UpdatedSettings.SetPeerBidiStreamCount(UpdatedSettings.PeerBidiStreamCount + 1);
    Context.Connection->SetSettings(UpdatedSettings);
    TEST_TRUE(ClientContext.StreamCountEvent.WaitTimeout(TestWaitTimeout));

    Connection.GetSettings(&UpdatedSettings);
    UpdatedSettings.IsSetFlags = 0;
    UpdatedSettings.SetPeerBidiStreamCount(UpdatedSettings.PeerBidiStreamCount + 1);
    Connection.SetSettings(UpdatedSettings);
    TEST_TRUE(Context.PeerStreamChangedEvent.WaitTimeout(TestWaitTimeout));
}

#endif
