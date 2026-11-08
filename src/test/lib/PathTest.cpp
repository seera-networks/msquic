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

//
// Counts datagrams arriving from a given client port that are at least a given
// length. An MTU probe is padded to the size it is probing, so it separates by
// length from everything else a path carries.
//
struct PathProbeSizeCounter : public DatapathHook
{
    uint16_t PathPort;
    uint16_t MinLength;
    long Count {0};
    PathProbeSizeCounter(uint16_t Port, uint16_t Min) : PathPort(Port), MinLength(Min) {
        DatapathHooks::Instance->AddHook(this);
    }
    ~PathProbeSizeCounter() {
        DatapathHooks::Instance->RemoveHook(this);
    }
    _IRQL_requires_max_(DISPATCH_LEVEL)
    BOOLEAN
    Receive(
        _Inout_ struct CXPLAT_RECV_DATA* Datagram
        ) {
        if (QuicAddrGetPort(&Datagram->Route->RemoteAddress) == PathPort &&
            Datagram->BufferLength >= MinLength) {
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

//
// Client settings for a test that manages its own paths.
//
// AddAddressMode MANUAL, which is what MANUAL is for: the application
// decides, and nothing happens to a path unless it asks. Every test that adds
// paths and then counts them, or reads back the path IDs it was handed, needs
// that. Under AUTO -- the default since #176, which made AddAddressMode drive
// the host's own addresses as well as the peer's -- the connection builds the
// candidate pair table and opens a path of its own for every usable local
// address. That both inflates the count and spends the path IDs the test was
// about to ask for, and QuicConnAddPath answers QUIC_STATUS_OUT_OF_MEMORY once
// QuicPathIDSetGetUnusedPathID runs dry.
//
// Invisible on a loopback connection, which has no pairs to open a path from,
// so the table stays empty and AUTO does nothing. The XDP runs put the
// connection on a real interface, where it does.
//
// The server keeps the default, because the reconciler is client-only. Tests
// that deliberately exercise it keep the default on both sides and do not use
// this.
//
static
MsQuicSettings
MultipathOwnPathsClientSettings(
    _In_ uint32_t InitialRttMs = 0
    )
{
    MsQuicSettings Settings;
    Settings.SetMultipathEnabled(TRUE).SetAddAddressMode(QUIC_ADD_ADDRESS_MANUAL);
    if (InitialRttMs != 0) {
        Settings.SetInitialRttMs(InitialRttMs);
    }
    return Settings;
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
        MultipathOwnPathsClientSettings(),
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
    MsQuicConfiguration ClientConfiguration(
        Registration, "MsQuicTest", MultipathOwnPathsClientSettings(InitialRttMs), ClientCredConfig);
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
    MsQuicConfiguration ClientConfiguration(
        Registration, "MsQuicTest", MultipathOwnPathsClientSettings(InitialRttMs), ClientCredConfig);
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
    MsQuicConfiguration ClientConfiguration(
        Registration, "MsQuicTest", MultipathOwnPathsClientSettings(InitialRttMs), ClientCredConfig);
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
    MsQuicConfiguration ClientConfiguration(
        Registration, "MsQuicTest", MultipathOwnPathsClientSettings(InitialRttMs), ClientCredConfig);
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

//
// A lost PATH_RESPONSE must not cost the path. The challenger is the only side
// that can recover it: RFC 9000 section 8.2.2 forbids the responder from
// re-sending -- "An endpoint MUST NOT send more than one PATH_RESPONSE frame in
// response to one PATH_CHALLENGE frame [...] The peer is expected to send more
// PATH_CHALLENGE frames as necessary to evoke additional PATH_RESPONSE frames"
// -- and loss detection cannot help either, because the packet carrying the
// challenge was acknowledged, so it is never declared lost and the re-arm in
// QuicLossDetectionOnPacketDiscarded never fires.
//
// Issue #129. Before the retry schedule, one lost response abandoned the path
// at the validation deadline and the connection lost it for the rest of the
// session.
//
void
QuicTestMultipathPathValidationRetry(
    _In_ const FamilyArgs& Params
    )
{
    const int Family = Params.Family;

    //
    // The deadline is max(3 PTO, 6 x InitialRtt) and the retries fall on its
    // thirds, so a small initial RTT is what keeps this test short. The PTO
    // branch is the one that wins here, not the floor: a new path starts at
    // SmoothedRtt = InitialRtt and RttVariance = half of it (path.c), so
    // PTO = 50 + 4 x 25 + 25 (the default MaxAckDelay) = 175 ms and three of
    // those come to 525 ms, past the 6 x 50 = 300 ms floor. So the budget is
    // 525 ms, with challenges at 0, 175 and 350 ms -- comfortably inside
    // TestWaitTimeout, which is what matters for the wait below.
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
    MsQuicConfiguration ClientConfiguration(
        Registration, "MsQuicTest", MultipathOwnPathsClientSettings(InitialRttMs), ClientCredConfig);
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
    // Nothing dropped towards the server, so the challenge lands and the server
    // answers. Two datagrams dropped coming back, which is what the issue's
    // trace shows: the server's PATH_RESPONSE and the challenge for its own
    // direction, lost together. Everything after that is delivered, so the
    // retry evokes a second response and the path comes up.
    //
    //
    // Owned, because TEST_TRUE and friends return on failure. A raw delete at
    // the end of the function is skipped exactly when an assertion fails, which
    // here is the regression case, and the hook would stay registered in the
    // process-global DatapathHooks for every later test in the binary -- still
    // matching on an ephemeral port that by then belongs to someone else.
    //
    UniquePtr<PathProbeHelper> ProbeHelper(
        new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), 0, 2));
    TEST_NOT_EQUAL(nullptr, ProbeHelper.get());

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_PATH_PARAM PathParam = { &SecondLocalAddr.SockAddr, &PairAddr.SockAddr };
    int Try = 0;
    do {
        Status = Connection.SetParam(
            QUIC_PARAM_CONN_ADD_PATH,
            sizeof(PathParam),
            &PathParam);
        if (QUIC_SUCCEEDED(Status)) {
            break;
        }
        SecondLocalAddr.SetEphemeralPort();
        ProbeHelper.reset(
            new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), 0, 2));
        TEST_NOT_EQUAL(nullptr, ProbeHelper.get());
    } while (++Try <= 3);
    TEST_QUIC_SUCCEEDED(Status);

    //
    // The client indicates PATH_ADDED when its own validation succeeds, which
    // is the whole assertion: the re-sent challenge got a response. Without the
    // retry the client sends one challenge, never hears back, and abandons --
    // PATH_REMOVED instead, and this times out.
    //
    TEST_TRUE(ClientContext.PathAddedEvent.WaitTimeout(TestWaitTimeout));
    TEST_FALSE(ClientContext.PathRemovedEvent.WaitTimeout(100));
    TEST_FALSE(ClientContext.ShutdownEvent.WaitTimeout(100));
}

//
// Every path of a multipath connection gets measured, not just the one the
// connection happens to be sending on.
//
// MTU discovery used to be asked for with a connection-wide send flag and the
// probe built on whichever path QuicConnChoosePath returned for that flush.
// The acknowledgement, though, is matched against the sending path's own
// ProbeSize in QuicMtuDiscoveryOnAckedPacket, so a probe that one path asked
// for and another carried came back not matching and was dropped as out of
// order -- and the path that asked was never measured at all. With one active
// path the two are the same path and nothing shows; with two they are not.
//
// The assertion is that no path is left at MinimumMtu. The statistics do not
// name a path by address, so "all of them grew" is what isolates the path that
// is not the one being sent on.
//
void
QuicTestMultipathPathsAreMeasured(
    _In_ const FamilyArgs& Params
    )
{
    const int Family = Params.Family;

    PathTestContext Context;
    PathTestClientContext ClientContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    //
    // Room to grow: paths start at MinimumMtu and loopback will carry them to
    // MaximumMtu, so a path still sitting at MinimumMtu was never probed.
    //
    MsQuicSettings Settings;
    Settings.SetMultipathEnabled(TRUE)
        .SetMinimumMtu(QUIC_DPLPMTUD_MIN_MTU)
        .SetMaximumMtu(1400);

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

    MsQuicConnection Connection(Registration, MsQuicCleanUpMode::CleanUpManual, PathTestClientContext::ClientCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    Connection.SetShareUdpBinding();

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    QuicAddr SecondLocalAddr, PairAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondLocalAddr));
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(PairAddr));
    SecondLocalAddr.SetEphemeralPort();

    UniquePtr<PathProbeHelper> ProbeHelper(
        new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort()));
    TEST_NOT_EQUAL(nullptr, ProbeHelper.get());

    //
    // Chosen to count MTU probes on the second path and nothing else, which
    // means counting UDP payload rather than MTU -- the hook sees the payload,
    // the MTU less the IP and UDP headers, 28 bytes over IPv4 and 48 over IPv6.
    //
    // Path validation pads its PATH_CHALLENGE to the path's current MTU, which
    // is MinimumMtu (1248) here: 1220 over IPv4, 1200 over IPv6. MTU probes
    // jump straight to 1280: 1252 and 1232. So 1225 is above every validation
    // challenge and below every probe, for both families -- a threshold below
    // the challenge would count validation traffic and the assertion would
    // then pass on a path that was never probed at all.
    //
    const uint16_t ProbeOnlyLength = 1225;
    UniquePtr<PathProbeSizeCounter> Probes(
        new(std::nothrow) PathProbeSizeCounter(SecondLocalAddr.GetPort(), ProbeOnlyLength));
    TEST_NOT_EQUAL(nullptr, Probes.get());

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_PATH_PARAM PathParam = { &SecondLocalAddr.SockAddr, &PairAddr.SockAddr };
    int Try = 0;
    do {
        Status = Connection.SetParam(QUIC_PARAM_CONN_ADD_PATH, sizeof(PathParam), &PathParam);
        if (QUIC_SUCCEEDED(Status)) {
            break;
        }
        SecondLocalAddr.SetEphemeralPort();
        ProbeHelper.reset(new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort()));
        TEST_NOT_EQUAL(nullptr, ProbeHelper.get());
        Probes.reset(
            new(std::nothrow) PathProbeSizeCounter(SecondLocalAddr.GetPort(), ProbeOnlyLength));
        TEST_NOT_EQUAL(nullptr, Probes.get());
    } while (++Try <= 3);
    TEST_QUIC_SUCCEEDED(Status);

    TEST_TRUE(ProbeHelper->ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ProbeHelper->ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
    ProbeHelper.reset(nullptr);
    TEST_TRUE(ClientContext.PathAddedEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.PathAddedEvent.WaitTimeout(TestWaitTimeout));

    //
    // Keep the connection busy, so the flush that carries the probe happens
    // promptly whichever path the connection is sending on.
    //
    Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(15));

    for (uint32_t i = 0; i < 100 && Probes->Count == 0; ++i) {
        CxPlatSleep(100);
    }

    Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(0));

    //
    // A probe-sized datagram from the second path's own port. Building every
    // probe on the path the flush chose sends it from the first path's port
    // instead, and this stays at zero -- which is the defect, and it is the
    // send that is asserted rather than the MTU that results, so the assertion
    // does not depend on the search converging or on where it stops.
    //
    TEST_TRUE(Probes->Count > 0);
}

#endif

#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)

//
// draft-munizaga-quic-alternative-server-address end to end.
//
// The server advertises an address, then withdraws it, and the client is
// expected to report both. MANUAL mode is used so the client reports rather
// than opening a path: the advertised address is a synthetic one the host
// cannot reach, which keeps the test deterministic and is enough to prove the
// frame round-tripped and the receive-side diff turned a whole-set frame back
// into an add and a remove.
//
//
// A real, routable address of this host, or false if it has none.
//
// Needed because the frame writer skips loopback observed addresses, exactly as
// the ADD_ADDRESS writer does: advertising 127.0.0.1 to a peer is meaningless,
// so a loopback-only host cannot exercise the advertisement at all. The peer
// here is on the same host, so any real interface address it binds is reachable.
//
static bool
AltServerAddressHostAddress(
    QuicAddr& Addr
    )
{
    uint32_t Length = 0;
    if (MsQuic->GetParam(nullptr, QUIC_PARAM_GLOBAL_LOCAL_ADDRESSES, &Length, nullptr)
            != QUIC_STATUS_BUFFER_TOO_SMALL ||
        Length == 0) {
        return false;
    }

    UniquePtr<uint8_t[]> Buffer(new(std::nothrow) uint8_t[Length]);
    if (Buffer.get() == nullptr ||
        QUIC_FAILED(
            MsQuic->GetParam(
                nullptr, QUIC_PARAM_GLOBAL_LOCAL_ADDRESSES, &Length, Buffer.get()))) {
        return false;
    }

    const QUIC_ADDR* Addresses = (const QUIC_ADDR*)Buffer.get();
    for (uint32_t i = 0; i < Length / sizeof(QUIC_ADDR); ++i) {
        if (QuicAddrGetFamily(&Addresses[i]) != QUIC_ADDRESS_FAMILY_INET) {
            continue;
        }
        uint8_t Bytes[4];
        CxPlatCopyMemory(Bytes, &Addresses[i].Ipv4.sin_addr, sizeof(Bytes));
        if (Bytes[0] == 127 || (Bytes[0] == 169 && Bytes[1] == 254)) {
            continue; // Loopback is skipped by the writer; link-local is not routable.
        }
        Addr.SockAddr = Addresses[i];
        return true;
    }
    return false;
}

//
// How many paths the connection reports. The statistics parameter sizes its own
// buffer, so asking with none is enough to get the count.
//
static uint32_t
AltServerAddressPathCount(
    MsQuicConnection& Conn
    )
{
    uint32_t Length = 0;
    const QUIC_STATUS Status =
        MsQuic->GetParam(Conn.Handle, QUIC_PARAM_CONN_PATH_STATISTICS, &Length, nullptr);
    if (Status != QUIC_STATUS_BUFFER_TOO_SMALL && QUIC_FAILED(Status)) {
        return 0;
    }
    return Length / (uint32_t)sizeof(QUIC_PATH_STATISTICS);
}

static bool
AltServerAddressWaitForPathCount(
    MsQuicConnection& Conn,
    uint32_t Expected
    )
{
    for (uint32_t i = 0; i < 100; ++i) {
        if (AltServerAddressPathCount(Conn) == Expected) {
            return true;
        }
        CxPlatSleep(50);
    }
    return false;
}

struct AltServerAddressTestContext {
    CxPlatEvent HandshakeCompleteEvent;
    CxPlatEvent AddedEvent;
    CxPlatEvent RemovedEvent;
    CxPlatEvent ShutdownEvent;
    MsQuicConnection* Connection {nullptr};
    QuicAddr AddedAddress;
    uint64_t AddedSequenceNumber {UINT64_MAX};
    uint64_t RemovedSequenceNumber {UINT64_MAX};
    uint32_t AddedCount {0};
    uint32_t RemovedCount {0};

    static QUIC_STATUS QUIC_API ConnCallback(
        _In_ MsQuicConnection* Conn,
        _In_opt_ void* Context,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        ) noexcept
    {
        auto Ctx = static_cast<AltServerAddressTestContext*>(Context);
        if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            Ctx->Connection = Conn;
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            Ctx->HandshakeCompleteEvent.Set();
            Ctx->AddedEvent.Set();
            Ctx->RemovedEvent.Set();
            Ctx->ShutdownEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_NOTIFY_REMOTE_ADDRESS_ADDED) {
            Ctx->AddedAddress.SockAddr = *Event->NOTIFY_REMOTE_ADDRESS_ADDED.Address;
            Ctx->AddedSequenceNumber = Event->NOTIFY_REMOTE_ADDRESS_ADDED.SequenceNumber;
            Ctx->AddedCount++;
            Ctx->AddedEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_NOTIFY_REMOTE_ADDRESS_REMOVED) {
            Ctx->RemovedSequenceNumber = Event->NOTIFY_REMOTE_ADDRESS_REMOVED.SequenceNumber;
            Ctx->RemovedCount++;
            Ctx->RemovedEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
        }
        return QUIC_STATUS_SUCCESS;
    }
};

void
QuicTestAlternativeServerAddress(
    )
{
    //
    // Declared before the registration so they outlive it; the auto-accepted
    // server connection's SHUTDOWN_COMPLETE arrives during RegistrationClose.
    //
    AltServerAddressTestContext ServerContext;
    AltServerAddressTestContext ClientContext;

    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings{}, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    //
    // MANUAL, so an advertised address is reported to the application instead
    // of having a path opened on it. Set on the struct directly because there
    // is no helper for this field.
    //
    MsQuicSettings ClientSettings;
    ClientSettings.SetAddAddressMode(QUIC_ADD_ADDRESS_MANUAL);
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientSettings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(
        Registration, ServerConfiguration, AltServerAddressTestContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());

    QuicAddr ServerLocalAddr(QUIC_ADDRESS_FAMILY_INET);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(
        Registration, CleanUpManual, AltServerAddressTestContext::ConnCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    TEST_QUIC_SUCCEEDED(
        Connection.Start(
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            QUIC_TEST_LOOPBACK_FOR_AF(QUIC_ADDRESS_FAMILY_INET),
            ServerLocalAddr.GetPort()));
    TEST_TRUE(ClientContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, ServerContext.Connection);

    //
    // A second address for the server to bind, and the address the outside
    // world would see it as. The bound one has to be real enough to bind; the
    // observed one is what goes on the wire, and is deliberately a TEST-NET-1
    // address so the client cannot accidentally reach it.
    //
    QuicAddr BoundAddr(QUIC_ADDRESS_FAMILY_INET);
    TEST_TRUE(QuicAddrFromString("127.0.0.1", 0, &BoundAddr.SockAddr));
    BoundAddr.SetEphemeralPort();

    QuicAddr ObservedAddr(QUIC_ADDRESS_FAMILY_INET);
    TEST_TRUE(QuicAddrFromString("192.0.2.1", 4433, &ObservedAddr.SockAddr));

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t Try = 0;
    do {
        Status =
            ServerContext.Connection->SetParam(
                QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                sizeof(BoundAddr.SockAddr),
                &BoundAddr.SockAddr);
        if (QUIC_FAILED(Status)) {
            BoundAddr.SetEphemeralPort();
        }
    } while (QUIC_FAILED(Status) && ++Try <= 3);
    TEST_QUIC_SUCCEEDED(Status);

    //
    // Attaching the observed address is what makes the server advertise: the
    // bound entry alone has nothing to tell the peer.
    //
    QUIC_ADD_OBSERVED_ADDRESS AddObserved = { &BoundAddr.SockAddr, &ObservedAddr.SockAddr };
    TEST_QUIC_SUCCEEDED(
        ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_ADD_OBSERVED_ADDRESS,
            sizeof(AddObserved),
            &AddObserved));

    //
    // The client learns of it, which is the frame having been encoded, sent,
    // decoded and diffed against an empty stored set.
    //
    TEST_TRUE(ClientContext.AddedEvent.WaitTimeout(TestWaitTimeout));
    TEST_EQUAL(1u, ClientContext.AddedCount);
    TEST_TRUE(QuicAddrCompare(&ObservedAddr.SockAddr, &ClientContext.AddedAddress.SockAddr));

    //
    // And the event is all that happened: MANUAL means the application opens
    // paths, so the library must not have opened one itself.
    //
    // Asserted since stage 3 of #157, which is where it became possible to get
    // wrong. The reconciler is queued unconditionally by the frame handler, so
    // without a mode check it would build a table containing this advertised
    // address -- MANUAL still records it, in order to report it -- and open a
    // path to it behind the application's back. Waited out rather than read
    // once, because a pass that did that would run asynchronously and a single
    // read here could happen before it.
    //
    CxPlatSleep(250);
    TEST_EQUAL(1u, AltServerAddressPathCount(Connection));

    //
    // Now withdraw it. There is no withdrawal frame in this draft: the server
    // sends its set again without the address, and the diff on the far side is
    // what turns that absence into a removal.
    //
    TEST_QUIC_SUCCEEDED(
        ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_REMOVE_BOUND_ADDRESS,
            sizeof(BoundAddr.SockAddr),
            &BoundAddr.SockAddr));

    TEST_TRUE(ClientContext.RemovedEvent.WaitTimeout(TestWaitTimeout));
    TEST_EQUAL(1u, ClientContext.RemovedCount);
    //
    // Reported with the sequence number the addition carried. The draft has no
    // per-address sequence numbers, so this is one the receiver assigned and
    // kept across the two indications -- the thing that lets an application
    // match a removal to what it was told was added.
    //
    TEST_EQUAL(ClientContext.AddedSequenceNumber, ClientContext.RemovedSequenceNumber);

    Connection.Shutdown(QUIC_TEST_NO_ERROR);
    TEST_TRUE(ClientContext.ShutdownEvent.WaitTimeout(TestWaitTimeout));
}

//
// The same mechanism in AUTO mode, which is the default and the one that
// actually opens and closes paths.
//
// This exists because the MANUAL test above cannot see any of that: it asserts
// on the application events, so it passed while AUTO mode did nothing at all.
// It covers both halves: an advertised address becoming a real path, and the
// server taking it back again. The second was unreachable until #156 was
// fixed -- the server crashed on its own bound-address teardown before the
// client could be observed reacting.
//
void
QuicTestAlternativeServerAddressAuto(
    )
{
    AltServerAddressTestContext ServerContext;
    AltServerAddressTestContext ClientContext;

    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings{}, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    //
    // AUTO explicitly, though it is also the default: the point of the test is
    // the mode that manages paths for itself.
    //
    MsQuicSettings ClientSettings;
    ClientSettings.SetAddAddressMode(QUIC_ADD_ADDRESS_AUTO);
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientSettings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(
        Registration, ServerConfiguration, AltServerAddressTestContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());

    QuicAddr ServerLocalAddr(QUIC_ADDRESS_FAMILY_INET);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(
        Registration, CleanUpManual, AltServerAddressTestContext::ConnCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    TEST_QUIC_SUCCEEDED(
        Connection.Start(
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            QUIC_TEST_LOOPBACK_FOR_AF(QUIC_ADDRESS_FAMILY_INET),
            ServerLocalAddr.GetPort()));
    TEST_TRUE(ClientContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, ServerContext.Connection);

    TEST_EQUAL(1u, AltServerAddressPathCount(Connection));

    //
    // A second address the server really is listening on, advertised as itself,
    // so the client can actually open a path to it. Unlike the MANUAL test a
    // synthetic address would not do: nothing would come of it and the test
    // could not tell a working withdrawal from a broken one.
    //
    // It has to be a real interface address rather than loopback, because the
    // writer skips loopback observed addresses. A host with no routable address
    // cannot run this.
    //
    QuicAddr SecondAddr;
    if (!AltServerAddressHostAddress(SecondAddr)) {
        return;
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t Try = 0;
    do {
        SecondAddr.SetEphemeralPort();
        Status =
            ServerContext.Connection->SetParam(
                QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                sizeof(SecondAddr.SockAddr),
                &SecondAddr.SockAddr);
    } while (QUIC_FAILED(Status) && ++Try <= 3);
    TEST_QUIC_SUCCEEDED(Status);

    QUIC_ADD_OBSERVED_ADDRESS AddObserved = { &SecondAddr.SockAddr, &SecondAddr.SockAddr };
    TEST_QUIC_SUCCEEDED(
        ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_ADD_OBSERVED_ADDRESS,
            sizeof(AddObserved),
            &AddObserved));

    //
    // Polled rather than waited on an event: AUTO raises no application event
    // for a path it opened itself unless multipath is negotiated.
    //
    TEST_TRUE(AltServerAddressWaitForPathCount(Connection, 2));

    //
    // And the withdrawal: the server takes the address back, and the client's
    // path on it goes away. This is what #156 used to make unreachable -- the
    // server crashed on its own bound-address teardown before the client could
    // be observed reacting.
    //
    TEST_QUIC_SUCCEEDED(
        ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_REMOVE_BOUND_ADDRESS,
            sizeof(SecondAddr.SockAddr),
            &SecondAddr.SockAddr));

    TEST_TRUE(AltServerAddressWaitForPathCount(Connection, 1));

    //
    // Both sides still up. The server is the one that matters here and is the
    // one that was broken: #156 was its own teardown freeing a CID its active
    // path still used. Asserting only on the client would not catch it --
    // the failure is a silent abort or use-after-free, so no CONNECTION_CLOSE
    // reaches the client, and with asserts compiled out a corrupted server
    // leaves this test green.
    //
    TEST_FALSE(ServerContext.ShutdownEvent.WaitTimeout(100));
    TEST_FALSE(ClientContext.ShutdownEvent.WaitTimeout(100));

    Connection.Shutdown(QUIC_TEST_NO_ERROR);
    TEST_TRUE(ClientContext.ShutdownEvent.WaitTimeout(TestWaitTimeout));
}

//
// Stage 2 of #157: every path records how it came to exist, so that the stage 3
// reconciler can remove the ones it created and leave everyone else's alone.
//
// Worth a test of its own because getting it wrong is silent and only shows up
// later: an application-created path mislabelled as the reconciler's would be
// deleted out from under an application that manages paths by hand, the first
// time AUTO reconciled.
//
void
QuicTestPathOrigins(
    )
{
#if !DEBUG
    //
    // The origins are only readable through a debug-only parameter.
    //
#else
    AltServerAddressTestContext ServerContext;
    AltServerAddressTestContext ClientContext;

    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings{}, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    //
    // MANUAL explicitly, because AUTO is the default (QUIC_DEFAULT_ADD_ADDRESS_MODE).
    // Without this the assertion below that no path is the reconciler's would
    // hold only because nothing happened to be advertised during the run, and
    // a route change mid-test would fail it for the wrong reason.
    //
    MsQuicSettings ClientSettings;
    ClientSettings.SetAddAddressMode(QUIC_ADD_ADDRESS_MANUAL);
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientSettings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(
        Registration, ServerConfiguration, AltServerAddressTestContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());

    QuicAddr ServerLocalAddr(QUIC_ADDRESS_FAMILY_INET);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(
        Registration, CleanUpManual, AltServerAddressTestContext::ConnCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    TEST_QUIC_SUCCEEDED(
        Connection.Start(
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            QUIC_TEST_LOOPBACK_FOR_AF(QUIC_ADDRESS_FAMILY_INET),
            ServerLocalAddr.GetPort()));
    TEST_TRUE(ClientContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));

    //
    // The connection's first path came from the handshake.
    //
    //
    // Pre-filled with a value no origin uses, so that a handler which wrote
    // nothing -- or wrote at the wrong offset -- cannot pass by leaving the
    // buffer as it found it.
    //
    uint8_t Origins[QUIC_MAX_PATH_COUNT];
    memset(Origins, 0xFF, sizeof(Origins));
    uint32_t Length = sizeof(Origins);
    TEST_QUIC_SUCCEEDED(
        MsQuic->GetParam(
            Connection.Handle, QUIC_PARAM_CONN_TEST_PATH_ORIGINS, &Length, Origins));
    TEST_EQUAL(1u, Length);
    TEST_EQUAL((uint8_t)QUIC_PATH_ORIGIN_INITIAL, Origins[0]);

    //
    // Wait for handshake confirmation, as the other add-path tests do:
    // QuicConnAddPath opens the path as soon as 1-RTT keys exist.
    //
    CxPlatSleep(100);

    //
    // One the application opened itself. The local address is the connection's
    // own with a fresh port, not a hardcoded loopback: the raw/XDP datapath
    // will not bind a client to a specific loopback address, and the address
    // the datapath already chose is by construction one it can bind. What
    // matters here is who asked for the path, not where it goes.
    //
    QuicAddr SecondLocal;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondLocal));
    QuicAddr Remote;
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(Remote));

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t Try = 0;
    do {
        SecondLocal.SetEphemeralPort();
        QUIC_PATH_PARAM PathParam = { &SecondLocal.SockAddr, &Remote.SockAddr };
        Status =
            Connection.SetParam(
                QUIC_PARAM_CONN_ADD_PATH, sizeof(PathParam), &PathParam);
    } while (QUIC_FAILED(Status) && ++Try <= 3);
    TEST_QUIC_SUCCEEDED(Status);

    memset(Origins, 0xFF, sizeof(Origins));
    Length = sizeof(Origins);
    TEST_QUIC_SUCCEEDED(
        MsQuic->GetParam(
            Connection.Handle, QUIC_PARAM_CONN_TEST_PATH_ORIGINS, &Length, Origins));
    TEST_EQUAL(2u, Length);

    //
    // The initial path stays Paths[0] and the new one is the application's.
    // Asserted as a set rather than by index, because QuicConnAddPath inserts
    // at index 1 and a future change to that ordering should not fail a test
    // about provenance.
    //
    uint32_t InitialCount = 0;
    uint32_t ApplicationCount = 0;
    for (uint32_t i = 0; i < Length; ++i) {
        //
        // NONE would mean a slot that never went through QuicPathInitialize
        // was reported as in use.
        //
        TEST_NOT_EQUAL((uint8_t)QUIC_PATH_ORIGIN_NONE, Origins[i]);
        if (Origins[i] == QUIC_PATH_ORIGIN_INITIAL) {
            InitialCount++;
        } else if (Origins[i] == QUIC_PATH_ORIGIN_APPLICATION) {
            ApplicationCount++;
        }
    }
    TEST_EQUAL(1u, InitialCount);
    TEST_EQUAL(1u, ApplicationCount);

    //
    // And nothing is labelled as the reconciler's. The connection is in MANUAL,
    // so nothing may open a path on its own behalf and stage 3 would have
    // nothing here to remove.
    //
    for (uint32_t i = 0; i < Length; ++i) {
        TEST_NOT_EQUAL((uint8_t)QUIC_PATH_ORIGIN_RECONCILER, Origins[i]);
    }

    Connection.Shutdown(QUIC_TEST_NO_ERROR);
    TEST_TRUE(ClientContext.ShutdownEvent.WaitTimeout(TestWaitTimeout));
#endif
}

//
// The other half: a path opened because the peer advertised an address is the
// reconciler's, and so is removable by it.
//
void
QuicTestPathOriginsAdvertised(
    )
{
#if !DEBUG
#else
    AltServerAddressTestContext ServerContext;
    AltServerAddressTestContext ClientContext;

    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings{}, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicSettings ClientSettings;
    ClientSettings.SetAddAddressMode(QUIC_ADD_ADDRESS_AUTO);
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientSettings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(
        Registration, ServerConfiguration, AltServerAddressTestContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());

    QuicAddr ServerLocalAddr(QUIC_ADDRESS_FAMILY_INET);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(
        Registration, CleanUpManual, AltServerAddressTestContext::ConnCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    TEST_QUIC_SUCCEEDED(
        Connection.Start(
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            QUIC_TEST_LOOPBACK_FOR_AF(QUIC_ADDRESS_FAMILY_INET),
            ServerLocalAddr.GetPort()));
    TEST_TRUE(ClientContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, ServerContext.Connection);

    //
    // A real interface address, because the frame writer skips loopback
    // observed addresses -- the same reason AlternativeServerAddressAuto needs
    // one.
    //
    QuicAddr SecondAddr;
    if (!AltServerAddressHostAddress(SecondAddr)) {
        return;
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t Try = 0;
    do {
        SecondAddr.SetEphemeralPort();
        Status =
            ServerContext.Connection->SetParam(
                QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                sizeof(SecondAddr.SockAddr),
                &SecondAddr.SockAddr);
    } while (QUIC_FAILED(Status) && ++Try <= 3);
    TEST_QUIC_SUCCEEDED(Status);

    QUIC_ADD_OBSERVED_ADDRESS AddObserved = { &SecondAddr.SockAddr, &SecondAddr.SockAddr };
    TEST_QUIC_SUCCEEDED(
        ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_ADD_OBSERVED_ADDRESS,
            sizeof(AddObserved),
            &AddObserved));

    TEST_TRUE(AltServerAddressWaitForPathCount(Connection, 2));

    uint8_t Origins[QUIC_MAX_PATH_COUNT];
    memset(Origins, 0xFF, sizeof(Origins));
    uint32_t Length = sizeof(Origins);
    TEST_QUIC_SUCCEEDED(
        MsQuic->GetParam(
            Connection.Handle, QUIC_PARAM_CONN_TEST_PATH_ORIGINS, &Length, Origins));
    TEST_EQUAL(2u, Length);

    uint32_t ReconcilerCount = 0;
    for (uint32_t i = 0; i < Length; ++i) {
        TEST_NOT_EQUAL((uint8_t)QUIC_PATH_ORIGIN_NONE, Origins[i]);
        if (Origins[i] == QUIC_PATH_ORIGIN_RECONCILER) {
            ReconcilerCount++;
        }
    }
    TEST_EQUAL(1u, ReconcilerCount);

    Connection.Shutdown(QUIC_TEST_NO_ERROR);
    TEST_TRUE(ClientContext.ShutdownEvent.WaitTimeout(TestWaitTimeout));
#endif
}

#if DEBUG
//
// Helpers for the stage 3 reconciler tests. Debug only, because they read the
// endpoints back through a debug-only parameter.
//

static uint32_t
ReconcilerPathAddresses(
    MsQuicConnection& Conn,
    QUIC_TEST_PATH_ADDRESSES* Addresses,
    uint32_t Capacity
    )
{
    uint32_t Length = Capacity * (uint32_t)sizeof(QUIC_TEST_PATH_ADDRESSES);
    if (QUIC_FAILED(
            MsQuic->GetParam(
                Conn.Handle, QUIC_PARAM_CONN_TEST_PATH_ADDRESSES, &Length, Addresses))) {
        return 0;
    }
    return Length / (uint32_t)sizeof(QUIC_TEST_PATH_ADDRESSES);
}

//
// Whether any path of the connection sends to this remote endpoint. Compared in
// full, port included: the addresses under test differ only by port.
//
static bool
ReconcilerHasPathTo(
    MsQuicConnection& Conn,
    const QUIC_ADDR* Remote
    )
{
    QUIC_TEST_PATH_ADDRESSES Addresses[QUIC_MAX_PATH_COUNT];
    const uint32_t Count =
        ReconcilerPathAddresses(Conn, Addresses, QUIC_MAX_PATH_COUNT);
    for (uint32_t i = 0; i < Count; ++i) {
        if (QuicAddrCompare(&Addresses[i].RemoteAddress, Remote)) {
            return true;
        }
    }
    return false;
}

static bool
ReconcilerWaitForPathTo(
    MsQuicConnection& Conn,
    const QUIC_ADDR* Remote,
    bool Expected
    )
{
    for (uint32_t i = 0; i < 100; ++i) {
        if (ReconcilerHasPathTo(Conn, Remote) == Expected) {
            return true;
        }
        CxPlatSleep(50);
    }
    return false;
}

//
// Starts advertising one more server address, on the host address given with a
// fresh port. Retried, because the ephemeral port it picks can already be
// taken.
//
static bool
ReconcilerAdvertise(
    MsQuicConnection* ServerConn,
    const QuicAddr& Host,
    QuicAddr& Advertised
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t Try = 0;
    do {
        Advertised = Host;
        Advertised.SetEphemeralPort();
        Status =
            ServerConn->SetParam(
                QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                sizeof(Advertised.SockAddr),
                &Advertised.SockAddr);
    } while (QUIC_FAILED(Status) && ++Try <= 5);
    if (QUIC_FAILED(Status)) {
        return false;
    }

    QUIC_ADD_OBSERVED_ADDRESS AddObserved =
        { &Advertised.SockAddr, &Advertised.SockAddr };
    return
        QUIC_SUCCEEDED(
            ServerConn->SetParam(
                QUIC_PARAM_CONN_ADD_OBSERVED_ADDRESS,
                sizeof(AddObserved),
                &AddObserved));
}
#endif // DEBUG

//
// Stage 3 of #157: a server swapping one advertised address for another while
// the client is at QUIC_MAX_PATH_COUNT.
//
// This is the case the #155 review found and could not fix at the time. The
// removal of an address was queued as its own operation while the additions
// from the same frame ran inline inside QuicConnRecvFrames, so the addition
// was attempted while the departing address still held its path slot: it
// failed with no slots free, and nothing retried it once the slot opened a
// moment later. The address the server had just told us to use ended up with
// no path for the life of the connection.
//
// The reconciler fixes it by construction rather than by retrying -- one pass,
// removals before creations -- so the test asserts the outcome: the new
// address has a path and the withdrawn one does not.
//
void
QuicTestPathReconcilerSwapAtPathLimit(
    )
{
#if !DEBUG
    //
    // Reads the paths' endpoints through a debug-only parameter.
    //
#else
    AltServerAddressTestContext ServerContext;
    AltServerAddressTestContext ClientContext;

    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings{}, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicSettings ClientSettings;
    ClientSettings.SetAddAddressMode(QUIC_ADD_ADDRESS_AUTO);
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientSettings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(
        Registration, ServerConfiguration, AltServerAddressTestContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());

    QuicAddr ServerLocalAddr(QUIC_ADDRESS_FAMILY_INET);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(
        Registration, CleanUpManual, AltServerAddressTestContext::ConnCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    TEST_QUIC_SUCCEEDED(
        Connection.Start(
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            QUIC_TEST_LOOPBACK_FOR_AF(QUIC_ADDRESS_FAMILY_INET),
            ServerLocalAddr.GetPort()));
    TEST_TRUE(ClientContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, ServerContext.Connection);
    TEST_EQUAL(1u, AltServerAddressPathCount(Connection));

    //
    // Real interface addresses, because the frame writer skips loopback
    // observed addresses. One host address with a different port per entry:
    // the advertised entries carry a port, so these are genuinely different
    // places to send, and a host with several routable addresses is not
    // something a test can count on.
    //
    QuicAddr Host;
    if (!AltServerAddressHostAddress(Host)) {
        return;
    }

    //
    // Fill the path array: the active path plus one per advertised address.
    //
    QuicAddr Advertised[QUIC_MAX_PATH_COUNT - 1];
    for (uint32_t i = 0; i < QUIC_MAX_PATH_COUNT - 1; ++i) {
        if (!ReconcilerAdvertise(ServerContext.Connection, Host, Advertised[i])) {
            return;
        }
        TEST_TRUE(AltServerAddressWaitForPathCount(Connection, i + 2));
    }
    TEST_EQUAL((uint32_t)QUIC_MAX_PATH_COUNT, AltServerAddressPathCount(Connection));

    //
    // The swap, with every slot taken. Back to back and in this order, so the
    // server's send path has the chance to coalesce both into one
    // ALTERNATIVE_ADDRESS frame -- which is the shape that used to fail. The
    // assertions below hold either way: if the two changes do go out as two
    // frames, the end state is the same and the test still fails if removal
    // does not free the slot before creation is attempted.
    //
    TEST_QUIC_SUCCEEDED(
        ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_REMOVE_BOUND_ADDRESS,
            sizeof(Advertised[0].SockAddr),
            &Advertised[0].SockAddr));

    QuicAddr Replacement;
    if (!ReconcilerAdvertise(ServerContext.Connection, Host, Replacement)) {
        return;
    }

    //
    // The replacement got the slot the withdrawn address gave up.
    //
    TEST_TRUE(ReconcilerWaitForPathTo(Connection, &Replacement.SockAddr, true));
    TEST_TRUE(ReconcilerWaitForPathTo(Connection, &Advertised[0].SockAddr, false));
    TEST_EQUAL((uint32_t)QUIC_MAX_PATH_COUNT, AltServerAddressPathCount(Connection));

    //
    // And the addresses that were never withdrawn kept theirs. Without this
    // the test would pass if the reconciler had simply rebuilt every path.
    //
    for (uint32_t i = 1; i < QUIC_MAX_PATH_COUNT - 1; ++i) {
        TEST_TRUE(ReconcilerHasPathTo(Connection, &Advertised[i].SockAddr));
    }

    TEST_FALSE(ServerContext.ShutdownEvent.WaitTimeout(100));
    TEST_FALSE(ClientContext.ShutdownEvent.WaitTimeout(100));

    Connection.Shutdown(QUIC_TEST_NO_ERROR);
    TEST_TRUE(ClientContext.ShutdownEvent.WaitTimeout(TestWaitTimeout));
#endif
}

//
// Stage 3 of #157: reconciliation leaves an application's path alone.
//
// The reason stage 2 recorded an origin at all. QUIC_PARAM_CONN_ADD_PATH is
// public API, so an application can hold paths the table knows nothing about;
// a reconciler that removed every path missing from its table would delete
// them the first time it ran, which for a default-AUTO client is the first
// advertised address.
//
void
QuicTestPathReconcilerKeepsApplicationPath(
    )
{
#if !DEBUG
#else
    AltServerAddressTestContext ServerContext;
    AltServerAddressTestContext ClientContext;

    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings{}, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicSettings ClientSettings;
    ClientSettings.SetAddAddressMode(QUIC_ADD_ADDRESS_AUTO);
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientSettings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(
        Registration, ServerConfiguration, AltServerAddressTestContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());

    QuicAddr ServerLocalAddr(QUIC_ADDRESS_FAMILY_INET);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(
        Registration, CleanUpManual, AltServerAddressTestContext::ConnCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    TEST_QUIC_SUCCEEDED(
        Connection.Start(
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            QUIC_TEST_LOOPBACK_FOR_AF(QUIC_ADDRESS_FAMILY_INET),
            ServerLocalAddr.GetPort()));
    TEST_TRUE(ClientContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, ServerContext.Connection);

    CxPlatSleep(100);

    //
    // A path the application opened, from the connection's own local address
    // with a fresh port.
    //
    // Its remote is the server's address on a *different* port, and that
    // detail is the whole test. The table's remotes are the current path's and
    // whatever the peer advertised, so this endpoint cannot be in it -- which
    // is the condition that gets a path removed when provenance is not
    // checked. Pointing it at the server's real port instead looks like a
    // stronger test and is a weaker one: the pair would then match the table
    // entry for the active path, since pairs compare local addresses without
    // their port, and the path would survive whether or not anything looked at
    // its origin. Confirmed by control -- that version passed with the
    // provenance check deleted.
    //
    // Nothing answers on that port, so the path never validates. It does not
    // need to: what is under test is whether reconciliation leaves it alone.
    //
    QuicAddr AppLocal;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(AppLocal));
    QuicAddr AppRemote;
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(AppRemote));
    AppRemote.SetPort((uint16_t)(ServerLocalAddr.GetPort() ^ 0x4000));

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t Try = 0;
    do {
        AppLocal.SetEphemeralPort();
        QUIC_PATH_PARAM PathParam = { &AppLocal.SockAddr, &AppRemote.SockAddr };
        Status =
            Connection.SetParam(
                QUIC_PARAM_CONN_ADD_PATH, sizeof(PathParam), &PathParam);
    } while (QUIC_FAILED(Status) && ++Try <= 3);
    TEST_QUIC_SUCCEEDED(Status);
    TEST_EQUAL(2u, AltServerAddressPathCount(Connection));

    //
    // Now make the reconciler run, with something for it to do so that the
    // pass is not a no-op.
    //
    QuicAddr Host;
    if (!AltServerAddressHostAddress(Host)) {
        return;
    }
    QuicAddr Advertised;
    if (!ReconcilerAdvertise(ServerContext.Connection, Host, Advertised)) {
        return;
    }
    TEST_TRUE(ReconcilerWaitForPathTo(Connection, &Advertised.SockAddr, true));

    //
    // The reconciler ran and opened its own path. The application's is still
    // there, and still labelled as the application's.
    //
    uint8_t Origins[QUIC_MAX_PATH_COUNT];
    memset(Origins, 0xFF, sizeof(Origins));
    uint32_t Length = sizeof(Origins);
    TEST_QUIC_SUCCEEDED(
        MsQuic->GetParam(
            Connection.Handle, QUIC_PARAM_CONN_TEST_PATH_ORIGINS, &Length, Origins));
    TEST_EQUAL(3u, Length);

    uint32_t ApplicationCount = 0;
    uint32_t ReconcilerCount = 0;
    for (uint32_t i = 0; i < Length; ++i) {
        TEST_NOT_EQUAL((uint8_t)QUIC_PATH_ORIGIN_NONE, Origins[i]);
        if (Origins[i] == QUIC_PATH_ORIGIN_APPLICATION) {
            ApplicationCount++;
        } else if (Origins[i] == QUIC_PATH_ORIGIN_RECONCILER) {
            ReconcilerCount++;
        }
    }
    TEST_EQUAL(1u, ApplicationCount);
    TEST_EQUAL(1u, ReconcilerCount);

    //
    // Asserted on the endpoint too, not just the origin count: a reconciler
    // that removed the application's path and happened to open one of its own
    // would leave the counts looking plausible.
    //
    QUIC_TEST_PATH_ADDRESSES Addresses[QUIC_MAX_PATH_COUNT];
    const uint32_t Count =
        ReconcilerPathAddresses(Connection, Addresses, QUIC_MAX_PATH_COUNT);
    TEST_EQUAL(3u, Count);
    bool FoundApplicationPath = false;
    for (uint32_t i = 0; i < Count; ++i) {
        if (QuicAddrCompare(&Addresses[i].LocalAddress, &AppLocal.SockAddr) &&
            QuicAddrCompare(&Addresses[i].RemoteAddress, &AppRemote.SockAddr)) {
            FoundApplicationPath = true;
            break;
        }
    }
    TEST_TRUE(FoundApplicationPath);

    Connection.Shutdown(QUIC_TEST_NO_ERROR);
    TEST_TRUE(ClientContext.ShutdownEvent.WaitTimeout(TestWaitTimeout));
#endif
}

#if DEBUG
//
// Brings up a client in AUTO, with the hold-down set explicitly so the stage 4
// tests do not depend on the default, and settles on an address for the server
// to advertise.
//
// That address is chosen after the handshake, from what the client has
// demonstrably reached:
//
//   - a non-loopback remote -- the DuoNIC runs, where it is 192.168.1.11 -- is
//     used as-is, so the advertised endpoint differs from the current one only
//     in port. Picking an arbitrary interface address instead was a real bug:
//     AltServerAddressHostAddress can return the runner's own NIC, which the
//     client cannot route to from the DuoNIC interface, so the path was
//     created and never validated and the migration never happened.
//   - a loopback remote falls back to AltServerAddressHostAddress, because the
//     ALTERNATIVE_ADDRESS writer skips loopback observed addresses and there
//     would otherwise be nothing to advertise.
//
// Returns false when there is no usable address -- which on the loopback path
// means the host has none routable, the condition
// AltServerAddressHostAddress reports -- and the caller skips rather than
// pretends.
//
struct TableMigrationTest {
    AltServerAddressTestContext ServerContext;
    AltServerAddressTestContext ClientContext;
    MsQuicRegistration Registration {true};
    QuicAddr Host;

    bool
    Start(
        MsQuicConnection*& Connection,
        uint32_t HoldDownMs,
        QUIC_ADD_ADDRESS_MODE Mode = QUIC_ADD_ADDRESS_AUTO,
        uint32_t InitialRttMs = 0
        )
    {
        if (!Registration.IsValid()) {
            return false;
        }

        ServerConfiguration =
            new(std::nothrow) MsQuicConfiguration(
                Registration, "MsQuicTest", MsQuicSettings{}, ServerSelfSignedCredConfig);
        if (ServerConfiguration == nullptr || !ServerConfiguration->IsValid()) {
            return false;
        }

        MsQuicSettings ClientSettings;
        ClientSettings.SetAddAddressMode(Mode);
        ClientSettings.AutoMigrationHoldDownMs = HoldDownMs;
        ClientSettings.IsSet.AutoMigrationHoldDownMs = TRUE;

        if (InitialRttMs != 0) {
            //
            // The path validation timeout is six times this, so it is what
            // decides how long a validation that will never be answered takes
            // to give up. Left alone by default.
            //
            ClientSettings.SetInitialRttMs((uint16_t)InitialRttMs);
        }
        ClientConfiguration =
            new(std::nothrow) MsQuicConfiguration(
                Registration, "MsQuicTest", ClientSettings, MsQuicCredentialConfig{});
        if (ClientConfiguration == nullptr || !ClientConfiguration->IsValid()) {
            return false;
        }

        Listener =
            new(std::nothrow) MsQuicAutoAcceptListener(
                Registration, *ServerConfiguration,
                AltServerAddressTestContext::ConnCallback, &ServerContext);
        if (Listener == nullptr || QUIC_FAILED(Listener->GetInitStatus())) {
            return false;
        }

        QuicAddrSetFamily(&ServerLocalAddr.SockAddr, QUIC_ADDRESS_FAMILY_INET);
        if (QUIC_FAILED(Listener->Start("MsQuicTest", &ServerLocalAddr.SockAddr)) ||
            QUIC_FAILED(Listener->GetLocalAddr(ServerLocalAddr))) {
            return false;
        }

        Client =
            new(std::nothrow) MsQuicConnection(
                Registration, CleanUpManual,
                AltServerAddressTestContext::ConnCallback, &ClientContext);
        if (Client == nullptr || QUIC_FAILED(Client->GetInitStatus())) {
            return false;
        }
        if (QUIC_FAILED(
                Client->Start(
                    *ClientConfiguration,
                    QUIC_ADDRESS_FAMILY_INET,
                    QUIC_TEST_LOOPBACK_FOR_AF(QUIC_ADDRESS_FAMILY_INET),
                    ServerLocalAddr.GetPort()))) {
            return false;
        }
        if (!ClientContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout) ||
            !ServerContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout) ||
            ServerContext.Connection == nullptr) {
            return false;
        }

        //
        // Handshake confirmation, as the other add-path tests wait for.
        //
        CxPlatSleep(100);

        //
        // The address the server will advertise, chosen only now because it has
        // to be one the client can validate a path to -- these tests migrate,
        // and a migration needs the peer to answer a challenge on the new
        // path.
        //
        // The address the connection is already on is that address by
        // construction, so it is the first choice. On the DuoNIC runs it is
        // 192.168.1.11 and picking an arbitrary interface address instead was
        // the bug: AltServerAddressHostAddress can return the runner's real
        // NIC, which the client cannot route to from the DuoNIC interface, so
        // the path was created and never validated and the migration never
        // happened. Basic.AlternativeServerAddressAuto did not notice because
        // it only waits for the path to exist.
        //
        // Loopback is the exception, and the reason the fallback stays: the
        // ALTERNATIVE_ADDRESS writer skips loopback observed addresses, so
        // there would be nothing to advertise.
        //
        QuicAddr Remote;
        if (QUIC_FAILED(Client->GetRemoteAddr(Remote))) {
            return false;
        }
        //
        // IS_LOOPBACK, which is what the ALTERNATIVE_ADDRESS writer itself
        // tests (send.c). The question here is exactly "will the writer skip
        // this address", so asking it any other way can disagree with the
        // answer that matters -- a hand-rolled 127/8 check would, since the
        // POSIX macro matches only 127.0.0.1.
        //
        if (IS_LOOPBACK(Remote.SockAddr)) {
            if (!AltServerAddressHostAddress(Host)) {
                return false;
            }
        } else {
            Host = Remote;
            Host.SetPort(0);
        }

        Connection = Client;
        return true;
    }

    ~TableMigrationTest() {
        delete Client;
        delete Listener;
        delete ClientConfiguration;
        delete ServerConfiguration;
    }

    QuicAddr ServerLocalAddr;
    MsQuicConfiguration* ServerConfiguration {nullptr};
    MsQuicConfiguration* ClientConfiguration {nullptr};
    MsQuicAutoAcceptListener* Listener {nullptr};
    MsQuicConnection* Client {nullptr};
};

//
// The remote address of the client's active path, which is Paths[0].
//
static bool
TableMigrationActiveRemote(
    MsQuicConnection& Conn,
    QUIC_ADDR* Remote
    )
{
    QUIC_TEST_PATH_ADDRESSES Addresses[QUIC_MAX_PATH_COUNT];
    if (ReconcilerPathAddresses(Conn, Addresses, QUIC_MAX_PATH_COUNT) == 0) {
        return false;
    }
    *Remote = Addresses[0].RemoteAddress;
    return true;
}

static bool
TableMigrationWaitForActiveRemote(
    MsQuicConnection& Conn,
    const QUIC_ADDR* Expected,
    uint32_t TimeoutMs
    )
{
    for (uint32_t Waited = 0; Waited < TimeoutMs; Waited += 50) {
        QUIC_ADDR Active;
        if (TableMigrationActiveRemote(Conn, &Active) &&
            QuicAddrCompare(&Active, Expected)) {
            return true;
        }
        CxPlatSleep(50);
    }
    return false;
}
#endif // DEBUG

//
// Stage 4 of #157: the client migrates onto the pair the table puts at its
// head, when the server has said it would rather be reached there.
//
void
QuicTestTableMigration(
    )
{
#if !DEBUG
    //
    // Reads the paths' endpoints through a debug-only parameter, and needs the
    // debug-only way for a server to mark an address preferred.
    //
#else
    TableMigrationTest Test;
    MsQuicConnection* Conn = nullptr;
    if (!Test.Start(Conn, 1000)) {
        return;
    }

    QUIC_ADDR OriginalRemote;
    TEST_TRUE(TableMigrationActiveRemote(*Conn, &OriginalRemote));
    TEST_EQUAL(1u, AltServerAddressPathCount(*Conn));

    //
    // A second address the server really is listening on, advertised as
    // preferred to the path the frame goes out on.
    //
    QuicAddr Advertised;
    if (!ReconcilerAdvertise(Test.ServerContext.Connection, Test.Host, Advertised)) {
        return;
    }

    //
    // Backup first, so the test shows the preference is what causes the move
    // and not merely the address appearing. The reconciler opens a path to it
    // either way -- that is stage 3 -- but must not make it active.
    //
    TEST_TRUE(ReconcilerWaitForPathTo(*Conn, &Advertised.SockAddr, true));
    CxPlatSleep(250);
    QUIC_ADDR StillOriginal;
    TEST_TRUE(TableMigrationActiveRemote(*Conn, &StillOriginal));
    TEST_TRUE(QuicAddrCompare(&StillOriginal, &OriginalRemote));

    //
    // Now the preference.
    //
    TEST_QUIC_SUCCEEDED(
        Test.ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_PREFER_OBSERVED_ADDRESS,
            sizeof(Advertised.SockAddr),
            &Advertised.SockAddr));

    //
    // Make-before-break, so the move waits for the peer to answer the
    // challenge on the new path. Generous, because that is a round trip plus a
    // hold-down window plus the reconciliation pass that completes it.
    //
    TEST_TRUE(TableMigrationWaitForActiveRemote(*Conn, &Advertised.SockAddr, 5000));

    //
    // And the break: the old path is gone rather than left as a spare, so the
    // connection is back to one path.
    //
    TEST_TRUE(AltServerAddressWaitForPathCount(*Conn, 1));

    //
    // The server sees it too. Its local address for this connection is now the
    // advertised one, which is what "the server observes traffic from the new
    // address" means from inside the test -- and it is the half that would
    // still fail if the client had activated a path the server never saw
    // traffic on.
    //
    QuicAddr ServerLocal;
    for (uint32_t Waited = 0; Waited < 3000; Waited += 50) {
        if (QUIC_SUCCEEDED(Test.ServerContext.Connection->GetLocalAddr(ServerLocal)) &&
            QuicAddrCompare(&ServerLocal.SockAddr, &Advertised.SockAddr)) {
            break;
        }
        CxPlatSleep(50);
    }
    TEST_TRUE(QuicAddrCompare(&ServerLocal.SockAddr, &Advertised.SockAddr));

    TEST_FALSE(Test.ServerContext.ShutdownEvent.WaitTimeout(100));
    TEST_FALSE(Test.ClientContext.ShutdownEvent.WaitTimeout(100));
#endif
}

//
// Stage 4 of #157: a backup-only advertisement moves nothing.
//
// The complement of the test above: that one checks the move happens, this one
// checks it does not happen without being asked for. It covers the third of
// #162's "done when" items directly.
//
// What it does *not* do, despite looking as though it should, is isolate the
// sentinel check -- deleting that check leaves this test passing. Verified by
// control rather than assumed.
//
// The reason is that the pair the connection is already on heads the table
// here, so the "already there" test returns before the sentinel is consulted.
// It heads it on the sentinel rank itself: every pair is route-preferred for
// its own remote, so that key ties, and CURRENT sorts above BACKUP. A backup
// could only head the table if there were no current pair at all. The sentinel
// ordering is covered by the unit tests in CandidateTest, and that the
// preference is what triggers a move is covered by the test above, which does
// fail if the server's mark is ignored.
//
void
QuicTestTableMigrationBackupOnly(
    )
{
#if !DEBUG
#else
    TableMigrationTest Test;
    MsQuicConnection* Conn = nullptr;
    if (!Test.Start(Conn, 0)) {
        return;
    }

    QUIC_ADDR OriginalRemote;
    TEST_TRUE(TableMigrationActiveRemote(*Conn, &OriginalRemote));

    //
    // Two advertised addresses, both backups, which is what the writer emits
    // unless told otherwise. The table ranks them and puts one at its head;
    // neither is a reason to move.
    //
    QuicAddr First;
    QuicAddr Second;
    if (!ReconcilerAdvertise(Test.ServerContext.Connection, Test.Host, First) ||
        !ReconcilerAdvertise(Test.ServerContext.Connection, Test.Host, Second)) {
        return;
    }
    TEST_TRUE(ReconcilerWaitForPathTo(*Conn, &First.SockAddr, true));
    TEST_TRUE(ReconcilerWaitForPathTo(*Conn, &Second.SockAddr, true));

    //
    // Hold-down is zero for this one, so a non-migration cannot be blamed on
    // rate limiting.
    //
    CxPlatSleep(500);

    QUIC_ADDR Active;
    TEST_TRUE(TableMigrationActiveRemote(*Conn, &Active));
    TEST_TRUE(QuicAddrCompare(&Active, &OriginalRemote));

    //
    // Still three paths, so the reconciler did its own job -- a test that
    // passed because nothing happened at all would be worthless here.
    //
    TEST_EQUAL(3u, AltServerAddressPathCount(*Conn));
#endif
}

//
// Stage 4 of #157: the hold-down rate-limits repeated preference changes.
//
void
QuicTestTableMigrationHoldDown(
    )
{
#if !DEBUG
#else
    //
    // Long enough that the delay is unambiguous against scheduling noise, and
    // short enough to wait out twice.
    //
    const uint32_t HoldDownMs = 3000;

    TableMigrationTest Test;
    MsQuicConnection* Conn = nullptr;
    if (!Test.Start(Conn, HoldDownMs)) {
        return;
    }

    QuicAddr First;
    QuicAddr Second;
    if (!ReconcilerAdvertise(Test.ServerContext.Connection, Test.Host, First) ||
        !ReconcilerAdvertise(Test.ServerContext.Connection, Test.Host, Second)) {
        return;
    }
    TEST_TRUE(ReconcilerWaitForPathTo(*Conn, &First.SockAddr, true));
    TEST_TRUE(ReconcilerWaitForPathTo(*Conn, &Second.SockAddr, true));

    //
    // The first preference. Opening those two paths charged the hold-down, so
    // even this one waits -- which is the behaviour under test, just from the
    // other end.
    //
    TEST_QUIC_SUCCEEDED(
        Test.ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_PREFER_OBSERVED_ADDRESS,
            sizeof(First.SockAddr),
            &First.SockAddr));
    TEST_TRUE(TableMigrationWaitForActiveRemote(*Conn, &First.SockAddr, 3 * HoldDownMs));

    //
    // The second, immediately after. The hold-down was charged by the
    // migration that just completed, so this must not take effect yet.
    //
    TEST_QUIC_SUCCEEDED(
        Test.ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_PREFER_OBSERVED_ADDRESS,
            sizeof(Second.SockAddr),
            &Second.SockAddr));

    CxPlatSleep(HoldDownMs / 3);
    QUIC_ADDR Active;
    TEST_TRUE(TableMigrationActiveRemote(*Conn, &Active));
    TEST_TRUE(QuicAddrCompare(&Active, &First.SockAddr));

    //
    // And then it does, without anything further happening on the connection.
    // That is the half that matters: a held-down attempt has to come back by
    // itself, not wait for the next unrelated change.
    //
    TEST_TRUE(TableMigrationWaitForActiveRemote(*Conn, &Second.SockAddr, 3 * HoldDownMs));
#endif
}

//
// Stage 4 of #157: one advertisement is worth at most one migration.
//
// This is the failure the hold-down test turned up, and it is worth its own
// test because it is not a wrong move -- every individual move is to a pair
// the table ranks above the one in use -- it is an endless series of right
// moves. The server marks two addresses preferred to the current path; the
// client moves to one; the other is still marked preferred and still ranks
// above the path now in use, so the next pass moves there, where the first
// ranks above it again.
//
// It is not self-sustaining: a reconciliation pass needs a trigger, and
// nothing in the loop provides one. What makes it matter is that almost
// anything else does -- a local address change, a route change, a later frame
// -- so on a connection that sees any churn at all the server's one statement
// keeps moving it, with no new information from the server.
//
// So the test supplies those triggers, with injected route changes, and
// asserts the connection does not move. Without them it asserts nothing: a
// version of this that merely waited and sampled passed with the guard
// deleted, because no pass ran in the quiet.
//
void
QuicTestTableMigrationNoFlap(
    )
{
#if !DEBUG
#else
    const uint32_t HoldDownMs = 200;

    TableMigrationTest Test;
    MsQuicConnection* Conn = nullptr;
    //
    // An injected route change reaches the reconciler in AUTO, which since
    // stage 5 is the only mode setting involved.
    //
    if (!Test.Start(Conn, HoldDownMs)) {
        return;
    }

    QuicAddr First;
    QuicAddr Second;
    if (!ReconcilerAdvertise(Test.ServerContext.Connection, Test.Host, First) ||
        !ReconcilerAdvertise(Test.ServerContext.Connection, Test.Host, Second)) {
        return;
    }
    TEST_TRUE(ReconcilerWaitForPathTo(*Conn, &First.SockAddr, true));
    TEST_TRUE(ReconcilerWaitForPathTo(*Conn, &Second.SockAddr, true));

    //
    // Both preferred.
    //
    TEST_QUIC_SUCCEEDED(
        Test.ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_PREFER_OBSERVED_ADDRESS,
            sizeof(First.SockAddr),
            &First.SockAddr));
    TEST_QUIC_SUCCEEDED(
        Test.ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_PREFER_OBSERVED_ADDRESS,
            sizeof(Second.SockAddr),
            &Second.SockAddr));

    //
    // Let it act on what those authorise. Several windows, so that however the
    // two changes were framed, every migration they allow has happened by the
    // end of it.
    //
    CxPlatSleep(HoldDownMs * 8);

    QUIC_ADDR Settled;
    TEST_TRUE(TableMigrationActiveRemote(*Conn, &Settled));

    //
    // It did move somewhere the server asked for, so what follows is not
    // passing because nothing ever happened.
    //
    TEST_TRUE(
        QuicAddrCompare(&Settled, &First.SockAddr) ||
        QuicAddrCompare(&Settled, &Second.SockAddr));

    //
    // Now the triggers. Each injected route change runs a reconciliation, and
    // each one is a chance to act on the server's spent statement again. The
    // route itself has not moved -- one interface, so the route-derived local
    // address is the one already in use -- so a route migration has nothing to
    // do and anything that moves is this.
    //
    for (uint32_t i = 0; i < 8; ++i) {
        TEST_QUIC_SUCCEEDED(
            MsQuic->SetParam(
                nullptr, QUIC_PARAM_GLOBAL_TEST_INJECT_ROUTE_CHANGE, 0, nullptr));
        CxPlatSleep(HoldDownMs + 100);

        QUIC_ADDR Active;
        TEST_TRUE(TableMigrationActiveRemote(*Conn, &Active));
        TEST_TRUE(QuicAddrCompare(&Active, &Settled));
    }

    TEST_FALSE(Test.ServerContext.ShutdownEvent.WaitTimeout(100));
    TEST_FALSE(Test.ClientContext.ShutdownEvent.WaitTimeout(100));
#endif
}

//
// Stage 4 of #157: a migration whose path never validates does not disable
// every later one.
//
// The markers that track a make-before-break attempt are shared between the
// two migrations, and nothing on the table side released them if the attempt's
// path went away: the validation timer removes the path, knowing nothing about
// what it was for, and the next pass then returns at "one attempt at a time"
// for the life of the connection. One firewalled address the server advertised
// was enough to disable every future migration -- and route migrations with
// them.
//
// Silent, which is why it is worth a test rather than only a fix. Nothing
// fails; the connection simply stops taking the server's advice.
//
void
QuicTestTableMigrationAfterFailure(
    )
{
#if !DEBUG
#else
    //
    // No hold-down, so the only delay in the test is the validation timeout,
    // and a small initial RTT so that timeout is six times something small.
    //
    TableMigrationTest Test;
    MsQuicConnection* Conn = nullptr;
    if (!Test.Start(Conn, 0, QUIC_ADD_ADDRESS_AUTO, 50)) {
        return;
    }

    QUIC_ADDR OriginalRemote;
    TEST_TRUE(TableMigrationActiveRemote(*Conn, &OriginalRemote));

    //
    // An address the server advertises but is not listening on. The observed
    // address is a separate field from the bound one, so the server can bind a
    // real port and advertise a different one -- which is exactly the
    // firewalled-address case: the client can open a path to it, and the
    // challenge will never be answered.
    //
    QuicAddr Bound;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t Try = 0;
    do {
        Bound = Test.Host;
        Bound.SetEphemeralPort();
        Status =
            Test.ServerContext.Connection->SetParam(
                QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                sizeof(Bound.SockAddr),
                &Bound.SockAddr);
    } while (QUIC_FAILED(Status) && ++Try <= 5);
    TEST_QUIC_SUCCEEDED(Status);

    //
    // A port nothing is listening on. Re-rolled until it differs from the
    // connection's own remote endpoint: Test.Host is the server's address on
    // the DuoNIC runs, so a port that happened to equal the listener's would
    // name the live server rather than a dead end -- and nothing would catch
    // it, because this address is only ever advertised and never bound, and
    // QUIC_PARAM_CONN_ADD_OBSERVED_ADDRESS does not check for a collision.
    //
    QuicAddr ClientRemote;
    TEST_QUIC_SUCCEEDED(Conn->GetRemoteAddr(ClientRemote));
    QuicAddr Dead = Test.Host;
    Dead.SetPort((uint16_t)(Bound.GetPort() ^ 0x4000));
    for (uint32_t i = 0; i < 16 && QuicAddrCompare(&Dead.SockAddr, &ClientRemote.SockAddr); ++i) {
        Dead.SetEphemeralPort();
    }
    TEST_FALSE(QuicAddrCompare(&Dead.SockAddr, &ClientRemote.SockAddr));
    QUIC_ADD_OBSERVED_ADDRESS AddDead = { &Bound.SockAddr, &Dead.SockAddr };
    TEST_QUIC_SUCCEEDED(
        Test.ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_ADD_OBSERVED_ADDRESS,
            sizeof(AddDead),
            &AddDead));
    TEST_QUIC_SUCCEEDED(
        Test.ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_PREFER_OBSERVED_ADDRESS,
            sizeof(Dead.SockAddr),
            &Dead.SockAddr));

    //
    // The client opens a path to it and starts an attempt that cannot finish.
    // Then the validation gives up and the path goes away.
    //
    TEST_TRUE(ReconcilerWaitForPathTo(*Conn, &Dead.SockAddr, true));
    TEST_TRUE(ReconcilerWaitForPathTo(*Conn, &Dead.SockAddr, false));

    //
    // Still on the original path, which is the right outcome for an address
    // that never answered.
    //
    QUIC_ADDR Active;
    TEST_TRUE(TableMigrationActiveRemote(*Conn, &Active));
    TEST_TRUE(QuicAddrCompare(&Active, &OriginalRemote));

    //
    // The server takes the dead address back before offering a live one.
    //
    // Needed to isolate what this test is about. Left advertised, the dead
    // address stays in the table and keeps winning the head -- both are
    // preferred and nothing else separates them, so the tie breaks on the
    // address bytes -- and the reconciler keeps re-opening a path to it that
    // keeps timing out. That is the server's instruction being followed, and
    // arguably right, but it starves the live address and would make this test
    // fail for a reason that has nothing to do with the stuck marker.
    //
    TEST_QUIC_SUCCEEDED(
        Test.ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_REMOVE_BOUND_ADDRESS,
            sizeof(Bound.SockAddr),
            &Bound.SockAddr));

    //
    // And now one that does answer. This is the assertion the whole test is
    // for: with the marker stuck, the client ignores it.
    //
    QuicAddr Good;
    if (!ReconcilerAdvertise(Test.ServerContext.Connection, Test.Host, Good)) {
        return;
    }
    TEST_TRUE(ReconcilerWaitForPathTo(*Conn, &Good.SockAddr, true));
    TEST_QUIC_SUCCEEDED(
        Test.ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_PREFER_OBSERVED_ADDRESS,
            sizeof(Good.SockAddr),
            &Good.SockAddr));

    TEST_TRUE(TableMigrationWaitForActiveRemote(*Conn, &Good.SockAddr, 5000));
#endif
}

//
// Stage 5 of #157: MANUAL builds no table and touches no path.
//
// The mode's contract is that the application is the interface. AUTO has had
// tests since stage 3; this is the one that says the other half of the switch
// actually switches, and it checks the strong form -- not just "no migration"
// but "no table", because a table is what every path change here comes from.
//
void
QuicTestModeManual(
    )
{
#if !DEBUG
#else
    TableMigrationTest Test;
    MsQuicConnection* Conn = nullptr;
    if (!Test.Start(Conn, 0, QUIC_ADD_ADDRESS_MANUAL)) {
        return;
    }

    QUIC_ADDR OriginalRemote;
    TEST_TRUE(TableMigrationActiveRemote(*Conn, &OriginalRemote));
    TEST_EQUAL(1u, AltServerAddressPathCount(*Conn));

    //
    // An advertised address, marked preferred -- the strongest thing a server
    // can say. In AUTO this opens a path and then migrates onto it.
    //
    QuicAddr Advertised;
    if (!ReconcilerAdvertise(Test.ServerContext.Connection, Test.Host, Advertised)) {
        return;
    }
    TEST_QUIC_SUCCEEDED(
        Test.ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_PREFER_OBSERVED_ADDRESS,
            sizeof(Advertised.SockAddr),
            &Advertised.SockAddr));

    //
    // The application is told, which is the whole of what MANUAL does.
    //
    TEST_TRUE(Test.ClientContext.AddedEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(QuicAddrCompare(&Advertised.SockAddr, &Test.ClientContext.AddedAddress.SockAddr));

    //
    // And nothing else. Waited out rather than read once: a path opened or a
    // migration started would happen asynchronously, so a single read here
    // could beat it.
    //
    CxPlatSleep(500);
    TEST_EQUAL(1u, AltServerAddressPathCount(*Conn));
    QUIC_ADDR Active;
    TEST_TRUE(TableMigrationActiveRemote(*Conn, &Active));
    TEST_TRUE(QuicAddrCompare(&Active, &OriginalRemote));

    //
    // The application can still do it by hand, which is the point of the mode:
    // nothing happened above because nothing was asked for, not because paths
    // cannot be opened.
    //
    // To the connection's own remote address with a fresh port, not to the
    // advertised one. The advertised address is a real interface address --
    // it has to be, because the frame writer skips loopback -- and the
    // connection's local address is loopback, so a path between them is
    // unroutable and ADD_PATH fails with WSAENETUNREACH. That is what this
    // test did, and the comment here used to claim the opposite. Fourth time
    // in this work that a test picked an address the datapath could not use;
    // the rule that keeps holding is to use what the connection has already
    // proved it can carry.
    //
    QuicAddr AppLocal;
    TEST_QUIC_SUCCEEDED(Conn->GetLocalAddr(AppLocal));
    QuicAddr AppRemote;
    TEST_QUIC_SUCCEEDED(Conn->GetRemoteAddr(AppRemote));
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t Try = 0;
    do {
        AppLocal.SetEphemeralPort();
        QUIC_PATH_PARAM PathParam = { &AppLocal.SockAddr, &AppRemote.SockAddr };
        Status = Conn->SetParam(QUIC_PARAM_CONN_ADD_PATH, sizeof(PathParam), &PathParam);
    } while (QUIC_FAILED(Status) && ++Try <= 3);
    TEST_QUIC_SUCCEEDED(Status);
    TEST_EQUAL(2u, AltServerAddressPathCount(*Conn));

    //
    // Still the application's path, not reconciliation's.
    //
    uint8_t Origins[QUIC_MAX_PATH_COUNT];
    memset(Origins, 0xFF, sizeof(Origins));
    uint32_t Length = sizeof(Origins);
    TEST_QUIC_SUCCEEDED(
        MsQuic->GetParam(
            Conn->Handle, QUIC_PARAM_CONN_TEST_PATH_ORIGINS, &Length, Origins));
    TEST_EQUAL(2u, Length);
    for (uint32_t i = 0; i < Length; ++i) {
        TEST_NOT_EQUAL((uint8_t)QUIC_PATH_ORIGIN_RECONCILER, Origins[i]);
    }
#endif
}

//
// Stage 5 of #157: NAT_TRAVERSAL stays on the older ADD_ADDRESS mechanism, so
// an advertised address does nothing on its own.
//
// Not the test this was meant to be, and the reason is worth stating. #163
// tables NAT_TRAVERSAL as "table built, but a pair produces no path unless a
// candidate is configured". That code is here -- the candidate requirement and
// the punch-before-probe are in QuicConnReconcileCreatePaths -- but it cannot
// be reached yet: a NAT_TRAVERSAL client deliberately does not offer the
// alternative_address transport parameter, because PUNCH_ME_NOW names the
// server's address by a per-address sequence number that only the older
// ADD_ADDRESS frames carry. So the table's remote set is just the current
// path's, and with one path per remote outside multipath there is no pair to
// create anything for.
//
// #173 is what unblocks it: once PUNCH_ME_NOW names the address directly, the
// parameter can be offered and the advertised set becomes table remotes. Until
// then what is testable is the boundary itself -- that this mode does not act
// on ALTERNATIVE_ADDRESS -- and that is what this asserts. It is also the
// mode's first test of any kind.
//
void
QuicTestModeNatTraversal(
    )
{
#if !DEBUG
#else
    TableMigrationTest Test;
    MsQuicConnection* Conn = nullptr;
    if (!Test.Start(Conn, 0, QUIC_ADD_ADDRESS_NAT_TRAVERSAL)) {
        return;
    }

    QUIC_ADDR OriginalRemote;
    TEST_TRUE(TableMigrationActiveRemote(*Conn, &OriginalRemote));
    TEST_EQUAL(1u, AltServerAddressPathCount(*Conn));

    //
    // An advertised address, marked preferred. In AUTO this opens a path and
    // migrates onto it; in MANUAL it raises an event.
    //
    QuicAddr Advertised;
    if (!ReconcilerAdvertise(Test.ServerContext.Connection, Test.Host, Advertised)) {
        return;
    }
    //
    // The server cannot even express a preference to this client: marking an
    // address preferred is an ALTERNATIVE_ADDRESS concept, and the extension
    // was never negotiated. Refused rather than silently ignored, so a server
    // that tries finds out.
    //
    TEST_EQUAL(
        QUIC_STATUS_INVALID_STATE,
        Test.ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_PREFER_OBSERVED_ADDRESS,
            sizeof(Advertised.SockAddr),
            &Advertised.SockAddr));

    CxPlatSleep(500);

    //
    // Neither. No path, no migration, and no report -- the client never asked
    // the server to use this extension, so there is nothing to act on.
    //
    TEST_EQUAL(1u, AltServerAddressPathCount(*Conn));
    TEST_FALSE(ReconcilerHasPathTo(*Conn, &Advertised.SockAddr));
    QUIC_ADDR Active;
    TEST_TRUE(TableMigrationActiveRemote(*Conn, &Active));
    TEST_TRUE(QuicAddrCompare(&Active, &OriginalRemote));
    TEST_EQUAL(0u, Test.ClientContext.AddedCount);

    //
    // And the connection is unharmed by the frames it chose not to negotiate.
    // Worth asserting: the server falls back to the older ADD_ADDRESS frames
    // for a peer that did not offer the extension, and a client that mishandled
    // those would abort rather than merely ignore them.
    //
    TEST_FALSE(Test.ServerContext.ShutdownEvent.WaitTimeout(100));
    TEST_FALSE(Test.ClientContext.ShutdownEvent.WaitTimeout(100));
#endif
}

#if DEBUG
//
// A second address on the same host that a connection could be carried by.
// Only 127/8 qualifies -- a loopback connection cannot be carried by a real
// interface address, and IPv6 has only ::1 -- so this answers only for IPv4
// loopback and the caller skips otherwise. The same reasoning, and the same
// limitation, as AlternateLoopbackAddress in AddressChangeTest.cpp.
//
static
bool
AlternateLoopbackAddressForPathTest(
    _In_ const QUIC_ADDR* Address,
    _Out_ QUIC_ADDR* Alternate
    )
{
    if (QuicAddrGetFamily(Address) != QUIC_ADDRESS_FAMILY_INET) {
        return false;
    }
    CxPlatZeroMemory(Alternate, sizeof(*Alternate));
    if (!QuicAddrFromString("127.0.0.2", 0, Alternate)) {
        return false;
    }
    if (QuicAddrCompareIp(Address, Alternate)) {
        return QuicAddrFromString("127.0.0.3", 0, Alternate);
    }
    return true;
}

//
// Stage 6 of #157: the server's whole use of local address detection.
//
// Builds the one shape the server acts on -- multipath, and a server path on a
// local address other than the one the connection arrived on -- and takes that
// address away.
//
// Getting there needs a little care. The client cannot learn the server's
// second address from ALTERNATIVE_ADDRESS, because the frame writer skips
// loopback observed addresses and loopback is the only place a second bindable
// address exists on a test host. So the client opens the path by hand, to the
// server's second bound address, and the server's side of it is created by
// QuicConnGetPathForPacket when the probe arrives. The client is in MANUAL
// throughout, so nothing on its side reacts to the injection and what the test
// observes is the server's doing alone.
//
static
void
RunServerLostAddressTest(
    _In_ bool MultipathEnabled
    )
{
    PathTestContext ServerContext;
    PathTestClientContext ClientContext;

    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicSettings ServerSettings;
    ServerSettings.SetMultipathEnabled(MultipathEnabled ? TRUE : FALSE);
    MsQuicConfiguration ServerConfiguration(
        Registration, "MsQuicTest", ServerSettings, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    //
    // MANUAL on the client, so its own address handling does nothing and the
    // server is the only thing that can react.
    //
    MsQuicSettings ClientSettings;
    ClientSettings.SetMultipathEnabled(MultipathEnabled ? TRUE : FALSE);
    ClientSettings.SetAddAddressMode(QUIC_ADD_ADDRESS_MANUAL);
    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(
        Registration, "MsQuicTest", ClientSettings, ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(
        Registration, ServerConfiguration, PathTestContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());

    QuicAddr ServerLocalAddr(QUIC_ADDRESS_FAMILY_INET);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(
        Registration, CleanUpManual, PathTestClientContext::ClientCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    Connection.SetShareUdpBinding();
    TEST_QUIC_SUCCEEDED(
        Connection.Start(
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            QUIC_TEST_LOOPBACK_FOR_AF(QUIC_ADDRESS_FAMILY_INET),
            ServerLocalAddr.GetPort()));
    TEST_TRUE(ClientContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, ServerContext.Connection);
    CxPlatSleep(100);

    //
    // A second loopback address for the server to be reachable at. Only 127/8
    // offers one, so the test skips where it cannot have it.
    //
    QuicAddr ClientLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(ClientLocalAddr));
    QUIC_ADDR SecondServerIp;
    if (!AlternateLoopbackAddressForPathTest(&ServerLocalAddr.SockAddr, &SecondServerIp)) {
        return;
    }
    //
    // An ephemeral port, not the listener's. The listener already holds that
    // port and binding it again on a second loopback address is refused.
    // Which port does not matter: the client names the endpoint explicitly
    // below rather than discovering it.
    //
    QuicAddr SecondServerAddr;
    QUIC_STATUS BindStatus = QUIC_STATUS_SUCCESS;
    uint32_t BindTry = 0;
    do {
        SecondServerAddr.SockAddr = SecondServerIp;
        SecondServerAddr.SetEphemeralPort();
        BindStatus =
            ServerContext.Connection->SetParam(
                QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                sizeof(SecondServerAddr.SockAddr),
                &SecondServerAddr.SockAddr);
    } while (QUIC_FAILED(BindStatus) && ++BindTry <= 5);
    TEST_QUIC_SUCCEEDED(BindStatus);

    //
    // The client opens a path to it. The server's side of that path is created
    // when the probe lands, with the second address as its local.
    //
    QuicAddr ClientSecond = ClientLocalAddr;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t Try = 0;
    do {
        ClientSecond.SetEphemeralPort();
        QUIC_PATH_PARAM PathParam =
            { &ClientSecond.SockAddr, &SecondServerAddr.SockAddr };
        Status =
            Connection.SetParam(
                QUIC_PARAM_CONN_ADD_PATH, sizeof(PathParam), &PathParam);
    } while (QUIC_FAILED(Status) && ++Try <= 3);
    TEST_QUIC_SUCCEEDED(Status);

    //
    // Wait for the server to have two paths, which is what says its side of
    // the new path exists.
    //
    bool ServerHasTwo = false;
    for (uint32_t i = 0; i < 100 && !ServerHasTwo; ++i) {
        CxPlatSleep(50);
        ServerHasTwo = AltServerAddressPathCount(*ServerContext.Connection) == 2;
    }
    if (!ServerHasTwo) {
        //
        // The probe never got through -- without multipath the peer may not
        // issue a connection ID for it. Nothing to take away, so nothing to
        // test; skipped rather than failed.
        //
        return;
    }

    ServerContext.PathRemovedEvent.Reset();
    ClientContext.PathRemovedEvent.Reset();

    //
    // Now the server's second address goes away. The injected set keeps the
    // address the connection arrived on and the client's, so the only thing
    // lost is the server's second path.
    //
    QUIC_ADDR Keep[2];
    Keep[0] = ServerLocalAddr.SockAddr;
    QuicAddrSetPort(&Keep[0], 0);
    Keep[1] = ClientLocalAddr.SockAddr;
    QuicAddrSetPort(&Keep[1], 0);
    TEST_QUIC_SUCCEEDED(
        MsQuic->SetParam(
            nullptr,
            QUIC_PARAM_GLOBAL_TEST_INJECT_ADDRESS_CHANGE,
            sizeof(Keep),
            Keep));

    if (MultipathEnabled) {
        //
        // Abandoned, and the peer is told -- which is the requirement from
        // draft-ietf-quic-multipath section 3.4 and the whole reason the
        // server does this at all.
        //
        TEST_TRUE(AltServerAddressWaitForPathCount(*ServerContext.Connection, 1));
        TEST_TRUE(ClientContext.PathRemovedEvent.WaitTimeout(TestWaitTimeout));
    } else {
        //
        // Without multipath the server does nothing. A second path there is a
        // validation candidate rather than somewhere traffic goes, and the one
        // path that matters is the one the client chose.
        //
        CxPlatSleep(500);
        TEST_EQUAL(2u, AltServerAddressPathCount(*ServerContext.Connection));
    }

    //
    // Either way the connection is alive: this is a tidy-up, not a teardown.
    //
    TEST_FALSE(ServerContext.ShutdownEvent.WaitTimeout(100));
    TEST_FALSE(ClientContext.ShutdownEvent.WaitTimeout(100));

    Connection.Shutdown(QUIC_TEST_NO_ERROR);
    TEST_TRUE(ClientContext.ShutdownEvent.WaitTimeout(TestWaitTimeout));
}
#endif // DEBUG

void
QuicTestServerLostAddressAbandonsPath(
    )
{
#if !DEBUG
    //
    // Needs the debug-only address injection.
    //
#else
    RunServerLostAddressTest(true);
#endif
}

void
QuicTestServerLostAddressWithoutMultipath(
    )
{
#if !DEBUG
#else
    RunServerLostAddressTest(false);
#endif
}

#endif // QUIC_API_ENABLE_PREVIEW_FEATURES
