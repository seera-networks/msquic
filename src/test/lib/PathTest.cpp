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

void
QuicTestPathRequiredMtu(
    _In_ const FamilyArgs& Params
    )
{
    const int Family = Params.Family;

    PathTestContext Context;
    PathTestClientContext ClientContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    //
    // The MTU is pinned so every path settles on exactly this value, which
    // makes "one above it" a requirement no path can ever meet and "the value
    // itself" one they all meet as soon as they are up.
    //
    const uint16_t FixedMtu = 1280;

    MsQuicSettings Settings;
    Settings.SetMultipathEnabled(TRUE).SetMinimumMtu(FixedMtu).SetMaximumMtu(FixedMtu);

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

    //
    // Round-trips, and rejects a requirement the connection could never reach.
    //
    uint16_t Required = FixedMtu;
    TEST_QUIC_SUCCEEDED(
        Connection.SetParam(QUIC_PARAM_CONN_PATH_REQUIRED_MTU, sizeof(Required), &Required));
    uint16_t ReadBack = 0;
    uint32_t Size = sizeof(ReadBack);
    TEST_QUIC_SUCCEEDED(
        Connection.GetParam(QUIC_PARAM_CONN_PATH_REQUIRED_MTU, &Size, &ReadBack));
    TEST_EQUAL(FixedMtu, ReadBack);

    //
    // Bounded by the range an MTU can take, not by this connection's
    // MaximumMtu -- see the comment on the parameter.
    //
    uint16_t TooBig = (uint16_t)(CXPLAT_MAX_MTU + 1);
    TEST_EQUAL(
        QUIC_STATUS_INVALID_PARAMETER,
        Connection.SetParam(QUIC_PARAM_CONN_PATH_REQUIRED_MTU, sizeof(TooBig), &TooBig));

    uint16_t TooSmall = 1;
    TEST_EQUAL(
        QUIC_STATUS_INVALID_PARAMETER,
        Connection.SetParam(QUIC_PARAM_CONN_PATH_REQUIRED_MTU, sizeof(TooSmall), &TooSmall));

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    QuicAddr FirstLocalAddr, SecondLocalAddr, PairAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(FirstLocalAddr));
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondLocalAddr));
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(PairAddr));
    SecondLocalAddr.SetEphemeralPort();

    //
    // Raise the requirement one byte above anything a path can reach. The
    // second path still validates -- the probe goes out at the path's own MTU
    // and is answered -- but must not join the send rotation.
    //
    uint16_t Unreachable = (uint16_t)(FixedMtu + 1);
    TEST_QUIC_SUCCEEDED(
        Connection.SetParam(QUIC_PARAM_CONN_PATH_REQUIRED_MTU, sizeof(Unreachable), &Unreachable));

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

    //
    // It validated: the connection knows about it and reports it.
    //
    TEST_TRUE(ClientContext.PathAddedEvent.WaitTimeout(TestWaitTimeout));
    QUIC_PATH_STATISTICS PathStats[QUIC_MAX_PATH_COUNT];
    Size = sizeof(PathStats);
    TEST_QUIC_SUCCEEDED(
        Connection.GetParam(QUIC_PARAM_CONN_PATH_STATISTICS, &Size, PathStats));
    TEST_EQUAL(2 * sizeof(QUIC_PATH_STATISTICS), Size);

    //
    // Asking for it explicitly is refused while the requirement stands.
    //
    TEST_EQUAL(
        QUIC_STATUS_INVALID_STATE,
        Connection.SetParam(QUIC_PARAM_CONN_ACTIVATE_PATH, sizeof(PathParam), &PathParam));

    //
    // And it is carrying nothing, which is the part that matters: a backup path
    // is not drawn from by QuicConnChoosePath.
    //
    {
        PathSendCounter Backup(SecondLocalAddr.GetPort());
        Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(15));
        CxPlatSleep(300);
        Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(0));
        TEST_EQUAL(0, Backup.Count);
    }

    //
    // Clearing the requirement lets it in.
    //
    uint16_t None = 0;
    TEST_QUIC_SUCCEEDED(
        Connection.SetParam(QUIC_PARAM_CONN_PATH_REQUIRED_MTU, sizeof(None), &None));
    Size = sizeof(ReadBack);
    TEST_QUIC_SUCCEEDED(
        Connection.GetParam(QUIC_PARAM_CONN_PATH_REQUIRED_MTU, &Size, &ReadBack));
    TEST_EQUAL(0, ReadBack);

    TEST_QUIC_SUCCEEDED(
        Connection.SetParam(QUIC_PARAM_CONN_ACTIVATE_PATH, sizeof(PathParam), &PathParam));

    {
        PathSendCounter Active(SecondLocalAddr.GetPort());
        Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(15));
        CxPlatSleep(500);
        Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(0));
        TEST_TRUE(Active.Count > 0);
    }
}

#endif
