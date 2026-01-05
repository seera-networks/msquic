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

    static QUIC_STATUS ConnCallback(_In_ MsQuicConnection* Conn, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event) {
        PathTestContext* Ctx = static_cast<PathTestContext*>(Context);
        Ctx->Connection = Conn;
        if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            Ctx->Connection = nullptr;
            Ctx->PeerAddrChangedEvent.Set();
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
        }
        return QUIC_STATUS_SUCCESS;
    }
};

struct PathTestClientContext {
    CxPlatEvent HandshakeCompleteEvent;
    CxPlatEvent ShutdownEvent;
    MsQuicConnection* Connection {nullptr};
    CxPlatEvent StreamCountEvent;

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
    _In_ int Family
    )
{
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

    QuicAddr SecondLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondLocalAddr));
    SecondLocalAddr.IncrementPort();
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

        if (Status != QUIC_STATUS_SUCCESS) {
            TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
            delete ProbeHelper;
            SecondLocalAddr.IncrementPort();
            ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), DropPacketCount, DropPacketCount);
        }
    } while (Status == QUIC_STATUS_ADDRESS_IN_USE && ++Try <= 3);
    TEST_EQUAL(Status, QUIC_STATUS_SUCCESS);

    if (DeferConnIDGen) {
        TEST_QUIC_SUCCEEDED(
            Context.Connection->SetParam(
                QUIC_PARAM_CONN_GENERATE_CONN_ID,
                0,
                NULL));
    }
    
    TEST_TRUE(ProbeHelper->ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    TEST_TRUE(ProbeHelper->ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    QUIC_STATISTICS_V2 Stats;
    uint32_t Size = sizeof(Stats);
    TEST_QUIC_SUCCEEDED(
        Connection.GetParam(
            QUIC_PARAM_CONN_STATISTICS_V2_PLAT,
            &Size,
            &Stats));
    TEST_EQUAL(Stats.RecvDroppedPackets, 0);
    delete ProbeHelper;
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

    QuicAddr SecondLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondLocalAddr));
    SecondLocalAddr.IncrementPort();
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

        if (Status != QUIC_STATUS_SUCCESS) {
            TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
            delete ProbeHelper;
            SecondLocalAddr.IncrementPort();
            ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), 255, 255);
        }
    } while (Status == QUIC_STATUS_ADDRESS_IN_USE && ++Try <= 3);
    TEST_EQUAL(Status, QUIC_STATUS_SUCCESS);

    CxPlatSleep(5000);

    delete ProbeHelper;
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

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    QuicAddr SecondAddr;
    QuicAddr PairAddr;
    QUIC_PATH_PARAM PathParam = { 0 };
    if (AddressType == NewLocalAddress) {
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondAddr));
        SecondAddr.SetPort(rand() % 65536);
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(PairAddr));
    } else if (AddressType == NewRemoteAddress) {
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(SecondAddr));
        SecondAddr.SetPort(rand() % 65536);
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(PairAddr));
    } else {
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(SecondAddr));
        QUIC_ADDR_STR SecondAddrStr;
        QuicAddrToString(&SecondAddr.SockAddr, &SecondAddrStr);
        fprintf(stderr, "Current Remote Address: %s scope:%u\n", SecondAddrStr.Address, SecondAddr.SockAddr.Ipv6.sin6_scope_id);
        SecondAddr.SetPort(rand() % 65536);
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(PairAddr));
        QUIC_ADDR_STR PairAddrStr;
        QuicAddrToString(&PairAddr.SockAddr, &PairAddrStr);
        fprintf(stderr, "Current Local Address: %s\n", PairAddrStr.Address);
        PairAddr.SetPort(rand() % 65536);
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
            if (!QUIC_SUCCEEDED(Status)) {
                TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
                delete ProbeHelper;
                SecondAddr.SetPort(rand() % 65536);
                ProbeHelper = new(std::nothrow) PathProbeHelper(SecondAddr.GetPort(), 0, 0, AddressType == NewRemoteAddress);
            }
        } while (Status == QUIC_STATUS_ADDRESS_IN_USE && ++Try <= 3);
        TEST_QUIC_SUCCEEDED(Status);

        if (AddressType == NewRemoteAddress) {
            PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            Status = Connection.SetParam(
                QUIC_PARAM_CONN_ADD_PATH,
                sizeof(PathParam),
                &PathParam);
            if (ShareBinding) {
#if defined(_WIN32)
                TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
                return;
#else
                TEST_QUIC_SUCCEEDED(Status);
#endif
            } else {
                TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
                delete ProbeHelper;
                return;
            }
        } else if (AddressType == NewBothAddresses) {
            PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            QUIC_ADDR_STR PairAddrStr;
            QuicAddrToString(&PairAddr.SockAddr, &PairAddrStr);
            QUIC_ADDR_STR SecondAddrStr;
            QuicAddrToString(&SecondAddr.SockAddr, &SecondAddrStr);
            fprintf(stderr, "New Path Local Address: %s Remote Address: %s\n", PairAddrStr.Address, SecondAddrStr.Address);
            Try = 0;
            do {
                Status = Connection.SetParam(
                    QUIC_PARAM_CONN_ADD_PATH,
                    sizeof(PathParam),
                    &PathParam);
                if (!QUIC_SUCCEEDED(Status)) {
                    TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
                    PairAddr.SetPort(rand() % 65536);
                }
            } while (Status == QUIC_STATUS_ADDRESS_IN_USE && ++Try <= 3);
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
        //
        // Wait for handshake confirmation.
        //
        CxPlatSleep(100);

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
            if (!QUIC_SUCCEEDED(Status)) {
                TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
                SecondAddr.SetPort(rand() % 65536);
            }
        } while (Status == QUIC_STATUS_ADDRESS_IN_USE && ++Try <= 3);
        TEST_QUIC_SUCCEEDED(Status);
        if (AddressType == NewRemoteAddress) {
            PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            Status = Connection.SetParam(
                QUIC_PARAM_CONN_ACTIVATE_PATH,
                sizeof(PathParam),
                &PathParam);
            if (ShareBinding) {
#if defined(_WIN32)
                TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
                return;
#else
                TEST_QUIC_SUCCEEDED(Status);
#endif
            } else {
                TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
                return;
            }
        } else if (AddressType == NewBothAddresses) {
            PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            Try = 0;
            do {
                Status = Connection.SetParam(
                    QUIC_PARAM_CONN_ACTIVATE_PATH,
                    sizeof(PathParam),
                    &PathParam);
                if (!QUIC_SUCCEEDED(Status)) {
                    TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
                    PairAddr.SetPort(rand() % 65536);
                }
            } while (Status == QUIC_STATUS_ADDRESS_IN_USE && ++Try <= 3);
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
    TEST_TRUE(PeerStreamsChanged.WaitTimeout(1500));
}

void
QuicTestMultipleLocalAddresses(
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

    QuicAddr ClientLocalAddrs[4] = {QuicAddrFamily, QuicAddrFamily, QuicAddrFamily, QuicAddrFamily};
    QuicAddr RemoteAddr;
    if (Family == 4) {
        QuicAddrFromString("127.0.0.1", ServerLocalAddr.GetPort(), &RemoteAddr.SockAddr);
    } else {
        QuicAddrFromString("::1", ServerLocalAddr.GetPort(), &RemoteAddr.SockAddr);
    }    

    for (uint8_t i = 0; i < 4; i++) {
        ClientLocalAddrs[i].SetPort(rand() % 65536);
        QUIC_PATH_PARAM PathParam = { &ClientLocalAddrs[i].SockAddr, &RemoteAddr.SockAddr };
        QUIC_STATUS Status;
        uint32_t Try = 0;
        do {
            Status = Connection.SetParam(
                QUIC_PARAM_CONN_ADD_PATH,
                sizeof(PathParam),
                &PathParam);
            if (Status != QUIC_STATUS_ADDRESS_IN_USE) {
                TEST_QUIC_SUCCEEDED(Status);
                break;
            }
        } while (++Try < 3);
        TEST_QUIC_SUCCEEDED(Status);
    }

    PathProbeHelper ProbeHelpers[3] = {
        {ClientLocalAddrs[1].GetPort(), DropPacketCount, DropPacketCount},
        {ClientLocalAddrs[2].GetPort(), DropPacketCount, DropPacketCount},
        {ClientLocalAddrs[3].GetPort(), DropPacketCount, DropPacketCount}};

    TEST_QUIC_SUCCEEDED(Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, Context.Connection);

    if (DeferConnIDGen) {
        TEST_QUIC_SUCCEEDED(Context.Connection->SetParam(QUIC_PARAM_CONN_GENERATE_CONN_ID, 0, NULL));
    }

    TEST_TRUE(ProbeHelpers[0].ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 20));
    TEST_TRUE(ProbeHelpers[0].ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 20));
    TEST_TRUE(ProbeHelpers[1].ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 20));
    TEST_TRUE(ProbeHelpers[1].ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 20));
    TEST_TRUE(ProbeHelpers[2].ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 20));
    TEST_TRUE(ProbeHelpers[2].ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 20));
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
    _In_ int Family
    )
{
    AddressDiscoveryTestContext ServerContext, ClientContext;
    MsQuicRegistration Registration(true);
    TEST_TRUE(Registration.IsValid());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    MsQuicCredentialConfig ClientCredConfig;
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientCredConfig);
    TEST_TRUE(ClientConfiguration.IsValid());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, AddressDiscoveryTestContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    QuicAddr ClientLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, CleanUpManual, AddressDiscoveryTestContext::ConnCallback, &ClientContext);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    if (Family == 4) {
        QuicAddrFromString("127.0.0.1", ServerLocalAddr.GetPort(), &ServerContext.ObservedAddress.SockAddr);
        QuicAddrFromString("127.0.0.1", 0, &ClientLocalAddr.SockAddr);
    } else {
        QuicAddrFromString("::1", ServerLocalAddr.GetPort(), &ServerContext.ObservedAddress.SockAddr);
        QuicAddrFromString("::1", 0, &ClientLocalAddr.SockAddr);
    }    

    ReplaceAddressHelper* ReplaceHelper = nullptr;
    uint32_t Try = 0;
    do {
        ClientLocalAddr.SetPort(rand() % 65536);
        TEST_QUIC_SUCCEEDED(Connection.SetParam(
            QUIC_PARAM_CONN_LOCAL_ADDRESS,
            sizeof(ClientLocalAddr.SockAddr),
            &ClientLocalAddr.SockAddr));
        ClientContext.ObservedAddress = ClientLocalAddr;
        ClientContext.ObservedAddress.IncrementPort();
        ReplaceHelper = new(std::nothrow) ReplaceAddressHelper(ClientLocalAddr.SockAddr, ClientContext.ObservedAddress.SockAddr);
        QUIC_STATUS Status = Connection.Start(ClientConfiguration, ServerLocalAddr.GetFamily(), QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()), ServerLocalAddr.GetPort());
        if (QUIC_SUCCEEDED(Status)) {
            break;
        } else {
            TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
            delete ReplaceHelper;
        }
    } while (++Try < 3);

    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_NOT_EQUAL(nullptr, ClientContext.Connection);
    TEST_NOT_EQUAL(nullptr, ServerContext.Connection);
    TEST_TRUE(ClientContext.ObservedAddrEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.ObservedAddrEvent.WaitTimeout(TestWaitTimeout));
    Connection.Shutdown(QUIC_TEST_NO_ERROR);
    TEST_TRUE(ClientContext.ShutdownEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.ShutdownEvent.WaitTimeout(TestWaitTimeout));
    delete ReplaceHelper;
}

void
QuicTestServerProbePath(
    _In_ int Family,
    _In_ BOOLEAN DeferConnIDGen,
    _In_ uint32_t DropPacketCount
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

    if (DeferConnIDGen) {
        BOOLEAN DisableConnIdGeneration = TRUE;
        TEST_QUIC_SUCCEEDED(
            ClientConfiguration.SetParam(
                QUIC_PARAM_CONFIGURATION_CONN_ID_GENERATION_DISABLED,
                sizeof(DisableConnIdGeneration),
                &DisableConnIdGeneration));
    }

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, PathTestClientContext::ConnCallback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
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
    SecondLocalAddr.SetPort(rand() % 65536);
    QuicAddr SecondRemoteAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondRemoteAddr));
    SecondRemoteAddr.SetPort(rand() % 65536);
    QUIC_PATH_PARAM PathParam = { &SecondLocalAddr.SockAddr, &SecondRemoteAddr.SockAddr };
    PathProbeHelper *ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), DropPacketCount, DropPacketCount);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    uint32_t Try = 0;
    do {
        Status = Connection.SetParam(
            QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
            sizeof(SecondRemoteAddr.SockAddr),
            &SecondRemoteAddr.SockAddr);

        if (!QUIC_SUCCEEDED(Status)) {
            TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
            SecondRemoteAddr.SetPort(rand() % 65536);
        }
    } while (Status == QUIC_STATUS_ADDRESS_IN_USE && ++Try <= 3);
    TEST_EQUAL(Status, QUIC_STATUS_SUCCESS);

    Try = 0;
    do {
        Status = ServerContext.Connection->SetParam(
            QUIC_PARAM_CONN_ADD_PATH,
            sizeof(PathParam),
            &PathParam);

        if (!QUIC_SUCCEEDED(Status)) {
            TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
            delete ProbeHelper;
            SecondLocalAddr.SetPort(rand() % 65536);
            ProbeHelper = new(std::nothrow) PathProbeHelper(SecondLocalAddr.GetPort(), DropPacketCount, DropPacketCount);
        }
    } while (Status == QUIC_STATUS_ADDRESS_IN_USE && ++Try <= 3);
    TEST_EQUAL(Status, QUIC_STATUS_SUCCESS);

    if (DeferConnIDGen) {
        TEST_QUIC_SUCCEEDED(Connection.SetParam(QUIC_PARAM_CONN_GENERATE_CONN_ID, 0, NULL));
    }
    
    TEST_TRUE(ProbeHelper->ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    TEST_TRUE(ProbeHelper->ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout * 10));
    delete ProbeHelper;
}

void
QuicTestServerMigration(
    _In_ int Family,
    _In_ QUIC_MIGRATION_ADDRESS_TYPE AddressType,
    _In_ QUIC_MIGRATION_TYPE Type
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
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
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

    QuicAddr SecondAddr;
    QuicAddr PairAddr;
    QUIC_PATH_PARAM PathParam = { 0 };
    if (AddressType == NewLocalAddress) {
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(SecondAddr));
        SecondAddr.SetPort(rand() % 65536);
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(PairAddr));
    } else if (AddressType == NewRemoteAddress) {
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondAddr));
        SecondAddr.SetPort(rand() % 65536);
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(PairAddr));
    } else {
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(SecondAddr));
        SecondAddr.SetPort(rand() % 65536);
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(PairAddr));
        PairAddr.SetPort(rand() % 65536);
    }

    if (Type == MigrateWithProbe || Type == DeleteAndMigrate) {
        QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
        PathProbeHelper* ProbeHelper = new(std::nothrow) PathProbeHelper(SecondAddr.GetPort(), 0, 0, AddressType == NewRemoteAddress);
        int Try = 0;

        if (AddressType == NewLocalAddress) {
            Status = Connection.SetParam(
                QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                sizeof(PairAddr.SockAddr),
                &PairAddr.SockAddr);
#if defined(_WIN32)
            TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
            delete ProbeHelper;
            return;
#endif
        } else {
            do {
                Status = Connection.SetParam(
                    QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                    sizeof(SecondAddr.SockAddr),
                    &SecondAddr.SockAddr);
                if (Status != QUIC_STATUS_SUCCESS) {
                    TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
                    delete ProbeHelper;
                    SecondAddr.SetPort(rand() % 65536);
                    ProbeHelper = new(std::nothrow) PathProbeHelper(SecondAddr.GetPort(), 0, 0, AddressType == NewRemoteAddress);
                }
            } while (Status == QUIC_STATUS_ADDRESS_IN_USE && ++Try <= 3);
        }
        TEST_QUIC_SUCCEEDED(Status);
        if (AddressType == NewRemoteAddress) {
            PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            Status = ServerContext.Connection->SetParam(
                QUIC_PARAM_CONN_ADD_PATH,
                sizeof(PathParam),
                &PathParam);
            TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
            delete ProbeHelper;
            return;
        } else {
            if (AddressType == NewLocalAddress) {
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
                if (Status != QUIC_STATUS_SUCCESS) {
                    TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
                    PairAddr.SetPort(rand() % 65536);
                }
            } while (Status == QUIC_STATUS_ADDRESS_IN_USE && ++Try <= 3);
        }

        TEST_TRUE(ProbeHelper->ServerReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
        TEST_TRUE(ProbeHelper->ClientReceiveProbeEvent.WaitTimeout(TestWaitTimeout));
        delete ProbeHelper;

        if (Type == MigrateWithProbe) {
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
        //
        // Wait for handshake confirmation.
        //
        CxPlatSleep(100);

        QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
        int Try = 0;
        if (AddressType == NewLocalAddress) {
            Status = Connection.SetParam(
                QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                sizeof(PairAddr.SockAddr),
                &PairAddr.SockAddr);
#if defined(_WIN32)
            TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
            return;
#endif
        } else {
            do {
                Status = Connection.SetParam(
                    QUIC_PARAM_CONN_ADD_BOUND_ADDRESS,
                    sizeof(SecondAddr.SockAddr),
                    &SecondAddr.SockAddr);
                if (Status != QUIC_STATUS_SUCCESS) {
                    TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
                    SecondAddr.SetPort(rand() % 65536);
                }
            } while (Status == QUIC_STATUS_ADDRESS_IN_USE && ++Try <= 3);
        }
        TEST_QUIC_SUCCEEDED(Status);
        if (AddressType == NewRemoteAddress) {
            PathParam = { &PairAddr.SockAddr, &SecondAddr.SockAddr };
            Status = ServerContext.Connection->SetParam(
                QUIC_PARAM_CONN_ACTIVATE_PATH,
                sizeof(PathParam),
                &PathParam);
            TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
            return;
        } else {
            if (AddressType == NewLocalAddress) {
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
                if (Status != QUIC_STATUS_SUCCESS) {
                    TEST_QUIC_STATUS(Status, QUIC_STATUS_ADDRESS_IN_USE);
                    PairAddr.SetPort(rand() % 65536);
                }
            } while (Status == QUIC_STATUS_ADDRESS_IN_USE && ++Try <= 3);
        }
    }

    TEST_TRUE(ClientContext.PeerAddrChangedEvent.WaitTimeout(1500));
    QuicAddr ServerNewRemoteAddr, ServerNewLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(ServerNewRemoteAddr));
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(ServerNewLocalAddr));
    if (AddressType == NewLocalAddress) {
        TEST_TRUE(QuicAddrCompare(&SecondAddr.SockAddr, &ServerNewRemoteAddr.SockAddr));
    } else { // AddressType == NewBothAddresses
        TEST_TRUE(QuicAddrCompare(&SecondAddr.SockAddr, &ServerNewLocalAddr.SockAddr));
        TEST_TRUE(QuicAddrCompare(&PairAddr.SockAddr, &ServerNewRemoteAddr.SockAddr));
    }
    Connection.SetSettings(MsQuicSettings{}.SetKeepAlive(0));
    TEST_TRUE(ServerContext.StreamCountEvent.WaitTimeout(1500));
}

#endif
