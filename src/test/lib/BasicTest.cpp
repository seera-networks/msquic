/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Basic MsQuic API Functionality.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "BasicTest.cpp.clog.h"
#endif

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES

namespace {

struct RegistrationCloseContext {
    CxPlatEvent Event;
};

_Function_class_(QUIC_REGISTRATION_CLOSE_CALLBACK)
void
QUIC_API RegistrationCloseCallback(
    _In_opt_ void* Context
    )
{
    RegistrationCloseContext* CloseContext = (RegistrationCloseContext*)Context;
    CloseContext->Event.Set();
}

}

#endif

void QuicTestRegistrationOpenClose()
{
    //
    // Open and syncrhonous close
    //
    {
        MsQuicRegistration Registration;
        TEST_TRUE(Registration.IsValid());
    }

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    //
    // Open and asyncrhonous close
    //
    {
        MsQuicRegistration Registration;
        TEST_TRUE(Registration.IsValid());

        RegistrationCloseContext Context{};
        Registration.CloseAsync(RegistrationCloseCallback, &Context);
        Context.Event.WaitForever();
    }
#endif
}

_Function_class_(NEW_CONNECTION_CALLBACK)
static
bool
QUIC_API
ListenerDoNothingCallback(
    _In_ TestListener* /* Listener */,
    _In_ HQUIC /* ConnectionHandle */
    )
{
    TEST_FAILURE("This callback should never be called!");
    return false;
}

void QuicTestCreateListener()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    {
        TestListener Listener(Registration, ListenerDoNothingCallback, nullptr);
        TEST_TRUE(Listener.IsValid());
    }

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerDoNothingCallback, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
    }
}

void QuicTestStartListener()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicAlpn Alpn("MsQuicTest");
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerDoNothingCallback, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, Alpn.Length()));
    }

    {
        TestListener Listener(Registration, ListenerDoNothingCallback, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        QuicAddr LocalAddress(QUIC_ADDRESS_FAMILY_UNSPEC);
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, Alpn.Length(), &LocalAddress.SockAddr));
    }
}

void QuicTestStartListenerMultiAlpns()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicAlpn Alpn("MsQuicTest1", "MsQuicTest2");
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerDoNothingCallback, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, Alpn.Length()));
    }

    {
        TestListener Listener(Registration, ListenerDoNothingCallback, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());
        QuicAddr LocalAddress(QUIC_ADDRESS_FAMILY_UNSPEC);
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, Alpn.Length(), &LocalAddress.SockAddr));
    }
}

void QuicTestStartListenerImplicit(const FamilyArgs& Params)
{
    const int Family = Params.Family;
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicAlpn Alpn("MsQuicTest");
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerDoNothingCallback, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());

        QuicAddr LocalAddress(Family == 4 ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6);
        TEST_QUIC_SUCCEEDED(Listener.Start(Alpn, Alpn.Length(), &LocalAddress.SockAddr));
    }
}

void QuicTestStartTwoListeners()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicAlpn Alpn1("MsQuicTest");
    MsQuicConfiguration ServerConfiguration1(Registration, Alpn1, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration1.IsValid());
    MsQuicAlpn Alpn2("MsQuicTest2");
    MsQuicConfiguration ServerConfiguration2(Registration, Alpn2, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration2.IsValid());

    {
        TestListener Listener1(Registration, ListenerDoNothingCallback, ServerConfiguration1);
        TEST_TRUE(Listener1.IsValid());
        TEST_QUIC_SUCCEEDED(Listener1.Start(Alpn1, Alpn1.Length()));

        QuicAddr LocalAddress;
        TEST_QUIC_SUCCEEDED(Listener1.GetLocalAddr(LocalAddress));

        TestListener Listener2(Registration, ListenerDoNothingCallback, ServerConfiguration2);
        TEST_TRUE(Listener2.IsValid());
        TEST_QUIC_SUCCEEDED(Listener2.Start(Alpn2, Alpn2.Length(), &LocalAddress.SockAddr));
    }
}

void QuicTestStartTwoListenersSameALPN()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicAlpn Alpn1("MsQuicTest");
    MsQuicConfiguration ServerConfiguration1(Registration, Alpn1, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration1.IsValid());
    MsQuicAlpn Alpn2("MsQuicTest", "MsQuicTest2");
    MsQuicConfiguration ServerConfiguration2(Registration, Alpn2, ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration2.IsValid());

    {
        //
        // Both try to listen on the same, single ALPN
        //
        TestListener Listener1(Registration, ListenerDoNothingCallback, ServerConfiguration1);
        TEST_TRUE(Listener1.IsValid());
        TEST_QUIC_SUCCEEDED(Listener1.Start(Alpn1, Alpn1.Length()));

        QuicAddr LocalAddress;
        TEST_QUIC_SUCCEEDED(Listener1.GetLocalAddr(LocalAddress));

        TestListener Listener2(Registration, ListenerDoNothingCallback, ServerConfiguration1);
        TEST_TRUE(Listener2.IsValid());
        TEST_QUIC_STATUS(
            QUIC_STATUS_ALPN_IN_USE,
            Listener2.Start(Alpn1, Alpn1.Length(), &LocalAddress.SockAddr));
    }

    {
        //
        // First listener on two ALPNs and second overlaps one of those.
        //
        TestListener Listener1(Registration, ListenerDoNothingCallback, ServerConfiguration2);
        TEST_TRUE(Listener1.IsValid());
        TEST_QUIC_SUCCEEDED(Listener1.Start(Alpn2, Alpn2.Length()));

        QuicAddr LocalAddress;
        TEST_QUIC_SUCCEEDED(Listener1.GetLocalAddr(LocalAddress));

        TestListener Listener2(Registration, ListenerDoNothingCallback, ServerConfiguration1);
        TEST_TRUE(Listener2.IsValid());
        TEST_QUIC_STATUS(
            QUIC_STATUS_ALPN_IN_USE,
            Listener2.Start(Alpn1, Alpn1.Length(), &LocalAddress.SockAddr));
    }

    {
        //
        // First listener on one ALPN and second with two (one that overlaps).
        //
        TestListener Listener1(Registration, ListenerDoNothingCallback, ServerConfiguration1);
        TEST_TRUE(Listener1.IsValid());
        TEST_QUIC_SUCCEEDED(Listener1.Start(Alpn1, Alpn1.Length()));

        QuicAddr LocalAddress;
        TEST_QUIC_SUCCEEDED(Listener1.GetLocalAddr(LocalAddress));

        TestListener Listener2(Registration, ListenerDoNothingCallback, ServerConfiguration2);
        TEST_TRUE(Listener2.IsValid());
        TEST_QUIC_STATUS(
            QUIC_STATUS_ALPN_IN_USE,
            Listener2.Start(Alpn2, Alpn2.Length(), &LocalAddress.SockAddr));
    }
}

void QuicTestStartListenerExplicit(const FamilyArgs& Params)
{
    const int Family = Params.Family;
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());
    MsQuicAlpn Alpn("MsQuicTest");
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_TRUE(ServerConfiguration.IsValid());

    {
        TestListener Listener(Registration, ListenerDoNothingCallback, ServerConfiguration);
        TEST_TRUE(Listener.IsValid());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
        QuicAddr LocalAddress(QuicAddr(QuicAddrFamily, true), TestUdpPortBase);
        if (UseDuoNic) {
            QuicAddrSetToDuoNic(&LocalAddress.SockAddr);
        }
        QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
        while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
            LocalAddress.IncrementPort();
            Status = Listener.Start(Alpn, Alpn.Length(), &LocalAddress.SockAddr);
        }
        TEST_QUIC_SUCCEEDED(Status);
    }
}

void QuicTestCreateConnection()
{
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    {
        TestConnection Connection(Registration);
        TEST_TRUE(Connection.IsValid());
    }
}

void QuicTestBindConnectionImplicit(const FamilyArgs& Params)
{
    const int Family = Params.Family;
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    {
        TestConnection Connection(Registration);
        TEST_TRUE(Connection.IsValid());

        QuicAddr LocalAddress(Family == 4 ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6);
        TEST_QUIC_SUCCEEDED(Connection.SetLocalAddr(LocalAddress));
    }
}

void QuicTestBindConnectionExplicit(const FamilyArgs& Params)
{
    const int Family = Params.Family;
    MsQuicRegistration Registration;
    TEST_TRUE(Registration.IsValid());

    {
        TestConnection Connection(Registration);
        TEST_TRUE(Connection.IsValid());

        QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
        QuicAddr LocalAddress(QuicAddr(QuicAddrFamily, true), TestUdpPortBase);
        if (UseDuoNic) {
            QuicAddrSetToDuoNic(&LocalAddress.SockAddr);
        }
        QUIC_STATUS Status = QUIC_STATUS_ADDRESS_IN_USE;
        while (Status == QUIC_STATUS_ADDRESS_IN_USE) {
            LocalAddress.IncrementPort();
            Status = Connection.SetLocalAddr(LocalAddress);
        }
        TEST_QUIC_SUCCEEDED(Status);
    }
}

void QuicTestAddrFunctions(const FamilyArgs& Params)
{
    const int Family = Params.Family;
    QUIC_ADDR SockAddr;
    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;

    // initialize the struct to 0xFF to ensure any code issues are caught by the following tests
    memset(&SockAddr, 0xFF, sizeof(SockAddr));

    QuicAddrSetFamily(&SockAddr, QuicAddrFamily);
    TEST_TRUE(QuicAddrGetFamily(&SockAddr) == QuicAddrFamily);

    QuicAddrSetToLoopback(&SockAddr);

    if (QuicAddrFamily == QUIC_ADDRESS_FAMILY_INET) {
        TEST_TRUE((SockAddr.Ipv4.sin_addr.s_addr & 0x00FFFF00UL) == 0);
    } else {
        for (unsigned long i = 0; i < sizeof(SockAddr.Ipv6.sin6_addr) - 1; i++) {
            TEST_TRUE(SockAddr.Ipv6.sin6_addr.s6_addr[i] == 0);
        }
    }

    TEST_TRUE(QuicAddrGetFamily(&SockAddr) == QuicAddrFamily);
}

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES

//
// QTIP carries QUIC over a TCP connection, which the raw datapath cannot
// establish without a destination, so an unconnected socket is rejected there.
// The tests below are about what the parameter does when it is available, so
// they have nothing to check under QTIP.
//
static bool QuicTestUnconnectedSocketUnavailable(_In_ MsQuicRegistration& Registration)
{
    MsQuicConnection Connection(Registration);
    if (QUIC_FAILED(Connection.GetInitStatus())) {
        return false;
    }
    MsQuicSettings Settings;
    if (QUIC_FAILED(Connection.GetSettings(&Settings))) {
        return false;
    }
    return Settings.QTIPEnabled != 0;
}

void QuicTestConnectUnconnectedSocket(const FamilyArgs& Params)
{
    const int Family = Params.Family;
    const QUIC_ADDRESS_FAMILY QuicAddrFamily =
        (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;

    MsQuicRegistration Registration(true);
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    if (QuicTestUnconnectedSocketUnavailable(Registration)) {
        return;
    }

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicCredentialConfig());
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    //
    // Two servers, so the two client connections have different remote
    // addresses and could not share a connected socket.
    //
    MsQuicAutoAcceptListener Listener1(Registration, ServerConfiguration, MsQuicConnection::NoOpCallback);
    TEST_QUIC_SUCCEEDED(Listener1.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Listener1.Start("MsQuicTest"));
    QuicAddr Server1Addr;
    TEST_QUIC_SUCCEEDED(Listener1.GetLocalAddr(Server1Addr));

    MsQuicAutoAcceptListener Listener2(Registration, ServerConfiguration, MsQuicConnection::NoOpCallback);
    TEST_QUIC_SUCCEEDED(Listener2.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Listener2.Start("MsQuicTest"));
    QuicAddr Server2Addr;
    TEST_QUIC_SUCCEEDED(Listener2.GetLocalAddr(Server2Addr));

    TEST_NOT_EQUAL(Server1Addr.GetPort(), Server2Addr.GetPort());

    //
    // An unconnected socket has no source address of its own to send from, so
    // the local address has to be named. The port is left unspecified, so the
    // stack picks one.
    //
    QuicAddr ClientLocalAddr(QuicAddrFamily, true);
    if (UseDuoNic) {
        QuicAddrSetToDuoNic(&ClientLocalAddr.SockAddr);
    }

    MsQuicConnection Connection1(Registration);
    TEST_QUIC_SUCCEEDED(Connection1.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Connection1.SetShareUdpBinding());
    TEST_QUIC_SUCCEEDED(Connection1.SetUnconnectedUdpSocket());
    TEST_QUIC_SUCCEEDED(Connection1.SetLocalAddr(ClientLocalAddr));
    TEST_QUIC_SUCCEEDED(
        Connection1.Start(
            ClientConfiguration,
            QuicAddrFamily,
            QUIC_TEST_LOOPBACK_FOR_AF(QuicAddrFamily),
            Server1Addr.GetPort()));
    TEST_TRUE(Connection1.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Connection1.HandshakeComplete);

    QuicAddr Client1Addr;
    TEST_QUIC_SUCCEEDED(Connection1.GetLocalAddr(Client1Addr));

    //
    // The second connection reuses the first one's local address, but talks to
    // a different server. That only works if the socket underneath is left
    // unconnected.
    //
    MsQuicConnection Connection2(Registration);
    TEST_QUIC_SUCCEEDED(Connection2.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Connection2.SetShareUdpBinding());
    TEST_QUIC_SUCCEEDED(Connection2.SetUnconnectedUdpSocket());
    TEST_QUIC_SUCCEEDED(Connection2.SetLocalAddr(Client1Addr));
    TEST_QUIC_SUCCEEDED(
        Connection2.Start(
            ClientConfiguration,
            QuicAddrFamily,
            QUIC_TEST_LOOPBACK_FOR_AF(QuicAddrFamily),
            Server2Addr.GetPort()));
    TEST_TRUE(Connection2.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Connection2.HandshakeComplete);

    QuicAddr Client2Addr;
    TEST_QUIC_SUCCEEDED(Connection2.GetLocalAddr(Client2Addr));
    TEST_EQUAL(Client1Addr.GetPort(), Client2Addr.GetPort());
}

void QuicTestUnconnectedSocketRequirements()
{
    MsQuicRegistration Registration(true);
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    if (QuicTestUnconnectedSocketUnavailable(Registration)) {
        return;
    }

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicCredentialConfig());
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    //
    // Without a shared binding there is no source connection ID to demultiplex
    // by, so an unconnected socket is rejected outright.
    //
    {
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_STATE,
            Connection.SetUnconnectedUdpSocket());
    }

    //
    // With one, it is accepted, and can be turned back off either way.
    //
    {
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Connection.SetShareUdpBinding());
        TEST_QUIC_SUCCEEDED(Connection.SetUnconnectedUdpSocket());
        TEST_QUIC_SUCCEEDED(Connection.SetUnconnectedUdpSocket(false));
    }

    //
    // Starting without a specific local address to send from fails the
    // connection.
    //
    {
        MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, MsQuicConnection::NoOpCallback);
        TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest"));
        QuicAddr ServerAddr;
        TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerAddr));

        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Connection.SetShareUdpBinding());
        TEST_QUIC_SUCCEEDED(Connection.SetUnconnectedUdpSocket());
        TEST_QUIC_SUCCEEDED(
            Connection.Start(
                ClientConfiguration,
                ServerAddr.GetFamily(),
                QUIC_TEST_LOOPBACK_FOR_AF(ServerAddr.GetFamily()),
                ServerAddr.GetPort()));

        TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
        TEST_FALSE(Connection.HandshakeComplete);
        TEST_EQUAL(QUIC_STATUS_INVALID_PARAMETER, Connection.TransportShutdownStatus);
    }
}

//
// Sets the connection's local and remote address with QUIC_PARAM_CONN_ADD_PATH
// instead of QUIC_PARAM_CONN_LOCAL_ADDRESS/REMOTE_ADDRESS. Before the
// connection is started, ADD_PATH configures Paths[0] rather than opening an
// additional path, so it has to satisfy the unconnected socket's requirement
// for a specific local address the same way the individual parameters do.
//
void QuicTestUnconnectedSocketAddPathBeforeStart(const FamilyArgs& Params)
{
    const int Family = Params.Family;
    const QUIC_ADDRESS_FAMILY QuicAddrFamily =
        (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;

    MsQuicRegistration Registration(true);
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    if (QuicTestUnconnectedSocketUnavailable(Registration)) {
        return;
    }

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicCredentialConfig());
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, MsQuicConnection::NoOpCallback);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest"));
    QuicAddr ServerAddr;
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerAddr));

    QuicAddr LocalAddr(QuicAddrFamily, true);
    QuicAddr RemoteAddr(QuicAddrFamily, true);
    if (UseDuoNic) {
        QuicAddrSetToDuoNic(&LocalAddr.SockAddr);
        QuicAddrSetToDuoNic(&RemoteAddr.SockAddr);
    }
    RemoteAddr.SetPort(ServerAddr.GetPort());

    QUIC_PATH_PARAM PathParam = { &LocalAddr.SockAddr, &RemoteAddr.SockAddr };

    //
    // A wildcard local address is rejected, since an unconnected socket has no
    // source address of its own to send the connection's first packet from.
    //
    {
        QuicAddr WildcardLocalAddr(QuicAddrFamily);
        QUIC_PATH_PARAM WildcardParam = { &WildcardLocalAddr.SockAddr, &RemoteAddr.SockAddr };

        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Connection.SetShareUdpBinding());
        TEST_QUIC_SUCCEEDED(Connection.SetUnconnectedUdpSocket());
        TEST_QUIC_SUCCEEDED(
            Connection.SetParam(QUIC_PARAM_CONN_ADD_PATH, sizeof(WildcardParam), &WildcardParam));
        TEST_QUIC_SUCCEEDED(
            Connection.Start(ClientConfiguration, QuicAddrFamily, nullptr, ServerAddr.GetPort()));

        TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
        TEST_FALSE(Connection.HandshakeComplete);
        TEST_EQUAL(QUIC_STATUS_INVALID_PARAMETER, Connection.TransportShutdownStatus);
    }

    //
    // With a specific one the connection is established, on the address that
    // was named.
    //
    {
        MsQuicConnection Connection(Registration);
        TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
        TEST_QUIC_SUCCEEDED(Connection.SetShareUdpBinding());
        TEST_QUIC_SUCCEEDED(Connection.SetUnconnectedUdpSocket());
        TEST_QUIC_SUCCEEDED(
            Connection.SetParam(QUIC_PARAM_CONN_ADD_PATH, sizeof(PathParam), &PathParam));
        TEST_QUIC_SUCCEEDED(
            Connection.Start(ClientConfiguration, QuicAddrFamily, nullptr, ServerAddr.GetPort()));

        TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
        TEST_TRUE(Connection.HandshakeComplete);

        QuicAddr ActualLocalAddr;
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(ActualLocalAddr));
        TEST_FALSE(QuicAddrIsWildCard(&ActualLocalAddr.SockAddr));
        TEST_NOT_EQUAL(0, ActualLocalAddr.GetPort());

        QuicAddr ActualRemoteAddr;
        TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(ActualRemoteAddr));
        TEST_EQUAL(ServerAddr.GetPort(), ActualRemoteAddr.GetPort());
    }
}

//
// Adds a path with QUIC_PARAM_CONN_ADD_PATH once the connection is established.
// Unlike the pre-start case, this opens a binding of its own, so it is the path
// that exercises the unconnected socket handling in QuicConnOpenNewPath.
//
void QuicTestUnconnectedSocketAddPathAfterStart(const FamilyArgs& Params)
{
    const int Family = Params.Family;
    const QUIC_ADDRESS_FAMILY QuicAddrFamily =
        (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;

    MsQuicRegistration Registration(true);
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    if (QuicTestUnconnectedSocketUnavailable(Registration)) {
        return;
    }

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", MsQuicCredentialConfig());
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    //
    // A second server, so the added path has a remote address the connected
    // socket of the first path could not have reached.
    //
    MsQuicAutoAcceptListener Listener1(Registration, ServerConfiguration, MsQuicConnection::NoOpCallback);
    TEST_QUIC_SUCCEEDED(Listener1.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Listener1.Start("MsQuicTest"));
    QuicAddr Server1Addr;
    TEST_QUIC_SUCCEEDED(Listener1.GetLocalAddr(Server1Addr));

    MsQuicAutoAcceptListener Listener2(Registration, ServerConfiguration, MsQuicConnection::NoOpCallback);
    TEST_QUIC_SUCCEEDED(Listener2.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Listener2.Start("MsQuicTest"));
    QuicAddr Server2Addr;
    TEST_QUIC_SUCCEEDED(Listener2.GetLocalAddr(Server2Addr));

    TEST_NOT_EQUAL(Server1Addr.GetPort(), Server2Addr.GetPort());

    QuicAddr LocalAddr(QuicAddrFamily, true);
    if (UseDuoNic) {
        QuicAddrSetToDuoNic(&LocalAddr.SockAddr);
    }

    MsQuicConnection Connection(Registration);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());
    TEST_QUIC_SUCCEEDED(Connection.SetShareUdpBinding());
    TEST_QUIC_SUCCEEDED(Connection.SetUnconnectedUdpSocket());
    TEST_QUIC_SUCCEEDED(Connection.SetLocalAddr(LocalAddr));
    TEST_QUIC_SUCCEEDED(
        Connection.Start(
            ClientConfiguration,
            QuicAddrFamily,
            QUIC_TEST_LOOPBACK_FOR_AF(QuicAddrFamily),
            Server1Addr.GetPort()));
    TEST_TRUE(Connection.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(Connection.HandshakeComplete);

    QuicAddr ClientAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(ClientAddr));
    QuicAddr Peer1Addr;
    TEST_QUIC_SUCCEEDED(Connection.GetRemoteAddr(Peer1Addr));

    QuicAddr Peer2Addr = Peer1Addr;
    Peer2Addr.SetPort(Server2Addr.GetPort());

    //
    // The address pair the connection already runs on is not a new path.
    //
    {
        QUIC_PATH_PARAM PathParam = { &ClientAddr.SockAddr, &Peer1Addr.SockAddr };
        TEST_QUIC_STATUS(
            QUIC_STATUS_ADDRESS_IN_USE,
            Connection.SetParam(QUIC_PARAM_CONN_ADD_PATH, sizeof(PathParam), &PathParam));
    }

    //
    // A wildcard local address is rejected: the added path's socket is left
    // unconnected, so it has no source address of its own to send from.
    //
    {
        QuicAddr WildcardLocalAddr(QuicAddrFamily);
        QUIC_PATH_PARAM PathParam = { &WildcardLocalAddr.SockAddr, &Peer2Addr.SockAddr };
        TEST_QUIC_STATUS(
            QUIC_STATUS_INVALID_PARAMETER,
            Connection.SetParam(QUIC_PARAM_CONN_ADD_PATH, sizeof(PathParam), &PathParam));
    }

    //
    // The same local address towards the second server is a new path, and it
    // shares the binding the connection is already using.
    //
    {
        QUIC_PATH_PARAM PathParam = { &ClientAddr.SockAddr, &Peer2Addr.SockAddr };
        TEST_QUIC_SUCCEEDED(
            Connection.SetParam(QUIC_PARAM_CONN_ADD_PATH, sizeof(PathParam), &PathParam));

        QuicAddr StillClientAddr;
        TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(StillClientAddr));
        TEST_EQUAL(ClientAddr.GetPort(), StillClientAddr.GetPort());
    }
}

#endif // QUIC_API_ENABLE_PREVIEW_FEATURES
