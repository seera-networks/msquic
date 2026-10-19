/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Tests for QUIC_LOCAL_ADDRESS_CHANGE_NOTIFY and the local address snapshot
    the library keeps behind it.

    These drive the library through QUIC_PARAM_GLOBAL_TEST_INJECT_ADDRESS_CHANGE
    rather than through the host, so what they cover is everything downstream of
    the platform callback: the cache, the fan-out, the per-connection
    reconciliation and the event contents. The backend itself, including its
    debounce window, is covered by the platform unit tests.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "AddressChangeTest.cpp.clog.h"
#endif

#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)

//
// What one LOCAL_ADDRESSES_CHANGED indication said. Copied out of the event,
// which owns its arrays only for the duration of the callback.
//
struct AddressChangeRecord {
    uint32_t AddedCount {0};
    uint32_t RemovedCount {0};
    uint32_t LostPathCount {0};
    QUIC_ADDR FirstRemoved {};
    QUIC_ADDR FirstLostLocal {};
};

struct AddressChangeContext {
    CxPlatEvent HandshakeCompleteEvent;
    CxPlatEvent ChangedEvent;
    CxPlatEvent LocalAddrChangedEvent;
    CxPlatEvent ShutdownEvent;
    AddressChangeRecord Last;
    uint32_t ChangeCount {0};
    uint32_t LocalAddrChangeCount {0};
    QUIC_ADDR NewLocalAddr {};

    static QUIC_STATUS QUIC_API Callback(
        _In_ MsQuicConnection* /* Connection */,
        _In_opt_ void* Context,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        ) noexcept
    {
        AddressChangeContext* Ctx = static_cast<AddressChangeContext*>(Context);
        if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            Ctx->HandshakeCompleteEvent.Set();
            Ctx->ChangedEvent.Set();
            Ctx->LocalAddrChangedEvent.Set();
            Ctx->ShutdownEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED) {
            Ctx->NewLocalAddr = *Event->LOCAL_ADDRESS_CHANGED.Address;
            Ctx->LocalAddrChangeCount++;
            Ctx->LocalAddrChangedEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
        } else if (Event->Type == QUIC_CONNECTION_EVENT_LOCAL_ADDRESSES_CHANGED) {
            AddressChangeRecord Record;
            Record.AddedCount = Event->LOCAL_ADDRESSES_CHANGED.AddedCount;
            Record.RemovedCount = Event->LOCAL_ADDRESSES_CHANGED.RemovedCount;
            Record.LostPathCount = Event->LOCAL_ADDRESSES_CHANGED.LostPathCount;
            if (Record.RemovedCount != 0) {
                Record.FirstRemoved = Event->LOCAL_ADDRESSES_CHANGED.Removed[0];
            }
            if (Record.LostPathCount != 0) {
                Record.FirstLostLocal =
                    *Event->LOCAL_ADDRESSES_CHANGED.LostPaths[0].LocalAddress;
            }
            Ctx->Last = Record;
            Ctx->ChangeCount++;
            Ctx->ChangedEvent.Set();
        }
        return QUIC_STATUS_SUCCESS;
    }
};

#if DEBUG

static
QUIC_STATUS
InjectAddresses(
    _In_reads_(Count) const QUIC_ADDR* Addresses,
    _In_ uint32_t Count
    )
{
    return
        MsQuic->SetParam(
            nullptr,
            QUIC_PARAM_GLOBAL_TEST_INJECT_ADDRESS_CHANGE,
            Count * (uint32_t)sizeof(QUIC_ADDR),
            Addresses);
}

//
// An address no host under test has, used to make the injected snapshot
// deterministic rather than whatever the machine happens to be configured
// with. TEST-NET-1 from RFC 5737.
//
static
void
SyntheticAddress(
    _In_ const char* Literal,
    _Out_ QUIC_ADDR* Addr
    )
{
    CxPlatZeroMemory(Addr, sizeof(*Addr));
    TEST_TRUE(QuicAddrFromString(Literal, 0, Addr));
    QuicAddrSetPort(Addr, 0);
}

#endif // DEBUG

//
// Brings up a loopback connection whose client is in the given mode, and hands
// back the client's local address.
//
static
void
RunAddressChangeTest(
    _In_ int Family,
    _In_ QUIC_LOCAL_ADDRESS_CHANGE_MODE Mode,
    _In_ bool ExpectEventOnLoss
    )
{
#if !DEBUG
    //
    // QUIC_PARAM_GLOBAL_TEST_INJECT_ADDRESS_CHANGE only exists in debug
    // builds, so there is no way to drive an address change from here.
    //
    UNREFERENCED_PARAMETER(Family);
    UNREFERENCED_PARAMETER(Mode);
    UNREFERENCED_PARAMETER(ExpectEventOnLoss);
#else
    AddressChangeContext Context;

    MsQuicRegistration Registration {true};
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings{}, ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicSettings ClientSettings;
    ClientSettings.SetLocalAddressChangeMode(Mode);
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientSettings, MsQuicCredentialConfig{});
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, MsQuicConnection::NoOpCallback);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());

    QUIC_ADDRESS_FAMILY QuicAddrFamily = (Family == 4) ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr ServerLocalAddr(QuicAddrFamily);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, CleanUpManual, AddressChangeContext::Callback, &Context);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    TEST_QUIC_SUCCEEDED(
        Connection.Start(
            ClientConfiguration,
            ServerLocalAddr.GetFamily(),
            QUIC_TEST_LOOPBACK_FOR_AF(ServerLocalAddr.GetFamily()),
            ServerLocalAddr.GetPort()));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));

    QuicAddr ClientLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(ClientLocalAddr));

    QUIC_ADDR ClientAddrNoPort = ClientLocalAddr.SockAddr;
    QuicAddrSetPort(&ClientAddrNoPort, 0);
    QUIC_ADDR Spare;
    SyntheticAddress(
        QuicAddrFamily == QUIC_ADDRESS_FAMILY_INET ? "192.0.2.1" : "2001:db8::1",
        &Spare);

    //
    // A baseline that the connection's own address is part of, so that the
    // next injection is a removal of something the connection is using rather
    // than a difference against whatever the host is configured with.
    //
    const QUIC_ADDR Baseline[] = { ClientAddrNoPort, Spare };
    Context.ChangedEvent.Reset();
    TEST_QUIC_SUCCEEDED(InjectAddresses(Baseline, ARRAYSIZE(Baseline)));

    if (Mode == QUIC_LOCAL_ADDRESS_CHANGE_NOTIFY) {
        //
        // The spare is not in use, so it is reported as something the
        // application could open a path on.
        //
        TEST_TRUE(Context.ChangedEvent.WaitTimeout(TestWaitTimeout));
        TEST_EQUAL(0u, Context.Last.LostPathCount);
        TEST_TRUE(Context.Last.AddedCount >= 1);
    }

    Context.ChangedEvent.Reset();
    TEST_QUIC_SUCCEEDED(InjectAddresses(&Spare, 1));

    if (!ExpectEventOnLoss) {
        //
        // A connection left at DISABLED hears nothing, which is the whole of
        // the promise that this feature changes no existing behaviour.
        //
        TEST_FALSE(Context.ChangedEvent.WaitTimeout(500));
        TEST_EQUAL(0u, Context.ChangeCount);
        return;
    }

    TEST_TRUE(Context.ChangedEvent.WaitTimeout(TestWaitTimeout));
    TEST_EQUAL(1u, Context.Last.LostPathCount);
    TEST_TRUE(QuicAddrCompare(&ClientLocalAddr.SockAddr, &Context.Last.FirstLostLocal));
    TEST_EQUAL(1u, Context.Last.RemovedCount);
    TEST_TRUE(QuicAddrCompare(&ClientAddrNoPort, &Context.Last.FirstRemoved));
    //
    // The spare is in use by nobody, but it is also not new to the connection
    // -- it was in the baseline -- so it is still reported as available.
    //
    TEST_TRUE(Context.Last.AddedCount >= 1);
#endif // !DEBUG
}

void
QuicTestLocalAddressChangeNotify(
    const FamilyArgs& Params
    )
{
    RunAddressChangeTest(Params.Family, QUIC_LOCAL_ADDRESS_CHANGE_NOTIFY, true);
}

void
QuicTestLocalAddressChangeDisabled(
    const FamilyArgs& Params
    )
{
    RunAddressChangeTest(Params.Family, QUIC_LOCAL_ADDRESS_CHANGE_DISABLED, false);
}

void
QuicTestGetLocalAddressesParam(
    )
{
    //
    // Nothing has turned the monitor on, so this also covers the getter
    // starting one for the length of the call and shutting it down after.
    //
    uint32_t Length = 0;
    QUIC_STATUS Status =
        MsQuic->GetParam(nullptr, QUIC_PARAM_GLOBAL_LOCAL_ADDRESSES, &Length, nullptr);
    if (Status == QUIC_STATUS_NOT_SUPPORTED) {
        //
        // No backend on this platform. Phase 4 adds the rest.
        //
        return;
    }
    TEST_TRUE(Status == QUIC_STATUS_BUFFER_TOO_SMALL || Status == QUIC_STATUS_SUCCESS);
    if (Status == QUIC_STATUS_SUCCESS) {
        //
        // A host with no usable address at all. Nothing more to check.
        //
        TEST_EQUAL(0u, Length);
        return;
    }

    TEST_TRUE(Length >= sizeof(QUIC_ADDR));
    TEST_EQUAL(0u, Length % sizeof(QUIC_ADDR));

    //
    // Allowing for the set to have grown between the two calls. The monitor is
    // created for the length of each call when nothing else holds it, so the
    // second one re-enumerates, and a host that gains an address in between
    // legitimately needs a bigger buffer.
    //
    UniquePtr<uint8_t[]> Buffer;
    for (uint32_t Attempt = 0; Attempt < 3; ++Attempt) {
        Buffer.reset(new(std::nothrow) uint8_t[Length]);
        TEST_TRUE(Buffer.get() != nullptr);
        Status =
            MsQuic->GetParam(nullptr, QUIC_PARAM_GLOBAL_LOCAL_ADDRESSES, &Length, Buffer.get());
        if (Status != QUIC_STATUS_BUFFER_TOO_SMALL) {
            break;
        }
    }
    TEST_QUIC_SUCCEEDED(Status);

    const QUIC_ADDR* Addresses = (const QUIC_ADDR*)Buffer.get();
    const uint32_t Count = Length / (uint32_t)sizeof(QUIC_ADDR);
    TEST_TRUE(Count >= 1);
    for (uint32_t i = 0; i < Count; ++i) {
        //
        // The contract is that every entry is a usable source address with the
        // port cleared.
        //
        TEST_EQUAL(0, QuicAddrGetPort(&Addresses[i]));
        TEST_TRUE(
            QuicAddrGetFamily(&Addresses[i]) == QUIC_ADDRESS_FAMILY_INET ||
            QuicAddrGetFamily(&Addresses[i]) == QUIC_ADDRESS_FAMILY_INET6);
    }
}

#if DEBUG

//
// What the server made of the client moving. Seeing the peer address change is
// the end-to-end proof that packets from the new local address actually
// arrived and were accepted, which no amount of client-side state can show.
//
struct AutoMigrationServerContext {
    CxPlatEvent HandshakeCompleteEvent;
    CxPlatEvent PeerAddrChangedEvent;
    QUIC_ADDR NewPeerAddr {};

    static QUIC_STATUS QUIC_API Callback(
        _In_ MsQuicConnection* /* Connection */,
        _In_opt_ void* Context,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        ) noexcept
    {
        AutoMigrationServerContext* Ctx =
            static_cast<AutoMigrationServerContext*>(Context);
        if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
            Ctx->HandshakeCompleteEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
            Ctx->HandshakeCompleteEvent.Set();
            Ctx->PeerAddrChangedEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED) {
            Ctx->NewPeerAddr = *Event->PEER_ADDRESS_CHANGED.Address;
            Ctx->PeerAddrChangedEvent.Set();
        } else if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
            MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
        }
        return QUIC_STATUS_SUCCESS;
    }
};

//
// A second address on the same host that the connection could actually bind
// and reach the peer from. Only 127/8 qualifies: a connection to loopback
// cannot be carried by a real interface address, and IPv6 has only ::1. So
// this works where the test talks to loopback over IPv4, and the callers skip
// otherwise rather than pretend.
//
static
bool
AlternateLoopbackAddress(
    _In_ const QUIC_ADDR* Current,
    _Out_ QUIC_ADDR* Alternate
    )
{
    *Alternate = *Current;
    if (QuicAddrGetFamily(Current) != QUIC_ADDRESS_FAMILY_INET) {
        return false;
    }

    uint8_t Bytes[4];
    CxPlatCopyMemory(Bytes, &Current->Ipv4.sin_addr, sizeof(Bytes));
    if (Bytes[0] != 127) {
        return false;
    }

    //
    // 127.0.0.1 -> 127.0.0.2, and anything else in 127/8 one along, staying
    // inside the range the host answers for.
    //
    Bytes[3] = (uint8_t)(Bytes[3] == 255 ? 1 : Bytes[3] + 1);
    CxPlatCopyMemory(&Alternate->Ipv4.sin_addr, Bytes, sizeof(Bytes));
    QuicAddrSetPort(Alternate, 0);
    return true;
}

//
// AUTO mode: the address the connection is using disappears, and the
// connection moves itself to another one without the application doing
// anything.
//
void
QuicTestLocalAddressChangeAuto(
    )
{
    //
    // Declared before the registration, so they outlive it. The server
    // connection is auto-deleted and its SHUTDOWN_COMPLETE arrives while
    // RegistrationClose is waiting -- a context on this stack frame has to
    // still be there when it does. PathTest.cpp does the same for the same
    // reason.
    //
    AddressChangeContext Context;
    AutoMigrationServerContext ServerContext;

    MsQuicRegistration Registration {true};
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings{}, ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicSettings ClientSettings;
    ClientSettings.SetLocalAddressChangeMode(QUIC_LOCAL_ADDRESS_CHANGE_AUTO);
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientSettings, MsQuicCredentialConfig{});
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    MsQuicAutoAcceptListener Listener(
        Registration, ServerConfiguration, AutoMigrationServerContext::Callback, &ServerContext);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());

    QuicAddr ServerLocalAddr(QUIC_ADDRESS_FAMILY_INET);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, CleanUpManual, AddressChangeContext::Callback, &Context);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    TEST_QUIC_SUCCEEDED(
        Connection.Start(
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            QUIC_TEST_LOOPBACK_FOR_AF(QUIC_ADDRESS_FAMILY_INET),
            ServerLocalAddr.GetPort()));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(ServerContext.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));

    QuicAddr ClientLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(ClientLocalAddr));

    QUIC_ADDR Alternate;
    if (!AlternateLoopbackAddress(&ClientLocalAddr.SockAddr, &Alternate)) {
        //
        // Not talking to loopback over IPv4, so there is no second address
        // this connection could be carried by.
        //
        return;
    }

    //
    // The only address the host has is one the connection is not using, so the
    // active path is lost and the alternate is the only candidate.
    //
    Context.LocalAddrChangedEvent.Reset();
    ServerContext.PeerAddrChangedEvent.Reset();
    TEST_QUIC_SUCCEEDED(InjectAddresses(&Alternate, 1));

    //
    // The application is told, without having asked for anything.
    //
    TEST_TRUE(Context.LocalAddrChangedEvent.WaitTimeout(TestWaitTimeout));
    TEST_EQUAL(1u, Context.LocalAddrChangeCount);
    TEST_TRUE(QuicAddrCompareIp(&Alternate, &Context.NewLocalAddr));

    //
    // And the connection really is on the new address.
    //
    QuicAddr MigratedLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(MigratedLocalAddr));
    TEST_TRUE(QuicAddrCompareIp(&Alternate, &MigratedLocalAddr.SockAddr));

    //
    // The end-to-end part: the server saw traffic arrive from the new address.
    // Without this the test would pass on a migration that never reached the
    // peer.
    //
    TEST_TRUE(ServerContext.PeerAddrChangedEvent.WaitTimeout(TestWaitTimeout));
    TEST_TRUE(QuicAddrCompareIp(&Alternate, &ServerContext.NewPeerAddr));

    //
    // Still up, not shut down by any of it.
    //
    TEST_FALSE(Context.ShutdownEvent.WaitTimeout(100));
}

//
// AUTO mode with nothing to migrate to. The connection and its dead path are
// kept, because the host having no address is not the connection's failure,
// and it recovers when an address comes back.
//
void
QuicTestLocalAddressChangeAutoOffline(
    )
{
    //
    // Declared before the registration, so they outlive it. The server
    // connection is auto-deleted and its SHUTDOWN_COMPLETE arrives while
    // RegistrationClose is waiting -- a context on this stack frame has to
    // still be there when it does. PathTest.cpp does the same for the same
    // reason.
    //
    AddressChangeContext Context;

    MsQuicRegistration Registration {true};
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings{}, ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicSettings ClientSettings;
    ClientSettings.SetLocalAddressChangeMode(QUIC_LOCAL_ADDRESS_CHANGE_AUTO);
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientSettings, MsQuicCredentialConfig{});
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, MsQuicConnection::NoOpCallback);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());

    QuicAddr ServerLocalAddr(QUIC_ADDRESS_FAMILY_INET);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, CleanUpManual, AddressChangeContext::Callback, &Context);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    TEST_QUIC_SUCCEEDED(
        Connection.Start(
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            QUIC_TEST_LOOPBACK_FOR_AF(QUIC_ADDRESS_FAMILY_INET),
            ServerLocalAddr.GetPort()));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));

    QuicAddr ClientLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(ClientLocalAddr));

    //
    // The host has nothing at all. There is no candidate, so AUTO holds.
    //
    Context.LocalAddrChangedEvent.Reset();
    TEST_QUIC_SUCCEEDED(InjectAddresses(nullptr, 0));

    TEST_FALSE(Context.LocalAddrChangedEvent.WaitTimeout(500));
    TEST_EQUAL(0u, Context.LocalAddrChangeCount);

    //
    // Kept, rather than torn down. This is the whole point of the offline case:
    // aborting here would be worse than waiting, since the idle timeout is
    // already the limit.
    //
    TEST_FALSE(Context.ShutdownEvent.WaitTimeout(100));
    QuicAddr StillLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(StillLocalAddr));
    TEST_TRUE(QuicAddrCompare(&ClientLocalAddr.SockAddr, &StillLocalAddr.SockAddr));

    //
    // The address comes back. The active path's address is present again, so
    // there is nothing to migrate and the connection carries on where it was.
    //
    QUIC_ADDR Back = ClientLocalAddr.SockAddr;
    QuicAddrSetPort(&Back, 0);
    TEST_QUIC_SUCCEEDED(InjectAddresses(&Back, 1));

    TEST_FALSE(Context.LocalAddrChangedEvent.WaitTimeout(300));
    TEST_FALSE(Context.ShutdownEvent.WaitTimeout(100));
}

//
// AUTO is accepted but inert on a connection that negotiated server-initiated
// migration, because QuicConnActivatePath and friends reject a client's calls
// on one. Worth a test of its own: the failure mode would be AUTO quietly
// fighting the path APIs on every reconciliation.
//
void
QuicTestLocalAddressChangeAutoServerMigration(
    )
{
    AddressChangeContext Context;

    MsQuicRegistration Registration {true};
    TEST_QUIC_SUCCEEDED(Registration.GetInitStatus());

    MsQuicSettings ServerSettings;
    ServerSettings.SetServerMigrationEnabled(true);
    MsQuicConfiguration ServerConfiguration(Registration, "MsQuicTest", ServerSettings, ServerSelfSignedCredConfig);
    TEST_QUIC_SUCCEEDED(ServerConfiguration.GetInitStatus());

    MsQuicSettings ClientSettings;
    ClientSettings.SetServerMigrationEnabled(true);
    ClientSettings.SetLocalAddressChangeMode(QUIC_LOCAL_ADDRESS_CHANGE_AUTO);
    MsQuicConfiguration ClientConfiguration(Registration, "MsQuicTest", ClientSettings, MsQuicCredentialConfig{});
    TEST_QUIC_SUCCEEDED(ClientConfiguration.GetInitStatus());

    MsQuicAutoAcceptListener Listener(Registration, ServerConfiguration, MsQuicConnection::NoOpCallback);
    TEST_QUIC_SUCCEEDED(Listener.GetInitStatus());

    QuicAddr ServerLocalAddr(QUIC_ADDRESS_FAMILY_INET);
    TEST_QUIC_SUCCEEDED(Listener.Start("MsQuicTest", &ServerLocalAddr.SockAddr));
    TEST_QUIC_SUCCEEDED(Listener.GetLocalAddr(ServerLocalAddr));

    MsQuicConnection Connection(Registration, CleanUpManual, AddressChangeContext::Callback, &Context);
    TEST_QUIC_SUCCEEDED(Connection.GetInitStatus());

    TEST_QUIC_SUCCEEDED(
        Connection.Start(
            ClientConfiguration,
            QUIC_ADDRESS_FAMILY_INET,
            QUIC_TEST_LOOPBACK_FOR_AF(QUIC_ADDRESS_FAMILY_INET),
            ServerLocalAddr.GetPort()));
    TEST_TRUE(Context.HandshakeCompleteEvent.WaitTimeout(TestWaitTimeout));

    QuicAddr ClientLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(ClientLocalAddr));

    QUIC_ADDR Alternate;
    if (!AlternateLoopbackAddress(&ClientLocalAddr.SockAddr, &Alternate)) {
        return;
    }

    //
    // The same injection that migrates an ordinary AUTO connection. Here it
    // must do nothing at all.
    //
    Context.LocalAddrChangedEvent.Reset();
    TEST_QUIC_SUCCEEDED(InjectAddresses(&Alternate, 1));

    TEST_FALSE(Context.LocalAddrChangedEvent.WaitTimeout(500));
    TEST_EQUAL(0u, Context.LocalAddrChangeCount);

    //
    // Still on the address it started on.
    //
    // N.B. Deliberately not asserting the connection is still up. A connection
    // with server migration negotiated shuts itself down with transport error 1
    // after roughly half a second of idling, with or without any address change
    // in the picture -- see #143. That is not this feature's doing, and
    // asserting on it here would make this test fail for an unrelated reason.
    //
    QuicAddr StillLocalAddr;
    TEST_QUIC_SUCCEEDED(Connection.GetLocalAddr(StillLocalAddr));
    TEST_TRUE(QuicAddrCompare(&ClientLocalAddr.SockAddr, &StillLocalAddr.SockAddr));
}

#endif // DEBUG

#endif // QUIC_API_ENABLE_PREVIEW_FEATURES
