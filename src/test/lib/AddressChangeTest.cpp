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
    AddressChangeRecord Last;
    uint32_t ChangeCount {0};

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

struct AddressChangeTestSetup {
    MsQuicRegistration Registration {true};
    MsQuicSettings Settings;
    MsQuicConfiguration ServerConfiguration;
    MsQuicConfiguration ClientConfiguration;

    AddressChangeTestSetup() :
        ServerConfiguration(Registration, "MsQuicTest", MsQuicSettings{}, ServerSelfSignedCredConfig),
        ClientConfiguration(Registration, "MsQuicTest", MsQuicSettings{}, MsQuicCredentialConfig{})
    { }
};

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

    AddressChangeContext Context;
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

    UniquePtr<uint8_t[]> Buffer(new(std::nothrow) uint8_t[Length]);
    TEST_TRUE(Buffer.get() != nullptr);
    TEST_QUIC_SUCCEEDED(
        MsQuic->GetParam(nullptr, QUIC_PARAM_GLOBAL_LOCAL_ADDRESSES, &Length, Buffer.get()));

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

#endif // QUIC_API_ENABLE_PREVIEW_FEATURES
