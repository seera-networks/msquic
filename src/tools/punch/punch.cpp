/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    The endpoint half of the NAT-traversal environment of #174, as three roles
    in one binary: a UDP relay, a server that advertises an address behind its
    NAT, and a client that asks for a punch towards it.

    Stages 1-4 of #169 are tested with both endpoints on one host, where the
    direct path works whether or not a punch packet was ever sent -- so the
    failure the mechanism exists to prevent, the client's PATH_CHALLENGE being
    dropped because no binding exists, cannot occur there. This tool is what
    runs inside scripts/nat-punch-test.sh, in Linux network namespaces, behind
    real NATs, where it can.

    Every line worth asserting on is printed as "PUNCH: key=value", because
    the script asserts on them rather than on exit codes alone. The exit code
    says only whether a direct path validated: 0 yes, 2 no, 1 for a failure to
    even get that far.

    Linux only, and deliberately: the relay role uses POSIX sockets directly
    and the harness around it is network namespaces. See
    docs/nat-punch-testing.md.

--*/

#define QUIC_API_ENABLE_PREVIEW_FEATURES 1

#include "msquichelper.h"
#include "msquic.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>

#include <atomic>
#include <string>
#include <vector>

#define PUNCH_ALPN "punch"

//
// The one global msquic.hpp declares extern and leaves each program to define.
//
const MsQuicApi* MsQuic;

static volatile sig_atomic_t Stopping = 0;

static
void
OnSignal(
    int /* Signal */
    )
{
    Stopping = 1;
}

//
// Annotated, and that is load-bearing rather than decoration: forwarding a
// format parameter to vprintf is -Wformat-nonliteral, which clang makes an
// error here (-Wformat=2 -Werror) and gcc does not raise at all -- so a Linux
// gcc build says nothing and every clang configuration fails. The attribute
// both silences it, by telling the compiler this is a format wrapper, and
// format-checks every Emit call site, which is the half worth having.
//
#if defined(__GNUC__) || defined(__clang__)
#define PUNCH_FORMAT(FmtArg, FirstArg) \
    __attribute__((format(printf, FmtArg, FirstArg)))
#else
#define PUNCH_FORMAT(FmtArg, FirstArg)
#endif

static
void
Emit(
    _In_z_ const char* Format,
    ...
    )
    PUNCH_FORMAT(1, 2);

static
void
Emit(
    _In_z_ const char* Format,
    ...
    )
{
    va_list Args;
    va_start(Args, Format);
    printf("PUNCH: ");
    vprintf(Format, Args);
    printf("\n");
    va_end(Args);
    fflush(stdout);
}

static
void
EmitAddr(
    _In_z_ const char* Key,
    _In_ const QUIC_ADDR* Addr
    )
{
    QUIC_ADDR_STR Str = { 0 };
    QuicAddrToString(Addr, &Str);
    Emit("%s=%s", Key, Str.Address);
}

//
// Parses "1.2.3.4:443", "[::1]:443", or either without a port. Written out
// rather than handed to QuicAddrFromString because the harness names addresses
// with ports everywhere and an unbracketed IPv6 literal has to stay
// distinguishable from a host:port pair -- the rule below is that a lone colon
// is a port separator and several colons are an address.
//
static
bool
ParseAddr(
    _In_z_ const char* Text,
    _Out_ QUIC_ADDR* Addr
    )
{
    CxPlatZeroMemory(Addr, sizeof(*Addr));

    const std::string Input(Text);
    std::string Host;
    uint16_t Port = 0;

    if (!Input.empty() && Input[0] == '[') {
        const size_t Close = Input.find(']');
        if (Close == std::string::npos) {
            return false;
        }
        Host = Input.substr(1, Close - 1);
        if (Close + 1 < Input.size()) {
            if (Input[Close + 1] != ':') {
                return false;
            }
            Port = (uint16_t)atoi(Input.c_str() + Close + 2);
        }
    } else {
        const size_t Last = Input.rfind(':');
        if (Last != std::string::npos && Input.find(':') == Last) {
            Host = Input.substr(0, Last);
            Port = (uint16_t)atoi(Input.c_str() + Last + 1);
        } else {
            Host = Input;
        }
    }

    return QuicAddrFromString(Host.c_str(), Port, Addr) != FALSE;
}

//
// GetValue returns only the first match, and both the server and the client
// take their address arguments repeatedly -- several advertised addresses, and
// the several local addresses the #161 items need.
//
static
std::vector<const char*>
GetValues(
    _In_ int argc,
    _In_reads_(argc) char* argv[],
    _In_z_ const char* Name
    )
{
    std::vector<const char*> Values;
    const size_t NameLen = strlen(Name);
    for (int i = 0; i < argc; ++i) {
        if (strlen(argv[i]) > NameLen + 2 &&
            argv[i][0] == '-' &&
            strncmp(argv[i] + 1, Name, NameLen) == 0 &&
            argv[i][1 + NameLen] == ':') {
            Values.push_back(argv[i] + NameLen + 2);
        }
    }
    return Values;
}

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

//
// A plain UDP relay, not a QUIC proxy. quicforward terminates the connection
// and opens a second one, which would give the two endpoints no shared
// connection to negotiate the extension on and no 4-tuple to punch for. What
// hole punching needs in the middle is something that forwards datagrams and
// nothing else.
//
// One client at a time, learned from whichever address is not the server's.
// That is all the harness asks for, and a relay that tracked sessions would
// need a demultiplexing key this one has no business reading.
//
static
int
RunRelay(
    _In_ int argc,
    _In_reads_(argc) char* argv[]
    )
{
    const char* ListenArg = GetValue(argc, argv, "listen");
    const char* ServerArg = GetValue(argc, argv, "server");
    if (ListenArg == nullptr || ServerArg == nullptr) {
        printf("relay requires -listen:<ip:port> and -server:<ip:port>\n");
        return 1;
    }

    QUIC_ADDR Listen, Server;
    if (!ParseAddr(ListenArg, &Listen) || !ParseAddr(ServerArg, &Server)) {
        printf("relay could not parse its addresses\n");
        return 1;
    }

    const int Sock = socket(QuicAddrGetFamily(&Listen), SOCK_DGRAM, 0);
    if (Sock < 0) {
        printf("relay socket failed, errno=%d\n", errno);
        return 1;
    }

    const socklen_t ListenLen =
        QuicAddrGetFamily(&Listen) == QUIC_ADDRESS_FAMILY_INET ?
            sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    if (bind(Sock, (struct sockaddr*)&Listen, ListenLen) < 0) {
        printf("relay bind failed, errno=%d\n", errno);
        close(Sock);
        return 1;
    }

    EmitAddr("relay_listen", &Listen);
    EmitAddr("relay_server", &Server);

    QUIC_ADDR Client = { 0 };
    bool HaveClient = false;
    uint64_t ToServer = 0, ToClient = 0;

    while (!Stopping) {
        struct pollfd Poll = { Sock, POLLIN, 0 };
        const int Ready = poll(&Poll, 1, 200);
        if (Ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (Ready == 0) {
            continue;
        }

        uint8_t Buffer[2048];
        QUIC_ADDR From = { 0 };
        socklen_t FromLen = sizeof(From);
        const ssize_t Read =
            recvfrom(Sock, Buffer, sizeof(Buffer), 0, (struct sockaddr*)&From, &FromLen);
        if (Read <= 0) {
            continue;
        }

        if (QuicAddrCompare(&From, &Server)) {
            if (HaveClient) {
                const socklen_t ClientLen =
                    QuicAddrGetFamily(&Client) == QUIC_ADDRESS_FAMILY_INET ?
                        sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
                if (sendto(Sock, Buffer, (size_t)Read, 0,
                        (struct sockaddr*)&Client, ClientLen) > 0) {
                    ++ToClient;
                }
            }
        } else {
            if (!HaveClient || !QuicAddrCompare(&From, &Client)) {
                Client = From;
                HaveClient = true;
                EmitAddr("relay_saw_client", &Client);
            }
            const socklen_t ServerLen =
                QuicAddrGetFamily(&Server) == QUIC_ADDRESS_FAMILY_INET ?
                    sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
            if (sendto(Sock, Buffer, (size_t)Read, 0,
                    (struct sockaddr*)&Server, ServerLen) > 0) {
                ++ToServer;
            }
        }
    }

    Emit("relay_to_server=%llu", (unsigned long long)ToServer);
    Emit("relay_to_client=%llu", (unsigned long long)ToClient);
    close(Sock);
    return 0;
}

// ---------------------------------------------------------------------------
// Shared reporting
// ---------------------------------------------------------------------------

//
// Both roles report their paths as pairs, which is what the harness asserts
// on: "the server observed traffic from the client's public mapping" is a
// statement about a path's remote address and nothing else. Debug-only, for
// the reason msquicp.h gives -- so the harness requires a Debug build, which
// docs/nat-punch-testing.md says out loud.
//
static
void
EmitPaths(
    _In_ MsQuicConnection* Connection,
    _In_z_ const char* Tag
    )
{
    //
    // Sized generously rather than to QUIC_MAX_PATH_COUNT, which is
    // internal to the library: GetParam writes however many paths there
    // are and reports the length, so the only requirement here is room.
    //
    QUIC_TEST_PATH_ADDRESSES Paths[16];
    uint32_t Length = sizeof(Paths);
    if (QUIC_FAILED(
            Connection->GetParam(
                QUIC_PARAM_CONN_TEST_PATH_ADDRESSES, &Length, Paths))) {
        Emit("%s_paths=unavailable", Tag);
        return;
    }

    const uint32_t Count = Length / sizeof(QUIC_TEST_PATH_ADDRESSES);
    Emit("%s_path_count=%u", Tag, Count);
    for (uint32_t i = 0; i < Count; ++i) {
        QUIC_ADDR_STR Local = { 0 }, Remote = { 0 };
        QuicAddrToString(&Paths[i].LocalAddress, &Local);
        QuicAddrToString(&Paths[i].RemoteAddress, &Remote);
        Emit("%s_path%u=%s->%s", Tag, i, Local.Address, Remote.Address);
    }
}

//
// The one-attempt property of the draft is a count, and nothing on the wire
// shows it: the request is in an encrypted frame and the punch leaves no state
// behind. These counters are the only place it is visible.
//
static
void
EmitPunchCounters(
    _In_ MsQuicConnection* Connection,
    _In_z_ const char* Tag
    )
{
    QUIC_TEST_PUNCH_COUNTERS Counters = { 0 };
    uint32_t Length = sizeof(Counters);
    if (QUIC_FAILED(
            Connection->GetParam(
                QUIC_PARAM_CONN_TEST_PUNCH_COUNTERS, &Length, &Counters))) {
        Emit("%s_punch_counters=unavailable", Tag);
        return;
    }
    Emit("%s_requests_sent=%u", Tag, Counters.RequestsSent);
    Emit("%s_requests_received=%u", Tag, Counters.RequestsReceived);
    Emit("%s_punches_sent=%u", Tag, Counters.PunchesSent);
    Emit("%s_requests_ignored_per_packet=%u", Tag, Counters.RequestsIgnoredPerPacket);
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

struct Advertisement {
    QUIC_ADDR Local;
    QUIC_ADDR Public;
};

struct ServerContext {
    std::vector<Advertisement> Advertise;
    std::atomic<uint32_t> Connections { 0 };
    std::atomic<uint32_t> PathsValidated { 0 };
    std::atomic<bool> Shutdown { false };
};

static
QUIC_STATUS
QUIC_API
ServerConnectionCallback(
    _In_ MsQuicConnection* Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) noexcept
{
    auto Ctx = (ServerContext*)Context;

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED: {
        Ctx->Connections++;
        Emit("server_connected=1");

        //
        // Applied from the callback rather than from the main thread, which is
        // where PathTest.cpp's equivalent runs it. SetParam from a connection
        // callback runs inline on the connection's worker, so this is the
        // ordered side of the two: the advertisement is in place before any
        // frame the peer sends next can be processed. It also avoids holding a
        // pointer to a connection the listener owns and auto-deletes.
        //
        for (const auto& Ad : Ctx->Advertise) {
            QUIC_ADDR Local = Ad.Local;
            QUIC_STATUS Status =
                Connection->SetParam(
                    QUIC_PARAM_CONN_ADD_BOUND_ADDRESS, sizeof(Local), &Local);
            if (QUIC_FAILED(Status)) {
                Emit("server_bind_failed=0x%x", Status);
                continue;
            }

            QUIC_ADDR Public = Ad.Public;
            QUIC_ADD_OBSERVED_ADDRESS Observed = { &Local, &Public };
            Status =
                Connection->SetParam(
                    QUIC_PARAM_CONN_ADD_OBSERVED_ADDRESS,
                    sizeof(Observed),
                    &Observed);
            if (QUIC_FAILED(Status)) {
                Emit("server_observe_failed=0x%x", Status);
                continue;
            }

            QUIC_ADDR_STR LocalStr = { 0 }, PublicStr = { 0 };
            QuicAddrToString(&Local, &LocalStr);
            QuicAddrToString(&Public, &PublicStr);
            Emit("server_advertised=%s@%s", PublicStr.Address, LocalStr.Address);
        }
        break;
    }

    case QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED:
        EmitAddr("server_peer_address_changed", Event->PEER_ADDRESS_CHANGED.Address);
        break;

    case QUIC_CONNECTION_EVENT_PATH_VALIDATED:
        Ctx->PathsValidated++;
        EmitAddr("server_path_validated_remote", Event->PATH_VALIDATED.RemoteAddress);
        EmitAddr("server_path_validated_local", Event->PATH_VALIDATED.LocalAddress);
        EmitPaths(Connection, "server");
        EmitPunchCounters(Connection, "server");
        break;

    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        //
        // Nothing is read: the client opens a stream only to put bytes on the
        // path, and a server that did not close these would hold them open for
        // the length of the run.
        //
        MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The last chance to read the counters, and for a run where no second
        // path validates it is the only one: the other report is on
        // PATH_VALIDATED, which such a run never reaches -- so without this
        // the harness would be asserting on a snapshot taken before the punch
        // was ever answered.
        //
        EmitPunchCounters(Connection, "server_final");
        Emit("server_shutdown=1");
        Ctx->Shutdown = true;
        break;

    default:
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

static
int
RunServer(
    _In_ int argc,
    _In_reads_(argc) char* argv[]
    )
{
    const char* ListenArg = GetValue(argc, argv, "listen");
    const char* CertArg = GetValue(argc, argv, "cert");
    const char* KeyArg = GetValue(argc, argv, "key");
    if (ListenArg == nullptr || CertArg == nullptr || KeyArg == nullptr) {
        printf("server requires -listen:<ip:port> -cert:<file> -key:<file>\n");
        return 1;
    }

    uint32_t Seconds = 30;
    TryGetValue(argc, argv, "time", &Seconds);

    QUIC_ADDR Listen;
    if (!ParseAddr(ListenArg, &Listen)) {
        printf("server could not parse -listen\n");
        return 1;
    }

    ServerContext Ctx;
    for (const char* Arg : GetValues(argc, argv, "advertise")) {
        const char* Split = strchr(Arg, '=');
        if (Split == nullptr) {
            printf("-advertise takes <local-ip:port>=<public-ip:port>\n");
            return 1;
        }
        const std::string LocalText(Arg, (size_t)(Split - Arg));
        Advertisement Ad;
        if (!ParseAddr(LocalText.c_str(), &Ad.Local) ||
            !ParseAddr(Split + 1, &Ad.Public)) {
            printf("-advertise could not be parsed\n");
            return 1;
        }
        Ctx.Advertise.push_back(Ad);
    }

    MsQuicApi Api;
    if (QUIC_FAILED(Api.GetInitStatus())) {
        printf("MsQuicApi failed, 0x%x\n", Api.GetInitStatus());
        return 1;
    }
    MsQuic = &Api;

    MsQuicRegistration Registration("quicpunch", QUIC_EXECUTION_PROFILE_LOW_LATENCY, true);
    if (QUIC_FAILED(Registration.GetInitStatus())) {
        printf("Registration failed, 0x%x\n", Registration.GetInitStatus());
        return 1;
    }

    uint8_t Multipath = 0;
    TryGetValue(argc, argv, "multipath", &Multipath);

    //
    // PathValidatedEventEnabled is the whole reason the server can report
    // anything: a validated path is the event the harness waits for, and it is
    // off by default.
    //
    MsQuicSettings Settings;
    Settings.SetPathValidatedEventEnabled(true);
    Settings.SetIdleTimeoutMs(Seconds * 1000 + 10000);
    Settings.SetPeerBidiStreamCount(4);
    Settings.SetPeerUnidiStreamCount(4);
    //
    // Needed on this side too for the cross product of #161 to appear at all:
    // without multipath negotiated the reconciler refuses a second local
    // address to a remote it already reaches, because that would be a
    // migration rather than an additional path.
    //
    if (Multipath != 0) {
        Settings.SetMultipathEnabled(true);
    }

    QUIC_CERTIFICATE_FILE CertFile = { KeyArg, CertArg };
    QUIC_CREDENTIAL_CONFIG Cred {};
    Cred.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    Cred.CertificateFile = &CertFile;

    MsQuicConfiguration Configuration(
        Registration, PUNCH_ALPN, Settings, MsQuicCredentialConfig(Cred));
    if (QUIC_FAILED(Configuration.GetInitStatus())) {
        printf("Configuration failed, 0x%x\n", Configuration.GetInitStatus());
        return 1;
    }

    MsQuicAutoAcceptListener Listener(
        Registration, Configuration, ServerConnectionCallback, &Ctx);
    if (QUIC_FAILED(Listener.GetInitStatus())) {
        printf("Listener failed, 0x%x\n", Listener.GetInitStatus());
        return 1;
    }

    if (QUIC_FAILED(Listener.Start(PUNCH_ALPN, &Listen))) {
        printf("Listener.Start failed\n");
        return 1;
    }

    EmitAddr("server_listen", &Listen);
    Emit("server_ready=1");

    for (uint32_t i = 0; i < Seconds * 10 && !Stopping; ++i) {
        usleep(100 * 1000);
    }

    Emit("server_connections=%u", Ctx.Connections.load());
    Emit("server_paths_validated=%u", Ctx.PathsValidated.load());
    return 0;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

struct ClientContext {
    QUIC_ADDR Target;
    std::atomic<bool> Connected { false };
    std::atomic<bool> DirectValidated { false };
    std::atomic<bool> Shutdown { false };
    std::atomic<uint32_t> PathsValidated { 0 };
};

static
QUIC_STATUS
QUIC_API
ClientConnectionCallback(
    _In_ MsQuicConnection* Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) noexcept
{
    auto Ctx = (ClientContext*)Context;

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        Emit("client_connected=1");
        Ctx->Connected = true;
        break;

    case QUIC_CONNECTION_EVENT_PATH_VALIDATED: {
        Ctx->PathsValidated++;
        EmitAddr("client_path_validated_local", Event->PATH_VALIDATED.LocalAddress);
        EmitAddr("client_path_validated_remote", Event->PATH_VALIDATED.RemoteAddress);

        //
        // A path to anything other than the relay is the one this harness
        // exists to produce. The relay's address is the only remote the
        // connection had before reconciliation, so "not the target" is exactly
        // "direct".
        //
        if (!QuicAddrCompare(Event->PATH_VALIDATED.RemoteAddress, &Ctx->Target)) {
            Emit("client_direct_path=1");
            Ctx->DirectValidated = true;
        }
        EmitPaths(Connection, "client");
        break;
    }

    case QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED:
        EmitAddr("client_local_address_changed", Event->LOCAL_ADDRESS_CHANGED.Address);
        break;

    case QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED:
        EmitAddr("client_peer_address_changed", Event->PEER_ADDRESS_CHANGED.Address);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // Reported because "the handshake failed" on its own is not a finding.
        // A harness that cannot say which status it failed with sends whoever
        // reads it back to the library to guess.
        //
        Emit("client_transport_shutdown=0x%x",
            Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        Emit("client_peer_shutdown=%llu",
            (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;

    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        Emit("client_shutdown=1");
        Ctx->Shutdown = true;
        break;

    default:
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

static
int
RunClient(
    _In_ int argc,
    _In_reads_(argc) char* argv[]
    )
{
    const char* TargetArg = GetValue(argc, argv, "target");
    if (TargetArg == nullptr) {
        printf("client requires -target:<ip:port>\n");
        return 1;
    }

    uint32_t Seconds = 20;
    TryGetValue(argc, argv, "time", &Seconds);

    uint8_t Multipath = 0;
    TryGetValue(argc, argv, "multipath", &Multipath);

    const char* ModeArg = GetValue(argc, argv, "mode");
    QUIC_ADD_ADDRESS_MODE Mode = QUIC_ADD_ADDRESS_NAT_TRAVERSAL;
    if (ModeArg != nullptr) {
        if (strcmp(ModeArg, "auto") == 0) {
            Mode = QUIC_ADD_ADDRESS_AUTO;
        } else if (strcmp(ModeArg, "manual") == 0) {
            Mode = QUIC_ADD_ADDRESS_MANUAL;
        } else if (strcmp(ModeArg, "nat") != 0) {
            printf("-mode takes nat, auto or manual\n");
            return 1;
        }
    }

    ClientContext Ctx;
    if (!ParseAddr(TargetArg, &Ctx.Target)) {
        printf("client could not parse -target\n");
        return 1;
    }

    MsQuicApi Api;
    if (QUIC_FAILED(Api.GetInitStatus())) {
        printf("MsQuicApi failed, 0x%x\n", Api.GetInitStatus());
        return 1;
    }
    MsQuic = &Api;

    MsQuicRegistration Registration("quicpunch", QUIC_EXECUTION_PROFILE_LOW_LATENCY, true);
    if (QUIC_FAILED(Registration.GetInitStatus())) {
        printf("Registration failed, 0x%x\n", Registration.GetInitStatus());
        return 1;
    }

    //
    // Both of these are settable, and zero means "leave the library's
    // default", because a harness has to be able to take its own
    // configuration out of the picture when something misbehaves.
    //
    uint32_t KeepAliveMs = 1000;
    TryGetValue(argc, argv, "keepalive", &KeepAliveMs);
    uint32_t IdleMs = Seconds * 1000 + 10000;
    TryGetValue(argc, argv, "idle", &IdleMs);

    uint8_t PathEvent = 1;
    TryGetValue(argc, argv, "pathevent", &PathEvent);

    MsQuicSettings Settings;
    Settings.SetAddAddressMode(Mode);
    if (PathEvent != 0) {
        Settings.SetPathValidatedEventEnabled(true);
    }
    if (IdleMs != 0) {
        Settings.SetIdleTimeoutMs(IdleMs);
    }
    //
    // Keepalive so the connection keeps putting packets through the relay for
    // the length of the run: the NAT mappings the whole scenario rests on are
    // held open by traffic, and a silent connection would lose them mid-test
    // for reasons that have nothing to do with the mechanism.
    //
    if (KeepAliveMs != 0) {
        Settings.SetKeepAlive(KeepAliveMs);
    }
    if (Multipath != 0) {
        Settings.SetMultipathEnabled(true);
    }

    QUIC_CREDENTIAL_CONFIG Cred {};
    Cred.Type = QUIC_CREDENTIAL_TYPE_NONE;
    Cred.Flags =
        QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

    MsQuicConfiguration Configuration(
        Registration, PUNCH_ALPN, Settings, MsQuicCredentialConfig(Cred));
    if (QUIC_FAILED(Configuration.GetInitStatus())) {
        printf("Configuration failed, 0x%x\n", Configuration.GetInitStatus());
        return 1;
    }

    MsQuicConnection Connection(Registration, CleanUpManual, ClientConnectionCallback, &Ctx);
    if (QUIC_FAILED(Connection.GetInitStatus())) {
        printf("Connection failed, 0x%x\n", Connection.GetInitStatus());
        return 1;
    }

    if (Multipath != 0) {
        //
        // Required, and the failure without it is not self-explanatory: a
        // client keeps its binding to itself by default, which gets it a
        // zero-length source connection id, and a server that then sees
        // initial_max_path_id closes the connection with PROTOCOL_VIOLATION
        // ("Multipath requires non-zero length connection IDs" in
        // crypto_tls.c). Sharing the binding is what makes the id non-zero.
        // Every multipath test in PathTest.cpp calls this for the same reason.
        //
        if (QUIC_FAILED(Connection.SetShareUdpBinding())) {
            printf("SetShareUdpBinding failed\n");
            return 1;
        }
    }

    QUIC_ADDR_STR TargetIp = { 0 };
    QuicAddrIpToString(&Ctx.Target, &TargetIp);
    if (QUIC_FAILED(
            Connection.Start(
                Configuration,
                QuicAddrGetFamily(&Ctx.Target),
                TargetIp.Address,
                QuicAddrGetPort(&Ctx.Target)))) {
        printf("Connection.Start failed\n");
        return 1;
    }

    for (uint32_t i = 0; i < 100 && !Ctx.Connected && !Ctx.Shutdown && !Stopping; ++i) {
        usleep(100 * 1000);
    }
    if (!Ctx.Connected) {
        Emit("client_handshake=failed");
        return 1;
    }

    QuicAddr Local;
    if (QUIC_FAILED(Connection.GetLocalAddr(Local))) {
        Emit("client_local_addr=unavailable");
        return 1;
    }
    EmitAddr("client_local", &Local.SockAddr);

    //
    // Each candidate names a local address and the public mapping it is seen
    // as. The mapping's port defaults to the connection's own local port,
    // which is what endpoint-independent mapping means in practice: a NAT that
    // preserves the port maps this socket to the same number on the outside,
    // so the harness does not have to be told it. An explicit port overrides,
    // which is how the endpoint-dependent case is set up.
    //
    for (const char* Arg : GetValues(argc, argv, "candidate")) {
        const char* Split = strchr(Arg, '=');
        QUIC_ADDR Host, Observed;
        if (Split == nullptr) {
            if (!ParseAddr(Arg, &Host)) {
                printf("-candidate could not be parsed\n");
                return 1;
            }
            Observed = Host;
        } else {
            const std::string HostText(Arg, (size_t)(Split - Arg));
            if (!ParseAddr(HostText.c_str(), &Host) ||
                !ParseAddr(Split + 1, &Observed)) {
                printf("-candidate could not be parsed\n");
                return 1;
            }
        }
        //
        // Both ports default to the connection's own, because the API requires
        // a non-zero port on each even though the reconciler matches the host
        // address by IP alone -- QuicTestModeNatTraversal passes the
        // connection's local address for the same reason.
        //
        if (QuicAddrGetPort(&Host) == 0) {
            QuicAddrSetPort(&Host, QuicAddrGetPort(&Local.SockAddr));
        }
        if (QuicAddrGetPort(&Observed) == 0) {
            QuicAddrSetPort(&Observed, QuicAddrGetPort(&Local.SockAddr));
        }

        QUIC_CANDIDATE_ADDRESS Candidate = { &Host, &Observed };
        const QUIC_STATUS Status =
            Connection.SetParam(
                QUIC_PARAM_CONN_ADD_CANDIDATE_ADDRESS, sizeof(Candidate), &Candidate);
        QUIC_ADDR_STR HostStr = { 0 }, ObservedStr = { 0 };
        QuicAddrToString(&Host, &HostStr);
        QuicAddrToString(&Observed, &ObservedStr);
        if (QUIC_FAILED(Status)) {
            Emit("client_candidate_failed=%s@%s,0x%x",
                ObservedStr.Address, HostStr.Address, Status);
            return 1;
        }
        Emit("client_candidate=%s@%s", ObservedStr.Address, HostStr.Address);
    }

    //
    // With -poll the run is a timeline rather than a race to the first
    // validated path: the #161 items are about paths appearing and
    // disappearing as local addresses come and go, so the loop reports the set
    // periodically and does not stop at the first success.
    //
    uint32_t Poll = 0;
    TryGetValue(argc, argv, "poll", &Poll);

    uint32_t Tick = 0;
    for (uint32_t i = 0; i < Seconds * 10 && !Ctx.Shutdown && !Stopping; ++i) {
        if (Poll == 0 && Ctx.DirectValidated) {
            break;
        }
        if (Poll != 0 && i != 0 && (i % (Poll * 10)) == 0) {
            char Tag[32];
            snprintf(Tag, sizeof(Tag), "client_poll%u", ++Tick);
            EmitPaths(&Connection, Tag);
        }
        usleep(100 * 1000);
    }

    EmitPaths(&Connection, "client_final");
    EmitPunchCounters(&Connection, "client");
    Emit("client_paths_validated=%u", Ctx.PathsValidated.load());
    Emit("client_connection_alive=%u", Ctx.Shutdown ? 0u : 1u);
    Emit("client_result=%s", Ctx.DirectValidated ? "direct" : "relay-only");

    Connection.Shutdown(0);
    return Ctx.DirectValidated ? 0 : 2;
}

// ---------------------------------------------------------------------------

int QUIC_MAIN_EXPORT main(int argc, char **argv) {
    const char* Role = GetValue(argc, argv, "role");
    if (Role == nullptr) {
        printf(
            "Usage:\n"
            "  quicpunch -role:relay  -listen:<ip:port> -server:<ip:port>\n"
            "  quicpunch -role:server -listen:<ip:port> -cert:<file> -key:<file>\n"
            "                         [-multipath:0|1]\n"
            "                         [-advertise:<local-ip:port>=<public-ip:port>]...\n"
            "                         [-time:<seconds>]\n"
            "  quicpunch -role:client -target:<ip:port>\n"
            "                         [-candidate:<local-ip>[=<public-ip>[:port]]]...\n"
            "                         [-mode:nat|auto|manual] [-multipath:0|1]\n"
            "                         [-poll:<seconds>] [-time:<seconds>]\n"
            "                         [-keepalive:<ms>] [-idle:<ms>] [-pathevent:0|1]\n"
            "\n"
            "Exit codes: 0 a direct path validated, 2 relay only, 1 error.\n");
        return 1;
    }

    signal(SIGINT, OnSignal);
    signal(SIGTERM, OnSignal);

    if (strcmp(Role, "relay") == 0) {
        return RunRelay(argc, argv);
    }
    if (strcmp(Role, "server") == 0) {
        return RunServer(argc, argv);
    }
    if (strcmp(Role, "client") == 0) {
        return RunClient(argc, argv);
    }

    printf("-role takes relay, server or client\n");
    return 1;
}
