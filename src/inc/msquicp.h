/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Private definitions for MsQuic. The are not meant for general consumption
    and are subject to change without warning.

--*/

#pragma once

#ifndef _MSQUICP_
#define _MSQUICP_

#include "msquic.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct CXPLAT_RECV_DATA CXPLAT_RECV_DATA;
typedef struct CXPLAT_SEND_DATA CXPLAT_SEND_DATA;

typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
(QUIC_API * QUIC_TEST_DATAPATH_CREATE_HOOK)(
    _Inout_opt_ QUIC_ADDR* RemoteAddress,
    _Inout_opt_ QUIC_ADDR* LocalAddress
    );

typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
void
(QUIC_API * QUIC_TEST_DATAPATH_GET_ADDRESS_HOOK)(
    _Inout_ QUIC_ADDR* Address
    );

//
// Returns TRUE to drop the packet.
//
typedef
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
(QUIC_API * QUIC_TEST_DATAPATH_RECEIVE_HOOK)(
    _Inout_ CXPLAT_RECV_DATA* Datagram
    );

//
// Returns TRUE to drop the packet.
//
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
(QUIC_API * QUIC_TEST_DATAPATH_SEND_HOOK)(
    _Inout_ QUIC_ADDR* RemoteAddress,
    _Inout_opt_ QUIC_ADDR* LocalAddress,
    _Inout_ CXPLAT_SEND_DATA* SendData
    );

typedef struct QUIC_TEST_DATAPATH_HOOKS {
    QUIC_TEST_DATAPATH_CREATE_HOOK Create;
    QUIC_TEST_DATAPATH_GET_ADDRESS_HOOK GetLocalAddress;
    QUIC_TEST_DATAPATH_GET_ADDRESS_HOOK GetRemoteAddress;
    QUIC_TEST_DATAPATH_RECEIVE_HOOK Receive;
    QUIC_TEST_DATAPATH_SEND_HOOK Send;
} QUIC_TEST_DATAPATH_HOOKS;

#if DEBUG
//
// Datapath hooks are currently only enabled on debug builds for functional
// testing helpers.
//
#define QUIC_TEST_DATAPATH_HOOKS_ENABLED 1

#ifndef QUIC_TEST_OPENSSL_FLAGS // Not supported on OpenSSL currently
//
// Failing test certificates are only available for debug builds
//
#define QUIC_TEST_FAILING_TEST_CERTIFICATES 1
#endif

//
// Allocation failures are currently only enabled on debug builds.
//
#define QUIC_TEST_ALLOC_FAILURES_ENABLED 1

//
// Enable support to disable automatic generation of the version
// negotiation transport parameter.
//
#define QUIC_TEST_DISABLE_VNE_TP_GENERATION 1

//
// Enable support to disable automatic generation of connection ID.
//
#define QUIC_TEST_MANUAL_CONN_ID_GENERATION 1
#endif

typedef struct QUIC_PRIVATE_TRANSPORT_PARAMETER {
    uint32_t Type;
    uint16_t Length;
    _Field_size_(Length)
    const uint8_t* Buffer;
} QUIC_PRIVATE_TRANSPORT_PARAMETER;

#define QUIC_PARAM_PREFIX_PRIVATE                        0x80000000

//
// The different private parameters for Global.
//

#define QUIC_PARAM_GLOBAL_TEST_DATAPATH_HOOKS           0x81000000  // QUIC_TEST_DATAPATH_HOOKS*
#define QUIC_PARAM_GLOBAL_ALLOC_FAIL_DENOMINATOR        0x81000001  // uint32_t
#define QUIC_PARAM_GLOBAL_ALLOC_FAIL_CYCLE              0x81000002  // uint32_t
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
#define QUIC_PARAM_GLOBAL_VERSION_NEGOTIATION_ENABLED   0x81000003  // BOOLEAN
#endif
#define QUIC_PARAM_GLOBAL_IN_USE                        0x81000004  // BOOLEAN
#define QUIC_PARAM_GLOBAL_DATAPATH_FEATURES             0x81000005  // uint32_t
#define QUIC_PARAM_GLOBAL_PLATFORM_WORKER_POOL          0x81000006  // CXPLAT_WORKER_POOL*


//
// Sets whether the datapath will be initialized with support for DSCP on receive.
// As of Windows 26100, requesting DSCP on the receive path causes packets to fall out of
// the Windows fast path causing a large performance regression.
//
#define QUIC_PARAM_GLOBAL_DATAPATH_DSCP_RECV_ENABLED    0x81000007 // BOOLEAN

//
// Replaces the library's cached set of local addresses with the one supplied
// and runs the change through exactly the path a platform notification takes,
// so that a test can drive address changes without touching the host. Set
// only, debug only.
//
#define QUIC_PARAM_GLOBAL_TEST_INJECT_ADDRESS_CHANGE    0x81000008 // QUIC_ADDR[]

//
// Republishes the library's current set of local addresses, unchanged, marked
// as having followed a routing change. This is the shape of the notification
// that route watching exists for -- the host moved where it sends a peer's
// traffic from, and not one address appeared or disappeared -- which the
// parameter above cannot express, since it is the snapshot diff that drives
// that one. Takes no buffer. Set only, debug only.
//
#define QUIC_PARAM_GLOBAL_TEST_INJECT_ROUTE_CHANGE      0x81000009 // No payload

//
// The different private parameters for Configuration.
//

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
#define QUIC_PARAM_CONFIGURATION_VERSION_NEG_ENABLED    0x83000001  // BOOLEAN
#endif
#define QUIC_PARAM_CONFIGURATION_CONN_ID_GENERATION_DISABLED 0x83000002  // BOOLEAN

//
// The different private parameters for Connection.
//

#define QUIC_PARAM_CONN_FORCE_KEY_UPDATE                0x85000000  // No payload
#define QUIC_PARAM_CONN_FORCE_CID_UPDATE                0x85000001  // No payload
#define QUIC_PARAM_CONN_TEST_TRANSPORT_PARAMETER        0x85000002  // QUIC_PRIVATE_TRANSPORT_PARAMETER
#define QUIC_PARAM_CONN_KEEP_ALIVE_PADDING              0x85000003  // uint16_t
#define QUIC_PARAM_CONN_DISABLE_VNE_TP_GENERATION       0x85000004  // BOOLEAN
#define QUIC_PARAM_CONN_DISABLE_CONN_ID_GENERATION      0x85000005  // BOOLEAN
#define QUIC_PARAM_CONN_GENERATE_CONN_ID                0x85000006  // No payload

//
// How a path came to exist.
//
// Stage 2 of #157. Recorded because stage 3 makes the candidate pair table
// drive path creation and removal, and it may only remove paths it created
// itself: QUIC_PARAM_CONN_ADD_PATH is public API, so an application can manage
// paths the table knows nothing about, and reconciling them away would break
// any application doing so the moment AUTO is enabled.
//
typedef enum QUIC_PATH_ORIGIN {

    //
    // Not a real origin: no path in Connection->Paths carries it, because
    // QuicPathInitialize is the only thing that sets InUse and it always
    // records an origin. Zero is spent on it deliberately. QUIC_CONNECTION is
    // zero-allocated and QuicPathRemove clears only InUse on the slot it
    // vacates, so without this the stale and never-initialized slots would
    // read as the one origin automatic removal must never touch -- a mistake
    // that would look correct. Reading NONE instead means someone walked the
    // array past PathsCount, and is worth asserting on.
    //
    QUIC_PATH_ORIGIN_NONE = 0,

    //
    // The connection's first path, from the handshake. Never removed by
    // reconciliation -- QuicPathRemove promotes a replacement into Paths[0]
    // rather than leaving the slot empty, so "the initial path" is a statement
    // about how the connection started, not about which slot it occupies now.
    //
    QUIC_PATH_ORIGIN_INITIAL,

    //
    // The application asked for it, through QUIC_PARAM_CONN_ADD_PATH.
    //
    QUIC_PATH_ORIGIN_APPLICATION,

    //
    // Opened automatically on the connection's own judgement: today by the AUTO
    // migration policy and by acting on an address the peer advertised, and
    // from stage 3 by the reconciler that replaces both. These are the only
    // paths automatic removal may touch.
    //
    QUIC_PATH_ORIGIN_RECONCILER,

    //
    // Created in response to a packet arriving from an address with no path --
    // QuicConnGetPathForPacket, typically a server reacting to a peer that
    // moved. The peer chose it, not us, so reconciliation has no say over it.
    //
    QUIC_PATH_ORIGIN_PEER,

    //
    // A stack-local path used to send one packet and then discarded, never
    // placed in Connection->Paths. QuicConnSendPunchProbe's is the only one.
    // Not an origin the issue anticipated, but labelling it as any of the
    // others would be a lie about a path that does not outlive its caller.
    //
    QUIC_PATH_ORIGIN_TRANSIENT,

} QUIC_PATH_ORIGIN;

//
// How each of the connection's paths came to exist: one byte per in-use path,
// in path-array order, each holding a QUIC_PATH_ORIGIN value. Bytes rather
// than the enum itself, so size the buffer as uint8_t[QUIC_MAX_PATH_COUNT].
// Get only, debug only.
//
// Exists so a test can check that reconciliation will leave an
// application-created path alone, which is the whole point of recording the
// origin and is otherwise invisible from outside the library.
//
#define QUIC_PARAM_CONN_TEST_PATH_ORIGINS               0x85000007  // uint8_t[]

//
// The endpoints of each of the connection's paths, in path-array order.
//
// QUIC_PATH_STATISTICS is the public way to count paths but carries no
// addresses, so a test can see that the number of paths changed and not which
// pairs they are -- which is the whole question for a reconciler driven by a
// table of pairs. Get only, debug only.
//
typedef struct QUIC_TEST_PATH_ADDRESSES {
    QUIC_ADDR LocalAddress;
    QUIC_ADDR RemoteAddress;
} QUIC_TEST_PATH_ADDRESSES;

#define QUIC_PARAM_CONN_TEST_PATH_ADDRESSES             0x85000008  // QUIC_TEST_PATH_ADDRESSES[]

//
// Marks one of this connection's advertised addresses as preferred to the path
// the ALTERNATIVE_ADDRESS frame goes out on -- the draft advertises that by
// placing the entry before its CURRENT_PATH sentinel, and the client's
// candidate pair table ranks on it. Takes the observed address of a bound
// address already added with QUIC_PARAM_CONN_ADD_OBSERVED_ADDRESS. Set only.
//
// In the private header rather than the public one because the draft is
// provisional, so the shape of "how a server expresses a preference" is not
// something to commit to in the stable API yet. Without it a server has no way
// to say this at all and the client's migration can only be tested by
// hand-rolling a frame, so the client half of stage 4 could not be verified.
//
#define QUIC_PARAM_CONN_PREFER_OBSERVED_ADDRESS         0x85000009  // QUIC_ADDR

//
// Whether draft-kozuka-quic-stateless-punch was negotiated on this connection:
// both endpoints advertised stateless_punch, and for a client it also offered
// alternative_address. Get only, debug only.
//
// Nothing else makes the answer visible. The handshake carries no event for
// it, and the server's half of the extension is deliberately unobservable --
// one unacknowledged datagram and no state kept -- so a test cannot infer
// negotiation from behaviour either. Without this, the condition that decides
// whether the parameter is sent at all could only be checked by reading the
// code.
//
#define QUIC_PARAM_CONN_TEST_STATELESS_PUNCH_NEGOTIATED 0x8500000A  // BOOLEAN

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
#define QUIC_PARAM_STREAM_RELIABLE_OFFSET_RECV          0x88000000  // uint64_t
#endif

#define QUIC_ENABLE_PRIVATE_NMR_PROVIDER(...) \
do { \
    MSQUIC_NPI_ID.Data1 = 0xDEADC0DE; \
} while (FALSE)

#if defined(__cplusplus)
}
#endif

#endif // _MSQUICP_
