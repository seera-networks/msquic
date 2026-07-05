/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

//
// Info for a particular type of pathid (client/server)
//
typedef struct QUIC_PATHID_TYPE_INFO {

    //
    // The largest MAX_{CLIENT, SERVER}_PATHS value indicated to the peer. This MUST not ever
    // decrease once the connection has started.
    //
    uint64_t MaxPathID;

    //
    // The largest MAX_{CLIENT, SERVER}_PATHS value indicated by the peer. This MUST not ever
    // decrease once the connection has started.
    //
    uint64_t PeerMaxPathID;

    //
    // The total number of path ids that have been opened. Includes any path ids
    // that have been closed as well.
    //
    uint32_t TotalPathIDCount;

    //
    // The maximum number of simultaneous open path ids allowed.
    //
    uint16_t MaxCurrentPathIDCount;

    //
    // The current count of currently open path ids.
    //
    uint16_t CurrentPathIDCount;

} QUIC_PATHID_TYPE_INFO;

//
// Different flags of a stream.
// Note - Keep quictypes.h's copy up to date.
//
typedef union QUIC_PATHID_SET_FLAGS {
    uint64_t AllFlags;
    struct {
        BOOLEAN MultipathEnabled        : 1;
        BOOLEAN ServerInitiatedEnabled  : 1;
    };
} QUIC_PATHID_SET_FLAGS;

typedef struct QUIC_PATHID_SET {

    //
    // The per-type Path ID information.
    //
    QUIC_PATHID_TYPE_INFO Types[NUMBER_OF_PATHID_TYPES];

    //
    // The current flags for path id set.
    //
    QUIC_PATHID_SET_FLAGS Flags;

    //
    // The number of PathIDs. Value of less than 2
    // indicates only a single PathID (may be NULL) is bound.
    //
    uint32_t PathIDCount;

    //
    // PathID lookup.
    //
    union {
        void* LookupTable;
        struct {
            //
            // Single PathID is bound.
            //
            QUIC_PATHID* PathID;
        } SINGLE;
        struct {
            //
            // Hash table.
            //
            CXPLAT_HASHTABLE* Table;
        } HASH;
    };

} QUIC_PATHID_SET;

//
// Initializes the path id set.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetInitialize(
    _Inout_ QUIC_PATHID_SET* PathIDSet
    );

//
// Uninitializes the path id set.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetUninitialize(
    _Inout_ QUIC_PATHID_SET* PathIDSet
    );

//
// Tracing rundown for the path id set.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetTraceRundown(
    _In_ QUIC_PATHID_SET* PathIDSet
    );

//
// Invoked when the the transport parameters have been received from the peer.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetInitializeTransportParameters(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ uint32_t MaxClientPath,
    _In_ uint32_t MaxServerPath
    );

//
// Invoked when the peer sends a MAX_{CLIENT, SERVER}_PATHS frame.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetUpdateMaxPaths(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ BOOLEAN IsServer,
    _In_ uint32_t MaxPaths
    );

//
// Updates the maximum count of streams allowed for a path id set.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDmSetUpdateMaxCount(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ uint8_t Type,
    _In_ uint16_t Count
    );

//
// Returns the number of available path ids still allowed.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
uint16_t
QuicPathIDSetGetCountAvailable(
    _In_ const QUIC_PATHID_SET* PathIDSet,
    _In_ uint8_t Type
    );

//
// Creates a new local path id.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicPathIDSetNewLocalPathID(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ uint8_t Type,
    _In_ QUIC_PATHID* PathID
    );

//
// Queries the current max Path IDs.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetGetMaxPathIDs(
    _In_ const QUIC_PATHID_SET* PathIDSet,
    _Out_writes_all_(NUMBER_OF_PATHID_TYPES)
        uint64_t* MaxPathIds
    );
