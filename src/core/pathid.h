/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define NUMBER_OF_PATHID_TYPES          2

#define PATHID_ID_MASK                  0b1

#define PATHID_ID_FLAG_IS_CLIENT        0b00
#define PATHID_ID_FLAG_IS_SERVER        0b01

#define PATHID_ID_IS_CLIENT(ID)         ((ID & 1) == 0)
#define PATHID_ID_IS_SERVER(ID)         ((ID & 1) == 1)

//
// Different flags of a stream.
// Note - Keep quictypes.h's copy up to date.
//
typedef union QUIC_PATHID_FLAGS {
    uint64_t AllFlags;
    struct {
        BOOLEAN ServerInitiating        : 1;    // The path id is for server's initiating path.
        BOOLEAN InPathIDTable           : 1;    // The path id is currently in the connection's table.
        BOOLEAN Started                 : 1;    // The path id has started.
        BOOLEAN Freed                   : 1;    // The path id has been freed.
        BOOLEAN LocalBlocked            : 1;    // The path id is blocked by local restriction.
        BOOLEAN PeerBlocked             : 1;    // The path id is blocked by peer restriction.
    };
} QUIC_PATHID_FLAGS;

//
// This structure represents all the per path id specific data.
//
typedef struct QUIC_PATHID {

    //
    // The parent connection for this path id.
    //
    QUIC_CONNECTION* Connection;

    //
    // Unique identifier;
    //
    uint32_t ID;

    //
    // The current flags for this path id.
    //
    QUIC_PATHID_FLAGS Flags;

    //
    // The entry in the connection's hashtable of path ids.
    //
    CXPLAT_HASHTABLE_ENTRY TableEntry;

} QUIC_PATHID;

//
// Allocates and partially initializes a new path id object.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicPathIDInitialize(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN IsServerInitiating,
    _Outptr_ _At_(*PathID, __drv_allocatesMem(Mem))
        QUIC_PATHID** PathID
    );

//
// Free the path id object.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPathIDFree(
    _In_ __drv_freesMem(Mem) QUIC_PATHID* PathID
    );

//
// Start the path id object.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicPathIDStart(
    _In_ QUIC_PATHID* PathID,
    _In_ BOOLEAN IsRemoteStream
    );
