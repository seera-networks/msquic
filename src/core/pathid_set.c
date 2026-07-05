/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A path id set manages all PathID-related state for a single connection. It
    keeps track of locally and remotely initiated path ids, and synchronizes max
    path ids with the peer.

--*/

#include "precomp.h"

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetInitialize(
    _Inout_ QUIC_PATHID_SET* PathIDSet
    )
{
    PathIDSet->Types[PATHID_ID_FLAG_IS_CLIENT].MaxCurrentPathIDCount = 1;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetUninitialize(
    _Inout_ QUIC_PATHID_SET* PathIDSet
    )
{
    if (PathIDSet->PathIDCount > 1) {
        CxPlatHashtableUninitialize(PathIDSet->HASH.Table);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicPathIDSetInsertPathID(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ QUIC_PATHID* PathID
    )
{
    if (PathIDSet->PathIDCount == 0) {
        PathID->Flags.InPathIDTable = TRUE;
        PathIDSet->SINGLE.PathID = PathID;
        return TRUE;
    } else if (PathIDSet->PathIDCount == 1) {
        QUIC_PATHID* ExisitingPathID = PathIDSet->SINGLE.PathID;

        //
        // Lazily initialize the hash table.
        //
        if (!CxPlatHashtableInitialize(&PathIDSet->HASH.Table, CXPLAT_HASH_MIN_SIZE)) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "pathid hash table",
                0);
            return FALSE;
        }

        CxPlatHashtableInsert(
            PathIDSet->HASH.Table,
            &PathID->TableEntry,
            (uint32_t)ExisitingPathID->ID,
            NULL);
    }

    PathID->Flags.InPathIDTable = TRUE;
    CxPlatHashtableInsert(
        PathIDSet->HASH.Table,
        &PathID->TableEntry,
        (uint32_t)PathID->ID,
        NULL);
    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathIDSetInitializeTransportParameters(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ uint32_t MaxClientPathID,
    _In_ uint32_t MaxServerPathID
    )
{
    //QUIC_CONNECTION* Connection = QuicPathIDSetGetConnection(PathIDSet);

    PathIDSet->Flags.MultipathEnabled = TRUE;
    PathIDSet->Types[PATHID_ID_FLAG_IS_CLIENT].MaxPathID = QUIC_ACTIVE_PATH_ID_LIMIT - 1;
    PathIDSet->Types[PATHID_ID_FLAG_IS_CLIENT].PeerMaxPathID = MaxClientPathID;
    PathIDSet->Types[PATHID_ID_FLAG_IS_CLIENT].MaxCurrentPathIDCount = QUIC_ACTIVE_PATH_ID_LIMIT;

    if (MaxServerPathID != UINT32_MAX) {
        PathIDSet->Flags.ServerInitiatedEnabled = TRUE;
        PathIDSet->Types[PATHID_ID_FLAG_IS_SERVER].MaxPathID = QUIC_ACTIVE_PATH_ID_LIMIT - 1;
        PathIDSet->Types[PATHID_ID_FLAG_IS_SERVER].PeerMaxPathID = MaxServerPathID;
        PathIDSet->Types[PATHID_ID_FLAG_IS_SERVER].MaxCurrentPathIDCount = QUIC_ACTIVE_PATH_ID_LIMIT;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicPathIDSetNewLocalPathID(
    _Inout_ QUIC_PATHID_SET* PathIDSet,
    _In_ uint8_t Type,
    _In_ QUIC_PATHID* PathID
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    QUIC_PATHID_TYPE_INFO* Info = &PathIDSet->Types[Type];
    uint32_t NewPathId = Type + (Info->TotalPathIDCount << 2);

    PathID->ID = NewPathId;

    if (!QuicPathIDSetInsertPathID(PathIDSet, PathID)) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        PathID->ID = UINT32_MAX;
        goto Exit;
    }

    Info->CurrentPathIDCount++;
    Info->TotalPathIDCount++;

    if (Info->MaxCurrentPathIDCount < Info->CurrentPathIDCount) {
        Info->MaxCurrentPathIDCount = Info->CurrentPathIDCount;
    }
    if (PathID->ID > Type + (Info->MaxPathID << 2)) {
        PathID->Flags.BlockedByPeer = TRUE;
    }
Exit:
    return Status;
}
