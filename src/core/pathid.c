/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A path id manages the resources for multipath. This file
    contains the initialization and cleanup functionality for the path id.

--*/

#include "precomp.h"

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicPathIDInitialize(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN IsServerInitiating,
    _Outptr_ _At_(*PathID, __drv_allocatesMem(Mem))
        QUIC_PATHID** NewPathID
    )
{
    QUIC_STATUS Status;
    QUIC_PATHID* PathID;
    QUIC_WORKER* Worker = Connection->Worker;

    PathID = CxPlatPoolAlloc(&Worker->PathIDPool);
    if (PathID == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    CxPlatZeroMemory(PathID, sizeof(QUIC_PATHID));

    PathID->Connection = Connection;
    PathID->Flags.ServerInitiating = IsServerInitiating;
    PathID->ID = UINT32_MAX;
    *NewPathID = PathID;

    QuicConnAddRef(Connection, QUIC_CONN_REF_PATHID);

    Status = QUIC_STATUS_SUCCESS;

Exit:
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPathIDFree(
    _In_ __drv_freesMem(Mem) QUIC_PATHID* PathID
    )
{
    QUIC_CONNECTION* Connection = PathID->Connection;
    QUIC_WORKER* Worker = Connection->Worker;

    PathID->Flags.Freed = TRUE;
    CxPlatPoolFree(&Worker->PathIDPool, PathID);

    QuicConnRelease(Connection, QUIC_CONN_REF_PATHID);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicPathIDStart(
    _In_ QUIC_PATHID* PathID,
    _In_ BOOLEAN IsRemotePathID
    )
{
    QUIC_STATUS Status;

    if (!IsRemotePathID) {
        uint8_t Type =
            PathID->Flags.ServerInitiating ?
                PATHID_ID_FLAG_IS_SERVER :
                PATHID_ID_FLAG_IS_CLIENT;
        Status =
            QuicPathIDSetNewLocalPathID(
                &PathID->Connection->PathIDs,
                Type,
                PathID);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }
    } else {
        Status = QUIC_STATUS_SUCCESS;
    }

    PathID->Flags.Started = TRUE;

Exit:
    return Status;
}
