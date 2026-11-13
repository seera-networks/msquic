/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    The connection is the topmost structure that all connection-specific state
    and logic is derived from. Connections are only ever processed by one
    thread at a time. Other threads may queue operations on the connection, but
    the operations are only drained and processed serially, by a single thread;
    though the thread that does the draining may change over time. All
    events/triggers/API calls are processed via operations.

    The connection drains operations in the QuicConnDrainOperations function.
    The only requirement here is that this function is not called in parallel
    on multiple threads. The function will drain up to QUIC_SETTINGS_INTERNAL's
    MaxOperationsPerDrain operations per call, so as to not starve any other
    work.

    While most of the connection specific work is managed by other modules,
    the following things are managed in this file:

    Connection Lifetime - Initialization, handshake and state changes, shutdown,
    closure and cleanup are located here.

    Receive Path - The per-connection packet receive path is here. This is the
    logic that happens after the global receive callback has processed the
    packet initially and done the necessary processing to pass the packet to
    the correct connection.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "connection.c.clog.h"
#endif

typedef struct QUIC_RECEIVE_PROCESSING_STATE {
    BOOLEAN ResetIdleTimeout;
    BOOLEAN UpdatePartitionId;
    uint16_t PartitionIndex;
} QUIC_RECEIVE_PROCESSING_STATE;


_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnApplyNewSettings(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN OverWrite,
    _In_ const QUIC_SETTINGS_INTERNAL* NewSettings
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
_Success_(return == QUIC_STATUS_SUCCESS)
QUIC_STATUS
QuicConnAlloc(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ QUIC_PARTITION* Partition,
    _In_opt_ QUIC_WORKER* Worker,
    _In_opt_ const QUIC_RX_PACKET* Packet,
    _Outptr_ _At_(*NewConnection, __drv_allocatesMem(Mem))
        QUIC_CONNECTION** NewConnection
    )
{
    BOOLEAN IsServer = Packet != NULL;
    *NewConnection = NULL;
    QUIC_STATUS Status;

    const uint16_t PartitionId = QuicPartitionIdCreate(Partition->Index);
    CXPLAT_DBG_ASSERT(Partition->Index == QuicPartitionIdGetIndex(PartitionId));

    QUIC_CONNECTION* Connection = CxPlatPoolAlloc(&Partition->ConnectionPool);
    if (Connection == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "connection",
            sizeof(QUIC_CONNECTION));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    CxPlatZeroMemory(Connection, sizeof(QUIC_CONNECTION));
    Connection->Partition = Partition;

#if DEBUG
    InterlockedIncrement(&MsQuicLib.ConnectionCount);
    QuicLibraryTrackDbgObject(QUIC_DBG_OBJECT_TYPE_CONNECTION, &Connection->DbgObjectLink);
#endif
    QuicPerfCounterIncrement(Connection->Partition, QUIC_PERF_COUNTER_CONN_CREATED);
    QuicPerfCounterIncrement(Connection->Partition, QUIC_PERF_COUNTER_CONN_ACTIVE);

    Connection->Stats.CorrelationId =
        InterlockedIncrement64((int64_t*)&MsQuicLib.ConnectionCorrelationId) - 1;
    QuicTraceEvent(
        ConnCreated,
        "[conn][%p] Created, IsServer=%hhu, CorrelationId=%llu",
        Connection,
        IsServer,
        Connection->Stats.CorrelationId);

    Connection->RefCount = 1;
#if DEBUG
    CxPlatRefInitializeMultiple(Connection->RefTypeBiasedCount, QUIC_CONN_REF_COUNT);
    CxPlatRefIncrement(&Connection->RefTypeBiasedCount[QUIC_CONN_REF_HANDLE_OWNER]);
#endif
    Connection->PartitionID = PartitionId;
    Connection->State.Allocated = TRUE;
    Connection->State.IsQMux = FALSE;
    Connection->State.ShareBinding = IsServer;
    Connection->State.FixedBit = TRUE;
    Connection->Stats.Timing.Start = CxPlatTimeUs64();
    Connection->AckDelayExponent = QUIC_ACK_DELAY_EXPONENT;
    Connection->PacketTolerance = QUIC_MIN_ACK_SEND_NUMBER;
    Connection->PeerPacketTolerance = QUIC_MIN_ACK_SEND_NUMBER;
    Connection->ReorderingThreshold = QUIC_MIN_REORDERING_THRESHOLD;
    Connection->PeerReorderingThreshold = QUIC_MIN_REORDERING_THRESHOLD;
    Connection->PeerTransportParams.AckDelayExponent = QUIC_TP_ACK_DELAY_EXPONENT_DEFAULT;
    Connection->ReceiveQueueTail = &Connection->ReceiveQueue;
    QuicSettingsCopy(&Connection->Settings, &MsQuicLib.Settings);
    Connection->Settings.IsSetFlags = 0; // Just grab the global values, not IsSet flags.
    CxPlatDispatchLockInitialize(&Connection->ReceiveQueueLock);
    CxPlatListInitializeHead(&Connection->BoundAddresses);
    CxPlatListInitializeHead(&Connection->CandidateAddresses);
    QuicStreamSetInitialize(&Connection->Streams);
    QuicSendBufferInitialize(&Connection->SendBuffer);
    QuicOperationQueueInitialize(&Connection->OperQ);
    QuicSendInitialize(&Connection->Send, &Connection->Settings);
    QuicPathIDSetInitialize(&Connection->PathIDs);
    QuicDatagramInitialize(&Connection->Datagram, IsServer);
    QuicRangeInitialize(
        QUIC_MAX_RANGE_DECODE_ACKS,
        &Connection->DecodedAckRanges);

    QUIC_PATHID *PathID = NULL;

    QUIC_PATH* Path = &Connection->Paths[0];
    QuicPathInitialize(Connection, Path, QUIC_PATH_ORIGIN_INITIAL);
    Path->IsActive = TRUE;
    Connection->PathsCount = 1;

    Connection->EarliestExpirationTime = UINT64_MAX;
    for (QUIC_CONN_TIMER_TYPE Type = 0; Type < QUIC_CONN_TIMER_COUNT; ++Type) {
        Connection->ExpirationTimes[Type] = UINT64_MAX;
    }

    if (IsServer) {

        Connection->Type = QUIC_HANDLE_TYPE_CONNECTION_SERVER;
        if (MsQuicLib.Settings.LoadBalancingMode == QUIC_LOAD_BALANCING_SERVER_ID_IP) {
            CxPlatRandom(1, Connection->ServerID); // Randomize the first byte.
            if (QuicAddrGetFamily(&Packet->Route->LocalAddress) == QUIC_ADDRESS_FAMILY_INET) {
                CxPlatCopyMemory(
                    Connection->ServerID + 1,
                    &Packet->Route->LocalAddress.Ipv4.sin_addr,
                    4);
            } else {
                CxPlatCopyMemory(
                    Connection->ServerID + 1,
                    ((uint8_t*)&Packet->Route->LocalAddress.Ipv6.sin6_addr) + 12,
                    4);
            }
        } else if (MsQuicLib.Settings.LoadBalancingMode == QUIC_LOAD_BALANCING_SERVER_ID_FIXED) {
            CxPlatRandom(1, Connection->ServerID); // Randomize the first byte.
            CxPlatCopyMemory(
                Connection->ServerID + 1,
                &MsQuicLib.Settings.FixedServerID,
                sizeof(MsQuicLib.Settings.FixedServerID));
        }

        Connection->Stats.QuicVersion = Packet->Invariant->LONG_HDR.Version;
        QuicConnOnQuicVersionSet(Connection);
        QuicCopyRouteInfo(&Path->Route, Packet->Route);
        Connection->State.LocalAddressSet = TRUE;
        Connection->State.RemoteAddressSet = TRUE;

        QuicTraceEvent(
            ConnLocalAddrAdded,
            "[conn][%p] New Local IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Path->Route.LocalAddress), &Path->Route.LocalAddress));

        QuicTraceEvent(
            ConnRemoteAddrAdded,
            "[conn][%p] New Remote IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Path->Route.RemoteAddress), &Path->Route.RemoteAddress));

        BOOLEAN FatalError = FALSE;
        PathID = QuicPathIDSetGetPathIDForPeer(
            &Connection->PathIDs,
            0,
            TRUE,
            &FatalError);
        if (PathID == NULL) {
            Status = QUIC_STATUS_INTERNAL_ERROR;
            goto Error;
        }
        QuicPathIDAddRef(PathID, QUIC_PATHID_REF_PATH);
        Path->PathID = PathID;
        PathID->Path = Path;
        PathID->Flags.InUse = TRUE;
        QuicCongestionControlInitialize(&PathID->CongestionControl, &Connection->Settings);

        Path->DestCid =
            QuicCidNewDestination(Packet->SourceCidLen, Packet->SourceCid);
        if (Path->DestCid == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }
        QUIC_CID_SET_PATH(Connection, Path->DestCid, Path);
        Path->DestCid->CID.UsedLocally = TRUE;
        QuicPathIDAddDestCID(PathID, Path->DestCid);

        QUIC_CID_SLIST_ENTRY* SourceCid =
            QuicCidNewSource(PathID, Packet->DestCidLen, Packet->DestCid);
        if (SourceCid == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }
        SourceCid->CID.IsInitial = TRUE;
        SourceCid->CID.UsedByPeer = TRUE;
        QuicPathIDAddSourceCID(PathID, SourceCid, TRUE);

        //
        // Server lazily finishes initialization in response to first operation.
        //

    } else {
        Connection->Type = QUIC_HANDLE_TYPE_CONNECTION_CLIENT;
        Connection->State.ExternalOwner = TRUE;
        Path->IsPeerValidated = TRUE;
        Path->Allowance = UINT32_MAX;

        Status = QuicPathIDSetNewLocalPathID(&Connection->PathIDs, &PathID);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
        QuicPathIDAddRef(PathID, QUIC_PATHID_REF_LOOKUP);
        QuicPathIDAddRef(PathID, QUIC_PATHID_REF_PATH);
        Path->PathID = PathID;
        PathID->Path = Path;
        PathID->Flags.InUse = TRUE;
        QuicCongestionControlInitialize(&PathID->CongestionControl, &Connection->Settings);

        Path->DestCid = QuicCidNewRandomDestination();
        if (Path->DestCid == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }
        QUIC_CID_SET_PATH(Connection, Path->DestCid, Path);
        Path->DestCid->CID.UsedLocally = TRUE;
        PathID->DestCidCount++;
        QuicPathIDAddDestCID(PathID, Path->DestCid);

        Connection->State.Initialized = TRUE;
        QuicTraceEvent(
            ConnInitializeComplete,
            "[conn][%p] Initialize complete",
            Connection);
    }

    QuicPathValidate(Path);
    if (Worker != NULL) {
        QuicWorkerAssignConnection(Worker, Connection);
    }
    if (!QuicConnRegister(Connection, Registration)) {
        Status = QUIC_STATUS_INVALID_STATE;
        goto Error;
    }
    QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);

    *NewConnection = Connection;
    return QUIC_STATUS_SUCCESS;

Error:

    Connection->State.HandleClosed = TRUE;
    if (PathID != NULL) {
        if (PathID->SourceCids.Next != NULL) {
            CXPLAT_FREE(
                CXPLAT_CONTAINING_RECORD(
                    PathID->SourceCids.Next,
                    QUIC_CID_SLIST_ENTRY,
                    Link),
                QUIC_POOL_CIDSLIST);
            PathID->SourceCids.Next = NULL;
        }
        QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
    }
    while (!CxPlatListIsEmpty(&Connection->BoundAddresses)) {
        QUIC_BOUND_ADDRESS_LIST_ENTRY *Bound =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&Connection->BoundAddresses),
                QUIC_BOUND_ADDRESS_LIST_ENTRY,
                Link);
        if (Bound->Binding != NULL) {
            QuicLibraryReleaseBinding(Bound->Binding);
            Bound->Binding = NULL;
        }
        CXPLAT_FREE(Bound, QUIC_POOL_BOUND_ADDRESS_LIST);
    }
    QuicConnRelease(Connection, QUIC_CONN_REF_HANDLE_OWNER);

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
_Success_(return == QUIC_STATUS_SUCCESS)
QUIC_STATUS
QuicConnQMuxAlloc(
    _In_ QUIC_REGISTRATION* Registration,
    _In_ QUIC_PARTITION* Partition,
    _In_opt_ QUIC_WORKER* Worker,
    _In_ BOOLEAN IsServer,
    _Outptr_ _At_(*NewConnection, __drv_allocatesMem(Mem))
        QUIC_CONNECTION** NewConnection
    )
{
    *NewConnection = NULL;
    QUIC_STATUS Status;

    const uint16_t PartitionId = QuicPartitionIdCreate(Partition->Index);
    CXPLAT_DBG_ASSERT(Partition->Index == QuicPartitionIdGetIndex(PartitionId));

    QUIC_CONNECTION* Connection = CxPlatPoolAlloc(&Partition->ConnectionPool);
    if (Connection == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "connection",
            sizeof(QUIC_CONNECTION));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    CxPlatZeroMemory(Connection, sizeof(QUIC_CONNECTION));
    Connection->Partition = Partition;

    Status = QuicQMuxInitialize(Connection, &Connection->QMux);
    if (QUIC_FAILED(Status)) {
        CxPlatPoolFree(Connection);
        return Status;
    }

#if DEBUG
    InterlockedIncrement(&MsQuicLib.ConnectionCount);
    QuicLibraryTrackDbgObject(QUIC_DBG_OBJECT_TYPE_CONNECTION, &Connection->DbgObjectLink);
#endif
    QuicPerfCounterIncrement(Connection->Partition, QUIC_PERF_COUNTER_CONN_CREATED);
    QuicPerfCounterIncrement(Connection->Partition, QUIC_PERF_COUNTER_CONN_ACTIVE);

    Connection->Stats.CorrelationId =
        InterlockedIncrement64((int64_t*)&MsQuicLib.ConnectionCorrelationId) - 1;
    QuicTraceEvent(
        ConnCreated,
        "[conn][%p] Created, IsServer=%hhu, CorrelationId=%llu",
        Connection,
        IsServer,
        Connection->Stats.CorrelationId);

    Connection->RefCount = 1;
#if DEBUG
    CxPlatRefInitializeMultiple(Connection->RefTypeBiasedCount, QUIC_CONN_REF_COUNT);
    CxPlatRefIncrement(&Connection->RefTypeBiasedCount[QUIC_CONN_REF_HANDLE_OWNER]);
#endif
    Connection->PartitionID = PartitionId;
    Connection->State.Allocated = TRUE;
    Connection->State.IsQMux = TRUE;
    Connection->State.FixedBit = TRUE;
    Connection->Stats.Timing.Start = CxPlatTimeUs64();
    QuicSettingsCopy(&Connection->Settings, &MsQuicLib.Settings);
    Connection->Settings.IsSetFlags = 0; // Just grab the global values, not IsSet flags.
    QuicStreamSetInitialize(&Connection->Streams);
    QuicSendBufferInitialize(&Connection->SendBuffer);
    QuicOperationQueueInitialize(&Connection->OperQ);
    QuicSendInitialize(&Connection->Send, &Connection->Settings);
    QuicDatagramInitialize(&Connection->Datagram, IsServer);

    Connection->EarliestExpirationTime = UINT64_MAX;
    for (QUIC_CONN_TIMER_TYPE Type = 0; Type < QUIC_CONN_TIMER_COUNT; ++Type) {
        Connection->ExpirationTimes[Type] = UINT64_MAX;
    }

    if (IsServer) {
        Connection->Type = QUIC_HANDLE_TYPE_CONNECTION_SERVER;
        //
        // Server lazily finishes initialization in response to first operation.
        //
    } else {
        Connection->Type = QUIC_HANDLE_TYPE_CONNECTION_CLIENT;
        Connection->State.ExternalOwner = TRUE;
        Connection->State.Initialized = TRUE;
        QuicTraceEvent(
            ConnInitializeComplete,
            "[conn][%p] Initialize complete",
            Connection);
    }

    if (Worker != NULL) {
        QuicWorkerAssignConnection(Worker, Connection);
    }
    if (!QuicConnRegister(Connection, Registration)) {
        Status = QUIC_STATUS_INVALID_STATE;
        goto Error;
    }

    *NewConnection = Connection;
    return QUIC_STATUS_SUCCESS;

Error:

    Connection->State.HandleClosed = TRUE;
    QuicConnRelease(Connection, QUIC_CONN_REF_HANDLE_OWNER);

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnFree(
    _In_ __drv_freesMem(Mem) QUIC_CONNECTION* Connection
    )
{
    QUIC_PARTITION* Partition = Connection->Partition;
#ifdef QUIC_SILO
    QUIC_SILO Silo = NULL;
    QuicConfigurationAttachSilo(Connection->Configuration);
#endif

    CXPLAT_FRE_ASSERT(!Connection->State.Freed);
    CXPLAT_TEL_ASSERT(Connection->RefCount == 0);
    if (Connection->State.ExternalOwner) {
        CXPLAT_TEL_ASSERT(Connection->State.HandleClosed);
    }
    CXPLAT_TEL_ASSERT(CxPlatListIsEmpty(&Connection->Streams.ClosedStreams));
    QuicRangeUninitialize(&Connection->DecodedAckRanges);
    QuicCryptoUninitialize(&Connection->Crypto);
    QuicSendUninitialize(&Connection->Send);
#if DEBUG
    while (!CxPlatListIsEmpty(&Connection->Streams.AllStreams)) {
        QUIC_STREAM *Stream =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&Connection->Streams.AllStreams),
                QUIC_STREAM,
                AllStreamsLink);
        CXPLAT_DBG_ASSERTMSG(Stream != NULL, "Stream was leaked!");
    }
#endif
    while (!CxPlatListIsEmpty(&Connection->BoundAddresses)) {
        QUIC_BOUND_ADDRESS_LIST_ENTRY *Bound =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&Connection->BoundAddresses),
                QUIC_BOUND_ADDRESS_LIST_ENTRY,
                Link);
        if (Bound->Binding != NULL) {
            QuicLibraryReleaseBinding(Bound->Binding);
            Bound->Binding = NULL;
        }
        CXPLAT_FREE(Bound, QUIC_POOL_BOUND_ADDRESS_LIST);
    }
    while (!CxPlatListIsEmpty(&Connection->CandidateAddresses)) {
        QUIC_CANDIDATE_ADDRESS_LIST_ENTRY *Candidate =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&Connection->CandidateAddresses),
                QUIC_CANDIDATE_ADDRESS_LIST_ENTRY,
                Link);
        CXPLAT_FREE(Candidate, QUIC_POOL_CANDIDATE_ADDRESS_LIST);
    }
    QuicPathIDSetFree(&Connection->PathIDs);
    QuicConnUnregister(Connection);
    if (Connection->Worker != NULL) {
        QuicTimerWheelRemoveConnection(&Connection->Worker->TimerWheel, Connection);
        QuicOperationQueueClear(&Connection->OperQ, Partition);
    }
    if (Connection->ReceiveQueue != NULL) {
        QUIC_RX_PACKET* Packet = Connection->ReceiveQueue;
        do {
            Packet->QueuedOnConnection = FALSE;
        } while ((Packet = (QUIC_RX_PACKET*)Packet->Next) != NULL);
        CxPlatRecvDataReturn((CXPLAT_RECV_DATA*)Connection->ReceiveQueue);
        Connection->ReceiveQueue = NULL;
    }
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        if (Connection->Paths[i].PathID != NULL) {
            QuicPathIDRelease(Connection->Paths[i].PathID, QUIC_PATHID_REF_PATH);
            Connection->Paths[i].PathID = NULL;
        }
        if (Connection->Paths[i].Binding != NULL) {
            QuicLibraryReleaseBinding(Connection->Paths[i].Binding);
            Connection->Paths[i].Binding = NULL;
        }
    }
    CxPlatDispatchLockUninitialize(&Connection->ReceiveQueueLock);
    QuicOperationQueueUninitialize(&Connection->OperQ);
    QuicStreamSetUninitialize(&Connection->Streams);
    QuicPathIDSetUninitialize(&Connection->PathIDs);
    QuicSendBufferUninitialize(&Connection->SendBuffer);
    QuicDatagramSendShutdown(&Connection->Datagram);
    QuicDatagramUninitialize(&Connection->Datagram);
    if (Connection->Configuration != NULL) {
#ifdef QUIC_SILO
        //
        // Take a ref on the silo before releasing the configuration
        // to prevent the silo from being destroyed while we are still
        // holding onto the thread to clean up other stuff for this connection.
        //
        Silo = Connection->Configuration->Silo;
        QuicSiloAddRef(Silo);
#endif
        QuicConfigurationRelease(Connection->Configuration, QUIC_CONF_REF_CONNECTION);
        Connection->Configuration = NULL;
    }
    if (Connection->RemoteServerName != NULL) {
        CXPLAT_FREE(Connection->RemoteServerName, QUIC_POOL_SERVERNAME);
    }
    if (Connection->OrigDestCID != NULL) {
        CXPLAT_FREE(Connection->OrigDestCID, QUIC_POOL_CID);
    }
    if (Connection->HandshakeTP != NULL) {
        QuicCryptoTlsCleanupTransportParameters(Connection->HandshakeTP);
        CxPlatPoolFree(Connection->HandshakeTP);
        Connection->HandshakeTP = NULL;
    }
    QuicCryptoTlsCleanupTransportParameters(&Connection->PeerTransportParams);
    QuicSettingsCleanup(&Connection->Settings);
    if (Connection->State.Started && !Connection->State.Connected) {
        QuicPerfCounterIncrement(Partition, QUIC_PERF_COUNTER_CONN_HANDSHAKE_FAIL);
    }
    if (Connection->State.Connected) {
        QuicPerfCounterDecrement(Partition, QUIC_PERF_COUNTER_CONN_CONNECTED);
    }
    if (Connection->Registration != NULL) {
        QuicRegistrationRundownRelease(Connection->Registration, QUIC_REG_REF_CONNECTION);
    }
    if (Connection->CloseReasonPhrase != NULL) {
        CXPLAT_FREE(Connection->CloseReasonPhrase, QUIC_POOL_CLOSE_REASON);
    }
    //
    // Should already be gone: QuicConnOnShutdownComplete releases it, at
    // PASSIVE_LEVEL where the monitor's teardown belongs. Kept as a net so a
    // path that somehow reaches free still returns the reference.
    //
    CXPLAT_DBG_ASSERT(!Connection->AddressMonitorRef);
    if (Connection->AddressMonitorRef) {
        Connection->AddressMonitorRef = FALSE;
        QuicLibraryReleaseAddressMonitor();
    }

    if (Connection->CandidatePairs != NULL) {
        CXPLAT_FREE(Connection->CandidatePairs, QUIC_POOL_CONN);
        Connection->CandidatePairs = NULL;
    }
    Connection->State.Freed = TRUE;
#if DEBUG
    QuicLibraryUntrackDbgObject(QUIC_DBG_OBJECT_TYPE_CONNECTION, &Connection->DbgObjectLink);
#endif
    QuicTraceEvent(
        ConnDestroyed,
        "[conn][%p] Destroyed",
        Connection);
    CxPlatPoolFree(Connection);

#if DEBUG
    InterlockedDecrement(&MsQuicLib.ConnectionCount);
#endif
    QuicPerfCounterDecrement(Partition, QUIC_PERF_COUNTER_CONN_ACTIVE);
#ifdef QUIC_SILO
    QuicConfigurationDetachSilo();
    QuicSiloRelease(Silo);
#endif
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQMuxFree(
    _In_ __drv_freesMem(Mem) QUIC_CONNECTION* Connection
    )
{
    QUIC_PARTITION* Partition = Connection->Partition;
#ifdef QUIC_SILO
    QUIC_SILO Silo = NULL;
    QuicConfigurationAttachSilo(Connection->Configuration);
#endif

    CXPLAT_FRE_ASSERT(!Connection->State.Freed);
    CXPLAT_TEL_ASSERT(Connection->RefCount == 0);
    if (Connection->State.ExternalOwner) {
        CXPLAT_TEL_ASSERT(Connection->State.HandleClosed);
    }
    CXPLAT_TEL_ASSERT(CxPlatListIsEmpty(&Connection->Streams.ClosedStreams));
    QuicSendUninitialize(&Connection->Send);
#if DEBUG
    while (!CxPlatListIsEmpty(&Connection->Streams.AllStreams)) {
        QUIC_STREAM *Stream =
            CXPLAT_CONTAINING_RECORD(
                CxPlatListRemoveHead(&Connection->Streams.AllStreams),
                QUIC_STREAM,
                AllStreamsLink);
        CXPLAT_DBG_ASSERTMSG(Stream != NULL, "Stream was leaked!");
    }
#endif
    QuicConnUnregister(Connection);
    if (Connection->Worker != NULL) {
        QuicTimerWheelRemoveConnection(&Connection->Worker->TimerWheel, Connection);
        QuicOperationQueueClear(&Connection->OperQ, Partition);
    }
    QuicOperationQueueUninitialize(&Connection->OperQ);
    QuicStreamSetUninitialize(&Connection->Streams);
    QuicSendBufferUninitialize(&Connection->SendBuffer);
    QuicDatagramSendShutdown(&Connection->Datagram);
    QuicDatagramUninitialize(&Connection->Datagram);
    if (Connection->Configuration != NULL) {
#ifdef QUIC_SILO
        //
        // Take a ref on the silo before releasing the configuration
        // to prevent the silo from being destroyed while we are still
        // holding onto the thread to clean up other stuff for this connection.
        //
        Silo = Connection->Configuration->Silo;
        QuicSiloAddRef(Silo);
#endif
        QuicConfigurationRelease(Connection->Configuration, QUIC_CONF_REF_CONNECTION);
        Connection->Configuration = NULL;
    }
    if (Connection->RemoteServerName != NULL) {
        CXPLAT_FREE(Connection->RemoteServerName, QUIC_POOL_SERVERNAME);
    }
    QuicSettingsCleanup(&Connection->Settings);
    if (Connection->State.Started && !Connection->State.Connected) {
        QuicPerfCounterIncrement(Partition, QUIC_PERF_COUNTER_CONN_HANDSHAKE_FAIL);
    }
    if (Connection->State.Connected) {
        QuicPerfCounterDecrement(Partition, QUIC_PERF_COUNTER_CONN_CONNECTED);
    }
    if (Connection->Registration != NULL) {
        QuicRegistrationRundownRelease(Connection->Registration, QUIC_REG_REF_CONNECTION);
    }
    if (Connection->CloseReasonPhrase != NULL) {
        CXPLAT_FREE(Connection->CloseReasonPhrase, QUIC_POOL_CLOSE_REASON);
    }
    Connection->State.Freed = TRUE;
#if DEBUG
    QuicLibraryUntrackDbgObject(QUIC_DBG_OBJECT_TYPE_CONNECTION, &Connection->DbgObjectLink);
#endif
    QuicQMuxUninitialize(Connection->QMux);
    Connection->QMux = NULL;
    QuicTraceEvent(
        ConnDestroyed,
        "[conn][%p] Destroyed",
        Connection);
    CxPlatPoolFree(Connection);

#if DEBUG
    InterlockedDecrement(&MsQuicLib.ConnectionCount);
#endif
    QuicPerfCounterDecrement(Partition, QUIC_PERF_COUNTER_CONN_ACTIVE);
#ifdef QUIC_SILO
    QuicConfigurationDetachSilo();
    QuicSiloRelease(Silo);
#endif
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnShutdown(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t Flags,
    _In_ QUIC_VAR_INT ErrorCode,
    _In_ BOOLEAN ShutdownFromRegistration,
    _In_ BOOLEAN ShutdownFromTransport
    )
{
    if (ShutdownFromRegistration &&
        !Connection->State.Started &&
        QuicConnIsClient(Connection)) {
        return;
    }

    uint32_t CloseFlags =
        ShutdownFromTransport ? QUIC_CLOSE_INTERNAL : QUIC_CLOSE_APPLICATION;
    if (Flags & QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT ||
        (!Connection->State.Started && QuicConnIsClient(Connection))) {
        CloseFlags |= QUIC_CLOSE_SILENT;
    }
    if (Flags & QUIC_CONNECTION_SHUTDOWN_FLAG_STATUS) {
        CloseFlags |= QUIC_CLOSE_QUIC_STATUS;
    }

    QuicConnCloseLocally(Connection, CloseFlags, ErrorCode, NULL);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnCloseHandle(
    _In_ QUIC_CONNECTION* Connection
    )
{
    CXPLAT_TEL_ASSERT(!Connection->State.HandleClosed);
    Connection->State.HandleClosed = TRUE;

    QuicConnCloseLocally(
        Connection,
        QUIC_CLOSE_SILENT | QUIC_CLOSE_QUIC_STATUS,
        (uint64_t)QUIC_STATUS_ABORTED,
        NULL);

    if (Connection->State.ProcessShutdownComplete) {
        QuicConnOnShutdownComplete(Connection);
    }

    QuicConnUnregister(Connection);

    QuicTraceEvent(
        ConnHandleClosed,
        "[conn][%p] Handle closed",
        Connection);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnUnregister(
    _Inout_ QUIC_CONNECTION* Connection
    )
{
    if (Connection->State.Registered) {
        CxPlatDispatchLockAcquire(&Connection->Registration->ConnectionLock);
        CxPlatListEntryRemove(&Connection->RegistrationLink);
        CxPlatDispatchLockRelease(&Connection->Registration->ConnectionLock);
        QuicRegistrationRundownRelease(Connection->Registration, QUIC_REG_REF_CONNECTION);

        QuicTraceEvent(
            ConnUnregistered,
            "[conn][%p] Unregistered from %p",
            Connection,
            Connection->Registration);
        Connection->Registration = NULL;
        Connection->State.Registered = FALSE;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
BOOLEAN
QuicConnRegister(
    _Inout_ QUIC_CONNECTION* Connection,
    _Inout_ QUIC_REGISTRATION* Registration
    )
{
    QuicConnUnregister(Connection);

    if (!QuicRegistrationRundownAcquire(Registration, QUIC_REG_REF_CONNECTION)) {
        return FALSE;
    }
    Connection->State.Registered = TRUE;
    Connection->Registration = Registration;
#ifdef CxPlatVerifierEnabledByAddr
    Connection->State.IsVerifying = Registration->IsVerifying;
#endif
    BOOLEAN RegistrationShuttingDown;

    CxPlatDispatchLockAcquire(&Registration->ConnectionLock);
    RegistrationShuttingDown = Registration->ShuttingDown;
    if (!RegistrationShuttingDown) {
        if (Connection->Worker == NULL) {
            QuicRegistrationQueueNewConnection(Registration, Connection);
        }
        CxPlatListInsertTail(&Registration->Connections, &Connection->RegistrationLink);
    }
    CxPlatDispatchLockRelease(&Registration->ConnectionLock);

    if (RegistrationShuttingDown) {
        Connection->State.Registered = FALSE;
        Connection->Registration = NULL;
        QuicRegistrationRundownRelease(Registration, QUIC_REG_REF_CONNECTION);
    } else {
        QuicTraceEvent(
            ConnRegistered,
            "[conn][%p] Registered with %p",
            Connection,
            Registration);
    }

    return !RegistrationShuttingDown;
}

//
// Forward declarations: the policy below drives the path APIs, which are
// defined further down this file with the rest of the parameter handling.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
QUIC_STATUS
QuicConnAddPath(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH_PARAM* Param,
    _In_ QUIC_PATH_ORIGIN Origin,
    _Out_ QUIC_PATH** NewPath
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static
QUIC_STATUS
QuicConnActivatePath(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH_PARAM* Param
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static
QUIC_STATUS
QuicConnRemovePath(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH_PARAM* Param
    );


//
// Whether the connection already sends from this address on some path. The
// comparison ignores the port, since a snapshot entry names an address and a
// path names an endpoint.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
BOOLEAN
QuicConnHasPathOnLocalAddress(
    _In_ const QUIC_CONNECTION* Connection,
    _In_ const QUIC_ADDR* Address
    )
{
    CXPLAT_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        if (Connection->Paths[i].Binding == NULL) {
            continue;
        }
        if (QuicAddrCompareIp(&Connection->Paths[i].Route.LocalAddress, Address)) {
            return TRUE;
        }
    }
    return FALSE;
}


// What the OS says it would send from to reach Remote, or FALSE when it cannot
// say. The answer is the host's own routing decision, which is the one input
// this feature cannot derive from the address snapshot: with two interfaces up
// and every address unchanged, this is the only thing that tells us which one
// now carries traffic to this peer.
//
// Must not be called from the platform's notification callback. The POSIX
// implementation opens a socket and connects it, and the Windows one asks the
// routing stack; neither is something to do on a thread the OS is waiting on.
// Every caller here runs on the connection's worker.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
BOOLEAN
QuicConnGetRouteLocalAddress(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_ADDR* Remote,
    _Out_ QUIC_ADDR* Local
    )
{
    CxPlatZeroMemory(Local, sizeof(*Local));

    const QUIC_STATUS Status =
        CxPlatDataPathGetLocalAddressForRemote(Remote, Local);
    if (QUIC_FAILED(Status)) {
        //
        // No route to the peer at all is the ordinary case here, not an error:
        // an interface going down takes its route with it, and the snapshot
        // ranking is a perfectly good fallback. Traced at verbose for that
        // reason -- a platform with no implementation would otherwise log a
        // warning on every reconciliation.
        //
        QuicTraceLogConnVerbose(
            RouteLocalAddressUnavailable,
            Connection,
            "No route-derived local address, status=0x%x",
            Status);
        return FALSE;
    }

    if (QuicAddrIsWildCard(Local)) {
        //
        // A wildcard answer names no interface, so it is no better than having
        // asked nothing. Rejected rather than passed on, because the selection
        // compares a hint against the snapshot and the wildcard matches
        // nothing there -- this only makes that explicit.
        //
        return FALSE;
    }

    return TRUE;
}

//
// Picks the local address AUTO mode should send from to reach Remote, or NULL
// when the host has nothing usable. Excludes addresses the connection already
// has a path on, since the caller is looking for somewhere new to go.
//
// RouteHint, when given, is the address the OS itself said it would send from
// to reach Remote. It wins outright over the ranking below, because the ranking
// is a set of preferences about addresses and the hint is the routing table's
// answer about this peer: it is the only input here that knows which interface
// actually reaches Remote, and following it is what makes the connection track
// the host's own choice of outgoing interface. It still has to clear the same
// filters as any other candidate and still has to be in the snapshot -- a hint
// naming an address the monitor does not report is a hint about an address this
// connection cannot bind.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
const CXPLAT_LOCAL_ADDRESS*
QuicConnSelectLocalAddress(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(AddressCount) const CXPLAT_LOCAL_ADDRESS* Addresses,
    _In_ uint32_t AddressCount,
    _In_ const QUIC_ADDR* Remote,
    _In_opt_ const CXPLAT_LOCAL_ADDRESS* Replacing,
    _In_ BOOLEAN ExcludeAddressesInUse,
    _In_opt_ const QUIC_ADDR* RouteHint
    )
{
    const QUIC_ADDRESS_FAMILY Family = QuicAddrGetFamily(Remote);
    const CXPLAT_LOCAL_ADDRESS* Best = NULL;
    const CXPLAT_LOCAL_ADDRESS* Hinted = NULL;

    //
    // Whether the peer is on this host, and whether it is only reachable
    // on-link. These decide which classes of local address can carry the
    // connection at all, below.
    //
    const BOOLEAN RemoteIsLoopback = QuicCandidateAddressIsLoopback(Remote);
    const BOOLEAN RemoteIsLinkLocal = QuicCandidateAddressIsLinkLocal(Remote);

    for (uint32_t i = 0; i < AddressCount; ++i) {
        const CXPLAT_LOCAL_ADDRESS* Candidate = &Addresses[i];

        //
        // Only an address of the peer's family can carry this connection.
        // There is no mapping step here: a v4 peer needs a v4 source.
        //
        if (QuicAddrGetFamily(&Candidate->Address) != Family) {
            continue;
        }

        if (ExcludeAddressesInUse &&
            QuicConnHasPathOnLocalAddress(Connection, &Candidate->Address)) {
            continue;
        }

        //
        // Excluded outright, not merely ranked last. The platform keeps
        // loopback and link-local in the snapshot on purpose -- whether to use
        // one is policy, and this is where that policy lives -- but neither can
        // carry traffic to a peer outside its scope. Ranking them would make
        // them the choice of last resort, which is worse than having no
        // candidate: AUTO would rebind the active path to an address that can
        // never reach the peer, retiring a CID and resetting congestion
        // control on the way, instead of holding the connection and waiting
        // for a real address.
        //
        // Scope is read from the address as well as from the platform's flag.
        // The flag is what a backend reports; the address is what it is. Not
        // every source of a snapshot sets flags -- the test injection
        // parameter does not -- and a filter that can be switched off by a
        // missing flag is not much of a filter.
        //
        const BOOLEAN CandidateIsLoopback =
            (Candidate->Flags & CXPLAT_ADDRESS_FLAG_LOOPBACK) ||
            QuicCandidateAddressIsLoopback(&Candidate->Address);
        const BOOLEAN CandidateIsLinkLocal =
            (Candidate->Flags & CXPLAT_ADDRESS_FLAG_LINK_LOCAL) ||
            QuicCandidateAddressIsLinkLocal(&Candidate->Address);

        //
        // Symmetric, and that is a behaviour change rather than a refactor.
        //
        // This filter used to reject only a narrow local address for a wider
        // remote, which let a global local address through for a loopback or
        // link-local remote -- nothing sends from 10.0.0.1 to 127.0.0.2, or to
        // an fe80:: peer. It did not matter much while the ranking derived
        // narrowness from the platform's flag alone, because a flagless
        // 169.254.x address then tied with a global one and fell through to the
        // later keys. The shared ranker derives it from the address too, so
        // without this the global address would be actively preferred for a
        // link-local peer and AUTO would migrate onto something that cannot
        // reach it. Matching QuicCandidatePairIsViable fixes both.
        //
        if (CandidateIsLoopback != RemoteIsLoopback) {
            continue;
        }
        if (CandidateIsLinkLocal != RemoteIsLinkLocal) {
            continue;
        }

        //
        // Recorded rather than returned from inside the loop, so that the
        // snapshot entry is the one that is used -- the hint carries an address
        // and a port, the snapshot entry carries the platform's flags, and it
        // is the flags the caller goes on to make decisions with.
        //
        // Compared on the IP alone: the hint comes back from a connected socket
        // and so names an ephemeral port, which is not the port this connection
        // will use.
        //
        if (RouteHint != NULL &&
            Hinted == NULL &&
            QuicAddrCompareIp(&Candidate->Address, RouteHint)) {
            Hinted = Candidate;
        }

        if (Best == NULL ||
            QuicCandidateLocalAddressIsBetter(
                Candidate,
                Best,
                Replacing != NULL && !!(Replacing->Flags & CXPLAT_ADDRESS_FLAG_TEMPORARY),
                Replacing != NULL)) {
            Best = Candidate;
        }
    }

    return Hinted != NULL ? Hinted : Best;
}


//
// Tells the application the active path's local address changed, whatever
// moved it -- AUTO's own migration or an application ACTIVATE_PATH. Compared
// against what the caller captured before the operation.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnIndicateLocalAddressChanged(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_ADDR* Previous
    )
{
    const QUIC_ADDR* Current = &Connection->Paths[0].Route.LocalAddress;
    if (QuicAddrCompare(Previous, Current)) {
        return;
    }

    QUIC_CONNECTION_EVENT Event;
    Event.Type = QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED;
    Event.LOCAL_ADDRESS_CHANGED.Address = Current;
    QuicTraceLogConnVerbose(
        IndicateLocalAddressChanged,
        Connection,
        "Indicating QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED");
    (void)QuicConnIndicateEvent(Connection, &Event);
}


//
// Finds a path other than the active one that the peer has already validated,
// so it can be made active without waiting. Returns NULL when there is none.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
QUIC_PATH*
QuicConnFindValidatedAlternatePath(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(AddressCount) const CXPLAT_LOCAL_ADDRESS* Addresses,
    _In_ uint32_t AddressCount
    )
{
    CXPLAT_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
    for (uint8_t i = 1; i < Connection->PathsCount; ++i) {
        QUIC_PATH* Path = &Connection->Paths[i];
        if (Path->Binding == NULL || !Path->IsPeerValidated) {
            continue;
        }

        //
        // The same screening QuicPathSetActive's other caller does, and for
        // the same reason: QuicPathSetActive asserts on the destination CID,
        // and a path that is closing is not one to move onto. Keeping the two
        // sites in agreement is the whole point -- they diverged once already.
        //
        if (Path->PathID == NULL ||
            Path->LocalClose ||
            Path->RemoteClose ||
            Path->DestCid == NULL ||
            Path->DestCid->CID.Retired) {
            continue;
        }

        //
        // No point moving onto a path whose own local address the host has
        // also just lost.
        //
        BOOLEAN StillThere = FALSE;
        for (uint32_t j = 0; j < AddressCount; ++j) {
            if (QuicAddrCompareIp(&Path->Route.LocalAddress, &Addresses[j].Address)) {
                StillThere = TRUE;
                break;
            }
        }
        if (StillThere) {
            return Path;
        }
    }
    return NULL;
}


//
// What to make of a path API refusing a migration AUTO wanted.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
void
QuicConnAutoNoteMigrationFailure(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_STATUS Status
    )
{
    if (Status == QUIC_STATUS_INVALID_STATE) {
        //
        // "Retry later", not "failed". This is what comes back when there is no
        // unused destination CID to migrate onto, and the peer is the only one
        // who can fix that. Reconciliation re-runs from the NEW_CONNECTION_ID
        // handler; treating it as an error would strand the connection on a
        // path it already knows is dead.
        //
        Connection->AddressMigrationDeferred = TRUE;
        QuicTraceLogConnInfo(
            AutoMigrateDeferred,
            Connection,
            "AUTO deferred a migration until the peer issues a new CID");
        return;
    }

    QuicTraceLogConnWarning(
        AutoMigrateFailed,
        Connection,
        "AUTO failed to migrate, status=0x%x",
        Status);
}


//
// Whether AUTO may make an optional change yet. Losing the active path's
// address is never held down -- that one is not optional, and rate-limiting it
// would strand the connection. This gates the changes that are only an
// improvement, where flapping is the worse failure.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
BOOLEAN
QuicConnAutoHoldDownElapsed(
    _In_ const QUIC_CONNECTION* Connection
    )
{
    const uint32_t HoldDownMs = Connection->Settings.AutoMigrationHoldDownMs;
    if (HoldDownMs == 0 || Connection->LastAutoMigrationTimeUs == 0) {
        return TRUE;
    }
    return
        CxPlatTimeDiff64(Connection->LastAutoMigrationTimeUs, CxPlatTimeUs64()) >=
            MS_TO_US((uint64_t)HoldDownMs);
}

//
// How much of the hold-down window is left, in microseconds, or zero if it has
// elapsed. The reconciler needs the remainder rather than the yes/no answer,
// because it has to come back when the window closes.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
uint64_t
QuicConnAutoHoldDownRemainingUs(
    _In_ const QUIC_CONNECTION* Connection
    )
{
    const uint32_t HoldDownMs = Connection->Settings.AutoMigrationHoldDownMs;
    if (HoldDownMs == 0 || Connection->LastAutoMigrationTimeUs == 0) {
        return 0;
    }
    const uint64_t WindowUs = MS_TO_US((uint64_t)HoldDownMs);
    const uint64_t ElapsedUs =
        CxPlatTimeDiff64(Connection->LastAutoMigrationTimeUs, CxPlatTimeUs64());
    return ElapsedUs >= WindowUs ? 0 : WindowUs - ElapsedUs;
}

//
// Drops the paths whose local address the host no longer has, skipping the one
// that is now active. Never removes the last path: with a single path left
// QuicConnRemovePath aborts the connection, and offline is not a failure.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
void
QuicConnAutoRemoveLostPaths(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(LostCount) const QUIC_PATH_PARAM* LostPaths,
    _In_ uint32_t LostCount,
    _In_ const QUIC_ADDR* KeepLocal,
    _In_ const QUIC_ADDR* KeepRemote
    )
{
    for (uint32_t i = 0; i < LostCount; ++i) {
        if (QuicAddrCompare(LostPaths[i].LocalAddress, KeepLocal) &&
            QuicAddrCompare(LostPaths[i].RemoteAddress, KeepRemote)) {
            continue;
        }

        if (Connection->PathsCount <= 1) {
            //
            // Nothing left to fall back to. Keeping a dead path beats aborting.
            //
            break;
        }

        QUIC_ADDR Local = *LostPaths[i].LocalAddress;
        QUIC_ADDR Remote = *LostPaths[i].RemoteAddress;
        QUIC_PATH_PARAM Param;
        Param.LocalAddress = &Local;
        Param.RemoteAddress = &Remote;

        const QUIC_STATUS Status = QuicConnRemovePath(Connection, &Param);
        if (QUIC_FAILED(Status)) {
            QuicTraceLogConnWarning(
                AutoRemovePathFailed,
                Connection,
                "AUTO failed to remove a path whose address was lost, status=0x%x",
                Status);
            continue;
        }
        QuicTraceLogConnInfo(
            AutoRemovedLostPath,
            Connection,
            "AUTO removed a path whose local address was lost");
    }
}


//
// Multipath AUTO. Abandons paths whose address is gone and opens paths on
// addresses that appeared, one per remote already in use.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
void
QuicConnAutoMigrateMultipath(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(AddressCount) const CXPLAT_LOCAL_ADDRESS* Addresses,
    _In_ uint32_t AddressCount,
    _In_reads_(LostCount) const QUIC_PATH_PARAM* LostPaths,
    _In_ uint32_t LostCount,
    _In_ BOOLEAN ActiveLost
    )
{
    //
    // What not to abandon. Starts as the active path and moves to whichever
    // path is promoted, if one is.
    //
    QUIC_ADDR KeepLocal = Connection->Paths[0].Route.LocalAddress;
    QUIC_ADDR KeepRemote = Connection->Paths[0].Route.RemoteAddress;

    //
    // Never leave the connection without an active path: if the active one is
    // going away, hand that role to a validated path before abandoning it.
    //
    if (ActiveLost) {
        QUIC_PATH* Alternate =
            QuicConnFindValidatedAlternatePath(Connection, Addresses, AddressCount);
        if (Alternate != NULL) {
            QUIC_ADDR AlternateLocal = Alternate->Route.LocalAddress;
            QUIC_ADDR AlternateRemote = Alternate->Route.RemoteAddress;
            QUIC_PATH_PARAM Param;
            Param.LocalAddress = &AlternateLocal;
            Param.RemoteAddress = &AlternateRemote;

            const QUIC_STATUS Status = QuicConnActivatePath(Connection, &Param);
            if (QUIC_SUCCEEDED(Status)) {
                QuicTraceLogConnInfo(
                    AutoMigrateMultipathActivate,
                    Connection,
                    "AUTO made a validated path active before abandoning the old one");
                Connection->AddressMigrationDeferred = FALSE;
                Connection->LastAutoMigrationTimeUs = CxPlatTimeUs64();
                //
                // Under multipath, promoting a path only sets its IsActive and
                // sends PATH_AVAILABLE -- Paths[0] does not move, and several
                // paths being active at once is normal. So the path to keep is
                // the one just promoted, not Paths[0], which is still the one
                // whose address is gone and which has to be abandoned below.
                //
                KeepLocal = AlternateLocal;
                KeepRemote = AlternateRemote;
            } else {
                QuicConnAutoNoteMigrationFailure(Connection, Status);
            }
        }
    }

    //
    // Abandon what is gone. PATH_ABANDON is what QuicConnRemovePath sends
    // under multipath, which is the existing behaviour for this.
    //
    // No LOCAL_ADDRESS_CHANGED here: that event is about the active path's
    // local address, and Paths[0] is unchanged by a multipath promotion. The
    // application hears about multipath changes through PATH_AVAILABLE and
    // PATH_REMOVED instead.
    //
    QuicConnAutoRemoveLostPaths(
        Connection, LostPaths, LostCount, &KeepLocal, &KeepRemote);

    //
    // Opening paths on what is new is the reconciler's job now, and
    // QuicConnProcessLocalAddressChange has already queued it. This used to
    // walk the remotes already in use and open one path per new local address
    // -- which could only ever express "the addresses I have, crossed with the
    // remotes I am already talking to", never the full cross product the
    // table holds, and never in an order that said which pairs were worth the
    // four slots.
    //
    // What is left here is the half the reconciler must not do: the active
    // path's address is gone, so a replacement has to be promoted and the old
    // one abandoned. That is a forced migration, and it is not rate-limited or
    // deferred, because a connection with no usable active path is not waiting
    // for an improvement.
    //
}

//
// Finds a path of this connection whose local address is Address, whatever
// port either carries. The by-address lookup in path.c compares the port too,
// which is the right thing for an application naming an endpoint and the wrong
// thing here: the snapshot and the route hint both name an address, and the
// port is whatever the binding was given.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
static
QUIC_PATH*
QuicConnGetPathByLocalIp(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_ADDR* Address,
    _In_ const QUIC_ADDR* Remote
    )
{
    CXPLAT_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        if (Connection->Paths[i].Binding == NULL) {
            continue;
        }
        if (QuicAddrCompareIp(&Connection->Paths[i].Route.LocalAddress, Address) &&
            QuicAddrCompare(&Connection->Paths[i].Route.RemoteAddress, Remote)) {
            return &Connection->Paths[i];
        }
    }
    return NULL;
}


//
// Makes the path AUTO opened for a migration the active one, now that the peer
// has answered its challenge on it. The old path goes away afterwards: this is
// the "break" half, and it is deliberately last.
//
// Shared by both reasons. A route change and the table's preferred pair differ
// only in what made them worth doing and which address changes; what has to
// happen once the new path is proven is the same, and two copies of it would
// drift.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
void
QuicConnAutoCompleteMigration(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    )
{
    //
    // Both markers cleared first, whatever happens below. One that outlives its
    // attempt would block every later route change, and nothing else clears
    // them on the paths out of here. Ready is cleared here as well as by the
    // reconciliation that usually calls this, because the other caller --
    // finding the path already validated -- has not been through that.
    //
    Connection->MigrationReady = FALSE;
    Connection->MigrationPending = FALSE;

    const QUIC_ADDR Previous = Connection->Paths[0].Route.LocalAddress;
    const QUIC_ADDR PreviousRemote = Connection->Paths[0].Route.RemoteAddress;

    if (QuicAddrCompareIp(&Previous, &Path->Route.LocalAddress) &&
        QuicAddrCompare(&PreviousRemote, &Path->Route.RemoteAddress)) {
        //
        // Already active. Reached when something else promoted the path first
        // -- an application ACTIVATE_PATH, or a lost-address migration that
        // chose the same address -- and there is nothing left to do.
        //
        // The remote is part of the test, and has to be. A route migration
        // changes the local address and keeps the peer, so for that one the
        // local comparison alone was sufficient and this reads the same. A
        // table migration is the other way round: same interface, different
        // peer address. Comparing the local address alone declared every such
        // migration already done and returned without activating anything,
        // which is what the hold-down test caught -- the first move worked,
        // because it happened to change interface too, and every move after it
        // silently did nothing.
        //
        return;
    }

    QUIC_ADDR NewLocal = Path->Route.LocalAddress;
    QUIC_ADDR NewRemote = Path->Route.RemoteAddress;
    QUIC_PATH_PARAM Param;
    Param.LocalAddress = &NewLocal;
    Param.RemoteAddress = &NewRemote;

    const QUIC_STATUS Status = QuicConnActivatePath(Connection, &Param);
    if (QUIC_FAILED(Status)) {
        //
        // The new path stays on the connection rather than being torn down:
        // it is validated and working, the old one still is too, and the next
        // reconciliation finds the path already there and only has to activate
        // it. Tearing it down here would mean re-validating from scratch.
        //
        QuicConnAutoNoteMigrationFailure(Connection, Status);
        return;
    }

    if (Connection->MigrationReason == QUIC_MIGRATION_REASON_ROUTE) {
        QuicTraceLogConnInfo(
            AutoFollowedRoute,
            Connection,
            "AUTO followed a route change onto a validated path");
    } else {
        QuicTraceLogConnInfo(
            AutoFollowedTable,
            Connection,
            "AUTO migrated onto the candidate pair table's preferred pair");
    }

    Connection->LastAutoMigrationTimeUs = CxPlatTimeUs64();
    QuicConnIndicateLocalAddressChanged(Connection, &Previous);

    //
    // Now the break. The old path is removed rather than left as a spare: this
    // connection is not multipath -- the multipath branch never gets here --
    // so a second path costs a binding and a path ID for something nothing
    // will send on, and the route change is the host saying that address is no
    // longer the way to this peer.
    //
    // Only ever the old path, found by the address it had before the
    // activation, and never when it is the last one: QuicPathRemove aborts the
    // connection on the last path, and this migration succeeded.
    //
    if (Connection->PathsCount <= 1) {
        return;
    }
    CXPLAT_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
    for (uint8_t i = 1; i < Connection->PathsCount; ++i) {
        if (!QuicAddrCompareIp(&Connection->Paths[i].Route.LocalAddress, &Previous) ||
            !QuicAddrCompare(&Connection->Paths[i].Route.RemoteAddress, &PreviousRemote)) {
            continue;
        }

        //
        // Named by endpoint, copied first: QuicConnRemovePath takes a param
        // block of pointers and moves the path array about, so pointing it at
        // the entry being removed would have it read what it just shifted.
        //
        QUIC_ADDR OldLocal = Connection->Paths[i].Route.LocalAddress;
        QUIC_ADDR OldRemote = Connection->Paths[i].Route.RemoteAddress;
        QUIC_PATH_PARAM RemoveParam;
        RemoveParam.LocalAddress = &OldLocal;
        RemoveParam.RemoteAddress = &OldRemote;

        const QUIC_STATUS RemoveStatus = QuicConnRemovePath(Connection, &RemoveParam);
        if (QUIC_FAILED(RemoveStatus)) {
            QuicTraceLogConnWarning(
                AutoRemoveOldRoutePathFailed,
                Connection,
                "AUTO failed to remove the path the route moved off, status=0x%x",
                RemoveStatus);
            break;
        }
        QuicTraceLogConnInfo(
            AutoRemovedOldRoutePath,
            Connection,
            "AUTO removed the path the route moved off");
        break;
    }
}


//
// Called when a path of this connection completes validation, to see whether
// it is the one AUTO opened to follow a route change.
//
// Only records it. The migration itself is made from the reconciliation
// operation, because this runs from the middle of QuicConnRecvFrames -- which
// goes on using its QUIC_PATH* after this returns -- and completing the
// migration activates one path and removes another, shifting the array under
// that pointer. Doing it here left the caller holding a slot whose path had
// just been removed, which is the same shape of bug as processing a receive
// batch on a path that was taken away for a rebind.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnAutoPathValidated(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    )
{
    if (!Connection->MigrationPending) {
        return;
    }

    //
    // Matched on the pair, not the local address alone. A route migration
    // keeps the remote and swaps the interface, so for that one the remote
    // check is always true; a table migration swaps the remote, and matching
    // on the local address alone would fire on any validated path sharing the
    // interface -- including the one the connection is already on.
    //
    if (!QuicAddrCompareIp(&Path->Route.LocalAddress, &Connection->MigrationLocal) ||
        !QuicAddrCompare(&Path->Route.RemoteAddress, &Connection->MigrationRemote)) {
        return;
    }

    //
    // The mode that has to still be AUTO is whichever one asked for this. An
    // application can turn either off between the attempt and the validation,
    // and the migration it did not ask for is not the one to cancel.
    //
    if (Connection->MigrationReason == QUIC_MIGRATION_REASON_ROUTE) {
        if (!QuicConnManagesPathsAutomatically(Connection)) {
            return;
        }
        Connection->MigrationReady = TRUE;
        QuicConnQueueLocalAddressChange(Connection);
    } else {
        if (Connection->Settings.AddAddressMode != QUIC_ADD_ADDRESS_AUTO) {
            return;
        }
        Connection->MigrationReady = TRUE;
        QuicConnQueueReconcile(Connection);
    }
}


//
// Follows the host's choice of outgoing interface when it moves, which is the
// case no address change reports: with Wi-Fi and cellular both up, the OS can
// send this connection's traffic out of a different interface with every
// address staying exactly where it was.
//
// Make-before-break, unlike the lost-address migration above. The path in use
// still works here, so there is no reason to move onto one the peer has not
// answered on -- a route change is an improvement, and an improvement that
// might not work is worth waiting out. The move itself happens from
// QuicConnAutoPathValidated.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
void
QuicConnAutoFollowRoute(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(AddressCount) const CXPLAT_LOCAL_ADDRESS* Addresses,
    _In_ uint32_t AddressCount
    )
{
    const QUIC_ADDR ActiveLocal = Connection->Paths[0].Route.LocalAddress;
    const QUIC_ADDR ActiveRemote = Connection->Paths[0].Route.RemoteAddress;

    //
    // A pending target with no path left under it had its validation time out,
    // and the validation timer took the path away. Cleared here because that
    // timer does not know what the path was for, and leaving the marker set
    // would block every later route change on this connection.
    //
    //
    // Only this function's own attempts. The markers are shared with the table
    // migration now, and a table attempt is heading for a different *remote*
    // address -- so this lookup would not find its path, and clearing the
    // marker here would abandon an attempt that is proceeding normally. Worse
    // than merely abandoning it: the advertisement was charged at the attempt,
    // so it would never be retried.
    //
    if (Connection->MigrationPending &&
        Connection->MigrationReason == QUIC_MIGRATION_REASON_ROUTE &&
        QuicConnGetPathByLocalIp(
            Connection, &Connection->MigrationLocal, &ActiveRemote) == NULL) {
        QuicTraceLogConnInfo(
            AutoRouteMigrationAbandoned,
            Connection,
            "AUTO lost the path it opened for a route change");
        Connection->MigrationPending = FALSE;
    }

    QUIC_ADDR RouteLocal;
    if (!QuicConnGetRouteLocalAddress(Connection, &ActiveRemote, &RouteLocal)) {
        return;
    }

    if (QuicAddrCompareIp(&RouteLocal, &ActiveLocal)) {
        //
        // The route still comes out of the address this connection is on, which
        // is what almost every route notification means: the table changed
        // somewhere that has nothing to do with this peer. A pending *route*
        // attempt is dropped, because the address it was heading for is no
        // longer the one the OS would use.
        //
        // A table attempt is left alone. It is heading for a different remote
        // address, not a different interface, so this condition says nothing
        // about it -- and it is the common condition, since a table migration
        // keeps the interface and this is then true on every route
        // notification. Dropping it here lost the migration for good, the
        // advertisement having been charged at the attempt.
        //
        if (Connection->MigrationReason == QUIC_MIGRATION_REASON_ROUTE) {
            Connection->MigrationPending = FALSE;
        }
        return;
    }

    if (Connection->MigrationPending &&
        QuicAddrCompareIp(&RouteLocal, &Connection->MigrationLocal)) {
        //
        // Already waiting on a challenge to this very address. Re-opening would
        // only restart the validation.
        //
        return;
    }

    //
    // Optional, so it waits out the hold-down. This is the migration that most
    // needs it: routing tables churn, and a connection that moved on every
    // churn would spend its life validating paths.
    //
    // Checked after the route lookup rather than before it, which costs a
    // socket, a connect and a getsockname on every route-change reconciliation
    // the hold-down then refuses -- at the 100ms default debounce, up to ten per
    // second per connection during real churn. That is the cheaper mistake.
    // Gating the lookup on the hold-down would mean never learning the route had
    // moved, and the generation that reported it is consumed either way, so a
    // route that moved once inside the window and then settled would be followed
    // only if something else happened to come along. None of the three calls
    // touches the network -- connect on a datagram socket only makes the stack
    // commit to a source -- and they are made on the connection's worker, which
    // is the constraint the interface actually imposes.
    //
    if (!QuicConnAutoHoldDownElapsed(Connection)) {
        QuicTraceLogConnVerbose(
            AutoFollowRouteHeldDown,
            Connection,
            "AUTO held down following a route change");
        return;
    }

    //
    // Through the same selection as every other choice, with the route as the
    // hint it now honours. Going straight to RouteLocal would skip the scope
    // filters and the snapshot check: an address the OS routes from is still
    // not one to use if the monitor does not report it, and a hint that cannot
    // be found in the snapshot is a hint about an address this connection
    // cannot bind to.
    //
    // ExcludeAddressesInUse is FALSE on purpose, so that an address this
    // connection already has a path on can still be chosen -- that path is
    // exactly what make-before-break wants to find.
    //
    const CXPLAT_LOCAL_ADDRESS* Chosen =
        QuicConnSelectLocalAddress(
            Connection, Addresses, AddressCount, &ActiveRemote, NULL, FALSE,
            &RouteLocal);
    if (Chosen == NULL || !QuicAddrCompareIp(&Chosen->Address, &RouteLocal)) {
        //
        // The selection did not land on the route's address, which means that
        // address failed a filter or is not in the snapshot. Nothing to follow:
        // the ranking's own best choice is not acted on here, because without a
        // route change saying otherwise a working path is left alone.
        //
        return;
    }

    //
    // A path already on that address is the cheap case. If the peer has
    // answered on it there is nothing to wait for and it can be made active
    // now; if not, waiting on the validation already in flight is the whole
    // point.
    //
    QUIC_PATH* Existing =
        QuicConnGetPathByLocalIp(Connection, &RouteLocal, &ActiveRemote);
    if (Existing != NULL) {
        Connection->MigrationLocal = RouteLocal;
        Connection->MigrationRemote = ActiveRemote;
        Connection->MigrationReason = QUIC_MIGRATION_REASON_ROUTE;
        Connection->MigrationPending = TRUE;
        if (Existing->IsPeerValidated) {
            QuicConnAutoCompleteMigration(Connection, Existing);
        }
        return;
    }

    QUIC_ADDR NewLocal = Chosen->Address;
    if (Connection->State.ShareBinding) {
        //
        // A shared binding is keyed on the port, so keep the one the connection
        // already has rather than asking for a fresh ephemeral.
        //
        QuicAddrSetPort(&NewLocal, QuicAddrGetPort(&ActiveLocal));
    } else {
        QuicAddrSetPort(&NewLocal, 0);
    }
    QUIC_ADDR NewRemote = ActiveRemote;
    QUIC_PATH_PARAM Param;
    Param.LocalAddress = &NewLocal;
    Param.RemoteAddress = &NewRemote;

    QUIC_PATH* NewPath = NULL;
    const QUIC_STATUS Status =
        QuicConnAddPath(Connection, &Param, QUIC_PATH_ORIGIN_RECONCILER, &NewPath);
    if (QUIC_FAILED(Status)) {
        //
        // Out of path IDs, out of CIDs, or the address would not bind. The old
        // path is untouched and still working, which is the property this whole
        // branch is built around, so this is a missed improvement and not a
        // failure: the next route change tries again.
        //
        QuicTraceLogConnInfo(
            AutoFollowRouteAddPathFailed,
            Connection,
            "AUTO could not open a path for a route change, status=0x%x",
            Status);
        return;
    }

    //
    // The hold-down is charged at the attempt, not at the activation. A route
    // that keeps moving would otherwise have this opening a path per change
    // while none of them ever got far enough to count as a migration.
    //
    Connection->LastAutoMigrationTimeUs = CxPlatTimeUs64();
    Connection->MigrationLocal = NewPath->Route.LocalAddress;
    Connection->MigrationRemote = NewPath->Route.RemoteAddress;
    Connection->MigrationReason = QUIC_MIGRATION_REASON_ROUTE;
    Connection->MigrationPending = TRUE;

    QuicTraceLogConnInfo(
        AutoFollowRouteAddedPath,
        Connection,
        "AUTO opened a path to follow a route change");

    //
    // A path with no destination CID to send on was opened but not challenged:
    // QuicConnOpenNewPath defers that until the peer issues one. Nothing is
    // needed here for it. QuicPathIDAssignCids, which the NEW_CONNECTION_ID
    // handler calls, arms the validation in full -- challenge, start time,
    // count and timer -- for exactly the paths in this state, and the
    // completion above is driven by that validation rather than by another
    // reconciliation. The pending marker is already set, so the answer lands
    // where it should whenever the CID arrives.
    //
}


//
// Takes the library's address-monitor reference when this connection wants the
// host's own addresses watched, and runs the opening pass.
//
// Whether it wants them:
//
//   - every AddAddressMode does, on a client. MANUAL to report them, AUTO and
//     NAT_TRAVERSAL to act on them, and the setting has no "off" value. That is
//     the default change stage 5 of #157 makes, documented on the enum in
//     msquic.h: the OS address monitor now starts for every client connection,
//     where before it started only for one that asked.
//   - a server only where it could act -- multipath, per stage 6 -- or where
//     the application asked to be told, in MANUAL. The ordinary server watches
//     nothing, and servers are where the connection count lives, so that is
//     where stage 5's default change actually cost something.
//
//     Keyed on MultipathEnabled rather than negotiated, because the settings
//     are applied before the handshake. A server that offered multipath and
//     did not get it watches addresses it will not act on, which costs a
//     reference on a monitor already running for someone else.
//   - nothing at all without preview features. QUIC_SETTINGS'
//     IsSet.LocalAddressChangeMode, the LOCAL_ADDRESSES_CHANGED event and the
//     path parameters an application would need to observe or override any of
//     this are preview-only, so without the gate such a build would get the
//     monitor thread and automatic path management with no way to see or stop
//     either.
//
// Not before the handshake is confirmed, which is the part that matters for
// correctness rather than cost. The reference is given back in
// QuicConnOnShutdownComplete, because tearing the monitor down joins the
// backend's thread and that is PASSIVE_LEVEL work -- and that function needs a
// worker to run. A connection opened, configured and closed without ever
// starting has no worker, so it would reach QuicConnFree still holding the
// reference, which is what its assert says must not happen. Taking it at
// confirmation also means a connection that never connects pays nothing.
//
// One direction only: there is no mode that turns this off, so a reference
// once taken is held until the connection closes.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnUpdateAddressMonitorRef(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN ModeWasSet
    )
{
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    //
    // QMux is excluded for the reason QuicConnQueueLocalAddressChange records:
    // the feature picks which local address a UDP path sends from, and a QMux
    // connection runs over a TCP channel whose addressing it does not own. So
    // there is no sense in starting the platform's monitor thread on its
    // behalf, and the reconciliation it drives dereferences a path ID a QMux
    // connection never allocates.
    //
    // Guarded here rather than at the call sites because #176 moved this
    // decision into one place and there are two of them -- this and the one
    // crypto.c makes when the handshake completes.
    //
    const BOOLEAN WantsAddressChanges =
        !QuicConnIsQMux(Connection) &&
        (!QuicConnIsServer(Connection) ||
         Connection->Settings.MultipathEnabled ||
         QuicConnWantsAddressReports(Connection));
#else
    const BOOLEAN WantsAddressChanges = FALSE;
#endif

    if (!WantsAddressChanges ||
        !Connection->State.HandshakeConfirmed ||
        Connection->State.ShutdownComplete) {
        return;
    }

    if (!Connection->AddressMonitorRef) {
        //
        // A failure here leaves the connection silent, which is the same as
        // the platform having no backend.
        //
        if (QUIC_FAILED(QuicLibraryAddRefAddressMonitor())) {
            return;
        }
        Connection->AddressMonitorRef = TRUE;
        //
        // Where "since I last looked" begins for route changes. Taken here
        // rather than on the first reconciliation, which can be the route
        // change itself.
        //
        Connection->LastRouteGeneration = QuicLibraryGetRouteGeneration();
    }

    //
    // Run a pass when the reference is first taken, and again whenever the
    // mode is set. Keying it on the reference alone meant the pass happened
    // once in whatever mode was in force then, so an application that
    // connected with the default AUTO and later set MANUAL never got the
    // opening LOCAL_ADDRESSES_CHANGED enumerating its addresses.
    //
    if (ModeWasSet || !Connection->AddressChangePassQueued) {
        Connection->AddressChangePassQueued = TRUE;
        QuicConnQueueLocalAddressChange(Connection);
    }
}

//
// Stage 6 of #157: the server's whole use of local address detection.
//
// Abandons the paths whose local address the host no longer has. Multipath
// only -- without it a second path is a validation candidate rather than
// somewhere traffic goes, and the one path a server has is the one the client
// chose, which a server may not move.
//
// draft-ietf-quic-multipath section 3.4 is why this exists: an endpoint
// abandoning a path has to tell its peer. The client cannot see that the
// server's interface went away, and would go on scheduling traffic onto a path
// that cannot carry it.
//
// Does not call QuicConnRemovePath, and must not. That is the application's
// entry point and it refuses a server's calls unless server migration was
// negotiated -- correctly, because a server has no business creating or
// removing paths on an application's behalf.
//
// QuicPathIDAbandonLocally instead, which is the canonical local abandon.
// Hand-rolling the flags it sets -- LocalClose, SendAbandon, the connection
// send flag -- looked equivalent and was not: it also indicates PATH_REMOVED
// and arms the three-PTO QUIC_CONN_TIMER_PATH_CLOSE deadline. Without that
// deadline, a peer that acknowledges our PATH_ABANDON but never sends its own
// leaves the path in Connection->Paths with LocalClose set for the life of the
// connection, holding a binding and one of four path slots on an address that
// no longer exists -- and nothing recovers it, because the loss-detection
// fallback that would arm the deadline is gated on !LocalClose, the very flag
// the hand-rolled version had just set.
//
// The path leaves Connection->Paths when the abandon completes, so nothing
// here moves the array and the loop can walk it forwards.
//
// Never Paths[0] and never the last path. That does leave a server whose
// *active* path lost its address sitting on it, which is correct rather than a
// gap: moving it would be a server-initiated migration, and the client is the
// one that picks a different path once PATH_ABANDON tells it the others are
// gone.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
void
QuicConnAbandonLostLocalAddressPaths(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(LostCount) const QUIC_PATH_PARAM* LostPaths,
    _In_ uint32_t LostCount
    )
{
    if (Connection->PathsCount <= 1) {
        return;
    }

    CXPLAT_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
    for (uint8_t i = 1; i < Connection->PathsCount; ++i) {
        QUIC_PATH* Path = &Connection->Paths[i];
        if (Path->Binding == NULL || Path->LocalClose) {
            continue;
        }

        BOOLEAN Lost = FALSE;
        for (uint32_t j = 0; j < LostCount; ++j) {
            if (QuicAddrCompare(LostPaths[j].LocalAddress, &Path->Route.LocalAddress) &&
                QuicAddrCompare(LostPaths[j].RemoteAddress, &Path->Route.RemoteAddress)) {
                Lost = TRUE;
                break;
            }
        }
        if (!Lost) {
            continue;
        }

        //
        // A path that never finished opening has no path ID, so there is no
        // abandon to send and nothing to arm a close deadline on. Skipped
        // rather than half-abandoned: marking it LocalClose with no frame and
        // no timer is what leaves a path stuck forever.
        //
        if (Path->PathID == NULL || Path->PathID->Path == NULL) {
            continue;
        }

        QuicPathIDAbandonLocally(Path->PathID);

        QuicTraceLogConnInfo(
            ServerAbandonedLostPath,
            Connection,
            "Server abandoned a path whose local address was lost");
    }
}

//
// AUTO mode. Reconciles the connection's paths with the host's addresses by
// itself, per the policy tables in #134.
//
// Runs on the connection's worker, from QuicConnProcessLocalAddressChange,
// with the snapshot that pass read.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
void
QuicConnAutoMigrate(
    _In_ QUIC_CONNECTION* Connection,
    _In_reads_(AddressCount) const CXPLAT_LOCAL_ADDRESS* Addresses,
    _In_ uint32_t AddressCount,
    _In_reads_(LostCount) const QUIC_PATH_PARAM* LostPaths,
    _In_ uint32_t LostCount,
    _In_reads_(RemovedCount) const CXPLAT_LOCAL_ADDRESS* Removed,
    _In_ uint32_t RemovedCount,
    _In_ BOOLEAN RouteChanged
    )
{
    //
    // The path APIs reject a client's calls once server migration is
    // negotiated, and a server's unless it is. AUTO is therefore inert on such
    // a connection: the setting is accepted, nothing happens, and it is said
    // once instead of on every reconciliation.
    //
    if ((QuicConnIsClient(Connection) && Connection->Settings.ServerMigrationEnabled) ||
        (QuicConnIsClient(Connection) && Connection->State.ServerMigrationNegotiated) ||
        (QuicConnIsServer(Connection) && !Connection->State.ServerMigrationNegotiated)) {
        if (!Connection->AutoMigrationUnavailableTraced) {
            Connection->AutoMigrationUnavailableTraced = TRUE;
            QuicTraceLogConnWarning(
                AutoMigrationUnavailableMode,
                Connection,
                "QUIC_ADD_ADDRESS_AUTO does nothing with server migration negotiated");
        }
        return;
    }

    //
    // Whether the active path is one of the ones that just lost its address.
    // Paths[0] is the active path, so LostPaths naming it is the case that
    // forces a migration; the rest are tidy-up.
    //
    const QUIC_ADDR ActiveLocal = Connection->Paths[0].Route.LocalAddress;
    const QUIC_ADDR ActiveRemote = Connection->Paths[0].Route.RemoteAddress;
    BOOLEAN ActiveLost = FALSE;
    for (uint32_t i = 0; i < LostCount; ++i) {
        if (QuicAddrCompare(LostPaths[i].LocalAddress, &ActiveLocal) &&
            QuicAddrCompare(LostPaths[i].RemoteAddress, &ActiveRemote)) {
            ActiveLost = TRUE;
            break;
        }
    }

    if (Connection->State.MultipathNegotiated) {
        //
        // RouteChanged is not passed on. Under multipath the connection already
        // holds a path on every usable address, so there is no interface for a
        // route change to move it to -- the peer's scheduler picks between
        // paths that all exist, and make-before-break has nothing to build.
        //
        QuicConnAutoMigrateMultipath(
            Connection, Addresses, AddressCount, LostPaths, LostCount, ActiveLost);
        return;
    }

    //
    // Single path, and the active path is fine. The only thing left that could
    // want a migration is the host having changed where it sends this peer's
    // traffic from, which is what RouteChanged reports. A new address alone is
    // not a reason to move a working connection.
    //
    if (!ActiveLost) {
        //
        // Other paths that lost their address still get cleaned up.
        //
        QuicConnAutoRemoveLostPaths(Connection, LostPaths, LostCount, &ActiveLocal, &ActiveRemote);
        if (RouteChanged) {
            QuicConnAutoFollowRoute(Connection, Addresses, AddressCount);
        }
        return;
    }

    //
    // The active path is dead. A path the peer has already validated is the
    // cheapest way out, since it needs no new validation.
    //
    QUIC_PATH* Alternate =
        QuicConnFindValidatedAlternatePath(Connection, Addresses, AddressCount);
    if (Alternate != NULL) {
        QUIC_ADDR AlternateLocal = Alternate->Route.LocalAddress;
        QUIC_ADDR AlternateRemote = Alternate->Route.RemoteAddress;
        QUIC_PATH_PARAM Param;
        Param.LocalAddress = &AlternateLocal;
        Param.RemoteAddress = &AlternateRemote;

        const QUIC_ADDR Previous = Connection->Paths[0].Route.LocalAddress;
        const QUIC_STATUS Status = QuicConnActivatePath(Connection, &Param);
        if (QUIC_SUCCEEDED(Status)) {
            QuicTraceLogConnInfo(
                AutoMigrateToValidatedPath,
                Connection,
                "AUTO moved to an already validated path");
            Connection->AddressMigrationDeferred = FALSE;
            Connection->LastAutoMigrationTimeUs = CxPlatTimeUs64();
            QuicConnIndicateLocalAddressChanged(Connection, &Previous);
            QuicConnAutoRemoveLostPaths(
                Connection, LostPaths, LostCount,
                &Connection->Paths[0].Route.LocalAddress,
                &Connection->Paths[0].Route.RemoteAddress);
            return;
        }
        QuicConnAutoNoteMigrationFailure(Connection, Status);
        return;
    }

    //
    // Nothing validated to fall back to, so migrate the active path onto a new
    // local address. RFC 9000 section 9.2 allows sending non-probing frames on
    // the new path, and the old one is unusable, so waiting for a parallel
    // validation to finish would only add delay.
    //
    //
    // The address being replaced, with the flags the platform reported for it.
    // Those flags are the point: they are what decides whether to stay on a
    // privacy address or a stable one. Synthesizing the entry with no flags --
    // as this first did -- silently turned that policy off, and a connection
    // that had deliberately been on an RFC 8981 temporary address would be
    // migrated onto the stable one, publishing a long-lived identifier.
    //
    CXPLAT_LOCAL_ADDRESS Replacing;
    CxPlatZeroMemory(&Replacing, sizeof(Replacing));
    Replacing.Address = ActiveLocal;
    QuicAddrSetPort(&Replacing.Address, 0);
    for (uint32_t i = 0; i < RemovedCount; ++i) {
        if (QuicAddrCompareIp(&Removed[i].Address, &ActiveLocal)) {
            Replacing = Removed[i];
            break;
        }
    }

    //
    // Asked here rather than once per reconciliation: this is the branch that
    // has to choose a replacement, and the question -- which address reaches
    // this peer now -- only has an answer worth having after the old one is
    // gone.
    //
    QUIC_ADDR RouteLocal;
    const BOOLEAN HaveRoute =
        QuicConnGetRouteLocalAddress(Connection, &ActiveRemote, &RouteLocal);

    const CXPLAT_LOCAL_ADDRESS* Chosen =
        QuicConnSelectLocalAddress(
            Connection, Addresses, AddressCount, &ActiveRemote, &Replacing, TRUE,
            HaveRoute ? &RouteLocal : NULL);
    if (Chosen == NULL) {
        //
        // Offline. The connection and its dead path are kept: post-handshake
        // send failures and unreachable events are already non-fatal, so the
        // idle timeout is the only limit, and the next reconciliation migrates
        // as soon as the host has an address again. Tearing the connection
        // down here would be strictly worse than waiting.
        //
        QuicTraceLogConnInfo(
            AutoMigrateOffline,
            Connection,
            "AUTO has no candidate local address; holding the connection");
        return;
    }

    QUIC_ADDR NewLocal = Chosen->Address;
    if (Connection->State.ShareBinding) {
        //
        // A shared binding is keyed on the port, so keep the one the
        // connection already has rather than asking for a fresh ephemeral.
        //
        QuicAddrSetPort(&NewLocal, QuicAddrGetPort(&ActiveLocal));
    } else {
        QuicAddrSetPort(&NewLocal, 0);
    }

    QUIC_ADDR NewRemote = ActiveRemote;
    QUIC_PATH_PARAM Param;
    Param.LocalAddress = &NewLocal;
    Param.RemoteAddress = &NewRemote;

    const QUIC_ADDR Previous = Connection->Paths[0].Route.LocalAddress;
    const QUIC_STATUS Status = QuicConnActivatePath(Connection, &Param);
    if (QUIC_FAILED(Status)) {
        QuicConnAutoNoteMigrationFailure(Connection, Status);
        return;
    }

    QuicTraceLogConnInfo(
        AutoMigrateImmediate,
        Connection,
        "AUTO migrated the active path to a new local address");

    //
    // Validate the peer on the new path as well. QuicConnActivatePath sends a
    // PING and lets the peer validate us, but says nothing about whether the
    // peer is reachable from here; on a migration we chose ourselves, that is
    // worth finding out rather than assuming.
    //
    if (Connection->Paths[0].IsPeerValidated) { // Not already validating.
        Connection->Paths[0].IsPeerValidated = FALSE;
        Connection->Paths[0].SendChallenge = TRUE;
        Connection->Paths[0].PathValidationStartTime = CxPlatTimeUs64();
        Connection->Paths[0].ChallengeCount = 1;
        CxPlatRandom(
            sizeof(Connection->Paths[0].Challenge),
            Connection->Paths[0].Challenge);
        QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PATH_CHALLENGE);
        //
        // Starting a validation is not enough on its own: without the timer
        // there is nothing to re-send a lost challenge or to notice that it
        // never completed, and the path would stay amplification-limited for
        // the life of the connection.
        //
        QuicConnPathValidationTimerUpdate(Connection);
    }

    Connection->AddressMigrationDeferred = FALSE;
    Connection->LastAutoMigrationTimeUs = CxPlatTimeUs64();
    QuicConnIndicateLocalAddressChanged(Connection, &Previous);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueLocalAddressChange(
    _In_ QUIC_CONNECTION* Connection
    )
{
    //
    // No mode test. Every AddAddressMode wants this pass: MANUAL to report the
    // change to the application, AUTO and NAT_TRAVERSAL to reconcile against
    // it. There is no "off" value, which is the default change stage 5 makes
    // and documents rather than defaults around.
    //
    if (Connection->State.Freed ||
        Connection->State.ShutdownComplete) {
        return;
    }

    //
    // Inert for a QMux connection. The whole feature is about which local
    // address a UDP path sends from, and a QMux connection has no QUIC paths to
    // reconcile -- it runs over a TCP connection the peer owns the addressing
    // of. More than useless, it is unsafe: QuicConnQMuxAlloc leaves
    // Paths[0].PathID NULL, and the reconciliation reaches QuicConnAddPath,
    // QuicConnActivatePath and QuicConnRemovePath, all of which dereference it.
    //
    // Guarded here rather than at each of those, because this is the one place
    // the operation is queued, and the library fans its notification out to
    // every connection in the process regardless of transport.
    //
    if (QuicConnIsQMux(Connection)) {
        return;
    }

    if (Connection->Worker == NULL) {
        //
        // No worker to queue onto yet, and no paths to reconcile either. Noted
        // so that handshake confirmation runs the first pass. Writing this
        // field off-worker is safe only here: a connection without a worker is
        // also not on its registration's list, so the platform fan-out cannot
        // have reached it, and the only caller is the thread opening it.
        //
        Connection->AddressChangeDirty = TRUE;
        return;
    }

    //
    // One operation at a time per connection. The handler reads the latest
    // snapshot rather than anything carried on the operation, so a second one
    // would do the same work twice -- and a burst of platform callbacks, which
    // is the normal shape of an interface transition, would otherwise queue one
    // apiece.
    //
    if (InterlockedFetchAndSetBoolean(&Connection->AddressChangeQueued)) {
        return;
    }

    QUIC_OPERATION* Oper =
        QuicConnAllocOperation(Connection, QUIC_OPER_TYPE_LOCAL_ADDRESS_CHANGE);
    if (Oper == NULL) {
        //
        // Cleared again, so the next change can queue one. Dropping it is the
        // right answer under memory pressure: the snapshot is level-triggered,
        // so the next reconciliation sees everything this one would have.
        //
        (void)InterlockedFetchAndClearBoolean(&Connection->AddressChangeQueued);
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "local address change operation",
            0);
        return;
    }

    QuicConnQueueOper(Connection, Oper);
}

//
// Reconciles the connection's paths against the library's latest local address
// snapshot, on the connection's own worker.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessLocalAddressChange(
    _In_ QUIC_CONNECTION* Connection
    )
{
    //
    // Not this connection's business if it never took the monitor reference.
    // The library's fan-out walks every connection in the process and does not
    // consult that flag, so a process holding one interested connection would
    // otherwise have every uninterested one copy the address snapshot, walk
    // its paths twice and allocate, before finding nothing to do. Which is
    // most of what stage 6 set out to save on a server.
    //
    if (!Connection->AddressMonitorRef) {
        (void)InterlockedFetchAndClearBoolean(&Connection->AddressChangeQueued);
        return;
    }

    //
    // Cleared before the snapshot is read, not after. The other order loses a
    // change that lands while this runs: the fan-out would see the flag still
    // set, queue nothing, and this pass would already have read the older
    // snapshot.
    //
    (void)InterlockedFetchAndClearBoolean(&Connection->AddressChangeQueued);

    //
    // The LocalAddressChangeMode test this used to carry went with #176, which
    // consolidated the modes onto AddAddressMode; the QMux guard stays, and is
    // the only reason this function is reachable-but-inert here. A QMux
    // connection runs over a TCP channel whose addressing it does not own.
    //
    if (Connection->State.ShutdownComplete ||
        QuicConnIsQMux(Connection)) {
        return;
    }

    if (!Connection->State.HandshakeConfirmed) {
        //
        // RFC 9000 section 9 does not allow migration before the handshake is
        // confirmed, and there is nothing useful to tell the application about
        // paths that do not exist yet. Noted instead, and re-run from where
        // QuicConnOpenNewPaths is called at confirmation.
        //
        Connection->AddressChangeDirty = TRUE;
        return;
    }

    Connection->AddressChangeDirty = FALSE;

    //
    // A make-before-break migration whose path finished validating while a
    // packet was being processed. Done here, where activating a path and
    // removing another is what this operation does anyway, and before the
    // snapshot is read: it does not depend on one, and the generation gate
    // below would otherwise skip it whenever no address had changed since the
    // pass that started it -- which is every time, since a route change is not
    // an address change.
    //
    if (Connection->MigrationReady &&
        Connection->MigrationReason == QUIC_MIGRATION_REASON_ROUTE) {
        Connection->MigrationReady = FALSE;
        if (Connection->MigrationPending &&
            QuicConnManagesPathsAutomatically(Connection)) {
            QUIC_PATH* Validated =
                QuicConnGetPathByLocalIp(
                    Connection,
                    &Connection->MigrationLocal,
                    &Connection->Paths[0].Route.RemoteAddress);
            if (Validated != NULL && Validated->IsPeerValidated) {
                QuicConnAutoCompleteMigration(Connection, Validated);
            } else {
                //
                // The path went away between validating and this running, or
                // never really validated. Nothing to move onto, and the marker
                // is dropped so a later route change is not blocked by it.
                //
                Connection->MigrationPending = FALSE;
            }
        }
    }

    CXPLAT_LOCAL_ADDRESS* Addresses = NULL;
    uint32_t AddressCount = 0;
    CXPLAT_LOCAL_ADDRESS* Removed = NULL;
    uint32_t RemovedCount = 0;
    uint64_t Generation = 0;
    uint64_t RouteGeneration = 0;
    //
    // Declared up here, before the first goto, so that every path to Exit
    // sees them initialized.
    //
    QUIC_ADDR* Added = NULL;
    QUIC_ADDR* RemovedAddrs = NULL;
    uint32_t AddedCount = 0;

    if (QUIC_FAILED(
            QuicLibraryGetLocalAddresses(
                &Addresses, &AddressCount, &Removed, &RemovedCount, &Generation,
                &RouteGeneration))) {
        return;
    }

    //
    // The getter may hand back NULL with a zero count, which its annotation
    // now says out loud. Normalized here so that every loop below is bounded
    // by a count that matches a pointer the analyzers can see is valid.
    //
    if (Addresses == NULL) {
        AddressCount = 0;
    }
    if (Removed == NULL) {
        RemovedCount = 0;
    }

    if (Generation == Connection->LastAddressGeneration) {
        //
        // Already reconciled against this one. Two operations can reach here
        // for one generation when a change lands just as a previous pass
        // cleared its flag.
        //
        goto Exit;
    }
    //
    // Whether a routing change has been reported since this connection last
    // looked. Compared rather than read as a flag, so that two notifications
    // collapsing into one reconciliation cannot lose the route half of the
    // first -- the same reason the address snapshot is a generation.
    //
    // What "last looked" starts at is seeded when the connection takes its
    // reference on the monitor, so a route change that happened before this
    // connection was watching is not news: the connection was established over
    // whatever route was in place by then, and an application that deliberately
    // bound a local address should not have it taken away on the first
    // reconciliation because of something that happened beforehand.
    //
    const BOOLEAN RouteChanged = RouteGeneration > Connection->LastRouteGeneration;
    Connection->LastRouteGeneration = RouteGeneration;

    Connection->LastAddressGeneration = Generation;

    //
    // Queued here, before the bail-outs below. A route change bumps the
    // generation without necessarily losing a path or adding an address, so a
    // connection whose paths already cover every address it has would reach
    // "nothing to do" and exit -- leaving the table holding pre-change
    // route preferences, which is its top-ranked key.
    //
    QuicConnQueueReconcile(Connection);

    //
    // Which of this connection's paths have lost the address they are bound
    // to. Compared without the port, since a snapshot entry names an address
    // and the path names an endpoint.
    //
    QUIC_PATH_PARAM LostPaths[QUIC_MAX_PATH_COUNT];
    QUIC_ADDR LostLocal[QUIC_MAX_PATH_COUNT];
    QUIC_ADDR LostRemote[QUIC_MAX_PATH_COUNT];
    uint32_t LostCount = 0;

    CXPLAT_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
    CXPLAT_ANALYSIS_ASSUME(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);

    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        const QUIC_PATH* Path = &Connection->Paths[i];
        if (Path->Binding == NULL) {
            continue;
        }

        QUIC_ADDR Local = Path->Route.LocalAddress;
        QuicAddrSetPort(&Local, 0);

        BOOLEAN Found = FALSE;
        for (uint32_t j = 0; j < AddressCount; ++j) {
            if (QuicAddrCompare(&Local, &Addresses[j].Address)) {
                Found = TRUE;
                break;
            }
        }
        if (Found) {
            continue;
        }

        LostLocal[LostCount] = Path->Route.LocalAddress;
        LostRemote[LostCount] = Path->Route.RemoteAddress;
        LostPaths[LostCount].LocalAddress = &LostLocal[LostCount];
        LostPaths[LostCount].RemoteAddress = &LostRemote[LostCount];
        ++LostCount;
    }

    if (QuicConnIsServer(Connection)) {
        //
        // Stage 6 of #157: a server does exactly one thing with the host's own
        // addresses, and only with multipath negotiated -- it abandons the
        // paths whose local address went away.
        //
        // draft-ietf-quic-multipath section 3.4 requires an endpoint
        // abandoning a path to tell its peer, so the abandon is the point: the
        // client cannot see that the server's interface went away and would go
        // on scheduling traffic onto a path that cannot carry it.
        //
        // Nothing else. No table, no pair ranking, no local-address selection,
        // no migration. All of that answers "where should this connection send
        // from", which is the client's question: a server sends from wherever
        // the client reached it, and RFC 9000 section 9 gives it no licence to
        // move a connection on its own anyway.
        //
        // Placed here, above the allocation below, deliberately. It needs only
        // LostPaths, and LastAddressGeneration is already committed -- so an
        // allocation failure for the event lists would take the abandon with
        // it *and* leave the generation gate skipping every later pass for the
        // same generation. The server would then keep a dead path until some
        // unrelated address change came along.
        //
        if (Connection->State.MultipathNegotiated) {
            QuicConnAbandonLostLocalAddressPaths(
                Connection, LostPaths, LostCount);
        }
        goto Exit;
    }

    //
    // Addresses the connection is not already using. Reported as added rather
    // than diffed against the previous snapshot: what an application wants to
    // know is which addresses it could open a path on now, and that is a
    // question about the present, not about what changed.
    //
    //
    // On the heap, not the stack: QUIC_MAX_LOCAL_ADDRESS_COUNT entries of
    // QUIC_ADDR twice over is several kilobytes, and this runs synchronously
    // from crypto frame processing, which is already deep in the receive path.
    // One allocation covers both lists.
    //
    //
    // At least one entry even when both lists are empty, so that the arrays
    // are never NULL past this point. The degenerate case is a generation
    // that empties the snapshot and removes nothing, which still has lost
    // paths worth reporting.
    //
    const uint32_t ListCount = CXPLAT_MAX(AddressCount + RemovedCount, 1);
    Added =
        CXPLAT_ALLOC_NONPAGED(
            ListCount * sizeof(QUIC_ADDR),
            QUIC_POOL_DATAPATH_ADDRESSES);
    if (Added == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "local address change event lists",
            ListCount * sizeof(QUIC_ADDR));
        goto Exit;
    }
    RemovedAddrs = Added + AddressCount;

    for (uint32_t j = 0; j < AddressCount; ++j) {
        BOOLEAN InUse = FALSE;
        for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
            if (Connection->Paths[i].Binding == NULL) {
                //
                // Same skip as the loop above. A torn-down path keeps a stale
                // local address, and counting it as in use would hide an
                // address the application could open a path on.
                //
                continue;
            }
            QUIC_ADDR Local = Connection->Paths[i].Route.LocalAddress;
            QuicAddrSetPort(&Local, 0);
            if (QuicAddrCompare(&Local, &Addresses[j].Address)) {
                InUse = TRUE;
                break;
            }
        }
        if (!InUse) {
            //
            // Bounded by the loop: one entry per snapshot address at most, and
            // the allocation holds AddressCount of them plus the removals.
            //
            CXPLAT_DBG_ASSERT(AddedCount < ListCount);
            CXPLAT_ANALYSIS_ASSUME(AddedCount < ListCount);
            Added[AddedCount++] = Addresses[j].Address;
        }
    }

    if (LostCount == 0 && AddedCount == 0 && RemovedCount == 0) {
        goto Exit;
    }

    //
    // Flattened for the event, which speaks in QUIC_ADDR rather than in the
    // platform's richer entry.
    //
    CXPLAT_ANALYSIS_ASSUME(AddressCount + RemovedCount <= ListCount);
    for (uint32_t i = 0; i < RemovedCount; ++i) {
        RemovedAddrs[i] = Removed[i].Address;
    }

    //
    // MANUAL is the mode in which the events are the whole interface, so it is
    // the one that gets this. It replaces QUIC_LOCAL_ADDRESS_CHANGE_NOTIFY,
    // which meant the same thing for the local half alone.
    //
    if (QuicConnWantsAddressReports(Connection)) {
        QUIC_CONNECTION_EVENT Event;
        Event.Type = QUIC_CONNECTION_EVENT_LOCAL_ADDRESSES_CHANGED;
        Event.LOCAL_ADDRESSES_CHANGED.AddedCount = AddedCount;
        Event.LOCAL_ADDRESSES_CHANGED.Added = AddedCount != 0 ? Added : NULL;
        Event.LOCAL_ADDRESSES_CHANGED.RemovedCount = RemovedCount;
        Event.LOCAL_ADDRESSES_CHANGED.Removed = RemovedCount != 0 ? RemovedAddrs : NULL;
        Event.LOCAL_ADDRESSES_CHANGED.LostPathCount = LostCount;
        Event.LOCAL_ADDRESSES_CHANGED.LostPaths = LostCount != 0 ? LostPaths : NULL;
        QuicTraceLogConnVerbose(
            IndicateLocalAddressesChanged,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_LOCAL_ADDRESSES_CHANGED, Added=%u, Removed=%u, Lost=%u",
            AddedCount,
            RemovedCount,
            LostCount);
        (void)QuicConnIndicateEvent(Connection, &Event);
    }

    if (QuicConnManagesPathsAutomatically(Connection)) {
        QuicConnAutoMigrate(
            Connection, Addresses, AddressCount, LostPaths, LostCount,
            Removed, RemovedCount, RouteChanged);
    }

    //
    // The host's addresses have changed, so the pairs they take part in have
    // too -- but only where something reads them. MANUAL and NAT_TRAVERSAL
    // would otherwise pay for a rebuild, and its route lookup per remote, on
    // every address change for a table nothing consults.
    //
    if (QuicConnWantsCandidateTable(Connection)) {
        QuicConnQueueReconcile(Connection);
    }

Exit:

    if (Addresses != NULL) {
        CXPLAT_FREE(Addresses, QUIC_POOL_DATAPATH_ADDRESSES);
    }
    if (Removed != NULL) {
        CXPLAT_FREE(Removed, QUIC_POOL_DATAPATH_ADDRESSES);
    }
    if (Added != NULL) {
        CXPLAT_FREE(Added, QUIC_POOL_DATAPATH_ADDRESSES);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueTraceRundown(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_OPERATION* Oper;
    if ((Oper = QuicConnAllocOperation(Connection, QUIC_OPER_TYPE_TRACE_RUNDOWN)) != NULL) {
        QuicConnQueueOper(Connection, Oper);
    } else {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "trace rundown operation",
            0);
    }
}

//
// Logs end-of-connection statistics for every active path id (or just the
// primary path id when multipath wasn't negotiated).
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnLogPathIDStatistics(
    _In_ QUIC_CONNECTION* Connection
    )
{
    if (!Connection->State.Started) {
        return;
    }
    if (Connection->State.MultipathNegotiated) {
        for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
            if (Connection->Paths[i].PathID != NULL) {
                QuicPathIDLogStatistics(Connection->Paths[i].PathID);
            }
        }
    } else if (Connection->Paths[0].PathID != NULL) {
        //
        // The same guard the multipath branch above has always had, and the
        // same one QuicPathRemove applies to this exact field before
        // repointing it -- so a NULL here was already understood to be
        // reachable, just not on this path through the code.
        //
        // It is reached when route resolution fails on the last path:
        // QuicConnProcessRouteCompletion removes the path, QuicPathRemove
        // finds nowhere left to go and closes the connection, and the close
        // logs statistics for a path ID that is no longer there.
        // QuicPathIDLogStatistics then reads PathID->Path and
        // PathID->CongestionControl, which on an ASAN build aborts with an
        // access violation at a small offset off the zero page.
        //
        // On this branch it is also how QMux connections get here at all:
        // QuicConnQMuxAlloc never allocates a path ID, so there are never
        // per-path statistics to log for one.
        //
        QuicPathIDLogStatistics(Connection->Paths[0].PathID);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnTraceRundownOper(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QuicTraceEvent(
        ConnRundown,
        "[conn][%p] Rundown, IsServer=%hu, CorrelationId=%llu",
        Connection,
        QuicConnIsServer(Connection),
        Connection->Stats.CorrelationId);
    QuicTraceEvent(
        ConnAssignWorker,
        "[conn][%p] Assigned worker: %p",
        Connection,
        Connection->Worker);
    QuicTraceEvent(
        ConnEcnCapable,
        "[conn][%p] Ecn: IsCapable=%hu",
        Connection,
        Connection->Paths[0].EcnValidationState == ECN_VALIDATION_CAPABLE);
    CXPLAT_DBG_ASSERT(Connection->Registration);
    QuicTraceEvent(
        ConnRegistered,
        "[conn][%p] Registered with %p",
        Connection,
        Connection->Registration);
    if (Connection->Stats.QuicVersion != 0) {
        QuicTraceEvent(
            ConnVersionSet,
            "[conn][%p] QUIC Version: 0x%x",
            Connection,
            Connection->Stats.QuicVersion);
    }
    if (Connection->State.Started) {
        for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
            if (Connection->State.LocalAddressSet || i != 0) {
                QuicTraceEvent(
                    ConnLocalAddrAdded,
                     "[conn][%p] New Local IP: %!ADDR!",
                    Connection,
                    CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[i].Route.LocalAddress), &Connection->Paths[i].Route.LocalAddress));
            }
            if (Connection->State.RemoteAddressSet || i != 0) {
                QuicTraceEvent(
                    ConnRemoteAddrAdded,
                    "[conn][%p] New Remote IP: %!ADDR!",
                    Connection,
                    CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[i].Route.RemoteAddress), &Connection->Paths[i].Route.RemoteAddress));
            }
        }
    }
    if (Connection->State.Connected) {
        QuicTraceEvent(
            ConnHandshakeComplete,
            "[conn][%p] Handshake complete",
            Connection);
    }
    if (Connection->State.HandleClosed) {
        QuicTraceEvent(
            ConnHandleClosed,
            "[conn][%p] Handle closed",
            Connection);
    }
    QuicConnLogPathIDStatistics(Connection);

    QuicStreamSetTraceRundown(&Connection->Streams);
    QuicPathIDSetTraceRundown(&Connection->PathIDs);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnIndicateEvent(
    _In_ QUIC_CONNECTION* Connection,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    CXPLAT_PASSIVE_CODE();
    QUIC_STATUS Status;
    if (Connection->ClientCallbackHandler != NULL) {
        //
        // MsQuic shouldn't indicate reentrancy to the app when at all possible.
        // The general exception to this rule is when the connection is being
        // closed because the API MUST block until all work is completed, so we
        // have to execute the event callbacks inline. Custom executions always
        // have InlineApiExecution set, which makes this reentrancy check
        // unreliable, so it is skipped for custom executions.
        //
        CXPLAT_DBG_ASSERT(
            !Connection->State.InlineApiExecution ||
            Connection->State.HandleClosed ||
            MsQuicLib.CustomExecutions);
        Status =
            Connection->ClientCallbackHandler(
                (HQUIC)Connection,
                Connection->ClientContext,
                Event);
    } else {
        QUIC_CONN_VERIFY(
            Connection,
            Connection->State.HandleClosed ||
                Connection->State.ShutdownComplete ||
                !Connection->State.ExternalOwner);
        Status = QUIC_STATUS_INVALID_STATE;
        QuicTraceLogConnWarning(
            ApiEventNoHandler,
            Connection,
            "Event silently discarded (no handler).");
    }
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueOper(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_OPERATION* Oper
    )
{
#if DEBUG
    if (!Connection->State.Initialized) {
        CXPLAT_DBG_ASSERT(QuicConnIsServer(Connection));
        CXPLAT_DBG_ASSERT(
            QuicConnIsQMux(Connection) ||
            Connection->Paths[0].PathID == NULL ||
            Connection->Paths[0].PathID->SourceCids.Next != NULL ||
            CxPlatIsRandomMemoryFailureEnabled());
    }
    if (Oper->Type == QUIC_OPER_TYPE_API_CALL) {
        if (Oper->API_CALL.Context->Type == QUIC_API_TYPE_CONN_SHUTDOWN) {
            CXPLAT_DBG_ASSERT(
                (Oper->API_CALL.Context->CONN_SHUTDOWN.ErrorCode <= QUIC_VAR_INT_MAX) ||
                (Oper->API_CALL.Context->CONN_SHUTDOWN.Flags & QUIC_CONNECTION_SHUTDOWN_FLAG_STATUS));
        }
    }
#endif
    if (QuicOperationEnqueue(&Connection->OperQ, Connection->Partition, Oper)) {
        //
        // The connection needs to be queued on the worker because this was the
        // first operation in our OperQ.
        //
        QuicWorkerQueueConnection(Connection->Worker, Connection);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueuePriorityOper(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_OPERATION* Oper
    )
{
#if DEBUG
    if (!Connection->State.Initialized) {
        CXPLAT_DBG_ASSERT(QuicConnIsServer(Connection));
        CXPLAT_DBG_ASSERT(
            Connection->Paths[0].PathID == NULL ||
            Connection->Paths[0].PathID->SourceCids.Next != NULL ||
            CxPlatIsRandomMemoryFailureEnabled());
    }
#endif
    if (QuicOperationEnqueuePriority(
            &Connection->OperQ,
            Connection->Partition,
            Oper)) {
        //
        // The connection needs to be queued on the worker because this was the
        // first operation in our OperQ.
        //
        QuicWorkerQueuePriorityConnection(Connection->Worker, Connection);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueHighestPriorityOper(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_OPERATION* Oper
    )
{
    if (QuicOperationEnqueueFront(
            &Connection->OperQ,
            Connection->Partition,
            Oper)) {
        //
        // The connection needs to be queued on the worker because this was the
        // first operation in our OperQ.
        //
        QuicWorkerQueuePriorityConnection(Connection->Worker, Connection);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnUpdateRtt(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ uint64_t LatestRtt,
    _In_ uint64_t OurSendTimestamp,
    _In_ uint64_t PeerSendTimestamp
    )
{
    if (LatestRtt == 0) {
        //
        // RTT cannot be zero or several loss recovery algorithms break down.
        //
        LatestRtt = 1;
    }

    BOOLEAN NewMinRtt = FALSE;
    Path->LatestRttSample = LatestRtt;
    if (LatestRtt < Path->MinRtt) {
        Path->MinRtt = LatestRtt;
        NewMinRtt = TRUE;
    }
    if (LatestRtt > Path->MaxRtt) {
        Path->MaxRtt = LatestRtt;
    }

    if (!Path->GotFirstRttSample) {
        Path->GotFirstRttSample = TRUE;
        Path->SmoothedRtt = LatestRtt;
        Path->RttVariance = LatestRtt / 2;

    } else {
        if (Path->SmoothedRtt > LatestRtt) {
            Path->RttVariance = CxPlatEwma(Path->RttVariance, Path->SmoothedRtt - LatestRtt, 4);
        } else {
            Path->RttVariance = CxPlatEwma(Path->RttVariance, LatestRtt - Path->SmoothedRtt, 4);
        }
        Path->SmoothedRtt = CxPlatEwma(Path->SmoothedRtt, LatestRtt, 8);
    }

    if (OurSendTimestamp != UINT64_MAX) {
        if (Connection->Stats.Timing.PhaseShift == 0 || NewMinRtt) {
            Connection->Stats.Timing.PhaseShift =
                (int64_t)PeerSendTimestamp - (int64_t)OurSendTimestamp - (int64_t)LatestRtt / 2;
            Path->OneWayDelayLatest = Path->OneWayDelay = LatestRtt / 2;
            QuicTraceLogConnVerbose(
                PhaseShiftUpdated,
                Connection,
                "New Phase Shift: %lld us",
                Connection->Stats.Timing.PhaseShift);
        } else {
            Path->OneWayDelayLatest =
                (uint64_t)((int64_t)PeerSendTimestamp - (int64_t)OurSendTimestamp - Connection->Stats.Timing.PhaseShift);
            Path->OneWayDelay = CxPlatEwma(Path->OneWayDelay, Path->OneWayDelayLatest, 8);
        }
    }

    CXPLAT_DBG_ASSERT(Path->SmoothedRtt != 0);
    QuicTraceLogConnVerbose(
        RttUpdatedV2,
        Connection,
        "Updated Rtt=%u.%03u ms, Var=%u.%03u 1Way=%u.%03u ms",
        (uint32_t)(Path->SmoothedRtt / 1000), (uint32_t)(Path->SmoothedRtt % 1000),
        (uint32_t)(Path->RttVariance / 1000), (uint32_t)(Path->RttVariance % 1000),
        (uint32_t)(Path->OneWayDelay / 1000), (uint32_t)(Path->OneWayDelay % 1000));
}

//
// The following connection-level CID helpers are retained for the seera
// features (address discovery / migration / NAT traversal) that were built on
// the pre-multipath "CIDs live on the connection" model. Under multipath the
// CID state lives on the QUIC_PATHID, so these now delegate to the primary
// path's PathID (Paths[0].PathID), or to the supplied path's PathID.
//
// NOTE: seera's original QuicConnGenerateNewSourceCid also made the new CID
// unique across every binding in use (including bound-address bindings);
// QuicPathIDGenerateNewSourceCid only accounts for the path bindings.
// Multi-local-address CID uniqueness must be folded into the PathID source-CID
// generation as a follow-up.
//

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_CID_SLIST_ENTRY*
QuicConnGenerateNewSourceCid(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN IsInitial
    )
{
    return QuicPathIDGenerateNewSourceCid(Connection->Paths[0].PathID, IsInitial);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnGenerateNewSourceCids(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN ReplaceExistingCids
    )
{
    QuicPathIDGenerateNewSourceCids(Connection->Paths[0].PathID, ReplaceExistingCids);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_CID_LIST_ENTRY*
QuicConnGetUnusedDestCid(
    _In_ const QUIC_CONNECTION* Connection
    )
{
    return QuicPathIDGetUnusedDestCid(Connection->Paths[0].PathID);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnRetireCurrentDestCid(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    )
{
    UNREFERENCED_PARAMETER(Connection);
    return QuicPathIDRetireCurrentDestCid(Path->PathID, Path);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
uint64_t
QuicGetEarliestExpirationTime(
    _In_ const QUIC_CONNECTION* Connection
    )
{
    uint64_t EarliestExpirationTime = Connection->ExpirationTimes[0];
    for (QUIC_CONN_TIMER_TYPE Type = 1; Type < QUIC_CONN_TIMER_COUNT; ++Type) {
        if (Connection->ExpirationTimes[Type] < EarliestExpirationTime) {
            EarliestExpirationTime = Connection->ExpirationTimes[Type];
        }
    }
    return EarliestExpirationTime;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnTimerSetEx(
    _Inout_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CONN_TIMER_TYPE Type,
    _In_ uint64_t Delay,
    _In_ uint64_t TimeNow
    )
{
    const uint64_t NewExpirationTime = TimeNow + Delay;

    QuicTraceEvent(
        ConnSetTimer,
        "[conn][%p] Setting %hhu, delay=%llu us",
        Connection,
        (uint8_t)Type,
        Delay);

    Connection->ExpirationTimes[Type] = NewExpirationTime;
    uint64_t NewEarliestExpirationTime  = QuicGetEarliestExpirationTime(Connection);
    if (NewEarliestExpirationTime != Connection->EarliestExpirationTime) {
        Connection->EarliestExpirationTime = NewEarliestExpirationTime;
        QuicTimerWheelUpdateConnection(&Connection->Worker->TimerWheel, Connection);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnTimerCancel(
    _Inout_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CONN_TIMER_TYPE Type
    )
{
    CXPLAT_DBG_ASSERT(Connection->EarliestExpirationTime <= Connection->ExpirationTimes[Type]);

    if (Connection->EarliestExpirationTime == UINT64_MAX) {
        //
        // No timers are currently scheduled.
        //
        return;
    }

    if (Connection->ExpirationTimes[Type] == Connection->EarliestExpirationTime) {
        //
        // We might be canceling the earliest timer, so we need to find the new
        // expiration time for this connection.
        //
        Connection->ExpirationTimes[Type] = UINT64_MAX;
        uint64_t NewEarliestExpirationTime = QuicGetEarliestExpirationTime(Connection);

        if (NewEarliestExpirationTime != Connection->EarliestExpirationTime) {
            //
            // We've either found a new earliest expiration time, or there will be no timers scheduled.
            //
            Connection->EarliestExpirationTime = NewEarliestExpirationTime;
            QuicTimerWheelUpdateConnection(&Connection->Worker->TimerWheel, Connection);
        }
    } else {
        Connection->ExpirationTimes[Type] = UINT64_MAX;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnTimerExpired(
    _Inout_ QUIC_CONNECTION* Connection,
    _In_ uint64_t TimeNow
    )
{
    BOOLEAN FlushSendImmediate = FALSE;

    Connection->EarliestExpirationTime = UINT64_MAX;

    //
    // Queue up operations for all expired timers and update the earliest expiration time
    // on the fly. Note that we must not call any functions that might update the timer wheel.
    //
    for (QUIC_CONN_TIMER_TYPE Type = 0; Type < QUIC_CONN_TIMER_COUNT; ++Type) {
        if (Connection->ExpirationTimes[Type] <= TimeNow) {
            Connection->ExpirationTimes[Type] = UINT64_MAX;
            QuicTraceEvent(
                ConnExpiredTimer,
                "[conn][%p] %hhu expired",
                Connection,
                (uint8_t)Type);
            if (Type == QUIC_CONN_TIMER_ACK_DELAY) {
                QuicTraceEvent(
                    ConnExecTimerOper,
                    "[conn][%p] Execute: %u",
                    Connection,
                    QUIC_CONN_TIMER_ACK_DELAY);
                QuicSendProcessDelayedAckTimer(&Connection->Send);
                FlushSendImmediate = TRUE;
            } else if (Type == QUIC_CONN_TIMER_PACING) {
                QuicTraceEvent(
                    ConnExecTimerOper,
                    "[conn][%p] Execute: %u",
                    Connection,
                    QUIC_CONN_TIMER_PACING);
                FlushSendImmediate = TRUE;
                Connection->Send.FlushForPacing = TRUE;
            } else {
                QUIC_OPERATION* Oper;
                if ((Oper = QuicConnAllocOperation(Connection, QUIC_OPER_TYPE_TIMER_EXPIRED)) != NULL) {
                    Oper->TIMER_EXPIRED.Type = Type;
                    QuicConnQueueOper(Connection, Oper);
                } else {
                    //
                    // TODO: ideally, we should put this event back to the timer wheel
                    // so it can fire again later.
                    //
                    QuicTraceEvent(
                        AllocFailure,
                        "Allocation of '%s' failed. (%llu bytes)",
                        "expired timer operation",
                        0);
                }
            }
        } else if (Connection->ExpirationTimes[Type] < Connection->EarliestExpirationTime) {
            Connection->EarliestExpirationTime = Connection->ExpirationTimes[Type];
        }
    }

    QuicTimerWheelUpdateConnection(&Connection->Worker->TimerWheel, Connection);

    if (FlushSendImmediate) {
        //
        // We don't want to actually call the flush immediate above as it can
        // cause a new timer to be inserted, messing up timer loop.
        //
        (void)QuicSendFlush(&Connection->Send);
    }
}

//
// Sends a shutdown being notification to the app, which represents the first
// indication that we know the connection is closed (locally or remotely).
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnIndicateShutdownBegin(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_CONNECTION_EVENT Event;
    if (Connection->State.AppClosed) {
        Event.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER;
        Event.SHUTDOWN_INITIATED_BY_PEER.ErrorCode = Connection->CloseErrorCode;
        QuicTraceLogConnVerbose(
            IndicateShutdownByPeer,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER [0x%llx]",
            Event.SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
    } else {
        Event.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT;
        Event.SHUTDOWN_INITIATED_BY_TRANSPORT.Status = Connection->CloseStatus;
        Event.SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode = Connection->CloseErrorCode;
        QuicTraceLogConnVerbose(
            IndicateShutdownByTransport,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT [0x%x]",
            Event.SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
    }
    (void)QuicConnIndicateEvent(Connection, &Event);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnOnShutdownComplete(
    _In_ QUIC_CONNECTION* Connection
    )
{
    Connection->State.ProcessShutdownComplete = FALSE;
    if (Connection->State.ShutdownComplete) {
        return;
    }
    Connection->State.ShutdownComplete = TRUE;
    Connection->State.UpdateWorker = FALSE;

    if (Connection->AddressMonitorRef) {
        //
        // Released here rather than at free: tearing the monitor down joins
        // the backend's thread, which is PASSIVE_LEVEL work, and QuicConnFree
        // runs at DISPATCH_LEVEL.
        //
        Connection->AddressMonitorRef = FALSE;
        QuicLibraryReleaseAddressMonitor();
    }

    QuicTraceEvent(
        ConnShutdownComplete,
        "[conn][%p] Shutdown complete, PeerFailedToAcknowledged=%hhu.",
        Connection,
        Connection->State.ShutdownCompleteTimedOut);

    //
    // Clean up any pending state that is irrelevant now.
    //
    QUIC_PATH* Path = &Connection->Paths[0];
    if (Path->Binding != NULL) {
        if (Path->EncryptionOffloading) {
            QuicPathUpdateQeo(Connection, Path, CXPLAT_QEO_OPERATION_REMOVE);
        }
    }
    //
    // Remove all entries in the binding's lookup tables so we don't get any
    // more packets queued.
    //
    if (Connection->RemoteHashEntry != NULL) {
        CXPLAT_DBG_ASSERT(Connection->RemoteHashEntry->Binding != NULL);
        QuicBindingRemoveRemoteHash(
            Connection->RemoteHashEntry->Binding,
            Connection->RemoteHashEntry);
    }

    QuicPathIDSetFreeSourceCids(&Connection->PathIDs);

    //
    // Clean up the rest of the internal state.
    //
    QuicTimerWheelRemoveConnection(&Connection->Worker->TimerWheel, Connection);
    //
    // Loss detection now lives on each QUIC_PATHID. Discard every path id's
    // outstanding sent packets here so that the stream references held by that
    // sent packet metadata are released. Otherwise those references would keep
    // the streams (and therefore the connection) alive, and the loss detection
    // would only be uninitialized in QuicPathIDFree, which never runs because
    // it is reached via QuicConnFree once the connection reference count drops
    // to zero - a circular dependency that would hang connection teardown.
    //
    QuicPathIDSetUninitializeLossDetection(&Connection->PathIDs);
    QuicSendUninitialize(&Connection->Send);
    QuicDatagramSendShutdown(&Connection->Datagram);
    if (QuicConnIsQMux(Connection)) {
        if (QuicConnGetQMux(Connection)->Socket != NULL) {
            CxPlatSocketDelete(QuicConnGetQMux(Connection)->Socket);
        }
    }

    if (Connection->State.ExternalOwner) {

        QUIC_CONNECTION_EVENT Event;
        Event.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE;
        Event.SHUTDOWN_COMPLETE.HandshakeCompleted =
            Connection->State.Connected;
        Event.SHUTDOWN_COMPLETE.PeerAcknowledgedShutdown =
            !Connection->State.ShutdownCompleteTimedOut;
        Event.SHUTDOWN_COMPLETE.AppCloseInProgress =
            Connection->State.HandleClosed;

        QuicTraceLogConnVerbose(
            IndicateConnectionShutdownComplete,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE");
        (void)QuicConnIndicateEvent(Connection, &Event);

        // This need to be later than QuicLossDetectionUninitialize to indicate
        // status change of Datagram frame for an app to free its buffer
        Connection->ClientCallbackHandler = NULL;
    } else {
        //
        // If the connection was never indicated to the application, then the
        // "owner" ref still resides with the stack and needs to be released.
        //
        QuicConnUnregister(Connection);
        QuicConnRelease(Connection, QUIC_CONN_REF_HANDLE_OWNER);
    }
}

QUIC_STATUS
QuicErrorCodeToStatus(
    QUIC_VAR_INT ErrorCode
    )
{
    switch (ErrorCode) {
    case QUIC_ERROR_NO_ERROR:                       return QUIC_STATUS_SUCCESS;
    case QUIC_ERROR_CONNECTION_REFUSED:             return QUIC_STATUS_CONNECTION_REFUSED;
    case QUIC_ERROR_PROTOCOL_VIOLATION:             return QUIC_STATUS_PROTOCOL_ERROR;
    case QUIC_ERROR_APPLICATION_ERROR:
    case QUIC_ERROR_CRYPTO_USER_CANCELED:           return QUIC_STATUS_USER_CANCELED;
    case QUIC_ERROR_CRYPTO_HANDSHAKE_FAILURE:       return QUIC_STATUS_HANDSHAKE_FAILURE;
    case QUIC_ERROR_CRYPTO_NO_APPLICATION_PROTOCOL: return QUIC_STATUS_ALPN_NEG_FAILURE;
    case QUIC_ERROR_VERSION_NEGOTIATION_ERROR:      return QUIC_STATUS_VER_NEG_ERROR;
    default:
        if (IS_QUIC_CRYPTO_ERROR(ErrorCode)) {
            return QUIC_STATUS_TLS_ALERT(ErrorCode);
        }
        return QUIC_STATUS_INTERNAL_ERROR;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnTryClose(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t Flags,
    _In_ uint64_t ErrorCode,
    _In_reads_bytes_opt_(RemoteReasonPhraseLength)
         const char* RemoteReasonPhrase,
    _In_ uint16_t RemoteReasonPhraseLength
    )
{
    BOOLEAN ClosedRemotely = !!(Flags & QUIC_CLOSE_REMOTE);
    BOOLEAN SilentClose = !!(Flags & QUIC_CLOSE_SILENT);

    CXPLAT_DBG_ASSERT(!(ClosedRemotely && SilentClose));

    Connection->State.ClosedSilently = SilentClose;

    if ((ClosedRemotely && Connection->State.ClosedRemotely) ||
        (!ClosedRemotely && Connection->State.ClosedLocally)) {
        //
        // Already closed.
        //
        if (SilentClose &&
            Connection->State.ClosedLocally &&
            !Connection->State.ClosedRemotely) {
            //
            // Silent close forced after we already started the close process.
            //
            Connection->State.ShutdownCompleteTimedOut = FALSE;
            Connection->State.ProcessShutdownComplete = TRUE;
        }
        return;
    }

    if (ClosedRemotely) {
        Connection->State.ClosedRemotely = TRUE;
    } else {
        Connection->State.ClosedLocally = TRUE;
        if (!Connection->State.ExternalOwner) {
            //
            // Don't continue processing the connection, since it has been
            // closed locally and it's not referenced externally.
            //
            QuicTraceLogConnVerbose(
                AbandonInternallyClosed,
                Connection,
                "Abandoning internal, closed connection");
            Connection->State.ProcessShutdownComplete = TRUE;
        }
    }

    if (Connection->Worker == NULL) {
        //
        // The connection is being closed before it was ever assigned to a
        // worker - e.g. an allocation failure while creating the initial path
        // id in QuicConnAlloc triggers a transport error. There is no worker to
        // run a closing/draining period, its timer wheel does not exist, and
        // nothing has been sent to the peer, so skip all network-facing close
        // handling (timers, send flags, operation queueing). QuicConnAlloc
        // tears the connection down immediately afterward.
        //
        Connection->State.ProcessShutdownComplete = TRUE;
        return;
    }

    BOOLEAN ResultQuicStatus = !!(Flags & QUIC_CLOSE_QUIC_STATUS);

    BOOLEAN IsFirstCloseForConnection = TRUE;

    if (ClosedRemotely && !Connection->State.ClosedLocally) {

        //
        // Peer closed first.
        //

        if (!Connection->State.Connected && QuicConnIsClient(Connection)) {
            //
            // If the server terminates a connection attempt, close immediately
            // without going through the draining period.
            //
            SilentClose = TRUE;
        }

        if (!SilentClose) {
            //
            // Enter 'draining period' to flush out any leftover packets.
            // During that time, no packet should be sent.
            //
            QuicConnTimerSet(
                Connection,
                QUIC_CONN_TIMER_SHUTDOWN,
                CXPLAT_MAX(MS_TO_US(15), Connection->Paths[0].SmoothedRtt * 2));

            QuicSendSetSendFlag(
                &Connection->Send,
                QUIC_CONN_SEND_FLAG_CONNECTION_CLOSE);
        }

    } else if (!ClosedRemotely && !Connection->State.ClosedRemotely) {

        //
        // Locally closed first.
        //

        if (!SilentClose) {
            //
            // Enter 'closing period' to wait for a (optional) connection close
            // response. During that time, the connection close will be re-transmitted
            // when packets are received. QMux connections have no PathID, and
            // therefore no loss detection, to compute a PTO from, so they fall
            // back to an RTT-based estimate.
            //
            uint64_t Pto =
                QuicConnIsQMux(Connection) ?
                    CXPLAT_MAX(MS_TO_US(15), Connection->Paths[0].SmoothedRtt * 2) :
                    QuicLossDetectionComputeProbeTimeout(
                        &Connection->Paths[0].PathID->LossDetection,
                        &Connection->Paths[0],
                        QUIC_CLOSE_PTO_COUNT);
            QuicConnTimerSet(
                Connection,
                QUIC_CONN_TIMER_SHUTDOWN,
                Pto);

            QuicSendSetSendFlag(
                &Connection->Send,
                (Flags & QUIC_CLOSE_APPLICATION) ?
                    QUIC_CONN_SEND_FLAG_APPLICATION_CLOSE :
                    QUIC_CONN_SEND_FLAG_CONNECTION_CLOSE);
        }

    } else {

        QuicTraceLogConnInfo(
            CloseComplete,
            Connection,
            "Connection close complete");

        //
        // Peer acknowledged our local close.
        //

        if (QuicConnIsClient(Connection)) {
            //
            // Client side can immediately clean up once its close frame was
            // acknowledged because we will close the socket during clean up,
            // which will automatically handle any leftover packets that
            // get received afterward by dropping them.
            //

        } else if (!SilentClose) {
            //
            // Server side transitions from the 'closing period' to the
            // 'draining period' and waits an additional 2 RTT just to make
            // sure all leftover packets have been flushed out.
            //
            QuicConnTimerSet(
                Connection,
                QUIC_CONN_TIMER_SHUTDOWN,
                CXPLAT_MAX(MS_TO_US(15), Connection->Paths[0].SmoothedRtt * 2));
        }

        IsFirstCloseForConnection = FALSE;
    }

    if (IsFirstCloseForConnection) {
        //
        // Default to the timed out state.
        //
        Connection->State.ShutdownCompleteTimedOut = TRUE;

        //
        // Cancel all non-shutdown related timers.
        //
        for (QUIC_CONN_TIMER_TYPE TimerType = QUIC_CONN_TIMER_IDLE;
            TimerType < QUIC_CONN_TIMER_SHUTDOWN;
            ++TimerType) {
            QuicConnTimerCancel(Connection, TimerType);
        }

        if (ResultQuicStatus) {
            Connection->CloseStatus = (QUIC_STATUS)ErrorCode;
            Connection->CloseErrorCode = QUIC_ERROR_INTERNAL_ERROR;
        } else {
            Connection->CloseStatus = QuicErrorCodeToStatus(ErrorCode);
            CXPLAT_DBG_ASSERT(ErrorCode <= QUIC_VAR_INT_MAX);
            Connection->CloseErrorCode = ErrorCode;
            if (QuicErrorIsProtocolError(ErrorCode)) {
                QuicPerfCounterIncrement(
                    Connection->Partition, QUIC_PERF_COUNTER_CONN_PROTOCOL_ERRORS);
            }
        }

        if (Flags & QUIC_CLOSE_APPLICATION) {
            Connection->State.AppClosed = TRUE;
        }

        if (Flags & QUIC_CLOSE_SEND_NOTIFICATION &&
            Connection->State.ExternalOwner) {
            QuicConnIndicateShutdownBegin(Connection);
        }

        if (Connection->CloseReasonPhrase != NULL) {
            CXPLAT_FREE(Connection->CloseReasonPhrase, QUIC_POOL_CLOSE_REASON);
            Connection->CloseReasonPhrase = NULL;
        }

        if (RemoteReasonPhraseLength != 0) {
            Connection->CloseReasonPhrase =
                CXPLAT_ALLOC_NONPAGED(RemoteReasonPhraseLength + 1, QUIC_POOL_CLOSE_REASON);
            if (Connection->CloseReasonPhrase != NULL) {
                CxPlatCopyMemory(
                    Connection->CloseReasonPhrase,
                    RemoteReasonPhrase,
                    RemoteReasonPhraseLength);
                Connection->CloseReasonPhrase[RemoteReasonPhraseLength] = 0;
            } else {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "close reason",
                    RemoteReasonPhraseLength + 1);
            }
        }

        QuicConnLogPathIDStatistics(Connection);

        if (Flags & QUIC_CLOSE_APPLICATION) {
            QuicTraceEvent(
                ConnAppShutdown,
                "[conn][%p] App Shutdown: %llu (Remote=%hhu)",
                Connection,
                ErrorCode,
                ClosedRemotely);
        } else {
            QuicTraceEvent(
                ConnTransportShutdown,
                "[conn][%p] Transport Shutdown: %llu (Remote=%hhu) (QS=%hhu)",
                Connection,
                ErrorCode,
                ClosedRemotely,
                !!(Flags & QUIC_CLOSE_QUIC_STATUS));
        }

        //
        // On initial close, we must shut down all the current streams and
        // clean up pending datagrams.
        //
        QuicStreamSetShutdown(&Connection->Streams);
        QuicDatagramSendShutdown(&Connection->Datagram);
    }

    if (SilentClose) {
        QuicSendClear(&Connection->Send);
    }

    if (SilentClose ||
        (Connection->State.ClosedRemotely && Connection->State.ClosedLocally)) {
        Connection->State.ShutdownCompleteTimedOut = FALSE;
        Connection->State.ProcessShutdownComplete = TRUE;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessShutdownTimerOperation(
    _In_ QUIC_CONNECTION* Connection
    )
{
    //
    // We now consider the peer closed, even if they didn't respond to our close
    // frame.
    //
    Connection->State.ClosedRemotely = TRUE;

    //
    // Now that we are closed in both directions, we can complete the shutdown
    // of the connection.
    //
    Connection->State.ProcessShutdownComplete = TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessProbeAfterPunchOperation(
    _In_ QUIC_CONNECTION* Connection
    )
{
    CXPLAT_DBG_ASSERT(Connection->State.HandshakeConfirmed);
    QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PATH_CHALLENGE);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnCloseLocally(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t Flags,
    _In_ uint64_t ErrorCode,
    _In_opt_z_ const char* ErrorMsg
    )
{
    CXPLAT_DBG_ASSERT(ErrorMsg == NULL || strlen(ErrorMsg) < UINT16_MAX);
    QuicConnTryClose(
        Connection,
        Flags,
        ErrorCode,
        ErrorMsg,
        ErrorMsg == NULL ? 0 : (uint16_t)strlen(ErrorMsg));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnOnQuicVersionSet(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QuicTraceEvent(
        ConnVersionSet,
        "[conn][%p] QUIC Version: 0x%x",
        Connection,
        Connection->Stats.QuicVersion);

    switch (Connection->Stats.QuicVersion) {
    case QUIC_VERSION_1:
    case QUIC_VERSION_DRAFT_29:
    case QUIC_VERSION_MS_1:
    case QUIC_VERSION_2:
    default:
        Connection->State.HeaderProtectionEnabled = TRUE;
        break;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnStart(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CONFIGURATION* Configuration,
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_opt_z_ const char* ServerName,
    _In_ uint16_t ServerPort, // Host byte order
    _In_ QUIC_CONN_START_FLAGS StartFlags
    )
{
    QUIC_STATUS Status;
    QUIC_PATH* Path = &Connection->Paths[0];
    CXPLAT_DBG_ASSERT(QuicConnIsClient(Connection));

    if (Connection->State.ClosedLocally || Connection->State.Started) {
        if (ServerName != NULL) {
            CXPLAT_FREE(ServerName, QUIC_POOL_SERVERNAME);
        }
        return QUIC_STATUS_INVALID_STATE;
    }

    BOOLEAN RegistrationShutingDown;
    uint64_t ShutdownErrorCode;
    QUIC_CONNECTION_SHUTDOWN_FLAGS ShutdownFlags;
    CxPlatDispatchLockAcquire(&Connection->Registration->ConnectionLock);
    ShutdownErrorCode = Connection->Registration->ShutdownErrorCode;
    ShutdownFlags = Connection->Registration->ShutdownFlags;
    RegistrationShutingDown = Connection->Registration->ShuttingDown;
    CxPlatDispatchLockRelease(&Connection->Registration->ConnectionLock);

    if (RegistrationShutingDown) {
        QuicConnShutdown(Connection, ShutdownFlags, ShutdownErrorCode, FALSE, FALSE);
        if (ServerName != NULL) {
            CXPLAT_FREE(ServerName, QUIC_POOL_SERVERNAME);
        }
        return QUIC_STATUS_INVALID_STATE;
    }

    CXPLAT_TEL_ASSERT(Path->Binding == NULL);

    QuicConnApplyNewSettings(
        Connection,
        FALSE,
        &Configuration->Settings);

    QUIC_ADDR* RemoteAddress =
        QuicConnIsQMux(Connection) ?
            &QuicConnGetQMux(Connection)->Route.RemoteAddress :
            &Path->Route.RemoteAddress;
    if (!Connection->State.RemoteAddressSet) {

        CXPLAT_DBG_ASSERT(ServerName != NULL);
        QuicAddrSetFamily(RemoteAddress, Family);

#ifdef QUIC_COMPARTMENT_ID
        BOOLEAN RevertCompartmentId = FALSE;
        QUIC_COMPARTMENT_ID PrevCompartmentId = QuicCompartmentIdGetCurrent();
        if (PrevCompartmentId != Configuration->CompartmentId) {
            Status = QuicCompartmentIdSetCurrent(Configuration->CompartmentId);
            if (QUIC_FAILED(Status)) {
                QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection, Status,
                    "Set current compartment Id");
                goto Exit;
            }
            RevertCompartmentId = TRUE;
        }
#endif

        //
        // Resolve the server name to IP address.
        //
        Status =
            CxPlatDataPathResolveAddress(
                MsQuicLib.Datapath,
                ServerName,
                RemoteAddress);

#ifdef QUIC_COMPARTMENT_ID
        if (RevertCompartmentId) {
            (void)QuicCompartmentIdSetCurrent(PrevCompartmentId);
        }
#endif

        if (QUIC_FAILED(Status)) {
            goto Exit;
        }

        Connection->State.RemoteAddressSet = TRUE;
    }

    if (QuicAddrIsWildCard(RemoteAddress)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Invalid wildcard remote address in connection start");
        goto Exit;
    }

    if (Connection->State.UnconnectedSocket) {
        if (!Connection->State.ShareBinding) {
            //
            // Setting the parameter requires a shared binding, so this only
            // catches a binding that was un-shared afterwards.
            //
            Status = QUIC_STATUS_INVALID_STATE;
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Unconnected socket requires a shared binding");
            goto Exit;
        }

        if (Connection->Settings.QTIPEnabled) {
            //
            // The raw datapath reads a socket with no remote address as a
            // server listener, and requires a wildcard local address of one
            // (see RawSocketCreateUdp). An unconnected socket has neither: no
            // remote address by definition, and a specific local address by
            // requirement. Without QTIP that only costs the raw datapath, since
            // the socket falls back to an OS one; with it there is no fallback.
            //
            Status = QUIC_STATUS_INVALID_STATE;
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Unconnected socket is not supported with QTIP");
            goto Exit;
        }

        if (!Connection->State.LocalAddressSet ||
            QuicAddrIsWildCard(&Path->Route.LocalAddress)) {
            //
            // A connected socket takes its source address from the kernel when
            // it is connected. An unconnected one does not, and the first packet
            // goes out before anything has been learned from the peer, so the
            // application has to name the address to send from.
            //
            Status = QUIC_STATUS_INVALID_PARAMETER;
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Unconnected socket requires a specific local address");
            goto Exit;
        }
    }

    if (ServerName == NULL) {
        //
        // If a server name is not provided, use the IP address for server certificate validation.
        //
        QUIC_ADDR_STR RemoteAddressString;
        if (!QuicAddrIpToString(RemoteAddress, &RemoteAddressString)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Failed to convert remote address to server name");
            goto Exit;
        }

        const size_t ServerNameLength = strlen(RemoteAddressString.Address);
        ServerName = CXPLAT_ALLOC_NONPAGED(ServerNameLength + 1, QUIC_POOL_SERVERNAME);
        if (ServerName == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Server name",
                ServerNameLength + 1);
            goto Exit;
        }
        CxPlatCopyMemory((char*)ServerName, RemoteAddressString.Address, ServerNameLength + 1);
    }

    QuicAddrSetPort(RemoteAddress, ServerPort);
    QuicTraceEvent(
        ConnRemoteAddrAdded,
        "[conn][%p] New Remote IP: %!ADDR!",
        Connection,
        CASTED_CLOG_BYTEARRAY(sizeof(*RemoteAddress), RemoteAddress));

    if (!QuicConnIsQMux(Connection)) {
        CXPLAT_UDP_CONFIG UdpConfig = {0};
        UdpConfig.LocalAddress = Connection->State.LocalAddressSet ? &Path->Route.LocalAddress : NULL;
        //
        // Passing no remote address leaves the socket unconnected, which is what
        // lets a single binding carry connections to different remote addresses.
        //
        UdpConfig.RemoteAddress = Connection->State.UnconnectedSocket ? NULL : &Path->Route.RemoteAddress;
        UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
        UdpConfig.InterfaceIndex = Connection->State.LocalInterfaceSet ? (uint32_t)Path->Route.LocalAddress.Ipv6.sin6_scope_id : 0; // NOLINT(google-readability-casting)
        UdpConfig.PartitionIndex = QuicPartitionIdGetIndex(Connection->PartitionID);
#ifdef QUIC_COMPARTMENT_ID
        UdpConfig.CompartmentId = Configuration->CompartmentId;
#endif
#ifdef QUIC_OWNING_PROCESS
        UdpConfig.OwningProcess = Configuration->OwningProcess;
#endif

        if (Connection->State.ShareBinding) {
            UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_SHARE;
        }
        if (Connection->Settings.XdpEnabled) {
            UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_XDP;
        }
        if (Connection->Settings.QTIPEnabled) {
            UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_QTIP;
        }
        if (Connection->State.Partitioned) {
            UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_PARTITIONED;
        }

        //
        // Get the binding for the current local & remote addresses.
        //
        Status =
            QuicLibraryGetBinding(
                &UdpConfig,
                &Path->Binding);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }

        //
        // Clients only need to generate a non-zero length source CID if it
        // intends to share the UDP binding.
        //
        QUIC_CID_SLIST_ENTRY* SourceCid;
        if (Connection->State.ShareBinding) {
            SourceCid =
                QuicCidNewRandomSource(
                    Path->PathID,
                    NULL,
                    Connection->PartitionID,
                    Connection->CibirId[0],
                    Connection->CibirId+2);
        } else {
            SourceCid = QuicCidNewNullSource(Path->PathID);
        }
        if (SourceCid == NULL) {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Exit;
        }

        Path->PathID->NextSourceCidSequenceNumber++;
        QuicPathIDAddSourceCID(Path->PathID, SourceCid, TRUE);

        if (!QuicBindingAddSourceConnectionID(Path->Binding, SourceCid)) {
            QuicLibraryReleaseBinding(Path->Binding);
            Path->Binding = NULL;
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Exit;
        }

        Connection->State.LocalAddressSet = TRUE;
        QuicBindingGetLocalAddress(Path->Binding, &Path->Route.LocalAddress);

        QuicTraceEvent(
            ConnLocalAddrAdded,
            "[conn][%p] New Local IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Path->Route.LocalAddress), &Path->Route.LocalAddress));

    } else {
        QUIC_QMUX* QMux = QuicConnGetQMux(Connection);
        Status = CxPlatSocketCreateTcp(MsQuicLib.Datapath,
            Connection->State.LocalAddressSet ? &QMux->Route.LocalAddress : NULL,
            &QMux->Route.RemoteAddress,
            QMux,
            &QMux->Socket
        );
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }

        //
        // Save the server name before handing the rest of the start off; the
        // TLS layer needs it for SNI.
        //
        Connection->RemoteServerName = ServerName;
        ServerName = NULL;

        //
        // The TCP connect completion is dispatched by the datapath on one of
        // the partition threads, which may well be the thread running this
        // operation. Waiting for it here would deadlock that thread against
        // itself, so hold on to the configuration and finish the start from
        // QuicConnQMuxCompleteStart once QuicQMuxTcpConnect queues
        // QUIC_OPER_TYPE_TCP_CONNECT. The idle timer, armed below with
        // HandshakeIdleTimeoutMs while the connection is not yet connected,
        // bounds how long the connect may take.
        //
        QuicConfigurationAddRef(Configuration, QUIC_CONF_REF_CONN_START_OP);
        QMux->PendingStartConfiguration = Configuration;
        QMux->PendingStartFlags = StartFlags;
        QuicConnResetIdleTimeout(Connection);

        Status = QUIC_STATUS_SUCCESS;
        goto Exit;
    }

    //
    // Save the server name.
    //
    Connection->RemoteServerName = ServerName;
    ServerName = NULL;

    if (!QuicConnIsQMux(Connection)) {
        Status = QuicCryptoInitialize(&Connection->Crypto);
        if (QUIC_FAILED(Status)) {
            goto Exit;
        }
    }

    //
    // Start the handshake.
    //
    Status = QuicConnSetConfiguration(Connection, Configuration);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

Exit:

    if (ServerName != NULL) {
        CXPLAT_FREE(ServerName, QUIC_POOL_SERVERNAME);
    }

    if (QUIC_FAILED(Status)) {
        if (StartFlags & QUIC_CONN_START_FLAG_FAIL_SILENTLY) {
            //
            // This connection was created internally (e.g. by the connection
            // pool) and was never returned to the application. Suppress the
            // shutdown-complete notification by clearing the callback handler.
            // The connection stays externally owned; the creating context is
            // responsible for closing it and releasing the owner reference.
            //
            Connection->ClientCallbackHandler = NULL;
        }
        QuicConnCloseLocally(
            Connection,
            StartFlags & QUIC_CONN_START_FLAG_FAIL_SILENTLY ?
                QUIC_CLOSE_SILENT | QUIC_CLOSE_QUIC_STATUS :
                QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
            (uint64_t)Status,
            NULL);
    }

    return Status;
}

//
// Finishes the client side of a QMux ConnectionStart once the TCP connect has
// completed. Runs on the connection's worker, from QUIC_OPER_TYPE_TCP_CONNECT.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnQMuxCompleteStart(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_QMUX* QMux = QuicConnGetQMux(Connection);
    QUIC_CONFIGURATION* Configuration = QMux->PendingStartConfiguration;
    QUIC_CONN_START_FLAGS StartFlags = QMux->PendingStartFlags;
    QUIC_STATUS Status;

    if (Configuration == NULL) {
        //
        // The start was already completed or abandoned.
        //
        return;
    }
    QMux->PendingStartConfiguration = NULL;

    if (!Connection->State.TcpConnected) {
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Exit;
    }

    Connection->State.LocalAddressSet = TRUE;
    CxPlatSocketGetLocalAddress(QMux->Socket, &QMux->Route.LocalAddress);

    //
    // Start the handshake.
    //
    Status = QuicConnSetConfiguration(Connection, Configuration);

Exit:

    if (QUIC_FAILED(Status)) {
        if (StartFlags & QUIC_CONN_START_FLAG_FAIL_SILENTLY) {
            //
            // See the matching comment in QuicConnStart.
            //
            Connection->ClientCallbackHandler = NULL;
        }
        QuicConnCloseLocally(
            Connection,
            StartFlags & QUIC_CONN_START_FLAG_FAIL_SILENTLY ?
                QUIC_CLOSE_SILENT | QUIC_CLOSE_QUIC_STATUS :
                QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
            (uint64_t)Status,
            NULL);
    }

    QuicConfigurationRelease(Configuration, QUIC_CONF_REF_CONN_START_OP);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRestart(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN CompleteReset
    )
{
    CXPLAT_TEL_ASSERT(Connection->State.Started);

    QuicTraceLogConnInfo(
        Restart,
        Connection,
        "Restart (CompleteReset=%hhu)",
        CompleteReset);

    if (CompleteReset) {
        //
        // Don't reset current RTT measurements unless doing a full reset.
        //
        QUIC_PATH* Path = &Connection->Paths[0];
        Path->GotFirstRttSample = FALSE;
        Path->SmoothedRtt = MS_TO_US(Connection->Settings.InitialRttMs);
        Path->RttVariance = Path->SmoothedRtt / 2;
    }

    QUIC_PATHID* PathID = Connection->Paths[0].PathID;
    CXPLAT_DBG_ASSERT(PathID != NULL && PathID->ID == 0);
    for (uint32_t i = 0; i < ARRAYSIZE(PathID->Packets); ++i) {
        CXPLAT_DBG_ASSERT(PathID->Packets[i] != NULL);
        QuicPacketSpaceReset(PathID->Packets[i]);
    }

    QuicCongestionControlReset(&Connection->Paths[0].PathID->CongestionControl, TRUE);
    QuicSendReset(&Connection->Send);
    QuicLossDetectionReset(&Connection->Paths[0].PathID->LossDetection);
    QuicCryptoTlsCleanupTransportParameters(&Connection->PeerTransportParams);

    if (CompleteReset) {
        CXPLAT_DBG_ASSERT(Connection->Configuration != NULL);

        QUIC_TRANSPORT_PARAMETERS LocalTP = { 0 };
        QUIC_STATUS Status =
            QuicConnGenerateLocalTransportParameters(Connection, &LocalTP);
        CXPLAT_FRE_ASSERT(QUIC_SUCCEEDED(Status)); // Can't fail since it passed already.
        UNREFERENCED_PARAMETER(Status);

        Status =
            QuicCryptoInitializeTls(
                &Connection->Crypto,
                Connection->Configuration->SecurityConfig,
                &LocalTP);
        if (QUIC_FAILED(Status)) {
            QuicConnFatalError(Connection, Status, NULL);
        }

        QuicCryptoTlsCleanupTransportParameters(&LocalTP);

    } else {
        QuicCryptoReset(&Connection->Crypto);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnSendResumptionTicket(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint16_t AppDataLength,
    _In_reads_bytes_opt_(AppDataLength)
        const uint8_t* AppResumptionData
    )
{
    QUIC_STATUS Status;
    uint8_t* TicketBuffer = NULL;
    uint32_t TicketLength = 0;
    uint8_t AlpnLength = !QuicConnIsQMux(Connection) ?
        Connection->Crypto.TlsState.NegotiatedAlpn[0] :
        QuicConnGetQMux(Connection)->TlsState.NegotiatedAlpn[0];

    if (Connection->HandshakeTP == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    Status =
        QuicCryptoEncodeServerTicket(
            Connection,
            Connection->Stats.QuicVersion,
            AppDataLength,
            AppResumptionData,
            Connection->HandshakeTP,
            NULL,    // No Careful Resumption data
            AlpnLength,
            !QuicConnIsQMux(Connection) ?
                Connection->Crypto.TlsState.NegotiatedAlpn + 1 :
                QuicConnGetQMux(Connection)->TlsState.NegotiatedAlpn + 1,
            &TicketBuffer,
            &TicketLength);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    if (!QuicConnIsQMux(Connection)) {
        Status = QuicCryptoProcessAppData(&Connection->Crypto, TicketLength, TicketBuffer);
    } else {
        uint32_t TicketLengthConsumed = TicketLength;
        uint32_t TicketOffset = 0;
        do {
            Status =
                QuicQMuxProcessHandshake(
                    QuicConnGetQMux(Connection),
                    CXPLAT_TLS_TICKET_DATA,
                    TicketBuffer + TicketOffset,
                    &TicketLengthConsumed);
            TicketOffset += TicketLengthConsumed;
        } while (TicketOffset < TicketLength && QUIC_SUCCEEDED(Status));
    }

Error:
    if (TicketBuffer != NULL) {
        CXPLAT_FREE(TicketBuffer, QUIC_POOL_SERVER_CRYPTO_TICKET);
    }

    if (AppResumptionData != NULL) {
        CXPLAT_FREE(AppResumptionData, QUIC_POOL_APP_RESUMPTION_DATA);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnRecvResumptionTicket(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t TicketLength,
    _In_reads_(TicketLength)
        const uint8_t* Ticket
    )
{
    BOOLEAN ResumptionAccepted = FALSE;
    QUIC_TRANSPORT_PARAMETERS ResumedTP = {0};
    CxPlatZeroMemory(&ResumedTP, sizeof(ResumedTP));
    if (QuicConnIsServer(Connection)) {
        if (!QuicConnIsQMux(Connection)) {
            if (Connection->Crypto.TicketValidationRejecting) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Resumption Ticket rejected by server app asynchronously");
                Connection->Crypto.TicketValidationRejecting = FALSE;
                Connection->Crypto.TicketValidationPending = FALSE;
                goto Error;
            }
            Connection->Crypto.TicketValidationPending = TRUE;
        } else {
            if (QuicConnGetQMux(Connection)->TicketValidationRejecting) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Resumption Ticket rejected by server app asynchronously");
                QuicConnGetQMux(Connection)->TicketValidationRejecting = FALSE;
                QuicConnGetQMux(Connection)->TicketValidationPending = FALSE;
                goto Error;
            }
            QuicConnGetQMux(Connection)->TicketValidationPending = TRUE;

        }

        if (TicketLength > UINT16_MAX) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Resumption Ticket length too large");
            goto Error;
        }

        const uint8_t* AppData = NULL;
        uint32_t AppDataLength = 0;

        QUIC_STATUS Status =
            QuicCryptoDecodeServerTicket(
                Connection,
                (uint16_t)TicketLength,
                Ticket,
                Connection->Configuration->AlpnList,
                Connection->Configuration->AlpnListLength,
                &ResumedTP,
                NULL,    // No Careful Resumption data
                &AppData,
                &AppDataLength);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }

        //
        // Validate resumed TP are <= current settings
        //
        if (ResumedTP.ActiveConnectionIdLimit > QUIC_ACTIVE_CONNECTION_ID_LIMIT ||
            ResumedTP.InitialMaxData > Connection->Send.MaxData ||
            ResumedTP.InitialMaxStreamDataBidiLocal > Connection->Settings.StreamRecvWindowBidiLocalDefault ||
            ResumedTP.InitialMaxStreamDataBidiRemote > Connection->Settings.StreamRecvWindowBidiRemoteDefault ||
            ResumedTP.InitialMaxStreamDataUni > Connection->Settings.StreamRecvWindowUnidiDefault ||
            ResumedTP.InitialMaxUniStreams > Connection->Streams.Types[STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_UNI_DIR].MaxTotalStreamCount ||
            ResumedTP.InitialMaxBidiStreams > Connection->Streams.Types[STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_BI_DIR].MaxTotalStreamCount) {
            //
            // Server settings have changed since the resumption ticket was
            // encoded, so reject resumption.
            //
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Resumption Ticket transport params greater than current server settings");
            goto Error;
        }

        QUIC_CONNECTION_EVENT Event;
        Event.Type = QUIC_CONNECTION_EVENT_RESUMED;
        Event.RESUMED.ResumptionStateLength = (uint16_t)AppDataLength;
        Event.RESUMED.ResumptionState = (AppDataLength > 0) ? AppData : NULL;
        QuicTraceLogConnVerbose(
            IndicateResumed,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_RESUMED");
        Status = QuicConnIndicateEvent(Connection, &Event);
        if (Status == QUIC_STATUS_SUCCESS) {
            QuicTraceEvent(
                ConnServerResumeTicket,
                "[conn][%p] Server app accepted resumption ticket",
                Connection);
            ResumptionAccepted = TRUE;
            if (!QuicConnIsQMux(Connection)) {
                Connection->Crypto.TicketValidationPending = FALSE;
            } else {
                QuicConnGetQMux(Connection)->TicketValidationPending = FALSE;
            }
        } else if (Status == QUIC_STATUS_PENDING) {
            QuicTraceEvent(
                ConnServerResumeTicket,
                "[conn][%p] Server app asynchronously validating resumption ticket",
                Connection);
            ResumptionAccepted = TRUE;
        } else {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Resumption Ticket rejected by server app");
            ResumptionAccepted = FALSE;
            if (!QuicConnIsQMux(Connection)) {
                Connection->Crypto.TicketValidationPending = FALSE;
            } else {
                QuicConnGetQMux(Connection)->TicketValidationPending = FALSE;
            }
        }

    } else {

        const uint8_t* ClientTicket = NULL;
        uint32_t ClientTicketLength = 0;

        CXPLAT_DBG_ASSERT(Connection->State.PeerTransportParameterValid);

        if (QUIC_SUCCEEDED(
            QuicCryptoEncodeClientTicket(
                Connection,
                TicketLength,
                Ticket,
                &Connection->PeerTransportParams,
                Connection->Stats.QuicVersion,
                &ClientTicket,
                &ClientTicketLength))) {

            QUIC_CONNECTION_EVENT Event;
            Event.Type = QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED;
            Event.RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength = ClientTicketLength;
            Event.RESUMPTION_TICKET_RECEIVED.ResumptionTicket = ClientTicket;
            QuicTraceLogConnVerbose(
                IndicateResumptionTicketReceived,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED");
            (void)QuicConnIndicateEvent(Connection, &Event);

            CXPLAT_FREE(ClientTicket, QUIC_POOL_CLIENT_CRYPTO_TICKET);
            ResumptionAccepted = TRUE;
        }
    }

Error:

    QuicCryptoTlsCleanupTransportParameters(&ResumedTP);
    return ResumptionAccepted;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnCleanupServerResumptionState(
    _In_ QUIC_CONNECTION* Connection
    )
{
    CXPLAT_DBG_ASSERT(QuicConnIsServer(Connection));
    if (!Connection->State.ResumptionEnabled) {
        if (Connection->HandshakeTP != NULL) {
            QuicCryptoTlsCleanupTransportParameters(Connection->HandshakeTP);
            CxPlatPoolFree(Connection->HandshakeTP);
            Connection->HandshakeTP = NULL;
        }

        QUIC_CRYPTO* Crypto = &Connection->Crypto;

        QuicTraceLogConnInfo(
            CryptoStateDiscard,
            Connection,
            "TLS state no longer needed");
        if (Crypto->TLS != NULL) {
            CxPlatTlsUninitialize(Crypto->TLS);
            Crypto->TLS = NULL;
        }
        if (Crypto->Initialized) {
            QuicRecvBufferUninitialize(&Crypto->RecvBuffer);
            QuicRangeUninitialize(&Crypto->SparseAckRanges);
            CXPLAT_FREE(Crypto->TlsState.Buffer, QUIC_POOL_TLS_BUFFER);
            Crypto->TlsState.Buffer = NULL;
            Crypto->Initialized = FALSE;
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnPostAcceptValidatePeerTransportParameters(
    _In_ QUIC_CONNECTION* Connection
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnGenerateLocalTransportParameters(
    _In_ QUIC_CONNECTION* Connection,
    _Out_ QUIC_TRANSPORT_PARAMETERS* LocalTP
    )
{
    CXPLAT_TEL_ASSERT(Connection->Configuration != NULL);

    CXPLAT_DBG_ASSERT(QuicConnIsQMux(Connection) || Connection->Paths[0].PathID->SourceCids.Next != NULL);
    const QUIC_CID_SLIST_ENTRY* SourceCid = NULL;
    if (!QuicConnIsQMux(Connection)) {
        SourceCid =
            CXPLAT_CONTAINING_RECORD(
                Connection->Paths[0].PathID->SourceCids.Next,
                QUIC_CID_SLIST_ENTRY,
                Link);
    }

    LocalTP->InitialMaxData = Connection->Send.MaxData;
    LocalTP->InitialMaxStreamDataBidiLocal = Connection->Settings.StreamRecvWindowBidiLocalDefault;
    LocalTP->InitialMaxStreamDataBidiRemote = Connection->Settings.StreamRecvWindowBidiRemoteDefault;
    LocalTP->InitialMaxStreamDataUni = Connection->Settings.StreamRecvWindowUnidiDefault;
    if (!QuicConnIsQMux(Connection)) {
        LocalTP->MaxUdpPayloadSize =
            MaxUdpPayloadSizeFromMTU(
                CxPlatSocketGetLocalMtu(
                    Connection->Paths[0].Binding->Socket,
                    &Connection->Paths[0].Route));
        LocalTP->MaxAckDelay = QuicConnGetAckDelay(Connection);
        LocalTP->MinAckDelay =
            MsQuicLib.ExecutionConfig != NULL &&
            MsQuicLib.ExecutionConfig->PollingIdleTimeoutUs != 0 ?
                0 : MS_TO_US(MsQuicLib.TimerResolutionMs);
        //
        // Ensure the advertised MaxAckDelay is not below MinAckDelay.
        //
        if (LocalTP->MinAckDelay > MS_TO_US(LocalTP->MaxAckDelay)) {
            LocalTP->MaxAckDelay = US_TO_MS_CEIL(LocalTP->MinAckDelay);
        }
        LocalTP->ActiveConnectionIdLimit = QUIC_ACTIVE_CONNECTION_ID_LIMIT;
    }

    if (!QuicConnIsQMux(Connection)) {
        LocalTP->Flags =
            QUIC_TP_FLAG_INITIAL_MAX_DATA |
            QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
            QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
            QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI |
            QUIC_TP_FLAG_MAX_UDP_PAYLOAD_SIZE |
            QUIC_TP_FLAG_MAX_ACK_DELAY |
            QUIC_TP_FLAG_MIN_ACK_DELAY |
            QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT;
    } else {
        LocalTP->Flags =
            QUIC_TP_FLAG_INITIAL_MAX_DATA |
            QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL |
            QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE |
            QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_UNI;
    }

    //
    // The observed_address transport parameter is only sent when at least one
    // direction of the extension is enabled; its value states which. Address
    // discovery is a UDP path concept, so QMux never advertises it.
    //
    if (!QuicConnIsQMux(Connection) &&
        (Connection->Settings.SendObservedAddressReports ||
         Connection->Settings.ReceiveObservedAddressReports)) {
        LocalTP->Flags |= QUIC_TP_FLAG_OBSERVED_ADDRESS;
        LocalTP->ObservedAddressRole =
            Connection->Settings.SendObservedAddressReports ?
                (Connection->Settings.ReceiveObservedAddressReports ?
                    QUIC_TP_OBSERVED_ADDRESS_ROLE_BOTH :
                    QUIC_TP_OBSERVED_ADDRESS_ROLE_SEND_ONLY) :
                QUIC_TP_OBSERVED_ADDRESS_ROLE_RECEIVE_ONLY;
    }

    if (Connection->Settings.IdleTimeoutMs != 0) {
        LocalTP->Flags |= QUIC_TP_FLAG_IDLE_TIMEOUT;
        LocalTP->IdleTimeout = Connection->Settings.IdleTimeoutMs;
    }

    if (!QuicConnIsQMux(Connection) &&
        Connection->AckDelayExponent != QUIC_TP_ACK_DELAY_EXPONENT_DEFAULT) {
        LocalTP->Flags |= QUIC_TP_FLAG_ACK_DELAY_EXPONENT;
        LocalTP->AckDelayExponent = Connection->AckDelayExponent;
    }

    if (!QuicConnIsQMux(Connection)) {
        LocalTP->Flags |= QUIC_TP_FLAG_INITIAL_SOURCE_CONNECTION_ID;
        LocalTP->InitialSourceConnectionIDLength = SourceCid->CID.Length;
        CxPlatCopyMemory(
            LocalTP->InitialSourceConnectionID,
            SourceCid->CID.Data,
            SourceCid->CID.Length);
    }

    if (Connection->Settings.DatagramReceiveEnabled) {
        LocalTP->Flags |= QUIC_TP_FLAG_MAX_DATAGRAM_FRAME_SIZE;
        LocalTP->MaxDatagramFrameSize = QUIC_DEFAULT_MAX_DATAGRAM_LENGTH;
    }

    if (!QuicConnIsQMux(Connection) && Connection->State.Disable1RttEncrytion) {
        LocalTP->Flags |= QUIC_TP_FLAG_DISABLE_1RTT_ENCRYPTION;
    }

    if (!QuicConnIsQMux(Connection) && Connection->CibirId[0] != 0) {
        LocalTP->Flags |= QUIC_TP_FLAG_CIBIR_ENCODING;
        LocalTP->CibirLength = Connection->CibirId[0];
        LocalTP->CibirOffset = Connection->CibirId[1];
    }

    if (!QuicConnIsQMux(Connection) &&
        Connection->Settings.VersionNegotiationExtEnabled
#if QUIC_TEST_DISABLE_VNE_TP_GENERATION
        && !Connection->State.DisableVneTp
#endif
        ) {
        uint32_t VersionInfoLength = 0;
        LocalTP->VersionInfo =
            QuicVersionNegotiationExtEncodeVersionInfo(Connection, &VersionInfoLength);
        if (LocalTP->VersionInfo != NULL) {
            LocalTP->Flags |= QUIC_TP_FLAG_VERSION_NEGOTIATION;
            LocalTP->VersionInfoLength = VersionInfoLength;
        } else {
            LocalTP->VersionInfoLength = 0;
        }
    }

    if (!QuicConnIsQMux(Connection) && Connection->Settings.GreaseQuicBitEnabled) {
        LocalTP->Flags |= QUIC_TP_FLAG_GREASE_QUIC_BIT;
    }

    if (Connection->Settings.ReliableResetEnabled) {
        LocalTP->Flags |= QUIC_TP_FLAG_RELIABLE_RESET_ENABLED;
    }

    if (!QuicConnIsQMux(Connection) && Connection->Settings.OneWayDelayEnabled) {
        LocalTP->Flags |= QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED |
                          QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED;
    }

    if (!QuicConnIsQMux(Connection) && Connection->Settings.ServerMigrationEnabled) {
        if (!Connection->State.ShareBinding) {
            //
            // Server migration requires a non-zero source CID.
            //
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Server migration requires non-zero length connection IDs");
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        LocalTP->Flags |= QUIC_TP_FLAG_SERVER_MIGRATION;
    }

    if (QuicConnIsQMux(Connection)) {
        LocalTP->Flags |= QX_TP_FLAG_MAX_RECORD_SIZE;
        LocalTP->MaxRecordSize = QX_TP_MAX_RECORD_SIZE_DEFAULT;
    }

    if (Connection->Settings.MultipathEnabled) {
        LocalTP->Flags |= QUIC_TP_FLAG_INITIAL_MAX_PATH_ID;
        LocalTP->InitialMaxPathId = QUIC_ACTIVE_PATH_ID_LIMIT - 1;
    }

    //
    // draft-munizaga-quic-alternative-server-address is a client-sent
    // parameter: it is how a client says it will accept the server's list of
    // alternative addresses. A server must not send it at all.
    //
    // Offered in NAT-traversal mode too, as of #173. It used to be withheld
    // there because the older PUNCH_ME_NOW paired a request to an advertised
    // address by that frame's per-address sequence number, which this draft's
    // single frame-level number cannot express -- so the mode stayed on
    // ADD_ADDRESS and a frame that is now gone. The stateless punch names the
    // pair by address instead, so there is nothing left to withhold it for,
    // and withholding it would now be the thing that breaks the mode: without
    // the advertised set the candidate pair table has no remotes to pair
    // against, and NAT traversal is a policy over that table.
    //
    // Not offered with server migration enabled. A client that negotiates that
    // hands path creation to the server, and QuicConnProcessAddAddress refuses
    // every address a client is told about in that state -- so offering the
    // extension would have the client acknowledge the frames, advance its
    // sequence number and store the set, then reject every address in it.
    // Silently inert is the worst of the three outcomes; not negotiating says
    // so honestly. That is also what keeps the ADD_ADDRESS frames alive: they
    // are the fallback for a peer this parameter was never agreed with.
    //
    if (QuicConnIsClient(Connection) &&
        !Connection->Settings.ServerMigrationEnabled) {
        LocalTP->Flags |= QUIC_TP_FLAG_ALTERNATIVE_ADDRESS;
    }

    //
    // draft-kozuka-quic-stateless-punch's transport parameter, which says
    // "send me PUNCH_ME_NOW and I will punch". True of us as of #171: the
    // frame handler answers a request. We send no requests of our own until
    // #172, which costs nothing -- a peer that asks us to punch gets a punch,
    // and a peer waiting for us to ask is waiting for something the draft
    // never promised it.
    //
    // Both endpoints advertise it, and a client must advertise
    // alternative_address as well -- a server receiving it without that is
    // required to fail the handshake, because the extension pairs the client's
    // candidates against the addresses that frame carries. So the client's
    // condition is "we offered alternative_address", which is the decision
    // made just above rather than a restatement of it, and a server has no
    // prerequisite at all.
    //
    if (QuicConnIsServer(Connection) ||
        (LocalTP->Flags & QUIC_TP_FLAG_ALTERNATIVE_ADDRESS)) {
        LocalTP->Flags |= QUIC_TP_FLAG_STATELESS_PUNCH;
    }

    if (QuicConnIsServer(Connection)) {

        if (Connection->Streams.Types[STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_BI_DIR].MaxTotalStreamCount) {
            LocalTP->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI;
            LocalTP->InitialMaxBidiStreams =
                Connection->Streams.Types[STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_BI_DIR].MaxTotalStreamCount;
        }

        if (Connection->Streams.Types[STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_UNI_DIR].MaxTotalStreamCount) {
            LocalTP->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
            LocalTP->InitialMaxUniStreams =
                Connection->Streams.Types[STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_UNI_DIR].MaxTotalStreamCount;
        }

        if (!QuicConnIsQMux(Connection) && !Connection->Settings.MigrationEnabled) {
            LocalTP->Flags |= QUIC_TP_FLAG_DISABLE_ACTIVE_MIGRATION;
        }

        if (!QuicConnIsQMux(Connection) && SourceCid != NULL) {
            LocalTP->Flags |= QUIC_TP_FLAG_STATELESS_RESET_TOKEN;
            QUIC_STATUS Status =
                QuicLibraryGenerateStatelessResetToken(
                    Connection->Partition,
                    SourceCid->CID.Data,
                    LocalTP->StatelessResetToken);
            if (QUIC_FAILED(Status)) {
                QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection,
                    Status,
                    "QuicLibraryGenerateStatelessResetToken");
                return Status;
            }
        }

        if (!QuicConnIsQMux(Connection) && Connection->OrigDestCID != NULL) {
            CXPLAT_DBG_ASSERT(Connection->OrigDestCID->Length <= QUIC_MAX_CONNECTION_ID_LENGTH_V1);
            LocalTP->Flags |= QUIC_TP_FLAG_ORIGINAL_DESTINATION_CONNECTION_ID;
            LocalTP->OriginalDestinationConnectionIDLength = Connection->OrigDestCID->Length;
            CxPlatCopyMemory(
                LocalTP->OriginalDestinationConnectionID,
                Connection->OrigDestCID->Data,
                Connection->OrigDestCID->Length);

            if (Connection->State.HandshakeUsedRetryPacket) {
                CXPLAT_DBG_ASSERT(SourceCid != NULL && SourceCid->Link.Next != NULL);
                const QUIC_CID_SLIST_ENTRY* PrevSourceCid =
                    CXPLAT_CONTAINING_RECORD(
                        SourceCid->Link.Next,
                        QUIC_CID_SLIST_ENTRY,
                        Link);

                LocalTP->Flags |= QUIC_TP_FLAG_RETRY_SOURCE_CONNECTION_ID;
                LocalTP->RetrySourceConnectionIDLength = PrevSourceCid->CID.Length;
                CxPlatCopyMemory(
                    LocalTP->RetrySourceConnectionID,
                    PrevSourceCid->CID.Data,
                    PrevSourceCid->CID.Length);
            }
        }
    } else {

        if (Connection->Streams.Types[STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_BI_DIR].MaxTotalStreamCount) {
            LocalTP->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI;
            LocalTP->InitialMaxBidiStreams =
                Connection->Streams.Types[STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_BI_DIR].MaxTotalStreamCount;
        }

        if (Connection->Streams.Types[STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_UNI_DIR].MaxTotalStreamCount) {
            LocalTP->Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
            LocalTP->InitialMaxUniStreams =
                Connection->Streams.Types[STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_UNI_DIR].MaxTotalStreamCount;
        }
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnSetConfiguration(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CONFIGURATION* Configuration
    )
{
    if (Connection->Configuration != NULL || QuicConnIsClosed(Connection)) {
        return QUIC_STATUS_INVALID_STATE;
    }

    QUIC_STATUS Status;
    QUIC_TRANSPORT_PARAMETERS LocalTP = { 0 };

    CXPLAT_TEL_ASSERT(Connection->Configuration == NULL);
    CXPLAT_TEL_ASSERT(Configuration != NULL);
    CXPLAT_TEL_ASSERT(Configuration->SecurityConfig != NULL);

    QuicTraceLogConnInfo(
        SetConfiguration,
        Connection,
        "Configuration set, %p",
        Configuration);

    QuicConfigurationAddRef(Configuration, QUIC_CONF_REF_CONNECTION);
    QuicConfigurationAttachSilo(Configuration);
    Connection->Configuration = Configuration;

    if (QuicConnIsServer(Connection)) {
        QuicConnApplyNewSettings(
            Connection,
            FALSE,
            &Configuration->Settings);
    }

    if (QuicConnIsClient(Connection)) {

        if (Connection->Stats.QuicVersion == 0) {
            //
            // Only initialize the version if not already done (by the
            // application layer).
            //
            Connection->Stats.QuicVersion = QUIC_VERSION_LATEST;
            QuicConnOnQuicVersionSet(Connection);
            Status = QuicCryptoOnVersionChange(&Connection->Crypto);
            if (QUIC_FAILED(Status)) {
                goto Error;
            }
        }

        if (!QuicConnIsQMux(Connection)) {
            CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&Connection->Paths[0].PathID->DestCids));
            const QUIC_CID_LIST_ENTRY* DestCid =
                CXPLAT_CONTAINING_RECORD(
                    Connection->Paths[0].PathID->DestCids.Flink,
                    QUIC_CID_LIST_ENTRY,
                    Link);

            //
            // Save the original CID for later validation in the TP.
            //
            Connection->OrigDestCID =
                CXPLAT_ALLOC_NONPAGED(
                    sizeof(QUIC_CID) +
                    DestCid->CID.Length,
                    QUIC_POOL_CID);
            if (Connection->OrigDestCID == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "OrigDestCID",
                    sizeof(QUIC_CID) + DestCid->CID.Length);
                Status = QUIC_STATUS_OUT_OF_MEMORY;
                goto Error;
            }

            Connection->OrigDestCID->Length = DestCid->CID.Length;
            CxPlatCopyMemory(
                Connection->OrigDestCID->Data,
                DestCid->CID.Data,
                DestCid->CID.Length);
        }
    } else if (!QuicConnIsQMux(Connection)) {
        if (!QuicConnPostAcceptValidatePeerTransportParameters(Connection)) {
            QuicConnTransportError(Connection, QUIC_ERROR_CONNECTION_REFUSED);
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Cleanup;
        }

        Status =
            QuicCryptoReNegotiateAlpn(
                Connection,
                Connection->Configuration->AlpnListLength,
                Connection->Configuration->AlpnList);
        if (QUIC_FAILED(Status)) {
            goto Cleanup;
        }
    }

    Status = QuicConnGenerateLocalTransportParameters(Connection, &LocalTP);
    if (QUIC_FAILED(Status)) {
        goto Cleanup;
    }

    //
    // Persist the transport parameters used during handshake for resumption.
    // (if resumption is enabled)
    //
    if (QuicConnIsServer(Connection) && Connection->HandshakeTP != NULL) {
        CXPLAT_DBG_ASSERT(Connection->State.ResumptionEnabled);
        QuicCryptoTlsCopyTransportParameters(&LocalTP, Connection->HandshakeTP);
    }

    Connection->State.Started = TRUE;
    Connection->Stats.Timing.Start = CxPlatTimeUs64();
    QuicTraceEvent(
        ConnHandshakeStart,
        "[conn][%p] Handshake start",
        Connection);

    if (QuicConnIsServer(Connection)) {
        //
        // Evaluate the datagram send state for a server. This is the first
        // point at which both of its inputs are settled and there is an
        // external owner to indicate the result to: the peer's transport
        // parameters are processed before the listener hands the connection to
        // the application, and `Started` selects the MTU that the max send
        // length is derived from.
        //
        // A client's send state is evaluated once its peer's transport
        // parameters arrive, which is always after it has an owner, so it needs
        // nothing here.
        //
        QuicDatagramOnSendStateChanged(&Connection->Datagram);
    }

    if (!QuicConnIsQMux(Connection)) {
        Status =
            QuicCryptoInitializeTls(
                &Connection->Crypto,
                Configuration->SecurityConfig,
                &LocalTP);
    } else {
        Status =
            QuicQMuxInitializeTls(
                QuicConnGetQMux(Connection),
                Configuration->SecurityConfig);
    }

Cleanup:

    QuicCryptoTlsCleanupTransportParameters(&LocalTP);

Error:

    QuicConfigurationDetachSilo();

    return Status;
}

BOOLEAN
QuicConnValidateTransportParameterCIDs(
    _In_ QUIC_CONNECTION* Connection
    )
{
    CXPLAT_DBG_ASSERT(!QuicConnIsQMux(Connection));

    if (!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_INITIAL_SOURCE_CONNECTION_ID)) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Peer didn't provide the initial source CID in TP");
        return FALSE;
    }

    const QUIC_CID_LIST_ENTRY* DestCid =
        CXPLAT_CONTAINING_RECORD(
            Connection->Paths[0].PathID->DestCids.Flink,
            QUIC_CID_LIST_ENTRY,
            Link);
    if (DestCid->CID.Length != Connection->PeerTransportParams.InitialSourceConnectionIDLength ||
        memcmp(DestCid->CID.Data, Connection->PeerTransportParams.InitialSourceConnectionID, DestCid->CID.Length) != 0) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Initial source CID from TP doesn't match");
        return FALSE;
    }

    if (QuicConnIsClient(Connection)) {
        if (!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_ORIGINAL_DESTINATION_CONNECTION_ID)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Server didn't provide the original destination CID in TP");
            return FALSE;
        }
        CXPLAT_DBG_ASSERT(Connection->OrigDestCID);
        if (Connection->OrigDestCID->Length != Connection->PeerTransportParams.OriginalDestinationConnectionIDLength ||
            memcmp(Connection->OrigDestCID->Data, Connection->PeerTransportParams.OriginalDestinationConnectionID, Connection->OrigDestCID->Length) != 0) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Original destination CID from TP doesn't match");
            return FALSE;
        }
        if (Connection->State.HandshakeUsedRetryPacket) {
            if (!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_RETRY_SOURCE_CONNECTION_ID)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Server didn't provide the retry source CID in TP");
                return FALSE;
            }
            // TODO - Validate
        } else {
            if (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_RETRY_SOURCE_CONNECTION_ID) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Server incorrectly provided the retry source CID in TP");
                return FALSE;
            }
        }
    }

    return TRUE;
}

QUIC_STATUS
QuicConnProcessPeerVersionNegotiationTP(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_STATUS Status;
    if (QuicConnIsServer(Connection)) {
        //
        // Check whether version is in (App-specified) list of acceptable versions.
        //
        uint32_t SupportedVersionsLength = 0;
        const uint32_t* SupportedVersions = NULL;
        if (MsQuicLib.Settings.IsSet.VersionSettings) {
            SupportedVersionsLength = MsQuicLib.Settings.VersionSettings->AcceptableVersionsLength;
            SupportedVersions = MsQuicLib.Settings.VersionSettings->AcceptableVersions;
        } else {
            SupportedVersionsLength = ARRAYSIZE(DefaultSupportedVersionsList);
            SupportedVersions = DefaultSupportedVersionsList;
        }

        uint32_t CurrentVersionIndex = 0;
        for (; CurrentVersionIndex < SupportedVersionsLength; ++CurrentVersionIndex) {
            if (Connection->Stats.QuicVersion == SupportedVersions[CurrentVersionIndex]) {
                break;
            }
        }
        if (CurrentVersionIndex == SupportedVersionsLength) {
            CXPLAT_DBG_ASSERTMSG(FALSE,"Incompatible Version Negotation should happen in binding layer");
            //
            // Current version not supported, start incompatible version negotiation.
            // This path should only hit when the AcceptableVersions are changed globally
            // between when the first flight was received, and this point.
            //
            return QUIC_STATUS_VER_NEG_ERROR;
        }

        QUIC_VERSION_INFORMATION_V1 ClientVI;
        Status =
            QuicVersionNegotiationExtParseVersionInfo(
                Connection,
                Connection->PeerTransportParams.VersionInfo,
                (uint16_t)Connection->PeerTransportParams.VersionInfoLength,
                &ClientVI);
        if (QUIC_FAILED(Status)) {
            QuicConnTransportError(Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
            return QUIC_STATUS_PROTOCOL_ERROR;
        }

        if (ClientVI.ChosenVersion == 0) {
            QuicTraceLogConnError(
                VersionInfoChosenVersionZero,
                Connection,
                "Version Info Chosen Version is zero!");
            QuicConnTransportError(Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
            return QUIC_STATUS_PROTOCOL_ERROR;
        }

        //
        // Assume QuicVersion on the Connection is the long header value
        // and verify it matches the VNE TP.
        //
        if (Connection->Stats.QuicVersion != ClientVI.ChosenVersion) {
            QuicTraceLogConnError(
                ClientVersionInfoVersionMismatch,
                Connection,
                "Client Chosen Version doesn't match long header. 0x%x != 0x%x",
                ClientVI.ChosenVersion,
                Connection->Stats.QuicVersion);
            QuicConnTransportError(Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
            return QUIC_STATUS_PROTOCOL_ERROR;
        }

        //
        // Attempt to upgrade the connection to a compatible version the server prefers.
        //
        for (uint32_t ServerVersionIdx = 0; ServerVersionIdx < CurrentVersionIndex; ++ServerVersionIdx) {
            if (QuicIsVersionReserved(SupportedVersions[ServerVersionIdx])) {
                continue;
            }
            for (uint32_t ClientVersionIdx = 0; ClientVersionIdx < ClientVI.AvailableVersionsCount; ++ClientVersionIdx) {
                if (ClientVI.AvailableVersions[ClientVersionIdx] == 0) {
                    QuicTraceLogConnError(
                        VersionInfoOtherVersionZero,
                        Connection,
                        "Version Info.AvailableVersions contains a zero version! Index = %u",
                        ClientVersionIdx);
                    QuicConnTransportError(Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
                    return QUIC_STATUS_PROTOCOL_ERROR;
                }
                if (!QuicIsVersionReserved(ClientVI.AvailableVersions[ClientVersionIdx]) &&
                    ClientVI.AvailableVersions[ClientVersionIdx] == SupportedVersions[ServerVersionIdx] &&
                    QuicVersionNegotiationExtAreVersionsCompatible(
                        ClientVI.ChosenVersion,
                        ClientVI.AvailableVersions[ClientVersionIdx])) {
                    QuicTraceLogConnVerbose(
                        ClientVersionNegotiationCompatibleVersionUpgrade,
                        Connection,
                        "Compatible version upgrade! Old: 0x%x, New: 0x%x",
                        Connection->Stats.QuicVersion,
                        SupportedVersions[ServerVersionIdx]);
                    Connection->Stats.QuicVersion = SupportedVersions[ServerVersionIdx];
                    QuicConnOnQuicVersionSet(Connection);
                    Status = QuicCryptoOnVersionChange(&Connection->Crypto);
                    if (QUIC_FAILED(Status)) {
                        QuicConnTransportError(Connection, QUIC_ERROR_VERSION_NEGOTIATION_ERROR);
                        return QUIC_STATUS_INTERNAL_ERROR;
                    }
                }
            }
        }
        //
        // If the version negotiation upgrade failed, just continue
        // with the current version.
        //
    } else {
        //
        // Client must perform downgrade prevention
        //
        QUIC_VERSION_INFORMATION_V1 ServerVI = {0};
        Status =
            QuicVersionNegotiationExtParseVersionInfo(
                Connection,
                Connection->PeerTransportParams.VersionInfo,
                (uint16_t)Connection->PeerTransportParams.VersionInfoLength,
                &ServerVI);
        if (QUIC_FAILED(Status)) {
            QuicConnTransportError(Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
            return QUIC_STATUS_PROTOCOL_ERROR;
        }

        if (ServerVI.ChosenVersion == 0) {
            QuicTraceLogConnError(
                VersionInfoChosenVersionZero,
                Connection,
                "Version Info Chosen Version is zero!");
            QuicConnTransportError(Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
            return QUIC_STATUS_PROTOCOL_ERROR;
        }

        if (Connection->Stats.QuicVersion != ServerVI.ChosenVersion) {
            QuicTraceLogConnError(
                ServerVersionInfoVersionMismatch,
                Connection,
                "Server Chosen Version doesn't match long header. 0x%x != 0x%x",
                ServerVI.ChosenVersion,
                Connection->Stats.QuicVersion);
            QuicConnTransportError(Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
            return QUIC_STATUS_PROTOCOL_ERROR;
        }

        uint32_t ClientChosenVersion = 0;
        BOOLEAN OriginalVersionFound = FALSE;
        for (uint32_t i = 0; i < ServerVI.AvailableVersionsCount; ++i) {
            if (ServerVI.AvailableVersions[i] == 0) {
                QuicTraceLogConnError(
                    VersionInfoOtherVersionZero,
                    Connection,
                    "Version Info Available Versions contains a zero version! Index = %u",
                    i);
                QuicConnTransportError(Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
                return QUIC_STATUS_PROTOCOL_ERROR;
            }
            //
            // Keep this logic up to date with the logic in QuicConnRecvVerNeg
            //
            if (Connection->Stats.VersionNegotiation &&
                ClientChosenVersion == 0 &&
                QuicVersionNegotiationExtIsVersionClientSupported(Connection, ServerVI.AvailableVersions[i])) {
                ClientChosenVersion = ServerVI.AvailableVersions[i];
            }
            if (Connection->OriginalQuicVersion == ServerVI.AvailableVersions[i]) {
                OriginalVersionFound = TRUE;
            }
        }
        if (ClientChosenVersion == 0 &&
            QuicVersionNegotiationExtIsVersionClientSupported(Connection, ServerVI.ChosenVersion)) {
            ClientChosenVersion = ServerVI.ChosenVersion;
        }
        if (ClientChosenVersion == 0 || (ClientChosenVersion != Connection->OriginalQuicVersion &&
            ClientChosenVersion != ServerVI.ChosenVersion)) {
            QuicTraceLogConnError(
                ClientChosenVersionMismatchServerChosenVersion,
                Connection,
                "Client Chosen Version doesn't match Server Chosen Version: 0x%x vs. 0x%x",
                ClientChosenVersion,
                ServerVI.ChosenVersion);
            QuicConnTransportError(Connection, QUIC_ERROR_VERSION_NEGOTIATION_ERROR);
            return QUIC_STATUS_PROTOCOL_ERROR;
        }
        //
        // If the client has already received a version negotiation packet, do
        // extra validation.
        //
        if (Connection->PreviousQuicVersion != 0) {
            if (Connection->PreviousQuicVersion == ServerVI.ChosenVersion) {
                QuicTraceLogConnError(
                    ServerVersionInformationPreviousVersionIsChosenVersion,
                    Connection,
                    "Previous Client Version is Server Chosen Version: 0x%x",
                    Connection->PreviousQuicVersion);
                QuicConnTransportError(Connection, QUIC_ERROR_VERSION_NEGOTIATION_ERROR);
                return QUIC_STATUS_PROTOCOL_ERROR;
            }
            //
            // Ensure the version which generated a VN packet is not in the AvailableVersions.
            //
            if (!QuicIsVersionReserved(Connection->PreviousQuicVersion)) {
                for (uint32_t i = 0; i < ServerVI.AvailableVersionsCount; ++i) {
                    if (Connection->PreviousQuicVersion == ServerVI.AvailableVersions[i]) {
                        QuicTraceLogConnError(
                            ServerVersionInformationPreviousVersionInOtherVerList,
                            Connection,
                            "Previous Client Version in Server Available Versions list: 0x%x",
                            Connection->PreviousQuicVersion);
                        QuicConnTransportError(Connection, QUIC_ERROR_VERSION_NEGOTIATION_ERROR);
                        return QUIC_STATUS_PROTOCOL_ERROR;
                    }
                }
            }
        }
        //
        // If Compatible Version Negotiation was performed, do extra validation
        //
        if (Connection->State.CompatibleVerNegotiationAttempted) {
            if (!QuicVersionNegotiationExtAreVersionsCompatible(
                Connection->OriginalQuicVersion, ServerVI.ChosenVersion)) {
                QuicTraceLogConnError(
                    CompatibleVersionNegotiationNotCompatible,
                    Connection,
                    "Compatible Version negotiation not compatible with client: original 0x%x, upgrade: 0x%x",
                    Connection->OriginalQuicVersion,
                    ServerVI.ChosenVersion);
                QuicConnTransportError(Connection, QUIC_ERROR_VERSION_NEGOTIATION_ERROR);
                return QUIC_STATUS_PROTOCOL_ERROR;
            }
            if (!OriginalVersionFound) {
                QuicTraceLogConnError(
                    CompatibleVersionNegotiationOriginalVersionNotFound,
                    Connection,
                    "OriginalVersion not found in server's TP: original 0x%x, upgrade: 0x%x",
                    Connection->OriginalQuicVersion,
                    ServerVI.ChosenVersion);
                QuicConnTransportError(Connection, QUIC_ERROR_VERSION_NEGOTIATION_ERROR);
                return QUIC_STATUS_PROTOCOL_ERROR;
            }
            Connection->State.CompatibleVerNegotiationCompleted = TRUE;
            QuicTraceLogConnVerbose(
                CompatibleVersionUpgradeComplete,
                Connection,
                "Compatible version upgrade! Old: 0x%x, New: 0x%x",
                Connection->OriginalQuicVersion,
                Connection->Stats.QuicVersion);
        }
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnProcessPeerTransportParameters(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN FromResumptionTicket
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QuicTraceLogConnInfo(
        PeerTPSet,
        Connection,
        "Peer Transport Parameters Set");
    Connection->State.PeerTransportParameterValid = TRUE;

    //
    // QMux connections run over TCP and never create PathIDs, so there is no
    // PathID set to initialize.
    //
    if (!QuicConnIsQMux(Connection)) {
        if ((Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_INITIAL_MAX_PATH_ID)) {
            QuicPathIDSetInitializeTransportParameters(&Connection->PathIDs,
                (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT) ?
                    (uint8_t)Connection->PeerTransportParams.ActiveConnectionIdLimit :
                    QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_DEFAULT,
                (uint32_t)Connection->PeerTransportParams.InitialMaxPathId);
        } else {
            QuicPathIDSetInitializeTransportParameters(&Connection->PathIDs,
                (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_ACTIVE_CONNECTION_ID_LIMIT) ?
                    (uint8_t)Connection->PeerTransportParams.ActiveConnectionIdLimit :
                    QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT_DEFAULT,
                UINT32_MAX);
        }
    }

    if (QuicConnPeerWantsObservedAddressReports(Connection)) {
        Connection->State.ObservedAddressNegotiated = TRUE;
        QuicSendSetSendFlag(
            &Connection->Send,
            QUIC_CONN_SEND_FLAG_OBSERVED_ADDRESS);
    }

    if (!FromResumptionTicket) {
        if (Connection->Settings.VersionNegotiationExtEnabled &&
            Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_VERSION_NEGOTIATION) {
            Status = QuicConnProcessPeerVersionNegotiationTP(Connection);
            if (QUIC_FAILED(Status)) {
                //
                // If the Version Info failed to parse, indicate the failure up the stack to perform
                // Incompatible Version Negotiation or so the connection can be closed.
                //
                goto Error;
            }
        }
        if (QuicConnIsClient(Connection) &&
            (Connection->State.CompatibleVerNegotiationAttempted || Connection->PreviousQuicVersion != 0) &&
            !(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_VERSION_NEGOTIATION)) {
            //
            // Client responded to a version negotiation packet, or compatible version negotiation,
            // but server didn't send Version Info TP. Kill the connection.
            //
            QuicConnTransportError(Connection, QUIC_ERROR_VERSION_NEGOTIATION_ERROR);
            Status = QUIC_STATUS_PROTOCOL_ERROR;
            goto Error;
        }

        if (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_STATELESS_RESET_TOKEN) {
            CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&Connection->Paths[0].PathID->DestCids));
            CXPLAT_DBG_ASSERT(QuicConnIsClient(Connection));
            QUIC_CID_LIST_ENTRY* DestCid =
                CXPLAT_CONTAINING_RECORD(
                    Connection->Paths[0].PathID->DestCids.Flink,
                    QUIC_CID_LIST_ENTRY,
                    Link);
            CxPlatCopyMemory(
                DestCid->ResetToken,
                Connection->PeerTransportParams.StatelessResetToken,
                QUIC_STATELESS_RESET_TOKEN_LENGTH);
            DestCid->CID.HasResetToken = TRUE;
        }

        if (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_PREFERRED_ADDRESS) {
            /*QuicTraceLogConnInfo(
                PeerPreferredAddress,
                Connection,
                "Peer configured preferred address %!ADDR!",
                CASTED_CLOG_BYTEARRAY(sizeof(Connection->PeerTransportParams.PreferredAddress), &Connection->PeerTransportParams.PreferredAddress));*/

            //
            // TODO - Implement preferred address feature.
            //
        }

        if (Connection->Settings.GreaseQuicBitEnabled &&
            (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_GREASE_QUIC_BIT) > 0) {
            //
            // Endpoints that receive the grease_quic_bit transport parameter from
            // a peer SHOULD set the QUIC Bit to an unpredictable value extension
            // assigns specific meaning to the value of the bit.
            //
            uint8_t RandomValue;
            (void) CxPlatRandom(sizeof(RandomValue), &RandomValue);
            Connection->State.FixedBit = (RandomValue % 2);
            Connection->Stats.GreaseBitNegotiated = TRUE;
        }

        if (Connection->Settings.ReliableResetEnabled) {
            Connection->State.ReliableResetStreamNegotiated =
                !!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_RELIABLE_RESET_ENABLED);

            //
            // Send event to app to indicate result of negotiation if app cares.
            //
            QUIC_CONNECTION_EVENT Event;
            Event.Type = QUIC_CONNECTION_EVENT_RELIABLE_RESET_NEGOTIATED;
            Event.RELIABLE_RESET_NEGOTIATED.IsNegotiated = Connection->State.ReliableResetStreamNegotiated;

            QuicTraceLogConnVerbose(
                IndicateReliableResetNegotiated,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_RELIABLE_RESET_NEGOTIATED [IsNegotiated=%hhu]",
                Event.RELIABLE_RESET_NEGOTIATED.IsNegotiated);
            QuicConnIndicateEvent(Connection, &Event);
        }

        if (Connection->Settings.OneWayDelayEnabled) {
            Connection->State.TimestampSendNegotiated = // Peer wants to recv, so we can send
                !!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED);
            Connection->State.TimestampRecvNegotiated = // Peer wants to send, so we can recv
                !!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED);

            //
            // Send event to app to indicate result of negotiation if app cares.
            //
            QUIC_CONNECTION_EVENT Event;
            Event.Type = QUIC_CONNECTION_EVENT_ONE_WAY_DELAY_NEGOTIATED;
            Event.ONE_WAY_DELAY_NEGOTIATED.SendNegotiated = Connection->State.TimestampSendNegotiated;
            Event.ONE_WAY_DELAY_NEGOTIATED.ReceiveNegotiated = Connection->State.TimestampRecvNegotiated;

            QuicTraceLogConnVerbose(
                IndicateOneWayDelayNegotiated,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_ONE_WAY_DELAY_NEGOTIATED [Send=%hhu,Recv=%hhu]",
                Event.ONE_WAY_DELAY_NEGOTIATED.SendNegotiated,
                Event.ONE_WAY_DELAY_NEGOTIATED.ReceiveNegotiated);
            QuicConnIndicateEvent(Connection, &Event);
        }

        if (Connection->Settings.ServerMigrationEnabled) {
            Connection->State.ServerMigrationNegotiated =
                !!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_SERVER_MIGRATION);
        }

        //
        // Asymmetric, because the parameter is: a server learns the client
        // wants the extension by receiving it, and a client knows it is in
        // effect because it sent it. The client cannot read this off the
        // peer's parameters -- a server is forbidden to echo it -- so it is
        // taken from the same condition that decided to send it.
        //
        if (QuicConnIsServer(Connection)) {
            Connection->State.AlternativeAddressNegotiated =
                !!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_ALTERNATIVE_ADDRESS);
        } else {
            Connection->State.AlternativeAddressNegotiated =
                !Connection->Settings.ServerMigrationEnabled;
        }

        //
        // Symmetric, because the parameter is: both endpoints send it, so both
        // can read the peer's. The local half is the same condition that
        // decided to send it -- a server always does, a client does when it
        // offered alternative_address, which is what
        // AlternativeAddressNegotiated records for a client.
        //
        Connection->State.StatelessPunchNegotiated =
            !!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_STATELESS_PUNCH) &&
            (QuicConnIsServer(Connection) ||
             Connection->State.AlternativeAddressNegotiated);

        if (Connection->Settings.MultipathEnabled) {
            Connection->State.MultipathNegotiated =
                !!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_INITIAL_MAX_PATH_ID);
        }

        //
        // Fully validate all exchanged connection IDs.
        //
        if (!QuicConnIsQMux(Connection) &&
            !QuicConnValidateTransportParameterCIDs(Connection)) {
            goto Error;
        }

        if (QuicConnIsClient(Connection) &&
            !QuicConnPostAcceptValidatePeerTransportParameters(Connection)) {
            goto Error;
        }
    }

    Connection->Send.PeerMaxData =
        Connection->PeerTransportParams.InitialMaxData;

    QuicStreamSetInitializeTransportParameters(
        &Connection->Streams,
        Connection->PeerTransportParams.InitialMaxBidiStreams,
        Connection->PeerTransportParams.InitialMaxUniStreams,
        !FromResumptionTicket);

    QuicDatagramOnSendStateChanged(&Connection->Datagram);

    if (Connection->State.Started) {
        if (Connection->State.Disable1RttEncrytion &&
            Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_DISABLE_1RTT_ENCRYPTION) {
            QuicTraceLogConnInfo(
                NegotiatedDisable1RttEncryption,
                Connection,
                "Negotiated Disable 1-RTT Encryption");
        } else {
            Connection->State.Disable1RttEncrytion = FALSE;
        }
    }

    return QUIC_STATUS_SUCCESS;

Error:
    //
    // Errors from Version Negotiation Extension parsing are treated differently
    // so Incompatible Version Negotiation can be done.
    //
    if (Status == QUIC_STATUS_SUCCESS) {
        QuicConnTransportError(Connection, QUIC_ERROR_TRANSPORT_PARAMETER_ERROR);
        Status = QUIC_STATUS_PROTOCOL_ERROR;
    }
    return Status;
}

//
// Called after the configuration has been set. This happens immediately on the
// client side, but not until after the listener accepted on the server side.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnPostAcceptValidatePeerTransportParameters(
    _In_ QUIC_CONNECTION* Connection
    )
{
    //
    // CIBIR encoding transport parameter validation.
    //
    if (Connection->CibirId[0] != 0) {
        if (!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_CIBIR_ENCODING)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Peer isn't using CIBIR but we are");
            return FALSE;
        }
        if (Connection->PeerTransportParams.CibirLength != Connection->CibirId[0]) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Peer isn't using a matching CIBIR length");
            return FALSE;
        }
        if (Connection->PeerTransportParams.CibirOffset != Connection->CibirId[1]) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Peer isn't using a matching CIBIR offset");
            return FALSE;
        }
    } else { // CIBIR not in use
        if (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_CIBIR_ENCODING) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Peer is using CIBIR but we aren't");
            return FALSE;
        }
    }

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnPeerCertReceived(
    _In_ QUIC_CONNECTION* Connection,
    _In_opt_ QUIC_CERTIFICATE* Certificate,
    _In_opt_ QUIC_CERTIFICATE_CHAIN* Chain,
    _In_ uint32_t DeferredErrorFlags,
    _In_ QUIC_STATUS DeferredStatus
    )
{
    QUIC_CONNECTION_EVENT Event;
    Connection->Crypto.CertValidationPending = TRUE;
    Event.Type = QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED;
    Event.PEER_CERTIFICATE_RECEIVED.Certificate = Certificate;
    Event.PEER_CERTIFICATE_RECEIVED.Chain = Chain;
    Event.PEER_CERTIFICATE_RECEIVED.DeferredErrorFlags = DeferredErrorFlags;
    Event.PEER_CERTIFICATE_RECEIVED.DeferredStatus = DeferredStatus;
    QuicTraceLogConnVerbose(
        IndicatePeerCertificateReceived,
        Connection,
        "Indicating QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED (0x%x, 0x%x)",
        DeferredErrorFlags,
        DeferredStatus);
    QUIC_STATUS Status = QuicConnIndicateEvent(Connection, &Event);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            ConnError,
            "[conn][%p] ERROR, %s.",
            Connection,
            "Custom cert validation failed.");
        Connection->Crypto.CertValidationPending = FALSE;
        return FALSE;
    }
    if (Status == QUIC_STATUS_PENDING) {
        //
        // Don't set pending here because validation may have completed in the callback.
        //
        QuicTraceLogConnInfo(
            CustomCertValidationPending,
            Connection,
            "Custom cert validation is pending");
    } else if (Status == QUIC_STATUS_SUCCESS) {
        Connection->Crypto.CertValidationPending = FALSE;
    }
    return TRUE; // Treat pending as success to the TLS layer.
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueRecvPackets(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_RX_PACKET* Packets,
    _In_ uint32_t PacketChainLength,
    _In_ uint32_t PacketChainByteLength
    )
{
    QUIC_RX_PACKET** PacketsTail = (QUIC_RX_PACKET**)&Packets->Next;
    uint32_t PathId = Packets->PathId;
    Packets->QueuedOnConnection = TRUE;
    Packets->AssignedToConnection = TRUE;
    while (*PacketsTail != NULL) {
        (*PacketsTail)->QueuedOnConnection = TRUE;
        (*PacketsTail)->AssignedToConnection = TRUE;
        (*PacketsTail)->PathId = PathId;
        PacketsTail = (QUIC_RX_PACKET**)&((*PacketsTail)->Next);
    }

    //
    // Base the limit of queued packets on the connection-wide flow control, but
    // allow at least a few packets even if the app configured an extremely
    // tiny FC window.
    //
    const uint32_t QueueLimit =
        CXPLAT_MAX(10, Connection->Settings.ConnFlowControlWindow >> 10);

    QuicTraceLogConnVerbose(
        QueueDatagrams,
        Connection,
        "Queuing %u UDP datagrams",
        PacketChainLength);

    BOOLEAN QueueOperation;
    CxPlatDispatchLockAcquire(&Connection->ReceiveQueueLock);
    if (Connection->ReceiveQueueCount >= QueueLimit) {
        QueueOperation = FALSE;
    } else {
        *Connection->ReceiveQueueTail = Packets;
        Connection->ReceiveQueueTail = PacketsTail;
        Packets = NULL;
        QueueOperation = (Connection->ReceiveQueueCount == 0);
        Connection->ReceiveQueueCount += PacketChainLength;
        Connection->ReceiveQueueByteCount += PacketChainByteLength;
    }
    CxPlatDispatchLockRelease(&Connection->ReceiveQueueLock);

    if (Packets != NULL) {
        QUIC_RX_PACKET* Packet = Packets;
        do {
            Packet->QueuedOnConnection = FALSE;
            QuicPacketLogDrop(Connection, Packet, "Max queue limit reached");
        } while ((Packet = (QUIC_RX_PACKET*)Packet->Next) != NULL);
        CxPlatRecvDataReturn((CXPLAT_RECV_DATA*)Packets);
        return;
    }

    if (QueueOperation) {
        QUIC_OPERATION* ConnOper =
            QuicConnAllocOperation(Connection, QUIC_OPER_TYPE_FLUSH_RECV);
        if (ConnOper != NULL) {
            QuicConnQueueOper(Connection, ConnOper);
        } else {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "Flush Recv operation",
                0);
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnQueueUnreachable(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    if (Connection->Crypto.TlsState.ReadKey > QUIC_PACKET_KEY_INITIAL) {
        //
        // Only queue unreachable events at the beginning of the handshake.
        // Otherwise, it opens up an attack surface.
        //
        QuicTraceLogConnWarning(
            IgnoreUnreachable,
            Connection,
            "Ignoring received unreachable event (inline)");
        return;
    }

    QUIC_OPERATION* ConnOper =
        QuicConnAllocOperation(Connection, QUIC_OPER_TYPE_UNREACHABLE);
    if (ConnOper != NULL) {
        ConnOper->UNREACHABLE.RemoteAddress = *RemoteAddress;
        QuicConnQueueOper(Connection, ConnOper);
    } else {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Unreachable operation",
            0);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(CXPLAT_ROUTE_RESOLUTION_CALLBACK)
void
QuicConnQueueRouteCompletion(
    _Inout_ void* Context,
    _When_(Succeeded == FALSE, _Reserved_)
    _When_(Succeeded == TRUE, _In_reads_bytes_(6))
        const uint8_t* PhysicalAddress,
    _In_ uint8_t PathId,
    _In_ BOOLEAN Succeeded
    )
{
    QUIC_CONNECTION* Connection = (QUIC_CONNECTION*)Context;
    QUIC_OPERATION* ConnOper =
        QuicConnAllocOperation(Connection, QUIC_OPER_TYPE_ROUTE_COMPLETION);
    if (ConnOper != NULL) {
        ConnOper->ROUTE.Succeeded = Succeeded;
        ConnOper->ROUTE.PathId = PathId;
        if (Succeeded) {
            memcpy(ConnOper->ROUTE.PhysicalAddress, PhysicalAddress, sizeof(ConnOper->ROUTE.PhysicalAddress));
        }
        QuicConnQueueOper(Connection, ConnOper);
    } else if (InterlockedCompareExchange16((short*)&Connection->BackUpOperUsed, 1, 0) == 0) {
        QUIC_OPERATION* Oper = &Connection->BackUpOper;
        Oper->FreeAfterProcess = FALSE;
        Oper->Type = QUIC_OPER_TYPE_API_CALL;
        Oper->API_CALL.Context = &Connection->BackupApiContext;
        Oper->API_CALL.Context->Type = QUIC_API_TYPE_CONN_SHUTDOWN;
        Oper->API_CALL.Context->CONN_SHUTDOWN.Flags = QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT;
        Oper->API_CALL.Context->CONN_SHUTDOWN.ErrorCode = QUIC_ERROR_INTERNAL_ERROR;
        Oper->API_CALL.Context->CONN_SHUTDOWN.RegistrationShutdown = FALSE;
        Oper->API_CALL.Context->CONN_SHUTDOWN.TransportShutdown = TRUE;
        QuicConnQueueHighestPriorityOper(Connection, Oper);
    }

    QuicConnRelease(Connection, QUIC_CONN_REF_ROUTE);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRecvVerNeg(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_RX_PACKET* const Packet
    )
{
    uint32_t SupportedVersion = 0;

    //
    // The Version Negotiation packet layout (see QUIC_VERSION_NEGOTIATION_PACKET)
    // places the Source CID immediately after the Destination CID:
    //
    //   ... | DestCidLength (1) | DestCid (DestCidLength) |
    //           SourceCidLength (1) | SourceCid (SourceCidLength) | SupportedVersions...
    //
    const uint8_t VnSourceCidLen =
        Packet->VerNeg->DestCid[Packet->VerNeg->DestCidLength];
    const uint8_t* VnSourceCid =
        Packet->VerNeg->DestCid + Packet->VerNeg->DestCidLength + sizeof(uint8_t);

    //
    // Validate that the packet's Source CID matches our current Destination CID
    //
    const QUIC_CID_LIST_ENTRY* DestCid = Connection->Paths[0].DestCid;
    CXPLAT_DBG_ASSERT(DestCid != NULL);
    if (VnSourceCidLen != DestCid->CID.Length ||
        memcmp(VnSourceCid, DestCid->CID.Data, VnSourceCidLen) != 0) {
        QuicPacketLogDrop(Connection, Packet, "Version Negotiation Source CID doesn't match our Destination CID");
        return;
    }

    const uint32_t* ServerVersionList =
        (const uint32_t*)(VnSourceCid + VnSourceCidLen);
    uint16_t ServerVersionListLength =
        (Packet->AvailBufferLength - (uint16_t)((uint8_t*)ServerVersionList - Packet->AvailBuffer)) / sizeof(uint32_t);

    //
    // Go through the list and make sure it doesn't include our originally
    // requested version. If it does, we are supposed to ignore it. Cache the
    // first supported version.
    //
    QuicTraceLogVerbose(
        PacketRxVersionNegotiation,
        "[C][RX][-] VN");
    for (uint16_t i = 0; i < ServerVersionListLength; i++) {

        uint32_t ServerVersion;
        CxPlatCopyMemory(&ServerVersion, &ServerVersionList[i], sizeof(ServerVersion));

        QuicTraceLogVerbose(
            PacketRxVersionNegVer,
            "[C][RX][-]   Ver[%d]: 0x%x",
            (int32_t)i,
            CxPlatByteSwapUint32(ServerVersion));

        //
        // Check to see if this is the current version.
        //
        if (ServerVersion == Connection->Stats.QuicVersion && !QuicIsVersionReserved(ServerVersion)) {
            QuicPacketLogDrop(Connection, Packet, "Version Negotation that includes the current version");
            return;
        }

        //
        // Check to see if this is supported, if we haven't already found a
        // supported version.
        //
        if (SupportedVersion == 0 &&
            ((QuicConnIsClient(Connection) && QuicVersionNegotiationExtIsVersionClientSupported(Connection, ServerVersion)) ||
            (QuicConnIsServer(Connection) && QuicVersionNegotiationExtIsVersionServerSupported(ServerVersion)))) {
            SupportedVersion = ServerVersion;
        }
    }

    if (SupportedVersion == 0) {
        //
        // No match! Connection failure.
        //
        QuicTraceLogConnError(
            RecvVerNegNoMatch,
            Connection,
            "Version Negotation contained no supported versions");
        QuicConnCloseLocally(
            Connection,
            QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
            (uint64_t)QUIC_STATUS_VER_NEG_ERROR,
            NULL);
        return;
    }

    Connection->PreviousQuicVersion = Connection->Stats.QuicVersion;
    Connection->Stats.QuicVersion = SupportedVersion;
    QuicConnOnQuicVersionSet(Connection);
    QUIC_STATUS Status = QuicCryptoOnVersionChange(&Connection->Crypto);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogConnError(
            RecvVerNegCryptoError,
            Connection,
            "Failed to update crypto on ver neg");
        QuicConnCloseLocally(
            Connection,
            QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
            (uint64_t)Status,
            NULL);
        return;
    }
    QuicConnRestart(Connection, TRUE);
}


_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRecvRetry(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_RX_PACKET* Packet
    )
{
    //
    // Only clients should receive Retry packets.
    //
    if (QuicConnIsServer(Connection)) {
        QuicPacketLogDrop(Connection, Packet, "Retry sent to server");
        return;
    }

    //
    // Make sure we are in the correct state of the handshake.
    //
    if (Connection->State.GotFirstServerResponse) {
        QuicPacketLogDrop(Connection, Packet, "Already received server response");
        return;
    }

    //
    // Make sure the connection is still active
    //
    if (Connection->State.ClosedLocally || Connection->State.ClosedRemotely) {
        QuicPacketLogDrop(Connection, Packet, "Retry while shutting down");
        return;
    }

    //
    // Decode and validate the Retry packet.
    //

    if (Packet->AvailBufferLength - Packet->HeaderLength <= QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1) {
        QuicPacketLogDrop(Connection, Packet, "No room for Retry Token");
        return;
    }

    if (!QuicVersionNegotiationExtIsVersionClientSupported(Connection, Packet->LH->Version)) {
        QuicPacketLogDrop(Connection, Packet, "Retry Version not supported by client");
        return;
    }

    const QUIC_VERSION_INFO* VersionInfo = NULL;
    for (uint32_t i = 0; i < ARRAYSIZE(QuicSupportedVersionList); ++i) {
        if (QuicSupportedVersionList[i].Number == Packet->LH->Version) {
            VersionInfo = &QuicSupportedVersionList[i];
            break;
        }
    }
    CXPLAT_FRE_ASSERT(VersionInfo != NULL);

    const uint8_t* Token = (Packet->AvailBuffer + Packet->HeaderLength);
    uint16_t TokenLength = Packet->AvailBufferLength - (Packet->HeaderLength + QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1);

    QuicPacketLogHeader(
        Connection,
        TRUE,
        0,
        0,
        Packet->AvailBufferLength,
        Packet->AvailBuffer,
        0);

    CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&Connection->Paths[0].PathID->DestCids));
    const QUIC_CID_LIST_ENTRY* DestCid =
        CXPLAT_CONTAINING_RECORD(
            Connection->Paths[0].PathID->DestCids.Flink,
            QUIC_CID_LIST_ENTRY,
            Link);

    uint8_t CalculatedIntegrityValue[QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1];

    if (QUIC_FAILED(
        QuicPacketGenerateRetryIntegrity(
            VersionInfo,
            DestCid->CID.Length,
            DestCid->CID.Data,
            Packet->AvailBufferLength - QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1,
            Packet->AvailBuffer,
            CalculatedIntegrityValue))) {
        QuicPacketLogDrop(Connection, Packet, "Failed to generate integrity field");
        return;
    }

    if (memcmp(
            CalculatedIntegrityValue,
            Packet->AvailBuffer + (Packet->AvailBufferLength - QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1),
            QUIC_RETRY_INTEGRITY_TAG_LENGTH_V1) != 0) {
        QuicPacketLogDrop(Connection, Packet, "Invalid integrity field");
        return;
    }

    //
    // Cache the Retry token.
    //

    Connection->Send.InitialToken = CXPLAT_ALLOC_PAGED(TokenLength, QUIC_POOL_INITIAL_TOKEN);
    if (Connection->Send.InitialToken == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "InitialToken",
            TokenLength);
        QuicPacketLogDrop(Connection, Packet, "InitialToken alloc failed");
        return;
    }

    Connection->Send.InitialTokenLength = TokenLength;
    memcpy((uint8_t*)Connection->Send.InitialToken, Token, TokenLength);

    //
    // Update the (destination) server's CID.
    //
    if (!QuicPathIDUpdateDestCid(Connection->Paths[0].PathID, Packet)) {
        return;
    }

    Connection->State.GotFirstServerResponse = TRUE;
    Connection->State.HandshakeUsedRetryPacket = TRUE;

    //
    // Update the Initial packet's key based on the new CID.
    //
    QuicPacketKeyFree(Connection->Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_INITIAL]);
    QuicPacketKeyFree(Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_INITIAL]);
    Connection->Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_INITIAL] = NULL;
    Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_INITIAL] = NULL;

    CXPLAT_DBG_ASSERT(!CxPlatListIsEmpty(&Connection->Paths[0].PathID->DestCids));
    DestCid =
        CXPLAT_CONTAINING_RECORD(
            Connection->Paths[0].PathID->DestCids.Flink,
            QUIC_CID_LIST_ENTRY,
            Link);

    QUIC_STATUS Status;
    if (QUIC_FAILED(
        Status =
        QuicPacketKeyCreateInitial(
            QuicConnIsServer(Connection),
            &VersionInfo->HkdfLabels,
            VersionInfo->Salt,
            DestCid->CID.Length,
            DestCid->CID.Data,
            &Connection->Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_INITIAL],
            &Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_INITIAL]))) {
        QuicConnFatalError(Connection, Status, "Failed to create initial keys");
        return;
    }

    Connection->Stats.StatelessRetry = TRUE;

    //
    // Restart the connection, using the new CID and Retry Token.
    //
    QuicConnRestart(Connection, FALSE);

    Packet->CompletelyValid = TRUE;
}

//
// Tries to get the requested decryption key or defers the packet for later
// processing.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnGetKeyOrDeferDatagram(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_RX_PACKET* Packet
    )
{
    if (Packet->KeyType > Connection->Crypto.TlsState.ReadKey) {

        //
        // We don't have the necessary key yet so try to defer the packet until
        // we get the key.
        //

        if (Packet->KeyType == QUIC_PACKET_KEY_0_RTT &&
            Connection->Crypto.TlsState.EarlyDataState != CXPLAT_TLS_EARLY_DATA_UNKNOWN) {
            //
            // We don't have the 0-RTT key, but we aren't in an unknown
            // "early data" state, so it must be rejected/unsupported. Just drop
            // the packets.
            //
            CXPLAT_DBG_ASSERT(Connection->Crypto.TlsState.EarlyDataState != CXPLAT_TLS_EARLY_DATA_ACCEPTED);
            QuicPacketLogDrop(Connection, Packet, "0-RTT not currently accepted");

        } else {
            QUIC_ENCRYPT_LEVEL EncryptLevel = QuicKeyTypeToEncryptLevel(Packet->KeyType);
            BOOLEAN FatalError = FALSE;
            QUIC_PATHID* PathID =
                QuicPathIDSetGetPathIDForPeer(
                    &Connection->PathIDs,
                    Packet->PathId,
                    FALSE,
                    &FatalError);
            CXPLAT_DBG_ASSERT(!FatalError && PathID != NULL);
            QUIC_PACKET_SPACE* Packets = PathID->Packets[EncryptLevel];
            CXPLAT_DBG_ASSERT(Packets != NULL);
            if (Packets->DeferredPacketsCount == QUIC_MAX_PENDING_DATAGRAMS) {
                //
                // We already have too many packets queued up. Just drop this
                // one.
                //
                QuicPacketLogDrop(Connection, Packet, "Max deferred packet count reached");

            } else {
                QuicTraceLogConnVerbose(
                    DeferDatagram,
                    Connection,
                    "Deferring datagram (type=%hu)",
                    (uint16_t)Packet->KeyType);

                Packets->DeferredPacketsCount++;
                Packet->ReleaseDeferred = TRUE;

                //
                // Add it to the list of pending packets that are waiting on a
                // key to decrypt with.
                //
                QUIC_RX_PACKET** Tail = &Packets->DeferredPackets;
                while (*Tail != NULL) {
                    Tail = (QUIC_RX_PACKET**)&((*Tail)->Next);
                }
                *Tail = Packet;
                (*Tail)->Next = NULL;
            }
            QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
        }

        return FALSE;
    }

    if (QuicConnIsServer(Connection) && !Connection->State.HandshakeConfirmed &&
        Packet->KeyType == QUIC_PACKET_KEY_1_RTT) {
        //
        // A server MUST NOT process incoming 1-RTT protected packets before the TLS
        // handshake is complete.
        //
        return FALSE;
    }

    _Analysis_assume_(Packet->KeyType >= 0 && Packet->KeyType < QUIC_PACKET_KEY_COUNT);
    if (Connection->Crypto.TlsState.ReadKeys[Packet->KeyType] == NULL) {
        //
        // This key is no longer being accepted. Throw the packet away.
        //
        QuicPacketLogDrop(Connection, Packet, "Key no longer accepted");
        return FALSE;
    }

    return TRUE;
}

//
// Validates a received packet's header. Returns TRUE if the packet should be
// processed further.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return != FALSE)
BOOLEAN
QuicConnRecvHeader(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_RX_PACKET* Packet,
    _Out_writes_all_(16) uint8_t* Cipher
    )
{
    //
    // Check invariants and packet version.
    //

    if (!Packet->ValidatedHeaderInv) {
        CXPLAT_DBG_ASSERT(Packet->DestCid != NULL); // This should only hit for coalesced packets.
        if (!QuicPacketValidateInvariant(Connection, Packet, Connection->State.ShareBinding)) {
            return FALSE;
        }
    }

    if (!Packet->IsShortHeader) {
        if (Packet->Invariant->LONG_HDR.Version != Connection->Stats.QuicVersion) {
            if (QuicConnIsClient(Connection) &&
                !Connection->State.CompatibleVerNegotiationAttempted &&
                QuicVersionNegotiationExtIsVersionCompatible(Connection, Packet->Invariant->LONG_HDR.Version)) {
                //
                // Server did compatible version negotiation, update local version
                // to proceed to TP processing. The TP processing must validate
                // this new version is the same as in the ChosenVersion field.
                //
                Connection->OriginalQuicVersion = Connection->Stats.QuicVersion;
                Connection->State.CompatibleVerNegotiationAttempted = TRUE;
                Connection->Stats.QuicVersion = Packet->Invariant->LONG_HDR.Version;
                QuicConnOnQuicVersionSet(Connection);
                if (QUIC_FAILED(QuicCryptoOnVersionChange(&Connection->Crypto))) {
                    return FALSE;
                }
                //
                // Do not return FALSE here, continue with the connection.
                //
            } else if (QuicConnIsClient(Connection) &&
                Packet->Invariant->LONG_HDR.Version == QUIC_VERSION_VER_NEG &&
                !Connection->Stats.VersionNegotiation) {
                //
                // Version negotiation packet received.
                //
                Connection->Stats.VersionNegotiation = TRUE;
                QuicConnRecvVerNeg(Connection, Packet);

                return FALSE;
            } else {
                QuicPacketLogDropWithValue(Connection, Packet, "Invalid version", CxPlatByteSwapUint32(Packet->Invariant->LONG_HDR.Version));
                return FALSE;
            }
        }
    } else {
        if (!QuicIsVersionSupported(Connection->Stats.QuicVersion)) {
            QuicPacketLogDrop(Connection, Packet, "SH packet during version negotiation");
            return FALSE;
        }
    }

    CXPLAT_FRE_ASSERT(QuicIsVersionSupported(Connection->Stats.QuicVersion));

    //
    // Begin non-version-independent logic. When future versions are supported,
    // there may be some switches based on packet version.
    //

    if (!Packet->IsShortHeader) {
#if DEBUG
        if (Connection->State.ShareBinding) {
            CXPLAT_DBG_ASSERT(Packet->DestCidLen >= QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH);
        } else {
            CXPLAT_DBG_ASSERT(Packet->DestCidLen == 0);
        }
#endif

        if ((Packet->LH->Version != QUIC_VERSION_2 && Packet->LH->Type == QUIC_RETRY_V1) ||
            (Packet->LH->Version == QUIC_VERSION_2 && Packet->LH->Type == QUIC_RETRY_V2)) {
            QuicConnRecvRetry(Connection, Packet);
            return FALSE;
        }

        const uint8_t* TokenBuffer = NULL;
        uint16_t TokenLength = 0;

        if (!Packet->ValidatedHeaderVer &&
            !QuicPacketValidateLongHeaderV1(
                Connection,
                QuicConnIsServer(Connection),
                Packet,
                &TokenBuffer,
                &TokenLength,
                Connection->Settings.GreaseQuicBitEnabled)) {
            return FALSE;
        }

        QUIC_PATH* Path = &Connection->Paths[0];
        if (!Path->IsPeerValidated && (Packet->ValidToken || TokenLength != 0)) {

            BOOLEAN InvalidRetryToken = FALSE;
            if (Packet->ValidToken) {
                CXPLAT_DBG_ASSERT(TokenBuffer == NULL);
                CXPLAT_DBG_ASSERT(TokenLength == 0);
                QuicPacketDecodeRetryTokenV1(Packet, &TokenBuffer, &TokenLength);
            } else {
                CXPLAT_DBG_ASSERT(TokenBuffer != NULL);
                if (!QuicPacketValidateInitialToken(
                        Connection,
                        Packet,
                        TokenLength,
                        TokenBuffer,
                        &InvalidRetryToken) &&
                    InvalidRetryToken) {
                    return FALSE;
                }
            }

            if (!InvalidRetryToken) {
                CXPLAT_DBG_ASSERT(TokenBuffer != NULL);
                CXPLAT_DBG_ASSERT(TokenLength == sizeof(QUIC_TOKEN_CONTENTS));

                QUIC_TOKEN_CONTENTS Token;
                if (!QuicRetryTokenDecrypt(Packet, TokenBuffer, &Token)) {
                    CXPLAT_DBG_ASSERT(FALSE); // Was already decrypted sucessfully once.
                    QuicPacketLogDrop(Connection, Packet, "Retry token decrypt failure");
                    return FALSE;
                }

                CXPLAT_DBG_ASSERT(Token.Encrypted.OrigConnIdLength <= sizeof(Token.Encrypted.OrigConnId));
                CXPLAT_DBG_ASSERT(QuicAddrCompare(&Path->Route.RemoteAddress, &Token.Encrypted.RemoteAddress));

                if (Connection->OrigDestCID != NULL) {
                    CXPLAT_FREE(Connection->OrigDestCID, QUIC_POOL_CID);
                }

                Connection->OrigDestCID =
                    CXPLAT_ALLOC_NONPAGED(
                        sizeof(QUIC_CID) +
                        Token.Encrypted.OrigConnIdLength,
                        QUIC_POOL_CID);
                if (Connection->OrigDestCID == NULL) {
                    QuicTraceEvent(
                        AllocFailure,
                        "Allocation of '%s' failed. (%llu bytes)",
                        "OrigDestCID",
                        sizeof(QUIC_CID) + Token.Encrypted.OrigConnIdLength);
                    QuicPacketLogDrop(Connection, Packet, "OrigDestCID from Retry OOM");
                    return FALSE;
                }

                Connection->OrigDestCID->Length = Token.Encrypted.OrigConnIdLength;
                CxPlatCopyMemory(
                    Connection->OrigDestCID->Data,
                    Token.Encrypted.OrigConnId,
                    Token.Encrypted.OrigConnIdLength);
                Connection->State.HandshakeUsedRetryPacket = TRUE;

                QuicPathSetValid(Connection, Path, QUIC_PATH_VALID_INITIAL_TOKEN);
            }
        }

        if (Connection->OrigDestCID == NULL) {

            Connection->OrigDestCID =
                CXPLAT_ALLOC_NONPAGED(
                    sizeof(QUIC_CID) +
                    Packet->DestCidLen,
                    QUIC_POOL_CID);
            if (Connection->OrigDestCID == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "OrigDestCID",
                    sizeof(QUIC_CID) + Packet->DestCidLen);
                QuicPacketLogDrop(Connection, Packet, "OrigDestCID OOM");
                return FALSE;
            }

            Connection->OrigDestCID->Length = Packet->DestCidLen;
            CxPlatCopyMemory(
                Connection->OrigDestCID->Data,
                Packet->DestCid,
                Packet->DestCidLen);
        }

        if (Packet->LH->Version == QUIC_VERSION_2) {
            Packet->KeyType = QuicPacketTypeToKeyTypeV2(Packet->LH->Type);
        } else {
            Packet->KeyType = QuicPacketTypeToKeyTypeV1(Packet->LH->Type);
        }
        Packet->Encrypted = TRUE;

    } else {

        if (!Packet->ValidatedHeaderVer &&
            !QuicPacketValidateShortHeaderV1(Connection, Packet, Connection->Settings.GreaseQuicBitEnabled)) {
            return FALSE;
        }

        Packet->KeyType = QUIC_PACKET_KEY_1_RTT;
        Packet->Encrypted =
            !Connection->State.Disable1RttEncrytion &&
            !Connection->Paths[0].EncryptionOffloading;
    }

    if (Packet->Encrypted &&
        Connection->State.HeaderProtectionEnabled &&
        Packet->PayloadLength < 4 + CXPLAT_HP_SAMPLE_LENGTH) {
        QuicPacketLogDrop(Connection, Packet, "Too short for HP");
        return FALSE;
    }

    //
    // If the key is not present then we will attempt to queue the packet
    // and defer processing for later.
    //
    // For compound packets, we defer processing the rest of the UDP packet
    // once we reach a QUIC packet we can't decrypt.
    //
    if (!QuicConnGetKeyOrDeferDatagram(Connection, Packet)) {
        return FALSE;
    }

    //
    // To decrypt the header, the payload after the header is used as the IV. We
    // don't actually know the length of the packet number so we assume maximum
    // (per spec) and start sampling 4 bytes after the start of the packet number.
    //
    if (Packet->Encrypted && Connection->State.HeaderProtectionEnabled) {
        CxPlatCopyMemory(
            Cipher,
            Packet->AvailBuffer + Packet->HeaderLength + 4,
            CXPLAT_HP_SAMPLE_LENGTH);
    } else {
        //
        // For unencrypted short header packets, no header protection mask will be computed,
        // so avoid reading an HP sample that may extend beyond the packet.
        //
        CxPlatZeroMemory(Cipher, CXPLAT_HP_SAMPLE_LENGTH);
    }

    return TRUE;
}

//
// Decodes and decompresses the packet number. If necessary, updates the key
// phase accordingly, to allow for decryption as the next step. Returns TRUE if
// the packet should continue to be processed further.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnRecvPrepareDecrypt(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_RX_PACKET* Packet,
    _In_reads_(16) const uint8_t* HpMask
    )
{
    CXPLAT_DBG_ASSERT(Packet->ValidatedHeaderInv);
    CXPLAT_DBG_ASSERT(Packet->ValidatedHeaderVer);
    CXPLAT_DBG_ASSERT(Packet->HeaderLength <= Packet->AvailBufferLength);
    CXPLAT_DBG_ASSERT(Packet->PayloadLength <= Packet->AvailBufferLength);
    CXPLAT_DBG_ASSERT(Packet->HeaderLength + Packet->PayloadLength <= Packet->AvailBufferLength);

    //
    // Packet->HeaderLength currently points to the start of the encrypted
    // packet number and Packet->PayloadLength includes the length of the rest
    // of the packet from that point on.
    //

    //
    // Decrypt the first byte of the header to get the packet number length.
    //
    uint8_t CompressedPacketNumberLength = 0;
    if (Packet->IsShortHeader) {
        ((uint8_t*)Packet->AvailBuffer)[0] ^= HpMask[0] & 0x1f; // Only the first 5 bits
        CompressedPacketNumberLength = Packet->SH->PnLength + 1;
    } else {
        ((uint8_t*)Packet->AvailBuffer)[0] ^= HpMask[0] & 0x0f; // Only the first 4 bits
        CompressedPacketNumberLength = Packet->LH->PnLength + 1;
    }

    CXPLAT_DBG_ASSERT(CompressedPacketNumberLength >= 1 && CompressedPacketNumberLength <= 4);
    CXPLAT_DBG_ASSERT(Packet->HeaderLength + CompressedPacketNumberLength <= Packet->AvailBufferLength);

    //
    // Decrypt the packet number now that we have the length.
    //
    for (uint8_t i = 0; i < CompressedPacketNumberLength; i++) {
        ((uint8_t*)Packet->AvailBuffer)[Packet->HeaderLength + i] ^= HpMask[1 + i];
    }

    //
    // Decode the packet number into the compressed packet number. The
    // compressed packet number only represents the least significant N bytes of
    // the true packet number.
    //

    uint64_t CompressedPacketNumber = 0;
    QuicPktNumDecode(
        CompressedPacketNumberLength,
        Packet->AvailBuffer + Packet->HeaderLength,
        &CompressedPacketNumber);

    Packet->HeaderLength += CompressedPacketNumberLength;
    Packet->PayloadLength -= CompressedPacketNumberLength;

    //
    // Decompress the packet number into the full packet number.
    //

    QUIC_ENCRYPT_LEVEL EncryptLevel = QuicKeyTypeToEncryptLevel(Packet->KeyType);

    BOOLEAN FatalError = FALSE;
    QUIC_PATHID* PathID =
        QuicPathIDSetGetPathIDForPeer(
            &Connection->PathIDs,
            Packet->PathId,
            FALSE,
            &FatalError);
    CXPLAT_DBG_ASSERT(!FatalError);
    if (PathID == NULL) {
        QuicPacketLogDrop(Connection, Packet, "No PathID");
        return FALSE;
    }
    CXPLAT_DBG_ASSERT(PathID->Packets[EncryptLevel] != NULL);

    Packet->PacketNumber =
        QuicPktNumDecompress(
            PathID->Packets[EncryptLevel]->NextRecvPacketNumber,
            CompressedPacketNumber,
            CompressedPacketNumberLength);
    Packet->PacketNumberSet = TRUE;

    if (Packet->PacketNumber > QUIC_VAR_INT_MAX) {
        QuicPacketLogDrop(Connection, Packet, "Packet number too big");
        return FALSE;
    }

    CXPLAT_DBG_ASSERT(Packet->IsShortHeader ||
        ((Packet->LH->Version != QUIC_VERSION_2 && Packet->LH->Type != QUIC_RETRY_V1) ||
        (Packet->LH->Version == QUIC_VERSION_2 && Packet->LH->Type != QUIC_RETRY_V2)));

    //
    // Ensure minimum encrypted payload length.
    //
    if (Packet->Encrypted &&
        Packet->PayloadLength < CXPLAT_ENCRYPTION_OVERHEAD) {
        QuicPacketLogDrop(Connection, Packet, "Payload length less than encryption tag");
        return FALSE;
    }

    QUIC_PACKET_SPACE* PacketSpace = PathID->Packets[QUIC_ENCRYPT_LEVEL_1_RTT];
    if (Packet->IsShortHeader && EncryptLevel == QUIC_ENCRYPT_LEVEL_1_RTT &&
        Packet->SH->KeyPhase != PacketSpace->CurrentKeyPhase) {
        if (Packet->PacketNumber < PacketSpace->ReadKeyPhaseStartPacketNumber) {
            //
            // The packet doesn't match our current key phase and the packet number
            // is less than the start of the current key phase, so this is likely
            // using the old keys.
            //
            QuicTraceLogConnVerbose(
                DecryptOldKey,
                Connection,
                "Using old key to decrypt");
            CXPLAT_DBG_ASSERT(Connection->Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_1_RTT_OLD] != NULL);
            CXPLAT_DBG_ASSERT(Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT_OLD] != NULL);
            Packet->KeyType = QUIC_PACKET_KEY_1_RTT_OLD;
        } else {
            //
            // The packet doesn't match our key phase, and the packet number is higher
            // than the start of the current key phase, so most likely using a new key phase.
            // Update the keys and try it out. If this fails, the packet was invalid anyway.
            //
            QuicTraceLogConnVerbose(
                PossiblePeerKeyUpdate,
                Connection,
                "Possible peer initiated key update [packet %llu]",
                Packet->PacketNumber);

            QUIC_STATUS Status = QuicCryptoGenerateNewKeys(Connection);
            if (QUIC_FAILED(Status)) {
                QuicPacketLogDrop(Connection, Packet, "Generate new packet keys");
                QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
                return FALSE;
            }
            Packet->KeyType = QUIC_PACKET_KEY_1_RTT_NEW;
        }
    }
    QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);

    return TRUE;
}

//
// Decrypts the packet's payload and authenticates the whole packet. On
// successful authentication of the packet, does some final processing of the
// packet header (key and CID updates). Returns TRUE if the packet should
// continue to be processed further.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnRecvDecryptAndAuthenticate(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ QUIC_RX_PACKET* Packet
    )
{
    CXPLAT_DBG_ASSERT(Packet->AvailBufferLength >= Packet->HeaderLength + Packet->PayloadLength);

    const uint8_t* Payload = Packet->AvailBuffer + Packet->HeaderLength;

    //
    // We need to copy the end of the packet before trying decryption, as a
    // failed decryption trashes the stateless reset token.
    //
    BOOLEAN CanCheckForStatelessReset = FALSE;
    uint8_t PacketResetToken[QUIC_STATELESS_RESET_TOKEN_LENGTH];
    if (QuicConnIsClient(Connection) &&
        Packet->IsShortHeader &&
        Packet->HeaderLength + Packet->PayloadLength >= QUIC_MIN_STATELESS_RESET_PACKET_LENGTH) {
        CanCheckForStatelessReset = TRUE;
        CxPlatCopyMemory(
            PacketResetToken,
            Payload + Packet->PayloadLength - QUIC_STATELESS_RESET_TOKEN_LENGTH,
            QUIC_STATELESS_RESET_TOKEN_LENGTH);
    }

    CXPLAT_DBG_ASSERT(Packet->PacketId != 0);

    uint8_t Iv[CXPLAT_MAX_IV_LENGTH];
    if (Packet->PathId == 0) {
        QuicCryptoCombineIvAndPacketNumber(
            Connection->Crypto.TlsState.ReadKeys[Packet->KeyType]->Iv,
            (uint8_t*)&Packet->PacketNumber,
            Iv);
    } else {
        QuicCryptoCombineIvAndPathIDAndPacketNumber(
            Connection->Crypto.TlsState.ReadKeys[Packet->KeyType]->Iv,
            (uint8_t*)&Packet->PathId,
            (uint8_t*)&Packet->PacketNumber,
            Iv);
    }

    //
    // Decrypt the payload with the appropriate key.
    //
    if (Packet->Encrypted) {
        QuicTraceEvent(
            PacketDecrypt,
            "[pack][%llu][%u] Decrypting",
            Packet->PacketId,
            Packet->PathId);
        uint64_t DecryptStart = CxPlatTimeUs64();
        QUIC_STATUS DecryptStatus =
            CxPlatDecrypt(
                Connection->Crypto.TlsState.ReadKeys[Packet->KeyType]->PacketKey,
                Iv,
                Packet->HeaderLength,   // HeaderLength
                Packet->AvailBuffer,    // Header
                Packet->PayloadLength,  // BufferLength
                (uint8_t*)Payload);     // Buffer
        QuicPerfCounterAdd(
            Connection->Partition,
            QUIC_PERF_COUNTER_DECRYPT_DURATION_US,
            (int64_t)CxPlatTimeDiff64(DecryptStart, CxPlatTimeUs64()));
        if (QUIC_FAILED(DecryptStatus)) {

            //
            // Check for a stateless reset packet.
            //
            if (CanCheckForStatelessReset) {
                BOOLEAN Reset = FALSE;

                QUIC_PATHID* PathIDs[QUIC_ACTIVE_PATH_ID_LIMIT];
                uint8_t PathIDCount = QUIC_ACTIVE_PATH_ID_LIMIT;
                QuicPathIDSetGetPathIDs(&Connection->PathIDs, PathIDs, &PathIDCount);

                for (uint8_t i = 0; i < PathIDCount ; i++) {
                    if (!Reset) {
                        for (CXPLAT_LIST_ENTRY* Entry = PathIDs[i]->DestCids.Flink;
                                Entry != &PathIDs[i]->DestCids;
                                Entry = Entry->Flink) {
                            //
                            // Loop through all our stored stateless reset tokens to see if
                            // we have a match.
                            //
                            QUIC_CID_LIST_ENTRY* DestCid =
                                CXPLAT_CONTAINING_RECORD(
                                    Entry,
                                    QUIC_CID_LIST_ENTRY,
                                    Link);
                            if (DestCid->CID.HasResetToken &&
                                !DestCid->CID.Retired &&
                                memcmp(
                                    DestCid->ResetToken,
                                    PacketResetToken,
                                    QUIC_STATELESS_RESET_TOKEN_LENGTH) == 0) {
                                QuicTraceLogVerbose(
                                    PacketRxStatelessReset,
                                    "[S][RX][-] SR %s",
                                    QuicCidBufToStr(PacketResetToken, QUIC_STATELESS_RESET_TOKEN_LENGTH).Buffer);
                                Reset = TRUE;
                                break;
                            }
                        }
                    }
                    QuicPathIDRelease(PathIDs[i], QUIC_PATHID_REF_LOOKUP);
                }

                if (Reset) {
                    QuicTraceLogConnInfo(
                        RecvStatelessReset,
                        Connection,
                        "Received stateless reset");
                    QuicConnCloseLocally(
                        Connection,
                        QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
                        (uint64_t)QUIC_STATUS_ABORTED,
                        NULL);
                    return FALSE;
                }
            }

            if (QuicTraceLogVerboseEnabled()) {
                QuicPacketLogHeader(
                    Connection,
                    TRUE,
                    Connection->State.ShareBinding ? MsQuicLib.CidTotalLength : 0,
                    Packet->PacketNumber,
                    Packet->HeaderLength,
                    Packet->AvailBuffer,
                    Connection->Stats.QuicVersion);
            }
            Path->PathID->Stats.Recv.DecryptionFailures++;
            Connection->Stats.Recv.DecryptionFailures++;
            QuicPacketLogDrop(Connection, Packet, "Decryption failure");
            QuicPerfCounterIncrement(Connection->Partition, QUIC_PERF_COUNTER_PKTS_DECRYPTION_FAIL);
            if (Connection->Stats.Recv.DecryptionFailures >= CXPLAT_AEAD_INTEGRITY_LIMIT) {
                QuicConnTransportError(Connection, QUIC_ERROR_AEAD_LIMIT_REACHED);
            }

            return FALSE;
        }
    }

    Connection->Stats.Recv.ValidPackets++;

    //
    // Validate the header's reserved bits now that the packet has been
    // decrypted.
    //
    if (Packet->IsShortHeader) {
        if (Packet->SH->Reserved != 0) {
            QuicPacketLogDrop(Connection, Packet, "Invalid SH Reserved bits values");
            QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
            return FALSE;
        }
    } else {
        if (Packet->LH->Reserved != 0) {
            QuicPacketLogDrop(Connection, Packet, "Invalid LH Reserved bits values");
            QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
            return FALSE;
        }
    }

    //
    // Account for updated payload length after decryption.
    //
    if (Packet->Encrypted) {
        Packet->PayloadLength -= CXPLAT_ENCRYPTION_OVERHEAD;
    }

    //
    // At this point the packet has been completely decrypted and authenticated.
    // Now all header processing that can only be done on an authenticated
    // packet may continue.
    //

    //
    // Drop any duplicate packet numbers now that we know the packet number is
    // valid.
    //
    QUIC_ENCRYPT_LEVEL EncryptLevel = QuicKeyTypeToEncryptLevel(Packet->KeyType);
    CXPLAT_DBG_ASSERT(Path->PathID != NULL);
    CXPLAT_DBG_ASSERT(Path->PathID->Packets[EncryptLevel] != NULL);
    if (QuicAckTrackerAddPacketNumber(
            &Path->PathID->Packets[EncryptLevel]->AckTracker,
            Packet->PacketNumber)) {

        if (QuicTraceLogVerboseEnabled()) {
            QuicPacketLogHeader(
                Connection,
                TRUE,
                Connection->State.ShareBinding ? MsQuicLib.CidTotalLength : 0,
                Packet->PacketNumber,
                Packet->AvailBufferLength,
                Packet->AvailBuffer,
                Connection->Stats.QuicVersion);
        }
        QuicPacketLogDrop(Connection, Packet, "Duplicate packet number");
        Path->PathID->Stats.Recv.DuplicatePackets++;
        Connection->Stats.Recv.DuplicatePackets++;
        return FALSE;
    }

    //
    // Log the received packet header and payload now that it's decrypted.
    //

    if (QuicTraceLogVerboseEnabled()) {
        QuicPacketLogHeader(
            Connection,
            TRUE,
            Connection->State.ShareBinding ? MsQuicLib.CidTotalLength : 0,
            Packet->PacketNumber,
            Packet->HeaderLength + Packet->PayloadLength,
            Packet->AvailBuffer,
            Connection->Stats.QuicVersion);
        QuicFrameLogAll(
            Connection,
            TRUE,
            Packet->PacketNumber,
            Packet->HeaderLength + Packet->PayloadLength,
            Packet->AvailBuffer,
            Packet->HeaderLength);
    }

    QuicTraceEvent(
        ConnPacketRecv,
        "[conn][%p][RX][%llu] %c (%hu bytes)",
        Connection,
        Packet->PacketNumber,
        Packet->IsShortHeader ? QUIC_TRACE_PACKET_ONE_RTT : (Packet->LH->Type + 1),
        Packet->HeaderLength + Packet->PayloadLength);

    //
    // Process any connection ID updates as necessary.
    //

    if (!Packet->IsShortHeader) {
        BOOLEAN IsVersion2 = (Connection->Stats.QuicVersion == QUIC_VERSION_2);
        if ((!IsVersion2 && Packet->LH->Type == QUIC_INITIAL_V1) ||
            (IsVersion2 && Packet->LH->Type == QUIC_INITIAL_V2)) {
            if (!Connection->State.Connected &&
                QuicConnIsClient(Connection) &&
                !QuicPathIDUpdateDestCid(Path->PathID, Packet)) {
                //
                // Client side needs to respond to the server's new source
                // connection ID that is received in the first Initial packet.
                //
                return FALSE;
            }
        } else if ((!IsVersion2 && Packet->LH->Type == QUIC_0_RTT_PROTECTED_V1) ||
            (IsVersion2 && Packet->LH->Type == QUIC_0_RTT_PROTECTED_V2)) {

            CXPLAT_DBG_ASSERT(QuicConnIsServer(Connection));
            Packet->EncryptedWith0Rtt = TRUE;
        }
    }

    //
    // Update key state if the keys have been updated.
    //

    if (Packet->IsShortHeader) {
        QUIC_PACKET_SPACE* PacketSpace = Path->PathID->Packets[QUIC_ENCRYPT_LEVEL_1_RTT];
        if (Packet->KeyType == QUIC_PACKET_KEY_1_RTT_NEW) {

            QuicCryptoUpdateKeyPhase(Connection, FALSE);
            PacketSpace->ReadKeyPhaseStartPacketNumber = Packet->PacketNumber;

            QuicTraceLogConnVerbose(
                UpdateReadKeyPhase,
                Connection,
                "Updating current read key phase and packet number[%llu]",
                Packet->PacketNumber);

        } else if (Packet->KeyType == QUIC_PACKET_KEY_1_RTT &&
            Packet->SH->KeyPhase == PacketSpace->CurrentKeyPhase &&
            Packet->PacketNumber < PacketSpace->ReadKeyPhaseStartPacketNumber) {
            //
            // This packet is in the current key phase and before the current phase
            // start, so update the packet space start point.
            //
            PacketSpace->ReadKeyPhaseStartPacketNumber = Packet->PacketNumber;
            QuicTraceLogConnVerbose(
                UpdateReadKeyPhase,
                Connection,
                "Updating current read key phase and packet number[%llu]",
                Packet->PacketNumber);
        }
    }

    if (Packet->KeyType == QUIC_PACKET_KEY_HANDSHAKE &&
        QuicConnIsServer(Connection)) {
        //
        // Per spec, server MUST discard Initial keys when it starts
        // decrypting packets using handshake keys.
        //
        QuicCryptoDiscardKeys(&Connection->Crypto, QUIC_PACKET_KEY_INITIAL);
        QuicPathSetValid(Connection, Path, QUIC_PATH_VALID_HANDSHAKE_PACKET);
    }

    return TRUE;
}

//
// Declared here and defined beside QuicConnSendPunchProbe, which the receive
// path reaches the same way: the punch send belongs with the other punch send,
// and the frame handler below is its only caller. The two predicates it
// consults are declared in connection.h instead, because they are the part
// worth unit testing on its own.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
BOOLEAN
QuicConnSendStatelessPunch(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_BOUND_ADDRESS_LIST_ENTRY* Bound,
    _In_ const QUIC_ADDR* ClientAddress,
    _In_ uint16_t RequestPacketLength
    );

//
// Reads the frames in a packet, and if everything is successful marks the
// packet for acknowledgement and returns TRUE.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnRecvFrames(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ QUIC_RX_PACKET* Packet,
    _In_ CXPLAT_ECN_TYPE ECN
    )
{
    BOOLEAN AckEliciting = FALSE;
    BOOLEAN AckImmediately = FALSE;
    BOOLEAN UpdatedFlowControl = FALSE;
    QUIC_ENCRYPT_LEVEL EncryptLevel = QuicKeyTypeToEncryptLevel(Packet->KeyType);
    BOOLEAN Closed = Connection->State.ClosedLocally || Connection->State.ClosedRemotely;

    //
    // draft-kozuka-quic-stateless-punch section 5.1: at most one punch packet
    // in response to a single received packet, whatever the frame count. A
    // per-packet local rather than connection state, because that is exactly
    // the scope the rule is stated in -- and the allowance cannot be banked,
    // since it goes out of scope with the packet.
    //
    BOOLEAN PunchSentForThisPacket = FALSE;

    const BOOLEAN ClosingState = Connection->State.ClosedLocally && !Connection->State.ClosedRemotely;
    const uint8_t* Payload = Packet->AvailBuffer + Packet->HeaderLength;
    uint16_t PayloadLength = Packet->PayloadLength;
    uint64_t RecvTime = CxPlatTimeUs64();

    //
    // In closing state, respond to any packet with a new close frame (rate-limited).
    // Note this excludes the draining state (i.e., ClosedRemotely == TRUE)
    // in which we should be silent.
    //
    if (ClosingState && !Connection->State.ShutdownComplete) {
        if (RecvTime - Connection->LastCloseResponseTimeUs >= QUIC_CLOSING_RESPONSE_MIN_INTERVAL) {
            QuicSendSetSendFlag(
                &Connection->Send,
                Connection->State.AppClosed ?
                    QUIC_CONN_SEND_FLAG_APPLICATION_CLOSE :
                    QUIC_CONN_SEND_FLAG_CONNECTION_CLOSE);
        }
    }

    if (QuicConnIsClient(Connection) &&
        !Connection->State.GotFirstServerResponse) {
        Connection->State.GotFirstServerResponse = TRUE;
    }

    uint16_t Offset = 0;
    while (Offset < PayloadLength) {

        //
        // Read the frame type.
        //
        QUIC_VAR_INT FrameType INIT_NO_SAL(0);
        if (!QuicVarIntDecode(PayloadLength, Payload, &Offset, &FrameType)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Frame type decode failure");
            QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
            return FALSE;
        }

        if (!QUIC_FRAME_IS_KNOWN(FrameType)) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Unknown frame type");
            QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
            return FALSE;
        }

        //
        // Validate allowable frames based on the packet type.
        //
        if (EncryptLevel != QUIC_ENCRYPT_LEVEL_1_RTT) {
            switch (FrameType) {
            //
            // The following frames are allowed pre-1-RTT encryption level:
            //
            case QUIC_FRAME_PADDING:
            case QUIC_FRAME_PING:
            case QUIC_FRAME_ACK:
            case QUIC_FRAME_ACK_1:
            case QUIC_FRAME_CRYPTO:
            case QUIC_FRAME_CONNECTION_CLOSE:
                break;
            //
            // All other frame types are disallowed.
            //
            default:
                QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection,
                    (uint32_t)FrameType,
                    "Disallowed frame type");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

        } else if (Packet->KeyType == QUIC_PACKET_KEY_0_RTT) {
            switch (FrameType) {
            //
            // The following frames are are disallowed in 0-RTT.
            //
            case QUIC_FRAME_ACK:
            case QUIC_FRAME_ACK_1:
            case QUIC_FRAME_HANDSHAKE_DONE:
                QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection,
                    (uint32_t)FrameType,
                    "Disallowed frame type");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            //
            // All other frame types are allowed.
            //
            default:
                break;
            }
        }

        //
        // Process the frame based on the frame type.
        //
        switch (FrameType) {

        case QUIC_FRAME_PADDING: {
            while (Offset < PayloadLength &&
                Payload[Offset] == QUIC_FRAME_PADDING) {
                Offset += sizeof(uint8_t);
            }
            break;
        }

        case QUIC_FRAME_PING: {
            //
            // No other payload. Just need to acknowledge the packet this was
            // contained in.
            //
            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_ACK:
        case QUIC_FRAME_ACK_1:
        case QUIC_FRAME_PATH_ACK:
        case QUIC_FRAME_PATH_ACK_1: {
            BOOLEAN InvalidAckFrame;
            if (!QuicPathIDSetProcessAckFrame(
                    &Connection->PathIDs,
                    Packet,
                    EncryptLevel,
                    FrameType,
                    PayloadLength,
                    Payload,
                    &Offset,
                    &InvalidAckFrame)) {
                if (InvalidAckFrame) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Invalid ACK frame");
                    QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                }
                return FALSE;
            }

            Connection->Stats.Recv.ValidAckFrames++;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_CRYPTO: {
            QUIC_CRYPTO_EX Frame;
            if (!QuicCryptoFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding CRYPTO frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            QUIC_STATUS Status =
                QuicCryptoProcessFrame(
                    &Connection->Crypto,
                    Packet->KeyType,
                    &Frame);
            if (QUIC_SUCCEEDED(Status)) {
                AckEliciting = TRUE;
            } else if (Status == QUIC_STATUS_OUT_OF_MEMORY) {
                QuicPacketLogDrop(Connection, Packet, "Crypto frame process OOM");
                return FALSE;
            } else {
                if (Status == QUIC_STATUS_VER_NEG_ERROR) {
                    if (QuicBindingQueueStatelessOperation(
                            Connection->Paths[0].Binding,
                            QUIC_OPER_TYPE_VERSION_NEGOTIATION,
                            Packet)) {
                        Packet->ReleaseDeferred = TRUE;
                    }
                    QuicConnCloseLocally(
                        Connection,
                        QUIC_CLOSE_INTERNAL_SILENT,
                        QUIC_ERROR_VERSION_NEGOTIATION_ERROR,
                        NULL);
                } else if (Status != QUIC_STATUS_INVALID_STATE) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Invalid CRYPTO frame");
                    QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                }
                return FALSE;
            }

            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_NEW_TOKEN: {
            QUIC_NEW_TOKEN_EX Frame;
            if (!QuicNewTokenFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding NEW_TOKEN frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            //
            // TODO - Save the token for future use.
            //

            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_RESET_STREAM:
        case QUIC_FRAME_STOP_SENDING:
        case QUIC_FRAME_STREAM:
        case QUIC_FRAME_STREAM_1:
        case QUIC_FRAME_STREAM_2:
        case QUIC_FRAME_STREAM_3:
        case QUIC_FRAME_STREAM_4:
        case QUIC_FRAME_STREAM_5:
        case QUIC_FRAME_STREAM_6:
        case QUIC_FRAME_STREAM_7:
        case QUIC_FRAME_MAX_STREAM_DATA:
        case QUIC_FRAME_STREAM_DATA_BLOCKED:
        case QUIC_FRAME_RELIABLE_RESET_STREAM: {
            if (Closed) {
                if (!QuicStreamFrameSkip(
                        FrameType, PayloadLength, Payload, &Offset)) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Skipping closed stream frame");
                    QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                    return FALSE;
                }
                break; // Ignore frame if we are closed.
            }

            uint64_t StreamId;
            if (!QuicStreamFramePeekID(
                    PayloadLength, Payload, Offset, &StreamId)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding stream ID from frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            AckEliciting = TRUE;

            BOOLEAN PeerOriginatedStream =
                QuicConnIsServer(Connection) ?
                    STREAM_ID_IS_CLIENT(StreamId) :
                    STREAM_ID_IS_SERVER(StreamId);

            if (STREAM_ID_IS_UNI_DIR(StreamId)) {
                BOOLEAN IsReceiverSideFrame =
                    FrameType == QUIC_FRAME_MAX_STREAM_DATA ||
                    FrameType == QUIC_FRAME_STOP_SENDING;
                if (PeerOriginatedStream == IsReceiverSideFrame) {
                    //
                    // For locally initiated unidirectional streams, the peer
                    // should only send receiver frame types, and vice versa
                    // for peer initiated unidirectional streams.
                    //
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Invalid frame on unidirectional stream");
                    QuicConnTransportError(Connection, QUIC_ERROR_STREAM_STATE_ERROR);
                    break;
                }
            }

            BOOLEAN FatalError;
            QUIC_STREAM* Stream =
                QuicStreamSetGetStreamForPeer(
                    &Connection->Streams,
                    StreamId,
                    Packet->EncryptedWith0Rtt,
                    PeerOriginatedStream,
                    &FatalError);

            if (Stream) {
                QUIC_STATUS Status =
                    QuicStreamRecv(
                        Stream,
                        Packet,
                        FrameType,
                        PayloadLength,
                        Payload,
                        &Offset,
                        &UpdatedFlowControl);
                QuicStreamRelease(Stream, QUIC_STREAM_REF_LOOKUP);
                if (Status == QUIC_STATUS_OUT_OF_MEMORY) {
                    QuicPacketLogDrop(Connection, Packet, "Stream frame process OOM");
                    return FALSE;
                }

                if (QUIC_FAILED(Status)) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Invalid stream frame");
                    QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                    return FALSE;
                }

            } else if (FatalError) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Getting stream from ID");
                return FALSE;
            } else {
                //
                // Didn't find a matching Stream. Skip the frame as the Stream
                // might have been closed already.
                //
                QuicTraceLogConnWarning(
                    IgnoreFrameAfterClose,
                    Connection,
                    "Ignoring frame (%hhu) for already closed stream id = %llu",
                    (uint8_t)FrameType, // This cast is safe because of the switch cases above.
                    StreamId);
                if (!QuicStreamFrameSkip(
                        FrameType, PayloadLength, Payload, &Offset)) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Skipping ignored stream frame");
                    QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                    return FALSE;
                }
            }

            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_MAX_DATA: {
            QUIC_MAX_DATA_EX Frame;
            if (!QuicMaxDataFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding MAX_DATA frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            if (Connection->Send.PeerMaxData < Frame.MaximumData) {
                Connection->Send.PeerMaxData = Frame.MaximumData;
                //
                // The peer has given us more allowance. Send packets from
                // any previously blocked streams.
                //
                UpdatedFlowControl = TRUE;
                QuicPathIDRemoveOutFlowBlockedReason(
                    Path->PathID, QUIC_FLOW_BLOCKED_CONN_FLOW_CONTROL);
                QuicSendQueueFlush(
                    &Connection->Send, REASON_CONNECTION_FLOW_CONTROL);
            }

            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_MAX_STREAMS:
        case QUIC_FRAME_MAX_STREAMS_1: {
            QUIC_MAX_STREAMS_EX Frame;
            if (!QuicMaxStreamsFrameDecode(FrameType, PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding MAX_STREAMS frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            if (Frame.MaximumStreams > QUIC_TP_MAX_STREAMS_MAX) {
                QuicConnTransportError(Connection, QUIC_ERROR_STREAM_LIMIT_ERROR);
                break;
            }

            QuicStreamSetUpdateMaxStreams(
                &Connection->Streams,
                Frame.BidirectionalStreams,
                Frame.MaximumStreams);

            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_DATA_BLOCKED: {
            QUIC_DATA_BLOCKED_EX Frame;
            if (!QuicDataBlockedFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding BLOCKED frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            //
            // TODO - Should we do anything else with this?
            //
            QuicTraceLogConnVerbose(
                PeerConnFCBlocked,
                Connection,
                "Peer Connection FC blocked (%llu)",
                Frame.DataLimit);
            QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_MAX_DATA);

            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_STREAMS_BLOCKED:
        case QUIC_FRAME_STREAMS_BLOCKED_1: {
            QUIC_STREAMS_BLOCKED_EX Frame;
            if (!QuicStreamsBlockedFrameDecode(FrameType, PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding STREAMS_BLOCKED frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            QuicTraceLogConnVerbose(
                PeerStreamFCBlocked,
                Connection,
                "Peer Streams[%hu] FC blocked (%llu)",
                Frame.BidirectionalStreams,
                Frame.StreamLimit);
            AckEliciting = TRUE;

            uint8_t Type =
                (QuicConnIsServer(Connection) ? // Peer's role, so flip
                STREAM_ID_FLAG_IS_CLIENT : STREAM_ID_FLAG_IS_SERVER)
                |
                (Frame.BidirectionalStreams ?
                 STREAM_ID_FLAG_IS_BI_DIR : STREAM_ID_FLAG_IS_UNI_DIR);

            const QUIC_STREAM_TYPE_INFO* Info = &Connection->Streams.Types[Type];

            if (Info->MaxTotalStreamCount > Frame.StreamLimit) {
                break;
            }

            QUIC_CONNECTION_EVENT Event;
            Event.Type = QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS;
            Event.PEER_NEEDS_STREAMS.Bidirectional = Frame.BidirectionalStreams;
            QuicTraceLogConnVerbose(
                IndicatePeerNeedStreamsV2,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS type: %s",
                Frame.BidirectionalStreams ? "Bidi" : "Unidi"
                );
            (void)QuicConnIndicateEvent(Connection, &Event);

            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_NEW_CONNECTION_ID:
        case QUIC_FRAME_PATH_NEW_CONNECTION_ID: {
            QUIC_NEW_CONNECTION_ID_EX Frame;
            if (!QuicNewConnectionIDFrameDecode(FrameType, PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding NEW_CONNECTION_ID frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            BOOLEAN FatalError = FALSE;
            QUIC_PATHID *PathID = NULL;
            PathID = QuicPathIDSetGetPathIDForPeer(
                &Connection->PathIDs,
                Frame.PathID,
                TRUE,
                &FatalError);
            if (PathID == NULL) {
                return FALSE;
            }

            BOOLEAN ReplaceRetiredCids = FALSE;
            if (PathID->RetirePriorTo < Frame.RetirePriorTo) {
                PathID->RetirePriorTo = Frame.RetirePriorTo;
                ReplaceRetiredCids = QuicPathIDOnRetirePriorToUpdated(PathID);
            }

            if (QuicPathIDGetDestCidFromSeq(PathID, Frame.Sequence, FALSE) == NULL) {
                //
                // Create the new destination connection ID.
                //
                QUIC_CID_LIST_ENTRY* DestCid =
                    QuicCidNewDestination(Frame.Length, Frame.Buffer);
                if (DestCid == NULL) {
                    QuicTraceEvent(
                        AllocFailure,
                        "Allocation of '%s' failed. (%llu bytes)",
                        "new DestCid",
                        sizeof(QUIC_CID_LIST_ENTRY) + Frame.Length);
                    if (ReplaceRetiredCids) {
                        QuicConnSilentlyAbort(Connection);
                    } else {
                        QuicConnFatalError(Connection, QUIC_STATUS_OUT_OF_MEMORY, NULL);
                    }
                    QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
                    return FALSE;
                }

                DestCid->CID.HasResetToken = TRUE;
                DestCid->CID.SequenceNumber = Frame.Sequence;
                CxPlatCopyMemory(
                    DestCid->ResetToken,
                    Frame.Buffer + Frame.Length,
                    QUIC_STATELESS_RESET_TOKEN_LENGTH);
                QuicPathIDAddDestCID(PathID, DestCid);
                PathID->DestCidCount++;

                if (DestCid->CID.SequenceNumber < PathID->RetirePriorTo) {
                    QuicPathIDRetireCid(PathID, DestCid);                    
                }

                if (PathID->DestCidCount > QUIC_ACTIVE_CONNECTION_ID_LIMIT) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Peer exceeded CID limit");
                    if (ReplaceRetiredCids) {
                        QuicConnSilentlyAbort(Connection);
                    } else {
                        QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                    }
                    QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
                    return FALSE;
                }
            }

            if (ReplaceRetiredCids && !QuicPathIDReplaceRetiredCids(PathID)) {
                QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
                return FALSE;
            }

            if (Connection->State.MultipathNegotiated) {
                QuicConnAssignPathIDs(Connection);
            }

            if (QuicPathIDAssignCids(PathID)) {
                QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PATH_CHALLENGE);
            }

            if (Connection->AddressMigrationDeferred) {
                //
                // AUTO wanted to migrate and had no unused CID to migrate
                // onto. The peer has just issued one, so this is the moment to
                // try again -- the connection is otherwise sitting on a path
                // it already knows is dead. Re-runs the whole reconciliation
                // rather than remembering a decision, since the host's
                // addresses may have moved on since.
                //
                Connection->AddressMigrationDeferred = FALSE;
                Connection->LastAddressGeneration = 0;
                QuicConnQueueLocalAddressChange(Connection);
            }

            AckEliciting = TRUE;
            QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
            break;
        }

        case QUIC_FRAME_RETIRE_CONNECTION_ID: 
        case QUIC_FRAME_PATH_RETIRE_CONNECTION_ID: {
            QUIC_RETIRE_CONNECTION_ID_EX Frame;
            if (!QuicRetireConnectionIDFrameDecode(FrameType, PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding RETIRE_CONNECTION_ID frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }
            BOOLEAN FatalError = FALSE;
            QUIC_PATHID* PathID = QuicPathIDSetGetPathIDForPeer(
                &Connection->PathIDs,
                Frame.PathID,
                FALSE,
                &FatalError);
            if (PathID == NULL) {
                return FALSE;
            }

            BOOLEAN IsLastCid;
            QUIC_CID_SLIST_ENTRY* SourceCid =
                QuicPathIDGetSourceCidFromSeq(
                    PathID,
                    Frame.Sequence,
                    TRUE,
                    &IsLastCid);
            if (SourceCid != NULL) {
                BOOLEAN CidAlreadyRetired = SourceCid->CID.Retired;
                CXPLAT_FREE(SourceCid, QUIC_POOL_CIDSLIST);
                if (IsLastCid) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "Last Source CID Retired!");
                    QuicConnCloseLocally(
                        Connection,
                        QUIC_CLOSE_INTERNAL_SILENT,
                        QUIC_ERROR_PROTOCOL_VIOLATION,
                        NULL);
                } else if (!CidAlreadyRetired) {
                    //
                    // Replace the CID if we weren't the one to request it to be
                    // retired in the first place.
                    //
                    if (!QuicPathIDGenerateNewSourceCid(PathID, FALSE)) {
                        QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
                        break;
                    }
                }
            }

            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;
            QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
            break;
        }

        case QUIC_FRAME_PATH_CHALLENGE: {
            QUIC_PATH_CHALLENGE_EX Frame;
            if (!QuicPathChallengeFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding PATH_CHALLENGE frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            Path->SendResponse = TRUE;
            CxPlatCopyMemory(Path->Response, Frame.Data, sizeof(Frame.Data));
            QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PATH_RESPONSE);

            AckEliciting = TRUE;
            break;
        }

        case QUIC_FRAME_PATH_RESPONSE: {
            QUIC_PATH_RESPONSE_EX Frame;
            if (!QuicPathChallengeFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding PATH_RESPONSE frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            CXPLAT_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
            for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
                QUIC_PATH* TempPath = &Connection->Paths[i];
                if (!TempPath->IsPeerValidated &&
                    !memcmp(Frame.Data, TempPath->Challenge, sizeof(Frame.Data))) {
                    QuicPerfCounterIncrement(
                        Connection->Partition, QUIC_PERF_COUNTER_PATH_VALIDATED);
                    QuicPathSetValid(Connection, TempPath, QUIC_PATH_VALID_PATH_RESPONSE);
                    if (Connection->State.MultipathNegotiated) {
                        QuicPathSetActive(Connection, TempPath);

                        QUIC_CONNECTION_EVENT Event;
                        Event.Type = QUIC_CONNECTION_EVENT_PATH_ADDED;
                        Event.PATH_ADDED.PeerAddress = &TempPath->Route.RemoteAddress;
                        Event.PATH_ADDED.LocalAddress = &TempPath->Route.LocalAddress;
                        Event.PATH_ADDED.PathId = TempPath->PathID->ID;
                        QuicTraceLogConnVerbose(
                            IndicatePathAdded,
                            Connection,
                            "Indicating QUIC_CONNECTION_EVENT_PATH_ADDED");
                        (void)QuicConnIndicateEvent(Connection, &Event);
                    }
                    break;
                }
            }

            AckEliciting = TRUE;
            break;
        }

        case QUIC_FRAME_PATH_ABANDON: {
            if (!Connection->State.MultipathNegotiated) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Received PATH_ABANDON frame when not negotiated");
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                return FALSE;
            }
            QUIC_PATH_ABANDON_EX Frame;
            if (!QuicPathAbandonFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding PATH_ABANDON frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            BOOLEAN FatalError = FALSE;
            QUIC_PATHID *PathID = QuicPathIDSetGetPathIDForPeer(
                &Connection->PathIDs,
                Frame.PathID,
                FALSE,
                &FatalError);
            if (PathID == NULL) {
                break;
            }
            if (PathID->Path == NULL) {
                //
                // The peer referenced a path ID with no QUIC_PATH bound: its
                // CIDs were provisioned by PATH_NEW_CONNECTION_ID but no packet
                // ever arrived to attach a path, either because one has not yet
                // or because one never will. Answer it anyway.
                //
                // Ignoring it was what stranded the peer. It needs our abandon
                // to set its own Abandoned flag, and without that
                // QuicPathIDSetTryFreePathID returns early for good,
                // QuicPathRemove is never called, and one of its QUIC_PATH
                // slots is spent for the life of the connection. A hole punch
                // that fails produces exactly this, which makes it the common
                // case rather than a corner.
                //
                // Nothing of RemoteClose, LocalClose or LocalCloseAcked can be
                // recorded, because all three live on the QUIC_PATH there isn't
                // one of. Abandoned is set here instead: it means both ends are
                // done with the path ID, the peer has just said so, and this
                // side holds no path to wind down.
                //
                PathID->Flags.Abandoned = TRUE;
                PathID->Flags.SendAbandon = TRUE;
                QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PATH_ABANDON);
                AckEliciting = TRUE;

                //
                // Still three PTO before the path ID goes, even though there is
                // no path to drain. draft-ietf-quic-multipath-21 section 3.4
                // asks for "knowledge of the connection IDs issued to the peer
                // and of the state of the number space associated to the path"
                // to "be retained for 3 PTO after the PATH_ABANDON frame has
                // been received", and section 3.4.2 gives the reason: packets
                // sent on the abandoned path can arrive after the CIDs are
                // retired, and one that finds no match makes us answer with a
                // stateless reset. A path ID with no path still has CIDs issued
                // to the peer and still has packet number spaces, so the window
                // applies to it as much as to any other.
                //
                // The PTO comes from the active path: this path ID has no RTT
                // of its own, having never carried anything.
                //
                if (!PathID->Flags.WaitClose && !PathID->Flags.Closed) {
                    const uint64_t ThreePto =
                        QuicLossDetectionComputeProbeTimeout(
                            &PathID->LossDetection,
                            &Connection->Paths[0],
                            3);
                    const uint64_t TimeNow = CxPlatTimeUs64();
                    PathID->Flags.WaitClose = TRUE;
                    PathID->CloseTime = TimeNow + ThreePto;
                    QuicConnTimerSetEx(
                        Connection,
                        QUIC_CONN_TIMER_PATH_CLOSE,
                        ThreePto,
                        TimeNow);
                }

                QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
                break;
            }

            PathID->Path->RemoteClose = TRUE;

            //
            // Read before abandoning, which does not touch LocalCloseAcked.
            //
            if (PathID->Path->LocalCloseAcked) {
                PathID->Flags.Abandoned = TRUE;
            }

            QuicPathIDAbandonLocally(PathID);

            AckEliciting = TRUE;
            QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
            break;
        }

        case QUIC_FRAME_PATH_BACKUP: {
            if (!Connection->State.MultipathNegotiated) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Received PATH_BACKUP frame when not negotiated");
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                return FALSE;
            }
            QUIC_PATH_BACKUP_EX Frame;
            if (!QuicPathBackupFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding PATH_BACKUP frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            BOOLEAN FatalError = FALSE;
            QUIC_PATHID *PathID = QuicPathIDSetGetPathIDForPeer(
                &Connection->PathIDs,
                Frame.PathID,
                FALSE,
                &FatalError);
            if (PathID == NULL) {
                break;
            }
            if (PathID->Path == NULL) {
                //
                // The peer referenced a path id whose QUIC_PATH is not (yet)
                // bound (e.g. CIDs provisioned via PATH_NEW_CONNECTION_ID before
                // QuicConnAssignPathIDs could attach a path). Ignore the frame.
                //
                QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
                break;
            }

            if (Frame.StatusSequenceNumber < PathID->StatusRecvSeq) {
                // ignore the frame
                QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
                break;
            }
            PathID->StatusRecvSeq = Frame.StatusSequenceNumber + 1;

            if (PathID->Path->IsActive) {
                // Change status of the path to backup
                PathID->Path->IsActive = FALSE;
                QUIC_CONNECTION_EVENT Event;
                Event.Type = QUIC_CONNECTION_EVENT_PATH_STATUS_CHANGED;
                Event.PATH_STATUS_CHANGED.PeerAddress = &PathID->Path->Route.RemoteAddress;
                Event.PATH_STATUS_CHANGED.LocalAddress = &PathID->Path->Route.LocalAddress;
                Event.PATH_STATUS_CHANGED.PathId = PathID->ID;
                Event.PATH_STATUS_CHANGED.IsActive = FALSE;
                QuicTraceLogConnVerbose(
                    IndicatePathStatusChanged,
                    Connection,
                    "Indicating QUIC_CONNECTION_EVENT_PATH_STATUS_CHANGED");
                (void)QuicConnIndicateEvent(Connection, &Event);
            }

            AckEliciting = TRUE;
            QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
            break;
        }

        case QUIC_FRAME_PATH_AVAILABLE: {
            if (!Connection->State.MultipathNegotiated) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Received PATH_AVAILABLE frame when not negotiated");
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                return FALSE;
            }
            QUIC_PATH_AVAILABLE_EX Frame;
            if (!QuicPathAvailableFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding PATH_AVAILABLE frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            BOOLEAN FatalError = FALSE;
            QUIC_PATHID *PathID = QuicPathIDSetGetPathIDForPeer(
                &Connection->PathIDs,
                Frame.PathID,
                FALSE,
                &FatalError);
            if (PathID == NULL) {
                break;
            }
            if (PathID->Path == NULL) {
                //
                // The peer referenced a path id whose QUIC_PATH is not (yet)
                // bound (e.g. CIDs provisioned via PATH_NEW_CONNECTION_ID before
                // QuicConnAssignPathIDs could attach a path). Ignore the frame.
                //
                QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
                break;
            }

            if (Frame.StatusSequenceNumber < PathID->StatusRecvSeq) {
                // ignore the frame
                QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
                break;
            }
            PathID->StatusRecvSeq = Frame.StatusSequenceNumber + 1;

            if (!PathID->Path->IsActive) {
                // Change status of the path to available (active)
                PathID->Path->IsActive = TRUE;
                QUIC_CONNECTION_EVENT Event;
                Event.Type = QUIC_CONNECTION_EVENT_PATH_STATUS_CHANGED;
                Event.PATH_STATUS_CHANGED.PeerAddress = &PathID->Path->Route.RemoteAddress;
                Event.PATH_STATUS_CHANGED.LocalAddress = &PathID->Path->Route.LocalAddress;
                Event.PATH_STATUS_CHANGED.PathId = PathID->ID;
                Event.PATH_STATUS_CHANGED.IsActive = TRUE;
                QuicTraceLogConnVerbose(
                    IndicatePathStatusChanged,
                    Connection,
                    "Indicating QUIC_CONNECTION_EVENT_PATH_STATUS_CHANGED");
                (void)QuicConnIndicateEvent(Connection, &Event);
            }

            AckEliciting = TRUE;
            QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
            break;
        }

        case QUIC_FRAME_MAX_PATH_ID: {
            QUIC_MAX_PATH_ID_EX Frame;
            if (!QuicMaxPathIDFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding MAX_PATH_ID frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            if (Frame.MaximumPathID > QUIC_TP_MAX_PATH_ID_MAX) {
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                break;
            }

            if (Frame.MaximumPathID < Connection->PathIDs.PeerMaxPathID) {
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                break;
            }

            QuicPathIDSetUpdateMaxPathID(
                &Connection->PathIDs,
                (uint32_t)Frame.MaximumPathID);

            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_PATHS_BLOCKED: {
            QUIC_PATHS_BLOCKED_EX Frame;
            if (!QuicPathsBlockedFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding PATHS_BLOCKED frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_PATH_CIDS_BLOCKED: {
            QUIC_PATH_CIDS_BLOCKED_EX Frame;
            if (!QuicPathCidsBlockedFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding PATH_CIDS_BLOCKED frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Closed) {
                break; // Ignore frame if we are closed.
            }

            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_CONNECTION_CLOSE:
        case QUIC_FRAME_CONNECTION_CLOSE_1: {
            QUIC_CONNECTION_CLOSE_EX Frame;
            if (!QuicConnCloseFrameDecode(FrameType, PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding CONNECTION_CLOSE frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            uint32_t Flags = QUIC_CLOSE_REMOTE | QUIC_CLOSE_SEND_NOTIFICATION;
            if (Frame.ApplicationClosed) {
                Flags |= QUIC_CLOSE_APPLICATION;
            }

            if (!Frame.ApplicationClosed && Frame.ErrorCode == QUIC_ERROR_APPLICATION_ERROR) {
                //
                // The APPLICATION_ERROR transport error should be sent only
                // when closing the connection before the handshake is
                // confirmed. In such case, we can also expect peer to send the
                // application CONNECTION_CLOSE frame in a 1-RTT packet
                // (presumably also in the same UDP datagram).
                //
                // We want to prioritize reporting the application-layer error
                // code to the application, so we postpone the call to
                // QuicConnTryClose and check again after processing incoming
                // datagrams in case it does not arrive.
                //
                QuicTraceEvent(
                    ConnDelayCloseApplicationError,
                    "[conn][%p] Received APPLICATION_ERROR error, delaying close in expectation of a 1-RTT CONNECTION_CLOSE frame.",
                    Connection);
                Connection->State.DelayedApplicationError = TRUE;
            } else {
                QuicConnTryClose(
                    Connection,
                    Flags,
                    Frame.ErrorCode,
                    Frame.ReasonPhrase,
                    (uint16_t)Frame.ReasonPhraseLength);
            }

            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;

            if (Connection->State.HandleClosed) {
                //
                // If we are now closed, we should exit immediately. No need to
                // parse anything else.
                //
                goto Done;
            }
            break;
        }

        case QUIC_FRAME_HANDSHAKE_DONE: {
            if (QuicConnIsServer(Connection)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Client sent HANDSHAKE_DONE frame");
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                return FALSE;
            }

            if (!Connection->State.HandshakeConfirmed) {
                QuicTraceLogConnInfo(
                    HandshakeConfirmedFrame,
                    Connection,
                    "Handshake confirmed (frame)");
                QuicCryptoHandshakeConfirmed(&Connection->Crypto, TRUE);
            }

            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;
            break;
        }

        case QUIC_FRAME_DATAGRAM:
        case QUIC_FRAME_DATAGRAM_1: {
            if (!Connection->Settings.DatagramReceiveEnabled) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Received DATAGRAM frame when not negotiated");
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                return FALSE;
            }
            if (!QuicDatagramProcessFrame(
                    &Connection->Datagram,
                    Packet,
                    FrameType,
                    PayloadLength,
                    Payload,
                    &Offset)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding DATAGRAM frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }
            AckEliciting = TRUE;
            break;
        }

        case QUIC_FRAME_ACK_FREQUENCY: { // Always accept the frame, because we always enable support.
            QUIC_ACK_FREQUENCY_EX Frame;
            if (!QuicAckFrequencyFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding ACK_FREQUENCY frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            if (Frame.RequestedMaxAckDelay < MS_TO_US(MsQuicLib.TimerResolutionMs)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "RequestedMaxAckDelay is less than TimerResolution");
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                return FALSE;
            }

            AckEliciting = TRUE;
            if (Frame.SequenceNumber < Connection->NextRecvAckFreqSeqNum) {
                //
                // This sequence number (or a higher one) has already been
                // received. Ignore this one.
                //
                break;
            }

            Connection->NextRecvAckFreqSeqNum = Frame.SequenceNumber + 1;
            if (Frame.RequestedMaxAckDelay == 0) {
                Connection->Settings.MaxAckDelayMs = 0;
            } else if (Frame.RequestedMaxAckDelay < 1000) {
                Connection->Settings.MaxAckDelayMs = 1;
            } else {
                CXPLAT_DBG_ASSERT(US_TO_MS(Frame.RequestedMaxAckDelay) <= UINT32_MAX);
                Connection->Settings.MaxAckDelayMs = (uint32_t)US_TO_MS(Frame.RequestedMaxAckDelay);
            }
            if (Frame.AckElicitingThreshold < UINT8_MAX) {
                Connection->PacketTolerance = (uint8_t)Frame.AckElicitingThreshold;
            } else {
                Connection->PacketTolerance = UINT8_MAX; // Cap to 0xFF for space savings.
            }
            if (Frame.ReorderingThreshold < UINT8_MAX) {
                Connection->ReorderingThreshold = (uint8_t)Frame.ReorderingThreshold;
            } else {
                Connection->ReorderingThreshold = UINT8_MAX; // Cap to 0xFF for space savings.
            }
            QuicTraceLogConnInfo(
                UpdatePacketTolerance,
                Connection,
                "Updating packet tolerance to %hhu",
                Connection->PacketTolerance);
            break;
        }

        case QUIC_FRAME_IMMEDIATE_ACK: // Always accept the frame, because we always enable support.
            AckImmediately = TRUE;
            break;

        case QUIC_FRAME_TIMESTAMP: { // Always accept the frame, because we always enable support.
            if (!Connection->State.TimestampRecvNegotiated) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Received TIMESTAMP frame when not negotiated");
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                return FALSE;

            }
            QUIC_TIMESTAMP_EX Frame;
            if (!QuicTimestampFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding TIMESTAMP frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            Packet->HasNonProbingFrame = TRUE;
            Packet->SendTimestamp = Frame.Timestamp;
            break;
        }

        case QUIC_FRAME_OBSERVED_ADDRESS_V4:
        case QUIC_FRAME_OBSERVED_ADDRESS_V6: {
            if (!Connection->Settings.ReceiveObservedAddressReports) {
                //
                // We never asked to receive these reports, so the peer isn't
                // allowed to send them.
                //
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Received OBSERVED_ADDRESS frame when not negotiated");
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                return FALSE;
            }

            QUIC_OBSERVED_ADDRESS_EX Frame;
            if (!QuicObservedAddressFrameDecode(FrameType, PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding OBSERVED_ADDRESS frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            QUIC_CONNECTION_EVENT Event;
            Event.Type = QUIC_CONNECTION_EVENT_NOTIFY_OBSERVED_ADDRESS;
            Event.NOTIFY_OBSERVED_ADDRESS.LocalAddress = &Path->Route.LocalAddress;
            Event.NOTIFY_OBSERVED_ADDRESS.ObservedAddress = &Frame.Address;
            QuicTraceLogConnVerbose(
                IndicateNotifyObservedAddress,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_NOTIFY_OBSERVED_ADDRESS");
            (void)QuicConnIndicateEvent(Connection, &Event);
            break;
        }

        case QUIC_FRAME_ADD_ADDRESS_V4:
        case QUIC_FRAME_ADD_ADDRESS_V6: {
            QUIC_ADD_ADDRESS_EX Frame;
            if (!QuicAddAddressFrameDecode(FrameType, PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding ADD_ADDRESS frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }
            if ((QuicConnIsClient(Connection) && Connection->State.ServerMigrationNegotiated) ||
                (QuicConnIsServer(Connection) && !Connection->State.ServerMigrationNegotiated)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Server received ADD_ADDRESS frame");
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                return FALSE;
            }
            QUIC_STATUS Status = QuicConnProcessAddAddress(Connection, &Frame);
            if (QUIC_FAILED(Status)) {
                QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection,
                    Status,
                    "Process ADD_ADDRESS frame");
            }
            break;
        }

        case QUIC_FRAME_ALTERNATIVE_ADDRESS: {
            QUIC_ALTERNATIVE_ADDRESS_EX Frame;
            if (!QuicAlternativeAddressFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding ALTERNATIVE_ADDRESS frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            //
            // Server to client only, and only when the client asked for it.
            // Both are PROTOCOL_VIOLATION per the draft rather than something
            // to ignore: a server receiving one, or a client receiving one it
            // never negotiated, means the peer is not speaking the extension
            // we agreed on.
            //
            if (QuicConnIsServer(Connection) ||
                !Connection->State.AlternativeAddressNegotiated) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Unexpected ALTERNATIVE_ADDRESS frame");
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                return FALSE;
            }

            AckEliciting = TRUE;

            const QUIC_STATUS Status =
                QuicConnProcessAlternativeAddress(Connection, &Frame);
            if (QUIC_FAILED(Status)) {
                QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection,
                    Status,
                    "Process ALTERNATIVE_ADDRESS frame");
            }
            break;
        }

        case QUIC_FRAME_REMOVE_ADDRESS: {
            QUIC_REMOVE_ADDRESS_EX Frame;
            if (!QuicRemoveAddressFrameDecode(PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding REMOVE_ADDRESS frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }
            if ((QuicConnIsClient(Connection) && Connection->State.ServerMigrationNegotiated) ||
                (QuicConnIsServer(Connection) && !Connection->State.ServerMigrationNegotiated)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Server received REMOVE_ADDRESS frame");
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                return FALSE;
            }
            QUIC_STATUS Status = QuicConnProcessRemoveAddress(Connection, &Frame);
            if (QUIC_FAILED(Status)) {
                QuicTraceEvent(
                    ConnErrorStatus,
                    "[conn][%p] ERROR, %u, %s.",
                    Connection,
                    Status,
                    "Process REMOVE_ADDRESS frame");
            }
            break;
        }

        case QUIC_FRAME_STATELESS_PUNCH_ME_NOW_V4:
        case QUIC_FRAME_STATELESS_PUNCH_ME_NOW_V6: {
            //
            // Stage 1 of #169: parsed, consumed and dropped. Nothing acts on
            // it until #171 gives the server a response.
            //
            // Decoded rather than skipped, and that is the point of handling
            // it at all. The frame is in QUIC_FRAME_IS_KNOWN now -- it has to
            // be, or the frame log cannot reach it -- and a known frame type
            // the loop does not consume leaves the body to be re-read as more
            // frame types. So the two go together: the type is known, the body
            // is consumed, and the contents are ignored for now.
            //
            //
            // Ack-eliciting and non-probing, which the draft says outright
            // (section 10). Set before the decode so that a malformed one
            // still counts -- the packet carried a non-probing frame whatever
            // its contents turn out to be, and the connection is about to be
            // closed anyway.
            //
            AckEliciting = TRUE;
            Packet->HasNonProbingFrame = TRUE;

            QUIC_STATELESS_PUNCH_ME_NOW_EX Frame;
            if (!QuicStatelessPunchMeNowFrameDecode(
                    FrameType, PayloadLength, Payload, &Offset, &Frame)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Decoding STATELESS_PUNCH_ME_NOW frame");
                QuicConnTransportError(Connection, QUIC_ERROR_FRAME_ENCODING_ERROR);
                return FALSE;
            }

            //
            // Client to server only, and a client receiving one is a
            // PROTOCOL_VIOLATION per the draft -- the punch flows the other
            // way, so a server asking us to punch has misunderstood the
            // extension.
            //
            if (QuicConnIsClient(Connection)) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Client received STATELESS_PUNCH_ME_NOW frame");
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                return FALSE;
            }

            //
            // And not negotiated means the peer was never told it could send
            // this, so the frame is not one we agreed to parse. The same
            // treatment ALTERNATIVE_ADDRESS gets.
            //
            if (!Connection->State.StatelessPunchNegotiated) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "STATELESS_PUNCH_ME_NOW without the transport parameter");
                QuicConnTransportError(Connection, QUIC_ERROR_PROTOCOL_VIOLATION);
                return FALSE;
            }

            //
            // Not before the handshake is confirmed, which is a limit the
            // draft does not set and this adds. The transport parameter is
            // read out of the ClientHello, so the flag above can be set while
            // 0-RTT is still being accepted -- and a 0-RTT packet arrives
            // before the client's own address is validated and can be replayed
            // from a spoofed source. Answering one would make the server send
            // a packet to an address of the replayer's choosing. The draft's
            // own limits hold it to one packet no larger than the request, so
            // it is not an amplifier either way, but a legitimate client has
            // no reason to ask this early: it learns the addresses it names
            // from an ALTERNATIVE_ADDRESS frame, which is 1-RTT.
            //
            if (!Connection->State.HandshakeConfirmed) {
                QuicTraceLogConnVerbose(
                    PunchBeforeHandshakeConfirmed,
                    Connection,
                    "Ignoring a punch request before the handshake is confirmed");
                break;
            }

            //
            // One punch per received packet. The frames past the first are
            // ignored, which section 5 says in so many words -- and the
            // ignoring has to happen after the decode above, because the body
            // still has to be consumed for the loop to reach the next frame.
            //
            Connection->PunchRequestsReceived++;

            if (PunchSentForThisPacket) {
                Connection->PunchRequestsIgnoredPerPacket++;
                QuicTraceLogConnVerbose(
                    PunchAlreadySentForPacket,
                    Connection,
                    "Ignoring a second punch request in one packet");
                break;
            }

            //
            // Which of this server's advertised addresses the request is
            // about. By address and port, which is what the frame carries and
            // the whole reason this draft needs no per-attempt state: the
            // older mechanism looked the entry up by a sequence number only
            // the ADD_ADDRESS frames carried.
            //
            // No match is not an error. The server may have withdrawn the
            // address, or never advertised it, and the draft asks only that
            // the frame be ignored.
            //
            // Removing entries are skipped for the reason the older handler
            // skipped them: QuicConnRemoveBoundAddress releases the binding
            // and leaves the entry on the list until the withdrawal is
            // acknowledged, so the binding is NULL in that window.
            //
            // The first match wins where several bound addresses share one
            // observed address. Appendix C.2 leaves that open; picking the
            // first makes the behaviour depend on list order, which is worth
            // saying out loud rather than discovering. The alternative --
            // preferring the base whose route to the client is best -- costs a
            // route lookup inside frame processing, which is the thing this
            // receive path must not do.
            //
            QUIC_BOUND_ADDRESS_LIST_ENTRY* Bound = NULL;
            for (CXPLAT_LIST_ENTRY* Entry = Connection->BoundAddresses.Flink;
                    Entry != &Connection->BoundAddresses;
                    Entry = Entry->Flink) {
                QUIC_BOUND_ADDRESS_LIST_ENTRY* Current =
                    CXPLAT_CONTAINING_RECORD(
                        Entry, QUIC_BOUND_ADDRESS_LIST_ENTRY, Link);
                if (Current->ObservedAddressSet &&
                    !Current->Removing &&
                    Current->Binding != NULL &&
                    QuicAddrCompare(&Current->ObservedAddress, &Frame.ServerAddress)) {
                    Bound = Current;
                    break;
                }
            }
            if (Bound == NULL) {
                QuicTraceLogConnVerbose(
                    PunchRequestUnknownAddress,
                    Connection,
                    "Punch request named an address this server did not advertise");
                break;
            }

            //
            // The filter before the rate check, so a request to an address
            // this server will never punch towards costs nothing but the
            // comparison. The order the other way round would let a peer burn
            // its own allowance on addresses that were never going to be
            // answered.
            //
            // The allowance is spent on the attempt, not refunded if the send
            // below declines -- a request in a packet too small to answer
            // within, say. The peer is the only one who can lose by that, and
            // bounding the work is the point.
            //
            if (!QuicConnPunchDestinationAllowed(Connection, &Frame.ClientAddress) ||
                !QuicConnPunchRateAllows(Connection)) {
                break;
            }

            //
            // One packet, and then nothing is remembered. No path, no
            // connection ID, no record of the attempt: the client learns the
            // outcome only from whether its own validation succeeds, which is
            // what makes the server's side of this stateless.
            //
            // The guard records whether a punch actually went out, not whether
            // one was attempted. "At most one punch packet" is satisfied
            // either way, and a request the send declined -- too small to
            // answer within -- should not cost a later frame its chance.
            //
            PunchSentForThisPacket =
                QuicConnSendStatelessPunch(
                    Connection,
                    Bound,
                    &Frame.ClientAddress,
                    //
                    // The QUIC packet, not the datagram that carried it.
                    // Section 5.1 bounds the punch by "the packet", and where
                    // a datagram coalesces several the stricter reading is the
                    // one that actually bounds amplification. For the 1-RTT
                    // packet a punch request arrives in the two are the same
                    // size anyway, since a short header's payload runs to the
                    // end of the datagram.
                    //
                    (uint16_t)(Packet->HeaderLength + Packet->PayloadLength));

            break;
        }

        default:
            //
            // No default case necessary, as we have already validated the frame
            // type initially, but included for clang the compiler.
            //
            break;
        }
    }

Done:

    if (UpdatedFlowControl) {
        QuicConnLogOutFlowStats(Connection);
        QuicPathIDLogOutFlowStats(Path->PathID);
    }

    if (Connection->State.ShutdownComplete || Connection->State.HandleClosed) {
        QuicTraceLogVerbose(
            PacketRxNotAcked,
            "[%c][RX][%llu] not acked (connection is closed)",
            PtkConnPre(Connection),
            Packet->PacketNumber);

    } else if (Path->PathID->Packets[EncryptLevel] != NULL) {

        if (Path->PathID->Packets[EncryptLevel]->NextRecvPacketNumber <= Packet->PacketNumber) {
            Path->PathID->Packets[EncryptLevel]->NextRecvPacketNumber = Packet->PacketNumber + 1;
            Packet->NewLargestPacketNumber = TRUE;
        }

        QUIC_ACK_TYPE AckType;
        if (AckImmediately) {
            AckType = QUIC_ACK_TYPE_ACK_IMMEDIATE;
        } else if (AckEliciting) {
            AckType = QUIC_ACK_TYPE_ACK_ELICITING;
        } else {
            AckType = QUIC_ACK_TYPE_NON_ACK_ELICITING;
        }

        QuicAckTrackerAckPacket(
            &Path->PathID->Packets[EncryptLevel]->AckTracker,
            Packet->PacketNumber,
            RecvTime,
            ECN,
            AckType);
    }

    Packet->CompletelyValid = TRUE;

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRecvPostProcessing(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH** Path,
    _In_ QUIC_RX_PACKET* Packet
    )
{
    BOOLEAN PeerUpdatedCid = FALSE;
    if (Packet->DestCidLen != 0) {
        QUIC_CID_SLIST_ENTRY* SourceCid =
            QuicPathIDGetSourceCidFromBuf(
                (*Path)->PathID,
                Packet->DestCidLen,
                Packet->DestCid);
        if (SourceCid != NULL && !SourceCid->CID.UsedByPeer) {
            QuicTraceLogConnInfo(
                FirstCidUsage,
                Connection,
                "First usage of SrcCid: %s",
                QuicCidBufToStr(Packet->DestCid, Packet->DestCidLen).Buffer);
            SourceCid->CID.UsedByPeer = TRUE;
            if (!SourceCid->CID.IsInitial) {
                PeerUpdatedCid = TRUE;
            }
        }
    }

    if (!(*Path)->GotValidPacket) {
        (*Path)->GotValidPacket = TRUE;

        if (!(*Path)->IsActive &&
            ((QuicConnIsClient(Connection) && Connection->State.ServerMigrationNegotiated) ||
             (QuicConnIsServer(Connection) && !Connection->State.ServerMigrationNegotiated))) {

            //
            // This is the first valid packet received on this non-active path.
            // Set the state accordingly and queue up a path challenge to be
            // sent back out.
            //

            if ((*Path)->DestCid == NULL ||
                (PeerUpdatedCid && (*Path)->DestCid->CID.Length != 0)) {
                //
                // TODO - What if the peer (client) only sends a single CID and
                // rebinding happens? Should we support using the same CID over?
                //
                QUIC_CID_LIST_ENTRY* NewDestCid = QuicPathIDGetUnusedDestCid((*Path)->PathID);
                if (NewDestCid == NULL) {
                    QuicTraceEvent(
                        ConnError,
                        "[conn][%p] ERROR, %s.",
                        Connection,
                        "No unused CID for new path");
                    (*Path)->GotValidPacket = FALSE; // Don't have a new CID to use!!!
                    (*Path)->DestCid = NULL;
                    return;
                }
                CXPLAT_DBG_ASSERT(NewDestCid != (*Path)->DestCid);
                (*Path)->DestCid = NewDestCid;
                QUIC_CID_SET_PATH(Connection, (*Path)->DestCid, (*Path));
                (*Path)->DestCid->CID.UsedLocally = TRUE;
            }

            CXPLAT_DBG_ASSERT((*Path)->DestCid != NULL);
            QuicPathValidate((*Path));
            (*Path)->SendChallenge = TRUE;
            (*Path)->PathValidationStartTime = CxPlatTimeUs64();
            (*Path)->ChallengeCount = 1;

            //
            // NB: The path challenge payload is initialized here and reused
            // for any retransmits, but the spec requires a new payload in each
            // path challenge.
            //
            CxPlatRandom(sizeof((*Path)->Challenge), (*Path)->Challenge);

            if (!Connection->State.MultipathNegotiated) {
                //
                // We need to also send a challenge on the active path to make sure
                // it is still good.
                //
                CXPLAT_DBG_ASSERT(Connection->Paths[0].IsActive);
                if (Connection->Paths[0].IsPeerValidated) { // Not already doing peer validation.
                    Connection->Paths[0].IsPeerValidated = FALSE;
                    Connection->Paths[0].SendChallenge = TRUE;
                    Connection->Paths[0].PathValidationStartTime = CxPlatTimeUs64();
                    Connection->Paths[0].ChallengeCount = 1;
                    CxPlatRandom(sizeof(Connection->Paths[0].Challenge), Connection->Paths[0].Challenge);
                }
            }

            QuicSendSetSendFlag(
                &Connection->Send,
                QUIC_CONN_SEND_FLAG_PATH_CHALLENGE);

            //
            // (Re-)arm the path validation timer for whichever of the now
            // in-progress validations has the earliest deadline.
            //
            QuicConnPathValidationTimerUpdate(Connection);
        }

    } else if (PeerUpdatedCid) {
        //
        // If we didn't initiate the CID change locally, we need to
        // respond to this change with a change of our own.
        //
        if (!(*Path)->InitiatedCidUpdate) {
            QuicPathIDRetireCurrentDestCid((*Path)->PathID, *Path);
        } else {
            (*Path)->InitiatedCidUpdate = FALSE;
        }
    }

    if (((QuicConnIsServer(Connection) && !Connection->State.ServerMigrationNegotiated) ||
         (QuicConnIsClient(Connection) && Connection->State.ServerMigrationNegotiated)) &&
        !Connection->State.MultipathNegotiated &&
        Packet->HasNonProbingFrame &&
        Packet->NewLargestPacketNumber &&
        !(*Path)->IsActive && (*Path)->InUse) {
        //
        // The peer has sent a non-probing frame on a path other than the active
        // one. This signals their intent to switch active paths.
        //
        QuicPathSetActive(Connection, *Path);
        *Path = &Connection->Paths[0];

        QuicTraceEvent(
            ConnRemoteAddrAdded,
            "[conn][%p] New Remote IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].Route.RemoteAddress), &Connection->Paths[0].Route.RemoteAddress)); // TODO - Addr removed event?

        QUIC_CONNECTION_EVENT Event;
        Event.Type = QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED;
        Event.PEER_ADDRESS_CHANGED.Address = &(*Path)->Route.RemoteAddress;
        QuicTraceLogConnVerbose(
            IndicatePeerAddrChanged,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED");
        (void)QuicConnIndicateEvent(Connection, &Event);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRecvDatagramBatch(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ uint8_t BatchCount,
    _In_reads_(BatchCount) QUIC_RX_PACKET** Packets,
    _In_reads_(BatchCount * CXPLAT_HP_SAMPLE_LENGTH)
        const uint8_t* Cipher,
    _Inout_ QUIC_RECEIVE_PROCESSING_STATE* RecvState
    )
{
    uint8_t HpMask[CXPLAT_HP_SAMPLE_LENGTH * QUIC_MAX_CRYPTO_BATCH_COUNT];

    CXPLAT_DBG_ASSERT(BatchCount > 0 && BatchCount <= QUIC_MAX_CRYPTO_BATCH_COUNT);
    QUIC_RX_PACKET* Packet = Packets[0];

    QuicTraceLogConnVerbose(
        UdpRecvBatch,
        Connection,
        "Batch Recv %u UDP datagrams",
        BatchCount);

    if (Connection->Crypto.TlsState.ReadKeys[Packet->KeyType] == NULL) {
        QuicPacketLogDrop(Connection, Packet, "Key no longer accepted (batch)");
        return;
    }

    if (Packet->Encrypted &&
        Connection->State.HeaderProtectionEnabled) {
        if (QUIC_FAILED(
            CxPlatHpComputeMask(
                Connection->Crypto.TlsState.ReadKeys[Packet->KeyType]->HeaderKey,
                BatchCount,
                Cipher,
                HpMask))) {
            QuicPacketLogDrop(Connection, Packet, "Failed to compute HP mask");
            return;
        }
    } else {
        CxPlatZeroMemory(HpMask, BatchCount * CXPLAT_HP_SAMPLE_LENGTH);
    }

    for (uint8_t i = 0; i < BatchCount; ++i) {
        CXPLAT_DBG_ASSERT(Packets[i]->Allocated);
        CXPLAT_ECN_TYPE ECN = CXPLAT_ECN_FROM_TOS(Packets[i]->TypeOfService);
        Packet = Packets[i];
        CXPLAT_DBG_ASSERT(Packet->PacketId != 0);
        if (!QuicConnRecvPrepareDecrypt(
                Connection, Packet, HpMask + i * CXPLAT_HP_SAMPLE_LENGTH) ||
            !QuicConnRecvDecryptAndAuthenticate(Connection, Path, Packet)) {
            if (Connection->State.CompatibleVerNegotiationAttempted &&
                !Connection->State.CompatibleVerNegotiationCompleted) {
                //
                // The packet which initiated compatible version negotation failed
                // decryption, so undo the version change.
                //
                Connection->Stats.QuicVersion = Connection->OriginalQuicVersion;
                Connection->State.CompatibleVerNegotiationAttempted = FALSE;
            }
        } else if (QuicConnRecvFrames(Connection, Path, Packet, ECN)) {

            QuicConnRecvPostProcessing(Connection, &Path, Packet);
            RecvState->ResetIdleTimeout |= Packet->CompletelyValid;

            if (!Connection->State.MultipathNegotiated && 
                Connection->Registration != NULL && !Connection->Registration->NoPartitioning &&
                !Path->Binding->Partitioned && !Connection->State.Partitioned && Path->IsActive &&
                !Path->PartitionUpdated && Packet->CompletelyValid &&
                (Packets[i]->PartitionIndex % MsQuicLib.PartitionCount) != RecvState->PartitionIndex) {
                RecvState->PartitionIndex = Packets[i]->PartitionIndex % MsQuicLib.PartitionCount;
                RecvState->UpdatePartitionId = TRUE;
                Path->PartitionUpdated = TRUE;
            }

            if (Packet->IsShortHeader && Packet->NewLargestPacketNumber) {

                if (QuicConnIsServer(Connection)) {
                    Path->SpinBit = Packet->SH->SpinBit;
                } else {
                    Path->SpinBit = !Packet->SH->SpinBit;
                }
            }
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRecvDatagrams(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_RX_PACKET* Packets,
    _In_ uint32_t PacketChainCount,
    _In_ uint32_t PacketChainByteCount,
    _In_ BOOLEAN IsDeferred
    )
{
    QUIC_RX_PACKET* ReleaseChain = NULL;
    QUIC_RX_PACKET** ReleaseChainTail = &ReleaseChain;
    uint32_t ReleaseChainCount = 0;
    QUIC_RECEIVE_PROCESSING_STATE RecvState = { FALSE, FALSE, 0 };
    RecvState.PartitionIndex = QuicPartitionIdGetIndex(Connection->PartitionID);

    UNREFERENCED_PARAMETER(PacketChainCount);
    UNREFERENCED_PARAMETER(PacketChainByteCount);

    CXPLAT_PASSIVE_CODE();

    if (IsDeferred) {
        QuicTraceLogConnVerbose(
            UdpRecvDeferred,
            Connection,
            "Recv %u deferred UDP datagrams",
            PacketChainCount);
    } else {
        QuicTraceEvent(
            ConnRecvUdpDatagrams,
            "[conn][%p] Recv %u UDP datagrams, %u bytes",
            Connection,
            PacketChainCount,
            PacketChainByteCount);
    }

    //
    // Iterate through each QUIC packet in the chain of UDP datagrams until an
    // error is encountered or we run out of buffer.
    //

    uint8_t BatchCount = 0;
    QUIC_RX_PACKET* Batch[QUIC_MAX_CRYPTO_BATCH_COUNT];
    uint8_t Cipher[CXPLAT_HP_SAMPLE_LENGTH * QUIC_MAX_CRYPTO_BATCH_COUNT];
    QUIC_PATH* CurrentPath = NULL;
    uint8_t CurrentPathID = 0;
    QUIC_PACKET_KEY_TYPE PrevPackKeyType = QUIC_PACKET_KEY_COUNT;

    QUIC_RX_PACKET* Packet;
    while ((Packet = Packets) != NULL) {
        CXPLAT_DBG_ASSERT(Packet->Allocated);
        CXPLAT_DBG_ASSERT(Packet->QueuedOnConnection);
        Packets = (QUIC_RX_PACKET*)Packet->Next;
        Packet->Next = NULL;

        CXPLAT_DBG_ASSERT(Packet != NULL);
        CXPLAT_DBG_ASSERT(Packet->PacketId != 0);

        CXPLAT_DBG_ASSERT(Packet->ReleaseDeferred == IsDeferred);
        Packet->ReleaseDeferred = FALSE;

        if (BatchCount != 0 && Connection->PathsCount == QUIC_MAX_PATH_COUNT) {
            //
            // With every path slot taken, QuicConnGetPathForPacket makes room
            // for a new address by removing the inactive paths that look like
            // a rebind of it, and the path the batched packets came in on can
            // be one of them. Finish the batch while its path still exists.
            //
            CXPLAT_DBG_ASSERT(CurrentPath != NULL);
            QuicConnRecvDatagramBatch(
                Connection,
                CurrentPath,
                BatchCount,
                Batch,
                Cipher,
                &RecvState);
            BatchCount = 0;
        }

        QUIC_PATH* DatagramPath = QuicConnGetPathForPacket(Connection, Packet);
        if (DatagramPath == NULL) {
            QuicPacketLogDrop(Connection, Packet, "Max paths already tracked");
            goto Drop;
        }

        CxPlatUpdateRoute(&DatagramPath->Route, Packet->Route);

        if (CurrentPath != NULL) {
            //
            // The current path may be moved, or gone.
            //
            uint8_t PathIndex;
            CurrentPath = QuicConnGetPathByID(Connection, CurrentPathID, &PathIndex);
            if (CurrentPath == NULL && BatchCount != 0) {
                //
                // Not expected after the flush above, but a batch must never
                // be processed without a path: drop it rather than crash.
                //
                CXPLAT_DBG_ASSERT(FALSE);
                for (uint8_t i = 0; i < BatchCount; ++i) {
                    QuicPacketLogDrop(Connection, Batch[i], "Path removed with packets batched");
                }
                BatchCount = 0;
            }
        }
        if (DatagramPath != CurrentPath) {
            if (BatchCount != 0) {
                //
                // This datagram is from a different path than the current
                // batch. Flush the current batch before continuing.
                //
                CXPLAT_DBG_ASSERT(CurrentPath != NULL);
                QuicConnRecvDatagramBatch(
                    Connection,
                    CurrentPath,
                    BatchCount,
                    Batch,
                    Cipher,
                    &RecvState);
                BatchCount = 0;
            }
            CurrentPath = DatagramPath;
            CurrentPathID = CurrentPath->ID;
        }

        if (!IsDeferred) {
            CurrentPath->PathID->Stats.Recv.TotalBytes += Packet->BufferLength;
            Connection->Stats.Recv.TotalBytes += Packet->BufferLength;
            if (Connection->Stats.Handshake.HandshakeHopLimitTTL == 0) {
                Connection->Stats.Handshake.HandshakeHopLimitTTL = Packet->HopLimitTTL;
            }
            QuicPathIDLogInFlowStats(CurrentPath->PathID);

            if (!CurrentPath->IsPeerValidated) {
                QuicPathIncrementAllowance(
                    Connection,
                    CurrentPath,
                    QUIC_AMPLIFICATION_RATIO * Packet->BufferLength);
            }
        }

        do {
            CXPLAT_DBG_ASSERT(BatchCount < QUIC_MAX_CRYPTO_BATCH_COUNT);
            CXPLAT_DBG_ASSERT(Packet->Allocated);
            CurrentPath->PathID->Stats.Recv.TotalPackets++;
            Connection->Stats.Recv.TotalPackets++;

            if (!Packet->ValidatedHeaderInv) {
                //
                // Only calculate the buffer length from the available UDP
                // payload length if the long header hasn't already been
                // validated (which indicates the actual length);
                //
                Packet->AvailBufferLength =
                    Packet->BufferLength - (uint16_t)(Packet->AvailBuffer - Packet->Buffer);
            }

            if (!QuicConnRecvHeader(
                    Connection,
                    Packet,
                    Cipher + BatchCount * CXPLAT_HP_SAMPLE_LENGTH)) {
                if (Packet->ReleaseDeferred) {
                    Connection->Stats.Recv.TotalPackets--; // Don't count the packet right now.
                } else if (!Packet->IsShortHeader && Packet->ValidatedHeaderVer) {
                    goto NextPacket;
                }
                break;
            }

            if ((BatchCount != 0) &&
                (!Packet->IsShortHeader ||
                (PrevPackKeyType != QUIC_PACKET_KEY_COUNT && PrevPackKeyType != Packet->KeyType))) {
                //
                // We already had some batched short header packets and then
                // encountered a long header packet OR the current packet
                // has different key type. Finish off the batch first and
                // then continue with the current packet.
                //
                QuicConnRecvDatagramBatch(
                    Connection,
                    CurrentPath,
                    BatchCount,
                    Batch,
                    Cipher,
                    &RecvState);
                CxPlatMoveMemory(
                    Cipher + BatchCount * CXPLAT_HP_SAMPLE_LENGTH,
                    Cipher,
                    CXPLAT_HP_SAMPLE_LENGTH);
                BatchCount = 0;
            }

            Batch[BatchCount++] = Packet;
            PrevPackKeyType = Packet->KeyType;
            if (Packet->IsShortHeader && BatchCount < QUIC_MAX_CRYPTO_BATCH_COUNT) {
                break;
            }

            QuicConnRecvDatagramBatch(
                Connection,
                CurrentPath,
                BatchCount,
                Batch,
                Cipher,
                &RecvState);
            BatchCount = 0;

            if (Packet->IsShortHeader) {
                break; // Short header packets aren't followed by additional packets.
            }

            //
            // Move to the next QUIC packet (if available) and reset the packet
            // state.
            //

        NextPacket:

            Packet->AvailBuffer += Packet->AvailBufferLength;

            Packet->ValidatedHeaderInv = FALSE;
            Packet->ValidatedHeaderVer = FALSE;
            Packet->ValidToken = FALSE;
            Packet->PacketNumberSet = FALSE;
            Packet->EncryptedWith0Rtt = FALSE;
            Packet->ReleaseDeferred = FALSE;
            Packet->CompletelyValid = FALSE;
            Packet->NewLargestPacketNumber = FALSE;
            Packet->HasNonProbingFrame = FALSE;

        } while (Packet->AvailBuffer - Packet->Buffer < Packet->BufferLength);

    Drop:

        if (!Packet->ReleaseDeferred) {
            *ReleaseChainTail = Packet;
            ReleaseChainTail = (QUIC_RX_PACKET**)&Packet->Next;
            Packet->QueuedOnConnection = FALSE;
            if (++ReleaseChainCount == QUIC_MAX_RECEIVE_BATCH_COUNT) {
                if (BatchCount != 0) {
                    QuicConnRecvDatagramBatch(
                        Connection,
                        CurrentPath,
                        BatchCount,
                        Batch,
                        Cipher,
                        &RecvState);
                    BatchCount = 0;
                }
                CxPlatRecvDataReturn((CXPLAT_RECV_DATA*)ReleaseChain);
                ReleaseChain = NULL;
                ReleaseChainTail = &ReleaseChain;
                ReleaseChainCount = 0;
            }
        }
    }

    if (BatchCount != 0) {
        QuicConnRecvDatagramBatch(
            Connection,
            CurrentPath,
            BatchCount,
            Batch,
            Cipher,
            &RecvState);
        BatchCount = 0; // cppcheck-suppress unreadVariable; NOLINT
    }

    if (Connection->State.DelayedApplicationError && Connection->CloseStatus == 0) {
        //
        // We received transport APPLICATION_ERROR, but didn't receive the expected
        // CONNECTION_ERROR frame, so close the connection with originally postponed
        // APPLICATION_ERROR.
        //
        QuicConnTryClose(
            Connection,
            QUIC_CLOSE_REMOTE | QUIC_CLOSE_SEND_NOTIFICATION,
            QUIC_ERROR_APPLICATION_ERROR,
            NULL,
            (uint16_t)0);
    }

    if (RecvState.ResetIdleTimeout) {
        QuicConnResetIdleTimeout(Connection);
    }

    QuicTraceEvent(
        ConnReleaseChain,
        "[conn][%p] ReleaseChain: %p",
        Connection,
        ReleaseChain);

    if (ReleaseChain != NULL) {
        CxPlatRecvDataReturn((CXPLAT_RECV_DATA*)ReleaseChain);
    }

    if (QuicConnIsServer(Connection) &&
        Connection->Stats.Recv.ValidPackets == 0 &&
        !Connection->State.ClosedLocally) {
        //
        // The packet(s) that created this connection weren't valid. We should
        // immediately throw away the connection.
        //
        QuicTraceLogConnWarning(
            InvalidInitialPackets,
            Connection,
            "Aborting connection with invalid initial packets");
        QuicConnSilentlyAbort(Connection);
    }

    if ((QuicConnIsClient(Connection) && Connection->State.ServerMigrationNegotiated) ||
        (QuicConnIsServer(Connection) && !Connection->State.ServerMigrationNegotiated)) {
        //
        // Any new paths created here were created before packet validation. Now
        // remove any non-active paths that didn't get any valid packets.
        // NB: Traversing the array backwards is simpler and more efficient here due
        // to the array shifting that happens in QuicPathRemove.
        //
        for (int i = Connection->PathsCount - 1; i > 0; --i) {
            if (!Connection->Paths[i].GotValidPacket) {
                QuicTraceLogConnInfo(
                    PathDiscarded,
                    Connection,
                    "Removing invalid path[%hhu]",
                    Connection->Paths[i].ID);
                CXPLAT_DBG_ASSERT(Connection->Paths[i].Binding != NULL);
                QuicLibraryReleaseBinding(Connection->Paths[i].Binding);
                Connection->Paths[i].Binding = NULL;
                QuicPathRemove(Connection, (uint8_t)i);
            }
        }
    }
    if (!Connection->State.UpdateWorker && Connection->State.Connected &&
        !Connection->State.ShutdownComplete && RecvState.UpdatePartitionId &&
        RecvState.PartitionIndex != QuicPartitionIdGetIndex(Connection->PartitionID)) {
        //
        // Packets were received on a different partition than the one assigned to the connection.
        // Migrate the connection to a new worker. New CIDs must be generated since the partition
        // id is encoded in the CID.
        //
        // The index has to be compared here and not merely asserted. Path->PartitionUpdated
        // limits this to once per path, not once per chain, and QuicConnRecvPostProcessing can
        // promote a newly created path to active in the middle of one. A chain that spans two
        // paths can therefore pick a partition twice and land back on the one the connection
        // already has, which would migrate it to the worker it is already on and regenerate
        // every source CID for nothing.
        //
        CXPLAT_DBG_ASSERT(Connection->Registration);
        CXPLAT_DBG_ASSERT(!Connection->Registration->NoPartitioning);
        Connection->PartitionID = QuicPartitionIdCreate(RecvState.PartitionIndex);
        QuicPathIDSetGenerateNewSourceCids(&Connection->PathIDs, TRUE);
        Connection->State.UpdateWorker = TRUE;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnFlushRecv(
    _In_ QUIC_CONNECTION* Connection
    )
{
    BOOLEAN FlushedAll;
    uint32_t ReceiveQueueCount, ReceiveQueueByteCount;
    QUIC_RX_PACKET* ReceiveQueue;

    CxPlatDispatchLockAcquire(&Connection->ReceiveQueueLock);
    ReceiveQueue = Connection->ReceiveQueue;
    if (Connection->ReceiveQueueCount > QUIC_MAX_RECEIVE_FLUSH_COUNT) {
        FlushedAll = FALSE;
        Connection->ReceiveQueueCount -= QUIC_MAX_RECEIVE_FLUSH_COUNT;
        QUIC_RX_PACKET* Tail = Connection->ReceiveQueue;
        ReceiveQueueCount = 0;
        ReceiveQueueByteCount = 0;
        while (++ReceiveQueueCount < QUIC_MAX_RECEIVE_FLUSH_COUNT) {
            ReceiveQueueByteCount += Tail->BufferLength;
            Tail = (QUIC_RX_PACKET*)Tail->Next;
        }
        ReceiveQueueByteCount += Tail->BufferLength;
        Connection->ReceiveQueueByteCount -= ReceiveQueueByteCount;
        Connection->ReceiveQueue = (QUIC_RX_PACKET*)Tail->Next;
        Tail->Next = NULL;
    } else {
        FlushedAll = TRUE;
        ReceiveQueueCount = Connection->ReceiveQueueCount;
        ReceiveQueueByteCount = Connection->ReceiveQueueByteCount;
        Connection->ReceiveQueueCount = 0;
        Connection->ReceiveQueueByteCount = 0;
        Connection->ReceiveQueue = NULL;
        Connection->ReceiveQueueTail = &Connection->ReceiveQueue;
    }
    CxPlatDispatchLockRelease(&Connection->ReceiveQueueLock);

    QuicConnRecvDatagrams(
        Connection, ReceiveQueue, ReceiveQueueCount, ReceiveQueueByteCount, FALSE);

    return FlushedAll;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnDiscardDeferred0Rtt(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_RX_PACKET* ReleaseChain = NULL;
    QUIC_RX_PACKET** ReleaseChainTail = &ReleaseChain;
    CXPLAT_DBG_ASSERT(Connection->Paths[0].PathID->ID == 0);
    QUIC_PACKET_SPACE* Packets = Connection->Paths[0].PathID->Packets[QUIC_ENCRYPT_LEVEL_1_RTT];
    CXPLAT_DBG_ASSERT(Packets != NULL);

    QUIC_RX_PACKET* DeferredPackets = Packets->DeferredPackets;
    QUIC_RX_PACKET** DeferredPacketsTail = &Packets->DeferredPackets;
    Packets->DeferredPackets = NULL;

    while (DeferredPackets != NULL) {
        QUIC_RX_PACKET* Packet = DeferredPackets;
        DeferredPackets = (QUIC_RX_PACKET*)DeferredPackets->Next;

        if (Packet->KeyType == QUIC_PACKET_KEY_0_RTT) {
            QuicPacketLogDrop(Connection, Packet, "0-RTT rejected");
            Packets->DeferredPacketsCount--;
            *ReleaseChainTail = Packet;
            ReleaseChainTail = (QUIC_RX_PACKET**)&Packet->Next;
        } else {
            *DeferredPacketsTail = Packet;
            DeferredPacketsTail = (QUIC_RX_PACKET**)&Packet->Next;
        }
    }

    if (ReleaseChain != NULL) {
        CxPlatRecvDataReturn((CXPLAT_RECV_DATA*)ReleaseChain);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnFlushDeferred(
    _In_ QUIC_CONNECTION* Connection
    )
{
    for (uint8_t i = 1; i <= (uint8_t)Connection->Crypto.TlsState.ReadKey; ++i) {

        if (Connection->Crypto.TlsState.ReadKeys[i] == NULL) {
            continue;
        }

        QUIC_ENCRYPT_LEVEL EncryptLevel =
            QuicKeyTypeToEncryptLevel((QUIC_PACKET_KEY_TYPE)i);
        CXPLAT_DBG_ASSERT(Connection->Paths[0].PathID->ID == 0);
        QUIC_PACKET_SPACE* Packets = Connection->Paths[0].PathID->Packets[EncryptLevel];

        if (Packets->DeferredPackets != NULL) {
            QUIC_RX_PACKET* DeferredPackets = Packets->DeferredPackets;
            uint8_t DeferredPacketsCount = Packets->DeferredPacketsCount;

            Packets->DeferredPacketsCount = 0;
            Packets->DeferredPackets = NULL;

            QuicConnRecvDatagrams(
                Connection,
                DeferredPackets,
                DeferredPacketsCount,
                0, // Unused for deferred datagrams
                TRUE);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessUdpUnreachable(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    if (Connection->Crypto.TlsState.ReadKey > QUIC_PACKET_KEY_INITIAL ||
        Connection->Settings.IgnoreUnreachable) {
        //
        // Only accept unreachable events at the beginning of the handshake.
        // Otherwise, it opens up an attack surface.
        // If configured, ignore unreachable events.
        //
        QuicTraceLogConnWarning(
            UnreachableIgnore,
            Connection,
            "Ignoring received unreachable event");

    } else if (QuicAddrCompare(&Connection->Paths[0].Route.RemoteAddress, RemoteAddress)) {
        QuicTraceLogConnInfo(
            Unreachable,
            Connection,
            "Received unreachable event");
        //
        // Close the connection since the peer is unreachable.
        //
        QuicConnCloseLocally(
            Connection,
            QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
            (uint64_t)QUIC_STATUS_UNREACHABLE,
            NULL);

    } else {
        QuicTraceLogConnWarning(
            UnreachableInvalid,
            Connection,
            "Received invalid unreachable event");
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessRouteCompletion(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const uint8_t* PhysicalAddress,
    _In_ uint8_t PathId,
    _In_ BOOLEAN Succeeded
    )
{
    uint8_t PathIndex;
    QUIC_PATH* Path = QuicConnGetPathByID(Connection, PathId, &PathIndex);
    if (Path == NULL) {
        return;
    }

    if (Succeeded) {
        CxPlatResolveRouteComplete(Connection, &Path->Route, PhysicalAddress, PathId);
    } else {
        //
        // Remove the path that failed route resolution, fallback to another path if possible.
        //
        QuicTraceLogConnInfo(
            FailedRouteResolution,
            Connection,
            "Route resolution failed on Path[%hhu]. Switching paths...",
            PathId);

        CXPLAT_DBG_ASSERT(Path->Binding != NULL);
        //
        // Remove this connection's source CIDs from the binding's lookup before
        // releasing it. Otherwise, when the binding is torn down its lookup
        // still references these CIDs and QuicLookupUninitialize asserts
        // (CidCount == 0). Matches the client cleanup in
        // QuicPathIDSetTryFreePathID. The server shares its binding across
        // connections and removes its CIDs via QuicConnUnregister instead.
        //
        if (!Path->UseBound) {
            QuicBindingRemoveAllSourceConnectionIDs(Path->Binding, Connection);
        }
        QuicLibraryReleaseBinding(Path->Binding);
        Path->Binding = NULL;
        QuicPathRemove(Connection, PathIndex);
    }

    if (!QuicSendFlush(&Connection->Send)) {
        QuicSendQueueFlush(&Connection->Send, REASON_ROUTE_COMPLETION);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnResetIdleTimeout(
    _In_ QUIC_CONNECTION* Connection
    )
{
    uint64_t IdleTimeoutMs;
    if (Connection->State.Connected) {
        //
        // Use the (non-zero) min value between local and peer's configuration.
        //
        IdleTimeoutMs = Connection->PeerTransportParams.IdleTimeout;
        if (IdleTimeoutMs == 0 ||
            (Connection->Settings.IdleTimeoutMs != 0 &&
             Connection->Settings.IdleTimeoutMs < IdleTimeoutMs)) {
            IdleTimeoutMs = Connection->Settings.IdleTimeoutMs;
        }
    } else {
        IdleTimeoutMs = Connection->Settings.HandshakeIdleTimeoutMs;
    }

    if (IdleTimeoutMs != 0) {
        if (Connection->State.Connected && !QuicConnIsQMux(Connection)) {
            QUIC_PATH* Path = &Connection->Paths[0];
            //
            // Idle timeout must be no less than the PTOs for closing.
            //
            uint64_t MinIdleTimeoutMs =
                US_TO_MS(QuicLossDetectionComputeProbeTimeout(
                    &Path->PathID->LossDetection,
                    Path,
                    QUIC_CLOSE_PTO_COUNT));
            if (IdleTimeoutMs < MinIdleTimeoutMs) {
                IdleTimeoutMs = MinIdleTimeoutMs;
            }
        }

        QuicConnTimerSet(
            Connection,
            QUIC_CONN_TIMER_IDLE,
            MS_TO_US(IdleTimeoutMs));

    } else {
        QuicConnTimerCancel(Connection, QUIC_CONN_TIMER_IDLE);
    }

    if (Connection->Settings.KeepAliveIntervalMs != 0) {
        QuicConnTimerSet(
            Connection,
            QUIC_CONN_TIMER_KEEP_ALIVE,
            MS_TO_US(Connection->Settings.KeepAliveIntervalMs));
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessIdleTimerOperation(
    _In_ QUIC_CONNECTION* Connection
    )
{
    //
    // Close the connection, as the agreed-upon idle time period has elapsed.
    //
    QuicConnCloseLocally(
        Connection,
        QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
        (uint64_t)QUIC_STATUS_CONNECTION_IDLE,
        NULL);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessKeepAliveOperation(
    _In_ QUIC_CONNECTION* Connection
    )
{
    if (QuicConnIsQMux(Connection)) {
        //
        // Send a QX PING frame to keep the connection alive.
        //
        QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_QX_PING);
    } else {
        //
        // Send a PING frame to keep the connection alive.
        //
        Connection->Send.TailLossProbeNeeded = TRUE;
        QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PING);
    }

    //
    // Restart the keep alive timer.
    //
    QuicConnTimerSet(
        Connection,
        QUIC_CONN_TIMER_KEEP_ALIVE,
        MS_TO_US(Connection->Settings.KeepAliveIntervalMs));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnPathKeepAliveTimerUpdate(
    _In_ QUIC_CONNECTION* Connection
    )
{
    //
    // A QMux connection has one transport-provided path and no 1-RTT keys of
    // its own, so there is nothing here for it to keep alive.
    //
    if (Connection->Settings.PathKeepAliveIntervalMs == 0 ||
        !Connection->State.Connected ||
        QuicConnIsQMux(Connection) ||
        QuicConnIsClosed(Connection)) {
        QuicConnTimerCancel(Connection, QUIC_CONN_TIMER_PATH_KEEP_ALIVE);
        return;
    }

    const uint64_t IntervalUs =
        MS_TO_US((uint64_t)Connection->Settings.PathKeepAliveIntervalMs);
    const uint64_t TimeNow = CxPlatTimeUs64();

    //
    // A path that hasn't sent anything for the whole interval gets a PING. The
    // rest tell us how long we can wait before looking again: the timer is set
    // for whichever path comes due first.
    //
    uint64_t NextDelayUs = IntervalUs;
    BOOLEAN AnyPath = FALSE;

    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        QUIC_PATH* Path = &Connection->Paths[i];
        if (!Path->InUse || Path->Binding == NULL || Path->DestCid == NULL) {
            continue;
        }
        const uint64_t IdleUs = CxPlatTimeDiff64(Path->LastSendTimeUs, TimeNow);
        if (IdleUs >= IntervalUs) {
            Path->SendKeepAlive = TRUE;
            AnyPath = TRUE;
        } else if (IntervalUs - IdleUs < NextDelayUs) {
            NextDelayUs = IntervalUs - IdleUs;
        }
    }

    if (AnyPath) {
        QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PATH_KEEP_ALIVE);
    }

    QuicConnTimerSet(
        Connection,
        QUIC_CONN_TIMER_PATH_KEEP_ALIVE,
        NextDelayUs);
}

//
// Returns the path validation timeout (in microseconds) for the given path.
// Per RFC 9000 section 8.2.4 we use the larger of:
//   - a multiple of the current PTO on the path
//   - a multiple of the connection's configured initial RTT
//       (a floor for paths with no RTT samples yet).
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
uint64_t
QuicConnPathValidationTimeoutUs(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_PATH* Path
    )
{
    return
        CXPLAT_MAX(
            QuicLossDetectionComputeProbeTimeout(
                &Path->PathID->LossDetection, Path, QUIC_PATH_VALIDATION_PTO_COUNT),
            QUIC_PATH_VALIDATION_MIN_INITIAL_RTT_MULTIPLE *
                MS_TO_US(Connection->Settings.InitialRttMs));
}

//
// When the next thing is due for a validation in progress: either the boundary
// at which another PATH_CHALLENGE should be queued, or the deadline at which
// the path is given up on, whichever comes first.
//
// RFC 9000 section 8.2.1 permits the retries -- "An endpoint MAY send multiple
// PATH_CHALLENGE frames to guard against packet loss" -- and section 8.2.2 puts
// the obligation here rather than on the peer: "An endpoint MUST NOT send more
// than one PATH_RESPONSE frame in response to one PATH_CHALLENGE frame [...]
// The peer is expected to send more PATH_CHALLENGE frames as necessary to evoke
// additional PATH_RESPONSE frames". Section 8.2.1 also caps the rate -- not
// "more frequently than it would send an Initial packet" -- which a PTO-sized
// interval satisfies.
//
//
// How long between the PATH_CHALLENGEs of one validation. The timer handler and
// the arming below must agree on this, or a re-arm could land on a boundary the
// handler does not consider due and the timer would fire in a loop, so it lives
// in one place.
//
// CXPLAT_MAX of one keeps a degenerate timeout from making this zero, for the
// same reason.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
uint64_t
QuicConnPathValidationIntervalUs(
    _In_ uint64_t Timeout
    )
{
    return CXPLAT_MAX(Timeout / QUIC_PATH_VALIDATION_PTO_COUNT, 1);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static
uint64_t
QuicConnPathValidationNextEventTime(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_PATH* Path
    )
{
    const uint64_t Timeout = QuicConnPathValidationTimeoutUs(Connection, Path);
    const uint64_t Deadline = Path->PathValidationStartTime + Timeout;

    if (Path->ChallengeCount >= QUIC_PATH_VALIDATION_PTO_COUNT) {
        return Deadline;
    }

    return
        CXPLAT_MIN(
            Path->PathValidationStartTime +
                (Path->ChallengeCount * QuicConnPathValidationIntervalUs(Timeout)),
            Deadline);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnPathValidationTimerUpdate(
    _In_ QUIC_CONNECTION* Connection
    )
{
    //
    // Find the earliest thing due across all paths that currently have a
    // validation in progress -- a challenge to re-send or a deadline to give up
    // at -- and arm (or cancel) the timer accordingly.
    //
    const uint64_t TimeNow = CxPlatTimeUs64();
    uint64_t EarliestDeadline = UINT64_MAX;

    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        const QUIC_PATH* Path = &Connection->Paths[i];
        if (Path->IsPeerValidated || Path->PathValidationStartTime == 0) {
            continue;
        }
        const uint64_t Deadline = QuicConnPathValidationNextEventTime(Connection, Path);
        EarliestDeadline = CXPLAT_MIN(Deadline, EarliestDeadline);
    }

    if (EarliestDeadline == UINT64_MAX) {
        QuicConnTimerCancel(Connection, QUIC_CONN_TIMER_PATH_VALIDATION);
        return;
    }

    const uint64_t Delay =
        (EarliestDeadline > TimeNow) ? (EarliestDeadline - TimeNow) : 0;
    QuicConnTimerSetEx(
        Connection,
        QUIC_CONN_TIMER_PATH_VALIDATION,
        Delay,
        TimeNow);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessPathValidationTimerOperation(
    _In_ QUIC_CONNECTION* Connection
    )
{
    //
    // Re-send the challenge for any path still waiting, and abandon any whose
    // validation timed out.
    //
    const uint64_t TimeNow = CxPlatTimeUs64();
    uint8_t i = 0;
    while (i < Connection->PathsCount) {
        QUIC_PATH* Path = &Connection->Paths[i];
        if (Path->IsPeerValidated || Path->PathValidationStartTime == 0) {
            ++i;
            continue;
        }
        const uint64_t Timeout = QuicConnPathValidationTimeoutUs(Connection, Path);
        const uint64_t Elapsed = CxPlatTimeDiff64(Path->PathValidationStartTime, TimeNow);
        if (Elapsed <= Timeout) {
            //
            // Still within the deadline, so this is a retry boundary rather
            // than the end. One PATH_CHALLENGE was queued when validation
            // started and one more is queued at each boundary after it, up to
            // QUIC_PATH_VALIDATION_PTO_COUNT in total.
            //
            // Nothing else re-sends it. The loss handler only re-arms when the
            // packet carrying the challenge is itself declared lost, and a lost
            // PATH_RESPONSE leaves that packet acknowledged, so without this a
            // single lost response cost the path permanently.
            //
            // Path->Challenge is deliberately left alone, so a response to any
            // copy still matches. RFC 9000 section 8.2.1 asks for unpredictable
            // data in every PATH_CHALLENGE frame, which reusing one payload for
            // the retries of a single validation does not do; the data is still
            // unpredictable to anyone who has not seen it, so what is given up
            // is only knowing which copy a response answers, which nothing here
            // uses. That deviation already existed for the loss-handler re-send
            // and is tracked separately.
            //
            // Which challenge the elapsed time says is due, rather than
            // simply the next one. A timer that fires late -- a loaded machine,
            // a busy worker -- therefore skips the boundaries it slept through
            // instead of firing off their challenges back to back, which would
            // breach the rate section 8.2.1 asks for. The cost is that a late
            // timer spends fewer than QUIC_PATH_VALIDATION_PTO_COUNT probes;
            // keeping the pacing is worth more than keeping the count, since
            // the probes exist to cover loss and two spaced a PTO apart cover
            // more than three bunched together.
            //
            const uint64_t Interval = QuicConnPathValidationIntervalUs(Timeout);
            const uint8_t Due =
                (uint8_t)CXPLAT_MIN(
                    (Elapsed / Interval) + 1,
                    QUIC_PATH_VALIDATION_PTO_COUNT);
            if (Due > Path->ChallengeCount) {
                Path->ChallengeCount = Due;
                Path->SendChallenge = TRUE;
                QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PATH_CHALLENGE);
                QuicTraceLogConnInfo(
                    PathChallengeResend,
                    Connection,
                    "Path[%hhu] re-sending PATH_CHALLENGE (%hhu of %u)",
                    Path->ID,
                    Path->ChallengeCount,
                    (uint32_t)QUIC_PATH_VALIDATION_PTO_COUNT);
            }
            ++i;
            continue;
        }

        QuicTraceEvent(
            ConnPathValidationTimeout,
            "[conn][%p] Path[%hhu] validation timed out",
            Connection,
            Path->ID);
        QuicPerfCounterIncrement(Connection->Partition, QUIC_PERF_COUNTER_PATH_FAILURE);

        //
        // The path ID is spent whether the path came up or not, and
        // draft-ietf-quic-multipath section 3.1 is explicit about what that
        // obliges: "As the used path ID is consumed either way, the endpoint
        // MUST explicitly close the path". Section 3.4 says the same from the
        // other direction -- an endpoint abandoning a path MUST send a
        // PATH_ABANDON frame, whatever prompted it -- and recommends sending it
        // on a different path precisely when the one being abandoned looks
        // broken, which is this case.
        //
        // Removing the path silently instead left the peer believing the path
        // ID was still in use, with no way to learn otherwise, and left our own
        // path ID in the set with no path attached to it, never freed and never
        // put on the close timer. Abandoning tells the peer and leaves
        // QuicPathIDSetTryFreePathID to take the path and its path ID away
        // together once the close timer expires.
        //
        // Only under multipath, which is what PATH_ABANDON requires, and only
        // while another usable path remains: there is nothing to carry the
        // frame otherwise, and nothing to carry the connection either, so the
        // last path still falls through to removal and closes the connection.
        //
        if (Connection->State.MultipathNegotiated &&
            Connection->Paths[i].PathID != NULL &&
            QuicConnHasOtherUsablePath(Connection, &Connection->Paths[i])) {
            QuicPathIDAbandonLocally(Connection->Paths[i].PathID);
            //
            // Keeps this path out of the validation timer from here on: it is
            // leaving on the close timer now, and QuicConnPathValidationTimerUpdate
            // skips paths with no validation in progress.
            //
            Connection->Paths[i].PathValidationStartTime = 0;
            ++i;
            continue;
        }

        //
        // A punch attempt that failed gives its destination CID back by
        // retiring it, so the peer issues a replacement and this one is never
        // used again. RFC 9000 section 9.5: the CID has been seen on this
        // path, and reusing it from a different local address is what links
        // the two attempts together. The multipath branch above has this
        // already -- PATH_ABANDON retires the path's CIDs with it -- so this
        // is the branch that did not.
        //
        // Scoped to punch attempts rather than applied to every failed
        // validation. Retiring on all of them would be defensible on the same
        // privacy grounds, but it changes CID churn for ordinary migration
        // failures, and QuicPathIDRetireCid aborts the connection once
        // retirements pass 8x the CID limit -- a flapping path would then
        // close the connection outright. Worth deciding separately rather
        // than as a side effect of this stage.
        //
        if (Connection->Paths[i].StatelessPunchAttempt &&
            Connection->Paths[i].DestCid != NULL &&
            Connection->Paths[i].PathID != NULL) {
            QUIC_CID_CLEAR_PATH(Connection->Paths[i].DestCid);
            QuicPathIDRetireCid(
                Connection->Paths[i].PathID, Connection->Paths[i].DestCid);
            Connection->Paths[i].DestCid = NULL;
            QuicTraceLogConnInfo(
                PunchAttemptCidRetired,
                Connection,
                "Path[%hhu] punch attempt failed; retired its destination CID",
                Connection->Paths[i].ID);
        }

        //
        // Release the abandoned path's UDP binding before removing it, matching
        // the convention used by every other QuicPathRemove caller (QuicPathRemove
        // itself does not release bindings). Only do this when the path will
        // actually be removed (PathsCount > 1); for the last remaining path
        // QuicPathRemove keeps Paths[0] intact and its binding is released later
        // during connection teardown. When removing the active path (i == 0),
        // QuicPathRemove swaps in a fallback, so nulling the binding here leaves
        // the abandoned (now released) binding on the slot that gets removed while
        // the promoted path keeps its own.
        //
        if (Connection->PathsCount > 1 &&
            Connection->Paths[i].Binding != NULL) {
            if (!Connection->Paths[i].UseBound) {
                //
                // An unconnected binding is matched on local port alone, so
                // paths to different remote addresses can share one. The source
                // connection IDs registered on it belong to the connection, not
                // to this path, and the paths still using the binding are still
                // reached through them. Only withdraw them once no other path
                // holds the same binding, or those paths stop receiving.
                //
                BOOLEAN IsCommonBinding = FALSE;
                for (uint8_t j = 0; j < Connection->PathsCount; ++j) {
                    if (i != j && Connection->Paths[i].Binding == Connection->Paths[j].Binding) {
                        IsCommonBinding = TRUE;
                        break;
                    }
                }
                if (!IsCommonBinding) {
                    QuicBindingRemoveAllSourceConnectionIDs(Connection->Paths[i].Binding, Connection);
                }
            }
            QuicLibraryReleaseBinding(Connection->Paths[i].Binding);
            Connection->Paths[i].Binding = NULL;
        }
        if (QuicPathRemove(Connection, i)) {
            //
            // Do not increase i: paths have been shifted with the removal.
            //
            continue;
        }

        //
        // QuicPathRemove returned FALSE: this was the last path and the
        // connection is closing. Clear the validation start time so
        // QuicConnPathValidationTimerUpdate won't re-arm the timer.
        //
        Connection->Paths[i].PathValidationStartTime = 0;
        ++i;
    }

    //
    // Re-arm the timer for whichever (if any) validation is now the earliest.
    //
    QuicConnPathValidationTimerUpdate(Connection);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnUpdatePeerPacketTolerance(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint8_t NewPacketTolerance
    )
{
    if (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_MIN_ACK_DELAY &&
        Connection->PeerPacketTolerance != NewPacketTolerance) {
        QuicTraceLogConnInfo(
            UpdatePeerPacketTolerance,
            Connection,
            "Updating peer packet tolerance to %hhu",
            NewPacketTolerance);
        Connection->SendAckFreqSeqNum++;
        Connection->PeerPacketTolerance = NewPacketTolerance;
        QuicSendSetSendFlag(
            &Connection->Send,
            QUIC_CONN_SEND_FLAG_ACK_FREQUENCY);
    }
}

// Opens a new path for the connection. 
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnAssignPathIDs(
    _In_ QUIC_CONNECTION* Connection
    )
{
    BOOLEAN Assigned = FALSE;

    CXPLAT_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        QUIC_PATH* Path = &Connection->Paths[i];
        if (Path->PathID != NULL || !Path->InUse) {
            continue;
        }

        QUIC_PATHID* PathID = QuicPathIDSetGetUnusedPathID(&Connection->PathIDs);
        if (PathID == NULL) {
            return Assigned;
        }

        QuicPathIDAddRef(PathID, QUIC_PATHID_REF_PATH);
        PathID->Flags.InUse = TRUE;
        Path->PathID = PathID;
        PathID->Path = Path;
        QuicCongestionControlInitialize(&PathID->CongestionControl, &Connection->Settings);
        Assigned = TRUE;
        QuicPathIDRelease(Path->PathID, QUIC_PATHID_REF_LOOKUP);
    }

    return Assigned;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnOpenNewPath(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    )
{
    CXPLAT_DBG_ASSERT(Connection->State.RemoteAddressSet);
    CXPLAT_DBG_ASSERT(Connection->Configuration != NULL);
    CXPLAT_DBG_ASSERT(Path != &Connection->Paths[0]);

    QUIC_PATHID *PathID = NULL;
    QUIC_STATUS Status;

    QUIC_BINDING* NewBinding = NULL;
    CXPLAT_UDP_CONFIG UdpConfig = {0};

    if (Connection->State.UnconnectedSocket) {
        if (!Connection->State.ShareBinding) {
            //
            // Setting the parameter requires a shared binding, so this only
            // catches a binding that was un-shared afterwards.
            //
            Status = QUIC_STATUS_INVALID_STATE;
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Unconnected socket requires a shared binding");
            goto Error;
        }

        if (Connection->Settings.QTIPEnabled) {
            //
            // The raw datapath reads a socket with no remote address as a
            // server listener, and requires a wildcard local address of one
            // (see RawSocketCreateUdp). An unconnected socket has neither: no
            // remote address by definition, and a specific local address by
            // requirement. Without QTIP that only costs the raw datapath, since
            // the socket falls back to an OS one; with it there is no fallback.
            //
            Status = QUIC_STATUS_INVALID_STATE;
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Unconnected socket is not supported with QTIP");
            goto Error;
        }

        if (QuicAddrIsWildCard(&Path->Route.LocalAddress)) {
            //
            // A connected socket takes its source address from the kernel when
            // it is connected. An unconnected one does not, and the path's first
            // packet goes out before anything has been learned from the peer, so
            // the caller has to name the address to send from.
            //
            Status = QUIC_STATUS_INVALID_PARAMETER;
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Unconnected socket requires a specific local address");
            goto Error;
        }
    }

    if (QuicAddrIsWildCard(&Path->Route.LocalAddress) && QuicAddrGetPort(&Path->Route.LocalAddress) == 0) {
        UdpConfig.LocalAddress = NULL;
    } else {
        UdpConfig.LocalAddress = &Path->Route.LocalAddress;
    }
    if (Connection->State.UnconnectedSocket) {
        //
        // Passing no remote address leaves the socket unconnected, which is what
        // lets a single binding carry connections to different remote addresses.
        //
        UdpConfig.RemoteAddress = NULL;
    } else if (QuicAddrIsWildCard(&Path->Route.RemoteAddress) && QuicAddrGetPort(&Path->Route.RemoteAddress) == 0) {
        UdpConfig.RemoteAddress = &Connection->Paths[0].Route.RemoteAddress;
    } else {
        UdpConfig.RemoteAddress = &Path->Route.RemoteAddress;
    }
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpConfig.InterfaceIndex = 0;
    // Open a new binding with the same partition as the connection.
    UdpConfig.PartitionIndex = QuicPartitionIdGetIndex(Connection->PartitionID);
#ifdef QUIC_COMPARTMENT_ID
    UdpConfig.CompartmentId = Connection->Configuration->CompartmentId;
#endif
#ifdef QUIC_OWNING_PROCESS
    UdpConfig.OwningProcess = Connection->Configuration->OwningProcess;
#endif

    if (Connection->State.ShareBinding) {
        UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_SHARE;
    }
    if (Connection->Settings.XdpEnabled) {
        UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_XDP;
    }
    if (Connection->Settings.QTIPEnabled) {
        UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_QTIP;
    }
    if (Connection->State.Partitioned) {
        UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_PARTITIONED;
    }

    Status = QuicLibraryGetBinding(&UdpConfig, &NewBinding);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Path->Binding = NewBinding;

    //
    // QuicLibraryGetBinding hands back an existing binding whenever one matches,
    // so this path may well have joined a binding another path of this same
    // connection is already on. That is the normal case for an unconnected
    // socket, which is matched on local port alone and therefore shared across
    // paths to different remote addresses. Whether the connection's source
    // connection IDs still have to be registered below depends on which it was.
    //
    BOOLEAN ReallyNewBinding = TRUE;
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        if (Path != &Connection->Paths[i] && Connection->Paths[i].Binding == NewBinding) {
            ReallyNewBinding = FALSE;
            break;
        }
    }

    QuicBindingGetLocalAddress(
        Path->Binding,
        &Path->Route.LocalAddress);

    //
    // Only inherit the primary path's remote address when the caller did not
    // request a specific one (mirroring the UdpConfig.RemoteAddress selection
    // above). Overwriting unconditionally would discard an explicitly
    // requested remote address (e.g. QUIC_PARAM_CONN_ADD_PATH targeting a new
    // server address), leaving the path unfindable by QuicConnGetPathByAddress.
    //
    if (QuicAddrIsWildCard(&Path->Route.RemoteAddress) &&
        QuicAddrGetPort(&Path->Route.RemoteAddress) == 0) {
        CxPlatCopyMemory(&Path->Route.RemoteAddress,
            &Connection->Paths[0].Route.RemoteAddress,
            sizeof(QUIC_ADDR));
    }
    if (Connection->State.MultipathNegotiated) {
        PathID = QuicPathIDSetGetUnusedPathID(&Connection->PathIDs);
        if (PathID != NULL) {
            QuicPathIDAddRef(PathID, QUIC_PATHID_REF_PATH);
            PathID->Flags.InUse = TRUE;
            PathID->Path = Path;
            Path->PathID = PathID;
            QuicCongestionControlInitialize(&PathID->CongestionControl, &Connection->Settings);
        } else {
            QuicLibraryReleaseBinding(Path->Binding);
            Path->Binding = NULL;
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            goto Error;
        }
    } else {
        QuicPathIDAddRef(Connection->Paths[0].PathID, QUIC_PATHID_REF_PATH);
        Path->PathID = Connection->Paths[0].PathID;
    }

    //
    // Registering the source connection IDs is what makes the binding deliver
    // this connection's packets, and it is per binding, not per path. A binding
    // inherited from another path of this connection already carries them, so
    // doing it again would either add a second null source CID for the same
    // connection or re-register the ones already there.
    //
    if (ReallyNewBinding) {
        if (!Connection->State.ShareBinding) {
            QUIC_CID_SLIST_ENTRY* SourceCid = QuicCidNewNullSource(Path->PathID);
            if (SourceCid == NULL) {
                Status = QUIC_STATUS_OUT_OF_MEMORY;
                goto Error;
            }

            Path->PathID->NextSourceCidSequenceNumber++;
            QuicPathIDAddSourceCID(Path->PathID, SourceCid, FALSE);

            if (!QuicBindingAddSourceConnectionID(NewBinding, SourceCid)) {
                Status = QUIC_STATUS_OUT_OF_MEMORY;
                goto Error;
            }
        } else {
            if (!QuicBindingAddAllSourceConnectionIDs(NewBinding, Connection)) {
                QuicPathIDSetGenerateNewSourceCids(&Connection->PathIDs, TRUE);
            }
        }
    }

    QuicTraceEvent(
        ConnLocalAddrAdded,
        "[conn][%p] New Local IP: %!ADDR!",
        Connection,
        CASTED_CLOG_BYTEARRAY(sizeof(Path->Route.LocalAddress), &Path->Route.LocalAddress));

    QuicTraceEvent(
        ConnRemoteAddrAdded,
        "[conn][%p] New Remote IP: %!ADDR!",
        Connection,
        CASTED_CLOG_BYTEARRAY(sizeof(Path->Route.RemoteAddress), &Path->Route.RemoteAddress));

    QUIC_CID_LIST_ENTRY* NewDestCid = QuicPathIDGetUnusedDestCid(Path->PathID);

    //
    // If we can't get a unused CID, we defer sending a path challange until we receieve a new CID.
    //
    if (NewDestCid != NULL) {
        Path->DestCid = NewDestCid;
        QUIC_CID_SET_PATH(Connection, Path->DestCid, Path);
        Path->DestCid->CID.UsedLocally = TRUE;

        CXPLAT_DBG_ASSERT(Path->DestCid != NULL);
        QuicPathValidate(Path);
        Path->SendChallenge = TRUE;
        Path->PathValidationStartTime = CxPlatTimeUs64();
        Path->ChallengeCount = 1;

        CxPlatRandom(sizeof(Path->Challenge), Path->Challenge);

        //
        // Starting a validation is not enough on its own: without the timer
        // there is nothing to notice that it never completed, and a path whose
        // peer never answers stays on the connection for good.
        //
        QuicConnPathValidationTimerUpdate(Connection);
    }

    Status = QUIC_STATUS_SUCCESS;
Error:
    if (PathID != NULL) {
        QuicPathIDRelease(Path->PathID, QUIC_PATHID_REF_LOOKUP);            
    }

    return Status;
}

// Opens new paths for the connection when the handshake is confirmed.
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnOpenNewPaths(
    _In_ QUIC_CONNECTION* Connection
    )
{
    BOOLEAN Assigned = FALSE;

    CXPLAT_DBG_ASSERT(Connection->PathsCount > 0);
    for (uint8_t i = Connection->PathsCount - 1; i > 0; --i) {
        if (Connection->Paths[i].Binding == NULL) {
            QUIC_STATUS Status = QuicConnOpenNewPath(Connection, &Connection->Paths[i]);
            if (QUIC_FAILED(Status)) {
                if (Connection->Paths[i].Binding != NULL) {
                    QuicLibraryReleaseBinding(Connection->Paths[i].Binding);
                    Connection->Paths[i].Binding = NULL;
                }
                QuicPathRemove(Connection, i);
            } else if (Connection->Paths[i].DestCid != NULL &&
                       !Connection->Paths[i].StatelessPunchAttempt) {
                //
                // A punch attempt is left out, because the caller turns this
                // into a PATH_CHALLENGE and that is the one thing such a path
                // must not send yet: its probe waits for
                // QUIC_CONN_TIMER_PROBE_AFTER_PUNCH so the server's punch has
                // time to open the mapping first. The reconciler armed that
                // timer and queued the request when it created the path;
                // nothing more is owed here.
                //
                // This branch used to be the NAT-traversal one, sending the
                // older PUNCH_ME_NOW and arming the same timer. #173 moved
                // both to the reconciler, so the mode no longer needs a case
                // of its own -- only the deferral does, and that is keyed on
                // the attempt rather than on the mode.
                //
                Assigned = TRUE;
            }
        }
    }
    return Assigned;
}

//
// Adds a new bound address to the connection.
//
// The function validates the current connection state and role (client/server)
// against server migration negotiation before allowing an additional local
// address to be registered. It enforces uniqueness of bound addresses per
// connection, ensures the per-connection bound-address limit is not exceeded,
// allocates and stores a new bound-address entry, and creates a corresponding
// UDP binding using the connection's partition. The binding is created on the
// address the caller named; if the caller does not specify a port, an ephemeral
// port is used and the address stored on the connection is updated with it.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
QUIC_STATUS
QuicConnAddBoundAddress(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_ADDR* Param
    )
    //
    // Once the connection has been locally closed, its configuration (including
    // bound addresses) must not be modified.
    //
{
    if (Connection->State.ClosedLocally) {
        return QUIC_STATUS_INVALID_STATE;
    }
    //
    // Only allow additional bound addresses when server migration is in a
    // valid state for the endpoint role:
    //   - Clients require successful negotiation before adding addresses.
    //   - Servers must not add addresses once migration has been negotiated.
    //

    if ((QuicConnIsClient(Connection) && !Connection->State.ServerMigrationNegotiated) ||
        (QuicConnIsServer(Connection) && Connection->State.ServerMigrationNegotiated)) {
        return QUIC_STATUS_INVALID_STATE;
    }
    //
    // Reject adding a bound address that is already present on the connection.
    // Comparison is performed against the existing bound-address list.
    //

    for (CXPLAT_LIST_ENTRY* Entry = Connection->BoundAddresses.Flink;
            Entry != &Connection->BoundAddresses;
            Entry = Entry->Flink) {
        QUIC_BOUND_ADDRESS_LIST_ENTRY* Bound =
    //
    // Enforce the maximum number of local addresses that may be associated
    // with a single connection before attempting allocation.
    //
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_BOUND_ADDRESS_LIST_ENTRY,
                Link);
        if (!QuicAddrCompare(&Bound->Address, Param)) {
            continue;
        }
        return QUIC_STATUS_ADDRESS_IN_USE;
    }

    if (Connection->BoundAddressesCount >= QUIC_MAX_LOCAL_ADDRESS_COUNT) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    //
    // Cache the caller-provided address in the new bound-address entry.
    //

    QUIC_BOUND_ADDRESS_LIST_ENTRY* Bound =
    //
    // The caller's address is used for the UDP binding as given. A zero port
    // requests an ephemeral one, which is read back off the binding below.
    //
        (QUIC_BOUND_ADDRESS_LIST_ENTRY*)
        CXPLAT_ALLOC_NONPAGED(
            sizeof(QUIC_BOUND_ADDRESS_LIST_ENTRY),
            QUIC_POOL_BOUND_ADDRESS_LIST);
    if (Bound == NULL) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    //
    // Initialize the UDP configuration for the new binding. Only the local
    // address is used here; the socket is created without a specific remote
    // peer and with default flags, bound to the same partition as the
    // connection in order to preserve locality and affinity.
    //
    }

    CxPlatCopyMemory(&Bound->Address, Param, sizeof(QUIC_ADDR));

    BOOLEAN PortUnspecified = QuicAddrGetPort(Param) == 0;

    //
    // The binding carries no remote address, which the raw datapath reads as a
    // server listener and then requires a wildcard local address of (see
    // RawSocketCreateUdp). Under QTIP there is no falling back to an OS socket,
    // so bind the wildcard and keep only the port, as this did before it learnt
    // to bind the address it was given. The address the peer is told about is
    // still the one the caller named; what is lost is the choice of interface
    // to receive on, which QTIP could not honour anyway.
    //
    QUIC_ADDR WildcardAddress = {0};
    if (Connection->Settings.QTIPEnabled) {
        QuicAddrSetFamily(&WildcardAddress, QUIC_ADDRESS_FAMILY_INET6);
        QuicAddrSetPort(&WildcardAddress, QuicAddrGetPort(Param));
        QuicTraceLogConnInfo(
            BoundAddressWildcardForQtip,
            Connection,
            "Binding a bound address on the wildcard, as QTIP requires");
    }

    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.LocalAddress = Connection->Settings.QTIPEnabled ? &WildcardAddress : Param;
    UdpConfig.RemoteAddress = NULL;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpConfig.InterfaceIndex = 0;
    // Open a new binding with the same partition as the connection.
    UdpConfig.PartitionIndex = QuicPartitionIdGetIndex(Connection->PartitionID);
#ifdef QUIC_COMPARTMENT_ID
    UdpConfig.CompartmentId = Connection->Configuration->CompartmentId;
#endif
#ifdef QUIC_OWNING_PROCESS
    UdpConfig.OwningProcess = Connection->Configuration->OwningProcess;
#endif

    if (Connection->State.ShareBinding) {
        UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_SHARE;
    }
    if (Connection->Settings.XdpEnabled) {
        UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_XDP;
    }
    if (Connection->Settings.QTIPEnabled) {
        UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_QTIP;
    }
    if (Connection->State.Partitioned) {
        UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_PARTITIONED;
    }

    QUIC_STATUS Status = QuicLibraryGetBinding(&UdpConfig, &Bound->Binding);
    if (QUIC_FAILED(Status)) {
        CXPLAT_FREE(Bound, QUIC_POOL_BOUND_ADDRESS_LIST);
        return Status;
    }
 
    if (PortUnspecified) {
        QUIC_ADDR BindingLocalAddress = {0};
        QuicBindingGetLocalAddress(Bound->Binding, &BindingLocalAddress);
        QuicAddrSetPort(
            &Bound->Address,
            QuicAddrGetPort(&BindingLocalAddress));
    }

    Bound->ObservedAddressSet = FALSE;
    Bound->SequenceNumberValid = FALSE;
    Bound->SequenceNumber = QUIC_VAR_INT_MAX;
    Bound->SendAddAddress = FALSE;
    Bound->Removing = FALSE;
    //
    // Explicit, because the entry comes from an unzeroed allocation and every
    // field here is set by hand. Left out, the acknowledgement path would read
    // it for any entry marked Removing and could free a bound address while its
    // withdrawal was still in flight.
    //
    Bound->WithdrawnAtAltSequenceNumber = 0;
    Bound->SendRemoveAddress = FALSE;

    CxPlatListInsertTail(&Connection->BoundAddresses, &Bound->Link);
    Connection->BoundAddressesCount++;

    QuicTraceEvent(
        ConnBoundAddrAdded,
        "[conn][%p] New Bound IP: %!ADDR!",
        Connection,
        CASTED_CLOG_BYTEARRAY(sizeof(Bound->Address), &Bound->Address));

    if (!QuicBindingAddAllSourceConnectionIDs(Bound->Binding, Connection)) {
        QuicConnGenerateNewSourceCids(Connection, TRUE);
    }

    return QUIC_STATUS_SUCCESS;
}

// Adds a new observed address for a bound address.
// This function invokes sending of ADD_ADDRESS frame.
_IRQL_requires_max_(PASSIVE_LEVEL)
static
QUIC_STATUS
QuicConnAddObservedAddress(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_ADD_OBSERVED_ADDRESS* Param
    )
{
    if (QuicAddrIsWildCard(Param->ObservedAddress) ||
        QuicAddrGetPort(Param->ObservedAddress) == 0) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (Connection->State.ClosedLocally) {
        return QUIC_STATUS_INVALID_STATE;
    }

    if ((QuicConnIsClient(Connection) && !Connection->State.ServerMigrationNegotiated) ||
        (QuicConnIsServer(Connection) && Connection->State.ServerMigrationNegotiated)) {
        return QUIC_STATUS_INVALID_STATE;
    }

    //
    // Some mechanism for telling the peer has to be in play, or a bound
    // address is a declaration nothing can carry. This used to be the
    // nat_traverse transport parameter, which #173 retired along with its
    // frame; the two that remain are the ones that actually advertise:
    // ALTERNATIVE_ADDRESS when the peer offered that parameter, and the older
    // ADD_ADDRESS when it did not, which in practice means a client whose peer
    // negotiated server migration.
    //
    // QuicConnAddBoundAddress picks between them at the end of this function,
    // so the test here is simply "is either available".
    //
    if (!Connection->State.AlternativeAddressNegotiated &&
        !Connection->State.ServerMigrationNegotiated) {
        return QUIC_STATUS_INVALID_STATE;
    }

    QUIC_BOUND_ADDRESS_LIST_ENTRY* Bound = NULL;
    for (CXPLAT_LIST_ENTRY* Entry = Connection->BoundAddresses.Flink;
            Entry != &Connection->BoundAddresses;
            Entry = Entry->Flink) {
        Bound =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_BOUND_ADDRESS_LIST_ENTRY,
                Link);
        if (QuicAddrCompare(&Bound->Address, Param->LocalAddress)) {
            break;
        }
        Bound = NULL;
    }

    if (Bound == NULL) {
        return QUIC_STATUS_NOT_FOUND;
    }

    CxPlatCopyMemory(&Bound->ObservedAddress, Param->ObservedAddress, sizeof(QUIC_ADDR));
    Bound->ObservedAddressSet = TRUE;

    QuicTraceEvent(
        ConnObservedAddrAdded,
        "[conn][%p] New Observed IP: %!ADDR! for Bound IP: %!ADDR!",
        Connection,
        CASTED_CLOG_BYTEARRAY(sizeof(Bound->ObservedAddress), &Bound->ObservedAddress),
        CASTED_CLOG_BYTEARRAY(sizeof(Bound->Address), &Bound->Address));

    Bound->SequenceNumber = Connection->AddAddressSequenceNumber++;
    Bound->SequenceNumberValid = TRUE;

    //
    // One mechanism or the other, never both. With the extension negotiated
    // the whole set goes out in a single ALTERNATIVE_ADDRESS frame, so the
    // per-address ADD_ADDRESS frame would be a second, redundant advertisement
    // of the same thing -- and the peer would have to reconcile two sets.
    //
    // The sequence number above is still assigned either way: the bound entry
    // is matched by it on the ADD_ADDRESS retransmission path, and leaving it
    // unset would make that lookup depend on which mechanism is in use.
    //
    //
    // Server only. The draft makes ALTERNATIVE_ADDRESS a server-to-client
    // frame, and a client has the flag set whenever it offered the parameter --
    // so without the role test a client advertising its own bound address
    // would send a frame the server is required to reject.
    //
    if (QuicConnIsServer(Connection) && Connection->State.AlternativeAddressNegotiated) {
        QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_ALTERNATIVE_ADDRESS);
    } else {
        Bound->SendAddAddress = TRUE;
        QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_ADD_ADDRESS);
    }

    return QUIC_STATUS_SUCCESS;
}

// Adds a new path to the connection.
_IRQL_requires_max_(PASSIVE_LEVEL)
static
QUIC_STATUS
QuicConnAddPath(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH_PARAM* Param,
    _In_ QUIC_PATH_ORIGIN Origin,
    _Out_ QUIC_PATH** NewPath
    )
{
    QUIC_PATH* Path = NULL;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    *NewPath = NULL;

    if (Param->LocalAddress == NULL || Param->RemoteAddress == NULL) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Done;
    }
    
    if (Connection->State.ClosedLocally) {
        Status = QUIC_STATUS_INVALID_STATE;
        goto Done;
    }

    if ((QuicConnIsClient(Connection) && Connection->Settings.ServerMigrationEnabled) ||
        (QuicConnIsClient(Connection) && Connection->State.ServerMigrationNegotiated) ||
        (QuicConnIsServer(Connection) && !Connection->State.ServerMigrationNegotiated)) {
        Status = QUIC_STATUS_INVALID_STATE;
        goto Done;
    }

    if (Connection->State.LocalAddressSet || Connection->State.RemoteAddressSet) {
        for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
            if (QuicAddrCompare(
                    &Connection->Paths[i].Route.LocalAddress,
                    Param->LocalAddress) &&
                QuicAddrCompare(
                    &Connection->Paths[i].Route.RemoteAddress,
                    Param->RemoteAddress)) {
                Status = QUIC_STATUS_ADDRESS_IN_USE;
                goto Done;
            }
        }
    }

    if (Connection->PathsCount == QUIC_MAX_PATH_COUNT) {
        //
        // Already tracking the maximum number of paths, and can't free
        // any more.
        //
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Done;
    }

    if (Connection->PathsCount > 1) {
        //
        // Make room for the new path (at index 1).
        //
        CxPlatMoveMemory(
            &Connection->Paths[2],
            &Connection->Paths[1],
            (Connection->PathsCount - 1) * sizeof(QUIC_PATH));
        if (Connection->State.MultipathNegotiated) {
            //
            // Update all PathID back references.
            //
            for (uint8_t i = 2; i < Connection->PathsCount + 1; ++i) {
                if (Connection->Paths[i].PathID != NULL) {
                    Connection->Paths[i].PathID->Path = &Connection->Paths[i];
                }
            }
        }
    }

    if (!Connection->State.LocalAddressSet && !Connection->State.RemoteAddressSet) {
        //
        // Before Start, this is not a second path at all: it is the connection
        // saying what addresses its handshake will use. So the origin is
        // deliberately not applied here -- Paths[0] stays INITIAL, because that
        // is what it still is.
        //
        Path = &Connection->Paths[0];
    } else {
        Path = &Connection->Paths[1];
        QuicPathInitialize(Connection, Path, Origin);
        Path->Allowance = UINT32_MAX;
        Connection->PathsCount++;
    }

    CxPlatCopyMemory(&Path->Route.LocalAddress, Param->LocalAddress, sizeof(QUIC_ADDR));
    CxPlatCopyMemory(&Path->Route.RemoteAddress, Param->RemoteAddress, sizeof(QUIC_ADDR));
    if (Path == &Connection->Paths[0]) {
        Connection->State.LocalAddressSet = TRUE;
        Connection->State.RemoteAddressSet = TRUE;
    }

    //
    // Open the path (create its UDP binding, assign a path id and start path
    // validation) as soon as the handshake is complete - i.e. once 1-RTT keys
    // exist and path challenges can be sent. Deferring all the way to handshake
    // *confirmation* is unnecessary and makes the open happen asynchronously,
    // after QuicConnAddPath has already returned success. A binding failure
    // (e.g. the requested local port is in use) would then be silent and
    // unrecoverable by the caller. Opening here surfaces such failures
    // synchronously so the caller can retry with a different address.
    //
    // Before the handshake completes (e.g. a path added before the connection
    // is started) the path is left pending and opened later by
    // QuicConnOpenNewPaths when the handshake is confirmed.
    //
    if (!Connection->State.Connected) {
        goto Done;
    }

    Status = QuicConnOpenNewPath(Connection, Path);
    if (QUIC_FAILED(Status)) {
        if (Path->Binding != NULL) {
            QuicLibraryReleaseBinding(Path->Binding);
            Path->Binding = NULL;
        }
        QuicPathRemove(Connection, 1);
        Path = NULL;
    }

Done:
    if (QUIC_SUCCEEDED(Status)) {
        CXPLAT_DBG_ASSERT(Path != NULL);
        *NewPath = Path;
    }
    return Status;
}

// Activates a new path for the connection.
_IRQL_requires_max_(PASSIVE_LEVEL)
static
QUIC_STATUS
QuicConnActivatePath(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH_PARAM* Param
    )
{
    if (Connection->State.ClosedLocally || !Connection->State.HandshakeConfirmed) {
        return QUIC_STATUS_INVALID_STATE;
    }

    if ((QuicConnIsClient(Connection) && Connection->State.ServerMigrationNegotiated) ||
        (QuicConnIsServer(Connection) && !Connection->State.ServerMigrationNegotiated)) {
        return QUIC_STATUS_INVALID_STATE;
    }

    // Check if the path already exists.
    QUIC_PATH* Path = QuicConnGetPathByAddress(
        Connection,
        Param->LocalAddress,
        Param->RemoteAddress);
    if (Path != NULL) {
        if (!Connection->State.MultipathNegotiated) {
            // If the path already exists, activate it.
            QuicPathSetActive(Connection, Path);
        } else {
            // If the path already exists, activate it and set the send flag to notify the peer.
            BOOLEAN PrevIsActive = Path->IsActive;
            Path->IsActive = TRUE;
            if (PrevIsActive != Path->IsActive) {
                Path->SendStatus = TRUE;
                QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PATH_AVAILABLE);
            }
        }
        return QUIC_STATUS_SUCCESS;
    }
    if (Connection->State.MultipathNegotiated) {
        // If the path doesn't exist and multipath is negotiated, we can't activate it.
        return QUIC_STATUS_NOT_FOUND;
    }

    // If the path doesn't exist, we try to create and activate it.
    QUIC_BINDING* OldBinding = Connection->Paths[0].Binding;

    CXPLAT_UDP_CONFIG UdpConfig = {0};
    UdpConfig.LocalAddress = Param->LocalAddress;
    UdpConfig.RemoteAddress = Param->RemoteAddress;
    UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
    UdpConfig.InterfaceIndex = 0;
#ifdef QUIC_COMPARTMENT_ID
    UdpConfig.CompartmentId = Connection->Configuration->CompartmentId;
#endif
#ifdef QUIC_OWNING_PROCESS
    UdpConfig.OwningProcess = Connection->Configuration->OwningProcess;
#endif
    if (Connection->State.ShareBinding) {
        UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_SHARE;
    }
    if (Connection->Settings.XdpEnabled) {
        UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_XDP;
    }
    if (Connection->Settings.QTIPEnabled) {
        UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_QTIP;
    }
    if (Connection->State.Partitioned) {
        UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_PARTITIONED;
    }

    QUIC_STATUS Status =
        QuicLibraryGetBinding(
            &UdpConfig,
            &Connection->Paths[0].Binding);
    if (QUIC_FAILED(Status)) {
        Connection->Paths[0].Binding = OldBinding;
        return Status;
    }

    if (!QuicConnRetireCurrentDestCid(Connection, &Connection->Paths[0])) {
        QuicLibraryReleaseBinding(Connection->Paths[0].Binding);
        Connection->Paths[0].Binding = OldBinding;
        Status = QUIC_STATUS_INVALID_STATE;
        return Status;
    }

    Connection->Paths[0].Route.State = RouteUnresolved;
    Connection->Paths[0].Route.Queue = NULL;

    //
    // TODO - Need to free any queued recv packets from old binding.
    //

    if (!Connection->State.ShareBinding) {
        if (!QuicBindingAddAllSourceConnectionIDs(Connection->Paths[0].Binding, Connection)) {
            QuicLibraryReleaseBinding(Connection->Paths[0].Binding);
            Connection->Paths[0].Binding = OldBinding;
            Status = QUIC_STATUS_OUT_OF_MEMORY;
            return Status;
        }
    } else {
        if (!QuicBindingAddAllSourceConnectionIDs(Connection->Paths[0].Binding, Connection)) {
            QuicConnGenerateNewSourceCids(Connection, TRUE);
        }
    }
    QuicBindingRemoveAllSourceConnectionIDs(OldBinding, Connection);
    QuicLibraryReleaseBinding(OldBinding);

    if (!QuicAddrCompare(&Connection->Paths[0].Route.LocalAddress, Param->LocalAddress)) {
        QuicTraceEvent(
            ConnLocalAddrRemoved,
            "[conn][%p] Removed Local IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].Route.LocalAddress), &Connection->Paths[0].Route.LocalAddress));

        QuicBindingGetLocalAddress(
            Connection->Paths[0].Binding,
            &Connection->Paths[0].Route.LocalAddress);

        QuicTraceEvent(
            ConnLocalAddrAdded,
            "[conn][%p] New Local IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].Route.LocalAddress), &Connection->Paths[0].Route.LocalAddress));
    }

    if (!QuicAddrCompare(&Connection->Paths[0].Route.RemoteAddress, Param->RemoteAddress)) {
        QuicTraceEvent(
            ConnRemoteAddrRemoved,
            "[conn][%p] Removed Remote IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].Route.RemoteAddress), &Connection->Paths[0].Route.RemoteAddress));

        QuicBindingGetRemoteAddress(
            Connection->Paths[0].Binding,
            &Connection->Paths[0].Route.RemoteAddress);

        QuicTraceEvent(
            ConnRemoteAddrAdded,
            "[conn][%p] New Remote IP: %!ADDR!",
            Connection,
            CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].Route.RemoteAddress), &Connection->Paths[0].Route.RemoteAddress));
    }

    QuicCongestionControlReset(&Connection->Paths[0].PathID->CongestionControl, FALSE);

    QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PING);
    return QUIC_STATUS_SUCCESS;
}

//
// Whether a destination CID is still referenced by a path other than this one.
//
// QuicConnGetPathForPacket hands a new path the active path's destination CID
// whenever the peer's CID is zero length -- the "TODO - Copy instead?" on that
// line -- and it does so without QUIC_CID_SET_PATH, which is what lets it past
// that macro's one-path-per-CID assertion. So a CID can genuinely be in use by
// two paths, and retiring it because one of them is going away takes it out
// from under the other.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
BOOLEAN
QuicConnDestCidUsedByAnotherPath(
    _In_ const QUIC_CONNECTION* Connection,
    _In_ const QUIC_PATH* Path,
    _In_ const QUIC_CID_LIST_ENTRY* DestCid
    )
{
    CXPLAT_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        if (&Connection->Paths[i] != Path &&
            Connection->Paths[i].DestCid == DestCid) {
            return TRUE;
        }
    }
    return FALSE;
}

// Removes a bound address from the connection.
_IRQL_requires_max_(PASSIVE_LEVEL)
static
QUIC_STATUS
QuicConnRemoveBoundAddress(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_ADDR* Param
    )
{
    if (Connection->State.ClosedLocally || !Connection->State.HandshakeConfirmed) {
        return QUIC_STATUS_INVALID_STATE;
    }

    if ((QuicConnIsClient(Connection) && !Connection->State.ServerMigrationNegotiated) ||
        (QuicConnIsServer(Connection) && Connection->State.ServerMigrationNegotiated)) {
        return QUIC_STATUS_INVALID_STATE;
    }

    BOOLEAN BoundAddressRemoved = FALSE;
    QUIC_BOUND_ADDRESS_LIST_ENTRY* Bound = NULL;
    for (CXPLAT_LIST_ENTRY* Entry = Connection->BoundAddresses.Flink;
            Entry != &Connection->BoundAddresses;
            Entry = Entry->Flink) {
        Bound =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_BOUND_ADDRESS_LIST_ENTRY,
                Link);
        if (QuicAddrCompare(&Bound->Address, Param)) {
            break;
        }
        Bound = NULL;
    }

    if (Bound != NULL && !Bound->Removing) {
        if (Bound->Binding != NULL) {
            QuicBindingRemoveAllSourceConnectionIDs(Bound->Binding, Connection);
            QuicLibraryReleaseBinding(Bound->Binding);
            Bound->Binding = NULL;
        }

        if (Bound->SequenceNumberValid &&
            QuicConnIsServer(Connection) &&
            Connection->State.AlternativeAddressNegotiated) {
            //
            // Withdrawn by omission: the entry is marked Removing so the next
            // ALTERNATIVE_ADDRESS frame leaves it out, and that absence is the
            // whole message. There is no per-address withdrawal frame in this
            // draft, which is why the entry has to survive long enough to be
            // left out of one -- freeing it here would advertise nothing and
            // the peer would keep the address.
            //
            Bound->Removing = TRUE;
            //
            // The next frame encoded is the first that will omit this address,
            // and it will carry exactly this number -- the writer uses the
            // counter's current value and then increments. Acknowledging
            // anything older proves nothing about this withdrawal.
            //
            Bound->WithdrawnAtAltSequenceNumber = Connection->AltAddrNextSequenceNumber;
            QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_ALTERNATIVE_ADDRESS);
        } else if (Bound->SequenceNumberValid) {
            //
            // A sequence number means this entry was advertised by the older
            // ADD_ADDRESS frame, which is only used when ALTERNATIVE_ADDRESS
            // was not negotiated -- so withdrawing it by REMOVE_ADDRESS is
            // right exactly when that is still true.
            //
            CXPLAT_DBG_ASSERT(!Connection->State.AlternativeAddressNegotiated);
            Bound->SendRemoveAddress = TRUE;
            Bound->Removing = TRUE;
            QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_REMOVE_ADDRESS);
        } else {
            CxPlatListEntryRemove(&Bound->Link);
            Connection->BoundAddressesCount--;
            CXPLAT_FREE(Bound, QUIC_POOL_BOUND_ADDRESS_LIST);
        }
        BoundAddressRemoved = TRUE;
    }   

    //
    // NB: Traversing the array backwards is simpler and more efficient here due
    // to the array shifting that happens in QuicPathRemove.
    //
    BOOLEAN PathRemoved = FALSE;
    for (int16_t i = Connection->PathsCount - 1; i >= 0; --i) {
        if (QuicAddrCompare(
                &Connection->Paths[i].Route.LocalAddress,
                Param)) {
            QUIC_PATH* Path = &Connection->Paths[i];
            uint8_t RemovingPathIndex = (uint8_t)i;

            //
            // Not retired while another path still holds it. Retiring a shared
            // CID sends RETIRE_CONNECTION_ID for one the surviving path is
            // still using, and the acknowledgement then frees it underneath
            // that path -- which is the assertion in
            // QuicLossDetectionOnPacketAcknowledged that #156 was.
            //
            if (Path->DestCid != NULL &&
                Connection->State.HandshakeConfirmed &&
                !QuicConnDestCidUsedByAnotherPath(Connection, Path, Path->DestCid)) {
                QuicPathIDRetireCid(Path->PathID, Path->DestCid);
            }

            if (Path->Binding != NULL) {
                QuicLibraryReleaseBinding(Path->Binding);
                Path->Binding = NULL;
            }

            if (Connection->PathsCount == 1) {
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Last Path Removed!");
                QuicConnSilentlyAbort(Connection);
                return QUIC_STATUS_ABORTED;
            }
            if (Path->IsActive) {
                // Server cannot remove an active path because it cannot switch to a new one.
                QuicTraceEvent(
                    ConnError,
                    "[conn][%p] ERROR, %s.",
                    Connection,
                    "Server cannot remove an active path");
                QuicConnSilentlyAbort(Connection);
                return QUIC_STATUS_ABORTED;
            }
            QuicPathRemove(Connection, RemovingPathIndex);
            PathRemoved = TRUE;
        }
    }

    if (!BoundAddressRemoved && !PathRemoved) {
        return QUIC_STATUS_NOT_FOUND;
    }

    return QUIC_STATUS_SUCCESS;
}

// Removes a path from the connection.
_IRQL_requires_max_(PASSIVE_LEVEL)
static
QUIC_STATUS
QuicConnRemovePath(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH_PARAM* Param
    )
{
    if (Connection->State.ClosedLocally) {
        return QUIC_STATUS_INVALID_STATE;
    }

    if ((QuicConnIsClient(Connection) && Connection->State.ServerMigrationNegotiated) ||
        (QuicConnIsServer(Connection) && !Connection->State.ServerMigrationNegotiated)) {
        return QUIC_STATUS_INVALID_STATE;
    }

    BOOLEAN PathFound = FALSE;
    //
    // NB: Traversing the array backwards is simpler and more efficient here due
    // to the array shifting that happens in QuicPathRemove.
    //
    for (int16_t i = Connection->PathsCount - 1; i >= 0; --i) {
        BOOLEAN LocalAddrMatch =
            (QuicAddrIsWildCard(Param->LocalAddress) && QuicAddrGetPort(Param->LocalAddress) == 0) ||
            (QuicAddrIsWildCard(Param->LocalAddress) &&
                QuicAddrGetPort(&Connection->Paths[i].Route.LocalAddress) ==
                    QuicAddrGetPort(Param->LocalAddress)) ||
            QuicAddrCompare(
                &Connection->Paths[i].Route.LocalAddress,
                Param->LocalAddress);

        BOOLEAN RemoteAddrMatch =
            (QuicAddrIsWildCard(Param->RemoteAddress) && QuicAddrGetPort(Param->RemoteAddress) == 0) ||
            (QuicAddrIsWildCard(Param->RemoteAddress) &&
                QuicAddrGetPort(&Connection->Paths[i].Route.RemoteAddress) ==
                    QuicAddrGetPort(Param->RemoteAddress)) ||
            QuicAddrCompare(
                &Connection->Paths[i].Route.RemoteAddress,
                Param->RemoteAddress);

        if (LocalAddrMatch && RemoteAddrMatch) {
            QUIC_PATH* Path = &Connection->Paths[i];
            PathFound = TRUE;

            if (!Connection->State.MultipathNegotiated) {
                uint8_t RemovingPathIndex = (uint8_t)i;
                //
                // The same shared-CID test QuicConnRemoveBoundAddress makes,
                // kept here for symmetry rather than because it can fire today.
                // Aliasing only happens in QuicConnGetPathForPacket, whose
                // creation gate is the exact complement of the role check at
                // the top of this function -- a connection that can hold an
                // aliased path cannot reach here -- and it also needs a
                // zero-length peer CID, which only a server sees. Retiring a
                // CID another path still uses would be wrong whichever function
                // did it, so the test belongs at both, but a reader should not
                // go looking for the case that reaches this one.
                //
                if (Path->DestCid != NULL &&
                    Connection->State.HandshakeConfirmed &&
                    !QuicConnDestCidUsedByAnotherPath(Connection, Path, Path->DestCid)) {
                    QuicPathIDRetireCid(Path->PathID, Path->DestCid);
                }

                if (Path->Binding != NULL) {
                    QuicBindingRemoveAllSourceConnectionIDs(Path->Binding, Connection);
                    QuicLibraryReleaseBinding(Path->Binding);
                    Path->Binding = NULL;
                }

                if (Connection->PathsCount == 1) {
                    if (QuicConnIsClient(Connection) && !Connection->State.Started) {
                        Connection->State.LocalAddressSet = FALSE;
                        Connection->State.RemoteAddressSet = FALSE;
                    } else {
                        QuicTraceEvent(
                            ConnError,
                            "[conn][%p] ERROR, %s.",
                            Connection,
                            "Last Path Removed!");
                        QuicConnSilentlyAbort(Connection);
                        return QUIC_STATUS_ABORTED;
                    }
                } else {
                    if (Path->IsActive) {
                        CXPLAT_DBG_ASSERT(i == 0);
                        if (QuicConnIsClient(Connection) && !Connection->State.Started) {
                            CXPLAT_DBG_ASSERT(Path->DestCid != NULL);
                            CXPLAT_DBG_ASSERT(!Path->DestCid->CID.Retired);
#if DEBUG
                            QUIC_CID_CLEAR_PATH(Path->DestCid);
#endif
                            // Move the dest CID to the new active path.
                            QUIC_CID_LIST_ENTRY* DestCid = Path->DestCid;
                            Path->DestCid = NULL;
                            QUIC_PATH* NewActivePath = &Connection->Paths[1];
                            NewActivePath->DestCid = DestCid;
                            QUIC_CID_SET_PATH(Connection, NewActivePath->DestCid, NewActivePath);

                            QuicPathSetActive(Connection, NewActivePath);
                            RemovingPathIndex = 1; // The removing path is now at index 1.
                        } else if (!Connection->State.HandshakeConfirmed) {
                            QuicTraceEvent(
                                ConnError,
                                "[conn][%p] ERROR, %s.",
                                Connection,
                                "Active Path Removed during Handshake!");
                            QuicConnSilentlyAbort(Connection);
                            return QUIC_STATUS_ABORTED;
                        } else {
                            uint8_t NewActivePathIndex = Connection->PathsCount;
                            for (uint8_t j = 1; j < Connection->PathsCount; ++j) {
                                if (Connection->Paths[j].DestCid != NULL) {
                                    NewActivePathIndex = j;
                                    break;
                                }
                            }
                            if (NewActivePathIndex == Connection->PathsCount) {
                                QuicTraceEvent(
                                    ConnError,
                                    "[conn][%p] ERROR, %s.",
                                    Connection,
                                    "No Active Path Remaining!");
                                QuicConnSilentlyAbort(Connection);
                                return QUIC_STATUS_ABORTED;
                            }
                            QUIC_PATH* NewActivePath = &Connection->Paths[NewActivePathIndex];
                            QuicPathSetActive(Connection, NewActivePath);
                            RemovingPathIndex = NewActivePathIndex; // The removing path is now at the new active index.
                        }
                    }
                    QuicPathRemove(Connection, RemovingPathIndex);
                }
            } else {
                Path->LocalClose = TRUE;
                //
                // PathID can be NULL for a path that never finished opening;
                // there is no abandon to send for a path ID it never got.
                //
                if (Path->PathID != NULL) {
                    Path->PathID->Flags.SendAbandon = TRUE;
                }
                QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PATH_ABANDON);
            }
        }
    }
    if (!PathFound) {
        return QUIC_STATUS_NOT_FOUND;
    }
    return QUIC_STATUS_SUCCESS;
}

// Adds a new candidate address for the connection.
_IRQL_requires_max_(PASSIVE_LEVEL)
static
QUIC_STATUS
QuicConnAddCandidateAddress(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CANDIDATE_ADDRESS* Param
    )
{
    if (QuicAddrIsWildCard(Param->HostAddress) ||
        QuicAddrGetPort(Param->HostAddress) == 0 ||
        QuicAddrIsWildCard(Param->ObservedAddress) ||
        QuicAddrGetPort(Param->ObservedAddress) == 0) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (Connection->State.ClosedLocally) {
        return QUIC_STATUS_INVALID_STATE;
    }

    if ((QuicConnIsClient(Connection) && Connection->State.ServerMigrationNegotiated) ||
        (QuicConnIsServer(Connection) && !Connection->State.ServerMigrationNegotiated)) {
        return QUIC_STATUS_INVALID_STATE;
    }

    for (CXPLAT_LIST_ENTRY* Entry = Connection->CandidateAddresses.Flink;
            Entry != &Connection->CandidateAddresses;
            Entry = Entry->Flink) {
        QUIC_CANDIDATE_ADDRESS_LIST_ENTRY* Candidate =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_CANDIDATE_ADDRESS_LIST_ENTRY,
                Link);
        if (!QuicAddrCompare(&Candidate->Address, Param->HostAddress) ||
            !QuicAddrCompare(&Candidate->ObservedAddress, Param->ObservedAddress)) {
            continue;
        }
        return QUIC_STATUS_ADDRESS_IN_USE;
    }

    QUIC_CANDIDATE_ADDRESS_LIST_ENTRY* Candidate =
        (QUIC_CANDIDATE_ADDRESS_LIST_ENTRY*)
        CXPLAT_ALLOC_NONPAGED(
            sizeof(QUIC_CANDIDATE_ADDRESS_LIST_ENTRY),
            QUIC_POOL_CANDIDATE_ADDRESS_LIST);
    if (Candidate == NULL) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    CxPlatCopyMemory(&Candidate->Address, Param->HostAddress, sizeof(QUIC_ADDR));
    CxPlatCopyMemory(&Candidate->ObservedAddress, Param->ObservedAddress, sizeof(QUIC_ADDR));

    CxPlatListInsertTail(&Connection->CandidateAddresses, &Candidate->Link);

    //
    // A candidate changes which pairs the reconciler may open a path for, so
    // the table has to be reconsidered. This matters as of #173: before it,
    // candidates were read when a punch request was written and nothing else
    // depended on them, so a late addition cost nothing. Now NAT traversal
    // refuses a pair that has no candidate -- so without this, adding one
    // after the server's advertised set arrived would leave the pair refused
    // until some unrelated event happened to trigger a pass, and against a
    // server that advertised nothing further, forever.
    //
    // Queued for AUTO as well, where it is merely harmless: the table is
    // rebuilt from current state, so a pass that changes nothing costs one
    // operation.
    //
    QuicConnQueueReconcile(Connection);

    return QUIC_STATUS_SUCCESS;
}

// Removes a candidate address from the connection.
_IRQL_requires_max_(PASSIVE_LEVEL)
static
QUIC_STATUS
QuicConnRemoveCandidateAddress(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CANDIDATE_ADDRESS* Param
    )
{
    if (Connection->State.ClosedLocally) {
        return QUIC_STATUS_INVALID_STATE;
    }

    if ((QuicConnIsClient(Connection) && Connection->State.ServerMigrationNegotiated) ||
        (QuicConnIsServer(Connection) && !Connection->State.ServerMigrationNegotiated)) {
        return QUIC_STATUS_INVALID_STATE;
    }

    QUIC_CANDIDATE_ADDRESS_LIST_ENTRY* Candidate = NULL;
    for (CXPLAT_LIST_ENTRY* Entry = Connection->CandidateAddresses.Flink;
            Entry != &Connection->CandidateAddresses;
            Entry = Entry->Flink) {
        Candidate =
            CXPLAT_CONTAINING_RECORD(
                Entry,
                QUIC_CANDIDATE_ADDRESS_LIST_ENTRY,
                Link);
        if (QuicAddrCompare(&Candidate->Address, Param->HostAddress) &&
            QuicAddrCompare(&Candidate->ObservedAddress, Param->ObservedAddress)) {
            break;
        }
        Candidate = NULL;
    }

    if (Candidate == NULL) {
        return QUIC_STATUS_NOT_FOUND;
    }

    CxPlatListEntryRemove(&Candidate->Link);
    CXPLAT_FREE(Candidate, QUIC_POOL_CANDIDATE_ADDRESS_LIST);

    //
    // A candidate changes which pairs the reconciler may open a path for, so
    // the table has to be reconsidered. This matters as of #173: before it,
    // candidates were read when a punch request was written and nothing else
    // depended on them, so a late addition cost nothing. Now NAT traversal
    // refuses a pair that has no candidate -- so without this, adding one
    // after the server's advertised set arrived would leave the pair refused
    // until some unrelated event happened to trigger a pass, and against a
    // server that advertised nothing further, forever.
    //
    // Queued for AUTO as well, where it is merely harmless: the table is
    // rebuilt from current state, so a pass that changes nothing costs one
    // operation.
    //
    QuicConnQueueReconcile(Connection);

    return QUIC_STATUS_SUCCESS;
}

// Processes an ADD_ADDRESS frame from the peer.
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnProcessAddAddress(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_ADD_ADDRESS_EX* Frame
    )
{
    if (Connection->State.ClosedLocally) {
        return QUIC_STATUS_INVALID_STATE;
    }

    if ((QuicConnIsClient(Connection) && Connection->State.ServerMigrationNegotiated) ||
        (QuicConnIsServer(Connection) && !Connection->State.ServerMigrationNegotiated)) {
        return QUIC_STATUS_INVALID_STATE;
    }

    if (Connection->Settings.AddAddressMode == QUIC_ADD_ADDRESS_MANUAL) {
        QUIC_CONNECTION_EVENT Event;
        Event.Type = QUIC_CONNECTION_EVENT_NOTIFY_REMOTE_ADDRESS_ADDED;
        Event.NOTIFY_REMOTE_ADDRESS_ADDED.Address = &Frame->Address;
        Event.NOTIFY_REMOTE_ADDRESS_ADDED.SequenceNumber = Frame->SequenceNumber;
        QuicTraceLogConnVerbose(
            IndicateNotifyRemoteAddressAdded,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_NOTIFY_REMOTE_ADDRESS_ADDED");
        (void)QuicConnIndicateEvent(Connection, &Event);
        return QUIC_STATUS_SUCCESS;
    }

    QUIC_ADDR LocalAddress = {0};

    //
    // PEER, not RECONCILER. This is reached from the legacy ADD_ADDRESS frames,
    // which produce no pair the candidate pair table can hold -- nothing
    // records these remotes in AltAddrs. Labelling them RECONCILER -- which
    // stage 2 of #157 did -- made them the one origin reconciliation is
    // allowed to delete, so the next pass tore down a path this handler had
    // just opened.
    //
    // NAT traversal used to arrive here too, for a local address taken from
    // the configured candidates. As of #173 it comes through the reconciler
    // with the rest, so what is left here is the fallback for a peer that
    // never agreed to alternative_address.
    //
    QUIC_PATH_PARAM PathParam = { &LocalAddress, &Frame->Address };
    QUIC_PATH* Path = NULL;
    QUIC_STATUS Status =
        QuicConnAddPath(Connection, &PathParam, QUIC_PATH_ORIGIN_PEER, &Path);
    if (QUIC_FAILED(Status)) {
        return Status;
    }

    //
    // Remembered so REMOVE_ADDRESS can find this path again: that frame names
    // an address by the sequence number ADD_ADDRESS gave it, and
    // QuicConnProcessRemoveAddressOper matches on exactly this field.
    //
    // Set for every path this handler opens, where it used to be set only in
    // the NAT-traversal branch -- so a path opened in any other mode could not
    // be withdrawn by the frame that is supposed to withdraw it. #173 removed
    // that branch, which would have left nothing setting it at all and the
    // lookup matching nothing; setting it here is both what keeps the frame
    // working and what it should always have been.
    //
    Path->RemoteAddressSequenceNumber = Frame->SequenceNumber;
    Path->RemoteAddressSequenceNumberValid = TRUE;

    if (QuicConnManagesPathsAutomatically(Connection) && Path->DestCid != NULL) {
        QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PATH_CHALLENGE);
    }

    return QUIC_STATUS_SUCCESS;
}

//
// Applies one address the peer has just started advertising, by handing it to
// the same code the per-address ADD_ADDRESS frame uses. Synthesizing the frame
// rather than refactoring that function is deliberate: the two drafts differ
// in how an address arrives, not in what should happen to it, and sharing the
// body keeps AUTO, MANUAL and NAT_TRAVERSAL behaving identically either way.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
QUIC_STATUS
QuicConnAltAddrApplyAdded(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_ADDR* Address,
    _In_ QUIC_VAR_INT SequenceNumber
    )
{
    QUIC_ADD_ADDRESS_EX Added;
    CxPlatZeroMemory(&Added, sizeof(Added));
    Added.SequenceNumber = SequenceNumber;
    Added.Address = *Address;
    return QuicConnProcessAddAddress(Connection, &Added);
}

//
// Asks for a rebuild on the connection's worker.
//
// Queued rather than done where the change is noticed, because
// QuicConnProcessAlternativeAddress runs synchronously inside
// QuicConnRecvFrames. Rebuilding there would put the address-snapshot copy --
// and, once stage 3 turns them on, a route lookup per remote, each a socket,
// connect and getsockname -- inline in packet processing, where a peer can
// decide how often it happens by putting several ALTERNATIVE_ADDRESS frames in
// one packet. One coalesced pass per worker visit instead, which is also where
// #157 says the reconciler has to live.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnQueueReconcile(
    _In_ QUIC_CONNECTION* Connection
    )
{
    //
    // QMux is excluded here, at the one place the operation is queued, rather
    // than at each of the nine callers or at the dereferences themselves --
    // the same choice QuicConnQueueLocalAddressChange records for the address
    // monitor. QuicConnReconcilePaths is reached only through this operation,
    // so this is the whole of it.
    //
    // It has to be excluded somewhere: QuicConnQMuxAlloc never allocates a
    // path ID, and the reconciler builds a candidate pair table and calls
    // QuicConnAddPath, which dereferences one. crypto.c queues a pass
    // unconditionally when the handshake completes, so every QMux connection
    // would reach it.
    //
    // Inert is also the correct behaviour and not merely the safe one: the
    // table pairs local addresses with remote ones to pick a UDP path, and a
    // QMux connection runs over a TCP channel whose addressing it does not own.
    //
    if (QuicConnIsQMux(Connection) ||
        Connection->State.ShutdownComplete ||
        Connection->State.Freed ||
        Connection->Worker == NULL ||
        Connection->CandidatePairsRebuildQueued) {
        return;
    }

    QUIC_OPERATION* Oper =
        QuicConnAllocOperation(Connection, QUIC_OPER_TYPE_RECONCILE_PATHS);
    if (Oper == NULL) {
        //
        // Dropped. The table is rebuilt from current state, so the next change
        // produces an equivalent pass; nothing accumulates.
        //
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "path reconciliation operation",
            0);
        return;
    }

    Connection->CandidatePairsRebuildQueued = TRUE;
    QuicConnQueueOper(Connection, Oper);
}

//
// Rebuilds the candidate pair table from the two inputs the connection has: the
// host's local addresses and the remote addresses it knows about.
//
// Nothing reads the table yet. It is built here so that the enumeration and the
// ordering are exercised by the existing tests before stage 3 of #157 makes
// paths follow it, rather than landing both at once.
//
// Runs on the connection's worker. It has to: the route lookup per remote
// address opens a socket and connects it, which is not something to do on a
// thread the platform is waiting on.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnRebuildCandidatePairs(
    _In_ QUIC_CONNECTION* Connection
    )
{
    Connection->CandidatePairsRebuildQueued = FALSE;
    Connection->CandidatePairsApproximate = FALSE;

    if (Connection->State.ShutdownComplete || Connection->Paths[0].Binding == NULL) {
        return;
    }

    CXPLAT_LOCAL_ADDRESS* Locals = NULL;
    uint32_t LocalCount = 0;
    CXPLAT_LOCAL_ADDRESS* Removed = NULL;
    uint32_t RemovedCount = 0;
    uint64_t Generation = 0;
    uint64_t RouteGeneration = 0;
    if (QUIC_FAILED(
            QuicLibraryGetLocalAddresses(
                &Locals, &LocalCount, &Removed, &RemovedCount, &Generation,
                &RouteGeneration))) {
        return;
    }
    if (Removed != NULL) {
        CXPLAT_FREE(Removed, QUIC_POOL_DATAPATH_ADDRESSES);
    }
    //
    // Locals is the working set from here on and may point at the stack array
    // built below; Allocated is the only thing that is ever freed.
    //
    CXPLAT_LOCAL_ADDRESS* Allocated = Locals;
    CXPLAT_LOCAL_ADDRESS Fallback[QUIC_MAX_ALTERNATIVE_ADDRESSES + 2];

    //
    // The remotes: the one the connection is on, plus everything the peer
    // advertised. The current path's remote is not in the advertised set --
    // the draft's CURRENT_PATH sentinel stands for it -- but it has to be a
    // candidate, or stage 3 would read the table as "remove the active path".
    //
    QUIC_CANDIDATE_REMOTE Remotes[QUIC_MAX_ALTERNATIVE_ADDRESSES + 1];
    CxPlatZeroMemory(Remotes, sizeof(Remotes));
    uint32_t RemoteCount = 0;

    Remotes[RemoteCount].Address = Connection->Paths[0].Route.RemoteAddress;
    Remotes[RemoteCount].SentinelRank = QUIC_CANDIDATE_CURRENT;
    Remotes[RemoteCount].PriorityHint = 0;
    RemoteCount++;

    //
    // The advertised set joins the table in the modes that act on it, which
    // since stage 5 means AUTO and NAT_TRAVERSAL. MANUAL still records it, in
    // order to report it, but a pair in the table is a pair the reconciler may
    // open a path for and in MANUAL it may not.
    //
    // NAT_TRAVERSAL was excluded when stage 3 wrote this, on the grounds that
    // it got its remotes from the older ADD_ADDRESS frames. Stage 5 puts the
    // mode on the table, so excluding them left it with nothing but the
    // current remote and therefore nothing to do.
    //
    const uint8_t AltAddrCount =
        QuicConnWantsCandidateTable(Connection) ? Connection->AltAddrCount : 0;
    CXPLAT_DBG_ASSERT(AltAddrCount <= QUIC_MAX_ALTERNATIVE_ADDRESSES);
    for (uint8_t i = 0; i < AltAddrCount; ++i) {
        //
        // Skipped if it is the current remote, which the peer can legitimately
        // advertise alongside the sentinel -- two entries for one address would
        // give it two sets of pairs.
        //
        if (QuicAddrCompare(&Connection->AltAddrs[i].Address, &Remotes[0].Address)) {
            continue;
        }
        if (RemoteCount >= ARRAYSIZE(Remotes)) {
            break;
        }
        Remotes[RemoteCount].Address = Connection->AltAddrs[i].Address;
        Remotes[RemoteCount].SentinelRank =
            Connection->AltAddrs[i].PreferredToCurrentPath ?
                QUIC_CANDIDATE_PREFERRED_TO_CURRENT : QUIC_CANDIDATE_BACKUP;
        Remotes[RemoteCount].PriorityHint = Connection->AltAddrs[i].PriorityHint;
        RemoteCount++;
    }

    //
    // The route lookup -- one per remote address, not per pair -- is where the
    // table's first ranking key comes from. Stage 1 deferred it to here on the
    // grounds that nothing read the table yet; now the reconciler does, so it
    // is paid.
    //
    // Each lookup opens a socket, connects it and reads the name back, so the
    // cost is bounded deliberately: once per remote rather than once per pair,
    // and only from this operation, never from frame processing. The remote
    // count is at most QUIC_MAX_ALTERNATIVE_ADDRESSES + 1, and the peer cannot
    // make this run more often than one coalesced pass per worker visit.
    //
    //
    // Bounded against the array as well as the count. RemoteCount cannot
    // exceed it -- it is one plus AltAddrCount, which the assert above pins --
    // but -O3 cannot see that through the two loops that built it, and gcc
    // turns the doubt into -Werror=stringop-overflow. Cheap, and true whatever
    // a future caller does to RemoteCount.
    //
    for (uint32_t i = 0; i < RemoteCount && i < ARRAYSIZE(Remotes); ++i) {
        Remotes[i].RoutePreferredLocalValid =
            QuicConnGetRouteLocalAddress(
                Connection, &Remotes[i].Address, &Remotes[i].RoutePreferredLocal);
    }

    //
    // No snapshot. Stage 5 made the monitor follow AddAddressMode, so this is
    // no longer the ordinary case it was -- but it is still reached. The
    // reference is taken when the settings are applied and the monitor
    // produces its first snapshot asynchronously, so an early pass can find
    // nothing; and a host with no usable address has nothing to report either.
    //
    // The local set instead falls back to the addresses this connection can be
    // shown to reach its remotes from: the active path's own local address,
    // plus whatever the route lookup above said it would send from to each
    // advertised remote. Which is why it has to be built here and not before
    // those lookups.
    //
    // The route-derived entries are the ones that matter. Pairing every
    // advertised remote with the active path's local address does not work and
    // is not what the old code did: a connection on 127.0.0.1 whose peer
    // advertises a routable address produces a pair the scope filter rightly
    // rejects, and nothing is left to open a path for. The old remote half
    // sidestepped this by opening the path with a wildcard local and letting
    // the OS choose. Asking the OS what it would choose, and recording that as
    // the pair, is the same answer with the pair actually named -- which is
    // what the table has to hold for a path to be matched back to it.
    //
    if (LocalCount == 0 || Locals == NULL) {
        uint32_t FallbackCount = 0;
        CxPlatZeroMemory(Fallback, sizeof(Fallback));

        for (uint32_t i = 0; i < RemoteCount && i < ARRAYSIZE(Remotes); ++i) {
            if (!Remotes[i].RoutePreferredLocalValid) {
                continue;
            }
            QUIC_ADDR Address = Remotes[i].RoutePreferredLocal;
            QuicAddrSetPort(&Address, 0);

            BOOLEAN Seen = FALSE;
            for (uint32_t k = 0; k < FallbackCount; ++k) {
                if (QuicAddrCompare(&Fallback[k].Address, &Address)) {
                    Seen = TRUE;
                    break;
                }
            }
            if (!Seen && FallbackCount < ARRAYSIZE(Fallback)) {
                Fallback[FallbackCount++].Address = Address;
            }
        }

        //
        // The active path's local address last, and only if it is a real one.
        // A wildcard names no interface, so it pairs with nothing the scope
        // filter can reason about, and a path opened on it would not be the
        // pair the table claimed to hold.
        //
        QUIC_ADDR Active = Connection->Paths[0].Route.LocalAddress;
        QuicAddrSetPort(&Active, 0);
        if (!QuicAddrIsWildCard(&Active)) {
            BOOLEAN Seen = FALSE;
            for (uint32_t k = 0; k < FallbackCount; ++k) {
                if (QuicAddrCompare(&Fallback[k].Address, &Active)) {
                    Seen = TRUE;
                    break;
                }
            }
            if (!Seen && FallbackCount < ARRAYSIZE(Fallback)) {
                Fallback[FallbackCount++].Address = Active;
            }
        }

        if (FallbackCount == 0) {
            //
            // Nothing to pair with. Emptied rather than left as it was, since
            // a stale entry is now a path.
            //
            if (Connection->CandidatePairs != NULL) {
                QuicCandidateSetInitialize(Connection->CandidatePairs);
            }
            //
            // And marked approximate, which the branch below does for the
            // weaker case and this one has to do for the stronger: no
            // snapshot, no route answer and a wildcard active local address is
            // the least information there is. Leaving the flag clear let the
            // removal step read an empty table as "remove the paths", which is
            // precisely what the flag exists to prevent.
            //
            Connection->CandidatePairsApproximate = TRUE;
            return;
        }

        //
        // Whether the fallback is only the active path's own address because no
        // route lookup answered. CxPlatDataPathGetLocalAddressForRemote is
        // unimplemented on winkernel, so in kernel mode with no snapshot that
        // is every pass, and the set collapses to one address whose scope
        // class need not match the advertised remotes -- the viability filter
        // would then reject them, the table would say "no pairs", and the
        // removal step would read that as "remove the paths".
        //
        // So the table is marked as not knowing enough to justify a removal.
        // It is still good enough to create from: a pair it does hold is one
        // the filter accepted. Removing anyway would turn a missing platform
        // call into torn-down paths.
        //
        //
        // Every remote, not just one of them. A table built on the fallback
        // can only say a pair is absent for the remotes it has an answer for;
        // for the rest its silence means "unknown", and the removal step
        // cannot tell the two apart. One advertised address whose lookup fails
        // transiently would otherwise have its path torn down -- retiring the
        // destination CID with it -- and reopened on the next pass.
        //
        BOOLEAN AllRoutes = TRUE;
        for (uint32_t i = 0; i < RemoteCount && i < ARRAYSIZE(Remotes); ++i) {
            if (!Remotes[i].RoutePreferredLocalValid) {
                AllRoutes = FALSE;
                break;
            }
        }
        Connection->CandidatePairsApproximate = !AllRoutes;

        //
        // No flags on any of these, which is honest: without the monitor there
        // is nothing that knows whether an address is deprecated or an RFC 8981
        // temporary one. The preferences that read those flags therefore have
        // nothing to say, and the route key -- which is the top one, and which
        // every one of these entries satisfies for its own remote -- does the
        // ordering instead.
        //
        Locals = Fallback;
        LocalCount = FallbackCount;
    }

    //
    // Whether the connection is currently on an RFC 8981 temporary address, so
    // that preference carries forward instead of being re-decided. Read from
    // the snapshot rather than the path, because only the snapshot has flags.
    //
    //
    // Compared on port-zeroed copies with QuicAddrCompare, not QuicAddrCompareIp:
    // that one branches on the first argument's family alone, so a v4 snapshot
    // entry against a v6 path address memcmps sin_addr against sin6_flowinfo and
    // can match two unrelated addresses -- which would take the privacy-address
    // preference from the wrong address and reorder the whole table.
    //
    QUIC_ADDR ActiveLocal = Connection->Paths[0].Route.LocalAddress;
    QuicAddrSetPort(&ActiveLocal, 0);
    BOOLEAN WantTemporary = FALSE;
    for (uint32_t i = 0; i < LocalCount; ++i) {
        QUIC_ADDR Candidate = Locals[i].Address;
        QuicAddrSetPort(&Candidate, 0);
        if (QuicAddrCompare(&Candidate, &ActiveLocal)) {
            WantTemporary = !!(Locals[i].Flags & CXPLAT_ADDRESS_FLAG_TEMPORARY);
            break;
        }
    }

    if (Connection->CandidatePairs == NULL) {
        Connection->CandidatePairs =
            CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_CANDIDATE_SET), QUIC_POOL_CONN);
        if (Connection->CandidatePairs == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "candidate pair table",
                (uint64_t)sizeof(QUIC_CANDIDATE_SET));
            if (Allocated != NULL) {
                CXPLAT_FREE(Allocated, QUIC_POOL_DATAPATH_ADDRESSES);
            }
            return;
        }
        QuicCandidateSetInitialize(Connection->CandidatePairs);
    }

    QuicCandidateSetRebuild(
        Connection->CandidatePairs,
        Locals,
        LocalCount,
        Remotes,
        RemoteCount,
        WantTemporary);

    QuicTraceLogConnVerbose(
        CandidatePairsRebuilt,
        Connection,
        "Candidate pairs rebuilt: %u locals x %u remotes -> %hhu pairs",
        LocalCount,
        RemoteCount,
        Connection->CandidatePairs->Count);

    if (Allocated != NULL) {
        CXPLAT_FREE(Allocated, QUIC_POOL_DATAPATH_ADDRESSES);
    }
}

//
// Whether a path's endpoints are one of the table's pairs.
//
// The local address is compared without its port and the remote address with
// it. A table entry's local address comes from the host's address snapshot,
// which names an address and carries no port; the path's names an endpoint
// whose port the binding chose. The remote is the other way round -- the port
// is part of what the peer advertised, so two entries differing only in port
// are two different places to send.
//
// QuicAddrCompare on port-zeroed copies rather than QuicAddrCompareIp, which
// branches on the first argument's family alone and would memcmp a v4 sin_addr
// against a v6 sin6_flowinfo.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
BOOLEAN
QuicConnCandidateSetHasPair(
    _In_ const QUIC_CANDIDATE_SET* Set,
    _In_ const QUIC_ADDR* Local,
    _In_ const QUIC_ADDR* Remote
    )
{
    QUIC_ADDR LocalNoPort = *Local;
    QuicAddrSetPort(&LocalNoPort, 0);

    for (CXPLAT_LIST_ENTRY* Link = Set->Pairs.Flink;
            Link != &Set->Pairs;
            Link = Link->Flink) {
        const QUIC_CANDIDATE_PAIR* Pair =
            CXPLAT_CONTAINING_RECORD(Link, QUIC_CANDIDATE_PAIR, Link);
        QUIC_ADDR PairLocal = Pair->LocalAddress;
        QuicAddrSetPort(&PairLocal, 0);
        if (QuicAddrCompare(&PairLocal, &LocalNoPort) &&
            QuicAddrCompare(&Pair->RemoteAddress, Remote)) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// Whether the connection already has a path realising this pair. The same
// comparison as above, read the other way round.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
BOOLEAN
QuicConnHasPathForPair(
    _In_ const QUIC_CONNECTION* Connection,
    _In_ const QUIC_ADDR* Local,
    _In_ const QUIC_ADDR* Remote
    )
{
    QUIC_ADDR LocalNoPort = *Local;
    QuicAddrSetPort(&LocalNoPort, 0);

    CXPLAT_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        if (Connection->Paths[i].Binding == NULL) {
            continue;
        }
        QUIC_ADDR PathLocal = Connection->Paths[i].Route.LocalAddress;
        QuicAddrSetPort(&PathLocal, 0);
        if (QuicAddrCompare(&PathLocal, &LocalNoPort) &&
            QuicAddrCompare(&Connection->Paths[i].Route.RemoteAddress, Remote)) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// Whether any path of this connection already sends to this remote address.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
BOOLEAN
QuicConnHasPathForRemote(
    _In_ const QUIC_CONNECTION* Connection,
    _In_ const QUIC_ADDR* Remote
    )
{
    CXPLAT_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        if (Connection->Paths[i].Binding != NULL &&
            QuicAddrCompare(&Connection->Paths[i].Route.RemoteAddress, Remote)) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// Step 2 of the reconciler: drop the paths the table no longer holds a pair
// for.
//
// Three things are never removed, and each for its own reason:
//
//  - paths this reconciler did not create. QUIC_PARAM_CONN_ADD_PATH is public
//    API, so an application can manage paths the table knows nothing about,
//    and reconciling them away would break it the moment AUTO were on. This is
//    what stage 2 recorded the origin for.
//  - Paths[0]. Replacing it is a migration -- stage 4's decision to make, from
//    the table's head, not a side effect of an address disappearing here.
//  - the last path. QuicConnRemovePath on a single path aborts the connection,
//    and a host that is briefly offline is not a failure.
//
// The work is collected first and removed afterwards, rather than rescanning
// after each removal. That is not a tidiness choice. Under multipath
// QuicConnRemovePath returns success *without* removing anything: it marks the
// path LocalClose, flags PATH_ABANDON, and the path leaves Connection->Paths
// only when the abandon completes. A rescan therefore finds the identical path
// still present, still absent from the table, removes it again, and spins
// forever on the connection's worker -- taking every connection on that worker
// with it. Collecting up front makes the pass finite whichever branch
// QuicConnRemovePath takes.
//
// Addresses are copied out for a related reason: QuicConnRemovePath can
// memmove the path array, so a QUIC_PATH* or an index taken before the call
// does not survive it.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
void
QuicConnReconcileRemovePaths(
    _In_ QUIC_CONNECTION* Connection
    )
{
    if (Connection->CandidatePairsApproximate) {
        //
        // The table was built without enough information to say that a pair is
        // absent rather than merely unknown. See the rebuild.
        //
        return;
    }

    const QUIC_CANDIDATE_SET* Set = Connection->CandidatePairs;

    QUIC_ADDR Locals[QUIC_MAX_PATH_COUNT];
    QUIC_ADDR Remotes[QUIC_MAX_PATH_COUNT];
    uint32_t Count = 0;

    //
    // From index 1, and deliberately without testing IsActive. Under multipath
    // several paths carry IsActive at once, so testing it would make every
    // working path unremovable -- which would quietly cost the pass its
    // removal step, and with it the ordering guarantee the whole operation
    // exists for. Without multipath only Paths[0] is ever active, so starting
    // at index 1 says the same thing. QuicConnAutoRemoveLostPaths, which
    // abandons paths for the same reason on the forced-migration side, draws
    // the line in exactly this place.
    //
    CXPLAT_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
    for (uint8_t i = 1; i < Connection->PathsCount; ++i) {
        const QUIC_PATH* Path = &Connection->Paths[i];
        if (Path->Binding == NULL ||
            Path->LocalClose ||
            Path->Origin != QUIC_PATH_ORIGIN_RECONCILER) {
            //
            // LocalClose means an abandon is already in flight, so asking
            // again would only send a second PATH_ABANDON.
            //
            continue;
        }
        if (QuicConnCandidateSetHasPair(
                Set, &Path->Route.LocalAddress, &Path->Route.RemoteAddress)) {
            continue;
        }

        CXPLAT_DBG_ASSERT(Count < QUIC_MAX_PATH_COUNT);
        Locals[Count] = Path->Route.LocalAddress;
        Remotes[Count] = Path->Route.RemoteAddress;
        Count++;
    }

    for (uint32_t i = 0; i < Count; ++i) {
        //
        // Re-checked each time rather than once: removing the previous one may
        // have been what took the count down to one.
        //
        if (Connection->PathsCount <= 1) {
            break;
        }

        QUIC_PATH_PARAM Param = { &Locals[i], &Remotes[i] };
        const QUIC_STATUS Status = QuicConnRemovePath(Connection, &Param);
        if (QUIC_FAILED(Status)) {
            QuicTraceLogConnWarning(
                ReconcileRemovePathFailed,
                Connection,
                "Reconciler failed to remove a path, status=0x%x",
                Status);
            continue;
        }
        QuicTraceLogConnInfo(
            ReconcileRemovedPath,
            Connection,
            "Reconciler removed a path whose pair left the table");
    }
}

//
// Step 3 of the reconciler: open paths for the best pairs that have none, in
// table order, while slots remain.
//
// Multipath decides how much of the table can become paths. With it, every
// pair is somewhere the connection can actually send, so the four slots go to
// the four best pairs and that is the cross product working.
//
// Whether a table pair is one this client can ask the server to punch for,
// and if so the address the request should name.
//
// Three conditions, and all three are about having something real to say:
//
//  - the extension is negotiated, so the frame is one the peer agreed to read;
//  - the pair's remote is an address the server actually advertised, because
//    that is what the server matches the request against -- it looks the
//    request up among the addresses it told us about, so naming anything else
//    is a frame it will ignore;
//  - the pair's local address has a configured candidate with an observed
//    address, because the request has to tell the server where to send, and
//    only the application knows how this client is seen from outside.
//
// The local addresses are compared by IP alone: a table pair's local carries
// no port, and the candidate is a host address rather than an endpoint.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnPunchableClientAddress(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress,
    _Out_ QUIC_ADDR* ClientAddress
    )
{
    CxPlatZeroMemory(ClientAddress, sizeof(*ClientAddress));

    if (!Connection->State.StatelessPunchNegotiated) {
        return FALSE;
    }

    BOOLEAN Advertised = FALSE;
    for (uint8_t i = 0; i < Connection->AltAddrCount; ++i) {
        if (QuicAddrCompare(&Connection->AltAddrs[i].Address, RemoteAddress)) {
            Advertised = TRUE;
            break;
        }
    }
    if (!Advertised) {
        return FALSE;
    }

    for (CXPLAT_LIST_ENTRY* Entry = Connection->CandidateAddresses.Flink;
            Entry != &Connection->CandidateAddresses;
            Entry = Entry->Flink) {
        const QUIC_CANDIDATE_ADDRESS_LIST_ENTRY* Candidate =
            CXPLAT_CONTAINING_RECORD(
                Entry, QUIC_CANDIDATE_ADDRESS_LIST_ENTRY, Link);

        if (!QuicAddrCompareIp(&Candidate->Address, LocalAddress)) {
            continue;
        }

        //
        // An observed address that is loopback, wildcard or portless is not
        // somewhere a server on the internet can send to, and the server's own
        // destination filter would refuse it anyway -- so the request is not
        // worth the packet. The older PUNCH_ME_NOW writer drops loopback at
        // write time for the same reason; deciding it here keeps a request
        // that will never be sent from being queued at all.
        //
        if (IS_LOOPBACK(Candidate->ObservedAddress) ||
            QuicAddrIsWildCard(&Candidate->ObservedAddress) ||
            QuicAddrGetPort(&Candidate->ObservedAddress) == 0) {
            continue;
        }

        //
        // And it has to be the same family as the server address it will be
        // paired with, because the frame type says which family both are.
        //
        if (QuicAddrGetFamily(&Candidate->ObservedAddress) !=
                QuicAddrGetFamily(RemoteAddress)) {
            continue;
        }

        *ClientAddress = Candidate->ObservedAddress;
        return TRUE;
    }

    return FALSE;
}

//
// Without it only one local address is in use at a time, so a second path is a
// validation candidate rather than somewhere traffic goes. One per remote
// address is therefore the limit: a pair that differs from an existing path
// only in its local address is a migration, which is stage 4's decision to
// make from the table's head and not something to pre-open a path for. That
// limit is also what the advertised-address behaviour has always been -- one
// probe path per address the server advertises -- so this keeps it rather than
// multiplying it by the host's address count.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
void
QuicConnReconcileCreatePaths(
    _In_ QUIC_CONNECTION* Connection
    )
{
    //
    // Rate-limited by AutoMigrationHoldDownMs, and the timer is what makes
    // that safe. A held-down pass otherwise has nowhere to put the work: it
    // returns, and the pair gets a path only when some unrelated change
    // happens to trigger another pass. That was the first version of this and
    // it showed immediately -- a server advertising three addresses in three
    // frames had the second wait not for the one-second window but for the
    // third frame to arrive, and against a server that advertised nothing
    // further it would have waited forever. So the window is a delay, not a
    // cancellation: the timer brings the pass back when it closes.
    //
    // Worth rate-limiting because each path costs a UDP binding and a
    // destination CID, and removing it retires that CID. A server that
    // alternates its advertised set, or an interface that flaps, would
    // otherwise drive binding churn and CID retirement as fast as it liked --
    // and retirement can outrun the peer's NEW_CONNECTION_ID issuance, which
    // leaves the connection unable to open any path at all.
    //
    const uint64_t RemainingUs = QuicConnAutoHoldDownRemainingUs(Connection);
    if (RemainingUs != 0) {
        QuicTraceLogConnVerbose(
            ReconcileCreateHeldDownFor,
            Connection,
            "Reconciler held down opening paths for %llu us",
            RemainingUs);
        QuicConnTimerSet(Connection, QUIC_CONN_TIMER_RECONCILE, RemainingUs);
        return;
    }

    const QUIC_CANDIDATE_SET* Set = Connection->CandidatePairs;
    BOOLEAN Created = FALSE;

    //
    // Walked in table order, so the slots go to the best pairs. The list is
    // not touched by QuicConnAddPath -- only Connection->Paths is -- so
    // iterating it across path creation is safe, which is the other reason the
    // pair-to-path mapping is derived by address rather than by index.
    //
    for (CXPLAT_LIST_ENTRY* Link = Set->Pairs.Flink;
            Link != &Set->Pairs;
            Link = Link->Flink) {
        if (Connection->PathsCount >= QUIC_MAX_PATH_COUNT) {
            break;
        }

        const QUIC_CANDIDATE_PAIR* Pair =
            CXPLAT_CONTAINING_RECORD(Link, QUIC_CANDIDATE_PAIR, Link);

        if (QuicConnHasPathForPair(
                Connection, &Pair->LocalAddress, &Pair->RemoteAddress)) {
            continue;
        }

        if (!Connection->State.MultipathNegotiated &&
            QuicConnHasPathForRemote(Connection, &Pair->RemoteAddress)) {
            //
            // Already reaching this remote, and without multipath a second
            // local address to it would be a migration. The table's order
            // decided which local address got here first, which is the part
            // worth having.
            //
            continue;
        }

        QUIC_ADDR PunchClientAddress;
        const BOOLEAN Punchable =
            QuicConnPunchableClientAddress(
                Connection,
                &Pair->LocalAddress,
                &Pair->RemoteAddress,
                &PunchClientAddress);

        //
        // NAT traversal is this one rule on top of AUTO: a pair becomes a path
        // only where the application configured a candidate for its local
        // address, because without one there is nothing to tell the server to
        // punch towards and the path would be a direct probe at an address
        // behind a NAT that has never heard of us.
        //
        // AUTO opens the path anyway and probes it directly, which is right
        // there: a pair with no candidate is still a pair worth trying when
        // both ends are reachable. The difference between the modes is this
        // test and nothing else -- #163 specified it as "table built, but a
        // pair produces no path unless a candidate is configured", and with
        // the table and the request frame both in place that is now literally
        // what it is.
        //
        if (!Punchable &&
            Connection->Settings.AddAddressMode == QUIC_ADD_ADDRESS_NAT_TRAVERSAL) {
            QuicTraceLogConnVerbose(
                ReconcileSkippedUnpunchablePair,
                Connection,
                "NAT traversal skipped a pair with no configured candidate");
            continue;
        }

        QUIC_ADDR Local = Pair->LocalAddress;
        QuicAddrSetPort(&Local, 0);
        QUIC_ADDR Remote = Pair->RemoteAddress;
        QUIC_PATH_PARAM Param = { &Local, &Remote };

        QUIC_PATH* NewPath = NULL;
        const QUIC_STATUS Status =
            QuicConnAddPath(Connection, &Param, QUIC_PATH_ORIGIN_RECONCILER, &NewPath);
        if (QUIC_FAILED(Status)) {
            //
            // Out of path IDs, out of CIDs, or the address would not bind.
            // Stop rather than work down the rest of the table: the next
            // reconciliation tries again, and the reasons this fails are not
            // specific to this pair. Broken out of rather than returned from,
            // so that paths opened earlier in this pass still charge the
            // hold-down below.
            //
            QuicTraceLogConnInfo(
                ReconcileAddPathFailed,
                Connection,
                "Reconciler could not open a path, status=0x%x",
                Status);
            break;
        }
        //
        // Arm the send loop, the same way QUIC_PARAM_CONN_ADD_PATH does.
        // QuicConnOpenNewPath sets the path's own SendChallenge and validation
        // timer, but the connection-level flag is what gets the send loop to
        // look; without it the challenge waits for an unrelated send.
        //
        if (Punchable) {
            //
            // Ask before probing. The server's binding for this pair does not
            // exist yet, so a PATH_CHALLENGE sent now arrives at a NAT with no
            // mapping for it and is dropped -- the attempt is spent for
            // nothing. The request goes out on the validated path this
            // connection is already using, and the probe waits for
            // QUIC_CONN_TIMER_PROBE_AFTER_PUNCH.
            //
            // One smoothed RTT of the relayed path, which is what the draft
            // recommends and what the older NAT-traversal code already did.
            // Appendix C.4 asks whether that is the right choice at all, or
            // whether probing immediately and leaning on PATH_CHALLENGE
            // retransmission would do better; it is left as it is, with the
            // trade written down: the validation clock starts when the path is
            // created, so this delay is spent out of the validation budget
            // rather than added to it.
            //
            // The request leaves on a validated path, which the draft
            // requires and which this gets for free rather than by arranging
            // it: the frame is written by QuicSendWriteFrames into the packet
            // QuicConnChoosePath picked, and that is Paths[0] without
            // multipath or an IsActive path with it. QuicPathInitialize zeroes
            // the path it is handed, so the path being punched for is not
            // IsActive and cannot be chosen until it validates. Worth stating
            // because nothing here enforces it.
            //
            NewPath->PunchClientAddress = PunchClientAddress;
            NewPath->SendStatelessPunch = TRUE;
            NewPath->StatelessPunchAttempt = TRUE;
            QuicSendSetSendFlag(
                &Connection->Send, QUIC_CONN_SEND_FLAG_STATELESS_PUNCH_ME_NOW);
            if (NewPath->DestCid != NULL) {
                QuicConnTimerSet(
                    Connection,
                    QUIC_CONN_TIMER_PROBE_AFTER_PUNCH,
                    Connection->Paths[0].SmoothedRtt);
            }
            QuicTraceLogConnInfo(
                PunchRequestQueued,
                Connection,
                "Queued a punch request for a table pair");
        } else if (NewPath != &Connection->Paths[0] && NewPath->DestCid != NULL) {
            QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PATH_CHALLENGE);
        }

        Created = TRUE;
        QuicTraceLogConnInfo(
            ReconcileAddedPath,
            Connection,
            "Reconciler opened a path for a table pair");
    }

    //
    // Charged once for the pass, not once per path. Filling the table's top
    // entries is one decision; charging each one would make four paths take
    // four windows to appear, which is the behaviour the timer above exists to
    // avoid rather than something to reintroduce here.
    //
    if (Created) {
        Connection->LastAutoMigrationTimeUs = CxPlatTimeUs64();
    }
}

//
// Step 4 of the reconciler: migrate onto the table's head when the server has
// said it would rather be reached there.
//
// Non-multipath only. With multipath every pair worth having is already a path
// and the peer's scheduler chooses between them, so there is nothing to
// migrate; step 3 has done the work.
//
// Only when the head of the table is PREFERRED_TO_CURRENT -- the server placed
// that address before the draft's CURRENT_PATH sentinel, which is it saying it
// would rather we used that than the path its frame arrived on. A head ranked
// CURRENT or BACKUP means the best thing available is where we already are, or
// is only a fallback, and neither is a reason to move a working connection.
//
// Note that the head can be a CURRENT pair even with a preferred address
// advertised, because the route-derived key outranks the sentinel: if routing
// says the interface we are on is the way to this peer, that beats the
// server's preference, and this does nothing. That is deliberate -- the server
// knows what it would like, the host knows what works.
//
// Make-before-break, which is why this only starts the attempt. The path in
// use still works, so there is no reason to move onto one the peer has not
// answered on yet; QuicConnAutoPathValidated records the answer and the next
// pass completes it through QuicConnAutoCompleteMigration.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
void
QuicConnReconcileMigrate(
    _In_ QUIC_CONNECTION* Connection
    )
{
    //
    // AUTO only. NAT_TRAVERSAL opens paths but does not migrate onto them on
    // the server's say-so: its paths exist to get through a NAT, and which one
    // carries traffic is the application's business there.
    //
    if (Connection->State.MultipathNegotiated ||
        !QuicConnManagesPathsAutomatically(Connection)) {
        return;
    }

    //
    // The completion half, first. Reached on the pass
    // QuicConnAutoPathValidated queued, and before the attempt below so that a
    // finished migration releases the markers rather than blocking the next
    // one for a whole pass.
    //
    if (Connection->MigrationReady &&
        Connection->MigrationReason == QUIC_MIGRATION_REASON_TABLE) {
        Connection->MigrationReady = FALSE;
        if (Connection->MigrationPending) {
            QUIC_PATH* Validated =
                QuicConnGetPathByLocalIp(
                    Connection,
                    &Connection->MigrationLocal,
                    &Connection->MigrationRemote);
            if (Validated != NULL && Validated->IsPeerValidated) {
                QuicConnAutoCompleteMigration(Connection, Validated);
            } else {
                //
                // The path went away between validating and this running, or
                // never really validated. The marker is dropped so a later
                // change is not blocked by it.
                //
                Connection->MigrationPending = FALSE;
            }
        }
        return;
    }

    //
    // A pending attempt whose path is gone had its validation time out, and
    // the validation timer took the path away. Released here, because that
    // timer does not know what the path was for and nothing else on this side
    // would ever clear the marker: with it set, the bail-out below returns on
    // every later pass, so one firewalled address the server advertised would
    // disable every future migration -- including route migrations, since the
    // markers are shared. QuicConnAutoFollowRoute does the same thing for its
    // own attempts, but only runs on a route change and only with the local
    // half in AUTO, which is not the default.
    //
    if (Connection->MigrationPending &&
        Connection->MigrationReason == QUIC_MIGRATION_REASON_TABLE &&
        QuicConnGetPathByLocalIp(
            Connection,
            &Connection->MigrationLocal,
            &Connection->MigrationRemote) == NULL) {
        QuicTraceLogConnInfo(
            ReconcileMigrateAbandoned,
            Connection,
            "Reconciler lost the path it was migrating onto");
        Connection->MigrationPending = FALSE;
    }

    //
    // One attempt at a time. The markers are shared with the route migration
    // for exactly this reason: two make-before-break attempts in flight would
    // fight over which path ends up active.
    //
    if (Connection->MigrationPending) {
        return;
    }

    if (Connection->CandidatePairs == NULL ||
        Connection->CandidatePairs->Count == 0) {
        return;
    }

    //
    // One migration per advertisement. See MigratedAtAltSequenceNumber: the
    // sentinel is a statement about the path the frame arrived on, so it is
    // spent once the connection has moved. Without this, every later pass --
    // and an address or route change is enough to cause one -- acts on the
    // same statement again and moves the connection to whichever marked
    // address it is not currently on.
    //
    if (!Connection->AltAddrPeerSequenceNumberValid ||
        (Connection->MigratedAtAltSequenceNumberValid &&
         Connection->AltAddrPeerSequenceNumber <=
             Connection->MigratedAtAltSequenceNumber)) {
        return;
    }

    const QUIC_CANDIDATE_PAIR* Head =
        CXPLAT_CONTAINING_RECORD(
            Connection->CandidatePairs->Pairs.Flink, QUIC_CANDIDATE_PAIR, Link);
    if (Head->SentinelRank != QUIC_CANDIDATE_PREFERRED_TO_CURRENT) {
        return;
    }

    //
    // Not straight back to where the last migration came from. One step of
    // history, which is what a two-address oscillation needs: having decided
    // to leave an address, the same advertised set is not a reason to return
    // to it. A genuinely new preference names a third address, or arrives
    // after a move that reset this.
    //
    // Deliberately not a full history. A three-address cycle would still
    // alternate, one move per advertisement -- bounded, since every move needs
    // a frame from the server, but not prevented. Tracking the whole set the
    // connection has acted on would prevent it, and is not worth the state for
    // a server that would have to be advertising three preferred addresses and
    // re-advertising them to achieve it.
    //
    if (Connection->MigratedFromRemoteValid &&
        QuicAddrCompare(&Head->RemoteAddress, &Connection->MigratedFromRemote)) {
        return;
    }

    //
    // Already there. Compared without the local port, as everywhere the table
    // meets a path: a table entry's local address comes from the address
    // snapshot and carries none.
    //
    QUIC_ADDR ActiveLocal = Connection->Paths[0].Route.LocalAddress;
    QuicAddrSetPort(&ActiveLocal, 0);
    QUIC_ADDR HeadLocal = Head->LocalAddress;
    QuicAddrSetPort(&HeadLocal, 0);
    if (QuicAddrCompare(&HeadLocal, &ActiveLocal) &&
        QuicAddrCompare(&Head->RemoteAddress, &Connection->Paths[0].Route.RemoteAddress)) {
        return;
    }

    //
    // Rate-limited, and charged at the attempt rather than the activation: a
    // server whose advertised set keeps moving would otherwise have this
    // opening a path per change while none of them ever got far enough to
    // count as a migration. The timer is what keeps a held-down attempt from
    // being lost, the same way it does for step 3.
    //
    const uint64_t RemainingUs = QuicConnAutoHoldDownRemainingUs(Connection);
    if (RemainingUs != 0) {
        QuicTraceLogConnVerbose(
            ReconcileMigrateHeldDown,
            Connection,
            "Reconciler held down migrating for %llu us",
            RemainingUs);
        QuicConnTimerSet(Connection, QUIC_CONN_TIMER_RECONCILE, RemainingUs);
        return;
    }

    //
    // Step 3 opens a path for every table pair it has room for, so the head's
    // path normally exists by the time this runs. When it does not -- no slot
    // was free, no destination CID was spare, the address would not bind --
    // there is nothing to migrate onto and nothing to do but wait for the next
    // pass, which tries step 3 again.
    //
    QUIC_PATH* Path =
        QuicConnGetPathByLocalIp(
            Connection, &Head->LocalAddress, &Head->RemoteAddress);
    if (Path == NULL) {
        QuicTraceLogConnVerbose(
            ReconcileMigrateNoPath,
            Connection,
            "Reconciler has no path yet for the pair it wants to migrate to");
        return;
    }
    if (Path == &Connection->Paths[0]) {
        //
        // The pair differs from Paths[0] by a port the comparison above
        // ignores. Nothing to do, and activating the active path would be a
        // no-op that still charged the hold-down.
        //
        return;
    }

    Connection->LastAutoMigrationTimeUs = CxPlatTimeUs64();
    Connection->MigrationLocal = Path->Route.LocalAddress;
    Connection->MigrationRemote = Path->Route.RemoteAddress;
    Connection->MigrationReason = QUIC_MIGRATION_REASON_TABLE;
    Connection->MigrationPending = TRUE;

    //
    // Marked spent at the attempt rather than at the activation, for the same
    // reason the hold-down is charged there: an attempt that does not finish
    // has still consumed the advertisement, and retrying it against the same
    // frame would be the oscillation this prevents.
    //
    Connection->MigratedAtAltSequenceNumber = Connection->AltAddrPeerSequenceNumber;
    Connection->MigratedAtAltSequenceNumberValid = TRUE;

    //
    // And where it came from, so the connection does not come straight back.
    // The sequence number alone does not hold: the writer numbers at encode
    // time and the loss handler re-arms the flag, so a retransmission of the
    // very same advertised set arrives with a higher number and authorises
    // another move. On a lossy path that is one bounce per loss event, which
    // is the oscillation again by a slower route.
    //
    Connection->MigratedFromRemote = Connection->Paths[0].Route.RemoteAddress;
    Connection->MigratedFromRemoteValid = TRUE;

    QuicTraceLogConnInfo(
        ReconcileMigrateStarted,
        Connection,
        "Reconciler started a migration onto the table's preferred pair");

    //
    // Validated already -- step 3 opened it on an earlier pass and the peer
    // has answered since -- so there is nothing to wait for.
    //
    if (Path->IsPeerValidated) {
        QuicConnAutoCompleteMigration(Connection, Path);
    }
}

//
// The reconciler. One pass: rebuild the table, remove the paths it no longer
// holds, then create paths for the best pairs that have none.
//
// That order is the point of the whole operation, not an implementation
// detail. Removal has to take effect synchronously before creation, which is
// exactly what was broken before: removals were queued while additions ran
// inline, so a frame that swapped one address for another at the path limit
// failed to add the new one. Both halves now happen in one pass with removal
// first, so the slot the departing address gives up is available to the
// arriving one.
//
// It runs only as a connection operation, never inline from frame processing.
// That is load-bearing twice over: it is what makes the ordering above
// possible, and it keeps path teardown out of QuicConnRecvFrames, where the
// caller goes on using a QUIC_PATH* across the call and a memmove of the array
// under it is the one thing the receive path cannot survive.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnReconcilePaths(
    _In_ QUIC_CONNECTION* Connection
    )
{
    Connection->CandidatePairsRebuildQueued = FALSE;

    //
    // Before the rebuild, not after it. Only AUTO asked for any of this, and
    // the rebuild is not cheap: a route lookup per remote address -- a socket,
    // a connect and a getsockname each -- a copy of the library's address
    // snapshot under a dispatch lock, and a kilobyte-and-a-half allocation for
    // the table itself. Handshake confirmation queues a pass unconditionally,
    // so with the gate below the rebuild every connection ever opened paid
    // that for a table nothing would read.
    //
    // Stage 1 said the table was worth building anyway, being "also the answer
    // to what could we do". That was true when the rebuild did no route
    // lookups. It stopped being true in stage 3, which turned them on.
    //
    if (!QuicConnWantsCandidateTable(Connection)) {
        return;
    }

    //
    // Client only, as of stage 6 of #157. The table answers "where should this
    // connection send from and to", which is the client's question: a server
    // sends from wherever the client reached it. A server's whole use of local
    // address detection is abandoning the paths whose address went away, which
    // QuicConnProcessLocalAddressChange does directly and without any of this.
    //
    // Previously this read as a server-migration test, which let a server that
    // had negotiated that extension build a table and reconcile paths. Nothing
    // wanted that: QuicConnAddPath is the only thing the table drives and a
    // server calling it is creating paths the client never asked for.
    //
    if (QuicConnIsServer(Connection)) {
        return;
    }

    //
    // And a client that handed path creation to the server has nothing to do
    // here either -- the path APIs reject its calls in that state, so every
    // pair in the table would fail one at a time.
    //
    if (Connection->Settings.ServerMigrationEnabled ||
        Connection->State.ServerMigrationNegotiated) {
        return;
    }

    QuicConnRebuildCandidatePairs(Connection);

    if (Connection->State.ShutdownComplete ||
        Connection->State.ClosedLocally ||
        Connection->CandidatePairs == NULL ||
        Connection->Paths[0].Binding == NULL) {
        return;
    }

    //
    // Before the handshake is confirmed there is nothing to reconcile: RFC 9000
    // section 9 does not allow migration. The table is still rebuilt above,
    // and QuicCryptoHandshakeConfirmed queues a pass of its own so that
    // whatever arrived early is acted on -- a claim that was wrong when first
    // written here, because no such pass existed and an ALTERNATIVE_ADDRESS
    // that beat HANDSHAKE_DONE was therefore dropped for good.
    //
    if (!Connection->State.HandshakeConfirmed) {
        return;
    }


    QuicConnReconcileRemovePaths(Connection);
    QuicConnReconcileCreatePaths(Connection);
    QuicConnReconcileMigrate(Connection);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnProcessAlternativeAddress(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_ALTERNATIVE_ADDRESS_EX* Frame
    )
{
    if (Connection->State.ClosedLocally) {
        return QUIC_STATUS_INVALID_STATE;
    }

    //
    // Server to client only. A server receiving one is a protocol violation
    // per the draft, and the caller turns this status into one.
    //
    if (QuicConnIsServer(Connection)) {
        return QUIC_STATUS_INVALID_STATE;
    }

    //
    // Not negotiated means the peer was never told it could send this, so the
    // frame is not one we agreed to parse.
    //
    if (!Connection->State.AlternativeAddressNegotiated) {
        return QUIC_STATUS_INVALID_STATE;
    }

    //
    // Stale or replayed. Ignored rather than failed: reordering is normal, and
    // the draft asks only that the older set not be applied.
    //
    if (Connection->AltAddrPeerSequenceNumberValid &&
        Frame->SequenceNumber <= Connection->AltAddrPeerSequenceNumber) {
        QuicTraceLogConnVerbose(
            AlternativeAddressStale,
            Connection,
            "Ignoring stale ALTERNATIVE_ADDRESS %llu (have %llu)",
            Frame->SequenceNumber,
            Connection->AltAddrPeerSequenceNumber);
        return QUIC_STATUS_SUCCESS;
    }
    Connection->AltAddrPeerSequenceNumber = Frame->SequenceNumber;
    Connection->AltAddrPeerSequenceNumberValid = TRUE;

    //
    // Which stored addresses the new set no longer contains. This loop now only
    // updates the stored set -- it opens and tears down nothing, and the
    // reconciliation queued at the end of this function is what acts on the
    // difference. That is what fixes the swap-at-the-limit case this comment
    // used to have to apologise for: removals were queued as operations while
    // the additions below ran QuicConnAddPath inline, so a frame swapping one
    // address for another at QUIC_MAX_PATH_COUNT failed to add the new one.
    //
    // Compared on the full endpoint, address and port both: the draft
    // advertises endpoints, two ports on one host are two different places to
    // send, and the path machinery already distinguishes them.
    //
    uint8_t Kept = 0;
    for (uint8_t i = 0; i < Connection->AltAddrCount; ++i) {
        uint8_t Match = Frame->AddressCount;
        for (uint8_t j = 0; j < Frame->AddressCount; ++j) {
            if (QuicAddrCompare(&Connection->AltAddrs[i].Address, &Frame->Addresses[j].Address)) {
                Match = j;
                break;
            }
        }
        const BOOLEAN StillAdvertised = Match != Frame->AddressCount;

        if (StillAdvertised) {
            //
            // Compacted in place, keeping the sequence number it was given, so
            // an address that stays advertised keeps naming the same path.
            //
            Connection->AltAddrs[Kept] = Connection->AltAddrs[i];
            //
            // The hint and the sentinel side are taken from the newest frame
            // though: the server can reorder its set, or move an address from
            // backup to preferred, without the address itself changing -- and
            // the candidate table ranks on exactly that.
            //
            // Using the index the search above already found rather than
            // scanning the frame a second time for the same entry.
            //
            Connection->AltAddrs[Kept].PriorityHint = Frame->Addresses[Match].PriorityHint;
            Connection->AltAddrs[Kept].PreferredToCurrentPath =
                Frame->Addresses[Match].PreferredToCurrentPath;
            Kept++;
            continue;
        }

        QuicTraceLogConnInfo(
            AlternativeAddressWithdrawn,
            Connection,
            "ALTERNATIVE_ADDRESS withdrew an address (seq %llu)",
            Connection->AltAddrs[i].SequenceNumber);

        if (Connection->Settings.AddAddressMode == QUIC_ADD_ADDRESS_MANUAL) {
            QUIC_CONNECTION_EVENT Event;
            Event.Type = QUIC_CONNECTION_EVENT_NOTIFY_REMOTE_ADDRESS_REMOVED;
            Event.NOTIFY_REMOTE_ADDRESS_REMOVED.SequenceNumber =
                Connection->AltAddrs[i].SequenceNumber;
            QuicTraceLogConnVerbose(
                IndicateNotifyRemoteAddressRemovedAlt,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_NOTIFY_REMOTE_ADDRESS_REMOVED");
            (void)QuicConnIndicateEvent(Connection, &Event);
        }
        //
        // Nothing else to do for AUTO. Dropping the entry from the stored set
        // is the whole action: the address stops appearing in the table on the
        // next rebuild, and the reconciler removes the path that pair had.
        //
        // This used to queue a per-address operation to tear that path down.
        // Two problems went away with it. The operation removed the path while
        // additions from the same frame had already run inline, so a frame
        // swapping one address for another at the path limit failed to add the
        // new one -- the slot was still occupied when the addition was tried
        // and free by the time anything noticed. And it matched paths by
        // address because the sequence numbers this receiver synthesised were
        // never put on a path outside NAT traversal, which is bookkeeping the
        // table does not need at all.
        //
    }
    Connection->AltAddrCount = Kept;

    //
    // Then whatever is new. Bounded by the stored array, which is the same
    // size as the frame's own limit, so the only way to run out is for the
    // peer to advertise more than this build tracks.
    //
    for (uint8_t j = 0; j < Frame->AddressCount; ++j) {
        BOOLEAN AlreadyKnown = FALSE;
        for (uint8_t i = 0; i < Connection->AltAddrCount; ++i) {
            if (QuicAddrCompare(&Connection->AltAddrs[i].Address, &Frame->Addresses[j].Address)) {
                AlreadyKnown = TRUE;
                break;
            }
        }
        if (AlreadyKnown) {
            continue;
        }

        if (Connection->AltAddrCount == QUIC_MAX_ALTERNATIVE_ADDRESSES) {
            QuicTraceLogConnWarning(
                AlternativeAddressFull,
                Connection,
                "ALTERNATIVE_ADDRESS advertised more addresses than tracked");
            break;
        }

        const QUIC_VAR_INT SequenceNumber = Connection->AddAddressSequenceNumber++;

        //
        // AUTO opens no path here. Recording the address is the whole action:
        // it joins the table on the next rebuild and the reconciler decides,
        // with the full picture, whether it is worth a path and which pair
        // should give one up for it. Deciding per frame could not do that --
        // it saw one address at a time and whatever paths happened to exist.
        //
        // MANUAL still goes through the ADD_ADDRESS machinery, which for that
        // mode is only the event: the application is the one that opens paths.
        //
        // NAT_TRAVERSAL used to as well, for the per-address sequence number
        // PUNCH_ME_NOW needs. Stage 5 moves it onto the table instead, so the
        // reconciler opens the path and punches. The older ADD_ADDRESS frames
        // still work through their own handler; what stops here is
        // synthesising one out of an ALTERNATIVE_ADDRESS entry, which would
        // open a second path for a pair the table already covers. #173 is
        // where the sequence number stops being needed at all.
        //
        if (QuicConnWantsAddressReports(Connection)) {
            const QUIC_STATUS Status =
                QuicConnAltAddrApplyAdded(
                    Connection, &Frame->Addresses[j].Address, SequenceNumber);
            if (QUIC_FAILED(Status)) {
                //
                // Left out of the stored set, so the next frame that still
                // advertises it is treated as a fresh addition and tries again.
                //
                // Recording it would be worse than it sounds: the only thing
                // the draft lets a server do is send its set again, and an
                // entry already in the stored set is skipped as known -- so an
                // address that failed once, because the path array was full or
                // no destination CID was spare, would never be attempted again
                // for the life of the connection even after room appeared.
                // Retrying is driven by the server's frames, not by a loop
                // here, so there is nothing to spin.
                //
                QuicTraceLogConnInfo(
                    AlternativeAddressAddFailed,
                    Connection,
                    "ALTERNATIVE_ADDRESS could not use an address, status=0x%x",
                    Status);
                continue;
            }
        }

        Connection->AltAddrs[Connection->AltAddrCount].Address = Frame->Addresses[j].Address;
        Connection->AltAddrs[Connection->AltAddrCount].SequenceNumber = SequenceNumber;
        Connection->AltAddrs[Connection->AltAddrCount].PriorityHint =
            Frame->Addresses[j].PriorityHint;
        Connection->AltAddrs[Connection->AltAddrCount].PreferredToCurrentPath =
            Frame->Addresses[j].PreferredToCurrentPath;
        Connection->AltAddrCount++;
    }

    //
    // The advertised set has changed, so the pairs it takes part in have too.
    // Queued, because this runs inside frame processing.
    //
    QuicConnQueueReconcile(Connection);

    return QUIC_STATUS_SUCCESS;
}

// Processes a REMOVE_ADDRESS frame from the peer.
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnProcessRemoveAddress(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_REMOVE_ADDRESS_EX* Frame
    )
{
    if (Connection->State.ClosedLocally) {
        return QUIC_STATUS_INVALID_STATE;
    }

    if ((QuicConnIsClient(Connection) && Connection->State.ServerMigrationNegotiated) ||
        (QuicConnIsServer(Connection) && !Connection->State.ServerMigrationNegotiated)) {
        return QUIC_STATUS_INVALID_STATE;
    }

    if (Connection->Settings.AddAddressMode == QUIC_ADD_ADDRESS_MANUAL) {
        QUIC_CONNECTION_EVENT Event;
        Event.Type = QUIC_CONNECTION_EVENT_NOTIFY_REMOTE_ADDRESS_REMOVED;
        Event.NOTIFY_REMOTE_ADDRESS_REMOVED.SequenceNumber = Frame->SequenceNumber;
        QuicTraceLogConnVerbose(
            IndicateNotifyRemoteAddressRemoved,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_NOTIFY_REMOTE_ADDRESS_REMOVED");
        (void)QuicConnIndicateEvent(Connection, &Event);
        return QUIC_STATUS_SUCCESS;
    }

    QUIC_OPERATION* Oper;
    if ((Oper = QuicConnAllocOperation(Connection, QUIC_OPER_TYPE_REMOVE_ADDRESS)) != NULL) {
        Oper->REMOVE_ADDRESS.SequenceNumber = Frame->SequenceNumber;
        QuicConnQueueOper(Connection, Oper);
    } else {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "remove address operation",
            0);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessRemoveAddressOper(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_VAR_INT SequenceNumber
    )
{
    uint8_t RemovingPathIndex = Connection->PathsCount;
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        if (Connection->Paths[i].RemoteAddressSequenceNumberValid &&
            Connection->Paths[i].RemoteAddressSequenceNumber == SequenceNumber) {
            RemovingPathIndex = i;
            break;
        }
    }

    if (RemovingPathIndex == Connection->PathsCount) {
        return;
    }
    QUIC_ADDR LocalAddress = {0};
    QUIC_PATH_PARAM PathParam = { &LocalAddress, &Connection->Paths[RemovingPathIndex].Route.RemoteAddress };
    QUIC_STATUS Status = QuicConnRemovePath(Connection, &PathParam);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            ConnErrorStatus,
            "[conn][%p] ERROR, %u, %s.",
            Connection,
            Status,
            "Process REMOVE_ADDRESS frame");
    }
}

//
// Whether a punch packet may be sent to this address at all.
//
// draft-kozuka-quic-stateless-punch section 5.1. The client chooses this
// address and the server sends an unauthenticated packet there, so it is the
// one place the mechanism could be turned into a way of reaching something it
// has no business reaching.
//
//  - MUST NOT: multicast, broadcast, unspecified. None of them is a peer.
//  - SHOULD NOT: loopback, link-local, or otherwise internally reachable.
//    Refused outright rather than made a policy knob, because a server with no
//    reason to punch towards its own host has no reason to offer the option.
//  - MAY refuse sensitive ports (RFC 9000 section 21.5.6). A short list of the
//    ports that make good amplifiers, which is what that section is about.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnPunchDestinationAllowed(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_ADDR* Address
    )
{
    const uint16_t Port = QuicAddrGetPort(Address);
    if (Port == 0 || QuicAddrIsWildCard(Address)) {
        QuicTraceLogConnVerbose(
            PunchDestinationRefused,
            Connection,
            "Refusing to punch towards an unspecified address");
        return FALSE;
    }

    if (QuicAddrGetFamily(Address) == QUIC_ADDRESS_FAMILY_INET) {
        //
        // Read as bytes, which is how QuicCandidateAddressIsLoopback reads the
        // same field and for the same reason: CxPlatByteSwapUint32 is an
        // unconditional bswap rather than an ntohl, so it would turn an
        // already-host-order address around on a big-endian host. The byte
        // order of a four-byte array is the one thing that does not change.
        //
        uint8_t Bytes[4];
        CxPlatCopyMemory(Bytes, &Address->Ipv4.sin_addr, sizeof(Bytes));
        //
        // 224/4 multicast, 255.255.255.255 broadcast, and 0/8 which names this
        // network rather than a host on it.
        //
        if ((Bytes[0] & 0xF0) == 0xE0 ||
            (Bytes[0] == 0xFF && Bytes[1] == 0xFF &&
             Bytes[2] == 0xFF && Bytes[3] == 0xFF) ||
            Bytes[0] == 0) {
            QuicTraceLogConnVerbose(
                PunchDestinationRefusedScope,
                Connection,
                "Refusing to punch towards a multicast or broadcast address");
            return FALSE;
        }
    } else if (Address->Ipv6.sin6_addr.s6_addr[0] == 0xFF) {
        QuicTraceLogConnVerbose(
            PunchDestinationRefusedScope,
            Connection,
            "Refusing to punch towards a multicast or broadcast address");
        return FALSE;
    }

    //
    // Reusing the predicates from the candidate pair table, which read scope
    // off the address rather than off a flag some platform set -- the same
    // reason they were written that way for #159.
    //
    if (QuicCandidateAddressIsLoopback(Address) ||
        QuicCandidateAddressIsLinkLocal(Address)) {
        QuicTraceLogConnVerbose(
            PunchDestinationRefusedLocal,
            Connection,
            "Refusing to punch towards a loopback or link-local address");
        return FALSE;
    }

    //
    // The ports RFC 9000 section 21.5.6 has in mind: ones where an unsolicited
    // datagram provokes a larger reply from something that is not a QUIC peer.
    // Not exhaustive and not meant to be -- it is a MAY, and the cost of the
    // list being short is bounded by everything above.
    //
    static const uint16_t SensitivePorts[] = {
        53,     // DNS
        123,    // NTP
        137,    // NetBIOS name service
        161,    // SNMP
        389,    // CLDAP
        1900,   // SSDP
        11211,  // memcached
    };
    for (uint32_t i = 0; i < ARRAYSIZE(SensitivePorts); ++i) {
        if (Port == SensitivePorts[i]) {
            QuicTraceLogConnVerbose(
                PunchDestinationRefusedPort,
                Connection,
                "Refusing to punch towards a sensitive port (%hu)",
                Port);
            return FALSE;
        }
    }

    return TRUE;
}

//
// Whether this connection's punch allowance has anything left in it.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnPunchRateAllows(
    _In_ QUIC_CONNECTION* Connection
    )
{
    const uint64_t Now = CxPlatTimeUs64();
    if (Connection->PunchWindowStartUs == 0 ||
        CxPlatTimeDiff64(Connection->PunchWindowStartUs, Now) >= QUIC_PUNCH_RATE_WINDOW_US) {
        Connection->PunchWindowStartUs = Now;
        Connection->PunchesInWindow = 0;
    }
    if (Connection->PunchesInWindow >= QUIC_PUNCH_RATE_LIMIT_PER_WINDOW) {
        QuicTraceLogConnVerbose(
            PunchRateLimited,
            Connection,
            "Punch rate limit reached, dropping the request");
        return FALSE;
    }
    Connection->PunchesInWindow++;
    return TRUE;
}

//
// Sends one punch packet, per draft-kozuka-quic-stateless-punch section 6.
//
// Opaque bytes behind a short header, not a protected 1-RTT packet, and that
// is the substantive choice here. The draft permits either -- "a single PING
// frame in a protected 1-RTT packet, or random bytes" -- and the second avoids
// a problem the first has in this implementation: QuicPacketBuilderFinalize
// hands every packet it builds to QuicLossDetectionOnPacketSent, so the
// existing QuicConnSendPunchProbe's packet is tracked for loss recovery and
// congestion control and would be retransmitted. Section 6 says a punch packet
// is none of those things and is never retransmitted. Random bytes have no
// packet number to track, so they satisfy that by construction rather than by
// unpicking the send path.
//
// To an observer the two are indistinguishable, which is the point of the short
// header and the random connection ID: section 11 wants the packet to look like
// ordinary traffic and to be uncorrelatable with the connection's other paths.
//
// Never larger than the packet that carried the request (section 5.1), so the
// mechanism cannot amplify by bytes any more than it can by packets.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
static
BOOLEAN
QuicConnSendStatelessPunch(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_BOUND_ADDRESS_LIST_ENTRY* Bound,
    _In_ const QUIC_ADDR* ClientAddress,
    _In_ uint16_t RequestPacketLength
    )
{
    //
    // Big enough for a short header and a random connection ID with a few
    // bytes after it, small enough never to exceed the request. A NAT needs a
    // datagram, not a large one.
    //
    const uint16_t MinLength = (uint16_t)(1 + MsQuicLib.CidTotalLength + 4);
    const uint16_t Cap = 64;
    uint16_t Length = RequestPacketLength < Cap ? RequestPacketLength : Cap;
    if (Length < MinLength) {
        //
        // The request arrived in a packet too small to answer within. Dropped
        // rather than answered over-size: the size bound is a MUST, and a
        // client that wants a punch can ask again in a larger packet.
        //
        QuicTraceLogConnVerbose(
            PunchRequestPacketTooSmall,
            Connection,
            "Punch request packet too small to answer within (%hu)",
            RequestPacketLength);
        return FALSE;
    }

    //
    // The frame's two addresses always share a family -- the frame type says
    // which -- and the entry was matched on the server one, so the client
    // address agrees with Bound->ObservedAddress. It need not agree with
    // Bound->Address, which is where the socket actually is: nothing stops an
    // application from reporting an observed address of the other family for a
    // bound address, and handing the datapath a local and remote of different
    // families is a platform-level failure rather than a QUIC-level one.
    //
    if (QuicAddrGetFamily(&Bound->Address) != QuicAddrGetFamily(ClientAddress)) {
        QuicTraceLogConnVerbose(
            PunchAddressFamilyMismatch,
            Connection,
            "Punch request address family does not match the bound address");
        return FALSE;
    }

    if (!QuicLibraryTryAddRefBinding(Bound->Binding)) {
        return FALSE;
    }
    QUIC_BINDING* Binding = Bound->Binding;

    CXPLAT_ROUTE Route = { 0 };
    CxPlatCopyMemory(&Route.LocalAddress, &Bound->Address, sizeof(QUIC_ADDR));
    CxPlatCopyMemory(&Route.RemoteAddress, ClientAddress, sizeof(QUIC_ADDR));

    //
    // The ordinary socket, named rather than left to the default. A zeroed
    // route is CXPLAT_DATAPATH_TYPE_UNKNOWN, and on a host where the raw
    // datapath is available CxPlatSendDataAlloc would choose it -- then
    // RawSocketSend asserts the route is resolved, which a route to an address
    // nothing has ever spoken to is not. Resolving it means neighbor discovery,
    // which pends, and a pended send has to be resumed from somewhere: state,
    // which is the one thing a stateless punch does not get to keep. The kernel
    // resolves this for us on the way out and forgets it afterwards, which is
    // the same bargain.
    //
    Route.DatapathType = CXPLAT_DATAPATH_TYPE_NORMAL;
    Route.State = RouteResolved;

    CXPLAT_SEND_CONFIG SendConfig = {
        &Route, Length, CXPLAT_ECN_NON_ECT, 0, CXPLAT_DSCP_CS0
    };
    CXPLAT_SEND_DATA* SendData = CxPlatSendDataAlloc(Binding->Socket, &SendConfig);
    if (SendData == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "punch packet",
            Length);
        QuicLibraryReleaseBinding(Binding);
        return FALSE;
    }

    QUIC_BUFFER* Datagram = CxPlatSendDataAllocBuffer(SendData, Length);
    if (Datagram == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "punch packet buffer",
            Length);
        CxPlatSendDataFree(SendData);
        QuicLibraryReleaseBinding(Binding);
        return FALSE;
    }

    //
    // Random throughout, then the first byte forced into the shape of a short
    // header: the long-header bit clear and the fixed bit set, so a middlebox
    // treats it as ordinary 1-RTT traffic. Everything after it -- the
    // connection ID included, which section 11 requires be unrelated to any
    // this connection uses -- stays random, which is what makes the packet
    // opaque.
    //
    CxPlatRandom(Length, Datagram->Buffer);
    Datagram->Buffer[0] = (uint8_t)((Datagram->Buffer[0] & 0x3F) | 0x40);

    QuicBindingSend(
        Binding,
        Connection->Partition,
        &Route,
        SendData,
        Length,
        1);

    QuicLibraryReleaseBinding(Binding);

    Connection->PunchesSent++;

    QuicTraceLogConnInfo(
        PunchPacketSent,
        Connection,
        "Sent a punch packet of %hu bytes",
        Length);

    return TRUE;
}


#define QUIC_CONN_BAD_START_STATE(CONN) (CONN->State.Started || CONN->State.ClosedLocally)

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnParamSet(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    QUIC_STATUS Status;
    QUIC_SETTINGS_INTERNAL InternalSettings = {0};

    switch (Param) {

    case QUIC_PARAM_CONN_LOCAL_ADDRESS: {

        if (BufferLength != sizeof(QUIC_ADDR)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (Connection->State.ClosedLocally || QuicConnIsServer(Connection)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        if (Connection->State.Started &&
            !Connection->State.HandshakeConfirmed) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        const QUIC_ADDR* LocalAddress = (const QUIC_ADDR*)Buffer;

        if (!QuicAddrIsValid(LocalAddress)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (!Connection->State.Started) {
            Connection->State.LocalAddressSet = TRUE;
            CxPlatCopyMemory(&Connection->Paths[0].Route.LocalAddress, Buffer, sizeof(QUIC_ADDR));
        } else {
            CXPLAT_DBG_ASSERT(Connection->State.RemoteAddressSet);
            QUIC_PATH* Path = QuicConnGetPathByAddress(Connection, LocalAddress, &Connection->Paths[0].Route.RemoteAddress);
            if (Path != NULL) {
                if (!Path->IsActive) {
                    QuicPathSetActive(Connection, Path);
                }
                Status = QUIC_STATUS_SUCCESS;
                break;
            }

            CXPLAT_DBG_ASSERT(Connection->Paths[0].Binding);
            CXPLAT_DBG_ASSERT(Connection->Configuration != NULL);

            QUIC_BINDING* OldBinding = Connection->Paths[0].Binding;

            CXPLAT_UDP_CONFIG UdpConfig = {0};
            UdpConfig.LocalAddress = LocalAddress;
            UdpConfig.RemoteAddress =
                Connection->State.UnconnectedSocket ? NULL : &Connection->Paths[0].Route.RemoteAddress;
            UdpConfig.Flags = CXPLAT_SOCKET_FLAG_NONE;
            UdpConfig.InterfaceIndex = 0;
#ifdef QUIC_COMPARTMENT_ID
            UdpConfig.CompartmentId = Connection->Configuration->CompartmentId;
#endif
#ifdef QUIC_OWNING_PROCESS
            UdpConfig.OwningProcess = Connection->Configuration->OwningProcess;
#endif
            if (Connection->State.ShareBinding) {
                UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_SHARE;
            }
            if (Connection->Settings.XdpEnabled) {
                UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_XDP;
            }
            if (Connection->Settings.QTIPEnabled) {
                UdpConfig.Flags |= CXPLAT_SOCKET_FLAG_QTIP;
            }
            Status =
                QuicLibraryGetBinding(
                    &UdpConfig,
                    &Connection->Paths[0].Binding);
            if (QUIC_FAILED(Status)) {
                Connection->Paths[0].Binding = OldBinding;
                break;
            }

            if (!QuicPathIDRetireCurrentDestCid(Connection->Paths[0].PathID, &Connection->Paths[0])) {
                QuicLibraryReleaseBinding(Connection->Paths[0].Binding);
                Connection->Paths[0].Binding = OldBinding;
                Status = QUIC_STATUS_INVALID_STATE;
                break;
            }

            Connection->Paths[0].Route.State = RouteUnresolved;
            Connection->Paths[0].Route.Queue = NULL;

            //
            // TODO - Need to free any queued recv packets from old binding.
            //

            if (!Connection->State.ShareBinding) {
                if (!QuicBindingAddAllSourceConnectionIDs(Connection->Paths[0].Binding, Connection)) {
                    QuicLibraryReleaseBinding(Connection->Paths[0].Binding);
                    Connection->Paths[0].Binding = OldBinding;
                    Status = QUIC_STATUS_OUT_OF_MEMORY;
                    break;
                }
            } else {
                if (!QuicBindingAddAllSourceConnectionIDs(Connection->Paths[0].Binding, Connection)) {
                    QuicPathIDSetGenerateNewSourceCids(&Connection->PathIDs, TRUE);
                }
            }
            QuicBindingRemoveAllSourceConnectionIDs(OldBinding, Connection);
            QuicLibraryReleaseBinding(OldBinding);

            QuicTraceEvent(
                ConnLocalAddrRemoved,
                "[conn][%p] Removed Local IP: %!ADDR!",
                Connection,
                CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].Route.LocalAddress), &Connection->Paths[0].Route.LocalAddress));

            QuicBindingGetLocalAddress(
                Connection->Paths[0].Binding,
                &Connection->Paths[0].Route.LocalAddress);

            QuicTraceEvent(
                ConnLocalAddrAdded,
                "[conn][%p] New Local IP: %!ADDR!",
                Connection,
                CASTED_CLOG_BYTEARRAY(sizeof(Connection->Paths[0].Route.LocalAddress), &Connection->Paths[0].Route.LocalAddress));

            QuicCongestionControlReset(&Connection->Paths[0].PathID->CongestionControl, FALSE);

            QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PING);
        }

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONN_REMOTE_ADDRESS:

        if (QUIC_CONN_BAD_START_STATE(Connection)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        if (BufferLength != sizeof(QUIC_ADDR) ||
            QuicAddrIsWildCard((QUIC_ADDR*)Buffer) ||
            QuicConnIsServer(Connection)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Connection->State.RemoteAddressSet = TRUE;
        CxPlatCopyMemory(&Connection->Paths[0].Route.RemoteAddress, Buffer, sizeof(QUIC_ADDR));
        //
        // Don't log new Remote address added here because it is logged when
        // the connection is started.
        //

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_SETTINGS:

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Status =
            QuicSettingsSettingsToInternal(
                BufferLength,
                (QUIC_SETTINGS*)Buffer,
                &InternalSettings);
        if (QUIC_FAILED(Status)) {
            break;
        }

        if (!QuicConnApplyNewSettings(
                Connection,
                TRUE,
                &InternalSettings)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        break;

    case QUIC_PARAM_CONN_VERSION_SETTINGS:

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Status =
            QuicSettingsVersionSettingsToInternal(
                BufferLength,
                (QUIC_VERSION_SETTINGS*)Buffer,
                &InternalSettings);
        if (QUIC_FAILED(Status)) {
            break;
        }

        if (!QuicConnApplyNewSettings(
                Connection,
                TRUE,
                &InternalSettings)) {
            QuicSettingsCleanup(&InternalSettings);
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }
        QuicSettingsCleanup(&InternalSettings);

        break;

    case QUIC_PARAM_CONN_SHARE_UDP_BINDING:

        if (BufferLength != sizeof(uint8_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (QUIC_CONN_BAD_START_STATE(Connection) ||
            QuicConnIsServer(Connection)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Connection->State.ShareBinding = *(uint8_t*)Buffer;

        QuicTraceLogConnInfo(
            UpdateShareBinding,
            Connection,
            "Updated ShareBinding = %hhu",
            Connection->State.ShareBinding);

        Status = QUIC_STATUS_SUCCESS;
        break;

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    case QUIC_PARAM_CONN_UNCONNECTED_UDP_SOCKET:

        if (BufferLength != sizeof(uint8_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (QUIC_CONN_BAD_START_STATE(Connection) ||
            QuicConnIsServer(Connection)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        if (*(uint8_t*)Buffer && !Connection->State.ShareBinding) {
            //
            // An unconnected socket receives datagrams from any remote address,
            // so the connection has to be identifiable by its connection ID
            // alone. That is only true when the binding is shared, which is what
            // gives the connection a non-zero length source connection ID.
            //
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Connection->State.UnconnectedSocket = *(uint8_t*)Buffer;

        QuicTraceLogConnInfo(
            UpdateUnconnectedSocket,
            Connection,
            "Updated UnconnectedSocket = %hhu",
            Connection->State.UnconnectedSocket);

        Status = QUIC_STATUS_SUCCESS;
        break;
#endif

    case QUIC_PARAM_CONN_CLOSE_REASON_PHRASE:

        if (BufferLength > QUIC_MAX_CONN_CLOSE_REASON_LENGTH) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        //
        // Require the reason to be null terminated.
        //
        if (Buffer && ((char*)Buffer)[BufferLength - 1] != 0) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        //
        // Free any old data.
        //
        if (Connection->CloseReasonPhrase != NULL) {
            CXPLAT_FREE(Connection->CloseReasonPhrase, QUIC_POOL_CLOSE_REASON);
        }

        //
        // Allocate new space.
        //
        Connection->CloseReasonPhrase =
            CXPLAT_ALLOC_NONPAGED(BufferLength, QUIC_POOL_CLOSE_REASON);

        if (Buffer && Connection->CloseReasonPhrase != NULL) {
            CxPlatCopyMemory(
                Connection->CloseReasonPhrase,
                Buffer,
                BufferLength);
            Status = QUIC_STATUS_SUCCESS;
        } else {
            Status = QUIC_STATUS_OUT_OF_MEMORY;
        }

        break;

    case QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME: {

        if (BufferLength != sizeof(QUIC_STREAM_SCHEDULING_SCHEME)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        QUIC_STREAM_SCHEDULING_SCHEME Scheme =
            *(QUIC_STREAM_SCHEDULING_SCHEME*)Buffer;

        if (Scheme >= QUIC_STREAM_SCHEDULING_SCHEME_COUNT) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Connection->State.UseRoundRobinStreamScheduling =
            Scheme == QUIC_STREAM_SCHEDULING_SCHEME_ROUND_ROBIN;

        QuicTraceLogConnInfo(
            UpdateStreamSchedulingScheme,
            Connection,
            "Updated Stream Scheduling Scheme = %u",
            (uint32_t)Scheme);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED:

        if (BufferLength != sizeof(BOOLEAN)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (QUIC_CONN_BAD_START_STATE(Connection)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Connection->Settings.DatagramReceiveEnabled = *(BOOLEAN*)Buffer;
        Connection->Settings.IsSet.DatagramReceiveEnabled = TRUE;
        Status = QUIC_STATUS_SUCCESS;

        QuicTraceLogConnVerbose(
            DatagramReceiveEnableUpdated,
            Connection,
            "Updated datagram receive enabled to %hhu",
            Connection->Settings.DatagramReceiveEnabled);

        break;

    case QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION:

        if (BufferLength != sizeof(BOOLEAN)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (QUIC_CONN_BAD_START_STATE(Connection)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        if (Connection->State.PeerTransportParameterValid &&
            (!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_DISABLE_1RTT_ENCRYPTION))) {
            //
            // The peer did't negotiate the feature.
            //
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Connection->State.Disable1RttEncrytion = *(BOOLEAN*)Buffer;
        Status = QUIC_STATUS_SUCCESS;

        QuicTraceLogConnVerbose(
            Disable1RttEncrytionUpdated,
            Connection,
            "Updated disable 1-RTT encrytption to %hhu",
            Connection->State.Disable1RttEncrytion);

        break;

    case QUIC_PARAM_CONN_RESUMPTION_TICKET: {
        if (BufferLength == 0 || Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }
        //
        // Must be set before the client connection is started.
        //

        if (QuicConnIsServer(Connection) ||
            QUIC_CONN_BAD_START_STATE(Connection)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Status =
            QuicCryptoDecodeClientTicket(
                Connection,
                (uint16_t)BufferLength,
                Buffer,
                &Connection->PeerTransportParams,
                !QuicConnIsQMux(Connection) ?
                    &Connection->Crypto.ResumptionTicket :
                    &QuicConnGetQMux(Connection)->ResumptionTicket,
                !QuicConnIsQMux(Connection) ?
                    &Connection->Crypto.ResumptionTicketLength :
                    &QuicConnGetQMux(Connection)->ResumptionTicketLength,
                &Connection->Stats.QuicVersion);
        if (QUIC_FAILED(Status)) {
            break;
        }

        QuicConnOnQuicVersionSet(Connection);
        Status = QuicConnProcessPeerTransportParameters(Connection, TRUE);
        CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
        if (QuicConnIsQMux(Connection)) {
            QuicConnGetQMux(Connection)->PermitEarlyData = TRUE;
        }

        break;
    }

    case QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID:
        if (BufferLength != sizeof(BOOLEAN) || Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        QuicCryptoCustomCertValidationComplete(
            &Connection->Crypto,
            *(BOOLEAN*)Buffer,
            QUIC_TLS_ALERT_CODE_BAD_CERTIFICATE);
        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_LOCAL_INTERFACE:

        if (BufferLength != sizeof(uint32_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (QuicConnIsServer(Connection) ||
            QUIC_CONN_BAD_START_STATE(Connection)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Connection->State.LocalInterfaceSet = TRUE;
        Connection->Paths[0].Route.LocalAddress.Ipv6.sin6_scope_id = *(uint32_t*)Buffer;

        QuicTraceLogConnInfo(
            LocalInterfaceSet,
            Connection,
            "Local interface set to %u",
            Connection->Paths[0].Route.LocalAddress.Ipv6.sin6_scope_id);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_TLS_SECRETS:

        if (BufferLength != sizeof(QUIC_TLS_SECRETS) || Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (QUIC_CONN_BAD_START_STATE(Connection)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Connection->TlsSecrets = (QUIC_TLS_SECRETS*)Buffer;
        CxPlatZeroMemory(Connection->TlsSecrets, sizeof(*Connection->TlsSecrets));
        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_CIBIR_ID: {

        if (QuicConnIsServer(Connection) ||
            QUIC_CONN_BAD_START_STATE(Connection)) {
            return QUIC_STATUS_INVALID_STATE;
        }
        if (!Connection->State.ShareBinding) {
            //
            // We aren't sharing the binding, and therefore we don't use source
            // connection IDs, so CIBIR is not supported.
            //
            return QUIC_STATUS_INVALID_STATE;
        }

        if (BufferLength > QUIC_MAX_CIBIR_LENGTH + 1) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        if (BufferLength == 0) {
            CxPlatZeroMemory(Connection->CibirId, sizeof(Connection->CibirId));
            return QUIC_STATUS_SUCCESS;
        }
        if (BufferLength < 2) { // Must have at least the offset and 1 byte of payload.
            return QUIC_STATUS_INVALID_PARAMETER;
        }

        if (((uint8_t*)Buffer)[0] != 0) {
            return QUIC_STATUS_NOT_SUPPORTED; // Not yet supproted.
        }

        Connection->CibirId[0] = (uint8_t)BufferLength - 1;
        memcpy(Connection->CibirId + 1, Buffer, BufferLength);

        QuicTraceLogConnInfo(
            CibirIdSetInfo,
            Connection,
            "CIBIR ID set (len %hhu, offset %hhu, id 0x%llx)",
            Connection->CibirId[0],
            Connection->CibirId[1],
            (unsigned long long)QuicCibirIdToUint64(
                Connection->CibirId + 2,
                Connection->CibirId[0]));

        return QUIC_STATUS_SUCCESS;
    }

    case QUIC_PARAM_CONN_SEND_DSCP: {
        if (BufferLength != sizeof(uint8_t) || Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        uint8_t DSCP = *(uint8_t*)Buffer;

        if (DSCP > CXPLAT_MAX_DSCP) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Connection->DSCP = DSCP;

        QuicTraceLogConnInfo(
            ConnDscpSet,
            Connection,
            "Connection DSCP set to %hhu",
            Connection->DSCP);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONN_CLOSE_ASYNC:
        if (BufferLength != sizeof(BOOLEAN)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (Connection->State.HandleClosed) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Connection->State.CloseAsync = *(BOOLEAN*)Buffer;
        Status = QUIC_STATUS_SUCCESS;

        QuicTraceLogConnVerbose(
            CloseAsyncUpdated,
            Connection,
            "Updated CloseAsync to %hhu",
            Connection->State.CloseAsync);

        break;

    case QUIC_PARAM_CONN_ADD_BOUND_ADDRESS: {

        if (BufferLength != sizeof(QUIC_ADDR) || Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }
        Status = QuicConnAddBoundAddress(Connection, (QUIC_ADDR*)Buffer);
        break;
    }

    case QUIC_PARAM_CONN_ADD_OBSERVED_ADDRESS: {

        if (BufferLength != sizeof(QUIC_ADD_OBSERVED_ADDRESS) || Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }
        Status = QuicConnAddObservedAddress(Connection, (QUIC_ADD_OBSERVED_ADDRESS*)Buffer);
        break;
    }

    case QUIC_PARAM_CONN_PREFER_OBSERVED_ADDRESS: {

        if (BufferLength != sizeof(QUIC_ADDR) || Buffer == NULL ||
            !QuicAddrIsValid((QUIC_ADDR*)Buffer)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Status = QUIC_STATUS_NOT_FOUND;
        for (CXPLAT_LIST_ENTRY* Entry = Connection->BoundAddresses.Flink;
                Entry != &Connection->BoundAddresses;
                Entry = Entry->Flink) {
            QUIC_BOUND_ADDRESS_LIST_ENTRY* Bound =
                CXPLAT_CONTAINING_RECORD(Entry, QUIC_BOUND_ADDRESS_LIST_ENTRY, Link);
            if (!Bound->ObservedAddressSet ||
                Bound->Removing ||
                !QuicAddrCompare(&Bound->ObservedAddress, (QUIC_ADDR*)Buffer)) {
                continue;
            }
            //
            // Server only, and only once negotiated -- the same test the other
            // place that arms this flag makes, and for the same reason. The
            // draft makes ALTERNATIVE_ADDRESS a server-to-client frame, and a
            // client has bound addresses with observed addresses of its own
            // whenever NAT traversal was negotiated. Arming the flag there
            // would send a frame the server is required to reject, which ends
            // the connection on a protocol violation.
            //
            if (!QuicConnIsServer(Connection) ||
                !Connection->State.AlternativeAddressNegotiated) {
                Status = QUIC_STATUS_INVALID_STATE;
                break;
            }

            Bound->PreferredToCurrentPath = TRUE;
            //
            // Re-armed, because the set the peer holds is now wrong in a way
            // only a new frame can correct: withdrawal in this draft is by
            // omission and preference is by position, so there is nothing
            // smaller to send than the whole set again.
            //
            QuicSendSetSendFlag(
                &Connection->Send, QUIC_CONN_SEND_FLAG_ALTERNATIVE_ADDRESS);
            Status = QUIC_STATUS_SUCCESS;
            break;
        }
        break;
    }

    case QUIC_PARAM_CONN_REMOVE_BOUND_ADDRESS: {
        if (BufferLength != sizeof(QUIC_ADDR) || Buffer == NULL ||
            !QuicAddrIsValid((QUIC_ADDR*)Buffer)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Status = QuicConnRemoveBoundAddress(Connection, (QUIC_ADDR*)Buffer);
        break;
    }

    case QUIC_PARAM_CONN_ADD_PATH: {

        if (BufferLength != sizeof(QUIC_PATH_PARAM) || Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }
        QUIC_PATH* Path = NULL;
        //
        // The application asked, so the application owns it: reconciliation
        // must leave this path alone.
        //
        Status =
            QuicConnAddPath(
                Connection, (QUIC_PATH_PARAM*)Buffer, QUIC_PATH_ORIGIN_APPLICATION, &Path);
        if (QUIC_FAILED(Status)) {
            break;
        }
        if (Path != &Connection->Paths[0] && Path->DestCid != NULL) {
            QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PATH_CHALLENGE);
        }

        break;
    }

    case QUIC_PARAM_CONN_ACTIVATE_PATH: {

        if (BufferLength != sizeof(QUIC_PATH_PARAM) || Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }
        //
        // Captured before the call so the indication below reports an actual
        // change. The application gets told either way -- whether the active
        // path moved because it asked or because AUTO did it.
        //
        const QUIC_ADDR PreviousLocal = Connection->Paths[0].Route.LocalAddress;
        Status = QuicConnActivatePath(Connection, (QUIC_PATH_PARAM*)Buffer);
        if (QUIC_SUCCEEDED(Status)) {
            QuicConnIndicateLocalAddressChanged(Connection, &PreviousLocal);
        }
        break;
    }

    case QUIC_PARAM_CONN_REMOVE_PATH: {

        if (BufferLength != sizeof(QUIC_PATH_PARAM) || Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Status = QuicConnRemovePath(Connection, (QUIC_PATH_PARAM*)Buffer);
        break;
    }

    case QUIC_PARAM_CONN_ADD_CANDIDATE_ADDRESS: {

        if (BufferLength != sizeof(QUIC_CANDIDATE_ADDRESS) || Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }
        Status = QuicConnAddCandidateAddress(Connection, (QUIC_CANDIDATE_ADDRESS*)Buffer);
        break;
    }

    case QUIC_PARAM_CONN_REMOVE_CANDIDATE_ADDRESS: {
        if (BufferLength != sizeof(QUIC_CANDIDATE_ADDRESS) || Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }
        Status = QuicConnRemoveCandidateAddress(Connection, (QUIC_CANDIDATE_ADDRESS*)Buffer);
        break;
    }

    case QUIC_PARAM_CONN_PATH_STATUS:
        if (BufferLength != sizeof(QUIC_PATH_STATUS)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (!Connection->State.MultipathNegotiated) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        QUIC_PATH_STATUS* PathStatus = (QUIC_PATH_STATUS*)Buffer;
        QUIC_PATH* Path = NULL;
        for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
            //
            // A path added via QUIC_PARAM_CONN_ADD_LOCAL_ADDRESS before the
            // handshake is confirmed has no PathID assigned yet; skip it.
            //
            if (Connection->Paths[i].PathID != NULL &&
                PathStatus->PathId == Connection->Paths[i].PathID->ID) {
                Path = &Connection->Paths[i];
                break;
            }
        }

        if (Path == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }
        BOOLEAN PrevIsActive = Path->IsActive;
        Path->IsActive = PathStatus->Active;
        if (PrevIsActive != Path->IsActive) {
            Path->SendStatus = TRUE;
            if (Path->IsActive) {
                QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PATH_AVAILABLE);
            } else {
                QuicSendSetSendFlag(&Connection->Send, QUIC_CONN_SEND_FLAG_PATH_BACKUP);
            }
        }
        Status = QUIC_STATUS_SUCCESS;
        break;

    //
    // Private
    //

    case QUIC_PARAM_CONN_FORCE_KEY_UPDATE:

        if (!Connection->State.Connected ||
            Connection->Paths[0].PathID->Packets[QUIC_ENCRYPT_LEVEL_1_RTT] == NULL ||
            Connection->Paths[0].PathID->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]->AwaitingKeyPhaseConfirmation ||
            !Connection->State.HandshakeConfirmed) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        QuicTraceLogConnVerbose(
            ForceKeyUpdate,
            Connection,
            "Forcing key update");

        Status = QuicCryptoGenerateNewKeys(Connection);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                ConnErrorStatus,
                "[conn][%p] ERROR, %u, %s.",
                Connection,
                Status,
                "Forced key update");
            break;
        }

        QuicCryptoUpdateKeyPhase(Connection, TRUE);
        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_FORCE_CID_UPDATE:

        if (!Connection->State.Connected ||
            !Connection->State.HandshakeConfirmed) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        QuicTraceLogConnVerbose(
            ForceCidUpdate,
            Connection,
            "Forcing destination CID update");

        if (!QuicPathIDRetireCurrentDestCid(Connection->Paths[0].PathID, &Connection->Paths[0])) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Connection->Paths[0].InitiatedCidUpdate = TRUE;
        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_TEST_TRANSPORT_PARAMETER:

        if (BufferLength != sizeof(QUIC_PRIVATE_TRANSPORT_PARAMETER)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (QUIC_CONN_BAD_START_STATE(Connection)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        CxPlatCopyMemory(
            &Connection->TestTransportParameter, Buffer, BufferLength);
        Connection->State.TestTransportParameterSet = TRUE;

        QuicTraceLogConnVerbose(
            TestTPSet,
            Connection,
            "Setting Test Transport Parameter (type %x, %hu bytes)",
            Connection->TestTransportParameter.Type,
            Connection->TestTransportParameter.Length);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_KEEP_ALIVE_PADDING:

        if (BufferLength != sizeof(Connection->KeepAlivePadding)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Connection->KeepAlivePadding = *(uint16_t*)Buffer;
        Status = QUIC_STATUS_SUCCESS;
        break;

#if QUIC_TEST_DISABLE_VNE_TP_GENERATION
    case QUIC_PARAM_CONN_DISABLE_VNE_TP_GENERATION:

        if (BufferLength != sizeof(BOOLEAN) || Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Connection->State.DisableVneTp = *(BOOLEAN*)Buffer;
        Status = QUIC_STATUS_SUCCESS;
        break;
#endif

#if QUIC_TEST_MANUAL_CONN_ID_GENERATION
    case QUIC_PARAM_CONN_DISABLE_CONN_ID_GENERATION:

        if (BufferLength != sizeof(BOOLEAN) || Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Connection->State.DisableConnIDGen = *(BOOLEAN*)Buffer;
        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_GENERATE_CONN_ID:

        if (!Connection->State.Connected ||
            !Connection->State.HandshakeConfirmed) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        if (BufferLength != sizeof(BOOLEAN) || Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        QuicPathIDSetGenerateNewSourceCids(&Connection->PathIDs, *(BOOLEAN*)Buffer);
        Status = QUIC_STATUS_SUCCESS;
        break;
#endif

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}

#define STATISTICS_HAS_FIELD(Size, Field) \
    (Size >= QUIC_STRUCT_SIZE_THRU_FIELD(QUIC_STATISTICS_V2, Field))

_IRQL_requires_max_(PASSIVE_LEVEL)
static
QUIC_STATUS
QuicConnGetV2Statistics(
    _In_ const QUIC_CONNECTION* Connection,
    _In_ BOOLEAN IsPlat,
    _Inout_ uint32_t* StatsLength,
    _Out_writes_bytes_opt_(*StatsLength)
        QUIC_STATISTICS_V2* Stats
    )
{
    const uint32_t MinimumStatsSize = QUIC_STATISTICS_V2_SIZE_1;

    if (*StatsLength == 0) {
        *StatsLength = sizeof(QUIC_STATISTICS_V2);
        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }

    if (*StatsLength < MinimumStatsSize) {
        *StatsLength = MinimumStatsSize;
        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }

    if (Stats == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    const QUIC_PATH* Path = &Connection->Paths[0];

    Stats->CorrelationId = Connection->Stats.CorrelationId;
    Stats->VersionNegotiation = Connection->Stats.VersionNegotiation;
    Stats->StatelessRetry = Connection->Stats.StatelessRetry;
    Stats->ResumptionAttempted = Connection->Stats.ResumptionAttempted;
    Stats->ResumptionSucceeded = Connection->Stats.ResumptionSucceeded;
    Stats->GreaseBitNegotiated = Connection->Stats.GreaseBitNegotiated;
    Stats->EncryptionOffloaded = Connection->Stats.EncryptionOffloaded;
    Stats->EcnCapable = Path->EcnValidationState == ECN_VALIDATION_CAPABLE;
    Stats->Rtt = (uint32_t)Path->SmoothedRtt;
    Stats->MinRtt = (uint32_t)Path->MinRtt;
    Stats->MaxRtt = (uint32_t)Path->MaxRtt;
    Stats->TimingStart = Connection->Stats.Timing.Start;
    Stats->TimingInitialFlightEnd = Connection->Stats.Timing.InitialFlightEnd;
    Stats->TimingHandshakeFlightEnd = Connection->Stats.Timing.HandshakeFlightEnd;
    Stats->HandshakeClientFlight1Bytes = Connection->Stats.Handshake.ClientFlight1Bytes;
    Stats->HandshakeServerFlight1Bytes = Connection->Stats.Handshake.ServerFlight1Bytes;
    Stats->HandshakeClientFlight2Bytes = Connection->Stats.Handshake.ClientFlight2Bytes;
    Stats->SendPathMtu = Path->Mtu;
    Stats->SendTotalPackets = Connection->Stats.Send.TotalPackets;
    Stats->SendRetransmittablePackets = Connection->Stats.Send.RetransmittablePackets;
    Stats->SendSuspectedLostPackets = Connection->Stats.Send.SuspectedLostPackets;
    Stats->SendSpuriousLostPackets = Connection->Stats.Send.SpuriousLostPackets;
    Stats->SendTotalBytes = Connection->Stats.Send.TotalBytes;
    Stats->SendTotalStreamBytes = Connection->Stats.Send.TotalStreamBytes;
    Stats->SendCongestionCount = Connection->Stats.Send.CongestionCount;
    Stats->SendPersistentCongestionCount = Connection->Stats.Send.PersistentCongestionCount;
    Stats->RecvTotalPackets = Connection->Stats.Recv.TotalPackets;
    Stats->RecvReorderedPackets = Connection->Stats.Recv.ReorderedPackets;
    Stats->RecvDroppedPackets = Connection->Stats.Recv.DroppedPackets;
    Stats->RecvDuplicatePackets = Connection->Stats.Recv.DuplicatePackets;
    Stats->RecvTotalBytes = Connection->Stats.Recv.TotalBytes;
    Stats->RecvTotalStreamBytes = Connection->Stats.Recv.TotalStreamBytes;
    Stats->RecvDecryptionFailures = Connection->Stats.Recv.DecryptionFailures;
    Stats->RecvValidAckFrames = Connection->Stats.Recv.ValidAckFrames;
    Stats->KeyUpdateCount = Connection->Stats.Misc.KeyUpdateCount;

    if (IsPlat) {
        Stats->TimingStart = CxPlatTimeUs64ToPlat(Stats->TimingStart); // cppcheck-suppress selfAssignment
        Stats->TimingInitialFlightEnd = CxPlatTimeUs64ToPlat(Stats->TimingInitialFlightEnd); // cppcheck-suppress selfAssignment
        Stats->TimingHandshakeFlightEnd = CxPlatTimeUs64ToPlat(Stats->TimingHandshakeFlightEnd); // cppcheck-suppress selfAssignment
    }

    //
    // N.B. Anything after this needs to be size checked
    //

    //
    // The below is how to add a new field while checking size.
    //
    // if (STATISTICS_HAS_FIELD(*StatsLength, KeyUpdateCount)) {
    //     Stats->KeyUpdateCount = Connection->Stats.Misc.KeyUpdateCount;
    // }

    if (STATISTICS_HAS_FIELD(*StatsLength, SendCongestionWindow)) {
        Stats->SendCongestionWindow = QuicCongestionControlGetCongestionWindow(&Connection->Paths[0].PathID->CongestionControl);
    }
    if (STATISTICS_HAS_FIELD(*StatsLength, DestCidUpdateCount)) {
        Stats->DestCidUpdateCount = Connection->Stats.Misc.DestCidUpdateCount;
    }
    if (STATISTICS_HAS_FIELD(*StatsLength, SendEcnCongestionCount)) {
        Stats->SendEcnCongestionCount = Connection->Stats.Send.EcnCongestionCount;
    }
    if (STATISTICS_HAS_FIELD(*StatsLength, HandshakeHopLimitTTL)) {
        Stats->HandshakeHopLimitTTL = Connection->Stats.Handshake.HandshakeHopLimitTTL;
    }
    if (STATISTICS_HAS_FIELD(*StatsLength, RttVariance)) {
        Stats->RttVariance = (uint32_t)Path->RttVariance;
    }
    if (STATISTICS_HAS_FIELD(*StatsLength, ConnectionQueueDelayAvgUs)) {
        Stats->ConnectionQueueDelayAvgUs = Connection->Stats.Schedule.QueueDelayAvgUs;
    }
    if (STATISTICS_HAS_FIELD(*StatsLength, ConnectionQueueDelayMaxUs)) {
        Stats->ConnectionQueueDelayMaxUs = Connection->Stats.Schedule.QueueDelayMaxUs;
    }
    if (STATISTICS_HAS_FIELD(*StatsLength, SendQueueDelayAvgUs)) {
        Stats->SendQueueDelayAvgUs = Connection->Stats.Schedule.SendQueueDelayAvgUs;
    }
    if (STATISTICS_HAS_FIELD(*StatsLength, SendQueueDelayMaxUs)) {
        Stats->SendQueueDelayMaxUs = Connection->Stats.Schedule.SendQueueDelayMaxUs;
    }
    if (STATISTICS_HAS_FIELD(*StatsLength, ReceiveQueueDelayAvgUs)) {
        Stats->ReceiveQueueDelayAvgUs = Connection->Stats.Schedule.ReceiveQueueDelayAvgUs;
    }
    if (STATISTICS_HAS_FIELD(*StatsLength, ReceiveQueueDelayMaxUs)) {
        Stats->ReceiveQueueDelayMaxUs = Connection->Stats.Schedule.ReceiveQueueDelayMaxUs;
    }

    *StatsLength = CXPLAT_MIN(*StatsLength, sizeof(QUIC_STATISTICS_V2));

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static
QUIC_STATUS
QuicConnGetNetworkStatistics(
    _In_ const QUIC_CONNECTION* Connection,
    _Inout_ uint32_t* StatsLength,
    _Out_writes_bytes_opt_(*StatsLength)
        QUIC_NETWORK_STATISTICS* Stats
    )
{
    if (*StatsLength < sizeof(QUIC_NETWORK_STATISTICS)) {
        *StatsLength = sizeof(QUIC_NETWORK_STATISTICS);
        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }

    if (Stats == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    CxPlatZeroMemory(Stats, sizeof(QUIC_NETWORK_STATISTICS));

    Connection->Paths[0].PathID->CongestionControl.QuicCongestionControlGetNetworkStatistics(
        Connection, &Connection->Paths[0].PathID->CongestionControl,
        &Connection->Paths[0], Stats);

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static
QUIC_STATUS
QuicConnGetPathStatistics(
    _In_ const QUIC_CONNECTION* Connection,
    _Inout_ uint32_t* StatsLength,
    _Out_writes_bytes_opt_(*StatsLength)
        QUIC_PATH_STATISTICS* Stats
    )
{
    //
    // Only paths that are in use and have a path ID can be reported on: the
    // path ID is what identifies the entry to the caller, and it owns the
    // congestion control the network statistics come from. A path added before
    // the handshake is confirmed has neither yet.
    //
    uint8_t PathCount = 0;
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        if (Connection->Paths[i].InUse && Connection->Paths[i].PathID != NULL) {
            PathCount++;
        }
    }

    const uint32_t RequiredLength = PathCount * sizeof(QUIC_PATH_STATISTICS);

    if (*StatsLength < RequiredLength) {
        *StatsLength = RequiredLength;
        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }

    if (Stats == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    CxPlatZeroMemory(Stats, RequiredLength);

    uint8_t Index = 0;
    for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
        const QUIC_PATH* Path = &Connection->Paths[i];
        if (!Path->InUse || Path->PathID == NULL) {
            continue;
        }

        QUIC_PATH_STATISTICS* PathStats = &Stats[Index++];
        PathStats->PathId = Path->PathID->ID;
        PathStats->Rtt = Path->SmoothedRtt;
        //
        // Until the path has produced an RTT sample, MinRtt still holds the
        // sentinel it was initialized to and MaxRtt is untouched. Reporting
        // those as microsecond counts would read as a minimum of over an hour,
        // so a path with nothing measured reports zero for both.
        //
        PathStats->MinRtt = Path->GotFirstRttSample ? Path->MinRtt : 0;
        PathStats->MaxRtt = Path->GotFirstRttSample ? Path->MaxRtt : 0;
        PathStats->Mtu = Path->Mtu;

        Path->PathID->CongestionControl.QuicCongestionControlGetNetworkStatistics(
            Connection, &Path->PathID->CongestionControl, Path,
            &PathStats->NetworkStatistics);
    }

    CXPLAT_DBG_ASSERT(Index == PathCount);

    *StatsLength = RequiredLength;

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnParamGet(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    QUIC_STATUS Status;
    uint32_t Length;
    uint8_t Type;

    switch (Param) {

    case QUIC_PARAM_CONN_QUIC_VERSION:

        if (*BufferLength < sizeof(Connection->Stats.QuicVersion)) {
            *BufferLength = sizeof(Connection->Stats.QuicVersion);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(Connection->Stats.QuicVersion);
        *(uint32_t*)Buffer = CxPlatByteSwapUint32(Connection->Stats.QuicVersion);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_LOCAL_ADDRESS:

        if (*BufferLength < sizeof(QUIC_ADDR)) {
            *BufferLength = sizeof(QUIC_ADDR);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (!Connection->State.LocalAddressSet) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        *BufferLength = sizeof(QUIC_ADDR);
        if (!QuicConnIsQMux(Connection)) {
            CxPlatCopyMemory(
                Buffer,
                &Connection->Paths[0].Route.LocalAddress,
                sizeof(QUIC_ADDR));
        } else {
            CxPlatCopyMemory(
                Buffer,
                &QuicConnGetQMux(Connection)->Route.LocalAddress,
                sizeof(QUIC_ADDR));
        } 

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_REMOTE_ADDRESS:

        if (*BufferLength < sizeof(QUIC_ADDR)) {
            *BufferLength = sizeof(QUIC_ADDR);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (!Connection->State.RemoteAddressSet) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        *BufferLength = sizeof(QUIC_ADDR);
        if (!QuicConnIsQMux(Connection)) {
            CxPlatCopyMemory(
                Buffer,
                &Connection->Paths[0].Route.RemoteAddress,
                sizeof(QUIC_ADDR));
        } else {
            CxPlatCopyMemory(
                Buffer,
                &QuicConnGetQMux(Connection)->Route.RemoteAddress,
                sizeof(QUIC_ADDR));
        }

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_IDEAL_PROCESSOR:

        if (*BufferLength < sizeof(uint16_t)) {
            *BufferLength = sizeof(uint16_t);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(uint16_t);
        *(uint16_t*)Buffer = Connection->Partition->Processor;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_SETTINGS:

        Status = QuicSettingsGetSettings(&Connection->Settings, BufferLength, (QUIC_SETTINGS*)Buffer);
        break;

    case QUIC_PARAM_CONN_VERSION_SETTINGS:

        Status = QuicSettingsGetVersionSettings(&Connection->Settings, BufferLength, (QUIC_VERSION_SETTINGS*)Buffer);
        break;

    case QUIC_PARAM_CONN_STATISTICS:
    case QUIC_PARAM_CONN_STATISTICS_PLAT: {

        if (*BufferLength < sizeof(QUIC_STATISTICS)) {
            *BufferLength = sizeof(QUIC_STATISTICS);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        QUIC_STATISTICS* Stats = (QUIC_STATISTICS*)Buffer;
        const QUIC_PATH* Path = &Connection->Paths[0];

        Stats->CorrelationId = Connection->Stats.CorrelationId;
        Stats->VersionNegotiation = Connection->Stats.VersionNegotiation;
        Stats->StatelessRetry = Connection->Stats.StatelessRetry;
        Stats->ResumptionAttempted = Connection->Stats.ResumptionAttempted;
        Stats->ResumptionSucceeded = Connection->Stats.ResumptionSucceeded;
        Stats->Rtt = (uint32_t)Path->SmoothedRtt;
        Stats->MinRtt = (uint32_t)Path->MinRtt;
        Stats->MaxRtt = (uint32_t)Path->MaxRtt;
        Stats->Timing.Start = Connection->Stats.Timing.Start;
        Stats->Timing.InitialFlightEnd = Connection->Stats.Timing.InitialFlightEnd;
        Stats->Timing.HandshakeFlightEnd = Connection->Stats.Timing.HandshakeFlightEnd;
        Stats->Handshake.ClientFlight1Bytes = Connection->Stats.Handshake.ClientFlight1Bytes;
        Stats->Handshake.ServerFlight1Bytes = Connection->Stats.Handshake.ServerFlight1Bytes;
        Stats->Handshake.ClientFlight2Bytes = Connection->Stats.Handshake.ClientFlight2Bytes;
        Stats->Send.PathMtu = Path->Mtu;
        Stats->Send.TotalPackets = Connection->Stats.Send.TotalPackets;
        Stats->Send.RetransmittablePackets = Connection->Stats.Send.RetransmittablePackets;
        Stats->Send.SuspectedLostPackets = Connection->Stats.Send.SuspectedLostPackets;
        Stats->Send.SpuriousLostPackets = Connection->Stats.Send.SpuriousLostPackets;
        Stats->Send.TotalBytes = Connection->Stats.Send.TotalBytes;
        Stats->Send.TotalStreamBytes = Connection->Stats.Send.TotalStreamBytes;
        Stats->Send.CongestionCount = Connection->Stats.Send.CongestionCount;
        Stats->Send.PersistentCongestionCount = Connection->Stats.Send.PersistentCongestionCount;
        Stats->Recv.TotalPackets = Connection->Stats.Recv.TotalPackets;
        Stats->Recv.ReorderedPackets = Connection->Stats.Recv.ReorderedPackets;
        Stats->Recv.DroppedPackets = Connection->Stats.Recv.DroppedPackets;
        Stats->Recv.DuplicatePackets = Connection->Stats.Recv.DuplicatePackets;
        Stats->Recv.TotalBytes = Connection->Stats.Recv.TotalBytes;
        Stats->Recv.TotalStreamBytes = Connection->Stats.Recv.TotalStreamBytes;
        Stats->Recv.DecryptionFailures = Connection->Stats.Recv.DecryptionFailures;
        Stats->Recv.ValidAckFrames = Connection->Stats.Recv.ValidAckFrames;
        Stats->Misc.KeyUpdateCount = Connection->Stats.Misc.KeyUpdateCount;

        if (Param == QUIC_PARAM_CONN_STATISTICS_PLAT) {
            Stats->Timing.Start = CxPlatTimeUs64ToPlat(Stats->Timing.Start); // cppcheck-suppress selfAssignment
            Stats->Timing.InitialFlightEnd = CxPlatTimeUs64ToPlat(Stats->Timing.InitialFlightEnd); // cppcheck-suppress selfAssignment
            Stats->Timing.HandshakeFlightEnd = CxPlatTimeUs64ToPlat(Stats->Timing.HandshakeFlightEnd); // cppcheck-suppress selfAssignment
        }

        *BufferLength = sizeof(QUIC_STATISTICS);
        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONN_SHARE_UDP_BINDING:

        if (*BufferLength < sizeof(uint8_t)) {
            *BufferLength = sizeof(uint8_t);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(uint8_t);
        *(uint8_t*)Buffer = Connection->State.ShareBinding;

        Status = QUIC_STATUS_SUCCESS;
        break;

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    case QUIC_PARAM_CONN_UNCONNECTED_UDP_SOCKET:

        if (*BufferLength < sizeof(uint8_t)) {
            *BufferLength = sizeof(uint8_t);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(uint8_t);
        *(uint8_t*)Buffer = Connection->State.UnconnectedSocket;

        Status = QUIC_STATUS_SUCCESS;
        break;
#endif

    case QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT:
        Type =
            QuicConnIsServer(Connection) ?
                STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_BI_DIR :
                STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_BI_DIR;
        goto Get_Stream_Count;

    case QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT:
        Type =
            QuicConnIsServer(Connection) ?
                STREAM_ID_FLAG_IS_SERVER | STREAM_ID_FLAG_IS_UNI_DIR :
                STREAM_ID_FLAG_IS_CLIENT | STREAM_ID_FLAG_IS_UNI_DIR;
        goto Get_Stream_Count;

    Get_Stream_Count:
        if (*BufferLength < sizeof(uint16_t)) {
            *BufferLength = sizeof(uint16_t);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(uint16_t);
        *(uint16_t*)Buffer =
            QuicStreamSetGetCountAvailable(&Connection->Streams, Type);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_MAX_STREAM_IDS:

        if (*BufferLength < sizeof(uint64_t) * NUMBER_OF_STREAM_TYPES) {
            *BufferLength = sizeof(uint64_t) * NUMBER_OF_STREAM_TYPES;
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(uint64_t) * NUMBER_OF_STREAM_TYPES;
        QuicStreamSetGetMaxStreamIDs(&Connection->Streams, (uint64_t*)Buffer);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_CLOSE_REASON_PHRASE:

        if (Connection->CloseReasonPhrase == NULL) {
            Status = QUIC_STATUS_NOT_FOUND;
            break;
        }

        Length = (uint32_t)strlen(Connection->CloseReasonPhrase) + 1;
        if (*BufferLength < Length) {
            *BufferLength = Length;
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = Length;
        CxPlatCopyMemory(Buffer, Connection->CloseReasonPhrase, Length);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME:

        if (*BufferLength < sizeof(QUIC_STREAM_SCHEDULING_SCHEME)) {
            *BufferLength = sizeof(QUIC_STREAM_SCHEDULING_SCHEME);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(QUIC_STREAM_SCHEDULING_SCHEME);
        *(QUIC_STREAM_SCHEDULING_SCHEME*)Buffer =
            Connection->State.UseRoundRobinStreamScheduling ?
                QUIC_STREAM_SCHEDULING_SCHEME_ROUND_ROBIN : QUIC_STREAM_SCHEDULING_SCHEME_FIFO;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED:

        if (*BufferLength < sizeof(BOOLEAN)) {
            *BufferLength = sizeof(BOOLEAN);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(BOOLEAN);
        *(BOOLEAN*)Buffer = Connection->Settings.DatagramReceiveEnabled;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED:

        if (*BufferLength < sizeof(BOOLEAN)) {
            *BufferLength = sizeof(BOOLEAN);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(BOOLEAN);
        *(BOOLEAN*)Buffer = Connection->Datagram.SendEnabled;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION:

        if (*BufferLength < sizeof(BOOLEAN)) {
            *BufferLength = sizeof(BOOLEAN);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(BOOLEAN);
        *(BOOLEAN*)Buffer = Connection->State.Disable1RttEncrytion;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_STATISTICS_V2:
    case QUIC_PARAM_CONN_STATISTICS_V2_PLAT: {

        Status =
            QuicConnGetV2Statistics(
                Connection,
                Param == QUIC_PARAM_CONN_STATISTICS_V2_PLAT,
                BufferLength,
                (QUIC_STATISTICS_V2*)Buffer);
        break;
    }

    case QUIC_PARAM_CONN_ORIG_DEST_CID:

        if (Connection->OrigDestCID == NULL) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        if (*BufferLength < Connection->OrigDestCID->Length) {
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            *BufferLength = Connection->OrigDestCID->Length;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        CxPlatCopyMemory(
            Buffer,
            Connection->OrigDestCID->Data,
            Connection->OrigDestCID->Length);

        //
        // Tell app how much buffer we copied.
        //
        *BufferLength = Connection->OrigDestCID->Length;

        Status = QUIC_STATUS_SUCCESS;
        break;

     case QUIC_PARAM_CONN_SEND_DSCP:

        if (*BufferLength < sizeof(uint8_t)) {
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            *BufferLength = sizeof(uint8_t);
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        CxPlatCopyMemory(
            Buffer,
            &Connection->DSCP,
            sizeof(Connection->DSCP));

        *BufferLength = sizeof(Connection->DSCP);
        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_NETWORK_STATISTICS:
        Status =
            QuicConnGetNetworkStatistics(Connection, BufferLength, (QUIC_NETWORK_STATISTICS *)Buffer);
        break;

    case QUIC_PARAM_CONN_PATH_STATISTICS:
        Status =
            QuicConnGetPathStatistics(Connection, BufferLength, (QUIC_PATH_STATISTICS *)Buffer);
        break;

#if DEBUG
    case QUIC_PARAM_CONN_TEST_PATH_ADDRESSES: {

        //
        // Every in-use path's endpoints, in array order, so a test can check
        // which pairs the reconciler settled on rather than only how many.
        //
        CXPLAT_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
        const uint32_t RequiredLength =
            Connection->PathsCount * (uint32_t)sizeof(QUIC_TEST_PATH_ADDRESSES);

        if (*BufferLength < RequiredLength) {
            *BufferLength = RequiredLength;
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }
        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        QUIC_TEST_PATH_ADDRESSES* Addresses = (QUIC_TEST_PATH_ADDRESSES*)Buffer;
        for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
            Addresses[i].LocalAddress = Connection->Paths[i].Route.LocalAddress;
            Addresses[i].RemoteAddress = Connection->Paths[i].Route.RemoteAddress;
        }
        *BufferLength = RequiredLength;
        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONN_TEST_PATH_ORIGINS: {

        //
        // Every in-use path, in array order, so a test can tell which paths
        // reconciliation owns. Debug only: it reports internal state that is
        // nobody's business outside the library.
        //
        CXPLAT_DBG_ASSERT(Connection->PathsCount <= QUIC_MAX_PATH_COUNT);
        const uint32_t RequiredLength = Connection->PathsCount;

        if (*BufferLength < RequiredLength) {
            *BufferLength = RequiredLength;
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }
        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        for (uint8_t i = 0; i < Connection->PathsCount; ++i) {
            ((uint8_t*)Buffer)[i] = Connection->Paths[i].Origin;
        }
        *BufferLength = RequiredLength;
        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_CONN_TEST_STATELESS_PUNCH_NEGOTIATED:

        if (*BufferLength < sizeof(BOOLEAN)) {
            *BufferLength = sizeof(BOOLEAN);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }
        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(BOOLEAN);
        *(BOOLEAN*)Buffer = Connection->State.StatelessPunchNegotiated;
        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_CONN_TEST_PUNCH_COUNTERS:

        if (*BufferLength < sizeof(QUIC_TEST_PUNCH_COUNTERS)) {
            *BufferLength = sizeof(QUIC_TEST_PUNCH_COUNTERS);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }
        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(QUIC_TEST_PUNCH_COUNTERS);
        ((QUIC_TEST_PUNCH_COUNTERS*)Buffer)->RequestsSent =
            Connection->PunchRequestsSent;
        ((QUIC_TEST_PUNCH_COUNTERS*)Buffer)->RequestsReceived =
            Connection->PunchRequestsReceived;
        ((QUIC_TEST_PUNCH_COUNTERS*)Buffer)->PunchesSent =
            Connection->PunchesSent;
        ((QUIC_TEST_PUNCH_COUNTERS*)Buffer)->RequestsIgnoredPerPacket =
            Connection->PunchRequestsIgnoredPerPacket;
        Status = QUIC_STATUS_SUCCESS;
        break;
#endif

    case QUIC_PARAM_CONN_CLOSE_ASYNC:

        if (*BufferLength < sizeof(BOOLEAN)) {
            *BufferLength = sizeof(BOOLEAN);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(BOOLEAN);
        *(BOOLEAN*)Buffer = Connection->State.CloseAsync;

        Status = QUIC_STATUS_SUCCESS;
        break;

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnApplyNewSettings(
    _In_ QUIC_CONNECTION* Connection,
    _In_ BOOLEAN OverWrite,
    _In_ const QUIC_SETTINGS_INTERNAL* NewSettings
    )
{
    QuicTraceLogConnInfo(
        ApplySettings,
        Connection,
        "Applying new settings");

    if (!QuicSettingApply(
            &Connection->Settings,
            OverWrite,
            !Connection->State.Started,
            NewSettings)) {
        return FALSE;
    }

    if (!Connection->State.Started) {

        Connection->Paths[0].SmoothedRtt = MS_TO_US(Connection->Settings.InitialRttMs);
        Connection->Paths[0].RttVariance = Connection->Paths[0].SmoothedRtt / 2;
        Connection->Paths[0].Mtu = Connection->Settings.MinimumMtu;

        if (Connection->Settings.ServerResumptionLevel > QUIC_SERVER_NO_RESUME &&
            Connection->HandshakeTP == NULL) {
            CXPLAT_DBG_ASSERT(!Connection->State.Started);
            Connection->HandshakeTP =
                CxPlatPoolAlloc(&Connection->Partition->TransportParamPool);
            if (Connection->HandshakeTP == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "handshake TP",
                    sizeof(*Connection->HandshakeTP));
            } else {
                CxPlatZeroMemory(Connection->HandshakeTP, sizeof(*Connection->HandshakeTP));
                Connection->State.ResumptionEnabled = TRUE;
            }
        }

        QuicSendApplyNewSettings(&Connection->Send, &Connection->Settings);
        if (!QuicConnIsQMux(Connection)) {
            //
            // QMux connections run over TCP and have no PathID (and therefore
            // no congestion control) of their own.
            //
            QuicCongestionControlInitialize(&Connection->Paths[0].PathID->CongestionControl, &Connection->Settings);
        }

        if (QuicConnIsClient(Connection) && Connection->Settings.IsSet.VersionSettings) {
            Connection->Stats.QuicVersion = Connection->Settings.VersionSettings->FullyDeployedVersions[0];
            QuicConnOnQuicVersionSet(Connection);
            //
            // The version has changed AFTER the crypto layer has been initialized,
            // so reinitialize the crypto layer here so it uses the right keys.
            // If the reinitialization fails, fail the connection.
            //
            if (QUIC_FAILED(QuicCryptoOnVersionChange(&Connection->Crypto))) {
                return FALSE;
            }
        }

        if (QuicConnIsServer(Connection) &&
            Connection->Settings.GreaseQuicBitEnabled &&
            (Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_GREASE_QUIC_BIT) > 0) {
            //
            // Endpoints that receive the grease_quic_bit transport parameter from
            // a peer SHOULD set the QUIC Bit to an unpredictable value extension
            // assigns specific meaning to the value of the bit.
            //
            uint8_t RandomValue;
            (void)CxPlatRandom(sizeof(RandomValue), &RandomValue);
            Connection->State.FixedBit = (RandomValue % 2);
            Connection->Stats.GreaseBitNegotiated = TRUE;
        }

        if (QuicConnIsServer(Connection) && Connection->Settings.ReliableResetEnabled) {
            Connection->State.ReliableResetStreamNegotiated =
                !!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_RELIABLE_RESET_ENABLED);

            //
            // Send event to app to indicate result of negotiation if app cares.
            //
            QUIC_CONNECTION_EVENT Event;
            Event.Type = QUIC_CONNECTION_EVENT_RELIABLE_RESET_NEGOTIATED;
            Event.RELIABLE_RESET_NEGOTIATED.IsNegotiated = Connection->State.ReliableResetStreamNegotiated;

            QuicTraceLogConnVerbose(
                IndicateReliableResetNegotiated,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_RELIABLE_RESET_NEGOTIATED [IsNegotiated=%hhu]",
                Event.RELIABLE_RESET_NEGOTIATED.IsNegotiated);
            QuicConnIndicateEvent(Connection, &Event);
        }

        if (QuicConnIsServer(Connection) && Connection->Settings.OneWayDelayEnabled) {
            Connection->State.TimestampSendNegotiated = // Peer wants to recv, so we can send
                !!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_TIMESTAMP_RECV_ENABLED);
            Connection->State.TimestampRecvNegotiated = // Peer wants to send, so we can recv
                !!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_TIMESTAMP_SEND_ENABLED);

            //
            // Send event to app to indicate result of negotiation if app cares.
            //
            QUIC_CONNECTION_EVENT Event;
            Event.Type = QUIC_CONNECTION_EVENT_ONE_WAY_DELAY_NEGOTIATED;
            Event.ONE_WAY_DELAY_NEGOTIATED.SendNegotiated = Connection->State.TimestampSendNegotiated;
            Event.ONE_WAY_DELAY_NEGOTIATED.ReceiveNegotiated = Connection->State.TimestampRecvNegotiated;

            QuicTraceLogConnVerbose(
                IndicateOneWayDelayNegotiated,
                Connection,
                "Indicating QUIC_CONNECTION_EVENT_ONE_WAY_DELAY_NEGOTIATED [Send=%hhu,Recv=%hhu]",
                Event.ONE_WAY_DELAY_NEGOTIATED.SendNegotiated,
                Event.ONE_WAY_DELAY_NEGOTIATED.ReceiveNegotiated);
            QuicConnIndicateEvent(Connection, &Event);
        }

        if (QuicConnIsServer(Connection) && QuicConnPeerWantsObservedAddressReports(Connection)) {
            Connection->State.ObservedAddressNegotiated = TRUE;
            QuicSendSetSendFlag(
                &Connection->Send,
                QUIC_CONN_SEND_FLAG_OBSERVED_ADDRESS);
        }

        if (QuicConnIsServer(Connection) && Connection->Settings.ServerMigrationEnabled) {
            Connection->State.ServerMigrationNegotiated =
                !!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_SERVER_MIGRATION);
        }

        if (QuicConnIsServer(Connection) && Connection->Settings.MultipathEnabled) {
            Connection->State.MultipathNegotiated =
                !!(Connection->PeerTransportParams.Flags & QUIC_TP_FLAG_INITIAL_MAX_PATH_ID);
        }

        if (Connection->Settings.EcnEnabled) {
            QUIC_PATH* Path = &Connection->Paths[0];
            Path->EcnValidationState = ECN_VALIDATION_TESTING;
        }
    }

    if (Connection->State.Started &&
        (Connection->Settings.EncryptionOffloadAllowed ^ Connection->Paths[0].EncryptionOffloading)) {
        // TODO: enable/disable after start
        CXPLAT_FRE_ASSERT(FALSE);
    }

    uint8_t PeerStreamType =
        QuicConnIsServer(Connection) ?
            STREAM_ID_FLAG_IS_CLIENT : STREAM_ID_FLAG_IS_SERVER;

    if (NewSettings->IsSet.PeerBidiStreamCount) {
        QuicStreamSetUpdateMaxCount(
            &Connection->Streams,
            PeerStreamType | STREAM_ID_FLAG_IS_BI_DIR,
            Connection->Settings.PeerBidiStreamCount);
    }
    if (NewSettings->IsSet.PeerUnidiStreamCount) {
        QuicStreamSetUpdateMaxCount(
            &Connection->Streams,
            PeerStreamType | STREAM_ID_FLAG_IS_UNI_DIR,
            Connection->Settings.PeerUnidiStreamCount);
    }

    if (NewSettings->IsSet.KeepAliveIntervalMs && Connection->State.Started) {
        if (Connection->Settings.KeepAliveIntervalMs != 0) {
            QuicConnProcessKeepAliveOperation(Connection);
        } else {
            QuicConnTimerCancel(Connection, QUIC_CONN_TIMER_KEEP_ALIVE);
        }
    }

    if (NewSettings->IsSet.PathKeepAliveIntervalMs) {
        //
        // Before the handshake completes this only cancels the timer; the
        // connection arms it itself once it gets there.
        //
        QuicConnPathKeepAliveTimerUpdate(Connection);
    }

#if QUIC_TEST_MANUAL_CONN_ID_GENERATION
    if (NewSettings->IsSet.ConnIDGenDisabled) {
        Connection->State.DisableConnIDGen = NewSettings->ConnIDGenDisabled;
    }
#endif

    //
    // !! rather than the bitfield itself: IsSet.AddAddressMode is a uint64_t:1
    // and the parameter is a BOOLEAN, which MSVC reports as C4244 and gcc does
    // not report at all. Third time this class has got through in this work,
    // after the mode enum and the deprecated setter.
    //
    QuicConnUpdateAddressMonitorRef(
        Connection, !!NewSettings->IsSet.AddAddressMode);

    if (OverWrite) {
        QuicSettingsDumpNew(NewSettings);
    } else {
        QuicSettingsDump(&Connection->Settings); // TODO - Really necessary?
    }

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicConnExportKeyingMaterial(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_KEYING_MATERIAL_CONFIG* Config,
    _Out_writes_bytes_(Config->OutputLength)
        uint8_t* Output
    )
{
    //
    // The keying material is derived from the connection's TLS secrets: the
    // handshake must be complete and the TLS context must still be present.
    //
    if (!Connection->State.Connected ||
        !Connection->Crypto.TlsState.HandshakeComplete ||
        Connection->Crypto.TLS == NULL) {
        QuicTraceLogConnWarning(
            ExportKeyingMaterialInvalidState,
            Connection,
            "Cannot export keying material [Connected=%hhu, HandshakeComplete=%hhu, HasTls=%hhu]",
            Connection->State.Connected,
            Connection->Crypto.TlsState.HandshakeComplete,
            (uint8_t)(Connection->Crypto.TLS != NULL));
        return QUIC_STATUS_INVALID_STATE;
    }

    return
        CxPlatTlsExportKeyingMaterial(
            Connection->Crypto.TLS,
            Config->Label,
            Config->Context,
            Config->ContextLength,
            Output,
            Config->OutputLength);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessApiOperation(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_API_CONTEXT* ApiCtx
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_STATUS* ApiStatus = ApiCtx->Status;
    CXPLAT_EVENT* ApiCompleted = ApiCtx->Completed;

    switch (ApiCtx->Type) {

    case QUIC_API_TYPE_CONN_CLOSE:
        QuicConnCloseHandle(Connection);
        if (Connection->State.CloseAsync) {
            CXPLAT_TEL_ASSERT(Connection->State.HandleClosed);
            //
            // Release the external reference to the connection for async
            // completion.
            //
            QuicConnRelease(Connection, QUIC_CONN_REF_HANDLE_OWNER);
        }
        break;

    case QUIC_API_TYPE_CONN_SHUTDOWN:
        QuicConnShutdown(
            Connection,
            ApiCtx->CONN_SHUTDOWN.Flags,
            ApiCtx->CONN_SHUTDOWN.ErrorCode,
            ApiCtx->CONN_SHUTDOWN.RegistrationShutdown,
            ApiCtx->CONN_SHUTDOWN.TransportShutdown);
        break;

    case QUIC_API_TYPE_CONN_START:
        Status =
            QuicConnStart(
                Connection,
                ApiCtx->CONN_START.Configuration,
                ApiCtx->CONN_START.Family,
                ApiCtx->CONN_START.ServerName,
                ApiCtx->CONN_START.ServerPort,
                ApiCtx->CONN_START.Flags);
        ApiCtx->CONN_START.ServerName = NULL;
        break;

    case QUIC_API_TYPE_CONN_SET_CONFIGURATION:
        Status =
            QuicConnSetConfiguration(
                Connection,
                ApiCtx->CONN_SET_CONFIGURATION.Configuration);
        break;

    case QUIC_API_TYPE_CONN_SEND_RESUMPTION_TICKET:
        CXPLAT_DBG_ASSERT(QuicConnIsServer(Connection));
        Status =
            QuicConnSendResumptionTicket(
                Connection,
                ApiCtx->CONN_SEND_RESUMPTION_TICKET.AppDataLength,
                ApiCtx->CONN_SEND_RESUMPTION_TICKET.ResumptionAppData);
        ApiCtx->CONN_SEND_RESUMPTION_TICKET.ResumptionAppData = NULL;
        if (ApiCtx->CONN_SEND_RESUMPTION_TICKET.Flags & QUIC_SEND_RESUMPTION_FLAG_FINAL) {
            Connection->State.ResumptionEnabled = FALSE;
        }
        break;

    case QUIC_API_TYPE_CONN_COMPLETE_RESUMPTION_TICKET_VALIDATION:
        CXPLAT_DBG_ASSERT(QuicConnIsServer(Connection));
        QuicCryptoCustomTicketValidationComplete(
            &Connection->Crypto,
            ApiCtx->CONN_COMPLETE_RESUMPTION_TICKET_VALIDATION.Result);
        break;

    case QUIC_API_TYPE_CONN_COMPLETE_CERTIFICATE_VALIDATION:
        QuicCryptoCustomCertValidationComplete(
            &Connection->Crypto,
            ApiCtx->CONN_COMPLETE_CERTIFICATE_VALIDATION.Result,
            ApiCtx->CONN_COMPLETE_CERTIFICATE_VALIDATION.TlsAlert);
        break;

    case QUIC_API_TYPE_STRM_CLOSE:
        QuicStreamClose(ApiCtx->STRM_CLOSE.Stream);
        break;

    case QUIC_API_TYPE_STRM_SHUTDOWN:
        QuicStreamShutdown(
            ApiCtx->STRM_SHUTDOWN.Stream,
            ApiCtx->STRM_SHUTDOWN.Flags,
            ApiCtx->STRM_SHUTDOWN.ErrorCode);
        break;

    case QUIC_API_TYPE_STRM_START:
        Status =
            QuicStreamStart(
                ApiCtx->STRM_START.Stream,
                ApiCtx->STRM_START.Flags,
                FALSE);
        break;

    case QUIC_API_TYPE_STRM_SEND:
        QuicStreamSendFlush(
            ApiCtx->STRM_SEND.Stream);
        break;

    case QUIC_API_TYPE_STRM_RECV_COMPLETE:
        QuicStreamReceiveCompletePending(
            ApiCtx->STRM_RECV_COMPLETE.Stream);
        break;

    case QUIC_API_TYPE_STRM_RECV_SET_ENABLED:
        Status =
            QuicStreamRecvSetEnabledState(
                ApiCtx->STRM_RECV_SET_ENABLED.Stream,
                ApiCtx->STRM_RECV_SET_ENABLED.IsEnabled);
        break;

    case QUIC_API_TYPE_STRM_PROVIDE_RECV_BUFFERS:
        Status =
            QuicStreamProvideRecvBuffers(
                ApiCtx->STRM_PROVIDE_RECV_BUFFERS.Stream,
                &ApiCtx->STRM_PROVIDE_RECV_BUFFERS.Chunks);

        if (Status != QUIC_STATUS_SUCCESS) {
            //
            // If we cannot accept the app provided buffers at this point, we need to abort
            // the connection: otherwise, we break the contract with the app about writting
            // data to the provided buffers in order.
            //
            QuicConnFatalError(
                ApiCtx->STRM_PROVIDE_RECV_BUFFERS.Stream->Connection,
                Status,
                "Failed to accept app provided receive buffers");
        }
        break;

    case QUIC_API_TYPE_SET_PARAM:
        Status =
            QuicLibrarySetParam(
                ApiCtx->SET_PARAM.Handle,
                ApiCtx->SET_PARAM.Param,
                ApiCtx->SET_PARAM.BufferLength,
                ApiCtx->SET_PARAM.Buffer);
        break;

    case QUIC_API_TYPE_GET_PARAM:
        Status =
            QuicLibraryGetParam(
                ApiCtx->GET_PARAM.Handle,
                ApiCtx->GET_PARAM.Param,
                ApiCtx->GET_PARAM.BufferLength,
                ApiCtx->GET_PARAM.Buffer);
        break;

    case QUIC_API_TYPE_DATAGRAM_SEND:
        QuicDatagramSendFlush(&Connection->Datagram);
        break;

    case QUIC_API_TYPE_CONN_EXPORT_KEYING_MATERIAL:
        Status =
            QuicConnExportKeyingMaterial(
                Connection,
                ApiCtx->CONN_EXPORT_KEYING_MATERIAL.Config,
                ApiCtx->CONN_EXPORT_KEYING_MATERIAL.Output);
        break;

    default:
        CXPLAT_TEL_ASSERT(FALSE);
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    if (ApiStatus) {
        *ApiStatus = Status;
    }
    if (ApiCompleted) {
        CxPlatEventSet(*ApiCompleted);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnProcessExpiredTimer(
    _Inout_ QUIC_CONNECTION* Connection,
    _In_ QUIC_CONN_TIMER_TYPE Type
    )
{
    switch (Type) {
    case QUIC_CONN_TIMER_IDLE:
        QuicConnProcessIdleTimerOperation(Connection);
        break;
    case QUIC_CONN_TIMER_LOSS_DETECTION:
        QuicPathIDSetProcessLossDetectionTimerOperation(&Connection->PathIDs);
        break;
    case QUIC_CONN_TIMER_KEEP_ALIVE:
        QuicConnProcessKeepAliveOperation(Connection);
        break;
    case QUIC_CONN_TIMER_PATH_KEEP_ALIVE:
        QuicConnPathKeepAliveTimerUpdate(Connection);
        break;
    case QUIC_CONN_TIMER_RECONCILE:
        //
        // A reconciliation that was held down. This is what makes the
        // hold-down a delay rather than a cancellation.
        //
        QuicConnQueueReconcile(Connection);
        break;
    case QUIC_CONN_TIMER_PATH_VALIDATION:
        QuicConnProcessPathValidationTimerOperation(Connection);
        break;
    case QUIC_CONN_TIMER_PATH_CLOSE:
        QuicPathIDSetProcessPathCloseTimerOperation(&Connection->PathIDs);
        break;
    case QUIC_CONN_TIMER_SHUTDOWN:
        QuicConnProcessShutdownTimerOperation(Connection);
        break;
    case QUIC_CONN_TIMER_PROBE_AFTER_PUNCH:
        QuicConnProcessProbeAfterPunchOperation(Connection);
        break;
    default:
        CXPLAT_FRE_ASSERT(FALSE);
        break;
    }
}

//
// Update a connection operation delay statistics
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicConnUpdateOperQueueDelay(
    _Inout_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_OPERATION* Oper
    )
{
    uint32_t DelayUs = CxPlatTimeDiff32(Oper->QueueTimeUs, CxPlatTimeUs32());

    switch (Oper->Type) {

    case QUIC_OPER_TYPE_FLUSH_RECV:
        Connection->Stats.Schedule.ReceiveQueueDelayAvgUs =
            (uint32_t)CxPlatEwma(Connection->Stats.Schedule.ReceiveQueueDelayAvgUs, DelayUs, 8);
        Connection->Stats.Schedule.ReceiveQueueDelayMaxUs =
            CXPLAT_MAX(Connection->Stats.Schedule.ReceiveQueueDelayMaxUs, DelayUs);
        break;
    case QUIC_OPER_TYPE_FLUSH_SEND:
        Connection->Stats.Schedule.SendQueueDelayAvgUs =
            (uint32_t)CxPlatEwma(Connection->Stats.Schedule.SendQueueDelayAvgUs, DelayUs, 8);
        Connection->Stats.Schedule.SendQueueDelayMaxUs =
            CXPLAT_MAX(Connection->Stats.Schedule.SendQueueDelayMaxUs, DelayUs);
        break;
    default:
        break;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnDrainOperations(
    _In_ QUIC_CONNECTION* Connection,
    _Inout_ BOOLEAN* StillHasPriorityWork
    )
{
    QUIC_OPERATION* Oper;
    const uint32_t MaxOperationCount =
        Connection->Settings.MaxOperationsPerDrain;
    uint32_t OperationCount = 0;
    BOOLEAN HasMoreWorkToDo = TRUE;

    CXPLAT_PASSIVE_CODE();

    if (!Connection->State.Initialized && !Connection->State.ShutdownComplete) {
        //
        // TODO - Try to move this only after the connection is accepted by the
        // listener. But that's going to be pretty complicated.
        //
        CXPLAT_DBG_ASSERT(QuicConnIsServer(Connection));
        QUIC_STATUS Status;
        if (!QuicConnIsQMux(Connection) &&
            QUIC_FAILED(Status = QuicCryptoInitialize(&Connection->Crypto))) {
            QuicConnFatalError(Connection, Status, "Lazily initialize failure");
        } else {
            Connection->State.Initialized = TRUE;
            QuicTraceEvent(
                ConnInitializeComplete,
                "[conn][%p] Initialize complete",
                Connection);
            if (Connection->Settings.KeepAliveIntervalMs != 0) {
                QuicConnTimerSet(
                    Connection,
                    QUIC_CONN_TIMER_KEEP_ALIVE,
                    MS_TO_US(Connection->Settings.KeepAliveIntervalMs));
            }
        }
    }

    while (!Connection->State.UpdateWorker &&
           OperationCount++ < MaxOperationCount) {

        Oper = QuicOperationDequeue(&Connection->OperQ, Connection->Partition);
        if (Oper == NULL) {
            HasMoreWorkToDo = FALSE;
            break;
        }

        QuicOperLog(Connection, Oper);
        QuicConnUpdateOperQueueDelay(Connection, Oper);

        BOOLEAN FreeOper = Oper->FreeAfterProcess;

        switch (Oper->Type) {

        case QUIC_OPER_TYPE_API_CALL:
            CXPLAT_DBG_ASSERT(Oper->API_CALL.Context != NULL);
            QuicConnProcessApiOperation(
                Connection,
                Oper->API_CALL.Context);
            break;

        case QUIC_OPER_TYPE_FLUSH_RECV:
            if (Connection->State.ShutdownComplete) {
                break; // Ignore if already shutdown
            }
            if (!QuicConnFlushRecv(Connection)) {
                //
                // Still have more data to recv. Put the operation back on the
                // queue.
                //
                FreeOper = FALSE;
                (void)QuicOperationEnqueue(&Connection->OperQ, Connection->Partition, Oper);
            }
            break;

        case QUIC_OPER_TYPE_UNREACHABLE:
            if (Connection->State.ShutdownComplete) {
                break; // Ignore if already shutdown
            }
            QuicConnProcessUdpUnreachable(
                Connection,
                &Oper->UNREACHABLE.RemoteAddress);
            break;

        case QUIC_OPER_TYPE_FLUSH_STREAM_RECV:
            if (Connection->State.ShutdownComplete) {
                break; // Ignore if already shutdown
            }
            QuicStreamRecvFlush(Oper->FLUSH_STREAM_RECEIVE.Stream);
            break;

        case QUIC_OPER_TYPE_FLUSH_SEND:
            if (Connection->State.ShutdownComplete) {
                break; // Ignore if already shutdown
            }
            if (QuicSendFlush(&Connection->Send)) {
                //
                // We have no more data to send out so clear the pending flag.
                //
                Connection->Send.FlushOperationPending = FALSE;
            } else {
                //
                // Still have more data to send. Put the operation back on the
                // queue.
                //
                FreeOper = FALSE;
                (void)QuicOperationEnqueue(&Connection->OperQ, Connection->Partition, Oper);
            }
            break;

        case QUIC_OPER_TYPE_TIMER_EXPIRED:
            if (Connection->State.ShutdownComplete) {
                break; // Ignore if already shutdown
            }
            QuicConnProcessExpiredTimer(Connection, Oper->TIMER_EXPIRED.Type);
            break;

        case QUIC_OPER_TYPE_TRACE_RUNDOWN:
            QuicConnTraceRundownOper(Connection);
            break;

        case QUIC_OPER_TYPE_ROUTE_COMPLETION:
            if (Connection->State.ShutdownComplete) {
                break; // Ignore if already shutdown
            }
            QuicConnProcessRouteCompletion(
                Connection, Oper->ROUTE.PhysicalAddress, Oper->ROUTE.PathId, Oper->ROUTE.Succeeded);
            break;

        case QUIC_OPER_TYPE_REMOVE_ADDRESS:
            QuicConnProcessRemoveAddressOper(Connection, Oper->REMOVE_ADDRESS.SequenceNumber);
            break;

        case QUIC_OPER_TYPE_RECONCILE_PATHS:
            QuicConnReconcilePaths(Connection);
            break;

        case QUIC_OPER_TYPE_LOCAL_ADDRESS_CHANGE:
            QuicConnProcessLocalAddressChange(Connection);
            break;

        case QUIC_OPER_TYPE_FLUSH_TCP_RECV:
            if (Connection->State.ShutdownComplete) {
                break; // Ignore if already shutdown
            }
            if (!QuicQMuxFlushRecv(QuicConnGetQMux(Connection))) {
                //
                // Still have more data to recv. Put the operation back on the
                // queue.
                //
                FreeOper = FALSE;
                (void)QuicOperationEnqueue(&Connection->OperQ, Connection->Partition, Oper);
            }
            break;

        case QUIC_OPER_TYPE_TCP_DISCONNECT:
            if (Connection->State.ShutdownComplete) {
                break; // Ignore if already shutdown
            }
            QuicQMuxProcessTcpDisconnect(QuicConnGetQMux(Connection));
            break;

        case QUIC_OPER_TYPE_TCP_CONNECT:
            if (Connection->State.ShutdownComplete) {
                break; // Ignore if already shutdown
            }
            QuicConnQMuxCompleteStart(Connection);
            break;

        default:
            CXPLAT_FRE_ASSERT(FALSE);
            break;
        }

        QuicConnValidate(Connection);

        if (FreeOper) {
            QuicOperationFree(Oper);
        }

        Connection->Stats.Schedule.OperationCount++;
        QuicPerfCounterIncrement(Connection->Partition, QUIC_PERF_COUNTER_CONN_OPER_COMPLETED);
    }

    if (Connection->State.ProcessShutdownComplete) {
        QuicConnOnShutdownComplete(Connection);
    }

    if (!Connection->State.ShutdownComplete) {
        if (OperationCount >= MaxOperationCount &&
            (Connection->Send.SendFlags & QUIC_CONN_SEND_FLAG_ACK)) {
            //
            // We can't process any more operations but still need to send an
            // immediate ACK. So as to not introduce additional queuing delay do
            // one immediate flush now.
            //
            (void)QuicSendFlush(&Connection->Send);
        }
    }

    QuicStreamSetDrainClosedStreams(&Connection->Streams);

    QuicConnValidate(Connection);

    if (HasMoreWorkToDo) {
        *StillHasPriorityWork = QuicOperationHasPriority(&Connection->OperQ);
        return TRUE;
    }

    return FALSE;
}
