/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Per path functionality for the connection.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "path.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathInitialize(
    _In_ uint32_t PathId,
    _In_ QUIC_CONNECTION* Connection,
    _Out_ QUIC_PATH* Path,
    _In_ QUIC_PATH_ORIGIN Origin
    )
{
    CxPlatZeroMemory(Path, sizeof(QUIC_PATH));
    //
    // The id is handed in by the path set, which owns the allocator.
    //
    Path->ID = PathId;
    //
    // Taken as a parameter rather than defaulted, so that a new creation site
    // has to say what it is instead of silently inheriting someone else's
    // answer. Automatic removal keys on it.
    //
    Path->Origin = (uint8_t)Origin;
    Path->InUse = TRUE;
    Path->RemoteAddressSequenceNumberValid = FALSE;
    Path->RemoteAddressSequenceNumber = QUIC_VAR_INT_MAX;
    //
    // Every new path wants its observed address reported, and the connection
    // flag has to go up with it or nothing will look. Raised here, at the one
    // place every path is created, rather than at each of the three creation
    // sites: QuicConnGetPathForPacket makes a path when a packet arrives from
    // a 4-tuple the connection has none for, which is how a peer whose local
    // address changed is first seen, and that is exactly the case that used to
    // go unreported -- the path asked for a report and only
    // QuicPathSetActive, on a migration that had not happened, ever raised the
    // flag.
    //
    // Gated on negotiation, like QuicPathSetActive's own raise. For the
    // initial path at connection setup the gate is closed and the two sites in
    // QuicConnProcessPeerTransportParameters raise it instead, once the peer
    // has asked for reports. QuicSendInitialize runs before this, so the send
    // state is there to set.
    //
    Path->SendObservedAddress = TRUE;
    if (Connection->State.ObservedAddressNegotiated) {
        QuicSendSetSendFlag(
            &Connection->Send,
            QUIC_CONN_SEND_FLAG_OBSERVED_ADDRESS);
    }
    Path->MinRtt = UINT32_MAX;
    Path->Mtu = Connection->Settings.MinimumMtu;
    Path->SmoothedRtt = MS_TO_US(Connection->Settings.InitialRttMs);
    Path->RttVariance = Path->SmoothedRtt / 2;
    Path->EcnValidationState =
        Connection->Settings.EcnEnabled ? ECN_VALIDATION_TESTING : ECN_VALIDATION_FAILED;
    //
    // A path that has never sent anything is not yet in need of a keep alive;
    // start its idle time from now.
    //
    Path->LastSendTimeUs = CxPlatTimeUs64();

    //
    // Defense in depth: initialize Challenge with random data so a zero-valued
    // PATH_RESPONSE can never match an uninitialized challenge.
    //
    CxPlatRandom(sizeof(Path->Challenge), Path->Challenge);

    if (Connection->Settings.QTIPEnabled) {
        CxPlatRandom(sizeof(Path->Route.TcpState.SequenceNumber), &Path->Route.TcpState.SequenceNumber);
    }

    QuicTraceEvent(
        ConnPathInitialized,
        "[conn][%p] Path[%u] Initialized",
        Connection,
        Path->ID);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathSetInitialize(
    _Out_ QUIC_PATH_SET* PathSet,
    _In_ QUIC_CONNECTION* Connection
    )
{
    CxPlatZeroMemory(PathSet, sizeof(*PathSet));
    QuicPathInitialize(
        PathSet->NextPathId++, Connection, &PathSet->Paths[0], QUIC_PATH_ORIGIN_INITIAL);
    PathSet->Paths[0].IsActive = TRUE;
    PathSet->Count = 1;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_PATH*
QuicPathGetActive(
    _In_ const QUIC_PATH_SET* PathSet
    )
{
    CXPLAT_DBG_ASSERT(PathSet->Count > 0);
    //
    // Upstream also asserts Paths[0].IsActive here. Under multipath IsActive is
    // per path and the path in slot 0 can be closed while others still carry
    // traffic, so what slot 0 means on this fork is "the path connection-level
    // work runs on", not "the one active path".
    //
    CXPLAT_DBG_ASSERT(
        PathSet->Paths[0].IsActive ||
        PathSet->Paths[0].LocalClose ||
        PathSet->Paths[0].RemoteClose);
    return (QUIC_PATH*)&PathSet->Paths[0];
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static
BOOLEAN
QuicPathUpdateDestCid(
    _In_ QUIC_CONNECTION* Connection,
    _Inout_ QUIC_PATH* Path
    )
{
    if (Path->DestCid != NULL && !Path->DestCid->CID.Retired) {
        return TRUE;
    }

    //
    // Destination CIDs are held per path ID on this fork, so the replacement
    // comes from this path's own store rather than from one connection-wide
    // list.
    //
    // A path with no path ID has nothing to draw from, and that is not a
    // failure: QuicConnAssignPathIDs leaves a path in exactly that state on
    // purpose when no path ID is free, to pick it up when one frees (#213).
    // Answering FALSE here would have the sweep below remove it, which is the
    // opposite of what the fork wants -- and with the reconciler filling the
    // path array, it would quietly empty it again.
    //
    if (Path->PathID == NULL) {
        return TRUE;
    }

    //
    // A path that never had a destination CID is in the same position: its path
    // ID is new and the peer has not issued CIDs for it yet. #196 answers that
    // by asking for them (PATH_CIDS_BLOCKED) and waiting. Upstream's sweep is
    // about a CID that was *retired* and needs replacing, which is the case
    // below; it knows nothing about per-path-ID CID issuance.
    //
    if (Path->DestCid == NULL) {
        return TRUE;
    }

    QUIC_CID_LIST_ENTRY* NewDestCid = QuicPathIDGetUnusedDestCid(Path->PathID);
    if (NewDestCid == NULL) {
        return FALSE;
    }

    if (Path->DestCid != NULL) {
        Path->DestCid = NULL;
    }

    Path->DestCid = NewDestCid;
    QuicCidSetPath(&Connection->Paths, NewDestCid, Path);
    Path->DestCid->CID.UsedLocally = TRUE;
    Path->InitiatedCidUpdate = TRUE;
    QuicPathValidate(Path);
    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathUpdateActive(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_PATH_SET* PathSet = &Connection->Paths;
    if (PathSet->PendingActivePathId == QuicPathGetActive(PathSet)->ID) {
        //
        // The active path hasn't changed, nothing to do.
        //
        return;
    }

    //
    // A path needs a usable destination CID before it can become active.
    //
    QUIC_PATH* NextActivePath =
        QuicConnGetPathByID(Connection, PathSet->PendingActivePathId);
    CXPLAT_DBG_ASSERT(NextActivePath != NULL);
    if (!QuicPathUpdateDestCid(Connection, NextActivePath)) {
        QuicTraceLogConnWarning(
            ActivePathCidAssignmentFailed,
            Connection,
            "Failed to assign a destination CID to Path[%u], it will not become active",
            NextActivePath->ID);
        PathSet->PendingActivePathId = QuicPathGetActive(PathSet)->ID;
        return;
    }

    QuicPathSetActive(Connection, PathSet->PendingActivePathId);

    QUIC_PATH* ActivePath = QuicPathGetActive(PathSet);
    QuicTraceEvent(
        ConnRemoteAddrAdded,
        "[conn][%p] New Remote IP: %!ADDR!",
        Connection,
        CASTED_CLOG_BYTEARRAY(
            sizeof(ActivePath->Route.RemoteAddress),
            &ActivePath->Route.RemoteAddress)); // TODO - Addr removed event?

    QUIC_CONNECTION_EVENT Event;
    Event.Type = QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED;
    Event.PEER_ADDRESS_CHANGED.Address = &ActivePath->Route.RemoteAddress;
    QuicTraceLogConnVerbose(
        IndicatePeerAddrChanged,
        Connection,
        "Indicating QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED");
    (void)QuicConnIndicateEvent(Connection, &Event);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicPathRemove(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path
    )
{
    QUIC_PATH_SET* PathSet = &Connection->Paths;
    CXPLAT_DBG_ASSERT(PathSet->Count <= QUIC_MAX_PATH_COUNT);
    CXPLAT_DBG_ASSERT(
        Path >= PathSet->Paths && Path < PathSet->Paths + PathSet->Count);
    CXPLAT_DBG_ASSERT(Path->InUse);
    CXPLAT_DBG_ASSERT(
        PathSet->PendingActivePathId == QuicPathGetActive(PathSet)->ID ||
        Path->ID != PathSet->PendingActivePathId);

    size_t Index = Path - PathSet->Paths;
    const uint32_t RemovedPathId = Path->ID;

    QuicTraceEvent(
        ConnPathRemoved,
        "[conn][%p] Path[%u] Removed",
        Connection,
        Path->ID);

    if (PathSet->Count == 1) {
        //
        // Last remaining path. Silently close per RFC 9000 sections 8.2.4 +
        // 10.2, but leave the Paths array intact so in-flight operations see
        // a valid Paths[0] until shutdown completes.
        //
        if (!Connection->State.ClosedLocally) {
            QuicConnCloseLocally(
                Connection,
                QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
                (uint64_t)QUIC_STATUS_UNREACHABLE,
                NULL);
        }
        return FALSE;
    }

    BOOLEAN CloseWithNowhereToGo = FALSE;

    if (Index == 0 && !Connection->State.MultipathNegotiated) {
        CXPLAT_DBG_ASSERT(PathSet->Count > 1);
        //
        // Promoting a replacement is a non-multipath concern: there the
        // active path has to be Paths[0] and QuicPathSetActive swaps it in.
        // Under multipath several paths carry IsActive independently,
        // QuicPathSetActive performs no swap, and raising the flag on another
        // path would only reset its congestion control and leave
        // QuicPathSetActive's trailing asserts examining Paths[0] -- the path
        // being removed -- rather than the promoted one. So nothing is
        // promoted there.
        //
        // Removing the active path while other paths exist. Whatever is
        // promoted has to be something QuicPathSetActive accepts and the
        // connection can actually send on: a path ID (QuicPathSetActive resets
        // its congestion control), no close in progress, and a usable
        // destination CID -- which is what QuicPathUpdateDestCid answers,
        // assigning one from the path ID's store when the path has none yet.
        // Prefer a peer validated path, take any of them otherwise.
        //
        // The two passes are upstream's: a CID is only drawn for a path that is
        // about to be promoted, so a candidate that loses to a peer validated
        // one does not spend an unused CID on the way past.
        //
        size_t FallbackIndex = 0;
        for (size_t Pass = 0; Pass < 2 && FallbackIndex == 0; ++Pass) {
            for (size_t j = 1; j < PathSet->Count; ++j) {
                QUIC_PATH* Candidate = &PathSet->Paths[j];
                if (Candidate->PathID == NULL ||
                    Candidate->LocalClose ||
                    Candidate->RemoteClose) {
                    continue;
                }
                if (Pass == 0 && !Candidate->IsPeerValidated) {
                    continue;
                }
                if (QuicPathUpdateDestCid(Connection, Candidate)) {
                    FallbackIndex = j;
                    break;
                }
            }
        }

        if (FallbackIndex != 0) {
            QuicTraceLogConnInfo(
                PathActiveFallback,
                Connection,
                "Path[%u] removed; falling back to Path[%u]",
                Path->ID,
                PathSet->Paths[FallbackIndex].ID);
            QuicPathSetActive(Connection, PathSet->Paths[FallbackIndex].ID);
            //
            // QuicPathSetActive swapped Paths[0] and Paths[FallbackIndex], so
            // the path being removed now lives at FallbackIndex and we remove
            // it there.
            //
            Index = FallbackIndex;

        } else {
            //
            // Without multipath there is exactly one active path and nothing
            // able to take over, so the connection has nowhere left to send.
            //
            // The removal still has to happen before closing, which is why the
            // close is deferred to the end rather than taken here the way
            // upstream does. Callers release this path's binding before calling
            // whenever Count > 1 and rely on the slot being gone; returning
            // early would leave an InUse, IsActive Paths[0] with a NULL binding
            // for the rest of the operation batch, which a flush in that same
            // batch would dereference.
            //
            // QuicConnRemovePath handles its own version of this case by moving
            // the departing path's destination CID to the survivor instead,
            // which can keep the connection alive. Doing that here would change
            // every QuicPathRemove caller's behaviour, so it is left alone.
            //
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "No path to fall back to");
            CloseWithNowhereToGo = TRUE;
        }
    }

    //
    // After the fallback swap above the path being removed lives at
    // Paths[Index], so work from there rather than through the (now possibly
    // stale) Path pointer.
    //
    QUIC_PATH* RemovedPath = &PathSet->Paths[Index];

    //
    // Retire the CID this path was using, so it is not left marked as used by
    // a path that no longer exists. Upstream's #6418; done through the path ID
    // that owns the CID store here, and before the reference below drops.
    //
    if (RemovedPath->DestCid != NULL) {
        if (RemovedPath->PathID != NULL &&
            RemovedPath->DestCid->CID.Length != 0 &&
            !RemovedPath->DestCid->CID.Retired) {
            QuicPathIDRetireCid(RemovedPath->PathID, RemovedPath->DestCid);
        }
        RemovedPath->DestCid = NULL;
    }

    //
    // Release the removed path's PathID reference.
    //
    // PathID can be NULL when a path was added but failed to fully open (e.g.
    // QuicConnOpenNewPath failing at binding creation, before a PathID is
    // assigned); QuicConnAddPath then calls here to undo the half-added slot.
    //
    if (RemovedPath->PathID != NULL) {
        //
        // Keep the addresses, so a PATH_REMOVED indicated after this still
        // describes the path it is about. PathID->Path is left behind pointing
        // at a slot another path may be about to shift into.
        //
        QUIC_PATHID* RemovedPathID = RemovedPath->PathID;
        RemovedPathID->RemovedLocalAddress = RemovedPath->Route.LocalAddress;
        RemovedPathID->RemovedRemoteAddress = RemovedPath->Route.RemoteAddress;
        RemovedPathID->Flags.RemovedAddressesValid = TRUE;

        QuicPathIDRelease(RemovedPathID, QUIC_PATHID_REF_PATH);
        RemovedPath->PathID = NULL;
    }

    if (Index + 1 < PathSet->Count) {
        CxPlatMoveMemory(
            PathSet->Paths + Index,
            PathSet->Paths + Index + 1,
            (PathSet->Count - Index - 1) * sizeof(QUIC_PATH));
        if (Connection->State.MultipathNegotiated) {
            //
            // Update all PathID back references.
            //
            for (size_t i = Index; i < (size_t)PathSet->Count - 1; ++i) {
                if (PathSet->Paths[i].PathID != NULL) {
                    PathSet->Paths[i].PathID->Path = &PathSet->Paths[i];
                }
            }
        }
    }

    PathSet->Count--;
    // NOLINTNEXTLINE(clang-analyzer-security.ArrayBound): False positive: new index is valid.
    PathSet->Paths[PathSet->Count].InUse = FALSE;

    //
    // Keep upstream's deferred activation honest. PendingActivePathId may name
    // the path just removed: under multipath nothing is promoted in its place
    // (see above), and this fork removes paths from places that know nothing
    // about the pending id -- a path ID abandoned, a close timer expiring, the
    // reconciler trading a slot. QuicPathUpdateActive then looks the id up at
    // the end of the receive batch, finds nothing, and asserts
    // (NextActivePath != NULL). Pointed at whatever holds slot 0 now, which is
    // what the non-multipath promotion above would have left it as.
    //
    if (PathSet->PendingActivePathId == RemovedPathId && PathSet->Count > 0) {
        PathSet->PendingActivePathId = PathSet->Paths[0].ID;
    }

    //
    // Without multipath every path shares one path ID, so PathID->Path is a
    // single pointer that can only name one of them -- and whichever path was
    // created last won it, because QuicConnGetPathForPacket sets it
    // unconditionally. Removing that path left the pointer at a slot that is no
    // longer in use, which congestion control goes on reading an MTU and an RTT
    // from and writing route state into (cubic.c, bbr.c). Repointed at the
    // active path, which is the one actually sending.
    //
    // The multipath case is covered by the shift fix-up above, where each path
    // has a path ID of its own and the pointer means something per path.
    //
    if (!Connection->State.MultipathNegotiated &&
        PathSet->Paths[0].PathID != NULL) {
        PathSet->Paths[0].PathID->Path = &PathSet->Paths[0];
    }

    if (CloseWithNowhereToGo && !Connection->State.ClosedLocally) {
        QuicConnCloseLocally(
            Connection,
            QUIC_CLOSE_INTERNAL_SILENT | QUIC_CLOSE_QUIC_STATUS,
            (uint64_t)QUIC_STATUS_UNREACHABLE,
            NULL);
    }

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathUpdateDestCids(
    _In_ QUIC_PATH_SET* PathSet,
    _In_ QUIC_CONNECTION* Connection
    )
{
    //
    // Iterate forward so paths at the front get destination CIDs first.
    //
    size_t i = 0;
    while (i < PathSet->Count) {
        QUIC_PATH* Path = &PathSet->Paths[i];
        if (QuicPathUpdateDestCid(Connection, Path)) {
            ++i;
            continue;
        }

        if (Path->IsActive) {
            QuicTraceEvent(
                ConnError,
                "[conn][%p] ERROR, %s.",
                Connection,
                "Active path has no replacement for retired CID");
            if (Path->DestCid != NULL) {
                Path->DestCid->CID.Retired = FALSE;
            }
            QuicConnSilentlyAbort(Connection);
            return;
        }

        QuicTraceLogConnWarning(
            NonActivePathCidRetired,
            Connection,
            "Non-active path has no replacement for retired CID.");
        CXPLAT_DBG_ASSERT(i != 0);

        //
        // Paths hold their own binding reference on this fork, and
        // QuicPathRemove does not release it, so this follows the same
        // convention as every other caller. The source CIDs registered on an
        // unconnected binding belong to the connection rather than to this
        // path, so they are only withdrawn once no other path still holds it.
        //
        if (Path->Binding != NULL) {
            if (!Path->UseBound && !QuicConnIsBindingShared(Connection, Path)) {
                QuicBindingRemoveAllSourceConnectionIDs(Path->Binding, Connection);
            }
            QuicLibraryReleaseBinding(Path->Binding);
            Path->Binding = NULL;
        }

        if (!QuicPathRemove(Connection, Path)) {
            break;
        }
    }

#if DEBUG
    //
    // Destination CIDs hang off the path ID here rather than the connection, so
    // the check upstream runs over one list runs over each path's own. Paths
    // share a path ID when multipath was not negotiated, which only means a
    // list can be walked twice.
    //
    for (size_t j = 0; j < PathSet->Count; ++j) {
        const QUIC_PATHID* PathID = PathSet->Paths[j].PathID;
        if (PathID == NULL) {
            continue;
        }
        for (CXPLAT_LIST_ENTRY* Entry = PathID->DestCids.Flink;
                Entry != &PathID->DestCids;
                Entry = Entry->Flink) {
            QUIC_CID_LIST_ENTRY* DestCid =
                CXPLAT_CONTAINING_RECORD(
                    Entry,
                    QUIC_CID_LIST_ENTRY,
                    Link);
            if (DestCid->CID.Retired) {
                QuicCidValidateUnused(PathSet, DestCid);
            }
        }
    }
#endif
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathSetAllowance(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ uint32_t NewAllowance
    )
{
    Path->Allowance = NewAllowance;
    BOOLEAN IsBlocked = Path->Allowance < QuicPathGetMinSendAllowance(Path);

    if (!Path->IsPeerValidated) {
        if (!IsBlocked) {
            if (QuicPathIDRemoveOutFlowBlockedReason(
                    Path->PathID, QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT)) {

                if (Connection->Send.SendFlags != 0) {
                    //
                    // We were blocked by amplification protection (no allowance
                    // left) and we have stuff to send, so flush the send now.
                    //
                    QuicSendQueueFlush(&Connection->Send, REASON_AMP_PROTECTION);
                }

                //
                // Now that we are no longer blocked by amplification protection
                // we need to re-enable the loss detection timers. This call may
                // even cause the loss timer to fire immediately because packets
                // were already lost, but we didn't know it.
                //
                QuicLossDetectionUpdateTimer(&Path->PathID->LossDetection, TRUE);
            }

        } else {
            QuicPathIDAddOutFlowBlockedReason(
                Path->PathID, QUIC_FLOW_BLOCKED_AMPLIFICATION_PROT);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathSetValid(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ QUIC_PATH_VALID_REASON Reason
    )
{
    if (Path->IsPeerValidated) {
        return;
    }

    QuicTraceEvent(
        ConnPathValidated,
        "[conn][%p] Path[%u] Validated (%hhu)",
        Connection,
        Path->ID,
        Reason);

    //
    // Only indicated when the application asked for it. Every connection
    // validates its initial path, so indicating this unconditionally delivers a
    // fork-only event to applications built against an msquic that has no such
    // event -- which is what broke the down-level tests, where a released test
    // binary runs against this library and rejects the unknown event outright.
    //
    if (Connection->Settings.PathValidatedEventEnabled) {
        QUIC_CONNECTION_EVENT Event;
        Event.Type = QUIC_CONNECTION_EVENT_PATH_VALIDATED;
        Event.PATH_VALIDATED.LocalAddress = &Path->Route.LocalAddress;
        Event.PATH_VALIDATED.RemoteAddress = &Path->Route.RemoteAddress;
        QuicTraceLogConnVerbose(
            IndicatePathValidated,
            Connection,
            "Indicating QUIC_CONNECTION_EVENT_PATH_VALIDATED");
        (void)QuicConnIndicateEvent(Connection, &Event);
    }

    Path->IsPeerValidated = TRUE;
    QuicPathSetAllowance(Connection, Path, UINT32_MAX);

    if (Reason == QUIC_PATH_VALID_PATH_RESPONSE) {
        //
        // If the active path was just validated, then let's queue up DPLPMTUD.
        // This will force validate min mtu if it has not already been
        // validated.
        //
        QuicMtuDiscoveryPeerValidated(&Path->MtuDiscovery, Connection);
    }

    //
    // One fewer in-progress validation; re-evaluate (or cancel) the timer.
    //
    QuicConnPathValidationTimerUpdate(Connection);

    //
    // Only a PATH_RESPONSE means the peer answered us on this path, which is
    // what make-before-break waits for. The other reasons are handshake
    // artefacts of the initial path, where there is nothing to migrate onto.
    //
    // Last, after the allowance and the timer: completing a migration activates
    // a path and may remove another, and the bookkeeping for the path that just
    // validated should be finished before that happens.
    //
    if (Reason == QUIC_PATH_VALID_PATH_RESPONSE) {
        QuicConnAutoPathValidated(Connection, Path);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
_Success_(return != NULL)
QUIC_PATH*
QuicConnGetPathByID(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t ID
    )
{
    QUIC_PATH_SET* PathSet = &Connection->Paths;
    for (size_t i = 0; i < PathSet->Count; ++i) {
        if (PathSet->Paths[i].ID == ID) {
            return &PathSet->Paths[i];
        }
    }
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicPathMatchPacket(
    _In_ const QUIC_PATH* Path,
    _In_ const QUIC_RX_PACKET* Packet
    )
{
    return
        QuicAddrCompare(
            &Packet->Route->LocalAddress,
            &Path->Route.LocalAddress) &&
        QuicAddrCompare(
            &Packet->Route->RemoteAddress,
            &Path->Route.RemoteAddress);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
QUIC_PATH*
QuicConnGetPathByAddress(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_ADDR* LocalAddress,
    _In_ const QUIC_ADDR* RemoteAddress
    )
{
    for (uint8_t i = 0; i < Connection->Paths.Count; ++i) {
        if (QuicAddrCompare(
                LocalAddress,
                &Connection->Paths.Paths[i].Route.LocalAddress) &&
            QuicAddrCompare(
                RemoteAddress,
                &Connection->Paths.Paths[i].Route.RemoteAddress)) {
            return &Connection->Paths.Paths[i];
        }
    }
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
QUIC_PATH*
QuicConnGetPathForPacket(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_RX_PACKET* Packet
    )
{
    QUIC_PATH_SET* PathSet = &Connection->Paths;
    BOOLEAN FatalError = FALSE;
    QUIC_PATHID* PathID = QuicPathIDSetGetPathIDForLocal(&Connection->PathIDs, Packet->PathId, &FatalError);
    CXPLAT_DBG_ASSERT(!FatalError);
    if (PathID == NULL) {
        return NULL;
    }
    BOOLEAN IsRebind = FALSE;

    //
    // A packet matches a path here only if it also carries that path's path ID,
    // which is the part upstream's QuicPathMatchPacket knows nothing about.
    //
    for (size_t i = 0; i < PathSet->Count; ++i) {
        if (PathID != PathSet->Paths[i].PathID ||
            !QuicPathMatchPacket(&PathSet->Paths[i], Packet)) {
            if (!Connection->State.HandshakeConfirmed) {
                //
                // Ignore packets on any other paths until connected/confirmed.
                //
                QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
                return NULL;
            }
            if (!IsRebind) {
                //
                // The packet did not match this path, but it may still be the
                // same path seen through a NAT that changed its port: same path
                // ID, same local address, same remote address but for the port.
                // That is a rebind of an existing path rather than a new one,
                // and the check below lets it through.
                //
                IsRebind =
                    PathID == PathSet->Paths[i].PathID &&
                    QuicAddrGetFamily(&Packet->Route->RemoteAddress) == QuicAddrGetFamily(&PathSet->Paths[i].Route.RemoteAddress)
                    && QuicAddrCompareIp(&Packet->Route->RemoteAddress, &PathSet->Paths[i].Route.RemoteAddress)
                    && QuicAddrCompare(&Packet->Route->LocalAddress, &PathSet->Paths[i].Route.LocalAddress);
            }
            continue;
        }
        QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
        return &PathSet->Paths[i];
    }

    if (PathID->Flags.Abandoned ||
        PathID->Flags.WaitClose ||
        PathID->Flags.Closed) {
        //
        // A path ID on its way out gets no path. A late or reordered packet
        // can arrive after both ends have declared the path ID dead -- the
        // receive side answers a PATH_ABANDON for a path ID with no path and
        // sets Abandoned there -- and attaching one here would allocate a
        // slot, initialize congestion control and make the path selectable
        // for sending, only for the close timer to tear it all down again.
        //
        QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
        return NULL;
    }

    if (!((QuicConnIsClient(Connection) && Connection->State.ServerMigrationNegotiated) ||
          (QuicConnIsServer(Connection) && !Connection->State.ServerMigrationNegotiated))) {
        // Client doesn't create a new path.
        QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
        return NULL;
    }

    if (Connection->State.MultipathNegotiated &&
        PathID->Flags.InUse &&
        !IsRebind) {
        //
        // With multipath a path ID identifies one path, so a path ID that
        // already has one cannot acquire a second. Reaching here means the
        // packet carried a path ID in use, from an address that is neither that
        // path's nor a rebind of it, which is not something to open a path for.
        //
        QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
        return NULL;
    }

    if (PathSet->Count == QUIC_MAX_PATH_COUNT) {
        //
        // See if any old paths share the same remote address, and is just a rebind.
        // If so, remove the old paths.
        //
        // Iterate backward when removing path to not invalidate the array.
        //
        for (int32_t i = (int32_t)PathSet->Count - 1; i > 0; --i) {
            QUIC_PATH* OldPath = &PathSet->Paths[i];
            if (!OldPath->IsActive &&
                //
                // Upstream's guard: a path that is about to become active when
                // the receive batch finishes is not a stale rebind to evict.
                //
                OldPath->ID != PathSet->PendingActivePathId &&
                QuicAddrGetFamily(&Packet->Route->RemoteAddress) ==
                    QuicAddrGetFamily(&OldPath->Route.RemoteAddress) &&
                QuicAddrCompareIp(
                    &Packet->Route->RemoteAddress,
                    &OldPath->Route.RemoteAddress) &&
                QuicAddrCompare(
                    &Packet->Route->LocalAddress,
                    &OldPath->Route.LocalAddress)) {
                //
                // Paths hold their own binding reference on this fork, so the
                // slot cannot just be dropped.
                //
                CXPLAT_DBG_ASSERT(OldPath->Binding != NULL);
                QuicLibraryReleaseBinding(OldPath->Binding);
                OldPath->Binding = NULL;
                if (QuicPathRemove(Connection, OldPath)) {
                    break;
                }
            }
        }

        if (PathSet->Count == QUIC_MAX_PATH_COUNT) {
            //
            // Already tracking the maximum number of paths, and can't free
            // any more.
            //
            QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
            return NULL;
        }
    }

    if (PathSet->NextPathId == UINT32_MAX) {
        QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
        return NULL;
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
        if (QuicAddrCompare(&Packet->Route->LocalAddress, &Bound->Address)) {
            break;
        }
        Bound = NULL;
    }
    if (Bound == NULL || Bound->Removing) {
        //
        // No matching local address found.
        //
        QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
        return NULL;
    }

    CXPLAT_DBG_ASSERT(Bound->Binding != NULL);
    if (!QuicLibraryTryAddRefBinding(Bound->Binding)) {
        QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
        return NULL;
    }

    if (PathSet->Count > 1) {
        //
        // Make room for the new path (at index 1).
        //
        CxPlatMoveMemory(
            &PathSet->Paths[2],
            &PathSet->Paths[1],
            (PathSet->Count - 1) * sizeof(QUIC_PATH));
        if (Connection->State.MultipathNegotiated) {
            //
            // Update all PathID back references.
            //
            for (size_t i = 2; i < (size_t)PathSet->Count + 1; ++i) {
                if (PathSet->Paths[i].PathID != NULL) {
                    PathSet->Paths[i].PathID->Path = &PathSet->Paths[i];
                }
            }
        }
    }

    CXPLAT_DBG_ASSERT(PathSet->Count < QUIC_MAX_PATH_COUNT);
    QUIC_PATH* Path = &PathSet->Paths[1];
    QuicPathInitialize(
        PathSet->NextPathId++, Connection, Path, QUIC_PATH_ORIGIN_PEER);
    PathSet->Count++;

    QUIC_PATH* ActivePath = QuicPathGetActive(PathSet);
    if (ActivePath->DestCid->CID.Length == 0) {
        Path->DestCid = ActivePath->DestCid; // TODO - Copy instead?
    }
    Path->UseBound = TRUE;
    Path->Binding = Bound->Binding;
    QuicPathIDAddRef(PathID, QUIC_PATHID_REF_PATH);
    Path->PathID = PathID;
    PathID->Path = Path;
    //
    // Only a path ID being claimed for the first time needs its congestion
    // control set up. Getting here with one already in use means a rebind, and
    // the path it rebinds carries on with the state it had built up.
    //
    if (!PathID->Flags.InUse) {
        if (Connection->State.MultipathNegotiated) {
            QuicCongestionControlInitialize(&PathID->CongestionControl, &Connection->Settings);
        }
        PathID->Flags.InUse = TRUE;
    }
    QuicCopyRouteInfo(&Path->Route, Packet->Route);
    Path->Route.State = RouteUnresolved;
    Path->Route.Queue = NULL;

    QuicPathValidate(Path);
    QuicPathIDRelease(PathID, QUIC_PATHID_REF_LOOKUP);
    return Path;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_notnull_
QUIC_PATH*
QuicConnChoosePath(
    _In_ QUIC_CONNECTION* Connection
    )
{
    QUIC_PATH* Path = &Connection->Paths.Paths[0];

    if (Connection->State.MultipathNegotiated && Connection->State.HandshakeConfirmed) {
        QUIC_PATH* ActivePaths[QUIC_MAX_PATH_COUNT];
        uint8_t ActivePathCount = 0;
        for (uint8_t i = 0; i < Connection->Paths.Count; ++i) {
            if (Connection->Paths.Paths[i].IsActive &&
                !Connection->Paths.Paths[i].LocalClose &&
                !Connection->Paths.Paths[i].RemoteClose &&
                //
                // A path with no path ID is not a candidate, which is #213.
                //
                // It is not a half-built path to be tolerated for a moment
                // either: QuicConnAssignPathIDs leaves one here on purpose
                // when no path ID is free, to be picked up when one is. Until
                // then the path cannot carry anything --
                // QuicPacketBuilderInitialize refuses a path whose path ID has
                // no source CID ("No src CID to send with") -- so choosing it
                // spends a flush on a path that cannot send, and the trace
                // below used to read PathID->ID through the NULL and take the
                // process with it.
                //
                Connection->Paths.Paths[i].PathID != NULL) {
                ActivePaths[ActivePathCount++] = &Connection->Paths.Paths[i];
            }
        }
        if (ActivePathCount > 0) {
            uint8_t Random;
            CxPlatRandom(sizeof(Random), &Random);
            Path = ActivePaths[Random % ActivePathCount];
        }
    }

    //
    // Paths[0] is the fallback and gets no such test: this function promises a
    // path, and the connection's own first path is the only thing left to
    // return. It normally has a path ID from QuicConnInitialize, but the
    // promise is what matters here, so the trace carries the shortage instead
    // of dereferencing it.
    //
    // Reported as UINT32_MAX rather than through a second trace id, so that
    // "chosen with no path ID" is visible in a log that has one line per
    // choice. Path ID 0 is a real id and could not have said it.
    //
    QuicTraceLogConnInfo(
        PathChosen,
        Connection,
        "Path[%u][PathID][%u] Chosen",
        Path->ID,
        Path->PathID != NULL ? Path->PathID->ID : UINT32_MAX);

    return Path;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnHasOtherUsablePath(
    _In_ const QUIC_CONNECTION* Connection,
    _In_ const QUIC_PATH* ExcludedPath
    )
{
    if (!Connection->State.MultipathNegotiated ||
        !Connection->State.HandshakeConfirmed) {
        //
        // QuicConnChoosePath returns Paths[0] regardless until both of these
        // hold, so no other path is usable whatever its own flags say.
        //
        return FALSE;
    }

    for (uint8_t i = 0; i < Connection->Paths.Count; ++i) {
        const QUIC_PATH* Path = &Connection->Paths.Paths[i];
        //
        // **A path declared backup counts, and that is the point of this
        // function.** PATH_BACKUP says "prefer not to send here", not "cannot":
        // QuicConnChoosePath honours the preference while any active path
        // remains, and an application can promote a backup the moment it needs
        // to. The question here is whether the connection has anywhere left to
        // go at all, which a live backup path is.
        //
        // Testing IsActive answered a different question and made a reasonable
        // application fragile. A sender that spreads traffic over every active
        // path -- QuicConnChoosePath picks among them at random -- forces an
        // application that wants one stable path to declare every other one
        // backup. With that done, the only active path is the one carrying
        // traffic, so when *it* died both callers -- loss detection giving up
        // on a path, and a path validation that timed out -- found "no other
        // usable path" and closed the whole connection: a path failure became a connection
        // failure, for the application that had followed the mechanism this
        // fork offers it.
        //
        // The path ID test is new here and is the other half of being usable:
        // QuicConnChoosePath already refuses a path without one (#213) and
        // QuicPacketBuilderInitialize refuses to send on it ("No src CID to
        // send with"), so counting such a path would answer this question
        // wrongly in the opposite direction -- abandon the dead path, then have
        // nothing that can actually carry the PATH_ABANDON frame.
        //
        if (Path != ExcludedPath &&
            !Path->LocalClose &&
            !Path->RemoteClose &&
            Path->PathID != NULL) {
            return TRUE;
        }
    }
    return FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Ret_maybenull_
QUIC_PATH*
QuicConnGetPathForPathID(
    _In_ QUIC_CONNECTION* Connection,
    _In_ const QUIC_PATHID* PathID
    )
{
    for (uint8_t i = 0; i < Connection->Paths.Count; ++i) {
        if (Connection->Paths.Paths[i].PathID == PathID) {
            return &Connection->Paths.Paths[i];
        }
    }
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicConnIsBindingShared(
    _In_ const QUIC_CONNECTION* Connection,
    _In_ const QUIC_PATH* Path
    )
{
    for (uint8_t i = 0; i < Connection->Paths.Count; ++i) {
        const QUIC_PATH* Other = &Connection->Paths.Paths[i];
        if (Other != Path && Other->Binding == Path->Binding) {
            return TRUE;
        }
    }
    return FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathSetActive(
    _In_ QUIC_CONNECTION* Connection,
    _In_ uint32_t PathId
    )
{
    BOOLEAN UdpPortChangeOnly = FALSE;
    QUIC_PATH* Path = QuicConnGetPathByID(Connection, PathId);
    CXPLAT_DBG_ASSERT(Path != NULL);

    QUIC_PATH* ActivePath = QuicPathGetActive(&Connection->Paths);
    if (Connection->State.MultipathNegotiated) {
        //
        // Under multipath IsActive is per path and several carry it at once, so
        // there is nothing to swap into slot 0: the named path simply becomes
        // one of the active ones.
        //
        Path->IsActive = TRUE;
    } else if (Path == ActivePath) {
        CXPLAT_DBG_ASSERT(!Path->IsActive);
        Path->IsActive = TRUE;
    } else {
        CXPLAT_DBG_ASSERT(Path->DestCid != NULL);
        //
        // Server side only on this fork: a client that changes its own port is
        // migrating, and treating that as a port-only change would carry the
        // old path's MTU validation onto a path it has not probed.
        //
        UdpPortChangeOnly =
            QuicConnIsServer(Connection) &&
            QuicAddrGetFamily(&Path->Route.RemoteAddress) == QuicAddrGetFamily(&ActivePath->Route.RemoteAddress) &&
            QuicAddrCompareIp(&Path->Route.RemoteAddress, &ActivePath->Route.RemoteAddress);

        QUIC_PATH PrevActivePath = *ActivePath;

        PrevActivePath.IsActive = FALSE;
        Path->IsActive = TRUE;
        if (UdpPortChangeOnly) {
            //
            // We assume port only changes don't change the PMTU.
            //
            Path->IsMinMtuValidated = PrevActivePath.IsMinMtuValidated;
        }

        *ActivePath = *Path;
        *Path = PrevActivePath;
    }

    //
    // When changing path, we need to increment the sequence number for observed
    // address.
    //
    if (Path->SendObservedAddress) {
        Connection->ObservedAddressSequenceNumber++;
        if (Connection->State.ObservedAddressNegotiated) {
            QuicSendSetSendFlag(
                &Connection->Send,
                QUIC_CONN_SEND_FLAG_OBSERVED_ADDRESS);
        }
    }

    QuicTraceEvent(
        ConnPathActive,
        "[conn][%p] Path[%u] Set active (rebind=%hhu)",
        Connection,
        ActivePath->ID,
        UdpPortChangeOnly);

    if (!UdpPortChangeOnly) {
        QuicCongestionControlReset(&Path->PathID->CongestionControl, FALSE);
    }
    //
    // Records what the batch's deferred activation should settle on, which is
    // what QuicPathUpdateActive reads. Under multipath nothing was swapped, so
    // this names the slot-0 path it already named.
    //
    Connection->Paths.PendingActivePathId = ActivePath->ID;
    CXPLAT_DBG_ASSERT(ActivePath->DestCid != NULL);
    CXPLAT_DBG_ASSERT(!ActivePath->DestCid->CID.Retired);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPathUpdateQeo(
    _In_ QUIC_CONNECTION* Connection,
    _In_ QUIC_PATH* Path,
    _In_ CXPLAT_QEO_OPERATION Operation
    )
{
    const QUIC_CID_SLIST_ENTRY* SourceCid =
        CXPLAT_CONTAINING_RECORD(Path->PathID->SourceCids.Next, QUIC_CID_SLIST_ENTRY, Link);
    CXPLAT_QEO_CONNECTION Offloads[2] = {
    {
        Operation,
        CXPLAT_QEO_DIRECTION_TRANSMIT,
        CXPLAT_QEO_DECRYPT_FAILURE_ACTION_DROP,
        0, // KeyPhase
        0, // Reserved
        CXPLAT_QEO_CIPHER_TYPE_AEAD_AES_256_GCM,
        Path->PathID->NextPacketNumber,
        Path->Route.RemoteAddress,
        Path->DestCid->CID.Length,
    },
    {
        Operation,
        CXPLAT_QEO_DIRECTION_RECEIVE,
        CXPLAT_QEO_DECRYPT_FAILURE_ACTION_DROP,
        0, // KeyPhase
        0, // Reserved
        CXPLAT_QEO_CIPHER_TYPE_AEAD_AES_256_GCM,
        0, // NextPacketNumber
        Path->Route.LocalAddress,
        SourceCid->CID.Length,
    }};
    CxPlatCopyMemory(Offloads[0].ConnectionId, Path->DestCid->CID.Data, Path->DestCid->CID.Length);
    CxPlatCopyMemory(Offloads[1].ConnectionId, SourceCid->CID.Data, SourceCid->CID.Length);

    if (Operation == CXPLAT_QEO_OPERATION_ADD) {
        CXPLAT_DBG_ASSERT(Path->PathID->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]);
        Offloads[0].KeyPhase = Path->PathID->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]->CurrentKeyPhase;
        Offloads[1].KeyPhase = Path->PathID->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]->CurrentKeyPhase;
        Offloads[1].NextPacketNumber = Path->PathID->Packets[QUIC_ENCRYPT_LEVEL_1_RTT]->AckTracker.LargestPacketNumberAcknowledged;
        if (QuicTlsPopulateOffloadKeys(Connection->Crypto.TLS, Connection->Crypto.TlsState.WriteKeys[QUIC_PACKET_KEY_1_RTT], "Tx offload", &Offloads[0]) &&
            QuicTlsPopulateOffloadKeys(Connection->Crypto.TLS, Connection->Crypto.TlsState.ReadKeys[QUIC_PACKET_KEY_1_RTT],  "Rx offload", &Offloads[1]) &&
            QUIC_SUCCEEDED(CxPlatSocketUpdateQeo(Path->Binding->Socket, Offloads, 2))) {
            Connection->Stats.EncryptionOffloaded = TRUE;
            Path->EncryptionOffloading = TRUE;
            QuicTraceLogConnInfo(
                PathQeoEnabled,
                Connection,
                "Path[%u] QEO enabled",
                Path->ID);
        }
        CxPlatSecureZeroMemory(Offloads, sizeof(Offloads));
    } else {
        CXPLAT_DBG_ASSERT(Path->EncryptionOffloading);
        (void)CxPlatSocketUpdateQeo(Path->Binding->Socket, Offloads, 2);
        Path->EncryptionOffloading = FALSE;
        QuicTraceLogConnInfo(
            PathQeoDisabled,
            Connection,
            "Path[%u] QEO disabled",
            Path->ID);
    }
}
