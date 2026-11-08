/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    The candidate pair table: every (local address, remote address) combination
    this connection could carry a path on, ordered best first.

    Stage 1 of #157. A path is a pair, and until now nothing computed the pair:
    the local-address machinery chose a local address for remotes already in
    use, and the remote-address machinery chose a remote address and left the
    local one wildcard. This is the single place that enumerates both.

    Deliberately pure. Nothing here touches a QUIC_CONNECTION, allocates, or
    calls the platform -- the caller does the route lookups and hands the
    results in. That is what makes the ranking, which is the part worth getting
    wrong, testable on its own.

--*/

#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

//
// How many pairs the table holds. The product is bounded by
// QUIC_MAX_LOCAL_ADDRESS_COUNT (128) times QUIC_MAX_ALTERNATIVE_ADDRESSES (8)
// plus the current remote, which is far more than QUIC_MAX_PATH_COUNT (4) can
// ever use. So the product is enumerated but not stored: a pair is kept only
// if it beats the worst one already held, which bounds memory here rather than
// letting the peer's advertised count decide it.
//
#define QUIC_MAX_CANDIDATE_PAIRS 16

//
// Where a remote address sits relative to the path the connection is on.
//
// draft-munizaga-quic-alternative-server-address puts a CURRENT_PATH sentinel
// in the middle of its address list: entries before it are ones the server
// would rather we used than the path its frame arrived on, entries after it are
// backups. The current path's own remote address is neither -- it *is* the
// sentinel's position -- so this is three-valued rather than a boolean. Stage 4
// needs that distinction: it may only migrate to something ranked strictly
// above where the connection already is.
//
typedef enum QUIC_CANDIDATE_SENTINEL_RANK {

    QUIC_CANDIDATE_PREFERRED_TO_CURRENT = 0,
    QUIC_CANDIDATE_CURRENT              = 1,
    QUIC_CANDIDATE_BACKUP               = 2,

} QUIC_CANDIDATE_SENTINEL_RANK;

typedef struct QUIC_CANDIDATE_PAIR {

    //
    // Threaded in priority order, best first.
    //
    CXPLAT_LIST_ENTRY Link;

    QUIC_ADDR LocalAddress;
    QUIC_ADDR RemoteAddress;

    //
    // The local address is the one routing would send to this remote from.
    //
    BOOLEAN RoutePreferred;

    uint8_t SentinelRank;       // QUIC_CANDIDATE_SENTINEL_RANK
    QUIC_VAR_INT PriorityHint;  // Lower is higher priority.

    //
    // Stage 1 reserved a PathIndex and a HasPath here for stage 3 to fill in.
    // Stage 3 does not want them. An index into Connection->Paths cannot be
    // kept valid -- QuicPathRemove memmoves the array and QuicConnAddPath
    // inserts at index 1, so every mutation the reconciler makes invalidates
    // the indices of the pairs it has not reached yet. The mapping is derived
    // by address instead, which is cheap at four paths and cannot go stale.
    //

} QUIC_CANDIDATE_PAIR;

typedef struct QUIC_CANDIDATE_SET {

    CXPLAT_LIST_ENTRY Pairs;    // Ordered, best first. Holds Count entries.
    uint8_t Count;
    QUIC_CANDIDATE_PAIR Pool[QUIC_MAX_CANDIDATE_PAIRS];

} QUIC_CANDIDATE_SET;

//
// One remote address the connection could send to, with everything the ranking
// needs to know about it. The caller fills RoutePreferredLocal in from
// CxPlatDataPathGetLocalAddressForRemote -- one lookup per remote address, not
// per pair, and never from a platform callback thread because that call can
// block.
//
typedef struct QUIC_CANDIDATE_REMOTE {

    QUIC_ADDR Address;
    QUIC_ADDR RoutePreferredLocal;
    BOOLEAN RoutePreferredLocalValid;
    uint8_t SentinelRank;       // QUIC_CANDIDATE_SENTINEL_RANK
    QUIC_VAR_INT PriorityHint;

} QUIC_CANDIDATE_REMOTE;

void
QuicCandidateSetInitialize(
    _Out_ QUIC_CANDIDATE_SET* Set
    );

//
// Rebuilds the table from the host's local addresses and the remote addresses
// the connection knows about.
//
// WantTemporary is whether the connection is currently on an RFC 8981 temporary
// address, so that preference can be carried forward rather than re-decided --
// a connection that deliberately started on a privacy address should not be
// moved onto the stable one, and vice versa.
//
void
QuicCandidateSetRebuild(
    _Inout_ QUIC_CANDIDATE_SET* Set,
    _In_reads_(LocalCount) const CXPLAT_LOCAL_ADDRESS* Locals,
    _In_ uint32_t LocalCount,
    _In_reads_(RemoteCount) const QUIC_CANDIDATE_REMOTE* Remotes,
    _In_ uint32_t RemoteCount,
    _In_ BOOLEAN WantTemporary
    );

//
// Whether an address is on this host, or reaches only the link. Both are read
// from the address itself rather than from a flag a platform set, because that
// is where scope lives.
//
BOOLEAN
QuicCandidateAddressIsLoopback(
    _In_ const QUIC_ADDR* Address
    );

BOOLEAN
QuicCandidateAddressIsLinkLocal(
    _In_ const QUIC_ADDR* Address
    );

//
// Ranks one candidate local address against another, by the criteria the
// local-address feature settled on in #134 phase 3. Exposed because it is both
// the tail of the pair ordering and still used on its own by the existing
// selection, and two copies of it would drift.
//
BOOLEAN
QuicCandidateLocalAddressIsBetter(
    _In_ const CXPLAT_LOCAL_ADDRESS* Left,
    _In_ const CXPLAT_LOCAL_ADDRESS* Right,
    _In_ BOOLEAN WantTemporary,
    _In_ BOOLEAN WantTemporaryValid
    );

#if defined(__cplusplus)
}
#endif
