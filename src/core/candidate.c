/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    The candidate pair table. See candidate.h for what it is and why it is
    pure; this file is the enumeration and the ordering.

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "candidate.c.clog.h"
#endif

BOOLEAN
QuicCandidateAddressIsLoopback(
    _In_ const QUIC_ADDR* Address
    )
{
    if (QuicAddrGetFamily(Address) == QUIC_ADDRESS_FAMILY_INET) {
        uint8_t Bytes[4];
        CxPlatCopyMemory(Bytes, &Address->Ipv4.sin_addr, sizeof(Bytes));
        //
        // The whole of 127/8 answers locally, not just 127.0.0.1 -- the tests
        // in this tree use 127.0.0.2.
        //
        return Bytes[0] == 127;
    }

    QUIC_ADDR Loopback;
    CxPlatZeroMemory(&Loopback, sizeof(Loopback));
    QuicAddrSetFamily(&Loopback, QUIC_ADDRESS_FAMILY_INET6);
    QuicAddrSetToLoopback(&Loopback);
    return QuicAddrCompareIp(&Loopback, Address);
}

BOOLEAN
QuicCandidateAddressIsLinkLocal(
    _In_ const QUIC_ADDR* Address
    )
{
    if (QuicAddrGetFamily(Address) == QUIC_ADDRESS_FAMILY_INET) {
        uint8_t Bytes[4];
        CxPlatCopyMemory(Bytes, &Address->Ipv4.sin_addr, sizeof(Bytes));
        return Bytes[0] == 169 && Bytes[1] == 254;
    }

    uint8_t Bytes[16];
    CxPlatCopyMemory(Bytes, &Address->Ipv6.sin6_addr, sizeof(Bytes));
    return Bytes[0] == 0xfe && (Bytes[1] & 0xc0) == 0x80;
}

//
// Scope read from the address as well as from the platform's flag. The flag is
// what a backend reports; the address is what it is. Not every source of a
// snapshot sets flags -- the test injection parameter does not -- and a filter
// that can be switched off by a missing flag is not much of a filter.
//
static
BOOLEAN
QuicCandidateIsLoopback(
    _In_ const CXPLAT_LOCAL_ADDRESS* Local
    )
{
    return
        !!(Local->Flags & CXPLAT_ADDRESS_FLAG_LOOPBACK) ||
        QuicCandidateAddressIsLoopback(&Local->Address);
}

static
BOOLEAN
QuicCandidateIsLinkLocal(
    _In_ const CXPLAT_LOCAL_ADDRESS* Local
    )
{
    return
        !!(Local->Flags & CXPLAT_ADDRESS_FLAG_LINK_LOCAL) ||
        QuicCandidateAddressIsLinkLocal(&Local->Address);
}

//
// Three-way rather than boolean, so a caller that needs to know two addresses
// rank *equally* can see it directly instead of asking twice with the arguments
// reversed -- which reads as a bug and which clang-tidy flags as one.
//
// Negative when Left is better, positive when Right is, zero when the criteria
// cannot separate them.
//
static
int
QuicCandidateLocalAddressCompare(
    _In_ const CXPLAT_LOCAL_ADDRESS* Left,
    _In_ const CXPLAT_LOCAL_ADDRESS* Right,
    _In_ BOOLEAN WantTemporary,
    _In_ BOOLEAN WantTemporaryValid
    )
{
    //
    // A deprecated address still works, but its lifetime has expired and it
    // will go away; anything else is preferable.
    //
    const BOOLEAN LeftDeprecated = !!(Left->Flags & CXPLAT_ADDRESS_FLAG_DEPRECATED);
    const BOOLEAN RightDeprecated = !!(Right->Flags & CXPLAT_ADDRESS_FLAG_DEPRECATED);
    if (LeftDeprecated != RightDeprecated) {
        return RightDeprecated ? -1 : 1;
    }

    //
    // A global address is preferable to one with narrower scope even when both
    // can reach the peer. Which of them *can* is settled by the pair filter,
    // not here.
    //
    const BOOLEAN LeftNarrow = QuicCandidateIsLoopback(Left) || QuicCandidateIsLinkLocal(Left);
    const BOOLEAN RightNarrow = QuicCandidateIsLoopback(Right) || QuicCandidateIsLinkLocal(Right);
    if (LeftNarrow != RightNarrow) {
        return RightNarrow ? -1 : 1;
    }

    //
    // Keep whichever kind of address the connection was already using, so one
    // that started on an RFC 8981 privacy address stays on one and one that
    // started on a stable address does not silently acquire a privacy address.
    //
    if (WantTemporaryValid) {
        const BOOLEAN LeftTemporary = !!(Left->Flags & CXPLAT_ADDRESS_FLAG_TEMPORARY);
        const BOOLEAN RightTemporary = !!(Right->Flags & CXPLAT_ADDRESS_FLAG_TEMPORARY);
        if (LeftTemporary != RightTemporary) {
            return LeftTemporary == !!WantTemporary ? -1 : 1;
        }
    }

    //
    // Nothing left to tell them apart, so pick deterministically: the same
    // input has to produce the same choice on every rebuild, or the connection
    // could move back and forth between equals.
    //
    if (Left->InterfaceIndex != Right->InterfaceIndex) {
        return Left->InterfaceIndex < Right->InterfaceIndex ? -1 : 1;
    }

    //
    // Ordered on the address bytes, by family. Not on the QUIC_ADDR union as a
    // whole: that has padding, whose contents are not defined, so comparing it
    // would make this ordering depend on bytes nobody set -- the opposite of
    // the stability the tiebreak exists to provide.
    //
    const QUIC_ADDRESS_FAMILY LeftFamily = QuicAddrGetFamily(&Left->Address);
    const QUIC_ADDRESS_FAMILY RightFamily = QuicAddrGetFamily(&Right->Address);
    if (LeftFamily != RightFamily) {
        return LeftFamily < RightFamily ? -1 : 1;
    }
    if (LeftFamily == QUIC_ADDRESS_FAMILY_INET) {
        return
            memcmp(
                &Left->Address.Ipv4.sin_addr,
                &Right->Address.Ipv4.sin_addr,
                sizeof(Left->Address.Ipv4.sin_addr));
    }
    return
        memcmp(
            &Left->Address.Ipv6.sin6_addr,
            &Right->Address.Ipv6.sin6_addr,
            sizeof(Left->Address.Ipv6.sin6_addr));
}

BOOLEAN
QuicCandidateLocalAddressIsBetter(
    _In_ const CXPLAT_LOCAL_ADDRESS* Left,
    _In_ const CXPLAT_LOCAL_ADDRESS* Right,
    _In_ BOOLEAN WantTemporary,
    _In_ BOOLEAN WantTemporaryValid
    )
{
    return
        QuicCandidateLocalAddressCompare(
            Left, Right, WantTemporary, WantTemporaryValid) < 0;
}

//
// Whether a local address can carry a path to this remote at all. Two hard
// filters, not ranking terms -- ranking a pair that cannot reach the peer would
// make it the choice of last resort, which is worse than having no candidate.
//
static
BOOLEAN
QuicCandidatePairIsViable(
    _In_ const CXPLAT_LOCAL_ADDRESS* Local,
    _In_ const QUIC_ADDR* Remote
    )
{
    //
    // Only an address of the peer's family can carry this connection. There is
    // no mapping step: a v4 peer needs a v4 source.
    //
    if (QuicAddrGetFamily(&Local->Address) != QuicAddrGetFamily(Remote)) {
        return FALSE;
    }

    //
    // Scope, and it has to match in both directions. This is the filter that is
    // inherently pair-shaped and that the pre-unification code could only apply
    // against the active remote.
    //
    // Symmetric, unlike the filter in QuicConnSelectLocalAddress that this
    // supersedes. That one only rejected a narrow local address for a wider
    // remote, which let a global local address through for a loopback remote --
    // and nothing can send from 10.0.0.1 to 127.0.0.2. Loopback is reachable
    // only from loopback, a link is reachable only from an address on it, and
    // everything else needs an address that is neither.
    //
    const BOOLEAN LocalLoopback = QuicCandidateIsLoopback(Local);
    const BOOLEAN RemoteLoopback = QuicCandidateAddressIsLoopback(Remote);
    if (LocalLoopback != RemoteLoopback) {
        return FALSE;
    }

    const BOOLEAN LocalLinkLocal = QuicCandidateIsLinkLocal(Local);
    const BOOLEAN RemoteLinkLocal = QuicCandidateAddressIsLinkLocal(Remote);
    if (LocalLinkLocal != RemoteLinkLocal) {
        return FALSE;
    }

    return TRUE;
}

//
// Whether Left outranks Right. Total and deterministic: the same inputs must
// always give the same table, or the connection flaps between equals.
//
static
BOOLEAN
QuicCandidatePairIsBetter(
    _In_ const QUIC_CANDIDATE_PAIR* Left,
    _In_ const CXPLAT_LOCAL_ADDRESS* LeftLocal,
    _In_ const QUIC_CANDIDATE_PAIR* Right,
    _In_ const CXPLAT_LOCAL_ADDRESS* RightLocal,
    _In_ BOOLEAN WantTemporary
    )
{
    //
    // 1. The pair routing would actually use. This is the only input that knows
    //    which local address reaches this particular remote, so it outranks
    //    every preference below it.
    //
    if (Left->RoutePreferred != Right->RoutePreferred) {
        return Left->RoutePreferred;
    }

    //
    // 2. What the server said about this remote relative to the path we are on:
    //    preferred to it, it, or a backup.
    //
    if (Left->SentinelRank != Right->SentinelRank) {
        return Left->SentinelRank < Right->SentinelRank;
    }

    //
    // 3. The server's own hint among addresses on the same side.
    //
    if (Left->PriorityHint != Right->PriorityHint) {
        return Left->PriorityHint < Right->PriorityHint;
    }

    //
    // 4. The local-address preferences, which are what is left to tell two
    //    pairs apart once the peer has said all it has to say.
    //
    const int LocalOrder =
        QuicCandidateLocalAddressCompare(LeftLocal, RightLocal, WantTemporary, TRUE);
    if (LocalOrder != 0) {
        return LocalOrder < 0;
    }

    //
    // 5. The remote address, on its bytes, which is the only thing left when
    //    two pairs share a local address and differ only in which remote they
    //    reach.
    //
    // Without this the order of such pairs came from the order the remotes
    // happened to be enumerated in, which is the compaction order of the
    // advertised set -- so a server withdrawing an address and re-advertising
    // it moved that address to the end of the stored set and reordered the
    // table, with nothing about the host having changed. That is exactly the
    // rebuild-to-rebuild flap the tiebreak exists to prevent.
    //
    // By family first, then bytes, and never on the QUIC_ADDR union as a whole:
    // that has padding whose contents are not defined.
    //
    const QUIC_ADDRESS_FAMILY LeftFamily = QuicAddrGetFamily(&Left->RemoteAddress);
    const QUIC_ADDRESS_FAMILY RightFamily = QuicAddrGetFamily(&Right->RemoteAddress);
    if (LeftFamily != RightFamily) {
        return LeftFamily < RightFamily;
    }
    if (LeftFamily == QUIC_ADDRESS_FAMILY_INET) {
        const int Cmp =
            memcmp(
                &Left->RemoteAddress.Ipv4.sin_addr,
                &Right->RemoteAddress.Ipv4.sin_addr,
                sizeof(Left->RemoteAddress.Ipv4.sin_addr));
        if (Cmp != 0) {
            return Cmp < 0;
        }
        return
            QuicAddrGetPort(&Left->RemoteAddress) <
                QuicAddrGetPort(&Right->RemoteAddress);
    }
    const int Cmp =
        memcmp(
            &Left->RemoteAddress.Ipv6.sin6_addr,
            &Right->RemoteAddress.Ipv6.sin6_addr,
            sizeof(Left->RemoteAddress.Ipv6.sin6_addr));
    if (Cmp != 0) {
        return Cmp < 0;
    }
    return
        QuicAddrGetPort(&Left->RemoteAddress) <
            QuicAddrGetPort(&Right->RemoteAddress);
}

void
QuicCandidateSetInitialize(
    _Out_ QUIC_CANDIDATE_SET* Set
    )
{
    CxPlatZeroMemory(Set, sizeof(*Set));
    CxPlatListInitializeHead(&Set->Pairs);
}

void
QuicCandidateSetRebuild(
    _Inout_ QUIC_CANDIDATE_SET* Set,
    _In_reads_(LocalCount) const CXPLAT_LOCAL_ADDRESS* Locals,
    _In_ uint32_t LocalCount,
    _In_reads_(RemoteCount) const QUIC_CANDIDATE_REMOTE* Remotes,
    _In_ uint32_t RemoteCount,
    _In_ BOOLEAN WantTemporary
    )
{
    //
    // Rebuilt from scratch rather than diffed. The inputs are small, the
    // ordering depends on all of them at once -- a route change can reorder
    // pairs whose own addresses did not move -- and a stale entry here would
    // become a path.
    //
    CxPlatListInitializeHead(&Set->Pairs);
    Set->Count = 0;

    //
    // The local address each held pair came from, parallel to the pool, so the
    // comparator can reach the flags without the pair carrying a copy of them.
    //
    //
    // Zero-initialized in the declaration rather than memset. Handing an array
    // of pointers-to-const to CxPlatZeroMemory's void* drops the const, which
    // MSVC reports as C4090 and treats as an error; gcc says nothing.
    //
    const CXPLAT_LOCAL_ADDRESS* HeldLocal[QUIC_MAX_CANDIDATE_PAIRS] = { NULL };

    for (uint32_t r = 0; r < RemoteCount; ++r) {
        for (uint32_t l = 0; l < LocalCount; ++l) {
            if (!QuicCandidatePairIsViable(&Locals[l], &Remotes[r].Address)) {
                continue;
            }

            QUIC_CANDIDATE_PAIR Pair;
            CxPlatZeroMemory(&Pair, sizeof(Pair));
            Pair.LocalAddress = Locals[l].Address;
            Pair.RemoteAddress = Remotes[r].Address;
            Pair.SentinelRank = Remotes[r].SentinelRank;
            Pair.PriorityHint = Remotes[r].PriorityHint;
            Pair.RoutePreferred =
                Remotes[r].RoutePreferredLocalValid &&
                QuicAddrCompareIp(&Remotes[r].RoutePreferredLocal, &Locals[l].Address);

            //
            // Claim storage first, then place it. The product can be far larger
            // than the table, so a pair that cannot beat the worst one held is
            // dropped without being stored -- which is what keeps this
            // O(table) in memory instead of O(locals x remotes).
            //
            QUIC_CANDIDATE_PAIR* Slot;
            if (Set->Count == QUIC_MAX_CANDIDATE_PAIRS) {
                CXPLAT_LIST_ENTRY* WorstLink = Set->Pairs.Blink;
                const QUIC_CANDIDATE_PAIR* Worst =
                    CXPLAT_CONTAINING_RECORD(WorstLink, QUIC_CANDIDATE_PAIR, Link);
                if (!QuicCandidatePairIsBetter(
                        &Pair, &Locals[l], Worst,
                        HeldLocal[Worst - Set->Pool], WantTemporary)) {
                    continue; // Cannot displace anything, so never stored.
                }
                //
                // The worst entry makes room and its storage is reused. Removed
                // before the insertion point is looked for, not after: the
                // position found on the full list can be the very entry being
                // evicted, and inserting before an entry already unlinked
                // corrupts the list.
                //
                CxPlatListEntryRemove(WorstLink);
                Slot = CXPLAT_CONTAINING_RECORD(WorstLink, QUIC_CANDIDATE_PAIR, Link);
            } else {
                Slot = &Set->Pool[Set->Count];
                Set->Count++;
            }

            *Slot = Pair;
            HeldLocal[Slot - Set->Pool] = &Locals[l];

            CXPLAT_LIST_ENTRY* Insert = Set->Pairs.Flink;
            while (Insert != &Set->Pairs) {
                const QUIC_CANDIDATE_PAIR* Held =
                    CXPLAT_CONTAINING_RECORD(Insert, QUIC_CANDIDATE_PAIR, Link);
                if (QuicCandidatePairIsBetter(
                        Slot, &Locals[l], Held,
                        HeldLocal[Held - Set->Pool], WantTemporary)) {
                    break;
                }
                Insert = Insert->Flink;
            }

            //
            // CxPlatListInsertTail links before the entry it is given, so this
            // is "insert before Insert" and appends when Insert is the head.
            //
            CxPlatListInsertTail(Insert, &Slot->Link);
        }
    }
}
