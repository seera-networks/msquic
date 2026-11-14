# Testing stateless punch behind real NATs

`draft-kozuka-quic-stateless-punch` exists for one situation: two endpoints
that cannot reach each other because each is behind a NAT. Every test in stages
1–4 of #169 runs both endpoints on one host, where the direct path works
whether or not a punch packet was ever sent — so the failure the mechanism
prevents, a `PATH_CHALLENGE` dropped because no binding exists, cannot occur
there, and a test can watch the whole sequence happen without showing that any
of it did anything.

This is the environment where it can: `scripts/nat-punch-test.sh`, a developer
script that builds Linux network namespaces with real NATs in the path and runs
the endpoint tool `quicpunch` inside them.

It is deliberately **not a CI job**. It needs a kernel configuration the hosted
runners do not reliably offer, and a flaky netns test is worse than none.
Promoting it is a separate decision once it has been stable locally for a while.

## Requirements

- Linux with network namespace support, `iptables`, the `xt_recent` match, and
  `openssl`.
- **No root.** The script re-executes itself inside a user, mount, network and
  PID namespace, where it has the privileges it needs over its own topology and
  none outside it.
- A **Debug** build with tools. The assertions rest on counters that are
  debug-only parameters (`msquicp.h`) because nothing else makes them visible:
  the punch leaves no state behind on either endpoint, so "the server answered
  once" is not observable any other way.

```
cmake -S . -B build/linux/x64_chk -DCMAKE_BUILD_TYPE=Debug -DQUIC_BUILD_TOOLS=on
cmake --build build/linux/x64_chk --target quicpunch
./scripts/nat-punch-test.sh
```

The script finds a build itself; `--bin <dir>` overrides. `--case <name>` runs
one case, `--verbose` echoes each role's output, and the exit status is the
number of failed assertions.

## Topology

```
  cli 10.1.0.2 ---- 10.1.0.1 cnat 203.0.113.2 ----+
                                                  +---- 203.0.113.1 pub (relay)
  srv 10.2.0.2 ---- 10.2.0.1 snat 203.0.113.3 ----+
```

Both NATs do endpoint-independent mapping, which is the draft's own
prerequisite (RFC 4787 §4.1), implemented as `SNAT --to-source <ip>` with no
port named so netfilter preserves the source port. That is what lets the client
name its own public mapping without being told it, and the server advertise one.

The relay reaches the server through a forward on `snat` that **only the relay
may use**. Without that restriction the client could reach the server directly
and every case would pass whether or not a punch was ever sent — which is the
trap this whole environment exists to avoid.

## What each case establishes

| Case | Configuration | Expectation |
| --- | --- | --- |
| `direct` | EIM, address-dependent filtering | A direct path validates; the server sees the client's public mapping |
| `strict` | EIM, plain conntrack filtering | The probe leaves from the advertised port (#198) |
| `edm` | Endpoint-dependent mapping | Traversal fails as the draft says it should, without stalling |
| `droppunch` | `direct`, punch dropped on the wire | Exactly one punch packet leaves; no retransmission; validation fails |
| `multiaddr-cross` | Two local addresses, two remotes, no NAT | Four paths — the full cross product |
| `multiaddr-return` | A local address removed and restored | The path is recreated and validates (see *Findings*) |
| `sameport` | Two local addresses, one port, no NAT | Each keeps its own binding (#200) |

`droppunch` measures the one-packet rule on the wire rather than from a
counter: the `DROP` rule's own packet count says how many punches actually
left, which is the evidence Appendix C.1 asks for. It reads **1**.

`multiaddr-cross` and `multiaddr-return` are the local-address half of #157 that
#161 lists as untestable on a single-interface host. `sameport` covers the
arrangement a NAT-traversal client actually ends up in: every candidate on a
host names the port its mapping was punched for, so paths on different local
addresses share one port number. `QuicLibraryLookupBinding` used to match an
unconnected binding on the local port alone -- on the stated premise that such
a binding "always uses wildcard addresses", which
`QUIC_PARAM_CONN_UNCONNECTED_UDP_SOCKET` breaks by requiring a specific one --
so the second address was handed the first's binding and sent from the wrong
interface. That is #200, and without the fix the case shows it as two paths
with identical local *and* remote addresses.

## Findings

**The client probes from the mapping it advertised** — which it did not always
do. The reconciler opened the path with `QuicAddrSetPort(&Local, 0)`, so the
probe left from a fresh socket and, under endpoint-independent mapping, a fresh
public port; the peer had punched towards the mapping of the socket the relayed
connection uses. Behind a NAT that filters on address *and* port — what
conntrack does — every `PATH_CHALLENGE` was dropped. That was #198, reported
from a real testbed, and the reconciler now binds the path to the port the
candidate registered. The `strict` case asserts it.

Three things a NAT-traversal client must do for that to work, none of them
obvious and all of them now in `quicpunch`:

- **Share its UDP binding.** The direct path has to leave from the port that
  already carries the relayed path, so the two paths share one socket. Without
  sharing, `QuicLibraryGetBinding` finds the port in use, declines to share,
  and the path cannot be opened at all -- the reconciler then never queues the
  punch request and the mechanism is silently inert.
- **Use an unconnected socket** (`QUIC_PARAM_CONN_UNCONNECTED_UDP_SOCKET`). A
  connected socket has a remote of its own and can carry only that peer, so the
  direct path cannot ride the punched port.
- **Name a specific local address.** An unconnected socket has no remote to
  take one from, and `QuicConnOpenNewPath` refuses a wildcard.

`direct` emulates address-dependent filtering with `xt_recent`: the punch
records its destination on the way out and only recorded addresses are
forwarded in. The binding therefore still exists *only because the punch
created it*, which is the property under test.

`strict` leaves plain conntrack in place and asserts the 5-tuple rather than the
validation: this emulation does not yet get the client's NAT to reuse its
mapping for a second destination, so end-to-end traversal there is still
unproven. The part #198 was about -- which port the probe leaves from -- is what
it checks, and it fails if that regresses.

**A path recreated for a returned local address could not send its
`PATH_CHALLENGE`** (#196). Found here, and the cause is fixed: a path ID taken
from the unused set carried the destination CIDs the peer had issued for it and
none of its own, because with a shared binding — which multipath requires —
`QuicConnOpenNewPath` registered the CIDs that already existed and generated
new ones only when that registration failed. `QuicPacketBuilderInitialize`
refuses a path whose path ID has no source CID, so the challenge the reconciler
had just armed was dropped with nothing said, and validation timed out three
attempts later.

It looked intermittent because it depended on whether some unrelated event —
a `MAX_PATH_ID`, a key update — happened to run
`QuicPathIDSetGenerateNewSourceCids` over every path ID before the validation
budget ran out, and whether it did was settled early in a connection and then
held. `QuicConnOpenNewPath` now generates the CIDs when the path is opened, and
`QuicSendPathChallenges` re-arms the send flag and traces when it cannot start
a packet, so a dropped challenge is no longer silent.

**The residual had a second cause, now fixed too.** The source CIDs were only
half of it. A path whose *path id* had no unused destination CID had its
challenge deferred -- `QuicConnOpenNewPath` says as much -- and nothing asked
the peer for one, because `PATH_CIDS_BLOCKED`, the frame that exists to ask,
had no writer and a receive handler that decoded it and dropped it. So the
deferral waited on an event nothing requested, and a restored address got a
usable path only when the peer happened to issue CIDs for reasons of its own.

The reconciler now declines to open a path it could not use, asks, and comes
back a hold-down later; the peer answers by issuing CIDs for that path id. In a
traced run the deferral went from firing 88 times and never resolving to firing
two or three times, each answered at once.

Finding it needed two things worth keeping. `--keep-logs` preserves each role's
log, and the case prints per cycle both what its own window saw and what the
whole file held at that moment -- which is how "the window was too tight" gets
told apart from "nothing happened". It also waits for the path to *appear*
rather than for a fixed number of polls, because a retrying reconciler makes
"not yet" a legitimate state.

One of the measurements along the way was wrong, and the reason is worth
recording: the script runs under `set -o pipefail`, and assertions that ended
in `… | grep -q` reported failure on a *match*, because `grep -q` exits at the
first hit and the producer dies of SIGPIPE. It only bites when the producer
still has output to write, so it hid on small logs and surfaced on a tracing
build's large ones. Use `grep -c` into a variable at the end of a pipeline, not
`grep -q`.

## Reading a run

Every line the tool prints that is worth asserting on is `PUNCH: key=value`.
The useful ones:

- `client_requests_sent`, `server_punches_sent` — the mechanism acted.
- `client_path_validated_remote` — what the direct path reached.
- `client_final_path<n>` / `client_poll<k>_path<n>` — `local->remote` per path,
  the second being a timeline when `-poll` is given.
- `client_result` — `direct` or `relay-only`; the exit code says the same (0 or 2).
- `client_transport_shutdown` — the status a failed handshake failed with.

To drive the roles by hand, `quicpunch` with no arguments prints its usage. The
one setting whose absence is not self-explanatory is share-binding: a multipath
client must call it or the peer closes the connection with `PROTOCOL_VIOLATION`
("Multipath requires non-zero length connection IDs"), because a client keeps
its binding to itself by default and so has a zero-length source connection ID.
