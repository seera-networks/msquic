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
| `strict` | EIM, address-and-port-dependent filtering | Traversal fails, connection survives (see *Findings*) |
| `edm` | Endpoint-dependent mapping | Traversal fails as the draft says it should, without stalling |
| `droppunch` | `direct`, punch dropped on the wire | Exactly one punch packet leaves; no retransmission; validation fails |
| `multiaddr-cross` | Two local addresses, two remotes, no NAT | Four paths — the full cross product |
| `multiaddr-return` | A local address removed and restored | The path is recreated (see *Findings*) |

`droppunch` measures the one-packet rule on the wire rather than from a
counter: the `DROP` rule's own packet count says how many punches actually
left, which is the evidence Appendix C.1 asks for. It reads **1**.

The last two are the local-address half of #157 that #161 lists as untestable
on a single-interface host.

## Findings

**The client probes from a mapping it did not advertise.** The reconciler opens
a path with `QuicAddrSetPort(&Local, 0)` (`connection.c`), so the direct path
uses a fresh socket, and under endpoint-independent mapping a fresh socket gets
a fresh public port. The client advertises the mapping of the socket its
relayed connection uses, the server punches towards that, and the probe then
arrives from a different port.

So traversal needs the server's NAT to filter on address rather than on address
and port. That is a documented NAT behaviour and RFC 4787's REQ-8 recommends
the looser end of it, so the `direct` case is realistic — but it is a real
constraint, and `strict` pins it: with the filtering plain conntrack gives, the
punch is sent, answered, and cannot help. Making the two coincide would mean
carrying the candidate's port into the path, which is a design change rather
than a fix.

`direct` emulates address-dependent filtering with `xt_recent`: the punch
records its destination on the way out and only recorded addresses are
forwarded in. The binding therefore still exists *only because the punch
created it*, which is the property under test.

**A path recreated for a returned local address does not validate.** In
`multiaddr-return` the reconciler does recreate the path — a binding appears on
the restored address and the peer issues connection IDs for the new path id —
but its `PATH_CHALLENGE`s never reach the peer, whose receive log has no record
of them. Validation times out after three attempts and both ends abandon the
path id. Plain traffic from the restored address works immediately, so the
environment is not what loses them.

That assertion is left **failing** rather than relaxed. A harness that reported
this green would be worse than no harness.

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
