# SEERA MsQuic

A fork of [MsQuic](https://github.com/microsoft/msquic), maintained by
[SEERA Networks](https://github.com/seera-networks).

It adds client-initiated connection migration and the QUIC extensions built on
top of it — multipath, NAT traversal, address discovery, server-initiated
migration — none of which are available in upstream MsQuic today.

Everything else is upstream MsQuic: same API, same build, same MIT license.

```sh
git clone --recursive https://github.com/seera-networks/msquic.git
```

That is the only change. Build instructions, API, and documentation are
[upstream's](https://github.com/microsoft/msquic/tree/main/docs).

## Why this fork exists

Upstream MsQuic does not implement client-initiated migration, and the multipath
extension is built on top of it. Both were submitted upstream by one of our
engineers — [#4218](https://github.com/microsoft/msquic/pull/4218) (migration)
and [#4724](https://github.com/microsoft/msquic/pull/4724) (multipath) — but the
changes are large and review has not progressed.

We need these features in production, so we maintain them in the open here
rather than in a private tree.

**We intend to retire this fork.** The goal is to get everything merged upstream.
If that happens, use upstream.

## Differences from upstream

| Feature | Specification | Upstream status |
| --- | --- | --- |
| Client Initiated Migration | [RFC 9000 §9](https://www.rfc-editor.org/rfc/rfc9000#section-9) | [PR #4218](https://github.com/microsoft/msquic/pull/4218), open |
| Multipath | [draft-ietf-quic-multipath](https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath/) | [PR #4724](https://github.com/microsoft/msquic/pull/4724), open |
| Address Discovery | [draft-ietf-quic-address-discovery](https://tools.ietf.org/html/draft-ietf-quic-address-discovery/) | not upstream |
| Server Initiated Migration | [draft-kozuka-quic-server-migration](https://datatracker.ietf.org/doc/html/draft-kozuka-quic-server-migration/) | not upstream |
| NAT Traversal | [draft-seemann-quic-nat-traversal](https://datatracker.ietf.org/doc/html/draft-seemann-quic-nat-traversal/) | not upstream |

There are no other intentional behavioural differences. If you find one that is
not listed here, please open an issue — it is a bug.

<!-- TODO: usage guides for the multipath and NAT traversal extensions -->

## Interoperability and testing

Multipath interoperability has been verified against
[noq](https://github.com/n0-computer/noq).

CI is upstream's, minus the jobs that require Microsoft-internal resources, plus
tests covering each of the extensions above.

## Keeping up with upstream

The fork lives on the `seera-main` branch. We merge upstream `main` into it
roughly once a month. Because the diff is confined to path handling, upstream
churn in that area is low and the merges have been uneventful so far.

We do not currently publish builds tracking upstream release tags. If you need
one, open an issue and tell us which release.

## Who uses it

SEERA MsQuic is the QUIC implementation behind
<!-- TODO: link to ISEKAI link --> ISEKAI link, our MASQUE-based relay, where
the migration and multipath extensions are used to move connections from a relay
path onto a direct peer-to-peer path.

## Contributing

Issues, pull requests, and discussions are welcome.

- Bugs in the extensions listed above → here.
- Bugs in core MsQuic → please file them
  [upstream](https://github.com/microsoft/msquic/issues) so everyone benefits.

## License

MIT, same as upstream MsQuic.

## Protocol features

Inherited from upstream, in addition to the extensions above:

[![](https://img.shields.io/static/v1?label=RFC&message=9000&color=brightgreen)](https://tools.ietf.org/html/rfc9000)
[![](https://img.shields.io/static/v1?label=RFC&message=9001&color=brightgreen)](https://tools.ietf.org/html/rfc9001)
[![](https://img.shields.io/static/v1?label=RFC&message=9002&color=brightgreen)](https://tools.ietf.org/html/rfc9002)
[![](https://img.shields.io/static/v1?label=RFC&message=9221&color=brightgreen)](https://tools.ietf.org/html/rfc9221)
[![](https://img.shields.io/static/v1?label=RFC&message=9287&color=brightgreen)](https://tools.ietf.org/html/rfc9287)
[![](https://img.shields.io/static/v1?label=RFC&message=9368&color=brightgreen)](https://tools.ietf.org/html/rfc9368)
[![](https://img.shields.io/static/v1?label=RFC&message=9369&color=brightgreen)](https://tools.ietf.org/html/rfc9369)
[![](https://img.shields.io/static/v1?label=Draft&message=Load%20Balancers&color=blue)](https://tools.ietf.org/html/draft-ietf-quic-load-balancers)
[![](https://img.shields.io/static/v1?label=Draft&message=ACK%20Frequency&color=blue)](https://tools.ietf.org/html/draft-ietf-quic-ack-frequency)
[![](https://img.shields.io/static/v1?label=Draft&message=ReliableReset&color=blue)](https://tools.ietf.org/html/draft-ietf-quic-reliable-stream-reset/)
[![](https://img.shields.io/static/v1?label=Draft&message=Disable%20Encryption&color=blueviolet)](https://tools.ietf.org/html/draft-banks-quic-disable-encryption)
[![](https://img.shields.io/static/v1?label=Draft&message=Performance&color=blueviolet)](https://tools.ietf.org/html/draft-banks-quic-performance)
[![](https://img.shields.io/static/v1?label=Draft&message=CIBIR&color=blueviolet)](https://tools.ietf.org/html/draft-banks-quic-cibir)
[![](https://img.shields.io/static/v1?label=Draft&message=Timestamps&color=blueviolet)](https://tools.ietf.org/html/draft-huitema-quic-ts)
