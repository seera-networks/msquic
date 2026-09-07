# MsQuic Settings

MsQuic supports a number of configuration knobs (or settings). These settings can either be set dynamically (via the [QUIC_SETTINGS](./api/QUIC_SETTINGS.md) structure) or via persistent storage (e.g. registry on Windows).

> **Warning**
> Generally MsQuic already choses the best / most correct default values for all settings. Settings should only be changed after due diligence and A/B testing is performed.

MsQuic settings are available on most MsQuic API objects. [Here](#api-object-parameters) we'll provide an overview of them with links to further details.

## Windows Registry

MsQuic supports most of the settings in the QUIC_SETTINGS struct in the registry to be loaded as defaults when the MsQuic library is loaded in a process.  These registry settings only provide the defaults; the application is free to change the settings with a call to [SetParam](./api/SetParam.md) or in [QUIC_SETTINGS](./api/QUIC_SETTINGS.md) structs passed into [ConfigurationOpen](./api/ConfigurationOpen.md).

The default settings are updated automatically in the application when changing the registry, assuming the application hasn't already changed the setting, which overrides the registry value. However, this does not change the settings on Connections which are already established, or Configurations which are already created.

Note: MaxWorkerQueueDelay uses **milliseconds** in the registry, but uses microseconds (us) in the [QUIC_SETTINGS](./api/QUIC_SETTINGS.md) struct.

The following settings are unique to the registry:

| Setting                            | Type     | Registry Name           | Default           | Description                                                                                                 |
|------------------------------------|----------|-------------------------|-------------------|-------------------------------------------------------------------------------------------------------------|
| Max Worker Queue Delay             | uint32_t | MaxWorkerQueueDelayMs   |               250 | The maximum queue delay (in ms) allowed for a worker thread.                                                |
| Max Partition Count                | uint16_t | MaxPartitionCount       |  System CPU count | The maximum processor count used for partitioning work in MsQuic. Max 512. **Restart is required.**         |

The following settings are available via registry as well as via [QUIC_SETTINGS](./api/QUIC_SETTINGS.md):

| Setting                            | Type       | Registry Name               | Default           | Description                                                                                                                   |
|------------------------------------|------------|-----------------------------|-------------------|-------------------------------------------------------------------------------------------------------------------------------|
| Max Bytes per Key                  | uint64_t   | MaxBytesPerKey              |   274,877,906,944 | Maximum number of bytes to encrypt with a single 1-RTT encryption key before initiating key update.                           |
| Handshake Idle Timeout             | uint64_t   | HandshakeIdleTimeoutMs      |            10,000 | How long a handshake can idle before it is discarded.                                                                         |
| Idle Timeout                       | uint64_t   | IdleTimeoutMs               |            30,000 | How long a connection can go idle before it is silently shut down. 0 to disable timeout                                       |
| Max TLS Send Buffer (Client)       | uint32_t   | TlsClientMaxSendBuffer      |             4,096 | How much client TLS data to buffer.                                                                                           |
| Max TLS Send Buffer (Server)       | uint32_t   | TlsServerMaxSendBuffer      |             8,192 | How much server TLS data to buffer.                                                                                           |
| Stream Receive Window              | uint32_t   | StreamRecvWindowDefault     |            65,536 | Initial stream receive window size for all stream types.                                                                      |
| Stream Receive Window (Bidirectional, locally created) | uint32_t   | StreamRecvWindowBidiLocalDefault |            - | If set, overrides stream receive window size for locally initiated bidirectional streams.                                     |
| Stream Receive Window (Bidirectional, remotely created) | uint32_t   | StreamRecvWindowBidiRemoteDefault |            - | If set, overrides stream receive window size for remote initiated bidirectional streams.                                     |
| Stream Receive Window (Unidirectional) | uint32_t   | StreamRecvWindowUnidiDefault |            - | If set, overrides stream receive window size for remote initiated unidirectional streams.                                     |
| Stream Receive Buffer              | uint32_t   | StreamRecvBufferDefault     |             4,096 | Stream initial buffer size.                                                                                                   |
| Flow Control Window                | uint32_t   | ConnFlowControlWindow       |        16,777,216 | Connection-wide flow control window.                                                                                          |
| Max Stateless Operations           | uint32_t   | MaxStatelessOperations      |                16 | The maximum number of stateless operations that may be queued on a worker at any one time.                                    |
| Initial Window                     | uint32_t   | InitialWindowPackets        |                10 | The size (in packets) of the initial congestion window for a connection.                                                      |
| Send Idle Timeout                  | uint32_t   | SendIdleTimeoutMs           |             1,000 | Reset congestion control after being idle `SendIdleTimeoutMs` milliseconds.                                                   |
| Initial RTT                        | uint32_t   | InitialRttMs                |               333 | Initial RTT estimate.                                                                                                         |
| Max ACK Delay                      | uint32_t   | MaxAckDelayMs               |                25 | How long to wait after receiving data before sending an ACK.                                                                  |
| Disconnect Timeout                 | uint32_t   | DisconnectTimeoutMs         |            16,000 | How long to wait for an ACK before declaring a path dead and disconnecting.                                                   |
| Keep Alive Interval                | uint32_t   | KeepAliveIntervalMs         |      0 (disabled) | How often to send PING frames to keep a connection alive. Reset whenever the connection sends or receives anything.           |
| Path Keep Alive Interval           | uint32_t   | PathKeepAliveIntervalMs     |      0 (disabled) | How long a path may go without sending before a PING is sent on it. Counted per path and not reset by activity elsewhere on the connection. |
| Idle Timeout Period Changes DestCid| uint32_t   | DestCidUpdateIdleTimeoutMs  |            20,000 | Idle timeout period after which the destination CID is updated before sending again.                                          |
| Peer Stream Count (Bidirectional)  | uint16_t   | PeerBidiStreamCount         |                 0 | Number of bidirectional streams to allow the peer to open.                                                                    |
| Peer Stream Count (Unidirectional) | uint16_t   | PeerUnidiStreamCount        |                 0 | Number of unidirectional streams to allow the peer to open.                                                                   |
| Retry Memory Limit                 | uint16_t   | RetryMemoryFraction         |        65 (~0.1%) | The percentage of available memory usable for handshake connections before stateless retry is used. Calculated as `N/65535`.  |
| Load Balancing Mode                | uint16_t   | LoadBalancingMode           |      0 (disabled) | Global setting, not per-connection/configuration.                                                                             |
| Max Operations per Drain           | uint8_t    | MaxOperationsPerDrain       |                16 | The maximum number of operations to drain per connection quantum.                                                             |
| Send Buffering                     | uint8_t    | SendBufferingEnabled        |          1 (TRUE) | Buffer send data within MsQuic instead of holding application buffers until sent data is acknowledged.                        |
| Send Pacing                        | uint8_t    | PacingEnabled               |          1 (TRUE) | Pace sending to avoid overfilling buffers on the path.                                                                        |
| Client Migration Support           | uint8_t    | MigrationEnabled            |          1 (TRUE) | Enable clients to migrate IP addresses and tuples. Requires a cooperative load-balancer, or no load-balancer.                 |
| Datagram Receive Support           | uint8_t    | DatagramReceiveEnabled      |         0 (FALSE) | Advertise support for QUIC datagram extension.                                                                                |
| Server Resumption Level            | uint8_t    | ServerResumptionLevel       | 0 (No resumption) | Server only. Controls resumption tickets and/or 0-RTT server support.                                                         |
| Grease Quic Bit Support            | uint8_t    | GreaseQuicBitEnabled        |         0 (FALSE) | Advertise support for Grease QUIC Bit extension.                                                                              |
| Minimum MTU                        | uint16_t   | MinimumMtu                  |              1288 | The minimum MTU supported by a connection. This will be used as the starting MTU.                                             |
| Maximum MTU                        | uint16_t   | MaximumMtu                  |              1500 | The maximum MTU supported by a connection. This will be the maximum probed value.                                             |
| MTU Discovery Search Timeout       | uint64_t   | MtuDiscoverySearchCompleteTimeoutUs | 600000000 | The time in microseconds to wait before reattempting MTU probing if max was not reached.                                      |
| MTU Discovery Missing Probe Count  | uint8_t    | MtuDiscoveryMissingProbeCount  |              3 | The number of MTU probes to retry before exiting MTU probing.                                                                 |
| Max Binding Stateless Operations   | uint16_t   | MaxBindingStatelessOperations  |            100 | The maximum number of stateless operations that may be queued on a binding at any one time.                                   |
| Stateless Operation Expiration     | uint16_t   | StatelessOperationExpirationMs |            100 | The time limit between operations for the same endpoint, in milliseconds.                                                     |
| Congestion Control Algorithm       | uint16_t   | CongestionControlAlgorithm  |         0 (Cubic) | The congestion control algorithm used for the connection.                                                                     |
| ECN                                | uint8_t    | EcnEnabled                  |         0 (FALSE) | Enable sender-side ECN support.                                                                                               |
| Stream Multi Receive               | uint8_t    | StreamMultiReceiveEnabled   |         0 (FALSE) | Enable multi receive support                                                                                                  |
| XDP                                | uint8_t    | XdpEnabled                  |         0 (FALSE) | Enable XDP. |
| QTIP                               | uint8_t    | QTIPEnabled                 |         0 (FALSE) | Enable QTIP. XDP must be used. Clients will only send/recv QTIP xor UDP traffic, listeners accept both. [More info](./QTIP.md)|
| Server Initiated Migration         | uint8_t    | ServerMigrationEnabled      |         0 (FALSE) | Enable Server Initiated Migration. |
| ADD_ADDRESS handling mode          | uint8_t    | AddAddressMode              |         0 (AUTO)  | Control handling of ADD_ADDRESS Frame |
| IgnoreUnreachable                  | uint8_t    | IgnoreUnreachable           |         0 (FALSE) | Ignore Unreachable during the Handshake |
| SendObservedAddressReports         | uint8_t    | SendObservedAddressReports  |         0 (FALSE) | Report the peer's observed address to it via OBSERVED_ADDRESS frames. Frames are only sent if the peer also asked to receive them. |
| ReceiveObservedAddressReports      | uint8_t    | ReceiveObservedAddressReports |       0 (FALSE) | Ask the peer to report this endpoint's observed address. Reports arrive as `QUIC_CONNECTION_EVENT_NOTIFY_OBSERVED_ADDRESS`. |

The types map to registry types as follows:
  - `uint64_t` is a `REG_QWORD`.
  - `uint32_t`, `uint16_t`, and `uint8_t` are `REG_DWORD`.

While `REG_DWORD` can hold values larger than `uint16_t`, the administrator should ensure they do not exceed the maximum value of 65,535 when configuring a `uint16_t` setting via the Windows Registry.

The following settings are available via registry as well as via [QUIC_VERSION_SETTINGS](./Versions.md):

| Setting                           | Type       | Registry Name                | Default           | Description                                                                                                                   |
|-----------------------------------|------------|------------------------------|-------------------|-------------------------------------------------------------------------------------------------------------------------------|
| Acceptable Versions List          | uint32_t[] | AcceptableVersions           | Unset             | Sets the list of versions that a given server instance will use if a client sends a first flight using them. |
| Offered Versions List             | uint32_t[] | OfferedVersions              | Unset             | Sets the list of versions that a given server instance will send in a Version Negotiation packet if it receives a first flight from an unknown version. This list will most often be equal to the Acceptable Versions list. |
| Fully-Deployed Versions List      | uint32_t[] | FullyDeployedVersions        | Unset             | Sets the list of QUIC versions that is supported and negotiated by every single QUIC server instance in this deployment. Used to generate the AvailableVersions list in the Version Negotiation Extension Transport Parameter. |
| Version Negotiation Ext. Enabled  | uint32_t   | VersionNegotiationExtEnabled | 0 (FALSE)         | Enables the Version Negotiation Extension. |

The `uint32_t[]` type is a `REG_BINARY` blob of the versions list, with each version in little-endian format.

All restrictions and effects on the versions mentioned in [QUIC_VERSION_SETTINGS](./Versions.md) apply to the registry-set versions as well.

Particularly, on server, these must be set **GLOBALLY** if you want them to take effect for servers.

The following settings are available via registry as well as via [QUIC_STATELESS_RETRY_CONFIG](./api/QUIC_STATELESS_RETRY_CONFIG.md):

| Setting | Type | Registry Name | Default | Description |
|---------|------|---------------|---------|-------------|
| Stateless Retry Key Rotation interval | uint32_t | RetryKeyRotationMs | 30000 | The interval stateless retry keys are rotated on. A token is valid for 2x this interval. |
| Stateless Retry Key Algorithm | uint32_t | RetryKeyAlgorithm | QUIC_AEAD_ALGORITHM_AES_256_GCM | The algorithm used to protect the stateless retry token. |
| Stateless Retry Key Secret | uint8_t[] | RetryKeySecret | Randomly Generated | The secret material used to generate the stateless retry keys. **MUST** be secure randomness! |

The `uint8_t[]` type is a `REG_BINARY` blob of the secret material, and must be the same length (in bytes) as the algorithm's key.

These settings only take effect in the global registry location.

When changing the stateless retry configuration via registry, admins **MUST** delete the existing RetryKeyRotationMs, RetryKeyAlgorithm, and RetryKeySecret registry values (if present) before writing the new values. This prevents a split state from occurring while applying settings.

For consistency when configuring Stateless Retry via the registry, values **MUST** be written in the following order:
1. RetryKeyRotationMs
2. RetryKeyAlgorithm
3. RetryKeySecret

See [QUIC_STATELESS_RETRY_CONFIG](./api/QUIC_STATELESS_RETRY_CONFIG.md) for more information.

## QUIC_SETTINGS

A [QUIC_SETTINGS](./api/QUIC_SETTINGS.md) struct is used to configure settings on a `Configuration` handle, `Connection` handle, or globally.

For more details see [QUIC_SETTINGS](./api/QUIC_SETTINGS.md).

# API Object Parameters

MsQuic API Objects have a number of settings, or parameters, which can be queried via [GetParam](api/GetParam.md), or can be set/modifed via [SetParam](api/SetParam.md).

## Global Parameters

These parameters are accessed by calling [GetParam](./api/GetParam.md) or [SetParam](./api/SetParam.md) with `QUIC_PARAM_GLOBAL_*` and a `NULL` object handle.

| Setting                                           | Type                    | Get/Set   | Description                                                                                           |
|---------------------------------------------------|-------------------------|-----------|-------------------------------------------------------------------------------------------------------|
| `QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT`<br> 0    | uint16_t                | Both      | The percentage of available memory usable for handshake connections before stateless retry is used.   |
| `QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS`<br> 1      | uint32_t[]              | Get-only  | List of QUIC protocol versions supported in network byte order.                                       |
| `QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE`<br> 2      | uint16_t                | Both      | Must be a `QUIC_LOAD_BALANCING_MODE`.                                                                 |
| `QUIC_PARAM_GLOBAL_PERF_COUNTERS`<br> 3           | uint64_t[]              | Get-only  | Array size is QUIC_PERF_COUNTER_MAX.                                                                  |
| `QUIC_PARAM_GLOBAL_LIBRARY_VERSION`<br> 4         | uint32_t[4]             | Get-only  | MsQuic API version.                                                                                   |
| `QUIC_PARAM_GLOBAL_SETTINGS`<br> 5                | QUIC_SETTINGS           | Both      | Globally change settings for all subsequent connections.                                              |
| `QUIC_PARAM_GLOBAL_GLOBAL_SETTINGS`<br> 6         | QUIC_GLOBAL_SETTINGS    | Both      | Globally change global only settings.                                                                 |
| `QUIC_PARAM_GLOBAL_VERSION_SETTINGS`<br> 7        | QUIC_VERSIONS_SETTINGS  | Both      | Globally change version settings for all subsequent connections.                                      |
| `QUIC_PARAM_GLOBAL_LIBRARY_GIT_HASH`<br> 8        | char[64]                | Get-only  | Git hash used to build MsQuic (null terminated string)                                                |
| `QUIC_PARAM_GLOBAL_EXECUTION_CONFIG`<br> 9 (preview)        | QUIC_GLOBAL_EXECUTION_CONFIG   | Both      | Globally configure the execution model used for QUIC. Must be set before opening registration.        |
| `QUIC_PARAM_GLOBAL_TLS_PROVIDER`<br> 10           | QUIC_TLS_PROVIDER       | Get-Only  | The TLS provider being used by MsQuic for the TLS handshake.                                          |
| `QUIC_PARAM_GLOBAL_STATELESS_RESET_KEY`<br> 11    | uint8_t[]               | Set-Only  | Globally change the stateless reset key for all subsequent connections.                               |
| `QUIC_PARAM_GLOBAL_STATISTICS_V2_SIZES`<br> 12    | uint32_t[]               | Get-only  | Array of well-known sizes for each version of the QUIC_STATISTICS_V2 struct. The output array length is variable; pass a buffer of uint32_t and check BufferLength for the number of sizes returned. See GetParam documentation for usage details. |
| `QUIC_PARAM_GLOBAL_VERSION_NEGOTIATION_ENABLED`<br> (preview) | uint8_t (BOOLEAN) | Both | Globally enable the version negotiation extension for all client and server connections. |
| `QUIC_PARAM_GLOBAL_STATELESS_RETRY_CONFIG`<br> 13    | [QUIC_STATELESS_RETRY_CONFIG](./api/QUIC_STATELESS_RETRY_CONFIG.md) | Set-Only | Configure the stateless retry token secret, key algorithm, and key rotation interval. The secret length *must* match the AEAD algorithm key length. |
| `QUIC_PARAM_GLOBAL_XDP_MAP_CONFIG`<br> 14 (preview) | QUIC_XDP_MAP_CONFIG[] | Both | Configures XDP maps per interface. If using maps, this parameter must be set prior to opening any registration. See [MsQuic over XDP](./XDP.md#api-quic_param_global_xdp_map_config). |

## Registration Parameters

These parameters are accessed by calling [GetParam](./api/GetParam.md) or [SetParam](./api/SetParam.md) with `QUIC_PARAM_REGISTRATION_*` and a Registration object handle.

| Setting                                           | Type          | Get/Set   | Description                                                                                           |
|---------------------------------------------------|---------------|-----------|-------------------------------------------------------------------------------------------------------|

## Configuration Parameters

These parameters are accessed by calling [GetParam](./api/GetParam.md) or [SetParam](./api/SetParam.md) with `QUIC_PARAM_CONFIGURATION_*` and a Configuration object handle.

| Setting                                                          | Type                                   | Get/Set   | Description                                                                                                       |
|------------------------------------------------------------------|----------------------------------------|-----------|-------------------------------------------------------------------------------------------------------------------|
| `QUIC_PARAM_CONFIGURATION_SETTINGS`<br> 0                        | QUIC_SETTINGS                          | Both      | Settings to use for all connections sharing this Configuration. See [QUIC_SETTINGS](./api/QUIC_SETTINGS.md).      |
| `QUIC_PARAM_CONFIGURATION_TICKET_KEYS`<br> 1                     | QUIC_TICKET_KEY_CONFIG[]               | Set-only  | Resumption ticket encryption keys. Server-side only.                                                              |
| `QUIC_PARAM_CONFIGURATION_VERSION_SETTINGS`<br> 2                | QUIC_VERSIONS_SETTINGS                 | Both      | Change version settings for all connections on the configuration.                                                 |
| `QUIC_PARAM_CONFIGURATION_SCHANNEL_CREDENTIAL_ATTRIBUTE_W`<br> 3 | QUIC_SCHANNEL_CREDENTIAL_ATTRIBUTE_W   | Set-only  | Calls `SetCredentialsAttributesW` with the supplied attribute and buffer on the credential handle. Schannel-only. Only valid once the credential has been loaded.  |
| `QUIC_PARAM_CONFIGURATION_VERSION_NEG_ENABLED`<br> (preview)     | uint8_t (BOOLEAN)                      | Both      | Enables the version negotiation extension for all client connections on the configuration. |

## Listener Parameters

These parameters are accessed by calling [GetParam](./api/GetParam.md) or [SetParam](./api/SetParam.md) with `QUIC_PARAM_LISTENER_*` and a Listener object handle.

| Setting                                   | Type                      | Get/Set   | Description                                               |
|-------------------------------------------|---------------------------|-----------|-----------------------------------------------------------|
| `QUIC_PARAM_LISTENER_LOCAL_ADDRESS`<br> 0 | QUIC_ADDR                 | Get-only  | Get the full address tuple the server is listening on.    |
| `QUIC_PARAM_LISTENER_STATS`<br> 1         | QUIC_LISTENER_STATISTICS  | Get-only  | Get statistics specific to this Listener instance.        |
| `QUIC_PARAM_LISTENER_CIBIR_ID`<br> 2      | uint8_t[]                 | Both      | Sets a [CIBIR](./CIBIR.md) (CID-Based Identification and Routing) well-known identifier. |
| `QUIC_PARAM_DOS_MODE_EVENTS`<br> 2        | BOOLEAN                   | Both      | The Listener opted in for DoS Mode event.                 |
| `QUIC_PARAM_LISTENER_PARTITION_INDEX`<br> (preview) | uint16_t           | Both      | The partition to use for listener callback events and incoming connections. |

## Connection Parameters

These parameters are accessed by calling [GetParam](./api/GetParam.md) or [SetParam](./api/SetParam.md) with `QUIC_PARAM_CONNECTION_*` and a Connection object handle.

| Setting                                           | Type                          | Get/Set   | Description                                                                               |
|---------------------------------------------------|-------------------------------|-----------|-------------------------------------------------------------------------------------------|
| `QUIC_PARAM_CONN_QUIC_VERSION`<br> 0              | uint32_t                      | Get-only  | Negotiated QUIC protocol version                                                          |
| `QUIC_PARAM_CONN_LOCAL_ADDRESS`<br> 1             | QUIC_ADDR                     | Both      | Set on client only. Must be set before start or after handshake confirmed.                |
| `QUIC_PARAM_CONN_REMOTE_ADDRESS`<br> 2            | QUIC_ADDR                     | Both      | Set on client only. Must be set before start.                                             |
| `QUIC_PARAM_CONN_IDEAL_PROCESSOR`<br> 3           | uint16_t                      | Get-only  | Ideal processor for the app to send from.                                                 |
| `QUIC_PARAM_CONN_SETTINGS`<br> 4                  | QUIC_SETTINGS                 | Both      | Connection settings. See [QUIC_SETTINGS](./api/QUIC_SETTINGS.md)                          |
| `QUIC_PARAM_CONN_STATISTICS`<br> 5                | QUIC_STATISTICS               | Get-only  | Connection-level statistics.                                                              |
| `QUIC_PARAM_CONN_STATISTICS_PLAT`<br> 6           | QUIC_STATISTICS               | Get-only  | Connection-level statistics with platform-specific time format.                           |
| `QUIC_PARAM_CONN_SHARE_UDP_BINDING`<br> 7         | uint8_t (BOOLEAN)             | Both      | Set on client only. Must be called before start.                                          |
| `QUIC_PARAM_CONN_LOCAL_BIDI_STREAM_COUNT`<br> 8   | uint16_t                      | Get-only  | Number of bidirectional streams available.                                                |
| `QUIC_PARAM_CONN_LOCAL_UNIDI_STREAM_COUNT`<br> 9  | uint16_t                      | Get-only  | Number of unidirectional streams available.                                               |
| `QUIC_PARAM_CONN_MAX_STREAM_IDS`<br> 10           | uint64_t[4]                   | Get-only  | Array of number of client and server, bidirectional and unidirectional streams.           |
| `QUIC_PARAM_CONN_CLOSE_REASON_PHRASE`<br> 11      | char[]                        | Both      | Max length 512 chars.                                                                     |
| `QUIC_PARAM_CONN_STREAM_SCHEDULING_SCHEME`<br> 12 | QUIC_STREAM_SCHEDULING_SCHEME | Both      | Whether to use FIFO or round-robin stream scheduling.                                     |
| `QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED`<br> 13 | uint8_t (BOOLEAN)             | Both      | Indicate/query support for QUIC datagram extension. Must be set before start.             |
| `QUIC_PARAM_CONN_DATAGRAM_SEND_ENABLED`<br> 14    | uint8_t (BOOLEAN)             | Get-only  | Indicates peer advertised support for QUIC datagram extension. Call after connected.      |
| `QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION`<br> 15  | uint8_t (BOOLEAN)             | Both      | Application must `#define QUIC_API_ENABLE_INSECURE_FEATURES` before including msquic.h.   |
| `QUIC_PARAM_CONN_RESUMPTION_TICKET`<br> 16        | uint8_t[]                     | Set-only  | Must be set on client before starting connection.                                         |
| `QUIC_PARAM_CONN_PEER_CERTIFICATE_VALID`<br> 17   | uint8_t (BOOLEAN)             | Set-only  | Used for asynchronous custom certificate validation. *Deprecated soon. Replaced by [ConnectionCertificateValidationComplete]*                                     |
| `QUIC_PARAM_CONN_LOCAL_INTERFACE`<br> 18          | uint32_t                      | Set-only  | The local interface index to bind to.                                                     |
| `QUIC_PARAM_CONN_TLS_SECRETS`<br> 19              | QUIC_TLS_SECRETS              | Set-only  | The TLS secrets struct to be populated by MsQuic.                                         |
| `QUIC_PARAM_CONN_VERSION_SETTINGS`<br> 20         | QUIC_VERSION_SETTINGS         | Both      | The desired QUIC versions for the connection.                                             |
| `QUIC_PARAM_CONN_CIBIR_ID`<br> 21                 | uint8_t[]                     | Set-only  | The CIBIR well-known identifier.                                                          |
| `QUIC_PARAM_CONN_STATISTICS_V2`<br> 22            | QUIC_STATISTICS_V2            | Get-only  | Connection-level statistics, version 2.                                                   |
| `QUIC_PARAM_CONN_STATISTICS_V2_PLAT`<br> 23       | QUIC_STATISTICS_V2            | Get-only  | Connection-level statistics with platform-specific time format, version 2.                |
| `QUIC_PARAM_CONN_ORIG_DEST_CID` <br> 24           | uint8_t[]                     | Get-only  | The original destination connection ID used by the client to connect to the server.       |
| `QUIC_PARAM_CONN_SEND_DSCP` <br> 25               | uint8_t                       | Both      | The DiffServ Code Point put in the DiffServ field (formerly TypeOfService/TrafficClass) on packets sent from this connection. |
| `QUIC_PARAM_CONN_NETWORK_STATISTICS` <br> 32      | QUIC_NETWORK_STATISTICS       | Get-only  | Returns Connection level network statistics |
| `QUIC_PARAM_CONN_CLOSE_ASYNC` <br> 26      | uint8_t (BOOLEAN)      | Both  | The desired connection close behavior. Defaults to false (synchronous). |
| `QUIC_PARAM_CONN_ADD_BOUND_ADDRESS` <br> 27       | QUIC_ADDR                     | Set-only  | Add a bound address. Server only. |
| `QUIC_PARAM_CONN_ADD_OBSERVED_ADDRESS` <br> 28    | QUIC_ADD_OBSERVED_ADDRESS     | Set-only  | Set an observed address for a bound address. Server only. |
| `QUIC_PARAM_CONN_REMOVE_BOUND_ADDRESS` <br> 29    | QUIC_ADDR                     | Set-only  | Remove a bound address. Server only. |
| `QUIC_PARAM_CONN_ADD_PATH` <br> 30                | QUIC_PATH_PARAM               | Set-only  | Add a path. Client only. |
| `QUIC_PARAM_CONN_ACTIVATE_PATH` <br> 31           | QUIC_PATH_PARAM               | Set-only  | Activate a path. Client only. |
| `QUIC_PARAM_CONN_REMOVE_PATH` <br> 33             | QUIC_PATH_PARAM               | Set-only  | Remove a path. Client only. |
| `QUIC_PARAM_CONN_ADD_CANDIDATE_ADDRESS` <br> 34   | QUIC_CANDIDATE_ADDRESS        | Set-only  | Add a candidate address. Client only. |
| `QUIC_PARAM_CONN_REMOVE_CANDIDATE_ADDRESS` <br> 35| QUIC_CANDIDATE_ADDRESS        | Set-only  | Remove a candidate address. Client only. |
| `QUIC_PARAM_CONN_PATH_STATUS` <br> 36 | QUIC_PATH_STATUS | Set-only | Mark a path active or backup, and tell the peer. Multipath only. See [QUIC_PARAM_CONN_PATH_STATUS](#quic_param_conn_path_status). |
| `QUIC_PARAM_CONN_UNCONNECTED_UDP_SOCKET` <br> 37 | uint8_t (BOOLEAN) | Both | Set on client only. Must be set before start, and requires `QUIC_PARAM_CONN_SHARE_UDP_BINDING`. See [QUIC_PARAM_CONN_UNCONNECTED_UDP_SOCKET](#quic_param_conn_unconnected_udp_socket). |
| `QUIC_PARAM_CONN_PATH_STATISTICS` <br> 38 | QUIC_PATH_STATISTICS[] | Get-only | Network statistics for every path at once, one array entry per path. See [QUIC_PARAM_CONN_PATH_STATISTICS](#quic_param_conn_path_statistics). |
| `QUIC_PARAM_CONN_PATH_REQUIRED_DATAGRAM_LENGTH` <br> 39 | uint16_t | Both | The datagram payload length a path must already carry before it is used for sending. Zero, the default, means no requirement. See [QUIC_PARAM_CONN_PATH_REQUIRED_DATAGRAM_LENGTH](#quic_param_conn_path_required_datagram_length). |

### QUIC_PARAM_CONN_PATH_REQUIRED_DATAGRAM_LENGTH

The datagram payload length a path must already be able to carry before the connection will send on it. Zero, the default, means no requirement and is how the connection behaved before this parameter existed.

It exists for applications that promise their own callers a datagram size that never shrinks. Moving to a path that carries less would break that promise inside msquic, where the application cannot recover it, so the requirement keeps such a path out of use instead.

**A payload length, not an MTU.** The two are not the same question. A path's datagram capacity is derived from its MTU, its address family and its connection ID length, and the same MTU carries twenty fewer bytes over IPv6 than over IPv4. A connection that moves from an IPv4 path to an IPv6 path of identical MTU loses those twenty bytes; comparing MTUs would not notice. The comparison here is against `QuicCalculateDatagramLength` for the path in question, the same arithmetic that produces the `MaxSendLength` reported by `QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED`, so the natural value to set is the `MaxSendLength` the application last saw.

**A newly added path starts at `MinimumMtu` and has to be measured up to the requirement.** It is not held at that size: a validated path is probed even while it is held back, so it climbs towards `MaximumMtu` and is admitted once it can carry the required length. What the requirement costs is time, not reachability. A requirement above what `MaximumMtu` yields is the one that can never be satisfied.

Any value is accepted, including such a one. There is nothing useful to bound it against: capacity depends on family and connection ID length as well as MTU, none of them settled when the parameter is usually set. A requirement nothing meets holds every path out of use, which the path statistics make visible.

**The requirement filters; it does not drive.** A path is judged on the MTU it has already measured, and setting a requirement does not ask for any particular size to be reached. It does not stop the path being measured either: a validated path that is being held back is probed on the path itself, with a padded `PATH_CHALLENGE` rather than the usual PING, so it goes on converging while out of the rotation. Nothing announces the moment it becomes wide enough, so an application that wants to know watches `QUIC_PARAM_CONN_PATH_STATISTICS`.

What happens to such a path depends on whether multipath was negotiated.

**Without multipath**, `QUIC_PARAM_CONN_ACTIVATE_PATH` on it fails with `QUIC_STATUS_INVALID_STATE`. Activating an address with no path at all is refused for as long as any requirement is set: that branch creates the path and migrates onto it in one step, with no validation in between and so no point at which its capacity could be judged. Reaching a new address under a requirement means adding it with `QUIC_PARAM_CONN_ADD_PATH` and activating it once it has been validated and measured.

**With multipath**, a path joins the send rotation the moment it completes validation, so that is where it is judged. A path below the requirement is left in the backup state rather than dropped, and `PATH_BACKUP` is sent so the peer stops treating it as available. `QUIC_CONNECTION_EVENT_PATH_ADDED` is still indicated: the path exists and works, it is only that the application will not send on one this narrow. `QUIC_PARAM_CONN_ACTIVATE_PATH` on it is refused as well.

`QUIC_PARAM_CONN_LOCAL_ADDRESS` is a third way to move onto a path, and is held to the same requirement: it refuses a matching path that is too narrow, and refuses outright to create and migrate onto a new local address while any requirement is set.

A path already being sent on is not re-judged: the requirement governs putting a path to use, so activating a path that is already active, or `Paths[0]`, is not refused. `Paths[0]` is what path selection falls back to when nothing is active, so refusing it would achieve nothing.

Three things this does not do. `QUIC_PARAM_CONN_PATH_STATUS` is not gated — setting a path active through it works regardless, and is the deliberate escape hatch. A path left backup can still be promoted internally, by the fallback when the active path is removed or when another path finishes validating; see the caveat under [QUIC_PARAM_CONN_PATH_STATUS](#quic_param_conn_path_status). And migration driven by the peer is not gated either: when a peer starts sending from a new address, the connection follows it onto a path created at `MinimumMtu`, whatever the requirement says. That is the ordinary NAT rebind case, and refusing it would mean refusing to follow a peer that has moved.

### QUIC_PARAM_CONN_PATH_STATUS

Marks one path as active or as backup, and announces the change to the peer. Set-only; there is no way to read the current status back through this parameter.

The parameter and its struct are behind `QUIC_API_ENABLE_PREVIEW_FEATURES`, which the application must define to use either.

```c
typedef struct QUIC_PATH_STATUS {
    uint32_t PathId;
    BOOLEAN Active;
} QUIC_PATH_STATUS;
```

`PathId` selects the path, matching the identifier reported by `QUIC_PARAM_CONN_PATH_STATISTICS` and by the `QUIC_CONNECTION_EVENT_PATH_ADDED` / `PATH_REMOVED` / `PATH_STATUS_CHANGED` events. A path that exists but has not been assigned a path ID yet — one added before the handshake is confirmed — cannot be addressed, and neither can an unknown id; both fail with `QUIC_STATUS_INVALID_PARAMETER`.

The parameter requires multipath to have been negotiated and fails with `QUIC_STATUS_INVALID_STATE` otherwise. `BufferLength` must be exactly `sizeof(QUIC_PATH_STATUS)`.

Setting it has two effects.

Locally, the status steers path selection. Once multipath is negotiated and the handshake is confirmed, each send flush picks one path at random from those that are active and not closing, and builds that flush's packets on it — the choice is per flush, not per packet, and a flush triggered by pacing reuses the path the pacing was set up for rather than choosing again. Marking a path backup therefore takes it out of that rotation while leaving it validated and usable.

Two caveats on that. **If no path is active at all**, selection falls back to the first path and keeps sending on it, so marking every path backup does not stop sending. And the status is **not durable against internal changes**: several paths through the stack promote a path to active on their own — the fallback when the active path is removed, and a new path completing validation — and those do not send a PATH_AVAILABLE frame or raise an event. A path the application marked backup can therefore end up active again, with the peer still believing it is backup.

On the wire, the change is announced with a PATH_AVAILABLE or PATH_BACKUP frame — the PATH_STATUS frames of draft-ietf-quic-multipath — carrying the path ID and a sequence number kept per path ID. Setting the status to the value it already has changes nothing and sends nothing.

The peer can do the same to us. An incoming PATH_AVAILABLE or PATH_BACKUP flips the path's status locally and raises `QUIC_CONNECTION_EVENT_PATH_STATUS_CHANGED` with the new `IsActive`. A frame whose sequence number is not greater than the last one accepted for that path ID is ignored, so a reordered announcement cannot undo a newer one.

That event fires only for changes the peer initiated; setting this parameter raises nothing. An application tracking the current status of a path needs both — what it set itself, and what arrives on the event — and, given the promotion caveat above, neither is a complete record.

### QUIC_PARAM_CONN_PATH_STATISTICS

Returns an array of `QUIC_PATH_STATISTICS`, one entry per path the connection currently holds. It is the per-path counterpart of `QUIC_PARAM_CONN_NETWORK_STATISTICS`, which only ever reports the first path.

The number of paths is not known in advance and changes over the life of the connection, so call it the usual two-step way: pass a `BufferLength` of `0` to be told the size needed, then call again with a buffer at least that large. A buffer too small for the current number of paths returns `QUIC_STATUS_BUFFER_TOO_SMALL` with `BufferLength` set to the required size. On success `BufferLength` is set to the number of bytes actually written, so the entry count is `BufferLength / sizeof(QUIC_PATH_STATISTICS)`.

```c
typedef struct QUIC_PATH_STATISTICS {
    uint32_t PathId;
    uint64_t Rtt;
    uint64_t MinRtt;
    uint64_t MaxRtt;
    uint16_t Mtu;
    QUIC_NETWORK_STATISTICS NetworkStatistics;
} QUIC_PATH_STATISTICS;
```

`PathId` identifies which path an entry describes. It is needed because array position is not stable: paths are removed and the remaining ones move up, so the entry at a given index is not necessarily the same path it was on the previous call. It matches the `PathId` used by `QUIC_PARAM_CONN_PATH_STATUS`.

It is not guaranteed unique. While a path is being rebound — the peer reappearing on a new port through a NAT, for instance — the new path and the one it replaces briefly share a path ID, and both are reported. The two entries carry that path ID's congestion control, so their `NetworkStatistics` agree; what tells them apart is the per-path `Rtt`, `MinRtt`, `MaxRtt` and `Mtu`.

`MinRtt` and `MaxRtt` are zero until the path has produced an RTT sample. `Rtt` is the smoothed RTT, which starts from the configured `InitialRttMs` and so is non-zero from the outset.

Paths that exist but have no path ID assigned yet — a path added before the handshake is confirmed — are not reported, since there is nothing to identify them by and no congestion control to read from.

Works whether or not multipath was negotiated; a connection with a single path returns one entry.

### QUIC_PARAM_CONN_UNCONNECTED_UDP_SOCKET

By default a client connection's UDP socket is connected to the server's address, so the binding underneath it can only ever be shared by connections to that same address. Setting `QUIC_PARAM_CONN_UNCONNECTED_UDP_SOCKET` to `TRUE` leaves the socket unconnected, which lets connections to different remote addresses share one binding, and therefore one local port.

The parameter requires `QUIC_PARAM_CONN_SHARE_UDP_BINDING` to also be set: an unconnected socket receives datagrams from any remote address, so incoming packets are matched to a connection by connection ID alone, and only a shared binding gives the connection a non-zero length source connection ID. Setting it without one fails with `QUIC_STATUS_INVALID_STATE`.

It also requires a specific local address, set with `QUIC_PARAM_CONN_LOCAL_ADDRESS`. A connected socket takes its source address from the kernel when it is connected; an unconnected one does not, and the connection's first packet goes out before anything has been learned from the peer, so the address to send from has to be named. The port may be left as 0 to let the stack choose one. Starting a connection with an unconnected socket and no local address, or a wildcard one, fails the connection with `QUIC_STATUS_INVALID_PARAMETER`. The same applies to each additional path opened with `QUIC_PARAM_CONN_ADD_PATH`, whose local address must likewise be a specific one.

To place several connections on one local port, start the first connection, read its local address back with `QUIC_PARAM_CONN_LOCAL_ADDRESS`, and set that address on the subsequent connections along with the same two parameters.

### QUIC_PARAM_CONN_STATISTICS_V2

Querying the `QUIC_STATISTICS_V2` struct via `QUIC_PARAM_CONN_STATISTICS_V2` or `QUIC_PARAM_CONN_STATISTICS_V2_PLAT` should be aware of possible changes in the size of the struct, depending on the version of MsQuic the app using at runtime, not just what it was compiled against.

The minimum size of the struct will always be `QUIC_STATISTICS_V2_SIZE_1`. Future version of MsQuic will append new fields to the end of the struct, so the maximum possible size will increase.

When an app queries for the statistics, it must always supply an input buffer of length at least `QUIC_STATISTICS_V2_SIZE_1`, but `sizeof(QUIC_STATISTICS_V2)` will always work as well. MsQuic will support older callers that supply at least that buffer size, even if the maximum size of the struct has grown in a future version of MsQuic. MsQuic will only write the fields that can completely fit in the buffer supplied by the app.

## TLS Parameters

These parameters are accessed by calling [GetParam](./api/GetParam.md) or [SetParam](./api/SetParam.md) with `QUIC_PARAM_TLS_*` and a Connection object handle.

| Setting                                   | Type                      | Get/Set   | Description                                                                                                               |
|-------------------------------------------|---------------------------|-----------|---------------------------------------------------------------------------------------------------------------------------|
| `QUIC_PARAM_TLS_HANDSHAKE_INFO`<br> 0     | QUIC_HANDSHAKE_INFO       | Get-only  | Called in the `QUIC_CONNECTION_EVENT_CONNECTED` event to get the cryptographic parameters negotiated in the handshake.    |
| `QUIC_PARAM_TLS_NEGOTIATED_ALPN`<br> 1    | uint8_t[] (max 255 bytes) | Get-only  | Called in the `QUIC_CONNECTION_EVENT_CONNECTED` event to get the negotiated ALPN.                                         |

## Schannel-only TLS Parameters

These parameters are access by calling [GetParam](./api/GetParam.md) or [SetParam](./api/SetParam.md) with `QUIC_PARAM_TLS_SCHANNEL_*` and a Connection object handle.

| Setting                                                | Type                                 | Get/Set   | Description                                                                                                                                                   |
|--------------------------------------------------------|--------------------------------------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W`<br> 0    | QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_W    | Get-only  | Calls `QueryContextAttributesW` for the given attribute and buffer. Only valid until the `QUIC_CONNECTION_EVENT_CONNECTED` event, or when TLS is cleaned up.   |
| `QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_EX_W`<br> 1 | QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_EX_W | Get-only  | Calls `QueryContextAttributesExW` for the given attribute and buffer. Only valid until the `QUIC_CONNECTION_EVENT_CONNECTED` event, or when TLS is cleaned up. |
| `QUIC_PARAM_TLS_SCHANNEL_SECURITY_CONTEXT_TOKEN`<br> 2 | HANDLE                               | Get-only  | Calls `QuerySecurityContextToken` on the Schannel handle. Only valid until the `QUIC_CONNECTION_EVENT_CONNECTED` event, or when TLS is cleaned up.            |

## Stream Parameters

These parameters are access by calling [GetParam](./api/GetParam.md) or [SetParam](./api/SetParam.md) with `QUIC_PARAM_STREAM_*` and a Stream object handle.

| Setting                                           | Type              | Get/Set   | Description                                                                           |
|---------------------------------------------------|-------------------|-----------|---------------------------------------------------------------------------------------|
| `QUIC_PARAM_STREAM_ID`<br> 0                      | QUIC_UINT62       | Get-only  | Must be called on a stream after [StreamStart](./api/StreamStart.md) is called.      |
| `QUIC_PARAM_STREAM_0RTT_LENGTH`<br> 1             | uint64_t          | Get-only  | Length of 0-RTT data received from peer.                                              |
| `QUIC_PARAM_STREAM_IDEAL_SEND_BUFFER_SIZE`<br> 2  | uint64_t - bytes  | Get-only  | Ideal buffer size to queue to the stream. Assumes only one stream sends steadily.     |
| `QUIC_PARAM_STREAM_PRIORITY` <br> 3               | uint16_t          | Get/Set   | A value from 0x0 to 0xFFFF that indicates the Stream priority. 0xFFFF is highest priority. Data on higher priority stream get sent first. All streams start with priority 0x7FFF by default.  |
| `QUIC_PARAM_STREAM_STATISTICS` <br> 4             | QUIC_STREAM_STATISTICS | Get-only  | Stream-level statistics. |
| `QUIC_PARAM_STREAM_RELIABLE_OFFSET` <br> 5        | uint64_t          | Get/Set   | Part of the new Reliable Reset preview feature. Sets/Gets the number of bytes a sender must send before closing SEND path.

## See Also

[QUIC_SETTINGS](./api/QUIC_SETTINGS.md)<br>
[GetParam](./api/GetParam.md)<br>
[SetParam](./api/SetParam.md)<br>

[ConnectionCertificateValidationComplete]: ./api/ConnectionCertificateValidationComplete.md
