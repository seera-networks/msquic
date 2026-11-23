SetParam function
======

Sets a parameter on an API object.

# Syntax

```C
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
(QUIC_API * QUIC_SET_PARAM_FN)(
    _When_(QUIC_PARAM_IS_GLOBAL(Param), _Reserved_)
    _When_(!QUIC_PARAM_IS_GLOBAL(Param), _In_ _Pre_defensive_)
        HQUIC Handle,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    );
```

# Parameters

`Handle`

The valid handle to any API object. This includes handles to registration, configuration, listener, connection and stream objects. For global parameters, this parameter must be `NULL`.

`Param`

The parameter for which the value is to be set (for example, `QUIC_PARAM_CONN_IDLE_TIMEOUT`).

`BufferLength`

A pointer to the size, in bytes, of the `Buffer` buffer.

`Buffer`

A pointer to the buffer in which the value for the requested option is to be returned.

# Return Value

The function returns a [QUIC_STATUS](QUIC_STATUS.md). The app may use `QUIC_FAILED` or `QUIC_SUCCEEDED` to determine if the function failed or succeeded.

# Remarks

**TODO**

## QUIC_PARAM_GLOBAL_REFRESH_LOCAL_ADDRESSES

**Preview feature**: This parameter is in [preview](../PreviewFeatures.md). It should be considered unstable and can be subject to breaking changes.

Asks the library to re-examine the host's local addresses now, as if the platform had reported a change.

- **Type:** none, or `uint32_t` of [`QUIC_REFRESH_LOCAL_ADDRESSES_FLAGS`](#quic_refresh_local_addresses_flags)
- **Set-only**
- **Handle:** `NULL` (global)

This exists for iOS, where the platform's address notifications come from `nw_path_monitor` and a suspended process receives none of them: when the application comes back to the foreground, its view of the host's addresses may be out of date and nothing will say so. Calling this on the foreground transition is what brings it back in step. It is not iOS-specific, though -- any application that has reason to think it missed notifications can use it.

What follows the call is exactly what follows a platform notification: the usual debounce window, a re-enumeration, and a comparison against the previous snapshot. If nothing changed, nothing is reported. If something did, it reaches connections as [QUIC_CONNECTION_EVENT_LOCAL_ADDRESSES_CHANGED](QUIC_CONNECTION_EVENT.md#quic_connection_event_local_addresses_changed), and `QUIC_ADD_ADDRESS_AUTO` connections manage their paths accordingly.

The call is asynchronous: it posts the request to the monitor's own thread and returns, so it is safe to call from a UI thread. The enumeration never runs on the caller's thread.

| Status | Meaning |
|---|---|
| `QUIC_STATUS_SUCCESS` | The request was posted, **or** there was nothing to post it to -- no address monitor is running, or the platform has no backend at all. An application can call this unconditionally, without knowing whether any connection asked for address tracking. |
| `QUIC_STATUS_INVALID_PARAMETER` | `BufferLength` was neither zero nor `sizeof(uint32_t)`, or an undefined flag bit was set. |

Note that this does **not** start the monitor, and says nothing about whether one could be started. A connection with `QUIC_SETTINGS.AddAddressMode` set to `QUIC_ADD_ADDRESS_AUTO` (the default) or `QUIC_ADD_ADDRESS_MANUAL` starts it; reading `QUIC_PARAM_GLOBAL_LOCAL_ADDRESSES` starts it for the length of that call, and that read is what reports `QUIC_STATUS_NOT_SUPPORTED` on a platform with no backend.

### QUIC_REFRESH_LOCAL_ADDRESSES_FLAGS

| Flag | Meaning |
|---|---|
| `QUIC_REFRESH_LOCAL_ADDRESSES_NONE` | Re-examine the addresses. What an empty buffer selects. |
| `QUIC_REFRESH_LOCAL_ADDRESSES_RESUBSCRIBE` | Also have the platform drop and re-arm its subscription, for one that may have been left stale rather than merely behind. Honoured on Apple and Linux; accepted elsewhere, where a subscription does not go stale, and treated as a plain refresh. |

**Sample usage:**
```c
//
// From the application's foreground transition -- on iOS,
// sceneDidBecomeActive or applicationDidBecomeActive.
//
uint32_t Flags = QUIC_REFRESH_LOCAL_ADDRESSES_RESUBSCRIBE;
QUIC_STATUS Status =
    MsQuic->SetParam(
        NULL,
        QUIC_PARAM_GLOBAL_REFRESH_LOCAL_ADDRESSES,
        sizeof(Flags),
        &Flags);
```

# See Also

[Settings](../Settings.md#api-object-parameters)<br>
[GetParam](GetParam.md)<br>
