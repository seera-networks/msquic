


/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            (uint32_t)Error,
            "getifaddrs(address monitor) failed");
// arg2 = arg2 = (uint32_t)Error = arg2
// arg3 = arg3 = "getifaddrs(address monitor) failed" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_ADDRESS_MONITOR_DARWIN_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "address monitor raw addresses",
            (uint64_t)Count * sizeof(CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS));
// arg2 = arg2 = "address monitor raw addresses" = arg2
// arg3 = arg3 = (uint64_t)Count * sizeof(CXPLAT_ADDRESS_MONITOR_RAW_ADDRESS) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_ADDRESS_MONITOR_DARWIN_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
