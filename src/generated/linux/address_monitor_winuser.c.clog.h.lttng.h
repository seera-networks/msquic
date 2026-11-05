


/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "address monitor adapter addresses",
                (uint64_t)AdaptersSize);
// arg2 = arg2 = "address monitor adapter addresses" = arg2
// arg3 = arg3 = (uint64_t)AdaptersSize = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_ADDRESS_MONITOR_WINUSER_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)



/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Error,
            "GetAdaptersAddresses(address monitor)");
// arg2 = arg2 = Error = arg2
// arg3 = arg3 = "GetAdaptersAddresses(address monitor)" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_ADDRESS_MONITOR_WINUSER_C, LibraryErrorStatus,
    TP_ARGS(
        unsigned int, arg2,
        const char *, arg3), 
    TP_FIELDS(
        ctf_integer(unsigned int, arg2, arg2)
        ctf_string(arg3, arg3)
    )
)
