


/*----------------------------------------------------------
// Decoder Ring for AllocFailure
// Allocation of '%s' failed. (%llu bytes)
// QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "address monitor snapshot",
                RawCount * sizeof(CXPLAT_LOCAL_ADDRESS));
// arg2 = arg2 = "address monitor snapshot" = arg2
// arg3 = arg3 = RawCount * sizeof(CXPLAT_LOCAL_ADDRESS) = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_ADDRESS_MONITOR_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
