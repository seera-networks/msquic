


/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            errno,
            "socket(AF_NETLINK, NETLINK_ROUTE) failed");
// arg2 = arg2 = errno = arg2
// arg3 = arg3 = "socket(AF_NETLINK, NETLINK_ROUTE) failed" = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_ADDRESS_MONITOR_LINUX_C, LibraryErrorStatus,
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
            "netlink dump buffer",
            (uint64_t)CXPLAT_NETLINK_BUFFER_SIZE);
// arg2 = arg2 = "netlink dump buffer" = arg2
// arg3 = arg3 = (uint64_t)CXPLAT_NETLINK_BUFFER_SIZE = arg3
----------------------------------------------------------*/
TRACEPOINT_EVENT(CLOG_ADDRESS_MONITOR_LINUX_C, AllocFailure,
    TP_ARGS(
        const char *, arg2,
        unsigned long long, arg3), 
    TP_FIELDS(
        ctf_string(arg2, arg2)
        ctf_integer(uint64_t, arg3, arg3)
    )
)
