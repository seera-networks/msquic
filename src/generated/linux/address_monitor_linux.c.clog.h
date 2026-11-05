#ifndef CLOG_DO_NOT_INCLUDE_HEADER
#include <clog.h>
#endif
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER CLOG_ADDRESS_MONITOR_LINUX_C
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define  TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "address_monitor_linux.c.clog.h.lttng.h"
#if !defined(DEF_CLOG_ADDRESS_MONITOR_LINUX_C) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define DEF_CLOG_ADDRESS_MONITOR_LINUX_C
#include <lttng/tracepoint.h>
#define __int64 __int64_t
#include "address_monitor_linux.c.clog.h.lttng.h"
#endif
#include <lttng/tracepoint-event.h>
#ifndef _clog_MACRO_QuicTraceEvent
#define _clog_MACRO_QuicTraceEvent  1
#define QuicTraceEvent(a, ...) _clog_CAT(_clog_ARGN_SELECTOR(__VA_ARGS__), _clog_CAT(_,a(#a, __VA_ARGS__)))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/*----------------------------------------------------------
// Decoder Ring for LibraryErrorStatus
// [ lib] ERROR, %u, %s.
// QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Error,
            "socket(AF_NETLINK, NETLINK_ROUTE) failed");
// arg2 = arg2 = Error = arg2
// arg3 = arg3 = "socket(AF_NETLINK, NETLINK_ROUTE) failed" = arg3
----------------------------------------------------------*/
#ifndef _clog_4_ARGS_TRACE_LibraryErrorStatus
#define _clog_4_ARGS_TRACE_LibraryErrorStatus(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_ADDRESS_MONITOR_LINUX_C, LibraryErrorStatus , arg2, arg3);\

#endif




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
#ifndef _clog_4_ARGS_TRACE_AllocFailure
#define _clog_4_ARGS_TRACE_AllocFailure(uniqueId, encoded_arg_string, arg2, arg3)\
tracepoint(CLOG_ADDRESS_MONITOR_LINUX_C, AllocFailure , arg2, arg3);\

#endif




#ifdef __cplusplus
}
#endif
#ifdef CLOG_INLINE_IMPLEMENTATION
#include "quic.clog_address_monitor_linux.c.clog.h.c"
#endif
