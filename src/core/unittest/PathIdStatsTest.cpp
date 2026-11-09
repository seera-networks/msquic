/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for logging per-path-ID statistics when there is no path ID left
    to log.

    The shape this covers is the one an XDP BVT crashed on: route resolution
    fails on the last path, QuicConnProcessRouteCompletion removes it,
    QuicPathRemove finds nowhere left to go and closes the connection, and the
    close logs statistics for a path whose path ID is already gone.
    QuicPathIDLogStatistics then reads PathID->Path and
    PathID->CongestionControl off a null pointer.

    Reproduced here rather than against a peer because the route failure that
    gets there needs the raw datapath, and the thing being tested is one
    missing null check reached from a call that is cheap to make directly.

    These only bite with logging compiled in. QuicPathIDLogStatistics is
    nothing but a trace call, so with tracing off its arguments are never
    evaluated and the null is never read -- the first version of this test
    passed with the fix removed, which is worth knowing before trusting it.
    Configure with -DQUIC_ENABLE_LOGGING=on -DQUIC_LOGGING_TYPE=stdout and the
    unguarded build segfaults here (exit 139) while the guarded one exits 0.
    That is also why CI found it and an ordinary local build would not: the
    BVTs run with logging on.

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "PathIdStatsTest.cpp.clog.h"
#endif

//
// Declared here rather than in connection.h: nothing outside connection.c
// calls it, and this test does not need it to.
//
extern "C" {
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicConnLogPathIDStatistics(
    _In_ QUIC_CONNECTION* Connection
    );
}

//
// A connection with no path ID on its only path, which QuicPathRemove already
// treats as reachable -- it guards this very field before repointing it.
// Logging statistics for it has to be equally willing to find nothing there.
//
TEST(PathIdStatsTest, SurvivesANullPathIdWithoutMultipath)
{
    QUIC_CONNECTION Connection {};
    Connection.State.Started = TRUE;
    Connection.State.MultipathNegotiated = FALSE;
    Connection.PathsCount = 1;
    Connection.Paths[0].PathID = nullptr;

    //
    // Dereferenced the null and took the process with it before the guard --
    // in a logging build. See the note at the top of this file.
    //
    QuicConnLogPathIDStatistics(&Connection);
}

//
// And the multipath branch, which has always had the check, still has it --
// so a fix to the branch above cannot quietly be a regression here.
//
TEST(PathIdStatsTest, SurvivesANullPathIdWithMultipath)
{
    QUIC_CONNECTION Connection {};
    Connection.State.Started = TRUE;
    Connection.State.MultipathNegotiated = TRUE;
    Connection.PathsCount = 2;
    Connection.Paths[0].PathID = nullptr;
    Connection.Paths[1].PathID = nullptr;

    QuicConnLogPathIDStatistics(&Connection);
}

//
// A connection that never started logs nothing at all, so the null never gets
// as far as being looked at. Worth pinning: it is the early return that makes
// the ordinary teardown path safe, and the guard above is only for the case
// that gets past it.
//
TEST(PathIdStatsTest, LogsNothingBeforeTheConnectionStarts)
{
    QUIC_CONNECTION Connection {};
    Connection.State.Started = FALSE;
    Connection.PathsCount = 1;
    Connection.Paths[0].PathID = nullptr;

    QuicConnLogPathIDStatistics(&Connection);
}
