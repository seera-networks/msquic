#!/usr/bin/env bash
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Stage 5 of #169: draft-kozuka-quic-stateless-punch behind real NATs.
#
# Every test in stages 1-4 runs both endpoints on one host, where the direct
# path works whether or not a punch packet was ever sent -- so the failure the
# mechanism exists to prevent, a PATH_CHALLENGE dropped because no binding
# exists, cannot occur. This builds an environment where it can: five Linux
# network namespaces, two of them NATs with the mapping behaviour RFC 4787
# describes, and a relay that is the only way the two endpoints can reach each
# other to begin with.
#
#   cli  10.1.0.2 --- 10.1.0.1 cnat 203.0.113.2 ---+
#                                                  +--- 203.0.113.1  pub (relay)
#   srv  10.2.0.2 --- 10.2.0.1 snat 203.0.113.3 ---+
#
# Needs no root: it re-executes itself inside a user, mount and network
# namespace, where it is root enough for ip(8) and iptables(8). It does need a
# Debug build, because the counters that make "one punch and no more" visible
# are debug-only parameters. See docs/nat-punch-testing.md.
#
set -u -o pipefail

#
# Re-exec into our own namespaces. Everything below runs as root-in-a-userns,
# which is what lets this be a script a developer runs rather than one they
# sudo.
#
if [ "${PUNCH_NS_READY:-}" != "1" ]; then
    if ! command -v unshare >/dev/null 2>&1; then
        echo "nat-punch-test: unshare(1) is required" >&2
        exit 1
    fi
    #
    # A private PID namespace as well as the network one, for two reasons
    # beyond hygiene: nothing this script starts can outlive it, and teardown
    # between cases can match processes by name. That matters because
    # `ip netns exec` forks -- the pid it returns is its own, not the tool's,
    # so killing that pid leaves the tool holding its port and the next case
    # fails to bind with EADDRINUSE. Inside a pid namespace, pkill by name
    # cannot reach anything but our own processes.
    #
    exec unshare -rmnp --fork --mount-proc --propagation private \
        env PUNCH_NS_READY=1 "$0" "$@"
fi

BIN=""
ONLY=""
KEEP=0
VERBOSE=0

usage() {
    cat <<EOF
Usage: scripts/nat-punch-test.sh [options]

  --bin <dir>    Directory holding quicpunch and libmsquic.so (a Debug build).
                 Defaults to the first build/linux/*/bin that has quicpunch.
  --case <name>  Run one case: direct, strict, edm, droppunch,
                 multiaddr-cross, multiaddr-return. Default: all.
  --keep         Drop into a shell inside the topology when the cases finish.
  --verbose      Echo each role's output.
  --help         This text.

Exit status is the number of failed cases.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --bin) BIN="${2:-}"; shift 2 ;;
        --case) ONLY="${2:-}"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        --verbose) VERBOSE=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ -z "$BIN" ]; then
    for Candidate in "$ROOT"/build/linux/*/bin "$ROOT"/build/linux/*/bin/Debug; do
        if [ -x "$Candidate/quicpunch" ]; then BIN="$Candidate"; break; fi
    done
fi
if [ -z "$BIN" ] || [ ! -x "$BIN/quicpunch" ]; then
    echo "nat-punch-test: no quicpunch found; build it with" >&2
    echo "  cmake -S . -B build/linux/x64_chk -DQUIC_BUILD_TOOLS=on -DCMAKE_BUILD_TYPE=Debug" >&2
    echo "  cmake --build build/linux/x64_chk --target quicpunch" >&2
    echo "and pass --bin <dir> if it is somewhere unusual." >&2
    exit 1
fi
BIN="$(cd "$BIN" && pwd)"

for Tool in ip iptables openssl; do
    command -v "$Tool" >/dev/null 2>&1 || { echo "nat-punch-test: $Tool is required" >&2; exit 1; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --------------------------------------------------------------------------
# Addresses. Named once here because the assertions quote them.
# --------------------------------------------------------------------------

CLI_PRIV=10.1.0.2
CNAT_LAN=10.1.0.1
CNAT_WAN=203.0.113.2
SRV_PRIV=10.2.0.2
SNAT_LAN=10.2.0.1
SNAT_WAN=203.0.113.3
PUB=203.0.113.1

RELAY_PORT=4555
SRV_PORT=4567
PUNCH_PORT=4600
EDM_PORT=4700

PASSED=0
FAILED=0

say()  { printf '%s\n' "$*"; }
ok()   { PASSED=$((PASSED+1)); printf '    ok    %s\n' "$*"; }
bad()  { FAILED=$((FAILED+1)); printf '    FAIL  %s\n' "$*"; }
note() { printf '          %s\n' "$*"; }

# Asserts a "PUNCH: key=value" line exists.
has() {
    if grep -q -- "$2" "$1"; then ok "$3"; else bad "$3"; note "wanted /$2/ in $(basename "$1")"; fi
}
hasnt() {
    if grep -q -- "$2" "$1"; then bad "$3"; note "unwanted /$2/ in $(basename "$1")"; else ok "$3"; fi
}

netns() { ip netns exec "$1" "${@:2}"; }
punch() { local Ns="$1"; shift; ip netns exec "$Ns" env LD_LIBRARY_PATH="$BIN" "$BIN/quicpunch" "$@"; }

# --------------------------------------------------------------------------
# Topology
# --------------------------------------------------------------------------

topo_down() {
    for Ns in cli cnat pub snat srv; do
        ip netns delete "$Ns" >/dev/null 2>&1
    done
}

link() { # <ns-a> <if-a> <ns-b> <if-b>
    ip link add "$2" type veth peer name "$4" >/dev/null 2>&1 || return 1
    ip link set "$2" netns "$1" || return 1
    ip link set "$4" netns "$3" || return 1
}

topo_up() {
    mount -t tmpfs none /run/netns >/dev/null 2>&1 || mkdir -p /run/netns

    topo_down
    for Ns in cli cnat pub snat srv; do
        ip netns add "$Ns" || return 1
        ip -n "$Ns" link set lo up || return 1
    done

    link cli eth0 cnat lan0 || return 1
    link cnat wan0 pub p1   || return 1
    link srv eth0 snat lan0 || return 1
    link snat wan0 pub p2   || return 1

    #
    # The two NATs share one L2 segment, which is what makes a direct path
    # physically possible at all -- the punched route is cnat <-> snat, and the
    # relay only ever sees the public addresses.
    #
    ip -n pub link add br0 type bridge          || return 1
    ip -n pub link set p1 master br0            || return 1
    ip -n pub link set p2 master br0            || return 1
    ip -n pub addr add "$PUB/24" dev br0        || return 1
    for If in br0 p1 p2; do ip -n pub link set "$If" up || return 1; done

    ip -n cli addr add "$CLI_PRIV/24" dev eth0  || return 1
    ip -n cli link set eth0 up                  || return 1
    ip -n cli route add default via "$CNAT_LAN"  || return 1

    ip -n srv addr add "$SRV_PRIV/24" dev eth0  || return 1
    ip -n srv link set eth0 up                  || return 1
    ip -n srv route add default via "$SNAT_LAN"  || return 1

    ip -n cnat addr add "$CNAT_LAN/24" dev lan0 || return 1
    ip -n cnat addr add "$CNAT_WAN/24" dev wan0 || return 1
    ip -n cnat link set lan0 up                 || return 1
    ip -n cnat link set wan0 up                 || return 1

    ip -n snat addr add "$SNAT_LAN/24" dev lan0 || return 1
    ip -n snat addr add "$SNAT_WAN/24" dev wan0 || return 1
    ip -n snat link set lan0 up                 || return 1
    ip -n snat link set wan0 up                 || return 1

    netns cnat sysctl -q -w net.ipv4.ip_forward=1 || return 1
    netns snat sysctl -q -w net.ipv4.ip_forward=1 || return 1
    return 0
}

flush_nat() { # <ns>
    netns "$1" iptables -t nat -F
    netns "$1" iptables -t mangle -F
    netns "$1" iptables -F
}

#
# The client's NAT, in every case: endpoint-independent mapping, which is the
# draft's own prerequisite (RFC 4787 section 4.1). SNAT to an address with no
# port named leaves netfilter free to keep the source port, and with one client
# it always can -- so this socket is seen as CNAT_WAN on the same port it uses
# inside, which is what makes the client able to name its own mapping without
# being told it.
#
cnat_rules() {
    flush_nat cnat
    netns cnat iptables -t nat -A POSTROUTING -o wan0 -s 10.1.0.0/24 -p udp \
        -j SNAT --to-source "$CNAT_WAN"
}

#
# The server's NAT. The relay reaches the listener through a forward that only
# the relay may use: without that restriction the client could reach the server
# directly and every case would pass whether or not a punch was ever sent,
# which is the trap this whole environment exists to avoid.
#
snat_base() { # <mapping: eim|edm>
    flush_nat snat
    netns snat iptables -t nat -A PREROUTING -i wan0 -s "$PUB" -p udp \
        --dport "$SRV_PORT" -j DNAT --to-destination "$SRV_PRIV:$SRV_PORT"

    if [ "$1" = "edm" ]; then
        #
        # Endpoint-dependent mapping: the port this host is seen as depends on
        # who it is talking to. The address the server learns -- and therefore
        # advertises -- is the one it is seen as towards the relay, so a punch
        # towards the client goes out as a different port and the client's
        # probe arrives at a mapping that does not exist. The draft says
        # traversal should simply fail here.
        #
        netns snat iptables -t nat -A POSTROUTING -o wan0 -s "$SRV_PRIV" -p udp \
            --sport "$PUNCH_PORT" -d "$PUB" -j SNAT --to-source "$SNAT_WAN:$PUNCH_PORT"
        netns snat iptables -t nat -A POSTROUTING -o wan0 -s "$SRV_PRIV" -p udp \
            --sport "$PUNCH_PORT" -j SNAT --to-source "$SNAT_WAN:$EDM_PORT"
    fi

    netns snat iptables -t nat -A POSTROUTING -o wan0 -s 10.2.0.0/24 -p udp \
        -j SNAT --to-source "$SNAT_WAN"
}

#
# Address-dependent filtering (RFC 4787 section 5): once the server has sent to
# an address, that address may send back to the mapping, on any port. This is
# what the implementation needs, and the reason is worth stating: the
# reconciler opens the direct path with QuicAddrSetPort(&Local, 0), so the
# client probes from a fresh socket whose mapping is not the one it advertised.
# Under address-and-port-dependent filtering -- what plain conntrack does, and
# what the "strict" case leaves in place -- the punched binding never matches
# that probe.
#
# xt_recent is the emulation: the punch records its destination on the way out,
# and only recorded addresses are forwarded in. So the binding still exists
# only because the punch created it, which is the property being tested.
#
snat_addr_dep_filtering() {
    netns snat iptables -t mangle -A POSTROUTING -o wan0 -s "$SRV_PRIV" -p udp \
        --sport "$PUNCH_PORT" -m recent --name punched --set --rdest
    netns snat iptables -t nat -A PREROUTING -i wan0 -p udp --dport "$PUNCH_PORT" \
        -m recent --name punched --rcheck --seconds 60 --rsource \
        -j DNAT --to-destination "$SRV_PRIV:$PUNCH_PORT"
}

make_cert() {
    openssl req -x509 -newkey rsa:2048 -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
        -days 2 -nodes -subj "/CN=quicpunch" >/dev/null 2>&1
}

# --------------------------------------------------------------------------
# Roles
# --------------------------------------------------------------------------

RELAY_PID=""
SRV_PID=""
CLI_RC=0

start_roles() { # <server-seconds>
    punch pub -role:relay \
        "-listen:$PUB:$RELAY_PORT" "-server:$SNAT_WAN:$SRV_PORT" \
        > "$WORK/relay.log" 2>&1 &
    RELAY_PID=$!

    local RelayWait=0
    while [ "$RelayWait" -lt 100 ]; do
        grep -q "relay_listen=" "$WORK/relay.log" 2>/dev/null && break
        if grep -q "bind failed" "$WORK/relay.log" 2>/dev/null; then
            note "relay could not bind: $(grep 'bind failed' "$WORK/relay.log" | head -1)"
            return 1
        fi
        sleep 0.1
        RelayWait=$((RelayWait+1))
    done

    punch srv -role:server \
        "-listen:$SRV_PRIV:$SRV_PORT" \
        "-cert:$WORK/cert.pem" "-key:$WORK/key.pem" \
        "-advertise:$SRV_PRIV:$PUNCH_PORT=$SNAT_WAN:$PUNCH_PORT" \
        "-time:$1" \
        > "$WORK/srv.log" 2>&1 &
    SRV_PID=$!

    #
    # Waited for rather than slept past. A fixed sleep was long enough until
    # the cases ran back to back, where a listener that had not yet got its
    # port made the next case look like a traversal failure.
    #
    local Waited=0
    while [ "$Waited" -lt 100 ]; do
        grep -q "server_ready=1" "$WORK/srv.log" 2>/dev/null && return 0
        sleep 0.1
        Waited=$((Waited+1))
    done
    note "server did not become ready"
    return 1
}

run_client() { # <seconds> [extra args...]
    local Seconds="$1"; shift
    punch cli -role:client \
        "-target:$PUB:$RELAY_PORT" \
        "-candidate:$CLI_PRIV=$CNAT_WAN" \
        "-time:$Seconds" "$@" \
        > "$WORK/cli.log" 2>&1
    CLI_RC=$?
}

stop_roles() {
    #
    # The client has just exited, and the server reports its punch counters
    # from its shutdown handler -- so it needs the peer's close to arrive and
    # be processed before it is asked to stop.
    #
    sleep 1

    #
    # By name, not by pid: see the note on the pid namespace above. Waited out
    # rather than left to the next case to discover -- these are often
    # sanitizer builds and their teardown is not instant, and a process still
    # holding the listener port is indistinguishable, from the next case's
    # point of view, from a NAT that does not work.
    #
    pkill -x quicpunch >/dev/null 2>&1
    local Waited=0
    while pgrep -x quicpunch >/dev/null 2>&1 && [ "$Waited" -lt 150 ]; do
        sleep 0.1
        Waited=$((Waited+1))
    done
    pkill -9 -x quicpunch >/dev/null 2>&1
    wait >/dev/null 2>&1
    RELAY_PID=""; SRV_PID=""
}

dump_logs() {
    [ "$VERBOSE" = "1" ] || return 0
    for Log in relay srv cli; do
        [ -f "$WORK/$Log.log" ] || continue
        note "--- $Log ---"
        sed 's/^/          /' "$WORK/$Log.log"
    done
}

# A ">= 1" assertion on a counter line, and an exact one.
counter_at_least() { # <file> <key> <min> <description>
    local Value
    Value="$(grep -o -- "$2=[0-9]*" "$1" | tail -1 | cut -d= -f2)"
    if [ -n "$Value" ] && [ "$Value" -ge "$3" ]; then
        ok "$4 ($2=$Value)"
    else
        bad "$4"; note "$2=${Value:-missing}, wanted >= $3"
    fi
}

# --------------------------------------------------------------------------
# Cases
# --------------------------------------------------------------------------

#
# The headline: a client behind a NAT reaches a server behind a NAT on a path
# that exists only because the server punched for it.
#
case_direct() {
    say "  direct: endpoint-independent mapping, address-dependent filtering"
    cnat_rules; snat_base eim; snat_addr_dep_filtering
    start_roles 30
    run_client 20
    stop_roles
    dump_logs

    [ "$CLI_RC" = "0" ] && ok "client reported a direct path (exit 0)" \
        || { bad "client reported a direct path"; note "exit=$CLI_RC"; }
    has "$WORK/cli.log" "client_direct_path=1" "a path to something other than the relay validated"
    has "$WORK/cli.log" "client_path_validated_remote=$SNAT_WAN:$PUNCH_PORT" \
        "the validated remote is the server's advertised mapping"
    counter_at_least "$WORK/cli.log" "client_requests_sent" 1 "the client asked for a punch"
    counter_at_least "$WORK/srv.log" "server_punches_sent" 1 "the server answered with a punch"
    has "$WORK/srv.log" "=$CNAT_WAN:" "the server saw traffic from the client's public mapping"
}

#
# The same, with the filtering plain conntrack gives. This case is not a
# should-work that fails: it pins a real limitation, that the reconciler probes
# from a socket whose mapping is not the one the client advertised. Asserted so
# that it is a known property rather than something rediscovered later.
#
case_strict() {
    say "  strict: address-and-port-dependent filtering (documents a limitation)"
    cnat_rules; snat_base eim
    start_roles 30
    run_client 15
    stop_roles
    dump_logs

    [ "$CLI_RC" = "2" ] && ok "traversal did not succeed (exit 2)" \
        || { bad "traversal did not succeed"; note "exit=$CLI_RC"; }
    counter_at_least "$WORK/cli.log" "client_requests_sent" 1 "the client still asked"
    counter_at_least "$WORK/srv.log" "server_final_punches_sent" 1 "the server still answered"
    hasnt "$WORK/cli.log" "client_direct_path=1" "no direct path was claimed"
    has "$WORK/cli.log" "client_connection_alive=1" "the relayed connection survived"
}

#
# Endpoint-dependent mapping, which the draft's prerequisite excludes: the
# address the server advertises is not the one it is seen as towards the
# client, so the punch opens a binding the client's probe cannot name.
# Traversal must fail without stalling the connection.
#
case_edm() {
    say "  edm: endpoint-dependent mapping, where the draft says it should fail"
    cnat_rules; snat_base edm
    start_roles 30
    run_client 15
    stop_roles
    dump_logs

    [ "$CLI_RC" = "2" ] && ok "traversal failed as the draft expects (exit 2)" \
        || { bad "traversal failed as the draft expects"; note "exit=$CLI_RC"; }
    counter_at_least "$WORK/srv.log" "server_final_punches_sent" 1 "the server answered the request"
    hasnt "$WORK/cli.log" "client_direct_path=1" "no direct path"
    has "$WORK/cli.log" "client_connection_alive=1" "the connection fell back to the relay"
}

#
# The punch is never retransmitted (section 6), so losing it costs the attempt
# and the client has to notice by its own validation failing. The DROP rule's
# packet counter is the measurement: it says how many punches actually left,
# which no counter inside either endpoint can.
#
case_droppunch() {
    say "  droppunch: the punch is lost, and is not retransmitted"
    cnat_rules; snat_base eim; snat_addr_dep_filtering
    netns snat iptables -A FORWARD -i lan0 -s "$SRV_PRIV" -p udp \
        --sport "$PUNCH_PORT" -j DROP
    start_roles 30
    run_client 15
    stop_roles
    dump_logs

    local Dropped
    Dropped="$(netns snat iptables -L FORWARD -v -n -x 2>/dev/null \
        | awk '/DROP/ && /udp/ {print $1; exit}')"
    note "punch packets dropped on the wire: ${Dropped:-unknown}"

    [ "$CLI_RC" = "2" ] && ok "validation failed, as it must (exit 2)" \
        || { bad "validation failed, as it must"; note "exit=$CLI_RC"; }
    if [ -n "${Dropped:-}" ] && [ "$Dropped" -ge 1 ]; then
        ok "a punch was sent and lost ($Dropped on the wire)"
    else
        bad "a punch was sent and lost"; note "dropped=${Dropped:-unknown}"
    fi
    has "$WORK/cli.log" "client_connection_alive=1" "the connection survived the failed attempt"
}


# --------------------------------------------------------------------------
# The local-address half of #157, which #161 lists as two items that a
# single-interface host cannot test at all: the cross product of several local
# addresses with the advertised remotes, and a path being recreated once a
# vanished local address comes back. No NAT here -- these are about the
# client's own addresses, so the topology is two namespaces on one wire and the
# mode is AUTO, where the candidate pair table drives paths directly.
# --------------------------------------------------------------------------

MCLI_A=10.3.0.2
MCLI_B=10.3.0.3
MSRV_A=10.3.0.1
MSRV_B=10.3.0.4
MSRV_PORT=4577
MSRV_PUNCH=4610

multi_down() {
    for Ns in mcli msrv; do ip netns delete "$Ns" >/dev/null 2>&1; done
}

multi_up() {
    multi_down
    ip netns add mcli || return 1
    ip netns add msrv || return 1
    ip -n mcli link set lo up || return 1
    ip -n msrv link set lo up || return 1

    link mcli mc0 msrv ms0 || return 1

    ip -n mcli addr add "$MCLI_A/24" dev mc0 || return 1
    ip -n mcli addr add "$MCLI_B/24" dev mc0 || return 1
    ip -n mcli link set mc0 up || return 1

    ip -n msrv addr add "$MSRV_A/24" dev ms0 || return 1
    ip -n msrv addr add "$MSRV_B/24" dev ms0 || return 1
    ip -n msrv link set ms0 up || return 1
    return 0
}

multi_start_server() { # <seconds>
    punch msrv -role:server \
        "-listen:$MSRV_A:$MSRV_PORT" \
        "-cert:$WORK/cert.pem" "-key:$WORK/key.pem" \
        "-advertise:$MSRV_B:$MSRV_PUNCH=$MSRV_B:$MSRV_PUNCH" \
        -multipath:1 "-time:$1" \
        > "$WORK/srv.log" 2>&1 &
    SRV_PID=$!

    local Waited=0
    while [ "$Waited" -lt 100 ]; do
        grep -q "server_ready=1" "$WORK/srv.log" 2>/dev/null && return 0
        sleep 0.1
        Waited=$((Waited+1))
    done
    note "server did not become ready"
    return 1
}

# The highest-numbered poll report in a client log, or empty if there is none.
poll_index() {
    grep -o 'client_poll[0-9]*_path_count' "$1" 2>/dev/null \
        | tail -1 | grep -o '[0-9][0-9]*' | head -1
}

# Waits for <n> further poll reports, so the assertions do not race the client.
wait_polls() { # <file> <n>
    local Start Now Target W
    Start="$(poll_index "$1")"; Start="${Start:-0}"
    Target=$((Start + $2))
    W=0
    while [ "$W" -lt 400 ]; do
        Now="$(poll_index "$1")"; Now="${Now:-0}"
        [ "$Now" -ge "$Target" ] && return 0
        sleep 0.2
        W=$((W+1))
    done
    return 1
}


# Everything logged from a given poll report onwards, so an assertion can be
# scoped to "after the address came back" without a marker line -- markers
# written into the client's own redirect get clobbered by its buffering.
after_poll() { # <file> <index>
    awk -v Pat="client_poll$2_path_count" 'index($0, Pat) { Seen = 1 } Seen' "$1"
}

# The paths reported by the most recent poll.
last_poll_paths() { # <file>
    local Index
    Index="$(poll_index "$1")"
    [ -n "$Index" ] || return 1
    grep -o "client_poll${Index}_path[0-9]*=[^ ]*" "$1"
}

case_multiaddr_cross() {
    say "  multiaddr-cross: several local addresses crossed with the advertised remotes"
    multi_up || { bad "could not build the multi-address topology"; return; }
    multi_start_server 40 || { bad "server did not start"; stop_roles; return; }

    punch mcli -role:client \
        "-target:$MSRV_A:$MSRV_PORT" -mode:auto -multipath:1 -time:16 -poll:2 \
        > "$WORK/cli.log" 2>&1
    CLI_RC=$?
    stop_roles
    dump_logs

    local Paths
    Paths="$(grep -o "client_final_path[0-9]*=[^ ]*" "$WORK/cli.log")"
    note "final paths:"
    printf '%s\n' "$Paths" | sed 's/^/            /'

    if printf '%s' "$Paths" | grep -q "=$MCLI_A:"; then
        ok "a path on the first local address"
    else
        bad "a path on the first local address"
    fi
    if printf '%s' "$Paths" | grep -q "=$MCLI_B:"; then
        ok "a path on the second local address"
    else
        bad "a path on the second local address"
    fi
    if printf '%s' "$Paths" | grep -q "\->$MSRV_B:"; then
        ok "a path to the advertised remote"
    else
        bad "a path to the advertised remote"
    fi
    counter_at_least "$WORK/cli.log" "client_final_path_count" 3 \
        "the table produced more than one pair"
    multi_down
}

case_multiaddr_return() {
    say "  multiaddr-return: a path is recreated when a vanished local address returns"
    multi_up || { bad "could not build the multi-address topology"; return; }
    multi_start_server 70 || { bad "server did not start"; stop_roles; return; }

    punch mcli -role:client \
        "-target:$MSRV_A:$MSRV_PORT" -mode:auto -multipath:1 -time:48 -poll:2 \
        > "$WORK/cli.log" 2>&1 &
    local ClientJob=$!

    wait_polls "$WORK/cli.log" 3
    if last_poll_paths "$WORK/cli.log" | grep -q "=$MCLI_B:"; then
        ok "the second local address carries a path to begin with"
    else
        bad "the second local address carries a path to begin with"
        note "$(last_poll_paths "$WORK/cli.log" | tr '\n' ' ')"
    fi

    ip -n mcli addr del "$MCLI_B/24" dev mc0 >/dev/null 2>&1
    note "removed $MCLI_B"
    wait_polls "$WORK/cli.log" 3
    if last_poll_paths "$WORK/cli.log" | grep -q "=$MCLI_B:"; then
        bad "the path went away with the address"
        note "$(last_poll_paths "$WORK/cli.log" | tr '\n' ' ')"
    else
        ok "the path went away with the address"
    fi

    #
    # The poll index the restore happens after, so the two assertions below can
    # be scoped to what followed it. Scoped rather than sampled, because a
    # recreated path that is later torn down would be invisible to a single
    # reading taken at the wrong moment -- which is exactly what happens here.
    #
    local Marker
    Marker="$(poll_index "$WORK/cli.log")"
    ip -n mcli addr add "$MCLI_B/24" dev mc0 >/dev/null 2>&1
    note "restored $MCLI_B"
    wait_polls "$WORK/cli.log" 6

    if after_poll "$WORK/cli.log" "$Marker" | grep -q "_path[0-9]*=$MCLI_B:"; then
        ok "a path on the address was recreated"
    else
        bad "a path on the address was recreated"
        note "no path on $MCLI_B in any poll after the restore"
    fi

    #
    # And it has to become usable, which is the half #161 actually asks for. As
    # of this harness it does not: the reconciler opens the path and arms its
    # challenge, the peer issues the connection IDs for the new path id, and
    # the PATH_CHALLENGEs never arrive -- the peer's receive log has no record
    # of them -- so validation times out and both ends abandon the path id.
    # Plain traffic from the restored address works immediately, so the
    # environment is not what loses them. Left asserted and failing, because a
    # harness that reported this green would be worse than no harness.
    #
    if after_poll "$WORK/cli.log" "$Marker" | grep -q "client_path_validated_local=$MCLI_B:"; then
        ok "the recreated path validated"
    else
        bad "the recreated path validated"
        note "recreated but never validated -- see docs/nat-punch-testing.md"
    fi

    wait "$ClientJob" >/dev/null 2>&1
    stop_roles
    dump_logs
    has "$WORK/cli.log" "client_connection_alive=1" "the connection survived the churn"
    multi_down
}

# --------------------------------------------------------------------------

run_one() { # <name>
    case "$1" in
        direct)    case_direct ;;
        strict)    case_strict ;;
        edm)       case_edm ;;
        droppunch) case_droppunch ;;
        multiaddr-cross)  case_multiaddr_cross ;;
        multiaddr-return) case_multiaddr_return ;;
        *) echo "unknown case: $1" >&2; return 1 ;;
    esac
}

make_cert || { echo "nat-punch-test: could not make a certificate" >&2; exit 1; }
topo_up || { echo "nat-punch-test: could not build the topology" >&2; topo_down; exit 1; }
say "nat-punch-test: topology up, using $BIN"

if [ -n "$ONLY" ]; then
    run_one "$ONLY"
else
    for Case in direct strict edm droppunch multiaddr-cross multiaddr-return; do
        run_one "$Case"
    done
fi

#
# The namespaces live inside this process's own network namespace, so they
# cannot outlive it -- which is why --keep hands over a shell rather than
# leaving something behind. `ip netns exec cli ...` and friends work in it.
#
if [ "$KEEP" = "1" ]; then
    if [ -t 0 ]; then
        say ""
        say "nat-punch-test: --keep, dropping into a shell inside the topology."
        say "  try: ip netns exec cli ip addr; ip netns exec snat iptables -t nat -L -n -v"
        say "  exit the shell to tear it down."
        "${SHELL:-/bin/sh}" || true
    else
        say "nat-punch-test: --keep needs a terminal; nothing to hand over"
    fi
fi
topo_down

say ""
say "nat-punch-test: $PASSED passed, $FAILED failed"
exit "$FAILED"
