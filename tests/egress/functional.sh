#!/usr/bin/env bash
# Functional test of host/sbx-egress-guard against the real kernel netfilter
# and real cgroup v2 membership. Runs as root inside a disposable privileged
# container that has its own network namespace (so nothing here touches the
# machine's real firewall) and the host cgroup namespace (so cgroup paths are
# real). Driven by tests/host/test_egress_functional.py.
#
#   functional.sh <path to sbx-egress-guard>
#
# Every assertion prints "ok" or "FAIL"; the script exits non-zero on any FAIL.
set -uo pipefail

guard=${1:?guard path}
fails=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fails=$((fails + 1)); }

prefix="/srfw-$$-$RANDOM"
unit_rel="user.slice/user-1000.slice/user@1000.service/study-room.slice/study-room-sbx.service"
root="/sys/fs/cgroup$prefix"
unit="$root/$unit_rel"
tailscaled="$root/system.slice/tailscaled.service"
hub="$root/system.slice/docker-magic-conch-hub.scope"
userapp="$root/$(dirname "$(dirname "$unit_rel")")/app.slice/user-app.service"
mkdir -p "$unit" "$tailscaled" "$hub" "$userapp"

cleanup() {
  pkill -f srfw-server >/dev/null 2>&1 || true
  for d in "$unit" "$tailscaled" "$hub" "$userapp"; do
    while read -r p; do echo "$p" > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true; done < "$d/cgroup.procs" 2>/dev/null
  done
  find "$root" -depth -type d -exec rmdir {} \; 2>/dev/null || true
}
trap cleanup EXIT

# Destinations: one address in each guarded range, Tailscale-style IPv4/IPv6
# addresses, and stand-ins for the public internet (documentation ranges,
# which the guard does not cover).
ip link add srfw type dummy && ip link set srfw up
for a in 10.213.0.1 172.20.0.1 192.168.213.1 169.254.213.1 100.100.213.1 198.51.100.7; do ip addr add "$a/32" dev srfw; done
for a in fd7a:115c:a1e0::1 fe80::213 2001:db8::7; do ip -6 addr add "$a/128" dev srfw nodad; done

cat > /tmp/srfw-server.py <<'EOF'
import http.server, socket, sys, threading
class S(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
for port in (8080, 53):
    threading.Thread(target=S(("::", port), H).serve_forever, daemon=True).start()
threading.Event().wait()
EOF
(exec -a srfw-server python3 /tmp/srfw-server.py &) ; sleep 1

# in_cgroup DIR CMD...: run CMD as a process of that cgroup.
in_cgroup() { local dir=$1; shift; bash -c 'echo $$ > "$0/cgroup.procs" && exec "$@"' "$dir" "$@"; }
# code DIR URL: HTTP status, or "x<curl exit>" when the connection fails.
code() {
  local out rc
  out=$(in_cgroup "$1" curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 3 -m 5 "$2" 2>/dev/null); rc=$?
  [ "$rc" -eq 0 ] && echo "$out" || echo "x$rc"
}
expect_blocked() { local c; c=$(code "$1" "$2"); case $c in x7) ok "blocked fast: $3 ($2)" ;; *) bad "expected a rejected connection for $3 ($2), got $c" ;; esac; }
expect_open() { local c; c=$(code "$1" "$2"); [ "$c" = 200 ] && ok "open: $3 ($2)" || bad "expected 200 for $3 ($2), got $c"; }
load() { in_cgroup "$1" env STUDY_ROOM_GUARD_CGROUP_PREFIX="$prefix" SUDO_UID=1000 "$guard" "${2:-load}"; }

PRIVATE=(
  "http://10.213.0.1:8080/ 10.0.0.0/8"
  "http://172.20.0.1:8080/ 172.16.0.0/12"
  "http://192.168.213.1:8080/ 192.168.0.0/16"
  "http://169.254.213.1:8080/ 169.254.0.0/16 (link-local, metadata)"
  "http://100.100.213.1:8080/ 100.64.0.0/10 (CGNAT, Tailscale)"
  "http://[fd7a:115c:a1e0::1]:8080/ fc00::/7 (ULA, Tailscale IPv6)"
  "http://[fe80::213%25srfw]:8080/ fe80::/10 (IPv6 link-local)"
)
PUBLIC=("http://198.51.100.7:8080/ public stand-in (IPv4)" "http://[2001:db8::7]:8080/ public stand-in (IPv6)")
LOOPBACK=("http://127.0.0.1:8080/ loopback (DNS stub, approved host services)" "http://[::1]:8080/ IPv6 loopback")

echo "# 1. without the guard the daemon cgroup reaches private addresses (control)"
expect_open "$unit" "http://10.213.0.1:8080/" "daemon before load"

echo "# 2. the guard refuses to run outside the managed unit"
if load "$userapp" >/dev/null 2>&1; then bad "guard loaded from a non-unit cgroup"; else ok "refused outside the unit"; fi
iptables -S STUDY-ROOM-SBX >/dev/null 2>&1 && bad "a refused load left rules behind" || ok "no rules after the refusal"

echo "# 3. loaded from the unit"
load "$unit" && ok "guard loaded" || bad "guard load failed"
for e in "${PRIVATE[@]}"; do expect_blocked "$unit" "${e%% *}" "daemon -> ${e#* }"; done
for e in "${PUBLIC[@]}" "${LOOPBACK[@]}"; do expect_open "$unit" "${e%% *}" "daemon -> ${e#* }"; done
expect_open "$unit" "http://10.213.0.1:53/" "daemon -> private resolver port 53 (WSL2 resolv.conf points at a private address)"

echo "# 4. other processes are untouched: Tailscale, the Magic Conch hub, ordinary host traffic"
for who in "$tailscaled:tailscaled" "$hub:magic-conch hub" "$userapp:user app"; do
  for e in "${PRIVATE[@]}" "${PUBLIC[@]}"; do expect_open "${who%%:*}" "${e%% *}" "${who#*:} -> ${e#* }"; done
done

counters=$(load "$unit" status 2>/dev/null | grep -Eo 'rejected=[0-9]+' | head -1)
[ -n "$counters" ] && [ "${counters#rejected=}" -gt 0 ] && ok "status reports rejected connections ($counters)" || bad "status counters missing: $counters"

echo "# 5. idempotent reload, one jump per family, status recorded"
load "$unit" >/dev/null && load "$unit" >/dev/null
n4=$(iptables -S OUTPUT | grep -c -- '-j STUDY-ROOM-SBX'); n6=$(ip6tables -S OUTPUT | grep -c -- '-j STUDY-ROOM-SBX')
[ "$n4" = 1 ] && [ "$n6" = 1 ] && ok "one jump rule per family after repeated loads" || bad "jump rules: ipv4=$n4 ipv6=$n6"
iptables -S OUTPUT | grep -- '-j STUDY-ROOM-SBX' | grep -qF -- "${prefix#/}/$unit_rel" && ok "the jump matches the unit's cgroup path" || bad "jump does not reference the unit cgroup: $(iptables -S OUTPUT | grep STUDY)"
status=/run/study-room/sbx-egress.json
if [ -f "$status" ] && grep -q "\"cgroup_inode\": $(stat -c %i "$unit")" "$status"; then ok "status file records the unit cgroup inode"; else bad "status file missing or wrong: $(cat "$status" 2>/dev/null)"; fi

echo "# 6. a restarted daemon gets a new cgroup; the guard must be reloaded (ExecStartPre does this)"
rmdir "$unit" && mkdir "$unit"
expect_open "$unit" "http://10.213.0.1:8080/" "new daemon cgroup before reload (why the unit reloads at every start)"
load "$unit" >/dev/null && ok "reloaded"
expect_blocked "$unit" "http://10.213.0.1:8080/" "new daemon cgroup after reload"

echo "# 7. unload removes everything"
load "$unit" unload && ok "unloaded" || bad "unload failed"
iptables -S STUDY-ROOM-SBX >/dev/null 2>&1 && bad "IPv4 chain still present" || ok "IPv4 chain removed"
ip6tables -S STUDY-ROOM-SBX >/dev/null 2>&1 && bad "IPv6 chain still present" || ok "IPv6 chain removed"
[ -f "$status" ] && bad "status file still present" || ok "status file removed"
expect_open "$unit" "http://10.213.0.1:8080/" "daemon after unload"

echo "# result: $fails failure(s)"
[ "$fails" -eq 0 ]
