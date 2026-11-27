#!/usr/bin/env bash
# ride.sh: run gated as a local daemon against real package managers, and
# check what it does. This is the test that counts: unit tests and CI passed
# on releases that hung every piped install and denied every Go module once
# gated ran as a service.
#
#   scripts/ride.sh [RUNS]      (or: make ride RUNS=3)
#
# Each run builds gated from this checkout and starts it as a transient
# systemd user unit: the environment the user service gets (no shell PATH,
# no go toolchain), not the one of the shell running this script. It watches
# fresh, per-run caches, so every package is really downloaded and gated, run
# after run, and nothing touches your real caches or your other processes.
# Package managers run with their output piped (what a CI log, `| tee` or an
# IDE does) under a timeout, so a hang is a failure, not a stall.
#
# Needs: systemd --user, curl, jq, syft and grype; uv, go, npm and cargo are
# each optional (their checks are skipped without them). Network access.
# Each run's files stay in $RIDE_DIR (default: a new temp dir) for a look.
set -uo pipefail

RUNS="${1:-1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RIDE_DIR="${RIDE_DIR:-$(mktemp -d -t gated-ride-XXXXXX)}"
SYFT="${SYFT:-$(command -v syft || echo "$HOME/.local/bin/syft")}"
GRYPE="${GRYPE:-$(command -v grype || echo "$HOME/.local/bin/grype")}"
TIMEOUT=120 # a command that takes longer than this counts as hung

for t in systemd-run journalctl curl jq "$SYFT" "$GRYPE"; do
	command -v "$t" >/dev/null || { echo "ride: missing $t" >&2; exit 2; }
done
have() { command -v "$1" >/dev/null; }

failures=0
results=()

check() { # check NAME OK DETAIL
	local status=PASS
	if [ "$2" != 1 ]; then status=FAIL; failures=$((failures + 1)); fi
	results+=("$(printf '%-4s  %-58s %s' "$status" "$1" "$3")")
}

# run LABEL CMD...: piped, timed; sets RC, SECS, WARNED (gated: lines), OUT.
run() {
	local label=$1; shift
	local start; start=$(date +%s.%N)
	OUT="$RUN_DIR/out/$(printf '%s' "$label" | tr -c 'a-zA-Z0-9.=@-' _).log"
	timeout "$TIMEOUT" "$@" 2>&1 | cat > "$OUT"
	RC=${PIPESTATUS[0]}
	SECS=$(printf '%.1f' "$(echo "$(date +%s.%N) - $start" | bc)")
	WARNED=$(grep -c '^gated: ' "$OUT")
}

journal() { journalctl --user -u "$UNIT" -o cat --no-pager | grep '^{'; }

# verdict PKG VERSION: ALLOWED, DENIED or "none" from the daemon's log.
verdict() {
	local v
	v=$(journal | jq -r --arg p "$1" --arg v "$2" \
		'select((.msg=="ALLOWED" or .msg=="DENIED") and .pkg==$p and .version==$v) | .msg' | tail -1)
	echo "${v:-none}"
}

# wait_verdict PKG VERSION [SECONDS]: wait for one, then echo it.
wait_verdict() {
	local i v
	for ((i = 0; i < ${3:-60} * 2; i++)); do
		v=$(verdict "$1" "$2")
		[ "$v" != none ] && { echo "$v"; return; }
		sleep 0.5
	done
	echo none
}

le() { [ "$(echo "$1 <= $2" | bc)" = 1 ] && echo 1 || echo 0; }

# denied_piped LABEL PKG VERSION MAXSECS CMD...: the install must end within
# MAXSECS (no hang), be denied, and carry gated's warning in its own output.
denied_piped() {
	local label=$1 pkg=$2 ver=$3 max=$4; shift 4
	run "$label" "$@"
	local v; v=$(wait_verdict "$pkg" "$ver")
	check "$label: denied" "$([ "$v" = DENIED ] && echo 1 || echo 0)" "verdict=$v"
	check "$label: warning in its output" "$([ "$WARNED" -gt 0 ] && echo 1 || echo 0)" "$WARNED gated: lines"
	check "$label: no hang (<= ${max}s)" "$(le "$SECS" "$max")" "${SECS}s rc=$RC"
}

# allowed_piped LABEL PKG VERSION MAXSECS CMD...
allowed_piped() {
	local label=$1 pkg=$2 ver=$3 max=$4; shift 4
	run "$label" "$@"
	local v; v=$(wait_verdict "$pkg" "$ver")
	check "$label: allowed" "$([ "$v" = ALLOWED ] && echo 1 || echo 0)" "verdict=$v"
	check "$label: no warning" "$([ "$WARNED" = 0 ] && echo 1 || echo 0)" "$WARNED gated: lines"
	check "$label: no hang (<= ${max}s)" "$(le "$SECS" "$max")" "${SECS}s rc=$RC"
}

one_run() {
	local n=$1
	RUN_DIR="$RIDE_DIR/run$n"
	UNIT="gated-ride-$$-$n"
	mkdir -p "$RUN_DIR"/{out,uv,gomod,m2/repository,buildrepo,npm,cargo,verdicts,work}
	results=()
	local failures_before=$failures

	(cd "$ROOT" && go build -trimpath -ldflags "-X main.version=ride-$(git rev-parse --short HEAD)" \
		-o "$RUN_DIR/gated" ./cmd/gated) || { echo "ride: build failed" >&2; exit 2; }
	cat > "$RUN_DIR/config.yaml" <<EOF
watch_paths:
  - {path: $RUN_DIR/uv,     ecosystem: pypi}
  - {path: $RUN_DIR/gomod,  ecosystem: go}
  - {path: $RUN_DIR/m2/repository, ecosystem: maven}
  - {path: $RUN_DIR/buildrepo, ecosystem: maven}  # -Dmaven.repo.local=...: no "repository/" in the path
  - {path: $RUN_DIR/npm,    ecosystem: npm}
  - {path: $RUN_DIR/cargo,  ecosystem: cargo}
tools: {syft: $SYFT, grype: $GRYPE}
policy_dir: $ROOT/policy
verdict_dir: $RUN_DIR/verdicts
watcher_mode: quarantine
warn_only: false
scan_timeout_seconds: 120
log_level: info
EOF
	systemd-run --user --quiet --collect --unit="$UNIT" "$RUN_DIR/gated" -config "$RUN_DIR/config.yaml" \
		|| { echo "ride: could not start $UNIT" >&2; exit 2; }
	trap 'systemctl --user stop "$UNIT" 2>/dev/null' EXIT
	local i
	for ((i = 0; i < 60; i++)); do journal | grep -q 'event loop started' && break; sleep 0.5; done
	local pid; pid=$(systemctl --user show -p MainPID --value "$UNIT")
	local fds_start; fds_start=$(ls "/proc/$pid/fd" | wc -l)
	check "daemon started under systemd" "$([ "$pid" -gt 0 ] && echo 1 || echo 0)" "unit $UNIT pid $pid"
	local env_path; env_path=$(tr '\0' '\n' < "/proc/$pid/environ" | sed -n 's/^PATH=//p')
	results+=("info  daemon PATH has go: $(PATH="$env_path" command -v go >/dev/null && echo yes || echo 'no (as the service)')")

	cd "$RUN_DIR/work" || exit 2

	if have uv; then
		export UV_NO_CONFIG=1
		local uvi=(uv pip install --python python3 --cache-dir "$RUN_DIR/uv")
		denied_piped "uv urllib3 1.26.4" urllib3 1.26.4 30 "${uvi[@]}" --target t1 'urllib3==1.26.4'
		allowed_piped "uv six 1.17.0" six 1.17.0 20 "${uvi[@]}" --target t2 'six==1.17.0'
		denied_piped "uv urllib3 1.26.4, again" urllib3 1.26.4 30 "${uvi[@]}" --target t3 'urllib3==1.26.4'
		# A busy install in the same cache must not hold up a small one.
		( run "uv busy: twine boto3 keyring" "${uvi[@]}" --target t4 twine boto3 keyring
		  echo "$SECS $RC" > "$RUN_DIR/busy.res" ) &
		sleep 1
		denied_piped "uv jinja2 2.10, next to a busy install" jinja2 2.10 45 "${uvi[@]}" --target t5 'jinja2==2.10'
		wait
		read -r bsecs brc < "$RUN_DIR/busy.res"
		check "uv busy install (~40 packages): no hang (<= 120s)" "$(le "$bsecs" 120)" "${bsecs}s rc=$brc"
		check "uv busy install: requests-toolbelt allowed (Apache 2.0 text)" \
			"$([ "$(wait_verdict requests-toolbelt 1.0.0 5)" = ALLOWED ] && echo 1 || echo 0)" "verdict=$(verdict requests-toolbelt 1.0.0)"
	else
		results+=("skip  uv not installed")
	fi

	if have go; then
		export GOMODCACHE="$RUN_DIR/gomod" GOFLAGS=-modcacherw GOTOOLCHAIN=local
		denied_piped "go x/text v0.3.5" golang.org/x/text v0.3.5 30 go mod download golang.org/x/text@v0.3.5
		check "go x/text v0.3.5: removed from the cache" \
			"$([ ! -e "$GOMODCACHE/cache/download/golang.org/x/text/@v/v0.3.5.zip" ] && echo 1 || echo 0)" ""
		allowed_piped "go uuid v1.4.0 (license from LICENSE)" github.com/google/uuid v1.4.0 20 go mod download github.com/google/uuid@v1.4.0
		allowed_piped "go cobra v1.7.0 (has dependencies)" github.com/spf13/cobra v1.7.0 20 go mod download github.com/spf13/cobra@v1.7.0
		check "go: syft downloaded nothing into the watched cache" \
			"$([ ! -d "$GOMODCACHE/cache/download/github.com/spf13/pflag" ] || [ -n "$(journal | jq -r 'select(.pkg=="github.com/spf13/pflag")' | head -1)" ] && echo 1 || echo 0)" ""
		mkdir -p gp && printf 'module ride\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.6\n' > gp/go.mod \
			&& printf 'package main\n\nimport _ "golang.org/x/text/language"\n\nfunc main() {}\n' > gp/main.go
		denied_piped "go build with x/text v0.3.6" golang.org/x/text v0.3.6 30 sh -c 'cd gp && go build -mod=mod -o /dev/null .'
		run "go build retry" sh -c 'cd gp && go build -mod=mod -o /dev/null .'
		check "go build retry: blocked" "$([ "$RC" != 0 ] && [ "$RC" != 124 ] && echo 1 || echo 0)" "rc=$RC ${SECS}s"
		unset GOMODCACHE GOFLAGS GOTOOLCHAIN
	else
		results+=("skip  go not installed")
	fi

	# Maven: jars as a build tool writes them, from Maven Central (checked),
	# into ~/.m2/repository's layout and into a local repository elsewhere.
	local mvn=https://repo1.maven.org/maven2 gav
	for gav in m2/repository:org.apache.logging.log4j:log4j-core:2.14.1:DENIED \
		m2/repository:org.apache.commons:commons-text:1.12.0:ALLOWED \
		buildrepo:org.apache.logging.log4j:log4j-core:2.14.1:DENIED; do
		IFS=: read -r repo g a v want <<<"$gav"
		local rel="${g//.//}/$a/$v/$a-$v.jar" tmp="$RUN_DIR/work/$a-$v.jar" label="maven $a $v ($repo)"
		curl -sSfL "$mvn/$rel" -o "$tmp" && [ "$(sha1sum < "$tmp" | cut -c1-40)" = "$(curl -sSfL "$mvn/$rel.sha1" | cut -c1-40)" ] \
			|| { check "$label: fetched" 0 "download or checksum failed"; continue; }
		local before; before=$(journal | wc -l)
		mkdir -p "$RUN_DIR/$repo/$(dirname "$rel")" && mv "$tmp" "$RUN_DIR/$repo/$rel"
		local got=none
		for ((i = 0; i < 120; i++)); do
			got=$(journal | tail -n +"$((before + 1))" | jq -r --arg p "$g:$a" --arg v "$v" \
				'select((.msg=="ALLOWED" or .msg=="DENIED") and .pkg==$p and .version==$v) | .msg' | tail -1)
			[ -n "$got" ] && break
			got=none; sleep 0.5
		done
		check "$label: $(echo "$want" | tr '[:upper:]' '[:lower:]')" "$([ "$got" = "$want" ] && echo 1 || echo 0)" "verdict=$got"
		sleep 0.5
		local there; there=$([ -e "$RUN_DIR/$repo/$rel" ] && echo present || echo gone)
		check "$label: jar $([ "$want" = ALLOWED ] && echo present || echo gone)" \
			"$({ [ "$want" = ALLOWED ] && [ "$there" = present ]; } || { [ "$want" = DENIED ] && [ "$there" = gone ]; } && echo 1 || echo 0)" "$there"
	done
	check "maven: nothing allowed unscanned" \
		"$([ -z "$(journal | jq -r 'select(.msg=="unresolvable artifact, allowing")')" ] && echo 1 || echo 0)" ""

	if have npm; then
		run "npm pack" npm pack --silent --cache "$RUN_DIR/work/npm-cache" --pack-destination "$RUN_DIR/npm" lodash@4.17.20 express@4.21.2
		local l e; l=$(wait_verdict lodash 4.17.20); e=$(wait_verdict express 4.21.2)
		check "npm lodash 4.17.20: denied" "$([ "$l" = DENIED ] && echo 1 || echo 0)" "verdict=$l"
		check "npm express 4.21.2: allowed (license from package.json)" "$([ "$e" = ALLOWED ] && echo 1 || echo 0)" "verdict=$e"
	else
		results+=("skip  npm not installed")
	fi

	if have cargo; then
		mkdir -p cp/src && echo 'fn main() {}' > cp/src/main.rs && printf '[package]\nname = "ride"\nversion = "0.1.0"\nedition = "2021"\n[dependencies]\nsmallvec = "=1.6.0"\nserde = { version = "=1.0.200", features = ["derive"] }\n' > cp/Cargo.toml
		run "cargo fetch" sh -c "cd cp && CARGO_HOME='$RUN_DIR/cargo' cargo fetch"
		local sv se ui; sv=$(wait_verdict smallvec 1.6.0); se=$(wait_verdict serde 1.0.200)
		ui=$(journal | jq -r 'select((.msg=="ALLOWED" or .msg=="DENIED") and .pkg=="unicode-ident") | .msg' | tail -1)
		check "cargo smallvec 1.6.0: denied" "$([ "$sv" = DENIED ] && echo 1 || echo 0)" "verdict=$sv"
		check "cargo serde 1.0.200: allowed (license from Cargo.toml)" "$([ "$se" = ALLOWED ] && echo 1 || echo 0)" "verdict=$se"
		check "cargo unicode-ident: allowed (Unicode-3.0)" "$([ "$ui" = ALLOWED ] && echo 1 || echo 0)" "verdict=${ui:-none}"
	else
		results+=("skip  cargo not installed")
	fi

	sleep 2 # let the daemon release what it holds
	local fds_end; fds_end=$(ls "/proc/$pid/fd" | wc -l)
	check "no file descriptors leaked" "$([ "$fds_end" -le $((fds_start + 2)) ] && echo 1 || echo 0)" "$fds_start at start, $fds_end at end"
	local errors; errors=$(journal | jq -r 'select(.level=="ERROR") | .msg' | sort | uniq -c | tr '\n' ';')
	check "no errors in the daemon's log" "$([ -z "$errors" ] && echo 1 || echo 0)" "$errors"
	check "daemon still running" "$(systemctl --user is-active --quiet "$UNIT" && echo 1 || echo 0)" ""

	journal > "$RUN_DIR/gated.log"
	systemctl --user stop "$UNIT" 2>/dev/null
	trap - EXIT
	cd "$ROOT" || exit 2

	echo "=== run $n of $RUNS ($((failures - failures_before)) failed) — files in $RUN_DIR"
	printf '%s\n' "${results[@]}"
	echo
}

for ((r = 1; r <= RUNS; r++)); do one_run "$r"; done
echo "ride: $RUNS run(s), $failures check(s) failed"
[ "$failures" = 0 ]
