#!/bin/sh
#
# Builds the harnesses, starts the demo host, drives every gated harness against it and prints one
# verdict. The POSIX counterpart to run-tests.ps1.
#
# Both exist for the same reason the sibling repositories keep autobahn.ps1 next to autobahn.sh: the
# development machine is Windows, and the Debian container that CI's second leg runs in has no pwsh.
# Each is exercised by the leg it belongs to, so neither can rot unnoticed - but they ARE two
# implementations of one thing, so a change to either belongs in both.
#
# Usage:
#   tests/run-tests.sh [-n|--no-build] [--filter <substr>] [--port <n>]
#
# Exit codes: 0 all harnesses passed (or skipped), 1 at least one failed.

set -u

NO_BUILD=0
FILTER=""
PORT=4433

while [ $# -gt 0 ]; do
    case "$1" in
        -n|--no-build) NO_BUILD=1; shift ;;
        --filter)      FILTER="${2:-}"; shift 2 ;;
        --port)        PORT="${2:-4433}"; shift 2 ;;
        -h|--help)     sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)             echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$REPO_ROOT" || exit 1

# Every gated harness. Adding one means adding a line here and nothing else.
HARNESSES="h3semantics h3attack"

if [ -n "$FILTER" ]; then
    MATCHED=""
    for h in $HARNESSES; do
        case "$h" in *"$FILTER"*) MATCHED="$MATCHED $h" ;; esac
    done
    HARNESSES="$MATCHED"
    if [ -z "$(echo "$HARNESSES" | tr -d ' ')" ]; then
        echo "No harness matches --filter '$FILTER'."
        exit 1
    fi
fi

if [ "$NO_BUILD" -eq 0 ]; then
    echo "=== Building ==="
    # Captured, not streamed: building the demo host drags in the whole Hermod submodule, whose ~360
    # pre-existing warnings would bury the harness output that follows. Printed in full on a failure,
    # which is the only time anyone wants to read it.
    for project in "samples/H3Server/H3Server.csproj" $(for h in $HARNESSES; do echo "tests/$h/$h.csproj"; done); do
        if ! BUILD_LOG=$(dotnet build "$project" --configuration Release --nologo --verbosity quiet 2>&1); then
            echo "Build failed: $project" >&2
            echo "$BUILD_LOG" >&2
            exit 1
        fi
    done
    echo
fi

SERVER_LOG=$(mktemp "${TMPDIR:-/tmp}/h3server-run-tests.XXXXXX")
echo "=== Starting the demo host on UDP/$PORT ==="
dotnet run --project samples/H3Server --configuration Release --no-build -- "$PORT" > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

cleanup() {
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
}
trap cleanup EXIT INT TERM

# Wait for the line the server prints once its socket is bound, rather than sleeping a guessed number
# of seconds: too short on a cold machine, wasted on a warm one.
READY=0
i=0
while [ "$i" -lt 60 ]; do
    sleep 0.5
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
    if grep -q "Listening on" "$SERVER_LOG" 2>/dev/null; then READY=1; break; fi
    i=$((i + 1))
done

if [ "$READY" -eq 0 ]; then
    echo "The demo host did not come up." >&2
    tail -20 "$SERVER_LOG" >&2
    exit 1
fi
echo "  up after $(echo "$i" | awk '{printf "%.1f", $1 * 0.5}')s"
echo

CHECKS_PASSED=0
CHECKS_TOTAL=0
FAILED=""
SUMMARY=""

for harness in $HARNESSES; do
    echo "=== $harness ==="
    EXE="tests/$harness/bin/Release/net10.0/$harness"
    [ -x "$EXE" ] || EXE="$EXE.exe"

    OUTPUT=$(H3_PORT="$PORT" "$EXE" 2>&1)
    CODE=$?
    echo "$OUTPUT"

    VERDICT=$(echo "$OUTPUT" | grep -oE '[0-9]+/[0-9]+ checks passed' | tail -1)
    PASSED=$(echo "$VERDICT" | cut -d/ -f1)
    TOTAL=$(echo "$VERDICT" | cut -d/ -f2 | cut -d' ' -f1)
    : "${PASSED:=0}"
    : "${TOTAL:=0}"
    CHECKS_PASSED=$((CHECKS_PASSED + PASSED))
    CHECKS_TOTAL=$((CHECKS_TOTAL + TOTAL))

    # Exit code 2 means the harness could not run at all - on Debian h3semantics finds no libmsquic
    # and says so. That is a SKIP, not a pass: reporting it as green 0/0 would hide a whole harness.
    if [ "$CODE" -eq 2 ]; then
        LABEL="SKIP"
    elif [ "$CODE" -eq 0 ]; then
        LABEL="PASS"
    else
        LABEL="FAIL"
        FAILED="$FAILED $harness"
    fi
    SUMMARY="$SUMMARY$(printf '  %-14s %s  %s/%s checks' "$harness" "$LABEL" "$PASSED" "$TOTAL")\n"
    echo
done

echo "=== Summary ==="
printf "%b" "$SUMMARY"
echo

if [ -z "$(echo "$FAILED" | tr -d ' ')" ]; then
    echo "  $CHECKS_PASSED/$CHECKS_TOTAL checks passed across $(echo "$HARNESSES" | wc -w | tr -d ' ') harnesses."
    exit 0
fi

echo "  $CHECKS_PASSED/$CHECKS_TOTAL checks passed - failed:$FAILED"
echo "  Demo host log: $SERVER_LOG"
exit 1
