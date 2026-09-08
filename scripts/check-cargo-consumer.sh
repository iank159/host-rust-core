#!/usr/bin/env bash
# Assert that an external Cargo consumer taking this repository as an exact git
# dependency does not initialize any host submodule.
#
# Cargo recursively initializes a git dependency's submodules. `hosts/*` are host
# applications, not part of the Rust crate graph, and at least one is a private
# repository, so a consumer without organization credentials cannot resolve the
# crates unless Cargo skips those gitlinks. `.gitmodules` marks them
# `update = none`, which Cargo honours.
#
# The probe points at this checkout over `file://` rather than the public URL:
# Cargo's submodule handling does not depend on the transport, and a local source
# keeps the check hermetic and credential-free, which is the property under test.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! REV="$(git rev-parse HEAD 2>/dev/null)"; then
    echo "error: not a git checkout, so there is no rev to pin" >&2
    exit 1
fi

GITLINKS="$(git config -f .gitmodules --get-regexp '^submodule\..*\.path$' | awk '{print $2}')"
if [ -z "${GITLINKS}" ]; then
    echo "no gitlinks declared; nothing to assert"
    exit 0
fi

PROBE="$(mktemp -d)"
CARGO_HOME="${PROBE}/cargo-home"
trap 'rm -rf "${PROBE}"' EXIT
export CARGO_HOME

mkdir -p "${PROBE}/consumer/src"
printf 'fn main() {}\n' >"${PROBE}/consumer/src/main.rs"
cat >"${PROBE}/consumer/Cargo.toml" <<TOML
[package]
name = "truapi-external-consumer-probe"
version = "0.0.0"
edition = "2021"

[dependencies]
truapi = { git = "file://${ROOT}", rev = "${REV}" }
truapi-server = { git = "file://${ROOT}", rev = "${REV}" }
TOML

echo "probing an external consumer at ${REV}"
if ! (cd "${PROBE}/consumer" && cargo fetch 2>&1 | tee "${PROBE}/fetch.log"); then
    echo "error: an external consumer could not resolve the crates" >&2
    echo "       see the log above; a host submodule fetch is the usual cause" >&2
    exit 1
fi

# Cargo lays checkouts out as `checkouts/<repo>-<hash>/<short-rev>/...`, so the
# gitlink sits two levels below the checkouts root. Search the whole tree rather
# than a fixed depth: a wrong bound makes every gitlink look absent and the
# assertion below passes without testing anything.
status=0
for path in ${GITLINKS}; do
    found=0
    while IFS= read -r checkout; do
        [ -n "${checkout}" ] || continue
        found=1
        if [ -z "$(ls -A "${checkout}" 2>/dev/null)" ]; then
            echo "ok      ${path}: present but not initialized"
        else
            echo "FAIL    ${path}: initialized in the consumer's checkout" >&2
            status=1
        fi
    done <<EOF
$(find "${CARGO_HOME}/git/checkouts" -type d -path "*/${path}" 2>/dev/null)
EOF
    if [ "${found}" -eq 0 ]; then
        # No directory at all: only trustworthy alongside Cargo saying it skipped,
        # otherwise it is indistinguishable from looking in the wrong place.
        if grep -q "Skipping git submodule" "${PROBE}/fetch.log"; then
            echo "ok      ${path}: Cargo reported skipping it"
        else
            echo "FAIL    ${path}: no checkout found and Cargo never reported a skip" >&2
            echo "        (the probe is not observing what it claims to)" >&2
            status=1
        fi
    fi
done

if [ "${status}" -ne 0 ]; then
    echo >&2
    echo "A host submodule was initialized for an external consumer. Mark it" >&2
    echo "'update = none' in .gitmodules, or the crates stop resolving for anyone" >&2
    echo "without credentials for it." >&2
fi
exit "${status}"
