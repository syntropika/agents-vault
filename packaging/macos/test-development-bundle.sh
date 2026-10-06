#!/bin/sh
# Development-only native integration. Never installs or changes service policy.
set -eu
if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
    echo 'Apple silicon macOS is required' >&2; exit 1
fi
# The shared broker integration test skips when curl is absent.
if [ ! -x /usr/bin/curl ]; then
    echo '/usr/bin/curl is required to run the broker integration test' >&2; exit 1
fi
if [ "$#" -ne 3 ]; then
    echo 'usage: test-development-bundle.sh <native-binary-dir> <format-2-guest-bundle> <new-output-dir>' >&2
    exit 2
fi
binaries=$(CDPATH= cd -- "$1" && pwd)
guest=$(CDPATH= cd -- "$2" && pwd)
output=$3
case "$output" in /*) ;; *) echo 'output must be an absolute path' >&2; exit 2;; esac
if [ -e "$output" ]; then echo 'output already exists' >&2; exit 1; fi
if [ "$(plutil -extract format raw -o - "$guest/guest.json")" != 2 ]; then
    echo 'This test requires guest manifest format 2' >&2; exit 1
fi
fixture_hash=$(plutil -extract fixture_sha256 raw -o - "$guest/guest.json")
case "$fixture_hash" in *[!a-f0-9]*|'') echo 'Invalid guest fixture digest' >&2; exit 1;; esac
[ "${#fixture_hash}" = 64 ] || exit 1
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository=$(CDPATH= cd -- "$script_dir/../.." && pwd)
mkdir -p "$output"
app="$output/AgentsVaultDevelopment.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources/guest"
for binary in av avd av-mcp av-vmm av-supervisor av-operator; do
    install -m 755 "$binaries/$binary" "$app/Contents/MacOS/$binary"
done
for resource in Image initramfs.gz guest.json; do
    install -m 644 "$guest/$resource" "$app/Contents/Resources/guest/$resource"
done
cp "$script_dir/Info.plist" "$app/Contents/Info.plist"
for binary in av avd av-mcp av-supervisor av-operator; do
    codesign --force --sign - --identifier "dev.agentsvault.$binary" \
        --options runtime "$app/Contents/MacOS/$binary"
done
codesign --force --sign - --identifier dev.agentsvault.av-vmm --options runtime \
    --entitlements "$script_dir/virtualization.entitlements" "$app/Contents/MacOS/av-vmm"
codesign --force --sign - --identifier dev.agentsvault.cli --options runtime "$app"
codesign --verify --deep --strict --verbose=2 "$app"

# This envelope tests resource tampering only. It conveys no Developer ID or
# installed-service authority, and cannot satisfy a protected service grant.
tampered="$output/Tampered.app"
for resource in guest.json Image initramfs.gz; do
    ditto "$app" "$tampered"
    printf '\nmodified development resource\n' >> "$tampered/Contents/Resources/guest/$resource"
    if codesign --verify --deep --strict "$tampered" > "$output/tamper-$resource.log" 2>&1; then
        echo "Modified signed resource was accepted: $resource" >&2; exit 1
    fi
    rm -rf "$tampered"
done

export AVD_TEST_VMM="$app/Contents/MacOS/av-vmm"
export AVD_TEST_GUEST_BUNDLE="$app/Contents/Resources/guest"
unset AVD_TEST_RUNNER_HELPER AVD_TEST_FIXTURE
cd "$repository"
cargo test -p av-vmm --test macos_vm -- --ignored --test-threads=1
cargo test -p av-vmm --lib
cargo test -p avd --lib macos
cargo test -p avd --test proxy_task \
    approved_fixture_task_injects_synthetic_secret_and_cannot_be_replayed -- --exact
codesign --verify --deep --strict --verbose=2 "$app"
printf 'AV_MAC_FORMAT2_DEVELOPMENT_PASS\n'
