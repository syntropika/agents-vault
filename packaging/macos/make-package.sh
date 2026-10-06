#!/bin/sh
# Run on Apple silicon macOS. This builds a signed synthetic test artifact; it never installs.
set -eu
if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
    echo 'Apple silicon macOS is required' >&2; exit 1
fi
if [ "$#" -ne 4 ]; then
    echo 'usage: make-package.sh <release-binary-dir> <guest-bundle> <version> <output.pkg>' >&2
    exit 2
fi
binaries=$(CDPATH= cd -- "$1" && pwd)
guest=$(CDPATH= cd -- "$2" && pwd)
[ -f "$guest/guest.json" ] && [ ! -L "$guest/guest.json" ] || { echo 'Guest manifest must be a regular file' >&2; exit 1; }
guest_manifest_hash=$(shasum -a 256 "$guest/guest.json" | awk '{print $1}')
guest_format=$(plutil -extract format raw -o - "$guest/guest.json")
[ "$guest_format" = 2 ] || { echo 'Protected packages require guest manifest format 2' >&2; exit 1; }
if [ "${AV_ALLOW_SYNTHETIC_PACKAGE:-}" != 1 ]; then
    echo 'The format-2 guest runs only av-fixture. Set AV_ALLOW_SYNTHETIC_PACKAGE=1 for a disposable synthetic test package; no production guest is available yet.' >&2
    exit 1
fi
: "${AV_APPLICATION_IDENTITY:?Set a Developer ID Application identity}"
: "${AV_INSTALLER_IDENTITY:?Set a Developer ID Installer identity}"
case "${AV_SKIP_NOTARIZATION:-0}" in
    0) : "${AV_NOTARY_PROFILE:?Set an existing notarytool keychain profile}" ;;
    1) ;;
    *) echo 'AV_SKIP_NOTARIZATION must be 0 or 1' >&2; exit 2 ;;
esac
fixture_hash=$(plutil -extract fixture_sha256 raw -o - "$guest/guest.json")
case "$fixture_hash" in *[!a-f0-9]*|'') echo 'Invalid guest fixture digest' >&2; exit 1;; esac
[ "${#fixture_hash}" = 64 ] || exit 1
kernel_hash=$(plutil -extract kernel_sha256 raw -o - "$guest/guest.json")
initramfs_hash=$(plutil -extract initramfs_sha256 raw -o - "$guest/guest.json")
for resource in Image initramfs.gz; do
    [ -f "$guest/$resource" ] && [ ! -L "$guest/$resource" ] || exit 1
    if [ "$resource" = Image ]; then expected=$kernel_hash; else expected=$initramfs_hash; fi
    actual=$(shasum -a 256 "$guest/$resource" | awk '{print $1}')
    [ "$expected" = "$actual" ] || { echo "Guest $resource digest mismatch" >&2; exit 1; }
done
[ "$(shasum -a 256 "$guest/guest.json" | awk '{print $1}')" = "$guest_manifest_hash" ] || {
    echo 'Guest manifest changed during verification' >&2; exit 1;
}
version=$3
output=$4
case "$version" in *[!0-9.]*|'') echo 'version must contain digits and dots' >&2; exit 2;; esac
case "$output" in /*) ;; *) echo 'output must be an absolute path' >&2; exit 2;; esac
if [ -e "$output" ]; then echo 'output already exists' >&2; exit 1; fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
app="$work/root/Library/PrivilegedHelperTools/AgentsVault.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources/guest" "$work/root/usr/local/bin" "$work/root/Library/LaunchDaemons"
for binary in av avd av-mcp av-vmm av-supervisor av-operator; do
    install -m 755 "$binaries/$binary" "$app/Contents/MacOS/$binary"
done
for resource in Image initramfs.gz guest.json; do
    install -m 644 "$guest/$resource" "$app/Contents/Resources/guest/$resource"
    [ "$(shasum -a 256 "$guest/$resource" | awk '{print $1}')" = "$(shasum -a 256 "$app/Contents/Resources/guest/$resource" | awk '{print $1}')" ] || {
        echo "Guest $resource changed during staging" >&2; exit 1;
    }
done
staged_guest="$app/Contents/Resources/guest"
[ "$(shasum -a 256 "$staged_guest/guest.json" | awk '{print $1}')" = "$guest_manifest_hash" ] || exit 1
[ "$(plutil -extract format raw -o - "$staged_guest/guest.json")" = "$guest_format" ] || exit 1
[ "$(plutil -extract fixture_sha256 raw -o - "$staged_guest/guest.json")" = "$fixture_hash" ] || exit 1
for resource in Image initramfs.gz; do
    if [ "$resource" = Image ]; then expected=$kernel_hash; else expected=$initramfs_hash; fi
    actual=$(shasum -a 256 "$staged_guest/$resource" | awk '{print $1}')
    [ "$expected" = "$actual" ] || { echo "Staged guest $resource differs from manifest" >&2; exit 1; }
done
cp "$script_dir/Info.plist" "$app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $version" "$app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $version" "$app/Contents/Info.plist"
ln -s /Library/PrivilegedHelperTools/AgentsVault.app/Contents/MacOS/av "$work/root/usr/local/bin/av"
install -m 644 "$script_dir/dev.agentsvault.supervisor.plist" "$work/root/Library/LaunchDaemons/dev.agentsvault.supervisor.plist"
install -m 644 "$script_dir/dev.agentsvault.broker.plist" "$work/root/Library/LaunchDaemons/dev.agentsvault.broker.plist"
install -m 755 "$script_dir/configure-service.sh" "$app/Contents/Resources/configure-service.sh"
install -m 755 "$script_dir/uninstall.sh" "$app/Contents/Resources/uninstall.sh"
mkdir "$work/scripts"
install -m 755 "$script_dir/scripts/preinstall" "$work/scripts/preinstall"
install -m 755 "$script_dir/scripts/postinstall" "$work/scripts/postinstall"
for binary in av avd av-mcp av-supervisor av-operator; do
    codesign --force --sign "$AV_APPLICATION_IDENTITY" --identifier "dev.agentsvault.$binary" \
        --timestamp --options runtime "$app/Contents/MacOS/$binary"
done
codesign --force --sign "$AV_APPLICATION_IDENTITY" --timestamp --options runtime \
    --identifier dev.agentsvault.av-vmm --entitlements "$script_dir/virtualization.entitlements" "$app/Contents/MacOS/av-vmm"
team=$(codesign -dv --verbose=4 "$app/Contents/MacOS/avd" 2>&1 | awk -F= '/^TeamIdentifier=/ {print $2}')
broker_hash=$(codesign -dv --verbose=4 "$app/Contents/MacOS/avd" 2>&1 | awk -F= '/^CDHash=/ {print $2}')
runner_hash=$(codesign -dv --verbose=4 "$app/Contents/MacOS/av-vmm" 2>&1 | awk -F= '/^CDHash=/ {print $2}')
supervisor_hash=$(codesign -dv --verbose=4 "$app/Contents/MacOS/av-supervisor" 2>&1 | awk -F= '/^CDHash=/ {print $2}')
case "$team" in *[!A-Z0-9]*|'') echo 'Invalid Developer ID team identifier' >&2; exit 1;; esac
[ "${#team}" = 10 ] || exit 1
for hash in "$broker_hash" "$supervisor_hash" "$runner_hash"; do
    case "$hash" in *[!a-fA-F0-9]*|'') echo 'Invalid signed helper CDHash' >&2; exit 1;; esac
    [ "${#hash}" = 40 ] || exit 1
done
publisher="anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"$team\""
for binary in avd av-mcp av-supervisor av-vmm av-operator; do
    codesign --verify --strict "-R=$publisher and identifier \"dev.agentsvault.$binary\"" "$app/Contents/MacOS/$binary"
done
printf '{"format":2,"team_identifier":"%s","broker_cdhash":"%s","supervisor_cdhash":"%s","runner_cdhash":"%s"}\n' \
    "$team" "$broker_hash" "$supervisor_hash" "$runner_hash" > "$app/Contents/Resources/service.json"
codesign --force --sign "$AV_APPLICATION_IDENTITY" --identifier dev.agentsvault.cli --timestamp --options runtime "$app"
codesign --verify --deep --strict --verbose=2 "$app"
codesign --verify --strict "-R=$publisher and identifier \"dev.agentsvault.cli\"" "$app"
pkgbuild --root "$work/root" --install-location / --identifier dev.agentsvault.offline \
    --version "$version" --ownership recommended --scripts "$work/scripts" "$work/payload.pkg"
productbuild --package "$work/payload.pkg" --sign "$AV_INSTALLER_IDENTITY" "$output"
pkgutil --check-signature "$output"
if [ "${AV_SKIP_NOTARIZATION:-0}" = 1 ]; then
    echo 'Signed test package created. Notarization, stapling, and Gatekeeper assessment were skipped.'
else
    xcrun notarytool submit "$output" --keychain-profile "$AV_NOTARY_PROFILE" --wait
    xcrun stapler staple "$output"
    xcrun stapler validate "$output"
    spctl --assess --type install --verbose=2 "$output"
fi
