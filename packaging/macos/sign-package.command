#!/bin/bash
# Launch this file from the logged-in macOS desktop, not from an SSH shell.
set -u

finish() {
    local result=$1
    printf '\nPress Return to close this window.'
    read -r _
    exit "$result"
}

if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ] || [ ! -t 0 ]; then
    printf 'Open this command in Terminal on an Apple silicon Mac.\n' >&2
    exit 1
fi

script_path=$0
while [ -L "$script_path" ]; do
    link_target=$(readlink "$script_path")
    case "$link_target" in
        /*) script_path=$link_target ;;
        *) script_path=$(dirname -- "$script_path")/$link_target ;;
    esac
done
script_dir=$(CDPATH= cd -- "$(dirname -- "$script_path")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
package_script="$script_dir/make-package.sh"
if [ ! -f "$package_script" ]; then
    printf 'Package script is missing: %s\n' "$package_script" >&2
    finish 1
fi

application_entry=$(security find-identity -v -p codesigning | grep '"Developer ID Application:')
installer_entry=$(security find-identity -v | grep '"Developer ID Installer:')
if [ -z "$application_entry" ] || [ -z "$installer_entry" ]; then
    printf 'Both Developer ID Application and Developer ID Installer identities must be installed in Keychain.\n' >&2
    finish 1
fi
case "$application_entry$installer_entry" in
    *$'\n'*) printf 'More than one matching Developer ID identity was found. Select identities explicitly in the package script.\n' >&2; finish 1 ;;
esac
application_identity=$(printf '%s\n' "$application_entry" | awk '{ print $2 }')
installer_identity=$(printf '%s\n' "$installer_entry" | awk '{ print $2 }')
application_team=$(printf '%s\n' "$application_entry" | sed -n 's/.*(\([A-Z0-9]\{10\}\))"$/\1/p')
installer_team=$(printf '%s\n' "$installer_entry" | sed -n 's/.*(\([A-Z0-9]\{10\}\))"$/\1/p')
if [ -z "$application_team" ] || [ "$application_team" != "$installer_team" ]; then
    printf 'Application and Installer identities must have the same valid Apple team identifier.\n' >&2
    finish 1
fi

printf 'Release binary directory [%s]: ' "$project_dir/target/release"
IFS= read -r binaries
binaries=${binaries:-$project_dir/target/release}
printf 'Verified guest bundle directory: '
IFS= read -r guest
printf 'Version [0.1.0]: '
IFS= read -r version
version=${version:-0.1.0}
printf 'Notarize with Apple now? [y/N]: '
IFS= read -r notarize_answer
case "$notarize_answer" in
    y|Y|yes|YES) notarize=1 ;;
    ''|n|N|no|NO) notarize=0 ;;
    *) printf 'Answer y or n.\n' >&2; finish 1 ;;
esac
if [ "$notarize" -eq 1 ]; then
    default_output="$HOME/Desktop/agents-vault-$version-synthetic.pkg"
else
    default_output="$HOME/Desktop/agents-vault-$version-synthetic-signed-only.pkg"
fi
printf 'Output package path [%s]: ' "$default_output"
IFS= read -r output
output=${output:-$default_output}
if [ "$notarize" -eq 1 ]; then
    printf 'Existing notarytool Keychain profile [agents-vault]: '
    IFS= read -r notary_profile
    notary_profile=${notary_profile:-agents-vault}
fi

if [ ! -d "$binaries" ] || [ ! -d "$guest" ]; then
    printf 'The binary directory and guest bundle are required.\n' >&2
    finish 1
fi
if [ "$notarize" -eq 1 ] && [ -z "$notary_profile" ]; then
    printf 'The notary profile is required for notarization.\n' >&2
    finish 1
fi
case "$output" in
    /*) ;;
    *) printf 'The output path must be absolute.\n' >&2; finish 1 ;;
esac
if [ -e "$output" ]; then
    printf 'Output already exists: %s\n' "$output" >&2
    finish 1
fi

printf '\nThis creates a synthetic test package only.\n'
printf 'Application identity: %s\n' "$application_identity"
printf 'Installer identity: %s\n' "$installer_identity"
printf 'Binaries: %s\nGuest: %s\nOutput: %s\n' "$binaries" "$guest" "$output"
if [ "$notarize" -eq 1 ]; then
    printf 'Type SIGN SYNTHETIC to sign, notarize, and verify this package: '
else
    printf 'Type SIGN SYNTHETIC to sign and verify this test package: '
fi
IFS= read -r confirmation
if [ "$confirmation" != 'SIGN SYNTHETIC' ]; then
    printf 'Cancelled.\n'
    finish 1
fi

log_dir="$HOME/Library/Logs/AgentsVault"
mkdir -p "$log_dir"
log_file="$log_dir/package-$(date +%Y%m%d-%H%M%S).log"
(
    export AV_APPLICATION_IDENTITY="$application_identity"
    export AV_INSTALLER_IDENTITY="$installer_identity"
    if [ "$notarize" -eq 1 ]; then
        export AV_NOTARY_PROFILE="$notary_profile"
    else
        export AV_SKIP_NOTARIZATION=1
    fi
    export AV_ALLOW_SYNTHETIC_PACKAGE=1
    /bin/sh "$package_script" "$binaries" "$guest" "$version" "$output"
) 2>&1 | /usr/bin/tee "$log_file"
result=${PIPESTATUS[0]}
printf 'Package script exit code: %s\nLog: %s\n' "$result" "$log_file"
finish "$result"
