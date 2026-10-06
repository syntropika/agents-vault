#!/bin/bash
# Create the local notarytool Keychain profile from a logged-in macOS desktop.
set -u

finish() {
    local result=$1
    printf '\nPress Return to close this window.'
    read -r _
    exit "$result"
}

if [ "$(uname -s)" != Darwin ] || [ ! -t 0 ]; then
    printf 'Open this command in Terminal on a Mac.\n' >&2
    exit 1
fi

application_identity=$(security find-identity -v -p codesigning | awk -F '"' '/"Developer ID Application:/ { print $2 }')
if [ -z "$application_identity" ] || [[ "$application_identity" == *$'\n'* ]]; then
    printf 'Exactly one Developer ID Application identity is required.\n' >&2
    finish 1
fi
team_id=$(printf '%s\n' "$application_identity" | sed -n 's/.*(\([A-Z0-9]\{10\}\))$/\1/p')
if [ -z "$team_id" ]; then
    printf 'Could not read the Apple team identifier.\n' >&2
    finish 1
fi

printf 'Create an app-specific password for notarytool at https://account.apple.com.\n'
printf 'The password will be entered at the secure notarytool prompt, not here.\n'
printf 'Apple Account email: '
IFS= read -r apple_id
if [ -z "$apple_id" ]; then
    printf 'An Apple Account email is required.\n' >&2
    finish 1
fi

profile=agents-vault
printf 'Saving profile %s for team %s.\n' "$profile" "$team_id"
/usr/bin/xcrun notarytool store-credentials "$profile" --apple-id "$apple_id" --team-id "$team_id"
result=$?
if [ "$result" -eq 0 ]; then
    printf 'Notarytool profile %s is ready.\n' "$profile"
fi
finish "$result"
