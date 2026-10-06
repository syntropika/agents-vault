#!/bin/sh
# Configure the public agent UID. Unlock/approval tokens remain private to _avd.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
[ "$(uname -s)" = Darwin ] && [ "$(id -u)" = 0 ] || { echo 'Run as an administrator on macOS' >&2; exit 1; }
[ "$#" = 2 ] && [ "$1" = --agent-uid ] || { echo 'usage: configure-service.sh --agent-uid UID' >&2; exit 2; }
agent_uid=$2
case "$agent_uid" in *[!0-9]*|'') exit 2;; esac
[ "$agent_uid" -ge 500 ] || { echo 'Choose a login UID of at least 500' >&2; exit 2; }
agent_name=$(id -nu "$agent_uid")
[ "$agent_uid" != "$(id -u _avd)" ] && [ "$agent_uid" != "$(id -u _avrunner)" ] || exit 1
shell=$(dscl . -read "/Users/$agent_name" UserShell | awk '{print $2}')
case "$shell" in ''|*/false|*/nologin) echo 'Agent must have a login shell' >&2; exit 1;; esac
plist=/Library/LaunchDaemons/dev.agentsvault.broker.plist
[ -f "$plist" ] && [ ! -L "$plist" ] && [ "$(stat -f %u "$plist")" = 0 ] || exit 1
if launchctl print system/dev.agentsvault.broker >/dev/null 2>&1; then
    echo 'Boot out the broker before changing its authorized agent UID' >&2; exit 1
fi
temporary=$(mktemp "$plist.XXXXXXXX")
trap 'rm -f "$temporary"' 0
trap 'exit 1' 1 2 3 15
cp "$plist" "$temporary"
/usr/libexec/PlistBuddy -c 'Delete :EnvironmentVariables:AVD_MAC_AGENT_UID' "$temporary" 2>/dev/null || :
/usr/libexec/PlistBuddy -c "Add :EnvironmentVariables:AVD_MAC_AGENT_UID string $agent_uid" "$temporary"
/usr/libexec/PlistBuddy -c 'Delete :EnvironmentVariables:AVD_CLIENT_UID' "$temporary" 2>/dev/null || :
/usr/libexec/PlistBuddy -c "Add :EnvironmentVariables:AVD_CLIENT_UID string $agent_uid" "$temporary"
plutil -lint "$temporary"
chown root:wheel "$temporary"
chmod 644 "$temporary"
mv -f "$temporary" "$plist"
trap - 0 1 2 3 15
printf 'Configured agent and protected CLI client UID %s. This command does not start services.\n' "$agent_uid"
