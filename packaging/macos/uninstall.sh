#!/bin/sh
# Remove the service package while retaining encrypted state and identities.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
dry_run=false
case "${1:-}" in --dry-run) dry_run=true;; '') ;; *) echo 'usage: uninstall.sh [--dry-run]' >&2; exit 2;; esac
[ "$#" -le 1 ] || exit 2
[ "$(uname -s)" = Darwin ] || { echo 'macOS is required' >&2; exit 1; }
app=/Library/PrivilegedHelperTools/AgentsVault.app
if [ "$dry_run" = true ]; then
    echo 'Would stop and disable dev.agentsvault.broker and dev.agentsvault.supervisor.'
    echo 'Would remove the installed app, two LaunchDaemon plists, matching av symlink, and installer receipt.'
    echo 'Would remove transient sockets and the private administration token while preserving encrypted vault/recovery data and both service identities.'
    exit 0
fi
[ "$(id -u)" = 0 ] || { echo 'Uninstall requires an administrator' >&2; exit 1; }
[ -d "$app" ] && [ ! -L "$app" ] && [ "$(stat -f %u "$app")" = 0 ] || { echo 'Installed root-owned bundle missing' >&2; exit 1; }
[ -f /private/var/db/agents-vault/identities ] && [ ! -L /private/var/db/agents-vault/identities ] || exit 1
[ "$(stat -f %u /private/var/db/agents-vault/identities)" = 0 ] || exit 1
for label in dev.agentsvault.broker dev.agentsvault.supervisor; do
    path="/Library/LaunchDaemons/$label.plist"
    [ -f "$path" ] && [ ! -L "$path" ] && [ "$(stat -f %u "$path")" = 0 ] || exit 1
done
for label in dev.agentsvault.broker dev.agentsvault.supervisor; do
    launchctl disable "system/$label"
    if launchctl print "system/$label" >/dev/null 2>&1; then launchctl bootout "system/$label"; fi
done
# launchd must confirm both services are gone before files are removed.
for label in dev.agentsvault.broker dev.agentsvault.supervisor; do
    if launchctl print "system/$label" >/dev/null 2>&1; then echo 'Service did not stop' >&2; exit 1; fi
done
if pgrep -f '^/Library/PrivilegedHelperTools/Agents Vault[.]app/Contents/MacOS/(avd|av-supervisor|av-vmm)( |$)' >/dev/null; then
    echo 'An installed service process is still running; refusing removal' >&2; exit 1
fi
broker_uid=$(id -u _avd)
for name in admin.sock admin.token; do
    path="/private/var/db/agents-vault/broker/runtime/$name"
    if [ -e "$path" ] || [ -L "$path" ]; then
        [ ! -L "$path" ] && [ "$(stat -f %u "$path")" = "$broker_uid" ] && { [ -f "$path" ] || [ -S "$path" ]; } || exit 1
        # The broker owns its runtime parent. Delete with that identity so a
        # concurrent parent replacement cannot make root unlink another file.
        sudo -n -u _avd /bin/rm "$path"
    fi
done
for path in /private/var/db/agents-vault/agent/agent.sock /private/var/db/agents-vault/agent/client.sock /private/var/db/agents-vault/run/supervisor.sock; do
    if [ -e "$path" ] || [ -L "$path" ]; then
        [ ! -L "$path" ] && [ -S "$path" ] || exit 1
        owner=$(stat -f %u "$path")
        [ "$owner" = 0 ] || [ "$owner" = "$broker_uid" ] || exit 1
        if [ "$owner" = "$broker_uid" ]; then sudo -n -u _avd /bin/rm "$path"; else rm "$path"; fi
    fi
done
for label in dev.agentsvault.broker dev.agentsvault.supervisor; do
    path="/Library/LaunchDaemons/$label.plist"
    [ ! -L "$path" ] && [ "$(stat -f %u "$path")" = 0 ] || exit 1
    rm "$path"
done
if [ -L /usr/local/bin/av ] && [ "$(readlink /usr/local/bin/av)" = "$app/Contents/MacOS/av" ]; then rm /usr/local/bin/av; fi
rm -rf "$app"
pkgutil --forget dev.agentsvault.offline >/dev/null
echo 'Package and transient capabilities removed. Encrypted state, recovery data, and identities remain for deliberate recovery.'
echo 'Installed packages refuse retained state; reinstall and deletion need a separate reviewed procedure.'
