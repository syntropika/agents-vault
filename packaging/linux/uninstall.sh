#!/bin/sh
set -eu

destdir=
if [ "$#" -ne 0 ]; then
    [ "$#" -eq 2 ] && [ "$1" = --destdir ] || {
        printf '%s\n' 'Usage: uninstall.sh [--destdir ABSOLUTE_STAGING_DIR]' >&2
        exit 2
    }
    destdir=$2
    case "$destdir" in /*) ;; *) exit 2 ;; esac
fi
if [ -z "$destdir" ]; then
    [ "$(id -u)" -eq 0 ] || { printf '%s\n' 'Uninstall requires root or --destdir.' >&2; exit 1; }
    systemctl disable --now agents-vault.service agents-vault-runner.service
    if [ -d /sys/kernel/security/apparmor ] && command -v apparmor_parser >/dev/null 2>&1; then
        apparmor_parser --remove /etc/apparmor.d/agents-vault-runner
    fi
fi
public_av="$destdir/usr/bin/av"
if [ -L "$public_av" ] && [ "$(readlink "$public_av")" = '../libexec/agents-vault/av' ]; then
    unlink "$public_av"
fi
for executable in avd av-operator av-runner-helper av-runner-service av-runner-client; do
    target="$destdir/usr/libexec/agents-vault/$executable"
    [ ! -e "$target" ] || unlink "$target"
done
target="$destdir/usr/libexec/agents-vault/av"
if [ -f "$target" ] && [ ! -L "$target" ]; then
    unlink "$target"
fi
for target in "$destdir/etc/apparmor.d/agents-vault-runner" "$destdir/usr/lib/systemd/system/agents-vault-runner.service" "$destdir/usr/lib/systemd/system/agents-vault.service" "$destdir/usr/lib/sysusers.d/agents-vault.conf" "$destdir/etc/agents-vault/identity.env"; do
    [ ! -e "$target" ] || unlink "$target"
done
if [ -z "$destdir" ]; then
    systemctl daemon-reload
fi
printf '%s\n' 'Removed broker package. Vault state, service.env, and the non-login identities were preserved for deliberate recovery or reinstall.'
