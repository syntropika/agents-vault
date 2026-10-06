#!/bin/sh
set -eu

usage() {
    printf '%s\n' 'Usage: install.sh --bin-dir ABSOLUTE_DIR --agent-uid UID [--client-uid UID] [--destdir ABSOLUTE_STAGING_DIR]'
    exit 2
}
bin_dir=
agent_uid=
client_uid=
destdir=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --bin-dir) [ "$#" -ge 2 ] || usage; bin_dir=$2; shift 2 ;;
        --agent-uid) [ "$#" -ge 2 ] || usage; agent_uid=$2; shift 2 ;;
        --client-uid) [ "$#" -ge 2 ] || usage; client_uid=$2; shift 2 ;;
        --destdir) [ "$#" -ge 2 ] || usage; destdir=$2; shift 2 ;;
        *) usage ;;
    esac
done
case "$bin_dir" in /*) ;; *) usage ;; esac
case "$agent_uid" in ''|0|*[!0-9]*) usage ;; esac
if [ -n "$client_uid" ]; then
    case "$client_uid" in 0|*[!0-9]*) usage ;; esac
    [ "$client_uid" != "$agent_uid" ] || usage
fi
case "$destdir" in ''|/*) ;; *) usage ;; esac
if [ -z "$destdir" ] && [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' 'System installation requires root. Use --destdir for an unprivileged staging review.' >&2
    exit 1
fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
verify_pinned_file() {
    expected=$1
    source=$2
    [ -f "$source" ] && [ ! -L "$source" ] || {
        printf 'Missing regular pinned file: %s\n' "$source" >&2
        exit 1
    }
    actual=$(sha256sum "$source")
    actual=${actual%% *}
    [ "$actual" = "$expected" ] || {
        printf 'Pinned file hash mismatch: %s\n' "$source" >&2
        exit 1
    }
}
for executable in av avd av-operator av-runner-helper av-runner-service av-runner-client; do
    [ -f "$bin_dir/$executable" ] && [ ! -L "$bin_dir/$executable" ] || {
        printf 'Missing regular executable: %s\n' "$bin_dir/$executable" >&2
        exit 1
    }
done
[ -x "$bin_dir/av" ] || {
    printf 'Public CLI source is not executable: %s\n' "$bin_dir/av" >&2
    exit 1
}
av_sha256=$(sha256sum "$bin_dir/av")
av_sha256=${av_sha256%% *}
av_target="$destdir/usr/libexec/agents-vault/av"
public_av="$destdir/usr/bin/av"
if [ -L "$av_target" ] || { [ -e "$av_target" ] && [ ! -f "$av_target" ]; }; then
    printf 'Public CLI destination must be absent or a regular file: %s\n' "$av_target" >&2
    exit 1
fi
if [ -z "$destdir" ] && [ -e "$av_target" ] && [ "$(stat -c %u "$av_target")" -ne 0 ]; then
    printf 'Public CLI destination is not root-owned: %s\n' "$av_target" >&2
    exit 1
fi
if [ -L "$public_av" ]; then
    [ "$(readlink "$public_av")" = '../libexec/agents-vault/av' ] || {
        printf 'Public CLI entry belongs to another installation: %s\n' "$public_av" >&2
        exit 1
    }
    if [ -z "$destdir" ] && [ "$(stat -c %u "$public_av")" -ne 0 ]; then
        printf 'Public CLI entry is not root-owned: %s\n' "$public_av" >&2
        exit 1
    fi
elif [ -e "$public_av" ]; then
    printf 'Public CLI entry belongs to another installation: %s\n' "$public_av" >&2
    exit 1
fi
install -d -m 0755 "$destdir/usr/bin" "$destdir/usr/libexec/agents-vault" "$destdir/usr/lib/systemd/system" \
    "$destdir/usr/lib/sysusers.d" "$destdir/etc/apparmor.d" "$destdir/etc/agents-vault"
av_staged=$(mktemp "$destdir/usr/libexec/agents-vault/.av.XXXXXXXX")
trap 'rm -f -- "$av_staged"' 0
trap 'exit 1' 1 2 15
install -m 0600 "$bin_dir/av" "$av_staged"
verify_pinned_file "$av_sha256" "$av_staged"
if [ -z "$destdir" ]; then
    chown root:root "$av_staged"
fi
chmod 0755 "$av_staged"
mv -fT -- "$av_staged" "$av_target"
trap - 0 1 2 15
verify_pinned_file "$av_sha256" "$av_target"
if [ ! -L "$public_av" ]; then
    ln -s ../libexec/agents-vault/av "$public_av"
fi
for executable in avd av-operator av-runner-helper av-runner-service av-runner-client; do
    install -m 0755 "$bin_dir/$executable" "$destdir/usr/libexec/agents-vault/$executable"
done
for unit in agents-vault.service agents-vault-runner.service; do
    install -m 0644 "$script_dir/$unit" "$destdir/usr/lib/systemd/system/$unit"
done
install -m 0644 "$script_dir/agents-vault-runner.apparmor" "$destdir/etc/apparmor.d/agents-vault-runner"
install -m 0644 "$script_dir/agents-vault.sysusers" "$destdir/usr/lib/sysusers.d/agents-vault.conf"
printf 'AVD_SERVICE_AGENT_UID=%s\n' "$agent_uid" > "$destdir/etc/agents-vault/identity.env"
if [ -n "$client_uid" ]; then
    printf 'AVD_CLIENT_UID=%s\n' "$client_uid" >> "$destdir/etc/agents-vault/identity.env"
fi
chmod 0644 "$destdir/etc/agents-vault/identity.env"
if [ ! -e "$destdir/etc/agents-vault/service.env" ]; then
    printf '%s\n' 'AVD_VAULT_PATH=/var/lib/agents-vault/vault.db' > "$destdir/etc/agents-vault/service.env"
    chmod 0644 "$destdir/etc/agents-vault/service.env"
fi
if [ -z "$destdir" ]; then
    for executable in av avd av-operator av-runner-helper av-runner-service av-runner-client; do
        chown root:root "/usr/libexec/agents-vault/$executable"
    done
    chown root:root /etc/agents-vault/identity.env
    systemd-sysusers /usr/lib/sysusers.d/agents-vault.conf
    # Offline initialization must be possible before the service has started.
    install -d -o av-broker -g av-broker -m 0700 /var/lib/agents-vault
    if [ -d /sys/kernel/security/apparmor ]; then
        if command -v apparmor_parser >/dev/null 2>&1; then
            apparmor_parser --replace /etc/apparmor.d/agents-vault-runner
        elif [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || true)" = 1 ]; then
            printf '%s\n' 'AppArmor restricts user namespaces. Install apparmor_parser and rerun this installer to load the scoped runner profile.' >&2
            exit 1
        fi
    fi
    systemctl daemon-reload
    printf '%s\n' 'Installed synthetic broker and distinct non-login broker/runner identities. Initialize the vault with av-operator init, then start agents-vault.service.'
else
    printf 'Staged installation in %s; no accounts or services changed.\n' "$destdir"
fi
