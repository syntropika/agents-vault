#!/bin/sh
# All services, identities and AppArmor policy changes stay inside the guest.
set -eu
if [ "$#" -ne 4 ] || [ "$1" != --bin-dir ] || [ "$3" != --artifact-dir ]; then
    printf '%s\n' 'Usage: run-systemd-tests.sh --bin-dir ABSOLUTE_BIN_DIR --artifact-dir NEW_ABSOLUTE_ARTIFACT_DIR' >&2
    exit 2
fi
bin_dir=$2
artifact_dir=$4
case "$bin_dir" in /*) ;; *) exit 2 ;; esac
case "$artifact_dir" in /*) ;; *) exit 2 ;; esac
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -- "$artifact_dir"
printf 'Building disposable guest and executor; logs: %s\n' "$artifact_dir"
docker build --target executor -f "$script_dir/Dockerfile.systemd-tests" -t agents-vault-systemd-executor:local "$script_dir" > "$artifact_dir/build-executor.log" 2>&1
docker build --target guest -f "$script_dir/Dockerfile.systemd-tests" -t agents-vault-systemd-guest:local "$script_dir" > "$artifact_dir/build-guest.log" 2>&1
guest_container=$(docker create agents-vault-systemd-guest:local)
trap 'docker rm "$guest_container" >/dev/null 2>&1 || true' EXIT HUP INT TERM
docker export "$guest_container" > "$artifact_dir/guest.tar"
docker rm "$guest_container" >/dev/null
trap - EXIT HUP INT TERM
docker run --rm --network none \
    -v "$artifact_dir:/work" -v "$bin_dir:/input-binaries:ro" -v "$script_dir:/test-code:ro" \
    agents-vault-systemd-executor:local python3 /test-code/prepare_systemd_image.py
printf '%s\n' 'Booting guest with QEMU software emulation; no host kernel policy or services are changed.'
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" -v "$artifact_dir:/work" \
    agents-vault-systemd-executor:local \
    timeout 900 qemu-system-x86_64 -machine q35,accel=tcg -cpu max -m 3072 -smp 2 \
    -display none -monitor none -serial stdio -no-reboot -nic none \
    -kernel /work/vmlinuz -initrd /work/initrd.img \
    -append 'root=/dev/vda rw console=ttyS0 apparmor=1 security=apparmor systemd.show_status=1 panic=-1' \
    -drive file=/work/guest.ext4,format=raw,if=virtio > "$artifact_dir/serial.log" 2>&1
python3 - "$artifact_dir/serial.log" <<'PY'
import pathlib
import sys
log = pathlib.Path(sys.argv[1]).read_text(errors="replace")
for line in log.splitlines():
    if "AV_VM_TEST_" in line:
        print(line)
if "AV_VM_TEST_PASS" not in log or "AV_VM_TEST_FAIL" in log:
    print("Guest test did not pass. Inspect the serial log.")
    sys.exit(1)
for value in ("synthetic-service-test-passphrase", "av-synthetic-systemd-fixture"):
    if value in log:
        print("Synthetic credential appeared in the serial log.")
        sys.exit(1)
PY
