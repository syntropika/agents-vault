#!/bin/sh
# Build-time Linux tool. It never runs on a user's Mac during installation.
set -eu
if [ "$#" -ne 4 ]; then
    echo 'usage: build-guest.sh <pinned-input-dir> <av-guest-arm64-musl> <av-fixture-arm64-musl> <output-dir>' >&2
    exit 2
fi
inputs=$(realpath "$1")
guest=$(realpath "$2")
fixture=$(realpath "$3")
output=$(realpath -m "$4")
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -e "$output" ]; then echo 'output directory already exists' >&2; exit 1; fi
# The kernel is an extracted raw Image, not Alpine's compressed PE wrapper.
check_hash() { printf '%s  %s\n' "$2" "$inputs/$1" | sha256sum -c -; }
check_hash Image d625d13a08f08ba1befa309edab7fa9360093b7e7c62b03010c0de084ff9ac20
check_hash initramfs-virt 384f2d828bbbf237bc57d03c0b5bb371482f01868b5f5fea151a2022554b889c
check_hash modloop-virt da142869626ec9d4543ab46482af10b5ff2c8c1c2e01068ddf32360316a06218
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir -p "$work/root" "$output"
gzip -dc "$inputs/initramfs-virt" | (cd "$work/root" && cpio -idmu --quiet)
unsquashfs -quiet -dest "$work/modules" "$inputs/modloop-virt"
module_path=lib/modules/6.12.110-0-virt/kernel/net/vmw_vsock
mkdir -p "$work/root/$module_path" "$work/root/usr/bin"
for module in vsock vmw_vsock_virtio_transport_common vmw_vsock_virtio_transport; do
    cp "$work/modules/modules/6.12.110-0-virt/kernel/net/vmw_vsock/$module.ko" "$work/root/$module_path/"
done
mkdir -p "$work/root/lib/modules/6.12.110-0-virt/kernel/drivers/char/hw_random"
for module in rng-core virtio-rng; do
    cp "$work/modules/modules/6.12.110-0-virt/kernel/drivers/char/hw_random/$module.ko" "$work/root/lib/modules/6.12.110-0-virt/kernel/drivers/char/hw_random/"
done
install -m 755 "$guest" "$work/root/usr/bin/av-guest"
install -m 755 "$fixture" "$work/root/usr/bin/av-fixture"
install -m 755 "$script_dir/guest/init" "$work/root/init"
cp "$inputs/Image" "$output/Image"
(cd "$work/root" && find . -print0 | LC_ALL=C sort -z | cpio --null -o -H newc --owner 0:0 --quiet) | gzip -n > "$output/initramfs.gz"
kernel_hash=$(sha256sum "$output/Image" | cut -d ' ' -f 1)
initramfs_hash=$(sha256sum "$output/initramfs.gz" | cut -d ' ' -f 1)
fixture_hash=$(sha256sum "$work/root/usr/bin/av-fixture" | cut -d ' ' -f 1)
printf '{"format":2,"architecture":"aarch64","kernel_sha256":"%s","initramfs_sha256":"%s","fixture_sha256":"%s"}\n' "$kernel_hash" "$initramfs_hash" "$fixture_hash" > "$output/guest.json"
echo "Guest bundle written to $output"
