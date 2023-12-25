#!/bin/bash

remote_scp_host="raspberrypi-3aplus"
remote_dir="~/spotify-nfc-player"

files="Cargo.toml src/main.rs src/spotify.rs src/nfc.rs"
for f in $files; do
    test -e $f || (echo "$f does not exist."; exit 1)
    scp "$f" "${remote_scp_host}:${remote_dir}/$f"
done
