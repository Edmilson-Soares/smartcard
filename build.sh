#!/bin/sh
# Compila a lib Rust fogusmartcard e grava o binário em native/<so>-<arch>/, com o
# nome que cada sistema usa — é lá que o _native.fg procura ao importar a lib:
#   native/windows-x64/fogusmartcard.dll   native/linux-x64/libfogusmartcard.so
#   native/macos-arm64/libfogusmartcard.dylib ...
#
#   ./build.sh                               este sistema/arquitetura
#   ./build.sh aarch64-unknown-linux-gnu     outro target (rustup target add ...)
#   ./build.sh all                           linux x64/arm64 e macOS x64/arm64
# Targets de outro sistema usam `cargo zigbuild` (cargo install cargo-zigbuild,
# e o zig no PATH) quando ele existe; senão, `cargo build` com o linker do target.
# CARGO_TARGET_DIR muda a pasta de build (útil no WSL, fora de /mnt/c).
# Linux: precisa do pcsc-lite (sudo apt install libpcsclite-dev pcscd). macOS: PCSC.framework (só compila num Mac).
set -e
cd "$(dirname "$0")"
crate=fogusmartcard
host="$(rustc -vV | sed -n 's/^host: //p')"

if [ "$1" = "all" ]; then
    set -- x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin
fi
[ $# -eq 0 ] && set -- "$host"

for target in "$@"; do
    case "$target" in
        x86_64-*-linux-*) dir=linux-x64; lib="lib$crate.so" ;;
        aarch64-*-linux-*) dir=linux-arm64; lib="lib$crate.so" ;;
        armv7-*-linux-*) dir=linux-armv7; lib="lib$crate.so" ;;
        x86_64-apple-darwin) dir=macos-x64; lib="lib$crate.dylib" ;;
        aarch64-apple-darwin) dir=macos-arm64; lib="lib$crate.dylib" ;;
        x86_64-pc-windows-*) dir=windows-x64; lib="$crate.dll" ;;
        i686-pc-windows-*) dir=windows-x86; lib="$crate.dll" ;;
        aarch64-pc-windows-*) dir=windows-arm64; lib="$crate.dll" ;;
        *) echo "target não suportado: $target" >&2; exit 1 ;;
    esac
    out="${CARGO_TARGET_DIR:-$crate/target}"
    echo "== $dir ($target)"
    if [ "$target" != "$host" ] && command -v cargo-zigbuild >/dev/null 2>&1; then
        cargo zigbuild --release --target "$target" --manifest-path "$crate/Cargo.toml"
    else
        cargo build --release --target "$target" --manifest-path "$crate/Cargo.toml"
    fi
    mkdir -p "native/$dir"
    cp "$out/$target/release/$lib" "native/$dir/$lib"
    echo "native/$dir/$lib atualizado"
done
