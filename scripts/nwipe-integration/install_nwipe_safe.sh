#!/usr/bin/env bash
# install_nwipe_safe.sh — Installs nwipe only on Ubuntu 22.04/24.04
# - Does NOT execute nwipe
# - Does NOT access /dev/sdX / nvme*
# - Does NOT perform destructive tests

set -Eeuo pipefail

log() { printf "\033[0;32m[INFO]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err() { printf "\033[0;31m[ERROR]\033[0m %s\n" "$*" >&2; }
die() { err "$*"; exit 1; }

cleanup() {
    [[ -n "${TMPDIR_CREATED:-}" && -d "${TMPDIR_CREATED}" ]] && rm -rf "${TMPDIR_CREATED}" || true
}
trap cleanup EXIT

require_root() { [[ $EUID -eq 0 ]] || die "Run as root (sudo)."; }

check_os() {
    if [[ -r /etc/os-release ]]; then
        . /etc/os-release
        case "${ID}-${VERSION_ID}" in
            ubuntu-24.04|ubuntu-22.04) ;;
            *) warn "Detected distribution: ${PRETTY_NAME:-unknown}. Proceeding anyway...";;
        esac
    fi
}

apt_update() {
    log "Updating APT indexes..."
    apt-get update -y
}

install_via_apt() {
    log "Attempting to install 'nwipe' via APT..."
    if DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nwipe; then
        log "nwipe installed via APT."
        return 0
    else
        warn "nwipe package unavailable or failed via APT. Falling back to compilation."
        return 1
    fi
}

install_build_deps() {
    log "Installing build dependencies..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential git autoconf automake libtool pkg-config \
        libparted-dev libncurses-dev
}

build_from_source() {
    local url dir
    url="${NWIPE_REPO:-https://github.com/martijnvanbrummelen/nwipe.git}"
    dir="$(mktemp -d)"
    TMPDIR_CREATED="${dir}"
    
    log "Cloning repository: ${url}"
    git clone --depth=1 "${url}" "${dir}/nwipe"
    cd "${dir}/nwipe"
    
    [[ -x ./autogen.sh ]] && ./autogen.sh
    ./configure --prefix=/usr
    make -j"$(nproc)"
    make install
    
    log "nwipe compiled and installed in /usr/bin/nwipe"
}

verify_install() {
    command -v nwipe >/dev/null || die "nwipe not found in PATH after installation."
    log "Installed version (safe call):"
    nwipe --version || true
}

main() {
    require_root
    check_os
    apt_update
    
    if ! install_via_apt; then
        install_build_deps
        build_from_source
    fi
    
    verify_install
    log "INSTALLATION COMPLETED SUCCESSFULLY."
    warn "This script DID NOT execute 'nwipe' and DID NOT touch any block device."
}

main "$@"
