#!/usr/bin/env bash
# Setup (J15 §3.3 items 1 to 3): ukai-jail into the runner's temporary
# directory everywhere; on a GitHub-hosted runner only, bubblewrap 0.11.1
# when the first one on PATH is missing or too old, and the one AppArmor
# profile when the userns restriction is on. The sysctl is never written.
# shellcheck source=action/scripts/lib.sh
source "${GITHUB_ACTION_PATH:?}/scripts/lib.sh"

# --- 1. ukai-jail, through the installer at the action's own ref ------------
install_jail() {
    local installer=$ACTION_DIR/../install.sh
    [ -f "$installer" ] || fail "setup: no installer at $installer (the action's ref must carry install.sh beside action/)"
    mkdir -p "$UKAI_ROOT/bin" "$UKAI_CONFIG_DIR" "$UKAI_DATA_DIR"
    chmod 0700 "$UKAI_CONFIG_DIR" "$UKAI_DATA_DIR"
    note "installing ukai-jail $UKAI_ACTION_VERSION with $(cd -P -- "$(dirname -- "$installer")" && pwd)/install.sh"
    bash "$installer" --version "$UKAI_ACTION_VERSION" --bin-dir "$UKAI_ROOT/bin" ||
        fail "setup: the installer refused ukai-jail $UKAI_ACTION_VERSION (only versions it pins install)"
    local release
    release=$(sed -n 1p "$UKAI_ROOT/bin/ukai-jail.release")
    "$UKAI_BIN" version --json > "$(report_dir)/version.json"
    fact "ukai-jail: release $release installed by install.sh sha256:$(sha256_of "$installer")"
    fact "  binary $UKAI_BIN sha256:$(sha256_of "$UKAI_BIN")"
    fact "  revision $(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["build"]["revision"])' "$(report_dir)/version.json")"
    fact "  UKAI_CONFIG_DIR=$UKAI_CONFIG_DIR UKAI_DATA_DIR=$UKAI_DATA_DIR (mode 0700)"
    set_fact release "$release"
}

# --- 2. bubblewrap 0.11.1 ----------------------------------------------------
ensure_bwrap() {
    local first version
    first=$(first_bwrap || true)
    version=
    [ -z "$first" ] || version=$(bwrap_version_of "$first")
    if [ -n "$first" ] && version_at_least "${version:-0}" 0.10.0; then
        fact "bubblewrap: $first $version found on PATH, at least 0.10.0; nothing built"
        set_fact bwrap_path "$first"
        set_fact bwrap_version "$version"
        set_fact bwrap_built false
        return 0
    fi
    fact "bubblewrap: first on PATH before setup: ${first:-none}${version:+ $version}; building $BWRAP_VERSION"
    local src=$UKAI_ROOT/src tarball
    mkdir -p "$src"
    tarball=$src/bubblewrap-$BWRAP_VERSION.tar.xz
    # The tarball is verified before anything is installed or built; one
    # already present (a cache, a retry) is verified the same way.
    if [ ! -f "$tarball" ]; then
        curl --disable --fail --silent --show-error --location \
            --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --connect-timeout 15 --max-time 300 --retry 3 \
            "$BWRAP_URL" --output "$tarball" || fail "setup: cannot download $BWRAP_URL"
    fi
    local digest
    digest=$(sha256_of "$tarball")
    if [ "$digest" != "$BWRAP_SHA256" ]; then
        fact "  tarball sha256:$digest REFUSED (pinned sha256:$BWRAP_SHA256); nothing built or installed"
        fail "setup: bubblewrap-$BWRAP_VERSION.tar.xz has sha256 $digest, not the pinned $BWRAP_SHA256; nothing was built or installed"
    fi
    fact "  tarball $BWRAP_URL sha256:$digest (pinned)"
    note "installing bubblewrap's build dependencies from the image's apt sources"
    sudo apt-get update -qq
    # shellcheck disable=SC2024 # the log is this action's own file, not root's
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
        meson ninja-build libcap-dev pkg-config gcc > "$(report_dir)/apt-build.txt" 2>&1 ||
        { cat "$(report_dir)/apt-build.txt"; fail "setup: apt could not install bubblewrap's build dependencies"; }
    fact "  build dependencies: meson ninja-build libcap-dev pkg-config gcc (apt)"
    rm -rf "$src/bubblewrap-$BWRAP_VERSION"
    tar -xJf "$tarball" -C "$src"
    (
        cd "$src/bubblewrap-$BWRAP_VERSION"
        meson setup build --prefix=/usr/local -Dman=disabled -Dselinux=disabled \
            -Dtests=false -Dbash_completion=disabled -Dzsh_completion=disabled
        ninja -C build
    ) > "$(report_dir)/bwrap-build.txt" 2>&1 ||
        { tail -40 "$(report_dir)/bwrap-build.txt"; fail "setup: building bubblewrap $BWRAP_VERSION failed"; }
    sudo install -o root -g root -m 0755 "$src/bubblewrap-$BWRAP_VERSION/build/bwrap" "$BWRAP_TARGET"
    version=$(bwrap_version_of "$BWRAP_TARGET")
    [ "$version" = "$BWRAP_VERSION" ] || fail "setup: $BWRAP_TARGET reports ${version:-nothing}, not $BWRAP_VERSION"
    first=$(first_bwrap || true)
    [ "$first" = "$BWRAP_TARGET" ] || fail "setup: the first bwrap on PATH is ${first:-none}, not $BWRAP_TARGET"
    fact "  installed $BWRAP_TARGET (root, 0755) bubblewrap $version sha256:$(sha256_of "$BWRAP_TARGET")"
    set_fact bwrap_path "$BWRAP_TARGET"
    set_fact bwrap_version "$version"
    set_fact bwrap_built true
}

# --- 3. the AppArmor profile, only when the restriction is on ---------------
ensure_apparmor() {
    local reading profile_file=$ACTION_DIR/$APPARMOR_PROFILE
    reading=$(read_sysctl)
    fact "apparmor: $APPARMOR_SYSCTL=$reading before setup"
    set_fact sysctl_before "$reading"
    set_fact profile_loaded false
    if [ "$reading" != 1 ]; then
        fact "  no profile loaded: the restriction is not on (reads $reading)"
        set_fact profile_reason "the restriction reads $reading"
        return 0
    fi
    if [ "$(get_fact bwrap_path)" != "$BWRAP_TARGET" ]; then
        fact "  no profile loaded: the bubblewrap in use is $(get_fact bwrap_path), not $BWRAP_TARGET, the only binary the profile names"
        set_fact profile_reason "the bubblewrap in use is not $BWRAP_TARGET"
        return 0
    fi
    if ! command -v apparmor_parser > /dev/null 2>&1 || [ ! -d /sys/kernel/security/apparmor ]; then
        fact "  no profile loaded: AppArmor is not available on this runner"
        set_fact profile_reason "AppArmor is not available"
        return 0
    fi
    sudo apparmor_parser -r "$profile_file" || fail "setup: apparmor_parser could not load $profile_file"
    sudo grep -qF "$APPARMOR_PROFILE (" /sys/kernel/security/apparmor/profiles ||
        fail "setup: the profile $APPARMOR_PROFILE is not listed as loaded"
    fact "  loaded $APPARMOR_PROFILE with \`sudo apparmor_parser -r\` from $profile_file (sha256:$(sha256_of "$profile_file")); the sysctl is not written. Profile text:"
    sed 's/^/    | /' "$profile_file" >> "$(report_dir)/setup.txt"
    set_fact profile_loaded true
}

# Sourced (by the action's tests), it defines the functions and runs nothing.
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
install_jail
if [ "${RUNNER_ENVIRONMENT:-}" = github-hosted ]; then
    ensure_bwrap
    ensure_apparmor
else
    # §3.2: anything but a GitHub-hosted runner gets no host change at all;
    # doctor must find it ready as it is.
    first=$(first_bwrap || true)
    fact "host setup: none (RUNNER_ENVIRONMENT=${RUNNER_ENVIRONMENT:-unset}); bubblewrap on PATH: ${first:-none}; $APPARMOR_SYSCTL=$(read_sysctl)"
    set_fact bwrap_path "$first"
    set_fact bwrap_built false
    set_fact profile_loaded false
    set_fact sysctl_before "$(read_sysctl)"
    set_fact profile_reason "not a GitHub-hosted runner"
fi
