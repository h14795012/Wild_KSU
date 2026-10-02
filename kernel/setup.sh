#!/bin/sh
set -eu

GKI_ROOT=$(pwd)
OWNER="${KSU_OWNER:-h14795012}"
REPO="${KSU_REPO:-Wild_KSU}"
BRANCH_DEFAULT="${KSU_BRANCH:-bootable}"

display_usage() {
    echo "Usage: $0 [--cleanup | <commit-or-tag-or-branch>]"
    echo "  --cleanup:              Cleans up previous modifications made by the script."
    echo "  <commit-or-tag-or-branch>: Sets up or updates the Wild KSU to specified tag, commit or branch."
    echo "  -h, --help:             Displays this usage information."
    echo "  (no args):              Sets up or updates the Wild KSU environment to default ($BRANCH_DEFAULT)."
}

initialize_variables() {
    if test -d "$GKI_ROOT/common/drivers"; then
         DRIVER_DIR="$GKI_ROOT/common/drivers"
    elif test -d "$GKI_ROOT/aosp/drivers"; then
         DRIVER_DIR="$GKI_ROOT/aosp/drivers"
    elif test -d "$GKI_ROOT/drivers"; then
         DRIVER_DIR="$GKI_ROOT/drivers"
    else
         echo '[ERROR] "drivers/" directory not found.'
         exit 127
    fi

    DRIVER_MAKEFILE=$DRIVER_DIR/Makefile
    DRIVER_KCONFIG=$DRIVER_DIR/Kconfig
}

perform_cleanup() {
    echo "[+] Cleaning up..."
    [ -L "$DRIVER_DIR/kernelsu" ] && rm "$DRIVER_DIR/kernelsu" && echo "[-] Symlink removed."
    grep -q "kernelsu" "$DRIVER_MAKEFILE" && sed -i '/kernelsu/d' "$DRIVER_MAKEFILE" && echo "[-] Makefile reverted."
    grep -q "drivers/kernelsu/Kconfig" "$DRIVER_KCONFIG" && sed -i '/drivers\/kernelsu\/Kconfig/d' "$DRIVER_KCONFIG" && echo "[-] Kconfig reverted."
    if [ -d "$GKI_ROOT/$REPO" ]; then
        rm -rf "$GKI_ROOT/$REPO" && echo "[-] $REPO directory deleted."
    fi
}

setup_kernelsu() {
    echo "[+] Setting up $REPO from $OWNER/$REPO..."
    test -d "$GKI_ROOT/$REPO" || git clone "https://github.com/$OWNER/$REPO" && echo "[+] Repository cloned."
    cd "$GKI_ROOT/$REPO"
    git stash && echo "[-] Stashed current changes."

    git fetch origin
    if [ -n "${1-}" ]; then
        TARGET="$1"
    else
        TARGET="$BRANCH_DEFAULT"
    fi

    echo "[-] Checking out target: $TARGET..."
    if ! git checkout "$TARGET" 2>/dev/null && ! git checkout -B "$TARGET" "origin/$TARGET" 2>/dev/null; then
        echo "[ERROR] Failed to check out target: $TARGET. Refusing to fallback silently."
        exit 1
    fi
    ACTUAL_SHA="$(git rev-parse HEAD)"
    echo "[+] Successfully checked out commit: $ACTUAL_SHA"

    cd "$DRIVER_DIR"
    ln -sf "$(realpath --relative-to="$DRIVER_DIR" "$GKI_ROOT/$REPO/kernel")" "kernelsu" && echo "[+] Symlink created."

    grep -q "kernelsu" "$DRIVER_MAKEFILE" || printf "\nobj-\$(CONFIG_KSU) += kernelsu/\n" >> "$DRIVER_MAKEFILE" && echo "[+] Modified Makefile."
    grep -q "source \"drivers/kernelsu/Kconfig\"" "$DRIVER_KCONFIG" || sed -i "/endmenu/i\source \"drivers/kernelsu/Kconfig\"" "$DRIVER_KCONFIG" && echo "[+] Modified Kconfig."
    echo '[+] Done.'
}

if [ "$#" -eq 0 ]; then
    initialize_variables
    setup_kernelsu
elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    display_usage
elif [ "$1" = "--cleanup" ]; then
    initialize_variables
    perform_cleanup
else
    initialize_variables
    setup_kernelsu "$@"
fi
