#!/bin/bash
#
# KotSafe APK Signature & Build Verification Utility
# Checks Android APK signing certificates against known KotSafe release channels.
#

set -euo pipefail

usage() {
    echo "Usage: $(basename "$0") <file.apk>"
    echo
    echo "Prints the KotSafe build channel (DEBUG, PLAYSTORE, GITHUB, FDROID) of an APK."
    exit 1
}

build_type() {
    case "$1" in
        511140392BFF2CFB4BD825895DD6510CE1807F6D) echo "DEBUG" ;;
        83AF496DC0C7CE72620606C465ECBBFA89F5E93F) echo "RELEASE" ;;
        EE953D4F988C8AC17575DFFAA1E3BBCE2E29E81D) echo "PLAYSTORE" ;;
        77DA81218F6E0D91220700317B2BCB906F4D4255) echo "GITHUB" ;;
        72777D6939EF150099219BBB68C17220DB28EA8E) echo "FDROID" ;;
        *) echo "" ;;
    esac
}

find_apksigner() {
    if command -v apksigner >/dev/null 2>&1; then
        command -v apksigner
        return 0
    fi

    local sdk_dirs=(
        "${ANDROID_HOME:-}"
        "${ANDROID_SDK_ROOT:-}"
        "$HOME/Android/Sdk"
        "/opt/android-sdk"
        "/usr/lib/android-sdk"
    )

    for sdk in "${sdk_dirs[@]}"; do
        [ -n "$sdk" ] || continue
        [ -d "$sdk/build-tools" ] || continue
        local tool
        tool=$(find "$sdk/build-tools" -mindepth 2 -maxdepth 2 -name apksigner -type f 2>/dev/null | sort -V | tail -n1)
        if [ -n "$tool" ]; then
            echo "$tool"
            return 0
        fi
    done
    return 1
}

get_fingerprints() {
    local apk="$1"
    if [ -n "$APKSIGNER" ]; then
        "$APKSIGNER" verify --print-certs "$apk" 2>/dev/null |
            sed -n 's/^Signer .* certificate SHA-1 digest: \([0-9a-fA-F]*\)$/\1/p' |
            tr 'a-f' 'A-F'
    else
        keytool -printcert -jarfile "$apk" 2>/dev/null |
            sed -n 's/^[[:space:]]*SHA1:[[:space:]]*\([0-9a-fA-F:]*\)$/\1/p' |
            tr -d ':' | tr 'a-f' 'A-F'
    fi
}

[ $# -eq 1 ] || usage
case "$1" in
    -h|--help) usage ;;
esac

apk="$1"
if [ ! -f "$apk" ]; then
    echo "Error: $apk not found" >&2
    exit 1
fi

APKSIGNER=$(find_apksigner || true)

fingerprints=$(get_fingerprints "$apk")
if [ -z "$fingerprints" ]; then
    echo "Error: Could not extract signing certificate (unsigned APK?)" >&2
    exit 1
fi

for fp in $fingerprints; do
    btype=$(build_type "$fp")
    if [ -n "$btype" ]; then
        echo "KotSafe Channel: $btype"
        exit 0
    fi
done

echo "UNKNOWN signature ($fingerprints)" >&2
exit 1
