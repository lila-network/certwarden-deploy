#!/usr/bin/env bash
set -euo pipefail


goarch="${GOARCH:-idk}"
goarm="${GOARM:-7}"  # Default GOARM=7, falls nicht übergeben
case "${GOARCH}" in
    amd64)    echo 'x86_64' ;;
    386)      echo 'i386' ;;
    arm64)    echo 'aarch64' ;;
    arm)
        case "${goarm}" in
            5) echo 'armv5l' ;;
            6) echo 'armv6l' ;;
            7) echo 'armv7l' ;;
            *) echo 'idk' ;;
        esac
        ;;
    ppc64le)  echo 'ppc64le' ;;
    s390x)    echo 's390x' ;;
    riscv64)  echo 'riscv64' ;;
    mips)     echo 'mips' ;;
    mipsle)   echo 'mipsel' ;;
    mips64)   echo 'mips64' ;;
    mips64le) echo 'mips64el' ;;
    *)
        # Fallback: unverändert zurückgeben
        printf '%s' "${goarch}"
        ;;
esac
